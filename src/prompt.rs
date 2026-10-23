//! Interactive prompts. Prompt text always goes to stderr (stdout is reserved
//! for shell code), and input always comes from the controlling terminal
//! (`/dev/tty`), never from stdin, so a pipe or redirect can neither feed nor
//! capture a secret.

use std::collections::VecDeque;
use std::fmt;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::sync::Mutex;

use anyhow::{Context, Result, anyhow, bail};

use crate::secret::Secret;

pub trait Prompter {
    /// Reads a secret without echoing it. An empty secret is an error.
    fn secret(&self, label: &str) -> Result<Secret>;
    /// Reads a visible value. Empty input yields `default` when there is one.
    fn plain(&self, label: &str, default: Option<&str>) -> Result<String>;
    /// Asks a yes/no question; only `y` and `yes` (any case) count as yes.
    fn confirm(&self, question: &str) -> Result<bool>;
}

/// The label of a hidden prompt for secret `name` in namespace `ns`. Names
/// only: a label never holds a value.
pub fn secret_label(name: &str, ns: &str) -> String {
    format!("Secret value for {name} in {ns}")
}

/// The label of a visible prompt for plain variable `name` in namespace `ns`.
pub fn plain_label(name: &str, ns: &str) -> String {
    format!("Value for {name} in {ns}")
}

/// Checks a secret obtained from any prompter: it must be non-empty and free
/// of NUL (environment variables cannot hold one, and the shell quoting cannot
/// represent it). Errors never include the value.
pub fn vet_secret(secret: Secret) -> Result<Secret> {
    if secret.expose().is_empty() {
        bail!("the secret is empty; nothing was changed");
    }
    if secret.expose().contains('\0') {
        bail!("the secret contains a NUL byte, which environment variables cannot hold");
    }
    Ok(secret)
}

/// Checks a plain value obtained from any prompter (NUL is never allowed).
pub fn vet_plain(value: String) -> Result<String> {
    if value.contains('\0') {
        bail!("the value contains a NUL byte, which environment variables cannot hold");
    }
    Ok(value)
}

/// Turns one raw typed line into a plain value: strips a single trailing line
/// ending (`\n` or `\r\n`) and nothing else, so spaces, quotes and embedded
/// newlines survive; empty input selects the default when there is one.
fn finish_plain(raw: &str, default: Option<&str>) -> Result<String> {
    let line = raw
        .strip_suffix("\r\n")
        .or_else(|| raw.strip_suffix('\n'))
        .unwrap_or(raw);
    let value = if line.is_empty() {
        default.unwrap_or("")
    } else {
        line
    };
    vet_plain(value.to_string())
}

fn parse_confirm(raw: &str) -> bool {
    matches!(raw.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

/// Prompts on the real terminal.
pub struct TtyPrompter;

impl TtyPrompter {
    fn open_tty() -> Result<File> {
        File::open("/dev/tty").context("no terminal available to prompt on (cannot open /dev/tty)")
    }

    fn ask(prompt: &str) -> Result<String> {
        let tty = Self::open_tty()?;
        let mut err = std::io::stderr().lock();
        write!(err, "{prompt}").and_then(|()| err.flush()).ok();
        drop(err);
        let mut line = String::new();
        BufReader::new(tty)
            .read_line(&mut line)
            .context("cannot read from the terminal")?;
        Ok(line)
    }
}

impl Prompter for TtyPrompter {
    fn secret(&self, label: &str) -> Result<Secret> {
        // Fail before printing anything if there is no terminal. rpassword's
        // `read_password` itself reads from /dev/tty with echo disabled.
        drop(Self::open_tty()?);
        eprint!("{label}: ");
        let typed =
            rpassword::read_password().context("cannot read the secret from the terminal")?;
        vet_secret(Secret::new(typed))
    }

    fn plain(&self, label: &str, default: Option<&str>) -> Result<String> {
        let prompt = match default {
            Some(d) => format!("{label} [{d}]: "),
            None => format!("{label}: "),
        };
        finish_plain(&Self::ask(&prompt)?, default)
    }

    fn confirm(&self, question: &str) -> Result<bool> {
        Ok(parse_confirm(&Self::ask(&format!("{question} [y/N]: "))?))
    }
}

/// What a [`ScriptedPrompter`] was asked, for assertions in tests. Secret
/// answers are never recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Asked {
    Secret(String),
    Plain {
        label: String,
        default: Option<String>,
    },
    Confirm(String),
}

enum Answer {
    Secret(String),
    Plain(String),
    Confirm(bool),
}

/// A prompter with a preloaded queue of answers, for tests. It is a plain
/// `pub` item (not `#[cfg(test)]`) so integration tests and other modules'
/// tests can use it. Asking for something the next answer is not, or running
/// out of answers, is an `Err`. Its `Debug` never shows the answers.
#[derive(Default)]
pub struct ScriptedPrompter {
    answers: Mutex<VecDeque<Answer>>,
    asked: Mutex<Vec<Asked>>,
}

impl fmt::Debug for ScriptedPrompter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScriptedPrompter")
            .field("remaining", &self.remaining())
            .finish_non_exhaustive()
    }
}

impl ScriptedPrompter {
    pub fn new() -> Self {
        Self::default()
    }

    fn push(self, answer: Answer) -> Self {
        self.answers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push_back(answer);
        self
    }

    /// Queues the answer to a hidden prompt.
    pub fn with_secret(self, value: &str) -> Self {
        self.push(Answer::Secret(value.to_string()))
    }

    /// Queues what is typed at a visible prompt (a raw line; an empty string
    /// selects the default).
    pub fn with_plain(self, value: &str) -> Self {
        self.push(Answer::Plain(value.to_string()))
    }

    pub fn with_confirm(self, yes: bool) -> Self {
        self.push(Answer::Confirm(yes))
    }

    /// Answers not yet consumed.
    pub fn remaining(&self) -> usize {
        self.answers.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Every prompt shown so far, in order.
    pub fn asked(&self) -> Vec<Asked> {
        self.asked.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn record(&self, asked: Asked) {
        self.asked
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(asked);
    }

    fn next(&self, wanted: &str) -> Result<Answer> {
        self.answers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .pop_front()
            .ok_or_else(|| anyhow!("scripted prompter ran out of answers (wanted a {wanted})"))
    }
}

impl Prompter for ScriptedPrompter {
    fn secret(&self, label: &str) -> Result<Secret> {
        self.record(Asked::Secret(label.to_string()));
        match self.next("secret")? {
            Answer::Secret(v) => vet_secret(Secret::new(v)),
            _ => bail!("scripted prompter: next answer is not a secret"),
        }
    }

    fn plain(&self, label: &str, default: Option<&str>) -> Result<String> {
        self.record(Asked::Plain {
            label: label.to_string(),
            default: default.map(str::to_string),
        });
        match self.next("plain value")? {
            Answer::Plain(v) => finish_plain(&v, default),
            _ => bail!("scripted prompter: next answer is not a plain value"),
        }
    }

    fn confirm(&self, question: &str) -> Result<bool> {
        self.record(Asked::Confirm(question.to_string()));
        match self.next("confirmation")? {
            Answer::Confirm(yes) => Ok(yes),
            _ => bail!("scripted prompter: next answer is not a confirmation"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scripted_answers_come_back_in_order_and_running_out_errors() {
        let p = ScriptedPrompter::new()
            .with_secret("s3cret")
            .with_plain("eu")
            .with_confirm(true);
        assert_eq!(p.secret("S").unwrap().expose(), "s3cret");
        assert_eq!(p.plain("P", None).unwrap(), "eu");
        assert!(p.confirm("C?").unwrap());
        assert_eq!(p.remaining(), 0);
        assert!(p.secret("S").is_err());
        assert!(p.plain("P", None).is_err());
        assert!(p.confirm("C?").is_err());
    }

    #[test]
    fn scripted_wrong_kind_of_answer_errors() {
        let p = ScriptedPrompter::new().with_confirm(true);
        assert!(p.secret("S").is_err());
    }

    #[test]
    fn scripted_records_what_was_asked_but_not_secrets() {
        let p = ScriptedPrompter::new()
            .with_secret("hunter2")
            .with_plain("")
            .with_confirm(false);
        p.secret("T").unwrap();
        assert_eq!(p.plain("R", Some("eu")).unwrap(), "eu");
        assert!(!p.confirm("Sure?").unwrap());
        let asked = p.asked();
        assert_eq!(
            asked,
            vec![
                Asked::Secret("T".into()),
                Asked::Plain {
                    label: "R".into(),
                    default: Some("eu".into())
                },
                Asked::Confirm("Sure?".into()),
            ]
        );
        assert!(!format!("{asked:?}").contains("hunter2"));
    }

    #[test]
    fn scripted_debug_never_shows_answers() {
        let p = ScriptedPrompter::new()
            .with_secret("hunter2")
            .with_plain("visible-value");
        let printed = format!("{p:?} {p:#?}");
        assert!(!printed.contains("hunter2") && !printed.contains("visible-value"));
        assert!(printed.contains("remaining"));
    }

    #[test]
    fn empty_and_nul_secrets_are_rejected_without_echoing_them() {
        let p = ScriptedPrompter::new()
            .with_secret("")
            .with_secret("zq9\0xw7");
        assert!(p.secret("S").is_err());
        let err = p.secret("S").unwrap_err().to_string();
        assert!(
            err.contains("NUL") && !err.contains("zq9") && !err.contains("xw7"),
            "{err}"
        );
    }

    #[test]
    fn finish_plain_strips_one_line_ending_only() {
        assert_eq!(finish_plain("a b\n", None).unwrap(), "a b");
        assert_eq!(finish_plain("a b\r\n", None).unwrap(), "a b");
        assert_eq!(finish_plain("a b\n\n", None).unwrap(), "a b\n");
        assert_eq!(
            finish_plain("  it's \"q\" \n", None).unwrap(),
            "  it's \"q\" "
        );
        assert_eq!(finish_plain("x\ny", None).unwrap(), "x\ny");
    }

    #[test]
    fn finish_plain_uses_default_on_empty_and_rejects_nul() {
        assert_eq!(finish_plain("\n", Some("old")).unwrap(), "old");
        assert_eq!(finish_plain("", Some("old")).unwrap(), "old");
        assert_eq!(finish_plain("\n", None).unwrap(), "");
        assert!(finish_plain("a\0b\n", None).is_err());
    }

    #[test]
    fn confirm_accepts_y_and_yes_only() {
        for yes in ["y", "Y", "yes", "YES", " yes \n"] {
            assert!(parse_confirm(yes), "{yes:?}");
        }
        for no in ["", "n", "no", "yep", "ye", "\n"] {
            assert!(!parse_confirm(no), "{no:?}");
        }
    }
}
