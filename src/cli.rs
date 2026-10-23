//! Command-line parsing: `envy <namespace> --flag` into a pure [`Action`].

use std::ffi::OsString;

use anyhow::{Result, bail};
use clap::{ArgMatches, CommandFactory, FromArgMatches};

use crate::commands::SetItem;
use crate::names::{validate_namespace, validate_var};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Status,
    Activate(String),
    Off,
    Init(String),
    New {
        ns: String,
        like: Option<String>,
        link: Option<String>,
    },
    /// `--secret` and `--plain`: the items in the order they were typed.
    Set {
        ns: String,
        items: Vec<SetItem>,
    },
    Edit(String),
    Rm(String),
    Link {
        ns: String,
        group: String,
    },
    Unlink(String),
    /// `envy <ns> --list`: the variables of one namespace.
    List(String),
}

/// Shown after the options in `--help`: what envy does, and the setup line.
const AFTER_HELP: &str = "\
envy keeps sets of environment variables, called namespaces, and loads one
into the current shell with `envy <namespace>`, replacing the namespace loaded
before (`envy --off` unloads it). Secrets live in the macOS Keychain; plain
values and the names live in ~/.config/envy/<namespace>.toml (or in
$ENVY_CONFIG_DIR). Run `envy --list` (or `envy` alone) to list the namespaces,
and `envy <namespace> --list` (alias `--ls`) to show a namespace's variables:
plain values are shown, secret values never are.

Example: set two secrets and two plain variables in one go (the secrets are
prompted for, hidden; AWS_REGION is given; AWS_PROFILE is prompted for):

    envy work --secret GITHUB_TOKEN OPENAI_KEY --plain AWS_REGION=eu-west-1 AWS_PROFILE

Setup: loading needs envy's shell function. Add this line to ~/.zshrc:

    eval \"$(envy --init zsh)\"";

/// Raw flags as clap parses them. Everything is optional here; which
/// combinations are legal is decided in one place, [`Flags::into_action`].
#[derive(clap::Parser, Debug)]
#[command(
    name = "envy",
    version,
    about = "Load secrets and variables into the current shell by namespace",
    after_help = AFTER_HELP
)]
struct Flags {
    /// Namespace to act on (comes first; may be named like a flag, e.g. `off`)
    namespace: Option<String>,

    /// Deactivate the active namespace
    #[arg(long)]
    off: bool,

    /// Print the shell integration for SHELL (only `zsh`)
    #[arg(long, value_name = "SHELL")]
    init: Option<String>,

    /// Create the namespace
    #[arg(long)]
    new: bool,

    /// Create the namespace as a copy of OTHER: copies its names and plain values and prompts for each secret (implies --new)
    #[arg(long, value_name = "OTHER")]
    like: Option<String>,

    /// Link the namespace to GROUP (with --new: at creation)
    #[arg(long, value_name = "GROUP")]
    link: Option<String>,

    /// Remove the namespace's group link
    #[arg(long)]
    unlink: bool,

    /// Set each NAME as a secret, stored in the Keychain. Each value is asked at a hidden prompt: secret values are never typed on the command line
    #[arg(long, value_name = "NAME", num_args = 1..)]
    secret: Vec<String>,

    /// Set each plain variable, stored in the namespace file: NAME=VALUE stores VALUE with no prompt; a bare NAME asks at a visible prompt (the current value is the default). An inline VALUE is written to the namespace file in plain text and also stays in your shell history: for anything sensitive use a bare NAME, or --secret
    #[arg(long, value_name = "NAME[=VALUE]", num_args = 1..)]
    plain: Vec<String>,

    /// Edit the namespace in $VISUAL/$EDITOR: change plain values, and add, remove or convert variables, including secrets (prompted for, hidden)
    #[arg(long)]
    edit: bool,

    /// Without a namespace, list the namespaces (same as plain `envy`); with one, show its variables: plain values are shown, secrets appear as @keychain and their values never are
    #[arg(long, visible_alias = "ls")]
    list: bool,

    /// Remove the namespace
    #[arg(long)]
    rm: bool,
}

/// Parses command-line arguments (first item is the program name) into an
/// [`Action`]. Pure: never exits or prints. clap's own failures, including
/// `--help`, come back as `Err` carrying clap's rendered text.
pub fn parse<I, T>(args: I) -> Result<Action>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let args: Vec<OsString> = args.into_iter().map(Into::into).collect();
    let typed: Vec<String> = args
        .iter()
        .skip(1)
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    parse_unredacted(args).map_err(|e| redact_error(e, &typed))
}

fn parse_unredacted(args: Vec<OsString>) -> Result<Action> {
    let matches = Flags::command().try_get_matches_from(args)?;
    let items = typed_items(&matches);
    Flags::from_arg_matches(&matches)?.into_action(items)
}

/// Removes from a parse error whatever the user typed after a `=` (see
/// [`redact`]). A clap error is rebuilt with the same kind, so `main` still
/// routes it; help and version, and errors with nothing to hide, are
/// returned untouched. The rebuilt error holds only the redacted text, so
/// neither its rendering nor its `Display`/`Debug` can reach the original.
fn redact_error(err: anyhow::Error, typed: &[String]) -> anyhow::Error {
    use clap::error::ErrorKind;
    match err.downcast::<clap::Error>() {
        Ok(ce) => {
            if matches!(
                ce.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) {
                return ce.into();
            }
            // `Display` of the rendering is plain text, never colour codes.
            let text = ce.render().to_string();
            let hidden = redact(&text, typed);
            if hidden == text {
                return ce.into();
            }
            let body = hidden.strip_prefix("error: ").unwrap_or(&hidden);
            clap::Error::raw(ce.kind(), body).into()
        }
        Err(other) => {
            let text = format!("{other:#}");
            let hidden = redact(&text, typed);
            if hidden == text {
                other
            } else {
                anyhow::anyhow!(hidden)
            }
        }
    }
}

/// Hides, in an error message, what the user typed after the first `=` of
/// any argument: it may be a secret value (`envy work --secret -- TOKEN=...`
/// gets past the `--secret` check, and clap quotes the argument back).
///
/// Only arguments with something after their `=` are considered, and only
/// whole typed text is replaced, never a single character or a fragment:
/// - the whole argument `head=tail` becomes `head=…` wherever it appears;
/// - the `tail` alone becomes `…` where it appears as a whole quoted token
///   (clap's `'tail'`, or Rust's `"tail"` as envy's own errors print it),
///   because clap quotes it on its own (`--off=tail`: "unexpected value
///   'tail'") and envy's errors quote option values (`--like=tail`).
fn redact(text: &str, typed: &[String]) -> String {
    let mut found: Vec<(&str, &str, &str)> = typed
        .iter()
        .filter_map(|arg| {
            let (head, tail) = arg.split_once('=')?;
            (!tail.is_empty()).then_some((arg.as_str(), head, tail))
        })
        .collect();
    // Longest first, so an argument that contains another is hidden whole.
    found.sort_by_key(|(arg, _, _)| std::cmp::Reverse(arg.len()));
    // `{:?}` without its quotes: how envy's own errors spell the text.
    let escaped = |s: &str| {
        let d = format!("{s:?}");
        d[1..d.len() - 1].to_string()
    };
    let mut out = text.to_string();
    for (arg, head, _) in &found {
        out = out.replace(arg, &format!("{head}=…"));
        out = out.replace(&escaped(arg), &format!("{}=…", escaped(head)));
    }
    for (_, _, tail) in &found {
        out = out.replace(&format!("'{tail}'"), "'…'");
        out = out.replace(&format!("{tail:?}"), "\"…\"");
    }
    out
}

/// The values of `--secret` (`true`) and `--plain` (`false`), in the order
/// they were typed, across both flags and any repeats of them.
fn typed_items(matches: &ArgMatches) -> Vec<(bool, String)> {
    let mut found: Vec<(usize, bool, String)> = Vec::new();
    for (id, secret) in [("secret", true), ("plain", false)] {
        if let (Some(values), Some(at)) = (matches.get_many::<String>(id), matches.indices_of(id)) {
            found.extend(at.zip(values).map(|(i, v)| (i, secret, v.clone())));
        }
    }
    found.sort_by_key(|(i, _, _)| *i);
    found.into_iter().map(|(_, s, v)| (s, v)).collect()
}

/// One typed item as a [`SetItem`]. `--plain` splits at the first `=`.
/// A `--secret` item with a `=` is refused naming the variable only: the
/// text after the `=` may be a real secret, so it is never repeated.
fn to_item(secret: bool, raw: &str) -> Result<SetItem> {
    let (name, value) = match raw.split_once('=') {
        Some((name, value)) => (name, Some(value)),
        None => (raw, None),
    };
    if secret && value.is_some() {
        const HIDDEN: &str = "secret values are never taken on the command line";
        const HOW: &str = "give the name only, as in `envy <namespace> --secret NAME`, and type the value at the hidden prompt";
        if name.is_empty() {
            bail!("--secret needs a variable name before the \"=\"; {HIDDEN}: {HOW}");
        }
        if let Err(e) = validate_var(name) {
            bail!("--secret: {e}; {HIDDEN}: {HOW}");
        }
        bail!(
            "--secret {name:?}: {HIDDEN} (they would stay in your shell history); give the name only, as in `envy <namespace> --secret {name}`, and type the value at the hidden prompt"
        );
    }
    validate_var(name)?;
    Ok(if secret {
        SetItem::secret(name)
    } else {
        SetItem::plain(name, value)
    })
}

impl Flags {
    fn into_action(self, typed: Vec<(bool, String)>) -> Result<Action> {
        let Flags {
            namespace,
            off,
            init,
            new,
            like,
            link,
            unlink,
            // Read in typed order from the matches instead (`typed`).
            secret: _,
            plain: _,
            edit,
            list,
            rm,
        } = self;
        let setting = !typed.is_empty();

        // `--like` implies `--new`; `--link` alone is the Link action, but
        // with `--new` it is an option of New.
        let creating = new || like.is_some();
        let link_alone = link.is_some() && !creating;
        if list
            && (off
                || init.is_some()
                || creating
                || setting
                || edit
                || rm
                || unlink
                || link.is_some())
        {
            bail!(
                "--list cannot be combined with another action (--off, --init, --new/--like, --secret/--plain, --edit, --rm, --link, --unlink)"
            );
        }
        let chosen = [
            off,
            init.is_some(),
            creating,
            setting,
            edit,
            rm,
            unlink,
            link_alone,
        ];
        if chosen.iter().filter(|&&c| c).count() > 1 {
            bail!(
                "conflicting actions: use only one of --off, --init, --new/--like, --secret/--plain, --edit, --rm, --link, --unlink"
            );
        }
        if link.is_some() && (off || init.is_some() || setting || edit || rm || unlink) {
            bail!("--link cannot be combined with that action");
        }

        // Validate every namespace-like value before building anything.
        if let Some(ns) = &namespace {
            validate_namespace(ns)?;
        }
        for value in [&like, &link].into_iter().flatten() {
            validate_namespace(value)?;
        }

        // Only `--off`, `--init` and no flags at all work without a namespace,
        // and the first two must not be given one.
        if off || init.is_some() {
            if namespace.is_some() {
                bail!("--off and --init do not take a namespace");
            }
        } else if namespace.is_none() && chosen.iter().any(|&c| c) {
            // `--secret`/`--plain` take every word after them, so a namespace
            // typed after the flag ends up among the items.
            bail!("this action needs a namespace, and it comes first: envy <namespace> --flag");
        }

        // Every item is checked, and no name may appear twice.
        let mut items: Vec<SetItem> = Vec::new();
        for (secret, raw) in &typed {
            let item = to_item(*secret, raw)?;
            if items.iter().any(|i| i.name == item.name) {
                bail!(
                    "variable {:?} is given more than once; give each name once",
                    item.name
                );
            }
            items.push(item);
        }

        let ns = namespace.clone();
        let need = || ns.clone().expect("namespace checked above");
        Ok(if off {
            Action::Off
        } else if let Some(shell) = init {
            if shell != "zsh" {
                bail!("unsupported shell {shell:?}: only zsh is supported");
            }
            Action::Init(shell)
        } else if creating {
            Action::New {
                ns: need(),
                like,
                link,
            }
        } else if setting {
            Action::Set { ns: need(), items }
        } else if edit {
            Action::Edit(need())
        } else if rm {
            Action::Rm(need())
        } else if unlink {
            Action::Unlink(need())
        } else if let Some(group) = link {
            Action::Link { ns: need(), group }
        } else {
            match (namespace, list) {
                (Some(ns), true) => Action::List(ns),
                (Some(ns), false) => Action::Activate(ns),
                (None, _) => Action::Status,
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(args: &[&str]) -> Result<Action> {
        parse(std::iter::once("envy").chain(args.iter().copied()))
    }

    fn s(v: &str) -> String {
        v.to_string()
    }

    fn set(ns: &str, items: Vec<SetItem>) -> Action {
        Action::Set { ns: s(ns), items }
    }

    fn sec(name: &str) -> SetItem {
        SetItem::secret(name)
    }

    fn pl(name: &str) -> SetItem {
        SetItem::plain(name, None)
    }

    fn pv(name: &str, value: &str) -> SetItem {
        SetItem::plain(name, Some(value))
    }

    #[test]
    fn parses_valid_invocations() {
        let cases: Vec<(&[&str], Action)> = vec![
            (&[], Action::Status),
            (&["work"], Action::Activate(s("work"))),
            (&["off"], Action::Activate(s("off"))),
            (&["new"], Action::Activate(s("new"))),
            (&["--off"], Action::Off),
            (&["--init", "zsh"], Action::Init(s("zsh"))),
            (
                &["work", "--new"],
                Action::New {
                    ns: s("work"),
                    like: None,
                    link: None,
                },
            ),
            (
                &["staging", "--like", "prod"],
                Action::New {
                    ns: s("staging"),
                    like: Some(s("prod")),
                    link: None,
                },
            ),
            (
                &["x", "--new", "--like", "prod", "--link", "aws"],
                Action::New {
                    ns: s("x"),
                    like: Some(s("prod")),
                    link: Some(s("aws")),
                },
            ),
            (
                &["x", "--new", "--link", "aws"],
                Action::New {
                    ns: s("x"),
                    like: None,
                    link: Some(s("aws")),
                },
            ),
            (
                &["work", "--secret", "TOKEN"],
                set("work", vec![sec("TOKEN")]),
            ),
            (&["work", "--secret=TOKEN"], set("work", vec![sec("TOKEN")])),
            (
                &["work", "--secret", "GITHUB_TOKEN", "OPENAI_KEY"],
                set("work", vec![sec("GITHUB_TOKEN"), sec("OPENAI_KEY")]),
            ),
            (&["work", "--plain", "_A1"], set("work", vec![pl("_A1")])),
            (
                &["work", "--plain", "AWS_REGION", "AWS_PROFILE"],
                set("work", vec![pl("AWS_REGION"), pl("AWS_PROFILE")]),
            ),
            (
                &[
                    "work",
                    "--secret",
                    "GITHUB_TOKEN",
                    "OPENAI_KEY",
                    "--plain",
                    "AWS_REGION",
                    "AWS_PROFILE",
                ],
                set(
                    "work",
                    vec![
                        sec("GITHUB_TOKEN"),
                        sec("OPENAI_KEY"),
                        pl("AWS_REGION"),
                        pl("AWS_PROFILE"),
                    ],
                ),
            ),
            // Items keep the order they were typed in, across both flags.
            (
                &[
                    "work",
                    "--plain",
                    "AWS_REGION=eu-west-1",
                    "--secret",
                    "GITHUB_TOKEN",
                ],
                set(
                    "work",
                    vec![pv("AWS_REGION", "eu-west-1"), sec("GITHUB_TOKEN")],
                ),
            ),
            (
                &["work", "--secret", "A", "--plain", "B", "--secret", "C"],
                set("work", vec![sec("A"), pl("B"), sec("C")]),
            ),
            (
                &["work", "--plain", "EMPTY="],
                set("work", vec![pv("EMPTY", "")]),
            ),
            (
                &["work", "--plain", "URL=a=b=c", "Q==x"],
                set("work", vec![pv("URL", "a=b=c"), pv("Q", "=x")]),
            ),
            (
                &["work", "--link", "aws"],
                Action::Link {
                    ns: s("work"),
                    group: s("aws"),
                },
            ),
            (&["work", "--unlink"], Action::Unlink(s("work"))),
            (&["work", "--edit"], Action::Edit(s("work"))),
            (&["work", "--rm"], Action::Rm(s("work"))),
            (&["--rm", "work"], Action::Rm(s("work"))),
            (&["--list"], Action::Status),
            (&["--ls"], Action::Status),
            (&["work", "--list"], Action::List(s("work"))),
            (&["work", "--ls"], Action::List(s("work"))),
            (&["--list", "work"], Action::List(s("work"))),
            (&["off", "--list"], Action::List(s("off"))),
        ];
        for (args, want) in cases {
            assert_eq!(p(args).unwrap(), want, "args: {args:?}");
        }
    }

    /// clap's rendered text for `args` (help, version or a clap error).
    fn clap_text(args: &[&str]) -> String {
        let err = p(args).unwrap_err();
        let ce = err.downcast_ref::<clap::Error>().expect("a clap error");
        ce.render().to_string()
    }

    #[test]
    fn help_explains_the_tool_and_the_zshrc_setup_line() {
        let help = clap_text(&["--help"]);
        assert!(help.contains("eval \"$(envy --init zsh)\""), "{help}");
        assert!(help.contains("~/.zshrc"), "{help}");
        assert!(help.contains("Keychain"), "{help}");
    }

    #[test]
    fn help_describes_like_and_edit_accurately() {
        let help = clap_text(&["--help"]);
        // The flag's line plus any wrapped continuation lines.
        let line = |flag: &str| -> String {
            let at = help
                .find(flag)
                .unwrap_or_else(|| panic!("{flag} in {help}"));
            let mut lines = help[at..].lines();
            let mut text = lines.next().unwrap().to_string();
            for more in lines.take_while(|l| {
                let l = l.trim_start();
                !l.is_empty() && !l.starts_with('-')
            }) {
                text.push(' ');
                text.push_str(more.trim());
            }
            text
        };
        let like = line("--like");
        assert!(
            like.contains("names and plain values") && like.contains("prompts for each secret"),
            "{like}"
        );
        assert!(!like.contains("with the secret names"), "{like}");
        let edit = line("--edit");
        assert!(edit.contains("secrets"), "{edit}");
        assert!(!edit.contains("plain variables"), "{edit}");
    }

    /// The full text `main` would print for a failed parse.
    fn error_text(args: &[&str]) -> String {
        let err = p(args).unwrap_err();
        match err.downcast_ref::<clap::Error>() {
            Some(ce) => ce.render().to_string(),
            None => format!("{err:#} {err:?}"),
        }
    }

    #[test]
    fn secret_values_on_the_command_line_are_refused_without_echoing_them() {
        for args in [
            &["work", "--secret", "TOKEN=zq-abc"][..],
            &["work", "--secret=TOKEN=zq-abc"],
            &["work", "--secret", "OK", "TOKEN=zq-abc", "--plain", "A=1"],
            &["work", "--plain", "A=1", "--secret", "TOKEN=zq-abc"],
            &["work", "--secret", "TOKEN="],
        ] {
            let msg = error_text(args);
            assert!(msg.contains("TOKEN"), "{args:?}: {msg}");
            assert!(
                msg.contains("never") && msg.contains("prompt"),
                "{args:?}: {msg}"
            );
            assert!(!msg.contains("zq-abc"), "{args:?}: {msg}");
        }
        // No name at all, or clap's own errors: still no value in the message.
        for args in [
            &["work", "--secret", "=zq-abc"][..],
            &["work", "--secret", "--TOKEN=zq-abc"],
            &["work", "--secret", "-T=zq-abc"],
            &["work", "--secret", "TOKEN=zq-abc", "--frobnicate"],
            &["--secret", "TOKEN=zq-abc", "work"],
            // clap quotes a whole argument, or the part after a `=`.
            &["work", "--secret", "A", "--", "TOKEN=zq-abc"],
            &["work", "--secret", "--", "TOKEN=zq-abc"],
            &["work", "--secret", "A", "--frob", "TOKEN=zq-abc"],
            &["--frob=TOKEN=zq-abc"],
            &["work", "--off=zq-abc"],
            &["work", "--new=TOKEN=zq-abc"],
            &[
                "work",
                "--plain",
                "X",
                "--secret",
                "A",
                "TOKEN=zq-abc",
                "--",
                "TOKEN2=zq-abc",
            ],
            // Our own errors quote values too.
            &["--init=zsh=zq-abc"],
            &["x", "--like=zq-abc=1"],
        ] {
            let msg = error_text(args);
            assert!(!msg.contains("zq-abc"), "{args:?}: {msg}");
        }
    }

    #[test]
    fn redacted_clap_errors_keep_their_kind_and_name_what_was_typed() {
        use clap::error::ErrorKind;
        let err = p(&["work", "--secret", "A", "--", "TOKEN=zq-abc"]).unwrap_err();
        let ce = err
            .downcast_ref::<clap::Error>()
            .expect("still a clap error");
        assert_eq!(ce.kind(), ErrorKind::UnknownArgument);
        assert_eq!(
            ce.render().to_string(),
            "error: unexpected argument 'TOKEN=…' found\n\n\
             Usage: envy [OPTIONS] [NAMESPACE]\n\n\
             For more information, try '--help'.\n"
        );
        assert!(!format!("{err:#} {err:?} {ce:?}").contains("zq-abc"));
        let msg = error_text(&["work", "--off=zq-abc"]);
        assert!(
            msg.starts_with("error: unexpected value '…' for '--off' found"),
            "{msg}"
        );
        let msg = error_text(&["--frob=TOKEN=zq-abc"]);
        assert!(
            msg.starts_with("error: unexpected argument '--frob' found"),
            "{msg}"
        );
        let msg = error_text(&[
            "work",
            "--plain",
            "X",
            "--secret",
            "A",
            "TOKEN=zq-abc",
            "--",
            "TOKEN2=zq-def",
        ]);
        assert!(msg.contains("'TOKEN2=…'") && !msg.contains("zq-"), "{msg}");
    }

    #[test]
    fn errors_without_a_value_after_an_equals_sign_are_untouched() {
        // Byte for byte what clap itself renders.
        for args in [
            &["envy", "work", "--frobnicate"][..],
            &["envy", "work", "--secret", "A", "--", "B"],
            &["envy", "work", "--off=", "--frob"],
            &["envy", "work", "--plain"],
        ] {
            let ours = p(&args[1..]).unwrap_err();
            let ours = ours.downcast_ref::<clap::Error>().unwrap();
            let theirs = Flags::command().try_get_matches_from(args).unwrap_err();
            assert_eq!(ours.kind(), theirs.kind(), "{args:?}");
            assert_eq!(
                ours.render().to_string(),
                theirs.render().to_string(),
                "{args:?}"
            );
        }
        // An `=` alone, or with nothing after it, hides nothing: no change.
        assert_eq!(
            redact("a = b, x= '='", &["=".into(), "x=".into()]),
            "a = b, x= '='"
        );
    }

    #[test]
    fn secret_items_with_a_value_get_a_clean_message() {
        let hidden = "secret values are never taken on the command line";
        for (item, want) in [
            (
                "TOKEN=zq-abc",
                format!(
                    "--secret \"TOKEN\": {hidden} (they would stay in your shell history); give the name only, as in `envy <namespace> --secret TOKEN`, and type the value at the hidden prompt"
                ),
            ),
            (
                "=",
                format!(
                    "--secret needs a variable name before the \"=\"; {hidden}: give the name only, as in `envy <namespace> --secret NAME`, and type the value at the hidden prompt"
                ),
            ),
            (
                "=zq-abc",
                format!(
                    "--secret needs a variable name before the \"=\"; {hidden}: give the name only, as in `envy <namespace> --secret NAME`, and type the value at the hidden prompt"
                ),
            ),
            (
                "TOKEN =zq-abc",
                format!(
                    "--secret: invalid variable name \"TOKEN \": must match [A-Za-z_][A-Za-z0-9_]*; {hidden}: give the name only, as in `envy <namespace> --secret NAME`, and type the value at the hidden prompt"
                ),
            ),
        ] {
            let err = p(&["work", "--secret", item]).unwrap_err();
            assert_eq!(format!("{err:#}"), want, "{item:?}");
            assert!(!format!("{err:?}").contains("zq-abc"), "{item:?}");
        }
    }

    #[test]
    fn a_name_given_twice_is_refused_naming_it() {
        for args in [
            &["work", "--secret", "A", "A"][..],
            &["work", "--plain", "A=1", "A=2"],
            &["work", "--secret", "A", "--plain", "A"],
            &["work", "--plain", "B", "A=1", "--secret", "C", "A"],
        ] {
            let msg = error_text(args);
            assert!(
                msg.contains("\"A\"") && msg.contains("more than once"),
                "{args:?}: {msg}"
            );
            assert!(!msg.contains('1'), "{args:?}: {msg}");
        }
    }

    #[test]
    fn invalid_names_are_refused_with_the_name_check_message() {
        let msg = error_text(&["work", "--plain", "ENVY_VARS=x"]);
        assert!(msg.contains("\"ENVY_VARS\" is reserved by envy"), "{msg}");
        let msg = error_text(&["work", "--secret", "SECONDS"]);
        assert!(msg.contains("special zsh parameter"), "{msg}");
        let msg = error_text(&["work", "--plain", "A-B=zq-v"]);
        assert!(msg.contains("invalid variable name \"A-B\""), "{msg}");
        assert!(!msg.contains("zq-v"), "{msg}");
    }

    #[test]
    fn the_namespace_must_come_first() {
        // The flags take every following word, so `work` here is an item
        // and there is no namespace: refused as such, not set as `work`.
        for args in [
            &["--secret", "A", "work"][..],
            &["--plain", "A=1", "work"],
            &["--secret", "A"],
        ] {
            let msg = error_text(args);
            assert!(
                msg.contains("needs a namespace") && msg.contains("first"),
                "{args:?}: {msg}"
            );
        }
    }

    #[test]
    fn help_documents_secret_and_plain() {
        let help = clap_text(&["--help"]);
        assert!(help.contains("--secret <NAME>..."), "{help}");
        assert!(help.contains("--plain <NAME[=VALUE]>..."), "{help}");
        assert!(!help.contains("--set"), "{help}");
        let flat = help.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(flat.contains("never typed on the command line"), "{help}");
        assert!(
            flat.contains("NAME=VALUE stores VALUE with no prompt"),
            "{help}"
        );
        assert!(
            flat.contains("in plain text and also stays in your shell history"),
            "{help}"
        );
        assert!(
            flat.contains(
                "envy work --secret GITHUB_TOKEN OPENAI_KEY --plain AWS_REGION=eu-west-1 AWS_PROFILE"
            ),
            "{help}"
        );
    }

    #[test]
    fn list_conflicts_with_every_other_action_with_a_clear_message() {
        let others: Vec<&[&str]> = vec![
            &["--new"],
            &["--like", "prod"],
            &["--link", "aws"],
            &["--unlink"],
            &["--secret", "A"],
            &["--plain", "A=1"],
            &["--edit"],
            &["--rm"],
            &["--off"],
            &["--init", "zsh"],
        ];
        for spelling in ["--list", "--ls"] {
            for other in &others {
                for ns in [Some("work"), None] {
                    let mut args: Vec<&str> = ns.into_iter().collect();
                    args.push(spelling);
                    args.extend(other.iter().copied());
                    let msg = error_text(&args);
                    assert!(
                        msg.contains("--list") && msg.contains("cannot be combined"),
                        "{args:?}: {msg}"
                    );
                }
            }
        }
    }

    #[test]
    fn list_still_redacts_what_follows_an_equals_sign() {
        for args in [
            &["work", "--list", "--plain", "TOKEN=zq-abc"][..],
            &["work", "--ls", "--secret", "TOKEN=zq-abc"],
            &["--list=zq-abc=1"],
            &["work", "--list=zq-abc"],
            &["work", "--list", "--", "TOKEN=zq-abc"],
            &["work", "--list", "TOKEN=zq-abc"],
        ] {
            assert!(p(args).is_err(), "{args:?}");
            let msg = error_text(args);
            assert!(!msg.contains("zq-abc"), "{args:?}: {msg}");
        }
    }

    #[test]
    fn help_documents_list_and_that_values_are_shown_or_not() {
        let help = clap_text(&["--help"]);
        assert!(help.contains("--list"), "{help}");
        assert!(help.contains("--ls"), "{help}");
        let flat = help.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(flat.contains("envy --list"), "{help}");
        assert!(flat.contains("envy <namespace> --list"), "{help}");
        assert!(flat.contains("plain values are shown"), "{help}");
        assert!(flat.contains("secret values never are"), "{help}");
    }

    #[test]
    fn version_is_reported_by_clap() {
        let err = p(&["--version"]).unwrap_err();
        let ce = err.downcast_ref::<clap::Error>().expect("a clap error");
        assert_eq!(ce.kind(), clap::error::ErrorKind::DisplayVersion);
        assert_eq!(
            ce.render().to_string(),
            format!("envy {}\n", env!("CARGO_PKG_VERSION"))
        );
    }

    #[test]
    fn rejects_invalid_invocations() {
        let cases: Vec<&[&str]> = vec![
            &["--off", "work"],
            &["work", "--off"],
            &["--init"],
            &["--init", "bash"],
            &["--init", "zsh", "work"],
            &["--init", "zsh", "--off"],
            &["work", "--plain"],
            &["--plain"],
            &["work", "--secret"],
            &["--secret"],
            &["work", "--secret", "--plain", "A"],
            &["work", "--plain", "A", "--secret"],
            &["work", "--edit", "--rm"],
            &["work", "--new", "--edit"],
            &["work", "--new", "--unlink"],
            &["work", "--link", "aws", "--rm"],
            &["work", "--secret", "X", "--link", "aws"],
            &["work", "--secret", "X", "--new"],
            &["work", "--plain", "X", "--new"],
            &["work", "--secret", "X", "--like", "prod"],
            &["work", "--plain", "X=1", "--unlink"],
            &["work", "--secret", "X", "--edit"],
            &["work", "--plain", "X", "--edit"],
            &["work", "--secret", "X", "--rm"],
            &["--off", "--secret", "X"],
            &["--init", "zsh", "--plain", "X=1"],
            &["work", "--set", "X"],
            &["work", "--secret", "ENVY_VARS"],
            &["work", "--plain", "ENVY_ACTIVE=x"],
            &["work", "--secret", "1A"],
            &["work", "--plain", "A-B"],
            &["work", "--plain", "SECONDS=1"],
            &["work", "--secret", "PATH"],
            &["work", "--plain", "=x"],
            &["work", "--secret", "OK", "A-B"],
            &["--secret", "X"],
            &["--plain", "X=1"],
            &["--secret", "X", "work"],
            &["--rm"],
            &["--edit"],
            &["--new"],
            &["--like", "prod"],
            &["--link", "aws"],
            &["--unlink"],
            &["../x"],
            &["../x", "--rm"],
            &["bad name", "--rm"],
            &["--", "-x"],
            &["staging", "--like", "../prod"],
            &["staging", "--like"],
            &["staging", "--like", "-x"],
            &["x", "--new", "--link", "../g"],
            &["x", "--link", "bad/label"],
            &["x", "--link", "-g"],
            &["x", "--link"],
            &["x", "--frobnicate"],
            &["-x"],
            &["a", "b"],
            &["a", "b", "--rm"],
            &["--help"],
            &["--version"],
            &["work", "--help"],
        ];
        for args in cases {
            assert!(p(args).is_err(), "expected error for {args:?}");
        }
    }
}
