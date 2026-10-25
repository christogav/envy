//! The namespaces a shell has active, as an ordered stack, and how that state
//! is written to and read back from the environment.
//!
//! State lives in three variables:
//!
//! - `ENVY_ACTIVE`: the namespace names, oldest first, separated by spaces.
//!   Informational (a prompt can print it); only read back for a shell that
//!   predates `ENVY_STACK`.
//! - `ENVY_STACK`: the full per-entry data, authoritative when present.
//! - `ENVY_VARS`: the flat union of every recorded variable name, so a plain
//!   `--off` works even when `ENVY_STACK` is damaged.
//!
//! `ENVY_STACK` encoding: entries are separated by the record separator
//! (U+001E) and each entry is `name US source US vars`, with fields separated
//! by the unit separator (U+001F) and `vars` space separated. `source` is
//! empty when unknown. A namespace name is `[A-Za-z0-9_-]`, a variable name
//! `[A-Za-z0-9_]`, and a level label printable ASCII (0x20 to 0x7e), so
//! neither control character can occur in any field: no escaping is needed
//! and a field can never run into the next. Each field is validated on the
//! way back in, so the delimiters themselves are the only structure trusted.
//!
//! A shell started before `ENVY_STACK` existed holds `ENVY_ACTIVE`,
//! `ENVY_SOURCE` and `ENVY_VARS` for one namespace: that reads as a stack of
//! one entry, and the next state written unsets `ENVY_SOURCE`.

use crate::names::{validate_namespace, validate_var};
use crate::quote::shell_quote;

/// The longest level label accepted back from the environment.
const MAX_SOURCE: usize = 4096;
const RECORD: char = '\u{1e}';
const FIELD: char = '\u{1f}';

/// One active namespace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub namespace: String,
    /// Which level the namespace was loaded from: `user`, or the encoded path
    /// of a project's `.envy` folder (see [`crate::levels::label`]). For
    /// display only: compared by exact equality with a level's label, never
    /// written into shell code or used as a path. `None` for a shell from
    /// before it existed, or a value that is not plausible.
    pub source: Option<String>,
    /// The variables this namespace contributed, in file order.
    pub vars: Vec<String>,
}

/// What the current shell has already activated.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ActiveState {
    /// Oldest first; the last entry defining a variable wins it.
    pub entries: Vec<Entry>,
    /// Recorded variable names that no entry owns (from damaged state).
    pub extra_vars: Vec<String>,
}

fn valid_source(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_SOURCE && s.bytes().all(|b| (0x20..=0x7e).contains(&b))
}

fn valid_vars(text: &str) -> Vec<String> {
    text.split_whitespace()
        .filter(|tok| validate_var(tok).is_ok())
        .map(str::to_string)
        .collect()
}

fn parse_entry(text: &str) -> Option<Entry> {
    let mut fields = text.split(FIELD);
    let (name, source, vars) = (fields.next()?, fields.next()?, fields.next()?);
    if fields.next().is_some() || validate_namespace(name).is_err() {
        return None;
    }
    Some(Entry {
        namespace: name.to_string(),
        source: Some(source).filter(|s| valid_source(s)).map(str::to_string),
        vars: valid_vars(vars),
    })
}

impl ActiveState {
    /// Reads the previous state from the environment. The environment is
    /// untrusted, so every token that is not valid is dropped: tampered state
    /// can never inject text into the `unset` or `export` lines.
    pub fn from_env(get: impl Fn(&str) -> Option<String>) -> Self {
        let flat = valid_vars(&get("ENVY_VARS").unwrap_or_default());
        let entries: Vec<Entry> = match get("ENVY_STACK") {
            Some(stack) => stack.split(RECORD).filter_map(parse_entry).collect(),
            None => get("ENVY_ACTIVE")
                .filter(|ns| validate_namespace(ns).is_ok())
                .map(|namespace| Entry {
                    namespace,
                    source: get("ENVY_SOURCE").filter(|s| valid_source(s)),
                    vars: flat.clone(),
                })
                .into_iter()
                .collect(),
        };
        let mut state = Self {
            entries,
            extra_vars: Vec::new(),
        };
        let owned = state.all_vars();
        state.extra_vars = flat.into_iter().filter(|v| !owned.contains(v)).collect();
        state
    }

    /// One namespace active, for tests and the legacy single-namespace shape.
    pub fn single(ns: &str, source: Option<&str>, vars: &[&str]) -> Self {
        Self {
            entries: vec![Entry {
                namespace: ns.to_string(),
                source: source.map(str::to_string),
                vars: vars.iter().map(|v| v.to_string()).collect(),
            }],
            extra_vars: Vec::new(),
        }
    }

    pub fn entry(&self, ns: &str) -> Option<&Entry> {
        self.entries.iter().find(|e| e.namespace == ns)
    }

    /// Every recorded variable name: entries in order, then the extras, in
    /// first-seen order without duplicates.
    pub fn all_vars(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        let all = self
            .entries
            .iter()
            .flat_map(|e| e.vars.iter())
            .chain(self.extra_vars.iter());
        for var in all {
            if !out.contains(var) {
                out.push(var.clone());
            }
        }
        out
    }

    /// The entry whose value of `var` is the one in the environment.
    pub fn winner(&self, var: &str) -> Option<&Entry> {
        self.entries
            .iter()
            .rev()
            .find(|e| e.vars.iter().any(|v| v == var))
    }

    /// The shell text that records this state. Everything written was
    /// validated on the way in; the values are quoted regardless. An empty
    /// state unsets the variables instead. `ENVY_SOURCE` belongs to the
    /// single-namespace state of older versions and is always unset.
    pub fn state_exports(&self) -> String {
        if self.entries.is_empty() && self.extra_vars.is_empty() {
            return "unset ENVY_ACTIVE ENVY_SOURCE ENVY_STACK ENVY_VARS\n".to_string();
        }
        let names: Vec<&str> = self.entries.iter().map(|e| e.namespace.as_str()).collect();
        let stack: Vec<String> = self
            .entries
            .iter()
            .map(|e| {
                format!(
                    "{}{FIELD}{}{FIELD}{}",
                    e.namespace,
                    e.source.as_deref().unwrap_or(""),
                    e.vars.join(" ")
                )
            })
            .collect();
        format!(
            "export ENVY_ACTIVE={}\nexport ENVY_STACK={}\nexport ENVY_VARS={}\nunset ENVY_SOURCE\n",
            shell_quote(&names.join(" ")),
            shell_quote(&stack.join(&RECORD.to_string())),
            shell_quote(&self.all_vars().join(" ")),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k| map.get(k).cloned()
    }

    fn entry(ns: &str, source: Option<&str>, vars: &[&str]) -> Entry {
        ActiveState::single(ns, source, vars).entries.remove(0)
    }

    /// Evaluates `state_exports` text the way the shell would, for the three
    /// exported variables.
    fn read_back(exports: &str) -> HashMap<String, String> {
        let mut map = HashMap::new();
        for var in ["ENVY_ACTIVE", "ENVY_STACK", "ENVY_VARS"] {
            let prefix = format!("export {var}='");
            if let Some(start) = exports.find(&prefix) {
                let rest = &exports[start + prefix.len()..];
                let end = rest.find('\'').unwrap();
                map.insert(var.to_string(), rest[..end].to_string());
            }
        }
        map
    }

    #[test]
    fn new_state_round_trips_through_the_environment() {
        let state = ActiveState {
            entries: vec![
                entry("base", Some("user"), &["A", "B"]),
                entry("dev", Some("/Users/me/src/api/.envy"), &["B", "C"]),
                entry("odd", None, &[]),
            ],
            extra_vars: vec![],
        };
        let map = read_back(&state.state_exports());
        assert_eq!(map["ENVY_ACTIVE"], "base dev odd");
        assert_eq!(map["ENVY_VARS"], "A B C");
        let back = ActiveState::from_env(|k| map.get(k).cloned());
        assert_eq!(back, state);
    }

    #[test]
    fn legacy_state_reads_as_one_entry() {
        let s = ActiveState::from_env(env(&[
            ("ENVY_ACTIVE", "dev"),
            ("ENVY_SOURCE", "user"),
            ("ENVY_VARS", "A B"),
        ]));
        assert_eq!(s, ActiveState::single("dev", Some("user"), &["A", "B"]));
    }

    #[test]
    fn legacy_state_without_source_has_source_none() {
        let s = ActiveState::from_env(env(&[("ENVY_ACTIVE", "dev"), ("ENVY_VARS", "A")]));
        assert_eq!(s, ActiveState::single("dev", None, &["A"]));
    }

    #[test]
    fn invalid_tokens_are_dropped() {
        let stack = [
            "ok\u{1f}user\u{1f}A B;x $(id) C",
            "bad name\u{1f}user\u{1f}A",
            "\u{1f}user\u{1f}A",
            "ctl\u{1f}us\ter\u{1f}A",
            "long\u{1f}xxxx\u{1f}A",
            "extra\u{1f}user\u{1f}A\u{1f}B",
            "short\u{1f}user",
            "ENVY_X\u{1f}user\u{1f}ENVY_Y",
        ]
        .join("\u{1e}");
        let long = format!("long\u{1f}{}\u{1f}A", "x".repeat(4097));
        let stack = stack.replace("long\u{1f}xxxx\u{1f}A", &long);
        let s = ActiveState::from_env(env(&[("ENVY_STACK", &stack)]));
        let names: Vec<&str> = s.entries.iter().map(|e| e.namespace.as_str()).collect();
        assert_eq!(names, ["ok", "ctl", "long", "ENVY_X"]);
        assert_eq!(s.entries[0].vars, ["A", "C"].map(String::from));
        assert_eq!(s.entries[1].source, None);
        assert_eq!(s.entries[2].source, None);
        assert_eq!(s.entries[3].vars, Vec::<String>::new());
        assert!(!s.state_exports().contains("id)"));
        // The longest label is accepted.
        let ok = format!("n\u{1f}{}\u{1f}", "x".repeat(4096));
        let s = ActiveState::from_env(env(&[("ENVY_STACK", &ok)]));
        assert_eq!(
            s.entries[0].source.as_deref(),
            Some("x".repeat(4096).as_str())
        );
    }

    #[test]
    fn a_damaged_stack_keeps_the_flat_var_list() {
        let s = ActiveState::from_env(env(&[
            ("ENVY_STACK", "garbage; rm -rf ~"),
            ("ENVY_ACTIVE", "dev"),
            ("ENVY_VARS", "A B"),
        ]));
        assert!(s.entries.is_empty());
        assert_eq!(s.all_vars(), ["A", "B"]);
    }

    #[test]
    fn extra_vars_are_names_no_entry_owns() {
        let s = ActiveState::from_env(env(&[
            ("ENVY_STACK", "dev\u{1f}user\u{1f}A"),
            ("ENVY_VARS", "A B C"),
        ]));
        assert_eq!(s.extra_vars, ["B", "C"]);
        assert_eq!(s.all_vars(), ["A", "B", "C"]);
        let none = ActiveState::from_env(env(&[("ENVY_VARS", "A")]));
        assert_eq!(none.extra_vars, ["A"]);
    }

    #[test]
    fn state_exports_quote_and_never_contain_unvalidated_text() {
        let evil = "x'; touch /tmp/pwned; echo '";
        let stack = format!("dev\u{1f}{evil}\u{1f}A;touch_pwned B");
        let s = ActiveState::from_env(env(&[("ENVY_STACK", &stack), ("ENVY_VARS", "A $(id) B")]));
        let out = s.state_exports();
        assert!(
            !out.contains("id)") && !out.contains("touch_pwned"),
            "{out}"
        );
        // The label is quoted: the quote inside it is escaped.
        let single = ActiveState::single("dev", Some("it's"), &["A"]).state_exports();
        assert!(single.contains("it'\\''s"), "{single}");
        assert_eq!(
            ActiveState::single("dev", Some("user"), &["A", "B"]).state_exports(),
            "export ENVY_ACTIVE='dev'\nexport ENVY_STACK='dev\u{1f}user\u{1f}A B'\nexport ENVY_VARS='A B'\nunset ENVY_SOURCE\n"
        );
        assert_eq!(
            ActiveState::default().state_exports(),
            "unset ENVY_ACTIVE ENVY_SOURCE ENVY_STACK ENVY_VARS\n"
        );
    }

    #[test]
    fn winner_is_the_last_entry_defining_the_var() {
        let s = ActiveState {
            entries: vec![entry("a", None, &["X", "Y"]), entry("b", None, &["Y"])],
            extra_vars: vec!["Z".into()],
        };
        assert_eq!(s.winner("X").unwrap().namespace, "a");
        assert_eq!(s.winner("Y").unwrap().namespace, "b");
        assert!(s.winner("Z").is_none());
        assert!(s.winner("Q").is_none());
        assert_eq!(s.entry("b").unwrap().namespace, "b");
        assert!(s.entry("c").is_none());
        assert_eq!(s.all_vars(), ["X", "Y", "Z"]);
    }
}
