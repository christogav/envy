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
use anyhow::{Result, bail};

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

/// A change to the stack.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Change {
    /// Push `entry` on top, first removing every entry with its name and each
    /// namespace in `replaces` (its linked alternatives).
    Add {
        entry: Entry,
        replaces: Vec<String>,
    },
    Remove {
        namespace: String,
    },
    Clear,
}

/// A variable to (re)export, and the namespace that wins it afterwards.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Export {
    pub var: String,
    pub from: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Warning {
    Collision {
        var: String,
        winner: String,
        shadowed: String,
    },
}

/// What a change does: the next state and the shell work to get there.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transition {
    pub next: ActiveState,
    pub unset: Vec<String>,
    pub export: Vec<Export>,
    pub warnings: Vec<Warning>,
}

/// Works out the next state and the shell work to reach it from `prev`.
///
/// State read from the environment may hold one name more than once, so a
/// same-name change acts on every entry with that name. Per variable, the
/// previous winner is compared with the next: no owner means unset, a new or
/// different winner means export from it. Every variable of an added entry is
/// exported again (a refresh may carry new values).
pub fn transition(prev: &ActiveState, change: &Change) -> Result<Transition> {
    let mut entries = prev.entries.clone();
    let mut added: Option<&Entry> = None;
    match change {
        Change::Add { entry, replaces } => {
            entries.retain(|e| e.namespace != entry.namespace && !replaces.contains(&e.namespace));
            added = Some(entry);
        }
        Change::Remove { namespace } => {
            if prev.entry(namespace).is_none() {
                if prev.extra_vars.is_empty() {
                    bail!("namespace {namespace:?} is not active");
                }
                bail!(
                    "namespace {namespace:?} is not active (the recorded state looks damaged: run envy --off to remove everything)"
                );
            }
            entries.retain(|e| &e.namespace != namespace);
        }
        Change::Clear => entries.clear(),
    }

    let mut warnings = Vec::new();
    if let Some(entry) = added {
        for var in &entry.vars {
            if let Some(shadowed) = entries
                .iter()
                .rev()
                .find(|e| e.vars.contains(var))
                .map(|e| e.namespace.clone())
            {
                warnings.push(Warning::Collision {
                    var: var.clone(),
                    winner: entry.namespace.clone(),
                    shadowed,
                });
            }
        }
        entries.push(entry.clone());
    }

    let mut next = ActiveState {
        entries,
        extra_vars: Vec::new(),
    };
    // Unowned recorded names stay recorded (and set) until nothing is left.
    if !next.entries.is_empty() {
        next.extra_vars = prev
            .extra_vars
            .iter()
            .filter(|v| next.winner(v).is_none())
            .cloned()
            .collect();
    }

    let mut unset = Vec::new();
    let mut export = Vec::new();
    let mut seen = prev.all_vars();
    for var in next.all_vars() {
        if !seen.contains(&var) {
            seen.push(var);
        }
    }
    for var in seen {
        match next.winner(&var) {
            None if next.extra_vars.contains(&var) => {}
            None => unset.push(var),
            Some(winner) => {
                let refreshed = added.is_some_and(|e| e.vars.contains(&var));
                let changed = prev.winner(&var).map(|e| &e.namespace) != Some(&winner.namespace);
                if refreshed || changed {
                    export.push(Export {
                        var,
                        from: winner.namespace.clone(),
                    });
                }
            }
        }
    }
    Ok(Transition {
        next,
        unset,
        export,
        warnings,
    })
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

    fn state(entries: &[(&str, &[&str])]) -> ActiveState {
        ActiveState {
            entries: entries.iter().map(|(n, v)| entry(n, None, v)).collect(),
            extra_vars: vec![],
        }
    }

    fn add(prev: &ActiveState, ns: &str, vars: &[&str], replaces: &[&str]) -> Transition {
        let change = Change::Add {
            entry: entry(ns, Some("user"), vars),
            replaces: replaces.iter().map(|r| r.to_string()).collect(),
        };
        transition(prev, &change).unwrap()
    }

    fn remove(prev: &ActiveState, ns: &str) -> Transition {
        transition(
            prev,
            &Change::Remove {
                namespace: ns.to_string(),
            },
        )
        .unwrap()
    }

    fn exp(var: &str, from: &str) -> Export {
        Export {
            var: var.into(),
            from: from.into(),
        }
    }

    fn names(s: &ActiveState) -> Vec<&str> {
        s.entries.iter().map(|e| e.namespace.as_str()).collect()
    }

    #[test]
    fn add_to_empty_exports_every_var() {
        let t = add(&ActiveState::default(), "a", &["X", "Y"], &[]);
        assert_eq!(t.export, [exp("X", "a"), exp("Y", "a")]);
        assert!(t.unset.is_empty() && t.warnings.is_empty());
        assert_eq!(names(&t.next), ["a"]);
    }

    #[test]
    fn add_pushes_on_top_and_keeps_others() {
        let t = add(&state(&[("a", &["X"])]), "b", &["Y"], &[]);
        assert_eq!(names(&t.next), ["a", "b"]);
        assert_eq!(t.export, [exp("Y", "b")]);
        assert!(t.unset.is_empty());
    }

    #[test]
    fn add_with_the_same_name_replaces_and_moves_to_top() {
        let prev = ActiveState {
            entries: vec![
                entry("a", Some("/old/.envy"), &["X"]),
                entry("b", None, &["Y"]),
            ],
            extra_vars: vec![],
        };
        let t = add(&prev, "a", &["X"], &[]);
        assert_eq!(names(&t.next), ["b", "a"]);
        assert_eq!(t.next.entries[1].source.as_deref(), Some("user"));
        // The value may have changed, so it is exported again.
        assert_eq!(t.export, [exp("X", "a")]);
        assert!(t.unset.is_empty() && t.warnings.is_empty());
    }

    #[test]
    fn add_replaces_the_named_linked_entries() {
        let prev = state(&[("work", &["X", "Y"]), ("other", &["Z"])]);
        let t = add(&prev, "personal", &["X"], &["work"]);
        assert_eq!(names(&t.next), ["other", "personal"]);
        assert_eq!(t.export, [exp("X", "personal")]);
        assert_eq!(t.unset, ["Y"]);
        assert!(t.warnings.is_empty());
    }

    #[test]
    fn a_collision_warns_naming_var_winner_and_shadowed() {
        let t = add(&state(&[("a", &["X", "Y"])]), "b", &["X"], &[]);
        assert_eq!(
            t.warnings,
            [Warning::Collision {
                var: "X".into(),
                winner: "b".into(),
                shadowed: "a".into()
            }]
        );
        assert_eq!(t.export, [exp("X", "b")]);
    }

    #[test]
    fn no_warning_without_overlap() {
        let t = add(&state(&[("a", &["X"])]), "b", &["Y"], &[]);
        assert!(t.warnings.is_empty());
    }

    #[test]
    fn removing_the_winner_exports_the_shadowed_value_from_the_next_owner() {
        let prev = state(&[("a", &["X"]), ("b", &["X", "Y"])]);
        let t = remove(&prev, "b");
        assert_eq!(t.export, [exp("X", "a")]);
        assert_eq!(t.unset, ["Y"]);
        assert_eq!(names(&t.next), ["a"]);
    }

    #[test]
    fn removing_the_loser_changes_no_exports() {
        let prev = state(&[("a", &["X"]), ("b", &["X"])]);
        let t = remove(&prev, "a");
        assert!(t.export.is_empty() && t.unset.is_empty());
        assert_eq!(names(&t.next), ["b"]);
    }

    #[test]
    fn removing_the_middle_of_three() {
        let prev = state(&[("a", &["X"]), ("b", &["X", "Y"]), ("c", &["Y"])]);
        let t = remove(&prev, "b");
        // b won X over a, so a's X comes back; c still wins Y.
        assert_eq!(t.export, [exp("X", "a")]);
        assert!(t.unset.is_empty());
        assert_eq!(names(&t.next), ["a", "c"]);
        let t = remove(&prev, "c");
        assert_eq!(t.export, [exp("Y", "b")]);
    }

    #[test]
    fn removing_the_only_owner_unsets_the_var() {
        let prev = state(&[("a", &["X"]), ("b", &["Y"])]);
        let t = remove(&prev, "b");
        assert_eq!(t.unset, ["Y"]);
        assert!(t.export.is_empty());
    }

    #[test]
    fn refresh_that_drops_a_var_restores_the_lower_owner() {
        let prev = state(&[("a", &["X"]), ("b", &["X", "Y"])]);
        let t = add(&prev, "b", &["Y"], &[]);
        assert_eq!(names(&t.next), ["a", "b"]);
        assert!(t.export.contains(&exp("X", "a")));
        assert!(t.export.contains(&exp("Y", "b")));
        assert!(t.unset.is_empty());
        let dropped = add(&state(&[("b", &["X", "Y"])]), "b", &["Y"], &[]);
        assert_eq!(dropped.unset, ["X"]);
    }

    #[test]
    fn remove_of_an_inactive_name_errors_and_names_it() {
        let err = transition(
            &state(&[("a", &["X"])]),
            &Change::Remove {
                namespace: "nope".into(),
            },
        )
        .unwrap_err();
        assert_eq!(err.to_string(), "namespace \"nope\" is not active");
        let mut damaged = state(&[]);
        damaged.extra_vars = vec!["X".into()];
        let err = transition(
            &damaged,
            &Change::Remove {
                namespace: "work".into(),
            },
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "namespace \"work\" is not active (the recorded state looks damaged: run envy --off to remove everything)"
        );
    }

    #[test]
    fn clear_unsets_every_recorded_var_including_extras() {
        let mut prev = state(&[("a", &["X"]), ("b", &["X", "Y"])]);
        prev.extra_vars = vec!["Z".into()];
        let t = transition(&prev, &Change::Clear).unwrap();
        assert_eq!(t.unset, ["X", "Y", "Z"]);
        assert!(t.export.is_empty());
        assert_eq!(t.next, ActiveState::default());
    }

    #[test]
    fn extras_are_carried_over_until_everything_is_removed() {
        let mut prev = state(&[("a", &["X"]), ("b", &["Y"])]);
        prev.extra_vars = vec!["Z".into()];
        let t = remove(&prev, "b");
        assert_eq!(t.next.extra_vars, ["Z"]);
        assert_eq!(t.unset, ["Y"]);
        let t = remove(&t.next, "a");
        assert_eq!(t.unset, ["X", "Z"]);
        assert_eq!(t.next, ActiveState::default());
    }

    #[test]
    fn unset_never_lists_a_var_that_still_has_an_owner() {
        let mut prev = state(&[("a", &["X", "W"]), ("b", &["X", "Y"])]);
        prev.extra_vars = vec!["Z".into()];
        for t in [
            remove(&prev, "a"),
            remove(&prev, "b"),
            add(&prev, "b", &["Q"], &[]),
            add(&prev, "c", &["W"], &["a", "b"]),
        ] {
            for var in &t.unset {
                assert!(t.next.winner(var).is_none(), "{var} still owned");
                assert!(!t.next.extra_vars.contains(var), "{var} still recorded");
            }
            for e in &t.export {
                assert_eq!(t.next.winner(&e.var).unwrap().namespace, e.from);
            }
        }
    }

    #[test]
    fn duplicate_names_are_all_removed_by_add_and_remove() {
        let prev = state(&[("a", &["X"]), ("b", &["Y"]), ("a", &["Z"])]);
        let t = remove(&prev, "a");
        assert_eq!(names(&t.next), ["b"]);
        assert_eq!(t.unset, ["X", "Z"]);
        let t = add(&prev, "a", &["W"], &[]);
        assert_eq!(names(&t.next), ["b", "a"]);
        assert_eq!(t.unset, ["X", "Z"]);
        assert_eq!(t.export, [exp("W", "a")]);
    }
}
