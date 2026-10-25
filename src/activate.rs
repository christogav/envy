//! The shell text envy prints for the wrapper's `eval`: the values of a
//! namespace's variables, and the lines that move the shell from one state to
//! the next.

use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};

use crate::config::{NamespaceFile, Value};
use crate::quote::shell_quote;
use crate::stack::{ActiveState, Transition};
use crate::store::SecretStore;

fn unset_line(vars: &[String]) -> String {
    if vars.is_empty() {
        String::new()
    } else {
        format!("unset {}\n", vars.join(" "))
    }
}

/// The value of variable `name` (whose file value is `value`) of `ns`: a
/// plain value as written, a secret from `store`, or `None` for a secret that
/// is not in the store. A failed read is an error naming the variable only.
///
/// `ns` must come from `Config::load`: a freshly parsed project file carries
/// the default key and would read the user-level item with the same name.
pub fn read_value(
    ns: &NamespaceFile,
    name: &str,
    value: &Value,
    store: &dyn SecretStore,
) -> Result<Option<String>> {
    Ok(match value {
        Value::Plain(text) => Some(text.clone()),
        Value::Secret => store
            .get(ns.secret_key(), name)
            .with_context(|| format!("cannot read secret {name} for namespace {}", ns.name()))?
            .map(|secret| secret.expose().to_string()),
    })
}

/// Every variable of `ns` with its value ([`read_value`]); a secret missing
/// from the store is an error.
pub fn read_values(
    ns: &NamespaceFile,
    store: &dyn SecretStore,
) -> Result<BTreeMap<String, String>> {
    let mut values = BTreeMap::new();
    for (name, value) in ns.vars() {
        let Some(text) = read_value(ns, &name, &value, store)? else {
            bail!(
                "secret {name} is missing from the Keychain for namespace {}",
                ns.name()
            );
        };
        values.insert(name, text);
    }
    Ok(values)
}

/// Renders the shell text for `t`: one `unset` line, then the next state,
/// then an `export` per variable in `t.export`. The `unset` line holds
/// `t.unset` and every variable of `t.export` that has no entry in `values`
/// (one that could not be restored is left unset, never stale). Every value
/// must already be in `values`, so nothing can fail once output is built.
///
/// The state is recorded before the variables are exported: if the shell
/// stops partway through the exports, `ENVY_VARS` already lists every name,
/// so `envy --off` (or the next change) still unsets whatever was set.
pub fn render_transition(t: &Transition, values: &BTreeMap<String, String>) -> String {
    let mut unset = t.unset.clone();
    unset.extend(
        t.export
            .iter()
            .filter(|e| !values.contains_key(&e.var))
            .map(|e| e.var.clone()),
    );
    let mut out = unset_line(&unset);
    out.push_str(&t.next.state_exports());
    for e in &t.export {
        if let Some(text) = values.get(&e.var) {
            out.push_str(&format!("export {}={}\n", e.var, shell_quote(text)));
        }
    }
    out
}

/// Renders the shell text that deactivates whatever `prev` describes.
pub fn render_off(prev: &ActiveState) -> String {
    format!(
        "{}{}",
        unset_line(&prev.all_vars()),
        ActiveState::default().state_exports()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::Secret;
    use crate::stack::{Change, Entry, transition};
    use crate::store::MemoryStore;

    fn state(vars: &[&str]) -> ActiveState {
        ActiveState::single("old", Some("user"), vars)
    }

    const S: &str = "\u{1f}";

    fn work() -> NamespaceFile {
        NamespaceFile::parse("work", "[vars]\nB = \"x\"\nC = \"@keychain\"\n").unwrap()
    }

    fn store_with_c() -> MemoryStore {
        let store = MemoryStore::default();
        store
            .set("work", "C", &Secret::new("s3cret".into()))
            .unwrap();
        store
    }

    /// `work` (B, C) added to `prev`, replacing `replaces`.
    fn add_work(prev: &ActiveState, replaces: &[&str]) -> Transition {
        let change = Change::Add {
            entry: Entry {
                namespace: "work".into(),
                source: Some("user".into()),
                vars: vec!["B".into(), "C".into()],
            },
            replaces: replaces.iter().map(|r| r.to_string()).collect(),
        };
        transition(prev, &change).unwrap()
    }

    fn values(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn render_transition_unsets_then_records_state_then_exports_exactly() {
        let t = add_work(&state(&["A", "B"]), &["old"]);
        let out = render_transition(&t, &values(&[("B", "x"), ("C", "s3cret")]));
        assert_eq!(
            out,
            format!(
                "unset A\nexport ENVY_ACTIVE='work'\nexport ENVY_STACK='work{S}user{S}B C'\nexport ENVY_VARS='B C'\nunset ENVY_SOURCE\nexport B='x'\nexport C='s3cret'\n"
            )
        );
    }

    #[test]
    fn nothing_to_unset_emits_no_unset_line() {
        let t = add_work(&ActiveState::default(), &[]);
        let out = render_transition(&t, &values(&[("B", "x"), ("C", "s3cret")]));
        assert_eq!(
            out,
            format!(
                "export ENVY_ACTIVE='work'\nexport ENVY_STACK='work{S}user{S}B C'\nexport ENVY_VARS='B C'\nunset ENVY_SOURCE\nexport B='x'\nexport C='s3cret'\n"
            )
        );
    }

    #[test]
    fn an_export_without_a_value_is_unset_instead() {
        let t = add_work(&state(&["A", "B"]), &["old"]);
        let out = render_transition(&t, &values(&[("C", "s3cret")]));
        assert!(out.starts_with("unset A B\nexport ENVY_ACTIVE="), "{out}");
        assert!(
            out.ends_with("unset ENVY_SOURCE\nexport C='s3cret'\n"),
            "{out}"
        );
        assert!(!out.contains("export B="), "{out}");
    }

    #[test]
    fn values_are_shell_quoted() {
        let t = add_work(&ActiveState::default(), &[]);
        let out = render_transition(&t, &values(&[("B", "it's $(id)"), ("C", "c")]));
        assert!(
            out.ends_with("export B='it'\\''s $(id)'\nexport C='c'\n"),
            "{out}"
        );
    }

    #[test]
    fn envy_source_is_read_back() {
        let env = |k: &str| match k {
            "ENVY_ACTIVE" => Some("work".to_string()),
            "ENVY_SOURCE" => Some("/Users/me/src/api/.envy".to_string()),
            _ => None,
        };
        let s = ActiveState::from_env(env);
        assert_eq!(
            s.entries[0].source.as_deref(),
            Some("/Users/me/src/api/.envy")
        );
    }

    #[test]
    fn tampered_envy_source_is_ignored_and_never_emitted() {
        for bad in [
            String::new(),
            "user\nunset PATH".to_string(),
            "$(id)\u{1b}[31m".to_string(),
            "x".repeat(10_000),
            "/Users/m\u{e9}/.envy".to_string(),
            "a\tb".to_string(),
            "\u{7f}".to_string(),
        ] {
            let env = |k: &str| match k {
                "ENVY_ACTIVE" => Some("other".to_string()),
                "ENVY_VARS" => Some("B C".to_string()),
                "ENVY_SOURCE" => Some(bad.clone()),
                _ => None,
            };
            let prev = ActiveState::from_env(env);
            assert_eq!(prev.entries[0].source, None, "{bad:?}");
            // The previous source never reaches shell code.
            let t = add_work(&prev, &[]);
            let out = render_transition(&t, &values(&[("B", "x"), ("C", "c")]));
            assert!(!out.contains("id)") && !out.contains("unset PATH"), "{out}");
            assert!(!render_off(&prev).contains("id)"));
        }
        // The longest value accepted.
        let with_source = |source: String| {
            ActiveState::from_env(|k| match k {
                "ENVY_ACTIVE" => Some("work".to_string()),
                "ENVY_SOURCE" => Some(source.clone()),
                _ => None,
            })
        };
        let long = "x".repeat(4096);
        assert_eq!(
            with_source(long.clone()).entries[0].source.as_deref(),
            Some(long.as_str())
        );
        assert_eq!(with_source("x".repeat(4097)).entries[0].source, None);
    }

    #[test]
    fn read_values_reads_plain_values_and_secrets() {
        assert_eq!(
            read_values(&work(), &store_with_c()).unwrap(),
            values(&[("B", "x"), ("C", "s3cret")])
        );
    }

    #[test]
    fn a_missing_keychain_item_fails_naming_it_only() {
        let ns = NamespaceFile::parse(
            "work",
            "[vars]\nB = \"@keychain\"\nC = \"@keychain\"\nD = \"plain\"\n",
        )
        .unwrap();
        let store = MemoryStore::default();
        store
            .set("work", "B", &Secret::new("b-secret-value".into()))
            .unwrap();
        let err = read_values(&ns, &store).unwrap_err();
        let msg = format!("{err:#}");
        assert_eq!(
            msg,
            "secret C is missing from the Keychain for namespace work"
        );
        assert!(
            !msg.contains("b-secret-value") && !msg.contains("plain"),
            "{msg}"
        );
    }

    #[test]
    fn tampered_envy_vars_is_filtered() {
        let env = |k: &str| match k {
            "ENVY_VARS" => Some("A B;touch_pwned $(id) C".to_string()),
            _ => None,
        };
        let s = ActiveState::from_env(env);
        assert_eq!(s.all_vars(), ["A", "C"]);
        assert!(s.entries.is_empty());
    }

    #[test]
    fn tampered_envy_active_is_dropped() {
        let env = |k: &str| match k {
            "ENVY_ACTIVE" => Some("x; rm -rf ~".to_string()),
            _ => None,
        };
        assert!(ActiveState::from_env(env).entries.is_empty());
    }

    #[test]
    fn off_output_matches_format() {
        assert_eq!(
            render_off(&state(&["A", "B"])),
            "unset A B\nunset ENVY_ACTIVE ENVY_SOURCE ENVY_STACK ENVY_VARS\n"
        );
        assert_eq!(
            render_off(&ActiveState::default()),
            "unset ENVY_ACTIVE ENVY_SOURCE ENVY_STACK ENVY_VARS\n"
        );
    }

    #[test]
    fn off_leaves_no_stack_variable_behind() {
        let stacked = ActiveState::from_env(|k| match k {
            "ENVY_STACK" => Some("a\u{1f}user\u{1f}A\u{1e}b\u{1f}\u{1f}B".to_string()),
            "ENVY_VARS" => Some("A B C".to_string()),
            _ => None,
        });
        assert_eq!(
            render_off(&stacked),
            "unset A B C\nunset ENVY_ACTIVE ENVY_SOURCE ENVY_STACK ENVY_VARS\n"
        );
    }

    #[test]
    fn read_values_reads_the_project_key() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = crate::config::Config::project(
            dir.path().join(".envy"),
            dir.path().to_path_buf(),
            "acme/api".into(),
            dir.path().join("user"),
        );
        let mut f = NamespaceFile::empty("work").unwrap();
        f.set_var("C", crate::config::Value::Secret).unwrap();
        cfg.save(&f).unwrap();
        let file = cfg.load("work").unwrap();

        let store = MemoryStore::default();
        store
            .set("work", "C", &Secret::new("user-level".into()))
            .unwrap();
        let err = read_values(&file, &store).unwrap_err();
        assert!(format!("{err:#}").contains("namespace work"), "{err:#}");

        store
            .set("project/acme/api/work", "C", &Secret::new("proj".into()))
            .unwrap();
        assert_eq!(
            read_values(&file, &store).unwrap(),
            values(&[("C", "proj")])
        );
    }
}
