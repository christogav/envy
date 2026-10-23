use anyhow::{Context, Result, bail};

use crate::config::{NamespaceFile, Value};
use crate::names::{validate_namespace, validate_var};
use crate::quote::shell_quote;
use crate::store::SecretStore;

/// What the current shell has already activated, as recorded in `ENVY_ACTIVE`
/// and `ENVY_VARS`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ActiveState {
    pub namespace: Option<String>,
    pub vars: Vec<String>,
}

impl ActiveState {
    /// Reads the previous state from the environment. The environment is
    /// untrusted, so every token that is not a valid variable name is dropped:
    /// tampered state can never inject text into the `unset` line.
    pub fn from_env(get: impl Fn(&str) -> Option<String>) -> Self {
        let namespace = get("ENVY_ACTIVE").filter(|ns| validate_namespace(ns).is_ok());
        let vars = get("ENVY_VARS")
            .unwrap_or_default()
            .split_whitespace()
            .filter(|tok| validate_var(tok).is_ok())
            .map(str::to_string)
            .collect();
        Self { namespace, vars }
    }
}

fn unset_line(vars: &[String]) -> String {
    if vars.is_empty() {
        String::new()
    } else {
        format!("unset {}\n", vars.join(" "))
    }
}

/// Renders the shell text that switches to `ns`: unset the previous
/// variables, record the new state (`ENVY_ACTIVE`, `ENVY_VARS`), then export
/// the new variables. Every secret is fetched before any
/// output is built, so a failure returns `Err` with nothing emitted.
pub fn render_activate(
    ns: &NamespaceFile,
    prev: &ActiveState,
    store: &dyn SecretStore,
) -> Result<String> {
    let mut resolved: Vec<(String, String)> = Vec::new();
    for (name, value) in ns.vars() {
        let text = match value {
            Value::Plain(text) => text,
            Value::Secret => match store
                .get(ns.secret_key(), &name)
                .with_context(|| format!("cannot read secret {name} for namespace {}", ns.name()))?
            {
                Some(secret) => secret.expose().to_string(),
                None => bail!(
                    "secret {name} is missing from the Keychain for namespace {}",
                    ns.name()
                ),
            },
        };
        resolved.push((name, text));
    }

    // The state is recorded before the variables are exported: if the shell
    // stops partway through the exports, ENVY_VARS already lists every name,
    // so `envy --off` (or the next switch) still unsets whatever was set.
    let mut out = unset_line(&prev.vars);
    let names: Vec<&str> = resolved.iter().map(|(n, _)| n.as_str()).collect();
    out.push_str(&format!("export ENVY_ACTIVE={}\n", shell_quote(ns.name())));
    out.push_str(&format!(
        "export ENVY_VARS={}\n",
        shell_quote(&names.join(" "))
    ));
    for (name, text) in &resolved {
        out.push_str(&format!("export {name}={}\n", shell_quote(text)));
    }
    Ok(out)
}

/// Renders the shell text that deactivates whatever `prev` describes.
pub fn render_off(prev: &ActiveState) -> String {
    format!("{}unset ENVY_ACTIVE ENVY_VARS\n", unset_line(&prev.vars))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::Secret;
    use crate::store::MemoryStore;

    fn state(vars: &[&str]) -> ActiveState {
        ActiveState {
            namespace: Some("old".into()),
            vars: vars.iter().map(|v| v.to_string()).collect(),
        }
    }

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

    #[test]
    fn activate_emits_unsets_then_state_then_exports_exactly() {
        let out = render_activate(&work(), &state(&["A", "B"]), &store_with_c()).unwrap();
        assert_eq!(
            out,
            "unset A B\nexport ENVY_ACTIVE='work'\nexport ENVY_VARS='B C'\nexport B='x'\nexport C='s3cret'\n"
        );
    }

    #[test]
    fn no_previous_state_emits_no_unset_line() {
        let out = render_activate(&work(), &ActiveState::default(), &store_with_c()).unwrap();
        assert_eq!(
            out,
            "export ENVY_ACTIVE='work'\nexport ENVY_VARS='B C'\nexport B='x'\nexport C='s3cret'\n"
        );
    }

    #[test]
    fn values_are_shell_quoted() {
        let ns = NamespaceFile::parse("w", "[vars]\nA = \"it's $(id)\"\n").unwrap();
        let out = render_activate(&ns, &ActiveState::default(), &MemoryStore::default()).unwrap();
        assert!(out.ends_with("export A='it'\\''s $(id)'\n"), "{out}");
    }

    #[test]
    fn reactivating_same_namespace_is_idempotent() {
        let store = store_with_c();
        let first = render_activate(&work(), &ActiveState::default(), &store).unwrap();
        let env = |k: &str| match k {
            "ENVY_ACTIVE" => Some("work".to_string()),
            "ENVY_VARS" => Some("B C".to_string()),
            _ => None,
        };
        let prev = ActiveState::from_env(env);
        assert_eq!(prev.vars, ["B", "C"]);
        let second = render_activate(&work(), &prev, &store).unwrap();
        assert_eq!(second, format!("unset B C\n{first}"));
    }

    #[test]
    fn missing_keychain_item_emits_nothing() {
        let ns = NamespaceFile::parse(
            "work",
            "[vars]\nB = \"@keychain\"\nC = \"@keychain\"\nD = \"plain\"\n",
        )
        .unwrap();
        let store = MemoryStore::default();
        store
            .set("work", "B", &Secret::new("b-secret-value".into()))
            .unwrap();
        let err = render_activate(&ns, &state(&["A"]), &store).unwrap_err();
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
        assert_eq!(s.vars, ["A", "C"]);
        assert_eq!(s.namespace, None);
    }

    #[test]
    fn tampered_envy_active_is_dropped() {
        let env = |k: &str| match k {
            "ENVY_ACTIVE" => Some("x; rm -rf ~".to_string()),
            _ => None,
        };
        assert_eq!(ActiveState::from_env(env).namespace, None);
    }

    #[test]
    fn off_output_matches_format() {
        assert_eq!(
            render_off(&state(&["A", "B"])),
            "unset A B\nunset ENVY_ACTIVE ENVY_VARS\n"
        );
        assert_eq!(
            render_off(&ActiveState::default()),
            "unset ENVY_ACTIVE ENVY_VARS\n"
        );
    }

    #[test]
    fn render_activate_reads_the_project_key() {
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
        let err = render_activate(&file, &ActiveState::default(), &store).unwrap_err();
        assert!(format!("{err:#}").contains("namespace work"), "{err:#}");

        store
            .set("project/acme/api/work", "C", &Secret::new("proj".into()))
            .unwrap();
        let out = render_activate(&file, &ActiveState::default(), &store).unwrap();
        assert!(out.ends_with("export C='proj'\n"), "{out}");
    }
}
