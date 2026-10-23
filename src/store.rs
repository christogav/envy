use std::collections::BTreeMap;
use std::sync::Mutex;

use anyhow::Result;

use crate::secret::Secret;

/// Storage for secret values, keyed by secret key and variable name. The key
/// is the namespace name at user level and `project/<identity>/<namespace>`
/// for a project namespace; the Keychain service becomes `envy.{key}`, e.g.
/// `envy.project/acme/api/dev`.
pub trait SecretStore {
    fn get(&self, ns: &str, name: &str) -> Result<Option<Secret>>;
    fn set(&self, ns: &str, name: &str, value: &Secret) -> Result<()>;
    /// Deleting an item that does not exist is not an error.
    fn delete(&self, ns: &str, name: &str) -> Result<()>;
}

/// In-memory store for tests; never touches disk or the Keychain.
#[derive(Default)]
pub struct MemoryStore {
    items: Mutex<BTreeMap<(String, String), String>>,
}

impl MemoryStore {
    fn items(&self) -> std::sync::MutexGuard<'_, BTreeMap<(String, String), String>> {
        self.items.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Every stored item as sorted `(namespace, name, value)` tuples.
    #[cfg(test)]
    pub(crate) fn snapshot(&self) -> Vec<(String, String, String)> {
        self.items()
            .iter()
            .map(|((ns, name), value)| (ns.clone(), name.clone(), value.clone()))
            .collect()
    }
}

impl SecretStore for MemoryStore {
    fn get(&self, ns: &str, name: &str) -> Result<Option<Secret>> {
        Ok(self
            .items()
            .get(&(ns.to_string(), name.to_string()))
            .map(|v| Secret::new(v.clone())))
    }

    fn set(&self, ns: &str, name: &str, value: &Secret) -> Result<()> {
        self.items().insert(
            (ns.to_string(), name.to_string()),
            value.expose().to_string(),
        );
        Ok(())
    }

    fn delete(&self, ns: &str, name: &str) -> Result<()> {
        self.items().remove(&(ns.to_string(), name.to_string()));
        Ok(())
    }
}

/// macOS login Keychain, accessed through the native Security framework.
/// Items are generic passwords with service `envy.<namespace>` and account
/// `<name>`.
#[cfg(target_os = "macos")]
pub struct MacKeychain;

#[cfg(target_os = "macos")]
mod keychain {
    use anyhow::{Context, Result};
    use security_framework::passwords::{
        delete_generic_password, get_generic_password, set_generic_password,
    };

    use super::{MacKeychain, SecretStore};
    use crate::secret::Secret;

    /// `ITEM_NOT_FOUND` from the Security framework.
    const ITEM_NOT_FOUND: i32 = -25300;

    fn service(ns: &str) -> String {
        format!("envy.{ns}")
    }

    impl SecretStore for MacKeychain {
        fn get(&self, ns: &str, name: &str) -> Result<Option<Secret>> {
            match get_generic_password(&service(ns), name) {
                Ok(bytes) => {
                    let value = String::from_utf8(bytes)
                        .map_err(|_| anyhow::anyhow!("secret {ns}/{name} is not valid UTF-8"))?;
                    Ok(Some(Secret::new(value)))
                }
                Err(e) if e.code() == ITEM_NOT_FOUND => Ok(None),
                Err(e) => {
                    Err(e).with_context(|| format!("reading secret {ns}/{name} from Keychain"))
                }
            }
        }

        fn set(&self, ns: &str, name: &str, value: &Secret) -> Result<()> {
            set_generic_password(&service(ns), name, value.expose().as_bytes())
                .with_context(|| format!("writing secret {ns}/{name} to Keychain"))
        }

        fn delete(&self, ns: &str, name: &str) -> Result<()> {
            match delete_generic_password(&service(ns), name) {
                Ok(()) => Ok(()),
                Err(e) if e.code() == ITEM_NOT_FOUND => Ok(()),
                Err(e) => {
                    Err(e).with_context(|| format!("deleting secret {ns}/{name} from Keychain"))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(v: &str) -> Secret {
        Secret::new(v.to_string())
    }

    #[test]
    fn memory_store_roundtrip() {
        let store = MemoryStore::default();
        assert!(store.get("ns", "TOKEN").unwrap().is_none());
        store.set("ns", "TOKEN", &secret("abc")).unwrap();
        assert_eq!(store.get("ns", "TOKEN").unwrap().unwrap().expose(), "abc");
        store.set("ns", "TOKEN", &secret("def")).unwrap();
        assert_eq!(store.get("ns", "TOKEN").unwrap().unwrap().expose(), "def");
        store.delete("ns", "TOKEN").unwrap();
        assert!(store.get("ns", "TOKEN").unwrap().is_none());
    }

    #[test]
    fn delete_of_missing_item_is_ok() {
        let store = MemoryStore::default();
        store.delete("ns", "MISSING").unwrap();
    }

    #[test]
    fn namespaces_are_isolated() {
        let store = MemoryStore::default();
        store.set("a", "TOKEN", &secret("one")).unwrap();
        store.set("b", "TOKEN", &secret("two")).unwrap();
        assert_eq!(store.get("a", "TOKEN").unwrap().unwrap().expose(), "one");
        assert_eq!(store.get("b", "TOKEN").unwrap().unwrap().expose(), "two");
        store.delete("a", "TOKEN").unwrap();
        assert!(store.get("a", "TOKEN").unwrap().is_none());
        assert_eq!(store.get("b", "TOKEN").unwrap().unwrap().expose(), "two");
    }

    #[test]
    fn snapshot_lists_all_items_sorted() {
        let store = MemoryStore::default();
        assert!(store.snapshot().is_empty());
        store.set("b", "Y", &secret("2")).unwrap();
        store.set("a", "Z", &secret("3")).unwrap();
        store.set("a", "X", &secret("1")).unwrap();
        assert_eq!(
            store.snapshot(),
            vec![
                ("a".to_string(), "X".to_string(), "1".to_string()),
                ("a".to_string(), "Z".to_string(), "3".to_string()),
                ("b".to_string(), "Y".to_string(), "2".to_string()),
            ]
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "writes to the real login Keychain; run manually"]
    fn mac_keychain_roundtrip() {
        let ns = format!("envy-test-{}", std::process::id());
        let store = MacKeychain;
        assert!(store.get(&ns, "TOKEN").unwrap().is_none());
        store.set(&ns, "TOKEN", &secret("s3cret")).unwrap();
        assert_eq!(store.get(&ns, "TOKEN").unwrap().unwrap().expose(), "s3cret");
        store.set(&ns, "TOKEN", &secret("rotated")).unwrap();
        assert_eq!(
            store.get(&ns, "TOKEN").unwrap().unwrap().expose(),
            "rotated"
        );
        store.delete(&ns, "TOKEN").unwrap();
        assert!(store.get(&ns, "TOKEN").unwrap().is_none());
        store.delete(&ns, "TOKEN").unwrap();
    }
}
