//! Local trust records for project namespaces, and the text shown before a
//! project namespace is loaded for the first time.
//!
//! A project namespace comes from a repository the user did not necessarily
//! write, so envy asks before loading it. An answer of yes is remembered as a
//! hash of the file's text, per checkout location and namespace, under
//! `<user_dir>/trust/`. Records hold only hashes: no identity, no URL, no
//! secret.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

use crate::commands::render_var_rows;
use crate::config::{Config, NamespaceFile, Value};

/// A record is 64 hex characters; anything much longer is not one.
const MAX_RECORD_BYTES: u64 = 256;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sha256_hex(parts: &[&[u8]]) -> String {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    hex(&h.finalize())
}

/// The user's trust records. Trust is keyed by the canonical checkout root and
/// the namespace, and holds the hash of the text that was approved.
pub struct TrustStore {
    dir: PathBuf,
}

impl TrustStore {
    pub fn new(user_dir: &Path) -> TrustStore {
        TrustStore {
            dir: user_dir.join("trust"),
        }
    }

    /// The record's file name: the hash of `root`, a NUL, and `ns`. NUL cannot
    /// occur in a path or a namespace name, so two pairs never share a key.
    fn record_path(&self, root: &Path, ns: &str) -> PathBuf {
        let key = sha256_hex(&[root.as_os_str().as_bytes(), &[0], ns.as_bytes()]);
        self.dir.join(key)
    }

    /// True only when a record for (`root`, `ns`) exists and approves exactly
    /// `file_text`. A missing, unreadable, oversized, non-regular (symlink
    /// included) or malformed record means untrusted, never an error.
    pub fn is_trusted(&self, root: &Path, ns: &str, file_text: &str) -> Result<bool> {
        let path = self.record_path(root, ns);
        let Ok(meta) = fs::symlink_metadata(&path) else {
            return Ok(false);
        };
        if !meta.file_type().is_file() {
            return Ok(false);
        }
        let Ok(file) = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
        else {
            return Ok(false);
        };
        let mut content = String::new();
        if file
            .take(MAX_RECORD_BYTES)
            .read_to_string(&mut content)
            .is_err()
        {
            return Ok(false);
        }
        Ok(content.trim_end() == sha256_hex(&[file_text.as_bytes()]))
    }

    /// Records that `file_text` was approved for (`root`, `ns`), replacing any
    /// earlier record. Written atomically: temp file, then rename.
    pub fn record(&self, root: &Path, ns: &str, file_text: &str) -> Result<()> {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.dir)
            .with_context(|| format!("cannot create {}", self.dir.display()))?;
        let path = self.record_path(root, ns);
        let tmp = self.dir.join(format!(
            ".tmp-{}-{}",
            std::process::id(),
            sha256_hex(&[path.as_os_str().as_bytes()])
        ));
        let result = (|| -> Result<()> {
            let mut f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&tmp)
                .context("cannot write trust record")?;
            f.write_all(sha256_hex(&[file_text.as_bytes()]).as_bytes())?;
            f.sync_all()?;
            fs::rename(&tmp, &path).context("cannot save trust record")?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        result
    }
}

/// What the user is shown before a project namespace is loaded for the first
/// time (or after it changed): where it comes from, exactly what it sets, and
/// which secrets it reads. `in_keychain` holds secret variable NAMES already in
/// the Keychain; no value can reach this function. The text ends without a
/// question mark: the prompter appends `[y/N]: `.
pub fn confirmation_text(cfg: &Config, file: &NamespaceFile, in_keychain: &[String]) -> String {
    let ns = file.name();
    let mut out = match cfg.identity() {
        Some(id) => format!("Project namespace \"{ns}\" from {id}\n"),
        None => format!("Project namespace \"{ns}\"\n"),
    };
    out.push_str(&format!(
        "file: {}\n",
        cfg.dir().join(format!("{ns}.toml")).display()
    ));
    if let Some(group) = file.link() {
        out.push_str(&format!("link: {group}\n"));
    }
    out.push('\n');
    let vars = file.vars();
    out.push_str(&render_var_rows(&vars));
    for (name, value) in &vars {
        if matches!(value, Value::Secret) {
            if in_keychain.iter().any(|n| n == name) {
                out.push_str(&format!("secret {name}: already in your Keychain\n"));
            } else {
                out.push_str(&format!("secret {name}: you will be asked for it\n"));
            }
        }
    }
    out.push_str("\nAllow envy to load these variables into your current shell");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::project::identity_from_url;
    use crate::store::{MemoryStore, SecretStore};

    fn project_cfg(
        files: &[(&str, &str)],
        identity: &str,
    ) -> (tempfile::TempDir, tempfile::TempDir, Config) {
        let root = tempfile::tempdir().unwrap();
        let user = tempfile::tempdir().unwrap();
        let dir = root.path().join(".envy");
        fs::create_dir(&dir).unwrap();
        for (n, t) in files {
            fs::write(dir.join(format!("{n}.toml")), t).unwrap();
        }
        let cfg = Config::project(
            dir,
            root.path().to_path_buf(),
            identity.to_string(),
            user.path().to_path_buf(),
        );
        (root, user, cfg)
    }

    #[test]
    fn record_then_trusted() {
        let user = tempfile::tempdir().unwrap();
        let store = TrustStore::new(user.path());
        let root = Path::new("/work/api");
        assert!(!store.is_trusted(root, "dev", "A = 1").unwrap());
        store.record(root, "dev", "A = 1").unwrap();
        assert!(store.is_trusted(root, "dev", "A = 1").unwrap());
        // Other namespace, same root: untrusted.
        assert!(!store.is_trusted(root, "prod", "A = 1").unwrap());
    }

    #[test]
    fn changed_contents_are_not_trusted() {
        let user = tempfile::tempdir().unwrap();
        let store = TrustStore::new(user.path());
        let root = Path::new("/work/api");
        store.record(root, "dev", "A = 1").unwrap();
        assert!(!store.is_trusted(root, "dev", "A = 2").unwrap());
        // Recording the new text replaces the old record.
        store.record(root, "dev", "A = 2").unwrap();
        assert!(store.is_trusted(root, "dev", "A = 2").unwrap());
        assert!(!store.is_trusted(root, "dev", "A = 1").unwrap());
    }

    #[test]
    fn trust_is_bound_to_the_checkout_path() {
        let user = tempfile::tempdir().unwrap();
        let store = TrustStore::new(user.path());
        store
            .record(Path::new("/work/api"), "dev", "A = 1")
            .unwrap();
        assert!(
            !store
                .is_trusted(Path::new("/elsewhere/api"), "dev", "A = 1")
                .unwrap()
        );
    }

    #[test]
    fn root_and_namespace_cannot_collide() {
        let user = tempfile::tempdir().unwrap();
        let store = TrustStore::new(user.path());
        store.record(Path::new("/a/b"), "c", "T").unwrap();
        assert!(!store.is_trusted(Path::new("/a"), "b/c", "T").unwrap());
        assert!(!store.is_trusted(Path::new("/a/b/c"), "", "T").unwrap());
    }

    #[test]
    fn bad_records_mean_untrusted_not_errors() {
        use std::os::unix::fs::symlink;
        let user = tempfile::tempdir().unwrap();
        let store = TrustStore::new(user.path());
        let root = Path::new("/work/api");
        store.record(root, "dev", "A = 1").unwrap();
        let path = store.record_path(root, "dev");
        fs::write(&path, "garbage").unwrap();
        assert!(!store.is_trusted(root, "dev", "A = 1").unwrap());
        fs::write(&path, vec![b'a'; 100_000]).unwrap();
        assert!(!store.is_trusted(root, "dev", "A = 1").unwrap());
        fs::write(&path, [0xff, 0xfe]).unwrap();
        assert!(!store.is_trusted(root, "dev", "A = 1").unwrap());
        // A symlink to a valid record elsewhere is not followed.
        let good = user.path().join("good");
        fs::write(&good, sha256_hex(&[b"A = 1"])).unwrap();
        fs::remove_file(&path).unwrap();
        symlink(&good, &path).unwrap();
        assert!(!store.is_trusted(root, "dev", "A = 1").unwrap());
        // A directory in its place is untrusted too.
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(!store.is_trusted(root, "dev", "A = 1").unwrap());
    }

    #[test]
    fn record_permissions_and_no_temp_left() {
        use std::os::unix::fs::PermissionsExt;
        let user = tempfile::tempdir().unwrap();
        let store = TrustStore::new(user.path());
        store
            .record(Path::new("/work/api"), "dev", "A = 1")
            .unwrap();
        let dir = user.path().join("trust");
        assert_eq!(
            fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let entries: Vec<_> = fs::read_dir(&dir).unwrap().map(|e| e.unwrap()).collect();
        assert_eq!(entries.len(), 1);
        let mode = entries[0].metadata().unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn trust_records_do_not_appear_as_namespaces() {
        let user = tempfile::tempdir().unwrap();
        fs::write(user.path().join("work.toml"), "[vars]\n").unwrap();
        let cfg = Config::new(user.path().to_path_buf());
        let before = cfg.list().unwrap();
        TrustStore::new(user.path())
            .record(Path::new("/work/api"), "dev", "A = 1")
            .unwrap();
        assert_eq!(cfg.list().unwrap(), before);
        assert_eq!(before, vec!["work".to_string()]);
    }

    #[test]
    fn trust_files_and_confirmation_never_contain_credentials() {
        let id = identity_from_url("https://user:s3cr3tTOKEN@github.com/acme/api.git").unwrap();
        assert!(!id.contains("s3cr3tTOKEN"));
        let (root, user, cfg) =
            project_cfg(&[("dev", "[vars]\nA = \"1\"\nT = \"@keychain\"\n")], &id);
        let file = cfg.load("dev").unwrap();
        let text = confirmation_text(&cfg, &file, &[]);
        assert!(!text.contains("s3cr3tTOKEN") && !text.contains("user:"));
        let store = TrustStore::new(user.path());
        store.record(root.path(), "dev", &file.text()).unwrap();
        for e in fs::read_dir(user.path().join("trust")).unwrap() {
            let e = e.unwrap();
            let name = e.file_name().to_string_lossy().into_owned();
            let content = fs::read_to_string(e.path()).unwrap();
            for s in [&name, &content] {
                assert!(s.chars().all(|c| c.is_ascii_hexdigit()), "{s}");
                assert!(!s.contains("s3cr3tTOKEN") && !s.contains(&id));
            }
        }
    }

    #[test]
    fn confirmation_text_is_exact() {
        let (_root, _user, cfg) = project_cfg(
            &[(
                "dev",
                "link = \"aws\"\n[vars]\nREGION = \"eu-west-1\"\nAPI_TOKEN = \"@keychain\"\nLOG = \"debug\"\nDB_PASS = \"@keychain\"\n",
            )],
            "acme/api",
        );
        let file = cfg.load("dev").unwrap();
        let text = confirmation_text(&cfg, &file, &["API_TOKEN".to_string()]);
        let path = cfg.dir().join("dev.toml");
        let expected = format!(
            "Project namespace \"dev\" from acme/api\n\
             file: {}\n\
             link: aws\n\
             \n\
             REGION     \"eu-west-1\"\n\
             API_TOKEN  @keychain\n\
             LOG        \"debug\"\n\
             DB_PASS    @keychain\n\
             secret API_TOKEN: already in your Keychain\n\
             secret DB_PASS: you will be asked for it\n\
             \n\
             Allow envy to load these variables into your current shell",
            path.display()
        );
        assert_eq!(text, expected);
        assert!(!text.contains('?') && !text.contains("[y/N]"));
    }

    #[test]
    fn confirmation_omits_link_when_unlinked() {
        let (_root, _user, cfg) = project_cfg(&[("dev", "[vars]\nA = \"1\"\n")], "acme/api");
        let file = cfg.load("dev").unwrap();
        assert!(!confirmation_text(&cfg, &file, &[]).contains("link:"));
    }

    #[test]
    fn confirmation_escapes_hostile_values() {
        let (_root, _user, cfg) = project_cfg(
            &[(
                "dev",
                "[vars]\nA = \"x\\u001b[31mred\\U000E0041\\u202e\"\nS = \"@keychain\"\n",
            )],
            "acme/api",
        );
        // A secret value lives in a store; the function cannot see it.
        let store = MemoryStore::default();
        store
            .set(
                &cfg.secret_key("dev"),
                "S",
                &crate::secret::Secret::new("TOPSECRETVALUE".into()),
            )
            .unwrap();
        let file = cfg.load("dev").unwrap();
        let text = confirmation_text(&cfg, &file, &["S".to_string()]);
        assert!(
            text.contains("A  \"x\\u{1b}[31mred\\u{e0041}\\u{202e}\""),
            "{text}"
        );
        assert!(!text.chars().any(|c| c.is_control() && c != '\n'));
        assert!(!text.contains("TOPSECRETVALUE"));
    }
}
