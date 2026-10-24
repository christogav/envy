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
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

use crate::commands::render_var_rows;
use crate::config::{Config, NamespaceFile, Value};
use crate::project::encode_path;

/// A record is 64 hex characters; anything much longer is not one.
const MAX_RECORD_BYTES: u64 = 256;

/// Makes temp record names unique within the process.
static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

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

    /// The stored hash for (`root`, `ns`), or `None` for anything but a
    /// well-formed record: missing, not a regular file (checked on the open
    /// handle, with `O_NOFOLLOW | O_NONBLOCK` so neither a symlink nor a FIFO
    /// can redirect or block the read), oversized, unreadable or malformed.
    fn read_record(&self, root: &Path, ns: &str) -> Option<String> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(self.record_path(root, ns))
            .ok()?;
        if !file.metadata().ok()?.file_type().is_file() {
            return None;
        }
        let mut content = String::new();
        file.take(MAX_RECORD_BYTES)
            .read_to_string(&mut content)
            .ok()?;
        let hash = content.trim_end();
        (hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit())).then(|| hash.to_string())
    }

    /// True only when a record for (`root`, `ns`) exists and approves exactly
    /// `file_text`. A missing, unreadable, oversized, non-regular (symlink
    /// included) or malformed record means untrusted, never an error.
    ///
    /// `root` must be the canonical absolute folder that contains `.envy/`
    /// (`Config::root()`); any other spelling of the same folder simply fails
    /// closed (the user is asked again).
    pub fn is_trusted(&self, root: &Path, ns: &str, file_text: &str) -> Result<bool> {
        debug_assert!(root.is_absolute());
        Ok(self.read_record(root, ns) == Some(sha256_hex(&[file_text.as_bytes()])))
    }

    /// True when a well-formed record exists for (`root`, `ns`), whatever
    /// contents it approved: it tells "changed since you trusted it" from
    /// "never trusted".
    pub fn previously_trusted(&self, root: &Path, ns: &str) -> Result<bool> {
        debug_assert!(root.is_absolute());
        Ok(self.read_record(root, ns).is_some())
    }

    /// Makes sure `<user_dir>/trust` is a real directory (not a symlink or
    /// file) that nobody else can write to; a loose existing mode is
    /// tightened to 0700.
    fn ensure_dir(&self) -> Result<()> {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.dir)
            .with_context(|| format!("cannot create {}", self.dir.display()))?;
        let meta = fs::symlink_metadata(&self.dir)
            .with_context(|| format!("cannot inspect {}", self.dir.display()))?;
        if !meta.file_type().is_dir() {
            bail!(
                "{} is not a directory (is it a symlink or a file?)",
                self.dir.display()
            );
        }
        if meta.permissions().mode() & 0o022 != 0 {
            fs::set_permissions(&self.dir, fs::Permissions::from_mode(0o700))
                .with_context(|| format!("cannot tighten {}", self.dir.display()))?;
        }
        Ok(())
    }

    /// Records that `file_text` was approved for (`root`, `ns`), replacing any
    /// earlier record (a symlink in its place is replaced, never written
    /// through). Written atomically: uniquely named temp file, then rename.
    /// `root` must be canonical and absolute, as for [`TrustStore::is_trusted`].
    pub fn record(&self, root: &Path, ns: &str, file_text: &str) -> Result<()> {
        debug_assert!(root.is_absolute());
        self.ensure_dir()?;
        let path = self.record_path(root, ns);
        let tmp = self.dir.join(format!(
            ".tmp-{}-{}",
            std::process::id(),
            TMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let result = (|| -> Result<()> {
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
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
#[cfg(test)]
pub(crate) fn confirmation_text(
    cfg: &Config,
    file: &NamespaceFile,
    in_keychain: &[String],
) -> String {
    confirmation_text_for(cfg, file, in_keychain, Purpose::Load, false)
}

/// What the user is asked to allow with a project namespace file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    /// Load the variables into the current shell.
    Load,
    /// Copy the names and plain values into a new namespace (`--new --like`).
    Copy,
    /// Change the namespace (`--secret`, `--plain`, `--edit`, `--link`,
    /// `--unlink`) and record the result as trusted.
    Change,
}

/// [`confirmation_text`] for a given purpose: only the closing line differs.
///
/// `new_checkout`: this checkout has never trusted the namespace. Then, when
/// loading or changing, if some of its secrets already exist (saved for the
/// same identity from another checkout), a caution line says to agree only if
/// this folder really is that project: a copied folder with its own `.git`
/// can claim any identity.
pub fn confirmation_text_for(
    cfg: &Config,
    file: &NamespaceFile,
    in_keychain: &[String],
    purpose: Purpose,
    new_checkout: bool,
) -> String {
    let ns = file.name();
    let mut out = match cfg.identity() {
        Some(id) => format!("Project namespace \"{ns}\" from {id}\n"),
        None => format!("Project namespace \"{ns}\"\n"),
    };
    // The checkout path is attacker-controlled (any byte but NUL and `/`), so
    // it is percent-encoded: no control, bidi or tag character, no newline.
    out.push_str(&format!(
        "file: {}\n",
        encode_path(&cfg.dir().join(format!("{ns}.toml")))
    ));
    if let Some(group) = file.link() {
        out.push_str(&format!("link: {group}\n"));
    }
    out.push('\n');
    let vars = file.vars();
    if vars.is_empty() {
        out.push_str("(no variables)\n");
    }
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
    if new_checkout
        && !in_keychain.is_empty()
        && purpose != Purpose::Copy
        && let Some(id) = cfg.identity()
    {
        out.push_str(&format!(
            "\nSome of these secrets were saved for {id} from another checkout; \
             say yes only if this folder really is {id}.\n"
        ));
    }
    out.push_str(match purpose {
        Purpose::Load => "\nAllow envy to load these variables into your current shell",
        Purpose::Copy => "\nAllow envy to copy these names and plain values into a new namespace",
        Purpose::Change => "\nAllow envy to change this namespace, and trust the result",
    });
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
    fn confirmation_closing_line_names_the_purpose() {
        let (_root, _user, cfg) = project_cfg(&[("dev", "[vars]\nA = \"1\"\n")], "acme/api");
        let file = cfg.load("dev").unwrap();
        let load = confirmation_text_for(&cfg, &file, &[], Purpose::Load, false);
        let copy = confirmation_text_for(&cfg, &file, &[], Purpose::Copy, false);
        assert_eq!(load, confirmation_text(&cfg, &file, &[]));
        assert!(load.ends_with("\n\nAllow envy to load these variables into your current shell"));
        assert!(
            copy.ends_with(
                "\n\nAllow envy to copy these names and plain values into a new namespace"
            )
        );
        assert!(!copy.contains('?') && !copy.contains("[y/N]"));
        assert_eq!(
            load.rsplit_once("\n\n").unwrap().0,
            copy.rsplit_once("\n\n").unwrap().0
        );
        let change = confirmation_text_for(&cfg, &file, &[], Purpose::Change, false);
        assert_eq!(
            change.rsplit_once("\n\n").unwrap(),
            (
                load.rsplit_once("\n\n").unwrap().0,
                "Allow envy to change this namespace, and trust the result"
            )
        );
        assert!(!change.contains('?') && !change.contains("[y/N]"));
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

    #[test]
    fn hostile_checkout_path_is_escaped_in_the_file_line() {
        use std::os::unix::ffi::OsStrExt;
        let user = tempfile::tempdir().unwrap();
        let root = PathBuf::from(std::ffi::OsStr::from_bytes(
            "/work/evil\x1b[2J\nfile: /safe/path\x1b]0;x\x07\u{202e}\u{e0041}".as_bytes(),
        ));
        let cfg = Config::project(
            root.join(".envy"),
            root.clone(),
            "acme/api".into(),
            user.path().to_path_buf(),
        );
        let file = NamespaceFile::parse("dev", "[vars]\nA = \"1\"\n").unwrap();
        let text = confirmation_text(&cfg, &file, &[]);
        assert!(
            !text.chars().any(|c| c.is_control() && c != '\n'),
            "{text:?}"
        );
        assert!(!text.contains('\u{202e}') && !text.contains('\u{e0041}'));
        assert_eq!(text.lines().filter(|l| l.starts_with("file:")).count(), 1);
        let line = text.lines().nth(1).unwrap();
        assert_eq!(
            line,
            "file: /work/evil%1B%5B2J%0Afile%3A /safe/path%1B%5D0%3Bx%07%E2%80%AE%F3%A0%81%81/.envy/dev.toml"
        );
    }

    #[test]
    fn empty_namespace_says_no_variables() {
        let (_root, _user, cfg) = project_cfg(&[("dev", "")], "acme/api");
        let file = cfg.load("dev").unwrap();
        let text = confirmation_text(&cfg, &file, &[]);
        assert!(text.contains("\n\n(no variables)\n"), "{text:?}");
        assert!(!text.contains("\n\n\n"));
    }

    #[test]
    fn previously_trusted_tells_changed_from_never() {
        let user = tempfile::tempdir().unwrap();
        let store = TrustStore::new(user.path());
        let root = Path::new("/work/api");
        assert!(!store.is_trusted(root, "dev", "A").unwrap());
        assert!(!store.previously_trusted(root, "dev").unwrap());
        store.record(root, "dev", "A").unwrap();
        assert!(store.previously_trusted(root, "dev").unwrap());
        assert!(!store.is_trusted(root, "dev", "B").unwrap());
        assert!(
            !store
                .previously_trusted(Path::new("/other"), "dev")
                .unwrap()
        );
        assert!(!store.previously_trusted(root, "prod").unwrap());
        // A malformed record is not "previously trusted".
        fs::write(store.record_path(root, "dev"), "garbage").unwrap();
        assert!(!store.previously_trusted(root, "dev").unwrap());
    }

    #[test]
    fn a_fifo_record_is_untrusted_without_hanging() {
        let user = tempfile::tempdir().unwrap();
        let store = TrustStore::new(user.path());
        let root = Path::new("/work/api");
        fs::create_dir(user.path().join("trust")).unwrap();
        let p =
            std::ffi::CString::new(store.record_path(root, "dev").as_os_str().as_bytes()).unwrap();
        // SAFETY: `p` is a valid NUL-terminated string.
        assert_eq!(unsafe { libc::mkfifo(p.as_ptr(), 0o600) }, 0);
        assert!(!store.is_trusted(root, "dev", "A").unwrap());
        assert!(!store.previously_trusted(root, "dev").unwrap());
    }

    #[test]
    fn a_regular_file_named_trust_is_untrusted_and_record_errors() {
        let user = tempfile::tempdir().unwrap();
        fs::write(user.path().join("trust"), "x").unwrap();
        let store = TrustStore::new(user.path());
        let root = Path::new("/work/api");
        assert!(!store.is_trusted(root, "dev", "A").unwrap());
        assert!(store.record(root, "dev", "A").is_err());
    }

    #[test]
    fn a_symlinked_trust_dir_is_refused() {
        let user = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(elsewhere.path(), user.path().join("trust")).unwrap();
        let store = TrustStore::new(user.path());
        assert!(store.record(Path::new("/work/api"), "dev", "A").is_err());
        assert_eq!(fs::read_dir(elsewhere.path()).unwrap().count(), 0);
    }

    #[test]
    fn record_replaces_a_symlinked_record_without_writing_through() {
        let user = tempfile::tempdir().unwrap();
        let store = TrustStore::new(user.path());
        let root = Path::new("/work/api");
        store.record(root, "dev", "A").unwrap();
        let path = store.record_path(root, "dev");
        let target = user.path().join("target");
        fs::write(&target, "untouched").unwrap();
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        store.record(root, "dev", "B").unwrap();
        assert_eq!(fs::read_to_string(&target).unwrap(), "untouched");
        assert!(
            !fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(store.is_trusted(root, "dev", "B").unwrap());
    }

    #[test]
    fn a_loose_existing_trust_dir_is_tightened() {
        use std::os::unix::fs::PermissionsExt;
        let user = tempfile::tempdir().unwrap();
        let dir = user.path().join("trust");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o777)).unwrap();
        TrustStore::new(user.path())
            .record(Path::new("/work/api"), "dev", "A")
            .unwrap();
        assert_eq!(
            fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    #[test]
    fn concurrent_records_of_one_key_all_succeed() {
        let user = tempfile::tempdir().unwrap();
        let store = std::sync::Arc::new(TrustStore::new(user.path()));
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let s = store.clone();
                std::thread::spawn(move || {
                    for _ in 0..20 {
                        s.record(Path::new("/work/api"), "dev", "A").unwrap();
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        assert!(
            store
                .is_trusted(Path::new("/work/api"), "dev", "A")
                .unwrap()
        );
        assert_eq!(fs::read_dir(user.path().join("trust")).unwrap().count(), 1);
    }

    #[test]
    fn a_new_checkout_with_existing_secrets_gets_a_caution_line() {
        let (_root, _user, cfg) = project_cfg(
            &[(
                "dev",
                "[vars]\nAPI_TOKEN = \"@keychain\"\nDB_PASS = \"@keychain\"\n",
            )],
            "acme/api",
        );
        let file = cfg.load("dev").unwrap();
        let have = ["API_TOKEN".to_string()];
        let text = confirmation_text_for(&cfg, &file, &have, Purpose::Load, true);
        let expected = format!(
            "Project namespace \"dev\" from acme/api\n\
             file: {}\n\
             \n\
             API_TOKEN  @keychain\n\
             DB_PASS    @keychain\n\
             secret API_TOKEN: already in your Keychain\n\
             secret DB_PASS: you will be asked for it\n\
             \n\
             Some of these secrets were saved for acme/api from another checkout; say yes only if this folder really is acme/api.\n\
             \n\
             Allow envy to load these variables into your current shell",
            encode_path(&cfg.dir().join("dev.toml"))
        );
        assert_eq!(text, expected);
        let caution = "Some of these secrets were saved for acme/api";
        let change = confirmation_text_for(&cfg, &file, &have, Purpose::Change, true);
        assert!(change.contains(caution), "{change}");
        // Not when copying, not when nothing exists yet, not when this
        // checkout trusted the file before (it changed since).
        for text in [
            confirmation_text_for(&cfg, &file, &have, Purpose::Copy, true),
            confirmation_text_for(&cfg, &file, &[], Purpose::Load, true),
            confirmation_text_for(&cfg, &file, &have, Purpose::Load, false),
        ] {
            assert!(!text.contains(caution), "{text}");
        }
        assert_eq!(
            confirmation_text_for(&cfg, &file, &have, Purpose::Load, false),
            confirmation_text(&cfg, &file, &have)
        );
    }
}
