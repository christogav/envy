use std::ffi::OsString;
use std::fs;
use std::io::{ErrorKind, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, bail};
use toml_edit::{DocumentMut, Item, Table, TableLike};

use crate::names::{validate_namespace, validate_var};

/// The value that marks a variable as a secret stored in the Keychain.
pub const SECRET_MARKER: &str = "@keychain";

/// A variable as declared in a namespace file. Plain values are stored in the
/// file; secrets only carry the marker, never the secret itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Secret,
    Plain(String),
}

/// One parsed namespace file. Wraps the TOML document so that comments and
/// ordering survive edits.
#[derive(Clone, Debug)]
pub struct NamespaceFile {
    name: String,
    /// The string the `SecretStore` is called with. Not part of the TOML.
    secret_key: String,
    doc: DocumentMut,
}

impl NamespaceFile {
    pub fn empty(name: &str) -> Result<Self> {
        validate_namespace(name)?;
        Ok(Self {
            name: name.to_string(),
            secret_key: name.to_string(),
            doc: DocumentMut::new(),
        })
    }

    /// Parses and validates a namespace file. Never panics on bad input and
    /// never echoes file contents (values) in errors.
    pub fn parse(name: &str, text: &str) -> Result<Self> {
        validate_namespace(name)?;
        let doc: DocumentMut = text.parse().map_err(|e: toml_edit::TomlError| {
            // Deliberately omit the Display form: it quotes the offending line.
            match e.span() {
                Some(span) => {
                    let end = span.start.min(text.len());
                    let line = text.as_bytes()[..end]
                        .iter()
                        .filter(|&&b| b == b'\n')
                        .count()
                        + 1;
                    anyhow::anyhow!(
                        "namespace {name:?}: invalid TOML at line {line}: {}",
                        e.message()
                    )
                }
                None => anyhow::anyhow!("namespace {name:?}: invalid TOML: {}", e.message()),
            }
        })?;

        if let Some(link) = doc.get("link") {
            let Some(label) = link.as_str() else {
                bail!("namespace {name:?}: `link` must be a string");
            };
            validate_namespace(label)
                .with_context(|| format!("namespace {name:?}: invalid `link` label"))?;
        }
        if let Some(vars) = doc.get("vars") {
            let Some(table) = vars.as_table_like() else {
                bail!("namespace {name:?}: `vars` must be a table");
            };
            for (key, item) in table.iter() {
                validate_var(key)
                    .with_context(|| format!("namespace {name:?}: invalid variable"))?;
                if item.as_str().is_none() {
                    bail!("namespace {name:?}: variable {key:?} must be a string");
                }
            }
        }
        Ok(Self {
            name: name.to_string(),
            secret_key: name.to_string(),
            doc,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// The key this namespace's secrets are filed under in the secret store:
    /// the name at user level, `project/<identity>/<name>` in a project.
    pub fn secret_key(&self) -> &str {
        &self.secret_key
    }

    /// The TOML text, with the user's comments and ordering intact.
    pub fn text(&self) -> String {
        self.doc.to_string()
    }

    pub fn link(&self) -> Option<&str> {
        self.doc.get("link").and_then(Item::as_str)
    }

    /// Sets or removes the `link` label. Comments survive both ways: removing
    /// the key keeps the comment lines above it and its inline comment (as a
    /// line of its own) where they were; adding it as the first line of the
    /// file puts it below a header comment (one followed by a blank line)
    /// rather than above it.
    pub fn set_link(&mut self, label: Option<&str>) -> Result<()> {
        match label {
            None => remove_link(&mut self.doc),
            Some(label) => {
                validate_namespace(label)?;
                if self.link().is_none() {
                    add_link(&mut self.doc, label);
                } else {
                    set_string(self.doc.as_table_mut(), "link", label);
                }
            }
        }
        Ok(())
    }

    /// Variables in file order.
    pub fn vars(&self) -> Vec<(String, Value)> {
        let Some(table) = self.doc.get("vars").and_then(Item::as_table_like) else {
            return Vec::new();
        };
        table
            .iter()
            .filter_map(|(k, item)| Some((k.to_string(), to_value(item.as_str()?))))
            .collect()
    }

    pub fn get(&self, name: &str) -> Option<Value> {
        let table = self.doc.get("vars")?.as_table_like()?;
        Some(to_value(table.get(name)?.as_str()?))
    }

    pub fn set_var(&mut self, name: &str, value: Value) -> Result<()> {
        validate_var(name)?;
        let text = match &value {
            Value::Secret => SECRET_MARKER,
            Value::Plain(v) if v == SECRET_MARKER => {
                bail!(
                    "variable {name:?}: the plain value {SECRET_MARKER:?} is reserved for secrets"
                )
            }
            Value::Plain(v) => v.as_str(),
        };
        let item = self
            .doc
            .as_table_mut()
            .entry("vars")
            .or_insert(Item::Table(Table::new()));
        let Some(table) = item.as_table_like_mut() else {
            bail!("namespace {:?}: `vars` must be a table", self.name);
        };
        set_string(table, name, text);
        Ok(())
    }

    /// Returns whether the variable was present.
    pub fn remove_var(&mut self, name: &str) -> bool {
        self.doc
            .get_mut("vars")
            .and_then(Item::as_table_like_mut)
            .is_some_and(|t| t.remove(name).is_some())
    }
}

fn to_value(s: &str) -> Value {
    if s == SECRET_MARKER {
        Value::Secret
    } else {
        Value::Plain(s.to_string())
    }
}

/// Sets a string entry. An existing entry is updated in place so its key (with
/// the comments and indentation above it) and its inline comment survive.
fn set_string(table: &mut dyn TableLike, key: &str, text: &str) {
    let mut new = toml_edit::Value::from(text);
    match table.get_mut(key) {
        Some(item) => {
            if let Some(old) = item.as_value() {
                *new.decor_mut() = old.decor().clone();
            }
            *item = Item::Value(new);
        }
        None => {
            table.insert(key, Item::Value(new));
        }
    }
}

/// Whether a top-level entry is printed among the top-level key/value lines
/// (rather than as a `[table]` after them).
fn prints_as_line(item: &Item) -> bool {
    match item {
        Item::Value(_) => true,
        Item::Table(t) => t.is_dotted(),
        _ => false,
    }
}

/// Where the text printed right after a top-level key lives: the prefix of
/// the next key line, of the first `[table]`, or the document's trailing text.
enum Spot {
    Key(String),
    Table(String),
    Trailing,
}

/// The spot printed after the top-level lines up to entry `from`. `None` for
/// layouts this does not handle (dotted keys, arrays of tables, hidden
/// implicit tables).
fn spot_after(root: &Table, from: usize) -> Option<Spot> {
    for (key, item) in root.iter().skip(from) {
        match item {
            Item::Value(_) => return Some(Spot::Key(key.to_string())),
            Item::Table(t) if t.is_dotted() => return None,
            _ => {}
        }
    }
    let mut first: Option<(isize, &str, &Table)> = None;
    for (key, item) in root.iter() {
        match item {
            Item::Table(t) => {
                let pos = t.position().unwrap_or(0);
                if first.is_none_or(|(p, _, _)| pos < p) {
                    first = Some((pos, key, t));
                }
            }
            Item::ArrayOfTables(_) => return None,
            _ => {}
        }
    }
    match first {
        None => Some(Spot::Trailing),
        Some((_, _, t)) if t.is_implicit() && t.get_values().is_empty() => None,
        Some((_, key, _)) => Some(Spot::Table(key.to_string())),
    }
}

fn raw_text(raw: Option<&toml_edit::RawString>) -> &str {
    raw.and_then(toml_edit::RawString::as_str).unwrap_or("")
}

fn spot_text(doc: &DocumentMut, spot: &Spot) -> String {
    let text = match spot {
        Spot::Key(k) => doc
            .as_table()
            .key(k)
            .map(|k| raw_text(k.leaf_decor().prefix())),
        Spot::Table(k) => doc
            .get(k)
            .and_then(Item::as_table)
            .map(|t| raw_text(t.decor().prefix())),
        Spot::Trailing => doc.trailing().as_str(),
    };
    text.unwrap_or("").to_string()
}

fn set_spot_text(doc: &mut DocumentMut, spot: &Spot, text: String) {
    match spot {
        Spot::Key(k) => {
            if let Some(mut key) = doc.as_table_mut().key_mut(k) {
                key.leaf_decor_mut().set_prefix(text);
            }
        }
        Spot::Table(k) => {
            if let Some(t) = doc.get_mut(k).and_then(Item::as_table_mut) {
                t.decor_mut().set_prefix(text);
            }
        }
        Spot::Trailing => doc.set_trailing(text),
    }
}

/// Whether the last line of `s` is blank.
fn ends_with_blank_line(s: &str) -> bool {
    s.split_inclusive('\n')
        .next_back()
        .is_some_and(|line| line.ends_with('\n') && line.trim().is_empty())
}

fn strip_leading_blank_lines(s: &str) -> &str {
    let mut rest = s;
    while let Some(line) = rest.split_inclusive('\n').next() {
        if !(line.ends_with('\n') && line.trim().is_empty()) {
            break;
        }
        rest = &rest[line.len()..];
    }
    rest
}

/// Splits `s` after its last blank line: a header, and the comment lines
/// directly attached to what follows.
fn split_after_last_blank_line(s: &str) -> (&str, &str) {
    let mut cut = 0;
    let mut end = 0;
    for line in s.split_inclusive('\n') {
        end += line.len();
        if line.ends_with('\n') && line.trim().is_empty() {
            cut = end;
        }
    }
    s.split_at(cut)
}

/// Adds `link` after the existing top-level lines. When it becomes the first
/// line of the file, a header comment (everything up to the last blank line
/// before the first table) moves above it, so the header stays at the top
/// and comments attached to that table stay with it.
fn add_link(doc: &mut DocumentMut, label: &str) {
    let first = !doc.as_table().iter().any(|(_, item)| prints_as_line(item));
    set_string(doc.as_table_mut(), "link", label);
    if !first {
        return;
    }
    let len = doc.as_table().len();
    let Some(spot) = spot_after(doc.as_table(), len) else {
        return;
    };
    let text = spot_text(doc, &spot);
    let (header, attached) = split_after_last_blank_line(&text);
    if header.is_empty() {
        return;
    }
    let (header, attached) = (header.to_string(), attached.to_string());
    set_spot_text(doc, &spot, attached);
    if let Some(mut key) = doc.as_table_mut().key_mut("link") {
        key.leaf_decor_mut().set_prefix(header);
    }
}

/// Removes `link`, moving the comment lines above it and its inline comment
/// onto whatever is printed next, so no comment is lost. A blank line that
/// only separated `link` from what follows is dropped with it.
fn remove_link(doc: &mut DocumentMut) {
    let Some(index) = doc.as_table().iter().position(|(k, _)| k == "link") else {
        return;
    };
    let first = !doc
        .as_table()
        .iter()
        .take(index)
        .any(|(_, item)| prints_as_line(item));
    let Some((key, item)) = doc.as_table_mut().remove_entry("link") else {
        return;
    };
    // The comment lines above the key, without the key line's indentation.
    let mut moved = raw_text(key.leaf_decor().prefix())
        .trim_end_matches([' ', '\t'])
        .to_string();
    if let Some(value) = item.as_value() {
        let inline = raw_text(value.decor().suffix()).trim();
        if !inline.is_empty() {
            moved.push_str(inline);
            moved.push('\n');
        }
    }
    let strip = if moved.is_empty() {
        first
    } else {
        ends_with_blank_line(&moved)
    };
    // Layouts `spot_after` does not handle keep the text at the end instead.
    let spot = spot_after(doc.as_table(), index).unwrap_or(Spot::Trailing);
    let old = spot_text(doc, &spot);
    let rest = if strip {
        strip_leading_blank_lines(&old)
    } else {
        &old
    };
    if moved.is_empty() && rest.len() == old.len() {
        return; // nothing to move: keep the spot's default formatting
    }
    let text = format!("{moved}{rest}");
    set_spot_text(doc, &spot, text);
}

/// The directory of namespace files.
#[derive(Clone, Debug)]
pub struct Config {
    dir: PathBuf,
    project: Option<ProjectInfo>,
}

/// What makes a `Config` project-level.
#[derive(Clone, Debug)]
struct ProjectInfo {
    root: PathBuf,
    identity: String,
    user_dir: PathBuf,
}

impl Config {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir, project: None }
    }

    /// The caller must already have validated `identity` (`project::identity_for_root`
    /// guarantees it); it is used verbatim in secret keys.
    ///
    /// A project's `.envy` directory (`dir`) inside `root`, whose secrets are
    /// filed under `identity`. `user_dir` is the user's own config directory.
    pub fn project(dir: PathBuf, root: PathBuf, identity: String, user_dir: PathBuf) -> Self {
        Self {
            dir,
            project: Some(ProjectInfo {
                root,
                identity,
                user_dir,
            }),
        }
    }

    pub fn is_project(&self) -> bool {
        self.project.is_some()
    }

    pub fn identity(&self) -> Option<&str> {
        self.project.as_ref().map(|p| p.identity.as_str())
    }

    pub fn root(&self) -> Option<&Path> {
        self.project.as_ref().map(|p| p.root.as_path())
    }

    /// The user's config directory (`dir()` for a user-level config).
    pub fn user_dir(&self) -> &Path {
        self.project.as_ref().map_or(&self.dir, |p| &p.user_dir)
    }

    /// The secret-store key for namespace `ns` in this config.
    pub fn secret_key(&self, ns: &str) -> String {
        match &self.project {
            Some(p) => format!("project/{}/{ns}", p.identity),
            None => ns.to_string(),
        }
    }

    /// `ENVY_CONFIG_DIR` if set (and non-empty; it must be absolute), else
    /// `$HOME/.config/envy`.
    pub fn from_env() -> Result<Self> {
        Ok(Self::new(dir_from_env(
            std::env::var_os("ENVY_CONFIG_DIR"),
            std::env::var_os("HOME"),
        )?))
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Namespace names become file names, so validate before building a path.
    fn path_for(&self, name: &str) -> Result<PathBuf> {
        validate_namespace(name)?;
        Ok(self.dir.join(format!("{name}.toml")))
    }

    /// Sorted names of the namespace files; stray files are ignored.
    pub fn list(&self) -> Result<Vec<String>> {
        self.list_names(true)
    }

    /// Like `list`, but includes every `*.toml` entry with a valid namespace
    /// stem whatever its type (directory, symlink, ...). Project levels use
    /// this so a bad entry is reported instead of hidden.
    pub fn list_present(&self) -> Result<Vec<String>> {
        self.list_names(false)
    }

    fn list_names(&self, files_only: bool) -> Result<Vec<String>> {
        let entries = match fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e).context("cannot read the envy config directory"),
        };
        let mut names = Vec::new();
        for entry in entries {
            let entry = entry.context("cannot read the envy config directory")?;
            let file_name = entry.file_name();
            let Some(stem) = file_name.to_str().and_then(|n| n.strip_suffix(".toml")) else {
                continue;
            };
            if validate_namespace(stem).is_ok() && (!files_only || entry.path().is_file()) {
                names.push(stem.to_string());
            }
        }
        names.sort();
        Ok(names)
    }

    pub fn exists(&self, name: &str) -> Result<bool> {
        let path = self.path_for(name)?;
        match fs::metadata(&path) {
            Ok(meta) => Ok(meta.is_file()),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e).with_context(|| format!("cannot access namespace {name:?}")),
        }
    }

    /// Whether any directory entry exists for `name` (a file, directory,
    /// dangling symlink, ...). Unlike `exists` it never follows symlinks, so
    /// project levels use it to fail closed on anything odd.
    pub fn present(&self, name: &str) -> Result<bool> {
        let path = self.path_for(name)?;
        match fs::symlink_metadata(&path) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e).with_context(|| format!("cannot access namespace {name:?}")),
        }
    }

    pub fn load(&self, name: &str) -> Result<NamespaceFile> {
        let path = self.path_for(name)?;
        let project = self.is_project();
        if project && fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_symlink()) {
            bail!(
                "refusing project namespace {name:?} ({}): it is a symlink",
                path.display()
            );
        }
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) if e.kind() == ErrorKind::NotFound => {
                bail!("namespace {name:?} does not exist (use --new to create it)")
            }
            Err(e) if project => {
                return Err(e).with_context(|| {
                    format!(
                        "cannot read project namespace {name:?} ({})",
                        path.display()
                    )
                });
            }
            Err(e) => return Err(e).with_context(|| format!("cannot read namespace {name:?}")),
        };
        let mut file = if project {
            NamespaceFile::parse(name, &text)
                .map_err(|e| anyhow::anyhow!("{e} ({})", path.display()))?
        } else {
            NamespaceFile::parse(name, &text)?
        };
        file.secret_key = self.secret_key(name);
        Ok(file)
    }

    /// Atomically writes the file: temp file in the same directory, then
    /// rename. User-level files are mode 0600 in a 0700 directory; project
    /// files are meant to be committed, so they are 0644 in a 0755 directory
    /// (subject to the umask). The temp file is removed if anything fails.
    pub fn save(&self, file: &NamespaceFile) -> Result<()> {
        let name = file.name();
        let path = self.path_for(name)?;
        let (dir_mode, file_mode) = if self.is_project() {
            (0o755, 0o644)
        } else {
            (0o700, 0o600)
        };
        fs::DirBuilder::new()
            .recursive(true)
            .mode(dir_mode)
            .create(&self.dir)
            .context("cannot create the envy config directory")?;

        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let tmp = self.dir.join(format!(
            ".{name}.toml.tmp.{}.{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let result = (|| -> std::io::Result<()> {
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(file_mode)
                .open(&tmp)?;
            f.write_all(file.text().as_bytes())?;
            f.sync_all()?;
            fs::rename(&tmp, &path)
        })();
        if let Err(e) = result {
            let _ = fs::remove_file(&tmp);
            return Err(e).with_context(|| format!("cannot write namespace {name:?}"));
        }
        Ok(())
    }

    /// Removes the namespace file. Deleting one that does not exist is not an
    /// error.
    pub fn delete(&self, name: &str) -> Result<()> {
        let path = self.path_for(name)?;
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e).with_context(|| format!("cannot delete namespace {name:?}")),
        }
    }
}

fn dir_from_env(config_dir: Option<OsString>, home: Option<OsString>) -> Result<PathBuf> {
    if let Some(dir) = config_dir.filter(|d| !d.is_empty()) {
        let dir = PathBuf::from(dir);
        // A relative path would resolve against the current directory, so
        // envy would read and write different files depending on where it
        // runs.
        if !dir.is_absolute() {
            bail!(
                "ENVY_CONFIG_DIR must be an absolute path, not {:?}",
                dir.display().to_string()
            );
        }
        return Ok(dir);
    }
    match home.filter(|h| !h.is_empty()) {
        Some(home) => Ok(PathBuf::from(home).join(".config").join("envy")),
        None => bail!("cannot locate the config directory: set ENVY_CONFIG_DIR or HOME"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn project_load_refuses_a_symlinked_file_and_names_the_path() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cfg = project_cfg(tmp.path(), "acme/api");
        fs::create_dir_all(cfg.dir()).unwrap();
        let real = tmp.path().join("real.toml");
        fs::write(&real, "[vars]\nA = \"1\"\n").unwrap();
        let link = cfg.dir().join("dev.toml");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let err = format!("{:#}", cfg.load("dev").unwrap_err());
        assert!(
            err.contains("symlink") && err.contains(&link.display().to_string()),
            "{err}"
        );
        assert!(cfg.present("dev").unwrap());
        // The user level is unchanged: it still follows symlinks.
        let user = Config::new(cfg.dir().to_path_buf());
        assert!(user.load("dev").is_ok());
    }

    #[test]
    fn project_load_errors_name_the_path_not_the_contents() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cfg = project_cfg(tmp.path(), "acme/api");
        fs::create_dir_all(cfg.dir()).unwrap();
        let p = cfg.dir().join("dev.toml");
        fs::write(&p, "SECRET_VALUE = [oops").unwrap();
        let err = format!("{:#}", cfg.load("dev").unwrap_err());
        assert!(
            err.contains(&p.display().to_string()) && !err.contains("SECRET_VALUE"),
            "{err}"
        );
        fs::remove_file(&p).unwrap();
        fs::create_dir(&p).unwrap();
        let err = format!("{:#}", cfg.load("dev").unwrap_err());
        assert!(err.contains(&p.display().to_string()), "{err}");
    }

    #[test]
    fn present_sees_any_directory_entry() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cfg = project_cfg(tmp.path(), "acme/api");
        fs::create_dir_all(cfg.dir()).unwrap();
        assert!(!cfg.present("dev").unwrap());
        std::os::unix::fs::symlink("/nonexistent/x", cfg.dir().join("dev.toml")).unwrap();
        assert!(cfg.present("dev").unwrap() && !cfg.exists("dev").unwrap());
        fs::create_dir(cfg.dir().join("ci.toml")).unwrap();
        assert_eq!(cfg.list_present().unwrap(), vec!["ci", "dev"]);
        assert!(cfg.list().unwrap().is_empty());
    }

    const SAMPLE: &str = "link = \"aws\"\n\n[vars]\nAWS_REGION = \"eu-west-1\"\nGITHUB_TOKEN = \"@keychain\"\nA = \"x\"\n";

    fn listing(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }

    #[test]
    fn parse_reads_link_and_vars_in_order() {
        let f = NamespaceFile::parse("work", SAMPLE).unwrap();
        assert_eq!(f.name(), "work");
        assert_eq!(f.link(), Some("aws"));
        assert_eq!(
            f.vars(),
            vec![
                ("AWS_REGION".into(), Value::Plain("eu-west-1".into())),
                ("GITHUB_TOKEN".into(), Value::Secret),
                ("A".into(), Value::Plain("x".into())),
            ]
        );
        assert_eq!(f.get("A"), Some(Value::Plain("x".into())));
        assert_eq!(f.get("MISSING"), None);
        assert_eq!(NamespaceFile::empty("e").unwrap().link(), None);
    }

    #[test]
    fn marker_value_is_secret_anything_else_plain() {
        let f = NamespaceFile::parse(
            "w",
            "[vars]\nA = \"@keychain\"\nB = \"@Keychain\"\nC = \" @keychain\"\nD = \"\"\n",
        )
        .unwrap();
        assert_eq!(f.get("A"), Some(Value::Secret));
        assert_eq!(f.get("B"), Some(Value::Plain("@Keychain".into())));
        assert_eq!(f.get("C"), Some(Value::Plain(" @keychain".into())));
        assert_eq!(f.get("D"), Some(Value::Plain(String::new())));
    }

    #[test]
    fn set_var_preserves_comments_and_order() {
        let text =
            "# my namespace\nlink = \"aws\"\n\n[vars]\nA = \"1\" # keep me\nB = \"@keychain\"\n";
        let mut f = NamespaceFile::parse("w", text).unwrap();
        f.set_var("C", Value::Plain("3".into())).unwrap();
        f.set_var("A", Value::Plain("2".into())).unwrap();
        let out = f.text();
        assert!(out.starts_with("# my namespace\nlink = \"aws\"\n"), "{out}");
        assert!(out.contains("A = \"2\" # keep me\n"), "{out}");
        assert!(out.contains("B = \"@keychain\"\n"), "{out}");
        let keys: Vec<_> = f.vars().into_iter().map(|(k, _)| k).collect();
        assert_eq!(keys, ["A", "B", "C"]);

        // Untouched text round-trips exactly, including after an add.
        let mut g = NamespaceFile::parse("w", text).unwrap();
        g.set_var("C", Value::Secret).unwrap();
        assert!(g.text().starts_with(text), "{}", g.text());
    }

    #[test]
    fn replacing_a_var_keeps_leading_comment_inline_comment_and_indentation() {
        let text = "[vars]\n# about A\nA = \"1\" # inline\n  B = \"2\"\n";
        let mut f = NamespaceFile::parse("w", text).unwrap();
        f.set_var("A", Value::Plain("9".into())).unwrap();
        assert_eq!(
            f.text(),
            "[vars]\n# about A\nA = \"9\" # inline\n  B = \"2\"\n"
        );
        f.set_var("A", Value::Secret).unwrap();
        assert_eq!(
            f.text(),
            "[vars]\n# about A\nA = \"@keychain\" # inline\n  B = \"2\"\n"
        );
    }

    #[test]
    fn replacing_link_keeps_leading_and_inline_comments() {
        let text = "# my namespace\nlink = \"aws\" # group\n\n[vars]\nA = \"1\"\n";
        let mut f = NamespaceFile::parse("w", text).unwrap();
        f.set_link(Some("gcp")).unwrap();
        assert_eq!(
            f.text(),
            "# my namespace\nlink = \"gcp\" # group\n\n[vars]\nA = \"1\"\n"
        );
    }

    fn unlinked(text: &str) -> String {
        let mut f = NamespaceFile::parse("w", text).unwrap();
        f.set_link(None).unwrap();
        let out = f.text();
        // Whatever envy writes must still be a valid namespace file.
        NamespaceFile::parse("w", &out).unwrap();
        out
    }

    #[test]
    fn removing_link_keeps_the_comment_above_it() {
        assert_eq!(
            unlinked(
                "# work account, keep in sync with prod\nlink = \"aws\"\n\n[vars]\nA = \"1\"\n"
            ),
            "# work account, keep in sync with prod\n\n[vars]\nA = \"1\"\n"
        );
        assert_eq!(
            unlinked("# header\n\n# about link\n  link = \"aws\"\n[vars]\nA = \"1\"\n"),
            "# header\n\n# about link\n[vars]\nA = \"1\"\n"
        );
    }

    #[test]
    fn removing_link_keeps_its_inline_comment_as_a_line() {
        assert_eq!(
            unlinked("link = \"aws\" # shared with prod\n[vars]\nA = \"1\"\n"),
            "# shared with prod\n[vars]\nA = \"1\"\n"
        );
        assert_eq!(
            unlinked("# above\nlink = \"aws\"   # inline\n\n[vars]\nA = \"1\"\n"),
            "# above\n# inline\n\n[vars]\nA = \"1\"\n"
        );
    }

    #[test]
    fn removing_link_that_is_the_only_top_level_content() {
        assert_eq!(unlinked("link = \"aws\"\n"), "");
        assert_eq!(
            unlinked("# note\nlink = \"aws\" # why\n"),
            "# note\n# why\n"
        );
        assert_eq!(unlinked("link = \"aws\"\n# trailing\n"), "# trailing\n");
    }

    #[test]
    fn removing_link_leaves_no_leading_blank_line() {
        assert_eq!(
            unlinked("link = \"aws\"\n\n[vars]\nA = \"1\"\n"),
            "[vars]\nA = \"1\"\n"
        );
        assert_eq!(
            unlinked("# header\n\nlink = \"aws\"\n\n[vars]\nA = \"1\"\n"),
            "# header\n\n[vars]\nA = \"1\"\n"
        );
    }

    #[test]
    fn removing_link_after_another_top_level_key_keeps_comments_in_place() {
        assert_eq!(
            unlinked(
                "other = \"x\" # o\n# about link\nlink = \"aws\" # grp\n\n[vars]\nA = \"1\"\n"
            ),
            "other = \"x\" # o\n# about link\n# grp\n\n[vars]\nA = \"1\"\n"
        );
    }

    #[test]
    fn adding_link_keeps_a_header_comment_above_it() {
        let mut f = NamespaceFile::parse("w", "# my envs\n\n[vars]\nA = \"1\"\n").unwrap();
        f.set_link(Some("aws")).unwrap();
        assert_eq!(f.text(), "# my envs\n\nlink = \"aws\"\n[vars]\nA = \"1\"\n");
        // A comment directly above [vars] stays with [vars].
        let mut f =
            NamespaceFile::parse("w", "# my envs\n\n# about vars\n[vars]\nA = \"1\"\n").unwrap();
        f.set_link(Some("aws")).unwrap();
        assert_eq!(
            f.text(),
            "# my envs\n\nlink = \"aws\"\n# about vars\n[vars]\nA = \"1\"\n"
        );
        assert_eq!(f.link(), Some("aws"));
    }

    #[test]
    fn adding_then_removing_link_round_trips() {
        for text in [
            "",
            "[vars]\nA = \"1\"\n",
            "# my envs\n\n[vars]\nA = \"1\"\n",
            "# my envs\n\n# about vars\n[vars]\nA = \"1\"\n",
            "# about vars\n[vars]\nA = \"1\" # inline\n",
            "\n\n[vars]\nA = \"1\"\n",
            "# only a comment\n",
            "# header\n\n# only comments\n",
            "other = \"x\"\n\n[vars]\nA = \"1\"\n",
        ] {
            let mut f = NamespaceFile::parse("w", text).unwrap();
            f.set_link(Some("aws")).unwrap();
            let linked = NamespaceFile::parse("w", &f.text()).unwrap();
            assert_eq!(linked.link(), Some("aws"), "{text:?}");
            f.set_link(None).unwrap();
            assert_eq!(f.text(), text, "{text:?}");
        }
    }

    #[test]
    fn parse_error_line_number_is_safe_on_multibyte_text() {
        assert!(NamespaceFile::parse("w", "# \u{e9}\u{e9}\u{e9}\n[vars\nA = \"\u{e9}\"").is_err());
    }

    #[test]
    fn set_var_creates_vars_table_and_link_roundtrips() {
        let mut f = NamespaceFile::empty("w").unwrap();
        f.set_var("A", Value::Plain("quo\"te\\".into())).unwrap();
        f.set_link(Some("grp")).unwrap();
        let reparsed = NamespaceFile::parse("w", &f.text()).unwrap();
        assert_eq!(reparsed.get("A"), Some(Value::Plain("quo\"te\\".into())));
        assert_eq!(reparsed.link(), Some("grp"));
        assert!(f.set_link(Some("../x")).is_err());
        assert_eq!(f.link(), Some("grp"));
        f.set_link(None).unwrap();
        assert_eq!(f.link(), None);
        assert!(f.remove_var("A"));
        assert!(!f.remove_var("A"));
        assert!(!NamespaceFile::empty("e").unwrap().remove_var("A"));
    }

    #[test]
    fn plain_marker_literal_is_rejected() {
        let mut f = NamespaceFile::empty("w").unwrap();
        assert!(f.set_var("A", Value::Plain("@keychain".into())).is_err());
        assert_eq!(f.get("A"), None);
    }

    #[test]
    fn invalid_var_name_is_rejected() {
        let mut f = NamespaceFile::empty("w").unwrap();
        for n in ["1A", "A-B", "", "ENVY_ACTIVE", "A B"] {
            assert!(f.set_var(n, Value::Secret).is_err(), "{n:?}");
        }
        assert!(f.vars().is_empty());
        assert!(NamespaceFile::parse("w", "[vars]\n\"A B\" = \"x\"\n").is_err());
    }

    #[test]
    fn existing_file_with_a_special_parameter_fails_to_parse_naming_it() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("work.toml"),
            "[vars]\nA = \"1\"\nSECONDS = \"a[$(touch pwned)] hunter2\"\n",
        )
        .unwrap();
        let err = Config::new(dir.path().to_path_buf())
            .load("work")
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("\"work\"") && msg.contains("\"SECONDS\""),
            "{msg}"
        );
        assert!(msg.contains("special zsh parameter"), "{msg}");
        assert!(!msg.contains("hunter2") && !msg.contains("pwned"), "{msg}");
    }

    #[test]
    fn parse_rejects_malformed_toml_and_non_string_values_without_panicking() {
        for bad in [
            "[vars\nA = ",
            "[vars]\nA = 1\n",
            "vars = [\"a\"]\n",
            "[[vars]]\nA = \"x\"\n",
            "link = 5\n",
            "link = \"../x\"\n",
        ] {
            assert!(NamespaceFile::parse("w", bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn parse_errors_do_not_leak_values() {
        let err = NamespaceFile::parse("w", "[vars]\nA = \"hunter2\" oops\n").unwrap_err();
        assert!(!format!("{err:#}").contains("hunter2"), "{err:#}");
    }

    #[test]
    fn load_unknown_namespace_errors_with_hint() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = Config::new(dir.path().to_path_buf());
        let msg = cfg.load("nope").unwrap_err().to_string();
        assert!(msg.contains("nope") && msg.contains("--new"), "{msg}");
        assert!(!cfg.exists("nope").unwrap());
    }

    #[test]
    fn path_escaping_names_never_touch_the_filesystem() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = Config::new(dir.path().join("envy"));
        let outer = listing(dir.path());
        for bad in ["../x", "a/b", ".hidden", ""] {
            assert!(cfg.load(bad).is_err(), "load {bad:?}");
            assert!(cfg.delete(bad).is_err(), "delete {bad:?}");
            assert!(cfg.exists(bad).is_err(), "exists {bad:?}");
            let forged = NamespaceFile {
                name: bad.to_string(),
                secret_key: bad.to_string(),
                doc: DocumentMut::new(),
            };
            assert!(cfg.save(&forged).is_err(), "save {bad:?}");
        }
        assert_eq!(listing(dir.path()), outer);
        assert!(NamespaceFile::empty("../x").is_err());
        assert!(NamespaceFile::parse("a/b", "").is_err());
    }

    #[test]
    fn list_ignores_non_toml_and_invalid_names() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = Config::new(dir.path().to_path_buf());
        assert_eq!(cfg.list().unwrap(), Vec::<String>::new());
        for n in [
            "b.toml",
            "a.toml",
            "notes.txt",
            ".hidden.toml",
            "bad name.toml",
            "x.toml.bak",
        ] {
            fs::write(dir.path().join(n), "").unwrap();
        }
        fs::create_dir(dir.path().join("dir.toml")).unwrap();
        assert_eq!(cfg.list().unwrap(), ["a", "b"]);
        let missing = Config::new(dir.path().join("missing"));
        assert!(missing.list().unwrap().is_empty());
    }

    #[test]
    fn save_is_0600_and_leaves_no_temp_files() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = Config::new(dir.path().join("nested").join("envy"));
        let mut f = NamespaceFile::empty("work").unwrap();
        f.set_var("A", Value::Plain("1".into())).unwrap();
        cfg.save(&f).unwrap();
        f.set_var("B", Value::Secret).unwrap();
        cfg.save(&f).unwrap();

        let path = cfg.dir().join("work.toml");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(listing(cfg.dir()), ["work.toml"]);
        assert_eq!(cfg.load("work").unwrap().vars().len(), 2);
        assert!(cfg.exists("work").unwrap());
        assert_eq!(cfg.list().unwrap(), ["work"]);

        cfg.delete("work").unwrap();
        cfg.delete("work").unwrap();
        assert!(!cfg.exists("work").unwrap());
    }

    fn project_cfg(base: &Path, identity: &str) -> Config {
        Config::project(
            base.join("proj").join(".envy"),
            base.join("proj"),
            identity.to_string(),
            base.join("user"),
        )
    }

    #[test]
    fn user_level_secret_key_is_the_name() {
        let cfg = Config::new(PathBuf::from("/x/envy"));
        assert_eq!(cfg.secret_key("dev"), "dev");
        assert!(!cfg.is_project());
        assert_eq!(cfg.identity(), None);
        assert_eq!(cfg.root(), None);
        assert_eq!(cfg.user_dir(), Path::new("/x/envy"));
        assert_eq!(NamespaceFile::empty("dev").unwrap().secret_key(), "dev");
        assert_eq!(NamespaceFile::parse("dev", "").unwrap().secret_key(), "dev");
    }

    #[test]
    fn project_level_secret_key_is_prefixed() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = project_cfg(dir.path(), "acme/api");
        assert_eq!(cfg.secret_key("dev"), "project/acme/api/dev");
        assert!(cfg.is_project());
        assert_eq!(cfg.identity(), Some("acme/api"));
        assert_eq!(cfg.root(), Some(dir.path().join("proj").as_path()));
        assert_eq!(cfg.dir(), dir.path().join("proj").join(".envy"));
        assert_eq!(cfg.user_dir(), dir.path().join("user"));
    }

    #[test]
    fn loaded_files_carry_their_secret_key() {
        let dir = tempfile::tempdir().unwrap();
        let project = project_cfg(dir.path(), "acme/api");
        project.save(&NamespaceFile::empty("dev").unwrap()).unwrap();
        let loaded = project.load("dev").unwrap();
        assert_eq!(loaded.secret_key(), "project/acme/api/dev");
        assert_eq!(loaded.name(), "dev");
        assert!(!loaded.text().contains("project/acme"));

        let user = Config::new(dir.path().join("u"));
        user.save(&NamespaceFile::empty("dev").unwrap()).unwrap();
        assert_eq!(user.load("dev").unwrap().secret_key(), "dev");
    }

    #[test]
    fn project_files_are_world_readable() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = project_cfg(dir.path(), "acme/api");
        cfg.save(&NamespaceFile::empty("dev").unwrap()).unwrap();
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        // Project files honour the umask: owner keeps access, never wider
        // than 0644 (files) or 0755 (directory).
        let file = mode(&cfg.dir().join("dev.toml"));
        assert_eq!(file & 0o600, 0o600, "{file:o}");
        assert_eq!(file & !0o644, 0, "{file:o}");
        let folder = mode(cfg.dir());
        assert_eq!(folder & 0o700, 0o700, "{folder:o}");
        assert_eq!(folder & !0o755, 0, "{folder:o}");
        // User level uses explicit modes.
        let user = Config::new(dir.path().join("u"));
        user.save(&NamespaceFile::empty("dev").unwrap()).unwrap();
        assert_eq!(mode(&user.dir().join("dev.toml")), 0o600);
        assert_eq!(mode(user.dir()), 0o700);
    }

    #[test]
    fn failed_save_leaves_no_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = Config::new(dir.path().to_path_buf());
        // A non-empty directory at the target makes the final rename fail.
        let target = dir.path().join("work.toml");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("keep"), "").unwrap();
        let f = NamespaceFile::empty("work").unwrap();
        assert!(cfg.save(&f).is_err());
        assert_eq!(listing(dir.path()), ["work.toml"]);
    }

    #[test]
    fn dir_from_env_prefers_override_then_home() {
        let o = |s: &str| Some(OsString::from(s));
        assert_eq!(dir_from_env(o("/c"), o("/h")).unwrap(), PathBuf::from("/c"));
        assert_eq!(
            dir_from_env(None, o("/h")).unwrap(),
            PathBuf::from("/h/.config/envy")
        );
        assert_eq!(
            dir_from_env(o(""), o("/h")).unwrap(),
            PathBuf::from("/h/.config/envy")
        );
        assert!(dir_from_env(None, None).is_err());
    }

    #[test]
    fn dir_from_env_rejects_a_relative_override_naming_it() {
        let o = |s: &str| Some(OsString::from(s));
        for rel in ["envy", "./envy", "../x", "~/envy"] {
            let err = dir_from_env(o(rel), o("/h")).unwrap_err().to_string();
            assert!(
                err.contains("ENVY_CONFIG_DIR") && err.contains("absolute"),
                "{rel}: {err}"
            );
        }
        // Empty still means unset.
        assert_eq!(
            dir_from_env(o(""), o("/h")).unwrap(),
            PathBuf::from("/h/.config/envy")
        );
    }
}
