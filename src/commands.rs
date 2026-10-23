//! envy's commands: `activate` and `status`, which return text for stdout,
//! and the interactive ones that change namespaces (`create`, `set_vars`,
//! `edit`, `remove`), with the write ordering they share ([`apply`]).

use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::activate::{ActiveState, render_activate};
use crate::config::{Config, NamespaceFile, SECRET_MARKER, Value};
use crate::link;
use crate::names::{validate_namespace, validate_var};
use crate::prompt::{Prompter, plain_label, secret_label, vet_plain};
use crate::secret::Secret;
use crate::store::SecretStore;

/// Shell text that switches to namespace `ns`. A linked namespace that has
/// drifted from its group is refused. The result contains secrets by design:
/// the caller may only write it to stdout.
pub fn activate(
    cfg: &Config,
    store: &dyn SecretStore,
    ns: &str,
    prev: &ActiveState,
) -> Result<String> {
    let file = cfg.load(ns)?;
    link::ensure_aligned(cfg, &file)?;
    render_activate(&file, prev, store)
}

/// Lists namespace names, one per line, `* ` marking the active one. Names
/// only: never values, secret or plain.
pub fn status(cfg: &Config, active: &ActiveState) -> Result<String> {
    let names = cfg.list()?;
    let mut out = String::new();
    for name in &names {
        let marker = if active.namespace.as_deref() == Some(name) {
            "*"
        } else {
            " "
        };
        out.push_str(&format!("{marker} {name}\n"));
    }
    if let Some(ns) = &active.namespace
        && !names.contains(ns)
    {
        out.push_str(&format!("* {ns} (no longer exists)\n"));
    }
    if out.is_empty() {
        out.push_str("no namespaces yet; create one with: envy <name> --new\n");
    }
    Ok(out)
}

/// Shows the variables of namespace `ns`: its link group, and per variable
/// the name and its value: a plain value quoted and escaped, a secret as the
/// bare marker `@keychain` (never its value). Reads only the namespace
/// file: it takes no `SecretStore`, so a secret value can never be fetched,
/// let alone printed. Plain values are quoted and escaped
/// ([`quote_for_display`]) so they cannot disturb the terminal or the layout.
pub fn list_vars(cfg: &Config, ns: &str, active: &ActiveState) -> Result<String> {
    let file = cfg.load(ns)?;
    let mut out = format!("namespace: {ns}");
    if active.namespace.as_deref() == Some(ns) {
        out.push_str(" (active)");
    }
    out.push('\n');
    if let Some(group) = file.link() {
        out.push_str(&format!("link: {group}\n"));
    }
    out.push('\n');
    let vars = file.vars();
    if vars.is_empty() {
        out.push_str("(no variables)\n");
        return Ok(out);
    }
    let width = vars
        .iter()
        .map(|(n, _)| n.chars().count())
        .max()
        .unwrap_or(0);
    for (name, value) in &vars {
        let shown = match value {
            Value::Secret => SECRET_MARKER.to_string(),
            Value::Plain(v) => quote_for_display(v),
        };
        out.push_str(&format!("{name:<width$}  {shown}\n"));
    }
    Ok(out)
}

/// `value` in double quotes with everything that could move the cursor,
/// recolour or retitle the terminal, or reorder the text written out as an
/// escape: `\"`, `\\`, `\n`, `\r`, `\t`, and `\u{..}` for the other control
/// characters (including ESC and DEL) and for invisible formatting characters
/// (see [`is_invisible_or_control`]).
/// Other text, accents and CJK included, is shown as is.
/// Characters that must not reach the terminal as they are: controls, and
/// characters that draw nothing or reorder text, which could hide a payload
/// (tag characters) or spoof what a value looks like. A general rule over
/// Unicode blocks, not a list of known offenders. Variation selectors,
/// U+FE0F (emoji presentation) included, are escaped on purpose: an emoji
/// value is rare and a hidden character is worse than a less pretty one.
fn is_invisible_or_control(c: char) -> bool {
    c.is_control()
        || matches!(c as u32,
            0x00ad
            | 0x034f
            | 0x061c
            | 0x115f..=0x1160
            | 0x17b4..=0x17b5
            | 0x180b..=0x180f
            | 0x200b..=0x200f
            | 0x2028..=0x202e
            | 0x2060..=0x206f
            | 0x3164
            | 0xfe00..=0xfe0f
            | 0xfeff
            | 0xffa0
            | 0xfff0..=0xfffb
            | 0x1bca0..=0x1bca3
            | 0x1d173..=0x1d17a
            | 0xe0000..=0xe0fff)
}

fn quote_for_display(value: &str) -> String {
    let mut out = String::from("\"");
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if is_invisible_or_control(c) => {
                out.push_str(&format!("\\u{{{:x}}}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Everything the interactive commands need. Tests build one from a temp
/// `Config`, a `MemoryStore` and a `ScriptedPrompter`.
pub struct Ctx<'a> {
    pub cfg: &'a Config,
    pub store: &'a dyn SecretStore,
    pub prompt: &'a dyn Prompter,
}

/// What a Keychain item held before we overwrote it, so a failed command can
/// put it back.
struct Undo {
    name: String,
    prior: Option<Secret>,
}

/// Per written namespace: its name, its secret key and what it replaced.
type Written = Vec<(String, String, Vec<Undo>)>;

/// Writes the secrets to the Keychain, remembering what they replaced. If a
/// write fails, the ones already written are rolled back before returning.
fn write_secrets(ctx: &Ctx, key: &str, items: &[(String, Secret)]) -> Result<Vec<Undo>> {
    let mut undo: Vec<Undo> = Vec::new();
    for (name, secret) in items {
        let step = ctx
            .store
            .get(key, name)
            .and_then(|prior| ctx.store.set(key, name, secret).map(|()| prior));
        match step {
            Ok(prior) => undo.push(Undo {
                name: name.clone(),
                prior,
            }),
            Err(e) => return Err(rollback(ctx, key, undo, e)),
        }
    }
    Ok(undo)
}

/// Restores the Keychain to what it was before `write_secrets`: items that did
/// not exist are deleted, items that did are put back. Returns `cause`, with a
/// note if the rollback itself could not finish.
fn rollback(ctx: &Ctx, key: &str, undo: Vec<Undo>, cause: anyhow::Error) -> anyhow::Error {
    let mut stuck: Vec<String> = Vec::new();
    for u in undo.into_iter().rev() {
        let result = match &u.prior {
            Some(prior) => ctx.store.set(key, &u.name, prior),
            None => ctx.store.delete(key, &u.name),
        };
        if result.is_err() {
            stuck.push(u.name);
        }
    }
    if stuck.is_empty() {
        cause
    } else {
        cause.context(format!(
            "could not undo the Keychain changes for: {}",
            stuck.join(", ")
        ))
    }
}

/// One namespace file written as part of a command, possibly alongside other
/// members of its link group.
pub(crate) struct Change {
    /// The new contents.
    pub file: NamespaceFile,
    /// What is on disk now (`None`: the file is being created).
    pub before: Option<NamespaceFile>,
    /// Keychain items to write before the file is saved.
    pub secrets: Vec<(String, Secret)>,
    /// Keychain items to delete once every file is saved (names the new file
    /// no longer has as secrets).
    pub delete: Vec<String>,
}

/// Writes a set of changes with no transaction to lean on, in the order that
/// keeps every intermediate state safe:
///
/// 1. Every new Keychain item, for every namespace. A failure restores the
///    items already written (prior values put back, new ones deleted).
/// 2. Every file, in order. A failure puts back the files already saved,
///    then the Keychain items. A file that cannot be put back keeps its new
///    contents, and so do its Keychain items, so no file ever refers to a
///    secret that is not in the Keychain.
/// 3. The Keychain items no file refers to any more. A failure here leaves
///    only unreferenced items behind, and says which.
pub(crate) fn apply(ctx: &Ctx, changes: Vec<Change>) -> Result<()> {
    let mut written: Written = Vec::new();
    for c in &changes {
        let key = ctx.cfg.secret_key(c.file.name());
        match write_secrets(ctx, &key, &c.secrets) {
            Ok(undo) => written.push((c.file.name().to_string(), key, undo)),
            Err(e) => return Err(rollback_all(ctx, written, &[], e)),
        }
    }
    for (i, c) in changes.iter().enumerate() {
        if let Err(e) = ctx.cfg.save(&c.file) {
            let (kept, e) = restore_files(ctx, &changes[..i], e);
            return Err(rollback_all(ctx, written, &kept, e));
        }
    }
    let mut stuck: Vec<String> = Vec::new();
    for c in &changes {
        let key = ctx.cfg.secret_key(c.file.name());
        for name in &c.delete {
            if ctx.store.delete(&key, name).is_err() {
                stuck.push(format!("{}/{name}", c.file.name()));
            }
        }
    }
    if !stuck.is_empty() {
        bail!(
            "the changes were saved, but these old Keychain items could not be deleted: {}",
            stuck.join(", ")
        );
    }
    Ok(())
}

/// Undoes the Keychain writes of every namespace except those in `keep`
/// (whose files could not be restored and still refer to the new items).
fn rollback_all(
    ctx: &Ctx,
    written: Written,
    keep: &[String],
    cause: anyhow::Error,
) -> anyhow::Error {
    let mut err = cause;
    for (ns, key, undo) in written.into_iter().rev() {
        if !keep.contains(&ns) {
            err = rollback(ctx, &key, undo, err);
        }
    }
    err
}

/// Puts back the files of `saved`. Returns the namespaces that could not be
/// put back, with `cause` noting them.
fn restore_files(
    ctx: &Ctx,
    saved: &[Change],
    cause: anyhow::Error,
) -> (Vec<String>, anyhow::Error) {
    let mut kept: Vec<String> = Vec::new();
    for c in saved.iter().rev() {
        let name = c.file.name();
        let result = match &c.before {
            Some(before) => ctx.cfg.save(before),
            None => ctx.cfg.delete(name),
        };
        if result.is_err() {
            kept.push(name.to_string());
        }
    }
    if kept.is_empty() {
        (kept, cause)
    } else {
        let note = format!(
            "could not restore these namespaces, which keep their new contents and secrets: {}",
            kept.join(", ")
        );
        (kept, cause.context(note))
    }
}

/// Creates namespace `ns`, empty or modelled on `like` (names and plain values
/// are copied; each secret is prompted for; the `link` label is not copied),
/// and with `link` joins it to that link group.
///
/// Order: validate, check that the namespace can join the group, prompt for
/// everything, re-check that `ns` still does not exist, then [`apply`]. A
/// failure at any step leaves nothing behind.
pub fn create(ctx: &Ctx, ns: &str, like: Option<&str>, link: Option<&str>) -> Result<()> {
    validate_namespace(ns)?;
    for name in [like, link].into_iter().flatten() {
        validate_namespace(name)?;
    }
    if like == Some(ns) {
        bail!("namespace {ns:?} cannot be created like itself");
    }
    if ctx.cfg.exists(ns)? {
        bail!("namespace {ns:?} already exists");
    }
    let mut file = NamespaceFile::empty(ns)?;
    let mut like_secrets: Vec<String> = Vec::new();
    if let Some(source) = like {
        for (name, value) in ctx.cfg.load(source)?.vars() {
            if value == Value::Secret {
                like_secrets.push(name.clone());
            }
            file.set_var(&name, value)?;
        }
    }
    let missing = match link {
        Some(group) => link::check_join(ctx.cfg, &file, group)?,
        None => Vec::new(),
    };
    let mut secrets: Vec<(String, Secret)> = Vec::new();
    for name in like_secrets {
        let secret = ctx
            .prompt
            .secret(&secret_label(&name, ns))
            .with_context(|| format!("no value for secret {name}; nothing was created"))?;
        secrets.push((name, secret));
    }
    if let Some(group) = link {
        link::fill_missing(ctx, &mut file, &missing, &mut secrets)?;
        file.set_link(Some(group))?;
    }
    // The prompts can take a while: do not replace a namespace created
    // meanwhile (or write over its Keychain items).
    if ctx.cfg.exists(ns)? {
        bail!(
            "namespace {ns:?} was created by something else while envy was prompting; nothing was changed"
        );
    }
    apply(
        ctx,
        vec![Change {
            file,
            before: None,
            secrets,
            delete: Vec::new(),
        }],
    )
}

/// How one variable of `--secret` or `--plain` is set. Never holds a secret
/// value: secrets are always prompted for, so deriving `Debug` is safe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetKind {
    /// `--secret NAME`: a hidden prompt; the value goes to the Keychain.
    Secret,
    /// `--plain NAME=value` (`Some`, used as given, no prompt) or
    /// `--plain NAME` (`None`, a visible prompt); the value goes in the file.
    Plain(Option<String>),
}

/// One variable to set, as given on the command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetItem {
    pub name: String,
    pub kind: SetKind,
}

impl SetItem {
    pub fn secret(name: &str) -> Self {
        Self {
            name: name.to_string(),
            kind: SetKind::Secret,
        }
    }

    pub fn plain(name: &str, value: Option<&str>) -> Self {
        Self {
            name: name.to_string(),
            kind: SetKind::Plain(value.map(str::to_string)),
        }
    }
}

/// Sets every variable of `items` in namespace `ns`, in one write: secrets
/// (hidden prompt, value in the Keychain, only the marker in the file) and
/// plain values (given inline, or prompted for visibly with the current value
/// as the default, and stored in the file). Changing the kind of an existing
/// variable asks first. In a linked namespace the rest of the group is then
/// made to match `ns`, for every item at once (see [`link::conform`]).
///
/// Names (and inline values) are all checked first. Then everything, for every
/// item and every member, is asked in the order given, before anything is
/// written; then, unless `ns` or its group changed meanwhile
/// ([`link::ensure_unchanged`]), the writes go through a single [`apply`].
pub fn set_vars(ctx: &Ctx, ns: &str, items: &[SetItem]) -> Result<()> {
    validate_namespace(ns)?;
    if items.is_empty() {
        bail!("no variables given; nothing was changed");
    }
    let mut seen: Vec<&str> = Vec::new();
    for item in items {
        let name = item.name.as_str();
        validate_var(name)?;
        if seen.contains(&name) {
            bail!("variable {name} is given more than once; nothing was changed");
        }
        seen.push(name);
        if let SetKind::Plain(Some(value)) = &item.kind {
            check_inline_plain(name, value)?;
        }
    }
    let before = ctx.cfg.load(ns)?;
    // Loaded before prompting, so an unreadable member stops us early.
    let others = link::others(ctx.cfg, &before)?;
    let mut file = before.clone();
    let mut secrets: Vec<(String, Secret)> = Vec::new();
    let mut delete: Vec<String> = Vec::new();

    for item in items {
        let name = item.name.as_str();
        let current = before.get(name);
        match &item.kind {
            SetKind::Plain(given) => {
                if current == Some(Value::Secret)
                    && !ctx.prompt.confirm(&format!(
                        "{name} is currently a secret. Replace it with a plain value (the Keychain item will be deleted)?"
                    ))?
                {
                    bail!("cancelled; nothing was changed");
                }
                let value = match given {
                    Some(value) => value.clone(),
                    None => {
                        let default = match &current {
                            Some(Value::Plain(v)) => Some(v.as_str()),
                            _ => None,
                        };
                        ctx.prompt
                            .plain(&plain_label(name, ns), default)
                            .with_context(|| format!("no value for {name}; nothing was changed"))?
                    }
                };
                // Rejects the reserved marker before anything is written.
                file.set_var(name, Value::Plain(value))?;
                if current == Some(Value::Secret) {
                    delete.push(name.to_string());
                }
            }
            SetKind::Secret => {
                if matches!(current, Some(Value::Plain(_)))
                    && !ctx.prompt.confirm(&format!(
                        "{name} is currently a plain value. Replace it with a secret?"
                    ))?
                {
                    bail!("cancelled; nothing was changed");
                }
                let secret = ctx
                    .prompt
                    .secret(&secret_label(name, ns))
                    .with_context(|| format!("no value for secret {name}; nothing was changed"))?;
                file.set_var(name, Value::Secret)?;
                secrets.push((name.to_string(), secret));
            }
        }
    }

    let group = link::conform(ctx, &file, others.clone())?;
    // The prompts can take a while: do not overwrite a change made meanwhile
    // (to `ns` or to its group).
    link::ensure_unchanged(ctx.cfg, &before, before.link(), &others)?;
    let mut changes = vec![Change {
        file,
        before: Some(before),
        secrets,
        delete,
    }];
    changes.extend(group);
    apply(ctx, changes)
}

/// Checks a plain value given on the command line before anything is asked:
/// the secret marker and NUL are refused. Names only in the errors.
fn check_inline_plain(name: &str, value: &str) -> Result<()> {
    if value == SECRET_MARKER {
        bail!(
            "variable {name}: the plain value {SECRET_MARKER:?} is reserved for secrets; use --secret {name}"
        );
    }
    vet_plain(value.to_string()).with_context(|| format!("variable {name}"))?;
    Ok(())
}

/// Deletes namespace `ns` after confirmation: its Keychain items first, then
/// the file. If something fails midway the file is still there, still lists
/// the secrets, and running the command again finishes the job (deleting an
/// item that is already gone is fine).
pub fn remove(ctx: &Ctx, ns: &str) -> Result<()> {
    let file = ctx.cfg.load(ns)?;
    let secrets: Vec<String> = file
        .vars()
        .into_iter()
        .filter_map(|(name, value)| (value == Value::Secret).then_some(name))
        .collect();
    let question = if secrets.is_empty() {
        format!("Delete namespace {ns:?}?")
    } else {
        format!(
            "Delete namespace {ns:?} and its {} secret(s) from the Keychain ({})?",
            secrets.len(),
            secrets.join(", ")
        )
    };
    if !ctx.prompt.confirm(&question)? {
        bail!("cancelled; nothing was changed");
    }
    let key = ctx.cfg.secret_key(ns);
    for name in &secrets {
        ctx.store.delete(&key, name)?;
    }
    ctx.cfg.delete(ns)
}

/// Opens namespace `ns` in an editor and saves what the user wrote, with
/// whatever that implies for the Keychain and the link group.
///
/// The editor (`run_editor`, normally [`crate::editor::launch`]) works on a
/// copy in a fresh private temporary directory (0700, file 0600), which is
/// deleted however this returns or unwinds. The copy holds no secret: those
/// appear as the `@keychain` marker. The edited text must parse as a
/// namespace file (names and the label are validated) and keep the `link`
/// label as it was; otherwise nothing is changed.
///
/// Reconciled against the file as it was:
/// - a name that is now a secret but was not (new, or plain before) is
///   prompted for, hidden;
/// - names that were secrets but no longer are (removed, or now plain) get
///   one `confirm` to delete their Keychain items; declining keeps the items
///   and still saves the file;
/// - plain values need no prompt;
/// - in a linked namespace the rest of the group is then made to match the
///   edited file ([`link::conform`]), even when nothing was edited, which
///   repairs a group that drifted through hand edits.
///
/// Everything is prompted before anything is written; the writes then go
/// through [`apply`]. An unedited file is not rewritten. Returns whether
/// anything was written (in `ns` or elsewhere in its group).
pub fn edit(ctx: &Ctx, ns: &str, run_editor: &dyn Fn(&Path) -> Result<()>) -> Result<bool> {
    validate_namespace(ns)?;
    let before = load_for_edit(ctx.cfg, ns)?;
    // Checked before the editor runs, so an unreadable member stops us early.
    link::others(ctx.cfg, &before)?;

    let dir = tempfile::Builder::new()
        .prefix("envy-edit-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .context("cannot create a private temporary directory for the editor")?;
    let copy = dir.path().join(format!("{ns}.toml"));
    write_private(&copy, &before.text())
        .context("cannot create the temporary copy for the editor")?;
    run_editor(&copy).context("the editor failed; nothing was changed")?;
    let text = std::fs::read_to_string(&copy)
        .context("cannot read the edited file back; nothing was changed")?;
    drop(dir);

    let after = NamespaceFile::parse(ns, &text)
        .context("the edited file was not saved; nothing was changed")?;
    if after.link() != before.link() {
        bail!(
            "the link label cannot be changed in the editor; use envy {ns} --link <group> or envy {ns} --unlink; nothing was changed"
        );
    }

    let was_secret = |name: &str| before.get(name) == Some(Value::Secret);
    let delete: Vec<String> = before
        .vars()
        .into_iter()
        .filter(|(name, value)| *value == Value::Secret && after.get(name) != Some(Value::Secret))
        .map(|(name, _)| name)
        .collect();
    let delete = if !delete.is_empty()
        && !ctx.prompt.confirm(&format!(
            "Delete the Keychain items for {} from {ns:?} (no longer secrets there)?",
            delete.join(", ")
        ))? {
        Vec::new()
    } else {
        delete
    };
    let mut secrets: Vec<(String, Secret)> = Vec::new();
    for (name, value) in after.vars() {
        if value == Value::Secret && !was_secret(&name) {
            let secret = ctx
                .prompt
                .secret(&secret_label(&name, ns))
                .with_context(|| format!("no value for secret {name}; nothing was changed"))?;
            secrets.push((name, secret));
        }
    }
    let others = link::others(ctx.cfg, &after)?;
    let group = link::conform(ctx, &after, others.clone())?;

    // The editor and the prompts can take a while: do not overwrite a change
    // made meanwhile, to `ns` or to the rest of its group.
    if ctx.cfg.load(ns).map(|now| now.text()).ok() != Some(before.text()) {
        bail!("namespace {ns:?} was changed while envy was editing it; nothing was changed");
    }
    link::ensure_unchanged(ctx.cfg, &before, after.link(), &others)?;
    let mut changes: Vec<Change> = Vec::new();
    if after.text() != before.text() {
        changes.push(Change {
            file: after,
            before: Some(before),
            secrets,
            delete,
        });
    }
    changes.extend(group);
    if changes.is_empty() {
        return Ok(false);
    }
    apply(ctx, changes)?;
    Ok(true)
}

/// Loads `ns` for editing. A file that does not parse cannot be reconciled
/// (there is no old state to compare against), so it is refused with its
/// path, for the user to repair by hand.
fn load_for_edit(cfg: &Config, ns: &str) -> Result<NamespaceFile> {
    match cfg.load(ns) {
        Ok(file) => Ok(file),
        Err(e) if cfg.exists(ns).unwrap_or(false) => Err(e.context(format!(
            "cannot edit {}: envy needs the current file to compare against, so fix it by hand first",
            cfg.dir().join(format!("{ns}.toml")).display()
        ))),
        Err(e) => Err(e),
    }
}

/// Creates `path` (which must not exist) with mode 0600 and writes `text`.
fn write_private(path: &Path, text: &str) -> std::io::Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(text.as_bytes())?;
    f.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prompt::{Asked, ScriptedPrompter};
    use crate::store::MemoryStore;

    fn config_with(files: &[(&str, &str)]) -> (tempfile::TempDir, Config) {
        let dir = tempfile::tempdir().unwrap();
        for (name, text) in files {
            std::fs::write(dir.path().join(format!("{name}.toml")), text).unwrap();
        }
        let cfg = Config::new(dir.path().to_path_buf());
        (dir, cfg)
    }

    #[test]
    fn status_lists_names_and_marks_active_and_never_values() {
        let (_dir, cfg) = config_with(&[
            (
                "work",
                "[vars]\nA = \"plain-value-123\"\nB = \"@keychain\"\n",
            ),
            ("personal", "[vars]\nC = \"other-value-456\"\n"),
        ]);
        let active = ActiveState {
            namespace: Some("work".into()),
            vars: vec!["A".into(), "B".into()],
        };
        let out = status(&cfg, &active).unwrap();
        assert_eq!(out, "  personal\n* work\n");
        assert!(!out.contains("value"));
    }

    fn rows(text: &str) -> Vec<&str> {
        text.lines().collect()
    }

    #[test]
    fn list_vars_shows_plain_values_in_file_order() {
        let (_dir, cfg) = config_with(&[(
            "dev",
            "[vars]\nAWS_REGION = \"eu-west-1\"\nLOG = \"debug\"\n",
        )]);
        let out = list_vars(&cfg, "dev", &ActiveState::default()).unwrap();
        assert_eq!(
            out,
            "namespace: dev\n\nAWS_REGION  \"eu-west-1\"\nLOG         \"debug\"\n"
        );
    }

    #[test]
    fn list_vars_shows_secrets_without_a_value_and_needs_no_store() {
        let (_dir, cfg) = config_with(&[(
            "dev",
            "[vars]\nTOKEN = \"@keychain\"\nREGION = \"eu\"\nB = \"@keychain\"\n",
        )]);
        // `list_vars` takes only a Config and an ActiveState: there is no
        // store to read from, by construction.
        let out = list_vars(&cfg, "dev", &ActiveState::default()).unwrap();
        assert_eq!(
            out,
            "namespace: dev\n\nTOKEN   @keychain\nREGION  \"eu\"\nB       @keychain\n"
        );
    }

    #[test]
    fn list_vars_shows_the_link_group() {
        let (_dir, cfg) = config_with(&[("dev", "link = \"aws\"\n[vars]\nA = \"1\"\n")]);
        let out = list_vars(&cfg, "dev", &ActiveState::default()).unwrap();
        assert_eq!(out, "namespace: dev\nlink: aws\n\nA  \"1\"\n");
    }

    #[test]
    fn list_vars_marks_the_active_namespace_only() {
        let (_dir, cfg) = config_with(&[
            ("dev", "link = \"aws\"\n[vars]\nA = \"1\"\n"),
            ("prod", "[vars]\nA = \"2\"\n"),
        ]);
        let active = ActiveState {
            namespace: Some("dev".into()),
            vars: vec!["A".into()],
        };
        assert_eq!(
            list_vars(&cfg, "dev", &active).unwrap(),
            "namespace: dev (active)\nlink: aws\n\nA  \"1\"\n"
        );
        assert_eq!(
            list_vars(&cfg, "prod", &active).unwrap(),
            "namespace: prod\n\nA  \"2\"\n"
        );
    }

    #[test]
    fn list_vars_on_an_empty_namespace_says_so() {
        let (_dir, cfg) = config_with(&[("dev", ""), ("lk", "link = \"g\"\n")]);
        assert_eq!(
            list_vars(&cfg, "dev", &ActiveState::default()).unwrap(),
            "namespace: dev\n\n(no variables)\n"
        );
        assert_eq!(
            list_vars(&cfg, "lk", &ActiveState::default()).unwrap(),
            "namespace: lk\nlink: g\n\n(no variables)\n"
        );
    }

    #[test]
    fn list_vars_escapes_control_characters_in_plain_values() {
        let (_dir, cfg) = config_with(&[(
            "dev",
            "[vars]\nA = \"x\\ny\\u001b[31mred\\tt \\\"q\\\" back\\\\slash caf\u{e9} \u{65e5}\u{672c}\\u007f\\u202e\\r\"\nE = \"\"\nB = \"ok\"\n",
        )]);
        let out = list_vars(&cfg, "dev", &ActiveState::default()).unwrap();
        assert_eq!(
            out,
            "namespace: dev\n\n\
             A  \"x\\ny\\u{1b}[31mred\\tt \\\"q\\\" back\\\\slash caf\u{e9} \u{65e5}\u{672c}\\u{7f}\\u{202e}\\r\"\n\
             E  \"\"\n\
             B  \"ok\"\n"
        );
        // One row per variable, and no raw control character anywhere.
        assert_eq!(rows(&out).len(), 5);
        assert!(!out.chars().any(|c| c.is_control() && c != '\n'));
    }

    #[test]
    fn invisible_and_control_characters_are_escaped_at_each_range_edge() {
        let ranges: &[(u32, u32)] = &[
            (0x00, 0x1f),
            (0x7f, 0x9f),
            (0xad, 0xad),
            (0x34f, 0x34f),
            (0x61c, 0x61c),
            (0x115f, 0x1160),
            (0x17b4, 0x17b5),
            (0x180b, 0x180f),
            (0x200b, 0x200f),
            (0x2028, 0x202e),
            (0x2060, 0x206f),
            (0x3164, 0x3164),
            (0xfe00, 0xfe0f),
            (0xfeff, 0xfeff),
            (0xffa0, 0xffa0),
            (0xfff0, 0xfffb),
            (0x1bca0, 0x1bca3),
            (0x1d173, 0x1d17a),
            (0xe0000, 0xe0fff),
        ];
        for &(first, last) in ranges {
            for cp in [first, last] {
                let c = char::from_u32(cp).unwrap();
                assert!(is_invisible_or_control(c), "U+{cp:04X} not flagged");
                if !matches!(c, '\n' | '\r' | '\t') {
                    assert_eq!(
                        quote_for_display(&c.to_string()),
                        format!("\"\\u{{{cp:x}}}\""),
                        "U+{cp:04X}"
                    );
                }
            }
        }
        // Ordinary text, combining marks, CJK and emoji bodies pass through.
        for text in [
            "caf\u{e9}",
            "e\u{301}",
            "\u{ac}\u{ae}\u{34e}\u{350}\u{61b}\u{61d}\u{3163}\u{3165}\u{ffa1}",
            "\u{65e5}\u{672c}\u{8a9e}",
            "\u{1f980}\u{1f600}",
        ] {
            assert_eq!(quote_for_display(text), format!("\"{text}\""), "{text:?}");
        }
    }

    #[test]
    fn list_vars_escapes_tag_and_other_invisible_characters() {
        let (_dir, cfg) = config_with(&[(
            "dev",
            "[vars]\nA = \"a\\U000E0041b\\u061c\\u00ad\\ufe0f\"\n",
        )]);
        let out = list_vars(&cfg, "dev", &ActiveState::default()).unwrap();
        assert_eq!(
            out,
            "namespace: dev\n\nA  \"a\\u{e0041}b\\u{61c}\\u{ad}\\u{fe0f}\"\n"
        );
    }

    #[test]
    fn list_vars_unknown_namespace_gives_the_new_hint() {
        let (_dir, cfg) = config_with(&[]);
        let err = list_vars(&cfg, "nope", &ActiveState::default()).unwrap_err();
        assert_eq!(
            format!("{err:#}"),
            "namespace \"nope\" does not exist (use --new to create it)"
        );
        assert!(list_vars(&cfg, "../x", &ActiveState::default()).is_err());
    }

    #[test]
    fn list_vars_corrupt_file_names_the_file_but_not_its_contents() {
        let (_dir, cfg) = config_with(&[("dev", "[vars\nA = \"zq-secretish\"\n")]);
        let err = list_vars(&cfg, "dev", &ActiveState::default()).unwrap_err();
        let msg = format!("{err:#} {err:?}");
        assert!(
            msg.contains("\"dev\"") && msg.contains("invalid TOML"),
            "{msg}"
        );
        assert!(!msg.contains("zq-secretish"), "{msg}");
    }

    #[test]
    fn status_without_active_marks_nothing_and_handles_empty_dir() {
        let (_dir, cfg) = config_with(&[("work", "")]);
        assert_eq!(status(&cfg, &ActiveState::default()).unwrap(), "  work\n");
        let (_dir, empty) = config_with(&[]);
        let out = status(&empty, &ActiveState::default()).unwrap();
        assert!(out.contains("--new"), "{out}");
    }

    #[test]
    fn status_flags_active_namespace_that_no_longer_exists() {
        let (_dir, cfg) = config_with(&[("work", "")]);
        let active = ActiveState {
            namespace: Some("gone".into()),
            vars: vec![],
        };
        assert_eq!(
            status(&cfg, &active).unwrap(),
            "  work\n* gone (no longer exists)\n"
        );
    }

    #[test]
    fn activate_loads_and_renders() {
        let (_dir, cfg) = config_with(&[("work", "[vars]\nA = \"x\"\nB = \"@keychain\"\n")]);
        let store = MemoryStore::default();
        store.set("work", "B", &Secret::new("s".into())).unwrap();
        let out = activate(&cfg, &store, "work", &ActiveState::default()).unwrap();
        assert_eq!(
            out,
            "export ENVY_ACTIVE='work'\nexport ENVY_VARS='A B'\nexport A='x'\nexport B='s'\n"
        );
    }

    #[test]
    fn activate_unknown_namespace_names_it_and_mentions_new() {
        let (_dir, cfg) = config_with(&[]);
        let err = activate(
            &cfg,
            &MemoryStore::default(),
            "nope",
            &ActiveState::default(),
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("nope") && msg.contains("--new"), "{msg}");
    }

    fn read(dir: &tempfile::TempDir, name: &str) -> String {
        std::fs::read_to_string(dir.path().join(format!("{name}.toml"))).unwrap()
    }

    fn file_names(dir: &tempfile::TempDir) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }

    fn snap(store: &MemoryStore) -> Vec<(String, String, String)> {
        store.snapshot()
    }

    fn entry(ns: &str, name: &str, value: &str) -> (String, String, String) {
        (ns.into(), name.into(), value.into())
    }

    /// `--secret NAME`.
    fn sec(name: &str) -> SetItem {
        SetItem::secret(name)
    }

    /// `--plain NAME` (prompted).
    fn pl(name: &str) -> SetItem {
        SetItem::plain(name, None)
    }

    /// `--plain NAME=value` (no prompt).
    fn pv(name: &str, value: &str) -> SetItem {
        SetItem::plain(name, Some(value))
    }

    const SOURCE: &str =
        "link = \"aws\"\n\n[vars]\nAWS_REGION = \"eu-west-1\"\nTOKEN = \"@keychain\"\n";

    #[test]
    fn create_empty_writes_file_and_errors_if_it_exists() {
        let (dir, cfg) = config_with(&[]);
        let store = MemoryStore::default();
        let prompt = ScriptedPrompter::new();
        let ctx = Ctx {
            cfg: &cfg,
            store: &store,
            prompt: &prompt,
        };
        create(&ctx, "work", None, None).unwrap();
        assert_eq!(read(&dir, "work"), "");
        assert!(snap(&store).is_empty());
        let err = create(&ctx, "work", None, None).unwrap_err().to_string();
        assert!(err.contains("already exists"), "{err}");
        assert_eq!(read(&dir, "work"), "");
    }

    #[test]
    fn create_rejects_invalid_name_without_touching_disk() {
        let (dir, cfg) = config_with(&[]);
        let store = MemoryStore::default();
        let prompt = ScriptedPrompter::new();
        let ctx = Ctx {
            cfg: &cfg,
            store: &store,
            prompt: &prompt,
        };
        assert!(create(&ctx, "../evil", None, None).is_err());
        assert!(file_names(&dir).is_empty());
    }

    #[test]
    fn create_like_copies_names_and_plain_values_and_prompts_each_secret() {
        let (dir, cfg) = config_with(&[("src", SOURCE)]);
        let store = MemoryStore::default();
        store
            .set("src", "TOKEN", &Secret::new("source-token".into()))
            .unwrap();
        let prompt = ScriptedPrompter::new().with_secret("new-token");
        let ctx = Ctx {
            cfg: &cfg,
            store: &store,
            prompt: &prompt,
        };
        create(&ctx, "dst", Some("src"), None).unwrap();
        assert_eq!(
            read(&dir, "dst"),
            "[vars]\nAWS_REGION = \"eu-west-1\"\nTOKEN = \"@keychain\"\n"
        );
        assert!(!read(&dir, "dst").contains("link"));
        assert_eq!(
            snap(&store),
            vec![
                entry("dst", "TOKEN", "new-token"),
                entry("src", "TOKEN", "source-token")
            ]
        );
        assert_eq!(read(&dir, "src"), SOURCE);
        assert_eq!(
            prompt.asked(),
            vec![Asked::Secret("Secret value for TOKEN in dst".into())]
        );
        assert_eq!(prompt.remaining(), 0);
    }

    #[test]
    fn like_unknown_source_errors_and_creates_nothing() {
        let (dir, cfg) = config_with(&[]);
        let store = MemoryStore::default();
        let prompt = ScriptedPrompter::new();
        let ctx = Ctx {
            cfg: &cfg,
            store: &store,
            prompt: &prompt,
        };
        let err = create(&ctx, "dst", Some("nope"), None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("nope"), "{err}");
        assert!(file_names(&dir).is_empty());
        assert!(snap(&store).is_empty());
    }

    #[test]
    fn like_itself_is_rejected_and_leaves_the_namespace_alone() {
        let (dir, cfg) = config_with(&[("w", SOURCE)]);
        let store = MemoryStore::default();
        let prompt = ScriptedPrompter::new();
        let ctx = Ctx {
            cfg: &cfg,
            store: &store,
            prompt: &prompt,
        };
        let err = create(&ctx, "w", Some("w"), None).unwrap_err().to_string();
        assert!(err.contains("itself"), "{err}");
        assert_eq!(read(&dir, "w"), SOURCE);
        assert!(snap(&store).is_empty());
    }

    #[test]
    fn create_like_failed_second_prompt_writes_nothing() {
        let src = "[vars]\nA = \"@keychain\"\nB = \"@keychain\"\n";
        let (dir, cfg) = config_with(&[("src", src)]);
        let store = MemoryStore::default();
        let prompt = ScriptedPrompter::new()
            .with_secret("a-value")
            .with_secret("");
        let ctx = Ctx {
            cfg: &cfg,
            store: &store,
            prompt: &prompt,
        };
        assert!(create(&ctx, "dst", Some("src"), None).is_err());
        assert_eq!(file_names(&dir), vec!["src.toml"]);
        assert!(snap(&store).is_empty());
    }

    /// A store whose `set` fails for one variable name.
    struct FailingSet {
        inner: MemoryStore,
        fail_on: &'static str,
    }

    impl SecretStore for FailingSet {
        fn get(&self, ns: &str, name: &str) -> Result<Option<Secret>> {
            self.inner.get(ns, name)
        }
        fn set(&self, ns: &str, name: &str, value: &Secret) -> Result<()> {
            if name == self.fail_on {
                bail!("simulated Keychain failure");
            }
            self.inner.set(ns, name, value)
        }
        fn delete(&self, ns: &str, name: &str) -> Result<()> {
            self.inner.delete(ns, name)
        }
    }

    #[test]
    fn create_like_keychain_failure_midway_rolls_back_and_writes_no_file() {
        let src = "[vars]\nA = \"@keychain\"\nB = \"@keychain\"\n";
        let (dir, cfg) = config_with(&[("src", src)]);
        let store = FailingSet {
            inner: MemoryStore::default(),
            fail_on: "B",
        };
        let prompt = ScriptedPrompter::new()
            .with_secret("a-value")
            .with_secret("b-value");
        let ctx = Ctx {
            cfg: &cfg,
            store: &store,
            prompt: &prompt,
        };
        assert!(create(&ctx, "dst", Some("src"), None).is_err());
        assert_eq!(file_names(&dir), vec!["src.toml"]);
        assert!(snap(&store.inner).is_empty());
    }

    #[test]
    fn create_like_file_save_failure_deletes_the_keychain_items_it_wrote() {
        let (dir, cfg) = config_with(&[("src", SOURCE)]);
        // A directory squatting on the target path makes the final rename fail.
        std::fs::create_dir(dir.path().join("dst.toml")).unwrap();
        let store = MemoryStore::default();
        let prompt = ScriptedPrompter::new().with_secret("new-token");
        let ctx = Ctx {
            cfg: &cfg,
            store: &store,
            prompt: &prompt,
        };
        // `exists` is false for a directory, so create proceeds to the save.
        assert!(create(&ctx, "dst", Some("src"), None).is_err());
        assert!(snap(&store).is_empty());
    }

    /// Answers like its inner prompter, but writes `path` while asking, as a
    /// concurrent `envy <ns> --new` would.
    struct CreatesFileWhilePrompting {
        inner: ScriptedPrompter,
        path: std::path::PathBuf,
    }

    impl Prompter for CreatesFileWhilePrompting {
        fn secret(&self, label: &str) -> Result<Secret> {
            std::fs::write(&self.path, "[vars]\nTHEIRS = \"1\"\n").unwrap();
            self.inner.secret(label)
        }
        fn plain(&self, label: &str, default: Option<&str>) -> Result<String> {
            self.inner.plain(label, default)
        }
        fn confirm(&self, question: &str) -> Result<bool> {
            self.inner.confirm(question)
        }
    }

    /// Answers like its inner prompter, but on every hidden or visible prompt
    /// writes `text` to `path`, as another envy command (or an editor) would
    /// while this one waits for the user.
    struct WritesWhilePrompting {
        inner: ScriptedPrompter,
        path: std::path::PathBuf,
        text: &'static str,
    }

    impl Prompter for WritesWhilePrompting {
        fn secret(&self, label: &str) -> Result<Secret> {
            std::fs::write(&self.path, self.text).unwrap();
            self.inner.secret(label)
        }
        fn plain(&self, label: &str, default: Option<&str>) -> Result<String> {
            std::fs::write(&self.path, self.text).unwrap();
            self.inner.plain(label, default)
        }
        fn confirm(&self, question: &str) -> Result<bool> {
            self.inner.confirm(question)
        }
    }

    #[test]
    fn set_does_not_overwrite_a_file_changed_while_prompting() {
        let (dir, cfg) = config_with(&[("work", "[vars]\nA = \"1\"\n")]);
        let store = MemoryStore::default();
        let theirs = "[vars]\nA = \"1\"\nTHEIRS = \"@keychain\"\n";
        for plain in [false, true] {
            let answers = ScriptedPrompter::new();
            let prompt = WritesWhilePrompting {
                inner: if plain {
                    answers.with_plain("mine")
                } else {
                    answers.with_secret("mine")
                },
                path: dir.path().join("work.toml"),
                text: theirs,
            };
            let ctx = Ctx {
                cfg: &cfg,
                store: &store,
                prompt: &prompt,
            };
            let item = if plain { pl("MINE") } else { sec("MINE") };
            let err = set_vars(&ctx, "work", &[item]).unwrap_err().to_string();
            assert!(
                err.contains("\"work\" was changed while envy was prompting"),
                "{err}"
            );
            assert!(err.contains("nothing was changed"), "{err}");
            assert_eq!(read(&dir, "work"), theirs);
            assert!(snap(&store).is_empty(), "orphaned Keychain item");
            std::fs::write(dir.path().join("work.toml"), "[vars]\nA = \"1\"\n").unwrap();
        }
    }

    #[test]
    fn edit_does_not_overwrite_a_member_changed_while_prompting() {
        let (dir, cfg) = config_with(&[("a", LINKED_A), ("b", LINKED_B)]);
        let store = MemoryStore::default();
        let theirs = "link = \"aws\"\n\n[vars]\nREGION = \"theirs\"\nTOKEN = \"@keychain\"\n";
        let prompt = WritesWhilePrompting {
            inner: ScriptedPrompter::new().with_plain("nb"),
            path: dir.path().join("b.toml"),
            text: theirs,
        };
        let ctx = Ctx {
            cfg: &cfg,
            store: &store,
            prompt: &prompt,
        };
        let seen = RefCell::new(Seen::default());
        let err = edit(&ctx, "a", &editor(&seen, |t| format!("{t}NEW = \"na\"\n")))
            .unwrap_err()
            .to_string();
        assert!(err.contains("\"b\" was changed while"), "{err}");
        assert_eq!(read(&dir, "a"), LINKED_A);
        assert_eq!(read(&dir, "b"), theirs);
    }

    #[test]
    fn create_does_not_replace_a_namespace_created_while_prompting() {
        let (dir, cfg) = config_with(&[("src", SOURCE)]);
        let store = MemoryStore::default();
        let prompt = CreatesFileWhilePrompting {
            inner: ScriptedPrompter::new().with_secret("new-token"),
            path: dir.path().join("dst.toml"),
        };
        let ctx = Ctx {
            cfg: &cfg,
            store: &store,
            prompt: &prompt,
        };
        let err = create(&ctx, "dst", Some("src"), None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("while envy was prompting"), "{err}");
        assert_eq!(read(&dir, "dst"), "[vars]\nTHEIRS = \"1\"\n");
        assert!(snap(&store).is_empty());
    }

    #[test]
    fn set_defaults_to_secret_and_file_holds_only_the_marker() {
        let (dir, cfg) = config_with(&[("work", "")]);
        let store = MemoryStore::default();
        let prompt = ScriptedPrompter::new().with_secret("hunter2");
        let ctx = Ctx {
            cfg: &cfg,
            store: &store,
            prompt: &prompt,
        };
        set_vars(&ctx, "work", &[sec("TOKEN")]).unwrap();
        assert_eq!(snap(&store), vec![entry("work", "TOKEN", "hunter2")]);
        let text = cfg.load("work").unwrap().text();
        assert!(!text.contains("hunter2"));
        assert_eq!(read(&dir, "work"), "[vars]\nTOKEN = \"@keychain\"\n");
    }

    #[test]
    fn set_secret_again_replaces_keychain_value_and_leaves_file() {
        let (dir, cfg) = config_with(&[("work", "[vars]\nTOKEN = \"@keychain\"\n")]);
        let store = MemoryStore::default();
        store
            .set("work", "TOKEN", &Secret::new("old".into()))
            .unwrap();
        let prompt = ScriptedPrompter::new().with_secret("new");
        let ctx = Ctx {
            cfg: &cfg,
            store: &store,
            prompt: &prompt,
        };
        set_vars(&ctx, "work", &[sec("TOKEN")]).unwrap();
        assert_eq!(snap(&store), vec![entry("work", "TOKEN", "new")]);
        assert_eq!(read(&dir, "work"), "[vars]\nTOKEN = \"@keychain\"\n");
    }

    #[test]
    fn set_plain_prompts_visible_with_current_value_as_default() {
        let (dir, cfg) = config_with(&[("work", "[vars]\nREGION = \"eu-west-1\"\n")]);
        let store = MemoryStore::default();
        let prompt = ScriptedPrompter::new().with_plain("us-east-1\n");
        let ctx = Ctx {
            cfg: &cfg,
            store: &store,
            prompt: &prompt,
        };
        set_vars(&ctx, "work", &[pl("REGION")]).unwrap();
        assert_eq!(
            prompt.asked(),
            vec![Asked::Plain {
                label: "Value for REGION in work".into(),
                default: Some("eu-west-1".into())
            }]
        );
        assert_eq!(read(&dir, "work"), "[vars]\nREGION = \"us-east-1\"\n");

        // Empty input keeps the current value.
        let keep = ScriptedPrompter::new().with_plain("\n");
        let ctx = Ctx {
            cfg: &cfg,
            store: &store,
            prompt: &keep,
        };
        set_vars(&ctx, "work", &[pl("REGION")]).unwrap();
        assert_eq!(read(&dir, "work"), "[vars]\nREGION = \"us-east-1\"\n");
        assert!(snap(&store).is_empty());
    }

    #[test]
    fn set_plain_keeps_awkward_characters_intact() {
        let (_dir, cfg) = config_with(&[("work", "")]);
        let store = MemoryStore::default();
        let prompt = ScriptedPrompter::new().with_plain("it's \"a\" b\\c  \n");
        let ctx = Ctx {
            cfg: &cfg,
            store: &store,
            prompt: &prompt,
        };
        set_vars(&ctx, "work", &[pl("MSG")]).unwrap();
        assert_eq!(
            cfg.load("work").unwrap().get("MSG"),
            Some(Value::Plain("it's \"a\" b\\c  ".into()))
        );
    }

    #[test]
    fn set_plain_marker_value_is_rejected_before_any_keychain_change() {
        let before = "[vars]\nTOKEN = \"@keychain\"\n";
        let (dir, cfg) = config_with(&[("work", before)]);
        let store = MemoryStore::default();
        store
            .set("work", "TOKEN", &Secret::new("keep-me".into()))
            .unwrap();
        let prompt = ScriptedPrompter::new()
            .with_confirm(true)
            .with_plain("@keychain");
        let ctx = Ctx {
            cfg: &cfg,
            store: &store,
            prompt: &prompt,
        };
        let err = set_vars(&ctx, "work", &[pl("TOKEN")])
            .unwrap_err()
            .to_string();
        assert!(err.contains("reserved"), "{err}");
        assert_eq!(read(&dir, "work"), before);
        assert_eq!(snap(&store), vec![entry("work", "TOKEN", "keep-me")]);
    }

    #[test]
    fn set_plain_nul_value_is_rejected() {
        let (dir, cfg) = config_with(&[("work", "")]);
        let store = MemoryStore::default();
        let prompt = ScriptedPrompter::new().with_plain("a\0b");
        let ctx = Ctx {
            cfg: &cfg,
            store: &store,
            prompt: &prompt,
        };
        assert!(set_vars(&ctx, "work", &[pl("X")]).is_err());
        assert_eq!(read(&dir, "work"), "");
    }

    #[test]
    fn set_converts_secret_to_plain_after_confirm_and_deletes_keychain_item() {
        let (dir, cfg) = config_with(&[("work", "[vars]\nTOKEN = \"@keychain\"\n")]);
        let store = MemoryStore::default();
        store
            .set("work", "TOKEN", &Secret::new("hunter2".into()))
            .unwrap();
        let prompt = ScriptedPrompter::new()
            .with_confirm(true)
            .with_plain("visible");
        let ctx = Ctx {
            cfg: &cfg,
            store: &store,
            prompt: &prompt,
        };
        set_vars(&ctx, "work", &[pl("TOKEN")]).unwrap();
        assert_eq!(read(&dir, "work"), "[vars]\nTOKEN = \"visible\"\n");
        assert!(snap(&store).is_empty());
        // The confirmation came first, and the plain prompt had no default.
        assert!(matches!(prompt.asked()[0], Asked::Confirm(_)));
        assert_eq!(
            prompt.asked()[1],
            Asked::Plain {
                label: "Value for TOKEN in work".into(),
                default: None
            }
        );
    }

    #[test]
    fn set_converts_plain_to_secret_after_confirm() {
        let (dir, cfg) = config_with(&[("work", "[vars]\nTOKEN = \"plain\"\n")]);
        let store = MemoryStore::default();
        let prompt = ScriptedPrompter::new()
            .with_confirm(true)
            .with_secret("hunter2");
        let ctx = Ctx {
            cfg: &cfg,
            store: &store,
            prompt: &prompt,
        };
        set_vars(&ctx, "work", &[sec("TOKEN")]).unwrap();
        assert_eq!(read(&dir, "work"), "[vars]\nTOKEN = \"@keychain\"\n");
        assert_eq!(snap(&store), vec![entry("work", "TOKEN", "hunter2")]);
    }

    #[test]
    fn declined_conversion_changes_nothing() {
        let secret_file = "[vars]\nTOKEN = \"@keychain\"\n";
        let plain_file = "[vars]\nTOKEN = \"plain\"\n";
        for (text, make_plain) in [(secret_file, true), (plain_file, false)] {
            let (dir, cfg) = config_with(&[("work", text)]);
            let store = MemoryStore::default();
            if text == secret_file {
                store
                    .set("work", "TOKEN", &Secret::new("hunter2".into()))
                    .unwrap();
            }
            let before = snap(&store);
            let prompt = ScriptedPrompter::new().with_confirm(false);
            let ctx = Ctx {
                cfg: &cfg,
                store: &store,
                prompt: &prompt,
            };
            let item = if make_plain {
                pl("TOKEN")
            } else {
                sec("TOKEN")
            };
            assert!(set_vars(&ctx, "work", &[item]).is_err());
            assert_eq!(read(&dir, "work"), text);
            assert_eq!(snap(&store), before);
            assert_eq!(prompt.asked().len(), 1);
        }
    }

    #[test]
    fn empty_secret_is_rejected_and_nothing_is_written() {
        let (dir, cfg) = config_with(&[("work", "")]);
        let store = MemoryStore::default();
        let prompt = ScriptedPrompter::new().with_secret("");
        let ctx = Ctx {
            cfg: &cfg,
            store: &store,
            prompt: &prompt,
        };
        assert!(set_vars(&ctx, "work", &[sec("TOKEN")]).is_err());
        assert_eq!(read(&dir, "work"), "");
        assert!(snap(&store).is_empty());
    }

    /// A store that, once an item is written, puts a non-empty directory
    /// where `path` was (keeping the file's text aside), so the save that
    /// follows fails. This runs inside `apply`, after every prompt and check.
    struct SquatOnSet {
        inner: MemoryStore,
        path: std::path::PathBuf,
        kept: std::cell::RefCell<Option<String>>,
    }

    impl SecretStore for SquatOnSet {
        fn get(&self, ns: &str, name: &str) -> Result<Option<Secret>> {
            self.inner.get(ns, name)
        }
        fn set(&self, ns: &str, name: &str, value: &Secret) -> Result<()> {
            self.inner.set(ns, name, value)?;
            if self.path.is_file() {
                *self.kept.borrow_mut() = Some(std::fs::read_to_string(&self.path).unwrap());
                std::fs::remove_file(&self.path).unwrap();
                std::fs::create_dir(&self.path).unwrap();
                std::fs::write(self.path.join("keep"), "").unwrap();
            }
            Ok(())
        }
        fn delete(&self, ns: &str, name: &str) -> Result<()> {
            self.inner.delete(ns, name)
        }
    }

    #[test]
    fn set_secret_file_save_failure_restores_the_keychain() {
        let (dir, cfg) = config_with(&[("work", "[vars]\nTOKEN = \"@keychain\"\n")]);
        let store = SquatOnSet {
            inner: MemoryStore::default(),
            path: dir.path().join("work.toml"),
            kept: Default::default(),
        };
        store
            .inner
            .set("work", "TOKEN", &Secret::new("stale".into()))
            .unwrap();
        let prompt = ScriptedPrompter::new().with_secret("fresh");
        let ctx = Ctx {
            cfg: &cfg,
            store: &store,
            prompt: &prompt,
        };
        let err = set_vars(&ctx, "work", &[sec("TOKEN")]).unwrap_err();
        assert!(
            format!("{err:#}").contains("cannot write namespace \"work\""),
            "{err:#}"
        );
        assert!(!format!("{err:#}").contains("fresh"), "{err:#}");
        // The squat really happened, and the prior value is back.
        assert!(dir.path().join("work.toml").is_dir());
        assert_eq!(
            store.kept.borrow().as_deref(),
            Some("[vars]\nTOKEN = \"@keychain\"\n")
        );
        assert_eq!(snap(&store.inner), vec![entry("work", "TOKEN", "stale")]);
    }

    #[test]
    fn set_on_unknown_namespace_errors_without_prompting() {
        let (dir, cfg) = config_with(&[]);
        let store = MemoryStore::default();
        let prompt = ScriptedPrompter::new().with_secret("hunter2");
        let ctx = Ctx {
            cfg: &cfg,
            store: &store,
            prompt: &prompt,
        };
        let err = set_vars(&ctx, "nope", &[sec("TOKEN")])
            .unwrap_err()
            .to_string();
        assert!(err.contains("nope") && err.contains("--new"), "{err}");
        assert!(file_names(&dir).is_empty());
        assert!(snap(&store).is_empty());
        assert_eq!(prompt.remaining(), 1);
    }

    #[test]
    fn set_rejects_invalid_names_before_any_access() {
        let (dir, cfg) = config_with(&[("work", "")]);
        let store = MemoryStore::default();
        let prompt = ScriptedPrompter::new().with_secret("hunter2");
        let ctx = Ctx {
            cfg: &cfg,
            store: &store,
            prompt: &prompt,
        };
        assert!(set_vars(&ctx, "work", &[sec("bad-name")]).is_err());
        assert!(set_vars(&ctx, "../x", &[sec("OK")]).is_err());
        // A bad name later in the list stops everything before any prompt.
        assert!(set_vars(&ctx, "work", &[sec("OK"), pv("ENVY_VARS", "x")]).is_err());
        assert_eq!(prompt.remaining(), 1);
        assert!(snap(&store).is_empty());
        assert_eq!(read(&dir, "work"), "");
    }

    // ---- set_vars: several items in one command ----

    fn ctx_for<'a>(
        cfg: &'a Config,
        store: &'a dyn SecretStore,
        prompt: &'a dyn Prompter,
    ) -> Ctx<'a> {
        Ctx { cfg, store, prompt }
    }

    #[test]
    fn set_vars_several_secrets_prompt_in_order_and_store_only_markers() {
        let (dir, cfg) = config_with(&[("work", "")]);
        let store = MemoryStore::default();
        let prompt = ScriptedPrompter::new()
            .with_secret("zq-gh")
            .with_secret("zq-oa")
            .with_secret("zq-np");
        set_vars(
            &ctx_for(&cfg, &store, &prompt),
            "work",
            &[sec("GITHUB_TOKEN"), sec("OPENAI_KEY"), sec("NPM_TOKEN")],
        )
        .unwrap();
        assert_eq!(
            prompt.asked(),
            vec![
                Asked::Secret("Secret value for GITHUB_TOKEN in work".into()),
                Asked::Secret("Secret value for OPENAI_KEY in work".into()),
                Asked::Secret("Secret value for NPM_TOKEN in work".into()),
            ]
        );
        assert_eq!(
            read(&dir, "work"),
            "[vars]\nGITHUB_TOKEN = \"@keychain\"\nOPENAI_KEY = \"@keychain\"\nNPM_TOKEN = \"@keychain\"\n"
        );
        assert_eq!(
            snap(&store),
            vec![
                entry("work", "GITHUB_TOKEN", "zq-gh"),
                entry("work", "NPM_TOKEN", "zq-np"),
                entry("work", "OPENAI_KEY", "zq-oa"),
            ]
        );
    }

    #[test]
    fn set_vars_mixed_kinds_prompt_in_the_given_order() {
        let (dir, cfg) = config_with(&[("work", "[vars]\nREGION = \"eu\"\n")]);
        let store = MemoryStore::default();
        let prompt = ScriptedPrompter::new()
            .with_plain("us\n")
            .with_secret("zq-tok");
        set_vars(
            &ctx_for(&cfg, &store, &prompt),
            "work",
            &[pl("REGION"), sec("TOKEN"), pv("PROFILE", "dev")],
        )
        .unwrap();
        assert_eq!(
            prompt.asked(),
            vec![
                Asked::Plain {
                    label: "Value for REGION in work".into(),
                    default: Some("eu".into())
                },
                Asked::Secret("Secret value for TOKEN in work".into()),
            ]
        );
        assert_eq!(
            read(&dir, "work"),
            "[vars]\nREGION = \"us\"\nTOKEN = \"@keychain\"\nPROFILE = \"dev\"\n"
        );
        assert_eq!(snap(&store), vec![entry("work", "TOKEN", "zq-tok")]);
    }

    #[test]
    fn set_vars_inline_plain_values_need_no_prompt() {
        let (dir, cfg) = config_with(&[("work", "[vars]\nA = \"old\"\n")]);
        let store = MemoryStore::default();
        let prompt = ScriptedPrompter::new();
        set_vars(
            &ctx_for(&cfg, &store, &prompt),
            "work",
            &[pv("A", "1"), pv("EMPTY", ""), pv("URL", "a=b=c")],
        )
        .unwrap();
        assert!(prompt.asked().is_empty());
        assert_eq!(
            read(&dir, "work"),
            "[vars]\nA = \"1\"\nEMPTY = \"\"\nURL = \"a=b=c\"\n"
        );
        assert_eq!(
            cfg.load("work").unwrap().get("EMPTY"),
            Some(Value::Plain(String::new()))
        );
        assert!(snap(&store).is_empty());
    }

    #[test]
    fn set_vars_conversions_confirm_each_then_write_once() {
        let before = "[vars]\nTOKEN = \"@keychain\"\nREGION = \"eu\"\n";
        let (dir, cfg) = config_with(&[("work", before)]);
        let store = MemoryStore::default();
        store
            .set("work", "TOKEN", &Secret::new("zq-old".into()))
            .unwrap();
        let prompt = ScriptedPrompter::new()
            .with_confirm(true)
            .with_confirm(true)
            .with_secret("zq-region");
        set_vars(
            &ctx_for(&cfg, &store, &prompt),
            "work",
            &[pv("TOKEN", "visible"), sec("REGION")],
        )
        .unwrap();
        assert_eq!(
            prompt.asked(),
            vec![
                Asked::Confirm(
                    "TOKEN is currently a secret. Replace it with a plain value (the Keychain item will be deleted)?"
                        .into()
                ),
                Asked::Confirm(
                    "REGION is currently a plain value. Replace it with a secret?".into()
                ),
                Asked::Secret("Secret value for REGION in work".into()),
            ]
        );
        assert_eq!(
            read(&dir, "work"),
            "[vars]\nTOKEN = \"visible\"\nREGION = \"@keychain\"\n"
        );
        assert_eq!(snap(&store), vec![entry("work", "REGION", "zq-region")]);
    }

    #[test]
    fn set_vars_declined_last_confirm_changes_nothing() {
        let before = "[vars]\nTOKEN = \"@keychain\"\n";
        let (dir, cfg) = config_with(&[("work", before)]);
        let store = MemoryStore::default();
        store
            .set("work", "TOKEN", &Secret::new("zq-keep".into()))
            .unwrap();
        let prompt = ScriptedPrompter::new()
            .with_secret("zq-new")
            .with_confirm(false);
        let err = set_vars(
            &ctx_for(&cfg, &store, &prompt),
            "work",
            &[sec("NEW"), pv("A", "1"), pl("TOKEN")],
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("cancelled") && err.contains("nothing was changed"),
            "{err}"
        );
        assert_eq!(prompt.asked().len(), 2, "{:?}", prompt.asked());
        assert_eq!(read(&dir, "work"), before);
        assert_eq!(file_names(&dir), ["work.toml"]);
        assert_eq!(snap(&store), vec![entry("work", "TOKEN", "zq-keep")]);
    }

    #[test]
    fn set_vars_failed_or_missing_later_prompt_writes_nothing() {
        let before = "[vars]\nOLD = \"@keychain\"\n";
        // The second item's prompt fails (empty secret), or the prompter
        // runs out of answers on the last one.
        for prompt in [
            ScriptedPrompter::new()
                .with_secret("zq-a")
                .with_secret("")
                .with_plain("c"),
            ScriptedPrompter::new()
                .with_secret("zq-a")
                .with_secret("zq-b"),
        ] {
            let (dir, cfg) = config_with(&[("work", before)]);
            let store = MemoryStore::default();
            store
                .set("work", "OLD", &Secret::new("zq-old".into()))
                .unwrap();
            let err = set_vars(
                &ctx_for(&cfg, &store, &prompt),
                "work",
                &[sec("A"), sec("OLD"), pl("C")],
            )
            .unwrap_err();
            assert!(!format!("{err:#}").contains("zq-"), "{err:#}");
            assert_eq!(read(&dir, "work"), before);
            assert_eq!(file_names(&dir), ["work.toml"]);
            assert_eq!(snap(&store), vec![entry("work", "OLD", "zq-old")]);
        }
    }

    #[test]
    fn set_vars_cancelled_plain_prompt_says_nothing_was_changed() {
        let (dir, cfg) = config_with(&[("work", "")]);
        let store = MemoryStore::default();
        // No answer for B's visible prompt (as when it is cancelled).
        let prompt = ScriptedPrompter::new().with_plain("1");
        let err =
            set_vars(&ctx_for(&cfg, &store, &prompt), "work", &[pl("A"), pl("B")]).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.starts_with("no value for B; nothing was changed"),
            "{msg}"
        );
        assert_eq!(read(&dir, "work"), "");
    }

    #[test]
    fn set_vars_inline_values_are_checked_before_any_prompt() {
        for bad in ["@keychain", "a\0b"] {
            let before = "[vars]\nB = \"@keychain\"\n";
            let (dir, cfg) = config_with(&[("work", before)]);
            let store = MemoryStore::default();
            store
                .set("work", "B", &Secret::new("zq-keep".into()))
                .unwrap();
            let prompt = ScriptedPrompter::new()
                .with_secret("zq-a")
                .with_confirm(true);
            let err = set_vars(
                &ctx_for(&cfg, &store, &prompt),
                "work",
                &[sec("A"), pv("B", bad)],
            )
            .unwrap_err()
            .to_string();
            assert!(err.contains("B"), "{err}");
            assert!(prompt.asked().is_empty(), "{:?}", prompt.asked());
            assert_eq!(read(&dir, "work"), before);
            assert_eq!(snap(&store), vec![entry("work", "B", "zq-keep")]);
        }
    }

    #[test]
    fn set_vars_rejects_duplicates_and_an_empty_list_before_any_prompt() {
        let (dir, cfg) = config_with(&[("work", "")]);
        let store = MemoryStore::default();
        let prompt = ScriptedPrompter::new().with_secret("zq-a");
        let ctx = ctx_for(&cfg, &store, &prompt);
        let err = set_vars(&ctx, "work", &[sec("A"), pv("A", "1")])
            .unwrap_err()
            .to_string();
        assert!(err.contains("A") && err.contains("more than once"), "{err}");
        assert!(set_vars(&ctx, "work", &[]).is_err());
        assert!(prompt.asked().is_empty());
        assert_eq!(read(&dir, "work"), "");
        assert!(snap(&store).is_empty());
    }

    #[test]
    fn set_vars_save_failure_restores_overwritten_and_new_secrets() {
        let before = "[vars]\nTOKEN = \"@keychain\"\n";
        let (dir, cfg) = config_with(&[("work", before)]);
        let store = SquatOnSet {
            inner: MemoryStore::default(),
            path: dir.path().join("work.toml"),
            kept: Default::default(),
        };
        store
            .inner
            .set("work", "TOKEN", &Secret::new("zq-stale".into()))
            .unwrap();
        let prompt = ScriptedPrompter::new()
            .with_secret("zq-fresh")
            .with_secret("zq-new");
        let err = set_vars(
            &ctx_for(&cfg, &store, &prompt),
            "work",
            &[sec("TOKEN"), sec("NEW"), pv("P", "x")],
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("cannot write namespace \"work\""), "{msg}");
        assert!(!msg.contains("zq-"), "{msg}");
        // The squat really happened (after every prompt), and the Keychain
        // is exactly as before: TOKEN's prior value back, NEW gone.
        assert!(dir.path().join("work.toml").is_dir());
        assert_eq!(store.kept.borrow().as_deref(), Some(before));
        assert_eq!(prompt.remaining(), 0);
        assert_eq!(snap(&store.inner), vec![entry("work", "TOKEN", "zq-stale")]);
    }

    /// Answers like its inner prompter; on the first hidden or visible prompt
    /// only, writes `text` to `path`, as another envy command would.
    struct WritesOnFirstPrompt {
        inner: ScriptedPrompter,
        path: std::path::PathBuf,
        text: &'static str,
        done: std::cell::Cell<bool>,
    }

    impl WritesOnFirstPrompt {
        fn touch(&self) {
            if !self.done.replace(true) {
                std::fs::write(&self.path, self.text).unwrap();
            }
        }
    }

    impl Prompter for WritesOnFirstPrompt {
        fn secret(&self, label: &str) -> Result<Secret> {
            self.touch();
            self.inner.secret(label)
        }
        fn plain(&self, label: &str, default: Option<&str>) -> Result<String> {
            self.touch();
            self.inner.plain(label, default)
        }
        fn confirm(&self, question: &str) -> Result<bool> {
            self.inner.confirm(question)
        }
    }

    #[test]
    fn set_vars_rechecks_the_file_after_all_prompts() {
        let (dir, cfg) = config_with(&[("work", "[vars]\nA = \"1\"\n")]);
        let store = MemoryStore::default();
        let theirs = "[vars]\nA = \"1\"\nTHEIRS = \"x\"\n";
        let prompt = WritesOnFirstPrompt {
            inner: ScriptedPrompter::new()
                .with_secret("zq-x")
                .with_plain("y")
                .with_secret("zq-z"),
            path: dir.path().join("work.toml"),
            text: theirs,
            done: Default::default(),
        };
        let err = set_vars(
            &ctx_for(&cfg, &store, &prompt),
            "work",
            &[sec("X"), pl("Y"), sec("Z")],
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("\"work\" was changed while envy was prompting")
                && err.contains("nothing was changed"),
            "{err}"
        );
        // Every prompt was still asked first: one check, before the write.
        assert_eq!(prompt.inner.remaining(), 0);
        assert_eq!(read(&dir, "work"), theirs);
        assert!(snap(&store).is_empty(), "orphaned Keychain item");
    }

    #[test]
    fn remove_deletes_file_and_keychain_items_after_confirm() {
        let (dir, cfg) = config_with(&[
            (
                "work",
                "[vars]\nA = \"x\"\nT1 = \"@keychain\"\nT2 = \"@keychain\"\n",
            ),
            ("other", "[vars]\nT1 = \"@keychain\"\n"),
        ]);
        let store = MemoryStore::default();
        store.set("work", "T1", &Secret::new("one".into())).unwrap();
        // T2 is already absent from the Keychain: still fine.
        store
            .set("other", "T1", &Secret::new("keep".into()))
            .unwrap();
        let prompt = ScriptedPrompter::new().with_confirm(true);
        let ctx = Ctx {
            cfg: &cfg,
            store: &store,
            prompt: &prompt,
        };
        remove(&ctx, "work").unwrap();
        assert_eq!(file_names(&dir), vec!["other.toml"]);
        assert_eq!(snap(&store), vec![entry("other", "T1", "keep")]);
    }

    #[test]
    fn remove_declined_changes_nothing() {
        let text = "[vars]\nT1 = \"@keychain\"\n";
        let (dir, cfg) = config_with(&[("work", text)]);
        let store = MemoryStore::default();
        store.set("work", "T1", &Secret::new("one".into())).unwrap();
        let prompt = ScriptedPrompter::new().with_confirm(false);
        let ctx = Ctx {
            cfg: &cfg,
            store: &store,
            prompt: &prompt,
        };
        assert!(remove(&ctx, "work").is_err());
        assert_eq!(read(&dir, "work"), text);
        assert_eq!(snap(&store), vec![entry("work", "T1", "one")]);
    }

    #[test]
    fn remove_unknown_namespace_errors_without_prompting() {
        let (_dir, cfg) = config_with(&[]);
        let store = MemoryStore::default();
        let prompt = ScriptedPrompter::new().with_confirm(true);
        let ctx = Ctx {
            cfg: &cfg,
            store: &store,
            prompt: &prompt,
        };
        assert!(remove(&ctx, "nope").is_err());
        assert_eq!(prompt.remaining(), 1);
    }

    #[test]
    fn remove_question_names_secrets_but_never_values() {
        let (_dir, cfg) =
            config_with(&[("work", "[vars]\nA = \"plain-val\"\nT1 = \"@keychain\"\n")]);
        let store = MemoryStore::default();
        store
            .set("work", "T1", &Secret::new("hunter2".into()))
            .unwrap();
        let prompt = ScriptedPrompter::new().with_confirm(true);
        let ctx = Ctx {
            cfg: &cfg,
            store: &store,
            prompt: &prompt,
        };
        remove(&ctx, "work").unwrap();
        let Asked::Confirm(q) = &prompt.asked()[0] else {
            panic!()
        };
        assert!(
            q.contains("T1") && !q.contains("hunter2") && !q.contains("plain-val"),
            "{q}"
        );
    }

    // ---- edit ----

    use std::cell::RefCell;
    use std::os::unix::fs::MetadataExt;
    use std::path::PathBuf;

    /// What the fake editor saw of the temp copy.
    #[derive(Default)]
    struct Seen {
        path: Option<PathBuf>,
        text: String,
        file_mode: u32,
        dir_mode: u32,
    }

    /// A fake editor that records what it was given and then replaces the
    /// copy's text with `edit(old text)`.
    fn editor<'a>(
        seen: &'a RefCell<Seen>,
        edit: impl Fn(&str) -> String + 'a,
    ) -> impl Fn(&Path) -> Result<()> + 'a {
        move |path: &Path| {
            let text = std::fs::read_to_string(path)?;
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            *seen.borrow_mut() = Seen {
                path: Some(path.to_path_buf()),
                text: text.clone(),
                file_mode: mode(path),
                dir_mode: mode(path.parent().unwrap()),
            };
            std::fs::write(path, edit(&text))?;
            Ok(())
        }
    }

    /// The fake editor ran on a private copy of `original`, which is gone now.
    fn assert_private_copy_removed(seen: &RefCell<Seen>, original: &str) {
        let seen = seen.borrow();
        let path = seen.path.as_ref().expect("the editor ran");
        assert_eq!(seen.text, original);
        assert_eq!(seen.file_mode, 0o600);
        assert_eq!(seen.dir_mode, 0o700);
        assert!(!path.exists(), "{path:?} left behind");
        assert!(!path.parent().unwrap().exists(), "temp dir left behind");
    }

    fn never_runs(_: &Path) -> Result<()> {
        panic!("the editor must not run")
    }

    #[test]
    fn edit_adds_secret_line_and_prompts_hidden_value() {
        let before = "# mine\n[vars]\nREGION = \"eu\" # where\n";
        let (dir, cfg) = config_with(&[("work", before)]);
        let store = MemoryStore::default();
        let prompt = ScriptedPrompter::new().with_secret("s3cret");
        let ctx = Ctx {
            cfg: &cfg,
            store: &store,
            prompt: &prompt,
        };
        let seen = RefCell::new(Seen::default());
        edit(
            &ctx,
            "work",
            &editor(&seen, |t| format!("{t}TOKEN = \"@keychain\" # new\n")),
        )
        .unwrap();
        assert_private_copy_removed(&seen, before);
        assert_eq!(
            read(&dir, "work"),
            "# mine\n[vars]\nREGION = \"eu\" # where\nTOKEN = \"@keychain\" # new\n"
        );
        assert_eq!(
            prompt.asked(),
            vec![Asked::Secret("Secret value for TOKEN in work".into())]
        );
        assert_eq!(snap(&store), vec![entry("work", "TOKEN", "s3cret")]);
        assert_eq!(file_names(&dir), ["work.toml"]);
    }

    #[test]
    fn edit_plain_to_secret_converts_and_prompts_hidden_value() {
        let (dir, cfg) = config_with(&[("work", "[vars]\nA = \"x\"\nB = \"y\"\n")]);
        let store = MemoryStore::default();
        let prompt = ScriptedPrompter::new().with_secret("sb");
        let ctx = Ctx {
            cfg: &cfg,
            store: &store,
            prompt: &prompt,
        };
        let seen = RefCell::new(Seen::default());
        edit(
            &ctx,
            "work",
            &editor(&seen, |t| t.replace("\"y\"", "\"@keychain\"")),
        )
        .unwrap();
        assert_eq!(read(&dir, "work"), "[vars]\nA = \"x\"\nB = \"@keychain\"\n");
        assert_eq!(
            prompt.asked(),
            vec![Asked::Secret("Secret value for B in work".into())]
        );
        assert_eq!(snap(&store), vec![entry("work", "B", "sb")]);
    }

    #[test]
    fn edit_plain_change_updates_file_without_prompts() {
        let before = "# top\n[vars]\n# about A\nA = \"1\" # inline\nT = \"@keychain\"\n";
        let (dir, cfg) = config_with(&[("work", before)]);
        let store = MemoryStore::default();
        store.set("work", "T", &Secret::new("t".into())).unwrap();
        let prompt = ScriptedPrompter::new();
        let ctx = Ctx {
            cfg: &cfg,
            store: &store,
            prompt: &prompt,
        };
        let seen = RefCell::new(Seen::default());
        let after = "# top\n[vars]\n# about A\nA = \"2\"   # inline, edited\nT = \"@keychain\"\nB = 'lit'\n";
        assert!(edit(&ctx, "work", &editor(&seen, |_| after.to_string())).unwrap());
        assert_private_copy_removed(&seen, before);
        assert_eq!(read(&dir, "work"), after);
        assert!(prompt.asked().is_empty());
        assert_eq!(snap(&store), vec![entry("work", "T", "t")]);
    }

    #[test]
    fn edit_secret_to_plain_deletes_keychain_item_after_confirm() {
        let (dir, cfg) = config_with(&[(
            "work",
            "[vars]\nTOKEN = \"@keychain\"\nGONE = \"@keychain\"\nKEEP = \"@keychain\"\n",
        )]);
        let store = MemoryStore::default();
        for (name, value) in [("TOKEN", "zq-1"), ("GONE", "zq-2"), ("KEEP", "zq-3")] {
            store.set("work", name, &Secret::new(value.into())).unwrap();
        }
        store
            .set("other", "TOKEN", &Secret::new("o".into()))
            .unwrap();
        let prompt = ScriptedPrompter::new().with_confirm(true);
        let ctx = Ctx {
            cfg: &cfg,
            store: &store,
            prompt: &prompt,
        };
        let seen = RefCell::new(Seen::default());
        edit(
            &ctx,
            "work",
            &editor(&seen, |_| {
                "[vars]\nTOKEN = \"now-visible\"\nKEEP = \"@keychain\"\n".into()
            }),
        )
        .unwrap();
        assert_eq!(
            read(&dir, "work"),
            "[vars]\nTOKEN = \"now-visible\"\nKEEP = \"@keychain\"\n"
        );
        assert_eq!(
            snap(&store),
            vec![entry("other", "TOKEN", "o"), entry("work", "KEEP", "zq-3")]
        );
        let asked = prompt.asked();
        assert_eq!(asked.len(), 1, "{asked:?}");
        let Asked::Confirm(q) = &asked[0] else {
            panic!("{asked:?}")
        };
        assert_eq!(
            q,
            "Delete the Keychain items for TOKEN, GONE from \"work\" (no longer secrets there)?"
        );
    }

    #[test]
    fn edit_declining_keychain_cleanup_saves_the_file_and_keeps_the_items() {
        let (dir, cfg) = config_with(&[("work", "[vars]\nTOKEN = \"@keychain\"\n")]);
        let store = MemoryStore::default();
        store
            .set("work", "TOKEN", &Secret::new("zq-1".into()))
            .unwrap();
        let prompt = ScriptedPrompter::new().with_confirm(false);
        let ctx = Ctx {
            cfg: &cfg,
            store: &store,
            prompt: &prompt,
        };
        let seen = RefCell::new(Seen::default());
        edit(&ctx, "work", &editor(&seen, |_| "[vars]\n".into())).unwrap();
        assert_eq!(read(&dir, "work"), "[vars]\n");
        assert_eq!(snap(&store), vec![entry("work", "TOKEN", "zq-1")]);
        assert_eq!(prompt.asked().len(), 1);
    }

    const LINKED_A: &str = "link = \"aws\"\n\n[vars]\nREGION = \"eu\"\nTOKEN = \"@keychain\"\n";
    const LINKED_B: &str = "link = \"aws\"\n\n[vars]\nREGION = \"us\"\nTOKEN = \"@keychain\"\n";
    const LINKED_C: &str = "link = \"aws\"\n\n[vars]\nTOKEN = \"@keychain\"\nREGION = \"ap\"\n";

    #[test]
    fn edit_removed_secret_offers_cleanup_and_propagates_to_group() {
        let (dir, cfg) = config_with(&[
            ("a", LINKED_A),
            ("b", LINKED_B),
            ("c", LINKED_C),
            ("other", "[vars]\nTOKEN = \"@keychain\"\n"),
        ]);
        let store = MemoryStore::default();
        for ns in ["a", "b", "c", "other"] {
            store
                .set(ns, "TOKEN", &Secret::new(format!("zq-{ns}")))
                .unwrap();
        }
        let prompt = ScriptedPrompter::new()
            .with_confirm(true)
            .with_confirm(true);
        let ctx = Ctx {
            cfg: &cfg,
            store: &store,
            prompt: &prompt,
        };
        let seen = RefCell::new(Seen::default());
        edit(
            &ctx,
            "a",
            &editor(&seen, |t| t.replace("TOKEN = \"@keychain\"\n", "")),
        )
        .unwrap();
        assert_private_copy_removed(&seen, LINKED_A);
        let asked = prompt.asked();
        assert_eq!(
            asked,
            vec![
                Asked::Confirm(
                    "Delete the Keychain items for TOKEN from \"a\" (no longer secrets there)?"
                        .into()
                ),
                Asked::Confirm(
                    "Link group \"aws\" must match \"a\". This will change:\n  b: remove TOKEN (deletes Keychain items: TOKEN)\n  c: remove TOKEN (deletes Keychain items: TOKEN)\nContinue?"
                        .into()
                ),
            ]
        );
        assert!(!format!("{asked:?}").contains("zq-"));
        assert_eq!(
            read(&dir, "a"),
            "link = \"aws\"\n\n[vars]\nREGION = \"eu\"\n"
        );
        assert_eq!(
            read(&dir, "b"),
            "link = \"aws\"\n\n[vars]\nREGION = \"us\"\n"
        );
        assert_eq!(
            read(&dir, "c"),
            "link = \"aws\"\n\n[vars]\nREGION = \"ap\"\n"
        );
        assert_eq!(snap(&store), vec![entry("other", "TOKEN", "zq-other")]);
    }

    #[test]
    fn edit_new_name_in_linked_namespace_prompts_in_every_member_before_writing() {
        let (dir, cfg) = config_with(&[("a", LINKED_A), ("b", LINKED_B)]);
        let store = MemoryStore::default();
        let edited = |t: &str| format!("{t}KEY = \"@keychain\"\nDB_USER = \"alice\"\n");

        // No answer for b's DB_USER: nothing at all is written.
        let short = ScriptedPrompter::new().with_secret("ka").with_secret("kb");
        let ctx = Ctx {
            cfg: &cfg,
            store: &store,
            prompt: &short,
        };
        let seen = RefCell::new(Seen::default());
        assert!(edit(&ctx, "a", &editor(&seen, edited)).is_err());
        assert_eq!(short.asked().len(), 3);
        assert_eq!(
            (read(&dir, "a"), read(&dir, "b")),
            (LINKED_A.into(), LINKED_B.into())
        );
        assert!(snap(&store).is_empty());

        let prompt = ScriptedPrompter::new()
            .with_secret("ka")
            .with_secret("kb")
            .with_plain("user-b");
        let ctx = Ctx {
            cfg: &cfg,
            store: &store,
            prompt: &prompt,
        };
        edit(&ctx, "a", &editor(&seen, edited)).unwrap();
        assert_eq!(
            prompt.asked(),
            vec![
                Asked::Secret("Secret value for KEY in a".into()),
                Asked::Secret("Secret value for KEY in b".into()),
                Asked::Plain {
                    label: "Value for DB_USER in b".into(),
                    default: None
                },
            ]
        );
        assert_eq!(
            snap(&store),
            vec![entry("a", "KEY", "ka"), entry("b", "KEY", "kb")]
        );
        assert_eq!(
            read(&dir, "a"),
            format!("{LINKED_A}KEY = \"@keychain\"\nDB_USER = \"alice\"\n")
        );
        assert_eq!(
            read(&dir, "b"),
            format!("{LINKED_B}KEY = \"@keychain\"\nDB_USER = \"user-b\"\n")
        );
    }

    #[test]
    fn edit_invalid_toml_is_rejected_and_original_untouched() {
        let before = "[vars]\nA = \"1\"\nT = \"@keychain\"\n";
        let (dir, cfg) = config_with(&[("work", before)]);
        let store = MemoryStore::default();
        store.set("work", "T", &Secret::new("t".into())).unwrap();
        let prompt = ScriptedPrompter::new().with_confirm(true);
        let ctx = Ctx {
            cfg: &cfg,
            store: &store,
            prompt: &prompt,
        };
        let seen = RefCell::new(Seen::default());
        let err = edit(
            &ctx,
            "work",
            &editor(&seen, |_| "[vars\nA = \"zq-typed\" oops\n".into()),
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("invalid TOML") && msg.contains("nothing was changed"),
            "{msg}"
        );
        assert!(!msg.contains("zq-typed"), "{msg}");
        assert_private_copy_removed(&seen, before);
        assert_eq!(read(&dir, "work"), before);
        assert_eq!(snap(&store), vec![entry("work", "T", "t")]);
        assert!(prompt.asked().is_empty());
    }

    #[test]
    fn edit_rejects_bad_variable_names_and_values() {
        let before = "[vars]\nA = \"1\"\n";
        for bad in [
            "[vars]\nA = \"1\"\n\"BAD-NAME\" = \"zq-v\"\n",
            "[vars]\nENVY_ACTIVE = \"zq-v\"\n",
            "[vars]\nA = 5\n",
            "[vars]\nA = \"zq-v\"\n[vars.nested]\nB = \"1\"\n",
        ] {
            let (dir, cfg) = config_with(&[("work", before)]);
            let store = MemoryStore::default();
            let prompt = ScriptedPrompter::new();
            let ctx = Ctx {
                cfg: &cfg,
                store: &store,
                prompt: &prompt,
            };
            let seen = RefCell::new(Seen::default());
            let err = edit(&ctx, "work", &editor(&seen, |_| bad.to_string())).unwrap_err();
            let msg = format!("{err:#}");
            assert!(msg.contains("nothing was changed"), "{bad:?}: {msg}");
            assert!(!msg.contains("zq-v"), "{msg}");
            assert_eq!(read(&dir, "work"), before);
            assert!(snap(&store).is_empty());
        }
    }

    #[test]
    fn edit_rejects_plain_marker_literal() {
        // In the editor the marker always means "secret", however it is
        // spelled: it is never stored as a plain value. Without a hidden
        // value to go with it, the edit is rejected.
        for spelled in [
            "'@keychain'",
            "\"\\u0040keychain\"",
            "\"\"\"@keychain\"\"\"",
        ] {
            let before = "[vars]\nA = \"x\"\n";
            let (dir, cfg) = config_with(&[("work", before)]);
            let store = MemoryStore::default();
            let prompt = ScriptedPrompter::new().with_secret("");
            let ctx = Ctx {
                cfg: &cfg,
                store: &store,
                prompt: &prompt,
            };
            let seen = RefCell::new(Seen::default());
            let after = format!("[vars]\nA = {spelled}\n");
            let err = edit(&ctx, "work", &editor(&seen, |_| after.clone())).unwrap_err();
            let msg = format!("{err:#}");
            assert!(msg.contains("nothing was changed"), "{msg}");
            assert_eq!(
                prompt.asked(),
                vec![Asked::Secret("Secret value for A in work".into())]
            );
            assert_eq!(read(&dir, "work"), before);
            assert!(snap(&store).is_empty());
            assert_eq!(
                cfg.load("work").unwrap().get("A"),
                Some(Value::Plain("x".into()))
            );
        }
    }

    #[test]
    fn edit_rejects_link_label_change() {
        let linked = "link = \"aws\"\n[vars]\nA = \"1\"\n";
        let unlinked = "[vars]\nA = \"1\"\n";
        for (before, after) in [
            (linked, "link = \"gcp\"\n[vars]\nA = \"1\"\n"),
            (linked, unlinked),
            (unlinked, linked),
        ] {
            let (dir, cfg) = config_with(&[("work", before)]);
            let store = MemoryStore::default();
            let prompt = ScriptedPrompter::new();
            let ctx = Ctx {
                cfg: &cfg,
                store: &store,
                prompt: &prompt,
            };
            let seen = RefCell::new(Seen::default());
            let err = edit(&ctx, "work", &editor(&seen, |_| after.to_string()))
                .unwrap_err()
                .to_string();
            assert!(err.contains("--link") && err.contains("--unlink"), "{err}");
            assert!(err.contains("nothing was changed"), "{err}");
            assert_eq!(read(&dir, "work"), before);
            assert!(prompt.asked().is_empty());
        }
        // A bad label is rejected by the parser.
        let (dir, cfg) = config_with(&[("work", linked)]);
        let store = MemoryStore::default();
        let prompt = ScriptedPrompter::new();
        let ctx = Ctx {
            cfg: &cfg,
            store: &store,
            prompt: &prompt,
        };
        let seen = RefCell::new(Seen::default());
        let err = edit(
            &ctx,
            "work",
            &editor(&seen, |_| "link = \"../x\"\n[vars]\nA = \"1\"\n".into()),
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("link"), "{err:#}");
        assert_eq!(read(&dir, "work"), linked);
    }

    #[test]
    fn edit_with_no_changes_repairs_drifted_group_by_conforming_others() {
        // `a` was hand-edited: it gained NEW and lost TOKEN. Editing it
        // without changes makes it the truth for the rest of the group.
        let a = "link = \"aws\"\n\n[vars]\nREGION = \"eu\"\nNEW = \"n\"\n";
        let (dir, cfg) = config_with(&[("a", a), ("b", LINKED_B), ("c", LINKED_C)]);
        let store = MemoryStore::default();
        store
            .set("b", "TOKEN", &Secret::new("zq-b".into()))
            .unwrap();
        store
            .set("c", "TOKEN", &Secret::new("zq-c".into()))
            .unwrap();
        assert!(link::ensure_aligned(&cfg, &cfg.load("a").unwrap()).is_err());
        let a_inode = std::fs::metadata(dir.path().join("a.toml")).unwrap().ino();
        let prompt = ScriptedPrompter::new()
            .with_confirm(true)
            .with_plain("nb")
            .with_plain("nc");
        let ctx = Ctx {
            cfg: &cfg,
            store: &store,
            prompt: &prompt,
        };
        let seen = RefCell::new(Seen::default());
        assert!(edit(&ctx, "a", &editor(&seen, str::to_string)).unwrap());
        assert_eq!(
            prompt.asked(),
            vec![
                Asked::Confirm(
                    "Link group \"aws\" must match \"a\". This will change:\n  b: remove TOKEN (deletes Keychain items: TOKEN)\n  c: remove TOKEN (deletes Keychain items: TOKEN)\nContinue?"
                        .into()
                ),
                Asked::Plain {
                    label: "Value for NEW in b".into(),
                    default: None
                },
                Asked::Plain {
                    label: "Value for NEW in c".into(),
                    default: None
                },
            ]
        );
        // `a` itself was not rewritten.
        assert_eq!(read(&dir, "a"), a);
        assert_eq!(
            std::fs::metadata(dir.path().join("a.toml")).unwrap().ino(),
            a_inode
        );
        assert_eq!(
            read(&dir, "b"),
            "link = \"aws\"\n\n[vars]\nREGION = \"us\"\nNEW = \"nb\"\n"
        );
        assert_eq!(
            read(&dir, "c"),
            "link = \"aws\"\n\n[vars]\nREGION = \"ap\"\nNEW = \"nc\"\n"
        );
        assert!(snap(&store).is_empty());
        link::ensure_aligned(&cfg, &cfg.load("b").unwrap()).unwrap();

        // Declining the group's confirmation changes nothing anywhere.
        let (dir, cfg) = config_with(&[("a", a), ("b", LINKED_B)]);
        let store = MemoryStore::default();
        store
            .set("b", "TOKEN", &Secret::new("zq-b".into()))
            .unwrap();
        let prompt = ScriptedPrompter::new().with_confirm(false);
        let ctx = Ctx {
            cfg: &cfg,
            store: &store,
            prompt: &prompt,
        };
        assert!(edit(&ctx, "a", &editor(&seen, str::to_string)).is_err());
        assert_eq!(
            (read(&dir, "a"), read(&dir, "b")),
            (a.into(), LINKED_B.into())
        );
        assert_eq!(snap(&store), vec![entry("b", "TOKEN", "zq-b")]);
    }

    #[test]
    fn edit_conforms_an_inconsistent_group_to_the_edited_member() {
        // b and c disagree with each other and with a. Unlike --link, edit
        // (like --secret and --plain) takes the edited file as the truth and conforms each
        // other member to it, so it repairs an inconsistent group too.
        let a = "link = \"aws\"\n[vars]\nREGION = \"eu\"\n";
        let b = "link = \"aws\"\n[vars]\nREGION = \"us\"\nX = \"1\"\n";
        let c = "link = \"aws\"\n[vars]\nY = \"2\"\n";
        let (dir, cfg) = config_with(&[("a", a), ("b", b), ("c", c)]);
        let store = MemoryStore::default();
        let prompt = ScriptedPrompter::new().with_confirm(true).with_plain("ap");
        let ctx = Ctx {
            cfg: &cfg,
            store: &store,
            prompt: &prompt,
        };
        let seen = RefCell::new(Seen::default());
        assert!(edit(&ctx, "a", &editor(&seen, str::to_string)).unwrap());
        let Asked::Confirm(q) = &prompt.asked()[0] else {
            panic!()
        };
        assert!(
            q.contains("b: remove X") && q.contains("c: remove Y"),
            "{q}"
        );
        assert_eq!(read(&dir, "a"), a);
        assert_eq!(read(&dir, "b"), "link = \"aws\"\n[vars]\nREGION = \"us\"\n");
        assert_eq!(read(&dir, "c"), "link = \"aws\"\n[vars]\nREGION = \"ap\"\n");
        assert!(snap(&store).is_empty());
    }

    #[test]
    fn edit_with_no_changes_on_unlinked_namespace_writes_and_asks_nothing() {
        let before = "# c\n[vars]\nA = \"1\"\nT = \"@keychain\"\n";
        let (dir, cfg) = config_with(&[("work", before), ("x", "link = \"g\"\n")]);
        let inode = std::fs::metadata(dir.path().join("work.toml"))
            .unwrap()
            .ino();
        let store = MemoryStore::default();
        store.set("work", "T", &Secret::new("t".into())).unwrap();
        let prompt = ScriptedPrompter::new();
        let ctx = Ctx {
            cfg: &cfg,
            store: &store,
            prompt: &prompt,
        };
        let seen = RefCell::new(Seen::default());
        assert!(!edit(&ctx, "work", &editor(&seen, str::to_string)).unwrap());
        assert_private_copy_removed(&seen, before);
        assert!(prompt.asked().is_empty());
        assert_eq!(read(&dir, "work"), before);
        assert_eq!(
            std::fs::metadata(dir.path().join("work.toml"))
                .unwrap()
                .ino(),
            inode
        );
        assert_eq!(snap(&store), vec![entry("work", "T", "t")]);
    }

    #[test]
    fn edit_editor_failure_changes_nothing_and_removes_the_copy() {
        let before = "[vars]\nA = \"1\"\n";
        let (dir, cfg) = config_with(&[("work", before)]);
        let store = MemoryStore::default();
        let prompt = ScriptedPrompter::new();
        let ctx = Ctx {
            cfg: &cfg,
            store: &store,
            prompt: &prompt,
        };
        let copy: RefCell<Option<PathBuf>> = RefCell::new(None);
        let err = edit(&ctx, "work", &|path: &Path| {
            std::fs::write(path, "[vars]\nA = \"2\"\n")?;
            *copy.borrow_mut() = Some(path.to_path_buf());
            bail!("the editor exited with status 1")
        })
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("status 1") && msg.contains("nothing was changed"),
            "{msg}"
        );
        assert_eq!(read(&dir, "work"), before);
        let copy = copy.borrow().clone().unwrap();
        assert!(!copy.parent().unwrap().exists());
        assert_eq!(file_names(&dir), ["work.toml"]);
    }

    #[test]
    fn edit_removes_the_copy_even_if_the_editor_panics() {
        let (_dir, cfg) = config_with(&[("work", "")]);
        let store = MemoryStore::default();
        let prompt = ScriptedPrompter::new();
        let ctx = Ctx {
            cfg: &cfg,
            store: &store,
            prompt: &prompt,
        };
        let copy: RefCell<Option<PathBuf>> = RefCell::new(None);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            edit(&ctx, "work", &|path: &Path| {
                *copy.borrow_mut() = Some(path.to_path_buf());
                panic!("editor blew up")
            })
        }));
        assert!(result.is_err());
        assert!(!copy.borrow().clone().unwrap().parent().unwrap().exists());
    }

    #[test]
    fn edit_refuses_unknown_and_unparseable_namespaces_without_running_the_editor() {
        let (dir, cfg) = config_with(&[("broken", "[vars\nA = \"zq-v\"\n")]);
        let store = MemoryStore::default();
        let prompt = ScriptedPrompter::new();
        let ctx = Ctx {
            cfg: &cfg,
            store: &store,
            prompt: &prompt,
        };
        let msg = format!("{:#}", edit(&ctx, "nope", &never_runs).unwrap_err());
        assert!(msg.contains("nope") && msg.contains("--new"), "{msg}");
        let msg = format!("{:#}", edit(&ctx, "broken", &never_runs).unwrap_err());
        let path = dir.path().join("broken.toml");
        assert!(
            msg.contains(&path.display().to_string()) && msg.contains("invalid TOML"),
            "{msg}"
        );
        assert!(!msg.contains("zq-v"), "{msg}");
        assert!(edit(&ctx, "../x", &never_runs).is_err());
        assert_eq!(read(&dir, "broken"), "[vars\nA = \"zq-v\"\n");
    }

    #[test]
    fn edit_refuses_a_linked_namespace_whose_group_cannot_be_read_before_editing() {
        let (_dir, cfg) = config_with(&[("a", LINKED_A), ("bad", "[vars\n")]);
        let store = MemoryStore::default();
        let prompt = ScriptedPrompter::new();
        let ctx = Ctx {
            cfg: &cfg,
            store: &store,
            prompt: &prompt,
        };
        let msg = format!("{:#}", edit(&ctx, "a", &never_runs).unwrap_err());
        assert!(msg.contains("\"bad\""), "{msg}");
    }

    #[test]
    fn edit_secret_prompt_failure_writes_nothing() {
        let before = "[vars]\nA = \"1\"\nOLD = \"@keychain\"\n";
        let (dir, cfg) = config_with(&[("work", before)]);
        let store = MemoryStore::default();
        store.set("work", "OLD", &Secret::new("o".into())).unwrap();
        let prompt = ScriptedPrompter::new().with_confirm(true).with_secret("");
        let ctx = Ctx {
            cfg: &cfg,
            store: &store,
            prompt: &prompt,
        };
        let seen = RefCell::new(Seen::default());
        assert!(
            edit(
                &ctx,
                "work",
                &editor(&seen, |_| "[vars]\nA = \"1\"\nNEW = \"@keychain\"\n".into())
            )
            .is_err()
        );
        assert_eq!(read(&dir, "work"), before);
        assert_eq!(snap(&store), vec![entry("work", "OLD", "o")]);
    }

    #[test]
    fn edit_does_not_overwrite_a_file_changed_while_the_editor_was_open() {
        let before = "[vars]\nA = \"1\"\n";
        let (dir, cfg) = config_with(&[("work", before)]);
        let store = MemoryStore::default();
        let prompt = ScriptedPrompter::new();
        let ctx = Ctx {
            cfg: &cfg,
            store: &store,
            prompt: &prompt,
        };
        let original = dir.path().join("work.toml");
        let err = edit(&ctx, "work", &|path: &Path| {
            std::fs::write(&original, "[vars]\nTHEIRS = \"1\"\n")?;
            std::fs::write(path, "[vars]\nA = \"2\"\n")?;
            Ok(())
        })
        .unwrap_err()
        .to_string();
        assert!(err.contains("changed while"), "{err}");
        assert_eq!(read(&dir, "work"), "[vars]\nTHEIRS = \"1\"\n");
    }

    fn project_cfg(base: &std::path::Path, identity: &str) -> Config {
        Config::project(
            base.join(".envy"),
            base.to_path_buf(),
            identity.to_string(),
            base.join("user"),
        )
    }

    fn secret_change(cfg: &Config, value: &str) -> Change {
        let mut file = NamespaceFile::empty("dev").unwrap();
        file.set_var("TOKEN", Value::Secret).unwrap();
        let before = cfg.load("dev").ok();
        Change {
            file,
            before,
            secrets: vec![("TOKEN".into(), Secret::new(value.into()))],
            delete: Vec::new(),
        }
    }

    #[test]
    fn apply_with_a_project_config_uses_the_project_key() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = project_cfg(dir.path(), "acme/api");
        let store = MemoryStore::default();
        let prompt = ScriptedPrompter::new();
        let ctx = Ctx {
            cfg: &cfg,
            store: &store,
            prompt: &prompt,
        };
        apply(&ctx, vec![secret_change(&cfg, "v1")]).unwrap();
        assert_eq!(
            store.snapshot(),
            vec![entry("project/acme/api/dev", "TOKEN", "v1")]
        );
        // Dropping the secret deletes the project item, not a bare one.
        let mut change = secret_change(&cfg, "v1");
        change.secrets.clear();
        change.delete = vec!["TOKEN".into()];
        apply(&ctx, vec![change]).unwrap();
        assert!(store.snapshot().is_empty());
    }

    #[test]
    fn two_projects_with_the_same_namespace_do_not_collide() {
        let dir = tempfile::tempdir().unwrap();
        let a = project_cfg(&dir.path().join("a"), "acme/api");
        let b = project_cfg(&dir.path().join("b"), "acme/web");
        let user = Config::new(dir.path().join("user-cfg"));
        let store = MemoryStore::default();
        let prompt = ScriptedPrompter::new();
        for (cfg, value) in [(&a, "va"), (&b, "vb"), (&user, "vu")] {
            let ctx = Ctx {
                cfg,
                store: &store,
                prompt: &prompt,
            };
            apply(&ctx, vec![secret_change(cfg, value)]).unwrap();
        }
        assert_eq!(
            store.snapshot(),
            vec![
                entry("dev", "TOKEN", "vu"),
                entry("project/acme/api/dev", "TOKEN", "va"),
                entry("project/acme/web/dev", "TOKEN", "vb"),
            ]
        );
        let render = |cfg: &Config| activate(cfg, &store, "dev", &ActiveState::default()).unwrap();
        assert!(render(&a).ends_with("export TOKEN='va'\n"));
        assert!(render(&b).ends_with("export TOKEN='vb'\n"));
        assert!(render(&user).ends_with("export TOKEN='vu'\n"));

        // Removing one leaves the others untouched.
        let yes = ScriptedPrompter::new().with_confirm(true);
        remove(
            &Ctx {
                cfg: &a,
                store: &store,
                prompt: &yes,
            },
            "dev",
        )
        .unwrap();
        assert_eq!(
            store.snapshot(),
            vec![
                entry("dev", "TOKEN", "vu"),
                entry("project/acme/web/dev", "TOKEN", "vb"),
            ]
        );
        assert!(!a.exists("dev").unwrap());
    }

    fn two_secret_change(cfg: &Config) -> Change {
        let mut file = NamespaceFile::empty("dev").unwrap();
        file.set_var("A", Value::Secret).unwrap();
        file.set_var("B", Value::Secret).unwrap();
        Change {
            file,
            before: cfg.load("dev").ok(),
            secrets: vec![
                ("A".into(), Secret::new("new-a".into())),
                ("B".into(), Secret::new("new-b".into())),
            ],
            delete: Vec::new(),
        }
    }

    #[test]
    fn project_keychain_failure_rolls_back_under_the_project_key() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = project_cfg(dir.path(), "acme/api");
        let store = FailingSet {
            inner: MemoryStore::default(),
            fail_on: "B",
        };
        store
            .inner
            .set("dev", "A", &Secret::new("user-a".into()))
            .unwrap();
        store
            .inner
            .set("project/acme/api/dev", "A", &Secret::new("old-a".into()))
            .unwrap();
        let before = snap(&store.inner);
        let prompt = ScriptedPrompter::new();
        let ctx = Ctx {
            cfg: &cfg,
            store: &store,
            prompt: &prompt,
        };
        // dev (A) is written first, then web (B) fails: dev must be rolled
        // back by `rollback_all` under its project key.
        let mut web = NamespaceFile::empty("web").unwrap();
        web.set_var("B", Value::Secret).unwrap();
        let web = Change {
            file: web,
            before: None,
            secrets: vec![("B".into(), Secret::new("new-b".into()))],
            delete: Vec::new(),
        };
        let mut dev = two_secret_change(&cfg);
        dev.secrets.truncate(1);
        assert!(apply(&ctx, vec![dev, web]).is_err());
        assert_eq!(
            before,
            vec![
                entry("dev", "A", "user-a"),
                entry("project/acme/api/dev", "A", "old-a"),
            ]
        );
        assert_eq!(snap(&store.inner), before);
        assert!(!cfg.exists("dev").unwrap() && !cfg.exists("web").unwrap());
    }

    #[test]
    fn project_file_save_failure_rolls_back_under_the_project_key() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = project_cfg(dir.path(), "acme/api");
        let text = "[vars]\nA = \"@keychain\"\n";
        std::fs::create_dir_all(cfg.dir()).unwrap();
        std::fs::write(cfg.dir().join("dev.toml"), text).unwrap();
        let store = SquatOnSet {
            inner: MemoryStore::default(),
            path: cfg.dir().join("dev.toml"),
            kept: Default::default(),
        };
        store
            .inner
            .set("dev", "A", &Secret::new("user-a".into()))
            .unwrap();
        store
            .inner
            .set("project/acme/api/dev", "A", &Secret::new("old-a".into()))
            .unwrap();
        let before = snap(&store.inner);
        let prompt = ScriptedPrompter::new();
        let ctx = Ctx {
            cfg: &cfg,
            store: &store,
            prompt: &prompt,
        };
        let err = apply(&ctx, vec![two_secret_change(&cfg)]).unwrap_err();
        assert!(
            format!("{err:#}").contains("cannot write namespace \"dev\""),
            "{err:#}"
        );
        assert!(cfg.dir().join("dev.toml").is_dir());
        assert_eq!(store.kept.borrow().as_deref(), Some(text));
        assert_eq!(snap(&store.inner), before);
    }
}
