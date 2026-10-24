//! Linked namespaces: a group of namespaces whose files carry the same
//! `link = "<label>"` key and always have the same variable names, with the
//! same secret/plain flag per name. Values stay per namespace. The members'
//! files are the only record of the group.

use std::collections::BTreeMap;

use anyhow::{Context, Result, anyhow, bail};

use crate::commands::{Change, Ctx, apply};
use crate::config::{Config, NamespaceFile, Value};
use crate::names::validate_namespace;
use crate::prompt::{plain_label, secret_label};
use crate::secret::Secret;

/// Every namespace whose `link` is `group`, sorted by name.
///
/// A file in the config directory that cannot be read or parsed stops this
/// with an error naming it: it might be a member, and skipping it would let
/// a group operation leave it behind and the group drift.
pub fn members(cfg: &Config, group: &str) -> Result<Vec<NamespaceFile>> {
    validate_namespace(group)?;
    let mut found = Vec::new();
    for name in cfg.list()? {
        let file = cfg.load(&name).with_context(|| {
            format!("cannot check link group {group:?}: namespace {name:?} cannot be read; fix or remove it first")
        })?;
        if file.link() == Some(group) {
            found.push(file);
        }
    }
    Ok(found)
}

/// The other members of `file`'s group (none when it is not linked).
pub(crate) fn others(cfg: &Config, file: &NamespaceFile) -> Result<Vec<NamespaceFile>> {
    match file.link() {
        None => Ok(Vec::new()),
        Some(group) => members_except(cfg, group, file.name()),
    }
}

/// The members of `group` other than `name`.
fn members_except(cfg: &Config, group: &str, name: &str) -> Result<Vec<NamespaceFile>> {
    Ok(members(cfg, group)?
        .into_iter()
        .filter(|m| m.name() != name)
        .collect())
}

/// Called just before writing, after every prompt: fails unless `file` and
/// the other members of `group` (`others`, as read when the command started)
/// are still exactly as they were, with the same members. Prompts can take a
/// while, and another envy command (or an editor) may have changed one of
/// them meanwhile; writing over that change would lose it and could orphan
/// its Keychain items. Names only in the errors.
pub(crate) fn ensure_unchanged(
    cfg: &Config,
    file: &NamespaceFile,
    group: Option<&str>,
    others: &[NamespaceFile],
) -> Result<()> {
    let changed = |name: &str| {
        anyhow!("namespace {name:?} was changed while envy was prompting; nothing was changed")
    };
    if cfg.load(file.name()).map(|now| now.text()).ok() != Some(file.text()) {
        return Err(changed(file.name()));
    }
    let Some(group) = group else {
        return Ok(());
    };
    let now = members_except(cfg, group, file.name()).with_context(|| {
        format!("link group {group:?} was changed while envy was prompting; nothing was changed")
    })?;
    let names = |files: &[NamespaceFile]| -> Vec<String> {
        files.iter().map(|f| f.name().to_string()).collect()
    };
    if names(&now) != names(others) {
        bail!(
            "link group {group:?} was changed while envy was prompting (a member joined or left); nothing was changed"
        );
    }
    for (then, now) in others.iter().zip(&now) {
        if then.text() != now.text() {
            return Err(changed(then.name()));
        }
    }
    Ok(())
}

/// Variable names with their secret flag; all that alignment compares.
type Shape = BTreeMap<String, bool>;

fn shape(file: &NamespaceFile) -> Shape {
    file.vars()
        .into_iter()
        .map(|(name, value)| (name, value == Value::Secret))
        .collect()
}

fn kind(secret: bool) -> &'static str {
    if secret { "secret" } else { "plain" }
}

/// How `file` differs from a group member `other`. Names keep file order:
/// `missing` in `other`'s, the rest in `file`'s.
#[derive(Default)]
struct Drift {
    /// In `other` but not in `file`, with `other`'s flag.
    missing: Vec<(String, bool)>,
    /// In `file` but not in `other`.
    extra: Vec<String>,
    /// In both with a different flag, with `file`'s flag.
    flipped: Vec<(String, bool)>,
}

fn drift(file: &NamespaceFile, other: &NamespaceFile) -> Drift {
    let mine = shape(file);
    let theirs = shape(other);
    let mut d = Drift::default();
    for (name, value) in other.vars() {
        if !mine.contains_key(&name) {
            d.missing.push((name, value == Value::Secret));
        }
    }
    for (name, value) in file.vars() {
        let secret = value == Value::Secret;
        match theirs.get(&name) {
            None => d.extra.push(name),
            Some(&s) if s != secret => d.flipped.push((name, secret)),
            Some(_) => {}
        }
    }
    d
}

/// `Ok` when `ns` is unlinked or matches every other member of its group;
/// otherwise an `Err` naming what is missing, extra or of the other kind
/// (names only, never values).
pub fn ensure_aligned(cfg: &Config, ns: &NamespaceFile) -> Result<()> {
    let Some(group) = ns.link() else {
        return Ok(());
    };
    let mut missing: Vec<String> = Vec::new();
    let mut extra: Vec<String> = Vec::new();
    let mut flipped: Vec<String> = Vec::new();
    let mut seen_flip: Vec<String> = Vec::new();
    let others = others(cfg, ns)?;
    for other in &others {
        let d = drift(ns, other);
        for (name, _) in d.missing {
            if !missing.contains(&name) {
                missing.push(name);
            }
        }
        for name in d.extra {
            if !extra.contains(&name) {
                extra.push(name);
            }
        }
        for (name, secret) in d.flipped {
            if !seen_flip.contains(&name) {
                flipped.push(format!(
                    "{name} is {} here but {} in {}",
                    kind(secret),
                    kind(!secret),
                    other.name()
                ));
                seen_flip.push(name);
            }
        }
    }
    let mut problems: Vec<String> = Vec::new();
    if !missing.is_empty() {
        problems.push(format!("missing {}", missing.join(", ")));
    }
    if !extra.is_empty() {
        problems.push(format!("extra {}", extra.join(", ")));
    }
    let only_missing = extra.is_empty() && flipped.is_empty();
    problems.extend(flipped);
    if problems.is_empty() {
        return Ok(());
    }
    let name = ns.name();
    // `--link` only adds missing names, and only when the rest of the group
    // agrees on what they are; anything else needs the namespace edited.
    let group_agrees = others.windows(2).all(|w| shape(&w[0]) == shape(&w[1]));
    let hint = if only_missing && group_agrees {
        format!("Repair it with: envy {name} --link {group}")
    } else {
        format!(
            "--link cannot repair this: make it match the group with envy {name} --edit \
             (or envy {name} --secret NAME or --plain NAME); saving it makes the rest of the group match it"
        )
    };
    bail!(
        "namespace {name:?} has drifted from link group {group:?}: {}. {hint}",
        problems.join("; ")
    )
}

/// Test helper only: makes every other member of `source`'s group match
/// `source`, which must already be on disk, writing them straight away.
/// Commands must not use it: saving the source first and then asking the
/// group's question would write before every prompt is answered. They build
/// the source's [`Change`] and pass it, with [`conform`]'s changes, to one
/// [`apply`] (see `commands::set_vars`).
#[cfg(test)]
pub(crate) fn propagate(ctx: &Ctx, source: &NamespaceFile) -> Result<()> {
    let group = others(ctx.cfg, source)?;
    apply(ctx, conform(ctx, source, group)?)
}

/// What one member needs in order to match the source.
struct Plan {
    member: NamespaceFile,
    drift: Drift,
}

/// Works out, asks and returns (without writing anything) the changes that
/// make each of `others` match `source`, the namespace the user just changed.
/// `source` is the truth: other members that disagree with it, or with each
/// other, are each brought to its names and flags.
///
/// One `confirm` first lists every removal and every conversion in every
/// member (names only); then each missing or converted name is prompted for,
/// member by member (hidden for secrets, visible for plain). Removed names
/// and secrets turned plain are deleted from that member's Keychain items
/// once all files are saved.
pub(crate) fn conform(
    ctx: &Ctx,
    source: &NamespaceFile,
    others: Vec<NamespaceFile>,
) -> Result<Vec<Change>> {
    let Some(group) = source.link() else {
        return Ok(Vec::new());
    };
    let plans: Vec<Plan> = others
        .into_iter()
        .map(|member| Plan {
            // `missing` here is what the member lacks; `flipped` carries the
            // member's current flag, so the target is the opposite.
            drift: drift(&member, source),
            member,
        })
        .collect();

    let mut lines: Vec<String> = Vec::new();
    for plan in &plans {
        let d = &plan.drift;
        let mut parts: Vec<String> = Vec::new();
        if !d.extra.is_empty() {
            parts.push(format!("remove {}", d.extra.join(", ")));
        }
        for target in [false, true] {
            let names: Vec<&str> = d
                .flipped
                .iter()
                .filter(|(_, secret)| *secret != target)
                .map(|(n, _)| n.as_str())
                .collect();
            if !names.is_empty() {
                parts.push(format!("make {} {}", names.join(", "), kind(target)));
            }
        }
        if parts.is_empty() {
            continue;
        }
        let deleted = keychain_deletions(&plan.member, d);
        let mut line = format!("  {}: {}", plan.member.name(), parts.join("; "));
        if !deleted.is_empty() {
            line.push_str(&format!(
                " (deletes Keychain items: {})",
                deleted.join(", ")
            ));
        }
        lines.push(line);
    }
    if !lines.is_empty() {
        let question = format!(
            "Link group {group:?} must match {:?}. This will change:\n{}\nContinue?",
            source.name(),
            lines.join("\n")
        );
        if !ctx.prompt.confirm(&question)? {
            bail!("cancelled; nothing was changed");
        }
    }

    let mut changes: Vec<Change> = Vec::new();
    for plan in plans {
        let d = &plan.drift;
        if d.missing.is_empty() && d.extra.is_empty() && d.flipped.is_empty() {
            continue;
        }
        let delete = keychain_deletions(&plan.member, d);
        let mut file = plan.member.clone();
        for name in &d.extra {
            file.remove_var(name);
        }
        // Prompt in the source's order for everything the member must take.
        let needed: Vec<(String, bool)> = source
            .vars()
            .into_iter()
            .map(|(name, value)| (name, value == Value::Secret))
            .filter(|(name, _)| {
                d.missing.iter().any(|(n, _)| n == name) || d.flipped.iter().any(|(n, _)| n == name)
            })
            .collect();
        let mut secrets: Vec<(String, Secret)> = Vec::new();
        fill_missing(ctx, &mut file, &needed, &mut secrets)?;
        changes.push(Change {
            file,
            before: Some(plan.member),
            secrets,
            delete,
        });
    }
    Ok(changes)
}

/// The member's secrets that its new version will no longer hold as secrets.
fn keychain_deletions(member: &NamespaceFile, d: &Drift) -> Vec<String> {
    let mut names: Vec<String> = d
        .extra
        .iter()
        .filter(|n| member.get(n) == Some(Value::Secret))
        .cloned()
        .collect();
    names.extend(d.flipped.iter().filter(|(_, s)| *s).map(|(n, _)| n.clone()));
    names
}

/// Prompts for each of `names` (with its secret flag) in `file`'s namespace,
/// setting it in `file` and queueing secrets for the Keychain. Labels hold
/// the variable and namespace names only.
pub(crate) fn fill_missing(
    ctx: &Ctx,
    file: &mut NamespaceFile,
    names: &[(String, bool)],
    secrets: &mut Vec<(String, Secret)>,
) -> Result<()> {
    let ns = file.name().to_string();
    for (name, secret) in names {
        let nothing = || format!("no value for {name} in {ns:?}; nothing was changed");
        if *secret {
            let value = ctx
                .prompt
                .secret(&secret_label(name, &ns))
                .with_context(nothing)?;
            file.set_var(name, Value::Secret)?;
            secrets.push((name.clone(), value));
        } else {
            let value = ctx
                .prompt
                .plain(&plain_label(name, &ns), None)
                .with_context(nothing)?;
            file.set_var(name, Value::Plain(value))?;
        }
    }
    Ok(())
}

/// Checks that `file` can join (or stay in) `group` and returns the names it
/// lacks, with their flags. Refuses, naming them, if `file` has names the
/// group does not or a name of the other kind, and refuses if the other
/// members do not agree with each other (there would be nothing to conform
/// to). A group with no other members accepts anything.
pub(crate) fn check_join(
    cfg: &Config,
    file: &NamespaceFile,
    group: &str,
) -> Result<Vec<(String, bool)>> {
    check_join_with(file, group, &members_except(cfg, group, file.name())?)
}

/// [`check_join`] against `others`, the group's other members.
fn check_join_with(
    file: &NamespaceFile,
    group: &str,
    others: &[NamespaceFile],
) -> Result<Vec<(String, bool)>> {
    let Some(first) = others.first() else {
        return Ok(Vec::new());
    };
    for other in &others[1..] {
        if shape(other) != shape(first) {
            bail!(
                "link group {group:?} is inconsistent: {:?} and {:?} do not have the same variables; \
                 setting a variable in one member with --secret or --plain brings the others in line with it",
                first.name(),
                other.name()
            );
        }
    }
    let d = drift(file, first);
    let mut problems: Vec<String> = Vec::new();
    if !d.extra.is_empty() {
        problems.push(format!(
            "it has variables the group does not: {} (remove them first)",
            d.extra.join(", ")
        ));
    }
    for (name, secret) in &d.flipped {
        problems.push(format!(
            "{name} is {} here but {} in the group",
            kind(*secret),
            kind(!secret)
        ));
    }
    if !problems.is_empty() {
        bail!(
            "namespace {:?} cannot join link group {group:?}: {}",
            file.name(),
            problems.join("; ")
        );
    }
    Ok(d.missing)
}

/// Joins `ns` to `group`. A new label starts the group from `ns`'s names;
/// otherwise `ns` must conform: names it lacks are prompted for, and it is
/// refused if it has extra names or a name of the other kind. Linking to the
/// group it is already in re-runs that check, which repairs drift. Nothing is
/// written if `ns` or a member of the group changed while prompting.
pub fn link(ctx: &Ctx, ns: &str, group: &str) -> Result<()> {
    validate_namespace(ns)?;
    validate_namespace(group)?;
    let before = ctx.cfg.load(ns)?;
    if let Some(current) = before.link()
        && current != group
    {
        bail!(
            "namespace {ns:?} is already in link group {current:?}; leave it first with: envy {ns} --unlink"
        );
    }
    let group_others = members_except(ctx.cfg, group, ns)?;
    let missing = check_join_with(&before, group, &group_others)?;
    if before.link() == Some(group) && missing.is_empty() {
        return Ok(());
    }
    let mut file = before.clone();
    let mut secrets: Vec<(String, Secret)> = Vec::new();
    fill_missing(ctx, &mut file, &missing, &mut secrets)?;
    file.set_link(Some(group))?;
    ensure_unchanged(ctx.cfg, &before, Some(group), &group_others)?;
    apply(
        ctx,
        vec![Change {
            file,
            before: Some(before),
            secrets,
            delete: Vec::new(),
        }],
    )
}

/// Takes `ns` out of its link group, keeping its variables. Unlinking a
/// namespace that is not linked is an error, so a typo is not silently
/// accepted.
pub fn unlink(ctx: &Ctx, ns: &str) -> Result<()> {
    validate_namespace(ns)?;
    let mut file = ctx.cfg.load(ns)?;
    if file.link().is_none() {
        bail!("namespace {ns:?} is not in a link group");
    }
    file.set_link(None)?;
    ctx.cfg.save(&file)
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::path::PathBuf;

    use super::*;
    use crate::activate::ActiveState;
    use crate::commands::{SetItem, activate, create, set_vars};
    use crate::prompt::{Asked, Prompter, ScriptedPrompter};
    use crate::secret::Secret;
    use crate::store::{MemoryStore, SecretStore};

    fn config_with(files: &[(&str, &str)]) -> (tempfile::TempDir, Config) {
        let dir = tempfile::tempdir().unwrap();
        for (name, text) in files {
            std::fs::write(dir.path().join(format!("{name}.toml")), text).unwrap();
        }
        let cfg = Config::new(dir.path().to_path_buf());
        (dir, cfg)
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
    fn pv_item(name: &str, value: &str) -> SetItem {
        SetItem::plain(name, Some(value))
    }

    fn store_with(items: &[(&str, &str, &str)]) -> MemoryStore {
        let store = MemoryStore::default();
        for (ns, name, value) in items {
            store
                .set(ns, name, &Secret::new(value.to_string()))
                .unwrap();
        }
        store
    }

    fn ctx<'a>(cfg: &'a Config, store: &'a dyn SecretStore, prompt: &'a dyn Prompter) -> Ctx<'a> {
        Ctx { cfg, store, prompt }
    }

    /// Every file's text, for byte-for-byte "nothing changed" checks.
    fn texts(dir: &tempfile::TempDir) -> Vec<(String, String)> {
        file_names(dir)
            .into_iter()
            .map(|f| {
                let text = std::fs::read_to_string(dir.path().join(&f)).unwrap();
                (f, text)
            })
            .collect()
    }

    const A: &str = "link = \"aws\"\n\n[vars]\nREGION = \"eu-west-1\"\nTOKEN = \"@keychain\"\nDB_USER = \"alice\"\n";

    #[test]
    fn link_with_new_label_creates_group_from_namespace() {
        let w = "[vars]\nREGION = \"eu\"\nTOKEN = \"@keychain\"\n";
        let x = "link = \"gcp\"\n\n[vars]\nOTHER = \"1\"\n";
        let (dir, cfg) = config_with(&[("w", w), ("x", x)]);
        let store = store_with(&[("w", "TOKEN", "t")]);
        let prompt = ScriptedPrompter::new();
        link(&ctx(&cfg, &store, &prompt), "w", "aws").unwrap();
        assert_eq!(
            read(&dir, "w"),
            "link = \"aws\"\n[vars]\nREGION = \"eu\"\nTOKEN = \"@keychain\"\n"
        );
        assert_eq!(read(&dir, "x"), x);
        assert!(prompt.asked().is_empty());
        assert_eq!(store.snapshot(), vec![entry("w", "TOKEN", "t")]);
        let members: Vec<String> = members(&cfg, "aws")
            .unwrap()
            .iter()
            .map(|m| m.name().to_string())
            .collect();
        assert_eq!(members, ["w"]);
        ensure_aligned(&cfg, &cfg.load("w").unwrap()).unwrap();
    }

    #[test]
    fn link_joins_existing_group_prompting_for_missing_names() {
        let b = "[vars]\nREGION = \"us-east-1\"\n";
        let (dir, cfg) = config_with(&[("a", A), ("b", b)]);
        let store = store_with(&[("a", "TOKEN", "ta")]);
        let prompt = ScriptedPrompter::new()
            .with_secret("tb")
            .with_plain("bob\n");
        link(&ctx(&cfg, &store, &prompt), "b", "aws").unwrap();
        assert_eq!(
            prompt.asked(),
            vec![
                Asked::Secret("Secret value for TOKEN in b".into()),
                Asked::Plain {
                    label: "Value for DB_USER in b".into(),
                    default: None
                },
            ]
        );
        assert_eq!(
            read(&dir, "b"),
            "link = \"aws\"\n[vars]\nREGION = \"us-east-1\"\nTOKEN = \"@keychain\"\nDB_USER = \"bob\"\n"
        );
        assert_eq!(read(&dir, "a"), A);
        assert_eq!(
            store.snapshot(),
            vec![entry("a", "TOKEN", "ta"), entry("b", "TOKEN", "tb")]
        );
        ensure_aligned(&cfg, &cfg.load("b").unwrap()).unwrap();
    }

    #[test]
    fn link_refuses_extra_names_listing_them_and_changes_nothing() {
        let b = "[vars]\nREGION = \"x\"\nEXTRA1 = \"zq-plain\"\nEXTRA2 = \"@keychain\"\n";
        let (dir, cfg) = config_with(&[("a", A), ("b", b)]);
        let store = store_with(&[("a", "TOKEN", "ta"), ("b", "EXTRA2", "zq-secret")]);
        let before = (texts(&dir), store.snapshot());
        let prompt = ScriptedPrompter::new().with_secret("tb").with_plain("bob");
        let err = link(&ctx(&cfg, &store, &prompt), "b", "aws")
            .unwrap_err()
            .to_string();
        assert!(err.contains("EXTRA1, EXTRA2"), "{err}");
        assert!(!err.contains("zq-"), "{err}");
        assert!(prompt.asked().is_empty());
        assert_eq!((texts(&dir), store.snapshot()), before);
    }

    #[test]
    fn link_refuses_flag_mismatch_naming_it_and_changes_nothing() {
        let b = "[vars]\nREGION = \"@keychain\"\nTOKEN = \"@keychain\"\n";
        let (dir, cfg) = config_with(&[("a", A), ("b", b)]);
        let store = store_with(&[("a", "TOKEN", "ta"), ("b", "REGION", "r")]);
        let before = (texts(&dir), store.snapshot());
        let prompt = ScriptedPrompter::new().with_plain("bob");
        let err = link(&ctx(&cfg, &store, &prompt), "b", "aws")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("REGION is secret here but plain in the group"),
            "{err}"
        );
        assert!(prompt.asked().is_empty());
        assert_eq!((texts(&dir), store.snapshot()), before);
    }

    /// Answers like its inner prompter, but on every hidden or visible prompt
    /// writes `text` to `path`, as a concurrent envy command would.
    struct WritesWhilePrompting {
        inner: ScriptedPrompter,
        path: PathBuf,
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

    /// `a` (= `A`) and an aligned `b` in group `aws`.
    const B: &str =
        "link = \"aws\"\n\n[vars]\nREGION = \"us\"\nTOKEN = \"@keychain\"\nDB_USER = \"bob\"\n";

    #[test]
    fn set_does_not_overwrite_a_member_changed_or_added_while_prompting() {
        let theirs_b = "link = \"aws\"\n\n[vars]\nREGION = \"theirs\"\nTOKEN = \"@keychain\"\nDB_USER = \"bob\"\n";
        // Changing a member, or a new member joining, both stop the write.
        for (file, text, culprit) in [
            ("b.toml", theirs_b, "namespace \"b\" was changed"),
            ("c.toml", A, "link group \"aws\" was changed"),
        ] {
            let (dir, cfg) = config_with(&[("a", A), ("b", B)]);
            let store = store_with(&[("a", "TOKEN", "ta"), ("b", "TOKEN", "tb")]);
            let prompt = WritesWhilePrompting {
                inner: ScriptedPrompter::new().with_plain("na").with_plain("nb"),
                path: dir.path().join(file),
                text,
            };
            let err = set_vars(&ctx(&cfg, &store, &prompt), "a", &[pl("NEW")])
                .unwrap_err()
                .to_string();
            assert!(
                err.contains(culprit) && err.contains("while envy was prompting"),
                "{err}"
            );
            assert!(err.contains("nothing was changed"), "{err}");
            assert_eq!(read(&dir, "a"), A);
            assert_eq!(
                std::fs::read_to_string(dir.path().join(file)).unwrap(),
                text
            );
            assert_eq!(
                store.snapshot(),
                vec![entry("a", "TOKEN", "ta"), entry("b", "TOKEN", "tb")]
            );
        }
    }

    #[test]
    fn link_does_not_overwrite_a_file_changed_while_prompting() {
        let b = "[vars]\nREGION = \"us-east-1\"\n";
        let theirs_b = "[vars]\nREGION = \"theirs\"\n";
        let theirs_a = "link = \"aws\"\n\n[vars]\nREGION = \"eu-west-1\"\nTOKEN = \"@keychain\"\nDB_USER = \"alice\"\nMORE = \"1\"\n";
        // The namespace being linked, or a member of the group it joins.
        for (file, text, culprit) in [
            ("b.toml", theirs_b, "namespace \"b\" was changed"),
            ("a.toml", theirs_a, "namespace \"a\" was changed"),
        ] {
            let (dir, cfg) = config_with(&[("a", A), ("b", b)]);
            let store = store_with(&[("a", "TOKEN", "ta")]);
            let prompt = WritesWhilePrompting {
                inner: ScriptedPrompter::new().with_secret("tb").with_plain("bob"),
                path: dir.path().join(file),
                text,
            };
            let err = link(&ctx(&cfg, &store, &prompt), "b", "aws")
                .unwrap_err()
                .to_string();
            assert!(
                err.contains(culprit) && err.contains("while envy was prompting"),
                "{err}"
            );
            assert_eq!(
                std::fs::read_to_string(dir.path().join(file)).unwrap(),
                text
            );
            if file == "a.toml" {
                assert_eq!(read(&dir, "b"), b);
            } else {
                assert_eq!(read(&dir, "a"), A);
            }
            assert_eq!(store.snapshot(), vec![entry("a", "TOKEN", "ta")]);
        }
    }

    #[test]
    fn link_to_own_group_repairs_drift() {
        // `b` was hand-edited and lost DB_USER.
        let b = "link = \"aws\"\n\n[vars]\nREGION = \"us\"\nTOKEN = \"@keychain\"\n";
        let (dir, cfg) = config_with(&[("a", A), ("b", b)]);
        let store = store_with(&[("a", "TOKEN", "ta"), ("b", "TOKEN", "tb")]);
        assert!(ensure_aligned(&cfg, &cfg.load("b").unwrap()).is_err());
        let prompt = ScriptedPrompter::new().with_plain("bob");
        link(&ctx(&cfg, &store, &prompt), "b", "aws").unwrap();
        assert_eq!(
            read(&dir, "b"),
            "link = \"aws\"\n\n[vars]\nREGION = \"us\"\nTOKEN = \"@keychain\"\nDB_USER = \"bob\"\n"
        );
        ensure_aligned(&cfg, &cfg.load("b").unwrap()).unwrap();
        assert_eq!(
            store.snapshot(),
            vec![entry("a", "TOKEN", "ta"), entry("b", "TOKEN", "tb")]
        );
        // Already aligned: linking again asks and changes nothing.
        let quiet = ScriptedPrompter::new();
        let before = texts(&dir);
        link(&ctx(&cfg, &store, &quiet), "b", "aws").unwrap();
        assert!(quiet.asked().is_empty());
        assert_eq!(texts(&dir), before);
    }

    #[test]
    fn link_refuses_namespace_in_another_group() {
        let b = "link = \"gcp\"\n\n[vars]\nREGION = \"x\"\n";
        let (dir, cfg) = config_with(&[("a", A), ("b", b)]);
        let store = MemoryStore::default();
        let prompt = ScriptedPrompter::new();
        let err = link(&ctx(&cfg, &store, &prompt), "b", "aws")
            .unwrap_err()
            .to_string();
        assert!(err.contains("gcp") && err.contains("--unlink"), "{err}");
        assert_eq!(read(&dir, "b"), b);
    }

    #[test]
    fn link_refuses_when_group_members_disagree() {
        let c = "link = \"aws\"\n\n[vars]\nREGION = \"x\"\n";
        let b = "[vars]\nREGION = \"y\"\n";
        let (dir, cfg) = config_with(&[("a", A), ("b", b), ("c", c)]);
        let store = MemoryStore::default();
        let before = texts(&dir);
        let prompt = ScriptedPrompter::new().with_secret("t").with_plain("u");
        let err = link(&ctx(&cfg, &store, &prompt), "b", "aws")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("inconsistent") && err.contains("\"a\"") && err.contains("\"c\""),
            "{err}"
        );
        assert!(err.contains("with --secret or --plain"), "{err}");
        assert!(prompt.asked().is_empty());
        assert_eq!(texts(&dir), before);
        assert!(store.snapshot().is_empty());
    }

    #[test]
    fn invalid_names_and_labels_are_rejected_before_any_access() {
        let (dir, cfg) = config_with(&[("a", A)]);
        let store = MemoryStore::default();
        let prompt = ScriptedPrompter::new().with_secret("t");
        let c = ctx(&cfg, &store, &prompt);
        let before = texts(&dir);
        assert!(link(&c, "a", "../x").is_err());
        assert!(link(&c, "../a", "aws").is_err());
        assert!(unlink(&c, "../a").is_err());
        assert!(members(&cfg, "a/b").is_err());
        assert!(create(&c, "n", None, Some("bad label")).is_err());
        assert!(prompt.asked().is_empty());
        assert_eq!(texts(&dir), before);
        assert!(store.snapshot().is_empty());
    }

    #[test]
    fn unlink_keeps_variables_and_removes_label() {
        let b =
            "link = \"aws\"\n\n[vars]\nREGION = \"us\"\nTOKEN = \"@keychain\"\nDB_USER = \"bob\"\n";
        let (dir, cfg) = config_with(&[("a", A), ("b", b)]);
        let store = store_with(&[("a", "TOKEN", "ta"), ("b", "TOKEN", "tb")]);
        let prompt = ScriptedPrompter::new();
        let c = ctx(&cfg, &store, &prompt);
        unlink(&c, "b").unwrap();
        assert_eq!(
            read(&dir, "b"),
            "[vars]\nREGION = \"us\"\nTOKEN = \"@keychain\"\nDB_USER = \"bob\"\n"
        );
        assert_eq!(read(&dir, "a"), A);
        assert_eq!(
            store.snapshot(),
            vec![entry("a", "TOKEN", "ta"), entry("b", "TOKEN", "tb")]
        );
        assert!(prompt.asked().is_empty());
        // Unlinking an unlinked namespace is an error, and changes nothing.
        let err = unlink(&c, "b").unwrap_err().to_string();
        assert!(err.contains("not in a link group"), "{err}");
        assert_eq!(
            read(&dir, "b"),
            "[vars]\nREGION = \"us\"\nTOKEN = \"@keychain\"\nDB_USER = \"bob\"\n"
        );
    }

    const PLAIN_A: &str = "link = \"aws\"\n\n[vars]\nREGION = \"eu\"\n";
    const PLAIN_B: &str = "link = \"aws\"\n\n[vars]\nREGION = \"us\"\n";
    const PLAIN_C: &str = "link = \"aws\"\n\n[vars]\nREGION = \"ap\"\n";

    #[test]
    fn set_new_name_prompts_a_value_in_every_other_member() {
        let (dir, cfg) = config_with(&[("a", PLAIN_A), ("b", PLAIN_B), ("c", PLAIN_C)]);
        let store = MemoryStore::default();
        let prompt = ScriptedPrompter::new()
            .with_secret("ta")
            .with_secret("tb")
            .with_secret("tc");
        set_vars(&ctx(&cfg, &store, &prompt), "a", &[sec("TOKEN")]).unwrap();
        assert_eq!(
            prompt.asked(),
            vec![
                Asked::Secret("Secret value for TOKEN in a".into()),
                Asked::Secret("Secret value for TOKEN in b".into()),
                Asked::Secret("Secret value for TOKEN in c".into()),
            ]
        );
        assert_eq!(read(&dir, "a"), format!("{PLAIN_A}TOKEN = \"@keychain\"\n"));
        assert_eq!(read(&dir, "b"), format!("{PLAIN_B}TOKEN = \"@keychain\"\n"));
        assert_eq!(read(&dir, "c"), format!("{PLAIN_C}TOKEN = \"@keychain\"\n"));
        assert_eq!(
            store.snapshot(),
            vec![
                entry("a", "TOKEN", "ta"),
                entry("b", "TOKEN", "tb"),
                entry("c", "TOKEN", "tc")
            ]
        );

        // A plain name prompts visibly in each other member.
        let prompt = ScriptedPrompter::new()
            .with_plain("ua")
            .with_plain("ub")
            .with_plain("uc");
        set_vars(&ctx(&cfg, &store, &prompt), "a", &[pl("DB_USER")]).unwrap();
        assert_eq!(
            prompt.asked()[1..],
            [
                Asked::Plain {
                    label: "Value for DB_USER in b".into(),
                    default: None
                },
                Asked::Plain {
                    label: "Value for DB_USER in c".into(),
                    default: None
                },
            ]
        );
        assert_eq!(
            read(&dir, "c"),
            format!("{PLAIN_C}TOKEN = \"@keychain\"\nDB_USER = \"uc\"\n")
        );
        // Setting an existing name again prompts nowhere else.
        let prompt = ScriptedPrompter::new().with_secret("ta2");
        set_vars(&ctx(&cfg, &store, &prompt), "a", &[sec("TOKEN")]).unwrap();
        assert_eq!(prompt.asked().len(), 1);
        assert_eq!(store.get("b", "TOKEN").unwrap().unwrap().expose(), "tb");
        assert_eq!(store.get("a", "TOKEN").unwrap().unwrap().expose(), "ta2");
    }

    #[test]
    fn set_conversion_propagates_to_other_members() {
        let a = "link = \"aws\"\n\n[vars]\nTOKEN = \"@keychain\"\n";
        let b = "link = \"aws\"\n\n[vars]\nTOKEN = \"@keychain\"\n";
        let other = "[vars]\nTOKEN = \"@keychain\"\n";
        let (dir, cfg) = config_with(&[("a", a), ("b", b), ("other", other)]);
        let store = store_with(&[
            ("a", "TOKEN", "sa"),
            ("b", "TOKEN", "sb"),
            ("other", "TOKEN", "keep"),
        ]);
        let prompt = ScriptedPrompter::new()
            .with_confirm(true)
            .with_plain("pa")
            .with_confirm(true)
            .with_plain("pb");
        set_vars(&ctx(&cfg, &store, &prompt), "a", &[pl("TOKEN")]).unwrap();
        let asked = prompt.asked();
        assert_eq!(asked.len(), 4);
        let Asked::Confirm(q) = &asked[2] else {
            panic!("{asked:?}")
        };
        assert!(q.contains("b: make TOKEN plain"), "{q}");
        assert!(!q.contains("sb") && !q.contains("sa"), "{q}");
        assert_eq!(
            asked[3],
            Asked::Plain {
                label: "Value for TOKEN in b".into(),
                default: None
            }
        );
        assert_eq!(
            read(&dir, "a"),
            "link = \"aws\"\n\n[vars]\nTOKEN = \"pa\"\n"
        );
        assert_eq!(
            read(&dir, "b"),
            "link = \"aws\"\n\n[vars]\nTOKEN = \"pb\"\n"
        );
        assert_eq!(store.snapshot(), vec![entry("other", "TOKEN", "keep")]);

        // And back to a secret.
        let prompt = ScriptedPrompter::new()
            .with_confirm(true)
            .with_secret("na")
            .with_confirm(true)
            .with_secret("nb");
        set_vars(&ctx(&cfg, &store, &prompt), "a", &[sec("TOKEN")]).unwrap();
        let Asked::Confirm(q) = &prompt.asked()[2] else {
            panic!()
        };
        assert!(q.contains("b: make TOKEN secret"), "{q}");
        assert_eq!(read(&dir, "a"), a);
        assert_eq!(read(&dir, "b"), b);
        assert_eq!(read(&dir, "other"), other);
        assert_eq!(
            store.snapshot(),
            vec![
                entry("a", "TOKEN", "na"),
                entry("b", "TOKEN", "nb"),
                entry("other", "TOKEN", "keep")
            ]
        );
    }

    #[test]
    fn set_vars_two_new_names_propagate_to_every_member_in_one_write() {
        let (dir, cfg) = config_with(&[("a", PLAIN_A), ("b", PLAIN_B), ("c", PLAIN_C)]);
        let store = MemoryStore::default();
        let prompt = ScriptedPrompter::new()
            .with_secret("zq-ta")
            .with_plain("ua")
            .with_secret("zq-tb")
            .with_plain("ub")
            .with_secret("zq-tc")
            .with_plain("uc");
        set_vars(
            &ctx(&cfg, &store, &prompt),
            "a",
            &[sec("TOKEN"), pl("DB_USER")],
        )
        .unwrap();
        let plain = |label: &str| Asked::Plain {
            label: label.into(),
            default: None,
        };
        // Additions need no group confirmation: one prompt per member and name.
        assert_eq!(
            prompt.asked(),
            vec![
                Asked::Secret("Secret value for TOKEN in a".into()),
                plain("Value for DB_USER in a"),
                Asked::Secret("Secret value for TOKEN in b".into()),
                plain("Value for DB_USER in b"),
                Asked::Secret("Secret value for TOKEN in c".into()),
                plain("Value for DB_USER in c"),
            ]
        );
        for (ns, base, user) in [
            ("a", PLAIN_A, "ua"),
            ("b", PLAIN_B, "ub"),
            ("c", PLAIN_C, "uc"),
        ] {
            assert_eq!(
                read(&dir, ns),
                format!("{base}TOKEN = \"@keychain\"\nDB_USER = \"{user}\"\n")
            );
            ensure_aligned(&cfg, &cfg.load(ns).unwrap()).unwrap();
        }
        assert_eq!(
            store.snapshot(),
            vec![
                entry("a", "TOKEN", "zq-ta"),
                entry("b", "TOKEN", "zq-tb"),
                entry("c", "TOKEN", "zq-tc")
            ]
        );
    }

    #[test]
    fn set_vars_in_a_group_writes_nothing_if_the_last_prompt_or_a_keychain_write_fails() {
        let fixture = || config_with(&[("a", PLAIN_A), ("b", PLAIN_B), ("c", PLAIN_C)]);
        let items = [sec("TOKEN"), pl("DB_USER")];

        // No answer for c's DB_USER, the very last prompt.
        let (dir, cfg) = fixture();
        let before = texts(&dir);
        let store = store_with(&[("b", "TOKEN", "leftover-b")]);
        let prompt = ScriptedPrompter::new()
            .with_secret("zq-ta")
            .with_plain("ua")
            .with_secret("zq-tb")
            .with_plain("ub")
            .with_secret("zq-tc");
        assert!(set_vars(&ctx(&cfg, &store, &prompt), "a", &items).is_err());
        assert_eq!(prompt.asked().len(), 6);
        assert_eq!(texts(&dir), before);
        assert_eq!(store.snapshot(), vec![entry("b", "TOKEN", "leftover-b")]);

        // Sets: a/TOKEN (1), b/TOKEN (2, over the leftover), c/TOKEN (3, fails).
        let (dir, cfg) = fixture();
        let store = FailNthSet {
            inner: store_with(&[("b", "TOKEN", "leftover-b")]),
            n: 3,
            calls: Cell::new(0),
        };
        let prompt = ScriptedPrompter::new()
            .with_secret("zq-ta")
            .with_plain("ua")
            .with_secret("zq-tb")
            .with_plain("ub")
            .with_secret("zq-tc")
            .with_plain("uc");
        let err = set_vars(&ctx(&cfg, &store, &prompt), "a", &items).unwrap_err();
        assert!(format!("{err:#}").contains("simulated"), "{err:#}");
        assert!(!format!("{err:#}").contains("zq-"), "{err:#}");
        assert_eq!(texts(&dir), before);
        assert_eq!(
            store.inner.snapshot(),
            vec![entry("b", "TOKEN", "leftover-b")]
        );
    }

    #[test]
    fn set_vars_flip_and_new_name_in_a_group_ask_one_group_question() {
        let a = "link = \"aws\"\n\n[vars]\nTOKEN = \"@keychain\"\n";
        let b = "link = \"aws\"\n\n[vars]\nTOKEN = \"@keychain\"\n";
        let (dir, cfg) = config_with(&[("a", a), ("b", b)]);
        let store = store_with(&[("a", "TOKEN", "zq-sa"), ("b", "TOKEN", "zq-sb")]);
        let items = [pv_item("TOKEN", "pa"), sec("NEW")];

        // Declining the group question, the last one, changes nothing.
        let before = (texts(&dir), store.snapshot());
        let prompt = ScriptedPrompter::new()
            .with_confirm(true)
            .with_secret("zq-na")
            .with_confirm(false);
        assert!(set_vars(&ctx(&cfg, &store, &prompt), "a", &items).is_err());
        assert_eq!((texts(&dir), store.snapshot()), before);

        let prompt = ScriptedPrompter::new()
            .with_confirm(true)
            .with_secret("zq-na")
            .with_confirm(true)
            .with_plain("pb")
            .with_secret("zq-nb");
        set_vars(&ctx(&cfg, &store, &prompt), "a", &items).unwrap();
        let asked = prompt.asked();
        let confirms = asked
            .iter()
            .filter(|q| matches!(q, Asked::Confirm(_)))
            .count();
        assert_eq!(confirms, 2, "{asked:?}");
        assert_eq!(
            asked[2],
            Asked::Confirm(
                "Link group \"aws\" must match \"a\". This will change:\n  b: make TOKEN plain (deletes Keychain items: TOKEN)\nContinue?"
                    .into()
            )
        );
        assert_eq!(
            asked[3..],
            [
                Asked::Plain {
                    label: "Value for TOKEN in b".into(),
                    default: None
                },
                Asked::Secret("Secret value for NEW in b".into()),
            ]
        );
        assert_eq!(
            read(&dir, "a"),
            "link = \"aws\"\n\n[vars]\nTOKEN = \"pa\"\nNEW = \"@keychain\"\n"
        );
        assert_eq!(
            read(&dir, "b"),
            "link = \"aws\"\n\n[vars]\nTOKEN = \"pb\"\nNEW = \"@keychain\"\n"
        );
        assert_eq!(
            store.snapshot(),
            vec![entry("a", "NEW", "zq-na"), entry("b", "NEW", "zq-nb")]
        );
    }

    #[test]
    fn set_vars_in_a_group_rechecks_every_member_after_all_prompts() {
        let theirs_c = "link = \"aws\"\n\n[vars]\nREGION = \"theirs\"\n";
        let (dir, cfg) = config_with(&[("a", PLAIN_A), ("b", PLAIN_B), ("c", PLAIN_C)]);
        let store = MemoryStore::default();
        let prompt = WritesWhilePrompting {
            inner: ScriptedPrompter::new()
                .with_plain("x")
                .with_plain("y")
                .with_plain("xb")
                .with_plain("yb")
                .with_plain("xc")
                .with_plain("yc"),
            path: dir.path().join("c.toml"),
            text: theirs_c,
        };
        let err = set_vars(&ctx(&cfg, &store, &prompt), "a", &[pl("X"), pl("Y")])
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("namespace \"c\" was changed while envy was prompting"),
            "{err}"
        );
        assert_eq!(prompt.inner.remaining(), 0);
        assert_eq!(read(&dir, "a"), PLAIN_A);
        assert_eq!(read(&dir, "b"), PLAIN_B);
        assert_eq!(read(&dir, "c"), theirs_c);
    }

    /// Group where the source `a` has just lost OLD and OLDS (as Task 9's
    /// `--edit` would leave it); `b` and `c` still have them.
    fn removal_fixture() -> (tempfile::TempDir, Config, MemoryStore) {
        let b = "link = \"aws\"\n\n[vars]\nREGION = \"us\"\nOLD = \"x\"\nOLDS = \"@keychain\"\n";
        let c = "link = \"aws\"\n\n[vars]\nOLDS = \"@keychain\"\nREGION = \"ap\"\n";
        let other = "[vars]\nOLDS = \"@keychain\"\n";
        let (dir, cfg) = config_with(&[("a", PLAIN_A), ("b", b), ("c", c), ("other", other)]);
        let store = store_with(&[
            ("b", "OLDS", "secret-b"),
            ("c", "OLDS", "secret-c"),
            ("other", "OLDS", "keep"),
        ]);
        (dir, cfg, store)
    }

    #[test]
    fn removed_name_is_deleted_from_other_members_and_keychain_after_one_confirm() {
        let (dir, cfg, store) = removal_fixture();
        let prompt = ScriptedPrompter::new().with_confirm(true);
        propagate(&ctx(&cfg, &store, &prompt), &cfg.load("a").unwrap()).unwrap();
        let asked = prompt.asked();
        assert_eq!(asked.len(), 1, "{asked:?}");
        let Asked::Confirm(q) = &asked[0] else {
            panic!()
        };
        assert_eq!(
            q,
            "Link group \"aws\" must match \"a\". This will change:\n  b: remove OLD, OLDS (deletes Keychain items: OLDS)\n  c: remove OLDS (deletes Keychain items: OLDS)\nContinue?"
        );
        assert_eq!(read(&dir, "a"), PLAIN_A);
        assert_eq!(read(&dir, "b"), PLAIN_B);
        assert_eq!(read(&dir, "c"), PLAIN_C);
        assert_eq!(store.snapshot(), vec![entry("other", "OLDS", "keep")]);
    }

    #[test]
    fn declined_confirm_changes_nothing() {
        let (dir, cfg, store) = removal_fixture();
        let before = (texts(&dir), store.snapshot());
        let prompt = ScriptedPrompter::new()
            .with_confirm(false)
            .with_plain("x")
            .with_secret("y");
        let err = propagate(&ctx(&cfg, &store, &prompt), &cfg.load("a").unwrap())
            .unwrap_err()
            .to_string();
        assert!(err.contains("cancelled"), "{err}");
        assert_eq!(prompt.asked().len(), 1);
        assert_eq!((texts(&dir), store.snapshot()), before);

        // Via --plain: the source's own change is not written either.
        let a = "link = \"aws\"\n\n[vars]\nREGION = \"@keychain\"\n";
        let b = "link = \"aws\"\n\n[vars]\nREGION = \"@keychain\"\n";
        let (dir, cfg) = config_with(&[("a", a), ("b", b)]);
        let store = store_with(&[("a", "REGION", "ra"), ("b", "REGION", "rb")]);
        let before = (texts(&dir), store.snapshot());
        let prompt = ScriptedPrompter::new()
            .with_confirm(true)
            .with_plain("eu")
            .with_confirm(false);
        assert!(set_vars(&ctx(&cfg, &store, &prompt), "a", &[pl("REGION")]).is_err());
        assert_eq!((texts(&dir), store.snapshot()), before);
    }

    const SECRET_A: &str = "link = \"aws\"\n\n[vars]\nREGION = \"eu\"\nTOKEN = \"@keychain\"\n";
    const SECRET_B: &str = "link = \"aws\"\n\n[vars]\nREGION = \"us\"\nTOKEN = \"@keychain\"\n";
    const SECRET_C: &str = "link = \"aws\"\n\n[vars]\nREGION = \"ap\"\nTOKEN = \"@keychain\"\n";

    fn secret_group() -> (tempfile::TempDir, Config, MemoryStore) {
        let (dir, cfg) = config_with(&[("a", SECRET_A), ("b", SECRET_B), ("c", SECRET_C)]);
        let store = store_with(&[
            ("a", "TOKEN", "ta"),
            ("b", "TOKEN", "tb"),
            // A leftover item for the name about to be added: it must be
            // restored, not lost, if the command fails.
            ("b", "NEW", "leftover-b"),
            ("c", "TOKEN", "tc"),
        ]);
        (dir, cfg, store)
    }

    #[test]
    fn propagation_failure_writes_nothing() {
        let (dir, cfg, store) = secret_group();
        let before = (texts(&dir), store.snapshot());
        // Answers for the source and for `b`, none for `c`.
        let prompt = ScriptedPrompter::new()
            .with_secret("new-a")
            .with_secret("new-b");
        let err = set_vars(&ctx(&cfg, &store, &prompt), "a", &[sec("NEW")]).unwrap_err();
        assert!(format!("{err:#}").contains("ran out"), "{err:#}");
        assert_eq!(
            prompt.asked().last(),
            Some(&Asked::Secret("Secret value for NEW in c".into()))
        );
        assert_eq!(read(&dir, "a"), SECRET_A);
        assert_eq!((texts(&dir), store.snapshot()), before);
    }

    /// A store whose `set` fails on the `n`th call (1-based).
    struct FailNthSet {
        inner: MemoryStore,
        n: usize,
        calls: Cell<usize>,
    }

    impl SecretStore for FailNthSet {
        fn get(&self, ns: &str, name: &str) -> Result<Option<Secret>> {
            self.inner.get(ns, name)
        }
        fn set(&self, ns: &str, name: &str, value: &Secret) -> Result<()> {
            self.calls.set(self.calls.get() + 1);
            if self.calls.get() == self.n {
                bail!("simulated Keychain failure");
            }
            self.inner.set(ns, name, value)
        }
        fn delete(&self, ns: &str, name: &str) -> Result<()> {
            self.inner.delete(ns, name)
        }
    }

    #[test]
    fn keychain_failure_on_last_member_restores_every_item() {
        let (dir, cfg, inner) = secret_group();
        let before = (texts(&dir), inner.snapshot());
        // Sets: a/NEW (1), b/NEW (2, over the leftover), c/NEW (3, fails).
        let store = FailNthSet {
            inner,
            n: 3,
            calls: Cell::new(0),
        };
        let prompt = ScriptedPrompter::new()
            .with_secret("new-a")
            .with_secret("new-b")
            .with_secret("new-c");
        let err = set_vars(&ctx(&cfg, &store, &prompt), "a", &[sec("NEW")]).unwrap_err();
        assert!(format!("{err:#}").contains("simulated"), "{err:#}");
        assert!(!format!("{err:#}").contains("new-"), "{err:#}");
        // Rollback: b's leftover is set back (call 4); a's new item is deleted.
        assert_eq!(store.calls.get(), 4);
        assert_eq!((texts(&dir), store.inner.snapshot()), before);
    }

    /// Answers like a `ScriptedPrompter`, and once the last answer is given,
    /// puts a directory where `path` was, so a later save of it fails.
    struct SquatAfterLastAnswer {
        inner: ScriptedPrompter,
        path: PathBuf,
    }

    impl SquatAfterLastAnswer {
        fn after<T>(&self, answer: Result<T>) -> Result<T> {
            if self.inner.remaining() == 0 && self.path.is_file() {
                std::fs::remove_file(&self.path).unwrap();
                std::fs::create_dir(&self.path).unwrap();
            }
            answer
        }
    }

    impl Prompter for SquatAfterLastAnswer {
        fn secret(&self, label: &str) -> Result<Secret> {
            self.after(self.inner.secret(label))
        }
        fn plain(&self, label: &str, default: Option<&str>) -> Result<String> {
            self.after(self.inner.plain(label, default))
        }
        fn confirm(&self, question: &str) -> Result<bool> {
            self.after(self.inner.confirm(question))
        }
    }

    /// A store that, once `ns`'s item `name` is written, puts a directory
    /// where `path` was, so a later save of it fails. Writing happens after
    /// every prompt and after the unchanged-files check, so this reaches the
    /// save itself.
    struct SquatOnSet {
        inner: MemoryStore,
        ns: &'static str,
        name: &'static str,
        path: PathBuf,
    }

    impl SecretStore for SquatOnSet {
        fn get(&self, ns: &str, name: &str) -> Result<Option<Secret>> {
            self.inner.get(ns, name)
        }
        fn set(&self, ns: &str, name: &str, value: &Secret) -> Result<()> {
            self.inner.set(ns, name, value)?;
            if (ns, name) == (self.ns, self.name) && self.path.is_file() {
                std::fs::remove_file(&self.path).unwrap();
                std::fs::create_dir(&self.path).unwrap();
            }
            Ok(())
        }
        fn delete(&self, ns: &str, name: &str) -> Result<()> {
            self.inner.delete(ns, name)
        }
    }

    #[test]
    fn save_failure_for_one_member_restores_files_and_keychain() {
        let (dir, cfg, inner) = secret_group();
        let before_store = inner.snapshot();
        let store = SquatOnSet {
            inner,
            ns: "c",
            name: "NEW",
            path: dir.path().join("c.toml"),
        };
        let prompt = ScriptedPrompter::new()
            .with_secret("new-a")
            .with_secret("new-b")
            .with_secret("new-c");
        // Files save in order a, b, c; c fails after a and b were written.
        let err = set_vars(&ctx(&cfg, &store, &prompt), "a", &[sec("NEW")]).unwrap_err();
        assert!(
            format!("{err:#}").contains("cannot write namespace \"c\""),
            "{err:#}"
        );
        assert_eq!(read(&dir, "a"), SECRET_A);
        assert_eq!(read(&dir, "b"), SECRET_B);
        assert!(dir.path().join("c.toml").is_dir());
        assert_eq!(store.inner.snapshot(), before_store);
        assert_eq!(file_names(&dir), ["a.toml", "b.toml", "c.toml"]);
    }

    #[test]
    fn save_failure_during_removal_keeps_every_secret() {
        let (dir, cfg, store) = removal_fixture();
        let before = store.snapshot();
        let b_before = read(&dir, "b");
        let prompt = SquatAfterLastAnswer {
            inner: ScriptedPrompter::new().with_confirm(true),
            path: dir.path().join("c.toml"),
        };
        // b saves, c fails: b is put back and no Keychain item is deleted.
        assert!(propagate(&ctx(&cfg, &store, &prompt), &cfg.load("a").unwrap()).is_err());
        assert_eq!(read(&dir, "b"), b_before);
        assert_eq!(read(&dir, "a"), PLAIN_A);
        assert_eq!(store.snapshot(), before);
    }

    /// A store whose `delete` always fails.
    struct FailingDelete(MemoryStore);

    impl SecretStore for FailingDelete {
        fn get(&self, ns: &str, name: &str) -> Result<Option<Secret>> {
            self.0.get(ns, name)
        }
        fn set(&self, ns: &str, name: &str, value: &Secret) -> Result<()> {
            self.0.set(ns, name, value)
        }
        fn delete(&self, _ns: &str, _name: &str) -> Result<()> {
            bail!("simulated Keychain failure")
        }
    }

    #[test]
    fn keychain_delete_failure_after_saving_names_the_leftover_items() {
        let (dir, cfg, inner) = removal_fixture();
        let before = inner.snapshot();
        let store = FailingDelete(inner);
        let prompt = ScriptedPrompter::new().with_confirm(true);
        let err = propagate(&ctx(&cfg, &store, &prompt), &cfg.load("a").unwrap())
            .unwrap_err()
            .to_string();
        assert!(err.contains("b/OLDS, c/OLDS"), "{err}");
        assert!(!err.contains("secret-"), "{err}");
        // The files are saved; the items are left over, not referenced.
        assert_eq!(read(&dir, "b"), PLAIN_B);
        assert_eq!(read(&dir, "c"), PLAIN_C);
        assert_eq!(store.0.snapshot(), before);
    }

    #[test]
    fn ensure_aligned_suggests_link_only_when_link_can_repair() {
        // Only missing names, and the rest of the group agrees: --link fixes it.
        let b = "link = \"aws\"\n\n[vars]\nREGION = \"us\"\nTOKEN = \"@keychain\"\n";
        let (_dir, cfg) = config_with(&[("a", A), ("b", b)]);
        let err = ensure_aligned(&cfg, &cfg.load("b").unwrap())
            .unwrap_err()
            .to_string();
        assert!(
            err.ends_with("missing DB_USER. Repair it with: envy b --link aws"),
            "{err}"
        );
        assert!(!err.contains("--edit"), "{err}");

        // Only an extra name: --link would refuse, so --edit is suggested.
        let b = "link = \"aws\"\n\n[vars]\nREGION = \"us\"\nTOKEN = \"@keychain\"\nDB_USER = \"b\"\nMORE = \"m\"\n";
        let (_dir, cfg) = config_with(&[("a", A), ("b", b)]);
        let err = ensure_aligned(&cfg, &cfg.load("b").unwrap())
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("extra MORE") && err.contains("envy b --edit"),
            "{err}"
        );
        assert!(!err.contains("--link aws"), "{err}");

        // Only missing names, but the other members disagree with each other
        // (so --link refuses): --edit again.
        let c = "link = \"aws\"\n\n[vars]\nREGION = \"ap\"\nTOKEN = \"@keychain\"\nOTHER = \"o\"\n";
        let b = "link = \"aws\"\n\n[vars]\nREGION = \"us\"\nTOKEN = \"@keychain\"\n";
        let (_dir, cfg) = config_with(&[("a", A), ("b", b), ("c", c)]);
        let err = ensure_aligned(&cfg, &cfg.load("b").unwrap())
            .unwrap_err()
            .to_string();
        assert!(err.contains("missing DB_USER, OTHER"), "{err}");
        assert!(
            err.contains("envy b --edit") && !err.contains("--link aws"),
            "{err}"
        );
    }

    #[test]
    fn ensure_aligned_reports_missing_extra_and_flag_mismatch() {
        let a = "link = \"aws\"\n\n[vars]\nREGION = \"eu\"\nTOKEN = \"@keychain\"\nKEY = \"k\"\n";
        let b = "link = \"aws\"\n\n[vars]\nREGION = \"us\"\nTOKEN = \"plain-secret-ish\"\nEXTRA = \"e\"\n";
        let (_dir, cfg) = config_with(&[("a", a), ("b", b)]);
        let err = ensure_aligned(&cfg, &cfg.load("b").unwrap())
            .unwrap_err()
            .to_string();
        assert_eq!(
            err,
            "namespace \"b\" has drifted from link group \"aws\": missing KEY; extra EXTRA; TOKEN is plain here but secret in a. \
             --link cannot repair this: make it match the group with envy b --edit \
             (or envy b --secret NAME or --plain NAME); saving it makes the rest of the group match it"
        );
        assert!(!err.contains("plain-secret-ish"));
        let err = ensure_aligned(&cfg, &cfg.load("a").unwrap())
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("missing EXTRA; extra KEY; TOKEN is secret here but plain in b"),
            "{err}"
        );
        // Values differing is not drift.
        let (_dir, cfg) = config_with(&[("a", SECRET_A), ("b", SECRET_B)]);
        ensure_aligned(&cfg, &cfg.load("b").unwrap()).unwrap();
    }

    #[test]
    fn corrupt_file_stops_group_operations_and_names_it() {
        let (_dir, cfg) = config_with(&[("a", SECRET_A), ("b", SECRET_B), ("bad", "[vars\n")]);
        let err = format!("{:#}", members(&cfg, "aws").unwrap_err());
        assert!(err.contains("\"bad\"") && err.contains("aws"), "{err}");
        assert!(ensure_aligned(&cfg, &cfg.load("a").unwrap()).is_err());
        let store = MemoryStore::default();
        let prompt = ScriptedPrompter::new().with_secret("x");
        assert!(link(&ctx(&cfg, &store, &prompt), "b", "aws").is_err());
        assert!(prompt.asked().is_empty());
    }

    #[test]
    fn activate_refuses_drifted_linked_namespace_and_emits_nothing() {
        let b = "link = \"aws\"\n\n[vars]\nREGION = \"us\"\n";
        let (_dir, cfg) = config_with(&[("a", SECRET_A), ("b", b)]);
        let store = store_with(&[("a", "TOKEN", "zq-secret")]);
        let err = activate(
            &ctx(&cfg, &store, &ScriptedPrompter::new()),
            "b",
            &ActiveState::default(),
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("missing TOKEN") && err.contains("--link"),
            "{err}"
        );
        let err = activate(
            &ctx(&cfg, &store, &ScriptedPrompter::new()),
            "a",
            &ActiveState::default(),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("extra TOKEN"), "{err}");
        assert!(!err.contains("zq-secret"), "{err}");
    }

    #[test]
    fn aligned_linked_namespace_activates() {
        let (_dir, cfg) = config_with(&[("a", SECRET_A), ("b", SECRET_B)]);
        let store = store_with(&[("a", "TOKEN", "ta"), ("b", "TOKEN", "tb")]);
        let out = activate(
            &ctx(&cfg, &store, &ScriptedPrompter::new()),
            "b",
            &ActiveState::default(),
        )
        .unwrap();
        assert!(out.contains("export TOKEN='tb'\n"), "{out}");
    }

    #[test]
    fn unlinked_namespace_ignores_group_rules() {
        let u = "[vars]\nONLY_HERE = \"1\"\n";
        let (dir, cfg) = config_with(&[("a", SECRET_A), ("b", SECRET_B), ("u", u)]);
        let store = store_with(&[("a", "TOKEN", "ta"), ("b", "TOKEN", "tb")]);
        ensure_aligned(&cfg, &cfg.load("u").unwrap()).unwrap();
        let prompt = ScriptedPrompter::new().with_secret("s");
        set_vars(&ctx(&cfg, &store, &prompt), "u", &[sec("NEW")]).unwrap();
        assert_eq!(prompt.asked().len(), 1);
        assert_eq!(read(&dir, "u"), format!("{u}NEW = \"@keychain\"\n"));
        assert_eq!(read(&dir, "a"), SECRET_A);
        assert_eq!(read(&dir, "b"), SECRET_B);
        let out = activate(
            &ctx(&cfg, &store, &ScriptedPrompter::new()),
            "u",
            &ActiveState::default(),
        )
        .unwrap();
        assert!(out.contains("export NEW='s'\n"), "{out}");
        // Propagating from an unlinked namespace does nothing at all.
        let quiet = ScriptedPrompter::new();
        propagate(&ctx(&cfg, &store, &quiet), &cfg.load("u").unwrap()).unwrap();
        assert!(quiet.asked().is_empty());
    }

    #[test]
    fn new_with_link_joins_group_prompting_for_its_names() {
        let (dir, cfg) = config_with(&[("a", SECRET_A)]);
        let store = store_with(&[("a", "TOKEN", "ta")]);
        let prompt = ScriptedPrompter::new()
            .with_plain("sa-east-1")
            .with_secret("tn");
        create(&ctx(&cfg, &store, &prompt), "n", None, Some("aws")).unwrap();
        assert_eq!(
            prompt.asked(),
            vec![
                Asked::Plain {
                    label: "Value for REGION in n".into(),
                    default: None
                },
                Asked::Secret("Secret value for TOKEN in n".into()),
            ]
        );
        let text = read(&dir, "n");
        let file = NamespaceFile::parse("n", &text).unwrap();
        assert_eq!(file.link(), Some("aws"));
        assert!(!text.contains("tn"), "{text}");
        ensure_aligned(&cfg, &file).unwrap();
        assert_eq!(
            store.snapshot(),
            vec![entry("a", "TOKEN", "ta"), entry("n", "TOKEN", "tn")]
        );

        // A new label creates the group from what --like copied.
        let prompt = ScriptedPrompter::new().with_secret("tm");
        create(
            &ctx(&cfg, &store, &prompt),
            "m",
            Some(&cfg.load("a").unwrap()),
            Some("gcp"),
        )
        .unwrap();
        assert_eq!(
            read(&dir, "m"),
            "link = \"gcp\"\n\n[vars]\nREGION = \"eu\"\nTOKEN = \"@keychain\"\n"
        );
        assert_eq!(read(&dir, "a"), SECRET_A);
    }

    #[test]
    fn new_with_link_failure_leaves_nothing_created() {
        let src = "[vars]\nREGION = \"x\"\nTOKEN = \"@keychain\"\nEXTRA = \"@keychain\"\n";
        let (dir, cfg) = config_with(&[("a", SECRET_A), ("src", src)]);
        let store = store_with(&[("a", "TOKEN", "ta"), ("src", "TOKEN", "ts")]);
        let before = (texts(&dir), store.snapshot());

        // --like copies a name the group does not have: refused before any prompt.
        let prompt = ScriptedPrompter::new().with_secret("t").with_secret("e");
        let err = create(
            &ctx(&cfg, &store, &prompt),
            "n",
            Some(&cfg.load("src").unwrap()),
            Some("aws"),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("EXTRA"), "{err}");
        assert!(prompt.asked().is_empty());
        assert_eq!((texts(&dir), store.snapshot()), before);

        // A prompt for one of the group's names fails: nothing is written.
        let prompt = ScriptedPrompter::new().with_plain("eu");
        assert!(create(&ctx(&cfg, &store, &prompt), "n", None, Some("aws")).is_err());
        assert_eq!(prompt.asked().len(), 2);
        assert_eq!((texts(&dir), store.snapshot()), before);

        // A Keychain write fails: nothing is left behind.
        let failing = FailNthSet {
            inner: store_with(&[("a", "TOKEN", "ta")]),
            n: 1,
            calls: Cell::new(0),
        };
        let prompt = ScriptedPrompter::new().with_plain("eu").with_secret("tn");
        assert!(create(&ctx(&cfg, &failing, &prompt), "n", None, Some("aws")).is_err());
        assert_eq!(texts(&dir), before.0);
        assert_eq!(failing.inner.snapshot(), vec![entry("a", "TOKEN", "ta")]);
    }
}
