//! Discovery of the project levels (`.envy/` folders) above a directory, and
//! resolution of a namespace name to exactly one level.

use std::collections::HashSet;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::config::Config;
use crate::project::{encode_path, identity_for_root};

/// Every `.envy/` level above a directory (nearest first), then the user level.
pub struct Levels {
    projects: Vec<Config>,
    user: Config,
}

/// The level a namespace name resolved to.
pub struct Resolved<'a> {
    pub cfg: &'a Config,
    /// The level is a project one and the user level also has the name.
    pub shadows_user: bool,
}

/// Where a listed namespace lives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Level {
    Project { dir: PathBuf },
    User,
}

/// One namespace in the status listing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub level: Level,
    /// A nearer level already provides this name.
    pub shadowed: bool,
}

/// How a level is named in `ENVY_SOURCE` and compared with it: `user`, or
/// the percent-encoded path of a project's `.envy` folder (printable ASCII,
/// never `user`: it starts with `/`).
pub fn label(cfg: &Config) -> String {
    if cfg.is_project() {
        encode_path(cfg.dir())
    } else {
        "user".to_string()
    }
}

/// The stderr line printed when a project namespace hides a user one.
pub fn shadow_note(ns: &str) -> String {
    format!("note: project namespace {ns:?} shadows your user-level {ns:?}; use --user for yours")
}

impl Levels {
    /// Walks up from `cwd` (nearest first, `cwd` included) collecting real
    /// `.envy` directories. Inside `home` the walk stops before `home`, which
    /// is never a project; elsewhere it runs to the filesystem root. A `.envy`
    /// symlink is ignored so a cloned repo cannot point at another directory.
    pub fn discover(cwd: &Path, home: &Path, user: Config) -> Result<Levels> {
        let (cwd, home) = resolve_paths(cwd, home)?;
        let inside_home = cwd.starts_with(&home);
        let mut projects = Vec::new();
        for dir in cwd.ancestors() {
            if inside_home && dir == home {
                break;
            }
            let envy = dir.join(".envy");
            let is_dir = match fs::symlink_metadata(&envy) {
                Ok(m) => m.file_type().is_dir(),
                Err(e) if e.kind() == ErrorKind::NotFound => false,
                // Fail closed: an unreadable ancestor may hide a project level.
                Err(e) => {
                    return Err(e).with_context(|| format!("cannot access {}", encode_path(&envy)));
                }
            };
            if is_dir {
                projects.push(Config::project(
                    envy,
                    dir.to_path_buf(),
                    identity_for_root(dir, &home),
                    user.dir().to_path_buf(),
                ));
            }
        }
        Ok(Levels { projects, user })
    }

    /// No project level: what [`Levels::discover`] finds outside any project.
    #[cfg(test)]
    pub fn user_only(user: Config) -> Levels {
        Levels {
            projects: Vec::new(),
            user,
        }
    }

    /// The user's own level.
    pub fn user(&self) -> &Config {
        &self.user
    }

    /// The project levels, nearest first.
    pub fn projects(&self) -> &[Config] {
        &self.projects
    }

    /// The level that provides `ns`: the nearest project level with the file,
    /// else the user level (which is also the answer when no level has it, so
    /// `load` reports the usual "does not exist"). Only file existence is
    /// checked, never contents, so a corrupt project file still wins and
    /// fails when loaded instead of falling through to the user's namespace.
    pub fn resolve(&self, ns: &str, force_user: bool) -> Result<Resolved<'_>> {
        if !force_user {
            for project in &self.projects {
                // `present`, not `exists`: a directory or dangling symlink
                // must win (and fail on load), never fall through to the user.
                if project.present(ns)? {
                    return Ok(Resolved {
                        cfg: project,
                        shadows_user: self.user.exists(ns)?,
                    });
                }
            }
        }
        Ok(Resolved {
            cfg: &self.user,
            shadows_user: false,
        })
    }

    /// Where a new namespace goes: the nearest project level unless `force_user`.
    pub fn creation_level(&self, force_user: bool) -> &Config {
        match self.projects.first() {
            Some(project) if !force_user => project,
            _ => &self.user,
        }
    }

    /// The `.envy/` level for `--project`: at the git repository root when
    /// `cwd` is inside one (a `.git` directory or file), else at `cwd`.
    /// Nothing is created on disk.
    pub fn new_project_level(cwd: &Path, home: &Path, user: &Config) -> Result<Config> {
        let (cwd, home) = resolve_paths(cwd, home)?;
        let has_git = |dir: &&Path| fs::symlink_metadata(dir.join(".git")).is_ok();
        let root = if cwd.starts_with(&home) {
            // Home itself (and anything above) is never a project root, so a
            // dotfiles repo at `~/.git` is ignored.
            cwd.ancestors().take_while(|d| *d != home).find(has_git)
        } else {
            cwd.ancestors().find(has_git)
        }
        .unwrap_or(&cwd)
        .to_path_buf();
        // Home itself and every folder above it (`/` included) hold the home
        // directory, so a project there would cover it.
        if home.starts_with(&root) {
            bail!(
                "cannot create a project level in your home directory or a folder above it; cd into a project folder first"
            );
        }
        Ok(Config::project(
            root.join(".envy"),
            root.clone(),
            identity_for_root(&root, &home),
            user.dir().to_path_buf(),
        ))
    }

    /// How many levels have a file named `ns` (as [`Levels::resolve`] sees
    /// them, ignoring `--user`).
    pub fn count(&self, ns: &str) -> Result<usize> {
        let mut n = usize::from(self.user.exists(ns)?);
        for project in &self.projects {
            n += usize::from(project.present(ns)?);
        }
        Ok(n)
    }

    /// Every namespace of every project level (nearest first), then the user
    /// level; names within a level are sorted.
    pub fn entries(&self) -> Result<Vec<Entry>> {
        // An unreadable level fails the whole listing on purpose (fail closed).
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for project in &self.projects {
            for name in project.list_present()? {
                let shadowed = !seen.insert(name.clone());
                out.push(Entry {
                    name,
                    level: Level::Project {
                        dir: project.dir().to_path_buf(),
                    },
                    shadowed,
                });
            }
        }
        for name in self.user.list()? {
            let shadowed = !seen.insert(name.clone());
            out.push(Entry {
                name,
                level: Level::User,
                shadowed,
            });
        }
        Ok(out)
    }
}

/// Both paths must be absolute and resolvable; anything else is an error so
/// the home boundary can never be silently skipped.
fn resolve_paths(cwd: &Path, home: &Path) -> Result<(PathBuf, PathBuf)> {
    for p in [cwd, home] {
        if !p.is_absolute() {
            bail!("{} is not an absolute path", encode_path(p));
        }
    }
    let cwd = cwd
        .canonicalize()
        .with_context(|| format!("cannot resolve {}", encode_path(cwd)))?;
    let home = home
        .canonicalize()
        .with_context(|| format!("cannot resolve {}", encode_path(home)))?;
    Ok((cwd, home))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    struct Fixture {
        _tmp: TempDir,
        home: PathBuf,
        user_dir: PathBuf,
    }

    fn fixture() -> Fixture {
        let tmp = TempDir::new().unwrap();
        let base = tmp.path().canonicalize().unwrap();
        let home = base.join("home");
        let user_dir = base.join("userconf");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&user_dir).unwrap();
        Fixture {
            _tmp: tmp,
            home,
            user_dir,
        }
    }

    impl Fixture {
        fn user(&self) -> Config {
            Config::new(self.user_dir.clone())
        }
        fn mkdir(&self, rel: &str) -> PathBuf {
            let p = self.home.join(rel);
            fs::create_dir_all(&p).unwrap();
            p
        }
        fn levels(&self, cwd: &Path) -> Levels {
            Levels::discover(cwd, &self.home, self.user()).unwrap()
        }
    }

    fn put(dir: &Path, name: &str, body: &str) {
        fs::create_dir_all(dir).unwrap();
        fs::write(dir.join(format!("{name}.toml")), body).unwrap();
    }

    fn dirs(l: &Levels) -> Vec<PathBuf> {
        l.projects.iter().map(|c| c.dir().to_path_buf()).collect()
    }

    #[test]
    fn discover_finds_nested_envy_dirs_nearest_first() {
        let f = fixture();
        let outer = f.mkdir("a");
        let inner = f.mkdir("a/b/c");
        fs::create_dir_all(outer.join(".envy")).unwrap();
        fs::create_dir_all(f.home.join("a/b/.envy")).unwrap();
        let l = f.levels(&inner);
        assert_eq!(
            dirs(&l),
            vec![f.home.join("a/b/.envy"), outer.join(".envy")]
        );
        assert_eq!(l.projects[0].root(), Some(f.home.join("a/b").as_path()));
        assert!(l.projects.iter().all(|c| c.user_dir() == f.user_dir));
    }

    #[test]
    fn discovery_stops_before_home() {
        let f = fixture();
        fs::create_dir_all(f.home.join(".envy")).unwrap();
        let above = f.home.parent().unwrap().join(".envy");
        put(&above, "dev", "A = \"1\"\n");
        put(&f.user_dir, "dev", "A = \"2\"\n");
        let cwd = f.mkdir("work/proj");
        for c in [&cwd, &f.home] {
            let l = f.levels(c);
            assert!(dirs(&l).is_empty());
            assert!(!l.resolve("dev", false).unwrap().cfg.is_project());
        }
    }

    #[test]
    fn cwd_outside_home_walks_to_the_root() {
        let f = fixture();
        let outside = f._tmp.path().canonicalize().unwrap().join("elsewhere/deep");
        fs::create_dir_all(&outside).unwrap();
        fs::create_dir_all(outside.parent().unwrap().join(".envy")).unwrap();
        let l = f.levels(&outside);
        assert_eq!(dirs(&l), vec![outside.parent().unwrap().join(".envy")]);
    }

    #[test]
    fn an_envy_file_is_not_a_level() {
        let f = fixture();
        let cwd = f.mkdir("p");
        fs::write(cwd.join(".envy"), "x").unwrap();
        assert!(dirs(&f.levels(&cwd)).is_empty());
    }

    #[test]
    fn a_symlinked_envy_is_ignored() {
        let f = fixture();
        let cwd = f.mkdir("p");
        let target = f.mkdir("elsewhere");
        put(&target, "dev", "A = \"1\"\n");
        symlink(&target, cwd.join(".envy")).unwrap();
        let l = f.levels(&cwd);
        assert!(dirs(&l).is_empty());
        assert!(!l.resolve("dev", false).unwrap().cfg.is_project());
    }

    #[test]
    fn project_wins_and_reports_the_shadow() {
        let f = fixture();
        let cwd = f.mkdir("p");
        put(&cwd.join(".envy"), "dev", "A = \"1\"\n");
        put(&f.user_dir, "dev", "A = \"2\"\n");
        let l = f.levels(&cwd);
        let r = l.resolve("dev", false).unwrap();
        assert!(r.cfg.is_project() && r.shadows_user);
        let r = l.resolve("dev", true).unwrap();
        assert!(!r.cfg.is_project() && !r.shadows_user);
        assert_eq!(
            shadow_note("dev"),
            "note: project namespace \"dev\" shadows your user-level \"dev\"; use --user for yours"
        );
    }

    #[test]
    fn project_only_name_does_not_shadow() {
        let f = fixture();
        let cwd = f.mkdir("p");
        put(&cwd.join(".envy"), "dev", "A = \"1\"\n");
        let r = f.levels(&cwd).resolve("dev", false).unwrap().shadows_user;
        assert!(!r);
    }

    #[test]
    fn nearest_level_containing_the_name_wins() {
        let f = fixture();
        let cwd = f.mkdir("a/b");
        put(&f.home.join("a/.envy"), "dev", "A = \"1\"\n");
        put(&f.home.join("a/.envy"), "only_outer", "A = \"1\"\n");
        put(&f.home.join("a/b/.envy"), "dev", "A = \"2\"\n");
        let l = f.levels(&cwd);
        let r = l.resolve("dev", false).unwrap();
        assert_eq!(r.cfg.dir(), f.home.join("a/b/.envy"));
        let r = l.resolve("only_outer", false).unwrap();
        assert_eq!(r.cfg.dir(), f.home.join("a/.envy"));
    }

    #[test]
    fn name_in_no_level_resolves_to_user() {
        let f = fixture();
        let cwd = f.mkdir("p");
        fs::create_dir_all(cwd.join(".envy")).unwrap();
        let l = f.levels(&cwd);
        let r = l.resolve("nope", false).unwrap();
        assert!(!r.cfg.is_project() && !r.shadows_user);
        assert!(
            r.cfg
                .load("nope")
                .unwrap_err()
                .to_string()
                .contains("does not exist")
        );
    }

    #[test]
    fn corrupt_project_file_fails_closed() {
        let f = fixture();
        let cwd = f.mkdir("p");
        put(&cwd.join(".envy"), "dev", "this is [not toml");
        put(&f.user_dir, "dev", "A = \"2\"\n");
        let l = f.levels(&cwd);
        let r = l.resolve("dev", false).unwrap();
        assert!(r.cfg.is_project());
        let err = format!("{:#}", r.cfg.load("dev").unwrap_err());
        assert!(err.contains("invalid TOML"), "{err}");
        assert!(
            err.contains(&cwd.join(".envy/dev.toml").display().to_string()),
            "{err}"
        );
    }

    #[test]
    fn entries_mark_shadowed_names() {
        let f = fixture();
        let cwd = f.mkdir("a/b");
        put(&f.home.join("a/b/.envy"), "dev", "A = \"1\"\n");
        put(&f.home.join("a/.envy"), "dev", "A = \"1\"\n");
        put(&f.home.join("a/.envy"), "ci", "A = \"1\"\n");
        put(&f.user_dir, "dev", "A = \"1\"\n");
        put(&f.user_dir, "mine", "A = \"1\"\n");
        let e = f.levels(&cwd).entries().unwrap();
        let got: Vec<_> = e.iter().map(|e| (e.name.as_str(), e.shadowed)).collect();
        assert_eq!(
            got,
            vec![
                ("dev", false),
                ("ci", false),
                ("dev", true),
                ("dev", true),
                ("mine", false)
            ]
        );
        assert_eq!(
            e[0].level,
            Level::Project {
                dir: f.home.join("a/b/.envy")
            }
        );
        assert_eq!(e[4].level, Level::User);
    }

    #[test]
    fn creation_level_defaults_to_nearest_envy_else_user() {
        let f = fixture();
        let plain = f.mkdir("plain");
        assert!(!f.levels(&plain).creation_level(false).is_project());
        let cwd = f.mkdir("p");
        fs::create_dir_all(cwd.join(".envy")).unwrap();
        let l = f.levels(&cwd);
        assert_eq!(l.creation_level(false).dir(), cwd.join(".envy"));
        assert!(!l.creation_level(true).is_project());
    }

    #[test]
    fn new_project_level_uses_the_git_root_else_cwd() {
        let f = fixture();
        let repo = f.mkdir("repo");
        fs::create_dir_all(repo.join(".git")).unwrap();
        fs::write(
            repo.join(".git/config"),
            "[remote \"origin\"]\n\turl = git@github.com:acme/api.git\n",
        )
        .unwrap();
        let sub = f.mkdir("repo/src/deep");
        let user = f.user();
        let c = Levels::new_project_level(&sub, &f.home, &user).unwrap();
        assert_eq!(c.dir(), repo.join(".envy"));
        assert_eq!(c.root(), Some(repo.as_path()));
        assert_eq!(c.identity(), Some("acme/api"));
        assert!(!repo.join(".envy").exists());

        let loose = f.mkdir("loose");
        let c = Levels::new_project_level(&loose, &f.home, &user).unwrap();
        assert_eq!(c.dir(), loose.join(".envy"));
        assert_eq!(c.identity(), Some("~/loose"));
        assert_eq!(c.user_dir(), f.user_dir);
        assert!(!loose.join(".envy").exists());

        let worktree = f.mkdir("wt/x");
        fs::write(f.home.join("wt/.git"), "gitdir: elsewhere\n").unwrap();
        let c = Levels::new_project_level(&worktree, &f.home, &user).unwrap();
        assert_eq!(c.dir(), f.home.join("wt/.envy"));
    }

    fn is_root() -> bool {
        std::process::Command::new("id")
            .arg("-u")
            .output()
            .map(|o| o.stdout == b"0\n")
            .unwrap_or(false)
    }

    /// A bad `.envy/dev.toml` of some kind, with a valid user `dev`: it must
    /// still win (fail closed) and fail on load.
    fn check_bad_entry(setup: impl Fn(&Path, &Path)) {
        let f = fixture();
        let cwd = f.mkdir("p");
        let envy = cwd.join(".envy");
        fs::create_dir_all(&envy).unwrap();
        setup(&envy, &envy.join("dev.toml"));
        put(&f.user_dir, "dev", "A = \"2\"\n");
        let l = f.levels(&cwd);
        let r = l.resolve("dev", false).unwrap();
        assert!(r.cfg.is_project() && r.shadows_user);
        assert!(r.cfg.load("dev").is_err());
        assert!(!l.resolve("dev", true).unwrap().cfg.is_project());
        let e = l.entries().unwrap();
        assert_eq!(e[0].name, "dev");
        assert!(matches!(e[0].level, Level::Project { .. }) && !e[0].shadowed);
        assert!(e[1].shadowed);
    }

    #[test]
    fn project_entry_that_is_a_directory_fails_closed() {
        check_bad_entry(|_, p| fs::create_dir(p).unwrap());
    }

    #[test]
    fn project_entry_that_is_a_dangling_symlink_fails_closed() {
        check_bad_entry(|_, p| symlink("/nonexistent/nowhere", p).unwrap());
    }

    #[test]
    fn project_entry_that_is_a_symlink_to_a_valid_file_fails_closed() {
        check_bad_entry(|d, p| {
            let t = d.parent().unwrap().join("real.toml");
            fs::write(&t, "A = \"1\"\n").unwrap();
            symlink(&t, p).unwrap();
        });
    }

    #[test]
    fn project_entry_that_is_garbage_fails_closed() {
        check_bad_entry(|_, p| fs::write(p, "not [toml").unwrap());
    }

    #[test]
    fn project_entry_that_is_unreadable_fails_closed() {
        use std::os::unix::fs::PermissionsExt;
        if is_root() {
            return;
        }
        check_bad_entry(|_, p| {
            fs::write(p, "A = \"1\"\n").unwrap();
            fs::set_permissions(p, fs::Permissions::from_mode(0o000)).unwrap();
        });
    }

    #[test]
    fn discover_refuses_relative_or_unresolvable_paths() {
        let f = fixture();
        let cwd = f.mkdir("p");
        assert!(Levels::discover(Path::new("rel/dir"), &f.home, f.user()).is_err());
        assert!(Levels::discover(&cwd, Path::new("relhome"), f.user()).is_err());
        let gone = f.home.join("gone");
        assert!(Levels::discover(&gone, &f.home, f.user()).is_err());
        assert!(Levels::discover(&cwd, &f.home.join("nohome"), f.user()).is_err());
    }

    #[test]
    fn an_unreadable_envy_probe_fails_closed() {
        use std::os::unix::fs::PermissionsExt;
        if is_root() {
            return;
        }
        let f = fixture();
        let cwd = f.mkdir("p");
        fs::set_permissions(&cwd, fs::Permissions::from_mode(0o600)).unwrap();
        let r = Levels::discover(&cwd, &f.home, f.user());
        fs::set_permissions(&cwd, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(r.is_err());
    }

    #[test]
    fn cwd_inside_a_symlinked_directory_is_resolved() {
        let f = fixture();
        let real = f.mkdir("real/sub");
        fs::create_dir_all(f.home.join("real/.envy")).unwrap();
        symlink(f.home.join("real"), f.home.join("link")).unwrap();
        let l = f.levels(&f.home.join("link/sub"));
        assert_eq!(dirs(&l), vec![f.home.join("real/.envy")]);
        let _ = real;
    }

    #[test]
    fn an_envy_symlink_to_a_file_is_not_a_level() {
        let f = fixture();
        let cwd = f.mkdir("p");
        fs::write(f.home.join("target"), "x").unwrap();
        symlink(f.home.join("target"), cwd.join(".envy")).unwrap();
        assert!(dirs(&f.levels(&cwd)).is_empty());
    }

    #[test]
    fn new_project_level_never_targets_home() {
        let f = fixture();
        let user = f.user();
        fs::create_dir_all(f.home.join(".git")).unwrap();
        fs::write(
            f.home.join(".git/config"),
            "[remote \"origin\"]\n\turl = git@github.com:me/dotfiles.git\n",
        )
        .unwrap();
        let p = f.mkdir("p");
        let c = Levels::new_project_level(&p, &f.home, &user).unwrap();
        assert_eq!(c.dir(), p.join(".envy"));
        assert_eq!(c.identity(), Some("~/p"));
        assert!(Levels::new_project_level(&f.home, &f.home, &user).is_err());
    }

    #[test]
    fn new_project_level_is_refused_at_or_above_home() {
        let f = fixture();
        let user = f.user();
        let above = f.home.parent().unwrap().to_path_buf();
        for cwd in [f.home.clone(), above.clone(), PathBuf::from("/")] {
            let err = Levels::new_project_level(&cwd, &f.home, &user)
                .err()
                .unwrap_or_else(|| panic!("{} was accepted", cwd.display()));
            assert!(err.to_string().contains("home directory"), "{err}");
        }
        // Even with a `.git` above home (a repository holding the home).
        fs::create_dir_all(above.join(".git")).unwrap();
        assert!(Levels::new_project_level(&above, &f.home, &user).is_err());
        assert!(!above.join(".envy").exists());
        // A folder outside home, beside it, is unaffected.
        let beside = above.join("beside");
        fs::create_dir_all(&beside).unwrap();
        fs::remove_dir_all(above.join(".git")).unwrap();
        let c = Levels::new_project_level(&beside, &f.home, &user).unwrap();
        assert_eq!(c.dir(), beside.join(".envy"));
    }

    #[test]
    fn errors_escape_hostile_paths() {
        let f = fixture();
        let evil = f.home.join("ev\u{1b}[31mil\nx");
        fs::create_dir_all(&evil).unwrap();
        let gone = evil.join("gone");
        let err = format!(
            "{:#}",
            Levels::discover(&gone, &f.home, f.user()).err().unwrap()
        );
        assert!(!err.chars().any(char::is_control), "{err:?}");
        assert!(err.contains("ev%1B%5B31mil%0Ax"), "{err}");
    }

    #[test]
    fn new_project_level_outside_home() {
        let f = fixture();
        let user = f.user();
        let base = f.home.parent().unwrap().join("other");
        let sub = base.join("repo/src");
        fs::create_dir_all(&sub).unwrap();
        let c = Levels::new_project_level(&sub, &f.home, &user).unwrap();
        assert_eq!(c.dir(), sub.join(".envy"));
        fs::create_dir_all(base.join("repo/.git")).unwrap();
        let c = Levels::new_project_level(&sub, &f.home, &user).unwrap();
        assert_eq!(c.dir(), base.join("repo/.envy"));
    }
}
