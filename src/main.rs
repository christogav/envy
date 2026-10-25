use std::ffi::{OsStr, OsString};
use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use envy::activate::render_off;
use envy::cli::{self, Action, Command, Scope};
use envy::commands::{self, Ctx};
use envy::config::Config;
use envy::editor;
use envy::init;
use envy::levels::{Levels, shadow_note};
use envy::link;
use envy::project::encode_path;
use envy::prompt::TtyPrompter;
use envy::stack::ActiveState;
use envy::store::MacKeychain;

/// Stops core dumps, which would write secrets held in memory to disk.
fn harden() {
    let zero = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `zero` is a valid, initialised rlimit that outlives the call.
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &zero) };
    if rc != 0 {
        eprintln!("warning: could not disable core dumps");
    }
}

/// Activation output is shell code that contains secrets, so it may only go
/// to the shell function's `eval`: never to a terminal, and never anywhere
/// unless the function marked the call with `ENVY_EVAL=1` (a script that
/// runs the binary with stdout sent to a log would write secrets into it).
/// `envy_eval` is the value of `ENVY_EVAL`.
fn emit_guard(stdout_is_terminal: bool, envy_eval: Option<OsString>) -> Result<()> {
    if stdout_is_terminal || envy_eval.as_deref() != Some(OsStr::new("1")) {
        bail!(
            "refusing to print shell code (it would show secret values); use the shell function, set up by adding this line to ~/.zshrc: eval \"$(envy --init zsh)\""
        );
    }
    Ok(())
}

/// Checked before the config or the Keychain is touched.
fn check_emit() -> Result<()> {
    emit_guard(
        std::io::stdout().is_terminal(),
        std::env::var_os("ENVY_EVAL"),
    )
}

fn active_state() -> ActiveState {
    ActiveState::from_env(|k| std::env::var(k).ok())
}

/// Where this run is: the current directory, the home directory (the
/// boundary of the project search), and every level found from there.
struct Here {
    cwd: PathBuf,
    home: PathBuf,
    levels: Levels,
}

impl Here {
    fn discover() -> Result<Here> {
        let home = match std::env::var_os("HOME") {
            Some(h) if !h.is_empty() => PathBuf::from(h),
            _ => bail!(
                "HOME is not set; envy needs it to know where to stop looking for a project's .envy folder"
            ),
        };
        let cwd = std::env::current_dir().context(
            "cannot read the current directory (was it deleted?); cd to an existing folder and try again",
        )?;
        let levels = Levels::discover(&cwd, &home, Config::from_env()?)?;
        for note in levels.notes() {
            eprintln!("{note}");
        }
        Ok(Here { cwd, home, levels })
    }

    /// The level `ns` resolves to (`--user` forces the user's own), with the
    /// shadow note on stderr when a project namespace hides a user one.
    fn resolve(&self, ns: &str, scope: Scope) -> Result<&Config> {
        let resolved = self.levels.resolve(ns, scope == Scope::User)?;
        if resolved.shadows_user {
            eprintln!("{}", shadow_note(ns));
        }
        Ok(resolved.cfg)
    }
}

fn ctx(cfg: &Config) -> Ctx<'_> {
    Ctx {
        cfg,
        store: &MacKeychain,
        prompt: &TtyPrompter,
    }
}

/// Runs the action and returns the text for stdout. The text of an activation
/// contains secrets: it is only ever written to stdout, never logged.
fn run(command: Command) -> Result<String> {
    let scope = command.scope;
    match command.action {
        Action::Init(_) => Ok(init::zsh_function().to_string()),
        Action::Off => {
            check_emit()?;
            Ok(render_off(&active_state()))
        }
        Action::Activate(ns) => {
            // Refuse before the config, the Keychain or the filesystem is read.
            check_emit()?;
            let here = Here::discover()?;
            let cfg = here.resolve(&ns, scope)?;
            commands::activate(&ctx(cfg), &ns, &active_state())
        }
        Action::Status => commands::status(&Here::discover()?.levels, &active_state()),
        Action::List(ns) => {
            let here = Here::discover()?;
            // For the note only: `list_vars` resolves the same way.
            here.resolve(&ns, scope)?;
            commands::list_vars(&here.levels, &ns, scope == Scope::User, &active_state())
        }
        Action::New { ns, like, link } => {
            let here = Here::discover()?;
            let new_level;
            let target = match scope {
                Scope::Auto => here.levels.creation_level(false),
                Scope::User => here.levels.creation_level(true),
                Scope::Project => {
                    new_level =
                        Levels::new_project_level(&here.cwd, &here.home, here.levels.user())?;
                    &new_level
                }
            };
            // The source resolves like any other name, at its own level, and
            // is loaded before anything is created.
            let source = match &like {
                Some(name) => {
                    let cfg = here.resolve(name, scope)?;
                    if scope == Scope::User && !cfg.exists(name)? {
                        bail!(
                            "namespace {name:?} does not exist in your own level (--user also applies to the --like source; to copy a project namespace, leave out --user)"
                        );
                    }
                    Some((cfg, cfg.load(name)?))
                }
                None => None,
            };
            commands::create(
                &ctx(target),
                &ns,
                source.as_ref().map(|(cfg, file)| (*cfg, file)),
                link.as_deref(),
            )?;
            if target.is_project() {
                eprintln!(
                    "created project namespace {ns:?} in {}",
                    encode_path(target.dir())
                );
            } else {
                eprintln!("created namespace {ns:?}");
            }
            Ok(String::new())
        }
        Action::Set { ns, items } => {
            let here = Here::discover()?;
            commands::set_vars(&ctx(here.resolve(&ns, scope)?), &ns, &items)?;
            // Names only: never a value.
            let names: Vec<&str> = items.iter().map(|i| i.name.as_str()).collect();
            eprintln!("saved {} in {ns:?}", names.join(", "));
            Ok(String::new())
        }
        Action::Rm(ns) => {
            let here = Here::discover()?;
            let kept = commands::remove(&ctx(here.resolve(&ns, scope)?), &ns)?;
            eprintln!("removed namespace {ns:?}");
            if !kept.is_empty() {
                eprintln!(
                    "kept the project's shared Keychain items for: {} (delete them in Keychain Access: search \"envy.project/\")",
                    kept.join(", ")
                );
            }
            Ok(String::new())
        }
        Action::Link { ns, group } => {
            let here = Here::discover()?;
            link::link(&ctx(here.resolve(&ns, scope)?), &ns, &group)?;
            eprintln!("linked {ns:?} to group {group:?}");
            Ok(String::new())
        }
        Action::Unlink(ns) => {
            let here = Here::discover()?;
            link::unlink(&ctx(here.resolve(&ns, scope)?), &ns)?;
            eprintln!("unlinked {ns:?}; its variables are kept");
            Ok(String::new())
        }
        Action::Edit(ns) => {
            let here = Here::discover()?;
            if commands::edit(&ctx(here.resolve(&ns, scope)?), &ns, &editor::launch)? {
                eprintln!("saved {ns:?}");
            } else {
                eprintln!("no changes");
            }
            Ok(String::new())
        }
    }
}

fn write_stdout(text: &str) -> std::io::Result<()> {
    let mut out = std::io::stdout().lock();
    out.write_all(text.as_bytes())?;
    out.flush()
}

fn main() -> ExitCode {
    harden();
    let command = match cli::parse(std::env::args_os()) {
        Ok(command) => command,
        Err(e) => {
            use clap::error::ErrorKind;
            return match e.downcast_ref::<clap::Error>() {
                Some(ce)
                    if matches!(
                        ce.kind(),
                        ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
                    ) =>
                {
                    match write_stdout(&ce.render().to_string()) {
                        Ok(()) => ExitCode::SUCCESS,
                        Err(_) => ExitCode::FAILURE,
                    }
                }
                // clap's text already starts with "error: ".
                Some(ce) => {
                    eprint!("{}", ce.render());
                    ExitCode::FAILURE
                }
                None => {
                    eprintln!("error: {e:#}");
                    ExitCode::FAILURE
                }
            };
        }
    };
    match run(command) {
        Ok(text) => match write_stdout(&text) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("error: cannot write output: {e}");
                ExitCode::FAILURE
            }
        },
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emit_guard_allows_only_the_shell_function_writing_to_a_pipe() {
        let one = Some(OsString::from("1"));
        assert!(emit_guard(false, one.clone()).is_ok());
        for (terminal, marker) in [
            (true, one),
            (true, None),
            (false, None),
            (false, Some(OsString::from("0"))),
            (false, Some(OsString::from("1 "))),
            (false, Some(OsString::from(""))),
        ] {
            let err = emit_guard(terminal, marker.clone())
                .unwrap_err()
                .to_string();
            assert!(
                err.contains("eval \"$(envy --init zsh)\""),
                "{terminal} {marker:?}: {err}"
            );
        }
    }

    #[test]
    fn harden_sets_core_limit_to_zero() {
        harden();
        let mut lim = libc::rlimit {
            rlim_cur: 1,
            rlim_max: 1,
        };
        // SAFETY: `lim` is a valid rlimit the call writes into.
        let rc = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut lim) };
        assert_eq!(rc, 0);
        assert_eq!(lim.rlim_cur, 0);
    }
}
