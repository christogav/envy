use std::ffi::{OsStr, OsString};
use std::io::{IsTerminal, Write};
use std::process::ExitCode;

use anyhow::{Result, bail};
use envy::activate::{ActiveState, render_off};
use envy::cli::{self, Action, Command, Scope};
use envy::commands::{self, Ctx};
use envy::config::Config;
use envy::editor;
use envy::init;
use envy::link;
use envy::prompt::TtyPrompter;
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

/// Runs the action and returns the text for stdout. The text of an activation
/// contains secrets: it is only ever written to stdout, never logged.
fn run(action: Action) -> Result<String> {
    match action {
        Action::Status => commands::status(&Config::from_env()?, &active_state()),
        Action::Activate(ns) => {
            // Refuse before the config or the Keychain is read.
            check_emit()?;
            let cfg = Config::from_env()?;
            let ctx = Ctx {
                cfg: &cfg,
                store: &MacKeychain,
                prompt: &TtyPrompter,
            };
            commands::activate(&ctx, &ns, &active_state())
        }
        Action::Off => {
            check_emit()?;
            Ok(render_off(&active_state()))
        }
        Action::List(ns) => commands::list_vars(&Config::from_env()?, &ns, &active_state()),
        Action::Init(_) => Ok(init::zsh_function().to_string()),
        Action::New { ns, like, link } => {
            let cfg = Config::from_env()?;
            let ctx = Ctx {
                cfg: &cfg,
                store: &MacKeychain,
                prompt: &TtyPrompter,
            };
            commands::create(&ctx, &ns, like.as_deref(), link.as_deref())?;
            eprintln!("created namespace {ns:?}");
            Ok(String::new())
        }
        Action::Set { ns, items } => {
            let cfg = Config::from_env()?;
            let ctx = Ctx {
                cfg: &cfg,
                store: &MacKeychain,
                prompt: &TtyPrompter,
            };
            commands::set_vars(&ctx, &ns, &items)?;
            // Names only: never a value.
            let names: Vec<&str> = items.iter().map(|i| i.name.as_str()).collect();
            eprintln!("saved {} in {ns:?}", names.join(", "));
            Ok(String::new())
        }
        Action::Rm(ns) => {
            let cfg = Config::from_env()?;
            let ctx = Ctx {
                cfg: &cfg,
                store: &MacKeychain,
                prompt: &TtyPrompter,
            };
            commands::remove(&ctx, &ns)?;
            eprintln!("removed namespace {ns:?}");
            Ok(String::new())
        }
        Action::Link { ns, group } => {
            let cfg = Config::from_env()?;
            let ctx = Ctx {
                cfg: &cfg,
                store: &MacKeychain,
                prompt: &TtyPrompter,
            };
            link::link(&ctx, &ns, &group)?;
            eprintln!("linked {ns:?} to group {group:?}");
            Ok(String::new())
        }
        Action::Unlink(ns) => {
            let cfg = Config::from_env()?;
            let ctx = Ctx {
                cfg: &cfg,
                store: &MacKeychain,
                prompt: &TtyPrompter,
            };
            link::unlink(&ctx, &ns)?;
            eprintln!("unlinked {ns:?}; its variables are kept");
            Ok(String::new())
        }
        Action::Edit(ns) => {
            let cfg = Config::from_env()?;
            let ctx = Ctx {
                cfg: &cfg,
                store: &MacKeychain,
                prompt: &TtyPrompter,
            };
            if commands::edit(&ctx, &ns, &editor::launch)? {
                eprintln!("saved {ns:?}");
            } else {
                eprintln!("no changes");
            }
            Ok(String::new())
        }
    }
}

/// Until the flags are wired in, refuse them instead of ignoring them.
fn scope_guard(command: &Command) -> Result<()> {
    if command.scope != Scope::Auto {
        bail!("--user and --project are not available yet");
    }
    Ok(())
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
    match scope_guard(&command).and_then(|()| run(command.action)) {
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
    fn scope_flags_are_refused_until_they_are_wired() {
        let cmd = |scope| Command {
            action: Action::Activate("dev".into()),
            scope,
        };
        assert!(scope_guard(&cmd(Scope::Auto)).is_ok());
        for scope in [Scope::User, Scope::Project] {
            let err = scope_guard(&cmd(scope)).unwrap_err().to_string();
            assert!(err.contains("not available yet"), "{err}");
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
