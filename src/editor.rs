//! Runs the user's editor on a file.

use std::ffi::{OsStr, OsString};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};

/// The editor command: `$VISUAL`, else `$EDITOR`, else `vi` (empty or
/// whitespace-only counts as unset).
fn choose(visual: Option<OsString>, editor: Option<OsString>) -> OsString {
    let set = |v: &OsString| !v.to_string_lossy().trim().is_empty();
    visual
        .filter(set)
        .or(editor.filter(set))
        .unwrap_or_else(|| OsString::from("vi"))
}

/// Sets the disposition of `sig` to `handler` (`SIG_IGN`, `SIG_DFL` or a
/// handler the caller got from here), returning the previous one. Only calls
/// `sigaction`, so it is async-signal-safe (usable in `pre_exec`).
fn set_disposition(
    sig: libc::c_int,
    handler: libc::sighandler_t,
) -> std::io::Result<libc::sighandler_t> {
    // SAFETY: `act` is fully initialised (zeroed, empty mask, a valid
    // disposition) and `old` is a valid out-parameter.
    unsafe {
        let mut act: libc::sigaction = std::mem::zeroed();
        act.sa_sigaction = handler;
        libc::sigemptyset(&mut act.sa_mask);
        let mut old: libc::sigaction = std::mem::zeroed();
        if libc::sigaction(sig, &act, &mut old) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(old.sa_sigaction)
    }
}

/// While alive, envy ignores Ctrl-C (`SIGINT`) and `SIGQUIT`, which the
/// terminal sends to the editor and envy alike; dropping it puts envy's
/// previous dispositions back, on every path.
struct IgnoreInterrupts {
    previous: Vec<(libc::c_int, libc::sighandler_t)>,
}

const INTERRUPTS: [libc::c_int; 2] = [libc::SIGINT, libc::SIGQUIT];

impl IgnoreInterrupts {
    fn start() -> Result<Self> {
        let mut guard = Self {
            previous: Vec::new(),
        };
        for sig in INTERRUPTS {
            let old = set_disposition(sig, libc::SIG_IGN)
                .context("cannot protect envy from Ctrl-C while the editor runs")?;
            guard.previous.push((sig, old));
        }
        Ok(guard)
    }

    /// What the editor should get for `sig`: the default action, unless envy
    /// itself was started with it ignored (as by `nohup`).
    fn for_child(&self) -> Vec<(libc::c_int, libc::sighandler_t)> {
        self.previous
            .iter()
            .map(|&(sig, old)| {
                let h = if old == libc::SIG_IGN {
                    libc::SIG_IGN
                } else {
                    libc::SIG_DFL
                };
                (sig, h)
            })
            .collect()
    }
}

impl Drop for IgnoreInterrupts {
    fn drop(&mut self) {
        for &(sig, old) in self.previous.iter().rev() {
            let _ = set_disposition(sig, old);
        }
    }
}

/// Runs `editor` (a shell command, possibly with arguments, from the user's
/// own environment) on `path` as `sh -c '<editor> "$1"' _ <path>`. The path
/// is passed as an argument, never spliced into the script, so no file name
/// can inject shell code. The editor inherits stdin, stdout and stderr, so a
/// terminal editor works (`envy <ns> --edit` is not run inside `eval`, so the
/// terminal is the user's). Exiting non-zero, or being killed, is an error.
///
/// Like git, envy ignores Ctrl-C and `SIGQUIT` while it waits (the terminal
/// sends them to the whole foreground process group, and vim users press
/// Ctrl-C routinely), and the editor gets the default handling back before
/// it starts. Otherwise envy would die mid-edit, losing the edit and leaving
/// its temporary copy and an orphaned editor behind.
fn run(editor: &OsStr, path: &Path) -> Result<()> {
    let mut script = editor.to_os_string();
    script.push(" \"$1\"");
    let mut command = Command::new("/bin/sh");
    command.arg("-c").arg(&script).arg("_").arg(path);
    let guard = IgnoreInterrupts::start()?;
    let child_dispositions = guard.for_child();
    // SAFETY: the closure runs in the forked child before exec and only calls
    // `sigaction` (async-signal-safe); it allocates nothing (the Vec was
    // built before the fork and is only read).
    unsafe {
        command.pre_exec(move || {
            for &(sig, h) in &child_dispositions {
                set_disposition(sig, h)?;
            }
            Ok(())
        });
    }
    let status = command
        .status()
        .with_context(|| format!("cannot start the editor {editor:?}"));
    drop(guard);
    let status = status?;
    if status.success() {
        return Ok(());
    }
    match (status.code(), status.signal()) {
        (Some(code), _) => bail!("the editor {editor:?} exited with status {code}"),
        (None, Some(signal)) => bail!("the editor {editor:?} was killed by signal {signal}"),
        (None, None) => bail!("the editor {editor:?} failed"),
    }
}

/// Opens `path` in `$VISUAL`, else `$EDITOR`, else `vi`, and waits for it.
pub fn launch(path: &Path) -> Result<()> {
    run(
        &choose(std::env::var_os("VISUAL"), std::env::var_os("EDITOR")),
        path,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(s: &str) -> Option<OsString> {
        Some(OsString::from(s))
    }

    #[test]
    fn visual_then_editor_then_vi() {
        assert_eq!(choose(os("code -w"), os("nano")), "code -w");
        assert_eq!(choose(None, os("nano")), "nano");
        assert_eq!(choose(os(""), os("nano")), "nano");
        assert_eq!(choose(os(""), os("")), "vi");
        assert_eq!(choose(None, None), "vi");
    }

    #[test]
    fn whitespace_only_visual_or_editor_counts_as_unset() {
        assert_eq!(choose(os("  "), os("nano")), "nano");
        assert_eq!(choose(os(" \t\n"), os(" ")), "vi");
        assert_eq!(choose(None, os("\t")), "vi");
    }

    /// Serialises the tests that run an editor: they change (and must put
    /// back) this process's signal dispositions.
    static SIGNALS: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn lock() -> std::sync::MutexGuard<'static, ()> {
        SIGNALS.lock().unwrap_or_else(|e| e.into_inner())
    }

    static INTERRUPTS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    extern "C" fn count_interrupt(_: libc::c_int) {
        INTERRUPTS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    fn handler(sig: libc::c_int) -> libc::sighandler_t {
        // SAFETY: a zeroed sigaction is a valid out-parameter, and a null
        // `act` only queries the current disposition.
        unsafe {
            let mut old: libc::sigaction = std::mem::zeroed();
            assert_eq!(libc::sigaction(sig, std::ptr::null(), &mut old), 0);
            old.sa_sigaction
        }
    }

    fn set_handler(sig: libc::c_int, h: libc::sighandler_t) {
        // SAFETY: `act` is fully initialised; `h` is SIG_DFL, SIG_IGN or an
        // async-signal-safe `extern "C"` function.
        unsafe {
            let mut act: libc::sigaction = std::mem::zeroed();
            act.sa_sigaction = h;
            libc::sigemptyset(&mut act.sa_mask);
            assert_eq!(libc::sigaction(sig, &act, std::ptr::null_mut()), 0);
        }
    }

    #[test]
    fn envy_ignores_interrupts_while_the_editor_runs_and_restores_them_after() {
        let _guard = lock();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f.toml");
        std::fs::write(&path, "").unwrap();
        let counter = count_interrupt as extern "C" fn(libc::c_int) as libc::sighandler_t;
        let before = (handler(libc::SIGINT), handler(libc::SIGQUIT));
        set_handler(libc::SIGINT, counter);
        set_handler(libc::SIGQUIT, counter);
        INTERRUPTS.store(0, std::sync::atomic::Ordering::SeqCst);

        // The "editor" interrupts envy (its parent), as Ctrl-C would, then
        // itself: it must die of it, so it was not left ignoring Ctrl-C.
        let result = run(
            OsStr::new("kill -INT $PPID; kill -QUIT $PPID; kill -INT $$; exit 0;"),
            &path,
        );
        let after = (handler(libc::SIGINT), handler(libc::SIGQUIT));
        let interrupted = INTERRUPTS.load(std::sync::atomic::Ordering::SeqCst);
        set_handler(libc::SIGINT, before.0);
        set_handler(libc::SIGQUIT, before.1);

        let err = result.unwrap_err().to_string();
        assert!(err.contains("signal 2"), "{err}");
        assert_eq!(interrupted, 0, "envy saw an interrupt meant for the editor");
        assert_eq!(after, (counter, counter), "handlers not restored");
    }

    #[test]
    fn editor_with_arguments_runs_on_the_path() {
        let _guard = lock();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("work.toml");
        std::fs::write(&path, "a\n").unwrap();
        run(OsStr::new("printf 'b\\n' >>"), &path).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "a\nb\n");
    }

    #[test]
    fn path_is_an_argument_never_shell_text() {
        let _guard = lock();
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join("a b'\"$(touch pwned)`touch pwned2`;touch pwned3.toml");
        std::fs::write(&path, "").unwrap();
        // Run from the temp dir, so any injected `touch` would land there.
        let editor = format!("cd '{}' && printf x >>", dir.path().display());
        run(OsStr::new(&editor), &path).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "x");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn failing_editor_is_an_error() {
        let _guard = lock();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f.toml");
        std::fs::write(&path, "").unwrap();
        let err = run(OsStr::new("exit 3;"), &path).unwrap_err().to_string();
        assert!(err.contains('3'), "{err}");
        let err = run(OsStr::new("kill -9 $$;"), &path)
            .unwrap_err()
            .to_string();
        assert!(err.contains("signal"), "{err}");
    }
}
