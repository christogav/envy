//! End-to-end tests: real zsh, real binary, plain variables only (no Keychain).
//!
//! The binary under test uses the real `MacKeychain`. That is safe only
//! because no fixture here contains an `@keychain` variable, so no command
//! ever reads, writes or deletes a Keychain item. Keep it that way.

use std::path::Path;
use std::process::{Command, Output};

use tempfile::TempDir;

const ENVY: &str = env!("CARGO_BIN_EXE_envy");

fn fixture() -> TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("work.toml"),
        "[vars]\nAWS_REGION = \"eu-west-1\"\nTAG = \"it's $HOME\"\n",
    )
    .unwrap();
    std::fs::write(
        dir.path().join("personal.toml"),
        "[vars]\nONLY_PERSONAL = \"p\"\n",
    )
    .unwrap();
    dir
}

/// `PATH` with the directory of the binary under test first.
fn path_with_envy() -> String {
    let bin_dir = Path::new(ENVY).parent().unwrap();
    format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    )
}

/// Runs `script` as is in a fresh zsh (`envy` on the `PATH`, no function).
fn zsh_raw(config: &Path, script: &str) -> Output {
    Command::new("zsh")
        .args(["-f", "-c", script])
        .env("PATH", path_with_envy())
        .env("ENVY_CONFIG_DIR", config)
        .env("HOME", config)
        .current_dir(config)
        .env_remove("ENVY_ACTIVE")
        .env_remove("ENVY_VARS")
        .env_remove("ENVY_EVAL")
        .output()
        .unwrap()
}

/// Runs `script` in a fresh zsh with envy's shell function loaded.
fn zsh(config: &Path, script: &str) -> Output {
    zsh_raw(config, &format!("eval \"$(envy --init zsh)\"\n{script}"))
}

fn stdout(out: &Output) -> String {
    String::from_utf8(out.stdout.clone()).unwrap()
}

fn stderr(out: &Output) -> String {
    String::from_utf8(out.stderr.clone()).unwrap()
}

#[test]
fn activate_then_switch_is_clean() {
    let dir = fixture();
    let out = zsh(
        dir.path(),
        r#"AWS_REGION=orig
envy work
print -r -- "$AWS_REGION|$TAG|$ENVY_ACTIVE"
envy personal
print -r -- "${AWS_REGION-unset}|$ONLY_PERSONAL"
envy --off
print -r -- "${ONLY_PERSONAL-unset}|${ENVY_ACTIVE-unset}"
"#,
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(
        stdout(&out),
        "eu-west-1|it's $HOME|work\nunset|p\nunset|unset\n"
    );
    assert_eq!(stderr(&out), "");
}

#[test]
fn unknown_namespace_errors_and_changes_nothing() {
    let dir = fixture();
    let out = zsh(
        dir.path(),
        r#"envy bogus
print -r -- "${ENVY_ACTIVE-unset}|${ENVY_VARS-unset}|${AWS_REGION-unset}"
"#,
    );
    assert_eq!(stdout(&out), "unset|unset|unset\n");
    let err = stderr(&out);
    assert!(err.contains("bogus"), "{err}");
    assert!(err.contains("--new"), "{err}");
}

#[test]
fn failed_activation_returns_nonzero() {
    let dir = fixture();
    let out = zsh(
        dir.path(),
        r#"envy work
envy bogus || print -r -- "failed:$?"
print -r -- "$ENVY_ACTIVE|$AWS_REGION"
envy bogus && print -r -- "deploy"
"#,
    );
    // The failed switch leaves the previous activation untouched, returns
    // non-zero (so `&&` chains stop) and prints nothing to stdout itself.
    assert_eq!(stdout(&out), "failed:1\nwork|eu-west-1\n");
    let err = stderr(&out);
    assert!(err.contains("bogus") && err.contains("--new"), "{err}");
}

#[test]
fn xtrace_does_not_leak_values() {
    let dir = fixture();
    let out = zsh(
        dir.path(),
        "set -x\nenvy work\nset +x\nprint -r -- \"$AWS_REGION\"\n",
    );
    assert_eq!(stdout(&out), "eu-west-1\n");
    let err = stderr(&out);
    assert!(!err.contains("eu-west-1"), "{err}");
    assert!(!err.contains("$HOME"), "{err}");
}

#[test]
fn non_activation_commands_are_not_evaluated() {
    let dir = fixture();
    let out = zsh(
        dir.path(),
        "envy work\nenvy\nenvy --init zsh | head -n 1\nenvy --help | head -n 1\n",
    );
    assert!(out.status.success(), "{}", stderr(&out));
    let text = stdout(&out);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines[0], "  personal");
    assert_eq!(lines[1], "* work");
    assert_eq!(lines[2], "envy() {", "{text}");
    assert!(lines[3].starts_with("Load secrets"), "{text}");
    assert_eq!(lines.len(), 4, "{text}");
}

#[test]
fn namespace_named_like_a_command_is_still_a_namespace() {
    let dir = fixture();
    std::fs::write(dir.path().join("status.toml"), "[vars]\nS = \"1\"\n").unwrap();
    let out = zsh(dir.path(), "envy status\nprint -r -- \"$ENVY_ACTIVE|$S\"\n");
    assert_eq!(stdout(&out), "status|1\n");
}

#[test]
fn binary_prints_nothing_to_stdout_on_failure() {
    let dir = fixture();
    for args in [&["bogus"][..], &["--off", "x"][..], &["bad name"][..]] {
        let out = Command::new(ENVY)
            .args(args)
            .env("ENVY_CONFIG_DIR", dir.path())
            .env("HOME", dir.path())
            .current_dir(dir.path())
            .env("ENVY_EVAL", "1")
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(1), "{args:?}");
        assert_eq!(stdout(&out), "", "{args:?}");
        assert!(stderr(&out).starts_with("error: "), "{args:?}");
    }
}

/// Runs the binary with no prompts expected (plain-only files, no Keychain).
fn envy(config: &Path, args: &[&str]) -> Output {
    Command::new(ENVY)
        .args(args)
        .env("ENVY_CONFIG_DIR", config)
        .env("HOME", config)
        .current_dir(config)
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap()
}

#[test]
fn link_unlink_and_new_with_link_are_wired() {
    let dir = fixture();
    let read = |name: &str| std::fs::read_to_string(dir.path().join(name)).unwrap();

    let out = envy(dir.path(), &["work", "--link", "grp"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "");
    assert!(
        read("work.toml").starts_with("link = \"grp\"\n"),
        "{}",
        read("work.toml")
    );

    // `personal` has names the group lacks: refused before any prompt.
    let out = envy(dir.path(), &["personal", "--link", "grp"]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(stdout(&out), "");
    assert!(stderr(&out).contains("ONLY_PERSONAL"), "{}", stderr(&out));
    assert_eq!(read("personal.toml"), "[vars]\nONLY_PERSONAL = \"p\"\n");

    let out = envy(dir.path(), &["fresh", "--new", "--link", "solo"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(read("fresh.toml"), "link = \"solo\"\n");

    let out = envy(dir.path(), &["work", "--unlink"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(!read("work.toml").contains("link"), "{}", read("work.toml"));
}

#[test]
fn drifted_linked_namespace_refuses_to_activate_with_no_stdout() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("a.toml"),
        "link = \"g\"\n[vars]\nX = \"1\"\n",
    )
    .unwrap();
    std::fs::write(
        dir.path().join("b.toml"),
        "link = \"g\"\n[vars]\nY = \"2\"\n",
    )
    .unwrap();
    let out = zsh(
        dir.path(),
        "envy a\nprint -r -- \"${X-unset}|${ENVY_ACTIVE-unset}\"\n",
    );
    assert_eq!(stdout(&out), "unset|unset\n");
    let err = stderr(&out);
    assert!(
        err.contains("missing Y") && err.contains("extra X"),
        "{err}"
    );
}

/// Writes an executable editor script into its own temp dir.
fn editor_script(body: &str) -> (TempDir, std::path::PathBuf) {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fake-editor");
    std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    (dir, path)
}

#[test]
fn edit_runs_visual_on_a_copy_and_saves_plain_changes() {
    let dir = fixture();
    // The editor records the path it was given, then appends a plain line.
    let log = dir.path().join("editor.log");
    let (_ed, script) = editor_script(&format!(
        "printf '%s\\n' \"$1\" > '{}'\nprintf 'NEW = \"added\"\\n' >> \"$1\"",
        log.display()
    ));
    let out = zsh(
        dir.path(),
        &format!(
            "VISUAL='{}' envy work --edit\nenvy work\nprint -r -- \"$NEW|$AWS_REGION\"\n",
            script.display()
        ),
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "added|eu-west-1\n");
    assert!(stderr(&out).contains("saved \"work\""), "{}", stderr(&out));
    assert_eq!(
        std::fs::read_to_string(dir.path().join("work.toml")).unwrap(),
        "[vars]\nAWS_REGION = \"eu-west-1\"\nTAG = \"it's $HOME\"\nNEW = \"added\"\n"
    );
    // The editor got a copy outside the config dir, removed afterwards.
    let copy = std::fs::read_to_string(&log).unwrap();
    let copy = Path::new(copy.trim_end());
    assert!(copy.ends_with("work.toml"), "{copy:?}");
    assert!(!copy.starts_with(dir.path()), "{copy:?}");
    assert!(!copy.exists() && !copy.parent().unwrap().exists());
}

#[test]
fn edit_with_failing_editor_or_bad_result_changes_nothing() {
    let dir = fixture();
    let before = std::fs::read_to_string(dir.path().join("work.toml")).unwrap();
    for body in [
        "printf 'NEW = \"x\"\\n' >> \"$1\"; exit 4",
        "printf '[vars\\n' > \"$1\"",
        "printf 'link = \"grp\"\\n' > \"$1\"",
    ] {
        let (_ed, script) = editor_script(body);
        let out = Command::new(ENVY)
            .args(["work", "--edit"])
            .env("ENVY_CONFIG_DIR", dir.path())
            .env("HOME", dir.path())
            .current_dir(dir.path())
            .env("VISUAL", &script)
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(1), "{body}");
        assert_eq!(stdout(&out), "", "{body}");
        assert!(
            stderr(&out).contains("nothing was changed"),
            "{body}: {}",
            stderr(&out)
        );
        assert_eq!(
            std::fs::read_to_string(dir.path().join("work.toml")).unwrap(),
            before
        );
    }
}

#[test]
fn edit_that_changes_nothing_says_so() {
    let dir = fixture();
    let before = std::fs::read_to_string(dir.path().join("work.toml")).unwrap();
    let (_ed, script) = editor_script("exit 0");
    let out = Command::new(ENVY)
        .args(["work", "--edit"])
        .env("ENVY_CONFIG_DIR", dir.path())
        .env("HOME", dir.path())
        .current_dir(dir.path())
        .env("VISUAL", &script)
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "");
    assert_eq!(stderr(&out), "no changes\n");
    assert_eq!(
        std::fs::read_to_string(dir.path().join("work.toml")).unwrap(),
        before
    );
}

/// Waits for `child`, killing it (and failing) after `secs` seconds.
fn wait_or_kill(child: &mut std::process::Child, secs: u64) -> std::process::ExitStatus {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            panic!("envy did not finish within {secs}s");
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

/// Ctrl-C in a terminal editor (vim users press it to leave insert mode)
/// is delivered to the whole foreground process group. envy must survive it
/// and finish the edit once the editor exits normally.
#[test]
fn ctrl_c_in_the_editor_does_not_kill_envy() {
    use std::os::unix::process::CommandExt;
    let dir = fixture();
    let scratch = tempfile::tempdir().unwrap();
    let log = scratch.path().join("editor.log");
    let ready = scratch.path().join("ready");
    let go = scratch.path().join("go");
    // Like vim, the editor handles Ctrl-C (and Ctrl-\\) itself and keeps going.
    let (_ed, script) = editor_script(&format!(
        "trap 'echo interrupted >> \"{log}\"' INT\n\
         trap 'echo quit >> \"{log}\"' QUIT\n\
         echo \"$1\" >> \"{log}\"\n\
         printf 'NEW = \"after-ctrl-c\"\\n' >> \"$1\"\n\
         : > \"{ready}\"\n\
         n=0\n\
         while [ ! -e \"{go}\" ] && [ $n -lt 400 ]; do sleep 0.05; n=$((n+1)); done\n\
         exit 0",
        log = log.display(),
        ready = ready.display(),
        go = go.display(),
    ));
    let mut child = Command::new(ENVY)
        .args(["work", "--edit"])
        .env("ENVY_CONFIG_DIR", dir.path())
        .env("HOME", dir.path())
        .current_dir(dir.path())
        .env("VISUAL", &script)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .process_group(0)
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !ready.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "the editor never started"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let pgid = child.id() as i32;
    // SAFETY: plain syscalls; a negative pid addresses the process group.
    assert_eq!(unsafe { libc::kill(-pgid, libc::SIGINT) }, 0);
    std::thread::sleep(std::time::Duration::from_millis(200));
    // SAFETY: as above.
    assert_eq!(unsafe { libc::kill(-pgid, libc::SIGQUIT) }, 0);
    std::thread::sleep(std::time::Duration::from_millis(200));
    std::fs::write(&go, "").unwrap();
    let status = wait_or_kill(&mut child, 10);
    let out = child.wait_with_output().unwrap();

    let log = std::fs::read_to_string(&log).unwrap();
    assert!(
        log.contains("interrupted") && log.contains("quit"),
        "the editor did not get both signals: {log}"
    );
    assert!(status.success(), "{status:?} {}", stderr(&out));
    assert_eq!(stdout(&out), "");
    assert_eq!(
        std::fs::read_to_string(dir.path().join("work.toml")).unwrap(),
        "[vars]\nAWS_REGION = \"eu-west-1\"\nTAG = \"it's $HOME\"\nNEW = \"after-ctrl-c\"\n"
    );
    let copy = Path::new(log.lines().next().unwrap());
    assert!(!copy.parent().unwrap().exists(), "temp dir left behind");
}

#[test]
fn help_goes_to_stdout_with_success() {
    let out = Command::new(ENVY).arg("--help").output().unwrap();
    assert!(out.status.success());
    assert!(stdout(&out).contains("Usage"), "{}", stdout(&out));
    assert_eq!(stderr(&out), "");
}

#[test]
fn special_zsh_parameter_names_are_refused() {
    let dir = fixture();
    // `--plain` refuses the name before any prompt or file access.
    let out = envy(dir.path(), &["work", "--plain", "SECONDS"]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(stdout(&out), "");
    let err = stderr(&out);
    assert!(
        err.contains("\"SECONDS\"") && err.contains("special zsh parameter"),
        "{err}"
    );
    assert!(
        !std::fs::read_to_string(dir.path().join("work.toml"))
            .unwrap()
            .contains("SECONDS")
    );

    // A file written by hand with such a name fails to activate, naming it,
    // and the shell keeps its previous activation untouched.
    let marker = dir.path().join("PWNED");
    std::fs::write(
        dir.path().join("evil.toml"),
        format!(
            "[vars]\nFIRST = \"1\"\nSECONDS = \"a[$(touch {})]\"\nCOLUMNS = \"hunter2 secret-tail\"\n",
            marker.display()
        ),
    )
    .unwrap();
    let out = zsh(
        dir.path(),
        r#"envy work
envy evil || print -r -- "failed:$?"
print -r -- "$ENVY_ACTIVE|$ENVY_VARS|$AWS_REGION|${FIRST-unset}"
"#,
    );
    assert_eq!(
        stdout(&out),
        "failed:1\nwork|AWS_REGION TAG|eu-west-1|unset\n"
    );
    let err = stderr(&out);
    assert!(
        err.contains("\"evil\"") && err.contains("\"SECONDS\"") && err.contains("special"),
        "{err}"
    );
    assert!(
        !err.contains("hunter2") && !err.contains("secret-tail"),
        "{err}"
    );
    assert!(!marker.exists(), "the value ran as code");
}

const NOT_THROUGH_THE_FUNCTION: &str = "use the shell function";

/// A script without the shell function, logging stdout to a file, must not
/// get the export lines (they would hold secrets) in the log.
#[test]
fn binary_refuses_to_print_exports_outside_the_shell_function() {
    let dir = fixture();
    let log = dir.path().join("out.log");
    for args in ["work", "--off"] {
        // The config "directory" is a file: had the binary gone on to read
        // the config (and from there the Keychain), it would fail with
        // "cannot read namespace" instead.
        let out = Command::new("zsh")
            .args(["-f", "-c", &format!("envy {args} > '{}'", log.display())])
            .env_clear()
            .env("PATH", path_with_envy())
            .env("HOME", dir.path())
            .env("ENVY_CONFIG_DIR", dir.path().join("work.toml"))
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(1), "{args}");
        assert_eq!(stdout(&out), "");
        let err = stderr(&out);
        assert!(
            err.starts_with("error: ")
                && err.contains(NOT_THROUGH_THE_FUNCTION)
                && err.contains("eval \"$(envy --init zsh)\""),
            "{args}: {err}"
        );
        assert!(!err.contains("cannot read"), "{err}");
        assert_eq!(std::fs::read_to_string(&log).unwrap(), "", "{args}");
    }
}

#[test]
fn the_eval_marker_never_reaches_the_shell_environment() {
    let dir = fixture();
    let out = zsh(
        dir.path(),
        "envy work\nprint -r -- \"$AWS_REGION|${ENVY_EVAL-unset}|$(printenv ENVY_EVAL || print absent)\"\n",
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "eu-west-1|unset|absent\n");
}

#[test]
fn aliases_defined_before_the_function_cannot_subvert_it() {
    let dir = fixture();
    let out = zsh_raw(
        dir.path(),
        r#"alias command='echo hijacked' builtin='echo hijacked' print='echo hijacked'
alias eval='echo hijacked' emulate='echo hijacked' unsetopt='echo hijacked'
eval "$(envy --init zsh)"
unalias command builtin print eval emulate unsetopt
envy work
print -r -- "$AWS_REGION|$ENVY_ACTIVE"
"#,
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "eu-west-1|work\n");
    assert_eq!(stderr(&out), "");
}

#[test]
fn clap_errors_have_a_single_error_prefix_and_version_goes_to_stdout() {
    let out = Command::new(ENVY).arg("--frobnicate").output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(stdout(&out), "");
    let err = stderr(&out);
    assert!(err.starts_with("error: unexpected argument"), "{err}");
    assert!(!err.contains("error: error:"), "{err}");

    let out = Command::new(ENVY).arg("--version").output().unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(
        stdout(&out),
        format!("envy {}\n", env!("CARGO_PKG_VERSION"))
    );
    assert_eq!(stderr(&out), "");
}

/// Every file in `dir` with its text, for "nothing changed" checks.
fn texts(dir: &Path) -> Vec<(String, String)> {
    let mut v: Vec<(String, String)> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| {
            let e = e.unwrap();
            let text = std::fs::read_to_string(e.path()).unwrap();
            (e.file_name().to_string_lossy().into_owned(), text)
        })
        .collect();
    v.sort();
    v
}

#[test]
fn several_plain_items_are_saved_in_one_command_and_load() {
    let dir = fixture();
    // Inline values only: no prompt, and no Keychain access at all.
    let out = envy(
        dir.path(),
        &[
            "work", "--plain", "A=1", "B=2", "URL=x=y", "--plain", "EMPTY=",
        ],
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "");
    assert_eq!(stderr(&out), "saved A, B, URL, EMPTY in \"work\"\n");
    assert_eq!(
        std::fs::read_to_string(dir.path().join("work.toml")).unwrap(),
        "[vars]\nAWS_REGION = \"eu-west-1\"\nTAG = \"it's $HOME\"\nA = \"1\"\nB = \"2\"\nURL = \"x=y\"\nEMPTY = \"\"\n"
    );
    let out = zsh(
        dir.path(),
        "envy work\nprint -r -- \"$A|$B|$URL|[$EMPTY]|${EMPTY+set}|$AWS_REGION\"\n",
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "1|2|x=y|[]|set|eu-west-1\n");
}

/// Runs the binary detached from any terminal: in a new session (so it has
/// no controlling terminal and cannot open `/dev/tty` to prompt), with stdin
/// closed, killed if it has not finished within 10 seconds. A regression
/// that reaches a prompt fails fast instead of hanging or asking.
fn envy_detached(config: &Path, args: &[&str]) -> Output {
    let mut cmd = Command::new(ENVY);
    cmd.args(args)
        .env("ENVY_CONFIG_DIR", config)
        .env("HOME", config)
        .current_dir(config);
    detached(cmd)
}

/// Runs `cmd` with no terminal (see [`envy_detached`]).
fn detached(mut cmd: Command) -> Output {
    use std::os::unix::process::CommandExt;
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    // SAFETY: `setsid` is async-signal-safe and touches no memory.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = cmd.spawn().unwrap();
    wait_or_kill(&mut child, 10);
    child.wait_with_output().unwrap()
}

#[test]
fn a_secret_value_on_the_command_line_is_refused_and_changes_nothing() {
    let dir = fixture();
    let before = texts(dir.path());
    for args in [
        &["work", "--secret", "TOKEN=zq-hunter2"][..],
        &["work", "--plain", "A=1", "--secret", "TOKEN=zq-hunter2"],
        &["work", "--secret=TOKEN=zq-hunter2"],
    ] {
        let out = envy_detached(dir.path(), args);
        assert_eq!(out.status.code(), Some(1), "{args:?}");
        assert_eq!(stdout(&out), "", "{args:?}");
        let err = stderr(&out);
        assert!(
            err.starts_with("error: ") && err.contains("\"TOKEN\"") && err.contains("prompt"),
            "{args:?}: {err}"
        );
        assert!(!err.contains("zq-hunter2"), "{args:?}: {err}");
        assert_eq!(texts(dir.path()), before, "{args:?}");
    }
}

/// clap's own errors quote arguments back; whatever followed a `=` must not
/// reach the terminal, on stderr or stdout.
#[test]
fn values_after_an_equals_sign_never_reach_the_output_of_a_failed_command() {
    let dir = fixture();
    let before = texts(dir.path());
    for args in [
        &["work", "--secret", "A", "--", "TOKEN=sk-live-123"][..],
        &["work", "--secret", "--", "TOKEN=sk-live-123"],
        &["work", "--secret", "A", "--frob", "TOKEN=sk-live-123"],
        &["--frob=TOKEN=sk-live-123"],
        &["work", "--off=sk-live-123"],
        &[
            "work",
            "--plain",
            "X",
            "--secret",
            "A",
            "TOKEN=sk-live-123",
            "--",
            "TOKEN2=sk-live-456",
        ],
    ] {
        let out = envy_detached(dir.path(), args);
        assert_eq!(out.status.code(), Some(1), "{args:?}");
        let (out_text, err) = (stdout(&out), stderr(&out));
        assert_eq!(out_text, "", "{args:?}");
        assert!(err.starts_with("error: "), "{args:?}: {err}");
        assert!(!err.contains("error: error:"), "{args:?}: {err}");
        assert!(
            err.contains("=…") || err.contains("'…'") || err.contains("'--frob'"),
            "{args:?}: {err}"
        );
        assert!(!err.contains("sk-live-"), "{args:?}: {err}");
        assert_eq!(texts(dir.path()), before, "{args:?}");
    }
    // Without an `=`, clap's message is shown exactly as clap words it.
    let out = envy_detached(dir.path(), &["work", "--secret", "A", "--", "B"]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        stderr(&out),
        "error: unexpected argument 'B' found\n\nUsage: envy [OPTIONS] [NAMESPACE]\n\nFor more information, try '--help'.\n"
    );
}

/// The shell function evaluates only `envy <namespace>` and `envy --off`.
/// A stub `envy` that prints shell code shows which calls were evaluated:
/// evaluated output sets LEAK; output that is not evaluated is just printed.
#[test]
fn set_commands_with_several_items_are_not_evaluated() {
    use std::os::unix::fs::PermissionsExt;
    let dir = fixture();
    let stub = tempfile::tempdir().unwrap();
    let path = stub.path().join("envy");
    std::fs::write(&path, "#!/bin/sh\nprintf '%s\\n' 'LEAK=\"${LEAK}x\"'\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    let out = zsh(
        dir.path(),
        &format!(
            r#"path=('{}' $path)
envy work --secret A B
print -r -- "1:${{LEAK-unset}}"
envy work --plain A=1 B=2
print -r -- "2:${{LEAK-unset}}"
envy work --secret A --plain B=2
print -r -- "3:${{LEAK-unset}}"
envy work
print -r -- "4:${{LEAK-unset}}"
"#,
            stub.path().display()
        ),
    );
    assert!(out.status.success(), "{}", stderr(&out));
    let shown = "LEAK=\"${LEAK}x\"";
    assert_eq!(
        stdout(&out),
        format!("{shown}\n1:unset\n{shown}\n2:unset\n{shown}\n3:unset\n4:x\n")
    );

    // With the real binary: the namespace is saved, not loaded.
    let out = zsh(
        dir.path(),
        "envy work --plain A=1 B=2\nprint -r -- \"${A-unset}|${ENVY_ACTIVE-unset}\"\n",
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "unset|unset\n");
    assert_eq!(stderr(&out), "saved A, B in \"work\"\n");
}

#[test]
fn list_commands_print_to_stdout_and_are_not_evaluated() {
    let dir = fixture();
    std::fs::write(
        dir.path().join("dev.toml"),
        "link = \"aws\"\n[vars]\nREGION = \"eu\\tx\"\nEMPTY = \"\"\nHOSTILE = \"\\u001b[31mred\\U000E0041\"\n",
    )
    .unwrap();
    // Through the shell function, with `dev` active.
    let out = zsh(
        dir.path(),
        "envy dev\nenvy --list\nenvy --ls\nenvy dev --list\n",
    );
    assert!(out.status.success(), "{}", stderr(&out));
    let names = "  dev\n  personal\n  work\n";
    let marked = "* dev\n  personal\n  work\n";
    let vars = "namespace: dev (active)\nsource: user\nlink: aws\n\nREGION   \"eu\\tx\"\nEMPTY    \"\"\nHOSTILE  \"\\u{1b}[31mred\\u{e0041}\"\n";
    assert_eq!(stdout(&out), format!("{marked}{marked}{vars}"));
    assert_eq!(stderr(&out), "");

    // The binary directly, with no marker and stdout piped.
    for (args, want) in [
        (&["--list"][..], marked.replace("* dev", "  dev")),
        (&["--ls"], names.to_string()),
        (&["dev", "--list"], vars.replace(" (active)", "")),
    ] {
        let out = envy(dir.path(), args);
        assert!(out.status.success(), "{args:?}: {}", stderr(&out));
        assert_eq!(stdout(&out), want, "{args:?}");
        assert_eq!(stderr(&out), "");
    }
}

#[test]
fn list_of_an_unknown_namespace_fails_with_the_hint_on_stderr() {
    let dir = fixture();
    let out = envy(dir.path(), &["bogus", "--list"]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(stdout(&out), "");
    let err = stderr(&out);
    assert!(err.contains("bogus") && err.contains("--new"), "{err}");
}

/// A word quoted for a zsh script: any text, `'` included.
fn sh_quote(word: &str) -> String {
    format!("'{}'", word.replace('\'', r"'\''"))
}

/// Runs each argv through the real shell function with a STUB `envy` on the
/// `PATH` that prints `print -r -- EVALUATED`. If the function evaluates the
/// output, the line is `EVALUATED`; if it only runs the stub, the line is the
/// literal `print -r -- EVALUATED`. `prelude` runs before the calls (to set
/// options). Also returns, per call, the arguments the stub received, as
/// `<count>` then ` [arg]` each, so a word that the function split, globbed
/// or expanded shows up.
fn wrapper_outcomes_with(prelude: &str, argvs: &[&[&str]]) -> (Vec<String>, Vec<String>) {
    let stub_dir = tempfile::tempdir().unwrap();
    let stub = stub_dir.path().join("envy");
    let log = stub_dir.path().join("args.log");
    std::fs::write(
        &stub,
        "#!/bin/sh\n{ printf '%s' \"$#\"; for a in \"$@\"; do printf ' [%s]' \"$a\"; done; printf '\\n'; } >> \"$STUB_LOG\"\necho 'print -r -- EVALUATED'\n",
    )
    .unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    // The function text comes from the real binary, run before the stub.
    let function = String::from_utf8(
        Command::new(ENVY)
            .args(["--init", "zsh"])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();
    let mut script = function;
    script.push_str(prelude);
    script.push('\n');
    for args in argvs {
        let quoted: Vec<String> = args.iter().map(|a| sh_quote(a)).collect();
        script.push_str(&format!("envy {}\n", quoted.join(" ")));
    }
    let out = Command::new("zsh")
        .args(["-f", "-c", &script])
        .env(
            "PATH",
            format!(
                "{}:{}",
                stub_dir.path().display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .env("STUB_LOG", &log)
        .current_dir(stub_dir.path())
        .env_remove("ENVY_EVAL")
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    let lines = stdout(&out).lines().map(str::to_string).collect();
    let seen = std::fs::read_to_string(&log)
        .unwrap_or_default()
        .lines()
        .map(str::to_string)
        .collect();
    (lines, seen)
}

/// What the stub logs for `args` (see [`wrapper_outcomes_with`]).
fn logged(args: &[&str]) -> String {
    let mut line = args.len().to_string();
    for a in args {
        line.push_str(&format!(" [{a}]"));
    }
    line
}

fn check_wrapper(prelude: &str) {
    let evaluated: &[&[&str]] = &[
        &["dev", "--user"],
        &["--user", "dev"],
        &["dev"],
        &["--off"],
        &["*"],
        &["$HOME"],
        &[""],
        &["a b"],
        &["*", "--user"],
        &["--user", "a b"],
    ];
    let shown: &[&[&str]] = &[
        &["dev", "--user", "--list"],
        &["--list", "--user"],
        &["dev", "--list"],
        &["--user", "--off"],
        &["dev", "--secret", "A"],
        &["--init", "zsh"],
        &["--user"],
        &["dev", "--new", "--project"],
        &["*", "--list"],
        &["a b", "--list"],
    ];
    let all: Vec<&[&str]> = evaluated.iter().chain(shown).copied().collect();
    let (lines, seen) = wrapper_outcomes_with(prelude, &all);
    assert_eq!(lines.len(), all.len(), "{prelude}: {lines:?}");
    for (args, line) in all.iter().zip(&lines) {
        let want = evaluated.contains(args);
        assert_eq!(line == "EVALUATED", want, "{prelude}: {args:?}: {line}");
        if !want {
            assert_eq!(line, "print -r -- EVALUATED", "{prelude}: {args:?}");
        }
    }
    // Every word reached the binary exactly as typed.
    let want: Vec<String> = all.iter().map(|a| logged(a)).collect();
    assert_eq!(seen, want, "{prelude}");
}

#[test]
fn user_flag_forms_are_evaluated_and_other_shapes_are_not() {
    check_wrapper("");
}

#[test]
fn the_wrapper_is_unaffected_by_the_callers_options() {
    check_wrapper("setopt ksh_arrays sh_word_split");
    check_wrapper("setopt ksh_arrays sh_word_split glob_subst nonomatch");
}

// ---- project levels ----
//
// A temp home with a temp repository (`home/work/api`, origin
// `git@github.com:acme/api.git`), the user level outside it, and every
// command run with no terminal: a confirmation or a hidden prompt would fail
// the command instead of waiting. Plain variables only (see the top of the
// file). Trust is recorded through the library, as a "yes" would record it.

use envy::config::Config;
use envy::project::{encode_path, identity_for_root};
use envy::trust::TrustStore;
use std::path::PathBuf;

const SHADOW: &str =
    "note: project namespace \"dev\" shadows your user-level \"dev\"; use --user for yours\n";

struct Proj {
    _tmp: TempDir,
    home: PathBuf,
    user: PathBuf,
    repo: PathBuf,
}

fn git_repo(dir: &Path, remotes: &[(&str, &str)]) {
    std::fs::create_dir_all(dir.join(".git")).unwrap();
    let mut config = String::new();
    for (name, url) in remotes {
        config.push_str(&format!("[remote \"{name}\"]\n\turl = {url}\n"));
    }
    std::fs::write(dir.join(".git/config"), config).unwrap();
}

fn project() -> Proj {
    let tmp = tempfile::tempdir().unwrap();
    // Canonical, so paths match what envy prints (`/var` is `/private/var`).
    let base = tmp.path().canonicalize().unwrap();
    let home = base.join("home");
    let user = base.join("userconf");
    let repo = home.join("work/api");
    std::fs::create_dir_all(repo.join("src/deep")).unwrap();
    std::fs::create_dir_all(&user).unwrap();
    git_repo(&repo, &[("origin", "git@github.com:acme/api.git")]);
    Proj {
        _tmp: tmp,
        home,
        user,
        repo,
    }
}

impl Proj {
    fn put_project(&self, ns: &str, text: &str) {
        std::fs::create_dir_all(self.repo.join(".envy")).unwrap();
        std::fs::write(self.repo.join(format!(".envy/{ns}.toml")), text).unwrap();
    }

    fn put_user(&self, ns: &str, text: &str) {
        std::fs::write(self.user.join(format!("{ns}.toml")), text).unwrap();
    }

    fn project_cfg(&self) -> Config {
        Config::project(
            self.repo.join(".envy"),
            self.repo.clone(),
            identity_for_root(&self.repo, &self.home),
            self.user.clone(),
        )
    }

    /// Records the file as it is now as trusted at this checkout.
    fn trust(&self, ns: &str) {
        let text = self.project_cfg().load(ns).unwrap().text();
        TrustStore::new(&self.user)
            .record(&self.repo, ns, &text)
            .unwrap();
    }

    fn trusted(&self, ns: &str) -> bool {
        let text = self.project_cfg().load(ns).unwrap().text();
        TrustStore::new(&self.user)
            .is_trusted(&self.repo, ns, &text)
            .unwrap()
    }

    fn env(&self, cmd: &mut Command, cwd: &Path) {
        cmd.env("PATH", path_with_envy())
            .env("ENVY_CONFIG_DIR", &self.user)
            .env("HOME", &self.home)
            .env_remove("ENVY_ACTIVE")
            .env_remove("ENVY_VARS")
            .env_remove("ENVY_EVAL")
            .current_dir(cwd);
    }

    /// `script` in zsh with the shell function loaded, run from `cwd`.
    fn zsh(&self, cwd: &Path, script: &str) -> Output {
        let mut cmd = Command::new("zsh");
        cmd.args([
            "-f",
            "-c",
            &format!("eval \"$(envy --init zsh)\"\n{script}"),
        ]);
        self.env(&mut cmd, cwd);
        detached(cmd)
    }

    /// The binary directly, run from `cwd`.
    fn envy(&self, cwd: &Path, args: &[&str]) -> Output {
        let mut cmd = Command::new(ENVY);
        cmd.args(args);
        self.env(&mut cmd, cwd);
        detached(cmd)
    }
}

const PROJECT_DEV: &str = "[vars]\nWHERE = \"project\"\nPONLY = \"p\"\n";
const USER_DEV: &str = "[vars]\nWHERE = \"user\"\n";

#[test]
fn e2e_a_project_namespace_loads_and_shadows_the_users() {
    let p = project();
    p.put_project("dev", PROJECT_DEV);
    p.trust("dev");
    let out = p.zsh(
        &p.repo,
        "envy dev\nprint -r -- \"$WHERE|$PONLY|$ENVY_ACTIVE\"\n",
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "project|p|dev\n");
    assert_eq!(stderr(&out), "");

    p.put_user("dev", USER_DEV);
    let out = p.zsh(
        &p.repo,
        r#"envy dev
print -r -- "$WHERE|$PONLY"
envy dev --user
print -r -- "$WHERE|${PONLY-unset}|$ENVY_ACTIVE"
envy dev
envy --user dev
print -r -- "$WHERE|${PONLY-unset}"
"#,
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "project|p\nuser|unset|dev\nuser|unset\n");
    // The note for each project load, none for `--user`.
    assert_eq!(stderr(&out), format!("{SHADOW}{SHADOW}"));
}

#[test]
fn e2e_a_subdirectory_finds_the_parent_project() {
    let p = project();
    p.put_project("dev", PROJECT_DEV);
    p.trust("dev");
    let out = p.zsh(
        &p.repo.join("src/deep"),
        "envy dev\nprint -r -- \"$WHERE|$ENVY_ACTIVE\"\n",
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "project|dev\n");
}

fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
}

#[test]
fn e2e_new_goes_to_the_user_level_or_the_project() {
    let p = project();
    // No `.envy` anywhere: the user level.
    let out = p.envy(&p.repo.join("src"), &["dev", "--new"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "");
    assert!(p.user.join("dev.toml").is_file());
    assert!(!p.repo.join(".envy").exists());
    assert!(!p.repo.join("src/.envy").exists());

    // `--project` from a subdirectory: at the repository root.
    let out = p.envy(&p.repo.join("src/deep"), &["dev", "--new", "--project"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "");
    let file = p.repo.join(".envy/dev.toml");
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "");
    assert!(!p.repo.join("src/deep/.envy").exists());
    // Shared, not private: at least rw for the owner, nothing beyond 0644.
    let m = mode(&file);
    assert!(m & 0o600 == 0o600 && m & !0o644 == 0, "{m:o}");
    let m = mode(&p.repo.join(".envy"));
    assert!(m & 0o700 == 0o700 && m & !0o755 == 0, "{m:o}");
    let err = stderr(&out);
    assert!(err.contains("created") && err.contains("\"dev\""), "{err}");
    // Its trust was recorded: it loads with no confirmation.
    assert!(p.trusted("dev"));
    let out = p.zsh(
        &p.repo.join("src"),
        "envy dev\nprint -r -- \"$ENVY_ACTIVE\"\n",
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "dev\n");
    assert_eq!(stderr(&out), SHADOW);

    // Now that `.envy` exists, a plain `--new` goes there; `--user` does not.
    let out = p.envy(&p.repo, &["web", "--new"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(p.repo.join(".envy/web.toml").is_file());
    assert!(!p.user.join("web.toml").exists());
    let out = p.envy(&p.repo, &["mine", "--new", "--user"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(p.user.join("mine.toml").is_file());
    assert!(!p.repo.join(".envy/mine.toml").exists());
}

#[test]
fn e2e_new_project_in_the_home_directory_is_refused() {
    let p = project();
    let out = p.envy(&p.home, &["dev", "--new", "--project"]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(stdout(&out), "");
    assert!(stderr(&out).contains("home directory"), "{}", stderr(&out));
    assert!(!p.home.join(".envy").exists());
    assert!(!p.user.join("dev.toml").exists());
}

#[test]
fn e2e_an_untrusted_project_namespace_needs_a_terminal() {
    let p = project();
    p.put_project("dev", PROJECT_DEV);
    p.put_user("dev", USER_DEV);
    let out = p.zsh(
        &p.repo,
        "envy dev || print -r -- \"failed:$?\"\nprint -r -- \"${WHERE-unset}|${ENVY_ACTIVE-unset}\"\n",
    );
    assert_eq!(stdout(&out), "failed:1\nunset|unset\n");
    let err = stderr(&out);
    assert!(err.contains("needs a terminal to review"), "{err}");
    assert!(!err.contains("\"project\""), "{err}");
    // The binary itself: exit 1 and nothing at all on stdout.
    let mut cmd = Command::new(ENVY);
    cmd.arg("dev");
    p.env(&mut cmd, &p.repo);
    cmd.env("ENVY_EVAL", "1");
    let out = detached(cmd);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(stdout(&out), "");
    assert!(
        stderr(&out).contains("needs a terminal to review"),
        "{}",
        stderr(&out)
    );
    assert!(!p.trusted("dev"));
    // A changed file is untrusted again.
    p.trust("dev");
    p.put_project("dev", "[vars]\nWHERE = \"changed\"\n");
    let out = p.zsh(&p.repo, "envy dev\nprint -r -- \"${WHERE-unset}\"\n");
    assert_eq!(stdout(&out), "unset\n");
    assert!(
        stderr(&out).contains("needs a terminal"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn e2e_a_corrupt_project_file_fails_closed() {
    let p = project();
    p.put_project("dev", "this is [not toml");
    p.put_user("dev", USER_DEV);
    let out = p.zsh(
        &p.repo,
        "envy dev || print -r -- \"failed:$?\"\nprint -r -- \"${WHERE-unset}|${ENVY_ACTIVE-unset}\"\n",
    );
    assert_eq!(stdout(&out), "failed:1\nunset|unset\n");
    let err = stderr(&out);
    let file = p.repo.join(".envy/dev.toml").display().to_string();
    assert!(err.contains(&file) && err.contains("invalid TOML"), "{err}");
    // `--user` still reaches the user's own.
    let out = p.zsh(&p.repo, "envy dev --user\nprint -r -- \"$WHERE\"\n");
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "user\n");
}

#[test]
fn e2e_listing_shows_both_levels_and_the_source() {
    let p = project();
    p.put_project("dev", PROJECT_DEV);
    p.put_project("ci", "");
    p.put_user("dev", USER_DEV);
    p.put_user("mine", "");
    p.trust("dev");
    let envy_dir = encode_path(&p.repo.join(".envy"));
    let listing = |dev: &str| {
        format!("project: {envy_dir}\n  ci\n{dev} dev\nuser:\n  dev (shadowed)\n  mine\n")
    };
    let out = p.envy(&p.repo, &["--list"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), listing(" "));
    assert_eq!(stderr(&out), "");

    let out = p.envy(&p.repo, &["dev", "--list"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(
        stdout(&out),
        format!(
            "namespace: dev\nsource: project ({envy_dir}/dev.toml)\n\nWHERE  \"project\"\nPONLY  \"p\"\n"
        )
    );
    assert_eq!(stderr(&out), SHADOW);
    let out = p.envy(&p.repo, &["dev", "--list", "--user"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(
        stdout(&out),
        "namespace: dev\nsource: user\n\nWHERE  \"user\"\n"
    );
    assert_eq!(stderr(&out), "");

    // Through the shell function, with the project's `dev` active.
    let out = p.zsh(&p.repo, "envy dev\nenvy\n");
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), listing("*"));

    // Outside the project only the user level shows, as before.
    let out = p.envy(&p.home, &["--list"]);
    assert_eq!(stdout(&out), "  dev\n  mine\n");
}

#[test]
fn e2e_new_like_an_unknown_namespace_creates_nothing() {
    let p = project();
    p.put_project("dev", PROJECT_DEV);
    for (cwd, extra) in [
        (&p.repo, &[][..]),
        (&p.repo, &["--user"][..]),
        (&p.home, &[][..]),
    ] {
        let mut args = vec!["fresh", "--new", "--like", "bogus"];
        args.extend_from_slice(extra);
        let out = p.envy(cwd, &args);
        assert_eq!(out.status.code(), Some(1), "{args:?}");
        assert_eq!(stdout(&out), "", "{args:?}");
        let err = stderr(&out);
        assert!(err.contains("\"bogus\""), "{args:?}: {err}");
        assert!(!p.repo.join(".envy/fresh.toml").exists(), "{args:?}");
        assert!(!p.user.join("fresh.toml").exists(), "{args:?}");
    }
    // `--like` resolves the source with the same rule: the project's `dev`.
    p.trust("dev");
    let out = p.envy(&p.repo, &["copy", "--new", "--like", "dev"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(
        std::fs::read_to_string(p.repo.join(".envy/copy.toml")).unwrap(),
        PROJECT_DEV
    );
}

#[test]
fn e2e_rm_on_a_project_namespace_needs_a_terminal_to_confirm() {
    let p = project();
    p.put_project("dev", PROJECT_DEV);
    let out = p.envy(&p.repo, &["dev", "--rm"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(p.repo.join(".envy/dev.toml").is_file());
}

#[test]
fn e2e_forks_share_the_upstream_identity_and_dotfiles_do_not_leak() {
    let p = project();
    let fork = p.home.join("forks/api");
    let other = p.home.join("other/api");
    git_repo(
        &fork,
        &[
            ("origin", "git@github.com:me/api.git"),
            ("upstream", "https://github.com/acme/api.git"),
        ],
    );
    git_repo(
        &other,
        &[
            ("origin", "ssh://git@gitlab.example.com/someone/else.git"),
            ("upstream", "git@github.com:Acme/API.git"),
        ],
    );
    let id = identity_for_root(&p.repo, &p.home);
    assert_eq!(id, "acme/api");
    assert_eq!(identity_for_root(&fork, &p.home), id);
    assert_eq!(identity_for_root(&other, &p.home), id);

    // A dotfiles repository at home lends nothing to a folder under it.
    git_repo(&p.home, &[("origin", "git@github.com:me/dotfiles.git")]);
    let loose = p.home.join("loose");
    std::fs::create_dir_all(loose.join("sub")).unwrap();
    assert_eq!(identity_for_root(&loose, &p.home), "~/loose");
    let out = p.envy(&loose.join("sub"), &["dev", "--new", "--project"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(loose.join("sub/.envy/dev.toml").is_file());
    assert!(!p.home.join(".envy").exists());
}
