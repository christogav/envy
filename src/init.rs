//! The zsh integration printed by `envy --init zsh`.

/// The `envy` shell function. A child process cannot change its parent
/// shell's environment, so activation works by `eval`-ing the binary's stdout.
///
/// Design points, each one load-bearing:
/// - `emulate -L zsh` normalises options for the call; `unsetopt xtrace`
///   stops `set -x` from echoing the evaluated exports (which contain secrets).
/// - Every command word is written `\command`, `\builtin ...`: the backslash
///   stops aliases the user defined before loading this from replacing them.
/// - The evaluated call carries `ENVY_EVAL=1` as a prefix assignment, which
///   reaches only that one process (never the shell's environment). Without
///   it the binary refuses to print export lines, so a script that runs it
///   with stdout sent to a file cannot write secrets there.
/// - Only a single non-flag argument (a namespace) or exactly `--off` is
///   evaluated. Everything else (`envy`, `envy --help`, `envy --init zsh`,
///   `envy work --edit`, `envy work --secret A B`, ...) runs the binary directly
///   so its output is shown.
/// - The output is evaluated straight from the command substitution: never
///   stored in a variable or a file.
/// - If the binary fails, its stdout is empty, so the substitution yields
///   `return 1`: the function fails (`envy bogus && deploy` stops) while the
///   binary's stderr still reaches the user. Exports are evaluated only on
///   success, because the binary prints nothing to stdout on failure.
pub fn zsh_function() -> &'static str {
    r#"envy() {
  \builtin emulate -L zsh
  \builtin unsetopt xtrace
  if [[ $# -eq 1 && ( $1 == --off || $1 != -* ) ]]; then
    \builtin eval "$(ENVY_EVAL=1 \command envy "$@" || \builtin print -r -- 'return 1')"
  else
    \command envy "$@"
  fi
}
"#
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn function_is_hardened_and_does_not_store_output() {
        let f = zsh_function();
        assert!(
            f.starts_with("envy() {\n  \\builtin emulate -L zsh\n  \\builtin unsetopt xtrace\n")
        );
        assert!(
            f.contains("\\builtin eval \"$(ENVY_EVAL=1 \\command envy \"$@\" || \\builtin print -r -- 'return 1')\""),
            "{f}"
        );
        assert!(!f.contains("=$(") && !f.contains('>'), "{f}");
    }

    #[test]
    fn list_invocations_are_not_evaluated() {
        // The function evaluates only one non-flag argument or exactly --off.
        let f = zsh_function();
        assert!(
            f.contains("[[ $# -eq 1 && ( $1 == --off || $1 != -* ) ]]"),
            "{f}"
        );
        for args in [
            &["--list"][..],
            &["--ls"],
            &["dev", "--list"],
            &["dev", "--ls"],
        ] {
            let evaluated = args.len() == 1 && (args[0] == "--off" || !args[0].starts_with('-'));
            assert!(!evaluated, "{args:?}");
        }
    }

    #[test]
    fn marker_is_only_on_the_evaluated_call_and_every_command_escapes_aliases() {
        let f = zsh_function();
        assert_eq!(f.matches("ENVY_EVAL=1").count(), 1, "{f}");
        for word in ["command", "builtin", "print", "eval", "emulate", "unsetopt"] {
            for (i, _) in f.match_indices(word) {
                let before = &f[..i];
                assert!(
                    before.ends_with('\\') || before.ends_with("\\builtin "),
                    "unescaped {word} in {f}"
                );
            }
        }
    }
}
