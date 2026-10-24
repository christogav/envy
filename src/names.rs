use anyhow::{Result, bail};

/// Every variable name starting with this is refused: envy's own settings
/// (`ENVY_CONFIG_DIR`, `ENVY_EVAL`) and shell state (`ENVY_ACTIVE`,
/// `ENVY_VARS`, `ENVY_SOURCE`) use it, and a namespace file that set one
/// could redirect envy's config and trust store or switch off its guards.
const RESERVED_PREFIX: &str = "ENVY_";

/// zsh's special parameters. Activation runs `export NAME='value'` in the
/// user's shell, and for these that is not a plain assignment: integer
/// specials (`SECONDS`, `LINES`, `UID`, ...) evaluate the value as arithmetic,
/// which can run command substitutions and echo the value in errors; array
/// and tied specials (`path`, `fpath`, `aliases`, ...) abort the whole
/// `eval`; others (`PATH`, `IFS`, `HOME`, `PS1`, ...) change how the shell
/// itself behaves.
///
/// Taken from zsh 5.9 on macOS with
/// `zsh -fc 'print -l ${(k)parameters[(R)*special*]}'`, after loading the
/// modules an interactive shell commonly has (zsh/parameter, zsh/datetime,
/// zsh/system, zsh/terminfo, zsh/termcap, zsh/mapfile, zsh/langinfo,
/// zsh/sched, zsh/watch, zsh/curses, zsh/zleparameter). Names that are not
/// identifiers (`$`, `?`, `0`, ...) are already refused by the syntax check.
/// A unit test compares this list with the local zsh.
const ZSH_SPECIALS: &[&str] = &[
    "ARGC",
    "CDPATH",
    "COLUMNS",
    "EGID",
    "EPOCHREALTIME",
    "EPOCHSECONDS",
    "EUID",
    "FIGNORE",
    "FPATH",
    "FUNCNEST",
    "GID",
    "HISTCHARS",
    "HISTCMD",
    "HISTSIZE",
    "HOME",
    "IFS",
    "KEYBOARD_HACK",
    "LANG",
    "LINENO",
    "LINES",
    "MAILPATH",
    "MANPATH",
    "MODULE_PATH",
    "NULLCMD",
    "OPTARG",
    "OPTIND",
    "PATH",
    "PPID",
    "PROMPT",
    "PROMPT2",
    "PROMPT3",
    "PROMPT4",
    "PS1",
    "PS2",
    "PS3",
    "PS4",
    "PSVAR",
    "RANDOM",
    "READNULLCMD",
    "SAVEHIST",
    "SECONDS",
    "SHLVL",
    "SPROMPT",
    "TERM",
    "TERMINFO",
    "TRY_BLOCK_ERROR",
    "TRY_BLOCK_INTERRUPT",
    "TTYIDLE",
    "UID",
    "USERNAME",
    "WATCH",
    "WORDCHARS",
    "ZCURSES_COLORS",
    "ZCURSES_COLOR_PAIRS",
    "ZSH_EVAL_CONTEXT",
    "ZSH_SUBSHELL",
    "_",
    "aliases",
    "argv",
    "builtins",
    "cdpath",
    "commands",
    "dirstack",
    "dis_aliases",
    "dis_builtins",
    "dis_functions",
    "dis_functions_source",
    "dis_galiases",
    "dis_patchars",
    "dis_reswords",
    "dis_saliases",
    "epochtime",
    "errnos",
    "fignore",
    "fpath",
    "funcfiletrace",
    "funcsourcetrace",
    "funcstack",
    "functions",
    "functions_source",
    "functrace",
    "galiases",
    "histchars",
    "history",
    "historywords",
    "jobdirs",
    "jobstates",
    "jobtexts",
    "keymaps",
    "langinfo",
    "mailpath",
    "manpath",
    "mapfile",
    "module_path",
    "modules",
    "nameddirs",
    "options",
    "parameters",
    "patchars",
    "path",
    "pipestatus",
    "prompt",
    "psvar",
    "reswords",
    "saliases",
    "status",
    "sysparams",
    "termcap",
    "terminfo",
    "userdirs",
    "usergroups",
    "watch",
    "widgets",
    "zcurses_attrs",
    "zcurses_colors",
    "zcurses_keycodes",
    "zcurses_windows",
    "zsh_eval_context",
    "zsh_scheduled_events",
];

/// Not special to zsh, but they describe the login and the shell itself, and
/// programs trust them; a namespace has no business replacing them.
const SESSION_VARS: [&str; 2] = ["SHELL", "USER"];

/// Prefixes of the dynamic loader's variables, which make every program the
/// shell starts load other code.
const LOADER_PREFIXES: [&str; 2] = ["DYLD_", "LD_"];

/// Validates a namespace name (also used for link group labels):
/// `[A-Za-z0-9][A-Za-z0-9_-]*`, 1 to 64 characters.
pub fn validate_namespace(name: &str) -> Result<()> {
    let len = name.chars().count();
    if len == 0 || len > 64 {
        bail!("invalid name {name:?}: must be 1 to 64 characters");
    }
    let mut chars = name.chars();
    let first = chars.next().expect("non-empty");
    if !first.is_ascii_alphanumeric()
        || !chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        bail!("invalid name {name:?}: must match [A-Za-z0-9][A-Za-z0-9_-]*");
    }
    Ok(())
}

/// Validates an environment variable name: a shell identifier
/// `[A-Za-z_][A-Za-z0-9_]*` that does not start with `ENVY_` (envy's own), a
/// zsh special parameter, `SHELL`/`USER`, or a dynamic loader variable.
/// Errors name the variable and the reason, never a value.
pub fn validate_var(name: &str) -> Result<()> {
    let mut chars = name.chars();
    let valid = matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
    if !valid {
        bail!("invalid variable name {name:?}: must match [A-Za-z_][A-Za-z0-9_]*");
    }
    if name.starts_with(RESERVED_PREFIX) {
        bail!(
            "variable name {name:?} is reserved by envy: the ENVY_ prefix is reserved for envy's own settings"
        );
    }
    if ZSH_SPECIALS.contains(&name) {
        bail!(
            "variable name {name:?} is a special zsh parameter: the shell gives it its own meaning, so envy cannot set it"
        );
    }
    if SESSION_VARS.contains(&name) {
        bail!(
            "variable name {name:?} is special: it describes your login shell or user, so envy cannot set it"
        );
    }
    if LOADER_PREFIXES.iter().any(|p| name.starts_with(p)) {
        bail!(
            "variable name {name:?} is reserved: DYLD_ and LD_ variables change what the dynamic loader loads into every program, so envy cannot set them"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_accepts_valid() {
        for n in ["work", "off", "new", "a-b_c1"] {
            assert!(validate_namespace(n).is_ok(), "{n}");
        }
        assert!(validate_namespace(&"a".repeat(64)).is_ok());
    }

    #[test]
    fn namespace_rejects_invalid() {
        let too_long = "a".repeat(65);
        for n in ["", "../x", "a/b", ".hidden", "-x", "a b", too_long.as_str()] {
            assert!(validate_namespace(n).is_err(), "{n:?}");
        }
    }

    #[test]
    fn var_accepts_valid() {
        for n in ["AWS_REGION", "_X"] {
            assert!(validate_var(n).is_ok(), "{n}");
        }
    }

    #[test]
    fn var_rejects_zsh_special_parameters_naming_them() {
        for n in [
            "SECONDS",
            "LINES",
            "COLUMNS",
            "HISTSIZE",
            "RANDOM",
            "UID",
            "GID",
            "EUID",
            "PATH",
            "path",
            "fpath",
            "FPATH",
            "cdpath",
            "manpath",
            "module_path",
            "mailpath",
            "psvar",
            "PSVAR",
            "IFS",
            "USERNAME",
            "HOME",
            "PS1",
            "PS4",
            "PROMPT",
            "PROMPT2",
            "prompt",
            "_",
            "argv",
            "status",
            "aliases",
            "EPOCHSECONDS",
            "SHELL",
            "TERM",
            "USER",
        ] {
            let err = validate_var(n).unwrap_err().to_string();
            assert!(err.contains(&format!("{n:?}")), "{err}");
            assert!(err.contains("special"), "{n}: {err}");
        }
    }

    #[test]
    fn var_rejects_loader_variables() {
        for n in [
            "DYLD_INSERT_LIBRARIES",
            "DYLD_LIBRARY_PATH",
            "LD_PRELOAD",
            "LD_",
        ] {
            let err = validate_var(n).unwrap_err().to_string();
            assert!(
                err.contains(&format!("{n:?}")) && err.contains("loader"),
                "{err}"
            );
        }
        // Only the prefix, and only in capitals, is reserved.
        for n in [
            "OLD_PATH",
            "dyld_x",
            "MY_LD_FLAGS",
            "http_proxy",
            "LANGUAGE",
            "Path",
        ] {
            assert!(validate_var(n).is_ok(), "{n}");
        }
    }

    /// Every special parameter the zsh on this machine knows (with the
    /// modules an interactive shell commonly loads) must be refused.
    #[test]
    fn var_rejects_every_special_parameter_of_the_local_zsh() {
        let out = std::process::Command::new("zsh")
            .args([
                "-fc",
                "zmodload zsh/parameter zsh/datetime zsh/system zsh/terminfo zsh/termcap \
                 zsh/mapfile zsh/langinfo zsh/sched zsh/watch zsh/curses 2>/dev/null; \
                 print -l ${(k)parameters[(R)*special*]}",
            ])
            .output()
            .expect("zsh runs");
        let text = String::from_utf8(out.stdout).unwrap();
        let mut checked = 0;
        for name in text.lines() {
            assert!(validate_var(name).is_err(), "{name} is accepted");
            checked += 1;
        }
        assert!(checked > 50, "{text}");
    }

    #[test]
    fn var_rejects_invalid() {
        for n in ["1A", "A-B", "", "ENVY_ACTIVE", "ENVY_VARS", "ENVY_SOURCE"] {
            assert!(validate_var(n).is_err(), "{n:?}");
        }
    }

    #[test]
    fn the_envy_prefix_is_reserved() {
        for n in [
            "ENVY_CONFIG_DIR",
            "ENVY_EVAL",
            "ENVY_ACTIVE",
            "ENVY_VARS",
            "ENVY_SOURCE",
            "ENVY_X",
            "ENVY_",
        ] {
            let err = validate_var(n).unwrap_err().to_string();
            assert_eq!(
                err,
                format!(
                    "variable name {n:?} is reserved by envy: the ENVY_ prefix is reserved for envy's own settings"
                )
            );
        }
        for ok in ["envy_x", "Envy_X", "ENVYX", "MY_ENVY_X"] {
            assert!(validate_var(ok).is_ok(), "{ok}");
        }
    }
}
