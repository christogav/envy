/// Wraps `value` in single quotes for safe use in a POSIX/zsh shell,
/// writing each embedded `'` as `'\''`.
pub fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn quotes_simple_values() {
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
        assert_eq!(shell_quote(""), "''");
    }

    #[test]
    fn quoted_value_round_trips_through_zsh() {
        for v in [
            "a'b", "$HOME", "`id`", "\"q\"", "a\nb", "\\\\", "-n", "!x", "",
        ] {
            let out = Command::new("zsh")
                .arg("-c")
                .arg(format!("print -rn -- {}", shell_quote(v)))
                .output()
                .expect("run zsh");
            assert_eq!(out.stdout, v.as_bytes(), "value {v:?}");
        }
    }
}
