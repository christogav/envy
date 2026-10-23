use std::fmt;

/// A secret value. Its `Debug` output is always redacted and it has no
/// `Display`, so it cannot leak through logging or formatting by accident.
pub struct Secret(String);

impl Secret {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    /// The only way to read the underlying value; call it only at the point
    /// the value is genuinely needed.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_debug_is_redacted() {
        assert_eq!(format!("{:?}", Secret::new("hunter2".into())), "[REDACTED]");

        #[derive(Debug)]
        #[allow(dead_code)]
        struct Holder {
            token: Secret,
        }
        let holder = Holder {
            token: Secret::new("hunter2".into()),
        };
        let printed = format!("{holder:?} {holder:#?}");
        assert!(!printed.contains("hunter2"));
        assert!(printed.contains("[REDACTED]"));
    }

    #[test]
    fn expose_returns_the_value() {
        assert_eq!(Secret::new("hunter2".into()).expose(), "hunter2");
    }
}
