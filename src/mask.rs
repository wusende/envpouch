//! Masking rule for secret values, shared across commands (spec §6.1).
//!
//! ```text
//! ""        => "(empty)"
//! len <= 4  => "****"
//! other     => "****" + last 4 characters
//! ```

/// Mask a secret value for display. Operates on `char`s so multi-byte
/// characters are counted and sliced correctly.
pub fn mask(v: &str) -> String {
    let count = v.chars().count();
    if count == 0 {
        return "(empty)".to_string();
    }
    if count <= 4 {
        return "****".to_string();
    }
    let tail: String = v.chars().skip(count - 4).collect();
    format!("****{tail}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_rules() {
        assert_eq!(mask(""), "(empty)");
        assert_eq!(mask("a"), "****");
        assert_eq!(mask("abcd"), "****");
        assert_eq!(mask("abcde"), "****bcde");
        assert_eq!(mask("1"), "****"); // M0 acceptance: A=1 -> "A = ****"
        assert_eq!(mask("super-secret-value"), "****alue");
    }

    #[test]
    fn mask_multibyte() {
        // 7 chars -> last 4 chars, no panics on char boundaries
        assert_eq!(mask("中文值测试中文"), "****测试中文");
        assert_eq!(mask("ünïcodé"), "****codé");
    }
}
