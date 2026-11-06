//! Masking rule for secret values, shared across commands (spec §6.1).
//!
//! ```text
//! ""        => "(empty)"
//! len <= 4  => "****"
//! other     => "****" + last min(4, len/2) characters
//! ```

/// Mask a secret value for display. Operates on `char`s so multi-byte
/// characters are counted and sliced correctly. At most 4 characters are
/// revealed and never more than half the value — a fixed last-4 would give
/// away 80% of a 5-character secret.
pub fn mask(v: &str) -> String {
    let count = v.chars().count();
    if count == 0 {
        return "(empty)".to_string();
    }
    if count <= 4 {
        return "****".to_string();
    }
    let reveal = 4.min(count / 2);
    let tail: String = v.chars().skip(count - reveal).collect();
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
        // never reveal more than half the value
        assert_eq!(mask("abcde"), "****de");
        assert_eq!(mask("abcdef"), "****def");
        assert_eq!(mask("abcdefgh"), "****efgh");
        assert_eq!(mask("1"), "****"); // M0 acceptance: A=1 -> "A = ****"
        assert_eq!(mask("super-secret-value"), "****alue");
    }

    #[test]
    fn mask_multibyte() {
        // 7 chars -> last 3 chars, no panics on char boundaries
        assert_eq!(mask("中文值测试中文"), "****试中文");
        assert_eq!(mask("ünïcodé"), "****odé");
    }
}
