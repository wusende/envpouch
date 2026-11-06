//! Masking rule for secret values, shared across commands (spec §6.1).
//!
//! ```text
//! ""        => "(empty)"
//! len < 8   => "****"
//! other     => "****" + last 4 characters
//! ```

/// Mask a secret value for display. Operates on `char`s so multi-byte
/// characters are counted and sliced correctly.
///
/// The GitHub-style "last 4" convention assumes long secrets; on a 5-char
/// value it would leak 80%. Values shorter than 8 characters reveal nothing,
/// so the visible tail is never more than half of the secret.
pub fn mask(v: &str) -> String {
    let count = v.chars().count();
    if count == 0 {
        return "(empty)".to_string();
    }
    if count < 8 {
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
        assert_eq!(mask("abcde"), "****");
        assert_eq!(mask("1234567"), "****");
        assert_eq!(mask("12345678"), "****5678");
        assert_eq!(mask("1"), "****"); // M0 acceptance: A=1 -> "A = ****"
        assert_eq!(mask("super-secret-value"), "****alue");
    }

    #[test]
    fn mask_multibyte() {
        // 7 chars -> fully masked; no panics on char boundaries either way
        assert_eq!(mask("中文值测试中文"), "****");
        assert_eq!(mask("ünïcodé"), "****");
        assert_eq!(mask("中文值测试中文字"), "****试中文字");
    }
}
