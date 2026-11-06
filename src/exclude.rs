//! Hardcoded exclusion list for `import --from-env` (spec §5.1).
//!
//! Without filtering, importing the current environment would swallow a pile
//! of system junk and widen the leak surface (SSH session variables, etc.).

/// Exact names and prefix wildcards (`LC_*` — trailing `*`).
const PATTERNS: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "PWD",
    "OLDPWD",
    "TMPDIR",
    "LANG",
    "LC_*",
    "TERM",
    "TERM_*",
    "SSH_*",
    "GPG_TTY",
    "XDG_*",
    "DISPLAY",
    "DBUS_*",
    "COLORTERM",
    "__CF*",
    "SECURITYSESSIONID",
    "Apple_*",
    "HIST*",
    "ZSH*",
    "ZDOTDIR",
    "PAGER",
    "LESS",
    "MANPAGER",
    "EDITOR",
    "VISUAL",
    "COLUMNS",
    "LINES",
];

/// Exact-name or prefix-wildcard matching.
pub fn is_excluded(key: &str) -> bool {
    PATTERNS.iter().any(|p| match p.strip_suffix('*') {
        Some(prefix) => key.starts_with(prefix),
        None => key == *p,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_names_excluded() {
        for key in [
            "PATH",
            "HOME",
            "USER",
            "SHELL",
            "PWD",
            "TMPDIR",
            "GPG_TTY",
            "SECURITYSESSIONID",
            "PAGER",
            "LESS",
            "MANPAGER",
            "EDITOR",
            "VISUAL",
            "COLUMNS",
            "LINES",
            "DISPLAY",
            "COLORTERM",
        ] {
            assert!(is_excluded(key), "{key} should be excluded");
        }
    }

    #[test]
    fn prefix_wildcards_excluded() {
        for key in [
            "LC_ALL",
            "LC_CTYPE",
            "TERM_PROGRAM",
            "TERM_PROGRAM_VERSION",
            "SSH_AUTH_SOCK",
            "SSH_CONNECTION",
            "XDG_DATA_HOME",
            "DBUS_SESSION_BUS_ADDRESS",
            "__CFBundleIdentifier",
            "__CF_USER_TEXT_ENCODING",
            "Apple_PubSub_Socket_Render",
            "HISTFILE",
            "HISTSIZE",
            "ZSH_VERSION",
            "ZDOTDIR",
        ] {
            assert!(is_excluded(key), "{key} should be excluded");
        }
    }

    #[test]
    fn ordinary_keys_not_excluded() {
        for key in ["FOO", "DATABASE_URL", "MY_TERM", "PAGERX", "LC", "SSH"] {
            assert!(!is_excluded(key), "{key} should NOT be excluded");
        }
    }
}
