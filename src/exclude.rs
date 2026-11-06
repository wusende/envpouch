//! Hardcoded exclusion list for `import --from-env` (spec §5.1).
//!
//! Without filtering, importing the current environment would swallow a pile
//! of system junk and widen the leak surface (SSH session variables, etc.).

/// Exact names and prefix wildcards (`LC_*` — trailing `*`). Matched
/// ASCII-case-insensitively: Windows environment names are case-preserving
/// but case-insensitive (`Path`, `ProgramFiles`, `PSModulePath`).
const PATTERNS: &[&str] = &[
    // unix session/shell basics
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
    "WAYLAND_*",
    "DBUS_*",
    "COLORTERM",
    // desktop/terminal integration
    "__CF*",
    "SECURITYSESSIONID",
    "Apple_*",
    "ITERM_*",
    "WEZTERM_*",
    "KONSOLE_*",
    "VTE_VERSION",
    "TERMINFO",
    "LS_COLORS",
    "COLORFGBG",
    "WINDOWID",
    "GNOME_*",
    "KDE_*",
    "DESKTOP_*",
    // shell state/history
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
    "SHLVL",
    "HOSTNAME",
    "MAIL",
    "MAILPATH",
    // systemd / WSL session
    "SYSTEMD_*",
    "INVOCATION_ID",
    "JOURNAL_STREAM",
    "WSL_*",
    // windows system (case-insensitive hits `Path`, `ProgramFiles(x86)`, …)
    "OS",
    "COMSPEC",
    "PATHEXT",
    "WINDIR",
    "SYSTEMDRIVE",
    "SYSTEMROOT",
    // covers ProgramData, ProgramFiles(x86), ProgramW6432, CommonProgramW6432…
    "PROGRAM*",
    "COMMONPROGRAM*",
    "NUMBER_OF_PROCESSORS",
    "PROCESSOR_*",
    "DRIVERDATA",
    "APPDATA",
    "LOCALAPPDATA",
    "USERPROFILE",
    "USERNAME",
    "USERDOMAIN*",
    "PUBLIC",
    "ALLUSERSPROFILE",
    "PSMODULEPATH",
];

/// Exact-name or prefix-wildcard matching, ASCII case-insensitive.
pub fn is_excluded(key: &str) -> bool {
    PATTERNS.iter().any(|p| match p.strip_suffix('*') {
        Some(prefix) => {
            key.len() >= prefix.len()
                && key.as_bytes()[..prefix.len()].eq_ignore_ascii_case(prefix.as_bytes())
        }
        None => key.eq_ignore_ascii_case(p),
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
            "ITERM_SESSION_ID",
            "WEZTERM_EXECUTABLE",
            "SYSTEMD_EXEC_PID",
            "PROCESSOR_ARCHITECTURE",
            "ProgramFiles(x86)",
            "CommonProgramW6432",
            "USERDOMAIN_ROAMINGPROFILE",
        ] {
            assert!(is_excluded(key), "{key} should be excluded");
        }
    }

    /// Windows env names are case-preserving but case-insensitive.
    #[test]
    fn matching_is_case_insensitive() {
        for key in [
            "Path",
            "ProgramData",
            "PSModulePath",
            "SystemRoot",
            "Username",
            "OS",
        ] {
            assert!(
                is_excluded(key),
                "{key} should be excluded (case-insensitive)"
            );
        }
    }

    #[test]
    fn windows_and_session_names_excluded() {
        for key in [
            "WINDOWID",
            "TERMINFO",
            "LS_COLORS",
            "SHLVL",
            "HOSTNAME",
            "INVOCATION_ID",
            "JOURNAL_STREAM",
            "NUMBER_OF_PROCESSORS",
            "PATHEXT",
            "DRIVERDATA",
            "APPDATA",
            "LOCALAPPDATA",
            "USERPROFILE",
            "PUBLIC",
        ] {
            assert!(is_excluded(key), "{key} should be excluded");
        }
    }

    #[test]
    fn ordinary_keys_not_excluded() {
        for key in [
            "FOO",
            "DATABASE_URL",
            "MY_TERM",
            "PAGERX",
            "LC",
            "SSH",
            "OS_",
        ] {
            assert!(!is_excluded(key), "{key} should NOT be excluded");
        }
    }
}
