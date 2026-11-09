//! Optional audit trail (off by default; enable with `ENVPOUCH_AUDIT=1`).
//!
//! Records one line per invocation: timestamp, subcommand,
//! profile name, and outcome — **never variable keys or values** (spec:
//! smallest possible secret propagation surface). Written best-effort: a
//! failed audit write warns on stderr but never fails the command itself.
//!
//! `run` on unix writes `exec` immediately before replacing its image. On
//! success no second line follows; on exec failure envp additionally
//! records its own nonzero `exit=` code, so `exec` directly followed by
//! `exit=N` means the target never started.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::Context;

use crate::profile;

/// Rotate audit.log to audit.log.1 (one generation kept) when it grows past
/// this size, so an enabled audit trail cannot grow a long-lived service's
/// disk without bound. Best-effort, like everything in this module.
const MAX_AUDIT_BYTES: u64 = 10 * 1024 * 1024;

/// Rename `log` to `<log>.1` when it is at least `max_bytes`. Concurrent envp
/// processes may race here; a lost race (the file is already gone) is ignored
/// — the append in the caller proceeds either way.
fn rotate_if_large(log: &Path, max_bytes: u64) -> bool {
    let large = std::fs::metadata(log)
        .map(|m| m.len() >= max_bytes)
        .unwrap_or(false);
    if !large {
        return false;
    }
    let mut rotated = log.as_os_str().to_os_string();
    rotated.push(".1");
    std::fs::rename(log, PathBuf::from(rotated)).is_ok()
}

/// Treat `ENVPOUCH_AUDIT` as enabled unless unset, empty, "0" or "false".
fn enabled() -> bool {
    match std::env::var_os("ENVPOUCH_AUDIT") {
        Some(v) => {
            let v = v.to_string_lossy().to_ascii_lowercase();
            !v.is_empty() && v != "0" && v != "false"
        }
        None => false,
    }
}

/// Append one audit line to `<base>/audit.log`. Best-effort by design.
pub fn record(action: &str, profile: Option<&str>, outcome: &str) {
    if !enabled() {
        return;
    }
    let result = (|| -> anyhow::Result<()> {
        let log = profile::base_dir()?.join("audit.log");
        rotate_if_large(&log, MAX_AUDIT_BYTES);
        let ts = chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%z");
        let line = format!("{ts}\t{action}\t{}\t{outcome}\n", profile.unwrap_or("-"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .mode(0o600)
                .open(&log)
                .with_context(|| format!("cannot open audit log: {}", log.display()))?;
            f.write_all(line.as_bytes())
                .with_context(|| format!("failed to write audit log: {}", log.display()))?;
        }
        #[cfg(not(unix))]
        {
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log)
                .with_context(|| format!("cannot open audit log: {}", log.display()))?;
            f.write_all(line.as_bytes())
                .with_context(|| format!("failed to write audit log: {}", log.display()))?;
        }
        Ok(())
    })();
    if let Err(e) = result {
        eprintln!("warning: audit log write failed: {e:#}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Edition 2024 makes env mutation unsafe; tests touching ENVPOUCH_HOME/
    /// ENVPOUCH_AUDIT serialize on testutil's mutex (parallel tests exist).
    #[test]
    fn audit_respects_toggle_and_format() {
        let _env = crate::testutil::lock_env();
        let dir = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var("ENVPOUCH_HOME", dir.path());
            std::env::set_var("ENVPOUCH_AUDIT", "1");
        }
        record("run", Some("prod"), "exit=0");
        record("list", None, "exit=0");
        unsafe {
            std::env::set_var("ENVPOUCH_AUDIT", "0");
        }
        record("show", Some("prod"), "error"); // must NOT be recorded

        let log = std::fs::read_to_string(dir.path().join("audit.log")).unwrap();
        let lines: Vec<&str> = log.lines().collect();
        assert_eq!(lines.len(), 2, "disabled audit must not append: {log:?}");
        assert!(lines[0].contains("\trun\tprod\texit=0"), "{lines:?}");
        assert!(lines[1].ends_with("\tlist\t-\texit=0"), "{lines:?}");
        // by construction record() only receives (action, profile, outcome) —
        // 4 tab-separated fields per line, never a variable key/value column
        for line in &lines {
            assert_eq!(
                line.split('\t').count(),
                4,
                "unexpected audit shape: {line:?}"
            );
        }

        unsafe {
            std::env::remove_var("ENVPOUCH_AUDIT");
            std::env::remove_var("ENVPOUCH_HOME");
        }
    }

    #[test]
    fn audit_log_rotates_at_size_threshold() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit.log");
        std::fs::write(&log, b"0123456789").unwrap();

        assert!(!rotate_if_large(&log, 100), "below threshold: untouched");
        assert!(log.exists());

        assert!(rotate_if_large(&log, 5), "at/over threshold: rotated");
        assert!(!log.exists());
        assert_eq!(
            std::fs::read(dir.path().join("audit.log.1")).unwrap(),
            b"0123456789"
        );

        assert!(!rotate_if_large(&log, 5), "nothing left to rotate");
        // the next record() appends to a freshly created audit.log
    }
}
