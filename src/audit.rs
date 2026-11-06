//! Optional audit trail (off by default; enable with `ENVPOUCH_AUDIT=1`).
//!
//! Records one line per decrypting invocation: timestamp, subcommand,
//! profile name, and outcome — **never variable keys or values** (spec:
//! smallest possible secret propagation surface). Written best-effort: a
//! failed audit write warns on stderr but never fails the command itself.
//!
//! `run` on unix writes `exec` immediately before replacing its image. On
//! success no second line follows; on exec failure envp additionally
//! records its own nonzero `exit=` code, so `exec` directly followed by
//! `exit=N` means the target never started.

use std::io::Write;

use anyhow::Context;

use crate::profile;

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

    /// Edition 2024 makes env mutation unsafe; tests run in parallel threads,
    /// but no other test touches ENVPOUCH_AUDIT/ENVPOUCH_HOME.
    #[test]
    fn audit_respects_toggle_and_format() {
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
}
