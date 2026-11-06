//! OS keychain cache for profile passwords (spec §4.3, milestone M3).
//!
//! Caches the profile password itself in the OS keychain (macOS Keychain /
//! Linux Secret Service) with an expiry timestamp, so `run` (and other
//! decrypting commands) can skip the prompt within the TTL window.
//!
//! Degradation rule (spec §4.3): any keychain failure must fall back to
//! manual password entry, never hard-fail the command. This includes the
//! macOS pitfall where a rebuilt binary or SSH session makes a keychain
//! call pop a GUI authorization prompt that blocks forever in headless
//! environments — every keychain call therefore runs on a helper thread
//! with a short timeout; on timeout we degrade to prompting instead of
//! deadlocking.

use std::sync::mpsc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use keyring::Entry;
use zeroize::Zeroizing;

const SERVICE: &str = "envpouch";

/// Upper bound for cache TTL: prevents `now + ttl` arithmetic overflow and
/// keeps a cached plaintext password from living arbitrarily long in the
/// keychain (production hardening).
pub const MAX_TTL_SECS: u64 = 30 * 24 * 3600; // 30 days

/// How long a single keychain call may block before we assume a GUI
/// authorization prompt is waiting in a headless session (spec §4.3).
const KEYCHAIN_TIMEOUT: Duration = Duration::from_secs(3);

fn entry(name: &str) -> Result<Entry, keyring::Error> {
    Entry::new(SERVICE, name)
}

/// Run `f` on a helper thread with a hard timeout. Returns None on timeout;
/// the helper thread stays blocked (it dies with the process) but the caller
/// proceeds — degrading instead of deadlocking.
fn with_timeout<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Option<T> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(KEYCHAIN_TIMEOUT).ok()
}

/// Store `password` for `name`, expiring `ttl_secs` from now.
/// Stored format: "<expiry_unix_secs>\n<password>".
///
/// If the keychain call times out, we tell the user it failed — so the helper
/// thread aborts before starting the write if the caller already gave up
/// (closes the common slow-keychain case; a write already mid-flight when the
/// timeout fires cannot be recalled, which is harmless: the password is the
/// verified one).
pub fn store(name: &str, password: &str, ttl_secs: u64) -> Result<()> {
    if ttl_secs == 0 || ttl_secs > MAX_TTL_SECS {
        anyhow::bail!(
            "--ttl must be between 1 and {} seconds (30 days)",
            MAX_TTL_SECS
        );
    }
    let expiry = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the unix epoch")?
        .as_secs()
        + ttl_secs;
    let name = name.to_string();
    let payload = Zeroizing::new(format!("{expiry}\n{password}"));
    let abandoned = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = abandoned.clone();
    match with_timeout(move || {
        if flag.load(std::sync::atomic::Ordering::Relaxed) {
            return None; // caller already reported failure — do not write late
        }
        Some(entry(&name).and_then(|e| e.set_password(&payload)))
    }) {
        Some(Some(Ok(()))) => Ok(()),
        Some(Some(Err(e))) => Err(anyhow::Error::from(e)),
        Some(None) => Ok(()), // abandoned before write; reported via timeout below
        None => {
            abandoned.store(true, std::sync::atomic::Ordering::Relaxed);
            anyhow::bail!(
                "keychain access timed out (GUI authorization prompt?); type the password manually instead"
            )
        }
    }
}

/// Look up a non-expired cached password. Returns None (and best-effort
/// clears the stale entry) on miss, expiry, timeout, or any keychain error —
/// callers fall back to prompting.
pub fn lookup(name: &str) -> Option<Zeroizing<String>> {
    let name = name.to_string();
    let result = with_timeout(move || {
        let raw = Zeroizing::new(entry(&name).ok()?.get_password().ok()?);
        let (expiry, password) = raw.split_once('\n')?;
        let expiry: u64 = expiry.parse().ok()?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
        if now >= expiry {
            let _ = clear(&name);
            return None;
        }
        Some(password.to_string())
    });
    match result {
        Some(Some(password)) => Some(Zeroizing::new(password)),
        _ => None,
    }
}

/// Remove the cached entry. Missing entries count as success.
pub fn clear(name: &str) -> Result<()> {
    let name = name.to_string();
    match with_timeout(move || entry(&name).and_then(|e| e.delete_credential())) {
        Some(Ok(())) => Ok(()),
        Some(Err(keyring::Error::NoEntry)) => Ok(()),
        Some(Err(e)) => Err(anyhow::Error::from(e)),
        None => anyhow::bail!("keychain access timed out; try again or remove the entry manually"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ttl_bounds_rejected_without_keychain_access() {
        // These fail before any keychain call, so they are safe to assert here
        let err = store("ttl-test", "pw", 0).unwrap_err().to_string();
        assert!(err.contains("--ttl must be between"));
        let err = store("ttl-test", "pw", MAX_TTL_SECS + 1)
            .unwrap_err()
            .to_string();
        assert!(err.contains("--ttl must be between"));
        assert!(err.contains("30 days"));
    }
}
