//! File-based unlock cache: caches a profile's *derived key* (never the
//! password) with an expiry timestamp, so decrypting commands skip the
//! password prompt — and the Argon2 pass — within the TTL window set by
//! `envp unlock`. `envp lock` removes the entry immediately.
//!
//! Storage: `<profiles dir>/<name>.envpouch.unlock` — a sidecar of the
//! profile (same 0700 directory as the profile and its `.envpouch.lock`
//! sibling), invisible to `list`, mode 0600 on unix from creation, written
//! atomically (temp + rename + best-effort dir fsync) so a crash cannot
//! leave a half-written entry behind.
//!
//! Why the derived key and not the password (the removed keychain cache
//! stored the password): the OS keychain guards secrets at rest; a plain
//! file must not hold anything more than necessary. The 32-byte derived key
//! can only decrypt this one profile under its current salt — exactly the
//! capability `unlock` grants, nothing more. A `passwd` or profile re-import
//! changes the salt, and the mismatch is caught against the profile header
//! before any decryption attempt.
//!
//! File format (v1):
//! ```text
//! magic "ENVULOCK"(8B) | version(1B) | expiry unix secs(8B, LE)
//! | salt(16B) | argon2 params m/t/p(12B, LE) | key(32B)
//! ```

use std::fs;
use std::io::Write as _;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use zeroize::Zeroizing;

use crate::crypto::{self, DerivedKey};
use crate::profile;

pub const MAGIC: &[u8; 8] = b"ENVULOCK";
pub const FORMAT_VERSION: u8 = 1;

/// Default unlock window when `--ttl` is omitted.
pub const DEFAULT_TTL_SECS: u64 = 900;
/// Upper bound for the TTL: keeps `now + ttl` overflow-free and bounds how
/// long a cached key can live unattended (carried over from the removed
/// keychain cache).
pub const MAX_TTL_SECS: u64 = 30 * 24 * 3600; // 30 days

const EXPIRY_LEN: usize = 8;
/// magic + version + expiry + salt + params(m/t/p) + key
const ENTRY_LEN: usize = MAGIC.len() + 1 + EXPIRY_LEN + crypto::SALT_LEN + 12 + crypto::KEY_LEN;

/// Sidecar path for `name`'s cached key. `validate_name` first, so a
/// profile-name-shaped argument can never escape the profiles directory.
fn cache_path(name: &str) -> Result<PathBuf> {
    profile::validate_name(name)?;
    Ok(profile::profiles_dir()?.join(format!("{name}.envpouch.unlock")))
}

/// Store `derived` for `name`, expiring `ttl_secs` from now. The TTL is
/// validated before any I/O: usage errors fail fast and leave no side effects.
pub fn store(name: &str, derived: &DerivedKey, ttl_secs: u64) -> Result<()> {
    if ttl_secs == 0 || ttl_secs > MAX_TTL_SECS {
        bail!("--ttl must be between 1 and {MAX_TTL_SECS} seconds (30 days)");
    }
    let expiry = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the unix epoch")?
        .as_secs()
        .checked_add(ttl_secs)
        .context("expiry timestamp overflow")?;

    let params = derived.params();
    let entry = encode_entry(expiry, *derived.salt(), *params, *derived.key_bytes());
    debug_assert_eq!(entry.len(), ENTRY_LEN);

    let path = cache_path(name)?;
    // Same atomic-write discipline as profiles: unique per-process temp name,
    // 0600 from creation, fsync, rename, best-effort dir fsync.
    let tmp = path.with_extension(format!("unlock.{}.tmp", std::process::id()));
    {
        let mut f = profile::create_private(&tmp)
            .with_context(|| format!("failed to create temp file: {}", tmp.display()))?;
        f.write_all(&entry)
            .and_then(|_| f.sync_all())
            .with_context(|| format!("failed to write temp file: {}", tmp.display()))?;
    }
    fs::rename(&tmp, &path)
        .with_context(|| format!("failed to write unlock cache entry: {}", path.display()))?;
    if let Some(dir) = path.parent() {
        profile::sync_dir_best_effort(dir);
    }
    Ok(())
}

/// Load the cached key for `name`, or None on miss, expiry, or corruption.
/// Expired and corrupt entries are removed, so stale state never outlives
/// the command that noticed it.
pub fn lookup(name: &str) -> Option<DerivedKey> {
    let path = cache_path(name).ok()?;
    let raw = Zeroizing::new(fs::read(&path).ok()?);
    let entry = match parse_entry(&raw) {
        Ok(entry) => entry,
        Err(_) => {
            // Torn write, bitrot, or hand-editing: drop it, fall back to prompting
            let _ = fs::remove_file(&path);
            return None;
        }
    };
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    if now >= entry.expiry {
        let _ = fs::remove_file(&path);
        return None;
    }
    DerivedKey::from_parts(*entry.key, entry.salt, entry.params).ok()
}

/// Remove the cached entry for `name`. A missing entry counts as success
/// (`envp lock` is idempotent).
pub fn clear(name: &str) -> Result<()> {
    let path = cache_path(name)?;
    match fs::remove_file(&path) {
        Ok(()) => {
            if let Some(dir) = path.parent() {
                profile::sync_dir_best_effort(dir);
            }
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e)
            .with_context(|| format!("failed to remove unlock cache entry: {}", path.display())),
    }
}

#[derive(Debug)]
pub(crate) struct CachedEntry {
    expiry: u64,
    salt: [u8; crypto::SALT_LEN],
    params: crypto::KdfParams,
    /// Zeroized on drop, like every other copy of the key material.
    key: Zeroizing<[u8; crypto::KEY_LEN]>,
}

/// Serialize an entry (v1). Crate-visible so the fuzz tests can build valid
/// entries to mutate.
pub(crate) fn encode_entry(
    expiry: u64,
    salt: [u8; crypto::SALT_LEN],
    params: crypto::KdfParams,
    key: [u8; crypto::KEY_LEN],
) -> Zeroizing<Vec<u8>> {
    let mut entry = Vec::with_capacity(ENTRY_LEN);
    entry.extend_from_slice(MAGIC);
    entry.push(FORMAT_VERSION);
    entry.extend_from_slice(&expiry.to_le_bytes());
    entry.extend_from_slice(&salt);
    entry.extend_from_slice(&params.m_cost.to_le_bytes());
    entry.extend_from_slice(&params.t_cost.to_le_bytes());
    entry.extend_from_slice(&params.p_cost.to_le_bytes());
    entry.extend_from_slice(&key);
    // The buffer holds raw key material: zero it when it goes out of scope.
    Zeroizing::new(entry)
}

/// Parse an entry. Crate-visible for the fuzz tests: any input must yield
/// Ok or a clean Err, never a panic.
pub(crate) fn parse_entry(raw: &[u8]) -> Result<CachedEntry> {
    if raw.len() != ENTRY_LEN {
        bail!("unlock cache entry has wrong size");
    }
    if &raw[..MAGIC.len()] != MAGIC {
        bail!("not a valid unlock cache entry (magic mismatch)");
    }
    if raw[MAGIC.len()] != FORMAT_VERSION {
        bail!(
            "unsupported unlock cache version: {} (supported: {})",
            raw[MAGIC.len()],
            FORMAT_VERSION
        );
    }
    let mut off = MAGIC.len() + 1;
    let expiry = u64::from_le_bytes(raw[off..off + EXPIRY_LEN].try_into().unwrap());
    off += EXPIRY_LEN;
    let salt = raw[off..off + crypto::SALT_LEN].try_into().unwrap();
    off += crypto::SALT_LEN;
    let m_cost = u32::from_le_bytes(raw[off..off + 4].try_into().unwrap());
    off += 4;
    let t_cost = u32::from_le_bytes(raw[off..off + 4].try_into().unwrap());
    off += 4;
    let p_cost = u32::from_le_bytes(raw[off..off + 4].try_into().unwrap());
    off += 4;
    let key = raw[off..off + crypto::KEY_LEN].try_into().unwrap();
    Ok(CachedEntry {
        expiry,
        salt,
        params: crypto::KdfParams {
            m_cost,
            t_cost,
            p_cost,
        },
        key: Zeroizing::new(key),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil;
    use std::sync::MutexGuard;

    /// Hold the env lock for the whole test body (edition 2024: set_var is
    /// unsafe and parallel tests must not observe each other's env).
    fn fresh_home() -> (MutexGuard<'static, ()>, tempfile::TempDir) {
        let guard = testutil::lock_env();
        let dir = tempfile::tempdir().unwrap();
        testutil::set_envpouch_home(dir.path());
        (guard, dir)
    }

    #[test]
    fn roundtrip_store_lookup_clear() {
        let (_env, _home) = fresh_home();
        let derived = DerivedKey::fresh("pw123456").unwrap();
        store("dev", &derived, DEFAULT_TTL_SECS).unwrap();

        let cached = lookup("dev").unwrap();
        assert_eq!(cached.salt(), derived.salt());
        assert_eq!(cached.params(), derived.params());

        clear("dev").unwrap();
        assert!(lookup("dev").is_none());
        testutil::clear_envpouch_home();
    }

    #[test]
    fn ttl_bounds_rejected_without_side_effects() {
        let (_env, home) = fresh_home();
        let derived = DerivedKey::fresh("pw123456").unwrap();
        for bad in [0, MAX_TTL_SECS + 1] {
            let err = store("dev", &derived, bad).unwrap_err().to_string();
            assert!(err.contains("--ttl must be between"));
            assert!(err.contains("30 days"));
        }
        // Rejected before any I/O: not even the profiles directory was created
        assert!(!home.path().join("profiles").exists());
        testutil::clear_envpouch_home();
    }

    #[test]
    fn expired_entry_is_removed_on_lookup() {
        let (_env, home) = fresh_home();
        let derived = DerivedKey::fresh("pw123456").unwrap();
        store("dev", &derived, DEFAULT_TTL_SECS).unwrap();

        // Patch the stored expiry into the past
        let path = home.path().join("profiles").join("dev.envpouch.unlock");
        let mut raw = fs::read(&path).unwrap();
        let past = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .saturating_sub(100);
        let off = MAGIC.len() + 1;
        raw[off..off + EXPIRY_LEN].copy_from_slice(&past.to_le_bytes());
        profile::write_private_file(&path, &raw).unwrap();

        assert!(lookup("dev").is_none());
        assert!(!path.exists(), "expired entry must be removed");
        testutil::clear_envpouch_home();
    }

    #[test]
    fn corrupt_entry_is_removed_on_lookup() {
        let (_env, home) = fresh_home();
        let derived = DerivedKey::fresh("pw123456").unwrap();
        store("dev", &derived, DEFAULT_TTL_SECS).unwrap();

        let path = home.path().join("profiles").join("dev.envpouch.unlock");
        profile::write_private_file(&path, b"garbage").unwrap();
        assert!(lookup("dev").is_none());
        assert!(!path.exists(), "corrupt entry must be removed");
        testutil::clear_envpouch_home();
    }

    #[test]
    fn clear_is_idempotent() {
        let (_env, _home) = fresh_home();
        clear("dev").unwrap();
        clear("dev").unwrap();
        testutil::clear_envpouch_home();
    }

    #[test]
    fn entry_rejects_unknown_version() {
        let mut raw = vec![0u8; ENTRY_LEN];
        raw[..MAGIC.len()].copy_from_slice(MAGIC);
        raw[MAGIC.len()] = 99;
        assert!(parse_entry(&raw).is_err());
    }

    #[test]
    fn entry_rejects_wrong_size_and_magic() {
        assert!(parse_entry(&[]).is_err());
        assert!(parse_entry(&[0u8; 8]).is_err());
        let mut raw = vec![0u8; ENTRY_LEN];
        raw[..MAGIC.len()].copy_from_slice(b"NOTMAGIC");
        assert!(parse_entry(&raw).is_err());
    }
}
