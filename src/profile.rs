//! Profile storage management: directory, paths, name validation, locking,
//! atomic writes, listing, and deletion.
//!
//! Profiles live at `~/.envpouch/profiles/<name>.envpouch`. Writes use
//! temp-file + rename atomic replacement; on unix, directory mode is 0700
//! and file mode is 0600. Mutating commands hold an exclusive advisory lock
//! on a stable sidecar path (`<name>.envpouch.lock`) across their whole
//! read-modify-write window so concurrent updates queue up (or fail with a
//! clear "busy" error) instead of silently overwriting each other.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::crypto;

const PROFILE_EXT: &str = "envpouch";

/// Profile name validation: prevents path traversal and keeps filenames safe.
pub fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("profile name cannot be empty");
    }
    if name.len() > 64 {
        bail!("profile name too long (max 64 bytes)");
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        bail!("profile name may only contain letters, digits, '-' and '_'");
    }
    Ok(())
}

/// Base storage directory: `$ENVPOUCH_HOME` when set (ops: containers, service
/// accounts, multi-instance isolation), otherwise `~/.envpouch`.
pub fn base_dir() -> Result<PathBuf> {
    match std::env::var_os("ENVPOUCH_HOME") {
        Some(h) if !h.is_empty() => Ok(PathBuf::from(h)),
        _ => {
            let home = dirs::home_dir().context(
                "cannot determine home directory (set ENVPOUCH_HOME to an absolute path to override)",
            )?;
            Ok(home.join(".envpouch"))
        }
    }
}

pub fn profiles_dir() -> Result<PathBuf> {
    let dir = base_dir()?.join("profiles");
    fs::create_dir_all(&dir)
        .with_context(|| format!("failed to create directory: {}", dir.display()))?;
    #[cfg(unix)]
    set_permissions(&dir, 0o700)?;
    Ok(dir)
}

fn profile_path(name: &str) -> Result<PathBuf> {
    validate_name(name)?;
    Ok(profiles_dir()?.join(format!("{name}.{PROFILE_EXT}")))
}

/// Exclusive-lock timeout for read-modify-write commands: long enough to
/// serialize back-to-back updates, short enough that a stuck concurrent
/// process surfaces as a clear error instead of a hang.
const LOCK_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(unix)]
const LOCK_POLL: Duration = Duration::from_millis(50);

/// Held for the whole read-modify-write window of one profile (read → modify
/// → atomic replace). Dropping it releases the lock.
///
/// The lock lives on a stable sidecar path (`<name>.envpouch.lock`), not on
/// the profile file itself: writes replace the file via rename, so a lock on
/// the file's inode would silently stop protecting the name after the first
/// write. Leftover 0-byte lock files are normal and ignored by `list`.
#[derive(Debug)]
pub struct ProfileGuard {
    _file: fs::File,
}

/// Acquire the profile's exclusive lock, polling up to `timeout`.
pub fn try_lock(name: &str, timeout: Duration) -> Result<ProfileGuard> {
    let lock_path = profile_path(name)?.with_extension(format!("{PROFILE_EXT}.lock"));
    try_lock_at(&lock_path, timeout)
}

/// Exclusive lock over an explicit lock path (unit-testable without
/// ENVPOUCH_HOME).
pub fn try_lock_at(lock_path: &Path, timeout: Duration) -> Result<ProfileGuard> {
    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(lock_path)
            .with_context(|| format!("failed to open lock file: {}", lock_path.display()))?
    };
    #[cfg(not(unix))]
    let file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path)
        .with_context(|| format!("failed to open lock file: {}", lock_path.display()))?;

    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        let deadline = std::time::Instant::now() + timeout;
        loop {
            // flock, not fcntl record locks: flock is per open file
            // description, so it also conflicts within one process and is
            // released by close/exit — exactly the semantics wanted here.
            let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if rc == 0 {
                return Ok(ProfileGuard { _file: file });
            }
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EWOULDBLOCK) {
                return Err(err)
                    .with_context(|| format!("failed to lock: {}", lock_path.display()));
            }
            if std::time::Instant::now() >= deadline {
                bail!(
                    "profile is busy: {} is locked by another envp process",
                    lock_path.display()
                );
            }
            std::thread::sleep(LOCK_POLL);
        }
    }
    #[cfg(not(unix))]
    {
        // Windows has no flock in libc; concurrent-modification protection is
        // unix-only (noted in the README).
        let _ = timeout;
        Ok(ProfileGuard { _file: file })
    }
}

/// Lock used by every mutating command.
pub(crate) fn lock_profile(name: &str) -> Result<ProfileGuard> {
    try_lock(name, LOCK_TIMEOUT)
}

pub fn exists(name: &str) -> Result<bool> {
    Ok(profile_path(name)?.exists())
}

#[cfg(unix)]
fn set_permissions(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .with_context(|| format!("failed to set file permissions: {}", path.display()))
}

/// Create a file that is owner-only from its first byte on unix — no brief
/// wide-permission window between create and chmod.
pub(crate) fn create_private(path: &Path) -> std::io::Result<fs::File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
    }
    #[cfg(not(unix))]
    {
        fs::File::create(path)
    }
}

/// Best-effort fsync of a directory after rename/delete: the rename itself is
/// atomic, but the directory entry is not durable until it reaches disk —
/// without this, a crash can roll the name back to the previous file (e.g.
/// after `passwd`, the old password would work again). Failure only warns:
/// atomicity is the hard guarantee, durability the best effort.
pub(crate) fn sync_dir_best_effort(dir: &Path) {
    #[cfg(unix)]
    if let Err(e) = fs::File::open(dir).and_then(|d| d.sync_all()) {
        eprintln!("warning: could not fsync directory {}: {e}", dir.display());
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
}

/// Atomically write a profile (temp file + rename; mode 0600 on unix from
/// creation onward, file and directory fsynced).
pub fn write(name: &str, blob: &[u8]) -> Result<()> {
    let path = profile_path(name)?;
    // Unique per-process temp name: two concurrent envp processes writing
    // the same profile must not clobber each other's temp file (review fix)
    let tmp = path.with_extension(format!("{PROFILE_EXT}.{}.tmp", std::process::id()));
    {
        let mut f = create_private(&tmp)
            .with_context(|| format!("failed to create temp file: {}", tmp.display()))?;
        f.write_all(blob)
            .and_then(|_| f.sync_all())
            .with_context(|| format!("failed to write temp file: {}", tmp.display()))?;
    }
    fs::rename(&tmp, &path)
        .with_context(|| format!("failed to replace profile file: {}", path.display()))?;
    if let Some(dir) = path.parent() {
        sync_dir_best_effort(dir);
    }
    Ok(())
}

pub fn read(name: &str) -> Result<Vec<u8>> {
    let path = profile_path(name)?;
    if !path.exists() {
        bail!("profile '{name}' does not exist (see `envp list`)");
    }
    fs::read(&path).with_context(|| format!("failed to read profile: {}", path.display()))
}

/// Rename a profile file in place (same directory, atomic on unix). The
/// destination must not exist — `fs::rename` would silently overwrite it.
pub fn rename(old_name: &str, new_name: &str) -> Result<()> {
    let from = profile_path(old_name)?;
    let to = profile_path(new_name)?;
    if !from.exists() {
        bail!("profile '{old_name}' does not exist (see `envp list`)");
    }
    if to.exists() {
        bail!("profile '{new_name}' already exists (see `envp list`)");
    }
    fs::rename(&from, &to).with_context(|| {
        format!(
            "failed to rename profile: {} -> {}",
            from.display(),
            to.display()
        )
    })?;
    if let Some(dir) = to.parent() {
        sync_dir_best_effort(dir);
    }
    Ok(())
}

pub fn delete(name: &str) -> Result<()> {
    let path = profile_path(name)?;
    if !path.exists() {
        bail!("profile '{name}' does not exist (see `envp list`)");
    }
    fs::remove_file(&path)
        .with_context(|| format!("failed to delete profile file: {}", path.display()))?;
    if let Some(dir) = path.parent() {
        sync_dir_best_effort(dir);
    }
    Ok(())
}

#[derive(Debug)]
pub struct ProfileMeta {
    pub name: String,
    pub var_count: u32,
    pub updated_at: u64,
    /// File corrupted (header validation failed)
    pub corrupted: bool,
}

/// List plaintext metadata of all profiles (sorted by name, no password needed).
pub fn list() -> Result<Vec<ProfileMeta>> {
    list_in(&profiles_dir()?)
}

/// Listing over an explicit directory (unit-testable without ENVPOUCH_HOME).
fn list_in(dir: &Path) -> Result<Vec<ProfileMeta>> {
    sweep_stale_temp_files(dir);
    let mut out = Vec::new();
    let entries = fs::read_dir(dir)
        .with_context(|| format!("failed to read directory: {}", dir.display()))?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some(PROFILE_EXT) {
            continue;
        }
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();
        // A single corrupted file must not fail the whole listing; mark it instead
        let meta = fs::read(&path)
            .with_context(|| format!("failed to read profile: {}", path.display()))
            .and_then(|data| crypto::read_meta(&data));
        match meta {
            Ok(meta) => out.push(ProfileMeta {
                name,
                var_count: meta.var_count,
                updated_at: meta.updated_at,
                corrupted: false,
            }),
            Err(_) => out.push(ProfileMeta {
                name,
                var_count: 0,
                updated_at: 0,
                corrupted: true,
            }),
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

/// Best-effort sweep of leftover `<name>.envpouch.<pid>.tmp` files from runs
/// killed between temp-file creation and rename. Only removes files older
/// than an hour so a concurrent write in progress is never disturbed
/// (production hardening: crash leftovers must not accumulate forever).
fn sweep_stale_temp_files(dir: &Path) {
    const STALE_AFTER: std::time::Duration = std::time::Duration::from_secs(3600);
    if let Ok(entries) = fs::read_dir(dir) {
        for e in entries.flatten() {
            let p = e.path();
            if p.extension().and_then(|s| s.to_str()) != Some("tmp") {
                continue;
            }
            let old_enough = e
                .metadata()
                .and_then(|m| m.modified())
                .map(|t| t.elapsed().unwrap_or_default() > STALE_AFTER)
                .unwrap_or(false);
            if old_enough {
                let _ = fs::remove_file(&p);
            }
        }
    }
}

/// Directory for `edit`'s plaintext temp files: under the envpouch base
/// (mode 0700 on unix) instead of the shared system temp dir. Leftovers from
/// older versions in the system temp dir are still swept (see
/// `commands::cleanup_edit_leftovers`).
pub fn edit_dir() -> Result<PathBuf> {
    let dir = base_dir()?.join("tmp");
    fs::create_dir_all(&dir)
        .with_context(|| format!("failed to create directory: {}", dir.display()))?;
    #[cfg(unix)]
    set_permissions(&dir, 0o700)?;
    Ok(dir)
}

/// Write a sensitive file (mode 0600 on unix from creation, so there is no
/// brief wide-permission window).
pub fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut f =
        create_private(path).with_context(|| format!("cannot write file: {}", path.display()))?;
    f.write_all(bytes)
        .and_then(|_| f.sync_all())
        .with_context(|| format!("failed to write file: {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_validation() {
        assert!(validate_name("dev").is_ok());
        assert!(validate_name("prod-1").is_ok());
        assert!(validate_name("my_profile").is_ok());
        assert!(validate_name("").is_err());
        assert!(validate_name("../evil").is_err());
        assert!(validate_name("a/b").is_err());
        assert!(validate_name("a b").is_err());
        assert!(validate_name(&"x".repeat(65)).is_err());
    }

    #[test]
    fn write_private_file_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.env");
        write_private_file(&path, b"A=1\n").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"A=1\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    /// flock is per open file description: a second lock on the same path
    /// conflicts even within one process, and dropping the guard releases it.
    /// (unix only — on Windows the lock is a no-op.)
    #[cfg(unix)]
    #[test]
    fn try_lock_at_is_exclusive_and_released() {
        let dir = tempfile::tempdir().unwrap();
        let lock = dir.path().join("svc.envpouch.lock");
        let wait = Duration::from_millis(50);

        let g1 = try_lock_at(&lock, wait).unwrap();
        let err = try_lock_at(&lock, wait).unwrap_err();
        assert!(err.to_string().contains("busy"), "{err}");
        drop(g1);
        let g2 = try_lock_at(&lock, wait).unwrap();
        drop(g2);
    }

    #[cfg(unix)]
    #[test]
    fn lock_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let lock = dir.path().join("svc.envpouch.lock");
        let _g = try_lock_at(&lock, Duration::from_millis(50)).unwrap();
        assert_eq!(
            fs::metadata(&lock).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    /// `list` shows only profile files: lock sidecars, stale temps and
    /// unrelated files are invisible, and a corrupt profile is flagged
    /// instead of failing the listing.
    #[test]
    fn list_in_ignores_lock_and_temp_files_and_flags_corruption() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.envpouch"), b"garbage").unwrap();
        std::fs::write(dir.path().join("a.envpouch.lock"), b"").unwrap();
        std::fs::write(dir.path().join("a.envpouch.999.tmp"), b"").unwrap();
        std::fs::write(dir.path().join("notes.txt"), b"").unwrap();

        let out = list_in(dir.path()).unwrap();
        assert_eq!(out.len(), 1, "{out:?}");
        assert_eq!(out[0].name, "a");
        assert!(out[0].corrupted);
    }

    /// edit_dir() is 0700 under the base dir so plaintext temp files never
    /// sit in the shared system temp directory.
    #[test]
    fn edit_dir_is_private() {
        let guard = crate::testutil::lock_env();
        let dir = tempfile::tempdir().unwrap();
        crate::testutil::set_envpouch_home(dir.path());
        let edit = edit_dir().unwrap();
        assert_eq!(edit.parent(), Some(dir.path()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&edit).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        crate::testutil::clear_envpouch_home();
        drop(guard);
    }
}
