//! Profile storage management: directory, paths, name validation, atomic
//! writes, listing, and deletion.
//!
//! Profiles live at `~/.envrun/profiles/<name>.envrun`. Writes use
//! temp-file + rename atomic replacement; on unix, directory mode is 0700
//! and file mode is 0600.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::crypto;

const PROFILE_EXT: &str = "envrun";

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

/// Base storage directory: `$ENVRUN_HOME` when set (ops: containers, service
/// accounts, multi-instance isolation), otherwise `~/.envrun`.
pub fn base_dir() -> Result<PathBuf> {
    match std::env::var_os("ENVRUN_HOME") {
        Some(h) if !h.is_empty() => Ok(PathBuf::from(h)),
        _ => {
            let home = dirs::home_dir().context(
                "cannot determine home directory (set ENVRUN_HOME to an absolute path to override)",
            )?;
            Ok(home.join(".envrun"))
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

pub fn exists(name: &str) -> Result<bool> {
    Ok(profile_path(name)?.exists())
}

#[cfg(unix)]
fn set_permissions(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .with_context(|| format!("failed to set file permissions: {}", path.display()))
}

/// Atomically write a profile (temp file + rename). Mode 0600 on unix.
pub fn write(name: &str, blob: &[u8]) -> Result<()> {
    let path = profile_path(name)?;
    // Unique per-process temp name: two concurrent envrun processes writing
    // the same profile must not clobber each other's temp file (review fix)
    let tmp = path.with_extension(format!("{PROFILE_EXT}.{}.tmp", std::process::id()));
    {
        let mut f = fs::File::create(&tmp)
            .with_context(|| format!("failed to create temp file: {}", tmp.display()))?;
        f.write_all(blob)
            .and_then(|_| f.sync_all())
            .with_context(|| format!("failed to write temp file: {}", tmp.display()))?;
    }
    #[cfg(unix)]
    set_permissions(&tmp, 0o600)?;
    fs::rename(&tmp, &path)
        .with_context(|| format!("failed to replace profile file: {}", path.display()))?;
    Ok(())
}

pub fn read(name: &str) -> Result<Vec<u8>> {
    let path = profile_path(name)?;
    if !path.exists() {
        bail!("profile '{name}' does not exist (see `envrun list`)");
    }
    fs::read(&path).with_context(|| format!("failed to read profile: {}", path.display()))
}

pub fn delete(name: &str) -> Result<()> {
    let path = profile_path(name)?;
    if !path.exists() {
        bail!("profile '{name}' does not exist (see `envrun list`)");
    }
    fs::remove_file(&path)
        .with_context(|| format!("failed to delete profile file: {}", path.display()))
}

pub struct ProfileMeta {
    pub name: String,
    pub var_count: u32,
    pub updated_at: u64,
    /// File corrupted (header validation failed)
    pub corrupted: bool,
}

/// List plaintext metadata of all profiles (sorted by name, no password needed).
pub fn list() -> Result<Vec<ProfileMeta>> {
    let dir = profiles_dir()?;
    sweep_stale_temp_files(&dir);
    let mut out = Vec::new();
    let entries = fs::read_dir(&dir)
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

/// Best-effort sweep of leftover `<name>.envrun.<pid>.tmp` files from runs
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

/// Write a sensitive file (mode 0600 on unix; permissions are tightened at
/// creation time to avoid a brief wide-permission window).
pub fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("cannot write file: {}", path.display()))?;
        f.write_all(bytes)
            .and_then(|_| f.sync_all())
            .with_context(|| format!("failed to write file: {}", path.display()))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        fs::write(path, bytes)
            .with_context(|| format!("failed to write file: {}", path.display()))?;
        Ok(())
    }
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
}
