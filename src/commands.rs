//! Implementations of the subcommands.

use std::fmt::Write as _;
use std::io::Write as IoWrite;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use zeroize::Zeroizing;

use crate::crypto::{self, FileMeta};
use crate::envfile::{self, EnvVars};
use crate::exclude;
use crate::mask;
use crate::profile;
#[cfg(unix)]
use crate::{keycache, signals};

/// Passwords are always held in Zeroizing<String> and wiped on drop.
fn prompt_password(prompt: &str) -> Result<Zeroizing<String>> {
    let pw = rpassword::prompt_password(prompt).context("failed to read password")?;
    Ok(Zeroizing::new(pw))
}

/// Unified password acquisition (spec §4.3): --password-stdin first, then the
/// OS keychain cache, then the interactive prompt. Every decrypting command
/// goes through this so `unlock` benefits all of them.
fn obtain_password(name: &str, password_stdin: bool, prompt: &str) -> Result<Zeroizing<String>> {
    if password_stdin {
        return read_password_stdin();
    }
    if let Some(pw) = keycache::lookup(name) {
        return Ok(pw);
    }
    prompt_password(prompt)
}

/// Interactive password setup: type twice to confirm; on mismatch, retry at
/// most once before giving up (spec §5.1). Prints the lost-password warning.
fn prompt_new_password() -> Result<Zeroizing<String>> {
    eprintln!("warning: if you lose this password, the profile cannot be recovered");
    const MAX_ATTEMPTS: usize = 2;
    for _attempt in 1..=MAX_ATTEMPTS {
        let pw = prompt_password("Set a new password: ")?;
        if pw.as_str().len() < 8 {
            eprintln!("error: password too short (minimum 8 characters)");
            continue;
        }
        let confirm = prompt_password("Confirm new password: ")?;
        if pw.as_str() == confirm.as_str() {
            return Ok(pw);
        }
        eprintln!("error: passwords do not match");
    }
    bail!("password setup failed after {MAX_ATTEMPTS} attempts");
}

fn now_unix() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time is before the Unix epoch")?
        .as_secs())
}

/// Write bytes to stdout. Rust ignores SIGPIPE, so a closed pipe (`envrun
/// export dev | head`) surfaces as EPIPE here; treat it as a clean exit
/// instead of panicking (review fix).
fn out_bytes(bytes: &[u8]) -> Result<()> {
    let mut out = std::io::stdout();
    match out.write_all(bytes).and_then(|()| out.flush()) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        Err(e) => Err(e).context("failed to write to stdout"),
    }
}

fn out_line(s: impl std::fmt::Display) -> Result<()> {
    out_bytes(format!("{s}\n").as_bytes())
}

/// Parse a comma-separated key list into trimmed, non-empty names.
fn parse_key_list(spec: &str) -> Vec<String> {
    spec.split(',')
        .map(|k| k.trim().to_string())
        .filter(|k| !k.is_empty())
        .collect()
}

/// Entry point for `import` (spec §5.1): exactly one of --from / --from-env.
pub fn import_command(
    name: &str,
    from: Option<PathBuf>,
    from_env: bool,
    only: Option<String>,
    except: Option<String>,
    merge: bool,
) -> Result<()> {
    match (from, from_env) {
        (Some(f), false) => import_from_file(name, &f, merge),
        (None, true) => import_from_env(name, only, except, merge),
        (Some(_), true) => bail!("--from and --from-env are mutually exclusive"),
        (None, false) => bail!("nothing to import: specify --from <file> or --from-env"),
    }
}

fn import_from_file(name: &str, from: &Path, merge: bool) -> Result<()> {
    if !from.exists() {
        bail!("file not found: {}", from.display());
    }
    let new_vars = EnvVars::parse_file(from)?;
    require_valid_keys(&new_vars)?;
    import_vars(name, new_vars, merge, 0)
}

/// `import --from-env`: grab variables from the current process environment.
/// Default behavior applies the hardcoded exclusion list (spec §5.1);
/// `--only` bypasses it entirely, `--except` adds to it.
fn import_from_env(
    name: &str,
    only: Option<String>,
    except: Option<String>,
    merge: bool,
) -> Result<()> {
    let only_list = only.as_ref().map(|s| parse_key_list(s));
    let except_list = except.as_ref().map(|s| parse_key_list(s));

    let mut map = std::collections::BTreeMap::new();
    let mut skipped = 0usize;
    for (k, v) in std::env::vars_os() {
        let (k, v) = match (k.into_string(), v.into_string()) {
            (Ok(k), Ok(v)) => (k, v),
            // Non-UTF-8 entries cannot be stored in a .env profile
            _ => {
                skipped += 1;
                continue;
            }
        };
        let take = if let Some(only) = &only_list {
            only.contains(&k)
        } else if let Some(except) = &except_list {
            !exclude::is_excluded(&k) && !except.contains(&k)
        } else {
            !exclude::is_excluded(&k)
        };
        if !take {
            skipped += 1;
            continue;
        }
        map.insert(k, v);
    }
    let vars = EnvVars::from_map(map);
    require_valid_keys(&vars)?;
    import_vars(name, vars, merge, skipped)
}

/// Fail fast (spec §4.4/§5.1): report every invalid key, then reject the
/// whole import.
fn require_valid_keys(vars: &EnvVars) -> Result<()> {
    let invalid: Vec<String> = vars
        .iter()
        .filter_map(|(k, v)| envfile::validate_key(k, v).err().map(|e| e.to_string()))
        .collect();
    if invalid.is_empty() {
        return Ok(());
    }
    // Every invalid key goes into the error chain itself (not just stderr), so
    // scripts capturing the final error line see the full list (spec §5.1)
    bail!(
        "import rejected, {} invalid variable(s):\n  {}",
        invalid.len(),
        invalid.join("\n  ")
    );
}

/// Shared import pipeline. `skipped` counts variables excluded by the
/// exclusion list (--from-env); always 0 for --from.
fn import_vars(name: &str, new_vars: EnvVars, merge: bool, skipped: usize) -> Result<()> {
    let existed = profile::exists(name)?;
    if existed && !merge {
        bail!("profile '{name}' already exists (use --merge to merge into it)");
    }
    let password = if existed {
        // Merging must verify the existing password; it stays unchanged
        obtain_password(
            name,
            false,
            &format!("Enter existing password for profile '{name}': "),
        )?
    } else {
        prompt_new_password()?
    };

    let vars = if existed {
        let blob = profile::read(name)?;
        let decrypted = crypto::decrypt(&blob, password.as_str())?;
        let existing = EnvVars::from_json(&decrypted.plaintext)?;
        let mut merged = existing;
        let (added, updated) = merged.merge(new_vars);
        eprintln!("Merge result: {added} added, {updated} updated");
        merged
    } else {
        new_vars
    };

    if vars.is_empty() {
        eprintln!("warning: no environment variables were imported");
    }

    let payload = vars.to_json()?;
    let meta = FileMeta {
        var_count: vars.len() as u32,
        updated_at: now_unix()?,
    };
    let blob = crypto::encrypt(&payload, password.as_str(), meta)?;
    profile::write(name, &blob)?;

    let mut out = String::new();
    let _ = writeln!(
        out,
        "Profile '{name}' written: {} variables ({skipped} skipped by exclusion list)",
        vars.len()
    );
    for (k, _) in vars.iter() {
        let _ = writeln!(out, "{k}");
    }
    out_bytes(out.as_bytes())?;

    // Spec §5.1 pitfall: dotenvy expands $VAR in double-quoted/bare values
    if vars.iter().any(|(_, v)| v.contains('$')) {
        eprintln!(
            "note: values containing $ are expanded under dotenvy semantics; use single quotes in .env files"
        );
    }
    Ok(())
}

/// `envrun show <name> [--reveal]`
pub fn show(name: &str, reveal: bool) -> Result<()> {
    profile::validate_name(name)?;
    let blob = profile::read(name)?;
    let password = obtain_password(
        name,
        false,
        &format!("Enter password for profile '{name}': "),
    )?;
    let decrypted = crypto::decrypt(&blob, password.as_str())?;
    let vars = EnvVars::from_json(&decrypted.plaintext)?;

    if reveal {
        eprintln!("warning: output contains plaintext secrets");
        out_bytes(vars.to_env_text().as_bytes())?;
    } else {
        let mut out = String::new();
        for (k, v) in vars.iter() {
            let _ = writeln!(out, "{k} = {}", mask::mask(v));
        }
        out_bytes(out.as_bytes())?;
    }
    Ok(())
}

/// `envrun export <name> [-o <file>]`
pub fn export(name: &str, output: Option<PathBuf>) -> Result<()> {
    profile::validate_name(name)?;
    let blob = profile::read(name)?;
    let password = obtain_password(
        name,
        false,
        &format!("Enter password for profile '{name}': "),
    )?;
    let decrypted = crypto::decrypt(&blob, password.as_str())?;
    let vars = EnvVars::from_json(&decrypted.plaintext)?;
    let text = vars.to_env_text();

    match output {
        Some(p) => {
            profile::write_private_file(&p, text.as_bytes())?;
            eprintln!(
                "warning: plaintext file written to {} - do not commit; delete when no longer needed",
                p.display()
            );
        }
        None => {
            eprintln!("warning: output contains plaintext secrets");
            out_bytes(text.as_bytes())?;
        }
    }
    Ok(())
}

/// `envrun edit <name>` (spec §5.3): decrypt into a 0600 temp file, open
/// $EDITOR (default vi), parse back, re-encrypt atomically.
pub fn edit(name: &str) -> Result<()> {
    profile::validate_name(name)?;
    cleanup_edit_leftovers();
    let blob = profile::read(name)?;
    let password = obtain_password(
        name,
        false,
        &format!("Enter password for profile '{name}': "),
    )?;
    let decrypted = crypto::decrypt(&blob, password.as_str())?;
    let vars = EnvVars::from_json(&decrypted.plaintext)?;

    let editor = std::env::var("EDITOR").unwrap_or_else(|_| "vi".to_string());
    let tmp = tempfile::Builder::new()
        .prefix("envrun-edit-")
        .suffix(".env")
        .rand_bytes(6)
        .tempfile_in(std::env::temp_dir())
        .context("failed to create temp file for editing")?;
    // tempfile crate creates the file with mode 0600 on unix
    {
        let mut f = tmp.as_file();
        f.write_all(vars.to_env_text().as_bytes())
            .and_then(|()| f.sync_all())
            .context("failed to write temp file for editing")?;
    }
    let path = tmp.path().to_path_buf();
    eprintln!(
        "warning: plaintext exists temporarily at {} while editing",
        path.display()
    );

    let status = Command::new(&editor)
        .arg(&path)
        .status()
        .with_context(|| format!("failed to launch editor: {editor}"))?;
    if !status.success() {
        bail!(
            "editor exited with {}; profile not modified",
            status.code().unwrap_or(-1)
        );
    }

    let new_vars = EnvVars::parse_file(&path)?;
    require_valid_keys(&new_vars)?;
    let payload = new_vars.to_json()?;
    let meta = FileMeta {
        var_count: new_vars.len() as u32,
        updated_at: now_unix()?,
    };
    let new_blob = crypto::encrypt(&payload, password.as_str(), meta)?;
    profile::write(name, &new_blob)?;

    if tmp.close().is_err() {
        eprintln!("warning: could not delete temp file {}", path.display());
    }
    out_line(format!(
        "Profile '{name}' updated: {} variables",
        new_vars.len()
    ))
}

/// Best-effort cleanup of leftover `envrun-edit-*` temp files from killed
/// sessions (spec §5.3). Not a data incident, but do not accumulate them.
fn cleanup_edit_leftovers() {
    let dir = std::env::temp_dir();
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for e in entries.flatten() {
            let p = e.path();
            if let Some(n) = p.file_name().and_then(|s| s.to_str())
                && n.starts_with("envrun-edit-")
            {
                let _ = std::fs::remove_file(&p);
            }
        }
    }
}

/// `envrun fpm-snippet <name>` (spec §4.7): emit php-fpm pool `env[...]`
/// lines on stdout.
pub fn fpm_snippet(name: &str) -> Result<()> {
    profile::validate_name(name)?;
    let blob = profile::read(name)?;
    let password = obtain_password(
        name,
        false,
        &format!("Enter password for profile '{name}': "),
    )?;
    let decrypted = crypto::decrypt(&blob, password.as_str())?;
    let vars = EnvVars::from_json(&decrypted.plaintext)?;

    eprintln!("warning: output contains plaintext secrets - do not paste into logs or commit it");
    let mut out = String::new();
    let mut dollar_keys = Vec::new();
    for (k, v) in vars.iter() {
        if v.contains('\n') {
            eprintln!(
                "warning: '{k}' contains a newline and cannot be written to pool config; consider clear_env=no for fpm"
            );
            continue;
        }
        if v.contains('$') {
            dollar_keys.push(k.clone());
        }
        let _ = writeln!(out, "{}", fpm_line(k, v));
    }
    out.push_str("; If pool uses clear_env=yes (default), also add env[PATH] = ...\n");
    out_bytes(out.as_bytes())?;

    if !dollar_keys.is_empty() {
        eprintln!(
            "note: values of {} contain $ which has variable-reference semantics in fpm config; review manually",
            dollar_keys.join(", ")
        );
    }
    eprintln!("warning: output contains plaintext secrets - do not paste into logs or commit it");
    Ok(())
}

/// One `env[KEY] = value` line (spec §4.7): values containing `\`, `"` or
/// `;`, `#` are double-quoted with `\` and `"` escaped.
pub(crate) fn fpm_line(key: &str, value: &str) -> String {
    if !value.contains(['\\', '"', ';', '#']) {
        return format!("env[{key}] = {value}");
    }
    let mut v = String::with_capacity(value.len() + 2);
    v.push('"');
    for c in value.chars() {
        match c {
            '\\' => v.push_str("\\\\"),
            '"' => v.push_str("\\\""),
            _ => v.push(c),
        }
    }
    v.push('"');
    format!("env[{key}] = {v}")
}

/// `envrun diff <a> <b>` (spec §9 M4): show key-level differences with
/// masked values.
pub fn diff(name_a: &str, name_b: &str) -> Result<()> {
    profile::validate_name(name_a)?;
    profile::validate_name(name_b)?;
    if name_a == name_b {
        bail!("cannot diff a profile with itself");
    }
    let blob_a = profile::read(name_a)?;
    let pw_a = obtain_password(
        name_a,
        false,
        &format!("Enter password for profile '{name_a}': "),
    )?;
    let vars_a = EnvVars::from_json(&crypto::decrypt(&blob_a, pw_a.as_str())?.plaintext)?;

    let blob_b = profile::read(name_b)?;
    let pw_b = obtain_password(
        name_b,
        false,
        &format!("Enter password for profile '{name_b}': "),
    )?;
    let vars_b = EnvVars::from_json(&crypto::decrypt(&blob_b, pw_b.as_str())?.plaintext)?;

    let mut only_a: Vec<&str> = Vec::new();
    let mut only_b: Vec<&str> = Vec::new();
    let mut changed = Vec::new();
    let mut same = 0usize;
    for (k, va) in vars_a.iter() {
        match vars_b.iter().find(|(kb, _)| *kb == k) {
            None => only_a.push(k.as_str()),
            Some((_, vb)) => {
                if va == vb {
                    same += 1;
                } else {
                    changed.push(format!("{k}: {} -> {}", mask::mask(va), mask::mask(vb)));
                }
            }
        }
    }
    for (k, _) in vars_b.iter() {
        if vars_a.iter().all(|(ka, _)| ka != k) {
            only_b.push(k.as_str());
        }
    }

    let mut out = String::new();
    if !only_a.is_empty() {
        let _ = writeln!(
            out,
            "Only in '{name_a}' ({}): {}",
            only_a.len(),
            only_a.join(" ")
        );
    }
    if !only_b.is_empty() {
        let _ = writeln!(
            out,
            "Only in '{name_b}' ({}): {}",
            only_b.len(),
            only_b.join(" ")
        );
    }
    for c in &changed {
        let _ = writeln!(out, "Changed {c}");
    }
    if only_a.is_empty() && only_b.is_empty() && changed.is_empty() {
        let _ = writeln!(
            out,
            "Profiles '{name_a}' and '{name_b}' are identical ({same} variables)"
        );
    } else {
        let _ = writeln!(out, "{same} variable(s) identical");
    }
    out_bytes(out.as_bytes())
}

/// `envrun run <name> [--clean] [--dry-run] [--detach] [--password-stdin] -- <cmd> [args...]`
///
/// Returns the child exit code (spec §3): child exit code 1:1, 127 not found,
/// 126 no execute permission, 128+N killed by signal N, 1 for envrun errors.
///
/// Process model (spec §4.1, do not change): the child runs in its own
/// process group (`process_group(0)`), envrun catches terminal signals and
/// forwards them — the same model as `timeout`/`docker run`. No `sh -c`
/// wrapping: the target program is exec'd directly.
#[allow(clippy::too_many_arguments)]
pub fn run(
    name: &str,
    clean: bool,
    dry_run: bool,
    detach: bool,
    password_stdin: bool,
    command: &[String],
) -> Result<i32> {
    profile::validate_name(name)?;
    if command.is_empty() {
        bail!("missing command to execute");
    }
    let blob = profile::read(name)?;
    let password = obtain_password(
        name,
        password_stdin,
        &format!("Enter password for profile '{name}': "),
    )?;
    let decrypted = crypto::decrypt(&blob, password.as_str())?;
    let vars = EnvVars::from_json(&decrypted.plaintext)?;

    let env_map = build_env(clean, &vars);

    if dry_run {
        return dry_run_report(command, clean, &vars, &env_map);
    }

    let mut cmd = Command::new(&command[0]);
    cmd.args(&command[1..]);
    // Deterministic env: clear, then set exactly the merged result
    // (overlay = full parent env + profile overrides; clean = base + profile)
    cmd.env_clear();
    for (k, v) in &env_map {
        cmd.env(k, v);
    }

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // Own process group: terminal-generated signals reach envrun only and
        // are forwarded explicitly (spec §4.1-§4.2).
        cmd.process_group(0);
        // Best-effort: disable core dumps for the child to shrink the leak
        // surface (spec §1, §4.6). setrlimit is async-signal-safe, allowed
        // inside pre_exec; ignore failures (rare, e.g. hard resource limit).
        unsafe {
            cmd.pre_exec(|| {
                // BSD/macOS take a struct pointer; Linux takes the value
                #[cfg(target_os = "macos")]
                {
                    let lim = libc::rlimit {
                        rlim_cur: 0,
                        rlim_max: 0,
                    };
                    libc::setrlimit(libc::RLIMIT_CORE, &lim);
                }
                #[cfg(not(target_os = "macos"))]
                {
                    libc::setrlimit(libc::RLIMIT_CORE, 0);
                }
                Ok(())
            });
        }
        if detach {
            // Spec §4.5 (P2): nohup-style detachment — new session, envrun
            // exits immediately after spawn. setsid is async-signal-safe.
            unsafe {
                cmd.pre_exec(|| {
                    libc::setsid();
                    Ok(())
                });
            }
        }
    }

    // Install forwarders after password entry so password stdin reads are
    // undisturbed and no signal gets lost before the child exists. Not needed
    // for --detach (envrun exits immediately).
    if !detach {
        #[cfg(unix)]
        signals::install();
    }

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("error: command not found: {}", command[0]);
            return Ok(127);
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("error: permission denied: {}", command[0]);
            return Ok(126);
        }
        Err(e) if e.raw_os_error() == Some(libc::E2BIG) => {
            eprintln!("error: environment too large (ARG_MAX limit)");
            return Ok(1);
        }
        Err(e) => {
            return Err(e).with_context(|| format!("failed to spawn: {}", command[0]));
        }
    };

    if detach {
        let pid = child.id();
        drop(child);
        // The orphaned child is reaped by launchd/init; do not wait (spec §4.5)
        return out_line(format!(
            "Detached: pid {pid} (envrun exits; stdout/stderr still go to this terminal)"
        ))
        .map(|()| 0);
    }
    let pid = child.id() as i32;

    // Polling loop (spec §4.2): 10 ms interval, negligible CPU cost.
    // SIGTERM does NOT reach the child automatically (the terminal only
    // signals the foreground group), so explicit forwarding is mandatory.
    // On SIGTSTP envrun keeps running and polls (spec §4.2).
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(exit_code_of(&status));
        }
        let sig = signals::take();
        if sig != 0 {
            unsafe {
                // Forward to the child's process group (covers descendants it
                // spawned into the group); fall back to the single pid when
                // the group no longer exists (e.g. child setsid'd away).
                if libc::kill(-pid, sig) != 0 {
                    libc::kill(pid, sig);
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

/// Minimal base environment for `--clean` (spec §4.4): taken from the current
/// environment, missing entries are skipped (never invented). TERM must be
/// kept or TTY programs lose all colors.
const CLEAN_BASE_KEYS: [&str; 7] = ["PATH", "HOME", "TMPDIR", "USER", "LOGNAME", "SHELL", "TERM"];

/// Final child environment:
/// - overlay (default): full current env, same-name keys overridden by profile;
/// - clean: fixed base keys + profile variables, nothing else.
fn build_env(
    clean: bool,
    vars: &EnvVars,
) -> std::collections::BTreeMap<std::ffi::OsString, std::ffi::OsString> {
    use std::collections::BTreeMap;
    use std::ffi::OsString;

    let mut env: BTreeMap<OsString, OsString> = BTreeMap::new();
    if clean {
        for k in CLEAN_BASE_KEYS {
            if let Some(v) = std::env::var_os(k) {
                env.insert(k.into(), v);
            }
        }
    } else {
        for (k, v) in std::env::vars_os() {
            env.insert(k, v);
        }
    }
    for (k, v) in vars.iter() {
        env.insert(k.into(), v.into());
    }
    env
}

/// Quote one argv element for the `--dry-run` display line (readability only).
pub(crate) fn shell_quote(a: &str) -> String {
    let is_safe = !a.is_empty()
        && a.bytes().all(|b| {
            matches!(
                b,
                b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'-' | b'.' | b'/'
                    | b':' | b'=' | b'@' | b'%' | b'+' | b',' | b'~'
            )
        });
    if is_safe {
        a.to_string()
    } else {
        format!("'{}'", a.replace('\'', "'\\''"))
    }
}

/// `--dry-run` report (spec §6.2): stdout only, never any values.
fn dry_run_report(
    command: &[String],
    clean: bool,
    vars: &EnvVars,
    env_map: &std::collections::BTreeMap<std::ffi::OsString, std::ffi::OsString>,
) -> Result<i32> {
    use std::os::unix::ffi::OsStrExt;

    let quoted: Vec<String> = command.iter().map(|a| shell_quote(a)).collect();
    let mut out = String::new();
    let _ = writeln!(out, "Command: {}", quoted.join(" "));
    let _ = writeln!(out, "Mode: {}", if clean { "clean" } else { "overlay" });
    let keys: Vec<&str> = vars.iter().map(|(k, _)| k.as_str()).collect();
    let _ = writeln!(
        out,
        "Injected variables ({}): {}",
        keys.len(),
        keys.join(" ")
    );

    // Size estimate: env key+value bytes (+ separators) + argv bytes.
    // Warn on E2BIG risk (spec §4.4): spawn would fail above ~2 MiB ARG_MAX.
    let env_bytes: usize = env_map
        .iter()
        .map(|(k, v)| k.as_bytes().len() + v.as_bytes().len() + 2)
        .sum();
    let argv_bytes: usize = command.iter().map(|a| a.len() + 1).sum();
    let total = env_bytes + argv_bytes;
    let _ = writeln!(
        out,
        "Estimated total environment size: {} bytes (~{:.1} KiB)",
        total,
        total as f64 / 1024.0
    );
    out_bytes(out.as_bytes())?;
    if total > 1_500_000 {
        eprintln!("warning: environment may exceed ARG_MAX (E2BIG)");
    }
    Ok(0)
}

/// Map a finished child status to an exit code (spec §3).
fn exit_code_of(status: &std::process::ExitStatus) -> i32 {
    match status.code() {
        Some(c) => c,
        None => {
            // Killed by a signal: exit 128+N per shell convention
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;
                status.signal().map(|s| 128 + s).unwrap_or(1)
            }
            #[cfg(not(unix))]
            {
                1
            }
        }
    }
}

/// `--password-stdin`: read the first line of stdin, stripping `\n`/`\r\n`
/// (spec §4.3). No ENVRUN_PASSPHRASE env var on purpose — process env is
/// readable by same-user processes via /proc.
fn read_password_stdin() -> Result<Zeroizing<String>> {
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .context("failed to read password from stdin")?;
    let pw = line.trim_end_matches(['\n', '\r']);
    if pw.is_empty() {
        bail!("no password provided on stdin");
    }
    Ok(Zeroizing::new(pw.to_string()))
}

/// `envrun list`
pub fn list() -> Result<()> {
    let profiles = profile::list()?;
    let mut out = String::new();
    if profiles.is_empty() {
        out.push_str("No profiles yet. Create one with: envrun import <name> --from <env-file>\n");
        return out_bytes(out.as_bytes());
    }
    let _ = writeln!(out, "{:<20} {:>8}  Updated", "Name", "Vars");
    for p in &profiles {
        let vars_cell = if p.corrupted {
            "-".to_string()
        } else {
            p.var_count.to_string()
        };
        let updated_cell = if p.corrupted {
            "(corrupted)".to_string()
        } else {
            format_unix(p.updated_at)
        };
        let _ = writeln!(out, "{:<20} {:>8}  {}", p.name, vars_cell, updated_cell);
    }
    out_bytes(out.as_bytes())
}

/// `envrun rm <name>`
pub fn rm(name: &str) -> Result<()> {
    profile::validate_name(name)?;
    if !profile::exists(name)? {
        bail!("profile '{name}' does not exist (see `envrun list`)");
    }
    eprint!("Delete profile '{name}'? [y/N] ");
    std::io::stderr().flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    let answer = answer.trim().to_ascii_lowercase();
    if answer != "y" && answer != "yes" {
        return out_line("Cancelled");
    }
    profile::delete(name)?;
    out_line(format!("Profile '{name}' deleted"))
}

/// `envrun passwd <name>`: decrypt with the current password, re-encrypt with
/// a new one (v1 format unchanged; fresh salt/nonce per write). A cached
/// keychain entry for the old password becomes stale — remove it.
pub fn passwd(name: &str) -> Result<()> {
    profile::validate_name(name)?;
    let blob = profile::read(name)?;
    let old = obtain_password(
        name,
        false,
        &format!("Enter current password for profile '{name}': "),
    )?;
    let decrypted = crypto::decrypt(&blob, old.as_str())?;
    let vars = EnvVars::from_json(&decrypted.plaintext)?;

    let new = prompt_new_password()?;
    let payload = vars.to_json()?;
    let meta = FileMeta {
        var_count: vars.len() as u32,
        updated_at: now_unix()?,
    };
    let new_blob = crypto::encrypt(&payload, new.as_str(), meta)?;
    profile::write(name, &new_blob)?;
    let _ = keycache::clear(name);
    out_line(format!("Password changed for profile '{name}'"))
}

/// `envrun unlock <name> [--ttl <seconds>]` (spec §4.3): verify the password,
/// then cache it in the OS keychain. On keychain failure, degrade to a
/// warning instead of hard-failing (SSH sessions without GUI access).
pub fn unlock(name: &str, ttl: u64) -> Result<()> {
    profile::validate_name(name)?;
    // Usage errors fail fast (§0.5) — they are not keychain unavailability
    // and must not be swallowed by the degrade path below.
    if ttl == 0 || ttl > keycache::MAX_TTL_SECS {
        bail!(
            "--ttl must be between 1 and {} seconds (30 days)",
            keycache::MAX_TTL_SECS
        );
    }
    let blob = profile::read(name)?;
    let password = prompt_password(&format!("Enter password for profile '{name}': "))?;
    crypto::decrypt(&blob, password.as_str())?;
    match keycache::store(name, password.as_str(), ttl) {
        Ok(()) => out_line(format!(
            "Password cached for profile '{name}' (expires in {ttl}s)"
        )),
        Err(e) => {
            eprintln!(
                "warning: could not access the OS keychain ({e}); type the password manually instead"
            );
            Ok(())
        }
    }
}

/// `envrun lock <name>`: remove the cached keychain entry.
pub fn lock(name: &str) -> Result<()> {
    profile::validate_name(name)?;
    let _ = keycache::clear(name);
    out_line(format!("Cached password for profile '{name}' removed"))
}

fn format_unix(ts: u64) -> String {
    use chrono::TimeZone;
    chrono::Local
        .timestamp_opt(ts as i64, 0)
        .single()
        .map(|t| t.format("%Y-%m-%d %H:%M").to_string())
        .unwrap_or_else(|| ts.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fpm_line_escaping() {
        assert_eq!(fpm_line("KEY", "plain"), "env[KEY] = plain");
        assert_eq!(fpm_line("KEY", "a b c"), "env[KEY] = a b c");
        assert_eq!(fpm_line("KEY", "a\"b"), "env[KEY] = \"a\\\"b\"");
        assert_eq!(fpm_line("KEY", "a\\b"), "env[KEY] = \"a\\\\b\"");
        assert_eq!(fpm_line("KEY", "a;b#c"), "env[KEY] = \"a;b#c\"");
        assert_eq!(fpm_line("KEY", "it's $HOME"), "env[KEY] = it's $HOME");
    }

    #[test]
    fn parse_key_list_trims_and_skips_empty() {
        assert_eq!(parse_key_list(" A , B,,C "), vec!["A", "B", "C"]);
        assert!(parse_key_list(",, ").is_empty());
    }

    #[test]
    fn shell_quotes_unsafe_args() {
        assert_eq!(shell_quote("plain"), "plain");
        assert_eq!(shell_quote(""), "''");
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
    }

    /// A UTF-8 BOM prefix (typical of Windows-edited .env files) must never
    /// reach encrypted storage: either dotenvy strips it, or import-time
    /// validation rejects it with an actionable error.
    #[test]
    fn bom_file_never_reaches_storage() {
        let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
        let path = dir.path().join("bom.env");
        std::fs::write(&path, "\u{feff}FOO=bar\n").unwrap();
        match EnvVars::parse_file(&path) {
            Ok(vars) => {
                assert!(
                    require_valid_keys(&vars).is_err(),
                    "BOM-prefixed key must be rejected by import validation"
                );
            }
            Err(_) => { /* dotenvy rejected the file outright — also fine */ }
        }
    }

    #[test]
    fn invalid_keys_are_all_reported() {
        let vars = EnvVars::from_map(std::collections::BTreeMap::from([
            ("GOOD".to_string(), "1".to_string()),
            ("BAD ONE".to_string(), "2".to_string()),
            ("2BAD".to_string(), "3".to_string()),
        ]));
        let err = require_valid_keys(&vars).unwrap_err().to_string();
        assert!(
            err.contains("BAD ONE"),
            "each invalid key must be listed: {err}"
        );
        assert!(
            err.contains("2BAD"),
            "each invalid key must be listed: {err}"
        );
        assert!(err.contains("2 invalid variable(s)"));
    }
}
