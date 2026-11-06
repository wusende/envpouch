//! Implementations of the subcommands.

use std::collections::BTreeMap;
use std::ffi::OsString;
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

/// Passwords are always held in Zeroizing<String> and wiped on drop.
fn prompt_password(prompt: &str) -> Result<Zeroizing<String>> {
    let pw = rpassword::prompt_password(prompt).context("failed to read password")?;
    Ok(Zeroizing::new(pw))
}

/// Password input configured by the global flags (spec §4.3):
/// `--password-stdin` (one stdin line per prompt), `--password-file`
/// (one file line per prompt, file must be mode 0600 on unix), or the
/// interactive prompt. Explicit flags never touch the tty.
pub(crate) struct PasswordInput {
    stdin: bool,
    file: Option<PathBuf>,
    /// Password-file lines, loaded on first use: commands that decrypt
    /// nothing (`list`, `rm`) never touch the file.
    lines: Option<Zeroizing<Vec<String>>>,
    cursor: usize,
}

impl PasswordInput {
    /// Build from the parsed global flags. Mutually exclusive at the CLI
    /// level (clap `conflicts_with`); re-checked here for defense in depth.
    pub(crate) fn from_flags(stdin: bool, file: Option<PathBuf>) -> Result<Self> {
        if stdin && file.is_some() {
            bail!("--password-stdin and --password-file are mutually exclusive");
        }
        Ok(Self {
            stdin,
            file,
            lines: None,
            cursor: 0,
        })
    }

    /// True when the password comes from a flag (stdin or file) instead of
    /// the interactive prompt.
    fn is_explicit(&self) -> bool {
        self.stdin || self.file.is_some()
    }

    /// True when stdin is reserved for password lines (--password-stdin);
    /// interactive value prompts must not read it.
    fn reserves_stdin(&self) -> bool {
        self.stdin
    }

    /// Consume the next password from the explicit source: one line per
    /// prompt, in prompt order (same contract as --password-stdin, so
    /// multi-prompt commands like `passwd` and `diff` work with files too).
    fn next_password(&mut self) -> Result<Zeroizing<String>> {
        if self.stdin {
            return read_password_stdin();
        }
        let Some(path) = self.file.clone() else {
            bail!("no explicit password source configured"); // unreachable via the CLI
        };
        if self.lines.is_none() {
            self.lines = Some(read_password_file(&path)?);
        }
        let line = {
            let lines = self.lines.as_ref().expect("loaded just above");
            let Some(line) = lines.get(self.cursor) else {
                bail!(
                    "password file {} has fewer lines than password prompts",
                    path.display()
                );
            };
            line.to_string()
        };
        self.cursor += 1;
        let pw = Zeroizing::new(line);
        if pw.as_str().is_empty() {
            bail!("empty line in password file {}", path.display());
        }
        Ok(pw)
    }
}

/// Upper bound for a whole password file: far beyond any sane multi-prompt
/// use (each single password is capped by MAX_PASSWORD_BYTES).
const MAX_PASSWORD_FILE_BYTES: usize = 64 * 1024;

/// Read the `--password-file` lines. The file must exist, be valid UTF-8,
/// and on unix be mode 0600 — a group/world-readable password file defeats
/// the feature's whole point, so it is refused instead of warned about.
fn read_password_file(path: &Path) -> Result<Zeroizing<Vec<String>>> {
    if !path.exists() {
        bail!("password file not found: {}", path.display());
    }
    let meta = std::fs::metadata(path)
        .with_context(|| format!("failed to stat password file: {}", path.display()))?;
    if meta.len() > MAX_PASSWORD_FILE_BYTES as u64 {
        bail!("password file too large (max {MAX_PASSWORD_FILE_BYTES} bytes)");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            bail!(
                "password file {} is mode {:o}; must be owner-only (chmod 600 {})",
                path.display(),
                mode,
                path.display()
            );
        }
    }
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read password file: {}", path.display()))?;
    let trimmed = raw.trim_end_matches(['\n', '\r']);
    if trimmed.is_empty() {
        bail!("password file {} is empty", path.display());
    }
    let lines: Vec<String> = trimmed
        .split('\n')
        .map(|l| l.trim_end_matches('\r').to_string())
        .collect();
    Ok(Zeroizing::new(lines))
}

/// Unified password acquisition (spec §4.3): the explicit flag source
/// (--password-stdin / --password-file) first, then the interactive prompt.
/// Every decrypting command goes through this.
fn obtain_password(input: &mut PasswordInput, prompt: &str) -> Result<Zeroizing<String>> {
    if input.is_explicit() {
        return input.next_password();
    }
    prompt_password(prompt)
}

/// Open an existing profile: read it, acquire the password (flag source or
/// prompt), decrypt, parse. The derived key is returned so callers that
/// re-save can skip a second KDF pass. Shared by every decrypting command.
fn open_profile(name: &str, input: &mut PasswordInput) -> Result<(EnvVars, crypto::DerivedKey)> {
    let blob = profile::read(name)?;
    let password = obtain_password(input, &format!("Enter password for profile '{name}': "))?;
    let (decrypted, derived) = crypto::decrypt_derived(&blob, password.as_str())?;
    let vars = EnvVars::from_json(&decrypted.plaintext)?;
    Ok((vars, derived))
}

/// New-password setup. Interactive: type twice to confirm with one retry on
/// mismatch (spec §5.1). With an explicit flag source: one line, no
/// confirmation (scripts cannot re-type; the lost-password warning still
/// prints).
fn new_password(input: &mut PasswordInput) -> Result<Zeroizing<String>> {
    eprintln!("warning: if you lose this password, the profile cannot be recovered");
    if input.is_explicit() {
        let pw = input.next_password()?;
        if pw.as_str().len() < 8 {
            bail!("password too short (minimum 8 characters)");
        }
        return Ok(pw);
    }
    prompt_new_password()
}

/// Interactive password setup: type twice to confirm; on mismatch, retry at
/// most once before giving up (spec §5.1).
fn prompt_new_password() -> Result<Zeroizing<String>> {
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
    bail!("password setup failed after {MAX_ATTEMPTS} attempts")
}

fn now_unix() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time is before the Unix epoch")?
        .as_secs())
}

/// Write bytes to stdout. Rust ignores SIGPIPE, so a closed pipe (`envp
/// export dev | head`) surfaces as EPIPE here; treat it as a clean exit
/// instead of panicking (review fix).
pub(crate) fn write_stdout(bytes: &[u8]) -> Result<()> {
    let mut out = std::io::stdout();
    match out.write_all(bytes).and_then(|()| out.flush()) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        Err(e) => Err(e).context("failed to write to stdout"),
    }
}

fn out_line(s: impl std::fmt::Display) -> Result<()> {
    write_stdout(format!("{s}\n").as_bytes())
}

/// Parse a comma-separated key list into trimmed, non-empty names.
fn parse_key_list(spec: &str) -> Vec<String> {
    spec.split(',')
        .map(|k| k.trim().to_string())
        .filter(|k| !k.is_empty())
        .collect()
}

/// Entry point for `import` (spec §5.1): exactly one of --from / --from-env.
#[allow(clippy::too_many_arguments)]
pub fn import_command(
    name: &str,
    from: Option<PathBuf>,
    from_env: bool,
    only: Option<String>,
    except: Option<String>,
    merge: bool,
    input: &mut PasswordInput,
) -> Result<()> {
    if only.is_some() && except.is_some() {
        bail!("--only and --except are mutually exclusive");
    }
    match (from, from_env) {
        (Some(f), false) => import_from_file(name, &f, merge, input),
        (None, true) => import_from_env(name, only, except, merge, input),
        (Some(_), true) => bail!("--from and --from-env are mutually exclusive"),
        (None, false) => bail!("nothing to import: specify --from <file> or --from-env"),
    }
}

fn import_from_file(name: &str, from: &Path, merge: bool, input: &mut PasswordInput) -> Result<()> {
    if !from.exists() {
        bail!("file not found: {}", from.display());
    }
    let new_vars = EnvVars::parse_file(from)?;
    require_valid_keys(&new_vars)?;
    import_vars(name, new_vars, merge, "", input)
}

/// `import --from-env`: grab variables from the current process environment.
/// Default behavior applies the hardcoded exclusion list (spec §5.1);
/// `--only` bypasses it entirely, `--except` adds to it.
fn import_from_env(
    name: &str,
    only: Option<String>,
    except: Option<String>,
    merge: bool,
    input: &mut PasswordInput,
) -> Result<()> {
    let only_list = only.as_ref().map(|s| parse_key_list(s));
    let except_list = except.as_ref().map(|s| parse_key_list(s));

    let mut map = BTreeMap::new();
    let mut skipped_filtered = 0usize;
    let mut skipped_non_utf8 = 0usize;
    for (k, v) in std::env::vars_os() {
        let (k, v) = match (k.into_string(), v.into_string()) {
            (Ok(k), Ok(v)) => (k, v),
            // Non-UTF-8 entries cannot be stored in a .env profile
            _ => {
                skipped_non_utf8 += 1;
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
            skipped_filtered += 1;
            continue;
        }
        map.insert(k, v);
    }
    let vars = EnvVars::from_map(map);
    require_valid_keys(&vars)?;
    let note = format_skipped_note(only.is_some(), skipped_filtered, skipped_non_utf8);
    import_vars(name, vars, merge, &note, input)
}

/// Parenthesized suffix for the import summary line: names why variables
/// were left out instead of lumping non-UTF-8 entries into the filter count.
fn format_skipped_note(only_mode: bool, filtered: usize, non_utf8: usize) -> String {
    let mut parts = Vec::new();
    if filtered > 0 {
        if only_mode {
            parts.push(format!("{filtered} not selected by --only"));
        } else {
            parts.push(format!("{filtered} skipped by exclusion list"));
        }
    }
    if non_utf8 > 0 {
        parts.push(format!("{non_utf8} not valid UTF-8"));
    }
    if parts.is_empty() {
        String::new()
    } else {
        format!(" ({})", parts.join(", "))
    }
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

/// Defensive re-check of stored keys before injection (spec §4.4 trusts
/// stored data; this only guards against a corrupted/crafted payload turning
/// into a panic inside `Command::env`). Key names only — never values.
fn validate_stored_keys(vars: &EnvVars) -> Result<()> {
    let invalid: Vec<&str> = vars
        .iter()
        .filter(|(k, _)| envfile::validate_key(k, "").is_err())
        .map(|(k, _)| k.as_str())
        .collect();
    if invalid.is_empty() {
        return Ok(());
    }
    bail!(
        "profile contains invalid variable name(s): {} (profile may be corrupted)",
        invalid.join(", ")
    );
}

/// Encrypt and atomically write `vars` under an already-derived key.
/// Reuses the profile's salt and draws a fresh nonce (see
/// `crypto::encrypt_derived`); for a new profile or a password change,
/// derive first via `crypto::DerivedKey::fresh`.
fn save_profile(name: &str, vars: &EnvVars, derived: &crypto::DerivedKey) -> Result<()> {
    let payload = vars.to_json()?;
    let meta = FileMeta {
        var_count: vars.len() as u32,
        updated_at: now_unix()?,
    };
    let blob = crypto::encrypt_derived(&payload, derived, meta)?;
    profile::write(name, &blob)
}

/// One `set` argument after parsing.
#[derive(Debug)]
enum Assignment {
    /// `KEY=VALUE` given on the command line
    Pair(String, String),
    /// bare `KEY`: the value is prompted (hidden) after the password is verified
    Prompt(String),
}

/// Parse `KEY=VALUE` / bare `KEY` assignments without touching stdin or the
/// terminal yet: structure errors must fail before any password is requested.
/// Bare keys are rejected with `--password-stdin` because stdin lines belong to
/// password prompts (one line per prompt).
fn parse_assignments(assignments: &[String], password_stdin: bool) -> Result<Vec<Assignment>> {
    let mut parsed = Vec::with_capacity(assignments.len());
    for item in assignments {
        match item.split_once('=') {
            Some((key, value)) => {
                envfile::validate_key(key, value)?;
                parsed.push(Assignment::Pair(key.to_string(), value.to_string()));
            }
            None => {
                envfile::validate_key(item, "")?;
                if password_stdin {
                    bail!(
                        "'{item}' has no value; with --password-stdin write KEY=VALUE \
                         (stdin is reserved for the password prompts)"
                    );
                }
                parsed.push(Assignment::Prompt(item.to_string()));
            }
        }
    }
    Ok(parsed)
}

/// Resolve bare keys with a hidden terminal prompt, after the password has
/// been verified. The value is never echoed and never enters shell history.
fn resolve_prompted(parsed: Vec<Assignment>) -> Result<Vec<(String, String)>> {
    let mut pairs = Vec::with_capacity(parsed.len());
    for item in parsed {
        match item {
            Assignment::Pair(key, value) => pairs.push((key, value)),
            Assignment::Prompt(key) => {
                let value = rpassword::prompt_password(format!("Value for {key}: "))
                    .context("cannot read the value from the terminal")?;
                let value = Zeroizing::new(value);
                envfile::validate_key(&key, &value)?;
                pairs.push((key, value.to_string()));
            }
        }
    }
    Ok(pairs)
}

/// `envp set <name> KEY=VALUE...` (bare `KEY` prompts for the value).
///
/// Creates the profile when it does not exist (prompting for a new
/// password), so a profile can be built from scratch without an .env file.
/// `KEY=VALUE` exposes the value to `ps`/shell history — use the bare form
/// for secrets.
pub fn set(name: &str, assignments: &[String], input: &mut PasswordInput) -> Result<()> {
    profile::validate_name(name)?;
    let parsed = parse_assignments(assignments, input.reserves_stdin())?;

    let existed = profile::exists(name)?;
    let (mut vars, derived) = if existed {
        open_profile(name, input)?
    } else {
        let password = new_password(input)?;
        (
            EnvVars::default(),
            crypto::DerivedKey::fresh(password.as_str())?,
        )
    };

    let pairs = resolve_prompted(parsed)?;

    let (mut added, mut replaced) = (0usize, 0usize);
    for (key, value) in pairs {
        if vars.insert(key, value) {
            replaced += 1;
        } else {
            added += 1;
        }
    }

    save_profile(name, &vars, &derived)?;
    let verb = if existed { "updated" } else { "created" };
    out_line(format!(
        "Profile '{name}' {verb}: {added} added, {replaced} replaced ({} variables)",
        vars.len()
    ))
}

/// `envp unset <name> KEY...`: remove variables; missing keys are reported but
/// do not fail the command unless nothing at all matched.
pub fn unset(name: &str, keys: &[String], input: &mut PasswordInput) -> Result<()> {
    profile::validate_name(name)?;
    if !profile::exists(name)? {
        bail!("profile '{name}' does not exist (create it with `envp set` or `envp import`)");
    }
    for key in keys {
        envfile::validate_key(key, "")?;
    }

    let (mut vars, derived) = open_profile(name, input)?;

    let mut removed = 0usize;
    let mut missing = Vec::new();
    for key in keys {
        if vars.remove(key) {
            removed += 1;
        } else {
            missing.push(key.as_str());
        }
    }

    if removed == 0 {
        bail!(
            "no matching variables in profile '{name}': {}",
            missing.join(", ")
        );
    }

    save_profile(name, &vars, &derived)?;
    out_line(format!(
        "Profile '{name}' updated: {removed} removed ({} variables)",
        vars.len()
    ))?;
    if !missing.is_empty() {
        eprintln!("warning: not found: {}", missing.join(", "));
    }
    Ok(())
}

/// Shared import pipeline. `skipped_note` is the preformatted suffix from
/// `format_skipped_note` (empty for `--from`, where nothing is filtered).
fn import_vars(
    name: &str,
    new_vars: EnvVars,
    merge: bool,
    skipped_note: &str,
    input: &mut PasswordInput,
) -> Result<()> {
    let existed = profile::exists(name)?;
    if existed && !merge {
        bail!("profile '{name}' already exists (use --merge to merge into it)");
    }
    let (vars, derived) = if existed {
        // Merging must verify the existing password; it stays unchanged
        let (existing, derived) = open_profile(name, input)?;
        let mut merged = existing;
        let (added, updated) = merged.merge(new_vars);
        eprintln!("Merge result: {added} added, {updated} updated");
        (merged, derived)
    } else {
        let password = new_password(input)?;
        (new_vars, crypto::DerivedKey::fresh(password.as_str())?)
    };

    if vars.is_empty() {
        eprintln!("warning: no environment variables were imported");
    }

    save_profile(name, &vars, &derived)?;

    let mut out = String::new();
    let _ = writeln!(
        out,
        "Profile '{name}' written: {} variables{skipped_note}",
        vars.len()
    );
    for (k, _) in vars.iter() {
        let _ = writeln!(out, "{k}");
    }
    write_stdout(out.as_bytes())?;

    // Spec §5.1 pitfall: dotenvy expands $VAR in double-quoted/bare values
    if vars.iter().any(|(_, v)| v.contains('$')) {
        eprintln!(
            "note: values containing $ are expanded under dotenvy semantics; use single quotes in .env files"
        );
    }
    Ok(())
}

/// `envp show <name> [--reveal]`
pub fn show(name: &str, reveal: bool, input: &mut PasswordInput) -> Result<()> {
    let (vars, _) = open_profile(name, input)?;

    if reveal {
        eprintln!("warning: output contains plaintext secrets");
        write_stdout(vars.to_env_text().as_bytes())?;
    } else {
        let mut out = String::new();
        for (k, v) in vars.iter() {
            let _ = writeln!(out, "{k} = {}", mask::mask(v));
        }
        write_stdout(out.as_bytes())?;
    }
    Ok(())
}

/// `envp export <name> [-o <file>]`
pub fn export(name: &str, output: Option<PathBuf>, input: &mut PasswordInput) -> Result<()> {
    let (vars, _) = open_profile(name, input)?;
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
            write_stdout(text.as_bytes())?;
        }
    }
    Ok(())
}

/// `envp edit <name>` (spec §5.3): decrypt into a 0600 temp file, open
/// $EDITOR (default vi), parse back, re-encrypt atomically.
pub fn edit(name: &str, input: &mut PasswordInput) -> Result<()> {
    cleanup_edit_leftovers();
    let (vars, key) = open_profile(name, input)?;

    let editor = split_editor(std::env::var("EDITOR").ok().as_deref());
    let tmp = tempfile::Builder::new()
        .prefix("envpouch-edit-")
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

    let status = Command::new(&editor[0])
        .args(&editor[1..])
        .arg(&path)
        .status()
        .with_context(|| format!("failed to launch editor: {}", editor[0]))?;
    if !status.success() {
        bail!(
            "editor exited with {}; profile not modified",
            status.code().unwrap_or(-1)
        );
    }

    let new_vars = EnvVars::parse_file(&path)?;
    require_valid_keys(&new_vars)?;
    save_profile(name, &new_vars, &key)?;

    if tmp.close().is_err() {
        eprintln!("warning: could not delete temp file {}", path.display());
    }
    out_line(format!(
        "Profile '{name}' updated: {} variables",
        new_vars.len()
    ))
}

/// $EDITOR may carry arguments (e.g. `code --wait`); split on whitespace.
/// Whitespace-only or unset falls back to `vi` (spec §5.3).
fn split_editor(editor: Option<&str>) -> Vec<String> {
    match editor.map(str::trim).filter(|e| !e.is_empty()) {
        Some(e) => e.split_whitespace().map(str::to_string).collect(),
        None => vec!["vi".to_string()],
    }
}

/// Best-effort cleanup of leftover `envpouch-edit-*` temp files from killed
/// sessions (spec §5.3). Not a data incident, but do not accumulate them.
/// $TMPDIR is shared between users on some platforms (/tmp on Linux), so only
/// files owned by the current uid (unix) AND untouched for an hour are
/// removed — a live concurrent edit session is never disturbed.
fn cleanup_edit_leftovers() {
    cleanup_edit_leftovers_in(&std::env::temp_dir(), std::time::Duration::from_secs(3600));
}

fn cleanup_edit_leftovers_in(dir: &Path, stale_after: std::time::Duration) {
    #[cfg(unix)]
    let euid = unsafe { libc::geteuid() };
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        let Some(name) = p.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if !name.starts_with("envpouch-edit-") {
            continue;
        }
        let Ok(meta) = e.metadata() else {
            continue;
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            // Not ours (another user's live session or leftover) — never touch
            if meta.uid() != euid {
                continue;
            }
        }
        let old_enough = meta
            .modified()
            .map(|t| t.elapsed().unwrap_or_default() > stale_after)
            .unwrap_or(false);
        if old_enough {
            let _ = std::fs::remove_file(&p);
        }
    }
}

/// `envp fpm-snippet <name>` (spec §4.7): emit php-fpm pool `env[...]`
/// lines on stdout.
pub fn fpm_snippet(name: &str, input: &mut PasswordInput) -> Result<()> {
    let (vars, _) = open_profile(name, input)?;

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
    write_stdout(out.as_bytes())?;

    if !dollar_keys.is_empty() {
        eprintln!(
            "note: values of {} contain $ which has variable-reference semantics in fpm config; review manually",
            dollar_keys.join(", ")
        );
    }
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

/// `envp diff <a> <b>` (spec §9 M4): show key-level differences with
/// masked values.
pub fn diff(name_a: &str, name_b: &str, input: &mut PasswordInput) -> Result<()> {
    if name_a == name_b {
        bail!("cannot diff a profile with itself");
    }
    let (vars_a, _) = open_profile(name_a, input)?;
    let (vars_b, _) = open_profile(name_b, input)?;

    // Key matching goes through EnvVars::get (O(log n) lookups), not linear
    // rescans of the other map — the old nested iteration was O(n²).
    let mut only_a: Vec<&str> = Vec::new();
    let mut only_b: Vec<&str> = Vec::new();
    let mut changed = Vec::new();
    let mut same = 0usize;
    for (k, va) in vars_a.iter() {
        match vars_b.get(k) {
            None => only_a.push(k.as_str()),
            Some(vb) => {
                if va == vb {
                    same += 1;
                } else {
                    changed.push(format!("{k}: {} -> {}", mask::mask(va), mask::mask(vb)));
                }
            }
        }
    }
    for (k, _) in vars_b.iter() {
        if vars_a.get(k).is_none() {
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
    write_stdout(out.as_bytes())
}

/// `envp run <name> [--clean] [--dry-run] [--allow-core-dumps] <cmd> [args...]`
/// (`--password-stdin` / `--password-file` are global flags, usable with this
/// and every other password-requiring command)
///
/// Process model: on unix, decrypt, prepare the environment, then `exec` the
/// target in place. The application keeps envp's PID and process group, so
/// Ctrl-C/Ctrl-Z, supervisor signals and the exit status go straight to it —
/// there is no wrapper process between systemd/supervisord and the app.
/// Windows has no `exec`, so it spawns and waits there.
///
/// Returns the exit code only on the paths that return (dry-run, windows,
/// errors): 1:1 for the child, 127 not found, 126 no execute permission, 1
/// for envp errors. A successful unix `exec` never returns.
///
/// Secrets hygiene: `exec` replaces envp's image, so decrypted vars, the
/// derived key and password buffers are reclaimed by the kernel instead of
/// living for the service lifetime. Core dumps stay disabled by default;
/// pass `allow_core_dumps` to keep the supervisor's limits (systemd
/// `LimitCORE=`, `ulimit -c`).
pub fn run(
    name: &str,
    clean: bool,
    dry_run: bool,
    allow_core_dumps: bool,
    input: &mut PasswordInput,
    command: &[String],
) -> Result<i32> {
    profile::validate_name(name)?;
    if command.is_empty() {
        bail!("missing command to execute");
    }
    let (vars, _) = open_profile(name, input)?;
    // Stored data is trusted per spec §4.4 (validated at import/edit time),
    // but a hand-crafted payload must still fail cleanly here instead of
    // panicking inside `Command::env` (keys containing '=' or NUL).
    validate_stored_keys(&vars)?;

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
    // The command env was copied into `cmd`; release the plaintext maps now.
    // The exec path replaces the image anyway, but this also covers errors.
    drop(env_map);
    drop(vars);

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;

        // Best-effort: disable core dumps for the target to shrink the leak
        // surface (spec §1, §4.6), unless the operator opted out to keep the
        // supervisor's core-dump policy. The limit survives exec.
        if !allow_core_dumps {
            disable_core_dumps();
        }

        // Become the target. exec() only returns on failure; PID, process
        // group, tty and signal dispositions are preserved, so supervisors
        // and job control see the application itself.
        //
        // Audit gets a line before the image is replaced; envp can no longer
        // observe the application's exit status afterwards.
        crate::audit::record("run", Some(name), "exec");
        let err = cmd.exec();
        start_error(err, command)
    }

    #[cfg(not(unix))]
    {
        // Windows has no exec: spawn and wait. Console Ctrl-C reaches the
        // child natively (same console group).
        let _ = allow_core_dumps; // no RLIMIT_CORE on Windows
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => return start_error(e, command),
        };
        // The child has its own copy of the environment now; dropping `cmd`
        // releases the parent-side copy std keeps inside the Command.
        drop(cmd);
        let status = child.wait()?;
        Ok(exit_code_of(&status))
    }
}

/// Best-effort `RLIMIT_CORE = 0` for the program envp is about to exec.
/// Failure is ignored (e.g. a hard limit the caller cannot lower further).
#[cfg(unix)]
fn disable_core_dumps() {
    unsafe {
        let lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &lim);
    }
}

/// Map a failed spawn/exec to the documented exit codes (127 not found,
/// 126 no execute permission, 1 environment too large) or an envp error.
fn start_error(e: std::io::Error, command: &[String]) -> Result<i32> {
    if e.kind() == std::io::ErrorKind::NotFound {
        eprintln!("error: command not found: {}", command[0]);
        return Ok(127);
    }
    if e.kind() == std::io::ErrorKind::PermissionDenied {
        eprintln!("error: permission denied: {}", command[0]);
        return Ok(126);
    }
    // libc::E2BIG is 7 on unix and on the Windows CRT alike, so this one
    // check covers both platforms.
    if e.raw_os_error() == Some(libc::E2BIG) {
        eprintln!("error: environment too large (ARG_MAX limit)");
        return Ok(1);
    }
    Err(e).with_context(|| format!("failed to start: {}", command[0]))
}

/// Minimal base environment for `--clean` (spec §4.4): taken from the current
/// environment, missing entries are skipped (never invented). On unix TERM
/// must be kept or TTY programs lose all colors; on Windows the equivalent
/// minimal set is PATH/USERPROFILE plus the temp/system locations programs
/// commonly expect.
#[cfg(unix)]
const CLEAN_BASE_KEYS: [&str; 7] = ["PATH", "HOME", "TMPDIR", "USER", "LOGNAME", "SHELL", "TERM"];
#[cfg(not(unix))]
const CLEAN_BASE_KEYS: [&str; 6] = [
    "PATH",
    "USERPROFILE",
    "TMP",
    "TEMP",
    "SystemRoot",
    "ComSpec",
];

/// Final child environment:
/// - overlay (default): full current env, same-name keys overridden by profile;
/// - clean: fixed base keys + profile variables, nothing else.
fn build_env(clean: bool, vars: &EnvVars) -> BTreeMap<OsString, OsString> {
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
    env_map: &BTreeMap<OsString, OsString>,
) -> Result<i32> {
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
    // as_encoded_bytes() is the cross-platform replacement for unix OsStrExt.
    let env_bytes: usize = env_map
        .iter()
        .map(|(k, v)| k.as_encoded_bytes().len() + v.as_encoded_bytes().len() + 2)
        .sum();
    let argv_bytes: usize = command.iter().map(|a| a.len() + 1).sum();
    let total = env_bytes + argv_bytes;
    let _ = writeln!(
        out,
        "Estimated total environment size: {} bytes (~{:.1} KiB)",
        total,
        total as f64 / 1024.0
    );
    write_stdout(out.as_bytes())?;
    if total > 1_500_000 {
        eprintln!("warning: environment may exceed ARG_MAX (E2BIG)");
    }
    Ok(0)
}

/// Map a finished child status to an exit code (Windows has no signals, so
/// the unix exec path never needs this).
#[cfg(not(unix))]
fn exit_code_of(status: &std::process::ExitStatus) -> i32 {
    status.code().unwrap_or(1)
}

/// `--password-stdin`: read the next line of stdin, stripping `\n`/`\r\n`
/// (spec §4.3). Commands that prompt twice (passwd: current+new; diff: one
/// per profile) read one line per prompt, in prompt order. Bounded so a
/// runaway pipe cannot balloon memory. No ENVPOUCH_PASSPHRASE env var on
/// purpose — process env is readable by same-user processes via /proc.
fn read_password_stdin() -> Result<Zeroizing<String>> {
    const MAX_PASSWORD_BYTES: usize = 8 * 1024;
    // Line-oriented AND bounded: multi-prompt commands (passwd, diff) read
    // one line per call; a runaway pipe without newlines cannot balloon
    // memory. The only legal over-length line is exactly MAX password bytes
    // plus the terminating newline.
    let mut buf = Zeroizing::new(Vec::new());
    let mut byte = [0u8; 1];
    loop {
        match read_stdin_byte(&mut byte) {
            Ok(0) => break, // EOF: last line may lack a newline
            Ok(_) => {
                buf.push(byte[0]);
                if byte[0] == b'\n' || buf.len() > MAX_PASSWORD_BYTES {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e).context("failed to read password from stdin"),
        }
    }
    if buf.len() > MAX_PASSWORD_BYTES
        && !(buf.len() == MAX_PASSWORD_BYTES + 1 && buf.last() == Some(&b'\n'))
    {
        bail!("password on stdin exceeds {MAX_PASSWORD_BYTES} bytes");
    }
    let line = std::str::from_utf8(&buf).context("password on stdin is not valid UTF-8")?;
    let pw = line.trim_end_matches(['\n', '\r']);
    if pw.is_empty() {
        bail!("no password provided on stdin");
    }
    Ok(Zeroizing::new(pw.to_string()))
}

/// Read one byte from stdin without the libc/std buffering layer. This
/// matters for `run --password-stdin`: anything the buffered reader pulled
/// in eagerly would be lost when envp execs the target (the target inherits
/// fd 0). Raw read(2) leaves the rest of the pipe for the application.
#[cfg(unix)]
fn read_stdin_byte(byte: &mut [u8; 1]) -> std::io::Result<usize> {
    loop {
        // SAFETY: `byte` is a valid one-byte writable buffer and fd 0 is the
        // process's stdin; read(2) writes at most the given length.
        let n = unsafe { libc::read(libc::STDIN_FILENO, byte.as_mut_ptr().cast(), 1) };
        if n >= 0 {
            return Ok(n as usize);
        }
        let err = std::io::Error::last_os_error();
        if err.kind() != std::io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

#[cfg(not(unix))]
fn read_stdin_byte(byte: &mut [u8; 1]) -> std::io::Result<usize> {
    use std::io::Read as _;
    std::io::stdin().lock().read(byte)
}

/// `envp list`
pub fn list() -> Result<()> {
    let profiles = profile::list()?;
    let mut out = String::new();
    if profiles.is_empty() {
        out.push_str(
            "No profiles yet. Create one with: envp import <name> --from <file>\n\
             or add variables directly:  envp set <name> KEY=VALUE\n",
        );
        return write_stdout(out.as_bytes());
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
    write_stdout(out.as_bytes())
}

/// `envp rm <name> [-f|--yes]`: delete after an interactive confirmation.
/// `-f/--yes` skips the prompt — without it, a non-interactive stdin (CI,
/// scripts) reads EOF and the answer is always "no" (review fix).
pub fn rm(name: &str, yes: bool) -> Result<()> {
    profile::validate_name(name)?;
    if !profile::exists(name)? {
        bail!("profile '{name}' does not exist (see `envp list`)");
    }
    if !yes {
        eprint!("Delete profile '{name}'? [y/N] ");
        std::io::stderr().flush()?;
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        let answer = answer.trim().to_ascii_lowercase();
        if answer != "y" && answer != "yes" {
            return out_line("Cancelled");
        }
    }
    profile::delete(name)?;
    out_line(format!("Profile '{name}' deleted"))
}

/// Shared guards for `cp`/`rename`: valid names, distinct, source present,
/// destination free.
fn check_transfer_args(src: &str, dst: &str) -> Result<()> {
    profile::validate_name(src)?;
    profile::validate_name(dst)?;
    if src == dst {
        bail!("source and destination are the same profile");
    }
    if !profile::exists(src)? {
        bail!("profile '{src}' does not exist (see `envp list`)");
    }
    if profile::exists(dst)? {
        bail!("profile '{dst}' already exists (see `envp list`)");
    }
    Ok(())
}

/// `envp cp <src> <dst>`: copy a profile under a new name. Profiles are
/// self-contained files, so this is a controlled copy through the same
/// atomic-write path as every other save — no decryption, password unchanged.
pub fn cp(src: &str, dst: &str) -> Result<()> {
    check_transfer_args(src, dst)?;
    let blob = profile::read(src)?;
    profile::write(dst, &blob)?;
    out_line(format!("Profile '{src}' copied to '{dst}'"))
}

/// `envp rename <src> <dst>` (alias `mv`): rename in place.
pub fn rename(src: &str, dst: &str) -> Result<()> {
    check_transfer_args(src, dst)?;
    profile::rename(src, dst)?;
    out_line(format!("Profile '{src}' renamed to '{dst}'"))
}

/// `envp passwd <name>`: decrypt with the current password, re-encrypt with
/// a new one (v1 format unchanged; fresh salt/nonce per write).
pub fn passwd(name: &str, input: &mut PasswordInput) -> Result<()> {
    let (vars, _) = open_profile(name, input)?;

    let new = new_password(input)?;
    let derived = crypto::DerivedKey::fresh(new.as_str())?;
    save_profile(name, &vars, &derived)?;
    out_line(format!("Password changed for profile '{name}'"))
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
    fn set_assignments_split_on_first_equals() {
        let parsed = parse_assignments(&["A=1".into(), "B=x=y".into()], true).expect("parses");
        assert_eq!(parsed.len(), 2);
        match &parsed[0] {
            Assignment::Pair(k, v) => assert_eq!((k.as_str(), v.as_str()), ("A", "1")),
            Assignment::Prompt(_) => panic!("A=1 must not prompt"),
        }
        match &parsed[1] {
            Assignment::Pair(k, v) => assert_eq!((k.as_str(), v.as_str()), ("B", "x=y")),
            Assignment::Prompt(_) => panic!("B=x=y must not prompt"),
        }
    }

    #[test]
    fn set_bare_key_prompts_only_without_password_stdin() {
        let parsed = parse_assignments(&["TOKEN".into()], false).expect("parses");
        assert!(matches!(parsed.as_slice(), [Assignment::Prompt(k)] if k == "TOKEN"));
        let err = parse_assignments(&["TOKEN".into()], true).expect_err("rejected");
        assert!(err.to_string().contains("KEY=VALUE"), "{err}");
    }

    #[test]
    fn set_rejects_invalid_keys_before_prompting() {
        let err = parse_assignments(&["BAD KEY=1".into()], true).expect_err("rejected");
        assert!(err.to_string().contains("invalid variable name"), "{err}");
        let err = parse_assignments(&["9LIVES=1".into()], true).expect_err("rejected");
        assert!(err.to_string().contains("invalid variable name"), "{err}");
    }

    #[test]
    fn parse_key_list_trims_and_skips_empty() {
        assert_eq!(parse_key_list(" A , B,,C "), vec!["A", "B", "C"]);
        assert!(parse_key_list(",, ").is_empty());
    }

    /// Giving both --only and --except would silently drop --except (none of
    /// its keys can match the --only allowlist); rejected before any IO.
    #[test]
    fn only_and_except_are_mutually_exclusive() {
        let mut input = PasswordInput::from_flags(false, None).unwrap();
        let err = import_command(
            "test-profile",
            None,
            false,
            Some("A".into()),
            Some("B".into()),
            false,
            &mut input,
        )
        .expect_err("both flags must be rejected");
        assert!(err.to_string().contains("mutually exclusive"), "{err}");
    }

    #[test]
    fn shell_quotes_unsafe_args() {
        assert_eq!(shell_quote("plain"), "plain");
        assert_eq!(shell_quote(""), "''");
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
    }

    #[test]
    fn editor_splitting() {
        assert_eq!(split_editor(None), vec!["vi"]);
        assert_eq!(split_editor(Some("  ")), vec!["vi"]);
        assert_eq!(split_editor(Some("vim")), vec!["vim"]);
        // EDITOR may carry arguments (e.g. VS Code waits for the editor to close)
        assert_eq!(split_editor(Some("code --wait")), vec!["code", "--wait"]);
        assert_eq!(split_editor(Some("  emacs  -nw ")), vec!["emacs", "-nw"]);
    }

    /// Leftover edit files are only removed when stale: a file touched just
    /// now (a live concurrent edit session) must survive the sweep.
    #[test]
    fn edit_leftover_sweep_only_removes_stale_files() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("envpouch-edit-x.env");
        let other = dir.path().join("unrelated-edit-x.env");
        std::fs::write(&target, b"A=1\n").unwrap();
        std::fs::write(&other, b"A=1\n").unwrap();

        // an hour threshold keeps a file touched just now (live session)
        cleanup_edit_leftovers_in(dir.path(), std::time::Duration::from_secs(3600));
        assert!(target.exists(), "file younger than the threshold survives");
        assert!(other.exists(), "unrelated names are never touched");

        // ~zero threshold: everything matching the prefix counts as stale
        cleanup_edit_leftovers_in(dir.path(), std::time::Duration::from_nanos(1));
        assert!(!target.exists(), "stale leftovers are removed");
        assert!(other.exists(), "unrelated names are never touched");
    }

    /// A crafted/corrupted payload with invalid key names must fail cleanly
    /// at `run` time (never panic inside `Command::env`).
    #[test]
    fn stored_keys_validated_defensively() {
        let good = EnvVars::from_map(BTreeMap::from([("FOO".to_string(), "bar".to_string())]));
        assert!(validate_stored_keys(&good).is_ok());

        let bad = EnvVars::from_map(BTreeMap::from([
            ("FOO".to_string(), "bar".to_string()),
            ("BAD=KEY".to_string(), "x".to_string()),
        ]));
        let err = bad
            .iter()
            .filter(|(k, _)| envfile::validate_key(k, "").is_err())
            .count();
        assert_eq!(err, 1);
        let msg = validate_stored_keys(&bad).unwrap_err().to_string();
        assert!(msg.contains("BAD=KEY"), "error names the key only: {msg}");
        assert!(!msg.contains("x\""), "error never contains values: {msg}");
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
        let vars = EnvVars::from_map(BTreeMap::from([
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

    /// --password-file serves one line per prompt, in prompt order, and
    /// fails cleanly when the file runs out of lines (same contract as
    /// --password-stdin).
    #[test]
    fn password_file_serves_one_line_per_prompt() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("pw");
        std::fs::write(&p, "first-pw\nsecond-pw").unwrap(); // no trailing newline
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let mut input = PasswordInput::from_flags(false, Some(p)).unwrap();
        assert!(input.is_explicit());
        assert_eq!(input.next_password().unwrap().as_str(), "first-pw");
        assert_eq!(input.next_password().unwrap().as_str(), "second-pw");
        let err = input.next_password().unwrap_err().to_string();
        assert!(err.contains("fewer lines"), "{err}");
    }

    #[test]
    fn password_flags_are_mutually_exclusive() {
        let err = PasswordInput::from_flags(true, Some(PathBuf::from("/x")))
            .err()
            .expect("both flags must be rejected")
            .to_string();
        assert!(err.contains("mutually exclusive"), "{err}");
        // stdin mode still works and reserves stdin
        let input = PasswordInput::from_flags(true, None).unwrap();
        assert!(input.is_explicit());
        assert!(input.reserves_stdin());
        // plain interactive mode touches neither
        let input = PasswordInput::from_flags(false, None).unwrap();
        assert!(!input.is_explicit());
        assert!(!input.reserves_stdin());
    }

    /// A missing password file fails only when a password is actually
    /// needed (lazy load: `list`-style commands never read the file).
    #[test]
    fn password_file_missing_fails_only_on_use() {
        let mut input =
            PasswordInput::from_flags(false, Some(PathBuf::from("/nonexistent/envp/pass")))
                .unwrap();
        let err = input.next_password().unwrap_err().to_string();
        assert!(err.contains("not found"), "{err}");
    }

    /// CRLF line endings and blank lines: CRLF is accepted per line, a blank
    /// line in the middle is a hard error (an empty password is never right).
    #[test]
    fn password_file_crlf_and_blank_lines() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("pw");
        std::fs::write(&p, "first\r\n\r\nsecond\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let mut input = PasswordInput::from_flags(false, Some(p)).unwrap();
        assert_eq!(input.next_password().unwrap().as_str(), "first");
        let err = input.next_password().unwrap_err().to_string();
        assert!(err.contains("empty line"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn password_file_rejects_loose_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("pw");
        std::fs::write(&p, "secret-pw\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        let mut input = PasswordInput::from_flags(false, Some(p.clone())).unwrap();
        let err = input.next_password().unwrap_err().to_string();
        assert!(err.contains("chmod 600"), "{err}");

        // tighten and retry: same input object recovers on the next prompt
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(input.next_password().unwrap().as_str(), "secret-pw");
    }

    #[test]
    fn password_file_rejects_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("pw");
        std::fs::write(&p, "\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let mut input = PasswordInput::from_flags(false, Some(p)).unwrap();
        let err = input.next_password().unwrap_err().to_string();
        assert!(err.contains("is empty"), "{err}");
    }
}
