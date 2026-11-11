//! Integration coverage for the unix foreground model: `envp run` must
//! replace itself with the target (exec), not sit between the target and its
//! supervisor. A wrapper would break MainPID, process-group signals and the
//! direct exit status used by systemd/supervisord.
#![cfg(unix)]

use std::ffi::OsString;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn envp_bin() -> &'static str {
    env!("CARGO_BIN_EXE_envp")
}

/// Create a profile through the public CLI, with a 0600 password file, and
/// return the password-file path (the temp dir owns the storage).
fn make_profile(dir: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let pw = dir.join("pw");
    std::fs::write(&pw, "integration-password\n").unwrap();
    std::fs::set_permissions(&pw, std::fs::Permissions::from_mode(0o600)).unwrap();

    let out = Command::new(envp_bin())
        .env("ENVPOUCH_HOME", dir.join("home"))
        .arg("--password-file")
        .arg(&pw)
        .args(["set", "svc", "KEY=value"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "set failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    pw
}

fn run_args(pw: &Path, command: &[&str]) -> Vec<OsString> {
    let mut args: Vec<OsString> = vec![
        "run".into(),
        "svc".into(),
        "--password-file".into(),
        pw.as_os_str().to_os_string(),
        "--".into(),
    ];
    args.extend(command.iter().map(OsString::from));
    args
}

/// The process the caller spawned is the process that runs the command: same
/// PID, same environment, and the target's exit code (not a wrapper's).
#[test]
fn run_execs_in_place_and_preserves_pid_and_exit_code() {
    let dir = tempfile::tempdir().unwrap();
    let pw = make_profile(dir.path());
    let child = Command::new(envp_bin())
        .env("ENVPOUCH_HOME", dir.path().join("home"))
        .args(run_args(
            &pw,
            &["/bin/sh", "-c", r#"printf '%s %s' "$$" "$KEY"; exit 7"#],
        ))
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let pid = child.id();
    let out = child.wait_with_output().unwrap();

    assert_eq!(
        out.status.code(),
        Some(7),
        "target exit code must pass through"
    );
    let text = String::from_utf8(out.stdout).unwrap();
    let (app_pid, key) = text.split_once(' ').expect("pid and key output");
    assert_eq!(
        app_pid.parse::<u32>().unwrap(),
        pid,
        "exec must keep envp's PID"
    );
    assert_eq!(key, "value", "profile variables must be injected");
}

/// Password input must not eat the bytes after the password line: the target
/// inherits the same fd 0, so `--password-stdin` plus a data pipe has to
/// leave the data for the application to read.
#[test]
fn run_leaves_stdin_data_for_the_command() {
    let dir = tempfile::tempdir().unwrap();
    make_profile(dir.path());
    let mut child = Command::new(envp_bin())
        .env("ENVPOUCH_HOME", dir.path().join("home"))
        .args(["run", "svc", "--password-stdin", "--", "/bin/cat"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"integration-password\nhello-from-stdin\n")
        .unwrap();
    let out = child.wait_with_output().unwrap();

    assert!(out.status.success());
    assert_eq!(out.stdout, b"hello-from-stdin\n");
}

/// With no wrapper, a signal-killed target keeps signal semantics: the
/// supervisor sees `code=killed, signal=TERM`, not envp's 143 translation.
#[test]
fn run_preserves_signal_exit_status() {
    use std::os::unix::process::ExitStatusExt;

    let dir = tempfile::tempdir().unwrap();
    let pw = make_profile(dir.path());
    let status = Command::new(envp_bin())
        .env("ENVPOUCH_HOME", dir.path().join("home"))
        .args(run_args(&pw, &["/bin/sh", "-c", "kill -TERM $$"]))
        .status()
        .unwrap();

    assert_eq!(status.signal(), Some(libc::SIGTERM));
}

/// `unlock` caches the verified key so `show` runs with no password source
/// at all; `lock` removes the cache again (file-level proof: the sidecar
/// appears and disappears). The re-prompt itself needs a tty, so the
/// "prompts again after lock" behavior is covered by scripts/fuzz_cli.sh
/// (no-tty prompt failure) plus the unit tests, not here.
#[test]
fn unlock_cache_answers_and_lock_removes_it() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let pw = make_profile(dir.path());
    let sidecar = home.join("profiles").join("svc.envpouch.unlock");
    assert!(!sidecar.exists(), "no cache entry before unlock");

    let out = Command::new(envp_bin())
        .env("ENVPOUCH_HOME", &home)
        .arg("--password-file")
        .arg(&pw)
        .args(["unlock", "svc", "--ttl", "600"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "unlock failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(sidecar.exists(), "unlock must write the cache sidecar");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("unlocked"), "{stdout}");
    assert!(stdout.contains("expires"), "{stdout}");

    // No password source at all — the cache must answer, prompting nothing
    let out = Command::new(envp_bin())
        .env("ENVPOUCH_HOME", &home)
        .stdin(Stdio::null())
        .args(["show", "svc"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "cached show failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("KEY"));

    let out = Command::new(envp_bin())
        .env("ENVPOUCH_HOME", &home)
        .args(["lock", "svc"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "lock failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!sidecar.exists(), "lock must remove the cache sidecar");

    // Locked again: a wrong password must be rejected by the profile itself
    // (deterministic, tty-free proof that the cache no longer answers)
    let bad = dir.path().join("bad-pw");
    std::fs::write(&bad, "wrong-password\n").unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&bad, std::fs::Permissions::from_mode(0o600)).unwrap();
    let out = Command::new(envp_bin())
        .env("ENVPOUCH_HOME", &home)
        .arg("--password-file")
        .arg(&bad)
        .args(["show", "svc"])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("wrong password"), "{stderr}");
}
