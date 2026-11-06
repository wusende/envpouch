# envpouch

[![CI](https://github.com/wusende/envpouch/actions/workflows/ci.yml/badge.svg)](https://github.com/wusende/envpouch/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/envpouch.svg)](https://crates.io/crates/envpouch)
[![npm](https://img.shields.io/npm/v/envpouch.svg)](https://www.npmjs.com/package/envpouch)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.85%2B%20(edition%202024)-orange)](https://github.com/wusende/envpouch)

Encrypted environment-variable profile manager for macOS, Linux, and
Windows.

Store `.env` files as encrypted, password-protected profiles, then export them,
edit them, or — the main use case — run any program with those variables
injected:

```sh
envpouch import prod --from .env.production
envpouch run prod -- ./start-server.sh
```

Every decrypting command obtains the password via the interactive prompt, the
OS keychain cache (`envpouch unlock`), or the global `--password-stdin` flag
for scripts/CI (see [Scripts / CI](#scripts--ci)).

## Install / build

Any of these:

```sh
npm install -g envpouch     # prebuilt binary, no toolchain
cargo install envpouch      # from crates.io, needs a Rust toolchain
```

Prebuilt binaries are also on
[Releases](https://github.com/wusende/envpouch/releases) — Linux (amd64,
glibc 2.35+; arm64, glibc 2.39+), macOS (universal2), Windows (amd64) — put
one on your `PATH`. The npm package is a thin launcher around that same
binary; musl/Alpine and Windows arm64 are not covered, use `cargo install`
there.

`cargo install` lands in `~/.cargo/bin`, which sudo can't see. So if you later
run `sudo envpouch run prod -- ...`, use `sudo ~/.cargo/bin/envpouch ...`.

From a checkout (requires Rust 1.85+, edition 2024):

```sh
cargo install --path .    # installs to ~/.cargo/bin (usually already on PATH)
# or just build locally:
cargo build --release     # binary at ./target/release/envpouch
cargo test --release
```

After installing, verify with:

```sh
envpouch --version
envpouch list               # first run prints how to create a profile
```

## Command reference

| Command | Purpose | Password? |
|---|---|---|
| `envpouch import <name> (--from <file> \| --from-env) [--merge]` | Import variables into an encrypted profile | yes |
| `envpouch show <name> [--reveal]` | Show variables (masked by default) | yes |
| `envpouch export <name> [-o <file>]` | Export as .env text (stdout without `-o`) | yes |
| `envpouch edit <name>` | Edit variables in `$EDITOR` (default `vi`) | yes |
| `envpouch fpm-snippet <name>` | Emit php-fpm pool `env[...]` lines | yes |
| `envpouch diff <a> <b>` | Compare two profiles (masked values) | yes |
| `envpouch run <name> [--clean] [--dry-run] [--detach] -- <cmd> [args...]` | Run a command with the variables injected | yes |
| `envpouch list` | List profiles | no |
| `envpouch rm <name>` | Delete a profile | no |
| `envpouch passwd <name>` | Change the profile password | yes |
| `envpouch unlock <name> [--ttl <seconds>]` | Verify + cache the password in the OS keychain (default TTL 900 s) | yes |
| `envpouch lock <name>` | Remove the cached keychain entry | no |
| `envpouch complete --shell <bash\|zsh\|fish\|...>` | Print shell completion script | no |

**Global flag**: `--password-stdin` works with every password-requiring
command, before or after the subcommand. Passwords are read from stdin, one
line per prompt, in prompt order (`passwd` reads two lines: current then new;
`diff` reads one per profile).

### Import

- `--from <file>` parses a `.env` file (comments, `export` prefix, quoted and
  multi-line values are supported).
- `--from-env` imports variables from the current environment, minus a
  hardcoded exclusion list (`PATH`, `HOME`, `SSH_*`, `LC_*`, `TERM*`, …) so
  you don't accidentally store system/SSH variables. `--only A,B` imports
  exactly the listed keys; `--except A,B` excludes more keys on top of the
  default list.
- Importing into an existing profile fails by default; use `--merge` to fold
  new values into it (same-name keys take the new value).
- **dotenvy semantics**: `$VAR` references inside double-quoted or bare values
  are expanded at import time (against earlier definitions and the actual
  environment); single-quoted values are stored literally. If a value looks
  like `SECRET_TOKEN=pa$$w0rd`, write it as `SECRET_TOKEN='pa$$w0rd'` in your
  `.env` file. envpouch prints a note on import when values contain `$`.
- **Export text is normalized**: key order (alphabetical) and quoting differ
  from the source file; the key/value semantics are preserved exactly.

### Run

- **Overlay (default)**: child gets the full current environment; profile
  variables override same-name variables.
- **`--clean`**: child gets only a minimal base environment plus the profile
  variables — nothing else. Unix base keys: `PATH`, `HOME`, `TMPDIR`, `USER`,
  `LOGNAME`, `SHELL`, `TERM`. Windows base keys: `PATH`, `USERPROFILE`,
  `TMP`, `TEMP`, `SystemRoot`, `ComSpec`. Missing keys are skipped, never
  invented.
- **`--dry-run`**: prints the command, mode, injected key names (never
  values) and an environment-size estimate; executes nothing.
- **`--detach`**: starts the command detached and exits immediately; the
  child keeps running after envpouch exits (unix: new session via `setsid`;
  Windows: child naturally outlives the parent).
- **Exit codes** (a stable interface for scripts):

  | Code | Meaning |
  |---|---|
  | 0 | success |
  | 1 | envpouch error (decryption, I/O, bad usage of args) |
  | 2 | usage error (clap) |
  | 126 | target has no execute permission (unix) |
  | 127 | target not found |
  | 128+N | child killed by signal N (Ctrl-C → 130) (unix) |
  | other | child's own exit code, passed through 1:1 |

  **Unix**: terminal signals (Ctrl-C, etc.) are caught by envpouch and
  forwarded to the child's process group — the same model as
  `timeout`/`docker run` — and the child runs with core dumps disabled
  (`RLIMIT_CORE=0`).
  **Windows**: the child shares envpouch's console group, so Ctrl-C reaches it
  natively; there is no separate signal-forwarding layer, and the
  process-group/core-dump hardening does not apply.

### Scripts / CI

`--password-stdin` is a global flag: it works with **every** password-requiring
command, so whole pipelines can run without a tty. Passwords are read from
stdin one line per prompt, in prompt order.

```sh
# feed the password on stdin (first line); avoid ENVPOUCH_PASSPHRASE-style
# env vars on purpose: /proc/<pid>/environ is readable by same-user processes
printf '%s\n' "$MY_SECRET_PASSPHRASE" | envpouch run prod --password-stdin -- ./deploy.sh

# the flag may also come before the subcommand, and other commands take it too
printf '%s\n' "$PW" | envpouch --password-stdin export prod -o /tmp/prod.env
printf '%s\n' "$PW" | envpouch --password-stdin fpm-snippet prod >> pool.conf

# commands that would prompt twice read two lines, in prompt order:
#   passwd: current password first, then the new one
printf '%s\n%s\n' "$OLD_PW" "$NEW_PW" | envpouch passwd prod --password-stdin
#   diff: one line per profile (unless the keychain cache answers first)
printf '%s\n%s\n' "$PW_A" "$PW_B" | envpouch diff a b --password-stdin

# creating a profile headless reads the new password once (no confirmation)
printf '%s\n' "$NEW_PW" | envpouch import prod --from .env.production --password-stdin

# cache the password in the OS keychain for 15 minutes
envpouch unlock prod --ttl 900
envpouch run prod -- ./dev-server.sh          # no prompt
envpouch lock prod                             # drop it now
```

## PHP-FPM notes

If you wrap `php-fpm` with `envpouch run`, three behaviors bite everyone:

1. **`clear_env=yes` (FPM default) wipes the environment for workers.**
   envpouch's injection only reaches the FPM *master*; `getenv()` in PHP returns
   nothing. Fixes, in order of preference:
   - generate pool lines with `envpouch fpm-snippet prod >> www.conf`
     (adds `env[KEY] = value` per variable), or
   - set `clear_env = no` in the pool so workers inherit the master's
     environment.
2. **`clear_env=yes` also clears `PATH`**, so PHP's `exec()`/`shell_exec()`
   find no binaries. Add `env[PATH] = ...` manually — `fpm-snippet` reminds
   you in its footer comment.
3. **`daemonize=yes` (FPM default)**: the master forks into the background
   and envpouch's direct child exits immediately, so envpouch returns right away.
   **That return is success, not a failure.** With `daemonize = no`
   (recommended under systemd/containers), envpouch stays in the foreground.

`fpm-snippet` skips values containing newlines, quotes values containing
`\ " ; #`, and warns about `$` (variable-reference semantics inside fpm
config). It never prints values to stderr.

## Security model

**Protects**: data at rest on disk (lost laptops, backups, accidentally
committed directories). Profiles are AES-256-GCM encrypted with a key derived
from your password via Argon2id (m=19 MiB, t=2, p=1); every write uses a
fresh random salt + nonce; the file header is covered by the GCM AAD so
tampering fails decryption. Profile files are mode `0600`, the storage
directory `0700`, writes are atomic (temp file + rename), and decrypted
plaintext is zeroized when dropped.

**Does not protect** (no tool on a general-purpose OS honestly can):

- the same user reading `/proc/<pid>/environ` (Linux) or `ps eww` of your
  running child processes;
- root, kernel-level attackers, memory dumps, screen capture, keyloggers;
- other variables in your shell environment that you did not move into a
  profile (use `--clean` to shrink the set given to a child).

Mitigations built in: child core dumps are disabled; passwords are never
accepted via environment variables; `--password-stdin` exists because process
environments are readable by same-user processes.

**There is no password recovery.** If you lose a profile's password, its data
is unrecoverable (authenticated encryption has no backdoor). envpouch warns you
when setting a password; keep backups of the password in your password
manager.

## Storage layout

```
~/.envpouch/profiles/<name>.envpouch
```

File format v1: `magic "ENVPOUCH" | version | salt(16B) | argon2 params |
nonce(12B) | var_count | updated_at | AES-256-GCM ciphertext`. The variable
count and update time are plaintext metadata so `envpouch list` works without a
password; everything else is ciphertext.

## Operations

**Storage location override** — for containers, service accounts, or
multi-instance isolation, point envpouch at a different base directory:

```sh
export ENVPOUCH_HOME=/var/lib/myapp/envpouch   # profiles live in $ENVPOUCH_HOME/profiles
```

**Audit trail** (off by default) — set `ENVPOUCH_AUDIT=1` to append one line per
decrypting invocation to `$ENVPOUCH_HOME/audit.log`:

```sh
export ENVPOUCH_AUDIT=1
envpouch run prod -- ./deploy.sh
tail -1 "$HOME/.envpouch/audit.log"    # 2026-11-06T09:12:00+0800	run	prod	exit=0
```

The audit log records timestamp, subcommand, profile name and exit code
only — never variable keys or values. Writes are best-effort: a failed audit
write warns on stderr but does not fail the command.

**Shell completions**:

```sh
envpouch complete --shell bash  > ~/.local/share/bash-completion/completions/envpouch
envpouch complete --shell zsh   > "${fpath[1]}/_envpouch"   # zsh
envpouch complete --shell fish  > ~/.config/fish/completions/envpouch.fish
```

**Prebuilt binaries** — tagged releases (`v*`) publish glibc binaries
(x86_64/aarch64 Linux), a universal2 macOS build, and an x86_64 Windows
build (MSVC, `.zip`) with SHA-256 checksums on the GitHub Releases page;
the same binaries are bundled in the npm package;
`scripts/fuzz_cli.sh` and `cargo test` gate every CI run.

**Backup / restore** — profile files are self-contained encrypted blobs;
backing up the profiles directory with any file-level tool is sufficient.
Keep profile passwords in a password manager: a lost password cannot be
recovered from any backup (they are encrypted with the same password).

## Known limitations

- Exported/edited text is normalized (alphabetical keys, canonical quoting);
  comments and original formatting of the source `.env` are not preserved.
- `edit` keeps a plaintext temp file (mode 0600, in `$TMPDIR`) only while the
  editor is open, and cleans up leftovers from killed sessions on the next
  run. `$EDITOR` may carry arguments (e.g. `EDITOR='code --wait'`); it is
  split on whitespace, so an editor path containing spaces cannot be quoted.
- **Ctrl-Z under `run` (unix)**: Ctrl-Z stops the child, but envpouch itself
  keeps running and holds the terminal — the shell never sees a stopped job,
  so `fg` cannot resume it. Ctrl-C still works (it kills the stopped child
  and envpouch exits 130); to resume the child instead, run
  `kill -CONT <child-pid>` from another terminal.
- **Windows differences** (functional but not identical to unix): no
  signal-forwarding layer — Ctrl-C reaches the child natively via the shared
  console group, and 128+N exit codes do not occur; core dumps are a unix
  concept so the `RLIMIT_CORE` hardening does not apply; file modes are NTFS
  ACLs, so the explicit 0600/0700 hardening is a no-op (use ACLs on the
  profile directory if you need per-user restrictions); the keychain cache
  uses Windows Credential Manager via `envpouch unlock`/`envpouch lock`.
