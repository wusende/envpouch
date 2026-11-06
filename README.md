# envrun

Encrypted environment-variable profile manager for macOS/Linux.

Store `.env` files as encrypted, password-protected profiles, then export them,
edit them, or — the main use case — run any program with those variables
injected:

```sh
envrun import prod --from .env.production
envrun run prod -- ./start-server.sh
```

Every decrypting command obtains the password via the interactive prompt, the
OS keychain cache (`envrun unlock`), or `--password-stdin` for scripts.

## Install / build

Requires Rust 1.85+ (edition 2024).

```sh
cargo build --release
# binary at ./target/release/envrun
cargo test --release
```

## Command reference

| Command | Purpose | Password? |
|---|---|---|
| `envrun import <name> (--from <file> \| --from-env) [--merge]` | Import variables into an encrypted profile | yes |
| `envrun show <name> [--reveal]` | Show variables (masked by default) | yes |
| `envrun export <name> [-o <file>]` | Export as .env text (stdout without `-o`) | yes |
| `envrun edit <name>` | Edit variables in `$EDITOR` (default `vi`) | yes |
| `envrun fpm-snippet <name>` | Emit php-fpm pool `env[...]` lines | yes |
| `envrun diff <a> <b>` | Compare two profiles (masked values) | yes |
| `envrun run <name> [--clean] [--dry-run] [--detach] [--password-stdin] -- <cmd> [args...]` | Run a command with the variables injected | yes |
| `envrun list` | List profiles | no |
| `envrun rm <name>` | Delete a profile | no |
| `envrun passwd <name>` | Change the profile password | yes |
| `envrun unlock <name> [--ttl <seconds>]` | Verify + cache the password in the OS keychain (default TTL 900 s) | yes |
| `envrun lock <name>` | Remove the cached keychain entry | no |

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
  `.env` file. envrun prints a note on import when values contain `$`.
- **Export text is normalized**: key order (alphabetical) and quoting differ
  from the source file; the key/value semantics are preserved exactly.

### Run

- **Overlay (default)**: child gets the full current environment; profile
  variables override same-name variables.
- **`--clean`**: child gets only `PATH`, `HOME`, `TMPDIR`, `USER`, `LOGNAME`,
  `SHELL`, `TERM` (when present in your environment) plus the profile
  variables — nothing else.
- **`--dry-run`**: prints the command, mode, injected key names (never
  values) and an environment-size estimate; executes nothing.
- **`--detach`**: starts the command in a new session (like nohup) and exits
  immediately; the child keeps running after the terminal closes.
- **Exit codes** (a stable interface for scripts):

  | Code | Meaning |
  |---|---|
  | 0 | success |
  | 1 | envrun error (decryption, I/O, bad usage of args) |
  | 2 | usage error (clap) |
  | 126 | target has no execute permission |
  | 127 | target not found |
  | 128+N | child killed by signal N (Ctrl-C → 130) |
  | other | child's own exit code, passed through 1:1 |

  Terminal signals (Ctrl-C, etc.) are caught by envrun and forwarded to the
  child's process group — the same model as `timeout`/`docker run`. The
  child also runs with core dumps disabled (`RLIMIT_CORE=0`).

### Scripts / CI

```sh
# feed the password on stdin (first line); avoid ENVRUN_PASSPHRASE-style
# env vars on purpose: /proc/<pid>/environ is readable by same-user processes
printf '%s\n' "$MY_SECRET_PASSPHRASE" | envrun run prod --password-stdin -- ./deploy.sh

# cache the password in the OS keychain for 15 minutes
envrun unlock prod --ttl 900
envrun run prod -- ./dev-server.sh          # no prompt
envrun lock prod                             # drop it now
```

## PHP-FPM notes

If you wrap `php-fpm` with `envrun run`, three behaviors bite everyone:

1. **`clear_env=yes` (FPM default) wipes the environment for workers.**
   envrun's injection only reaches the FPM *master*; `getenv()` in PHP returns
   nothing. Fixes, in order of preference:
   - generate pool lines with `envrun fpm-snippet prod >> www.conf`
     (adds `env[KEY] = value` per variable), or
   - set `clear_env = no` in the pool so workers inherit the master's
     environment.
2. **`clear_env=yes` also clears `PATH`**, so PHP's `exec()`/`shell_exec()`
   find no binaries. Add `env[PATH] = ...` manually — `fpm-snippet` reminds
   you in its footer comment.
3. **`daemonize=yes` (FPM default)**: the master forks into the background
   and envrun's direct child exits immediately, so envrun returns right away.
   **That return is success, not a failure.** With `daemonize = no`
   (recommended under systemd/containers), envrun stays in the foreground.

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
is unrecoverable (authenticated encryption has no backdoor). envrun warns you
when setting a password; keep backups of the password in your password
manager.

## Storage layout

```
~/.envrun/profiles/<name>.envrun
```

File format v1: `magic "ENVRUN" | version | salt(16B) | argon2 params |
nonce(12B) | var_count | updated_at | AES-256-GCM ciphertext`. The variable
count and update time are plaintext metadata so `envrun list` works without a
password; everything else is ciphertext.

## Known limitations

- v1 supports macOS and Linux only.
- Exported/edited text is normalized (alphabetical keys, canonical quoting);
  comments and original formatting of the source `.env` are not preserved.
- `edit` keeps a plaintext temp file (mode 0600, in `$TMPDIR`) only while the
  editor is open, and cleans up leftovers from killed sessions on the next run.
