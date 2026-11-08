# envpouch

[![CI](https://github.com/wusende/envpouch/actions/workflows/ci.yml/badge.svg)](https://github.com/wusende/envpouch/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/envpouch.svg)](https://crates.io/crates/envpouch)
[![npm](https://img.shields.io/npm/v/envpouch.svg)](https://www.npmjs.com/package/envpouch)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Encrypted environment-variable profiles for macOS, Linux and Windows.
Turn a `.env` file into a password-protected profile, then run any command
with those variables injected:

```sh
envp import prod --from .env.production
envp run prod ./start-server.sh
```

The package is `envpouch`; the command it installs is `envp`.

## Why not just keep the `.env` file

Plaintext `.env` files leak through the three channels nobody watches:

| Leak channel | What happens | envpouch |
|---|---|---|
| Git commits | `.env.production` lands in a repo; every fork and clone now holds live secrets | profiles are AES-256-GCM encrypted files; the repo never sees values |
| Backups & sync | Time Machine, Nextcloud, `rsync` jobs snapshot your home dir, secrets and all | a stolen profile file is inert without the password (Argon2id, no recovery) |
| Long-lived processes | a service runs with secrets in its environment for weeks; any same-user process can read them (`/proc/<pid>/environ`) | `envp run` **execs** the app in place — no wrapper process, no lingering plaintext; core dumps off by default |

What it does **not** protect against: root, keyloggers, and the same user
reading a running process's environment. No tool on a general-purpose OS can.

**Running AI agents?** [keysink](https://github.com/wusende/keysink) is the
companion tool from the same author: a one-way gateway that keeps real API
keys out of the agent entirely (the agent gets a revocable virtual key).
envpouch is the file-based, single-command counterpart.

## How it compares

| | envpouch | dotenvx | direnv | sops |
|---|---|---|---|---|
| Encryption at rest | ✅ per-profile, password-derived | ✅ (private-key based) | ❌ | ✅ (KMS / age key) |
| No plaintext on disk ever | ✅ | ❌ (encrypts on demand) | ❌ | ✅ |
| Per-command injection (`run`) | ✅ exec, no wrapper | ✅ | ✅ shell hook | ❌ (decrypts to file) |
| Needs a key management service | ❌ just a password | ❌ | — | usually |
| Multi-profile, one binary | ✅ | ✅ | ❌ per-directory | ❌ file-per-operation |

Pick envpouch when you want `.env`-simplicity with real at-rest encryption
and no infra.

## Install

```sh
npm install -g envpouch    # prebuilt binary, no toolchain needed
cargo install envpouch     # from source, needs Rust 1.85+
```

Check with `envp --version`. Prebuilt binaries for Linux (glibc and static
musl), macOS (one binary for Intel and Apple Silicon) and Windows are also
on the [releases page](https://github.com/wusende/envpouch/releases). On
Windows arm64, use `cargo install`.

## Basics

```sh
envp import prod --from .env.production   # new profile, prompts for a password
envp list                                 # list profiles, no password needed
envp show prod                            # variables, values masked
envp run prod ./start-server.sh           # decrypt and run with them set
```

Each profile is one encrypted file under `~/.envpouch/profiles/` — copy
that directory to back everything up (see [Files](#files)).

Mutating commands (`import`, `set`, `unset`, `edit`, `passwd`, `rm`, `cp`,
`rename`) hold an exclusive lock on `<name>.envpouch.lock` while they work
(unix), so concurrent updates queue up instead of silently overwriting each
other; after ~5 seconds of waiting the command fails with a "busy" error.
The 0-byte lock files are normal, ignored by `envp list`, and copying or
deleting them is harmless.

Every command that decrypts gets the password one of three ways: the
interactive prompt (default), `--password-stdin` reading it from stdin
for scripts, or `--password-file <file>` reading one password per line
from a file only your user can read (mode 0600) for services (see
[systemd / supervisord](#systemd--supervisord)).

**There is no password recovery.** A lost password means the profile is
gone. Keep passwords in a password manager.

## Commands

All commands except `list`, `rm`, `cp`, `rename` and `complete` need the
password. `--password-stdin` and `--password-file` are global flags that
work with every one of them, before or after the subcommand (the two are
mutually exclusive).

| Command | What it does |
|---|---|
| `import <name> --from <file> [--merge]` | Create a profile from a `.env` file; `--merge` folds into an existing one |
| `import <name> --from-env [--only A,B \| --except A,B]` | Import from the current environment; a default list (`PATH`, `HOME`, `SSH_*`, …) is always excluded |
| `show <name> [--reveal]` | Print variables, masked by default |
| `export <name> [-o <file>]` | Print `.env` text to stdout, or write it to a file |
| `edit <name>` | Edit in `$EDITOR` |
| `set <name> KEY=VALUE...` | Add or replace keys; a bare `KEY` prompts for the value with hidden input |
| `unset <name> KEY...` | Remove keys |
| `diff <a> <b>` | Compare two profiles, masked |
| `run <name> <cmd> [args...]` | Run a command with the variables injected |
| `fpm-snippet <name>` | Print php-fpm pool `env[...]` lines |
| `list` / `rm` / `passwd` / `cp` / `rename` | List, delete, change password, copy, rename |
| `complete --shell <shell>` | Print shell completions |

A bare `KEY` in `set` is the safe way to store secrets: `KEY=VALUE` on the
command line is visible to same-user processes and lands in shell history.

## run

```sh
envp run prod ./deploy.sh
envp run prod --clean python app.py      # only a minimal base env plus profile vars
envp run prod --dry-run ./deploy.sh      # print what would run, never values
envp run prod --allow-core-dumps ./srv   # keep core dumps (LimitCORE= applies)
```

For an ad-hoc background process, `nohup envp run prod ./server &` works
(with `--password-file`; a backgrounded job cannot prompt). envp turns
into the app and leaves nothing behind. Use systemd/supervisord when you
need restarts and supervision.

- By default the command gets your full environment with the profile
  variables on top. `--clean` gives it only `PATH`, `HOME`, `USER` and a
  few base variables plus the profile.
- Everything after the command name goes to it untouched. `--` is
  only needed when the command itself starts with an envp option, e.g.
  `envp run prod -- --clean`.
- On unix, after decrypting envp **execs the command in place**: envp
  turns into the command itself, keeping the same PID, process group and
  terminal. Nothing named envp stays in the process tree, so
  Ctrl-C/Ctrl-Z, supervisor signals and the exit status reach the
  application directly.
- The exit status you get is the application's own. envp itself exits
  nonzero only for its own errors: `1` such as a wrong password, `2` a
  usage error, `126` no execute permission, `127` command not found.
- Core dumps are disabled for the command by default (a crash cannot
  dump memory that holds the decrypted variables); `--allow-core-dumps`
  keeps the supervisor's limits instead (systemd `LimitCORE=`,
  `ulimit -c`).

## Scripts / CI / services

```sh
printf '%s\n' "$PW" | envp run prod --password-stdin ./deploy.sh
printf '%s\n' "$PW" | envp --password-stdin export prod -o /tmp/prod.env
envp run prod --password-file /etc/myapp/envp.pass ./deploy.sh   # services
```

One stdin line — or one file line — per password prompt, in prompt
order: `passwd` reads the current password then the new one, `diff`
reads one per profile. On unix, `run` consumes exactly one line and
leaves the rest of stdin to the command. envp deliberately has no password
environment variable, since process environments are readable by
same-user processes. `--password-file` refuses group/world-readable
files (chmod 600) so the file cannot silently become the weak link.

## systemd / supervisord

Every start and every automatic restart needs the password unattended —
there is no interactive tty in a system service — so use
`--password-file` (or a systemd credential).

### systemd

```ini
[Service]
User=myapp
StateDirectory=myapp
Environment=ENVPOUCH_HOME=/var/lib/myapp/envpouch
LoadCredentialEncrypted=envp.pass:/etc/myapp/envp.pass.enc
ExecStart=/usr/local/bin/envp run prod --password-file ${CREDENTIALS_DIRECTORY}/envp.pass -- /usr/bin/myapp
Restart=on-failure
RestartSec=5
```

Create the encrypted credential with
`systemd-creds encrypt --name=envp.pass /etc/myapp/envp.pass /etc/myapp/envp.pass.enc`.
`LoadCredential*` exposes it at mode 0400 in `$CREDENTIALS_DIRECTORY`,
which `--password-file` accepts. With `LoadCredential=` the source may
stay root-owned 0600; systemd copies it for the service user. If you
point `--password-file` at a plain path directly instead, `chmod 600`
and own it as the service user; envp refuses group/world-readable
password files.

- `StateDirectory=myapp` creates `/var/lib/myapp` with the right owner.
  Create the profile itself as `myapp` (or chown the profile files) under
  `ENVPOUCH_HOME`, otherwise the 0600 files are unreadable to the service.
- `Type=notify` works normally: the application is MainPID because envp
  execs it.
- Do not use `--clean` under systemd: it drops `NOTIFY_SOCKET`,
  `WATCHDOG_USEC`, `JOURNAL_STREAM` and other systemd-provided variables.
- Every start pays one Argon2id derivation (tens to hundreds of
  milliseconds). Give crash-looping services `RestartSec` and
  `StartLimitBurst` headroom so this delay does not eat the start budget.
- The application receives SIGTERM directly; if it dies from the signal,
  systemd reports `code=killed, signal=TERM` (conventional), not a
  wrapper's 143.
- Core dumps are disabled for the application by default; add
  `--allow-core-dumps` when systemd's `LimitCORE=` should apply.

For unattended daemon secrets, also weigh systemd's native
`LoadCredential=` / `LoadCredentialEncrypted=`. envpouch's edge is the
encrypted profile storage — backups and accidental commits stay inert —
at the cost of one Argon2id derivation per start; after that the process
is the application.

### supervisord

With the exec model, supervisord sees the application itself: envp is
gone after startup, so `stopasgroup`/`killasgroup`, `stopwaitsecs`,
autostart and exit-status handling behave exactly as for a normal
program.

- Use `--password-file` (0600) for unattended starts.
- Do not use `--clean` if the app relies on supervisor-provided
  environment variables.
- The application must stay in the foreground (no self-daemonizing);
  that is a supervisord requirement, not an envp one.

## php-fpm

Two php-fpm defaults defeat injected variables; `fpm-snippet` exists for
this:

- `clear_env=yes` (the default) wipes the environment for workers, so
  `getenv()` in PHP returns nothing. Append
  `envp fpm-snippet prod >> www.conf` to emit one `env[KEY] = value` line
  per variable, or set `clear_env = no` in the pool.
- `daemonize=yes` (the default) forks the master into the background and
  the original process exits, so the supervisor sees the service stop.
  Under systemd/supervisord, use `daemonize = no`.

## Files

Profiles live in `~/.envpouch/profiles/<name>.envpouch`, each a
self-contained encrypted file. Back them up by copying the directory.

```sh
export ENVPOUCH_HOME=/var/lib/myapp/envpouch   # move storage elsewhere
export ENVPOUCH_AUDIT=1                        # log each decrypting command to audit.log
```

The audit log records timestamp, command, profile and exit code, never
variable names or values.

## Shell completion

```sh
envp complete --shell bash > ~/.local/share/bash-completion/completions/envp
envp complete --shell zsh   > "${fpath[1]}/_envp"
envp complete --shell fish  > ~/.config/fish/completions/envp.fish
```

## Security

Profiles are encrypted with AES-256-GCM, keys derived via Argon2id, fresh
salt and nonce on every write, atomic writes, files mode 0600. This
protects data at rest: lost laptops, backups, accidentally committed
directories.

On unix, `run` execs the application instead of wrapping it, so decrypted
variables, the derived key and password buffers do not linger in memory
for the service lifetime.

It does not protect against the same user reading a running process's
environment (`/proc/<pid>/environ`, `ps eww`), root, or keyloggers. No
tool on a general-purpose OS can. Use `--clean` to shrink what the
application sees.

## Limitations

- Export and edit rewrite the profile in canonical form (alphabetical
  keys); comments and formatting from the source `.env` are not kept.
- `edit` keeps a plaintext temp file (mode 0600, in a 0700 directory under
  `ENVPOUCH_HOME`) while the editor is open. If the editor is killed, the
  file lingers there until the next `edit` removes files older than an
  hour. (Older versions used the shared system temp directory; leftovers
  from those versions are still swept from there.)
- On Windows there is no `exec`: `run` spawns and waits, so one extra
  process remains (Ctrl-C reaches the application via the shared console).
  File permissions are NTFS ACLs rather than 0600. There, `run
  --password-stdin` reads through a buffered pipe: if the command itself
  also reads stdin, buffered bytes can be lost to it (unix reads
  byte-by-byte and leaves the rest of the pipe alone).

---

envpouch is one of two companion tools for keeping secrets out of the wrong
places. If a leaked-key scare made you set this up — or it quietly saved you
from rotating every credential you own — a
[star](https://github.com/wusende/envpouch/stargazers) helps others find it.
For AI agents specifically, see [keysink](https://github.com/wusende/keysink):
real API keys never enter the agent's environment at all.

## 中文说明

**envpouch** 把 `.env` 变成密码加密的 profile,再用 `envp run` 注入运行:明文不落盘、不进 git、不进备份。命令与上方英文文档一一对应:

```sh
envp import prod --from .env.production   # 导入 .env,提示设密码
envp run prod ./start-server.sh           # 解密注入并运行(原地 exec,不留包装进程)
envp show prod                            # 查看变量,默认打码
```

保护范围:丢了笔记本、备份外泄、误提交进 git——没有密码的 profile 文件是死的(Argon2id,无找回)。不防:root、键盘记录器、同用户进程读运行中进程的环境变量。

在跑 AI agent?同作者的 [keysink](https://github.com/wusende/keysink) 是配套工具:单向网关,真 API key 根本不进 agent 环境(agent 只拿可吊销的虚拟 key)。envpouch 是单命令、文件态的那一半。

如果它帮你省下过一次「全量换 key」,去 [点个 star](https://github.com/wusende/envpouch/stargazers)。
