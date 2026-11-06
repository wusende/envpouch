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

## Install

```sh
npm install -g envpouch    # prebuilt binary, no toolchain needed
cargo install envpouch     # from source, needs Rust 1.85+
```

Check with `envp --version`. Prebuilt binaries for Linux (glibc), macOS
(universal2) and Windows are also on the
[releases page](https://github.com/wusende/envpouch/releases). On Alpine or
Windows arm64, use `cargo install`.

## Basics

```sh
envp import prod --from .env.production   # new profile, prompts for a password
envp list                                 # list profiles, no password needed
envp show prod                            # variables, values masked
envp run prod ./start-server.sh           # decrypt and run with them set
```

Every command that decrypts gets the password one of three ways: the
interactive prompt (default), the OS keychain after `envp unlock prod`
caches it for 15 minutes (`envp lock prod` drops it early), or
`--password-stdin` reading it from stdin for scripts.

**There is no password recovery.** A lost password means the profile is
gone. Keep passwords in a password manager.

## Commands

All commands except `list`, `rm`, `lock` and `complete` need the password.
`--password-stdin` is a global flag and works with every one of them,
before or after the subcommand.

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
| `list` / `rm` / `passwd` | List, delete, change password |
| `unlock` / `lock` | Cache the password in the OS keychain / drop it |
| `complete --shell <shell>` | Print shell completions |

A bare `KEY` in `set` is the safe way to store secrets: `KEY=VALUE` on the
command line is visible to same-user processes and lands in shell history.

## run

```sh
envp run prod ./deploy.sh
envp run prod --clean python app.py      # only a minimal base env plus profile vars
envp run prod --dry-run ./deploy.sh      # print what would run, never values
envp run prod --detach ./server.sh       # detach; envp exits immediately
```

- By default the child gets your full environment with the profile
  variables on top. `--clean` gives it only `PATH`, `HOME`, `USER` and a
  few base variables plus the profile.
- Everything after the command name goes to the child untouched. `--` is
  only needed when the command itself starts with an envp option, e.g.
  `envp run prod -- --clean`.
- The child's exit code is passed through. `1` is an envp error such as a
  wrong password, `2` a usage error, `127` command not found.
- On unix, Ctrl-C is forwarded to the child, same as `docker run`.

## Scripts / CI

```sh
printf '%s\n' "$PW" | envp run prod --password-stdin ./deploy.sh
printf '%s\n' "$PW" | envp --password-stdin export prod -o /tmp/prod.env
```

One stdin line per password prompt, in prompt order: `passwd` reads the
current password then the new one, `diff` reads one per profile. envp
deliberately has no password environment variable, since process
environments are readable by same-user processes.

## php-fpm

Two php-fpm defaults defeat injected variables; `fpm-snippet` exists for
this:

- `clear_env=yes` (the default) wipes the environment for workers, so
  `getenv()` in PHP returns nothing. Append
  `envp fpm-snippet prod >> www.conf` to emit one `env[KEY] = value` line
  per variable, or set `clear_env = no` in the pool.
- `daemonize=yes` (the default) forks the master into the background, so
  envp returns immediately. That is success, not failure. Under systemd,
  use `daemonize = no`.

## Files

Profiles live in `~/.envpouch/profiles/<name>.envpouch`, each a
self-contained encrypted file. Back them up by copying the directory.

```sh
export ENVPOUCH_HOME=/var/lib/myapp/envpouch   # move storage elsewhere
export ENVPOUCH_AUDIT=1                        # log each decrypting command to audit.log
```

The audit log records timestamp, command, profile and exit code, never
variable names or values.

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

It does not protect against the same user reading a running process's
environment (`/proc/<pid>/environ`, `ps eww`), root, or keyloggers. No
tool on a general-purpose OS can. Use `--clean` to shrink what a child
process sees.

## Limitations

- Export and edit rewrite the profile in canonical form (alphabetical
  keys); comments and formatting from the source `.env` are not kept.
- `edit` briefly keeps a plaintext temp file (mode 0600) while the editor
  is open.
- Ctrl-Z under `run` does not suspend envp. Ctrl-C still works; to resume
  the child, `kill -CONT <pid>` from another terminal.
- On Windows there is no signal-forwarding layer (Ctrl-C reaches the child
  via the shared console) and file permissions are NTFS ACLs rather than
  0600.
