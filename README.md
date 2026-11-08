# envpouch

[![CI](https://github.com/wusende/envpouch/actions/workflows/ci.yml/badge.svg)](https://github.com/wusende/envpouch/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/envpouch.svg)](https://crates.io/crates/envpouch)
[![npm](https://img.shields.io/npm/v/envpouch.svg)](https://www.npmjs.com/package/envpouch)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Encrypted environment-variable profiles for macOS, Linux and Windows. Turn a
`.env` file into a password-protected profile, then run any command with those
variables injected:

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
| Long-lived processes | a service runs with secrets in its environment for weeks; any same-user process can read them (`/proc/<pid>/environ`) | no wrapper process holding a second copy, and core dumps are off by default; a same-uid reader still sees the live environment ([why](https://github.com/wusende/envpouch/blob/main/docs/security.md#ai-agents-why-run-is-not-a-boundary)) |

What it does **not** protect against: root, keyloggers, and a same-user
process reading a running process's environment — anything handed to a process
can be read back by the user's other processes.

## Install

```sh
npm install -g envpouch    # prebuilt binary, no toolchain needed
cargo install envpouch     # from source, needs Rust 1.85+
```

Check with `envp --version`. Prebuilt binaries for Linux (glibc and static
musl), macOS (one binary for Intel and Apple Silicon) and Windows are also on
the [releases page](https://github.com/wusende/envpouch/releases). On Windows
arm64, use `cargo install`.

## Basics

```sh
envp import prod --from .env.production   # new profile, prompts for a password
envp list                                 # list profiles, no password needed
envp show prod                            # variables, values masked
envp run prod ./start-server.sh           # decrypt and run with them set
```

Each profile is one encrypted file under `~/.envpouch/profiles/` — copy that
directory to back everything up. Every decrypting command takes its password
from the interactive prompt, `--password-stdin`, or `--password-file <file>`
(owner-only, 0600) for services.

**There is no password recovery.** A lost password means the profile is gone.
Keep passwords in a password manager.

**Running a service?** `envp run` replaces itself with the application, so
systemd and supervisord see the app directly (same PID, signals, exit code).
Recipes for systemd, supervisord and php-fpm are in
[services.md](https://github.com/wusende/envpouch/blob/main/docs/services.md).

**Running an AI agent?** It runs with your uid and your file access, so
`envp run` is not a boundary against it. Read
[security.md](https://github.com/wusende/envpouch/blob/main/docs/security.md)
before pointing an agent at a profile; the short version is a dedicated uid
for the service, and [keysink](https://github.com/wusende/keysink) for keys an
agent has to use itself.

## How it compares

| | envpouch | dotenvx | direnv | sops |
|---|---|---|---|---|
| Encryption at rest | ✅ per-profile, password-derived | ✅ (private-key based) | ❌ | ✅ (KMS / age key) |
| No plaintext on disk ever | ✅ | ❌ (encrypts on demand) | ❌ | ✅ |
| Per-command injection (`run`) | ✅ exec, no wrapper | ✅ | ✅ shell hook | ❌ (decrypts to file) |
| Needs a key management service | ❌ just a password | ❌ | — | usually |
| Multi-profile, one binary | ✅ | ✅ | ❌ per-directory | ❌ file-per-operation |

Pick envpouch when you want `.env`-simplicity with real at-rest encryption and
no infra.

## Documentation

| Doc | What is in it |
|---|---|
| [usage.md](https://github.com/wusende/envpouch/blob/main/docs/usage.md) | every command and flag, `run` semantics, scripts/CI, files, shell completion, limitations |
| [services.md](https://github.com/wusende/envpouch/blob/main/docs/services.md) | systemd, supervisord, php-fpm |
| [security.md](https://github.com/wusende/envpouch/blob/main/docs/security.md) | what is encrypted, what is not, why `run` is not a sandbox, what to do about AI agents |

## 中文说明

**envpouch** 把 `.env` 变成密码加密的 profile,再用 `envp run` 注入运行:明文不落盘、不进 git、不进备份,丢了笔记本或误提交时 profile 文件是死的(Argon2id,无密码找回)。不防:root、键盘记录器、同用户进程读运行中进程的环境变量。

给服务用要配独立 uid;给 AI agent 用不要用 `envp run`,它要的 key 交给 [keysink](https://github.com/wusende/keysink)。原因和做法写在英文的 [security.md](https://github.com/wusende/envpouch/blob/main/docs/security.md#ai-agents-why-run-is-not-a-boundary) 里。

---

If a leaked-key scare made you set this up — or it quietly saved you from
rotating every credential you own — a
[star](https://github.com/wusende/envpouch/stargazers) helps others find it.
