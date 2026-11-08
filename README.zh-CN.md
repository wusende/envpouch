# envpouch

[English](README.md) | 简体中文

[![CI](https://github.com/wusende/envpouch/actions/workflows/ci.yml/badge.svg)](https://github.com/wusende/envpouch/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/envpouch.svg)](https://crates.io/crates/envpouch)
[![npm](https://img.shields.io/npm/v/envpouch.svg)](https://www.npmjs.com/package/envpouch)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

给 macOS / Linux / Windows 用的加密环境变量 profile。把 `.env` 变成带密码的 profile,再用一条命令注入运行:

```sh
envp import prod --from .env.production
envp run prod ./start-server.sh
```

包名 `envpouch`,装出来的命令是 `envp`。

## 为什么不直接留 `.env`

明文 `.env` 从三个没人盯的渠道漏:

| 泄漏渠道 | 会发生什么 | envpouch |
|---|---|---|
| 提交进 git | `.env.production` 进了仓库,之后每个 fork、每个 clone 都握着活的密钥 | profile 是 AES-256-GCM 加密文件,仓库里永远看不到值 |
| 备份与同步 | Time Machine、Nextcloud、`rsync` 把家目录整个快照走,密钥一起 | 没有密码的 profile 文件是死的(Argon2id,无找回) |
| 长期运行的进程 | 服务带着密钥跑几周,同用户任何进程都能读(`/proc/<pid>/environ`) | 不留包装进程的第二份副本,默认关 core dump;同 uid 的读者仍能看到活着的环境变量([原因](docs/zh-CN/security.md#ai-agents-why-run-is-not-a-boundary)) |

**不防**:root、键盘记录器、同用户进程读运行中进程的环境变量——交给进程的东西,同用户的其它进程都能读回来。

## 安装

```sh
npm install -g envpouch    # 预编译二进制,不需要工具链
cargo install envpouch     # 从源码编译,需要 Rust 1.85+
```

`envp --version` 自检。Linux(glibc 与静态 musl)、macOS(Intel 与 Apple Silicon 同一个二进制)、Windows 的预编译包在 [Releases](https://github.com/wusende/envpouch/releases);Windows arm64 用 `cargo install`。

## 基础用法

```sh
envp import prod --from .env.production   # 新建 profile,提示设密码
envp list                                 # 列 profile,不用密码
envp show prod                            # 看变量,默认打码
envp run prod ./start-server.sh           # 解密注入并运行
```

每个 profile 是 `~/.envpouch/profiles/` 下的一个加密文件,备份就是拷这个目录。需要解密时,密码来自交互提示、`--password-stdin`,或给服务用的 `--password-file`(仅属主可读,0600)。

**没有密码找回。** 密码丢了,profile 就没了,把密码存进密码管理器。

**要跑服务?** `envp run` 会把自己替换成应用,systemd / supervisord 看到的就是应用本身(同一个 PID、信号、退出码)。systemd、supervisord、php-fpm 的配方在 [services.md](docs/zh-CN/services.md)。

**要跑 AI agent?** 它用你的 uid、你的文件权限,`envp run` 挡不住它。把 profile 交给 agent 之前先读 [security.md](docs/zh-CN/security.md);短版本:给服务配独立 uid,agent 自己要用的 key 交给 [keysink](https://github.com/wusende/keysink)。

## 什么时候不该用

- **环境变量本来就该常驻 shell。** 那是 direnv 的活儿,和这个正好相反。
- **只需要让 `.env` 不进 git。** dotenvx 用密钥而不是密码解决同一件事,看你更信哪种。
- **多人、多机共享密钥。** Vault、Infisical、1Password CLI 或云厂商的 secrets manager;envpouch 是单用户、一个 profile 一个密码。
- **已经在用 sops / age 管流水线。** 那就留着,envpouch 的唯一优势是不需要 host key 和 KMS。
- **消费者是同 uid 的 AI agent。** 见上一节。

## 文档

| 文档 | 内容 |
|---|---|
| [usage.md](docs/zh-CN/usage.md) | 全部命令与参数、`run` 语义、脚本/CI、文件位置、shell 补全、已知限制 |
| [services.md](docs/zh-CN/services.md) | systemd、supervisord、php-fpm |
| [security.md](docs/zh-CN/security.md) | 加密了什么、没加密什么、为什么 `run` 不是沙箱、AI agent 怎么办 |

---

如果它帮你省下过一次「全量换 key」,去 [点个 star](https://github.com/wusende/envpouch/stargazers)。
