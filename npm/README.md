# 发布说明（维护者）

两个 registry 各一个包，版本号都来自 `Cargo.toml`：

| registry | 包 | 发布方式 |
|---|---|---|
| crates.io | `envpouch` | 打 tag 后 CI 自动发布（OIDC 无 token） |
| npm | `envpouch` | 打 tag 后 CI 自动发布（OIDC 无 token） |

## npm 包的形态

npm 上只有一个包 `envpouch`，里面**内置了 6 个平台的二进制**，启动壳按
`process.platform` / `process.arch` 选一个执行（Linux 上再用 `process.report`
区分 glibc / musl）。**包名是 `envpouch`，命令是
`envp`**：`bin` 只声明 `envp`，安装时的 postinstall 会打印这条提示（写
`/dev/tty` 而不是 stdout——npm 默认 `foreground-scripts=false`，会把脚本输出吞掉；
没有 tty 时退回 stdout）。

```
envpouch/
├── bin/envp.js               启动壳：选平台、透传参数/信号/退出码
├── bin/postinstall.js        安装后打印「命令是 envp」
├── vendor/linux-x64/envp
├── vendor/linux-arm64/envp
├── vendor/linux-musl-x64/envp     静态链接，Alpine/BusyBox 用
├── vendor/linux-musl-arm64/envp
├── vendor/darwin-universal/envp   universal2，两个架构共用
└── vendor/win32-x64/envp.exe
```

Linux 每个架构出两份：glibc 构建（x86_64 在 ubuntu-22.04 上编，glibc 2.35
下限；arm64 在 ubuntu-24.04-arm 上编，2.39）和静态 musl 构建（同 runner；
musl target 用 rust-lld + 自带 musl libc 链接，不需要 musl 工具链，CI 里有
构建防护）。启动壳探测到 musl 就选 `linux-musl-*` 目录，目录缺失即安装
损坏（提示 `npm rebuild envpouch`）；旧版包的壳在 musl 上仍回退
`cargo install` 提示。
macOS 用 `lipo` 合成的 universal2，一份二进制覆盖
x64 与 arm64（启动壳把 `darwin-x64` / `darwin-arm64` 都映射到该目录）。

为什么不拆成「主包 + 平台包」：npm 对新账号的新包会转成 `0.0.0-stage`
占位审核态，每个包都要人工批，且 `<name>-win32-x64` 这类包名撞反垃圾规则
（同类案例 `keelrun-cli-win32-x64`）。为什么不改成安装时从 GitHub 下载：
GitHub Releases 没有 npm 那样的国内镜像，安装路径上放了最不可达的一环。
单包内置的代价是每个用户都为 6 个平台付流量（~10 MB 解包，下载包比
4 平台时多约 1.5 MB）。

## 一次性准备（只有账号持有人能做）

1. **npm 账号 + 邮箱验证**，**开 2FA**。
2. **首次手工发布**（Trusted Publisher 只能在包存在之后配置）：

   ```bash
   export HTTPS_PROXY=http://127.0.0.1:7892   # 本机拉 GitHub 资产用
   bash scripts/npm-pack.sh                   # 从 GitHub Releases 拉 4 个资产并校验 sha256
   bash scripts/npm-publish.sh --dry-run
   bash scripts/npm-publish.sh --otp 123456
   ```

   若账号仍在「新发布者审核」状态，`npm publish` 会生成 `0.0.0-stage` 占位包，
   需要去 npmjs.com 的 **Staged Packages** 批准，或提工单。

3. **给 `envpouch` 配 Trusted Publisher**（npmjs.com → 包 → Settings → Trusted publishing）：

   | 字段 | 值 |
   |---|---|
   | Provider | GitHub Actions |
   | Organization or user | `wusende` |
   | Repository | `envpouch` |
   | Workflow filename | `release.yml` |

   然后把 Publishing access 改成「Require two-factor authentication and disallow tokens」。

4. **打开 CI 自动发布**：仓库 Settings → Variables 加 `NPM_PUBLISH = true`。

## crates.io

token 在 `~/.cargo/credentials.toml`（**不要**提交、不要贴进聊天）。crates.io
只认已发布过的版本，发布后不可删除（只能在 24 小时内 yank，且名字永久保留）。

### CI 自动发布（trusted publishing）

和 npm 一样：推 tag 时 `release.yml` 的 `crates-io` job 用 OIDC 换一个 30 分钟
有效期的 token（`rust-lang/crates-io-auth-action`），不落长期密钥。一次性准备：

1. crates.io → 打开 `envpouch` → **Settings → Trusted Publishing** → Add：
   Provider `GitHub`，Repository owner `wusende`，Repository name `envpouch`，
   Workflow filename `release.yml`。
2. 仓库 Settings → Variables 加 `CRATES_PUBLISH = true`。

未设变量时该 job 直接跳过（不红），和 `NPM_PUBLISH` 同一个开关逻辑。配置好之后
建议把账号的 API token 权限改成「只限发布」，或干脆吊销——CI 不再用它。

### 本地手动发布（备用）

本机 token 只留作应急，脚本可重复执行（版本已在线上就跳过）：

```bash
bash scripts/cargo-publish.sh --dry-run   # 完整验证但不落地
bash scripts/cargo-publish.sh             # 真正发布
```

`Cargo.toml` 里的 `exclude = [".github", "scripts", "npm"]` 保证 crate 里只有
`src/`、`Cargo.toml`、`README.md`、`LICENSE` 和 `Cargo.lock`。

## 每次发版

版本号只写在 `Cargo.toml`，`npm-pack.sh` 会同步进 `npm/envpouch/package.json`；
`npm/envpouch/package.json` 是入库文件，所以**发版提交必须把它一起改掉**——CI 的
`npm manifest matches Cargo.toml` 步骤会拦截漂移（本地可先跑
`bash scripts/npm-pack.sh --check-version`）。

```bash
# 1. 改 Cargo.toml 版本 + npm/envpouch/package.json 的 version，提交
# 2. 打 tag → CI 构建六平台二进制、发 Release、发 crates.io、发 npm
git tag v0.1.1 && git push origin v0.1.1
```

两个 registry 都只要打 tag。任何一个 registry 没配置好（`CRATES_PUBLISH` /
`NPM_PUBLISH` 未设 true）时对应 job 跳过；配置好之后本地什么都不用做。
发失败可重试：两个发布脚本都会跳过已存在的版本，不会因为「版本已上传」变红。

tag 必须等于 `v` + `Cargo.toml` 里的版本号（`v0.2.2` ↔ `0.2.2`）：crate 版本
一旦发出去就再也收不回，所以 `cargo-publish.sh` 在 tag 构建上先比对，不一致
直接失败，避免用一个错误的 tag 花掉一个版本号。

CI 里的 npm job 用本次构建产物（`--from-artifacts`），不依赖 Release 上传完成的
时序。手动补发：`bash scripts/npm-pack.sh --from-release && bash scripts/npm-publish.sh`。

本地只想验证启动壳：

```bash
cargo build --release
bash scripts/npm-pack.sh --from-target   # 只 stage 本机已构建的平台
npm install -g ./npm/dist/envpouch
envp --version
```

## 平台矩阵

| vendor 目录 | 来源资产 | 运行要求 |
|---|---|---|
| `linux-x64` | `envpouch-x86_64-unknown-linux-gnu.tar.gz` | glibc 2.35+（22.04 构建） |
| `linux-arm64` | `envpouch-aarch64-unknown-linux-gnu.tar.gz` | glibc 2.39+（24.04 构建） |
| `linux-musl-x64` | `envpouch-x86_64-unknown-linux-musl.tar.gz` | 任意 x86_64 Linux（静态链接） |
| `linux-musl-arm64` | `envpouch-aarch64-unknown-linux-musl.tar.gz` | 任意 arm64 Linux（静态链接） |
| `darwin-universal` | `envpouch-universal2-apple-darwin.tar.gz` | macOS 11+，Intel/Apple Silicon |
| `win32-x64` | `envpouch-x86_64-pc-windows-msvc.zip` | Windows 10+ |

没覆盖的平台（Windows arm64、Linux armv7、xBSD 等）由启动壳给出明确提示并回退到
`cargo install envpouch`。

## 文件

- `npm/envpouch/` — 启动壳与清单（唯一提交的 package.json）
- `scripts/npm-pack.sh` — 拉资产、校验 sha256、解包进 `npm/dist/envpouch/vendor/**`
- `scripts/npm-publish.sh` — 发布单包；已发布的版本自动跳过，2FA 码过期可直接重跑
- `scripts/cargo-publish.sh` — 发布 crate；已发布的版本自动跳过，CI 走 OIDC token
