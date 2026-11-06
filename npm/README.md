# 发布说明（维护者）

两个 registry 各一个包，版本号都来自 `Cargo.toml`：

| registry | 包 | 发布方式 |
|---|---|---|
| crates.io | `envpouch` | 本机 `cargo publish`（手动） |
| npm | `envpouch` | 打 tag 后 CI 自动发布（OIDC 无 token） |

## npm 包的形态

npm 上只有一个包 `envpouch`，里面**内置了 4 个平台的二进制**，启动壳按
`process.platform` / `process.arch` 选一个执行。

```
envpouch/
├── bin/envpouch.js           启动壳：选平台、透传参数/信号/退出码
├── vendor/linux-x64/envpouch
├── vendor/linux-arm64/envpouch
├── vendor/darwin-universal/envpouch   universal2，两个架构共用
└── vendor/win32-x64/envpouch.exe
```

Linux 是 glibc 构建（`keyring` 的 Secret Service 后端链接 libdbus-1，没有可用的
musl 构建），x86_64 在 ubuntu-22.04 上编（glibc 2.35 下限）、arm64 在
ubuntu-24.04-arm 上编（2.39）；启动壳对 musl 给出明确提示并回退 `cargo install`。
macOS 用 `lipo` 合成的 universal2，一份二进制覆盖
x64 与 arm64（启动壳把 `darwin-x64` / `darwin-arm64` 都映射到该目录）。

为什么不拆成「主包 + 平台包」：npm 对新账号的新包会转成 `0.0.0-stage`
占位审核态，每个包都要人工批，且 `<name>-win32-x64` 这类包名撞反垃圾规则
（同类案例 `keelrun-cli-win32-x64`）。为什么不改成安装时从 GitHub 下载：
GitHub Releases 没有 npm 那样的国内镜像，安装路径上放了最不可达的一环。
单包内置的代价是每个用户都为 4 个平台付流量（~7 MB tarball）。

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

```bash
cargo package --list          # 看会打进 crate 的文件
cargo publish --dry-run       # 完整验证但不落地
cargo publish                 # 真正发布（0.1.0 是首次）
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
# 2. 先发 crate（可重复；已存在的版本会报 already uploaded）
cargo publish
# 3. 打 tag → CI 构建四平台、打包成单包发布 npm（NPM_PUBLISH=true 时）
git tag v0.1.1 && git push origin v0.1.1
```

CI 里的 npm job 用本次构建产物（`--from-artifacts`），不依赖 Release 上传完成的
时序。手动补发：`bash scripts/npm-pack.sh --from-release && bash scripts/npm-publish.sh`。

本地只想验证启动壳：

```bash
cargo build --release
bash scripts/npm-pack.sh --from-target   # 只 stage 本机已构建的平台
npm install -g ./npm/dist/envpouch
envpouch --version
```

## 平台矩阵

| vendor 目录 | 来源资产 | 运行要求 |
|---|---|---|
| `linux-x64` | `envpouch-x86_64-unknown-linux-gnu.tar.gz` | glibc 2.35+（22.04 构建） |
| `linux-arm64` | `envpouch-aarch64-unknown-linux-gnu.tar.gz` | glibc 2.39+（24.04 构建） |
| `darwin-universal` | `envpouch-universal2-apple-darwin.tar.gz` | macOS 11+，Intel/Apple Silicon |
| `win32-x64` | `envpouch-x86_64-pc-windows-msvc.zip` | Windows 10+ |

没覆盖的平台（musl/Alpine、Windows arm64、Linux armv7 等）由启动壳给出明确提示并回退到
`cargo install envpouch`。

## 文件

- `npm/envpouch/` — 启动壳与清单（唯一提交的 package.json）
- `scripts/npm-pack.sh` — 拉资产、校验 sha256、解包进 `npm/dist/envpouch/vendor/**`
- `scripts/npm-publish.sh` — 发布单包；已发布的版本自动跳过，2FA 码过期可直接重跑
