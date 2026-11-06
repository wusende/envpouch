# envrun 开发指导与踩坑文档

> 本文档面向 coding agent，是开发的唯一依据。先通读 §0-§3，再按 §9 里程碑顺序实现；
> 实现每个里程碑前重读对应章节，完成后跑 §9.6 的验收命令。
> 已有代码的模块（§2）**不要重构、不要改动文件格式**，除非文档明确要求。

---

## 0. 铁律（必须遵守）

1. **文件格式 v1 不变**：`crypto.rs` 定义的 profile 二进制格式已发布逻辑（magic/version/AAD），改动会毁掉用户已有数据。新增字段只能走新 version。
2. **全英文交付**：所有代码注释、CLI 帮助文案、错误信息、交互提示、命令输出一律英文，风格仍走 `anyhow::Context`/`bail!`。已有三个模块内的中文注释与错误信息也须翻译成英文（§2、§9 M0）。
3. **明文 secret 的传播面最小化**：解密后的 JSON 已是 `Zeroizing<Vec<u8>>`；新代码中密码用 `Zeroizing<String>` 接住；凡是打印 key 列表/预览的地方一律走 §6 的 mask 规则。
4. **stdout 只放数据，stderr 只放诊断**：`export`/`fpm-snippet` 的输出要能进管道；错误、警告、提示全部 stderr。
5. **fail fast**：profile 已存在、key 非法、必填参数缺失 → 直接报错退出，不做猜测性默认。
6. 平台支持（v1.1 修订，原 §0.6 "仅 unix" 已过时）：macOS/Linux/Windows 三平台。Unix 路径保持 §4.1-§4.2 的进程组+信号转发模型与 RLIMIT_CORE 加固；Windows 路径由控制台组原生传递 Ctrl-C，无信号转发层、无 128+N 退出码、无 core-dump 加固（差异已写入 README Known limitations）。行为分歧只能随平台 cfg 分叉，不得引入运行时探测。

## 1. 项目定位

**一句话**：把环境变量加密存储为命名 profile（dev/prod/myapp…），用 `envrun run <profile> -- <command>` 注入后启动任意程序。

**目标用户场景**（按优先级）：
1. 启动应用/服务并注入参数（php-fpm、应用服务、systemd 前台服务）；
2. Python 脚本的环境变量设置；
3. .env 文件的加密托管（防误提交、防备份泄漏）。

**非目标（不要做）**：
- 不做 secret 轮换/共享/多用户同步（那是 Vault/1Password 的领域）；
- 不做进程管理器（重启/守护/日志收集交给 systemd/supervisor）；
- 不防同用户进程窥探（OS 限制，见 §7，文档诚实声明即可）。

**安全边界声明（最终要写进 README，这里先定稿）**：
- 能防：磁盘上的静态数据泄漏（丢失的笔记本、备份、误提交的目录）；
- 不能防：进程运行期间同用户可读 `/proc/<pid>/environ`（Linux）、root、内存转储、屏幕截屏。
- 因此 `run` 时要顺手把子进程的 core dump 关掉（`RLIMIT_CORE=0`，见 §4.6），尽量缩小泄漏面。

## 2. 当前代码状态盘点

| 模块 | 状态 | 说明 |
|---|---|---|
| `src/crypto.rs` | ✅ 完成 | Argon2id(m=19MiB,t=2,p=1) + AES-256-GCM，头部作 AAD，`read_meta` 免密读元数据，测试齐全 |
| `src/envfile.rs` | ✅ 完成 | dotenvy 解析、`merge`、JSON(Zeroizing) 往返、`.env` 导出转义与 roundtrip 测试 |
| `src/profile.rs` | ✅ 完成 | `~/.envrun/profiles/<name>.envrun`、原子写、0700/0600、名称校验、list 容错 |
| `src/main.rs` | ❌ 空壳 | **全部剩余工作在这里及新模块**：CLI、run、import/export、show、fpm-snippet、密码 UX |

对已有模块的允许改动：
- **全量英文化（M0 第一步执行）**：把三个模块中的中文注释、中文错误信息翻译成英文，并同步更新引用错误文案的测试断言（如 crypto.rs 测试中的 `contains("密码错误")`）。这是机械性改动，不得改变任何逻辑、行为或文件格式。
- `crypto.rs`：若实现 §4.3 密码缓存需要派生 key 复用，可把 `derive_key` 改为 `pub(crate)`，其他不动。

## 3. CLI 总规格

clap derive 风格（Cargo.toml 已有 derive feature）。v1 命令集：

```
envrun list                                   # 列出所有 profile（免密）
envrun import <name> (--from <file> | --from-env [--only k1,k2 | --except k1,k2])
                                              # 创建 profile（可选 --merge 合入已有）
envrun show <name> [--reveal]                 # 默认 mask 显示；--reveal 输出 .env 格式明文
envrun export <name> [-o <file>]              # 导出 .env；无 -o 则打 stdout
envrun edit <name>                            # 用 $EDITOR 编辑（临时明文文件，见 §5.3）
envrun run <name> [--clean] [--dry-run] [--detach] [--password-stdin] -- <cmd> [args...]
envrun fpm-snippet <name>                     # 生成 php-fpm pool 的 env[...] 片段（stdout）
envrun passwd <name>                          # 修改密码（解密→新密码重加密，v1 格式不变）
envrun unlock <name> [--ttl <秒>]             # P1：密码缓存进 OS keychain（§4.3）
```

- 省略子命令直接 `envrun <name> -- cmd` 不支持，必须显式 `run`（保持错误信息可预测）。
- 全局 `--version`/`--help` 由 clap 提供；help 文案英文。
- **exit code 约定**（必须实现，这是脚本可依赖的接口）：

| 退出码 | 含义 |
|---|---|
| 0 | 成功 |
| 1 | envrun 自身错误（解密失败、IO 失败、参数错等） |
| 2 | 用法错误（clap 默认） |
| 127 | run: 目标程序不存在 |
| 126 | run: 目标程序无执行权限 |
| 128+N | run: 子进程被信号 N 杀死（N=SIGINT 时即 130） |
| 其他 | 子进程自身退出码，1:1 透传 |

- 所有子命令在解密需要密码时统一走 §4.3 的密码获取流程。
- `run` 之外，除 `list` 外所有子命令都需要密码（show mask 需要 key 名，而 key 名在密文里）。

## 4. run 子命令规格（P0 核心，最容易做错的部分）

### 4.1 进程模型（设计决策，不要偏离）

用 `std::process::Command` 直接 exec 目标程序。**禁止**用 `sh -c` 包一层（额外引号求值、信号链断裂、退出码失真）。

关键决策：**子进程放入独立进程组 + envrun 全权转发信号**：

```rust
use std::os::unix::process::CommandExt;
command.process_group(0);   // Rust 1.64+，unix
```

为什么必须是独立进程组（踩坑）：终端 Ctrl-C 时，内核把 SIGINT 发给前台进程组的**每个成员**。若子进程与 envrun 同组，SIGINT 会被"终端直发 + envrun 转发"双份送达，时序不可控；且 envrun 若先死，子进程变孤儿。独立进程组后，终端信号只到 envrun，由 envrun 转发，行为与 `timeout`/`docker run` 一致，完全可控。

### 4.2 信号转发的精确算法

Rust std 没有信号 API，用 `libc`（新增依赖）或 `signal-hook`。用 libc 的话：

1. `spawn` 前用 `sigaction` 注册 handler：`SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGTSTP, SIGWINCH, SIGUSR1, SIGUSR2`。handler **只做一件事**：把信号号写入 `static AtomicI32`（在 handler 里调 printf/malloc 等非 async-signal-safe 函数是 UB）。
2. spawn 后进入轮询循环（10ms 间隔，CPU 开销可忽略）：
   - `child.try_wait()` 返回 `Some(status)` → 跳到 3；
   - atomic 标志非 0 → `libc::kill(child_pid, sig)` 转发（SIGTSTP 转发后 envrun 自己**不要**停，继续循环等子进程），清标志，继续循环。
3. 退出码映射：
   - `status.code()` 为 `Some(c)` → exit c；
   - 为 `None`（被信号杀死）→ exit `128 + signal`（SIGINT 死亡即 130，符合 shell 惯例）。
4. spawn 本身失败：`io::ErrorKind::NotFound` → 报错 exit 127；`PermissionDenied` → exit 126；其他 → exit 1。

注意事项（踩坑）：
- **SIGTERM 不会自动传给子进程**（终端只把 INT/QUIT 发前台组），必须显式转发，否则 `kill <envrun_pid>` 会留下孤儿。
- SIGTSTP/SIGWINCH 必须在转发集合里，否则 vim/htop 类交互程序在 envrun 下挂起/不随终端 resize。
- SIGSTOP/SIGKILL 无法捕获，不处理。
- envrun 自己打印的错误一律到 stderr；转发等待期间若收到第二个信号，继续转发即可，不要提前退出。

### 4.3 密码获取

- 交互：`rpassword::prompt_password` 提示语打到 **stderr/tty**（`envrun run prod -- cmd` 的 stdout 可能被管道消费）。
- 脚本/CI：`--password-stdin` 从 stdin 读第一行（去 `\n`/`\r\n`），读不到报错。**不提供** `ENVRUN_PASSPHRASE` 环境变量方案（env 会被同用户 `/proc` 读到，且容易无意传给子进程——见 §4.5 剔除规则）。
- 密码在内存中用 `Zeroizing<String>` 持有（`rpassword` 返回 `String`，立刻包进去；`crypto::decrypt` 只需要 `&str`）。
- **P1 缓存（`unlock`）**：用 `keyring` crate 把主密码存入 OS keychain（macOS Keychain / Linux Secret Service），条目属性带过期时间戳；`run` 时若缓存命中且未过期则免输。踩坑：macOS 上 SSH 远程会话访问 login keychain 可能弹 GUI 授权框甚至死锁——`unlock` 失败时要降级为提示手动输密码，而不是硬失败。缓存的是**密码本身**（当前格式每 profile 独立 salt，key 不可复用），TTL 默认 900 秒，`envrun lock <name>`（顺手提供）删除缓存条目。
- 忘记密码 = 数据不可恢复（AAD+GCM 无后门）。`import`/`passwd` 首次设密码时输出一行明确警告："密码丢失后 profile 无法恢复，请妥善保管"。

### 4.4 环境合并语义

- 默认（overlay）：`当前进程环境 ∪ profile 变量`，同名键 **profile 覆盖** shell。
- `--clean`：只给 `最小基础环境 ∪ profile 变量`。最小基础环境**固定为**：`PATH`、`HOME`、`TMPDIR`、`USER`、`LOGNAME`、`SHELL`、`TERM`（取自当前环境；缺失就不设，不编造值）。`TERM` 必须保留，否则 TTY 交互程序颜色全丢。
- 踩坑：**必须把 `ENVRUN_PASSPHRASE`（即使将来支持）和 envrun 自身无关注入项从子进程环境中剔除**——原则：给子进程的环境 = 上述语义的结果，绝不多带。当前版本即：overlay 用 `std::env::vars()` 全量但这是用户 shell 环境的本意，可接受；`--clean` 则严格按清单。
- 踩坑 E2BIG：环境+argv 总量超 `ARG_MAX`（Linux 通常 ~2MB）时 `spawn` 报错，错误信息写明 `environment too large (ARG_MAX limit)` 而不是裸的 E2BIG。`--dry-run` 要打印体积估算（§6.2）。
- key 合法性在 **import/set 时**拦截（空名、含 `=`、含 NUL、以数字开头 POSIX 未定义 → 拒绝），run 时信任已存数据。
- 无 `--` 后命令 → 报错 `error: missing command to execute`。

### 4.5 php-fpm 专题（用户必踩的两个坑，全部要处理）

**坑 1：`clear_env=yes`（FPM 默认）—— worker 不继承 master 的环境变量。**
envrun 注入的一切只到达 fpm master。PHP 代码里 `getenv()` 拿到的是**空**。解法按推荐顺序：
1. pool 配置加 `env[KEY] = ...` 行（→ 由 `envrun fpm-snippet` 生成，§4.6）；
2. 或 pool 配置 `clear_env = no`，worker 继承 master 环境（envrun 注入的变量此时才直达 worker）。

**坑 2：`daemonize` 行为。**
- `daemonize = yes`（FPM 默认）：master 启动后 fork 脱离，envrun 的直接子进程随即退出 → envrun 正常返回。**这是预期行为，不算 bug**，文档要说明"envrun 立即返回 ≠ 失败"。
- `daemonize = no`（配 systemd/容器时推荐）：envrun 前台驻留直到 master 退出，也是预期。
- `--detach`（P2）只用于 nohup 类场景（启动后 envrun 立即退出且子进程脱离会话/进程组：`setsid` + `pre_exec` 或 double-fork），php-fpm 场景基本用不到，优先级放低。

**坑 3（文档要写）：`clear_env=yes` 连 `PATH` 都会被清掉**，PHP `exec()`/`shell_exec()` 找不到任何二进制。fpm-snippet 输出后要提示用户把 `env[PATH]` 也补上。

### 4.6 其他 run 时动作

- 关闭子进程 core dump：`pre_exec` 中 `libc::setrlimit(RLIMIT_CORE, 0)`（`unsafe` 闭包内只允许 async-signal-safe 调用，setrlimit 合法）。
- `--dry-run`：不执行，打印（stdout）：目标命令、合并模式、将注入的 key 列表（**只有 key，无值**）、环境总体积估算、是否超过 ARG_MAX 的预警。
- `run` 的错误（如密码错）打印后 exit 1，不要把解密后的任何内容带进错误信息。

### 4.7 fpm-snippet 规格

输入：profile 名（需解密）。输出：stdout，每行一条 pool 配置：

```
env[DB_PASSWORD] = <value>
```

转义/拦截规则（按序）：
1. 值含换行 → **跳过该条**，stderr 警告"KEY 含换行，无法写入 pool 配置；建议对 fpm 使用 clear_env=no"；
2. 值含 `\`、`"`、`;`、`#` → 双引号包裹并对 `\` 和 `"` 转义（`\"`、`\\`）；
3. 值含 `$` → 正常输出但 stderr 提示"$ 在 fpm 配置中有变量引用语义，请人工确认"；
4. 输出末尾追加英文注释行：`; If pool uses clear_env=yes (default), also add env[PATH] = ...`（以 `;` 开头，fpm ini 注释）；
5. 输出前后 stderr 各打一行英文警告：`warning: output contains plaintext secrets - do not paste into logs or commit it`。

验收必须包含：生成片段贴入 pool 配置后 `php-fpm -tt`（test 配置）通过，且 PHP `getenv('KEY')` 能取到。

## 5. import / export / edit 规格（P1）

### 5.1 import

- `--from <file>`：dotenvy 解析（复用 `envfile::parse_file`）。
- `--from-env`：从**当前进程环境**抓变量。默认应用**硬编码排除名单**（踩坑：不排除的话用户会一次存入一堆系统垃圾，且 SSH 会话变量泄漏面大）：
  `PATH HOME USER LOGNAME SHELL PWD OLDPWD TMPDIR LANG LC_* TERM TERM_* SSH_* GPG_TTY XDG_* DISPLAY DBUS_* COLORTERM __CF* SECURITYSESSIONID Apple_* HIST* ZSH* PAGER LESS MANPAGER EDITOR VISUAL COLUMNS LINES`
  （模式匹配：精确名 + 前缀通配；实现一个 `fn is_excluded(key) -> bool` 并配测试。）
- `--only a,b,c` / `--except a,b,c` 覆盖默认行为（--only 优先于名单，--except 在名单之上追加排除）。
- key 非法（含 `=`、空、控制字符）→ 逐条报错并拒绝整个导入（fail fast）。
- profile 已存在：默认报错退出；`--merge` 时用 `envfile::merge` 合入并报告 (新增数, 更新数)。
- 成功后输出（英文）：`Profile '<name>' written: N variables (M skipped by exclusion list)` + 完整 key 列表（无值）。
- 首次创建时要求输两遍密码确认；不一致报错重来（最多重试一次后放弃）。
- **踩坑 dotenvy `$VAR` 展开**：`envfile.rs` 注释已注明 dotenvy 会对值中 `$VAR` 做环境展开（双引号/裸值展开，**单引号不展开**）。用户密码类值含 `$` 时会被静默吃掉一段。缓解：import 成功后 stderr 提示（英文）`note: values containing $ are expanded under dotenvy semantics; use single quotes in .env files`；README 建议单引号。不改 dotenvy 行为。

### 5.2 export

- 无 `-o`：输出 stdout（可管道），stderr 提示 `warning: output contains plaintext secrets`。
- `-o <file>`：用 `profile::write_private_file`（0600），stderr 警告 `warning: plaintext file written to <path> - do not commit; delete when no longer needed`。
- 导出内容用 `envfile::to_env_text`（已有 roundtrip 测试保证语义一致）。

### 5.3 edit（比逐条 set/unset 更实用，优先做这个）

- 解密 → 写临时文件（`tempfile` crate，`$TMPDIR` 下，权限 0600）→ `$EDITOR`（默认 vi）→ 读回解析（`parse_file`）→ 重新加密原子写回 → 删除临时文件。
- 编辑器异常退出（非 0）→ 不写回，保留提示。
- stderr 警告（英文）：`warning: plaintext exists temporarily at <path> while editing`。
- 临时文件删除失败（进程被杀）不算数据事故，但启动 edit 时若发现残留临时文件（名字前缀 `envrun-edit-`）提示并清理。

## 6. show / list / mask 规则

### 6.1 mask 函数（单一实现，全项目复用，配测试）

```
fn mask(v: &str) -> String:
  ""        => "(empty)"
  len <= 4  => "****"
  其他      => "****" + v 最后 4 个字符
```

- `show <name>` 默认输出两列：`KEY = ****abcd`（空值显示 `(empty)`）。
- `show <name> --reveal`：输出 `.env` 文本格式（`to_env_text`），可直接 source / 重导入；stderr 提示明文。
- `list`：已有实现（免密读 meta），输出列：名称、变量数、更新时间（本地时区）、损坏标记。损坏的文件行尾加 `(文件损坏)` 而不是让整个 list 失败（已有逻辑，保持）。

### 6.2 --dry-run 输出（stdout，无任何值）

```
命令: python train.py
模式: overlay | clean
注入变量 (12): DB_HOST DB_PASSWORD ...（按字母序）
环境总体积: 约 3.2 KB
```

体积估算 = 所有 env 键+值字节数 + argv 字节数，超 1.5MB 时 stderr 预警 E2BIG。

## 7. 安全边界与 README 诚实声明（实现完成后写 README 用）

- 防护范围：磁盘静态数据（AES-256-GCM + Argon2id）；文件 0600/目录 0700；原子写防撕裂；内存明文 zeroize。
- 不防护：同用户进程读 `/proc/<pid>/environ`（Linux）、`ps eww`（部分平台）、root、内存转储。
- 缓解：run 时关闭子进程 core dump（§4.6）；不提供 ENVRUN_PASSPHRASE；README 明示上述边界。
- 不承诺：防键盘记录、防 root、防同用户恶意进程。

## 8. 踩坑清单汇总（实现前逐条对照）

| # | 坑 | 正确做法 | 出处 |
|---|---|---|---|
| 1 | 用 `sh -c` 包命令 | 直接 `Command::new(bin)`，让用户自己决定是否写 `-- sh -c '...'` | §4.1 |
| 2 | 终端信号双发 / 孤儿进程 | `process_group(0)` + envrun 捕获转发 | §4.1-4.2 |
| 3 | signal handler 里做复杂操作 | handler 只写 AtomicI32，主循环轮询 | §4.2 |
| 4 | SIGTERM 不自动传子进程 | 显式转发，退出码 128+N | §4.2 |
| 5 | SIGTSTP/SIGWINCH 不转发 → 交互程序挂死 | 纳入转发集合 | §4.2 |
| 6 | php-fpm `clear_env=yes` worker 拿不到变量 | fpm-snippet / clear_env=no，README 专章 | §4.5 |
| 7 | php-fpm `daemonize=yes` 下 envrun 立即返回被误判失败 | 文档说明，不算错误 | §4.5 |
| 8 | `env[PATH]` 被 clear_env 清掉 | snippet 尾部提示补 PATH | §4.7 |
| 9 | E2BIG（ARG_MAX）spawn 失败 | 错误信息可读 + dry-run 体积预警 | §4.4 |
| 10 | dotenvy 值中 `$VAR` 被展开 | import 后提示；文档建议单引号 | §5.1 |
| 11 | import 抓进一堆系统变量 | 硬编码排除名单 + --only/--except | §5.1 |
| 12 | clap 吃掉 `--` 之后的 `-` 参数 | run 子命令 `trailing_var_arg(true)` + `allow_hyphen_values(true)`，测试 `envrun run x -- curl --data a=b` | §3 |
| 13 | 非交互环境 rpassword 挂死 | `--password-stdin` | §4.3 |
| 14 | 密码 String 未 zeroize | `Zeroizing<String>` 接住 rpassword 返回值 | §4.3 |
| 15 | keychain 在 SSH 会话弹 GUI | unlock 失败降级为手输密码 | §4.3 |
| 16 | ENVRUN_PASSPHRASE 泄漏面 | 不提供该方案 | §4.4 |
| 17 | 错误信息带出明文 | 错误只含 key 名/文件名，绝不含 value | §0 |
| 18 | 忘记密码无恢复 | 设密码时明确警告 | §4.3 |
| 19 | std 无信号 API | 新增 libc（或 signal-hook）依赖 | §4.2 |
| 20 | 原子写已有，勿重造 | 复用 `profile::write` / `write_private_file` | §2 |

## 9. 实施里程碑与验收

按顺序做，每个里程碑完成 = 验收命令全过 + `cargo test` 全绿 + `cargo clippy -- -D warnings` 无警告。

### M0：已有代码英文化 + CLI 骨架 + 免密/只读命令
第一步：按 §2 将 `crypto.rs`/`envfile.rs`/`profile.rs` 的中文注释与错误信息翻译成英文（含测试断言），跑 `cargo test` 确认全绿。
然后实现 `list`、`show`（含 mask）、`export`、`rm`、`passwd`（复用已有三模块，新代码全英文）。
- 验收：
  ```
  cargo run -- list
  echo 'A=1' > /tmp/a.env && cargo run -- import t1 --from /tmp/a.env   # 两遍密码
  cargo run -- show t1          # A = ****（len<=4 -> ****）
  cargo run -- export t1        # stdout 得 A=1
  ```

### M1：run（本项目的灵魂）
信号转发、退出码表、overlay/--clean、--dry-run、--password-stdin、core dump 关闭、127/126。
- 验收脚本（逐条跑）：
  ```
  # 1) 注入 + 退出码透传
  echo 'FOO=hello' > /tmp/t.env; cargo run -- import t --from /tmp/t.env
  cargo run -- run t -- sh -c 'echo $FOO; exit 7'; echo "exit=$?"        # hello / exit=7
  # 2) 命令不存在 / 无权限
  cargo run -- run t -- /nonexistent; echo "exit=$?"                     # 127
  # 3) SIGTERM 转发（关键）
  cargo run -- run t -- sh -c 'trap "" TERM; sleep 30' &                  # 忽略 TERM 的 sh
  kill -TERM $!; sleep 1;  # envrun 不应提前退出，若子进程不退出由用户自行处理；
  cargo run -- run t -- python3 -c 'import time,sys; time.sleep(30)' &
  kill -TERM $!; sleep 1;  # python 应收到 TERM 死掉，envrun exit 143（128+15）
  # 4) Ctrl-C：交互终端里 cargo run -- run t -- python3 后按 Ctrl-C → exit 130，无孤儿
  # 5) --clean
  cargo run -- run t --clean -- sh -c 'echo $PATH; echo ${FOO-unset}'    # FOO 在；另有 PATH/HOME/TERM 等
  # 6) --dry-run 不执行任何东西且无值
  cargo run -- run t --dry-run -- python3 -c 'print("should not run")'
  # 7) clap 不吞参数
  cargo run -- run t -- curl --data a=b -I https://example.com 2>/dev/null || true   # curl 收到了自己的参数
  ```

### M2：import 排除名单 + edit + fpm-snippet
- 验收：
  ```
  cargo run -- import t2 --from-env --only MYVAR        # 名单外才进
  cargo run -- edit t2                                  # $EDITOR 里改一改，show 验证
  cargo run -- fpm-snippet t > pool.conf 片段           # 贴入 pool 后 php-fpm -tt 通过
  # php-fpm 实测（本机有 php 时）：
  #   pool 配置 clear_env=yes + snippet → PHP 中 getenv('FOO') 有值（env[] 生效）
  #   pool 配置 clear_env=no + envrun run → worker 也能拿到（继承生效）
  ```

### M3：密码体验
`--password-stdin`（若 M1 未含）、`unlock --ttl`（keyring crate）、`lock`、keychain 降级逻辑。
- 验收：`unlock` 后 90 秒内 `run` 免输密码；SSH 无 GUI 会话下 unlock 失败回退手输；`lock` 后恢复询问。

### M4（P2）：`--detach`、`envrun diff a b`（mask 输出差异 key）、README 完整版
README **全英文**，必含：§7 安全边界声明、php-fpm 三坑专章、.env 单引号建议、脚本用 `--password-stdin` 示例。

## 10. 测试要求

- 保持既有单测全绿；`mask`、`is_excluded`、fpm-snippet 转义、exit code 映射必须有单测。
- 信号行为无法在单测覆盖，以 §9 M1 手动验收脚本为准，验收结果记入 PR 描述。
- 端到端用 `/tmp` 下临时 profile，测试后清理（补一个 `envrun rm <name>`，M0 顺手实现，删除前英文确认提示 `Delete profile '<name>'? [y/N]`）。
