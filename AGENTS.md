# envrun

加密的环境变量 profile 管理器（Rust）。核心命令：`envrun run <profile> -- <command>`。

## 开发必读

**开始任何编码前，先完整阅读 [docs/DEV_GUIDE.md](docs/DEV_GUIDE.md)**，它是本项目的唯一开发依据：

- §0 铁律（文件格式 v1 不可破坏、错误信息中文、stdout/stderr 分离等）
- §2 代码现状盘点：`crypto.rs` / `envfile.rs` / `profile.rs` 已完成，**不要重构**
- §8 踩坑清单：实现前逐条对照（信号转发、php-fpm clear_env/daemonize、clap `--` 处理等 20 条）
- §9 里程碑：按 M0→M3 顺序实现，每个里程碑有可执行的验收命令

## 约定

- **全英文开发**：代码注释、CLI 帮助文案、错误信息、交互提示、命令输出一律英文；M0 第一步先把已有三个模块的中文注释/错误信息翻译成英文
- stdout 只放数据，stderr 放诊断；secret 一律 mask 输出（§6.1 的 mask 函数）
- 完成每个里程碑：`cargo test` 全绿 + `cargo clippy -- -D warnings` 无警告 + 验收命令通过
