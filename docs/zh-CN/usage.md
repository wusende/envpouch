# 用法

[← 中文 README](../../README.zh-CN.md)

所有命令、旗标和文件的完整说明。服务的配置配方见
[services.md](services.md)；加密能防什么、不能防什么见
[security.md](security.md)。

## 命令

除 `list`、`rm`、`cp`、`rename` 和 `complete` 外，所有命令都需要密码。
`--password-stdin` 和 `--password-file` 是全局旗标，对每条命令都有效，放在子命令前后均可（两者互斥）。

| 命令 | 作用 |
|---|---|
| `import <name> --from <file> [--merge]` | 从 `.env` 文件创建 profile；`--merge` 合并进已有 profile |
| `import <name> --from-env [--only A,B \| --except A,B]` | 从当前环境导入；默认排除列表（`PATH`、`HOME`、`SSH_*` 等）始终排除 |
| `show <name> [--reveal]` | 打印变量，默认打码 |
| `export <name> [-o <file>]` | 把 `.env` 文本打印到 stdout，或写入文件 |
| `edit <name>` | 在 `$EDITOR` 中编辑 |
| `set <name> KEY=VALUE...` | 添加或替换键；单独的 `KEY` 会以隐藏输入方式提示输入值 |
| `unset <name> KEY...` | 删除键 |
| `diff <a> <b>` | 比较两个 profile，打码显示 |
| `run <name> <cmd> [args...]` | 注入变量并运行命令 |
| `fpm-snippet <name>` | 打印 php-fpm pool 的 `env[...]` 行 |
| `list` / `rm` / `passwd` / `cp` / `rename` | 列出、删除、改密码、复制、重命名 |
| `complete --shell <shell>` | 打印 shell 补全脚本 |

在 `set` 中用单独的 `KEY` 是存放机密的安全方式：命令行上的 `KEY=VALUE`
对同用户进程可见，还会进入 shell 历史。

变更类命令（`import`、`set`、`unset`、`edit`、`passwd`、`rm`、`cp`、
`rename`）工作时会对 `<name>.envpouch.lock` 持有排他锁（unix），并发更新会排队而不是互相静默覆盖；等待约 5 秒后命令以
"busy" 错误失败。0 字节的锁文件是正常的，`envp list` 会忽略它们，复制或删除它们也无害。

## run

```sh
envp run prod ./deploy.sh
envp run prod --clean python app.py      # 只有最小基础环境加 profile 变量
envp run prod --dry-run ./deploy.sh      # 打印将要运行的命令，绝不打印值
envp run prod --allow-core-dumps ./srv   # 保留 core dump（LimitCORE= 生效）
```

临时后台进程可以用 `nohup envp run prod ./server &`（需配合
`--password-file`；后台任务无法交互提示）。envp 会变成应用本身，不留任何东西。需要重启和守护时用 systemd/supervisord。

- 默认情况下，命令继承你的完整环境，profile 变量覆盖在其上。`--clean`
  则只给 `PATH`、`HOME`、`USER` 和少数基础变量加 profile。
- 命令名之后的所有内容原样传给命令。只有当命令本身以 envp 选项开头时才需要
  `--`，例如 `envp run prod -- --clean`。
- 在 unix 上，解密后 envp 会**就地 exec 目标命令**：envp 变成命令本身，保持相同的
  PID、进程组和终端。进程树里不再有名为 envp 的东西，因此 Ctrl-C/Ctrl-Z、守护进程信号和退出状态都直接到达应用。
- 你得到的退出状态就是应用自己的。envp 只为自己的错误以非零退出：`1`
  如密码错误，`2` 用法错误，`126` 无执行权限，`127` 命令未找到。
- 默认对命令禁用 core dump（崩溃时无法转储含有解密变量的内存）；
  `--allow-core-dumps` 则保留守护进程的限制（systemd `LimitCORE=`、
  `ulimit -c`）。

## 脚本 / CI

```sh
printf '%s\n' "$PW" | envp run prod --password-stdin ./deploy.sh
printf '%s\n' "$PW" | envp --password-stdin export prod -o /tmp/prod.env
envp run prod --password-file /etc/myapp/envp.pass ./deploy.sh   # 服务
```

每次密码提示从 stdin 读一行——或从文件读一行——顺序与提示出现顺序一致：
`passwd` 先读当前密码再读新密码，`diff` 每个 profile 读一个。在 unix 上，`run` 恰好消费一行，把 stdin 的剩余部分留给命令。envp 刻意不提供密码环境变量，因为进程环境对同用户进程可读。`--password-file`
拒绝组/其他用户可读的文件（chmod 600）。

## 文件

profile 存放在 `~/.envpouch/profiles/<name>.envpouch`，每个都是自包含的加密文件。备份就是拷贝这个目录。

```sh
export ENVPOUCH_HOME=/var/lib/myapp/envpouch   # 把存储移到别处
export ENVPOUCH_AUDIT=1                        # 把每条解密命令记入 audit.log
```

审计日志记录时间戳、命令、profile 和退出码，从不记录变量名或值。

## Shell 补全

```sh
envp complete --shell bash > ~/.local/share/bash-completion/completions/envp
envp complete --shell zsh   > "${fpath[1]}/_envp"
envp complete --shell fish  > ~/.config/fish/completions/envp.fish
```

## 限制

- export 和 edit 会以规范形式重写 profile（键按字母排序）；源 `.env`
  的注释和格式不会保留。
- 编辑器打开期间，`edit` 会保留一个明文临时文件（权限 0600，位于
  `ENVPOUCH_HOME` 下的 0700 目录中）。如果编辑器被杀掉，文件会留在那里，直到下一次 `edit` 清理超过一小时
  的旧文件。（旧版本使用共享的系统临时目录；那些版本留下的残留文件仍会从那里清理。）
- 在 Windows 上没有 `exec`：`run` 会 spawn 并等待，因此会多留一个进程
  （Ctrl-C 通过共享控制台到达应用）。文件权限是 NTFS ACL 而非 0600。在 Windows 上，`run --password-stdin`
  通过缓冲管道读取：如果命令本身也读 stdin，缓冲的字节可能被它抢走（unix 逐字节读取，管道中剩余部分不受影响）。
