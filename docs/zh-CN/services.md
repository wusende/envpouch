# 以服务方式运行

[← 中文 README](../../README.zh-CN.md)

`envp run` 会把自己替换成应用，所以每个守护进程看到的都是应用本身——没有包装进程、不需要换算 PID，信号和退出码直接透传。

每次启动和每次自动重启都需要无人值守地提供密码——系统服务里没有交互
tty——所以要用 `--password-file`（或 systemd credential）。

**给服务用专用 uid。** 这是唯一能挡住同用户下其他一切进程（包括 AI agent）访问应用环境的边界。见
[security.md](security.md#ai-agents-why-run-is-not-a-boundary)。

## systemd

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

用
`systemd-creds encrypt --name=envp.pass /etc/myapp/envp.pass /etc/myapp/envp.pass.enc`
创建加密凭证。`LoadCredential*` 以 0400 权限把它暴露在
`$CREDENTIALS_DIRECTORY` 中，`--password-file` 接受它。用 `LoadCredential=`
时源文件可以保持 root 属主 0600；systemd 会为服务用户复制一份。如果直接把
`--password-file` 指向普通路径，则要 `chmod 600` 并把属主设为服务用户；envp 拒绝组/其他用户可读的密码文件。

- `StateDirectory=myapp` 会以正确的属主创建 `/var/lib/myapp`。profile 本身要以
  `myapp` 身份创建（或对 profile 文件 chown），放在
  `ENVPOUCH_HOME` 下，否则 0600 的文件对服务不可读。
- `Type=notify` 正常工作：因为 envp exec 成了应用，应用就是 MainPID。
- 在 systemd 下不要用 `--clean`：它会丢掉 `NOTIFY_SOCKET`、
  `WATCHDOG_USEC`、`JOURNAL_STREAM` 和其他 systemd 提供的变量。
- 每次启动都要付一次 Argon2id 派生（几十到几百毫秒）。给会崩溃重启的服务留足
  `RestartSec` 和 `StartLimitBurst` 余量，别让这个延迟吃掉启动预算。
- 应用直接收到 SIGTERM；如果它死于该信号，systemd 报告
  `code=killed, signal=TERM`（常规形式），而不是包装进程的 143。
- 默认对应用禁用 core dump；当 systemd 的 `LimitCORE=` 应当生效时加
  `--allow-core-dumps`。

对于无人值守的守护进程机密，也要权衡 systemd 原生的 `LoadCredential=` /
`LoadCredentialEncrypted=`。envpouch 的优势在于加密的 profile 存储——备份和误提交都是死的——代价是每次启动一次 Argon2id 派生；之后进程就是应用本身。

## supervisord

在 exec 模型下，supervisord 看到的就是应用本身：启动后 envp 已经不在了，所以
`stopasgroup`/`killasgroup`、`stopwaitsecs`、autostart 和退出状态处理都与普通程序完全一致。

- 无人值守启动用 `--password-file`（0600）。
- 如果应用依赖 supervisor 提供的环境变量，不要用 `--clean`。
- 应用必须保持前台运行（不要自行 daemonize）；这是 supervisord 的要求，不是
  envp 的。

## php-fpm

php-fpm 的两个默认值会干掉注入的变量；`fpm-snippet` 就是为它准备的：

- `clear_env=yes`（默认）会清空 worker 的环境，PHP 里的
  `getenv()` 什么都拿不到。执行 `envp fpm-snippet prod >> www.conf`
  追加，每个变量输出一行 `env[KEY] = value`，或在 pool 里设 `clear_env = no`。
- `daemonize=yes`（默认）会把 master fork 到后台、原进程退出，于是守护进程看到服务停止。在 systemd/supervisord 下用 `daemonize = no`。
