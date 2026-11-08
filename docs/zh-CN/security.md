# 安全模型

[← 中文 README](../../README.zh-CN.md)

## 加密了什么

profile 用 AES-256-GCM 加密，密钥经 Argon2id 派生，每次写入都使用新的 salt 和
nonce，原子写入，文件权限 0600。这保护的是静态数据：丢失的笔记本、备份、误提交的目录。

在 unix 上，`run` 会 exec 应用而不是包着它运行，所以解密后的变量、派生密钥和密码缓冲区不会在服务的整个生命周期里驻留内存。

它防不住同用户进程读取运行中进程的环境（`/proc/<pid>/environ`、
`ps eww`）、root 或键盘记录器。`--clean` 缩小的是应用能看到的内容，而不是同 uid 读者能拿到的内容。下一节讲的就是这个缺口，因为当 AI agent 就是那个同用户进程时，被咬的就是这里。

<a id="ai-agents-why-run-is-not-a-boundary"></a>

## AI agent：为什么 `run` 不是边界

在这里，威胁模型不是敲 `cat` 的人。带着 shell 的 agent 才是：同 uid、同样的文件访问权，不需要恶意，一条 `env` 或 `cat` 就够了。`envp run` 抗不住这个，也没有任何旗标能让它抗住。

在 Linux 上、agent 与服务同用户运行时实测：

| agent 做什么 | 得到什么 |
|---|---|
| `tr '\0' '\n' < /proc/<pid>/environ` | 所有注入的变量，明文 |
| `ps eww -p <pid>` | 同样结果，连 `/proc` 都不用打开 |
| 启动应用的一个子进程 | 所有变量原样继承 |
| `envp export prod --password-file … -o out.env` | 一份明文 `.env` |
| `cat token.txt`（任何残留的 0600 机密） | 明文 |

最后两行最关键：agent 根本不需要 `/proc`。如果它能读密码文件，它就能自己解密 profile，于是 profile 毫无增益。而仍然存在于 `token.txt`、`.env` 或 CI 变量里的机密，从一开始就没加密过——`envp run` 只覆盖你真正搬进来的值。

### 进程内没有解法

Linux 对同 uid 读者只提供一个杠杆：
`prctl(PR_SET_DUMPABLE, 0)`，它让 `/proc/<pid>/{environ,mem,maps}` 和
`ptrace(2)` 附着对非 root 读者返回 `EPERM`。它有效——但只对在自己
`execve(2)` 之后调用它的进程有效，而 execve 会把该标志重置为 1。envp 的模型是"解密，然后 exec 目标"，所以 envp 只能在目标替换自己之前的那一瞬间设置标志。目标可以在 `main()` 里调用 prctl；envp 无法替目标调用。这也是禁用 core dump 和替换进程映像的原因——以及为什么这些都帮不了对抗读者。

### 真正有效的做法

**1. 换一个 uid。** 这是通用操作系统提供的唯一边界。

```sh
sudo useradd -r -M -s /usr/sbin/nologin appsrv
sudo install -d -o appsrv -m 700 /var/lib/appsrv/envpouch
# 以 appsrv 身份导入 profile，然后在 unit 中：
#   User=appsrv
#   Environment=ENVPOUCH_HOME=/var/lib/appsrv/envpouch
#   ExecStart=/usr/local/bin/envp run prod --password-file /etc/appsrv/envp.pass -- /usr/bin/app
```

这样，以你的用户运行的 agent 既读不了 0700 的
`/var/lib/appsrv`，也读不了 `/etc/appsrv/envp.pass`（0600，属主
`appsrv`），也读不了 `appsrv` 的 `/proc/<pid>/environ`。把 agent 挡在这个 uid 之外，机密就够不着了。

**2. 把凭证留在 agent 的世界之外。** 当 agent 自己必须调用第三方 API
时，往它的环境里注入密钥——或递给它一份 profile——形状就错了。agent 需要的是*能力*，而不是*密钥*。这正是
[keysink](https://github.com/wusende/keysink) 提供的：一个长驻本地网关持有机密并在上游注入，agent 只跟
`http://127.0.0.1:<port>/…` 通信，从不持有凭证。

长驻网关能做一件 envp 做不到的事：`keysink serve` 在启动时调用
`prctl(PR_SET_DUMPABLE, 0)`，此后同 uid 的 agent 访问
`/proc/<pid>/{environ,mem,maps}`、`gdb -p` 和 `strace -p` 都会得到 `EPERM`，即使
`kernel.yama.ptrace_scope=0` 也是如此。只有能在 `exec` 中幸存的进程才能做到，这正是 `envp run` 永远做不到的原因。这覆盖的是网关自己的内存，不是你的 vault 目录：部署前先读
[keysink 威胁模型一节](https://github.com/wusende/keysink#the-other-channels-same-user-not-same-process)，因为 `vault.key` 的私密性仍然只取决于它的文件权限。

部署规则——不遵守，网关就是演戏：

- 机密放在 agent 读不到的地方（仅 root 可读，或网关自己的 uid；systemd unit 里的
  `LoadCredentialEncrypted=`）；
- 网关的*代码*也要放在那里——agent 可写目录里的网关，是你亲手安装的机密外泄端点；
- 网关收窄能力：method 和 endpoint 白名单、限流、审计日志。agent 不再持有你的密钥，但仍在消耗你的配额，所以配额要按滥用的规模来设。

**3. 两者都做不到？那就控制损害范围。** 从 agent 可读的所有目录树中删除明文
token（`token.txt`、`.env`、CI 变量），给 token 尽可能窄但仍可用的 scope，并设置过期时间。这是遏制，不是边界。

### 经验法则

| 机密给谁用 | 用什么 |
|---|---|
| 你启动并守护的服务 | 专用 uid 下的 `envp run` |
| agent 调用的工具 | 网关（[keysink](https://github.com/wusende/keysink)），不是 `envp run` |
| 两者都有 | profile 放在服务 uid 下；面向 agent 的一切走网关 |
