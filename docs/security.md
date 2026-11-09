# Security model

[← README](../README.md)

## What is encrypted

Profiles are encrypted with AES-256-GCM, keys derived via Argon2id: a fresh
nonce on every write, and a fresh salt when the profile is created or the
password changes (edits keep the profile's salt; GCM requires only nonce
uniqueness per key). Writes are atomic, files mode 0600. This protects data
at rest: lost laptops, backups, accidentally committed directories.

On unix, `run` execs the application instead of wrapping it, so decrypted
variables, the derived key and password buffers do not linger in memory for
the service lifetime.

It does not protect against a same-user process reading a running process's
environment (`/proc/<pid>/environ`, `ps eww`), root, or keyloggers. `--clean`
shrinks what the application sees, not what a same-uid reader can take. The
next section is about that gap, because it is the one that bites when an AI
agent is the same-user process.

## AI agents: why `run` is not a boundary

A human typing `cat` is not the threat model here. An agent with a shell is:
same uid, same file access, no malice required, and a single `env` or `cat` is
all it takes. `envp run` does not survive that, and no flag can make it.

Measured on Linux with the agent running as the same user as the service:

| What the agent does | What it gets |
|---|---|
| `tr '\0' '\n' < /proc/<pid>/environ` | every injected variable in plaintext |
| `ps eww -p <pid>` | the same, without even opening `/proc` |
| starts a child of the app | every variable inherited |
| `envp export prod --password-file … -o out.env` | a plaintext `.env` |
| `cat token.txt` (any leftover 0600 secret) | plaintext |

The bottom two matter most: the agent never needs `/proc`. If it can read the
password file, it can decrypt the profile itself, so the profile adds nothing.
And a secret that still lives in `token.txt`, `.env` or a CI variable was never
encrypted in the first place — `envp run` only covers the values you actually
moved in.

### There is no in-process fix

Linux offers exactly one lever against a same-uid reader:
`prctl(PR_SET_DUMPABLE, 0)`, which makes `/proc/<pid>/{environ,mem,maps}` and
`ptrace(2)` attachments fail with `EPERM` for non-root readers. It works — but
only on a process that calls it after its own `execve(2)`, which resets the
flag to 1. envp's model is "decrypt, then exec the target", so the flag is
envp's to set only for the instant before the target replaces it. The target
could call the prctl in `main()`; envp cannot call it on the target's behalf.
This is also why core dumps are disabled and the image is replaced — and why
none of it helps against a reader.

### What actually works

**1. A different uid.** The only boundary a general-purpose OS offers.

```sh
sudo useradd -r -M -s /usr/sbin/nologin appsrv
sudo install -d -o appsrv -m 700 /var/lib/appsrv/envpouch
# import the profile as appsrv, then in the unit:
#   User=appsrv
#   Environment=ENVPOUCH_HOME=/var/lib/appsrv/envpouch
#   ExecStart=/usr/local/bin/envp run prod --password-file /etc/appsrv/envp.pass -- /usr/bin/app
```

The agent, running as your user, can then read neither the 0700
`/var/lib/appsrv`, nor `/etc/appsrv/envp.pass` (0600, `appsrv`), nor `appsrv`'s
`/proc/<pid>/environ`. Keep the agent off that uid and the secrets are out of
reach.

**2. Keep the credential out of the agent's world.** When the agent itself has
to call a third-party API, injecting a key into its environment — or handing it
a profile — is the wrong shape. The agent needs the *capability*, not the
*key*. That is what [keysink](https://github.com/wusende/keysink) provides: a
long-lived local gateway holds the secret and injects it upstream, and the
agent talks to `http://127.0.0.1:<port>/…` without ever holding a credential.

A long-lived gateway can do one thing envp cannot: `keysink serve` calls
`prctl(PR_SET_DUMPABLE, 0)` at startup, and a same-uid agent then gets `EPERM`
from `/proc/<pid>/{environ,mem,maps}`, `gdb -p` and `strace -p`, even with
`kernel.yama.ptrace_scope=0`. Only a process that survives `exec` can do this,
which is why `envp run` never can. That covers the gateway's memory, not your
vault directory: read the
[keysink threat section](https://github.com/wusende/keysink#the-other-channels-same-user-not-same-process)
before deploying, because `vault.key` is still only as private as its file
mode makes it.

Deployment rules, or the gateway is theatre:

- the secret lives where the agent cannot read it (root-only, or the gateway's
  own uid; `LoadCredentialEncrypted=` in a systemd unit);
- the gateway's *code* lives there too — a gateway inside a directory the agent
  can write is a secret-exfiltration endpoint you installed yourself;
- the gateway narrows the capability: method and endpoint allowlist, rate
  limit, audit log. The agent stops holding your key but still spends your
  quota, so size that quota for abuse.

**3. Neither? Then scope the damage.** Delete plaintext tokens from any tree
the agent can read (`token.txt`, `.env`, CI variables), give tokens the
narrowest scopes that still work, and set expiry. That is containment, not a
boundary.

### Rule of thumb

| The secret is meant for | Use |
|---|---|
| a service you start and supervise | `envp run` under a dedicated uid |
| a tool the agent invokes | the gateway ([keysink](https://github.com/wusende/keysink)), not `envp run` |
| both | profile under the service uid; gateway for anything agent-facing |
