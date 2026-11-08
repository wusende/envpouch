# Running as a service

[← README](../README.md)

`envp run` replaces itself with the application, so every supervisor sees the
application directly — no wrapper process, no PID to translate, signals and
exit codes pass through.

Every start and every automatic restart needs the password unattended — there
is no interactive tty in a system service — so use `--password-file` (or a
systemd credential).

**Use a dedicated uid for the service.** That is the one boundary that keeps
the application's environment out of reach of anything else running as you
(including an AI agent). See [security.md](security.md#ai-agents-why-run-is-not-a-boundary).

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

Create the encrypted credential with
`systemd-creds encrypt --name=envp.pass /etc/myapp/envp.pass /etc/myapp/envp.pass.enc`.
`LoadCredential*` exposes it at mode 0400 in `$CREDENTIALS_DIRECTORY`, which
`--password-file` accepts. With `LoadCredential=` the source may stay
root-owned 0600; systemd copies it for the service user. If you point
`--password-file` at a plain path directly instead, `chmod 600` and own it as
the service user; envp refuses group/world-readable password files.

- `StateDirectory=myapp` creates `/var/lib/myapp` with the right owner. Create
  the profile itself as `myapp` (or chown the profile files) under
  `ENVPOUCH_HOME`, otherwise the 0600 files are unreadable to the service.
- `Type=notify` works normally: the application is MainPID because envp execs
  it.
- Do not use `--clean` under systemd: it drops `NOTIFY_SOCKET`,
  `WATCHDOG_USEC`, `JOURNAL_STREAM` and other systemd-provided variables.
- Every start pays one Argon2id derivation (tens to hundreds of milliseconds).
  Give crash-looping services `RestartSec` and `StartLimitBurst` headroom so
  this delay does not eat the start budget.
- The application receives SIGTERM directly; if it dies from the signal,
  systemd reports `code=killed, signal=TERM` (conventional), not a wrapper's
  143.
- Core dumps are disabled for the application by default; add
  `--allow-core-dumps` when systemd's `LimitCORE=` should apply.

For unattended daemon secrets, also weigh systemd's native `LoadCredential=` /
`LoadCredentialEncrypted=`. envpouch's edge is the encrypted profile storage —
backups and accidental commits stay inert — at the cost of one Argon2id
derivation per start; after that the process is the application.

## supervisord

With the exec model, supervisord sees the application itself: envp is gone
after startup, so `stopasgroup`/`killasgroup`, `stopwaitsecs`, autostart and
exit-status handling behave exactly as for a normal program.

- Use `--password-file` (0600) for unattended starts.
- Do not use `--clean` if the app relies on supervisor-provided environment
  variables.
- The application must stay in the foreground (no self-daemonizing); that is a
  supervisord requirement, not an envp one.

## php-fpm

Two php-fpm defaults defeat injected variables; `fpm-snippet` exists for this:

- `clear_env=yes` (the default) wipes the environment for workers, so
  `getenv()` in PHP returns nothing. Append `envp fpm-snippet prod >> www.conf`
  to emit one `env[KEY] = value` line per variable, or set `clear_env = no` in
  the pool.
- `daemonize=yes` (the default) forks the master into the background and the
  original process exits, so the supervisor sees the service stop. Under
  systemd/supervisord, use `daemonize = no`.
