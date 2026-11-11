# Usage

[← README](../README.md)

Every command, flag and file. For service recipes see
[services.md](services.md); for what the encryption does and does not cover,
see [security.md](security.md).

## Commands

All commands except `list`, `rm`, `cp`, `rename`, `lock` and `complete` need
the password — unless the profile was unlocked first (`envp unlock`).
`--password-stdin` and `--password-file` are global flags that work
with every one of them, before or after the subcommand (the two are mutually
exclusive).

| Command | What it does |
|---|---|
| `import <name> --from <file> [--merge]` | Create a profile from a `.env` file; `--merge` folds into an existing one |
| `import <name> --from-env [--only A,B \| --except A,B]` | Import from the current environment; a default list (`PATH`, `HOME`, `SSH_*`, …) is excluded — `--only` bypasses it, `--except` adds to it |
| `show <name> [--reveal]` | Print variables, masked by default |
| `export <name> [-o <file>]` | Print `.env` text to stdout, or write it to a file |
| `edit <name>` | Edit in `$EDITOR` |
| `set <name> KEY=VALUE...` | Add or replace keys (creates the profile on first use); a bare `KEY` prompts for the value with hidden input |
| `unset <name> KEY...` | Remove keys |
| `diff <a> <b>` | Compare two profiles, masked |
| `run <name> <cmd> [args...]` | Run a command with the variables injected |
| `fpm-snippet <name>` | Print php-fpm pool `env[...]` lines |
| `list` / `rm` / `passwd` / `cp` / `rename` | List, delete (`rm -f` skips the confirmation), change password, copy, rename |
| `unlock <name> [--ttl <seconds>]` | Verify the password once, then let other commands skip the prompt until the TTL expires (default 900s) |
| `lock <name>` | Remove the cached unlock key immediately |
| `complete --shell <shell>` | Print shell completions |

`ls` and `mv` are aliases of `list` and `rename`.

A bare `KEY` in `set` is the safe way to store secrets: `KEY=VALUE` on the
command line is visible to same-user processes and lands in shell history.

Mutating commands (`import`, `set`, `unset`, `edit`, `passwd`, `rm`, `cp`,
`rename`) hold an exclusive lock on `<name>.envpouch.lock` while they work
(unix), so concurrent updates queue up instead of silently overwriting each
other; after ~5 seconds of waiting the command fails with a "busy" error. The
0-byte lock files are normal, ignored by `envp list`, and copying or deleting
them is harmless.

## run

```sh
envp run prod ./deploy.sh
envp run prod --clean python app.py      # only a minimal base env plus profile vars
envp run prod --dry-run ./deploy.sh      # print what would run, never values
envp run prod --allow-core-dumps ./srv   # keep core dumps (LimitCORE= applies)
```

For an ad-hoc background process, `nohup envp run prod ./server &` works (with
`--password-file`; a backgrounded job cannot prompt). envp turns into the app
and leaves nothing behind. Use systemd/supervisord when you need restarts and
supervision.

- By default the command gets your full environment with the profile variables
  on top. `--clean` gives it only `PATH`, `HOME`, `USER` and a few base
  variables plus the profile.
- Everything after the command name goes to it untouched. `--` is only needed
  when the command itself starts with an envp option, e.g.
  `envp run prod -- --clean`.
- On unix, after decrypting envp **execs the command in place**: envp turns
  into the command itself, keeping the same PID, process group and terminal.
  Nothing named envp stays in the process tree, so Ctrl-C/Ctrl-Z, supervisor
  signals and the exit status reach the application directly.
- The exit status you get is the application's own. envp itself exits nonzero
  only for its own errors: `1` such as a wrong password, `2` a usage error,
  `126` no execute permission, `127` command not found.
- Core dumps are disabled for the command by default (a crash cannot dump
  memory that holds the decrypted variables); `--allow-core-dumps` keeps the
  supervisor's limits instead (systemd `LimitCORE=`, `ulimit -c`).

## unlock / lock

Typing the password for every command adds up during development.
`unlock` verifies the password once and caches the profile's derived key
(never the password itself) for a while:

```sh
envp unlock prod                 # cache for 15 minutes (default TTL)
envp unlock prod --ttl 3600      # custom window, max 30 days
envp show prod                   # no prompt — and no Argon2 pass
envp run prod ./deploy.sh        # same
envp lock prod                   # remove the cache immediately
```

- Only commands run without `--password-stdin` / `--password-file` use
  the cache, so scripts and services keep their deterministic
  one-line-per-prompt behavior.
- The cache lives next to the profile
  (`~/.envpouch/profiles/<name>.envpouch.unlock`, mode 0600 in the same
  0700 directory) and holds the derived key only — enough to decrypt that
  one profile, nothing more. `passwd`, `rm` and `rename` invalidate it,
  and expired entries are deleted the next time a command looks.
- Within the window, `passwd` skips the old-password check too — the
  cached key already proves it — and only asks for the new password.
  (`rm` never asked for a password in the first place.)
- `envp lock <name>` is idempotent: running it on a locked profile is a
  clean success.

The security tradeoff — a derived key sitting on disk for the TTL — is
covered in [security.md](security.md#what-is-encrypted).

## Scripts / CI

```sh
printf '%s\n' "$PW" | envp run prod --password-stdin ./deploy.sh
printf '%s\n' "$PW" | envp --password-stdin export prod -o /tmp/prod.env
envp run prod --password-file /etc/myapp/envp.pass ./deploy.sh   # services
```

One stdin line — or one file line — per password prompt, in prompt order:
`passwd` reads the current password then the new one, `diff` reads one per
profile. On unix, `run` consumes exactly one line and leaves the rest of stdin
to the command. envp deliberately has no password environment variable, since
process environments are readable by same-user processes. `--password-file`
refuses group/world-readable files (chmod 600).

## Files

Profiles live in `~/.envpouch/profiles/<name>.envpouch`, each a self-contained
encrypted file. Back them up by copying the directory. Sidecars live next to
them: `<name>.envpouch.lock` (the write lock) and `<name>.envpouch.unlock`
(the cached key from `envp unlock`, mode 0600).

```sh
export ENVPOUCH_HOME=/var/lib/myapp/envpouch   # move storage elsewhere
export ENVPOUCH_AUDIT=1                        # log every command to audit.log
```

The audit log records timestamp, command, profile and exit code for every
invocation, never variable names or values.

## Shell completion

```sh
envp complete --shell bash > ~/.local/share/bash-completion/completions/envp
envp complete --shell zsh   > "${fpath[1]}/_envp"
envp complete --shell fish  > ~/.config/fish/completions/envp.fish
```

## Limitations

- The stored profile is canonical (alphabetical keys): comments and
  formatting from the source `.env` are dropped at import; `export` and
  `edit` show and rewrite that canonical form.
- `edit` keeps a plaintext temp file (mode 0600, in a 0700 directory under
  `ENVPOUCH_HOME`) while the editor is open. If the editor is killed, the file
  lingers there until the next `edit` removes files older than an hour. (Older
  versions used the shared system temp directory; leftovers from those
  versions are still swept from there.)
- On Windows there is no `exec`: `run` spawns and waits, so one extra process
  remains (Ctrl-C reaches the application via the shared console). File
  permissions are NTFS ACLs rather than 0600. There, `run --password-stdin`
  reads through a buffered pipe: if the command itself also reads stdin,
  buffered bytes can be lost to it (unix reads byte-by-byte and leaves the
  rest of the pipe alone).
