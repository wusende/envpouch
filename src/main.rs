//! envpouch — encrypted environment variable profile manager.
//! The installed command is `envp` (the package/project is `envpouch`).
//!
//! Usage:
//! - `envp import <name> (--from <file> | --from-env) [--merge]`   import into an encrypted profile
//! - `envp show <name> [--reveal]`                                 show variables (masked by default)
//! - `envp export <name> [-o <file>]`                              export as .env (stdout without -o)
//! - `envp edit <name>`                                            edit variables in $EDITOR
//! - `envp fpm-snippet <name>`                                     php-fpm pool env[...] lines
//! - `envp diff <a> <b>`                                           compare two profiles (masked)
//! - `envp run <name> [options] <command> [args...]`                run with the variables injected
//! - `envp list / rm / cp / rename / passwd / unlock / lock`        profile management
//!
//! Every decrypting command obtains the password via one of the global
//! `--password-stdin` flag (one stdin line per prompt — scripts/CI),
//! `--password-file <file>` (one file line per prompt — services; file must
//! be mode 0600), the OS keychain cache (`unlock`), or the interactive
//! prompt (spec §4.3).

mod audit;
mod commands;
mod crypto;
mod envfile;
mod exclude;
#[cfg(test)]
mod fuzz_tests;
mod keycache;
mod mask;
mod profile;
#[cfg(unix)]
mod signals;

use std::path::PathBuf;

use clap::{CommandFactory, Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "envp",
    bin_name = "envp",
    version,
    about = "Encrypted environment variable profile manager (project: envpouch)",
    long_about = "Store .env files as encrypted, password-protected profiles (Argon2id + AES-256-GCM),\nexport them, or inject them into child processes. Every import/show/export/run\nrequires the password.\n\nThe project is called envpouch; the command is envp.",
    after_help = "Quick start:
  envp import prod --from .env.production   store a .env file as an encrypted profile
  envp run prod ./start-server.sh           run a command with those variables
  envp list                                 list profiles (no password)

Docs: https://github.com/wusende/envpouch"
)]
struct Cli {
    /// Read passwords from stdin (one line per prompt, in prompt order)
    /// instead of the interactive tty prompt — for scripts and CI
    #[arg(long, global = true)]
    password_stdin: bool,
    /// Read one password per line from this file (in prompt order) instead
    /// of the interactive tty prompt — for services; the file must be mode
    /// 0600 on unix
    #[arg(
        long,
        global = true,
        value_name = "FILE",
        conflicts_with = "password_stdin"
    )]
    password_file: Option<PathBuf>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Import variables into an encrypted profile (--from <file> or --from-env)
    Import {
        /// Profile name (letters, digits, '-', '_')
        name: String,
        /// Path to the .env file to import
        #[arg(long, value_name = "FILE")]
        from: Option<PathBuf>,
        /// Import variables from the current process environment
        #[arg(long)]
        from_env: bool,
        /// With --from-env: import only these comma-separated keys (bypasses the exclusion list)
        #[arg(long, value_name = "KEYS")]
        only: Option<String>,
        /// With --from-env: exclude these keys in addition to the default exclusion list
        #[arg(long, value_name = "KEYS")]
        except: Option<String>,
        /// Merge into an existing profile (same-name keys take the new value)
        #[arg(long)]
        merge: bool,
    },
    /// Show profile variables (values masked by default)
    Show {
        /// Profile name
        name: String,
        /// Print plaintext .env format instead of masked values
        #[arg(long)]
        reveal: bool,
    },
    /// Export a profile as .env format (stdout when no -o is given)
    Export {
        /// Profile name
        name: String,
        /// Output file path (default: stdout)
        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,
    },
    /// Edit a profile's variables in $EDITOR (plaintext exists only temporarily)
    Edit {
        /// Profile name
        name: String,
    },
    /// Add or replace variables (KEY=value; a bare KEY prompts with hidden input).
    /// Creates the profile on first use (asks for a new password).
    Set {
        /// Profile name
        name: String,
        /// KEY=value assignments; a bare KEY asks for the value without echo
        #[arg(required = true, value_name = "ASSIGNMENT")]
        assignments: Vec<String>,
    },
    /// Remove variables from a profile
    Unset {
        /// Profile name
        name: String,
        /// Variable names to remove
        #[arg(required = true, value_name = "KEY")]
        keys: Vec<String>,
    },
    /// Emit php-fpm pool env[...] lines for a profile (stdout)
    FpmSnippet {
        /// Profile name
        name: String,
    },
    /// Compare two profiles (masked values)
    Diff {
        /// First profile
        #[arg(value_name = "A")]
        name_a: String,
        /// Second profile
        #[arg(value_name = "B")]
        name_b: String,
    },
    /// Decrypt a profile and run a command with the variables injected
    Run {
        /// Profile name
        name: String,
        /// Use only a minimal base environment (PATH/HOME/TMPDIR/USER/LOGNAME/SHELL/TERM) plus profile variables
        #[arg(long)]
        clean: bool,
        /// Print what would be executed without running it (never any values)
        #[arg(long)]
        dry_run: bool,
        /// Start the command detached in a new session; envp exits immediately
        #[arg(long)]
        detach: bool,
        /// Keep core dumps enabled for the child (RLIMIT_CORE inherited from
        /// the supervisor, e.g. systemd LimitCORE=); core dumps are disabled
        /// by default
        #[arg(long)]
        allow_core_dumps: bool,
        /// Command and arguments to execute (everything after it is passed through;
        /// prefix with -- only if the command starts with an envp option)
        #[arg(
            trailing_var_arg = true,
            allow_hyphen_values = true,
            value_name = "COMMAND"
        )]
        command: Vec<String>,
    },
    /// List all profiles (no password required)
    #[command(visible_alias = "ls")]
    List,
    /// Delete a profile
    Rm {
        /// Profile name
        name: String,
        /// Delete without the confirmation prompt (scripts/CI)
        #[arg(short = 'f', long = "yes")]
        force: bool,
    },
    /// Copy a profile under a new name (same password)
    Cp {
        #[arg(value_name = "SRC")]
        src: String,
        #[arg(value_name = "DST")]
        dst: String,
    },
    /// Rename a profile
    #[command(visible_alias = "mv")]
    Rename {
        #[arg(value_name = "SRC")]
        src: String,
        #[arg(value_name = "DST")]
        dst: String,
    },
    /// Change the password of a profile
    Passwd {
        /// Profile name
        name: String,
    },
    /// Verify and cache the password in the OS keychain (default TTL 900s)
    Unlock {
        /// Profile name
        name: String,
        /// Cache lifetime in seconds
        #[arg(long, value_name = "SECONDS", default_value_t = 900)]
        ttl: u64,
    },
    /// Remove the cached keychain entry for a profile
    Lock {
        /// Profile name
        name: String,
    },
    /// Print shell completion script for the given shell (stdout)
    Complete {
        /// Target shell
        #[arg(long, value_enum)]
        shell: clap_complete::Shell,
    },
}

impl Commands {
    /// Audit metadata: (subcommand, profile name). Contains no secrets.
    fn audit_info(&self) -> (&'static str, Option<String>) {
        match self {
            Commands::Import { name, .. } => ("import", Some(name.clone())),
            Commands::Show { name, .. } => ("show", Some(name.clone())),
            Commands::Export { name, .. } => ("export", Some(name.clone())),
            Commands::Edit { name } => ("edit", Some(name.clone())),
            Commands::Set { name, .. } => ("set", Some(name.clone())),
            Commands::Unset { name, .. } => ("unset", Some(name.clone())),
            Commands::FpmSnippet { name } => ("fpm-snippet", Some(name.clone())),
            Commands::Diff { name_a, .. } => ("diff", Some(name_a.clone())),
            Commands::Run { name, .. } => ("run", Some(name.clone())),
            Commands::List => ("list", None),
            Commands::Rm { name, .. } => ("rm", Some(name.clone())),
            Commands::Cp { src, .. } => ("cp", Some(src.clone())),
            Commands::Rename { src, .. } => ("rename", Some(src.clone())),
            Commands::Passwd { name } => ("passwd", Some(name.clone())),
            Commands::Unlock { name, .. } => ("unlock", Some(name.clone())),
            Commands::Lock { name } => ("lock", Some(name.clone())),
            Commands::Complete { .. } => ("complete", None),
        }
    }
}

fn main() {
    let cli = Cli::parse();
    let password_stdin = cli.password_stdin;
    let password_file = cli.password_file;
    let (action, profile) = cli.command.audit_info();
    let code = dispatch(password_stdin, password_file, cli.command);
    audit::record(action, profile.as_deref(), &format!("exit={code}"));
    if code != 0 {
        std::process::exit(code);
    }
}

/// Exit codes (spec §3): 0 success, 1 envp error, 2 usage error (clap default).
/// `run` forwards the child's exit code 1:1.
fn dispatch(password_stdin: bool, password_file: Option<PathBuf>, command: Commands) -> i32 {
    let mut input = match commands::PasswordInput::from_flags(password_stdin, password_file) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("error: {e:#}");
            return 1;
        }
    };
    let result = match command {
        Commands::Import {
            name,
            from,
            from_env,
            only,
            except,
            merge,
        } => commands::import_command(&name, from, from_env, only, except, merge, &mut input)
            .map(|_| 0),
        Commands::Show { name, reveal } => commands::show(&name, reveal, &mut input).map(|_| 0),
        Commands::Export { name, output } => commands::export(&name, output, &mut input).map(|_| 0),
        Commands::Edit { name } => commands::edit(&name, &mut input).map(|_| 0),
        Commands::Set { name, assignments } => {
            commands::set(&name, &assignments, &mut input).map(|_| 0)
        }
        Commands::Unset { name, keys } => commands::unset(&name, &keys, &mut input).map(|_| 0),
        Commands::FpmSnippet { name } => commands::fpm_snippet(&name, &mut input).map(|_| 0),
        Commands::Diff { name_a, name_b } => {
            commands::diff(&name_a, &name_b, &mut input).map(|_| 0)
        }
        Commands::Run {
            name,
            clean,
            dry_run,
            detach,
            allow_core_dumps,
            command,
        } => commands::run(
            &name,
            clean,
            dry_run,
            detach,
            allow_core_dumps,
            &mut input,
            &command,
        ),
        Commands::List => commands::list().map(|_| 0),
        Commands::Rm { name, force } => commands::rm(&name, force).map(|_| 0),
        Commands::Cp { src, dst } => commands::cp(&src, &dst).map(|_| 0),
        Commands::Rename { src, dst } => commands::rename(&src, &dst).map(|_| 0),
        Commands::Passwd { name } => commands::passwd(&name, &mut input).map(|_| 0),
        Commands::Unlock { name, ttl } => commands::unlock(&name, ttl, &mut input).map(|_| 0),
        Commands::Lock { name } => commands::lock(&name).map(|_| 0),
        Commands::Complete { shell } => {
            let mut buf = Vec::new();
            clap_complete::generate(shell, &mut Cli::command(), "envp", &mut buf);
            commands::write_stdout(&buf).map(|_| 0)
        }
    };
    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            1
        }
    }
}
