//! envrun — encrypted environment variable profile manager.
//!
//! Usage:
//! - `envrun import <name> (--from <file> | --from-env) [--merge]`   import into an encrypted profile
//! - `envrun show <name> [--reveal]`                                 show variables (masked by default)
//! - `envrun export <name> [-o <file>]`                              export as .env (stdout without -o)
//! - `envrun edit <name>`                                            edit variables in $EDITOR
//! - `envrun fpm-snippet <name>`                                     php-fpm pool env[...] lines
//! - `envrun diff <a> <b>`                                           compare two profiles (masked)
//! - `envrun run <name> -- <command> [args...]`                      run with the variables injected
//! - `envrun list / rm / passwd / unlock / lock`                     profile management
//!
//! Every decrypting command obtains the password via --password-stdin, the
//! OS keychain cache (`unlock`), or the interactive prompt (spec §4.3).

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
    name = "envrun",
    version,
    about = "Encrypted environment variable profile manager",
    long_about = "Store .env files as encrypted, password-protected profiles (Argon2id + AES-256-GCM),\nexport them, or inject them into child processes. Every import/show/export/run\nrequires the password."
)]
struct Cli {
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
        /// Start the command detached in a new session; envrun exits immediately
        #[arg(long)]
        detach: bool,
        /// Read the password from the first line of stdin (for scripts/CI)
        #[arg(long)]
        password_stdin: bool,
        /// Command and arguments to execute (separate them with --)
        #[arg(
            trailing_var_arg = true,
            allow_hyphen_values = true,
            value_name = "COMMAND"
        )]
        command: Vec<String>,
    },
    /// List all profiles (no password required)
    List,
    /// Delete a profile
    Rm {
        /// Profile name
        name: String,
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
            Commands::FpmSnippet { name } => ("fpm-snippet", Some(name.clone())),
            Commands::Diff { name_a, .. } => ("diff", Some(name_a.clone())),
            Commands::Run { name, .. } => ("run", Some(name.clone())),
            Commands::List => ("list", None),
            Commands::Rm { name } => ("rm", Some(name.clone())),
            Commands::Passwd { name } => ("passwd", Some(name.clone())),
            Commands::Unlock { name, .. } => ("unlock", Some(name.clone())),
            Commands::Lock { name } => ("lock", Some(name.clone())),
            Commands::Complete { .. } => ("complete", None),
        }
    }
}

fn main() {
    let cli = Cli::parse();
    let (action, profile) = cli.command.audit_info();
    let code = dispatch(cli.command);
    audit::record(action, profile.as_deref(), &format!("exit={code}"));
    if code != 0 {
        std::process::exit(code);
    }
}

/// Exit codes (spec §3): 0 success, 1 envrun error, 2 usage error (clap default).
/// `run` forwards the child's exit code 1:1.
fn dispatch(command: Commands) -> i32 {
    let result = match command {
        Commands::Import {
            name,
            from,
            from_env,
            only,
            except,
            merge,
        } => commands::import_command(&name, from, from_env, only, except, merge).map(|_| 0),
        Commands::Show { name, reveal } => commands::show(&name, reveal).map(|_| 0),
        Commands::Export { name, output } => commands::export(&name, output).map(|_| 0),
        Commands::Edit { name } => commands::edit(&name).map(|_| 0),
        Commands::FpmSnippet { name } => commands::fpm_snippet(&name).map(|_| 0),
        Commands::Diff { name_a, name_b } => commands::diff(&name_a, &name_b).map(|_| 0),
        Commands::Run {
            name,
            clean,
            dry_run,
            detach,
            password_stdin,
            command,
        } => commands::run(&name, clean, dry_run, detach, password_stdin, &command),
        Commands::List => commands::list().map(|_| 0),
        Commands::Rm { name } => commands::rm(&name).map(|_| 0),
        Commands::Passwd { name } => commands::passwd(&name).map(|_| 0),
        Commands::Unlock { name, ttl } => commands::unlock(&name, ttl).map(|_| 0),
        Commands::Lock { name } => commands::lock(&name).map(|_| 0),
        Commands::Complete { shell } => {
            let mut buf = Vec::new();
            clap_complete::generate(shell, &mut Cli::command(), "envrun", &mut buf);
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
