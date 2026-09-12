//! The `systole` binary: the CLI reference adapter (ADR-0001, ADR-0004).
//! One binary, project root resolved from `--project`, `$SYSTOLE_PROJECT`, or
//! the current directory.

mod cmd;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "systole",
    version,
    about = "Agent-native game engine: audited, reversible project transactions"
)]
struct Cli {
    /// Project root directory (default: $SYSTOLE_PROJECT, else the current directory)
    #[arg(long, global = true, value_name = "DIR")]
    project: Option<PathBuf>,

    /// Machine-readable one-line JSON output
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Project lifecycle verbs
    Project {
        #[command(subcommand)]
        command: ProjectCommand,
    },
}

#[derive(Subcommand)]
enum ProjectCommand {
    /// Initialize a new project directory at rev_00000
    Init {
        /// The directory to initialize
        dir: PathBuf,

        /// Initialize even if the directory is not empty
        #[arg(long)]
        force: bool,
    },
    /// Load and verify the project's integrity
    Check,
    /// Rewrite every IR file to canonical bytes
    Format {
        /// Report non-canonical files without writing; exit 1 if any
        #[arg(long)]
        check: bool,
    },
}

fn main() {
    let cli = Cli::parse();
    let code = match &cli.command {
        Command::Project { command } => match command {
            ProjectCommand::Init { dir, force } => cmd::init::run(dir, *force, cli.json),
            ProjectCommand::Check => {
                let root = cmd::project_root(cli.project.as_deref());
                cmd::check::run(&root, cli.json)
            }
            ProjectCommand::Format { check } => {
                let root = cmd::project_root(cli.project.as_deref());
                cmd::format::run(&root, *check, cli.json)
            }
        },
    };
    std::process::exit(code);
}
