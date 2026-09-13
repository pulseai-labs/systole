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
    /// The operation catalog
    Op {
        #[command(subcommand)]
        command: OpCommand,
    },
    /// Materialize an op request into a plan file
    Plan {
        /// The operation id
        op_id: String,

        /// JSON literal, @file, or - for stdin
        #[arg(long, value_name = "JSON")]
        input: String,

        /// Write the plan here instead of plans/<plan_id>.json
        #[arg(long, value_name = "PATH")]
        out: Option<PathBuf>,
    },
    /// Show a plan's diff and findings without writing anything
    Preview {
        /// A plan file, or an op id when --input is given
        target: String,

        /// JSON literal, @file, or - for stdin (required when target is an op id)
        #[arg(long, value_name = "JSON")]
        input: Option<String>,

        /// Print canonical before/after values under each change
        #[arg(long)]
        verbose: bool,
    },
    /// Preview, then commit the transaction and audit it
    Apply {
        /// A plan file, or an op id when --input is given
        target: String,

        /// JSON literal, @file, or - for stdin (required when target is an op id)
        #[arg(long, value_name = "JSON")]
        input: Option<String>,

        /// Print canonical before/after values under each change
        #[arg(long)]
        verbose: bool,
    },
    /// Roll back the head audit entry with a compensating transaction
    Rollback {
        /// The audit id to roll back (must be the head)
        audit_id: String,
    },
    /// Run a read operation and print its output
    Query {
        /// The read operation id
        op_id: String,

        /// JSON literal, @file, or - for stdin
        #[arg(long, value_name = "JSON")]
        input: String,
    },
}

#[derive(Subcommand)]
enum OpCommand {
    /// Every registered op: id, version, capability, mutability, summary
    List,
    /// The full description of one op, including its input schema
    Describe {
        /// The operation id
        id: String,
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
    /// Resolve interrupted commits, verify the chain and the project hash
    Doctor {
        /// Record out-of-band edits as an external_edit audit entry
        #[arg(long)]
        absorb: bool,
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
            ProjectCommand::Doctor { absorb } => {
                let root = cmd::project_root(cli.project.as_deref());
                cmd::doctor::run(&root, *absorb, cli.json)
            }
        },
        Command::Op { command } => match command {
            OpCommand::List => cmd::op::list(cli.json),
            OpCommand::Describe { id } => {
                let root = cmd::project_root(cli.project.as_deref());
                cmd::op::describe(&root, id, cli.json)
            }
        },
        Command::Plan { op_id, input, out } => {
            let root = cmd::project_root(cli.project.as_deref());
            cmd::plan::run(&root, op_id, input, out.as_deref(), cli.json)
        }
        Command::Preview {
            target,
            input,
            verbose,
        } => {
            let root = cmd::project_root(cli.project.as_deref());
            cmd::preview::run(&root, target, input.as_deref(), *verbose, cli.json)
        }
        Command::Apply {
            target,
            input,
            verbose,
        } => {
            let root = cmd::project_root(cli.project.as_deref());
            cmd::apply::run(&root, target, input.as_deref(), *verbose, cli.json)
        }
        Command::Rollback { audit_id } => {
            let root = cmd::project_root(cli.project.as_deref());
            cmd::rollback::run(&root, audit_id, cli.json)
        }
        Command::Query { op_id, input } => {
            let root = cmd::project_root(cli.project.as_deref());
            cmd::query::run(&root, op_id, input, cli.json)
        }
    };
    std::process::exit(code);
}
