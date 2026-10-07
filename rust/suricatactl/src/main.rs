// SPDX-FileCopyrightText: Copyright 2023 Open Information Security Foundation
// SPDX-License-Identifier: GPL-2.0-only

// Allow these patterns as its a style we like.
#![allow(clippy::needless_return)]
#![allow(clippy::let_and_return)]
#![allow(clippy::uninlined_format_args)]

use std::path::PathBuf;

use clap::Parser;
use clap::Subcommand;
use clap::ValueEnum;
use tracing::Level;

mod config;
mod filestore;

#[derive(Parser, Debug)]
struct Cli {
    #[arg(long, short, global = true, action = clap::ArgAction::Count)]
    verbose: u8,

    #[arg(
        long,
        short,
        global = true,
        help = "Quiet mode, only warnings and errors will be logged"
    )]
    quiet: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Configuration commands
    Config(ConfigCommand),

    /// Filestore management commands
    Filestore(FilestoreCommand),
}

#[derive(Parser, Debug)]
struct ConfigCommand {
    #[command(subcommand)]
    command: ConfigCommands,
}

#[derive(Subcommand, Debug)]
enum ConfigCommands {
    /// Load a configuration like Suricata does and print it
    Print(ConfigPrintArgs),
}

#[derive(Parser, Debug)]
struct ConfigPrintArgs {
    #[arg(
        short = 'c',
        value_name = "FILE",
        required = true,
        help = "path to the configuration file"
    )]
    config: PathBuf,
    #[arg(
        long,
        value_name = "FILE",
        help = "additional configuration file, may be used more than once"
    )]
    include: Vec<PathBuf>,
    #[arg(long, value_enum, default_value_t = ConfigFormat::Yaml, help = "output format")]
    format: ConfigFormat,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ConfigFormat {
    /// YAML
    Yaml,
    /// The format of suricata --dump-config
    Flat,
}

#[derive(Parser, Debug)]
struct FilestoreCommand {
    #[command(subcommand)]
    command: FilestoreCommands,
}

#[derive(Subcommand, Debug)]
enum FilestoreCommands {
    /// Remove files by age
    Prune(FilestorePruneArgs),
}

#[derive(Parser, Debug)]
struct FilestorePruneArgs {
    #[arg(long, short = 'n', help = "only print what would happen")]
    dry_run: bool,
    #[arg(long, short, help = "file-store directory")]
    directory: String,
    #[arg(long, help = "prune files older than age, units: s, m, h, d")]
    age: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let log_level = if cli.quiet {
        Level::WARN
    } else if cli.verbose > 0 {
        Level::DEBUG
    } else {
        Level::INFO
    };
    tracing_subscriber::fmt().with_max_level(log_level).init();

    match cli.command {
        Commands::Config(config) => match config.command {
            ConfigCommands::Print(args) => crate::config::print::print(args),
        },
        Commands::Filestore(filestore) => match filestore.command {
            FilestoreCommands::Prune(args) => crate::filestore::prune::prune(args),
        },
    }
}
