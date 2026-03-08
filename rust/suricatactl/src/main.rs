// SPDX-FileCopyrightText: Copyright 2023 Open Information Security Foundation
// SPDX-License-Identifier: GPL-2.0-only

// Allow these patterns as its a style we like.
#![allow(clippy::needless_return)]
#![allow(clippy::let_and_return)]
#![allow(clippy::uninlined_format_args)]

use clap::builder::styling::{AnsiColor, Effects, Styles};
use clap::Parser;
use clap::Subcommand;
use tracing::Level;

mod config;
mod filestore;

const CLAP_STYLING: Styles = Styles::styled()
    .header(AnsiColor::Green.on_default().effects(Effects::BOLD))
    .usage(AnsiColor::Green.on_default().effects(Effects::BOLD))
    .literal(AnsiColor::Cyan.on_default().effects(Effects::BOLD))
    .placeholder(AnsiColor::Cyan.on_default())
    .error(AnsiColor::Red.on_default().effects(Effects::BOLD))
    .valid(AnsiColor::Cyan.on_default().effects(Effects::BOLD))
    .invalid(AnsiColor::Yellow.on_default().effects(Effects::BOLD));

#[derive(Parser, Debug)]
#[command(styles = CLAP_STYLING)]
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
    /// Filestore management commands
    Filestore(FilestoreCommand),

    /// Suricata configuration commands
    Config(config::ConfigCommand),
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
        Commands::Filestore(filestore) => match filestore.command {
            FilestoreCommands::Prune(args) => crate::filestore::prune::prune(args),
        },
        Commands::Config(config) => crate::config::run(config),
    }
}
