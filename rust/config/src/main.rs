// SPDX-FileCopyrightText: Copyright 2026 Open Information Security Foundation
// SPDX-License-Identifier: GPL-2.0-only

use std::path::PathBuf;

use clap::Parser;
use clap::Subcommand;
use clap::ValueEnum;

#[derive(Parser, Debug)]
#[command(about = "Utilities for Suricata configuration files")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Read and print a Suricata configuration file.
    Print(PrintArgs),
}

#[derive(Parser, Debug)]
struct PrintArgs {
    /// Path to the Suricata configuration file.
    path: PathBuf,

    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Yaml)]
    format: OutputFormat,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum OutputFormat {
    Yaml,
    Debug,
    Flat,
}

// Parse CLI arguments and dispatch the selected subcommand.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Command::Print(args) => print_config(args),
    }
}

// Load a configuration file and print it in the requested format.
fn print_config(args: PrintArgs) -> Result<(), Box<dyn std::error::Error>> {
    let config = suricata_config::load_file(&args.path)?;

    match args.format {
        OutputFormat::Yaml => print!("{}", suricata_config::print_yaml(&config)?),
        OutputFormat::Debug => println!("{config:#?}"),
        OutputFormat::Flat => print!("{}", suricata_config::print_flat_config(&config)),
    }

    Ok(())
}
