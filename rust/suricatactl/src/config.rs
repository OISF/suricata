// SPDX-FileCopyrightText: Copyright 2026 Open Information Security Foundation
// SPDX-License-Identifier: GPL-2.0-only

use std::path::PathBuf;

use clap::Parser;
use clap::Subcommand;
use clap::ValueEnum;

#[derive(Parser, Debug)]
pub struct ConfigCommand {
    #[command(subcommand)]
    command: ConfigCommands,
}

#[derive(Subcommand, Debug)]
enum ConfigCommands {
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
    Json,
    Debug,
    Flat,
}

pub fn run(config: ConfigCommand) -> Result<(), Box<dyn std::error::Error>> {
    match config.command {
        ConfigCommands::Print(args) => print_config(args),
    }
}

fn print_config(args: PrintArgs) -> Result<(), Box<dyn std::error::Error>> {
    let config = suricata_config::load_file(&args.path)?;

    match args.format {
        OutputFormat::Yaml => print!("{}", suricata_config::print_yaml(&config)?),
        OutputFormat::Json => println!("{}", suricata_config::print_json(&config)?),
        OutputFormat::Debug => println!("{config:#?}"),
        OutputFormat::Flat => print!("{}", suricata_config::print_flat_config(&config)),
    }

    Ok(())
}
