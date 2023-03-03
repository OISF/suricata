// SPDX-FileCopyrightText: Copyright 2023 Open Information Security Foundation
// SPDX-License-Identifier: GPL-2.0-only

use crate::unix::commands::CommandParser;
use crate::unix::commands::Commands;
use crate::unix::rustyprompt::RustyPrompt;
use serde_json::json;
use suricata_client::unix::{Client, ClientError, Response};

const DEFAULT_SC_PATH: &str = "/var/run/suricata/suricata-command.socket";

pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    let localstatedir = option_env!("LOCALSTATEDIR");
    let args: Vec<String> = std::env::args().collect();
    let mut opts = getopts::Options::new();
    opts.optflag("v", "verbose", "Verbose output");
    opts.optflag("h", "help", "Print this help menu");
    opts.optopt("c", "command", "Execute command and return JSON", "COMMAND");
    let matches = opts.parse(&args[1..])?;
    if matches.opt_present("h") {
        let brief = format!("Usage: {} [OPTIONS]", &args[0]);
        print!("{}", opts.usage(&brief));
        return Ok(());
    }

    let socket_filename = if let Some(filename) = matches.free.get(0) {
        filename.to_string()
    } else if let Some(localstatedir) = localstatedir {
        format!("{localstatedir}/suricata-command.socket")
    } else {
        DEFAULT_SC_PATH.to_string()
    };

    let verbose = matches.opt_present("v");
    if verbose {
        println!("Using Suricata command socket: {}", &socket_filename);
    }

    let client = match Client::connect(&socket_filename, verbose) {
        Ok(client) => client,
        Err(err) => {
            eprintln!("Unable to connect socket to {}: {}", &socket_filename, err);
            std::process::exit(1);
        }
    };

    if let Some(command) = matches.opt_str("c") {
        run_batch_command(client, &command)
    } else {
        run_interactive(client)
    }
}

fn run_interactive(mut client: Client) -> Result<(), Box<dyn std::error::Error>> {
    client.send(&json!({"command": "command-list"}))?;
    let response = client.read()?;
    let server_commands: Vec<String> =
        serde_json::from_value(response["message"]["commands"].clone())?;
    println!("Command list: {}, quit", server_commands.join(", "));
    let commands = Commands::new(server_commands);
    let command_parser = CommandParser::new(&commands);
    let mut prompt = RustyPrompt::new(commands.clone());

    while let Some(line) = prompt.readline() {
        if line.starts_with("quit") {
            break;
        }
        match command_parser.parse(&line) {
            Ok(command) => match interactive_request_response(&mut client, &command) {
                Ok(response) => {
                    let response: Response = serde_json::from_value(response).unwrap();
                    if response.status == "OK" {
                        println!("Success:");
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&response.message).unwrap()
                        );
                    } else {
                        println!("Error:");
                        println!("{}", serde_json::to_string(&response.message).unwrap());
                    }
                }
                Err(err) => {
                    println!("{}", err);
                }
            },
            Err(err) => {
                println!("{}", err);
            }
        }
    }

    Ok(())
}

fn run_batch_command(mut client: Client, command: &str) -> Result<(), Box<dyn std::error::Error>> {
    let commands = Commands::new(vec![]);
    let command_parser = CommandParser::new(&commands);
    let command = command_parser.parse(command)?;
    client.send(&command)?;
    let response = client.read()?;
    println!("{}", serde_json::to_string(&response)?);
    Ok(())
}

fn interactive_request_response(
    client: &mut Client, msg: &serde_json::Value,
) -> Result<serde_json::Value, ClientError> {
    client.send(msg)?;
    let response = client.read()?;
    Ok(response)
}
