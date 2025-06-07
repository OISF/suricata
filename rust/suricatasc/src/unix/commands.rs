// SPDX-FileCopyrightText: Copyright 2023 Open Information Security Foundation
// SPDX-License-Identifier: GPL-2.0-only

use serde::Deserialize;
use serde_json::json;
use std::{collections::HashMap, num::ParseIntError, str::FromStr};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CommandParseError {
    #[error("Unknown command {0}")]
    UnknownCommand(String),
    #[error("Failed to parse as number")]
    ParseIntError(#[from] ParseIntError),
    #[error("`{0}`")]
    Other(String),
}

#[derive(Debug, Copy, Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ArgType {
    String,
    Number,
    Bool,
    #[serde(rename = "number[]")]
    NumberArray,
}

#[derive(Clone)]
pub struct Commands {
    /// The list of parsed command the client knows about.
    pub commands: HashMap<String, Vec<Argument>>,

    /// A list of commands from the server. This is used to:
    /// - augment the list of known commands
    /// - error out on commands not given by Suricata as not all
    ///   command are valid in all running modes.
    server_commands: Vec<String>,
}

impl Commands {
    pub fn new(server_commands: Vec<String>) -> Self {
        let mut commands = command_defs().unwrap();
        for command in &server_commands {
            if !commands.contains_key(command) {
                commands.insert(command.to_string(), vec![]);
            }
        }
        Self {
            commands,
            server_commands,
        }
    }

    pub fn get(&self, command: &str) -> Option<&Vec<Argument>> {
        self.commands.get(command)
    }

    pub fn is_valid(&self, command: &str) -> bool {
        self.server_commands.iter().any(|c| c == command)
    }
}

pub struct CommandParser<'a> {
    pub commands: &'a Commands,
}

impl<'a> CommandParser<'a> {
    pub fn new(commands: &'a Commands) -> Self {
        Self { commands }
    }

    pub fn parse(&self, input: &str) -> Result<serde_json::Value, CommandParseError> {
        let mut parts: Vec<&str> = input.split(' ').map(|s| s.trim()).collect();
        if parts.is_empty() {
            return Err(CommandParseError::Other("No command provided".to_string()));
        }
        let command = parts[0];

        let spec = self
            .commands
            .get(command)
            .ok_or(CommandParseError::UnknownCommand(command.to_string()))?;

        if !self.commands.is_valid(command) {
            return Err(CommandParseError::Other(
                "Command not valid for current Suricata running-mode".to_string(),
            ));
        }

        // Calculate the number of required arguments for better error reporting.
        let required = spec.iter().filter(|e| e.required).count();
        let optional = spec.iter().filter(|e| !e.required).count();
        // Handle the case where the command has only required arguments and allow
        // last one to contain spaces.
        if optional == 0 {
            parts = input.splitn(required + 1, ' ').collect();
        }
        let args = &parts[1..];

        let mut json_args = HashMap::new();

        for (i, spec) in spec.iter().enumerate() {
            if let Some(arg) = args.get(i) {
                let val = match spec.datatype {
                    ArgType::String => serde_json::Value::String(arg.to_string()),
                    ArgType::Bool => match *arg {
                        "true" | "1" => true.into(),
                        "false" | "0" => false.into(),
                        _ => {
                            return Err(CommandParseError::Other(format!(
                                "Bad argument: value is not a boolean: {}",
                                arg
                            )));
                        }
                    },
                    ArgType::Number => {
                        let number = serde_json::Number::from_str(arg).map_err(|_| {
                            CommandParseError::Other(format!("Bad argument: not a number: {}", arg))
                        })?;
                        serde_json::Value::Number(number)
                    }
                    ArgType::NumberArray => {
                        let mut numbers = vec![];
                        for arg in &args[i..] {
                            numbers.push(arg.parse::<u16>()?);
                        }
                        let json: serde_json::Value = numbers.into();
                        dbg!(json);
                        panic!();
                    }
                };
                json_args.insert(&spec.name, val);
            } else if spec.required {
                return Err(CommandParseError::Other(format!(
                    "Missing arguments: expected at least {}",
                    required
                )));
            }
        }

        let mut message = json!({ "command": command });
        if !json_args.is_empty() {
            message["arguments"] = json!(json_args);
        }

        Ok(message)
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct Argument {
    pub name: String,
    pub required: bool,
    #[serde(rename = "type")]
    pub datatype: ArgType,
    pub _value: Option<serde_json::Value>,
}

fn command_defs() -> Result<HashMap<String, Vec<Argument>>, serde_json::Error> {
    // As found in specs.py.
    #[rustfmt::skip]
    let defs = json!({
	"pcap-file": [
            {
		"name": "filename",
		"required": true,
		"type": "string",
            },
            {
		"name": "output-dir",
		"required": true,
		"type": "string",
            },
            {
		"name": "tenant",
		"type": "number",
		"required": false,
            },
            {
		"name": "continuous",
		"required": false,
		"type": "bool",
            },
            {
		"name": "delete-when-done",
		"required": false,
		"type": "bool",
            },
	],
	"pcap-file-continuous": [
            {
		"name": "filename",
		"required": true,
		"type": "string",
            },
            {
		"name": "output-dir",
		"required": true,
		"type": "string",
            },
            {
		"name": "continuous",
		"required": true,
		"type": "bool",
		"value": true,
            },
            {
		"name": "tenant",
		"type": "number",
		"required": false,
            },
            {
		"name": "delete-when-done",
		"required": false,
		"type": "bool",
            },
	],
	"shutdown": [],
	"quit": [],
	"pcap-file-number": [],
	"pcap-file-list": [],
	"pcap-file-processed": [],
	"pcap-interrupt": [],
	"iface-list": [],
	"iface-stat": [
            {
		"name": "iface",
		"required": true,
		"type": "string",
            },
	],
	"conf-get": [
            {
		"name": "variable",
		"required": true,
		"type": "string",
            }
	],
	"unregister-tenant-handler": [
            {
		"name": "id",
		"type": "number",
		"required": true,
            },
            {
		"name": "htype",
		"required": true,
		"type": "string",
            },
            {
		"name": "hargs",
		"type": "number",
		"required": false,
            },
	],
	"register-tenant-handler": [
            {
		"name": "id",
		"type": "number",
		"required": true,
            },
            {
		"name": "htype",
		"required": true,
		"type": "string",
            },
            {
		"name": "hargs",
		"type": "number[]",
		"required": false,
            },
	],
	"unregister-tenant": [
            {
		"name": "id",
		"type": "number",
		"required": true,
            },
	],
	"register-tenant": [
            {
		"name": "id",
		"type": "number",
		"required": true,
            },
            {
		"name": "filename",
		"required": true,
		"type": "string",
            },
	],
	"reload-tenant": [
            {
		"name": "id",
		"type": "number",
		"required": true,
            },
            {
		"name": "filename",
		"required": false,
		"type": "string",
            },
	],
        "reload-tenants": [],
	"add-hostbit": [
            {
		"name": "ipaddress",
		"required": true,
		"type": "string",
            },
            {
		"name": "hostbit",
		"required": true,
		"type": "string",
            },
            {
		"name": "expire",
		"type": "number",
		"required": true,
            },
	],
	"remove-hostbit": [
            {
		"name": "ipaddress",
		"required": true,
		"type": "string",
            },
            {
		"name": "hostbit",
		"required": true,
		"type": "string",
            },
	],
	"list-hostbit": [
            {
		"name": "ipaddress",
		"required": true,
		"type": "string",
            },
	],
	"memcap-set": [
            {
		"name": "config",
		"required": true,
		"type": "string",
            },
            {
		"name": "memcap",
		"required": true,
		"type": "string",
            },
	],
	"memcap-show": [
            {
		"name": "config",
		"required": true,
		"type": "string",
            },
	],
	"dataset-add": [
            {
		"name": "setname",
		"required": true,
		"type": "string",
            },
            {
		"name": "settype",
		"required": true,
		"type": "string",
            },
            {
		"name": "datavalue",
		"required": true,
		"type": "string",
            },
	],
	"dataset-remove": [
            {
		"name": "setname",
		"required": true,
		"type": "string",
            },
            {
		"name": "settype",
		"required": true,
		"type": "string",
            },
            {
		"name": "datavalue",
		"required": true,
		"type": "string",
            },
	],
	"dataset-add-json": [
            {
		"name": "setname",
		"required": true,
		"type": "string",
            },
            {
		"name": "settype",
		"required": true,
		"type": "string",
            },
            {
		"name": "datavalue",
		"required": true,
		"type": "string",
            },
            {
		"name": "datajson",
		"required": true,
		"type": "string",
            },
	],
	"get-flow-stats-by-id": [
            {
		"name": "flow_id",
		"type": "number",
		"required": true,
            },
	],
	"dataset-clear": [
            {
		"name": "setname",
		"required": true,
		"type": "string",
            },
            {
		"name": "settype",
		"required": true,
		"type": "string",
            }
	],
	"dataset-lookup": [
            {
		"name": "setname",
		"required": true,
		"type": "string",
            },
            {
		"name": "settype",
		"required": true,
		"type": "string",
            },
            {
		"name": "datavalue",
		"required": true,
		"type": "string",
            },
	],
    });
    serde_json::from_value(defs)
}
