// SPDX-FileCopyrightText: Copyright 2023 Open Information Security Foundation
// SPDX-License-Identifier: MIT

/// This example connects to the Suricata control socket and requests
/// the interface list.
use serde_json::json;
use suricata_client::unix::Client;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    let filename = if let Some(filename) = args.get(1) {
        filename
    } else {
        "/run/suricata/suricata-command.socket"
    };
    dbg!(filename);

    let mut client = Client::connect(filename, false)?;
    client.send(&json!({"command": "iface-list"}))?;
    let response = client.read()?;
    dbg!(response);
    Ok(())
}
