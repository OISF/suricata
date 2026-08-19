// SPDX-FileCopyrightText: Copyright 2023 Open Information Security Foundation
// SPDX-License-Identifier: MIT

use serde::Deserialize;
use serde::Serialize;
use serde_json::json;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("ioerror: `{0}`")]
    IoError(#[from] std::io::Error),
    #[error("serde error: `{0}`")]
    DeserializeError(#[from] serde_json::Error),
    #[error("connection closed")]
    Closed,
}

pub struct Client {
    filename: String,
    socket: UnixStream,

    // If set, the client will print to stdout the messages sent and
    // received. Primarily useful when running with the interactive
    // client in verbose mode.
    verbose: bool,
}

impl Client {
    pub fn connect<T: AsRef<str>>(filename: T, verbose: bool) -> Result<Self, ClientError> {
        let filename = filename.as_ref().to_string();
        let socket = UnixStream::connect(&filename)?;
        let mut client = Self {
            filename,
            socket,
            verbose,
        };
        client.handshake()?;
        Ok(client)
    }

    pub fn reconnect(&mut self) -> Result<(), ClientError> {
        if self.verbose {
            println!("Reconnecting to socket: {}", self.filename);
        }
        self.socket = UnixStream::connect(&self.filename)?;
        self.handshake()?;
        Ok(())
    }

    fn handshake(&mut self) -> Result<(), ClientError> {
        self.send(&json!({"version": "0.2"}))?;
        self.read().map(serde_json::from_value::<Response>)??;
        Ok(())
    }

    pub fn send<T>(&mut self, msg: &T) -> Result<(), std::io::Error>
    where
        T: ?Sized + Serialize,
    {
        let mut encoded = serde_json::to_string(&msg)?;
        if self.verbose {
            println!("SND: {}", &encoded);
        }
        encoded.push('\n');
        self.socket.write_all(encoded.as_bytes())?;
        Ok(())
    }

    /// Read a line of data from the client.
    ///
    /// An empty line means the server has disconnected.
    pub fn read_line(&self) -> Result<String, ClientError> {
        let mut reader = BufReader::new(&self.socket);
        let mut response = String::new();
        reader.read_line(&mut response)?;
        if self.verbose {
            println!("RCV: {}", response.trim_end());
        }
        Ok(response)
    }

    pub fn read(&self) -> Result<serde_json::Value, ClientError> {
        let line = self.read_line()?;
        if line.is_empty() {
            return Err(ClientError::Closed);
        }
        let decoded = serde_json::from_str(&line)?;
        Ok(decoded)
    }
}

#[derive(Debug, Deserialize)]
pub struct Response {
    #[serde(rename = "return")]
    pub status: String,
    #[serde(default)]
    pub message: serde_json::Value,
}
