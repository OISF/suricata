/* Copyright (C) 2026 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

// Author: Giuseppe Longo <glongo@oisf.net>

use std::collections::HashMap;

use crate::imap::{
    imap::{extract_command_from_requests, ImapTransaction},
    parser::{EmailData, ImapMessageType},
};
use crate::jsonbuilder::{JsonBuilder, JsonError};

fn log_email_header_string(
    js: &mut JsonBuilder, headers: &HashMap<String, Vec<String>>, key: &str, json_name: &str,
) -> Result<(), JsonError> {
    if let Some(values) = headers.get(key) {
        if let Some(first) = values.first() {
            js.set_string(json_name, first)?;
        }
    }
    Ok(())
}

fn log_email_header_array(
    js: &mut JsonBuilder, headers: &HashMap<String, Vec<String>>, key: &str, json_name: &str,
) -> Result<(), JsonError> {
    if let Some(values) = headers.get(key) {
        let joined = values.join(", ");
        let parts: Vec<&str> = joined.split(',').map(|s| s.trim()).collect();
        js.open_array(json_name)?;
        for part in &parts {
            if !part.is_empty() {
                js.append_string(part)?;
            }
        }
        js.close()?;
    }
    Ok(())
}

fn log_imap(tx: &ImapTransaction, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.open_object("imap")?;
    let mut message_email: Option<&EmailData> = None;

    let command_bytes = extract_command_from_requests(&tx.requests);
    let command = String::from_utf8_lossy(&command_bytes).into_owned();

    if !tx.requests.is_empty() {
        js.open_array("requests")?;

        for req in &tx.requests {
            match &req.message {
                ImapMessageType::Command {
                    command: cmd,
                    arguments,
                } => {
                    let tag = req
                        .tag
                        .as_ref()
                        .map(|t| String::from_utf8_lossy(t))
                        .unwrap_or_default();
                    if arguments.is_empty() {
                        js.append_string(&format!("{} {}", tag, cmd))?;
                    } else {
                        let args: Vec<_> = arguments
                            .iter()
                            .map(|a| String::from_utf8_lossy(a))
                            .collect();
                        js.append_string(&format!("{} {} {}", tag, cmd, args.join(" ")))?;
                    }
                }
                _ => {
                    if !req.raw_line.is_empty() {
                        js.append_string(&String::from_utf8_lossy(&req.raw_line))?;
                    }
                }
            }
            if let ImapMessageType::LiteralData {
                email: Some(email_data),
                ..
            } = &req.message
            {
                message_email = Some(email_data);
            }
        }

        js.close()?;
    }

    if !tx.responses.is_empty() {
        js.open_array("responses")?;

        for response in &tx.responses {
            if !response.raw_line.is_empty() {
                js.append_string(&String::from_utf8_lossy(&response.raw_line))?;
            }
            if let ImapMessageType::Untagged {
                fetch_data: Some(fetch),
                ..
            } = &response.message
            {
                for part in &fetch.body_parts {
                    if let Some(email_data) = &part.email {
                        message_email = Some(email_data);
                        break;
                    }
                }
            }
        }
        js.close()?;
    }

    js.close()?;

    if let Some(email_data) = message_email {
        js.open_object("email")?;
        js.set_string("command", &command)?;
        log_email_header_string(js, &email_data.headers, "from", "from")?;
        log_email_header_array(js, &email_data.headers, "to", "to")?;
        log_email_header_array(js, &email_data.headers, "cc", "cc")?;
        log_email_header_string(js, &email_data.headers, "subject", "subject")?;
        log_email_header_string(js, &email_data.headers, "date", "date")?;
        log_email_header_string(js, &email_data.headers, "message_id", "message_id")?;
        log_email_header_string(js, &email_data.headers, "x_mailer", "x_mailer")?;
        log_email_header_array(js, &email_data.headers, "received", "received")?;
        //js.set_string_from_bytes("body", &email_data.email_body)?;
        js.close()?;
    }

    Ok(())
}

#[no_mangle]
pub unsafe extern "C" fn SCImapLoggerLog(
    tx: *mut std::os::raw::c_void, js: &mut JsonBuilder,
) -> bool {
    let tx = cast_pointer!(tx, ImapTransaction);
    log_imap(tx, js).is_ok()
}
