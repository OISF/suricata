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

use crate::imap::{imap::ImapTransaction, parser::ImapMessageType};
use crate::jsonbuilder::{JsonBuilder, JsonError};

fn args_to_string(arguments: &[Vec<u8>]) -> String {
    arguments
        .iter()
        .map(|arg| String::from_utf8_lossy(arg))
        .collect::<Vec<_>>()
        .join(" ")
}

fn log_imap(tx: &ImapTransaction, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.open_object("imap")?;

    if !tx.requests.is_empty() {
        js.open_array("requests")?;

        for req in &tx.requests {
            js.start_object()?;

            let mut line = String::new();

            if let Some(tag) = &req.tag {
                line.push_str(&String::from_utf8_lossy(tag));
                line.push(' ');
            }
            match &req.message {
                ImapMessageType::Command { command, arguments } => {
                    line.push_str(&command.to_string());
                    if !arguments.is_empty() {
                        line.push(' ');
                        line.push_str(&args_to_string(arguments));
                    }
                    js.set_string("line", &line)?;
                }
                ImapMessageType::ContinuationData { data } => {
                    line.push_str(&String::from_utf8_lossy(data));
                    js.set_string("line", &line)?;
                }
                ImapMessageType::LiteralData { raw: _, email } => {
                    js.set_string("type", "literal_data")?;
                    if let Some(email_data) = email {
                        js.open_object("email")?;
                        js.open_object("headers")?;
                        for (name, value) in &email_data.headers {
                            js.set_string(name, value)?;
                        }
                        js.close()?;
                        js.set_string_from_bytes("body", &email_data.email_body)?;
                        js.close()?;
                    }
                }
                _ => {}
            }
            js.close()?;
        }

        js.close()?;
    }

    if !tx.responses.is_empty() {
        js.open_array("responses")?;

        for response in &tx.responses {
            js.start_object()?;

            let mut line = String::new();

            if let Some(tag) = &response.tag {
                line.push_str(&String::from_utf8_lossy(tag));
                line.push(' ');
            }

            match &response.message {
                ImapMessageType::Response { status, text } => {
                    line.push_str(&status.to_string());
                    if let Some(text) = text {
                        line.push(' ');
                        line.push_str(&String::from_utf8_lossy(text));
                    }
                    js.set_string("line", &line)?;
                }
                ImapMessageType::Untagged {
                    seq_number,
                    keyword,
                    data,
                    fetch_data,
                } => {
                    line.push_str("* ");
                    if let Some(seq) = seq_number {
                        line.push_str(&seq.to_string());
                        line.push(' ');
                    }
                    line.push_str(&String::from_utf8_lossy(keyword));
                    if let Some(data) = data {
                        line.push(' ');
                        line.push_str(&String::from_utf8_lossy(data));
                    }
                    js.set_string("line", &line)?;

                    if let Some(fetch) = fetch_data {
                        for part in &fetch.body_parts {
                            if let Some(email_data) = &part.email {
                                js.open_object("email")?;
                                js.open_object("headers")?;
                                for (name, value) in &email_data.headers {
                                    js.set_string(name, value)?;
                                }
                                js.close()?; // headers
                                js.set_string_from_bytes("body", &email_data.email_body)?;
                                js.close()?;
                                break; // Only log first email part for now
                            }
                        }
                    }
                }
                ImapMessageType::Continuation { text } => {
                    line.push_str("+ ");
                    if let Some(text) = text {
                        line.push_str(&String::from_utf8_lossy(text));
                    }
                    js.set_string("line", &line)?;
                }
                _ => {}
            }
            js.close()?;
        }
        js.close()?;
    }

    js.close()?;
    Ok(())
}

#[no_mangle]
pub unsafe extern "C" fn SCImapLoggerLog(
    tx: *mut std::os::raw::c_void, js: &mut JsonBuilder,
) -> bool {
    let tx = cast_pointer!(tx, ImapTransaction);
    log_imap(tx, js).is_ok()
}
