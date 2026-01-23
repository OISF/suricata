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

fn log_imap(tx: &ImapTransaction, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.open_object("imap")?;
    let mut message_email: Option<(&crate::imap::parser::EmailData, &str)> = None;

    if !tx.requests.is_empty() {
        js.open_array("requests")?;

        for req in &tx.requests {
            match &req.message {
                ImapMessageType::Command { command, arguments } => {
                    let tag = req
                        .tag
                        .as_ref()
                        .map(|t| String::from_utf8_lossy(t))
                        .unwrap_or_default();
                    if arguments.is_empty() {
                        js.append_string(&format!("{} {}", tag, command))?;
                    } else {
                        let args: Vec<_> =
                            arguments.iter().map(|a| String::from_utf8_lossy(a)).collect();
                        js.append_string(&format!("{} {} {}", tag, command, args.join(" ")))?;
                    }
                }
                _ => {
                    if !req.raw_line.is_empty() {
                        js.append_string(&String::from_utf8_lossy(&req.raw_line))?;
                    }
                }
            }
            if let ImapMessageType::LiteralData { email: Some(email_data), .. } = &req.message {
                message_email = Some((email_data, "to_server"));
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
            if let ImapMessageType::Untagged { fetch_data: Some(fetch), .. } = &response.message {
                for part in &fetch.body_parts {
                    if let Some(email_data) = &part.email {
                        message_email = Some((email_data, "to_client"));
                        break;
                    }
                }
            }
        }
        js.close()?;
    }

    if let Some((email_data, direction)) = message_email {
        js.open_object("email")?;
        js.set_string("direction", direction)?;
        js.open_object("headers")?;
        for (name, values) in &email_data.headers {
            js.set_string(name, &values.join(", "))?;
        }
        js.close()?;
        js.set_string_from_bytes("body", &email_data.email_body)?;
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
