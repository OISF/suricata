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

use std::borrow::Cow;

use crate::imap::imap::ImapTransaction;
use crate::imap::parser::{ImapCommand, ImapMessage, ImapMessageType};
use crate::jsonbuilder::{JsonBuilder, JsonError};

const REDACTED: &str = "<redacted>";

fn log_request_line(
    request: &ImapMessage, suppress_continuation_data: bool,
) -> Option<Cow<'_, str>> {
    if request.raw_line.is_empty() {
        return None;
    }

    match &request.message {
        ImapMessageType::ContinuationData { .. } if suppress_continuation_data => None,
        ImapMessageType::Command {
            command: ImapCommand::Login,
            arguments,
        } if !arguments.is_empty() => {
            let tag = request
                .tag
                .as_deref()
                .map(String::from_utf8_lossy)
                .unwrap_or_default();
            Some(Cow::Owned(format!("{tag} LOGIN {REDACTED}")))
        }
        ImapMessageType::Command {
            command: ImapCommand::Authenticate,
            arguments,
        } if arguments.len() > 1 => {
            let tag = request
                .tag
                .as_deref()
                .map(String::from_utf8_lossy)
                .unwrap_or_default();
            let mechanism = String::from_utf8_lossy(&arguments[0]);
            Some(Cow::Owned(format!(
                "{tag} AUTHENTICATE {mechanism} {REDACTED}"
            )))
        }
        _ => Some(String::from_utf8_lossy(&request.raw_line)),
    }
}

fn log_imap(tx: &ImapTransaction, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.open_object("imap")?;

    if !tx.requests.is_empty() {
        js.open_array("requests")?;

        let suppress_continuation_data = tx.command.eq_ignore_ascii_case(b"AUTHENTICATE")
            || tx.command.eq_ignore_ascii_case(b"LOGIN");
        for req in &tx.requests {
            if let Some(line) = log_request_line(req, suppress_continuation_data) {
                js.append_string(&line)?;
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
