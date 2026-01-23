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

const REDACTED: &[u8] = b"<redacted>";

fn log_request_line(
    request: &ImapMessage, suppress_continuation_data: bool,
) -> Option<Cow<'_, [u8]>> {
    if request.raw_line.is_empty() {
        return None;
    }

    let tag = request.tag.as_deref().unwrap_or_default();
    match &request.message {
        ImapMessageType::ContinuationData if suppress_continuation_data => None,
        ImapMessageType::Command {
            command: ImapCommand::Login,
            arguments,
            ..
        } if !arguments.is_empty() => {
            Some(Cow::Owned([tag, b" LOGIN ".as_slice(), REDACTED].concat()))
        }
        ImapMessageType::Command {
            command: ImapCommand::Authenticate,
            arguments,
            ..
        } if arguments.len() > 1 => Some(Cow::Owned(
            [
                tag,
                b" AUTHENTICATE ".as_slice(),
                arguments[0].as_slice(),
                b" ".as_slice(),
                REDACTED,
            ]
            .concat(),
        )),
        _ => Some(Cow::Borrowed(request.raw_line.as_slice())),
    }
}

fn log_imap(tx: &ImapTransaction, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.open_object("imap")?;

    if !tx.requests.is_empty() {
        js.open_array("requests")?;

        let suppress_continuation_data = matches!(
            tx.command,
            Some(ImapCommand::Authenticate | ImapCommand::Login)
        );
        for req in &tx.requests {
            if let Some(line) = log_request_line(req, suppress_continuation_data) {
                js.append_string_from_bytes(&line)?;
            }
        }

        js.close()?;
    }

    if !tx.response_lines.is_empty() {
        js.open_array("responses")?;

        for line in &tx.response_lines {
            js.append_string_from_bytes(line)?;
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
    // A transaction carrying only an event has no lines to log.
    if tx.requests.is_empty() && tx.response_lines.is_empty() {
        return false;
    }
    log_imap(tx, js).is_ok()
}
