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

use crate::imap::imap::ImapTransaction;
use crate::imap::parser::{ImapCommand, ImapMessageType};
use crate::jsonbuilder::{JsonBuilder, JsonError};

fn log_imap(tx: &ImapTransaction, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.open_object("imap")?;

    if !tx.requests.is_empty() {
        js.open_array("requests")?;

        let mut has_auth = false;
        for req in &tx.requests {
            if matches!(
                &req.message,
                ImapMessageType::Command {
                    command: ImapCommand::Authenticate,
                    ..
                }
            ) {
                has_auth = true;
            }
            // do not log credentials sent in response to an AUTHENTICATE continuation
            if has_auth && matches!(&req.message, ImapMessageType::ContinuationData { .. }) {
                continue;
            }
            if !req.raw_line.is_empty() {
                js.append_string(&String::from_utf8_lossy(&req.raw_line))?;
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
