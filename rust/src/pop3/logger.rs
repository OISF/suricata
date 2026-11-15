/* Copyright (C) 2025 Open Information Security Foundation
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

// Author: Alex Savage <exlavasage@gmail.com>

//! POP3 parser json logger

use super::pop3::POP3Transaction;
use crate::jsonbuilder::{JsonBuilder, JsonError};
use std;

const POP3_LOG_MAX_STRING: usize = 8 * 1024;
const POP3_LOG_MAX_ARRAY: usize = 64;
const POP3_LOG_MAX_BYTES: usize = 128 * 1024;

struct Pop3LogBudget {
    remaining: usize,
    truncated: bool,
}

impl Pop3LogBudget {
    fn new() -> Self {
        Self {
            remaining: POP3_LOG_MAX_BYTES,
            truncated: false,
        }
    }

    fn append(&mut self, js: &mut JsonBuilder, data: &[u8]) -> Result<(), JsonError> {
        let len = data.len().min(POP3_LOG_MAX_STRING);
        let cost = len + 8;
        if cost > self.remaining {
            self.truncated = true;
            return Ok(());
        }
        self.remaining -= cost;
        if len < data.len() {
            self.truncated = true;
        }
        js.append_string_from_bytes_limited(data, POP3_LOG_MAX_STRING)?;
        Ok(())
    }

    fn set(&mut self, js: &mut JsonBuilder, key: &str, data: &[u8]) -> Result<(), JsonError> {
        let len = data.len().min(POP3_LOG_MAX_STRING);
        let cost = len + 24;
        if cost > self.remaining {
            self.truncated = true;
            return Ok(());
        }
        self.remaining -= cost;
        if len < data.len() {
            self.truncated = true;
        }
        js.set_string_from_bytes_limited(key, data, POP3_LOG_MAX_STRING)?;
        Ok(())
    }
}

fn log_pop3(tx: &POP3Transaction, js: &mut JsonBuilder) -> Result<(), JsonError> {
    let mut budget = Pop3LogBudget::new();
    js.open_object("pop3")?;
    if let Some(ref request) = tx.request {
        let js_request = js.open_object("request")?;
        let command = request.keyword.to_string();
        js_request.set_string("command", &command)?;
        // USER/PASS carry the password, AUTH PLAIN/XOAUTH2 and APOP carry a
        // credential in the arguments; keep only the mechanism or user name.
        let keep_args =
            if command.eq_ignore_ascii_case("USER") || command.eq_ignore_ascii_case("PASS") {
                Some(0)
            } else if command.eq_ignore_ascii_case("AUTH") || command.eq_ignore_ascii_case("APOP") {
                Some(1)
            } else {
                None
            };
        if let Some(keep) = keep_args {
            if request.args.len() > keep {
                js_request.set_bool("credentials_redacted", true)?;
            }
            if keep > 0 && !request.args.is_empty() {
                let js_args = js_request.open_array("args")?;
                budget.append(js_args, &request.args[0])?;
                js_args.close()?;
            }
        } else {
            let args_truncated = request.args.len() > POP3_LOG_MAX_ARRAY;
            let js_args = js_request.open_array("args")?;
            for arg in request.args.iter().take(POP3_LOG_MAX_ARRAY) {
                budget.append(js_args, arg)?;
            }
            js_args.close()?;
            if args_truncated {
                js_request.set_bool("args_truncated", true)?;
                budget.truncated = true;
            }
        }
        js_request.close()?;
    }
    if let Some(ref response) = tx.response {
        let js_response = js.open_object("response")?;
        js_response.set_bool("success", response.status == sawp_pop3::Status::OK)?;
        js_response.set_string("status", response.status.to_str())?;
        budget.set(js_response, "header", &response.header)?;
        let data_truncated = response.data.len() > POP3_LOG_MAX_ARRAY;
        let js_data = js_response.open_array("data")?;
        for data in response.data.iter().take(POP3_LOG_MAX_ARRAY) {
            budget.append(js_data, data)?;
        }
        js_data.close()?;
        if data_truncated {
            js_response.set_bool("data_truncated", true)?;
            budget.truncated = true;
        }
        js_response.close()?;
    }
    if budget.truncated {
        js.set_bool("truncated", true)?;
    }
    js.close()?;
    Ok(())
}

#[no_mangle]
pub unsafe extern "C" fn SCPop3LoggerLog(
    tx: *mut std::os::raw::c_void, js: &mut JsonBuilder,
) -> bool {
    let tx = cast_pointer!(tx, POP3Transaction);
    log_pop3(tx, js).is_ok()
}
