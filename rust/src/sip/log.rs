/* Copyright (C) 2019-2022 Open Information Security Foundation
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

// written by Giuseppe Longo <giuseppe@glongo.it>

use crate::jsonbuilder::{JsonBuilder, JsonError};
use crate::sip::sip::SIPTransaction;

fn log(tx: &SIPTransaction, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.open_object("sip")?;

    if let Some(req) = &tx.request {
        js.set_string("method", &req.method)?
            .set_string("uri", &req.path)?
            .set_string("version", &req.version)?;
    }

    if let Some(req_line) = &tx.request_line {
        js.set_string("request_line", req_line)?;
    }

    if let Some(resp) = &tx.response {
        js.set_string("version", &resp.version)?
            .set_string("code", &resp.code)?
            .set_string("reason", &resp.reason)?;
    }

    if let Some(resp_line) = &tx.response_line {
        js.set_string("response_line", resp_line)?;
    }

    js.close()?;

    Ok(())
}

#[no_mangle]
pub extern "C" fn rs_sip_log_json(tx: &mut SIPTransaction, js: &mut JsonBuilder) -> bool {
    log(tx, js).is_ok()
}