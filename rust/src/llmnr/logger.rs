/* Copyright (C) 2024 Open Information Security Foundation
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
use crate::llmnr::llmnr::LLMNRTransaction;

fn log_json(tx: &LLMNRTransaction, flags: u64, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.open_object("dns")?;

    let message = if let Some(request) = &tx.request {
        js.set_string("type", "request")?;
        request
    } else if let Some(response) = &tx.response {
        js.set_string("type", "response")?;
        response
    } else {
        debug_validate_fail!("unreachable");
        return Ok(());
    };

    // The internal Suricata transaction ID.
    js.set_uint("tx_id", tx.id - 1)?;

    // The on the wire LOGGER transaction ID.
    js.set_uint("id", tx.tx_id() as u64)?;

    let header = &message.header;
    js.set_string("flags", format!("{:x}", header.flags).as_str())?;
    if header.flags & 0x0400 != 0 {
        js.set_bool("c", true)?;
    }
    if header.flags & 0x0200 != 0 {
        js.set_bool("tc", true)?;
    }
    if header.flags & 0x0100 != 0 {
        js.set_bool("t", true)?;
    }
    let opcode = ((header.flags >> 11) & 0xf) as u8;
    js.set_uint("opcode", opcode as u64)?;

    if !message.queries.is_empty() {
        js.open_array("queries")?;
        for query in &message.queries {
            if crate::dns::log::dns_log_rrtype_enabled(query.rrtype, flags) {
                js.start_object()?
                    .set_string_from_bytes("rrname", &query.name)?
                    .set_string("rrtype", &crate::dns::log::dns_rrtype_string(query.rrtype))?
                    .close()?;
            }
        }
        js.close()?;
    }

    if !message.answers.is_empty() {
        crate::dns::log::dns_log_json_answers(js, message, flags)?;
    }

    if !message.authorities.is_empty() {
        js.open_array("authorities")?;
        for auth in &message.authorities {
            let auth_detail = crate::dns::log::dns_log_json_answer_detail(auth)?;
            js.append_object(&auth_detail)?;
        }
        js.close()?;
    }

    if !message.additionals.is_empty() {
        let mut is_js_open = false;
        for add in &message.additionals {
            if let crate::dns::dns::DNSRData::OPT(rdata) = &add.data {
                if rdata.is_empty() {
                    continue;
                }
            }
            if !is_js_open {
                js.open_array("additionals")?;
                is_js_open = true;
            }
            let add_detail = crate::dns::log::dns_log_json_answer_detail(add)?;
            js.append_object(&add_detail)?;
        }
        if is_js_open {
            js.close()?;
        }
    }

    js.close()?;
    Ok(())
}

#[no_mangle]
pub extern "C" fn SCLLMNRLogEnabled(tx: &LLMNRTransaction, flags: u64) -> bool {
    let message = if let Some(request) = &tx.request {
        request
    } else if let Some(response) = &tx.response {
        response
    } else {
        return false;
    };

    for query in &message.queries {
        if crate::dns::log::dns_log_rrtype_enabled(query.rrtype, flags) {
            return true;
        }
    }
    return false;
}

#[no_mangle]
pub extern "C" fn SCLLMNRLogJson(
    tx: &mut LLMNRTransaction, flags: u64, jb: &mut JsonBuilder,
) -> bool {
    log_json(tx, flags, jb).is_ok()
}
