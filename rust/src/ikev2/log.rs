/* Copyright (C) 2018 Open Information Security Foundation
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

// written by Pierre Chifflier  <chifflier@wzdftpd.net>

use ikev2::ikev2::{IKEV2State, IKEV2Transaction};
use json::*;

use ikev2::ipsec_parser::IKEV2_FLAG_INITIATOR;

#[no_mangle]
pub extern "C" fn rs_ikev2_log_json_response(
    state: &mut IKEV2State,
    tx: &mut IKEV2Transaction,
) -> *mut JsonT {
    let js = Json::object();
    js.set_integer("version_major", tx.hdr.maj_ver as u64);
    js.set_integer("version_minor", tx.hdr.min_ver as u64);
    js.set_integer("exchange_type", tx.hdr.exch_type.0 as u64);
    js.set_integer("message_id", tx.hdr.msg_id as u64);
    js.set_string("init_spi", &format!("{:016x}", tx.hdr.init_spi));
    js.set_string("resp_spi", &format!("{:016x}", tx.hdr.resp_spi));
    if tx.hdr.flags & IKEV2_FLAG_INITIATOR != 0 {
        js.set_string("role", &"initiator");
    } else {
        js.set_string("role", &"responder");
        js.set_string("alg_enc", &format!("{:?}", state.alg_enc));
        js.set_string("alg_auth", &format!("{:?}", state.alg_auth));
        js.set_string("alg_prf", &format!("{:?}", state.alg_prf));
        js.set_string("alg_dh", &format!("{:?}", state.alg_dh));
        js.set_string("alg_esn", &format!("{:?}", state.alg_esn));
    }
    js.set_integer("errors", tx.errors as u64);
    let jsa = Json::array();
    for payload in tx.payload_types.iter() {
        jsa.array_append_string(&format!("{:?}", payload));
    }
    js.set("payload", jsa);
    let jsa = Json::array();
    for notify in tx.notify_types.iter() {
        jsa.array_append_string(&format!("{:?}", notify));
    }
    js.set("notify", jsa);
    return js.unwrap();
}
