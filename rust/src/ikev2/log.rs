/* Copyright (C) 2018-2020 Open Information Security Foundation
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

use crate::jsonbuilder::{JsonBuilder, JsonError};
use crate::ikev2::ikev2::{IKEV2State,IKEV2Transaction};

use crate::ikev2::ipsec_parser::IKEV2_FLAG_INITIATOR;

fn ikev2_log_response(state: &mut IKEV2State,
                      tx: &mut IKEV2Transaction,
                      jb: &mut JsonBuilder)
                      -> Result<(), JsonError>
{
    jb.set_uint("version_major", tx.hdr.maj_ver as u64)?;
    jb.set_uint("version_minor", tx.hdr.min_ver as u64)?;
    jb.set_uint("exchange_type", tx.hdr.exch_type.0 as u64)?;
    jb.set_uint("message_id", tx.hdr.msg_id as u64)?;
    jb.set_string("init_spi", &format!("{:016x}", tx.hdr.init_spi))?;
    jb.set_string("resp_spi", &format!("{:016x}", tx.hdr.resp_spi))?;
    if tx.hdr.flags & IKEV2_FLAG_INITIATOR != 0 {
        jb.set_string("role", &"initiator")?;
    } else {
        jb.set_string("role", &"responder")?;
        jb.set_string("alg_enc", &format!("{:?}", state.alg_enc))?;
        jb.set_string("alg_auth", &format!("{:?}", state.alg_auth))?;
        jb.set_string("alg_prf", &format!("{:?}", state.alg_prf))?;
        jb.set_string("alg_dh", &format!("{:?}", state.alg_dh))?;
        jb.set_string("alg_esn", &format!("{:?}", state.alg_esn))?;
    }
    jb.set_uint("errors", tx.errors as u64)?;
    jb.open_array("payload")?;
    for payload in tx.payload_types.iter() {
        jb.append_string(&format!("{:?}", payload))?;
    }
    jb.close()?;
    jb.open_array("notify")?;
    for notify in tx.notify_types.iter() {
        jb.append_string(&format!("{:?}", notify))?;
    }
    jb.close()?;
    Ok(())
}

#[no_mangle]
pub extern "C" fn rs_ikev2_log_json_response(state: &mut IKEV2State,
                                             tx: &mut IKEV2Transaction,
                                             jb: &mut JsonBuilder)
                                             -> bool
{
    ikev2_log_response(state, tx, jb).is_ok()
}
