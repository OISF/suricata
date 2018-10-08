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

use json::*;
use snmp::snmp::{SNMPState,SNMPTransaction};
use snmp::snmp_parser::NetworkAddress;

#[no_mangle]
pub extern "C" fn rs_snmp_log_json_response(state: &mut SNMPState, tx: &mut SNMPTransaction) -> *mut JsonT
{
    let js = Json::object();
    js.set_integer("version", state.version as u64);
    if tx.encrypted {
        js.set_string("pdu_type", "encrypted");
    } else {
        match tx.info {
            Some(ref info) => {
                js.set_string("pdu_type", &format!("{:?}", info.pdu_type));
                if info.err.0 != 0 {
                    js.set_string("error", &format!("{:?}", info.err));
                }
                match &info.trap_type {
                    Some((trap_type, oid, address)) => {
                        js.set_string("trap_type", &format!("{:?}", trap_type));
                        js.set_string("trap_oid", &oid.to_string());
                        match address {
                            NetworkAddress::IPv4(ip) => js.set_string("trap_address", &ip.to_string())
                        }
                    },
                    _ => ()
                }
                if info.vars.len() > 0 {
                    let jsa = Json::array();
                    for var in info.vars.iter() {
                        jsa.array_append_string(&var.to_string());
                    }
                    js.set("vars", jsa);
                }
            },
            _ => ()
        }
        match tx.community {
            Some(ref c) => js.set_string("community", c),
            _           => ()
        }
        match tx.usm {
            Some(ref s) => js.set_string("usm", s),
            _           => ()
        }
    }
    js.unwrap()
}
