/* Copyright (C) 2018-2019 Open Information Security Foundation
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
use crate::snmp::snmp::SNMPTransaction;
use crate::snmp::snmp_parser::{NetworkAddress,PduType};
use std::borrow::Cow;

fn str_of_pdu_type(t:&PduType) -> Cow<'_, str> {
    match t {
        &PduType::GetRequest => Cow::Borrowed("get_request"),
        &PduType::GetNextRequest => Cow::Borrowed("get_next_request"),
        &PduType::Response => Cow::Borrowed("response"),
        &PduType::SetRequest => Cow::Borrowed("set_request"),
        &PduType::TrapV1 => Cow::Borrowed("trap_v1"),
        &PduType::GetBulkRequest => Cow::Borrowed("get_bulk_request"),
        &PduType::InformRequest => Cow::Borrowed("inform_request"),
        &PduType::TrapV2 => Cow::Borrowed("trap_v2"),
        &PduType::Report => Cow::Borrowed("report"),
        x => Cow::Owned(format!("Unknown(0x{:x})", x.0)),
    }
}

fn snmp_log_response(jsb: &mut JsonBuilder, tx: &mut SNMPTransaction) -> Result<(), JsonError>
{
    jsb.set_uint("version", tx.version as u64)?;
    if tx.encrypted {
        jsb.set_string("pdu_type", "encrypted")?;
    } else {
        if let Some(ref info) = tx.info {
            jsb.set_string("pdu_type", &str_of_pdu_type(&info.pdu_type))?;
            if info.err.0 != 0 {
                jsb.set_string("error", &format!("{:?}", info.err))?;
            }
            if let Some((trap_type, ref oid, address)) = info.trap_type {
                jsb.set_string("trap_type", &format!("{:?}", trap_type))?;
                jsb.set_string("trap_oid", &oid.to_string())?;
                match address {
                    NetworkAddress::IPv4(ip) => {jsb.set_string("trap_address", &ip.to_string())?;},
                }
            }
            if !info.vars.is_empty() {
                jsb.open_array("vars")?;
                for var in info.vars.iter() {
                    jsb.append_string(&var.to_string())?;
                }
                jsb.close()?;
            }
        }
        if let Some(community) = &tx.community {
            jsb.set_string("community", community)?;
        }
        if let Some(usm) = &tx.usm {
            jsb.set_string("usm", usm)?;
        }
    }

    return Ok(());
}

#[no_mangle]
pub extern "C" fn rs_snmp_log_json_response(jsb: &mut JsonBuilder, tx: &mut SNMPTransaction) -> bool
{
    snmp_log_response(jsb, tx).is_ok()
}
