/* Copyright (C) 2020 Open Information Security Foundation
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
use uuid::Uuid;

use crate::dcerpc::dcerpc::*;
use crate::jsonbuilder::{JsonBuilder, JsonError};

fn log_dcerpc_header(
    js: &mut JsonBuilder, state: &DCERPCState, tx: &DCERPCTransaction,
) -> Result<(), JsonError> {
    if tx.req_done == true {
        js.set_string("request", &dcerpc_type_string(tx.req_cmd))?;
        match tx.req_cmd {
            DCERPC_TYPE_REQUEST => {
                js.open_object("req")?;
                js.set_uint("opnum", tx.opnum as u64)?;
                js.set_uint("frag_cnt", tx.frag_cnt_ts as u64)?;
                js.set_uint("stub_data_size", tx.stub_data_buffer_len_ts as u64)?;
                js.close()?;
            }
            DCERPC_TYPE_BIND => match &state.bind {
                Some(bind) => {
                    let mut jsd = JsonBuilder::new_array();
                    for uuid in &bind.uuid_list {
                        let mut jso = JsonBuilder::new_object();
                        let ifstr = Uuid::from_slice(uuid.uuid.as_slice());
                        let ifstr = ifstr.map(|uuid| uuid.to_hyphenated().to_string()).unwrap();
                        jso.set_string("uuid", &ifstr)?;
                        let vstr = format!("{}.{}", uuid.version, uuid.versionminor);
                        jso.set_string("version", &vstr)?;
                        jso.set_uint("ack_result", uuid.result as u64)?;
                        jso.close()?;
                        jsd.append_object(&jso)?;
                    }
                    jsd.close()?;
                    js.set_object("interfaces", &jsd)?;
                }
                None => {}
            },
            _ => {}
        }
    } else {
        js.set_string("request", "REQUEST_LOST")?;
    }

    if tx.resp_done == true {
        js.set_string("response", &dcerpc_type_string(tx.resp_cmd))?;
        match tx.resp_cmd {
            DCERPC_TYPE_RESPONSE => {
                js.open_object("res")?;
                js.set_uint("frag_cnt", tx.frag_cnt_tc as u64)?;
                js.set_uint("stub_data_size", tx.stub_data_buffer_len_tc as u64)?;
                js.close()?;
            }
            _ => {} // replicating behavior from smb
        }
    } else {
        js.set_string("response", "UNREPLIED")?;
    }

    js.set_uint("call_id", tx.call_id as u64)?;
    if let Some(ref hdr) = state.header {
        let vstr = format!("{}.{}", hdr.rpc_vers, hdr.rpc_vers_minor);
        js.set_string("rpc_version", &vstr)?;
    }
    js.close()?;

    return Ok(());
}

#[no_mangle]
pub extern "C" fn rs_dcerpc_log_json_record(
    state: &DCERPCState, tx: &DCERPCTransaction, mut jsb: &mut JsonBuilder,
) -> bool {
    log_dcerpc_header(&mut jsb, state, tx).is_ok()
}
