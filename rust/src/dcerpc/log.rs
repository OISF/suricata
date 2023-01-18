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
use crate::dcerpc::dcerpc_udp::*;
use crate::jsonbuilder::{JsonBuilder, JsonError};

fn log_dcerpc_header_tcp(
    jsb: &mut JsonBuilder, state: &DCERPCState, tx: &DCERPCTransaction,
) -> Result<(), JsonError> {
    if tx.req_done && !tx.req_lost {
        jsb.set_string("request", &dcerpc_type_string(tx.req_cmd))?;
        match tx.req_cmd {
            DCERPC_TYPE_REQUEST => {
                jsb.open_object("req")?;
                jsb.set_uint("opnum", tx.opnum as u64)?;
                jsb.set_uint("frag_cnt", tx.frag_cnt_ts as u64)?;
                jsb.set_uint("stub_data_size", tx.stub_data_buffer_ts.len() as u64)?;
                jsb.close()?;
            }
            DCERPC_TYPE_BIND => match &state.bind {
                Some(bind) => {
                    jsb.open_array("interfaces")?;
                    for uuid in &bind.uuid_list {
                        jsb.start_object()?;
                        let ifstr = Uuid::from_slice(uuid.uuid.as_slice());
                        let ifstr = ifstr.map(|uuid| uuid.to_hyphenated().to_string()).unwrap();
                        jsb.set_string("uuid", &ifstr)?;
                        let vstr = format!("{}.{}", uuid.version, uuid.versionminor);
                        jsb.set_string("version", &vstr)?;
                        jsb.set_uint("ack_result", uuid.result as u64)?;
                        jsb.close()?;
                    }
                    jsb.close()?;
                }
                None => {}
            },
            _ => {}
        }
    } else {
        jsb.set_string("request", "REQUEST_LOST")?;
    }

    if tx.resp_done && !tx.resp_lost {
        jsb.set_string("response", &dcerpc_type_string(tx.resp_cmd))?;
        #[allow(clippy::single_match)]
        match tx.resp_cmd {
            DCERPC_TYPE_RESPONSE => {
                jsb.open_object("res")?;
                jsb.set_uint("frag_cnt", tx.frag_cnt_tc as u64)?;
                jsb.set_uint("stub_data_size", tx.stub_data_buffer_tc.len() as u64)?;
                jsb.close()?;
            }
            _ => {} // replicating behavior from smb
        }
    } else {
        jsb.set_string("response", "UNREPLIED")?;
    }

    if let Some(ref hdr) = state.header {
        jsb.set_uint("call_id", tx.call_id as u64)?;
        let vstr = format!("{}.{}", hdr.rpc_vers, hdr.rpc_vers_minor);
        jsb.set_string("rpc_version", &vstr)?;
    }

    return Ok(());
}

fn log_dcerpc_header_udp(
    jsb: &mut JsonBuilder, _state: &DCERPCUDPState, tx: &DCERPCTransaction,
) -> Result<(), JsonError> {
    if tx.req_done && !tx.req_lost {
        jsb.set_string("request", &dcerpc_type_string(tx.req_cmd))?;
        #[allow(clippy::single_match)]
        match tx.req_cmd {
            DCERPC_TYPE_REQUEST => {
                jsb.open_object("req")?;
                jsb.set_uint("opnum", tx.opnum as u64)?;
                jsb.set_uint("frag_cnt", tx.frag_cnt_ts as u64)?;
                jsb.set_uint("stub_data_size", tx.stub_data_buffer_ts.len() as u64)?;
                jsb.close()?;
            }
            _ => {}
        }
    } else {
        jsb.set_string("request", "REQUEST_LOST")?;
    }

    if tx.resp_done && !tx.resp_lost {
        jsb.set_string("response", &dcerpc_type_string(tx.resp_cmd))?;
        #[allow(clippy::single_match)]
        match tx.resp_cmd {
            DCERPC_TYPE_RESPONSE => {
                jsb.open_object("res")?;
                jsb.set_uint("frag_cnt", tx.frag_cnt_tc as u64)?;
                jsb.set_uint("stub_data_size", tx.stub_data_buffer_tc.len() as u64)?;
                jsb.close()?;
            }
            _ => {} // replicating behavior from smb
        }
    } else {
        jsb.set_string("response", "UNREPLIED")?;
    }
    let activityuuid = Uuid::from_slice(tx.activityuuid.as_slice());
    let activityuuid = activityuuid.map(|uuid| uuid.to_hyphenated().to_string()).unwrap();
    jsb.set_string("activityuuid", &activityuuid)?;
    jsb.set_uint("seqnum", tx.seqnum as u64)?;
    jsb.set_string("rpc_version", "4.0")?;
    return Ok(());
}

#[no_mangle]
pub extern "C" fn rs_dcerpc_log_json_record_tcp(
    state: &DCERPCState, tx: &DCERPCTransaction, jsb: &mut JsonBuilder,
) -> bool {
    log_dcerpc_header_tcp(jsb, state, tx).is_ok()
}

#[no_mangle]
pub extern "C" fn rs_dcerpc_log_json_record_udp(
    state: &DCERPCUDPState, tx: &DCERPCTransaction, jsb: &mut JsonBuilder,
) -> bool {
    log_dcerpc_header_udp(jsb, state, tx).is_ok()
}
