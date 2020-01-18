/* Copyright (C) 2017 Open Information Security Foundation
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

use crate::json::*;
use crate::dcerpc::dcerpc::*;

fn log_dcerpc_header(state: &DCERPCUDPState) -> Json
{
    let js = Json::object();

    match state.dcerpcrequest {
        Some(ref req) => {
            match state.dcerpchdrudp {
                Some(ref hdr) => {
                    js.set_string("request", &dcerpc_type_string(hdr.pkt_type));
                    let reqd = Json::object();
                    js.set_integer("opnum", hdr.opnum as u64);
                    reqd.set_integer("frag_cnt", hdr.fragnum as u64);
                    reqd.set_integer("stub_data_size", req.stub_data_buffer_len as u64);
                    js.set("req", reqd);
                },
                None => {}
            }
        },
        None => {
            js.set_string("request", "REQUEST_LOST");
        }
    }

    match state.dcerpcresponse {
        Some(ref resp) => {
            match state.dcerpchdrudp {
                Some(ref hdr) => {
                    js.set_string("response", &dcerpc_type_string(hdr.pkt_type));
                    let respd = Json::object();
                    respd.set_integer("frag_cnt", hdr.fragnum as u64);
                    respd.set_integer("stub_data_size", resp.stub_data_buffer_len as u64);
                    js.set("res", respd);
                },
                None => {}
            }
        },
        None => {
            js.set_string("response", "UNREPLIED");
        }
    }

    // TODO add the same for TCP once done
    return js;
}

#[no_mangle]
pub extern "C" fn rs_dcerpc_log_json_request(state: &mut DCERPCUDPState) -> *mut JsonT
{
    let js = log_dcerpc_header(state);
    return js.unwrap();
}

#[no_mangle]
pub extern "C" fn rs_dcerpc_log_json_response(state: &mut DCERPCUDPState) -> *mut JsonT
{
    let js = log_dcerpc_header(state);
    return js.unwrap();
}

