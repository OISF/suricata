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

use crate::dcerpc::dcerpc::*;
use crate::json::*;

fn log_dcerpc_header(tx: &DCERPCTransaction) -> Json {
    let js = Json::object();

    if tx.req_done == true {
        js.set_string("request", &dcerpc_type_string(tx.req_cmd));
        let reqd = Json::object();
        js.set_integer("opnum", tx.opnum as u64);
        reqd.set_integer("frag_cnt", tx.frag_cnt_ts as u64);
        reqd.set_integer("stub_data_size", tx.stub_data_buffer_len_ts as u64);
        js.set("req", reqd);
    }

    if tx.resp_done == true {
        js.set_string("response", &dcerpc_type_string(tx.resp_cmd));
        let respd = Json::object();
        respd.set_integer("frag_cnt", tx.frag_cnt_tc as u64);
        respd.set_integer("stub_data_size", tx.stub_data_buffer_len_tc as u64);
        js.set("res", respd);
    }

    return js;
}

#[no_mangle]
pub extern "C" fn rs_dcerpc_log_json_record(tx: &mut DCERPCTransaction) -> *mut JsonT {
    let js = log_dcerpc_header(tx);
    return js.unwrap();
}
