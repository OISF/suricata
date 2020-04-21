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
use crate::jsonbuilder::{JsonBuilder, JsonError};

fn log_dcerpc_header(js: &mut JsonBuilder, tx: &DCERPCTransaction) -> Result<(), JsonError> {
    if tx.req_done == true {
        js.set_string("request", &dcerpc_type_string(tx.req_cmd))?;
        js.open_object("req")?;
        js.set_uint("opnum", tx.opnum as u64)?;
        js.set_uint("frag_cnt", tx.frag_cnt_ts as u64)?;
        js.set_uint("stub_data_size", tx.stub_data_buffer_len_ts as u64)?;
        js.close()?;
    }

    if tx.resp_done == true {
        js.set_string("response", &dcerpc_type_string(tx.resp_cmd))?;
        js.open_object("res")?;
        js.set_uint("frag_cnt", tx.frag_cnt_tc as u64)?;
        js.set_uint("stub_data_size", tx.stub_data_buffer_len_tc as u64)?;
        js.close()?;
    }

    return Ok(());
}

#[no_mangle]
pub extern "C" fn rs_dcerpc_log_json_record(tx: &mut DCERPCTransaction, mut jsb: &mut JsonBuilder) -> bool {
    log_dcerpc_header(&mut jsb, tx).is_ok()
}
