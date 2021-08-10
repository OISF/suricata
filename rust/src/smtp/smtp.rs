/* Copyright (C) 2021 Open Information Security Foundation
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
use crate::core::*;
use std;


#[no_mangle]
pub extern "C" fn set_min_inspect_depth(flow: *const std::os::raw::c_void, ctnt_min_size: u32,
    ts_data_cnt: u64, ts_last_ds: u64, dir: u16, trigger_reassembly: bool)
{
    let flow = cast_pointer!(flow, Flow);

    let depth: u64 = ctnt_min_size as u64 + ts_data_cnt - ts_last_ds;
    if trigger_reassembly == true {
        sc_app_layer_parser_trigger_raw_stream_reassembly(flow, dir as i32);
    }
    SCLogDebug!("StreamTcpReassemblySetMinInspectDepth STREAM_TOSERVER: {}", depth);
    let protoctx = flow.get_protoctx();
    unsafe { StreamTcpReassemblySetMinInspectDepth(protoctx, dir, depth as u32) };
}
