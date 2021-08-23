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

#[no_mangle]
pub extern "C" fn handle_fragmented_lines(input: *mut *const u8,
    input_len: *mut i32, ts_db: *mut *const u8,
    ts_cur_line_db: u8, ts_db_len: *mut i32) -> i32
{
    let buf_len = input_len as usize;
    let buf = build_slice!(input, buf_len);
    let mut its_db;
    let lf_idx = buf.to_vec().iter().position(|c| *c == &0x0a);
    match lf_idx {
        Some(_idx) => {
            if ts_cur_line_db == 0 {
                its_db = Vec::with_capacity(buf_len);
                its_db.extend_from_slice(buf);
                unsafe {
                    *ts_db_len = buf_len as i32;
                }
            } else {
                its_db = build_slice!(ts_db, ts_db_len as usize).to_vec();
                its_db.extend_from_slice(&buf);
                unsafe {
                    *ts_db = *its_db.as_ptr();
                    let slice = &buf[buf_len..];
                    *input = *slice.as_ptr();
                    *input_len = 0 as i32;
                }
            }
        }
        None => { return -1; }
    }
    lf_idx.unwrap() as i32
}
