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

// written by Clément Galland <clement.galland@epita.fr>

extern crate libc;
extern crate nom;

use std::str;
use std;
use std::mem::transmute;

use applayer::LoggerFlags;

#[derive(Debug)]
pub struct TFTPTransaction {
    pub opcode : u8,
    pub filename : String,
    pub mode : String,
    pub logged : LoggerFlags
}

pub struct TFTPState {
    pub transactions : Vec<TFTPTransaction>
}

impl TFTPTransaction {
    pub fn new(opcode : u8, filename : String, mode : String) -> TFTPTransaction {
        TFTPTransaction {
            opcode : opcode,
            filename : filename,
            mode : mode.to_lowercase(),
            logged : LoggerFlags::new(),
        }
    }
    pub fn is_mode_ok(&self) -> bool {
        match self.mode.as_str() {
            "netascii" | "mail" | "octet" => true,
            _ => false
        }
    }
}

#[no_mangle]
pub extern "C" fn rs_tftp_state_alloc() -> *mut libc::c_void {
    let state = TFTPState { transactions : Vec::new() };
    let boxed = Box::new(state);
    return unsafe{transmute(boxed)};
}

#[no_mangle]
pub extern "C" fn rs_tftp_state_free(state: *mut libc::c_void) {
    let _state : Box<TFTPState> = unsafe{transmute(state)};
}

#[no_mangle]
pub extern "C" fn rs_tftp_state_tx_free(state: &mut TFTPState,
                                        tx_id: libc::uint32_t) {
    state.transactions.remove(tx_id as usize);
}

#[no_mangle]
pub extern "C" fn rs_tftp_get_tx(state: &mut TFTPState,
                                    tx_id: libc::uint64_t) -> *mut libc::c_void {
    if state.transactions.len() <= tx_id as usize {
        return std::ptr::null_mut();
    }
    return unsafe{transmute(&state.transactions[tx_id as usize])};
}

#[no_mangle]
pub extern "C" fn rs_tftp_get_tx_logged(_state: &mut TFTPState,
                                        tx: &mut TFTPTransaction)
                                        -> u32 {
    return tx.logged.get();
}

#[no_mangle]
pub extern "C" fn rs_tftp_set_tx_logged(_state: &mut TFTPState,
                                        tx: &mut TFTPTransaction,
                                        logged: libc::uint32_t) {
    tx.logged.set(logged);
}

#[no_mangle]
pub extern "C" fn rs_tftp_has_event(state: &mut TFTPState) -> i64 {
    return state.transactions.len() as i64;
}

#[no_mangle]
pub extern "C" fn rs_tftp_get_tx_cnt(state: &mut TFTPState) -> u64 {
    return state.transactions.len() as u64;
}

named!(getstr<&str>, map_res!(
        take_while!(call!(|c| c != 0)),
        str::from_utf8
    )
);

named!(pub tftp_request<TFTPTransaction>,
       do_parse!(
           tag!([0]) >>
           opcode: take!(1) >>
           filename: getstr >>
           tag!([0]) >>
           mode : getstr >>
           (
               TFTPTransaction::new(opcode[0], String::from(filename), String::from(mode))
           )
    )
);


#[no_mangle]
pub extern "C" fn rs_tftp_request(state: &mut TFTPState,
                                  input: *const libc::uint8_t,
                                  len: libc::uint32_t) -> i64 {
    let buf = unsafe{std::slice::from_raw_parts(input, len as usize)};
    return match tftp_request(buf) {
        Ok((_, rqst)) => {
            state.transactions.push(rqst);
            1
        },
        _ => 0
    }
}
