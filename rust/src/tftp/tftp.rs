/* Copyright (C) 2017-2019 Open Information Security Foundation
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
    pub logged : LoggerFlags,
    id: u64,
}

pub struct TFTPState {
    pub transactions : Vec<TFTPTransaction>,
    /// tx counter for assigning incrementing id's to tx's
    tx_id: u64,
}

impl TFTPState {
    fn get_tx_by_id(&mut self, tx_id: u64) -> Option<&TFTPTransaction> {
        self.transactions.iter().find(|&tx| tx.id == tx_id + 1)
    }

    fn free_tx(&mut self, tx_id: u64) {
        let tx = self.transactions.iter().position(|ref tx| tx.id == tx_id + 1);
        debug_assert!(tx != None);
        if let Some(idx) = tx {
            let _ = self.transactions.remove(idx);
        }
    }
}

impl TFTPTransaction {
    pub fn new(opcode : u8, filename : String, mode : String) -> TFTPTransaction {
        TFTPTransaction {
            opcode : opcode,
            filename : filename,
            mode : mode.to_lowercase(),
            logged : LoggerFlags::new(),
            id : 0,
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
pub extern "C" fn rs_tftp_state_alloc() -> *mut std::os::raw::c_void {
    let state = TFTPState { transactions : Vec::new(), tx_id: 0, };
    let boxed = Box::new(state);
    return unsafe{transmute(boxed)};
}

#[no_mangle]
pub extern "C" fn rs_tftp_state_free(state: *mut std::os::raw::c_void) {
    let _state : Box<TFTPState> = unsafe{transmute(state)};
}

#[no_mangle]
pub extern "C" fn rs_tftp_state_tx_free(state: &mut TFTPState,
                                        tx_id: u64) {
    state.free_tx(tx_id);
}

#[no_mangle]
pub extern "C" fn rs_tftp_get_tx(state: &mut TFTPState,
                                    tx_id: u64) -> *mut std::os::raw::c_void {
    match state.get_tx_by_id(tx_id) {
        Some(tx) => unsafe{std::mem::transmute(tx)},
        None     => std::ptr::null_mut(),
    }
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
                                        logged: u32) {
    tx.logged.set(logged);
}

#[no_mangle]
pub extern "C" fn rs_tftp_get_tx_cnt(state: &mut TFTPState) -> u64 {
    return state.tx_id as u64;
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
                                  input: *const u8,
                                  len: u32) -> i64 {
    let buf = unsafe{std::slice::from_raw_parts(input, len as usize)};
    return match tftp_request(buf) {
        Ok((_, mut rqst)) => {
            state.tx_id += 1;
            rqst.id = state.tx_id;
            state.transactions.push(rqst);
            1
        },
        _ => 0
    }
}
