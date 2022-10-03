/* Copyright (C) 2017-2021 Open Information Security Foundation
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

use std::str;
use std;
use nom7::IResult;
use nom7::combinator::map_res;
use nom7::bytes::streaming::{tag, take_while};
use nom7::number::streaming::be_u8;

use crate::applayer::{AppLayerTxData,AppLayerStateData};

const READREQUEST:  u8 = 1;
const WRITEREQUEST: u8 = 2;
const DATA:         u8 = 3;
const ACK:          u8 = 4;
const ERROR:        u8 = 5;

#[derive(Debug, PartialEq)]
pub struct TFTPTransaction {
    pub opcode : u8,
    pub filename : String,
    pub mode : String,
    id: u64,
    tx_data: AppLayerTxData,
}

pub struct TFTPState {
    state_data: AppLayerStateData,
    pub transactions : Vec<TFTPTransaction>,
    /// tx counter for assigning incrementing id's to tx's
    tx_id: u64,
}

impl TFTPState {
    fn get_tx_by_id(&mut self, tx_id: u64) -> Option<&TFTPTransaction> {
        self.transactions.iter().find(|&tx| tx.id == tx_id + 1)
    }

    fn free_tx(&mut self, tx_id: u64) {
        let tx = self.transactions.iter().position(|tx| tx.id == tx_id + 1);
        debug_assert!(tx.is_some());
        if let Some(idx) = tx {
            let _ = self.transactions.remove(idx);
        }
    }
}

impl TFTPTransaction {
    pub fn new(opcode : u8, filename : String, mode : String) -> TFTPTransaction {
        TFTPTransaction {
            opcode,
            filename,
            mode : mode.to_lowercase(),
            id : 0,
            tx_data: AppLayerTxData::new(),
        }
    }
    pub fn is_mode_ok(&self) -> bool {
        match self.mode.as_str() {
            "netascii" | "mail" | "octet" => true,
            _ => false
        }
    }
    pub fn is_opcode_ok(&self) -> bool {
        match self.opcode {
            READREQUEST | WRITEREQUEST | ACK | DATA | ERROR => true,
            _ => false
        }
    }
}

#[no_mangle]
pub extern "C" fn rs_tftp_state_alloc() -> *mut std::os::raw::c_void {
    let state = TFTPState { state_data: AppLayerStateData::new(), transactions : Vec::new(), tx_id: 0, };
    let boxed = Box::new(state);
    return Box::into_raw(boxed) as *mut _;
}

#[no_mangle]
pub extern "C" fn rs_tftp_state_free(state: *mut std::os::raw::c_void) {
    std::mem::drop(unsafe { Box::from_raw(state as *mut TFTPState) });
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
        Some(tx) => tx as *const _ as *mut _,
        None     => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn rs_tftp_get_tx_cnt(state: &mut TFTPState) -> u64 {
    return state.tx_id as u64;
}

fn getstr(i: &[u8]) -> IResult<&[u8], &str> {
    map_res(
        take_while(|c| c != 0),
        str::from_utf8
    )(i)
}

fn tftp_request<'a>(slice: &'a [u8]) -> IResult<&[u8], TFTPTransaction> {
    let (i, _) = tag([0])(slice)?;
    let (i, opcode) = be_u8(i)?;
    let (i, filename) = getstr(i)?;
    let (i, _) = tag([0])(i)?;
    let (i, mode) = getstr(i)?;
    Ok((i,
        TFTPTransaction::new(opcode, String::from(filename), String::from(mode))
       )
      )
}

fn parse_tftp_request(input: &[u8]) -> Option<TFTPTransaction> {
    match tftp_request(input) {
        Ok((_, tx)) => {
            if !tx.is_mode_ok() {
                return None;
            }
            if !tx.is_opcode_ok() {
                return None;
            }
            return Some(tx);
        }
        Err(_) => {
            return None;
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_tftp_request(state: &mut TFTPState,
                                  input: *const u8,
                                  len: u32) -> i64 {
    let buf = std::slice::from_raw_parts(input, len as usize);
    match parse_tftp_request(buf) {
        Some(mut tx) => {
            state.tx_id += 1;
            tx.id = state.tx_id;
            state.transactions.push(tx);
            0
        },
        None => {
           -1
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_tftp_get_tx_data(
    tx: *mut std::os::raw::c_void)
    -> *mut AppLayerTxData
{
    let tx = cast_pointer!(tx, TFTPTransaction);
    return &mut tx.tx_data;
}

#[no_mangle]
pub unsafe extern "C" fn rs_tftp_get_state_data(
    state: *mut std::os::raw::c_void)
    -> *mut AppLayerStateData
{
    let state = cast_pointer!(state, TFTPState);
    return &mut state.state_data;
}

#[cfg(test)]
mod test {
    use super::*;
    static READ_REQUEST: [u8; 20] = [
            0x00, 0x01, 0x72, 0x66, 0x63, 0x31, 0x33, 0x35, 0x30, 0x2e, 0x74, 0x78, 0x74, 0x00, 0x6f, 0x63, 0x74, 0x65, 0x74, 0x00,
    ];
    /* filename not terminated */
    static READ_REQUEST_INVALID_1: [u8; 20] = [
            0x00, 0x01, 0x72, 0x66, 0x63, 0x31, 0x33, 0x35, 0x30, 0x2e, 0x74, 0x78, 0x74, 0x6e, 0x6f, 0x63, 0x74, 0x65, 0x74, 0x00,
    ];
    /* garbage */
    static READ_REQUEST_INVALID_2: [u8; 3] = [
            0xff, 0xff, 0xff,
    ];
    static WRITE_REQUEST: [u8; 20] = [
            0x00, 0x02, 0x72, 0x66, 0x63, 0x31, 0x33, 0x35, 0x30, 0x2e, 0x74, 0x78, 0x74, 0x00, 0x6f, 0x63, 0x74, 0x65, 0x74, 0x00,
    ];
    /* filename not terminated */
    static INVALID_OPCODE: [u8; 20] = [
            0x00, 0x06, 0x72, 0x66, 0x63, 0x31, 0x33, 0x35, 0x30, 0x2e, 0x74, 0x78, 0x74, 0x6e, 0x6f, 0x63, 0x74, 0x65, 0x74, 0x00,
    ];
    static INVALID_MODE: [u8; 20] = [
            0x00, 0x01, 0x72, 0x66, 0x63, 0x31, 0x33, 0x35, 0x30, 0x2e, 0x74, 0x78, 0x74, 0x00, 0x63, 0x63, 0x63, 0x63, 0x63, 0x00,
    ];

    #[test]
    pub fn test_parse_tftp_read_request_1() {
        let tx = TFTPTransaction {
            opcode: READREQUEST,
            filename: String::from("rfc1350.txt"),
            mode: String::from("octet"),
            id: 0,
            tx_data: AppLayerTxData::new(),
        };

        match parse_tftp_request(&READ_REQUEST[..]) {
            Some(txp) => {
                assert_eq!(tx, txp);
            }
            None => {
                assert!(true);
            }
        }
    }

    #[test]
    pub fn test_parse_tftp_write_request_1() {
        let tx = TFTPTransaction {
            opcode: WRITEREQUEST,
            filename: String::from("rfc1350.txt"),
            mode: String::from("octet"),
            id: 0,
            tx_data: AppLayerTxData::new(),
        };

        match parse_tftp_request(&WRITE_REQUEST[..]) {
            Some(txp) => {
                assert_eq!(tx, txp);
            }
            None => {
                assert!(true, "fadfasd");
            }
        }
    }

    // Invalid request: filename not terminated
    #[test]
    pub fn test_parse_tftp_read_request_2() {
        assert_eq!(None, parse_tftp_request(&READ_REQUEST_INVALID_1[..]));
    }

    // Invalid request: garbage input
    #[test]
    pub fn test_parse_tftp_read_request_3() {
        assert_eq!(None, parse_tftp_request(&READ_REQUEST_INVALID_2[..]));
    }

    #[test]
    pub fn test_parse_tftp_invalid_opcode_1() {
        assert_eq!(None, parse_tftp_request(&INVALID_OPCODE[..]));
    }

    #[test]
    pub fn test_parse_tftp_invalid_mode() {

        assert_eq!(None, parse_tftp_request(&INVALID_MODE[..]));
    }
}
