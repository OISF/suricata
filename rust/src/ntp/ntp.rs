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

// written by Pierre Chifflier  <chifflier@wzdftpd.net>

extern crate ntp_parser;
use self::ntp_parser::*;
use core;
use applayer;
use libc;
use std;
use std::ffi::CStr;

use log::*;

use nom::IResult;

#[repr(u32)]
pub enum NTPEvent {
    UnsolicitedResponse = 0,
    MalformedData,
    NotRequest,
    NotResponse,
}



pub struct NTPState {
    /// List of transactions for this session
    transactions: Vec<NTPTransaction>,

    /// Detection engine states counter
    de_state_count: u64,

    /// Events counter
    events: u16,

    /// tx counter for assigning incrementing id's to tx's
    tx_id: u64,
}

#[derive(Debug)]
pub struct NTPTransaction {
    /// The NTP reference ID
    pub xid: u32,

    /// The internal transaction id
    id: u64,

    /// The detection engine state, if present
    de_state: Option<*mut core::DetectEngineState>,

    /// The events associated with this transaction
    events: *mut core::AppLayerDecoderEvents,

    logged: applayer::LoggerFlags,
}



impl NTPState {
    pub fn new() -> NTPState {
        NTPState{
            transactions: Vec::new(),
            de_state_count: 0,
            events: 0,
            tx_id: 0,
        }
    }
}

impl NTPState {
    /// Parse an NTP request message
    ///
    /// Returns The number of messages parsed, or -1 on error
    fn parse(&mut self, i: &[u8], _direction: u8) -> i8 {
        match parse_ntp(i) {
            IResult::Done(_,ref msg) => {
                // SCLogDebug!("parse_ntp: {:?}",msg);
                if msg.mode == 1 || msg.mode == 3 {
                    let mut tx = self.new_tx();
                    // use the reference id as identifier
                    tx.xid = msg.ref_id;
                    self.transactions.push(tx);
                }
                1
            },
            IResult::Incomplete(_) => {
                SCLogDebug!("Insufficient data while parsing NTP data");
                self.set_event(NTPEvent::MalformedData);
                -1
            },
            IResult::Error(_) => {
                SCLogDebug!("Error while parsing NTP data");
                self.set_event(NTPEvent::MalformedData);
                -1
            },
        }
    }

    fn free(&mut self) {
        // All transactions are freed when the `transactions` object is freed.
        // But let's be explicit
        self.transactions.clear();
    }

    fn new_tx(&mut self) -> NTPTransaction {
        self.tx_id += 1;
        NTPTransaction::new(self.tx_id)
    }

    pub fn get_tx_by_id(&mut self, tx_id: u64) -> Option<&NTPTransaction> {
        self.transactions.iter().find(|&tx| tx.id == tx_id + 1)
    }

    fn free_tx(&mut self, tx_id: u64) {
        let tx = self.transactions.iter().position(|ref tx| tx.id == tx_id + 1);
        debug_assert!(tx != None);
        if let Some(idx) = tx {
            let _ = self.transactions.remove(idx);
        }
    }

    /// Set an event. The event is set on the most recent transaction.
    pub fn set_event(&mut self, event: NTPEvent) {
        if let Some(tx) = self.transactions.last_mut() {
            let ev = event as u8;
            core::sc_app_layer_decoder_events_set_event_raw(&mut tx.events, ev);
            self.events += 1;
        }
    }
}

impl NTPTransaction {
    pub fn new(id: u64) -> NTPTransaction {
        NTPTransaction {
            xid: 0,
            id: id,
            de_state: None,
            events: std::ptr::null_mut(),
            logged: applayer::LoggerFlags::new(),
        }
    }

    fn free(&mut self) {
        if self.events != std::ptr::null_mut() {
            core::sc_app_layer_decoder_events_free_events(&mut self.events);
        }
    }
}

impl Drop for NTPTransaction {
    fn drop(&mut self) {
        self.free();
    }
}


/// TOSERVER probe function
#[no_mangle]
pub extern "C" fn rs_ntp_probe(input: *const libc::uint8_t, len: libc::uint32_t)
                               -> libc::int8_t
{
    let slice: &[u8] = unsafe {
        std::slice::from_raw_parts(input as *mut u8, len as usize)
    };
    match parse_ntp(slice) {
        IResult::Done(_, ref msg) => {
            if msg.version == 3 || msg.version == 4 {
                return 1;
            } else {
                return -1;
            }
        },
        IResult::Incomplete(_) => {
            return 0;
        },
        IResult::Error(_) => {
            return -1;
        },
    }
}







/// Returns *mut NTPState
#[no_mangle]
pub extern "C" fn rs_ntp_state_new() -> *mut libc::c_void {
    let state = NTPState::new();
    let boxed = Box::new(state);
    return unsafe{std::mem::transmute(boxed)};
}

/// Params:
/// - state: *mut NTPState as void pointer
#[no_mangle]
pub extern "C" fn rs_ntp_state_free(state: *mut libc::c_void) {
    // Just unbox...
    let mut ntp_state: Box<NTPState> = unsafe{std::mem::transmute(state)};
    ntp_state.free();
}

#[no_mangle]
pub extern "C" fn rs_ntp_parse_request(_flow: *const core::Flow,
                                       state: &mut NTPState,
                                       _pstate: *const libc::c_void,
                                       input: *const libc::uint8_t,
                                       input_len: u32,
                                       _data: *const libc::c_void) -> i8 {
    let buf = unsafe{std::slice::from_raw_parts(input, input_len as usize)};
    state.parse(buf, 0)
}

#[no_mangle]
pub extern "C" fn rs_ntp_parse_response(_flow: *const core::Flow,
                                       state: &mut NTPState,
                                       _pstate: *const libc::c_void,
                                       input: *const libc::uint8_t,
                                       input_len: u32,
                                       _data: *const libc::c_void) -> i8 {
    let buf = unsafe{std::slice::from_raw_parts(input, input_len as usize)};
    state.parse(buf, 1)
}

#[no_mangle]
pub extern "C" fn rs_ntp_state_get_tx(state: &mut NTPState,
                                      tx_id: libc::uint64_t)
                                      -> *mut NTPTransaction
{
    match state.get_tx_by_id(tx_id) {
        Some(tx) => unsafe{std::mem::transmute(tx)},
        None     => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn rs_ntp_state_get_tx_count(state: &mut NTPState)
                                            -> libc::uint64_t
{
    state.tx_id
}

#[no_mangle]
pub extern "C" fn rs_ntp_state_tx_free(state: &mut NTPState,
                                       tx_id: libc::uint64_t)
{
    state.free_tx(tx_id);
}

#[no_mangle]
pub extern "C" fn rs_ntp_state_progress_completion_status(
    _direction: libc::uint8_t)
    -> libc::c_int
{
    return 1;
}

#[no_mangle]
pub extern "C" fn rs_ntp_tx_get_alstate_progress(_tx: &mut NTPTransaction,
                                                 _direction: libc::uint8_t)
                                                 -> libc::uint8_t
{
    1
}





#[no_mangle]
pub extern "C" fn rs_ntp_tx_set_logged(_state: &mut NTPState,
                                       tx: &mut NTPTransaction,
                                       logger: libc::uint32_t)
{
    tx.logged.set_logged(logger);
}

#[no_mangle]
pub extern "C" fn rs_ntp_tx_get_logged(_state: &mut NTPState,
                                       tx: &mut NTPTransaction,
                                       logger: libc::uint32_t)
                                       -> i8
{
    if tx.logged.is_logged(logger) {
        return 1;
    }
    return 0;
}


#[no_mangle]
pub extern "C" fn rs_ntp_state_set_tx_detect_state(
    state: &mut NTPState,
    tx: &mut NTPTransaction,
    de_state: &mut core::DetectEngineState)
{
    state.de_state_count += 1;
    tx.de_state = Some(de_state);
}

#[no_mangle]
pub extern "C" fn rs_ntp_state_get_tx_detect_state(
    tx: &mut NTPTransaction)
    -> *mut core::DetectEngineState
{
    match tx.de_state {
        Some(ds) => ds,
        None => std::ptr::null_mut(),
    }
}


#[no_mangle]
pub extern "C" fn rs_ntp_state_has_events(state: &mut NTPState) -> u8 {
    if state.events > 0 {
        return 1;
    }
    return 0;
}

#[no_mangle]
pub extern "C" fn rs_ntp_state_get_events(state: &mut NTPState,
                                          tx_id: libc::uint64_t)
                                          -> *mut core::AppLayerDecoderEvents
{
    match state.get_tx_by_id(tx_id) {
        Some(tx) => tx.events,
        _        => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn rs_ntp_state_get_event_info(event_name: *const libc::c_char,
                                              event_id: *mut libc::c_int,
                                              event_type: *mut core::AppLayerEventType)
                                              -> i8
{
    if event_name == std::ptr::null() { return -1; }
    let c_event_name: &CStr = unsafe { CStr::from_ptr(event_name) };
    let event = match c_event_name.to_str() {
        Ok(s) => {
            match s {
                "malformed_data" => NTPEvent::MalformedData as i32,
                _ => -1, // unknown event
            }
        },
        Err(_) => -1, // UTF-8 conversion failed
    };
    unsafe{
        *event_type = core::APP_LAYER_EVENT_TYPE_TRANSACTION;
        *event_id = event as libc::c_int;
    };
    0
}

#[cfg(test)]
mod tests {
    use super::NTPState;

    #[test]
    fn test_ntp_parse_request_valid() {
        // A UDP NTP v4 request, in client mode
        const REQ : &[u8] = &[
            0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x18, 0x57, 0xab, 0xc3, 0x4a, 0x5f, 0x2c, 0xfe
        ];

        let mut state = NTPState::new();
        assert_eq!(1, state.parse(REQ, 0));
    }
}
