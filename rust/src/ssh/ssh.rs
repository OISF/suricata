/* Copyright (C) 2018 Open Information Security Foundation
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

use super::parser;
use crate::applayer::{LoggerFlags, TxDetectFlags};
use crate::core::STREAM_TOSERVER;
use crate::core::{self, AppProto, Flow, ALPROTO_UNKNOWN, IPPROTO_TCP};
use crate::log::*;
use crate::parser::*;
use std;
use std::ffi::{CStr, CString};
use std::mem::transmute;

static mut ALPROTO_SSH: AppProto = ALPROTO_UNKNOWN;

#[repr(u32)]
pub enum SSHEvent {
    InvalidBanner = 0,
    LongBanner,
    InvalidRecord,
}

impl SSHEvent {
    fn from_i32(value: i32) -> Option<SSHEvent> {
        match value {
            0 => Some(SSHEvent::InvalidBanner),
            1 => Some(SSHEvent::LongBanner),
            2 => Some(SSHEvent::InvalidRecord),
            _ => None,
        }
    }
}

//TODO Exporting constant to C works, enum does not...
//pub const SSH_STATE_IN_PROGRESS: isize = 0;

#[repr(C)]
pub enum SSHConnectionState {
    SshStateInProgress = 0,
    SshStateBannerDone = 1,
    SshStateFinished = 2,
}

const SSH_FLAG_NONE: u8 = 0;
const SSH_FLAG_VERSION_PARSED: u8 = 1;
const SSH_FLAG_PARSER_DONE: u8 = 2;

const SSH_MAX_BANNER_LEN: usize = 256;
const SSH_RECORD_HEADER_LEN: usize = 6;
//TODO complete enum and parse messages contents
const SSH_MSG_NEWKEYS: u8 = 21;

pub struct SshHeader {
    record_left: u32,
    record_buf: Vec<u8>,
    flags: u8,
    banner: Vec<u8>,
    //can we have these be references to banner ?
    pub protover: Vec<u8>,
    pub swver: Vec<u8>,
}

impl SshHeader {
    pub fn new() -> SshHeader {
        SshHeader {
            record_left: 0,
            record_buf: Vec::with_capacity(SSH_RECORD_HEADER_LEN),
            flags: SSH_FLAG_NONE,
            banner: Vec::with_capacity(SSH_MAX_BANNER_LEN),
            protover: Vec::new(),
            swver: Vec::new(),
        }
    }
}

pub struct SSHTransaction {
    pub srv_hdr: SshHeader,
    pub cli_hdr: SshHeader,

    logged: LoggerFlags,
    de_state: Option<*mut core::DetectEngineState>,
    detect_flags: TxDetectFlags,
    events: *mut core::AppLayerDecoderEvents,
}

impl SSHTransaction {
    pub fn new() -> SSHTransaction {
        SSHTransaction {
            srv_hdr: SshHeader::new(),
            cli_hdr: SshHeader::new(),
            logged: LoggerFlags::new(),
            de_state: None,
            detect_flags: TxDetectFlags::default(),
            events: std::ptr::null_mut(),
        }
    }

    pub fn free(&mut self) {
        if self.events != std::ptr::null_mut() {
            core::sc_app_layer_decoder_events_free_events(&mut self.events);
        }
        if let Some(state) = self.de_state {
            core::sc_detect_engine_state_free(state);
        }
    }
}

impl Drop for SSHTransaction {
    fn drop(&mut self) {
        self.free();
    }
}

pub struct SSHState {
    transaction: SSHTransaction,
}

impl SSHState {
    pub fn new() -> Self {
        Self {
            transaction: SSHTransaction::new(),
        }
    }

    fn set_event(&mut self, event: SSHEvent) {
        let ev = event as u8;
        core::sc_app_layer_decoder_events_set_event_raw(&mut self.transaction.events, ev);
    }

    fn parse_record(&mut self, mut input: &[u8], resp: bool) -> bool {
        //TODO add SCLogDebug ?
        let mut hdr = &mut self.transaction.cli_hdr;
        if resp {
            hdr = &mut self.transaction.srv_hdr;
        }
        //first skip record left bytes
        if hdr.record_left > 0 {
            //should we check for overflow ?
            let ilen = input.len() as u32;
            if hdr.record_left >= ilen {
                hdr.record_left -= ilen;
                return true;
            } else {
                let start = hdr.record_left as usize;
                input = &input[start..];
                hdr.record_left = 0;
            }
        } else if hdr.record_buf.len() > 0 {
            //complete already present record_buf
            if hdr.record_buf.len() + input.len() < SSH_RECORD_HEADER_LEN {
                hdr.record_buf.extend(input);
                return true;
            } else {
                let needed = SSH_RECORD_HEADER_LEN - hdr.record_buf.len();
                hdr.record_buf.extend(&input[..needed]);
                input = &input[needed..];
            }
        }
        // Should we make the code with less duplicates ?
        if hdr.record_buf.len() > 0 {
            //parse header out of completed record_buf
            match parser::ssh_parse_record_header(&hdr.record_buf) {
                Ok((_, head)) => {
                    hdr.record_left = head.pkt_len - 2;
                    if head.msg_code == SSH_MSG_NEWKEYS {
                        hdr.flags = SSH_FLAG_PARSER_DONE;
                    }
                    //header with input as maybe incomplete data
                }
                Err(_) => {
                    self.set_event(SSHEvent::InvalidRecord);
                    return false;
                }
            }
            //empty buffer
            hdr.record_buf.clear();
            if hdr.record_left > 0 {
                let ilen = input.len() as u32;
                if hdr.record_left >= ilen {
                    hdr.record_left -= ilen;
                    return true;
                } else {
                    let start = hdr.record_left as usize;
                    input = &input[start..];
                    hdr.record_left = 0;
                }
            }
        }
        //parse records out of input
        while input.len() > 0 {
            match parser::ssh_parse_record(input) {
                Ok((rem, head)) => {
                    input = rem;
                    if head.msg_code == SSH_MSG_NEWKEYS {
                        hdr.flags = SSH_FLAG_PARSER_DONE;
                    }
                    //header and complete data (not returned)
                }
                Err(nom::Err::Incomplete(_)) => {
                    match parser::ssh_parse_record_header(input) {
                        Ok((rem, head)) => {
                            let remlen = rem.len() as u32;
                            hdr.record_left = head.pkt_len - 2 - remlen;
                            //header with rem as incomplete data
                            if head.msg_code == SSH_MSG_NEWKEYS {
                                hdr.flags = SSH_FLAG_PARSER_DONE;
                            }
                            return true;
                        }
                        Err(nom::Err::Incomplete(_)) => {
                            hdr.record_buf.extend(input);
                            return true;
                        }
                        Err(_) => {
                            self.set_event(SSHEvent::InvalidRecord);
                            return false;
                        }
                    }
                }
                Err(_) => {
                    self.set_event(SSHEvent::InvalidRecord);
                    return false;
                }
            }
        }
        return true;
    }

    fn parse_banner(&mut self, input: &[u8], resp: bool) -> bool {
        let mut hdr = &mut self.transaction.cli_hdr;
        if resp {
            hdr = &mut self.transaction.srv_hdr;
        }
        let mut iline = input;
        let mut vec = vec![13u8];
        if hdr.banner.len() > 0 {
            if hdr.banner[hdr.banner.len() - 1] == 13 {
                vec.extend(input);
                iline = &vec[..];
            }
        }
        match parser::ssh_parse_line(iline) {
            Ok((rem, line)) => {
                let mut set_event_long = false;
                if hdr.banner.len() + line.len() <= SSH_MAX_BANNER_LEN {
                    hdr.banner.extend(line);
                } else if hdr.banner.len() < SSH_MAX_BANNER_LEN {
                    hdr.banner
                        .extend(&line[0..SSH_MAX_BANNER_LEN - hdr.banner.len()]);
                    set_event_long = true;
                }
                match parser::ssh_parse_banner(&hdr.banner) {
                    Ok((_, banner)) => {
                        hdr.protover.extend(banner.protover);
                        if banner.swver.len() > 0 {
                            hdr.swver.extend(banner.swver);
                        }
                        hdr.flags = SSH_FLAG_VERSION_PARSED;
                    }
                    Err(_) => {
                        self.set_event(SSHEvent::InvalidBanner);
                        return false;
                    }
                }
                if set_event_long {
                    self.set_event(SSHEvent::LongBanner);
                }
                return self.parse_record(rem, resp);
            }
            Err(nom::Err::Incomplete(_)) => {
                if hdr.banner.len() + input.len() <= SSH_MAX_BANNER_LEN {
                    hdr.banner.extend(input);
                } else if hdr.banner.len() < SSH_MAX_BANNER_LEN {
                    hdr.banner
                        .extend(&input[0..SSH_MAX_BANNER_LEN - hdr.banner.len()]);
                    self.set_event(SSHEvent::LongBanner);
                }
                return true;
            }
            Err(_) => {
                self.set_event(SSHEvent::InvalidBanner);
                return false;
            }
        }
    }
}

// C exports.

export_tx_get_detect_state!(rs_ssh_tx_get_detect_state, SSHTransaction);
export_tx_set_detect_state!(rs_ssh_tx_set_detect_state, SSHTransaction);

export_tx_detect_flags_set!(rs_ssh_set_tx_detect_flags, SSHTransaction);
export_tx_detect_flags_get!(rs_ssh_get_tx_detect_flags, SSHTransaction);

#[no_mangle]
pub extern "C" fn rs_ssh_state_get_events(
    tx: *mut std::os::raw::c_void,
) -> *mut core::AppLayerDecoderEvents {
    let tx = cast_pointer!(tx, SSHTransaction);
    return tx.events;
}

#[no_mangle]
pub extern "C" fn rs_ssh_state_get_event_info(
    event_name: *const std::os::raw::c_char,
    event_id: *mut std::os::raw::c_int,
    event_type: *mut core::AppLayerEventType,
) -> std::os::raw::c_int {
    if event_name == std::ptr::null() {
        return -1;
    }
    let c_event_name: &CStr = unsafe { CStr::from_ptr(event_name) };
    let event = match c_event_name.to_str() {
        Ok(s) => {
            match s {
                "invalid_banner" => SSHEvent::InvalidBanner as i32,
                "long_banner" => SSHEvent::LongBanner as i32,
                "invalid_record" => SSHEvent::InvalidRecord as i32,
                _ => -1, // unknown event
            }
        }
        Err(_) => -1, // UTF-8 conversion failed
    };
    unsafe {
        *event_type = core::APP_LAYER_EVENT_TYPE_TRANSACTION;
        *event_id = event as std::os::raw::c_int;
    };
    0
}

#[no_mangle]
pub extern "C" fn rs_ssh_state_get_event_info_by_id(
    event_id: std::os::raw::c_int,
    event_name: *mut *const std::os::raw::c_char,
    event_type: *mut core::AppLayerEventType,
) -> i8 {
    if let Some(e) = SSHEvent::from_i32(event_id as i32) {
        let estr = match e {
            SSHEvent::InvalidBanner => "invalid_banner\0",
            SSHEvent::LongBanner => "long_banner\0",
            SSHEvent::InvalidRecord => "invalid_record\0",
        };
        unsafe {
            *event_name = estr.as_ptr() as *const std::os::raw::c_char;
            *event_type = core::APP_LAYER_EVENT_TYPE_TRANSACTION;
        };
        0
    } else {
        -1
    }
}

#[no_mangle]
pub extern "C" fn rs_ssh_state_new() -> *mut std::os::raw::c_void {
    let state = SSHState::new();
    let boxed = Box::new(state);
    return unsafe { transmute(boxed) };
}

#[no_mangle]
pub extern "C" fn rs_ssh_state_free(state: *mut std::os::raw::c_void) {
    // Just unbox...
    let _drop: Box<SSHState> = unsafe { transmute(state) };
}

#[no_mangle]
pub extern "C" fn rs_ssh_state_tx_free(_state: *mut std::os::raw::c_void, _tx_id: u64) {
    //do nothing
}

#[no_mangle]
pub extern "C" fn rs_ssh_parse_request(
    _flow: *const Flow,
    state: *mut std::os::raw::c_void,
    pstate: *mut std::os::raw::c_void,
    input: *const u8,
    input_len: u32,
    _data: *const std::os::raw::c_void,
    _flags: u8,
) -> i32 {
    let state = &mut cast_pointer!(state, SSHState);
    let buf = build_slice!(input, input_len as usize);
    let hdr = &mut state.transaction.cli_hdr;
    let mut rv = -1;
    if hdr.flags < SSH_FLAG_VERSION_PARSED {
        if state.parse_banner(buf, false) {
            rv = 1;
        }
    } else {
        if state.parse_record(buf, false) {
            rv = 1;
        }
    }
    if state.transaction.cli_hdr.flags >= SSH_FLAG_PARSER_DONE
        && state.transaction.srv_hdr.flags >= SSH_FLAG_PARSER_DONE
    {
        unsafe {
            AppLayerParserStateSetFlag(
                pstate,
                APP_LAYER_PARSER_NO_INSPECTION
                    | APP_LAYER_PARSER_NO_REASSEMBLY
                    | APP_LAYER_PARSER_BYPASS_READY,
            );
        }
    }

    return rv;
}

#[no_mangle]
pub extern "C" fn rs_ssh_parse_response(
    _flow: *const Flow,
    state: *mut std::os::raw::c_void,
    pstate: *mut std::os::raw::c_void,
    input: *const u8,
    input_len: u32,
    _data: *const std::os::raw::c_void,
    _flags: u8,
) -> i32 {
    let state = &mut cast_pointer!(state, SSHState);
    let buf = build_slice!(input, input_len as usize);
    let hdr = &mut state.transaction.srv_hdr;
    let mut rv = -1;
    if hdr.flags < SSH_FLAG_VERSION_PARSED {
        if state.parse_banner(buf, true) {
            rv = 1;
        }
    } else {
        if state.parse_record(buf, true) {
            rv = 1;
        }
    }
    if state.transaction.cli_hdr.flags >= SSH_FLAG_PARSER_DONE
        && state.transaction.srv_hdr.flags >= SSH_FLAG_PARSER_DONE
    {
        unsafe {
            AppLayerParserStateSetFlag(
                pstate,
                APP_LAYER_PARSER_NO_INSPECTION
                    | APP_LAYER_PARSER_NO_REASSEMBLY
                    | APP_LAYER_PARSER_BYPASS_READY,
            );
        }
    }
    return rv;
}

#[no_mangle]
pub extern "C" fn rs_ssh_state_get_tx(
    state: *mut std::os::raw::c_void,
    _tx_id: u64,
) -> *mut std::os::raw::c_void {
    let state = cast_pointer!(state, SSHState);
    return unsafe { transmute(&state.transaction) };
}

#[no_mangle]
pub extern "C" fn rs_ssh_state_get_tx_count(_state: *mut std::os::raw::c_void) -> u64 {
    return 1;
}

#[no_mangle]
pub extern "C" fn rs_ssh_state_progress_completion_status(_direction: u8) -> std::os::raw::c_int {
    return SSHConnectionState::SshStateFinished as i32;
}

#[no_mangle]
pub extern "C" fn rs_ssh_tx_get_flags(
    tx: *mut std::os::raw::c_void,
    direction: u8,
) -> std::os::raw::c_int {
    let tx = cast_pointer!(tx, SSHTransaction);
    if direction == STREAM_TOSERVER {
        return tx.cli_hdr.flags as i32;
    } else {
        return tx.srv_hdr.flags as i32;
    }
}

#[no_mangle]
pub extern "C" fn rs_ssh_tx_get_alstate_progress(
    tx: *mut std::os::raw::c_void,
    direction: u8,
) -> std::os::raw::c_int {
    let tx = cast_pointer!(tx, SSHTransaction);

    if tx.cli_hdr.flags >= SSH_FLAG_PARSER_DONE && tx.srv_hdr.flags >= SSH_FLAG_PARSER_DONE {
        return SSHConnectionState::SshStateFinished as i32;
    }

    if direction == STREAM_TOSERVER {
        if tx.cli_hdr.flags >= SSH_FLAG_VERSION_PARSED {
            return SSHConnectionState::SshStateBannerDone as i32;
        }
    } else {
        if tx.srv_hdr.flags >= SSH_FLAG_VERSION_PARSED {
            return SSHConnectionState::SshStateBannerDone as i32;
        }
    }

    return SSHConnectionState::SshStateInProgress as i32;
}

#[no_mangle]
pub extern "C" fn rs_ssh_tx_get_logged(
    _state: *mut std::os::raw::c_void,
    tx: *mut std::os::raw::c_void,
) -> u32 {
    let tx = cast_pointer!(tx, SSHTransaction);
    return tx.logged.get();
}

#[no_mangle]
pub extern "C" fn rs_ssh_tx_set_logged(
    _state: *mut std::os::raw::c_void,
    tx: *mut std::os::raw::c_void,
    logged: u32,
) {
    let tx = cast_pointer!(tx, SSHTransaction);
    tx.logged.set(logged);
}

// Parser name as a C style string.
const PARSER_NAME: &'static [u8] = b"ssh\0";

#[no_mangle]
pub unsafe extern "C" fn rs_ssh_register_parser() {
    let default_port = CString::new("[22]").unwrap();
    let parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const std::os::raw::c_char,
        default_port: default_port.as_ptr(),
        ipproto: IPPROTO_TCP,
        //simple patterns, no probing
        probe_ts: None,
        probe_tc: None,
        min_depth: 0,
        max_depth: 0,
        state_new: rs_ssh_state_new,
        state_free: rs_ssh_state_free,
        tx_free: rs_ssh_state_tx_free,
        parse_ts: rs_ssh_parse_request,
        parse_tc: rs_ssh_parse_response,
        get_tx_count: rs_ssh_state_get_tx_count,
        get_tx: rs_ssh_state_get_tx,
        tx_get_comp_st: rs_ssh_state_progress_completion_status,
        tx_get_progress: rs_ssh_tx_get_alstate_progress,
        get_tx_logged: Some(rs_ssh_tx_get_logged),
        set_tx_logged: Some(rs_ssh_tx_set_logged),
        get_de_state: rs_ssh_tx_get_detect_state,
        set_de_state: rs_ssh_tx_set_detect_state,
        get_events: Some(rs_ssh_state_get_events),
        get_eventinfo: Some(rs_ssh_state_get_event_info),
        get_eventinfo_byid: Some(rs_ssh_state_get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_tx_mpm_id: None,
        set_tx_mpm_id: None,
        get_files: None,
        get_tx_iterator: None,
        get_tx_detect_flags: Some(rs_ssh_get_tx_detect_flags),
        set_tx_detect_flags: Some(rs_ssh_set_tx_detect_flags),
    };

    let ip_proto_str = CString::new("tcp").unwrap();

    if AppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_SSH = alproto;
        if AppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
        SCLogNotice!("Rust ssh parser registered.");
    } else {
        SCLogNotice!("Protocol detector and parser disabled for SSH.");
    }
}
