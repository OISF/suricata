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

use super::parser;
use crate::applayer::*;
use crate::core::STREAM_TOSERVER;
use crate::core::{self, AppProto, Flow, ALPROTO_UNKNOWN, IPPROTO_TCP};
use std::ffi::{CStr, CString};
use std::mem::transmute;
use std::sync::atomic::{AtomicBool, Ordering};

static mut ALPROTO_SSH: AppProto = ALPROTO_UNKNOWN;
static HASSH_ENABLED: AtomicBool = AtomicBool::new(false);

fn hassh_is_enabled() -> bool {
    HASSH_ENABLED.load(Ordering::Relaxed)
}

#[repr(u32)]
pub enum SSHEvent {
    InvalidBanner = 0,
    LongBanner,
    InvalidRecord,
    LongKexRecord,
}

impl SSHEvent {
    fn from_i32(value: i32) -> Option<SSHEvent> {
        match value {
            0 => Some(SSHEvent::InvalidBanner),
            1 => Some(SSHEvent::LongBanner),
            2 => Some(SSHEvent::InvalidRecord),
            3 => Some(SSHEvent::LongKexRecord),
            _ => None,
        }
    }
}

#[repr(u8)]
#[derive(Copy, Clone, PartialOrd, PartialEq)]
pub enum SSHConnectionState {
    SshStateInProgress = 0,
    SshStateBannerWaitEol = 1,
    SshStateBannerDone = 2,
    SshStateFinished = 3,
}

const SSH_MAX_BANNER_LEN: usize = 256;
const SSH_RECORD_HEADER_LEN: usize = 6;
const SSH_MAX_REASSEMBLED_RECORD_LEN: usize = 65535;

pub struct SshHeader {
    record_left: u32,
    record_left_msg: parser::MessageCode,

    flags: SSHConnectionState,
    pub protover: Vec<u8>,
    pub swver: Vec<u8>,

    pub hassh: Vec<u8>,
    pub hassh_string: Vec<u8>,
}

impl SshHeader {
    pub fn new() -> SshHeader {
        SshHeader {
            record_left: 0,
            record_left_msg: parser::MessageCode::SshMsgUndefined(0),

            flags: SSHConnectionState::SshStateInProgress,
            protover: Vec::new(),
            swver: Vec::new(),

            hassh: Vec::new(),
            hassh_string: Vec::new(),
        }
    }
}

pub struct SSHTransaction {
    pub srv_hdr: SshHeader,
    pub cli_hdr: SshHeader,

    de_state: Option<*mut core::DetectEngineState>,
    events: *mut core::AppLayerDecoderEvents,
    tx_data: AppLayerTxData,
}

impl SSHTransaction {
    pub fn new() -> SSHTransaction {
        SSHTransaction {
            srv_hdr: SshHeader::new(),
            cli_hdr: SshHeader::new(),
            de_state: None,
            events: std::ptr::null_mut(),
            tx_data: AppLayerTxData::new(),
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

    fn parse_record(
        &mut self, mut input: &[u8], resp: bool, pstate: *mut std::os::raw::c_void,
    ) -> AppLayerResult {
        let (mut hdr, ohdr) = if !resp {
            (&mut self.transaction.cli_hdr, &self.transaction.srv_hdr)
        } else {
            (&mut self.transaction.srv_hdr, &self.transaction.cli_hdr)
        };
        let il = input.len();
        //first skip record left bytes
        if hdr.record_left > 0 {
            //should we check for overflow ?
            let ilen = input.len() as u32;
            if hdr.record_left > ilen {
                hdr.record_left -= ilen;
                return AppLayerResult::ok();
            } else {
                let start = hdr.record_left as usize;
                match hdr.record_left_msg {
                    // parse reassembled tcp segments
                    parser::MessageCode::SshMsgKexinit if hassh_is_enabled() => {
                        if let Ok((_rem, key_exchange)) =
                            parser::ssh_parse_key_exchange(&input[..start])
                        {
                            key_exchange.generate_hassh(
                                &mut hdr.hassh_string,
                                &mut hdr.hassh,
                                &resp,
                            );
                        }
                        hdr.record_left_msg = parser::MessageCode::SshMsgUndefined(0);
                    }
                    _ => {}
                }
                input = &input[start..];
                hdr.record_left = 0;
            }
        }
        //parse records out of input
        while input.len() > 0 {
            match parser::ssh_parse_record(input) {
                Ok((rem, head)) => {
                    SCLogDebug!("SSH valid record {}", head);
                    match head.msg_code {
                        parser::MessageCode::SshMsgKexinit if hassh_is_enabled() => {
                            //let endkex = SSH_RECORD_HEADER_LEN + head.pkt_len - 2;
                            let endkex = input.len() - rem.len();
                            if let Ok((_, key_exchange)) = parser::ssh_parse_key_exchange(&input[SSH_RECORD_HEADER_LEN..endkex]) {
                                key_exchange.generate_hassh(&mut hdr.hassh_string, &mut hdr.hassh, &resp);
                            }
                        }
                        parser::MessageCode::SshMsgNewKeys => {
                            hdr.flags = SSHConnectionState::SshStateFinished;
                            if ohdr.flags >= SSHConnectionState::SshStateFinished {
                                unsafe {
                                    AppLayerParserStateSetFlag(
                                        pstate,
                                        APP_LAYER_PARSER_NO_INSPECTION
                                        | APP_LAYER_PARSER_NO_REASSEMBLY
                                        | APP_LAYER_PARSER_BYPASS_READY,
                                    );
                                }
                            }
                        }
                        _ => {}
                    }
                    
                    input = rem;
                    //header and complete data (not returned)
                }
                Err(nom::Err::Incomplete(_)) => {
                    match parser::ssh_parse_record_header(input) {
                        Ok((rem, head)) => {
                            SCLogDebug!("SSH valid record header {}", head);
                            let remlen = rem.len() as u32;
                            hdr.record_left = head.pkt_len - 2 - remlen;
                            //header with rem as incomplete data
                            match head.msg_code { 
                                parser::MessageCode::SshMsgNewKeys => {
                                    hdr.flags = SSHConnectionState::SshStateFinished;
                                }
                                parser::MessageCode::SshMsgKexinit if hassh_is_enabled() => {
                                    // check if buffer is bigger than maximum reassembled packet size
                                    hdr.record_left = head.pkt_len - 2;
                                    if hdr.record_left < SSH_MAX_REASSEMBLED_RECORD_LEN as u32 {
                                        // saving type of incomplete kex message
                                        hdr.record_left_msg = parser::MessageCode::SshMsgKexinit;
                                        return AppLayerResult::incomplete(
                                            (il - rem.len()) as u32,
                                            (head.pkt_len - 2) as u32
                                        );
                                    }
                                    else {
                                        SCLogDebug!("SSH buffer is bigger than maximum reassembled packet size");
                                        self.set_event(SSHEvent::LongKexRecord);
                                    }
                                }
                                _ => {}
                            }
                            return AppLayerResult::ok();
                        }
                        Err(nom::Err::Incomplete(_)) => {
                            //we may have consumed data from previous records
                            if input.len() < SSH_RECORD_HEADER_LEN {
                                //do not trust nom incomplete value
                                return AppLayerResult::incomplete(
                                    (il - input.len()) as u32,
                                    SSH_RECORD_HEADER_LEN as u32,
                                );
                            } else {
                                panic!("SSH invalid length record header");
                            }
                        }
                        Err(_e) => {
                            SCLogDebug!("SSH invalid record header {}", _e);
                            self.set_event(SSHEvent::InvalidRecord);
                            return AppLayerResult::err();
                        }
                    }
                }
                Err(_e) => {
                    SCLogDebug!("SSH invalid record {}", _e);
                    self.set_event(SSHEvent::InvalidRecord);
                    return AppLayerResult::err();
                }
            }
        }
        return AppLayerResult::ok();
    }

    fn parse_banner(
        &mut self, input: &[u8], resp: bool, pstate: *mut std::os::raw::c_void,
    ) -> AppLayerResult {
        let mut hdr = if !resp {
            &mut self.transaction.cli_hdr
        } else {
            &mut self.transaction.srv_hdr
        };
        if hdr.flags == SSHConnectionState::SshStateBannerWaitEol {
            match parser::ssh_parse_line(input) {
                Ok((rem, _)) => {
                    let mut r = self.parse_record(rem, resp, pstate);
                    if r.is_incomplete() {
                        //adds bytes consumed by banner to incomplete result
                        r.consumed += (input.len() - rem.len()) as u32;
                    }
                    return r;
                }
                Err(nom::Err::Incomplete(_)) => {
                    return AppLayerResult::incomplete(0 as u32, (input.len() + 1) as u32);
                }
                Err(_e) => {
                    SCLogDebug!("SSH invalid banner {}", _e);
                    self.set_event(SSHEvent::InvalidBanner);
                    return AppLayerResult::err();
                }
            }
        }
        match parser::ssh_parse_line(input) {
            Ok((rem, line)) => {
                if let Ok((_, banner)) = parser::ssh_parse_banner(line) {
                    hdr.protover.extend(banner.protover);
                    if banner.swver.len() > 0 {
                        hdr.swver.extend(banner.swver);
                    }
                    hdr.flags = SSHConnectionState::SshStateBannerDone;
                } else {
                    SCLogDebug!("SSH invalid banner");
                    self.set_event(SSHEvent::InvalidBanner);
                    return AppLayerResult::err();
                }
                if line.len() >= SSH_MAX_BANNER_LEN {
                    SCLogDebug!(
                        "SSH banner too long {} vs {}",
                        line.len(),
                        SSH_MAX_BANNER_LEN
                    );
                    self.set_event(SSHEvent::LongBanner);
                }
                let mut r = self.parse_record(rem, resp, pstate);
                if r.is_incomplete() {
                    //adds bytes consumed by banner to incomplete result
                    r.consumed += (input.len() - rem.len()) as u32;
                }
                return r;
            }
            Err(nom::Err::Incomplete(_)) => {
                if input.len() < SSH_MAX_BANNER_LEN {
                    //0 consumed, needs at least one more byte
                    return AppLayerResult::incomplete(0 as u32, (input.len() + 1) as u32);
                } else {
                    SCLogDebug!(
                        "SSH banner too long {} vs {} and waiting for eol",
                        input.len(),
                        SSH_MAX_BANNER_LEN
                    );
                    if let Ok((_, banner)) = parser::ssh_parse_banner(input) {
                        hdr.protover.extend(banner.protover);
                        if banner.swver.len() > 0 {
                            hdr.swver.extend(banner.swver);
                        }
                        hdr.flags = SSHConnectionState::SshStateBannerWaitEol;
                        self.set_event(SSHEvent::LongBanner);
                        return AppLayerResult::ok();
                    } else {
                        self.set_event(SSHEvent::InvalidBanner);
                        return AppLayerResult::err();
                    }
                }
            }
            Err(_e) => {
                SCLogDebug!("SSH invalid banner {}", _e);
                self.set_event(SSHEvent::InvalidBanner);
                return AppLayerResult::err();
            }
        }
    }
}

// C exports.

export_tx_get_detect_state!(rs_ssh_tx_get_detect_state, SSHTransaction);
export_tx_set_detect_state!(rs_ssh_tx_set_detect_state, SSHTransaction);

export_tx_data_get!(rs_ssh_get_tx_data, SSHTransaction);

#[no_mangle]
pub extern "C" fn rs_ssh_state_get_events(
    tx: *mut std::os::raw::c_void,
) -> *mut core::AppLayerDecoderEvents {
    let tx = cast_pointer!(tx, SSHTransaction);
    return tx.events;
}

#[no_mangle]
pub extern "C" fn rs_ssh_state_get_event_info(
    event_name: *const std::os::raw::c_char, event_id: *mut std::os::raw::c_int,
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
                "long_kex_record" => SSHEvent::LongKexRecord as i32,
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
    event_id: std::os::raw::c_int, event_name: *mut *const std::os::raw::c_char,
    event_type: *mut core::AppLayerEventType,
) -> i8 {
    if let Some(e) = SSHEvent::from_i32(event_id as i32) {
        let estr = match e {
            SSHEvent::InvalidBanner => "invalid_banner\0",
            SSHEvent::LongBanner => "long_banner\0",
            SSHEvent::InvalidRecord => "invalid_record\0",
            SSHEvent::LongKexRecord => "long_kex_record\0",
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
pub extern "C" fn rs_ssh_state_new(_orig_state: *mut std::os::raw::c_void, _orig_proto: AppProto) -> *mut std::os::raw::c_void {
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
    _flow: *const Flow, state: *mut std::os::raw::c_void, pstate: *mut std::os::raw::c_void,
    input: *const u8, input_len: u32, _data: *const std::os::raw::c_void, _flags: u8,
) -> AppLayerResult {
    let state = &mut cast_pointer!(state, SSHState);
    let buf = build_slice!(input, input_len as usize);
    let hdr = &mut state.transaction.cli_hdr;
    if hdr.flags < SSHConnectionState::SshStateBannerDone {
        return state.parse_banner(buf, false, pstate);
    } else {
        return state.parse_record(buf, false, pstate);
    }
}

#[no_mangle]
pub extern "C" fn rs_ssh_parse_response(
    _flow: *const Flow, state: *mut std::os::raw::c_void, pstate: *mut std::os::raw::c_void,
    input: *const u8, input_len: u32, _data: *const std::os::raw::c_void, _flags: u8,
) -> AppLayerResult {
    let state = &mut cast_pointer!(state, SSHState);
    let buf = build_slice!(input, input_len as usize);
    let hdr = &mut state.transaction.srv_hdr;
    if hdr.flags < SSHConnectionState::SshStateBannerDone {
        return state.parse_banner(buf, true, pstate);
    } else {
        return state.parse_record(buf, true, pstate);
    }
}

#[no_mangle]
pub extern "C" fn rs_ssh_state_get_tx(
    state: *mut std::os::raw::c_void, _tx_id: u64,
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
    tx: *mut std::os::raw::c_void, direction: u8,
) -> SSHConnectionState {
    let tx = cast_pointer!(tx, SSHTransaction);
    if direction == STREAM_TOSERVER {
        return tx.cli_hdr.flags;
    } else {
        return tx.srv_hdr.flags;
    }
}

#[no_mangle]
pub extern "C" fn rs_ssh_tx_get_alstate_progress(
    tx: *mut std::os::raw::c_void, direction: u8,
) -> std::os::raw::c_int {
    let tx = cast_pointer!(tx, SSHTransaction);

    if tx.cli_hdr.flags >= SSHConnectionState::SshStateFinished
        && tx.srv_hdr.flags >= SSHConnectionState::SshStateFinished
    {
        return SSHConnectionState::SshStateFinished as i32;
    }

    if direction == STREAM_TOSERVER {
        if tx.cli_hdr.flags >= SSHConnectionState::SshStateBannerDone {
            return SSHConnectionState::SshStateBannerDone as i32;
        }
    } else {
        if tx.srv_hdr.flags >= SSHConnectionState::SshStateBannerDone {
            return SSHConnectionState::SshStateBannerDone as i32;
        }
    }

    return SSHConnectionState::SshStateInProgress as i32;
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
        get_de_state: rs_ssh_tx_get_detect_state,
        set_de_state: rs_ssh_tx_set_detect_state,
        get_events: Some(rs_ssh_state_get_events),
        get_eventinfo: Some(rs_ssh_state_get_event_info),
        get_eventinfo_byid: Some(rs_ssh_state_get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_files: None,
        get_tx_iterator: None,
        get_tx_data: rs_ssh_get_tx_data,
        apply_tx_config: None,
        flags: 0,
        truncate: None,
    };

    let ip_proto_str = CString::new("tcp").unwrap();

    if AppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_SSH = alproto;
        if AppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
        SCLogDebug!("Rust ssh parser registered.");
    } else {
        SCLogNotice!("Protocol detector and parser disabled for SSH.");
    }
}

#[no_mangle]
pub extern "C" fn rs_ssh_enable_hassh() {
    HASSH_ENABLED.store(true, Ordering::Relaxed)
}

#[no_mangle]
pub extern "C" fn rs_ssh_hassh_is_enabled() -> bool {
    hassh_is_enabled()
}

#[no_mangle]
pub extern "C" fn rs_ssh_tx_get_log_condition( tx: *mut std::os::raw::c_void) -> bool {
    let tx = cast_pointer!(tx, SSHTransaction);
    
    if rs_ssh_hassh_is_enabled() {
        if  tx.cli_hdr.flags == SSHConnectionState::SshStateFinished &&
            tx.srv_hdr.flags == SSHConnectionState::SshStateFinished {
            return true; 
        }
    }
    else {
        if  tx.cli_hdr.flags == SSHConnectionState::SshStateBannerDone && 
            tx.srv_hdr.flags == SSHConnectionState::SshStateBannerDone {
            return true;
        }
    }
    return false;
}
