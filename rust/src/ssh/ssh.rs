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
use std::ffi::CString;
use std::mem::transmute;

static mut ALPROTO_SSH: AppProto = ALPROTO_UNKNOWN;

pub enum SSHConnectionState {
    SshStateInProgress,
    SshStateBannerDone,
    SshStateFinished,
}

bitflags! {
    pub struct SSHTxFlag: u8 {
        const SSH_FLAG_NONE = 0;
        const SSH_FLAG_VERSION_PARSED=1;
        const SSH_FLAG_PARSER_DONE=2;
    }
}

const SSH_MAX_BANNER_LEN: usize = 256;

pub struct SshHeader {
    pub pkt_len: u32,
    flags: SSHTxFlag,
    pub banner: Vec<u8>,
}

impl SshHeader {
    pub fn new() -> SshHeader {
        SshHeader {
            pkt_len: 0,
            flags: SSHTxFlag::SSH_FLAG_NONE,
            banner: Vec::with_capacity(SSH_MAX_BANNER_LEN),
        }
    }

    fn parse_banner(&mut self, input: &[u8]) -> bool {
        match parser::ssh_parse_banner(input) {
            Ok((_, banner)) => {
                if self.banner.len() + banner.len() <= SSH_MAX_BANNER_LEN {
                    self.banner.extend(banner);
                    //remove final CR if any
                    if self.banner.last() == Some(&13) {
                        self.banner.pop();
                    }
                } else if self.banner.len() < SSH_MAX_BANNER_LEN {
                    self.banner
                        .extend(&banner[0..SSH_MAX_BANNER_LEN - self.banner.len()]);
                }
                self.flags = SSHTxFlag::SSH_FLAG_VERSION_PARSED;
                //TODO parse remaining bytes
                return true;
            }
            Err(nom::Err::Incomplete(_)) => {
                if self.banner.len() + input.len() <= SSH_MAX_BANNER_LEN {
                    self.banner.extend(input);
                } else if self.banner.len() < SSH_MAX_BANNER_LEN {
                    self.banner
                        .extend(&input[0..SSH_MAX_BANNER_LEN - self.banner.len()]);
                }
                return true;
            }
            Err(_) => {
                //TODO self.set_event(SSHEvent::InvalidData);
                return false;
            }
        }
    }
}

pub struct SSHTransaction {
    pub srv_hdr: SshHeader,
    pub cli_hdr: SshHeader,

    logged: LoggerFlags,
    de_state: Option<*mut core::DetectEngineState>,
    detect_flags: TxDetectFlags,
}

impl SSHTransaction {
    pub fn new() -> SSHTransaction {
        SSHTransaction {
            srv_hdr: SshHeader::new(),
            cli_hdr: SshHeader::new(),
            logged: LoggerFlags::new(),
            de_state: None,
            detect_flags: TxDetectFlags::default(),
        }
    }

    pub fn free(&mut self) {
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

    fn parse_request(&mut self, input: &[u8]) -> bool {
        // We're not interested in empty requests.
        if input.len() < 4 {
            return false;
        }

        self.transaction.cli_hdr.pkt_len = 1;

        return true;
    }
}

// C exports.

export_tx_get_detect_state!(rs_ssh_tx_get_detect_state, SSHTransaction);
export_tx_set_detect_state!(rs_ssh_tx_set_detect_state, SSHTransaction);

export_tx_detect_flags_set!(rs_ssh_set_tx_detect_flags, SSHTransaction);
export_tx_detect_flags_get!(rs_ssh_get_tx_detect_flags, SSHTransaction);

/// C entry point for a probing parser.
#[no_mangle]
pub extern "C" fn rs_dummy_probing_parser(
    _flow: *const Flow,
    _direction: u8,
    _input: *const u8,
    _input_len: u32,
    _rdir: *mut u8,
) -> AppProto {
    return ALPROTO_UNKNOWN;
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
    _pstate: *mut std::os::raw::c_void,
    input: *const u8,
    input_len: u32,
    _data: *const std::os::raw::c_void,
    _flags: u8,
) -> i32 {
    let state = cast_pointer!(state, SSHState);
    let buf = build_slice!(input, input_len as usize);
    let hdr = &mut state.transaction.cli_hdr;
    if !(hdr.flags.contains(SSHTxFlag::SSH_FLAG_VERSION_PARSED)) {
        if hdr.parse_banner(buf) {
            return 1;
        }
    } else {
        //TODO
        if state.parse_request(buf) {
            return 1;
        }
    }
    return -1;
}

#[no_mangle]
pub extern "C" fn rs_ssh_parse_response(
    _flow: *const Flow,
    state: *mut std::os::raw::c_void,
    _pstate: *mut std::os::raw::c_void,
    input: *const u8,
    input_len: u32,
    _data: *const std::os::raw::c_void,
    _flags: u8,
) -> i32 {
    let state = cast_pointer!(state, SSHState);
    let buf = build_slice!(input, input_len as usize);
    if state.parse_request(buf) {
        return 1;
    }
    return -1;
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
pub extern "C" fn rs_ssh_tx_get_alstate_progress(
    tx: *mut std::os::raw::c_void,
    direction: u8,
) -> std::os::raw::c_int {
    let tx = cast_pointer!(tx, SSHTransaction);

    if tx.cli_hdr.flags.contains(SSHTxFlag::SSH_FLAG_PARSER_DONE)
        && tx.srv_hdr.flags.contains(SSHTxFlag::SSH_FLAG_PARSER_DONE)
    {
        return SSHConnectionState::SshStateFinished as i32;
    }

    if direction == STREAM_TOSERVER {
        if tx
            .cli_hdr
            .flags
            .contains(SSHTxFlag::SSH_FLAG_VERSION_PARSED)
        {
            return SSHConnectionState::SshStateBannerDone as i32;
        }
    } else {
        if tx
            .srv_hdr
            .flags
            .contains(SSHTxFlag::SSH_FLAG_VERSION_PARSED)
        {
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
        probe_ts: rs_dummy_probing_parser,
        probe_tc: rs_dummy_probing_parser,
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
        get_events: None,
        get_eventinfo: None,
        get_eventinfo_byid: None,
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
