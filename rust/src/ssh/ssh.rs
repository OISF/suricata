/* Copyright (C) 2020-2025 Open Information Security Foundation
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
use crate::core::*;
use crate::direction::Direction;
use crate::flow::Flow;
use crate::frames::Frame;
use nom8::Err;
use std::ffi::CString;
use std::sync::atomic::{AtomicBool, Ordering};
use suricata_sys::sys::{
    AppLayerParserState, AppProto, SCAppLayerParserConfParserEnabled,
    SCAppLayerParserRegisterLogger, SCAppLayerParserStateSetFlag,
    SCAppLayerProtoDetectConfProtoDetectionEnabled,
};

#[repr(C)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[allow(non_camel_case_types)]
pub enum SshEncryptionHandling {
    SSH_HANDLE_ENCRYPTION_TRACK_ONLY = 0, // Disable raw content inspection, continue tracking
    SSH_HANDLE_ENCRYPTION_BYPASS = 1,     // Skip processing of flow, bypass if possible
    SSH_HANDLE_ENCRYPTION_FULL = 2,       // Handle fully like any other protocol
}

static mut ALPROTO_SSH: AppProto = ALPROTO_UNKNOWN;
static HASSH_ENABLED: AtomicBool = AtomicBool::new(false);

static mut ENCRYPTION_BYPASS_ENABLED: SshEncryptionHandling =
    SshEncryptionHandling::SSH_HANDLE_ENCRYPTION_TRACK_ONLY;

fn hassh_is_enabled() -> bool {
    HASSH_ENABLED.load(Ordering::Relaxed)
}

fn encryption_bypass_mode() -> SshEncryptionHandling {
    unsafe { ENCRYPTION_BYPASS_ENABLED }
}

#[derive(AppLayerFrameType)]
pub enum SshFrameType {
    RecordHdr,
    RecordData,
    RecordPdu,
}

#[derive(AppLayerEvent)]
pub enum SSHEvent {
    InvalidBanner,
    LongBanner,
    InvalidRecord,
    LongKexRecord,
}

#[repr(u8)]
#[derive(AppLayerState, Copy, Clone, PartialOrd, PartialEq, Eq)]
#[suricata(alstate_strip_prefix = "SshState")]
pub enum SSHConnectionState {
    SshStateInProgress = 0,
    SshStateBannerWaitEol = 1,
    SshStateBannerDone = 2,
    SshStateFinished = 3,
}

pub const SSH_MAX_BANNER_LEN: usize = 256;
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

impl Default for SshHeader {
    fn default() -> Self {
        Self::new()
    }
}

impl SshHeader {
    pub fn new() -> SshHeader {
        Self {
            record_left: 0,
            record_left_msg: parser::MessageCode::Undefined(0),

            flags: SSHConnectionState::SshStateInProgress,
            protover: Vec::new(),
            swver: Vec::new(),

            hassh: Vec::new(),
            hassh_string: Vec::new(),
        }
    }
}

#[derive(Default)]
pub struct SSHTransaction {
    pub srv_hdr: SshHeader,
    pub cli_hdr: SshHeader,

    tx_data: AppLayerTxData,
}

#[derive(Default)]
pub struct SSHState {
    state_data: AppLayerStateData,
    transaction: SSHTransaction,
}

impl SSHState {
    pub fn new() -> Self {
        Default::default()
    }

    fn set_event(&mut self, event: SSHEvent) {
        self.transaction.tx_data.set_event(event as u8);
    }

    fn parse_record(
        &mut self, mut input: &[u8], resp: bool, pstate: *mut AppLayerParserState,
        flow: *mut Flow, stream_slice: &StreamSlice,
    ) -> AppLayerResult {
        let (hdr, ohdr) = if !resp {
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
                    parser::MessageCode::Kexinit if hassh_is_enabled() => {
                        if let Ok((_rem, key_exchange)) =
                            parser::ssh_parse_key_exchange(&input[..start])
                        {
                            key_exchange.generate_hassh(
                                &mut hdr.hassh_string,
                                &mut hdr.hassh,
                                &resp,
                            );
                        }
                        hdr.record_left_msg = parser::MessageCode::Undefined(0);
                    }
                    _ => {}
                }
                input = &input[start..];
                hdr.record_left = 0;
            }
        }
        //parse records out of input
        while !input.is_empty() {
            match parser::ssh_parse_record(input) {
                Ok((rem, head)) => {
                    let _pdu = Frame::new(
                        flow,
                        stream_slice,
                        input,
                        SSH_RECORD_HEADER_LEN as i64,
                        SshFrameType::RecordHdr as u8,
                        Some(0),
                    );
                    let _pdu = Frame::new(
                        flow,
                        stream_slice,
                        &input[SSH_RECORD_HEADER_LEN..],
                        (head.pkt_len - 2) as i64,
                        SshFrameType::RecordData as u8,
                        Some(0),
                    );
                    let _pdu = Frame::new(
                        flow,
                        stream_slice,
                        input,
                        (head.pkt_len + 4) as i64,
                        SshFrameType::RecordPdu as u8,
                        Some(0),
                    );
                    SCLogDebug!("SSH valid record {}", head);
                    match head.msg_code {
                        parser::MessageCode::Kexinit if hassh_is_enabled() => {
                            //let endkex = SSH_RECORD_HEADER_LEN + head.pkt_len - 2;
                            let endkex = input.len() - rem.len();
                            if let Ok((_, key_exchange)) = parser::ssh_parse_key_exchange(
                                &input[SSH_RECORD_HEADER_LEN..endkex],
                            ) {
                                key_exchange.generate_hassh(
                                    &mut hdr.hassh_string,
                                    &mut hdr.hassh,
                                    &resp,
                                );
                            }
                        }
                        parser::MessageCode::NewKeys => {
                            hdr.flags = SSHConnectionState::SshStateFinished;
                            if ohdr.flags >= SSHConnectionState::SshStateFinished {
                                let mut flags = 0;

                                match encryption_bypass_mode() {
                                    SshEncryptionHandling::SSH_HANDLE_ENCRYPTION_BYPASS => {
                                        flags |= APP_LAYER_PARSER_NO_INSPECTION
                                            | APP_LAYER_PARSER_NO_REASSEMBLY
                                            | APP_LAYER_PARSER_BYPASS_READY;
                                    }
                                    SshEncryptionHandling::SSH_HANDLE_ENCRYPTION_TRACK_ONLY => {
                                        flags |= APP_LAYER_PARSER_NO_INSPECTION;
                                    }
                                    _ => {}
                                }

                                if flags != 0 {
                                    unsafe {
                                        SCAppLayerParserStateSetFlag(pstate, flags);
                                    }
                                }
                            }
                        }
                        _ => {}
                    }

                    input = rem;
                    //header and complete data (not returned)
                }
                Err(Err::Incomplete(_)) => {
                    match parser::ssh_parse_record_header(input) {
                        Ok((rem, head)) => {
                            let _pdu = Frame::new(
                                flow,
                                stream_slice,
                                input,
                                SSH_RECORD_HEADER_LEN as i64,
                                SshFrameType::RecordHdr as u8,
                                Some(0),
                            );
                            let _pdu = Frame::new(
                                flow,
                                stream_slice,
                                &input[SSH_RECORD_HEADER_LEN..],
                                (head.pkt_len - 2) as i64,
                                SshFrameType::RecordData as u8,
                                Some(0),
                            );
                            let _pdu = Frame::new(
                                flow,
                                stream_slice,
                                input,
                                // cast first to avoid unsigned integer overflow
                                (head.pkt_len as u64 + 4) as i64,
                                SshFrameType::RecordPdu as u8,
                                Some(0),
                            );
                            SCLogDebug!("SSH valid record header {}", head);
                            let remlen = rem.len() as u32;
                            hdr.record_left = head.pkt_len - 2 - remlen;
                            //header with rem as incomplete data
                            match head.msg_code {
                                parser::MessageCode::NewKeys => {
                                    hdr.flags = SSHConnectionState::SshStateFinished;
                                }
                                parser::MessageCode::Kexinit if hassh_is_enabled() => {
                                    // check if buffer is bigger than maximum reassembled packet size
                                    hdr.record_left = head.pkt_len - 2;
                                    if hdr.record_left < SSH_MAX_REASSEMBLED_RECORD_LEN as u32 {
                                        // saving type of incomplete kex message
                                        hdr.record_left_msg = parser::MessageCode::Kexinit;
                                        return AppLayerResult::incomplete(
                                            (il - rem.len()) as u32,
                                            head.pkt_len - 2,
                                        );
                                    } else {
                                        SCLogDebug!("SSH buffer is bigger than maximum reassembled packet size");
                                        self.set_event(SSHEvent::LongKexRecord);
                                    }
                                }
                                _ => {}
                            }
                            return AppLayerResult::ok();
                        }
                        Err(Err::Incomplete(_)) => {
                            //we may have consumed data from previous records
                            debug_validate_bug_on!(input.len() >= SSH_RECORD_HEADER_LEN);
                            //do not trust nom incomplete value
                            return AppLayerResult::incomplete(
                                (il - input.len()) as u32,
                                SSH_RECORD_HEADER_LEN as u32,
                            );
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
        &mut self, input: &[u8], resp: bool, pstate: *mut AppLayerParserState, flow: *mut Flow,
        stream_slice: &StreamSlice,
    ) -> AppLayerResult {
        let hdr = if !resp {
            &mut self.transaction.cli_hdr
        } else {
            &mut self.transaction.srv_hdr
        };
        if hdr.flags == SSHConnectionState::SshStateBannerWaitEol {
            match parser::ssh_parse_line(input) {
                Ok((rem, _)) => {
                    let mut r = self.parse_record(rem, resp, pstate, flow, stream_slice);
                    if r.is_incomplete() {
                        //adds bytes consumed by banner to incomplete result
                        r.consumed += (input.len() - rem.len()) as u32;
                    } else if r.is_ok() {
                        let mut dir = Direction::ToServer as i32;
                        if resp {
                            dir = Direction::ToClient as i32;
                        }
                        sc_app_layer_parser_trigger_raw_stream_inspection(flow, dir);
                    }
                    return r;
                }
                Err(Err::Incomplete(_)) => {
                    // we do not need to retain these bytes
                    // we parsed them, we skip them
                    return AppLayerResult::ok();
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
                    if !banner.swver.is_empty() {
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
                let mut r = self.parse_record(rem, resp, pstate, flow, stream_slice);
                if r.is_incomplete() {
                    //adds bytes consumed by banner to incomplete result
                    r.consumed += (input.len() - rem.len()) as u32;
                } else if r.is_ok() {
                    let mut dir = Direction::ToServer as i32;
                    if resp {
                        dir = Direction::ToClient as i32;
                    }
                    sc_app_layer_parser_trigger_raw_stream_inspection(flow, dir);
                }
                return r;
            }
            Err(Err::Incomplete(_)) => {
                // see https://github.com/rust-lang/rust-clippy/issues/15158
                #[allow(clippy::collapsible_else_if)]
                if input.len() < SSH_MAX_BANNER_LEN {
                    //0 consumed, needs at least one more byte
                    return AppLayerResult::incomplete(0_u32, (input.len() + 1) as u32);
                } else {
                    SCLogDebug!(
                        "SSH banner too long {} vs {} and waiting for eol",
                        input.len(),
                        SSH_MAX_BANNER_LEN
                    );
                    if let Ok((_, banner)) = parser::ssh_parse_banner(input) {
                        hdr.protover.extend(banner.protover);
                        if !banner.swver.is_empty() {
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

export_tx_data_get!(ssh_get_tx_data, SSHTransaction);
export_state_data_get!(ssh_get_state_data, SSHState);

extern "C" fn ssh_state_new(
    _orig_state: *mut std::os::raw::c_void, _orig_proto: AppProto,
) -> *mut std::os::raw::c_void {
    let state = SSHState::new();
    let boxed = Box::new(state);
    return Box::into_raw(boxed) as *mut _;
}

unsafe extern "C" fn ssh_state_free(state: *mut std::os::raw::c_void) {
    std::mem::drop(Box::from_raw(state as *mut SSHState));
}

extern "C" fn ssh_state_tx_free(_state: *mut std::os::raw::c_void, _tx_id: u64) {
    //do nothing
}

unsafe extern "C" fn ssh_parse_request(
    flow: *mut Flow, state: *mut std::os::raw::c_void, pstate: *mut AppLayerParserState,
    stream_slice: StreamSlice, _data: *const std::os::raw::c_void,
) -> AppLayerResult {
    let state = &mut cast_pointer!(state, SSHState);
    let buf = stream_slice.as_slice();
    let hdr = &mut state.transaction.cli_hdr;
    state.transaction.tx_data.updated_ts = true;
    if hdr.flags < SSHConnectionState::SshStateBannerDone {
        return state.parse_banner(buf, false, pstate, flow, &stream_slice);
    } else {
        return state.parse_record(buf, false, pstate, flow, &stream_slice);
    }
}

unsafe extern "C" fn ssh_parse_response(
    flow: *mut Flow, state: *mut std::os::raw::c_void, pstate: *mut AppLayerParserState,
    stream_slice: StreamSlice, _data: *const std::os::raw::c_void,
) -> AppLayerResult {
    let state = &mut cast_pointer!(state, SSHState);
    let buf = stream_slice.as_slice();
    let hdr = &mut state.transaction.srv_hdr;
    state.transaction.tx_data.updated_tc = true;
    if hdr.flags < SSHConnectionState::SshStateBannerDone {
        return state.parse_banner(buf, true, pstate, flow, &stream_slice);
    } else {
        return state.parse_record(buf, true, pstate, flow, &stream_slice);
    }
}

#[no_mangle]
pub unsafe extern "C" fn SCSshStateGetTx(
    state: *mut std::os::raw::c_void, _tx_id: u64,
) -> *mut std::os::raw::c_void {
    let state = cast_pointer!(state, SSHState);
    return &state.transaction as *const _ as *mut _;
}

extern "C" fn ssh_state_get_tx_count(_state: *mut std::os::raw::c_void) -> u64 {
    return 1;
}

#[no_mangle]
pub unsafe extern "C" fn SCSshTxGetFlags(
    tx: *mut std::os::raw::c_void, direction: u8,
) -> SSHConnectionState {
    let tx = cast_pointer!(tx, SSHTransaction);
    if direction == u8::from(Direction::ToServer) {
        return tx.cli_hdr.flags;
    } else {
        return tx.srv_hdr.flags;
    }
}

#[no_mangle]
pub unsafe extern "C" fn SCSshTxGetAlStateProgress(
    tx: *mut std::os::raw::c_void, direction: u8,
) -> std::os::raw::c_int {
    let tx = cast_pointer!(tx, SSHTransaction);

    if tx.cli_hdr.flags >= SSHConnectionState::SshStateFinished
        && tx.srv_hdr.flags >= SSHConnectionState::SshStateFinished
    {
        return SSHConnectionState::SshStateFinished as i32;
    }

    if direction == u8::from(Direction::ToServer) {
        if tx.cli_hdr.flags >= SSHConnectionState::SshStateBannerDone {
            return SSHConnectionState::SshStateBannerDone as i32;
        }
    } else if tx.srv_hdr.flags >= SSHConnectionState::SshStateBannerDone {
        return SSHConnectionState::SshStateBannerDone as i32;
    }

    return SSHConnectionState::SshStateInProgress as i32;
}

// Parser name as a C style string.
const PARSER_NAME: &[u8] = b"ssh\0";

#[no_mangle]
pub unsafe extern "C" fn SCRegisterSshParser() {
    let parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const std::os::raw::c_char,
        default_port: std::ptr::null(),
        ipproto: IPPROTO_TCP,
        //simple patterns, no probing
        probe_ts: None,
        probe_tc: None,
        min_depth: 0,
        max_depth: 0,
        state_new: ssh_state_new,
        state_free: ssh_state_free,
        tx_free: ssh_state_tx_free,
        parse_ts: ssh_parse_request,
        parse_tc: ssh_parse_response,
        get_tx_count: ssh_state_get_tx_count,
        get_tx: SCSshStateGetTx,
        tx_comp_st_ts: SSHConnectionState::SshStateFinished as i32,
        tx_comp_st_tc: SSHConnectionState::SshStateFinished as i32,
        tx_get_progress: SCSshTxGetAlStateProgress,
        get_eventinfo: Some(SSHEvent::get_event_info),
        get_eventinfo_byid: Some(SSHEvent::get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_tx_files: None,
        get_tx_iterator: None,
        get_tx_data: ssh_get_tx_data,
        get_state_data: ssh_get_state_data,
        apply_tx_config: None,
        flags: 0,
        get_frame_id_by_name: Some(SshFrameType::ffi_id_from_name),
        get_frame_name_by_id: Some(SshFrameType::ffi_name_from_id),
        get_state_id_by_name: Some(SSHConnectionState::ffi_id_from_name),
        get_state_name_by_id: Some(SSHConnectionState::ffi_name_from_id),
    };

    let ip_proto_str = CString::new("tcp").unwrap();

    if SCAppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_SSH = alproto;
        if SCAppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
        SCAppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_SSH);
        SCLogDebug!("Rust ssh parser registered.");
    } else {
        SCLogNotice!("Protocol detector and parser disabled for SSH.");
    }
}

#[no_mangle]
pub extern "C" fn SCSshEnableHassh() {
    HASSH_ENABLED.store(true, Ordering::Relaxed)
}

#[no_mangle]
pub extern "C" fn SCSshHasshIsEnabled() -> bool {
    hassh_is_enabled()
}

#[no_mangle]
pub extern "C" fn SCSshEnableBypass(mode: SshEncryptionHandling) {
    unsafe {
        ENCRYPTION_BYPASS_ENABLED = mode;
    }
}

#[no_mangle]
pub unsafe extern "C" fn SCSshTxGetLogCondition(tx: *mut std::os::raw::c_void) -> bool {
    let tx = cast_pointer!(tx, SSHTransaction);

    if SCSshHasshIsEnabled() {
        if tx.cli_hdr.flags == SSHConnectionState::SshStateFinished
            && tx.srv_hdr.flags == SSHConnectionState::SshStateFinished
        {
            return true;
        }
    } else if tx.cli_hdr.flags == SSHConnectionState::SshStateBannerDone
        && tx.srv_hdr.flags == SSHConnectionState::SshStateBannerDone
    {
        return true;
    }
    return false;
}
