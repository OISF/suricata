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
use crate::encryption::EncryptionHandling;
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

pub(super) static mut ALPROTO_SSH: AppProto = ALPROTO_UNKNOWN;
static HASSH_ENABLED: AtomicBool = AtomicBool::new(false);
static HASSH_DISABLED: AtomicBool = AtomicBool::new(false);

static mut ENCRYPTION_BYPASS_ENABLED: EncryptionHandling =
    EncryptionHandling::ENCRYPTION_HANDLING_TRACK_ONLY;

fn hassh_is_enabled() -> bool {
    HASSH_ENABLED.load(Ordering::Relaxed)
}

fn encryption_bypass_mode() -> EncryptionHandling {
    unsafe { ENCRYPTION_BYPASS_ENABLED }
}

// Arms the no-inspection/bypass flags on the session transition,
// shared by the complete-record and incomplete-header arms: a
// NewKeys record whose body arrives in a later parser call must
// reach the same decision - the record header already identifies
// the key switch. The peer check keeps a merely-failed peer from
// arming the flags.
fn ssh_arm_session_flags(ohdr_state: SSHConnectionState, pstate: *mut AppLayerParserState) {
    if ohdr_state < SSHConnectionState::SshStateSession {
        return;
    }
    let mut flags = 0;
    match encryption_bypass_mode() {
        EncryptionHandling::ENCRYPTION_HANDLING_BYPASS => {
            flags |= APP_LAYER_PARSER_NO_INSPECTION
                | APP_LAYER_PARSER_NO_REASSEMBLY
                | APP_LAYER_PARSER_BYPASS_READY;
        }
        EncryptionHandling::ENCRYPTION_HANDLING_TRACK_ONLY => {
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

/// Unrecoverable parse failure per direction. Set at the failure
/// sites alongside the failure event; never cleared. The failed
/// direction is frozen in the state the error occurred in.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum SSHError {
    InvalidBanner,
    InvalidRecord,
}

/// Per-direction phases; the value doubles as the detection progress
/// (progress changes when the processing of the next state begins).
/// SshStateDone is the registered completion state and is never
/// reported: a successful direction tops out at SshStateSession, and
/// a failed direction is frozen in the state the unrecoverable parse
/// error occurred in (the parse entry guards on the error flag). It
/// stays out of both name tables (not hookable, not listed, not a
/// firewall policy key); the failure is exposed via app-layer
/// events.
#[repr(u8)]
#[derive(AppLayerState, Copy, Clone, PartialOrd, PartialEq, Eq)]
#[suricata(alstate_strip_prefix = "SshState")]
pub enum SSHConnectionState {
    SshStateBanner = 0,
    SshStateBannerWaitEol = 1,
    SshStateKex = 2,
    SshStateSession = 3,
    SshStateDone = 4,
}

pub const SSH_MAX_BANNER_LEN: usize = 256;
const SSH_RECORD_HEADER_LEN: usize = 6;
const SSH_MAX_REASSEMBLED_RECORD_LEN: usize = 65535;

pub struct SshHeader {
    record_left: u32,
    record_left_msg: parser::MessageCode,

    pub state: SSHConnectionState,
    pub protover: Vec<u8>,
    pub swver: Vec<u8>,
    pub error: Option<SSHError>,

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

            state: SSHConnectionState::SshStateBanner,
            protover: Vec::new(),
            swver: Vec::new(),
            error: None,

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
        &mut self, mut input: &[u8], resp: bool, pstate: *mut AppLayerParserState, flow: *mut Flow,
        stream_slice: &StreamSlice,
    ) -> AppLayerResult {
        let (hdr, ohdr) = if !resp {
            (&mut self.transaction.cli_hdr, &self.transaction.srv_hdr)
        } else {
            (&mut self.transaction.srv_hdr, &self.transaction.cli_hdr)
        };
        let il = input.len();
        // first skip record left bytes; a buffer shorter than the
        // pending record is absorbed into the stash. The parse entry
        // does not pre-check this case (nor the leading header
        // fragment, handled by the Incomplete arm below): both return
        // the same AppLayerResult as the entry short-circuit would,
        // and only this site must stay in sync with the record_left
        // arithmetic
        if hdr.record_left > 0 {
            let ilen = input.len() as u32;
            if stash_record_bytes(&mut hdr.record_left, ilen) {
                return AppLayerResult::ok();
            }
            let start = hdr.record_left as usize;
            match hdr.record_left_msg {
                // parse reassembled tcp segments
                parser::MessageCode::Kexinit if hassh_is_enabled() => {
                    if let Ok((_rem, key_exchange)) =
                        parser::ssh_parse_key_exchange(&input[..start])
                    {
                        key_exchange.generate_hassh(&mut hdr.hassh_string, &mut hdr.hassh, &resp);
                    }
                    hdr.record_left_msg = parser::MessageCode::Undefined(0);
                }
                _ => {}
            }
            input = &input[start..];
            hdr.record_left = 0;
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
                        // a failed direction never gets here: it is
                        // frozen in the state it failed in
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
                            hdr.state = SSHConnectionState::SshStateSession;
                            ssh_arm_session_flags(ohdr.state, pstate);
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
                                    hdr.state = SSHConnectionState::SshStateSession;
                                    ssh_arm_session_flags(ohdr.state, pstate);
                                }
                                parser::MessageCode::Kexinit if hassh_is_enabled() => {
                                    // check if buffer is bigger than maximum reassembled packet size
                                    let body_len = head.pkt_len - 2;
                                    if body_len < SSH_MAX_REASSEMBLED_RECORD_LEN as u32 {
                                        // returning incomplete means the body bytes in rem are
                                        // not consumed and will be delivered again, so the whole
                                        // body has to be skipped on the next call
                                        hdr.record_left = body_len;
                                        // saving type of incomplete kex message
                                        hdr.record_left_msg = parser::MessageCode::Kexinit;
                                        return AppLayerResult::incomplete(
                                            (il - rem.len()) as u32,
                                            body_len,
                                        );
                                    } else {
                                        // returning ok consumes the body bytes in rem, so keep
                                        // record_left = body_len - remlen computed above
                                        SCLogDebug!("SSH buffer is bigger than maximum reassembled packet size");
                                        self.set_event(SSHEvent::LongKexRecord);
                                    }
                                }
                                _ => {}
                            }
                            return AppLayerResult::ok();
                        }
                        Err(Err::Incomplete(_)) => {
                            // the buffer ran out between records in
                            // this call; do not trust nom's
                            // incomplete value. The header parser only
                            // reports Incomplete when fewer than
                            // SSH_RECORD_HEADER_LEN bytes remain, so
                            // this asserts the arm's branch
                            // precondition (a later parse change that
                            // makes it reachable with a full header
                            // aborts debug builds)
                            debug_validate_bug_on!(input.len() >= SSH_RECORD_HEADER_LEN);
                            return AppLayerResult::incomplete(
                                (il - input.len()) as u32,
                                SSH_RECORD_HEADER_LEN as u32,
                            );
                        }
                        Err(_e) => {
                            SCLogDebug!("SSH invalid record header {}", _e);
                            hdr.error = Some(SSHError::InvalidRecord);
                            self.set_event(SSHEvent::InvalidRecord);
                            return AppLayerResult::err();
                        }
                    }
                }
                Err(_e) => {
                    SCLogDebug!("SSH invalid record {}", _e);
                    hdr.error = Some(SSHError::InvalidRecord);
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
        if hdr.state == SSHConnectionState::SshStateBannerWaitEol {
            match parser::ssh_parse_line(input) {
                Ok((rem, _)) => {
                    // line complete: the banner data was parsed at
                    // entry, this only takes the direction to kex
                    hdr.state = SSHConnectionState::SshStateKex;
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
                    hdr.error = Some(SSHError::InvalidBanner);
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
                    hdr.state = SSHConnectionState::SshStateKex;
                } else {
                    SCLogDebug!("SSH invalid banner");
                    hdr.error = Some(SSHError::InvalidBanner);
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
                        hdr.state = SSHConnectionState::SshStateBannerWaitEol;
                        self.set_event(SSHEvent::LongBanner);
                        return AppLayerResult::ok();
                    } else {
                        hdr.error = Some(SSHError::InvalidBanner);
                        self.set_event(SSHEvent::InvalidBanner);
                        return AppLayerResult::err();
                    }
                }
            }
            Err(_e) => {
                SCLogDebug!("SSH invalid banner {}", _e);
                hdr.error = Some(SSHError::InvalidBanner);
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

/// Absorb `ilen` bytes into the pending-record stash. True if the
/// whole chunk was stashed (nothing was parsed).
fn stash_record_bytes(record_left: &mut u32, ilen: u32) -> bool {
    if *record_left > ilen {
        *record_left -= ilen;
        true
    } else {
        false
    }
}

unsafe extern "C" fn ssh_parse_request(
    flow: *mut Flow, state: *mut std::os::raw::c_void, pstate: *mut AppLayerParserState,
    stream_slice: StreamSlice, _data: *mut std::os::raw::c_void,
) -> AppLayerResult {
    let state = &mut cast_pointer!(state, SSHState);
    let buf = stream_slice.as_slice();
    let hdr = &mut state.transaction.cli_hdr;

    // A failed direction is frozen in the state it failed in: the
    // failure is unrecoverable, so no further parsing, no state
    // change. The end state the progress accessor reports is the
    // state it failed in.
    if hdr.error.is_some() {
        return AppLayerResult::ok();
    }
    // Mark the tx updated at parse entry, as the base parser did:
    // every delivery - including the short-circuits below that
    // publish nothing - is decided by the state rules and the
    // firewall default-policy sweep rather than the firewall
    // default-accept.
    state.transaction.tx_data.0.updated_ts = true;

    let r = if hdr.state < SSHConnectionState::SshStateKex {
        state.parse_banner(buf, false, pstate, flow, &stream_slice)
    } else {
        state.parse_record(buf, false, pstate, flow, &stream_slice)
    };
    return r;
}

unsafe extern "C" fn ssh_parse_response(
    flow: *mut Flow, state: *mut std::os::raw::c_void, pstate: *mut AppLayerParserState,
    stream_slice: StreamSlice, _data: *mut std::os::raw::c_void,
) -> AppLayerResult {
    let state = &mut cast_pointer!(state, SSHState);
    let buf = stream_slice.as_slice();
    let hdr = &mut state.transaction.srv_hdr;

    // See ssh_parse_request for the failure freeze and the updated
    // flag.
    if hdr.error.is_some() {
        return AppLayerResult::ok();
    }
    state.transaction.tx_data.0.updated_tc = true;

    let r = if hdr.state < SSHConnectionState::SshStateKex {
        state.parse_banner(buf, true, pstate, flow, &stream_slice)
    } else {
        state.parse_record(buf, true, pstate, flow, &stream_slice)
    };
    return r;
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
        return tx.cli_hdr.state;
    } else {
        return tx.srv_hdr.state;
    }
}

#[no_mangle]
pub unsafe extern "C" fn SCSshTxGetAlStateProgress(
    tx: *mut std::os::raw::c_void, direction: u8,
) -> std::os::raw::c_int {
    let tx = cast_pointer!(tx, SSHTransaction);
    // per-direction: each direction reports its own phase. No direction
    // reports the completion state (maximum is session; a failed
    // direction is frozen in the state it failed in), so a live tx
    // stays inspectable until flow end
    let progress = if direction == u8::from(Direction::ToServer) {
        tx.cli_hdr.state
    } else {
        tx.srv_hdr.state
    };
    return progress as i32;
}

// State name tables for rule hooks. "done" is intentionally absent
// from both name tables: no direction ever reports it (success
// tops out at session; failure keeps the state the error occurred
// in - banner, kex, or session), so a hook on it would be dead
// configuration; the hook listing, the firewall policy key walk
// and the rule-engine lookups must all agree it is not a state
// name (the id-to-name lookup returns null for it).
unsafe extern "C" fn ssh_state_id_by_name(
    name: *const std::os::raw::c_char, dir: u8,
) -> std::os::raw::c_int {
    if name.is_null() {
        return -1;
    }
    let Ok(s) = std::ffi::CStr::from_ptr(name).to_str() else {
        return -1;
    };
    let s2 = match Direction::from(dir) {
        Direction::ToServer => {
            if !s.starts_with("request_") {
                return -1;
            }
            &s["request_".len()..]
        }
        Direction::ToClient => {
            if !s.starts_with("response_") {
                return -1;
            }
            &s["response_".len()..]
        }
    };
    match s2 {
        "banner" => SSHConnectionState::SshStateBanner as i32,
        "banner_wait_eol" => SSHConnectionState::SshStateBannerWaitEol as i32,
        "kex" => SSHConnectionState::SshStateKex as i32,
        "session" => SSHConnectionState::SshStateSession as i32,
        _ => -1,
    }
}

extern "C" fn ssh_state_name_by_id(
    id: std::os::raw::c_int, dir: u8,
) -> *const std::os::raw::c_char {
    // process-lifetime statics
    static NAMES_TS: [&[u8]; 4] = [
        b"request_banner\0",
        b"request_banner_wait_eol\0",
        b"request_kex\0",
        b"request_session\0",
    ];
    static NAMES_TC: [&[u8]; 4] = [
        b"response_banner\0",
        b"response_banner_wait_eol\0",
        b"response_kex\0",
        b"response_session\0",
    ];
    let names = if dir == u8::from(Direction::ToServer) {
        &NAMES_TS
    } else {
        &NAMES_TC
    };
    // the completion state stays out of the id-to-name table as well,
    // so the hook listing and the firewall policy key walk see the
    // same surface as the name-to-id table
    match id {
        0..=3 => names[id as usize].as_ptr() as *const std::os::raw::c_char,
        _ => std::ptr::null(),
    }
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
        tx_comp_st_ts: SSHConnectionState::SshStateDone as i32,
        tx_comp_st_tc: SSHConnectionState::SshStateDone as i32,
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
        get_state_id_by_name: Some(ssh_state_id_by_name),
        get_state_name_by_id: Some(ssh_state_name_by_id),
    };

    let ip_proto_str = CString::new("tcp").unwrap();

    if SCAppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = applayer_register_protocol_detection(&parser, 1);
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
    if !HASSH_DISABLED.load(Ordering::Relaxed) {
        HASSH_ENABLED.store(true, Ordering::Relaxed)
    }
}

#[no_mangle]
pub extern "C" fn SCSshHasshIsEnabled() -> bool {
    hassh_is_enabled()
}

#[no_mangle]
pub extern "C" fn SCSshDisableHassh() {
    HASSH_DISABLED.store(true, Ordering::Relaxed)
}

#[no_mangle]
pub extern "C" fn SCSshEnableBypass(mode: EncryptionHandling) {
    unsafe {
        ENCRYPTION_BYPASS_ENABLED = mode;
    }
}

#[no_mangle]
pub unsafe extern "C" fn SCSshTxGetLogCondition(tx: *mut std::os::raw::c_void) -> bool {
    let tx = cast_pointer!(tx, SSHTransaction);

    // Failure-only: the tx logger is one-shot (the engine's logged
    // bit is never reset), and a successful handshake reaches kex
    // long before a later failure can occur, so a mid-flow success
    // condition would consume the log before the failure could be
    // reported. The failure latches, so the object is emitted
    // exactly once - at the failure, carrying the error and the
    // frozen state - and successful flows are logged at the
    // flow-end flush, where the engine logs unconditionally.
    tx.cli_hdr.error.is_some() || tx.srv_hdr.error.is_some()
}
