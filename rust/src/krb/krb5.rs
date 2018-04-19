/* Copyright (C) 2017-2018 Open Information Security Foundation
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

use libc;
use std;
use std::ffi::{CStr,CString};
use nom::{IResult,be_u32};
use der_parser::der_read_element_header;
use kerberos_parser::krb5_parser;
use kerberos_parser::krb5::{EncryptionType,MessageType,PrincipalName,Realm};
use applayer;
use core;
use core::{AppProto,Flow,ALPROTO_FAILED,ALPROTO_UNKNOWN,STREAM_TOCLIENT,STREAM_TOSERVER,sc_detect_engine_state_free};
use conf::conf_get_bool;
use parser::*;

use log::*;

#[repr(u32)]
pub enum KRB5Event {
    MalformedData = 0,
    WeakCrypto,
}

pub struct KRB5State {
    pub req_id: u8,

    /// Configuration option to warn user on weak crypto
    pub log_weak_crypto: bool,

    /// List of transactions for this session
    transactions: Vec<KRB5Transaction>,

    /// tx counter for assigning incrementing id's to tx's
    tx_id: u64,
}

pub struct KRB5Transaction {
    /// The message type: AS-REQ, AS-REP, etc.
    pub msg_type: MessageType,

    /// The client PrincipalName, if present
    pub cname: Option<PrincipalName>,
    /// The server Realm, if present
    pub realm: Option<Realm>,
    /// The server PrincipalName, if present
    pub sname: Option<PrincipalName>,

    /// Encryption used (only in AS-REP and TGS-REP)
    pub etype: Option<EncryptionType>,

    /// Error code, if request has failed
    pub error_code: Option<i32>,

    /// The internal transaction id
    id: u64,

    /// The detection engine state, if present
    de_state: Option<*mut core::DetectEngineState>,

    /// The events associated with this transaction
    events: *mut core::AppLayerDecoderEvents,

    logged: applayer::LoggerFlags,
}

pub fn to_hex_string(bytes: &[u8]) -> String {
    let mut s = String::new();
    for &b in bytes {
        s.push_str(&format!("{:02X}", b));
    }
    s
}

impl KRB5State {
    pub fn new() -> KRB5State {
        let l = conf_get_bool("app-layer.protocols.krb5.warn-weak-crypto");
        KRB5State{
            req_id: 0,
            log_weak_crypto: l,
            transactions: Vec::new(),
            tx_id: 0,
        }
    }

    /// Parse a Kerberos request message
    ///
    /// Returns The number of messages parsed, or -1 on error
    fn parse(&mut self, i: &[u8], _direction: u8) -> i8 {
        match der_read_element_header(i) {
            IResult::Done(_rem,hdr) => {
                // Kerberos messages start with an APPLICATION header
                if hdr.class != 0b01 { return 1; }
                match hdr.tag {
                    10 => {
                        self.req_id = hdr.tag;
                    },
                    11 => {
                        let res = krb5_parser::parse_as_rep(i);
                        res.map(|kdc_rep| {
                            let mut tx = self.new_tx();
                            tx.msg_type = MessageType::KRB_AS_REP;
                            tx.cname = Some(kdc_rep.cname);
                            tx.realm = Some(kdc_rep.crealm);
                            tx.sname = Some(kdc_rep.ticket.sname);
                            tx.etype = Some(kdc_rep.enc_part.etype);
                            self.transactions.push(tx);
                            self.check_crypto(kdc_rep.enc_part.etype);
                        });
                        self.req_id = 0;
                    },
                    12 => {
                        self.req_id = hdr.tag;
                    },
                    13 => {
                        let res = krb5_parser::parse_tgs_rep(i);
                        res.map(|kdc_rep| {
                            let mut tx = self.new_tx();
                            tx.msg_type = MessageType::KRB_TGS_REP;
                            tx.cname = Some(kdc_rep.cname);
                            tx.realm = Some(kdc_rep.crealm);
                            tx.sname = Some(kdc_rep.ticket.sname);
                            tx.etype = Some(kdc_rep.enc_part.etype);
                            self.transactions.push(tx);
                            self.check_crypto(kdc_rep.enc_part.etype);
                        });
                        self.req_id = 0;
                    },
                    14 => {
                        self.req_id = hdr.tag;
                    },
                    15 => {
                        self.req_id = 0;
                    },
                    30 => {
                        let res = krb5_parser::parse_krb_error(i);
                        res.map(|error| {
                            let mut tx = self.new_tx();
                            tx.msg_type = MessageType(self.req_id as u32);
                            tx.cname = error.cname;
                            tx.realm = error.crealm;
                            tx.sname = Some(error.sname);
                            tx.error_code = Some(error.error_code);
                            self.transactions.push(tx);
                        });
                        self.req_id = 0;
                    },
                    _ => { SCLogDebug!("unknown/unsupported tag {}", hdr.tag); },
                }
                0
            },
            IResult::Incomplete(_) => {
                SCLogDebug!("Insufficient data while parsing KRB5 data");
                self.set_event(KRB5Event::MalformedData);
                -1
            },
            IResult::Error(_) => {
                SCLogDebug!("Error while parsing KRB5 data");
                self.set_event(KRB5Event::MalformedData);
                -1
            },
        }
    }

    fn check_crypto(&mut self, alg:EncryptionType) {
        // this warning is configurable: it can generate lots of logs
        if !self.log_weak_crypto { return; }
        match alg {
            EncryptionType::AES128_CTS_HMAC_SHA1_96 |
            EncryptionType::AES256_CTS_HMAC_SHA1_96 |
            EncryptionType::AES128_CTS_HMAC_SHA256_128 |
            EncryptionType::AES256_CTS_HMAC_SHA384_192 |
            EncryptionType::CAMELLIA128_CTS_CMAC |
            EncryptionType::CAMELLIA256_CTS_CMAC => (),
            _ => { // all other ciphers are weak or deprecated
                SCLogDebug!("Kerberos5: weak encryption {:?}", alg);
                self.set_event(KRB5Event::WeakCrypto);
            }
        }
    }

    pub fn free(&mut self) {
        // All transactions are freed when the `transactions` object is freed.
        // But let's be explicit
        self.transactions.clear();
    }

    fn new_tx(&mut self) -> KRB5Transaction {
        self.tx_id += 1;
        KRB5Transaction::new(self.tx_id)
    }

    fn get_tx_by_id(&mut self, tx_id: u64) -> Option<&KRB5Transaction> {
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
    fn set_event(&mut self, event: KRB5Event) {
        if let Some(tx) = self.transactions.last_mut() {
            let ev = event as u8;
            core::sc_app_layer_decoder_events_set_event_raw(&mut tx.events, ev);
        }
    }
}

impl KRB5Transaction {
    pub fn new(id: u64) -> KRB5Transaction {
        KRB5Transaction{
            msg_type: MessageType(0),
            cname: None,
            realm: None,
            sname: None,
            etype: None,
            error_code: None,
            id: id,
            de_state: None,
            events: std::ptr::null_mut(),
            logged: applayer::LoggerFlags::new(),
        }
    }
}

impl Drop for KRB5Transaction {
    fn drop(&mut self) {
        if self.events != std::ptr::null_mut() {
            core::sc_app_layer_decoder_events_free_events(&mut self.events);
        }
        if let Some(state) = self.de_state {
            sc_detect_engine_state_free(state);
        }
    }
}




/// Returns *mut KRB5State
#[no_mangle]
pub extern "C" fn rs_krb5_state_new() -> *mut libc::c_void {
    let state = KRB5State::new();
    let boxed = Box::new(state);
    return unsafe{std::mem::transmute(boxed)};
}

/// Params:
/// - state: *mut KRB5State as void pointer
#[no_mangle]
pub extern "C" fn rs_krb5_state_free(state: *mut libc::c_void) {
    // Just unbox...
    let mut state: Box<KRB5State> = unsafe{std::mem::transmute(state)};
    state.free();
}

#[no_mangle]
pub extern "C" fn rs_krb5_state_get_tx(state: *mut libc::c_void,
                                      tx_id: libc::uint64_t)
                                      -> *mut libc::c_void
{
    let state = cast_pointer!(state,KRB5State);
    match state.get_tx_by_id(tx_id) {
        Some(tx) => unsafe{std::mem::transmute(tx)},
        None     => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn rs_krb5_state_get_tx_count(state: *mut libc::c_void)
                                            -> libc::uint64_t
{
    let state = cast_pointer!(state,KRB5State);
    state.tx_id
}

#[no_mangle]
pub extern "C" fn rs_krb5_state_tx_free(state: *mut libc::c_void,
                                       tx_id: libc::uint64_t)
{
    let state = cast_pointer!(state,KRB5State);
    state.free_tx(tx_id);
}

#[no_mangle]
pub extern "C" fn rs_krb5_state_progress_completion_status(
    _direction: libc::uint8_t)
    -> libc::c_int
{
    return 1;
}

#[no_mangle]
pub extern "C" fn rs_krb5_tx_get_alstate_progress(_tx: *mut libc::c_void,
                                                 _direction: libc::uint8_t)
                                                 -> libc::c_int
{
    1
}

#[no_mangle]
pub extern "C" fn rs_krb5_tx_set_logged(_state: *mut libc::c_void,
                                       tx: *mut libc::c_void,
                                       logged: libc::uint32_t)
{
    let tx = cast_pointer!(tx,KRB5Transaction);
    tx.logged.set(logged);
}

#[no_mangle]
pub extern "C" fn rs_krb5_tx_get_logged(_state: *mut libc::c_void,
                                       tx: *mut libc::c_void)
                                       -> u32
{
    let tx = cast_pointer!(tx,KRB5Transaction);
    return tx.logged.get();
}


#[no_mangle]
pub extern "C" fn rs_krb5_state_set_tx_detect_state(
    tx: *mut libc::c_void,
    de_state: &mut core::DetectEngineState) -> libc::c_int
{
    let tx = cast_pointer!(tx,KRB5Transaction);
    tx.de_state = Some(de_state);
    0
}

#[no_mangle]
pub extern "C" fn rs_krb5_state_get_tx_detect_state(
    tx: *mut libc::c_void)
    -> *mut core::DetectEngineState
{
    let tx = cast_pointer!(tx,KRB5Transaction);
    match tx.de_state {
        Some(ds) => ds,
        None => std::ptr::null_mut(),
    }
}


#[no_mangle]
pub extern "C" fn rs_krb5_state_get_events(state: *mut libc::c_void,
                                          tx_id: libc::uint64_t)
                                          -> *mut core::AppLayerDecoderEvents
{
    let state = cast_pointer!(state,KRB5State);
    match state.get_tx_by_id(tx_id) {
        Some(tx) => tx.events,
        _        => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn rs_krb5_state_get_event_info(event_name: *const libc::c_char,
                                              event_id: *mut libc::c_int,
                                              event_type: *mut core::AppLayerEventType)
                                              -> libc::c_int
{
    if event_name == std::ptr::null() { return -1; }
    let c_event_name: &CStr = unsafe { CStr::from_ptr(event_name) };
    let event = match c_event_name.to_str() {
        Ok(s) => {
            match s {
                "malformed_data"     => KRB5Event::MalformedData as i32,
                _                    => -1, // unknown event
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
static mut ALPROTO_KRB5 : AppProto = ALPROTO_UNKNOWN;

#[no_mangle]
pub extern "C" fn rs_krb5_probing_parser(_flow: *const Flow, input:*const libc::uint8_t, input_len: u32, _offset: *const u32) -> AppProto {
    let slice = build_slice!(input,input_len as usize);
    let alproto = unsafe{ ALPROTO_KRB5 };
    if slice.len() <= 10 { return unsafe{ALPROTO_FAILED}; }
    match der_read_element_header(slice) {
        IResult::Done(rem, ref hdr) => {
            // Kerberos messages start with an APPLICATION header
            if hdr.class != 0b01 { return unsafe{ALPROTO_FAILED}; }
            // Tag number should be <= 30
            if hdr.tag >= 30 { return unsafe{ALPROTO_FAILED}; }
            // Kerberos messages contain sequences
            if rem.is_empty() || rem[0] != 0x30 { return unsafe{ALPROTO_FAILED}; }
            // Check kerberos version
            if let IResult::Done(rem,_hdr) = der_read_element_header(rem) {
                if rem.len() > 5 {
                    match (rem[2],rem[3],rem[4]) {
                        // Encoding of DER integer 5 (version)
                        (2,1,5) => { return alproto; },
                        _       => (),
                    }
                }
            }
            return unsafe{ALPROTO_FAILED};
        },
        IResult::Incomplete(_) => {
            return ALPROTO_UNKNOWN;
        },
        IResult::Error(_) => {
            return unsafe{ALPROTO_FAILED};
        },
    }
}

#[no_mangle]
pub extern "C" fn rs_krb5_probing_parser_tcp(_flow: *const Flow, input:*const libc::uint8_t, input_len: u32, _offset: *const u32) -> AppProto {
    let slice = build_slice!(input,input_len as usize);
    if slice.len() <= 14 { return unsafe{ALPROTO_FAILED}; }
    match be_u32(slice) {
        IResult::Done(rem, record_mark) => {
            if record_mark != rem.len() as u32 { return unsafe{ALPROTO_FAILED}; }
            return rs_krb5_probing_parser(_flow, rem.as_ptr(), rem.len() as u32, _offset);
        },
        IResult::Incomplete(_) => {
            return ALPROTO_UNKNOWN;
        },
        IResult::Error(_) => {
            return unsafe{ALPROTO_FAILED};
        },
    }
}

#[no_mangle]
pub extern "C" fn rs_krb5_parse_request(_flow: *const core::Flow,
                                       state: *mut libc::c_void,
                                       _pstate: *mut libc::c_void,
                                       input: *const libc::uint8_t,
                                       input_len: u32,
                                       _data: *const libc::c_void) -> i8 {
    let buf = build_slice!(input,input_len as usize);
    let state = cast_pointer!(state,KRB5State);
    state.parse(buf, STREAM_TOSERVER)
}

#[no_mangle]
pub extern "C" fn rs_krb5_parse_response(_flow: *const core::Flow,
                                       state: *mut libc::c_void,
                                       _pstate: *mut libc::c_void,
                                       input: *const libc::uint8_t,
                                       input_len: u32,
                                       _data: *const libc::c_void) -> i8 {
    let buf = build_slice!(input,input_len as usize);
    let state = cast_pointer!(state,KRB5State);
    state.parse(buf, STREAM_TOCLIENT)
}

#[no_mangle]
pub extern "C" fn rs_krb5_parse_request_tcp(_flow: *const core::Flow,
                                       state: *mut libc::c_void,
                                       _pstate: *mut libc::c_void,
                                       input: *const libc::uint8_t,
                                       input_len: u32,
                                       _data: *const libc::c_void) -> i8 {
    if input_len < 4 { return -1; }
    let buf = build_slice!(input,input_len as usize);
    let state = cast_pointer!(state,KRB5State);
    // skip the record mark
    state.parse(&buf[4..], STREAM_TOSERVER)
}

#[no_mangle]
pub extern "C" fn rs_krb5_parse_response_tcp(_flow: *const core::Flow,
                                       state: *mut libc::c_void,
                                       _pstate: *mut libc::c_void,
                                       input: *const libc::uint8_t,
                                       input_len: u32,
                                       _data: *const libc::c_void) -> i8 {
    if input_len < 4 { return -1; }
    let buf = build_slice!(input,input_len as usize);
    let state = cast_pointer!(state,KRB5State);
    // skip the record mark
    state.parse(&buf[4..], STREAM_TOCLIENT)
}


const PARSER_NAME : &'static [u8] = b"krb5\0";

#[no_mangle]
pub unsafe extern "C" fn rs_register_krb5_parser() {
    let default_port = CString::new("88").unwrap();
    let mut parser = RustParser {
        name              : PARSER_NAME.as_ptr() as *const libc::c_char,
        default_port      : default_port.as_ptr(),
        ipproto           : libc::IPPROTO_UDP,
        probe_ts          : rs_krb5_probing_parser,
        probe_tc          : rs_krb5_probing_parser,
        min_depth         : 0,
        max_depth         : 16,
        state_new         : rs_krb5_state_new,
        state_free        : rs_krb5_state_free,
        tx_free           : rs_krb5_state_tx_free,
        parse_ts          : rs_krb5_parse_request,
        parse_tc          : rs_krb5_parse_response,
        get_tx_count      : rs_krb5_state_get_tx_count,
        get_tx            : rs_krb5_state_get_tx,
        tx_get_comp_st    : rs_krb5_state_progress_completion_status,
        tx_get_progress   : rs_krb5_tx_get_alstate_progress,
        get_tx_logged     : Some(rs_krb5_tx_get_logged),
        set_tx_logged     : Some(rs_krb5_tx_set_logged),
        get_de_state      : rs_krb5_state_get_tx_detect_state,
        set_de_state      : rs_krb5_state_set_tx_detect_state,
        get_events        : Some(rs_krb5_state_get_events),
        get_eventinfo     : Some(rs_krb5_state_get_event_info),
        localstorage_new  : None,
        localstorage_free : None,
        get_tx_mpm_id     : None,
        set_tx_mpm_id     : None,
        get_files         : None,
    };
    // register UDP parser
    let ip_proto_str = CString::new("udp").unwrap();
    if AppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        // store the allocated ID for the probe function
        ALPROTO_KRB5 = alproto;
        if AppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
    } else {
        SCLogDebug!("Protocol detecter and parser disabled for KRB5/UDP.");
    }
    // register TCP parser
    parser.ipproto = libc::IPPROTO_TCP;
    parser.probe_ts = rs_krb5_probing_parser_tcp;
    parser.probe_tc = rs_krb5_probing_parser_tcp;
    parser.parse_ts = rs_krb5_parse_request_tcp;
    parser.parse_tc = rs_krb5_parse_response_tcp;
    let ip_proto_str = CString::new("tcp").unwrap();
    if AppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        // store the allocated ID for the probe function
        ALPROTO_KRB5 = alproto;
        if AppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
    } else {
        SCLogDebug!("Protocol detecter and parser disabled for KRB5/TCP.");
    }
}
