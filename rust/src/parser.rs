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

//! Parser registration functions and common interface

use core::{DetectEngineState,Flow,AppLayerEventType,AppLayerDecoderEvents,STREAM_TOCLIENT,STREAM_TOSERVER};

use log::*;

use libc;
use libc::{c_void,c_char,c_int};
use std::ffi::CString;


// Application layer protocol identifiers (app-layer-protos.h)

pub const ALPROTO_UNKNOWN : AppProto = 0;
pub const ALPROTO_FAILED : AppProto = 20;

/// Rust parser declaration
pub struct RustParser {
    /// Parser name.
    pub name:            &'static str,
    /// Default port
    pub default_port:    &'static str,

    /// IP Protocol (libc::IPPROTO_UDP, libc::IPPROTO_TCP, etc.)
    pub ipproto:         c_int,

    /// Protocol name.
    pub proto_name:      &'static str,

    /// Probing function, for packets going to server
    pub probe_ts:        ProbeFn,
    /// Probing function, for packets going to client
    pub probe_tc:        ProbeFn,

    /// Minimum frame depth for probing
    pub min_depth:       u16,
    /// Maximum frame depth for probing
    pub max_depth:       u16,

    /// Allocation function for a new state
    pub state_new:       StateAllocFn,
    /// Function called to free a state
    pub state_free:      StateFreeFn,

    /// Parsing function, for packets going to server
    pub parse_ts:        ParseFn,
    /// Parsing function, for packets going to client
    pub parse_tc:        ParseFn,

    /// Get the current transaction count
    pub get_tx_count:    StateGetTxCntFn,
    /// Get a transaction
    pub get_tx:          StateGetTxFn,
    /// Function called to free a transaction
    pub tx_free:         StateTxFreeFn,
    /// Function returning the current transaction completion status
    pub tx_get_comp_st:  StateGetTxCompletionStatusFn,
    /// Function returning the current transaction progress
    pub tx_get_progress: StateGetProgressFn,

    /// Logged transaction getter function
    pub get_tx_logged:   Option<GetTxLoggedFn>,
    /// Logged transaction setter function
    pub set_tx_logged:   Option<SetTxLoggedFn>,

    /// Function called to get a detection state
    pub get_de_state:    GetDetectStateFn,
    /// Function called to set a detection state
    pub set_de_state:    SetDetectStateFn,
    /// Function to check if a detection state is present
    pub has_de_state:    Option<HasDetectStateFn>,

    /// Function to check if there are events
    pub has_events:      Option<HasEventsFn>,
    /// Function to get events
    pub get_events:      Option<GetEventsFn>,
    /// Function to get an event description
    pub get_eventinfo:   Option<GetEventInfoFn>,

    // Missing:
    // - LocalStorageAlloc / LocalStorageFree
    // - SetTxMpmIDs / GetTxMpmIDs
    // - GetFiles
}




/// Create a slice, given a buffer and a length
///
/// UNSAFE !
#[macro_export]
macro_rules! build_slice {
    ($buf:ident, $len:expr) => ( unsafe{ std::slice::from_raw_parts($buf, $len) } );
}

/// Cast pointer to a variable, as a mutable reference to an object
///
/// UNSAFE !
#[macro_export]
macro_rules! cast_pointer {
    ($ptr:ident, $ty:ty) => ( unsafe{ &mut *($ptr as *mut $ty) } );
}

pub type AppProto = c_int;

pub type ParseFn      = extern "C" fn (flow: *const Flow,
                                       state: *mut c_void,
                                       pstate: *const c_void,
                                       input: *const u8,
                                       input_len: u32,
                                       data: *const c_void) -> i8;
pub type ProbeFn      = extern "C" fn (input:*const i8, input_len: u32, offset: *const i8) -> AppProto;
pub type StateAllocFn = extern "C" fn () -> *mut c_void;
pub type StateFreeFn  = extern "C" fn (*mut c_void);
pub type StateTxFreeFn  = extern "C" fn (*mut c_void, u64);
pub type StateGetTxFn            = extern "C" fn (*mut c_void, u64) -> *mut c_void;
pub type StateGetTxCntFn         = extern "C" fn (*mut c_void) -> u64;
pub type StateGetTxCompletionStatusFn = extern "C" fn (u8) -> c_int;
pub type StateGetProgressFn = extern "C" fn (*mut c_void, u8) -> c_int;
pub type HasDetectStateFn   = extern "C" fn (*mut c_void) -> c_int;
pub type GetDetectStateFn   = extern "C" fn (*mut c_void) -> *mut DetectEngineState;
pub type SetDetectStateFn   = extern "C" fn (*mut c_void, *mut c_void, &mut DetectEngineState) -> c_int;
pub type GetEventInfoFn     = extern "C" fn (*const c_char, *mut c_int, *mut AppLayerEventType) -> c_int;
pub type GetEventsFn        = extern "C" fn (*mut c_void, u64) -> *mut AppLayerDecoderEvents;
pub type HasEventsFn        = extern "C" fn (*mut c_void) -> c_int;
pub type GetTxLoggedFn      = extern "C" fn (*mut c_void, *mut c_void, u32) -> c_int;
pub type SetTxLoggedFn      = extern "C" fn (*mut c_void, *mut c_void, u32);

// Defined in app-layer-protos.h
extern {
    pub fn StringToAppProto(proto_name: *const u8) -> AppProto;
}

// Defined in app-layer-detect-proto.h
extern {
    pub fn AppLayerProtoDetectConfProtoDetectionEnabled(ipproto: *const c_char, alproto_name: *const c_char) -> c_int;
    pub fn AppLayerProtoDetectRegisterProtocol(alproto: c_int, alproto_name: *const c_char);
    pub fn AppLayerProtoDetectPPParseConfPorts(ipproto_name: *const c_char,
                                               ipproto: u8,
                                               alproto_name: *const c_char,
                                               alproto: AppProto,
                                               min_depth: u16,
                                               max_depth: u16,
                                               probe_to_server: ProbeFn,
                                               probe_to_client: ProbeFn) -> c_int;
    pub fn AppLayerProtoDetectPPRegister(ipproto: u8,
                                         portstr: *const c_char,
                                         alproto: AppProto,
                                         min_depth: u16,
                                         max_depth: u16,
                                         direction: u8,
                                         probe_to_server: ProbeFn,
                                         probe_to_client: ProbeFn);
}

// Defined in app-layer-parser.h
extern {
    /// Given a protocol name, checks if the parser is enabled in the conf file.
    /// Return: 1 if enabled, 0 if disabled
    pub fn AppLayerParserConfParserEnabled(ipproto: *const c_char, alproto_name: *const c_char) -> c_int;

    pub fn AppLayerParserRegisterStateFuncs(ipproto: u8, alproto: AppProto,
                                            state_alloc: StateAllocFn,
                                            state_free: StateFreeFn);
    pub fn AppLayerParserRegisterParser(ipproto: u8, alproto: AppProto,
                                        direction: u8,
                                        parser: ParseFn);
    pub fn AppLayerParserRegisterTxFreeFunc(ipproto: u8, alproto: AppProto,
                                            free: StateTxFreeFn);
    pub fn AppLayerParserRegisterGetTxCnt(ipproto: u8, alproto: AppProto,
                                          state_get_tx_cnt: StateGetTxCntFn);
    pub fn AppLayerParserRegisterGetStateProgressCompletionStatus(alproto: AppProto,
                                                                  get: StateGetTxCompletionStatusFn);
    pub fn AppLayerParserRegisterGetStateProgressFunc(ipproto:u8, alproto: AppProto,
                                                      get: StateGetProgressFn);
    pub fn AppLayerParserRegisterGetTx(ipproto: u8, alproto: AppProto,
                                       get: StateGetTxFn);
    // Use an Option<extern fn()> type to handle the NULL case
    // See https://github.com/rust-lang/rust/issues/8730
    pub fn AppLayerParserRegisterDetectStateFuncs(ipproto: u8, alproto: AppProto,
                                                  has_de: Option<HasDetectStateFn>,
                                                  get_de: GetDetectStateFn,
                                                  set_de: SetDetectStateFn);
    pub fn AppLayerParserRegisterGetEventInfo(ipproto: u8, alproto: AppProto,
                                                   get_eventinfo: GetEventInfoFn);
    pub fn AppLayerParserRegisterGetEventsFunc(ipproto: u8, proto: AppProto,
                                               get_events: GetEventsFn);
    pub fn AppLayerParserRegisterHasEventsFunc(ipproto: u8, alproto: AppProto,
                                               has_events: HasEventsFn);
    pub fn AppLayerParserRegisterLoggerFuncs(ipproto: u8, alproto: AppProto,
                                             get_tx: GetTxLoggedFn,
                                             set_tx: SetTxLoggedFn);
}



/// Register a new parser to Suricata
pub unsafe fn register_parser(p: &RustParser, alproto:AppProto) {
    let ipproto = p.ipproto as u8;
    let ipproto_str = match p.ipproto {
        libc::IPPROTO_TCP => CString::new("tcp").unwrap(),
        libc::IPPROTO_UDP => CString::new("udp").unwrap(),
        _ => panic!("Unknown or unsupported ipproto field in parser"),
    };
    let parser_name = CString::new(p.name).unwrap();
    let proto_name = CString::new(p.proto_name).unwrap();
    let default_port_str = CString::new(p.default_port).unwrap();

    /* Check if protocol detection is enabled. If it does not exist in
     * the configuration file then it will be enabled by default. */
    if AppLayerProtoDetectConfProtoDetectionEnabled(ipproto_str.as_ptr(), parser_name.as_ptr()) == 1 {
        SCLogDebug!("{:?} {:?} protocol detection enabled.", parser_name, ipproto_str);
        AppLayerProtoDetectRegisterProtocol(alproto, proto_name.as_ptr());
        // if runmode is unit tests
        // else (not unit tests)
        let res = AppLayerProtoDetectPPParseConfPorts(ipproto_str.as_ptr(), ipproto,
                                                      proto_name.as_ptr(), alproto,
                                                      p.min_depth, p.max_depth,
                                                      p.probe_ts, p.probe_tc);
        if res != 0 {
            SCLogDebug!("No {} app-layer configuration, enabling {} detection {:?} detection on port {}.",
                        p.proto_name, p.proto_name, ipproto_str, p.default_port);
            AppLayerProtoDetectPPRegister(ipproto, default_port_str.as_ptr(),
                                          alproto,
                                          p.min_depth, p.max_depth,
                                          STREAM_TOSERVER,
                                          p.probe_ts, p.probe_tc);
        }
    } else {
        SCLogDebug!("Protocol detecter and parser disabled for {}.", p.name);
        return;
    }

    if AppLayerParserConfParserEnabled(ipproto_str.as_ptr(), proto_name.as_ptr()) == 1 {
        SCLogDebug!("Registering {} protocol parser.", p.name);
        /* Register functions for state allocation and freeing. A
         * state is allocated for every new protocol flow. */
        AppLayerParserRegisterStateFuncs(ipproto, alproto,
                                         p.state_new, p.state_free);
        /* Register request parser for parsing frame from server to client. */
        AppLayerParserRegisterParser(ipproto, alproto,
                                     STREAM_TOSERVER, p.parse_ts);
        /* Register response parser for parsing frames from server to client. */
        AppLayerParserRegisterParser(ipproto, alproto,
                                     STREAM_TOCLIENT, p.parse_tc);
        /* Register a function to be called by the application layer
         * when a transaction is to be freed. */
        AppLayerParserRegisterTxFreeFunc(ipproto, alproto, p.tx_free);
        // AppLayerParserRegisterLoggerFuncs(IPPROTO_UDP, ALPROTO_NTP,
        //     NTPGetTxLogged, NTPSetTxLogged);

        /* Register a function to return the current transaction count. */
        AppLayerParserRegisterGetTxCnt(ipproto, alproto, p.get_tx_count);

        /* Transaction handling. */
        AppLayerParserRegisterGetStateProgressCompletionStatus(alproto, p.tx_get_comp_st);
        AppLayerParserRegisterGetStateProgressFunc(ipproto, alproto, p.tx_get_progress);
        AppLayerParserRegisterGetTx(ipproto, alproto, p.get_tx);

        match (p.get_tx_logged,p.set_tx_logged) {
            (Some(f1),Some(f2)) => AppLayerParserRegisterLoggerFuncs(ipproto, alproto, f1, f2),
            (None,None)         => (),
            _                   => SCLogDebug!("GetTxLogger/SetTxLogged: only one function is set for protocol {}",p.name),
        }

        /* Application layer event handling. */
        if let Some(fun) = p.has_events {
            AppLayerParserRegisterHasEventsFunc(ipproto, alproto, fun);
        }

        /* What is this being registered for? */
        AppLayerParserRegisterDetectStateFuncs(ipproto, alproto,
                                               p.has_de_state,
                                               p.get_de_state,
                                               p.set_de_state);

        if let Some(fun) = p.get_eventinfo {
            AppLayerParserRegisterGetEventInfo(ipproto, alproto, fun);
        }
        if let Some(fun) = p.get_events {
            AppLayerParserRegisterGetEventsFunc(ipproto, alproto, fun);
        }
    } else {
        SCLogDebug!("{} protocol parsing disabled.", p.name);
        return;
    }
}

