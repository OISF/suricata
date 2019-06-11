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

use core::{DetectEngineState,Flow,AppLayerEventType,AppLayerDecoderEvents,AppProto};
use filecontainer::FileContainer;
use applayer;

use std::os::raw::{c_void,c_char,c_int};
use applayer::{AppLayerGetTxIterTuple};

/// Rust parser declaration
#[repr(C)]
pub struct RustParser {
    /// Parser name.
    pub name:               *const c_char,
    /// Default port
    pub default_port:       *const c_char,

    /// IP Protocol (core::IPPROTO_UDP, core::IPPROTO_TCP, etc.)
    pub ipproto:            c_int,

    /// Probing function, for packets going to server
    pub probe_ts:           ProbeFn,
    /// Probing function, for packets going to client
    pub probe_tc:           ProbeFn,

    /// Minimum frame depth for probing
    pub min_depth:          u16,
    /// Maximum frame depth for probing
    pub max_depth:          u16,

    /// Allocation function for a new state
    pub state_new:          StateAllocFn,
    /// Function called to free a state
    pub state_free:         StateFreeFn,

    /// Parsing function, for packets going to server
    pub parse_ts:           ParseFn,
    /// Parsing function, for packets going to client
    pub parse_tc:           ParseFn,

    /// Get the current transaction count
    pub get_tx_count:       StateGetTxCntFn,
    /// Get a transaction
    pub get_tx:             StateGetTxFn,
    /// Function called to free a transaction
    pub tx_free:            StateTxFreeFn,
    /// Function returning the current transaction completion status
    pub tx_get_comp_st:     StateGetTxCompletionStatusFn,
    /// Function returning the current transaction progress
    pub tx_get_progress:    StateGetProgressFn,

    /// Logged transaction getter function
    pub get_tx_logged:      Option<GetTxLoggedFn>,
    /// Logged transaction setter function
    pub set_tx_logged:      Option<SetTxLoggedFn>,

    /// Function called to get a detection state
    pub get_de_state:       GetDetectStateFn,
    /// Function called to set a detection state
    pub set_de_state:       SetDetectStateFn,

    /// Function to get events
    pub get_events:         Option<GetEventsFn>,
    /// Function to get an event id from a description
    pub get_eventinfo:      Option<GetEventInfoFn>,
    /// Function to get an event description from an event id
    pub get_eventinfo_byid: Option<GetEventInfoByIdFn>,

    /// Function to allocate local storage
    pub localstorage_new:   Option<LocalStorageNewFn>,
    /// Function to free local storage
    pub localstorage_free:  Option<LocalStorageFreeFn>,

    /// Function to get transaction MPM ID
    pub get_tx_mpm_id:      Option<GetTxMpmIDFn>,
    /// Function to set transaction MPM ID
    pub set_tx_mpm_id:      Option<SetTxMpmIDFn>,

    /// Function to get files
    pub get_files:          Option<GetFilesFn>,

    /// Function to get the TX iterator
    pub get_tx_iterator:    Option<GetTxIteratorFn>,
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

pub type ParseFn      = extern "C" fn (flow: *const Flow,
                                       state: *mut c_void,
                                       pstate: *mut c_void,
                                       input: *const u8,
                                       input_len: u32,
                                       data: *const c_void,
                                       flags: u8) -> i32;
pub type ProbeFn      = extern "C" fn (flow: *const Flow,direction: u8,input:*const u8, input_len: u32, rdir: *mut u8) -> AppProto;
pub type StateAllocFn = extern "C" fn () -> *mut c_void;
pub type StateFreeFn  = extern "C" fn (*mut c_void);
pub type StateTxFreeFn  = extern "C" fn (*mut c_void, u64);
pub type StateGetTxFn            = extern "C" fn (*mut c_void, u64) -> *mut c_void;
pub type StateGetTxCntFn         = extern "C" fn (*mut c_void) -> u64;
pub type StateGetTxCompletionStatusFn = extern "C" fn (u8) -> c_int;
pub type StateGetProgressFn = extern "C" fn (*mut c_void, u8) -> c_int;
pub type GetDetectStateFn   = extern "C" fn (*mut c_void) -> *mut DetectEngineState;
pub type SetDetectStateFn   = extern "C" fn (*mut c_void, &mut DetectEngineState) -> c_int;
pub type GetEventInfoFn     = extern "C" fn (*const c_char, *mut c_int, *mut AppLayerEventType) -> c_int;
pub type GetEventInfoByIdFn = extern "C" fn (c_int, *mut *const c_char, *mut AppLayerEventType) -> i8;
pub type GetEventsFn        = extern "C" fn (*mut c_void) -> *mut AppLayerDecoderEvents;
pub type GetTxLoggedFn      = extern "C" fn (*mut c_void, *mut c_void) -> u32;
pub type SetTxLoggedFn      = extern "C" fn (*mut c_void, *mut c_void, u32);
pub type LocalStorageNewFn  = extern "C" fn () -> *mut c_void;
pub type LocalStorageFreeFn = extern "C" fn (*mut c_void);
pub type GetTxMpmIDFn       = extern "C" fn (*mut c_void) -> u64;
pub type SetTxMpmIDFn       = extern "C" fn (*mut c_void, u64) -> c_int;
pub type GetFilesFn         = extern "C" fn (*mut c_void, u8) -> *mut FileContainer;
pub type GetTxIteratorFn    = extern "C" fn (ipproto: u8, alproto: AppProto,
                                             state: *mut c_void,
                                             min_tx_id: u64,
                                             max_tx_id: u64,
                                             istate: &mut u64)
                                             -> AppLayerGetTxIterTuple;

// Defined in app-layer-register.h
extern {
    pub fn AppLayerRegisterProtocolDetection(parser: *const RustParser, enable_default: c_int) -> AppProto;
    pub fn AppLayerRegisterParser(parser: *const RustParser, alproto: AppProto) -> c_int;
}

// Defined in app-layer-detect-proto.h
extern {
    pub fn AppLayerProtoDetectConfProtoDetectionEnabled(ipproto: *const c_char, proto: *const c_char) -> c_int;
}

// Defined in app-layer-parser.h
pub const APP_LAYER_PARSER_EOF : u8 = 0b0;
pub const APP_LAYER_PARSER_NO_INSPECTION : u8 = 0b1;
pub const APP_LAYER_PARSER_NO_REASSEMBLY : u8 = 0b10;
pub const APP_LAYER_PARSER_NO_INSPECTION_PAYLOAD : u8 = 0b100;
pub const APP_LAYER_PARSER_BYPASS_READY : u8 = 0b1000;

pub type AppLayerGetTxIteratorFn = extern "C" fn (ipproto: u8,
                                                  alproto: AppProto,
                                                  alstate: *mut c_void,
                                                  min_tx_id: u64,
                                                  max_tx_id: u64,
                                                  istate: &mut u64) -> applayer::AppLayerGetTxIterTuple;

extern {
    pub fn AppLayerParserStateSetFlag(state: *mut c_void, flag: u8);
    pub fn AppLayerParserStateIssetFlag(state: *mut c_void, flag: u8) -> c_int;
    pub fn AppLayerParserConfParserEnabled(ipproto: *const c_char, proto: *const c_char) -> c_int;
    pub fn AppLayerParserRegisterGetTxIterator(ipproto: u8, alproto: AppProto, fun: AppLayerGetTxIteratorFn);
}
