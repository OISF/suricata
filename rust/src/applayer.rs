/* Copyright (C) 2017-2022 Open Information Security Foundation
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

//! Parser registration functions and common interface module.

use std;
use crate::core::{self,AppLayerEventType, STREAM_TOSERVER};
use crate::direction::Direction;
use crate::flow::Flow;
use std::os::raw::{c_void,c_char,c_int};
use std::ffi::CStr;

// Make the AppLayerEvent derive macro available to users importing
// AppLayerEvent from this module.
pub use suricata_derive::AppLayerEvent;
use suricata_sys::sys::{
    AppLayerGetTxIterState, AppLayerParserState, AppProto,
};

pub use suricata_sys::sys::{
    AppLayerGetFileState, AppLayerGetTxIterTuple, AppLayerResult, AppLayerStateData,
    AppLayerTxConfig, StreamSlice,
};

#[cfg(not(test))]
use suricata_sys::sys::SCAppLayerDecoderEventsSetEventRaw;

/// Cast pointer to a variable, as a mutable reference to an object
///
/// UNSAFE !
#[macro_export]
macro_rules! cast_pointer {
    ($ptr:ident, $ty:ty) => ( &mut *($ptr as *mut $ty) );
}

pub trait StreamSliceRust {
    #[cfg(test)]
    fn from_slice(slice: &[u8], flags: u8, offset: u64) -> Self;
    fn is_gap(&self) -> bool;
    fn gap_size(&self) -> u32;
    fn as_slice(&self) -> &[u8];
    fn is_empty(&self) -> bool;
    fn len(&self) -> u32;
    fn offset_from(&self, slice: &[u8]) -> u32;
    fn flags(&self) -> u8;
}

impl StreamSliceRust for StreamSlice {
    /// Create a StreamSlice from a Rust slice. Useful in unit tests.
    #[cfg(test)]
    fn from_slice(slice: &[u8], flags: u8, offset: u64) -> Self {
        Self {
            input: slice.as_ptr(),
            input_len: slice.len() as u32,
            flags,
            offset
        }
    }

    fn is_gap(&self) -> bool {
        self.input.is_null() && self.input_len > 0
    }
    fn gap_size(&self) -> u32 {
        self.input_len
    }
    fn as_slice(&self) -> &[u8] {
        if self.input.is_null() && self.input_len == 0 {
            return &[];
        }
        unsafe { std::slice::from_raw_parts(self.input, self.input_len as usize) }
    }
    fn is_empty(&self) -> bool {
        self.input_len == 0
    }
    fn len(&self) -> u32 {
        self.input_len
    }
    fn offset_from(&self, slice: &[u8]) -> u32 {
        self.len() - slice.len() as u32
    }
    fn flags(&self) -> u8 {
        self.flags
    }
}

#[derive(Debug, Default, Eq, PartialEq)]
pub struct AppLayerTxData(pub suricata_sys::sys::AppLayerTxData);

impl AppLayerTxData {
    /// Create new AppLayerTxData for a transaction that covers both
    /// directions.
    pub fn new() -> Self {
        Self (suricata_sys::sys::AppLayerTxData {
            updated_tc: true,
            updated_ts: true,
            ..Default::default()
        })
    }

    /// Create new AppLayerTxData for a transaction in a single
    /// direction.
    pub fn for_direction(direction: Direction) -> Self {
        let (flags, updated_ts, updated_tc) = match direction {
            Direction::ToServer => (APP_LAYER_TX_SKIP_INSPECT_TC, true, false),
            Direction::ToClient => (APP_LAYER_TX_SKIP_INSPECT_TS, false, true),
        };
        Self (suricata_sys::sys::AppLayerTxData{
            updated_tc,
            updated_ts,
            flags,
            ..Default::default()
        })
    }

    pub fn init_files_opened(&mut self) {
        self.0.files_opened = 1;
    }

    pub fn incr_files_opened(&mut self) {
        self.0.files_opened += 1;
    }

    pub fn set_event(&mut self, _event: u8) {
        #[cfg(not(test))]
        unsafe {
            SCAppLayerDecoderEventsSetEventRaw(&mut self.0.events, _event);
        }
    }

    pub fn update_file_flags(&mut self, state_flags: u16) {
        unsafe {
            SCTxDataUpdateFileFlags(&mut self.0, state_flags);
        }
    }
}

#[cfg(not(test))]
use suricata_sys::sys::SCAppLayerTxDataCleanup;

impl Drop for AppLayerTxData {
    fn drop(&mut self) {
        #[cfg(not(test))]
        unsafe {
            SCAppLayerTxDataCleanup(&mut self.0);
        }
    }
}


// need to keep in sync with C flow.h
pub const FLOWFILE_NO_STORE_TS: u16 = BIT_U16!(2);
pub const FLOWFILE_NO_STORE_TC: u16 = BIT_U16!(3);
pub const FLOWFILE_STORE_TS: u16 = BIT_U16!(12);
pub const FLOWFILE_STORE_TC: u16 = BIT_U16!(13);

#[no_mangle]
pub unsafe extern "C" fn SCTxDataUpdateFileFlags(txd: &mut suricata_sys::sys::AppLayerTxData, state_flags: u16) {
    if (txd.file_flags & state_flags) != state_flags {
        SCLogDebug!("updating tx file_flags {:04x} with state flags {:04x}", txd.file_flags, state_flags);
        let mut nf = state_flags;
        // With keyword filestore:both,flow :
        // There may be some opened unclosed file in one direction without filestore
        // As such it has tx file_flags had FLOWFILE_NO_STORE_TS or TC
        // But a new file in the other direction may trigger filestore:both,flow
        // And thus set state_flags FLOWFILE_STORE_TS
        // If the file was opened without storing it, do not try to store just the end of it
        if (txd.file_flags & FLOWFILE_NO_STORE_TS) != 0 && (state_flags & FLOWFILE_STORE_TS) != 0 {
            nf &= !FLOWFILE_STORE_TS;
        }
        if (txd.file_flags & FLOWFILE_NO_STORE_TC) != 0 && (state_flags & FLOWFILE_STORE_TC) != 0 {
            nf &= !FLOWFILE_STORE_TC;
        }
        txd.file_flags |= nf;
    }
}

#[macro_export]
macro_rules!export_tx_data_get {
    ($name:ident, $type:ty) => {
        unsafe extern "C" fn $name(tx: *mut std::os::raw::c_void)
            -> *mut suricata_sys::sys::AppLayerTxData
        {
            let tx = &mut *(tx as *mut $type);
            &mut tx.tx_data.0
        }
    }
}

#[macro_export]
macro_rules!export_state_data_get {
    ($name:ident, $type:ty) => {
        unsafe extern "C" fn $name(state: *mut std::os::raw::c_void)
            -> *mut $crate::applayer::AppLayerStateData
        {
            let state = &mut *(state as *mut $type);
            &mut state.state_data
        }
    }
}

pub trait AppLayerResultRust {
    fn ok() -> Self;
    fn ok_partial_continue(consumed: u32) -> Self;
    fn err() -> Self;
    fn incomplete(consumed: u32, needed: u32) -> Self;
    fn is_ok(&self) -> bool;
    fn is_err(&self) -> bool;
    fn is_incomplete(&self) -> bool;
}

impl AppLayerResultRust for AppLayerResult {
    /// parser has successfully processed in the input, and has consumed all of it
    fn ok() -> Self {
        Default::default()
    }
    /// parser has successfully processed input, but not all. The rest should be
    /// immediately be processed.
    fn ok_partial_continue(consumed: u32) -> Self {
        return Self {
            status: 2,
            consumed,
            needed: 0,
        };
    }
    /// parser has hit an unrecoverable error. Returning this to the API
    /// leads to no further calls to the parser.
    fn err() -> Self {
        return AppLayerResult{
            status: -1,
            ..Default::default()
        };
    }

    /// parser needs more data. Through 'consumed' it will indicate how many
    /// of the input bytes it has consumed. Through 'needed' it will indicate
    /// how many more bytes it needs before getting called again.
    /// Note: consumed should never be more than the input len
    ///       needed + consumed should be more than the input len
    fn incomplete(consumed: u32, needed: u32) -> Self {
        return Self {
            status: 1,
            consumed,
            needed,
        };
    }

    fn is_ok(&self) -> bool {
        self.status == 0
    }

    fn is_err(&self) -> bool {
        self.status == -1
    }

    fn is_incomplete(&self) -> bool {
        self.status == 1
    }
}

/// Rust parser declaration
#[repr(C)]
pub struct RustParser {
    /// Parser name.
    pub name:               *const c_char,
    /// Default port
    pub default_port:       *const c_char,

    /// IP Protocol (core::IPPROTO_UDP, core::IPPROTO_TCP, etc.)
    pub ipproto:            u8,

    /// Probing function, for packets going to server
    pub probe_ts:           Option<ProbeFn>,
    /// Probing function, for packets going to client
    pub probe_tc:           Option<ProbeFn>,

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
    /// Progress values at which the tx is considered complete in a direction
    pub tx_comp_st_ts:      c_int,
    pub tx_comp_st_tc:      c_int,
    /// Function returning the current transaction progress
    pub tx_get_progress:    StateGetProgressFn,

    /// Function to get an event id from a description
    pub get_eventinfo:      Option<GetEventInfoFn>,
    /// Function to get an event description from an event id
    pub get_eventinfo_byid: Option<GetEventInfoByIdFn>,

    /// Function to allocate local storage
    pub localstorage_new:   Option<LocalStorageNewFn>,
    /// Function to free local storage
    pub localstorage_free:  Option<LocalStorageFreeFn>,

    /// Function to get files
    pub get_tx_files:       Option<GetTxFilesFn>,

    /// Function to get the TX iterator
    pub get_tx_iterator:    Option<GetTxIteratorFn>,

    pub get_state_data: GetStateDataFn,
    pub get_tx_data: GetTxDataFn,

    // Function to apply config to a TX. Optional. Normal (bidirectional)
    // transactions don't need to set this. It is meant for cases where
    // the requests and responses are not sharing tx. It is then up to
    // the implementation to make sure the config is applied correctly.
    pub apply_tx_config: Option<ApplyTxConfigFn>,

    pub flags: u32,

    pub get_frame_id_by_name: Option<GetFrameIdByName>,
    pub get_frame_name_by_id: Option<GetFrameNameById>,

    pub get_state_id_by_name: Option<GetStateIdByName>,
    pub get_state_name_by_id: Option<GetStateNameById>,
}

/// Create a slice, given a buffer and a length
///
/// UNSAFE !
#[macro_export]
macro_rules! build_slice {
    ($buf:ident, $len:expr) => ( std::slice::from_raw_parts($buf, $len) );
}

pub trait AppLayerGetFileStateRust {
    fn err() -> Self;
}

impl AppLayerGetFileStateRust for AppLayerGetFileState {
    fn err() -> AppLayerGetFileState {
        AppLayerGetFileState { fc: std::ptr::null_mut(), cfg: std::ptr::null() }
    }
}

pub type ParseFn      = unsafe extern "C" fn (flow: *mut Flow,
                                       state: *mut c_void,
                                       pstate: *mut AppLayerParserState,
                                       stream_slice: StreamSlice,
                                       data: *mut c_void) -> AppLayerResult;
pub type ProbeFn      = unsafe extern "C" fn (flow: *const Flow, flags: u8, input:*const u8, input_len: u32, rdir: *mut u8) -> AppProto;
pub type StateAllocFn = unsafe extern "C" fn (*mut c_void, AppProto) -> *mut c_void;
pub type StateFreeFn  = unsafe extern "C" fn (*mut c_void);
pub type StateTxFreeFn  = unsafe extern "C" fn (*mut c_void, u64);
pub type StateGetTxFn            = unsafe extern "C" fn (*mut c_void, u64) -> *mut c_void;
pub type StateGetTxCntFn         = unsafe extern "C" fn (*mut c_void) -> u64;
pub type StateGetProgressFn = unsafe extern "C" fn (*mut c_void, u8) -> c_int;
pub type GetEventInfoFn     = unsafe extern "C" fn (*const c_char, event_id: *mut u8, *mut AppLayerEventType) -> c_int;
pub type GetEventInfoByIdFn = unsafe extern "C" fn (event_id: u8, *mut *const c_char, *mut AppLayerEventType) -> c_int;
pub type LocalStorageNewFn  = unsafe extern "C" fn () -> *mut c_void;
pub type LocalStorageFreeFn = unsafe extern "C" fn (*mut c_void);
pub type GetTxFilesFn       = unsafe extern "C" fn (*mut c_void, u8) -> AppLayerGetFileState;
pub type GetTxIteratorFn    = unsafe extern "C" fn (ipproto: u8, alproto: AppProto,
                                             state: *mut c_void,
                                             min_tx_id: u64,
                                             max_tx_id: u64,
                                             istate: *mut AppLayerGetTxIterState)
                                             -> AppLayerGetTxIterTuple;
pub type GetTxDataFn = unsafe extern "C" fn(*mut c_void) -> *mut suricata_sys::sys::AppLayerTxData;
pub type GetStateDataFn = unsafe extern "C" fn(*mut c_void) -> *mut AppLayerStateData;
pub type ApplyTxConfigFn = unsafe extern "C" fn (*mut c_void, *mut c_void, c_int, AppLayerTxConfig);
pub type GetFrameIdByName = unsafe extern "C" fn(*const c_char) -> c_int;
pub type GetFrameNameById = unsafe extern "C" fn(u8) -> *const c_char;
pub type GetStateIdByName = unsafe extern "C" fn(*const c_char, u8) -> c_int;
pub type GetStateNameById = unsafe extern "C" fn(c_int, u8) -> *const c_char;

use suricata_sys::sys::{AppLayerParser, SCAppLayerRegisterParser};

#[allow(non_snake_case)]
pub fn AppLayerRegisterParser(parser: &RustParser, alproto: AppProto) -> c_int {
    let det = AppLayerParser{
        name: parser.name,
        default_port: parser.default_port,
        ip_proto: parser.ipproto,
        ProbeTS: parser.probe_ts,
        ProbeTC: parser.probe_tc,
        min_depth: parser.min_depth,
        max_depth: parser.max_depth,

        StateAlloc: Some(parser.state_new),
        StateFree: Some(parser.state_free),

        ParseTS: Some(parser.parse_ts),
        ParseTC: Some(parser.parse_tc),

        StateGetTxCnt: Some(parser.get_tx_count),
        StateGetTx: Some(parser.get_tx),
        StateTransactionFree: Some(parser.tx_free),

        complete_ts: parser.tx_comp_st_ts,
        complete_tc: parser.tx_comp_st_tc,
        StateGetProgress: Some(parser.tx_get_progress),

        StateGetEventInfo: parser.get_eventinfo,
        StateGetEventInfoById: parser.get_eventinfo_byid,
        LocalStorageAlloc: parser.localstorage_new,
        LocalStorageFree: parser.localstorage_free,

        GetTxFiles: parser.get_tx_files,
        GetTxIterator: parser.get_tx_iterator,
        GetStateData: Some(parser.get_state_data),
        GetTxData: Some(parser.get_tx_data),
        ApplyTxConfig: parser.apply_tx_config,

        flags: parser.flags,

        GetFrameIdByName: parser.get_frame_id_by_name,
        GetFrameNameById: parser.get_frame_name_by_id,
        GetStateIdByName: parser.get_state_id_by_name,
        GetStateNameById: parser.get_state_name_by_id,
    };
    unsafe {SCAppLayerRegisterParser(&det, alproto) }
}

use suricata_sys::sys::{AppLayerProtocolDetect, SCAppLayerRegisterProtocolDetection};

pub fn applayer_register_protocol_detection(parser: &RustParser, enable_default: c_int) -> AppProto {
    let det = AppLayerProtocolDetect{
        name: parser.name,
        default_port: parser.default_port,
        ip_proto: parser.ipproto,
        ProbeTS: parser.probe_ts,
        ProbeTC: parser.probe_tc,
        min_depth: parser.min_depth,
        max_depth: parser.max_depth,
    };
    unsafe {SCAppLayerRegisterProtocolDetection(&det, enable_default) }
}


// Defined in app-layer-parser.h
pub const APP_LAYER_PARSER_NO_INSPECTION : u16 = BIT_U16!(1);
pub const APP_LAYER_PARSER_NO_REASSEMBLY : u16 = BIT_U16!(2);
pub const APP_LAYER_PARSER_NO_INSPECTION_PAYLOAD : u16 = BIT_U16!(3);
pub const APP_LAYER_PARSER_BYPASS_READY : u16 = BIT_U16!(4);
pub const APP_LAYER_PARSER_EOF_TS : u16 = BIT_U16!(5);
pub const APP_LAYER_PARSER_EOF_TC : u16 = BIT_U16!(6);

pub const APP_LAYER_PARSER_OPT_ACCEPT_GAPS: u32 = BIT_U32!(0);

pub const APP_LAYER_TX_SKIP_INSPECT_TS: u8 = BIT_U8!(0);
pub const APP_LAYER_TX_SKIP_INSPECT_TC: u8 = BIT_U8!(1);
pub const _APP_LAYER_TX_INSPECTED_TS: u8 = BIT_U8!(2);
pub const _APP_LAYER_TX_INSPECTED_TC: u8 = BIT_U8!(3);
pub const APP_LAYER_TX_ACCEPT: u8 = BIT_U8!(4);

pub trait AppLayerGetTxIterTupleRust {
    fn with_values(tx_ptr: *mut std::os::raw::c_void, tx_id: u64, has_next: bool) -> Self;
    fn not_found() -> Self;
}

impl AppLayerGetTxIterTupleRust for AppLayerGetTxIterTuple {
    fn with_values(tx_ptr: *mut std::os::raw::c_void, tx_id: u64, has_next: bool) -> AppLayerGetTxIterTuple {
        AppLayerGetTxIterTuple {
            tx_ptr, tx_id, has_next,
        }
    }
    fn not_found() -> AppLayerGetTxIterTuple {
        AppLayerGetTxIterTuple {
            tx_ptr: std::ptr::null_mut(), tx_id: 0, has_next: false,
        }
    }
}

/// AppLayerEvent trait that will be implemented on enums that
/// derive AppLayerEvent.
pub trait AppLayerEvent {
    /// Return the enum variant of the given ID.
    fn from_id(id: u8) -> Option<Self> where Self: std::marker::Sized;

    /// Convert the enum variant to a C-style string (suffixed with \0).
    fn to_cstring(&self) -> &str;

    /// Return the enum variant for the given name.
    fn from_string(s: &str) -> Option<Self> where Self: std::marker::Sized;

    /// Return the ID value of the enum variant.
    fn as_u8(&self) -> u8;

    unsafe extern "C" fn get_event_info(
        event_name: *const std::os::raw::c_char,
        event_id: *mut u8,
        event_type: *mut core::AppLayerEventType,
    ) -> std::os::raw::c_int;

    unsafe extern "C" fn get_event_info_by_id(
        event_id: u8,
        event_name: *mut *const std::os::raw::c_char,
        event_type: *mut core::AppLayerEventType,
    ) -> std::os::raw::c_int;
}

/// Generic `get_info_info` implementation for enums implementing
/// AppLayerEvent.
///
/// Normally usage of this function will be generated by
/// derive(AppLayerEvent), for example:
///
/// ```rust,ignore
/// #[derive(AppLayerEvent)]
/// enum AppEvent {
///     EventOne,
///     EventTwo,
/// }
///
/// get_event_info::<AppEvent>(...)
/// ```
#[inline(always)]
pub unsafe fn get_event_info<T: AppLayerEvent>(
    event_name: *const std::os::raw::c_char,
    event_id: *mut u8,
    event_type: *mut core::AppLayerEventType,
) -> std::os::raw::c_int {
    if event_name.is_null() {
        return -1;
    }

    let event = match CStr::from_ptr(event_name).to_str().map(T::from_string) {
        Ok(Some(event)) => event.as_u8(),
        _ => {
            return -1;
        }
    };
    *event_type = core::AppLayerEventType::APP_LAYER_EVENT_TYPE_TRANSACTION;
    *event_id = event;
    return 0;
}

/// Generic `get_info_info_by_id` implementation for enums implementing
/// AppLayerEvent.
#[inline(always)]
pub unsafe fn get_event_info_by_id<T: AppLayerEvent>(
    event_id: u8,
    event_name: *mut *const std::os::raw::c_char,
    event_type: *mut core::AppLayerEventType,
) -> std::os::raw::c_int {
    if let Some(e) = T::from_id(event_id) {
        *event_name = e.to_cstring().as_ptr() as *const std::os::raw::c_char;
        *event_type = core::AppLayerEventType::APP_LAYER_EVENT_TYPE_TRANSACTION;
        return 0;
    }
    return -1;
}

/// Transaction trait.
///
/// This trait defines methods that a Transaction struct must implement
/// in order to define some generic helper functions.
pub trait Transaction {
    fn id(&self) -> u64;
}

pub trait State<Tx: Transaction> {
    /// Return the number of transactions in the state's transaction collection.
    fn get_transaction_count(&self) -> usize;

    /// Return a transaction by its index in the container.
    fn get_transaction_by_index(&self, index: usize) -> Option<&Tx>;

    fn get_transaction_iterator(&self, min_tx_id: u64, state: &mut u64) -> AppLayerGetTxIterTuple {
        let mut index = *state as usize;
        let len = self.get_transaction_count();
        while index < len {
            let tx = self.get_transaction_by_index(index).unwrap();
            if tx.id() < min_tx_id + 1 {
                index += 1;
                continue;
            }
            *state = index as u64;
            return AppLayerGetTxIterTuple::with_values(
                tx as *const _ as *mut _,
                tx.id() - 1,
                len - index > 1,
            );
        }
        return AppLayerGetTxIterTuple::not_found();
    }
}

pub unsafe extern "C" fn state_get_tx_iterator<S: State<Tx>, Tx: Transaction>(
    _ipproto: u8, _alproto: AppProto, state: *mut std::os::raw::c_void, min_tx_id: u64,
    _max_tx_id: u64, istate: *mut AppLayerGetTxIterState,
) -> AppLayerGetTxIterTuple {
    let state = cast_pointer!(state, S);
    state.get_transaction_iterator(min_tx_id, &mut (*istate).un.u64_)
}

/// AppLayerFrameType trait.
///
/// This is the behavior expected from an enum of frame types. For most instances
/// this behavior can be derived.
///
/// Example:
///
/// #[derive(AppLayerFrameType)]
/// enum SomeProtoFrameType {
///     PDU,
///     Data,
/// }
pub trait AppLayerFrameType {
    /// Create a frame type variant from a u8.
    ///
    /// None will be returned if there is no matching enum variant.
    fn from_u8(value: u8) -> Option<Self> where Self: std::marker::Sized;

    /// Return the u8 value of the enum where the first entry has the value of 0.
    fn as_u8(&self) -> u8;

    /// Create a frame type variant from a &str.
    ///
    /// None will be returned if there is no matching enum variant.
    fn from_str(s: &str) -> Option<Self> where Self: std::marker::Sized;

    /// Return a pointer to a C string of the enum variant suitable as-is for
    /// FFI.
    fn to_cstring(&self) -> *const std::os::raw::c_char;

    /// Converts a C string formatted name to a frame type ID.
    unsafe extern "C" fn ffi_id_from_name(name: *const std::os::raw::c_char) -> i32 where Self: Sized {
        if name.is_null() {
            return -1;
        }
        let frame_id = if let Ok(s) = std::ffi::CStr::from_ptr(name).to_str() {
            Self::from_str(s).map(|t| t.as_u8() as i32).unwrap_or(-1)
        } else {
            -1
        };
        frame_id
    }

    /// Converts a variant ID to an FFI safe name.
    extern "C" fn ffi_name_from_id(id: u8) -> *const std::os::raw::c_char where Self: Sized {
        Self::from_u8(id).map(|s| s.to_cstring()).unwrap_or_else(std::ptr::null)
    }
}

/// AppLayerState trait.
///
/// This is the behavior expected from an enum of state progress. For most instances
/// this behavior can be derived. This is for protocols which do not need direction,
/// like SSH (which is symmetric).
///
/// Example:
///
/// #[derive(AppLayerState)]
/// enum SomeProtoState {
///     Start,
///     Complete,
/// }
pub trait AppLayerState {
    /// Create a state progress variant from a u8.
    ///
    /// None will be returned if there is no matching enum variant.
    fn from_u8(value: u8) -> Option<Self>
    where
        Self: Sized;

    /// Return the u8 value of the enum where the first entry has the value of 0.
    fn as_u8(&self) -> u8;

    /// Create a state progress variant from a &str.
    ///
    /// None will be returned if there is no matching enum variant.
    fn from_str(s: &str) -> Option<Self>
    where
        Self: Sized;

    /// Return a pointer to a C string of the enum variant suitable as-is for
    /// FFI.
    fn to_cstring(&self, to_server: bool) -> *const c_char;

    /// Converts a C string formatted name to a state progress.
    unsafe extern "C" fn ffi_id_from_name(name: *const c_char, dir: u8) -> c_int
    where
        Self: Sized,
    {
        if name.is_null() {
            return -1;
        }
        if let Ok(s) = std::ffi::CStr::from_ptr(name).to_str() {
            let dir = Direction::from(dir);
            let s2 = match dir {
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
            Self::from_str(s2).map(|t| t.as_u8() as c_int).unwrap_or(-1)
        } else {
            -1
        }
    }

    /// Converts a variant ID to an FFI name.
    unsafe extern "C" fn ffi_name_from_id(id: c_int, dir: u8) -> *const c_char
    where
        Self: Sized,
    {
        if id < 0 || id > c_int::from(u8::MAX) {
            return std::ptr::null();
        }
        if let Some(v) = Self::from_u8(id as u8) {
            return v.to_cstring(dir == STREAM_TOSERVER);
        }
        return std::ptr::null();
    }
}
