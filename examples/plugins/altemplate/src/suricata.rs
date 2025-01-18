// This file is kind of the include required by API
// completed by helper functions

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};

// Type definitions
pub type AppProto = u16;
pub type AppLayerEventType = c_int;

// Constant definitions
pub const ALPROTO_UNKNOWN: AppProto = 0;

pub const IPPROTO_TCP: u8 = 6;

pub const APP_LAYER_PARSER_OPT_ACCEPT_GAPS: u32 = 0x00000001;

pub const APP_LAYER_PARSER_EOF_TC: u16 = 0x0040;
pub const APP_LAYER_PARSER_EOF_TS: u16 = 0x0020;

pub const APP_LAYER_EVENT_TYPE_TRANSACTION: i32 = 1;

pub const SIGMATCH_NOOPT: u16 = 1;
pub const SIGMATCH_INFO_STICKY_BUFFER: u16 = 0x200;

//pub const STREAM_TOCLIENT: u8 = 0x08;

// Opaque definitions
pub enum DetectEngineState {}
pub enum AppLayerDecoderEvents {}
pub enum Flow {}

// Enum definitions
#[repr(C)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Direction {
    ToClient = 0x08,
}

#[allow(dead_code)]
#[derive(Debug)]
#[repr(C)]
pub enum Level {
    NotSet = -1,
    None = 0,

    Error,
    Warning,
    Notice,
    Info,
    Perf,
    Config,
    Debug,
}

// Struct definitions
#[repr(C)]
#[allow(non_snake_case)]
pub struct SCPlugin {
    pub name: *const libc::c_char,
    pub license: *const libc::c_char,
    pub author: *const libc::c_char,
    pub Init: extern "C" fn(),
}

#[repr(C)]
#[allow(non_snake_case)]
pub struct SCAppLayerPlugin {
    pub version: u64,
    pub name: *const libc::c_char,
    pub Register: unsafe extern "C" fn(),
    pub KeywordsRegister: unsafe extern "C" fn(),
    pub logname: *const libc::c_char,
    pub confname: *const libc::c_char,
    pub Logger: unsafe extern "C" fn(
        tx: *const std::os::raw::c_void,
        jb: *mut std::os::raw::c_void,
    ) -> bool,
}

#[repr(C)]
#[derive(Default, Debug, PartialEq, Eq)]
pub struct AppLayerTxConfig {
    log_flags: u8,
}

#[repr(C)]
#[derive(Default, Debug, PartialEq, Eq)]
pub struct LoggerFlags {
    flags: u32,
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq)]
pub struct AppLayerTxData {
    pub config: AppLayerTxConfig,
    pub updated_tc: bool,
    pub updated_ts: bool,
    logged: LoggerFlags,
    pub files_opened: u32,
    pub files_logged: u32,
    pub files_stored: u32,

    pub file_flags: u16,
    pub file_tx: u8,

    pub guessed_applayer_logged: u8,

    detect_flags_ts: u64,
    detect_flags_tc: u64,

    de_state: *mut DetectEngineState,
    pub events: *mut AppLayerDecoderEvents,
}

#[repr(C)]
#[derive(Default, Debug, PartialEq, Eq, Copy, Clone)]
pub struct AppLayerStateData {
    pub file_flags: u16,
}

#[repr(C)]
#[derive(Default, Debug, PartialEq, Eq, Copy, Clone)]
pub struct AppLayerResult {
    pub status: i32,
    pub consumed: u32,
    pub needed: u32,
}

#[repr(C)]
pub struct StreamSlice {
    input: *const u8,
    input_len: u32,
    flags: u8,
    offset: u64,
}

#[repr(C)]
pub struct AppLayerGetTxIterTuple {
    tx_ptr: *mut std::os::raw::c_void,
    tx_id: u64,
    has_next: bool,
}

#[repr(C)]
#[derive(Debug)]
pub struct FileContainer {
    pub head: *mut c_void,
    pub tail: *mut c_void,
}

#[repr(C)]
pub struct StreamingBufferConfig {
    pub buf_size: u32,

    pub max_regions: u16,
    pub region_gap: u32,
    // do not bother with real prototypes
    pub calloc: Option<unsafe extern "C" fn()>,
    pub realloc: Option<unsafe extern "C" fn()>,
    pub free: Option<unsafe extern "C" fn()>,
}

#[allow(non_snake_case)]
#[repr(C)]
pub struct AppLayerGetFileState {
    pub fc: *mut FileContainer,
    pub cfg: *const StreamingBufferConfig,
}

#[repr(C)]
#[allow(non_snake_case)]
pub struct SCSigTableElmt {
    pub name: *const libc::c_char,
    pub desc: *const libc::c_char,
    pub url: *const libc::c_char,
    pub flags: u16,
    pub Setup: unsafe extern "C" fn(
        de: *mut c_void,
        s: *mut c_void,
        raw: *const std::os::raw::c_char,
    ) -> c_int,
    pub Free: Option<unsafe extern "C" fn(de: *mut c_void, ptr: *mut c_void)>,
    pub AppLayerTxMatch: Option<
        unsafe extern "C" fn(
            de: *mut c_void,
            f: *mut c_void,
            flags: u8,
            state: *mut c_void,
            tx: *mut c_void,
            sig: *const c_void,
            ctx: *const c_void,
        ) -> c_int,
    >,
}

// Function type definitions for RustParser struct
pub type ParseFn = unsafe extern "C" fn(
    flow: *const Flow,
    state: *mut c_void,
    pstate: *mut c_void,
    stream_slice: StreamSlice,
    data: *const c_void,
) -> AppLayerResult;
pub type ProbeFn = unsafe extern "C" fn(
    flow: *const Flow,
    flags: u8,
    input: *const u8,
    input_len: u32,
    rdir: *mut u8,
) -> AppProto;
pub type StateAllocFn = extern "C" fn(*mut c_void, AppProto) -> *mut c_void;
pub type StateFreeFn = unsafe extern "C" fn(*mut c_void);
pub type StateTxFreeFn = unsafe extern "C" fn(*mut c_void, u64);
pub type StateGetTxFn = unsafe extern "C" fn(*mut c_void, u64) -> *mut c_void;
pub type StateGetTxCntFn = unsafe extern "C" fn(*mut c_void) -> u64;
pub type StateGetProgressFn = unsafe extern "C" fn(*mut c_void, u8) -> c_int;
pub type GetEventInfoFn =
    unsafe extern "C" fn(*const c_char, *mut c_int, *mut AppLayerEventType) -> c_int;
pub type GetEventInfoByIdFn =
    unsafe extern "C" fn(c_int, *mut *const c_char, *mut AppLayerEventType) -> i8;
pub type LocalStorageNewFn = extern "C" fn() -> *mut c_void;
pub type LocalStorageFreeFn = extern "C" fn(*mut c_void);
pub type GetTxFilesFn = unsafe extern "C" fn(*mut c_void, *mut c_void, u8) -> AppLayerGetFileState;
pub type GetTxIteratorFn = unsafe extern "C" fn(
    ipproto: u8,
    alproto: AppProto,
    state: *mut c_void,
    min_tx_id: u64,
    max_tx_id: u64,
    istate: &mut u64,
) -> AppLayerGetTxIterTuple;
pub type GetTxDataFn = unsafe extern "C" fn(*mut c_void) -> *mut AppLayerTxData;
pub type GetStateDataFn = unsafe extern "C" fn(*mut c_void) -> *mut AppLayerStateData;
pub type ApplyTxConfigFn = unsafe extern "C" fn(*mut c_void, *mut c_void, c_int, AppLayerTxConfig);
pub type GetFrameIdByName = unsafe extern "C" fn(*const c_char) -> c_int;
pub type GetFrameNameById = unsafe extern "C" fn(u8) -> *const c_char;

#[repr(C)]
pub struct RustParser {
    pub name: *const c_char,
    pub default_port: *const c_char,
    pub ipproto: u8,
    pub probe_ts: Option<ProbeFn>,
    pub probe_tc: Option<ProbeFn>,
    pub min_depth: u16,
    pub max_depth: u16,
    pub state_new: StateAllocFn,
    pub state_free: StateFreeFn,
    pub parse_ts: ParseFn,
    pub parse_tc: ParseFn,
    pub get_tx_count: StateGetTxCntFn,
    pub get_tx: StateGetTxFn,
    pub tx_free: StateTxFreeFn,

    pub tx_comp_st_ts: c_int,
    pub tx_comp_st_tc: c_int,
    pub tx_get_progress: StateGetProgressFn,

    pub get_eventinfo: Option<GetEventInfoFn>,
    pub get_eventinfo_byid: Option<GetEventInfoByIdFn>,
    pub localstorage_new: Option<LocalStorageNewFn>,
    pub localstorage_free: Option<LocalStorageFreeFn>,

    pub get_tx_files: Option<GetTxFilesFn>,

    pub get_tx_iterator: Option<GetTxIteratorFn>,

    pub get_state_data: GetStateDataFn,

    pub get_tx_data: GetTxDataFn,
    pub apply_tx_config: Option<ApplyTxConfigFn>,
    pub flags: u32,
    pub get_frame_id_by_name: Option<GetFrameIdByName>,
    pub get_frame_name_by_id: Option<GetFrameNameById>,
}

// Suricata functions to use
extern "C" {
    pub fn ConfGet(key: *const c_char, res: *mut *const c_char) -> i8;
    pub fn SCLogMessage(
        level: c_int, filename: *const std::os::raw::c_char, line: std::os::raw::c_uint,
        function: *const std::os::raw::c_char, subsystem: *const std::os::raw::c_char,
        message: *const std::os::raw::c_char,
    ) -> c_int;

    pub fn AppLayerParserStateIssetFlag(state: *mut c_void, flag: u16) -> u16;

    pub fn AppLayerProtoDetectConfProtoDetectionEnabled(
        ipproto: *const c_char, proto: *const c_char,
    ) -> c_int;

    pub fn AppLayerRegisterProtocolDetection(
        parser: *const RustParser, enable_default: c_int,
    ) -> AppProto;
    pub fn AppLayerParserConfParserEnabled(ipproto: *const c_char, proto: *const c_char) -> c_int;
    pub fn AppLayerRegisterParser(parser: *const RustParser, alproto: AppProto) -> c_int;
    pub fn SCPluginRegisterAppLayer(plugin: *const SCAppLayerPlugin) -> c_int;
    pub fn AppLayerDecoderEventsSetEventRaw(events: *mut *mut AppLayerDecoderEvents, event: u8);
    pub fn AppLayerParserRegisterLogger(pproto: u8, alproto: AppProto);
    pub fn DetectHelperBufferMpmRegister(
        name: *const c_char, desc: *const c_char, alproto: AppProto, toclient: bool,
        toserver: bool,
        get_data: unsafe extern "C" fn(
            *mut c_void,
            *const c_void,
            *const c_void,
            u8,
            *const c_void,
            i32,
        ) -> *mut c_void,
    ) -> c_int;
    pub fn DetectHelperGetData(
        de: *mut c_void, transforms: *const c_void, flow: *const c_void, flow_flags: u8,
        tx: *const c_void, list_id: c_int,
        get_buf: unsafe extern "C" fn(*const c_void, u8, *mut *const u8, *mut u32) -> bool,
    ) -> *mut c_void;
    pub fn DetectHelperKeywordRegister(kw: *const SCSigTableElmt) -> c_int;
    pub fn DetectSignatureSetAppProto(s: *mut c_void, alproto: AppProto) -> c_int;
    pub fn DetectBufferSetActiveList(de: *mut c_void, s: *mut c_void, bufid: c_int) -> c_int;
}

// Helper implementations to feel like usual

// Jsonbuilder opaque with implementation using C API to feel like usual
pub enum JsonBuilder {}

impl JsonBuilder {
    pub fn close(&mut self) -> Result<(), JsonError> {
        if unsafe { !jb_close(self) } {
            return Err(JsonError::SuricataError);
        }
        Ok(())
    }
    pub fn open_object(&mut self, key: &str) -> Result<(), JsonError> {
        let keyc = CString::new(key).unwrap();
        if unsafe { !jb_open_object(self, keyc.as_ptr()) } {
            return Err(JsonError::SuricataError);
        }
        Ok(())
    }
    pub fn set_string(&mut self, key: &str, val: &str) -> Result<(), JsonError> {
        let keyc = CString::new(key).unwrap();
        let valc = CString::new(val.escape_default().to_string()).unwrap();
        if unsafe { !jb_set_string(self, keyc.as_ptr(), valc.as_ptr()) } {
            return Err(JsonError::SuricataError);
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum JsonError {
    SuricataError,
}

extern "C" {
    pub fn jb_set_string(jb: &mut JsonBuilder, key: *const c_char, val: *const c_char) -> bool;
    pub fn jb_close(jb: &mut JsonBuilder) -> bool;
    pub fn jb_open_object(jb: &mut JsonBuilder, key: *const c_char) -> bool;
}

// Helper functions
impl AppLayerResult {
    pub fn ok() -> Self {
        Default::default()
    }
    pub fn err() -> Self {
        Self {
            status: -1,
            ..Default::default()
        }
    }
    pub fn incomplete(consumed: u32, needed: u32) -> Self {
        Self {
            status: 1,
            consumed,
            needed,
        }
    }
}

impl StreamSlice {
    pub fn as_slice(&self) -> &[u8] {
        if self.input.is_null() && self.input_len == 0 {
            unsafe {
                return std::slice::from_raw_parts(
                    std::ptr::NonNull::<u8>::dangling().as_ptr(),
                    self.input_len as usize,
                );
            }
        }
        unsafe { std::slice::from_raw_parts(self.input, self.input_len as usize) }
    }
    pub fn is_gap(&self) -> bool {
        self.input.is_null() && self.input_len > 0
    }
    pub fn gap_size(&self) -> u32 {
        self.input_len
    }
}

impl AppLayerGetTxIterTuple {
    pub fn with_values(
        tx_ptr: *mut std::os::raw::c_void, tx_id: u64, has_next: bool,
    ) -> AppLayerGetTxIterTuple {
        AppLayerGetTxIterTuple {
            tx_ptr,
            tx_id,
            has_next,
        }
    }
    pub fn not_found() -> AppLayerGetTxIterTuple {
        AppLayerGetTxIterTuple {
            tx_ptr: std::ptr::null_mut(),
            tx_id: 0,
            has_next: false,
        }
    }
}

impl AppLayerTxData {
    pub fn new() -> Self {
        Self {
            config: AppLayerTxConfig::default(),
            logged: LoggerFlags::default(),
            files_opened: 0,
            files_logged: 0,
            files_stored: 0,
            file_flags: 0,
            file_tx: 0,
            guessed_applayer_logged: 0,
            updated_tc: true,
            updated_ts: true,
            detect_flags_ts: 0,
            detect_flags_tc: 0,
            de_state: std::ptr::null_mut(),
            events: std::ptr::null_mut(),
        }
    }
    pub fn set_event(&mut self, event: u8) {
        unsafe {
            AppLayerDecoderEventsSetEventRaw(&mut self.events, event);
        }
    }
}

// Helper functions to feel like usual

// Return the string value of a configuration value.
pub fn conf_get(key: &str) -> Option<&str> {
    let mut vptr: *const c_char = std::ptr::null_mut();

    unsafe {
        let s = CString::new(key).unwrap();
        if ConfGet(s.as_ptr(), &mut vptr) != 1 {
            return None;
        }
    }

    if vptr.is_null() {
        return None;
    }

    let value = std::str::from_utf8(unsafe { CStr::from_ptr(vptr).to_bytes() }).unwrap();

    return Some(value);
}

// Macro definitions

macro_rules! cast_pointer {
    ($ptr:ident, $ty:ty) => {
        &mut *($ptr as *mut $ty)
    };
}
pub(crate) use cast_pointer;

// This macro returns the function name.
//
// This macro has been borrowed from https://github.com/popzxc/stdext-rs, which
// is released under the MIT license as there is currently no macro in Rust
// to provide the function name.
macro_rules! function {
    () => {{
        // Okay, this is ugly, I get it. However, this is the best we can get on a stable rust.
        fn __f() {}
        fn type_name_of<T>(_: T) -> &'static str {
            std::any::type_name::<T>()
        }
        let name = type_name_of(__f);
        &name[..name.len() - 5]
    }};
}
pub(crate) use function;

macro_rules!SCLog {
    ($level:expr, $($arg:tt)*) => {
        $crate::suricata::sclog($level, file!(), line!(), crate::suricata::function!(),
                &(format!($($arg)*)));
    }
}

pub(crate) use SCLog;

pub fn sclog(level: Level, filename: &str, line: u32, function: &str, message: &str) {
    let filenamec = CString::new(filename).unwrap();
    let functionc = CString::new(function).unwrap();
    let modulec = CString::new("altemplate").unwrap();
    let messagec = CString::new(message).unwrap();
    unsafe {
        SCLogMessage(
            level as i32,
            filenamec.as_ptr(),
            line,
            (functionc).as_ptr(),
            (modulec).as_ptr(),
            (messagec).as_ptr(),
        );
    }
}

#[macro_export]
macro_rules!SCLogNotice {
    ($($arg:tt)*) => {
        $crate::suricata::sclog(Level::Notice, file!(), line!(), crate::suricata::function!(),
                &(format!($($arg)*)));
    }
}
pub(crate) use SCLogNotice;

#[macro_export]
macro_rules!SCLogError {
    ($($arg:tt)*) => {
        $crate::suricata::sclog(Level::Error, file!(), line!(), crate::suricata::function!(),
                &(format!($($arg)*)));
    }
}
pub(crate) use SCLogError;

#[macro_export]
macro_rules! build_slice {
    ($buf:ident, $len:expr) => {
        std::slice::from_raw_parts($buf, $len)
    };
}
pub(crate) use build_slice;
