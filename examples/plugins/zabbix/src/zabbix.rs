use super::parser;
use super::suricata::{
    AppLayerGetTxIterTuple, AppLayerParserConfParserEnabled, AppLayerParserRegisterLogger,
    AppLayerProtoDetectConfProtoDetectionEnabled, AppLayerProtoDetectPMRegisterPatternCS,
    AppLayerRegisterParser, AppLayerRegisterProtocolDetection, AppLayerResult, AppLayerStateData,
    AppLayerTxData, AppProto, Direction, Flow, Frame, Level, RustParser, StreamSlice,
    StringToAppProto, ALPROTO_UNKNOWN, APP_LAYER_EVENT_TYPE_TRANSACTION,
    APP_LAYER_PARSER_OPT_ACCEPT_GAPS, IPPROTO_TCP,
};
use crate::util::{ctor_pointer, SCLog};
use std::collections::VecDeque;
use std::ffi::CStr;
use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_void};

pub(crate) static mut ALPROTO_ZABBIX: AppProto = ALPROTO_UNKNOWN;
static mut ALPROTO_FAILED: AppProto = 0xFFFF;

#[derive(Debug, PartialEq, Eq)]
pub enum ZabbixEvent {
    ErrorDecompression,
    WrongDecompressedLen,
}

impl ZabbixEvent {
    fn from_id(id: i32) -> Option<ZabbixEvent> {
        match id {
            0 => Some(ZabbixEvent::ErrorDecompression),
            1 => Some(ZabbixEvent::WrongDecompressedLen),
            _ => None,
        }
    }

    fn to_cstring(&self) -> &str {
        match *self {
            ZabbixEvent::ErrorDecompression => "error_decompression\0",
            ZabbixEvent::WrongDecompressedLen => "wrong_decompressed_len\0",
        }
    }

    fn as_i32(&self) -> i32 {
        match *self {
            ZabbixEvent::ErrorDecompression => 0,
            ZabbixEvent::WrongDecompressedLen => 1,
        }
    }

    fn from_string(s: &str) -> Option<ZabbixEvent> {
        match s {
            "error_decompression" => Some(ZabbixEvent::ErrorDecompression),
            "wrong_decompressed_len" => Some(ZabbixEvent::WrongDecompressedLen),
            _ => None,
        }
    }

    pub unsafe extern "C" fn get_event_info(
        event_name: *const std::os::raw::c_char,
        event_id: *mut std::os::raw::c_int,
        event_type: *mut std::os::raw::c_int,
    ) -> std::os::raw::c_int {
        if event_name.is_null() {
            return -1;
        }

        let event = match CStr::from_ptr(event_name)
            .to_str()
            .map(ZabbixEvent::from_string)
        {
            Ok(Some(event)) => event.as_i32(),
            _ => {
                return -1;
            }
        };
        *event_type = APP_LAYER_EVENT_TYPE_TRANSACTION;
        *event_id = event as std::os::raw::c_int;
        0
    }

    pub unsafe extern "C" fn get_event_info_by_id(
        event_id: std::os::raw::c_int,
        event_name: *mut *const std::os::raw::c_char,
        event_type: *mut std::os::raw::c_int,
    ) -> i8 {
        if let Some(e) = ZabbixEvent::from_id(event_id) {
            *event_name = e.to_cstring().as_ptr() as *const std::os::raw::c_char;
            *event_type = APP_LAYER_EVENT_TYPE_TRANSACTION;
            return 0;
        }
        -1
    }
}

pub enum ZabbixFrameType {
    Pdu,
    Hdr,
    Data,
}

impl ZabbixFrameType {
    fn from_u8(id: u8) -> Option<ZabbixFrameType> {
        match id {
            0 => Some(ZabbixFrameType::Pdu),
            1 => Some(ZabbixFrameType::Hdr),
            2 => Some(ZabbixFrameType::Data),
            _ => None,
        }
    }

    fn to_cstring(&self) -> *const std::os::raw::c_char {
        let s = match *self {
            ZabbixFrameType::Pdu => "pdu\0",
            ZabbixFrameType::Hdr => "hdr\0",
            ZabbixFrameType::Data => "data\0",
        };
        s.as_ptr() as *const std::os::raw::c_char
    }

    fn as_u8(&self) -> u8 {
        match *self {
            ZabbixFrameType::Pdu => 0,
            ZabbixFrameType::Hdr => 1,
            ZabbixFrameType::Data => 2,
        }
    }

    fn from_str(s: &str) -> Option<ZabbixFrameType> {
        match s {
            "pdu" => Some(ZabbixFrameType::Pdu),
            "hdr" => Some(ZabbixFrameType::Hdr),
            "data" => Some(ZabbixFrameType::Data),
            _ => None,
        }
    }

    pub unsafe extern "C" fn ffi_id_from_name(name: *const std::os::raw::c_char) -> i32 {
        if name.is_null() {
            return -1;
        }
        let frame_id = if let Ok(s) = std::ffi::CStr::from_ptr(name).to_str() {
            ZabbixFrameType::from_str(s)
                .map(|t| t.as_u8() as i32)
                .unwrap_or(-1)
        } else {
            -1
        };
        frame_id
    }

    pub unsafe extern "C" fn ffi_name_from_id(id: u8) -> *const std::os::raw::c_char {
        ZabbixFrameType::from_u8(id)
            .map(|s| s.to_cstring())
            .unwrap_or_else(std::ptr::null)
    }
}

pub struct ZabbixTransaction {
    tx_id: u64,
    pub zabbix: parser::ZabbixPdu,
    tx_data: AppLayerTxData,
}

impl ZabbixTransaction {
    pub fn new(dir: Direction) -> ZabbixTransaction {
        Self {
            tx_id: 0,
            zabbix: parser::ZabbixPdu::default(),
            tx_data: AppLayerTxData::for_direction(dir),
        }
    }
    pub fn set_event(&mut self, event: u8) {
        self.tx_data.set_event(event);
    }
}

#[derive(Default)]
pub struct ZabbixState {
    state_data: AppLayerStateData,
    tx_id: u64,
    transactions: VecDeque<ZabbixTransaction>,
    in_gap: [bool; 2],
    to_skip: [usize; 2],
}

impl ZabbixState {
    pub fn new() -> Self {
        Default::default()
    }

    // Free a transaction by ID.
    fn free_tx(&mut self, tx_id: u64) {
        let len = self.transactions.len();
        let mut found = false;
        let mut index = 0;
        for i in 0..len {
            let tx = &self.transactions[i];
            if tx.tx_id == tx_id + 1 {
                found = true;
                index = i;
                break;
            }
        }
        if found {
            self.transactions.remove(index);
        }
    }

    pub fn get_tx(&mut self, tx_id: u64) -> Option<&ZabbixTransaction> {
        self.transactions.iter().find(|tx| tx.tx_id == tx_id + 1)
    }

    fn process_frames(
        zabbix: &parser::ZabbixPdu,
        stream_slice: &StreamSlice,
        flow: *const Flow,
        input: &[u8],
        remlen: usize,
        tx_id: u64,
    ) {
        let hdrlen = if (zabbix.flags & 4) != 0 {
            4 + 1 + 2 * 8
        } else {
            4 + 1 + 2 * 4
        };
        let _pdu = Frame::new(
            flow,
            stream_slice,
            input,
            (input.len() - remlen) as i64,
            ZabbixFrameType::Pdu as u8,
            tx_id,
        );
        let _hdr = Frame::new(
            flow,
            stream_slice,
            input,
            hdrlen as i64,
            ZabbixFrameType::Hdr as u8,
            tx_id,
        );
        let _data = Frame::new(
            flow,
            stream_slice,
            &input[hdrlen..],
            (input.len() - remlen - hdrlen) as i64,
            ZabbixFrameType::Data as u8,
            tx_id,
        );
    }

    fn parse_zabbix(
        &mut self,
        dir: Direction,
        flow: *const Flow,
        stream_slice: StreamSlice,
    ) -> AppLayerResult {
        if stream_slice.is_gap() {
            self.in_gap[dir.index()] = true;
            return AppLayerResult::ok();
        }
        let input = stream_slice.as_slice();
        if self.in_gap[dir.index()] {
            if parser::check_zabbix(input) {
                self.in_gap[dir.index()] = false;
            } else {
                return AppLayerResult::ok();
            }
        }
        let mut start = input;
        while !start.is_empty() {
            if self.to_skip[dir.index()] > start.len() {
                self.to_skip[dir.index()] -= start.len();
                return AppLayerResult::ok();
            }
            start = &start[self.to_skip[dir.index()]..];
            match parser::parse_zabbix(start) {
                Ok((rem, h)) => {
                    let mut tx = ZabbixTransaction::new(dir);
                    self.tx_id += 1;
                    tx.tx_id = self.tx_id;
                    ZabbixState::process_frames(
                        &h,
                        &stream_slice,
                        flow,
                        start,
                        rem.len(),
                        tx.tx_id,
                    );
                    if h.error_decompression {
                        tx.set_event(ZabbixEvent::ErrorDecompression as u8);
                    }
                    if h.wrong_decompressed_len {
                        tx.set_event(ZabbixEvent::WrongDecompressedLen as u8);
                    }
                    self.to_skip[dir.index()] = h.rem_len as usize;
                    tx.zabbix = h;
                    self.transactions.push_back(tx);
                    start = rem;
                }
                Err(nom7::Err::Incomplete(n1)) => {
                    if let nom7::Needed::Size(n2) = n1 {
                        let consumed = input.len() - start.len();
                        let needed = start.len() + usize::from(n2);
                        return AppLayerResult::incomplete(consumed as u32, needed as u32);
                    } else {
                        return AppLayerResult::err();
                    }
                }
                Err(_) => {
                    return AppLayerResult::err();
                }
            }
        }

        // Input was fully consumed.
        AppLayerResult::ok()
    }
}

// C exports.

extern "C" fn rs_zabbix_state_new(_orig_state: *mut c_void, _orig_proto: AppProto) -> *mut c_void {
    let state = ZabbixState::new();
    let boxed = Box::new(state);
    Box::into_raw(boxed) as *mut c_void
}

unsafe extern "C" fn rs_zabbix_state_free(state: *mut c_void) {
    std::mem::drop(Box::from_raw(state as *mut ZabbixState));
}

unsafe extern "C" fn rs_zabbix_state_tx_free(state: *mut c_void, tx_id: u64) {
    let state = ctor_pointer!(state, ZabbixState);
    state.free_tx(tx_id);
}

unsafe extern "C" fn rs_zabbix_parse_request(
    _flow: *const Flow,
    state: *mut c_void,
    _pstate: *mut c_void,
    stream_slice: StreamSlice,
    _data: *const c_void,
) -> AppLayerResult {
    let state = ctor_pointer!(state, ZabbixState);
    state.parse_zabbix(Direction::ToServer, _flow, stream_slice)
}

unsafe extern "C" fn rs_zabbix_parse_response(
    _flow: *const Flow,
    state: *mut c_void,
    _pstate: *mut c_void,
    stream_slice: StreamSlice,
    _data: *const c_void,
) -> AppLayerResult {
    let state = ctor_pointer!(state, ZabbixState);
    state.parse_zabbix(Direction::ToClient, _flow, stream_slice)
}

unsafe extern "C" fn rs_zabbix_state_get_tx(state: *mut c_void, tx_id: u64) -> *mut c_void {
    let state = ctor_pointer!(state, ZabbixState);
    match state.get_tx(tx_id) {
        Some(tx) => tx as *const _ as *mut _,
        None => std::ptr::null_mut(),
    }
}

unsafe extern "C" fn rs_zabbix_state_get_tx_count(state: *mut c_void) -> u64 {
    let state = ctor_pointer!(state, ZabbixState);
    state.tx_id
}

unsafe extern "C" fn rs_zabbix_tx_get_alstate_progress(_tx: *mut c_void, _direction: u8) -> c_int {
    1
}

#[no_mangle]
pub unsafe extern "C" fn rs_zabbix_get_tx_data(
    tx: *mut std::os::raw::c_void,
) -> *mut AppLayerTxData {
    let tx = &mut *(tx as *mut ZabbixTransaction);
    &mut tx.tx_data
}

#[no_mangle]
pub unsafe extern "C" fn rs_zabbix_get_state_data(
    state: *mut std::os::raw::c_void,
) -> *mut AppLayerStateData {
    let state = &mut *(state as *mut ZabbixState);
    &mut state.state_data
}

pub unsafe extern "C" fn zabbix_get_tx_iterator(
    _ipproto: u8,
    _alproto: AppProto,
    state: *mut std::os::raw::c_void,
    min_tx_id: u64,
    _max_tx_id: u64,
    istate: &mut u64,
) -> AppLayerGetTxIterTuple {
    let state = ctor_pointer!(state, ZabbixState);
    let mut index = *istate as usize;
    let len = state.transactions.len();
    while index < len {
        let tx = state.transactions.get(index).unwrap();
        if tx.tx_id < min_tx_id + 1 {
            index += 1;
            continue;
        }
        *istate = index as u64;
        return AppLayerGetTxIterTuple::with_values(
            tx as *const _ as *mut _,
            tx.tx_id - 1,
            len - index > 1,
        );
    }
    AppLayerGetTxIterTuple::not_found()
}

#[no_mangle]
pub extern "C" fn rs_zabbix_state_progress_completion_status(
    _direction: u8,
) -> std::os::raw::c_int {
    1
}

#[no_mangle]
pub unsafe extern "C" fn rs_zabbix_register_parser() {
    SCLog!(Level::Notice, "Registering zabbix parser");
    //let default_port = CString::new("[10050]").unwrap();
    let parser = RustParser {
        name: b"zabbix\0".as_ptr() as *const c_char,
        default_port: std::ptr::null(),
        ipproto: IPPROTO_TCP,
        probe_ts: None,
        probe_tc: None,
        min_depth: 16,
        max_depth: 16,
        state_new: rs_zabbix_state_new,
        state_free: rs_zabbix_state_free,
        tx_free: rs_zabbix_state_tx_free,
        parse_ts: rs_zabbix_parse_request,
        parse_tc: rs_zabbix_parse_response,
        get_tx_count: rs_zabbix_state_get_tx_count,
        get_tx: rs_zabbix_state_get_tx,

        // unidirectional, always complete after creation
        tx_comp_st_ts: 1,
        tx_comp_st_tc: 1,
        tx_get_progress: rs_zabbix_tx_get_alstate_progress,

        get_eventinfo: Some(ZabbixEvent::get_event_info),
        get_eventinfo_byid: Some(ZabbixEvent::get_event_info_by_id),

        localstorage_new: None,
        localstorage_free: None,
        get_tx_files: None,

        get_tx_iterator: Some(zabbix_get_tx_iterator),
        get_tx_data: rs_zabbix_get_tx_data,
        get_state_data: rs_zabbix_get_state_data,
        apply_tx_config: None,
        flags: APP_LAYER_PARSER_OPT_ACCEPT_GAPS,
        get_frame_id_by_name: Some(ZabbixFrameType::ffi_id_from_name),
        get_frame_name_by_id: Some(ZabbixFrameType::ffi_name_from_id),
    };

    let ip_proto_str = CString::new("tcp").unwrap();
    ALPROTO_FAILED = StringToAppProto("failed\0".as_ptr());

    if AppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_ZABBIX = alproto;
        if AppLayerProtoDetectPMRegisterPatternCS(
            IPPROTO_TCP,
            ALPROTO_ZABBIX,
            b"ZBXD\0".as_ptr() as *const std::os::raw::c_char,
            4,
            0,
            Direction::ToServer as u8,
        ) < 0
        {
            SCLog!(Level::Warning, "Rust zabbix failed to register detection.");
        }

        if AppLayerProtoDetectPMRegisterPatternCS(
            IPPROTO_TCP,
            ALPROTO_ZABBIX,
            b"ZBXD\0".as_ptr() as *const std::os::raw::c_char,
            4,
            0,
            Direction::ToClient as u8,
        ) < 0
        {
            SCLog!(Level::Warning, "Rust zabbix failed to register detection.");
        }

        if AppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
        AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_ZABBIX);
        SCLog!(Level::Notice, "Rust zabbix parser registered.");
    } else {
        SCLog!(
            Level::Notice,
            "Protocol detector and parser disabled for zabbix."
        );
    }
}
