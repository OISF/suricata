/* Copyright (C) 2018-2020 Open Information Security Foundation
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

use std;
use crate::core::{self, ALPROTO_UNKNOWN, AppProto, Flow, IPPROTO_TCP};
use std::mem::transmute;
use crate::applayer::{self, *};
use std::ffi::CString;
use nom;
use super::parser;

static mut ALPROTO_NEWMODBUS: AppProto = ALPROTO_UNKNOWN;

/* Modbus Protocol version. */
pub const MODBUS_PROTOCOL_VER: u16 = 0x0000;

/* Modbus Function Code Categories. */
// TODO - confirm if those should really be u8
pub const MODBUS_CAT_NONE: u8 =                   0x0;
pub const MODBUS_CAT_PUBLIC_ASSIGNED: u8 =      1<<0;
pub const MODBUS_CAT_PUBLIC_UNASSIGNED: u8 =    1<<1;
pub const MODBUS_CAT_USER_DEFINED: u8 =         1<<2;
pub const MODBUS_CAT_RESERVED: u8 =             1<<3;
pub const MODBUS_CAT_ALL: u8 =                   0xFF;

/* Modbus Function Code. */
pub const MODBUS_FUNC_NONE: u8 =                 0x00;

/* Modbus Read/Write function and Access Types. */
pub const MODBUS_TYP_NONE: u8 =                  0x0;
pub const MODBUS_TYP_ACCESS_MASK: u8 =           0x03;
pub const MODBUS_TYP_READ: u8 =                 1<<0;
pub const MODBUS_TYP_WRITE: u8 =                1<<1;
pub const MODBUS_TYP_ACCESS_FUNCTION_MASK: u8 =  0x3C;
pub const MODBUS_TYP_BIT_ACCESS_MASK: u8 =       0x0C;
pub const MODBUS_TYP_DISCRETES: u8 =            1<<2;
pub const MODBUS_TYP_COILS: u8 =                1<<3;
pub const MODBUS_TYP_WORD_ACCESS_MASK: u8 =      0x30;
pub const MODBUS_TYP_INPUT: u8 =                1<<4;
pub const MODBUS_TYP_HOLDING: u8 =              1<<5;
pub const MODBUS_TYP_SINGLE: u8 =               1<<6;
pub const MODBUS_TYP_MULTIPLE: u8 =             1<<7;
pub const MODBUS_TYP_WRITE_SINGLE: u8 =         MODBUS_TYP_WRITE | MODBUS_TYP_SINGLE;
pub const MODBUS_TYP_WRITE_MULTIPLE: u8 =       MODBUS_TYP_WRITE | MODBUS_TYP_MULTIPLE;
pub const MODBUS_TYP_READ_WRITE_MULTIPLE: u8 =  MODBUS_TYP_READ | MODBUS_TYP_WRITE | MODBUS_TYP_MULTIPLE;

/* Modbus Read/Write function and Access Types. */
// TODO I think those exactly the same as the last three above, can we delete them, therefore?
// pub const MODBUS_TYP_WRITE_SINGLE         MODBUS_TYP_WRITE | MODBUS_TYP_SINGLE;
// pub const MODBUS_TYP_WRITE_MULTIPLE       MODBUS_TYP_WRITE | MODBUS_TYP_MULTIPLE;
// pub const MODBUS_TYP_READ_WRITE_MULTIPLE  MODBUS_TYP_READ | MODBUS_TYP_WRITE | MODBUS_TYP_MULTIPLE;

// Modbus Application Protocol Header (MBAP) size
pub const MODBUS_PDA_HEADER_LEN: usize = 7; 

/* Modbus Protocol Data Unit (PDU) length range. */
pub const MODBUS_MIN_ADU_LEN: usize =   2;
pub const MODBUS_MAX_ADU_LEN: usize =  254; 
// TODO confirm MODBUS PDU MAX value with tests and pcaps, documentation says max is 253
// Unless it's being used like that because the length field in the MBAP header contains the length
// including next field, which is unit address (1 byte), in which case, yes, if we compare 
// with that in mind, max is 254. but, then, min len would be... 3? still confused
// TODO should this really be usize? I'm having trouble using it, because header length is
// u16. Not sure how to handle this properly...

/* Modbus Unit Identifier range. */
pub const MODBUS_MIN_INVALID_UNIT_ID: u8 = 247;
pub const MODBUS_MAX_INVALID_UNIT_ID: u8 = 255;

/* Modbus Quantity range. */
pub const MODBUS_MIN_QUANTITY: u8                =     0;
pub const MODBUS_MAX_QUANTITY_IN_BIT_ACCESS: u16 =  2000;
pub const MODBUS_MAX_QUANTITY_IN_WORD_ACCESS: u8 =   125;

/* Modbus Count range. */
pub const MODBUS_MIN_COUNT: u8  =     1;
pub const MODBUS_MAX_COUNT: u16 =    250;

/* Modbus Function Code. */
pub const MODBUS_FUNC_READCOILS: u8 =           0x01;
pub const MODBUS_FUNC_READDISCINPUTS: u8 =      0x02;
pub const MODBUS_FUNC_READHOLDREGS: u8 =        0x03;
pub const MODBUS_FUNC_READINPUTREGS: u8 =       0x04;
pub const MODBUS_FUNC_WRITESINGLECOIL: u8 =     0x05;
pub const MODBUS_FUNC_WRITESINGLEREG: u8 =      0x06;
pub const MODBUS_FUNC_READEXCSTATUS: u8 =       0x07;
pub const MODBUS_FUNC_DIAGNOSTIC: u8 =          0x08;
pub const MODBUS_FUNC_GETCOMEVTCOUNTER: u8 =    0x0b;
pub const MODBUS_FUNC_GETCOMEVTLOG: u8 =        0x0c;
pub const MODBUS_FUNC_WRITEMULTCOILS: u8 =      0x0f;
pub const MODBUS_FUNC_WRITEMULTREGS: u8 =       0x10;
pub const MODBUS_FUNC_REPORTSERVERID: u8 =      0x11;
pub const MODBUS_FUNC_READFILERECORD: u8 =      0x14;
pub const MODBUS_FUNC_WRITEFILERECORD: u8 =     0x15;
pub const MODBUS_FUNC_MASKWRITEREG: u8 =        0x16;
pub const MODBUS_FUNC_READWRITEMULTREGS: u8 =   0x17;
pub const MODBUS_FUNC_READFIFOQUEUE: u8 =       0x18;
pub const MODBUS_FUNC_ENCAPINTTRANS: u8 =       0x2b;
pub const MODBUS_FUNC_MASK: u8 =                0x7f;
pub const MODBUS_FUNC_ERRORMASK: u8 =           0x80;

/* Modbus Diagnostic functions: Subfunction Code. */
pub const MODBUS_SUBFUNC_QUERY_DATA: u16 =           0x00;
pub const MODBUS_SUBFUNC_RESTART_COM: u16 =          0x01;
pub const MODBUS_SUBFUNC_DIAG_REGS: u16 =            0x02;
pub const MODBUS_SUBFUNC_CHANGE_DELIMITER: u16 =     0x03;
pub const MODBUS_SUBFUNC_LISTEN_MODE: u16 =          0x04;
pub const MODBUS_SUBFUNC_CLEAR_REGS: u16 =           0x0a;
pub const MODBUS_SUBFUNC_BUS_MSG_COUNT: u16 =        0x0b;
pub const MODBUS_SUBFUNC_COM_ERR_COUNT: u16 =        0x0c;
pub const MODBUS_SUBFUNC_EXCEPT_ERR_COUNT: u16 =     0x0d;
pub const MODBUS_SUBFUNC_SERVER_MSG_COUNT: u16 =     0x0e;
pub const MODBUS_SUBFUNC_SERVER_NO_RSP_COUNT: u16 =  0x0f;
pub const MODBUS_SUBFUNC_SERVER_NAK_COUNT: u16 =     0x10;
pub const MODBUS_SUBFUNC_SERVER_BUSY_COUNT: u16 =    0x11;
pub const MODBUS_SUBFUNC_SERVER_CHAR_COUNT: u16 =    0x12;
pub const MODBUS_SUBFUNC_CLEAR_COUNT: u16 =          0x14;

/* Modbus Encapsulated Interface Transport function: MEI type. */
pub const MODBUS_MEI_ENCAPINTTRANS_CAN: u8 =   0x0d;
pub const MODBUS_MEI_ENCAPINTTRANS_READ: u8 =  0x0e;

/* Modbus Exception Codes. */
pub const MODBUS_ERROR_CODE_ILLEGAL_FUNCTION: u8 =      0x01;
pub const MODBUS_ERROR_CODE_ILLEGAL_DATA_ADDRESS: u8 =  0x02;
pub const MODBUS_ERROR_CODE_ILLEGAL_DATA_VALUE: u8 =    0x03;
pub const MODBUS_ERROR_CODE_SERVER_DEVICE_FAILURE: u8 = 0x04;
pub const MODBUS_ERROR_CODE_MEMORY_PARITY_ERROR: u8 =   0x08;

/* Macro to convert quantity value (in bit) into count value (in word):
 count = Ceil(quantity/8) */
 //TODO this macro
// #define CEIL(quantity) (((quantity) + 7)>>3)

/* Modbus Default unreplied Modbus requests are considered a flood */
pub const MODBUS_CONFIG_DEFAULT_REQUEST_FLOOD: u32 = 500;

/* Modbus default stream reassembly depth */
pub const MODBUS_CONFIG_DEFAULT_STREAM_DEPTH: u32 = 0;

static mut request_flood: u32 = MODBUS_CONFIG_DEFAULT_REQUEST_FLOOD;
static mut stream_depth: u32 = MODBUS_CONFIG_DEFAULT_STREAM_DEPTH;

#[repr(packed, C)]
pub struct NewModbusHeader {
    pub transaction_id: u16,
    pub protocol_id: u16,
    pub length: u16,
    pub unit_id: u8,
}

impl NewModbusHeader {
    pub fn new() -> NewModbusHeader {
        NewModbusHeader {
            transaction_id: 0,
            protocol_id: MODBUS_PROTOCOL_VER,
            length: 0,
            unit_id: 0,
        }
    }

    //TODO will the simplest parser come here? Will I need a simpler method that will be struct independent? most likely...
    
}


//TODO check and adapt these
pub struct NewModbusTransaction {
    tx_id: u64,
    pub request: Option<String>,
    pub response: Option<String>,

    de_state: Option<*mut core::DetectEngineState>,
    events: *mut core::AppLayerDecoderEvents,
    tx_data: AppLayerTxData,
}

impl NewModbusTransaction {
    pub fn new() -> NewModbusTransaction {
        NewModbusTransaction {
            tx_id: 0,
            request: None,
            response: None,
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

impl Drop for NewModbusTransaction {
    fn drop(&mut self) {
        self.free();
    }
}

pub struct NewModbusState {
    tx_id: u64,
    transactions: Vec<NewModbusTransaction>,
    request_gap: bool,
    response_gap: bool,
}

impl NewModbusState {
    pub fn new() -> Self {
        Self {
            tx_id: 0,
            transactions: Vec::new(),
            request_gap: false,
            response_gap: false,
        }
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

    pub fn get_tx(&mut self, tx_id: u64) -> Option<&NewModbusTransaction> {
        for tx in &mut self.transactions {
            if tx.tx_id == tx_id + 1 {
                return Some(tx);
            }
        }
        return None;
    }

    fn new_tx(&mut self) -> NewModbusTransaction {
        let mut tx = NewModbusTransaction::new();
        self.tx_id += 1;
        tx.tx_id = self.tx_id;
        return tx;
    }

    fn find_request(&mut self) -> Option<&mut NewModbusTransaction> {
        for tx in &mut self.transactions {
            if tx.response.is_none() {
                return Some(tx);
            }
        }
        None
    }

    fn parse_request(&mut self, input: &[u8]) -> AppLayerResult {
        // We're not interested in empty requests.
        if input.len() == 0 {
            return AppLayerResult::ok();
        }

        // If there was gap, check we can sync up again.
        if self.request_gap {
            if probe(input).is_err() {
                // The parser now needs to decide what to do as we are not in sync.
                // For this newmodbus, we'll just try again next time.
                return AppLayerResult::ok();
            }

            // It looks like we're in sync with a message header, clear gap
            // state and keep parsing.
            self.request_gap = false;
        }

        let mut start = input;
        while start.len() > 0 {
            match parser::parse_message(start) {
                Ok((rem, request)) => {
                    start = rem;

                    SCLogNotice!("Request: {}", request);
                    let mut tx = self.new_tx();
                    tx.request = Some(request);
                    self.transactions.push(tx);
                },
                Err(nom::Err::Incomplete(_)) => {
                    // Not enough data. This parser doesn't give us a good indication
                    // of how much data is missing so just ask for one more byte so the
                    // parse is called as soon as more data is received.
                    let consumed = input.len() - start.len();
                    let needed = start.len() + 1;
                    return AppLayerResult::incomplete(consumed as u32, needed as u32);
                },
                Err(_) => {
                    return AppLayerResult::err();
                },
            }
        }

        // Input was fully consumed.
        return AppLayerResult::ok();
    }

    fn parse_response(&mut self, input: &[u8]) -> AppLayerResult {
        // We're not interested in empty responses.
        if input.len() == 0 {
            return AppLayerResult::ok();
        }

        let mut start = input;
        while start.len() > 0 {
            match parser::parse_message(start) {
                Ok((rem, response)) => {
                    start = rem;

                    match self.find_request() {
                        Some(tx) => {
                            tx.response = Some(response);
                            SCLogNotice!("Found response for request:");
                            SCLogNotice!("- Request: {:?}", tx.request);
                            SCLogNotice!("- Response: {:?}", tx.response);
                        }
                        None => {}
                    }
                }
                Err(nom::Err::Incomplete(_)) => {
                    let consumed = input.len() - start.len();
                    let needed = start.len() + 1;
                    return AppLayerResult::incomplete(consumed as u32, needed as u32);
                }
                Err(_) => {
                    return AppLayerResult::err();
                }
            }
        }

        // All input was fully consumed.
        return AppLayerResult::ok();
    }

    fn tx_iterator(
        &mut self,
        min_tx_id: u64,
        state: &mut u64,
    ) -> Option<(&NewModbusTransaction, u64, bool)> {
        let mut index = *state as usize;
        let len = self.transactions.len();

        while index < len {
            let tx = &self.transactions[index];
            if tx.tx_id < min_tx_id + 1 {
                index += 1;
                continue;
            }
            *state = index as u64;
            return Some((tx, tx.tx_id - 1, (len - index) > 1));
        }

        return None;
    }

    fn on_request_gap(&mut self, _size: u32) {
        self.request_gap = true;
    }

    fn on_response_gap(&mut self, _size: u32) {
        self.response_gap = true;
    }
}


/// Probe for a valid header.
///
/// TODO CHANGE THIS
/// For Modbus Application Packet (MBAP) Header, the size is fixed
// /// at 7 bytes
// fn probe(input: &[u8]) -> nom::IResult<&[u8], ()> {
//     let (size) = cmp::assert_eq!(input.len(),std::mem::size_of<NewModbusHeader>())?;
//     Ok((rem, ()))
// }


/// Probe for a valid header.
///
/// As this newmodbus protocol uses messages prefixed with the size
/// as a string followed by a ':', we look at up to the first 10
/// characters for that pattern.
fn probe(input: &[u8]) -> nom::IResult<&[u8], ()> {
    let size = std::cmp::min(10, input.len());
    let (rem, prefix) = nom::bytes::complete::take(size)(input)?;
    nom::sequence::terminated(
        nom::bytes::complete::take_while1(nom::character::is_digit),
        nom::bytes::complete::tag(":"),
    )(prefix)?;
    Ok((rem, ()))
}

// C exports.

export_tx_get_detect_state!(
    rs_newmodbus_tx_get_detect_state,
    NewModbusTransaction
);
export_tx_set_detect_state!(
    rs_newmodbus_tx_set_detect_state,
    NewModbusTransaction
);

/// C entry point for a probing parser.
#[no_mangle]
pub extern "C" fn rs_newmodbus_probing_parser(
    _flow: *const Flow,
    _direction: u8,
    input: *const u8,
    input_len: u32,
    _rdir: *mut u8
) -> AppProto {
    // Need at least 2 bytes.
    if input_len > 1 && input != std::ptr::null_mut() {
        let slice = build_slice!(input, input_len as usize);
        if probe(slice).is_ok() {
            return unsafe { ALPROTO_NEWMODBUS };
        }
    }
    return ALPROTO_UNKNOWN;
}

#[no_mangle]
pub extern "C" fn rs_newmodbus_state_new(_orig_state: *mut std::os::raw::c_void, _orig_proto: AppProto) -> *mut std::os::raw::c_void {
    let state = NewModbusState::new();
    let boxed = Box::new(state);
    return unsafe { transmute(boxed) };
}

#[no_mangle]
pub extern "C" fn rs_newmodbus_state_free(state: *mut std::os::raw::c_void) {
    // Just unbox...
    let _drop: Box<NewModbusState> = unsafe { transmute(state) };
}

#[no_mangle]
pub extern "C" fn rs_newmodbus_state_tx_free(
    state: *mut std::os::raw::c_void,
    tx_id: u64,
) {
    let state = cast_pointer!(state, NewModbusState);
    state.free_tx(tx_id);
}

#[no_mangle]
pub extern "C" fn rs_newmodbus_parse_request(
    _flow: *const Flow,
    state: *mut std::os::raw::c_void,
    pstate: *mut std::os::raw::c_void,
    input: *const u8,
    input_len: u32,
    _data: *const std::os::raw::c_void,
    _flags: u8,
) -> AppLayerResult {
    let eof = unsafe {
        if AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF) > 0 {
            true
        } else {
            false
        }
    };

    if eof {
        // If needed, handled EOF, or pass it into the parser.
        return AppLayerResult::ok();
    }

    let state = cast_pointer!(state, NewModbusState);

    if input == std::ptr::null_mut() && input_len > 0 {
        // Here we have a gap signaled by the input being null, but a greater
        // than 0 input_len which provides the size of the gap.
        state.on_request_gap(input_len);
        AppLayerResult::ok()
    } else {
        let buf = build_slice!(input, input_len as usize);
        state.parse_request(buf)
    }
}

#[no_mangle]
pub extern "C" fn rs_newmodbus_parse_response(
    _flow: *const Flow,
    state: *mut std::os::raw::c_void,
    pstate: *mut std::os::raw::c_void,
    input: *const u8,
    input_len: u32,
    _data: *const std::os::raw::c_void,
    _flags: u8,
) -> AppLayerResult {
    let _eof = unsafe {
        if AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF) > 0 {
            true
        } else {
            false
        }
    };
    let state = cast_pointer!(state, NewModbusState);

    if input == std::ptr::null_mut() && input_len > 0 {
        // Here we have a gap signaled by the input being null, but a greater
        // than 0 input_len which provides the size of the gap.
        state.on_response_gap(input_len);
        AppLayerResult::ok()
    } else {
        let buf = build_slice!(input, input_len as usize);
        state.parse_response(buf).into()
    }
}

#[no_mangle]
pub extern "C" fn rs_newmodbus_state_get_tx(
    state: *mut std::os::raw::c_void,
    tx_id: u64,
) -> *mut std::os::raw::c_void {
    let state = cast_pointer!(state, NewModbusState);
    match state.get_tx(tx_id) {
        Some(tx) => {
            return unsafe { transmute(tx) };
        }
        None => {
            return std::ptr::null_mut();
        }
    }
}

#[no_mangle]
pub extern "C" fn rs_newmodbus_state_get_tx_count(
    state: *mut std::os::raw::c_void,
) -> u64 {
    let state = cast_pointer!(state, NewModbusState);
    return state.tx_id;
}

#[no_mangle]
pub extern "C" fn rs_newmodbus_tx_get_alstate_progress(
    tx: *mut std::os::raw::c_void,
    _direction: u8,
) -> std::os::raw::c_int {
    let tx = cast_pointer!(tx, NewModbusTransaction);

    // Transaction is done if we have a response.
    if tx.response.is_some() {
        return 1;
    }
    return 0;
}

#[no_mangle]
pub extern "C" fn rs_newmodbus_state_get_events(
    tx: *mut std::os::raw::c_void
) -> *mut core::AppLayerDecoderEvents {
    let tx = cast_pointer!(tx, NewModbusTransaction);
    return tx.events;
}

#[no_mangle]
pub extern "C" fn rs_newmodbus_state_get_event_info(
    _event_name: *const std::os::raw::c_char,
    _event_id: *mut std::os::raw::c_int,
    _event_type: *mut core::AppLayerEventType,
) -> std::os::raw::c_int {
    return -1;
}

#[no_mangle]
pub extern "C" fn rs_newmodbus_state_get_event_info_by_id(_event_id: std::os::raw::c_int,
                                                         _event_name: *mut *const std::os::raw::c_char,
                                                         _event_type: *mut core::AppLayerEventType
) -> i8 {
    return -1;
}
#[no_mangle]
pub extern "C" fn rs_newmodbus_state_get_tx_iterator(
    _ipproto: u8,
    _alproto: AppProto,
    state: *mut std::os::raw::c_void,
    min_tx_id: u64,
    _max_tx_id: u64,
    istate: &mut u64,
) -> applayer::AppLayerGetTxIterTuple {
    let state = cast_pointer!(state, NewModbusState);
    match state.tx_iterator(min_tx_id, istate) {
        Some((tx, out_tx_id, has_next)) => {
            let c_tx = unsafe { transmute(tx) };
            let ires = applayer::AppLayerGetTxIterTuple::with_values(
                c_tx,
                out_tx_id,
                has_next,
            );
            return ires;
        }
        None => {
            return applayer::AppLayerGetTxIterTuple::not_found();
        }
    }
}

/// Get the request buffer for a transaction from C.
///
/// No required for parsing, but an example function for retrieving a
/// pointer to the request buffer from C for detection.
#[no_mangle]
pub extern "C" fn rs_newmodbus_get_request_buffer(
    tx: *mut std::os::raw::c_void,
    buf: *mut *const u8,
    len: *mut u32,
) -> u8
{
    let tx = cast_pointer!(tx, NewModbusTransaction);
    if let Some(ref request) = tx.request {
        if request.len() > 0 {
            unsafe {
                *len = request.len() as u32;
                *buf = request.as_ptr();
            }
            return 1;
        }
    }
    return 0;
}

/// Get the response buffer for a transaction from C.
#[no_mangle]
pub extern "C" fn rs_newmodbus_get_response_buffer(
    tx: *mut std::os::raw::c_void,
    buf: *mut *const u8,
    len: *mut u32,
) -> u8
{
    let tx = cast_pointer!(tx, NewModbusTransaction);
    if let Some(ref response) = tx.response {
        if response.len() > 0 {
            unsafe {
                *len = response.len() as u32;
                *buf = response.as_ptr();
            }
            return 1;
        }
    }
    return 0;
}

export_tx_data_get!(rs_newmodbus_get_tx_data, NewModbusTransaction);

// Parser name as a C style string.
const PARSER_NAME: &'static [u8] = b"newmodbus\0";

#[no_mangle]
pub unsafe extern "C" fn rs_newmodbus_register_parser() {
    let default_port = CString::new("[7000]").unwrap();
    let parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const std::os::raw::c_char,
        default_port: default_port.as_ptr(),
        ipproto: IPPROTO_TCP,
        probe_ts: Some(rs_newmodbus_probing_parser),
        probe_tc: Some(rs_newmodbus_probing_parser),
        min_depth: 0,
        max_depth: 16,
        state_new: rs_newmodbus_state_new,
        state_free: rs_newmodbus_state_free,
        tx_free: rs_newmodbus_state_tx_free,
        parse_ts: rs_newmodbus_parse_request,
        parse_tc: rs_newmodbus_parse_response,
        get_tx_count: rs_newmodbus_state_get_tx_count,
        get_tx: rs_newmodbus_state_get_tx,
        tx_comp_st_ts: 1,
        tx_comp_st_tc: 1,
        tx_get_progress: rs_newmodbus_tx_get_alstate_progress,
        get_de_state: rs_newmodbus_tx_get_detect_state,
        set_de_state: rs_newmodbus_tx_set_detect_state,
        get_events: Some(rs_newmodbus_state_get_events),
        get_eventinfo: Some(rs_newmodbus_state_get_event_info),
        get_eventinfo_byid : Some(rs_newmodbus_state_get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_files: None,
        get_tx_iterator: Some(rs_newmodbus_state_get_tx_iterator),
        get_tx_data: rs_newmodbus_get_tx_data,
        apply_tx_config: None,
        flags: APP_LAYER_PARSER_OPT_ACCEPT_GAPS,
        truncate: None,
    };

    let ip_proto_str = CString::new("tcp").unwrap();

    if AppLayerProtoDetectConfProtoDetectionEnabled(
        ip_proto_str.as_ptr(),
        parser.name,
    ) != 0
    {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_NEWMODBUS = alproto;
        if AppLayerParserConfParserEnabled(
            ip_proto_str.as_ptr(),
            parser.name,
        ) != 0
        {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
        SCLogNotice!("Rust newmodbus parser registered.");
    } else {
        SCLogNotice!("Protocol detector and parser disabled for NEWMODBUS.");
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::applayer::AppLayerResult;
    use crate::core;
    use std::cmp;
    use std::mem;

    #[test]
    fn test_header_constructor() {
        let mut header_valid = NewModbusHeader::new();
        header_valid.transaction_id = 0x000A;
        header_valid.protocol_id = MODBUS_PROTOCOL_VER;
        header_valid.length = 0x0008;
        header_valid.unit_id = 0x00;

        assert_eq!(7,mem::size_of::<NewModbusHeader>());
    }

    #[test]
    fn test_max_pdu_length() {
        // TODO what's the best way to test this?
        unimplemented!("Still to understand best way to check this. PCAPs?");
    }

    #[test]
    fn test_probe() { ///TODO re-write
        assert!(probe(b"1").is_err());
        assert!(probe(b"1:").is_ok());
        assert!(probe(b"123456789:").is_ok());
        assert!(probe(b"0123456789:").is_err());
    }

    #[test]
    fn test_incomplete() {
        let mut state = NewModbusState::new();
        let buf = b"5:Hello3:bye";

        let r = state.parse_request(&buf[0..0]);
        assert_eq!(r, AppLayerResult{ status: 0, consumed: 0, needed: 0});

        let r = state.parse_request(&buf[0..1]);
        assert_eq!(r, AppLayerResult{ status: 1, consumed: 0, needed: 2});

        let r = state.parse_request(&buf[0..2]);
        assert_eq!(r, AppLayerResult{ status: 1, consumed: 0, needed: 3});

        // This is the first message and only the first message.
        let r = state.parse_request(&buf[0..7]);
        assert_eq!(r, AppLayerResult{ status: 0, consumed: 0, needed: 0});

        // The first message and a portion of the second.
        let r = state.parse_request(&buf[0..9]);
        assert_eq!(r, AppLayerResult{ status: 1, consumed: 7, needed: 3});
    }
}
