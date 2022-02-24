/* Copyright (C) 2021 Open Information Security Foundation
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
use crate::applayer::{self, *};
use crate::core::{self, AppProto, ALPROTO_FAILED, ALPROTO_UNKNOWN, IPPROTO_TCP};

use std::ffi::CString;

use sawp::error::Error as SawpError;
use sawp::error::ErrorKind as SawpErrorKind;
use sawp::parser::{Direction, Parse};
use sawp::probe::{Probe, Status};
use sawp_modbus::{self, AccessType, ErrorFlags, Flags, Message};

pub const REQUEST_FLOOD: usize = 500; // Default unreplied Modbus requests are considered a flood
pub const MODBUS_PARSER: sawp_modbus::Modbus = sawp_modbus::Modbus {};

static mut ALPROTO_MODBUS: AppProto = ALPROTO_UNKNOWN;

#[derive(AppLayerEvent)]
enum ModbusEvent {
    UnsolicitedResponse,
    InvalidFunctionCode,
    InvalidLength,
    InvalidValue,
    InvalidExceptionCode,
    ValueMismatch,
    Flooded,
    InvalidProtocolId,
}
pub struct ModbusTransaction {
    pub id: u64,

    pub request: Option<Message>,
    pub response: Option<Message>,

    pub tx_data: AppLayerTxData,
}

impl Transaction for ModbusTransaction {
    fn id(&self) -> u64 {
        self.id
    }
}

impl ModbusTransaction {
    pub fn new(id: u64) -> Self {
        Self {
            id,
            request: None,
            response: None,
            tx_data: AppLayerTxData::new(),
        }
    }

    fn set_event(&mut self, event: ModbusEvent) {
        self.tx_data.set_event(event as u8);
    }

    fn set_events_from_flags(&mut self, flags: &Flags<ErrorFlags>) {
        if flags.intersects(ErrorFlags::FUNC_CODE) {
            self.set_event(ModbusEvent::InvalidFunctionCode);
        }
        if flags.intersects(ErrorFlags::DATA_VALUE) {
            self.set_event(ModbusEvent::InvalidValue);
        }
        if flags.intersects(ErrorFlags::DATA_LENGTH) {
            self.set_event(ModbusEvent::InvalidLength);
        }
        if flags.intersects(ErrorFlags::EXC_CODE) {
            self.set_event(ModbusEvent::InvalidExceptionCode);
        }
        if flags.intersects(ErrorFlags::PROTO_ID) {
            self.set_event(ModbusEvent::InvalidProtocolId);
        }
    }
}

pub struct ModbusState {
    pub transactions: Vec<ModbusTransaction>,
    tx_id: u64,
    givenup: bool, // Indicates flood
}

impl State<ModbusTransaction> for ModbusState {
    fn get_transactions(&self) -> &[ModbusTransaction] {
        &self.transactions
    }
}

impl ModbusState {
    pub fn new() -> Self {
        Self {
            transactions: Vec::new(),
            tx_id: 0,
            givenup: false,
        }
    }

    pub fn get_tx(&mut self, tx_id: u64) -> Option<&mut ModbusTransaction> {
        for tx in &mut self.transactions {
            if tx.id == tx_id + 1 {
                return Some(tx);
            }
        }
        None
    }

    /// Searches the requests in order to find one matching the given response. Returns the matching
    /// transaction, if it exists
    pub fn find_request_and_validate(
        &mut self, resp: &mut Message,
    ) -> Option<&mut ModbusTransaction> {
        for tx in &mut self.transactions {
            if let Some(req) = &tx.request {
                if tx.response.is_none() && resp.matches(req) {
                    return Some(tx);
                }
            }
        }
        None
    }

    /// Searches the responses in order to find one matching the given request. Returns the matching
    /// transaction, if it exists
    pub fn find_response_and_validate(
        &mut self, req: &mut Message,
    ) -> Option<&mut ModbusTransaction> {
        for tx in &mut self.transactions {
            if let Some(resp) = &tx.response {
                if tx.request.is_none() && req.matches(resp) {
                    return Some(tx);
                }
            }
        }
        None
    }

    pub fn new_tx(&mut self) -> Option<ModbusTransaction> {
        // Check flood limit
        if self.givenup {
            return None;
        }

        self.tx_id += 1;
        let mut tx = ModbusTransaction::new(self.tx_id);

        if REQUEST_FLOOD != 0 && self.transactions.len() >= REQUEST_FLOOD {
            tx.set_event(ModbusEvent::Flooded);
            self.givenup = true;
        }

        Some(tx)
    }

    pub fn free_tx(&mut self, tx_id: u64) {
        if let Some(index) = self.transactions.iter().position(|tx| tx.id == tx_id + 1) {
            self.transactions.remove(index);

            // Check flood limit
            if self.givenup && REQUEST_FLOOD != 0 && self.transactions.len() < REQUEST_FLOOD {
                self.givenup = false;
            }
        }
    }

    pub fn parse(&mut self, input: &[u8], direction: Direction) -> AppLayerResult {
        let mut rest = input;
        while rest.len() > 0 {
            match MODBUS_PARSER.parse(rest, direction.clone()) {
                Ok((inner_rest, Some(mut msg))) => {
                    match direction {
                        Direction::ToServer | Direction::Unknown => {
                            match self.find_response_and_validate(&mut msg) {
                                Some(tx) => {
                                    tx.set_events_from_flags(&msg.error_flags);
                                    tx.request = Some(msg);
                                }
                                None => {
                                    let mut tx = match self.new_tx() {
                                        Some(tx) => tx,
                                        None => return AppLayerResult::ok(),
                                    };
                                    tx.set_events_from_flags(&msg.error_flags);
                                    tx.request = Some(msg);
                                    self.transactions.push(tx);
                                }
                            }
                        }
                        Direction::ToClient => match self.find_request_and_validate(&mut msg) {
                            Some(tx) => {
                                if msg
                                    .access_type
                                    .intersects(AccessType::READ | AccessType::WRITE)
                                    && msg.error_flags.intersects(
                                        ErrorFlags::DATA_LENGTH | ErrorFlags::DATA_VALUE,
                                    )
                                {
                                    tx.set_event(ModbusEvent::ValueMismatch);
                                } else {
                                    tx.set_events_from_flags(&msg.error_flags);
                                }
                                tx.response = Some(msg);
                            }
                            None => {
                                let mut tx = match self.new_tx() {
                                    Some(tx) => tx,
                                    None => return AppLayerResult::ok(),
                                };
                                if msg
                                    .access_type
                                    .intersects(AccessType::READ | AccessType::WRITE)
                                    && msg.error_flags.intersects(
                                        ErrorFlags::DATA_LENGTH | ErrorFlags::DATA_VALUE,
                                    )
                                {
                                    tx.set_event(ModbusEvent::ValueMismatch);
                                } else {
                                    tx.set_events_from_flags(&msg.error_flags);
                                }
                                tx.response = Some(msg);
                                tx.set_event(ModbusEvent::UnsolicitedResponse);
                                self.transactions.push(tx);
                            }
                        },
                    }

                    if inner_rest.len() >= rest.len() {
                        return AppLayerResult::err();
                    }
                    rest = inner_rest;
                }
                Ok((inner_rest, None)) => {
                    return AppLayerResult::incomplete(
                        (input.len() - inner_rest.len()) as u32,
                        inner_rest.len() as u32 + 1,
                    );
                }
                Err(SawpError {
                    kind: SawpErrorKind::Incomplete(sawp::error::Needed::Size(needed)),
                }) => {
                    return AppLayerResult::incomplete(
                        (input.len() - rest.len()) as u32,
                        (rest.len() + needed.get()) as u32,
                    );
                }
                Err(SawpError {
                    kind: SawpErrorKind::Incomplete(sawp::error::Needed::Unknown),
                }) => {
                    return AppLayerResult::incomplete(
                        (input.len() - rest.len()) as u32,
                        rest.len() as u32 + 1,
                    );
                }
                Err(_) => return AppLayerResult::err(),
            }
        }
        AppLayerResult::ok()
    }
}

/// Probe input to see if it looks like Modbus.
#[no_mangle]
pub extern "C" fn rs_modbus_probe(
    _flow: *const core::Flow, _direction: u8, input: *const u8, len: u32, _rdir: *mut u8,
) -> AppProto {
    let slice: &[u8] = unsafe { std::slice::from_raw_parts(input as *mut u8, len as usize) };
    match MODBUS_PARSER.probe(slice, Direction::Unknown) {
        Status::Recognized => unsafe { ALPROTO_MODBUS },
        Status::Incomplete => ALPROTO_UNKNOWN,
        Status::Unrecognized => unsafe { ALPROTO_FAILED },
    }
}

#[no_mangle]
pub extern "C" fn rs_modbus_state_new(
    _orig_state: *mut std::os::raw::c_void, _orig_proto: AppProto,
) -> *mut std::os::raw::c_void {
    Box::into_raw(Box::new(ModbusState::new())) as *mut std::os::raw::c_void
}

#[no_mangle]
pub extern "C" fn rs_modbus_state_free(state: *mut std::os::raw::c_void) {
    let _state: Box<ModbusState> = unsafe { Box::from_raw(state as *mut ModbusState) };
}

#[no_mangle]
pub unsafe extern "C" fn rs_modbus_state_tx_free(state: *mut std::os::raw::c_void, tx_id: u64) {
    let state = cast_pointer!(state, ModbusState);
    state.free_tx(tx_id);
}

#[no_mangle]
pub unsafe extern "C" fn rs_modbus_parse_request(
    _flow: *const core::Flow, state: *mut std::os::raw::c_void, pstate: *mut std::os::raw::c_void,
    stream_slice: StreamSlice,
    _data: *const std::os::raw::c_void,
) -> AppLayerResult {
    let buf = stream_slice.as_slice();
    if buf.len() == 0 {
        if AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TS) > 0 {
            return AppLayerResult::ok();
        } else {
            return AppLayerResult::err();
        }
    }

    let state = cast_pointer!(state, ModbusState);
    state.parse(buf, Direction::ToServer)
}

#[no_mangle]
pub unsafe extern "C" fn rs_modbus_parse_response(
    _flow: *const core::Flow, state: *mut std::os::raw::c_void, pstate: *mut std::os::raw::c_void,
    stream_slice: StreamSlice,
    _data: *const std::os::raw::c_void,
) -> AppLayerResult {
    let buf = stream_slice.as_slice();
    if buf.len() == 0 {
        if AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TC) > 0 {
            return AppLayerResult::ok();
        } else {
            return AppLayerResult::err();
        }
    }

    let state = cast_pointer!(state, ModbusState);
    state.parse(buf, Direction::ToClient)
}

#[no_mangle]
pub unsafe extern "C" fn rs_modbus_state_get_tx_count(state: *mut std::os::raw::c_void) -> u64 {
    let state = cast_pointer!(state, ModbusState);
    state.tx_id
}

#[no_mangle]
pub unsafe extern "C" fn rs_modbus_state_get_tx(
    state: *mut std::os::raw::c_void, tx_id: u64,
) -> *mut std::os::raw::c_void {
    let state = cast_pointer!(state, ModbusState);
    match state.get_tx(tx_id) {
        Some(tx) => (tx as *mut ModbusTransaction) as *mut std::os::raw::c_void,
        None => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_modbus_tx_get_alstate_progress(
    tx: *mut std::os::raw::c_void, _direction: u8,
) -> std::os::raw::c_int {
    let tx = cast_pointer!(tx, ModbusTransaction);
    tx.response.is_some() as std::os::raw::c_int
}

#[no_mangle]
pub unsafe extern "C" fn rs_modbus_state_get_tx_data(
    tx: *mut std::os::raw::c_void,
) -> *mut AppLayerTxData {
    let tx = cast_pointer!(tx, ModbusTransaction);
    &mut tx.tx_data
}

#[no_mangle]
pub unsafe extern "C" fn rs_modbus_register_parser() {
    let default_port = std::ffi::CString::new("[502]").unwrap();
    let parser = RustParser {
        name: b"modbus\0".as_ptr() as *const std::os::raw::c_char,
        default_port: default_port.as_ptr(),
        ipproto: IPPROTO_TCP,
        probe_ts: Some(rs_modbus_probe),
        probe_tc: Some(rs_modbus_probe),
        min_depth: 0,
        max_depth: 16,
        state_new: rs_modbus_state_new,
        state_free: rs_modbus_state_free,
        tx_free: rs_modbus_state_tx_free,
        parse_ts: rs_modbus_parse_request,
        parse_tc: rs_modbus_parse_response,
        get_tx_count: rs_modbus_state_get_tx_count,
        get_tx: rs_modbus_state_get_tx,
        tx_comp_st_ts: 1,
        tx_comp_st_tc: 1,
        tx_get_progress: rs_modbus_tx_get_alstate_progress,
        get_eventinfo: Some(ModbusEvent::get_event_info),
        get_eventinfo_byid: Some(ModbusEvent::get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_files: None,
        get_tx_iterator: Some(applayer::state_get_tx_iterator::<ModbusState, ModbusTransaction>),
        get_tx_data: rs_modbus_state_get_tx_data,
        apply_tx_config: None,
        flags: 0,
        truncate: None,
        get_frame_id_by_name: None,
        get_frame_name_by_id: None,
    };

    let ip_proto_str = CString::new("tcp").unwrap();
    if AppLayerProtoDetectConfProtoDetectionEnabledDefault(ip_proto_str.as_ptr(), parser.name, false) != 0 {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_MODBUS = alproto;
        if AppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
    }
}

// This struct and accessor functions are used for app-layer-modbus.c tests.
pub mod test {
    use super::ModbusState;
    use sawp_modbus::{Data, Message, Read, Write};
    use std::ffi::c_void;
    #[repr(C)]
    pub struct ModbusMessage(*const c_void);

    #[no_mangle]
    pub unsafe extern "C" fn rs_modbus_message_get_function(msg: *const ModbusMessage) -> u8 {
        let msg = msg.as_ref().unwrap().0 as *const Message;
        let msg = msg.as_ref().unwrap();
        msg.function.raw
    }

    #[no_mangle]
    pub unsafe extern "C" fn rs_modbus_message_get_subfunction(msg: *const ModbusMessage) -> u16 {
        let msg = msg.as_ref().unwrap().0 as *const Message;
        let msg = msg.as_ref().unwrap();
        if let Data::Diagnostic { func, data: _ } = &msg.data {
            func.raw
        } else {
            panic!("wrong modbus message data type");
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn rs_modbus_message_get_read_request_address(
        msg: *const ModbusMessage,
    ) -> u16 {
        let msg = msg.as_ref().unwrap().0 as *const Message;
        let msg = msg.as_ref().unwrap();
        if let Data::Read(Read::Request {
            address,
            quantity: _,
        }) = &msg.data
        {
            *address
        } else {
            panic!("wrong modbus message data type");
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn rs_modbus_message_get_read_request_quantity(
        msg: *const ModbusMessage,
    ) -> u16 {
        let msg = msg.as_ref().unwrap().0 as *const Message;
        let msg = msg.as_ref().unwrap();
        if let Data::Read(Read::Request {
            address: _,
            quantity,
        }) = &msg.data
        {
            *quantity
        } else {
            panic!("wrong modbus message data type");
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn rs_modbus_message_get_rw_multreq_read_address(
        msg: *const ModbusMessage,
    ) -> u16 {
        let msg = msg.as_ref().unwrap().0 as *const Message;
        let msg = msg.as_ref().unwrap();
        if let Data::ReadWrite {
            read:
                Read::Request {
                    address,
                    quantity: _,
                },
            write: _,
        } = &msg.data
        {
            *address
        } else {
            panic!("wrong modbus message data type");
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn rs_modbus_message_get_rw_multreq_read_quantity(
        msg: *const ModbusMessage,
    ) -> u16 {
        let msg = msg.as_ref().unwrap().0 as *const Message;
        let msg = msg.as_ref().unwrap();
        if let Data::ReadWrite {
            read:
                Read::Request {
                    address: _,
                    quantity,
                },
            write: _,
        } = &msg.data
        {
            *quantity
        } else {
            panic!("wrong modbus message data type");
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn rs_modbus_message_get_rw_multreq_write_address(
        msg: *const ModbusMessage,
    ) -> u16 {
        let msg = msg.as_ref().unwrap().0 as *const Message;
        let msg = msg.as_ref().unwrap();
        if let Data::ReadWrite {
            read: _,
            write:
                Write::MultReq {
                    address,
                    quantity: _,
                    data: _,
                },
        } = &msg.data
        {
            *address
        } else {
            panic!("wrong modbus message data type");
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn rs_modbus_message_get_rw_multreq_write_quantity(
        msg: *const ModbusMessage,
    ) -> u16 {
        let msg = msg.as_ref().unwrap().0 as *const Message;
        let msg = msg.as_ref().unwrap();
        if let Data::ReadWrite {
            read: _,
            write:
                Write::MultReq {
                    address: _,
                    quantity,
                    data: _,
                },
        } = &msg.data
        {
            *quantity
        } else {
            panic!("wrong modbus message data type");
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn rs_modbus_message_get_rw_multreq_write_data(
        msg: *const ModbusMessage, data_len: *mut usize,
    ) -> *const u8 {
        let msg = msg.as_ref().unwrap().0 as *const Message;
        let msg = msg.as_ref().unwrap();
        if let Data::ReadWrite {
            read: _,
            write:
                Write::MultReq {
                    address: _,
                    quantity: _,
                    data,
                },
        } = &msg.data
        {
            *data_len = data.len();
            data.as_slice().as_ptr()
        } else {
            panic!("wrong modbus message data type");
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn rs_modbus_message_get_write_multreq_address(
        msg: *const ModbusMessage,
    ) -> u16 {
        let msg = msg.as_ref().unwrap().0 as *const Message;
        let msg = msg.as_ref().unwrap();
        if let Data::Write(Write::MultReq {
            address,
            quantity: _,
            data: _,
        }) = &msg.data
        {
            *address
        } else {
            panic!("wrong modbus message data type");
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn rs_modbus_message_get_write_multreq_quantity(
        msg: *const ModbusMessage,
    ) -> u16 {
        let msg = msg.as_ref().unwrap().0 as *const Message;
        let msg = msg.as_ref().unwrap();
        if let Data::Write(Write::MultReq {
            address: _,
            quantity,
            data: _,
        }) = &msg.data
        {
            *quantity
        } else {
            panic!("wrong modbus message data type");
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn rs_modbus_message_get_write_multreq_data(
        msg: *const ModbusMessage, data_len: *mut usize,
    ) -> *const u8 {
        let msg = msg.as_ref().unwrap().0 as *const Message;
        let msg = msg.as_ref().unwrap();
        if let Data::Write(Write::MultReq {
            address: _,
            quantity: _,
            data,
        }) = &msg.data
        {
            *data_len = data.len();
            data.as_slice().as_ptr()
        } else {
            panic!("wrong modbus message data type");
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn rs_modbus_message_get_and_mask(msg: *const ModbusMessage) -> u16 {
        let msg = msg.as_ref().unwrap().0 as *const Message;
        let msg = msg.as_ref().unwrap();
        if let Data::Write(Write::Mask {
            address: _,
            and_mask,
            or_mask: _,
        }) = &msg.data
        {
            *and_mask
        } else {
            panic!("wrong modbus message data type");
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn rs_modbus_message_get_or_mask(msg: *const ModbusMessage) -> u16 {
        let msg = msg.as_ref().unwrap().0 as *const Message;
        let msg = msg.as_ref().unwrap();
        if let Data::Write(Write::Mask {
            address: _,
            and_mask: _,
            or_mask,
        }) = &msg.data
        {
            *or_mask
        } else {
            panic!("wrong modbus message data type");
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn rs_modbus_message_get_write_address(msg: *const ModbusMessage) -> u16 {
        let msg = msg.as_ref().unwrap().0 as *const Message;
        let msg = msg.as_ref().unwrap();
        if let Data::Write(Write::Other { address, data: _ }) = &msg.data {
            *address
        } else {
            panic!("wrong modbus message data type");
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn rs_modbus_message_get_write_data(msg: *const ModbusMessage) -> u16 {
        let msg = msg.as_ref().unwrap().0 as *const Message;
        let msg = msg.as_ref().unwrap();
        if let Data::Write(Write::Other { address: _, data }) = &msg.data {
            *data
        } else {
            panic!("wrong modbus message data type");
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn rs_modbus_message_get_bytevec_data(
        msg: *const ModbusMessage, data_len: *mut usize,
    ) -> *const u8 {
        let msg = msg.as_ref().unwrap().0 as *const Message;
        let msg = msg.as_ref().unwrap();
        if let Data::ByteVec(data) = &msg.data {
            *data_len = data.len();
            data.as_slice().as_ptr()
        } else {
            panic!("wrong modbus message data type");
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn rs_modbus_state_get_tx_request(
        state: *mut std::os::raw::c_void, tx_id: u64,
    ) -> ModbusMessage {
        let state = cast_pointer!(state, ModbusState);
        if let Some(tx) = state.get_tx(tx_id) {
            if let Some(request) = &tx.request {
                ModbusMessage((request as *const Message) as *const c_void)
            } else {
                ModbusMessage(std::ptr::null())
            }
        } else {
            ModbusMessage(std::ptr::null())
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn rs_modbus_state_get_tx_response(
        state: *mut std::os::raw::c_void, tx_id: u64,
    ) -> ModbusMessage {
        let state = cast_pointer!(state, ModbusState);
        if let Some(tx) = state.get_tx(tx_id) {
            if let Some(response) = &tx.response {
                ModbusMessage((response as *const Message) as *const c_void)
            } else {
                ModbusMessage(std::ptr::null())
            }
        } else {
            ModbusMessage(std::ptr::null())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sawp_modbus::{
        Data, Diagnostic, DiagnosticSubfunction, Exception, ExceptionCode, FunctionCode, Read,
        Write,
    };

    const INVALID_FUNC_CODE: &[u8] = &[
        0x00, 0x00, // Transaction ID
        0x00, 0x00, // Protocol ID
        0x00, 0x02, // Length
        0x00, // Unit ID
        0x00, // Function code
    ];

    const RD_COILS_REQ: &[u8] = &[
        0x00, 0x00, // Transaction ID
        0x00, 0x00, // Protocol ID
        0x00, 0x06, // Length
        0x00, // Unit ID
        0x01, // Function code
        0x78, 0x90, // Starting Address
        0x00, 0x13, // Quantity of coils
    ];

    const RD_COILS_RESP: &[u8] = &[
        0x00, 0x00, // Transaction ID
        0x00, 0x00, // Protocol ID
        0x00, 0x06, // Length
        0x00, // Unit ID
        0x01, // Function code
        0x03, // Byte count
        0xCD, 0x6B, 0x05, // Coil Status
    ];

    const RD_COILS_ERR_RESP: &[u8] = &[
        0x00, 0x00, // Transaction ID
        0x00, 0x00, // Protocol ID
        0x00, 0x03, // Length
        0x00, // Unit ID
        0x81, // Function code
        0xFF, // Exception code
    ];

    const WR_SINGLE_REG_REQ: &[u8] = &[
        0x00, 0x0A, // Transaction ID
        0x00, 0x00, // Protocol ID
        0x00, 0x06, // Length
        0x00, // Unit ID
        0x06, // Function code
        0x00, 0x01, // Register Address
        0x00, 0x03, // Register Value
    ];

    const INVALID_WR_SINGLE_REG_REQ: &[u8] = &[
        0x00, 0x0A, // Transaction ID
        0x00, 0x00, // Protocol ID
        0x00, 0x04, // Length
        0x00, // Unit ID
        0x06, // Function code
        0x00, 0x01, // Register Address
    ];

    const WR_SINGLE_REG_RESP: &[u8] = &[
        0x00, 0x0A, // Transaction ID
        0x00, 0x00, // Protocol ID
        0x00, 0x06, // Length
        0x00, // Unit ID
        0x06, // Function code
        0x00, 0x01, // Register Address
        0x00, 0x03, // Register Value
    ];

    const WR_MULT_REG_REQ: &[u8] = &[
        0x00, 0x0A, // Transaction ID
        0x00, 0x00, // Protocol ID
        0x00, 0x0B, // Length
        0x00, // Unit ID
        0x10, // Function code
        0x00, 0x01, // Starting Address
        0x00, 0x02, // Quantity of Registers
        0x04, // Byte count
        0x00, 0x0A, // Registers Value
        0x01, 0x02,
    ];

    const INVALID_PDU_WR_MULT_REG_REQ: &[u8] = &[
        0x00, 0x0A, // Transaction ID
        0x00, 0x00, // Protocol ID
        0x00, 0x02, // Length
        0x00, // Unit ID
        0x10, // Function code
    ];

    const WR_MULT_REG_RESP: &[u8] = &[
        0x00, 0x0A, // Transaction ID
        0x00, 0x00, // Protocol ID
        0x00, 0x06, // Length
        0x00, // Unit ID
        0x10, // Function code
        0x00, 0x01, // Starting Address
        0x00, 0x02, // Quantity of Registers
    ];

    const MASK_WR_REG_REQ: &[u8] = &[
        0x00, 0x0A, // Transaction ID
        0x00, 0x00, // Protocol ID
        0x00, 0x08, // Length
        0x00, // Unit ID
        0x16, // Function code
        0x00, 0x04, // Reference Address
        0x00, 0xF2, // And_Mask
        0x00, 0x25, // Or_Mask
    ];

    const INVALID_MASK_WR_REG_REQ: &[u8] = &[
        0x00, 0x0A, // Transaction ID
        0x00, 0x00, // Protocol ID
        0x00, 0x06, // Length
        0x00, // Unit ID
        0x16, // Function code
        0x00, 0x04, // Reference Address
        0x00, 0xF2, // And_Mask
    ];

    const MASK_WR_REG_RESP: &[u8] = &[
        0x00, 0x0A, // Transaction ID
        0x00, 0x00, // Protocol ID
        0x00, 0x08, // Length
        0x00, // Unit ID
        0x16, // Function code
        0x00, 0x04, // Reference Address
        0x00, 0xF2, // And_Mask
        0x00, 0x25, // Or_Mask
    ];

    const RD_WR_MULT_REG_REQ: &[u8] = &[
        0x12, 0x34, // Transaction ID
        0x00, 0x00, // Protocol ID
        0x00, 0x11, // Length
        0x00, // Unit ID
        0x17, // Function code
        0x00, 0x03, // Read Starting Address
        0x00, 0x06, // Quantity to Read
        0x00, 0x0E, // Write Starting Address
        0x00, 0x03, // Quantity to Write
        0x06, // Write Byte count
        0x12, 0x34, // Write Registers Value
        0x56, 0x78, 0x9A, 0xBC,
    ];

    // Mismatch value in Byte count 0x0B instead of 0x0C
    const RD_WR_MULT_REG_RESP: &[u8] = &[
        0x12, 0x34, // Transaction ID
        0x00, 0x00, // Protocol ID
        0x00, 0x0E, // Length
        0x00, // Unit ID
        0x17, // Function code
        0x0B, // Byte count
        0x00, 0xFE, // Read Registers Value
        0x0A, 0xCD, 0x00, 0x01, 0x00, 0x03, 0x00, 0x0D, 0x00,
    ];

    const FORCE_LISTEN_ONLY_MODE: &[u8] = &[
        0x0A, 0x00, // Transaction ID
        0x00, 0x00, // Protocol ID
        0x00, 0x06, // Length
        0x00, // Unit ID
        0x08, // Function code
        0x00, 0x04, // Sub-function code
        0x00, 0x00, // Data
    ];

    const INVALID_PROTO_REQ: &[u8] = &[
        0x00, 0x00, // Transaction ID
        0x00, 0x01, // Protocol ID
        0x00, 0x06, // Length
        0x00, // Unit ID
        0x01, // Function code
        0x78, 0x90, // Starting Address
        0x00, 0x13, // Quantity of coils
    ];

    const INVALID_LEN_WR_MULT_REG_REQ: &[u8] = &[
        0x00, 0x0A, // Transaction ID
        0x00, 0x00, // Protocol ID
        0x00, 0x09, // Length
        0x00, // Unit ID
        0x10, // Function code
        0x00, 0x01, // Starting Address
        0x00, 0x02, // Quantity of Registers
        0x04, // Byte count
        0x00, 0x0A, // Registers Value
        0x01, 0x02,
    ];

    const EXCEEDED_LEN_WR_MULT_REG_REQ: &[u8] = &[
        0x00, 0x0A, // Transaction ID
        0x00, 0x00, // Protocol ID
        0xff, 0xfa, // Length
        0x00, // Unit ID
        0x10, // Function code
        0x00, 0x01, // Starting Address
        0x7f, 0xf9, // Quantity of Registers
        0xff, // Byte count
    ];

    #[test]
    fn read_coils() {
        let mut state = ModbusState::new();
        assert_eq!(
            AppLayerResult::ok(),
            state.parse(RD_COILS_REQ, Direction::ToServer)
        );
        assert_eq!(state.transactions.len(), 1);

        let tx = &state.transactions[0];
        let msg = tx.request.as_ref().unwrap();
        assert_eq!(msg.function.code, FunctionCode::RdCoils);
        assert_eq!(
            msg.data,
            Data::Read(Read::Request {
                address: 0x7890,
                quantity: 0x0013
            })
        );

        assert_eq!(
            AppLayerResult::ok(),
            state.parse(RD_COILS_RESP, Direction::ToClient)
        );
        assert_eq!(state.transactions.len(), 1);

        let tx = &state.transactions[0];
        let msg = tx.response.as_ref().unwrap();
        assert_eq!(msg.function.code, FunctionCode::RdCoils);
        assert_eq!(msg.data, Data::Read(Read::Response(vec![0xCD, 0x6B, 0x05])));
    }

    #[test]
    fn write_multiple_registers() {
        let mut state = ModbusState::new();
        assert_eq!(
            AppLayerResult::ok(),
            state.parse(WR_MULT_REG_REQ, Direction::ToServer)
        );
        assert_eq!(state.transactions.len(), 1);

        let tx = &state.transactions[0];
        let msg = tx.request.as_ref().unwrap();
        assert_eq!(msg.function.code, FunctionCode::WrMultRegs);
        assert_eq!(
            msg.data,
            Data::Write(Write::MultReq {
                address: 0x0001,
                quantity: 0x0002,
                data: vec![0x00, 0x0a, 0x01, 0x02],
            })
        );

        assert_eq!(
            AppLayerResult::ok(),
            state.parse(WR_MULT_REG_RESP, Direction::ToClient)
        );
        assert_eq!(state.transactions.len(), 1);

        let tx = &state.transactions[0];
        let msg = tx.response.as_ref().unwrap();
        assert_eq!(msg.function.code, FunctionCode::WrMultRegs);
        assert_eq!(
            msg.data,
            Data::Write(Write::Other {
                address: 0x0001,
                data: 0x0002
            })
        );
    }

    #[test]
    fn read_write_multiple_registers() {
        let mut state = ModbusState::new();
        assert_eq!(
            AppLayerResult::ok(),
            state.parse(RD_WR_MULT_REG_REQ, Direction::ToServer)
        );
        assert_eq!(state.transactions.len(), 1);

        let tx = &state.transactions[0];
        let msg = tx.request.as_ref().unwrap();
        assert_eq!(msg.function.code, FunctionCode::RdWrMultRegs);
        assert_eq!(
            msg.data,
            Data::ReadWrite {
                read: Read::Request {
                    address: 0x0003,
                    quantity: 0x0006,
                },
                write: Write::MultReq {
                    address: 0x000e,
                    quantity: 0x0003,
                    data: vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc]
                }
            }
        );

        assert_eq!(
            AppLayerResult::ok(),
            state.parse(RD_WR_MULT_REG_RESP, Direction::ToClient)
        );
        assert_eq!(state.transactions.len(), 1);

        let tx = &state.transactions[0];
        let msg = tx.response.as_ref().unwrap();
        assert_eq!(msg.function.code, FunctionCode::RdWrMultRegs);
        assert_eq!(
            msg.data,
            Data::Read(Read::Response(vec![
                0x00, 0xFE, 0x0A, 0xCD, 0x00, 0x01, 0x00, 0x03, 0x00, 0x0D, 0x00,
            ]))
        );
    }

    #[test]
    fn force_listen_only_mode() {
        let mut state = ModbusState::new();
        assert_eq!(
            AppLayerResult::ok(),
            state.parse(FORCE_LISTEN_ONLY_MODE, Direction::ToServer)
        );
        assert_eq!(state.transactions.len(), 1);

        let tx = &state.transactions[0];
        let msg = tx.request.as_ref().unwrap();
        assert_eq!(msg.function.code, FunctionCode::Diagnostic);
        assert_eq!(
            msg.data,
            Data::Diagnostic {
                func: Diagnostic {
                    raw: 4,
                    code: DiagnosticSubfunction::ForceListenOnlyMode
                },
                data: vec![0x00, 0x00]
            }
        );
    }

    #[test]
    fn invalid_protocol_version() {
        let mut state = ModbusState::new();
        assert_eq!(
            AppLayerResult::ok(),
            state.parse(INVALID_PROTO_REQ, Direction::ToServer)
        );

        assert_eq!(state.transactions.len(), 1);
        let tx = &state.transactions[0];
        let msg = tx.request.as_ref().unwrap();
        assert_eq!(msg.error_flags, ErrorFlags::PROTO_ID);
    }

    #[test]
    fn unsolicited_response() {
        let mut state = ModbusState::new();
        assert_eq!(
            AppLayerResult::ok(),
            state.parse(RD_COILS_RESP, Direction::ToClient)
        );
        assert_eq!(state.transactions.len(), 1);

        let tx = &state.transactions[0];
        let msg = tx.response.as_ref().unwrap();
        assert_eq!(msg.function.code, FunctionCode::RdCoils);
        assert_eq!(msg.data, Data::Read(Read::Response(vec![0xCD, 0x6B, 0x05])));
    }

    #[test]
    fn invalid_length_request() {
        let mut state = ModbusState::new();
        assert_eq!(
            AppLayerResult::incomplete(15, 4),
            state.parse(INVALID_LEN_WR_MULT_REG_REQ, Direction::ToServer)
        );
        assert_eq!(state.transactions.len(), 1);

        let tx = &state.transactions[0];
        let msg = tx.request.as_ref().unwrap();
        assert_eq!(msg.function.code, FunctionCode::WrMultRegs);
        assert_eq!(
            msg.data,
            Data::Write(Write::MultReq {
                address: 0x0001,
                quantity: 0x0002,
                data: vec![0x00, 0x0a]
            })
        );
        assert_eq!(msg.error_flags, ErrorFlags::DATA_LENGTH);
    }

    #[test]
    fn exception_code_invalid() {
        let mut state = ModbusState::new();
        assert_eq!(
            AppLayerResult::ok(),
            state.parse(RD_COILS_REQ, Direction::ToServer)
        );
        assert_eq!(state.transactions.len(), 1);

        let tx = &state.transactions[0];
        let msg = tx.request.as_ref().unwrap();
        assert_eq!(msg.function.code, FunctionCode::RdCoils);
        assert_eq!(
            msg.data,
            Data::Read(Read::Request {
                address: 0x7890,
                quantity: 0x0013
            })
        );

        assert_eq!(
            AppLayerResult::ok(),
            state.parse(RD_COILS_ERR_RESP, Direction::ToClient)
        );
        assert_eq!(state.transactions.len(), 1);

        let tx = &state.transactions[0];
        let msg = tx.response.as_ref().unwrap();
        assert_eq!(
            msg.data,
            Data::Exception(Exception {
                raw: 255,
                code: ExceptionCode::Unknown
            })
        );
        assert_eq!(msg.error_flags, ErrorFlags::EXC_CODE);
    }

    #[test]
    fn fragmentation_1_adu_in_2_tcp_packets() {
        let mut state = ModbusState::new();
        assert_eq!(
            AppLayerResult::incomplete(0, 15),
            state.parse(
                &RD_COILS_REQ[0..(RD_COILS_REQ.len() - 3)],
                Direction::ToServer
            )
        );
        assert_eq!(state.transactions.len(), 0);
        assert_eq!(
            AppLayerResult::ok(),
            state.parse(RD_COILS_REQ, Direction::ToServer)
        );
        assert_eq!(state.transactions.len(), 1);

        let tx = &state.transactions[0];
        assert!(&tx.request.is_some());
        let msg = tx.request.as_ref().unwrap();
        assert_eq!(msg.function.code, FunctionCode::RdCoils);
        assert_eq!(
            msg.data,
            Data::Read(Read::Request {
                address: 0x7890,
                quantity: 0x0013
            })
        );
    }

    #[test]
    fn fragmentation_2_adu_in_1_tcp_packet() {
        let req = [RD_COILS_REQ, WR_MULT_REG_REQ].concat();
        let resp = [RD_COILS_RESP, WR_MULT_REG_RESP].concat();

        let mut state = ModbusState::new();
        assert_eq!(AppLayerResult::ok(), state.parse(&req, Direction::ToServer));
        assert_eq!(state.transactions.len(), 2);

        let tx = &state.transactions[0];
        let msg = tx.request.as_ref().unwrap();
        assert_eq!(msg.function.code, FunctionCode::RdCoils);
        assert_eq!(
            msg.data,
            Data::Read(Read::Request {
                address: 0x7890,
                quantity: 0x0013
            })
        );

        let tx = &state.transactions[1];
        let msg = tx.request.as_ref().unwrap();
        assert_eq!(msg.function.code, FunctionCode::WrMultRegs);
        assert_eq!(
            msg.data,
            Data::Write(Write::MultReq {
                address: 0x0001,
                quantity: 0x0002,
                data: vec![0x00, 0x0a, 0x01, 0x02]
            })
        );

        assert_eq!(
            AppLayerResult::ok(),
            state.parse(&resp, Direction::ToClient)
        );
        assert_eq!(state.transactions.len(), 2);

        let tx = &state.transactions[0];
        let msg = tx.response.as_ref().unwrap();
        assert_eq!(msg.function.code, FunctionCode::RdCoils);
        assert_eq!(msg.data, Data::Read(Read::Response(vec![0xCD, 0x6B, 0x05])));

        let tx = &state.transactions[1];
        let msg = tx.response.as_ref().unwrap();
        assert_eq!(msg.function.code, FunctionCode::WrMultRegs);
        assert_eq!(
            msg.data,
            Data::Write(Write::Other {
                address: 0x0001,
                data: 0x0002
            })
        );
    }

    #[test]
    fn exceeded_length_request() {
        let mut state = ModbusState::new();
        assert_eq!(
            AppLayerResult::ok(),
            state.parse(EXCEEDED_LEN_WR_MULT_REG_REQ, Direction::ToServer)
        );

        assert_eq!(state.transactions.len(), 1);
        let tx = &state.transactions[0];
        let msg = tx.request.as_ref().unwrap();
        assert_eq!(msg.error_flags, ErrorFlags::DATA_LENGTH);
    }

    #[test]
    fn invalid_pdu_len_req() {
        let mut state = ModbusState::new();
        assert_eq!(
            AppLayerResult::ok(),
            state.parse(INVALID_PDU_WR_MULT_REG_REQ, Direction::ToServer)
        );

        assert_eq!(state.transactions.len(), 1);

        let tx = &state.transactions[0];
        let msg = tx.request.as_ref().unwrap();
        assert_eq!(msg.function.code, FunctionCode::WrMultRegs);
        assert_eq!(msg.data, Data::ByteVec(vec![]));
    }

    #[test]
    fn mask_write_register_request() {
        let mut state = ModbusState::new();
        assert_eq!(
            AppLayerResult::ok(),
            state.parse(MASK_WR_REG_REQ, Direction::ToServer)
        );
        assert_eq!(state.transactions.len(), 1);

        let tx = &state.transactions[0];
        let msg = tx.request.as_ref().unwrap();
        assert_eq!(msg.function.code, FunctionCode::MaskWrReg);
        assert_eq!(
            msg.data,
            Data::Write(Write::Mask {
                address: 0x0004,
                and_mask: 0x00f2,
                or_mask: 0x0025
            })
        );

        assert_eq!(
            AppLayerResult::ok(),
            state.parse(MASK_WR_REG_RESP, Direction::ToClient)
        );
        assert_eq!(state.transactions.len(), 1);

        let tx = &state.transactions[0];
        let msg = tx.response.as_ref().unwrap();
        assert_eq!(msg.function.code, FunctionCode::MaskWrReg);
        assert_eq!(
            msg.data,
            Data::Write(Write::Mask {
                address: 0x0004,
                and_mask: 0x00f2,
                or_mask: 0x0025
            })
        );
    }

    #[test]
    fn write_single_register_request() {
        let mut state = ModbusState::new();
        assert_eq!(
            AppLayerResult::ok(),
            state.parse(WR_SINGLE_REG_REQ, Direction::ToServer)
        );
        assert_eq!(state.transactions.len(), 1);

        let tx = &state.transactions[0];
        let msg = tx.request.as_ref().unwrap();
        assert_eq!(msg.function.code, FunctionCode::WrSingleReg);
        assert_eq!(
            msg.data,
            Data::Write(Write::Other {
                address: 0x0001,
                data: 0x0003
            })
        );

        assert_eq!(
            AppLayerResult::ok(),
            state.parse(WR_SINGLE_REG_RESP, Direction::ToClient)
        );
        assert_eq!(state.transactions.len(), 1);

        let tx = &state.transactions[0];
        let msg = tx.response.as_ref().unwrap();
        assert_eq!(msg.function.code, FunctionCode::WrSingleReg);
        assert_eq!(
            msg.data,
            Data::Write(Write::Other {
                address: 0x0001,
                data: 0x0003
            })
        );
    }

    #[test]
    fn invalid_mask_write_register_request() {
        let mut state = ModbusState::new();
        assert_eq!(
            AppLayerResult::ok(),
            state.parse(INVALID_MASK_WR_REG_REQ, Direction::ToServer)
        );
        assert_eq!(state.transactions.len(), 1);

        let tx = &state.transactions[0];
        let msg = tx.request.as_ref().unwrap();
        assert_eq!(msg.function.code, FunctionCode::MaskWrReg);
        assert_eq!(msg.error_flags, ErrorFlags::DATA_LENGTH);
        assert_eq!(msg.data, Data::ByteVec(vec![0x00, 0x04, 0x00, 0xF2]));

        assert_eq!(
            AppLayerResult::ok(),
            state.parse(MASK_WR_REG_RESP, Direction::ToClient)
        );
        assert_eq!(state.transactions.len(), 1);

        let tx = &state.transactions[0];
        let msg = tx.response.as_ref().unwrap();
        assert_eq!(msg.function.code, FunctionCode::MaskWrReg);
        assert_eq!(
            msg.data,
            Data::Write(Write::Mask {
                address: 0x0004,
                and_mask: 0x00f2,
                or_mask: 0x0025
            })
        );
    }

    #[test]
    fn invalid_write_single_register_request() {
        let mut state = ModbusState::new();
        assert_eq!(
            AppLayerResult::ok(),
            state.parse(INVALID_WR_SINGLE_REG_REQ, Direction::ToServer)
        );
        assert_eq!(state.transactions.len(), 1);

        let tx = &state.transactions[0];
        let msg = tx.request.as_ref().unwrap();
        assert_eq!(msg.function.code, FunctionCode::WrSingleReg);
        assert_eq!(msg.error_flags, ErrorFlags::DATA_LENGTH);
        assert_eq!(msg.data, Data::ByteVec(vec![0x00, 0x01]));

        assert_eq!(
            AppLayerResult::ok(),
            state.parse(WR_SINGLE_REG_RESP, Direction::ToClient)
        );
        assert_eq!(state.transactions.len(), 1);

        let tx = &state.transactions[0];
        let msg = tx.response.as_ref().unwrap();
        assert_eq!(msg.function.code, FunctionCode::WrSingleReg);
        assert_eq!(
            msg.data,
            Data::Write(Write::Other {
                address: 0x0001,
                data: 0x0003
            })
        );
    }

    #[test]
    fn invalid_function_code() {
        let mut state = ModbusState::new();
        assert_eq!(
            AppLayerResult::ok(),
            state.parse(INVALID_FUNC_CODE, Direction::ToServer)
        );
        assert_eq!(state.transactions.len(), 1);

        let tx = &state.transactions[0];
        let msg = tx.request.as_ref().unwrap();
        assert_eq!(msg.function.code, FunctionCode::Unknown);
        assert_eq!(msg.data, Data::ByteVec(vec![]));
    }
}
