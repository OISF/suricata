/* Copyright (C) 2020-2023 Open Information Security Foundation
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

// Author: Frank Honza <frank.honza@dcso.de>
//         Sascha Steinbiss <sascha.steinbiss@dcso.de>

use super::parser;
use crate::applayer;
use crate::applayer::*;
use crate::core::{AppProto, Flow, ALPROTO_UNKNOWN, IPPROTO_TCP};
use crate::frames::*;
use nom7::Err;
use std;
use std::ffi::CString;

static mut ALPROTO_RFB: AppProto = ALPROTO_UNKNOWN;

#[derive(FromPrimitive, Debug, AppLayerEvent)]
pub enum RFBEvent {
    UnimplementedSecurityType,
    UnknownSecurityResult,
    MalformedMessage,
    ConfusedState,
}

#[derive(AppLayerFrameType)]
pub enum RFBFrameType {
    Pdu,
}
pub struct RFBTransaction {
    tx_id: u64,
    pub complete: bool,
    pub chosen_security_type: Option<u32>,

    pub tc_server_protocol_version: Option<parser::ProtocolVersion>,
    pub ts_client_protocol_version: Option<parser::ProtocolVersion>,
    pub tc_supported_security_types: Option<parser::SupportedSecurityTypes>,
    pub ts_security_type_selection: Option<parser::SecurityTypeSelection>,
    pub tc_server_security_type: Option<parser::ServerSecurityType>,
    pub tc_vnc_challenge: Option<parser::VncAuth>,
    pub ts_vnc_response: Option<parser::VncAuth>,
    pub ts_client_init: Option<parser::ClientInit>,
    pub tc_security_result: Option<parser::SecurityResult>,
    pub tc_failure_reason: Option<parser::FailureReason>,
    pub tc_server_init: Option<parser::ServerInit>,

    tx_data: applayer::AppLayerTxData,
}

impl Transaction for RFBTransaction {
    fn id(&self) -> u64 {
        self.tx_id
    }
}

impl Default for RFBTransaction {
    fn default() -> Self {
        Self::new()
    }
}

impl RFBTransaction {
    pub fn new() -> Self {
        Self {
            tx_id: 0,
            complete: false,
            chosen_security_type: None,

            tc_server_protocol_version: None,
            ts_client_protocol_version: None,
            tc_supported_security_types: None,
            ts_security_type_selection: None,
            tc_server_security_type: None,
            tc_vnc_challenge: None,
            ts_vnc_response: None,
            ts_client_init: None,
            tc_security_result: None,
            tc_failure_reason: None,
            tc_server_init: None,

            tx_data: applayer::AppLayerTxData::new(),
        }
    }

    fn set_event(&mut self, event: RFBEvent) {
        self.tx_data.set_event(event as u8);
    }
}

pub struct RFBState {
    state_data: AppLayerStateData,
    tx_id: u64,
    transactions: Vec<RFBTransaction>,
    state: parser::RFBGlobalState,
}

impl State<RFBTransaction> for RFBState {
    fn get_transaction_count(&self) -> usize {
        self.transactions.len()
    }

    fn get_transaction_by_index(&self, index: usize) -> Option<&RFBTransaction> {
        self.transactions.get(index)
    }
}

impl Default for RFBState {
    fn default() -> Self {
        Self::new()
    }
}

impl RFBState {
    pub fn new() -> Self {
        Self {
            state_data: AppLayerStateData::new(),
            tx_id: 0,
            transactions: Vec::new(),
            state: parser::RFBGlobalState::TCServerProtocolVersion,
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

    pub fn get_tx(&mut self, tx_id: u64) -> Option<&RFBTransaction> {
        self.transactions.iter().find(|tx| tx.tx_id == tx_id + 1)
    }

    fn new_tx(&mut self) -> RFBTransaction {
        let mut tx = RFBTransaction::new();
        self.tx_id += 1;
        tx.tx_id = self.tx_id;
        return tx;
    }

    fn get_current_tx(&mut self) -> Option<&mut RFBTransaction> {
        let tx_id = self.tx_id;
        self.transactions.iter_mut().find(|tx| tx.tx_id == tx_id)
    }

    fn parse_request(&mut self, flow: *const Flow, stream_slice: StreamSlice) -> AppLayerResult {
        let input = stream_slice.as_slice();

        // We're not interested in empty requests.
        if input.is_empty() {
            return AppLayerResult::ok();
        }

        let mut current = input;
        let mut consumed = 0;
        SCLogDebug!("request_state {}, input_len {}", self.state, input.len());
        loop {
            if current.is_empty() {
                return AppLayerResult::ok();
            }
            match self.state {
                parser::RFBGlobalState::TSClientProtocolVersion => {
                    match parser::parse_protocol_version(current) {
                        Ok((rem, request)) => {
                            consumed += current.len() - rem.len();
                            let _pdu = Frame::new(
                                flow,
                                &stream_slice,
                                current,
                                consumed as i64,
                                RFBFrameType::Pdu as u8,
                            );

                            current = rem;

                            if request.major == "003" && request.minor == "003" {
                                // in version 3.3 the server decided security type
                                self.state = parser::RFBGlobalState::TCServerSecurityType;
                            } else {
                                self.state = parser::RFBGlobalState::TCSupportedSecurityTypes;
                            }

                            if let Some(current_transaction) = self.get_current_tx() {
                                current_transaction.ts_client_protocol_version = Some(request);
                            } else {
                                debug_validate_fail!(
                                    "no transaction set at protocol selection stage"
                                );
                            }
                        }
                        Err(Err::Incomplete(_)) => {
                            return AppLayerResult::incomplete(
                                consumed as u32,
                                (current.len() + 1) as u32,
                            );
                        }
                        Err(_) => {
                            // We even failed to parse the protocol version.
                            return AppLayerResult::err();
                        }
                    }
                }
                parser::RFBGlobalState::TSSecurityTypeSelection => {
                    match parser::parse_security_type_selection(current) {
                        Ok((rem, request)) => {
                            consumed += current.len() - rem.len();
                            let _pdu = Frame::new(
                                flow,
                                &stream_slice,
                                current,
                                consumed as i64,
                                RFBFrameType::Pdu as u8,
                            );

                            current = rem;

                            let chosen_security_type = request.security_type;

                            if let Some(current_transaction) = self.get_current_tx() {
                                current_transaction.ts_security_type_selection = Some(request);
                                current_transaction.chosen_security_type =
                                    Some(chosen_security_type as u32);
                            } else {
                                debug_validate_fail!("no transaction set at security type stage");
                            }

                            match chosen_security_type {
                                2 => self.state = parser::RFBGlobalState::TCVncChallenge,
                                1 => self.state = parser::RFBGlobalState::TSClientInit,
                                _ => {
                                    if let Some(current_transaction) = self.get_current_tx() {
                                        current_transaction
                                            .set_event(RFBEvent::UnimplementedSecurityType);
                                    }
                                    // We have just have seen a security type we don't know about.
                                    // This is not bad per se, it might just mean this is a
                                    // proprietary one not in the spec.
                                    // Continue the flow but stop trying to map the protocol.
                                    self.state = parser::RFBGlobalState::Skip;
                                    return AppLayerResult::ok();
                                }
                            }
                        }
                        Err(Err::Incomplete(_)) => {
                            return AppLayerResult::incomplete(
                                consumed as u32,
                                (current.len() + 1) as u32,
                            );
                        }
                        Err(_) => {
                            if let Some(current_transaction) = self.get_current_tx() {
                                current_transaction.set_event(RFBEvent::MalformedMessage);
                                current_transaction.complete = true;
                            }
                            // We failed to parse the security type.
                            // Continue the flow but stop trying to map the protocol.
                            self.state = parser::RFBGlobalState::Skip;
                            return AppLayerResult::ok();
                        }
                    }
                }
                parser::RFBGlobalState::TSVncResponse => match parser::parse_vnc_auth(current) {
                    Ok((rem, request)) => {
                        consumed += current.len() - rem.len();
                        let _pdu = Frame::new(
                            flow,
                            &stream_slice,
                            current,
                            consumed as i64,
                            RFBFrameType::Pdu as u8,
                        );

                        current = rem;

                        self.state = parser::RFBGlobalState::TCSecurityResult;

                        if let Some(current_transaction) = self.get_current_tx() {
                            current_transaction.ts_vnc_response = Some(request);
                        } else {
                            debug_validate_fail!("no transaction set at security result stage");
                        }
                    }
                    Err(Err::Incomplete(_)) => {
                        return AppLayerResult::incomplete(
                            consumed as u32,
                            (current.len() + 1) as u32,
                        );
                    }
                    Err(_) => {
                        if let Some(current_transaction) = self.get_current_tx() {
                            current_transaction.set_event(RFBEvent::MalformedMessage);
                            current_transaction.complete = true;
                        }
                        // Continue the flow but stop trying to map the protocol.
                        self.state = parser::RFBGlobalState::Skip;
                        return AppLayerResult::ok();
                    }
                },
                parser::RFBGlobalState::TSClientInit => match parser::parse_client_init(current) {
                    Ok((rem, request)) => {
                        consumed += current.len() - rem.len();
                        let _pdu = Frame::new(
                            flow,
                            &stream_slice,
                            current,
                            consumed as i64,
                            RFBFrameType::Pdu as u8,
                        );

                        current = rem;

                        self.state = parser::RFBGlobalState::TCServerInit;

                        if let Some(current_transaction) = self.get_current_tx() {
                            current_transaction.ts_client_init = Some(request);
                        } else {
                            debug_validate_fail!("no transaction set at client init stage");
                        }
                    }
                    Err(Err::Incomplete(_)) => {
                        return AppLayerResult::incomplete(
                            consumed as u32,
                            (current.len() + 1) as u32,
                        );
                    }
                    Err(_) => {
                        if let Some(current_transaction) = self.get_current_tx() {
                            current_transaction.set_event(RFBEvent::MalformedMessage);
                            current_transaction.complete = true;
                        }
                        // We failed to parse the client init.
                        // Continue the flow but stop trying to map the protocol.
                        self.state = parser::RFBGlobalState::Skip;
                        return AppLayerResult::ok();
                    }
                },
                parser::RFBGlobalState::Skip => {
                    // End of parseable handshake reached, skip rest of traffic
                    return AppLayerResult::ok();
                }
                _ => {
                    // We have gotten out of sync with the expected state flow.
                    // This could happen since we use a global state (i.e. that
                    // is used for both directions), but if traffic can not be
                    // parsed as expected elsewhere, we might not have advanced
                    // a state for one direction but received data in the
                    // "unexpected" direction, causing the parser to end up
                    // here. Let's stop trying to parse the traffic but still
                    // accept it.
                    SCLogDebug!("Invalid state for request: {}", self.state);
                    if let Some(current_transaction) = self.get_current_tx() {
                        current_transaction.set_event(RFBEvent::ConfusedState);
                        current_transaction.complete = true;
                    }
                    self.state = parser::RFBGlobalState::Skip;
                    return AppLayerResult::ok();
                }
            }
        }
    }

    fn parse_response(&mut self, flow: *const Flow, stream_slice: StreamSlice) -> AppLayerResult {
        let input = stream_slice.as_slice();
        // We're not interested in empty responses.
        if input.is_empty() {
            return AppLayerResult::ok();
        }

        let mut current = input;
        let mut consumed = 0;
        SCLogDebug!(
            "response_state {}, response_len {}",
            self.state,
            input.len()
        );
        loop {
            if current.is_empty() {
                return AppLayerResult::ok();
            }
            match self.state {
                parser::RFBGlobalState::TCServerProtocolVersion => {
                    match parser::parse_protocol_version(current) {
                        Ok((rem, request)) => {
                            consumed += current.len() - rem.len();
                            let _pdu = Frame::new(
                                flow,
                                &stream_slice,
                                current,
                                consumed as i64,
                                RFBFrameType::Pdu as u8,
                            );

                            current = rem;

                            self.state = parser::RFBGlobalState::TSClientProtocolVersion;
                            let tx = self.new_tx();
                            self.transactions.push(tx);

                            if let Some(current_transaction) = self.get_current_tx() {
                                current_transaction.tc_server_protocol_version = Some(request);
                            } else {
                                debug_validate_fail!("no transaction set but we just set one");
                            }
                        }
                        Err(Err::Incomplete(_)) => {
                            return AppLayerResult::incomplete(
                                consumed as u32,
                                (current.len() + 1) as u32,
                            );
                        }
                        Err(_) => {
                            // We even failed to parse the protocol version.
                            return AppLayerResult::err();
                        }
                    }
                }
                parser::RFBGlobalState::TCSupportedSecurityTypes => {
                    match parser::parse_supported_security_types(current) {
                        Ok((rem, request)) => {
                            consumed += current.len() - rem.len();
                            let _pdu = Frame::new(
                                flow,
                                &stream_slice,
                                current,
                                consumed as i64,
                                RFBFrameType::Pdu as u8,
                            );

                            current = rem;

                            SCLogDebug!(
                                "supported_security_types: {}, types: {}",
                                request.number_of_types,
                                request
                                    .types
                                    .iter()
                                    .map(ToString::to_string)
                                    .map(|v| v + " ")
                                    .collect::<String>()
                            );

                            self.state = parser::RFBGlobalState::TSSecurityTypeSelection;
                            if request.number_of_types == 0 {
                                self.state = parser::RFBGlobalState::TCFailureReason;
                            }

                            if let Some(current_transaction) = self.get_current_tx() {
                                current_transaction.tc_supported_security_types = Some(request);
                            } else {
                                debug_validate_fail!("no transaction set at security type stage");
                            }
                        }
                        Err(Err::Incomplete(_)) => {
                            return AppLayerResult::incomplete(
                                consumed as u32,
                                (current.len() + 1) as u32,
                            );
                        }
                        Err(_) => {
                            if let Some(current_transaction) = self.get_current_tx() {
                                current_transaction.set_event(RFBEvent::MalformedMessage);
                                current_transaction.complete = true;
                            }
                            // Continue the flow but stop trying to map the protocol.
                            self.state = parser::RFBGlobalState::Skip;
                            return AppLayerResult::ok();
                        }
                    }
                }
                parser::RFBGlobalState::TCServerSecurityType => {
                    // In RFB 3.3, the server decides the authentication type
                    match parser::parse_server_security_type(current) {
                        Ok((rem, request)) => {
                            consumed += current.len() - rem.len();
                            let _pdu = Frame::new(
                                flow,
                                &stream_slice,
                                current,
                                consumed as i64,
                                RFBFrameType::Pdu as u8,
                            );

                            current = rem;

                            let chosen_security_type = request.security_type;
                            SCLogDebug!("chosen_security_type: {}", chosen_security_type);
                            match chosen_security_type {
                                0 => self.state = parser::RFBGlobalState::TCFailureReason,
                                1 => self.state = parser::RFBGlobalState::TSClientInit,
                                2 => self.state = parser::RFBGlobalState::TCVncChallenge,
                                _ => {
                                    if let Some(current_transaction) = self.get_current_tx() {
                                        current_transaction
                                            .set_event(RFBEvent::UnimplementedSecurityType);
                                        current_transaction.complete = true;
                                    } else {
                                        debug_validate_fail!(
                                            "no transaction set at security type stage"
                                        );
                                    }
                                    // We have just have seen a security type we don't know about.
                                    // This is not bad per se, it might just mean this is a
                                    // proprietary one not in the spec.
                                    // Continue the flow but stop trying to map the protocol.
                                    self.state = parser::RFBGlobalState::Skip;
                                    return AppLayerResult::ok();
                                }
                            }

                            if let Some(current_transaction) = self.get_current_tx() {
                                current_transaction.tc_server_security_type = Some(request);
                                current_transaction.chosen_security_type =
                                    Some(chosen_security_type);
                            } else {
                                debug_validate_fail!("no transaction set at security type stage");
                            }
                        }
                        Err(Err::Incomplete(_)) => {
                            return AppLayerResult::incomplete(
                                consumed as u32,
                                (current.len() + 1) as u32,
                            );
                        }
                        Err(_) => {
                            if let Some(current_transaction) = self.get_current_tx() {
                                current_transaction.set_event(RFBEvent::MalformedMessage);
                                current_transaction.complete = true;
                            }
                            // Continue the flow but stop trying to map the protocol.
                            self.state = parser::RFBGlobalState::Skip;
                            return AppLayerResult::ok();
                        }
                    }
                }
                parser::RFBGlobalState::TCVncChallenge => match parser::parse_vnc_auth(current) {
                    Ok((rem, request)) => {
                        consumed += current.len() - rem.len();
                        let _pdu = Frame::new(
                            flow,
                            &stream_slice,
                            current,
                            consumed as i64,
                            RFBFrameType::Pdu as u8,
                        );

                        current = rem;

                        self.state = parser::RFBGlobalState::TSVncResponse;

                        if let Some(current_transaction) = self.get_current_tx() {
                            current_transaction.tc_vnc_challenge = Some(request);
                        } else {
                            debug_validate_fail!("no transaction set at auth stage");
                        }
                    }
                    Err(Err::Incomplete(_)) => {
                        return AppLayerResult::incomplete(
                            consumed as u32,
                            (current.len() + 1) as u32,
                        );
                    }
                    Err(_) => {
                        if let Some(current_transaction) = self.get_current_tx() {
                            current_transaction.set_event(RFBEvent::MalformedMessage);
                            current_transaction.complete = true;
                        }
                        // Continue the flow but stop trying to map the protocol.
                        self.state = parser::RFBGlobalState::Skip;
                        return AppLayerResult::ok();
                    }
                },
                parser::RFBGlobalState::TCSecurityResult => {
                    match parser::parse_security_result(current) {
                        Ok((rem, request)) => {
                            consumed += current.len() - rem.len();
                            let _pdu = Frame::new(
                                flow,
                                &stream_slice,
                                current,
                                consumed as i64,
                                RFBFrameType::Pdu as u8,
                            );

                            current = rem;

                            if request.status == 0 {
                                self.state = parser::RFBGlobalState::TSClientInit;

                                if let Some(current_transaction) = self.get_current_tx() {
                                    current_transaction.tc_security_result = Some(request);
                                } else {
                                    debug_validate_fail!(
                                        "no transaction set at security result stage"
                                    );
                                }
                            } else if request.status == 1 {
                                self.state = parser::RFBGlobalState::TCFailureReason;
                            } else {
                                if let Some(current_transaction) = self.get_current_tx() {
                                    current_transaction.set_event(RFBEvent::UnknownSecurityResult);
                                    current_transaction.complete = true;
                                }
                                // Continue the flow but stop trying to map the protocol.
                                self.state = parser::RFBGlobalState::Skip;
                                return AppLayerResult::ok();
                            }
                        }
                        Err(Err::Incomplete(_)) => {
                            return AppLayerResult::incomplete(
                                consumed as u32,
                                (current.len() + 1) as u32,
                            );
                        }
                        Err(_) => {
                            if let Some(current_transaction) = self.get_current_tx() {
                                current_transaction.set_event(RFBEvent::MalformedMessage);
                                current_transaction.complete = true;
                            }
                            // Continue the flow but stop trying to map the protocol.
                            self.state = parser::RFBGlobalState::Skip;
                            return AppLayerResult::ok();
                        }
                    }
                }
                parser::RFBGlobalState::TCFailureReason => {
                    match parser::parse_failure_reason(current) {
                        Ok((_rem, request)) => {
                            if let Some(current_transaction) = self.get_current_tx() {
                                current_transaction.tc_failure_reason = Some(request);
                            } else {
                                debug_validate_fail!("no transaction set at failure reason stage");
                            }
                            return AppLayerResult::ok();
                        }
                        Err(Err::Incomplete(_)) => {
                            return AppLayerResult::incomplete(
                                consumed as u32,
                                (current.len() + 1) as u32,
                            );
                        }
                        Err(_) => {
                            if let Some(current_transaction) = self.get_current_tx() {
                                current_transaction.set_event(RFBEvent::MalformedMessage);
                                current_transaction.complete = true;
                            }
                            // Continue the flow but stop trying to map the protocol.
                            self.state = parser::RFBGlobalState::Skip;
                            return AppLayerResult::ok();
                        }
                    }
                }
                parser::RFBGlobalState::TCServerInit => {
                    match parser::parse_server_init(current) {
                        Ok((rem, request)) => {
                            consumed += current.len() - rem.len();
                            let _pdu = Frame::new(
                                flow,
                                &stream_slice,
                                current,
                                consumed as i64,
                                RFBFrameType::Pdu as u8,
                            );

                            current = rem;

                            self.state = parser::RFBGlobalState::Skip;

                            if let Some(current_transaction) = self.get_current_tx() {
                                current_transaction.tc_server_init = Some(request);
                                // connection initialization is complete and parsed
                                current_transaction.complete = true;
                            } else {
                                debug_validate_fail!("no transaction set at server init stage");
                            }
                        }
                        Err(Err::Incomplete(_)) => {
                            return AppLayerResult::incomplete(
                                consumed as u32,
                                (current.len() + 1) as u32,
                            );
                        }
                        Err(_) => {
                            if let Some(current_transaction) = self.get_current_tx() {
                                current_transaction.set_event(RFBEvent::MalformedMessage);
                                current_transaction.complete = true;
                            }
                            // Continue the flow but stop trying to map the protocol.
                            self.state = parser::RFBGlobalState::Skip;
                            return AppLayerResult::ok();
                        }
                    }
                }
                parser::RFBGlobalState::Skip => {
                    //todo implement RFB messages, for now we stop here
                    return AppLayerResult::ok();
                }
                _ => {
                    // We have gotten out of sync with the expected state flow.
                    // This could happen since we use a global state (i.e. that
                    // is used for both directions), but if traffic can not be
                    // parsed as expected elsewhere, we might not have advanced
                    // a state for one direction but received data in the
                    // "unexpected" direction, causing the parser to end up
                    // here. Let's stop trying to parse the traffic but still
                    // accept it.
                    SCLogDebug!("Invalid state for response: {}", self.state);
                    if let Some(current_transaction) = self.get_current_tx() {
                        current_transaction.set_event(RFBEvent::ConfusedState);
                        current_transaction.complete = true;
                    }
                    self.state = parser::RFBGlobalState::Skip;
                    return AppLayerResult::ok();
                }
            }
        }
    }
}

// C exports.

#[no_mangle]
pub extern "C" fn rs_rfb_state_new(
    _orig_state: *mut std::os::raw::c_void, _orig_proto: AppProto,
) -> *mut std::os::raw::c_void {
    let state = RFBState::new();
    let boxed = Box::new(state);
    return Box::into_raw(boxed) as *mut _;
}

#[no_mangle]
pub extern "C" fn rs_rfb_state_free(state: *mut std::os::raw::c_void) {
    // Just unbox...
    std::mem::drop(unsafe { Box::from_raw(state as *mut RFBState) });
}

#[no_mangle]
pub unsafe extern "C" fn rs_rfb_state_tx_free(state: *mut std::os::raw::c_void, tx_id: u64) {
    let state = cast_pointer!(state, RFBState);
    state.free_tx(tx_id);
}

#[no_mangle]
pub unsafe extern "C" fn rs_rfb_parse_request(
    flow: *const Flow, state: *mut std::os::raw::c_void, _pstate: *mut std::os::raw::c_void,
    stream_slice: StreamSlice, _data: *const std::os::raw::c_void,
) -> AppLayerResult {
    let state = cast_pointer!(state, RFBState);
    return state.parse_request(flow, stream_slice);
}

#[no_mangle]
pub unsafe extern "C" fn rs_rfb_parse_response(
    flow: *const Flow, state: *mut std::os::raw::c_void, _pstate: *mut std::os::raw::c_void,
    stream_slice: StreamSlice, _data: *const std::os::raw::c_void,
) -> AppLayerResult {
    let state = cast_pointer!(state, RFBState);
    return state.parse_response(flow, stream_slice);
}

#[no_mangle]
pub unsafe extern "C" fn rs_rfb_state_get_tx(
    state: *mut std::os::raw::c_void, tx_id: u64,
) -> *mut std::os::raw::c_void {
    let state = cast_pointer!(state, RFBState);
    match state.get_tx(tx_id) {
        Some(tx) => {
            return tx as *const _ as *mut _;
        }
        None => {
            return std::ptr::null_mut();
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_rfb_state_get_tx_count(state: *mut std::os::raw::c_void) -> u64 {
    let state = cast_pointer!(state, RFBState);
    return state.tx_id;
}

#[no_mangle]
pub unsafe extern "C" fn rs_rfb_tx_get_alstate_progress(
    tx: *mut std::os::raw::c_void, _direction: u8,
) -> std::os::raw::c_int {
    let tx = cast_pointer!(tx, RFBTransaction);
    if tx.complete {
        return 1;
    }
    return 0;
}

// Parser name as a C style string.
const PARSER_NAME: &[u8] = b"rfb\0";

export_tx_data_get!(rs_rfb_get_tx_data, RFBTransaction);
export_state_data_get!(rs_rfb_get_state_data, RFBState);

#[no_mangle]
pub unsafe extern "C" fn rs_rfb_register_parser() {
    let parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const std::os::raw::c_char,
        default_port: std::ptr::null(),
        ipproto: IPPROTO_TCP,
        probe_ts: None,
        probe_tc: None,
        min_depth: 0,
        max_depth: 16,
        state_new: rs_rfb_state_new,
        state_free: rs_rfb_state_free,
        tx_free: rs_rfb_state_tx_free,
        parse_ts: rs_rfb_parse_request,
        parse_tc: rs_rfb_parse_response,
        get_tx_count: rs_rfb_state_get_tx_count,
        get_tx: rs_rfb_state_get_tx,
        tx_comp_st_ts: 1,
        tx_comp_st_tc: 1,
        tx_get_progress: rs_rfb_tx_get_alstate_progress,
        get_eventinfo: Some(RFBEvent::get_event_info),
        get_eventinfo_byid: Some(RFBEvent::get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_tx_files: None,
        get_tx_iterator: Some(applayer::state_get_tx_iterator::<RFBState, RFBTransaction>),
        get_tx_data: rs_rfb_get_tx_data,
        get_state_data: rs_rfb_get_state_data,
        apply_tx_config: None,
        flags: 0,
        truncate: None,
        get_frame_id_by_name: Some(RFBFrameType::ffi_id_from_name),
        get_frame_name_by_id: Some(RFBFrameType::ffi_name_from_id),
    };

    let ip_proto_str = CString::new("tcp").unwrap();

    if AppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_RFB = alproto;
        if AppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
        SCLogDebug!("Rust rfb parser registered.");
        AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_RFB);
    } else {
        SCLogDebug!("Protocol detector and parser disabled for RFB.");
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::core::STREAM_START;

    #[test]
    fn test_error_state() {
        let mut state = RFBState::new();

        let buf: &[u8] = &[
            0x05, 0x00, 0x03, 0x20, 0x20, 0x18, 0x00, 0x01, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff,
            0x10, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1e, 0x61, 0x6e, 0x65, 0x61,
            0x67, 0x6c, 0x65, 0x73, 0x40, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74,
            0x2e, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e,
        ];
        let r = state.parse_response(
            std::ptr::null(),
            StreamSlice::from_slice(buf, STREAM_START, 0),
        );

        assert_eq!(
            r,
            AppLayerResult {
                status: -1,
                consumed: 0,
                needed: 0
            }
        );
    }

    // Test the state machine for RFB protocol
    // Passes an initial buffer with initial RFBState = TCServerProtocolVersion
    // Tests various client and server RFBStates as the buffer is parsed using parse_request and parse_response functions
    #[test]
    fn test_rfb_state_machine() {
        let mut init_state = RFBState::new();

        let buf: &[u8] = &[
            0x52, 0x46, 0x42, 0x20, 0x30, 0x30, 0x33, 0x2e, 0x30, 0x30, 0x38, 0x0a,
            0x01, /* Number of security types: 1 */
            0x02, /* Security type: VNC (2) */
            0x02, /* Security type selected: VNC (2) */
            0x54, 0x7b, 0x7a, 0x6f, 0x36, 0xa1, 0x54, 0xdb, 0x03, 0xa2, 0x57, 0x5c, 0x6f, 0x2a,
            0x4e,
            0xc5, /* 16 byte Authentication challenge: 547b7a6f36a154db03a2575c6f2a4ec5 */
            0x00, 0x00, 0x00, 0x00, /* Authentication result: OK */
            0x00, /* Share desktop flag: False */
            0x05, 0x00, 0x03, 0x20, 0x20, 0x18, 0x00, 0x01, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff,
            0x10, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1e, 0x61, 0x6e, 0x65, 0x61,
            0x67, 0x6c, 0x65, 0x73, 0x40, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74,
            0x2e, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x64, 0x6f, 0x6d, 0x61, 0x69,
            0x6e, /* Server framebuffer parameters */
        ];

        //The buffer values correspond to Server Protocol version: 003.008
        // Same buffer is used for both functions due to similar values in request and response
        init_state.parse_response(
            std::ptr::null(),
            StreamSlice::from_slice(&buf[0..12], STREAM_START, 0),
        );
        let mut ok_state = parser::RFBGlobalState::TSClientProtocolVersion;
        assert_eq!(init_state.state, ok_state);

        //The buffer values correspond to Client Protocol version: 003.008
        init_state.parse_request(
            std::ptr::null(),
            StreamSlice::from_slice(&buf[0..12], STREAM_START, 0),
        );
        ok_state = parser::RFBGlobalState::TCSupportedSecurityTypes;
        assert_eq!(init_state.state, ok_state);

        init_state.parse_response(
            std::ptr::null(),
            StreamSlice::from_slice(&buf[12..14], STREAM_START, 0),
        );
        ok_state = parser::RFBGlobalState::TSSecurityTypeSelection;
        assert_eq!(init_state.state, ok_state);

        init_state.parse_request(
            std::ptr::null(),
            StreamSlice::from_slice(&buf[14..15], STREAM_START, 0),
        );
        ok_state = parser::RFBGlobalState::TCVncChallenge;
        assert_eq!(init_state.state, ok_state);

        //The buffer values correspond to Server Authentication challenge: 547b7a6f36a154db03a2575c6f2a4ec5
        // Same buffer is used for both functions due to similar values in request and response
        init_state.parse_response(
            std::ptr::null(),
            StreamSlice::from_slice(&buf[15..31], STREAM_START, 0),
        );
        ok_state = parser::RFBGlobalState::TSVncResponse;
        assert_eq!(init_state.state, ok_state);

        //The buffer values correspond to Client Authentication response: 547b7a6f36a154db03a2575c6f2a4ec5
        init_state.parse_request(
            std::ptr::null(),
            StreamSlice::from_slice(&buf[15..31], STREAM_START, 0),
        );
        ok_state = parser::RFBGlobalState::TCSecurityResult;
        assert_eq!(init_state.state, ok_state);

        init_state.parse_response(
            std::ptr::null(),
            StreamSlice::from_slice(&buf[31..35], STREAM_START, 0),
        );
        ok_state = parser::RFBGlobalState::TSClientInit;
        assert_eq!(init_state.state, ok_state);

        init_state.parse_request(
            std::ptr::null(),
            StreamSlice::from_slice(&buf[35..36], STREAM_START, 0),
        );
        ok_state = parser::RFBGlobalState::TCServerInit;
        assert_eq!(init_state.state, ok_state);

        init_state.parse_response(
            std::ptr::null(),
            StreamSlice::from_slice(&buf[36..90], STREAM_START, 0),
        );
        ok_state = parser::RFBGlobalState::Skip;
        assert_eq!(init_state.state, ok_state);
    }
}
