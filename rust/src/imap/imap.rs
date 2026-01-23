/* Copyright (C) 2026 Open Information Security Foundation
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

// Author: Giuseppe Longo <glongo@oisf.net>

use crate::applayer::{self, *};
use crate::conf::conf_get;
use crate::core::*;
use crate::direction::Direction;
use crate::flow::Flow;
use crate::frames::*;
use crate::imap::parser::{
    extract_literal_from_arguments, imap_parse_message, parse_continuation_data,
    parse_email_content, EmailData, ImapCommand, ImapMessage, ImapMessageType,
    ImapResponseStatus, LiteralInfo,
};
use nom::character::complete::crlf;
use nom7 as nom;
use std;
use std::collections::VecDeque;
use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_void};
use suricata_sys::sys::{
    AppLayerParserState, AppProto, SCAppLayerParserConfParserEnabled,
    SCAppLayerParserRegisterLogger, SCAppLayerParserStateIssetFlag,
    SCAppLayerProtoDetectConfProtoDetectionEnabled, SCAppLayerRequestProtocolTLSUpgrade,
};

static IMAP_MAX_TX_DEFAULT: usize = 256;

static mut IMAP_MAX_TX: usize = IMAP_MAX_TX_DEFAULT;

pub(super) static mut ALPROTO_IMAP: AppProto = ALPROTO_UNKNOWN;

#[derive(AppLayerFrameType)]
pub enum ImapFrameType {
    Pdu,
    Headers,
    Body,
}

#[derive(AppLayerEvent)]
enum ImapEvent {
    TooManyTransactions,
    InvalidData,
    RequestNotFound,
    IncompleteData,
}

#[derive(Clone, Debug, Default, EnumStringU8)]
#[repr(u8)]
pub enum ImapEmailDirection {
    #[default]
    ToServer = 0,
    ToClient = 1,
}

#[derive(Debug, Default)]
pub struct ImapParsedEmail {
    pub direction: u8,
    pub body: Vec<u8>,
    pub headers: Vec<Vec<u8>>,
    pub header_names: Vec<Vec<u8>>,
    pub header_values: Vec<Vec<u8>>,
}

#[derive(Debug)]
pub struct ImapTransaction {
    pub tx_id: u64,
    pub complete: bool,

    pub requests: Vec<ImapMessage>,
    pub responses: Vec<ImapMessage>,
    pub request_lines: Vec<Vec<u8>>,
    pub response_lines: Vec<Vec<u8>>,

    pub parsed_email: Option<ImapParsedEmail>,

    tx_data: AppLayerTxData,
}

impl Default for ImapTransaction {
    fn default() -> Self {
        Self::new()
    }
}

impl ImapTransaction {
    pub fn new() -> ImapTransaction {
        Self {
            tx_id: 0,
            complete: false,
            requests: Vec::new(),
            responses: Vec::new(),
            request_lines: Vec::new(),
            response_lines: Vec::new(),
            parsed_email: None,
            tx_data: AppLayerTxData::new(),
        }
    }

    /// Check if transaction is complete
    /// A transaction is complete when:
    /// - We have a tagged response (OK/NO/BAD) matching the request's tag, OR
    /// - We received a BYE response (server closing connection) AND there's no tagged request, OR
    /// - It's a server greeting (no request, just untagged response)
    pub fn is_complete(&self) -> bool {
        // Find the first request with a tag (the initial command, not continuation data)
        let request_tag = self.requests.iter().find_map(|req| req.tag.as_ref());

        // Check if we have a tagged response matching our request
        let has_tagged_response = if let Some(tag) = request_tag {
            self.responses.iter().any(|response| {
                if let Some(ref resp_tag) = response.tag {
                    if resp_tag == tag {
                        if let ImapMessageType::Response { .. } = response.message {
                            return true;
                        }
                    }
                }
                false
            })
        } else {
            false
        };

        // If we have a tagged request, require the tagged response for completion
        if request_tag.is_some() {
            return has_tagged_response;
        }

        // For untagged-only transactions (server greeting, unsolicited BYE):
        // Check for BYE - connection is closing
        for response in &self.responses {
            if let ImapMessageType::Untagged {
                keyword,
                seq_number: _,
                ..
            } = &response.message
            {
                if keyword.eq_ignore_ascii_case(b"BYE") {
                    return true;
                }
            }
        }

        // No tagged request, check if we have any response (server greeting case)
        !self.responses.is_empty()
    }
}

impl Transaction for ImapTransaction {
    fn id(&self) -> u64 {
        self.tx_id
    }
}

fn build_parsed_email(email: &EmailData, direction: u8) -> ImapParsedEmail {
    let mut parsed_email = ImapParsedEmail {
        direction,
        body: email.email_body.clone(),
        headers: Vec::new(),
        header_names: Vec::new(),
        header_values: Vec::new(),
    };
    for (name, values) in &email.headers {
        for value in values {
            let mut header = Vec::new();
            header.extend_from_slice(name.as_bytes());
            header.extend_from_slice(b": ");
            header.extend_from_slice(value.as_bytes());
            parsed_email.headers.push(header);

            parsed_email.header_names.push(name.as_bytes().to_vec());
            parsed_email.header_values.push(value.as_bytes().to_vec());
        }
    }
    parsed_email
}

fn extract_parsed_email_from_response(response: &ImapMessage) -> Option<ImapParsedEmail> {
    if let ImapMessageType::Untagged {
        fetch_data: Some(fetch),
        ..
    } = &response.message
    {
        for part in &fetch.body_parts {
            if let Some(email_data) = &part.email {
                return Some(build_parsed_email(email_data, ImapEmailDirection::ToClient as u8));
            }
        }
    }
    None
}


pub struct ImapState {
    state_data: AppLayerStateData,
    tx_id: u64,
    transactions: VecDeque<ImapTransaction>,
    request_frame: Option<Frame>,
    response_frame: Option<Frame>,
    request_gap: bool,
    response_gap: bool,
    // True when server sent '+' and we're expecting client continuation data
    expecting_continuation_data: bool,
    // Pending literal data being collected (for APPEND command)
    pending_literal: Option<LiteralInfo>,
    // True when server sent '+' for a pending non-LITERAL+ literal
    literal_continuation_received: bool,
    request_tls: bool,
    has_starttls: bool,
}

impl State<ImapTransaction> for ImapState {
    fn get_transaction_count(&self) -> usize {
        self.transactions.len()
    }

    fn get_transaction_by_index(&self, index: usize) -> Option<&ImapTransaction> {
        self.transactions.get(index)
    }
}

impl Default for ImapState {
    fn default() -> Self {
        Self::new()
    }
}

impl ImapState {
    pub fn new() -> Self {
        Self {
            state_data: AppLayerStateData::default(),
            tx_id: 0,
            transactions: VecDeque::new(),
            request_frame: None,
            response_frame: None,
            request_gap: false,
            response_gap: false,
            expecting_continuation_data: false,
            pending_literal: None,
            literal_continuation_received: false,
            request_tls: false,
            has_starttls: false,
        }
    }

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

    pub fn get_tx(&mut self, tx_id: u64) -> Option<&ImapTransaction> {
        self.transactions.iter().find(|tx| tx.tx_id == tx_id + 1)
    }

    pub fn new_tx(&mut self) -> Option<ImapTransaction> {
        if self.transactions.len() > unsafe { IMAP_MAX_TX } {
            for tx_old in &mut self.transactions {
                if !tx_old.complete {
                    tx_old.tx_data.0.updated_tc = true;
                    tx_old.tx_data.0.updated_ts = true;
                    tx_old.complete = true;
                    tx_old
                        .tx_data
                        .set_event(ImapEvent::TooManyTransactions as u8);
                }
            }
            return None;
        }
        let mut tx = ImapTransaction::new();
        self.tx_id += 1;
        tx.tx_id = self.tx_id;
        return Some(tx);
    }

    fn set_event(&mut self, e: ImapEvent) {
        if let Some(tx) = self.transactions.back_mut() {
            tx.tx_data.set_event(e as u8);
        }
    }

    fn find_request(&mut self, tag: &[u8]) -> Option<&mut ImapTransaction> {
        self.transactions.iter_mut().find(|tx| {
            for request in &tx.requests {
                if let Some(ref req_tag) = request.tag {
                    return req_tag.as_slice() == tag && !tx.complete;
                }
            }
            false
        })
    }

    fn parse_request(&mut self, flow: *mut Flow, stream_slice: StreamSlice) -> AppLayerResult {
        let input = stream_slice.as_slice();
        if input.is_empty() {
            return AppLayerResult::ok();
        }

        if self.has_starttls {
            unsafe {
                SCAppLayerRequestProtocolTLSUpgrade(flow);
            }
            return AppLayerResult::ok();
        }

        if self.request_gap {
            match imap_parse_message(input) {
                Ok((_, _msg)) => {
                    AppLayerResult::ok();
                }
                Err(_e) => {
                    return AppLayerResult::err();
                }
            }
            self.request_gap = false;
        }

        let mut start = input;
        while !start.is_empty() {
            if self.request_frame.is_none() {
                self.request_frame = Frame::new(
                    flow,
                    &stream_slice,
                    start,
                    -1_i64,
                    ImapFrameType::Pdu as u8,
                    None,
                );
                SCLogDebug!("ts: pdu {:?}", self.request_frame);
            }

            let should_consume_literal = self
                .pending_literal
                .as_ref()
                .is_some_and(|lit| lit.is_literal_plus || self.literal_continuation_received);

            if should_consume_literal {
                if let Some(ref mut literal) = self.pending_literal {
                    let bytes_needed = (literal.size - literal.bytes_consumed) as usize;
                    if start.len() >= bytes_needed {
                        let is_single_chunk = literal.bytes_consumed == 0;
                        literal.buffer.extend_from_slice(&start[..bytes_needed]);
                        let raw_data = std::mem::take(&mut literal.buffer);
                        let email = match parse_email_content(&raw_data) {
                            Ok((_, data)) => Some(data),
                            Err(_) => None,
                        };

                        let email_offsets = if is_single_chunk {
                            email.as_ref().map(|e| (e.headers_len, e.body_offset))
                        } else {
                            None
                        };

                        let parsed_email = email.as_ref().map(|e| build_parsed_email(e, ImapEmailDirection::ToServer as u8));

                        let literal_msg = ImapMessage {
                            tag: None,
                            message: ImapMessageType::LiteralData {
                                raw: raw_data,
                                email,
                            },
                            raw_line: Vec::new(),
                        };

                        if let Some(tx) = self.transactions.iter_mut().rev().find(|tx| !tx.complete)
                        {
                            let tx_id = tx.id();
                            tx.tx_data.0.updated_ts = true;

                            // Store cached email data in transaction
                            if parsed_email.is_some() {
                                tx.parsed_email = parsed_email;
                            }

                            if let Some((headers_len, body_offset)) = email_offsets {
                                let _headers_frame = Frame::new(
                                    flow,
                                    &stream_slice,
                                    start,
                                    headers_len as i64,
                                    ImapFrameType::Headers as u8,
                                    Some(tx_id),
                                );
                                let body_len = bytes_needed as i64 - body_offset as i64;
                                if body_len > 0 {
                                    let _body_frame = Frame::new(
                                        flow,
                                        &stream_slice,
                                        &start[body_offset as usize..],
                                        body_len,
                                        ImapFrameType::Body as u8,
                                        Some(tx_id),
                                    );
                                }
                            }

                            tx.requests.push(literal_msg);
                            self.set_frame_ts(flow, tx_id, bytes_needed as i64);
                        }

                        self.pending_literal = None;
                        self.literal_continuation_received = false;
                        start = &start[bytes_needed..];
                        if let Ok((remaining, _)) = crlf::<_, nom::error::Error<_>>(start) {
                            start = remaining;
                        }
                        continue;
                    } else {
                        literal.buffer.extend_from_slice(start);
                        literal.bytes_consumed += start.len() as u32;
                        let consumed = input.len() - start.len();
                        let needed = bytes_needed - start.len() + 1;
                        return AppLayerResult::incomplete(consumed as u32, needed as u32);
                    }
                }
            }

            if self.expecting_continuation_data {
                if let Ok((rem, request)) = parse_continuation_data(start) {
                    let consumed = start.len() - rem.len();

                    self.expecting_continuation_data = false;

                    if let Some(tx) = self.transactions.iter_mut().rev().find(|tx| !tx.complete) {
                        let tx_id = tx.id();
                        tx.tx_data.0.updated_ts = true;
                        if !request.raw_line.is_empty() {
                            tx.request_lines.push(request.raw_line.clone());
                        }
                        tx.requests.push(request);
                        start = rem;
                        self.set_frame_ts(flow, tx_id, consumed as i64);
                        continue;
                    }
                }
                self.expecting_continuation_data = false;
                if let Some(pos) = start.iter().position(|&c| c == b'\n') {
                    start = &start[pos + 1..];
                    continue;
                } else {
                    break;
                }
            }

            match imap_parse_message(start) {
                Ok((rem, request)) => {
                    let consumed = start.len() - rem.len();

                    let mut setup_literal = None;
                    if let ImapMessageType::Command { command, arguments } = &request.message {
                        if matches!(command, ImapCommand::StartTls) {
                            self.request_tls = true;
                        }
                        if matches!(command, ImapCommand::Append) {
                            if let Some((size, is_plus)) = extract_literal_from_arguments(arguments)
                            {
                                setup_literal = Some((size, is_plus));
                            }
                        }
                    }

                    let tx = self.new_tx();
                    if tx.is_none() {
                        return AppLayerResult::err();
                    }
                    let mut tx = tx.unwrap();
                    let tx_id = tx.id();
                    tx.complete |= tx.is_complete();
                    if let ImapMessageType::Command {
                        command: ref cmd,
                        arguments: ref args,
                    } = request.message
                    {
                        let tag = request
                            .tag
                            .as_ref()
                            .map(|t| String::from_utf8_lossy(t))
                            .unwrap_or_default();
                        if args.is_empty() {
                            tx.request_lines
                                .push(format!("{} {}", tag, cmd).into_bytes());
                        } else {
                            let joined: Vec<_> =
                                args.iter().map(|a| String::from_utf8_lossy(a)).collect();
                            tx.request_lines
                                .push(format!("{} {} {}", tag, cmd, joined.join(" ")).into_bytes());
                        }
                    } else if !request.raw_line.is_empty() {
                        tx.request_lines.push(request.raw_line.clone());
                    }
                    tx.requests.push(request);
                    self.transactions.push_back(tx);
                    start = rem;
                    self.set_frame_ts(flow, tx_id, consumed as i64);

                    if let Some((size, is_plus)) = setup_literal {
                        self.pending_literal = Some(LiteralInfo::new(size, is_plus));
                    }
                }
                Err(nom::Err::Incomplete(_)) => {
                    let consumed = input.len() - start.len();
                    let needed = start.len() + 1;
                    return AppLayerResult::incomplete(consumed as u32, needed as u32);
                }
                Err(nom::Err::Error(e)) if e.code == nom::error::ErrorKind::Eof => {
                    break;
                }
                Err(_) => {
                    self.set_event(ImapEvent::InvalidData);
                    return AppLayerResult::err();
                }
            }
        }

        return AppLayerResult::ok();
    }

    fn parse_response(&mut self, flow: *mut Flow, stream_slice: StreamSlice) -> AppLayerResult {
        let input = stream_slice.as_slice();
        if input.is_empty() {
            return AppLayerResult::ok();
        }

        if self.response_gap {
            match imap_parse_message(input) {
                Ok((_, _msg)) => {
                    AppLayerResult::ok();
                }
                Err(_e) => {
                    return AppLayerResult::err();
                }
            }
            self.response_gap = false;
        }

        let mut start = input;
        while !start.is_empty() {
            if self.response_frame.is_none() {
                self.response_frame = Frame::new(
                    flow,
                    &stream_slice,
                    start,
                    -1_i64,
                    ImapFrameType::Pdu as u8,
                    None,
                );
                SCLogDebug!("tc: pdu {:?}", self.response_frame);
            }
            match imap_parse_message(start) {
                Ok((rem, response)) => {
                    let consumed = start.len() - rem.len();

                    if self.request_tls {
                        if let ImapMessageType::Response { status, .. } = &response.message {
                            if matches!(status, ImapResponseStatus::Ok) {
                                SCLogDebug!("IMAP: STARTTLS detected");
                                self.has_starttls = true;
                            }
                        }
                        self.request_tls = false;
                    }

                    let parsed_email = extract_parsed_email_from_response(&response);

                    if let Some(ref tag) = response.tag {
                        if let Some(tx) = self.find_request(tag) {
                            let tx_id = tx.id();
                            tx.tx_data.0.updated_tc = true;
                            if !response.raw_line.is_empty() {
                                tx.response_lines.push(response.raw_line.clone());
                            }
                            if tx.parsed_email.is_none() {
                                tx.parsed_email = parsed_email;
                            }
                            tx.responses.push(response);
                            tx.complete = tx.is_complete();
                            self.set_frame_tc(flow, tx_id, consumed as i64);
                        } else {
                            // No matching request (e.g. midstream/async-oneside mode).
                            // Create a new transaction for this tagged response.
                            let tx = self.new_tx();
                            if tx.is_none() {
                                return AppLayerResult::err();
                            }
                            let mut tx = tx.unwrap();
                            let tx_id = tx.id();
                            tx.tx_data.0.updated_tc = true;
                            if !response.raw_line.is_empty() {
                                tx.response_lines.push(response.raw_line.clone());
                            }
                            tx.parsed_email = parsed_email;
                            tx.responses.push(response);
                            tx.complete = tx.is_complete();
                            self.transactions.push_back(tx);
                            self.set_frame_tc(flow, tx_id, consumed as i64);
                        }
                    } else {
                        if matches!(response.message, ImapMessageType::Continuation { .. }) {
                            if let Some(ref literal) = self.pending_literal {
                                if !literal.is_literal_plus {
                                    self.literal_continuation_received = true;
                                }
                            } else {
                                self.expecting_continuation_data = true;
                            }
                        }

                        if let Some(tx) = self.transactions.iter_mut().rev().find(|tx| !tx.complete)
                        {
                            let tx_id = tx.id();
                            if !response.raw_line.is_empty() {
                                tx.response_lines.push(response.raw_line.clone());
                            }
                            if tx.parsed_email.is_none() {
                                tx.parsed_email = parsed_email;
                            }
                            tx.responses.push(response);
                            tx.complete = tx.is_complete();
                            tx.tx_data.0.updated_tc = true;
                            self.set_frame_tc(flow, tx_id, consumed as i64);
                        } else {
                            let tx = self.new_tx();
                            if tx.is_none() {
                                return AppLayerResult::err();
                            }
                            let mut tx = tx.unwrap();
                            let tx_id = tx.id();
                            if !response.raw_line.is_empty() {
                                tx.response_lines.push(response.raw_line.clone());
                            }
                            tx.parsed_email = parsed_email;
                            tx.responses.push(response);
                            tx.complete = tx.is_complete();
                            self.transactions.push_back(tx);
                            self.set_frame_tc(flow, tx_id, consumed as i64);
                        }
                    }
                    start = rem;
                }
                Err(nom::Err::Incomplete(_)) => {
                    let consumed = input.len() - start.len();
                    let needed = start.len() + 1;
                    return AppLayerResult::incomplete(consumed as u32, needed as u32);
                }
                Err(nom::Err::Error(e)) if e.code == nom::error::ErrorKind::Eof => {
                    break;
                }
                Err(_) => {
                    self.set_event(ImapEvent::InvalidData);
                    return AppLayerResult::err();
                }
            }
        }

        return AppLayerResult::ok();
    }

    fn set_frame_ts(&mut self, flow: *const Flow, tx_id: u64, consumed: i64) {
        if let Some(frame) = &self.request_frame {
            frame.set_len(flow, consumed);
            frame.set_tx(flow, tx_id);
            self.request_frame = None;
        }
    }

    fn set_frame_tc(&mut self, flow: *const Flow, tx_id: u64, consumed: i64) {
        if let Some(frame) = &self.response_frame {
            frame.set_len(flow, consumed);
            frame.set_tx(flow, tx_id);
            self.response_frame = None;
        }
    }

    fn on_request_gap(&mut self, _size: u32) {
        self.request_gap = true;
    }

    fn on_response_gap(&mut self, _size: u32) {
        self.response_gap = true;
    }
}

fn probe(input: &[u8], dir: Direction, rdir: *mut u8) -> AppProto {
    match imap_parse_message(input) {
        Ok((_, imap_msg)) => {
            if dir == Direction::ToServer && !imap_msg.is_request() {
                unsafe {
                    *rdir = Direction::ToClient.into();
                }
            }
            if dir == Direction::ToClient && !imap_msg.is_response() {
                unsafe {
                    *rdir = Direction::ToServer.into();
                }
            }
            return unsafe { ALPROTO_IMAP };
        }
        Err(nom::Err::Incomplete(_)) => {
            return ALPROTO_UNKNOWN;
        }
        Err(_e) => {
            return ALPROTO_FAILED;
        }
    }
}

unsafe extern "C" fn imap_probing_parser(
    _flow: *const Flow, direction: u8, input: *const u8, input_len: u32, rdir: *mut u8,
) -> AppProto {
    if input_len > 1 && !input.is_null() {
        let slice = build_slice!(input, input_len as usize);
        return probe(slice, direction.into(), rdir);
    }
    return ALPROTO_UNKNOWN;
}

extern "C" fn imap_state_new(_orig_state: *mut c_void, _orig_proto: AppProto) -> *mut c_void {
    let state = ImapState::new();
    let boxed = Box::new(state);
    return Box::into_raw(boxed) as *mut c_void;
}

unsafe extern "C" fn imap_state_free(state: *mut c_void) {
    std::mem::drop(Box::from_raw(state as *mut ImapState));
}

unsafe extern "C" fn imap_state_tx_free(state: *mut c_void, tx_id: u64) {
    let state = cast_pointer!(state, ImapState);
    state.free_tx(tx_id);
}

unsafe extern "C" fn imap_parse_request(
    flow: *mut Flow, state: *mut c_void, pstate: *mut AppLayerParserState,
    stream_slice: StreamSlice, _data: *mut c_void,
) -> AppLayerResult {
    if stream_slice.is_empty() {
        if SCAppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TS) > 0 {
            return AppLayerResult::ok();
        } else {
            return AppLayerResult::err();
        }
    }
    let state = cast_pointer!(state, ImapState);

    if stream_slice.is_gap() {
        state.on_request_gap(stream_slice.gap_size());
    } else {
        return state.parse_request(flow, stream_slice);
    }
    AppLayerResult::ok()
}

unsafe extern "C" fn imap_parse_response(
    flow: *mut Flow, state: *mut c_void, pstate: *mut AppLayerParserState,
    stream_slice: StreamSlice, _data: *mut c_void,
) -> AppLayerResult {
    if stream_slice.is_empty() {
        if SCAppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TC) > 0 {
            return AppLayerResult::ok();
        } else {
            return AppLayerResult::err();
        }
    }
    let state = cast_pointer!(state, ImapState);
    if stream_slice.is_gap() {
        state.on_response_gap(stream_slice.gap_size());
    } else {
        return state.parse_response(flow, stream_slice);
    }
    AppLayerResult::ok()
}

unsafe extern "C" fn imap_state_get_tx(state: *mut c_void, tx_id: u64) -> *mut c_void {
    let state = cast_pointer!(state, ImapState);
    match state.get_tx(tx_id) {
        Some(tx) => {
            return tx as *const _ as *mut _;
        }
        None => {
            return std::ptr::null_mut();
        }
    }
}

unsafe extern "C" fn imap_state_get_tx_count(state: *mut c_void) -> u64 {
    let state = cast_pointer!(state, ImapState);
    return state.tx_id;
}

unsafe extern "C" fn imap_tx_get_alstate_progress(tx: *mut c_void, _direction: u8) -> c_int {
    let tx = cast_pointer!(tx, ImapTransaction);
    if tx.complete {
        return 1;
    }
    return 0;
}

export_tx_data_get!(imap_get_tx_data, ImapTransaction);
export_state_data_get!(imap_get_state_data, ImapState);

const PARSER_NAME: &[u8] = b"imap\0";

#[no_mangle]
pub unsafe extern "C" fn SCRegisterImapParser() {
    let default_port = CString::new("[143]").unwrap();
    let parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const c_char,
        default_port: default_port.as_ptr(),
        ipproto: IPPROTO_TCP,
        probe_ts: Some(imap_probing_parser),
        probe_tc: Some(imap_probing_parser),
        min_depth: 0,
        max_depth: 16,
        state_new: imap_state_new,
        state_free: imap_state_free,
        tx_free: imap_state_tx_free,
        parse_ts: imap_parse_request,
        parse_tc: imap_parse_response,
        get_tx_count: imap_state_get_tx_count,
        get_tx: imap_state_get_tx,
        tx_comp_st_ts: 1,
        tx_comp_st_tc: 1,
        tx_get_progress: imap_tx_get_alstate_progress,
        get_eventinfo: Some(ImapEvent::get_event_info),
        get_eventinfo_byid: Some(ImapEvent::get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_tx_files: None,
        get_tx_iterator: Some(applayer::state_get_tx_iterator::<ImapState, ImapTransaction>),
        get_tx_data: imap_get_tx_data,
        get_state_data: imap_get_state_data,
        apply_tx_config: None,
        flags: APP_LAYER_PARSER_OPT_ACCEPT_GAPS,
        get_frame_id_by_name: Some(ImapFrameType::ffi_id_from_name),
        get_frame_name_by_id: Some(ImapFrameType::ffi_name_from_id),
        get_state_id_by_name: None,
        get_state_name_by_id: None,
    };

    let ip_proto_str = CString::new("tcp").unwrap();
    if SCAppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = applayer_register_protocol_detection(&parser, 1);
        ALPROTO_IMAP = alproto;
        if SCAppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
        if let Some(val) = conf_get("app-layer.protocols.imap.max-tx") {
            if let Ok(v) = val.parse::<usize>() {
                if IMAP_MAX_TX == IMAP_MAX_TX_DEFAULT {
                    IMAP_MAX_TX = v;
                }
            } else {
                SCLogError!("Invalid value for imap.max-tx");
            }
        }
        SCAppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_IMAP);
    } else {
        SCLogDebug!("Protocol detection and parser disabled for IMAP/TCP.");
    }
}
