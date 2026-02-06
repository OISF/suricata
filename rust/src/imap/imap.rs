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
use digest::Digest;
use md5::Md5;
use suricata_derive::AppLayerState;

use crate::imap::parser::{
    parse_command, parse_command_continuation, parse_continuation_data, parse_email_content,
    parse_response, parse_response_continuation, peek_untagged, probe_command_prefix,
    sequence_set_contains, untagged_trailing_literal, CommandLiteral, EmailData, EmailHeader,
    FetchBodySection, FetchResponseProgress, FetchResponseState, ImapCommand, ImapMessage,
    ImapMessageType, ImapResponseStatus, LiteralInfo, IMAP_MAX_BODY_SIZE, IMAP_MAX_LINE_SIZE,
};
use nom8::error::{Error, ErrorKind};
use nom8::Err;
use std;
use std::collections::VecDeque;
use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_void};
use suricata_sys::sys::{
    AppLayerParserState, AppProto, SCAppLayerParserConfParserEnabled,
    SCAppLayerParserRegisterLogger, SCAppLayerParserStateIssetFlag,
    SCAppLayerProtoDetectConfProtoDetectionEnabled, SCAppLayerProtoDetectGetStreamDataSize,
    SCAppLayerProtoDetectPMRegisterPatternCI, SCAppLayerProtoDetectPMRegisterPatternCIwPP,
    SCAppLayerRequestProtocolTLSUpgrade, SCFlowGetAppProtocolToClient,
};

const IMAP_MAX_TX_DEFAULT: usize = 256;
const IMAP_MAX_LINES: usize = 512;
const IMAP_MAX_MSGS_PER_TX: usize = 512;
const IMAP_MAX_RETAINED_BYTES_PER_TX: usize = 10 * 1024 * 1024;
const IMAP_MAX_RETAINED_BYTES_PER_STATE: usize = 100 * 1024 * 1024;
const IMAP_MAX_LINE_BYTES_PER_STATE: usize = 100 * 1024 * 1024;

static mut IMAP_MAX_TX: usize = IMAP_MAX_TX_DEFAULT;
static mut IMAP_MIME_BODY_MD5_ENABLED: bool = false;
static mut IMAP_MIME_BODY_MD5_DISABLED: bool = false;

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
    TooManyHeaders,
    BodyTooLarge,
    LineTooLong,
    DataLimitReached,
}

#[derive(Debug, Default)]
pub struct ImapParsedEmail {
    pub command: Vec<u8>,
    pub body: Vec<u8>,
    pub headers: Vec<EmailHeader>,
    pub direction: u8,
    pub body_md5: Option<String>,
}

impl ImapParsedEmail {
    fn retained_size(&self) -> usize {
        self.command.len()
            + self.body.len()
            + self
                .headers
                .iter()
                .map(|header| header.data.len())
                .sum::<usize>()
    }
}

fn retained_request_bytes(request: &ImapMessage) -> usize {
    let mut bytes = request.raw_line.capacity() + request.tag.as_ref().map_or(0, Vec::capacity);
    if let ImapMessageType::Command {
        command, arguments, ..
    } = &request.message
    {
        bytes += arguments.capacity() * std::mem::size_of::<Vec<u8>>()
            + arguments.iter().map(Vec::capacity).sum::<usize>();
        if let ImapCommand::Unknown(name) = command {
            bytes += name.capacity();
        }
    }
    bytes
}

fn retain_item<T>(items: &mut Vec<T>, item: T, mut bytes: usize, budget: &mut usize) -> bool {
    if bytes > *budget {
        return false;
    }
    if items.len() == items.capacity() {
        let slots = ((*budget - bytes) / std::mem::size_of::<T>()).min(items.len().max(1));
        if slots == 0 {
            return false;
        }
        let mut grown = Vec::with_capacity(items.len() + slots);
        bytes += (grown.capacity() - items.capacity()) * std::mem::size_of::<T>();
        if bytes > *budget {
            return false;
        }
        grown.append(items);
        *items = grown;
    }
    items.push(item);
    *budget -= bytes;
    true
}

fn extract_command(request: &ImapMessage) -> Vec<u8> {
    if let ImapMessageType::Command {
        command, arguments, ..
    } = &request.message
    {
        // UID is a prefix, the actual command (FETCH, STORE, etc.) is in arguments[0].
        if matches!(command, ImapCommand::Uid) {
            arguments
                .first()
                .map(|arg| arg.to_ascii_uppercase())
                .unwrap_or_default()
        } else {
            command.to_string().into_bytes()
        }
    } else {
        Vec::new()
    }
}

#[derive(AppLayerState, Copy, Clone, Debug, PartialOrd, PartialEq, Eq)]
#[suricata(alstate_strip_prefix = "ImapState")]
pub enum ImapStateProgress {
    ImapStateInProgress = 0,
    ImapStateComplete = 1,
}

#[derive(Debug)]
pub struct ImapTransaction {
    pub tx_id: u64,

    progress_ts: ImapStateProgress,
    progress_tc: ImapStateProgress,

    pub requests: Vec<ImapMessage>,
    pub request_lines: Vec<Vec<u8>>,
    pub response_lines: Vec<Vec<u8>>,

    pub parsed_emails: Vec<ImapParsedEmail>,

    request_tag: Option<Vec<u8>>,
    pub command: Vec<u8>,
    retained_bytes: usize,
    line_bytes: usize,
    data_limit_event_set: bool,

    tx_data: AppLayerTxData,
}

impl ImapTransaction {
    pub fn new() -> ImapTransaction {
        Self {
            tx_id: 0,
            progress_ts: ImapStateProgress::ImapStateInProgress,
            progress_tc: ImapStateProgress::ImapStateInProgress,
            requests: Vec::new(),
            request_lines: Vec::new(),
            response_lines: Vec::new(),
            parsed_emails: Vec::new(),
            request_tag: None,
            command: Vec::new(),
            retained_bytes: 0,
            line_bytes: 0,
            data_limit_event_set: false,
            tx_data: AppLayerTxData::new(),
        }
    }

    fn complete(&self) -> bool {
        self.progress_tc == ImapStateProgress::ImapStateComplete
    }

    fn awaiting_response(&self) -> bool {
        !self.complete() && self.request_tag.is_some()
    }

    fn update_completion_from_response(&mut self, response: &ImapMessage) {
        let completes = match &self.request_tag {
            Some(request_tag) => {
                response.tag.as_deref() == Some(request_tag.as_slice())
                    && matches!(response.message, ImapMessageType::Response { .. })
            }
            None => true,
        };
        if completes {
            if self.request_tag.is_some() {
                self.complete_request();
            }
            self.progress_tc = ImapStateProgress::ImapStateComplete;
        }
    }

    fn complete_request(&mut self) {
        if self.progress_ts != ImapStateProgress::ImapStateComplete {
            self.progress_ts = ImapStateProgress::ImapStateComplete;
            self.tx_data.0.updated_ts = true;
        }
    }

    fn complete_response(&mut self) {
        if self.progress_tc != ImapStateProgress::ImapStateComplete {
            self.progress_tc = ImapStateProgress::ImapStateComplete;
            self.tx_data.0.updated_tc = true;
        }
    }

    fn mark_data_limit(&mut self) {
        if !self.data_limit_event_set {
            self.tx_data.set_event(ImapEvent::DataLimitReached as u8);
            self.data_limit_event_set = true;
        }
    }

    fn retain_parsed_email(&mut self, email: EmailData, direction: u8, retain_limit: usize) {
        if email.too_many_headers {
            self.tx_data.set_event(ImapEvent::TooManyHeaders as u8);
        }
        if self.parsed_emails.len() >= IMAP_MAX_MSGS_PER_TX {
            self.mark_data_limit();
            return;
        }
        let mut email = ImapParsedEmail {
            command: self.command.clone(),
            body: email.email_body,
            headers: email.headers,
            direction,
            body_md5: None,
        };
        let budget =
            retain_limit.min(IMAP_MAX_RETAINED_BYTES_PER_TX.saturating_sub(self.retained_bytes));
        let metadata = email.retained_size() - email.body.len();
        if metadata > budget {
            self.mark_data_limit();
            return;
        }
        let body_allowance = budget - metadata;
        if email.body.len() > body_allowance {
            email.body.truncate(body_allowance);
            email.body.shrink_to_fit();
            self.mark_data_limit();
        }
        // Hash the final retained body, after applying all retention limits.
        email.body_md5 = if unsafe { IMAP_MIME_BODY_MD5_ENABLED } && !email.body.is_empty() {
            let hash = Md5::digest(&email.body);
            Some(format!("{:x}", hash))
        } else {
            None
        };
        self.retained_bytes = self.retained_bytes.saturating_add(email.retained_size());
        self.parsed_emails.push(email);
    }

    fn add_request(&mut self, req: ImapMessage, line: Vec<u8>, line_budget: usize) -> bool {
        self.tx_data.0.updated_ts = true;
        if req.line_truncated {
            self.tx_data.set_event(ImapEvent::LineTooLong as u8);
        }
        let mut rem = line_budget;
        if self.request_tag.is_none() && matches!(req.message, ImapMessageType::Command { .. }) {
            let tag = req.tag.clone();
            let command = extract_command(&req);
            let bytes = tag.as_ref().map_or(0, Vec::capacity) + command.capacity();
            if bytes > rem {
                self.mark_data_limit();
                return false;
            }
            rem -= bytes;
            self.request_tag = tag;
            self.command = command;
        }
        let line_bytes = line.capacity();
        if !line.is_empty()
            && (self.request_lines.len() >= IMAP_MAX_LINES
                || !retain_item(&mut self.request_lines, line, line_bytes, &mut rem))
        {
            self.mark_data_limit();
        }
        let request_bytes = retained_request_bytes(&req);
        if self.requests.len() >= IMAP_MAX_MSGS_PER_TX
            || !retain_item(&mut self.requests, req, request_bytes, &mut rem)
        {
            self.mark_data_limit();
        }
        self.line_bytes += line_budget - rem;
        true
    }

    fn add_response(&mut self, mut resp: ImapMessage, retain_limit: usize, line_budget: usize) {
        self.tx_data.0.updated_tc = true;
        let mut rem = line_budget;
        let bytes = resp.raw_line.capacity();
        if !resp.raw_line.is_empty()
            && (self.response_lines.len() >= IMAP_MAX_LINES
                || !retain_item(
                    &mut self.response_lines,
                    std::mem::take(&mut resp.raw_line),
                    bytes,
                    &mut rem,
                ))
        {
            self.mark_data_limit();
        }
        self.line_bytes += line_budget - rem;
        if resp.line_truncated {
            self.tx_data.set_event(ImapEvent::LineTooLong as u8);
        }
        if let ImapMessageType::Untagged {
            fetch_data: Some(fetch),
            ..
        } = &mut resp.message
        {
            if let Some(email) = fetch.email.take() {
                self.retain_parsed_email(email, STREAM_TOCLIENT, retain_limit);
            }
            if fetch.body_too_large {
                self.tx_data.set_event(ImapEvent::BodyTooLarge as u8);
            }
            if fetch.data_limit_reached {
                self.mark_data_limit();
            }
        }
        self.update_completion_from_response(&resp);
    }
}

fn request_line(request: &ImapMessage) -> Vec<u8> {
    let ImapMessageType::Command {
        command, arguments, ..
    } = &request.message
    else {
        return request.raw_line.clone();
    };
    let tag = request.tag_str();
    let mut line = if arguments.is_empty() {
        format!("{tag} {command}")
    } else {
        let joined: Vec<_> = arguments
            .iter()
            .map(|a| String::from_utf8_lossy(a))
            .collect();
        format!("{tag} {command} {}", joined.join(" "))
    }
    .into_bytes();
    line.truncate(IMAP_MAX_LINE_SIZE);
    line.shrink_to_fit();
    line
}

impl Default for ImapTransaction {
    fn default() -> Self {
        Self::new()
    }
}

impl Transaction for ImapTransaction {
    fn id(&self) -> u64 {
        self.tx_id
    }
}

#[derive(Debug)]
struct PendingLiteral {
    tx_id: u64,
    literal: LiteralInfo,
    continuation_received: bool,
    awaiting_line_rest: bool,
    parenthesis_depth: usize,
    is_email: bool,
    email_frame: Option<PendingEmailFrame>,
}

impl PendingLiteral {
    fn new(tx_id: u64, literal: CommandLiteral, retain_limit: usize, is_email: bool) -> Self {
        Self {
            tx_id,
            literal: LiteralInfo::new(literal.size, literal.is_literal_plus, retain_limit),
            continuation_received: false,
            awaiting_line_rest: false,
            parenthesis_depth: literal.parenthesis_depth,
            is_email,
            email_frame: None,
        }
    }

    fn is_ready(&self) -> bool {
        self.literal.is_literal_plus || self.continuation_received
    }

    fn consume_chunk(
        &mut self, flow: *mut Flow, stream_slice: &StreamSlice, chunk: &[u8],
    ) -> usize {
        let consumed = self.literal.consume_chunk(chunk);
        if let Some(email_frame) = self.email_frame.as_mut() {
            if email_frame.consume(flow, stream_slice, &chunk[..consumed], self.tx_id) {
                self.email_frame = None;
            }
        }
        consumed
    }
}

#[derive(Debug)]
struct PendingResponseLiteral {
    tx_id: Option<u64>,
    literal: LiteralInfo,
    awaiting_line_rest: bool,
}

impl PendingResponseLiteral {
    fn new(tx_id: Option<u64>, size: u64) -> Self {
        Self {
            tx_id,
            literal: LiteralInfo::new(size, false, 0),
            /* An empty literal has no octets to skip. */
            awaiting_line_rest: size == 0,
        }
    }
}

#[derive(Debug)]
struct PendingFetchResponse {
    tx_id: u64,
    frame_len: usize,
    parser: FetchResponseState,
    email_frame: Option<PendingEmailFrame>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct EmailFrameBoundary {
    headers_len: u64,
    body_offset: u64,
}

#[derive(Debug, Default)]
struct EmailFrameBoundaryScanner {
    bytes_seen: u64,
    tail: [u8; 4],
    tail_len: usize,
}

impl EmailFrameBoundaryScanner {
    fn consume(&mut self, i: &[u8]) -> Option<EmailFrameBoundary> {
        for &b in i {
            self.bytes_seen = self.bytes_seen.saturating_add(1);
            if self.tail_len < self.tail.len() {
                self.tail[self.tail_len] = b;
                self.tail_len += 1;
            } else {
                self.tail.copy_within(1.., 0);
                self.tail[3] = b;
            }

            if self.bytes_seen == 2 && &self.tail[..self.tail_len] == b"\r\n" {
                return Some(EmailFrameBoundary {
                    headers_len: 0,
                    body_offset: 2,
                });
            }
            if self.tail_len == self.tail.len() && self.tail == *b"\r\n\r\n" {
                return Some(EmailFrameBoundary {
                    headers_len: self.bytes_seen.saturating_sub(2),
                    body_offset: self.bytes_seen,
                });
            }
        }
        None
    }
}

#[derive(Debug)]
struct PendingEmailFrame {
    literal_size: u64,
    observed: u64,
    headers_frame: Option<Frame>,
    boundary_scanner: EmailFrameBoundaryScanner,
}

impl PendingEmailFrame {
    fn create(
        flow: *mut Flow, stream_slice: &StreamSlice, literal_start: &[u8], tx_id: u64,
        literal_size: u64, section: FetchBodySection,
    ) -> Option<Self> {
        let tx_id = tx_id - 1;
        if literal_size == 0 {
            return None;
        }

        let frame_len = i64::try_from(literal_size).unwrap_or(i64::MAX);
        match section {
            FetchBodySection::Full => Some(Self {
                literal_size,
                observed: 0,
                headers_frame: Frame::new(
                    flow,
                    stream_slice,
                    literal_start,
                    -1,
                    ImapFrameType::Headers as u8,
                    Some(tx_id),
                ),
                boundary_scanner: EmailFrameBoundaryScanner::default(),
            }),
            FetchBodySection::Header => {
                let _headers_frame = Frame::new(
                    flow,
                    stream_slice,
                    literal_start,
                    frame_len,
                    ImapFrameType::Headers as u8,
                    Some(tx_id),
                );
                None
            }
            FetchBodySection::Text => {
                let _body_frame = Frame::new(
                    flow,
                    stream_slice,
                    literal_start,
                    frame_len,
                    ImapFrameType::Body as u8,
                    Some(tx_id),
                );
                None
            }
            FetchBodySection::Other => None,
        }
    }

    fn remaining(&self) -> u64 {
        self.literal_size.saturating_sub(self.observed)
    }

    fn consume(
        &mut self, flow: *mut Flow, stream_slice: &StreamSlice, input: &[u8], tx_id: u64,
    ) -> bool {
        let tx_id = tx_id - 1;
        let chunk_len = usize::try_from(self.remaining())
            .unwrap_or(usize::MAX)
            .min(input.len());
        let chunk = &input[..chunk_len];
        let chunk_offset = self.observed;

        let boundary = self.boundary_scanner.consume(chunk);

        self.observed = self
            .observed
            .saturating_add(u64::try_from(chunk_len).unwrap_or(u64::MAX));

        if let Some(boundary) = boundary {
            if let Some(frame) = &self.headers_frame {
                frame.set_len(
                    flow,
                    i64::try_from(boundary.headers_len).unwrap_or(i64::MAX),
                );
            }

            let body_len = self.literal_size.saturating_sub(boundary.body_offset);
            if body_len > 0 {
                let body_start = usize::try_from(boundary.body_offset.saturating_sub(chunk_offset))
                    .unwrap_or(chunk.len())
                    .min(chunk.len());
                let _body_frame = Frame::new(
                    flow,
                    stream_slice,
                    &chunk[body_start..],
                    i64::try_from(body_len).unwrap_or(i64::MAX),
                    ImapFrameType::Body as u8,
                    Some(tx_id),
                );
            }
            return true;
        }

        if self.remaining() == 0 {
            self.close_headers(flow);
            return true;
        }

        false
    }

    fn close_headers(&self, flow: *const Flow) {
        if let Some(frame) = &self.headers_frame {
            frame.set_len(flow, i64::try_from(self.observed).unwrap_or(i64::MAX));
        }
    }
}

const UNTAGGED_KEYWORD_COMMANDS: &[(&[u8], &[&[u8]])] = &[
    (b"FETCH", &[b"FETCH"]),
    (b"SEARCH", &[b"SEARCH"]),
    (b"ESEARCH", &[b"SEARCH"]),
    (b"FLAGS", &[b"SELECT", b"EXAMINE"]),
    (b"EXISTS", &[b"SELECT", b"EXAMINE"]),
    (b"RECENT", &[b"SELECT", b"EXAMINE"]),
    (b"CAPABILITY", &[b"CAPABILITY"]),
    (b"LIST", &[b"LIST"]),
    (b"LSUB", &[b"LSUB"]),
    (b"STATUS", &[b"STATUS"]),
    (b"ID", &[b"ID"]),
    (b"NAMESPACE", &[b"NAMESPACE"]),
    (b"ENABLED", &[b"ENABLE"]),
    (b"SORT", &[b"SORT"]),
    (b"THREAD", &[b"THREAD"]),
    (b"QUOTA", &[b"GETQUOTA", b"GETQUOTAROOT", b"SETQUOTA"]),
    (b"QUOTAROOT", &[b"GETQUOTAROOT"]),
];

pub struct ImapState {
    state_data: AppLayerStateData,
    tx_id: u64,
    transactions: VecDeque<ImapTransaction>,
    request_frame: Option<Frame>,
    response_frame: Option<Frame>,
    request_gap: bool,
    response_gap: bool,
    // Transaction currently receiving a group of untagged responses.
    active_response_tx_id: Option<u64>,
    // Transaction that owns the next client continuation line.
    continuation_tx_id: Option<u64>,
    // Literal announced by the current client command line, until its line ends.
    pending_literal: Option<PendingLiteral>,
    // FETCH response whose literal data is being consumed incrementally.
    pending_fetch_response: Option<PendingFetchResponse>,
    // Literal announced by an untagged non-FETCH response, until its line ends.
    pending_response_literal: Option<PendingResponseLiteral>,
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
            active_response_tx_id: None,
            continuation_tx_id: None,
            pending_literal: None,
            pending_fetch_response: None,
            pending_response_literal: None,
        }
    }

    fn retained_bytes(&self) -> usize {
        self.transactions.iter().map(|tx| tx.retained_bytes).sum()
    }

    fn line_retain_budget(&self) -> usize {
        let used: usize = self.transactions.iter().map(|tx| tx.line_bytes).sum();
        IMAP_MAX_LINE_BYTES_PER_STATE.saturating_sub(used)
    }

    fn tx_by_id(&self, tx_id: u64) -> Option<&ImapTransaction> {
        self.transactions.iter().find(|tx| tx.tx_id == tx_id)
    }

    fn tx_by_id_mut(&mut self, tx_id: u64) -> Option<&mut ImapTransaction> {
        self.transactions.iter_mut().find(|tx| tx.tx_id == tx_id)
    }

    fn email_retain_limit_for_tx(&self, tx_id: Option<u64>) -> usize {
        let state_left = IMAP_MAX_RETAINED_BYTES_PER_STATE.saturating_sub(self.retained_bytes());
        let tx_left = tx_id
            .and_then(|tx_id| self.tx_by_id(tx_id))
            .map(|tx| IMAP_MAX_RETAINED_BYTES_PER_TX.saturating_sub(tx.retained_bytes))
            .unwrap_or(IMAP_MAX_RETAINED_BYTES_PER_TX);
        state_left.min(tx_left)
    }

    fn literal_retain_limit(&self, tx_id: u64, is_email: bool) -> usize {
        if is_email {
            self.email_retain_limit_for_tx(Some(tx_id))
        } else {
            0
        }
    }

    fn active_response_tx_id(&self) -> Option<u64> {
        self.active_response_tx_id
            .and_then(|tx_id| self.tx_by_id(tx_id))
            .filter(|tx| tx.awaiting_response())
            .map(|tx| tx.tx_id)
    }

    fn single_pending_tx_id(&self) -> Option<u64> {
        let mut outstanding = self.transactions.iter().filter(|tx| tx.awaiting_response());
        match (outstanding.next(), outstanding.next()) {
            (Some(tx), None) => Some(tx.tx_id),
            _ => None,
        }
    }

    fn fetch_request_may_include_sequence(
        tx: &ImapTransaction, sequence_number: Option<u32>,
    ) -> bool {
        let Some(sequence_number) = sequence_number else {
            return true;
        };
        let Some(request) = tx.requests.first() else {
            return true;
        };

        match &request.message {
            ImapMessageType::Command {
                command: ImapCommand::Fetch,
                arguments,
                ..
            } => arguments
                .first()
                .and_then(|set| sequence_set_contains(set, sequence_number))
                .unwrap_or(true),
            // An untagged UID FETCH response starts with the message sequence
            // number, not the UID requested by the client.
            _ => true,
        }
    }

    fn resolve_fetch_response_target(&self, sequence_number: Option<u32>) -> Option<u64> {
        let mut candidate = None;
        let mut found_fetch_request = false;

        for tx in self
            .transactions
            .iter()
            .filter(|tx| tx.awaiting_response() && tx.command.eq_ignore_ascii_case(b"FETCH"))
        {
            found_fetch_request = true;
            if !Self::fetch_request_may_include_sequence(tx, sequence_number) {
                continue;
            }
            if candidate.is_some() {
                return None;
            }
            candidate = Some(tx.tx_id);
        }

        if found_fetch_request {
            candidate
        } else {
            self.single_pending_tx_id()
        }
    }

    fn resolve_untagged_response_target(
        &self, sequence_number: Option<u32>, keyword: &[u8],
    ) -> Option<u64> {
        if keyword.eq_ignore_ascii_case(b"FETCH") {
            return self.resolve_fetch_response_target(sequence_number);
        }

        if let Some((_, expected_commands)) = UNTAGGED_KEYWORD_COMMANDS
            .iter()
            .find(|(untagged, _)| keyword.eq_ignore_ascii_case(untagged))
        {
            let mut candidate = None;
            for tx in self.transactions.iter().filter(|tx| tx.awaiting_response()) {
                if expected_commands
                    .iter()
                    .any(|command| tx.command.eq_ignore_ascii_case(command))
                {
                    if candidate.is_some() {
                        return None;
                    }
                    candidate = Some(tx.tx_id);
                }
            }
            return candidate.or_else(|| self.single_pending_tx_id());
        }

        if let Some(tx_id) = self.active_response_tx_id() {
            return Some(tx_id);
        }

        self.single_pending_tx_id()
    }

    fn commit_untagged_response_target(&mut self, target: Option<u64>) -> Option<u64> {
        self.active_response_tx_id = target;
        target
    }

    fn continuation_response_tx_id(&self) -> Option<u64> {
        self.pending_literal
            .as_ref()
            .map(|pending| pending.tx_id)
            .or_else(|| {
                self.transactions
                    .iter()
                    .rev()
                    .find(|tx| {
                        !tx.complete()
                            && tx.progress_ts == ImapStateProgress::ImapStateInProgress
                            && (tx.command.eq_ignore_ascii_case(b"AUTHENTICATE")
                                || tx.command.eq_ignore_ascii_case(b"IDLE"))
                    })
                    .map(|tx| tx.tx_id)
            })
            .or_else(|| {
                self.transactions
                    .iter()
                    .rev()
                    .find(|tx| !tx.complete())
                    .map(|tx| tx.tx_id)
            })
    }

    fn forget_tx(&mut self, tx_id: u64) {
        if self.active_response_tx_id == Some(tx_id) {
            self.active_response_tx_id = None;
        }
        if self.continuation_tx_id == Some(tx_id) {
            self.continuation_tx_id = None;
        }
        if self
            .pending_literal
            .as_ref()
            .is_some_and(|pending| pending.tx_id == tx_id)
        {
            self.pending_literal = None;
        }
        if self
            .pending_fetch_response
            .as_ref()
            .is_some_and(|pending| pending.tx_id == tx_id)
        {
            self.pending_fetch_response = None;
            self.response_frame = None;
        }
        if let Some(pending) = self
            .pending_response_literal
            .as_mut()
            .filter(|pending| pending.tx_id == Some(tx_id))
        {
            pending.tx_id = None;
        }
    }

    fn free_tx(&mut self, tx_id: u64) {
        if let Some(index) = self
            .transactions
            .iter()
            .position(|tx| tx.tx_id == tx_id + 1)
        {
            self.forget_tx(tx_id + 1);
            self.transactions.remove(index);
        }
    }

    pub fn get_tx(&mut self, tx_id: u64) -> Option<&ImapTransaction> {
        self.transactions.iter().find(|tx| tx.tx_id == tx_id + 1)
    }

    pub fn new_tx(&mut self) -> Option<ImapTransaction> {
        if self.transactions.len() >= unsafe { IMAP_MAX_TX } {
            self.active_response_tx_id = None;
            self.continuation_tx_id = None;
            self.pending_literal = None;
            self.pending_fetch_response = None;
            self.pending_response_literal = None;
            self.response_frame = None;
            for tx_old in &mut self.transactions {
                if !tx_old.complete() {
                    tx_old.tx_data.0.updated_tc = true;
                    tx_old.tx_data.0.updated_ts = true;
                    tx_old.progress_ts = ImapStateProgress::ImapStateComplete;
                    tx_old.progress_tc = ImapStateProgress::ImapStateComplete;
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

    /// At end of stream, complete the given direction of every open
    /// transaction so buffers that are already populated (a parsed FETCH email,
    /// the response lines) are inspected even without a tagged completion reply.
    fn complete_transactions_at_eof(&mut self, direction: Direction) {
        for tx in &mut self.transactions {
            match direction {
                Direction::ToServer => tx.complete_request(),
                Direction::ToClient => tx.complete_response(),
            }
        }
    }

    fn push_response_tx(&mut self) -> Option<&mut ImapTransaction> {
        let mut tx = self.new_tx()?;
        tx.tx_data = AppLayerTxData::for_direction(Direction::ToClient);
        tx.progress_ts = ImapStateProgress::ImapStateComplete;
        self.transactions.push_back(tx);
        self.transactions.back_mut()
    }

    fn set_event(&mut self, e: ImapEvent) {
        if let Some(tx) = self.transactions.back_mut() {
            tx.tx_data.set_event(e as u8);
        }
    }

    fn reject_oversized_tag(&mut self, direction: Direction) -> AppLayerResult {
        if let Some(mut tx) = self.new_tx() {
            tx.tx_data = AppLayerTxData::for_direction(direction);
            tx.tx_data.set_event(ImapEvent::LineTooLong as u8);
            tx.progress_ts = ImapStateProgress::ImapStateComplete;
            tx.progress_tc = ImapStateProgress::ImapStateComplete;
            self.transactions.push_back(tx);
        }
        AppLayerResult::err()
    }

    fn find_request(&mut self, tag: &[u8]) -> Option<&mut ImapTransaction> {
        self.transactions
            .iter_mut()
            .find(|tx| tx.request_tag.as_deref() == Some(tag) && !tx.complete())
    }

    fn parse_request(&mut self, flow: *mut Flow, stream_slice: StreamSlice) -> AppLayerResult {
        let input = stream_slice.as_slice();
        if input.is_empty() {
            return AppLayerResult::ok();
        }

        if self.request_gap {
            if parse_command(input).is_err() {
                return AppLayerResult::ok();
            }
            self.request_gap = false;
        }

        let incomplete = |rest: &[u8]| {
            AppLayerResult::incomplete((input.len() - rest.len()) as u32, (rest.len() + 1) as u32)
        };
        let mut start = input;
        while !start.is_empty() {
            if let Some((tx_id, is_email, depth)) = self
                .pending_literal
                .as_ref()
                .filter(|pending| pending.awaiting_line_rest)
                .map(|pending| (pending.tx_id, pending.is_email, pending.parenthesis_depth))
            {
                match parse_command_continuation(start, depth) {
                    Ok((rem, (request, literal))) => {
                        if !request.raw_line.is_empty() {
                            let line_budget = self.line_retain_budget();
                            if let Some(tx) = self.tx_by_id_mut(tx_id) {
                                let line = request.raw_line.clone();
                                tx.add_request(request, line, line_budget);
                            }
                        }
                        if let Some(literal) = literal {
                            let retain_limit = self.literal_retain_limit(tx_id, is_email);
                            self.pending_literal =
                                Some(PendingLiteral::new(tx_id, literal, retain_limit, is_email));
                        } else {
                            self.pending_literal = None;
                            if let Some(tx) = self.tx_by_id_mut(tx_id) {
                                tx.complete_request();
                            }
                        }
                        start = rem;
                        continue;
                    }
                    Err(Err::Incomplete(_)) => return incomplete(start),
                    Err(_) => {
                        self.set_event(ImapEvent::InvalidData);
                        return AppLayerResult::err();
                    }
                }
            }

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

            if let Some(mut pending) = self.pending_literal.take_if(|pending| pending.is_ready()) {
                if pending.is_email && pending.literal.bytes_consumed == 0 {
                    pending.email_frame = PendingEmailFrame::create(
                        flow,
                        &stream_slice,
                        start,
                        pending.tx_id,
                        pending.literal.size,
                        FetchBodySection::Full,
                    );
                }
                let consumed = pending.consume_chunk(flow, &stream_slice, start);
                if pending.literal.remaining() != 0 {
                    self.pending_literal = Some(pending);
                    return AppLayerResult::ok();
                }

                let tx_id = pending.tx_id;
                let is_email = pending.is_email;
                let literal = &mut pending.literal;
                let email = if is_email {
                    parse_email_content(std::mem::take(&mut literal.buffer))
                } else {
                    None
                };

                let retain_limit = self.email_retain_limit_for_tx(Some(tx_id));

                if let Some(tx) = self.tx_by_id_mut(tx_id) {
                    tx.tx_data.0.updated_ts = true;

                    if is_email
                        && literal.size > u64::try_from(IMAP_MAX_BODY_SIZE).unwrap_or(u64::MAX)
                    {
                        tx.tx_data.set_event(ImapEvent::BodyTooLarge as u8);
                    }
                    if is_email && literal.truncated {
                        tx.mark_data_limit();
                    }
                    if let Some(email) = email {
                        tx.retain_parsed_email(email, STREAM_TOSERVER, retain_limit);
                    }

                    let frame_len = i64::try_from(literal.size).unwrap_or(i64::MAX);
                    self.set_frame_ts(flow, tx_id, frame_len);
                }

                pending.awaiting_line_rest = true;
                self.pending_literal = Some(pending);
                start = &start[consumed..];
                continue;
            }

            if let Some(continuation_tx_id) = self.continuation_tx_id {
                match parse_continuation_data(start) {
                    Ok((rem, request)) => {
                        let consumed = start.len() - rem.len();

                        self.continuation_tx_id = None;

                        let line_budget = self.line_retain_budget();
                        if let Some(tx) = self
                            .tx_by_id_mut(continuation_tx_id)
                            .filter(|tx| !tx.complete())
                        {
                            let tx_id = tx.id();
                            let data = request.raw_line.as_slice();
                            let completes_request = (tx.command.eq_ignore_ascii_case(b"IDLE")
                                && data.eq_ignore_ascii_case(b"DONE"))
                                || (tx.command.eq_ignore_ascii_case(b"AUTHENTICATE")
                                    && data == b"*");
                            let line = request.raw_line.clone();
                            tx.add_request(request, line, line_budget);
                            if completes_request {
                                tx.complete_request();
                            }
                            start = rem;
                            self.set_frame_ts(flow, tx_id, consumed as i64);
                            continue;
                        }
                    }
                    Err(Err::Incomplete(_)) => return incomplete(start),
                    Err(_) => {}
                }
                self.continuation_tx_id = None;
                if let Some(pos) = start.iter().position(|&c| c == b'\n') {
                    start = &start[pos + 1..];
                    continue;
                } else {
                    break;
                }
            }

            match parse_command(start) {
                Ok((rem, request)) => {
                    let consumed = start.len() - rem.len();

                    let mut setup_literal = None;
                    let mut client_data_pending = false;
                    if let ImapMessageType::Command {
                        command, literal, ..
                    } = &request.message
                    {
                        if let Some(literal) = literal {
                            let is_email = matches!(command, ImapCommand::Append);
                            setup_literal = Some((*literal, is_email));
                            client_data_pending = true;
                        }
                        if matches!(command, ImapCommand::Authenticate | ImapCommand::Idle) {
                            client_data_pending = true;
                        }
                    }

                    let line_budget = self.line_retain_budget();
                    let Some(mut tx) = self.new_tx() else {
                        return AppLayerResult::err();
                    };
                    let tx_id = tx.id();
                    let line = request_line(&request);
                    if !tx.add_request(request, line, line_budget) {
                        tx.progress_ts = ImapStateProgress::ImapStateComplete;
                        tx.progress_tc = ImapStateProgress::ImapStateComplete;
                        self.transactions.push_back(tx);
                        return AppLayerResult::err();
                    }
                    if !client_data_pending {
                        tx.complete_request();
                    }
                    self.transactions.push_back(tx);
                    start = rem;
                    self.set_frame_ts(flow, tx_id, consumed as i64);

                    if let Some((literal, is_email)) = setup_literal {
                        let retain_limit = self.literal_retain_limit(tx_id, is_email);
                        self.pending_literal =
                            Some(PendingLiteral::new(tx_id, literal, retain_limit, is_email));
                    }
                }
                Err(Err::Incomplete(_)) => return incomplete(start),
                Err(Err::Error(e)) if e.code == ErrorKind::Eof => {
                    break;
                }
                Err(Err::Failure(e)) if e.code == ErrorKind::TooLarge => {
                    return self.reject_oversized_tag(Direction::ToServer);
                }
                Err(_e) => {
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
            if probe_response(input).is_err() {
                return AppLayerResult::ok();
            }
            self.response_gap = false;
        }

        let incomplete = |rest: &[u8]| {
            AppLayerResult::incomplete((input.len() - rest.len()) as u32, (rest.len() + 1) as u32)
        };
        let mut start = input;
        while !start.is_empty() {
            if let Some(tx_id) = self
                .pending_response_literal
                .as_ref()
                .filter(|pending| pending.awaiting_line_rest)
                .map(|pending| pending.tx_id)
            {
                match parse_response_continuation(start) {
                    Ok((rem, literal_size)) => {
                        self.pending_response_literal =
                            literal_size.map(|size| PendingResponseLiteral::new(tx_id, size));
                        start = rem;
                        continue;
                    }
                    Err(Err::Incomplete(_)) => return incomplete(start),
                    Err(_) => {
                        self.set_event(ImapEvent::InvalidData);
                        return AppLayerResult::err();
                    }
                }
            }

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

            if let Some(pending) = self
                .pending_response_literal
                .as_mut()
                .filter(|pending| !pending.awaiting_line_rest)
            {
                let consumed = pending.literal.consume_chunk(start);
                if pending.literal.remaining() != 0 {
                    return AppLayerResult::ok();
                }

                pending.awaiting_line_rest = true;
                let tx_id = pending.tx_id;
                let frame_len = i64::try_from(pending.literal.size).unwrap_or(i64::MAX);
                if let Some(tx_id) = tx_id {
                    self.set_frame_tc(flow, tx_id, frame_len);
                } else {
                    self.response_frame = None;
                }
                start = &start[consumed..];
                continue;
            }

            if let Some(pending) = self.pending_fetch_response.as_mut() {
                if let Some(email_frame) = pending.email_frame.as_mut() {
                    if email_frame.consume(flow, &stream_slice, start, pending.tx_id) {
                        pending.email_frame = None;
                    }
                }
                let progress = pending.parser.consume(start);

                match progress {
                    Ok(FetchResponseProgress::LiteralStart {
                        consumed,
                        literal_size,
                        section,
                    }) => {
                        let literal_start = &start[consumed..];
                        if let Some(pending) = self.pending_fetch_response.as_mut() {
                            pending.frame_len = pending.frame_len.saturating_add(consumed);
                            pending.email_frame = PendingEmailFrame::create(
                                flow,
                                &stream_slice,
                                literal_start,
                                pending.tx_id,
                                literal_size,
                                section,
                            );
                        }
                        start = literal_start;
                        continue;
                    }
                    Ok(FetchResponseProgress::Incomplete { consumed }) => {
                        if let Some(pending) = self.pending_fetch_response.as_mut() {
                            pending.frame_len = pending.frame_len.saturating_add(consumed);
                            if let Some(tx) = self
                                .transactions
                                .iter_mut()
                                .find(|tx| tx.tx_id == pending.tx_id)
                            {
                                tx.tx_data.0.updated_tc = true;
                            }
                        }
                        start = &start[consumed..];
                        continue;
                    }
                    Ok(FetchResponseProgress::Complete { consumed, message }) => {
                        let Some(pending) = self.pending_fetch_response.take() else {
                            self.response_frame = None;
                            return AppLayerResult::err();
                        };
                        let tx_id = pending.tx_id;
                        let frame_len = pending.frame_len.saturating_add(consumed);
                        let retain_limit = self.email_retain_limit_for_tx(Some(tx_id));
                        let line_budget = self.line_retain_budget();

                        if let Some(tx) = self.tx_by_id_mut(tx_id) {
                            tx.add_response(message, retain_limit, line_budget);
                            let frame_len = i64::try_from(frame_len).unwrap_or(i64::MAX);
                            self.set_frame_tc(flow, tx_id, frame_len);
                        } else {
                            self.response_frame = None;
                        }

                        start = &start[consumed..];
                        continue;
                    }
                    Err(_) => {
                        self.response_frame = None;
                        if let Some(pending) = self.pending_fetch_response.take() {
                            if let Some(email_frame) = pending.email_frame {
                                email_frame.close_headers(flow);
                            }
                            if let Some(tx) = self.tx_by_id_mut(pending.tx_id) {
                                tx.tx_data.set_event(ImapEvent::InvalidData as u8);
                            }
                        }
                        return AppLayerResult::err();
                    }
                }
            }

            let untagged = peek_untagged(start);
            let untagged_response_target = untagged.and_then(|(sequence_number, keyword)| {
                self.resolve_untagged_response_target(sequence_number, keyword)
            });
            let retain_limit = self.email_retain_limit_for_tx(untagged_response_target);
            let line_budget = self.line_retain_budget();

            if untagged.is_some_and(|(_, keyword)| keyword.eq_ignore_ascii_case(b"FETCH")) {
                match FetchResponseState::new(start, retain_limit) {
                    Ok((rem, parser)) => {
                        let tx_id =
                            match self.commit_untagged_response_target(untagged_response_target) {
                                Some(tx_id) => tx_id,
                                None => {
                                    let Some(tx) = self.push_response_tx() else {
                                        self.response_frame = None;
                                        return AppLayerResult::err();
                                    };
                                    tx.id()
                                }
                            };

                        if let Some(tx) = self.tx_by_id_mut(tx_id) {
                            tx.tx_data.0.updated_tc = true;
                        }

                        self.pending_fetch_response = Some(PendingFetchResponse {
                            tx_id,
                            frame_len: start.len() - rem.len(),
                            parser,
                            email_frame: None,
                        });
                        start = rem;
                        continue;
                    }
                    Err(Err::Incomplete(_)) => return incomplete(start),
                    Err(_) => {
                        self.set_event(ImapEvent::InvalidData);
                        self.response_frame = None;
                        return AppLayerResult::err();
                    }
                }
            }

            match parse_response(start, retain_limit) {
                Ok((rem, response)) => {
                    let consumed = start.len() - rem.len();

                    if let Some(ref tag) = response.tag {
                        if let Some(tx) = self.find_request(tag) {
                            let tx_id = tx.id();
                            /* The reply that completes a STARTTLS command with
                             * OK is the one that switches the flow to TLS. */
                            let starttls_ok = tx.command.eq_ignore_ascii_case(b"STARTTLS")
                                && matches!(
                                    response.message,
                                    ImapMessageType::Response {
                                        status: ImapResponseStatus::Ok
                                    }
                                );
                            tx.add_response(response, retain_limit, line_budget);
                            if starttls_ok {
                                SCLogDebug!("IMAP: STARTTLS completed");
                                unsafe {
                                    SCAppLayerRequestProtocolTLSUpgrade(flow);
                                }
                            }
                            /* The tagged reply completes the command, so no
                             * pending client or server state may refer to it. */
                            self.forget_tx(tx_id);
                            self.set_frame_tc(flow, tx_id, consumed as i64);
                        } else {
                            let Some(tx) = self.push_response_tx() else {
                                return AppLayerResult::err();
                            };
                            let tx_id = tx.id();
                            tx.add_response(response, retain_limit, line_budget);
                            self.set_frame_tc(flow, tx_id, consumed as i64);
                        }
                    } else {
                        let is_continuation =
                            matches!(response.message, ImapMessageType::Continuation);

                        let untagged_target = if let ImapMessageType::Untagged {
                            seq_number,
                            keyword,
                            ..
                        } = &response.message
                        {
                            Some(untagged_response_target.or_else(|| {
                                self.resolve_untagged_response_target(*seq_number, keyword)
                            }))
                        } else {
                            None
                        };
                        let response_tx_id = if let Some(target) = untagged_target {
                            self.commit_untagged_response_target(target)
                        } else if is_continuation {
                            self.continuation_response_tx_id()
                        } else {
                            self.transactions
                                .iter()
                                .rev()
                                .find(|tx| !tx.complete())
                                .map(|tx| tx.tx_id)
                        };

                        if is_continuation {
                            if let Some(pending) = self.pending_literal.as_mut() {
                                if !pending.literal.is_literal_plus {
                                    pending.continuation_received = true;
                                }
                            } else {
                                self.continuation_tx_id = response_tx_id;
                            }
                        }

                        let tx_id =
                            match response_tx_id.filter(|&tx_id| self.tx_by_id(tx_id).is_some()) {
                                Some(tx_id) => tx_id,
                                None => {
                                    if untagged_target.is_some() {
                                        self.active_response_tx_id = None;
                                    }
                                    if is_continuation {
                                        self.continuation_tx_id = None;
                                    }
                                    let Some(tx) = self.push_response_tx() else {
                                        return AppLayerResult::err();
                                    };
                                    tx.id()
                                }
                            };

                        /* A data response (LIST, STATUS, ID, ...) may end in a
                         * literal specifier: its octets follow the CRLF. */
                        let literal_size = match &response.message {
                            ImapMessageType::Untagged { keyword, .. } => untagged_trailing_literal(
                                keyword,
                                &start[..consumed.saturating_sub(2)],
                            ),
                            _ => None,
                        };

                        if let Some(tx) = self.tx_by_id_mut(tx_id) {
                            tx.add_response(response, retain_limit, line_budget);
                        }
                        self.set_frame_tc(flow, tx_id, consumed as i64);
                        if let Some(size) = literal_size {
                            self.pending_response_literal =
                                Some(PendingResponseLiteral::new(Some(tx_id), size));
                        }
                    }
                    start = rem;
                }
                Err(Err::Incomplete(_)) => return incomplete(start),
                Err(Err::Error(e)) if e.code == ErrorKind::Eof => {
                    break;
                }
                Err(Err::Failure(e)) if e.code == ErrorKind::TooLarge => {
                    return self.reject_oversized_tag(Direction::ToClient);
                }
                Err(_e) => {
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
            frame.set_tx(flow, tx_id - 1);
            self.request_frame = None;
        }
    }

    fn set_frame_tc(&mut self, flow: *const Flow, tx_id: u64, consumed: i64) {
        if let Some(frame) = &self.response_frame {
            frame.set_len(flow, consumed);
            frame.set_tx(flow, tx_id - 1);
            self.response_frame = None;
        }
    }

    fn on_request_gap(&mut self, flow: *const Flow, _size: u32) {
        self.request_gap = true;
        self.continuation_tx_id = None;
        if let Some(email_frame) = self.pending_literal.take().and_then(|p| p.email_frame) {
            email_frame.close_headers(flow);
        }
        self.request_frame = None;
    }

    fn on_response_gap(&mut self, flow: *const Flow, _size: u32) {
        self.response_gap = true;
        self.active_response_tx_id = None;
        self.continuation_tx_id = None;
        if let Some(email_frame) = self.pending_literal.take().and_then(|p| p.email_frame) {
            email_frame.close_headers(flow);
        }
        if let Some(email_frame) = self
            .pending_fetch_response
            .take()
            .and_then(|p| p.email_frame)
        {
            email_frame.close_headers(flow);
        }
        self.pending_response_literal = None;
        self.response_frame = None;
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ProbeResult {
    Match { flip: bool },
    Incomplete,
    Mismatch,
}

fn probe_request(input: &[u8]) -> Result<bool, Err<Error<&[u8]>>> {
    match parse_command(input) {
        Ok((_, request)) => Ok(!matches!(
            request.message,
            ImapMessageType::Command {
                command: ImapCommand::Unknown(_),
                ..
            }
        )),
        Err(Err::Incomplete(needed)) => {
            if matches!(probe_command_prefix(input), Ok((_, true))) {
                Ok(true)
            } else {
                Err(Err::Incomplete(needed))
            }
        }
        Err(e) => Err(e),
    }
}

fn probe_response(input: &[u8]) -> Result<bool, Err<Error<&[u8]>>> {
    if FetchResponseState::new(input, 0).is_ok() {
        return Ok(true);
    }
    parse_response(input, 0).map(|_| true)
}

fn probe(input: &[u8], dir: Direction) -> ProbeResult {
    let to_server = dir.is_to_server();
    let res = if to_server {
        probe_request(input)
    } else {
        probe_response(input)
    };
    match res {
        Ok(true) => return ProbeResult::Match { flip: false },
        Err(Err::Incomplete(_)) => return ProbeResult::Incomplete,
        Ok(false) | Err(_) => {}
    }
    // try the opposite direction
    let res = if to_server {
        probe_response(input)
    } else {
        probe_request(input)
    };
    match res {
        Ok(true) => ProbeResult::Match { flip: true },
        Err(Err::Incomplete(_)) => ProbeResult::Incomplete,
        Ok(false) | Err(_) => ProbeResult::Mismatch,
    }
}

unsafe extern "C" fn imap_probing_parser(
    _flow: *const Flow, direction: u8, input: *const u8, input_len: u32, rdir: *mut u8,
) -> AppProto {
    if input_len > 1 && !input.is_null() {
        let slice = build_slice!(input, input_len as usize);
        let dir: Direction = direction.into();
        return match probe(slice, dir) {
            ProbeResult::Match { flip } => {
                if flip {
                    *rdir = match dir {
                        Direction::ToServer => Direction::ToClient,
                        Direction::ToClient => Direction::ToServer,
                    }
                    .into();
                }
                ALPROTO_IMAP
            }
            ProbeResult::Incomplete => ALPROTO_UNKNOWN,
            ProbeResult::Mismatch => ALPROTO_FAILED,
        };
    }
    return ALPROTO_UNKNOWN;
}

fn capability_tag_has_digit(input: &[u8]) -> bool {
    input
        .iter()
        .take_while(|&&b| b != b' ')
        .any(|b| b.is_ascii_digit())
}

unsafe extern "C" fn imap_capability_probing_parser(
    flow: *const Flow, _direction: u8, input: *const u8, input_len: u32, _rdir: *mut u8,
) -> AppProto {
    let alproto_tc = SCFlowGetAppProtocolToClient(flow);
    if alproto_tc == ALPROTO_IMAP {
        return ALPROTO_IMAP;
    }
    if !input.is_null() && capability_tag_has_digit(build_slice!(input, input_len as usize)) {
        return ALPROTO_IMAP;
    }
    let mut size_tc: u32 = 0;
    if !SCAppLayerProtoDetectGetStreamDataSize(flow, STREAM_TOCLIENT, &mut size_tc) {
        return ALPROTO_FAILED;
    }
    if size_tc < 8 && alproto_tc == ALPROTO_UNKNOWN {
        return ALPROTO_UNKNOWN;
    }
    return ALPROTO_FAILED;
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
    let eof = SCAppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TS) > 0;
    if stream_slice.is_empty() && !eof {
        return AppLayerResult::err();
    }
    let state = cast_pointer!(state, ImapState);

    let result = if stream_slice.is_gap() {
        state.on_request_gap(flow, stream_slice.gap_size());
        AppLayerResult::ok()
    } else {
        state.parse_request(flow, stream_slice)
    };
    if eof {
        state.complete_transactions_at_eof(Direction::ToServer);
    }
    result
}

unsafe extern "C" fn imap_parse_response(
    flow: *mut Flow, state: *mut c_void, pstate: *mut AppLayerParserState,
    stream_slice: StreamSlice, _data: *mut c_void,
) -> AppLayerResult {
    let eof = SCAppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TC) > 0;
    if stream_slice.is_empty() && !eof {
        return AppLayerResult::err();
    }
    let state = cast_pointer!(state, ImapState);
    let result = if stream_slice.is_gap() {
        state.on_response_gap(flow, stream_slice.gap_size());
        AppLayerResult::ok()
    } else {
        state.parse_response(flow, stream_slice)
    };
    if eof {
        state.complete_transactions_at_eof(Direction::ToClient);
    }
    result
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

unsafe extern "C" fn imap_tx_get_alstate_progress(tx: *mut c_void, direction: u8) -> c_int {
    let tx = cast_pointer!(tx, ImapTransaction);
    if direction == STREAM_TOSERVER {
        return tx.progress_ts as c_int;
    }
    return tx.progress_tc as c_int;
}

#[no_mangle]
pub unsafe extern "C" fn SCImapMimeBodyMd5IsEnabled() -> bool {
    IMAP_MIME_BODY_MD5_ENABLED
}

#[no_mangle]
pub unsafe extern "C" fn SCImapMimeBodyMd5IsDisabled() -> bool {
    IMAP_MIME_BODY_MD5_DISABLED
}

#[no_mangle]
pub unsafe extern "C" fn SCImapMimeConfigBodyMd5(val: bool) {
    if val {
        IMAP_MIME_BODY_MD5_ENABLED = true;
    } else {
        IMAP_MIME_BODY_MD5_DISABLED = true;
    }
}

export_tx_data_get!(imap_get_tx_data, ImapTransaction);
export_state_data_get!(imap_get_state_data, ImapState);

const PARSER_NAME: &[u8] = b"imap\0";

fn register_pattern_probe() -> i8 {
    const PATTERNS: &[&[u8]] = &[
        b"* OK \0",
        b"* NO \0",
        b"* BAD \0",
        b"* LIST \0",
        b"* ESEARCH \0",
        b"* STATUS \0",
        b"* FLAGS \0",
    ];
    for pattern in PATTERNS {
        let depth = (pattern.len() - 1) as u16;
        let r = unsafe {
            SCAppLayerProtoDetectPMRegisterPatternCI(
                IPPROTO_TCP,
                ALPROTO_IMAP,
                pattern.as_ptr() as *const c_char,
                depth,
                0,
                Direction::ToClient as u8,
            )
        };
        if r < 0 {
            return -1;
        }
    }
    // The client CAPABILITY command has no fixed server response to key on, so
    // detect it on the request side, independent of port. Depth 17 allows up to
    // a 6-char tag + space + "CAPABILITY", matching the historical detector.
    // "USER CAPABILITY" may be FTP as well, so a probing parser disambiguates.
    let capability = b" CAPABILITY\0";
    let r = unsafe {
        SCAppLayerProtoDetectPMRegisterPatternCIwPP(
            IPPROTO_TCP,
            ALPROTO_IMAP,
            capability.as_ptr() as *const c_char,
            17,
            0,
            Direction::ToServer as u8,
            Some(imap_capability_probing_parser),
            12,
            17,
        )
    };
    if r < 0 {
        return -1;
    }
    0
}

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
        get_state_id_by_name: Some(ImapStateProgress::ffi_id_from_name),
        get_state_name_by_id: Some(ImapStateProgress::ffi_name_from_id),
    };

    let ip_proto_str = CString::new("tcp").unwrap();
    if SCAppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = applayer_register_protocol_detection(&parser, 1);
        ALPROTO_IMAP = alproto;
        if register_pattern_probe() < 0 {
            return;
        }
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
        if let Some(val) = conf_get("app-layer.protocols.imap.mime.body-md5") {
            if val == "true" || val == "yes" {
                IMAP_MIME_BODY_MD5_ENABLED = true;
            } else if val == "false" || val == "no" {
                IMAP_MIME_BODY_MD5_DISABLED = true;
            } else if val != "auto" {
                SCLogWarning!("Unknown value for imap.mime.body-md5: {}", val);
            }
        }
        SCAppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_IMAP);
    } else {
        SCLogDebug!("Protocol detection and parser disabled for IMAP/TCP.");
    }
}
