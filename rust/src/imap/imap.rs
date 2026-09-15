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
    extract_literal_from_arguments, imap_parse_message, parse_continuation_data,
    parse_email_content, peek_untagged, sequence_set_contains, EmailData, FetchBodySection,
    FetchResponseProgress, FetchResponseState, ImapCommand, ImapMessage, ImapMessageType,
    ImapResponseStatus, LiteralInfo, IMAP_MAX_BODY_SIZE, IMAP_MAX_LINE_SIZE,
};
use nom8::character::streaming::crlf;
use nom8::error::{Error, ErrorKind};
use nom8::{Err, Parser};
use std;
use std::collections::VecDeque;
use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_void};
use suricata_sys::sys::{
    AppLayerParserState, AppProto, SCAppLayerParserConfParserEnabled,
    SCAppLayerParserRegisterLogger, SCAppLayerParserStateIssetFlag,
    SCAppLayerProtoDetectConfProtoDetectionEnabled, SCAppLayerProtoDetectPMRegisterPatternCI,
    SCAppLayerRequestProtocolTLSUpgrade,
};

static IMAP_MAX_TX_DEFAULT: usize = 256;
static IMAP_MAX_LINES: usize = 512;
static IMAP_MAX_MSGS_PER_TX: usize = 512;
static IMAP_MAX_RETAINED_BYTES_PER_TX: usize = 10 * 1024 * 1024;
static IMAP_MAX_RETAINED_BYTES_PER_STATE: usize = 100 * 1024 * 1024;

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
pub struct ImapParsedHeader {
    pub data: Vec<u8>,
    pub name_len: usize,
    pub value_offset: usize,
}

#[derive(Debug, Default)]
pub struct ImapParsedEmail {
    pub command: Vec<u8>,
    pub body: Vec<u8>,
    pub headers: Vec<ImapParsedHeader>,
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

fn extract_command(request: &ImapMessage) -> Vec<u8> {
    if let ImapMessageType::Command { command, arguments } = &request.message {
        // UID is a prefix, the actual command (FETCH, STORE, etc.) is in arguments[0]
        if matches!(command, ImapCommand::Uid) {
            arguments.first().cloned().unwrap_or_default()
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
    pub complete: bool,

    progress_ts: ImapStateProgress,
    progress_tc: ImapStateProgress,

    pub requests: Vec<ImapMessage>,
    pub responses: Vec<ImapMessage>,
    pub request_lines: Vec<Vec<u8>>,
    pub response_lines: Vec<Vec<u8>>,

    pub parsed_emails: Vec<ImapParsedEmail>,

    request_tag: Option<Vec<u8>>,
    pub command: Vec<u8>,
    retained_bytes: usize,
    data_limit_event_set: bool,

    tx_data: AppLayerTxData,
}

impl ImapTransaction {
    pub fn new() -> ImapTransaction {
        Self {
            tx_id: 0,
            complete: false,
            progress_ts: ImapStateProgress::ImapStateInProgress,
            progress_tc: ImapStateProgress::ImapStateInProgress,
            requests: Vec::new(),
            responses: Vec::new(),
            request_lines: Vec::new(),
            response_lines: Vec::new(),
            parsed_emails: Vec::new(),
            request_tag: None,
            command: Vec::new(),
            retained_bytes: 0,
            data_limit_event_set: false,
            tx_data: AppLayerTxData::new(),
        }
    }

    fn update_completion_from_response(&mut self, response: &ImapMessage) {
        let completes = if let Some(request_tag) = &self.request_tag {
            response.tag.as_deref() == Some(request_tag.as_slice())
                && matches!(response.message, ImapMessageType::Response { .. })
        } else {
            response.is_response()
        };
        if completes {
            if self.request_tag.is_some() {
                self.complete_request();
            }
            self.complete = true;
            self.progress_tc = ImapStateProgress::ImapStateComplete;
        }
    }

    fn complete_request(&mut self) {
        if self.progress_ts != ImapStateProgress::ImapStateComplete {
            self.progress_ts = ImapStateProgress::ImapStateComplete;
            self.tx_data.0.updated_ts = true;
        }
    }

    fn mark_data_limit(&mut self) {
        if !self.data_limit_event_set {
            self.tx_data.set_event(ImapEvent::DataLimitReached as u8);
            self.data_limit_event_set = true;
        }
    }

    fn retain_parsed_email(&mut self, email: ImapParsedEmail, retain_limit: usize) {
        if self.parsed_emails.len() >= IMAP_MAX_MSGS_PER_TX {
            self.mark_data_limit();
            return;
        }
        let size = email.retained_size();
        if size <= retain_limit
            && self.retained_bytes.saturating_add(size) <= IMAP_MAX_RETAINED_BYTES_PER_TX
        {
            self.retained_bytes = self.retained_bytes.saturating_add(size);
            self.parsed_emails.push(email);
        } else {
            self.mark_data_limit();
        }
    }
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

fn build_parsed_email(
    email: EmailData, command: Vec<u8>, direction: u8,
) -> (ImapParsedEmail, bool) {
    let body_md5 = if unsafe { IMAP_MIME_BODY_MD5_ENABLED } && !email.email_body.is_empty() {
        let hash = Md5::digest(&email.email_body);
        Some(format!("{:x}", hash))
    } else {
        None
    };
    let mut parsed_email = ImapParsedEmail {
        command,
        body: email.email_body,
        headers: Vec::new(),
        direction,
        body_md5,
    };
    for (name, values) in email.headers {
        for value in values {
            let name_len = name.len();
            let value_offset = name_len + 2;
            let mut header = Vec::with_capacity(value_offset + value.len());
            header.extend_from_slice(name.as_bytes());
            header.extend_from_slice(b": ");
            header.extend_from_slice(value.as_bytes());
            parsed_email.headers.push(ImapParsedHeader {
                data: header,
                name_len,
                value_offset,
            });
        }
    }
    (parsed_email, email.too_many_headers)
}

fn extract_parsed_email_from_response(
    response: &mut ImapMessage, command: Vec<u8>, direction: u8,
) -> Option<(ImapParsedEmail, bool)> {
    if let ImapMessageType::Untagged {
        fetch_data: Some(fetch),
        ..
    } = &mut response.message
    {
        if let Some(email_data) = fetch.take_email() {
            return Some(build_parsed_email(email_data, command, direction));
        }
    }
    None
}

fn update_tx_with_response_email(
    tx: &mut ImapTransaction, response: &mut ImapMessage, command: Vec<u8>, direction: u8,
    retain_limit: usize,
) {
    if response.line_truncated {
        tx.tx_data.set_event(ImapEvent::LineTooLong as u8);
    }

    let parsed_email = extract_parsed_email_from_response(response, command, direction);
    let body_too_large = matches!(
        &response.message,
        ImapMessageType::Untagged {
            fetch_data: Some(fetch),
            ..
        } if fetch.body_too_large
    );
    let data_limit_reached = matches!(
        &response.message,
        ImapMessageType::Untagged {
            fetch_data: Some(fetch),
            ..
        } if fetch.data_limit_reached
    );
    if let Some((email, too_many)) = parsed_email {
        if too_many {
            tx.tx_data.set_event(ImapEvent::TooManyHeaders as u8);
        }
        tx.retain_parsed_email(email, retain_limit);
    }
    if body_too_large {
        tx.tx_data.set_event(ImapEvent::BodyTooLarge as u8);
    }
    if data_limit_reached {
        tx.mark_data_limit();
    }
    if let ImapMessageType::Untagged {
        data, fetch_data, ..
    } = &mut response.message
    {
        *data = None;
        *fetch_data = None;
    }
}

#[derive(Debug)]
struct PendingLiteral {
    tx_id: u64,
    request_tag: Vec<u8>,
    literal: LiteralInfo,
    continuation_received: bool,
}

impl PendingLiteral {
    fn new(
        tx_id: u64, request_tag: Vec<u8>, size: u64, is_literal_plus: bool, retain_limit: usize,
    ) -> Self {
        Self {
            tx_id,
            request_tag,
            literal: LiteralInfo::new(size, is_literal_plus, retain_limit),
            continuation_received: false,
        }
    }

    fn is_ready(&self) -> bool {
        self.literal.is_literal_plus || self.continuation_received
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
            FetchBodySection::Header { .. } => {
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
            FetchBodySection::Part(_) | FetchBodySection::Unknown(_) => return None,
        }
    }

    fn remaining(&self) -> u64 {
        self.literal_size.saturating_sub(self.observed)
    }

    fn consume(
        &mut self, flow: *mut Flow, stream_slice: &StreamSlice, input: &[u8], tx_id: u64,
    ) -> bool {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum UntaggedResponseTarget {
    Transaction(u64),
    Ambiguous,
    Unsolicited,
}

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
    // Pending literal data being collected (for APPEND command)
    pending_literal: Option<PendingLiteral>,
    // APPEND transaction whose completed literal still needs its trailing CRLF.
    pending_literal_crlf_tx_id: Option<u64>,
    // FETCH response whose literal data is being consumed incrementally.
    pending_fetch_response: Option<PendingFetchResponse>,
    request_tls: bool,
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
            pending_literal_crlf_tx_id: None,
            pending_fetch_response: None,
            request_tls: false,
        }
    }

    fn retained_bytes(&self) -> usize {
        self.transactions.iter().map(|tx| tx.retained_bytes).sum()
    }

    fn email_retain_limit_for_tx(&self, tx_id: Option<u64>) -> usize {
        let state_left = IMAP_MAX_RETAINED_BYTES_PER_STATE.saturating_sub(self.retained_bytes());
        let tx_left = tx_id
            .and_then(|tx_id| self.transactions.iter().find(|tx| tx.tx_id == tx_id))
            .map(|tx| IMAP_MAX_RETAINED_BYTES_PER_TX.saturating_sub(tx.retained_bytes))
            .unwrap_or(IMAP_MAX_RETAINED_BYTES_PER_TX);
        state_left.min(tx_left)
    }

    fn active_response_tx_id(&self) -> Option<u64> {
        self.active_response_tx_id.and_then(|tx_id| {
            self.transactions
                .iter()
                .find(|tx| tx.tx_id == tx_id && !tx.complete && tx.request_tag.is_some())
                .map(|tx| tx.tx_id)
        })
    }

    fn expected_commands_for_untagged_keyword(keyword: &[u8]) -> Option<&'static [&'static [u8]]> {
        if keyword.eq_ignore_ascii_case(b"FETCH") {
            Some(&[b"FETCH"])
        } else if keyword.eq_ignore_ascii_case(b"SEARCH")
            || keyword.eq_ignore_ascii_case(b"ESEARCH")
        {
            Some(&[b"SEARCH"])
        } else if keyword.eq_ignore_ascii_case(b"FLAGS")
            || keyword.eq_ignore_ascii_case(b"EXISTS")
            || keyword.eq_ignore_ascii_case(b"RECENT")
        {
            Some(&[b"SELECT", b"EXAMINE"])
        } else if keyword.eq_ignore_ascii_case(b"CAPABILITY") {
            Some(&[b"CAPABILITY"])
        } else if keyword.eq_ignore_ascii_case(b"LIST") {
            Some(&[b"LIST"])
        } else if keyword.eq_ignore_ascii_case(b"LSUB") {
            Some(&[b"LSUB"])
        } else if keyword.eq_ignore_ascii_case(b"STATUS") {
            Some(&[b"STATUS"])
        } else if keyword.eq_ignore_ascii_case(b"ID") {
            Some(&[b"ID"])
        } else if keyword.eq_ignore_ascii_case(b"NAMESPACE") {
            Some(&[b"NAMESPACE"])
        } else if keyword.eq_ignore_ascii_case(b"ENABLED") {
            Some(&[b"ENABLE"])
        } else if keyword.eq_ignore_ascii_case(b"SORT") {
            Some(&[b"SORT"])
        } else if keyword.eq_ignore_ascii_case(b"THREAD") {
            Some(&[b"THREAD"])
        } else if keyword.eq_ignore_ascii_case(b"QUOTA") {
            Some(&[b"GETQUOTA", b"GETQUOTAROOT", b"SETQUOTA"])
        } else if keyword.eq_ignore_ascii_case(b"QUOTAROOT") {
            Some(&[b"GETQUOTAROOT"])
        } else {
            None
        }
    }

    fn sole_outstanding_response_target(&self) -> UntaggedResponseTarget {
        let mut outstanding = self
            .transactions
            .iter()
            .filter(|tx| !tx.complete && tx.request_tag.is_some());
        match (outstanding.next(), outstanding.next()) {
            (None, _) => UntaggedResponseTarget::Unsolicited,
            (Some(tx), None) => UntaggedResponseTarget::Transaction(tx.tx_id),
            (Some(_), Some(_)) => UntaggedResponseTarget::Ambiguous,
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
            } => arguments
                .first()
                .and_then(|set| sequence_set_contains(set, sequence_number))
                .unwrap_or(true),
            // An untagged UID FETCH response starts with the message sequence
            // number, not the UID requested by the client.
            ImapMessageType::Command {
                command: ImapCommand::Uid,
                ..
            } => true,
            _ => true,
        }
    }

    fn resolve_fetch_response_target(
        &self, sequence_number: Option<u32>,
    ) -> UntaggedResponseTarget {
        let mut candidate = None;
        let mut found_fetch_request = false;

        for tx in self.transactions.iter().filter(|tx| {
            !tx.complete && tx.request_tag.is_some() && tx.command.eq_ignore_ascii_case(b"FETCH")
        }) {
            found_fetch_request = true;
            if !Self::fetch_request_may_include_sequence(tx, sequence_number) {
                continue;
            }
            if candidate.is_some() {
                return UntaggedResponseTarget::Ambiguous;
            }
            candidate = Some(tx.tx_id);
        }

        if let Some(tx_id) = candidate {
            UntaggedResponseTarget::Transaction(tx_id)
        } else if found_fetch_request {
            UntaggedResponseTarget::Ambiguous
        } else {
            self.sole_outstanding_response_target()
        }
    }

    fn resolve_untagged_response_target(
        &self, sequence_number: Option<u32>, keyword: &[u8],
    ) -> UntaggedResponseTarget {
        if keyword.eq_ignore_ascii_case(b"FETCH") {
            return self.resolve_fetch_response_target(sequence_number);
        }

        if let Some(expected_commands) = Self::expected_commands_for_untagged_keyword(keyword) {
            let mut candidate = None;
            for tx in self
                .transactions
                .iter()
                .filter(|tx| !tx.complete && tx.request_tag.is_some())
            {
                if expected_commands
                    .iter()
                    .any(|command| tx.command.eq_ignore_ascii_case(command))
                {
                    if candidate.is_some() {
                        return UntaggedResponseTarget::Ambiguous;
                    }
                    candidate = Some(tx.tx_id);
                }
            }
            return candidate
                .map(UntaggedResponseTarget::Transaction)
                .unwrap_or_else(|| self.sole_outstanding_response_target());
        }

        if let Some(tx_id) = self.active_response_tx_id() {
            return UntaggedResponseTarget::Transaction(tx_id);
        }

        self.sole_outstanding_response_target()
    }

    fn commit_untagged_response_target(&mut self, target: UntaggedResponseTarget) -> Option<u64> {
        match target {
            UntaggedResponseTarget::Transaction(tx_id) => {
                self.active_response_tx_id = Some(tx_id);
                Some(tx_id)
            }
            UntaggedResponseTarget::Ambiguous | UntaggedResponseTarget::Unsolicited => {
                self.active_response_tx_id = None;
                None
            }
        }
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
                        !tx.complete
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
                    .find(|tx| !tx.complete)
                    .map(|tx| tx.tx_id)
            })
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
            let removed_tx_id = self.transactions[index].tx_id;
            if self.active_response_tx_id == Some(removed_tx_id) {
                self.active_response_tx_id = None;
            }
            if self.continuation_tx_id == Some(removed_tx_id) {
                self.continuation_tx_id = None;
            }
            if self.pending_literal_crlf_tx_id == Some(removed_tx_id) {
                self.pending_literal_crlf_tx_id = None;
            }
            if self
                .pending_literal
                .as_ref()
                .is_some_and(|pending| pending.tx_id == removed_tx_id)
            {
                self.pending_literal = None;
            }
            if self
                .pending_fetch_response
                .as_ref()
                .is_some_and(|pending| pending.tx_id == removed_tx_id)
            {
                self.pending_fetch_response = None;
                self.response_frame = None;
            }
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
            self.pending_literal_crlf_tx_id = None;
            self.pending_fetch_response = None;
            self.response_frame = None;
            for tx_old in &mut self.transactions {
                if !tx_old.complete {
                    tx_old.tx_data.0.updated_tc = true;
                    tx_old.tx_data.0.updated_ts = true;
                    tx_old.complete = true;
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

    fn new_tx_for_direction(&mut self, direction: Direction) -> Option<ImapTransaction> {
        self.new_tx().map(|mut tx| {
            tx.tx_data = AppLayerTxData::for_direction(direction);
            match direction {
                Direction::ToServer => {
                    tx.progress_tc = ImapStateProgress::ImapStateComplete;
                }
                Direction::ToClient => {
                    tx.progress_ts = ImapStateProgress::ImapStateComplete;
                }
            }
            tx
        })
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

        if self.request_gap {
            if imap_parse_message(input, IMAP_MAX_BODY_SIZE).is_err() {
                return AppLayerResult::ok();
            }
            self.request_gap = false;
        }

        let mut start = input;
        while !start.is_empty() {
            if let Some(tx_id) = self.pending_literal_crlf_tx_id {
                match crlf::<_, Error<_>>.parse(start) {
                    Ok((remaining, _)) => {
                        self.pending_literal_crlf_tx_id = None;
                        if let Some(tx) = self.transactions.iter_mut().find(|tx| tx.tx_id == tx_id)
                        {
                            tx.complete_request();
                        }
                        start = remaining;
                        continue;
                    }
                    Err(Err::Incomplete(_)) => {
                        let consumed = input.len() - start.len();
                        let needed = start.len() + 1;
                        return AppLayerResult::incomplete(consumed as u32, needed as u32);
                    }
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

            let completed_literal = if let Some(pending) = self
                .pending_literal
                .as_mut()
                .filter(|pending| pending.is_ready())
            {
                let bytes_needed = match usize::try_from(pending.literal.remaining()) {
                    Ok(remaining) => remaining,
                    Err(_) => {
                        pending.literal.consume_chunk(start);
                        return AppLayerResult::ok();
                    }
                };
                if start.len() < bytes_needed {
                    pending.literal.consume_chunk(start);
                    return AppLayerResult::ok();
                }

                let literal = &mut pending.literal;
                let is_single_chunk = literal.bytes_consumed == 0;
                literal.consume_chunk(&start[..bytes_needed]);
                Some((
                    bytes_needed,
                    pending.tx_id,
                    is_single_chunk,
                    literal.truncated,
                    literal.size > u64::try_from(IMAP_MAX_BODY_SIZE).unwrap_or(u64::MAX),
                    std::mem::take(&mut literal.buffer),
                ))
            } else {
                None
            };

            if let Some((
                bytes_needed,
                owner_tx_id,
                is_single_chunk,
                literal_truncated,
                literal_too_large,
                literal_data,
            )) = completed_literal
            {
                let email = parse_email_content(literal_data);

                let email_offsets = if is_single_chunk {
                    email.as_ref().map(|e| (e.headers_len, e.body_offset))
                } else {
                    None
                };

                let command = self
                    .transactions
                    .iter()
                    .find(|tx| tx.tx_id == owner_tx_id)
                    .map(|tx| tx.command.clone())
                    .unwrap_or_default();
                let res = email.map(|email| build_parsed_email(email, command, STREAM_TOSERVER));
                let retain_limit = self.email_retain_limit_for_tx(Some(owner_tx_id));

                if let Some(tx) = self
                    .transactions
                    .iter_mut()
                    .find(|tx| tx.tx_id == owner_tx_id)
                {
                    let tx_id = tx.id();
                    tx.tx_data.0.updated_ts = true;

                    if literal_too_large {
                        tx.tx_data.set_event(ImapEvent::BodyTooLarge as u8);
                    }
                    if literal_truncated {
                        tx.mark_data_limit();
                    }
                    if let Some((parsed_email, too_many)) = res {
                        if too_many {
                            tx.tx_data.set_event(ImapEvent::TooManyHeaders as u8);
                        }
                        tx.retain_parsed_email(parsed_email, retain_limit);
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

                    self.set_frame_ts(flow, tx_id, bytes_needed as i64);
                }

                self.pending_literal = None;
                self.pending_literal_crlf_tx_id = Some(owner_tx_id);
                start = &start[bytes_needed..];
                continue;
            }

            if let Some(continuation_tx_id) = self.continuation_tx_id {
                if let Ok((rem, request)) = parse_continuation_data(start) {
                    let consumed = start.len() - rem.len();

                    self.continuation_tx_id = None;

                    if let Some(tx) = self
                        .transactions
                        .iter_mut()
                        .find(|tx| tx.tx_id == continuation_tx_id && !tx.complete)
                    {
                        let tx_id = tx.id();
                        let completes_request =
                            if let ImapMessageType::ContinuationData { data } = &request.message {
                                (tx.command.eq_ignore_ascii_case(b"IDLE")
                                    && data.eq_ignore_ascii_case(b"DONE"))
                                    || (tx.command.eq_ignore_ascii_case(b"AUTHENTICATE")
                                        && data == b"*")
                            } else {
                                false
                            };
                        tx.tx_data.0.updated_ts = true;
                        if request.line_truncated {
                            tx.tx_data.set_event(ImapEvent::LineTooLong as u8);
                        }
                        if !request.raw_line.is_empty() && tx.request_lines.len() < IMAP_MAX_LINES {
                            tx.request_lines.push(request.raw_line.clone());
                        }
                        if tx.requests.len() < IMAP_MAX_MSGS_PER_TX {
                            tx.requests.push(request);
                        }
                        if completes_request {
                            tx.complete_request();
                        }
                        start = rem;
                        self.set_frame_ts(flow, tx_id, consumed as i64);
                        continue;
                    }
                }
                self.continuation_tx_id = None;
                if let Some(pos) = start.iter().position(|&c| c == b'\n') {
                    start = &start[pos + 1..];
                    continue;
                } else {
                    break;
                }
            }

            match imap_parse_message(start, IMAP_MAX_BODY_SIZE) {
                Ok((rem, request)) => {
                    let consumed = start.len() - rem.len();

                    let mut setup_literal = None;
                    let mut client_data_pending = false;
                    if let ImapMessageType::Command { command, arguments } = &request.message {
                        if matches!(command, ImapCommand::StartTls) {
                            self.request_tls = true;
                        }
                        if matches!(command, ImapCommand::Append) {
                            if let Some((size, is_plus)) = extract_literal_from_arguments(arguments)
                            {
                                setup_literal = Some((size, is_plus));
                                client_data_pending = true;
                            }
                        }
                        if matches!(command, ImapCommand::Authenticate | ImapCommand::Idle) {
                            client_data_pending = true;
                        }
                    }

                    let tx = self.new_tx();
                    if tx.is_none() {
                        return AppLayerResult::err();
                    }
                    let mut tx = tx.unwrap();
                    let tx_id = tx.id();
                    let request_tag = request.tag.clone();
                    tx.request_tag = request_tag.clone();
                    tx.command = extract_command(&request);
                    if request.line_truncated {
                        tx.tx_data.set_event(ImapEvent::LineTooLong as u8);
                    }
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
                        if tx.request_lines.len() < IMAP_MAX_LINES {
                            let mut line = if args.is_empty() {
                                format!("{} {}", tag, cmd).into_bytes()
                            } else {
                                let joined: Vec<_> =
                                    args.iter().map(|a| String::from_utf8_lossy(a)).collect();
                                format!("{} {} {}", tag, cmd, joined.join(" ")).into_bytes()
                            };
                            line.truncate(IMAP_MAX_LINE_SIZE);
                            tx.request_lines.push(line);
                        }
                    } else if !request.raw_line.is_empty()
                        && tx.request_lines.len() < IMAP_MAX_LINES
                    {
                        tx.request_lines.push(request.raw_line.clone());
                    }
                    if tx.requests.len() < IMAP_MAX_MSGS_PER_TX {
                        tx.requests.push(request);
                    }
                    tx.tx_data.0.updated_ts = true;
                    if !client_data_pending {
                        tx.complete_request();
                    }
                    self.transactions.push_back(tx);
                    start = rem;
                    self.set_frame_ts(flow, tx_id, consumed as i64);

                    if let (Some((size, is_plus)), Some(request_tag)) = (setup_literal, request_tag)
                    {
                        let retain_limit = self.email_retain_limit_for_tx(Some(tx_id));
                        self.pending_literal = Some(PendingLiteral::new(
                            tx_id,
                            request_tag,
                            size,
                            is_plus,
                            retain_limit,
                        ));
                    }
                }
                Err(Err::Incomplete(_)) => {
                    let consumed = input.len() - start.len();
                    let needed = start.len() + 1;
                    return AppLayerResult::incomplete(consumed as u32, needed as u32);
                }
                Err(Err::Error(e)) if e.code == ErrorKind::Eof => {
                    break;
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
            if imap_parse_message(input, IMAP_MAX_BODY_SIZE).is_err() {
                return AppLayerResult::ok();
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

            if self.pending_fetch_response.is_some() {
                if let Some(pending) = self.pending_fetch_response.as_mut() {
                    if let Some(email_frame) = pending.email_frame.as_mut() {
                        if email_frame.consume(flow, &stream_slice, start, pending.tx_id) {
                            pending.email_frame = None;
                        }
                    }
                }

                let progress = if let Some(pending) = self.pending_fetch_response.as_mut() {
                    pending.parser.consume(start)
                } else {
                    continue;
                };

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
                    Ok(FetchResponseProgress::Complete {
                        consumed,
                        mut message,
                    }) => {
                        let Some(pending) = self.pending_fetch_response.take() else {
                            self.response_frame = None;
                            return AppLayerResult::err();
                        };
                        let tx_id = pending.tx_id;
                        let frame_len = pending.frame_len.saturating_add(consumed);
                        let retain_limit = self.email_retain_limit_for_tx(Some(tx_id));

                        if let Some(tx) = self.transactions.iter_mut().find(|tx| tx.tx_id == tx_id)
                        {
                            if !message.raw_line.is_empty()
                                && tx.response_lines.len() < IMAP_MAX_LINES
                            {
                                tx.response_lines.push(message.raw_line.clone());
                            }
                            let command = tx.command.clone();
                            update_tx_with_response_email(
                                tx,
                                &mut message,
                                command,
                                STREAM_TOCLIENT,
                                retain_limit,
                            );
                            tx.update_completion_from_response(&message);
                            if tx.responses.len() < IMAP_MAX_MSGS_PER_TX {
                                tx.responses.push(message);
                            }
                            tx.tx_data.0.updated_tc = true;
                            let frame_len = i64::try_from(frame_len).unwrap_or(i64::MAX);
                            self.set_frame_tc(flow, tx_id, frame_len);
                        } else {
                            self.response_frame = None;
                        }

                        start = &start[consumed..];
                        continue;
                    }
                    Err(_) => {
                        if let Some(pending) = self.pending_fetch_response.as_mut() {
                            if let Some(email_frame) = pending.email_frame.take() {
                                email_frame.close_headers(flow);
                            }
                        }
                        let tx_id = self
                            .pending_fetch_response
                            .as_ref()
                            .map(|pending| pending.tx_id);
                        self.pending_fetch_response = None;
                        self.response_frame = None;
                        if let Some(tx) = tx_id.and_then(|tx_id| {
                            self.transactions.iter_mut().find(|tx| tx.tx_id == tx_id)
                        }) {
                            tx.tx_data.set_event(ImapEvent::InvalidData as u8);
                        }
                        return AppLayerResult::err();
                    }
                }
            }

            let untagged = peek_untagged(start);
            let untagged_response_target = untagged.map(|(sequence_number, keyword)| {
                self.resolve_untagged_response_target(sequence_number, keyword)
            });
            let retain_limit = match untagged_response_target {
                Some(UntaggedResponseTarget::Transaction(tx_id)) => {
                    self.email_retain_limit_for_tx(Some(tx_id))
                }
                Some(UntaggedResponseTarget::Ambiguous)
                | Some(UntaggedResponseTarget::Unsolicited)
                | None => self.email_retain_limit_for_tx(None),
            };

            if untagged.is_some_and(|(_, keyword)| keyword.eq_ignore_ascii_case(b"FETCH")) {
                match FetchResponseState::new(start, retain_limit) {
                    Ok((rem, parser)) => {
                        let target =
                            untagged_response_target.unwrap_or(UntaggedResponseTarget::Unsolicited);
                        let tx_id = if let Some(tx_id) =
                            self.commit_untagged_response_target(target)
                        {
                            tx_id
                        } else {
                            let Some(tx) = self.new_tx_for_direction(Direction::ToClient) else {
                                self.response_frame = None;
                                return AppLayerResult::err();
                            };
                            let tx_id = tx.id();
                            self.transactions.push_back(tx);
                            tx_id
                        };

                        if let Some(tx) = self.transactions.iter_mut().find(|tx| tx.tx_id == tx_id)
                        {
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
                    Err(Err::Incomplete(_)) => {
                        let consumed = input.len() - start.len();
                        let needed = start.len() + 1;
                        return AppLayerResult::incomplete(consumed as u32, needed as u32);
                    }
                    Err(_) => {
                        self.set_event(ImapEvent::InvalidData);
                        self.response_frame = None;
                        return AppLayerResult::err();
                    }
                }
            }

            match imap_parse_message(start, retain_limit) {
                Ok((rem, mut response)) => {
                    let consumed = start.len() - rem.len();

                    if self.request_tls {
                        if let ImapMessageType::Response { status, .. } = &response.message {
                            if matches!(status, ImapResponseStatus::Ok) {
                                SCLogDebug!("IMAP: STARTTLS detected");
                                unsafe {
                                    SCAppLayerRequestProtocolTLSUpgrade(flow);
                                }
                            }
                        }
                        self.request_tls = false;
                    }

                    if let Some(ref tag) = response.tag {
                        let completes_pending_literal =
                            self.pending_literal.as_ref().is_some_and(|pending| {
                                pending.request_tag.as_slice() == tag.as_slice()
                            });
                        if let Some(tx) = self.find_request(tag) {
                            let tx_id = tx.id();
                            tx.tx_data.0.updated_tc = true;
                            if !response.raw_line.is_empty()
                                && tx.response_lines.len() < IMAP_MAX_LINES
                            {
                                tx.response_lines.push(response.raw_line.clone());
                            }
                            let cmd = tx.command.clone();
                            update_tx_with_response_email(
                                tx,
                                &mut response,
                                cmd,
                                STREAM_TOCLIENT,
                                retain_limit,
                            );
                            tx.update_completion_from_response(&response);
                            if tx.responses.len() < IMAP_MAX_MSGS_PER_TX {
                                tx.responses.push(response);
                            }
                            if self.active_response_tx_id == Some(tx_id) {
                                self.active_response_tx_id = None;
                            }
                            if self.continuation_tx_id == Some(tx_id) {
                                self.continuation_tx_id = None;
                            }
                            if self.pending_literal_crlf_tx_id == Some(tx_id) {
                                self.pending_literal_crlf_tx_id = None;
                            }
                            if completes_pending_literal
                                && self
                                    .pending_literal
                                    .as_ref()
                                    .is_some_and(|pending| pending.tx_id == tx_id)
                            {
                                self.pending_literal = None;
                            }
                            self.set_frame_tc(flow, tx_id, consumed as i64);
                        } else {
                            /* No matching request (e.g. midstream/async-oneside mode).
                             * Create a new transaction for this tagged response. */
                            let tx = self.new_tx_for_direction(Direction::ToClient);
                            if tx.is_none() {
                                return AppLayerResult::err();
                            }
                            let mut tx = tx.unwrap();
                            let tx_id = tx.id();
                            tx.tx_data.0.updated_tc = true;
                            if !response.raw_line.is_empty()
                                && tx.response_lines.len() < IMAP_MAX_LINES
                            {
                                tx.response_lines.push(response.raw_line.clone());
                            }
                            update_tx_with_response_email(
                                &mut tx,
                                &mut response,
                                Vec::new(),
                                STREAM_TOCLIENT,
                                retain_limit,
                            );
                            tx.update_completion_from_response(&response);
                            if tx.responses.len() < IMAP_MAX_MSGS_PER_TX {
                                tx.responses.push(response);
                            }
                            self.transactions.push_back(tx);
                            self.set_frame_tc(flow, tx_id, consumed as i64);
                        }
                    } else {
                        let is_continuation =
                            matches!(response.message, ImapMessageType::Continuation { .. });

                        let untagged_target = if let ImapMessageType::Untagged {
                            seq_number,
                            keyword,
                            ..
                        } = &response.message
                        {
                            Some(untagged_response_target.unwrap_or_else(|| {
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
                                .find(|tx| !tx.complete)
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

                        if let Some(tx) = response_tx_id.and_then(|tx_id| {
                            self.transactions.iter_mut().find(|tx| tx.tx_id == tx_id)
                        }) {
                            let tx_id = tx.id();
                            if !response.raw_line.is_empty()
                                && tx.response_lines.len() < IMAP_MAX_LINES
                            {
                                tx.response_lines.push(response.raw_line.clone());
                            }
                            let cmd = tx.command.clone();
                            update_tx_with_response_email(
                                tx,
                                &mut response,
                                cmd,
                                STREAM_TOCLIENT,
                                retain_limit,
                            );
                            tx.update_completion_from_response(&response);
                            if tx.responses.len() < IMAP_MAX_MSGS_PER_TX {
                                tx.responses.push(response);
                            }
                            tx.tx_data.0.updated_tc = true;
                            self.set_frame_tc(flow, tx_id, consumed as i64);
                        } else {
                            if untagged_target.is_some() {
                                self.active_response_tx_id = None;
                            }
                            if is_continuation {
                                self.continuation_tx_id = None;
                            }
                            let tx = self.new_tx_for_direction(Direction::ToClient);
                            if tx.is_none() {
                                return AppLayerResult::err();
                            }
                            let mut tx = tx.unwrap();
                            let tx_id = tx.id();
                            if !response.raw_line.is_empty()
                                && tx.response_lines.len() < IMAP_MAX_LINES
                            {
                                tx.response_lines.push(response.raw_line.clone());
                            }
                            update_tx_with_response_email(
                                &mut tx,
                                &mut response,
                                Vec::new(),
                                STREAM_TOCLIENT,
                                retain_limit,
                            );
                            tx.update_completion_from_response(&response);
                            if tx.responses.len() < IMAP_MAX_MSGS_PER_TX {
                                tx.responses.push(response);
                            }
                            self.transactions.push_back(tx);
                            self.set_frame_tc(flow, tx_id, consumed as i64);
                        }
                    }
                    start = rem;
                }
                Err(Err::Incomplete(_)) => {
                    let consumed = input.len() - start.len();
                    let needed = start.len() + 1;
                    return AppLayerResult::incomplete(consumed as u32, needed as u32);
                }
                Err(Err::Error(e)) if e.code == ErrorKind::Eof => {
                    break;
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
        self.continuation_tx_id = None;
        self.pending_literal = None;
        self.pending_literal_crlf_tx_id = None;
    }

    fn on_response_gap(&mut self, flow: *const Flow, _size: u32) {
        self.response_gap = true;
        self.active_response_tx_id = None;
        self.continuation_tx_id = None;
        self.pending_literal = None;
        if let Some(pending) = self.pending_fetch_response.as_mut() {
            if let Some(email_frame) = pending.email_frame.take() {
                email_frame.close_headers(flow);
            }
        }
        self.pending_fetch_response = None;
        self.response_frame = None;
    }
}

fn probe(input: &[u8], dir: Direction, rdir: *mut u8) -> AppProto {
    if FetchResponseState::new(input, 0).is_ok() {
        if dir == Direction::ToServer {
            unsafe {
                *rdir = Direction::ToClient.into();
            }
        }
        return unsafe { ALPROTO_IMAP };
    }

    match imap_parse_message(input, IMAP_MAX_BODY_SIZE) {
        Ok((_, imap_msg)) => {
            if matches!(
                &imap_msg.message,
                ImapMessageType::Command {
                    command: ImapCommand::Unknown(_),
                    ..
                }
            ) {
                return ALPROTO_FAILED;
            }
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
        Err(Err::Incomplete(_)) => {
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
        state.on_response_gap(flow, stream_slice.gap_size());
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

unsafe extern "C" fn imap_tx_get_alstate_progress(tx: *mut c_void, direction: u8) -> c_int {
    let tx = cast_pointer!(tx, ImapTransaction);
    if direction == STREAM_TOSERVER {
        return tx.progress_ts as c_int;
    }
    return tx.progress_tc as c_int;
}

export_tx_data_get!(imap_get_tx_data, ImapTransaction);
export_state_data_get!(imap_get_state_data, ImapState);

const PARSER_NAME: &[u8] = b"imap\0";

fn register_pattern_probe() -> i8 {
    unsafe {
        if SCAppLayerProtoDetectPMRegisterPatternCI(
            IPPROTO_TCP,
            ALPROTO_IMAP,
            b"* OK \0".as_ptr() as *const c_char,
            5,
            0,
            Direction::ToClient as u8,
        ) < 0
        {
            return -1;
        }
        if SCAppLayerProtoDetectPMRegisterPatternCI(
            IPPROTO_TCP,
            ALPROTO_IMAP,
            b"* NO \0".as_ptr() as *const c_char,
            5,
            0,
            Direction::ToClient as u8,
        ) < 0
        {
            return -1;
        }
        if SCAppLayerProtoDetectPMRegisterPatternCI(
            IPPROTO_TCP,
            ALPROTO_IMAP,
            b"* BAD \0".as_ptr() as *const c_char,
            6,
            0,
            Direction::ToClient as u8,
        ) < 0
        {
            return -1;
        }
        if SCAppLayerProtoDetectPMRegisterPatternCI(
            IPPROTO_TCP,
            ALPROTO_IMAP,
            b"* LIST \0".as_ptr() as *const c_char,
            7,
            0,
            Direction::ToClient as u8,
        ) < 0
        {
            return -1;
        }
        if SCAppLayerProtoDetectPMRegisterPatternCI(
            IPPROTO_TCP,
            ALPROTO_IMAP,
            b"* ESEARCH \0".as_ptr() as *const c_char,
            10,
            0,
            Direction::ToClient as u8,
        ) < 0
        {
            return -1;
        }
        if SCAppLayerProtoDetectPMRegisterPatternCI(
            IPPROTO_TCP,
            ALPROTO_IMAP,
            b"* STATUS \0".as_ptr() as *const c_char,
            9,
            0,
            Direction::ToClient as u8,
        ) < 0
        {
            return -1;
        }
        if SCAppLayerProtoDetectPMRegisterPatternCI(
            IPPROTO_TCP,
            ALPROTO_IMAP,
            b"* FLAGS \0".as_ptr() as *const c_char,
            8,
            0,
            Direction::ToClient as u8,
        ) < 0
        {
            return -1;
        }
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
