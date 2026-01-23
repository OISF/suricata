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
use crate::conf::{conf_get, get_memval};
use crate::core::*;
use crate::direction::Direction;
use crate::flow::Flow;
use crate::frames::*;
use suricata_derive::AppLayerState;

use crate::imap::parser::{
    command_from_name, non_sync_literal_capability, parse_command, parse_command_continuation,
    parse_continuation_data, parse_response, parse_response_continuation, probe_command_prefix,
    untagged_trailing_literal, CommandLiteral, ImapCommand, ImapMessage, ImapMessageType,
    ImapResponseStatus, LiteralInfo, SequenceSet, IMAP_MAX_LINE_SIZE,
};
use nom8::error::Error;
use nom8::Err;
use std;
use std::collections::VecDeque;
use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_void};
use suricata_sys::sys::{
    AppLayerParserState, AppProto, SCAppLayerParserConfParserEnabled,
    SCAppLayerParserRegisterLogger, SCAppLayerParserSetStreamDepth, SCAppLayerParserStateIssetFlag,
    SCAppLayerParserStateSetFlag, SCAppLayerProtoDetectConfProtoDetectionEnabled,
    SCAppLayerProtoDetectGetStreamDataSize, SCAppLayerProtoDetectPMRegisterPatternCI,
    SCAppLayerProtoDetectPMRegisterPatternCIwPP, SCAppLayerRequestProtocolTLSUpgrade,
    SCFlowGetAppProtocolToClient,
};

const IMAP_MAX_TX_DEFAULT: usize = 256;
const IMAP_MAX_RESPONSES_DEFAULT: usize = 4096;
const IMAP_MAX_MSGS_PER_TX: usize = 512;
const IMAP_MAX_LINE_BYTES_PER_STATE: usize = 1024 * 1024;
// A line is buffered by the stream until its line feed arrives. Past this
// size it is given up, so that a peer sending no line feed cannot make the
// stream grow without bound.
const IMAP_MAX_PENDING_LINE: usize = 1024 * 1024;
// Message bodies easily exceed the global reassembly depth, after which
// nothing more of a direction would be parsed.
const IMAP_CONFIG_DEFAULT_STREAM_DEPTH: u32 = 0;

static mut IMAP_MAX_TX: usize = IMAP_MAX_TX_DEFAULT;
static mut IMAP_MAX_RESPONSES: usize = IMAP_MAX_RESPONSES_DEFAULT;

pub(super) static mut ALPROTO_IMAP: AppProto = ALPROTO_UNKNOWN;

#[derive(AppLayerFrameType)]
pub enum ImapFrameType {
    Pdu,
}

#[derive(AppLayerEvent)]
enum ImapEvent {
    TooManyTransactions,
    InvalidData,
    LineTooLong,
    DataLimitReached,
    TooManyResponses,
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

fn extract_command(request: &ImapMessage) -> Option<ImapCommand> {
    let ImapMessageType::Command {
        command, arguments, ..
    } = &request.message
    else {
        return None;
    };
    // UID is a prefix, the actual command (FETCH, STORE, etc.) is in
    // arguments[0]. Other known commands take no UID prefix: the server
    // rejects them, so they are not taken for the command they name.
    if matches!(command, ImapCommand::Uid) {
        return Some(
            match arguments.first().map(|name| command_from_name(name)) {
                Some(
                    command @ (ImapCommand::Fetch
                    | ImapCommand::Search
                    | ImapCommand::Store
                    | ImapCommand::Copy
                    | ImapCommand::Expunge
                    | ImapCommand::Unknown(_)),
                ) => command,
                _ => ImapCommand::Uid,
            },
        );
    }
    Some(command.clone())
}

fn extract_fetch_set(request: &ImapMessage) -> Option<SequenceSet> {
    // Truncation may cut the set short, even inside a number.
    if request.line_truncated {
        return None;
    }
    match &request.message {
        ImapMessageType::Command {
            command: ImapCommand::Fetch,
            arguments,
            ..
        } => arguments.first().and_then(|set| SequenceSet::parse(set)),
        _ => None,
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
    pub response_lines: Vec<Vec<u8>>,

    request_tag: Option<Vec<u8>>,
    pub command: Option<ImapCommand>,
    // Sequence set of a FETCH command, to match its untagged responses.
    fetch_set: Option<SequenceSet>,
    line_bytes: usize,
    data_limit_event_set: bool,
    too_many_responses_event_set: bool,
    request_too_long_event_set: bool,
    // The command line came while the server may have been reading the data
    // of the command before it (a literal or a SASL response whose
    // continuation request was not seen), so the server may never have read
    // it as a command.
    ambiguous: bool,
    // That command before it. Its tagged reply shows that the server read
    // this line as a command, unless a continuation request came first: then
    // the server was reading data, and this is None.
    ambiguous_with: Option<u64>,
    // The line may be the data of a LOGIN or AUTHENTICATE literal whose
    // continuation request was not seen: it is not logged.
    pub may_hold_credentials: bool,
    // A response line was cut to IMAP_MAX_LINE_SIZE. Long response lines are
    // ordinary, so this is logged and raises no event.
    pub reply_truncated: bool,

    tx_data: AppLayerTxData,
}

impl ImapTransaction {
    pub fn new() -> ImapTransaction {
        Self {
            tx_id: 0,
            progress_ts: ImapStateProgress::ImapStateInProgress,
            progress_tc: ImapStateProgress::ImapStateInProgress,
            requests: Vec::new(),
            response_lines: Vec::new(),
            request_tag: None,
            command: None,
            fetch_set: None,
            line_bytes: 0,
            data_limit_event_set: false,
            too_many_responses_event_set: false,
            request_too_long_event_set: false,
            ambiguous: false,
            ambiguous_with: None,
            may_hold_credentials: false,
            reply_truncated: false,
            tx_data: AppLayerTxData::new(),
        }
    }

    fn complete(&self) -> bool {
        self.progress_tc == ImapStateProgress::ImapStateComplete
    }

    fn awaiting_response(&self) -> bool {
        !self.complete() && self.request_tag.is_some()
    }

    fn completed_by(&self, response: &ImapMessage) -> bool {
        match &self.request_tag {
            Some(request_tag) => {
                response.tag.as_deref() == Some(request_tag.as_slice())
                    && matches!(response.message, ImapMessageType::Response { .. })
            }
            None => true,
        }
    }

    fn complete_request(&mut self) {
        if self.progress_ts != ImapStateProgress::ImapStateComplete {
            self.progress_ts = ImapStateProgress::ImapStateComplete;
            self.tx_data.0.updated_ts = true;
        }
    }

    /// Called once the command line and its literals are done. The client may
    /// still send lines for AUTHENTICATE and IDLE, and may for a command this
    /// parser does not know, so those complete with the tagged reply instead:
    /// a completed request is not inspected again.
    fn end_command_line(&mut self) {
        if !matches!(
            self.command,
            Some(ImapCommand::Authenticate | ImapCommand::Idle | ImapCommand::Unknown(_))
        ) {
            self.complete_request();
        }
    }

    fn complete_response(&mut self) {
        if self.progress_tc != ImapStateProgress::ImapStateComplete {
            self.progress_tc = ImapStateProgress::ImapStateComplete;
            self.tx_data.0.updated_tc = true;
        }
    }

    /// Returns whether the event was raised now.
    fn mark_data_limit(&mut self) -> bool {
        if self.data_limit_event_set {
            return false;
        }
        self.tx_data.set_event(ImapEvent::DataLimitReached as u8);
        self.data_limit_event_set = true;
        true
    }

    /// Returns whether the event was raised now.
    fn mark_too_many_responses(&mut self) -> bool {
        if self.too_many_responses_event_set {
            return false;
        }
        self.tx_data.set_event(ImapEvent::TooManyResponses as u8);
        self.too_many_responses_event_set = true;
        true
    }

    /// Returns the octets retained against the line budget.
    fn add_request(&mut self, req: ImapMessage, line_budget: usize) -> usize {
        self.tx_data.0.updated_ts = true;
        if req.line_truncated && !self.request_too_long_event_set {
            self.tx_data.set_event(ImapEvent::LineTooLong as u8);
            self.request_too_long_event_set = true;
        }
        // The tag, command and FETCH set are bounded per transaction, as are
        // the transactions by max-tx, so they are kept outside the line
        // budget: a full budget never loses the command itself.
        if self.request_tag.is_none() && matches!(req.message, ImapMessageType::Command { .. }) {
            self.request_tag = req.tag.clone();
            self.command = extract_command(&req);
            self.fetch_set = extract_fetch_set(&req);
        }
        let mut rem = line_budget;
        let request_bytes = retained_request_bytes(&req);
        // So is a command line of ordinary size, so that a budget used up by
        // another transaction leaves every command inspected and logged.
        let mut own = request_bytes + std::mem::size_of::<ImapMessage>();
        let budget = if self.requests.is_empty()
            && matches!(req.message, ImapMessageType::Command { .. })
            && request_bytes <= IMAP_MAX_LINE_SIZE
        {
            &mut own
        } else {
            &mut rem
        };
        if self.requests.len() >= IMAP_MAX_MSGS_PER_TX
            || !retain_item(&mut self.requests, req, request_bytes, budget)
        {
            self.mark_data_limit();
        }
        let retained = line_budget - rem;
        self.line_bytes += retained;
        retained
    }

    /// Returns the octets retained against the line budget.
    fn add_response(&mut self, mut resp: ImapMessage, line_budget: usize) -> usize {
        let completes = self.completed_by(&resp);
        let mut rem = line_budget;
        let bytes = resp.raw_line.capacity();
        // A line dropped past the limit leaves nothing new to inspect, so it
        // does not mark the transaction updated.
        let mut updated = completes || resp.line_truncated;
        if !resp.raw_line.is_empty() {
            // The reply completing a command is kept past the limits, outside
            // the line budget, so a large reply still shows its status.
            let completes_command = completes && self.request_tag.is_some();
            let mut own = bytes + std::mem::size_of::<Vec<u8>>();
            let budget = if completes_command {
                &mut own
            } else {
                &mut rem
            };
            if !completes_command && self.response_lines.len() >= unsafe { IMAP_MAX_RESPONSES } {
                updated |= self.mark_too_many_responses();
            } else if retain_item(
                &mut self.response_lines,
                std::mem::take(&mut resp.raw_line),
                bytes,
                budget,
            ) {
                updated = true;
            } else {
                updated |= self.mark_data_limit();
            }
        }
        if updated {
            self.tx_data.0.updated_tc = true;
        }
        let retained = line_budget - rem;
        self.line_bytes += retained;
        self.reply_truncated |= resp.line_truncated;
        if completes {
            if self.request_tag.is_some() {
                self.complete_request();
            }
            self.progress_tc = ImapStateProgress::ImapStateComplete;
        }
        retained
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

#[derive(Debug)]
struct PendingLiteral {
    tx_id: u64,
    literal: LiteralInfo,
    continuation_received: bool,
    awaiting_line_rest: bool,
    parenthesis_depth: usize,
}

impl PendingLiteral {
    fn new(tx_id: u64, literal: CommandLiteral) -> Self {
        Self {
            tx_id,
            literal: LiteralInfo::new(literal.size, literal.is_literal_plus),
            continuation_received: false,
            awaiting_line_rest: false,
            parenthesis_depth: literal.parenthesis_depth,
        }
    }

    fn is_ready(&self) -> bool {
        self.literal.is_literal_plus || self.continuation_received
    }
}

#[derive(Debug)]
struct PendingResponseLiteral {
    // None for a response matching no command, or whose transaction is gone:
    // it joins the transaction of unmatched responses once the literal ends.
    tx_id: Option<u64>,
    // Untagged response announcing the literal. The text following the
    // literal octets is appended to its line until the response ends.
    response: ImapMessage,
    literal: LiteralInfo,
    awaiting_line_rest: bool,
}

impl PendingResponseLiteral {
    fn new(tx_id: Option<u64>, response: ImapMessage, size: u64) -> Self {
        Self {
            tx_id,
            response,
            literal: LiteralInfo::new(size, false),
            /* An empty literal has no octets to skip. */
            awaiting_line_rest: size == 0,
        }
    }

    fn append_line_rest(&mut self, rest: &[u8]) {
        let line = &mut self.response.raw_line;
        let room = IMAP_MAX_LINE_SIZE.saturating_sub(line.len());
        if rest.len() > room {
            self.response.line_truncated = true;
        }
        line.extend_from_slice(&rest[..rest.len().min(room)]);
    }
}

#[derive(Debug, Default)]
struct PartialLine {
    // Stream offset of the line start.
    offset: u64,
    // Bytes from the line start known not to contain a line feed.
    scanned: usize,
}

impl PartialLine {
    /// Returns the input once it holds a line feed. No line parses without
    /// one, so until then nothing is parsed, and only the new octets are
    /// searched for it.
    fn window<'a>(&mut self, offset: u64, input: &'a [u8]) -> Option<&'a [u8]> {
        let from = if self.offset == offset {
            self.scanned.min(input.len())
        } else {
            0
        };
        if input[from..].contains(&b'\n') {
            return Some(input);
        }
        self.offset = offset;
        self.scanned = input.len();
        None
    }
}

/// After a gap the data most likely starts inside a line cut by it. Unless it
/// starts with a complete message to resync on, that line is skipped. Returns
/// the octets to skip, or None while the line has not ended.
fn gap_resync_skip(resync: Result<bool, Err<Error<&[u8]>>>, line: &[u8]) -> Option<usize> {
    match resync {
        Ok(true) => Some(0),
        Err(Err::Incomplete(_)) => None,
        Ok(false) | Err(_) => line.iter().position(|&c| c == b'\n').map(|end| end + 1),
    }
}

fn is_known_command(request: &ImapMessage) -> bool {
    !matches!(
        request.message,
        ImapMessageType::Command {
            command: ImapCommand::Unknown(_),
            ..
        }
    )
}

/// An untagged response keyword and the commands it answers. Those this
/// parser does not know are named instead.
type UntaggedKeywordCommands = (
    &'static [u8],
    &'static [ImapCommand],
    &'static [&'static [u8]],
);

// FETCH responses are matched by sequence set instead.
const UNTAGGED_KEYWORD_COMMANDS: &[UntaggedKeywordCommands] = &[
    (b"SEARCH", &[ImapCommand::Search], &[]),
    (b"ESEARCH", &[ImapCommand::Search], &[]),
    (b"FLAGS", &[ImapCommand::Select, ImapCommand::Examine], &[]),
    (b"EXISTS", &[ImapCommand::Select, ImapCommand::Examine], &[]),
    (b"RECENT", &[ImapCommand::Select, ImapCommand::Examine], &[]),
    (b"CAPABILITY", &[ImapCommand::Capability], &[]),
    (b"LIST", &[ImapCommand::List], &[]),
    (b"LSUB", &[ImapCommand::Lsub], &[]),
    (b"STATUS", &[ImapCommand::Status], &[]),
    (b"ID", &[ImapCommand::Id], &[]),
    (b"NAMESPACE", &[], &[b"NAMESPACE"]),
    (b"ENABLED", &[], &[b"ENABLE"]),
    (b"SORT", &[], &[b"SORT"]),
    (b"THREAD", &[], &[b"THREAD"]),
    (b"QUOTA", &[], &[b"GETQUOTA", b"GETQUOTAROOT", b"SETQUOTA"]),
    (b"QUOTAROOT", &[], &[b"GETQUOTAROOT"]),
];

/// Whether a response is one to resume parsing on after a gap: the reply to
/// a pending command, or an untagged response this parser knows. A
/// continuation request is not, as any line of text starting with "+" reads
/// as one.
fn resyncs_response(transactions: &VecDeque<ImapTransaction>, response: &ImapMessage) -> bool {
    match &response.message {
        ImapMessageType::Response { .. } => transactions
            .iter()
            .any(|tx| !tx.complete() && tx.request_tag.is_some() && tx.request_tag == response.tag),
        ImapMessageType::Untagged { keyword, .. } => {
            const KEYWORDS: &[&[u8]] = &[
                b"OK", b"NO", b"BAD", b"BYE", b"PREAUTH", b"FETCH", b"EXPUNGE",
            ];
            KEYWORDS
                .iter()
                .chain(
                    UNTAGGED_KEYWORD_COMMANDS
                        .iter()
                        .map(|(untagged, _, _)| untagged),
                )
                .any(|known| keyword.eq_ignore_ascii_case(known))
        }
        _ => false,
    }
}

pub struct ImapState {
    state_data: AppLayerStateData,
    tx_id: u64,
    transactions: VecDeque<ImapTransaction>,
    request_frame: Option<Frame>,
    response_frame: Option<Frame>,
    request_gap: bool,
    response_gap: bool,
    // COMPRESS was accepted: both directions are a deflate stream from here on.
    compressed: bool,
    // Transaction currently receiving a group of untagged responses.
    active_response_tx_id: Option<u64>,
    // Transaction that owns the next client continuation line.
    continuation_tx_id: Option<u64>,
    // Literal announced by the current client command line, until its line ends.
    pending_literal: Option<PendingLiteral>,
    // Whether the last capability list seen offers non-synchronizing literals
    // (LITERAL+ or LITERAL-). None until the server sends one.
    non_sync_literals: Option<bool>,
    // Literal announced by an untagged response, until its line ends.
    pending_response_literal: Option<PendingResponseLiteral>,
    request_line: PartialLine,
    response_line: PartialLine,
    // Skipping invalid lines since the last valid command or response; the
    // first of them reported the event.
    request_invalid: bool,
    response_invalid: bool,
    // Events that found no room at max-tx, raised once there is.
    request_too_long_deferred: bool,
    response_too_long_deferred: bool,
    responses_dropped_deferred: bool,
    // A LOGIN or AUTHENTICATE literal was given up: until a known command,
    // the lines parsed as commands may be its data.
    credentials_may_follow: bool,
    // Octets retained by all transactions, against IMAP_MAX_LINE_BYTES_PER_STATE.
    retained_line_bytes: usize,
    // Transactions before this index were scanned for completion at max-tx.
    tx_index_completed: usize,
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
            compressed: false,
            active_response_tx_id: None,
            continuation_tx_id: None,
            pending_literal: None,
            non_sync_literals: None,
            pending_response_literal: None,
            request_line: PartialLine::default(),
            response_line: PartialLine::default(),
            request_invalid: false,
            response_invalid: false,
            request_too_long_deferred: false,
            response_too_long_deferred: false,
            responses_dropped_deferred: false,
            credentials_may_follow: false,
            retained_line_bytes: 0,
            tx_index_completed: 0,
        }
    }

    fn line_retain_budget(&self) -> usize {
        IMAP_MAX_LINE_BYTES_PER_STATE.saturating_sub(self.retained_line_bytes)
    }

    fn add_request_to(&mut self, tx_id: u64, request: ImapMessage) {
        let line_budget = self.line_retain_budget();
        if let Some(tx) = self.tx_by_id_mut(tx_id) {
            let retained = tx.add_request(request, line_budget);
            self.retained_line_bytes += retained;
        }
    }

    fn add_response_to(&mut self, tx_id: u64, response: ImapMessage) {
        let line_budget = self.line_retain_budget();
        if let Some(tx) = self.tx_by_id_mut(tx_id) {
            let retained = tx.add_response(response, line_budget);
            self.retained_line_bytes += retained;
        }
    }

    fn tx_by_id(&self, tx_id: u64) -> Option<&ImapTransaction> {
        self.transactions.iter().find(|tx| tx.tx_id == tx_id)
    }

    fn tx_by_id_mut(&mut self, tx_id: u64) -> Option<&mut ImapTransaction> {
        self.transactions.iter_mut().find(|tx| tx.tx_id == tx_id)
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
        // Only FETCH keeps a set: an untagged UID FETCH response starts with
        // the message sequence number, not the UID requested by the client.
        match (&tx.fetch_set, sequence_number) {
            (Some(set), Some(sequence_number)) => set.contains(sequence_number).unwrap_or(true),
            _ => true,
        }
    }

    fn resolve_fetch_response_target(&self, sequence_number: Option<u32>) -> Option<u64> {
        let mut candidate = None;
        let mut found_fetch_request = false;

        for tx in self
            .transactions
            .iter()
            .filter(|tx| tx.awaiting_response() && tx.command == Some(ImapCommand::Fetch))
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

        if let Some((_, known, named)) = UNTAGGED_KEYWORD_COMMANDS
            .iter()
            .find(|(untagged, _, _)| keyword.eq_ignore_ascii_case(untagged))
        {
            let mut candidate = None;
            for tx in self.transactions.iter().filter(|tx| tx.awaiting_response()) {
                if tx.command.as_ref().is_some_and(|command| match command {
                    ImapCommand::Unknown(name) => {
                        named.iter().any(|named| name.eq_ignore_ascii_case(named))
                    }
                    command => known.contains(command),
                }) {
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

    /// AUTHENTICATE or IDLE command still waiting for client lines. Only the
    /// most recent command qualifies: a later command ended the exchange, even
    /// if the tagged reply was not seen.
    fn waiting_continuation_tx_id(&self) -> Option<u64> {
        self.transactions
            .iter()
            .rev()
            .find(|tx| tx.request_tag.is_some())
            .filter(|tx| {
                !tx.complete()
                    && tx.progress_ts == ImapStateProgress::ImapStateInProgress
                    && matches!(
                        tx.command,
                        Some(ImapCommand::Authenticate | ImapCommand::Idle)
                    )
            })
            .map(|tx| tx.tx_id)
    }

    fn continuation_response_tx_id(&self) -> Option<u64> {
        // The command of a literal still counted may have been answered and
        // freed already.
        self.pending_literal
            .as_ref()
            .map(|pending| pending.tx_id)
            .filter(|&tx_id| self.tx_by_id(tx_id).is_some())
            .or_else(|| self.waiting_continuation_tx_id())
            .or_else(|| {
                // Only a command this parser does not know may take other
                // continuation lines: binding to a known one would take the
                // client's next command as one of its lines.
                self.transactions
                    .iter()
                    .rev()
                    .find(|tx| {
                        tx.awaiting_response()
                            && matches!(tx.command, Some(ImapCommand::Unknown(_)))
                    })
                    .map(|tx| tx.tx_id)
            })
    }

    /// Gives up a pending literal and ends the command line that announced
    /// it. This is the case when the client sends another line instead of the
    /// octets of a synchronizing literal whose continuation request was not
    /// seen: a later gap must not be taken for its octets.
    fn abandon_pending_literal(&mut self) {
        if let Some(pending) = self.pending_literal.take() {
            if let Some(tx) = self.tx_by_id_mut(pending.tx_id) {
                tx.end_command_line();
                if matches!(
                    tx.command,
                    Some(ImapCommand::Login | ImapCommand::Authenticate)
                ) {
                    self.credentials_may_follow = true;
                }
            }
        }
    }

    /// A server that does not offer non-synchronizing literals rejects a
    /// command line ending in one and reads what follows as commands. Without
    /// a capability list the literal is trusted, until the command is
    /// answered with BAD.
    fn expects_literal(&self, literal: &CommandLiteral) -> bool {
        !literal.is_literal_plus || self.non_sync_literals != Some(false)
    }

    fn forget_tx(&mut self, tx_id: u64) {
        if self.active_response_tx_id == Some(tx_id) {
            self.active_response_tx_id = None;
        }
        if self.continuation_tx_id == Some(tx_id) {
            self.continuation_tx_id = None;
        }
        // A literal the client may already be sending is still counted down:
        // the server reads its octets even when it answers the command early.
        if self
            .pending_literal
            .as_ref()
            .is_some_and(|pending| pending.tx_id == tx_id && !pending.is_ready())
        {
            self.pending_literal = None;
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
            self.tx_index_completed = 0;
            if let Some(tx) = self.transactions.remove(index) {
                self.retained_line_bytes = self.retained_line_bytes.saturating_sub(tx.line_bytes);
            }
        }
    }

    pub fn get_tx(&mut self, tx_id: u64) -> Option<&ImapTransaction> {
        self.transactions.iter().find(|tx| tx.tx_id == tx_id + 1)
    }

    fn at_max_tx(&self) -> bool {
        self.transactions.len() >= unsafe { IMAP_MAX_TX }.saturating_add(self.tx_index_completed)
    }

    /// At max-tx, the oldest open transaction is completed, as in MQTT and
    /// PGSQL, so that parsing goes on with bounded memory.
    pub fn new_tx(&mut self) -> ImapTransaction {
        if self.at_max_tx() {
            let mut index = self.tx_index_completed;
            for tx_old in self.transactions.range_mut(self.tx_index_completed..) {
                index += 1;
                if !tx_old.complete() {
                    tx_old.tx_data.0.updated_tc = true;
                    tx_old.tx_data.0.updated_ts = true;
                    tx_old.progress_ts = ImapStateProgress::ImapStateComplete;
                    tx_old.progress_tc = ImapStateProgress::ImapStateComplete;
                    tx_old
                        .tx_data
                        .set_event(ImapEvent::TooManyTransactions as u8);
                    break;
                }
            }
            self.tx_index_completed = index;
        }
        let mut tx = ImapTransaction::new();
        self.tx_id += 1;
        tx.tx_id = self.tx_id;
        tx
    }

    /// At end of stream, complete the given direction of every open
    /// transaction so buffers that are already populated (e.g. the response
    /// lines) are inspected even without a tagged completion reply.
    fn complete_transactions_at_eof(&mut self, direction: Direction) {
        if matches!(direction, Direction::ToClient) {
            if let Some(pending) = self.pending_response_literal.take() {
                self.complete_pending_response(pending, &mut None);
            }
        }
        for tx in &mut self.transactions {
            match direction {
                Direction::ToServer => tx.complete_request(),
                Direction::ToClient => tx.complete_response(),
            }
        }
    }

    fn push_response_tx(&mut self) -> u64 {
        let mut tx = self.new_tx();
        tx.tx_data = AppLayerTxData::for_direction(Direction::ToClient);
        tx.progress_ts = ImapStateProgress::ImapStateComplete;
        let tx_id = tx.tx_id;
        self.transactions.push_back(tx);
        tx_id
    }

    /// Raises an event on a new transaction of its own, so that it is
    /// inspected whatever state the other transactions are in.
    fn push_event_tx(&mut self, direction: Direction, event: ImapEvent) {
        let mut tx = self.new_tx();
        tx.tx_data = AppLayerTxData::for_direction(direction);
        tx.tx_data.set_event(event as u8);
        tx.progress_ts = ImapStateProgress::ImapStateComplete;
        tx.progress_tc = ImapStateProgress::ImapStateComplete;
        self.transactions.push_back(tx);
    }

    /// Raises the events that wait for room below max-tx, where a new
    /// transaction would complete the oldest open command.
    fn raise_deferred_events(&mut self) {
        if self.request_too_long_deferred && !self.at_max_tx() {
            self.request_too_long_deferred = false;
            self.push_event_tx(Direction::ToServer, ImapEvent::LineTooLong);
        }
        if self.response_too_long_deferred && !self.at_max_tx() {
            self.response_too_long_deferred = false;
            self.push_event_tx(Direction::ToClient, ImapEvent::LineTooLong);
        }
        if self.responses_dropped_deferred && !self.at_max_tx() {
            self.responses_dropped_deferred = false;
            self.push_event_tx(Direction::ToClient, ImapEvent::TooManyTransactions);
        }
    }

    /// Skips an invalid line once it has ended, as a server answers it with
    /// BAD and carries on. Returns its length, or None while it has not ended.
    fn skip_invalid_line(
        &mut self, flow: *const Flow, direction: Direction, line: &[u8],
    ) -> Option<usize> {
        let len = line.iter().position(|&c| c == b'\n')? + 1;
        self.end_frame(flow, direction, len);
        // At max-tx a new transaction would complete the oldest open command,
        // so the event waits until there is room for it.
        let room = !self.at_max_tx();
        let reported = match direction {
            Direction::ToServer => &mut self.request_invalid,
            Direction::ToClient => &mut self.response_invalid,
        };
        if room && !*reported {
            *reported = true;
            self.push_event_tx(direction, ImapEvent::InvalidData);
        }
        Some(len)
    }

    /// Ends the frame of a line that belongs to no transaction.
    fn end_frame(&mut self, flow: *const Flow, direction: Direction, len: usize) {
        let frame = match direction {
            Direction::ToServer => self.request_frame.take(),
            Direction::ToClient => self.response_frame.take(),
        };
        if let Some(frame) = frame {
            frame.set_len(flow, len as i64);
        }
    }

    /// Transaction for responses that belong to no command. Those of one
    /// chunk share it, so a burst of them cannot exhaust max-tx. At max-tx
    /// there is none, as a new transaction would complete the oldest open
    /// command: the response is dropped, and TooManyTransactions is raised
    /// once there is room.
    fn orphan_response_tx(&mut self, orphan_tx_id: &mut Option<u64>) -> Option<u64> {
        if orphan_tx_id.is_none() {
            if self.at_max_tx() {
                self.responses_dropped_deferred = true;
            } else {
                *orphan_tx_id = Some(self.push_response_tx());
            }
        }
        *orphan_tx_id
    }

    /// Adds a response to its transaction and ends its frame.
    fn add_response_frame(
        &mut self, flow: *const Flow, tx_id: Option<u64>, response: ImapMessage, consumed: usize,
    ) {
        match tx_id {
            Some(tx_id) => {
                self.add_response_to(tx_id, response);
                self.set_frame_tc(flow, tx_id, consumed as i64);
            }
            None => self.end_frame(flow, Direction::ToClient, consumed),
        }
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

        let incomplete = |rest: &[u8]| {
            AppLayerResult::incomplete((input.len() - rest.len()) as u32, (rest.len() + 1) as u32)
        };
        let offset_of = |rest: &[u8]| stream_slice.offset + (input.len() - rest.len()) as u64;
        self.raise_deferred_events();
        let mut start = input;
        // The lost data may hold the announcement of a literal, whose text
        // easily reads as commands this parser does not know: lines are
        // skipped until a known command.
        while self.request_gap && !start.is_empty() {
            let Some(line) = self.request_line.window(offset_of(start), start) else {
                return incomplete(start);
            };
            let known = parse_command(line).map(|(_, request)| is_known_command(&request));
            let Some(skip) = gap_resync_skip(known, line) else {
                return incomplete(start);
            };
            start = &start[skip..];
            self.request_gap = skip != 0;
        }
        while !start.is_empty() {
            if let Some((tx_id, depth)) = self
                .pending_literal
                .as_ref()
                .filter(|pending| pending.awaiting_line_rest)
                .map(|pending| (pending.tx_id, pending.parenthesis_depth))
            {
                let Some(line) = self.request_line.window(offset_of(start), start) else {
                    return incomplete(start);
                };
                match parse_command_continuation(line, depth) {
                    Ok((rem, (request, literal))) => {
                        if !request.raw_line.is_empty() {
                            self.add_request_to(tx_id, request);
                        }
                        if let Some(literal) = literal.filter(|l| self.expects_literal(l)) {
                            self.pending_literal = Some(PendingLiteral::new(tx_id, literal));
                        } else {
                            self.pending_literal = None;
                            if let Some(tx) = self.tx_by_id_mut(tx_id) {
                                tx.end_command_line();
                            }
                        }
                        start = rem;
                        continue;
                    }
                    Err(Err::Incomplete(_)) => return incomplete(start),
                    Err(_) => {
                        let Some(len) = self.skip_invalid_line(flow, Direction::ToServer, line)
                        else {
                            return incomplete(start);
                        };
                        // The rest of the command is lost with its line.
                        self.pending_literal = None;
                        if let Some(tx) = self.tx_by_id_mut(tx_id) {
                            tx.end_command_line();
                        }
                        start = &start[len..];
                        continue;
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
                let consumed = pending.literal.consume_chunk(start);
                if pending.literal.remaining() != 0 {
                    self.pending_literal = Some(pending);
                    return AppLayerResult::ok();
                }

                let tx_id = pending.tx_id;
                let frame_len = pending.literal.size_since_gap();
                if let Some(tx) = self.tx_by_id_mut(tx_id) {
                    tx.tx_data.0.updated_ts = true;
                    self.set_frame_ts(flow, tx_id, i64::try_from(frame_len).unwrap_or(i64::MAX));
                } else {
                    // The command was answered before its literal ended.
                    self.end_frame(
                        flow,
                        Direction::ToServer,
                        usize::try_from(frame_len).unwrap_or(usize::MAX),
                    );
                }

                pending.awaiting_line_rest = true;
                self.pending_literal = Some(pending);
                start = &start[consumed..];
                continue;
            }

            if let Some(continuation_tx_id) = self.continuation_tx_id {
                let Some(line) = self.request_line.window(offset_of(start), start) else {
                    return incomplete(start);
                };
                match parse_continuation_data(line) {
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
                            let completes_request = match tx.command {
                                Some(ImapCommand::Idle) => data.eq_ignore_ascii_case(b"DONE"),
                                Some(ImapCommand::Authenticate) => data == b"*",
                                _ => false,
                            };
                            let retained = tx.add_request(request, line_budget);
                            if completes_request {
                                tx.complete_request();
                            }
                            self.retained_line_bytes += retained;
                            self.set_frame_ts(flow, tx_id, consumed as i64);
                        } else {
                            // A valid line whose transaction is gone has no owner.
                            self.end_frame(flow, Direction::ToServer, consumed);
                        }
                        start = rem;
                    }
                    Err(Err::Incomplete(_)) => return incomplete(start),
                    Err(_) => {
                        let Some(len) = self.skip_invalid_line(flow, Direction::ToServer, line)
                        else {
                            return incomplete(start);
                        };
                        self.continuation_tx_id = None;
                        start = &start[len..];
                    }
                }
                continue;
            }

            let Some(line) = self.request_line.window(offset_of(start), start) else {
                return incomplete(start);
            };
            match parse_command(line) {
                Ok((rem, request)) => {
                    let consumed = start.len() - rem.len();

                    let setup_literal = match &request.message {
                        ImapMessageType::Command { literal, .. } => {
                            literal.filter(|literal| self.expects_literal(literal))
                        }
                        _ => None,
                    };

                    // Only a synchronizing literal whose continuation
                    // request was not seen is still pending here.
                    let ambiguous_with = self
                        .pending_literal
                        .as_ref()
                        .map(|pending| pending.tx_id)
                        .or_else(|| self.waiting_continuation_tx_id());

                    self.abandon_pending_literal();
                    if is_known_command(&request) {
                        self.credentials_may_follow = false;
                    }
                    let line_budget = self.line_retain_budget();
                    let mut tx = self.new_tx();
                    let tx_id = tx.id();
                    tx.ambiguous = ambiguous_with.is_some();
                    tx.ambiguous_with = ambiguous_with;
                    tx.may_hold_credentials = self.credentials_may_follow;
                    self.retained_line_bytes += tx.add_request(request, line_budget);
                    if setup_literal.is_none() {
                        tx.end_command_line();
                    }
                    self.transactions.push_back(tx);
                    start = rem;
                    self.set_frame_ts(flow, tx_id, consumed as i64);
                    self.request_invalid = false;
                    sc_app_layer_parser_trigger_raw_stream_inspection(
                        flow,
                        Direction::ToServer as i32,
                    );

                    if let Some(literal) = setup_literal {
                        self.pending_literal = Some(PendingLiteral::new(tx_id, literal));
                    }
                }
                Err(Err::Incomplete(_)) => return incomplete(start),
                Err(_) => {
                    // A client line that is no command answers an AUTHENTICATE
                    // or IDLE whose continuation request was not seen.
                    if let Some(tx_id) = self.waiting_continuation_tx_id() {
                        self.abandon_pending_literal();
                        self.continuation_tx_id = Some(tx_id);
                        continue;
                    }
                    let Some(len) = self.skip_invalid_line(flow, Direction::ToServer, line) else {
                        return incomplete(start);
                    };
                    self.abandon_pending_literal();
                    start = &start[len..];
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

        let incomplete = |rest: &[u8]| {
            AppLayerResult::incomplete((input.len() - rest.len()) as u32, (rest.len() + 1) as u32)
        };
        let offset_of = |rest: &[u8]| stream_slice.offset + (input.len() - rest.len()) as u64;
        self.raise_deferred_events();
        let mut orphan_tx_id = None;
        let mut start = input;
        // As for requests, the lost data may hold the announcement of a
        // literal, whose text easily reads as responses: lines are skipped
        // until a response to resync on.
        while self.response_gap && !start.is_empty() {
            let Some(line) = self.response_line.window(offset_of(start), start) else {
                return incomplete(start);
            };
            let known = parse_response(line)
                .map(|(_, response)| resyncs_response(&self.transactions, &response));
            let Some(skip) = gap_resync_skip(known, line) else {
                return incomplete(start);
            };
            start = &start[skip..];
            self.response_gap = skip != 0;
        }
        while !start.is_empty() {
            if let Some(mut pending) = self
                .pending_response_literal
                .take_if(|pending| pending.awaiting_line_rest)
            {
                let Some(line) = self.response_line.window(offset_of(start), start) else {
                    self.pending_response_literal = Some(pending);
                    return incomplete(start);
                };
                match parse_response_continuation(line) {
                    Ok((rem, (rest, literal_size))) => {
                        pending.append_line_rest(rest);
                        if let Some(size) = literal_size {
                            self.pending_response_literal = Some(PendingResponseLiteral::new(
                                pending.tx_id,
                                pending.response,
                                size,
                            ));
                        } else {
                            self.complete_pending_response(pending, &mut orphan_tx_id);
                        }
                        start = rem;
                        continue;
                    }
                    Err(Err::Incomplete(_)) => {
                        self.pending_response_literal = Some(pending);
                        return incomplete(start);
                    }
                    Err(_) => {
                        let Some(len) = self.skip_invalid_line(flow, Direction::ToClient, line)
                        else {
                            self.pending_response_literal = Some(pending);
                            return incomplete(start);
                        };
                        self.complete_pending_response(pending, &mut orphan_tx_id);
                        start = &start[len..];
                        continue;
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
                let frame_len = pending.literal.size_since_gap();
                if let Some(tx_id) = tx_id {
                    self.set_frame_tc(flow, tx_id, i64::try_from(frame_len).unwrap_or(i64::MAX));
                } else {
                    self.end_frame(
                        flow,
                        Direction::ToClient,
                        usize::try_from(frame_len).unwrap_or(usize::MAX),
                    );
                }
                start = &start[consumed..];
                continue;
            }

            let Some(line) = self.response_line.window(offset_of(start), start) else {
                return incomplete(start);
            };

            match parse_response(line) {
                Ok((rem, response)) => {
                    let consumed = start.len() - rem.len();
                    if let Some(offered) = non_sync_literal_capability(&response) {
                        self.non_sync_literals = Some(offered);
                    }

                    if let Some(ref tag) = response.tag {
                        let status = match &response.message {
                            ImapMessageType::Response { status } => Some(status.clone()),
                            _ => None,
                        };
                        let tag_reused = self
                            .transactions
                            .iter()
                            .filter(|tx| tx.request_tag.as_ref() == Some(tag) && !tx.complete())
                            .nth(1)
                            .is_some();
                        if let Some(tx) = self.find_request(tag) {
                            let tx_id = tx.id();
                            /* The reply that completes a STARTTLS command with
                             * OK is the one that switches the flow to TLS, and
                             * likewise for COMPRESS. It is only trusted if it
                             * can be no reply to another command: the server
                             * may not have read this one as a command. */
                            let switches = status == Some(ImapResponseStatus::Ok)
                                && !tx.ambiguous
                                && !tag_reused;
                            let starttls_ok = switches && tx.command == Some(ImapCommand::StartTls);
                            let compress_ok = switches && tx.command == Some(ImapCommand::Compress);
                            /* A server without non-synchronizing literals
                             * answers the command line with BAD and reads
                             * what follows as commands. */
                            let literal_rejected = status == Some(ImapResponseStatus::Bad)
                                && self.non_sync_literals.is_none()
                                && self.pending_literal.as_ref().is_some_and(|pending| {
                                    pending.tx_id == tx_id && pending.literal.is_literal_plus
                                });
                            if literal_rejected {
                                self.request_frame = None;
                                self.resync_request();
                            }
                            self.add_response_to(tx_id, response);
                            /* Answered without a continuation request, the
                             * command read no data: the lines after it were
                             * commands. */
                            for tx in &mut self.transactions {
                                if tx.ambiguous_with == Some(tx_id) {
                                    tx.ambiguous = false;
                                    tx.ambiguous_with = None;
                                }
                            }
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
                            sc_app_layer_parser_trigger_raw_stream_inspection(
                                flow,
                                Direction::ToClient as i32,
                            );
                            if compress_ok {
                                /* RFC 4978: what follows this reply is
                                 * compressed, in both directions. */
                                SCLogDebug!("IMAP: COMPRESS completed");
                                self.compressed = true;
                                return AppLayerResult::ok();
                            }
                        } else {
                            let tx_id = self.orphan_response_tx(&mut orphan_tx_id);
                            self.add_response_frame(flow, tx_id, response, consumed);
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
                            Some(self.resolve_untagged_response_target(*seq_number, keyword))
                        } else {
                            None
                        };
                        // A tagless response is untagged or a continuation request.
                        let response_tx_id = if let Some(target) = untagged_target {
                            self.commit_untagged_response_target(target)
                        } else {
                            self.continuation_response_tx_id()
                        };

                        if is_continuation {
                            for tx in &mut self.transactions {
                                tx.ambiguous_with = None;
                            }
                            if let Some(pending) = self.pending_literal.as_mut() {
                                if !pending.literal.is_literal_plus {
                                    pending.continuation_received = true;
                                }
                            } else {
                                self.continuation_tx_id = response_tx_id;
                            }
                        }

                        /* A data response (LIST, STATUS, ID, ...) may end in a
                         * literal specifier: its octets follow the CRLF. */
                        let literal_size = match &response.message {
                            ImapMessageType::Untagged { keyword, .. } => {
                                let line = &start[..consumed - 1];
                                untagged_trailing_literal(
                                    keyword,
                                    line.strip_suffix(b"\r").unwrap_or(line),
                                )
                            }
                            _ => None,
                        };

                        if let Some(size) = literal_size {
                            self.pending_response_literal =
                                Some(PendingResponseLiteral::new(response_tx_id, response, size));
                            match response_tx_id {
                                Some(tx_id) => self.set_frame_tc(flow, tx_id, consumed as i64),
                                None => self.end_frame(flow, Direction::ToClient, consumed),
                            }
                        } else {
                            let tx_id = response_tx_id
                                .or_else(|| self.orphan_response_tx(&mut orphan_tx_id));
                            self.add_response_frame(flow, tx_id, response, consumed);
                        }
                    }
                    self.response_invalid = false;
                    start = rem;
                }
                Err(Err::Incomplete(_)) => return incomplete(start),
                Err(_) => {
                    let Some(len) = self.skip_invalid_line(flow, Direction::ToClient, line) else {
                        return incomplete(start);
                    };
                    start = &start[len..];
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

    /// Gives up a line that has not ended within IMAP_MAX_PENDING_LINE: its
    /// octets are dropped instead of being buffered further, and parsing
    /// resyncs after its line feed, as after a gap.
    fn limit_pending_line(
        &mut self, flow: *const Flow, direction: Direction, result: AppLayerResult,
    ) -> AppLayerResult {
        // An incomplete result always leaves a line without its line feed.
        if !result.is_incomplete() || result.needed as usize <= IMAP_MAX_PENDING_LINE {
            return result;
        }
        self.end_frame(flow, direction, result.needed as usize - 1);
        // While resyncing these are further octets of a line already reported.
        let resyncing = match direction {
            Direction::ToServer => self.request_gap,
            Direction::ToClient => self.response_gap,
        };
        if !resyncing {
            match direction {
                Direction::ToServer => self.request_too_long_deferred = true,
                Direction::ToClient => self.response_too_long_deferred = true,
            }
            self.raise_deferred_events();
        }
        match direction {
            Direction::ToServer => self.resync_request(),
            Direction::ToClient => self.resync_response(),
        }
        AppLayerResult::ok()
    }

    fn resync_request(&mut self) {
        self.request_gap = true;
        self.continuation_tx_id = None;
        self.abandon_pending_literal();
    }

    fn resync_response(&mut self) {
        self.response_gap = true;
        self.active_response_tx_id = None;
        if let Some(pending) = self.pending_response_literal.take() {
            self.complete_pending_response(pending, &mut None);
        }
    }

    fn on_request_gap(&mut self, size: u32) {
        self.request_frame = None;
        // Octets lost within a literal leave its end known, so parsing stays
        // in sync. The client sends them only after a continuation request.
        if let Some(pending) = self
            .pending_literal
            .as_mut()
            .filter(|pending| !pending.awaiting_line_rest)
        {
            if pending.literal.consume_gap(size) {
                pending.continuation_received = true;
                return;
            }
        }
        self.resync_request();
    }

    fn on_response_gap(&mut self, size: u32) {
        self.response_frame = None;
        // As for requests, octets lost within a literal keep parsing in sync.
        if self
            .pending_response_literal
            .as_mut()
            .filter(|pending| !pending.awaiting_line_rest)
            .is_some_and(|pending| pending.literal.consume_gap(size))
        {
            return;
        }
        self.resync_response();
        // The lost data may hold the continuation request the client answers
        // next, so a pending literal or continuation line is kept.
        if let Some(pending) = self.pending_literal.as_mut() {
            pending.continuation_received = true;
        }
    }

    /// Hand the untagged response that announced a literal over to its
    /// transaction, once its line ended or no more data will complete it.
    /// Without one, it joins the transaction of unmatched responses: that is
    /// only chosen now, as the literal may have outlasted a chunk.
    fn complete_pending_response(
        &mut self, pending: PendingResponseLiteral, orphan_tx_id: &mut Option<u64>,
    ) {
        if let Some(tx_id) = pending
            .tx_id
            .or_else(|| self.orphan_response_tx(orphan_tx_id))
        {
            self.add_response_to(tx_id, pending.response);
        }
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
        Ok((_, request)) => Ok(is_known_command(&request)),
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
    // a bare continuation line is not enough to identify IMAP
    parse_response(input)
        .map(|(_, response)| !matches!(response.message, ImapMessageType::Continuation))
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
        state.on_request_gap(stream_slice.gap_size());
        AppLayerResult::ok()
    } else {
        let result = state.parse_request(flow, stream_slice);
        state.limit_pending_line(flow, Direction::ToServer, result)
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
        state.on_response_gap(stream_slice.gap_size());
        AppLayerResult::ok()
    } else {
        let result = state.parse_response(flow, stream_slice);
        state.limit_pending_line(flow, Direction::ToClient, result)
    };
    if state.compressed {
        // The deflate stream is not parsed: stop tracking the flow, as SSH
        // does for encrypted data.
        SCAppLayerParserStateSetFlag(
            pstate,
            APP_LAYER_PARSER_NO_INSPECTION | APP_LAYER_PARSER_NO_REASSEMBLY,
        );
    }
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
            SCLogError!("Failed to register IMAP protocol detection patterns");
            return;
        }
        if SCAppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
            // Without the parser the global reassembly depth stays in place.
            let mut stream_depth = IMAP_CONFIG_DEFAULT_STREAM_DEPTH;
            if let Some(val) = conf_get("app-layer.protocols.imap.stream-depth") {
                match get_memval(val).ok().and_then(|v| u32::try_from(v).ok()) {
                    Some(v) => stream_depth = v,
                    None => {
                        SCLogError!("Invalid value for imap.stream-depth");
                    }
                }
            }
            SCAppLayerParserSetStreamDepth(IPPROTO_TCP, ALPROTO_IMAP, stream_depth);
        }
        if let Some(val) = conf_get("app-layer.protocols.imap.max-tx") {
            match val.parse::<usize>() {
                Ok(v) if v > 0 => IMAP_MAX_TX = v,
                _ => {
                    SCLogError!("Invalid value for imap.max-tx");
                }
            }
        }
        if let Some(val) = conf_get("app-layer.protocols.imap.max-responses") {
            match val.parse::<usize>() {
                Ok(v) if v > 0 => IMAP_MAX_RESPONSES = v,
                _ => {
                    SCLogError!("Invalid value for imap.max-responses");
                }
            }
        }
        SCAppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_IMAP);
    } else {
        SCLogDebug!("Protocol detection and parser disabled for IMAP/TCP.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_probe_continuation() {
        // a bare continuation, e.g. a POP3 greeting, must not match
        assert_eq!(
            probe(b"+OK POP3 ready\r\n", Direction::ToClient),
            ProbeResult::Mismatch
        );
        assert_eq!(
            probe(b"+ Ready\r\n", Direction::ToServer),
            ProbeResult::Mismatch
        );
        assert_eq!(
            probe(b"* OK IMAP4rev1 ready\r\n", Direction::ToClient),
            ProbeResult::Match { flip: false }
        );
        assert_eq!(
            probe(b"A1 OK done\r\n", Direction::ToServer),
            ProbeResult::Match { flip: true }
        );
    }
}
