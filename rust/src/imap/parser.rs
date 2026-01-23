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

use nom8::branch::alt;
use nom8::bytes::streaming::{tag, tag_no_case, take_till, take_while1};
use nom8::character::complete::{char as complete_char, u32 as complete_u32};
use nom8::character::streaming::{char, line_ending, space0, space1, u64 as streaming_u64};
use nom8::combinator::{all_consuming, complete, cond, map, opt, value, verify};
use nom8::error::{Error, ErrorKind};
use nom8::sequence::preceded;
use nom8::{Err, IResult, Needed, Parser};

pub const IMAP_MAX_LINE_SIZE: usize = 8 * 1024;
const IMAP_MAX_ARGUMENTS: usize = IMAP_MAX_LINE_SIZE / 2;
const IMAP_MAX_LITERAL_SIZE: u64 = i64::MAX as u64;
const IMAP_MAX_SEQUENCE_RANGES: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImapCommand {
    // Any state commands
    Capability,
    Noop,
    Logout,

    // Not authenticated state
    StartTls,
    Authenticate,
    Login,

    // Authenticated state
    Select,
    Examine,
    Create,
    Delete,
    Rename,
    Subscribe,
    Unsubscribe,
    List,
    Lsub,
    Status,
    Append,

    // Selected state
    Check,
    Close,
    Expunge,
    Search,
    Fetch,
    Store,
    Copy,
    Uid,

    // Extensions
    Idle,
    Id,
    Compress,

    // Unknown command
    Unknown(Vec<u8>),
}

const COMMANDS: &[(&str, ImapCommand)] = &[
    ("CAPABILITY", ImapCommand::Capability),
    ("NOOP", ImapCommand::Noop),
    ("LOGOUT", ImapCommand::Logout),
    ("STARTTLS", ImapCommand::StartTls),
    ("AUTHENTICATE", ImapCommand::Authenticate),
    ("LOGIN", ImapCommand::Login),
    ("SELECT", ImapCommand::Select),
    ("EXAMINE", ImapCommand::Examine),
    ("CREATE", ImapCommand::Create),
    ("DELETE", ImapCommand::Delete),
    ("RENAME", ImapCommand::Rename),
    ("SUBSCRIBE", ImapCommand::Subscribe),
    ("UNSUBSCRIBE", ImapCommand::Unsubscribe),
    ("LIST", ImapCommand::List),
    ("LSUB", ImapCommand::Lsub),
    ("STATUS", ImapCommand::Status),
    ("APPEND", ImapCommand::Append),
    ("CHECK", ImapCommand::Check),
    ("CLOSE", ImapCommand::Close),
    ("EXPUNGE", ImapCommand::Expunge),
    ("SEARCH", ImapCommand::Search),
    ("FETCH", ImapCommand::Fetch),
    ("STORE", ImapCommand::Store),
    ("COPY", ImapCommand::Copy),
    ("UID", ImapCommand::Uid),
    ("IDLE", ImapCommand::Idle),
    ("ID", ImapCommand::Id),
    ("COMPRESS", ImapCommand::Compress),
];

/// Command named by `name`, as on the wire, which may be unknown.
pub fn command_from_name(name: &[u8]) -> ImapCommand {
    COMMANDS
        .iter()
        .find(|(known, _)| name.eq_ignore_ascii_case(known.as_bytes()))
        .map_or_else(
            || ImapCommand::Unknown(name[..name.len().min(IMAP_MAX_LINE_SIZE)].to_vec()),
            |(_, command)| command.clone(),
        )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImapResponseStatus {
    Ok,
    No,
    Bad,
    PreAuth,
    Bye,
}

#[derive(Debug, Clone)]
pub struct LiteralInfo {
    pub size: u64,
    pub is_literal_plus: bool,
    pub bytes_consumed: u64,
    // Octets before the end of the last gap, where the data resumed.
    resumed_at: u64,
}

impl LiteralInfo {
    pub fn new(size: u64, is_literal_plus: bool) -> Self {
        Self {
            size,
            is_literal_plus,
            bytes_consumed: 0,
            resumed_at: 0,
        }
    }

    /// Octets of the literal since the data resumed after the last gap, or
    /// all of them without a gap.
    pub fn size_since_gap(&self) -> u64 {
        self.size - self.resumed_at
    }

    pub fn remaining(&self) -> u64 {
        self.size.saturating_sub(self.bytes_consumed)
    }

    pub fn consume_chunk(&mut self, chunk: &[u8]) -> usize {
        let consumed = match usize::try_from(self.remaining()) {
            Ok(remaining) => std::cmp::min(chunk.len(), remaining),
            Err(_) => chunk.len(),
        };
        self.bytes_consumed = self
            .bytes_consumed
            .saturating_add(u64::try_from(consumed).unwrap_or(u64::MAX));
        consumed
    }

    /// Counts lost octets against the literal. Returns false, consuming
    /// nothing, when the gap runs past the end of the literal.
    pub fn consume_gap(&mut self, size: u32) -> bool {
        let size = u64::from(size);
        if size > self.remaining() {
            return false;
        }
        self.bytes_consumed += size;
        self.resumed_at = self.bytes_consumed;
        true
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommandLiteral {
    pub size: u64,
    pub is_literal_plus: bool,
    pub parenthesis_depth: usize,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ImapMessageType {
    Command {
        command: ImapCommand,
        arguments: Vec<Vec<u8>>,
        literal: Option<CommandLiteral>,
    },
    Response {
        status: ImapResponseStatus,
    },
    Untagged {
        seq_number: Option<u32>,
        keyword: Vec<u8>,
    },
    Continuation,
    ContinuationData,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ImapMessage {
    pub tag: Option<Vec<u8>>,
    pub message: ImapMessageType,
    pub raw_line: Vec<u8>,
    pub line_truncated: bool,
}

#[inline]
fn is_line_ending(b: u8) -> bool {
    b == b'\r' || b == b'\n'
}

#[inline]
fn is_tag_char(c: u8) -> bool {
    c.is_ascii_graphic() && !b"(){}%*\"\\+ ".contains(&c)
}

#[inline]
fn is_atom_char(c: u8) -> bool {
    c.is_ascii_graphic() && !b"(){}%*\"\\ ".contains(&c)
}

fn cap_raw_line(line: &[u8]) -> (Vec<u8>, bool) {
    if line.len() > IMAP_MAX_LINE_SIZE {
        (line[..IMAP_MAX_LINE_SIZE].to_vec(), true)
    } else {
        (line.to_vec(), false)
    }
}

fn parse_tag(i: &[u8]) -> IResult<&[u8], &[u8]> {
    take_while1(is_tag_char).parse(i)
}

fn parse_command_keyword(i: &[u8]) -> IResult<&[u8], ImapCommand> {
    let (i, cmd) = parse_atom(i)?;
    Ok((i, command_from_name(cmd)))
}

pub fn probe_command_prefix(i: &[u8]) -> IResult<&[u8], bool> {
    let (i, _tag) = parse_tag(i)?;
    let (i, _) = space1.parse(i)?;
    let (i, command) = parse_command_keyword(i)?;
    Ok((i, !matches!(command, ImapCommand::Unknown(_))))
}

fn parse_status(i: &[u8]) -> IResult<&[u8], ImapResponseStatus> {
    alt((
        value(ImapResponseStatus::Ok, tag_no_case("OK")),
        value(ImapResponseStatus::No, tag_no_case("NO")),
        value(ImapResponseStatus::Bad, tag_no_case("BAD")),
        value(ImapResponseStatus::PreAuth, tag_no_case("PREAUTH")),
        value(ImapResponseStatus::Bye, tag_no_case("BYE")),
    ))
    .parse(i)
}

fn parse_quoted_string(i: &[u8], retain_limit: usize) -> IResult<&[u8], Vec<u8>> {
    let (mut rem, _) = char('"').parse(i)?;
    let mut value = Vec::new();

    loop {
        let Some((&byte, after_byte)) = rem.split_first() else {
            return Err(Err::Incomplete(Needed::new(1)));
        };

        match byte {
            b'"' => {
                value.shrink_to_fit();
                return Ok((after_byte, value));
            }
            b'\\' => {
                let Some((&escaped, after_escape)) = after_byte.split_first() else {
                    return Err(Err::Incomplete(Needed::new(1)));
                };
                // Only a quote or a backslash may be escaped, but servers
                // accept any character: so does this parser, or a command
                // the server runs would be skipped as invalid.
                if matches!(escaped, b'\0' | b'\r' | b'\n') {
                    return Err(Err::Error(Error::new(rem, ErrorKind::Escaped)));
                }
                if value.len() < retain_limit {
                    value.push(escaped);
                }
                rem = after_escape;
            }
            b'\0' | b'\r' | b'\n' => {
                return Err(Err::Error(Error::new(rem, ErrorKind::Char)));
            }
            _ => {
                if value.len() < retain_limit {
                    value.push(byte);
                }
                rem = after_byte;
            }
        }
    }
}

fn parse_atom(i: &[u8]) -> IResult<&[u8], &[u8]> {
    take_while1(is_atom_char).parse(i)
}

#[derive(Debug, Default)]
struct ParenthesisScanner {
    depth: usize,
    in_quoted: bool,
    escaped: bool,
}

impl ParenthesisScanner {
    fn scan(&mut self, i: &[u8]) -> Result<Option<usize>, ErrorKind> {
        for (pos, &b) in i.iter().enumerate() {
            if self.in_quoted {
                if self.escaped {
                    if matches!(b, b'\0' | b'\r' | b'\n') {
                        return Err(ErrorKind::Escaped);
                    }
                    self.escaped = false;
                    continue;
                }

                match b {
                    b'\\' => self.escaped = true,
                    b'"' => self.in_quoted = false,
                    b'\0' | b'\r' | b'\n' => return Err(ErrorKind::Char),
                    _ => {}
                }
                continue;
            }

            match b {
                b'"' => self.in_quoted = true,
                b'(' => {
                    self.depth = self.depth.checked_add(1).ok_or(ErrorKind::TooLarge)?;
                }
                b')' => {
                    if self.depth == 0 {
                        return Err(ErrorKind::Char);
                    }
                    self.depth -= 1;
                    if self.depth == 0 {
                        return Ok(Some(pos));
                    }
                }
                b'\r' | b'\n' => return Ok(Some(pos)),
                _ => {}
            }
        }
        Ok(None)
    }
}

fn parse_list(
    i: &[u8], depth: usize, retain_limit: usize,
) -> IResult<&[u8], (Vec<u8>, Option<CommandLiteral>)> {
    if depth == 0 {
        let _ = char('(').parse(i)?;
    } else if let Some(&first) = i.first() {
        if !matches!(first, b' ' | b'\t' | b')') {
            return Err(Err::Error(Error::new(i, ErrorKind::Char)));
        }
    }
    let mut scanner = ParenthesisScanner {
        depth,
        ..Default::default()
    };
    let line_end = match scanner
        .scan(i)
        .map_err(|kind| Err::Error(Error::new(i, kind)))?
    {
        Some(pos) if !is_line_ending(i[pos]) => {
            return Ok((
                &i[pos + 1..],
                (i[..(pos + 1).min(retain_limit)].to_vec(), None),
            ));
        }
        Some(pos) => pos,
        None => return Err(Err::Incomplete(Needed::new(1))),
    };
    let line = &i[..line_end];
    if let Some((prefix, (size, is_literal_plus))) = detect_trailing_literal(line) {
        let prefix = prefix.strip_suffix(b"~").unwrap_or(prefix);
        if matches!(prefix.last(), Some(b' ' | b'\t' | b'(')) {
            let literal = CommandLiteral {
                size,
                is_literal_plus,
                parenthesis_depth: scanner.depth,
            };
            return Ok((
                &i[line.len()..],
                (line[..line.len().min(retain_limit)].to_vec(), Some(literal)),
            ));
        }
    }
    Err(Err::Error(Error::new(i, ErrorKind::Char)))
}

fn parse_literal_as_argument(
    i: &[u8], retain_limit: usize,
) -> IResult<&[u8], (Vec<u8>, Option<CommandLiteral>)> {
    let start = i;
    // A literal8 (RFC 3516) carries a `~` marker.
    let (i, _) = opt(tag("~")).parse(i)?;
    let (i, (size, is_literal_plus)) = parse_literal_specifier(i)?;
    let len = start.len() - i.len();
    let literal = CommandLiteral {
        size,
        is_literal_plus,
        parenthesis_depth: 0,
    };
    Ok((i, (start[..len.min(retain_limit)].to_vec(), Some(literal))))
}

#[inline]
fn is_list_char(c: u8) -> bool {
    is_atom_char(c) || c == b'%' || c == b'*' || c == b'\\'
}

fn parse_sequence_value(i: &[u8]) -> Option<Option<u32>> {
    all_consuming(alt((
        value(None, complete_char::<_, Error<_>>('*')),
        map(verify(complete_u32::<_, Error<_>>, |num| *num != 0), Some),
    )))
    .parse(i)
    .ok()
    .map(|(_, val)| val)
}

/// Sequence set of a command, parsed once so that each untagged response
/// is matched against it with a binary search.
#[derive(Debug)]
pub struct SequenceSet {
    // Sorted, merged ranges of the items without `*`.
    ranges: Vec<(u32, u32)>,
    // Lowest n of the `n:*` and `*:n` items, which include every number from n.
    open_from: Option<u32>,
    // Whether the set has a `*` or `*:*` item, whose value is unknown here.
    has_star: bool,
}

impl SequenceSet {
    /// Returns None for an invalid set or one with too many ranges to keep.
    pub fn parse(set: &[u8]) -> Option<Self> {
        let mut ranges = Vec::new();
        let mut open_from: Option<u32> = None;
        let mut has_star = false;

        for item in set.split(|b| *b == b',') {
            let mut vals = item.split(|b| *b == b':');
            let first_val = parse_sequence_value(vals.next()?)?;
            let second_val = match vals.next() {
                Some(val) => Some(parse_sequence_value(val)?),
                None => None,
            };
            if vals.next().is_some() {
                return None;
            }

            match (first_val, second_val) {
                (Some(num), None) => ranges.push((num, num)),
                (Some(first_val), Some(Some(second_val))) => {
                    ranges.push((first_val.min(second_val), first_val.max(second_val)));
                }
                (Some(val), Some(None)) | (None, Some(Some(val))) => {
                    open_from = Some(open_from.map_or(val, |lower| lower.min(val)));
                }
                (None, None) | (None, Some(None)) => has_star = true,
            }
        }

        ranges.sort_unstable();
        ranges.dedup_by(|&mut (lower, upper), prev| {
            if lower > prev.1.saturating_add(1) {
                return false;
            }
            prev.1 = prev.1.max(upper);
            true
        });
        if ranges.len() > IMAP_MAX_SEQUENCE_RANGES {
            return None;
        }
        ranges.shrink_to_fit();
        Some(Self {
            ranges,
            open_from,
            has_star,
        })
    }

    /// Returns None when the set may or may not include the number, because
    /// `*` depends on the mailbox size.
    pub fn contains(&self, sequence_number: u32) -> Option<bool> {
        let pos = self
            .ranges
            .partition_point(|&(_, upper)| upper < sequence_number);
        if self
            .ranges
            .get(pos)
            .is_some_and(|&(lower, _)| lower <= sequence_number)
            || self.open_from.is_some_and(|lower| sequence_number >= lower)
        {
            return Some(true);
        }
        if self.has_star || self.open_from.is_some() {
            return None;
        }
        Some(false)
    }
}

fn parse_body_section_argument(
    i: &[u8], retain_limit: usize,
) -> IResult<&[u8], (Vec<u8>, Option<CommandLiteral>)> {
    let (_, line) = take_till(is_line_ending).parse(i)?;
    let (rem, _) = complete(parse_body_section).parse(line)?;
    if rem.first().is_some_and(|b| !matches!(b, b' ' | b'\t')) {
        return Err(Err::Error(Error::new(i, ErrorKind::Verify)));
    }
    let consumed = line.len() - rem.len();
    Ok((
        &i[consumed..],
        (i[..consumed.min(retain_limit)].to_vec(), None),
    ))
}

fn parse_argument(
    i: &[u8], retain_limit: usize,
) -> IResult<&[u8], (Vec<u8>, Option<CommandLiteral>)> {
    alt((
        map(|i| parse_quoted_string(i, retain_limit), |arg| (arg, None)),
        |i| parse_list(i, 0, retain_limit),
        |i| parse_literal_as_argument(i, retain_limit),
        map(take_while1(is_list_char), |s: &[u8]| {
            (s[..s.len().min(retain_limit)].to_vec(), None)
        }),
    ))
    .parse(i)
}

type CommandArguments = (Vec<Vec<u8>>, Option<CommandLiteral>);

fn parse_arguments<'a>(
    mut i: &'a [u8], depth: usize, command: Option<&ImapCommand>,
) -> IResult<&'a [u8], CommandArguments> {
    let mut arguments = Vec::new();
    let mut retain_left = if command.is_some() {
        IMAP_MAX_LINE_SIZE
    } else {
        0
    };
    let mut position = 0;
    let mut literal = None;
    if depth != 0 {
        let (rem, (argument, pending)) = parse_list(i, depth, retain_left)?;
        if retain_left != 0 {
            retain_left -= argument.len();
            arguments.push(argument);
        }
        position += 1;
        literal = pending;
        i = rem;
    }
    while literal.is_none() {
        let fetch_attribute = match command {
            Some(ImapCommand::Fetch) => position == 1,
            Some(ImapCommand::Uid) => {
                position == 2
                    && arguments
                        .first()
                        .is_some_and(|arg| arg.eq_ignore_ascii_case(b"FETCH"))
            }
            _ => false,
        };
        let (rem, argument) = opt(preceded(space1, |input| {
            if fetch_attribute {
                alt((
                    |i| parse_body_section_argument(i, retain_left),
                    |i| parse_argument(i, retain_left),
                ))
                .parse(input)
            } else {
                parse_argument(input, retain_left)
            }
        }))
        .parse(i)?;
        let Some((argument, pending)) = argument else {
            break;
        };
        if retain_left != 0 {
            retain_left -= argument.len();
            arguments.push(argument);
            if arguments.len() == IMAP_MAX_ARGUMENTS {
                retain_left = 0;
            }
        }
        position += 1;
        literal = pending;
        i = rem;
    }
    arguments.shrink_to_fit();
    Ok((i, (arguments, literal)))
}

pub fn parse_command_continuation(
    i: &[u8], depth: usize,
) -> IResult<&[u8], (ImapMessage, Option<CommandLiteral>)> {
    let start = i;
    let (i, (_, literal)) = parse_arguments(i, depth, None)?;
    let (i, _) = cond(literal.is_none(), space0).parse(i)?;
    let (i, eol) = line_ending.parse(i)?;

    let raw_len = start.len() - i.len() - eol.len();
    let suffix = &start[..raw_len];
    let offset = suffix
        .iter()
        .position(|&b| b != b' ')
        .unwrap_or(suffix.len());
    let (raw_line, line_truncated) = cap_raw_line(&suffix[offset..]);
    Ok((
        i,
        (
            ImapMessage {
                tag: None,
                message: ImapMessageType::ContinuationData,
                raw_line,
                line_truncated,
            },
            literal,
        ),
    ))
}

/// Parses the rest of a response line following literal octets. Returns that
/// text and the size of the next literal it announces, if any.
pub fn parse_response_continuation(i: &[u8]) -> IResult<&[u8], (&[u8], Option<u64>)> {
    let (i, rest) = take_till(is_line_ending).parse(i)?;
    let (i, _) = line_ending.parse(i)?;
    Ok((
        i,
        (
            rest,
            detect_trailing_literal(rest).map(|(_, (size, _))| size),
        ),
    ))
}

fn detect_trailing_literal(line: &[u8]) -> Option<(&[u8], (u64, bool))> {
    let brace_pos = line.iter().rposition(|&c| c == b'{')?;
    match parse_literal_specifier(&line[brace_pos..]) {
        Ok(([], literal)) => Some((&line[..brace_pos], literal)),
        _ => None,
    }
}

/// Whether a capability list carried by this response offers
/// non-synchronizing literals. None when the response has no such list.
pub fn non_sync_literal_capability(response: &ImapMessage) -> Option<bool> {
    let line = response.raw_line.as_slice();
    let list = match &response.message {
        ImapMessageType::Untagged { keyword, .. }
            if keyword.eq_ignore_ascii_case(b"CAPABILITY") =>
        {
            line
        }
        // A status response may carry the list as a response code.
        ImapMessageType::Untagged { keyword, .. }
            if all_consuming(parse_status)
                .parse(keyword.as_slice())
                .is_err() =>
        {
            return None;
        }
        ImapMessageType::Untagged { .. } | ImapMessageType::Response { .. } => {
            let code = &line[line.iter().position(|&c| c == b'[')? + 1..];
            let code = &code[..code.iter().position(|&c| c == b']')?];
            if !code
                .get(..11)
                .is_some_and(|name| name.eq_ignore_ascii_case(b"CAPABILITY "))
            {
                return None;
            }
            code
        }
        _ => return None,
    };
    Some(list.split(|&c| c == b' ').any(|capability| {
        capability.eq_ignore_ascii_case(b"LITERAL+") || capability.eq_ignore_ascii_case(b"LITERAL-")
    }))
}

pub fn untagged_trailing_literal(keyword: &[u8], line: &[u8]) -> Option<u64> {
    if all_consuming(parse_status).parse(keyword).is_ok() {
        return None;
    }
    detect_trailing_literal(line).map(|(_, (size, _))| size)
}

fn parse_partial_offset(i: &[u8]) -> IResult<&[u8], ()> {
    let (i, _) = complete_char('<').parse(i)?;
    let (i, _) = complete_u32::<_, Error<_>>(i)?;
    let (i, _) = opt(preceded(complete_char('.'), complete_u32::<_, Error<_>>)).parse(i)?;
    let (i, _) = complete_char('>').parse(i)?;
    Ok((i, ()))
}

fn parse_body_section(i: &[u8]) -> IResult<&[u8], ()> {
    let (i, _) = alt((tag_no_case("BODY.PEEK"), tag_no_case("BODY"))).parse(i)?;
    let (i, _) = char('[').parse(i)?;
    let (i, _) = take_till(|c| c == b']').parse(i)?;
    let (i, _) = char(']').parse(i)?;
    let (i, _) = opt(parse_partial_offset).parse(i)?;
    Ok((i, ()))
}

pub fn parse_command(i: &[u8]) -> IResult<&[u8], ImapMessage> {
    let start = i;
    let (i, tag_bytes) = parse_tag(i)?;
    let (i, _) = space1.parse(i)?;
    let (i, command) = parse_command_keyword(i)?;
    let (i, (arguments, literal)) = parse_arguments(i, 0, Some(&command))?;
    // tolerate trailing whitespace and a bare LF, as lenient servers do, but
    // a literal must be directly followed by the line end
    let (i, _) = cond(literal.is_none(), space0).parse(i)?;
    let (i, eol) = line_ending.parse(i)?;

    let raw_len = start.len() - i.len() - eol.len();
    let (raw_line, line_truncated) = cap_raw_line(&start[..raw_len]);

    Ok((
        i,
        ImapMessage {
            tag: Some(tag_bytes[..tag_bytes.len().min(IMAP_MAX_LINE_SIZE)].to_vec()),
            message: ImapMessageType::Command {
                command,
                arguments,
                literal,
            },
            raw_line,
            line_truncated,
        },
    ))
}

fn parse_tagged_response(i: &[u8]) -> IResult<&[u8], ImapMessage> {
    let start = i;
    let (i, tag_bytes) = parse_tag(i)?;
    let (i, _) = space1.parse(i)?;
    let (i, status) = parse_status(i)?;
    let (i, _) = opt(preceded(space1, take_till(is_line_ending))).parse(i)?;
    let (i, eol) = line_ending.parse(i)?;

    let raw_len = start.len() - i.len() - eol.len();
    let (raw_line, line_truncated) = cap_raw_line(&start[..raw_len]);

    Ok((
        i,
        ImapMessage {
            tag: Some(tag_bytes[..tag_bytes.len().min(IMAP_MAX_LINE_SIZE)].to_vec()),
            message: ImapMessageType::Response { status },
            raw_line,
            line_truncated,
        },
    ))
}

fn parse_untagged_prefix(i: &[u8]) -> IResult<&[u8], (Option<u32>, &[u8])> {
    let (i, _) = tag("* ").parse(i)?;
    let (i, first_token) = take_while1(|c: u8| c.is_ascii_alphanumeric()).parse(i)?;

    if first_token.iter().all(|c| c.is_ascii_digit()) {
        let (i, _) = space1.parse(i)?;
        let (i, keyword) = take_while1(|c: u8| c.is_ascii_alphanumeric()).parse(i)?;
        // A number past u32 is no sequence number a command can name, so it
        // is left unknown rather than taken as 0.
        let seq = std::str::from_utf8(first_token)
            .ok()
            .and_then(|s| s.parse().ok());
        Ok((i, (seq, keyword)))
    } else {
        Ok((i, (None, first_token)))
    }
}

fn parse_untagged_response(i: &[u8]) -> IResult<&[u8], ImapMessage> {
    let start = i;
    let (rem, (seq_number, keyword)) = parse_untagged_prefix(i)?;

    let (i, _) = space0.parse(rem)?;
    let (i, _) = take_till(is_line_ending).parse(i)?;
    let (i, eol) = line_ending.parse(i)?;
    let raw_len = start.len() - i.len() - eol.len();
    let (raw_line, line_truncated) = cap_raw_line(&start[..raw_len]);

    Ok((
        i,
        ImapMessage {
            tag: None,
            message: ImapMessageType::Untagged {
                seq_number,
                keyword: keyword.to_vec(),
            },
            raw_line,
            line_truncated,
        },
    ))
}

fn parse_continuation(i: &[u8]) -> IResult<&[u8], ImapMessage> {
    let start = i;
    let (i, _) = tag("+").parse(i)?;
    let (i, _) = space0.parse(i)?;
    let (i, _) = take_till(is_line_ending).parse(i)?;
    let (i, eol) = line_ending.parse(i)?;

    let raw_len = start.len() - i.len() - eol.len();
    let (raw_line, line_truncated) = cap_raw_line(&start[..raw_len]);

    Ok((
        i,
        ImapMessage {
            tag: None,
            message: ImapMessageType::Continuation,
            raw_line,
            line_truncated,
        },
    ))
}

pub fn parse_continuation_data(i: &[u8]) -> IResult<&[u8], ImapMessage> {
    let (i, data) = take_till(is_line_ending).parse(i)?;
    let (i, _) = line_ending.parse(i)?;

    let (raw_line, line_truncated) = cap_raw_line(data);

    Ok((
        i,
        ImapMessage {
            tag: None,
            message: ImapMessageType::ContinuationData,
            raw_line,
            line_truncated,
        },
    ))
}

pub fn parse_response(i: &[u8]) -> IResult<&[u8], ImapMessage> {
    alt((
        parse_untagged_response,
        parse_continuation,
        parse_tagged_response,
    ))
    .parse(i)
}

fn parse_number64(i: &[u8]) -> IResult<&[u8], u64> {
    verify(streaming_u64, |value| *value <= IMAP_MAX_LITERAL_SIZE).parse(i)
}

pub fn parse_literal_specifier(i: &[u8]) -> IResult<&[u8], (u64, bool)> {
    let (i, _) = char('{').parse(i)?;
    let (i, size) = parse_number64(i)?;
    let (i, is_plus) = opt(char('+')).parse(i)?;
    let (i, _) = char('}').parse(i)?;

    Ok((i, (size, is_plus.is_some())))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_incomplete_at_each_boundary<O>(
        input: &[u8], parser: for<'a> fn(&'a [u8]) -> IResult<&'a [u8], O>,
    ) {
        for split in 1..input.len() {
            assert!(
                matches!(parser(&input[..split]), Err(Err::Incomplete(_))),
                "expected incomplete at byte boundary {split}"
            );
        }

        let (rem, _) = parser(input).expect("complete input should parse");
        assert!(rem.is_empty());
    }

    #[test]
    fn test_command_incomplete_at_each_boundary() {
        let input = b"A001 UID FETCH 1:* (FLAGS BODY.PEEK[HEADER.FIELDS (FROM TO)])\r\n";
        assert_incomplete_at_each_boundary(input, parse_command);
    }

    #[test]
    fn test_responses_incomplete_at_each_boundary() {
        for input in [
            b"A001 OK FETCH completed\r\n".as_slice(),
            b"* 23 EXISTS\r\n".as_slice(),
        ] {
            assert_incomplete_at_each_boundary(input, parse_response);
        }
    }

    #[test]
    fn test_unterminated_list_at_line_end_is_invalid() {
        assert!(matches!(
            parse_command(b"A001 FETCH 1 (FLAGS\r\n"),
            Err(Err::Error(_))
        ));
    }

    #[test]
    fn test_parse_command_metadata_limits() {
        let large = "x".repeat(1_000_000);
        for command in [
            format!("A1 CREATE \"{large}\""),
            format!("A1 CREATE {large}"),
            format!("A1 SEARCH ({large})"),
            format!("A1 FETCH 1 BODY[HEADER.FIELDS ({large})]"),
            format!("A1 FETCH {large} BODY[TEXT]"),
            format!("A1 {large}"),
            format!("A1 SEARCH{}", " \"\"".repeat(100_000)),
            format!("A1 SEARCH{}", " ()".repeat(100_000)),
        ] {
            let input = format!("{command}\r\nA2 NOOP\r\n");
            let (rem, msg) = parse_command(input.as_bytes()).unwrap();
            assert_eq!(rem, b"A2 NOOP\r\n");
            assert!(msg.line_truncated);
            assert!(msg.raw_line.capacity() <= IMAP_MAX_LINE_SIZE);
            let ImapMessageType::Command {
                command, arguments, ..
            } = msg.message
            else {
                panic!("Expected Command");
            };
            if let ImapCommand::Unknown(name) = command {
                assert_eq!(name, vec![b'x'; IMAP_MAX_LINE_SIZE]);
                assert_eq!(name.capacity(), IMAP_MAX_LINE_SIZE);
            } else {
                assert!(!arguments.is_empty());
            }
            assert!(arguments.capacity() <= IMAP_MAX_ARGUMENTS);
            assert!(arguments.iter().map(Vec::capacity).sum::<usize>() <= IMAP_MAX_LINE_SIZE);
            assert!(parse_command(rem).unwrap().0.is_empty());
        }
    }

    #[test]
    fn test_command_limits_preserve_syntax_and_literals() {
        for arguments in [
            format!(" {}", "x".repeat(IMAP_MAX_LINE_SIZE)),
            " \"\"".repeat(IMAP_MAX_ARGUMENTS + 1),
        ] {
            let input = format!("A1 SEARCH{arguments} {{3+}}\r\nfoo SUBJECT secret\r\nA2 NOOP\r\n");
            let (rem, msg) = parse_command(input.as_bytes()).unwrap();
            let ImapMessageType::Command {
                literal: Some(literal),
                ..
            } = msg.message
            else {
                panic!("Lost literal after retention limit");
            };
            assert_eq!(literal.size, 3);
            assert!(literal.is_literal_plus);
            let (rem, (suffix, next_literal)) = parse_command_continuation(&rem[3..], 0).unwrap();
            assert_eq!(suffix.raw_line, b"SUBJECT secret");
            assert!(next_literal.is_none());
            assert_eq!(rem, b"A2 NOOP\r\n");
            let invalid = format!("A1 SEARCH{arguments} \"bad\\\0escape\"\r\n");
            assert!(matches!(
                parse_command(invalid.as_bytes()),
                Err(Err::Error(_))
            ));
            let incomplete = format!("A1 SEARCH{arguments} \"unfinished");
            assert!(matches!(
                parse_command(incomplete.as_bytes()),
                Err(Err::Incomplete(_))
            ));
            let suffix = format!("{arguments} {{3+}}\r\n");
            let (_, (retained, literal)) = parse_arguments(suffix.as_bytes(), 0, None).unwrap();
            assert_eq!(retained.capacity(), 0);
            assert!(literal.is_some());
        }
    }

    #[test]
    fn test_tag_size_limit() {
        for len in [
            IMAP_MAX_LINE_SIZE - 1,
            IMAP_MAX_LINE_SIZE,
            IMAP_MAX_LINE_SIZE + 1,
            1_000_000,
        ] {
            let tag = vec![b'A'; len];
            for suffix in [b" NOOP\r\n".as_slice(), b" OK done\r\n"] {
                let mut input = tag.clone();
                input.extend_from_slice(suffix);
                let result = if suffix == b" NOOP\r\n" {
                    parse_command(&input)
                } else {
                    parse_response(&input)
                };
                // A longer tag is kept truncated, like any other long field.
                let (rem, msg) = result.unwrap();
                assert!(rem.is_empty());
                assert_eq!(
                    msg.tag.as_deref(),
                    Some(&tag[..len.min(IMAP_MAX_LINE_SIZE)])
                );
            }
            assert!(matches!(parse_tag(&tag), Err(Err::Incomplete(_))));
        }
    }

    #[test]
    fn test_parse_fetch_arguments() {
        for (input, expected) in [
            (
                b"A1 FETCH 1 BODY[HEADER.FIELDS (SUBJECT FROM)]\r\n".as_slice(),
                b"BODY[HEADER.FIELDS (SUBJECT FROM)]".as_slice(),
            ),
            (
                b"A1 FETCH 1 BODY.PEEK[HEADER.FIELDS (TO)]\r\n",
                b"BODY.PEEK[HEADER.FIELDS (TO)]",
            ),
            (
                b"A1 FETCH 1 BODY[HEADER.FIELDS (SUBJECT)]\r\n",
                b"BODY[HEADER.FIELDS (SUBJECT)]",
            ),
            (b"A1 FETCH 1 BODY[TEXT]\r\n", b"BODY[TEXT]"),
            (b"A1 FETCH 1 BODY[HEADER]\r\n", b"BODY[HEADER]"),
            (b"A1 FETCH 1 BODYSTRUCTURE\r\n", b"BODYSTRUCTURE"),
        ] {
            let (rem, msg) = parse_command(input).unwrap();
            assert!(rem.is_empty(), "unconsumed input for {input:?}");
            match msg.message {
                ImapMessageType::Command { arguments, .. } => {
                    assert_eq!(arguments, [b"1".to_vec(), expected.to_vec()]);
                }
                _ => panic!("Expected Command"),
            }
        }
    }

    #[test]
    fn test_parse_fetch_section_argument_streaming() {
        for input in [
            b"A1 FETCH 1 BODY[]<0.128>\r\n".as_slice(),
            b"A1 FETCH 1 BODY[HEADER.FIELDS (SUBJECT FROM)]<0.128>\r\n",
            b"A1 UID FETCH 1 body.peek[header.fields.not (subject)]<123.456>\r\n",
            b"A1 FETCH 1 BODY[TEXT]\r\n",
            b"A1 FETCH 1 BODYSTRUCTURE\r\n",
        ] {
            assert_incomplete_at_each_boundary(input, parse_command);
            let mut commands = input.to_vec();
            commands.extend_from_slice(b"A2 NOOP\r\n");
            let (rem, msg) = parse_command(&commands).unwrap();
            assert_eq!(msg.raw_line, &input[..input.len() - 2]);
            assert_eq!(rem, b"A2 NOOP\r\n");
        }
    }

    #[test]
    fn test_parse_body_prefix_as_ordinary_argument() {
        for (input, expected) in [
            (
                b"A1 SELECT BODY[Archive]suffix\r\n".as_slice(),
                b"BODY[Archive]suffix".as_slice(),
            ),
            (b"A1 SELECT BODY[Archive\r\n", b"BODY[Archive"),
            (
                b"A1 CREATE body.peek[TEXT]suffix\r\n",
                b"body.peek[TEXT]suffix",
            ),
            (b"A1 CREATE BODY[]<0.\r\n", b"BODY[]<0."),
            (b"A1 LOGIN user BODY[password\r\n", b"BODY[password"),
            (b"A1 UID COPY 1 BODY[Archive\r\n", b"BODY[Archive"),
            (
                b"A1 SEARCH BODY BODY[Archive]suffix\r\n",
                b"BODY[Archive]suffix",
            ),
        ] {
            assert_incomplete_at_each_boundary(input, parse_command);
            let mut commands = input.to_vec();
            commands.extend_from_slice(b"A2 FETCH 1 BODY[TEXT]\r\n");
            let (rem, msg) = parse_command(&commands).unwrap();
            assert_eq!(rem, b"A2 FETCH 1 BODY[TEXT]\r\n");
            let ImapMessageType::Command {
                arguments, literal, ..
            } = msg.message
            else {
                panic!("Expected Command");
            };
            assert_eq!(arguments.last().unwrap(), expected);
            assert_eq!(literal, None);
        }
        for input in [b" BODY[Archive\r\n".as_slice(), b" BODY[Archive]suffix\r\n"] {
            assert_incomplete_at_each_boundary(input, |i| parse_command_continuation(i, 0));
            let (rem, (msg, literal)) = parse_command_continuation(input, 0).unwrap();
            assert!(rem.is_empty());
            assert_eq!(msg.raw_line, &input[1..input.len() - 2]);
            assert_eq!(literal, None);
        }
    }

    #[test]
    fn test_parse_fetch_section_argument_malformed() {
        let input = b"A1 FETCH 1 BODY[HEADER.FIELDS (SUBJECT\r\nA2 NOOP\r\n";
        assert!(matches!(parse_command(input), Err(Err::Error(_))));
    }

    #[test]
    fn test_parse_login_quoted_args() {
        let i = b"A001 LOGIN \"user name\" \"pass word\"\r\n";
        let (rem, msg) = parse_command(i).unwrap();
        assert!(rem.is_empty());
        match msg.message {
            ImapMessageType::Command {
                command, arguments, ..
            } => {
                assert_eq!(command, ImapCommand::Login);
                assert_eq!(arguments.len(), 2);
                assert_eq!(arguments[0], b"user name".to_vec());
                assert_eq!(arguments[1], b"pass word".to_vec());
            }
            _ => panic!("Expected Command"),
        }
    }

    #[test]
    fn test_parse_quoted_args_with_escapes() {
        let i = b"A001 LOGIN \"user\\\"name\" \"pa\\\\ss\"\r\n";
        let (rem, msg) = parse_command(i).unwrap();
        assert!(rem.is_empty());
        assert_eq!(msg.raw_line, &i[..i.len() - 2]);
        match msg.message {
            ImapMessageType::Command {
                command, arguments, ..
            } => {
                assert_eq!(command, ImapCommand::Login);
                assert_eq!(arguments, [b"user\"name".to_vec(), b"pa\\ss".to_vec()]);
            }
            _ => panic!("Expected Command"),
        }
    }

    #[test]
    fn test_parse_quoted_string_validation() {
        assert_eq!(
            parse_quoted_string(b"\"\"", IMAP_MAX_LINE_SIZE),
            Ok((b"".as_slice(), Vec::new()))
        );
        assert_eq!(
            parse_quoted_string(b"\"any\\escape\"", IMAP_MAX_LINE_SIZE),
            Ok((b"".as_slice(), b"anyescape".to_vec()))
        );
        assert!(matches!(
            parse_quoted_string(b"\"bad\\\0escape\"", IMAP_MAX_LINE_SIZE),
            Err(Err::Error(_))
        ));
        assert!(matches!(
            parse_quoted_string(b"\"bad\0value\"", IMAP_MAX_LINE_SIZE),
            Err(Err::Error(_))
        ));
        assert!(matches!(
            parse_quoted_string(b"\"bad\r\n", IMAP_MAX_LINE_SIZE),
            Err(Err::Error(_))
        ));
        assert!(matches!(
            parse_quoted_string(b"\"unfinished\\", IMAP_MAX_LINE_SIZE),
            Err(Err::Incomplete(_))
        ));
    }

    #[test]
    fn test_parse_list_ignores_quoted_parentheses() {
        let i = b"A001 ID (\"name\" \"value ) ( \\\"quoted\\\" \\\\folder\")\r\n";
        assert_incomplete_at_each_boundary(i, parse_command);
        let (rem, msg) = parse_command(i).unwrap();
        assert!(rem.is_empty());
        match msg.message {
            ImapMessageType::Command {
                command, arguments, ..
            } => {
                assert_eq!(command, ImapCommand::Id);
                assert_eq!(
                    arguments,
                    [b"(\"name\" \"value ) ( \\\"quoted\\\" \\\\folder\")".to_vec()]
                );
            }
            _ => panic!("Expected Command"),
        }
    }

    #[test]
    fn test_literal_info_consume_chunk_boundaries() {
        let cases: &[(u64, &[u8], usize)] = &[
            (0, b"", 0),
            (0, b"next", 0),
            (4, b"", 0),
            (4, b"ab", 2),
            (4, b"abcd", 4),
            (4, b"abcdnext", 4),
        ];
        for &(size, input, expected) in cases {
            for split in 0..=input.len() {
                let mut literal = LiteralInfo::new(size, false);
                let mut total = 0;
                for (chunk, consumed) in [
                    (&input[..split], split.min(expected)),
                    (&input[split..], expected.saturating_sub(split)),
                ] {
                    assert_eq!(literal.consume_chunk(chunk), consumed);
                    total += consumed;
                    assert_eq!(literal.bytes_consumed, total as u64);
                    assert_eq!(literal.remaining(), size - total as u64);
                }
            }
        }
    }

    #[test]
    fn test_literal_info_consume_gap() {
        let mut literal = LiteralInfo::new(10, false);
        assert_eq!(literal.consume_chunk(b"abc"), 3);
        // A gap past the end of the literal consumes nothing.
        assert!(!literal.consume_gap(8));
        assert_eq!(literal.remaining(), 7);
        assert_eq!(literal.size_since_gap(), 10);
        assert!(literal.consume_gap(4));
        assert_eq!(literal.remaining(), 3);
        assert_eq!(literal.size_since_gap(), 3);
        assert!(literal.consume_gap(3));
        assert_eq!(literal.remaining(), 0);
        assert!(literal.consume_gap(0));
        assert!(!literal.consume_gap(1));
    }

    #[test]
    fn test_command_quoted_literal_lookalikes() {
        for input in [
            b"A1 CREATE INBOX\r\n".as_slice(),
            b"A1 CREATE \"{3}\"\r\n",
            b"A1 CREATE \"{3+}\"\r\n",
            b"A1 SEARCH (SUBJECT \"{3}\")\r\n",
            b"A1 SEARCH (SUBJECT \"{3+}\")\r\n",
        ] {
            assert_incomplete_at_each_boundary(input, parse_command);
            let (rem, msg) = parse_command(input).unwrap();
            assert!(rem.is_empty());
            assert!(matches!(
                msg.message,
                ImapMessageType::Command { literal: None, .. }
            ));
        }
    }

    #[test]
    fn test_command_parenthesized_literals() {
        for (input, size, is_literal_plus, depth) in [
            (
                b"A1 SEARCH (SUBJECT {3}\r\nfoo)\r\nA2 NOOP\r\n".as_slice(),
                3,
                false,
                1,
            ),
            (
                b"A1 SEARCH ((SUBJECT {4+}\r\n)(\r\n)) UNSEEN\r\nA2 NOOP\r\n",
                4,
                true,
                2,
            ),
            (b"A1 SEARCH (SUBJECT {0+}\r\n)\r\nA2 NOOP\r\n", 0, true, 1),
        ] {
            let (rem, msg) = parse_command(input).unwrap();
            let syntax_len = input.len() - rem.len();
            assert_incomplete_at_each_boundary(&input[..syntax_len], parse_command);
            let ImapMessageType::Command {
                command, literal, ..
            } = msg.message
            else {
                panic!("Expected Command");
            };
            assert_eq!(command, ImapCommand::Search);
            assert_eq!(
                literal,
                Some(CommandLiteral {
                    size,
                    is_literal_plus,
                    parenthesis_depth: depth,
                })
            );

            for split in 0..=size as usize {
                let mut data = LiteralInfo::new(size, is_literal_plus);
                assert_eq!(data.consume_chunk(&rem[..split]), split);
                assert_eq!(data.consume_chunk(&rem[split..]), size as usize - split);
                assert_eq!(data.remaining(), 0);
                let (next, (_, literal)) =
                    parse_command_continuation(&rem[size as usize..], depth).unwrap();
                assert_eq!(literal, None);
                assert_eq!(next, b"A2 NOOP\r\n");
                assert!(parse_command(next).unwrap().0.is_empty());
            }
        }
    }

    #[test]
    fn test_command_nested_literal_continuations() {
        for input in [b" BODY {0}\r\n".as_slice(), b") (TEXT {2+}\r\n"] {
            assert_incomplete_at_each_boundary(input, |i| parse_command_continuation(i, 2));
            let (rem, (_, literal)) = parse_command_continuation(input, 2).unwrap();
            assert!(rem.is_empty());
            assert_eq!(literal.unwrap().parenthesis_depth, 2);
        }
        let input = b")) UNSEEN\r\n";
        assert_incomplete_at_each_boundary(input, |i| parse_command_continuation(i, 2));
        let (rem, (msg, literal)) = parse_command_continuation(input, 2).unwrap();
        assert!(rem.is_empty());
        assert_eq!(msg.raw_line, b")) UNSEEN");
        assert_eq!(literal, None);
    }

    #[test]
    fn test_command_continuation_quoted_literal_lookalikes() {
        for (input, depth) in [
            (b" \"{5+}\"\r\n".as_slice(), 0),
            (b" \"{5}\"\r\n", 0),
            (b" SUBJECT \"{5+}\")\r\n", 1),
            (b") (SUBJECT \"{5}\")\r\n", 1),
        ] {
            for end in 0..input.len() {
                assert!(matches!(
                    parse_command_continuation(&input[..end], depth),
                    Err(Err::Incomplete(_))
                ));
            }
            let (rem, (_, literal)) = parse_command_continuation(input, depth).unwrap();
            assert!(rem.is_empty());
            assert_eq!(literal, None);
        }
    }

    #[test]
    fn test_command_list_literal_malformed() {
        for input in [
            b"A1 SEARCH (SUBJECT foo\r\n".as_slice(),
            b"A1 SEARCH (SUBJECT foo{3}\r\n",
            b"A1 SEARCH (SUBJECT {x}\r\n",
            b"A1 SEARCH (SUBJECT {3+} extra\r\n",
            b"A1 SEARCH (SUBJECT \"{3}\r\n",
            b"A1 SEARCH (SUBJECT \"bad\\\0escape\" {3}\r\n",
            b"A1 SEARCH (SUBJECT foo))\r\n",
            b"A1 CREATE {3} foo\r\n",
        ] {
            assert!(
                matches!(parse_command(input), Err(Err::Error(_))),
                "{input:?}"
            );
        }
        for input in [
            b"\r\n".as_slice(),
            b"))\r\n",
            b"foo)\r\n",
            b" {x}\r\n",
            b" \"{3}\r\n",
        ] {
            assert!(
                matches!(parse_command_continuation(input, 1), Err(Err::Error(_))),
                "{input:?}"
            );
        }
    }

    #[test]
    fn test_bare_lf_line_end() {
        let (rem, msg) = parse_command(b"A1 LOGIN user pass\nA2 SEARCH TEXT {3+}\n").unwrap();
        assert_eq!(msg.raw_line, b"A1 LOGIN user pass");
        let (rem, msg) = parse_command(rem).unwrap();
        assert_eq!(rem, b"");
        assert_eq!(msg.raw_line, b"A2 SEARCH TEXT {3+}");
        assert!(matches!(
            msg.message,
            ImapMessageType::Command {
                literal: Some(_),
                ..
            }
        ));

        let (rem, (msg, _)) = parse_command_continuation(b" pass\n", 0).unwrap();
        assert_eq!(rem, b"");
        assert_eq!(msg.raw_line, b"pass");

        for input in [b"* 3 EXISTS\n".as_slice(), b"+ Ready\n", b"A1 OK done\n"] {
            let (rem, msg) = parse_response(input).unwrap();
            assert_eq!(rem, b"");
            assert_eq!(msg.raw_line, &input[..input.len() - 1]);
        }
        let (rem, msg) = parse_continuation_data(b"DONE\n").unwrap();
        assert_eq!(rem, b"");
        assert_eq!(msg.raw_line, b"DONE");
        assert_eq!(
            parse_response_continuation(b")\n"),
            Ok((&b""[..], (&b")"[..], None)))
        );

        // a bare CR is no line end
        assert!(matches!(
            parse_command(b"A1 NOOP\rA2 NOOP\r\n"),
            Err(Err::Error(_))
        ));
    }

    #[test]
    fn test_non_sync_literal_capability() {
        for (line, expected) in [
            (
                b"* CAPABILITY IMAP4rev1 LITERAL+ IDLE\r\n".as_slice(),
                Some(true),
            ),
            (b"* CAPABILITY IMAP4rev1 literal- IDLE\r\n", Some(true)),
            (b"* CAPABILITY IMAP4rev1 IDLE\r\n", Some(false)),
            (
                b"* OK [CAPABILITY IMAP4rev1 LITERAL+] ready\r\n",
                Some(true),
            ),
            (
                b"A1 OK [CAPABILITY IMAP4rev1 IDLE] Logged in\r\n",
                Some(false),
            ),
            (b"* OK ready, LITERAL+ is nice\r\n", None),
            (b"A1 OK [READ-WRITE] done\r\n", None),
            // not a status response: the text is no response code
            (
                b"* 1 FETCH (ENVELOPE (\"[CAPABILITY IMAP4rev1]\"))\r\n",
                None,
            ),
            (b"+ [CAPABILITY IMAP4rev1]\r\n", None),
        ] {
            let (_, response) = parse_response(line).unwrap();
            assert_eq!(non_sync_literal_capability(&response), expected, "{line:?}");
        }
    }

    #[test]
    fn test_command_trailing_whitespace() {
        let (rem, msg) = parse_command(b"A1 LOGIN user pass \r\nA2 NOOP  \r\n").unwrap();
        assert_eq!(msg.raw_line, b"A1 LOGIN user pass ");
        let ImapMessageType::Command {
            command, arguments, ..
        } = msg.message
        else {
            panic!("Expected Command");
        };
        assert_eq!(command, ImapCommand::Login);
        assert_eq!(arguments, vec![b"user".to_vec(), b"pass".to_vec()]);

        let (rem, msg) = parse_command(rem).unwrap();
        assert_eq!(rem, b"");
        assert_eq!(msg.raw_line, b"A2 NOOP  ");

        let (rem, (msg, literal)) =
            parse_command_continuation(b" pass \r\nA2 NOOP\r\n", 0).unwrap();
        assert_eq!(rem, b"A2 NOOP\r\n");
        assert_eq!(msg.raw_line, b"pass ");
        assert_eq!(literal, None);

        assert!(matches!(
            parse_command(b"A1 NOOP "),
            Err(Err::Incomplete(_))
        ));
        assert!(matches!(
            parse_command(b"A1 LOGIN {4+} \r\n"),
            Err(Err::Error(_))
        ));
    }

    #[test]
    fn test_parse_command_continuation_caps_raw_line() {
        for size in [
            IMAP_MAX_LINE_SIZE - 1,
            IMAP_MAX_LINE_SIZE,
            IMAP_MAX_LINE_SIZE + 1,
        ] {
            let mut input = b"   ".to_vec();
            input.resize(input.len() + size, b'x');
            input.extend_from_slice(b"\r\nA2 NOOP\r\n");
            let (rem, (msg, literal)) = parse_command_continuation(&input, 0).unwrap();
            assert_eq!(rem, b"A2 NOOP\r\n");
            assert_eq!(msg.raw_line, vec![b'x'; size.min(IMAP_MAX_LINE_SIZE)]);
            assert_eq!(msg.line_truncated, size > IMAP_MAX_LINE_SIZE);
            assert_eq!(literal, None);
        }
    }

    #[test]
    fn test_parse_command_continuation_literal_beyond_raw_line_limit() {
        let mut input = b" ".to_vec();
        input.resize(input.len() + IMAP_MAX_LINE_SIZE + 1, b'x');
        input.extend_from_slice(b" {4+}\r\ndata\r\nA2 NOOP\r\n");
        let (rem, (msg, literal)) = parse_command_continuation(&input, 0).unwrap();
        assert_eq!(rem, b"data\r\nA2 NOOP\r\n");
        assert_eq!(msg.raw_line, vec![b'x'; IMAP_MAX_LINE_SIZE]);
        assert!(msg.line_truncated);
        assert_eq!(
            literal,
            Some(CommandLiteral {
                size: 4,
                is_literal_plus: true,
                parenthesis_depth: 0,
            })
        );
    }

    #[test]
    fn test_parse_response_continuation_incomplete_at_each_boundary() {
        for input in [
            b"\r\n".as_slice(),
            b" (MESSAGES 1)\r\n".as_slice(),
            b" {6}\r\n".as_slice(),
        ] {
            assert_incomplete_at_each_boundary(input, |i| {
                parse_response_continuation(i).map(|(rem, (_, literal))| (rem, literal))
            });
        }
    }

    #[test]
    fn test_parse_response_continuation_malformed() {
        assert!(matches!(
            parse_response_continuation(b" a\rb\r\n"),
            Err(Err::Error(_))
        ));
    }

    #[test]
    fn test_parse_fetch_single_star() {
        let i = b"A005 FETCH * FLAGS\r\n";
        let (rem, msg) = parse_command(i).unwrap();
        assert!(rem.is_empty());
        match msg.message {
            ImapMessageType::Command {
                command, arguments, ..
            } => {
                assert_eq!(command, ImapCommand::Fetch);
                assert_eq!(arguments[0], b"*".to_vec());
                assert_eq!(arguments[1], b"FLAGS".to_vec());
            }
            _ => panic!("Expected Command"),
        }
    }

    #[test]
    fn test_sequence_set() {
        let set = SequenceSet::parse(b"5,1:3,9:7").unwrap();
        for (number, expected) in [
            (1, true),
            (3, true),
            (4, false),
            (5, true),
            (6, false),
            (8, true),
            (10, false),
        ] {
            assert_eq!(set.contains(number), Some(expected), "{number}");
        }

        // `*` depends on the mailbox size, so only a number covered by `n:*`
        // is known to be included.
        let set = SequenceSet::parse(b"2,10:*").unwrap();
        assert_eq!(set.contains(2), Some(true));
        assert_eq!(set.contains(12), Some(true));
        assert_eq!(set.contains(5), None);
        assert_eq!(SequenceSet::parse(b"*:4").unwrap().contains(4), Some(true));
        assert_eq!(SequenceSet::parse(b"1,*").unwrap().contains(1), Some(true));
        assert_eq!(SequenceSet::parse(b"1,*").unwrap().contains(2), None);
        assert_eq!(SequenceSet::parse(b"*:*").unwrap().contains(1), None);

        for invalid in [&b""[..], b"0", b"1,,2", b"1:2:3", b"1:", b"a"] {
            assert!(SequenceSet::parse(invalid).is_none());
        }

        // Repeated and adjacent items merge, so only distinct ranges count
        // towards the limit.
        let repeated = [b"1,".repeat(4000), b"2:3".to_vec()].concat();
        assert_eq!(SequenceSet::parse(&repeated).unwrap().ranges, vec![(1, 3)]);
        let disjoint = |count: usize| {
            (0..count)
                .map(|i| (2 * i + 1).to_string())
                .collect::<Vec<_>>()
                .join(",")
        };
        let set = SequenceSet::parse(disjoint(IMAP_MAX_SEQUENCE_RANGES).as_bytes()).unwrap();
        assert_eq!(
            set.contains(2 * IMAP_MAX_SEQUENCE_RANGES as u32 - 1),
            Some(true)
        );
        assert!(SequenceSet::parse(disjoint(IMAP_MAX_SEQUENCE_RANGES + 1).as_bytes()).is_none());
    }

    #[test]
    fn test_parse_list_wildcard_arguments() {
        for (input, expected) in [
            (
                b"A1 LIST \"\" %\r\n".as_slice(),
                vec![b"".to_vec(), b"%".to_vec()],
            ),
            (
                b"A2 LIST \"\" Arch%\r\n",
                vec![b"".to_vec(), b"Arch%".to_vec()],
            ),
            (
                b"A3 LSUB \"\" *foo\r\n",
                vec![b"".to_vec(), b"*foo".to_vec()],
            ),
            (
                b"A4 LIST INBOX INBOX/*\r\n",
                vec![b"INBOX".to_vec(), b"INBOX/*".to_vec()],
            ),
            (
                b"A5 FETCH 1:* (FLAGS)\r\n",
                vec![b"1:*".to_vec(), b"(FLAGS)".to_vec()],
            ),
            (
                b"A6 UID FETCH 2,4:6 FLAGS\r\n",
                vec![b"FETCH".to_vec(), b"2,4:6".to_vec(), b"FLAGS".to_vec()],
            ),
        ] {
            let (rem, msg) = parse_command(input).unwrap();
            assert!(rem.is_empty());
            match msg.message {
                ImapMessageType::Command { arguments, .. } => assert_eq!(arguments, expected),
                _ => panic!("Expected Command"),
            }
        }
    }

    #[test]
    fn test_parse_fetch_no_literal_still_works() {
        let i = b"* 1 FETCH (UID 1 FLAGS (\\Seen))\r\n";
        let (rem, msg) = parse_response(i).unwrap();
        assert!(rem.is_empty());
        assert_eq!(msg.raw_line, b"* 1 FETCH (UID 1 FLAGS (\\Seen))".to_vec());
        match msg.message {
            ImapMessageType::Untagged {
                seq_number,
                keyword,
            } => {
                assert_eq!(seq_number, Some(1));
                assert_eq!(keyword, b"FETCH".to_vec());
            }
            _ => panic!("Expected Untagged"),
        }

        let (_, msg) = parse_response(b"* 99999999999 FETCH (FLAGS ())\r\n").unwrap();
        assert!(matches!(
            msg.message,
            ImapMessageType::Untagged {
                seq_number: None,
                ..
            }
        ));
    }

    #[test]
    fn test_command_literal8() {
        for (input, is_literal_plus, depth) in [
            (&b"A1 APPEND INBOX ~{5}\r\n"[..], false, 0),
            (b"A1 APPEND INBOX UTF8 (~{5+}\r\n", true, 1),
        ] {
            let (rem, msg) = parse_command(input).unwrap();
            assert!(rem.is_empty());
            let ImapMessageType::Command {
                literal: Some(literal),
                ..
            } = msg.message
            else {
                panic!("Expected a literal");
            };
            assert_eq!(literal.size, 5);
            assert_eq!(literal.is_literal_plus, is_literal_plus);
            assert_eq!(literal.parenthesis_depth, depth);
        }
        // A `~` that starts no literal remains part of an atom.
        assert!(parse_command(b"A1 SEARCH ~x\r\n").is_ok());
    }

    #[test]
    fn test_detect_trailing_literal() {
        assert_eq!(
            detect_trailing_literal(b"BODY[] {100}"),
            Some((b"BODY[] ".as_slice(), (100, false)))
        );
        assert_eq!(
            detect_trailing_literal(b"{50+}"),
            Some((b"".as_slice(), (50, true)))
        );
        assert_eq!(detect_trailing_literal(b"no literal here"), None);
        assert_eq!(detect_trailing_literal(b"middle {10} stuff"), None);
    }

    #[test]
    fn test_untagged_trailing_literal() {
        assert_eq!(
            untagged_trailing_literal(b"LIST", b"* LIST () \"/\" {5}"),
            Some(5)
        );
        assert_eq!(
            untagged_trailing_literal(b"list", b"* list () \"/\" {5}"),
            Some(5)
        );
        assert_eq!(untagged_trailing_literal(b"ID", b"* ID ({4}"), Some(4));
        assert_eq!(
            untagged_trailing_literal(b"STATUS", b"* STATUS INBOX (MESSAGES 1)"),
            None
        );
        assert_eq!(
            untagged_trailing_literal(b"LIST", b"* LIST () \"/\" \"{5}\""),
            None
        );
        assert_eq!(untagged_trailing_literal(b"EXISTS", b"* 12 EXISTS"), None);
        for status in [b"OK".as_slice(), b"ok", b"NO", b"BAD", b"BYE", b"PREAUTH"] {
            assert_eq!(untagged_trailing_literal(status, b"* OK done {3}"), None);
        }
    }

    #[test]
    fn test_parse_body_section() {
        for input in [
            b"BODY[]<1024>".as_slice(),
            b"BODY[HEADER]<50>",
            b"BODY[]<0.512>",
            b"BODY[]",
            b"BODY.PEEK[]",
            b"BODY[1.2]",
            b"BODY[TEXT]",
            b"body.peek[header.fields (subject)]",
        ] {
            let (rem, _) = parse_body_section(input).unwrap();
            assert!(rem.is_empty(), "unconsumed input for {input:?}");
        }
    }

    #[test]
    fn test_parse_untagged_response_stops_at_literal_specifier() {
        for (input, keyword, raw_line, rem_expected) in [
            (
                b"* LIST () \"/\" {5}\r\nINBOX\r\n".as_slice(),
                b"LIST".as_slice(),
                b"* LIST () \"/\" {5}".as_slice(),
                b"INBOX\r\n".as_slice(),
            ),
            (
                b"* 2 FETCH (BODY[] {10}\r\nHelloWorld)\r\n",
                b"FETCH",
                b"* 2 FETCH (BODY[] {10}",
                b"HelloWorld)\r\n",
            ),
        ] {
            let (rem, msg) = parse_response(input).unwrap();
            assert_eq!(rem, rem_expected);
            assert_eq!(msg.raw_line, raw_line);
            assert!(matches!(
                msg.message,
                ImapMessageType::Untagged { keyword: ref kw, .. } if kw == keyword
            ));
        }
    }
}
