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
use nom8::bytes::streaming::{tag, tag_no_case, take_till, take_while, take_while1};
use nom8::character::complete::{char as complete_char, u32 as complete_u32};
use nom8::character::streaming::{char, crlf, space0, space1, u64 as streaming_u64};
use nom8::combinator::{all_consuming, complete, map, opt, value, verify};
use nom8::error::{Error, ErrorKind};
use nom8::sequence::{delimited, preceded};
use nom8::{Err, IResult, Needed, Parser};
use std::borrow::Cow;
use std::fmt;

pub const IMAP_MAX_BODY_SIZE: usize = 10 * 1024 * 1024;
pub const IMAP_MAX_HEADERS: usize = 512;
pub const IMAP_MAX_LINE_SIZE: usize = 8 * 1024;
const IMAP_MAX_ARGUMENTS: usize = IMAP_MAX_LINE_SIZE / 2;
const IMAP_MAX_LITERAL_SIZE: u64 = i64::MAX as u64;

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
];

impl fmt::Display for ImapCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let ImapCommand::Unknown(bytes) = self {
            return write!(f, "{}", String::from_utf8_lossy(bytes));
        }
        let name = COMMANDS
            .iter()
            .find(|(_, command)| command == self)
            .map_or("", |(name, _)| name);
        f.write_str(name)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImapResponseStatus {
    Ok,
    No,
    Bad,
    PreAuth,
    Bye,
}

impl fmt::Display for ImapResponseStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ImapResponseStatus::Ok => write!(f, "OK"),
            ImapResponseStatus::No => write!(f, "NO"),
            ImapResponseStatus::Bad => write!(f, "BAD"),
            ImapResponseStatus::PreAuth => write!(f, "PREAUTH"),
            ImapResponseStatus::Bye => write!(f, "BYE"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct EmailHeader {
    pub data: Vec<u8>,
    name_len: usize,
}

impl EmailHeader {
    fn new(name: &[u8], value: &[u8]) -> Self {
        let mut data = Vec::with_capacity(name.len() + 2 + value.len());
        data.extend_from_slice(name);
        data.extend_from_slice(b": ");
        data.extend_from_slice(value);
        Self {
            data,
            name_len: name.len(),
        }
    }

    pub fn name(&self) -> &[u8] {
        &self.data[..self.name_len]
    }

    pub fn value(&self) -> &[u8] {
        &self.data[self.name_len + 2..]
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct EmailData {
    pub headers: Vec<EmailHeader>,
    pub headers_len: u32,
    pub body_offset: u32,
    pub email_body: Vec<u8>,
    pub too_many_headers: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchBodySection {
    Full,
    Header,
    Text,
    Other,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct FetchData {
    pub email: Option<EmailData>,
    pub body_too_large: bool,
    pub data_limit_reached: bool,
}

#[derive(Debug, Clone)]
pub struct LiteralInfo {
    pub size: u64,
    pub is_literal_plus: bool,
    pub bytes_consumed: u64,
    pub buffer: Vec<u8>,
    pub truncated: bool,
    pub retain_limit: usize,
}

impl LiteralInfo {
    pub fn new(size: u64, is_literal_plus: bool, retain_limit: usize) -> Self {
        let capacity = usize::try_from(size)
            .unwrap_or(usize::MAX)
            .min(retain_limit);
        let retain_limit_u64 = u64::try_from(retain_limit).unwrap_or(u64::MAX);
        Self {
            size,
            is_literal_plus,
            bytes_consumed: 0,
            buffer: Vec::with_capacity(capacity),
            truncated: size > retain_limit_u64,
            retain_limit,
        }
    }

    pub fn remaining(&self) -> u64 {
        self.size.saturating_sub(self.bytes_consumed)
    }

    pub fn consume_chunk(&mut self, chunk: &[u8]) -> usize {
        let consumed = match usize::try_from(self.remaining()) {
            Ok(remaining) => std::cmp::min(chunk.len(), remaining),
            Err(_) => chunk.len(),
        };
        let chunk = &chunk[..consumed];
        let retain_left = self.retain_limit.saturating_sub(self.buffer.len());
        let retain_len = std::cmp::min(chunk.len(), retain_left);

        if retain_len > 0 {
            self.buffer.extend_from_slice(&chunk[..retain_len]);
        }
        if retain_len < chunk.len() {
            self.truncated = true;
        }

        self.bytes_consumed = self
            .bytes_consumed
            .saturating_add(u64::try_from(consumed).unwrap_or(u64::MAX));
        consumed
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
        fetch_data: Option<FetchData>,
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

impl ImapMessage {
    pub fn tag_str(&self) -> Cow<'_, str> {
        self.tag
            .as_deref()
            .map(String::from_utf8_lossy)
            .unwrap_or_default()
    }
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
    if i.iter()
        .take(IMAP_MAX_LINE_SIZE + 1)
        .take_while(|&&b| is_tag_char(b))
        .count()
        > IMAP_MAX_LINE_SIZE
    {
        return Err(Err::Failure(Error::new(i, ErrorKind::TooLarge)));
    }
    take_while1(is_tag_char).parse(i)
}

fn parse_command_keyword(i: &[u8]) -> IResult<&[u8], ImapCommand> {
    let (i, cmd) = parse_atom(i)?;
    let command = COMMANDS
        .iter()
        .find(|(name, _)| cmd.eq_ignore_ascii_case(name.as_bytes()))
        .map_or_else(
            || ImapCommand::Unknown(cmd[..cmd.len().min(IMAP_MAX_LINE_SIZE)].to_vec()),
            |(_, command)| command.clone(),
        );
    Ok((i, command))
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
                if escaped != b'"' && escaped != b'\\' {
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
    saw_open: bool,
}

impl ParenthesisScanner {
    fn scan(&mut self, i: &[u8]) -> Result<Option<usize>, ErrorKind> {
        for (pos, &b) in i.iter().enumerate() {
            if self.in_quoted {
                if self.escaped {
                    if b != b'"' && b != b'\\' {
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
                    self.saw_open = true;
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
                b'\r' | b'\n' => return Err(ErrorKind::Char),
                _ => {}
            }
        }
        Ok(None)
    }

    fn quote_is_closed(&self) -> bool {
        !self.in_quoted && !self.escaped
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
    let line_end = i.iter().position(|&b| is_line_ending(b)).unwrap_or(i.len());
    if let Some(pos) = scanner
        .scan(&i[..line_end])
        .map_err(|kind| Err::Error(Error::new(i, kind)))?
    {
        return Ok((
            &i[pos + 1..],
            (i[..(pos + 1).min(retain_limit)].to_vec(), None),
        ));
    }
    if line_end == i.len() {
        return Err(Err::Incomplete(Needed::new(1)));
    }
    let line = &i[..line_end];
    if scanner.quote_is_closed() {
        if let Some((prefix, (size, is_literal_plus))) = detect_trailing_literal(line) {
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
    }
    Err(Err::Error(Error::new(i, ErrorKind::Char)))
}

fn parse_literal_as_argument(
    i: &[u8], retain_limit: usize,
) -> IResult<&[u8], (Vec<u8>, Option<CommandLiteral>)> {
    let start = i;
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

pub fn sequence_set_contains(set: &[u8], sequence_number: u32) -> Option<bool> {
    let mut has_unknown_item = false;

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

        let item_contains = match (first_val, second_val) {
            (Some(num), None) => Some(sequence_number == num),
            (None, None) => None,
            (Some(first_val), Some(Some(second_val))) => {
                let lower = first_val.min(second_val);
                let upper = first_val.max(second_val);
                Some((lower..=upper).contains(&sequence_number))
            }
            (Some(val), Some(None)) | (None, Some(Some(val))) => {
                if sequence_number >= val {
                    Some(true)
                } else {
                    None
                }
            }
            (None, Some(None)) => None,
        };

        match item_contains {
            Some(true) => return Some(true),
            Some(false) => {}
            None => has_unknown_item = true,
        }
    }

    if has_unknown_item {
        None
    } else {
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
    let (i, _) = crlf.parse(i)?;

    let raw_len = start.len() - i.len() - 2;
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

pub fn parse_response_continuation(i: &[u8]) -> IResult<&[u8], Option<u64>> {
    let (i, rest) = take_till(is_line_ending).parse(i)?;
    let (i, _) = crlf.parse(i)?;
    Ok((i, detect_trailing_literal(rest).map(|(_, (size, _))| size)))
}

fn detect_trailing_literal(line: &[u8]) -> Option<(&[u8], (u64, bool))> {
    let brace_pos = line.iter().rposition(|&c| c == b'{')?;
    match parse_literal_specifier(&line[brace_pos..]) {
        Ok(([], literal)) => Some((&line[..brace_pos], literal)),
        _ => None,
    }
}

pub fn untagged_trailing_literal(keyword: &[u8], line: &[u8]) -> Option<u64> {
    if all_consuming(parse_status).parse(keyword).is_ok() {
        return None;
    }
    detect_trailing_literal(line).map(|(_, (size, _))| size)
}

fn parse_partial_offset(i: &[u8]) -> IResult<&[u8], u64> {
    let (i, _) = complete_char('<').parse(i)?;
    let (i, origin) = complete_u32::<_, Error<_>>(i)?;
    let (i, _) = opt(preceded(complete_char('.'), complete_u32::<_, Error<_>>)).parse(i)?;
    let (i, _) = complete_char('>').parse(i)?;
    Ok((i, u64::from(origin)))
}

fn parse_body_section(i: &[u8]) -> IResult<&[u8], FetchBodySection> {
    let (i, _) = alt((tag_no_case("BODY.PEEK"), tag_no_case("BODY"))).parse(i)?;
    let (i, _) = char('[').parse(i)?;
    let (i, section_name) = take_while(|c: u8| c.is_ascii_alphanumeric() || c == b'.').parse(i)?;
    let (i, _) = take_till(|c| c == b']').parse(i)?;
    let (i, _) = char(']').parse(i)?;
    let (i, partial_offset) = opt(parse_partial_offset).parse(i)?;

    let section = if section_name.is_empty() {
        FetchBodySection::Full
    } else if section_name.eq_ignore_ascii_case(b"TEXT") {
        FetchBodySection::Text
    } else if section_name
        .get(..6)
        .is_some_and(|name| name.eq_ignore_ascii_case(b"HEADER"))
    {
        FetchBodySection::Header
    } else {
        FetchBodySection::Other
    };

    let section = if partial_offset.is_some_and(|origin| origin > 0)
        && matches!(section, FetchBodySection::Full | FetchBodySection::Header)
    {
        FetchBodySection::Text
    } else {
        section
    };

    Ok((i, section))
}

fn rfc822_section(token: &[u8]) -> Option<FetchBodySection> {
    if token.eq_ignore_ascii_case(b"RFC822") {
        Some(FetchBodySection::Full)
    } else if token.eq_ignore_ascii_case(b"RFC822.HEADER") {
        Some(FetchBodySection::Header)
    } else if token.eq_ignore_ascii_case(b"RFC822.TEXT") {
        Some(FetchBodySection::Text)
    } else {
        None
    }
}

fn extract_fetch_section_from_prefix(prefix: &[u8]) -> Option<FetchBodySection> {
    let end = prefix.iter().rposition(|b| !b.is_ascii_whitespace())? + 1;
    let token_start = prefix[..end]
        .iter()
        .rposition(|&b| b.is_ascii_whitespace() || b == b'(')
        .map_or(0, |pos| pos + 1);
    if let Some(section) = rfc822_section(&prefix[token_start..end]) {
        return Some(section);
    }

    let body_pos = prefix
        .windows(4)
        .rposition(|window| window.eq_ignore_ascii_case(b"BODY"))?;

    parse_body_section(&prefix[body_pos..])
        .ok()
        .map(|(_, section)| section)
}

#[derive(Debug)]
struct LiteralContext {
    prefix: Vec<u8>,
    literal_data: Vec<u8>,
}

fn append_capped(buffer: &mut Vec<u8>, data: &[u8], limit: usize) -> bool {
    let retain_len = data.len().min(limit.saturating_sub(buffer.len()));
    buffer.extend_from_slice(&data[..retain_len]);
    retain_len < data.len()
}

fn append_tail_capped(buffer: &mut Vec<u8>, data: &[u8], limit: usize) {
    if data.len() >= limit {
        buffer.clear();
        buffer.extend_from_slice(&data[data.len() - limit..]);
        return;
    }

    let overflow = buffer
        .len()
        .saturating_add(data.len())
        .saturating_sub(limit);
    if overflow > 0 {
        buffer.drain(..overflow);
    }
    buffer.extend_from_slice(data);
}

#[derive(Debug)]
pub enum FetchResponseProgress {
    LiteralStart {
        consumed: usize,
        literal_size: u64,
        section: FetchBodySection,
    },
    Incomplete {
        consumed: usize,
    },
    Complete {
        consumed: usize,
        message: ImapMessage,
    },
}

#[derive(Debug)]
pub struct FetchResponseState {
    seq_number: Option<u32>,
    keyword: Vec<u8>,
    metadata_len: usize,
    current_prefix: Vec<u8>,
    literal_contexts: Vec<LiteralContext>,
    current_literal: Option<(LiteralInfo, Vec<u8>)>,
    parentheses: ParenthesisScanner,
    parentheses_closed: bool,
    literal_retain_left: usize,
    data_limit_reached: bool,
    body_too_large: bool,
    raw_line: Vec<u8>,
    line_truncated: bool,
    first_line: bool,
    saw_cr: bool,
    had_literal: bool,
}

impl FetchResponseState {
    pub fn new(i: &[u8], retain_limit: usize) -> IResult<&[u8], Self> {
        let (rem, (seq_number, keyword)) = parse_untagged_prefix(i)?;
        if !keyword.eq_ignore_ascii_case(b"FETCH") {
            return Err(Err::Error(Error::new(i, ErrorKind::Tag)));
        }

        match rem.first() {
            Some(b' ' | b'\r' | b'\n') => {}
            Some(_) => return Err(Err::Error(Error::new(rem, ErrorKind::Tag))),
            None => return Err(Err::Incomplete(Needed::new(1))),
        }

        let (rem, _) = space0.parse(rem)?;
        let prefix_len = i.len() - rem.len();
        let (raw_line, line_truncated) = cap_raw_line(&i[..prefix_len]);

        Ok((
            rem,
            Self {
                seq_number,
                keyword: keyword.to_vec(),
                metadata_len: 0,
                current_prefix: Vec::new(),
                literal_contexts: Vec::new(),
                current_literal: None,
                parentheses: ParenthesisScanner::default(),
                parentheses_closed: false,
                literal_retain_left: retain_limit,
                data_limit_reached: false,
                body_too_large: false,
                raw_line,
                line_truncated,
                first_line: true,
                saw_cr: false,
                had_literal: false,
            },
        ))
    }

    fn note_metadata(&mut self, fragment: &[u8]) {
        self.metadata_len = self.metadata_len.saturating_add(fragment.len());
        if self.metadata_len > IMAP_MAX_LINE_SIZE {
            self.line_truncated = true;
        }
    }

    fn parse_non_literal_data(&mut self, i: &[u8]) -> Result<(usize, bool), ErrorKind> {
        let mut consumed = 0;

        while consumed < i.len() {
            if self.saw_cr {
                if i[consumed] != b'\n' {
                    return Err(ErrorKind::CrLf);
                }
                self.saw_cr = false;
                consumed += 1;

                if !self.parentheses.quote_is_closed() {
                    return Err(ErrorKind::Char);
                }

                let trailing_literal = detect_trailing_literal(&self.current_prefix)
                    .map(|(prefix, (size, _))| (prefix.len(), size));
                if let Some((prefix_len, literal_size)) = trailing_literal {
                    self.current_prefix.truncate(prefix_len);
                    let literal_prefix = std::mem::take(&mut self.current_prefix);
                    let retain_limit = if self.metadata_len <= IMAP_MAX_LINE_SIZE {
                        self.literal_retain_left
                    } else {
                        0
                    };
                    self.current_literal = Some((
                        LiteralInfo::new(literal_size, false, retain_limit),
                        literal_prefix,
                    ));
                    self.had_literal = true;
                    self.first_line = false;
                    return Ok((consumed, false));
                }

                self.first_line = false;
                if self.parentheses_closed || !self.parentheses.saw_open {
                    return Ok((consumed, true));
                }

                self.note_metadata(b"\r\n");
                append_tail_capped(&mut self.current_prefix, b"\r\n", IMAP_MAX_LINE_SIZE);
                continue;
            }

            let line_end = i[consumed..]
                .iter()
                .position(|&b| is_line_ending(b))
                .map_or(i.len(), |pos| consumed + pos);
            let line_fragment = &i[consumed..line_end];

            if !line_fragment.is_empty() {
                if !self.parentheses_closed && self.parentheses.scan(line_fragment)?.is_some() {
                    self.parentheses_closed = true;
                }
                self.note_metadata(line_fragment);
                append_tail_capped(&mut self.current_prefix, line_fragment, IMAP_MAX_LINE_SIZE);
                if self.first_line
                    && append_capped(&mut self.raw_line, line_fragment, IMAP_MAX_LINE_SIZE)
                {
                    self.line_truncated = true;
                }
                consumed = line_end;
            }

            if consumed == i.len() {
                break;
            }

            match i[consumed] {
                b'\r' => {
                    self.saw_cr = true;
                    consumed += 1;
                }
                b'\n' => return Err(ErrorKind::CrLf),
                _ => return Err(ErrorKind::Char),
            }
        }

        Ok((consumed, false))
    }

    fn finish(&mut self) -> ImapMessage {
        if self.had_literal
            && self.raw_line.len() < IMAP_MAX_LINE_SIZE
            && self.raw_line.last() != Some(&b')')
        {
            self.raw_line.push(b')');
        }

        let literal_contexts = std::mem::take(&mut self.literal_contexts);
        let current_prefix = std::mem::take(&mut self.current_prefix);
        let within_line = self.metadata_len <= IMAP_MAX_LINE_SIZE;
        let mut retain_left = self.literal_retain_left;
        let mut contexts = Vec::with_capacity(literal_contexts.len());
        for ctx in literal_contexts {
            if within_line {
                collect_quoted_body_contexts(&ctx.prefix, &mut contexts, &mut retain_left);
            }
            contexts.push(ctx);
        }
        if within_line {
            collect_quoted_body_contexts(&current_prefix, &mut contexts, &mut retain_left);
        }

        let fetch_data = if self.had_literal || !contexts.is_empty() {
            let mut fetch = parse_fetch_data(contexts);
            fetch.data_limit_reached = self.data_limit_reached;
            fetch.body_too_large = self.body_too_large;
            Some(fetch)
        } else {
            None
        };

        ImapMessage {
            tag: None,
            message: ImapMessageType::Untagged {
                seq_number: self.seq_number,
                keyword: std::mem::take(&mut self.keyword),
                fetch_data,
            },
            raw_line: std::mem::take(&mut self.raw_line),
            line_truncated: self.line_truncated,
        }
    }

    pub fn consume(&mut self, i: &[u8]) -> Result<FetchResponseProgress, ErrorKind> {
        let mut consumed = 0;

        loop {
            if let Some((literal, prefix)) = self.current_literal.as_mut() {
                let literal_consumed = literal.consume_chunk(&i[consumed..]);
                consumed += literal_consumed;
                if literal.remaining() > 0 {
                    return Ok(FetchResponseProgress::Incomplete { consumed });
                }

                self.data_limit_reached |= literal.truncated;
                self.body_too_large |=
                    literal.size > u64::try_from(IMAP_MAX_BODY_SIZE).unwrap_or(u64::MAX);
                if self.metadata_len <= IMAP_MAX_LINE_SIZE {
                    self.literal_retain_left = self
                        .literal_retain_left
                        .saturating_sub(literal.buffer.len());
                    self.literal_contexts.push(LiteralContext {
                        prefix: std::mem::take(prefix),
                        literal_data: std::mem::take(&mut literal.buffer),
                    });
                } else {
                    self.data_limit_reached = true;
                }
                self.current_literal = None;
            }

            if consumed == i.len() {
                return Ok(FetchResponseProgress::Incomplete { consumed });
            }

            let (syntax_consumed, complete) = self.parse_non_literal_data(&i[consumed..])?;
            consumed += syntax_consumed;
            if complete {
                return Ok(FetchResponseProgress::Complete {
                    consumed,
                    message: self.finish(),
                });
            }
            if let Some((literal, prefix)) = &self.current_literal {
                let section =
                    extract_fetch_section_from_prefix(prefix).unwrap_or(FetchBodySection::Other);
                return Ok(FetchResponseProgress::LiteralStart {
                    consumed,
                    literal_size: literal.size,
                    section,
                });
            }
        }
    }
}

pub fn parse_command(i: &[u8]) -> IResult<&[u8], ImapMessage> {
    let start = i;
    let (i, tag_bytes) = parse_tag(i)?;
    let (i, _) = space1.parse(i)?;
    let (i, command) = parse_command_keyword(i)?;
    let (i, (arguments, literal)) = parse_arguments(i, 0, Some(&command))?;
    let (i, _) = crlf.parse(i)?;

    let raw_len = start.len() - i.len() - 2;
    let (raw_line, line_truncated) = cap_raw_line(&start[..raw_len]);

    Ok((
        i,
        ImapMessage {
            tag: Some(tag_bytes.to_vec()),
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
    let (i, _) = crlf.parse(i)?;

    let raw_len = start.len() - i.len() - 2;
    let (raw_line, line_truncated) = cap_raw_line(&start[..raw_len]);

    Ok((
        i,
        ImapMessage {
            tag: Some(tag_bytes.to_vec()),
            message: ImapMessageType::Response { status },
            raw_line,
            line_truncated,
        },
    ))
}

fn parse_quoted_body_value(i: &[u8]) -> IResult<&[u8], (&[u8], Vec<u8>)> {
    let after_spec = if let Ok((rem, _)) = parse_body_section(i) {
        rem
    } else {
        let (rem, atom) = parse_atom(i)?;
        if rfc822_section(atom).is_none() {
            return Err(Err::Error(Error::new(i, ErrorKind::Tag)));
        }
        rem
    };
    let spec = &i[..i.len() - after_spec.len()];
    let (rem, _) = space0.parse(after_spec)?;
    let (rem, value) = parse_quoted_string(rem, IMAP_MAX_LINE_SIZE)?;
    Ok((rem, (spec, value)))
}

fn collect_quoted_body_contexts(
    prefix: &[u8], out: &mut Vec<LiteralContext>, retain_left: &mut usize,
) {
    let mut pos = 0;
    while pos < prefix.len() {
        let at_boundary =
            pos == 0 || prefix[pos - 1].is_ascii_whitespace() || prefix[pos - 1] == b'(';
        if at_boundary {
            if let Ok((rem, (spec, mut value))) = parse_quoted_body_value(&prefix[pos..]) {
                let retain = value.len().min(*retain_left);
                *retain_left -= retain;
                value.truncate(retain);
                out.push(LiteralContext {
                    prefix: prefix[..pos + spec.len()].to_vec(),
                    literal_data: value,
                });
                pos = prefix.len() - rem.len();
                continue;
            }
        }
        pos += 1;
    }
}

fn parse_fetch_data(literal_ctxs: Vec<LiteralContext>) -> FetchData {
    let mut fetch_data = FetchData::default();

    for LiteralContext {
        prefix,
        literal_data,
    } in literal_ctxs
    {
        let section = extract_fetch_section_from_prefix(&prefix).unwrap_or(FetchBodySection::Other);

        let email = match section {
            FetchBodySection::Full => parse_email_content(literal_data),
            FetchBodySection::Header => {
                parse_email_headers(&literal_data)
                    .ok()
                    .map(|(_, parsed_headers)| EmailData {
                        headers: parsed_headers.headers,
                        too_many_headers: parsed_headers.too_many_headers,
                        ..Default::default()
                    })
            }
            FetchBodySection::Text => Some(EmailData {
                email_body: literal_data,
                ..Default::default()
            }),
            FetchBodySection::Other => None,
        };

        let Some(mut email) = email else {
            continue;
        };
        let Some(merged) = fetch_data.email.as_mut() else {
            fetch_data.email = Some(email);
            continue;
        };
        merged.too_many_headers |= email.too_many_headers;
        let room = IMAP_MAX_HEADERS.saturating_sub(merged.headers.len());
        if email.headers.len() > room {
            merged.too_many_headers = true;
            email.headers.truncate(room);
        }
        merged.headers.append(&mut email.headers);
        merged.email_body.append(&mut email.email_body);
    }

    fetch_data
}

fn parse_untagged_prefix(i: &[u8]) -> IResult<&[u8], (Option<u32>, &[u8])> {
    let (i, _) = tag("* ").parse(i)?;
    let (i, first_token) = take_while1(|c: u8| c.is_ascii_alphanumeric()).parse(i)?;

    if first_token.iter().all(|c| c.is_ascii_digit()) {
        let (i, _) = space1.parse(i)?;
        let (i, keyword) = take_while1(|c: u8| c.is_ascii_alphanumeric()).parse(i)?;
        let seq: u32 = std::str::from_utf8(first_token)
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        Ok((i, (Some(seq), keyword)))
    } else {
        Ok((i, (None, first_token)))
    }
}

pub fn peek_untagged(i: &[u8]) -> Option<(Option<u32>, &[u8])> {
    parse_untagged_prefix(i).ok().map(|(_, prefix)| prefix)
}

fn parse_untagged_response(i: &[u8], literal_retain_limit: usize) -> IResult<&[u8], ImapMessage> {
    let start = i;
    let (rem, (seq_number, keyword)) = parse_untagged_prefix(i)?;

    if keyword.eq_ignore_ascii_case(b"FETCH") {
        let (rem, mut state) = FetchResponseState::new(start, literal_retain_limit)?;
        let mut consumed_total = 0;
        loop {
            let current = &rem[consumed_total..];
            match state
                .consume(current)
                .map_err(|kind| Err::Error(Error::new(current, kind)))?
            {
                FetchResponseProgress::LiteralStart { consumed, .. } => {
                    consumed_total = consumed_total.saturating_add(consumed);
                }
                FetchResponseProgress::Incomplete { .. } => {
                    return Err(Err::Incomplete(Needed::new(1)));
                }
                FetchResponseProgress::Complete { consumed, message } => {
                    consumed_total = consumed_total.saturating_add(consumed);
                    return Ok((&rem[consumed_total..], message));
                }
            }
        }
    }

    let (i, _) = space0.parse(rem)?;
    let (i, _) = take_till(is_line_ending).parse(i)?;
    let (i, _) = crlf.parse(i)?;
    let raw_len = start.len() - i.len() - 2;
    let (raw_line, line_truncated) = cap_raw_line(&start[..raw_len]);

    Ok((
        i,
        ImapMessage {
            tag: None,
            message: ImapMessageType::Untagged {
                seq_number,
                keyword: keyword.to_vec(),
                fetch_data: None,
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
    let (i, _) = crlf.parse(i)?;

    let raw_len = start.len() - i.len() - 2;
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
    let (i, _) = crlf.parse(i)?;

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

pub fn parse_response(i: &[u8], literal_retain_limit: usize) -> IResult<&[u8], ImapMessage> {
    alt((
        |input| parse_untagged_response(input, literal_retain_limit),
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

#[inline]
fn is_header_name_char(b: u8) -> bool {
    b.is_ascii_graphic() && b != b':'
}

#[inline]
fn email_hcolon(i: &[u8]) -> IResult<&[u8], char> {
    delimited(space0, char(':'), space0).parse(i)
}

fn parse_header_value(i: &[u8]) -> IResult<&[u8], Vec<u8>> {
    let mut value = Vec::new();
    let mut rem = i;

    loop {
        let (after_line, line) = take_till(is_line_ending).parse(rem)?;
        value.extend_from_slice(line);
        rem = after_line;

        let (after_eol, _) = crlf.parse(rem)?;
        rem = after_eol;

        if matches!(rem.first(), Some(b' ' | b'\t')) {
            value.push(b' ');
            let (after_ws, _) = space0.parse(rem)?;
            rem = after_ws;
        } else {
            break;
        }
    }

    let end = value.trim_ascii_end().len();
    value.truncate(end);
    let start = value.len() - value.trim_ascii_start().len();
    value.drain(..start);
    Ok((rem, value))
}

fn message_header(i: &[u8]) -> IResult<&[u8], EmailHeader> {
    let (i, name) = take_while1(is_header_name_char).parse(i)?;
    let (i, _) = email_hcolon(i)?;
    let (i, value) = parse_header_value(i)?;
    Ok((i, EmailHeader::new(name, &value)))
}

pub struct ParsedEmailHeaders {
    pub headers: Vec<EmailHeader>,
    pub too_many_headers: bool,
}

pub fn parse_email_headers(mut i: &[u8]) -> IResult<&[u8], ParsedEmailHeaders> {
    let mut headers = Vec::new();
    let mut too_many_headers = false;

    loop {
        if i.is_empty() || crlf::<&[u8], Error<&[u8]>>.parse(i).is_ok() {
            break;
        }

        let (rest, header) = message_header(i)?;
        if headers.len() < IMAP_MAX_HEADERS {
            headers.push(header);
        } else {
            too_many_headers = true;
        }
        i = rest;
    }

    Ok((
        i,
        ParsedEmailHeaders {
            headers,
            too_many_headers,
        },
    ))
}

pub fn parse_email_content(mut data: Vec<u8>) -> Option<EmailData> {
    let (rem, parsed_headers) = parse_email_headers(&data).ok()?;
    let headers_len = data.len() - rem.len();
    let (body, _) = crlf::<_, Error<_>>.parse(rem).ok()?;
    let body_offset = data.len() - body.len();

    data.drain(..body_offset);
    data.shrink_to_fit();

    Some(EmailData {
        headers: parsed_headers.headers,
        headers_len: headers_len as u32,
        body_offset: body_offset as u32,
        email_body: data,
        too_many_headers: parsed_headers.too_many_headers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header_values<'a>(headers: &'a [EmailHeader], name: &str) -> Vec<&'a [u8]> {
        headers
            .iter()
            .filter(|header| header.name().eq_ignore_ascii_case(name.as_bytes()))
            .map(EmailHeader::value)
            .collect()
    }

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
            assert_incomplete_at_each_boundary(input, |input| {
                parse_response(input, IMAP_MAX_BODY_SIZE)
            });
        }
    }

    #[test]
    fn test_fetch_literal_incomplete_at_each_boundary() {
        let input = b"* 1 FETCH (BODY[] {8}\r\n\0ab\r\n()z)\r\n";
        assert_incomplete_at_each_boundary(input, |input| {
            parse_response(input, IMAP_MAX_BODY_SIZE)
        });

        let next = b"* 2 EXISTS\r\n";
        let mut pipelined = input.to_vec();
        pipelined.extend_from_slice(next);

        let (rem, msg) = parse_response(&pipelined, IMAP_MAX_BODY_SIZE).unwrap();
        assert_eq!(rem, next);
        match msg.message {
            ImapMessageType::Untagged {
                fetch_data: Some(fetch),
                ..
            } => {
                assert!(fetch.email.is_none());
            }
            _ => panic!("Expected FETCH response"),
        }

        let (rem, _) = parse_response(rem, IMAP_MAX_BODY_SIZE).unwrap();
        assert!(rem.is_empty());
    }

    #[test]
    fn test_fetch_literal_start_progress() {
        for (input, expected_section, expected_size) in [
            (
                b"* 1 FETCH (BODY[] {38}\r\n".as_slice(),
                FetchBodySection::Full,
                38,
            ),
            (
                b"* 1 FETCH (BODY[HEADER] {24}\r\n".as_slice(),
                FetchBodySection::Header,
                24,
            ),
            (
                b"* 1 FETCH (BODY[TEXT] {12}\r\n".as_slice(),
                FetchBodySection::Text,
                12,
            ),
            (
                b"* 1 FETCH (RFC822 {38}\r\n".as_slice(),
                FetchBodySection::Full,
                38,
            ),
            (
                b"* 1 FETCH (RFC822.HEADER {24}\r\n".as_slice(),
                FetchBodySection::Header,
                24,
            ),
            (
                b"* 1 FETCH (RFC822.TEXT {12}\r\n".as_slice(),
                FetchBodySection::Text,
                12,
            ),
        ] {
            let (rem, mut state) = FetchResponseState::new(input, IMAP_MAX_BODY_SIZE).unwrap();
            let progress = state.consume(rem).unwrap();
            match progress {
                FetchResponseProgress::LiteralStart {
                    consumed,
                    literal_size,
                    section,
                } => {
                    assert_eq!(section, expected_section);
                    assert_eq!(literal_size, expected_size);
                    assert!(rem[consumed..].is_empty());
                }
                _ => panic!("Expected literal start"),
            }
        }
    }

    #[test]
    fn test_fetch_multiple_literal_start_progress() {
        let input = b"* 1 FETCH (BODY[HEADER] {24}\r\nFrom: test@example.com\r\n BODY[TEXT] {12}\r\nHello World!)\r\n";
        let (mut rem, mut state) = FetchResponseState::new(input, IMAP_MAX_BODY_SIZE).unwrap();
        let mut sections = Vec::new();

        loop {
            match state.consume(rem).unwrap() {
                FetchResponseProgress::LiteralStart {
                    consumed, section, ..
                } => {
                    sections.push(section);
                    rem = &rem[consumed..];
                }
                FetchResponseProgress::Incomplete { .. } => {
                    panic!("Complete input should not be incomplete")
                }
                FetchResponseProgress::Complete { consumed, .. } => {
                    rem = &rem[consumed..];
                    break;
                }
            }
        }

        assert!(rem.is_empty());
        assert_eq!(
            sections,
            vec![FetchBodySection::Header, FetchBodySection::Text,]
        );
    }

    fn consume_fetch_chunk(
        state: &mut FetchResponseState, mut input: &[u8],
    ) -> Option<ImapMessage> {
        loop {
            match state.consume(input).unwrap() {
                FetchResponseProgress::LiteralStart { consumed, .. } => {
                    input = &input[consumed..];
                }
                FetchResponseProgress::Incomplete { consumed } => {
                    assert_eq!(consumed, input.len());
                    return None;
                }
                FetchResponseProgress::Complete { consumed, message } => {
                    assert_eq!(consumed, input.len());
                    return Some(message);
                }
            }
        }
    }

    #[test]
    fn test_fetch_empty_literal_metadata_bounded() {
        for padding in [0, IMAP_MAX_LINE_SIZE - 32] {
            for retain_limit in [0, IMAP_MAX_BODY_SIZE] {
                let (rem, mut state) =
                    FetchResponseState::new(b"* 1 FETCH (", retain_limit).unwrap();
                assert!(consume_fetch_chunk(&mut state, rem).is_none());
                let mut literal = vec![b' '; padding];
                literal.extend_from_slice(b" BODY[TEXT] {0}\r\n");
                for _ in 0..3000 {
                    let previous_count = state.literal_contexts.len();
                    let already_limited = state.metadata_len > IMAP_MAX_LINE_SIZE;
                    assert!(consume_fetch_chunk(&mut state, &literal).is_none());
                    if already_limited {
                        assert_eq!(state.literal_contexts.len(), previous_count);
                    }
                    let prefix_bytes: usize = state
                        .literal_contexts
                        .iter()
                        .map(|ctx| ctx.prefix.len())
                        .sum();
                    assert!(prefix_bytes <= IMAP_MAX_LINE_SIZE);
                    assert!(state.literal_contexts.len() <= IMAP_MAX_LINE_SIZE / 3);
                    assert!(state
                        .literal_contexts
                        .iter()
                        .all(|ctx| ctx.literal_data.is_empty()));
                    assert_eq!(state.literal_retain_left, retain_limit);
                }
                let msg = consume_fetch_chunk(&mut state, b")\r\n").unwrap();
                assert!(msg.line_truncated);
                let ImapMessageType::Untagged {
                    fetch_data: Some(fetch),
                    ..
                } = msg.message
                else {
                    panic!("Expected FETCH data");
                };
                assert!(fetch.data_limit_reached);
                assert!(!fetch.body_too_large);
                assert_eq!(fetch.email, Some(EmailData::default()));
            }
        }
    }

    #[test]
    fn test_fetch_metadata_limit_boundary_segmented() {
        for excess in [0, 1] {
            let marker = b"BODY[TEXT] {4}";
            let mut syntax = vec![b'('];
            syntax.resize(IMAP_MAX_LINE_SIZE + excess - marker.len(), b' ');
            syntax.extend_from_slice(marker);
            syntax.extend_from_slice(b"\r\n");
            for chunk_size in [1, 2, 7, syntax.len()] {
                let (_, mut state) = FetchResponseState::new(b"* 1 FETCH (", 4).unwrap();
                for chunk in syntax.chunks(chunk_size) {
                    assert!(consume_fetch_chunk(&mut state, chunk).is_none());
                }
                assert_eq!(state.metadata_len, IMAP_MAX_LINE_SIZE + excess);
                let literal = &state.current_literal.as_ref().unwrap().0;
                assert_eq!(literal.retain_limit, if excess == 0 { 4 } else { 0 });
                assert!(consume_fetch_chunk(&mut state, b"body").is_none());
                let msg = consume_fetch_chunk(&mut state, b")\r\n").unwrap();
                let ImapMessageType::Untagged {
                    fetch_data: Some(fetch),
                    ..
                } = msg.message
                else {
                    panic!("Expected FETCH data, even when all literals are skipped");
                };
                assert_eq!(fetch.data_limit_reached, excess != 0);
                assert!(!fetch.body_too_large);
                if excess == 0 {
                    assert_eq!(fetch.email.unwrap().email_body, b"body");
                } else {
                    assert!(fetch.email.is_none());
                }
            }
        }
    }

    #[test]
    fn test_fetch_metadata_limit_preserves_early_data_and_next_response() {
        let skipped = b")\r\nA1 OK not a response\r\n";
        let mut input = b"* 1 FETCH (BODY[TEXT] {5}\r\nearly".to_vec();
        input.extend(vec![b' '; IMAP_MAX_LINE_SIZE]);
        input.extend_from_slice(format!("BODY[TEXT] {{{}}}\r\n", skipped.len()).as_bytes());
        input.extend_from_slice(skipped);
        input.extend_from_slice(b")\r\nA1 OK FETCH completed\r\n");
        for retain_limit in [0, 3, IMAP_MAX_BODY_SIZE] {
            let (rem, msg) = parse_response(&input, retain_limit).unwrap();
            assert_eq!(rem, b"A1 OK FETCH completed\r\n");
            let ImapMessageType::Untagged {
                fetch_data: Some(fetch),
                ..
            } = msg.message
            else {
                panic!("Expected FETCH data");
            };
            assert!(fetch.data_limit_reached);
            assert_eq!(
                fetch.email.unwrap().email_body,
                &b"early"[..retain_limit.min(5)]
            );
            let (rem, next) = parse_response(rem, retain_limit).unwrap();
            assert!(rem.is_empty());
            assert_eq!(next.tag.as_deref(), Some(b"A1".as_slice()));
            assert!(matches!(
                next.message,
                ImapMessageType::Response {
                    status: ImapResponseStatus::Ok
                }
            ));
        }
    }

    #[test]
    fn test_fetch_skipped_literal_body_too_large() {
        let (_, mut state) = FetchResponseState::new(b"* 1 FETCH (", IMAP_MAX_BODY_SIZE).unwrap();
        let mut syntax = vec![b'('];
        syntax.resize(IMAP_MAX_LINE_SIZE, b' ');
        let size = IMAP_MAX_BODY_SIZE + 1;
        syntax.extend_from_slice(format!("BODY[TEXT] {{{size}}}\r\n").as_bytes());
        match state.consume(&syntax).unwrap() {
            FetchResponseProgress::LiteralStart {
                consumed,
                literal_size,
                section,
            } => {
                assert_eq!(consumed, syntax.len());
                assert_eq!(literal_size, size as u64);
                assert_eq!(section, FetchBodySection::Text);
            }
            _ => panic!("Skipped literals must still announce their frames"),
        }
        let chunk = vec![b'x'; 64 * 1024];
        let mut remaining = size;
        while remaining > 0 {
            let len = remaining.min(chunk.len());
            assert!(consume_fetch_chunk(&mut state, &chunk[..len]).is_none());
            if let Some((literal, _)) = &state.current_literal {
                assert_eq!(literal.buffer.capacity(), 0);
            }
            assert!(state.literal_contexts.is_empty());
            remaining -= len;
        }
        let msg = consume_fetch_chunk(&mut state, b")\r\n").unwrap();
        let ImapMessageType::Untagged {
            fetch_data: Some(fetch),
            ..
        } = msg.message
        else {
            panic!("Expected FETCH limit flags");
        };
        assert!(fetch.data_limit_reached);
        assert!(fetch.body_too_large);
        assert!(fetch.email.is_none());
    }

    #[test]
    fn test_fetch_skipped_literal_incomplete_and_malformed() {
        let mut input = b"* 1 FETCH (".to_vec();
        input.extend(vec![b' '; IMAP_MAX_LINE_SIZE]);
        input.extend_from_slice(b"BODY[TEXT] {4}\r\nab");
        assert!(matches!(
            parse_response(&input, IMAP_MAX_BODY_SIZE),
            Err(Err::Incomplete(_))
        ));
        let (rem, mut state) = FetchResponseState::new(&input, IMAP_MAX_BODY_SIZE).unwrap();
        assert!(consume_fetch_chunk(&mut state, rem).is_none());
        assert_eq!(state.current_literal.as_ref().unwrap().0.remaining(), 2);
        assert!(matches!(state.consume(b"cd)\rX"), Err(ErrorKind::CrLf)));
        input.extend_from_slice(b"cd)\rX");
        assert!(matches!(
            parse_response(&input, IMAP_MAX_BODY_SIZE),
            Err(Err::Error(_))
        ));
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
            let invalid = format!("A1 SEARCH{arguments} \"bad\\escape\"\r\n");
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
                    parse_response(&input, IMAP_MAX_BODY_SIZE)
                };
                if len <= IMAP_MAX_LINE_SIZE {
                    let (rem, msg) = result.unwrap();
                    assert!(rem.is_empty());
                    assert_eq!(msg.tag.as_deref(), Some(tag.as_slice()));
                } else {
                    assert!(matches!(
                        result,
                        Err(Err::Failure(Error {
                            code: ErrorKind::TooLarge,
                            ..
                        }))
                    ));
                }
            }
            let result = parse_tag(&tag);
            if len <= IMAP_MAX_LINE_SIZE {
                assert!(matches!(result, Err(Err::Incomplete(_))));
            } else {
                assert!(matches!(
                    result,
                    Err(Err::Failure(Error {
                        code: ErrorKind::TooLarge,
                        ..
                    }))
                ));
            }
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
        for input in [
            b"A1 FETCH 1 BODY[HEADER.FIELDS (SUBJECT\r\nA2 NOOP\r\n".as_slice(),
            b"A1 FETCH 1 BODY[HEADER.FIELDS (SUBJECT)]\nA2 NOOP\r\n",
        ] {
            assert!(
                matches!(parse_command(input), Err(Err::Error(_))),
                "{input:?}"
            );
        }
    }

    #[test]
    fn test_parse_login_command() {
        for (input, tag) in [
            (b"A1 LOGIN user pass\r\n".as_slice(), b"A1".as_slice()),
            (b"A001 LOGIN user pass\r\n", b"A001"),
        ] {
            let (rem, msg) = parse_command(input).unwrap();
            assert!(rem.is_empty());
            assert_eq!(msg.tag.as_deref(), Some(tag));
            assert_eq!(msg.raw_line, &input[..input.len() - 2]);
            assert!(!msg.line_truncated);
            match msg.message {
                ImapMessageType::Command {
                    command, arguments, ..
                } => {
                    assert_eq!(command, ImapCommand::Login);
                    assert_eq!(arguments, [b"user".to_vec(), b"pass".to_vec()]);
                }
                _ => panic!("Expected Command"),
            }
        }
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
            parse_quoted_string("\"café\"".as_bytes(), IMAP_MAX_LINE_SIZE),
            Ok((b"".as_slice(), "café".as_bytes().to_vec()))
        );
        assert!(matches!(
            parse_quoted_string(b"\"bad\\escape\"", IMAP_MAX_LINE_SIZE),
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
    fn test_parse_tagged_no_response() {
        let i = b"A001 NO Login failed\r\n";
        let (rem, msg) = parse_response(i, IMAP_MAX_BODY_SIZE).unwrap();
        assert!(rem.is_empty());
        assert_eq!(msg.tag, Some(b"A001".to_vec()));
        match msg.message {
            ImapMessageType::Response { status } => {
                assert_eq!(status, ImapResponseStatus::No);
            }
            _ => panic!("Expected Response"),
        }
    }

    #[test]
    fn test_parse_empty_continuation() {
        let i = b"+\r\n";
        let (rem, msg) = parse_response(i, IMAP_MAX_BODY_SIZE).unwrap();
        assert!(rem.is_empty());
        assert_eq!(msg.tag, None);
        assert_eq!(msg.message, ImapMessageType::Continuation);
    }

    #[test]
    fn test_parse_numeric_untagged() {
        let i = b"* 172 EXISTS\r\n";
        let (rem, msg) = parse_response(i, IMAP_MAX_BODY_SIZE).unwrap();
        assert!(rem.is_empty());
        assert_eq!(msg.tag, None);
        match msg.message {
            ImapMessageType::Untagged {
                seq_number,
                keyword,
                ..
            } => {
                assert_eq!(seq_number, Some(172));
                assert_eq!(keyword, b"EXISTS".to_vec());
            }
            _ => panic!("Expected Untagged"),
        }
    }

    #[test]
    fn test_case_insensitive_command() {
        let i = b"A001 login USER PASS\r\n";
        let (rem, msg) = parse_command(i).unwrap();
        assert!(rem.is_empty());
        match msg.message {
            ImapMessageType::Command { command, .. } => {
                assert_eq!(command, ImapCommand::Login);
            }
            _ => panic!("Expected Command"),
        }
    }

    #[test]
    fn test_parse_tag_with_special_chars() {
        for (input, tag) in [
            (
                b"a.b-c_d:e<f>g NOOP\r\n".as_slice(),
                b"a.b-c_d:e<f>g".as_slice(),
            ),
            (b"A]001 NOOP\r\n", b"A]001"),
        ] {
            let (rem, msg) = parse_command(input).unwrap();
            assert!(rem.is_empty());
            assert_eq!(msg.tag.as_deref(), Some(tag));
            match msg.message {
                ImapMessageType::Command { command, .. } => {
                    assert_eq!(command, ImapCommand::Noop);
                }
                _ => panic!("Expected Command"),
            }
        }
    }

    #[test]
    fn test_parse_literal_specifier_number64_boundaries() {
        let (rem, (size, is_plus)) = parse_literal_specifier(b"{4294967296+}").unwrap();
        assert!(rem.is_empty());
        assert_eq!(size, u64::from(u32::MAX) + 1);
        assert!(is_plus);

        let (rem, (size, is_plus)) = parse_literal_specifier(b"{9223372036854775807}").unwrap();
        assert!(rem.is_empty());
        assert_eq!(size, IMAP_MAX_LITERAL_SIZE);
        assert!(!is_plus);

        assert!(matches!(
            parse_literal_specifier(b"{9223372036854775808}"),
            Err(Err::Error(_))
        ));
        assert!(matches!(
            parse_command(b"A001 APPEND INBOX {9223372036854775808}\r\n"),
            Err(Err::Error(_))
        ));
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
            for retain_limit in [0, 2, 4, 8] {
                for split in 0..=input.len() {
                    let mut literal = LiteralInfo::new(size, false, retain_limit);
                    let mut total = 0;
                    for (chunk, consumed) in [
                        (&input[..split], split.min(expected)),
                        (&input[split..], expected.saturating_sub(split)),
                    ] {
                        assert_eq!(literal.consume_chunk(chunk), consumed);
                        total += consumed;
                        assert_eq!(literal.bytes_consumed, total as u64);
                        assert_eq!(literal.remaining(), size - total as u64);
                        assert_eq!(literal.buffer, &b"abcd"[..total.min(retain_limit)]);
                        assert_eq!(literal.truncated, size > retain_limit as u64);
                    }
                }
            }
        }
    }

    #[test]
    fn test_literal_info_tracks_more_than_u32() {
        let size = u64::from(u32::MAX) + 2;
        let mut literal = LiteralInfo::new(size, false, 0);
        literal.bytes_consumed = u64::from(u32::MAX);

        assert_eq!(literal.consume_chunk(b"ab"), 2);
        assert_eq!(literal.bytes_consumed, size);
        assert_eq!(literal.remaining(), 0);
        assert!(literal.buffer.is_empty());
        assert!(literal.truncated);
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
                let mut data = LiteralInfo::new(size, is_literal_plus, 0);
                assert_eq!(data.consume_chunk(&rem[..split]), split);
                assert_eq!(data.consume_chunk(&rem[split..]), size as usize - split);
                assert_eq!(data.remaining(), 0);
                assert!(data.buffer.is_empty());
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
            b"A1 SEARCH (SUBJECT {3+}\n",
            b"A1 SEARCH (SUBJECT \"{3}\r\n",
            b"A1 SEARCH (SUBJECT \"bad\\escape\" {3}\r\n",
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
    fn test_parse_command_continuation_second_literal() {
        let (rem, (msg, literal)) = parse_command_continuation(b" {8}\r\n", 0).unwrap();
        assert!(rem.is_empty());
        assert_eq!(msg.raw_line, b"{8}");
        assert_eq!(
            literal,
            Some(CommandLiteral {
                size: 8,
                is_literal_plus: false,
                parenthesis_depth: 0
            })
        );

        let (rem, (msg, literal)) = parse_command_continuation(b" user {4+}\r\n", 0).unwrap();
        assert!(rem.is_empty());
        assert_eq!(msg.raw_line, b"user {4+}");
        assert_eq!(
            literal,
            Some(CommandLiteral {
                size: 4,
                is_literal_plus: true,
                parenthesis_depth: 0
            })
        );
    }

    #[test]
    fn test_parse_command_continuation_raw_line() {
        for (input, expected) in [
            (
                b"   SUBJECT secret\r\n".as_slice(),
                b"SUBJECT secret".as_slice(),
            ),
            (b"\tSUBJECT\tsecret\r\n", b"\tSUBJECT\tsecret"),
            (
                b"  \tSUBJECT  \"a\\\"b\\\\c\"\r\n",
                b"\tSUBJECT  \"a\\\"b\\\\c\"",
            ),
        ] {
            assert_incomplete_at_each_boundary(input, |i| parse_command_continuation(i, 0));
            let mut commands = input.to_vec();
            commands.extend_from_slice(b"A2 NOOP\r\n");
            let (rem, (msg, literal)) = parse_command_continuation(&commands, 0).unwrap();
            assert_eq!(rem, b"A2 NOOP\r\n");
            assert_eq!(msg.tag, None);
            assert_eq!(msg.message, ImapMessageType::ContinuationData);
            assert_eq!(msg.raw_line, expected);
            assert!(!msg.line_truncated);
            assert_eq!(literal, None);
        }
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
    fn test_parse_command_continuation_incomplete_at_each_boundary() {
        for input in [
            b" {8}\r\n".as_slice(),
            b" INBOX (\\Seen)\r\n".as_slice(),
            b"\r\n".as_slice(),
        ] {
            assert_incomplete_at_each_boundary(input, |i| parse_command_continuation(i, 0));
        }
    }

    #[test]
    fn test_parse_command_continuation_malformed() {
        for input in [
            b"x\r\n".as_slice(),
            b" \r\n".as_slice(),
            b"\n".as_slice(),
            b" {8} \r\n".as_slice(),
        ] {
            assert!(
                matches!(parse_command_continuation(input, 0), Err(Err::Error(_))),
                "expected error for {input:?}"
            );
        }
    }

    #[test]
    fn test_parse_response_continuation() {
        assert_eq!(
            parse_response_continuation(b"\r\n"),
            Ok((b"".as_slice(), None))
        );
        assert_eq!(
            parse_response_continuation(b" (MESSAGES 1)\r\nA2 OK\r\n"),
            Ok((b"A2 OK\r\n".as_slice(), None))
        );
        assert_eq!(
            parse_response_continuation(b" {6}\r\n"),
            Ok((b"".as_slice(), Some(6)))
        );
        assert_eq!(
            parse_response_continuation(b" name {6}\r\n"),
            Ok((b"".as_slice(), Some(6)))
        );
        assert_eq!(
            parse_response_continuation(b" {6} x\r\n"),
            Ok((b"".as_slice(), None))
        );
    }

    #[test]
    fn test_parse_response_continuation_incomplete_at_each_boundary() {
        for input in [
            b"\r\n".as_slice(),
            b" (MESSAGES 1)\r\n".as_slice(),
            b" {6}\r\n".as_slice(),
        ] {
            assert_incomplete_at_each_boundary(input, parse_response_continuation);
        }
    }

    #[test]
    fn test_parse_response_continuation_malformed() {
        for input in [b"\n".as_slice(), b" a\rb\r\n".as_slice()] {
            assert!(
                matches!(parse_response_continuation(input), Err(Err::Error(_))),
                "expected error for {input:?}"
            );
        }
    }

    #[test]
    fn test_parse_email_headers_simple() {
        let email = b"From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nBody text";
        let (remaining, parsed) = parse_email_headers(email).unwrap();
        let headers = parsed.headers;
        assert!(!parsed.too_many_headers);
        assert_eq!(headers.len(), 3);
        assert_eq!(headers[0].data, b"From: sender@example.com".to_vec());
        assert_eq!(headers[0].name(), b"From");
        assert_eq!(headers[0].value(), b"sender@example.com");
        assert_eq!(
            header_values(&headers, "to"),
            [b"recipient@example.com".as_slice()]
        );
        assert_eq!(header_values(&headers, "Subject"), [b"Test".as_slice()]);
        assert_eq!(remaining, b"\r\nBody text");
    }

    #[test]
    fn test_parse_email_headers_folded() {
        let email =
            b"Subject: This is a very long\r\n subject that spans multiple lines\r\n\r\nBody";
        let (rem, parsed) = parse_email_headers(email).unwrap();
        let headers = parsed.headers;
        assert!(!parsed.too_many_headers);
        assert_eq!(
            header_values(&headers, "Subject"),
            [b"This is a very long subject that spans multiple lines".as_slice()]
        );
        assert_eq!(rem, b"\r\nBody");
    }

    #[test]
    fn test_parse_email_headers_repeated() {
        let email = b"Received: from server1.example.com\r\nReceived: from server2.example.com\r\nFrom: sender@example.com\r\n\r\nBody";
        let (remaining, parsed) = parse_email_headers(email).unwrap();
        let headers = parsed.headers;
        assert!(!parsed.too_many_headers);
        assert_eq!(
            header_values(&headers, "Received"),
            [
                b"from server1.example.com".as_slice(),
                b"from server2.example.com".as_slice()
            ]
        );
        assert_eq!(
            header_values(&headers, "From"),
            [b"sender@example.com".as_slice()]
        );
        assert_eq!(remaining, b"\r\nBody");
    }

    #[test]
    fn test_parse_email_headers_keeps_raw_bytes() {
        let email = b"Subject: caf\xe9 \r\nX-Empty:\r\n\r\n";
        let (_, parsed) = parse_email_headers(email).unwrap();
        assert_eq!(parsed.headers[0].value(), b"caf\xe9");
        assert_eq!(parsed.headers[1].data, b"X-Empty: ".to_vec());
        assert_eq!(parsed.headers[1].value(), b"");
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
        let (rem, msg) = parse_response(i, IMAP_MAX_BODY_SIZE).unwrap();
        assert!(rem.is_empty());
        assert_eq!(msg.raw_line, b"* 1 FETCH (UID 1 FLAGS (\\Seen))".to_vec());
        match msg.message {
            ImapMessageType::Untagged {
                seq_number,
                keyword,
                fetch_data,
            } => {
                assert_eq!(seq_number, Some(1));
                assert_eq!(keyword, b"FETCH".to_vec());
                assert!(fetch_data.is_none());
            }
            _ => panic!("Expected Untagged"),
        }
    }

    #[test]
    fn test_parse_fetch_with_literal_plus() {
        let i = b"* 2 FETCH (BODY[] {10+}\r\nHelloWorld)\r\n";
        let (rem, msg) = parse_response(i, IMAP_MAX_BODY_SIZE).unwrap();
        assert!(rem.is_empty());
        assert_eq!(msg.raw_line, b"* 2 FETCH (BODY[] {10+})".to_vec());
        match msg.message {
            ImapMessageType::Untagged {
                seq_number,
                keyword,
                fetch_data,
            } => {
                assert_eq!(seq_number, Some(2));
                assert_eq!(keyword, b"FETCH".to_vec());
                let fetch = fetch_data.unwrap();
                assert!(fetch.email.is_none());
            }
            _ => panic!("Expected Untagged"),
        }
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
        for (input, expected) in [
            (b"BODY[]<1024>".as_slice(), FetchBodySection::Text),
            (b"BODY[HEADER]<50>".as_slice(), FetchBodySection::Text),
            (b"BODY[]<0>".as_slice(), FetchBodySection::Full),
            (b"BODY[]<0.512>".as_slice(), FetchBodySection::Full),
            (b"BODY[]".as_slice(), FetchBodySection::Full),
            (b"BODY.PEEK[]".as_slice(), FetchBodySection::Full),
            (b"BODY[HEADER]".as_slice(), FetchBodySection::Header),
            (b"BODY[1.2]".as_slice(), FetchBodySection::Other),
            (b"BODY[TEXT]<2048>".as_slice(), FetchBodySection::Text),
            (b"BODY[TEXT]".as_slice(), FetchBodySection::Text),
        ] {
            let (rem, section) = parse_body_section(input).unwrap();
            assert!(rem.is_empty(), "unconsumed input for {input:?}");
            assert_eq!(section, expected, "wrong section for {input:?}");
        }
    }

    #[test]
    fn test_parse_fetch_partial_first_chunk_full() {
        let i = b"* 1 FETCH (BODY[]<0> {27}\r\nSubject: hi\r\n\r\nHello there!)\r\n";
        let (_, msg) = parse_response(i, IMAP_MAX_BODY_SIZE).unwrap();
        let ImapMessageType::Untagged {
            fetch_data: Some(fetch),
            ..
        } = msg.message
        else {
            panic!("Expected FETCH data");
        };
        let email = fetch.email.unwrap();
        assert_eq!(header_values(&email.headers, "Subject"), [b"hi".as_slice()]);
        assert_eq!(email.email_body, b"Hello there!");
    }

    #[test]
    fn test_extract_fetch_section_from_prefix() {
        let prefix = b"(UID 1 RFC822.SIZE 452 BODY[HEADER.FIELDS (FROM TO)] ";
        let section = extract_fetch_section_from_prefix(prefix);
        assert_eq!(section, Some(FetchBodySection::Header));

        let prefix = b"(BODY[] ";
        let section = extract_fetch_section_from_prefix(prefix);
        assert_eq!(section, Some(FetchBodySection::Full));

        assert_eq!(
            extract_fetch_section_from_prefix(b"(RFC822 "),
            Some(FetchBodySection::Full)
        );
        assert_eq!(
            extract_fetch_section_from_prefix(b"(rFc822.HeAdEr "),
            Some(FetchBodySection::Header)
        );
        assert_eq!(
            extract_fetch_section_from_prefix(b"(RFC822.text "),
            Some(FetchBodySection::Text)
        );
        assert_eq!(extract_fetch_section_from_prefix(b"(RFC822.SIZE "), None);
    }

    #[test]
    fn test_parse_fetch_quoted_body_rfc822_text() {
        let i = b"* 1 FETCH (RFC822.TEXT \"plainbody\")\r\n";
        let (_, msg) = parse_response(i, IMAP_MAX_BODY_SIZE).unwrap();
        let ImapMessageType::Untagged {
            fetch_data: Some(fetch),
            ..
        } = msg.message
        else {
            panic!("Expected FETCH data");
        };
        assert_eq!(fetch.email.unwrap().email_body, b"plainbody");
    }

    #[test]
    fn test_parse_fetch_quoted_body_full_and_header_without_email() {
        let i = b"* 1 FETCH (BODY[] \"raw\" BODY[HEADER] \"Subject: hi\")\r\n";
        let (_, msg) = parse_response(i, IMAP_MAX_BODY_SIZE).unwrap();
        let ImapMessageType::Untagged {
            fetch_data: Some(fetch),
            ..
        } = msg.message
        else {
            panic!("Expected FETCH data");
        };
        assert!(fetch.email.is_none());
    }

    #[test]
    fn test_parse_fetch_quoted_body_escaped_quote() {
        let i = b"* 1 FETCH (BODY[TEXT] \"a\\\"b\")\r\n";
        let (_, msg) = parse_response(i, IMAP_MAX_BODY_SIZE).unwrap();
        let ImapMessageType::Untagged {
            fetch_data: Some(fetch),
            ..
        } = msg.message
        else {
            panic!("Expected FETCH data");
        };
        assert_eq!(fetch.email.unwrap().email_body, b"a\"b");
    }

    #[test]
    fn test_parse_fetch_quoted_body_nil_no_body() {
        let i = b"* 1 FETCH (BODY[TEXT] NIL)\r\n";
        let (_, msg) = parse_response(i, IMAP_MAX_BODY_SIZE).unwrap();
        match msg.message {
            ImapMessageType::Untagged { fetch_data, .. } => assert!(fetch_data.is_none()),
            _ => panic!("Expected Untagged"),
        }
    }

    #[test]
    fn test_parse_fetch_quoted_bodystructure_not_extracted() {
        let i = b"* 1 FETCH (BODYSTRUCTURE (\"TEXT\" \"PLAIN\" NIL NIL \"7BIT\" 12 1))\r\n";
        let (_, msg) = parse_response(i, IMAP_MAX_BODY_SIZE).unwrap();
        match msg.message {
            ImapMessageType::Untagged { fetch_data, .. } => assert!(fetch_data.is_none()),
            _ => panic!("Expected Untagged"),
        }
    }

    #[test]
    fn test_parse_fetch_data_headers_only() {
        let i = b"* 1 FETCH (BODY[HEADER] {24}\r\nFrom: test@example.com\r\n)\r\n";
        let (rem, msg) = parse_response(i, IMAP_MAX_BODY_SIZE).unwrap();
        assert!(rem.is_empty());
        match msg.message {
            ImapMessageType::Untagged { fetch_data, .. } => {
                let fetch = fetch_data.unwrap();
                let email = fetch.email.unwrap();
                assert_eq!(
                    header_values(&email.headers, "From"),
                    [b"test@example.com".as_slice()]
                );
                assert!(email.email_body.is_empty());
            }
            _ => panic!("Expected Untagged"),
        }
    }

    #[test]
    fn test_parse_fetch_data_with_rfc822_full() {
        let i = b"* 1 FETCH (RFC822 {38}\r\nFrom: test@example.com\r\n\r\nHello World!)\r\n";
        let (rem, msg) = parse_response(i, IMAP_MAX_BODY_SIZE).unwrap();
        assert!(rem.is_empty());
        match msg.message {
            ImapMessageType::Untagged { fetch_data, .. } => {
                let fetch = fetch_data.unwrap();
                let email = fetch.email.unwrap();
                assert_eq!(
                    header_values(&email.headers, "From"),
                    [b"test@example.com".as_slice()]
                );
                assert_eq!(email.email_body, b"Hello World!");
            }
            _ => panic!("Expected Untagged"),
        }
    }

    #[test]
    fn test_parse_fetch_data_with_rfc822_header_and_text() {
        let i = b"* 1 FETCH (RFC822.HEADER {24}\r\nFrom: test@example.com\r\n RFC822.TEXT {12}\r\nHello World!)\r\n";
        let (rem, msg) = parse_response(i, IMAP_MAX_BODY_SIZE).unwrap();
        assert!(rem.is_empty());
        match msg.message {
            ImapMessageType::Untagged { fetch_data, .. } => {
                let fetch = fetch_data.unwrap();
                let email = fetch.email.unwrap();
                assert_eq!(
                    header_values(&email.headers, "From"),
                    [b"test@example.com".as_slice()]
                );
                assert_eq!(email.email_body, b"Hello World!");
            }
            _ => panic!("Expected Untagged"),
        }
    }

    #[test]
    fn test_fetch_merge_order_and_offsets() {
        for text_first in [false, true] {
            let mut contexts: Vec<_> = [
                (
                    b"BODY[]".as_slice(),
                    b"Subject: first\r\n\r\none".as_slice(),
                ),
                (b"BODY[TEXT]", b"middle"),
                (b"BODY[]", b"Subject: second\r\n\r\ntwo"),
            ]
            .into_iter()
            .map(|(prefix, data)| LiteralContext {
                prefix: prefix.to_vec(),
                literal_data: data.to_vec(),
            })
            .collect();
            if text_first {
                contexts.swap(0, 1);
            }
            let email = parse_fetch_data(contexts).email.unwrap();
            assert_eq!(
                header_values(&email.headers, "Subject"),
                [b"first".as_slice(), b"second".as_slice()]
            );
            assert_eq!(
                email.email_body,
                if text_first {
                    b"middleonetwo"
                } else {
                    b"onemiddletwo"
                }
            );
            assert_eq!(email.headers_len, if text_first { 0 } else { 16 });
            assert_eq!(email.body_offset, if text_first { 0 } else { 18 });
            assert!(!email.too_many_headers);
        }
    }

    #[test]
    fn test_fetch_merge_header_limit() {
        for (first, second) in [
            (256, 256),
            (256, 257),
            (513, 1),
            (1, 513),
            (0, 513),
            (513, 0),
        ] {
            let contexts = [0..first, first..first + second]
                .into_iter()
                .map(|indices| LiteralContext {
                    prefix: b"BODY[HEADER]".to_vec(),
                    literal_data: indices
                        .flat_map(|idx| format!("X-Index: {idx}\r\n").into_bytes())
                        .collect(),
                })
                .collect();
            let email = parse_fetch_data(contexts).email.unwrap();
            assert_eq!(email.headers.len(), IMAP_MAX_HEADERS);
            assert_eq!(email.too_many_headers, first + second > IMAP_MAX_HEADERS);
            for (idx, header) in email.headers.iter().enumerate() {
                assert_eq!(header.value(), idx.to_string().as_bytes());
            }
            assert!(email.email_body.is_empty());
        }
    }

    #[test]
    fn test_fetch_merge_empty_and_invalid_parts() {
        for (prefix, data, has_email) in [
            (b"BODY[TEXT]".as_slice(), b"".as_slice(), true),
            (b"BODY[HEADER]", b"", true),
            (b"BODY[]", b"\r\n", true),
            (b"BODY[]", b"raw", false),
            (b"BODY[HEADER]", b"Subject: missing CRLF", false),
            (b"BODY[1]", b"ignored", false),
        ] {
            let context = || LiteralContext {
                prefix: prefix.to_vec(),
                literal_data: data.to_vec(),
            };
            assert_eq!(parse_fetch_data(vec![context()]).email.is_some(), has_email);
            let email = parse_fetch_data(vec![
                context(),
                LiteralContext {
                    prefix: b"BODY[TEXT]".to_vec(),
                    literal_data: b"body".to_vec(),
                },
                context(),
            ])
            .email
            .unwrap();
            assert!(email.headers.is_empty());
            assert_eq!(email.email_body, b"body");
            assert!(!email.too_many_headers);
        }
    }

    #[test]
    fn test_fetch_merge_segmented() {
        for input in [
            b"* 1 FETCH (BODY[HEADER] {12}\r\nSubject: a\r\n BODY[TEXT] {3}\r\none)\r\n".as_slice(),
            b"* 1 FETCH (BODY[TEXT] {3}\r\none BODY[HEADER] {12}\r\nSubject: a\r\n)\r\n",
            b"* 1 FETCH (BODY[TEXT] \"before\" BODY[HEADER] {12}\r\nSubject: a\r\n BODY[TEXT] {3}\r\nmid BODY[TEXT] \"after\")\r\n",
        ] {
            for limit in [0, 3, 12, 15, 20, IMAP_MAX_BODY_SIZE] {
                let (rem, expected) = parse_response(input, limit).unwrap();
                assert!(rem.is_empty());
                for chunk_size in [1, 2, 7, input.len()] {
                    let (rem, mut state) = FetchResponseState::new(input, limit).unwrap();
                    let mut message = None;
                    for chunk in rem.chunks(chunk_size) {
                        assert!(message.is_none());
                        message = consume_fetch_chunk(&mut state, chunk);
                    }
                    assert_eq!(message.as_ref(), Some(&expected));
                }
                if limit == IMAP_MAX_BODY_SIZE {
                    let ImapMessageType::Untagged {
                        fetch_data: Some(fetch),
                        ..
                    } = expected.message
                    else {
                        panic!("Expected FETCH data");
                    };
                    let email = fetch.email.unwrap();
                    assert_eq!(header_values(&email.headers, "Subject"), [b"a".as_slice()]);
                    let body = if input.contains(&b'"') {
                        b"beforemidafter".as_slice()
                    } else {
                        b"one"
                    };
                    assert_eq!(email.email_body, body);
                }
            }
        }
    }

    #[test]
    fn test_fetch_merge_quoted_literal_budget() {
        let input =
            b"* 1 FETCH (BODY[TEXT] \"before\" BODY[TEXT] {3}\r\nmid BODY[TEXT] \"after\")\r\n";
        for (limit, body) in [
            (0, b"".as_slice()),
            (1, b"m"),
            (3, b"mid"),
            (5, b"bemid"),
            (10, b"beforemida"),
            (IMAP_MAX_BODY_SIZE, b"beforemidafter"),
        ] {
            let (_, msg) = parse_response(input, limit).unwrap();
            let ImapMessageType::Untagged {
                fetch_data: Some(fetch),
                ..
            } = msg.message
            else {
                panic!("Expected FETCH data");
            };
            assert_eq!(fetch.email.unwrap().email_body, body);
            assert_eq!(fetch.data_limit_reached, limit < 3);
            assert!(!fetch.body_too_large);
        }
    }

    #[test]
    fn test_parse_untagged_response_stops_at_literal_specifier() {
        let i = b"* LIST () \"/\" {5}\r\nINBOX\r\n";
        let (rem, msg) = parse_response(i, IMAP_MAX_BODY_SIZE).unwrap();
        assert_eq!(rem, b"INBOX\r\n");
        assert_eq!(msg.raw_line, b"* LIST () \"/\" {5}".to_vec());
        assert!(matches!(
            msg.message,
            ImapMessageType::Untagged { ref keyword, .. } if keyword == b"LIST"
        ));
    }

    #[test]
    fn test_parse_email_content_with_content_disposition() {
        let email = b"From: sender@example.com\r\nTo: recipient@example.com\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Disposition: inline\r\nSubject: Test\r\n\r\nThis is the body.";
        let res = parse_email_content(email.to_vec()).unwrap();
        assert_eq!(
            header_values(&res.headers, "From"),
            [b"sender@example.com".as_slice()]
        );
        assert_eq!(
            header_values(&res.headers, "Content-Disposition"),
            [b"inline".as_slice()]
        );
        assert_eq!(
            header_values(&res.headers, "Content-Type"),
            [b"text/plain; charset=UTF-8".as_slice()]
        );
        assert_eq!(res.email_body, b"This is the body.");
    }
}
