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
use nom8::character::streaming::{char, crlf, digit1, space0, space1};
use nom8::combinator::{all_consuming, map, map_res, opt, value, verify};
use nom8::error::{Error, ErrorKind};
use nom8::multi::many0;
use nom8::sequence::{delimited, preceded};
use nom8::{Err, IResult, Needed, Parser};
use std::collections::HashMap;
use std::fmt;

pub const IMAP_MAX_BODY_SIZE: usize = 10 * 1024 * 1024;
pub const IMAP_MAX_HEADERS: usize = 512;
pub const IMAP_MAX_LINE_SIZE: usize = 8 * 1024;
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

impl fmt::Display for ImapCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ImapCommand::Capability => write!(f, "CAPABILITY"),
            ImapCommand::Noop => write!(f, "NOOP"),
            ImapCommand::Logout => write!(f, "LOGOUT"),
            ImapCommand::StartTls => write!(f, "STARTTLS"),
            ImapCommand::Authenticate => write!(f, "AUTHENTICATE"),
            ImapCommand::Login => write!(f, "LOGIN"),
            ImapCommand::Select => write!(f, "SELECT"),
            ImapCommand::Examine => write!(f, "EXAMINE"),
            ImapCommand::Create => write!(f, "CREATE"),
            ImapCommand::Delete => write!(f, "DELETE"),
            ImapCommand::Rename => write!(f, "RENAME"),
            ImapCommand::Subscribe => write!(f, "SUBSCRIBE"),
            ImapCommand::Unsubscribe => write!(f, "UNSUBSCRIBE"),
            ImapCommand::List => write!(f, "LIST"),
            ImapCommand::Lsub => write!(f, "LSUB"),
            ImapCommand::Status => write!(f, "STATUS"),
            ImapCommand::Append => write!(f, "APPEND"),
            ImapCommand::Check => write!(f, "CHECK"),
            ImapCommand::Close => write!(f, "CLOSE"),
            ImapCommand::Expunge => write!(f, "EXPUNGE"),
            ImapCommand::Search => write!(f, "SEARCH"),
            ImapCommand::Fetch => write!(f, "FETCH"),
            ImapCommand::Store => write!(f, "STORE"),
            ImapCommand::Copy => write!(f, "COPY"),
            ImapCommand::Uid => write!(f, "UID"),
            ImapCommand::Idle => write!(f, "IDLE"),
            ImapCommand::Id => write!(f, "ID"),
            ImapCommand::Unknown(bytes) => write!(f, "{}", String::from_utf8_lossy(bytes)),
        }
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

#[derive(Debug, Clone, Default, PartialEq)]
pub struct EmailData {
    pub headers: HashMap<String, Vec<String>>,
    pub headers_len: u32,
    pub body_offset: u32,
    pub email_body: Vec<u8>,
    pub too_many_headers: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum FetchBodySection {
    Full,
    Header { fields: Option<Vec<String>> },
    Text,
    Part(Vec<u32>),
    Unknown(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct FetchBodyPart {
    pub section: FetchBodySection,
    pub email: Option<EmailData>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct FetchData {
    pub seq_number: u32,
    pub uid: Option<u32>,
    pub flags: Option<Vec<String>>,
    pub rfc822_size: Option<u32>,
    pub body_parts: Vec<FetchBodyPart>,
    pub body_truncated: bool,
    pub body_too_large: bool,
    pub data_limit_reached: bool,
}

impl FetchData {
    pub fn take_email(&mut self) -> Option<EmailData> {
        let mut email: Option<EmailData> = None;
        let mut header_count = 0usize;
        for part in self.body_parts.drain(..) {
            if let Some(mut em) = part.email {
                match email {
                    None => {
                        header_count = em.headers.values().map(Vec::len).sum();
                        email = Some(em);
                    }
                    Some(ref mut m) => {
                        if em.too_many_headers {
                            m.too_many_headers = true;
                        }
                        let mut retain_left = IMAP_MAX_HEADERS.saturating_sub(header_count);
                        if em.headers.values().map(Vec::len).sum::<usize>() > retain_left {
                            m.too_many_headers = true;
                        }
                        for (key, values) in em.headers.drain() {
                            let retain_count = values.len().min(retain_left);
                            if retain_count > 0 {
                                m.headers
                                    .entry(key)
                                    .or_default()
                                    .extend(values.into_iter().take(retain_count));
                                header_count += retain_count;
                                retain_left -= retain_count;
                            }
                            if retain_left == 0 {
                                break;
                            }
                        }
                        if !em.email_body.is_empty() {
                            m.email_body.append(&mut em.email_body);
                        }
                    }
                }
            }
        }
        email
    }
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

#[derive(Clone, PartialEq)]
pub enum ImapMessageType {
    Command {
        command: ImapCommand,
        arguments: Vec<Vec<u8>>,
    },
    Response {
        status: ImapResponseStatus,
        text: Option<Vec<u8>>,
    },
    Untagged {
        seq_number: Option<u32>,
        keyword: Vec<u8>,
        data: Option<Vec<u8>>,
        fetch_data: Option<FetchData>,
    },
    Continuation {
        text: Option<Vec<u8>>,
    },
    ContinuationData {
        data: Vec<u8>,
    },
    LiteralData {
        raw: Vec<u8>,
        email: Option<EmailData>,
    },
}

impl fmt::Debug for ImapMessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ImapMessageType::Command { command, arguments } => {
                let args: Vec<String> = arguments
                    .iter()
                    .map(|a| String::from_utf8_lossy(a).into_owned())
                    .collect();
                f.debug_struct("Command")
                    .field("command", command)
                    .field("arguments", &args)
                    .finish()
            }
            ImapMessageType::Response { status, text } => {
                let text_str = text
                    .as_ref()
                    .map(|t| String::from_utf8_lossy(t).into_owned());
                f.debug_struct("Response")
                    .field("status", status)
                    .field("text", &text_str)
                    .finish()
            }
            ImapMessageType::Untagged {
                seq_number,
                keyword,
                data,
                fetch_data,
            } => {
                let keyword_str = String::from_utf8_lossy(keyword).into_owned();
                let data_str = data
                    .as_ref()
                    .map(|d| String::from_utf8_lossy(d).into_owned());
                f.debug_struct("Untagged")
                    .field("seq_number", seq_number)
                    .field("keyword", &keyword_str)
                    .field("data", &data_str)
                    .field("fetch_data", fetch_data)
                    .finish()
            }
            ImapMessageType::Continuation { text } => {
                let text_str = text
                    .as_ref()
                    .map(|t| String::from_utf8_lossy(t).into_owned());
                f.debug_struct("Continuation")
                    .field("text", &text_str)
                    .finish()
            }
            ImapMessageType::ContinuationData { data } => {
                let data_str = String::from_utf8_lossy(data).into_owned();
                f.debug_struct("ContinuationData")
                    .field("data", &data_str)
                    .finish()
            }
            ImapMessageType::LiteralData { raw, email } => {
                let raw_preview = if raw.len() > 100 {
                    format!(
                        "{}... ({} bytes)",
                        String::from_utf8_lossy(&raw[..100]),
                        raw.len()
                    )
                } else {
                    String::from_utf8_lossy(raw).into_owned()
                };
                f.debug_struct("LiteralData")
                    .field("raw", &raw_preview)
                    .field("email", email)
                    .finish()
            }
        }
    }
}

#[derive(Clone, PartialEq)]
pub struct ImapMessage {
    pub tag: Option<Vec<u8>>,
    pub message: ImapMessageType,
    pub raw_line: Vec<u8>,
    pub line_truncated: bool,
}

impl fmt::Debug for ImapMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tag_str = self
            .tag
            .as_ref()
            .map(|t| String::from_utf8_lossy(t).into_owned());
        let raw_line_str = String::from_utf8_lossy(&self.raw_line).into_owned();
        f.debug_struct("ImapMessage")
            .field("tag", &tag_str)
            .field("message", &self.message)
            .field("raw_line", &raw_line_str)
            .field("line_truncated", &self.line_truncated)
            .finish()
    }
}

impl ImapMessage {
    pub fn is_request(&self) -> bool {
        matches!(self.message, ImapMessageType::Command { .. })
    }

    pub fn is_response(&self) -> bool {
        matches!(
            self.message,
            ImapMessageType::Response { .. }
                | ImapMessageType::Untagged { .. }
                | ImapMessageType::Continuation { .. }
        )
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
    take_while1(is_tag_char).parse(i)
}

fn parse_command_keyword(i: &[u8]) -> IResult<&[u8], ImapCommand> {
    let (i, cmd) = parse_atom(i)?;
    let command = match cmd.to_ascii_uppercase().as_slice() {
        b"CAPABILITY" => ImapCommand::Capability,
        b"NOOP" => ImapCommand::Noop,
        b"LOGOUT" => ImapCommand::Logout,
        b"STARTTLS" => ImapCommand::StartTls,
        b"AUTHENTICATE" => ImapCommand::Authenticate,
        b"LOGIN" => ImapCommand::Login,
        b"SELECT" => ImapCommand::Select,
        b"EXAMINE" => ImapCommand::Examine,
        b"CREATE" => ImapCommand::Create,
        b"DELETE" => ImapCommand::Delete,
        b"RENAME" => ImapCommand::Rename,
        b"SUBSCRIBE" => ImapCommand::Subscribe,
        b"UNSUBSCRIBE" => ImapCommand::Unsubscribe,
        b"LIST" => ImapCommand::List,
        b"LSUB" => ImapCommand::Lsub,
        b"STATUS" => ImapCommand::Status,
        b"APPEND" => ImapCommand::Append,
        b"CHECK" => ImapCommand::Check,
        b"CLOSE" => ImapCommand::Close,
        b"EXPUNGE" => ImapCommand::Expunge,
        b"SEARCH" => ImapCommand::Search,
        b"FETCH" => ImapCommand::Fetch,
        b"STORE" => ImapCommand::Store,
        b"COPY" => ImapCommand::Copy,
        b"UID" => ImapCommand::Uid,
        b"IDLE" => ImapCommand::Idle,
        b"ID" => ImapCommand::Id,
        _ => ImapCommand::Unknown(cmd.to_vec()),
    };
    Ok((i, command))
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

fn parse_quoted_string(i: &[u8]) -> IResult<&[u8], Vec<u8>> {
    let (mut rem, _) = char('"').parse(i)?;
    let mut value = Vec::new();

    loop {
        let Some((&byte, after_byte)) = rem.split_first() else {
            return Err(Err::Incomplete(Needed::new(1)));
        };

        match byte {
            b'"' => return Ok((after_byte, value)),
            b'\\' => {
                let Some((&escaped, after_escape)) = after_byte.split_first() else {
                    return Err(Err::Incomplete(Needed::new(1)));
                };
                if escaped != b'"' && escaped != b'\\' {
                    return Err(Err::Error(Error::new(rem, ErrorKind::Escaped)));
                }
                value.push(escaped);
                rem = after_escape;
            }
            b'\0' | b'\r' | b'\n' => {
                return Err(Err::Error(Error::new(rem, ErrorKind::Char)));
            }
            _ => {
                value.push(byte);
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
    fn with_open_parenthesis() -> Self {
        Self {
            depth: 1,
            saw_open: true,
            ..Default::default()
        }
    }

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

fn parse_list(i: &[u8]) -> IResult<&[u8], Vec<u8>> {
    let (i, _) = char('(')(i)?;
    let mut scanner = ParenthesisScanner::with_open_parenthesis();
    let end_pos = scanner
        .scan(i)
        .map_err(|kind| Err::Error(Error::new(i, kind)))?
        .ok_or(Err::Incomplete(Needed::new(1)))?;

    let content = &i[..end_pos];
    let rem = &i[end_pos + 1..];

    let mut result = vec![b'('];
    result.extend_from_slice(content);
    result.push(b')');
    Ok((rem, result))
}

fn parse_literal_as_argument(i: &[u8]) -> IResult<&[u8], Vec<u8>> {
    let start = i;
    let (i, _) = parse_literal_specifier(i)?;
    let len = start.len() - i.len();
    Ok((i, start[..len].to_vec()))
}

#[inline]
fn is_sequence_set_char(c: u8) -> bool {
    c.is_ascii_digit() || c == b':' || c == b'*' || c == b','
}

fn parse_sequence_set(i: &[u8]) -> IResult<&[u8], Vec<u8>> {
    let (rem, seq) = take_while1(is_sequence_set_char).parse(i)?;
    if !seq.is_empty() && (seq[0].is_ascii_digit() || seq[0] == b'*') {
        Ok((rem, seq.to_vec()))
    } else {
        Err(Err::Error(Error::new(i, ErrorKind::Char)))
    }
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

fn parse_argument(i: &[u8]) -> IResult<&[u8], Vec<u8>> {
    alt((
        parse_quoted_string,
        parse_list,
        parse_literal_as_argument,
        parse_sequence_set,
        map(parse_atom, |s| s.to_vec()),
    ))
    .parse(i)
}

fn parse_arguments(i: &[u8]) -> IResult<&[u8], Vec<Vec<u8>>> {
    many0(preceded(space1, parse_argument)).parse(i)
}

fn parse_rest_of_line(i: &[u8]) -> IResult<&[u8], Option<Vec<u8>>> {
    let (i, rest) = take_till(is_line_ending).parse(i)?;
    let text = if rest.is_empty() {
        None
    } else {
        Some(rest.to_vec())
    };
    Ok((i, text))
}

fn detect_trailing_literal(line: &[u8]) -> Option<(&[u8], u64)> {
    if let Some(brace_pos) = line.iter().rposition(|&c| c == b'{') {
        let lit = &line[brace_pos..];
        if let Ok((rem, (size, _))) = parse_literal_specifier(lit) {
            if rem.is_empty() {
                return Some((&line[..brace_pos], size));
            }
        }
    }
    None
}

fn parse_header_field_names(i: &[u8]) -> IResult<&[u8], Vec<String>> {
    let (i, _) = char('(').parse(i)?;
    let (i, _) = space0.parse(i)?;

    let mut fields = Vec::new();
    let mut rem = i;

    loop {
        if let Ok((after, _)) = char::<&[u8], Error<&[u8]>>(')').parse(rem) {
            return Ok((after, fields));
        }

        let (after, field) =
            take_while1(|c: u8| c.is_ascii_alphanumeric() || c == b'-').parse(rem)?;
        fields.push(String::from_utf8_lossy(field).to_string());

        let (after, _) = space0.parse(after)?;
        rem = after;
    }
}

fn parse_body_section(i: &[u8]) -> IResult<&[u8], FetchBodySection> {
    let (i, _) = alt((tag_no_case("BODY.PEEK"), tag_no_case("BODY"))).parse(i)?;
    let (i, _) = char('[').parse(i)?;

    if let Ok((after, _)) = char::<&[u8], Error<&[u8]>>(']').parse(i) {
        return Ok((after, FetchBodySection::Full));
    }

    let (i, section_name) = take_while1(|c: u8| c.is_ascii_alphanumeric() || c == b'.').parse(i)?;
    let section_upper = section_name.to_ascii_uppercase();

    let (i, section) = if section_upper == b"TEXT" {
        let (i, _) = char(']').parse(i)?;
        (i, FetchBodySection::Text)
    } else if section_upper == b"HEADER" {
        let (i, _) = char(']').parse(i)?;
        (i, FetchBodySection::Header { fields: None })
    } else if section_upper.starts_with(b"HEADER.FIELDS") {
        let (i, _) = space0.parse(i)?;
        let (i, fields) = opt(parse_header_field_names).parse(i)?;
        let (i, _) = char(']').parse(i)?;
        (i, FetchBodySection::Header { fields })
    } else if section_name
        .iter()
        .all(|&c| c.is_ascii_digit() || c == b'.')
    {
        let parts: Vec<u32> = String::from_utf8_lossy(section_name)
            .split('.')
            .filter_map(|s| s.parse().ok())
            .collect();
        let (i, _) = char(']').parse(i)?;
        (i, FetchBodySection::Part(parts))
    } else {
        let (i, _) = char(']').parse(i)?;
        (i, FetchBodySection::Unknown(section_name.to_vec()))
    };

    Ok((i, section))
}

fn extract_fetch_section_from_prefix(prefix: &[u8]) -> Option<FetchBodySection> {
    let end = prefix.iter().rposition(|b| !b.is_ascii_whitespace())? + 1;
    let token_start = prefix[..end]
        .iter()
        .rposition(|&b| b.is_ascii_whitespace() || b == b'(')
        .map_or(0, |pos| pos + 1);
    let token = &prefix[token_start..end];

    if token.eq_ignore_ascii_case(b"RFC822") {
        return Some(FetchBodySection::Full);
    } else if token.eq_ignore_ascii_case(b"RFC822.HEADER") {
        return Some(FetchBodySection::Header { fields: None });
    } else if token.eq_ignore_ascii_case(b"RFC822.TEXT") {
        return Some(FetchBodySection::Text);
    }

    let body_pos = prefix
        .windows(4)
        .rposition(|window| window.eq_ignore_ascii_case(b"BODY"))?;

    let section_start = &prefix[body_pos..];
    if let Ok((_, section)) = parse_body_section(section_start) {
        return Some(section);
    }
    None
}

#[derive(Debug)]
struct LiteralContext {
    prefix: Vec<u8>,
    literal_data: Vec<u8>,
    truncated: bool,
    too_large: bool,
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
    metadata: Vec<u8>,
    current_prefix: Vec<u8>,
    line_tail: Vec<u8>,
    literal_contexts: Vec<LiteralContext>,
    current_literal: Option<(LiteralInfo, Vec<u8>)>,
    parentheses: ParenthesisScanner,
    parentheses_closed: bool,
    literal_retain_left: usize,
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
                metadata: Vec::new(),
                current_prefix: Vec::new(),
                line_tail: Vec::new(),
                literal_contexts: Vec::new(),
                current_literal: None,
                parentheses: ParenthesisScanner::default(),
                parentheses_closed: false,
                literal_retain_left: retain_limit,
                raw_line,
                line_truncated,
                first_line: true,
                saw_cr: false,
                had_literal: false,
            },
        ))
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

                if let Some((prefix, literal_size)) = detect_trailing_literal(&self.line_tail) {
                    let marker_len = self.line_tail.len() - prefix.len();
                    let prefix_len = self.current_prefix.len().saturating_sub(marker_len);
                    self.current_prefix.truncate(prefix_len);
                    let literal_prefix = std::mem::take(&mut self.current_prefix);
                    self.current_literal = Some((
                        LiteralInfo::new(literal_size, false, self.literal_retain_left),
                        literal_prefix,
                    ));
                    self.had_literal = true;
                    self.first_line = false;
                    self.line_tail.clear();
                    return Ok((consumed, false));
                }

                self.line_tail.clear();
                self.first_line = false;
                if self.parentheses_closed || !self.parentheses.saw_open {
                    return Ok((consumed, true));
                }

                if append_capped(&mut self.metadata, b"\r\n", IMAP_MAX_LINE_SIZE) {
                    self.line_truncated = true;
                }
                append_tail_capped(&mut self.current_prefix, b"\r\n", IMAP_MAX_LINE_SIZE);
                continue;
            }

            let line_end = i[consumed..]
                .iter()
                .position(|&b| b == b'\r' || b == b'\n')
                .map(|pos| consumed + pos)
                .unwrap_or(i.len());
            let line_fragment = &i[consumed..line_end];

            if !line_fragment.is_empty() {
                if !self.parentheses_closed && self.parentheses.scan(line_fragment)?.is_some() {
                    self.parentheses_closed = true;
                }
                if append_capped(&mut self.metadata, line_fragment, IMAP_MAX_LINE_SIZE) {
                    self.line_truncated = true;
                }
                append_tail_capped(&mut self.current_prefix, line_fragment, IMAP_MAX_LINE_SIZE);
                append_tail_capped(&mut self.line_tail, line_fragment, IMAP_MAX_LINE_SIZE);
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

        let seq = self.seq_number.unwrap_or(0);
        let metadata = std::mem::take(&mut self.metadata);
        let literal_contexts = std::mem::take(&mut self.literal_contexts);
        let fetch = parse_fetch_data(seq, &metadata, literal_contexts);
        let fetch_data =
            if fetch.body_parts.is_empty() && fetch.uid.is_none() && fetch.flags.is_none() {
                None
            } else {
                Some(fetch)
            };

        ImapMessage {
            tag: None,
            message: ImapMessageType::Untagged {
                seq_number: self.seq_number,
                keyword: std::mem::take(&mut self.keyword),
                data: if metadata.is_empty() {
                    None
                } else {
                    Some(metadata)
                },
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

                let literal_size = literal.size;
                self.literal_retain_left = self
                    .literal_retain_left
                    .saturating_sub(literal.buffer.len());
                self.literal_contexts.push(LiteralContext {
                    prefix: std::mem::take(prefix),
                    literal_data: std::mem::take(&mut literal.buffer),
                    truncated: literal.truncated,
                    too_large: literal_size > u64::try_from(IMAP_MAX_BODY_SIZE).unwrap_or(u64::MAX),
                });
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
                let section = extract_fetch_section_from_prefix(prefix)
                    .unwrap_or_else(|| FetchBodySection::Unknown(prefix.clone()));
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
    let (i, arguments) = parse_arguments(i)?;
    let (i, _) = crlf.parse(i)?;

    let raw_len = start.len() - i.len() - 2;
    let (raw_line, line_truncated) = cap_raw_line(&start[..raw_len]);

    Ok((
        i,
        ImapMessage {
            tag: Some(tag_bytes.to_vec()),
            message: ImapMessageType::Command { command, arguments },
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
    let (i, text) = opt(preceded(space1, parse_rest_of_line)).parse(i)?;
    let (i, _) = crlf.parse(i)?;

    let raw_len = start.len() - i.len() - 2;
    let (raw_line, line_truncated) = cap_raw_line(&start[..raw_len]);

    Ok((
        i,
        ImapMessage {
            tag: Some(tag_bytes.to_vec()),
            message: ImapMessageType::Response {
                status,
                text: text.flatten(),
            },
            raw_line,
            line_truncated,
        },
    ))
}

fn extract_uid_from_data(data: &[u8]) -> Option<u32> {
    if let Some(pos) = data
        .windows(4)
        .position(|window| window.eq_ignore_ascii_case(b"UID "))
    {
        let after_uid = &data[pos + 4..];
        let num_end = after_uid
            .iter()
            .position(|&c| !c.is_ascii_digit())
            .unwrap_or(after_uid.len());
        if num_end > 0 {
            return std::str::from_utf8(&after_uid[..num_end])
                .ok()
                .and_then(|s| s.parse().ok());
        }
    }
    None
}

fn extract_rfc822_size_from_data(data: &[u8]) -> Option<u32> {
    if let Some(pos) = data
        .windows(11)
        .position(|window| window.eq_ignore_ascii_case(b"RFC822.SIZE"))
    {
        let after = &data[pos + 11..];
        let start = after.iter().position(|&c| c.is_ascii_digit())?;
        let num_start = &after[start..];
        let num_end = num_start
            .iter()
            .position(|&c| !c.is_ascii_digit())
            .unwrap_or(num_start.len());
        if num_end > 0 {
            return std::str::from_utf8(&num_start[..num_end])
                .ok()
                .and_then(|s| s.parse().ok());
        }
    }
    None
}

fn extract_flags_from_data(data: &[u8]) -> Option<Vec<String>> {
    if let Some(pos) = data
        .windows(6)
        .position(|window| window.eq_ignore_ascii_case(b"FLAGS "))
    {
        let after_flags = &data[pos + 6..];
        if let Some(open_pos) = after_flags.iter().position(|&c| c == b'(') {
            let after_open = &after_flags[open_pos + 1..];
            if let Some(close_pos) = after_open.iter().position(|&c| c == b')') {
                let flags_content = &after_open[..close_pos];
                let flags: Vec<String> = String::from_utf8_lossy(flags_content)
                    .split_whitespace()
                    .map(|s| s.to_string())
                    .collect();
                if !flags.is_empty() {
                    return Some(flags);
                }
            }
        }
    }
    None
}

fn parse_fetch_data(
    seq_number: u32, metadata: &[u8], literal_ctxs: Vec<LiteralContext>,
) -> FetchData {
    let mut fetch_data = FetchData {
        seq_number,
        uid: extract_uid_from_data(metadata),
        flags: extract_flags_from_data(metadata),
        rfc822_size: extract_rfc822_size_from_data(metadata),
        body_parts: Vec::new(),
        body_truncated: false,
        body_too_large: false,
        data_limit_reached: false,
    };

    for ctx in literal_ctxs {
        let LiteralContext {
            prefix,
            literal_data,
            truncated,
            too_large,
        } = ctx;

        if truncated {
            fetch_data.body_truncated = true;
            fetch_data.data_limit_reached = true;
        }
        if too_large {
            fetch_data.body_too_large = true;
        }
        let section = match extract_fetch_section_from_prefix(&prefix) {
            Some(section) => section,
            None => FetchBodySection::Unknown(prefix),
        };

        let email = match &section {
            FetchBodySection::Full => parse_email_content(literal_data),
            FetchBodySection::Header { .. } => {
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
            _ => None,
        };

        fetch_data.body_parts.push(FetchBodyPart { section, email });
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
    let (i, data) = parse_rest_of_line(i)?;
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
                data,
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
    let (i, text) = parse_rest_of_line(i)?;
    let (i, _) = crlf.parse(i)?;

    let raw_len = start.len() - i.len() - 2;
    let (raw_line, line_truncated) = cap_raw_line(&start[..raw_len]);

    Ok((
        i,
        ImapMessage {
            tag: None,
            message: ImapMessageType::Continuation { text },
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
            message: ImapMessageType::ContinuationData {
                data: data.to_vec(),
            },
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

pub fn imap_parse_message(i: &[u8], literal_retain_limit: usize) -> IResult<&[u8], ImapMessage> {
    alt((
        |input| parse_untagged_response(input, literal_retain_limit),
        parse_continuation,
        parse_tagged_response,
        parse_command,
    ))
    .parse(i)
}

fn parse_number64(i: &[u8]) -> IResult<&[u8], u64> {
    map_res(digit1, |digits: &[u8]| {
        digits.iter().try_fold(0_u64, |value, digit| {
            let value = value
                .checked_mul(10)
                .and_then(|value| value.checked_add(u64::from(*digit - b'0')))
                .ok_or(())?;
            if value <= IMAP_MAX_LITERAL_SIZE {
                Ok(value)
            } else {
                Err(())
            }
        })
    })
    .parse(i)
}

pub fn parse_literal_specifier(i: &[u8]) -> IResult<&[u8], (u64, bool)> {
    let (i, _) = char('{').parse(i)?;
    let (i, size) = parse_number64(i)?;
    let (i, is_plus) = opt(char('+')).parse(i)?;
    let (i, _) = char('}').parse(i)?;

    Ok((i, (size, is_plus.is_some())))
}

pub fn extract_literal_from_arguments(args: &[Vec<u8>]) -> Option<(u64, bool)> {
    for arg in args.iter().rev() {
        if let Ok((rem, (size, is_plus))) = parse_literal_specifier(arg) {
            if rem.is_empty() {
                return Some((size, is_plus));
            }
        }
    }
    None
}

#[inline]
fn is_header_name_char(b: u8) -> bool {
    b > 32 && b < 127 && b != b':'
}

#[inline]
fn email_header_name(i: &[u8]) -> IResult<&[u8], &str> {
    map_res(take_while1(is_header_name_char), std::str::from_utf8).parse(i)
}

#[inline]
fn email_hcolon(i: &[u8]) -> IResult<&[u8], char> {
    delimited(space0, char(':'), space0).parse(i)
}

fn parse_header_value(i: &[u8]) -> IResult<&[u8], String> {
    let mut value = Vec::new();
    let mut rem = i;

    loop {
        let (after_line, line) = take_till(is_line_ending).parse(rem)?;
        value.extend_from_slice(line);
        rem = after_line;

        let (after_eol, _) = crlf.parse(rem)?;
        rem = after_eol;

        if !rem.is_empty() && (rem[0] == b' ' || rem[0] == b'\t') {
            value.push(b' ');
            let (after_ws, _) = space0.parse(rem)?;
            rem = after_ws;
        } else {
            break;
        }
    }

    Ok((rem, String::from_utf8_lossy(&value).trim().to_string()))
}

fn skip_header_value(i: &[u8]) -> IResult<&[u8], ()> {
    let mut rem = i;

    loop {
        let (after_line, _) = take_till(is_line_ending).parse(rem)?;
        rem = after_line;

        let (after_eol, _) = crlf.parse(rem)?;
        rem = after_eol;

        if !rem.is_empty() && (rem[0] == b' ' || rem[0] == b'\t') {
            let (after_ws, _) = space0.parse(rem)?;
            rem = after_ws;
        } else {
            break;
        }
    }

    Ok((rem, ()))
}

fn message_header(i: &[u8]) -> IResult<&[u8], (String, String)> {
    let (i, name) = email_header_name(i)?;
    let (i, _) = email_hcolon(i)?;
    let (i, value) = parse_header_value(i)?;
    Ok((i, (name.to_string(), value)))
}

fn skip_message_header(i: &[u8]) -> IResult<&[u8], ()> {
    let (i, _) = email_header_name(i)?;
    let (i, _) = email_hcolon(i)?;
    skip_header_value(i)
}

pub struct ParsedEmailHeaders {
    pub headers: HashMap<String, Vec<String>>,
    pub too_many_headers: bool,
}

pub fn parse_email_headers(mut i: &[u8]) -> IResult<&[u8], ParsedEmailHeaders> {
    let mut headers: HashMap<String, Vec<String>> = HashMap::new();
    let mut header_count = 0usize;
    let mut too_many_headers = false;

    loop {
        if let Ok((_, _)) = crlf::<&[u8], Error<&[u8]>>.parse(i) {
            break;
        }
        if i.is_empty() {
            break;
        }

        if header_count < IMAP_MAX_HEADERS {
            let (rest, (name, value)) = message_header(i)?;
            headers.entry(name).or_default().push(value);
            i = rest;
        } else {
            too_many_headers = true;
            let (rest, _) = skip_message_header(i)?;
            i = rest;
        }
        header_count = header_count.saturating_add(1);
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
    let (headers, too_many_headers, headers_len, body_offset) = {
        let (rem, parsed_headers) = parse_email_headers(&data).ok()?;
        let headers_len = data.len().saturating_sub(rem.len());
        let (body, _) = crlf::<_, Error<_>>.parse(rem).ok()?;
        let body_offset = data.len().saturating_sub(body.len());
        (
            parsed_headers.headers,
            parsed_headers.too_many_headers,
            headers_len,
            body_offset,
        )
    };

    drop(data.drain(..body_offset));
    data.shrink_to_fit();

    Some(EmailData {
        headers,
        headers_len: headers_len as u32,
        body_offset: body_offset as u32,
        email_body: data,
        too_many_headers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_incomplete_at_each_boundary(
        input: &[u8], parser: for<'a> fn(&'a [u8]) -> IResult<&'a [u8], ImapMessage>,
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
        assert_incomplete_at_each_boundary(input, |input| {
            imap_parse_message(input, IMAP_MAX_BODY_SIZE)
        });
    }

    #[test]
    fn test_responses_incomplete_at_each_boundary() {
        for input in [
            b"A001 OK FETCH completed\r\n".as_slice(),
            b"* 23 EXISTS\r\n".as_slice(),
        ] {
            assert_incomplete_at_each_boundary(input, |input| {
                imap_parse_message(input, IMAP_MAX_BODY_SIZE)
            });
        }
    }

    #[test]
    fn test_fetch_literal_incomplete_at_each_boundary() {
        let input = b"* 1 FETCH (BODY[] {8}\r\n\0ab\r\n()z)\r\n";
        assert_incomplete_at_each_boundary(input, |input| {
            imap_parse_message(input, IMAP_MAX_BODY_SIZE)
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
                assert_eq!(fetch.body_parts.len(), 1);
                assert_eq!(fetch.body_parts[0].section, FetchBodySection::Full);
                assert!(fetch.body_parts[0].email.is_none());
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
                FetchBodySection::Header { fields: None },
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
                FetchBodySection::Header { fields: None },
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
            vec![
                FetchBodySection::Header { fields: None },
                FetchBodySection::Text,
            ]
        );
    }

    #[test]
    fn test_unterminated_list_at_line_end_is_invalid() {
        assert!(matches!(
            parse_command(b"A001 FETCH 1 (FLAGS\r\n"),
            Err(Err::Error(_))
        ));
    }

    #[test]
    fn test_parse_capability_command() {
        let i = b"A001 CAPABILITY\r\n";
        let (rem, msg) = parse_command(i).unwrap();
        assert!(rem.is_empty());
        assert_eq!(msg.tag, Some(b"A001".to_vec()));
        match msg.message {
            ImapMessageType::Command { command, arguments } => {
                assert_eq!(command, ImapCommand::Capability);
                assert!(arguments.is_empty());
            }
            _ => panic!("Expected Command"),
        }
    }

    #[test]
    fn test_parse_login_command() {
        let i = b"A001 LOGIN user pass\r\n";
        let (rem, msg) = parse_command(i).unwrap();
        assert!(rem.is_empty());
        assert_eq!(msg.tag, Some(b"A001".to_vec()));
        match msg.message {
            ImapMessageType::Command { command, arguments } => {
                assert_eq!(command, ImapCommand::Login);
                assert_eq!(arguments.len(), 2);
                assert_eq!(arguments[0], b"user".to_vec());
                assert_eq!(arguments[1], b"pass".to_vec());
            }
            _ => panic!("Expected Command"),
        }
    }

    #[test]
    fn test_parse_login_quoted_args() {
        let i = b"A001 LOGIN \"user name\" \"pass word\"\r\n";
        let (rem, msg) = parse_command(i).unwrap();
        assert!(rem.is_empty());
        match msg.message {
            ImapMessageType::Command { command, arguments } => {
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
            ImapMessageType::Command { command, arguments } => {
                assert_eq!(command, ImapCommand::Login);
                assert_eq!(arguments, [b"user\"name".to_vec(), b"pa\\ss".to_vec()]);
            }
            _ => panic!("Expected Command"),
        }
    }

    #[test]
    fn test_quoted_escapes_incomplete_at_each_boundary() {
        let input = b"A001 ID (\"name\" \"value ) ( \\\"quoted\\\" \\\\folder\")\r\n";
        assert_incomplete_at_each_boundary(input, |input| {
            imap_parse_message(input, IMAP_MAX_BODY_SIZE)
        });
    }

    #[test]
    fn test_parse_quoted_string_validation() {
        assert_eq!(
            parse_quoted_string(b"\"\""),
            Ok((b"".as_slice(), Vec::new()))
        );
        assert_eq!(
            parse_quoted_string("\"café\"".as_bytes()),
            Ok((b"".as_slice(), "café".as_bytes().to_vec()))
        );
        assert!(matches!(
            parse_quoted_string(b"\"bad\\escape\""),
            Err(Err::Error(_))
        ));
        assert!(matches!(
            parse_quoted_string(b"\"bad\0value\""),
            Err(Err::Error(_))
        ));
        assert!(matches!(
            parse_quoted_string(b"\"bad\r\n"),
            Err(Err::Error(_))
        ));
        assert!(matches!(
            parse_quoted_string(b"\"unfinished\\"),
            Err(Err::Incomplete(_))
        ));
    }

    #[test]
    fn test_parse_list_ignores_quoted_parentheses() {
        let i = b"A001 ID (\"name\" \"value ) ( \\\"quoted\\\" \\\\folder\")\r\n";
        let (rem, msg) = parse_command(i).unwrap();
        assert!(rem.is_empty());
        match msg.message {
            ImapMessageType::Command { command, arguments } => {
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
    fn test_fetch_parentheses_ignore_quoted_content() {
        let i = b"* 1 FETCH (BODYSTRUCTURE (\"TEXT\" \"PLAIN\" (\"NAME\" \"a)b\") NIL NIL \"7BIT\" 12 1))\r\nA001 OK FETCH completed\r\n";
        let (rem, msg) = parse_response(i, IMAP_MAX_BODY_SIZE).unwrap();
        assert_eq!(rem, b"A001 OK FETCH completed\r\n");
        assert!(matches!(
            msg.message,
            ImapMessageType::Untagged {
                seq_number: Some(1),
                ref keyword,
                ..
            } if keyword == b"FETCH"
        ));

        let (rem, msg) = parse_response(rem, IMAP_MAX_BODY_SIZE).unwrap();
        assert!(rem.is_empty());
        assert!(matches!(
            msg.message,
            ImapMessageType::Response {
                status: ImapResponseStatus::Ok,
                ..
            }
        ));
    }

    #[test]
    fn test_parse_select_command() {
        let i = b"A002 SELECT INBOX\r\n";
        let (rem, msg) = parse_command(i).unwrap();
        assert!(rem.is_empty());
        assert_eq!(msg.tag, Some(b"A002".to_vec()));
        match msg.message {
            ImapMessageType::Command { command, arguments } => {
                assert_eq!(command, ImapCommand::Select);
                assert_eq!(arguments.len(), 1);
                assert_eq!(arguments[0], b"INBOX".to_vec());
            }
            _ => panic!("Expected Command"),
        }
    }

    #[test]
    fn test_parse_untagged_ok_response() {
        let i = b"* OK IMAP4rev1 Service Ready\r\n";
        let (rem, msg) = parse_response(i, IMAP_MAX_BODY_SIZE).unwrap();
        assert!(rem.is_empty());
        assert_eq!(msg.tag, None);
        match msg.message {
            ImapMessageType::Untagged {
                seq_number,
                keyword,
                data,
                ..
            } => {
                assert_eq!(seq_number, None);
                assert_eq!(keyword, b"OK".to_vec());
                assert_eq!(data, Some(b"IMAP4rev1 Service Ready".to_vec()));
            }
            _ => panic!("Expected Untagged"),
        }
    }

    #[test]
    fn test_parse_untagged_capability_response() {
        let i = b"* CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN\r\n";
        let (rem, msg) = parse_response(i, IMAP_MAX_BODY_SIZE).unwrap();
        assert!(rem.is_empty());
        assert_eq!(msg.tag, None);
        match msg.message {
            ImapMessageType::Untagged {
                seq_number,
                keyword,
                data,
                ..
            } => {
                assert_eq!(seq_number, None);
                assert_eq!(keyword, b"CAPABILITY".to_vec());
                assert_eq!(data, Some(b"IMAP4rev1 STARTTLS AUTH=PLAIN".to_vec()));
            }
            _ => panic!("Expected Untagged"),
        }
    }

    #[test]
    fn test_parse_tagged_ok_response() {
        let i = b"A001 OK LOGIN completed\r\n";
        let (rem, msg) = parse_response(i, IMAP_MAX_BODY_SIZE).unwrap();
        assert!(rem.is_empty());
        assert_eq!(msg.tag, Some(b"A001".to_vec()));
        match msg.message {
            ImapMessageType::Response { status, text } => {
                assert_eq!(status, ImapResponseStatus::Ok);
                assert_eq!(text, Some(b"LOGIN completed".to_vec()));
            }
            _ => panic!("Expected Response"),
        }
    }

    #[test]
    fn test_parse_tagged_no_response() {
        let i = b"A001 NO Login failed\r\n";
        let (rem, msg) = parse_response(i, IMAP_MAX_BODY_SIZE).unwrap();
        assert!(rem.is_empty());
        assert_eq!(msg.tag, Some(b"A001".to_vec()));
        match msg.message {
            ImapMessageType::Response { status, text } => {
                assert_eq!(status, ImapResponseStatus::No);
                assert_eq!(text, Some(b"Login failed".to_vec()));
            }
            _ => panic!("Expected Response"),
        }
    }

    #[test]
    fn test_parse_continuation() {
        let i = b"+ Ready for additional command text\r\n";
        let (rem, msg) = parse_response(i, IMAP_MAX_BODY_SIZE).unwrap();
        assert!(rem.is_empty());
        assert_eq!(msg.tag, None);
        match msg.message {
            ImapMessageType::Continuation { text } => {
                assert_eq!(text, Some(b"Ready for additional command text".to_vec()));
            }
            _ => panic!("Expected Continuation"),
        }
    }

    #[test]
    fn test_parse_empty_continuation() {
        let i = b"+\r\n";
        let (rem, msg) = parse_response(i, IMAP_MAX_BODY_SIZE).unwrap();
        assert!(rem.is_empty());
        assert_eq!(msg.tag, None);
        match msg.message {
            ImapMessageType::Continuation { text } => {
                assert_eq!(text, None);
            }
            _ => panic!("Expected Continuation"),
        }
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
                data,
                ..
            } => {
                assert_eq!(seq_number, Some(172));
                assert_eq!(keyword, b"EXISTS".to_vec());
                assert_eq!(data, None);
            }
            _ => panic!("Expected Untagged"),
        }
    }

    #[test]
    fn test_parse_message_command() {
        let i = b"A001 NOOP\r\n";
        let (rem, msg) = imap_parse_message(i, IMAP_MAX_BODY_SIZE).unwrap();
        assert!(rem.is_empty());
        assert_eq!(msg.tag, Some(b"A001".to_vec()));
        match msg.message {
            ImapMessageType::Command { command, .. } => {
                assert_eq!(command, ImapCommand::Noop);
            }
            _ => panic!("Expected Command"),
        }
    }

    #[test]
    fn test_parse_message_response() {
        let i = b"* BYE Server shutting down\r\n";
        let (rem, msg) = imap_parse_message(i, IMAP_MAX_BODY_SIZE).unwrap();
        assert!(rem.is_empty());
        match msg.message {
            ImapMessageType::Untagged {
                seq_number,
                keyword,
                data,
                ..
            } => {
                assert_eq!(seq_number, None);
                assert_eq!(keyword, b"BYE".to_vec());
                assert_eq!(data, Some(b"Server shutting down".to_vec()));
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
        // RFC 3501 allows ASTRING-CHAR except '+' in tags
        let i = b"a.b-c_d:e<f>g NOOP\r\n";
        let (rem, msg) = parse_command(i).unwrap();
        assert!(rem.is_empty());
        assert_eq!(msg.tag, Some(b"a.b-c_d:e<f>g".to_vec()));
        match msg.message {
            ImapMessageType::Command { command, .. } => {
                assert_eq!(command, ImapCommand::Noop);
            }
            _ => panic!("Expected Command"),
        }
    }

    #[test]
    fn test_parse_continuation_data() {
        let i = b"AGRpZ2l0YWxpbnZlc3RpZ2F0b3JAbmV0d29ya3NpbXMuY29tAG5hcGllcjEyMw==\r\n";
        let (rem, msg) = parse_continuation_data(i).unwrap();
        assert!(rem.is_empty());
        assert_eq!(msg.tag, None);
        match msg.message {
            ImapMessageType::ContinuationData { data } => {
                assert_eq!(
                    data,
                    b"AGRpZ2l0YWxpbnZlc3RpZ2F0b3JAbmV0d29ya3NpbXMuY29tAG5hcGllcjEyMw==".to_vec()
                );
            }
            _ => panic!("Expected ContinuationData"),
        }
    }

    #[test]
    fn test_parse_literal_specifier_basic() {
        let i = b"{123}";
        let (rem, (size, is_plus)) = parse_literal_specifier(i).unwrap();
        assert!(rem.is_empty());
        assert_eq!(size, 123);
        assert!(!is_plus);
    }

    #[test]
    fn test_parse_literal_specifier_plus() {
        let i = b"{452+}";
        let (rem, (size, is_plus)) = parse_literal_specifier(i).unwrap();
        assert!(rem.is_empty());
        assert_eq!(size, 452);
        assert!(is_plus);
    }

    #[test]
    fn test_parse_literal_specifier_zero() {
        let i = b"{0}";
        let (rem, (size, is_plus)) = parse_literal_specifier(i).unwrap();
        assert!(rem.is_empty());
        assert_eq!(size, 0);
        assert!(!is_plus);
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
    fn test_extract_literal_from_arguments() {
        let args = vec![
            b"INBOX".to_vec(),
            b"(\\Seen)".to_vec(),
            b"\"01-Jan-2020 10:00:00 +0000\"".to_vec(),
            b"{452+}".to_vec(),
        ];
        let result = extract_literal_from_arguments(&args);
        assert_eq!(result, Some((452, true)));
    }

    #[test]
    fn test_extract_literal_from_arguments_no_literal() {
        let args = vec![b"INBOX".to_vec(), b"test".to_vec()];
        let result = extract_literal_from_arguments(&args);
        assert_eq!(result, None);
    }

    #[test]
    fn test_parse_email_headers_simple() {
        let email = b"From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nBody text";
        let (remaining, parsed) = parse_email_headers(email).unwrap();
        let headers = parsed.headers;
        assert!(!parsed.too_many_headers);
        assert_eq!(
            headers.get("From"),
            Some(&vec!["sender@example.com".to_string()])
        );
        assert_eq!(
            headers.get("To"),
            Some(&vec!["recipient@example.com".to_string()])
        );
        assert_eq!(headers.get("Subject"), Some(&vec!["Test".to_string()]));
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
            headers.get("Subject"),
            Some(&vec![
                "This is a very long subject that spans multiple lines".to_string()
            ])
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
            headers.get("Received"),
            Some(&vec![
                "from server1.example.com".to_string(),
                "from server2.example.com".to_string()
            ])
        );
        assert_eq!(
            headers.get("From"),
            Some(&vec!["sender@example.com".to_string()])
        );
        assert_eq!(remaining, b"\r\nBody");
    }

    #[test]
    fn test_parse_email_content() {
        let email = b"From: test@example.com\r\nSubject: Hello\r\n\r\nHello World!";
        let result = parse_email_content(email.to_vec()).unwrap();
        assert_eq!(
            result.headers.get("From"),
            Some(&vec!["test@example.com".to_string()])
        );
        assert_eq!(
            result.headers.get("Subject"),
            Some(&vec!["Hello".to_string()])
        );
        assert_eq!(result.email_body, b"Hello World!");
    }

    #[test]
    fn test_parse_append_command_with_literal() {
        let i = b"4 APPEND INBOX {452+}\r\n";
        let (rem, msg) = parse_command(i).unwrap();
        assert!(rem.is_empty());
        assert_eq!(msg.tag, Some(b"4".to_vec()));
        match msg.message {
            ImapMessageType::Command { command, arguments } => {
                assert_eq!(command, ImapCommand::Append);
                assert_eq!(arguments.len(), 2);
                assert_eq!(arguments[0], b"INBOX".to_vec());
                assert_eq!(arguments[1], b"{452+}".to_vec());
                let result = extract_literal_from_arguments(&arguments);
                assert_eq!(result, Some((452, true)));
            }
            _ => panic!("Expected Command"),
        }
    }

    #[test]
    fn test_parse_uid_fetch_sequence_set_star() {
        let i = b"6 UID FETCH 1:* (FLAGS)\r\n";
        let (rem, msg) = parse_command(i).unwrap();
        assert!(rem.is_empty());
        match msg.message {
            ImapMessageType::Command { command, arguments } => {
                assert_eq!(command, ImapCommand::Uid);
                assert_eq!(arguments.len(), 3);
                assert_eq!(arguments[0], b"FETCH".to_vec());
                assert_eq!(arguments[1], b"1:*".to_vec());
                assert_eq!(arguments[2], b"(FLAGS)".to_vec());
            }
            _ => panic!("Expected Command"),
        }
    }

    #[test]
    fn test_parse_fetch_single_star() {
        let i = b"A005 FETCH * FLAGS\r\n";
        let (rem, msg) = parse_command(i).unwrap();
        assert!(rem.is_empty());
        match msg.message {
            ImapMessageType::Command { command, arguments } => {
                assert_eq!(command, ImapCommand::Fetch);
                assert_eq!(arguments[0], b"*".to_vec());
                assert_eq!(arguments[1], b"FLAGS".to_vec());
            }
            _ => panic!("Expected Command"),
        }
    }

    #[test]
    fn test_untagged_response() {
        let i = b"* OK IMAP4rev1 Server Ready\r\n";
        let (rem, msg) = parse_response(i, IMAP_MAX_BODY_SIZE).unwrap();
        assert!(rem.is_empty());
        match msg.message {
            ImapMessageType::Untagged {
                seq_number,
                keyword,
                ..
            } => {
                assert_eq!(seq_number, None);
                assert_eq!(keyword, b"OK".to_vec());
            }
            _ => panic!("Expected Untagged"),
        }
    }

    #[test]
    fn test_parse_fetch_response_with_seq_number() {
        let i = b"* 1 FETCH (UID 1 FLAGS (\\Recent \\Seen))\r\n";
        let (rem, msg) = parse_response(i, IMAP_MAX_BODY_SIZE).unwrap();
        assert!(rem.is_empty());
        match msg.message {
            ImapMessageType::Untagged {
                seq_number,
                keyword,
                data,
                fetch_data,
            } => {
                assert_eq!(seq_number, Some(1));
                assert_eq!(keyword, b"FETCH".to_vec());
                assert_eq!(data, Some(b"(UID 1 FLAGS (\\Recent \\Seen))".to_vec()));
                let fetch = fetch_data.unwrap();
                assert_eq!(fetch.seq_number, 1);
                assert_eq!(fetch.uid, Some(1));
                assert!(fetch.flags.is_some());
                let flags = fetch.flags.unwrap();
                assert!(flags.contains(&"\\Recent".to_string()));
                assert!(flags.contains(&"\\Seen".to_string()));
            }
            _ => panic!("Expected Untagged"),
        }
    }

    #[test]
    fn test_parse_uid_fetch_body_peek_header_fields() {
        let i = b"7 UID fetch 1 (UID RFC822.SIZE FLAGS BODY.PEEK[HEADER.FIELDS (From To Cc Bcc Subject Date Message-ID Priority X-Priority References Newsgroups In-Reply-To Content-Type)])\r\n";
        let (rem, msg) = parse_command(i).unwrap();
        assert!(rem.is_empty());
        match msg.message {
            ImapMessageType::Command { command, arguments } => {
                assert_eq!(command, ImapCommand::Uid);
                assert_eq!(arguments.len(), 3);
                assert_eq!(arguments[0], b"fetch".to_vec());
                assert_eq!(arguments[1], b"1".to_vec());
                assert!(arguments[2].starts_with(b"(UID"));
                assert!(arguments[2].ends_with(b"])"));
            }
            _ => panic!("Expected Command"),
        }
    }

    #[test]
    fn test_parse_fetch_response_with_inline_literal() {
        let i = b"* 1 FETCH (UID 1 RFC822.SIZE 452 FLAGS (\\Recent \\Seen) BODY[HEADER.FIELDS (FROM TO)] {46}\r\nFrom: test@example.com\r\nTo: user@example.com\r\n)\r\n";
        let (rem, msg) = parse_response(i, IMAP_MAX_BODY_SIZE).unwrap();
        assert!(rem.is_empty());
        match msg.message {
            ImapMessageType::Untagged {
                seq_number,
                keyword,
                data,
                fetch_data,
            } => {
                assert_eq!(seq_number, Some(1));
                assert_eq!(keyword, b"FETCH".to_vec());
                let data = data.unwrap();
                assert!(data.starts_with(b"(UID 1"));
                assert!(data.ends_with(b")"));
                assert!(!data.windows(4).any(|w| w == b"From"));
                let fetch = fetch_data.unwrap();
                assert_eq!(fetch.seq_number, 1);
                assert_eq!(fetch.uid, Some(1));
                assert_eq!(fetch.rfc822_size, Some(452));
                assert!(fetch.flags.is_some());
                assert_eq!(fetch.body_parts.len(), 1);
                let part = &fetch.body_parts[0];
                assert!(matches!(part.section, FetchBodySection::Header { .. }));
                assert!(part.email.is_some());
                let email = part.email.as_ref().unwrap();
                assert_eq!(
                    email.headers.get("From"),
                    Some(&vec!["test@example.com".to_string()])
                );
                assert_eq!(
                    email.headers.get("To"),
                    Some(&vec!["user@example.com".to_string()])
                );
            }
            _ => panic!("Expected Untagged"),
        }
    }

    #[test]
    fn test_parse_fetch_no_literal_still_works() {
        let i = b"* 1 FETCH (UID 1 FLAGS (\\Seen))\r\n";
        let (rem, msg) = parse_response(i, IMAP_MAX_BODY_SIZE).unwrap();
        assert!(rem.is_empty());
        match msg.message {
            ImapMessageType::Untagged {
                seq_number,
                keyword,
                data,
                fetch_data,
            } => {
                assert_eq!(seq_number, Some(1));
                assert_eq!(keyword, b"FETCH".to_vec());
                assert_eq!(data, Some(b"(UID 1 FLAGS (\\Seen))".to_vec()));
                let fetch = fetch_data.unwrap();
                assert_eq!(fetch.seq_number, 1);
                assert_eq!(fetch.uid, Some(1));
                assert!(fetch.body_parts.is_empty());
            }
            _ => panic!("Expected Untagged"),
        }
    }

    #[test]
    fn test_parse_fetch_with_literal_plus() {
        let i = b"* 2 FETCH (BODY[] {10+}\r\nHelloWorld)\r\n";
        let (rem, msg) = parse_response(i, IMAP_MAX_BODY_SIZE).unwrap();
        assert!(rem.is_empty());
        match msg.message {
            ImapMessageType::Untagged {
                seq_number,
                keyword,
                data,
                fetch_data,
            } => {
                assert_eq!(seq_number, Some(2));
                assert_eq!(keyword, b"FETCH".to_vec());
                let data = data.unwrap();
                assert!(data.starts_with(b"(BODY[]"));
                assert!(!data.windows(10).any(|w| w == b"HelloWorld"));
                let fetch = fetch_data.unwrap();
                assert_eq!(fetch.seq_number, 2);
                assert_eq!(fetch.body_parts.len(), 1);
                let part = &fetch.body_parts[0];
                assert_eq!(part.section, FetchBodySection::Full);
                assert!(part.email.is_none());
            }
            _ => panic!("Expected Untagged"),
        }
    }

    #[test]
    fn test_detect_trailing_literal() {
        assert_eq!(
            detect_trailing_literal(b"BODY[] {100}"),
            Some((b"BODY[] ".as_slice(), 100))
        );
        assert_eq!(
            detect_trailing_literal(b"{50+}"),
            Some((b"".as_slice(), 50))
        );
        assert_eq!(detect_trailing_literal(b"no literal here"), None);
        assert_eq!(detect_trailing_literal(b"middle {10} stuff"), None);
    }

    #[test]
    fn test_parse_body_section_full() {
        let (rem, section) = parse_body_section(b"BODY[]").unwrap();
        assert!(rem.is_empty());
        assert_eq!(section, FetchBodySection::Full);

        let (rem, section) = parse_body_section(b"BODY.PEEK[]").unwrap();
        assert!(rem.is_empty());
        assert_eq!(section, FetchBodySection::Full);
    }

    #[test]
    fn test_parse_body_section_header() {
        let (rem, section) = parse_body_section(b"BODY[HEADER]").unwrap();
        assert!(rem.is_empty());
        assert_eq!(section, FetchBodySection::Header { fields: None });
    }

    #[test]
    fn test_parse_body_section_header_fields() {
        let (rem, section) = parse_body_section(b"BODY[HEADER.FIELDS (FROM TO)]").unwrap();
        assert!(rem.is_empty());
        match section {
            FetchBodySection::Header { fields } => {
                let fields = fields.unwrap();
                assert!(fields.contains(&"FROM".to_string()));
                assert!(fields.contains(&"TO".to_string()));
            }
            _ => panic!("Expected Header section"),
        }
    }

    #[test]
    fn test_parse_body_section_text() {
        let (rem, section) = parse_body_section(b"BODY[TEXT]").unwrap();
        assert!(rem.is_empty());
        assert_eq!(section, FetchBodySection::Text);
    }

    #[test]
    fn test_parse_body_section_part() {
        let (rem, section) = parse_body_section(b"BODY[1.2]").unwrap();
        assert!(rem.is_empty());
        assert_eq!(section, FetchBodySection::Part(vec![1, 2]));
    }

    #[test]
    fn test_extract_fetch_section_from_prefix() {
        let prefix = b"(UID 1 RFC822.SIZE 452 BODY[HEADER.FIELDS (FROM TO)] ";
        let section = extract_fetch_section_from_prefix(prefix);
        assert!(section.is_some());
        match section.unwrap() {
            FetchBodySection::Header { fields } => {
                assert!(fields.is_some());
            }
            _ => panic!("Expected Header section"),
        }

        let prefix = b"(BODY[] ";
        let section = extract_fetch_section_from_prefix(prefix);
        assert_eq!(section, Some(FetchBodySection::Full));

        assert_eq!(
            extract_fetch_section_from_prefix(b"(RFC822 "),
            Some(FetchBodySection::Full)
        );
        assert_eq!(
            extract_fetch_section_from_prefix(b"(rFc822.HeAdEr "),
            Some(FetchBodySection::Header { fields: None })
        );
        assert_eq!(
            extract_fetch_section_from_prefix(b"(RFC822.text "),
            Some(FetchBodySection::Text)
        );
        assert_eq!(extract_fetch_section_from_prefix(b"(RFC822.SIZE "), None);
    }

    #[test]
    fn test_parse_fetch_data_with_email() {
        let i = b"* 1 FETCH (BODY[] {38}\r\nFrom: test@example.com\r\n\r\nHello World!)\r\n";
        let (rem, msg) = parse_response(i, IMAP_MAX_BODY_SIZE).unwrap();
        assert!(rem.is_empty());
        match msg.message {
            ImapMessageType::Untagged { fetch_data, .. } => {
                let fetch = fetch_data.unwrap();
                assert_eq!(fetch.seq_number, 1);
                assert_eq!(fetch.body_parts.len(), 1);
                let part = &fetch.body_parts[0];
                assert_eq!(part.section, FetchBodySection::Full);
                let email = part.email.as_ref().unwrap();
                assert_eq!(
                    email.headers.get("From"),
                    Some(&vec!["test@example.com".to_string()])
                );
                assert_eq!(email.email_body, b"Hello World!");
            }
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
                assert_eq!(fetch.body_parts.len(), 1);
                let part = &fetch.body_parts[0];
                match &part.section {
                    FetchBodySection::Header { fields } => {
                        assert!(fields.is_none());
                    }
                    _ => panic!("Expected Header section"),
                }
                let email = part.email.as_ref().unwrap();
                assert_eq!(
                    email.headers.get("From"),
                    Some(&vec!["test@example.com".to_string()])
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
                assert_eq!(fetch.body_parts.len(), 1);
                let part = &fetch.body_parts[0];
                assert_eq!(part.section, FetchBodySection::Full);
                let email = part.email.as_ref().unwrap();
                assert_eq!(
                    email.headers.get("From"),
                    Some(&vec!["test@example.com".to_string()])
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
                let mut fetch = fetch_data.unwrap();
                assert_eq!(fetch.body_parts.len(), 2);
                assert_eq!(
                    fetch.body_parts[0].section,
                    FetchBodySection::Header { fields: None }
                );
                assert_eq!(fetch.body_parts[1].section, FetchBodySection::Text);

                let email = fetch.take_email().unwrap();
                assert_eq!(
                    email.headers.get("From"),
                    Some(&vec!["test@example.com".to_string()])
                );
                assert_eq!(email.email_body, b"Hello World!");
            }
            _ => panic!("Expected Untagged"),
        }
    }

    #[test]
    fn test_merged_email_header_and_text() {
        let i = b"* 1 FETCH (BODY[HEADER] {24}\r\nFrom: test@example.com\r\n BODY[TEXT] {12}\r\nHello World!)\r\n";
        let (_, msg) = parse_response(i, IMAP_MAX_BODY_SIZE).unwrap();
        match msg.message {
            ImapMessageType::Untagged { fetch_data, .. } => {
                let mut fetch = fetch_data.unwrap();
                let merged = fetch.take_email().expect("Should have merged email");
                assert_eq!(
                    merged.headers.get("From"),
                    Some(&vec!["test@example.com".to_string()])
                );
                assert_eq!(merged.email_body, b"Hello World!");
            }
            _ => panic!("Expected Untagged"),
        }
    }

    #[test]
    fn test_merged_email_single_full() {
        let i = b"* 1 FETCH (BODY[] {38}\r\nFrom: test@example.com\r\n\r\nHello World!)\r\n";
        let (_, msg) = parse_response(i, IMAP_MAX_BODY_SIZE).unwrap();
        match msg.message {
            ImapMessageType::Untagged { fetch_data, .. } => {
                let mut fetch = fetch_data.unwrap();
                assert_eq!(fetch.body_parts.len(), 1);
                let merged = fetch.take_email().expect("Should have merged email");
                assert_eq!(
                    merged.headers.get("From"),
                    Some(&vec!["test@example.com".to_string()])
                );
                assert_eq!(merged.email_body, b"Hello World!");
            }
            _ => panic!("Expected Untagged"),
        }
    }

    #[test]
    fn test_tag_allows_bracket() {
        let i = b"A]001 NOOP\r\n";
        let (rem, msg) = parse_command(i).unwrap();
        assert!(rem.is_empty());
        assert_eq!(msg.tag, Some(b"A]001".to_vec()));
    }

    #[test]
    fn test_raw_line_command() {
        let i = b"A001 LOGIN user pass\r\n";
        let (rem, msg) = parse_command(i).unwrap();
        assert!(rem.is_empty());
        assert_eq!(msg.raw_line, b"A001 LOGIN user pass".to_vec());
    }

    #[test]
    fn test_raw_line_tagged_response() {
        let i = b"A001 OK LOGIN completed\r\n";
        let (rem, msg) = parse_response(i, IMAP_MAX_BODY_SIZE).unwrap();
        assert!(rem.is_empty());
        assert_eq!(msg.raw_line, b"A001 OK LOGIN completed".to_vec());
    }

    #[test]
    fn test_raw_line_untagged_response() {
        let i = b"* OK IMAP4rev1 Service Ready\r\n";
        let (rem, msg) = parse_response(i, IMAP_MAX_BODY_SIZE).unwrap();
        assert!(rem.is_empty());
        assert_eq!(msg.raw_line, b"* OK IMAP4rev1 Service Ready".to_vec());
    }

    #[test]
    fn test_raw_line_continuation() {
        let i = b"+ Ready for additional command text\r\n";
        let (rem, msg) = parse_response(i, IMAP_MAX_BODY_SIZE).unwrap();
        assert!(rem.is_empty());
        assert_eq!(
            msg.raw_line,
            b"+ Ready for additional command text".to_vec()
        );
    }

    #[test]
    fn test_raw_line_continuation_data() {
        let i = b"AGRpZ2l0YWxpbnZlc3RpZ2F0b3I=\r\n";
        let (rem, msg) = parse_continuation_data(i).unwrap();
        assert!(rem.is_empty());
        assert_eq!(msg.raw_line, b"AGRpZ2l0YWxpbnZlc3RpZ2F0b3I=".to_vec());
    }

    #[test]
    fn test_raw_line_untagged_with_seq_number() {
        let i = b"* 172 EXISTS\r\n";
        let (rem, msg) = parse_response(i, IMAP_MAX_BODY_SIZE).unwrap();
        assert!(rem.is_empty());
        assert_eq!(msg.raw_line, b"* 172 EXISTS".to_vec());
    }

    #[test]
    fn test_parse_email_content_with_content_disposition() {
        let email = b"From: sender@example.com\r\nTo: recipient@example.com\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Disposition: inline\r\nSubject: Test\r\n\r\nThis is the body.";
        let res = parse_email_content(email.to_vec()).unwrap();
        assert_eq!(
            res.headers.get("From"),
            Some(&vec!["sender@example.com".to_string()])
        );
        assert_eq!(
            res.headers.get("Content-Disposition"),
            Some(&vec!["inline".to_string()])
        );
        assert_eq!(
            res.headers.get("Content-Type"),
            Some(&vec!["text/plain; charset=UTF-8".to_string()])
        );
        assert_eq!(res.email_body, b"This is the body.");
    }
}
