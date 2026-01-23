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

use nom::branch::alt;
use nom::bytes::complete::{tag, tag_no_case, take, take_till, take_while, take_while1};
use nom::character::complete::{char, crlf, digit1, space0, space1};
use nom::character::is_space;
use nom::combinator::{map, map_res, opt, value};
use nom::multi::many0;
use nom::sequence::{delimited, preceded};
use nom::IResult;
use nom7 as nom;
use std::collections::HashMap;
use std::fmt;

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
    pub raw_data: Vec<u8>,
    pub email: Option<EmailData>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct FetchData {
    pub seq_number: u32,
    pub uid: Option<u32>,
    pub flags: Option<Vec<String>>,
    pub rfc822_size: Option<u32>,
    pub body_parts: Vec<FetchBodyPart>,
}

#[derive(Debug, Clone)]
pub struct LiteralInfo {
    pub size: u32,
    pub is_literal_plus: bool,
    pub bytes_consumed: u32,
    pub buffer: Vec<u8>,
}

impl LiteralInfo {
    pub fn new(size: u32, is_literal_plus: bool) -> Self {
        Self {
            size,
            is_literal_plus,
            bytes_consumed: 0,
            buffer: Vec::with_capacity(size as usize),
        }
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

fn parse_tag(i: &[u8]) -> IResult<&[u8], &[u8]> {
    take_while1(is_tag_char)(i)
}

fn parse_command_keyword(i: &[u8]) -> IResult<&[u8], ImapCommand> {
    alt((
        alt((
            value(ImapCommand::Capability, tag_no_case(b"CAPABILITY")),
            value(ImapCommand::Noop, tag_no_case(b"NOOP")),
            value(ImapCommand::Logout, tag_no_case(b"LOGOUT")),
            value(ImapCommand::StartTls, tag_no_case(b"STARTTLS")),
            value(ImapCommand::Authenticate, tag_no_case(b"AUTHENTICATE")),
            value(ImapCommand::Login, tag_no_case(b"LOGIN")),
        )),
        alt((
            value(ImapCommand::Select, tag_no_case(b"SELECT")),
            value(ImapCommand::Examine, tag_no_case(b"EXAMINE")),
            value(ImapCommand::Create, tag_no_case(b"CREATE")),
            value(ImapCommand::Delete, tag_no_case(b"DELETE")),
            value(ImapCommand::Rename, tag_no_case(b"RENAME")),
            value(ImapCommand::Subscribe, tag_no_case(b"SUBSCRIBE")),
            value(ImapCommand::Unsubscribe, tag_no_case(b"UNSUBSCRIBE")),
            value(ImapCommand::List, tag_no_case(b"LIST")),
            value(ImapCommand::Lsub, tag_no_case(b"LSUB")),
            value(ImapCommand::Status, tag_no_case(b"STATUS")),
            value(ImapCommand::Append, tag_no_case(b"APPEND")),
        )),
        alt((
            value(ImapCommand::Check, tag_no_case(b"CHECK")),
            value(ImapCommand::Close, tag_no_case(b"CLOSE")),
            value(ImapCommand::Expunge, tag_no_case(b"EXPUNGE")),
            value(ImapCommand::Search, tag_no_case(b"SEARCH")),
            value(ImapCommand::Fetch, tag_no_case(b"FETCH")),
            value(ImapCommand::Store, tag_no_case(b"STORE")),
            value(ImapCommand::Copy, tag_no_case(b"COPY")),
            value(ImapCommand::Uid, tag_no_case(b"UID")),
            value(ImapCommand::Idle, tag_no_case(b"IDLE")),
            value(ImapCommand::Id, tag_no_case(b"ID")),
        )),
        map(parse_atom, |cmd| ImapCommand::Unknown(cmd.to_vec())),
    ))(i)
}

fn parse_status(i: &[u8]) -> IResult<&[u8], ImapResponseStatus> {
    alt((
        value(ImapResponseStatus::Ok, tag_no_case(b"OK")),
        value(ImapResponseStatus::No, tag_no_case(b"NO")),
        value(ImapResponseStatus::Bad, tag_no_case(b"BAD")),
        value(ImapResponseStatus::PreAuth, tag_no_case(b"PREAUTH")),
        value(ImapResponseStatus::Bye, tag_no_case(b"BYE")),
    ))(i)
}

fn parse_quoted_string(i: &[u8]) -> IResult<&[u8], &[u8]> {
    delimited(
        char('"'),
        take_while(|c| c != b'"' && c != b'\r' && c != b'\n'),
        char('"'),
    )(i)
}

fn parse_atom(i: &[u8]) -> IResult<&[u8], &[u8]> {
    take_while1(is_atom_char)(i)
}

fn parse_list(i: &[u8]) -> IResult<&[u8], Vec<u8>> {
    let (i, _) = char('(')(i)?;

    let mut depth = 1;
    let mut end_pos = 0;

    for (pos, &byte) in i.iter().enumerate() {
        match byte {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    end_pos = pos;
                    break;
                }
            }
            _ => {}
        }
    }

    if depth != 0 {
        return Err(nom::Err::Error(nom::error::Error::new(
            i,
            nom::error::ErrorKind::Char,
        )));
    }

    let content = &i[..end_pos];
    let rem = &i[end_pos + 1..];

    let mut result = vec![b'('];
    result.extend_from_slice(content);
    result.push(b')');
    Ok((rem, result))
}

fn parse_literal_as_argument(i: &[u8]) -> IResult<&[u8], Vec<u8>> {
    let start = i;
    let (i, _) = char('{')(i)?;
    let (i, _) = digit1(i)?;
    let (i, _) = opt(char('+'))(i)?;
    let (i, _) = char('}')(i)?;
    let len = start.len() - i.len();
    Ok((i, start[..len].to_vec()))
}

#[inline]
fn is_sequence_set_char(c: u8) -> bool {
    c.is_ascii_digit() || c == b':' || c == b'*' || c == b','
}

fn parse_sequence_set(i: &[u8]) -> IResult<&[u8], Vec<u8>> {
    let (rem, seq) = take_while1(is_sequence_set_char)(i)?;
    // Must start with a digit or '*'
    if !seq.is_empty() && (seq[0].is_ascii_digit() || seq[0] == b'*') {
        Ok((rem, seq.to_vec()))
    } else {
        Err(nom::Err::Error(nom::error::Error::new(
            i,
            nom::error::ErrorKind::Char,
        )))
    }
}

fn parse_argument(i: &[u8]) -> IResult<&[u8], Vec<u8>> {
    alt((
        map(parse_quoted_string, |s| s.to_vec()),
        parse_list,
        parse_literal_as_argument,
        parse_sequence_set,
        map(parse_atom, |s| s.to_vec()),
    ))(i)
}

fn parse_arguments(i: &[u8]) -> IResult<&[u8], Vec<Vec<u8>>> {
    many0(preceded(space1, parse_argument))(i)
}

fn parse_rest_of_line(i: &[u8]) -> IResult<&[u8], Option<Vec<u8>>> {
    let (i, rest) = take_till(is_line_ending)(i)?;
    let text = if rest.is_empty() {
        None
    } else {
        Some(rest.to_vec())
    };
    Ok((i, text))
}

fn detect_trailing_literal(line: &[u8]) -> Option<(&[u8], u32)> {
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
    let (i, _) = char('(')(i)?;
    let (i, _) = space0(i)?;

    let mut fields = Vec::new();
    let mut rem = i;

    loop {
        if let Ok((after, _)) = char::<&[u8], nom::error::Error<&[u8]>>(')')(rem) {
            return Ok((after, fields));
        }

        let (after, field) = take_while1(|c: u8| c.is_ascii_alphanumeric() || c == b'-')(rem)?;
        fields.push(String::from_utf8_lossy(field).to_string());

        let (after, _) = space0(after)?;
        rem = after;
    }
}

fn parse_body_section(i: &[u8]) -> IResult<&[u8], FetchBodySection> {
    let (i, _) = alt((tag_no_case(b"BODY.PEEK"), tag_no_case(b"BODY")))(i)?;
    let (i, _) = char('[')(i)?;

    if let Ok((after, _)) = char::<&[u8], nom::error::Error<&[u8]>>(']')(i) {
        return Ok((after, FetchBodySection::Full));
    }

    let (i, section_name) = take_while1(|c: u8| c.is_ascii_alphanumeric() || c == b'.')(i)?;
    let section_upper = section_name.to_ascii_uppercase();

    let (i, section) = if section_upper == b"TEXT" {
        let (i, _) = char(']')(i)?;
        (i, FetchBodySection::Text)
    } else if section_upper == b"HEADER" {
        let (i, _) = char(']')(i)?;
        (i, FetchBodySection::Header { fields: None })
    } else if section_upper.starts_with(b"HEADER.FIELDS") {
        let (i, _) = space0(i)?;
        let (i, fields) = opt(parse_header_field_names)(i)?;
        let (i, _) = char(']')(i)?;
        (i, FetchBodySection::Header { fields })
    } else if section_name
        .iter()
        .all(|&c| c.is_ascii_digit() || c == b'.')
    {
        let parts: Vec<u32> = String::from_utf8_lossy(section_name)
            .split('.')
            .filter_map(|s| s.parse().ok())
            .collect();
        let (i, _) = char(']')(i)?;
        (i, FetchBodySection::Part(parts))
    } else {
        let (i, _) = char(']')(i)?;
        (i, FetchBodySection::Unknown(section_name.to_vec()))
    };

    Ok((i, section))
}

fn extract_body_section_from_prefix(prefix: &[u8]) -> Option<FetchBodySection> {
    let prefix_upper = prefix.to_ascii_uppercase();
    let body_pos = prefix_upper.windows(4).rposition(|w| w == b"BODY")?;

    let section_start = &prefix[body_pos..];
    if let Ok((_, section)) = parse_body_section(section_start) {
        return Some(section);
    }
    None
}

#[derive(Debug, Clone)]
struct LiteralContext {
    prefix: Vec<u8>,
    literal_data: Vec<u8>,
}

fn parse_response_data_with_literals(i: &[u8]) -> IResult<&[u8], (Vec<u8>, Vec<LiteralContext>)> {
    let mut result = Vec::new();
    let mut literal_ctxs = Vec::new();
    let mut rem = i;
    let mut curr_prefix = Vec::new();
    let mut par_open: usize = 0;
    let mut par_close: usize = 0;

    loop {
        let (after_line, line_content) = take_till(is_line_ending)(rem)?;

        if let Some((prefix, literal_size)) = detect_trailing_literal(line_content) {
            curr_prefix.extend_from_slice(prefix);
            result.extend_from_slice(prefix);
            result.extend_from_slice(&line_content[prefix.len()..]);

            par_open += prefix.iter().filter(|&&c| c == b'(').count();
            par_close += prefix.iter().filter(|&&c| c == b')').count();

            let (after_crlf, _) = crlf(after_line)?;

            let (after_literal, literal_data): (&[u8], &[u8]) =
                take(literal_size as usize)(after_crlf)?;
            result.extend_from_slice(literal_data);

            literal_ctxs.push(LiteralContext {
                prefix: curr_prefix.clone(),
                literal_data: literal_data.to_vec(),
            });

            curr_prefix.clear();
            rem = after_literal;
        } else {
            curr_prefix.extend_from_slice(line_content);
            result.extend_from_slice(line_content);

            let (after_crlf, _) = crlf(after_line)?;

            par_open += line_content.iter().filter(|&&c| c == b'(').count();
            par_close += line_content.iter().filter(|&&c| c == b')').count();

            if par_open > 0 && par_open == par_close {
                return Ok((after_crlf, (result, literal_ctxs)));
            }

            if after_crlf.is_empty() || (par_open == 0 && par_close == 0) {
                return Ok((after_crlf, (result, literal_ctxs)));
            }

            rem = after_crlf;
            curr_prefix.extend_from_slice(b"\r\n");
            result.extend_from_slice(b"\r\n");
        }
    }
}

pub fn parse_command(i: &[u8]) -> IResult<&[u8], ImapMessage> {
    let start = i;
    let (i, tag_bytes) = parse_tag(i)?;
    let (i, _) = space1(i)?;
    let (i, command) = parse_command_keyword(i)?;
    let (i, arguments) = parse_arguments(i)?;
    let (i, _) = crlf(i)?;

    let raw_len = start.len() - i.len() - 2;
    let raw_line = start[..raw_len].to_vec();

    Ok((
        i,
        ImapMessage {
            tag: Some(tag_bytes.to_vec()),
            message: ImapMessageType::Command { command, arguments },
            raw_line,
        },
    ))
}

fn parse_tagged_response(i: &[u8]) -> IResult<&[u8], ImapMessage> {
    let start = i;
    let (i, tag_bytes) = parse_tag(i)?;
    let (i, _) = space1(i)?;
    let (i, status) = parse_status(i)?;
    let (i, text) = opt(preceded(space1, parse_rest_of_line))(i)?;
    let (i, _) = crlf(i)?;

    let raw_len = start.len() - i.len() - 2;
    let raw_line = start[..raw_len].to_vec();

    Ok((
        i,
        ImapMessage {
            tag: Some(tag_bytes.to_vec()),
            message: ImapMessageType::Response {
                status,
                text: text.flatten(),
            },
            raw_line,
        },
    ))
}

fn extract_uid_from_data(data: &[u8]) -> Option<u32> {
    let data_upper = data.to_ascii_uppercase();
    if let Some(pos) = data_upper.windows(4).position(|w| w == b"UID ") {
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
    let data_upper = data.to_ascii_uppercase();
    if let Some(pos) = data_upper.windows(11).position(|w| w == b"RFC822.SIZE") {
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
    let data_upper = data.to_ascii_uppercase();
    if let Some(pos) = data_upper.windows(6).position(|w| w == b"FLAGS ") {
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
    seq_number: u32, raw_data: &[u8], literal_ctxs: Vec<LiteralContext>,
) -> FetchData {
    let mut fetch_data = FetchData {
        seq_number,
        uid: extract_uid_from_data(raw_data),
        flags: extract_flags_from_data(raw_data),
        rfc822_size: extract_rfc822_size_from_data(raw_data),
        body_parts: Vec::new(),
    };

    for ctx in literal_ctxs {
        let section = extract_body_section_from_prefix(&ctx.prefix)
            .unwrap_or(FetchBodySection::Unknown(ctx.prefix.clone()));

        let email = match &section {
            FetchBodySection::Full => parse_email_content(&ctx.literal_data)
                .ok()
                .map(|(_, email)| email),
            FetchBodySection::Header { .. } => {
                parse_email_headers(&ctx.literal_data)
                    .ok()
                    .map(|(_, headers)| EmailData {
                        headers,
                        ..Default::default()
                    })
            }
            FetchBodySection::Text => Some(EmailData {
                email_body: ctx.literal_data.clone(),
                ..Default::default()
            }),
            _ => None,
        };

        fetch_data.body_parts.push(FetchBodyPart {
            section,
            raw_data: ctx.literal_data,
            email,
        });
    }

    fetch_data
}

fn parse_untagged_response(i: &[u8]) -> IResult<&[u8], ImapMessage> {
    let start = i;
    let (i, _) = tag(b"* ")(i)?;
    let (i, first_token) = take_while1(|c: u8| c.is_ascii_alphanumeric())(i)?;

    let (seq_number, keyword, rem) = if first_token.iter().all(|c| c.is_ascii_digit()) {
        let (i, _) = space1(i)?;
        let (i, kw) = take_while1(|c: u8| c.is_ascii_alphanumeric())(i)?;
        let seq: u32 = std::str::from_utf8(first_token)
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        (Some(seq), kw, i)
    } else {
        (None, first_token, i)
    };

    let is_fetch = keyword.eq_ignore_ascii_case(b"FETCH");

    let (i, _) = space0(rem)?;

    let (i, data, fetch_data, raw_line) = if is_fetch {
        let first_line_end = i.iter().position(|&c| c == b'\r').unwrap_or(i.len());
        let raw_len = start.len() - i.len() + first_line_end;
        let mut raw_line = start[..raw_len].to_vec();

        let (i, (data, literal_ctxs)) = parse_response_data_with_literals(i)?;

        // When FETCH spans multiple lines due to literals, raw_line only
        // captures the first line and misses the closing parenthesis.
        if !literal_ctxs.is_empty() && raw_line.last() != Some(&b')') {
            raw_line.push(b')');
        }
        let seq = seq_number.unwrap_or(0);
        let fetch = parse_fetch_data(seq, &data, literal_ctxs);
        let fetch_opt =
            if fetch.body_parts.is_empty() && fetch.uid.is_none() && fetch.flags.is_none() {
                None
            } else {
                Some(fetch)
            };
        (
            i,
            if data.is_empty() { None } else { Some(data) },
            fetch_opt,
            raw_line,
        )
    } else {
        let (i, data) = parse_rest_of_line(i)?;
        let (i, _) = crlf(i)?;
        let raw_len = start.len() - i.len() - 2;
        let raw_line = start[..raw_len].to_vec();
        (i, data, None, raw_line)
    };

    Ok((
        i,
        ImapMessage {
            tag: None,
            message: ImapMessageType::Untagged {
                seq_number,
                keyword: keyword.to_vec(),
                data,
                fetch_data,
            },
            raw_line,
        },
    ))
}

fn parse_continuation(i: &[u8]) -> IResult<&[u8], ImapMessage> {
    let start = i;
    let (i, _) = tag(b"+")(i)?;
    let (i, _) = space0(i)?;
    let (i, text) = parse_rest_of_line(i)?;
    let (i, _) = crlf(i)?;

    let raw_len = start.len() - i.len() - 2;
    let raw_line = start[..raw_len].to_vec();

    Ok((
        i,
        ImapMessage {
            tag: None,
            message: ImapMessageType::Continuation { text },
            raw_line,
        },
    ))
}

pub fn parse_continuation_data(i: &[u8]) -> IResult<&[u8], ImapMessage> {
    let (i, data) = take_till(is_line_ending)(i)?;
    let (i, _) = crlf(i)?;

    let raw_line = data.to_vec();

    Ok((
        i,
        ImapMessage {
            tag: None,
            message: ImapMessageType::ContinuationData {
                data: data.to_vec(),
            },
            raw_line,
        },
    ))
}

pub fn parse_response(i: &[u8]) -> IResult<&[u8], ImapMessage> {
    alt((
        parse_untagged_response,
        parse_continuation,
        parse_tagged_response,
    ))(i)
}

pub fn imap_parse_message(i: &[u8]) -> IResult<&[u8], ImapMessage> {
    alt((
        parse_untagged_response,
        parse_continuation,
        parse_tagged_response,
        parse_command,
    ))(i)
}

pub fn parse_literal_specifier(i: &[u8]) -> IResult<&[u8], (u32, bool)> {
    let (i, _) = char('{')(i)?;
    let (i, size_bytes) = digit1(i)?;
    let (i, is_plus) = opt(char('+'))(i)?;
    let (i, _) = char('}')(i)?;

    let size_str = std::str::from_utf8(size_bytes).unwrap_or("0");
    let size = size_str.parse::<u32>().unwrap_or(0);

    Ok((i, (size, is_plus.is_some())))
}

pub fn extract_literal_from_arguments(args: &[Vec<u8>]) -> Option<(u32, bool)> {
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
    map_res(take_while1(is_header_name_char), std::str::from_utf8)(i)
}

#[inline]
fn email_hcolon(i: &[u8]) -> IResult<&[u8], char> {
    delimited(space0, char(':'), space0)(i)
}

fn parse_header_value(i: &[u8]) -> IResult<&[u8], String> {
    let mut value = Vec::new();
    let mut rem = i;

    loop {
        let (after_line, line) = take_till(is_line_ending)(rem)?;
        value.extend_from_slice(line);
        rem = after_line;

        let (after_eol, _) = crlf(rem)?;
        rem = after_eol;

        if !rem.is_empty() && is_space(rem[0]) {
            value.push(b' ');
            let (after_ws, _) = space0(rem)?;
            rem = after_ws;
        } else {
            break;
        }
    }

    Ok((rem, String::from_utf8_lossy(&value).trim().to_string()))
}

fn message_header(i: &[u8]) -> IResult<&[u8], (String, String)> {
    let (i, name) = email_header_name(i)?;
    let (i, _) = email_hcolon(i)?;
    let (i, value) = parse_header_value(i)?;
    Ok((i, (name.to_string(), value)))
}

pub fn parse_email_headers(mut i: &[u8]) -> IResult<&[u8], HashMap<String, Vec<String>>> {
    let mut headers: HashMap<String, Vec<String>> = HashMap::new();

    loop {
        if let Ok((_, _)) = crlf::<&[u8], nom::error::Error<&[u8]>>(i) {
            break;
        }
        if i.is_empty() {
            break;
        }

        let (rest, (name, value)) = message_header(i)?;
        headers
            .entry(name.to_lowercase().replace('-', "_"))
            .or_default()
            .push(value);
        i = rest;
    }

    Ok((i, headers))
}

pub fn parse_email_content(i: &[u8]) -> IResult<&[u8], EmailData> {
    let (rem, headers) = parse_email_headers(i)?;
    let headers_len = i.len() - rem.len();
    let (body, _) = crlf(rem)?;
    let body_offset = i.len() - body.len();

    Ok((
        &[],
        EmailData {
            headers,
            headers_len: headers_len as u32,
            body_offset: body_offset as u32,
            email_body: body.to_vec(),
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let (rem, msg) = parse_response(i).unwrap();
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
        let (rem, msg) = parse_response(i).unwrap();
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
        let (rem, msg) = parse_response(i).unwrap();
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
        let (rem, msg) = parse_response(i).unwrap();
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
        let (rem, msg) = parse_response(i).unwrap();
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
        let (rem, msg) = parse_response(i).unwrap();
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
        let (rem, msg) = parse_response(i).unwrap();
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
        let (rem, msg) = imap_parse_message(i).unwrap();
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
        let (rem, msg) = imap_parse_message(i).unwrap();
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
        let (remaining, headers) = parse_email_headers(email).unwrap();
        assert_eq!(
            headers.get("from"),
            Some(&vec!["sender@example.com".to_string()])
        );
        assert_eq!(
            headers.get("to"),
            Some(&vec!["recipient@example.com".to_string()])
        );
        assert_eq!(headers.get("subject"), Some(&vec!["Test".to_string()]));
        assert_eq!(remaining, b"\r\nBody text");
    }

    #[test]
    fn test_parse_email_headers_folded() {
        let email =
            b"Subject: This is a very long\r\n subject that spans multiple lines\r\n\r\nBody";
        let (rem, headers) = parse_email_headers(email).unwrap();
        assert_eq!(
            headers.get("subject"),
            Some(&vec![
                "This is a very long subject that spans multiple lines".to_string()
            ])
        );
        assert_eq!(rem, b"\r\nBody");
    }

    #[test]
    fn test_parse_email_headers_repeated() {
        let email = b"Received: from server1.example.com\r\nReceived: from server2.example.com\r\nFrom: sender@example.com\r\n\r\nBody";
        let (remaining, headers) = parse_email_headers(email).unwrap();
        assert_eq!(
            headers.get("received"),
            Some(&vec![
                "from server1.example.com".to_string(),
                "from server2.example.com".to_string()
            ])
        );
        assert_eq!(
            headers.get("from"),
            Some(&vec!["sender@example.com".to_string()])
        );
        assert_eq!(remaining, b"\r\nBody");
    }

    #[test]
    fn test_parse_email_content() {
        let email = b"From: test@example.com\r\nSubject: Hello\r\n\r\nHello World!";
        let (rem, result) = parse_email_content(email).unwrap();
        assert!(rem.is_empty());
        assert_eq!(
            result.headers.get("from"),
            Some(&vec!["test@example.com".to_string()])
        );
        assert_eq!(
            result.headers.get("subject"),
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
        let (rem, msg) = parse_response(i).unwrap();
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
        let (rem, msg) = parse_response(i).unwrap();
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
        let (rem, msg) = parse_response(i).unwrap();
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
                assert!(data.windows(4).any(|w| w == b"From"));
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
                    email.headers.get("from"),
                    Some(&vec!["test@example.com".to_string()])
                );
                assert_eq!(
                    email.headers.get("to"),
                    Some(&vec!["user@example.com".to_string()])
                );
            }
            _ => panic!("Expected Untagged"),
        }
    }

    #[test]
    fn test_parse_fetch_no_literal_still_works() {
        let i = b"* 1 FETCH (UID 1 FLAGS (\\Seen))\r\n";
        let (rem, msg) = parse_response(i).unwrap();
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
        let (rem, msg) = parse_response(i).unwrap();
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
                assert!(data.windows(10).any(|w| w == b"HelloWorld"));
                let fetch = fetch_data.unwrap();
                assert_eq!(fetch.seq_number, 2);
                assert_eq!(fetch.body_parts.len(), 1);
                let part = &fetch.body_parts[0];
                assert_eq!(part.section, FetchBodySection::Full);
                assert_eq!(part.raw_data, b"HelloWorld");
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
    fn test_extract_body_section_from_prefix() {
        let prefix = b"(UID 1 RFC822.SIZE 452 BODY[HEADER.FIELDS (FROM TO)] ";
        let section = extract_body_section_from_prefix(prefix);
        assert!(section.is_some());
        match section.unwrap() {
            FetchBodySection::Header { fields } => {
                assert!(fields.is_some());
            }
            _ => panic!("Expected Header section"),
        }

        let prefix = b"(BODY[] ";
        let section = extract_body_section_from_prefix(prefix);
        assert_eq!(section, Some(FetchBodySection::Full));
    }

    #[test]
    fn test_parse_fetch_data_with_email() {
        let i = b"* 1 FETCH (BODY[] {38}\r\nFrom: test@example.com\r\n\r\nHello World!)\r\n";
        let (rem, msg) = parse_response(i).unwrap();
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
                    email.headers.get("from"),
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
        let (rem, msg) = parse_response(i).unwrap();
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
                    email.headers.get("from"),
                    Some(&vec!["test@example.com".to_string()])
                );
                assert!(email.email_body.is_empty());
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
        let (rem, msg) = parse_response(i).unwrap();
        assert!(rem.is_empty());
        assert_eq!(msg.raw_line, b"A001 OK LOGIN completed".to_vec());
    }

    #[test]
    fn test_raw_line_untagged_response() {
        let i = b"* OK IMAP4rev1 Service Ready\r\n";
        let (rem, msg) = parse_response(i).unwrap();
        assert!(rem.is_empty());
        assert_eq!(msg.raw_line, b"* OK IMAP4rev1 Service Ready".to_vec());
    }

    #[test]
    fn test_raw_line_continuation() {
        let i = b"+ Ready for additional command text\r\n";
        let (rem, msg) = parse_response(i).unwrap();
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
        let (rem, msg) = parse_response(i).unwrap();
        assert!(rem.is_empty());
        assert_eq!(msg.raw_line, b"* 172 EXISTS".to_vec());
    }

    #[test]
    fn test_parse_email_content_with_content_disposition() {
        let email = b"From: sender@example.com\r\nTo: recipient@example.com\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Disposition: inline\r\nSubject: Test\r\n\r\nThis is the body.";
        let (rem, res) = parse_email_content(email).unwrap();
        assert!(rem.is_empty());
        assert_eq!(
            res.headers.get("from"),
            Some(&vec!["sender@example.com".to_string()])
        );
        assert_eq!(
            res.headers.get("content_disposition"),
            Some(&vec!["inline".to_string()])
        );
        assert_eq!(
            res.headers.get("content_type"),
            Some(&vec!["text/plain; charset=UTF-8".to_string()])
        );
        assert_eq!(res.email_body, b"This is the body.");
    }
}
