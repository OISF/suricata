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

use crate::common::nom7::take_until_and_consume;
use nom7::branch::alt;
use nom7::bytes::complete::{tag, take, take_till, take_until, take_while};
use nom7::character::complete::char;
use nom7::combinator::{complete, opt, rest, value};
use nom7::error::{make_error, ErrorKind};
use nom7::{Err, IResult};
use std;
use std::collections::HashMap;

#[derive(Clone)]
pub struct HeaderTokens<'a> {
    pub tokens: HashMap<&'a [u8], &'a [u8]>,
}

fn mime_parse_value_delimited(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let (input, _) = char('"')(input)?;
    let mut escaping = false;
    for i in 0..input.len() {
        if input[i] == b'\\' {
            escaping = true;
        } else {
            if input[i] == b'"' && !escaping {
                return Ok((&input[i + 1..], &input[..i]));
            }
            // unescape can be processed later
            escaping = false;
        }
    }
    // should fail
    let (input, value) = take_until("\"")(input)?;
    let (input, _) = char('"')(input)?;
    return Ok((input, value));
}

fn mime_parse_value_until_semicolon(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let (input, value) = alt((take_till(|ch: u8| ch == b';'), rest))(input)?;
    for i in 0..value.len() {
        if !is_mime_space(value[value.len() - i - 1]) {
            return Ok((input, &value[..value.len() - i]));
        }
    }
    return Ok((input, value));
}

#[inline]
fn is_mime_space(ch: u8) -> bool {
    ch == 0x20 || ch == 0x09 || ch == 0x0a || ch == 0x0d
}

pub fn mime_parse_header_token(input: &[u8]) -> IResult<&[u8], (&[u8], &[u8])> {
    // from RFC2047 : like ch.is_ascii_whitespace but without 0x0c FORM-FEED
    let (input, _) = take_while(is_mime_space)(input)?;
    let (input, name) = take_until("=")(input)?;
    let (input, _) = char('=')(input)?;
    let (input, value) =
        alt((mime_parse_value_delimited, mime_parse_value_until_semicolon))(input)?;
    let (input, _) = take_while(is_mime_space)(input)?;
    let (input, _) = opt(complete(char(';')))(input)?;
    return Ok((input, (name, value)));
}

fn mime_parse_header_tokens(input: &[u8]) -> IResult<&[u8], HeaderTokens> {
    let (mut input, _) = take_until_and_consume(b";")(input)?;
    let mut tokens = HashMap::new();
    while !input.is_empty() {
        match mime_parse_header_token(input) {
            Ok((rem, t)) => {
                tokens.insert(t.0, t.1);
                // should never happen
                debug_validate_bug_on!(input.len() == rem.len());
                if input.len() == rem.len() {
                    //infinite loop
                    return Err(Err::Error(make_error(input, ErrorKind::Eof)));
                }
                input = rem;
            }
            Err(_) => {
                // keep first tokens is error in remaining buffer
                break;
            }
        }
    }
    return Ok((input, HeaderTokens { tokens }));
}

pub fn mime_find_header_token<'a>(
    header: &'a [u8], token: &[u8], sections_values: &'a mut Vec<u8>,
) -> Option<&'a [u8]> {
    match mime_parse_header_tokens(header) {
        Ok((_rem, t)) => {
            // in case of multiple sections for the parameter cf RFC2231
            let mut current_section_slice = Vec::new();

            // look for the specific token
            match t.tokens.get(token) {
                // easy nominal case
                Some(value) => return Some(value),
                None => {
                    // check for initial section of a parameter
                    current_section_slice.extend_from_slice(token);
                    current_section_slice.extend_from_slice(b"*0");
                    match t.tokens.get(&current_section_slice[..]) {
                        Some(value) => {
                            sections_values.extend_from_slice(value);
                            let l = current_section_slice.len();
                            current_section_slice[l - 1] = b'1';
                        }
                        None => return None,
                    }
                }
            }

            let mut current_section_seen = 1;
            // we have at least the initial section
            // try looping until we do not find anymore a next section
            loop {
                match t.tokens.get(&current_section_slice[..]) {
                    Some(value) => {
                        sections_values.extend_from_slice(value);
                        current_section_seen += 1;
                        let nbdigits = current_section_slice.len() - token.len() - 1;
                        current_section_slice.truncate(current_section_slice.len() - nbdigits);
                        current_section_slice
                            .extend_from_slice(current_section_seen.to_string().as_bytes());
                    }
                    None => return Some(sections_values),
                }
            }
        }
        Err(_) => {
            return None;
        }
    }
}

pub(crate) const RS_MIME_MAX_TOKEN_LEN: usize = 255;

#[derive(Debug)]
enum MimeParserState {
    Start,
    Header,
    HeaderEnd,
    Chunk,
    BoundaryWaitingForEol,
}

impl Default for MimeParserState {
    fn default() -> Self {
        MimeParserState::Start
    }
}

#[derive(Debug, Default)]
pub struct MimeStateHTTP {
    boundary: Vec<u8>,
    filename: Vec<u8>,
    state: MimeParserState,
}

#[repr(u8)]
#[derive(Copy, Clone, PartialOrd, PartialEq, Eq)]
pub enum MimeParserResult {
    MimeNeedsMore = 0,
    MimeFileOpen = 1,
    MimeFileChunk = 2,
    MimeFileClose = 3,
}

fn mime_parse_skip_line(input: &[u8]) -> IResult<&[u8], MimeParserState> {
    let (input, _) = take_till(|ch: u8| ch == b'\n')(input)?;
    let (input, _) = char('\n')(input)?;
    return Ok((input, MimeParserState::Start));
}

fn mime_parse_boundary_regular<'a>(
    boundary: &[u8], input: &'a [u8],
) -> IResult<&'a [u8], MimeParserState> {
    let (input, _) = tag(boundary)(input)?;
    let (input, _) = take_till(|ch: u8| ch == b'\n')(input)?;
    let (input, _) = char('\n')(input)?;
    return Ok((input, MimeParserState::Header));
}

// Number of characters after boundary, without end of line, before changing state to streaming
const MIME_BOUNDARY_MAX_BEFORE_EOL: usize = 128;
const MIME_HEADER_MAX_LINE: usize = 4096;

fn mime_parse_boundary_missing_eol<'a>(
    boundary: &[u8], input: &'a [u8],
) -> IResult<&'a [u8], MimeParserState> {
    let (input, _) = tag(boundary)(input)?;
    let (input, _) = take(MIME_BOUNDARY_MAX_BEFORE_EOL)(input)?;
    return Ok((input, MimeParserState::BoundaryWaitingForEol));
}

fn mime_parse_boundary<'a>(boundary: &[u8], input: &'a [u8]) -> IResult<&'a [u8], MimeParserState> {
    let r = mime_parse_boundary_regular(boundary, input);
    if r.is_ok() {
        return r;
    }
    let r2 = mime_parse_skip_line(input);
    if r2.is_ok() {
        return r2;
    }
    return mime_parse_boundary_missing_eol(boundary, input);
}

fn mime_consume_until_eol(input: &[u8]) -> IResult<&[u8], bool> {
    return alt((value(true, mime_parse_skip_line), value(false, rest)))(input);
}

pub fn mime_parse_header_line(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let (input, name) = take_till(|ch: u8| ch == b':')(input)?;
    let (input, _) = char(':')(input)?;
    let (input, _) = take_while(is_mime_space)(input)?;
    return Ok((input, name));
}

// s2 is already lower case
pub fn slice_equals_lowercase(s1: &[u8], s2: &[u8]) -> bool {
    if s1.len() == s2.len() {
        for i in 0..s1.len() {
            if s1[i].to_ascii_lowercase() != s2[i] {
                return false;
            }
        }
        return true;
    }
    return false;
}

fn mime_parse_headers<'a>(
    ctx: &mut MimeStateHTTP, i: &'a [u8],
) -> IResult<&'a [u8], (MimeParserState, bool, bool)> {
    let mut fileopen = false;
    let mut errored = false;
    let mut input = i;
    while !input.is_empty() {
        if let Ok((input2, line)) = take_until::<_, &[u8], nom7::error::Error<&[u8]>>("\r\n")(input)
        {
            if let Ok((value, name)) = mime_parse_header_line(line) {
                if slice_equals_lowercase(name, "content-disposition".as_bytes()) {
                    let mut sections_values = Vec::new();
                    if let Some(filename) =
                        mime_find_header_token(value, "filename".as_bytes(), &mut sections_values)
                    {
                        if !filename.is_empty() {
                            ctx.filename = Vec::with_capacity(filename.len());
                            fileopen = true;
                            for c in filename {
                                // unescape
                                if *c != b'\\' {
                                    ctx.filename.push(*c);
                                }
                            }
                        }
                    }
                }
                if value.is_empty() {
                    errored = true;
                }
            } else if !line.is_empty() {
                errored = true;
            }
            let (input3, _) = tag("\r\n")(input2)?;
            input = input3;
            if line.is_empty() || (line.len() == 1 && line[0] == b'\r') {
                return Ok((input, (MimeParserState::HeaderEnd, fileopen, errored)));
            }
        } else {
            // guard against too long header lines
            if input.len() > MIME_HEADER_MAX_LINE {
                return Ok((
                    input,
                    (MimeParserState::BoundaryWaitingForEol, fileopen, errored),
                ));
            }
            if input.len() < i.len() {
                return Ok((input, (MimeParserState::Header, fileopen, errored)));
            } // else only an incomplete line, ask for more
            return Err(Err::Error(make_error(input, ErrorKind::Eof)));
        }
    }
    return Ok((input, (MimeParserState::Header, fileopen, errored)));
}

type NomTakeError<'a> = Err<nom7::error::Error<&'a [u8]>>;

fn mime_consume_chunk<'a>(boundary: &[u8], input: &'a [u8]) -> IResult<&'a [u8], bool> {
    let r: Result<(&[u8], &[u8]), NomTakeError> = take_until("\r\n")(input);
    if let Ok((input, line)) = r {
        let (next_line, _) = tag("\r\n")(input)?;
        if next_line.len() < boundary.len() {
            if next_line == &boundary[..next_line.len()] {
                if !line.is_empty() {
                    // consume as chunk up to eol (not consuming eol)
                    return Ok((input, false));
                }
                // new line beignning like boundary, with nothin to consume as chunk : request more
                return Err(Err::Error(make_error(input, ErrorKind::Eof)));
            }
            // not like boundary : consume everything as chunk
            return Ok((&input[input.len()..], false));
        } // else
        if &next_line[..boundary.len()] == boundary {
            // end of file with boundary, consume eol but do not consume boundary
            return Ok((next_line, true));
        }
        // not like boundary : consume everything as chunk
        return Ok((next_line, false));
    } else {
        return Ok((&input[input.len()..], false));
    }
}

pub const MIME_EVENT_FLAG_INVALID_HEADER: u32 = 0x01;
pub const MIME_EVENT_FLAG_NO_FILEDATA: u32 = 0x02;

fn mime_process(ctx: &mut MimeStateHTTP, i: &[u8]) -> (MimeParserResult, u32, u32) {
    let mut input = i;
    let mut consumed = 0;
    let mut warnings = 0;
    while !input.is_empty() {
        match ctx.state {
            MimeParserState::Start => {
                if let Ok((rem, next)) = mime_parse_boundary(&ctx.boundary, input) {
                    ctx.state = next;
                    consumed += (input.len() - rem.len()) as u32;
                    input = rem;
                } else {
                    return (MimeParserResult::MimeNeedsMore, consumed, warnings);
                }
            }
            MimeParserState::BoundaryWaitingForEol => {
                if let Ok((rem, found)) = mime_consume_until_eol(input) {
                    if found {
                        ctx.state = MimeParserState::Header;
                    }
                    consumed += (input.len() - rem.len()) as u32;
                    input = rem;
                } else {
                    // should never happen
                    return (MimeParserResult::MimeNeedsMore, consumed, warnings);
                }
            }
            MimeParserState::Header => {
                if let Ok((rem, (next, fileopen, err))) = mime_parse_headers(ctx, input) {
                    ctx.state = next;
                    consumed += (input.len() - rem.len()) as u32;
                    input = rem;
                    if err {
                        warnings |= MIME_EVENT_FLAG_INVALID_HEADER;
                    }
                    if fileopen {
                        return (MimeParserResult::MimeFileOpen, consumed, warnings);
                    }
                } else {
                    return (MimeParserResult::MimeNeedsMore, consumed, warnings);
                }
            }
            MimeParserState::HeaderEnd => {
                // check if we start with the boundary
                // and transition to chunk, or empty file and back to start
                if input.len() < ctx.boundary.len() {
                    if input == &ctx.boundary[..input.len()] {
                        return (MimeParserResult::MimeNeedsMore, consumed, warnings);
                    }
                    ctx.state = MimeParserState::Chunk;
                } else if input[..ctx.boundary.len()] == ctx.boundary {
                    ctx.state = MimeParserState::Start;
                    if !ctx.filename.is_empty() {
                        warnings |= MIME_EVENT_FLAG_NO_FILEDATA;
                    }
                    ctx.filename.clear();
                    return (MimeParserResult::MimeFileClose, consumed, warnings);
                } else {
                    ctx.state = MimeParserState::Chunk;
                }
            }
            MimeParserState::Chunk => {
                if let Ok((rem, eof)) = mime_consume_chunk(&ctx.boundary, input) {
                    consumed += (input.len() - rem.len()) as u32;
                    if eof {
                        ctx.state = MimeParserState::Start;
                        ctx.filename.clear();
                        return (MimeParserResult::MimeFileClose, consumed, warnings);
                    } else {
                        // + 2 for \r\n
                        if rem.len() < ctx.boundary.len() + 2 {
                            return (MimeParserResult::MimeFileChunk, consumed, warnings);
                        }
                        input = rem;
                    }
                } else {
                    return (MimeParserResult::MimeNeedsMore, consumed, warnings);
                }
            }
        }
    }
    return (MimeParserResult::MimeNeedsMore, consumed, warnings);
}

pub fn mime_state_init(i: &[u8]) -> Option<MimeStateHTTP> {
    let mut sections_values = Vec::new();
    if let Some(value) = mime_find_header_token(i, "boundary".as_bytes(), &mut sections_values) {
        if value.len() <= RS_MIME_MAX_TOKEN_LEN {
            let mut r = MimeStateHTTP {
                boundary: Vec::with_capacity(2 + value.len()),
                ..Default::default()
            };
            // start wih 2 additional hyphens
            r.boundary.push(b'-');
            r.boundary.push(b'-');
            for c in value {
                // unescape
                if *c != b'\\' {
                    r.boundary.push(*c);
                }
            }
            return Some(r);
        }
    }
    return None;
}

#[no_mangle]
pub unsafe extern "C" fn SCMimeStateInit(input: *const u8, input_len: u32) -> *mut MimeStateHTTP {
    let slice = build_slice!(input, input_len as usize);

    if let Some(ctx) = mime_state_init(slice) {
        let boxed = Box::new(ctx);
        return Box::into_raw(boxed) as *mut _;
    }
    return std::ptr::null_mut();
}

#[no_mangle]
pub unsafe extern "C" fn SCMimeParse(
    ctx: &mut MimeStateHTTP, input: *const u8, input_len: u32, consumed: *mut u32,
    warnings: *mut u32,
) -> MimeParserResult {
    let slice = build_slice!(input, input_len as usize);
    let (r, c, w) = mime_process(ctx, slice);
    *consumed = c;
    *warnings = w;
    return r;
}

#[no_mangle]
pub unsafe extern "C" fn SCMimeStateGetFilename(
    ctx: &mut MimeStateHTTP, buffer: *mut *const u8, filename_len: *mut u16,
) {
    if !ctx.filename.is_empty() {
        *buffer = ctx.filename.as_ptr();
        if ctx.filename.len() < u16::MAX.into() {
            *filename_len = ctx.filename.len() as u16;
        } else {
            *filename_len = u16::MAX;
        }
    } else {
        *buffer = std::ptr::null_mut();
        *filename_len = 0;
    }
}

#[no_mangle]
pub unsafe extern "C" fn SCMimeStateFree(ctx: &mut MimeStateHTTP) {
    std::mem::drop(Box::from_raw(ctx));
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_mime_find_header_token() {
        let mut outvec = Vec::new();
        let undelimok = mime_find_header_token(
            "attachment; filename=test;".as_bytes(),
            "filename".as_bytes(),
            &mut outvec,
        );
        assert_eq!(undelimok, Some("test".as_bytes()));

        let delimok = mime_find_header_token(
            "attachment; filename=\"test2\";".as_bytes(),
            "filename".as_bytes(),
            &mut outvec,
        );
        assert_eq!(delimok, Some("test2".as_bytes()));

        let escaped = mime_find_header_token(
            "attachment; filename=\"test\\\"2\";".as_bytes(),
            "filename".as_bytes(),
            &mut outvec,
        );
        assert_eq!(escaped, Some("test\\\"2".as_bytes()));

        let evasion_othertoken = mime_find_header_token(
            "attachment; dummy=\"filename=wrong\"; filename=real;".as_bytes(),
            "filename".as_bytes(),
            &mut outvec,
        );
        assert_eq!(evasion_othertoken, Some("real".as_bytes()));

        let evasion_suffixtoken = mime_find_header_token(
            "attachment; notafilename=wrong; filename=good;".as_bytes(),
            "filename".as_bytes(),
            &mut outvec,
        );
        assert_eq!(evasion_suffixtoken, Some("good".as_bytes()));

        let badending = mime_find_header_token(
            "attachment; filename=oksofar; badending".as_bytes(),
            "filename".as_bytes(),
            &mut outvec,
        );
        assert_eq!(badending, Some("oksofar".as_bytes()));

        let missend = mime_find_header_token(
            "attachment; filename=test".as_bytes(),
            "filename".as_bytes(),
            &mut outvec,
        );
        assert_eq!(missend, Some("test".as_bytes()));

        let spaces = mime_find_header_token(
            "attachment; filename=test me wrong".as_bytes(),
            "filename".as_bytes(),
            &mut outvec,
        );
        assert_eq!(spaces, Some("test me wrong".as_bytes()));

        assert_eq!(outvec.len(), 0);
        let multi = mime_find_header_token(
            "attachment; filename*0=abc; filename*1=\"def\";".as_bytes(),
            "filename".as_bytes(),
            &mut outvec,
        );
        assert_eq!(multi, Some("abcdef".as_bytes()));
        outvec.clear();

        let multi = mime_find_header_token(
            "attachment; filename*1=456; filename*0=\"123\"".as_bytes(),
            "filename".as_bytes(),
            &mut outvec,
        );
        assert_eq!(multi, Some("123456".as_bytes()));
        outvec.clear();
    }
}
