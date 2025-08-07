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

//! MIME protocol parser module.

use crate::common::nom7::take_until_and_consume;
use nom7::branch::alt;
use nom7::bytes::streaming::{tag, take_until, take_while};
use nom7::combinator::{complete, opt, rest};
use nom7::error::{make_error, ErrorKind};
use nom7::{Err, IResult};
use std;
use std::collections::HashMap;

#[derive(Clone)]
pub struct MIMEHeaderTokens<'a> {
    pub tokens: HashMap<&'a [u8], &'a [u8]>,
}

pub fn mime_parse_value_delimited(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let (input, _) = tag("\"")(input)?;
    let (input, value) = take_until("\"")(input)?;
    let (input, _) = tag("\"")(input)?;
    return Ok((input, value));
}

pub fn mime_parse_header_token(input: &[u8]) -> IResult<&[u8], (&[u8], &[u8])> {
    // from RFC2047 : like ch.is_ascii_whitespace but without 0x0c FORM-FEED
    let (input, _) = take_while(|ch: u8| ch == 0x20
        || ch == 0x09
        || ch == 0x0a
        || ch == 0x0d)(input)?;
    let (input, name) = take_until("=")(input)?;
    let (input, _) = tag("=")(input)?;
    let (input, value) = alt((
        mime_parse_value_delimited,
        complete(take_until(";")),
        rest
    ))(input)?;
    let (input, _) = opt(complete(tag(";")))(input)?;
    return Ok((input, (name, value)));
}

fn mime_parse_header_tokens(input: &[u8]) -> IResult<&[u8], MIMEHeaderTokens<'_>> {
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
    return Ok((input, MIMEHeaderTokens { tokens }));
}

fn mime_find_header_token<'a>(
    header: &'a [u8], token: &[u8], sections_values: &'a mut Vec<u8>,
) -> Result<&'a [u8], ()> {
    match mime_parse_header_tokens(header) {
        Ok((_rem, t)) => {
            // in case of multiple sections for the parameter cf RFC2231
            let mut current_section_slice = Vec::new();

            // look for the specific token
            match t.tokens.get(token) {
                // easy nominal case
                Some(value) => return Ok(value),
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
                        None => return Err(()),
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
                    None => return Ok(sections_values),
                }
            }
        }
        Err(_) => {
            return Err(());
        }
    }
}

// used on the C side
pub const RS_MIME_MAX_TOKEN_LEN: usize = 255;

#[no_mangle]
pub unsafe extern "C" fn rs_mime_find_header_token(
    hinput: *const u8, hlen: u32, tinput: *const u8, tlen: u32, outbuf: &mut [u8; 255],
    outlen: *mut u32,
) -> bool {
    let hbuf = build_slice!(hinput, hlen as usize);
    let tbuf = build_slice!(tinput, tlen as usize);
    let mut sections_values = Vec::new();
    if let Ok(value) = mime_find_header_token(hbuf, tbuf, &mut sections_values) {
        // limit the copy to the supplied buffer size
        if value.len() <= RS_MIME_MAX_TOKEN_LEN {
            outbuf[..value.len()].clone_from_slice(value);
        } else {
            outbuf.clone_from_slice(&value[..RS_MIME_MAX_TOKEN_LEN]);
        }
        *outlen = value.len() as u32;
        return true;
    }
    return false;
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
        assert_eq!(undelimok, Ok("test".as_bytes()));

        let delimok = mime_find_header_token(
            "attachment; filename=\"test2\";".as_bytes(),
            "filename".as_bytes(),
            &mut outvec,
        );
        assert_eq!(delimok, Ok("test2".as_bytes()));

        let evasion_othertoken = mime_find_header_token(
            "attachment; dummy=\"filename=wrong\"; filename=real;".as_bytes(),
            "filename".as_bytes(),
            &mut outvec,
        );
        assert_eq!(evasion_othertoken, Ok("real".as_bytes()));

        let evasion_suffixtoken = mime_find_header_token(
            "attachment; notafilename=wrong; filename=good;".as_bytes(),
            "filename".as_bytes(),
            &mut outvec,
        );
        assert_eq!(evasion_suffixtoken, Ok("good".as_bytes()));

        let badending = mime_find_header_token(
            "attachment; filename=oksofar; badending".as_bytes(),
            "filename".as_bytes(),
            &mut outvec,
        );
        assert_eq!(badending, Ok("oksofar".as_bytes()));

        let missend = mime_find_header_token(
            "attachment; filename=test".as_bytes(),
            "filename".as_bytes(),
            &mut outvec,
        );
        assert_eq!(missend, Ok("test".as_bytes()));

        let spaces = mime_find_header_token(
            "attachment; filename=test me wrong".as_bytes(),
            "filename".as_bytes(),
            &mut outvec,
        );
        assert_eq!(spaces, Ok("test me wrong".as_bytes()));

        assert_eq!(outvec.len(), 0);
        let multi = mime_find_header_token(
            "attachment; filename*0=abc; filename*1=\"def\";".as_bytes(),
            "filename".as_bytes(),
            &mut outvec,
        );
        assert_eq!(multi, Ok("abcdef".as_bytes()));
        outvec.clear();

        let multi = mime_find_header_token(
            "attachment; filename*1=456; filename*0=\"123\"".as_bytes(),
            "filename".as_bytes(),
            &mut outvec,
        );
        assert_eq!(multi, Ok("123456".as_bytes()));
        outvec.clear();
    }
}
