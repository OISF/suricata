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

use std;
use std::collections::HashMap;

use nom::combinator::rest;
use nom::error::ErrorKind;
use nom::Err;
use nom::IResult;

#[derive(Clone)]
pub struct MIMEHeaderTokens<'a> {
    pub tokens: HashMap<&'a [u8], &'a [u8]>,
}

pub fn mime_parse_value_delimited(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let (i2, _) = tag!(input, "\"")?;
    let (i3, value) = take_until!(i2, "\"")?;
    let (i4, _) = tag!(i3, "\"")?;
    return Ok((i4, value));
}

pub fn mime_parse_header_token(input: &[u8]) -> IResult<&[u8], (&[u8], &[u8])> {
    // from RFC2047 : like ch.is_ascii_whitespace but without 0x0c FORM-FEED
    let (i1, _) = take_while!(input, |ch: u8| ch == 0x20
        || ch == 0x09
        || ch == 0x0a
        || ch == 0x0d)?;
    let (i2, name) = take_until!(i1, "=")?;
    let (i3, _) = tag!(i2, "=")?;
    let (i4, value) = alt!(
        i3,
        mime_parse_value_delimited | complete!(take_until!(";")) | rest
    )?;
    let (i5, _) = opt!(i4, complete!(tag!(";")))?;
    return Ok((i5, (name, value)));
}

fn mime_parse_header_tokens(input: &[u8]) -> IResult<&[u8], MIMEHeaderTokens> {
    let (mut i2, _) = take_until_and_consume!(input, ";")?;
    let mut tokens = HashMap::new();
    while i2.len() > 0 {
        match mime_parse_header_token(i2) {
            Ok((rem, t)) => {
                tokens.insert(t.0, t.1);
                // should never happen
                debug_validate_bug_on!(i2.len() == rem.len());
                if i2.len() == rem.len() {
                    //infinite loop
                    return Err(Err::Error((input, ErrorKind::Eof)));
                }
                i2 = rem;
            }
            Err(_) => {
                // keep first tokens is error in remaining buffer
                break;
            }
        }
    }
    return Ok((i2, MIMEHeaderTokens { tokens }));
}

fn mime_find_header_token<'a>(header: &'a [u8], token: &[u8]) -> Result<&'a [u8], ()> {
    match mime_parse_header_tokens(header) {
        Ok((_rem, t)) => {
            // look for the specific token
            match t.tokens.get(token) {
                // easy nominal case
                Some(value) => return Ok(value),
                None => return Err(()),
            }
        }
        Err(_) => {
            return Err(());
        }
    }
}

// TODO ? export with "constants" in cbindgen
// and use in outbuf definition for rs_mime_find_header_token
// but other constants are now defined twice in rust and in C
pub const RS_MIME_MAX_TOKEN_LEN: usize = 255;

#[no_mangle]
pub extern "C" fn rs_mime_find_header_token(
    hinput: *const u8, hlen: u32, tinput: *const u8, tlen: u32, outbuf: &mut [u8; 255],
    outlen: *mut u32,
) -> bool {
    let hbuf = build_slice!(hinput, hlen as usize);
    let tbuf = build_slice!(tinput, tlen as usize);
    match mime_find_header_token(hbuf, tbuf) {
        Ok(value) => {
            // limit the copy to the supplied buffer size
            if value.len() <= RS_MIME_MAX_TOKEN_LEN {
                outbuf[..value.len()].clone_from_slice(value);
            } else {
                outbuf.clone_from_slice(&value[..RS_MIME_MAX_TOKEN_LEN]);
            }
            unsafe {
                *outlen = value.len() as u32;
            }
            return true;
        }
        _ => {}
    }
    return false;
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_mime_find_header_token() {
        let undelimok = mime_find_header_token(
            "attachment; filename=test;".as_bytes(),
            "filename".as_bytes(),
        );
        assert_eq!(undelimok, Ok("test".as_bytes()));

        let delimok = mime_find_header_token(
            "attachment; filename=\"test2\";".as_bytes(),
            "filename".as_bytes(),
        );
        assert_eq!(delimok, Ok("test2".as_bytes()));

        let evasion_othertoken = mime_find_header_token(
            "attachment; dummy=\"filename=wrong\"; filename=real;".as_bytes(),
            "filename".as_bytes(),
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
        );
        assert_eq!(badending, Ok("oksofar".as_bytes()));

        let missend = mime_find_header_token(
            "attachment; filename=test".as_bytes(),
            "filename".as_bytes(),
        );
        assert_eq!(missend, Ok("test".as_bytes()));
    }
}
