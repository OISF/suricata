/* Copyright (C) 2019 Open Information Security Foundation
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

// Author: Zach Kelly <zach.kelly@lmco.com>

use crate::rdp::error::RdpError;
use byteorder::ReadBytesExt;
use memchr::memchr;
use nom7::{Err, IResult, Needed};
use std::io::Cursor;
use widestring::U16CString;

/// converts a raw u8 slice of little-endian wide chars into a String
pub fn le_slice_to_string(input: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    let mut vec = Vec::new();
    let mut cursor = Cursor::new(input);
    loop {
        match cursor.read_u16::<byteorder::LittleEndian>() {
            Ok(x) => {
                if x == 0 {
                    break;
                };
                vec.push(x)
            }
            Err(_) => break,
        }
    }
    match U16CString::new(vec) {
        Ok(x) => match x.to_string() {
            Ok(x) => Ok(x),
            Err(e) => Err(e.into()),
        },
        Err(e) => Err(e.into()),
    }
}

/// converts a raw u8 slice of null-padded utf7 chars into a String, dropping the nulls
pub fn utf7_slice_to_string(input: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    let s = match memchr(b'\0', input) {
        Some(end) => &input[..end],
        None => input,
    };
    match std::str::from_utf8(s) {
        Ok(s) => Ok(String::from(s)),
        Err(e) => Err(e.into()),
    }
}

/// parses a PER length determinant, to determine the length of the data following
/// x.691-spec: section 10.9
pub fn parse_per_length_determinant(input: &[u8]) -> IResult<&[u8], u32, RdpError> {
    if input.is_empty() {
        // need a single byte to begin length determination
        Err(Err::Incomplete(Needed::new(1)))
    } else {
        let bit7 = input[0] >> 7;
        match bit7 {
            0b0 => {
                // byte starts with 0b0.  Length stored in the lower 7 bits of the current byte
                let length = input[0] as u32 & 0x7f;
                Ok((&input[1..], length))
            }
            _ => {
                let bit6 = input[0] >> 6 & 0x1;
                match bit6 {
                    0b0 => {
                        // byte starts with 0b10.  Length stored in the remaining 6 bits and the next byte
                        if input.len() < 2 {
                            Err(Err::Incomplete(Needed::new(2)))
                        } else {
                            let length = ((input[0] as u32 & 0x3f) << 8) | input[1] as u32;
                            Ok((&input[2..], length))
                        }
                    }
                    _ => {
                        // byte starts with 0b11.  Without an example to confirm 16K+ lengths are properly
                        // handled, leaving this branch unimplemented
                        Err(Err::Error(RdpError::UnimplementedLengthDeterminant))
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rdp::error::RdpError;
    use nom7::Needed;

    #[test]
    fn test_le_string_abc() {
        let abc = &[0x41, 0x00, 0x42, 0x00, 0x43, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(String::from("ABC"), le_slice_to_string(abc).unwrap());
    }

    #[test]
    fn test_le_string_empty() {
        let empty = &[];
        assert_eq!(String::from(""), le_slice_to_string(empty).unwrap());
    }

    #[test]
    fn test_le_string_invalid() {
        let not_utf16le = &[0x00, 0xd8, 0x01, 0x00];
        assert!(le_slice_to_string(not_utf16le).is_err());
    }

    #[test]
    fn test_utf7_string_abc() {
        let abc = &[0x41, 0x42, 0x43, 0x00, 0x00];
        assert_eq!(String::from("ABC"), utf7_slice_to_string(abc).unwrap());
    }

    #[test]
    fn test_utf7_string_empty() {
        let empty = &[];
        assert_eq!(String::from(""), utf7_slice_to_string(empty).unwrap());
    }

    #[test]
    fn test_utf7_string_invalid() {
        let not_utf7 = &[0x80];
        assert!(utf7_slice_to_string(not_utf7).is_err());
    }

    #[test]
    fn test_length_single_length() {
        let bytes = &[0x28];
        assert_eq!(Ok((&[][..], 0x28)), parse_per_length_determinant(bytes));
    }

    #[test]
    fn test_length_double_length() {
        let bytes = &[0x81, 0x28];
        assert_eq!(Ok((&[][..], 0x128)), parse_per_length_determinant(bytes));
    }

    #[test]
    fn test_length_single_length_incomplete() {
        let bytes = &[];
        assert_eq!(
            Err(Err::Incomplete(Needed::new(1))),
            parse_per_length_determinant(bytes)
        )
    }

    #[test]
    fn test_length_16k_unimplemented() {
        let bytes = &[0xc0];
        assert_eq!(
            Err(Err::Error(RdpError::UnimplementedLengthDeterminant)),
            parse_per_length_determinant(bytes)
        )
    }

    #[test]
    fn test_length_double_length_incomplete() {
        let bytes = &[0x81];
        assert_eq!(
            Err(Err::Incomplete(Needed::new(2))),
            parse_per_length_determinant(bytes)
        )
    }
}
