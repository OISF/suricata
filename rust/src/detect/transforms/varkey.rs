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

//! Shared helpers for transforms that read key bytes from a fixed
//! position within the inspection buffer at transform time.

use nom8::{
    character::complete::{digit1, multispace1},
    combinator::map_res,
    sequence::separated_pair,
    IResult, Parser,
};

/// Location in an inspection buffer from which key bytes are read at
/// transform time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct VariableKeyLocation {
    /// Absolute byte offset in the inspection buffer.
    pub(super) offset: u16,
    /// Number of bytes to read starting at `offset`.
    pub(super) nbytes: u8,
}

/// Return the key bytes at `loc` within `input`, or `None` if the
/// location is out of bounds.
pub(super) fn variable_key_bytes<'a>(
    input: &'a [u8], loc: &VariableKeyLocation,
) -> Option<&'a [u8]> {
    let start = loc.offset as usize;
    let end = start + loc.nbytes as usize;
    if end > input.len() {
        return None;
    }
    Some(&input[start..end])
}

/// Strip a leading keyword from `s` if it is followed by whitespace.
/// Returns the trimmed remainder, or `None` if the keyword is absent or
/// not followed by whitespace.
pub(super) fn strip_keyword_prefix<'a>(s: &'a str, keyword: &str) -> Option<&'a str> {
    s.strip_prefix(keyword)
        .filter(|r| r.starts_with(|c: char| c.is_ascii_whitespace()))
        .map(|r| r.trim_start())
}

fn parse_location(input: &str) -> IResult<&str, VariableKeyLocation> {
    let parse_nbytes = map_res(digit1, |s: &str| s.parse::<u8>());
    let parse_offset = map_res(digit1, |s: &str| s.parse::<u16>());
    let (rest, (nbytes, offset)) =
        separated_pair(parse_nbytes, multispace1, parse_offset).parse(input)?;
    Ok((rest, VariableKeyLocation { nbytes, offset }))
}

/// Parse `<nbytes> <offset>` from a trimmed string (the keyword has
/// already been stripped by the caller). Returns a `VariableKeyLocation`
/// or `None` if the format is wrong, a value overflows its type, or
/// `nbytes` is zero.
pub(super) fn parse_key_location(s: &str) -> Option<VariableKeyLocation> {
    match parse_location(s) {
        Ok(("", loc)) if loc.nbytes > 0 => Some(loc),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_keyword_prefix_match() {
        assert_eq!(strip_keyword_prefix("var 1 0", "var"), Some("1 0"));
    }

    #[test]
    fn test_strip_keyword_prefix_offset() {
        assert_eq!(
            strip_keyword_prefix("offset 4,key", "offset"),
            Some("4,key")
        );
    }

    #[test]
    fn test_strip_keyword_prefix_no_trailing_whitespace() {
        assert_eq!(strip_keyword_prefix("var1 0", "var"), None);
    }

    #[test]
    fn test_strip_keyword_prefix_absent() {
        assert_eq!(strip_keyword_prefix("aabb", "var"), None);
    }

    #[test]
    fn test_parse_key_location_basic() {
        assert_eq!(
            parse_key_location("1 0"),
            Some(VariableKeyLocation {
                nbytes: 1,
                offset: 0
            })
        );
    }

    #[test]
    fn test_parse_key_location_large_offset() {
        assert_eq!(
            parse_key_location("4 1024"),
            Some(VariableKeyLocation {
                nbytes: 4,
                offset: 1024
            })
        );
    }

    #[test]
    fn test_parse_key_location_missing_offset() {
        assert_eq!(parse_key_location("1"), None);
    }

    #[test]
    fn test_parse_key_location_zero_nbytes() {
        assert_eq!(parse_key_location("0 0"), None);
    }

    #[test]
    fn test_parse_key_location_nbytes_overflow() {
        assert_eq!(parse_key_location("256 0"), None);
    }

    #[test]
    fn test_parse_key_location_offset_overflow() {
        assert_eq!(parse_key_location("1 65536"), None);
    }

    #[test]
    fn test_variable_key_bytes_in_bounds() {
        let input = b"\x42hello";
        let loc = VariableKeyLocation {
            offset: 0,
            nbytes: 1,
        };
        assert_eq!(variable_key_bytes(input, &loc), Some(&[0x42u8][..]));
    }

    #[test]
    fn test_variable_key_bytes_offset_out_of_bounds() {
        let input = b"\x42hello";
        let loc = VariableKeyLocation {
            offset: 100,
            nbytes: 1,
        };
        assert_eq!(variable_key_bytes(input, &loc), None);
    }

    #[test]
    fn test_variable_key_bytes_end_out_of_bounds() {
        let input = b"\x42hello";
        let loc = VariableKeyLocation {
            offset: 5,
            nbytes: 3,
        };
        assert_eq!(variable_key_bytes(input, &loc), None);
    }

    #[test]
    fn test_variable_key_bytes_multi() {
        let input = b"\x42\x37data";
        let loc = VariableKeyLocation {
            offset: 0,
            nbytes: 2,
        };
        assert_eq!(variable_key_bytes(input, &loc), Some(&[0x42u8, 0x37][..]));
    }
}
