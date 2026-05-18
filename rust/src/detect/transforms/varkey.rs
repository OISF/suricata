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

/// Location in an inspection buffer from which key bytes are read at
/// transform time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VarKeyLocation {
    /// Absolute byte offset in the inspection buffer.
    pub offset: u16,
    /// Number of bytes to read starting at `offset`.
    pub nbytes: u8,
}

/// Return the key bytes at `loc` within `input`, or `None` if the
/// location is out of bounds or `nbytes` is zero.
pub fn var_key_bytes(input: &[u8], loc: VarKeyLocation) -> Option<&[u8]> {
    let start = loc.offset as usize;
    let end = start + loc.nbytes as usize;
    if loc.nbytes == 0 || end > input.len() {
        return None;
    }
    Some(&input[start..end])
}

/// Strip a leading keyword from `s` if it is followed by whitespace.
/// Returns the trimmed remainder, or `None` if the keyword is absent or
/// not followed by whitespace.
pub fn strip_keyword_prefix<'a>(s: &'a str, keyword: &str) -> Option<&'a str> {
    s.strip_prefix(keyword)
        .filter(|r| r.starts_with(|c: char| c.is_ascii_whitespace()))
        .map(|r| r.trim_start())
}

/// Parse `<nbytes> <offset>` from a trimmed string (the `var` keyword
/// has already been stripped by the caller). Returns a `VarKeyLocation`
/// or `None` if the format is wrong or a value overflows its type.
pub fn parse_var_spec(s: &str) -> Option<VarKeyLocation> {
    let mut parts = s.splitn(2, |c: char| c.is_ascii_whitespace());
    let nbytes_str = parts.next()?.trim();
    let offset_str = parts.next()?.trim();
    if offset_str.is_empty() {
        return None;
    }
    let nbytes: u8 = nbytes_str.parse().ok()?;
    let offset: u16 = offset_str.parse().ok()?;
    Some(VarKeyLocation { nbytes, offset })
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
        assert_eq!(strip_keyword_prefix("offset 4,key", "offset"), Some("4,key"));
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
    fn test_parse_var_spec_basic() {
        assert_eq!(
            parse_var_spec("1 0"),
            Some(VarKeyLocation {
                nbytes: 1,
                offset: 0
            })
        );
    }

    #[test]
    fn test_parse_var_spec_large_offset() {
        assert_eq!(
            parse_var_spec("4 1024"),
            Some(VarKeyLocation {
                nbytes: 4,
                offset: 1024
            })
        );
    }

    #[test]
    fn test_parse_var_spec_missing_offset() {
        assert_eq!(parse_var_spec("1"), None);
    }

    #[test]
    fn test_parse_var_spec_nbytes_overflow() {
        assert_eq!(parse_var_spec("256 0"), None);
    }

    #[test]
    fn test_parse_var_spec_offset_overflow() {
        assert_eq!(parse_var_spec("1 65536"), None);
    }

    #[test]
    fn test_var_key_bytes_in_bounds() {
        let input = b"\x42hello";
        let loc = VarKeyLocation {
            offset: 0,
            nbytes: 1,
        };
        assert_eq!(var_key_bytes(input, loc), Some(&[0x42u8][..]));
    }

    #[test]
    fn test_var_key_bytes_offset_out_of_bounds() {
        let input = b"\x42hello";
        let loc = VarKeyLocation {
            offset: 100,
            nbytes: 1,
        };
        assert_eq!(var_key_bytes(input, loc), None);
    }

    #[test]
    fn test_var_key_bytes_end_out_of_bounds() {
        let input = b"\x42hello";
        let loc = VarKeyLocation {
            offset: 5,
            nbytes: 3,
        };
        assert_eq!(var_key_bytes(input, loc), None);
    }

    #[test]
    fn test_var_key_bytes_multi() {
        let input = b"\x42\x37data";
        let loc = VarKeyLocation {
            offset: 0,
            nbytes: 2,
        };
        assert_eq!(var_key_bytes(input, loc), Some(&[0x42u8, 0x37][..]));
    }

    #[test]
    fn test_var_key_bytes_zero_nbytes() {
        let input = b"\x42hello";
        let loc = VarKeyLocation {
            offset: 0,
            nbytes: 0,
        };
        assert_eq!(var_key_bytes(input, loc), None);
    }
}
