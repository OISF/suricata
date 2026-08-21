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

//! Shared helpers for transforms whose key is not a literal in the rule.
//!
//! Two key sources are supported:
//!
//! * a fixed location within the inspection buffer, read at transform time
//!   ([`VariableKeyLocation`] / [`variable_key_bytes`]); and
//! * a `byte_extract` or `byte_math` variable, resolved against the signature
//!   at setup ([`parse_byte_var`] / [`resolve_byte_var`]) and read from the
//!   thread context at transform time ([`byte_var_key_bytes`]).

use nom8::{
    character::complete::{digit1, multispace1},
    combinator::map_res,
    sequence::separated_pair,
    IResult, Parser,
};
use std::ffi::CString;
use suricata_sys::sys::{
    DetectEngineThreadCtx, SCDetectByteVarResolve, SCDetectEngineThreadCtxGetByteVar,
    SCSignatureSetVarTransform, Signature,
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

/// Parsed `var <name> [<nbytes>]` spec, before the variable is resolved
/// against the signature.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct ByteVarSpec {
    /// The `byte_extract`/`byte_math` variable name.
    pub(super) name: String,
    /// Optional explicit key width in bytes; resolved against the variable's
    /// natural width when omitted.
    pub(super) width: Option<u8>,
}

/// A key read from a `byte_extract`/`byte_math` variable at transform time.
/// `local_id` is the runtime slot; `nbytes` (1-8) selects how many low bytes
/// of the variable's value form the key, rendered big-endian.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ByteVarKey {
    pub(super) local_id: u8,
    pub(super) nbytes: u8,
}

/// Parse `<name> [<nbytes>]` for the `var` form (the `var` keyword has already
/// been stripped by the caller). Logs and returns `None` on malformed input.
pub(super) fn parse_byte_var(rest: &str) -> Option<ByteVarSpec> {
    let mut parts = rest.split_whitespace();
    let name = match parts.next() {
        Some(n) => n,
        None => {
            SCLogError!("transform 'var' requires a variable name");
            return None;
        }
    };
    // Optional explicit key width (number of bytes of the variable's value to
    // use). Required for byte_math variables, which have no natural width;
    // optional for byte_extract, which defaults to its read width.
    let width = match parts.next() {
        Some(w) => match w.parse::<u8>() {
            Ok(n) => Some(n),
            Err(_) => {
                SCLogError!("transform 'var' width must be a number");
                return None;
            }
        },
        None => None,
    };
    if parts.next().is_some() {
        SCLogError!("transform 'var' takes a variable name and optional width");
        return None;
    }
    Some(ByteVarSpec {
        name: name.to_string(),
        width,
    })
}

/// Resolve a parsed byte-variable spec against signature `s`: look up the
/// variable, settle the key width, validate it, and mark the signature so it
/// is kept out of prefilter (the key is only known at inspection time).
/// Returns the compiled key, or `None` on any error (already logged).
///
/// # Safety
///
/// `s` must be a valid signature pointer; intended to be called from a
/// transform's `Setup` callback.
pub(super) unsafe fn resolve_byte_var(s: *mut Signature, spec: &ByteVarSpec) -> Option<ByteVarKey> {
    let cname = CString::new(spec.name.as_str()).ok()?;
    let mut local_id: u8 = 0;
    let mut natural_nbytes: u8 = 0;
    if !SCDetectByteVarResolve(s, cname.as_ptr(), &mut local_id, &mut natural_nbytes) {
        SCLogError!(
            "transform 'var': unknown byte_extract or byte_math variable '{}'",
            spec.name
        );
        return None;
    }
    // Use the explicit width if given, otherwise the variable's natural width.
    // A byte_math result has no natural width (reported as 0), so an explicit
    // width is required there.
    let nbytes = match spec.width {
        Some(w) => w,
        None => {
            if natural_nbytes == 0 {
                SCLogError!(
                    "transform 'var': variable '{}' has no inherent width; specify the key width, e.g. 'var <name> <nbytes>'",
                    spec.name
                );
                return None;
            }
            natural_nbytes
        }
    };
    if nbytes == 0 || nbytes > 8 {
        SCLogError!("transform 'var': key width must be 1-8 bytes");
        return None;
    }
    /* The key is only known at inspection time, so the buffer can't be
     * precomputed: disqualify this signature from prefilter/MPM. */
    SCSignatureSetVarTransform(s);
    Some(ByteVarKey { local_id, nbytes })
}

/// Read the byte-variable key's value from the thread context and render its
/// low `nbytes` big-endian into `out`, returning the written slice. `out` must
/// be at least `key.nbytes` (<= 8) bytes long. Returns `None` if `det` is null.
///
/// # Safety
///
/// `det` must be a valid thread-context pointer or null.
pub(super) unsafe fn byte_var_key_bytes<'a>(
    det: *mut DetectEngineThreadCtx, key: &ByteVarKey, out: &'a mut [u8],
) -> Option<&'a [u8]> {
    if det.is_null() {
        return None;
    }
    // Render the low `nbytes` bytes of the value big-endian, regardless of the
    // keyword's own endianness.
    let value = SCDetectEngineThreadCtxGetByteVar(det, key.local_id);
    let n = key.nbytes as usize;
    out[..n].copy_from_slice(&value.to_be_bytes()[8 - n..]);
    Some(&out[..n])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_keyword_prefix_match() {
        assert_eq!(strip_keyword_prefix("var 1 0", "var"), Some("1 0"));
    }

    #[test]
    fn test_parse_byte_var_name_only() {
        // width is resolved later from the variable
        assert_eq!(
            parse_byte_var("xkey"),
            Some(ByteVarSpec {
                name: "xkey".to_string(),
                width: None
            })
        );
        // extra whitespace is tolerated
        assert_eq!(
            parse_byte_var("  xkey  "),
            Some(ByteVarSpec {
                name: "xkey".to_string(),
                width: None
            })
        );
    }

    #[test]
    fn test_parse_byte_var_explicit_width() {
        assert_eq!(
            parse_byte_var("xkey 4"),
            Some(ByteVarSpec {
                name: "xkey".to_string(),
                width: Some(4)
            })
        );
    }

    #[test]
    fn test_parse_byte_var_missing_name() {
        assert!(parse_byte_var("").is_none());
        assert!(parse_byte_var("   ").is_none());
    }

    #[test]
    fn test_parse_byte_var_bad_width() {
        // width must be numeric
        assert!(parse_byte_var("xkey wide").is_none());
        // width must fit in u8
        assert!(parse_byte_var("xkey 256").is_none());
    }

    #[test]
    fn test_parse_byte_var_trailing_garbage() {
        // more than a name and a width
        assert!(parse_byte_var("xkey 1 extra").is_none());
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
