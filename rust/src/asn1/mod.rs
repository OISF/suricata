/* Copyright (C) 2020-2022 Open Information Security Foundation
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

use der_parser::ber::{parse_ber_recursive, BerObject, BerObjectContent, BerTag};
use std::convert::TryFrom;

mod parse_rules;
use parse_rules::DetectAsn1Data;

/// Container for parsed Asn1 objects
#[derive(Debug)]
pub struct Asn1<'a>(Vec<BerObject<'a>>);

/// Errors possible during decoding of Asn1
#[derive(Debug)]
enum Asn1DecodeError {
    InvalidKeywordParameter,
    MaxFrames,
    BerError(nom::Err<der_parser::error::BerError>),
}

/// Enumeration of Asn1 checks
#[derive(Debug, PartialEq)]
enum Asn1Check {
    OversizeLength,
    BitstringOverflow,
    DoubleOverflow,
    MaxDepth,
}

impl<'a> Asn1<'a> {
    /// Checks each BerObject contained in self with the provided detection
    /// data, returns the first successful match if one occurs
    fn check(&self, ad: &DetectAsn1Data) -> Option<Asn1Check> {
        for obj in &self.0 {
            let res = Asn1::check_object_recursive(obj, ad, ad.max_frames as usize);
            if res.is_some() {
                return res;
            }
        }

        None
    }

    fn check_object_recursive(
        obj: &BerObject, ad: &DetectAsn1Data, max_depth: usize,
    ) -> Option<Asn1Check> {
        // Check stack depth
        if max_depth == 0 {
            return Some(Asn1Check::MaxDepth);
        }

        // Check current object
        let res = Asn1::check_object(obj, ad);
        if res.is_some() {
            return res;
        }

        // Check sub-nodes
        for node in obj.ref_iter() {
            let res = Asn1::check_object_recursive(node, ad, max_depth - 1);
            if res.is_some() {
                return res;
            }
        }

        None
    }

    /// Checks a BerObject and subnodes against the Asn1 checks
    fn check_object(obj: &BerObject, ad: &DetectAsn1Data) -> Option<Asn1Check> {
        // oversize_length will check if a node has a length greater than
        // the user supplied length
        if let Some(oversize_length) = ad.oversize_length {
            if obj.header.len > oversize_length as u64
                || obj.content.as_slice().unwrap_or(&[]).len() > oversize_length as usize
            {
                return Some(Asn1Check::OversizeLength);
            }
        }

        // bitstring_overflow check a malformed option where the number of bits
        // to ignore is greater than the length decoded (in bits)
        if ad.bitstring_overflow
            && (obj.header.is_universal()
                && obj.header.tag == BerTag::BitString
                && obj.header.is_primitive())
        {
            if let BerObjectContent::BitString(bits, _v) = &obj.content {
                if obj.header.len > 0
                    && *bits as u64 > obj.header.len.saturating_mul(8)
                {
                    return Some(Asn1Check::BitstringOverflow);
                }
            }
        }

        // double_overflow checks a known issue that affects the MSASN1 library
        // when decoding double/real types. If the encoding is ASCII,
        // and the buffer is greater than 256, the array is overflown
        if ad.double_overflow
            && (obj.header.is_universal()
                && obj.header.tag == BerTag::RealType
                && obj.header.is_primitive())
        {
            if let Ok(data) = obj.content.as_slice() {
                if obj.header.len > 0
                    && !data.is_empty()
                    && data[0] & 0xC0 == 0
                    && (obj.header.len > 256 || data.len() > 256)
                {
                    return Some(Asn1Check::DoubleOverflow);
                }
            }
        }

        None
    }

    fn from_slice(input: &'a [u8], ad: &DetectAsn1Data) -> Result<Asn1<'a>, Asn1DecodeError> {
        let mut results = Vec::new();
        let mut rest = input;

        // while there's data to process
        while !rest.is_empty() {
            let max_depth = ad.max_frames as usize;

            if results.len() >= max_depth {
                return Err(Asn1DecodeError::MaxFrames);
            }

            let res = parse_ber_recursive(rest, max_depth);

            match res {
                Ok((new_rest, obj)) => {
                    results.push(obj);

                    rest = new_rest;
                }
                // If there's an error, bail
                Err(_) => {
                    // silent error as this could fail
                    // on non-asn1 or fragmented packets
                    break;
                }
            }
        }

        Ok(Asn1(results))
    }
}

/// Decodes Asn1 objects from an input + length while applying the offset
/// defined in the asn1 keyword options
fn asn1_decode<'a>(
    buffer: &'a [u8], buffer_offset: u32, ad: &DetectAsn1Data,
) -> Result<Asn1<'a>, Asn1DecodeError> {
    // Get offset
    let offset = if let Some(absolute_offset) = ad.absolute_offset {
        absolute_offset
    } else if let Some(relative_offset) = ad.relative_offset {
        // relative offset in regards to the last content match

        // buffer_offset (u32) + relative_offset (i32) => offset (u16)
        u16::try_from({
            if relative_offset > 0 {
                buffer_offset
                    .checked_add(u32::try_from(relative_offset)?)
                    .ok_or(Asn1DecodeError::InvalidKeywordParameter)?
            } else {
                buffer_offset
                    .checked_sub(u32::try_from(-relative_offset)?)
                    .ok_or(Asn1DecodeError::InvalidKeywordParameter)?
            }
        })
        .or(Err(Asn1DecodeError::InvalidKeywordParameter))?
    } else {
        0
    };

    // Make sure we won't read past the end or front of the buffer
    if offset as usize >= buffer.len() {
        return Err(Asn1DecodeError::InvalidKeywordParameter);
    }

    // Get slice from buffer at offset
    let slice = &buffer[offset as usize..];

    Asn1::from_slice(slice, ad)
}

/// Attempt to parse a Asn1 object from input, and return a pointer
/// to the parsed object if successful, null on failure
///
/// # Safety
///
/// input must be a valid buffer of at least input_len bytes
/// pointer must be freed using `rs_asn1_free`
#[no_mangle]
pub unsafe extern "C" fn rs_asn1_decode(
    input: *const u8, input_len: u16, buffer_offset: u32, ad_ptr: *const DetectAsn1Data,
) -> *mut Asn1<'static> {
    if input.is_null() || input_len == 0 || ad_ptr.is_null() {
        return std::ptr::null_mut();
    }

    let slice = build_slice!(input, input_len as usize);

    let ad = &*ad_ptr ;

    let res = asn1_decode(slice, buffer_offset, ad);

    match res {
        Ok(asn1) => Box::into_raw(Box::new(asn1)),
        Err(_e) => std::ptr::null_mut(),
    }
}

/// Free a Asn1 object allocated by Rust
///
/// # Safety
///
/// ptr must be a valid object obtained using `rs_asn1_decode`
#[no_mangle]
pub unsafe extern "C" fn rs_asn1_free(ptr: *mut Asn1) {
    if ptr.is_null() {
        return;
    }
    drop(Box::from_raw(ptr));
}

/// This function implements the detection of the following options:
///   - oversize_length
///   - bitstring_overflow
///   - double_overflow
///
/// # Safety
///
/// ptr must be a valid object obtained using `rs_asn1_decode`
/// ad_ptr must be a valid object obtained using `rs_detect_asn1_parse`
///
/// Returns 1 if any of the options match, 0 if not
#[no_mangle]
pub unsafe extern "C" fn rs_asn1_checks(ptr: *const Asn1, ad_ptr: *const DetectAsn1Data) -> u8 {
    if ptr.is_null() || ad_ptr.is_null() {
        return 0;
    }

    let asn1 = &*ptr;
    let ad = &*ad_ptr;

    match asn1.check(ad) {
        Some(_check) => 1,
        None => 0,
    }
}

impl From<std::num::TryFromIntError> for Asn1DecodeError {
    fn from(_e: std::num::TryFromIntError) -> Asn1DecodeError {
        Asn1DecodeError::InvalidKeywordParameter
    }
}

impl From<nom::Err<der_parser::error::BerError>> for Asn1DecodeError {
    fn from(e: nom::Err<der_parser::error::BerError>) -> Asn1DecodeError {
        Asn1DecodeError::BerError(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    // Example from the specification X.690-0207 Appendix A.3
    static ASN1_A3: &[u8] = b"\x60\x81\x85\x61\x10\x1A\x04John\x1A\x01 \
                    P\x1A\x05Smith\xA0\x0A\x1A\x08Director \
                    \x42\x01\x33\xA1\x0A\x43\x0819710917 \
                    \xA2\x12\x61\x10\x1A\x04Mary\x1A\x01T\x1A\x05 \
                    Smith\xA3\x42\x31\x1F\x61\x11\x1A\x05Ralph\x1A\x01 \
                    T\x1A\x05Smith\xA0\x0A\x43\x0819571111 \
                    \x31\x1F\x61\x11\x1A\x05Susan\x1A\x01B\x1A\x05 \
                    Jones\xA0\x0A\x43\x0819590717";

    /// Ensure that the checks work when they should
    #[test_case("oversize_length 132 absolute_offset 0", ASN1_A3, DetectAsn1Data {
            oversize_length: Some(132),
            absolute_offset: Some(0),
            ..Default::default()
        }, Some(Asn1Check::OversizeLength); "Test oversize_length rule (match)" )]
    #[test_case("oversize_length 133 absolute_offset 0", ASN1_A3, DetectAsn1Data {
            oversize_length: Some(133),
            absolute_offset: Some(0),
            ..Default::default()
        }, None; "Test oversize_length rule (non-match)" )]
    #[test_case("bitstring_overflow, absolute_offset 0",
        /* tagnum bitstring, primitive, and as universal tag,
           length = 1 octet, but the next octet specify to ignore the last 256 bits */
        b"\x03\x01\xFF",
        DetectAsn1Data {
            bitstring_overflow: true,
            absolute_offset: Some(0),
            ..Default::default()
        }, Some(Asn1Check::BitstringOverflow); "Test bitstring_overflow rule (match)" )]
    #[test_case("bitstring_overflow, absolute_offset 0",
        /* tagnum bitstring, primitive, and as universal tag,
           length = 1 octet, but the next octet specify to ignore the last 7 bits */
        b"\x03\x01\x07",
        DetectAsn1Data {
            bitstring_overflow: true,
            absolute_offset: Some(0),
            ..Default::default()
        }, None; "Test bitstring_overflow rule (non-match)" )]
    #[test_case("double_overflow, absolute_offset 0",
        {
            static TEST_BUF: [u8; 261] = {
                let mut b = [0x05; 261];
                /* universal class, primitive type, tag_num = 9 (Data type Real) */
                b[0] = 0x09;
                /* length, definite form, 2 octets */
                b[1] = 0x82;
                /* length is the sum of the following octets (257): */
                b[2] = 0x01;
                b[3] = 0x01;

                b
            };

            &TEST_BUF
        },
        DetectAsn1Data {
            double_overflow: true,
            absolute_offset: Some(0),
            ..Default::default()
        }, Some(Asn1Check::DoubleOverflow); "Test double_overflow rule (match)" )]
    #[test_case("double_overflow, absolute_offset 0",
        {
            static TEST_BUF: [u8; 261] = {
                let mut b = [0x05; 261];
                /* universal class, primitive type, tag_num = 9 (Data type Real) */
                b[0] = 0x09;
                /* length, definite form, 2 octets */
                b[1] = 0x82;
                /* length is the sum of the following octets (256): */
                b[2] = 0x01;
                b[3] = 0x00;

                b
            };

            &TEST_BUF
        },
        DetectAsn1Data {
            double_overflow: true,
            absolute_offset: Some(0),
            ..Default::default()
        }, None; "Test double_overflow rule (non-match)" )]
    fn test_checks(
        rule: &str, asn1_buf: &'static [u8], expected_data: DetectAsn1Data,
        expected_check: Option<Asn1Check>,
    ) {
        // Parse rule
        let (_rest, ad) = parse_rules::asn1_parse_rule(rule).unwrap();
        assert_eq!(expected_data, ad);

        // Decode
        let asn1 = Asn1::from_slice(asn1_buf, &ad).unwrap();

        // Run checks
        let result = asn1.check(&ad);
        assert_eq!(expected_check, result);
    }
}
