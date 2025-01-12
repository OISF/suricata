/* Copyright (C) 2024 Open Information Security Foundation
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

// Author: Jeff Lucovsky <jlucovsky@oisf.net>
//
use crate::detect::error::RuleParseError;
use crate::detect::parser::take_until_whitespace;

use nom7::bytes::complete::tag;
use nom7::character::complete::multispace0;
use nom7::sequence::preceded;
use nom7::{Err, IResult};

use std::ffi::CStr;
use std::os::raw::{c_char, c_void};
use std::slice;

#[repr(u8)]
#[derive(PartialEq, Debug)]
// operators: ==, <, <=, >, >=, !=
pub enum DetectEntropyOperator {
    OperatorEQ = 1,
    OperatorLT = 2,
    OperatorLTE = 3,
    OperatorGT = 4,
    OperatorGTE = 5,
    OperatorNEQ = 6,
}

fn detect_entropy_match(entropy: f64, value: f64, operator: &DetectEntropyOperator) -> bool {
    let res = match operator {
        DetectEntropyOperator::OperatorEQ => entropy == value,
        DetectEntropyOperator::OperatorLT => entropy < value,
        DetectEntropyOperator::OperatorLTE => entropy <= value,
        DetectEntropyOperator::OperatorGT => entropy > value,
        DetectEntropyOperator::OperatorGTE => entropy >= value,
        DetectEntropyOperator::OperatorNEQ => entropy != value,
    };
    res
}

fn get_oper_value(value: &str) -> Result<DetectEntropyOperator, ()> {
    let res = match value {
        "==" => DetectEntropyOperator::OperatorEQ,
        "<" => DetectEntropyOperator::OperatorLT,
        "<=" => DetectEntropyOperator::OperatorLTE,
        ">" => DetectEntropyOperator::OperatorGT,
        ">=" => DetectEntropyOperator::OperatorGTE,
        "!=" => DetectEntropyOperator::OperatorNEQ,
        _ => return Err(()),
    };

    Ok(res)
}
#[repr(C)]
#[derive(Debug)]
pub struct DetectEntropyData {
    offset: i32,
    nbytes: i32,
    value: f64,
    oper: DetectEntropyOperator,
    flags: u8,
}

impl Default for DetectEntropyData {
    fn default() -> Self {
        DetectEntropyData {
            offset: 0,
            nbytes: 0,
            value: 0.0,
            oper: DetectEntropyOperator::OperatorEQ,
            flags: 0,
        }
    }
}
impl DetectEntropyData {
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }
}

// All options have default values except for the entropy value
const DETECT_ENTROPY_FIXED_PARAM_COUNT: usize = 1;
const DETECT_ENTROPY_MAX_PARAM_COUNT: usize = 4;
pub const DETECT_ENTROPY_FLAG_BYTES: u8 = 0x01;
pub const DETECT_ENTROPY_FLAG_OFFSET: u8 = 0x02;
pub const DETECT_ENTROPY_FLAG_VALUE: u8 = 0x04;
pub const DETECT_ENTROPY_FLAG_OPER: u8 = 0x08;

fn parse_entropy(input: &str) -> IResult<&str, DetectEntropyData, RuleParseError<&str>> {
    // Inner utility function for easy error creation.
    fn make_error(reason: String) -> nom7::Err<RuleParseError<&'static str>> {
        Err::Error(RuleParseError::InvalidEntropy(reason))
    }
    let (_, values) = nom7::multi::separated_list1(
        tag(","),
        preceded(multispace0, nom7::bytes::complete::is_not(",")),
    )(input)?;

    if values.len() < DETECT_ENTROPY_FIXED_PARAM_COUNT
        || values.len() > DETECT_ENTROPY_MAX_PARAM_COUNT
    {
        return Err(make_error(format!("Incorrect argument string; at least {} values must be specified but no more than {}: {:?}",
            DETECT_ENTROPY_FIXED_PARAM_COUNT, DETECT_ENTROPY_MAX_PARAM_COUNT, input)));
    }

    let mut entropy = DetectEntropyData::new();
    //for value in &values[0..] {
    for value in values {
        let (mut val, mut name) = take_until_whitespace(value)?;
        val = val.trim();
        name = name.trim();
        match name {
            "bytes" => {
                if 0 != (entropy.flags & DETECT_ENTROPY_FLAG_BYTES) {
                    return Err(make_error("bytes already set".to_string()));
                }
                entropy.nbytes = val
                    .parse::<i32>()
                    .map_err(|_| make_error(format!("invalid bytes value: {}", val)))?;
                entropy.flags |= DETECT_ENTROPY_FLAG_BYTES;
            }
            "offset" => {
                if 0 != (entropy.flags & DETECT_ENTROPY_FLAG_OFFSET) {
                    return Err(make_error("offset already set".to_string()));
                }
                entropy.offset = val
                    .parse::<i32>()
                    .map_err(|_| make_error(format!("invalid offset value: {}", val)))?;
                if entropy.offset > 65535 || entropy.offset < -65535 {
                    return Err(make_error(format!(
                        "invalid offset value: must be between -65535 and 65535: {}",
                        val
                    )));
                }
                entropy.flags |= DETECT_ENTROPY_FLAG_OFFSET;
            }
            "oper" => {
                if 0 != (entropy.flags & DETECT_ENTROPY_FLAG_OPER) {
                    return Err(make_error("operator already set".to_string()));
                }
                entropy.oper = match get_oper_value(val) {
                    Ok(val) => val,
                    Err(_) => {
                        return Err(make_error(format!("unknown operator value {}", val)));
                    }
                };
                entropy.flags |= DETECT_ENTROPY_FLAG_OPER;
            }
            "value" => {
                if 0 != (entropy.flags & DETECT_ENTROPY_FLAG_VALUE) {
                    return Err(make_error("value already set".to_string()));
                }
                entropy.value = val
                    .parse::<f64>()
                    .map_err(|_| make_error(format!("invalid entropy value: {}", val)))?;
                entropy.flags |= DETECT_ENTROPY_FLAG_VALUE;
            }
            _ => {
                return Err(make_error(format!("unknown entropy keyword: {}", name)));
            }
        };
    }

    // an entropy value is required; the default operator is equality
    if (entropy.flags & DETECT_ENTROPY_FLAG_VALUE) != DETECT_ENTROPY_FLAG_VALUE {
        return Err(make_error(format!(
            "required entropy parameter missing: \"{:?}\"",
            input
        )));
    }

    Ok((input, entropy))
}

fn calculate_entropy(data: *const u8, length: i32) -> f64 {
    if data.is_null() || length <= 0 {
        return 0.0;
    }

    // Convert the raw pointer to a slice safely
    let data_slice = unsafe { slice::from_raw_parts(data, length as usize) };

    // Use a 256-element array to store byte frequencies
    let mut frequency = [0u32; 256];

    // Calculate the frequency of each byte
    for &byte in data_slice.iter() {
        frequency[byte as usize] += 1;
    }

    // Calculate entropy using byte frequencies
    let length_f64 = length as f64;
    frequency.iter().fold(0.0, |entropy, &count| {
        if count > 0 {
            let probability = count as f64 / length_f64;
            entropy - probability * probability.log2()
        } else {
            entropy
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectEntropyMatch(
    c_data: *const c_void, length: i32, ctx: &DetectEntropyData,
) -> bool {
    if c_data.is_null() {
        return false;
    }

    let buffer = std::slice::from_raw_parts(c_data as *const u8, length as usize);
    let mut start = buffer;
    let mut count = length;

    // Adjust start and count based on offset and nbytes from context
    if ctx.offset > 0{
		let offset = ctx.offset;
        if offset> count {
            SCLogDebug!("offset {} exceeds buffer length {}", offset, count);
            return false;
        }
        start = &start[offset as usize..];
        count -= offset;
    }

    if ctx.nbytes > 0 {
		let nbytes = ctx.nbytes;
        if nbytes > count {
            SCLogDebug!("byte count {} exceeds buffer length {}", nbytes, count);
            return false;
        }
        count = nbytes;
    }

    // Calculate entropy based on the adjusted buffer slice
    let entropy = calculate_entropy(start.as_ptr(), count);
    SCLogNotice!("entropy is {}", entropy);

    // Use a hypothetical `detect_entropy_match` function to check entropy
    detect_entropy_match(entropy, ctx.value, &ctx.oper)
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectEntropyParse(c_arg: *const c_char) -> *mut DetectEntropyData {
    if c_arg.is_null() {
        return std::ptr::null_mut();
    }

    if let Ok(arg) = CStr::from_ptr(c_arg).to_str() {
        match parse_entropy(arg) {
            Ok((_, detect)) => return Box::into_raw(Box::new(detect)),
            Err(_) => return std::ptr::null_mut(),
        }
    }
    return std::ptr::null_mut();
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectEntropyFree(ptr: *mut c_void) {
    if !ptr.is_null() {
        let _ = Box::from_raw(ptr as *mut DetectEntropyData);
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    // structure equality only used by test cases
    impl PartialEq for DetectEntropyData {
        fn eq(&self, other: &Self) -> bool {
            self.value == other.value
                && self.oper == other.oper
                && self.flags == other.flags
                && self.offset == other.offset
                && self.nbytes == other.nbytes
        }
    }

    fn valid_test(
        args: &str, nbytes: i32, offset: i32, oper: DetectEntropyOperator, value: f64, flags: u8,
    ) {
        let ded = DetectEntropyData {
            offset,
            nbytes,
            value,
            oper,
            flags,
        };

        let (_, val) = parse_entropy(args).unwrap();
        assert_eq!(val, ded);
    }

    #[test]
    fn test_parse_entropy_valid() {
        valid_test(
            "value 7",
            0,
            0,
            DetectEntropyOperator::OperatorEQ,
            7.0,
            DETECT_ENTROPY_FLAG_VALUE,
        );
        valid_test(
            "bytes 4, value 7, oper >=",
            4,
            0,
            DetectEntropyOperator::OperatorGTE,
            7.0,
            DETECT_ENTROPY_FLAG_OPER | DETECT_ENTROPY_FLAG_VALUE | DETECT_ENTROPY_FLAG_BYTES,
        );
        valid_test(
            "bytes 4, value 7, oper !=",
            4,
            0,
            DetectEntropyOperator::OperatorNEQ,
            7.0,
            DETECT_ENTROPY_FLAG_OPER | DETECT_ENTROPY_FLAG_VALUE | DETECT_ENTROPY_FLAG_BYTES,
        );
        valid_test(
            "bytes 4, value 7, oper <",
            4,
            0,
            DetectEntropyOperator::OperatorLT,
            7.0,
            DETECT_ENTROPY_FLAG_OPER | DETECT_ENTROPY_FLAG_VALUE | DETECT_ENTROPY_FLAG_BYTES,
        );
        valid_test(
            "bytes 4, value 7, oper <=",
            4,
            0,
            DetectEntropyOperator::OperatorLTE,
            7.0,
            DETECT_ENTROPY_FLAG_OPER | DETECT_ENTROPY_FLAG_VALUE | DETECT_ENTROPY_FLAG_BYTES,
        );
        valid_test(
            "bytes 4, value 7, oper ==",
            4,
            0,
            DetectEntropyOperator::OperatorEQ,
            7.0,
            DETECT_ENTROPY_FLAG_OPER | DETECT_ENTROPY_FLAG_VALUE | DETECT_ENTROPY_FLAG_BYTES,
        );
        valid_test(
            "bytes 4, value 7, oper >",
            4,
            0,
            DetectEntropyOperator::OperatorGT,
            7.0,
            DETECT_ENTROPY_FLAG_OPER | DETECT_ENTROPY_FLAG_VALUE | DETECT_ENTROPY_FLAG_BYTES,
        );
        valid_test(
            "bytes 4, offset 30, value 7, oper >",
            4,
            30,
            DetectEntropyOperator::OperatorGT,
            7.0,
            DETECT_ENTROPY_FLAG_OPER
                | DETECT_ENTROPY_FLAG_VALUE
                | DETECT_ENTROPY_FLAG_BYTES
                | DETECT_ENTROPY_FLAG_OFFSET,
        );
        valid_test(
            "bytes 4, offset 30, value 7",
            4,
            30,
            DetectEntropyOperator::OperatorEQ,
            7.0,
            DETECT_ENTROPY_FLAG_VALUE | DETECT_ENTROPY_FLAG_BYTES | DETECT_ENTROPY_FLAG_OFFSET,
        );
        valid_test(
            "bytes 4, offset 30, oper <, value 7",
            4,
            30,
            DetectEntropyOperator::OperatorLT,
            7.0,
            DETECT_ENTROPY_FLAG_VALUE
                | DETECT_ENTROPY_FLAG_OPER
                | DETECT_ENTROPY_FLAG_BYTES
                | DETECT_ENTROPY_FLAG_OFFSET,
        );
        valid_test(
            "bytes 4, offset 30, oper <=,value 7",
            4,
            30,
            DetectEntropyOperator::OperatorLTE,
            7.0,
            DETECT_ENTROPY_FLAG_OPER
                | DETECT_ENTROPY_FLAG_VALUE
                | DETECT_ENTROPY_FLAG_BYTES
                | DETECT_ENTROPY_FLAG_OFFSET,
        );
    }

    #[test]
    fn test_parse_entropy_invalid() {
        assert!(parse_entropy("").is_err());
        assert!(parse_entropy("value ? 7.0").is_err());
        assert!(parse_entropy("bytes 100").is_err());
        assert!(parse_entropy("offset 100").is_err());
        assert!(parse_entropy("bytes 100, offset 100").is_err());
        assert!(parse_entropy("bytes 1, offset 10, oper >, value 7.0, extra").is_err());
    }

    #[test]
    fn test_entropy_calculation() {
        // Test data
        let data = b"aaaaaaa"; // All the same byte
        let length = data.len() as i32;

        // Calculate entropy
        let entropy = calculate_entropy(data.as_ptr(), length);

        // Expected entropy is 0 (no randomness)
        assert!(
            (entropy - 0.0).abs() < 1e-6,
            "Entropy should be 0.0 for identical bytes"
        );

        // Test data with more randomness
        let data = b"abcdabcd"; // Equal distribution
        let length = data.len() as i32;

        // Calculate entropy
        let entropy = calculate_entropy(data.as_ptr(), length);

        // Expected entropy is 2 (each byte has 1/4 probability)
        assert!(
            (entropy - 2.0).abs() < 1e-6,
            "Entropy should be 2.0 for uniform distribution of 4 values"
        );

        // Test empty data
        let data: [u8; 0] = [];
        let length = data.len() as i32;

        // Calculate entropy
        let entropy = calculate_entropy(data.as_ptr(), length);

        // Expected entropy is 0 (no data)
        assert!(
            (entropy - 0.0).abs() < 1e-6,
            "Entropy should be 0.0 for empty data"
        );

        // Test mixed data
        let data = b"aaabbcc";
        let length = data.len() as i32;

        // Calculate entropy
        let entropy = calculate_entropy(data.as_ptr(), length);

        // Verify entropy is non-zero and less than maximum
        assert!(
            entropy > 0.0 && entropy <= 8.0,
            "Entropy should be between 0.0 and 8.0"
        );
    }
}
