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

use super::dns::DNSTransaction;
use crate::core::*;
use std::ffi::CStr;
use std::os::raw::{c_char, c_void};

#[derive(Debug, PartialEq, Eq)]
pub struct DetectDnsOpcode {
    negate: bool,
    opcode: u8,
}

/// Parse a DNS opcode argument returning the code and if it is to be
/// negated or not.
///
/// For now only an indication that an error occurred is returned, not
/// the details of the error.
fn parse_opcode(opcode: &str) -> Result<DetectDnsOpcode, ()> {
    let mut negated = false;
    for (i, c) in opcode.chars().enumerate() {
        match c {
            ' ' | '\t' => {
                continue;
            }
            '!' => {
                negated = true;
            }
            _ => {
                let code: u8 = opcode[i..].parse().map_err(|_| ())?;
                return Ok(DetectDnsOpcode {
                    negate: negated,
                    opcode: code,
                });
            }
        }
    }
    Err(())
}

/// Perform the DNS opcode match.
///
/// 1 will be returned on match, otherwise 0 will be returned.
#[no_mangle]
pub extern "C" fn rs_dns_opcode_match(
    tx: &mut DNSTransaction,
    detect: &mut DetectDnsOpcode,
    flags: u8,
) -> u8 {
    let header_flags = if flags & Direction::ToServer as u8 != 0 {
        if let Some(request) = &tx.request {
            request.header.flags
        } else {
            return 0;
        }
    } else if flags & Direction::ToClient as u8 != 0 {
        if let Some(response) = &tx.response {
            response.header.flags
        } else {
            return 0;
        }
    } else {
        // Not to server or to client??
        return 0;
    };

    if match_opcode(detect, header_flags) {
        1
    } else {
        0
    }
}

fn match_opcode(detect: &DetectDnsOpcode, flags: u16) -> bool {
    let opcode = ((flags >> 11) & 0xf) as u8;
    if detect.negate {
        detect.opcode != opcode
    } else {
        detect.opcode == opcode
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_detect_dns_opcode_parse(carg: *const c_char) -> *mut c_void {
    if carg.is_null() {
        return std::ptr::null_mut();
    }
    let arg = match CStr::from_ptr(carg).to_str() {
        Ok(arg) => arg,
        _ => {
            return std::ptr::null_mut();
        }
    };

    match parse_opcode(arg) {
        Ok(detect) => Box::into_raw(Box::new(detect)) as *mut _,
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_dns_detect_opcode_free(ptr: *mut c_void) {
    if !ptr.is_null() {
        std::mem::drop(Box::from_raw(ptr as *mut DetectDnsOpcode));
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parse_opcode_good() {
        assert_eq!(
            parse_opcode("1"),
            Ok(DetectDnsOpcode {
                negate: false,
                opcode: 1
            })
        );
        assert_eq!(
            parse_opcode("123"),
            Ok(DetectDnsOpcode {
                negate: false,
                opcode: 123
            })
        );
        assert_eq!(
            parse_opcode("!123"),
            Ok(DetectDnsOpcode {
                negate: true,
                opcode: 123
            })
        );
        assert_eq!(
            parse_opcode("!123"),
            Ok(DetectDnsOpcode {
                negate: true,
                opcode: 123
            })
        );
        assert_eq!(parse_opcode(""), Err(()));
        assert_eq!(parse_opcode("!"), Err(()));
        assert_eq!(parse_opcode("!   "), Err(()));
        assert_eq!(parse_opcode("!asdf"), Err(()));
    }

    #[test]
    fn test_match_opcode() {
        assert_eq!(
            match_opcode(
                &DetectDnsOpcode {
                    negate: false,
                    opcode: 0,
                },
                0b0000_0000_0000_0000,
            ),
            true
        );

        assert_eq!(
            match_opcode(
                &DetectDnsOpcode {
                    negate: true,
                    opcode: 0,
                },
                0b0000_0000_0000_0000,
            ),
            false
        );

        assert_eq!(
            match_opcode(
                &DetectDnsOpcode {
                    negate: false,
                    opcode: 4,
                },
                0b0010_0000_0000_0000,
            ),
            true
        );

        assert_eq!(
            match_opcode(
                &DetectDnsOpcode {
                    negate: true,
                    opcode: 4,
                },
                0b0010_0000_0000_0000,
            ),
            false
        );
    }
}
