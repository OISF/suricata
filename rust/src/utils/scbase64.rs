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

// Author: Shivani Bhardwaj <shivani@oisf.net>

use std::io::{Result, Error, ErrorKind};
use std::ffi::CString;
use std::os::raw::c_char;
use crate::log::vec_to_safe_cstring;

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Base64Mode {
    /* If the following strings were to be passed to the decoder with RFC2045 mode,
     * the results would be as follows. See the unittest B64TestVectorsRFC2045 in
     * src/util-base64.c
     *
     * BASE64("") = ""
     * BASE64("f") = "Zg=="
     * BASE64("fo") = "Zm8="
     * BASE64("foo") = "Zm9v"
     * BASE64("foob") = "Zm9vYg=="
     * BASE64("fooba") = "Zm9vYmE="
     * BASE64("foobar") = "Zm9vYmFy"
     * BASE64("foobar") = "Zm 9v Ym Fy"   <-- Notice how the spaces are ignored
     * BASE64("foobar") = "Zm$9vYm.Fy"    # According to RFC 2045, All line breaks or *other
     * characters* not found in base64 alphabet must be ignored by decoding software
     * */
    Base64ModeRFC2045 = 0, /* SPs are allowed during transfer but must be skipped by Decoder */
    Base64ModeStrict,
    /* If the following strings were to be passed to the decoder with RFC4648 mode,
     * the results would be as follows. See the unittest B64TestVectorsRFC4648 in
     * src/util-base64.c
     *
     * BASE64("") = ""
     * BASE64("f") = "Zg=="
     * BASE64("fo") = "Zm8="
     * BASE64("foo") = "Zm9v"
     * BASE64("foob") = "Zm9vYg=="
     * BASE64("fooba") = "Zm9vYmE="
     * BASE64("foobar") = "Zm9vYmFy"
     * BASE64("f") = "Zm 9v Ym Fy"   <-- Notice how the processing stops once space is encountered
     * BASE64("f") = "Zm$9vYm.Fy"    <-- Notice how the processing stops once an invalid char is
     * encountered
     * */
    Base64ModeRFC4648, /* reject the encoded data if it contains characters outside the base alphabet */
}

fn base64_map(input: u8) -> Result<u8> {
    match input {
        43 => Ok(62),  // +
        47 => Ok(63),  // /
        48 => Ok(52),  // 0
        49 => Ok(53),  // 1
        50 => Ok(54),  // 2
        51 => Ok(55),  // 3
        52 => Ok(56),  // 4
        53 => Ok(57),  // 5
        54 => Ok(58),  // 6
        55 => Ok(59),  // 7
        56 => Ok(60),  // 8
        57 => Ok(61),  // 9
        65 => Ok(0),   // A
        66 => Ok(1),   // B
        67 => Ok(2),   // C
        68 => Ok(3),   // D
        69 => Ok(4),   // E
        70 => Ok(5),   // F
        71 => Ok(6),   // G
        72 => Ok(7),   // H
        73 => Ok(8),   // I
        74 => Ok(9),   // J
        75 => Ok(10),  // K
        76 => Ok(11),  // L
        77 => Ok(12),  // M
        78 => Ok(13),  // N
        79 => Ok(14),  // O
        80 => Ok(15),  // P
        81 => Ok(16),  // Q
        82 => Ok(17),  // R
        83 => Ok(18),  // S
        84 => Ok(19),  // T
        85 => Ok(20),  // U
        86 => Ok(21),  // V
        87 => Ok(22),  // W
        88 => Ok(23),  // X
        89 => Ok(24),  // Y
        90 => Ok(25),  // Z
        97 => Ok(26),  // a
        98 => Ok(27),  // b
        99 => Ok(28),  // c
        100 => Ok(29), // d
        101 => Ok(30), // e
        102 => Ok(31), // f
        103 => Ok(32), // g
        104 => Ok(33), // h
        105 => Ok(34), // i
        106 => Ok(35), // j
        107 => Ok(36), // k
        108 => Ok(37), // l
        109 => Ok(38), // m
        110 => Ok(39), // n
        111 => Ok(40), // o
        112 => Ok(41), // p
        113 => Ok(42), // q
        114 => Ok(43), // r
        115 => Ok(44), // s
        116 => Ok(45), // t
        117 => Ok(46), // u
        118 => Ok(47), // v
        119 => Ok(48), // w
        120 => Ok(49), // x
        121 => Ok(50), // y
        122 => Ok(51), // z
        _ => Err(Error::new(ErrorKind::InvalidData, "invalid base64")),
    }
}

#[derive(Debug)]
pub struct Decoder {
    tmp: [u8; 4],
    pub nb: u8,
}

#[repr(C)]
pub struct Base64Decoded {
    decoded: *const c_char,
    decoded_len: u32,
}

impl Default for Base64Decoded {
    fn default() -> Self {
        Self::new()
    }
}

impl Base64Decoded {
    pub fn new() -> Base64Decoded {
        Base64Decoded {
            decoded: std::ptr::null_mut(),
            decoded_len: 0,
        }
    }
}

impl Drop for Base64Decoded {
    fn drop(&mut self) {
        unsafe {
            if !self.decoded.is_null() {
                let _ = CString::from_raw(self.decoded as *mut c_char);
            }
        }
    }
}

impl Decoder {
    pub fn new() -> Decoder {
        Decoder { tmp: [0; 4], nb: 0 }
    }
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

pub fn decode_rfc4648(decoder: &mut Decoder, input: &[u8], max_decoded: u32) -> Result<Vec<u8>> {
    let mut i = input;
    let mut r = vec![0; max_decoded as usize];
    let mut offset = 0;
    let mut stop = false;
    while !i.is_empty() {
        while decoder.nb < 4 {
            if !i.is_empty() && (base64_map(i[0]).is_ok() || i[0] == b'=') {
                decoder.tmp[decoder.nb as usize] = i[0];
                decoder.nb += 1;
            } else {
                while decoder.nb > 0 && decoder.nb < 4 && (offset + decoder.nb as usize) <= max_decoded as usize {
                    decoder.tmp[decoder.nb as usize] = b'=';
                    decoder.nb += 1;
                }
                stop = true;
                break;
            }
            i = &i[1..];
        }
        if decoder.nb == 4 {
            decoder.tmp[0] = base64_map(decoder.tmp[0])?;
            decoder.tmp[1] = base64_map(decoder.tmp[1])?;
            if decoder.tmp[2] == b'=' {
                r[offset] = (decoder.tmp[0] << 2) | (decoder.tmp[1] >> 4);
                offset += 1;
            } else {
                decoder.tmp[2] = base64_map(decoder.tmp[2])?;
                if decoder.tmp[3] == b'=' {
                    r[offset] = (decoder.tmp[0] << 2) | (decoder.tmp[1] >> 4);
                    r[offset + 1] = (decoder.tmp[1] << 4) | (decoder.tmp[2] >> 2);
                    offset += 2;
                } else {
                    decoder.tmp[3] = base64_map(decoder.tmp[3])?;
                    r[offset] = (decoder.tmp[0] << 2) | (decoder.tmp[1] >> 4);
                    r[offset + 1] = (decoder.tmp[1] << 4) | (decoder.tmp[2] >> 2);
                    r[offset + 2] = (decoder.tmp[2] << 6) | decoder.tmp[3];
                    offset += 3;
                }
            }
            decoder.nb = 0;
        }
        if stop {
            break;
        }
    }
    r.truncate(offset);
    return Ok(r);
}

pub fn decode_rfc2045(decoder: &mut Decoder, input: &[u8]) -> Result<Vec<u8>> {
    let mut i = input;
    let maxlen = ((decoder.nb as usize + i.len()) * 3) / 4;
    let mut r = vec![0; maxlen];
    let mut offset = 0;
    while !i.is_empty() {
        while decoder.nb < 4 && !i.is_empty() {
            if base64_map(i[0]).is_ok() || i[0] == b'=' {
                decoder.tmp[decoder.nb as usize] = i[0];
                decoder.nb += 1;
            }
            i = &i[1..];
        }
        if decoder.nb == 4 {
            decoder.tmp[0] = base64_map(decoder.tmp[0])?;
            decoder.tmp[1] = base64_map(decoder.tmp[1])?;
            if decoder.tmp[2] == b'=' {
                r[offset] = (decoder.tmp[0] << 2) | (decoder.tmp[1] >> 4);
                offset += 1;
            } else {
                decoder.tmp[2] = base64_map(decoder.tmp[2])?;
                if decoder.tmp[3] == b'=' {
                    r[offset] = (decoder.tmp[0] << 2) | (decoder.tmp[1] >> 4);
                    r[offset + 1] = (decoder.tmp[1] << 4) | (decoder.tmp[2] >> 2);
                    offset += 2;
                } else {
                    decoder.tmp[3] = base64_map(decoder.tmp[3])?;
                    r[offset] = (decoder.tmp[0] << 2) | (decoder.tmp[1] >> 4);
                    r[offset + 1] = (decoder.tmp[1] << 4) | (decoder.tmp[2] >> 2);
                    r[offset + 2] = (decoder.tmp[2] << 6) | decoder.tmp[3];
                    offset += 3;
                }
            }
            decoder.nb = 0;
        }
    }
    r.truncate(offset);
    return Ok(r);
}

#[no_mangle]
pub unsafe extern "C" fn rs_base64_decode(input: *const u8, len: u32, max_decoded: u32, mode: Base64Mode) -> *mut Base64Decoded {
    if input.is_null() || len == 0 {
        return std::ptr::null_mut();
    }

    let in_vec: &[u8] = std::slice::from_raw_parts(input as *mut u8, len as usize);
    let mut decoder = Decoder::new();
    let mut decoded_string = Vec::new();
    match mode {
        Base64Mode::Base64ModeRFC2045 => {
            if let Ok(fin_str) = decode_rfc2045(&mut decoder, in_vec) {
                decoded_string = fin_str;
            }
        },
        Base64Mode::Base64ModeRFC4648 => {
            if let Ok(fin_str) = decode_rfc4648(&mut decoder, in_vec, max_decoded) {
                decoded_string = fin_str;
            }
        },
        Base64Mode::Base64ModeStrict => {
            if let Ok(fin_str) = base64::decode(in_vec) {
                decoded_string = fin_str;
            }
        }
    }
    let mut b64_decoded = Base64Decoded::new();
    b64_decoded.decoded_len = decoded_string.len() as u32;
    if b64_decoded.decoded_len == 0 {
        return std::ptr::null_mut();
    } else {
        let safe_cstring = vec_to_safe_cstring(decoded_string);
        let safe_cstring_len = safe_cstring.clone().into_bytes().len() as u32;
        b64_decoded.decoded_len = safe_cstring_len;
        b64_decoded.decoded = safe_cstring.into_raw();
    }
    return Box::into_raw(Box::new(b64_decoded));
}

#[no_mangle]
pub unsafe extern "C" fn rs_base64_decode_free(b64d: *mut std::os::raw::c_void)
{
    std::mem::drop(Box::from_raw(b64d as *mut Base64Decoded));
}
