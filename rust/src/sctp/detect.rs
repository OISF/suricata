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

// Author: Giuseppe Longo <glongo@oisf.net>

use crate::detect::uint::{detect_parse_uint_enum, DetectUintData};
use crate::detect::EnumString;
use crate::jsonbuilder::JsonBuilder;
use suricata_sys::sys::SCJsonBuilder;

use std::ffi::CStr;

/// SCTP chunk types (RFC 4960 sec 3.2)
#[repr(u8)]
#[derive(EnumStringU8)]
pub enum SctpChunkType {
    Data = 0x00,
    Init = 0x01,
    InitAck = 0x02,
    Sack = 0x03,
    Heartbeat = 0x04,
    HbAck = 0x05,
    Abort = 0x06,
    Shutdown = 0x07,
    ShutdownAck = 0x08,
    Error = 0x09,
    CookieEcho = 0x0A,
    CookieAck = 0x0B,
    Ecne = 0x0C,
    Cwr = 0x0D,
    ShutdownComplete = 0x0E,
    ForwardTsn = 0xC0,
}

#[no_mangle]
pub unsafe extern "C" fn SCSctpDetectChunkTypeParse(
    ustr: *const std::os::raw::c_char,
) -> *mut DetectUintData<u8> {
    let ft_name: &CStr = CStr::from_ptr(ustr);
    if let Ok(s) = ft_name.to_str() {
        if let Some(ctx) = detect_parse_uint_enum::<u8, SctpChunkType>(s) {
            let boxed = Box::new(ctx);
            return Box::into_raw(boxed) as *mut _;
        }
    }
    return std::ptr::null_mut();
}

/// Returns the string name for a chunk type value, or NULL for unknown types.
#[no_mangle]
pub extern "C" fn SCSctpChunkTypeToString(val: u8) -> *const std::os::raw::c_char {
    let s: &[u8] = match val {
        0x00 => b"data\0",
        0x01 => b"init\0",
        0x02 => b"init_ack\0",
        0x03 => b"sack\0",
        0x04 => b"heartbeat\0",
        0x05 => b"hb_ack\0",
        0x06 => b"abort\0",
        0x07 => b"shutdown\0",
        0x08 => b"shutdown_ack\0",
        0x09 => b"error\0",
        0x0A => b"cookie_echo\0",
        0x0B => b"cookie_ack\0",
        0x0C => b"ecne\0",
        0x0D => b"cwr\0",
        0x0E => b"shutdown_complete\0",
        0xC0 => b"forward_tsn\0",
        _ => return std::ptr::null(),
    };
    s.as_ptr() as *const std::os::raw::c_char
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectSCTPChunkTypeListValues(jsb: *mut SCJsonBuilder) {
    let jsb = cast_pointer!(jsb, JsonBuilder);
    let _ = SctpChunkType::list_values(jsb);
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::detect::uint::DetectUintMode;

    #[test]
    fn parse_numeric() {
        let ctx = detect_parse_uint_enum::<u8, SctpChunkType>("0").unwrap();
        assert_eq!(ctx.arg1, 0);
        let ctx = detect_parse_uint_enum::<u8, SctpChunkType>("1").unwrap();
        assert_eq!(ctx.arg1, 1);
        let ctx = detect_parse_uint_enum::<u8, SctpChunkType>("192").unwrap();
        assert_eq!(ctx.arg1, 0xC0);
    }

    #[test]
    fn parse_named() {
        let ctx = detect_parse_uint_enum::<u8, SctpChunkType>("data").unwrap();
        assert_eq!(ctx.arg1, 0);
        let ctx = detect_parse_uint_enum::<u8, SctpChunkType>("init").unwrap();
        assert_eq!(ctx.arg1, 1);
        let ctx = detect_parse_uint_enum::<u8, SctpChunkType>("init_ack").unwrap();
        assert_eq!(ctx.arg1, 2);
        let ctx = detect_parse_uint_enum::<u8, SctpChunkType>("sack").unwrap();
        assert_eq!(ctx.arg1, 3);
        let ctx = detect_parse_uint_enum::<u8, SctpChunkType>("heartbeat").unwrap();
        assert_eq!(ctx.arg1, 4);
        let ctx = detect_parse_uint_enum::<u8, SctpChunkType>("hb_ack").unwrap();
        assert_eq!(ctx.arg1, 5);
        let ctx = detect_parse_uint_enum::<u8, SctpChunkType>("abort").unwrap();
        assert_eq!(ctx.arg1, 6);
        let ctx = detect_parse_uint_enum::<u8, SctpChunkType>("shutdown").unwrap();
        assert_eq!(ctx.arg1, 7);
        let ctx = detect_parse_uint_enum::<u8, SctpChunkType>("cookie_echo").unwrap();
        assert_eq!(ctx.arg1, 0x0A);
        let ctx = detect_parse_uint_enum::<u8, SctpChunkType>("forward_tsn").unwrap();
        assert_eq!(ctx.arg1, 0xC0);
    }

    #[test]
    fn parse_case_insensitive() {
        let ctx = detect_parse_uint_enum::<u8, SctpChunkType>("INIT").unwrap();
        assert_eq!(ctx.arg1, 1);
        let ctx = detect_parse_uint_enum::<u8, SctpChunkType>("Init").unwrap();
        assert_eq!(ctx.arg1, 1);
        let ctx = detect_parse_uint_enum::<u8, SctpChunkType>("INIT_ACK").unwrap();
        assert_eq!(ctx.arg1, 2);
    }

    #[test]
    fn parse_negation() {
        let ctx = detect_parse_uint_enum::<u8, SctpChunkType>("!init").unwrap();
        assert_eq!(ctx.arg1, 1);
        assert_eq!(ctx.mode, DetectUintMode::DetectUintModeNe);
    }

    #[test]
    fn parse_invalid() {
        assert!(detect_parse_uint_enum::<u8, SctpChunkType>("foo").is_none());
        assert!(detect_parse_uint_enum::<u8, SctpChunkType>("").is_none());
    }
}
