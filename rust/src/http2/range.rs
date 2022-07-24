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

use super::detect;
use crate::core::{
    Direction, Flow, HttpRangeContainerBlock, StreamingBufferConfig, SuricataFileContext, SC,
};
use crate::filecontainer::FileContainer;
use crate::http2::http2::HTTP2Transaction;

use nom7::branch::alt;
use nom7::bytes::streaming::{take_till, take_while};
use nom7::character::complete::{char, digit1};
use nom7::combinator::{map_res, value};
use nom7::error::{make_error, ErrorKind};
use nom7::{Err, IResult};
use std::os::raw::c_uchar;
use std::str::FromStr;

#[derive(Debug)]
#[repr(C)]
pub struct HTTPContentRange {
    pub start: i64,
    pub end: i64,
    pub size: i64,
}

pub fn http2_parse_content_range_star<'a>(input: &'a [u8]) -> IResult<&'a [u8], HTTPContentRange> {
    let (i2, _) = char('*')(input)?;
    let (i2, _) = char('/')(i2)?;
    let (i2, size) = map_res(map_res(digit1, std::str::from_utf8), i64::from_str)(i2)?;
    return Ok((
        i2,
        HTTPContentRange {
            start: -1,
            end: -1,
            size,
        },
    ));
}

pub fn http2_parse_content_range_def<'a>(input: &'a [u8]) -> IResult<&'a [u8], HTTPContentRange> {
    let (i2, start) = map_res(map_res(digit1, std::str::from_utf8), i64::from_str)(input)?;
    let (i2, _) = char('-')(i2)?;
    let (i2, end) = map_res(map_res(digit1, std::str::from_utf8), i64::from_str)(i2)?;
    let (i2, _) = char('/')(i2)?;
    let (i2, size) = alt((
        value(-1, char('*')),
        map_res(map_res(digit1, std::str::from_utf8), i64::from_str),
    ))(i2)?;
    return Ok((i2, HTTPContentRange { start, end, size }));
}

fn http2_parse_content_range<'a>(input: &'a [u8]) -> IResult<&'a [u8], HTTPContentRange> {
    let (i2, _) = take_while(|c| c == b' ')(input)?;
    let (i2, _) = take_till(|c| c == b' ')(i2)?;
    let (i2, _) = take_while(|c| c == b' ')(i2)?;
    return alt((
        http2_parse_content_range_star,
        http2_parse_content_range_def,
    ))(i2);
}

pub fn http2_parse_check_content_range<'a>(input: &'a [u8]) -> IResult<&'a [u8], HTTPContentRange> {
    let (rem, v) = http2_parse_content_range(input)?;
    if v.start > v.end || (v.end > 0 && v.size > 0 && v.end > v.size - 1) {
        return Err(Err::Error(make_error(rem, ErrorKind::Verify)));
    }
    return Ok((rem, v));
}

#[no_mangle]
pub unsafe extern "C" fn rs_http_parse_content_range(
    cr: &mut HTTPContentRange, buffer: *const u8, buffer_len: u32,
) -> std::os::raw::c_int {
    let slice = build_slice!(buffer, buffer_len as usize);
    match http2_parse_content_range(slice) {
        Ok((_, c)) => {
            *cr = c;
            return 0;
        }
        _ => {
            return -1;
        }
    }
}

fn http2_range_key_get(tx: &mut HTTP2Transaction) -> Result<(Vec<u8>, usize), ()> {
    let hostv = detect::http2_frames_get_header_value_vec(tx, Direction::ToServer, ":authority")?;
    let mut hostv = &hostv[..];
    match hostv.iter().position(|&x| x == b':') {
        Some(p) => {
            hostv = &hostv[..p];
        }
        None => {}
    }
    let uriv = detect::http2_frames_get_header_value_vec(tx, Direction::ToServer, ":path")?;
    let mut uriv = &uriv[..];
    match uriv.iter().position(|&x| x == b'?') {
        Some(p) => {
            uriv = &uriv[..p];
        }
        None => {}
    }
    match uriv.iter().rposition(|&x| x == b'/') {
        Some(p) => {
            uriv = &uriv[p..];
        }
        None => {}
    }
    let mut r = Vec::with_capacity(hostv.len() + uriv.len());
    r.extend_from_slice(hostv);
    r.extend_from_slice(uriv);
    return Ok((r, hostv.len()));
}

pub fn http2_range_open(
    tx: &mut HTTP2Transaction, v: &HTTPContentRange, flow: *const Flow,
    cfg: &'static SuricataFileContext, flags: u16, data: &[u8],
) {
    if v.end <= 0 || v.size <= 0 {
        // skipped for incomplete range information
        return;
    } else if v.end == v.size - 1 && v.start == 0 {
        // whole file in one range
        return;
    }
    if let Ok((key, index)) = http2_range_key_get(tx) {
        let name = &key[index..];
        tx.file_range = unsafe {
            HttpRangeContainerOpenFile(
                key.as_ptr(),
                key.len() as u32,
                flow,
                v,
                cfg.files_sbcfg,
                name.as_ptr(),
                name.len() as u16,
                flags,
                data.as_ptr(),
                data.len() as u32,
            )
        };
    }
}

pub fn http2_range_append(fr: *mut HttpRangeContainerBlock, data: &[u8]) {
    unsafe {
        HttpRangeAppendData(fr, data.as_ptr(), data.len() as u32);
    }
}

pub fn http2_range_close(
    tx: &mut HTTP2Transaction, files: &mut FileContainer, flags: u16, data: &[u8],
) {
    let added = if let Some(c) = unsafe { SC } {
        let added = (c.HTPFileCloseHandleRange)(
            files,
            flags,
            tx.file_range,
            data.as_ptr(),
            data.len() as u32,
        );
        (c.HttpRangeFreeBlock)(tx.file_range);
        added
    } else {
        false
    };
    tx.file_range = std::ptr::null_mut();
    if added {
        tx.tx_data.incr_files_opened();
    }
}

// Defined in app-layer-htp-range.h
extern "C" {
    pub fn HttpRangeContainerOpenFile(
        key: *const c_uchar, keylen: u32, f: *const Flow, cr: &HTTPContentRange,
        sbcfg: *const StreamingBufferConfig, name: *const c_uchar, name_len: u16, flags: u16,
        data: *const c_uchar, data_len: u32,
    ) -> *mut HttpRangeContainerBlock;
    pub fn HttpRangeAppendData(
        c: *mut HttpRangeContainerBlock, data: *const c_uchar, data_len: u32,
    ) -> std::os::raw::c_int;
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_http2_parse_content_range() {
        let buf0: &[u8] = " bytes */100".as_bytes();
        let r0 = http2_parse_content_range(buf0);
        match r0 {
            Ok((rem, rg)) => {
                // Check the first message.
                assert_eq!(rg.start, -1);
                assert_eq!(rg.end, -1);
                assert_eq!(rg.size, 100);
                // And we should have no bytes left.
                assert_eq!(rem.len(), 0);
            }
            _ => {
                panic!("Result should have been ok.");
            }
        }

        let buf1: &[u8] = " bytes 10-20/200".as_bytes();
        let r1 = http2_parse_content_range(buf1);
        match r1 {
            Ok((rem, rg)) => {
                // Check the first message.
                assert_eq!(rg.start, 10);
                assert_eq!(rg.end, 20);
                assert_eq!(rg.size, 200);
                // And we should have no bytes left.
                assert_eq!(rem.len(), 0);
            }
            _ => {
                panic!("Result should have been ok.");
            }
        }

        let buf2: &[u8] = " bytes 30-68/*".as_bytes();
        let r2 = http2_parse_content_range(buf2);
        match r2 {
            Ok((rem, rg)) => {
                // Check the first message.
                assert_eq!(rg.start, 30);
                assert_eq!(rg.end, 68);
                assert_eq!(rg.size, -1);
                // And we should have no bytes left.
                assert_eq!(rem.len(), 0);
            }
            _ => {
                panic!("Result should have been ok.");
            }
        }
    }
}
