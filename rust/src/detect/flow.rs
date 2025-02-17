/* Copyright (C) 2025 Open Information Security Foundation
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

use super::uint::{detect_parse_uint, DetectUintData};
use nom7::branch::alt;
use nom7::bytes::complete::{is_a, tag};
use nom7::combinator::{opt, value};
use nom7::IResult;
use std::ffi::CStr;

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(PartialEq, Eq, Clone, Debug)]
/// This data structure is also used in detect-flow-pkts.c
pub enum DetectFlowDir {
    DETECT_FLOW_TOSERVER = 1,
    DETECT_FLOW_TOCLIENT = 2,
    DETECT_FLOW_TOEITHER = 3,
}

#[repr(C)]
#[derive(Debug, PartialEq)]
/// This data structure is also used in detect-flow-pkts.c
pub struct DetectFlowPkts {
    pub pkt_data: DetectUintData<u32>,
    pub dir: DetectFlowDir,
}

#[repr(C)]
#[derive(Debug, PartialEq)]
/// This data structure is also used in detect-flow-pkts.c
pub struct DetectFlowBytes {
    pub byte_data: DetectUintData<u64>,
    pub dir: DetectFlowDir,
}

pub fn detect_parse_flow_direction(i: &str) -> IResult<&str, DetectFlowDir> {
    let (i, fd) = alt((
        value(DetectFlowDir::DETECT_FLOW_TOSERVER, tag("toserver")),
        value(DetectFlowDir::DETECT_FLOW_TOCLIENT, tag("toclient")),
        value(DetectFlowDir::DETECT_FLOW_TOEITHER, tag("either")),
    ))(i)?;
    return Ok((i, fd));
}

pub fn detect_parse_flow_pkts(i: &str) -> IResult<&str, DetectFlowPkts> {
    let (i, _) = opt(is_a(" \t"))(i)?;
    let (i, fd) = detect_parse_flow_direction(i)?;
    let (i, _) = opt(is_a(" \t"))(i)?;
    let (i, _) = tag(",")(i)?;
    let (i, _) = opt(is_a(" \t"))(i)?;
    let (i, du32) = detect_parse_uint::<u32>(i)?;
    return Ok((
        i,
        DetectFlowPkts {
            pkt_data: du32,
            dir: fd,
        },
    ));
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectFlowPktsParse(
    ustr: *const std::os::raw::c_char,
) -> *mut DetectFlowPkts {
    let ft_name: &CStr = CStr::from_ptr(ustr); //unsafe
    if let Ok(s) = ft_name.to_str() {
        if let Ok(ctx) = detect_parse_flow_pkts(s) {
            let boxed = Box::new(ctx);
            return Box::into_raw(boxed) as *mut _;
        }
    }
    return std::ptr::null_mut();
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectFlowPktsFree(ctx: &mut DetectFlowPkts) {
    // Just unbox...
    std::mem::drop(Box::from_raw(ctx));
}


pub fn detect_parse_flow_bytes(i: &str) -> IResult<&str, DetectFlowBytes> {
    let (i, _) = opt(is_a(" \t"))(i)?;
    let (i, fd) = detect_parse_flow_direction(i)?;
    let (i, _) = opt(is_a(" \t"))(i)?;
    let (i, _) = tag(",")(i)?;
    let (i, _) = opt(is_a(" \t"))(i)?;
    let (i, du64) = detect_parse_uint::<u64>(i)?;
    return Ok((
        i,
        DetectFlowBytes {
            byte_data: du64,
            dir: fd,
        },
    ));
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectFlowBytesParse(
    ustr: *const std::os::raw::c_char,
) -> *mut DetectFlowPkts {
    let ft_name: &CStr = CStr::from_ptr(ustr); //unsafe
    if let Ok(s) = ft_name.to_str() {
        if let Ok(ctx) = detect_parse_flow_bytes(s) {
            let boxed = Box::new(ctx);
            return Box::into_raw(boxed) as *mut _;
        }
    }
    return std::ptr::null_mut();
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectFlowBytesFree(ctx: &mut DetectFlowBytes) {
    // Just unbox...
    std::mem::drop(Box::from_raw(ctx));
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::detect::uint::DetectUintMode;

    #[test]
    fn test_detect_parse_flow_pkts() {
        assert_eq!(
            detect_parse_flow_pkts(" toserver  ,   300 ").unwrap().1,
            DetectFlowPkts {
                pkt_data: DetectUintData {
                    arg1: 300,
                    arg2: 0,
                    mode: DetectUintMode::DetectUintModeEqual,
                },
                dir: DetectFlowDir::DETECT_FLOW_TOSERVER,
            }
        );
        assert!(detect_parse_flow_pkts("toserver").is_err());
    }
}
