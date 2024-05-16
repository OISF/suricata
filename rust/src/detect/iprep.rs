/* Copyright (C) 2022 Open Information Security Foundation
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

use super::uint::*;
use crate::detect::error::RuleParseError;
use nom7::bytes::complete::tag;
use nom7::character::complete::multispace0;
use nom7::sequence::preceded;

use nom7::Err;
use nom7::IResult;

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::str::FromStr;

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, FromPrimitive, Debug)]
pub enum DetectIPRepDataCmd {
    IPRepCmdAny = 0,
    IPRepCmdBoth = 1,
    IPRepCmdSrc = 2,
    IPRepCmdDst = 3,
}

impl std::str::FromStr for DetectIPRepDataCmd {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "any" => Ok(DetectIPRepDataCmd::IPRepCmdAny),
            "both" => Ok(DetectIPRepDataCmd::IPRepCmdBoth),
            "src" => Ok(DetectIPRepDataCmd::IPRepCmdSrc),
            "dst" => Ok(DetectIPRepDataCmd::IPRepCmdDst),
            _ => Err(format!(
                "'{}' is not a valid value for DetectIPRepDataCmd",
                s
            )),
        }
    }
}

/// value matching is done use `DetectUintData` logic.
/// isset matching is done using special `DetectUintData` value ">= 0"
/// isnotset matching bypasses `DetectUintData` and is handled directly
/// in the match function (in C).
#[derive(Debug)]
#[repr(C)]
pub struct DetectIPRepData {
    pub du8: DetectUintData<u8>,
    pub cat: u8,
    pub cmd: DetectIPRepDataCmd,
    pub isnotset: bool, // if true, ignores `du8`
}

pub fn is_alphanumeric_or_slash(chr: char) -> bool {
    if chr.is_ascii_alphanumeric() {
        return true;
    }
    if chr == '_' || chr == '-' {
        return true;
    }
    return false;
}

extern "C" {
    pub fn SRepCatGetByShortname(name: *const c_char) -> u8;
}

pub fn detect_parse_iprep(i: &str) -> IResult<&str, DetectIPRepData, RuleParseError<&str>> {
    // Inner utility function for easy error creation.
    fn make_error(reason: String) -> nom7::Err<RuleParseError<&'static str>> {
        Err::Error(RuleParseError::InvalidIPRep(reason))
    }
    let (_, values) = nom7::multi::separated_list1(
        tag(","),
        preceded(multispace0, nom7::bytes::complete::is_not(",")),
    )(i)?;

    let args = values.len();
    if args == 4 || args == 3 {
        let cmd = if let Ok(cmd) = DetectIPRepDataCmd::from_str(values[0].trim()) {
            cmd
        } else {
            return Err(make_error("invalid command".to_string()));
        };
        let name = values[1].trim();
        let namez = if let Ok(name) = CString::new(name) {
            name
        } else {
            return Err(make_error("invalid name".to_string()));
        };
        let cat = unsafe { SRepCatGetByShortname(namez.as_ptr()) };
        if cat == 0 {
            return Err(make_error("unknown category".to_string()));
        }

        if values.len() == 4 {
            let mode = match detect_parse_uint_mode(values[2].trim()) {
                Ok(val) => val.1,
                Err(_) => return Err(make_error("invalid mode".to_string())),
            };

            let arg1 = match values[3].trim().parse::<u8>() {
                Ok(val) => val,
                Err(_) => return Err(make_error("invalid value".to_string())),
            };
            let du8 = DetectUintData::<u8> {
                arg1,
                arg2: 0,
                mode,
            };
            return Ok((i, DetectIPRepData { du8, cat, cmd, isnotset: false, }));
        } else {
            let (isnotset, mode, arg1) = match values[2].trim() {
                "isset" => { (false, DetectUintMode::DetectUintModeGte, 0) },
                "isnotset" => { (true, DetectUintMode::DetectUintModeEqual, 0) },
                _ => { return Err(make_error("invalid mode".to_string())); },
            };
            let du8 = DetectUintData::<u8> {
                arg1,
                arg2: 0,
                mode,
            };
            return Ok((i, DetectIPRepData { du8, cat, cmd, isnotset, }));
        }
    } else if args < 3 {
        return Err(make_error("too few arguments".to_string()));
    } else  {
        return Err(make_error("too many arguments".to_string()));
    }

}

#[no_mangle]
pub unsafe extern "C" fn rs_detect_iprep_parse(
    ustr: *const std::os::raw::c_char,
) -> *mut DetectIPRepData {
    let ft_name: &CStr = CStr::from_ptr(ustr); //unsafe
    if let Ok(s) = ft_name.to_str() {
        if let Ok((_, ctx)) = detect_parse_iprep(s) {
            let boxed = Box::new(ctx);
            return Box::into_raw(boxed) as *mut _;
        }
    }
    return std::ptr::null_mut();
}

#[no_mangle]
pub unsafe extern "C" fn rs_detect_iprep_free(ctx: &mut DetectIPRepData) {
    // Just unbox...
    std::mem::drop(Box::from_raw(ctx));
}
