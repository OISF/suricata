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

use nom7::branch::alt;
use nom7::bytes::complete::{is_a, tag};
use nom7::character::complete::digit1;
use nom7::combinator::{complete, map_opt, opt};
use nom7::IResult;

#[derive(PartialEq, Debug)]
pub enum DetectUintMode {
    DetectUintModeEqual,
    DetectUintModeLt,
    DetectUintModeGt,
    DetectUintModeRange,
}

#[derive(Debug)]
pub struct DetectU32Data {
    pub value: u32,
    pub valrange: u32,
    pub mode: DetectUintMode,
}

fn detect_parse_u32_start_equal(i: &str) -> IResult<&str, DetectU32Data> {
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, _) = opt(tag("="))(i)?;
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, value) = map_opt(digit1, |s: &str| s.parse::<u32>().ok())(i)?;
    Ok((
        i,
        DetectU32Data {
            value,
            valrange: 0,
            mode: DetectUintMode::DetectUintModeEqual,
        },
    ))
}

fn detect_parse_u32_start_interval(i: &str) -> IResult<&str, DetectU32Data> {
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, value) = map_opt(digit1, |s: &str| s.parse::<u32>().ok())(i)?;
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, _) = tag("-")(i)?;
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, valrange) = map_opt(digit1, |s: &str| s.parse::<u32>().ok())(i)?;
    Ok((
        i,
        DetectU32Data {
            value,
            valrange,
            mode: DetectUintMode::DetectUintModeRange,
        },
    ))
}

fn detect_parse_u32_start_lesser(i: &str) -> IResult<&str, DetectU32Data> {
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, _) = tag("<")(i)?;
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, value) = map_opt(digit1, |s: &str| s.parse::<u32>().ok())(i)?;
    Ok((
        i,
        DetectU32Data {
            value,
            valrange: 0,
            mode: DetectUintMode::DetectUintModeLt,
        },
    ))
}

fn detect_parse_u32_start_greater(i: &str) -> IResult<&str, DetectU32Data> {
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, _) = tag(">")(i)?;
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, value) = map_opt(digit1, |s: &str| s.parse::<u32>().ok())(i)?;
    Ok((
        i,
        DetectU32Data {
            value,
            valrange: 0,
            mode: DetectUintMode::DetectUintModeGt,
        },
    ))
}

pub fn detect_match_u32(x: &DetectU32Data, val: u32) -> bool {
    match x.mode {
        DetectUintMode::DetectUintModeEqual => {
            if val == x.value {
                return true;
            }
        }
        DetectUintMode::DetectUintModeLt => {
            if val < x.value {
                return true;
            }
        }
        DetectUintMode::DetectUintModeGt => {
            if val > x.value {
                return true;
            }
        }
        DetectUintMode::DetectUintModeRange => {
            if val < x.value && val > x.valrange {
                return true;
            }
        }
    }
    return false;
}

pub fn detect_parse_u32(i: &str) -> IResult<&str, DetectU32Data> {
    let (i, u32) = alt((
        detect_parse_u32_start_lesser,
        detect_parse_u32_start_greater,
        complete(detect_parse_u32_start_interval),
        detect_parse_u32_start_equal,
    ))(i)?;
    Ok((i, u32))
}

#[derive(Debug)]
pub struct DetectU64Data {
    pub value: u64,
    pub valrange: u64,
    pub mode: DetectUintMode,
}

fn detect_parse_u64_start_equal(i: &str) -> IResult<&str, DetectU64Data> {
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, _) = opt(tag("="))(i)?;
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, value) = map_opt(digit1, |s: &str| s.parse::<u64>().ok())(i)?;
    Ok((
        i,
        DetectU64Data {
            value,
            valrange: 0,
            mode: DetectUintMode::DetectUintModeEqual,
        },
    ))
}

fn detect_parse_u64_start_interval(i: &str) -> IResult<&str, DetectU64Data> {
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, value) = map_opt(digit1, |s: &str| s.parse::<u64>().ok())(i)?;
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, _) = tag("-")(i)?;
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, valrange) = map_opt(digit1, |s: &str| s.parse::<u64>().ok())(i)?;
    Ok((
        i,
        DetectU64Data {
            value,
            valrange,
            mode: DetectUintMode::DetectUintModeRange,
        },
    ))
}

fn detect_parse_u64_start_lesser(i: &str) -> IResult<&str, DetectU64Data> {
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, _) = tag("<")(i)?;
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, value) = map_opt(digit1, |s: &str| s.parse::<u64>().ok())(i)?;
    Ok((
        i,
        DetectU64Data {
            value,
            valrange: 0,
            mode: DetectUintMode::DetectUintModeLt,
        },
    ))
}

fn detect_parse_u64_start_greater(i: &str) -> IResult<&str, DetectU64Data> {
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, _) = tag(">")(i)?;
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, value) = map_opt(digit1, |s: &str| s.parse::<u64>().ok())(i)?;
    Ok((
        i,
        DetectU64Data {
            value,
            valrange: 0,
            mode: DetectUintMode::DetectUintModeGt,
        },
    ))
}

pub fn detect_parse_u64(i: &str) -> IResult<&str, DetectU64Data> {
    let (i, u64) = alt((
        detect_parse_u64_start_lesser,
        detect_parse_u64_start_greater,
        complete(detect_parse_u64_start_interval),
        detect_parse_u64_start_equal,
    ))(i)?;
    Ok((i, u64))
}

pub fn detect_match_u64(x: &DetectU64Data, val: u64) -> bool {
    match x.mode {
        DetectUintMode::DetectUintModeEqual => {
            if val == x.value {
                return true;
            }
        }
        DetectUintMode::DetectUintModeLt => {
            if val < x.value {
                return true;
            }
        }
        DetectUintMode::DetectUintModeGt => {
            if val > x.value {
                return true;
            }
        }
        DetectUintMode::DetectUintModeRange => {
            if val < x.value && val > x.valrange {
                return true;
            }
        }
    }
    return false;
}

#[derive(Debug)]
pub struct DetectU16Data {
    pub value: u16,
    pub valrange: u16,
    pub mode: DetectUintMode,
}

fn detect_parse_u16_start_equal(i: &str) -> IResult<&str, DetectU16Data> {
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, _) = opt(tag("="))(i)?;
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, value) = map_opt(digit1, |s: &str| s.parse::<u16>().ok())(i)?;
    Ok((
        i,
        DetectU16Data {
            value,
            valrange: 0,
            mode: DetectUintMode::DetectUintModeEqual,
        },
    ))
}

fn detect_parse_u16_start_interval(i: &str) -> IResult<&str, DetectU16Data> {
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, value) = map_opt(digit1, |s: &str| s.parse::<u16>().ok())(i)?;
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, _) = tag("-")(i)?;
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, valrange) = map_opt(digit1, |s: &str| s.parse::<u16>().ok())(i)?;
    Ok((
        i,
        DetectU16Data {
            value,
            valrange,
            mode: DetectUintMode::DetectUintModeRange,
        },
    ))
}

fn detect_parse_u16_start_lesser(i: &str) -> IResult<&str, DetectU16Data> {
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, _) = tag("<")(i)?;
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, value) = map_opt(digit1, |s: &str| s.parse::<u16>().ok())(i)?;
    Ok((
        i,
        DetectU16Data {
            value,
            valrange: 0,
            mode: DetectUintMode::DetectUintModeLt,
        },
    ))
}

fn detect_parse_u16_start_greater(i: &str) -> IResult<&str, DetectU16Data> {
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, _) = tag(">")(i)?;
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, value) = map_opt(digit1, |s: &str| s.parse::<u16>().ok())(i)?;
    Ok((
        i,
        DetectU16Data {
            value,
            valrange: 0,
            mode: DetectUintMode::DetectUintModeGt,
        },
    ))
}

pub fn detect_parse_u16(i: &str) -> IResult<&str, DetectU16Data> {
    let (i, u16) = alt((
        detect_parse_u16_start_lesser,
        detect_parse_u16_start_greater,
        complete(detect_parse_u16_start_interval),
        detect_parse_u16_start_equal,
    ))(i)?;
    Ok((i, u16))
}

pub fn detect_match_u16(x: &DetectU16Data, val: u16) -> bool {
    match x.mode {
        DetectUintMode::DetectUintModeEqual => {
            if val == x.value {
                return true;
            }
        }
        DetectUintMode::DetectUintModeLt => {
            if val < x.value {
                return true;
            }
        }
        DetectUintMode::DetectUintModeGt => {
            if val > x.value {
                return true;
            }
        }
        DetectUintMode::DetectUintModeRange => {
            if val < x.value && val > x.valrange {
                return true;
            }
        }
    }
    return false;
}
