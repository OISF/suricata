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
use nom7::combinator::{complete, map_opt, opt, verify};
use nom7::IResult;

#[derive(PartialEq, Debug)]
pub enum DetectUintMode {
    DetectUintModeEqual,
    DetectUintModeLt,
    DetectUintModeGt,
    DetectUintModeRange,
    DetectUintModeNe,
}

#[derive(Debug)]
pub struct DetectUintData<T> {
    pub value: T,
    pub valrange: T,
    pub mode: DetectUintMode,
}

fn detect_parse_uint_start_equal<T: std::str::FromStr + std::cmp::PartialOrd + num::Bounded>(
    i: &str,
) -> IResult<&str, DetectUintData<T>> {
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, _) = opt(tag("="))(i)?;
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, value) = map_opt(digit1, |s: &str| s.parse::<T>().ok())(i)?;
    Ok((
        i,
        DetectUintData {
            value,
            valrange: T::min_value(),
            mode: DetectUintMode::DetectUintModeEqual,
        },
    ))
}

fn detect_parse_uint_start_ne<T: std::str::FromStr + std::cmp::PartialOrd + num::Bounded>(
    i: &str,
) -> IResult<&str, DetectUintData<T>> {
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, _) = opt(tag("!"))(i)?;
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, value) = map_opt(digit1, |s: &str| s.parse::<T>().ok())(i)?;
    Ok((
        i,
        DetectUintData {
            value,
            valrange: T::min_value(),
            mode: DetectUintMode::DetectUintModeNe,
        },
    ))
}

fn detect_parse_uint_start_interval<
    T: std::str::FromStr
        + std::cmp::PartialOrd
        + num::Bounded
        + std::ops::Sub<Output = T>
        + num::One
        + Copy,
>(
    i: &str,
) -> IResult<&str, DetectUintData<T>> {
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, value) = map_opt(digit1, |s: &str| s.parse::<T>().ok())(i)?;
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, _) = tag("-")(i)?;
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, valrange) = verify(map_opt(digit1, |s: &str| s.parse::<T>().ok()), |x| {
        x > &value && *x - value > T::one()
    })(i)?;
    Ok((
        i,
        DetectUintData {
            value,
            valrange,
            mode: DetectUintMode::DetectUintModeRange,
        },
    ))
}

fn detect_parse_uint_start_lesser<T: std::str::FromStr + std::cmp::PartialOrd + num::Bounded>(
    i: &str,
) -> IResult<&str, DetectUintData<T>> {
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, _) = tag("<")(i)?;
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, value) = verify(map_opt(digit1, |s: &str| s.parse::<T>().ok()), |x| {
        x > &T::min_value()
    })(i)?;
    Ok((
        i,
        DetectUintData {
            value,
            valrange: T::min_value(),
            mode: DetectUintMode::DetectUintModeLt,
        },
    ))
}

fn detect_parse_uint_start_greater<T: std::str::FromStr + std::cmp::PartialOrd + num::Bounded>(
    i: &str,
) -> IResult<&str, DetectUintData<T>> {
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, _) = tag(">")(i)?;
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, value) = verify(map_opt(digit1, |s: &str| s.parse::<T>().ok()), |x| {
        x < &T::max_value()
    })(i)?;
    Ok((
        i,
        DetectUintData {
            value,
            valrange: T::min_value(),
            mode: DetectUintMode::DetectUintModeGt,
        },
    ))
}

pub fn detect_match_uint<T: std::str::FromStr + std::cmp::PartialOrd + num::Bounded>(
    x: &DetectUintData<T>, val: T,
) -> bool {
    match x.mode {
        DetectUintMode::DetectUintModeEqual => {
            if val == x.value {
                return true;
            }
        }
        DetectUintMode::DetectUintModeNe => {
            if val != x.value {
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
            if val > x.value && val < x.valrange {
                return true;
            }
        }
    }
    return false;
}

pub fn detect_parse_uint<
    T: std::str::FromStr
        + std::cmp::PartialOrd
        + num::Bounded
        + std::ops::Sub<Output = T>
        + num::One
        + Copy,
>(
    i: &str,
) -> IResult<&str, DetectUintData<T>> {
    let (i, uint) = alt((
        detect_parse_uint_start_lesser,
        detect_parse_uint_start_greater,
        complete(detect_parse_uint_start_interval),
        detect_parse_uint_start_equal,
        detect_parse_uint_start_ne,
    ))(i)?;
    Ok((i, uint))
}
