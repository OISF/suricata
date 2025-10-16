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
use nom7::bytes::complete::{is_a, tag, tag_no_case, take, take_till, take_while};
use nom7::character::complete::{anychar, char, digit1, hex_digit1, i32 as nom_i32};
use nom7::combinator::{all_consuming, map_opt, opt, value, verify};
use nom7::error::{make_error, Error, ErrorKind};
use nom7::Err;
use nom7::IResult;

use super::EnumString;

use std::ffi::{c_int, c_void, CStr};

#[derive(PartialEq, Eq, Clone, Debug)]
#[repr(u8)]
pub enum DetectUintMode {
    DetectUintModeEqual,
    DetectUintModeLt,
    DetectUintModeLte,
    DetectUintModeGt,
    DetectUintModeGte,
    DetectUintModeRange,
    DetectUintModeNe,
    DetectUintModeNegRg,
    DetectUintModeBitmask,
    DetectUintModeNegBitmask,
}

#[derive(Clone, Debug, PartialEq)]
#[repr(C)]
pub struct DetectUintData<T> {
    pub arg1: T,
    pub arg2: T,
    pub mode: DetectUintMode,
}

#[derive(Debug, PartialEq)]
pub enum DetectUintIndex {
    Any,
    AllOrAbsent,
    All,
    OrAbsent,
    Index((bool, i32)),
    NumberMatches(DetectUintData<u32>),
    Count(DetectUintData<u32>),
}

#[derive(Debug, PartialEq)]
pub struct DetectUintArrayData<T> {
    pub du: DetectUintData<T>,
    pub index: DetectUintIndex,
    // subslice
    pub start: i32,
    pub end: i32,
}

fn parse_uint_index_precise(s: &str) -> IResult<&str, DetectUintIndex> {
    let (s, oob) = opt(tag("oob_or"))(s)?;
    let (s, _) = opt(is_a(" "))(s)?;
    let (s, i32_index) = nom_i32(s)?;
    Ok((s, DetectUintIndex::Index((oob.is_some(), i32_index))))
}

fn parse_uint_index_nb(s: &str) -> IResult<&str, DetectUintIndex> {
    let (s, _) = tag("nb")(s)?;
    let (s, _) = opt(is_a(" "))(s)?;
    let (s, du32) = detect_parse_uint::<u32>(s)?;
    Ok((s, DetectUintIndex::NumberMatches(du32)))
}

fn parse_uint_index_val(s: &str) -> Option<DetectUintIndex> {
    let (_s, arg1) = alt((parse_uint_index_precise, parse_uint_index_nb))(s).ok()?;
    Some(arg1)
}

fn parse_uint_subslice_aux(s: &str) -> IResult<&str, (i32, i32)> {
    let (s, start) = nom_i32(s)?;
    let (s, _) = char(':')(s)?;
    let (s, end) = nom_i32(s)?;
    return Ok((s, (start, end)));
}

fn parse_uint_subslice(parts: &[&str]) -> Option<(i32, i32)> {
    if parts.len() < 3 {
        return Some((0, 0));
    }
    let (_, (start, end)) = parse_uint_subslice_aux(parts[2]).ok()?;
    if start > 0 && end > 0 && end <= start {
        SCLogError!("subslice must end after start {} {}", start, end);
        return None;
    }
    if start < 0 && end < 0 && end <= start {
        SCLogError!("subslice must end after start {} {}", start, end);
        return None;
    }
    return Some((start, end));
}

fn parse_uint_count(s: &str) -> IResult<&str, DetectUintData<u32>> {
    let (s, _) = tag("count")(s)?;
    let (s, _) = opt(is_a(" "))(s)?;
    let (s, du32) = detect_parse_uint::<u32>(s)?;
    Ok((s, du32))
}

fn parse_uint_index(parts: &[&str]) -> Option<DetectUintIndex> {
    let index = if parts.len() >= 2 {
        match parts[1] {
            "all" => DetectUintIndex::All,
            "all_or_absent" => DetectUintIndex::AllOrAbsent,
            "any" => DetectUintIndex::Any,
            "or_absent" => DetectUintIndex::OrAbsent,
            // not only a literal, but some numeric value
            _ => return parse_uint_index_val(parts[1]),
        }
    } else if let Ok((_, du)) = parse_uint_count(parts[0]) {
        DetectUintIndex::Count(du)
    } else {
        DetectUintIndex::Any
    };
    return Some(index);
}

pub(crate) fn detect_parse_array_uint<T: DetectIntType>(s: &str) -> Option<DetectUintArrayData<T>> {
    let parts: Vec<&str> = s.split(',').collect();
    if parts.len() > 3 {
        SCLogError!("Too many comma-separated parts in multi-integer");
        return None;
    }

    let index = parse_uint_index(&parts)?;
    if let DetectUintIndex::Count(_) = &index {
        return Some(DetectUintArrayData {
            du: DetectUintData::<T> {
                arg1: T::min_value(),
                arg2: T::min_value(),
                mode: DetectUintMode::DetectUintModeEqual,
            },
            index,
            start: 0,
            end: 0,
        });
    }

    let (_, du) = detect_parse_uint::<T>(parts[0]).ok()?;
    let (start, end) = parse_uint_subslice(&parts)?;

    Some(DetectUintArrayData {
        du,
        index,
        start,
        end,
    })
}

pub(crate) fn detect_parse_array_uint_enum<T1: DetectIntType, T2: EnumString<T1>>(
    s: &str,
) -> Option<DetectUintArrayData<T1>> {
    let parts: Vec<&str> = s.split(',').collect();
    if parts.len() > 3 {
        SCLogError!("Too many comma-separated parts in multi-integer");
        return None;
    }

    let index = parse_uint_index(&parts)?;
    if let DetectUintIndex::Count(_) = &index {
        return Some(DetectUintArrayData {
            du: DetectUintData::<T1> {
                arg1: T1::min_value(),
                arg2: T1::min_value(),
                mode: DetectUintMode::DetectUintModeEqual,
            },
            index,
            start: 0,
            end: 0,
        });
    }

    let du = detect_parse_uint_enum::<T1, T2>(parts[0])?;
    let (start, end) = parse_uint_subslice(&parts)?;

    Some(DetectUintArrayData {
        du,
        index,
        start,
        end,
    })
}

pub(crate) fn detect_uint_match_at_index<T, U: DetectIntType>(
    array: &[T], ctx: &DetectUintArrayData<U>, get_value: impl Fn(&T) -> Option<U>, eof: bool,
) -> c_int {
    let start = if ctx.start >= 0 {
        ctx.start as usize
    } else {
        ((array.len() as i32) + ctx.start) as usize
    };
    let end = if ctx.end > 0 {
        ctx.end as usize
    } else {
        ((array.len() as i32) + ctx.end) as usize
    };
    let subslice = if end > array.len() || start >= end {
        &array[..0]
    } else {
        &array[start..end]
    };
    match &ctx.index {
        DetectUintIndex::Any => {
            for response in subslice {
                if let Some(code) = get_value(response) {
                    if detect_match_uint::<U>(&ctx.du, code) {
                        return 1;
                    }
                }
            }
            return 0;
        }
        DetectUintIndex::OrAbsent => {
            let mut has_elem = false;
            for response in subslice {
                if let Some(code) = get_value(response) {
                    if detect_match_uint::<U>(&ctx.du, code) {
                        return 1;
                    }
                    has_elem = true;
                }
            }
            if !has_elem && eof {
                return 1;
            }
            return 0;
        }
        DetectUintIndex::NumberMatches(du32) => {
            if !eof {
                match du32.mode {
                    DetectUintMode::DetectUintModeGt | DetectUintMode::DetectUintModeGte => {}
                    _ => {
                        return 0;
                    }
                }
            }
            let mut nb = 0u32;
            for response in subslice {
                if let Some(code) = get_value(response) {
                    if detect_match_uint::<U>(&ctx.du, code) {
                        nb += 1;
                    }
                }
            }
            if detect_match_uint(du32, nb) {
                return 1;
            }
            return 0;
        }
        DetectUintIndex::Count(du32) => {
            if !eof {
                match du32.mode {
                    DetectUintMode::DetectUintModeGt | DetectUintMode::DetectUintModeGte => {}
                    _ => {
                        return 0;
                    }
                }
            }
            let mut nb = 0u32;
            for response in subslice {
                if get_value(response).is_some() {
                    nb += 1;
                }
            }
            if detect_match_uint(du32, nb) {
                return 1;
            }
            return 0;
        }
        DetectUintIndex::AllOrAbsent => {
            if !eof {
                return 0;
            }
            for response in subslice {
                if let Some(code) = get_value(response) {
                    if !detect_match_uint::<U>(&ctx.du, code) {
                        return 0;
                    }
                }
            }
            return 1;
        }
        DetectUintIndex::All => {
            if !eof {
                return 0;
            }
            let mut has_elem = false;
            for response in subslice {
                if let Some(code) = get_value(response) {
                    if !detect_match_uint::<U>(&ctx.du, code) {
                        return 0;
                    }
                    has_elem = true;
                }
            }
            if has_elem {
                return 1;
            }
            return 0;
        }
        DetectUintIndex::Index((oob, idx)) => {
            let index = if *idx < 0 {
                // negative values for backward indexing.
                ((subslice.len() as i32) + idx) as usize
            } else {
                *idx as usize
            };
            if subslice.len() <= index {
                if *oob && eof {
                    return 1;
                }
                return 0;
            }
            if let Some(code) = get_value(&subslice[index]) {
                return detect_match_uint::<U>(&ctx.du, code) as c_int;
            }
            return 0;
        }
    }
}

#[derive(Debug, PartialEq)]
struct FlagItem<T> {
    value: T,
    neg: bool,
}

fn parse_flag_list<T1: DetectIntType, T2: EnumString<T1>>(
    s: &str, singlechar: bool,
) -> IResult<&str, Vec<FlagItem<T1>>> {
    let mut r = Vec::new();
    let mut s2 = s;
    while !s2.is_empty() {
        let (s, _) = opt(is_a(" "))(s2)?;
        let (s, neg) = opt(tag("!"))(s)?;
        let neg = neg.is_some();
        let (s, vals) = if singlechar {
            take(1usize)(s)
        } else {
            take_while(|c| c != ' ' && c != ',')(s)
        }?;
        let value = T2::from_str(vals);
        if value.is_none() {
            SCLogError!("Bitflag unexpected value {}", vals);
            return Err(Err::Error(make_error(s, ErrorKind::Switch)));
        }
        let value = value.unwrap().into_u();
        let (s, _) = if singlechar {
            Ok((s, None))
        } else {
            opt(is_a(" ,"))(s)
        }?;
        r.push(FlagItem { neg, value });
        s2 = s;
    }
    return Ok((s2, r));
}

pub fn detect_parse_uint_bitflags<T1: DetectIntType, T2: EnumString<T1>>(
    s: &str, defmod: DetectBitflagModifier, singlechar: bool,
) -> Option<DetectUintData<T1>> {
    if let Ok((_, ctx)) = detect_parse_uint::<T1>(s) {
        return Some(ctx);
    }
    // otherwise, try strings for bitmask
    let (s, modifier) = parse_bitchars_modifier(s, defmod).ok()?;
    let (s, _) = take_while::<_, &str, Error<_>>(|c| c == ' ' || c == '\t')(s).ok()?;
    if let Ok((rem, l)) = parse_flag_list::<T1, T2>(s, singlechar) {
        if !rem.is_empty() {
            SCLogError!("junk at the end of bitflags");
            return None;
        }
        let mut arg1 = T1::min_value();
        let mut arg2 = T1::min_value();
        for elem in l.iter() {
            if elem.value & arg1 != T1::min_value() {
                SCLogError!(
                    "Repeated bitflag for {}",
                    T2::from_u(elem.value).unwrap().to_str()
                );
                return None;
            }
            arg1 |= elem.value;
            if !elem.neg {
                arg2 |= elem.value;
            }
        }
        let ctx = match modifier {
            DetectBitflagModifier::Equal => DetectUintData::<T1> {
                arg1,
                arg2: T1::min_value(),
                mode: DetectUintMode::DetectUintModeEqual,
            },
            DetectBitflagModifier::Plus => DetectUintData::<T1> {
                arg1,
                arg2,
                mode: DetectUintMode::DetectUintModeBitmask,
            },
            DetectBitflagModifier::Any => DetectUintData::<T1> {
                arg1,
                arg2: T1::min_value(),
                mode: DetectUintMode::DetectUintModeNegBitmask,
            },
            DetectBitflagModifier::Not => DetectUintData::<T1> {
                arg1,
                arg2,
                mode: DetectUintMode::DetectUintModeNegBitmask,
            },
        };
        return Some(ctx);
    }
    return None;
}

#[derive(Clone, Debug, PartialEq)]
pub enum DetectBitflagModifier {
    Equal,
    Plus,
    Any,
    Not,
}

pub(crate) fn parse_bitchars_modifier(
    s: &str, default: DetectBitflagModifier,
) -> IResult<&str, DetectBitflagModifier> {
    let (s1, m) = anychar(s)?;
    match m {
        '!' => {
            // exclamation mark is only accepted for legacy keywords
            // excluded for newer to avoid ambiguity with negating single flag
            if default == DetectBitflagModifier::Equal {
                Ok((s1, DetectBitflagModifier::Not))
            } else {
                Ok((s, default))
            }
        }
        '-' => Ok((s1, DetectBitflagModifier::Not)),
        '+' => Ok((s1, DetectBitflagModifier::Plus)),
        '*' => Ok((s1, DetectBitflagModifier::Any)),
        '=' => Ok((s1, DetectBitflagModifier::Equal)),
        // do not consume if not a known modifier: use default equal
        _ => Ok((s, default)),
    }
}

/// Parses a string for detection with integers, using enumeration strings
///
/// Needs to specify T1 the integer type (like u8)
/// And the Enumeration for the stringer.
/// Will try to parse numerical value first, as any integer detection keyword
/// And if this fails, will resort to using the enumeration strings.
///
/// Returns Some DetectUintData on success, None on failure
pub fn detect_parse_uint_enum<T1: DetectIntType, T2: EnumString<T1>>(
    s: &str,
) -> Option<DetectUintData<T1>> {
    if let Ok((_, ctx)) = detect_parse_uint::<T1>(s) {
        return Some(ctx);
    }

    // we need to precise the Error type, we get error[E0283]: type annotations needed
    let (s, neg) = opt(char::<_, Error<_>>('!'))(s).ok()?;
    let mode = if neg.is_some() {
        DetectUintMode::DetectUintModeNe
    } else {
        DetectUintMode::DetectUintModeEqual
    };
    if let Some(enum_val) = T2::from_str(s) {
        let ctx = DetectUintData::<T1> {
            arg1: enum_val.into_u(),
            arg2: T1::min_value(),
            mode,
        };
        return Some(ctx);
    }
    SCLogError!("Unexpected value for enumeration integer: {}", s);
    return None;
}

pub trait DetectIntType:
    std::str::FromStr
    + std::cmp::PartialOrd
    + std::ops::BitOrAssign
    + num::PrimInt
    + num::Bounded
    + num::ToPrimitive
    + num::FromPrimitive
{
}
impl<T> DetectIntType for T where
    T: std::str::FromStr
        + std::cmp::PartialOrd
        + std::ops::BitOrAssign
        + num::PrimInt
        + num::Bounded
        + num::ToPrimitive
        + num::FromPrimitive
{
}

pub fn detect_parse_uint_unit(i: &str) -> IResult<&str, u64> {
    let (i, unit) = alt((
        value(1024, tag_no_case("kib")),
        value(1024, tag_no_case("kb")),
        value(1024 * 1024, tag_no_case("mib")),
        value(1024 * 1024, tag_no_case("mb")),
        value(1024 * 1024 * 1024, tag_no_case("gib")),
        value(1024 * 1024 * 1024, tag_no_case("gb")),
    ))(i)?;
    return Ok((i, unit));
}

pub fn detect_parse_uint_value_hex<T: DetectIntType>(i: &str) -> IResult<&str, T> {
    let (i, _) = tag("0x")(i)?;
    let (i, arg1s) = hex_digit1(i)?;
    match T::from_str_radix(arg1s, 16) {
        Ok(arg1) => Ok((i, arg1)),
        _ => Err(Err::Error(make_error(i, ErrorKind::Verify))),
    }
}

pub fn detect_parse_uint_value<T: DetectIntType>(i: &str) -> IResult<&str, T> {
    let (i, arg1) = alt((detect_parse_uint_value_hex, detect_parse_uint_with_unit))(i)?;
    Ok((i, arg1))
}

pub fn detect_parse_uint_with_unit<T: DetectIntType>(i: &str) -> IResult<&str, T> {
    let (i, arg1) = map_opt(digit1, |s: &str| s.parse::<T>().ok())(i)?;
    let (i, unit) = opt(detect_parse_uint_unit)(i)?;
    if arg1 >= T::one() {
        if let Some(u) = unit {
            if T::max_value().to_u64().unwrap() / u < arg1.to_u64().unwrap() {
                return Err(Err::Error(make_error(i, ErrorKind::Verify)));
            }
            let ru64 = arg1 * T::from_u64(u).unwrap();
            return Ok((i, ru64));
        }
    }
    Ok((i, arg1))
}

pub fn detect_parse_uint_start_equal<T: DetectIntType>(
    i: &str,
) -> IResult<&str, DetectUintData<T>> {
    let (i, _) = opt(tag("="))(i)?;
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, arg1) = detect_parse_uint_value(i)?;
    Ok((
        i,
        DetectUintData {
            arg1,
            arg2: T::min_value(),
            mode: DetectUintMode::DetectUintModeEqual,
        },
    ))
}

pub fn detect_parse_uint_start_interval<T: DetectIntType>(
    i: &str,
) -> IResult<&str, DetectUintData<T>> {
    let (i, neg) = opt(char('!'))(i)?;
    let (i, arg1) = detect_parse_uint_value(i)?;
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, _) = alt((tag("-"), tag("<>")))(i)?;
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, arg2) = verify(detect_parse_uint_value, |x| {
        x > &arg1 && *x - arg1 > T::one()
    })(i)?;
    let mode = if neg.is_some() {
        DetectUintMode::DetectUintModeNegRg
    } else {
        DetectUintMode::DetectUintModeRange
    };
    Ok((i, DetectUintData { arg1, arg2, mode }))
}

pub fn detect_parse_uint_bitmask<T: DetectIntType>(i: &str) -> IResult<&str, DetectUintData<T>> {
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, _) = tag("&")(i)?;
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, arg1) = detect_parse_uint_value(i)?;
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, neg) = opt(tag("!"))(i)?;
    let (i, _) = tag("=")(i)?;
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, arg2) = detect_parse_uint_value(i)?;
    if arg2 & arg1 != arg2 {
        // could never match
        return Err(Err::Error(make_error(i, ErrorKind::Verify)));
    }
    let mode = if neg.is_none() {
        DetectUintMode::DetectUintModeBitmask
    } else {
        DetectUintMode::DetectUintModeNegBitmask
    };
    Ok((i, DetectUintData { arg1, arg2, mode }))
}

fn detect_parse_uint_start_interval_inclusive<T: DetectIntType>(
    i: &str,
) -> IResult<&str, DetectUintData<T>> {
    let (i, neg) = opt(char('!'))(i)?;
    let (i, arg1) = verify(detect_parse_uint_value::<T>, |x| *x > T::min_value())(i)?;
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, _) = alt((tag("-"), tag("<>")))(i)?;
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, arg2) = verify(detect_parse_uint_value::<T>, |x| {
        *x > arg1 && *x < T::max_value()
    })(i)?;
    let mode = if neg.is_some() {
        DetectUintMode::DetectUintModeNegRg
    } else {
        DetectUintMode::DetectUintModeRange
    };
    Ok((
        i,
        DetectUintData {
            arg1: arg1 - T::one(),
            arg2: arg2 + T::one(),
            mode,
        },
    ))
}

pub fn detect_parse_uint_mode(i: &str) -> IResult<&str, DetectUintMode> {
    let (i, mode) = alt((
        value(DetectUintMode::DetectUintModeGte, tag(">=")),
        value(DetectUintMode::DetectUintModeLte, tag("<=")),
        value(DetectUintMode::DetectUintModeGt, tag(">")),
        value(DetectUintMode::DetectUintModeLt, tag("<")),
        value(DetectUintMode::DetectUintModeNe, tag("!=")),
        value(DetectUintMode::DetectUintModeNe, tag("!")),
        value(DetectUintMode::DetectUintModeEqual, tag("=")),
    ))(i)?;
    return Ok((i, mode));
}

fn detect_parse_uint_start_symbol<T: DetectIntType>(i: &str) -> IResult<&str, DetectUintData<T>> {
    let (i, mode) = detect_parse_uint_mode(i)?;
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, arg1) = detect_parse_uint_value(i)?;

    match mode {
        DetectUintMode::DetectUintModeNe => {}
        DetectUintMode::DetectUintModeLt => {
            if arg1 == T::min_value() {
                return Err(Err::Error(make_error(i, ErrorKind::Verify)));
            }
        }
        DetectUintMode::DetectUintModeLte => {
            if arg1 == T::max_value() {
                return Err(Err::Error(make_error(i, ErrorKind::Verify)));
            }
        }
        DetectUintMode::DetectUintModeGt => {
            if arg1 == T::max_value() {
                return Err(Err::Error(make_error(i, ErrorKind::Verify)));
            }
        }
        DetectUintMode::DetectUintModeGte => {
            if arg1 == T::min_value() {
                return Err(Err::Error(make_error(i, ErrorKind::Verify)));
            }
        }
        _ => {
            return Err(Err::Error(make_error(i, ErrorKind::MapOpt)));
        }
    }

    Ok((
        i,
        DetectUintData {
            arg1,
            arg2: T::min_value(),
            mode,
        },
    ))
}

pub fn detect_match_uint<T: DetectIntType>(x: &DetectUintData<T>, val: T) -> bool {
    match x.mode {
        DetectUintMode::DetectUintModeEqual => {
            if val == x.arg1 {
                return true;
            }
        }
        DetectUintMode::DetectUintModeNe => {
            if val != x.arg1 {
                return true;
            }
        }
        DetectUintMode::DetectUintModeLt => {
            if val < x.arg1 {
                return true;
            }
        }
        DetectUintMode::DetectUintModeLte => {
            if val <= x.arg1 {
                return true;
            }
        }
        DetectUintMode::DetectUintModeGt => {
            if val > x.arg1 {
                return true;
            }
        }
        DetectUintMode::DetectUintModeGte => {
            if val >= x.arg1 {
                return true;
            }
        }
        DetectUintMode::DetectUintModeRange => {
            if val > x.arg1 && val < x.arg2 {
                return true;
            }
        }
        DetectUintMode::DetectUintModeNegRg => {
            if val <= x.arg1 || val >= x.arg2 {
                return true;
            }
        }
        DetectUintMode::DetectUintModeBitmask => {
            if val & x.arg1 == x.arg2 {
                return true;
            }
        }
        DetectUintMode::DetectUintModeNegBitmask => {
            if val & x.arg1 != x.arg2 {
                return true;
            }
        }
    }
    return false;
}

/// This helper function takes a string and returns a DetectUintData<T>
/// But it does not check if there are more characters to consume.
/// As such, it may be used by keywords that want a DetectUintData<T>
/// and other parameters to parse after.
/// Callers should ensure to use all_consuming on the remainder
/// Otherwise, invalid ranges such as 1-foo will be parsed as =1
pub(crate) fn detect_parse_uint_notending<T: DetectIntType>(
    i: &str,
) -> IResult<&str, DetectUintData<T>> {
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, uint) = alt((
        detect_parse_uint_bitmask,
        detect_parse_uint_start_interval,
        detect_parse_uint_start_equal,
        detect_parse_uint_start_symbol,
    ))(i)?;
    Ok((i, uint))
}

pub fn detect_parse_uint<T: DetectIntType>(i: &str) -> IResult<&str, DetectUintData<T>> {
    let (i, uint) = detect_parse_uint_notending(i)?;
    let (i, _) = all_consuming(take_while(|c| c == ' '))(i)?;
    Ok((i, uint))
}

pub fn detect_parse_uint_inclusive<T: DetectIntType>(i: &str) -> IResult<&str, DetectUintData<T>> {
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, uint) = alt((
        detect_parse_uint_start_interval_inclusive,
        detect_parse_uint_start_equal,
        detect_parse_uint_start_symbol,
    ))(i)?;
    let (i, _) = all_consuming(take_while(|c| c == ' '))(i)?;
    Ok((i, uint))
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectU64Parse(
    ustr: *const std::os::raw::c_char,
) -> *mut DetectUintData<u64> {
    let ft_name: &CStr = CStr::from_ptr(ustr); //unsafe
    if let Ok(s) = ft_name.to_str() {
        if let Ok((_, ctx)) = detect_parse_uint::<u64>(s) {
            let boxed = Box::new(ctx);
            return Box::into_raw(boxed) as *mut _;
        }
    }
    return std::ptr::null_mut();
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectU64Match(
    arg: u64, ctx: &DetectUintData<u64>,
) -> std::os::raw::c_int {
    if detect_match_uint(ctx, arg) {
        return 1;
    }
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectU64Free(ctx: &mut DetectUintData<u64>) {
    // Just unbox...
    std::mem::drop(Box::from_raw(ctx));
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectU32Parse(
    ustr: *const std::os::raw::c_char,
) -> *mut DetectUintData<u32> {
    let ft_name: &CStr = CStr::from_ptr(ustr); //unsafe
    if let Ok(s) = ft_name.to_str() {
        if let Ok((_, ctx)) = detect_parse_uint::<u32>(s) {
            let boxed = Box::new(ctx);
            return Box::into_raw(boxed) as *mut _;
        }
    }
    return std::ptr::null_mut();
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectU32ParseInclusive(
    ustr: *const std::os::raw::c_char,
) -> *mut DetectUintData<u32> {
    let ft_name: &CStr = CStr::from_ptr(ustr); //unsafe
    if let Ok(s) = ft_name.to_str() {
        if let Ok((_, ctx)) = detect_parse_uint_inclusive::<u32>(s) {
            let boxed = Box::new(ctx);
            return Box::into_raw(boxed) as *mut _;
        }
    }
    return std::ptr::null_mut();
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectU32Match(
    arg: u32, ctx: &DetectUintData<u32>,
) -> std::os::raw::c_int {
    if detect_match_uint(ctx, arg) {
        return 1;
    }
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectU32Free(ctx: &mut DetectUintData<u32>) {
    // Just unbox...
    std::mem::drop(Box::from_raw(ctx));
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectU8Parse(
    ustr: *const std::os::raw::c_char,
) -> *mut DetectUintData<u8> {
    let ft_name: &CStr = CStr::from_ptr(ustr); //unsafe
    if let Ok(s) = ft_name.to_str() {
        if let Ok((_, ctx)) = detect_parse_uint::<u8>(s) {
            let boxed = Box::new(ctx);
            return Box::into_raw(boxed) as *mut _;
        }
    }
    return std::ptr::null_mut();
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectU8Match(arg: u8, ctx: &DetectUintData<u8>) -> std::os::raw::c_int {
    if detect_match_uint(ctx, arg) {
        return 1;
    }
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectU8Free(ctx: &mut DetectUintData<u8>) {
    // Just unbox...
    std::mem::drop(Box::from_raw(ctx));
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectU8ArrayParse(ustr: *const std::os::raw::c_char) -> *mut c_void {
    let ft_name: &CStr = CStr::from_ptr(ustr); //unsafe
    if let Ok(s) = ft_name.to_str() {
        if let Some(ctx) = detect_parse_array_uint::<u8>(s) {
            let boxed = Box::new(ctx);
            // DetectUintArrayData<u8> cannot be cbindgend
            return Box::into_raw(boxed) as *mut c_void;
        }
    }
    return std::ptr::null_mut();
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectU8ArrayFree(ctx: &mut DetectUintArrayData<u8>) {
    std::mem::drop(Box::from_raw(ctx));
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectU32ArrayParse(ustr: *const std::os::raw::c_char) -> *mut c_void {
    let ft_name: &CStr = CStr::from_ptr(ustr); //unsafe
    if let Ok(s) = ft_name.to_str() {
        if let Some(ctx) = detect_parse_array_uint::<u32>(s) {
            let boxed = Box::new(ctx);
            return Box::into_raw(boxed) as *mut c_void;
        }
    }
    return std::ptr::null_mut();
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectU32ArrayFree(ctx: &mut DetectUintArrayData<u32>) {
    // Just unbox...
    std::mem::drop(Box::from_raw(ctx));
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectU16Parse(
    ustr: *const std::os::raw::c_char,
) -> *mut DetectUintData<u16> {
    let ft_name: &CStr = CStr::from_ptr(ustr); //unsafe
    if let Ok(s) = ft_name.to_str() {
        if let Ok((_, ctx)) = detect_parse_uint::<u16>(s) {
            let boxed = Box::new(ctx);
            return Box::into_raw(boxed) as *mut _;
        }
    }
    return std::ptr::null_mut();
}

pub fn detect_parse_unquote_uint<T: DetectIntType>(i: &str) -> IResult<&str, DetectUintData<T>> {
    let (i, _) = take_while(|c| c == ' ')(i)?;
    let (i, quote) = opt(tag("\""))(i)?;
    if quote.is_some() {
        let (i, unquote) = take_till(|c| c == '"')(i)?;
        if i.is_empty() {
            return Err(Err::Error(make_error(i, ErrorKind::Tag)));
        }
        let (_i, uint) = detect_parse_uint(unquote)?;
        return Ok((i, uint));
    }
    let (i, uint) = detect_parse_uint(i)?;
    Ok((i, uint))
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectU16UnquoteParse(
    ustr: *const std::os::raw::c_char,
) -> *mut DetectUintData<u16> {
    let ft_name: &CStr = CStr::from_ptr(ustr); //unsafe
    if let Ok(s) = ft_name.to_str() {
        if let Ok((_, ctx)) = detect_parse_unquote_uint::<u16>(s) {
            let boxed = Box::new(ctx);
            return Box::into_raw(boxed) as *mut _;
        }
    }
    return std::ptr::null_mut();
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectU16Match(
    arg: u16, ctx: &DetectUintData<u16>,
) -> std::os::raw::c_int {
    if detect_match_uint(ctx, arg) {
        return 1;
    }
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectU16Free(ctx: &mut DetectUintData<u16>) {
    // Just unbox...
    std::mem::drop(Box::from_raw(ctx));
}

#[cfg(test)]
mod tests {
    use super::*;

    use suricata_derive::EnumStringU8;

    #[derive(Clone, Debug, PartialEq, EnumStringU8)]
    #[repr(u8)]
    pub enum TestEnum {
        Zero = 0,
        BestValueEver = 42,
    }

    #[test]
    fn test_detect_parse_uint_enum() {
        let ctx = detect_parse_uint_enum::<u8, TestEnum>("best_value_ever").unwrap();
        assert_eq!(ctx.arg1, 42);
        assert_eq!(ctx.mode, DetectUintMode::DetectUintModeEqual);

        let ctx = detect_parse_uint_enum::<u8, TestEnum>(">1").unwrap();
        assert_eq!(ctx.arg1, 1);
        assert_eq!(ctx.mode, DetectUintMode::DetectUintModeGt);
    }

    #[test]
    fn test_parse_uint_bitmask() {
        let (_, val) = detect_parse_uint::<u64>("&0x40!=0").unwrap();
        assert_eq!(val.arg1, 0x40);
        assert_eq!(val.arg2, 0);
        assert_eq!(val.mode, DetectUintMode::DetectUintModeNegBitmask);
        assert!(!detect_match_uint(&val, 0xBF));
        assert!(detect_match_uint(&val, 0x40));
        let (_, val) = detect_parse_uint::<u64>("&0xc0=0x80").unwrap();
        assert_eq!(val.arg1, 0xc0);
        assert_eq!(val.arg2, 0x80);
        assert_eq!(val.mode, DetectUintMode::DetectUintModeBitmask);
        assert!(detect_match_uint(&val, 0x80));
        assert!(!detect_match_uint(&val, 0x40));
        assert!(!detect_match_uint(&val, 0xc0));
        // could never match
        assert!(detect_parse_uint::<u64>("&0xc0=12").is_err());
    }
    #[test]
    fn test_parse_uint_hex() {
        let (_, val) = detect_parse_uint::<u64>("0x100").unwrap();
        assert_eq!(val.arg1, 0x100);
        let (_, val) = detect_parse_uint::<u8>("0xFF").unwrap();
        assert_eq!(val.arg1, 255);
        let (_, val) = detect_parse_uint::<u8>("0xff").unwrap();
        assert_eq!(val.arg1, 255);
    }

    #[test]
    fn test_parse_uint_negated_range() {
        let (_, val) = detect_parse_uint::<u8>("!1-6").unwrap();
        assert_eq!(val.arg1, 1);
        assert_eq!(val.arg2, 6);
        assert_eq!(val.mode, DetectUintMode::DetectUintModeNegRg);
        assert!(detect_match_uint(&val, 1));
        assert!(!detect_match_uint(&val, 2));
        assert!(!detect_match_uint(&val, 5));
        assert!(detect_match_uint(&val, 6));
    }

    #[test]
    fn test_parse_uint_unit() {
        let (_, val) = detect_parse_uint::<u64>(" 2kb").unwrap();
        assert_eq!(val.arg1, 2048);

        assert!(detect_parse_uint::<u8>("2kb").is_err());

        let (_, val) = detect_parse_uint::<u32>("> 3MB").unwrap();
        assert_eq!(val.arg1, 3 * 1024 * 1024);
    }

    #[test]
    fn test_parse_uint_like_mqtt_protocol_version() {
        let (_, val) = detect_parse_uint::<u8>("3").unwrap();
        assert_eq!(val.mode, DetectUintMode::DetectUintModeEqual);
        assert_eq!(val.arg1, 3);
        let (_, val) = detect_parse_uint::<u8>("5").unwrap();
        assert_eq!(val.mode, DetectUintMode::DetectUintModeEqual);
        assert_eq!(val.arg1, 5);
        let (_, val) = detect_parse_uint::<u8>(">3").unwrap();
        assert_eq!(val.mode, DetectUintMode::DetectUintModeGt);
        assert_eq!(val.arg1, 3);
        let (_, val) = detect_parse_uint::<u8>("<44").unwrap();
        assert_eq!(val.mode, DetectUintMode::DetectUintModeLt);
        assert_eq!(val.arg1, 44);
        assert!(detect_parse_uint::<u8>("").is_err());
        assert!(detect_parse_uint::<u8>("<444").is_err());
    }
}
