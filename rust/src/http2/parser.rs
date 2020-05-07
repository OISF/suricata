/* Copyright (C) 2020 Open Information Security Foundation
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

use nom::character::complete::digit1;
use nom::combinator::rest;
use nom::number::streaming::{be_u16, be_u32, be_u8};
use nom::IResult;
use nom::error::ErrorKind;
use nom::Err;
use std::fmt;
use std::str::FromStr;

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, FromPrimitive, Debug)]
pub enum HTTP2FrameType {
    DATA = 0,
    HEADERS = 1,
    PRIORITY = 2,
    RSTSTREAM = 3,
    SETTINGS = 4,
    PUSHPROMISE = 5,
    PING = 6,
    GOAWAY = 7,
    WINDOWUPDATE = 8,
    CONTINUATION = 9,
}

impl fmt::Display for HTTP2FrameType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::str::FromStr for HTTP2FrameType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let su = s.to_uppercase();
        let su_slice: &str = &*su;
        match su_slice {
            "DATA" => Ok(HTTP2FrameType::DATA),
            "HEADERS" => Ok(HTTP2FrameType::HEADERS),
            "PRIORITY" => Ok(HTTP2FrameType::PRIORITY),
            "RSTSTREAM" => Ok(HTTP2FrameType::RSTSTREAM),
            "SETTINGS" => Ok(HTTP2FrameType::SETTINGS),
            "PUSHPROMISE" => Ok(HTTP2FrameType::PUSHPROMISE),
            "PING" => Ok(HTTP2FrameType::PING),
            "GOAWAY" => Ok(HTTP2FrameType::GOAWAY),
            "WINDOWUPDATE" => Ok(HTTP2FrameType::WINDOWUPDATE),
            "CONTINUATION" => Ok(HTTP2FrameType::CONTINUATION),
            _ => Err(format!("'{}' is not a valid value for HTTP2FrameType", s)),
        }
    }
}

#[derive(PartialEq)]
pub struct HTTP2FrameHeader {
    //TODO detection on GOAWAY additional data = length
    pub length: u32,
    pub ftype: HTTP2FrameType,
    pub flags: u8,
    pub reserved: u8,
    stream_id: u32,
}

named!(pub http2_parse_frame_header<HTTP2FrameHeader>,
    do_parse!(
        length: bits!( take_bits!(24u32) ) >>
        ftype: map_opt!( be_u8,
                         num::FromPrimitive::from_u8 ) >>
        flags: be_u8 >>
        stream_id: bits!( tuple!( take_bits!(1u8),
                                  take_bits!(31u32) ) ) >>
        (HTTP2FrameHeader{length, ftype, flags,
                          reserved:stream_id.0,
                          stream_id:stream_id.1})
    )
);

#[repr(u32)]
#[derive(Clone, Copy, PartialEq, FromPrimitive, Debug)]
pub enum HTTP2ErrorCode {
    NOERROR = 0,
    PROTOCOLERROR = 1,
    INTERNALERROR = 2,
    FLOWCONTROLERROR = 3,
    SETTINGSTIMEOUT = 4,
    STREAMCLOSED = 5,
    FRAMESIZEERROR = 6,
    REFUSEDSTREAM = 7,
    CANCEL = 8,
    COMPRESSIONERROR = 9,
    CONNECTERROR = 10,
    ENHANCEYOURCALM = 11,
    INADEQUATESECURITY = 12,
    HTTP11REQUIRED = 13,
}

impl fmt::Display for HTTP2ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::str::FromStr for HTTP2ErrorCode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let su = s.to_uppercase();
        let su_slice: &str = &*su;
        match su_slice {
            "NO_ERROR" => Ok(HTTP2ErrorCode::NOERROR),
            "PROTOCOL_ERROR" => Ok(HTTP2ErrorCode::PROTOCOLERROR),
            "FLOW_CONTROL_ERROR" => Ok(HTTP2ErrorCode::FLOWCONTROLERROR),
            "SETTINGS_TIMEOUT" => Ok(HTTP2ErrorCode::SETTINGSTIMEOUT),
            "STREAM_CLOSED" => Ok(HTTP2ErrorCode::STREAMCLOSED),
            "FRAME_SIZE_ERROR" => Ok(HTTP2ErrorCode::FRAMESIZEERROR),
            "REFUSED_STREAM" => Ok(HTTP2ErrorCode::REFUSEDSTREAM),
            "CANCEL" => Ok(HTTP2ErrorCode::CANCEL),
            "COMPRESSION_ERROR" => Ok(HTTP2ErrorCode::COMPRESSIONERROR),
            "CONNECT_ERROR" => Ok(HTTP2ErrorCode::CONNECTERROR),
            "ENHANCE_YOUR_CALM" => Ok(HTTP2ErrorCode::ENHANCEYOURCALM),
            "INADEQUATE_SECURITY" => Ok(HTTP2ErrorCode::INADEQUATESECURITY),
            "HTTP_1_1_REQUIRED" => Ok(HTTP2ErrorCode::HTTP11REQUIRED),
            _ => Err(format!("'{}' is not a valid value for HTTP2ErrorCode", s)),
        }
    }
}

#[derive(Clone, Copy)]
pub struct HTTP2FrameGoAway {
    pub errorcode: HTTP2ErrorCode,
}

named!(pub http2_parse_frame_goaway<HTTP2FrameGoAway>,
    do_parse!(
        errorcode: map_opt!( be_u32,
            num::FromPrimitive::from_u32 ) >>
        (HTTP2FrameGoAway{errorcode})
    )
);

#[derive(Clone, Copy)]
pub struct HTTP2FrameRstStream {
    pub errorcode: HTTP2ErrorCode,
}

named!(pub http2_parse_frame_rststream<HTTP2FrameRstStream>,
    do_parse!(
        errorcode: map_opt!( be_u32,
            num::FromPrimitive::from_u32 ) >>
        (HTTP2FrameRstStream{errorcode})
    )
);

#[derive(Clone, Copy)]
pub struct HTTP2FramePriority {
    pub weight: u8,
}

named!(pub http2_parse_frame_priority<HTTP2FramePriority>,
    do_parse!(
        weight: be_u8 >>
        (HTTP2FramePriority{weight})
    )
);

#[derive(Clone, Copy)]
pub struct HTTP2FrameWindowUpdate {
    pub reserved: u8,
    pub sizeinc: u32,
}

named!(pub http2_parse_frame_windowupdate<HTTP2FrameWindowUpdate>,
    do_parse!(
        sizeinc: bits!( tuple!( take_bits!(1u8),
                                take_bits!(31u32) ) ) >>
        (HTTP2FrameWindowUpdate{reserved:sizeinc.0, sizeinc:sizeinc.1})
    )
);

#[derive(Clone, Copy)]
pub struct HTTP2FrameHeadersPriority {
    pub exclusive: u8,
    pub dependency: u32,
    pub weight: u8,
}

named!(pub http2_parse_headers_priority<HTTP2FrameHeadersPriority>,
    do_parse!(
        sid: bits!( tuple!( take_bits!(1u8),
                                take_bits!(31u32) ) ) >>
        weight: be_u8 >>
        (HTTP2FrameHeadersPriority{exclusive:sid.0, dependency:sid.1, weight})
    )
);

fn http2_frame_header_static(n: u8) -> Option<HTTP2FrameHeaderBlock> {
    match n {
1 => Some(HTTP2FrameHeaderBlock {name:":authority".to_string(), value: "".to_string(),}),
2 => Some(HTTP2FrameHeaderBlock {name:":method".to_string(), value: "GET".to_string(),}),
3 => Some(HTTP2FrameHeaderBlock {name:":method".to_string(), value: "POST".to_string(),}),
4 => Some(HTTP2FrameHeaderBlock {name:":path".to_string(), value: "/".to_string(),}),
5 => Some(HTTP2FrameHeaderBlock {name:":path".to_string(), value: "/index.html".to_string(),}),
6 => Some(HTTP2FrameHeaderBlock {name:":scheme".to_string(), value: "http".to_string(),}),
7 => Some(HTTP2FrameHeaderBlock {name:":scheme".to_string(), value: "https".to_string(),}),
8 => Some(HTTP2FrameHeaderBlock {name:":status".to_string(), value: "200".to_string(),}),
9 => Some(HTTP2FrameHeaderBlock {name:":status".to_string(), value: "204".to_string(),}),
10 => Some(HTTP2FrameHeaderBlock {name:":status".to_string(), value: "206".to_string(),}),
11 => Some(HTTP2FrameHeaderBlock {name:":status".to_string(), value: "304".to_string(),}),
12 => Some(HTTP2FrameHeaderBlock {name:":status".to_string(), value: "400".to_string(),}),
13 => Some(HTTP2FrameHeaderBlock {name:":status".to_string(), value: "404".to_string(),}),
14 => Some(HTTP2FrameHeaderBlock {name:":status".to_string(), value: "500".to_string(),}),
15 => Some(HTTP2FrameHeaderBlock {name:"accept-charset".to_string(), value: "".to_string(),}),
16 => Some(HTTP2FrameHeaderBlock {name:"accept-encoding".to_string(), value: "gzip, deflate".to_string(),}),
17 => Some(HTTP2FrameHeaderBlock {name:"accept-language".to_string(), value: "".to_string(),}),
18 => Some(HTTP2FrameHeaderBlock {name:"accept-ranges".to_string(), value: "".to_string(),}),
19 => Some(HTTP2FrameHeaderBlock {name:"accept".to_string(), value: "".to_string(),}),
20 => Some(HTTP2FrameHeaderBlock {name:"access-control-allow-origin".to_string(), value: "".to_string(),}),
21 => Some(HTTP2FrameHeaderBlock {name:"age".to_string(), value: "".to_string(),}),
22 => Some(HTTP2FrameHeaderBlock {name:"allow".to_string(), value: "".to_string(),}),
23 => Some(HTTP2FrameHeaderBlock {name:"authorization".to_string(), value: "".to_string(),}),
24 => Some(HTTP2FrameHeaderBlock {name:"cache-control".to_string(), value: "".to_string(),}),
25 => Some(HTTP2FrameHeaderBlock {name:"content-disposition".to_string(), value: "".to_string(),}),
26 => Some(HTTP2FrameHeaderBlock {name:"content-encoding".to_string(), value: "".to_string(),}),
27 => Some(HTTP2FrameHeaderBlock {name:"content-language".to_string(), value: "".to_string(),}),
28 => Some(HTTP2FrameHeaderBlock {name:"content-length".to_string(), value: "".to_string(),}),
29 => Some(HTTP2FrameHeaderBlock {name:"content-location".to_string(), value: "".to_string(),}),
30 => Some(HTTP2FrameHeaderBlock {name:"content-range".to_string(), value: "".to_string(),}),
31 => Some(HTTP2FrameHeaderBlock {name:"content-type".to_string(), value: "".to_string(),}),
32 => Some(HTTP2FrameHeaderBlock {name:"cookie".to_string(), value: "".to_string(),}),
33 => Some(HTTP2FrameHeaderBlock {name:"date".to_string(), value: "".to_string(),}),
34 => Some(HTTP2FrameHeaderBlock {name:"etag".to_string(), value: "".to_string(),}),
35 => Some(HTTP2FrameHeaderBlock {name:"expect".to_string(), value: "".to_string(),}),
36 => Some(HTTP2FrameHeaderBlock {name:"expires".to_string(), value: "".to_string(),}),
37 => Some(HTTP2FrameHeaderBlock {name:"from".to_string(), value: "".to_string(),}),
38 => Some(HTTP2FrameHeaderBlock {name:"host".to_string(), value: "".to_string(),}),
39 => Some(HTTP2FrameHeaderBlock {name:"if-match".to_string(), value: "".to_string(),}),
40 => Some(HTTP2FrameHeaderBlock {name:"if-modified-since".to_string(), value: "".to_string(),}),
41 => Some(HTTP2FrameHeaderBlock {name:"if-none-match".to_string(), value: "".to_string(),}),
42 => Some(HTTP2FrameHeaderBlock {name:"if-range".to_string(), value: "".to_string(),}),
43 => Some(HTTP2FrameHeaderBlock {name:"if-unmodified-since".to_string(), value: "".to_string(),}),
44 => Some(HTTP2FrameHeaderBlock {name:"last-modified".to_string(), value: "".to_string(),}),
45 => Some(HTTP2FrameHeaderBlock {name:"link".to_string(), value: "".to_string(),}),
46 => Some(HTTP2FrameHeaderBlock {name:"location".to_string(), value: "".to_string(),}),
47 => Some(HTTP2FrameHeaderBlock {name:"max-forwards".to_string(), value: "".to_string(),}),
48 => Some(HTTP2FrameHeaderBlock {name:"proxy-authenticate".to_string(), value: "".to_string(),}),
49 => Some(HTTP2FrameHeaderBlock {name:"proxy-authorization".to_string(), value: "".to_string(),}),
50 => Some(HTTP2FrameHeaderBlock {name:"range".to_string(), value: "".to_string(),}),
51 => Some(HTTP2FrameHeaderBlock {name:"referer".to_string(), value: "".to_string(),}),
52 => Some(HTTP2FrameHeaderBlock {name:"refresh".to_string(), value: "".to_string(),}),
53 => Some(HTTP2FrameHeaderBlock {name:"retry-after".to_string(), value: "".to_string(),}),
54 => Some(HTTP2FrameHeaderBlock {name:"server".to_string(), value: "".to_string(),}),
55 => Some(HTTP2FrameHeaderBlock {name:"set-cookie".to_string(), value: "".to_string(),}),
56 => Some(HTTP2FrameHeaderBlock {name:"strict-transport-security".to_string(), value: "".to_string(),}),
57 => Some(HTTP2FrameHeaderBlock {name:"transfer-encoding".to_string(), value: "".to_string(),}),
58 => Some(HTTP2FrameHeaderBlock {name:"user-agent".to_string(), value: "".to_string(),}),
59 => Some(HTTP2FrameHeaderBlock {name:"vary".to_string(), value: "".to_string(),}),
60 => Some(HTTP2FrameHeaderBlock {name:"via".to_string(), value: "".to_string(),}),
61 => Some(HTTP2FrameHeaderBlock {name:"www-authenticate".to_string(), value: "".to_string(),}),
        _ => None,
    }
}

#[derive(Clone)]
pub struct HTTP2FrameHeaderBlock {
    pub name: String,
    pub value: String,
}

fn http2_parse_headers_block_indexed(input: &[u8]) -> IResult<&[u8], HTTP2FrameHeaderBlock> {
    //TODO ask why we need this over error[E0282]: type annotations needed for `((&[u8], usize), O1)`
    fn parser(input: &[u8]) -> IResult<&[u8], (u8, HTTP2FrameHeaderBlock)> {
        bits!(
            input,
            tuple!(
                verify!(take_bits!(1u8), |&x| x == 1),
                map_opt!(take_bits!(7u8), http2_frame_header_static)
            )
        )
    }
    //TODO0.9 map with dynamic list
    let (i2, indexed) = parser(input)?;
    return Ok((i2, indexed.1));
}

#[derive(Clone, Copy)]
pub struct HTTP2HeaderString<'a> {
    pub huff: u8,
    //TODO remove this dummy parameter
    pub dummy: u8,
    pub data: &'a [u8],
}

named!(pub http2_parse_headers_block_string<HTTP2HeaderString>,
    do_parse!(
        huffslen: bits!( tuple!( take_bits!(1u8),
                    take_bits!(7u8) ) ) >>
//TODO decompress if huffslen.0 is set
        data: take!(huffslen.1 as usize) >>
        (HTTP2HeaderString{huff:huffslen.0, dummy:huffslen.1, data:data})
    )
);

fn http2_parse_headers_block_literal(input: &[u8]) -> IResult<&[u8], HTTP2FrameHeaderBlock> {
    fn parser(input: &[u8]) -> IResult<&[u8], (u8, u8)> {
        bits!(
            input,
            tuple!(verify!(take_bits!(2u8), |&x| x == 1), take_bits!(6u8))
        )
    }
    let (i2, indexed) = parser(input)?;
    if indexed.1 == 0 {
        //TODO0.2 name http2_parse_headers_block_string
    } else {
        //TODO0.4 name from indexed.1
    }
    //TODO0.3 value call!(http2_parse_headers_block_string)
    let idx = http2_frame_header_static(indexed.1);
    match idx {
        Some(ok) => {
            return Ok((i2, ok));
        }
        None => {
            return Err(Err::Error((i2, ErrorKind::MapOpt)));
        }
    }
}

named!(
    http2_parse_headers_block<HTTP2FrameHeaderBlock>,
    alt!(
        http2_parse_headers_block_indexed | http2_parse_headers_block_literal //TODO0.7 http2_parse_headers_block more possibilities
    )
);

#[derive(Clone)]
pub struct HTTP2FrameHeaders {
    pub padlength: Option<u8>,
    pub priority: Option<HTTP2FrameHeadersPriority>,
    pub blocks: Vec<HTTP2FrameHeaderBlock>,
}

const HTTP2_FLAG_HEADER_PADDED: u8 = 0x8;
const HTTP2_FLAG_HEADER_PRIORITY: u8 = 0x20;

pub fn http2_parse_frame_headers(input: &[u8], flags: u8) -> IResult<&[u8], HTTP2FrameHeaders> {
    do_parse!(
        input,
        padlength: cond!(flags & HTTP2_FLAG_HEADER_PADDED != 0, be_u8)
            >> priority:
                cond!(
                    flags & HTTP2_FLAG_HEADER_PRIORITY != 0,
                    http2_parse_headers_priority
                )
            >> blocks: many0!(http2_parse_headers_block)
            >> (HTTP2FrameHeaders {
                padlength,
                priority: priority,
                blocks: Vec::new()
            })
    )
}

#[repr(u16)]
#[derive(Clone, Copy, PartialEq, FromPrimitive, Debug)]
pub enum HTTP2SettingsId {
    SETTINGSHEADERTABLESIZE = 1,
    SETTINGSENABLEPUSH = 2,
    SETTINGSMAXCONCURRENTSTREAMS = 3,
    SETTINGSINITIALWINDOWSIZE = 4,
    SETTINGSMAXFRAMESIZE = 5,
    SETTINGSMAXHEADERLISTSIZE = 6,
}

impl fmt::Display for HTTP2SettingsId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::str::FromStr for HTTP2SettingsId {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let su = s.to_uppercase();
        let su_slice: &str = &*su;
        match su_slice {
            "SETTINGS_HEADER_TABLE_SIZE" => Ok(HTTP2SettingsId::SETTINGSHEADERTABLESIZE),
            "SETTINGS_ENABLE_PUSH" => Ok(HTTP2SettingsId::SETTINGSENABLEPUSH),
            "SETTINGS_MAX_CONCURRENT_STREAMS" => Ok(HTTP2SettingsId::SETTINGSMAXCONCURRENTSTREAMS),
            "SETTINGS_INITIAL_WINDOW_SIZE" => Ok(HTTP2SettingsId::SETTINGSINITIALWINDOWSIZE),
            "SETTINGS_MAX_FRAME_SIZE" => Ok(HTTP2SettingsId::SETTINGSMAXFRAMESIZE),
            "SETTINGS_MAX_HEADER_LIST_SIZE" => Ok(HTTP2SettingsId::SETTINGSMAXHEADERLISTSIZE),
            _ => Err(format!("'{}' is not a valid value for HTTP2SettingsId", s)),
        }
    }
}

//TODO move elsewhere generic
#[derive(PartialEq, Debug)]
pub enum DetectUintMode {
    DetectUintModeEqual,
    DetectUintModeLt,
    DetectUintModeGt,
    DetectUintModeRange,
}

pub struct DetectU32Data {
    pub value: u32,
    pub valrange: u32,
    pub mode: DetectUintMode,
}

pub struct DetectHTTP2settingsSigCtx {
    pub id: HTTP2SettingsId,          //identifier
    pub value: Option<DetectU32Data>, //optional value
}

named!(detect_parse_u32_start_equal<&str,DetectU32Data>,
    do_parse!(
        opt!( is_a!( " " ) ) >>
        opt! (tag!("=") ) >>
        opt!( is_a!( " " ) ) >>
        value : map_opt!(digit1, |s: &str| s.parse::<u32>().ok()) >>
        (DetectU32Data{value, valrange:0, mode:DetectUintMode::DetectUintModeEqual})
    )
);

named!(detect_parse_u32_start_interval<&str,DetectU32Data>,
    do_parse!(
        opt!( is_a!( " " ) ) >>
        value : map_opt!(digit1, |s: &str| s.parse::<u32>().ok()) >>
        opt!( is_a!( " " ) ) >>
        tag!("-") >>
        opt!( is_a!( " " ) ) >>
        valrange : map_opt!(digit1, |s: &str| s.parse::<u32>().ok()) >>
        (DetectU32Data{value, valrange, mode:DetectUintMode::DetectUintModeRange})
    )
);

named!(detect_parse_u32_start_lesser<&str,DetectU32Data>,
    do_parse!(
        opt!( is_a!( " " ) ) >>
        tag!("<") >>
        opt!( is_a!( " " ) ) >>
        value : map_opt!(digit1, |s: &str| s.parse::<u32>().ok()) >>
        (DetectU32Data{value, valrange:0, mode:DetectUintMode::DetectUintModeLt})
    )
);

named!(detect_parse_u32_start_greater<&str,DetectU32Data>,
    do_parse!(
        opt!( is_a!( " " ) ) >>
        tag!(">") >>
        opt!( is_a!( " " ) ) >>
        value : map_opt!(digit1, |s: &str| s.parse::<u32>().ok()) >>
        (DetectU32Data{value, valrange:0, mode:DetectUintMode::DetectUintModeGt})
    )
);

named!(detect_parse_u32<&str,DetectU32Data>,
    do_parse!(
        u32 : alt! (
            detect_parse_u32_start_lesser |
            detect_parse_u32_start_greater |
            complete!( detect_parse_u32_start_interval ) |
            detect_parse_u32_start_equal
        ) >>
        (u32)
    )
);

named!(pub http2_parse_settingsctx<&str,DetectHTTP2settingsSigCtx>,
    do_parse!(
        opt!( is_a!( " " ) ) >>
        id: map_opt!( alt! ( complete!( is_not!( " <>=" ) ) | rest ),
            |s: &str| HTTP2SettingsId::from_str(s).ok() ) >>
        value: opt!( complete!( detect_parse_u32 ) ) >>
        (DetectHTTP2settingsSigCtx{id, value})
    )
);

#[derive(Clone, Copy)]
pub struct HTTP2FrameSettings {
    pub id: HTTP2SettingsId,
    pub value: u32,
}

named!(
    http2_parse_frame_setting<HTTP2FrameSettings>,
    do_parse!(
        id: map_opt!(be_u16, num::FromPrimitive::from_u16)
            >> value: be_u32
            >> (HTTP2FrameSettings { id, value })
    )
);

named!(pub http2_parse_frame_settings<Vec<HTTP2FrameSettings>>,
    many0!(http2_parse_frame_setting)
);

#[cfg(test)]
mod tests {

    use super::*;
    use nom::*;

    /// Simple test of some valid data.
    #[test]
    fn test_http2_parse_settingsctx() {
        let s = "SETTINGS_ENABLE_PUSH";
        let r = http2_parse_settingsctx(s);
        match r {
            Ok((rem, ctx)) => {
                assert_eq!(ctx.id, HTTP2SettingsId::SETTINGSENABLEPUSH);
                match ctx.value {
                    Some(_) => {
                        panic!("Unexpected value");
                    }
                    None => {}
                }
                assert_eq!(rem.len(), 0);
            }
            Err(e) => {
                panic!("Result should not be an error {:?}.", e);
            }
        }

        //spaces in the end
        let s1 = "SETTINGS_ENABLE_PUSH ";
        let r1 = http2_parse_settingsctx(s1);
        match r1 {
            Ok((rem, ctx)) => {
                assert_eq!(ctx.id, HTTP2SettingsId::SETTINGSENABLEPUSH);
                match ctx.value {
                    Some(_) => {
                        panic!("Unexpected value");
                    }
                    None => {}
                }
                assert_eq!(rem.len(), 1);
            }
            Err(e) => {
                panic!("Result should not be an error {:?}.", e);
            }
        }

        let s2 = "SETTINGS_MAX_CONCURRENT_STREAMS  42";
        let r2 = http2_parse_settingsctx(s2);
        match r2 {
            Ok((rem, ctx)) => {
                assert_eq!(ctx.id, HTTP2SettingsId::SETTINGSMAXCONCURRENTSTREAMS);
                match ctx.value {
                    Some(ctxval) => {
                        assert_eq!(ctxval.value, 42);
                    }
                    None => {
                        panic!("No value");
                    }
                }
                assert_eq!(rem.len(), 0);
            }
            Err(e) => {
                panic!("Result should not be an error {:?}.", e);
            }
        }

        let s3 = "SETTINGS_MAX_CONCURRENT_STREAMS 42-68";
        let r3 = http2_parse_settingsctx(s3);
        match r3 {
            Ok((rem, ctx)) => {
                assert_eq!(ctx.id, HTTP2SettingsId::SETTINGSMAXCONCURRENTSTREAMS);
                match ctx.value {
                    Some(ctxval) => {
                        assert_eq!(ctxval.value, 42);
                        assert_eq!(ctxval.mode, DetectUintMode::DetectUintModeRange);
                        assert_eq!(ctxval.valrange, 68);
                    }
                    None => {
                        panic!("No value");
                    }
                }
                assert_eq!(rem.len(), 0);
            }
            Err(e) => {
                panic!("Result should not be an error {:?}.", e);
            }
        }

        let s4 = "SETTINGS_MAX_CONCURRENT_STREAMS<54";
        let r4 = http2_parse_settingsctx(s4);
        match r4 {
            Ok((rem, ctx)) => {
                assert_eq!(ctx.id, HTTP2SettingsId::SETTINGSMAXCONCURRENTSTREAMS);
                match ctx.value {
                    Some(ctxval) => {
                        assert_eq!(ctxval.value, 54);
                        assert_eq!(ctxval.mode, DetectUintMode::DetectUintModeLt);
                    }
                    None => {
                        panic!("No value");
                    }
                }
                assert_eq!(rem.len(), 0);
            }
            Err(e) => {
                panic!("Result should not be an error {:?}.", e);
            }
        }

        let s5 = "SETTINGS_MAX_CONCURRENT_STREAMS > 76";
        let r5 = http2_parse_settingsctx(s5);
        match r5 {
            Ok((rem, ctx)) => {
                assert_eq!(ctx.id, HTTP2SettingsId::SETTINGSMAXCONCURRENTSTREAMS);
                match ctx.value {
                    Some(ctxval) => {
                        assert_eq!(ctxval.value, 76);
                        assert_eq!(ctxval.mode, DetectUintMode::DetectUintModeGt);
                    }
                    None => {
                        panic!("No value");
                    }
                }
                assert_eq!(rem.len(), 0);
            }
            Err(e) => {
                panic!("Result should not be an error {:?}.", e);
            }
        }
    }

    #[test]
    fn test_http2_parse_frame_header() {
        let buf: &[u8] = &[
            0x00, 0x00, 0x06, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
            0x64,
        ];
        let result = http2_parse_frame_header(buf);
        match result {
            Ok((remainder, frame)) => {
                // Check the first message.
                assert_eq!(frame.length, 6);
                assert_eq!(frame.ftype, HTTP2FrameType::SETTINGS);
                assert_eq!(frame.flags, 0);
                assert_eq!(frame.reserved, 0);
                assert_eq!(frame.stream_id, 0);

                // And we should have 6 bytes left.
                assert_eq!(remainder.len(), 6);
            }
            Err(Err::Incomplete(_)) => {
                panic!("Result should not have been incomplete.");
            }
            Err(Err::Error(err)) | Err(Err::Failure(err)) => {
                panic!("Result should not be an error: {:?}.", err);
            }
        }
        let buf2: &[u8] = &[
            0x00, 0x00, 0x06, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
            0x64,
        ];
        let result2 = http2_parse_frame_header(buf2);
        match result2 {
            Ok((_, _)) => {
                panic!("Result should not have been Ok.");
            }
            Err(Err::Error((_, kind))) => {
                assert_eq!(kind, error::ErrorKind::MapOpt);
            }
            Err(err) => {
                panic!("Result should not have been an unknown error: {:?}.", err);
            }
        }
    }

}
