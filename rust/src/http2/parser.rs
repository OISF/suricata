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
use nom::error::ErrorKind;
use nom::number::streaming::{be_u16, be_u32, be_u8};
use nom::Err;
use nom::IResult;
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
    //TODO5 detection on (GOAWAY) additional data = length
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

pub const HTTP2_STATIC_HEADERS_NUMBER: usize = 61;

fn http2_frame_header_static(
    n: u8,
    dyn_headers: &Vec<HTTP2FrameHeaderBlock>,
) -> Option<HTTP2FrameHeaderBlock> {
    match n {
        1 => Some(HTTP2FrameHeaderBlock {
            name: ":authority".as_bytes().to_vec(),
            value: Vec::new(),
            error: HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
        }),
        2 => Some(HTTP2FrameHeaderBlock {
            name: ":method".as_bytes().to_vec(),
            value: "GET".as_bytes().to_vec(),
            error: HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
        }),
        3 => Some(HTTP2FrameHeaderBlock {
            name: ":method".as_bytes().to_vec(),
            value: "POST".as_bytes().to_vec(),
            error: HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
        }),
        4 => Some(HTTP2FrameHeaderBlock {
            name: ":path".as_bytes().to_vec(),
            value: "/".as_bytes().to_vec(),
            error: HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
        }),
        5 => Some(HTTP2FrameHeaderBlock {
            name: ":path".as_bytes().to_vec(),
            value: "/index.html".as_bytes().to_vec(),
            error: HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
        }),
        6 => Some(HTTP2FrameHeaderBlock {
            name: ":scheme".as_bytes().to_vec(),
            value: "http".as_bytes().to_vec(),
            error: HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
        }),
        7 => Some(HTTP2FrameHeaderBlock {
            name: ":scheme".as_bytes().to_vec(),
            value: "https".as_bytes().to_vec(),
            error: HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
        }),
        8 => Some(HTTP2FrameHeaderBlock {
            name: ":status".as_bytes().to_vec(),
            value: "200".as_bytes().to_vec(),
            error: HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
        }),
        9 => Some(HTTP2FrameHeaderBlock {
            name: ":status".as_bytes().to_vec(),
            value: "204".as_bytes().to_vec(),
            error: HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
        }),
        10 => Some(HTTP2FrameHeaderBlock {
            name: ":status".as_bytes().to_vec(),
            value: "206".as_bytes().to_vec(),
            error: HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
        }),
        11 => Some(HTTP2FrameHeaderBlock {
            name: ":status".as_bytes().to_vec(),
            value: "304".as_bytes().to_vec(),
            error: HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
        }),
        12 => Some(HTTP2FrameHeaderBlock {
            name: ":status".as_bytes().to_vec(),
            value: "400".as_bytes().to_vec(),
            error: HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
        }),
        13 => Some(HTTP2FrameHeaderBlock {
            name: ":status".as_bytes().to_vec(),
            value: "404".as_bytes().to_vec(),
            error: HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
        }),
        14 => Some(HTTP2FrameHeaderBlock {
            name: ":status".as_bytes().to_vec(),
            value: "500".as_bytes().to_vec(),
            error: HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
        }),
        15 => Some(HTTP2FrameHeaderBlock {
            name: "accept-charset".as_bytes().to_vec(),
            value: Vec::new(),
            error: HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
        }),
        16 => Some(HTTP2FrameHeaderBlock {
            name: "accept-encoding".as_bytes().to_vec(),
            value: "gzip, deflate".as_bytes().to_vec(),
            error: HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
        }),
        17 => Some(HTTP2FrameHeaderBlock {
            name: "accept-language".as_bytes().to_vec(),
            value: Vec::new(),
            error: HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
        }),
        18 => Some(HTTP2FrameHeaderBlock {
            name: "accept-ranges".as_bytes().to_vec(),
            value: Vec::new(),
            error: HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
        }),
        19 => Some(HTTP2FrameHeaderBlock {
            name: "accept".as_bytes().to_vec(),
            value: Vec::new(),
            error: HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
        }),
        20 => Some(HTTP2FrameHeaderBlock {
            name: "access-control-allow-origin".as_bytes().to_vec(),
            value: Vec::new(),
            error: HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
        }),
        21 => Some(HTTP2FrameHeaderBlock {
            name: "age".as_bytes().to_vec(),
            value: Vec::new(),
            error: HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
        }),
        22 => Some(HTTP2FrameHeaderBlock {
            name: "allow".as_bytes().to_vec(),
            value: Vec::new(),
            error: HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
        }),
        23 => Some(HTTP2FrameHeaderBlock {
            name: "authorization".as_bytes().to_vec(),
            value: Vec::new(),
            error: HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
        }),
        24 => Some(HTTP2FrameHeaderBlock {
            name: "cache-control".as_bytes().to_vec(),
            value: Vec::new(),
            error: HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
        }),
        25 => Some(HTTP2FrameHeaderBlock {
            name: "content-disposition".as_bytes().to_vec(),
            value: Vec::new(),
            error: HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
        }),
        26 => Some(HTTP2FrameHeaderBlock {
            name: "content-encoding".as_bytes().to_vec(),
            value: Vec::new(),
            error: HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
        }),
        27 => Some(HTTP2FrameHeaderBlock {
            name: "content-language".as_bytes().to_vec(),
            value: Vec::new(),
            error: HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
        }),
        28 => Some(HTTP2FrameHeaderBlock {
            name: "content-length".as_bytes().to_vec(),
            value: Vec::new(),
            error: HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
        }),
        29 => Some(HTTP2FrameHeaderBlock {
            name: "content-location".as_bytes().to_vec(),
            value: Vec::new(),
            error: HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
        }),
        30 => Some(HTTP2FrameHeaderBlock {
            name: "content-range".as_bytes().to_vec(),
            value: Vec::new(),
            error: HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
        }),
        31 => Some(HTTP2FrameHeaderBlock {
            name: "content-type".as_bytes().to_vec(),
            value: Vec::new(),
            error: HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
        }),
        32 => Some(HTTP2FrameHeaderBlock {
            name: "cookie".as_bytes().to_vec(),
            value: Vec::new(),
            error: HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
        }),
        33 => Some(HTTP2FrameHeaderBlock {
            name: "date".as_bytes().to_vec(),
            value: Vec::new(),
            error: HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
        }),
        34 => Some(HTTP2FrameHeaderBlock {
            name: "etag".as_bytes().to_vec(),
            value: Vec::new(),
            error: HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
        }),
        35 => Some(HTTP2FrameHeaderBlock {
            name: "expect".as_bytes().to_vec(),
            value: Vec::new(),
            error: HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
        }),
        36 => Some(HTTP2FrameHeaderBlock {
            name: "expires".as_bytes().to_vec(),
            value: Vec::new(),
            error: HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
        }),
        37 => Some(HTTP2FrameHeaderBlock {
            name: "from".as_bytes().to_vec(),
            value: Vec::new(),
            error: HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
        }),
        38 => Some(HTTP2FrameHeaderBlock {
            name: "host".as_bytes().to_vec(),
            value: Vec::new(),
            error: HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
        }),
        39 => Some(HTTP2FrameHeaderBlock {
            name: "if-match".as_bytes().to_vec(),
            value: Vec::new(),
            error: HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
        }),
        40 => Some(HTTP2FrameHeaderBlock {
            name: "if-modified-since".as_bytes().to_vec(),
            value: Vec::new(),
            error: HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
        }),
        41 => Some(HTTP2FrameHeaderBlock {
            name: "if-none-match".as_bytes().to_vec(),
            value: Vec::new(),
            error: HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
        }),
        42 => Some(HTTP2FrameHeaderBlock {
            name: "if-range".as_bytes().to_vec(),
            value: Vec::new(),
            error: HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
        }),
        43 => Some(HTTP2FrameHeaderBlock {
            name: "if-unmodified-since".as_bytes().to_vec(),
            value: Vec::new(),
            error: HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
        }),
        44 => Some(HTTP2FrameHeaderBlock {
            name: "last-modified".as_bytes().to_vec(),
            value: Vec::new(),
            error: HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
        }),
        45 => Some(HTTP2FrameHeaderBlock {
            name: "link".as_bytes().to_vec(),
            value: Vec::new(),
            error: HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
        }),
        46 => Some(HTTP2FrameHeaderBlock {
            name: "location".as_bytes().to_vec(),
            value: Vec::new(),
            error: HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
        }),
        47 => Some(HTTP2FrameHeaderBlock {
            name: "max-forwards".as_bytes().to_vec(),
            value: Vec::new(),
            error: HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
        }),
        48 => Some(HTTP2FrameHeaderBlock {
            name: "proxy-authenticate".as_bytes().to_vec(),
            value: Vec::new(),
            error: HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
        }),
        49 => Some(HTTP2FrameHeaderBlock {
            name: "proxy-authorization".as_bytes().to_vec(),
            value: Vec::new(),
            error: HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
        }),
        50 => Some(HTTP2FrameHeaderBlock {
            name: "range".as_bytes().to_vec(),
            value: Vec::new(),
            error: HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
        }),
        51 => Some(HTTP2FrameHeaderBlock {
            name: "referer".as_bytes().to_vec(),
            value: Vec::new(),
            error: HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
        }),
        52 => Some(HTTP2FrameHeaderBlock {
            name: "refresh".as_bytes().to_vec(),
            value: Vec::new(),
            error: HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
        }),
        53 => Some(HTTP2FrameHeaderBlock {
            name: "retry-after".as_bytes().to_vec(),
            value: Vec::new(),
            error: HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
        }),
        54 => Some(HTTP2FrameHeaderBlock {
            name: "server".as_bytes().to_vec(),
            value: Vec::new(),
            error: HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
        }),
        55 => Some(HTTP2FrameHeaderBlock {
            name: "set-cookie".as_bytes().to_vec(),
            value: Vec::new(),
            error: HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
        }),
        56 => Some(HTTP2FrameHeaderBlock {
            name: "strict-transport-security".as_bytes().to_vec(),
            value: Vec::new(),
            error: HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
        }),
        57 => Some(HTTP2FrameHeaderBlock {
            name: "transfer-encoding".as_bytes().to_vec(),
            value: Vec::new(),
            error: HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
        }),
        58 => Some(HTTP2FrameHeaderBlock {
            name: "user-agent".as_bytes().to_vec(),
            value: Vec::new(),
            error: HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
        }),
        59 => Some(HTTP2FrameHeaderBlock {
            name: "vary".as_bytes().to_vec(),
            value: Vec::new(),
            error: HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
        }),
        60 => Some(HTTP2FrameHeaderBlock {
            name: "via".as_bytes().to_vec(),
            value: Vec::new(),
            error: HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
        }),
        61 => Some(HTTP2FrameHeaderBlock {
            name: "www-authenticate".as_bytes().to_vec(),
            value: Vec::new(),
            error: HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
        }),
        _ => {
            //use dynamic table
            if dyn_headers.len() + HTTP2_STATIC_HEADERS_NUMBER < n as usize {
                Some(HTTP2FrameHeaderBlock {
                    name: Vec::new(),
                    value: Vec::new(),
                    error: HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeNotIndexed,
                })
            } else {
                let indyn = dyn_headers.len() - (n as usize - HTTP2_STATIC_HEADERS_NUMBER);
                let headcopy = HTTP2FrameHeaderBlock {
                    name: dyn_headers[indyn].name.to_vec(),
                    value: dyn_headers[indyn].value.to_vec(),
                    error: HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
                };
                Some(headcopy)
            }
        }
    }
}

#[repr(u8)]
#[derive(Copy, Clone, PartialOrd, PartialEq)]
pub enum HTTP2HeaderDecodeStatus {
    HTTP2HeaderDecodeSuccess = 0,
    HTTP2HeaderDecodeSizeUpdate = 1,
    HTTP2HeaderDecodeError = 0x80,
    HTTP2HeaderDecodeNotIndexed = 0x81,
}

#[derive(Clone)]
pub struct HTTP2FrameHeaderBlock {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
    pub error: HTTP2HeaderDecodeStatus,
}

fn http2_parse_headers_block_indexed<'a>(
    input: &'a [u8],
    dyn_headers: &Vec<HTTP2FrameHeaderBlock>,
) -> IResult<&'a [u8], HTTP2FrameHeaderBlock> {
    fn parser(input: &[u8]) -> IResult<&[u8], (u8, u8)> {
        bits!(
            input,
            complete!(tuple!(
                verify!(take_bits!(1u8), |&x| x == 1),
                take_bits!(7u8)
            ))
        )
    }
    let (i2, indexed) = parser(input)?;
    match http2_frame_header_static(indexed.1, dyn_headers) {
        Some(h) => Ok((i2, h)),
        _ => Err(Err::Error((i2, ErrorKind::MapOpt))),
    }
}

fn http2_huffman_table_len5(n: u32) -> Option<u8> {
    match n {
        0 => Some(48),
        1 => Some(49),
        2 => Some(50),
        3 => Some(97),
        4 => Some(99),
        5 => Some(101),
        6 => Some(105),
        7 => Some(111),
        8 => Some(115),
        9 => Some(116),
        _ => None,
    }
}

named!(http2_decode_huffman_len5<(&[u8], usize), u8>,
    complete!( map_opt!(take_bits!(5u32), http2_huffman_table_len5) )
);

fn http2_huffman_table_len6(n: u32) -> Option<u8> {
    match n {
        0x14 => Some(32),
        0x15 => Some(37),
        0x16 => Some(45),
        0x17 => Some(46),
        0x18 => Some(47),
        0x19 => Some(51),
        0x1a => Some(52),
        0x1b => Some(53),
        0x1c => Some(54),
        0x1d => Some(55),
        0x1e => Some(56),
        0x1f => Some(57),
        0x20 => Some(61),
        0x21 => Some(65),
        0x22 => Some(95),
        0x23 => Some(98),
        0x24 => Some(100),
        0x25 => Some(102),
        0x26 => Some(103),
        0x27 => Some(104),
        0x28 => Some(108),
        0x29 => Some(109),
        0x2a => Some(110),
        0x2b => Some(112),
        0x2c => Some(114),
        0x2d => Some(117),
        _ => None,
    }
}

named!(http2_decode_huffman_len6<(&[u8], usize), u8>,
    complete!( map_opt!(take_bits!(6u32), http2_huffman_table_len6))
);

fn http2_huffman_table_len7(n: u32) -> Option<u8> {
    match n {
        0x5c => Some(58),
        0x5d => Some(66),
        0x5e => Some(67),
        0x5f => Some(68),
        0x60 => Some(69),
        0x61 => Some(70),
        0x62 => Some(71),
        0x63 => Some(72),
        0x64 => Some(73),
        0x65 => Some(74),
        0x66 => Some(75),
        0x67 => Some(76),
        0x68 => Some(77),
        0x69 => Some(78),
        0x6a => Some(79),
        0x6b => Some(80),
        0x6c => Some(81),
        0x6d => Some(82),
        0x6e => Some(83),
        0x6f => Some(84),
        0x70 => Some(85),
        0x71 => Some(86),
        0x72 => Some(87),
        0x73 => Some(89),
        0x74 => Some(106),
        0x75 => Some(107),
        0x76 => Some(113),
        0x77 => Some(118),
        0x78 => Some(119),
        0x79 => Some(120),
        0x7a => Some(121),
        0x7b => Some(122),
        _ => None,
    }
}

named!(http2_decode_huffman_len7<(&[u8], usize), u8>,
complete!( map_opt!(take_bits!(7u32), http2_huffman_table_len7))
);

fn http2_huffman_table_len8(n: u32) -> Option<u8> {
    match n {
        0xf8 => Some(38),
        0xf9 => Some(42),
        0xfa => Some(44),
        0xfb => Some(59),
        0xfc => Some(88),
        0xfd => Some(90),
        _ => None,
    }
}

named!(http2_decode_huffman_len8<(&[u8], usize), u8>,
complete!( map_opt!(take_bits!(8u32), http2_huffman_table_len8))
);

fn http2_huffman_table_len10(n: u32) -> Option<u8> {
    match n {
        0x3f8 => Some(33),
        0x3f9 => Some(34),
        0x3fa => Some(40),
        0x3fb => Some(41),
        0x3fc => Some(63),
        _ => None,
    }
}

named!(http2_decode_huffman_len10<(&[u8], usize), u8>,
complete!( map_opt!(take_bits!(10u32), http2_huffman_table_len10))
);

fn http2_huffman_table_len11(n: u32) -> Option<u8> {
    match n {
        0x7fa => Some(39),
        0x7fb => Some(43),
        0x7fc => Some(124),
        _ => None,
    }
}

named!(http2_decode_huffman_len11<(&[u8], usize), u8>,
complete!( map_opt!(take_bits!(11u32), http2_huffman_table_len11))
);

fn http2_huffman_table_len12(n: u32) -> Option<u8> {
    match n {
        0xffa => Some(35),
        0xffb => Some(62),
        _ => None,
    }
}

named!(http2_decode_huffman_len12<(&[u8], usize), u8>,
complete!( map_opt!(take_bits!(12u32), http2_huffman_table_len12))
);

fn http2_huffman_table_len13(n: u32) -> Option<u8> {
    match n {
        0x1ff8 => Some(0),
        0x1ff9 => Some(36),
        0x1ffa => Some(64),
        0x1ffb => Some(91),
        0x1ffc => Some(93),
        0x1ffd => Some(126),
        _ => None,
    }
}

named!(http2_decode_huffman_len13<(&[u8], usize), u8>,
complete!( map_opt!(take_bits!(13u32), http2_huffman_table_len13))
);

fn http2_huffman_table_len14(n: u32) -> Option<u8> {
    match n {
        0x3ffc => Some(94),
        0x3ffd => Some(125),
        _ => None,
    }
}

named!(http2_decode_huffman_len14<(&[u8], usize), u8>,
complete!( map_opt!(take_bits!(14u32), http2_huffman_table_len14))
);

fn http2_huffman_table_len15(n: u32) -> Option<u8> {
    match n {
        0x7ffc => Some(60),
        0x7ffd => Some(96),
        0x7ffe => Some(123),
        _ => None,
    }
}

named!(http2_decode_huffman_len15<(&[u8], usize), u8>,
complete!( map_opt!(take_bits!(15u32), http2_huffman_table_len15))
);

fn http2_huffman_table_len19(n: u32) -> Option<u8> {
    match n {
        0x7fff0 => Some(92),
        0x7fff1 => Some(195),
        0x7fff2 => Some(208),
        _ => None,
    }
}

named!(http2_decode_huffman_len19<(&[u8], usize), u8>,
complete!( map_opt!(take_bits!(19u32), http2_huffman_table_len19))
);

fn http2_huffman_table_len20(n: u32) -> Option<u8> {
    match n {
        0xfffe6 => Some(128),
        0xfffe7 => Some(130),
        0xfffe8 => Some(131),
        0xfffe9 => Some(162),
        0xfffea => Some(184),
        0xfffeb => Some(194),
        0xfffec => Some(224),
        0xfffed => Some(226),
        _ => None,
    }
}

named!(http2_decode_huffman_len20<(&[u8], usize), u8>,
complete!( map_opt!(take_bits!(20u32), http2_huffman_table_len20))
);

fn http2_huffman_table_len21(n: u32) -> Option<u8> {
    match n {
        0x1fffdc => Some(153),
        0x1fffdd => Some(161),
        0x1fffde => Some(167),
        0x1fffdf => Some(172),
        0x1fffe0 => Some(176),
        0x1fffe1 => Some(177),
        0x1fffe2 => Some(179),
        0x1fffe3 => Some(209),
        0x1fffe4 => Some(216),
        0x1fffe5 => Some(217),
        0x1fffe6 => Some(227),
        0x1fffe7 => Some(229),
        0x1fffe8 => Some(230),
        _ => None,
    }
}

named!(http2_decode_huffman_len21<(&[u8], usize), u8>,
complete!( map_opt!(take_bits!(21u32), http2_huffman_table_len21))
);

fn http2_huffman_table_len22(n: u32) -> Option<u8> {
    match n {
        0x3fffd2 => Some(129),
        0x3fffd3 => Some(132),
        0x3fffd4 => Some(133),
        0x3fffd5 => Some(134),
        0x3fffd6 => Some(136),
        0x3fffd7 => Some(146),
        0x3fffd8 => Some(154),
        0x3fffd9 => Some(156),
        0x3fffda => Some(160),
        0x3fffdb => Some(163),
        0x3fffdc => Some(164),
        0x3fffdd => Some(169),
        0x3fffde => Some(170),
        0x3fffdf => Some(173),
        0x3fffe0 => Some(178),
        0x3fffe1 => Some(181),
        0x3fffe2 => Some(185),
        0x3fffe3 => Some(186),
        0x3fffe4 => Some(187),
        0x3fffe5 => Some(189),
        0x3fffe6 => Some(190),
        0x3fffe7 => Some(196),
        0x3fffe8 => Some(198),
        0x3fffe9 => Some(228),
        0x3fffea => Some(232),
        0x3fffeb => Some(233),
        _ => None,
    }
}

named!(http2_decode_huffman_len22<(&[u8], usize), u8>,
complete!( map_opt!(take_bits!(22u32), http2_huffman_table_len22))
);

fn http2_huffman_table_len23(n: u32) -> Option<u8> {
    match n {
        0x7fffd8 => Some(1),
        0x7fffd9 => Some(135),
        0x7fffda => Some(137),
        0x7fffdb => Some(138),
        0x7fffdc => Some(139),
        0x7fffdd => Some(140),
        0x7fffde => Some(141),
        0x7fffdf => Some(143),
        0x7fffe0 => Some(147),
        0x7fffe1 => Some(149),
        0x7fffe2 => Some(150),
        0x7fffe3 => Some(151),
        0x7fffe4 => Some(152),
        0x7fffe5 => Some(155),
        0x7fffe6 => Some(157),
        0x7fffe7 => Some(158),
        0x7fffe8 => Some(165),
        0x7fffe9 => Some(166),
        0x7fffea => Some(168),
        0x7fffeb => Some(174),
        0x7fffec => Some(175),
        0x7fffed => Some(180),
        0x7fffee => Some(182),
        0x7fffef => Some(183),
        0x7ffff0 => Some(188),
        0x7ffff1 => Some(191),
        0x7ffff2 => Some(197),
        0x7ffff3 => Some(231),
        0x7ffff4 => Some(239),
        _ => None,
    }
}

named!(http2_decode_huffman_len23<(&[u8], usize), u8>,
    complete!( map_opt!(take_bits!(23u32), http2_huffman_table_len23))
);

fn http2_huffman_table_len24(n: u32) -> Option<u8> {
    match n {
        0xffffea => Some(9),
        0xffffeb => Some(142),
        0xffffec => Some(144),
        0xffffed => Some(145),
        0xffffee => Some(148),
        0xffffef => Some(159),
        0xfffff0 => Some(171),
        0xfffff1 => Some(206),
        0xfffff2 => Some(215),
        0xfffff3 => Some(225),
        0xfffff4 => Some(236),
        0xfffff5 => Some(237),
        _ => None,
    }
}

named!(http2_decode_huffman_len24<(&[u8], usize), u8>,
    complete!( map_opt!(take_bits!(24u32), http2_huffman_table_len24))
);

fn http2_huffman_table_len25(n: u32) -> Option<u8> {
    match n {
        0x1ffffec => Some(199),
        0x1ffffed => Some(207),
        0x1ffffee => Some(234),
        0x1ffffef => Some(235),
        _ => None,
    }
}

named!(http2_decode_huffman_len25<(&[u8], usize), u8>,
    complete!( map_opt!(take_bits!(25u32), http2_huffman_table_len25))
);

fn http2_huffman_table_len26(n: u32) -> Option<u8> {
    match n {
        0x3ffffe0 => Some(192),
        0x3ffffe1 => Some(193),
        0x3ffffe2 => Some(200),
        0x3ffffe3 => Some(201),
        0x3ffffe4 => Some(202),
        0x3ffffe5 => Some(205),
        0x3ffffe6 => Some(210),
        0x3ffffe7 => Some(213),
        0x3ffffe8 => Some(218),
        0x3ffffe9 => Some(219),
        0x3ffffea => Some(238),
        0x3ffffeb => Some(240),
        0x3ffffec => Some(242),
        0x3ffffed => Some(243),
        0x3ffffee => Some(255),
        _ => None,
    }
}

named!(http2_decode_huffman_len26<(&[u8], usize), u8>,
    complete!( map_opt!(take_bits!(26u32), http2_huffman_table_len26))
);

fn http2_huffman_table_len27(n: u32) -> Option<u8> {
    match n {
        0x7ffffde => Some(203),
        0x7ffffdf => Some(204),
        0x7ffffe0 => Some(211),
        0x7ffffe1 => Some(212),
        0x7ffffe2 => Some(214),
        0x7ffffe3 => Some(221),
        0x7ffffe4 => Some(222),
        0x7ffffe5 => Some(223),
        0x7ffffe6 => Some(241),
        0x7ffffe7 => Some(244),
        0x7ffffe8 => Some(245),
        0x7ffffe9 => Some(246),
        0x7ffffea => Some(247),
        0x7ffffeb => Some(248),
        0x7ffffec => Some(250),
        0x7ffffed => Some(251),
        0x7ffffee => Some(252),
        0x7ffffef => Some(253),
        0x7fffff0 => Some(254),
        _ => None,
    }
}

named!(http2_decode_huffman_len27<(&[u8], usize), u8>,
    complete!( map_opt!(take_bits!(27u32), http2_huffman_table_len27))
);

fn http2_huffman_table_len28(n: u32) -> Option<u8> {
    match n {
        0xfffffe2 => Some(2),
        0xfffffe3 => Some(3),
        0xfffffe4 => Some(4),
        0xfffffe5 => Some(5),
        0xfffffe6 => Some(6),
        0xfffffe7 => Some(7),
        0xfffffe8 => Some(8),
        0xfffffe9 => Some(11),
        0xfffffea => Some(12),
        0xfffffeb => Some(14),
        0xfffffec => Some(15),
        0xfffffed => Some(16),
        0xfffffee => Some(17),
        0xfffffef => Some(18),
        0xffffff0 => Some(19),
        0xffffff1 => Some(20),
        0xffffff2 => Some(21),
        0xffffff3 => Some(23),
        0xffffff4 => Some(24),
        0xffffff5 => Some(25),
        0xffffff6 => Some(26),
        0xffffff7 => Some(27),
        0xffffff8 => Some(28),
        0xffffff9 => Some(29),
        0xffffffa => Some(30),
        0xffffffb => Some(31),
        0xffffffc => Some(127),
        0xffffffd => Some(220),
        0xffffffe => Some(249),
        _ => None,
    }
}

named!(http2_decode_huffman_len28<(&[u8], usize), u8>,
    complete!( map_opt!(take_bits!(28u32), http2_huffman_table_len28))
);

fn http2_huffman_table_len30(n: u32) -> Option<u8> {
    match n {
        0x3ffffffc => Some(10),
        0x3ffffffd => Some(13),
        0x3ffffffe => Some(22),
        // 0x3fffffff => Some(256),
        _ => None,
    }
}

named!(http2_decode_huffman_len30<(&[u8], usize), u8>,
    complete!( map_opt!(take_bits!(30u32), http2_huffman_table_len30))
);

//hack to end many0 even if some bits are remaining
fn http2_decode_huffman_end(input: (&[u8], usize)) -> IResult<(&[u8], usize), u8> {
    return Err(Err::Error((input, ErrorKind::Eof)));
}

//TODOend profile and optimize perf
named!(http2_decode_huffman<(&[u8], usize), u8>,
    alt!(http2_decode_huffman_len5 | http2_decode_huffman_len6 | http2_decode_huffman_len7 |
    http2_decode_huffman_len8 | http2_decode_huffman_len10 | http2_decode_huffman_len11 |
    http2_decode_huffman_len12 | http2_decode_huffman_len13 | http2_decode_huffman_len14 |
    http2_decode_huffman_len15 | http2_decode_huffman_len19 | http2_decode_huffman_len20 |
    http2_decode_huffman_len21 | http2_decode_huffman_len22 | http2_decode_huffman_len23 |
    http2_decode_huffman_len24 | http2_decode_huffman_len25 | http2_decode_huffman_len26 |
    http2_decode_huffman_len27 | http2_decode_huffman_len28 | http2_decode_huffman_len30 |
    http2_decode_huffman_end)
);

fn http2_parse_headers_block_string(input: &[u8]) -> IResult<&[u8], Vec<u8>> {
    fn parser(input: &[u8]) -> IResult<&[u8], (u8, u8)> {
        bits!(input, tuple!(take_bits!(1u8), take_bits!(7u8)))
    }
    let (i2, huffslen) = parser(input)?;
    let (i3, data) = take!(i2, huffslen.1 as usize)?;
    if huffslen.0 == 0 {
        return Ok((i3, data.to_vec()));
    } else {
        let (_, val) = bits!(data, many0!(http2_decode_huffman))?;
        return Ok((i3, val));
    }
}

fn http2_parse_headers_block_literal_common<'a>(
    input: &'a [u8],
    index: u8,
    dyn_headers: &Vec<HTTP2FrameHeaderBlock>,
) -> IResult<&'a [u8], HTTP2FrameHeaderBlock> {
    let (i3, name, error) = if index == 0 {
        match http2_parse_headers_block_string(input) {
            Ok((r, n)) => Ok((r, n, HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess)),
            Err(e) => Err(e),
        }
    } else {
        match http2_frame_header_static(index, dyn_headers) {
            Some(x) => Ok((
                input,
                x.name,
                HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess,
            )),
            None => Ok((
                input,
                Vec::new(),
                HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeNotIndexed,
            )),
        }
    }?;
    let (i4, value) = http2_parse_headers_block_string(i3)?;
    return Ok((i4, HTTP2FrameHeaderBlock { name, value, error }));
}

fn http2_parse_headers_block_literal_incindex<'a>(
    input: &'a [u8],
    dyn_headers: &mut Vec<HTTP2FrameHeaderBlock>,
) -> IResult<&'a [u8], HTTP2FrameHeaderBlock> {
    fn parser(input: &[u8]) -> IResult<&[u8], (u8, u8)> {
        bits!(
            input,
            complete!(tuple!(
                verify!(take_bits!(2u8), |&x| x == 1),
                take_bits!(6u8)
            ))
        )
    }
    let (i2, indexed) = parser(input)?;
    let r = http2_parse_headers_block_literal_common(i2, indexed.1, dyn_headers);
    match r {
        Ok((r, head)) => {
            let headcopy = HTTP2FrameHeaderBlock {
                name: head.name.to_vec(),
                value: head.value.to_vec(),
                error: head.error,
            };
            dyn_headers.push(headcopy);
            if dyn_headers.len() > 255 - HTTP2_STATIC_HEADERS_NUMBER {
                dyn_headers.remove(0);
            }
            //TODOnext? handle dynamic table size limit
            return Ok((r, head));
        }
        Err(e) => {
            return Err(e);
        }
    }
}

fn http2_parse_headers_block_literal_noindex<'a>(
    input: &'a [u8],
    dyn_headers: &Vec<HTTP2FrameHeaderBlock>,
) -> IResult<&'a [u8], HTTP2FrameHeaderBlock> {
    fn parser(input: &[u8]) -> IResult<&[u8], (u8, u8)> {
        bits!(
            input,
            complete!(tuple!(
                verify!(take_bits!(4u8), |&x| x == 0),
                take_bits!(4u8)
            ))
        )
    }
    let (i2, indexed) = parser(input)?;
    let r = http2_parse_headers_block_literal_common(i2, indexed.1, dyn_headers);
    return r;
}

fn http2_parse_headers_block_literal_neverindex<'a>(
    input: &'a [u8],
    dyn_headers: &Vec<HTTP2FrameHeaderBlock>,
) -> IResult<&'a [u8], HTTP2FrameHeaderBlock> {
    fn parser(input: &[u8]) -> IResult<&[u8], (u8, u8)> {
        bits!(
            input,
            complete!(tuple!(
                verify!(take_bits!(4u8), |&x| x == 1),
                take_bits!(4u8)
            ))
        )
    }
    let (i2, indexed) = parser(input)?;
    let r = http2_parse_headers_block_literal_common(i2, indexed.1, dyn_headers);
    return r;
}

fn http2_parse_headers_block_dynamic_size(input: &[u8]) -> IResult<&[u8], HTTP2FrameHeaderBlock> {
    fn parser(input: &[u8]) -> IResult<&[u8], (u8, u8)> {
        bits!(
            input,
            complete!(tuple!(
                verify!(take_bits!(3u8), |&x| x == 1),
                take_bits!(5u8)
            ))
        )
    }
    let (i2, maxsize) = parser(input)?;
    if maxsize.1 == 31 {
        let (i3, _maxsize2) = take_while!(i2, |ch| (ch & 0x80) != 0)?;
        let (i4, _maxsize3) = take!(i3, 1)?;
        //TODOnext detect on Dynamic Table Size Update RFC6.3
        return Ok((
            i4,
            HTTP2FrameHeaderBlock {
                name: Vec::new(),
                value: Vec::new(),
                error: HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSizeUpdate,
            },
        ));
    }
    return Ok((
        i2,
        HTTP2FrameHeaderBlock {
            name: Vec::new(),
            value: Vec::new(),
            error: HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSizeUpdate,
        },
    ));
}

fn http2_parse_headers_block<'a>(
    input: &'a [u8],
    dyn_headers: &mut Vec<HTTP2FrameHeaderBlock>,
) -> IResult<&'a [u8], HTTP2FrameHeaderBlock> {
    //caller garantees o have at least one byte
    if input[0] & 0x80 != 0 {
        return http2_parse_headers_block_indexed(input, dyn_headers);
    } else if input[0] & 0x40 != 0 {
        return http2_parse_headers_block_literal_incindex(input, dyn_headers);
    } else if input[0] & 0x20 != 0 {
        return http2_parse_headers_block_dynamic_size(input);
    } else if input[0] & 0x10 != 0 {
        return http2_parse_headers_block_literal_neverindex(input, dyn_headers);
    } else {
        return http2_parse_headers_block_literal_noindex(input, dyn_headers);
    }
}

#[derive(Clone)]
pub struct HTTP2FrameHeaders {
    pub padlength: Option<u8>,
    pub priority: Option<HTTP2FrameHeadersPriority>,
    pub blocks: Vec<HTTP2FrameHeaderBlock>,
}

const HTTP2_FLAG_HEADER_PADDED: u8 = 0x8;
const HTTP2_FLAG_HEADER_PRIORITY: u8 = 0x20;

pub fn http2_parse_frame_headers<'a>(
    input: &'a [u8],
    flags: u8,
    dyn_headers: &mut Vec<HTTP2FrameHeaderBlock>,
) -> IResult<&'a [u8], HTTP2FrameHeaders> {
    let (i2, padlength) = cond!(input, flags & HTTP2_FLAG_HEADER_PADDED != 0, be_u8)?;
    let (mut i3, priority) = cond!(
        i2,
        flags & HTTP2_FLAG_HEADER_PRIORITY != 0,
        http2_parse_headers_priority
    )?;
    let mut blocks = Vec::new();
    while i3.len() > 0 {
        match http2_parse_headers_block(i3, dyn_headers) {
            Ok((rem, b)) => {
                blocks.push(b);
                if i3.len() == rem.len() {
                    //infinite loop
                    //TODOnext panic on fuzzing
                    return Err(Err::Error((input, ErrorKind::Eof)));
                }
                i3 = rem;
            }
            Err(x) => {
                return Err(x);
            }
        }
    }
    return Ok((
        i3,
        HTTP2FrameHeaders {
            padlength,
            priority,
            blocks,
        },
    ));
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

//TODOask move elsewhere generic
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
    many0!( complete!(http2_parse_frame_setting) )
);

#[cfg(test)]
mod tests {

    use super::*;
    use nom::*;

    #[test]
    fn test_http2_parse_header() {
        let buf0: &[u8] = &[0x82];
        let mut dynh: Vec<HTTP2FrameHeaderBlock> =
            Vec::with_capacity(255 - HTTP2_STATIC_HEADERS_NUMBER);
        let r0 = http2_parse_headers_block(buf0, &mut dynh);
        match r0 {
            Ok((remainder, hd)) => {
                // Check the first message.
                assert_eq!(hd.name, ":method".as_bytes().to_vec());
                assert_eq!(hd.value, "GET".as_bytes().to_vec());
                // And we should have no bytes left.
                assert_eq!(remainder.len(), 0);
            }
            Err(Err::Incomplete(_)) => {
                panic!("Result should not have been incomplete.");
            }
            Err(Err::Error(err)) | Err(Err::Failure(err)) => {
                panic!("Result should not be an error: {:?}.", err);
            }
        }
        let buf1: &[u8] = &[0x53, 0x03, 0x2A, 0x2F, 0x2A];
        let r1 = http2_parse_headers_block(buf1, &mut dynh);
        match r1 {
            Ok((remainder, hd)) => {
                // Check the first message.
                assert_eq!(hd.name, "accept".as_bytes().to_vec());
                assert_eq!(hd.value, "*/*".as_bytes().to_vec());
                // And we should have no bytes left.
                assert_eq!(remainder.len(), 0);
                assert_eq!(dynh.len(), 1);
            }
            Err(Err::Incomplete(_)) => {
                panic!("Result should not have been incomplete.");
            }
            Err(Err::Error(err)) | Err(Err::Failure(err)) => {
                panic!("Result should not be an error: {:?}.", err);
            }
        }
        let buf: &[u8] = &[
            0x41, 0x8a, 0xa0, 0xe4, 0x1d, 0x13, 0x9d, 0x09, 0xb8, 0xc8, 0x00, 0x0f,
        ];
        let result = http2_parse_headers_block(buf, &mut dynh);
        match result {
            Ok((remainder, hd)) => {
                // Check the first message.
                assert_eq!(hd.name, ":authority".as_bytes().to_vec());
                assert_eq!(hd.value, "localhost:3000".as_bytes().to_vec());
                // And we should have no bytes left.
                assert_eq!(remainder.len(), 0);
                assert_eq!(dynh.len(), 2);
            }
            Err(Err::Incomplete(_)) => {
                panic!("Result should not have been incomplete.");
            }
            Err(Err::Error(err)) | Err(Err::Failure(err)) => {
                panic!("Result should not be an error: {:?}.", err);
            }
        }
        let buf3: &[u8] = &[0xbe];
        let r3 = http2_parse_headers_block(buf3, &mut dynh);
        match r3 {
            Ok((remainder, hd)) => {
                // same as before
                assert_eq!(hd.name, ":authority".as_bytes().to_vec());
                assert_eq!(hd.value, "localhost:3000".as_bytes().to_vec());
                // And we should have no bytes left.
                assert_eq!(remainder.len(), 0);
                assert_eq!(dynh.len(), 2);
            }
            Err(Err::Incomplete(_)) => {
                panic!("Result should not have been incomplete.");
            }
            Err(Err::Error(err)) | Err(Err::Failure(err)) => {
                panic!("Result should not be an error: {:?}.", err);
            }
        }
        let buf2: &[u8] = &[
            0x04, 0x94, 0x62, 0x43, 0x91, 0x8a, 0x47, 0x55, 0xa3, 0xa1, 0x89, 0xd3, 0x4d, 0x0c,
            0x1a, 0xa9, 0x0b, 0xe5, 0x79, 0xd3, 0x4d, 0x1f,
        ];
        let r2 = http2_parse_headers_block(buf2, &mut dynh);
        match r2 {
            Ok((remainder, hd)) => {
                // Check the first message.
                assert_eq!(hd.name, ":path".as_bytes().to_vec());
                assert_eq!(hd.value, "/doc/manual/html/index.html".as_bytes().to_vec());
                // And we should have no bytes left.
                assert_eq!(remainder.len(), 0);
                assert_eq!(dynh.len(), 2);
            }
            Err(Err::Incomplete(_)) => {
                panic!("Result should not have been incomplete.");
            }
            Err(Err::Error(err)) | Err(Err::Failure(err)) => {
                panic!("Result should not be an error: {:?}.", err);
            }
        }
    }

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
    fn test_http2_parse_headers_block_string() {
        let buf: &[u8] = &[0x01, 0xFF];
        let r = http2_parse_headers_block_string(buf);
        match r {
            Ok((remainder, _)) => {
                assert_eq!(remainder.len(), 0);
            }
            Err(Err::Error(err)) | Err(Err::Failure(err)) => {
                panic!("Result should not be an error: {:?}.", err);
            }
            _ => {
                panic!("Result should have been ok");
            }
        }
        let buf2: &[u8] = &[0x83, 0xFF, 0xFF, 0xEA];
        let r2 = http2_parse_headers_block_string(buf2);
        match r2 {
            Ok((remainder, _)) => {
                assert_eq!(remainder.len(), 0);
            }
            _ => {
                panic!("Result should have been ok");
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
