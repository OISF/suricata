/* Copyright (C) 2020-2022 Open Information Security Foundation
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

// Author: Frank Honza <frank.honza@dcso.de>

use nom8::bytes::streaming::tag;
use nom8::bytes::streaming::take;
use nom8::combinator::map_res;
use nom8::number::streaming::*;
use nom8::{IResult, Parser};
use std::fmt;
use std::str;

#[derive(Debug, PartialEq)]
pub enum RFBGlobalState {
    TCServerProtocolVersion,
    TCSupportedSecurityTypes,
    TCVncChallenge,
    TCServerInit,
    TCFailureReason,
    TSClientProtocolVersion,
    TCServerSecurityType,
    TSSecurityTypeSelection,
    TSVncResponse,
    TCSecurityResult,
    TSClientInit,
    Skip,
}

impl fmt::Display for RFBGlobalState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            RFBGlobalState::TCServerProtocolVersion => write!(f, "TCServerProtocolVersion"),
            RFBGlobalState::TCSupportedSecurityTypes => write!(f, "TCSupportedSecurityTypes"),
            RFBGlobalState::TCVncChallenge => write!(f, "TCVncChallenge"),
            RFBGlobalState::TCServerInit => write!(f, "TCServerInit"),
            RFBGlobalState::TCFailureReason => write!(f, "TCFailureReason"),
            RFBGlobalState::TSClientProtocolVersion => write!(f, "TSClientProtocolVersion"),
            RFBGlobalState::TSSecurityTypeSelection => write!(f, "TSSecurityTypeSelection"),
            RFBGlobalState::TSVncResponse => write!(f, "TSVncResponse"),
            RFBGlobalState::TCSecurityResult => write!(f, "TCSecurityResult"),
            RFBGlobalState::TCServerSecurityType => write!(f, "TCServerSecurityType"),
            RFBGlobalState::TSClientInit => write!(f, "TSClientInit"),
            RFBGlobalState::Skip => write!(f, "Skip"),
        }
    }
}

pub struct ProtocolVersion {
    pub major: String,
    pub minor: String,
}

pub struct SupportedSecurityTypes {
    pub number_of_types: u8,
    pub types: Vec<u8>,
}

pub struct SecurityTypeSelection {
    pub security_type: u8,
}

pub struct ServerSecurityType {
    pub security_type: u32,
}

#[derive(Clone, Debug, Default, EnumStringU32)]
#[repr(u32)]
pub enum RFBSecurityResultStatus {
    #[default]
    Ok = 0,
    Fail = 1,
    TooMany = 2,
    Unknown = 3,
}

pub struct SecurityResult {
    pub status: u32,
}

pub struct FailureReason {
    pub reason_string: String,
}

pub struct VncAuth {
    pub secret: Vec<u8>,
}

pub struct ClientInit {
    pub shared: u8,
}

pub struct PixelFormat {
    pub bits_per_pixel: u8,
    pub depth: u8,
    pub big_endian_flag: u8,
    pub true_colour_flag: u8,
    pub red_max: u16,
    pub green_max: u16,
    pub blue_max: u16,
    pub red_shift: u8,
    pub green_shift: u8,
    pub blue_shift: u8,
}

pub struct ServerInit {
    pub width: u16,
    pub height: u16,
    pub pixel_format: PixelFormat,
    pub name_length: u32,
    pub name: Vec<u8>,
}

pub fn parse_protocol_version(i: &[u8]) -> IResult<&[u8], ProtocolVersion> {
    let (i, _) = tag("RFB ")(i)?;
    let (i, major) = map_res(take(3_usize), str::from_utf8).parse(i)?;
    let (i, _) = tag(".")(i)?;
    let (i, minor) = map_res(take(3_usize), str::from_utf8).parse(i)?;
    let (i, _) = tag("\n")(i)?;
    Ok((
        i,
        ProtocolVersion {
            major: major.to_string(),
            minor: minor.to_string(),
        },
    ))
}

pub fn parse_supported_security_types(i: &[u8]) -> IResult<&[u8], SupportedSecurityTypes> {
    let (i, number_of_types) = be_u8(i)?;
    let (i, types) = take(number_of_types as usize)(i)?;
    Ok((
        i,
        SupportedSecurityTypes {
            number_of_types,
            types: types.to_vec(),
        },
    ))
}

pub fn parse_server_security_type(i: &[u8]) -> IResult<&[u8], ServerSecurityType> {
    let (i, security_type) = be_u32(i)?;
    Ok((i, ServerSecurityType { security_type }))
}

pub fn parse_vnc_auth(i: &[u8]) -> IResult<&[u8], VncAuth> {
    let (i, secret) = take(16_usize)(i)?;
    Ok((
        i,
        VncAuth {
            secret: secret.to_vec(),
        },
    ))
}

pub fn parse_security_type_selection(i: &[u8]) -> IResult<&[u8], SecurityTypeSelection> {
    let (i, security_type) = be_u8(i)?;
    Ok((i, SecurityTypeSelection { security_type }))
}

pub fn parse_security_result(i: &[u8]) -> IResult<&[u8], SecurityResult> {
    let (i, status) = be_u32(i)?;
    Ok((i, SecurityResult { status }))
}

pub fn parse_failure_reason(i: &[u8]) -> IResult<&[u8], FailureReason> {
    let (i, reason_length) = be_u32(i)?;
    let (i, reason_string) = map_res(take(reason_length as usize), str::from_utf8).parse(i)?;
    Ok((
        i,
        FailureReason {
            reason_string: reason_string.to_string(),
        },
    ))
}

pub fn parse_client_init(i: &[u8]) -> IResult<&[u8], ClientInit> {
    let (i, shared) = be_u8(i)?;
    Ok((i, ClientInit { shared }))
}

pub fn parse_pixel_format(i: &[u8]) -> IResult<&[u8], PixelFormat> {
    let (i, bits_per_pixel) = be_u8(i)?;
    let (i, depth) = be_u8(i)?;
    let (i, big_endian_flag) = be_u8(i)?;
    let (i, true_colour_flag) = be_u8(i)?;
    let (i, red_max) = be_u16(i)?;
    let (i, green_max) = be_u16(i)?;
    let (i, blue_max) = be_u16(i)?;
    let (i, red_shift) = be_u8(i)?;
    let (i, green_shift) = be_u8(i)?;
    let (i, blue_shift) = be_u8(i)?;
    let (i, _) = take(3_usize)(i)?;
    let format = PixelFormat {
        bits_per_pixel,
        depth,
        big_endian_flag,
        true_colour_flag,
        red_max,
        green_max,
        blue_max,
        red_shift,
        green_shift,
        blue_shift,
    };
    Ok((i, format))
}

pub fn parse_server_init(i: &[u8]) -> IResult<&[u8], ServerInit> {
    let (i, width) = be_u16(i)?;
    let (i, height) = be_u16(i)?;
    let (i, pixel_format) = parse_pixel_format(i)?;
    let (i, name_length) = be_u32(i)?;
    let (i, name) = take(name_length as usize)(i)?;
    let init = ServerInit {
        width,
        height,
        pixel_format,
        name_length,
        name: name.to_vec(),
    };
    Ok((i, init))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nom8::Err;

    /// Simple test of some valid data.
    #[test]
    fn test_parse_version() {
        let buf = b"RFB 003.008\n";

        let result = parse_protocol_version(buf);
        match result {
            Ok((remainder, message)) => {
                // Check the first message.
                assert_eq!(message.major, "003");

                // And we should have 0 bytes left.
                assert_eq!(remainder.len(), 0);
            }
            Err(Err::Incomplete(_)) => {
                panic!("Result should not have been incomplete.");
            }
            Err(Err::Error(err)) | Err(Err::Failure(err)) => {
                panic!("Result should not be an error: {:?}.", err);
            }
        }
    }

    #[test]
    fn test_parse_server_init() {
        let buf = [
            0x05, 0x00, 0x03, 0x20, 0x20, 0x18, 0x00, 0x01, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff,
            0x10, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1e, 0x61, 0x6e, 0x65, 0x61,
            0x67, 0x6c, 0x65, 0x73, 0x40, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74,
            0x2e, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e,
        ];

        let result = parse_server_init(&buf);
        match result {
            Ok((remainder, message)) => {
                // Check the first message.
                assert_eq!(message.width, 1280);
                assert_eq!(message.height, 800);
                assert_eq!(message.pixel_format.bits_per_pixel, 32);

                // And we should have 0 bytes left.
                assert_eq!(remainder.len(), 0);
            }
            Err(Err::Incomplete(_)) => {
                panic!("Result should not have been incomplete.");
            }
            Err(Err::Error(err)) | Err(Err::Failure(err)) => {
                panic!("Result should not be an error: {:?}.", err);
            }
        }
    }

    #[test]
    fn test_parse_pixel_format() {
        let buf = [
            0x20, /* Bits per pixel: 32 */
            0x18, /* Depth: 24 */
            0x00, /* Big endian flag: False */
            0x01, /* True color flag: True */
            0x00, 0xff, /* Red maximum: 255 */
            0x00, 0xff, /* Green maximum: 255 */
            0x00, 0xff, /* Blue maximum: 255 */
            0x10, /* Red shift: 16 */
            0x08, /* Green shift: 8 */
            0x00, /* Blue shift: 0 */
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xa0,
        ];

        let result = parse_pixel_format(&buf);
        match result {
            Ok((remainder, message)) => {
                assert_eq!(message.bits_per_pixel, 32);
                assert_eq!(message.depth, 24);
                assert_eq!(message.big_endian_flag, 0);
                assert_eq!(message.true_colour_flag, 1);
                assert_eq!(message.red_max, 255);
                assert_eq!(message.green_max, 255);
                assert_eq!(message.blue_max, 255);
                assert_eq!(message.red_shift, 16);
                assert_eq!(message.green_shift, 8);
                assert_eq!(message.blue_shift, 0);
                assert_eq!(remainder.len(), 5);
            }
            Err(Err::Incomplete(_)) => {
                panic!("Result should not have been incomplete.");
            }
            Err(Err::Error(err)) | Err(Err::Failure(err)) => {
                panic!("Result should not be an error: {:?}.", err);
            }
        }
    }

    #[test]
    fn test_parse_supported_security_types() {
        let buf = [
            0x01, /* Number of security types: 1 */
            0x02, /* Security type: VNC (2) */
            0x00, 0x01, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x10, 0x08, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01, 0xa0,
        ];

        let result = parse_supported_security_types(&buf);
        match result {
            Ok((remainder, message)) => {
                assert_eq!(message.number_of_types, 1);
                assert_eq!(message.types[0], 2);
                assert_eq!(remainder.len(), 19);
            }
            Err(Err::Incomplete(_)) => {
                panic!("Result should not have been incomplete.");
            }
            Err(Err::Error(err)) | Err(Err::Failure(err)) => {
                panic!("Result should not be an error: {:?}.", err);
            }
        }
    }

    #[test]
    fn test_parse_vnc_auth() {
        let buf = [
            0x54, 0x7b, 0x7a, 0x6f, 0x36, 0xa1, 0x54, 0xdb, 0x03, 0xa2, 0x57, 0x5c, 0x6f, 0x2a,
            0x4e, 0xc5, /* Authentication challenge: 547b7a6f36a154db03a2575c6f2a4ec5 */
            0x00, 0x00, 0x00, 0x01, 0xa0,
        ];

        let result = parse_vnc_auth(&buf);
        match result {
            Ok((remainder, message)) => {
                assert_eq!(
                    hex::encode(message.secret),
                    "547b7a6f36a154db03a2575c6f2a4ec5"
                );
                assert_eq!(remainder.len(), 5);
            }
            Err(Err::Incomplete(_)) => {
                panic!("Result should not have been incomplete.");
            }
            Err(Err::Error(err)) | Err(Err::Failure(err)) => {
                panic!("Result should not be an error: {:?}.", err);
            }
        }
    }

    #[test]
    fn test_parse_client_init() {
        let buf = [
            0x00, /*Share desktop flag: False*/
            0x7b, 0x7a, 0x6f, 0x36, 0xa1, 0x54, 0xdb, 0x03, 0xa2, 0x57, 0x5c, 0x6f, 0x2a, 0x4e,
            0xc5, 0x00, 0x00, 0x00, 0x01, 0xa0,
        ];

        let result = parse_client_init(&buf);
        match result {
            Ok((remainder, message)) => {
                assert_eq!(message.shared, 0);
                assert_eq!(remainder.len(), 20);
            }
            Err(Err::Incomplete(_)) => {
                panic!("Result should not have been incomplete.");
            }
            Err(Err::Error(err)) | Err(Err::Failure(err)) => {
                panic!("Result should not be an error: {:?}.", err);
            }
        }
    }
}
