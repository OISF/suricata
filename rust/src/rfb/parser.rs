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

use std::fmt;
use std::str;
use nom7::bytes::streaming::take;
use nom7::combinator::map_res;
use nom7::number::streaming::*;
use nom7::*;

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
    Message
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
            RFBGlobalState::Message => write!(f, "Message")
        }
    }
}

pub struct ProtocolVersion {
    pub major: String,
    pub minor: String
}

pub struct SupportedSecurityTypes {
    pub number_of_types: u8,
    pub types: Vec<u8>
}

pub struct SecurityTypeSelection {
    pub security_type: u8
}

pub struct ServerSecurityType {
    pub security_type: u32
}

pub struct SecurityResult {
    pub status: u32
}

pub struct FailureReason {
    pub reason_string: String
}

pub struct VncAuth {
    pub secret: Vec<u8>
}

pub struct ClientInit {
    pub shared: u8
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
    pub name: Vec<u8>
}

pub fn parse_protocol_version(i: &[u8]) -> IResult<&[u8], ProtocolVersion> {
    let (i, _rfb_string) = map_res(take(3_usize), str::from_utf8)(i)?;
    let (i, _) = be_u8(i)?;
    let (i, major) = map_res(take(3_usize), str::from_utf8)(i)?;
    let (i, _) = be_u8(i)?;
    let (i, minor) = map_res(take(3_usize), str::from_utf8)(i)?;
    let (i, _) = be_u8(i)?;
    Ok((i, ProtocolVersion{ major: major.to_string(), minor: minor.to_string(), }))
}

pub fn parse_supported_security_types(i: &[u8]) -> IResult<&[u8], SupportedSecurityTypes> {
    let (i, number_of_types) = be_u8(i)?;
    let (i, types) = take(number_of_types as usize)(i)?;
    Ok((
            i,
            SupportedSecurityTypes{
                number_of_types,
                types: types.to_vec()
            }
        ))
}

pub fn parse_server_security_type(i: &[u8]) -> IResult<&[u8], ServerSecurityType> {
    let (i, security_type) = be_u32(i)?;
    Ok((i, ServerSecurityType{ security_type, }))
}

pub fn parse_vnc_auth(i: &[u8]) -> IResult<&[u8], VncAuth> {
    let (i, secret) = take(16_usize)(i)?;
    Ok((i, VncAuth { secret: secret.to_vec() }))
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
    let (i, reason_string) = map_res(take(reason_length as usize), str::from_utf8)(i)?;
    Ok((
            i,
            FailureReason {
                reason_string: reason_string.to_string()
            }
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
        name: name.to_vec()
    };
    Ok((i, init))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Simple test of some valid data.
    #[test]
    fn test_parse_version() {
        let buf = b"RFB 003.008\n";

        let result = parse_protocol_version(buf);
        match result {
            Ok((remainder, message)) => {
                // Check the first message.
                assert_eq!(message.major, "003");

                // And we should have 6 bytes left.
                assert_eq!(remainder.len(), 0);
            }
            Err(Err::Incomplete(_)) => {
                panic!("Result should not have been incomplete.");
            }
            Err(Err::Error(err)) |
            Err(Err::Failure(err)) => {
                panic!("Result should not be an error: {:?}.", err);
            }
        }
    }

    #[test]
    fn test_parse_server_init() {
        let buf = [
            0x05, 0x00, 0x03, 0x20, 0x20, 0x18, 0x00, 0x01,
            0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x10, 0x08,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1e,
            0x61, 0x6e, 0x65, 0x61, 0x67, 0x6c, 0x65, 0x73,
            0x40, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f,
            0x73, 0x74, 0x2e, 0x6c, 0x6f, 0x63, 0x61, 0x6c,
            0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e
        ];

        let result = parse_server_init(&buf);
        match result {
            Ok((remainder, message)) => {
                // Check the first message.
                assert_eq!(message.width, 1280);
                assert_eq!(message.height, 800);
                assert_eq!(message.pixel_format.bits_per_pixel, 32);

                // And we should have 6 bytes left.
                assert_eq!(remainder.len(), 0);
            }
            Err(Err::Incomplete(_)) => {
                panic!("Result should not have been incomplete.");
            }
            Err(Err::Error(err)) |
            Err(Err::Failure(err)) => {
                panic!("Result should not be an error: {:?}.", err);
            }
        }
    }

}
