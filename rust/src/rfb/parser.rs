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

// Author: Frank Honza <frank.honza@dcso.de>

use std::fmt;
use nom::*;
use nom::number::streaming::*;

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

named!(pub parse_protocol_version<ProtocolVersion>,
    do_parse!(
        _rfb_string: take_str!(3)
        >> be_u8
        >> major: take_str!(3)
        >> be_u8
        >> minor: take_str!(3)
        >> be_u8
        >> (
            ProtocolVersion{
                major: major.to_string(),
                minor: minor.to_string(),
            }
        )
    )
);

named!(pub parse_supported_security_types<SupportedSecurityTypes>,
    do_parse!(
        number_of_types: be_u8
        >> types: take!(number_of_types)
        >> (
            SupportedSecurityTypes{
                number_of_types: number_of_types,
                types: types.to_vec()
            }
        )
    )
);

named!(pub parse_server_security_type<ServerSecurityType>,
    do_parse!(
        security_type: be_u32
        >> (
            ServerSecurityType{
                security_type: security_type,
            }
        )
    )
);

named!(pub parse_vnc_auth<VncAuth>,
    do_parse!(
        secret: take!(16)
        >> (
            VncAuth {
                secret: secret.to_vec()
            }
        )
    )
);

named!(pub parse_security_type_selection<SecurityTypeSelection>,
    do_parse!(
        security_type: be_u8
        >> (
            SecurityTypeSelection {
                security_type: security_type
            }
        )
    )
);

named!(pub parse_security_result<SecurityResult>,
    do_parse!(
        status: be_u32
        >> (
            SecurityResult {
                status: status
            }
        )
    )
);

named!(pub parse_failure_reason<FailureReason>,
    do_parse!(
        reason_length: be_u32
        >> reason_string: take_str!(reason_length)
        >> (
            FailureReason {
                reason_string: reason_string.to_string()
            }
        )
    )
);

named!(pub parse_client_init<ClientInit>,
    do_parse!(
        shared: be_u8
        >> (
            ClientInit {
                shared: shared
            }
        )
    )
);

named!(pub parse_pixel_format<PixelFormat>,
    do_parse!(
        bits_per_pixel: be_u8
        >> depth: be_u8
        >> big_endian_flag: be_u8
        >> true_colour_flag: be_u8
        >> red_max: be_u16
        >> green_max: be_u16
        >> blue_max: be_u16
        >> red_shift: be_u8
        >> green_shift: be_u8
        >> blue_shift: be_u8
        >> take!(3)
        >> (
            PixelFormat {
                bits_per_pixel: bits_per_pixel,
                depth: depth,
                big_endian_flag: big_endian_flag,
                true_colour_flag: true_colour_flag,
                red_max: red_max,
                green_max: green_max,
                blue_max: blue_max,
                red_shift: red_shift,
                green_shift: green_shift,
                blue_shift: blue_shift,
            }
        )
    )
);

named!(pub parse_server_init<ServerInit>,
    do_parse!(
        width: be_u16
        >> height: be_u16
        >> pixel_format: parse_pixel_format
        >> name_length: be_u32
        >> name: take!(name_length)
        >> (
            ServerInit {
                width: width,
                height: height,
                pixel_format: pixel_format,
                name_length: name_length,
                name: name.to_vec()
            }
        )
    )
);

#[cfg(test)]
mod tests {
    use nom::*;
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
