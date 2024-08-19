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

use nom7::bytes::streaming::take;
use nom7::combinator::{complete, cond, opt};
use nom7::multi::{count, many1};
use nom7::number::streaming::{be_u128, be_u16, be_u8};
use nom7::IResult;

#[repr(u16)]
#[derive(Debug, PartialEq, Eq)]
pub enum StunMethod {
    Reserved = 0x0000,
    BindingRequest = 0x0001,
    BindingResponse = 0x0101,
    BindingErrorResponse = 0x0111,
    SharedSecretRequest = 0x0002,
    SharedSecretResponse = 0x0102,
    SharedSecretErrorResponse = 0x0112,
    UnrecognizedMethod,
}

impl StunMethod {
    pub fn to_str(&self) -> &str {
        match self {
            StunMethod::Reserved => "reserved",
            StunMethod::BindingRequest => "binding_request",
            StunMethod::BindingResponse => "binding_response",
            StunMethod::BindingErrorResponse => "binding_error_response",
            StunMethod::SharedSecretRequest => "shared_secret_request",
            StunMethod::SharedSecretResponse => "shared_secret_response",
            StunMethod::SharedSecretErrorResponse => "shared_secret_error_response",
            StunMethod::UnrecognizedMethod => "unrecognized_method",
        }
    }
}

impl From<u16> for StunMethod {
    fn from(method: u16) -> Self {
        match method {
            0x0000 => StunMethod::Reserved,
            0x0001 => StunMethod::BindingRequest,
            0x0101 => StunMethod::BindingResponse,
            0x0111 => StunMethod::BindingErrorResponse,
            0x0002 => StunMethod::SharedSecretRequest, // Deprecated (RFC 5389)
            0x0102 => StunMethod::SharedSecretResponse,
            0x0112 => StunMethod::SharedSecretErrorResponse,
            _ => StunMethod::UnrecognizedMethod,
        }
    }
}

// TODO Probably have to also map // add family address (0x01 ipv4, 0x02 ipv6)


// TODO Add RFC reference to attribute
#[repr(u16)]
#[derive(Debug, PartialEq, Eq)]
pub enum StunAttributeType {
    MappedAddress = 0x0001,
    ResponseAddress = 0x0002, // deprecated
    ChangeRequest = 0x0003,  // deprecated
    SourceAddress = 0x0004, // deprecated
    ChangedAddress = 0x0005, // deprecated
    Username = 0x0006,
    Password = 0x0007, // deprecated
    MessageIntegrity = 0x0008,
    ErrorCode = 0x0009,
    UnknownAttributes = 0x000a,
    AttributeReflectedFrom = 0x000b, // deprecated. Now reserved
    Realm = 0x0014,
    Nonce = 0x0015,
    XorMappedAddress = 0x0020, // can also be 0x8020 (older servers)
    Software = 0x8022,
    AlternateServer = 0x8023,
    Fingerprint = 0x8028,
    MessageIntegritySha256 = 0x001c,
    PasswordAlgorithm = 0x001d,
    UserHash = 0x001e,
    PasswordAlgorithms = 0x8002,
    AlternateDomain = 0x8003,
    // parser found a parser not mentioned in the covered RFCs
    UnrecognizedAttribute,
}

impl StunAttributeType {
    pub fn to_str(&self) -> &str {
        match self {
            StunAttributeType::MappedAddress => "mapped_address",
            StunAttributeType::ResponseAddress => "response_address",
            StunAttributeType::ChangeRequest => "change_request",
            StunAttributeType::SourceAddress => "source_address",
            StunAttributeType::ChangedAddress => "changed_address",
            StunAttributeType::Username => "username",
            StunAttributeType::Password => "password",
            StunAttributeType::MessageIntegrity => "message_integrity",
            StunAttributeType::ErrorCode => "error_code",
            StunAttributeType::UnknownAttributes => "unknown_attributes",
            StunAttributeType::AttributeReflectedFrom => "attribute_reflected_from",
            StunAttributeType::Realm => "realm",
            StunAttributeType::Nonce => "nonce",
            StunAttributeType::XorMappedAddress => "xor_mapped_address",
            StunAttributeType::Software => "software",
            StunAttributeType::AlternateServer => "alternate_server",
            StunAttributeType::Fingerprint => "fingerprint",
            StunAttributeType::MessageIntegritySha256 => "message_integrity_sha256",
            StunAttributeType::PasswordAlgorithm => "password_algorithm",
            StunAttributeType::UserHash => "user_hash",
            StunAttributeType::PasswordAlgorithms => "password_algorithms",
            StunAttributeType::AlternateDomain => "alternate_domain",
            _ => "unrecognized_attribute",
        }
    }
}

impl From<u16> for StunAttributeType {
    fn from(attribute: u16) -> Self {
        match attribute {
            0x0001 => StunAttributeType::MappedAddress,
            0x0002 => StunAttributeType::ResponseAddress,
            0x0003 => StunAttributeType::ChangeRequest,
            0x0004 => StunAttributeType::SourceAddress,
            0x0005 => StunAttributeType::ChangedAddress,
            0x0006 => StunAttributeType::Username,
            0x0007 => StunAttributeType::Password,
            0x0008 => StunAttributeType::MessageIntegrity,
            0x0009 => StunAttributeType::ErrorCode,
            0x000a => StunAttributeType::UnknownAttributes,
            0x000b => StunAttributeType::AttributeReflectedFrom,
            0x0014 => StunAttributeType::Realm,
            0x0015 => StunAttributeType::Nonce,
            0x0020 => StunAttributeType::XorMappedAddress,
            0x8022 => StunAttributeType::Software,
            0x8023 => StunAttributeType::AlternateServer,
            0x8028 => StunAttributeType::Fingerprint,
            0x001c => StunAttributeType::MessageIntegritySha256,
            0x001d => StunAttributeType::PasswordAlgorithm,
            0x001e => StunAttributeType::UserHash,
            0x8002 => StunAttributeType::PasswordAlgorithms,
            0x8003 => StunAttributeType::AlternateDomain,
            _ => StunAttributeType::UnrecognizedAttribute,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct StunMessage {
    pub message_type: StunMethod, // mandatory two 0 bits start, so msg_type actually 14 bits long
    pub payload_length: u16,      // always end in two 0 bits (?)
    pub cookie_and_transaction_id: u128, // cookie: 4 bytes, tx_id: 12 bytes
    pub attrs: Option<Vec<StunAttribute>>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct StunAttribute {
    pub attr_type: StunAttributeType,
    pub length: u16, // actual length of attribute without padding
    pub value: Option<Vec<u8>>, // 32-bits boundary, must be a multiple of 4 bytes, padded with 1, 2, or 3 zero-only bytes if need be
                                // If that's the case, isn't it better to have...
                                // we may be able to just ignore the padding bits. check
}

fn calc_needed_padding(length: u16) -> u16 {
    (4 - (length % 4)) % 4
}

fn parse_attribute(i: &[u8]) -> IResult<&[u8], StunAttribute> {
    let (i, attr_type) = be_u16(i)?;
    let (i, length) = be_u16(i)?;
    // let(i, value) = cond(length > 0, parse_attr_value(i, length as usize))(i)?;
    let (i, value) = cond(length as usize > 0, count(be_u8, length as usize))(i)?;
    let padding = calc_needed_padding(length);
    let (i, _padds) = cond(padding > 0, take(padding as usize))(i)?;
    // check if u16 to usize is safe or could lead to complications

    Ok((
        i,
        StunAttribute {
            attr_type: StunAttributeType::from(attr_type),
            length,
            value,
        },
    ))
}

pub fn parse_message(i: &[u8]) -> IResult<&[u8], StunMessage> {
    let (i, message_type) = be_u16(i)?;
    let (i, payload_length) = be_u16(i)?;
    let (i, cookie_and_transaction_id) = be_u128(i)?;
    let (i, attrs) = opt(many1(complete(parse_attribute)))(i)?;

    Ok((
        i,
        StunMessage {
            message_type: StunMethod::from(message_type),
            payload_length,
            cookie_and_transaction_id,
            attrs,
        },
    ))
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_parse_attributes() {
        let buf = &[
            0x00, 0x06, 0x00, 0x19, 0x54, 0x77, 0x35, 0x58, 0x6d, 0x47, 0x41, 0x42, 0x54, 0x55,
            0x35, 0x35, 0x75, 0x36, 0x46, 0x32, 0x3a, 0x33, 0x31, 0x65, 0x35, 0x38, 0x62, 0x62,
            0x36, 0x00, 0x00, 0x00,
        ];

        let expected_result = StunAttribute {
            attr_type: 6.into(),
            length: 25,
            value: Some(br#"Tw5XmGABTU55u6F2:31e58bb6"#.to_vec()),
        };

        let (remainder, result) = parse_attribute(buf).unwrap();
        assert_eq!(expected_result, result);
        // assert_eq!(remainder.len(), 3 as usize);
        assert!(remainder.is_empty());

        // parse use-candidate
        let buf1 = &[0x00, 0x25, 0x00, 0x00];
        let result = parse_attribute(buf1);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_message() {
        let buf = &[
            0x00, 0x01, 0x00, 0x00, 0xd2, 0x68, 0x29, 0x9d, 0xe0, 0x7f, 0xd4, 0x36, 0xa1, 0xf1,
            0xbb, 0xba, 0x70, 0xfe, 0x4d, 0x75,
        ];

        let expected_result = StunMessage {
            message_type: 1.into(),
            payload_length: 0,
            cookie_and_transaction_id: 279678722075214397769715254464381603189,
            attrs: None,
        };

        let (remainder, result) = parse_message(buf).unwrap();

        assert_eq!(result, expected_result);
        assert!(remainder.is_empty());

        let buf1 = &[
            0x00, 0x01, 0x00, 0x58, 0x21, 0x12, 0xa4, 0x42, 0x25, 0x98, 0xa6, 0x5b, 0x97, 0x10,
            0xb8, 0x98, 0x65, 0xbc, 0x34, 0x40, 0x00, 0x06, 0x00, 0x19, 0x54, 0x77, 0x35, 0x58,
            0x6d, 0x47, 0x41, 0x42, 0x54, 0x55, 0x35, 0x35, 0x75, 0x36, 0x46, 0x32, 0x3a, 0x33,
            0x31, 0x65, 0x35, 0x38, 0x62, 0x62, 0x36, 0x00, 0x00, 0x00, 0x00, 0x25, 0x00, 0x00,
            0x00, 0x24, 0x00, 0x04, 0x6e, 0x7f, 0x00, 0xff, 0x80, 0x2a, 0x00, 0x08, 0x9e, 0x68,
            0x1f, 0x4a, 0x7b, 0x38, 0xb1, 0xcc, 0x00, 0x08, 0x00, 0x14, 0x73, 0x20, 0xf8, 0x7b,
            0x2a, 0xfd, 0x14, 0xaa, 0xe9, 0x87, 0xea, 0xc3, 0xa8, 0x5b, 0x6b, 0xcb, 0x31, 0xce,
            0xa5, 0x50, 0x80, 0x28, 0x00, 0x04, 0x28, 0x7c, 0x89, 0x26,
        ];

        let result1 = parse_message(buf1);
        assert!(result1.is_ok());
    }
}
