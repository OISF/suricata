/* Copyright (C) 2021 Open Information Security Foundation
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

use std::{fmt};
use nom::number::streaming::{be_u8, be_u16, be_u32};

pub const PGSQL_DUMMY_PROTO_MAJOR: u16 = 1234; // 0x04d2
pub const PGSQL_DUMMY_PROTO_MINOR_SSL: u16 = 5679; //0x162f
pub const _PGSQL_DUMMY_PROTO_MINOR_GSSAPI: u16 = 5680; // 0x1630

#[derive(Debug, PartialEq)]
struct PgsqlParameter {
    param_name: Vec<u8>,
    param_value: Vec<u8>,
}

// TODO I think I can simplify this by simply having a vector of pgsqlparams
// (but I didn't manage to make this work without overcomplicating things...)
#[derive(Debug, PartialEq)]
pub struct PgsqlStartupParameters {
    user: PgsqlParameter,
    database: Option<PgsqlParameter>,
    // TODO size-wise, being Option<Vec> or just Vec here is the same. I wonder if
    // implementation-wise one way is preferred over the other
    optional_params: Option<Vec<PgsqlParameter>>,
}

impl fmt::Display for PgsqlStartupParameters {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

named!(parse_user_param<PgsqlParameter>,
    do_parse!(
        param_name: tag_no_case!("user")
        >> tag!("\x00")
        >> param_value: take_until1!("\x00")
        >> tag!("\x00")
        >> (PgsqlParameter{
            param_name: param_name.to_vec(),
            param_value: param_value.to_vec(),
            })
    ));

named!(parse_database_param<PgsqlParameter>,
    do_parse!(
        param_name: tag_no_case!("database")
        >> tag!("\x00")
        >> param_value: take_until1!("\x00")
        >> tag!("\x00")
        >> (PgsqlParameter{
                param_name: param_name.to_vec(),
                param_value: param_value.to_vec(),
            })
    ));

//TODO shall I create a generic parser for the parameters, which receives tag as an argument?
// using named_args....
named!(pgsql_parse_parameter<PgsqlParameter>,
    do_parse!(
        param_name: take_until1!("\x00")
        >> tag!("\x00")
        >> param_value: take_until1!("\x00")
        >> tag!("\x00")
        >> (PgsqlParameter{
                param_name: param_name.to_vec(),
                param_value: param_value.to_vec(),
            })
    ));

named!(pub pgsql_parse_startup_parameters<PgsqlStartupParameters>,
    do_parse!(
        user: call!(parse_user_param)
        >> database: opt!(parse_database_param)
        >> optional: opt!(terminated!(many1!(pgsql_parse_parameter), tag!("\x00")))
        >> (PgsqlStartupParameters{
                user,
                database,
                optional_params: optional,
        })
    ));

#[derive(Debug, PartialEq)]
pub struct PgsqlDummyStartupPacket {
    length: u32,
    proto_major: u16,
    proto_minor: u16,
}

#[derive(Debug, PartialEq)]
pub struct PgsqlStartupPacket{
    length: u32,
    proto_major: u16,
    proto_minor: u16,
    params: PgsqlStartupParameters,
}

impl fmt::Display for PgsqlStartupPacket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

//TODO soon to find out whether this shall be specialized or not (as in, having
// more structs to cover specific cases)
#[derive(Debug, PartialEq)]
pub struct PgsqlRegularPacket{
    identifier: u8,
    length: u32,
    payload: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub enum PgsqlSslResponse {
    SslAccepted,
    SslRejected,
    InvalidResponse,
}

impl From<u8> for PgsqlSslResponse {
    fn from(identifier: u8) -> Self {
        match identifier {
            b'S' => Self::SslAccepted,
            b'N' => Self::SslRejected,
            _ => Self::InvalidResponse,
        }
    }
}

impl From<char> for PgsqlSslResponse {
    fn from(identifier: char) -> Self {
        match identifier {
            'S' => Self::SslAccepted,
            'N'=> Self::SslRejected,
            _ => Self::InvalidResponse,
        }
    }
}
// TODO decide whether to have different enums for FE / BE messages,
// as few are common
#[derive(Debug, PartialEq)]
pub enum PgsqlMessageType {
    StartupMessage(PgsqlStartupPacket),
    SslRequest(PgsqlDummyStartupPacket),
    SslResponse(PgsqlSslResponse), // BE message
    PasswordMessage(PgsqlRegularPacket), // FE message
    AuthenticationMD5Password(PgsqlAuthenticationMessage), // BE message
    AuthenticationCleartextPassword(PgsqlAuthenticationMessage), // BE message
    AuthenticationOk(PgsqlAuthenticationMessage), // BE message
}

#[derive(Debug, PartialEq)]
pub struct PgsqlAuthenticationMessage {
    identifier: u8,
    length: u32,
    auth_type: u32,
    payload: Option<Vec<u8>>,
}

// TODO even though they have now the same implementation, I think it's better
// to have them as different types
#[derive(Debug, PartialEq)]
pub struct PgsqlRequestMessage {
    pub message_type: PgsqlMessageType,
    // TODO I'm not sure whether length should be in the other structures, or here
}

impl fmt::Display for PgsqlRequestMessage {
    fn fmt(&self, f:&mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

// TODO keep extending, to parse more messages!
// Likely requires refactoring, to hide part of the logic in specialized parsers
// may also need better checking to ensure length is right
named!(pub pgsql_parse_startup_packet<PgsqlRequestMessage>,
    do_parse!(
        len: verify!(be_u32, |&x| x >= 8)
        >> proto_major: peek!(be_u16)
        >> message: flat_map!(take!(len - 4),
                    switch!(value!(proto_major),
                        1 | 2 | 3 => do_parse!(
                                        proto_major: be_u16
                                        >> proto_minor: be_u16
                                        >> params: call!(pgsql_parse_startup_parameters)
                                        >> (PgsqlMessageType::StartupMessage(PgsqlStartupPacket{
                                                length: len,
                                                proto_major,
                                                proto_minor,
                                                params}))) |
                        PGSQL_DUMMY_PROTO_MAJOR => do_parse!(
                                        proto_major: be_u16
                                        >> proto_minor: exact!(be_u16)
                                        >> message: switch!(value!(proto_minor),
                                            PGSQL_DUMMY_PROTO_MINOR_SSL => tuple!(
                                                        value!(len),
                                                        value!(proto_major),
                                                        value!(proto_minor)))
                                        >> (PgsqlMessageType::SslRequest(PgsqlDummyStartupPacket{
                                            length: len,
                                            proto_major,
                                            proto_minor})))
                        ))
        >> (PgsqlRequestMessage{
            message_type: message,
        })
    ));

// Password can be encrypted or in cleartext
named!(pgsql_parse_password_message<PgsqlRequestMessage>,
    do_parse!(
        identifier: verify!(be_u8, |&x| x == b'p')
        >> length: verify!(be_u32, |&x| x >= 5)
        >> password: flat_map!(take!(length - 4), take_until1!("\x00"))
        >> (PgsqlRequestMessage{
                message_type: PgsqlMessageType::PasswordMessage(
                    PgsqlRegularPacket{
                        identifier,
                        length,
                        payload: password.to_vec(),
                    })
        })
    ));

// TODO messages that begin with 'p' but are not password ones are not parsed yet
// we may need to bring some context logic to pgsql.rs, as content interpretation
// of such messages is context (transaction, I believe) dependent
named!(pub pgsql_parse_request<PgsqlRequestMessage>,
    do_parse!(
        tag: peek!(be_u8)
        >> message: switch!(value!(tag),
                        b'\0' => call!(pgsql_parse_startup_packet) |
                        b'p' =>  call!(pgsql_parse_password_message) // |
                )
        >> (message)
    ));

    //TODO this is working at minimum capabilities. I'll take a break and go to the
    // lighter task (hopefully) of fixing typos, and may can be later on today to this,
    // next TODO is parse the response, unit test it, then move on to pgsql file to integrate
    // current decoders to suricata <3

#[derive(Debug, PartialEq)]
pub struct PgsqlResponseMessage{
    // TODO I'm not sure whether length should be in the other structures, or here
    pub message_type: PgsqlMessageType,
}

impl fmt::Display for PgsqlResponseMessage {
    fn fmt(&self, f:&mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

named!(pgsql_parse_ssl_response<PgsqlMessageType>,
    do_parse!(
        tag: alt!(char!('N') | char!('S')) // TODO this doesn't work. Could use char!
        // but must make sure it's just 1 byte long....
        >> (PgsqlMessageType::SslResponse(
            PgsqlSslResponse::from(tag))
        )
    ));

named!(pgsql_parse_authentication_message<PgsqlMessageType>,
    do_parse!(
        identifier: verify!(be_u8, |&x| x == b'R')
        >> length: verify!(be_u32, |&x| x >= 8 )
        >> auth_type: be_u32
        >> message: flat_map!(take!(length - 8), switch!(value!(auth_type),
            5 => do_parse!(
                salt: exact!(take!(4))
                >> (PgsqlMessageType::AuthenticationMD5Password(
                        PgsqlAuthenticationMessage {
                            identifier,
                            length,
                            auth_type,
                            payload: Some(salt.to_vec()),
                        }))) |
            3 => value!(PgsqlMessageType::AuthenticationCleartextPassword(
                    PgsqlAuthenticationMessage {
                        identifier,
                        length,
                        auth_type,
                        payload: None,
                    }))  |
            0 => value!(PgsqlMessageType::AuthenticationOk(
                    PgsqlAuthenticationMessage {
                        identifier,
                        length,
                        auth_type,
                        payload: None,
                    }))
            // TODO parse AuthOk
        ))
        >> (message)
    ));

named!(pub pgsql_parse_response<PgsqlResponseMessage>,
    do_parse!(
        message: switch!(peek!(be_u8),
            // TODO This will need refactoring, must take into account length,
            // else this could take a parameters message as an SSL Response
            b'N' | b'S' => dbg_dmp!(call!(pgsql_parse_ssl_response)) |
            b'R' => dbg_dmp!(call!(pgsql_parse_authentication_message))
            // _ => {}
        )
        >> (PgsqlResponseMessage{
            message_type: message,
        })
    ));

// TODOs
// unit tests!!!
// nom parser for PgsqlDummyStartupPacket or will I?
// nom parser for PgsqlRequestMessage -- on its way...
// nom parser for PgsqlResponseMessage
// nom parser for PgsqlSslResponse
// implementing the above should allow me to rewrite SSL handshake
// nom parser for PgsqlParams
// nom parser for PgsqlStartupParameters
// nom parser for PgsqlStartupPacket -- embed in parser for request message, now

// TODO decide whether to keep this or not. If I have to parse length in more
// than one place, it does sound reasonable,
// to avoid writing take!(len - 4) everywhere and any possible related mistakes...
fn _parse_len(input: &str) -> Result<u32, std::num::ParseIntError> {
    input.parse::<u32>()
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_parse_request() {
        // An SSLRequest
        let buf: &[u8] = &[0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f];
        let ssl_request = PgsqlDummyStartupPacket {
            length: 8,
            proto_major: PGSQL_DUMMY_PROTO_MAJOR,
            proto_minor: PGSQL_DUMMY_PROTO_MINOR_SSL,
        };
        let request_ok = PgsqlRequestMessage {
            message_type: PgsqlMessageType::SslRequest(ssl_request),
        };

        let (_remainder, result) = pgsql_parse_request(&buf).unwrap();
        assert_eq!(result, request_ok);

        // incomplete message
        let result = pgsql_parse_request(&buf[0..7]);
        assert!(result.is_err());

        // Length is wrong
        let buf: &[u8] = &[0x00, 0x00, 0x00, 0x07, 0x04, 0xd2, 0x16, 0x2f];
        let result = pgsql_parse_request(&buf);
        assert!(result.is_err());

        let buf: &[u8] = &[
        /* Length */        0x00, 0x00, 0x00, 0x55,
        /* Protocol */      0x00, 0x03, 0x00, 0x00,
        /* user*/           0x75, 0x73, 0x65, 0x72, 0x00,
        /* value */         0x72, 0x65, 0x70, 0x00,
        /* database */      0x64, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65, 0x00,
        /* optional */      0x72, 0x65, 0x70, 0x6c, 0x69, 0x63,
                            0x61, 0x74, 0x69, 0x6f, 0x6e, 0x00, 0x72, 0x65,
                            0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f,
                            0x6e, 0x00, 0x74, 0x72, 0x75, 0x65, 0x00, 0x61,
                            0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69,
                            0x6f, 0x6e, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x00,
                            0x77, 0x61, 0x6c, 0x72, 0x65, 0x63, 0x65, 0x69,
                            0x76, 0x65, 0x72, 0x00, 0x00
          ];
        let result = pgsql_parse_request(&buf);
        match result {
            Ok((remainder, _message)) => {
                // there should be nothing left
                assert_eq!(remainder.len(), 0);
            }
            Err(nom::Err::Error((_remainder, err))) => {
                panic!("Result should not be an error: {:?}.", err);
            }
            Err(nom::Err::Incomplete(_)) => {
                panic!("Result should not have been incomplete.");
            }
            _ => {
                panic!("Unexpected behavior!");
            }
        }

        // A valid startup message/request without optional parameters
        let buf: &[u8] = &[ 0x00, 0x00, 0x00, 0x26,
                            0x00, 0x03, 0x00, 0x00,
                            0x75, 0x73, 0x65, 0x72, 0x00,
                            0x6f, 0x72, 0x79, 0x78, 0x00,
                            0x64, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65, 0x00,
                            0x6d, 0x61, 0x69, 0x6c, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x00, 0x00];
        let user = PgsqlParameter {
            param_name: [0x75, 0x73, 0x65, 0x72].to_vec(),
            param_value: [0x6f, 0x72, 0x79, 0x78].to_vec(),
        };
        let database = PgsqlParameter {
            param_name: [0x64, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65].to_vec(),
            param_value: [0x6d, 0x61, 0x69, 0x6c, 0x73, 0x74, 0x6f, 0x72, 0x65].to_vec(),
        };
        let params = PgsqlStartupParameters{
            user,
            database: Some(database),
            optional_params: None,
        };
        let expected_result = PgsqlRequestMessage{
            message_type: PgsqlMessageType::StartupMessage(
                PgsqlStartupPacket{
                    length: 38,
                    proto_major: 3,
                    proto_minor: 0,
                    params,
                })};
        let result = pgsql_parse_request(&buf);
        match result {
            Ok((remainder, message)) => {
                assert_eq!(message, expected_result);
                assert_eq!(remainder.len(), 0);
            }
            Err(nom::Err::Error((_remainder, err))) => {
                panic!("Shouldn't be error: {:?}", err);
            }
            Err(nom::Err::Incomplete(needed)) => {
                panic!("Should not be Incomplete! Needed: {:?}", needed);
            }
            _ => {
                panic!("Unexpected behavior");
            }
        }

        // A valid startup message/request without any optional parameters
        let buf: &[u8] = &[ 0x00, 0x00, 0x00, 0x13,
                            0x00, 0x03, 0x00, 0x00,
                            0x75, 0x73, 0x65, 0x72, 0x00,
                            0x6f, 0x72, 0x79, 0x78, 0x00, 0x00];
        let user = PgsqlParameter {
            param_name: [0x75, 0x73, 0x65, 0x72].to_vec(),
            param_value: [0x6f, 0x72, 0x79, 0x78].to_vec(),
        };
        let params = PgsqlStartupParameters{
            user,
            database: None,
            optional_params: None,
        };
        let expected_result = PgsqlRequestMessage{
            message_type: PgsqlMessageType::StartupMessage(
                PgsqlStartupPacket{
                    length: 19,
                    proto_major: 3,
                    proto_minor: 0,
                    params,
                })};
        let result = pgsql_parse_request(&buf);
        match result {
            Ok((remainder, message)) => {
                assert_eq!(message, expected_result);
                assert_eq!(remainder.len(), 0);
            }
            Err(nom::Err::Error((_remainder, err))) => {
                panic!("Shouldn't be error: {:?}", err);
            }
            Err(nom::Err::Incomplete(needed)) => {
                panic!("Should not be Incomplete! Needed: {:?}", needed);
            }
            _ => {
                panic!("Unexpected behavior");
            }
        }

        // A startup message/request with length off by one
        let buf: &[u8] = &[ 0x00, 0x00, 0x00, 0x12,
                            0x00, 0x03, 0x00, 0x00,
                            0x75, 0x73, 0x65, 0x72, 0x00,
                            0x6f, 0x72, 0x79, 0x78, 0x00, 0x00];
        let result = pgsql_parse_request(&buf);
        assert!(result.is_err());

        // A startup message/request with bad length
        let buf: &[u8] = &[ 0x00, 0x00, 0x00, 0x01,
                            0x00, 0x03, 0x00, 0x00,
                            0x75, 0x73, 0x65, 0x72, 0x00,
                            0x6f, 0x72, 0x79, 0x78, 0x00, 0x00];
        let result = pgsql_parse_request(&buf);
        assert!(result.is_err());

        // A startup message/request with corrupted user param
        let buf: &[u8] = &[ 0x00, 0x00, 0x00, 0x013,
                            0x00, 0x03, 0x00, 0x00,
                            0x75, 0x73, 0x65, 0x00,
                            0x6f, 0x72, 0x79, 0x78, 0x00, 0x00];
        let result = pgsql_parse_request(&buf);
        assert!(result.is_err());

        // A startup message/request missing the terminator
        let buf: &[u8] = &[ 0x00, 0x00, 0x00, 0x013,
                            0x00, 0x03, 0x00, 0x00,
                            0x75, 0x73, 0x65, 0x72, 0x00,
                            0x6f, 0x72, 0x79, 0x78, 0x00];
        let result = pgsql_parse_request(&buf);
        assert!(result.is_err());

        // A password message (MD5)
        let buf: &[u8] = &[ 0x70, 0x00, 0x00, 0x00, 0x28, 0x6d, 0x64, 0x35,
                            0x63, 0x65, 0x66, 0x66, 0x63, 0x30, 0x31, 0x64,
                            0x63, 0x64, 0x65, 0x37, 0x35, 0x34, 0x31, 0x38,
                            0x32, 0x39, 0x64, 0x65, 0x65, 0x66, 0x36, 0x62,
                            0x35, 0x65, 0x39, 0x63, 0x39, 0x31, 0x34, 0x32,
                            0x00];
        let ok_result = PgsqlRequestMessage {
            message_type: PgsqlMessageType::PasswordMessage(
                PgsqlRegularPacket {
                    identifier: b'p',
                    length: 40,
                    payload: br#"md5ceffc01dcde7541829deef6b5e9c9142"#.to_vec(),
                })
        };
        let (_remainder, result) = pgsql_parse_request(&buf).unwrap();
        assert_eq!(result, ok_result);

        // Length is off by one here
        let buf: &[u8] = &[ 0x70, 0x00, 0x00, 0x00, 0x27, 0x6d, 0x64, 0x35,
                            0x63, 0x65, 0x66, 0x66, 0x63, 0x30, 0x31, 0x64,
                            0x63, 0x64, 0x65, 0x37, 0x35, 0x34, 0x31, 0x38,
                            0x32, 0x39, 0x64, 0x65, 0x65, 0x66, 0x36, 0x62,
                            0x35, 0x65, 0x39, 0x63, 0x39, 0x31, 0x34, 0x32,
                            0x00];
        let result = pgsql_parse_request(&buf);
        assert!(result.is_err());

        // Length also off by one, but now bigger than it should
        let buf: &[u8] = &[ 0x70, 0x00, 0x00, 0x00, 0x29, 0x6d, 0x64, 0x35,
                            0x63, 0x65, 0x66, 0x66, 0x63, 0x30, 0x31, 0x64,
                            0x63, 0x64, 0x65, 0x37, 0x35, 0x34, 0x31, 0x38,
                            0x32, 0x39, 0x64, 0x65, 0x65, 0x66, 0x36, 0x62,
                            0x35, 0x65, 0x39, 0x63, 0x39, 0x31, 0x34, 0x32,
                            0x00];
        let result = pgsql_parse_request(&buf);
        assert!(result.is_err());

        // Incomplete payload
        let buf: &[u8] = &[ 0x70, 0x00, 0x00, 0x00, 0x28, 0x6d, 0x64, 0x35,
                            0x63, 0x65, 0x66, 0x66, 0x63, 0x30, 0x31, 0x64,
                            0x63, 0x64, 0x65, 0x37, 0x35, 0x34, 0x31, 0x38,
                            0x32, 0x39, 0x64, 0x65, 0x65, 0x66, 0x36, 0x62,
                            0x35, 0x65, 0x39, 0x63, 0x39, 0x31, 0x34, 0x32];
        let result = pgsql_parse_request(&buf);
        assert!(result.is_err());

        // TODO add other messages

    }

    #[test]
    fn test_parse_response() {
        // An SSL response - N
        let buf: &[u8] = &[0x4e];
        let ssl_response = PgsqlMessageType::SslResponse(PgsqlSslResponse::SslRejected);
        let response_ok = PgsqlResponseMessage{
            message_type: ssl_response,
        };
        let (_remainder, result) = pgsql_parse_response(&buf).unwrap();
        assert_eq!(result, response_ok);

        // An SSL response - S
        let buf: &[u8] = &[0x53];
        let ssl_response = PgsqlMessageType::SslResponse(PgsqlSslResponse::SslAccepted);
        let response_ok = PgsqlResponseMessage{
            message_type: ssl_response,
        };
        let (_remainder, result) = pgsql_parse_response(&buf).unwrap();
        assert_eq!(result, response_ok);

        // Not an SSL response
        let buf: &[u8] = &[0x52];
        let result = pgsql_parse_response(&buf);
        assert!(result.is_err());

        // - auth MD5
        let buf: &[u8] = &[ 0x52,
                            0x00, 0x00, 0x00, 0x0c,
                            0x00, 0x00, 0x00, 0x05,
                            0xf2, 0x11, 0xa3, 0xed];
        let ok_res = PgsqlResponseMessage {
            message_type: PgsqlMessageType::AuthenticationMD5Password(
                PgsqlAuthenticationMessage {
                    identifier: b'R',
                    length: 12,
                    auth_type: 5,
                    payload: Some(vec![0xf2, 0x11, 0xa3, 0xed]),
                })
        };
        let result = pgsql_parse_response(&buf);
        match result {
            Ok((remainder, message)) => {
                assert_eq!(message, ok_res);
                assert_eq!(remainder.len(), 0);
            }
            Err(nom::Err::Error((_remainder, err))) => {
                panic!("Shouldn't be error: {:?}", err);
            }
            Err(nom::Err::Incomplete(needed)) => {
                panic!("Should not be Incomplete! Needed: {:?}", needed);
            }
            _ => {
                panic!("Unexpected behavior");
            }
        }

        // - auth clear text...
        let buf: &[u8] = &[ 0x52,
                            0x00, 0x00, 0x00, 0x08,
                            0x00, 0x00, 0x00, 0x03];
        let ok_res = PgsqlResponseMessage{
            message_type: PgsqlMessageType::AuthenticationCleartextPassword(
                PgsqlAuthenticationMessage{
                    identifier: b'R',
                    length: 8,
                    auth_type: 3,
                    payload: None,
                })};
        let result = pgsql_parse_response(&buf);
        match result {
            Ok((remainder, message)) => {
                assert_eq!(remainder.len(), 0);
                assert_eq!(message, ok_res);
            }
            Err(nom::Err::Error((_remainder, err))) => {
                panic!("Shouldn't be error: {:?}", err);
            }
            Err(nom::Err::Incomplete(needed)) => {
                panic!("Should not be incomplete. Needed {:?}", needed);
            }
            _ => {
                panic!("Unexpected behavior");
            }
        }

        let result = pgsql_parse_response(&buf[0..6]);
        assert!(result.is_err());

        let buf: &[u8] = &[ 0x52,
                            0x00, 0x00, 0x00, 0x07,
                            0x00, 0x00, 0x00, 0x03];
        let result = pgsql_parse_response(&buf);
        assert!(result.is_err());

        // - auth Ok
        let buf: &[u8] = &[0x52, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,0x00];
        let ok_res = PgsqlResponseMessage{
            message_type: PgsqlMessageType::AuthenticationOk(
                PgsqlAuthenticationMessage{
                    identifier: b'R',
                    length: 8,
                    auth_type: 0,
                    payload: None,
                })};
        let result = pgsql_parse_response(&buf);
        match result {
            Ok((remainder, message)) => {
                assert_eq!(message, ok_res);
                assert_eq!(remainder.len(), 0);
            }
            Err(nom::Err::Error((_remainder, err))) => {
                panic!("Should not be error {:?}", err);
            }
            Err(nom::Err::Incomplete(needed)) => {
                panic!("Should not be incomplete. Needed: {:?}", needed);
            }
            _ => {
                panic!("Unexpected behavior!");
            }
        }

        // TODO keep adding more messages
    }
}
