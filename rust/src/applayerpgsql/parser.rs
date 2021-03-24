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
use nom::combinator::rest;
use nom::number::streaming::{be_u8, be_u16, be_u32};

pub const PGSQL_DUMMY_PROTO_MAJOR: u16 = 1234; // 0x04d2
pub const PGSQL_DUMMY_PROTO_MINOR_SSL: u16 = 5679; //0x162f
pub const _PGSQL_DUMMY_PROTO_MINOR_GSSAPI: u16 = 5680; // 0x1630

#[derive(Debug, PartialEq)]
struct PgsqlParameter {
    param_name: Vec<u8>,
    param_value: Vec<u8>,
}

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
        user: dbg_dmp!(call!(parse_user_param))
        >> database: dbg_dmp!(opt!(parse_database_param))
        >> rest: dbg_dmp!(rest)
        >> optional: cond!(rest.len() > 1, flat_map!(value!(rest), many0!(pgsql_parse_parameter)))//opt!(pgsql_parse_param)
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

#[non_exhaustive]
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

#[non_exhaustive]
#[derive(Debug, PartialEq)]
pub enum PgsqlMessageType {
    StartupMessage(PgsqlStartupPacket),
    SslRequest(PgsqlDummyStartupPacket),
    SslResponse(PgsqlSslResponse),
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
named!(pub pgsql_parse_startup_packet<PgsqlRequestMessage>,
    do_parse!(
        len: verify!(be_u32, |&x| x >= 8)
        >> proto_major: peek!(be_u16)
        >> message: flat_map!(take!(len - 4),
                    switch!(value!(proto_major),
                        1 | 2 | 3 => do_parse!(
                                        proto_major: be_u16
                                        >> proto_minor: be_u16
                                        >> params: dbg_dmp!(call!(pgsql_parse_startup_parameters))
                                        >> (PgsqlMessageType::StartupMessage(PgsqlStartupPacket{
                                                length: len,
                                                proto_major, 
                                                proto_minor, 
                                                params}))) |
                        PGSQL_DUMMY_PROTO_MAJOR => do_parse!(
                                        proto_major: be_u16
                                        >> proto_minor: be_u16
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

named!(pub pgsql_parse_request<PgsqlRequestMessage>,
    do_parse!(
        tag: peek!(be_u8)
        >> message: dbg_dmp!(switch!(value!(tag), 
                        b'\0' => call!(pgsql_parse_startup_packet) //|
                        // _ =>    call!(pgsql_parse_regular_packet))
                        ))
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

named!(pub pgsql_parse_response<PgsqlResponseMessage>,
    do_parse!(
        message: switch!(peek!(be_u8),
            // TODO This will need refactoring, must take into account length,
            // else this could take a parameters message as an SSL Response
            b'N' | b'S' => dbg_dmp!(call!(pgsql_parse_ssl_response)) //|
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

named!(pub _parse_message<String>,
       do_parse!(
           len:  map_res!(
                 map_res!(take_until!(":"), std::str::from_utf8), _parse_len) >>
           _sep: take!(1) >>
           msg:  take_str!(len) >>
               (
                   msg.to_string()
               )
       ));

#[cfg(test)]
mod tests {

    use digest::generic_array::typenum::private::IsEqualPrivate;
    use nom::*;
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

        let (remainder, result) = pgsql_parse_request(&buf).unwrap();

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
        // let result = pgsql_parse_request(&buf);
        // assert!(result.is_ok());
        let result = pgsql_parse_request(&buf);

        match result {
            Ok((remainder, message)) => {
                println!("{:?}", message);

                // there should be nothing left
                assert_eq!(remainder.len(), 0); // TODO FIX

                // this packet has protocol version 3.0, so it is valid
                // assert_eq!(message.is_valid(), true);
            }
            Err(nom::Err::Error((_remainder, err))) => {
                panic!("Result should not be an error: {:?}.", err);
            }
            Err(nom::Err::Incomplete(_)) => {
                println!("Incomplete!");
                panic!("Result should not have been incomplete.");
            }
            _ => {
                panic!("Unexpected behavior!");
            }
        }
    }

    #[test]
    fn test_parse_response() {
        // An SSL response - N
        let buf: &[u8] = &[0x4e];

        let ssl_response = PgsqlMessageType::SslResponse(PgsqlSslResponse::SslRejected);

        let response_ok = PgsqlResponseMessage{
            message_type: ssl_response,
        };

        let (remainder, result) = pgsql_parse_response(&buf).unwrap();
        assert_eq!(result, response_ok);

        // An SSL response - S
        let buf: &[u8] = &[0x53];

        let ssl_response = PgsqlMessageType::SslResponse(PgsqlSslResponse::SslAccepted);

        let response_ok = PgsqlResponseMessage{
            message_type: ssl_response,
        };

        let (remainder, result) = pgsql_parse_response(&buf).unwrap();
        assert_eq!(result, response_ok);

        // Not an SSL response
        let buf: &[u8] = &[0x52];

        let result = pgsql_parse_response(&buf);
        assert!(result.is_err());
    }

    /// Simple test of some valid data.
    #[test]
    fn test_parse_valid() {
        let buf = b"12:Hello World!4:Bye.";

        let result = _parse_message(buf);
        match result {
            Ok((remainder, message)) => {
                // Check the first message.
                assert_eq!(message, "Hello World!");

                // And we should have 6 bytes left.
                assert_eq!(remainder.len(), 6);
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
