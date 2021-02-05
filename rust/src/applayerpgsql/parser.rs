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

use std::{fmt, self, u16, u8};
use nom::{number::streaming::{be_u16, be_u32}};

// Dummy protocol major version, used for SSL, GSSAPI or Cancellation requests
pub const PGSQL_DUMMY_PROTO_MAJOR: u16 = 1234;

// Dummy protocol minor version, used for SSL encryption requests
pub const PGSQL_DUMMY_PROTO_MINOR_SSL: u16 = 5679;

pub const PGSQL_FLAG_SSL_NEGATIVE_RESPONSE: u8 = 'N' as u8;
pub const PGSQL_FLAG_SSL_POSITIVE_RESPONSE: u8 = 'S' as u8;

#[derive(Debug, PartialEq)]
pub enum StartupMessageType {
    StartupMessage = 0,
    SslRequest = 1,
    GssApiRequest = 2,
}
 
impl fmt::Display for StartupMessageType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            StartupMessageType::StartupMessage => f.write_str("Startup Message"),
            StartupMessageType::SslRequest => f.write_str("SSL Request"),
            StartupMessageType::GssApiRequest => f.write_str("GSSAPI Request"),
        }  
    } 
}

#[derive(Debug, PartialEq)]
pub struct PgsqlGenericStartupMessage{
    message_type: StartupMessageType,
    length: u32,
    proto_major: u16,
    proto_minor: u16,
}

impl fmt::Display for PgsqlGenericStartupMessage {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    } 
}
 
named!(pub parse_ssl_request<PgsqlGenericStartupMessage>,
    do_parse!(
        len: verify!(be_u32, |&x| x == 8 )
        >> proto_major: verify!(be_u16, |&x| x == PGSQL_DUMMY_PROTO_MAJOR )
        >> proto_minor: verify!(be_u16, |&x| x == PGSQL_DUMMY_PROTO_MINOR_SSL )
        >> (PgsqlGenericStartupMessage {
            message_type: StartupMessageType::SslRequest,
            length: len,
            proto_major: proto_major,
            proto_minor: proto_minor,
        })
));
 
#[derive(Debug, PartialEq)]
pub struct PgsqlSslResponse {
    message_type: u8,
}

impl fmt::Display for PgsqlSslResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    } 
}

named!(pub parse_ssl_response<PgsqlSslResponse>,
    do_parse!(
        identifier: alt!(char!('N') | char!('S'))
        >> (PgsqlSslResponse{
            message_type: identifier as u8,
        })
    ));

// TODO will I use this? Maybe not...
fn parse_len(input: &str) -> Result<u32, std::num::ParseIntError> {
    input.parse::<u32>()
}

// Parse a request message
//
// For now, only parses SSL encryption requests
named!(pub parse_request_message<PgsqlGenericStartupMessage>,
    do_parse!(
        res: parse_ssl_request
        >> (res)
));

// Parse a request message
//
// For now, only parses SSL encryption responses
named!(pub parse_response_message<PgsqlSslResponse>,
    do_parse!(
        message: parse_ssl_response
        >> (message)
));

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_parse_pgsql_ssl_request() {
        
        let buf: &[u8] = &[0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f];
        let ok_res = PgsqlGenericStartupMessage {
            message_type: StartupMessageType::SslRequest,
            length: 8,
            proto_major: PGSQL_DUMMY_PROTO_MAJOR,
            proto_minor: PGSQL_DUMMY_PROTO_MINOR_SSL,
        };
        let (_remainder, res) = parse_ssl_request(&buf).unwrap();
        assert_eq!(res, ok_res);

        let buf: &[u8] = &[0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x30];
        let res = parse_ssl_request(&buf);
        assert!(res.is_err());

        let buf: &[u8] = &[0x00, 0x00, 0x00, 0x01, 0x04, 0xd2, 0x16, 0x2f];
        let res = parse_ssl_request(&buf);
        assert!(res.is_err());

        let buf: &[u8] = &[0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16];
        let res = parse_ssl_request(&buf);
        assert!(res.is_err());
    }

    #[test]
    fn test_parse_pgsql_ssl_response() {
        // 'S'
        let input: &[u8] = &[0x53];

        let ok_res = PgsqlSslResponse {
            message_type: PGSQL_FLAG_SSL_POSITIVE_RESPONSE,
        };

        let (_remainder, result) = parse_ssl_response(&input).unwrap();
        assert_eq!(result, ok_res);

        // 'N'
        let input: &[u8] = &[0x4e];

        let ok_res = PgsqlSslResponse {
            message_type: PGSQL_FLAG_SSL_NEGATIVE_RESPONSE,
        };

        let (_remainder, result) = parse_ssl_response(&input).unwrap();
        assert_eq!(result, ok_res);

        // 'O' -- invalid option
        let input: &[u8] = &[0x4f];
        let result = parse_ssl_response(&input);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_request_message() {
        let buf: &[u8] = &[0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f];
        let res = parse_request_message(&buf);
        assert!(res.is_ok());

        let buf: &[u8] = &[0x00, 0x00, 0x00, 0x07, 0x04, 0xd2, 0x16, 0x2f];
        let res = parse_request_message(&buf);
        assert!(res.is_err());

        let buf: &[u8] = &[0x00, 0x00, 0x00, 0x07, 0x04, 0xd2, 0x16, 0x2f];
        let res = parse_request_message(&buf);
        assert!(res.is_err());
    }

    #[test]
    fn test_parse_response_message() {
        // 'S'
        let input: &[u8] = &[0x53];

        let ok_res = PgsqlSslResponse {
            message_type: PGSQL_FLAG_SSL_POSITIVE_RESPONSE,
        };

        let (_remainder, result) = parse_response_message(&input).unwrap();
        assert_eq!(result, ok_res);

        // 'N'
        let input: &[u8] = &[0x4e];

        let ok_res = PgsqlSslResponse {
            message_type: PGSQL_FLAG_SSL_NEGATIVE_RESPONSE,
        };

        let (_remainder, result) = parse_response_message(&input).unwrap();
        assert_eq!(result, ok_res);
    }
}
