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

use std::{self, fmt, u16, u8};
use nom::character::streaming::alphanumeric1;
use nom::{number::streaming::{be_u8, be_u16, be_u32}};

// Dummy protocol major version, used for SSL, GSSAPI or Cancellation requests
pub const PGSQL_DUMMY_PROTO_MAJOR: u16 = 1234;

// Dummy protocol minor version, used for SSL encryption requests
pub const PGSQL_DUMMY_PROTO_MINOR_SSL: u16 = 5679;

#[repr(u8)]
#[derive(Debug, PartialEq)]
pub enum PgsqlSslResponseType {
    SslAccepted, // 'S'
    SslRejected,// 'N
    ErrorResponse, // 'E' // TODO I'm not sure if this should be here, since error responses may happen elsewhere, too
    InvalidIdentifier,
}

impl From<char> for PgsqlSslResponseType {
    fn from(identifier: char) -> PgsqlSslResponseType {
        match identifier {
            'S' => PgsqlSslResponseType::SslAccepted, 
            'N' => PgsqlSslResponseType::SslRejected,
            'E' => PgsqlSslResponseType::ErrorResponse, 
            _ => PgsqlSslResponseType::InvalidIdentifier,
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum PgsqlStartupMessageType {
    StartupMessage = 0,
    SslRequest = 1,
    GssApiRequest = 2,
}
 
impl fmt::Display for PgsqlStartupMessageType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            PgsqlStartupMessageType::StartupMessage => f.write_str("Startup Message"),
            PgsqlStartupMessageType::SslRequest => f.write_str("SSL Request"),
            PgsqlStartupMessageType::GssApiRequest => f.write_str("GSSAPI Request"),
        }  
    } 
}

#[derive(Debug, PartialEq)]
pub struct PgsqlGenericStartupMessage{
    pub message_type: PgsqlStartupMessageType, // TODO not the best approach, right.
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
            message_type: PgsqlStartupMessageType::SslRequest,
            length: len,
            proto_major: proto_major,
            proto_minor: proto_minor,
        })
));
 
#[derive(Debug, PartialEq)]
pub struct PgsqlSslResponse {
    message_type: PgsqlSslResponseType,
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
            message_type: PgsqlSslResponseType::from(identifier),
        })
    ));
#[derive(Debug, Eq, PartialEq)]
pub enum PgsqlErrorNoticeFieldTypes {
    SeverityLocalizable,
    SeverityNonLocalizable,
    CodeSqlStateCode,
    Message,
    Detail,
    Hint,
    Position,
    InternalPosition,
    InternalQuery,
    Where,
    SchemaName,
    TableName,
    ColumnName,
    DataType,
    ConstraintName,
    File,
    Line,
    Routine,
    TerminatorToken,
    UnknownFieldType,
}

impl From<char> for PgsqlErrorNoticeFieldTypes {
    fn from(identifier: char) -> PgsqlErrorNoticeFieldTypes {
        match identifier {
            'S' => PgsqlErrorNoticeFieldTypes::SeverityLocalizable,
            'V' => PgsqlErrorNoticeFieldTypes::SeverityNonLocalizable,
            'C' => PgsqlErrorNoticeFieldTypes::CodeSqlStateCode,
            'M' => PgsqlErrorNoticeFieldTypes::Message,
            'D' => PgsqlErrorNoticeFieldTypes::Detail,
            'H' => PgsqlErrorNoticeFieldTypes::Hint,
            'P' => PgsqlErrorNoticeFieldTypes::Position,
            'p' => PgsqlErrorNoticeFieldTypes::InternalPosition,
            'q' => PgsqlErrorNoticeFieldTypes::InternalQuery,
            'W' => PgsqlErrorNoticeFieldTypes::Where,
            's' => PgsqlErrorNoticeFieldTypes::SchemaName,
            't' => PgsqlErrorNoticeFieldTypes::TableName,
            'c' => PgsqlErrorNoticeFieldTypes::ColumnName,
            'd' => PgsqlErrorNoticeFieldTypes::DataType,
            'n' => PgsqlErrorNoticeFieldTypes::ConstraintName,
            'F' => PgsqlErrorNoticeFieldTypes::File,
            'L' => PgsqlErrorNoticeFieldTypes::Line,
            'R' => PgsqlErrorNoticeFieldTypes::Routine,
            '\u{0}' => PgsqlErrorNoticeFieldTypes::TerminatorToken,
            _ => PgsqlErrorNoticeFieldTypes::UnknownFieldType, // adding this because documentation says "rontends should silently ignore fields of unrecognized type."
        }
    }
}

impl From<u8> for PgsqlErrorNoticeFieldTypes {
    fn from(identifier: u8) -> PgsqlErrorNoticeFieldTypes {
        match identifier {
            b'S' => PgsqlErrorNoticeFieldTypes::SeverityLocalizable,
            b'V' => PgsqlErrorNoticeFieldTypes::SeverityNonLocalizable,
            b'C' => PgsqlErrorNoticeFieldTypes::CodeSqlStateCode,
            b'M' => PgsqlErrorNoticeFieldTypes::Message,
            b'D' => PgsqlErrorNoticeFieldTypes::Detail,
            b'H' => PgsqlErrorNoticeFieldTypes::Hint,
            b'P' => PgsqlErrorNoticeFieldTypes::Position,
            b'p' => PgsqlErrorNoticeFieldTypes::InternalPosition,
            b'q' => PgsqlErrorNoticeFieldTypes::InternalQuery,
            b'W' => PgsqlErrorNoticeFieldTypes::Where,
            b's' => PgsqlErrorNoticeFieldTypes::SchemaName,
            b't' => PgsqlErrorNoticeFieldTypes::TableName,
            b'c' => PgsqlErrorNoticeFieldTypes::ColumnName,
            b'd' => PgsqlErrorNoticeFieldTypes::DataType,
            b'n' => PgsqlErrorNoticeFieldTypes::ConstraintName,
            b'F' => PgsqlErrorNoticeFieldTypes::File,
            b'L' => PgsqlErrorNoticeFieldTypes::Line,
            b'R' => PgsqlErrorNoticeFieldTypes::Routine,
            b'\0' => PgsqlErrorNoticeFieldTypes::TerminatorToken,
            _ => PgsqlErrorNoticeFieldTypes::UnknownFieldType, // adding this because documentation says "frontends should silently ignore fields of unrecognized type."
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct PgsqlErrorNoticeMessageField<'a>{
    field_type: PgsqlErrorNoticeFieldTypes,
    field_value: Option<&'a[u8]>, // TODO Would it be better if this were a String or a &str?
}

// TODO not sure this is working... but idk
impl fmt::Display for PgsqlErrorNoticeMessageField<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut readable_field = "None";
        match (*self).field_value {
            Some(_) => {
                readable_field = std::str::from_utf8(self.field_value.unwrap()).unwrap_or("Not a UTF8 string!");
            }
            None => {},
        }
        write!(f, "{:?} {}", self.field_type, readable_field)
    } 
}

// Parse an error response with non-localizeable severity message.
// Possible values: ERROR, FATAL, or PANIC
named!(pub parse_error_response_severity<PgsqlErrorNoticeMessageField>,
    do_parse!(
        field_type: char!('V')
        >> field_value: alt!(tag!("ERROR") | tag!("FATAL") | tag!("PANIC"))
        >> tag!("\x00")
        >> (PgsqlErrorNoticeMessageField{
                field_type: PgsqlErrorNoticeFieldTypes::from(field_type),
                field_value: Some(field_value)
        })
    ));

named!(pub parse_error_response_code<PgsqlErrorNoticeMessageField>,
    do_parse!(
        field_type: char!('C')
        >> field_value: flat_map!(take!(6), call!(alphanumeric1))
        >> (PgsqlErrorNoticeMessageField{
            field_type: PgsqlErrorNoticeFieldTypes::CodeSqlStateCode,
            field_value: Some(field_value)
        })
    ));

named!(pub parse_error_response_field<PgsqlErrorNoticeMessageField>,
    switch!(peek!(be_u8),
        b'\0' => do_parse!(
            field_type: be_u8
            >> data: eof!()
            >> (PgsqlErrorNoticeMessageField{
                field_type: PgsqlErrorNoticeFieldTypes::from(field_type),
                field_value: None
            })
        ) |
        b'V' => call!(parse_error_response_severity) |
        b'C' => call!(parse_error_response_code) |
        b'S' | b'M' | b'D' | b'H' | b'P' | b'p' | b'q' |
        b'W' | b's' | b't' | b'c' | b'd' | b'n' | b'F' | b'L' | b'R' 
        => do_parse!(
            field_type: be_u8
            >> field_value: take_until1!("\x00")
            >> tag!("\x00")
            >> (PgsqlErrorNoticeMessageField{
                field_type: PgsqlErrorNoticeFieldTypes::from(field_type),
                field_value: Some(field_value),
            })
        ) |
        _ => do_parse!(
            field_type: be_u8 
            >> field_value: opt!(take_until1!("\x00"))
            >> tag!("\x00")
            >> (PgsqlErrorNoticeMessageField{
                field_type: PgsqlErrorNoticeFieldTypes::UnknownFieldType,
                field_value: field_value,
            })
        ))
);

named!(pub parse_error_notice_fields<&[u8], Vec<PgsqlErrorNoticeMessageField>>,
    do_parse!(
        data: many_till!(call!(parse_error_response_field), eof!())
        >> (data.0)
    ));

// Char-tag identifiers for Backend messages.
// Some of these char represent more than one message subtype.
// Such types are decoded by specific int values present in the payload
// right after the length field.
#[derive(Debug, Eq, PartialEq)]
pub enum PgsqlBeMessageType {
    BackendKeyData, //'K' - 0x4b
    ParameterStatus, //'S' - 0x53
    ParseCompletion, //'1' - 0x31
    BindCompletion, //'2' - 0x32
    CloseCompletion, //'3' - 0x33
    CommandCompletion, //'C' - 0x43
    ParameterDescription, //'t' - 0x74
    RowDescription, //'T' - 0x54
    DataRow, //'D' - 0x44
    EmptyQuery, //'I' - 0x49
    NoData, //'n' - 0x6e
    Error, //'E' - 0x45
    Notice, //'N' - 0x4e
    PortalSuspended, //'s' - 0x73
    ReadyForQuery, //'Z' - 0x5a
    Notification, //'A' - 0x41
    FunctionCallResponse, //'V' - 0x56
    CopyInResponse, //'G' - 0x47
    CopyOutResponse, //'H' - 0x48
    CopyData, // 'd' - 0x64
    CopyCompletion, //'c' - 0x63
    NegotiateProtocolVersion, // 'v' - 0x76
    UnknownMessageType,
}

impl From<u8> for PgsqlBeMessageType {
    fn from(identifier: u8) -> PgsqlBeMessageType {
        match identifier {
            b'K' => PgsqlBeMessageType::BackendKeyData,
            b'S' => PgsqlBeMessageType::ParameterStatus,
            b'1' => PgsqlBeMessageType::ParseCompletion,
            b'2' => PgsqlBeMessageType::BindCompletion,
            b'3' => PgsqlBeMessageType::CloseCompletion,
            b'C' => PgsqlBeMessageType::CommandCompletion,
            b't' => PgsqlBeMessageType::ParameterDescription,
            b'T' => PgsqlBeMessageType::RowDescription,
            b'D' => PgsqlBeMessageType::DataRow,
            b'I' => PgsqlBeMessageType::EmptyQuery,
            b'n' => PgsqlBeMessageType::NoData,
            b'E' => PgsqlBeMessageType::Error,
            b'N' => PgsqlBeMessageType::Notice,
            b's' => PgsqlBeMessageType::PortalSuspended,
            b'Z' => PgsqlBeMessageType::ReadyForQuery,
            b'A' => PgsqlBeMessageType::Notification,
            b'V' => PgsqlBeMessageType::FunctionCallResponse,
            b'G' => PgsqlBeMessageType::CopyInResponse,
            b'H' => PgsqlBeMessageType::CopyOutResponse,
            b'd' => PgsqlBeMessageType::CopyData,
            b'c' => PgsqlBeMessageType::CopyCompletion,
            b'v' => PgsqlBeMessageType::NegotiateProtocolVersion,
               _ => PgsqlBeMessageType::UnknownMessageType,
        }
    }
}

impl From<char> for PgsqlBeMessageType {
    fn from(identifier: char) -> PgsqlBeMessageType {
        match identifier {
            'K' => PgsqlBeMessageType::BackendKeyData,
            'S' => PgsqlBeMessageType::ParameterStatus,
            '1' => PgsqlBeMessageType::ParseCompletion,
            '2' => PgsqlBeMessageType::BindCompletion,
            '3' => PgsqlBeMessageType::CloseCompletion,
            'C' => PgsqlBeMessageType::CommandCompletion,
            't' => PgsqlBeMessageType::ParameterDescription,
            'T' => PgsqlBeMessageType::RowDescription,
            'D' => PgsqlBeMessageType::DataRow,
            'I' => PgsqlBeMessageType::EmptyQuery,
            'n' => PgsqlBeMessageType::NoData,
            'E' => PgsqlBeMessageType::Error,
            'N' => PgsqlBeMessageType::Notice,
            's' => PgsqlBeMessageType::PortalSuspended,
            'Z' => PgsqlBeMessageType::ReadyForQuery,
            'A' => PgsqlBeMessageType::Notification,
            'V' => PgsqlBeMessageType::FunctionCallResponse,
            'G' => PgsqlBeMessageType::CopyInResponse,
            'H' => PgsqlBeMessageType::CopyOutResponse,
            'd' => PgsqlBeMessageType::CopyData,
            'c' => PgsqlBeMessageType::CopyCompletion,
            'v' => PgsqlBeMessageType::NegotiateProtocolVersion,
              _ => PgsqlBeMessageType::UnknownMessageType,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct PgsqlErrorNoticeResponse<'a> {
    message_type: PgsqlBeMessageType,
    length: u32,
    message_body: Vec<PgsqlErrorNoticeMessageField<'a>>,
}

impl<'a> PgsqlErrorNoticeResponse<'a> {
    pub fn new() -> PgsqlErrorNoticeResponse<'a> {
        return PgsqlErrorNoticeResponse{
            message_type: PgsqlBeMessageType::UnknownMessageType,
            length: 0,
            message_body: Vec::new(),
        } 
    }
}

impl fmt::Display for PgsqlErrorNoticeResponse<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    } 
}

named!(pub parse_error_response<PgsqlErrorNoticeResponse>,
    do_parse!(
        message_type: char!('E')
        >> len: be_u32
        >> message: flat_map!(take!(len - 4), call!(parse_error_notice_fields))
        >> (PgsqlErrorNoticeResponse{
            message_type: message_type.into(),
            length: len,
            message_body: message,
        })
    ));

// Parse a request message
//
// TODO decide and parse message type based on what is in the protocol version
//  
// proto version major 1 | 2 | 3 -- Actual Startup Message (new connection)
// proto version min: 5678 -- Cancellation request
// proto version min: 5679 -- SSL encryption requests
// proto version min: 5680 -- GSSAPI request
named!(pub parse_request_message<PgsqlGenericStartupMessage>,
    do_parse!( //TODO add more message types here
        res: parse_ssl_request
        >> (res)
));

// Parse a request message
//
// For now, only parses SSL encryption responses, includding error messages
// Such error messages can happen in other circumstances, as well.
named!(pub parse_response_message<PgsqlSslResponse>,
    do_parse!( //TODO add more message types here
        message: parse_ssl_response
        >> (message)
));

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_parse_error_response_code() {
        let buf: &[u8] = &[0x43, 0x32, 0x38, 0x30, 0x30, 0x30, 0x00];
        let value_str = "28000".as_bytes();
        let ok_res = PgsqlErrorNoticeMessageField{
            field_type: PgsqlErrorNoticeFieldTypes::CodeSqlStateCode,
            field_value: Some(value_str),
        };
        let result = parse_error_response_code(&buf);
        assert!(result.is_ok());

        let (remainder, result) = parse_error_response_code(&buf).unwrap();
        assert_eq!(result, ok_res);
        assert_eq!(remainder.len(), 0);

        let result = parse_error_response_code(&buf[0..5]);
        assert!(result.is_err()); //TODO is there a better way to check for incomplete here? I didn't manage to... 
    }

    #[test]
    fn test_parse_pgsql_ssl_request() {
        
        let buf: &[u8] = &[0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f];
        let ok_res = PgsqlGenericStartupMessage {
            message_type: PgsqlStartupMessageType::SslRequest,
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
            message_type: PgsqlSslResponseType::SslAccepted,
        };

        let (_remainder, result) = parse_ssl_response(&input).unwrap();
        assert_eq!(result, ok_res);

        // 'N'
        let input: &[u8] = &[0x4e];

        let ok_res = PgsqlSslResponse {
            message_type: PgsqlSslResponseType::SslRejected,
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
            message_type: PgsqlSslResponseType::SslAccepted,
        };

        let (_remainder, result) = parse_response_message(&input).unwrap();
        assert_eq!(result, ok_res);

        // 'N'
        let input: &[u8] = &[0x4e];

        let ok_res = PgsqlSslResponse {
            message_type: PgsqlSslResponseType::SslRejected,
        };

        let (_remainder, result) = parse_response_message(&input).unwrap();
        assert_eq!(result, ok_res);
    }

    #[test]
    fn test_parse_error_response_severity() {
        // VFATAL
        let input: &[u8] = &[0x56, 0x46, 0x41, 0x54, 0x41, 0x4c, 0x00];

        let value_str = "FATAL".as_bytes();
        let ok_res = PgsqlErrorNoticeMessageField {
            field_type: PgsqlErrorNoticeFieldTypes::SeverityNonLocalizable,
            field_value: Some(value_str),
        };

        let (remainder, result) = parse_error_response_severity(&input).unwrap();
        assert_eq!(result, ok_res);
        assert_eq!(remainder.len(), 0);        
    }

    #[test]
    fn test_parse_error_response_field() {
        // VFATAL
        let input: &[u8] = &[0x56, 0x46, 0x41, 0x54, 0x41, 0x4c, 0x00];

        let value_str = "FATAL".as_bytes();
        let ok_res = PgsqlErrorNoticeMessageField {
            field_type: PgsqlErrorNoticeFieldTypes::SeverityNonLocalizable,
            field_value: Some(value_str),
        };

        let (remainder, result) = parse_error_response_field(&input).unwrap();
        assert_eq!(result, ok_res);
        assert_eq!(remainder.len(), 0); 

        // "Mno pg_hba.conf entry for replication connection from host "192.168.50.11", user "rep", SSL off "
        let input: &[u8] = &[0x4d, 0x6e, 0x6f, 0x20, 0x70, 0x67, 0x5f, 0x68,
                            0x62, 0x61, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x20, 
                            0x65, 0x6e, 0x74, 0x72, 0x79, 0x20, 0x66, 0x6f,
                            0x72, 0x20, 0x72, 0x65, 0x70, 0x6c, 0x69, 0x63,
                            0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x63, 0x6f,
                            0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e,
                            0x20, 0x66, 0x72, 0x6f, 0x6d, 0x20, 0x68, 0x6f,
                            0x73, 0x74, 0x20, 0x22, 0x31, 0x39, 0x32, 0x2e,
                            0x31, 0x36, 0x38, 0x2e, 0x35, 0x30, 0x2e, 0x31,
                            0x31, 0x22, 0x2c, 0x20, 0x75, 0x73, 0x65, 0x72,
                            0x20, 0x22, 0x72, 0x65, 0x70, 0x22, 0x2c, 0x20,
                            0x53, 0x53, 0x4c, 0x20, 0x6f, 0x66, 0x66, 0x00];

        let value_str = br#"no pg_hba.conf entry for replication connection from host "192.168.50.11", user "rep", SSL off"#;
        let ok_res = PgsqlErrorNoticeMessageField {
            field_type: PgsqlErrorNoticeFieldTypes::Message,
            field_value: Some(value_str),
        };

        let (remainder, result) = parse_error_response_field(&input).unwrap();
        assert_eq!(result, ok_res);
        assert_eq!(remainder.len(), 0);

        // if incomplete, here we should get an error
        let result = parse_error_response_field(&input[0..12]);
        assert!(result.is_err());

        // C28000
        let input: &[u8] = &[0x43, 0x32, 0x38, 0x30, 0x30, 0x30, 0x00];
        let value_str = "28000".as_bytes();
        let ok_res = PgsqlErrorNoticeMessageField{
            field_type: PgsqlErrorNoticeFieldTypes::CodeSqlStateCode,
            field_value: Some(value_str),
        };
        let (remainder, result) = parse_error_response_field(&input).unwrap();
        assert_eq!(result, ok_res);
        assert_eq!(remainder.len(), 0);
    }

    #[test]
    fn test_parse_error_notice_fields() {
        // test that, given a set of possible error/notice response message fields,
        // those are parsed accordingly
        // test that we'll get an error in case such stream isn't complete (preferrably, matching against)
        // incomplete, for that's what we want to inform to the API.
        let input: &[u8] = &[0x53, 0x46, 0x41, 0x54, 0x41, 0x4c, 0x00, 0x00];

        let field1 = PgsqlErrorNoticeMessageField{
            field_type: PgsqlErrorNoticeFieldTypes::SeverityLocalizable,
            field_value: Some(br#"FATAL"#),
        };
        let field2 = PgsqlErrorNoticeMessageField{
            field_type: PgsqlErrorNoticeFieldTypes::CodeSqlStateCode,
            field_value: Some(br#"28000"#),
        };
        let field3 = PgsqlErrorNoticeMessageField{
            field_type: PgsqlErrorNoticeFieldTypes::Message,
            field_value: Some(br#"no pg_hba.conf entry for replication connection from host "192.168.50.11", user "rep", SSL off"#),
        };
        let field4 = PgsqlErrorNoticeMessageField{
            field_type: PgsqlErrorNoticeFieldTypes::TerminatorToken,
            field_value: None,
        };

        let mut ok_res: Vec<PgsqlErrorNoticeMessageField> = Vec::new();
        ok_res.push(field1);
        ok_res.push(field4);

        let (remainder, result) = parse_error_notice_fields(&input).unwrap();
        assert_eq!(result, ok_res);
        assert_eq!(remainder.len(), 0);
        ok_res.pop();

        ok_res.push(field2);
        ok_res.push(field3);

        let field4 = PgsqlErrorNoticeMessageField{
            field_type: PgsqlErrorNoticeFieldTypes::TerminatorToken,
            field_value: None,
        };

        ok_res.push(field4);

        let input: &[u8] = &[0x53, 0x46, 0x41, 
        0x54, 0x41, 0x4c, 0x00, 0x43, 0x32, 0x38, 0x30,
        0x30, 0x30, 0x00, 0x4d, 0x6e, 0x6f, 0x20, 0x70,
        0x67, 0x5f, 0x68, 0x62, 0x61, 0x2e, 0x63, 0x6f,
        0x6e, 0x66, 0x20, 0x65, 0x6e, 0x74, 0x72, 0x79,
        0x20, 0x66, 0x6f, 0x72, 0x20, 0x72, 0x65, 0x70,
        0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e,
        0x20, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74,
        0x69, 0x6f, 0x6e, 0x20, 0x66, 0x72, 0x6f, 0x6d,
        0x20, 0x68, 0x6f, 0x73, 0x74, 0x20, 0x22, 0x31,
        0x39, 0x32, 0x2e, 0x31, 0x36, 0x38, 0x2e, 0x35,
        0x30, 0x2e, 0x31, 0x31, 0x22, 0x2c, 0x20, 0x75,
        0x73, 0x65, 0x72, 0x20, 0x22, 0x72, 0x65, 0x70,
        0x22, 0x2c, 0x20, 0x53, 0x53, 0x4c, 0x20, 0x6f,
        0x66, 0x66, 0x00, 0x00];

        let (remainder, result) = parse_error_notice_fields(&input).unwrap();
        assert_eq!(result, ok_res);
        assert_eq!(remainder.len(), 0);

        let input: &[u8] = &[0x53, 0x46, 0x41, 
        0x54, 0x41, 0x4c, 0x00, 0x43, 0x32, 0x38, 0x30,
        0x30, 0x30, 0x00, 0x4d, 0x6e, 0x6f, 0x20, 0x70,
        0x67, 0x5f, 0x68, 0x62, 0x61, 0x2e, 0x63, 0x6f,
        0x6e, 0x66, 0x20, 0x65, 0x6e, 0x74, 0x72, 0x79,
        0x20, 0x66, 0x6f, 0x72, 0x20, 0x72, 0x65, 0x70,
        0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e,
        0x20, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74,
        0x69, 0x6f, 0x6e, 0x20, 0x66, 0x72, 0x6f, 0x6d,
        0x20, 0x68, 0x6f, 0x73, 0x74, 0x20, 0x22, 0x31,
        0x39, 0x32, 0x2e, 0x31, 0x36, 0x38, 0x2e, 0x35,
        0x30, 0x2e, 0x31, 0x31, 0x22, 0x2c, 0x20, 0x75,
        0x73, 0x65, 0x72, 0x20, 0x22, 0x72, 0x65, 0x70,
        0x22, 0x2c, 0x20, 0x53, 0x53, 0x4c, 0x20, 0x6f,
        0x66, 0x66, 0x00, 0x46, 0x61, 0x75, 0x74, 0x68,
        0x2e, 0x63, 0x00, 0x4c, 0x34, 0x38, 0x31, 0x00,
        0x52, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x41,
        0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63,
        0x61, 0x74, 0x69, 0x6f, 0x6e, 0x00, 0x00];

        let result = parse_error_notice_fields(&input);
        assert!(result.is_ok());

        let result = parse_error_notice_fields(&input[0..12]);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_error_response() {
        // E   .SFATAL C28000 Mno pg_hba.conf entry for replication connection 
        // from host "192.168.50.11", user "rep", SSL off Fauth.c L481 
        // RClientAuthentication  
        let input: &[u8] = &[0x45, 0x00, 0x00, 0x00, 0x96, 0x53, 0x46, 0x41,
                            0x54, 0x41, 0x4c, 0x00, 0x43, 0x32, 0x38, 0x30,
                            0x30, 0x30, 0x00, 0x4d, 0x6e, 0x6f, 0x20, 0x70,
                            0x67, 0x5f, 0x68, 0x62, 0x61, 0x2e, 0x63, 0x6f,
                            0x6e, 0x66, 0x20, 0x65, 0x6e, 0x74, 0x72, 0x79,
                            0x20, 0x66, 0x6f, 0x72, 0x20, 0x72, 0x65, 0x70,
                            0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e,
                            0x20, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74,
                            0x69, 0x6f, 0x6e, 0x20, 0x66, 0x72, 0x6f, 0x6d,
                            0x20, 0x68, 0x6f, 0x73, 0x74, 0x20, 0x22, 0x31,
                            0x39, 0x32, 0x2e, 0x31, 0x36, 0x38, 0x2e, 0x35,
                            0x30, 0x2e, 0x31, 0x31, 0x22, 0x2c, 0x20, 0x75,
                            0x73, 0x65, 0x72, 0x20, 0x22, 0x72, 0x65, 0x70,
                            0x22, 0x2c, 0x20, 0x53, 0x53, 0x4c, 0x20, 0x6f,
                            0x66, 0x66, 0x00, 0x46, 0x61, 0x75, 0x74, 0x68,
                            0x2e, 0x63, 0x00, 0x4c, 0x34, 0x38, 0x31, 0x00,
                            0x52, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x41,
                            0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63,
                            0x61, 0x74, 0x69, 0x6f, 0x6e, 0x00, 0x00];

        let field1 = PgsqlErrorNoticeMessageField{
            field_type: PgsqlErrorNoticeFieldTypes::SeverityLocalizable,
            field_value: Some(br#"FATAL"#),
        };
        let field2 = PgsqlErrorNoticeMessageField{
            field_type: PgsqlErrorNoticeFieldTypes::CodeSqlStateCode,
            field_value: Some(br#"28000"#),
        };
        let field3 = PgsqlErrorNoticeMessageField{
            field_type: PgsqlErrorNoticeFieldTypes::Message,
            field_value: Some(br#"no pg_hba.conf entry for replication connection from host "192.168.50.11", user "rep", SSL off"#),
        };
        let field4 = PgsqlErrorNoticeMessageField{
            field_type: PgsqlErrorNoticeFieldTypes::File,
            field_value: Some(br#"auth.c"#),
        };
        let field5 = PgsqlErrorNoticeMessageField{
            field_type: PgsqlErrorNoticeFieldTypes::Line,
            field_value: Some(br#"481"#),
        }; 
        let field6 = PgsqlErrorNoticeMessageField {
            field_type: PgsqlErrorNoticeFieldTypes::Routine,
            field_value: Some(br#"ClientAuthentication"#),
        };
        let field7 = PgsqlErrorNoticeMessageField{
            field_type: PgsqlErrorNoticeFieldTypes::TerminatorToken,
            field_value: None,
        };

        let mut fields_vec: Vec<PgsqlErrorNoticeMessageField> = Vec::new();
        fields_vec.push(field1);
        fields_vec.push(field2);
        fields_vec.push(field3);
        fields_vec.push(field4);
        fields_vec.push(field5);
        fields_vec.push(field6);
        fields_vec.push(field7);

        let ok_res = PgsqlErrorNoticeResponse {
            message_type: PgsqlBeMessageType::from('E'),
            length: 150,
            message_body: fields_vec,
        };
        
        let (remainder, result) = parse_error_response(&input).unwrap();
        assert!(parse_error_response(&input).is_ok());
        assert_eq!(result, ok_res);
        assert_eq!(remainder.len(), 0);

        let result = parse_error_response(&input[0..53]);
        assert!(result.is_err());
    }
}
