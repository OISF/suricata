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
use nom::character::streaming::alphanumeric1;
use nom::number::streaming::{be_u8, be_u16, be_u32};

pub const PGSQL_DUMMY_PROTO_MAJOR: u16 = 1234; // 0x04d2
pub const PGSQL_DUMMY_PROTO_MINOR_SSL: u16 = 5679; //0x162f
pub const _PGSQL_DUMMY_PROTO_MINOR_GSSAPI: u16 = 5680; // 0x1630

#[derive(Debug, PartialEq)]
struct PgsqlParameter {
    param_name: Vec<u8>,
    param_value: Vec<u8>,
}

// TODO I think I can simplify this by having a vector of pgsqlparams
// (but I didn't manage to make this work without overcomplicating things...)
#[derive(Debug, PartialEq)]
pub struct PgsqlStartupParameters {
    user: PgsqlParameter,
    database: Option<PgsqlParameter>,
    optional_params: Option<Vec<PgsqlParameter>>,
}

impl fmt::Display for PgsqlStartupParameters {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, PartialEq)]
pub struct DummyStartupPacket {
    length: u32,
    proto_major: u16,
    proto_minor: u16,
}

#[derive(Debug, PartialEq)]
pub struct StartupPacket{
    length: u32,
    proto_major: u16,
    proto_minor: u16,
    params: PgsqlStartupParameters,
}

impl fmt::Display for StartupPacket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, PartialEq)]
pub struct RegularPacket{
    identifier: u8,
    length: u32,
    payload: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub struct PgsqlErrorNoticeMessageField{
    field_type: PgsqlErrorNoticeFieldTypes,
    field_value: Option<Vec<u8>>,
}

#[derive(Debug, PartialEq)]
pub struct ErrorNoticeMessage {
    identifier: u8,
    length: u32,
    message_body: Vec<PgsqlErrorNoticeMessageField>,
}

impl ErrorNoticeMessage {
    pub fn new(identifier: u8, length: u32) -> Self {
        ErrorNoticeMessage{
            identifier,
            length,
            message_body: Vec::new(),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum SslResponse {
    SslAccepted,
    SslRejected,
    InvalidResponse,
}

impl From<u8> for SslResponse {
    fn from(identifier: u8) -> Self {
        match identifier {
            b'S' => Self::SslAccepted,
            b'N' => Self::SslRejected,
            _ => Self::InvalidResponse,
        }
    }
}

impl From<char> for SslResponse {
    fn from(identifier: char) -> Self {
        match identifier {
            'S' => Self::SslAccepted,
            'N'=> Self::SslRejected,
            _ => Self::InvalidResponse,
        }
    }
}

// #[derive(Debug, PartialEq)]
// pub enum PgsqlBEMessage {
//     SslResponse(PgsqlSslResponse), // BE message
//     PasswordMessage(PgsqlRegularPacket), // FE message
//     AuthenticationGSS(PgsqlAuthenticationMessage), // BE Message
//     AuthenticationGSSContinue(PgsqlAuthenticationMessage), // BE Message
//     AuthenticationMD5Password(PgsqlAuthenticationMessage), // BE message
//     AuthenticationCleartextPassword(PgsqlAuthenticationMessage), // BE message
//     AuthenticationSSPI(PgsqlAuthenticationMessage), // BE Message
//     AuthenticationSASL(AuthenticationSASLMechanismMessage), // BE Message
//     AuthenticationSASLContinue(PgsqlAuthenticationMessage), // BE Message
//     AuthenticationSASLFinal(PgsqlAuthenticationMessage), // BE Message
//     AuthenticationOk(PgsqlAuthenticationMessage), // BE message
//     ErrorResponse(PgsqlErrorNoticeResponse), // BE message
//     NoticeResponse(PgsqlErrorNoticeResponse), // BE message
//     SASLInitialResponse(SASLInitialResponsePacket), // FE message
//     SASLResponse(PgsqlRegularPacket), // FE Message
//     ParameterStatus(ParameterStatusMessage), // BE message
//     BackendKeyData(BackendKeyDataMessage), // BE message
//     ReadyForQuery(ReadyForQueryMessage), // BE message
// }

// #[derive(Debug, PartialEq)]
// pub struct AuthenticationRequest {
//     length: u32,
//     auth_type: u32,
//     payload: Option<Vec<u8>>,
// }

#[derive(Debug, PartialEq)]
pub struct ParameterStatusMessage {
    identifier: u8,
    length: u32,
    param: PgsqlParameter,
}

#[derive(Debug, PartialEq)]
pub struct BackendKeyDataMessage {
    identifier: u8,
    length: u32,
    pub backend_pid: u32,
    pub secret_key: u32,
}

#[derive(Debug, PartialEq)]
pub struct ReadyForQueryMessage {
    identifier: u8,
    length: u32,
    transaction_status: u8,
}

#[derive(Debug, PartialEq)]
pub enum PgsqlBEMessage {
    SslResponse(SslResponse),
    ErrorResponse(ErrorNoticeMessage),
    NoticeResponse(ErrorNoticeMessage),
    AuthenticationOk(AuthenticationMessage),
    AuthenticationKerb5(AuthenticationMessage),
    AuthenticationCleartextPassword(AuthenticationMessage),
    AuthenticationMD5Password(AuthenticationMessage),
    AuthenticationGSS(AuthenticationMessage),
    AuthenticationSSPI(AuthenticationMessage),
    AuthenticationGSSContinue(AuthenticationMessage),
    AuthenticationSASL(AuthenticationSASLMechanismMessage),
    AuthenticationSASLContinue(AuthenticationMessage),
    AuthenticationSASLFinal(AuthenticationMessage),
    ParameterStatus(ParameterStatusMessage),
    BackendKeyData(BackendKeyDataMessage),
    ReadyForQuery(ReadyForQueryMessage),
}



impl fmt::Display for PgsqlBEMessage {
    fn fmt(&self, f:&mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl PgsqlBEMessage {
    pub fn get_message_type(&self) -> u8 {
        match self {
            PgsqlBEMessage::SslResponse(_) => 1,
            PgsqlBEMessage::ErrorResponse(_) => 2,
            PgsqlBEMessage::NoticeResponse(_) => 3,
            PgsqlBEMessage::AuthenticationOk(_) => 4,
            PgsqlBEMessage::AuthenticationKerb5(_) => 5,
            PgsqlBEMessage::AuthenticationCleartextPassword(_) => 6,
            PgsqlBEMessage::AuthenticationMD5Password(_) => 7,
            PgsqlBEMessage::AuthenticationGSS(_) => 8,
            PgsqlBEMessage::AuthenticationSSPI(_) => 9,
            PgsqlBEMessage::AuthenticationGSSContinue(_) => 10,
            PgsqlBEMessage::AuthenticationSASL(_) => 11,
            PgsqlBEMessage::AuthenticationSASLContinue(_) => 12,
            PgsqlBEMessage::AuthenticationSASLFinal(_) => 13,
            PgsqlBEMessage::ParameterStatus(_) => 14,
            PgsqlBEMessage::BackendKeyData(_) => 15,
            PgsqlBEMessage::ReadyForQuery(_) => 16,
        }
    }

    pub fn get_backendkey_info(&self) -> (u32, u32) {
        match self {
            PgsqlBEMessage::BackendKeyData(message) => {
                return (message.backend_pid, message.secret_key);
            }
            _ => (0, 0)
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
enum SASLAuthenticationMechanism {
    ScramSha256,
    ScramSha256Plus,
    // UnknownMechanism,
}

#[derive(Debug, PartialEq)]
pub enum PgsqlFEMessage {
    StartupMessage(StartupPacket),
    SslRequest(DummyStartupPacket),
    PasswordMessage(RegularPacket),
    SASLInitialResponse(SASLInitialResponsePacket),
    SASLResponse(RegularPacket),
}

impl fmt::Display for PgsqlFEMessage {
    fn fmt(&self, f:&mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl PgsqlFEMessage {
    pub fn is_ssl_request(&self) -> bool {
        match self {
            Self::SslRequest(DummyStartupPacket {
                length: 8,
                proto_major: PGSQL_DUMMY_PROTO_MAJOR,
                proto_minor: PGSQL_DUMMY_PROTO_MINOR_SSL,
            }) => true,
            _ => false,
        }
    }
}
#[derive(Debug, PartialEq)]
pub struct AuthenticationMessage {
    identifier: u8,
    length: u32,
    auth_type: u32,
    payload: Option<Vec<u8>>,
}

#[derive(Debug, PartialEq)]
pub struct SASLInitialResponsePacket {
    identifier: u8,
    length: u32,
    auth_mechanism: SASLAuthenticationMechanism,
    param_length: u32,
    sasl_param: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub struct AuthenticationSASLMechanismMessage {
    identifier: u8,
    length: u32,
    auth_type: u32,
    auth_mechanisms: Vec<SASLAuthenticationMechanism>,
}

#[derive(Debug, PartialEq)]
pub struct PgsqlRequestMessage {
    pub message_type: PgsqlBEMessage,
    // TODO I'm not sure whether length should be in the other structures, or here
}

impl fmt::Display for PgsqlRequestMessage {
    fn fmt(&self, f:&mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, PartialEq)]
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
            _ => PgsqlErrorNoticeFieldTypes::UnknownFieldType, // adding this because documentation says "frontends should silently ignore fields of unrecognized type."
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

named!(parse_sasl_initial_response_payload<(SASLAuthenticationMechanism, u32, Vec<u8>)>,
    do_parse!(
        sasl_mechanism: call!(parse_sasl_mechanism)
        >> param_length: be_u32
        // From RFC 5802 - the client-first-message will always start w/
        // 'n', 'y' or 'p', otherwise it's invalid, I think we should check that, at some point
        >> param: terminated!(take!(param_length), eof!())
        >> ((sasl_mechanism, param_length, param.to_vec()))
    ));

named!(pgsql_parse_sasl_initial_response<PgsqlFEMessage>,
    do_parse!(
        identifier: verify!(be_u8, |&x| x == b'p')
        >> length: verify!(be_u32, |&x| x > 8)
        >> payload: flat_map!(take!(length - 4), parse_sasl_initial_response_payload)
        >> (PgsqlFEMessage::SASLInitialResponse(
            SASLInitialResponsePacket {
            identifier,
            length,
            auth_mechanism: payload.0,
            param_length: payload.1,
            sasl_param: payload.2,
        }))
    ));

named!(pgsql_parse_sasl_response<PgsqlFEMessage>,
    do_parse!(
        identifier: verify!(be_u8, |&x| x == b'p')
        >> length: verify!(be_u32, |&x| x > 4)
        >> payload: flat_map!(take!(length - 4), rest)
        >> (PgsqlFEMessage::SASLResponse(
            RegularPacket {
            identifier,
            length,
            payload: payload.to_vec(),
        }))
    ));

// TODO keep extending, to parse more messages!
// Likely requires refactoring, to hide part of the logic in specialized parsers
// may also need better checking to ensure length is right
named!(pub pgsql_parse_startup_packet<PgsqlFEMessage>,
    do_parse!(
        len: verify!(be_u32, |&x| x >= 8)
        >> proto_major: peek!(be_u16)
        >> message: flat_map!(take!(len - 4),
                    switch!(value!(proto_major),
                        1 | 2 | 3 => do_parse!(
                                        proto_major: be_u16
                                        >> proto_minor: be_u16
                                        >> params: call!(pgsql_parse_startup_parameters)
                                        >> (PgsqlFEMessage::StartupMessage(StartupPacket{
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
                                        >> (PgsqlFEMessage::SslRequest(DummyStartupPacket{
                                            length: len,
                                            proto_major,
                                            proto_minor})))
                        ))
        >> (message)
    ));

// Password can be encrypted or in cleartext
named!(pgsql_parse_password_message<PgsqlFEMessage>,
    do_parse!(
        identifier: verify!(be_u8, |&x| x == b'p')
        >> length: verify!(be_u32, |&x| x >= 5) // a magic number to check that we have some data.
        >> password: flat_map!(take!(length - 4), take_until1!("\x00"))
        >> (PgsqlFEMessage::PasswordMessage(
                    RegularPacket{
                        identifier,
                        length,
                        payload: password.to_vec(),
            }))
    ));

// TODO messages that begin with 'p' but are not password ones are not parsed (yet) here
// we may need to bring some context logic to pgsql.rs, as content interpretation
// of such messages is context (transaction, I believe) dependent
named!(pub pgsql_parse_request<PgsqlFEMessage>,
    do_parse!(
        tag: peek!(be_u8)
        >> message: switch!(value!(tag),
                        b'\0' => call!(pgsql_parse_startup_packet) | // TODO this will probably be taken away from here.
                        b'p' =>  call!(pgsql_parse_password_message)
                )
        >> (message)
    ));

named!(pgsql_parse_authentication_message<PgsqlBEMessage>,
    do_parse!(
        identifier: verify!(be_u8, |&x| x == b'R')
        >> length: verify!(be_u32, |&x| x >= 8 )
        >> auth_type: be_u32
        >> message: flat_map!(take!(length - 8), switch!(value!(auth_type),
            0 => value!(PgsqlBEMessage::AuthenticationOk(
                    AuthenticationMessage {
                        identifier,
                        length,
                        auth_type,
                        payload: None,
                    }))  |
            3 => value!(PgsqlBEMessage::AuthenticationCleartextPassword(
                    AuthenticationMessage {
                        identifier,
                        length,
                        auth_type,
                        payload: None,
                    }))  |
            5 => do_parse!(
                salt: exact!(take!(4))
                >> (PgsqlBEMessage::AuthenticationMD5Password(
                        AuthenticationMessage {
                            identifier,
                            length,
                            auth_type,
                            payload: Some(salt.to_vec()),
                        }))
                ) |
            9 => value!(PgsqlBEMessage::AuthenticationSSPI(
                    AuthenticationMessage {
                        identifier,
                        length,
                        auth_type,
                        payload: None,
                    })) |
            // TODO - Question: For SASL, should I parse specific details of the challenge itself? (as seen in: https://github.com/launchbadge/sqlx/blob/master/sqlx-core/src/postgres/message/authentication.rs )
            10 => do_parse!(
                    auth_mechanisms: call!(parse_sasl_mechanisms)
                    >> (PgsqlBEMessage::AuthenticationSASL(
                        AuthenticationSASLMechanismMessage {
                            identifier,
                            length,
                            auth_type,
                            auth_mechanisms,
                        }))
                ) |
            11 => do_parse!(
                sasl_challenge: rest
                >> (PgsqlBEMessage::AuthenticationSASLContinue(
                    AuthenticationMessage {
                        identifier,
                        length,
                        auth_type,
                        payload: Some(sasl_challenge.to_vec())
                    }))
                ) |
            12 => do_parse!(
                signature: rest
                >> (PgsqlBEMessage::AuthenticationSASLFinal(
                    AuthenticationMessage {
                        identifier,
                        length,
                        auth_type,
                        payload: Some(signature.to_vec()),
                    }
                ))
            )
            // TODO - Question: Should I add here a pattern for unknown message types? If so, should I create PgsqlError, like SmbError?)
            // TODO add other authentication messages
        ))
        >> (message)
    ));


named!(parse_parameter_status_message<PgsqlBEMessage>,
    dbg_dmp!(do_parse!(
        identifier: verify!(be_u8, |&x| x == b'S')
        >> length: verify!(be_u32, |&x| x >= 4)
        >> param : flat_map!(take!(length - 4), pgsql_parse_parameter)
        >> (PgsqlBEMessage::ParameterStatus(ParameterStatusMessage {
            identifier,
            length,
            param,
        }))
    )));

// TODO This will need thinking and refactoring.
// I believe it must be called from elsewhere, not from
// parse_response, for that one already has other messages with the same identifier, so handling these two via events or smth, from pgsql.rs might work better
named!(pgsql_parse_ssl_response<PgsqlBEMessage>,
    do_parse!(
        tag: alt!(char!('N') | char!('S'))
        >> (PgsqlBEMessage::SslResponse(
            SslResponse::from(tag))
        )
    ));

named!(parse_backend_key_data_message<PgsqlBEMessage>,
    do_parse!(
        identifier: verify!(be_u8, |&x| x == b'K')
        >> length: verify!(be_u32, |&x| x == 12)
        >> pid: be_u32
        >> secret_key: be_u32
        >> (PgsqlBEMessage::BackendKeyData(
            BackendKeyDataMessage {
                identifier,
                length,
                backend_pid: pid,
                secret_key,
            }))
    ));

named!(parse_ready_for_query<PgsqlBEMessage>,
    do_parse!(
        identifier: verify!(be_u8, |&x| x == b'Z')
        >> length: verify!(be_u32, |&x| x == 5)
        >> status: verify!(be_u8, |&x| x == b'I' || x == b'T' || x == b'E')
        >> (PgsqlBEMessage::ReadyForQuery(
            ReadyForQueryMessage {
                identifier,
                length,
                transaction_status: status,
            }))
    ));

// TODO - Question - although this works with the unittests, if I run the tests w/
// dbg_dmp I can see that there are errors for the tag!("\x00") cases.
// I haven't managed to make things work with other structures, though.
// are these errors an issue?
named!(parse_sasl_mechanism<SASLAuthenticationMechanism>,
    do_parse!(
        mechanism: alt!(
            terminated!(tag!("SCRAM-SHA-256-PLUS"), tag!("\x00")) => { |_| SASLAuthenticationMechanism::ScramSha256Plus} |
            terminated!(tag!("SCRAM-SHA-256"), tag!("\x00")) => { |_| SASLAuthenticationMechanism::ScramSha256}
        )
        >> (mechanism)
    ));

named!(parse_sasl_mechanisms<Vec<SASLAuthenticationMechanism>>,
    terminated!(many1!(parse_sasl_mechanism), tag!("\x00")));


named!(pub parse_error_response_code<PgsqlErrorNoticeMessageField>,
    do_parse!(
        field_type: char!('C')
        >> field_value: flat_map!(take!(6), call!(alphanumeric1))
        >> (PgsqlErrorNoticeMessageField{
            field_type: PgsqlErrorNoticeFieldTypes::CodeSqlStateCode,
            field_value: Some(field_value.to_vec())
        })
    ));

// Parse an error response with non-localizeable severity message.
// Possible values: ERROR, FATAL, or PANIC
named!(pub parse_error_response_severity<PgsqlErrorNoticeMessageField>,
    do_parse!(
        field_type: char!('V')
        >> field_value: alt!(tag!("ERROR") | tag!("FATAL") | tag!("PANIC"))
        >> tag!("\x00")
        >> (PgsqlErrorNoticeMessageField{
                field_type: PgsqlErrorNoticeFieldTypes::from(field_type),
                field_value: Some(field_value.to_vec())
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
                field_value: Some(field_value.to_vec()),
            })
        ) |
        _ => do_parse!(
            field_type: be_u8
            >> field_value: opt!(take_until1!("\x00"))
            >> tag!("\x00")
            >> (PgsqlErrorNoticeMessageField{
                field_type: PgsqlErrorNoticeFieldTypes::UnknownFieldType,
                field_value: Some(field_value.unwrap().to_vec()),
            })
        ))
);

named!(pub parse_error_notice_fields<Vec<PgsqlErrorNoticeMessageField>>,
    do_parse!(
        data: many_till!(call!(parse_error_response_field), eof!())
        >> (data.0)
    ));

named!(pgsql_parse_error_response<PgsqlBEMessage>,
    do_parse!(
        identifier: verify!(be_u8, |&x| x == b'E')
        >> length: verify!(be_u32, |&x| x > 10)
        >> message_body: flat_map!(take!(length - 4), call!(parse_error_notice_fields))
        >> (PgsqlBEMessage::ErrorResponse(
            ErrorNoticeMessage {
                identifier,
                length,
                message_body,
            }))
    ));

named!(pgsql_parse_notice_response<PgsqlBEMessage>,
    do_parse!(
        identifier: verify!(be_u8, |&x| x == b'N')
        >> length: verify!(be_u32, |&x| x > 10)
        >> message_body: flat_map!(take!(length - 4), call!(parse_error_notice_fields))
        >> (PgsqlBEMessage::NoticeResponse(
            ErrorNoticeMessage {
                identifier,
                length,
                message_body,
            }))
    ));

named!(pub pgsql_parse_response<PgsqlBEMessage>,
    do_parse!(
        message: switch!(peek!(be_u8),
            b'E' => call!(pgsql_parse_error_response) |
            b'K' => call!(parse_backend_key_data_message) |
            b'N' => call!(pgsql_parse_notice_response) |
            b'R' => call!(pgsql_parse_authentication_message) |
            b'S' => call!(parse_parameter_status_message) |
            b'Z' => call!(parse_ready_for_query)
            // _ => {} // TODO question should I add an unknown message type here, or maybe an error?
        )
        >> (message)
    ));

// TODO decide whether to keep this or not. If I have to parse length in more
// than one place, it does sound reasonable,
// to avoid writing take!(len - 4) everywhere and any possible related mistakes...
fn _parse_len(input: &str) -> Result<u32, std::num::ParseIntError> {
    input.parse::<u32>()
}

#[cfg(test)]
mod tests {

    use super::*;
    use nom::Needed::Size;

    #[test]
    fn test_parse_request() {
        // An SSLRequest
        let buf: &[u8] = &[0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f];
        let ssl_request = DummyStartupPacket {
            length: 8,
            proto_major: PGSQL_DUMMY_PROTO_MAJOR,
            proto_minor: PGSQL_DUMMY_PROTO_MINOR_SSL,
        };
        let request_ok = PgsqlFEMessage::SslRequest(ssl_request);

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
        let expected_result = PgsqlFEMessage::StartupMessage(
                StartupPacket{
                    length: 38,
                    proto_major: 3,
                    proto_minor: 0,
                    params,
        });
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
        let expected_result = PgsqlFEMessage::StartupMessage(
                StartupPacket{
                    length: 19,
                    proto_major: 3,
                    proto_minor: 0,
                    params,
                });
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
        let ok_result = PgsqlFEMessage::PasswordMessage(
                RegularPacket {
                    identifier: b'p',
                    length: 40,
                    payload: br#"md5ceffc01dcde7541829deef6b5e9c9142"#.to_vec(),
                });
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
    fn test_parse_error_response_code() {
        let buf: &[u8] = &[0x43, 0x32, 0x38, 0x30, 0x30, 0x30, 0x00];
        let value_str = "28000".as_bytes();
        let ok_res = PgsqlErrorNoticeMessageField{
            field_type: PgsqlErrorNoticeFieldTypes::CodeSqlStateCode,
            field_value: Some(value_str.to_vec()),
        };
        let result = parse_error_response_code(&buf);
        assert!(result.is_ok());

        let (remainder, result) = parse_error_response_code(&buf).unwrap();
        assert_eq!(result, ok_res);
        assert_eq!(remainder.len(), 0);

        let result = parse_error_response_code(&buf[0..5]);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_error_response_field() {
        // VFATAL
        let input: &[u8] = &[0x56, 0x46, 0x41, 0x54, 0x41, 0x4c, 0x00];

        let value_str = "FATAL".as_bytes();
        let ok_res = PgsqlErrorNoticeMessageField {
            field_type: PgsqlErrorNoticeFieldTypes::SeverityNonLocalizable,
            field_value: Some(value_str.to_vec()),
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
            field_value: Some(value_str.to_vec()),
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
            field_value: Some(value_str.to_vec()),
        };
        let (remainder, result) = parse_error_response_field(&input).unwrap();
        assert_eq!(result, ok_res);
        assert_eq!(remainder.len(), 0);
    }

    // After sending AuthenticationOk, the backend will send a series of messages with parameters, a backend key message, and, finally a ready for query message
    #[test]
    fn test_parse_startup_phase_wrapup() {
        let buf: &[u8] = &[
                            0x53,
                            0x00, 0x00, 0x00, 0x1a,
                            0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69,
                            0x6f, 0x6e, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x00,
                            0x70, 0x73, 0x71, 0x6c, 0x00];
        let ok_res = PgsqlBEMessage::ParameterStatus(ParameterStatusMessage {
                    identifier: b'S',
                    length: 26,
                    param: PgsqlParameter {
                        param_name:br#"application_name"#.to_vec(),
                        param_value:br#"psql"#.to_vec(),
                    }});
        let (_remainder, result) = parse_parameter_status_message(&buf).unwrap();
        assert_eq!(result, ok_res);

        let ok_res = PgsqlBEMessage::ParameterStatus(
                ParameterStatusMessage {
                    identifier: b'S',
                    length: 26,
                    param: PgsqlParameter {
                        param_name:br#"application_name"#.to_vec(),
                        param_value:br#"psql"#.to_vec(),
                    }});

                    let result = pgsql_parse_response(&buf);
        match result {
            Ok((_remainder, message)) => {
                assert_eq!(message, ok_res);
            }
            Err(nom::Err::Error((remainder, err))) => {
                panic!("Shouldn't be err {:?}, expected Ok(_). Remainder is: {:?} ", err, remainder);
            }
            Err(nom::Err::Incomplete(needed)) => {
                panic!("Should not be incomplete {:?}, expected Ok(_)", needed);
            }
            _ => panic!("Unexpected behavior, expected Ok(_)")
        }

        let buf: &[u8] = &[
                            0x53,
                            0x00, 0x00, 0x00, 0x19,
                            0x69, 0x6e, 0x74, 0x65, 0x67, 0x65, 0x72, 0x5f, 0x64, 0x61, 0x74, 0x65, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x00,
                            0x6f, 0x6e, 0x00];
        let result = parse_parameter_status_message(&buf);
        assert!(result.is_ok());

        let buf: &[u8] = &[
                            0x4b,
                            0x00, 0x00, 0x00, 0x0c,
                            0x00, 0x00, 0x00, 0x3d,
                            0xbb, 0xe1, 0xe1, 0xae];

        let result = parse_backend_key_data_message(&buf);
        assert!(result.is_ok());

        let buf: &[u8] = &[
                            0x5a,
                            0x00, 0x00, 0x00, 0x05,
                            0x49
        ];
        let result = parse_ready_for_query(&buf);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_error_notice_fields() {
        let input: &[u8] = &[0x53, 0x46, 0x41, 0x54, 0x41, 0x4c, 0x00, 0x00];

        let field1 = PgsqlErrorNoticeMessageField{
            field_type: PgsqlErrorNoticeFieldTypes::SeverityLocalizable,
            field_value: Some(br#"FATAL"#.to_vec()),
        };
        let field2 = PgsqlErrorNoticeMessageField{
            field_type: PgsqlErrorNoticeFieldTypes::CodeSqlStateCode,
            field_value: Some(br#"28000"#.to_vec()),
        };
        let field3 = PgsqlErrorNoticeMessageField{
            field_type: PgsqlErrorNoticeFieldTypes::Message,
            field_value: Some(br#"no pg_hba.conf entry for replication connection from host "192.168.50.11", user "rep", SSL off"#.to_vec()),
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
        match result {
            Ok((_remainder, _message)) =>
                panic!("Result should not be ok, but incomplete."),

            Err(nom::Err::Error((_remainder, err))) => {
                panic!("Shouldn't be error: {:?}", err);
            }
            Err(nom::Err::Incomplete(needed)) => {
                    assert_eq!(needed, Size(6));
                }
            _ => panic!("Unexpected behavior.")
        }
    }

    #[test]
    fn test_parse_error_notice_response() {
        // declare test case buffer
        let buf: &[u8] = &[
        /* identifier */    0x45,
        /* length */        0x00, 0x00, 0x00, 0x96,
        /* Severity */      0x53, 0x46, 0x41, 0x54, 0x41, 0x4c, 0x00,
        /* Code */          0x43, 0x32, 0x38, 0x30, 0x30, 0x30, 0x00,
        /* Message */       0x4d, 0x6e, 0x6f, 0x20, 0x70, 0x67, 0x5f, 0x68, 0x62,
                            0x61, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x20, 0x65, 0x6e, 0x74, 0x72, 0x79, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x72, 0x65, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74,
                            0x69, 0x6f, 0x6e, 0x20, 0x66, 0x72, 0x6f, 0x6d, 0x20, 0x68, 0x6f, 0x73, 0x74, 0x20, 0x22, 0x31, 0x39, 0x32, 0x2e, 0x31, 0x36, 0x38, 0x2e, 0x35, 0x30, 0x2e, 0x31, 0x31, 0x22, 0x2c, 0x20, 0x75, 0x73, 0x65, 0x72, 0x20, 0x22, 0x72, 0x65, 0x70, 0x22, 0x2c, 0x20, 0x53, 0x53, 0x4c, 0x20, 0x6f, 0x66, 0x66, 0x00,
        /* File */          0x46, 0x61, 0x75, 0x74, 0x68, 0x2e, 0x63, 0x00,
        /* Line */          0x4c, 0x34, 0x38, 0x31, 0x00,
        /* Routine */       0x52, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x41,
                            0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63,
                            0x61, 0x74, 0x69, 0x6f, 0x6e, 0x00, 0x00];
        // declare expected result

        let field1 = PgsqlErrorNoticeMessageField {
            field_type: PgsqlErrorNoticeFieldTypes::SeverityLocalizable,
            field_value: Some(br#"FATAL"#.to_vec()),
        };
        let field2 = PgsqlErrorNoticeMessageField {
            field_type: PgsqlErrorNoticeFieldTypes::CodeSqlStateCode,
            field_value: Some(br#"28000"#.to_vec()),
        };
        let field3 = PgsqlErrorNoticeMessageField {
            field_type: PgsqlErrorNoticeFieldTypes::Message,
            field_value: Some(br#"no pg_hba.conf entry for replication connection from host "192.168.50.11", user "rep", SSL off"#.to_vec()),
        };
        let field4 = PgsqlErrorNoticeMessageField {
            field_type: PgsqlErrorNoticeFieldTypes::File,
            field_value: Some(br#"auth.c"#.to_vec()),
        };
        let field5 = PgsqlErrorNoticeMessageField {
            field_type: PgsqlErrorNoticeFieldTypes::Line,
            field_value: Some(br#"481"#.to_vec()),
        };
        let field6 = PgsqlErrorNoticeMessageField {
            field_type: PgsqlErrorNoticeFieldTypes::Routine,
            field_value: Some(br#"ClientAuthentication"#.to_vec()),
        };
        let field7 = PgsqlErrorNoticeMessageField {
            field_type: PgsqlErrorNoticeFieldTypes::TerminatorToken,
            field_value: None,
        };

        let mut payload = ErrorNoticeMessage::new(b'E', 150);
        payload.message_body.push(field1);
        payload.message_body.push(field2);
        payload.message_body.push(field3);
        payload.message_body.push(field4);
        payload.message_body.push(field5);
        payload.message_body.push(field6);
        payload.message_body.push(field7);

        let ok_res = PgsqlBEMessage::ErrorResponse(payload);

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

        let result_incomplete = pgsql_parse_response(&buf[0..22]);
        match result_incomplete {
            Err(nom::Err::Incomplete(needed)) => {
                // parser first tries to take whole length (is )150 - 4), but buffer is incomplete
                assert_eq!(needed, Size(146));
            }
            _ => {
                panic!("Unexpected behavior. Should be incomplete.");
            }
        }

        //repeat for different case-scenarios:
        // - message is valid
        // some invalid character
    }

    #[test]
    fn test_parse_sasl_authentication_message() {
        let buf: &[u8] = &[
            /* identifier R */      0x52,
            /* length */            0x00, 0x00, 0x00, 0x1c,
            /* auth_type */         0x00, 0x00, 0x00, 0x0a,
            /* SCRAM-SHA-256-PLUS */0x53, 0x43, 0x52, 0x41, 0x4d, 0x2d, 0x53, 0x48,
                                    0x41, 0x2d, 0x32, 0x35, 0x36, 0x2d, 0x50, 0x4c,
                                    0x55,0x53, 0x00, 0x00];
            let mechanism = vec![SASLAuthenticationMechanism::ScramSha256Plus];
            let ok_res = PgsqlBEMessage::AuthenticationSASL(
                AuthenticationSASLMechanismMessage {
                    identifier: b'R',
                    length: 28,
                    auth_type: 10,
                    auth_mechanisms: mechanism,
                });

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

        let buf: &[u8] = &[
        /* identifier R */      0x52,
        /* length */            0x00, 0x00, 0x00, 0x2a,
        /* auth_type */         0x00, 0x00, 0x00, 0x0a,
        /* SCRAM-SHA-256-PLUS */0x53, 0x43, 0x52, 0x41, 0x4d, 0x2d, 0x53, 0x48,
                                0x41, 0x2d, 0x32, 0x35, 0x36, 0x2d, 0x50, 0x4c,
                                0x55,0x53, 0x00,
        /* SCRAM-SHA-256 */     0x53, 0x43, 0x52, 0x41, 0x4d, 0x2d, 0x53, 0x48,
                                0x41, 0x2d, 0x32, 0x35, 0x36, 0x00, 0x00];
        let mechanism = vec![SASLAuthenticationMechanism::ScramSha256Plus, SASLAuthenticationMechanism::ScramSha256];
        let ok_res = PgsqlBEMessage::AuthenticationSASL(
            AuthenticationSASLMechanismMessage {
                identifier: b'R',
                length: 42,
                auth_type: 10,
                auth_mechanisms: mechanism,
            });

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

        let incomplete_result = pgsql_parse_response(&buf[0..27]);
        match incomplete_result {
            Ok((_remainder, _message)) =>
            panic!("Should not be Ok(_), expected Incomplete!"),
            Err(nom::Err::Error((_remainder, err))) =>
            panic!("Should not be error {:?}, expected Incomplete!", err),
            Err(nom::Err::Incomplete(needed)) => assert_eq!(needed, Size(34)),
            _ => panic!("Unexpected behavior, expected Incomplete.")
        }
    }

    #[test]
    fn test_parse_sasl_continue_authentication_message() {
        // As found in: https://blog.hackeriet.no/Better-password-hashing-in-PostgreSQL/
        let buf: &[u8] = &[
        /* 'R' */           0x52,
        /* 92 */            0x00, 0x00, 0x00, 0x5c,
        /* 11 */            0x00, 0x00, 0x00, 0x0b,
        /* challenge data*/ 0x72, 0x3d, 0x2f, 0x7a, 0x2b, 0x67, 0x69, 0x5a, 0x69,
                            0x54, 0x78, 0x41, 0x48, 0x37, 0x72, 0x38, 0x73, 0x4e,
                            0x41, 0x65, 0x48, 0x72, 0x37, 0x63, 0x76, 0x70, 0x71,
                            0x56, 0x33, 0x75, 0x6f, 0x37, 0x47, 0x2f, 0x62, 0x4a,
                            0x42, 0x49, 0x4a, 0x4f, 0x33, 0x70, 0x6a, 0x56, 0x4d,
                            0x37, 0x74, 0x33, 0x6e, 0x67, 0x2c, 0x73, 0x3d, 0x34,
                            0x55, 0x56, 0x36, 0x38, 0x62, 0x49, 0x6b, 0x43, 0x38,
                            0x66, 0x39, 0x2f, 0x58, 0x38, 0x78, 0x48, 0x37, 0x61,
                            0x50, 0x68, 0x67, 0x3d, 0x3d, 0x2c, 0x69, 0x3d, 0x34,
                            0x30, 0x39, 0x36];

        let ok_res = PgsqlBEMessage::AuthenticationSASLContinue(
            AuthenticationMessage {
                identifier: b'R',
                length: 92,
                auth_type: 11,
                payload: Some(br#"r=/z+giZiTxAH7r8sNAeHr7cvpqV3uo7G/bJBIJO3pjVM7t3ng,s=4UV68bIkC8f9/X8xH7aPhg==,i=4096"#.to_vec()),
        });

        let result = pgsql_parse_response(&buf);
        match result {
            Ok((remainder, message)) => {
                assert_eq!(message, ok_res);
                assert_eq!(remainder.len(), 0);
            }
            Err(nom::Err::Error((_remainder, err))) => panic!("Shouldn't be error {:?} expected Ok(_)", err),
            Err(nom::Err::Incomplete(needed)) => panic!("shouldn't be incomplete {:?}, expected Ok(_)", needed),
            _ => panic!("Unexpected behavior, expected Ok(_)")
        }

        let result_incomplete = pgsql_parse_response(&buf[0..31]);
        match result_incomplete {
            Ok((_remainder, _message)) => panic!("Should not be Ok(_), expected Incomplete!"),
            Err(nom::Err::Error((_remainder, err))) => panic!("Shouldn't be error {:?} expected Incomplete!", err),
            Err(nom::Err::Incomplete(needed)) => {
                assert_eq!(needed, Size(84));
            }
            _ => panic!("Unexpected behavior, expected Ok(_)")
        }
    }

    #[test]
    fn test_parse_sasl_final_authentication_message() {
        let buf: &[u8] = &[
        /* R */             0x52,
        /* 54 */            0x00, 0x00, 0x00, 0x36,
        /* 12 */            0x00, 0x00, 0x00, 0x0c,
        /* signature */     0x76, 0x3d, 0x64, 0x31, 0x50, 0x58, 0x61, 0x38, 0x54,
                            0x4b, 0x46, 0x50, 0x5a, 0x72, 0x52, 0x33, 0x4d, 0x42,
                            0x52, 0x6a, 0x4c, 0x79, 0x33, 0x2b, 0x4a, 0x36, 0x79,
                            0x78, 0x72, 0x66, 0x77, 0x2f, 0x7a, 0x7a, 0x70, 0x38,
                            0x59, 0x54, 0x39, 0x65, 0x78, 0x56, 0x37, 0x73, 0x38, 0x3d];
        let ok_res = PgsqlBEMessage::AuthenticationSASLFinal(
            AuthenticationMessage {
                identifier: b'R',
                length: 54,
                auth_type: 12,
                payload: Some(br#"v=d1PXa8TKFPZrR3MBRjLy3+J6yxrfw/zzp8YT9exV7s8="#.to_vec()),
        });

        let result = pgsql_parse_response(&buf);
        match result {
            Ok((remainder, message)) => {
                assert_eq!(message, ok_res);
                assert_eq!(remainder.len(), 0);
            }
            Err(nom::Err::Error((_remainder, err))) => {
                panic!("Shouldn't be error {:?}, expected Ok(_)", err);
            }
            Err(nom::Err::Incomplete(needed)) => {
                panic!("Shouldn't be incomplete {:?}, expected OK(_)", needed);
            }
            _ => panic!("Unexpected behavior, expected Ok(_)"),
        }

        let result_incomplete = pgsql_parse_response(&buf[0..34]);
        match result_incomplete {
            Err(nom::Err::Incomplete(needed)) => {
                assert_eq!(needed, Size(46));
            }
            _ => panic!("Unexpected behavior, expected incomplete."),
        }

        let result_err = pgsql_parse_response(&buf[1..34]);
        match result_err {
            Err(nom::Err::Error((_remainder, err))) => {
                assert_eq!(err, nom::error::ErrorKind::Switch);
            }
            _ => panic!("Unexpected behavior, expected Error"),
        }
    }

    // Test messages with fixed formats, like AuthenticationSSPI
    #[test]
    fn test_parse_simple_authentication_requests() {
        let buf: &[u8] = &[
        /* R */             0x52,
        /* 8 */             0x00, 0x00, 0x00, 0x08,
        /* 9 */             0x00, 0x00, 0x00, 0x09];

        let ok_res = PgsqlBEMessage::AuthenticationSSPI(
                AuthenticationMessage {
                    identifier: b'R',
                    length: 8,
                    auth_type: 9,
                    payload: None,
                });

        let (_remainder, result) = pgsql_parse_response(&buf).unwrap();
        assert_eq!(result, ok_res);
    }

    #[test]
    fn test_parse_sasl_frontend_messages() {
        // SASL Initial Response (as seen in https://blog.hackeriet.no/Better-password-hashing-in-PostgreSQL/)
        let buf: &[u8] = &[
        /* p */             0x70,
        /* 54 */            0x00, 0x00, 0x00, 0x36,
        /* sasl mechanism */0x53, 0x43, 0x52, 0x41, 0x4d, 0x2d, 0x53, 0x48, 0x41,
                            0x2d, 0x32, 0x35, 0x36, 0x00,
        /* 32 */            0x00, 0x00, 0x00, 0x20,
        /* FE 1st msg */    0x6e, 0x2c, 0x2c, 0x6e, 0x3d, 0x2c, 0x72, 0x3d, 0x2f,
                            0x7a, 0x2b, 0x67, 0x69, 0x5a, 0x69, 0x54, 0x78, 0x41,
                            0x48, 0x37, 0x72, 0x38, 0x73, 0x4e, 0x41, 0x65, 0x48, 0x72, 0x37, 0x63, 0x76, 0x70];
        let ok_res = PgsqlFEMessage::SASLInitialResponse(
            SASLInitialResponsePacket {
                identifier: b'p',
                length: 54,
                auth_mechanism: SASLAuthenticationMechanism::ScramSha256,
                param_length: 32,
                sasl_param: br#"n,,n=,r=/z+giZiTxAH7r8sNAeHr7cvp"#.to_vec(),
            });

        let result = pgsql_parse_sasl_initial_response(&buf);
        match result {
            Ok((remainder, message)) => {
                assert_eq!(message, ok_res);
                assert_eq!(remainder.len(), 0);
            }
            Err(nom::Err::Error((_remainder, err))) => panic!("Shouldn't be error {:?}, expected Ok(_)", err),
            Err(nom::Err::Incomplete(needed)) => panic!("Shouldn't be incomplete: ?{:?}, expected Ok(_)", needed),
            _ => panic!("Unexpected behavior, expected Ok(_)"),
        }

        let buf: &[u8] = &[
        /* p */             0x70,
        /* 108 */           0x00, 0x00, 0x00, 0x6c,
        /* final msg*/      0x63, 0x3d, 0x62, 0x69, 0x77, 0x73, 0x2c, 0x72, 0x3d,
                            0x2f, 0x7a, 0x2b, 0x67, 0x69, 0x5a, 0x69, 0x54, 0x78,
                            0x41, 0x48, 0x37, 0x72, 0x38, 0x73, 0x4e, 0x41, 0x65,
                            0x48, 0x72, 0x37, 0x63, 0x76, 0x70, 0x71, 0x56, 0x33,
                            0x75, 0x6f, 0x37, 0x47, 0x2f, 0x62, 0x4a, 0x42, 0x49,
                            0x4a, 0x4f, 0x33, 0x70, 0x6a, 0x56, 0x4d, 0x37, 0x74,
                            0x33, 0x6e, 0x67, 0x2c, 0x70, 0x3d, 0x41, 0x46, 0x70,
                            0x53, 0x59, 0x48, 0x2f, 0x4b, 0x2f, 0x38, 0x62, 0x75,
                            0x78, 0x31, 0x6d, 0x52, 0x50, 0x55, 0x77, 0x78, 0x54,
                            0x65, 0x38, 0x6c, 0x42, 0x75, 0x49, 0x50, 0x45, 0x79,
                            0x68, 0x69, 0x2f, 0x37, 0x55, 0x46, 0x50, 0x51, 0x70,
                            0x53, 0x72, 0x34, 0x41, 0x3d];

        let ok_res = PgsqlFEMessage::SASLResponse(
            RegularPacket {
                identifier: b'p',
                length: 108,
                payload: br#"c=biws,r=/z+giZiTxAH7r8sNAeHr7cvpqV3uo7G/bJBIJO3pjVM7t3ng,p=AFpSYH/K/8bux1mRPUwxTe8lBuIPEyhi/7UFPQpSr4A="#.to_vec(),
            });

        let result = pgsql_parse_sasl_response(&buf);
        match result {
            Ok((_remainder, message)) => {
                assert_eq!(message, ok_res);
            }
            Err(nom::Err::Error((_remainder, err))) => panic!("Shouldn't be error: {:?} expected Ok(_)", err),
            Err(nom::Err::Incomplete(needed)) => panic!("Shouldn't be incomplete: {:?}, expected Ok(_)", needed),
            _ => panic!("Unexpected behavior, should be Ok(_)"),
        }
    }

    #[test]
    fn test_parse_response() {
        // An SSL response - N
        let buf: &[u8] = &[0x4e];
        let response_ok = PgsqlBEMessage::SslResponse(SslResponse::SslRejected);
        let (_remainder, result) = pgsql_parse_ssl_response(&buf).unwrap();
        assert_eq!(result, response_ok);

        // An SSL response - S
        let buf: &[u8] = &[0x53];
        let response_ok = PgsqlBEMessage::SslResponse(SslResponse::SslAccepted);

        let (_remainder, result) = pgsql_parse_ssl_response(&buf).unwrap();
        assert_eq!(result, response_ok);

        // Not an SSL response
        let buf: &[u8] = &[0x52];
        let result = pgsql_parse_ssl_response(&buf);
        assert!(result.is_err());

        // - auth MD5
        let buf: &[u8] = &[ 0x52,
                            0x00, 0x00, 0x00, 0x0c,
                            0x00, 0x00, 0x00, 0x05,
                            0xf2, 0x11, 0xa3, 0xed];
        let ok_res = PgsqlBEMessage::AuthenticationMD5Password(
                AuthenticationMessage {
                    identifier: b'R',
                    length: 12,
                    auth_type: 5,
                    payload: Some(vec![0xf2, 0x11, 0xa3, 0xed]),
                });
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
        let ok_res = PgsqlBEMessage::AuthenticationCleartextPassword(
                AuthenticationMessage{
                    identifier: b'R',
                    length: 8,
                    auth_type: 3,
                    payload: None,
                });
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
        let ok_res = PgsqlBEMessage::AuthenticationOk(
                AuthenticationMessage{
                    identifier: b'R',
                    length: 8,
                    auth_type: 0,
                    payload: None,
                });
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
