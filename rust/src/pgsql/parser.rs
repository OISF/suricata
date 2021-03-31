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

// Author: Juliana Fajardini <jufajardini@oisf.net>

//! PostgreSQL nom parsers

use nom::character::streaming::alphanumeric1;
use nom::combinator::rest;
use nom::number::streaming::{be_i16, be_i32};
use nom::number::streaming::{be_u16, be_u32, be_u8};

pub const PGSQL_DUMMY_PROTO_MAJOR: u16 = 1234; // 0x04d2
pub const PGSQL_DUMMY_PROTO_MINOR_SSL: u16 = 5679; //0x162f
pub const _PGSQL_DUMMY_PROTO_MINOR_GSSAPI: u16 = 5680; // 0x1630

#[derive(Debug, PartialEq)]
pub struct PgsqlParameter {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub struct PgsqlStartupParameters {
    pub user: PgsqlParameter,
    pub database: Option<PgsqlParameter>,
    // TODO get rid of this Option<vec>
    pub optional_params: Option<Vec<PgsqlParameter>>,
}

#[derive(Debug, PartialEq)]
pub struct DummyStartupPacket {
    length: u32,
    proto_major: u16,
    proto_minor: u16,
}

#[derive(Debug, PartialEq)]
pub struct StartupPacket {
    pub length: u32,
    pub proto_major: u16,
    pub proto_minor: u16,
    pub params: PgsqlStartupParameters,
}

#[derive(Debug, PartialEq)]
pub struct RegularPacket {
    pub identifier: u8,
    pub length: u32,
    pub payload: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub struct PgsqlErrorNoticeMessageField {
    pub field_type: PgsqlErrorNoticeFieldType,
    pub field_value: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub struct ErrorNoticeMessage {
    pub identifier: u8,
    pub length: u32,
    pub message_body: Vec<PgsqlErrorNoticeMessageField>,
}

impl ErrorNoticeMessage {
    pub fn new(identifier: u8, length: u32) -> Self {
        ErrorNoticeMessage {
            identifier,
            length,
            message_body: Vec::new(),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum SSLResponseMessage {
    SSLAccepted,
    SSLRejected,
    InvalidResponse,
}

impl SSLResponseMessage {
    pub fn to_str(&self) -> &'static str {
        match self {
            SSLResponseMessage::SSLAccepted => "SSL Accepted",
            SSLResponseMessage::SSLRejected => "SSL Rejected",
            SSLResponseMessage::InvalidResponse => "Invalid server response",
        }
    }
}

impl From<u8> for SSLResponseMessage {
    fn from(identifier: u8) -> Self {
        match identifier {
            b'S' => Self::SSLAccepted,
            b'N' => Self::SSLRejected,
            _ => Self::InvalidResponse,
        }
    }
}

impl From<char> for SSLResponseMessage {
    fn from(identifier: char) -> Self {
        match identifier {
            'S' => Self::SSLAccepted,
            'N' => Self::SSLRejected,
            _ => Self::InvalidResponse,
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct ParameterStatusMessage {
    pub identifier: u8,
    pub length: u32,
    pub param: PgsqlParameter,
}

#[derive(Debug, PartialEq)]
pub struct BackendKeyDataMessage {
    pub identifier: u8,
    pub length: u32,
    pub backend_pid: u32,
    pub secret_key: u32,
}

#[derive(Debug, PartialEq)]
pub struct ReadyForQueryMessage {
    pub identifier: u8,
    pub length: u32,
    pub transaction_status: u8,
}

#[derive(Debug, PartialEq)]
pub enum PgsqlBEMessage {
    SSLResponse(SSLResponseMessage),
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
    CommandComplete(RegularPacket),
    ReadyForQuery(ReadyForQueryMessage),
    RowDescription(RowDescriptionMessage),
    DataRow(DataRowMessage),
    DummyDataRow(RegularPacket),
}

impl PgsqlBEMessage {
    pub fn to_str(&self) -> &'static str {
        match self {
            PgsqlBEMessage::SSLResponse(SSLResponseMessage::SSLAccepted) => "ssl_accepted",
            PgsqlBEMessage::SSLResponse(SSLResponseMessage::SSLRejected) => "ssl_rejected",
            PgsqlBEMessage::ErrorResponse(_) => "error_response",
            PgsqlBEMessage::NoticeResponse(_) => "notice_response",
            PgsqlBEMessage::AuthenticationOk(_) => "authentication_ok",
            PgsqlBEMessage::AuthenticationKerb5(_) => "authentication_kerb5",
            PgsqlBEMessage::AuthenticationCleartextPassword(_) => {
                "authentication_cleartext_password"
            }
            PgsqlBEMessage::AuthenticationMD5Password(_) => "authentication_md5_password",
            PgsqlBEMessage::AuthenticationGSS(_) => "authentication_gss",
            PgsqlBEMessage::AuthenticationSSPI(_) => "authentication_sspi",
            PgsqlBEMessage::AuthenticationGSSContinue(_) => "authentication_gss_continue",
            PgsqlBEMessage::AuthenticationSASL(_) => "authentication_sasl",
            PgsqlBEMessage::AuthenticationSASLContinue(_) => "authentication_sasl_continue",
            PgsqlBEMessage::AuthenticationSASLFinal(_) => "authentication_sasl_final",
            PgsqlBEMessage::ParameterStatus(_) => "parameter_status",
            PgsqlBEMessage::BackendKeyData(_) => "backend_key_data",
            PgsqlBEMessage::CommandComplete(_) => "command_completed",
            PgsqlBEMessage::ReadyForQuery(_) => "ready_for_query",
            PgsqlBEMessage::RowDescription(_) => "row_description",
            PgsqlBEMessage::DataRow(_) => "data_row",
            PgsqlBEMessage::SSLResponse(SSLResponseMessage::InvalidResponse) => {
                "invalid_be_message"
            }
            PgsqlBEMessage::DummyDataRow(_) => "data_row",
        }
    }

    pub fn get_backendkey_info(&self) -> (u32, u32) {
        match self {
            PgsqlBEMessage::BackendKeyData(message) => {
                return (message.backend_pid, message.secret_key);
            }
            _ => (0, 0),
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum SASLAuthenticationMechanism {
    ScramSha256,
    ScramSha256Plus,
    // UnknownMechanism,
}

impl SASLAuthenticationMechanism {
    pub fn to_str(&self) -> &'static str {
        match self {
            SASLAuthenticationMechanism::ScramSha256 => "scram_SHA256",
            SASLAuthenticationMechanism::ScramSha256Plus => "scram_SHA256_plus",
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct TerminationMessage {
    pub identifier: u8,
    pub length: u32,
}

#[derive(Debug, PartialEq)]
pub enum PgsqlFEMessage {
    SSLRequest(DummyStartupPacket),
    StartupMessage(StartupPacket),
    PasswordMessage(RegularPacket),
    SASLInitialResponse(SASLInitialResponsePacket),
    SASLResponse(RegularPacket),
    SimpleQuery(RegularPacket),
    Terminate(TerminationMessage),
}

impl PgsqlFEMessage {
    pub fn to_str(&self) -> &'static str {
        match self {
            PgsqlFEMessage::StartupMessage(_) => "startup_message",
            PgsqlFEMessage::SSLRequest(_) => "ssl_request",
            PgsqlFEMessage::PasswordMessage(_) => "password_message",
            PgsqlFEMessage::SASLInitialResponse(_) => "sasl_initial_response",
            PgsqlFEMessage::SASLResponse(_) => "sasl_response",
            PgsqlFEMessage::SimpleQuery(_) => "simple_query",
            PgsqlFEMessage::Terminate(_) => "termination_message",
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct AuthenticationMessage {
    pub identifier: u8,
    pub length: u32,
    pub auth_type: u32,
    pub payload: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub struct SASLInitialResponsePacket {
    pub identifier: u8,
    pub length: u32,
    pub auth_mechanism: SASLAuthenticationMechanism,
    pub param_length: u32,
    pub sasl_param: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub struct AuthenticationSASLMechanismMessage {
    identifier: u8,
    length: u32,
    auth_type: u32,
    auth_mechanisms: Vec<SASLAuthenticationMechanism>,
}

#[derive(Debug, PartialEq)]
pub struct RowField {
    pub field_name: Vec<u8>,
    pub table_oid: u32,
    pub column_index: u16,
    pub data_type_oid: u32,
    // "see pg_type.typlen. Note that negative values denote variable-width types"
    pub data_type_size: i16,
    // "The value will generally be -1 for types that do not need pg_attribute.atttypmod."
    pub type_modifier: i32,
    // "The format code being used for the field. Currently will be zero (text) or one (binary). In a RowDescription returned from the variant of Describe, will always be zero"
    pub format_code: u16,
}

#[derive(Debug, PartialEq)]
pub struct RowDescriptionMessage {
    pub identifier: u8,
    pub length: u32,
    pub field_count: u16,
    pub fields: Vec<RowField>,
}

#[derive(Debug, PartialEq)]
pub struct ColumnFieldValue {
    // Can be 0, or -1 as a special NULL column value
    pub value_length: i32,
    pub value: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub struct DataRowMessage {
    pub identifier: u8,
    pub length: u32,
    pub field_count: u16,
    pub fields: Vec<ColumnFieldValue>,
}

#[derive(Debug, PartialEq)]
pub enum PgsqlErrorNoticeFieldType {
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

impl From<char> for PgsqlErrorNoticeFieldType {
    fn from(identifier: char) -> PgsqlErrorNoticeFieldType {
        match identifier {
            'S' => PgsqlErrorNoticeFieldType::SeverityLocalizable,
            'V' => PgsqlErrorNoticeFieldType::SeverityNonLocalizable,
            'C' => PgsqlErrorNoticeFieldType::CodeSqlStateCode,
            'M' => PgsqlErrorNoticeFieldType::Message,
            'D' => PgsqlErrorNoticeFieldType::Detail,
            'H' => PgsqlErrorNoticeFieldType::Hint,
            'P' => PgsqlErrorNoticeFieldType::Position,
            'p' => PgsqlErrorNoticeFieldType::InternalPosition,
            'q' => PgsqlErrorNoticeFieldType::InternalQuery,
            'W' => PgsqlErrorNoticeFieldType::Where,
            's' => PgsqlErrorNoticeFieldType::SchemaName,
            't' => PgsqlErrorNoticeFieldType::TableName,
            'c' => PgsqlErrorNoticeFieldType::ColumnName,
            'd' => PgsqlErrorNoticeFieldType::DataType,
            'n' => PgsqlErrorNoticeFieldType::ConstraintName,
            'F' => PgsqlErrorNoticeFieldType::File,
            'L' => PgsqlErrorNoticeFieldType::Line,
            'R' => PgsqlErrorNoticeFieldType::Routine,
            '\u{0}' => PgsqlErrorNoticeFieldType::TerminatorToken,
            // Pgsql documentation says "frontends should silently ignore fields of unrecognized type."
            _ => PgsqlErrorNoticeFieldType::UnknownFieldType,
        }
    }
}

impl From<u8> for PgsqlErrorNoticeFieldType {
    fn from(identifier: u8) -> PgsqlErrorNoticeFieldType {
        match identifier {
            b'S' => PgsqlErrorNoticeFieldType::SeverityLocalizable,
            b'V' => PgsqlErrorNoticeFieldType::SeverityNonLocalizable,
            b'C' => PgsqlErrorNoticeFieldType::CodeSqlStateCode,
            b'M' => PgsqlErrorNoticeFieldType::Message,
            b'D' => PgsqlErrorNoticeFieldType::Detail,
            b'H' => PgsqlErrorNoticeFieldType::Hint,
            b'P' => PgsqlErrorNoticeFieldType::Position,
            b'p' => PgsqlErrorNoticeFieldType::InternalPosition,
            b'q' => PgsqlErrorNoticeFieldType::InternalQuery,
            b'W' => PgsqlErrorNoticeFieldType::Where,
            b's' => PgsqlErrorNoticeFieldType::SchemaName,
            b't' => PgsqlErrorNoticeFieldType::TableName,
            b'c' => PgsqlErrorNoticeFieldType::ColumnName,
            b'd' => PgsqlErrorNoticeFieldType::DataType,
            b'n' => PgsqlErrorNoticeFieldType::ConstraintName,
            b'F' => PgsqlErrorNoticeFieldType::File,
            b'L' => PgsqlErrorNoticeFieldType::Line,
            b'R' => PgsqlErrorNoticeFieldType::Routine,
            b'\0' => PgsqlErrorNoticeFieldType::TerminatorToken,
            // Pgsql documentation says "frontends should silently ignore fields of unrecognized type."
            _ => PgsqlErrorNoticeFieldType::UnknownFieldType,
        }
    }
}

named!(
    parse_user_param<PgsqlParameter>,
    do_parse!(
        param_name: tag_no_case!("user")
            >> tag!("\x00")
            >> param_value: take_until1!("\x00")
            >> tag!("\x00")
            >> (PgsqlParameter {
                name: param_name.to_vec(),
                value: param_value.to_vec(),
            })
    )
);

named!(
    parse_database_param<PgsqlParameter>,
    do_parse!(
        param_name: tag_no_case!("database")
            >> tag!("\x00")
            >> param_value: take_until1!("\x00")
            >> tag!("\x00")
            >> (PgsqlParameter {
                name: param_name.to_vec(),
                value: param_value.to_vec(),
            })
    )
);

//TODO Future version could have a generic parser for the parameters, which receives tag as an argument
named!(
    pgsql_parse_parameter<PgsqlParameter>,
    do_parse!(
        param_name: take_until1!("\x00")
            >> tag!("\x00")
            >> param_value: take_until1!("\x00")
            >> tag!("\x00")
            >> (PgsqlParameter {
                name: param_name.to_vec(),
                value: param_value.to_vec(),
            })
    )
);

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

named!(
    parse_sasl_initial_response_payload<(SASLAuthenticationMechanism, u32, Vec<u8>)>,
    do_parse!(
        sasl_mechanism: call!(parse_sasl_mechanism)
        >> param_length: be_u32
        // From RFC 5802 - the client-first-message will always start w/
        // 'n', 'y' or 'p', otherwise it's invalid, I think we should check that, at some point
        >> param: terminated!(take!(param_length), eof!())
        >> ((sasl_mechanism, param_length, param.to_vec()))
    )
);

named!(pub parse_sasl_initial_response<PgsqlFEMessage>,
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

named!(pub parse_sasl_response<PgsqlFEMessage>,
do_parse!(
    identifier: verify!(be_u8, |&x| x == b'p')
    >> length: verify!(be_u32, |&x| x > 4)
    >> payload: take!(length - 4)
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
                                    >> _message: switch!(value!(proto_minor),
                                        PGSQL_DUMMY_PROTO_MINOR_SSL => tuple!(
                                                    value!(len),
                                                    value!(proto_major),
                                                    value!(proto_minor)))
                                    >> (PgsqlFEMessage::SSLRequest(DummyStartupPacket{
                                        length: len,
                                        proto_major,
                                        proto_minor})))
                    ))
    >> (message)
));

// TODO Decide if it's a good idea to offer GSS encryption support right now, as the documentation seems to
// have conflicting information...
// If I do:
// To initiate a GSSAPI-encrypted connection, the frontend initially sends a GSSENCRequest message rather than a
// StartupMessage. The server then responds with a single byte containing G or N, indicating that it is willing or unwilling to perform GSSAPI encryption, respectively. The frontend might close the connection at this point if it is
// dissatisfied with the response. To continue after G, using the GSSAPI C bindings as discussed in RFC2744 or equivalent,
// perform a GSSAPI initialization by calling gss_init_sec_context() in a loop and sending the result to the server,
// starting with an empty input and then with each result from the server, until it returns no output. When sending the
// results of gss_init_sec_context() to the server, prepend the length of the message as a four byte integer in network
// byte order. To continue after N, send the usual StartupMessage and proceed without encryption. (Alternatively, it is
// permissible to issue an SSLRequest message after an N response to try to use SSL encryption instead of GSSAPI.)
// Source: https://www.postgresql.org/docs/13/protocol-flow.html#id-1.10.5.7.11, GSSAPI Session Encryption

// Password can be encrypted or in cleartext
named!(pub parse_password_message<PgsqlFEMessage>,
do_parse!(
    identifier: verify!(be_u8, |&x| x == b'p')
    // check that we have some data ( 4 bytes (length) + at least 1 byte)
    >> length: verify!(be_u32, |&x| x >= 5)
    >> password: flat_map!(take!(length - 4), take_until1!("\x00"))
    >> (PgsqlFEMessage::PasswordMessage(
                RegularPacket{
                    identifier,
                    length,
                    payload: password.to_vec(),
        }))
));

named!(
    parse_simple_query<PgsqlFEMessage>,
    do_parse!(
        identifier: verify!(be_u8, |&x| x == b'Q')
            >> length: verify!(be_u32, |&x| x > 4)
            >> query: flat_map!(take!(length - 4), take_until1!("\x00"))
            >> (PgsqlFEMessage::SimpleQuery(RegularPacket {
                identifier,
                length,
                payload: query.to_vec(),
            }))
    )
);

named!(
    parse_terminate_message<PgsqlFEMessage>,
    do_parse!(
        identifier: verify!(be_u8, |&x| x == b'X')
            >> length: verify!(be_u32, |&x| x == 4)
            >> (PgsqlFEMessage::Terminate(TerminationMessage { identifier, length }))
    )
);

// Messages that begin with 'p' but are not password ones are not parsed here
named!(pub parse_request<PgsqlFEMessage>,
do_parse!(
    tag: peek!(be_u8)
    >> message: switch!(value!(tag),
                    b'\0' => call!(pgsql_parse_startup_packet) |
                    b'Q' => dbg_dmp!(call!(parse_simple_query)) |
                    b'X' => dbg_dmp!(call!(parse_terminate_message)))
    >> (message)
));

named!(
    pgsql_parse_authentication_message<PgsqlBEMessage>,
    do_parse!(
        identifier: verify!(be_u8, |&x| x == b'R')
            >> length: verify!(be_u32, |&x| x >= 8)
            >> auth_type: be_u32
            >> payload: peek!(rest)
            >> message:
                flat_map!(
                    take!(length - 8),
                    switch!(value!(auth_type),
                        0 => value!(PgsqlBEMessage::AuthenticationOk(
                                AuthenticationMessage {
                                    identifier,
                                    length,
                                    auth_type,
                                    payload: payload.to_vec(),
                                }))  |
                        3 => value!(PgsqlBEMessage::AuthenticationCleartextPassword(
                                AuthenticationMessage {
                                    identifier,
                                    length,
                                    auth_type,
                                    payload: payload.to_vec(),
                                }))  |
                        5 => do_parse!(
                            salt: exact!(take!(4))
                            >> (PgsqlBEMessage::AuthenticationMD5Password(
                                    AuthenticationMessage {
                                        identifier,
                                        length,
                                        auth_type,
                                        payload: salt.to_vec(),
                                    }))
                            ) |
                        9 => value!(PgsqlBEMessage::AuthenticationSSPI(
                                AuthenticationMessage {
                                    identifier,
                                    length,
                                    auth_type,
                                    payload: payload.to_vec(),
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
                                    payload: sasl_challenge.to_vec(),
                                }))
                            ) |
                        12 => do_parse!(
                            signature: rest
                            >> (PgsqlBEMessage::AuthenticationSASLFinal(
                                AuthenticationMessage {
                                    identifier,
                                    length,
                                    auth_type,
                                    payload: signature.to_vec(),
                                }
                            ))
                        )
                        // TODO - Question: Should I add here a pattern for unknown message types? If so, should I create PgsqlError, like SmbError?)
                        // TODO add other authentication messages
                    )
                )
            >> (message)
    )
);

named!(
    parse_parameter_status_message<PgsqlBEMessage>,
    dbg_dmp!(do_parse!(
        identifier: verify!(be_u8, |&x| x == b'S')
            >> length: verify!(be_u32, |&x| x >= 4)
            >> param: flat_map!(take!(length - 4), pgsql_parse_parameter)
            >> (PgsqlBEMessage::ParameterStatus(ParameterStatusMessage {
                identifier,
                length,
                param,
            }))
    ))
);

named!(pub parse_ssl_response<PgsqlBEMessage>,
do_parse!(
    tag: alt!(char!('N') | char!('S'))
    >> (PgsqlBEMessage::SSLResponse(
        SSLResponseMessage::from(tag))
    )
));

named!(
    parse_backend_key_data_message<PgsqlBEMessage>,
    do_parse!(
        identifier: verify!(be_u8, |&x| x == b'K')
            >> length: verify!(be_u32, |&x| x == 12)
            >> pid: be_u32
            >> secret_key: be_u32
            >> (PgsqlBEMessage::BackendKeyData(BackendKeyDataMessage {
                identifier,
                length,
                backend_pid: pid,
                secret_key,
            }))
    )
);

named!(
    parse_command_complete<PgsqlBEMessage>,
    do_parse!(
        identifier: verify!(be_u8, |&x| x == b'C')
            >> length: verify!(be_u32, |&x| x > 4)
            >> payload: take!(length - 4)
            >> (PgsqlBEMessage::CommandComplete(RegularPacket {
                identifier,
                length,
                payload: payload.to_vec(),
            }))
    )
);

named!(
    parse_ready_for_query<PgsqlBEMessage>,
    do_parse!(
        identifier: verify!(be_u8, |&x| x == b'Z')
            >> length: verify!(be_u32, |&x| x == 5)
            >> status: verify!(be_u8, |&x| x == b'I' || x == b'T' || x == b'E')
            >> (PgsqlBEMessage::ReadyForQuery(ReadyForQueryMessage {
                identifier,
                length,
                transaction_status: status,
            }))
    )
);

named!(
    parse_row_field<RowField>,
    do_parse!(
        field_name: take_until1!("\x00")
            >> tag!("\x00")
            >> table_oid: be_u32
            >> column_index: be_u16
            >> data_type_oid: be_u32
            >> data_type_size: be_i16
            >> type_modifier: be_i32
            >> format_code: be_u16
            >> (RowField {
                field_name: field_name.to_vec(),
                table_oid,
                column_index,
                data_type_oid,
                data_type_size,
                type_modifier,
                format_code,
            })
    )
);

named!(pub parse_row_description<PgsqlBEMessage>,
do_parse!(
    identifier: dbg_dmp!(verify!(be_u8, |&x| x == b'T'))
    >> length: verify!(be_u32, |&x| x > 6)
    >> field_count: dbg_dmp!(be_u16)
    >> fields: flat_map!(
        take!(length - 6),
        many_m_n!(0, field_count.into(),
            call!(parse_row_field)))
    >> (PgsqlBEMessage::RowDescription(
        RowDescriptionMessage {
            identifier,
            length,
            field_count,
            fields,
    }))
));

named!(
    parse_data_row_value<ColumnFieldValue>,
    do_parse!(
        // TODO make sure that the -1s here don't mess up with everything
        value_length: be_i32
            >> value: cond!(value_length >= 0, take!(value_length))
            >> (ColumnFieldValue {
                value_length,
                value: {
                    match value {
                        Some(data) => data.to_vec(),
                        None => [].to_vec(),
                    }
                },
            })
    )
);

// We won't actually parse the data rows, for the first version
// named!(pub parse_data_row<PgsqlBEMessage>,
//     do_parse!(
//         identifier: verify!(be_u8, |&x| x == b'D')
//         >> length: verify!(be_u32, |&x| x > 6)
//         >> field_count: be_u16
//         >> rows: dbg_dmp!(flat_map!(take!(length - 6), many_m_n!(0, field_count.into(), call!(parse_data_row_value))))
//         >> (PgsqlBEMessage::DataRow(
//             DataRowMessage {
//                 identifier,
//                 length,
//                 field_count,
//                 fields: rows,
//             }
//         ))
//     ));

named!(pub dummy_parse_data_row<PgsqlBEMessage>,
do_parse!(
    identifier: verify!(be_u8, |&x| x == b'D')
    >> length: verify!(be_u32, |&x| x > 6)
    >> _rest: take!(length - 4)
    >> (PgsqlBEMessage::DummyDataRow(
        RegularPacket {
            identifier,
            length,
            payload: b"response ok".to_vec(),
        }
    ))
));

named!(
    parse_sasl_mechanism<SASLAuthenticationMechanism>,
    do_parse!(
        mechanism:
            alt!(
                terminated!(tag!("SCRAM-SHA-256-PLUS"), tag!("\x00")) => { |_| SASLAuthenticationMechanism::ScramSha256Plus} |
                terminated!(tag!("SCRAM-SHA-256"), tag!("\x00")) => { |_| SASLAuthenticationMechanism::ScramSha256}
            )
            >> (mechanism)
    )
);

named!(
    parse_sasl_mechanisms<Vec<SASLAuthenticationMechanism>>,
    terminated!(many1!(parse_sasl_mechanism), tag!("\x00"))
);

named!(pub parse_error_response_code<PgsqlErrorNoticeMessageField>,
do_parse!(
    _field_type: char!('C')
    >> field_value: flat_map!(take!(6), call!(alphanumeric1))
    >> (PgsqlErrorNoticeMessageField{
        field_type: PgsqlErrorNoticeFieldType::CodeSqlStateCode,
        field_value: field_value.to_vec(),
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
            field_type: PgsqlErrorNoticeFieldType::from(field_type),
            field_value: field_value.to_vec(),
    })
));

named!(pub parse_error_response_field<PgsqlErrorNoticeMessageField>,
    switch!(peek!(be_u8),
        b'\0' => do_parse!(
            field_type: be_u8
            >> data: eof!()
            >> (PgsqlErrorNoticeMessageField{
                field_type: PgsqlErrorNoticeFieldType::from(field_type),
                field_value: data.to_vec(),
            })
        ) |
        b'V' => call!(parse_error_response_severity) |
        b'C' => call!(parse_error_response_code) |
        b'S' | b'M' | b'D' | b'H' | b'P' | b'p' | b'q' |
        b'W' | b's' | b't' | b'c' | b'd' | b'n' | b'F' | b'L' | b'R'
        => do_parse!(
            field_type: be_u8
            >> field_value: take_until_and_consume!("\x00")
            >> (PgsqlErrorNoticeMessageField{
                field_type: PgsqlErrorNoticeFieldType::from(field_type),
                field_value: field_value.to_vec(),
            })
        ) |
        _ => do_parse!(
            field_type: be_u8
            >> field_value: opt!(take_until_and_consume!("\x00"))
            >> (PgsqlErrorNoticeMessageField{
                field_type: PgsqlErrorNoticeFieldType::from(field_type),
                field_value: field_value.unwrap().to_vec(),
            })
        ))
);

named!(pub parse_error_notice_fields<Vec<PgsqlErrorNoticeMessageField>>,
do_parse!(
    data: many_till!(call!(parse_error_response_field), eof!())
    >> (data.0)
));

named!(
    pgsql_parse_error_response<PgsqlBEMessage>,
    do_parse!(
        identifier: verify!(be_u8, |&x| x == b'E')
            >> length: verify!(be_u32, |&x| x > 10)
            >> message_body: flat_map!(take!(length - 4), call!(parse_error_notice_fields))
            >> (PgsqlBEMessage::ErrorResponse(ErrorNoticeMessage {
                identifier,
                length,
                message_body,
            }))
    )
);

named!(
    pgsql_parse_notice_response<PgsqlBEMessage>,
    do_parse!(
        identifier: verify!(be_u8, |&x| x == b'N')
            >> length: verify!(be_u32, |&x| x > 10)
            >> message_body: flat_map!(take!(length - 4), call!(parse_error_notice_fields))
            >> (PgsqlBEMessage::NoticeResponse(ErrorNoticeMessage {
                identifier,
                length,
                message_body,
            }))
    )
);

named!(pub pgsql_parse_response<PgsqlBEMessage>,
do_parse!(
    // TODO Would 'length' be better here?
    pseudo_header: peek!(tuple!(be_u8, be_u32))
    // TODO could pseudo_header + 1 be bad?
    >> message: flat_map!(take!(pseudo_header.1 + 1), switch!(value!(pseudo_header.0),
        b'E' => call!(pgsql_parse_error_response) |
        b'K' => call!(parse_backend_key_data_message) |
        b'N' => call!(pgsql_parse_notice_response) |
        b'R' => call!(pgsql_parse_authentication_message) |
        b'S' => call!(parse_parameter_status_message) |
        b'C' => call!(parse_command_complete) |
        b'Z' => call!(parse_ready_for_query) |
        b'T' => call!(parse_row_description) |
        b'D' => call!(dummy_parse_data_row)
        // b'D' => call!(parse_data_row)
        // _ => {} // TODO question should I add an unknown message type here, or maybe an error?
    ))
    >> (message)
));

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
        let request_ok = PgsqlFEMessage::SSLRequest(ssl_request);

        let (_remainder, result) = parse_request(buf).unwrap();
        assert_eq!(result, request_ok);

        // incomplete message
        let result = parse_request(&buf[0..7]);
        assert!(result.is_err());

        // Same request, but length is wrong
        let buf: &[u8] = &[0x00, 0x00, 0x00, 0x07, 0x04, 0xd2, 0x16, 0x2f];
        let result = parse_request(buf);
        assert!(result.is_err());

        let buf: &[u8] = &[
            /* Length 85 */ 0x00, 0x00, 0x00, 0x55, /* Proto version */ 0x00, 0x03, 0x00,
            0x00, /* user */ 0x75, 0x73, 0x65, 0x72, 0x00, /* [value] rep */ 0x72, 0x65,
            0x70, 0x00, /* database */ 0x64, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65, 0x00,
            /* [optional] */ 0x72, 0x65, 0x70, 0x6c, 0x69, 0x63,
            /* replication replication true application_name walreceiver */
            0x61, 0x74, 0x69, 0x6f, 0x6e, 0x00, 0x72, 0x65, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74,
            0x69, 0x6f, 0x6e, 0x00, 0x74, 0x72, 0x75, 0x65, 0x00, 0x61, 0x70, 0x70, 0x6c, 0x69,
            0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x00, 0x77, 0x61,
            0x6c, 0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x72, 0x00, 0x00,
        ];
        let result = parse_request(buf);
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
        let buf: &[u8] = &[
            0x00, 0x00, 0x00, 0x26, 0x00, 0x03, 0x00, 0x00, 0x75, 0x73, 0x65, 0x72, 0x00, 0x6f,
            0x72, 0x79, 0x78, 0x00, 0x64, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65, 0x00, 0x6d,
            0x61, 0x69, 0x6c, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x00, 0x00,
        ];
        let user = PgsqlParameter {
            name: [0x75, 0x73, 0x65, 0x72].to_vec(),
            value: [0x6f, 0x72, 0x79, 0x78].to_vec(),
        };
        let database = PgsqlParameter {
            name: [0x64, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65].to_vec(),
            value: [0x6d, 0x61, 0x69, 0x6c, 0x73, 0x74, 0x6f, 0x72, 0x65].to_vec(),
        };
        let params = PgsqlStartupParameters {
            user,
            database: Some(database),
            optional_params: None,
        };
        let expected_result = PgsqlFEMessage::StartupMessage(StartupPacket {
            length: 38,
            proto_major: 3,
            proto_minor: 0,
            params,
        });
        let result = parse_request(buf);
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
        let buf: &[u8] = &[
            0x00, 0x00, 0x00, 0x13, 0x00, 0x03, 0x00, 0x00, 0x75, 0x73, 0x65, 0x72, 0x00, 0x6f,
            0x72, 0x79, 0x78, 0x00, 0x00,
        ];
        let user = PgsqlParameter {
            name: [0x75, 0x73, 0x65, 0x72].to_vec(),
            value: [0x6f, 0x72, 0x79, 0x78].to_vec(),
        };
        let params = PgsqlStartupParameters {
            user,
            database: None,
            optional_params: None,
        };
        let expected_result = PgsqlFEMessage::StartupMessage(StartupPacket {
            length: 19,
            proto_major: 3,
            proto_minor: 0,
            params,
        });
        let result = parse_request(buf);
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
        let buf: &[u8] = &[
            0x00, 0x00, 0x00, 0x12, 0x00, 0x03, 0x00, 0x00, 0x75, 0x73, 0x65, 0x72, 0x00, 0x6f,
            0x72, 0x79, 0x78, 0x00, 0x00,
        ];
        let result = parse_request(buf);
        assert!(result.is_err());

        // A startup message/request with bad length
        let buf: &[u8] = &[
            0x00, 0x00, 0x00, 0x01, 0x00, 0x03, 0x00, 0x00, 0x75, 0x73, 0x65, 0x72, 0x00, 0x6f,
            0x72, 0x79, 0x78, 0x00, 0x00,
        ];
        let result = parse_request(buf);
        assert!(result.is_err());

        // A startup message/request with corrupted user param
        let buf: &[u8] = &[
            0x00, 0x00, 0x00, 0x013, 0x00, 0x03, 0x00, 0x00, 0x75, 0x73, 0x65, 0x00, 0x6f, 0x72,
            0x79, 0x78, 0x00, 0x00,
        ];
        let result = parse_request(buf);
        assert!(result.is_err());

        // A startup message/request missing the terminator
        let buf: &[u8] = &[
            0x00, 0x00, 0x00, 0x013, 0x00, 0x03, 0x00, 0x00, 0x75, 0x73, 0x65, 0x72, 0x00, 0x6f,
            0x72, 0x79, 0x78, 0x00,
        ];
        let result = parse_request(buf);
        assert!(result.is_err());

        // A termination message
        let buf: &[u8] = &[0x58, 0x00, 0x00, 0x00, 0x04];
        let result = parse_request(buf);
        assert!(result.is_ok());

        let result = parse_request(&buf[0..3]);
        assert!(result.is_err());

        // TODO add other messages
    }

    #[test]
    fn test_parse_error_response_code() {
        let buf: &[u8] = &[0x43, 0x32, 0x38, 0x30, 0x30, 0x30, 0x00];
        let value_str = "28000".as_bytes();
        let ok_res = PgsqlErrorNoticeMessageField {
            field_type: PgsqlErrorNoticeFieldType::CodeSqlStateCode,
            field_value: value_str.to_vec(),
        };
        let result = parse_error_response_code(buf);
        assert!(result.is_ok());

        let (remainder, result) = parse_error_response_code(buf).unwrap();
        assert_eq!(result, ok_res);
        assert_eq!(remainder.len(), 0);

        let result = parse_error_response_code(&buf[0..5]);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_password_messages() {
        // A password message (MD5)
        let buf: &[u8] = &[
            0x70, 0x00, 0x00, 0x00, 0x28, 0x6d, 0x64, 0x35, 0x63, 0x65, 0x66, 0x66, 0x63, 0x30,
            0x31, 0x64, 0x63, 0x64, 0x65, 0x37, 0x35, 0x34, 0x31, 0x38, 0x32, 0x39, 0x64, 0x65,
            0x65, 0x66, 0x36, 0x62, 0x35, 0x65, 0x39, 0x63, 0x39, 0x31, 0x34, 0x32, 0x00,
        ];
        let ok_result = PgsqlFEMessage::PasswordMessage(RegularPacket {
            identifier: b'p',
            length: 40,
            payload: br#"md5ceffc01dcde7541829deef6b5e9c9142"#.to_vec(),
        });
        let (_remainder, result) = parse_password_message(buf).unwrap();
        assert_eq!(result, ok_result);

        // Length is off by one here
        let buf: &[u8] = &[
            0x70, 0x00, 0x00, 0x00, 0x27, 0x6d, 0x64, 0x35, 0x63, 0x65, 0x66, 0x66, 0x63, 0x30,
            0x31, 0x64, 0x63, 0x64, 0x65, 0x37, 0x35, 0x34, 0x31, 0x38, 0x32, 0x39, 0x64, 0x65,
            0x65, 0x66, 0x36, 0x62, 0x35, 0x65, 0x39, 0x63, 0x39, 0x31, 0x34, 0x32, 0x00,
        ];
        let result = parse_password_message(buf);
        assert!(result.is_err());

        // Length also off by one, but now bigger than it should
        let buf: &[u8] = &[
            0x70, 0x00, 0x00, 0x00, 0x29, 0x6d, 0x64, 0x35, 0x63, 0x65, 0x66, 0x66, 0x63, 0x30,
            0x31, 0x64, 0x63, 0x64, 0x65, 0x37, 0x35, 0x34, 0x31, 0x38, 0x32, 0x39, 0x64, 0x65,
            0x65, 0x66, 0x36, 0x62, 0x35, 0x65, 0x39, 0x63, 0x39, 0x31, 0x34, 0x32, 0x00,
        ];
        let result = parse_password_message(buf);
        assert!(result.is_err());

        // Incomplete payload
        let buf: &[u8] = &[
            0x70, 0x00, 0x00, 0x00, 0x28, 0x6d, 0x64, 0x35, 0x63, 0x65, 0x66, 0x66, 0x63, 0x30,
            0x31, 0x64, 0x63, 0x64, 0x65, 0x37, 0x35, 0x34, 0x31, 0x38, 0x32, 0x39, 0x64, 0x65,
            0x65, 0x66, 0x36, 0x62, 0x35, 0x65, 0x39, 0x63, 0x39, 0x31, 0x34, 0x32,
        ];
        let result = parse_password_message(buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_error_response_field() {
        // VFATAL
        let input: &[u8] = &[0x56, 0x46, 0x41, 0x54, 0x41, 0x4c, 0x00];

        let value_str = "FATAL".as_bytes();
        let ok_res = PgsqlErrorNoticeMessageField {
            field_type: PgsqlErrorNoticeFieldType::SeverityNonLocalizable,
            field_value: value_str.to_vec(),
        };

        let (remainder, result) = parse_error_response_field(input).unwrap();
        assert_eq!(result, ok_res);
        assert_eq!(remainder.len(), 0);

        // "Mno pg_hba.conf entry for replication connection from host "192.168.50.11", user "rep", SSL off "
        let input: &[u8] = &[
            0x4d, 0x6e, 0x6f, 0x20, 0x70, 0x67, 0x5f, 0x68, 0x62, 0x61, 0x2e, 0x63, 0x6f, 0x6e,
            0x66, 0x20, 0x65, 0x6e, 0x74, 0x72, 0x79, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x72, 0x65,
            0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x63, 0x6f, 0x6e, 0x6e,
            0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x66, 0x72, 0x6f, 0x6d, 0x20, 0x68, 0x6f,
            0x73, 0x74, 0x20, 0x22, 0x31, 0x39, 0x32, 0x2e, 0x31, 0x36, 0x38, 0x2e, 0x35, 0x30,
            0x2e, 0x31, 0x31, 0x22, 0x2c, 0x20, 0x75, 0x73, 0x65, 0x72, 0x20, 0x22, 0x72, 0x65,
            0x70, 0x22, 0x2c, 0x20, 0x53, 0x53, 0x4c, 0x20, 0x6f, 0x66, 0x66, 0x00,
        ];

        let value_str = br#"no pg_hba.conf entry for replication connection from host "192.168.50.11", user "rep", SSL off"#;
        let ok_res = PgsqlErrorNoticeMessageField {
            field_type: PgsqlErrorNoticeFieldType::Message,
            field_value: value_str.to_vec(),
        };

        let (remainder, result) = parse_error_response_field(input).unwrap();
        assert_eq!(result, ok_res);
        assert_eq!(remainder.len(), 0);

        // if incomplete, here we should get an error
        let result = parse_error_response_field(&input[0..12]);
        assert!(result.is_err());

        // C28000
        let input: &[u8] = &[0x43, 0x32, 0x38, 0x30, 0x30, 0x30, 0x00];
        let value_str = "28000".as_bytes();
        let ok_res = PgsqlErrorNoticeMessageField {
            field_type: PgsqlErrorNoticeFieldType::CodeSqlStateCode,
            field_value: value_str.to_vec(),
        };
        let (remainder, result) = parse_error_response_field(input).unwrap();
        assert_eq!(result, ok_res);
        assert_eq!(remainder.len(), 0);
    }

    // After sending AuthenticationOk, the backend will send a series of messages with parameters, a backend key message, and, finally a ready for query message
    #[test]
    fn test_parse_startup_phase_wrapup() {
        let buf: &[u8] = &[
            0x53, 0x00, 0x00, 0x00, 0x1a, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69,
            0x6f, 0x6e, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x00, 0x70, 0x73, 0x71, 0x6c, 0x00,
        ];
        let ok_res = PgsqlBEMessage::ParameterStatus(ParameterStatusMessage {
            identifier: b'S',
            length: 26,
            param: PgsqlParameter {
                name: br#"application_name"#.to_vec(),
                value: br#"psql"#.to_vec(),
            },
        });
        let (_remainder, result) = parse_parameter_status_message(buf).unwrap();
        assert_eq!(result, ok_res);

        let ok_res = PgsqlBEMessage::ParameterStatus(ParameterStatusMessage {
            identifier: b'S',
            length: 26,
            param: PgsqlParameter {
                name: br#"application_name"#.to_vec(),
                value: br#"psql"#.to_vec(),
            },
        });

        let result = pgsql_parse_response(buf);
        match result {
            Ok((_remainder, message)) => {
                assert_eq!(message, ok_res);
            }
            Err(nom::Err::Error((remainder, err))) => {
                panic!(
                    "Shouldn't be err {:?}, expected Ok(_). Remainder is: {:?} ",
                    err, remainder
                );
            }
            Err(nom::Err::Incomplete(needed)) => {
                panic!("Should not be incomplete {:?}, expected Ok(_)", needed);
            }
            _ => panic!("Unexpected behavior, expected Ok(_)"),
        }

        let buf: &[u8] = &[
            0x53, 0x00, 0x00, 0x00, 0x19, 0x69, 0x6e, 0x74, 0x65, 0x67, 0x65, 0x72, 0x5f, 0x64,
            0x61, 0x74, 0x65, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x00, 0x6f, 0x6e, 0x00,
        ];
        let result = parse_parameter_status_message(buf);
        assert!(result.is_ok());

        let buf: &[u8] = &[
            0x4b, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x3d, 0xbb, 0xe1, 0xe1, 0xae,
        ];

        let result = parse_backend_key_data_message(buf);
        assert!(result.is_ok());

        let buf: &[u8] = &[0x5a, 0x00, 0x00, 0x00, 0x05, 0x49];
        let result = parse_ready_for_query(buf);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_error_notice_fields() {
        let input: &[u8] = &[0x53, 0x46, 0x41, 0x54, 0x41, 0x4c, 0x00, 0x00];

        let field1 = PgsqlErrorNoticeMessageField {
            field_type: PgsqlErrorNoticeFieldType::SeverityLocalizable,
            field_value: br#"FATAL"#.to_vec(),
        };
        let field2 = PgsqlErrorNoticeMessageField {
            field_type: PgsqlErrorNoticeFieldType::CodeSqlStateCode,
            field_value: br#"28000"#.to_vec(),
        };
        let field3 = PgsqlErrorNoticeMessageField{
            field_type: PgsqlErrorNoticeFieldType::Message,
            field_value: br#"no pg_hba.conf entry for replication connection from host "192.168.50.11", user "rep", SSL off"#.to_vec(),
        };
        let field4 = PgsqlErrorNoticeMessageField {
            field_type: PgsqlErrorNoticeFieldType::TerminatorToken,
            field_value: br#""#.to_vec(),
        };

        let mut ok_res: Vec<PgsqlErrorNoticeMessageField> = Vec::new();
        ok_res.push(field1);
        ok_res.push(field4);

        let (remainder, result) = parse_error_notice_fields(input).unwrap();
        assert_eq!(result, ok_res);
        assert_eq!(remainder.len(), 0);
        ok_res.pop();

        ok_res.push(field2);
        ok_res.push(field3);

        let field4 = PgsqlErrorNoticeMessageField {
            field_type: PgsqlErrorNoticeFieldType::TerminatorToken,
            field_value: br#""#.to_vec(),
        };

        ok_res.push(field4);

        let input: &[u8] = &[
            0x53, 0x46, 0x41, 0x54, 0x41, 0x4c, 0x00, 0x43, 0x32, 0x38, 0x30, 0x30, 0x30, 0x00,
            0x4d, 0x6e, 0x6f, 0x20, 0x70, 0x67, 0x5f, 0x68, 0x62, 0x61, 0x2e, 0x63, 0x6f, 0x6e,
            0x66, 0x20, 0x65, 0x6e, 0x74, 0x72, 0x79, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x72, 0x65,
            0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x63, 0x6f, 0x6e, 0x6e,
            0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x66, 0x72, 0x6f, 0x6d, 0x20, 0x68, 0x6f,
            0x73, 0x74, 0x20, 0x22, 0x31, 0x39, 0x32, 0x2e, 0x31, 0x36, 0x38, 0x2e, 0x35, 0x30,
            0x2e, 0x31, 0x31, 0x22, 0x2c, 0x20, 0x75, 0x73, 0x65, 0x72, 0x20, 0x22, 0x72, 0x65,
            0x70, 0x22, 0x2c, 0x20, 0x53, 0x53, 0x4c, 0x20, 0x6f, 0x66, 0x66, 0x00, 0x00,
        ];

        let (remainder, result) = parse_error_notice_fields(input).unwrap();
        assert_eq!(result, ok_res);
        assert_eq!(remainder.len(), 0);

        let input: &[u8] = &[
            0x53, 0x46, 0x41, 0x54, 0x41, 0x4c, 0x00, 0x43, 0x32, 0x38, 0x30, 0x30, 0x30, 0x00,
            0x4d, 0x6e, 0x6f, 0x20, 0x70, 0x67, 0x5f, 0x68, 0x62, 0x61, 0x2e, 0x63, 0x6f, 0x6e,
            0x66, 0x20, 0x65, 0x6e, 0x74, 0x72, 0x79, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x72, 0x65,
            0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x63, 0x6f, 0x6e, 0x6e,
            0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x66, 0x72, 0x6f, 0x6d, 0x20, 0x68, 0x6f,
            0x73, 0x74, 0x20, 0x22, 0x31, 0x39, 0x32, 0x2e, 0x31, 0x36, 0x38, 0x2e, 0x35, 0x30,
            0x2e, 0x31, 0x31, 0x22, 0x2c, 0x20, 0x75, 0x73, 0x65, 0x72, 0x20, 0x22, 0x72, 0x65,
            0x70, 0x22, 0x2c, 0x20, 0x53, 0x53, 0x4c, 0x20, 0x6f, 0x66, 0x66, 0x00, 0x46, 0x61,
            0x75, 0x74, 0x68, 0x2e, 0x63, 0x00, 0x4c, 0x34, 0x38, 0x31, 0x00, 0x52, 0x43, 0x6c,
            0x69, 0x65, 0x6e, 0x74, 0x41, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61,
            0x74, 0x69, 0x6f, 0x6e, 0x00, 0x00,
        ];

        let result = parse_error_notice_fields(input);
        assert!(result.is_ok());

        let result = parse_error_notice_fields(&input[0..12]);
        match result {
            Ok((_remainder, _message)) => panic!("Result should not be ok, but incomplete."),

            Err(nom::Err::Error((_remainder, err))) => {
                panic!("Shouldn't be error: {:?}", err);
            }
            Err(nom::Err::Incomplete(needed)) => {
                assert_eq!(needed, Size(6));
            }
            _ => panic!("Unexpected behavior."),
        }
    }

    #[test]
    fn test_parse_error_notice_response() {
        // declare test case buffer
        let buf: &[u8] = &[
            /* identifier */ 0x45, /* length */ 0x00, 0x00, 0x00, 0x96,
            /* Severity */ 0x53, 0x46, 0x41, 0x54, 0x41, 0x4c, 0x00, /* Code */ 0x43,
            0x32, 0x38, 0x30, 0x30, 0x30, 0x00, /* Message */ 0x4d, 0x6e, 0x6f, 0x20, 0x70,
            0x67, 0x5f, 0x68, 0x62, 0x61, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x20, 0x65, 0x6e, 0x74,
            0x72, 0x79, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x72, 0x65, 0x70, 0x6c, 0x69, 0x63, 0x61,
            0x74, 0x69, 0x6f, 0x6e, 0x20, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f,
            0x6e, 0x20, 0x66, 0x72, 0x6f, 0x6d, 0x20, 0x68, 0x6f, 0x73, 0x74, 0x20, 0x22, 0x31,
            0x39, 0x32, 0x2e, 0x31, 0x36, 0x38, 0x2e, 0x35, 0x30, 0x2e, 0x31, 0x31, 0x22, 0x2c,
            0x20, 0x75, 0x73, 0x65, 0x72, 0x20, 0x22, 0x72, 0x65, 0x70, 0x22, 0x2c, 0x20, 0x53,
            0x53, 0x4c, 0x20, 0x6f, 0x66, 0x66, 0x00, /* File */ 0x46, 0x61, 0x75, 0x74, 0x68,
            0x2e, 0x63, 0x00, /* Line */ 0x4c, 0x34, 0x38, 0x31, 0x00,
            /* Routine */ 0x52, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x41, 0x75, 0x74, 0x68,
            0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x00, 0x00,
        ];
        // declare expected result

        let field1 = PgsqlErrorNoticeMessageField {
            field_type: PgsqlErrorNoticeFieldType::SeverityLocalizable,
            field_value: br#"FATAL"#.to_vec(),
        };
        let field2 = PgsqlErrorNoticeMessageField {
            field_type: PgsqlErrorNoticeFieldType::CodeSqlStateCode,
            field_value: br#"28000"#.to_vec(),
        };
        let field3 = PgsqlErrorNoticeMessageField {
            field_type: PgsqlErrorNoticeFieldType::Message,
            field_value: br#"no pg_hba.conf entry for replication connection from host "192.168.50.11", user "rep", SSL off"#.to_vec(),
        };
        let field4 = PgsqlErrorNoticeMessageField {
            field_type: PgsqlErrorNoticeFieldType::File,
            field_value: br#"auth.c"#.to_vec(),
        };
        let field5 = PgsqlErrorNoticeMessageField {
            field_type: PgsqlErrorNoticeFieldType::Line,
            field_value: br#"481"#.to_vec(),
        };
        let field6 = PgsqlErrorNoticeMessageField {
            field_type: PgsqlErrorNoticeFieldType::Routine,
            field_value: br#"ClientAuthentication"#.to_vec(),
        };
        let field7 = PgsqlErrorNoticeMessageField {
            field_type: PgsqlErrorNoticeFieldType::TerminatorToken,
            field_value: br#""#.to_vec(),
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

        let result = pgsql_parse_response(buf);
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
                // parser first tries to take whole message (length + identifier = 151), but buffer is incomplete
                assert_eq!(needed, Size(151));
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
            /* identifier R */ 0x52, /* length 28 */ 0x00, 0x00, 0x00, 0x1c,
            /* auth_type */ 0x00, 0x00, 0x00, 0x0a, /* SCRAM-SHA-256-PLUS */ 0x53, 0x43,
            0x52, 0x41, 0x4d, 0x2d, 0x53, 0x48, 0x41, 0x2d, 0x32, 0x35, 0x36, 0x2d, 0x50, 0x4c,
            0x55, 0x53, 0x00, 0x00,
        ];
        let mechanism = vec![SASLAuthenticationMechanism::ScramSha256Plus];
        let ok_res = PgsqlBEMessage::AuthenticationSASL(AuthenticationSASLMechanismMessage {
            identifier: b'R',
            length: 28,
            auth_type: 10,
            auth_mechanisms: mechanism,
        });

        let result = pgsql_parse_response(buf);
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
            /* identifier R */ 0x52, /* length 42 */ 0x00, 0x00, 0x00, 0x2a,
            /* auth_type */ 0x00, 0x00, 0x00, 0x0a, /* SCRAM-SHA-256-PLUS */ 0x53, 0x43,
            0x52, 0x41, 0x4d, 0x2d, 0x53, 0x48, 0x41, 0x2d, 0x32, 0x35, 0x36, 0x2d, 0x50, 0x4c,
            0x55, 0x53, 0x00, /* SCRAM-SHA-256 */ 0x53, 0x43, 0x52, 0x41, 0x4d, 0x2d, 0x53,
            0x48, 0x41, 0x2d, 0x32, 0x35, 0x36, 0x00, 0x00,
        ];
        let mechanism = vec![
            SASLAuthenticationMechanism::ScramSha256Plus,
            SASLAuthenticationMechanism::ScramSha256,
        ];
        let ok_res = PgsqlBEMessage::AuthenticationSASL(AuthenticationSASLMechanismMessage {
            identifier: b'R',
            length: 42,
            auth_type: 10,
            auth_mechanisms: mechanism,
        });

        let result = pgsql_parse_response(buf);
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
            Ok((_remainder, _message)) => panic!("Should not be Ok(_), expected Incomplete!"),
            Err(nom::Err::Error((_remainder, err))) => {
                panic!("Should not be error {:?}, expected Incomplete!", err)
            }
            Err(nom::Err::Incomplete(needed)) => assert_eq!(needed, Size(43)),
            _ => panic!("Unexpected behavior, expected Incomplete."),
        }
    }

    #[test]
    fn test_parse_sasl_continue_authentication_message() {
        // As found in: https://blog.hackeriet.no/Better-password-hashing-in-PostgreSQL/
        let buf: &[u8] = &[
            /* 'R' */ 0x52, /* 92 */ 0x00, 0x00, 0x00, 0x5c, /* 11 */ 0x00, 0x00,
            0x00, 0x0b, /* challenge data*/ 0x72, 0x3d, 0x2f, 0x7a, 0x2b, 0x67, 0x69, 0x5a,
            0x69, 0x54, 0x78, 0x41, 0x48, 0x37, 0x72, 0x38, 0x73, 0x4e, 0x41, 0x65, 0x48, 0x72,
            0x37, 0x63, 0x76, 0x70, 0x71, 0x56, 0x33, 0x75, 0x6f, 0x37, 0x47, 0x2f, 0x62, 0x4a,
            0x42, 0x49, 0x4a, 0x4f, 0x33, 0x70, 0x6a, 0x56, 0x4d, 0x37, 0x74, 0x33, 0x6e, 0x67,
            0x2c, 0x73, 0x3d, 0x34, 0x55, 0x56, 0x36, 0x38, 0x62, 0x49, 0x6b, 0x43, 0x38, 0x66,
            0x39, 0x2f, 0x58, 0x38, 0x78, 0x48, 0x37, 0x61, 0x50, 0x68, 0x67, 0x3d, 0x3d, 0x2c,
            0x69, 0x3d, 0x34, 0x30, 0x39, 0x36,
        ];

        let ok_res = PgsqlBEMessage::AuthenticationSASLContinue(
            AuthenticationMessage {
                identifier: b'R',
                length: 92,
                auth_type: 11,
                payload: br#"r=/z+giZiTxAH7r8sNAeHr7cvpqV3uo7G/bJBIJO3pjVM7t3ng,s=4UV68bIkC8f9/X8xH7aPhg==,i=4096"#.to_vec(),
        });

        let result = pgsql_parse_response(buf);
        match result {
            Ok((remainder, message)) => {
                assert_eq!(message, ok_res);
                assert_eq!(remainder.len(), 0);
            }
            Err(nom::Err::Error((_remainder, err))) => {
                panic!("Shouldn't be error {:?} expected Ok(_)", err)
            }
            Err(nom::Err::Incomplete(needed)) => {
                panic!("shouldn't be incomplete {:?}, expected Ok(_)", needed)
            }
            _ => panic!("Unexpected behavior, expected Ok(_)"),
        }

        let result_incomplete = pgsql_parse_response(&buf[0..31]);
        match result_incomplete {
            Ok((_remainder, _message)) => panic!("Should not be Ok(_), expected Incomplete!"),
            Err(nom::Err::Error((_remainder, err))) => {
                panic!("Shouldn't be error {:?} expected Incomplete!", err)
            }
            Err(nom::Err::Incomplete(needed)) => {
                assert_eq!(needed, Size(93));
            }
            _ => panic!("Unexpected behavior, expected Ok(_)"),
        }
    }

    #[test]
    fn test_parse_sasl_final_authentication_message() {
        let buf: &[u8] = &[
            /* R */ 0x52, /* 54 */ 0x00, 0x00, 0x00, 0x36, /* 12 */ 0x00, 0x00,
            0x00, 0x0c, /* signature */ 0x76, 0x3d, 0x64, 0x31, 0x50, 0x58, 0x61, 0x38, 0x54,
            0x4b, 0x46, 0x50, 0x5a, 0x72, 0x52, 0x33, 0x4d, 0x42, 0x52, 0x6a, 0x4c, 0x79, 0x33,
            0x2b, 0x4a, 0x36, 0x79, 0x78, 0x72, 0x66, 0x77, 0x2f, 0x7a, 0x7a, 0x70, 0x38, 0x59,
            0x54, 0x39, 0x65, 0x78, 0x56, 0x37, 0x73, 0x38, 0x3d,
        ];
        let ok_res = PgsqlBEMessage::AuthenticationSASLFinal(AuthenticationMessage {
            identifier: b'R',
            length: 54,
            auth_type: 12,
            payload: br#"v=d1PXa8TKFPZrR3MBRjLy3+J6yxrfw/zzp8YT9exV7s8="#.to_vec(),
        });

        let result = pgsql_parse_response(buf);
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
                assert_eq!(needed, Size(55));
            }
            _ => panic!("Unexpected behavior, expected incomplete."),
        }

        let bad_buf: &[u8] = &[
            /* ` */ 0x60, /* 54 */ 0x00, 0x00, 0x00, 0x36, /* 12 */ 0x00, 0x00,
            0x00, 0x0c, /* signature */ 0x76, 0x3d, 0x64, 0x31, 0x50, 0x58, 0x61, 0x38, 0x54,
            0x4b, 0x46, 0x50, 0x5a, 0x72, 0x52, 0x33, 0x4d, 0x42, 0x52, 0x6a, 0x4c, 0x79, 0x33,
            0x2b, 0x4a, 0x36, 0x79, 0x78, 0x72, 0x66, 0x77, 0x2f, 0x7a, 0x7a, 0x70, 0x38, 0x59,
            0x54, 0x39, 0x65, 0x78, 0x56, 0x37, 0x73, 0x38, 0x3d,
        ];
        let result_err = pgsql_parse_response(bad_buf);
        match result_err {
            Err(nom::Err::Error((_remainder, err))) => {
                assert_eq!(err, nom::error::ErrorKind::Switch);
            }
            Err(nom::Err::Incomplete(_)) => {
                panic!("Unexpected Incomplete, should be ErrorKind::Switch");
            }
            _ => panic!("Unexpected behavior, expected Error"),
        }
    }

    #[test]
    fn test_parse_sasl_frontend_messages() {
        // SASL Initial Response (as seen in https://blog.hackeriet.no/Better-password-hashing-in-PostgreSQL/)
        let buf: &[u8] = &[
            /* p */ 0x70, /* 54 */ 0x00, 0x00, 0x00, 0x36,
            /* sasl mechanism */ 0x53, 0x43, 0x52, 0x41, 0x4d, 0x2d, 0x53, 0x48, 0x41, 0x2d,
            0x32, 0x35, 0x36, 0x00, /* 32 */ 0x00, 0x00, 0x00, 0x20,
            /* FE 1st msg */ 0x6e, 0x2c, 0x2c, 0x6e, 0x3d, 0x2c, 0x72, 0x3d, 0x2f, 0x7a, 0x2b,
            0x67, 0x69, 0x5a, 0x69, 0x54, 0x78, 0x41, 0x48, 0x37, 0x72, 0x38, 0x73, 0x4e, 0x41,
            0x65, 0x48, 0x72, 0x37, 0x63, 0x76, 0x70,
        ];
        let ok_res = PgsqlFEMessage::SASLInitialResponse(SASLInitialResponsePacket {
            identifier: b'p',
            length: 54,
            auth_mechanism: SASLAuthenticationMechanism::ScramSha256,
            param_length: 32,
            sasl_param: br#"n,,n=,r=/z+giZiTxAH7r8sNAeHr7cvp"#.to_vec(),
        });

        let result = parse_sasl_initial_response(buf);
        match result {
            Ok((remainder, message)) => {
                assert_eq!(message, ok_res);
                assert_eq!(remainder.len(), 0);
            }
            Err(nom::Err::Error((_remainder, err))) => {
                panic!("Shouldn't be error {:?}, expected Ok(_)", err)
            }
            Err(nom::Err::Incomplete(needed)) => {
                panic!("Shouldn't be incomplete: {:?}, expected Ok(_)", needed)
            }
            _ => panic!("Unexpected behavior, expected Ok(_)"),
        }

        let buf: &[u8] = &[
            /* p */ 0x70, /* 108 */ 0x00, 0x00, 0x00, 0x6c, /* final msg*/ 0x63,
            0x3d, 0x62, 0x69, 0x77, 0x73, 0x2c, 0x72, 0x3d, 0x2f, 0x7a, 0x2b, 0x67, 0x69, 0x5a,
            0x69, 0x54, 0x78, 0x41, 0x48, 0x37, 0x72, 0x38, 0x73, 0x4e, 0x41, 0x65, 0x48, 0x72,
            0x37, 0x63, 0x76, 0x70, 0x71, 0x56, 0x33, 0x75, 0x6f, 0x37, 0x47, 0x2f, 0x62, 0x4a,
            0x42, 0x49, 0x4a, 0x4f, 0x33, 0x70, 0x6a, 0x56, 0x4d, 0x37, 0x74, 0x33, 0x6e, 0x67,
            0x2c, 0x70, 0x3d, 0x41, 0x46, 0x70, 0x53, 0x59, 0x48, 0x2f, 0x4b, 0x2f, 0x38, 0x62,
            0x75, 0x78, 0x31, 0x6d, 0x52, 0x50, 0x55, 0x77, 0x78, 0x54, 0x65, 0x38, 0x6c, 0x42,
            0x75, 0x49, 0x50, 0x45, 0x79, 0x68, 0x69, 0x2f, 0x37, 0x55, 0x46, 0x50, 0x51, 0x70,
            0x53, 0x72, 0x34, 0x41, 0x3d,
        ];

        let ok_res = PgsqlFEMessage::SASLResponse(
            RegularPacket {
                identifier: b'p',
                length: 108,
                payload: br#"c=biws,r=/z+giZiTxAH7r8sNAeHr7cvpqV3uo7G/bJBIJO3pjVM7t3ng,p=AFpSYH/K/8bux1mRPUwxTe8lBuIPEyhi/7UFPQpSr4A="#.to_vec(),
            });

        let result = parse_sasl_response(buf);
        match result {
            Ok((_remainder, message)) => {
                assert_eq!(message, ok_res);
            }
            Err(nom::Err::Error((_remainder, err))) => {
                panic!("Shouldn't be error: {:?} expected Ok(_)", err)
            }
            Err(nom::Err::Incomplete(needed)) => {
                panic!("Shouldn't be incomplete: {:?}, expected Ok(_)", needed)
            }
            _ => panic!("Unexpected behavior, should be Ok(_)"),
        }
    }

    // Test messages with fixed formats, like AuthenticationSSPI
    #[test]
    fn test_parse_simple_authentication_requests() {
        let buf: &[u8] = &[
            /* R */ 0x52, /* 8 */ 0x00, 0x00, 0x00, 0x08, /* 9 */ 0x00, 0x00, 0x00,
            0x09,
        ];

        let ok_res = PgsqlBEMessage::AuthenticationSSPI(AuthenticationMessage {
            identifier: b'R',
            length: 8,
            auth_type: 9,
            payload: Vec::<u8>::new(),
        });

        let (_remainder, result) = pgsql_parse_response(buf).unwrap();
        assert_eq!(result, ok_res);
    }

    #[test]
    fn test_parse_response() {
        // An SSL response - N
        let buf: &[u8] = &[0x4e];
        let response_ok = PgsqlBEMessage::SSLResponse(SSLResponseMessage::SSLRejected);
        let (_remainder, result) = parse_ssl_response(buf).unwrap();
        assert_eq!(result, response_ok);

        // An SSL response - S
        let buf: &[u8] = &[0x53];
        let response_ok = PgsqlBEMessage::SSLResponse(SSLResponseMessage::SSLAccepted);

        let (_remainder, result) = parse_ssl_response(buf).unwrap();
        assert_eq!(result, response_ok);

        // Not an SSL response
        let buf: &[u8] = &[0x52];
        let result = parse_ssl_response(buf);
        assert!(result.is_err());

        // - auth MD5
        let buf: &[u8] = &[
            0x52, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x05, 0xf2, 0x11, 0xa3, 0xed,
        ];
        let ok_res = PgsqlBEMessage::AuthenticationMD5Password(AuthenticationMessage {
            identifier: b'R',
            length: 12,
            auth_type: 5,
            payload: vec![0xf2, 0x11, 0xa3, 0xed],
        });
        let result = pgsql_parse_response(buf);
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
        let buf: &[u8] = &[0x52, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x03];
        let ok_res = PgsqlBEMessage::AuthenticationCleartextPassword(AuthenticationMessage {
            identifier: b'R',
            length: 8,
            auth_type: 3,
            payload: Vec::<u8>::new(),
        });
        let result = pgsql_parse_response(buf);
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

        let buf: &[u8] = &[0x52, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x03];
        let result = pgsql_parse_response(buf);
        assert!(result.is_err());

        // - auth Ok
        let buf: &[u8] = &[0x52, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00];
        let ok_res = PgsqlBEMessage::AuthenticationOk(AuthenticationMessage {
            identifier: b'R',
            length: 8,
            auth_type: 0,
            payload: Vec::<u8>::new(),
        });
        let result = pgsql_parse_response(buf);
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

    #[test]
    fn test_parse_row_description() {
        // RowDescription message
        // T  ..
        // source   @  .   .......  version   @  .   .......  sid   @  .   . .....
        let buffer: &[u8] = &[
            0x54, 0x00, 0x00, 0x00, 0x50, 0x00, 0x03, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x00,
            0x00, 0x00, 0x40, 0x09, 0x00, 0x01, 0x00, 0x00, 0x00, 0x19, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0x00, 0x00, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x00, 0x00, 0x00,
            0x40, 0x09, 0x00, 0x02, 0x00, 0x00, 0x00, 0x19, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x00, 0x73, 0x69, 0x64, 0x00, 0x00, 0x00, 0x40, 0x09, 0x00, 0x03, 0x00, 0x00,
            0x00, 0x14, 0x00, 0x08, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00,
        ];

        let field1 = RowField {
            field_name: br#"source"#.to_vec(),
            table_oid: 16393,
            column_index: 1,
            data_type_oid: 25,
            data_type_size: -1,
            type_modifier: -1,
            format_code: 0,
        };

        let field2 = RowField {
            field_name: br#"version"#.to_vec(),
            table_oid: 16393,
            column_index: 2,
            data_type_oid: 25,
            data_type_size: -1,
            type_modifier: -1,
            format_code: 0,
        };

        let field3 = RowField {
            field_name: br#"sid"#.to_vec(),
            table_oid: 16393,
            column_index: 3,
            data_type_oid: 20,
            data_type_size: 8,
            type_modifier: -1,
            format_code: 0,
        };

        let mut fields_vec = Vec::<RowField>::new();
        fields_vec.push(field1);
        fields_vec.push(field2);
        fields_vec.push(field3);

        let ok_res = PgsqlBEMessage::RowDescription(RowDescriptionMessage {
            identifier: b'T',
            length: 80,
            field_count: 3,
            fields: fields_vec,
        });

        let result = parse_row_description(buffer);

        match result {
            Ok((rem, response)) => {
                assert_eq!(response, ok_res);
                assert!(rem.is_empty());
            }
            Err(nom::Err::Incomplete(needed)) => {
                panic!("Should not be Incomplete! Needed: {:?}", needed);
            }
            Err(nom::Err::Error((rem, err))) => {
                println!("Remainder is: {:?}", rem);
                panic!("Shouldn't be error: {:?}", err);
            }
            _ => {
                panic!("Unexpected behavior");
            }
        }
    }

    #[test]
    fn test_parse_data_row() {
        let buffer: &[u8] = &[
            0x44, 0x00, 0x00, 0x00, 0x23, 0x00, 0x03, 0x00, 0x00, 0x00, 0x07, 0x65, 0x74, 0x2f,
            0x6f, 0x70, 0x65, 0x6e, 0x00, 0x00, 0x00, 0x03, 0x36, 0x2e, 0x30, 0x00, 0x00, 0x00,
            0x07, 0x32, 0x30, 0x32, 0x31, 0x37, 0x30, 0x31,
        ];

        // let mut rows_vec = Vec::<ColumnFieldValue>::new();

        // let field1 = ColumnFieldValue {
        //     value_length: 7,
        //     value: [0x65, 0x74, 0x2f, 0x6f, 0x70,0x65, 0x6e].to_vec(),
        // };
        // let field2 = ColumnFieldValue {
        //     value_length: 3,
        //     value: [0x36, 0x2e, 0x30].to_vec(),
        // };
        // let field3 = ColumnFieldValue {
        //     value_length: 7,
        //     value: [0x32, 0x30, 0x32, 0x31, 0x37, 0x30, 0x31].to_vec(),
        // };
        // rows_vec.push(field1);
        // rows_vec.push(field2);
        // rows_vec.push(field3);

        // let ok_res = PgsqlBEMessage::DataRow(
        //     DataRowMessage {
        //         identifier: b'D',
        //         length: 35,
        //         field_count: 3,
        //         fields: rows_vec,
        //     });

        // let result = parse_data_row(&buffer);

        // match result {
        //     Ok((rem, message)) => {
        //         assert_eq!(message, ok_res);
        //         assert!(rem.is_empty());
        //     },
        //     Err(nom::Err::Incomplete(needed)) => {
        //         panic!("Shouldn't be Incomplete! Expected Ok(). Needed: {:?}", needed);
        //     },
        //     Err(nom::Err::Error((rem, err))) => {
        //         println!("Remainder is {:?}", rem);
        //         panic!("Shouldn't be Err {:?}, expected Ok().", err);
        //     },
        //     _ => {
        //         panic!("Unexpected behavior, should be Ok()");
        //     }
        // }
        let result = dummy_parse_data_row(buffer);
        assert!(result.is_ok());
    }

    #[test]
    fn test_command_complete() {
        let buffer: &[u8] = &[
            0x43, 0x00, 0x00, 0x00, 0x0d, 0x53, 0x45, 0x4c, 0x45, 0x43, 0x54, 0x20, 0x33, 0x00,
        ];

        let ok_res = PgsqlBEMessage::CommandComplete(RegularPacket {
            identifier: b'C',
            length: 13,
            payload: b"SELECT 3\0".to_vec(),
        });

        let result = pgsql_parse_response(buffer);

        match result {
            Ok((rem, message)) => {
                assert_eq!(ok_res, message);
                assert!(rem.is_empty());
            }
            Err(nom::Err::Incomplete(needed)) => {
                panic!(
                    "Shouldn't be Incomplete! Expected Ok(). Needed: {:?}",
                    needed
                );
            }
            Err(nom::Err::Error((rem, err))) => {
                println!("Unparsed slice: {:?}", rem);
                panic!("Shouldn't be Error: {:?}, expected Ok()", err);
            }
            _ => {
                panic!("Unexpected behavior, should be Ok()");
            }
        }
    }
}
