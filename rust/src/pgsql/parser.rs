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

// Author: Juliana Fajardini <jufajardini@oisf.net>

//! PostgreSQL nom parsers

use crate::common::nom7::take_until_and_consume;
use nom7::branch::alt;
use nom7::bytes::streaming::{tag, take, take_until, take_until1};
use nom7::character::streaming::{alphanumeric1, char};
use nom7::combinator::{all_consuming, cond, eof, map_parser, opt, peek, rest, verify};
use nom7::error::{make_error, ErrorKind};
use nom7::multi::{many1, many_m_n, many_till};
use nom7::number::streaming::{be_i16, be_i32};
use nom7::number::streaming::{be_u16, be_u32, be_u8};
use nom7::sequence::{terminated, tuple};
use nom7::{Err, IResult};

pub const PGSQL_LENGTH_FIELD: u32 = 4;

pub const PGSQL_DUMMY_PROTO_MAJOR: u16 = 1234; // 0x04d2
pub const PGSQL_DUMMY_PROTO_MINOR_SSL: u16 = 5679; //0x162f
pub const _PGSQL_DUMMY_PROTO_MINOR_GSSAPI: u16 = 5680; // 0x1630

#[derive(Debug, PartialEq, Eq)]
pub enum PgsqlParameters {
    // startup parameters
    User,
    Database,
    Options,
    Replication,
    // runtime parameters
    ServerVersion,
    ServerEncoding,
    ClientEncoding,
    ApplicationName,
    DefaultTransactionReadOnly,
    InHotStandby,
    IsSuperuser,
    SessionAuthorization,
    DateStyle,
    IntervalStyle,
    TimeZone,
    IntegerDatetimes,
    StandardConformingStrings,
    UnknownParameter(Vec<u8>),
}

impl PgsqlParameters {
    pub fn to_str(&self) -> &str {
        match self {
            PgsqlParameters::User => "user",
            PgsqlParameters::Database => "database",
            PgsqlParameters::Options => "options",
            PgsqlParameters::Replication => "replication",
            PgsqlParameters::ServerVersion => "server_version",
            PgsqlParameters::ServerEncoding => "server_encoding",
            PgsqlParameters::ClientEncoding => "client_encoding",
            PgsqlParameters::ApplicationName => "application_name",
            PgsqlParameters::DefaultTransactionReadOnly => "default_transaction_read_only",
            PgsqlParameters::InHotStandby => "in_hot_standby",
            PgsqlParameters::IsSuperuser => "is_superuser",
            PgsqlParameters::SessionAuthorization => "session_authorization",
            PgsqlParameters::DateStyle => "date_style",
            PgsqlParameters::IntervalStyle => "interval_style",
            PgsqlParameters::TimeZone => "time_zone",
            PgsqlParameters::IntegerDatetimes => "integer_datetimes",
            PgsqlParameters::StandardConformingStrings => "standard_conforming_strings",
            PgsqlParameters::UnknownParameter(name) => {
                std::str::from_utf8(name).unwrap_or("unknown_parameter")
            }
        }
    }
}

impl From<&[u8]> for PgsqlParameters {
    fn from(name: &[u8]) -> Self {
        match name {
            br#"user"# => PgsqlParameters::User,
            br#"database"# => PgsqlParameters::Database,
            br#"options"# => PgsqlParameters::Options,
            br#"replication"# => PgsqlParameters::Replication,
            br#"server_version"# => PgsqlParameters::ServerVersion,
            br#"server_encoding"# => PgsqlParameters::ServerEncoding,
            br#"client_encoding"# => PgsqlParameters::ClientEncoding,
            br#"application_name"# => PgsqlParameters::ApplicationName,
            br#"default_transaction_read_only"# => PgsqlParameters::DefaultTransactionReadOnly,
            br#"in_hot_standby"# => PgsqlParameters::InHotStandby,
            br#"is_superuser"# => PgsqlParameters::IsSuperuser,
            br#"session_authorization"# => PgsqlParameters::SessionAuthorization,
            br#"DateStyle"# => PgsqlParameters::DateStyle,
            br#"IntervalStyle"# => PgsqlParameters::IntervalStyle,
            br#"TimeZone"# => PgsqlParameters::TimeZone,
            br#"integer_datetimes"# => PgsqlParameters::IntegerDatetimes,
            br#"standard_conforming_strings"# => PgsqlParameters::StandardConformingStrings,
            _ => PgsqlParameters::UnknownParameter(name.to_vec()),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct PgsqlParameter {
    pub name: PgsqlParameters,
    pub value: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct PgsqlStartupParameters {
    pub user: PgsqlParameter,
    pub optional_params: Option<Vec<PgsqlParameter>>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct DummyStartupPacket {
    length: u32,
    proto_major: u16,
    proto_minor: u16,
}

#[derive(Debug, PartialEq, Eq)]
pub struct StartupPacket {
    pub length: u32,
    pub proto_major: u16,
    pub proto_minor: u16,
    pub params: PgsqlStartupParameters,
}

#[derive(Debug, PartialEq, Eq)]
pub struct RegularPacket {
    pub identifier: u8,
    pub length: u32,
    pub payload: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct PgsqlErrorNoticeMessageField {
    pub field_type: PgsqlErrorNoticeFieldType,
    pub field_value: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
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

#[derive(Debug, PartialEq, Eq)]
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

#[derive(Debug, PartialEq, Eq)]
pub struct ParameterStatusMessage {
    pub identifier: u8,
    pub length: u32,
    pub param: PgsqlParameter,
}

#[derive(Debug, PartialEq, Eq)]
pub struct BackendKeyDataMessage {
    pub identifier: u8,
    pub length: u32,
    pub backend_pid: u32,
    pub secret_key: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ConsolidatedDataRowPacket {
    pub identifier: u8,
    pub length: u32,
    pub row_cnt: u16,
    pub data_size: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ReadyForQueryMessage {
    pub identifier: u8,
    pub length: u32,
    pub transaction_status: u8,
}

#[derive(Debug, PartialEq, Eq)]
pub struct NotificationResponse {
    pub identifier: u8,
    pub length: u32,
    pub pid: u32,
    // two str fields, one right after the other
    pub channel_name: Vec<u8>,
    pub payload: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
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
    ConsolidatedDataRow(ConsolidatedDataRowPacket),
    NotificationResponse(NotificationResponse),
    UnknownMessageType(RegularPacket),
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
            PgsqlBEMessage::SSLResponse(SSLResponseMessage::InvalidResponse) => {
                "invalid_be_message"
            }
            PgsqlBEMessage::ConsolidatedDataRow(_) => "data_row",
            PgsqlBEMessage::NotificationResponse(_) => "notification_response",
            PgsqlBEMessage::UnknownMessageType(_) => "unknown_message_type"
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

#[derive(Debug, PartialEq, Eq, Clone)]
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

#[derive(Debug, PartialEq, Eq)]
pub struct TerminationMessage {
    pub identifier: u8,
    pub length: u32,
}

#[derive(Debug, PartialEq, Eq)]
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

#[derive(Debug, PartialEq, Eq)]
pub struct AuthenticationMessage {
    pub identifier: u8,
    pub length: u32,
    pub auth_type: u32,
    pub payload: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct SASLInitialResponsePacket {
    pub identifier: u8,
    pub length: u32,
    pub auth_mechanism: SASLAuthenticationMechanism,
    pub param_length: u32,
    pub sasl_param: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct AuthenticationSASLMechanismMessage {
    identifier: u8,
    length: u32,
    auth_type: u32,
    auth_mechanisms: Vec<SASLAuthenticationMechanism>,
}

#[derive(Debug, PartialEq, Eq)]
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

#[derive(Debug, PartialEq, Eq)]
pub struct RowDescriptionMessage {
    pub identifier: u8,
    pub length: u32,
    pub field_count: u16,
    pub fields: Vec<RowField>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ColumnFieldValue {
    // Can be 0, or -1 as a special NULL column value
    pub value_length: i32,
    pub value: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
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
    // Indicates end of message
    TerminatorToken,
    // From the documentation: "Since more field types might be added in future, frontends should silently ignore fields of unrecognized type." For us, then, I think the best option is actually to print it as we parse it, so it is readable?
    UnknownFieldType,
}

impl PgsqlErrorNoticeFieldType {
    pub fn to_str(&self) -> &'static str {
        match self {
            PgsqlErrorNoticeFieldType::SeverityLocalizable => "severity_localizable",
            PgsqlErrorNoticeFieldType::SeverityNonLocalizable => "severity_non_localizable",
            PgsqlErrorNoticeFieldType::CodeSqlStateCode => "code",
            PgsqlErrorNoticeFieldType::Message => "message",
            PgsqlErrorNoticeFieldType::Detail => "detail",
            PgsqlErrorNoticeFieldType::Hint => "hint",
            PgsqlErrorNoticeFieldType::Position => "position",
            PgsqlErrorNoticeFieldType::InternalPosition => "internal_position",
            PgsqlErrorNoticeFieldType::InternalQuery => "internal_query",
            PgsqlErrorNoticeFieldType::Where => "where",
            PgsqlErrorNoticeFieldType::SchemaName => "schema_name",
            PgsqlErrorNoticeFieldType::TableName => "table_name",
            PgsqlErrorNoticeFieldType::ColumnName => "column_name",
            PgsqlErrorNoticeFieldType::DataType => "data_type",
            PgsqlErrorNoticeFieldType::ConstraintName => "constraint_name",
            PgsqlErrorNoticeFieldType::File => "file",
            PgsqlErrorNoticeFieldType::Line => "line",
            PgsqlErrorNoticeFieldType::Routine => "routine",
            PgsqlErrorNoticeFieldType::TerminatorToken => "",
            PgsqlErrorNoticeFieldType::UnknownFieldType => "unknown_field_type",
        }
    }
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

// Currently the set of parameters that could trigger a ParameterStatus message is fixed:
// server_version
// server_encoding
// client_encoding
// application_name
// default_transaction_read_only
// in_hot_standby
// is_superuser
// session_authorization
// DateStyle
// IntervalStyle
// TimeZone
// integer_datetimes
// standard_conforming_strings
// (source: PostgreSQL documentation)
// We may be interested, then, in controling this, somehow, to prevent weird things?
fn pgsql_parse_generic_parameter(i: &[u8]) -> IResult<&[u8], PgsqlParameter> {
    let (i, param_name) = take_until1("\x00")(i)?;
    let (i, _) = tag("\x00")(i)?;
    let (i, param_value) = take_until("\x00")(i)?;
    let (i, _) = tag("\x00")(i)?;
    Ok((i, PgsqlParameter {
        name: PgsqlParameters::from(param_name),
        value: param_value.to_vec(),
    }))
}

pub fn pgsql_parse_startup_parameters(i: &[u8]) -> IResult<&[u8], PgsqlStartupParameters> {
    let (i, mut optional) = opt(terminated(many1(pgsql_parse_generic_parameter), tag("\x00")))(i)?;
    if let Some(ref mut params) = optional {
        let mut user = PgsqlParameter{name: PgsqlParameters::User, value: Vec::new() };
        let mut index: usize = 0;
        for (j, p) in params.iter().enumerate() {
            if p.name == PgsqlParameters::User {
                user.value.extend_from_slice(&p.value);
                index = j;
            }
        }
        params.remove(index);
        if user.value.is_empty() {
            return Err(Err::Error(make_error(i, ErrorKind::Tag)));
        }
        return Ok((i, PgsqlStartupParameters{
            user,
            optional_params: if !params.is_empty() {
                optional
            } else { None },
        }));
    }
    return Err(Err::Error(make_error(i, ErrorKind::Tag)));
}

fn parse_sasl_initial_response_payload(i: &[u8]) -> IResult<&[u8], (SASLAuthenticationMechanism, u32, Vec<u8>)> {
    let (i, sasl_mechanism) = parse_sasl_mechanism(i)?;
    let (i, param_length) = be_u32(i)?;
    // From RFC 5802 - the client-first-message will always start w/
    // 'n', 'y' or 'p', otherwise it's invalid, I think we should check that, at some point
    let (i, param) = terminated(take(param_length), eof)(i)?;
    Ok((i, (sasl_mechanism, param_length, param.to_vec())))
}

pub fn parse_sasl_initial_response(i: &[u8]) -> IResult<&[u8], PgsqlFEMessage> {
    let (i, identifier) = verify(be_u8, |&x| x == b'p')(i)?;
    let (i, length) = verify(be_u32, |&x| x > PGSQL_LENGTH_FIELD)(i)?;
    let (i, payload) = map_parser(take(length - PGSQL_LENGTH_FIELD), parse_sasl_initial_response_payload)(i)?;
    Ok((i, PgsqlFEMessage::SASLInitialResponse(
                SASLInitialResponsePacket {
                    identifier,
                    length,
                    auth_mechanism: payload.0,
                    param_length: payload.1,
                    sasl_param: payload.2,
                })))
}

pub fn parse_sasl_response(i: &[u8]) -> IResult<&[u8], PgsqlFEMessage> {
    let (i, identifier) = verify(be_u8, |&x| x == b'p')(i)?;
    let (i, length) = verify(be_u32, |&x| x > PGSQL_LENGTH_FIELD)(i)?;
    let (i, payload) = take(length - PGSQL_LENGTH_FIELD)(i)?;
    let resp = PgsqlFEMessage::SASLResponse(
        RegularPacket {
            identifier,
            length,
            payload: payload.to_vec(),
        });
    Ok((i, resp))
}

pub fn pgsql_parse_startup_packet(i: &[u8]) -> IResult<&[u8], PgsqlFEMessage> {
    let (i, len) = verify(be_u32, |&x| x >= 8)(i)?;
    let (i, proto_major) = peek(be_u16)(i)?;
    let (i, b) = take(len - PGSQL_LENGTH_FIELD)(i)?;
    let (_, message) =
        match proto_major {
            1 | 2 | 3 => {
                let (b, proto_major) = be_u16(b)?;
                let (b, proto_minor) = be_u16(b)?;
                let (b, params) = pgsql_parse_startup_parameters(b)?;
                (b, PgsqlFEMessage::StartupMessage(StartupPacket{
                    length: len,
                    proto_major,
                    proto_minor,
                    params}))
            },
            PGSQL_DUMMY_PROTO_MAJOR => {
                let (b, proto_major) = be_u16(b)?;
                let (b, proto_minor) = all_consuming(be_u16)(b)?;
                let _message = match proto_minor {
                    PGSQL_DUMMY_PROTO_MINOR_SSL => (len, proto_major, proto_minor),
                    _ => return Err(Err::Error(make_error(b, ErrorKind::Switch))),
                };

                (b, PgsqlFEMessage::SSLRequest(DummyStartupPacket{
                    length: len,
                    proto_major,
                    proto_minor}))
            }
            _ => return Err(Err::Error(make_error(b, ErrorKind::Switch))),
        };
    Ok((i, message))
}

// TODO Decide if it's a good idea to offer GSS encryption support right now, as the documentation seems to have conflicting information...
// If we do:
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
pub fn parse_password_message(i: &[u8]) -> IResult<&[u8], PgsqlFEMessage> {
    let (i, identifier) = verify(be_u8, |&x| x == b'p')(i)?;
    let (i, length) = verify(be_u32, |&x| x >= PGSQL_LENGTH_FIELD)(i)?;
    let (i, password) = map_parser(
        take(length - PGSQL_LENGTH_FIELD),
        take_until1("\x00")
        )(i)?;
    Ok((i, PgsqlFEMessage::PasswordMessage(
                RegularPacket{
                    identifier,
                    length,
                    payload: password.to_vec(),
                })))
}

fn parse_simple_query(i: &[u8]) -> IResult<&[u8], PgsqlFEMessage> {
    let (i, identifier) = verify(be_u8, |&x| x == b'Q')(i)?;
    let (i, length) = verify(be_u32, |&x| x > PGSQL_LENGTH_FIELD)(i)?;
    let (i, query) = map_parser(take(length - PGSQL_LENGTH_FIELD), take_until1("\x00"))(i)?;
    Ok((i, PgsqlFEMessage::SimpleQuery(RegularPacket {
        identifier,
        length,
        payload: query.to_vec(),
    })))
}

fn parse_terminate_message(i: &[u8]) -> IResult<&[u8], PgsqlFEMessage> {
    let (i, identifier) = verify(be_u8, |&x| x == b'X')(i)?;
    let (i, length) = verify(be_u32, |&x| x == PGSQL_LENGTH_FIELD)(i)?;
    Ok((i, PgsqlFEMessage::Terminate(TerminationMessage { identifier, length })))
}

// Messages that begin with 'p' but are not password ones are not parsed here
pub fn parse_request(i: &[u8]) -> IResult<&[u8], PgsqlFEMessage> {
    let (i, tag) = peek(be_u8)(i)?;
    let (i, message) = match tag {
        b'\0' => pgsql_parse_startup_packet(i)?,
        b'Q' => parse_simple_query(i)?,
        b'X' => parse_terminate_message(i)?,
        _ => return Err(Err::Error(make_error(i, ErrorKind::Switch))),
    };
    Ok((i, message))
}

fn pgsql_parse_authentication_message<'a>(i: &'a [u8]) -> IResult<&'a [u8], PgsqlBEMessage> {
    let (i, identifier) = verify(be_u8, |&x| x == b'R')(i)?;
    let (i, length) = verify(be_u32, |&x| x >= 8)(i)?;
    let (i, auth_type) = be_u32(i)?;
    let (i, payload) = peek(rest)(i)?;
    let (i, message) = map_parser(
        take(length - 8),
        |b: &'a [u8]| {
            match auth_type {
                0 => Ok((b, PgsqlBEMessage::AuthenticationOk(
                            AuthenticationMessage {
                                identifier,
                                length,
                                auth_type,
                                payload: payload.to_vec(),
                            }))),
                3 => Ok((b, PgsqlBEMessage::AuthenticationCleartextPassword(
                            AuthenticationMessage {
                                identifier,
                                length,
                                auth_type,
                                payload: payload.to_vec(),
                            }))),
                5 => {
                    let (b, salt) = all_consuming(take(4_usize))(b)?;
                    Ok((b, PgsqlBEMessage::AuthenticationMD5Password(
                                AuthenticationMessage {
                                    identifier,
                                    length,
                                    auth_type,
                                    payload: salt.to_vec(),
                                })))
                }
                9 => Ok((b, PgsqlBEMessage::AuthenticationSSPI(
                            AuthenticationMessage {
                                identifier,
                                length,
                                auth_type,
                                payload: payload.to_vec(),
                            }))),
                // TODO - For SASL, should we parse specific details of the challenge itself? (as seen in: https://github.com/launchbadge/sqlx/blob/master/sqlx-core/src/postgres/message/authentication.rs )
                10 => {
                    let (b, auth_mechanisms) = parse_sasl_mechanisms(b)?;
                    Ok((b, PgsqlBEMessage::AuthenticationSASL(
                                AuthenticationSASLMechanismMessage {
                                    identifier,
                                    length,
                                    auth_type,
                                    auth_mechanisms,
                                })))
                }
                11 => {
                    let (b, sasl_challenge) = rest(i)?;
                    Ok((b, PgsqlBEMessage::AuthenticationSASLContinue(
                                AuthenticationMessage {
                                    identifier,
                                    length,
                                    auth_type,
                                    payload: sasl_challenge.to_vec(),
                                })))
                },
                12 => {
                    let (i, signature) = take(length - 8)(i)?;
                    Ok((i, PgsqlBEMessage::AuthenticationSASLFinal(
                                AuthenticationMessage {
                                    identifier,
                                    length,
                                    auth_type,
                                    payload: signature.to_vec(),
                                }
                                )))
                }
                // TODO add other authentication messages
                _ => return Err(Err::Error(make_error(i, ErrorKind::Switch))),
            }
        }
    )(i)?;
    Ok((i, message))
}

fn parse_parameter_status_message(i: &[u8]) -> IResult<&[u8], PgsqlBEMessage> {
    let (i, identifier) = verify(be_u8, |&x| x == b'S')(i)?;
    let (i, length) = verify(be_u32, |&x| x >= PGSQL_LENGTH_FIELD)(i)?;
    let (i, param) = map_parser(take(length - PGSQL_LENGTH_FIELD), pgsql_parse_generic_parameter)(i)?;
    Ok((i, PgsqlBEMessage::ParameterStatus(ParameterStatusMessage {
        identifier,
        length,
        param,
    })))
}

pub fn parse_ssl_response(i: &[u8]) -> IResult<&[u8], PgsqlBEMessage> {
    let (i, tag) = alt((char('N'), char('S')))(i)?;
    Ok((i, PgsqlBEMessage::SSLResponse(
                SSLResponseMessage::from(tag))
       ))
}

fn parse_backend_key_data_message(i: &[u8]) -> IResult<&[u8], PgsqlBEMessage> {
    let (i, identifier) = verify(be_u8, |&x| x == b'K')(i)?;
    let (i, length) = verify(be_u32, |&x| x == 12)(i)?;
    let (i, pid) = be_u32(i)?;
    let (i, secret_key) = be_u32(i)?;
    Ok((i, PgsqlBEMessage::BackendKeyData(BackendKeyDataMessage {
        identifier,
        length,
        backend_pid: pid,
        secret_key,
    })))
}

fn parse_command_complete(i: &[u8]) -> IResult<&[u8], PgsqlBEMessage> {
    let (i, identifier) = verify(be_u8, |&x| x == b'C')(i)?;
    let (i, length) = verify(be_u32, |&x| x > PGSQL_LENGTH_FIELD)(i)?;
    let (i, payload) = map_parser(take(length - PGSQL_LENGTH_FIELD), take_until("\x00"))(i)?;
    Ok((i, PgsqlBEMessage::CommandComplete(RegularPacket {
        identifier,
        length,
        payload: payload.to_vec(),
    })))
}

fn parse_ready_for_query(i: &[u8]) -> IResult<&[u8], PgsqlBEMessage> {
    let (i, identifier) = verify(be_u8, |&x| x == b'Z')(i)?;
    let (i, length) = verify(be_u32, |&x| x == 5)(i)?;
    let (i, status) = verify(be_u8, |&x| x == b'I' || x == b'T' || x == b'E')(i)?;
    Ok((i, PgsqlBEMessage::ReadyForQuery(ReadyForQueryMessage {
        identifier,
        length,
        transaction_status: status,
    })))
}

fn parse_row_field(i: &[u8]) -> IResult<&[u8], RowField> {
    let (i, field_name) = take_until1("\x00")(i)?;
    let (i, _) = tag("\x00")(i)?;
    let (i, table_oid) = be_u32(i)?;
    let (i, column_index) = be_u16(i)?;
    let (i, data_type_oid) = be_u32(i)?;
    let (i, data_type_size) = be_i16(i)?;
    let (i, type_modifier) = be_i32(i)?;
    let (i, format_code) = be_u16(i)?;
    Ok((i, RowField {
        field_name: field_name.to_vec(),
        table_oid,
        column_index,
        data_type_oid,
        data_type_size,
        type_modifier,
        format_code,
    }))
}

pub fn parse_row_description(i: &[u8]) -> IResult<&[u8], PgsqlBEMessage> {
    let (i, identifier) = verify(be_u8, |&x| x == b'T')(i)?;
    let (i, length) = verify(be_u32, |&x| x > 6)(i)?;
    let (i, field_count) = be_u16(i)?;
    let (i, fields) = map_parser(
        take(length - 6),
        many_m_n(0, field_count.into(), parse_row_field)
    )(i)?;
    Ok((i, PgsqlBEMessage::RowDescription(
                RowDescriptionMessage {
                    identifier,
                    length,
                    field_count,
                    fields,
                })))
}

fn parse_data_row_value(i: &[u8]) -> IResult<&[u8], ColumnFieldValue> {
    let (i, value_length) = be_i32(i)?;
    let (i, value) = cond(value_length >= 0, take(value_length as usize))(i)?;
    Ok((i, ColumnFieldValue {
        value_length,
        value: {
            match value {
                Some(data) => data.to_vec(),
                None => [].to_vec(),
            }
        },
    }))
}

/// For each column, add up the data size. Return the total
fn add_up_data_size(columns: Vec<ColumnFieldValue>) -> u64 {
    let mut data_size: u64 = 0;
    for field in columns {
        // -1 value means data value is NULL, let's not add that up
        if field.value_length > 0 {
            data_size += field.value_length as u64;
        }
    }
    data_size
}

// Currently, we don't store the actual DataRow messages, as those could easily become a burden, memory-wise
// We use ConsolidatedDataRow to store info we still want to log: message size.
// Later on, we calculate the number of lines the command actually returned by counting ConsolidatedDataRow messages
pub fn parse_consolidated_data_row(i: &[u8]) -> IResult<&[u8], PgsqlBEMessage> {
    let (i, identifier) = verify(be_u8, |&x| x == b'D')(i)?;
    let (i, length) = verify(be_u32, |&x| x >= 6)(i)?;
    let (i, field_count) = be_u16(i)?;
    // 6 here is for skipping length + field_count
    let (i, rows) = map_parser(take(length - 6), many_m_n(0, field_count.into(), parse_data_row_value))(i)?;
    Ok((i, PgsqlBEMessage::ConsolidatedDataRow(
                ConsolidatedDataRowPacket {
                    identifier,
                    length,
                    row_cnt: 1,
                    data_size: add_up_data_size(rows),
                }
                )))
}

fn parse_sasl_mechanism(i: &[u8]) -> IResult<&[u8], SASLAuthenticationMechanism> {
    let res: IResult<_, _, ()> = terminated(tag("SCRAM-SHA-256-PLUS"), tag("\x00"))(i);
    if let Ok((i, _)) = res {
        return Ok((i, SASLAuthenticationMechanism::ScramSha256Plus));
    }
    let res: IResult<_, _, ()> = terminated(tag("SCRAM-SHA-256"), tag("\x00"))(i);
    if let Ok((i, _)) = res {
        return Ok((i, SASLAuthenticationMechanism::ScramSha256));
    }
    return Err(Err::Error(make_error(i, ErrorKind::Alt)));
}

fn parse_sasl_mechanisms(i: &[u8]) -> IResult<&[u8], Vec<SASLAuthenticationMechanism>> {
    terminated(many1(parse_sasl_mechanism), tag("\x00"))(i)
}

pub fn parse_error_response_code(i: &[u8]) -> IResult<&[u8], PgsqlErrorNoticeMessageField> {
    let (i, _field_type) = char('C')(i)?;
    let (i, field_value) = map_parser(take(6_usize), alphanumeric1)(i)?;
    Ok((i, PgsqlErrorNoticeMessageField{
        field_type: PgsqlErrorNoticeFieldType::CodeSqlStateCode,
        field_value: field_value.to_vec(),
    }))
}

// Parse an error response with non-localizeable severity message.
// Possible values: ERROR, FATAL, or PANIC
pub fn parse_error_response_severity(i: &[u8]) -> IResult<&[u8], PgsqlErrorNoticeMessageField> {
    let (i, field_type) = char('V')(i)?;
    let (i, field_value) = alt((tag("ERROR"), tag("FATAL"), tag("PANIC")))(i)?;
    let (i, _) = tag("\x00")(i)?;
    Ok((i, PgsqlErrorNoticeMessageField{
        field_type: PgsqlErrorNoticeFieldType::from(field_type),
        field_value: field_value.to_vec(),
    }))
}

// The non-localizable version of Severity field has different values,
// in case of a notice: 'WARNING', 'NOTICE', 'DEBUG', 'INFO' or 'LOG'
pub fn parse_notice_response_severity(i: &[u8]) -> IResult<&[u8], PgsqlErrorNoticeMessageField> {
    let (i, field_type) = char('V')(i)?;
    let (i, field_value) = alt((
            tag("WARNING"),
            tag("NOTICE"),
            tag("DEBUG"),
            tag("INFO"),
            tag("LOG")))(i)?;
    let (i, _) = tag("\x00")(i)?;
    Ok((i, PgsqlErrorNoticeMessageField{
        field_type: PgsqlErrorNoticeFieldType::from(field_type),
        field_value: field_value.to_vec(),
    }))
}

pub fn parse_error_response_field(
    i: &[u8], is_err_msg: bool,
) -> IResult<&[u8], PgsqlErrorNoticeMessageField> {
    let (i, field_type) = peek(be_u8)(i)?;
    let (i, data) = match field_type {
        b'V' => {
            if is_err_msg {
                parse_error_response_severity(i)?
            } else {
                parse_notice_response_severity(i)?
            }
        }
        b'C' => parse_error_response_code(i)?,
        _ => {
            let (i, field_type) = be_u8(i)?;
            let (i, field_value) = take_until("\x00")(i)?;
            let (i, _just_tag) = tag("\x00")(i)?;
            let message = PgsqlErrorNoticeMessageField {
                field_type: PgsqlErrorNoticeFieldType::from(field_type),
                field_value: field_value.to_vec(),
            };
            return Ok((i, message));
        }
    };
    Ok((i, data))
}

pub fn parse_error_notice_fields(i: &[u8], is_err_msg: bool) -> IResult<&[u8], Vec<PgsqlErrorNoticeMessageField>> {
    let (i, data) = many_till(|b| parse_error_response_field(b, is_err_msg), tag("\x00"))(i)?;
    Ok((i, data.0))
}

fn pgsql_parse_error_response(i: &[u8]) -> IResult<&[u8], PgsqlBEMessage> {
    let (i, identifier) = verify(be_u8, |&x| x == b'E')(i)?;
    let (i, length) = verify(be_u32, |&x| x > 10)(i)?;
    let (i, message_body) = map_parser(
        take(length - PGSQL_LENGTH_FIELD),
        |b| parse_error_notice_fields(b, true)
        )(i)?;

    Ok((i, PgsqlBEMessage::ErrorResponse(ErrorNoticeMessage {
        identifier,
        length,
        message_body,
    })))
}

fn pgsql_parse_notice_response(i: &[u8]) -> IResult<&[u8], PgsqlBEMessage> {
    let (i, identifier) = verify(be_u8, |&x| x == b'N')(i)?;
    let (i, length) = verify(be_u32, |&x| x > 10)(i)?;
    let (i, message_body) = map_parser(
        take(length - PGSQL_LENGTH_FIELD),
        |b| parse_error_notice_fields(b, false)
        )(i)?;
    Ok((i, PgsqlBEMessage::NoticeResponse(ErrorNoticeMessage {
        identifier,
        length,
        message_body,
    })))
}

fn parse_notification_response(i: &[u8]) -> IResult<&[u8], PgsqlBEMessage> {
    let (i, identifier) = verify(be_u8, |&x| x == b'A')(i)?;
    // length (u32) + pid (u32) + at least one byte, for we have two str fields
    let (i, length) = verify(be_u32, |&x| x > 9)(i)?;
    let (i, data) = map_parser(
        take(length - PGSQL_LENGTH_FIELD),
        |b| {
            let (b, pid) = be_u32(b)?;
            let (b, channel_name) = take_until_and_consume(b"\x00")(b)?;
            let (b, payload) = take_until_and_consume(b"\x00")(b)?;
            Ok((b, (pid, channel_name, payload)))
        })(i)?;
    let msg = PgsqlBEMessage::NotificationResponse(NotificationResponse{
        identifier,
        length,
        pid: data.0,
        channel_name: data.1.to_vec(),
        payload: data.2.to_vec(),
    });
    Ok((i, msg))
}

pub fn pgsql_parse_response(i: &[u8]) -> IResult<&[u8], PgsqlBEMessage> {
    let (i, pseudo_header) = peek(tuple((be_u8, be_u32)))(i)?;
    let (i, message) =
            match pseudo_header.0 {
                b'E' => pgsql_parse_error_response(i)?,
                b'K' => parse_backend_key_data_message(i)?,
                b'N' => pgsql_parse_notice_response(i)?,
                b'R' => pgsql_parse_authentication_message(i)?,
                b'S' => parse_parameter_status_message(i)?,
                b'C' => parse_command_complete(i)?,
                b'Z' => parse_ready_for_query(i)?,
                b'T' => parse_row_description(i)?,
                b'A' => parse_notification_response(i)?,
                b'D' => parse_consolidated_data_row(i)?,
                // _ => return Err(Err::Error(make_error(i, ErrorKind::Switch))),
                _ => {
                    let (i, payload) = rest(i)?;
                    let unknown = PgsqlBEMessage::UnknownMessageType (RegularPacket{
                        identifier: pseudo_header.0,
                        length: pseudo_header.1,
                        payload: payload.to_vec(),
                    });
                    (i, unknown)
                }

            };
    Ok((i, message))
}

#[cfg(test)]
mod tests {

    use super::*;
    use nom7::Needed;

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
            Err(Err::Error(err)) => {
                panic!("Result should not be an error: {:?}.", err.code);
            }
            Err(Err::Incomplete(_)) => {
                panic!("Result should not have been incomplete.");
            }
            _ => {
                panic!("Unexpected behavior!");
            }
        }

        // A valid startup message/request without optional parameters
        // ...&....user.oryx.database.mailstore..
        let buf: &[u8] = &[
            0x00, 0x00, 0x00, 0x26, 0x00, 0x03, 0x00, 0x00, 0x75, 0x73, 0x65, 0x72, 0x00, 0x6f,
            0x72, 0x79, 0x78, 0x00, 0x64, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65, 0x00, 0x6d,
            0x61, 0x69, 0x6c, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x00, 0x00,
        ];
        let user = PgsqlParameter {
            name: PgsqlParameters::User,
            value: br#"oryx"#.to_vec(),
        };
        let database = PgsqlParameter {
            name: PgsqlParameters::Database,
            value: br#"mailstore"#.to_vec(),
        };
        let mut database_param: Vec<PgsqlParameter> = Vec::new();
        database_param.push(database);
        let params = PgsqlStartupParameters {
            user,
            optional_params: Some(database_param),
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
            Err(Err::Error(err)) => {
                panic!("Shouldn't be error: {:?}", err.code);
            }
            Err(Err::Incomplete(needed)) => {
                panic!("Should not be Incomplete! Needed: {:?}", needed);
            }
            _ => {
                panic!("Unexpected behavior");
            }
        }

        // A valid startup message/request without any optional parameters
        // ........user.oryx..
        let buf: &[u8] = &[
            0x00, 0x00, 0x00, 0x13, 0x00, 0x03, 0x00, 0x00, 0x75, 0x73, 0x65, 0x72, 0x00, 0x6f,
            0x72, 0x79, 0x78, 0x00, 0x00,
        ];
        let user = PgsqlParameter {
            name: PgsqlParameters::User,
            value: br#"oryx"#.to_vec(),
        };
        let params = PgsqlStartupParameters {
            user,
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
            Err(Err::Error(err)) => {
                panic!("Shouldn't be error: {:?}", err.code);
            }
            Err(Err::Incomplete(needed)) => {
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

        let (remainder, result) = parse_error_response_field(input, true).unwrap();
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

        let (remainder, result) = parse_error_response_field(input, true).unwrap();
        assert_eq!(result, ok_res);
        assert_eq!(remainder.len(), 0);

        // if incomplete, here we should get an error
        let result = parse_error_response_field(&input[0..12], true);
        assert!(result.is_err());

        // C28000
        let input: &[u8] = &[0x43, 0x32, 0x38, 0x30, 0x30, 0x30, 0x00];
        let value_str = "28000".as_bytes();
        let ok_res = PgsqlErrorNoticeMessageField {
            field_type: PgsqlErrorNoticeFieldType::CodeSqlStateCode,
            field_value: value_str.to_vec(),
        };
        let (remainder, result) = parse_error_response_field(input, true).unwrap();
        assert_eq!(result, ok_res);
        assert_eq!(remainder.len(), 0);
    }

    // After sending AuthenticationOk, the backend will send a series of messages with parameters, a backend key message, and finally a ready for query message
    #[test]
    fn test_parse_startup_phase_wrapup() {
        // S   .application_name psql
        let buf: &[u8] = &[
            0x53, 0x00, 0x00, 0x00, 0x1a, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69,
            0x6f, 0x6e, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x00, 0x70, 0x73, 0x71, 0x6c, 0x00,
        ];

        let ok_res = PgsqlBEMessage::ParameterStatus(ParameterStatusMessage {
            identifier: b'S',
            length: 26,
            param: PgsqlParameter {
                name: PgsqlParameters::ApplicationName,
                value: br#"psql"#.to_vec(),
            },
        });

        let (_remainder, result) = parse_parameter_status_message(buf).unwrap();
        assert_eq!(result, ok_res);

        let result = pgsql_parse_response(buf);
        match result {
            Ok((_remainder, message)) => {
                assert_eq!(message, ok_res);
            }
            Err(Err::Error(err)) => {
                panic!(
                    "Shouldn't be err {:?}, expected Ok(_). Remainder is: {:?} ",
                    err.code, err.input
                );
            }
            Err(Err::Incomplete(needed)) => {
                panic!("Should not be incomplete {:?}, expected Ok(_)", needed);
            }
            _ => panic!("Unexpected behavior, expected Ok(_)"),
        }

        // S   .integer_datetimes on
        let buf: &[u8] = &[
            0x53, 0x00, 0x00, 0x00, 0x19, 0x69, 0x6e, 0x74, 0x65, 0x67, 0x65, 0x72, 0x5f, 0x64,
            0x61, 0x74, 0x65, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x00, 0x6f, 0x6e, 0x00,
        ];
        let result = parse_parameter_status_message(buf);
        assert!(result.is_ok());

        // K       =.... // PID 61 Key 3152142766
        let buf: &[u8] = &[
            0x4b, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x3d, 0xbb, 0xe1, 0xe1, 0xae,
        ];

        let result = parse_backend_key_data_message(buf);
        assert!(result.is_ok());

        // Z   .I
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
        // let field4 = PgsqlErrorNoticeMessageField {
        //     field_type: PgsqlErrorNoticeFieldType::TerminatorToken,
        //     field_value: br#""#.to_vec(),
        // };

        let mut ok_res: Vec<PgsqlErrorNoticeMessageField> = Vec::new();
        ok_res.push(field1);
        // ok_res.push(field4);

        let (remainder, result) = parse_error_notice_fields(input, true).unwrap();
        assert_eq!(result, ok_res);
        assert_eq!(remainder.len(), 0);
        // ok_res.pop();

        ok_res.push(field2);
        ok_res.push(field3);

        // let field4 = PgsqlErrorNoticeMessageField {
        //     field_type: PgsqlErrorNoticeFieldType::TerminatorToken,
        //     field_value: br#""#.to_vec(),
        // };

        // ok_res.push(field4);

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

        let (remainder, result) = parse_error_notice_fields(input, true).unwrap();
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

        let result = parse_error_notice_fields(input, true);
        assert!(result.is_ok());

        let result = parse_error_notice_fields(&input[0..12], true);
        match result {
            Ok((_remainder, _message)) => panic!("Result should not be ok, but incomplete."),

            Err(Err::Error(err)) => {
                panic!("Shouldn't be error: {:?}", err.code);
            }
            Err(Err::Incomplete(needed)) => {
                assert_eq!(needed, Needed::new(2));
            }
            _ => panic!("Unexpected behavior."),
        }
    }

    #[test]
    fn test_parse_error_notice_response() {
        // test case buffer
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

        // expected result
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

        let mut payload = ErrorNoticeMessage::new(b'E', 150);
        payload.message_body.push(field1);
        payload.message_body.push(field2);
        payload.message_body.push(field3);
        payload.message_body.push(field4);
        payload.message_body.push(field5);
        payload.message_body.push(field6);

        let ok_res = PgsqlBEMessage::ErrorResponse(payload);

        let result = pgsql_parse_response(buf);
        match result {
            Ok((remainder, message)) => {
                assert_eq!(message, ok_res);
                assert_eq!(remainder.len(), 0);
            }
            Err(Err::Error(err)) => {
                panic!("Shouldn't be error: {:?}", err.code);
            }
            Err(Err::Incomplete(needed)) => {
                panic!("Should not be Incomplete! Needed: {:?}", needed);
            }
            _ => {
                panic!("Unexpected behavior");
            }
        }

        let result_incomplete = pgsql_parse_response(&buf[0..22]);
        match result_incomplete {
            Err(Err::Incomplete(needed)) => {
                // parser first tries to take whole message (length + identifier = 151), but buffer is incomplete
                assert_eq!(needed, Needed::new(129));
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
    fn test_parse_notice_response() {
        // N   .SDEBUG VDEBUG C23505 Mduplicate key value violates unique constraint "unique_a" DKey (a)=(mea5) already exists. Fnbtinsert.c L397 R_bt_check_unique
        let buf: &[u8] = &[
            0x4e, 0x00, 0x00, 0x00, 0x99, 0x53, 0x44, 0x45, 0x42, 0x55, 0x47, 0x00, 0x56, 0x44,
            0x45, 0x42, 0x55, 0x47, 0x00, 0x43, 0x32, 0x33, 0x35, 0x30, 0x35, 0x00, 0x4d, 0x64,
            0x75, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x65, 0x20, 0x6b, 0x65, 0x79, 0x20, 0x76,
            0x61, 0x6c, 0x75, 0x65, 0x20, 0x76, 0x69, 0x6f, 0x6c, 0x61, 0x74, 0x65, 0x73, 0x20,
            0x75, 0x6e, 0x69, 0x71, 0x75, 0x65, 0x20, 0x63, 0x6f, 0x6e, 0x73, 0x74, 0x72, 0x61,
            0x69, 0x6e, 0x74, 0x20, 0x22, 0x75, 0x6e, 0x69, 0x71, 0x75, 0x65, 0x5f, 0x61, 0x22,
            0x00, 0x44, 0x4b, 0x65, 0x79, 0x20, 0x28, 0x61, 0x29, 0x3d, 0x28, 0x6d, 0x65, 0x61,
            0x35, 0x29, 0x20, 0x61, 0x6c, 0x72, 0x65, 0x61, 0x64, 0x79, 0x20, 0x65, 0x78, 0x69,
            0x73, 0x74, 0x73, 0x2e, 0x00, 0x46, 0x6e, 0x62, 0x74, 0x69, 0x6e, 0x73, 0x65, 0x72,
            0x74, 0x2e, 0x63, 0x00, 0x4c, 0x33, 0x39, 0x37, 0x00, 0x52, 0x5f, 0x62, 0x74, 0x5f,
            0x63, 0x68, 0x65, 0x63, 0x6b, 0x5f, 0x75, 0x6e, 0x69, 0x71, 0x75, 0x65, 0x00, 0x00,
        ];

        // expected result
        let field1 = PgsqlErrorNoticeMessageField {
            field_type: PgsqlErrorNoticeFieldType::SeverityLocalizable,
            field_value: br#"DEBUG"#.to_vec(),
        };
        let field2 = PgsqlErrorNoticeMessageField {
            field_type: PgsqlErrorNoticeFieldType::SeverityNonLocalizable,
            field_value: br#"DEBUG"#.to_vec(),
        };
        let field3 = PgsqlErrorNoticeMessageField {
            field_type: PgsqlErrorNoticeFieldType::CodeSqlStateCode,
            field_value: br#"23505"#.to_vec(),
        };
        let field4 = PgsqlErrorNoticeMessageField {
            field_type: PgsqlErrorNoticeFieldType::Message,
            field_value: br#"duplicate key value violates unique constraint "unique_a""#.to_vec(),
        };
        let field5 = PgsqlErrorNoticeMessageField {
            field_type: PgsqlErrorNoticeFieldType::Detail,
            field_value: br#"Key (a)=(mea5) already exists."#.to_vec(),
        };
        let field6 = PgsqlErrorNoticeMessageField {
            field_type: PgsqlErrorNoticeFieldType::File,
            field_value: br#"nbtinsert.c"#.to_vec(),
        };
        let field7 = PgsqlErrorNoticeMessageField {
            field_type: PgsqlErrorNoticeFieldType::Line,
            field_value: br#"397"#.to_vec(),
        };
        let field8 = PgsqlErrorNoticeMessageField {
            field_type: PgsqlErrorNoticeFieldType::Routine,
            field_value: br#"_bt_check_unique"#.to_vec(),
        };

        let mut payload = ErrorNoticeMessage::new(b'N', 153);
        payload.message_body.push(field1);
        payload.message_body.push(field2);
        payload.message_body.push(field3);
        payload.message_body.push(field4);
        payload.message_body.push(field5);
        payload.message_body.push(field6);
        payload.message_body.push(field7);
        payload.message_body.push(field8);

        let ok_res = PgsqlBEMessage::NoticeResponse(payload);

        let result = pgsql_parse_response(buf);
        match result {
            Ok((remainder, message)) => {
                assert_eq!(message, ok_res);
                assert_eq!(remainder.len(), 0);
            }
            Err(Err::Error(err)) => {
                panic!("Shouldn't be error: {:?}", err.code);
            }
            Err(Err::Incomplete(needed)) => {
                panic!("Should not be Incomplete! Needed: {:?} ", needed);
            }
            _ => {
                panic!("Unexpected behavior");
            }
        }
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
            Err(Err::Error(err)) => {
                panic!("Shouldn't be error: {:?}", err.code);
            }
            Err(Err::Incomplete(needed)) => {
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
            Err(Err::Error(err)) => {
                panic!("Shouldn't be error: {:?}", err.code);
            }
            Err(Err::Incomplete(needed)) => {
                panic!("Should not be Incomplete! Needed: {:?}", needed);
            }
            _ => {
                panic!("Unexpected behavior");
            }
        }

        let incomplete_result = pgsql_parse_response(&buf[0..27]);
        match incomplete_result {
            Ok((_remainder, _message)) => panic!("Should not be Ok(_), expected Incomplete!"),
            Err(Err::Error(err)) => {
                panic!("Should not be error {:?}, expected Incomplete!", err.code)
            }
            Err(Err::Incomplete(needed)) => assert_eq!(needed, Needed::new(16)),
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
            Err(Err::Error(err)) => {
                panic!("Shouldn't be error {:?} expected Ok(_)", err.code)
            }
            Err(Err::Incomplete(needed)) => {
                panic!("shouldn't be incomplete {:?}, expected Ok(_)", needed)
            }
            _ => panic!("Unexpected behavior, expected Ok(_)"),
        }

        let result_incomplete = pgsql_parse_response(&buf[0..31]);
        match result_incomplete {
            Ok((_remainder, _message)) => panic!("Should not be Ok(_), expected Incomplete!"),
            Err(Err::Error(err)) => {
                panic!("Shouldn't be error {:?} expected Incomplete!", err.code)
            }
            Err(Err::Incomplete(needed)) => {
                assert_eq!(needed, Needed::new(62));
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
            Err(Err::Error(err)) => {
                panic!("Shouldn't be error {:?}, expected Ok(_)", err.code);
            }
            Err(Err::Incomplete(needed)) => {
                panic!("Shouldn't be incomplete {:?}, expected OK(_)", needed);
            }
            _ => panic!("Unexpected behavior, expected Ok(_)"),
        }

        let result_incomplete = pgsql_parse_response(&buf[0..34]);
        match result_incomplete {
            Err(Err::Incomplete(needed)) => {
                assert_eq!(needed, Needed::new(21));
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
        let (remainder, result) = pgsql_parse_response(bad_buf).expect("parsing sasl final response failed");
        let res = PgsqlBEMessage::UnknownMessageType(RegularPacket {
            identifier: b'`',
            length: 54,
            payload: bad_buf.to_vec(),
        });
        assert_eq!(result, res);
        assert!(remainder.is_empty());
    }

    #[test]
    fn test_parse_sasl_frontend_messages() {
        // SASL Initial Response
        // (as seen in https://blog.hackeriet.no/Better-password-hashing-in-PostgreSQL/)
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
            Err(Err::Error(err)) => {
                panic!("Shouldn't be error {:?}, expected Ok(_)", err.code)
            }
            Err(Err::Incomplete(needed)) => {
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
            Err(Err::Error(err)) => {
                panic!("Shouldn't be error: {:?} expected Ok(_)", err.code)
            }
            Err(Err::Incomplete(needed)) => {
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
            Err(Err::Error(err)) => {
                panic!("Shouldn't be error: {:?}", err.code);
            }
            Err(Err::Incomplete(needed)) => {
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
            Err(Err::Error(err)) => {
                panic!("Shouldn't be error: {:?}", err.code);
            }
            Err(Err::Incomplete(needed)) => {
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
            Err(Err::Error(err)) => {
                panic!("Should not be error {:?}", err.code);
            }
            Err(Err::Incomplete(needed)) => {
                panic!("Should not be incomplete. Needed: {:?}", needed);
            }
            _ => {
                panic!("Unexpected behavior!");
            }
        }

        //A series of response messages from the backend:
        // R   ·    S   ·application_name
        // S   ·client_encoding UTF8 S   ·DateStyle ISO, MDY
        // S   &default_transaction_read_only off S   ·in_hot_standby off
        // S   ·integer_datetimes on S   ·IntervalStyle postgres
        // S   ·is_superuser off S   ·server_encoding UTF8
        // S   ·server_version 14.5 S   "session_authorization ctfpost
        // S   #standard_conforming_strings on S   ·TimeZone Europe/Paris
        // K      ···O··Z   ·I
        let buf = &[
            0x52, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
            0x00, 0x53, 0x00, 0x00, 0x00, 0x16, 0x61, 0x70,
            0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f,
            0x6e, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x00, 0x00,
            0x53, 0x00, 0x00, 0x00, 0x19, 0x63, 0x6c, 0x69,
            0x65, 0x6e, 0x74, 0x5f, 0x65, 0x6e, 0x63, 0x6f,
            0x64, 0x69, 0x6e, 0x67, 0x00, 0x55, 0x54, 0x46,
            0x38, 0x00, 0x53, 0x00, 0x00, 0x00, 0x17, 0x44,
            0x61, 0x74, 0x65, 0x53, 0x74, 0x79, 0x6c, 0x65,
            0x00, 0x49, 0x53, 0x4f, 0x2c, 0x20, 0x4d, 0x44,
            0x59, 0x00, 0x53, 0x00, 0x00, 0x00, 0x26, 0x64,
            0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x5f, 0x74,
            0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69,
            0x6f, 0x6e, 0x5f, 0x72, 0x65, 0x61, 0x64, 0x5f,
            0x6f, 0x6e, 0x6c, 0x79, 0x00, 0x6f, 0x66, 0x66,
            0x00, 0x53, 0x00, 0x00, 0x00, 0x17, 0x69, 0x6e,
            0x5f, 0x68, 0x6f, 0x74, 0x5f, 0x73, 0x74, 0x61,
            0x6e, 0x64, 0x62, 0x79, 0x00, 0x6f, 0x66, 0x66,
            0x00, 0x53, 0x00, 0x00, 0x00, 0x19, 0x69, 0x6e,
            0x74, 0x65, 0x67, 0x65, 0x72, 0x5f, 0x64, 0x61,
            0x74, 0x65, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x00,
            0x6f, 0x6e, 0x00, 0x53, 0x00, 0x00, 0x00, 0x1b,
            0x49, 0x6e, 0x74, 0x65, 0x72, 0x76, 0x61, 0x6c,
            0x53, 0x74, 0x79, 0x6c, 0x65, 0x00, 0x70, 0x6f,
            0x73, 0x74, 0x67, 0x72, 0x65, 0x73, 0x00, 0x53,
            0x00, 0x00, 0x00, 0x15, 0x69, 0x73, 0x5f, 0x73,
            0x75, 0x70, 0x65, 0x72, 0x75, 0x73, 0x65, 0x72,
            0x00, 0x6f, 0x66, 0x66, 0x00, 0x53, 0x00, 0x00,
            0x00, 0x19, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72,
            0x5f, 0x65, 0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e,
            0x67, 0x00, 0x55, 0x54, 0x46, 0x38, 0x00, 0x53,
            0x00, 0x00, 0x00, 0x18, 0x73, 0x65, 0x72, 0x76,
            0x65, 0x72, 0x5f, 0x76, 0x65, 0x72, 0x73, 0x69,
            0x6f, 0x6e, 0x00, 0x31, 0x34, 0x2e, 0x35, 0x00,
            0x53, 0x00, 0x00, 0x00, 0x22, 0x73, 0x65, 0x73,
            0x73, 0x69, 0x6f, 0x6e, 0x5f, 0x61, 0x75, 0x74,
            0x68, 0x6f, 0x72, 0x69, 0x7a, 0x61, 0x74, 0x69,
            0x6f, 0x6e, 0x00, 0x63, 0x74, 0x66, 0x70, 0x6f,
            0x73, 0x74, 0x00, 0x53, 0x00, 0x00, 0x00, 0x23,
            0x73, 0x74, 0x61, 0x6e, 0x64, 0x61, 0x72, 0x64,
            0x5f, 0x63, 0x6f, 0x6e, 0x66, 0x6f, 0x72, 0x6d,
            0x69, 0x6e, 0x67, 0x5f, 0x73, 0x74, 0x72, 0x69,
            0x6e, 0x67, 0x73, 0x00, 0x6f, 0x6e, 0x00, 0x53,
            0x00, 0x00, 0x00, 0x1a, 0x54, 0x69, 0x6d, 0x65,
            0x5a, 0x6f, 0x6e, 0x65, 0x00, 0x45, 0x75, 0x72,
            0x6f, 0x70, 0x65, 0x2f, 0x50, 0x61, 0x72, 0x69,
            0x73, 0x00, 0x4b, 0x00, 0x00, 0x00, 0x0c, 0x00,
            0x00, 0x0b, 0x8d, 0xcf, 0x4f, 0xb6, 0xcf, 0x5a,
            0x00, 0x00, 0x00, 0x05, 0x49
        ];

        let result = pgsql_parse_response(buf);
        assert!(result.is_ok());
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
            Err(Err::Incomplete(needed)) => {
                panic!("Should not be Incomplete! Needed: {:?}", needed);
            }
            Err(Err::Error(err)) => {
                println!("Remainder is: {:?}", err.input);
                panic!("Shouldn't be error: {:?}", err.code);
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

        let result = parse_consolidated_data_row(buffer);
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
            payload: b"SELECT 3".to_vec(),
        });

        let result = pgsql_parse_response(buffer);

        match result {
            Ok((rem, message)) => {
                assert_eq!(ok_res, message);
                assert!(rem.is_empty());
            }
            Err(Err::Incomplete(needed)) => {
                panic!(
                    "Shouldn't be Incomplete! Expected Ok(). Needed: {:?}",
                    needed
                );
            }
            Err(Err::Error(err)) => {
                println!("Unparsed slice: {:?}", err.input);
                panic!("Shouldn't be Error: {:?}, expected Ok()", err.code);
            }
            _ => {
                panic!("Unexpected behavior, should be Ok()");
            }
        }
    }

    #[test]
    fn test_parse_notification_response() {
        // Handcrafted notification response message, based on documentation specification
        // identifier: 'A'
        // length: 39
        // pid: 61
        // channel_name: test_channel
        // payload: Test notification
        let buf: &[u8] = &[
            0x41, 0x00, 0x00, 0x00, 0x27, 0x00, 0x00, 0x00, 0x3d, // test_channel
            0x74, 0x65, 0x73, 0x74, 0x5f, 0x63, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x00,
            // Test notification
            0x54, 0x65, 0x73, 0x74, 0x20, 0x6e, 0x6f, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74,
            0x69, 0x6f, 0x6e, 0x00,
        ];

        let ok_res = PgsqlBEMessage::NotificationResponse(NotificationResponse {
            identifier: b'A',
            length: 39,
            pid: 61,
            channel_name: br#"test_channel"#.to_vec(),
            payload: br#"Test notification"#.to_vec(),
        });

        let (_rem, result) = pgsql_parse_response(buf).unwrap();

        assert_eq!(ok_res, result);
    }
}
