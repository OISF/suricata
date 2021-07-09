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

use std;
use crate::jsonbuilder::{JsonBuilder, JsonError};
use crate::pgsql::pgsql::*;
use crate::pgsql::parser::*;

fn log_pgsql(tx: &PgsqlTransaction, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.set_uint("transaction id", tx.tx_id.into());
    if !tx.requests.is_empty() {
        if tx.requests.len() > 1 {
            js.open_array("requests")?;
            for request in &tx.requests {
                let jbr = log_request(&request)?;
                js.append_object(&jbr)?;
            }
            js.close()?;
        } else {
            let jbr = log_request(&tx.requests[0])?;
            js.set_object("request", &jbr)?;
        }
        if tx.responses.len() > 1 {
            js.open_array("responses")?;
            for response in &tx.responses {
                let jb = log_response(&response)?;
                js.append_object(&jb)?;
            }
            js.close()?;
        }
        else if !tx.responses.is_empty() {
            let jb = log_response(&tx.responses[0])?;
            js.set_object("response", &jb);
        }
    } else {
        SCLogNotice!("Suricata logging a transaction without finding its request id {:?}", &tx.tx_id);
        if !tx.responses.is_empty() {
            js.open_array("response")?;
            for response in &tx.responses {
                let jb = log_response(&response)?;
                js.append_object(&jb)?;
            }
            js.close()?;
        } else {
            js.set_string("request", "request is empty");
            js.set_string("response", "response is empty");
            SCLogNotice!("Warning, Suricata created an empty PGSQL transaction");
        }
    }
    Ok(())
}

fn log_request(req: &PgsqlFEMessage) -> Result<JsonBuilder, JsonError>
{
    let mut js = JsonBuilder::new_object();
    js.open_object(&req.get_message_type())?;
    match req {
        PgsqlFEMessage::StartupMessage(
            StartupPacket{
                length,
                proto_major,
                proto_minor,
                params}) =>
        {
            let proto = format!("{}.{}", proto_major, proto_minor);
            let len = (*length) as u64;
            js.set_uint("length", len)?;
            js.set_string("protocol version", &proto)?;
            let jb = log_pgsql_parameters(params)?;
            js.set_object("startup parameters", &jb)?;
        },
        PgsqlFEMessage::SslRequest(_) =>
        {
            js.set_string("message type", "SSL Request");
        },
        PgsqlFEMessage::SASLInitialResponse(
            SASLInitialResponsePacket{
                identifier,
                length,
                auth_mechanism,
                param_length,
                sasl_param,
            }) =>
        {
            let id = (*identifier) as char;
            js.set_string("identifier", &id.to_string())?;
            let len = (*length) as u64;
            js.set_uint("length", len)?;
            js.set_string("authentication mechanism", &auth_mechanism.to_string())?;
            js.set_string_from_bytes("sasl param", sasl_param)?;
        },
        PgsqlFEMessage::PasswordMessage(
            RegularPacket{
                identifier,
                length,
                payload,
            }) |
        PgsqlFEMessage::SASLResponse(
            RegularPacket{
                identifier,
                length,
                payload,
            }) |
        PgsqlFEMessage::SimpleQuery(
            RegularPacket{
                identifier,
                length,
                payload,
            }) =>
        {
            let id = (*identifier) as char;
            js.set_string("identifier", &id.to_string())?;
            let len = (*length) as u64;
            js.set_uint("length", len)?;
            js.set_string_from_bytes("payload", payload)?;
        },
        PgsqlFEMessage::Terminate(
            TerminationMessage{
                identifier,
                length,
            }) =>
        {
            let id = (*identifier) as char;
            js.set_string("identifier", &id.to_string())?;
            let len = (*length) as u64;
            js.set_uint("length", len)?;
        }
    }
    js.close()?;
    js.close()?;
    Ok(js)
}

fn log_response(res: &PgsqlBEMessage) -> Result<JsonBuilder, JsonError>
{
    let mut js = JsonBuilder::new_object();
    js.open_object(&res.get_message_type())?;
    match res {
        PgsqlBEMessage::SslResponse(message) =>
        {
            js.set_string("ssl response", &message.to_string())?;
        },
        PgsqlBEMessage::NoticeResponse(ErrorNoticeMessage{
            identifier,
            length,
            message_body,
        }) |
        PgsqlBEMessage::ErrorResponse(ErrorNoticeMessage{
            identifier,
            length,
            message_body,
        }) => {
            // TODO should I suppress the identifier, given that the object says what's the message type, already?
            let id = (*identifier) as char;
            js.set_string("identifier", &id.to_string())?;
            let len = (*length) as u64;
            js.set_uint("length", len)?;
            let jb = log_error_notice_field_types( message_body)?;
            js.set_object("message body", &jb)?;
        },
        PgsqlBEMessage::AuthenticationOk(AuthenticationMessage{
            identifier,
            length,
            auth_type,
            payload,
        }) |
        PgsqlBEMessage::AuthenticationKerb5(AuthenticationMessage{
            identifier,
            length,
            auth_type,
            payload,
        }) |
        PgsqlBEMessage::AuthenticationCleartextPassword(AuthenticationMessage{
            identifier,
            length,
            auth_type,
            payload,
        }) |
        PgsqlBEMessage::AuthenticationMD5Password(AuthenticationMessage{
            identifier,
            length,
            auth_type,
            payload,
        }) |
        PgsqlBEMessage::AuthenticationGSS(AuthenticationMessage{
            identifier,
            length,
            auth_type,
            payload,
        }) |
        PgsqlBEMessage::AuthenticationSSPI(AuthenticationMessage{
            identifier,
            length,
            auth_type,
            payload,
        }) |
        PgsqlBEMessage::AuthenticationGSSContinue(AuthenticationMessage{
            identifier,
            length,
            auth_type,
            payload,
        }) |
        PgsqlBEMessage::AuthenticationSASLFinal(AuthenticationMessage{
            identifier,
            length,
            auth_type,
            payload,
        }) => {
            let id = (*identifier) as char;
            js.set_string("identifier", &id.to_string())?;
            let len = (*length) as u64;
            js.set_uint("length", len)?;
            let at = (*auth_type) as u64;
            js.set_uint("auth_type", at)?;
            // TODO question - not sure what method to use here, the format printed doesn't look good
            js.set_string_from_bytes("payload", payload)?;
        },
        PgsqlBEMessage::AuthenticationSASL(_) => {
            js.set_string("authentication SASL", &res.to_string())?;
        },
        PgsqlBEMessage::AuthenticationSASLContinue(_) => {
            js.set_string("authentication SASL continue", &res.to_string())?;
        },
        PgsqlBEMessage::ParameterStatus(ParameterStatusMessage{
            identifier,
            length,
            param,
        }) => {
            let id = (*identifier) as char;
            js.set_string("identifier", &id.to_string())?;
            let len = (*length) as u64;
            js.set_uint("length", len)?;
            js.set_string_from_bytes("parameter name", &param.param_name)?;
            js.set_string_from_bytes("parameter value", &param.param_value)?;
        },
        PgsqlBEMessage::BackendKeyData(BackendKeyDataMessage{
            identifier,
            length,
            backend_pid,
            secret_key,
        }) => {
            let id = (*identifier) as char;
            js.set_string("identifier", &id.to_string())?;
            let len = (*length) as u64;
            js.set_uint("length", len)?;
            js.set_uint("process id", (*backend_pid) as u64)?;
            js.set_uint("secret key", (*secret_key) as u64)?;
        },
        PgsqlBEMessage::CommandComplete(
            RegularPacket{
                identifier,
                length,
                payload,
            }) =>
        {
            let id = (*identifier) as char;
            js.set_string("identifier", &id.to_string())?;
            let len = (*length) as u64;
            js.set_uint("length", len)?;
            // TODO this may result in not so pretty strings. not sure what to do
            //  example "SELECT 3\u0000"
            js.set_string_from_bytes("payload", payload)?;
        },
        PgsqlBEMessage::ReadyForQuery(ReadyForQueryMessage{
            identifier,
            length,
            transaction_status,
        }) => {
            let id = (*identifier) as char;
            js.set_string("identifier", &id.to_string())?;
            let len = (*length) as u64;
            js.set_uint("length", len)?;
            let tx_status = (*transaction_status) as char;
            js.set_string("transaction status", &tx_status.to_string());
        },
        PgsqlBEMessage::RowDescription(RowDescriptionMessage{
            identifier,
            length,
            field_count,
            fields,
        }) => {
            let id = (*identifier) as char;
            js.set_string("identifier", &id.to_string())?;
            let len = (*length) as u64;
            js.set_uint("length", len)?;
            let count = (*field_count) as u64;
            js.set_uint("field count", count)?;
            let jb = log_row_description(fields)?;
            js.set_object("columns", &jb)?;
        },
        PgsqlBEMessage::DataRow(DataRowMessage{
            identifier,
            length,
            field_count,
            fields,
        }) => {
            let id = (*identifier) as char;
            js.set_string("identifier", &id.to_string())?;
            let len = (*length) as u64;
            js.set_uint("length", len)?;
            let count = (*field_count) as u64;
            js.set_uint("field_count", count);
            let jb = log_data_row(fields)?;
            js.set_object("rows", &jb)?;
        },
    }
    js.close()?;
    js.close()?;
    Ok(js)
}

fn log_row_description(columns: &Vec<RowField>) -> Result<JsonBuilder, JsonError>
{
    let mut jb = JsonBuilder::new_object();
    let mut i = 0;
    for column in columns {
        let key = format!("column {}", i);
        jb.open_object(&key)?;
        jb.set_string_from_bytes("column name", &column.field_name)?;
        let toid = (*column).table_oid as u64;
        jb.set_uint("table oid", toid)?;
        let cix = (*column).data_type_oid as u64;
        jb.set_uint("column index", cix)?;
        jb.set_float("data type size", (*column).data_type_size as f64)?;
        jb.set_float("type modifier", (*column).type_modifier as f64)?;
        let fc = (*column).format_code as u64;
        jb.set_uint("format code", fc)?;
        jb.close()?;
        i = i + 1;
    }
    jb.close()?;
    Ok(jb)
}

fn log_data_row(rows: &Vec<ColumnFieldValue>) -> Result<JsonBuilder, JsonError>
{
    let mut jb = JsonBuilder::new_object();
    let mut i = 0;
    for row in rows {
        // JsonBuilder requires that keys are unique...
        let key = format!("row {}", i);
        jb.open_object(&key)?;
        if row.value_length >= 0 {
            let len = (*row).value_length as u64;
            jb.set_uint("column length", len)?;
            jb.set_string_from_bytes("data", &row.value)?;
        } else {
            jb.set_float("column length", row.value_length as f64)?;
            // When column_length is '-1', data is NULL. What's the best way to log it?
            jb.set_string_from_bytes("data", b"NULL")?;
        }
        i = i + 1;
        jb.close()?;
    }
    jb.close()?;
    Ok(jb)
}

// TODO rename this to make it generic for error responses and notice message
fn log_error_notice_field_types(error_fields: &Vec<PgsqlErrorNoticeMessageField>) -> Result<JsonBuilder, JsonError>
{
    let mut jb = JsonBuilder::new_object();
    for field in error_fields {
        match field.field_type {
            PgsqlErrorNoticeFieldType::SeverityLocalizable => {
                jb.set_string_from_bytes("severity", &field.field_value)?;
            },
            PgsqlErrorNoticeFieldType::SeverityNonLocalizable => {
                jb.set_string_from_bytes("severity", &field.field_value)?;
            },
            PgsqlErrorNoticeFieldType::CodeSqlStateCode => {
                jb.set_string_from_bytes("code", &field.field_value)?;
            },
            PgsqlErrorNoticeFieldType::Message => {
                jb.set_string_from_bytes("message", &field.field_value)?;
            },
            PgsqlErrorNoticeFieldType::Detail => {
                jb.set_string_from_bytes("detail", &field.field_value)?;
            },
            PgsqlErrorNoticeFieldType::Hint => {
                jb.set_string_from_bytes("hint", &field.field_value)?;
            },
            PgsqlErrorNoticeFieldType::Position => {
                jb.set_string_from_bytes("position", &field.field_value)?;
            },
            PgsqlErrorNoticeFieldType::InternalPosition => {
                jb.set_string_from_bytes("internal position", &field.field_value)?;
            },
            PgsqlErrorNoticeFieldType::InternalQuery => {
                jb.set_string_from_bytes("internal query", &field.field_value)?;
            },
            PgsqlErrorNoticeFieldType::Where => {
                jb.set_string_from_bytes("where", &field.field_value)?;
            },
            PgsqlErrorNoticeFieldType::SchemaName => {
                jb.set_string_from_bytes("schema name", &field.field_value)?;
            },
            PgsqlErrorNoticeFieldType::TableName => {
                jb.set_string_from_bytes("table name", &field.field_value)?;
            },
            PgsqlErrorNoticeFieldType::ColumnName => {
                jb.set_string_from_bytes("column name", &field.field_value)?;
            },
            PgsqlErrorNoticeFieldType::DataType => {
                jb.set_string_from_bytes("data type", &field.field_value)?;
            },
            PgsqlErrorNoticeFieldType::ConstraintName => {
                jb.set_string_from_bytes("constraint name", &field.field_value)?;
            },
            PgsqlErrorNoticeFieldType::File => {
                jb.set_string_from_bytes("file", &field.field_value)?;
            },
            PgsqlErrorNoticeFieldType::Line => {
                jb.set_string_from_bytes("line", &field.field_value)?;
            },
            PgsqlErrorNoticeFieldType::Routine => {
                jb.set_string_from_bytes("routine", &field.field_value)?;
            },
            PgsqlErrorNoticeFieldType::TerminatorToken => {
                // do nothing, as that's the terminator token (?)
            },
            PgsqlErrorNoticeFieldType::UnknownFieldType => {
                // TODO what should be done here?
            },
        }
    }
    jb.close()?;
    Ok(jb)
}

fn log_pgsql_parameters(params: &PgsqlStartupParameters) -> Result<JsonBuilder, JsonError>
{
    let mut jb = JsonBuilder::new_object();
    jb.set_string_from_bytes("user", &params.user.param_value)?;
    if let Some(PgsqlParameter{param_name: _, param_value}) = &params.database {
        jb.set_string_from_bytes("database", &param_value)?;
    }
    if let Some(vec) = &params.optional_params {
        for param in vec {
            // TODO extract this value?
            let param_name = String::from_utf8_lossy(&param.param_name);
            jb.set_string_from_bytes(&param_name, &param.param_value)?;
        }
    }
    jb.close()?;
    Ok(jb)
}

#[no_mangle]
pub extern "C" fn rs_pgsql_logger_log(tx: *mut std::os::raw::c_void, js: &mut JsonBuilder) -> bool {
    let tx = cast_pointer!(tx, PgsqlTransaction);
    SCLogNotice!("----------- PGSQL rs_pgsql_logger_log call.");
    log_pgsql(tx, js).is_ok()
}
