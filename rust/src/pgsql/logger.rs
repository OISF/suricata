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

use crate::jsonbuilder::{JsonBuilder, JsonError};
use crate::pgsql::parser::*;
use crate::pgsql::pgsql::*;
use std;

fn log_pgsql(tx: &PgsqlTransaction, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.set_uint("transaction_id", tx.tx_id)?;
    if !tx.requests.is_empty() {
        if tx.requests.len() > 1 {
            js.open_array("requests")?;
            for request in &tx.requests {
                let jbr = log_request(request)?;
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
                let jb = log_response(response)?;
                js.append_object(&jb)?;
            }
            js.close()?;
        } else if !tx.responses.is_empty() {
            let jb = log_response(&tx.responses[0])?;
            js.set_object("response", &jb)?;
        }
    } else {
        SCLogDebug!(
            "Suricata logging a transaction without finding a request. Tx_id {:?}",
            &tx.tx_id
        );
        if !tx.responses.is_empty() {
            js.open_array("response")?;
            for response in &tx.responses {
                let jb = log_response(response)?;
                js.append_object(&jb)?;
            }
            js.close()?;
        } else {
            js.set_string("request", "request is empty")?;
            js.set_string("response", "response is empty")?;
            SCLogDebug!("Suricata created an empty PGSQL transaction");
        }
    }
    Ok(())
}

fn log_request(req: &PgsqlFEMessage) -> Result<JsonBuilder, JsonError> {
    let mut js = JsonBuilder::new_object();
    js.open_object(req.to_str())?;
    match req {
        PgsqlFEMessage::StartupMessage(StartupPacket {
            length: _,
            proto_major,
            proto_minor,
            params,
        }) => {
            let proto = format!("{}.{}", proto_major, proto_minor);
            js.set_string("protocol_version", &proto)?;
            let jb = log_pgsql_parameters(params)?;
            js.set_object("startup_parameters", &jb)?;
        }
        PgsqlFEMessage::SSLRequest(_) => {
            js.set_string("message_type", "SSL Request")?;
        }
        PgsqlFEMessage::SASLInitialResponse(SASLInitialResponsePacket {
            identifier: _,
            length: _,
            auth_mechanism,
            param_length: _,
            sasl_param,
        }) => {
            js.set_string("authentication_mechanism", &auth_mechanism.to_str())?;
            js.set_string_from_bytes("sasl_param", sasl_param)?;
        }
        PgsqlFEMessage::PasswordMessage(RegularPacket {
            identifier: _,
            length: _,
            payload,
        })
        | PgsqlFEMessage::SASLResponse(RegularPacket {
            identifier: _,
            length: _,
            payload,
        })
        | PgsqlFEMessage::SimpleQuery(RegularPacket {
            identifier: _,
            length: _,
            payload,
        }) => {
            js.set_string_from_bytes("payload", payload)?;
        }
        PgsqlFEMessage::Terminate(TerminationMessage {
            identifier: _,
            length: _,
        }) => {
            js.set_string("message_type", "termination_token")?;
        }
    }
    js.close()?;
    js.close()?;
    Ok(js)
}

fn log_response(res: &PgsqlBEMessage) -> Result<JsonBuilder, JsonError> {
    let mut js = JsonBuilder::new_object();
    js.open_object(res.to_str())?;
    match res {
        PgsqlBEMessage::SSLResponse(message) => {
            js.set_string("ssl_response", &message.to_str())?;
        }
        PgsqlBEMessage::NoticeResponse(ErrorNoticeMessage {
            identifier: _,
            length: _,
            message_body,
        })
        | PgsqlBEMessage::ErrorResponse(ErrorNoticeMessage {
            identifier: _,
            length: _,
            message_body,
        }) => {
            let jb = log_error_notice_field_types(message_body)?;
            js.set_object("message_body", &jb)?;
        }
        PgsqlBEMessage::AuthenticationOk(AuthenticationMessage {
            identifier: _,
            length: _,
            auth_type: _,
            payload,
        })
        | PgsqlBEMessage::AuthenticationKerb5(AuthenticationMessage {
            identifier: _,
            length: _,
            auth_type: _,
            payload,
        })
        | PgsqlBEMessage::AuthenticationCleartextPassword(AuthenticationMessage {
            identifier: _,
            length: _,
            auth_type: _,
            payload,
        })
        | PgsqlBEMessage::AuthenticationMD5Password(AuthenticationMessage {
            identifier: _,
            length: _,
            auth_type: _,
            payload,
        })
        | PgsqlBEMessage::AuthenticationGSS(AuthenticationMessage {
            identifier: _,
            length: _,
            auth_type: _,
            payload,
        })
        | PgsqlBEMessage::AuthenticationSSPI(AuthenticationMessage {
            identifier: _,
            length: _,
            auth_type: _,
            payload,
        })
        | PgsqlBEMessage::AuthenticationGSSContinue(AuthenticationMessage {
            identifier: _,
            length: _,
            auth_type: _,
            payload,
        })
        | PgsqlBEMessage::AuthenticationSASLFinal(AuthenticationMessage {
            identifier: _,
            length: _,
            auth_type: _,
            payload,
        }) => {
            // TODO - nit - not sure what method to use here, the format printed doesn't look good
            js.set_string_from_bytes("payload", payload)?;
        }
        PgsqlBEMessage::AuthenticationSASL(_) => {
            js.set_string("authentication_SASL", &res.to_str())?;
        }
        PgsqlBEMessage::AuthenticationSASLContinue(_) => {
            js.set_string("authentication_SASL_continue", &res.to_str())?;
        }
        PgsqlBEMessage::ParameterStatus(ParameterStatusMessage {
            identifier: _,
            length: _,
            param,
        }) => {
            js.set_string_from_bytes("name", &param.name)?;
            js.set_string_from_bytes("value", &param.value)?;
        }
        PgsqlBEMessage::BackendKeyData(BackendKeyDataMessage {
            identifier: _,
            length: _,
            backend_pid,
            secret_key,
        }) => {
            js.set_uint("process_id", (*backend_pid) as u64)?;
            js.set_uint("secret_key", (*secret_key) as u64)?;
        }
        PgsqlBEMessage::CommandComplete(RegularPacket {
            identifier: _,
            length: _,
            payload,
        }) => {
            // TODO - nit - this may result in not so pretty strings.
            //  example "SELECT 3\u0000"
            js.set_string_from_bytes("payload", payload)?;
        }
        PgsqlBEMessage::ReadyForQuery(ReadyForQueryMessage {
            identifier: _,
            length: _,
            transaction_status,
        }) => {
            let tx_status = (*transaction_status) as char;
            js.set_string("transaction_status", &tx_status.to_string())?;
        }
        PgsqlBEMessage::RowDescription(RowDescriptionMessage {
            identifier: _,
            length: _,
            field_count,
            fields: _,
        }) => {
            let count = (*field_count) as u64;
            js.set_uint("field_count", count)?;
            // let jb = log_row_description(fields)?;
            // js.set_object("columns", &jb)?;
            js.set_string("backend_response", "Response Ok")?;
        }
        PgsqlBEMessage::DataRow(DataRowMessage {
            identifier: _,
            length: _,
            field_count,
            fields,
        }) => {
            let count = (*field_count) as u64;
            js.set_uint("field_count", count)?;
            let jb = log_data_row(fields)?;
            js.set_object("rows", &jb)?;
        }
        PgsqlBEMessage::DummyDataRow(RegularPacket {
            identifier: _,
            length: _,
            payload: _,
        }) => {
            js.set_string("backend_response", "Response Ok")?;
        }
    }
    js.close()?;
    js.close()?;
    Ok(js)
}

// fn log_row_description(columns: &Vec<RowField>) -> Result<JsonBuilder, JsonError>
// {
//     let mut jb = JsonBuilder::new_object();
//     let mut i = 0;
//     for column in columns {
//         let key = format!("column_{}", i);
//         jb.open_object(&key)?;
//         jb.set_string_from_bytes("column_name", &column.field_name)?;
//         let toid = (*column).table_oid as u64;
//         jb.set_uint("table_oid", toid)?;
//         let cix = (*column).data_type_oid as u64;
//         jb.set_uint("column_index", cix)?;
//         jb.set_float("data_type_size", (*column).data_type_size as f64)?;
//         jb.set_float("type_modifier", (*column).type_modifier as f64)?;
//         let fc = (*column).format_code as u64;
//         jb.set_uint("format_code", fc)?;
//         jb.close()?;
//         i = i + 1;
//     }
//     jb.close()?;
//     Ok(jb)
// }

fn log_data_row(rows: &Vec<ColumnFieldValue>) -> Result<JsonBuilder, JsonError> {
    let mut jb = JsonBuilder::new_object();
    let mut i = 0;
    for row in rows {
        // JsonBuilder requires that keys are unique...
        let key = format!("row_{}", i);
        jb.open_object(&key)?;
        if row.value_length >= 0 {
            let len = (*row).value_length as u64;
            jb.set_uint("column_length", len)?;
            jb.set_string_from_bytes("data", &row.value)?;
        } else {
            jb.set_float("column_length", row.value_length as f64)?;
            // When column_length is '-1', data is NULL. What's the best way to log it?
            jb.set_string_from_bytes("data", b"NULL")?;
        }
        i = i + 1;
        jb.close()?;
    }
    jb.close()?;
    Ok(jb)
}

fn log_error_notice_field_types(
    error_fields: &Vec<PgsqlErrorNoticeMessageField>,
) -> Result<JsonBuilder, JsonError> {
    let mut jb = JsonBuilder::new_object();
    for field in error_fields {
        match field.field_type {
            PgsqlErrorNoticeFieldType::SeverityLocalizable => {
                jb.set_string_from_bytes("severity", &field.field_value)?;
            }
            PgsqlErrorNoticeFieldType::SeverityNonLocalizable => {
                jb.set_string_from_bytes("severity", &field.field_value)?;
            }
            PgsqlErrorNoticeFieldType::CodeSqlStateCode => {
                jb.set_string_from_bytes("code", &field.field_value)?;
            }
            PgsqlErrorNoticeFieldType::Message => {
                jb.set_string_from_bytes("message", &field.field_value)?;
            }
            PgsqlErrorNoticeFieldType::Detail => {
                jb.set_string_from_bytes("detail", &field.field_value)?;
            }
            PgsqlErrorNoticeFieldType::Hint => {
                jb.set_string_from_bytes("hint", &field.field_value)?;
            }
            PgsqlErrorNoticeFieldType::Position => {
                jb.set_string_from_bytes("position", &field.field_value)?;
            }
            PgsqlErrorNoticeFieldType::InternalPosition => {
                jb.set_string_from_bytes("internal_position", &field.field_value)?;
            }
            PgsqlErrorNoticeFieldType::InternalQuery => {
                jb.set_string_from_bytes("internal_query", &field.field_value)?;
            }
            PgsqlErrorNoticeFieldType::Where => {
                jb.set_string_from_bytes("where", &field.field_value)?;
            }
            PgsqlErrorNoticeFieldType::SchemaName => {
                jb.set_string_from_bytes("schema_name", &field.field_value)?;
            }
            PgsqlErrorNoticeFieldType::TableName => {
                jb.set_string_from_bytes("table_name", &field.field_value)?;
            }
            PgsqlErrorNoticeFieldType::ColumnName => {
                jb.set_string_from_bytes("column_name", &field.field_value)?;
            }
            PgsqlErrorNoticeFieldType::DataType => {
                jb.set_string_from_bytes("data_type", &field.field_value)?;
            }
            PgsqlErrorNoticeFieldType::ConstraintName => {
                jb.set_string_from_bytes("constraint_name", &field.field_value)?;
            }
            PgsqlErrorNoticeFieldType::File => {
                jb.set_string_from_bytes("file", &field.field_value)?;
            }
            PgsqlErrorNoticeFieldType::Line => {
                jb.set_string_from_bytes("line", &field.field_value)?;
            }
            PgsqlErrorNoticeFieldType::Routine => {
                jb.set_string_from_bytes("routine", &field.field_value)?;
            }
            PgsqlErrorNoticeFieldType::TerminatorToken => {
                // do nothing, as that's the terminator token ?
            }
            PgsqlErrorNoticeFieldType::UnknownFieldType => {
                // TODO Question - what should be done here?
            }
        }
    }
    jb.close()?;
    Ok(jb)
}

fn log_pgsql_parameters(params: &PgsqlStartupParameters) -> Result<JsonBuilder, JsonError> {
    let mut jb = JsonBuilder::new_object();
    jb.set_string_from_bytes("user", &params.user.value)?;
    if let Some(PgsqlParameter { name: _, value }) = &params.database {
        jb.set_string_from_bytes("database", value)?;
    }
    // TODO Leaving these out in the less verbose version, and only show them in case extended and file logging is enabled in yaml?
    // if let Some(vec) = &params.optional_params {
    //     for param in vec {
    //         let name = String::from_utf8_lossy(&param.name);
    //         jb.set_string_from_bytes(&name, &param.value)?;
    //     }
    // }
    jb.close()?;
    Ok(jb)
}

#[no_mangle]
pub extern "C" fn rs_pgsql_logger_log(tx: *mut std::os::raw::c_void, js: &mut JsonBuilder) -> bool {
    let tx_safe: &mut PgsqlTransaction;
    unsafe {
        tx_safe = cast_pointer!(tx, PgsqlTransaction);
    }
    SCLogDebug!(
        "----------- PGSQL rs_pgsql_logger_log call. Tx id is {:?}",
        tx_safe.tx_id
    );
    log_pgsql(tx_safe, js).is_ok()
}
