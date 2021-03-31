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

// Author: Juliana Fajardini <jufajardini@gmail.com>

//! PostgreSQL parser json logger

use crate::jsonbuilder::{JsonBuilder, JsonError};
use crate::pgsql::parser::*;
use crate::pgsql::pgsql::*;
use std;

pub const PGSQL_LOG_PASSWORDS: u32 = BIT_U32!(1);

fn log_pgsql(tx: &PgsqlTransaction, flags: u32, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.set_uint("tx_id", tx.tx_id)?;
    if !tx.requests.is_empty() {
        js.set_object("request", &log_request(&tx.requests[0], flags)?)?;
        if tx.responses.len() > 1 {
            js.open_array("responses")?;
            for response in &tx.responses {
                js.append_object(&log_response(response)?)?;
            }
            js.close()?;
        } else if !tx.responses.is_empty() {
            js.set_object("response", &log_response(&tx.responses[0])?)?;
        }
    } else {
        SCLogDebug!(
            "Suricata logging a transaction without finding a request. Tx_id {:?}",
            &tx.tx_id
        );
        if !tx.responses.is_empty() {
            js.open_array("responses")?;
            for response in &tx.responses {
                js.append_object(&log_response(response)?)?;
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

fn log_request(req: &PgsqlFEMessage, flags: u32) -> Result<JsonBuilder, JsonError> {
    let mut js = JsonBuilder::new_object();
    match req {
        PgsqlFEMessage::StartupMessage(StartupPacket {
            length: _,
            proto_major,
            proto_minor,
            params,
        }) => {
            js.open_object(req.to_str())?;
            let proto = format!("{}.{}", proto_major, proto_minor);
            js.set_string("protocol_version", &proto)?;
            js.set_object("startup_parameters", &log_pgsql_parameters(params)?)?;
            js.close()?;
        }
        PgsqlFEMessage::SSLRequest(_) => {
            js.set_string("message", "SSL Request")?;
        }
        PgsqlFEMessage::SASLInitialResponse(SASLInitialResponsePacket {
            identifier: _,
            length: _,
            auth_mechanism,
            param_length: _,
            sasl_param,
        }) => {
            js.open_object(req.to_str())?;
            js.set_string("authentication_mechanism", auth_mechanism.to_str())?;
            js.set_string_from_bytes("sasl_param", sasl_param)?;
            js.close()?;
        }
        PgsqlFEMessage::PasswordMessage(RegularPacket {
            identifier: _,
            length: _,
            payload,
        }) => {
            if flags & PGSQL_LOG_PASSWORDS != 0 {
                js.open_object(req.to_str())?;
                js.set_string_from_bytes("password", payload)?;
                js.close()?;
            } else {
                js.set_string(req.to_str(), "password log disabled")?;
            }
        }
        PgsqlFEMessage::SASLResponse(RegularPacket {
            identifier: _,
            length: _,
            payload,
        }) => {
            js.open_object(req.to_str())?;
            js.set_string_from_bytes("payload", payload)?;
            js.close()?;
        }
        | PgsqlFEMessage::SimpleQuery(RegularPacket {
            identifier: _,
            length: _,
            payload,
        }) => {
            js.set_string_from_bytes(req.to_str(), payload)?;
        }
        PgsqlFEMessage::Terminate(TerminationMessage {
            identifier: _,
            length: _,
        }) => {
            js.set_string("message", req.to_str())?;
        }
    }
    js.close()?;
    Ok(js)
}

fn log_response(res: &PgsqlBEMessage) -> Result<JsonBuilder, JsonError> {
    let mut js = JsonBuilder::new_object();
    match res {
        PgsqlBEMessage::SSLResponse(message) => {
            js.set_string("message", message.to_str())?;
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
            js.open_object(res.to_str())?;
            js.set_object("message_body", &log_error_notice_field_types(message_body)?)?;
            js.close()?;
        }
        PgsqlBEMessage::AuthenticationMD5Password(AuthenticationMessage {
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
        })
        | PgsqlBEMessage::CommandComplete(RegularPacket {
            identifier: _,
            length: _,
            payload,
        }) => {
            js.set_string_from_bytes(res.to_str(), payload)?;
        }
        PgsqlBEMessage::AuthenticationOk(_) |
        PgsqlBEMessage::AuthenticationKerb5(_) |
        PgsqlBEMessage::AuthenticationCleartextPassword(_) |
        PgsqlBEMessage::AuthenticationSASL(_) |
        PgsqlBEMessage::AuthenticationSASLContinue(_) => {
            js.set_string("message", res.to_str())?;
        }
        PgsqlBEMessage::ParameterStatus(ParameterStatusMessage {
            identifier: _,
            length: _,
            param,
        }) => {
            js.open_object(res.to_str())?;
            js.set_string_from_bytes("name", &param.name)?;
            js.set_string_from_bytes("value", &param.value)?;
            js.close()?;
        }
        PgsqlBEMessage::BackendKeyData(BackendKeyDataMessage {
            identifier: _,
            length: _,
            backend_pid,
            secret_key,
        }) => {
            js.open_object(res.to_str())?;
            js.set_uint("process_id", (*backend_pid) as u64)?;
            js.set_uint("secret_key", (*secret_key) as u64)?;
            js.close()?;
        }
        PgsqlBEMessage::ReadyForQuery(ReadyForQueryMessage {
            identifier: _,
            length: _,
            transaction_status,
        }) => {
            js.open_object(res.to_str())?;
            let tx_status = (*transaction_status) as char;
            js.set_string("transaction_status", &tx_status.to_string())?;
            js.close()?;
        }
        PgsqlBEMessage::RowDescription(RowDescriptionMessage {
            identifier: _,
            length: _,
            field_count,
            fields: _,
        }) => {
            js.open_object(res.to_str())?;
            let count = (*field_count) as u64;
            js.set_uint("field_count", count)?;
            js.set_string("backend_response", "Response Ok")?;
            js.close()?;
        }
        PgsqlBEMessage::DataRow(DataRowMessage {
            identifier: _,
            length: _,
            field_count,
            fields,
        }) => {
            js.open_object(res.to_str())?;
            let count = (*field_count) as u64;
            js.set_uint("field_count", count)?;
            js.set_object("rows", &log_data_row(fields)?)?;
            js.close()?;
        }
        PgsqlBEMessage::DummyDataRow(RegularPacket {
            identifier: _,
            length: _,
            payload: _,
        }) => {
            js.open_object(res.to_str())?;
            js.set_string("backend_response", "Response Ok")?;
            js.close()?;
        }
    }
    js.close()?;
    Ok(js)
}

fn log_data_row(rows: &Vec<ColumnFieldValue>) -> Result<JsonBuilder, JsonError> {
    let mut jb = JsonBuilder::new_object();
    let mut i = 0;
    for row in rows {
        // JsonBuilder requires that keys are unique...?
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
    for field in error_fields{
        jb.set_string_from_bytes(&field.field_type.to_str(), &field.field_value)?;
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

    jb.close()?;
    Ok(jb)
}

#[no_mangle]
pub unsafe extern "C" fn rs_pgsql_logger(tx: *mut std::os::raw::c_void, flags: u32, js: &mut JsonBuilder) -> bool {
    let tx_pgsql = cast_pointer!(tx, PgsqlTransaction);
    SCLogDebug!(
        "----------- PGSQL rs_pgsql_logger call. Tx id is {:?}",
        tx_pgsql.tx_id
    );
    log_pgsql(tx_pgsql, flags, js).is_ok()
}
