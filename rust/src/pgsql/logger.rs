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

// Author: Juliana Fajardini <jufajardini@gmail.com>

//! PostgreSQL parser json logger

use crate::jsonbuilder::{JsonBuilder, JsonError};
use crate::pgsql::parser::*;
use crate::pgsql::pgsql::*;
use std;

pub const PGSQL_LOG_PASSWORDS: u32 = BIT_U32!(0);

fn log_pgsql(tx: &PgsqlTransaction, flags: u32, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.open_object("pgsql")?;
    js.set_uint("tx_id", tx.tx_id)?;
    if !tx.requests.is_empty() {
        // For now, even if 'requests' is an array, we don't need to log it as such, as
        // there should be no duplicated messages, and there should be no more than 2 requests per tx
        debug_validate_bug_on!(tx.requests.len() > 2);
        js.open_object("request")?;
        log_request(tx, flags, js)?;
        js.close()?;
    } else if tx.responses.is_empty() {
        SCLogDebug!("Suricata created an empty PGSQL transaction");
        // TODO Log anomaly event?
        // if there are no transactions, there's nothing more to be logged
        js.close()?;
        return Ok(());
    }

    if !tx.responses.is_empty() {
        SCLogDebug!("Responses length: {}", tx.responses.len());
        js.set_object("response", &log_response_object(tx)?)?;
    }
    js.close()?;

    Ok(())
}

fn log_request(tx: &PgsqlTransaction, flags: u32, js: &mut JsonBuilder) -> Result<(), JsonError> {
    // CopyFail, ConsolidatedCopyDataIn, CopyDone
    let mut duplicated_messages: [u8; 3] = [0, 0, 0];
    for req in &tx.requests {
        SCLogDebug!("Suricata requests length: {}", tx.requests.len());
        match req {
            PgsqlFEMessage::StartupMessage(StartupPacket {
                length: _,
                proto_major,
                proto_minor,
                params,
            }) => {
                let proto = format!("{}.{}", proto_major, proto_minor);
                js.set_string("protocol_version", &proto)?;
                js.set_object("startup_parameters", &log_startup_parameters(params)?)?;
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
                js.set_string("sasl_authentication_mechanism", auth_mechanism.to_str())?;
                js.set_string_from_bytes("sasl_param", sasl_param)?;
            }
            PgsqlFEMessage::PasswordMessage(RegularPacket {
                identifier: _,
                length: _,
                payload,
            }) => {
                if flags & PGSQL_LOG_PASSWORDS != 0 {
                    js.set_string_from_bytes(req.to_str(), payload)?;
                } else {
                    js.set_bool("password_redacted", true)?;
                }
            }
            PgsqlFEMessage::SASLResponse(RegularPacket {
                identifier: _,
                length: _,
                payload,
            }) => {
                js.set_string_from_bytes("sasl_response", payload)?;
            }
            PgsqlFEMessage::SimpleQuery(RegularPacket {
                identifier: _,
                length: _,
                payload,
            }) => {
                js.set_string_from_bytes(req.to_str(), payload)?;
            }
            PgsqlFEMessage::CopyFail(RegularPacket {
                identifier: _,
                length: _,
                payload,
            }) => {
                js.set_string_from_bytes(req.to_str(), payload)?;
                duplicated_messages[0] += 1;
                debug_validate_bug_on!(duplicated_messages[0] > 1);
            }
            PgsqlFEMessage::CancelRequest(CancelRequestMessage { pid, backend_key }) => {
                js.set_string("message", "cancel_request")?;
                js.set_uint("process_id", *pid)?;
                js.set_uint("secret_key", *backend_key)?;
            }
            PgsqlFEMessage::ConsolidatedCopyDataIn(ConsolidatedDataRowPacket {
                identifier: _,
                row_cnt,
                data_size,
            }) => {
                js.open_object(req.to_str())?;
                js.set_uint("msg_count", *row_cnt)?;
                js.set_uint("data_size", *data_size)?;
                js.close()?;
                duplicated_messages[1] += 1;
                debug_validate_bug_on!(duplicated_messages[1] > 1);
            }
            PgsqlFEMessage::CopyDone(_) => {
                js.set_string("message", req.to_str())?;
                duplicated_messages[2] += 1;
                debug_validate_bug_on!(duplicated_messages[2] > 1);
            }
            PgsqlFEMessage::Terminate(_) => {
                js.set_string("message", req.to_str())?;
            }
            PgsqlFEMessage::UnknownMessageType(RegularPacket {
                identifier: _,
                length: _,
                payload: _,
            }) => {
                // We don't want to log these, for now. Cf redmine: #6576
            }
        }
    }
    Ok(())
}

fn log_response_object(tx: &PgsqlTransaction) -> Result<JsonBuilder, JsonError> {
    let mut jb = JsonBuilder::try_new_object()?;
    let mut array_open = false;
    for response in &tx.responses {
        if let PgsqlBEMessage::ParameterStatus(msg) = response {
            if !array_open {
                jb.open_array("parameter_status")?;
                array_open = true;
            }
            jb.append_object(&log_pgsql_param(&msg.param)?)?;
        } else {
            if array_open {
                jb.close()?;
                array_open = false;
            }
            log_response(response, &mut jb)?;
        }
    }
    jb.close()?;
    Ok(jb)
}

fn log_response(res: &PgsqlBEMessage, jb: &mut JsonBuilder) -> Result<(), JsonError> {
    match res {
        PgsqlBEMessage::SSLResponse(message) => {
            if let SSLResponseMessage::SSLAccepted = message {
                jb.set_bool("ssl_accepted", true)?;
            } else {
                jb.set_bool("ssl_accepted", false)?;
            }
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
            log_error_notice_field_types(message_body, jb)?;
        }
        PgsqlBEMessage::AuthenticationMD5Password(AuthenticationMessage {
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
            jb.set_string_from_bytes(res.to_str(), payload)?;
        }
        PgsqlBEMessage::UnknownMessageType(RegularPacket {
            identifier: _,
            length: _,
            payload: _,
        }) => {
            // We don't want to log these, for now. Cf redmine: #6576
        }
        PgsqlBEMessage::AuthenticationOk(_)
        | PgsqlBEMessage::AuthenticationCleartextPassword(_)
        | PgsqlBEMessage::AuthenticationSASL(_)
        | PgsqlBEMessage::AuthenticationSASLContinue(_)
        | PgsqlBEMessage::CopyDone(_) => {
            jb.set_string("message", res.to_str())?;
        }
        PgsqlBEMessage::ParameterStatus(ParameterStatusMessage {
            identifier: _,
            length: _,
            param: _,
        }) => {
            // We take care of these elsewhere
        }
        PgsqlBEMessage::CopyOutResponse(CopyResponse {
            identifier: _,
            length: _,
            column_cnt,
        })
        | PgsqlBEMessage::CopyInResponse(CopyResponse {
            identifier: _,
            length: _,
            column_cnt,
        }) => {
            jb.open_object(res.to_str())?;
            jb.set_uint("columns", *column_cnt)?;
            jb.close()?;
        }
        PgsqlBEMessage::BackendKeyData(BackendKeyDataMessage {
            identifier: _,
            length: _,
            backend_pid,
            secret_key,
        }) => {
            jb.set_uint("process_id", *backend_pid)?;
            jb.set_uint("secret_key", *secret_key)?;
        }
        PgsqlBEMessage::ReadyForQuery(ReadyForQueryMessage {
            identifier: _,
            length: _,
            transaction_status: _,
        }) => {
            // We don't want to log this one
        }
        PgsqlBEMessage::ConsolidatedCopyDataOut(ConsolidatedDataRowPacket {
            identifier: _,
            row_cnt,
            data_size,
        }) => {
            jb.open_object(res.to_str())?;
            jb.set_uint("row_count", *row_cnt)?;
            jb.set_uint("data_size", *data_size)?;
            jb.close()?;
        }
        PgsqlBEMessage::RowDescription(RowDescriptionMessage {
            identifier: _,
            length: _,
            field_count,
            fields: _,
        }) => {
            jb.set_uint("field_count", *field_count)?;
        }
        PgsqlBEMessage::ConsolidatedDataRow(ConsolidatedDataRowPacket {
            identifier: _,
            row_cnt,
            data_size,
        }) => {
            jb.set_uint("data_rows", *row_cnt)?;
            jb.set_uint("data_size", *data_size)?;
        }
        PgsqlBEMessage::NotificationResponse(NotificationResponse {
            identifier: _,
            length: _,
            pid,
            channel_name,
            payload,
        }) => {
            jb.set_uint("pid", *pid)?;
            jb.set_string_from_bytes("channel_name", channel_name)?;
            jb.set_string_from_bytes("payload", payload)?;
        }
    }
    Ok(())
}

fn log_error_notice_field_types(
    error_fields: &Vec<PgsqlErrorNoticeMessageField>, jb: &mut JsonBuilder,
) -> Result<(), JsonError> {
    for field in error_fields {
        jb.set_string_from_bytes(field.field_type.to_str(), &field.field_value)?;
    }
    Ok(())
}

fn log_startup_parameters(params: &PgsqlStartupParameters) -> Result<JsonBuilder, JsonError> {
    let mut jb = JsonBuilder::try_new_object()?;
    // User is a mandatory field in a pgsql message
    jb.set_string_from_bytes("user", &params.user.value)?;
    if let Some(parameters) = &params.optional_params {
        jb.open_array("optional_parameters")?;
        for parameter in parameters {
            jb.append_object(&log_pgsql_param(parameter)?)?;
        }
        jb.close()?;
    }

    jb.close()?;
    Ok(jb)
}

fn log_pgsql_param(param: &PgsqlParameter) -> Result<JsonBuilder, JsonError> {
    let mut jb = JsonBuilder::try_new_object()?;
    jb.set_string_from_bytes(param.name.to_str(), &param.value)?;
    jb.close()?;
    Ok(jb)
}

#[no_mangle]
pub unsafe extern "C" fn SCPgsqlLogger(
    tx: *mut std::os::raw::c_void, flags: u32, js: &mut JsonBuilder,
) -> bool {
    let tx_pgsql = cast_pointer!(tx, PgsqlTransaction);
    SCLogDebug!(
        "----------- PGSQL rs_pgsql_logger call. Tx id is {:?}",
        tx_pgsql.tx_id
    );
    log_pgsql(tx_pgsql, flags, js).is_ok()
}
