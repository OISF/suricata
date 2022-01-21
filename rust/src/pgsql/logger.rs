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
    js.set_uint("tx_id", tx.tx_id)?;
    if let &Some(ref request) = &tx.request {
        js.set_object("request", &log_request(request, flags)?)?;
    } else if tx.responses.is_empty() {
        SCLogDebug!("Suricata created an empty PGSQL transaction");
        // TODO Log anomaly event instead?
        js.set_bool("request", false)?;
        js.set_bool("response", false)?;
        return Ok(());
    }

    if !tx.responses.is_empty() {
        js.set_object("response", &log_response_object(tx)?)?;
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
                js.set_string_from_bytes("password", payload)?;
            } else {
                js.set_string(req.to_str(), "password log disabled")?;
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

fn log_response_object(tx: &PgsqlTransaction) -> Result<JsonBuilder, JsonError> {
    let mut jb = JsonBuilder::new_object();
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
            jb.set_string_from_bytes(res.to_str(), payload)?;
        }
        PgsqlBEMessage::AuthenticationOk(_)
        | PgsqlBEMessage::AuthenticationKerb5(_)
        | PgsqlBEMessage::AuthenticationCleartextPassword(_)
        | PgsqlBEMessage::AuthenticationSASL(_)
        | PgsqlBEMessage::AuthenticationSASLContinue(_) => {
            jb.set_string("message", res.to_str())?;
        }
        PgsqlBEMessage::ParameterStatus(ParameterStatusMessage {
            identifier: _,
            length: _,
            param: _,
        }) => {
            // We take care of these elsewhere
        }
        PgsqlBEMessage::BackendKeyData(BackendKeyDataMessage {
            identifier: _,
            length: _,
            backend_pid,
            secret_key,
        }) => {
            jb.set_uint("process_id", (*backend_pid).into())?;
            jb.set_uint("secret_key", (*secret_key).into())?;
        }
        PgsqlBEMessage::ReadyForQuery(ReadyForQueryMessage {
            identifier: _,
            length: _,
            transaction_status: _,
        }) => {
            // We don't want to log this one
        }
        PgsqlBEMessage::RowDescription(RowDescriptionMessage {
            identifier: _,
            length: _,
            field_count,
            fields: _,
        }) => {
            jb.set_uint("field_count", (*field_count).into())?;
        }
        PgsqlBEMessage::ConsolidatedDataRow(ConsolidatedDataRowPacket {
            identifier: _,
            length: _,
            row_cnt,
            data_size,
        }) => {
            jb.set_uint("data_rows", (*row_cnt).into())?;
            jb.set_uint("data_size", *data_size)?;
        }
        PgsqlBEMessage::NotificationResponse(NotificationResponse {
            identifier: _,
            length: _,
            pid,
            channel_name,
            payload,
        }) => {
            jb.set_uint("pid", (*pid).into())?;
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
    let mut jb = JsonBuilder::new_object();
    // User is a mandatory field in a pgsql message
    jb.set_string_from_bytes("user", &params.user.value)?;
    if let Some(PgsqlParameter { name: _, value }) = &params.database {
        jb.set_string_from_bytes("database", value)?;
    }

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
    let mut jb = JsonBuilder::new_object();
    jb.set_string_from_bytes(param.name.to_str(), &param.value)?;
    jb.close()?;
    Ok(jb)
}

#[no_mangle]
pub unsafe extern "C" fn rs_pgsql_logger(
    tx: *mut std::os::raw::c_void, flags: u32, js: &mut JsonBuilder,
) -> bool {
    let tx_pgsql = cast_pointer!(tx, PgsqlTransaction);
    SCLogDebug!(
        "----------- PGSQL rs_pgsql_logger call. Tx id is {:?}",
        tx_pgsql.tx_id
    );
    log_pgsql(tx_pgsql, flags, js).is_ok()
}
