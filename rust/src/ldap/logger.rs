/* Copyright (C) 2024 Open Information Security Foundation
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

// written by Giuseppe Longo <giuseppe@glongo.it>

use crate::jsonbuilder::{JsonBuilder, JsonError};
use crate::ldap::filters::*;
use crate::ldap::ldap::LdapTransaction;
use crate::ldap::types::*;

fn log_ldap(tx: &LdapTransaction, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.open_object("ldap")?;

    if let Some(req) = &tx.request {
        js.open_object("request")?;
        js.set_uint("message_id", req.message_id.0 as u64)?;

        match &req.protocol_op {
            ProtocolOp::SearchRequest(msg) => log_search_request(msg, js)?,
            ProtocolOp::BindRequest(msg) => log_bind_request(msg, js)?,
            ProtocolOp::UnbindRequest => log_unbind_request(js)?,
            _ => {}
        };

        log_controls(&req.controls, js)?;

        js.close()?;
    }

    if tx.responses.len() > 0 {
        js.open_array("responses")?;

        for response in &tx.responses {
            js.start_object()?;
            js.set_uint("message_id", response.message_id.0 as u64)?;
            match &response.protocol_op {
                ProtocolOp::SearchResultEntry(msg) => log_search_result_entry(msg, js)?,
                ProtocolOp::SearchResultDone(msg) => log_search_result_done(msg, js)?,
                ProtocolOp::BindResponse(msg) => log_bind_response(msg, js)?,
                _ => {}
            }
            log_controls(&response.controls, js)?;
            js.close()?;
        }
        js.close()?;
    }

    js.close()?;
    Ok(())
}

fn log_search_request(msg: &SearchRequest, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.set_string("operation", "search_request")?;
    js.open_object("search_request")?;
    js.set_string("base_object", &msg.base_object.0)?;
    js.set_uint("scope", msg.scope.0 as u64)?;
    js.set_uint("deref_alias", msg.deref_aliases.0 as u64)?;
    js.set_uint("size_limit", msg.size_limit as u64)?;
    js.set_uint("time_limit", msg.time_limit as u64)?;
    js.set_bool("types_only", msg.types_only)?;
    match &msg.filter {
        Filter::Present(val) => {
            js.open_object("filter")?;
            js.set_string("type", "present")?;
            js.set_string("value", &val.0.to_string())?;
            js.close()?;
        }
        _ => {}
    }
    if msg.attributes.len() > 0 {
        js.open_array("attributes")?;
        for attr in &msg.attributes {
            js.append_string(&attr.0)?;
        }
        js.close()?;
    }

    js.close()?;
    Ok(())
}

fn log_bind_request(msg: &BindRequest, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.set_string("operation", "bind_request")?;
    js.open_object("bind_request")?;
    js.set_uint("version", msg.version as u64)?;
    js.set_string("name", &msg.name.0)?;
    match &msg.authentication {
        AuthenticationChoice::Sasl(sasl) => {
            js.open_object("sasl")?;
            js.set_string("mechanism", &sasl.mechanism.0)?;
            if let Some(credentials) = &sasl.credentials {
                js.set_hex("credentials", &credentials)?;
            }
            js.close()?;
        }
        _ => {}
    }
    js.close()?;
    Ok(())
}

fn log_unbind_request(js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.set_string("operation", "unbind_request")?;
    Ok(())
}

fn log_search_result_entry(msg: &SearchResultEntry, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.set_string("operation", "search_result_entry")?;
    js.open_object("search_result_entry")?;
    js.set_string("base_object", &msg.object_name.0)?;
    if msg.attributes.len() > 0 {
        js.open_array("attributes")?;
        for attr in &msg.attributes {
            js.start_object()?;
            js.set_string("type", &attr.attr_type.0)?;
            if attr.attr_vals.len() > 0 {
                js.open_array("values")?;
                for val in &attr.attr_vals {
                    js.append_string_from_bytes(&val.0)?;
                }
                js.close()?;
            }
            js.close()?;
        }
        js.close()?;
    }
    js.close()?;
    Ok(())
}

fn log_search_result_done(msg: &LdapResult, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.set_string("operation", "search_result_done")?;
    js.open_object("search_result_done")?;
    js.set_uint("result_code", msg.result_code.0 as u64)?;
    js.set_string("matched_dn", &msg.matched_dn.0)?;
    js.set_string("message", &msg.diagnostic_message.0)?;
    js.close()?;
    Ok(())
}

fn log_bind_response(msg: &BindResponse, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.set_string("operation", "bind_response")?;
    js.open_object("bind_response")?;
    js.set_uint("result_code", msg.result.result_code.0 as u64)?;
    js.set_string("matched_dn", &msg.result.matched_dn.0)?;
    js.set_string("message", &msg.result.diagnostic_message.0)?;
    if let Some(creds) = &msg.server_sasl_creds {
        js.set_hex("server_sasl_creds", &creds)?;
    };
    js.close()?;
    Ok(())
}

fn log_controls(controls: &Option<Vec<Control>>, js: &mut JsonBuilder) -> Result<(), JsonError> {
    if let Some(ctls) = controls {
        js.open_array("controls")?;
        for ctl in ctls {
            js.start_object()?;
            js.set_string("control_type", &ctl.control_type.0)?;
            js.set_bool("criticality", ctl.criticality)?;
            if let Some(ctl_val) = &ctl.control_value {
                js.set_hex("control_value", ctl_val)?;
            };
            js.close()?;
        }
        js.close()?;
    }
    Ok(())
}
#[no_mangle]
pub unsafe extern "C" fn rs_ldap_logger_log(
    tx: *mut std::os::raw::c_void, js: &mut JsonBuilder,
) -> bool {
    let tx = cast_pointer!(tx, LdapTransaction);
    log_ldap(tx, js).is_ok()
}
