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
        let protocol_op_str = req.protocol_op.to_string();
        js.open_object("request")?;
        js.set_uint("message_id", req.message_id.0.into())?;
        js.set_string("operation", &protocol_op_str)?;

        match &req.protocol_op {
            ProtocolOp::SearchRequest(msg) => log_search_request(msg, js)?,
            ProtocolOp::BindRequest(msg) => log_bind_request(msg, js)?,
            ProtocolOp::UnbindRequest => (),
            ProtocolOp::ModifyRequest(msg) => log_modify_request(msg, js)?,
            ProtocolOp::AddRequest(msg) => log_add_request(msg, js)?,
            ProtocolOp::DelRequest(msg) => log_del_request(msg, js)?,
            ProtocolOp::ModDnRequest(msg) => log_mod_dn_request(msg, js)?,
            ProtocolOp::CompareRequest(msg) => log_compare_request(msg, js)?,
            ProtocolOp::ExtendedRequest(msg) => log_extended_request(msg, js)?,
            _ => {}
        };

        log_controls(&req.controls, js)?;

        js.close()?;
    }

    if !tx.responses.is_empty() {
        js.open_array("responses")?;

        for response in &tx.responses {
            js.start_object()?;

            if tx.request.is_none() {
                js.set_uint("message_id", response.message_id.0.into())?;
            }

            match &response.protocol_op {
                ProtocolOp::SearchResultEntry(msg) => log_search_result_entry(msg, js)?,
                ProtocolOp::SearchResultDone(msg) => log_search_result_done(msg, js)?,
                ProtocolOp::BindResponse(msg) => log_bind_response(msg, js)?,
                ProtocolOp::ModifyResponse(msg) => log_modify_response(msg, js)?,
                ProtocolOp::AddResponse(msg) => log_add_response(msg, js)?,
                ProtocolOp::DelResponse(msg) => log_del_response(msg, js)?,
                ProtocolOp::ModDnResponse(msg) => log_mod_dn_response(msg, js)?,
                ProtocolOp::CompareResponse(msg) => log_compare_response(msg, js)?,
                ProtocolOp::ExtendedResponse(msg) => log_extended_response(msg, js)?,
                ProtocolOp::IntermediateResponse(msg) => log_intermediate_response(msg, js)?,
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
    js.open_object("search_request")?;
    js.set_string("base_object", &msg.base_object.0)?;
    js.set_uint("scope", msg.scope.0.into())?;
    js.set_uint("deref_alias", msg.deref_aliases.0.into())?;
    js.set_uint("size_limit", msg.size_limit.into())?;
    js.set_uint("time_limit", msg.time_limit.into())?;
    js.set_bool("types_only", msg.types_only)?;
    if let Filter::Present(val) = &msg.filter {
        js.open_object("filter")?;
        js.set_string("type", "present")?;
        js.set_string("value", &val.0.to_string())?;
        js.close()?;
    }
    if !msg.attributes.is_empty() {
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
    js.open_object("bind_request")?;
    js.set_uint("version", msg.version.into())?;
    js.set_string("name", &msg.name.0)?;
    if let AuthenticationChoice::Sasl(sasl) = &msg.authentication {
        js.open_object("sasl")?;
        js.set_string("mechanism", &sasl.mechanism.0)?;
        if let Some(credentials) = &sasl.credentials {
            js.set_hex("credentials", credentials)?;
        }
        js.close()?;
    }
    js.close()?;
    Ok(())
}

fn log_modify_request(msg: &ModifyRequest, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.open_object("modify_request")?;
    js.set_string("object", &msg.object.0)?;
    if !msg.changes.is_empty() {
        js.open_array("changes")?;
        for change in &msg.changes {
            js.start_object()?;
            js.set_string("operation", &change.operation.to_string())?;
            js.open_object("modification")?;
            js.set_string("attribute_type", &change.modification.attr_type.0)?;
            if !change.modification.attr_vals.is_empty() {
                js.open_array("attribute_values")?;
                for attr in &change.modification.attr_vals {
                    js.append_string_from_bytes(&attr.0[..])?;
                }
                js.close()?;
            }
            js.close()?;
            js.close()?;
        }
        js.close()?;
    }
    js.close()?;
    Ok(())
}

fn log_add_request(msg: &AddRequest, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.open_object("add_request")?;
    js.set_string("entry", &msg.entry.0)?;
    if !msg.attributes.is_empty() {
        js.open_array("attributes")?;
        for attr in &msg.attributes {
            js.start_object()?;
            js.set_string("name", &attr.attr_type.0)?;
            if !attr.attr_vals.is_empty() {
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

fn log_del_request(msg: &LdapDN, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.open_object("del_request")?;
    js.set_string("dn", &msg.0)?;
    js.close()?;
    Ok(())
}

fn log_mod_dn_request(msg: &ModDnRequest, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.open_object("mod_dn_request")?;
    js.set_string("entry", &msg.entry.0)?;
    js.set_string("new_rdn", &msg.newrdn.0)?;
    js.set_bool("delete_old_rdn", msg.deleteoldrdn)?;
    if let Some(newsuperior) = &msg.newsuperior {
        js.set_string("new_superior", &newsuperior.0)?;
    }
    js.close()?;
    Ok(())
}

fn log_compare_request(msg: &CompareRequest, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.open_object("compare_request")?;
    js.set_string("entry", &msg.entry.0)?;
    js.open_object("attribute_value_assertion")?;
    js.set_string("description", &msg.ava.attribute_desc.0)?;
    js.set_string_from_bytes("value", &msg.ava.assertion_value[..])?;
    js.close()?;
    js.close()?;
    Ok(())
}

fn log_extended_request(msg: &ExtendedRequest, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.open_object("extended_request")?;
    js.set_string("name", &msg.request_name.0)?;
    if let Some(value) = &msg.request_value {
        js.set_string_from_bytes("value", &value[..])?;
    }
    js.close()?;
    Ok(())
}

fn log_search_result_entry(msg: &SearchResultEntry, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.open_object("search_result_entry")?;
    js.set_string("base_object", &msg.object_name.0)?;
    if !msg.attributes.is_empty() {
        js.open_array("attributes")?;
        for attr in &msg.attributes {
            js.start_object()?;
            js.set_string("type", &attr.attr_type.0)?;
            if !attr.attr_vals.is_empty() {
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
    js.open_object("search_result_done")?;
    log_ldap_result(msg, js)?;
    js.close()?;
    Ok(())
}

fn log_bind_response(msg: &BindResponse, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.open_object("bind_response")?;
    log_ldap_result(&msg.result, js)?;
    if let Some(creds) = &msg.server_sasl_creds {
        js.set_hex("server_sasl_creds", creds)?;
    };
    js.close()?;
    Ok(())
}

fn log_modify_response(msg: &ModifyResponse, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.open_object("modify_response")?;
    log_ldap_result(&msg.result, js)?;
    js.close()?;
    Ok(())
}

fn log_add_response(msg: &LdapResult, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.open_object("add_response")?;
    log_ldap_result(msg, js)?;
    js.close()?;
    Ok(())
}

fn log_del_response(msg: &LdapResult, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.open_object("del_response")?;
    log_ldap_result(msg, js)?;
    js.close()?;
    Ok(())
}

fn log_mod_dn_response(msg: &LdapResult, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.open_object("mod_dn_response")?;
    log_ldap_result(msg, js)?;
    js.close()?;
    Ok(())
}

fn log_compare_response(msg: &LdapResult, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.open_object("compare_response")?;
    log_ldap_result(msg, js)?;
    js.close()?;
    Ok(())
}

fn log_extended_response(msg: &ExtendedResponse, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.open_object("extended_response")?;
    log_ldap_result(&msg.result, js)?;
    if let Some(name) = &msg.response_name {
        js.set_string("name", &name.0)?;
    }
    if let Some(value) = &msg.response_value {
        js.set_string_from_bytes("value", &value[..])?;
    }
    js.close()?;
    Ok(())
}

fn log_intermediate_response(
    msg: &IntermediateResponse, js: &mut JsonBuilder,
) -> Result<(), JsonError> {
    js.open_object("intermediate_response")?;
    if let Some(name) = &msg.response_name {
        js.set_string("name", &name.0)?;
    }
    if let Some(value) = &msg.response_value {
        js.set_string_from_bytes("value", &value[..])?;
    }
    js.close()?;
    Ok(())
}

fn log_ldap_result(msg: &LdapResult, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.set_string("result_code", &msg.result_code.to_string())?;
    js.set_string("matched_dn", &msg.matched_dn.0)?;
    js.set_string("message", &msg.diagnostic_message.0)?;
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
