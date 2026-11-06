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

use crate::detect::EnumString;
use crate::jsonbuilder::{JsonBuilder, JsonError};
use crate::ldap::ldap::LdapTransaction;
use crate::ldap::types::*;
use ldap_parser::filter::*;
use ldap_parser::ldap::*;

const LDAP_LOG_MAX_STRING: usize = 8 * 1024;
const LDAP_LOG_MAX_BYTES: usize = 128 * 1024;

struct LdapLogBudget {
    remaining: usize,
    truncated: bool,
}

impl LdapLogBudget {
    fn new() -> Self {
        Self {
            remaining: LDAP_LOG_MAX_BYTES,
            truncated: false,
        }
    }
}

fn ldap_set_string(
    budget: &mut LdapLogBudget, js: &mut JsonBuilder, key: &str, val: &str,
) -> Result<(), JsonError> {
    let cost = val.len().min(LDAP_LOG_MAX_STRING) + 24;
    if cost > budget.remaining {
        budget.truncated = true;
        return Ok(());
    }
    budget.remaining -= cost;
    if val.len() > LDAP_LOG_MAX_STRING {
        budget.truncated = true;
        js.set_string_limited(key, val, LDAP_LOG_MAX_STRING)?;
    } else {
        js.set_string(key, val)?;
    }
    Ok(())
}

fn ldap_set_bytes(
    budget: &mut LdapLogBudget, js: &mut JsonBuilder, key: &str, val: &[u8],
) -> Result<(), JsonError> {
    let cost = val.len().min(LDAP_LOG_MAX_STRING) + 24;
    if cost > budget.remaining {
        budget.truncated = true;
        return Ok(());
    }
    budget.remaining -= cost;
    if val.len() > LDAP_LOG_MAX_STRING {
        budget.truncated = true;
    }
    js.set_string_from_bytes_limited(key, val, LDAP_LOG_MAX_STRING)?;
    Ok(())
}

fn ldap_append_string(
    budget: &mut LdapLogBudget, js: &mut JsonBuilder, val: &str,
) -> Result<(), JsonError> {
    let cost = val.len().min(LDAP_LOG_MAX_STRING) + 8;
    if cost > budget.remaining {
        budget.truncated = true;
        return Ok(());
    }
    budget.remaining -= cost;
    if val.len() > LDAP_LOG_MAX_STRING {
        budget.truncated = true;
    }
    js.append_string_limited(val, LDAP_LOG_MAX_STRING)?;
    Ok(())
}

fn ldap_append_bytes(
    budget: &mut LdapLogBudget, js: &mut JsonBuilder, val: &[u8],
) -> Result<(), JsonError> {
    let cost = val.len().min(LDAP_LOG_MAX_STRING) + 8;
    if cost > budget.remaining {
        budget.truncated = true;
        return Ok(());
    }
    budget.remaining -= cost;
    if val.len() > LDAP_LOG_MAX_STRING {
        budget.truncated = true;
    }
    js.append_string_from_bytes_limited(val, LDAP_LOG_MAX_STRING)?;
    Ok(())
}

fn ldap_set_hex(
    budget: &mut LdapLogBudget, js: &mut JsonBuilder, key: &str, val: &[u8],
) -> Result<(), JsonError> {
    let len = val.len().min(LDAP_LOG_MAX_STRING);
    let cost = len * 2 + 24;
    if cost > budget.remaining {
        budget.truncated = true;
        return Ok(());
    }
    budget.remaining -= cost;
    if len < val.len() {
        budget.truncated = true;
    }
    js.set_hex(key, &val[..len])?;
    Ok(())
}

fn log_ldap(tx: &LdapTransaction, js: &mut JsonBuilder) -> Result<(), JsonError> {
    let budget = &mut LdapLogBudget::new();
    js.open_object("ldap")?;

    if let Some(req) = &tx.request {
        let protocol_op_str = ldap_protocol_op_as_str(&req.protocol_op);
        js.open_object("request")?;
        js.set_uint("message_id", req.message_id.0)?;
        ldap_set_string(budget, js, "operation", protocol_op_str)?;

        match &req.protocol_op {
            ProtocolOp::SearchRequest(msg) => log_search_request(msg, js, budget)?,
            ProtocolOp::BindRequest(msg) => log_bind_request(msg, js, budget)?,
            ProtocolOp::UnbindRequest => (),
            ProtocolOp::ModifyRequest(msg) => log_modify_request(msg, js, budget)?,
            ProtocolOp::AddRequest(msg) => log_add_request(msg, js, budget)?,
            ProtocolOp::DelRequest(msg) => log_del_request(msg, js, budget)?,
            ProtocolOp::ModDnRequest(msg) => log_mod_dn_request(msg, js, budget)?,
            ProtocolOp::CompareRequest(msg) => log_compare_request(msg, js, budget)?,
            ProtocolOp::ExtendedRequest(msg) => log_extended_request(msg, js, budget)?,
            _ => {}
        };

        log_controls(&req.controls, js, budget)?;

        js.close()?;
    }

    if !tx.responses.is_empty() {
        js.open_array("responses")?;

        for response in &tx.responses {
            js.start_object()?;

            let protocol_op_str = ldap_protocol_op_as_str(&response.protocol_op);
            ldap_set_string(budget, js, "operation", protocol_op_str)?;

            if tx.request.is_none() {
                js.set_uint("message_id", response.message_id.0)?;
            }

            match &response.protocol_op {
                ProtocolOp::SearchResultEntry(msg) => log_search_result_entry(msg, js, budget)?,
                ProtocolOp::SearchResultDone(msg) => log_search_result_done(msg, js, budget)?,
                ProtocolOp::BindResponse(msg) => log_bind_response(msg, js, budget)?,
                ProtocolOp::ModifyResponse(msg) => log_modify_response(msg, js, budget)?,
                ProtocolOp::AddResponse(msg) => log_add_response(msg, js, budget)?,
                ProtocolOp::DelResponse(msg) => log_del_response(msg, js, budget)?,
                ProtocolOp::ModDnResponse(msg) => log_mod_dn_response(msg, js, budget)?,
                ProtocolOp::CompareResponse(msg) => log_compare_response(msg, js, budget)?,
                ProtocolOp::ExtendedResponse(msg) => log_extended_response(msg, js, budget)?,
                ProtocolOp::IntermediateResponse(msg) => {
                    log_intermediate_response(msg, js, budget)?
                }
                _ => {}
            }
            log_controls(&response.controls, js, budget)?;
            js.close()?;
        }
        js.close()?;
    }

    if budget.truncated {
        js.set_bool("truncated", true)?;
    }
    js.close()?;
    Ok(())
}

fn log_search_request(
    msg: &SearchRequest, js: &mut JsonBuilder, budget: &mut LdapLogBudget,
) -> Result<(), JsonError> {
    js.open_object("search_request")?;
    ldap_set_string(budget, js, "base_object", &msg.base_object.0)?;
    js.set_uint("scope", msg.scope.0)?;
    js.set_uint("deref_alias", msg.deref_aliases.0)?;
    js.set_uint("size_limit", msg.size_limit)?;
    js.set_uint("time_limit", msg.time_limit)?;
    js.set_bool("types_only", msg.types_only)?;
    if let Filter::Present(val) = &msg.filter {
        js.open_object("filter")?;
        ldap_set_string(budget, js, "type", "present")?;
        ldap_set_string(budget, js, "value", &val.0)?;
        js.close()?;
    }
    if !msg.attributes.is_empty() {
        js.open_array("attributes")?;
        for attr in &msg.attributes {
            ldap_append_string(budget, js, &attr.0)?;
        }
        js.close()?;
    }

    js.close()?;
    Ok(())
}

fn log_bind_request(
    msg: &BindRequest, js: &mut JsonBuilder, budget: &mut LdapLogBudget,
) -> Result<(), JsonError> {
    js.open_object("bind_request")?;
    js.set_uint("version", msg.version)?;
    ldap_set_string(budget, js, "name", &msg.name.0)?;
    if let AuthenticationChoice::Sasl(sasl) = &msg.authentication {
        js.open_object("sasl")?;
        ldap_set_string(budget, js, "mechanism", &sasl.mechanism.0)?;
        if let Some(credentials) = &sasl.credentials {
            ldap_set_bytes(budget, js, "credentials", credentials)?;
        }
        js.close()?;
    }
    js.close()?;
    Ok(())
}

fn log_modify_request(
    msg: &ModifyRequest, js: &mut JsonBuilder, budget: &mut LdapLogBudget,
) -> Result<(), JsonError> {
    js.open_object("modify_request")?;
    ldap_set_string(budget, js, "object", &msg.object.0)?;
    if !msg.changes.is_empty() {
        js.open_array("changes")?;
        for change in &msg.changes {
            js.start_object()?;
            ldap_set_string(
                budget,
                js,
                "operation",
                ldap_operation_to_string(&change.operation).as_str(),
            )?;
            js.open_object("modification")?;
            ldap_set_string(
                budget,
                js,
                "attribute_type",
                &change.modification.attr_type.0,
            )?;
            if !change.modification.attr_vals.is_empty() {
                js.open_array("attribute_values")?;
                for attr in &change.modification.attr_vals {
                    ldap_append_bytes(budget, js, &attr.0[..])?;
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

fn log_add_request(
    msg: &AddRequest, js: &mut JsonBuilder, budget: &mut LdapLogBudget,
) -> Result<(), JsonError> {
    js.open_object("add_request")?;
    ldap_set_string(budget, js, "entry", &msg.entry.0)?;
    if !msg.attributes.is_empty() {
        js.open_array("attributes")?;
        for attr in &msg.attributes {
            js.start_object()?;
            ldap_set_string(budget, js, "name", &attr.attr_type.0)?;
            if !attr.attr_vals.is_empty() {
                js.open_array("values")?;
                for val in &attr.attr_vals {
                    ldap_append_bytes(budget, js, &val.0)?;
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

fn log_del_request(
    msg: &LdapDN, js: &mut JsonBuilder, budget: &mut LdapLogBudget,
) -> Result<(), JsonError> {
    js.open_object("del_request")?;
    ldap_set_string(budget, js, "dn", &msg.0)?;
    js.close()?;
    Ok(())
}

fn log_mod_dn_request(
    msg: &ModDnRequest, js: &mut JsonBuilder, budget: &mut LdapLogBudget,
) -> Result<(), JsonError> {
    js.open_object("mod_dn_request")?;
    ldap_set_string(budget, js, "entry", &msg.entry.0)?;
    ldap_set_string(budget, js, "new_rdn", &msg.newrdn.0)?;
    js.set_bool("delete_old_rdn", msg.deleteoldrdn)?;
    if let Some(newsuperior) = &msg.newsuperior {
        ldap_set_string(budget, js, "new_superior", &newsuperior.0)?;
    }
    js.close()?;
    Ok(())
}

fn log_compare_request(
    msg: &CompareRequest, js: &mut JsonBuilder, budget: &mut LdapLogBudget,
) -> Result<(), JsonError> {
    js.open_object("compare_request")?;
    ldap_set_string(budget, js, "entry", &msg.entry.0)?;
    js.open_object("attribute_value_assertion")?;
    ldap_set_string(budget, js, "description", &msg.ava.attribute_desc.0)?;
    ldap_set_bytes(budget, js, "value", &msg.ava.assertion_value[..])?;
    js.close()?;
    js.close()?;
    Ok(())
}

fn log_extended_request(
    msg: &ExtendedRequest, js: &mut JsonBuilder, budget: &mut LdapLogBudget,
) -> Result<(), JsonError> {
    js.open_object("extended_request")?;
    ldap_set_string(budget, js, "name", &msg.request_name.0)?;
    if let Some(value) = &msg.request_value {
        ldap_set_bytes(budget, js, "value", &value[..])?;
    }
    js.close()?;
    Ok(())
}

fn log_search_result_entry(
    msg: &SearchResultEntry, js: &mut JsonBuilder, budget: &mut LdapLogBudget,
) -> Result<(), JsonError> {
    js.open_object("search_result_entry")?;
    ldap_set_string(budget, js, "base_object", &msg.object_name.0)?;
    if !msg.attributes.is_empty() {
        js.open_array("attributes")?;
        for attr in &msg.attributes {
            js.start_object()?;
            ldap_set_string(budget, js, "type", &attr.attr_type.0)?;
            if !attr.attr_vals.is_empty() {
                js.open_array("values")?;
                for val in &attr.attr_vals {
                    ldap_append_bytes(budget, js, &val.0)?;
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

fn log_search_result_done(
    msg: &LdapResult, js: &mut JsonBuilder, budget: &mut LdapLogBudget,
) -> Result<(), JsonError> {
    js.open_object("search_result_done")?;
    log_ldap_result(msg, js, budget)?;
    js.close()?;
    Ok(())
}

fn log_bind_response(
    msg: &BindResponse, js: &mut JsonBuilder, budget: &mut LdapLogBudget,
) -> Result<(), JsonError> {
    js.open_object("bind_response")?;
    log_ldap_result(&msg.result, js, budget)?;
    if let Some(creds) = &msg.server_sasl_creds {
        ldap_set_bytes(budget, js, "server_sasl_creds", creds)?;
    }
    js.close()?;
    Ok(())
}

fn log_modify_response(
    msg: &ModifyResponse, js: &mut JsonBuilder, budget: &mut LdapLogBudget,
) -> Result<(), JsonError> {
    js.open_object("modify_response")?;
    log_ldap_result(&msg.result, js, budget)?;
    js.close()?;
    Ok(())
}

fn log_add_response(
    msg: &LdapResult, js: &mut JsonBuilder, budget: &mut LdapLogBudget,
) -> Result<(), JsonError> {
    js.open_object("add_response")?;
    log_ldap_result(msg, js, budget)?;
    js.close()?;
    Ok(())
}

fn log_del_response(
    msg: &LdapResult, js: &mut JsonBuilder, budget: &mut LdapLogBudget,
) -> Result<(), JsonError> {
    js.open_object("del_response")?;
    log_ldap_result(msg, js, budget)?;
    js.close()?;
    Ok(())
}

fn log_mod_dn_response(
    msg: &LdapResult, js: &mut JsonBuilder, budget: &mut LdapLogBudget,
) -> Result<(), JsonError> {
    js.open_object("mod_dn_response")?;
    log_ldap_result(msg, js, budget)?;
    js.close()?;
    Ok(())
}

fn log_compare_response(
    msg: &LdapResult, js: &mut JsonBuilder, budget: &mut LdapLogBudget,
) -> Result<(), JsonError> {
    js.open_object("compare_response")?;
    log_ldap_result(msg, js, budget)?;
    js.close()?;
    Ok(())
}

fn log_extended_response(
    msg: &ExtendedResponse, js: &mut JsonBuilder, budget: &mut LdapLogBudget,
) -> Result<(), JsonError> {
    js.open_object("extended_response")?;
    log_ldap_result(&msg.result, js, budget)?;
    if let Some(name) = &msg.response_name {
        ldap_set_string(budget, js, "name", &name.0)?;
    }
    if let Some(value) = &msg.response_value {
        ldap_set_bytes(budget, js, "value", &value[..])?;
    }
    js.close()?;
    Ok(())
}

fn log_intermediate_response(
    msg: &IntermediateResponse, js: &mut JsonBuilder, budget: &mut LdapLogBudget,
) -> Result<(), JsonError> {
    js.open_object("intermediate_response")?;
    if let Some(name) = &msg.response_name {
        ldap_set_string(budget, js, "name", &name.0)?;
    }
    if let Some(value) = &msg.response_value {
        ldap_set_bytes(budget, js, "value", &value[..])?;
    }
    js.close()?;
    Ok(())
}

fn log_ldap_result(
    msg: &LdapResult, js: &mut JsonBuilder, budget: &mut LdapLogBudget,
) -> Result<(), JsonError> {
    if let Some(rc) = LdapResultCode::from_u(msg.result_code.0) {
        ldap_set_string(budget, js, "result_code", rc.to_str())?;
    } else {
        ldap_set_string(
            budget,
            js,
            "result_code",
            &format!("unknown-{}", msg.result_code.0),
        )?;
    }
    ldap_set_string(budget, js, "matched_dn", &msg.matched_dn.0)?;
    ldap_set_string(budget, js, "message", &msg.diagnostic_message.0)?;
    Ok(())
}

fn log_controls(
    controls: &Option<Vec<Control>>, js: &mut JsonBuilder, budget: &mut LdapLogBudget,
) -> Result<(), JsonError> {
    if let Some(ctls) = controls {
        js.open_array("controls")?;
        for ctl in ctls {
            js.start_object()?;
            ldap_set_string(budget, js, "control_type", &ctl.control_type.0)?;
            js.set_bool("criticality", ctl.criticality)?;
            if let Some(ctl_val) = &ctl.control_value {
                ldap_set_hex(budget, js, "control_value", ctl_val)?;
            };
            js.close()?;
        }
        js.close()?;
    }
    Ok(())
}

#[no_mangle]
pub unsafe extern "C" fn SCLdapLoggerLog(
    tx: *mut std::os::raw::c_void, js: &mut JsonBuilder,
) -> bool {
    let tx = cast_pointer!(tx, LdapTransaction);
    log_ldap(tx, js).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ldap_append_multibyte() {
        let mut budget = LdapLogBudget::new();
        let mut js = JsonBuilder::try_new_array().unwrap();
        let mut val = vec![b'A'; LDAP_LOG_MAX_STRING - 1];
        val.extend_from_slice("é".as_bytes());
        val.extend_from_slice(b"tail");
        ldap_append_bytes(&mut budget, &mut js, &val).unwrap();
        assert!(budget.truncated);
        assert!(js.as_str().contains("[truncated"), "{}", js.as_str());
    }

    #[test]
    fn test_ldap_set_binary() {
        let mut budget = LdapLogBudget::new();
        let mut js = JsonBuilder::try_new_object().unwrap();
        ldap_set_bytes(&mut budget, &mut js, "v", &[0xff; 10]).unwrap();
        assert!(js.as_str().contains("\\xff"), "{}", js.as_str());
    }
}
