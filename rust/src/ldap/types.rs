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

use std::convert::{From, TryFrom};

use crate::ldap::filters::*;

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct ResultCode(pub u32);

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct MessageID(pub u32);

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct SearchScope(pub u32);

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct DerefAliases(pub u32);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LdapString(pub String);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LdapDN(pub String);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelativeLdapDN(pub String);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LdapOID(pub String);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LdapResult {
    pub result_code: ResultCode,
    pub matched_dn: LdapDN,
    pub diagnostic_message: LdapString,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BindRequest {
    pub version: u8,
    pub name: LdapDN,
    pub authentication: AuthenticationChoice,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SaslCredentials {
    pub mechanism: LdapString,
    pub credentials: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthenticationChoice {
    Simple(Vec<u8>),
    Sasl(SaslCredentials),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BindResponse {
    pub result: LdapResult,
    pub server_sasl_creds: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SearchRequest {
    pub base_object: LdapDN,
    pub scope: SearchScope,
    pub deref_aliases: DerefAliases,
    pub size_limit: u32,
    pub time_limit: u32,
    pub types_only: bool,
    pub filter: Filter,
    pub attributes: Vec<LdapString>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SearchResultEntry {
    pub object_name: LdapDN,
    pub attributes: Vec<PartialAttribute>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProtocolOp {
    BindRequest(BindRequest),
    BindResponse(BindResponse),
    UnbindRequest,
    SearchRequest(SearchRequest),
    SearchResultEntry(SearchResultEntry),
    SearchResultDone(LdapResult),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LdapMessage {
    pub message_id: MessageID,
    pub protocol_op: ProtocolOp,
    pub controls: Option<Vec<Control>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Control {
    pub control_type: LdapOID,
    pub criticality: bool,
    pub control_value: Option<Vec<u8>>,
}

impl<'a> TryFrom<ldap_parser::ldap::LdapMessage<'a>> for LdapMessage {
    type Error = &'static str;

    fn try_from(ldap_msg: ldap_parser::ldap::LdapMessage) -> Result<Self, Self::Error> {
        let message_id = MessageID(ldap_msg.message_id.0);
        let protocol_op = match ldap_msg.protocol_op {
            ldap_parser::ldap::ProtocolOp::BindRequest(msg) => Self::from_bind_request(msg),
            ldap_parser::ldap::ProtocolOp::UnbindRequest => ProtocolOp::UnbindRequest,
            ldap_parser::ldap::ProtocolOp::SearchRequest(msg) => Self::from_search_request(msg),
            ldap_parser::ldap::ProtocolOp::SearchResultEntry(msg) => {
                Self::from_search_result_entry(msg)
            }
            ldap_parser::ldap::ProtocolOp::SearchResultDone(msg) => {
                Self::from_search_result_done(msg)
            }
            _ => return Err("LDAP Message doesn't contain a request"),
        };
        let controls = if let Some(ctls) = ldap_msg.controls {
            Some(
                ctls.iter()
                    .map(|ctl| Control {
                        control_type: LdapOID(ctl.control_type.0.to_string()),
                        criticality: ctl.criticality,
                        control_value: if let Some(val) = &ctl.control_value {
                            Some(val.to_vec())
                        } else {
                            None
                        },
                    })
                    .collect(),
            )
        } else {
            None
        };

        Ok(Self {
            message_id,
            protocol_op,
            controls,
        })
    }
}

impl LdapMessage {
    fn from_bind_request(msg: ldap_parser::ldap::BindRequest) -> ProtocolOp {
        let authentication = match msg.authentication {
            ldap_parser::ldap::AuthenticationChoice::Simple(val) => {
                AuthenticationChoice::Simple(val.to_vec())
            }
            ldap_parser::ldap::AuthenticationChoice::Sasl(val) => {
                AuthenticationChoice::Sasl(SaslCredentials {
                    mechanism: LdapString(val.mechanism.0.to_string()),
                    credentials: if let Some(creds) = val.credentials {
                        Some(creds.to_vec())
                    } else {
                        None
                    },
                })
            }
        };
        ProtocolOp::BindRequest(BindRequest {
            version: msg.version,
            name: LdapDN(msg.name.0.to_string()),
            authentication,
        })
    }

    fn from_search_request(msg: ldap_parser::ldap::SearchRequest) -> ProtocolOp {
        let attributes = msg
            .attributes
            .iter()
            .map(|s| LdapString(s.0.to_string()))
            .collect();
        ProtocolOp::SearchRequest(SearchRequest {
            base_object: LdapDN(msg.base_object.0.to_string()),
            scope: SearchScope(msg.scope.0),
            deref_aliases: DerefAliases(msg.deref_aliases.0),
            size_limit: msg.size_limit,
            time_limit: msg.time_limit,
            types_only: msg.types_only,
            filter: Filter::from(msg.filter),
            attributes,
        })
    }

    fn from_search_result_entry(msg: ldap_parser::ldap::SearchResultEntry) -> ProtocolOp {
        let attributes = msg
            .attributes
            .iter()
            .map(|attr| PartialAttribute::from(attr))
            .collect();
        ProtocolOp::SearchResultEntry(SearchResultEntry {
            object_name: LdapDN(msg.object_name.0.to_string()),
            attributes,
        })
    }

    fn from_search_result_done(msg: ldap_parser::ldap::LdapResult) -> ProtocolOp {
        ProtocolOp::SearchResultDone(LdapResult {
            result_code: ResultCode(msg.result_code.0),
            matched_dn: LdapDN(msg.matched_dn.0.to_string()),
            diagnostic_message: LdapString(msg.diagnostic_message.0.to_string()),
        })
    }
}
