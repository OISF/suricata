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

use std::convert::From;
use std::fmt;
use std::fmt::{Display, Formatter};

use ldap_parser::asn1_rs::{FromBer, ParseResult};
use ldap_parser::error::LdapError;

use crate::ldap::filters::*;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Operation(pub u32);

impl Display for Operation {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self.0 {
            0 => write!(f, "add"),
            1 => write!(f, "delete"),
            2 => write!(f, "replace"),
            _ => write!(f, "{}", self.0),
        }
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct ResultCode(pub u32);

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct MessageID(pub u32);

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct SearchScope(pub u32);

impl Display for SearchScope {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self.0 {
            0 => write!(f, "base_object"),
            1 => write!(f, "single_level"),
            2 => write!(f, "whole_subtree"),
            _ => write!(f, "{}", self.0),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct DerefAliases(pub u32);

impl Display for DerefAliases {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self.0 {
            0 => write!(f, "never_deref_aliases"),
            1 => write!(f, "deref_in_searching"),
            2 => write!(f, "deref_finding_base_obj"),
            3 => write!(f, "deref_always"),
            _ => write!(f, "{}", self.0),
        }
    }
}

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
pub struct ModifyRequest {
    pub object: LdapDN,
    pub changes: Vec<Change>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModifyResponse {
    pub result: LdapResult,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Change {
    pub operation: Operation,
    pub modification: PartialAttribute,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AddRequest {
    pub entry: LdapDN,
    pub attributes: Vec<Attribute>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModDnRequest {
    pub entry: LdapDN,
    pub newrdn: RelativeLdapDN,
    pub deleteoldrdn: bool,
    pub newsuperior: Option<LdapDN>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompareRequest {
    pub entry: LdapDN,
    pub ava: AttributeValueAssertion,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AbandonRequest {
    pub message_id: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtendedRequest {
    pub request_name: LdapOID,
    pub request_value: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtendedResponse {
    pub result: LdapResult,
    pub response_name: Option<LdapOID>,
    pub response_value: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntermediateResponse {
    pub response_name: Option<LdapOID>,
    pub response_value: Option<Vec<u8>>,
}

#[derive(Clone, Debug, EnumStringU32)]
#[repr(u32)]
pub enum LdapResultCode {
    Success = 0,
    OperationsError = 1,
    ProtocolError = 2,
    TimeLimitExceeded = 3,
    SizeLimitExceeded = 4,
    CompareFalse = 5,
    CompareTrue = 6,
    AuthMethodNotSupported = 7,
    StrongerAuthRequired = 8,
    Referral = 10,
    AdminLimitExceeded = 11,
    UnavailableCriticalExtension = 12,
    ConfidentialityRequired = 13,
    SaslBindInProgress = 14,
    NoSuchAttribute = 16,
    UndefinedAttributeType = 17,
    InappropriateMatching = 18,
    ConstraintViolation = 19,
    AttributeOrValueExists = 20,
    InvalidAttributeSyntax = 21,
    NoSuchObject = 32,
    AliasProblem = 33,
    InvalidDnsSyntax = 34,
    IsLeaf = 35,
    AliasDereferencingProblem = 36,
    InappropriateAuthentication = 48,
    InvalidCredentials = 49,
    InsufficientAccessRights = 50,
    Busy = 51,
    Unavailable = 52,
    UnwillingToPerform = 53,
    LoopDetect = 54,
    SortControlMissing = 60,
    OffsetRangeError = 61,
    NamingViolation = 64,
    ObjectClassViolation = 65,
    NotAllowedOnNonLeaf = 66,
    NotAllowedOnRdn = 67,
    EntryAlreadyExists = 68,
    ObjectClassModsProhibited = 69,
    ResultsTooLarge = 70,
    AffectsMultipleDsas = 71,
    ControlError = 76,
    Other = 80,
    ServerDown = 81,
    LocalError = 82,
    EncodingError = 83,
    DecodingError = 84,
    Timeout = 85,
    AuthUnknown = 86,
    FilterError = 87,
    UserCanceled = 88,
    ParamError = 89,
    NoMemory = 90,
    ConnectError = 91,
    NotSupported = 92,
    ControlNotFound = 93,
    NoResultsReturned = 94,
    MoreResultsToReturn = 95,
    ClientLoop = 96,
    ReferralLimitExceeded = 97,
    InvalidResponse = 100,
    AmbiguousResponse = 101,
    TlsNotSupported = 112,
    IntermediateResponse = 113,
    UnknownType = 114,
    Canceled = 118,
    NoSuchOperation = 119,
    TooLate = 120,
    CannotCancel = 121,
    AssertionFailed = 122,
    AuthorizationDenied = 123,
    ESyncRefreshRequired = 4096,
    NoOperation = 16654,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProtocolOp {
    BindRequest(BindRequest),
    BindResponse(BindResponse),
    UnbindRequest,
    SearchRequest(SearchRequest),
    SearchResultEntry(SearchResultEntry),
    SearchResultDone(LdapResult),
    SearchResultReference(Vec<LdapString>),
    ModifyRequest(ModifyRequest),
    ModifyResponse(ModifyResponse),
    AddRequest(AddRequest),
    AddResponse(LdapResult),
    DelRequest(LdapDN),
    DelResponse(LdapResult),
    ModDnRequest(ModDnRequest),
    ModDnResponse(LdapResult),
    CompareRequest(CompareRequest),
    CompareResponse(LdapResult),
    ExtendedRequest(ExtendedRequest),
    ExtendedResponse(ExtendedResponse),
    IntermediateResponse(IntermediateResponse),
    AbandonRequest(AbandonRequest),
}

#[derive(Clone, Debug, Default, EnumStringU8)]
#[repr(u8)]
pub enum ProtocolOpCode {
    #[default]
    BindRequest = 0,
    BindResponse = 1,
    UnbindRequest = 2,
    SearchRequest = 3,
    SearchResultEntry = 4,
    SearchResultDone = 5,
    SearchResultReference = 19,
    ModifyRequest = 6,
    ModifyResponse = 7,
    AddRequest = 8,
    AddResponse = 9,
    DelRequest = 10,
    DelResponse = 11,
    ModDnRequest = 12,
    ModDnResponse = 13,
    CompareRequest = 14,
    CompareResponse = 15,
    AbandonRequest = 16,
    ExtendedRequest = 23,
    ExtendedResponse = 24,
    IntermediateResponse = 25,
}

impl ProtocolOp {
    pub fn to_u8(&self) -> u8 {
        match self {
            ProtocolOp::BindRequest(_) => 0,
            ProtocolOp::BindResponse(_) => 1,
            ProtocolOp::UnbindRequest => 2,
            ProtocolOp::SearchRequest(_) => 3,
            ProtocolOp::SearchResultEntry(_) => 4,
            ProtocolOp::SearchResultDone(_) => 5,
            ProtocolOp::SearchResultReference(_) => 19,
            ProtocolOp::ModifyRequest(_) => 6,
            ProtocolOp::ModifyResponse(_) => 7,
            ProtocolOp::AddRequest(_) => 8,
            ProtocolOp::AddResponse(_) => 9,
            ProtocolOp::DelRequest(_) => 10,
            ProtocolOp::DelResponse(_) => 11,
            ProtocolOp::ModDnRequest(_) => 12,
            ProtocolOp::ModDnResponse(_) => 13,
            ProtocolOp::CompareRequest(_) => 14,
            ProtocolOp::CompareResponse(_) => 15,
            ProtocolOp::AbandonRequest(_) => 16,
            ProtocolOp::ExtendedRequest(_) => 23,
            ProtocolOp::ExtendedResponse(_) => 24,
            ProtocolOp::IntermediateResponse(_) => 25,
        }
    }
}

impl Display for ProtocolOp {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            ProtocolOp::BindRequest(_) => write!(f, "bind_request"),
            ProtocolOp::BindResponse(_) => write!(f, "bind_response"),
            ProtocolOp::UnbindRequest => write!(f, "unbind_request"),
            ProtocolOp::SearchRequest(_) => write!(f, "search_request"),
            ProtocolOp::SearchResultEntry(_) => write!(f, "search_result_entry"),
            ProtocolOp::SearchResultDone(_) => write!(f, "search_result_done"),
            ProtocolOp::SearchResultReference(_) => write!(f, "search_result_reference"),
            ProtocolOp::ModifyRequest(_) => write!(f, "modify_request"),
            ProtocolOp::ModifyResponse(_) => write!(f, "modify_response"),
            ProtocolOp::AddRequest(_) => write!(f, "add_request"),
            ProtocolOp::AddResponse(_) => write!(f, "add_response"),
            ProtocolOp::DelRequest(_) => write!(f, "del_request"),
            ProtocolOp::DelResponse(_) => write!(f, "del_response"),
            ProtocolOp::ModDnRequest(_) => write!(f, "mod_dn_request"),
            ProtocolOp::ModDnResponse(_) => write!(f, "mod_dn_response"),
            ProtocolOp::CompareRequest(_) => write!(f, "compare_request"),
            ProtocolOp::CompareResponse(_) => write!(f, "compare_response"),
            ProtocolOp::AbandonRequest(_) => write!(f, "abandon_request"),
            ProtocolOp::ExtendedRequest(_) => write!(f, "extended_request"),
            ProtocolOp::ExtendedResponse(_) => write!(f, "extended_response"),
            ProtocolOp::IntermediateResponse(_) => write!(f, "intermediate_response"),
        }
    }
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

impl From<ldap_parser::ldap::LdapMessage<'_>> for LdapMessage {
    fn from(ldap_msg: ldap_parser::ldap::LdapMessage) -> Self {
        let message_id = MessageID(ldap_msg.message_id.0);
        let protocol_op = match ldap_msg.protocol_op {
            ldap_parser::ldap::ProtocolOp::BindRequest(msg) => Self::from_bind_request(msg),
            ldap_parser::ldap::ProtocolOp::BindResponse(msg) => Self::from_bind_response(msg),
            ldap_parser::ldap::ProtocolOp::UnbindRequest => ProtocolOp::UnbindRequest,
            ldap_parser::ldap::ProtocolOp::SearchRequest(msg) => Self::from_search_request(msg),
            ldap_parser::ldap::ProtocolOp::SearchResultEntry(msg) => {
                Self::from_search_result_entry(msg)
            }
            ldap_parser::ldap::ProtocolOp::SearchResultDone(msg) => {
                Self::from_search_result_done(msg)
            }
            ldap_parser::ldap::ProtocolOp::SearchResultReference(msg) => {
                Self::from_search_result_reference(msg)
            }
            ldap_parser::ldap::ProtocolOp::ModifyRequest(msg) => Self::from_modify_request(msg),
            ldap_parser::ldap::ProtocolOp::ModifyResponse(msg) => Self::from_modify_response(msg),
            ldap_parser::ldap::ProtocolOp::AddRequest(msg) => Self::from_add_request(msg),
            ldap_parser::ldap::ProtocolOp::AddResponse(msg) => Self::from_add_response(msg),
            ldap_parser::ldap::ProtocolOp::DelRequest(msg) => Self::from_del_request(msg),
            ldap_parser::ldap::ProtocolOp::DelResponse(msg) => Self::from_del_response(msg),
            ldap_parser::ldap::ProtocolOp::ModDnRequest(msg) => Self::from_mod_dn_request(msg),
            ldap_parser::ldap::ProtocolOp::ModDnResponse(msg) => Self::from_mod_dn_response(msg),
            ldap_parser::ldap::ProtocolOp::CompareRequest(msg) => Self::from_compare_request(msg),
            ldap_parser::ldap::ProtocolOp::CompareResponse(msg) => Self::from_compare_response(msg),
            ldap_parser::ldap::ProtocolOp::ExtendedRequest(msg) => Self::from_extended_request(msg),
            ldap_parser::ldap::ProtocolOp::ExtendedResponse(msg) => {
                Self::from_extended_response(msg)
            }
            ldap_parser::ldap::ProtocolOp::IntermediateResponse(msg) => {
                Self::from_intermediate_response(msg)
            }
            ldap_parser::ldap::ProtocolOp::AbandonRequest(msg) => Self::from_abandon_request(msg),
        };
        let controls = ldap_msg.controls.map(|ctls| {
            ctls.iter()
                .map(|ctl| Control {
                    control_type: LdapOID(ctl.control_type.0.to_string()),
                    criticality: ctl.criticality,
                    control_value: ctl.control_value.as_ref().map(|val| val.to_vec()),
                })
                .collect()
        });

        Self {
            message_id,
            protocol_op,
            controls,
        }
    }
}

impl LdapMessage {
    pub fn is_request(&self) -> bool {
        match self.protocol_op {
            ProtocolOp::BindRequest(_)
            | ProtocolOp::UnbindRequest
            | ProtocolOp::SearchRequest(_)
            | ProtocolOp::ModifyRequest(_)
            | ProtocolOp::AddRequest(_)
            | ProtocolOp::DelRequest(_)
            | ProtocolOp::ModDnRequest(_)
            | ProtocolOp::CompareRequest(_)
            | ProtocolOp::AbandonRequest(_)
            | ProtocolOp::ExtendedRequest(_) => {
                return true;
            }
            _ => {
                return false;
            }
        }
    }

    pub fn is_response(&self) -> bool {
        // it is either a response or a request
        return !self.is_request();
    }

    fn from_bind_request(msg: ldap_parser::ldap::BindRequest) -> ProtocolOp {
        let authentication = match msg.authentication {
            ldap_parser::ldap::AuthenticationChoice::Simple(val) => {
                AuthenticationChoice::Simple(val.to_vec())
            }
            ldap_parser::ldap::AuthenticationChoice::Sasl(val) => {
                AuthenticationChoice::Sasl(SaslCredentials {
                    mechanism: LdapString(val.mechanism.0.to_string()),
                    credentials: val.credentials.map(|creds| creds.to_vec()),
                })
            }
        };
        ProtocolOp::BindRequest(BindRequest {
            version: msg.version,
            name: LdapDN(msg.name.0.to_string()),
            authentication,
        })
    }

    fn from_bind_response(msg: ldap_parser::ldap::BindResponse) -> ProtocolOp {
        ProtocolOp::BindResponse(BindResponse {
            result: LdapResult {
                result_code: ResultCode(msg.result.result_code.0),
                matched_dn: LdapDN(msg.result.matched_dn.0.to_string()),
                diagnostic_message: LdapString(msg.result.diagnostic_message.0.to_string()),
            },
            server_sasl_creds: msg
                .server_sasl_creds
                .map(|server_sasl_creds| server_sasl_creds.to_vec()),
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
        let attributes = msg.attributes.iter().map(PartialAttribute::from).collect();
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

    fn from_search_result_reference(msg: Vec<ldap_parser::ldap::LdapString<'_>>) -> ProtocolOp {
        let strs = msg.iter().map(|s| LdapString(s.0.to_string())).collect();
        ProtocolOp::SearchResultReference(strs)
    }

    fn from_modify_request(msg: ldap_parser::ldap::ModifyRequest) -> ProtocolOp {
        let changes = msg
            .changes
            .iter()
            .map(|c| Change {
                operation: Operation(c.operation.0),
                modification: PartialAttribute::from(&c.modification),
            })
            .collect();
        ProtocolOp::ModifyRequest(ModifyRequest {
            object: LdapDN(msg.object.0.to_string()),
            changes,
        })
    }

    fn from_modify_response(msg: ldap_parser::ldap::ModifyResponse) -> ProtocolOp {
        ProtocolOp::ModifyResponse(ModifyResponse {
            result: LdapResult {
                result_code: ResultCode(msg.result.result_code.0),
                matched_dn: LdapDN(msg.result.matched_dn.0.to_string()),
                diagnostic_message: LdapString(msg.result.diagnostic_message.0.to_string()),
            },
        })
    }

    fn from_add_request(msg: ldap_parser::ldap::AddRequest) -> ProtocolOp {
        let attributes = msg.attributes.iter().map(Attribute::from).collect();
        ProtocolOp::AddRequest(AddRequest {
            entry: LdapDN(msg.entry.0.to_string()),
            attributes,
        })
    }

    fn from_add_response(msg: ldap_parser::ldap::LdapResult) -> ProtocolOp {
        ProtocolOp::AddResponse(LdapResult {
            result_code: ResultCode(msg.result_code.0),
            matched_dn: LdapDN(msg.matched_dn.0.to_string()),
            diagnostic_message: LdapString(msg.diagnostic_message.0.to_string()),
        })
    }

    fn from_del_request(msg: ldap_parser::ldap::LdapDN<'_>) -> ProtocolOp {
        ProtocolOp::DelRequest(LdapDN(msg.0.to_string()))
    }

    fn from_del_response(msg: ldap_parser::ldap::LdapResult) -> ProtocolOp {
        ProtocolOp::DelResponse(LdapResult {
            result_code: ResultCode(msg.result_code.0),
            matched_dn: LdapDN(msg.matched_dn.0.to_string()),
            diagnostic_message: LdapString(msg.diagnostic_message.0.to_string()),
        })
    }

    fn from_mod_dn_request(msg: ldap_parser::ldap::ModDnRequest) -> ProtocolOp {
        ProtocolOp::ModDnRequest(ModDnRequest {
            entry: LdapDN(msg.entry.0.to_string()),
            newrdn: RelativeLdapDN(msg.newrdn.0.to_string()),
            deleteoldrdn: msg.deleteoldrdn,
            newsuperior: if let Some(newsuperior) = msg.newsuperior {
                Some(LdapDN(newsuperior.0.to_string()))
            } else {
                None
            },
        })
    }

    fn from_mod_dn_response(msg: ldap_parser::ldap::LdapResult) -> ProtocolOp {
        ProtocolOp::ModDnResponse(LdapResult {
            result_code: ResultCode(msg.result_code.0),
            matched_dn: LdapDN(msg.matched_dn.0.to_string()),
            diagnostic_message: LdapString(msg.diagnostic_message.0.to_string()),
        })
    }

    fn from_compare_request(msg: ldap_parser::ldap::CompareRequest) -> ProtocolOp {
        ProtocolOp::CompareRequest(CompareRequest {
            entry: LdapDN(msg.entry.0.to_string()),
            ava: AttributeValueAssertion::from(&msg.ava),
        })
    }

    fn from_compare_response(msg: ldap_parser::ldap::LdapResult) -> ProtocolOp {
        ProtocolOp::CompareResponse(LdapResult {
            result_code: ResultCode(msg.result_code.0),
            matched_dn: LdapDN(msg.matched_dn.0.to_string()),
            diagnostic_message: LdapString(msg.diagnostic_message.0.to_string()),
        })
    }

    fn from_abandon_request(msg: ldap_parser::ldap::MessageID) -> ProtocolOp {
        ProtocolOp::AbandonRequest(AbandonRequest { message_id: msg.0 })
    }

    fn from_extended_request(msg: ldap_parser::ldap::ExtendedRequest) -> ProtocolOp {
        ProtocolOp::ExtendedRequest(ExtendedRequest {
            request_name: LdapOID(msg.request_name.0.to_string()),
            request_value: msg
                .request_value
                .map(|request_value| request_value.to_vec()),
        })
    }

    fn from_extended_response(msg: ldap_parser::ldap::ExtendedResponse) -> ProtocolOp {
        ProtocolOp::ExtendedResponse(ExtendedResponse {
            result: LdapResult {
                result_code: ResultCode(msg.result.result_code.0),
                matched_dn: LdapDN(msg.result.matched_dn.0.to_string()),
                diagnostic_message: LdapString(msg.result.diagnostic_message.0.to_string()),
            },
            response_name: msg
                .response_name
                .map(|response_name| LdapOID(response_name.0.to_string())),
            response_value: msg
                .response_value
                .map(|response_value| response_value.to_vec()),
        })
    }

    fn from_intermediate_response(msg: ldap_parser::ldap::IntermediateResponse) -> ProtocolOp {
        ProtocolOp::IntermediateResponse(IntermediateResponse {
            response_name: msg
                .response_name
                .map(|response_name| LdapOID(response_name.0.to_string())),
            response_value: msg
                .response_value
                .map(|response_value| response_value.to_vec()),
        })
    }
}

pub fn ldap_parse_msg(input: &[u8]) -> ParseResult<ldap_parser::ldap::LdapMessage, LdapError> {
    ldap_parser::ldap::LdapMessage::from_ber(input)
}
