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

// Author: Giuseppe Longo <giuseppe@glongo.it>
// Author: Pierre Chifflier <chifflier@wzdftpd.net>

use ldap_parser::asn1_rs::{FromBer, ParseResult};
use ldap_parser::error::LdapError;
use ldap_parser::ldap::{LdapMessage, Operation, ProtocolOp};

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

pub fn ldap_operation_to_string(op: &Operation) -> String {
    match op.0 {
        0 => "add".to_string(),
        1 => "delete".to_string(),
        2 => "replace".to_string(),
        _ => op.0.to_string(),
    }
}

pub fn ldap_protocol_op_as_str(op: &ProtocolOp) -> &'static str {
    match op {
        ProtocolOp::BindRequest(_) => "bind_request",
        ProtocolOp::BindResponse(_) => "bind_response",
        ProtocolOp::UnbindRequest => "unbind_request",
        ProtocolOp::SearchRequest(_) => "search_request",
        ProtocolOp::SearchResultEntry(_) => "search_result_entry",
        ProtocolOp::SearchResultDone(_) => "search_result_done",
        ProtocolOp::SearchResultReference(_) => "search_result_reference",
        ProtocolOp::ModifyRequest(_) => "modify_request",
        ProtocolOp::ModifyResponse(_) => "modify_response",
        ProtocolOp::AddRequest(_) => "add_request",
        ProtocolOp::AddResponse(_) => "add_response",
        ProtocolOp::DelRequest(_) => "del_request",
        ProtocolOp::DelResponse(_) => "del_response",
        ProtocolOp::ModDnRequest(_) => "mod_dn_request",
        ProtocolOp::ModDnResponse(_) => "mod_dn_response",
        ProtocolOp::CompareRequest(_) => "compare_request",
        ProtocolOp::CompareResponse(_) => "compare_response",
        ProtocolOp::AbandonRequest(_) => "abandon_request",
        ProtocolOp::ExtendedRequest(_) => "extended_request",
        ProtocolOp::ExtendedResponse(_) => "extended_response",
        ProtocolOp::IntermediateResponse(_) => "intermediate_response",
    }
}

pub fn ldap_is_request(message: &LdapMessage) -> bool {
    match message.protocol_op {
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

pub fn ldap_is_response(message: &LdapMessage) -> bool {
    // it is either a response or a request
    return !ldap_is_request(message);
}

pub fn ldap_parse_msg(input: &[u8]) -> ParseResult<'_, LdapMessage<'_>, LdapError> {
    LdapMessage::from_ber(input)
}
