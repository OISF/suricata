/* Copyright (C) 2020 Open Information Security Foundation
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

use std;
use super::ikev1::{IKEV1Transaction, IKEV1State};
use crate::ikev1::parser::{SaAttribute, ExchangeType, IsakmpPayloadType};
use crate::jsonbuilder::{JsonBuilder, JsonError};
use std::convert::TryFrom;

const LOG_EXTENDED:    u32 = 0x01;

fn add_attributes(transform: &Vec<SaAttribute>, flags: u32, js: &mut JsonBuilder) -> Result<(), JsonError> {
    for attribute in transform {
        if let Some(numeric_value) = attribute.numeric_value {
            js.set_uint(
                attribute.attribute_type.to_string().as_str(),
                numeric_value as u64)?;
        } else if let Some(hex_value) = &attribute.hex_value {
            js.set_string(
                attribute.attribute_type.to_string().as_str(),
                &hex_value)?;
        }

        if (flags & LOG_EXTENDED) == LOG_EXTENDED {
            js.set_string(
                format!("{}_verbose", attribute.attribute_type).as_str(),
                format!("{}", attribute.attribute_value.to_string()).as_str()
            )?;
        }
    }

    return Ok(());
}

fn log_ikev1(state: &IKEV1State, tx: &IKEV1Transaction, flags: u32, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.open_object("ikev1")?;

    if let Some(spi_initiator) = &tx.spi_initiator {
        js.set_string("spi_initiator", spi_initiator)?;
    }
    if let Some(spi_responder) = &tx.spi_responder {
        js.set_string("spi_responder", spi_responder)?;
    }

    if let Some(maj_ver) = tx.maj_ver {
        js.set_uint("maj_ver", maj_ver as u64)?;
    }
    if let Some(min_ver) = tx.min_ver {
        js.set_uint("min_ver", min_ver as u64)?;
    }
    if let Some(payload_types) = &tx.payload_types {
        js.open_array("contained_payload_types")?;
        for pt in payload_types {
            js.append_string(pt.to_string().as_str())?;
        }
        js.close()?; // contained_payload_types

        if (flags & LOG_EXTENDED) == LOG_EXTENDED {
            js.open_array("contained_payload_types_verbose")?;
            for pt in payload_types {
                match *pt {
                    1 => js.append_string(IsakmpPayloadType::SecurityAssociation.to_string().as_str())?,
                    2 => js.append_string(IsakmpPayloadType::Proposal.to_string().as_str())?,
                    3 => js.append_string(IsakmpPayloadType::Transform.to_string().as_str())?,
                    4 => js.append_string(IsakmpPayloadType::KeyExchange.to_string().as_str())?,
                    5 => js.append_string(IsakmpPayloadType::Identification.to_string().as_str())?,
                    6 => js.append_string(IsakmpPayloadType::Certificate.to_string().as_str())?,
                    7 => js.append_string(IsakmpPayloadType::CertificateRequest.to_string().as_str())?,
                    8 => js.append_string(IsakmpPayloadType::Hash.to_string().as_str())?,
                    9 => js.append_string(IsakmpPayloadType::Signature.to_string().as_str())?,
                    10 => js.append_string(IsakmpPayloadType::Nonce.to_string().as_str())?,
                    11 => js.append_string(IsakmpPayloadType::Notification.to_string().as_str())?,
                    12 => js.append_string(IsakmpPayloadType::Delete.to_string().as_str())?,
                    13 => js.append_string(IsakmpPayloadType::VendorID.to_string().as_str())?,
                    15 => js.append_string(IsakmpPayloadType::SaKekPayload.to_string().as_str())?,
                    16 => js.append_string(IsakmpPayloadType::SaTekPayload.to_string().as_str())?,
                    17 => js.append_string(IsakmpPayloadType::KeyDownload.to_string().as_str())?,
                    18 => js.append_string(IsakmpPayloadType::SequenceNumber.to_string().as_str())?,
                    19 => js.append_string(IsakmpPayloadType::ProofOfPossession.to_string().as_str())?,
                    20 => js.append_string(IsakmpPayloadType::NatDiscovery.to_string().as_str())?,
                    21 => js.append_string(IsakmpPayloadType::NatOriginalAddress.to_string().as_str())?,
                    22 => js.append_string(IsakmpPayloadType::GroupAssociatedPolicy.to_string().as_str())?,
                    _ => js.append_string("")?
                };
            }
            js.close()?; // contained_payload_types_verbose
        }

    }
    if let Some(doi) = state.domain_of_interpretation {
        js.set_uint("doi", doi as u64)?;
    }
    js.set_bool("encrypted_payloads", tx.encrypted_payloads)?;

    if let Some(exchange_type) = tx.exchange_type {
        js.set_uint("exchange_type", exchange_type as u64)?;

        if (flags & LOG_EXTENDED) == LOG_EXTENDED {
            match exchange_type {
                1 => js.set_string("exchange_type_verbose", ExchangeType::Base.to_string().as_str())?,
                2 => js.set_string("exchange_type_verbose", ExchangeType::IdentityProtection.to_string().as_str())?,
                3 => js.set_string("exchange_type_verbose", ExchangeType::AuthenticationOnly.to_string().as_str())?,
                4 => js.set_string("exchange_type_verbose", ExchangeType::Aggressive.to_string().as_str())?,
                5 => js.set_string("exchange_type_verbose", ExchangeType::Informational.to_string().as_str())?,
                6 => js.set_string("exchange_type_verbose", ExchangeType::Transaction.to_string().as_str())?,
                32 => js.set_string("exchange_type_verbose", ExchangeType::QuickMode.to_string().as_str())?,
                33 => js.set_string("exchange_type_verbose", ExchangeType::NewGroupMode.to_string().as_str())?,
                _ => js.set_string("exchange_type_verbose", ExchangeType::None.to_string().as_str())?
            };
        }
    }

    if !tx.encrypted_payloads {
        // enable logging of collected state if not-encrypted payloads

        // client data
        js.open_object("client")?;
        if state.client_key_exchange.len() > 0 {
            js.set_string("key_exchange_payload", &state.client_key_exchange)?;
            if let Ok(client_key_length) = u64::try_from(state.client_key_exchange.len()) {
                js.set_uint("key_exchange_payload_length", client_key_length / 2)?;
            }
        }
        if state.client_nonce.len() > 0 {
            js.set_string("nonce_payload", &state.client_nonce)?;
            if let Ok(client_nonce_length) = u64::try_from(state.client_nonce.len()) {
                js.set_uint("nonce_payload_length", client_nonce_length / 2)?;
            }
        }

        js.open_array("proposals")?;
        for client_transform in &state.client_transforms {
            js.start_object()?;
            add_attributes(client_transform, flags, js)?;
            js.close()?;
        }
        js.close()?; // proposals
        js.close()?; // client

        // server data
        js.open_object("server")?;
        if state.server_key_exchange.len() > 0 {
            js.set_string("key_exchange_payload", &state.server_key_exchange)?;
            if let Ok(server_key_length) = u64::try_from(state.server_key_exchange.len()) {
                js.set_uint("key_exchange_payload_length", server_key_length / 2)?;
            }
        }
        if state.server_nonce.len() > 0 {
            js.set_string("nonce_payload", &state.server_nonce)?;
            if let Ok(server_nonce_length) = u64::try_from(state.server_nonce.len()) {
                js.set_uint("nonce_payload_length", server_nonce_length / 2)?;
            }
        }
        let mut index = 0;
        for server_transform in &state.server_transforms {
            if index >= 1 {
                // this should never happen!
                break;
            }

            js.open_object("chosen_proposal")?;
            add_attributes(server_transform, flags, js)?;
            js.close()?;
            index += 1;
        }
        js.close()?; // server

        js.open_array("vendor_ids")?;
        for vendor in state.client_vendor_ids.union(&state.server_vendor_ids) {
            js.append_string(vendor)?;
        }
        js.close()?; // vendor_ids
    }
    js.close()?; // mqtt

    return Ok(());
}

#[no_mangle]
pub extern "C" fn rs_ikev1_logger_log(state: &mut IKEV1State, tx: *mut std::os::raw::c_void, flags: u32, js: &mut JsonBuilder) -> bool {
    let tx = cast_pointer!(tx, IKEV1Transaction);
    log_ikev1(state, tx, flags, js).is_ok()
}
