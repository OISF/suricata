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

use super::ike::{IKEState, IKETransaction};
use super::ipsec_parser::IKEV2_FLAG_INITIATOR;
use crate::core::Direction;
use crate::ike::parser::{ExchangeType, IsakmpPayloadType, SaAttribute};
use crate::jsonbuilder::{JsonBuilder, JsonError};
use num_traits::FromPrimitive;
use std;
use std::convert::TryFrom;

const LOG_EXTENDED: u32 = 0x01;

fn add_attributes(transform: &Vec<SaAttribute>, js: &mut JsonBuilder) -> Result<(), JsonError> {
    for attribute in transform {
        js.set_string(
            attribute.attribute_type.to_string().as_str(),
            attribute.attribute_value.to_string().as_str(),
        )?;

        if let Some(numeric_value) = attribute.numeric_value {
            js.set_uint(
                format!("{}_raw", attribute.attribute_type).as_str(),
                numeric_value as u64,
            )?;
        } else if let Some(hex_value) = &attribute.hex_value {
            js.set_string(
                format!("{}_raw", attribute.attribute_type).as_str(),
                hex_value,
            )?;
        }
    }

    Ok(())
}

fn log_ike(
    state: &IKEState, tx: &IKETransaction, flags: u32, jb: &mut JsonBuilder,
) -> Result<(), JsonError> {
    jb.open_object("ike")?;

    jb.set_uint("version_major", tx.hdr.maj_ver as u64)?;
    jb.set_uint("version_minor", tx.hdr.min_ver as u64)?;
    jb.set_string("init_spi", &tx.hdr.spi_initiator)?;
    jb.set_string("resp_spi", &tx.hdr.spi_responder)?;
    jb.set_uint("message_id", tx.hdr.msg_id as u64)?;

    if tx.ike_version == 1 {
        if let Some(exchange_type) = tx.hdr.ikev1_header.exchange_type {
            jb.set_uint("exchange_type", exchange_type as u64)?;
            if (flags & LOG_EXTENDED) == LOG_EXTENDED {
                if let Some(etype) = ExchangeType::from_u8(exchange_type) {
                    jb.set_string("exchange_type_verbose", etype.to_string().as_str())?;
                };
            }
        }
    } else if tx.ike_version == 2 {
        jb.set_uint("exchange_type", tx.hdr.ikev2_header.exch_type.0 as u64)?;
    }

    if tx.ike_version == 1 {
        if state.ikev1_container.server.nb_transforms > 0 {
            // log the first transform as the chosen one
            add_attributes(&state.ikev1_container.server.transform, jb)?;
        }
        if tx.direction == Direction::ToClient && tx.hdr.ikev1_transforms.len() > 1 {
            // in case we have multiple server transforms log them in a list
            jb.open_array("server_proposals")?;
            for server_transform in &tx.hdr.ikev1_transforms {
                jb.start_object()?;
                add_attributes(server_transform, jb)?;
                jb.close()?;
            }
            jb.close()?;
        }
    } else if tx.ike_version == 2 {
        if tx.hdr.flags & IKEV2_FLAG_INITIATOR != 0 {
            jb.set_string("role", "initiator")?;
        } else {
            jb.set_string("role", "responder")?;
            jb.set_string("alg_enc", &format!("{:?}", state.ikev2_container.alg_enc))?;
            jb.set_string("alg_auth", &format!("{:?}", state.ikev2_container.alg_auth))?;
            jb.set_string("alg_prf", &format!("{:?}", state.ikev2_container.alg_prf))?;
            jb.set_string("alg_dh", &format!("{:?}", state.ikev2_container.alg_dh))?;
            jb.set_string("alg_esn", &format!("{:?}", state.ikev2_container.alg_esn))?;
        }
    }

    // payloads in packet
    jb.open_array("payload")?;
    if tx.ike_version == 1 {
        if let Some(payload_types) = &tx.payload_types.ikev1_payload_types {
            for pt in payload_types {
                append_payload_type_extended(jb, pt)?;
            }
        }
    } else if tx.ike_version == 2 {
        for payload in tx.payload_types.ikev2_payload_types.iter() {
            jb.append_string(&format!("{:?}", payload))?;
        }
    }
    jb.close()?;

    if tx.ike_version == 1 {
        log_ikev1(state, tx, jb)?;
    } else if tx.ike_version == 2 {
        log_ikev2(tx, jb)?;
    }
    jb.close()?;
    Ok(())
}

fn log_ikev1(state: &IKEState, tx: &IKETransaction, jb: &mut JsonBuilder) -> Result<(), JsonError> {
    jb.open_object("ikev1")?;

    if let Some(doi) = state.ikev1_container.domain_of_interpretation {
        jb.set_uint("doi", doi as u64)?;
    }
    jb.set_bool("encrypted_payloads", tx.hdr.ikev1_header.encrypted_payloads)?;

    if !tx.hdr.ikev1_header.encrypted_payloads {
        // enable logging of collected state if not-encrypted payloads

        // client data
        jb.open_object("client")?;
        if !state.ikev1_container.client.key_exchange.is_empty() {
            jb.set_string(
                "key_exchange_payload",
                &state.ikev1_container.client.key_exchange,
            )?;
            if let Ok(client_key_length) =
                u64::try_from(state.ikev1_container.client.key_exchange.len())
            {
                jb.set_uint("key_exchange_payload_length", client_key_length / 2)?;
            }
        }
        if !state.ikev1_container.client.nonce.is_empty() {
            jb.set_string("nonce_payload", &state.ikev1_container.client.nonce)?;
            if let Ok(client_nonce_length) = u64::try_from(state.ikev1_container.client.nonce.len())
            {
                jb.set_uint("nonce_payload_length", client_nonce_length / 2)?;
            }
        }

        if tx.direction == Direction::ToServer && !tx.hdr.ikev1_transforms.is_empty() {
            jb.open_array("proposals")?;
            for client_transform in &tx.hdr.ikev1_transforms {
                jb.start_object()?;
                add_attributes(client_transform, jb)?;
                jb.close()?;
            }
            jb.close()?; // proposals
        }
        jb.close()?; // client

        // server data
        jb.open_object("server")?;
        if !state.ikev1_container.server.key_exchange.is_empty() {
            jb.set_string(
                "key_exchange_payload",
                &state.ikev1_container.server.key_exchange,
            )?;
            if let Ok(server_key_length) =
                u64::try_from(state.ikev1_container.server.key_exchange.len())
            {
                jb.set_uint("key_exchange_payload_length", server_key_length / 2)?;
            }
        }
        if !state.ikev1_container.server.nonce.is_empty() {
            jb.set_string("nonce_payload", &state.ikev1_container.server.nonce)?;
            if let Ok(server_nonce_length) = u64::try_from(state.ikev1_container.server.nonce.len())
            {
                jb.set_uint("nonce_payload_length", server_nonce_length / 2)?;
            }
        }
        jb.close()?; // server

        if !tx.hdr.ikev1_header.vendor_ids.is_empty() {
            jb.open_array("vendor_ids")?;
            for vendor in &tx.hdr.ikev1_header.vendor_ids {
                jb.append_string(vendor)?;
            }
            jb.close()?; // vendor_ids
        }
    }
    jb.close()?;

    Ok(())
}

fn append_payload_type_extended(js: &mut JsonBuilder, pt: &u8) -> Result<(), JsonError> {
    if let Some(v) = IsakmpPayloadType::from_u8(*pt) {
        js.append_string(&format!("{:?}", v))?;
    }
    Ok(())
}

fn log_ikev2(tx: &IKETransaction, jb: &mut JsonBuilder) -> Result<(), JsonError> {
    jb.open_object("ikev2")?;

    jb.set_uint("errors", tx.errors as u64)?;
    if !tx.notify_types.is_empty() {
        jb.open_array("notify")?;
        for notify in tx.notify_types.iter() {
            jb.append_string(&format!("{:?}", notify))?;
        }
        jb.close()?;
    }
    jb.close()?;
    Ok(())
}

#[no_mangle]
pub unsafe extern "C" fn rs_ike_logger_log(
    state: &mut IKEState, tx: *mut std::os::raw::c_void, flags: u32, js: &mut JsonBuilder,
) -> bool {
    let tx = cast_pointer!(tx, IKETransaction);
    log_ike(state, tx, flags, js).is_ok()
}
