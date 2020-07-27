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

// Author: Frank Honza <frank.honza@dcso.de>

use std;
use crate::core::{STREAM_TOSERVER};
use crate::log::*;
use crate::applayer::*;
use nom;
use crate::ikev1::parser::*;
use crate::ikev1::ike::IKEV1State;
use std::collections::HashSet;

#[derive(Default)]
pub struct IkeV1Header {
    pub maj_ver: Option<u8>,
    pub min_ver: Option<u8>,
    pub exchange_type: Option<u8>,
    pub encrypted_payloads: bool,

    pub key_exchange: String,
    pub nonce: String,
    pub transforms: Vec<Vec<SaAttribute>>,
    pub vendor_ids: HashSet<String>,
}

pub fn handle_ikev1(mut state: &mut IKEV1State, current: &[u8], isakmp_header: IsakmpHeader, direction: u8) -> AppLayerResult {
    let mut tx = state.new_tx();

    tx.ike_version = 1;
    tx.hdr.spi_initiator = Some(format!("{:016x}", isakmp_header.init_spi));
    tx.hdr.spi_responder = Some(format!("{:016x}", isakmp_header.resp_spi));
    tx.hdr.ikev1_header.maj_ver = Some(isakmp_header.maj_ver);
    tx.hdr.ikev1_header.min_ver = Some(isakmp_header.min_ver);
    tx.hdr.ikev1_header.exchange_type = Some(isakmp_header.exch_type);

    let mut cur_payload_type = isakmp_header.next_payload;
    let mut payload_types: HashSet<u8> = HashSet::new();
    payload_types.insert(cur_payload_type);

    let mut encrypted_payloads = false;
    if isakmp_header.flags & 0x01 == 0x01 {
        encrypted_payloads = true;
    } else {
        match parse_ikev1_payload_list(current) {
            Ok((_rem, payload_list)) => {
                for isakmp_payload in payload_list {
                    if let Err(_) = parse_payload(
                        cur_payload_type,
                        isakmp_payload.data,
                        isakmp_payload.data.len() as u16,
                        &mut state.ikev1_container.domain_of_interpretation,
                        &mut tx.hdr.ikev1_header.key_exchange,
                        &mut tx.hdr.ikev1_header.nonce,
                        &mut tx.hdr.ikev1_header.transforms,
                        &mut tx.hdr.ikev1_header.vendor_ids,
                        &mut payload_types
                    ) {
                        SCLogDebug!("Error while parsing IKEV1 payloads");
                        return AppLayerResult::err();
                    }

                    cur_payload_type = isakmp_payload.payload_header.next_payload;
                }

                if payload_types.contains(&(IsakmpPayloadType::SecurityAssociation as u8)) {
                    // clear transforms on new SA
                    if direction == STREAM_TOSERVER {
                        state.ikev1_container.client_transforms.clear();
                        state.ikev1_container.client_key_exchange.clear();
                        state.ikev1_container.client_nonce.clear();
                        state.ikev1_container.client_vendor_ids.clear();
                    } else {
                        state.ikev1_container.server_transforms.clear();
                        state.ikev1_container.server_key_exchange.clear();
                        state.ikev1_container.server_nonce.clear();
                        state.ikev1_container.server_vendor_ids.clear();
                    }
                }

                // add transaction values to state values
                if direction == STREAM_TOSERVER {
                    state.ikev1_container.client_key_exchange = tx.hdr.ikev1_header.key_exchange.clone();
                } else {
                    state.ikev1_container.server_key_exchange = tx.hdr.ikev1_header.key_exchange.clone();
                }

                if direction == STREAM_TOSERVER {
                    state.ikev1_container.client_nonce = tx.hdr.ikev1_header.nonce.clone();
                } else {
                    state.ikev1_container.server_nonce = tx.hdr.ikev1_header.nonce.clone();
                }

                if direction == STREAM_TOSERVER {
                    state.ikev1_container.client_transforms.extend(tx.hdr.ikev1_header.transforms.iter().cloned());
                } else {
                    state.ikev1_container.server_transforms.extend(tx.hdr.ikev1_header.transforms.iter().cloned());
                }

                if direction == STREAM_TOSERVER {
                    state.ikev1_container.client_vendor_ids.extend(tx.hdr.ikev1_header.vendor_ids.iter().cloned());
                } else {
                    state.ikev1_container.server_vendor_ids.extend(tx.hdr.ikev1_header.vendor_ids.iter().cloned());
                }
            },
            Err(nom::Err::Incomplete(_)) => {
                SCLogDebug!("Insufficient data while parsing IKEV1");
                return AppLayerResult::err();
            }
            Err(_) => {
                SCLogDebug!("Error while parsing payloads and adding to the state");
                return AppLayerResult::err();
            }
        }
    }

    tx.payload_types.ikev1_payload_types = Some(payload_types);
    tx.hdr.ikev1_header.encrypted_payloads = encrypted_payloads;
    state.transactions.push(tx);
    return AppLayerResult::ok();
}