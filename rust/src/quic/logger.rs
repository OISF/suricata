/* Copyright (C) 2021-2022 Open Information Security Foundation
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

use super::parser::QuicType;
use super::quic::QuicTransaction;
use crate::jsonbuilder::{JsonBuilder, JsonError};
use digest::Digest;
use digest::Update;
use md5::Md5;

fn quic_tls_extension_name(e: u16) -> Option<String> {
    match e {
        0 => Some("server_name".to_string()),
        1 => Some("max_fragment_length".to_string()),
        2 => Some("client_certificate_url".to_string()),
        3 => Some("trusted_ca_keys".to_string()),
        4 => Some("truncated_hmac".to_string()),
        5 => Some("status_request".to_string()),
        6 => Some("user_mapping".to_string()),
        7 => Some("client_authz".to_string()),
        8 => Some("server_authz".to_string()),
        9 => Some("cert_type".to_string()),
        10 => Some("supported_groups".to_string()),
        11 => Some("ec_point_formats".to_string()),
        12 => Some("srp".to_string()),
        13 => Some("signature_algorithms".to_string()),
        14 => Some("use_srtp".to_string()),
        15 => Some("heartbeat".to_string()),
        16 => Some("alpn".to_string()),
        17 => Some("status_request_v2".to_string()),
        18 => Some("signed_certificate_timestamp".to_string()),
        19 => Some("client_certificate_type".to_string()),
        20 => Some("server_certificate_type".to_string()),
        21 => Some("padding".to_string()),
        22 => Some("encrypt_then_mac".to_string()),
        23 => Some("extended_master_secret".to_string()),
        24 => Some("token_binding".to_string()),
        25 => Some("cached_info".to_string()),
        26 => Some("tls_lts".to_string()),
        27 => Some("compress_certificate".to_string()),
        28 => Some("record_size_limit".to_string()),
        29 => Some("pwd_protect".to_string()),
        30 => Some("pwd_clear".to_string()),
        31 => Some("password_salt".to_string()),
        32 => Some("ticket_pinning".to_string()),
        33 => Some("tls_cert_with_extern_psk".to_string()),
        34 => Some("delegated_credentials".to_string()),
        35 => Some("session_ticket".to_string()),
        36 => Some("tlmsp".to_string()),
        37 => Some("tlmsp_proxying".to_string()),
        38 => Some("tlmsp_delegate".to_string()),
        39 => Some("supported_ekt_ciphers".to_string()),
        41 => Some("pre_shared_key".to_string()),
        42 => Some("early_data".to_string()),
        43 => Some("supported_versions".to_string()),
        44 => Some("cookie".to_string()),
        45 => Some("psk_key_exchange_modes".to_string()),
        47 => Some("certificate_authorities".to_string()),
        48 => Some("oid_filters".to_string()),
        49 => Some("post_handshake_auth".to_string()),
        50 => Some("signature_algorithms_cert".to_string()),
        51 => Some("key_share".to_string()),
        52 => Some("transparency_info".to_string()),
        53 => Some("connection_id_deprecated".to_string()),
        54 => Some("connection_id".to_string()),
        55 => Some("external_id_hash".to_string()),
        56 => Some("external_session_id".to_string()),
        57 => Some("quic_transport_parameters".to_string()),
        58 => Some("ticket_request".to_string()),
        59 => Some("dnssec_chain".to_string()),
        13172 => Some("next_protocol_negotiation".to_string()),
        65281 => Some("renegotiation_info".to_string()),
        _ => None,
    }
}

fn log_template(tx: &QuicTransaction, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.open_object("quic")?;
    if tx.header.ty != QuicType::Short {
        js.set_string("version", String::from(tx.header.version).as_str())?;

        if let Some(sni) = &tx.sni {
            js.set_string("sni", &String::from_utf8_lossy(&sni))?;
        }
        if let Some(ua) = &tx.ua {
            js.set_string("ua", &String::from_utf8_lossy(&ua))?;
        }
    }
    if tx.cyu.len() > 0 {
        js.open_array("cyu")?;
        for cyu in &tx.cyu {
            js.start_object()?;
            js.set_string("hash", &cyu.hash)?;
            js.set_string("string", &cyu.string)?;
            js.close()?;
        }
        js.close()?;
    }

    if let Some(ja3) = &tx.ja3 {
        if tx.client {
            js.open_object("ja3")?;
        } else {
            js.open_object("ja3s")?;
        }
        let hash = format!("{:x}", Md5::new().chain(&ja3).finalize());
        js.set_string("hash", &hash)?;
        js.set_string("string", ja3)?;
        js.close()?;
    }
    if tx.extv.len() > 0 {
        js.open_array("extensions")?;
        for e in &tx.extv {
            js.start_object()?;
            let etype = u16::from(e.etype);
            if let Some(s) = quic_tls_extension_name(etype) {
                js.set_string("name", &s)?;
            }
            js.set_uint("type", etype.into())?;

            if e.values.len() > 0 {
                js.open_array("values")?;
                for i in 0..e.values.len() {
                    js.append_string(&String::from_utf8_lossy(&e.values[i]))?;
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

#[no_mangle]
pub unsafe extern "C" fn rs_quic_to_json(
    tx: *mut std::os::raw::c_void, js: &mut JsonBuilder,
) -> bool {
    let tx = cast_pointer!(tx, QuicTransaction);
    log_template(tx, js).is_ok()
}
