/* Copyright (C) 2021 Open Information Security Foundation
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

const QUIC_LOG_MAX_STRING: usize = 8 * 1024;
const QUIC_LOG_MAX_EXTENSIONS: usize = 256;
const QUIC_LOG_MAX_EXT_VALUES: usize = 32;
const QUIC_LOG_MAX_EXT_BYTES: usize = 64 * 1024;
const QUIC_LOG_MAX_CYU: usize = 64;

struct QuicLogBudget {
    ext_bytes: usize,
    truncated: bool,
}

fn append_limited_string(
    js: &mut JsonBuilder, data: &[u8], limit: usize, budget: &mut QuicLogBudget,
) -> Result<(), JsonError> {
    if data.len() > limit {
        budget.truncated = true;
    }
    js.append_string_from_bytes_limited(data, limit)?;
    Ok(())
}

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

fn log_quic(tx: &QuicTransaction, js: &mut JsonBuilder) -> Result<(), JsonError> {
    let mut budget = QuicLogBudget {
        ext_bytes: 0,
        truncated: false,
    };
    js.open_object("quic")?;
    if tx.header.ty != QuicType::Short {
        js.set_string("version", String::from(tx.header.version).as_str())?;

        if let Some(sni) = &tx.sni {
            if sni.len() > QUIC_LOG_MAX_STRING {
                budget.truncated = true;
            }
            js.set_string_from_bytes_limited("sni", sni, QUIC_LOG_MAX_STRING)?;
        }
        if let Some(ua) = &tx.ua {
            if ua.len() > QUIC_LOG_MAX_STRING {
                budget.truncated = true;
            }
            js.set_string_from_bytes_limited("ua", ua, QUIC_LOG_MAX_STRING)?;
        }
    }
    if !tx.cyu.is_empty() {
        let mut cyu_truncated = tx.cyu.len() > QUIC_LOG_MAX_CYU;
        js.open_array("cyu")?;
        for cyu in tx.cyu.iter().take(QUIC_LOG_MAX_CYU) {
            js.start_object()?;
            js.set_string("hash", &cyu.hash)?;
            if cyu.string.len() > QUIC_LOG_MAX_STRING {
                cyu_truncated = true;
            }
            js.set_string_from_bytes_limited("string", cyu.string.as_bytes(), QUIC_LOG_MAX_STRING)?;
            js.close()?;
        }
        js.close()?;
        if cyu_truncated {
            js.set_bool("cyu_truncated", true)?;
            budget.truncated = true;
        }
    }

    if let Some(ja3) = &tx.ja3 {
        if tx.client {
            js.open_object("ja3")?;
        } else {
            js.open_object("ja3s")?;
        }
        let hash = format!("{:x}", Md5::new().chain(ja3).finalize());
        js.set_string("hash", &hash)?;
        if ja3.len() > QUIC_LOG_MAX_STRING {
            budget.truncated = true;
        }
        js.set_string_from_bytes_limited("string", ja3.as_bytes(), QUIC_LOG_MAX_STRING)?;
        js.close()?;
    }

    if let Some(ref ja4) = &tx.ja4 {
        let val = ja4.as_ref();
        if val.len() > QUIC_LOG_MAX_STRING {
            budget.truncated = true;
        }
        js.set_string_from_bytes_limited("ja4", val.as_bytes(), QUIC_LOG_MAX_STRING)?;
    }

    if !tx.extv.is_empty() {
        let mut ext_truncated = tx.extv.len() > QUIC_LOG_MAX_EXTENSIONS;
        js.open_array("extensions")?;
        for e in tx.extv.iter().take(QUIC_LOG_MAX_EXTENSIONS) {
            js.start_object()?;
            let etype = u16::from(e.etype);
            if let Some(s) = quic_tls_extension_name(etype) {
                js.set_string("name", &s)?;
            }
            js.set_uint("type", etype)?;

            if !e.values.is_empty() {
                if e.values.len() > QUIC_LOG_MAX_EXT_VALUES {
                    ext_truncated = true;
                }
                js.open_array("values")?;
                for v in e.values.iter().take(QUIC_LOG_MAX_EXT_VALUES) {
                    let remaining = QUIC_LOG_MAX_EXT_BYTES.saturating_sub(budget.ext_bytes);
                    if remaining == 0 {
                        ext_truncated = true;
                        break;
                    }
                    let limit = v.len().min(remaining).min(QUIC_LOG_MAX_STRING);
                    if limit < v.len() {
                        ext_truncated = true;
                        budget.truncated = true;
                    }
                    budget.ext_bytes += limit;
                    append_limited_string(js, v, limit, &mut budget)?;
                }
                js.close()?;
            }
            js.close()?;
        }
        js.close()?;
        if ext_truncated {
            js.set_bool("extensions_truncated", true)?;
            budget.truncated = true;
        }
    }

    if budget.truncated {
        js.set_bool("truncated", true)?;
    }
    js.close()?;
    Ok(())
}

#[no_mangle]
pub unsafe extern "C" fn SCQuicLogJson(
    tx: *mut std::os::raw::c_void, js: &mut JsonBuilder,
) -> bool {
    let tx = cast_pointer!(tx, QuicTransaction);
    log_quic(tx, js).is_ok()
}

#[cfg(test)]
mod tests {
    use super::super::frames::QuicTlsExtension;
    use super::*;
    use crate::quic::quic::new_test_tx;
    use tls_parser::TlsExtensionType;

    #[test]
    fn test_quic_log_limits() {
        let mut tx = new_test_tx();
        tx.sni = Some(vec![b'A'; 9000]);
        tx.ua = Some(vec![b'B'; 9000]);
        tx.ja3 = Some("C".repeat(9000));
        tx.extv = (0..300)
            .map(|i| QuicTlsExtension {
                etype: TlsExtensionType(0x1000 + i as u16),
                values: (0..40).map(|_| vec![b'D'; 300]).collect(),
            })
            .collect();
        for _ in 0..100 {
            tx.push_test_cyu("E".repeat(9000));
        }

        let mut jb = JsonBuilder::try_new_object().unwrap();
        log_quic(&tx, &mut jb).unwrap();
        jb.close().unwrap();
        let s = jb.as_str();

        assert!(s.contains("\"truncated\":true"), "missing aggregate marker");
        assert!(s.contains("\"extensions_truncated\":true"));
        assert!(s.contains("\"cyu_truncated\":true"));
        assert!(s.matches("[truncated").count() >= 4);
        assert!(s.len() < 2 * 1024 * 1024, "record too large: {}", s.len());
    }
}
