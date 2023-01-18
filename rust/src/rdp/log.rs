/* Copyright (C) 2019 Open Information Security Foundation
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

// Author: Zach Kelly <zach.kelly@lmco.com>

use super::rdp::{RdpTransaction, RdpTransactionItem};
use crate::jsonbuilder::{JsonBuilder, JsonError};
use crate::rdp::parser::*;
use crate::rdp::windows;
use x509_parser::prelude::{X509Certificate, FromDer};

#[no_mangle]
pub extern "C" fn rs_rdp_to_json(tx: &mut RdpTransaction, js: &mut JsonBuilder) -> bool {
    log(tx, js).is_ok()
}

/// populate a json object with transactional information, for logging
fn log(tx: &RdpTransaction, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.open_object("rdp")?;
    js.set_uint("tx_id", tx.id)?;

    match &tx.item {
        RdpTransactionItem::X224ConnectionRequest(ref x224) => x224_req_to_json(x224, js)?,
        RdpTransactionItem::X224ConnectionConfirm(ref x224) => x224_conf_to_json(x224, js)?,

        RdpTransactionItem::McsConnectRequest(ref mcs) => {
            mcs_req_to_json(mcs, js)?;
        }

        RdpTransactionItem::McsConnectResponse(_) => {
            // no additional JSON data beyond `event_type`
            js.set_string("event_type", "connect_response")?;
        }

        RdpTransactionItem::TlsCertificateChain(chain) => {
            js.set_string("event_type", "tls_handshake")?;
            js.open_array("x509_serials")?;
            for blob in chain {
                if let Ok((_, cert)) = X509Certificate::from_der(&blob.data) {
                    js.append_string(&cert.tbs_certificate.serial.to_str_radix(16))?;
                }
            }
            js.close()?;
        }
    }

    js.close()?;
    Ok(())
}

/// json helper for X224ConnectionRequest
fn x224_req_to_json(x224: &X224ConnectionRequest, js: &mut JsonBuilder) -> Result<(), JsonError> {
    use crate::rdp::parser::NegotiationRequestFlags as Flags;

    js.set_string("event_type", "initial_request")?;
    if let Some(ref cookie) = x224.cookie {
        js.set_string("cookie", &cookie.mstshash)?;
    }
    if let Some(ref req) = x224.negotiation_request {
        if !req.flags.is_empty() {
            js.open_array("flags")?;
            if req.flags.contains(Flags::RESTRICTED_ADMIN_MODE_REQUIRED) {
                js.append_string("restricted_admin_mode_required")?;
            }
            if req
                .flags
                .contains(Flags::REDIRECTED_AUTHENTICATION_MODE_REQUIRED)
            {
                js.append_string("redirected_authentication_mode_required")?;
            }
            if req.flags.contains(Flags::CORRELATION_INFO_PRESENT) {
                js.append_string("correlation_info_present")?;
            }
            js.close()?;
        }
    }

    Ok(())
}

/// json helper for X224ConnectionConfirm
fn x224_conf_to_json(x224: &X224ConnectionConfirm, js: &mut JsonBuilder) -> Result<(), JsonError> {
    use crate::rdp::parser::NegotiationResponseFlags as Flags;

    js.set_string("event_type", "initial_response")?;
    if let Some(ref from_server) = x224.negotiation_from_server {
        match &from_server {
            NegotiationFromServer::Response(ref resp) => {
                if !resp.flags.is_empty() {
                    js.open_array("server_supports")?;
                    if resp.flags.contains(Flags::EXTENDED_CLIENT_DATA_SUPPORTED) {
                        js.append_string("extended_client_data")?;
                    }
                    if resp.flags.contains(Flags::DYNVC_GFX_PROTOCOL_SUPPORTED) {
                        js.append_string("dynvc_gfx")?;
                    }

                    // NEGRSP_FLAG_RESERVED not logged

                    if resp.flags.contains(Flags::RESTRICTED_ADMIN_MODE_SUPPORTED) {
                        js.append_string("restricted_admin")?;
                    }
                    if resp
                        .flags
                        .contains(Flags::REDIRECTED_AUTHENTICATION_MODE_SUPPORTED)
                    {
                        js.append_string("redirected_authentication")?;
                    }
                    js.close()?;
                }

                let protocol = match resp.protocol {
                    Protocol::ProtocolRdp => "rdp",
                    Protocol::ProtocolSsl => "ssl",
                    Protocol::ProtocolHybrid => "hybrid",
                    Protocol::ProtocolRdsTls => "rds_tls",
                    Protocol::ProtocolHybridEx => "hybrid_ex",
                };
                js.set_string("protocol", protocol)?;
            }

            NegotiationFromServer::Failure(ref fail) => match fail.code {
                NegotiationFailureCode::SslRequiredByServer => {
                    js.set_uint(
                        "error_code",
                        NegotiationFailureCode::SslRequiredByServer as u64,
                    )?;
                    js.set_string("reason", "ssl required by server")?;
                }
                NegotiationFailureCode::SslNotAllowedByServer => {
                    js.set_uint(
                        "error_code",
                        NegotiationFailureCode::SslNotAllowedByServer as u64,
                    )?;
                    js.set_string("reason", "ssl not allowed by server")?;
                }
                NegotiationFailureCode::SslCertNotOnServer => {
                    js.set_uint(
                        "error_code",
                        NegotiationFailureCode::SslCertNotOnServer as u64,
                    )?;
                    js.set_string("reason", "ssl cert not on server")?;
                }
                NegotiationFailureCode::InconsistentFlags => {
                    js.set_uint(
                        "error_code",
                        NegotiationFailureCode::InconsistentFlags as u64,
                    )?;
                    js.set_string("reason", "inconsistent flags")?;
                }
                NegotiationFailureCode::HybridRequiredByServer => {
                    js.set_uint(
                        "error_code",
                        NegotiationFailureCode::HybridRequiredByServer as u64,
                    )?;
                    js.set_string("reason", "hybrid required by server")?;
                }
                NegotiationFailureCode::SslWithUserAuthRequiredByServer => {
                    js.set_uint(
                        "error_code",
                        NegotiationFailureCode::SslWithUserAuthRequiredByServer as u64,
                    )?;
                    js.set_string("reason", "ssl with user auth required by server")?;
                }
            },
        }
    }

    Ok(())
}

/// json helper for McsConnectRequest
fn mcs_req_to_json(mcs: &McsConnectRequest, js: &mut JsonBuilder) -> Result<(), JsonError> {
    // placeholder string value.  We do not simply omit "unknown" values so that they can
    // help indicate that a given enum may be out of date (new Windows version, etc.)
    let unknown = String::from("unknown");

    js.set_string("event_type", "connect_request")?;
    for child in &mcs.children {
        match child {
            McsConnectRequestChild::CsClientCore(ref client) => {
                js.open_object("client")?;

                match client.version {
                    Some(ref ver) => {
                        js.set_string("version", &version_to_string(ver, "v"))?;
                    }
                    None => {
                        js.set_string("version", &unknown)?;
                    }
                }

                js.set_uint("desktop_width", client.desktop_width as u64)?;
                js.set_uint("desktop_height", client.desktop_height as u64)?;

                if let Some(depth) = get_color_depth(client) {
                    js.set_uint("color_depth", depth)?;
                }

                // sas_sequence not logged

                js.set_string(
                    "keyboard_layout",
                    &windows::lcid_to_string(client.keyboard_layout, &unknown),
                )?;

                js.set_string(
                    "build",
                    &windows::os_to_string(&client.client_build, &unknown),
                )?;

                if !client.client_name.is_empty() {
                    js.set_string("client_name", &client.client_name)?;
                }

                if let Some(ref kb) = client.keyboard_type {
                    js.set_string("keyboard_type", &keyboard_to_string(kb))?;
                }

                if client.keyboard_subtype != 0 {
                    js.set_uint("keyboard_subtype", client.keyboard_subtype as u64)?;
                }

                if client.keyboard_function_key != 0 {
                    js.set_uint("function_keys", client.keyboard_function_key as u64)?;
                }

                if !client.ime_file_name.is_empty() {
                    js.set_string("ime", &client.ime_file_name)?;
                }

                //
                // optional fields
                //

                if let Some(id) = client.client_product_id {
                    js.set_uint("product_id", id as u64)?;
                }

                if let Some(serial) = client.serial_number {
                    if serial != 0 {
                        js.set_uint("serial_number", serial as u64)?;
                    }
                }

                // supported_color_depth not logged

                if let Some(ref early_capability_flags) = client.early_capability_flags {
                    use crate::rdp::parser::EarlyCapabilityFlags as Flags;

                    if !early_capability_flags.is_empty() {
                        js.open_array("capabilities")?;
                        if early_capability_flags.contains(Flags::RNS_UD_CS_SUPPORT_ERRINFO_PDF) {
                            js.append_string("support_errinfo_pdf")?;
                        }
                        if early_capability_flags.contains(Flags::RNS_UD_CS_WANT_32BPP_SESSION) {
                            js.append_string("want_32bpp_session")?;
                        }
                        if early_capability_flags.contains(Flags::RNS_UD_CS_SUPPORT_STATUSINFO_PDU)
                        {
                            js.append_string("support_statusinfo_pdu")?;
                        }
                        if early_capability_flags.contains(Flags::RNS_UD_CS_STRONG_ASYMMETRIC_KEYS)
                        {
                            js.append_string("strong_asymmetric_keys")?;
                        }

                        // RNS_UD_CS_UNUSED not logged

                        if early_capability_flags.contains(Flags::RNS_UD_CS_VALID_CONNECTION_TYPE) {
                            js.append_string("valid_connection_type")?;
                        }
                        if early_capability_flags
                            .contains(Flags::RNS_UD_CS_SUPPORT_MONITOR_LAYOUT_PDU)
                        {
                            js.append_string("support_monitor_layout_pdu")?;
                        }
                        if early_capability_flags
                            .contains(Flags::RNS_UD_CS_SUPPORT_NETCHAR_AUTODETECT)
                        {
                            js.append_string("support_netchar_autodetect")?;
                        }
                        if early_capability_flags
                            .contains(Flags::RNS_UD_CS_SUPPORT_DYNVC_GFX_PROTOCOL)
                        {
                            js.append_string("support_dynvc_gfx_protocol")?;
                        }
                        if early_capability_flags
                            .contains(Flags::RNS_UD_CS_SUPPORT_DYNAMIC_TIME_ZONE)
                        {
                            js.append_string("support_dynamic_time_zone")?;
                        }
                        if early_capability_flags.contains(Flags::RNS_UD_CS_SUPPORT_HEARTBEAT_PDU) {
                            js.append_string("support_heartbeat_pdu")?;
                        }
                        js.close()?;
                    }
                }

                if let Some(ref id) = client.client_dig_product_id {
                    if !id.is_empty() {
                        js.set_string("id", id)?;
                    }
                }

                if let Some(ref hint) = client.connection_hint {
                    let s = match hint {
                        ConnectionHint::ConnectionHintModem => "modem",
                        ConnectionHint::ConnectionHintBroadbandLow => "low_broadband",
                        ConnectionHint::ConnectionHintSatellite => "satellite",
                        ConnectionHint::ConnectionHintBroadbandHigh => "high_broadband",
                        ConnectionHint::ConnectionHintWan => "wan",
                        ConnectionHint::ConnectionHintLan => "lan",
                        ConnectionHint::ConnectionHintAutoDetect => "autodetect",
                        ConnectionHint::ConnectionHintNotProvided => "",
                    };
                    if *hint != ConnectionHint::ConnectionHintNotProvided {
                        js.set_string("connection_hint", s)?;
                    }
                }

                // server_selected_procotol not logged

                if let Some(width) = client.desktop_physical_width {
                    js.set_uint("physical_width", width as u64)?;
                }

                if let Some(height) = client.desktop_physical_height {
                    js.set_uint("physical_height", height as u64)?;
                }

                if let Some(orientation) = client.desktop_orientation {
                    js.set_uint("desktop_orientation", orientation as u64)?;
                }

                if let Some(scale) = client.desktop_scale_factor {
                    js.set_uint("scale_factor", scale as u64)?;
                }

                if let Some(scale) = client.device_scale_factor {
                    js.set_uint("device_scale_factor", scale as u64)?;
                }
                js.close()?;
            }

            McsConnectRequestChild::CsNet(ref net) => {
                if !net.channels.is_empty() {
                    js.open_array("channels")?;
                    for channel in &net.channels {
                        js.append_string(channel)?;
                    }
                    js.close()?;
                }
            }

            McsConnectRequestChild::CsUnknown(_) => {}
        }
    }

    Ok(())
}

/// converts RdpClientVersion to a string, using the provided prefix
fn version_to_string(ver: &RdpClientVersion, prefix: &str) -> String {
    let mut result = String::from(prefix);
    match ver {
        RdpClientVersion::V4 => result.push('4'),
        RdpClientVersion::V5_V8_1 => result.push('5'),
        RdpClientVersion::V10_0 => result.push_str("10.0"),
        RdpClientVersion::V10_1 => result.push_str("10.1"),
        RdpClientVersion::V10_2 => result.push_str("10.2"),
        RdpClientVersion::V10_3 => result.push_str("10.3"),
        RdpClientVersion::V10_4 => result.push_str("10.4"),
        RdpClientVersion::V10_5 => result.push_str("10.5"),
        RdpClientVersion::V10_6 => result.push_str("10.6"),
        RdpClientVersion::V10_7 => result.push_str("10.7"),
    };
    result
}

/// checks multiple client info fields to determine color depth
fn get_color_depth(client: &CsClientCoreData) -> Option<u64> {
    // first check high_color_depth
    match client.high_color_depth {
        Some(HighColorDepth::HighColor4Bpp) => return Some(4),
        Some(HighColorDepth::HighColor8Bpp) => return Some(8),
        Some(HighColorDepth::HighColor15Bpp) => return Some(15),
        Some(HighColorDepth::HighColor16Bpp) => return Some(16),
        Some(HighColorDepth::HighColor24Bpp) => return Some(24),
        _ => (),
    };

    // if not present, try post_beta2_color_depth
    match client.post_beta2_color_depth {
        Some(PostBeta2ColorDepth::RnsUdColor4Bpp) => return Some(4),
        Some(PostBeta2ColorDepth::RnsUdColor8Bpp) => return Some(8),
        Some(PostBeta2ColorDepth::RnsUdColor16Bpp555) => return Some(15),
        Some(PostBeta2ColorDepth::RnsUdColor16Bpp565) => return Some(16),
        Some(PostBeta2ColorDepth::RnsUdColor24Bpp) => return Some(24),
        _ => (),
    };

    // if not present, try color_depth
    match client.color_depth {
        Some(ColorDepth::RnsUdColor4Bpp) => return Some(4),
        Some(ColorDepth::RnsUdColor8Bpp) => return Some(8),
        _ => return None,
    }
}

fn keyboard_to_string(kb: &KeyboardType) -> String {
    let s = match kb {
        KeyboardType::KbXt => "xt",
        KeyboardType::KbIco => "ico",
        KeyboardType::KbAt => "at",
        KeyboardType::KbEnhanced => "enhanced",
        KeyboardType::Kb1050 => "1050",
        KeyboardType::Kb9140 => "9140",
        KeyboardType::KbJapanese => "jp",
    };
    String::from(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    // for now, testing of JsonBuilder output is done by suricata-verify

    #[test]
    fn test_version_string() {
        assert_eq!("v10.7", version_to_string(&RdpClientVersion::V10_7, "v"));
    }

    #[test]
    fn test_color_depth_high() {
        let core_data = CsClientCoreData {
            version: None,
            desktop_width: 1280,
            desktop_height: 768,
            color_depth: Some(ColorDepth::RnsUdColor4Bpp),
            sas_sequence: None,
            keyboard_layout: 0x409,
            client_build: windows::OperatingSystem {
                build: windows::Build::Win10_17763,
                suffix: windows::Suffix::Rs5,
            },
            client_name: String::from("SERVER-XYZ"),
            keyboard_type: None,
            keyboard_subtype: 0,
            keyboard_function_key: 12,
            ime_file_name: String::from(""),
            post_beta2_color_depth: Some(PostBeta2ColorDepth::RnsUdColor8Bpp),
            client_product_id: None,
            serial_number: None,
            high_color_depth: Some(HighColorDepth::HighColor24Bpp),
            supported_color_depth: None,
            early_capability_flags: None,
            client_dig_product_id: None,
            connection_hint: None,
            server_selected_protocol: None,
            desktop_physical_width: None,
            desktop_physical_height: None,
            desktop_orientation: None,
            desktop_scale_factor: None,
            device_scale_factor: None,
        };
        assert_eq!(Some(24), get_color_depth(&core_data));
    }

    #[test]
    fn test_color_depth_post_beta2() {
        let core_data = CsClientCoreData {
            version: None,
            desktop_width: 1280,
            desktop_height: 768,
            color_depth: Some(ColorDepth::RnsUdColor4Bpp),
            sas_sequence: None,
            keyboard_layout: 0x409,
            client_build: windows::OperatingSystem {
                build: windows::Build::Win10_17763,
                suffix: windows::Suffix::Rs5,
            },
            client_name: String::from("SERVER-XYZ"),
            keyboard_type: None,
            keyboard_subtype: 0,
            keyboard_function_key: 12,
            ime_file_name: String::from(""),
            post_beta2_color_depth: Some(PostBeta2ColorDepth::RnsUdColor8Bpp),
            client_product_id: None,
            serial_number: None,
            high_color_depth: None,
            supported_color_depth: None,
            early_capability_flags: None,
            client_dig_product_id: None,
            connection_hint: None,
            server_selected_protocol: None,
            desktop_physical_width: None,
            desktop_physical_height: None,
            desktop_orientation: None,
            desktop_scale_factor: None,
            device_scale_factor: None,
        };
        assert_eq!(Some(8), get_color_depth(&core_data));
    }

    #[test]
    fn test_color_depth_basic() {
        let core_data = CsClientCoreData {
            version: None,
            desktop_width: 1280,
            desktop_height: 768,
            color_depth: Some(ColorDepth::RnsUdColor4Bpp),
            sas_sequence: None,
            keyboard_layout: 0x409,
            client_build: windows::OperatingSystem {
                build: windows::Build::Win10_17763,
                suffix: windows::Suffix::Rs5,
            },
            client_name: String::from("SERVER-XYZ"),
            keyboard_type: None,
            keyboard_subtype: 0,
            keyboard_function_key: 12,
            ime_file_name: String::from(""),
            post_beta2_color_depth: None,
            client_product_id: None,
            serial_number: None,
            high_color_depth: None,
            supported_color_depth: None,
            early_capability_flags: None,
            client_dig_product_id: None,
            connection_hint: None,
            server_selected_protocol: None,
            desktop_physical_width: None,
            desktop_physical_height: None,
            desktop_orientation: None,
            desktop_scale_factor: None,
            device_scale_factor: None,
        };
        assert_eq!(Some(4), get_color_depth(&core_data));
    }

    #[test]
    fn test_color_depth_missing() {
        let core_data = CsClientCoreData {
            version: None,
            desktop_width: 1280,
            desktop_height: 768,
            color_depth: None,
            sas_sequence: None,
            keyboard_layout: 0x409,
            client_build: windows::OperatingSystem {
                build: windows::Build::Win10_17763,
                suffix: windows::Suffix::Rs5,
            },
            client_name: String::from("SERVER-XYZ"),
            keyboard_type: None,
            keyboard_subtype: 0,
            keyboard_function_key: 12,
            ime_file_name: String::from(""),
            post_beta2_color_depth: None,
            client_product_id: None,
            serial_number: None,
            high_color_depth: None,
            supported_color_depth: None,
            early_capability_flags: None,
            client_dig_product_id: None,
            connection_hint: None,
            server_selected_protocol: None,
            desktop_physical_width: None,
            desktop_physical_height: None,
            desktop_orientation: None,
            desktop_scale_factor: None,
            device_scale_factor: None,
        };
        assert!(get_color_depth(&core_data).is_none());
    }

    #[test]
    fn test_keyboard_string() {
        assert_eq!("enhanced", keyboard_to_string(&KeyboardType::KbEnhanced));
    }
}
