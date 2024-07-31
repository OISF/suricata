/* Copyright (C) 2026 Open Information Security Foundation
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

use std;
use std::ffi::CString;

use crate::applayer::*;
use crate::core::*;
use crate::dns::dns;
use crate::dns::dns::DNSHeader;
use crate::flow::Flow;

use suricata_sys::sys::{
    AppProto, AppProtoEnum, SCAppLayerParserConfParserEnabled,
    SCAppLayerProtoDetectConfProtoDetectionEnabled,
};

static mut ALPROTO_LLMNR: AppProto = ALPROTO_UNKNOWN;

unsafe extern "C" fn probe_udp(
    _flow: *const Flow, _dir: u8, input: *const u8, len: u32, _rdir: *mut u8,
) -> AppProto {
    if crate::dns::dns::probe_udp(_flow, _dir, input, len, _rdir)
        == AppProtoEnum::ALPROTO_DNS as u16
    {
        return ALPROTO_LLMNR;
    }
    return 0;
}

unsafe extern "C" fn probe_tcp(
    _flow: *const Flow, _dir: u8, input: *const u8, len: u32, _rdir: *mut u8,
) -> AppProto {
    if crate::dns::dns::c_probe_tcp(_flow, _dir, input, len, _rdir)
        == AppProtoEnum::ALPROTO_DNS as u16
    {
        return ALPROTO_LLMNR;
    }
    return 0;
}

pub(crate) extern "C" fn state_new(
    _orig_state: *mut std::os::raw::c_void, _orig_proto: AppProto,
) -> *mut std::os::raw::c_void {
    let state = dns::DNSState::new_variant(dns::DnsVariant::Llmnr);
    let boxed = Box::new(state);
    return Box::into_raw(boxed) as *mut _;
}

#[no_mangle]
pub extern "C" fn SCLLMNRTxIsRequest(tx: &mut dns::DNSTransaction) -> bool {
    tx.request.is_some()
}

#[no_mangle]
pub extern "C" fn SCLLMNRTxIsResponse(tx: &mut dns::DNSTransaction) -> bool {
    tx.response.is_some()
}

#[no_mangle]
pub unsafe extern "C" fn SCRegisterLLMNRUdpParser() {
    let default_port = std::ffi::CString::new("5355").unwrap();
    let parser = RustParser {
        name: b"llmnr\0".as_ptr() as *const std::os::raw::c_char,
        default_port: default_port.as_ptr(),
        ipproto: IPPROTO_UDP,
        probe_ts: Some(probe_udp),
        probe_tc: Some(probe_udp),
        min_depth: 0,
        max_depth: std::mem::size_of::<DNSHeader>() as u16,
        state_new,
        state_free: dns::state_free,
        tx_free: dns::state_tx_free,
        parse_ts: dns::parse_request,
        parse_tc: dns::parse_response,
        get_tx_count: dns::state_get_tx_count,
        get_tx: dns::state_get_tx,
        tx_comp_st_ts: 1,
        tx_comp_st_tc: 1,
        tx_get_progress: dns::tx_get_alstate_progress,
        get_eventinfo: Some(dns::DNSEvent::get_event_info),
        get_eventinfo_byid: Some(dns::DNSEvent::get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_tx_files: None,
        get_tx_iterator: Some(
            crate::applayer::state_get_tx_iterator::<dns::DNSState, dns::DNSTransaction>,
        ),
        get_tx_data: dns::state_get_tx_data,
        get_state_data: dns::dns_get_state_data,
        apply_tx_config: None,
        flags: 0,
        get_frame_id_by_name: Some(dns::DnsFrameType::ffi_id_from_name),
        get_frame_name_by_id: Some(dns::DnsFrameType::ffi_name_from_id),
        get_state_id_by_name: None,
        get_state_name_by_id: None,
    };

    let ip_proto_str = CString::new("udp").unwrap();
    if SCAppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = applayer_register_protocol_detection(&parser, 1);
        ALPROTO_LLMNR = alproto;
        if SCAppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn SCRegisterLLMNRTcpParser() {
    let default_port = std::ffi::CString::new("5355").unwrap();
    let parser = RustParser {
        name: b"llmnr\0".as_ptr() as *const std::os::raw::c_char,
        default_port: default_port.as_ptr(),
        ipproto: IPPROTO_TCP,
        probe_ts: Some(probe_tcp),
        probe_tc: Some(probe_tcp),
        min_depth: 0,
        max_depth: std::mem::size_of::<DNSHeader>() as u16 + 2,
        state_new,
        state_free: dns::state_free,
        tx_free: dns::state_tx_free,
        parse_ts: dns::parse_request_tcp,
        parse_tc: dns::parse_response_tcp,
        get_tx_count: dns::state_get_tx_count,
        get_tx: dns::state_get_tx,
        tx_comp_st_ts: 1,
        tx_comp_st_tc: 1,
        tx_get_progress: dns::tx_get_alstate_progress,
        get_eventinfo: Some(dns::DNSEvent::get_event_info),
        get_eventinfo_byid: Some(dns::DNSEvent::get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_tx_files: None,
        get_tx_iterator: Some(
            crate::applayer::state_get_tx_iterator::<dns::DNSState, dns::DNSTransaction>,
        ),
        get_tx_data: dns::state_get_tx_data,
        get_state_data: dns::dns_get_state_data,
        apply_tx_config: None,
        flags: APP_LAYER_PARSER_OPT_ACCEPT_GAPS,
        get_frame_id_by_name: Some(dns::DnsFrameType::ffi_id_from_name),
        get_frame_name_by_id: Some(dns::DnsFrameType::ffi_name_from_id),
        get_state_id_by_name: None,
        get_state_name_by_id: None,
    };

    let ip_proto_str = CString::new("tcp").unwrap();
    if SCAppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = applayer_register_protocol_detection(&parser, 1);
        ALPROTO_LLMNR = alproto;
        if SCAppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
    }
}
