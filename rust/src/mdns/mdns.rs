/* Copyright (C) 2025 Open Information Security Foundation
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
use std::ffi::CString;
use std::os::raw::c_void;

use crate::applayer::*;
use crate::core::*;
use crate::direction::Direction;
use crate::dns::dns;
use crate::flow::Flow;

use suricata_sys::sys::DetectEngineThreadCtx;
use suricata_sys::sys::{
    AppProto, AppProtoEnum, SCAppLayerParserConfParserEnabled,
    SCAppLayerProtoDetectConfProtoDetectionEnabled,
};

pub(super) static mut ALPROTO_MDNS: AppProto = ALPROTO_UNKNOWN;

unsafe extern "C" fn probe(
    _flow: *const Flow, _dir: u8, input: *const u8, len: u32, _rdir: *mut u8,
) -> AppProto {
    if crate::dns::dns::probe_udp(_flow, _dir, input, len, _rdir)
        == AppProtoEnum::ALPROTO_DNS as u16
    {
        let dir = Direction::ToServer;
        *_rdir = dir as u8;
        return ALPROTO_MDNS;
    }
    return 0;
}

/// Returns *mut DNSState
pub(crate) extern "C" fn state_new(
    _orig_state: *mut std::os::raw::c_void, _orig_proto: AppProto,
) -> *mut std::os::raw::c_void {
    let state = dns::DNSState::new_variant(dns::DnsVariant::MulticastDns);
    let boxed = Box::new(state);
    return Box::into_raw(boxed) as *mut _;
}

/// Get the mDNS response answer name and index i.
///
/// Very similar to the DNS version, but mDNS is always to_server.
#[no_mangle]
pub unsafe extern "C" fn SCMdnsTxGetAnswerName(
    _de: *mut DetectEngineThreadCtx, tx: *const c_void, _flow_flags: u8, i: u32,
    buf: *mut *const u8, len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, dns::DNSTransaction);
    let answers = if tx.request.is_some() {
        tx.request.as_ref().map(|request| &request.answers)
    } else {
        tx.response.as_ref().map(|response| &response.answers)
    };
    let index = i as usize;

    if let Some(answers) = answers {
        if let Some(answer) = answers.get(index) {
            if !answer.name.value.is_empty() {
                *buf = answer.name.value.as_ptr();
                *len = answer.name.value.len() as u32;
                return true;
            }
        }
    }

    false
}

#[no_mangle]
pub unsafe extern "C" fn SCRegisterMdnsParser() {
    let default_port = std::ffi::CString::new("[5353]").unwrap();
    let parser = RustParser {
        name: b"mdns\0".as_ptr() as *const std::os::raw::c_char,
        default_port: default_port.as_ptr(),
        ipproto: IPPROTO_UDP,
        probe_ts: Some(probe),
        probe_tc: Some(probe),
        min_depth: 0,
        max_depth: std::mem::size_of::<dns::DNSHeader>() as u16,
        state_new,
        state_free: dns::state_free,
        tx_free: dns::state_tx_free,
        parse_ts: dns::parse_request,
        parse_tc: dns::parse_request,
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
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_MDNS = alproto;
        if SCAppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
    }
}
