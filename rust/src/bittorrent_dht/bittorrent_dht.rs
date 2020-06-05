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

use crate::applayer::{self, *};
use crate::bittorrent_dht::parser::{
    parse_bittorrent_dht_packet, BitTorrentDHTError, BitTorrentDHTRequest, BitTorrentDHTResponse,
};
use crate::core::{self, AppProto, Flow, ALPROTO_UNKNOWN, IPPROTO_UDP};
use std::ffi::CString;
use std::str::FromStr;

const BITTORRENT_DHT_PAYLOAD_PREFIX: &[u8] = b"d1:ad2:id20:";
const BITTORRENT_DHT_PAYLOAD_PREFIX_LEN: u32 = 12;

static mut ALPROTO_BITTORRENT_DHT: AppProto = ALPROTO_UNKNOWN;

#[repr(u32)]
#[derive(AppLayerEvent)]
pub enum BitTorrentDHTEvent {
    MalformedPacket = 0,
}

impl BitTorrentDHTEvent {
    pub fn to_cstring(&self) -> &str {
        match *self {
            BitTorrentDHTEvent::MalformedPacket => "malformed_packet\0",
        }
    }

    pub fn from_id(id: u32) -> Option<BitTorrentDHTEvent> {
        match id {
            0 => Some(BitTorrentDHTEvent::MalformedPacket),
            _ => None,
        }
    }
}

impl FromStr for BitTorrentDHTEvent {
    type Err = ();

    fn from_str(s: &str) -> Result<BitTorrentDHTEvent, Self::Err> {
        match s.to_lowercase().as_ref() {
            "malformed_packet" => Ok(BitTorrentDHTEvent::MalformedPacket),
            _ => Err(()),
        }
    }
}

pub struct BitTorrentDHTTransaction {
    tx_id: u64,
    pub request_type: Option<String>,
    pub request: Option<BitTorrentDHTRequest>,
    pub response: Option<BitTorrentDHTResponse>,
    pub error: Option<BitTorrentDHTError>,
    pub transaction_id: String,
    pub client_version: Option<String>,

    de_state: Option<*mut core::DetectEngineState>,
    events: *mut core::AppLayerDecoderEvents,
    tx_data: AppLayerTxData,
}

impl BitTorrentDHTTransaction {
    pub fn new() -> BitTorrentDHTTransaction {
        BitTorrentDHTTransaction {
            tx_id: 0,
            request_type: None,
            request: None,
            response: None,
            error: None,
            transaction_id: String::new(),
            client_version: None,
            de_state: None,
            events: std::ptr::null_mut(),
            tx_data: AppLayerTxData::new(),
        }
    }

    pub fn free(&mut self) {
        if self.events != std::ptr::null_mut() {
            core::sc_app_layer_decoder_events_free_events(&mut self.events);
        }
        if let Some(state) = self.de_state {
            core::sc_detect_engine_state_free(state);
        }
    }

    /// Set an event on the transaction
    pub fn set_event(&mut self, event: BitTorrentDHTEvent) {
        core::sc_app_layer_decoder_events_set_event_raw(&mut self.events, event as u8);
    }
}

impl Drop for BitTorrentDHTTransaction {
    fn drop(&mut self) {
        self.free();
    }
}

pub struct BitTorrentDHTState {
    tx_id: u64,
    transactions: Vec<BitTorrentDHTTransaction>,
}

impl BitTorrentDHTState {
    pub fn new() -> Self {
        Self {
            tx_id: 0,
            transactions: Vec::new(),
        }
    }

    // Free a transaction by ID.
    fn free_tx(&mut self, tx_id: u64) {
        self.transactions.retain(|tx| tx.tx_id != tx_id + 1);
    }

    pub fn get_tx(&mut self, tx_id: u64) -> Option<&BitTorrentDHTTransaction> {
        self.transactions.iter().find(|&tx| tx.tx_id == tx_id + 1)
    }

    fn new_tx(&mut self) -> BitTorrentDHTTransaction {
        let mut tx = BitTorrentDHTTransaction::new();
        self.tx_id += 1;
        tx.tx_id = self.tx_id;
        return tx;
    }

    pub fn parse(&mut self, input: &[u8]) -> bool {
        let mut tx = self.new_tx();
        let mut status = true;

        if let Err(_e) = parse_bittorrent_dht_packet(input, &mut tx) {
            status = false;
            tx.set_event(BitTorrentDHTEvent::MalformedPacket);
            SCLogDebug!("BitTorrent DHT Parsing Error: {}", _e);
        }

        self.transactions.push(tx);

        return status;
    }

    fn tx_iterator(
        &mut self, min_tx_id: u64, state: &mut u64,
    ) -> Option<(&BitTorrentDHTTransaction, u64, bool)> {
        let mut index = *state as usize;
        let len = self.transactions.len();

        while index < len {
            let tx = &self.transactions[index];
            if tx.tx_id < min_tx_id + 1 {
                index += 1;
                continue;
            }
            *state = index as u64;
            return Some((tx, tx.tx_id - 1, (len - index) > 1));
        }

        return None;
    }
}

/// Probe to see if this flow looks like BitTorrent DHT
fn probe(input: &[u8]) -> bool {
    // Ensure the flow started with a request from the client which
    // contained the BitTorrent DHT request payload prefix bytes
    if input.starts_with(BITTORRENT_DHT_PAYLOAD_PREFIX) {
        return true;
    }
    return false;
}

// C exports.

export_tx_data_get!(rs_bittorrent_dht_get_tx_data, BitTorrentDHTTransaction);

/// C entry point for BitTorrent DHT probing parser.
#[no_mangle]
pub unsafe extern "C" fn rs_bittorrent_dht_probing_parser(
    _flow: *const Flow, _direction: u8, input: *const u8, input_len: u32, _rdir: *mut u8,
) -> AppProto {
    // Need more than BITTORRENT_DHT_PAYLOAD_PREFIX_LEN bytes.
    if input_len > BITTORRENT_DHT_PAYLOAD_PREFIX_LEN && input != std::ptr::null_mut() {
        let slice = build_slice!(input, input_len as usize);
        if probe(slice) {
            return ALPROTO_BITTORRENT_DHT;
        }
    }
    return ALPROTO_UNKNOWN;
}

#[no_mangle]
pub extern "C" fn rs_bittorrent_dht_state_new(
    _orig_state: *mut std::os::raw::c_void, _orig_proto: AppProto,
) -> *mut std::os::raw::c_void {
    let state = BitTorrentDHTState::new();
    let boxed = Box::new(state);
    return Box::into_raw(boxed) as *mut std::os::raw::c_void;
}

#[no_mangle]
pub unsafe extern "C" fn rs_bittorrent_dht_state_free(state: *mut std::os::raw::c_void) {
    std::mem::drop(Box::from_raw(state as *mut BitTorrentDHTState));
}

#[no_mangle]
pub unsafe extern "C" fn rs_bittorrent_dht_state_tx_free(
    state: *mut std::os::raw::c_void, tx_id: u64,
) {
    let state = cast_pointer!(state, BitTorrentDHTState);
    state.free_tx(tx_id);
}

#[no_mangle]
pub unsafe extern "C" fn rs_bittorrent_dht_parse(
    _flow: *const Flow, state: *mut std::os::raw::c_void, _pstate: *mut std::os::raw::c_void,
    stream_slice: StreamSlice, _data: *const std::os::raw::c_void,
) -> AppLayerResult {
    let state = cast_pointer!(state, BitTorrentDHTState);
    let buf = stream_slice.as_slice();
    state.parse(buf).into()
}

#[no_mangle]
pub unsafe extern "C" fn rs_bittorrent_dht_state_get_tx(
    state: *mut std::os::raw::c_void, tx_id: u64,
) -> *mut std::os::raw::c_void {
    let state = cast_pointer!(state, BitTorrentDHTState);
    match state.get_tx(tx_id) {
        Some(tx) => {
            return tx as *const _ as *mut _;
        }
        None => {
            return std::ptr::null_mut();
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_bittorrent_dht_state_get_tx_count(
    state: *mut std::os::raw::c_void,
) -> u64 {
    let state = cast_pointer!(state, BitTorrentDHTState);
    return state.tx_id;
}

#[no_mangle]
pub unsafe extern "C" fn rs_bittorrent_dht_tx_get_alstate_progress(
    tx: *mut std::os::raw::c_void, _direction: u8,
) -> std::os::raw::c_int {
    let tx = cast_pointer!(tx, BitTorrentDHTTransaction);

    // Transaction is done if we have a request, response, or error since
    // a new transaction is created for each received packet
    if tx.request.is_some() || tx.response.is_some() || tx.error.is_some() {
        return 1;
    }
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn rs_bittorrent_dht_state_get_events(
    tx: *mut std::os::raw::c_void,
) -> *mut core::AppLayerDecoderEvents {
    let tx = cast_pointer!(tx, BitTorrentDHTTransaction);
    return tx.events;
}

#[no_mangle]
pub unsafe extern "C" fn rs_bittorrent_dht_state_get_tx_iterator(
    _ipproto: u8, _alproto: AppProto, state: *mut std::os::raw::c_void, min_tx_id: u64,
    _max_tx_id: u64, istate: &mut u64,
) -> applayer::AppLayerGetTxIterTuple {
    let state = cast_pointer!(state, BitTorrentDHTState);
    match state.tx_iterator(min_tx_id, istate) {
        Some((tx, out_tx_id, has_next)) => {
            let c_tx = tx as *const _ as *mut _;
            let ires = applayer::AppLayerGetTxIterTuple::with_values(c_tx, out_tx_id, has_next);
            return ires;
        }
        None => {
            return applayer::AppLayerGetTxIterTuple::not_found();
        }
    }
}

// Parser name as a C style string.
const PARSER_NAME: &[u8] = b"bittorrent-dht\0";

#[no_mangle]
pub unsafe extern "C" fn rs_bittorrent_dht_udp_register_parser() {
    let default_port = CString::new("[1024:65535]").unwrap();
    let parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const std::os::raw::c_char,
        default_port: default_port.as_ptr(),
        ipproto: IPPROTO_UDP,
        probe_ts: Some(rs_bittorrent_dht_probing_parser),
        probe_tc: Some(rs_bittorrent_dht_probing_parser),
        min_depth: 0,
        max_depth: 16,
        state_new: rs_bittorrent_dht_state_new,
        state_free: rs_bittorrent_dht_state_free,
        tx_free: rs_bittorrent_dht_state_tx_free,
        parse_ts: rs_bittorrent_dht_parse,
        parse_tc: rs_bittorrent_dht_parse,
        get_tx_count: rs_bittorrent_dht_state_get_tx_count,
        get_tx: rs_bittorrent_dht_state_get_tx,
        tx_comp_st_ts: 1,
        tx_comp_st_tc: 1,
        tx_get_progress: rs_bittorrent_dht_tx_get_alstate_progress,
        get_eventinfo: Some(BitTorrentDHTEvent::get_event_info),
        get_eventinfo_byid: Some(BitTorrentDHTEvent::get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_files: None,
        get_tx_iterator: Some(rs_bittorrent_dht_state_get_tx_iterator),
        get_tx_data: rs_bittorrent_dht_get_tx_data,
        apply_tx_config: None,
        flags: 0,
        truncate: None,
        get_frame_id_by_name: None,
        get_frame_name_by_id: None,
    };

    let ip_proto_str = CString::new("udp").unwrap();

    if AppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_BITTORRENT_DHT = alproto;
        if AppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
        SCLogDebug!("Parser registered for bittorrent-dht.");
    } else {
        SCLogDebug!("Protocol detector and parser disabled for bittorrent-dht.");
    }
}
