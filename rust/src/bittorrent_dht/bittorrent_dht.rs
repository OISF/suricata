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

use crate::applayer::{self, *};
use crate::bittorrent_dht::parser::{
    parse_bittorrent_dht_packet, BitTorrentDHTError, BitTorrentDHTRequest, BitTorrentDHTResponse,
};
use crate::core::{AppProto, Flow, ALPROTO_UNKNOWN, IPPROTO_UDP};
use std::ffi::CString;
use std::os::raw::c_char;

const BITTORRENT_DHT_PAYLOAD_PREFIX: &[u8] = b"d1:ad2:id20:\0";

static mut ALPROTO_BITTORRENT_DHT: AppProto = ALPROTO_UNKNOWN;

#[derive(AppLayerEvent, Debug, PartialEq)]
pub enum BitTorrentDHTEvent {
    MalformedPacket,
}

pub struct BitTorrentDHTTransaction {
    tx_id: u64,
    pub request_type: Option<String>,
    pub request: Option<BitTorrentDHTRequest>,
    pub response: Option<BitTorrentDHTResponse>,
    pub error: Option<BitTorrentDHTError>,
    pub transaction_id: Vec<u8>,
    pub client_version: Option<Vec<u8>>,

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
            transaction_id: Vec::new(),
            client_version: None,
            tx_data: AppLayerTxData::new(),
        }
    }

    /// Set an event on the transaction
    pub fn set_event(&mut self, event: BitTorrentDHTEvent) {
        self.tx_data.set_event(event as u8);
    }
}

#[derive(Default)]
pub struct BitTorrentDHTState {
    tx_id: u64,
    transactions: Vec<BitTorrentDHTTransaction>,
    state_data: AppLayerStateData,
}

impl BitTorrentDHTState {
    pub fn new() -> Self {
        Self::default()
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

    fn is_dht(input: &[u8]) -> bool {
        if input.len() > 5 {
            match &input[0..5] {
                b"d1:ad" | b"d1:rd" | b"d2:ip" | b"d1:el" => true,
                _ => false,
            }
        } else {
            false
        }
    }

    pub fn parse(&mut self, input: &[u8]) -> bool {
        if !Self::is_dht(input) {
            return true;
        }
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

// C exports.

export_tx_data_get!(rs_bittorrent_dht_get_tx_data, BitTorrentDHTTransaction);
export_state_data_get!(rs_bittorrent_dht_get_state_data, BitTorrentDHTState);

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
    let parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const std::os::raw::c_char,
        default_port: std::ptr::null(),
        ipproto: IPPROTO_UDP,
        probe_ts: None,
        probe_tc: None,
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
        get_tx_files: None,
        get_tx_iterator: Some(rs_bittorrent_dht_state_get_tx_iterator),
        get_tx_data: rs_bittorrent_dht_get_tx_data,
        get_state_data: rs_bittorrent_dht_get_state_data,
        apply_tx_config: None,
        flags: APP_LAYER_PARSER_OPT_UNIDIR_TXS,
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

        if AppLayerProtoDetectPMRegisterPatternCS(
            IPPROTO_UDP as u8,
            ALPROTO_BITTORRENT_DHT,
            BITTORRENT_DHT_PAYLOAD_PREFIX.as_ptr() as *const c_char,
            BITTORRENT_DHT_PAYLOAD_PREFIX.len() as u16 - 1,
            0,
            crate::core::Direction::ToServer.into(),
        ) < 0
        {
            SCLogDebug!("Failed to register protocol detection pattern for direction TOSERVER");
        };
        if AppLayerProtoDetectPMRegisterPatternCS(
            IPPROTO_UDP as u8,
            ALPROTO_BITTORRENT_DHT,
            BITTORRENT_DHT_PAYLOAD_PREFIX.as_ptr() as *const c_char,
            BITTORRENT_DHT_PAYLOAD_PREFIX.len() as u16 - 1,
            0,
            crate::core::Direction::ToClient.into(),
        ) < 0
        {
            SCLogDebug!("Failed to register protocol detection pattern for direction TOCLIENT");
        }

        SCLogDebug!("Parser registered for bittorrent-dht.");
    } else {
        SCLogDebug!("Protocol detector and parser disabled for bittorrent-dht.");
    }
}
