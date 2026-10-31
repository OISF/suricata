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

use super::{
    connection::QuicConnection,
    cyu::Cyu,
    frames::{Frame, QuicTlsExtension, StreamTag},
    parser::{QuicData, QuicHeader, QuicType},
};
use crate::conf::conf_get;
use crate::encryption::EncryptionHandling;
use crate::{
    applayer::{self, *},
    direction::Direction,
    flow::{flow_get_last_time, Flow},
    ja4::JA4,
};
use crate::{
    core::{ALPROTO_FAILED, ALPROTO_UNKNOWN, IPPROTO_UDP},
    ja4::JA4Impl,
};
use std::collections::VecDeque;
use std::ffi::CString;
use std::str::FromStr;
use std::time::Duration;
use suricata_sys::sys::{
    AppLayerParserState, AppProto, SCAppLayerParserConfParserEnabled,
    SCAppLayerParserRegisterLogger, SCAppLayerParserStateSetFlag,
    SCAppLayerProtoDetectConfProtoDetectionEnabled,
};
use tls_parser::TlsExtensionType;

pub(super) static mut ALPROTO_QUIC: AppProto = ALPROTO_UNKNOWN;

static mut ENCRYPTION_BYPASS_ENABLED: EncryptionHandling =
    EncryptionHandling::ENCRYPTION_HANDLING_TRACK_ONLY;

const DEFAULT_DCID_LEN: usize = 16;
static mut MAX_CONNECTIONS: usize = 64;
static mut CONNECTION_IDLE_TIMEOUT: u64 = 60;
pub(super) const QUIC_MAX_CRYPTO_FRAG_LEN: u64 = 65535;

#[derive(FromPrimitive, Debug, AppLayerEvent)]
pub enum QuicEvent {
    FailedDecrypt,
    ErrorOnData,
    ErrorOnHeader,
    CryptoFragTooLong,
    TooManyConnections,
}

#[derive(Debug)]
pub struct QuicTransaction {
    tx_id: u64,
    pub header: QuicHeader,
    pub cyu: Vec<Cyu>,
    pub sni: Option<Vec<u8>>,
    pub ua: Option<Vec<u8>>,
    pub extv: Vec<QuicTlsExtension>,
    pub ja3: Option<String>,
    pub ja4: Option<JA4>,
    pub client: bool,
    tx_data: AppLayerTxData,
}

impl QuicTransaction {
    fn new(
        header: QuicHeader, data: QuicData, sni: Option<Vec<u8>>, ua: Option<Vec<u8>>,
        extv: Vec<QuicTlsExtension>, ja3: Option<String>, ja4: Option<JA4>, client: bool,
    ) -> Self {
        let direction = if client {
            Direction::ToServer
        } else {
            Direction::ToClient
        };
        let cyu = Cyu::generate(&header, &data.frames);
        QuicTransaction {
            tx_id: 0,
            header,
            cyu,
            sni,
            ua,
            extv,
            ja3,
            ja4,
            client,
            tx_data: AppLayerTxData::for_direction(direction),
        }
    }

    fn new_empty(client: bool, header: QuicHeader) -> Self {
        let direction = if client {
            Direction::ToServer
        } else {
            Direction::ToClient
        };
        QuicTransaction {
            tx_id: 0,
            header,
            cyu: Vec::new(),
            sni: None,
            ua: None,
            extv: Vec::new(),
            ja3: None,
            ja4: None,
            client,
            tx_data: AppLayerTxData::for_direction(direction),
        }
    }
}

pub struct QuicState {
    state_data: AppLayerStateData,
    max_tx_id: u64,
    connections: Vec<QuicConnection>,
    max_connections: usize,
    idle_timeout: Duration,
    transactions: VecDeque<QuicTransaction>,
}

impl Default for QuicState {
    fn default() -> Self {
        Self {
            state_data: AppLayerStateData::default(),
            max_tx_id: 0,
            connections: Vec::new(),
            max_connections: unsafe { MAX_CONNECTIONS },
            idle_timeout: Duration::from_secs(unsafe { CONNECTION_IDLE_TIMEOUT }),
            transactions: VecDeque::new(),
        }
    }
}

impl QuicState {
    fn new() -> Self {
        Self::default()
    }

    // Free a transaction by ID.
    fn free_tx(&mut self, tx_id: u64) {
        let tx = self
            .transactions
            .iter()
            .position(|tx| tx.tx_id == tx_id + 1);
        if let Some(idx) = tx {
            let _ = self.transactions.remove(idx);
        }
    }

    fn get_tx(&mut self, tx_id: u64) -> Option<&QuicTransaction> {
        self.transactions.iter().find(|&tx| tx.tx_id == tx_id + 1)
    }

    fn new_tx(
        &mut self, header: QuicHeader, data: QuicData, sni: Option<Vec<u8>>, ua: Option<Vec<u8>>,
        extb: Vec<QuicTlsExtension>, ja3: Option<String>, ja4: Option<JA4>, client: bool,
        frag_long: bool,
    ) {
        let mut tx = QuicTransaction::new(header, data, sni, ua, extb, ja3, ja4, client);
        self.max_tx_id += 1;
        tx.tx_id = self.max_tx_id;
        if frag_long {
            tx.tx_data.set_event(QuicEvent::CryptoFragTooLong as u8);
        }
        self.transactions.push_back(tx);
    }

    fn handle_frames(&mut self, data: QuicData, header: QuicHeader, to_server: bool) {
        let mut sni: Option<Vec<u8>> = None;
        let mut ua: Option<Vec<u8>> = None;
        let mut ja3: Option<String> = None;
        let mut ja4: Option<JA4> = None;
        let mut extv: Vec<QuicTlsExtension> = Vec::new();
        for frame in &data.frames {
            match frame {
                Frame::Stream(s) => {
                    if let Some(tags) = &s.tags {
                        for (tag, value) in tags {
                            if tag == &StreamTag::Sni {
                                sni = Some(value.to_vec());
                            } else if tag == &StreamTag::Uaid {
                                ua = Some(value.to_vec());
                            }
                            if sni.is_some() && ua.is_some() {
                                break;
                            }
                        }
                    }
                }
                Frame::Crypto(c) => {
                    if let Some(ja3str) = &c.ja3 {
                        ja3 = Some(ja3str.clone());
                    }
                    // we only do client fingerprints for now
                    if to_server {
                        // our hash is complete, let's only use strings from
                        // now on
                        if let Some(ref rja4) = c.hs {
                            ja4 = JA4::try_new(rja4);
                        }
                    }
                    for e in &c.extv {
                        if e.etype == TlsExtensionType::ServerName && !e.values.is_empty() {
                            sni = Some(e.values[0].to_vec());
                        }
                    }
                    extv.extend_from_slice(&c.extv);
                }
                _ => {}
            }
        }
        self.new_tx(header, data, sni, ua, extv, ja3, ja4, to_server, false);
    }

    fn set_event_notx(&mut self, event: QuicEvent, header: QuicHeader, client: bool) {
        let mut tx = QuicTransaction::new_empty(client, header);
        self.max_tx_id += 1;
        tx.tx_id = self.max_tx_id;
        tx.tx_data.set_event(event as u8);
        self.transactions.push_back(tx);
    }

    fn parse(
        &mut self, input: &[u8], to_server: bool, pstate: *mut AppLayerParserState, now: Duration,
    ) -> bool {
        self.connections
            .retain(|c| now.saturating_sub(c.last_seen) < self.idle_timeout);
        let mut buf = input;
        while !buf.is_empty() {
            let Ok((rest, header)) = QuicHeader::from_bytes(buf, DEFAULT_DCID_LEN) else {
                // The next boundary is unknown; discard this datagram, not the flow.
                return true;
            };
            if header.ty == QuicType::Short {
                break;
            }
            let hlen = buf.len() - rest.len();
            let (payload, next) = rest.split_at(header.length as usize);
            let packet = &buf[..hlen + payload.len()];
            if header.ty == QuicType::Retry && !to_server {
                let matches: Vec<_> = self
                    .connections
                    .iter()
                    .enumerate()
                    .filter(|(_, c)| c.accepts_retry(&header, packet))
                    .map(|(i, _)| i)
                    .collect();
                if let [i] = matches.as_slice() {
                    self.connections[*i].retry(&header, now);
                }
            }
            if header.ty != QuicType::Initial {
                // Non-Initial packets cannot introduce a connection. A CID
                // learned only from encrypted 1-RTT traffic is also unknown here.
                if header.ty != QuicType::VersionNegotiation
                    && !header.version.is_gquic()
                    && !self.connections.is_empty()
                    && !self
                        .connections
                        .iter()
                        .any(|c| c.matches(&header, to_server) && !c.hello_done(to_server))
                {
                    buf = next;
                    continue;
                }
                self.new_tx(
                    header,
                    QuicData { frames: Vec::new() },
                    None,
                    None,
                    Vec::new(),
                    None,
                    None,
                    to_server,
                    false,
                );
                buf = next;
                continue;
            }

            let mut candidates: Vec<_> = self
                .connections
                .iter()
                .enumerate()
                .filter(|(_, c)| c.matches(&header, to_server))
                .map(|(i, _)| i)
                .collect();
            if let [i] = candidates.as_slice() {
                if self.connections[*i].hello_done(to_server) {
                    buf = next;
                    continue;
                }
            }

            let mut selected = None;
            let mut ambiguous = false;
            let mut error = QuicEvent::FailedDecrypt;
            let has_candidates = !candidates.is_empty();
            if !has_candidates && to_server {
                // The first server Initial may be absent from a partial capture.
                // Try retained keys before deriving new ones from the changed
                // DCID. These loose candidates must not block a new connection
                // or skip decryption based on an already completed Hello.
                candidates.extend(
                    self.connections
                        .iter()
                        .enumerate()
                        .filter(|(_, c)| c.may_match_client_initial(&header))
                        .map(|(i, _)| i),
                );
            }
            for i in candidates {
                match self.connections[i].decode(&header, to_server, packet, payload, hlen) {
                    Ok(data) => {
                        if selected.is_some() {
                            ambiguous = true;
                            break;
                        }
                        selected = Some((i, data));
                    }
                    Err(e) => error = e,
                }
            }
            if ambiguous {
                self.set_event_notx(QuicEvent::ErrorOnData, header, to_server);
                buf = next;
                continue;
            }

            let (i, mut data) = if let Some(found) = selected {
                found
            } else if !has_candidates && (to_server || !header.flags.is_long) {
                let mut connection = QuicConnection::new(&header, now);
                if !connection.supported(&header) {
                    self.new_tx(
                        header,
                        QuicData { frames: Vec::new() },
                        None,
                        None,
                        Vec::new(),
                        None,
                        None,
                        to_server,
                        false,
                    );
                    buf = next;
                    continue;
                }
                let mut data = match connection.decode(&header, to_server, packet, payload, hlen) {
                    Ok(data) => data,
                    Err(e) => {
                        self.set_event_notx(e, header, to_server);
                        buf = next;
                        continue;
                    }
                };
                // Validate before admitting a connection or evicting an old record.
                if let Err(e) = connection.ingest(&mut data, &header, to_server, now) {
                    self.set_event_notx(e, header, to_server);
                    buf = next;
                    continue;
                }
                if self.connections.len() >= self.max_connections {
                    if let Some(oldest) = self
                        .connections
                        .iter()
                        .enumerate()
                        .filter(|(_, c)| c.complete())
                        .min_by_key(|(_, c)| c.last_seen)
                        .map(|(i, _)| i)
                    {
                        self.connections.remove(oldest);
                    } else {
                        self.set_event_notx(QuicEvent::TooManyConnections, header, to_server);
                        buf = next;
                        continue;
                    }
                }
                self.connections.push(connection);
                self.handle_frames(data, header, to_server);
                buf = next;
                continue;
            } else {
                // Without a matching client Initial, server Initial keys cannot
                // be recovered. This is expected with partial captures.
                if has_candidates {
                    self.set_event_notx(error, header, to_server);
                }
                buf = next;
                continue;
            };

            if !self.connections[i].hello_done(to_server) {
                match self.connections[i].ingest(&mut data, &header, to_server, now) {
                    Ok(()) => self.handle_frames(data, header, to_server),
                    Err(e) => self.set_event_notx(e, header, to_server),
                }
            }
            buf = next;
        }
        self.apply_encryption_policy(pstate);
        true
    }

    fn apply_encryption_policy(&self, pstate: *mut AppLayerParserState) {
        if pstate.is_null()
            || self.connections.is_empty()
            || !self.connections.iter().all(QuicConnection::complete)
        {
            return;
        }
        // Keep UDP application parsing alive for future connections. Explicit
        // bypass remains a flow-wide opt-out of subsequent connection inspection.
        let flags = self.encryption_flags(unsafe { ENCRYPTION_BYPASS_ENABLED });
        if flags != 0 {
            unsafe {
                SCAppLayerParserStateSetFlag(pstate, flags);
            }
        }
    }

    fn encryption_flags(&self, handling: EncryptionHandling) -> u16 {
        if self.connections.is_empty() || !self.connections.iter().all(QuicConnection::complete) {
            return 0;
        }
        match handling {
            EncryptionHandling::ENCRYPTION_HANDLING_TRACK_ONLY => {
                APP_LAYER_PARSER_NO_INSPECTION_PAYLOAD
            }
            EncryptionHandling::ENCRYPTION_HANDLING_BYPASS => {
                APP_LAYER_PARSER_NO_INSPECTION | APP_LAYER_PARSER_BYPASS_READY
            }
            _ => 0,
        }
    }
}

extern "C" fn quic_state_new(
    _orig_state: *mut std::os::raw::c_void, _orig_proto: AppProto,
) -> *mut std::os::raw::c_void {
    let state = QuicState::new();
    let boxed = Box::new(state);
    return Box::into_raw(boxed) as *mut _;
}

extern "C" fn quic_state_free(state: *mut std::os::raw::c_void) {
    // Just unbox...
    std::mem::drop(unsafe { Box::from_raw(state as *mut QuicState) });
}

unsafe extern "C" fn quic_state_tx_free(state: *mut std::os::raw::c_void, tx_id: u64) {
    let state = cast_pointer!(state, QuicState);
    state.free_tx(tx_id);
}

unsafe extern "C" fn quic_probing_parser(
    _flow: *const Flow, _direction: u8, input: *const u8, input_len: u32, _rdir: *mut u8,
) -> AppProto {
    if input.is_null() {
        return ALPROTO_UNKNOWN;
    }
    let slice = build_slice!(input, input_len as usize);

    if QuicHeader::from_bytes(slice, DEFAULT_DCID_LEN).is_ok() {
        return ALPROTO_QUIC;
    } else {
        return ALPROTO_FAILED;
    }
}

unsafe extern "C" fn quic_parse_tc(
    flow: *mut Flow, state: *mut std::os::raw::c_void, pstate: *mut AppLayerParserState,
    stream_slice: StreamSlice, _data: *mut std::os::raw::c_void,
) -> AppLayerResult {
    let state = cast_pointer!(state, QuicState);
    let buf = stream_slice.as_slice();

    if state.parse(buf, false, pstate, flow_get_last_time(&*flow)) {
        return AppLayerResult::ok();
    } else {
        return AppLayerResult::err();
    }
}

unsafe extern "C" fn quic_parse_ts(
    flow: *mut Flow, state: *mut std::os::raw::c_void, pstate: *mut AppLayerParserState,
    stream_slice: StreamSlice, _data: *mut std::os::raw::c_void,
) -> AppLayerResult {
    let state = cast_pointer!(state, QuicState);
    let buf = stream_slice.as_slice();

    if state.parse(buf, true, pstate, flow_get_last_time(&*flow)) {
        return AppLayerResult::ok();
    } else {
        return AppLayerResult::err();
    }
}

unsafe extern "C" fn quic_state_get_tx(
    state: *mut std::os::raw::c_void, tx_id: u64,
) -> *mut std::os::raw::c_void {
    let state = cast_pointer!(state, QuicState);
    match state.get_tx(tx_id) {
        Some(tx) => {
            return tx as *const _ as *mut _;
        }
        None => {
            return std::ptr::null_mut();
        }
    }
}

unsafe extern "C" fn quic_state_get_tx_count(state: *mut std::os::raw::c_void) -> u64 {
    let state = cast_pointer!(state, QuicState);
    return state.max_tx_id;
}

unsafe extern "C" fn quic_tx_get_alstate_progress(
    tx: *mut std::os::raw::c_void, _direction: u8,
) -> std::os::raw::c_int {
    let _tx = cast_pointer!(tx, QuicTransaction);
    return 1;
}

export_tx_data_get!(quic_get_tx_data, QuicTransaction);
export_state_data_get!(quic_get_state_data, QuicState);

// Parser name as a C style string.
const PARSER_NAME: &[u8] = b"quic\0";

impl State<QuicTransaction> for QuicState {
    fn get_transaction_count(&self) -> usize {
        self.transactions.len()
    }

    fn get_transaction_by_index(&self, index: usize) -> Option<&QuicTransaction> {
        self.transactions.get(index)
    }
}

impl Transaction for QuicTransaction {
    fn id(&self) -> u64 {
        self.tx_id
    }
}

#[no_mangle]
pub unsafe extern "C" fn SCRegisterQuicParser() {
    let default_port = CString::new("[443,80]").unwrap();
    let parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const std::os::raw::c_char,
        default_port: default_port.as_ptr(),
        ipproto: IPPROTO_UDP,
        probe_ts: Some(quic_probing_parser),
        probe_tc: Some(quic_probing_parser),
        min_depth: 0,
        max_depth: 16,
        state_new: quic_state_new,
        state_free: quic_state_free,
        tx_free: quic_state_tx_free,
        parse_ts: quic_parse_ts,
        parse_tc: quic_parse_tc,
        get_tx_count: quic_state_get_tx_count,
        get_tx: quic_state_get_tx,
        tx_comp_st_ts: 1,
        tx_comp_st_tc: 1,
        tx_get_progress: quic_tx_get_alstate_progress,
        get_eventinfo: Some(QuicEvent::get_event_info),
        get_eventinfo_byid: Some(QuicEvent::get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_tx_files: None,
        get_tx_iterator: Some(applayer::state_get_tx_iterator::<QuicState, QuicTransaction>),
        get_tx_data: quic_get_tx_data,
        get_state_data: quic_get_state_data,
        apply_tx_config: None,
        flags: 0,
        get_frame_id_by_name: None,
        get_frame_name_by_id: None,
        get_state_id_by_name: None,
        get_state_name_by_id: None,
    };

    let ip_proto_str = CString::new("udp").unwrap();

    if SCAppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = applayer_register_protocol_detection(&parser, 1);
        ALPROTO_QUIC = alproto;
        if SCAppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
            if let Some(value) = conf_get("app-layer.protocols.quic.max-connections") {
                match value.parse::<usize>().ok().filter(|n| *n > 0) {
                    Some(n) => MAX_CONNECTIONS = n,
                    None => {
                        SCFatalErrorOnInit!("Invalid quic.max-connections");
                    }
                }
            }
            if let Some(value) = conf_get("app-layer.protocols.quic.connection-idle-timeout") {
                match value.parse::<u64>().ok().filter(|n| *n > 0) {
                    Some(n) => CONNECTION_IDLE_TIMEOUT = n,
                    None => {
                        SCFatalErrorOnInit!("Invalid quic.connection-idle-timeout");
                    }
                }
            }
            if let Some(val) = conf_get("app-layer.protocols.quic.encryption-handling") {
                if let Ok(eh) = EncryptionHandling::from_str(val) {
                    unsafe { ENCRYPTION_BYPASS_ENABLED = eh };
                } else {
                    SCFatalErrorOnInit!("Unknown value {} for quic.encryption-handling.", val);
                }
            }
        }
        SCLogDebug!("Rust quic parser registered.");
        SCAppLayerParserRegisterLogger(IPPROTO_UDP, ALPROTO_QUIC);
    } else {
        SCLogDebug!("Protocol detector and parser disabled for quic.");
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
