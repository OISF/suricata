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
    crypto::{quic_keys_initial, QuicKeys, AES128_KEY_LEN},
    cyu::Cyu,
    frames::{Frame, QuicTlsExtension, StreamTag},
    parser::{quic_pkt_num, QuicData, QuicHeader, QuicType},
};
use crate::{
    applayer::{self, *},
    direction::Direction,
    flow::Flow,
    ja4::JA4,
};
use crate::{
    core::{ALPROTO_FAILED, ALPROTO_UNKNOWN, IPPROTO_UDP},
    ja4::JA4Impl,
};
use std::collections::VecDeque;
use std::ffi::CString;
use suricata_sys::sys::{
    AppLayerParserState, AppProto, SCAppLayerParserConfParserEnabled,
    SCAppLayerParserRegisterLogger, SCAppLayerProtoDetectConfProtoDetectionEnabled,
};
use tls_parser::TlsExtensionType;

static mut ALPROTO_QUIC: AppProto = ALPROTO_UNKNOWN;

const DEFAULT_DCID_LEN: usize = 16;
const PKT_NUM_BUF_MAX_LEN: usize = 4;
pub(super) const QUIC_MAX_CRYPTO_FRAG_LEN: u64 = 65535;

#[derive(FromPrimitive, Debug, AppLayerEvent)]
pub enum QuicEvent {
    FailedDecrypt,
    ErrorOnData,
    ErrorOnHeader,
    CryptoFragTooLong,
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
    keys: Option<QuicKeys>,
    /// crypto fragment data already seen and reassembled to client
    crypto_frag_tc: Vec<u8>,
    /// number of bytes set in crypto fragment data to client
    crypto_fraglen_tc: u32,
    /// crypto fragment data already seen and reassembled to server
    crypto_frag_ts: Vec<u8>,
    /// number of bytes set in crypto fragment data to server
    crypto_fraglen_ts: u32,
    hello_tc: bool,
    hello_ts: bool,
    has_retried: bool,
    transactions: VecDeque<QuicTransaction>,
}

impl Default for QuicState {
    fn default() -> Self {
        Self {
            state_data: AppLayerStateData::new(),
            max_tx_id: 0,
            keys: None,
            crypto_frag_tc: Vec::new(),
            crypto_frag_ts: Vec::new(),
            crypto_fraglen_tc: 0,
            crypto_fraglen_ts: 0,
            hello_tc: false,
            hello_ts: false,
            has_retried: false,
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

    fn tx_iterator(
        &mut self, min_tx_id: u64, state: &mut u64,
    ) -> Option<(&QuicTransaction, u64, bool)> {
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

    fn decrypt<'a>(
        &mut self, to_server: bool, header: &QuicHeader, framebuf: &'a [u8], buf: &'a [u8],
        hlen: usize, output: &'a mut Vec<u8>,
    ) -> Result<usize, ()> {
        if let Some(keys) = &self.keys {
            let hkey = if to_server {
                &keys.remote.header
            } else {
                &keys.local.header
            };
            if framebuf.len() < PKT_NUM_BUF_MAX_LEN + AES128_KEY_LEN {
                return Err(());
            }
            let h2len = hlen + usize::from(header.length);
            let mut h2 = Vec::with_capacity(h2len);
            h2.extend_from_slice(&buf[..h2len]);
            let mut h20 = h2[0];
            let mut pktnum_buf = Vec::with_capacity(PKT_NUM_BUF_MAX_LEN);
            pktnum_buf.extend_from_slice(&h2[hlen..hlen + PKT_NUM_BUF_MAX_LEN]);
            let r1 = hkey.decrypt_in_place(
                &h2[hlen + PKT_NUM_BUF_MAX_LEN..hlen + PKT_NUM_BUF_MAX_LEN + AES128_KEY_LEN],
                &mut h20,
                &mut pktnum_buf,
            );
            if r1.is_err() {
                return Err(());
            }
            // mutate one at a time
            h2[0] = h20;
            let _ = &h2[hlen..hlen + 1 + ((h20 & 3) as usize)]
                .copy_from_slice(&pktnum_buf[..1 + ((h20 & 3) as usize)]);
            let pkt_num = quic_pkt_num(&h2[hlen..hlen + 1 + ((h20 & 3) as usize)]);
            if framebuf.len() < 1 + ((h20 & 3) as usize) {
                return Err(());
            }
            output.extend_from_slice(&framebuf[1 + ((h20 & 3) as usize)..]);
            let pkey = if to_server {
                &keys.remote.packet
            } else {
                &keys.local.packet
            };
            let r = pkey.decrypt_in_place(pkt_num, &h2[..hlen + 1 + ((h20 & 3) as usize)], output);
            if let Ok(r2) = r {
                return Ok(r2.len());
            }
        }
        return Err(());
    }

    fn handle_frames(&mut self, data: QuicData, header: QuicHeader, to_server: bool) {
        let mut sni: Option<Vec<u8>> = None;
        let mut ua: Option<Vec<u8>> = None;
        let mut ja3: Option<String> = None;
        let mut ja4: Option<JA4> = None;
        let mut extv: Vec<QuicTlsExtension> = Vec::new();
        let mut frag_long = false;
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
                Frame::CryptoFrag(frag) => {
                    // means we had some fragments but not full TLS hello
                    // save it for a later packet
                    if to_server {
                        // use a hardcoded limit to not grow indefinitely
                        if frag.length < QUIC_MAX_CRYPTO_FRAG_LEN {
                            self.crypto_frag_ts.clone_from(&frag.data);
                            self.crypto_fraglen_ts = frag.offset as u32;
                        } else {
                            frag_long = true;
                        }
                    } else if frag.length < QUIC_MAX_CRYPTO_FRAG_LEN {
                        self.crypto_frag_tc.clone_from(&frag.data);
                        self.crypto_fraglen_tc = frag.offset as u32;
                    } else {
                        frag_long = true;
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
                    if to_server {
                        self.hello_ts = true
                    } else {
                        self.hello_tc = true
                    }
                }
                _ => {}
            }
        }
        self.new_tx(header, data, sni, ua, extv, ja3, ja4, to_server, frag_long);
    }

    fn set_event_notx(&mut self, event: QuicEvent, header: QuicHeader, client: bool) {
        let mut tx = QuicTransaction::new_empty(client, header);
        self.max_tx_id += 1;
        tx.tx_id = self.max_tx_id;
        tx.tx_data.set_event(event as u8);
        self.transactions.push_back(tx);
    }

    fn parse(&mut self, input: &[u8], to_server: bool) -> bool {
        // so as to loop over multiple quic headers in one packet
        let mut buf = input;
        while !buf.is_empty() {
            match QuicHeader::from_bytes(buf, DEFAULT_DCID_LEN) {
                Ok((rest, header)) => {
                    if (to_server && self.hello_ts) || (!to_server && self.hello_tc) {
                        // payload is encrypted, stop parsing here
                        return true;
                    }
                    if header.ty == QuicType::Short {
                        // nothing to get
                        return true;
                    }

                    // unprotect/decrypt packet
                    if self.keys.is_none() && header.ty == QuicType::Initial {
                        self.keys = quic_keys_initial(u32::from(header.version), &header.dcid);
                    } else if !to_server
                        && self.keys.is_some()
                        && header.ty == QuicType::Retry
                        && !self.has_retried
                    {
                        // a retry packet discards the current keys, client will resend an initial packet with new keys
                        self.hello_ts = false;
                        self.keys = None;
                        // RFC 9000 17.2.5.2 After the client has received and processed an Initial or Retry packet
                        // from the server, it MUST discard any subsequent Retry packets that it receives.
                        self.has_retried = true;
                    }
                    // header.length was checked against rest.len() during parsing
                    let (mut framebuf, next_buf) = rest.split_at(header.length.into());
                    if header.ty != QuicType::Initial {
                        // only version is interesting, no frames
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
                        buf = next_buf;
                        continue;
                    }
                    let hlen = buf.len() - rest.len();
                    let mut output;
                    if self.keys.is_some() && !framebuf.is_empty() {
                        output = Vec::with_capacity(framebuf.len() + 4);
                        if let Ok(dlen) =
                            self.decrypt(to_server, &header, framebuf, buf, hlen, &mut output)
                        {
                            output.resize(dlen, 0);
                        } else {
                            self.set_event_notx(QuicEvent::FailedDecrypt, header, to_server);
                            return false;
                        }
                        framebuf = &output;
                    }
                    buf = next_buf;

                    let mut frag = Vec::new();
                    // take the current fragment and reset it in the state
                    let past_frag = if to_server {
                        std::mem::swap(&mut self.crypto_frag_ts, &mut frag);
                        &frag
                    } else {
                        std::mem::swap(&mut self.crypto_frag_tc, &mut frag);
                        &frag
                    };
                    let past_fraglen = if to_server {
                        self.crypto_fraglen_ts
                    } else {
                        self.crypto_fraglen_tc
                    };
                    if to_server {
                        self.crypto_fraglen_ts = 0
                    } else {
                        self.crypto_fraglen_tc = 0
                    }
                    match QuicData::from_bytes(framebuf, past_frag, past_fraglen) {
                        Ok(data) => {
                            self.handle_frames(data, header, to_server);
                        }
                        Err(_e) => {
                            self.set_event_notx(QuicEvent::ErrorOnData, header, to_server);
                            return false;
                        }
                    }
                }
                Err(_e) => {
                    // should we make an event with an empty header ?
                    return false;
                }
            }
        }
        return true;
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
    _flow: *mut Flow, state: *mut std::os::raw::c_void, _pstate: *mut AppLayerParserState,
    stream_slice: StreamSlice, _data: *const std::os::raw::c_void,
) -> AppLayerResult {
    let state = cast_pointer!(state, QuicState);
    let buf = stream_slice.as_slice();

    if state.parse(buf, false) {
        return AppLayerResult::ok();
    } else {
        return AppLayerResult::err();
    }
}

unsafe extern "C" fn quic_parse_ts(
    _flow: *mut Flow, state: *mut std::os::raw::c_void, _pstate: *mut AppLayerParserState,
    stream_slice: StreamSlice, _data: *const std::os::raw::c_void,
) -> AppLayerResult {
    let state = cast_pointer!(state, QuicState);
    let buf = stream_slice.as_slice();

    if state.parse(buf, true) {
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

unsafe extern "C" fn quic_state_get_tx_iterator(
    _ipproto: u8, _alproto: AppProto, state: *mut std::os::raw::c_void, min_tx_id: u64,
    _max_tx_id: u64, istate: &mut u64,
) -> applayer::AppLayerGetTxIterTuple {
    let state = cast_pointer!(state, QuicState);
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

export_tx_data_get!(quic_get_tx_data, QuicTransaction);
export_state_data_get!(quic_get_state_data, QuicState);

// Parser name as a C style string.
const PARSER_NAME: &[u8] = b"quic\0";

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
        get_tx_iterator: Some(quic_state_get_tx_iterator),
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
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_QUIC = alproto;
        if SCAppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
        SCLogDebug!("Rust quic parser registered.");
        SCAppLayerParserRegisterLogger(IPPROTO_UDP, ALPROTO_QUIC);
    } else {
        SCLogDebug!("Protocol detector and parser disabled for quic.");
    }
}
