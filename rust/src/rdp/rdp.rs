/* Copyright (C) 2019-2022 Open Information Security Foundation
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

//! RDP application layer

use crate::applayer::{self, *};
use crate::core::{AppProto, Flow, ALPROTO_UNKNOWN, IPPROTO_TCP};
use crate::rdp::parser::*;
use nom7::Err;
use std;
use std::collections::VecDeque;
use tls_parser::{parse_tls_plaintext, TlsMessage, TlsMessageHandshake, TlsRecordType};

static mut ALPROTO_RDP: AppProto = ALPROTO_UNKNOWN;

//
// transactions
//

#[derive(Debug, PartialEq)]
pub struct CertificateBlob {
    pub data: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub enum RdpTransactionItem {
    X224ConnectionRequest(X224ConnectionRequest),
    X224ConnectionConfirm(X224ConnectionConfirm),
    McsConnectRequest(McsConnectRequest),
    McsConnectResponse(McsConnectResponse),
    TlsCertificateChain(Vec<CertificateBlob>),
}

#[derive(Debug, PartialEq)]
pub struct RdpTransaction {
    pub id: u64,
    pub item: RdpTransactionItem,
    // managed by macros `export_tx_get_detect_state!` and `export_tx_set_detect_state!`
    tx_data: AppLayerTxData,
}

impl Transaction for RdpTransaction {
    fn id(&self) -> u64 {
        self.id
    }
}

impl RdpTransaction {
    fn new(id: u64, item: RdpTransactionItem) -> Self {
        Self {
            id,
            item,
            tx_data: AppLayerTxData::new(),
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_rdp_state_get_tx(
    state: *mut std::os::raw::c_void, tx_id: u64,
) -> *mut std::os::raw::c_void {
    let state = cast_pointer!(state, RdpState);
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
pub unsafe extern "C" fn rs_rdp_state_get_tx_count(state: *mut std::os::raw::c_void) -> u64 {
    let state = cast_pointer!(state, RdpState);
    return state.next_id;
}

#[no_mangle]
pub extern "C" fn rs_rdp_tx_get_progress(
    _tx: *mut std::os::raw::c_void, _direction: u8,
) -> std::os::raw::c_int {
    // tx complete when `rs_rdp_tx_get_progress(...) == rs_rdp_tx_get_progress_complete(...)`
    // here, all transactions are immediately complete on insert
    return 1;
}

//
// state
//

#[derive(Debug, PartialEq)]
pub struct RdpState {
    next_id: u64,
    transactions: VecDeque<RdpTransaction>,
    tls_parsing: bool,
    bypass_parsing: bool,
}

impl State<RdpTransaction> for RdpState {
    fn get_transaction_count(&self) -> usize {
        self.transactions.len()
    }

    fn get_transaction_by_index(&self, index: usize) -> Option<&RdpTransaction> {
        self.transactions.get(index)
    }
}

impl RdpState {
    fn new() -> Self {
        Self {
            next_id: 0,
            transactions: VecDeque::new(),
            tls_parsing: false,
            bypass_parsing: false,
        }
    }

    fn free_tx(&mut self, tx_id: u64) {
        let len = self.transactions.len();
        let mut found = false;
        let mut index = 0;
        for ii in 0..len {
            let tx = &self.transactions[ii];
            if tx.id == tx_id {
                found = true;
                index = ii;
                break;
            }
        }
        if found {
            self.transactions.remove(index);
        }
    }

    fn get_tx(&self, tx_id: u64) -> Option<&RdpTransaction> {
        for tx in &self.transactions {
            if tx.id == tx_id {
                return Some(tx);
            }
        }
        return None;
    }

    fn new_tx(&mut self, item: RdpTransactionItem) -> RdpTransaction {
        self.next_id += 1;
        let tx = RdpTransaction::new(self.next_id, item);
        return tx;
    }

    /// parse buffer captures from client to server
    fn parse_ts(&mut self, input: &[u8]) -> AppLayerResult {
        // no need to process input buffer
        if self.bypass_parsing {
            return AppLayerResult::ok();
        }
        let mut available = input;

        loop {
            if available.len() == 0 {
                return AppLayerResult::ok();
            }
            if self.tls_parsing {
                match parse_tls_plaintext(available) {
                    Ok((remainder, _tls)) => {
                        // bytes available for futher parsing are what remain
                        available = remainder;
                    }

                    Err(Err::Incomplete(_)) => {
                        // nom need not compatible with applayer need, request one more byte
                        return AppLayerResult::incomplete(
                            (input.len() - available.len()) as u32,
                            (available.len() + 1) as u32,
                        );
                    }

                    Err(Err::Failure(_)) | Err(Err::Error(_)) => {
                        return AppLayerResult::err();
                    }
                }
            } else {
                // every message should be encapsulated within a T.123 tpkt
                match parse_t123_tpkt(available) {
                    // success
                    Ok((remainder, t123)) => {
                        // bytes available for futher parsing are what remain
                        available = remainder;
                        // evaluate message within the tpkt
                        match t123.child {
                            // X.224 connection request
                            T123TpktChild::X224ConnectionRequest(x224) => {
                                let tx =
                                    self.new_tx(RdpTransactionItem::X224ConnectionRequest(x224));
                                self.transactions.push_back(tx);
                            }

                            // X.223 data packet, evaluate what it encapsulates
                            T123TpktChild::Data(x223) => {
                                match x223.child {
                                    X223DataChild::McsConnectRequest(mcs) => {
                                        let tx =
                                            self.new_tx(RdpTransactionItem::McsConnectRequest(mcs));
                                        self.transactions.push_back(tx);
                                    }
                                    // unknown message in X.223, skip
                                    _ => (),
                                }
                            }

                            // unknown message in T.123, skip
                            _ => (),
                        }
                    }

                    Err(Err::Incomplete(_)) => {
                        // nom need not compatible with applayer need, request one more byte
                        return AppLayerResult::incomplete(
                            (input.len() - available.len()) as u32,
                            (available.len() + 1) as u32,
                        );
                    }

                    Err(Err::Failure(_)) | Err(Err::Error(_)) => {
                        if probe_tls_handshake(available) {
                            self.tls_parsing = true;
                            let r = self.parse_ts(available);
                            if r.status == 1 {
                                //adds bytes already consumed to incomplete result
                                let consumed = (input.len() - available.len()) as u32;
                                return AppLayerResult::incomplete(r.consumed + consumed, r.needed);
                            } else {
                                return r;
                            }
                        } else {
                            return AppLayerResult::err();
                        }
                    }
                }
            }
        }
    }

    /// parse buffer captures from server to client
    fn parse_tc(&mut self, input: &[u8]) -> AppLayerResult {
        // no need to process input buffer
        if self.bypass_parsing {
            return AppLayerResult::ok();
        }
        let mut available = input;

        loop {
            if available.len() == 0 {
                return AppLayerResult::ok();
            }
            if self.tls_parsing {
                match parse_tls_plaintext(available) {
                    Ok((remainder, tls)) => {
                        // bytes available for futher parsing are what remain
                        available = remainder;
                        for message in &tls.msg {
                            match message {
                                TlsMessage::Handshake(TlsMessageHandshake::Certificate(
                                    contents,
                                )) => {
                                    let mut chain = Vec::new();
                                    for cert in &contents.cert_chain {
                                        chain.push(CertificateBlob {
                                            data: cert.data.to_vec(),
                                        });
                                    }
                                    let tx =
                                        self.new_tx(RdpTransactionItem::TlsCertificateChain(chain));
                                    self.transactions.push_back(tx);
                                    self.bypass_parsing = true;
                                }
                                _ => {}
                            }
                        }
                    }

                    Err(Err::Incomplete(_)) => {
                        // nom need not compatible with applayer need, request one more byte
                        return AppLayerResult::incomplete(
                            (input.len() - available.len()) as u32,
                            (available.len() + 1) as u32,
                        );
                    }

                    Err(Err::Failure(_)) | Err(Err::Error(_)) => {
                        return AppLayerResult::err();
                    }
                }
            } else {
                // every message should be encapsulated within a T.123 tpkt
                match parse_t123_tpkt(available) {
                    // success
                    Ok((remainder, t123)) => {
                        // bytes available for futher parsing are what remain
                        available = remainder;
                        // evaluate message within the tpkt
                        match t123.child {
                            // X.224 connection confirm
                            T123TpktChild::X224ConnectionConfirm(x224) => {
                                let tx =
                                    self.new_tx(RdpTransactionItem::X224ConnectionConfirm(x224));
                                self.transactions.push_back(tx);
                            }

                            // X.223 data packet, evaluate what it encapsulates
                            T123TpktChild::Data(x223) => {
                                match x223.child {
                                    X223DataChild::McsConnectResponse(mcs) => {
                                        let tx = self
                                            .new_tx(RdpTransactionItem::McsConnectResponse(mcs));
                                        self.transactions.push_back(tx);
                                        self.bypass_parsing = true;
                                        return AppLayerResult::ok();
                                    }

                                    // unknown message in X.223, skip
                                    _ => (),
                                }
                            }

                            // unknown message in T.123, skip
                            _ => (),
                        }
                    }

                    Err(Err::Incomplete(_)) => {
                        // nom need not compatible with applayer need, request one more byte
                        return AppLayerResult::incomplete(
                            (input.len() - available.len()) as u32,
                            (available.len() + 1) as u32,
                        );
                    }

                    Err(Err::Failure(_)) | Err(Err::Error(_)) => {
                        if probe_tls_handshake(available) {
                            self.tls_parsing = true;
                            let r = self.parse_tc(available);
                            if r.status == 1 {
                                //adds bytes already consumed to incomplete result
                                let consumed = (input.len() - available.len()) as u32;
                                return AppLayerResult::incomplete(r.consumed + consumed, r.needed);
                            } else {
                                return r;
                            }
                        } else {
                            return AppLayerResult::err();
                        }
                    }
                }
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn rs_rdp_state_new(_orig_state: *mut std::os::raw::c_void, _orig_proto: AppProto) -> *mut std::os::raw::c_void {
    let state = RdpState::new();
    let boxed = Box::new(state);
    return Box::into_raw(boxed) as *mut _;
}

#[no_mangle]
pub extern "C" fn rs_rdp_state_free(state: *mut std::os::raw::c_void) {
    std::mem::drop(unsafe { Box::from_raw(state as *mut RdpState) });
}

#[no_mangle]
pub unsafe extern "C" fn rs_rdp_state_tx_free(state: *mut std::os::raw::c_void, tx_id: u64) {
    let state = cast_pointer!(state, RdpState);
    state.free_tx(tx_id);
}

//
// probe
//

/// probe for T.123 type identifier, as each message is encapsulated in T.123
fn probe_rdp(input: &[u8]) -> bool {
    input.len() > 0 && input[0] == TpktVersion::T123 as u8
}

/// probe for T.123 message, whether to client or to server
#[no_mangle]
pub unsafe extern "C" fn rs_rdp_probe_ts_tc(
    _flow: *const Flow, _direction: u8, input: *const u8, input_len: u32, _rdir: *mut u8,
) -> AppProto {
    if !input.is_null() {
        // probe bytes for `rdp` protocol pattern
        let slice = build_slice!(input, input_len as usize);

        // Some sessions immediately (first byte) switch to TLS/SSL, e.g.
        // https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=view&target=rdp-ssl.pcap.gz
        // but this callback will not be exercised, so `probe_tls_handshake` not needed here.
        if probe_rdp(slice) {
            return ALPROTO_RDP;
        }
    }
    return ALPROTO_UNKNOWN;
}

/// probe for TLS
fn probe_tls_handshake(input: &[u8]) -> bool {
    input.len() > 0 && input[0] == u8::from(TlsRecordType::Handshake)
}

//
// parse
//

#[no_mangle]
pub unsafe extern "C" fn rs_rdp_parse_ts(
    _flow: *const Flow, state: *mut std::os::raw::c_void, _pstate: *mut std::os::raw::c_void,
    stream_slice: StreamSlice,
    _data: *const std::os::raw::c_void
) -> AppLayerResult {
    let state = cast_pointer!(state, RdpState);
    let buf = stream_slice.as_slice();
    // attempt to parse bytes as `rdp` protocol
    return state.parse_ts(buf);
}

#[no_mangle]
pub unsafe extern "C" fn rs_rdp_parse_tc(
    _flow: *const Flow, state: *mut std::os::raw::c_void, _pstate: *mut std::os::raw::c_void,
    stream_slice: StreamSlice,
    _data: *const std::os::raw::c_void
) -> AppLayerResult {
    let state = cast_pointer!(state, RdpState);
    let buf = stream_slice.as_slice();
    // attempt to parse bytes as `rdp` protocol
    return state.parse_tc(buf);
}

export_tx_data_get!(rs_rdp_get_tx_data, RdpTransaction);

//
// registration
//

const PARSER_NAME: &'static [u8] = b"rdp\0";

#[no_mangle]
pub unsafe extern "C" fn rs_rdp_register_parser() {
    let default_port = std::ffi::CString::new("[3389]").unwrap();
    let parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const std::os::raw::c_char,
        default_port: default_port.as_ptr(),
        ipproto: IPPROTO_TCP,
        probe_ts: Some(rs_rdp_probe_ts_tc),
        probe_tc: Some(rs_rdp_probe_ts_tc),
        min_depth: 0,
        max_depth: 16,
        state_new: rs_rdp_state_new,
        state_free: rs_rdp_state_free,
        tx_free: rs_rdp_state_tx_free,
        parse_ts: rs_rdp_parse_ts,
        parse_tc: rs_rdp_parse_tc,
        get_tx_count: rs_rdp_state_get_tx_count,
        get_tx: rs_rdp_state_get_tx,
        tx_comp_st_ts: 1,
        tx_comp_st_tc: 1,
        tx_get_progress: rs_rdp_tx_get_progress,
        get_eventinfo: None,
        get_eventinfo_byid: None,
        localstorage_new: None,
        localstorage_free: None,
        get_files: None,
        get_tx_iterator: Some(applayer::state_get_tx_iterator::<RdpState, RdpTransaction>),
        get_tx_data: rs_rdp_get_tx_data,
        apply_tx_config: None,
        flags: APP_LAYER_PARSER_OPT_UNIDIR_TXS,
        truncate: None,
        get_frame_id_by_name: None,
        get_frame_name_by_id: None,
    };

    let ip_proto_str = std::ffi::CString::new("tcp").unwrap();

    if AppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_RDP = alproto;
        if AppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rdp::parser::{RdpCookie, X224ConnectionRequest};

    #[test]
    fn test_probe_rdp() {
        let buf: &[u8] = &[0x03, 0x00];
        assert_eq!(true, probe_rdp(buf));
    }

    #[test]
    fn test_probe_rdp_other() {
        let buf: &[u8] = &[0x04, 0x00];
        assert_eq!(false, probe_rdp(buf));
    }

    #[test]
    fn test_probe_tls_handshake() {
        let buf: &[u8] = &[0x16, 0x00];
        assert_eq!(true, probe_tls_handshake(buf));
    }

    #[test]
    fn test_probe_tls_handshake_other() {
        let buf: &[u8] = &[0x17, 0x00];
        assert_eq!(false, probe_tls_handshake(buf));
    }

    #[test]
    fn test_parse_ts_rdp() {
        let buf_1: &[u8] = &[0x03, 0x00, 0x00, 0x25, 0x20, 0xe0, 0x00, 0x00];
        let buf_2: &[u8] = &[
            0x03, 0x00, 0x00, 0x25, 0x20, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x43, 0x6f, 0x6f,
            0x6b, 0x69, 0x65, 0x3a, 0x20, 0x6d, 0x73, 0x74, 0x73, 0x68, 0x61, 0x73, 0x68, 0x3d,
            0x75, 0x73, 0x65, 0x72, 0x31, 0x32, 0x33, 0x0d, 0x0a,
        ];
        let mut state = RdpState::new();
        // will consume 0, request length + 1
        assert_eq!(AppLayerResult::incomplete(0, 9), state.parse_ts(buf_1));
        assert_eq!(0, state.transactions.len());
        // exactly aligns with transaction
        assert_eq!(AppLayerResult::ok(), state.parse_ts(buf_2));
        assert_eq!(1, state.transactions.len());
        let item = RdpTransactionItem::X224ConnectionRequest(X224ConnectionRequest {
            cdt: 0,
            dst_ref: 0,
            src_ref: 0,
            class: 0,
            options: 0,
            cookie: Some(RdpCookie {
                mstshash: String::from("user123"),
            }),
            negotiation_request: None,
            data: Vec::new(),
        });
        assert_eq!(item, state.transactions[0].item);
    }

    #[test]
    fn test_parse_ts_other() {
        let buf: &[u8] = &[0x03, 0x00, 0x00, 0x01, 0x00];
        let mut state = RdpState::new();
        assert_eq!(AppLayerResult::err(), state.parse_ts(buf));
    }

    #[test]
    fn test_parse_tc_rdp() {
        let buf_1: &[u8] = &[0x03, 0x00, 0x00, 0x09, 0x02];
        let buf_2: &[u8] = &[0x03, 0x00, 0x00, 0x09, 0x02, 0xf0, 0x80, 0x7f, 0x66];
        let mut state = RdpState::new();
        // will consume 0, request length + 1
        assert_eq!(AppLayerResult::incomplete(0, 6), state.parse_tc(buf_1));
        assert_eq!(0, state.transactions.len());
        // exactly aligns with transaction
        assert_eq!(AppLayerResult::ok(), state.parse_tc(buf_2));
        assert_eq!(1, state.transactions.len());
        let item = RdpTransactionItem::McsConnectResponse(McsConnectResponse {});
        assert_eq!(item, state.transactions[0].item);
    }

    #[test]
    fn test_parse_tc_other() {
        let buf: &[u8] = &[0x03, 0x00, 0x00, 0x01, 0x00];
        let mut state = RdpState::new();
        assert_eq!(AppLayerResult::err(), state.parse_tc(buf));
    }

    #[test]
    fn test_state_new_tx() {
        let mut state = RdpState::new();
        let item0 = RdpTransactionItem::McsConnectRequest(McsConnectRequest {
            children: Vec::new(),
        });
        let item1 = RdpTransactionItem::McsConnectRequest(McsConnectRequest {
            children: Vec::new(),
        });
        let tx0 = state.new_tx(item0);
        let tx1 = state.new_tx(item1);
        assert_eq!(2, state.next_id);
        state.transactions.push_back(tx0);
        state.transactions.push_back(tx1);
        assert_eq!(2, state.transactions.len());
        assert_eq!(1, state.transactions[0].id);
        assert_eq!(2, state.transactions[1].id);
        assert_eq!(false, state.tls_parsing);
        assert_eq!(false, state.bypass_parsing);
    }

    #[test]
    fn test_state_get_tx() {
        let mut state = RdpState::new();
        let item0 = RdpTransactionItem::McsConnectRequest(McsConnectRequest {
            children: Vec::new(),
        });
        let item1 = RdpTransactionItem::McsConnectRequest(McsConnectRequest {
            children: Vec::new(),
        });
        let item2 = RdpTransactionItem::McsConnectRequest(McsConnectRequest {
            children: Vec::new(),
        });
        let tx0 = state.new_tx(item0);
        let tx1 = state.new_tx(item1);
        let tx2 = state.new_tx(item2);
        state.transactions.push_back(tx0);
        state.transactions.push_back(tx1);
        state.transactions.push_back(tx2);
        assert_eq!(Some(&state.transactions[1]), state.get_tx(2));
    }

    #[test]
    fn test_state_free_tx() {
        let mut state = RdpState::new();
        let item0 = RdpTransactionItem::McsConnectRequest(McsConnectRequest {
            children: Vec::new(),
        });
        let item1 = RdpTransactionItem::McsConnectRequest(McsConnectRequest {
            children: Vec::new(),
        });
        let item2 = RdpTransactionItem::McsConnectRequest(McsConnectRequest {
            children: Vec::new(),
        });
        let tx0 = state.new_tx(item0);
        let tx1 = state.new_tx(item1);
        let tx2 = state.new_tx(item2);
        state.transactions.push_back(tx0);
        state.transactions.push_back(tx1);
        state.transactions.push_back(tx2);
        state.free_tx(1);
        assert_eq!(3, state.next_id);
        assert_eq!(2, state.transactions.len());
        assert_eq!(2, state.transactions[0].id);
        assert_eq!(3, state.transactions[1].id);
        assert_eq!(None, state.get_tx(1));
    }
}
