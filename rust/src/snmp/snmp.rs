/* Copyright (C) 2017-2021 Open Information Security Foundation
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

// written by Pierre Chifflier  <chifflier@wzdftpd.net>

use crate::snmp::snmp_parser::*;
use crate::core::{self, *};
use crate::applayer::{self, *};
use std;
use std::ffi::CString;

use der_parser::ber::BerObjectContent;
use der_parser::der::parse_der_sequence;
use der_parser::oid::Oid;
use nom7::{Err, IResult};
use nom7::error::{ErrorKind, make_error};

#[derive(AppLayerEvent)]
pub enum SNMPEvent {
    MalformedData,
    UnknownSecurityModel,
    VersionMismatch,
}

pub struct SNMPState<'a> {
    state_data: AppLayerStateData,

    /// SNMP protocol version
    pub version: u32,

    /// List of transactions for this session
    transactions: Vec<SNMPTransaction<'a>>,

    /// tx counter for assigning incrementing id's to tx's
    tx_id: u64,
}

pub struct SNMPPduInfo<'a> {
    pub pdu_type: PduType,

    pub err: ErrorStatus,

    pub trap_type: Option<(TrapType,Oid<'a>,NetworkAddress)>,

    pub vars: Vec<Oid<'a>>,
}

pub struct SNMPTransaction<'a> {
    /// PDU version
    pub version: u32,

    /// PDU info, if present (and cleartext)
    pub info: Option<SNMPPduInfo<'a>>,

    /// Community, if present (SNMPv2)
    pub community: Option<String>,

    /// USM info, if present (SNMPv3)
    pub usm: Option<String>,

    /// True if transaction was encrypted
    pub encrypted: bool,

    /// The internal transaction id
    id: u64,

    tx_data: applayer::AppLayerTxData,
}

impl<'a> Transaction for SNMPTransaction<'a> {
    fn id(&self) -> u64 {
        self.id
    }
}

impl<'a> SNMPState<'a> {
    pub fn new() -> SNMPState<'a> {
        SNMPState{
            state_data: AppLayerStateData::new(),
            version: 0,
            transactions: Vec::new(),
            tx_id: 0,
        }
    }
}

impl<'a> Default for SNMPPduInfo<'a> {
    fn default() -> SNMPPduInfo<'a> {
        SNMPPduInfo{
            pdu_type: PduType(0),
            err: ErrorStatus::NoError,
            trap_type: None,
            vars: Vec::new()
        }
    }
}

impl<'a> State<SNMPTransaction<'a>> for SNMPState<'a> {
    fn get_transaction_count(&self) -> usize {
        self.transactions.len()
    }

    fn get_transaction_by_index(&self, index: usize) -> Option<&SNMPTransaction<'a>> {
        self.transactions.get(index)
    }
}

impl<'a> SNMPState<'a> {
    fn add_pdu_info(&mut self, pdu: &SnmpPdu<'a>, tx: &mut SNMPTransaction<'a>) {
        let mut pdu_info = SNMPPduInfo::default();
        pdu_info.pdu_type = pdu.pdu_type();
        match *pdu {
            SnmpPdu::Generic(ref pdu) => {
                pdu_info.err = pdu.err;
            },
            SnmpPdu::Bulk(_) => {
            },
            SnmpPdu::TrapV1(ref t)    => {
                pdu_info.trap_type = Some((t.generic_trap,t.enterprise.clone(),t.agent_addr));
            }
        }

        for var in pdu.vars_iter() {
            pdu_info.vars.push(var.oid.to_owned());
        }
        tx.info = Some(pdu_info);
    }

    fn handle_snmp_v12(&mut self, msg: SnmpMessage<'a>, _direction: Direction) -> i32 {
        let mut tx = self.new_tx();
        // in the message, version is encoded as 0 (version 1) or 1 (version 2)
        if self.version != msg.version + 1 {
            SCLogDebug!("SNMP version mismatch: expected {}, received {}", self.version, msg.version+1);
            self.set_event_tx(&mut tx, SNMPEvent::VersionMismatch);
        }
        self.add_pdu_info(&msg.pdu, &mut tx);
        tx.community = Some(msg.community);
        self.transactions.push(tx);
        0
    }

    fn handle_snmp_v3(&mut self, msg: SnmpV3Message<'a>, _direction: Direction) -> i32 {
        let mut tx = self.new_tx();
        if self.version != msg.version {
            SCLogDebug!("SNMP version mismatch: expected {}, received {}", self.version, msg.version);
            self.set_event_tx(&mut tx, SNMPEvent::VersionMismatch);
        }
        match msg.data {
            ScopedPduData::Plaintext(pdu) => {
                self.add_pdu_info(&pdu.data, &mut tx);
            },
            _                             => {
                tx.encrypted = true;
            }
        }
        match msg.security_params {
            SecurityParameters::USM(usm) => {
                tx.usm = Some(usm.msg_user_name);
            },
            _                            => {
                self.set_event_tx(&mut tx, SNMPEvent::UnknownSecurityModel);
            }
        }
        self.transactions.push(tx);
        0
    }

    /// Parse an SNMP request message
    ///
    /// Returns 0 if successful, or -1 on error
    fn parse(&mut self, i: &'a [u8], direction: Direction) -> i32 {
        if self.version == 0 {
            match parse_pdu_enveloppe_version(i) {
                Ok((_,x)) => self.version = x,
                _         => (),
            }
        }
        match parse_snmp_generic_message(i) {
            Ok((_rem,SnmpGenericMessage::V1(msg))) |
            Ok((_rem,SnmpGenericMessage::V2(msg))) => self.handle_snmp_v12(msg, direction),
            Ok((_rem,SnmpGenericMessage::V3(msg))) => self.handle_snmp_v3(msg, direction),
            Err(_e) => {
                SCLogDebug!("parse_snmp failed: {:?}", _e);
                self.set_event(SNMPEvent::MalformedData);
                -1
            },
        }
    }

    fn free(&mut self) {
        // All transactions are freed when the `transactions` object is freed.
        // But let's be explicit
        self.transactions.clear();
    }

    fn new_tx(&mut self) -> SNMPTransaction<'a> {
        self.tx_id += 1;
        SNMPTransaction::new(self.version, self.tx_id)
    }

    fn get_tx_by_id(&mut self, tx_id: u64) -> Option<&SNMPTransaction> {
        self.transactions.iter().rev().find(|&tx| tx.id == tx_id + 1)
    }

    fn free_tx(&mut self, tx_id: u64) {
        let tx = self.transactions.iter().position(|tx| tx.id == tx_id + 1);
        debug_assert!(tx != None);
        if let Some(idx) = tx {
            let _ = self.transactions.remove(idx);
        }
    }

    /// Set an event. The event is set on the most recent transaction.
    fn set_event(&mut self, event: SNMPEvent) {
        if let Some(tx) = self.transactions.last_mut() {
            tx.tx_data.set_event(event as u8);
        }
    }

    /// Set an event on a specific transaction.
    fn set_event_tx(&self, tx: &mut SNMPTransaction, event: SNMPEvent) {
        tx.tx_data.set_event(event as u8);
    }
}

impl<'a> SNMPTransaction<'a> {
    pub fn new(version: u32, id: u64) -> SNMPTransaction<'a> {
        SNMPTransaction {
            version,
            info: None,
            community: None,
            usm: None,
            encrypted: false,
            id: id,
            tx_data: applayer::AppLayerTxData::new(),
        }
    }
}

/// Returns *mut SNMPState
#[no_mangle]
pub extern "C" fn rs_snmp_state_new(_orig_state: *mut std::os::raw::c_void, _orig_proto: AppProto) -> *mut std::os::raw::c_void {
    let state = SNMPState::new();
    let boxed = Box::new(state);
    return Box::into_raw(boxed) as *mut _;
}

/// Params:
/// - state: *mut SNMPState as void pointer
#[no_mangle]
pub extern "C" fn rs_snmp_state_free(state: *mut std::os::raw::c_void) {
    let mut snmp_state = unsafe{ Box::from_raw(state as *mut SNMPState) };
    snmp_state.free();
}

#[no_mangle]
pub unsafe extern "C" fn rs_snmp_parse_request(_flow: *const core::Flow,
                                       state: *mut std::os::raw::c_void,
                                       _pstate: *mut std::os::raw::c_void,
                                       stream_slice: StreamSlice,
                                       _data: *const std::os::raw::c_void,
                                       ) -> AppLayerResult {
    let state = cast_pointer!(state,SNMPState);
    state.parse(stream_slice.as_slice(), Direction::ToServer).into()
}

#[no_mangle]
pub unsafe extern "C" fn rs_snmp_parse_response(_flow: *const core::Flow,
                                       state: *mut std::os::raw::c_void,
                                       _pstate: *mut std::os::raw::c_void,
                                       stream_slice: StreamSlice,
                                       _data: *const std::os::raw::c_void,
                                       ) -> AppLayerResult {
    let state = cast_pointer!(state,SNMPState);
    state.parse(stream_slice.as_slice(), Direction::ToClient).into()
}

#[no_mangle]
pub unsafe extern "C" fn rs_snmp_state_get_tx(state: *mut std::os::raw::c_void,
                                      tx_id: u64)
                                      -> *mut std::os::raw::c_void
{
    let state = cast_pointer!(state,SNMPState);
    match state.get_tx_by_id(tx_id) {
        Some(tx) => tx as *const _ as *mut _,
        None     => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_snmp_state_get_tx_count(state: *mut std::os::raw::c_void)
                                            -> u64
{
    let state = cast_pointer!(state,SNMPState);
    state.tx_id
}

#[no_mangle]
pub unsafe extern "C" fn rs_snmp_state_tx_free(state: *mut std::os::raw::c_void,
                                       tx_id: u64)
{
    let state = cast_pointer!(state,SNMPState);
    state.free_tx(tx_id);
}

#[no_mangle]
pub extern "C" fn rs_snmp_tx_get_alstate_progress(_tx: *mut std::os::raw::c_void,
                                                 _direction: u8)
                                                 -> std::os::raw::c_int
{
    1
}

static mut ALPROTO_SNMP : AppProto = ALPROTO_UNKNOWN;

// Read PDU sequence and extract version, if similar to SNMP definition
fn parse_pdu_enveloppe_version(i:&[u8]) -> IResult<&[u8],u32> {
    match parse_der_sequence(i) {
        Ok((_,x))     => {
            match x.content {
                BerObjectContent::Sequence(ref v) => {
                    if v.len() == 3 {
                        match v[0].as_u32()  {
                            Ok(0) => { return Ok((i,1)); }, // possibly SNMPv1
                            Ok(1) => { return Ok((i,2)); }, // possibly SNMPv2c
                            _     => ()
                        }
                    } else if v.len() == 4 && v[0].as_u32() == Ok(3) {
                        return Ok((i,3)); // possibly SNMPv3
                    }
                },
                _ => ()
            };
            Err(Err::Error(make_error(i, ErrorKind::Verify)))
        },
        Err(Err::Incomplete(i)) => Err(Err::Incomplete(i)),
        Err(Err::Failure(_)) |
        Err(Err::Error(_))      => Err(Err::Error(make_error(i,ErrorKind::Verify)))
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_snmp_probing_parser(_flow: *const Flow,
                                         _direction: u8,
                                         input:*const u8,
                                         input_len: u32,
                                         _rdir: *mut u8) -> AppProto {
    let slice = build_slice!(input,input_len as usize);
    let alproto = ALPROTO_SNMP;
    if slice.len() < 4 { return ALPROTO_FAILED; }
    match parse_pdu_enveloppe_version(slice) {
        Ok((_,_))               => alproto,
        Err(Err::Incomplete(_)) => ALPROTO_UNKNOWN,
        _                       => ALPROTO_FAILED,
    }
}

export_tx_data_get!(rs_snmp_get_tx_data, SNMPTransaction);
export_state_data_get!(rs_snmp_get_state_data, SNMPState);

const PARSER_NAME : &'static [u8] = b"snmp\0";

#[no_mangle]
pub unsafe extern "C" fn rs_register_snmp_parser() {
    let default_port = CString::new("161").unwrap();
    let mut parser = RustParser {
        name               : PARSER_NAME.as_ptr() as *const std::os::raw::c_char,
        default_port       : default_port.as_ptr(),
        ipproto            : core::IPPROTO_UDP,
        probe_ts           : Some(rs_snmp_probing_parser),
        probe_tc           : Some(rs_snmp_probing_parser),
        min_depth          : 0,
        max_depth          : 16,
        state_new          : rs_snmp_state_new,
        state_free         : rs_snmp_state_free,
        tx_free            : rs_snmp_state_tx_free,
        parse_ts           : rs_snmp_parse_request,
        parse_tc           : rs_snmp_parse_response,
        get_tx_count       : rs_snmp_state_get_tx_count,
        get_tx             : rs_snmp_state_get_tx,
        tx_comp_st_ts      : 1,
        tx_comp_st_tc      : 1,
        tx_get_progress    : rs_snmp_tx_get_alstate_progress,
        get_eventinfo      : Some(SNMPEvent::get_event_info),
        get_eventinfo_byid : Some(SNMPEvent::get_event_info_by_id),
        localstorage_new   : None,
        localstorage_free  : None,
        get_tx_files       : None,
        get_tx_iterator    : Some(applayer::state_get_tx_iterator::<SNMPState, SNMPTransaction>),
        get_tx_data        : rs_snmp_get_tx_data,
        get_state_data     : rs_snmp_get_state_data,
        apply_tx_config    : None,
        flags              : APP_LAYER_PARSER_OPT_UNIDIR_TXS,
        truncate           : None,
        get_frame_id_by_name: None,
        get_frame_name_by_id: None,
    };
    let ip_proto_str = CString::new("udp").unwrap();
    if AppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        // port 161
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        // store the allocated ID for the probe function
        ALPROTO_SNMP = alproto;
        if AppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
        // port 162
        let default_port_traps = CString::new("162").unwrap();
        parser.default_port = default_port_traps.as_ptr();
        let _ = AppLayerRegisterProtocolDetection(&parser, 1);
        if AppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
    } else {
        SCLogDebug!("Protocol detector and parser disabled for SNMP.");
    }
}
