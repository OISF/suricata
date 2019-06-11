/* Copyright (C) 2017-2018 Open Information Security Foundation
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

use ikev2::ipsec_parser::*;
use ikev2::state::IKEV2ConnectionState;
use core;
use core::{AppProto,Flow,ALPROTO_UNKNOWN,ALPROTO_FAILED,STREAM_TOSERVER,STREAM_TOCLIENT};
use applayer;
use parser::*;
use std;
use std::ffi::{CStr,CString};

use log::*;

use nom;

#[repr(u32)]
pub enum IKEV2Event {
    MalformedData = 0,
    NoEncryption,
    WeakCryptoEnc,
    WeakCryptoPRF,
    WeakCryptoDH,
    WeakCryptoAuth,
    WeakCryptoNoDH,
    WeakCryptoNoAuth,
    InvalidProposal,
    UnknownProposal,
}

impl IKEV2Event {
    fn from_i32(value: i32) -> Option<IKEV2Event> {
        match value {
            0 => Some(IKEV2Event::MalformedData),
            1 => Some(IKEV2Event::NoEncryption),
            2 => Some(IKEV2Event::WeakCryptoEnc),
            3 => Some(IKEV2Event::WeakCryptoPRF),
            4 => Some(IKEV2Event::WeakCryptoDH),
            5 => Some(IKEV2Event::WeakCryptoAuth),
            6 => Some(IKEV2Event::WeakCryptoNoDH),
            7 => Some(IKEV2Event::WeakCryptoNoAuth),
            8 => Some(IKEV2Event::InvalidProposal),
            9 => Some(IKEV2Event::UnknownProposal),
            _ => None,
        }
    }
}

pub struct IKEV2State {
    /// List of transactions for this session
    transactions: Vec<IKEV2Transaction>,

    /// tx counter for assigning incrementing id's to tx's
    tx_id: u64,

    /// The connection state
    connection_state: IKEV2ConnectionState,

    /// The transforms proposed by the initiator
    pub client_transforms : Vec<Vec<IkeV2Transform>>,

    /// The transforms selected by the responder
    pub server_transforms : Vec<Vec<IkeV2Transform>>,

    /// The encryption algorithm selected by the responder
    pub alg_enc:  IkeTransformEncType,
    /// The authentication algorithm selected by the responder
    pub alg_auth: IkeTransformAuthType,
    /// The PRF algorithm selected by the responder
    pub alg_prf:  IkeTransformPRFType,
    /// The Diffie-Hellman algorithm selected by the responder
    pub alg_dh:   IkeTransformDHType,
    /// The extended sequence numbers parameter selected by the responder
    pub alg_esn:  IkeTransformESNType,

    /// The Diffie-Hellman group from the server KE message, if present.
    pub dh_group: IkeTransformDHType,

}

#[derive(Debug)]
pub struct IKEV2Transaction {
    /// The IKEV2 reference ID
    pub xid: u64,

    pub hdr: IkeV2Header,

    pub payload_types: Vec<IkePayloadType>,
    pub notify_types: Vec<NotifyType>,

    /// IKEv2 errors seen during exchange
    pub errors: u32,

    /// The internal transaction id
    id: u64,

    /// The detection engine state, if present
    de_state: Option<*mut core::DetectEngineState>,

    /// The events associated with this transaction
    events: *mut core::AppLayerDecoderEvents,

    logged: applayer::LoggerFlags,
}



impl IKEV2State {
    pub fn new() -> IKEV2State {
        IKEV2State{
            transactions: Vec::new(),
            tx_id: 0,
            connection_state: IKEV2ConnectionState::Init,
            dh_group: IkeTransformDHType::None,
            client_transforms: Vec::new(),
            server_transforms: Vec::new(),
            alg_enc: IkeTransformEncType::ENCR_NULL,
            alg_auth: IkeTransformAuthType::NONE,
            alg_prf: IkeTransformPRFType::PRF_NULL,
            alg_dh: IkeTransformDHType::None,
            alg_esn: IkeTransformESNType::NoESN,
        }
    }
}

impl IKEV2State {
    /// Parse an IKEV2 request message
    ///
    /// Returns The number of messages parsed, or -1 on error
    fn parse(&mut self, i: &[u8], direction: u8) -> i32 {
        match parse_ikev2_header(i) {
            Ok((rem,ref hdr)) => {
                if rem.len() == 0 && hdr.length == 28 {
                    return 1;
                }
                // Rule 0: check version
                if hdr.maj_ver != 2 || hdr.min_ver != 0 {
                    self.set_event(IKEV2Event::MalformedData);
                    return -1;
                }
                if hdr.init_spi == 0 {
                    self.set_event(IKEV2Event::MalformedData);
                    return -1;
                }
                // only analyse IKE_SA, other payloads are encrypted
                if hdr.exch_type != IkeExchangeType::IKE_SA_INIT {
                    return 0;
                }
                let mut tx = self.new_tx();
                // use init_spi as transaction identifier
                tx.xid = hdr.init_spi;
                tx.hdr = (*hdr).clone();
                self.transactions.push(tx);
                let mut payload_types = Vec::new();
                let mut errors = 0;
                let mut notify_types = Vec::new();
                match parse_ikev2_payload_list(rem,hdr.next_payload) {
                    Ok((_,Ok(ref p))) => {
                        for payload in p {
                            payload_types.push(payload.hdr.next_payload_type);
                            match payload.content {
                                IkeV2PayloadContent::Dummy => (),
                                IkeV2PayloadContent::SA(ref prop) => {
                                    // if hdr.flags & IKEV2_FLAG_INITIATOR != 0 {
                                        self.add_proposals(prop, direction);
                                    // }
                                },
                                IkeV2PayloadContent::KE(ref kex) => {
                                    SCLogDebug!("KEX {:?}", kex.dh_group);
                                    if direction == STREAM_TOCLIENT {
                                        self.dh_group = kex.dh_group;
                                    }
                                },
                                IkeV2PayloadContent::Nonce(ref n) => {
                                    SCLogDebug!("Nonce: {:?}", n);
                                },
                                IkeV2PayloadContent::Notify(ref n) => {
                                    SCLogDebug!("Notify: {:?}", n);
                                    if n.notify_type.is_error() {
                                        errors += 1;
                                    }
                                    notify_types.push(n.notify_type);
                                },
                                // XXX CertificateRequest
                                // XXX Certificate
                                // XXX Authentication
                                // XXX TSi
                                // XXX TSr
                                // XXX IDr
                                _ => {
                                    SCLogDebug!("Unknown payload content {:?}", payload.content);
                                },
                            }
                            self.connection_state = self.connection_state.advance(payload);
                            if let Some(tx) = self.transactions.last_mut() {
                                // borrow back tx to update it
                                tx.payload_types.append(&mut payload_types);
                                tx.errors = errors;
                                tx.notify_types.append(&mut notify_types);
                            }
                        };
                    },
                    e => { SCLogDebug!("parse_ikev2_payload_with_type: {:?}",e); () },
                }
                1
            },
            Err(nom::Err::Incomplete(_)) => {
                SCLogDebug!("Insufficient data while parsing IKEV2 data");
                self.set_event(IKEV2Event::MalformedData);
                -1
            },
            Err(_) => {
                SCLogDebug!("Error while parsing IKEV2 data");
                self.set_event(IKEV2Event::MalformedData);
                -1
            },
        }
    }

    fn free(&mut self) {
        // All transactions are freed when the `transactions` object is freed.
        // But let's be explicit
        self.transactions.clear();
    }

    fn new_tx(&mut self) -> IKEV2Transaction {
        self.tx_id += 1;
        IKEV2Transaction::new(self.tx_id)
    }

    fn get_tx_by_id(&mut self, tx_id: u64) -> Option<&IKEV2Transaction> {
        self.transactions.iter().find(|&tx| tx.id == tx_id + 1)
    }

    fn free_tx(&mut self, tx_id: u64) {
        let tx = self.transactions.iter().position(|ref tx| tx.id == tx_id + 1);
        debug_assert!(tx != None);
        if let Some(idx) = tx {
            let _ = self.transactions.remove(idx);
        }
    }

    /// Set an event. The event is set on the most recent transaction.
    fn set_event(&mut self, event: IKEV2Event) {
        if let Some(tx) = self.transactions.last_mut() {
            let ev = event as u8;
            core::sc_app_layer_decoder_events_set_event_raw(&mut tx.events, ev);
        } else {
            SCLogDebug!("IKEv2: trying to set event {} on non-existing transaction", event as u32);
        }
    }

    fn add_proposals(&mut self, prop: &Vec<IkeV2Proposal>, direction: u8) {
        for ref p in prop {
            let transforms : Vec<IkeV2Transform> = p.transforms.iter().map(|x| x.into()).collect();
            // Rule 1: warn on weak or unknown transforms
            for xform in &transforms {
                match *xform {
                    IkeV2Transform::Encryption(ref enc) => {
                        match *enc {
                            IkeTransformEncType::ENCR_DES_IV64 |
                            IkeTransformEncType::ENCR_DES |
                            IkeTransformEncType::ENCR_3DES |
                            IkeTransformEncType::ENCR_RC5 |
                            IkeTransformEncType::ENCR_IDEA |
                            IkeTransformEncType::ENCR_CAST |
                            IkeTransformEncType::ENCR_BLOWFISH |
                            IkeTransformEncType::ENCR_3IDEA |
                            IkeTransformEncType::ENCR_DES_IV32 |
                            IkeTransformEncType::ENCR_NULL => {
                                SCLogDebug!("Weak Encryption: {:?}", enc);
                                // XXX send event only if direction == STREAM_TOCLIENT ?
                                self.set_event(IKEV2Event::WeakCryptoEnc);
                            },
                            _ => (),
                        }
                    },
                    IkeV2Transform::PRF(ref prf) => {
                        match *prf {
                            IkeTransformPRFType::PRF_NULL => {
                                SCLogDebug!("'Null' PRF transform proposed");
                                self.set_event(IKEV2Event::InvalidProposal);
                            },
                            IkeTransformPRFType::PRF_HMAC_MD5 |
                            IkeTransformPRFType::PRF_HMAC_SHA1 => {
                                SCLogDebug!("Weak PRF: {:?}", prf);
                                self.set_event(IKEV2Event::WeakCryptoPRF);
                            },
                            _ => (),
                        }
                    },
                    IkeV2Transform::Auth(ref auth) => {
                        match *auth {
                            IkeTransformAuthType::NONE => {
                                // Note: this could be expected with an AEAD encription alg.
                                // See rule 4
                                ()
                            },
                            IkeTransformAuthType::AUTH_HMAC_MD5_96 |
                            IkeTransformAuthType::AUTH_HMAC_SHA1_96 |
                            IkeTransformAuthType::AUTH_DES_MAC |
                            IkeTransformAuthType::AUTH_KPDK_MD5 |
                            IkeTransformAuthType::AUTH_AES_XCBC_96 |
                            IkeTransformAuthType::AUTH_HMAC_MD5_128 |
                            IkeTransformAuthType::AUTH_HMAC_SHA1_160 => {
                                SCLogDebug!("Weak auth: {:?}", auth);
                                self.set_event(IKEV2Event::WeakCryptoAuth);
                            },
                            _ => (),
                        }
                    },
                    IkeV2Transform::DH(ref dh) => {
                        match *dh {
                            IkeTransformDHType::None => {
                                SCLogDebug!("'None' DH transform proposed");
                                self.set_event(IKEV2Event::InvalidProposal);
                            },
                            IkeTransformDHType::Modp768 |
                            IkeTransformDHType::Modp1024 |
                            IkeTransformDHType::Modp1024s160 |
                            IkeTransformDHType::Modp1536 => {
                                SCLogDebug!("Weak DH: {:?}", dh);
                                self.set_event(IKEV2Event::WeakCryptoDH);
                            },
                            _ => (),
                        }
                    },
                    IkeV2Transform::Unknown(tx_type,tx_id) => {
                        SCLogDebug!("Unknown proposal: type={:?}, id={}", tx_type, tx_id);
                        self.set_event(IKEV2Event::UnknownProposal);
                    },
                    _ => (),
                }
            }
            // Rule 2: check if no DH was proposed
            if ! transforms.iter().any(|x| {
                match *x {
                    IkeV2Transform::DH(_) => true,
                    _                     => false
                }
            })
            {
                SCLogDebug!("No DH transform found");
                self.set_event(IKEV2Event::WeakCryptoNoDH);
            }
            // Rule 3: check if proposing AH ([RFC7296] section 3.3.1)
            if p.protocol_id == ProtocolID::AH {
                SCLogDebug!("Proposal uses protocol AH - no confidentiality");
                self.set_event(IKEV2Event::NoEncryption);
            }
            // Rule 4: lack of integrity is accepted only if using an AEAD proposal
            // Look if no auth was proposed, including if proposal is Auth::None
            if ! transforms.iter().any(|x| {
                match *x {
                    IkeV2Transform::Auth(IkeTransformAuthType::NONE) => false,
                    IkeV2Transform::Auth(_)                          => true,
                    _                                                => false,
                }
            })
            {
                if ! transforms.iter().any(|x| {
                    match *x {
                        IkeV2Transform::Encryption(ref enc) => enc.is_aead(),
                        _                                   => false
                    }
                }) {
                    SCLogDebug!("No integrity transform found");
                    self.set_event(IKEV2Event::WeakCryptoNoAuth);
                }
            }
            // Finally
            if direction == STREAM_TOCLIENT {
                transforms.iter().for_each(|t|
                                           match *t {
                                               IkeV2Transform::Encryption(ref e) => self.alg_enc = *e,
                                               IkeV2Transform::Auth(ref a) => self.alg_auth = *a,
                                               IkeV2Transform::PRF(ref p) => self.alg_prf = *p,
                                               IkeV2Transform::DH(ref dh) => self.alg_dh = *dh,
                                               IkeV2Transform::ESN(ref e) => self.alg_esn = *e,
                                               _ => (),
                                           });
                SCLogDebug!("Selected transforms: {:?}", transforms);
                self.server_transforms.push(transforms);
            } else {
                SCLogDebug!("Proposed transforms: {:?}", transforms);
                self.client_transforms.push(transforms);
            }
        }
    }
}

impl IKEV2Transaction {
    pub fn new(id: u64) -> IKEV2Transaction {
        IKEV2Transaction {
            xid: 0,
            hdr: IkeV2Header {
                init_spi: 0,
                resp_spi: 0,
                next_payload: IkePayloadType::NoNextPayload,
                maj_ver: 0,
                min_ver: 0,
                exch_type: IkeExchangeType(0),
                flags: 0,
                msg_id: 0,
                length: 0,
            },
            payload_types: Vec::new(),
            notify_types: Vec::new(),
            errors: 0,
            id: id,
            de_state: None,
            events: std::ptr::null_mut(),
            logged: applayer::LoggerFlags::new(),
        }
    }

    fn free(&mut self) {
        if self.events != std::ptr::null_mut() {
            core::sc_app_layer_decoder_events_free_events(&mut self.events);
        }
        if let Some(state) = self.de_state {
            core::sc_detect_engine_state_free(state);
        }
    }
}

impl Drop for IKEV2Transaction {
    fn drop(&mut self) {
        self.free();
    }
}

/// Returns *mut IKEV2State
#[no_mangle]
pub extern "C" fn rs_ikev2_state_new() -> *mut std::os::raw::c_void {
    let state = IKEV2State::new();
    let boxed = Box::new(state);
    return unsafe{std::mem::transmute(boxed)};
}

/// Params:
/// - state: *mut IKEV2State as void pointer
#[no_mangle]
pub extern "C" fn rs_ikev2_state_free(state: *mut std::os::raw::c_void) {
    // Just unbox...
    let mut ikev2_state: Box<IKEV2State> = unsafe{std::mem::transmute(state)};
    ikev2_state.free();
}

#[no_mangle]
pub extern "C" fn rs_ikev2_parse_request(_flow: *const core::Flow,
                                       state: *mut std::os::raw::c_void,
                                       _pstate: *mut std::os::raw::c_void,
                                       input: *const u8,
                                       input_len: u32,
                                       _data: *const std::os::raw::c_void,
                                       _flags: u8) -> i32 {
    let buf = build_slice!(input,input_len as usize);
    let state = cast_pointer!(state,IKEV2State);
    state.parse(buf, STREAM_TOSERVER)
}

#[no_mangle]
pub extern "C" fn rs_ikev2_parse_response(_flow: *const core::Flow,
                                       state: *mut std::os::raw::c_void,
                                       pstate: *mut std::os::raw::c_void,
                                       input: *const u8,
                                       input_len: u32,
                                       _data: *const std::os::raw::c_void,
                                       _flags: u8) -> i32 {
    let buf = build_slice!(input,input_len as usize);
    let state = cast_pointer!(state,IKEV2State);
    let res = state.parse(buf, STREAM_TOCLIENT);
    if state.connection_state == IKEV2ConnectionState::ParsingDone {
        unsafe{
            AppLayerParserStateSetFlag(pstate, APP_LAYER_PARSER_NO_INSPECTION |
                                       APP_LAYER_PARSER_NO_REASSEMBLY |
                                       APP_LAYER_PARSER_BYPASS_READY)
        };
    }
    res
}

#[no_mangle]
pub extern "C" fn rs_ikev2_state_get_tx(state: *mut std::os::raw::c_void,
                                      tx_id: u64)
                                      -> *mut std::os::raw::c_void
{
    let state = cast_pointer!(state,IKEV2State);
    match state.get_tx_by_id(tx_id) {
        Some(tx) => unsafe{std::mem::transmute(tx)},
        None     => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn rs_ikev2_state_get_tx_count(state: *mut std::os::raw::c_void)
                                            -> u64
{
    let state = cast_pointer!(state,IKEV2State);
    state.tx_id
}

#[no_mangle]
pub extern "C" fn rs_ikev2_state_tx_free(state: *mut std::os::raw::c_void,
                                       tx_id: u64)
{
    let state = cast_pointer!(state,IKEV2State);
    state.free_tx(tx_id);
}

#[no_mangle]
pub extern "C" fn rs_ikev2_state_progress_completion_status(
    _direction: u8)
    -> std::os::raw::c_int
{
    return 1;
}

#[no_mangle]
pub extern "C" fn rs_ikev2_tx_get_alstate_progress(_tx: *mut std::os::raw::c_void,
                                                 _direction: u8)
                                                 -> std::os::raw::c_int
{
    1
}





#[no_mangle]
pub extern "C" fn rs_ikev2_tx_set_logged(_state: *mut std::os::raw::c_void,
                                       tx: *mut std::os::raw::c_void,
                                       logged: u32)
{
    let tx = cast_pointer!(tx,IKEV2Transaction);
    tx.logged.set(logged);
}

#[no_mangle]
pub extern "C" fn rs_ikev2_tx_get_logged(_state: *mut std::os::raw::c_void,
                                       tx: *mut std::os::raw::c_void)
                                       -> u32
{
    let tx = cast_pointer!(tx,IKEV2Transaction);
    return tx.logged.get();
}


#[no_mangle]
pub extern "C" fn rs_ikev2_state_set_tx_detect_state(
    tx: *mut std::os::raw::c_void,
    de_state: &mut core::DetectEngineState) -> std::os::raw::c_int
{
    let tx = cast_pointer!(tx,IKEV2Transaction);
    tx.de_state = Some(de_state);
    0
}

#[no_mangle]
pub extern "C" fn rs_ikev2_state_get_tx_detect_state(
    tx: *mut std::os::raw::c_void)
    -> *mut core::DetectEngineState
{
    let tx = cast_pointer!(tx,IKEV2Transaction);
    match tx.de_state {
        Some(ds) => ds,
        None => std::ptr::null_mut(),
    }
}


#[no_mangle]
pub extern "C" fn rs_ikev2_state_get_events(tx: *mut std::os::raw::c_void)
                                          -> *mut core::AppLayerDecoderEvents
{
    let tx = cast_pointer!(tx, IKEV2Transaction);
    return tx.events;
}

#[no_mangle]
pub extern "C" fn rs_ikev2_state_get_event_info_by_id(event_id: std::os::raw::c_int,
                                                      event_name: *mut *const std::os::raw::c_char,
                                                      event_type: *mut core::AppLayerEventType)
                                                      -> i8
{
    if let Some(e) = IKEV2Event::from_i32(event_id as i32) {
        let estr = match e {
            IKEV2Event::MalformedData    => { "malformed_data\0" },
            IKEV2Event::NoEncryption     => { "no_encryption\0" },
            IKEV2Event::WeakCryptoEnc    => { "weak_crypto_enc\0" },
            IKEV2Event::WeakCryptoPRF    => { "weak_crypto_prf\0" },
            IKEV2Event::WeakCryptoDH     => { "weak_crypto_dh\0" },
            IKEV2Event::WeakCryptoAuth   => { "weak_crypto_auth\0" },
            IKEV2Event::WeakCryptoNoDH   => { "weak_crypto_nodh\0" },
            IKEV2Event::WeakCryptoNoAuth => { "weak_crypto_noauth\0" },
            IKEV2Event::InvalidProposal  => { "invalid_proposal\0" },
            IKEV2Event::UnknownProposal  => { "unknown_proposal\0" },
        };
        unsafe{
            *event_name = estr.as_ptr() as *const std::os::raw::c_char;
            *event_type = core::APP_LAYER_EVENT_TYPE_TRANSACTION;
        };
        0
    } else {
        -1
    }
}

#[no_mangle]
pub extern "C" fn rs_ikev2_state_get_event_info(event_name: *const std::os::raw::c_char,
                                              event_id: *mut std::os::raw::c_int,
                                              event_type: *mut core::AppLayerEventType)
                                              -> std::os::raw::c_int
{
    if event_name == std::ptr::null() { return -1; }
    let c_event_name: &CStr = unsafe { CStr::from_ptr(event_name) };
    let event = match c_event_name.to_str() {
        Ok(s) => {
            match s {
                "malformed_data"     => IKEV2Event::MalformedData as i32,
                "no_encryption"      => IKEV2Event::NoEncryption as i32,
                "weak_crypto_enc"    => IKEV2Event::WeakCryptoEnc as i32,
                "weak_crypto_prf"    => IKEV2Event::WeakCryptoPRF as i32,
                "weak_crypto_auth"   => IKEV2Event::WeakCryptoAuth as i32,
                "weak_crypto_dh"     => IKEV2Event::WeakCryptoDH as i32,
                "weak_crypto_nodh"   => IKEV2Event::WeakCryptoNoDH as i32,
                "weak_crypto_noauth" => IKEV2Event::WeakCryptoNoAuth as i32,
                "invalid_proposal"   => IKEV2Event::InvalidProposal as i32,
                "unknown_proposal"   => IKEV2Event::UnknownProposal as i32,
                _                    => -1, // unknown event
            }
        },
        Err(_) => -1, // UTF-8 conversion failed
    };
    unsafe{
        *event_type = core::APP_LAYER_EVENT_TYPE_TRANSACTION;
        *event_id = event as std::os::raw::c_int;
    };
    0
}


static mut ALPROTO_IKEV2 : AppProto = ALPROTO_UNKNOWN;

#[no_mangle]
pub extern "C" fn rs_ikev2_probing_parser(_flow: *const Flow,
        _direction: u8,
        input:*const u8, input_len: u32,
        _rdir: *mut u8) -> AppProto
{
    let slice = build_slice!(input,input_len as usize);
    let alproto = unsafe{ ALPROTO_IKEV2 };
    match parse_ikev2_header(slice) {
        Ok((_, ref hdr)) => {
            if hdr.maj_ver != 2 || hdr.min_ver != 0 {
                SCLogDebug!("ipsec_probe: could be ipsec, but with unsupported/invalid version {}.{}",
                        hdr.maj_ver, hdr.min_ver);
                return unsafe{ALPROTO_FAILED};
            }
            if hdr.exch_type.0 < 34 || hdr.exch_type.0 > 37 {
                SCLogDebug!("ipsec_probe: could be ipsec, but with unsupported/invalid exchange type {}",
                       hdr.exch_type.0);
                return unsafe{ALPROTO_FAILED};
            }
            if hdr.length as usize != slice.len() {
                SCLogDebug!("ipsec_probe: could be ipsec, but length does not match");
                return unsafe{ALPROTO_FAILED};
            }
            return alproto;
        },
        Err(nom::Err::Incomplete(_)) => {
            return ALPROTO_UNKNOWN;
        },
        Err(_) => {
            return unsafe{ALPROTO_FAILED};
        },
    }
}

const PARSER_NAME : &'static [u8] = b"ikev2\0";

#[no_mangle]
pub unsafe extern "C" fn rs_register_ikev2_parser() {
    let default_port = CString::new("500").unwrap();
    let parser = RustParser {
        name               : PARSER_NAME.as_ptr() as *const std::os::raw::c_char,
        default_port       : default_port.as_ptr(),
        ipproto            : core::IPPROTO_UDP,
        probe_ts           : rs_ikev2_probing_parser,
        probe_tc           : rs_ikev2_probing_parser,
        min_depth          : 0,
        max_depth          : 16,
        state_new          : rs_ikev2_state_new,
        state_free         : rs_ikev2_state_free,
        tx_free            : rs_ikev2_state_tx_free,
        parse_ts           : rs_ikev2_parse_request,
        parse_tc           : rs_ikev2_parse_response,
        get_tx_count       : rs_ikev2_state_get_tx_count,
        get_tx             : rs_ikev2_state_get_tx,
        tx_get_comp_st     : rs_ikev2_state_progress_completion_status,
        tx_get_progress    : rs_ikev2_tx_get_alstate_progress,
        get_tx_logged      : Some(rs_ikev2_tx_get_logged),
        set_tx_logged      : Some(rs_ikev2_tx_set_logged),
        get_de_state       : rs_ikev2_state_get_tx_detect_state,
        set_de_state       : rs_ikev2_state_set_tx_detect_state,
        get_events         : Some(rs_ikev2_state_get_events),
        get_eventinfo      : Some(rs_ikev2_state_get_event_info),
        get_eventinfo_byid : Some(rs_ikev2_state_get_event_info_by_id),
        localstorage_new   : None,
        localstorage_free  : None,
        get_tx_mpm_id      : None,
        set_tx_mpm_id      : None,
        get_files          : None,
        get_tx_iterator    : None,
    };

    let ip_proto_str = CString::new("udp").unwrap();
    if AppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        // store the allocated ID for the probe function
        ALPROTO_IKEV2 = alproto;
        if AppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
    } else {
        SCLogDebug!("Protocol detector and parser disabled for IKEV2.");
    }
}


#[cfg(test)]
mod tests {
    use super::IKEV2State;

    #[test]
    fn test_ikev2_parse_request_valid() {
        // A UDP IKEV2 v4 request, in client mode
        const REQ : &[u8] = &[
            0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x20, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x18, 0x57, 0xab, 0xc3, 0x4a, 0x5f, 0x2c, 0xfe
        ];

        let mut state = IKEV2State::new();
        assert_eq!(1, state.parse(REQ, 0));
    }
}
