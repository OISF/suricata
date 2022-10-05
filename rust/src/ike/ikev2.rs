/* Copyright (C) 2017-2020 Open Information Security Foundation
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

use crate::applayer::*;
use crate::core::Direction;
use crate::ike::ipsec_parser::*;

use super::ipsec_parser::IkeV2Transform;
use crate::ike::ike::{IKEState, IKETransaction, IkeEvent};
use crate::ike::parser::IsakmpHeader;
use ipsec_parser::{IkeExchangeType, IkePayloadType, IkeV2Header};

#[derive(Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum IKEV2ConnectionState {
    Init,
    InitSASent,
    InitKESent,
    InitNonceSent,
    RespSASent,
    RespKESent,
    RespNonceSent,
    RespCertReqSent,

    ParsingDone,

    Invalid,
}

impl IKEV2ConnectionState {
    pub fn advance(&self, payload: &IkeV2Payload) -> IKEV2ConnectionState {
        use self::IKEV2ConnectionState::*;
        match (self, &payload.content) {
            (&Init, &IkeV2PayloadContent::SA(_)) => InitSASent,
            (&InitSASent, &IkeV2PayloadContent::KE(_)) => InitKESent,
            (&InitKESent, &IkeV2PayloadContent::Nonce(_)) => InitNonceSent,
            (&InitNonceSent, &IkeV2PayloadContent::SA(_)) => RespSASent,
            (&RespSASent, &IkeV2PayloadContent::KE(_)) => RespKESent,
            (&RespKESent, &IkeV2PayloadContent::Nonce(_)) => ParsingDone, // RespNonceSent,
            (&RespNonceSent, &IkeV2PayloadContent::CertificateRequest(_)) => ParsingDone, // RespCertReqSent,
            (&ParsingDone, _) => self.clone(),
            (_, &IkeV2PayloadContent::Notify(_)) => self.clone(),
            (_, &IkeV2PayloadContent::Dummy) => self.clone(),
            (_, _) => Invalid,
        }
    }
}

pub struct Ikev2Container {
    /// The connection state
    pub connection_state: IKEV2ConnectionState,

    /// The transforms proposed by the initiator
    pub client_transforms: Vec<Vec<IkeV2Transform>>,

    /// The encryption algorithm selected by the responder
    pub alg_enc: IkeTransformEncType,
    /// The authentication algorithm selected by the responder
    pub alg_auth: IkeTransformAuthType,
    /// The PRF algorithm selected by the responder
    pub alg_prf: IkeTransformPRFType,
    /// The Diffie-Hellman algorithm selected by the responder
    pub alg_dh: IkeTransformDHType,
    /// The extended sequence numbers parameter selected by the responder
    pub alg_esn: IkeTransformESNType,
    /// The Diffie-Hellman group from the server KE message, if present.
    pub dh_group: IkeTransformDHType,
}

impl Default for Ikev2Container {
    fn default() -> Ikev2Container {
        Ikev2Container {
            connection_state: IKEV2ConnectionState::Init,
            dh_group: IkeTransformDHType::None,
            client_transforms: Vec::new(),
            alg_enc: IkeTransformEncType::ENCR_NULL,
            alg_auth: IkeTransformAuthType::NONE,
            alg_prf: IkeTransformPRFType::PRF_NULL,
            alg_dh: IkeTransformDHType::None,
            alg_esn: IkeTransformESNType::NoESN,
        }
    }
}

pub fn handle_ikev2(
    mut state: &mut IKEState, current: &[u8], isakmp_header: IsakmpHeader, direction: Direction,
) -> AppLayerResult {
    let hdr = IkeV2Header {
        init_spi: isakmp_header.init_spi,
        resp_spi: isakmp_header.resp_spi,
        next_payload: IkePayloadType(isakmp_header.next_payload),
        maj_ver: isakmp_header.maj_ver,
        min_ver: isakmp_header.min_ver,
        exch_type: IkeExchangeType(isakmp_header.exch_type),
        flags: isakmp_header.flags,
        msg_id: isakmp_header.msg_id,
        length: isakmp_header.length,
    };

    let mut tx = state.new_tx();
    tx.ike_version = 2;
    // use init_spi as transaction identifier
    // tx.xid = hdr.init_spi; todo is this used somewhere?
    tx.hdr.ikev2_header = hdr.clone();
    tx.hdr.spi_initiator = format!("{:016x}", isakmp_header.init_spi);
    tx.hdr.spi_responder = format!("{:016x}", isakmp_header.resp_spi);
    tx.hdr.maj_ver = isakmp_header.maj_ver;
    tx.hdr.min_ver = isakmp_header.min_ver;
    tx.hdr.msg_id = isakmp_header.msg_id;
    tx.hdr.flags = isakmp_header.flags;
    let mut payload_types = Vec::new();
    let mut errors = 0;
    let mut notify_types = Vec::new();
    match parse_ikev2_payload_list(current, hdr.next_payload) {
        Ok((_, Ok(ref p))) => {
            for payload in p {
                payload_types.push(payload.hdr.next_payload_type);
                match payload.content {
                    IkeV2PayloadContent::Dummy => (),
                    IkeV2PayloadContent::SA(ref prop) => {
                        // if hdr.flags & IKEV2_FLAG_INITIATOR != 0 {
                        add_proposals(state, &mut tx, prop, direction);
                        // }
                    }
                    IkeV2PayloadContent::KE(ref kex) => {
                        SCLogDebug!("KEX {:?}", kex.dh_group);
                        if direction == Direction::ToClient {
                            state.ikev2_container.dh_group = kex.dh_group;
                        }
                    }
                    IkeV2PayloadContent::Nonce(ref _n) => {
                        SCLogDebug!("Nonce: {:?}", _n);
                    }
                    IkeV2PayloadContent::Notify(ref n) => {
                        SCLogDebug!("Notify: {:?}", n);
                        if n.notify_type.is_error() {
                            errors += 1;
                        }
                        notify_types.push(n.notify_type);
                    }
                    // XXX CertificateRequest
                    // XXX Certificate
                    // XXX Authentication
                    // XXX TSi
                    // XXX TSr
                    // XXX IDr
                    _ => {
                        SCLogDebug!("Unknown payload content {:?}", payload.content);
                    }
                }
                state.ikev2_container.connection_state =
                    state.ikev2_container.connection_state.advance(payload);
                tx.payload_types
                    .ikev2_payload_types
                    .append(&mut payload_types);
                tx.errors = errors;
                tx.notify_types.append(&mut notify_types);
            }
        }
        _e => {
            SCLogDebug!("parse_ikev2_payload_with_type: {:?}", _e);
        }
    }
    state.transactions.push(tx);
    return AppLayerResult::ok();
}

fn add_proposals(
    state: &mut IKEState, tx: &mut IKETransaction, prop: &Vec<IkeV2Proposal>, direction: Direction,
) {
    for p in prop {
        let transforms: Vec<IkeV2Transform> = p.transforms.iter().map(|x| x.into()).collect();
        // Rule 1: warn on weak or unknown transforms
        for xform in &transforms {
            match *xform {
                IkeV2Transform::Encryption(ref enc) => {
                    match *enc {
                        IkeTransformEncType::ENCR_DES_IV64
                        | IkeTransformEncType::ENCR_DES
                        | IkeTransformEncType::ENCR_3DES
                        | IkeTransformEncType::ENCR_RC5
                        | IkeTransformEncType::ENCR_IDEA
                        | IkeTransformEncType::ENCR_CAST
                        | IkeTransformEncType::ENCR_BLOWFISH
                        | IkeTransformEncType::ENCR_3IDEA
                        | IkeTransformEncType::ENCR_DES_IV32
                        | IkeTransformEncType::ENCR_NULL => {
                            SCLogDebug!("Weak Encryption: {:?}", enc);
                            // XXX send event only if direction == Direction::ToClient ?
                            tx.set_event(IkeEvent::WeakCryptoEnc);
                        }
                        _ => (),
                    }
                }
                IkeV2Transform::PRF(ref prf) => match *prf {
                    IkeTransformPRFType::PRF_NULL => {
                        SCLogDebug!("'Null' PRF transform proposed");
                        tx.set_event(IkeEvent::InvalidProposal);
                    }
                    IkeTransformPRFType::PRF_HMAC_MD5 | IkeTransformPRFType::PRF_HMAC_SHA1 => {
                        SCLogDebug!("Weak PRF: {:?}", prf);
                        tx.set_event(IkeEvent::WeakCryptoPrf);
                    }
                    _ => (),
                },
                IkeV2Transform::Auth(ref auth) => {
                    match *auth {
                        IkeTransformAuthType::NONE => {
                            // Note: this could be expected with an AEAD encription alg.
                            // See rule 4
                        }
                        IkeTransformAuthType::AUTH_HMAC_MD5_96
                        | IkeTransformAuthType::AUTH_HMAC_SHA1_96
                        | IkeTransformAuthType::AUTH_DES_MAC
                        | IkeTransformAuthType::AUTH_KPDK_MD5
                        | IkeTransformAuthType::AUTH_AES_XCBC_96
                        | IkeTransformAuthType::AUTH_HMAC_MD5_128
                        | IkeTransformAuthType::AUTH_HMAC_SHA1_160 => {
                            SCLogDebug!("Weak auth: {:?}", auth);
                            tx.set_event(IkeEvent::WeakCryptoAuth);
                        }
                        _ => (),
                    }
                }
                IkeV2Transform::DH(ref dh) => match *dh {
                    IkeTransformDHType::None => {
                        SCLogDebug!("'None' DH transform proposed");
                        tx.set_event(IkeEvent::InvalidProposal);
                    }
                    IkeTransformDHType::Modp768
                    | IkeTransformDHType::Modp1024
                    | IkeTransformDHType::Modp1024s160
                    | IkeTransformDHType::Modp1536 => {
                        SCLogDebug!("Weak DH: {:?}", dh);
                        tx.set_event(IkeEvent::WeakCryptoDh);
                    }
                    _ => (),
                },
                IkeV2Transform::Unknown(_tx_type, _tx_id) => {
                    SCLogDebug!("Unknown proposal: type={:?}, id={}", _tx_type, _tx_id);
                    tx.set_event(IkeEvent::UnknownProposal);
                }
                _ => (),
            }
        }
        // Rule 2: check if no DH was proposed
        if !transforms.iter().any(|x| match *x {
            IkeV2Transform::DH(_) => true,
            _ => false,
        }) {
            SCLogDebug!("No DH transform found");
            tx.set_event(IkeEvent::WeakCryptoNoDh);
        }
        // Rule 3: check if proposing AH ([RFC7296] section 3.3.1)
        if p.protocol_id == ProtocolID::AH {
            SCLogDebug!("Proposal uses protocol AH - no confidentiality");
            tx.set_event(IkeEvent::NoEncryption);
        }
        // Rule 4: lack of integrity is accepted only if using an AEAD proposal
        // Look if no auth was proposed, including if proposal is Auth::None
        if !transforms.iter().any(|x| match *x {
            IkeV2Transform::Auth(IkeTransformAuthType::NONE) => false,
            IkeV2Transform::Auth(_) => true,
            _ => false,
        }) && !transforms.iter().any(|x| match *x {
                IkeV2Transform::Encryption(ref enc) => enc.is_aead(),
                _ => false,
            }) {
            SCLogDebug!("No integrity transform found");
            tx.set_event(IkeEvent::WeakCryptoNoAuth);
        }
        // Finally
        if direction == Direction::ToClient {
            transforms.iter().for_each(|t| match *t {
                IkeV2Transform::Encryption(ref e) => {
                    state.ikev2_container.alg_enc = *e;
                    tx.hdr.ikev2_transforms.push(IkeV2Transform::Encryption(*e));
                }
                IkeV2Transform::Auth(ref a) => {
                    state.ikev2_container.alg_auth = *a;
                    tx.hdr.ikev2_transforms.push(IkeV2Transform::Auth(*a));
                }
                IkeV2Transform::PRF(ref p) => {
                    state.ikev2_container.alg_prf = *p;
                    tx.hdr.ikev2_transforms.push(IkeV2Transform::PRF(*p));
                }
                IkeV2Transform::DH(ref dh) => {
                    state.ikev2_container.alg_dh = *dh;
                    tx.hdr.ikev2_transforms.push(IkeV2Transform::DH(*dh));
                }
                IkeV2Transform::ESN(ref e) => {
                    state.ikev2_container.alg_esn = *e;
                    tx.hdr.ikev2_transforms.push(IkeV2Transform::ESN(*e));
                }
                _ => {}
            });
            SCLogDebug!("Selected transforms: {:?}", transforms);
        } else {
            SCLogDebug!("Proposed transforms: {:?}", transforms);
            state.ikev2_container.client_transforms.push(transforms);
        }
    }
}
