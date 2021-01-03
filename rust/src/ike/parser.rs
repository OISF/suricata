/* Copyright (C) 2020 Open Information Security Foundation
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

use crate::common::to_hex;
use core::fmt;
use nom::number::streaming::{be_u16, be_u32, be_u64, be_u8};
use nom::*;
use std::collections::HashSet;

// Generic ISAKMP "Container" structs
#[repr(u8)]
#[derive(Copy, Clone, FromPrimitive)]
pub enum ExchangeType {
    None = 0,
    Base = 1,
    IdentityProtection = 2,
    AuthenticationOnly = 3,
    Aggressive = 4,
    Informational = 5,
    Transaction = 6,
    QuickMode = 32,
    NewGroupMode = 33,
}

impl fmt::Display for ExchangeType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ExchangeType::Base => write!(f, "Base"),
            ExchangeType::IdentityProtection => write!(f, "Identity Protection"),
            ExchangeType::AuthenticationOnly => write!(f, "Authentication Only"),
            ExchangeType::Aggressive => write!(f, "Aggressive"),
            ExchangeType::Informational => write!(f, "Informational"),
            ExchangeType::Transaction => write!(f, "Transaction (Config Mode)"),
            ExchangeType::QuickMode => write!(f, "Quick Mode"),
            ExchangeType::NewGroupMode => write!(f, "New Group Mode"),
            _ => write!(f, "Unknown Exchange Type"),
        }
    }
}

pub struct IsakmpHeader {
    pub init_spi: u64,
    pub resp_spi: u64,
    pub next_payload: u8,
    pub maj_ver: u8,
    pub min_ver: u8,
    pub exch_type: u8,
    pub flags: u8,
    pub msg_id: u32,
    pub length: u32,
}

pub struct IsakmpPayloadHeader {
    pub next_payload: u8,
    pub reserved: u8,
    pub payload_length: u16,
}

pub struct IsakmpPayload<'a> {
    pub payload_header: IsakmpPayloadHeader,
    pub data: &'a [u8],
}

// IKEV1 specific payloads

// 1 -> Security Association
pub struct SecurityAssociationPayload<'a> {
    pub domain_of_interpretation: u32,
    pub situation: Option<&'a [u8]>,
    pub data: Option<&'a [u8]>,
}

// 2 -> Proposal
pub struct ProposalPayload<'a> {
    pub proposal_number: u8,
    pub proposal_type: u8,
    pub spi_size: u8,
    pub number_transforms: u8,
    pub spi: &'a [u8],
    pub data: &'a [u8],
}

// 3 -> Transform
pub struct TransformPayload<'a> {
    pub transform_number: u8,
    pub transform_type: u8,
    pub sa_attributes: &'a [u8],
}

// 4 -> Key Exchange
pub struct KeyExchangePayload<'a> {
    pub key_exchange_data: &'a [u8],
}

// 5 -> Identification
// 6 -> Certificate
// 7 -> Certificate Request
// 8 -> Hash
// 9 -> Signature

// 10 -> Nonce
pub struct NoncePayload<'a> {
    pub nonce_data: &'a [u8],
}

// 11 -> Notification
// 12 -> Delete

// 13 -> Vendor ID
pub struct VendorPayload<'a> {
    pub vendor_id: &'a [u8],
}

// Attributes inside Transform
#[derive(Debug, Clone)]
pub enum AttributeType {
    Unknown = 0,
    EncryptionAlgorithm = 1,
    HashAlgorithm = 2,
    AuthenticationMethod = 3,
    GroupDescription = 4,
    GroupType = 5,
    GroupPrime = 6,
    GroupGeneratorOne = 7,
    GroupGeneratorTwo = 8,
    GroupCurveA = 9,
    GroupCurveB = 10,
    LifeType = 11,
    LifeDuration = 12,
    PRF = 13,
    KeyLength = 14,
    FieldSize = 15,
    GroupOrder = 16,
}

impl fmt::Display for AttributeType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AttributeType::EncryptionAlgorithm => write!(f, "alg_enc"),
            AttributeType::HashAlgorithm => write!(f, "alg_hash"),
            AttributeType::AuthenticationMethod => write!(f, "alg_auth"),
            AttributeType::GroupDescription => write!(f, "alg_dh"),
            AttributeType::GroupType => write!(f, "sa_group_type"),
            AttributeType::GroupPrime => write!(f, "sa_group_prime"),
            AttributeType::GroupGeneratorOne => write!(f, "sa_group_generator_one"),
            AttributeType::GroupGeneratorTwo => write!(f, "sa_group_generator_two"),
            AttributeType::GroupCurveA => write!(f, "sa_group_curve_a"),
            AttributeType::GroupCurveB => write!(f, "sa_group_curve_b"),
            AttributeType::LifeType => write!(f, "sa_life_type"),
            AttributeType::LifeDuration => write!(f, "sa_life_duration"),
            AttributeType::PRF => write!(f, "alg_prf"),
            AttributeType::KeyLength => write!(f, "sa_key_length"),
            AttributeType::FieldSize => write!(f, "sa_field_size"),
            AttributeType::GroupOrder => write!(f, "sa_group_order"),
            _ => write!(f, "unknown"),
        }
    }
}

#[derive(Debug, Clone)]
pub enum AttributeValue {
    // https://www.iana.org/assignments/ipsec-registry/ipsec-registry.xhtml
    Unknown,
    // Encryption Algorithm
    EncDesCbc,
    EncIdeaCbc,
    EncBlowfishCbc,
    EncRc5R16B64Cbc,
    EncTripleDesCbc,
    EncCastCbc,
    EncAesCbc,
    EncCamelliaCbc,
    // Hash Algorithm
    HashMd5,
    HashSha,
    HashTiger,
    HashSha2_256,
    HashSha2_384,
    HashSha2_512,
    // Authentication Method
    AuthPreSharedKey,
    AuthDssSignatures,
    AuthRsaSignatures,
    AuthEncryptionWithRsa,
    AuthRevisedEncryptionWithRsa,
    AuthReserved,
    AuthEcdsaSha256,
    AuthEcdsaSha384,
    AuthEcdsaSha512,
    // Group Description
    GroupDefault768BitModp,
    GroupAlternate1024BitModpGroup,
    GroupEc2nOnGp2p155,
    GroupEc2nOnGp2p185,
    GroupModp1536Bit,
    GroupEc2nOverGf2p163,
    GroupEc2nOverGf2p283,
    GroupEc2nOverGf2p409,
    GroupEc2nOverGf2p571,
    GroupModp2048Bit,
    GroupModp3072Bit,
    GroupModp4096Bit,
    GroupModp6144Bit,
    GroupModp8192Bit,
    GroupRandomEcp256,
    GroupRandomEcp384,
    GroupRandomEcp521,
    GroupModp1024With160BitPrime,
    GroupModp2048With224BitPrime,
    GroupModp2048With256BitPrime,
    GroupRandomEcp192,
    GroupRandomEcp224,
    GroupBrainpoolEcp224,
    GroupBrainpoolEcp256,
    GroupBrainpoolEcp384,
    GroupBrainpoolEcp512,
    // Life Type
    LifeTypeSeconds,
    LifeTypeKilobytes,
}

impl fmt::Display for AttributeValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Clone)]
pub struct SaAttribute {
    pub attribute_format: u8,
    pub attribute_type: AttributeType,
    pub attribute_value: AttributeValue,
    pub numeric_value: Option<u32>,
    pub hex_value: Option<String>,
}

named! {pub parse_isakmp_header<IsakmpHeader>,
    do_parse!(
        init_spi: be_u64 >>
        resp_spi: be_u64 >>
        np:       be_u8 >>
        vers: bits!(
            tuple!(take_bits!(4u8),take_bits!(4u8))
        ) >>
        ex:       be_u8 >>
        flags:    be_u8 >>
        id:       be_u32 >>
        l:        be_u32 >>
        (
            IsakmpHeader {
                init_spi,
                resp_spi,
                next_payload: np,
                maj_ver: vers.0,
                min_ver: vers.1,
                exch_type: ex,
                flags,
                msg_id: id,
                length: l,
            }
        )
    )
}

pub fn parse_security_association(i: &[u8]) -> IResult<&[u8], SecurityAssociationPayload> {
    do_parse!(
        i,
        domain_of_interpretation: be_u32
            >> situation: cond!(domain_of_interpretation == 1, take!(4))
            >> data: cond!(
                domain_of_interpretation == 1 && i.len() >= 8,
                take!(i.len() - 8)
            )
            >> (SecurityAssociationPayload {
                domain_of_interpretation,
                situation,
                data
            })
    )
}

pub fn parse_key_exchange(i: &[u8], length: u16) -> IResult<&[u8], KeyExchangePayload> {
    do_parse!(
        i,
        key_exchange_data: take!(length) >> (KeyExchangePayload { key_exchange_data })
    )
}

pub fn parse_proposal(i: &[u8]) -> IResult<&[u8], ProposalPayload> {
    do_parse!(
        i,
        proposal_number: be_u8
            >> proposal_type: be_u8
            >> spi_size: be_u8
            >> number_transforms: be_u8
            >> spi: take!(spi_size)
            >> payload_data:
                cond!(
                    (i.len() as i16 - 4) - spi_size as i16 >= 0,
                    take!((i.len() as u16 - 4) - spi_size as u16)
                )
            >> (ProposalPayload {
                proposal_number,
                proposal_type,
                spi_size,
                number_transforms,
                spi,
                data: if let Some(_data) = payload_data {
                    _data
                } else {
                    b""
                }
            })
    )
}

pub fn parse_transform(i: &[u8], length: u16) -> IResult<&[u8], TransformPayload> {
    do_parse!(
        i,
        transform_number: be_u8
            >> transform_type: be_u8
            >> be_u16
            >> payload_data: cond!(length >= 4, take!(length - 4))
            >> (TransformPayload {
                transform_number,
                transform_type,
                sa_attributes: if let Some(_data) = payload_data {
                    _data
                } else {
                    b""
                }
            })
    )
}

pub fn parse_vendor_id(i: &[u8], length: u16) -> IResult<&[u8], VendorPayload> {
    map!(i, take!(length), |v| VendorPayload { vendor_id: v })
}

fn get_attribute_type(v: u16) -> AttributeType {
    match v {
        1 => AttributeType::EncryptionAlgorithm,
        2 => AttributeType::HashAlgorithm,
        3 => AttributeType::AuthenticationMethod,
        4 => AttributeType::GroupDescription,
        5 => AttributeType::GroupType,
        6 => AttributeType::GroupPrime,
        7 => AttributeType::GroupGeneratorOne,
        8 => AttributeType::GroupGeneratorTwo,
        9 => AttributeType::GroupCurveA,
        10 => AttributeType::GroupCurveB,
        11 => AttributeType::LifeType,
        12 => AttributeType::LifeDuration,
        13 => AttributeType::PRF,
        14 => AttributeType::KeyLength,
        15 => AttributeType::FieldSize,
        16 => AttributeType::GroupOrder,
        _ => AttributeType::Unknown,
    }
}

fn get_encryption_algorithm(v: u16) -> AttributeValue {
    match v {
        1 => AttributeValue::EncDesCbc,
        2 => AttributeValue::EncIdeaCbc,
        3 => AttributeValue::EncBlowfishCbc,
        4 => AttributeValue::EncRc5R16B64Cbc,
        5 => AttributeValue::EncTripleDesCbc,
        6 => AttributeValue::EncCastCbc,
        7 => AttributeValue::EncAesCbc,
        8 => AttributeValue::EncCamelliaCbc,
        _ => AttributeValue::Unknown,
    }
}

fn get_hash_algorithm(v: u16) -> AttributeValue {
    match v {
        1 => AttributeValue::HashMd5,
        2 => AttributeValue::HashSha,
        3 => AttributeValue::HashTiger,
        4 => AttributeValue::HashSha2_256,
        5 => AttributeValue::HashSha2_384,
        6 => AttributeValue::HashSha2_512,
        _ => AttributeValue::Unknown,
    }
}

fn get_authentication_method(v: u16) -> AttributeValue {
    match v {
        1 => AttributeValue::AuthPreSharedKey,
        2 => AttributeValue::AuthDssSignatures,
        3 => AttributeValue::AuthRsaSignatures,
        4 => AttributeValue::AuthEncryptionWithRsa,
        5 => AttributeValue::AuthRevisedEncryptionWithRsa,
        6 => AttributeValue::AuthReserved,
        7 => AttributeValue::AuthReserved,
        8 => AttributeValue::AuthReserved,
        9 => AttributeValue::AuthEcdsaSha256,
        10 => AttributeValue::AuthEcdsaSha384,
        11 => AttributeValue::AuthEcdsaSha512,
        _ => AttributeValue::Unknown,
    }
}

fn get_group_description(v: u16) -> AttributeValue {
    match v {
        1 => AttributeValue::GroupDefault768BitModp,
        2 => AttributeValue::GroupAlternate1024BitModpGroup,
        3 => AttributeValue::GroupEc2nOnGp2p155,
        4 => AttributeValue::GroupEc2nOnGp2p185,
        5 => AttributeValue::GroupModp1536Bit,
        6 => AttributeValue::GroupEc2nOverGf2p163,
        7 => AttributeValue::GroupEc2nOverGf2p163,
        8 => AttributeValue::GroupEc2nOverGf2p283,
        9 => AttributeValue::GroupEc2nOverGf2p283,
        10 => AttributeValue::GroupEc2nOverGf2p409,
        11 => AttributeValue::GroupEc2nOverGf2p409,
        12 => AttributeValue::GroupEc2nOverGf2p571,
        13 => AttributeValue::GroupEc2nOverGf2p571,
        14 => AttributeValue::GroupModp2048Bit,
        15 => AttributeValue::GroupModp3072Bit,
        16 => AttributeValue::GroupModp4096Bit,
        17 => AttributeValue::GroupModp6144Bit,
        18 => AttributeValue::GroupModp8192Bit,
        19 => AttributeValue::GroupRandomEcp256,
        20 => AttributeValue::GroupRandomEcp384,
        21 => AttributeValue::GroupRandomEcp521,
        22 => AttributeValue::GroupModp1024With160BitPrime,
        23 => AttributeValue::GroupModp2048With224BitPrime,
        24 => AttributeValue::GroupModp2048With256BitPrime,
        25 => AttributeValue::GroupRandomEcp192,
        26 => AttributeValue::GroupRandomEcp224,
        27 => AttributeValue::GroupBrainpoolEcp224,
        28 => AttributeValue::GroupBrainpoolEcp256,
        29 => AttributeValue::GroupBrainpoolEcp384,
        30 => AttributeValue::GroupBrainpoolEcp512,
        _ => AttributeValue::Unknown,
    }
}

named! { pub parse_sa_attribute<&[u8], Vec<SaAttribute>>,
    many0!(
        complete!(
            do_parse!(
                format: bits!(tuple!(take_bits!(1u8),take_bits!(15u16))) >>
                attribute_length_or_value: be_u16 >>  // depends on format bit: 1 -> value | 0 -> number of following bytes
                numeric_variable_value: cond!(format.0 == 0 && attribute_length_or_value == 4, be_u32) >>  // interpret as number
                variable_attribute_value: cond!(format.0 == 0 && attribute_length_or_value != 4, take!(attribute_length_or_value)) >>
                (
                    SaAttribute {
                        attribute_format: format.0,
                        attribute_type: get_attribute_type(format.1),
                        attribute_value : match format.1 {
                            1 => get_encryption_algorithm(attribute_length_or_value),
                            2 => get_hash_algorithm(attribute_length_or_value),
                            3 => get_authentication_method(attribute_length_or_value),
                            4 => get_group_description(attribute_length_or_value),
                            11 => match attribute_length_or_value {
                                1 => AttributeValue::LifeTypeSeconds,
                                2 => AttributeValue::LifeTypeKilobytes,
                                _ => AttributeValue::Unknown
                            }
                            _ => AttributeValue::Unknown
                        },
                        numeric_value: match format.0 {
                            1 => Some(attribute_length_or_value as u32),
                            0 => {
                                if let Some(_numeric_variable_value) = numeric_variable_value {
                                    Some(_numeric_variable_value)
                                }
                                else {
                                    None
                                }
                            },
                            _ => None,
                        },
                        hex_value: match format.0 {
                            0 => {
                                if let Some(_variable_attribute_value) = variable_attribute_value {
                                    Some(to_hex(_variable_attribute_value))
                                } else {
                                    None
                                }
                            }
                            _ => None,
                        }
                    }
                )
            )
        )
    )
}

pub fn parse_nonce(i: &[u8], length: u16) -> IResult<&[u8], NoncePayload> {
    map!(i, take!(length), |v| NoncePayload { nonce_data: v })
}

named! { pub parse_ikev1_payload_list<&[u8], Vec<IsakmpPayload>>,
    many0!(
        complete!(
            do_parse!(
                next_payload: be_u8 >>
                reserved: be_u8 >>
                payload_length: be_u16 >>
                payload_data: cond!(payload_length >= 4, take!(payload_length - 4)) >>
                (
                    IsakmpPayload {
                        payload_header: IsakmpPayloadHeader {
                            next_payload,
                            reserved,
                            payload_length
                        },
                        data: if let Some(_data) = payload_data { _data } else { b"" }
                    }
                )
            )
        )
    )
}

#[derive(FromPrimitive, Debug)]
pub enum IsakmpPayloadType {
    None = 0,
    SecurityAssociation = 1,
    Proposal = 2,
    Transform = 3,
    KeyExchange = 4,
    Identification = 5,
    Certificate = 6,
    CertificateRequest = 7,
    Hash = 8,
    Signature = 9,
    Nonce = 10,
    Notification = 11,
    Delete = 12,
    VendorID = 13,
    SaKekPayload = 15,
    SaTekPayload = 16,
    KeyDownload = 17,
    SequenceNumber = 18,
    ProofOfPossession = 19,
    NatDiscovery = 20,
    NatOriginalAddress = 21,
    GroupAssociatedPolicy = 22,
}

impl fmt::Display for IsakmpPayloadType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

pub fn parse_payload<'a>(
    payload_type: u8, data: &'a [u8], data_length: u16, domain_of_interpretation: &mut Option<u32>,
    key_exchange: &mut Vec<u8>, nonce: &mut Vec<u8>, transforms: &mut Vec<Vec<SaAttribute>>,
    vendor_ids: &mut Vec<String>, payload_types: &mut HashSet<u8>,
) -> Result<(), ()> {
    payload_types.insert(payload_type);

    let element = num::FromPrimitive::from_u8(payload_type);
    match element {
        Some(IsakmpPayloadType::SecurityAssociation) => {
            if let Err(_) = parse_security_association_payload(
                data,
                data_length,
                domain_of_interpretation,
                key_exchange,
                nonce,
                transforms,
                vendor_ids,
                payload_types,
            ) {
                SCLogDebug!("Error parsing SecurityAssociation");
                return Err(());
            }
            Ok(())
        }
        Some(IsakmpPayloadType::Proposal) => {
            if let Err(_) = parse_proposal_payload(
                data,
                data_length,
                domain_of_interpretation,
                key_exchange,
                nonce,
                transforms,
                vendor_ids,
                payload_types,
            ) {
                SCLogDebug!("Error parsing Proposal");
                return Err(());
            }
            Ok(())
        }
        Some(IsakmpPayloadType::Transform) => {
            if let Ok((_rem, payload)) = parse_transform(data, data_length) {
                if let Ok((_, attribute_list)) = parse_sa_attribute(payload.sa_attributes) {
                    transforms.push(attribute_list);
                }
            }
            Ok(())
        }
        Some(IsakmpPayloadType::KeyExchange) => {
            let res = parse_key_exchange(data, data_length);
            if let Ok((_rem, payload)) = res {
                *key_exchange = Vec::from(payload.key_exchange_data);
            }
            Ok(())
        }
        Some(IsakmpPayloadType::Nonce) => {
            let res = parse_nonce(data, data_length);
            if let Ok((_rem, payload)) = res {
                *nonce = Vec::from(payload.nonce_data);
            }
            Ok(())
        }
        Some(IsakmpPayloadType::VendorID) => {
            let res = parse_vendor_id(data, data_length);
            if let Ok((_rem, payload)) = res {
                vendor_ids.push(to_hex(payload.vendor_id));
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn parse_proposal_payload<'a>(
    data: &'a [u8], data_length: u16, domain_of_interpretation: &mut Option<u32>,
    key_exchange: &mut Vec<u8>, nonce: &mut Vec<u8>, transforms: &mut Vec<Vec<SaAttribute>>,
    vendor_ids: &mut Vec<String>, payload_types: &mut HashSet<u8>,
) -> Result<(), ()> {
    match parse_proposal(&data[0..data_length as usize]) {
        Ok((_rem, payload)) => {
            let mut cur_payload_type = IsakmpPayloadType::Transform as u8;
            match parse_ikev1_payload_list(payload.data) {
                Ok((_, payload_list)) => {
                    for isakmp_payload in payload_list {
                        if let Err(_) = parse_payload(
                            cur_payload_type,
                            isakmp_payload.data,
                            isakmp_payload.data.len() as u16,
                            domain_of_interpretation,
                            key_exchange,
                            nonce,
                            transforms,
                            vendor_ids,
                            payload_types,
                        ) {
                            SCLogDebug!("Error parsing transform payload");
                            return Err(());
                        }
                        cur_payload_type = isakmp_payload.payload_header.next_payload;
                    }
                    Ok(())
                }
                Err(nom::Err::Incomplete(_)) => {
                    SCLogDebug!("Incomplete data parsing payload list");
                    Err(())
                }
                Err(_) => {
                    SCLogDebug!("Error parsing payload list");
                    Err(())
                }
            }
        }
        Err(nom::Err::Incomplete(_)) => {
            SCLogDebug!("Incomplete data");
            Err(())
        }
        Err(_) => Err(()),
    }
}

fn parse_security_association_payload<'a>(
    data: &'a [u8], data_length: u16, domain_of_interpretation: &mut Option<u32>,
    key_exchange: &mut Vec<u8>, nonce: &mut Vec<u8>, transforms: &mut Vec<Vec<SaAttribute>>,
    vendor_ids: &mut Vec<String>, payload_types: &mut HashSet<u8>,
) -> Result<(), ()> {
    match parse_security_association(&data[0..data_length as usize]) {
        Ok((_rem, payload)) => {
            *domain_of_interpretation = Some(payload.domain_of_interpretation);
            if payload.domain_of_interpretation == 1 {
                // 1 is assigned to IPsec DOI
                let mut cur_payload_type = IsakmpPayloadType::Proposal as u8;
                if let Some(p_data) = payload.data {
                    match parse_ikev1_payload_list(p_data) {
                        Ok((_, payload_list)) => {
                            for isakmp_payload in payload_list {
                                if let Err(_) = parse_payload(
                                    cur_payload_type,
                                    isakmp_payload.data,
                                    isakmp_payload.data.len() as u16,
                                    domain_of_interpretation,
                                    key_exchange,
                                    nonce,
                                    transforms,
                                    vendor_ids,
                                    payload_types,
                                ) {
                                    SCLogDebug!("Error parsing proposal payload");
                                    return Err(());
                                }
                                cur_payload_type = isakmp_payload.payload_header.next_payload;
                            }
                        }
                        Err(nom::Err::Incomplete(_)) => {
                            SCLogDebug!("Incomplete data parsing payload list");
                            return Err(());
                        }
                        Err(_) => {
                            SCLogDebug!("Error parsing payload list");
                            return Err(());
                        }
                    }
                }
            }
            Ok(())
        }
        Err(nom::Err::Incomplete(_)) => {
            SCLogDebug!("Incomplete data");
            Err(())
        }
        Err(_) => Err(()),
    }
}
