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
use super::error::QuicError;
use super::frames::Frame;
use nom7::bytes::complete::take;
use nom7::combinator::{all_consuming, map};
use nom7::number::complete::{be_u24, be_u32, be_u8};
use nom7::IResult;
use std::convert::TryFrom;

/*
   gQUIC is the Google version of QUIC.

   The following docs were referenced when writing this parser

   References:
       - https://docs.google.com/document/d/1WJvyZflAO2pq77yOLbp9NsGjC1CHetAXV8I0fQe-B_U/edit
       - https://docs.google.com/document/d/1g5nIXAIkN_Y-7XJW5K45IblHd_L2f5LTaDUDwvZ5L6g/edit
       - https://www.slideshare.net/shigeki_ohtsu/quic-overview
       - https://tools.ietf.org/html/draft-ietf-quic-transport-17#section-19.8
       - https://github.com/salesforce/GQUIC_Protocol_Analyzer/blob/master/src/gquic-protocol.pac
*/

// List of accepted and tested quic versions format
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct QuicVersion(pub u32);

impl QuicVersion {
    pub const Q039: QuicVersion = QuicVersion(0x51303339);
    pub const Q043: QuicVersion = QuicVersion(0x51303433);
    pub const Q044: QuicVersion = QuicVersion(0x51303434);
    pub const Q045: QuicVersion = QuicVersion(0x51303435);
    pub const Q046: QuicVersion = QuicVersion(0x51303436);

    fn is_gquic(&self) -> bool {
        *self == QuicVersion::Q043
            || *self == QuicVersion::Q044
            || *self == QuicVersion::Q045
            || *self == QuicVersion::Q046
    }
}

impl From<QuicVersion> for String {
    fn from(from: QuicVersion) -> Self {
        match from {
            QuicVersion(0x51303339) => "Q039".to_string(),
            QuicVersion(0x51303433) => "Q043".to_string(),
            QuicVersion(0x51303434) => "Q044".to_string(),
            QuicVersion(0x51303435) => "Q045".to_string(),
            QuicVersion(0x51303436) => "Q046".to_string(),
            QuicVersion(x) => format!("{:x}", x),
        }
    }
}
impl From<QuicVersion> for u32 {
    fn from(from: QuicVersion) -> Self {
        from.0
    }
}

impl From<u32> for QuicVersion {
    fn from(from: u32) -> Self {
        QuicVersion(from)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum QuicType {
    Initial,
    Retry,
    Handshake,
    ZeroRTT,
    VersionNegotiation,
    Short,
}

const QUIC_FLAG_MULTIPATH: u8 = 0x40;
const QUIC_FLAG_DCID_LEN: u8 = 0x8;
const QUIC_FLAG_NONCE: u8 = 0x4;
const QUIC_FLAG_VERSION: u8 = 0x1;

#[derive(Debug, PartialEq, Eq)]
pub struct PublicFlags {
    pub is_long: bool,
    pub raw: u8,
}

impl PublicFlags {
    pub fn new(value: u8) -> Self {
        let is_long = value & 0x80 == 0x80;
        let raw = value;

        PublicFlags { is_long, raw }
    }
}

pub fn quic_pkt_num(input: &[u8]) -> u64 {
    // There must be a more idiomatic way sigh...
    match input.len() {
        1 => {
            input[0] as u64
        }
        2 => {
            ((input[0] as u64) << 8) | (input[1] as u64)
        }
        3 => {
            ((input[0] as u64) << 16) | ((input[1] as u64) << 8) | (input[2] as u64)
        }
        4 => {
            ((input[0] as u64) << 24)
                | ((input[1] as u64) << 16)
                | ((input[2] as u64) << 8)
                | (input[3] as u64)
        }
        _ => {
            // should not be reachable
            debug_validate_fail!("Unexpected length for quic pkt num");
            0
        }
    }
}

pub fn quic_var_uint(input: &[u8]) -> IResult<&[u8], u64, QuicError> {
    let (rest, first) = be_u8(input)?;
    let msb = first >> 6;
    let lsb = (first & 0x3F) as u64;
    match msb {
        3 => {
            // nom does not have be_u56
            let (rest, second) = be_u24(rest)?;
            let (rest, third) = be_u32(rest)?;
            Ok((rest, (lsb << 56) | ((second as u64) << 32) | (third as u64)))
        }
        2 => {
            let (rest, second) = be_u24(rest)?;
            Ok((rest, (lsb << 24) | (second as u64)))
        }
        1 => {
            let (rest, second) = be_u8(rest)?;
            Ok((rest, (lsb << 8) | (second as u64)))
        }
        _ => {
            // only remaining case is msb==0
            Ok((rest, lsb))
        }
    }
}

/// A QUIC packet's header.
#[derive(Debug, PartialEq, Eq)]
pub struct QuicHeader {
    pub flags: PublicFlags,
    pub ty: QuicType,
    pub version: QuicVersion,
    pub version_buf: Vec<u8>,
    pub dcid: Vec<u8>,
    pub scid: Vec<u8>,
    pub length: u16,
}

#[derive(Debug, PartialEq)]
pub(crate) struct QuicData {
    pub frames: Vec<Frame>,
}

impl QuicHeader {
    #[cfg(test)]
    pub(crate) fn new(
        flags: PublicFlags, ty: QuicType, version: QuicVersion, dcid: Vec<u8>, scid: Vec<u8>,
    ) -> Self {
        Self {
            flags,
            ty,
            version,
            version_buf: Vec::new(),
            dcid,
            scid,
            length: 0,
        }
    }

    pub(crate) fn from_bytes(
        input: &[u8], _dcid_len: usize,
    ) -> IResult<&[u8], QuicHeader, QuicError> {
        let (rest, first) = be_u8(input)?;
        let flags = PublicFlags::new(first);

        if !flags.is_long && (flags.raw & QUIC_FLAG_MULTIPATH) == 0 {
            let (mut rest, dcid) = if (flags.raw & QUIC_FLAG_DCID_LEN) != 0 {
                take(8_usize)(rest)?
            } else {
                take(0_usize)(rest)?
            };
            if (flags.raw & QUIC_FLAG_NONCE) != 0 && (flags.raw & QUIC_FLAG_DCID_LEN) == 0 {
                let (rest1, _) = take(32_usize)(rest)?;
                rest = rest1;
            }
            let version_buf: &[u8];
            let version;
            if (flags.raw & QUIC_FLAG_VERSION) != 0 {
                let (_, version_buf1) = take(4_usize)(rest)?;
                let (rest1, version1) = map(be_u32, QuicVersion)(rest)?;
                rest = rest1;
                version = version1;
                version_buf = version_buf1;
            } else {
                version = QuicVersion(0);
                version_buf = &rest[..0];
            }
            let pkt_num_len = 1 + ((flags.raw & 0x30) >> 4);
            let (mut rest, _pkt_num) = take(pkt_num_len)(rest)?;
            if (flags.raw & QUIC_FLAG_DCID_LEN) != 0 {
                let (rest1, _msg_auth_hash) = take(12_usize)(rest)?;
                rest = rest1;
            }
            let ty = if (flags.raw & QUIC_FLAG_VERSION) != 0 {
                QuicType::Initial
            } else {
                QuicType::Short
            };
            if let Ok(plength) = u16::try_from(rest.len()) {
                Ok((
                    rest,
                    QuicHeader {
                        flags,
                        ty,
                        version,
                        version_buf: version_buf.to_vec(),
                        dcid: dcid.to_vec(),
                        scid: Vec::new(),
                        length: plength,
                    },
                ))
            } else {
                Err(nom7::Err::Error(QuicError::InvalidPacket))
            }
        } else if !flags.is_long {
            // Decode short header
            // depends on version let (rest, dcid) = take(_dcid_len)(rest)?;

            if let Ok(plength) = u16::try_from(rest.len()) {
                Ok((
                    rest,
                    QuicHeader {
                        flags,
                        ty: QuicType::Short,
                        version: QuicVersion(0),
                        version_buf: Vec::new(),
                        dcid: Vec::new(),
                        scid: Vec::new(),
                        length: plength,
                    },
                ))
            } else {
                Err(nom7::Err::Error(QuicError::InvalidPacket))
            }
        } else {
            // Decode Long header
            let (_, version_buf) = take(4_usize)(rest)?;
            let (rest, version) = map(be_u32, QuicVersion)(rest)?;

            let ty = if version == QuicVersion(0) {
                QuicType::VersionNegotiation
            } else {
                // Q046 is when they started using IETF
                if version.is_gquic() && version != QuicVersion::Q046 {
                    match first & 0x7f {
                        0x7f => QuicType::Initial,
                        0x7e => QuicType::Retry,
                        0x7d => QuicType::Handshake,
                        0x7c => QuicType::ZeroRTT,
                        _ => {
                            return Err(nom7::Err::Error(QuicError::InvalidPacket));
                        }
                    }
                } else {
                    match (first & 0x30) >> 4 {
                        0x00 => QuicType::Initial,
                        0x01 => QuicType::ZeroRTT,
                        0x02 => QuicType::Handshake,
                        0x03 => QuicType::Retry,
                        _ => {
                            return Err(nom7::Err::Error(QuicError::InvalidPacket));
                        }
                    }
                }
            };

            let (rest, dcid, scid) = if version.is_gquic() {
                // [DCID_LEN (4)][SCID_LEN (4)]
                let (rest, lengths) = be_u8(rest)?;

                let mut dcid_len = (lengths & 0xF0) >> 4;
                let mut scid_len = lengths & 0x0F;

                // Decode dcid length if not 0
                if dcid_len != 0 {
                    dcid_len += 3;
                }

                // Decode scid length if not 0
                if scid_len != 0 {
                    scid_len += 3;
                }

                let (rest, dcid) = take(dcid_len as usize)(rest)?;
                let (rest, scid) = take(scid_len as usize)(rest)?;

                (rest, dcid.to_vec(), scid.to_vec())
            } else {
                let (rest, dcid_len) = be_u8(rest)?;
                let (rest, dcid) = take(dcid_len as usize)(rest)?;

                let (rest, scid_len) = be_u8(rest)?;
                let (rest, scid) = take(scid_len as usize)(rest)?;
                (rest, dcid.to_vec(), scid.to_vec())
            };

            let mut has_length = false;
            let rest = match ty {
                QuicType::Initial => {
                    if version.is_gquic() {
                        let (rest, _pkt_num) = be_u32(rest)?;
                        let (rest, _msg_auth_hash) = take(12usize)(rest)?;

                        rest
                    } else {
                        let (rest, token_length) = quic_var_uint(rest)?;
                        let (rest, _token) = take(token_length as usize)(rest)?;
                        has_length = true;
                        rest
                    }
                }
                _ => rest,
            };
            let (rest, length) = if has_length {
                let (rest2, plength) = quic_var_uint(rest)?;
                if plength > rest2.len() as u64 {
                    return Err(nom7::Err::Error(QuicError::InvalidPacket));
                }
                if let Ok(length) = u16::try_from(plength) {
                    (rest2, length)
                } else {
                    return Err(nom7::Err::Error(QuicError::InvalidPacket));
                }
            } else {
                if let Ok(length) = u16::try_from(rest.len()) {
                    (rest, length)
                } else {
                    return Err(nom7::Err::Error(QuicError::InvalidPacket));
                }
            };

            Ok((
                rest,
                QuicHeader {
                    flags,
                    ty,
                    version,
                    version_buf: version_buf.to_vec(),
                    dcid,
                    scid,
                    length,
                },
            ))
        }
    }
}

impl QuicData {
    pub(crate) fn from_bytes(input: &[u8]) -> Result<QuicData, QuicError> {
        let (_, frames) = all_consuming(Frame::decode_frames)(input)?;
        Ok(QuicData { frames })
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::quic::frames::{Frame, Stream, StreamTag};

    #[test]
    fn public_flags_test() {
        let pf = PublicFlags::new(0xcb);
        assert_eq!(
            PublicFlags {
                is_long: true,
                raw: 0xcb
            },
            pf
        );
    }

    const TEST_DEFAULT_CID_LENGTH: usize = 8;

    #[test]
    fn test_parse_gquic_unknown_version() {
        // Test that we can parse unknown versions
        let data = hex::decode("cbff00001d1091d0b10ac886039973885dfa07c469431409b15e86dd0990aaf906c5de620c4538398ffa58004482d2b19e732fc58818e57cb63569ce11abc00ea4fbac0725c5690a0838c27faf88663b48eca63baf0fba52af4eff7b4117384457c5cf1c1c0e52a1843c7676a4a35cf60c4c179e7186274c121110ace964771f31090f586b283bddbf82e9dd1d6a0e41fbaf243540dfb64f4543e1e87857c77cfc1ee9f883b97b89b6321ce30436119acfdbf2b31f4d0dbac0e5ea740ee59c8619d7c431320504c67f5c3aa9be5192f28ae378e0c8305fb95f01e7cb47c27f92cad7e8d55f699a41df3afe3894939f79e5f164771a6fe987602d975a06bfe8e6906b23601d08bcf2026eac25eca958a7b19ed7ba415e4d31b474264a479c53f01e1d35745ae62a9b148e39e2d7d33176f384d6ce4beb25d2177a8e0fbe5503ea034c9a645e5a8c98098bc5db4e11a351ac72b7079db1a858e11a6c6a4a1f44e1073903029cc08e82c48e6de00f5da7a546db371a4e49d4a213339ca074832cfeb4c39731f98a1683d7fb7db8a5b48c763440d6003fdfadd6a7fb23a62074064aafd585f6a887d5648ce71099d7d21e5cc1e14645f066016a7570d885bde4f239226884ee64fb8ec1218efec83d46ca104d9104bf46637ba3a3d8d6a88967859d60f46198e3a8495f2f211d717c6ca39987d2f4f971b502809932d973736dac67e5e28152c23d844d99fe7a5def822ca97aa433603423ee7fef57e6daa4579bb8f4f14a93663c54db415da5e8b9000d673d99c065c5922ba193eada475f2366b422d42dd86dd3b86fdef67d0e71cd200e3e24b77578f90e0e60717e3a1d6078b836d262028fc73efe7b3684b635f3001225acfd249fbe950dae7c539f015a0ce51c983c4d8e01d7e73e16946e681b2148d0ae4e72fb44d1048eb25572dae0a8016434b8c9e3fd3c93045b8afe67adc6cf7ce61a46819b712a8c24980e6c75bf007adf8910badfa102cd60c96238c8719b5e2b405905cfa6840176c7f71b7d9a2f480c36806f415b93b72821f0547b06f298584be093710a381fa352c34ba221cbcf1bbcd0b7d1aea354e460f6824df14d4bf4377a4503397e70f9993a55905ba298e798d9c69386eae8d0ebf6d871ff75e2d5a546bb8ee6ad9c92d88f950e2d8bc371aaad0d948e9f81c8151c51ee17c9257df4fd27cfeb9944b301a0fff1cb0a1b18836969457edd42f6ba370ecc2e5700bbb9fc15dc9f88c9bfc12c7dda64d423179c1eff8c53cca97056e09a07e29d02b4e553141b78d224cd79ae8056d923d41bc67eec00c943e3a62304487261d0877d54c40b7453c52e6c02141c2fa6601a357d53dddf39ae6e152501813e562a0613ca727ef3b0548c1f5a7e5036a8da84e166cec45de83bf217fb8f6c9a0ea20db0b16d1d2bb9e5e305e9d1f35e3065ab7188f79b9a841d1f6000ea744df1ba49116f7558feedf70677e35985d71b1c87c988d0b1ef2e436a54a77397546513c82bf307fc4b29152cafab11c8527eeda2addd00081c3b7b836a39920322a405c4e3774f20feda9998bf703fd10e93748b7834f3f3794d5b1f3f3099c608e84b025f5675b1526e8feee91ed04f4e91e37bd8e7089ec5a48edc2537bcddbd9d118d7937e2c25fa383186efd2f48fa3f5ebe7eaf544835bb330b61af1a95158c5e").unwrap();
        let (_rest, value) =
            QuicHeader::from_bytes(data.as_ref(), TEST_DEFAULT_CID_LENGTH).unwrap();
        assert_eq!(
            QuicHeader {
                flags: PublicFlags {
                    is_long: true,
                    raw: 0xcb
                },
                ty: QuicType::Initial,
                version: QuicVersion(0xff00001d),
                version_buf: vec![0xff, 0x00, 0x00, 0x1d],
                dcid: hex::decode("91d0b10ac886039973885dfa07c46943")
                    .unwrap()
                    .to_vec(),
                scid: hex::decode("09b15e86dd0990aaf906c5de620c4538398ffa58")
                    .unwrap()
                    .to_vec(),
                length: 1154,
            },
            value
        );
    }

    #[test]
    fn test_parse_gquic_q044() {
        let test_data = hex::decode("ff513034345005cad2cc06c4d0e400000001afac230bc5b56fb89800171b800143484c4f09000000504144008f030000534e490098030000564552009c03000043435300ac03000050444d44b00300004943534cb40300004d494453b803000043464357bc03000053464357c003000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003132372e302e302e310000000001e8816092921ae87eed8086a215829158353039803a09006400000000c0000000800000").unwrap();
        let (rest, header) =
            QuicHeader::from_bytes(test_data.as_ref(), TEST_DEFAULT_CID_LENGTH).unwrap();

        assert_eq!(
            QuicHeader {
                flags: PublicFlags {
                    is_long: true,
                    raw: 0xff
                },
                ty: QuicType::Initial,
                version: QuicVersion::Q044,
                version_buf: vec![0x51, 0x30, 0x34, 0x34],
                dcid: hex::decode("05cad2cc06c4d0e4").unwrap().to_vec(),
                scid: Vec::new(),
                length: 1042,
            },
            header
        );

        let data = QuicData::from_bytes(rest).unwrap();
        assert_eq!(
            QuicData {
                frames: vec![Frame::Stream(Stream {
                    fin: false,
                    stream_id: vec![0x1],
                    offset: vec![],
                    tags: Some(vec![
                        (StreamTag::Pad, [0x0; 911].to_vec()),
                        (
                            StreamTag::Sni,
                            vec![0x31, 0x32, 0x37, 0x2e, 0x30, 0x2e, 0x30, 0x2e, 0x31]
                        ),
                        (StreamTag::Ver, vec![0x0, 0x0, 0x0, 0x0]),
                        (
                            StreamTag::Ccs,
                            vec![
                                0x1, 0xe8, 0x81, 0x60, 0x92, 0x92, 0x1a, 0xe8, 0x7e, 0xed, 0x80,
                                0x86, 0xa2, 0x15, 0x82, 0x91
                            ]
                        ),
                        (StreamTag::Pdmd, vec![0x58, 0x35, 0x30, 0x39]),
                        (StreamTag::Icsl, vec![0x80, 0x3a, 0x9, 0x0]),
                        (StreamTag::Mids, vec![0x64, 0x0, 0x0, 0x0]),
                        (StreamTag::Cfcw, vec![0x0, 0xc0, 0x0, 0x0]),
                        (StreamTag::Sfcw, vec![0x0, 0x80, 0x0, 0x0]),
                    ])
                })]
            },
            data,
        );
    }
}
