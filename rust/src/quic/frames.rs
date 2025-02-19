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
use super::quic::QUIC_MAX_CRYPTO_FRAG_LEN;
use crate::ja4::*;
use crate::quic::parser::quic_var_uint;
use nom7::bytes::complete::take;
use nom7::combinator::{all_consuming, complete};
use nom7::multi::{count, many0};
use nom7::number::complete::{be_u16, be_u32, be_u8, le_u16, le_u32};
use nom7::sequence::pair;
use nom7::IResult;
use num::FromPrimitive;
use std::fmt;
use tls_parser::TlsMessage::Handshake;
use tls_parser::TlsMessageHandshake::{ClientHello, ServerHello};
use tls_parser::{
    parse_tls_extensions, parse_tls_message_handshake, TlsCipherSuiteID, TlsExtension,
    TlsExtensionType, TlsMessage,
};

/// Tuple of StreamTag and offset
type TagOffset = (StreamTag, u32);

/// Tuple of StreamTag and value
type TagValue = (StreamTag, Vec<u8>);

#[derive(Debug, PartialEq)]
pub(crate) struct Stream {
    pub fin: bool,
    pub stream_id: Vec<u8>,
    pub offset: Vec<u8>,
    pub tags: Option<Vec<TagValue>>,
}

#[repr(u32)]
#[derive(Debug, PartialEq, Clone, Copy, FromPrimitive)]
pub(crate) enum StreamTag {
    Aead = 0x41454144,
    Ccrt = 0x43435254,
    Ccs = 0x43435300,
    Cetv = 0x43455456,
    Cfcw = 0x43464357,
    Chlo = 0x43484c4f,
    Copt = 0x434f5054,
    Csct = 0x43534354,
    Ctim = 0x4354494d,
    Icsl = 0x4943534c,
    Irtt = 0x49525454,
    Kexs = 0x4b455853,
    Mids = 0x4d494453,
    Mspc = 0x4d535043,
    Nonc = 0x4e4f4e43,
    Nonp = 0x4e4f4e50,
    Pad = 0x50414400,
    Pdmd = 0x50444d44,
    Pubs = 0x50554253,
    Scid = 0x53434944,
    Scls = 0x53434c53,
    Sfcw = 0x53464357,
    Smhl = 0x534d484c,
    Sni = 0x534e4900,
    Sno = 0x534e4f00,
    Stk = 0x53544b00,
    Tcid = 0x54434944,
    Uaid = 0x55414944,
    Ver = 0x56455200,
    Xlct = 0x584c4354,
}

impl fmt::Display for StreamTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                StreamTag::Aead => "AEAD",
                StreamTag::Ccrt => "CCRT",
                StreamTag::Ccs => "CCS",
                StreamTag::Cetv => "CETV",
                StreamTag::Cfcw => "CFCW",
                StreamTag::Chlo => "CHLO",
                StreamTag::Copt => "COPT",
                StreamTag::Csct => "CSCT",
                StreamTag::Ctim => "CTIM",
                StreamTag::Icsl => "ICSL",
                StreamTag::Irtt => "IRTT",
                StreamTag::Kexs => "KEXS",
                StreamTag::Mids => "MIDS",
                StreamTag::Mspc => "MSPC",
                StreamTag::Nonc => "NONC",
                StreamTag::Nonp => "NONP",
                StreamTag::Pad => "PAD",
                StreamTag::Pdmd => "PDMD",
                StreamTag::Pubs => "PUBS",
                StreamTag::Scid => "SCID",
                StreamTag::Scls => "SCLS",
                StreamTag::Sfcw => "SFCW",
                StreamTag::Smhl => "SMHL",
                StreamTag::Sni => "SNI",
                StreamTag::Sno => "SNO",
                StreamTag::Stk => "STK",
                StreamTag::Tcid => "TCID",
                StreamTag::Uaid => "UAID",
                StreamTag::Ver => "VER",
                StreamTag::Xlct => "XLCT",
            }
        )
    }
}

#[derive(Debug, PartialEq)]
pub(crate) struct Ack {
    pub largest_acknowledged: u64,
    pub ack_delay: u64,
    pub ack_range_count: u64,
    pub first_ack_range: u64,
}

#[derive(Debug, PartialEq)]
pub(crate) struct Crypto {
    pub ciphers: Vec<TlsCipherSuiteID>,
    // We remap the Vec<TlsExtension> from tls_parser::parse_tls_extensions because of
    // the lifetime of TlsExtension due to references to the slice used for parsing
    pub extv: Vec<QuicTlsExtension>,
    pub ja3: Option<String>,
    pub ja4: Option<JA4>,
}

#[derive(Debug, PartialEq)]
pub(crate) struct CryptoFrag {
    pub offset: u64,
    pub length: u64,
    pub data: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub(crate) enum Frame {
    Padding,
    Ping,
    Ack(Ack),
    // this is more than a crypto frame : it contains a fully parsed tls hello
    Crypto(Crypto),
    // this is a regular quic crypto frame : they can be reassembled
    // in order to parse a tls hello
    CryptoFrag(CryptoFrag),
    Stream(Stream),
    Unknown(Vec<u8>),
}

fn parse_padding_frame(input: &[u8]) -> IResult<&[u8], Frame, QuicError> {
    // nom take_while: cannot infer type for type parameter `Error` declared on the function `take_while`
    let mut offset = 0;
    while offset < input.len() {
        if input[offset] != 0 {
            break;
        }
        offset += 1;
    }
    return Ok((&input[offset..], Frame::Padding));
}

fn parse_ack_frame(input: &[u8]) -> IResult<&[u8], Frame, QuicError> {
    let (rest, largest_acknowledged) = quic_var_uint(input)?;
    let (rest, ack_delay) = quic_var_uint(rest)?;
    let (rest, ack_range_count) = quic_var_uint(rest)?;
    let (mut rest, first_ack_range) = quic_var_uint(rest)?;

    for _ in 0..ack_range_count {
        //RFC9000 section 19.3.1.  ACK Ranges
        let (rest1, _gap) = quic_var_uint(rest)?;
        let (rest1, _ack_range_length) = quic_var_uint(rest1)?;
        rest = rest1;
    }

    Ok((
        rest,
        Frame::Ack(Ack {
            largest_acknowledged,
            ack_delay,
            ack_range_count,
            first_ack_range,
        }),
    ))
}

fn parse_ack3_frame(input: &[u8]) -> IResult<&[u8], Frame, QuicError> {
    let (rest, ack) = parse_ack_frame(input)?;
    let (rest, _ect0_count) = quic_var_uint(rest)?;
    let (rest, _ect1_count) = quic_var_uint(rest)?;
    let (rest, _ecn_count) = quic_var_uint(rest)?;
    Ok((rest, ack))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuicTlsExtension {
    pub etype: TlsExtensionType,
    pub values: Vec<Vec<u8>>,
}

fn quic_tls_ja3_client_extends(ja3: &mut String, exts: Vec<TlsExtension>) {
    ja3.push(',');
    let mut dash = false;
    for e in &exts {
        if let TlsExtension::EllipticCurves(x) = e {
            for ec in x {
                if dash {
                    ja3.push('-');
                } else {
                    dash = true;
                }
                ja3.push_str(&ec.0.to_string());
            }
        }
    }
    ja3.push(',');
    dash = false;
    for e in &exts {
        if let TlsExtension::EcPointFormats(x) = e {
            for ec in *x {
                if dash {
                    ja3.push('-');
                } else {
                    dash = true;
                }
                ja3.push_str(&ec.to_string());
            }
        }
    }
}

// get interesting stuff out of parsed tls extensions
fn quic_get_tls_extensions(
    input: Option<&[u8]>, ja3: &mut String, mut ja4: Option<&mut JA4>, client: bool,
) -> Vec<QuicTlsExtension> {
    let mut extv = Vec::new();
    if let Some(extr) = input {
        if let Ok((_, exts)) = parse_tls_extensions(extr) {
            let mut dash = false;
            for e in &exts {
                let etype = TlsExtensionType::from(e);
                if dash {
                    ja3.push('-');
                } else {
                    dash = true;
                }
                ja3.push_str(&u16::from(etype).to_string());
                if let Some(ref mut ja4) = ja4 {
                    ja4.add_extension(etype)
                }
                let mut values = Vec::new();
                match e {
                    TlsExtension::SupportedVersions(x) => {
                        for version in x {
                            let mut value = Vec::new();
                            value.extend_from_slice(version.to_string().as_bytes());
                            values.push(value);
                            if let Some(ref mut ja4) = ja4 {
                                ja4.set_tls_version(*version);
                            }
                        }
                    }
                    TlsExtension::SNI(x) => {
                        for sni in x {
                            let mut value = Vec::new();
                            value.extend_from_slice(sni.1);
                            values.push(value);
                        }
                    }
                    TlsExtension::SignatureAlgorithms(x) => {
                        for sigalgo in x {
                            let mut value = Vec::new();
                            value.extend_from_slice(sigalgo.to_string().as_bytes());
                            values.push(value);
                            if let Some(ref mut ja4) = ja4 {
                                ja4.add_signature_algorithm(*sigalgo)
                            }
                        }
                    }
                    TlsExtension::ALPN(x) => {
                        if !x.is_empty() {
                            if let Some(ref mut ja4) = ja4 {
                                ja4.set_alpn(x[0]);
                            }
                        }
                        for alpn in x {
                            let mut value = Vec::new();
                            value.extend_from_slice(alpn);
                            values.push(value);
                        }
                    }
                    _ => {}
                }
                extv.push(QuicTlsExtension { etype, values })
            }
            if client {
                quic_tls_ja3_client_extends(ja3, exts);
            }
        }
    }
    return extv;
}

fn parse_quic_handshake(msg: TlsMessage) -> Option<Frame> {
    if let Handshake(hs) = msg {
        match hs {
            ClientHello(ch) => {
                let mut ja3 = String::with_capacity(256);
                ja3.push_str(&u16::from(ch.version).to_string());
                ja3.push(',');
                let mut ja4 = JA4::new();
                ja4.set_quic();
                let mut dash = false;
                for c in &ch.ciphers {
                    if dash {
                        ja3.push('-');
                    } else {
                        dash = true;
                    }
                    ja3.push_str(&u16::from(*c).to_string());
                    ja4.add_cipher_suite(*c);
                }
                ja3.push(',');
                let ciphers = ch.ciphers;
                let extv = quic_get_tls_extensions(ch.ext, &mut ja3, Some(&mut ja4), true);
                return Some(Frame::Crypto(Crypto {
                    ciphers,
                    extv,
                    ja3: if cfg!(feature = "ja3") {
                        Some(ja3)
                    } else {
                        None
                    },
                    ja4: if cfg!(feature = "ja4") {
                        Some(ja4)
                    } else {
                        None
                    },
                }));
            }
            ServerHello(sh) => {
                let mut ja3 = String::with_capacity(256);
                ja3.push_str(&u16::from(sh.version).to_string());
                ja3.push(',');
                ja3.push_str(&u16::from(sh.cipher).to_string());
                ja3.push(',');
                let ciphers = vec![sh.cipher];
                let extv = quic_get_tls_extensions(sh.ext, &mut ja3, None, false);
                return Some(Frame::Crypto(Crypto {
                    ciphers,
                    extv,
                    ja3: if cfg!(feature = "ja3") {
                        Some(ja3)
                    } else {
                        None
                    },
                    ja4: None,
                }));
            }
            _ => {}
        }
    }
    return None;
}

fn parse_crypto_frame(input: &[u8]) -> IResult<&[u8], Frame, QuicError> {
    let (rest, offset) = quic_var_uint(input)?;
    let (rest, length) = quic_var_uint(rest)?;
    let (rest, data) = take(length as usize)(rest)?;

    if offset > 0 {
        return Ok((
            rest,
            Frame::CryptoFrag(CryptoFrag {
                offset,
                length,
                data: data.to_vec(),
            }),
        ));
    }
    // if we have offset 0, try quick path : parse directly
    match parse_tls_message_handshake(data) {
        Ok((_, msg)) => {
            if let Some(c) = parse_quic_handshake(msg) {
                return Ok((rest, c));
            }
        }
        Err(nom7::Err::Incomplete(_)) => {
            // offset 0 but incomplete : save it as a fragment for later reassembly
            return Ok((
                rest,
                Frame::CryptoFrag(CryptoFrag {
                    offset,
                    length,
                    data: data.to_vec(),
                }),
            ));
        }
        _ => {}
    }
    return Err(nom7::Err::Error(QuicError::InvalidPacket));
}

fn parse_tag(input: &[u8]) -> IResult<&[u8], StreamTag, QuicError> {
    let (rest, tag) = be_u32(input)?;

    let tag = StreamTag::from_u32(tag).ok_or(nom7::Err::Error(QuicError::StreamTagNoMatch(tag)))?;

    Ok((rest, tag))
}

fn parse_tag_and_offset(input: &[u8]) -> IResult<&[u8], TagOffset, QuicError> {
    pair(parse_tag, le_u32)(input)
}

fn parse_crypto_stream(input: &[u8]) -> IResult<&[u8], Vec<TagValue>, QuicError> {
    // [message tag][number of tag entries: N][pad][[tag][end offset], ...N][value data]
    let (rest, _message_tag) = parse_tag(input)?;

    let (rest, num_entries) = le_u16(rest)?;
    let (rest, _padding) = take(2usize)(rest)?;

    let (rest, tags_offset) = count(complete(parse_tag_and_offset), num_entries.into())(rest)?;

    // Convert (Tag, Offset) to (Tag, Value)
    let mut tags = Vec::new();
    let mut previous_offset = 0;
    let mut rest = rest;
    for (tag, offset) in tags_offset {
        // offsets should be increasing
        let value_len = offset
            .checked_sub(previous_offset)
            .ok_or(nom7::Err::Error(QuicError::InvalidPacket))?;
        let (new_rest, value) = take(value_len)(rest)?;

        previous_offset = offset;
        rest = new_rest;

        tags.push((tag, value.to_vec()))
    }

    Ok((rest, tags))
}

fn parse_stream_frame(input: &[u8], frame_ty: u8) -> IResult<&[u8], Frame, QuicError> {
    // 0b1_f_d_ooo_ss
    let fin = frame_ty & 0x40 == 0x40;
    let has_data_length = frame_ty & 0x20 == 0x20;

    let offset_hdr_length = {
        let mut offset_length = (frame_ty & 0x1c) >> 2;
        if offset_length != 0 {
            offset_length += 1;
        }
        offset_length
    };

    let stream_id_hdr_length = usize::from((frame_ty & 0x03) + 1);

    let (rest, stream_id) = take(stream_id_hdr_length)(input)?;
    let (rest, offset) = take(offset_hdr_length)(rest)?;

    let (rest, data_length) = if has_data_length {
        let (rest, data_length) = be_u16(rest)?;

        (rest, usize::from(data_length))
    } else {
        (rest, rest.len())
    };

    let (rest, stream_data) = take(data_length)(rest)?;

    let tags = if let Ok((_, tags)) = all_consuming(parse_crypto_stream)(stream_data) {
        Some(tags)
    } else {
        None
    };

    Ok((
        rest,
        Frame::Stream(Stream {
            fin,
            stream_id: stream_id.to_vec(),
            offset: offset.to_vec(),
            tags,
        }),
    ))
}

fn parse_crypto_stream_frame(input: &[u8]) -> IResult<&[u8], Frame, QuicError> {
    let (rest, _offset) = quic_var_uint(input)?;
    let (rest, data_length) = quic_var_uint(rest)?;
    if data_length > u32::MAX as u64 {
        return Err(nom7::Err::Error(QuicError::Unhandled));
    }
    let (rest, stream_data) = take(data_length as u32)(rest)?;

    let tags = if let Ok((_, tags)) = all_consuming(parse_crypto_stream)(stream_data) {
        Some(tags)
    } else {
        None
    };

    Ok((
        rest,
        Frame::Stream(Stream {
            fin: false,
            stream_id: Vec::new(),
            offset: Vec::new(),
            tags,
        }),
    ))
}

impl Frame {
    fn decode_frame(input: &[u8]) -> IResult<&[u8], Frame, QuicError> {
        let (rest, frame_ty) = be_u8(input)?;

        // Special frame types
        let (rest, value) = if frame_ty & 0x80 == 0x80 {
            // STREAM
            parse_stream_frame(rest, frame_ty)?
        } else {
            match frame_ty {
                0x00 => parse_padding_frame(rest)?,
                0x01 => (rest, Frame::Ping),
                0x02 => parse_ack_frame(rest)?,
                0x03 => parse_ack3_frame(rest)?,
                0x06 => parse_crypto_frame(rest)?,
                0x08 => parse_crypto_stream_frame(rest)?,
                _ => ([].as_ref(), Frame::Unknown(rest.to_vec())),
            }
        };

        Ok((rest, value))
    }

    pub(crate) fn decode_frames<'a>(
        input: &'a [u8], past_frag: &'a [u8], past_fraglen: u32,
    ) -> IResult<&'a [u8], Vec<Frame>, QuicError> {
        let (rest, mut frames) = all_consuming(many0(complete(Frame::decode_frame)))(input)?;

        // we use the already seen past fragment data
        let mut crypto_max_size = past_frag.len() as u64;
        let mut crypto_total_size = 0;
        // reassemble crypto fragments : first find total size
        for f in &frames {
            if let Frame::CryptoFrag(c) = f {
                if crypto_max_size < c.offset + c.length {
                    crypto_max_size = c.offset + c.length;
                }
                crypto_total_size += c.length;
            }
        }
        if crypto_max_size > 0 && crypto_max_size < QUIC_MAX_CRYPTO_FRAG_LEN {
            // we have some, and no gaps from offset 0
            let mut d = vec![0; crypto_max_size as usize];
            d[..past_frag.len()].clone_from_slice(past_frag);
            for f in &frames {
                if let Frame::CryptoFrag(c) = f {
                    d[c.offset as usize..(c.offset + c.length) as usize].clone_from_slice(&c.data);
                }
            }
            // check that we have enough data, some new data, and data for the first byte
            if crypto_total_size + past_fraglen as u64 >= crypto_max_size && crypto_total_size > 0 {
                match parse_tls_message_handshake(&d) {
                    Ok((_, msg)) => {
                        if let Some(c) = parse_quic_handshake(msg) {
                            // add a parsed crypto frame
                            frames.push(c);
                        }
                    }
                    Err(nom7::Err::Incomplete(_)) => {
                        // this means the current packet does not have all the hanshake data yet
                        let frag = CryptoFrag {
                            offset: crypto_total_size + past_fraglen as u64,
                            length: d.len() as u64,
                            data: d.to_vec(),
                        };
                        frames.push(Frame::CryptoFrag(frag));
                    }
                    _ => {}
                }
            } else {
                // pass in offset the number of bytes set in data
                let frag = CryptoFrag {
                    offset: crypto_total_size + past_fraglen as u64,
                    length: d.len() as u64,
                    data: d.to_vec(),
                };
                frames.push(Frame::CryptoFrag(frag));
            }
        } else if crypto_max_size >= QUIC_MAX_CRYPTO_FRAG_LEN {
            // just notice the engine that we have a big crypto fragment without supplying data
            let frag = CryptoFrag {
                offset: 0,
                length: crypto_max_size,
                data: Vec::new(),
            };
            frames.push(Frame::CryptoFrag(frag));
        }

        Ok((rest, frames))
    }
}
