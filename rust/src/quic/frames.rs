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
use nom::bytes::complete::take;
use nom::combinator::{all_consuming, complete};
use nom::multi::{count, many0};
use nom::number::complete::{be_u16, be_u32, be_u8, le_u16, le_u32};
use nom::sequence::pair;
use nom::IResult;
use num::FromPrimitive;
use std::fmt;

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
pub(crate) enum Frame {
    Padding,
    Stream(Stream),
    Unknown(Vec<u8>),
}

fn parse_tag(input: &[u8]) -> IResult<&[u8], StreamTag, QuicError> {
    let (rest, tag) = be_u32(input)?;

    let tag = StreamTag::from_u32(tag).ok_or(nom::Err::Error(QuicError::StreamTagNoMatch(tag)))?;

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
            .ok_or(nom::Err::Error(QuicError::InvalidPacket))?;
        let (new_rest, value) = take(value_len)(rest)?;

        previous_offset = offset;
        rest = new_rest;

        tags.push((tag, value.to_vec()))
    }

    Ok((rest, tags))
}

fn parse_stream_frame(input: &[u8], frame_ty: u8) -> IResult<&[u8], Frame, QuicError> {
    let rest = input;

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

    let (rest, stream_id) = take(stream_id_hdr_length)(rest)?;
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

impl Frame {
    fn decode_frame(input: &[u8]) -> IResult<&[u8], Frame, QuicError> {
        let (rest, frame_ty) = be_u8(input)?;

        // Special frame types
        let (rest, value) = if frame_ty & 0x80 == 0x80 {
            // STREAM
            parse_stream_frame(rest, frame_ty)?
        } else {
            match frame_ty {
                0x00 => (rest, Frame::Padding),
                _ => ([].as_ref(), Frame::Unknown(rest.to_vec())),
            }
        };

        Ok((rest, value))
    }

    pub(crate) fn decode_frames(input: &[u8]) -> IResult<&[u8], Vec<Frame>, QuicError> {
        let (rest, frames) = many0(complete(Frame::decode_frame))(input)?;

        Ok((rest, frames))
    }
}
