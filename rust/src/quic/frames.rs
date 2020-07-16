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

use super::error::QuicError;
use nom::bytes::complete::take;
use nom::number::complete::{be_u16, be_u8, le_u16, le_u32};
use std::convert::TryFrom;
use std::str::FromStr;
use strum_macros::{Display, EnumString};

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

#[derive(Debug, PartialEq, Clone, Copy, Display, EnumString)]
#[strum(serialize_all = "UPPERCASE")]
pub(crate) enum StreamTag {
    Aead,
    Ccrt,
    Ccs,
    Cetv,
    Cfcw,
    Chlo,
    Copt,
    Csct,
    Ctim,
    Icsl,
    Irtt,
    Kexs,
    Mids,
    Mspc,
    Nonc,
    Nonp,
    Pad,
    Pdmd,
    Pubs,
    Scid,
    Scls,
    Sfcw,
    Smhl,
    Sni,
    Sno,
    Stk,
    Tcid,
    Uaid,
    Ver,
    Xlct,
}

#[derive(Debug, PartialEq)]
pub(crate) enum Frame {
    Padding,
    Stream(Stream),
    Unknown(Vec<u8>),
}

fn parse_tag(input: &[u8]) -> Result<(&[u8], StreamTag), QuicError> {
    let (rest, tag) = take(4usize)(input)?;

    let tag_as_str = std::str::from_utf8(tag)
        .map_err(|e| {
            QuicError::Parse(format!(
                "Could not parse stream tag as str: {}",
                e.to_string()
            ))
        })?
        .trim_matches(char::from(0)); // trim null padding

    let tag = StreamTag::from_str(tag_as_str).map_err(|e| {
        QuicError::Parse(format!(
            "Could not match stream tag '{}': {}",
            tag_as_str,
            e.to_string()
        ))
    })?;

    Ok((rest, tag))
}

fn parse_tag_and_offset(input: &[u8]) -> Result<(&[u8], TagOffset), QuicError> {
    let (rest, tag) = parse_tag(input)?;
    let (rest, offset) = le_u32(rest)?;

    Ok((rest, (tag, offset)))
}

fn parse_crypto_stream(input: &[u8]) -> Result<(&[u8], Vec<TagValue>), QuicError> {
    // [message tag][number of tag entries: N][pad][[tag][end offset], ...N][value data]
    let (rest, _message_tag) = parse_tag(input)?;

    let (rest, num_entries) = le_u16(rest)?;
    let (rest, _padding) = take(2usize)(rest)?;

    let mut tags_offset = Vec::new();
    let rest = {
        let mut rest = rest;

        for _i in 0..num_entries {
            let (new_rest, (tag, offset)) = parse_tag_and_offset(rest)?;
            rest = new_rest;

            tags_offset.push((tag, offset));
        }

        rest
    };

    // Convert (Tag, Offset) to (Tag, Value)
    let mut tags = Vec::new();
    let mut previous_offset = 0;
    let mut rest = rest;
    for (tag, offset) in tags_offset {
        let offset = usize::try_from(offset).map_err(|e| {
            QuicError::Parse(format!(
                "Could not convert offset to usize: {}",
                e.to_string()
            ))
        })?;

        if offset < previous_offset {
            // offsets should be increasing
            SCLogDebug!(
                "Invalid packet, offsets not increasing: offset {} previous {}",
                offset,
                previous_offset
            );
            return Err(QuicError::InvalidPacket);
        }

        let value_len = offset - previous_offset;
        let (new_rest, value) = take(value_len)(rest)?;

        previous_offset = offset;
        rest = new_rest;

        tags.push((tag, value.to_vec()))
    }

    Ok((rest, tags))
}

fn parse_stream_frame(input: &[u8], frame_ty: u8) -> Result<(&[u8], Frame), QuicError> {
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

    let stream_id_hdr_length = (frame_ty & 0x03) + 1;

    let (rest, stream_id) = take(usize::from(stream_id_hdr_length))(rest)?;
    let (rest, offset) = take(usize::from(offset_hdr_length))(rest)?;

    let (rest, data_length) = if has_data_length {
        let (rest, data_length) = be_u16(rest)?;

        (rest, usize::from(data_length))
    } else {
        (rest, rest.len())
    };

    let (rest, stream_data) = take(data_length)(rest)?;

    let tags = if let Ok((stream_data_rest, tags)) = parse_crypto_stream(stream_data) {
        if !stream_data_rest.is_empty() {
            // We couldn't parse all the data
            return Err(QuicError::InvalidPacket);
        }

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
    fn decode_frame(input: &[u8]) -> Result<(&[u8], Frame), QuicError> {
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

    pub(crate) fn decode_frames(input: &[u8]) -> Result<Vec<Frame>, QuicError> {
        let mut frames = Vec::new();

        let mut rest = input;
        while !rest.is_empty() {
            let (new_rest, frame) = Frame::decode_frame(rest)?;

            frames.push(frame);
            rest = new_rest;
        }

        Ok(frames)
    }
}
