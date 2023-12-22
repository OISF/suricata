/* Copyright (C) 2023 Open Information Security Foundation
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

use nom7::bytes::streaming::take;
use nom7::combinator::cond;
use nom7::number::streaming::{be_u16, be_u32, be_u64, be_u8};
use nom7::IResult;
use suricata_derive::EnumStringU8;

#[derive(Clone, Debug, Default, EnumStringU8)]
#[repr(u8)]
pub enum WebSocketOpcode {
    #[default]
    Continuation = 0,
    Text = 1,
    Binary = 2,
    Ping = 8,
    Pong = 9,
}

#[derive(Clone, Debug, Default)]
pub struct WebSocketPdu {
    pub flags: u8,
    pub fin: bool,
    pub compress: bool,
    pub opcode: u8,
    pub mask: Option<u32>,
    pub payload: Vec<u8>,
    pub to_skip: u64,
}

// cf rfc6455#section-5.2
pub fn parse_message(i: &[u8], max_pl_size: u32) -> IResult<&[u8], WebSocketPdu> {
    let (i, flags_op) = be_u8(i)?;
    let fin = (flags_op & 0x80) != 0;
    let compress = (flags_op & 0x40) != 0;
    let flags = flags_op & 0xF0;
    let opcode = flags_op & 0xF;
    let (i, mask_plen) = be_u8(i)?;
    let mask_flag = (mask_plen & 0x80) != 0;
    let (i, payload_len) = match mask_plen & 0x7F {
        126 => {
            let (i, val) = be_u16(i)?;
            Ok((i, val.into()))
        }
        127 => be_u64(i),
        _ => Ok((i, (mask_plen & 0x7F).into())),
    }?;
    let (i, xormask) = cond(mask_flag, take(4usize))(i)?;
    let mask = if mask_flag {
        let (_, m) = be_u32(xormask.unwrap())?;
        Some(m)
    } else {
        None
    };
    // we limit payload_len to u32, so as to build on 32-bit system
    // where we cannot take(usize) with a u64
    let (to_skip, payload_len) = if payload_len < max_pl_size.into() {
        (0, payload_len as u32)
    } else {
        (payload_len - (max_pl_size as u64), max_pl_size)
    };
    let (i, payload_raw) = take(payload_len)(i)?;
    let mut payload = payload_raw.to_vec();
    if let Some(xorkey) = xormask {
        for i in 0..payload.len() {
            payload[i] ^= xorkey[i % 4];
        }
    }
    Ok((
        i,
        WebSocketPdu {
            flags,
            fin,
            compress,
            opcode,
            mask,
            payload,
            to_skip,
        },
    ))
}
