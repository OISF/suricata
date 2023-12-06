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
use nom7::number::streaming::{be_u16, be_u64, be_u8};
use nom7::IResult;

#[derive(Clone, Debug, Default)]
pub struct WebSocketsPdu {
    pub fin: bool,
    pub opcode: u8,
    pub mask: bool,
    pub payload: Vec<u8>,
}

// cf rfc6455#section-5.2
pub fn parse_message(i: &[u8]) -> IResult<&[u8], WebSocketsPdu> {
    let (i, fin_op) = be_u8(i)?;
    let fin = (fin_op & 0x80) != 0;
    let opcode = fin_op & 0xF;
    let (i, mask_plen) = be_u8(i)?;
    let mask = (mask_plen & 0x80) != 0;
    let (i, payload_len) = match mask_plen & 0x7F {
        126 => {
            let (i, val) = be_u16(i)?;
            Ok((i, val.into()))
        }
        127 => be_u64(i),
        _ => Ok((i, (mask_plen & 0x7F).into())),
    }?;
    let (i, xormask) = cond(mask, take(4usize))(i)?;
    let (i, payload_raw) = take(payload_len)(i)?;
    let mut payload = payload_raw.to_vec();
    if let Some(xorkey) = xormask {
        for i in 0..payload.len() {
            payload[i] = payload[i] ^ xorkey[i % 4];
        }
    }
    Ok((
        i,
        WebSocketsPdu {
            fin,
            opcode,
            mask,
            payload,
        },
    ))
}
