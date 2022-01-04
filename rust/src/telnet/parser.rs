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

use crate::common::nom7::take_until_and_consume;
use nom7::combinator::peek;
use nom7::bytes::complete::take;
use nom7::{IResult};
use nom7::number::streaming::le_u8;
use nom7::bytes::streaming::tag;
use nom7::bytes::streaming::{take_until};

pub fn peek_message_is_ctl(i: &[u8]) -> IResult<&[u8], bool> {
    let (i, v) = peek(le_u8)(i)?;
    Ok((i, v == b'\xff'))
}

pub enum TelnetMessageType<'a> {
    Control(&'a [u8]),
    Data(&'a [u8]),
}

pub fn parse_ctl_suboption<'a>(i: &'a[u8], full: &'a[u8]) -> IResult<&'a[u8], &'a[u8]> {
    let (i, _sc) = le_u8(i)?;
    let tag: &[u8] = b"\xff\xf0";
    let (i, x) = take_until(tag)(i)?;
    let o = &full[..(x.len()+3)];
    Ok((i, o))
}

pub fn parse_ctl_message(oi: &[u8]) -> IResult<&[u8], &[u8]> {
    let (i, _) = tag(b"\xff")(oi)?;
    let (i, cmd) = le_u8(i)?;
    let (i, d) = match cmd {
        251..=254 => take(3_usize)(oi)?,
        240..=249 => take(2_usize)(oi)?,
        250 => parse_ctl_suboption(i, oi)?,
        _ => take(2_usize)(oi)?, // TODO maybe an error or some other special handling
    };
    Ok((i, d))
}

pub fn parse_message(i: &[u8]) -> IResult<&[u8], TelnetMessageType> {
    let (i, v) = peek(le_u8)(i)?;
    if v == b'\xff' {
        let (i, c) = parse_ctl_message(i)?;
        Ok((i, TelnetMessageType::Control(c)))
    } else {
        let (i, t) = take_until_and_consume(b"\n")(i)?;
        Ok((i, TelnetMessageType::Data(t)))
    }
}

// 'login: ', 'Password: ', possibly with leading ctls
pub fn parse_welcome_message(i: &[u8]) -> IResult<&[u8], TelnetMessageType> {
    let (i, v) = peek(le_u8)(i)?;
    if v == b'\xff' {
        let (i, c) = parse_ctl_message(i)?;
        Ok((i, TelnetMessageType::Control(c)))
    } else {
        let (i, t) = take_until_and_consume(b": ")(i)?;
        Ok((i, TelnetMessageType::Data(t)))
    }
}
