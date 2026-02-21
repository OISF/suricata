/* Copyright (C) 2025 Open Information Security Foundation
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

use nom7::{
    bytes::streaming::{tag, take_until},
    number::streaming::{le_u8},
    character::complete::{digit1},
    combinator::map_res,
    IResult,
};
use std;
use std::str;
use std::str::FromStr;
use std::net::IpAddr;

#[derive(Debug, PartialEq, Eq)]
pub struct SSLproxyHeader<> {
    pub ip1: IpAddr,
    pub port1: u16,
    pub ip2: IpAddr,
    pub port2: u16,
    pub ip3: IpAddr,
    pub port3: u16,
    pub opt: u8,
}

// SSLproxy: [127.0.0.1]:44627,[192.168.0.30]:54116,[83.215.238.28]:465,s
pub fn parse_message(i: &[u8]) -> IResult<&[u8], SSLproxyHeader<>> {
    let (i, _hdr) = tag(b"SSLproxy: [")(i)?;
    let (i, body) = take_until("\r\n")(i)?;
    let (x, ip1) = map_res(map_res(take_until("]:"), std::str::from_utf8), IpAddr::from_str,)(body)?;
    let (x, _) = tag(b"]:")(x)?;
    let (x, port1) = map_res(map_res(digit1, str::from_utf8), u16::from_str)(x)?;
    let (x, _) = tag(b",[")(x)?;
    let (x, ip2) = map_res(map_res(take_until("]:"), std::str::from_utf8), IpAddr::from_str,)(x)?;
    let (x, _) = tag(b"]:")(x)?;
    let (x, port2) = map_res(map_res(digit1, str::from_utf8), u16::from_str)(x)?;
    let (x, _) = tag(b",[")(x)?;
    let (x, ip3) = map_res(map_res(take_until("]:"), std::str::from_utf8), IpAddr::from_str,)(x)?;
    let (x, _) = tag(b"]:")(x)?;
    let (x, port3) = map_res(map_res(digit1, str::from_utf8), u16::from_str)(x)?;
    let (x, _) = tag(b",")(x)?;
    let (_, opt) = le_u8(x)?;

    let r = SSLproxyHeader {
        ip1,
        port1,
        ip2,
        port2,
        ip3,
        port3,
        opt,
    };
    Ok((i, r))
}
