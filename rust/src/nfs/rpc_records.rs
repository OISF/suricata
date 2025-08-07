/* Copyright (C) 2017-2022 Open Information Security Foundation
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

//! Nom parsers for RPCv2

use crate::common::nom7::bits;
use nom7::bits::streaming::take as take_bits;
use nom7::bytes::streaming::take;
use nom7::combinator::{cond, verify, rest};
use nom7::multi::length_data;
use nom7::number::streaming::{be_u32};
use nom7::sequence::tuple;
use nom7::error::{make_error, ErrorKind};
use nom7::{IResult, Err};

pub const RPC_MAX_MACHINE_SIZE: u32 = 256; // Linux kernel defines 64.
pub const RPC_MAX_CREDS_SIZE: u32 = 4096; // Linux kernel defines 400.
pub const RPC_MAX_VERIFIER_SIZE: u32 = 4096; // Linux kernel defines 400.

#[derive(Debug, PartialEq, Eq)]
pub enum RpcRequestCreds<'a> {
    Unix(RpcRequestCredsUnix<'a>),
    GssApi(RpcRequestCredsGssApi<'a>),
    Unknown(&'a [u8]),
}

#[derive(Debug, PartialEq, Eq)]
pub struct RpcRequestCredsUnix<'a> {
    pub stamp: u32,
    pub machine_name_len: u32,
    pub machine_name_buf: &'a [u8],
    pub uid: u32,
    pub gid: u32,
    pub aux_gids: Option<Vec<u32>>,
    // list of gids
}

//named!(parse_rpc_creds_unix_aux_gids<Vec<u32>>,
//    many0!(be_u32)
//);

fn parse_rpc_request_creds_unix(i: &[u8]) -> IResult<&[u8], RpcRequestCreds<'_>> {
    let (i, stamp) = be_u32(i)?;
    let (i, machine_name_len) = verify(be_u32, |&size| size < RPC_MAX_MACHINE_SIZE)(i)?;
    let (i, machine_name_buf) = take(machine_name_len as usize)(i)?;
    let (i, uid) = be_u32(i)?;
    let (i, gid) = be_u32(i)?;
    // let (i, aux_gids) = parse_rpc_creds_unix_aux_gids(i)?;
    let creds = RpcRequestCreds::Unix(RpcRequestCredsUnix {
        stamp,
        machine_name_len,
        machine_name_buf,
        uid,
        gid,
        aux_gids: None,
    });
    Ok((i, creds))
}

#[derive(Debug, PartialEq, Eq)]
pub struct RpcRequestCredsGssApi<'a> {
    pub version: u32,
    pub procedure: u32,
    pub seq_num: u32,
    pub service: u32,

    pub ctx: &'a [u8],
}

fn parse_rpc_request_creds_gssapi(i: &[u8]) -> IResult<&[u8], RpcRequestCreds<'_>> {
    let (i, version) = be_u32(i)?;
    let (i, procedure) = be_u32(i)?;
    let (i, seq_num) = be_u32(i)?;
    let (i, service) = be_u32(i)?;
    let (i, ctx) = length_data(be_u32)(i)?;
    let creds = RpcRequestCreds::GssApi(RpcRequestCredsGssApi {
        version,
        procedure,
        seq_num,
        service,
        ctx,
    });
    Ok((i, creds))
}

fn parse_rpc_request_creds_unknown(i: &[u8]) -> IResult<&[u8], RpcRequestCreds<'_>> {
    Ok((&[], RpcRequestCreds::Unknown(i)))
}

#[derive(Debug, PartialEq, Eq)]
pub struct RpcGssApiIntegrity<'a> {
    pub seq_num: u32,
    pub data: &'a [u8],
}

// Parse the GSSAPI Integrity envelope to get to the
// data we care about.
pub fn parse_rpc_gssapi_integrity(i: &[u8]) -> IResult<&[u8], RpcGssApiIntegrity<'_>> {
    let (i, len) = verify(be_u32, |&size| size < RPC_MAX_CREDS_SIZE)(i)?;
    let (i, seq_num) = be_u32(i)?;
    let (i, data) = take(len as usize)(i)?;
    let res = RpcGssApiIntegrity { seq_num, data };
    Ok((i, res))
}

#[derive(Debug, PartialEq, Eq)]
pub struct RpcPacketHeader {
    pub frag_is_last: bool,
    pub frag_len: u32,
    pub xid: u32,
    pub msgtype: u32,
}

fn parse_bits(i: &[u8]) -> IResult<&[u8], (u8, u32)> {
    bits(tuple((
        take_bits(1u8),   // is_last
        take_bits(31u32), // len
    )))(i)
}

pub fn parse_rpc_packet_header(i: &[u8]) -> IResult<&[u8], RpcPacketHeader> {
    let (i, fraghdr) = verify(parse_bits, |v: &(u8,u32)| v.1 >= 24)(i)?;
    let (i, xid) = be_u32(i)?;
    let (i, msgtype) = verify(be_u32, |&v| v <= 1)(i)?;
    let hdr = RpcPacketHeader {
        frag_is_last: fraghdr.0 == 1,
        frag_len: fraghdr.1,
        xid,
        msgtype,
    };
    Ok((i, hdr))
}

#[derive(Debug, PartialEq, Eq)]
pub struct RpcReplyPacket<'a> {
    pub hdr: RpcPacketHeader,

    pub verifier_flavor: u32,
    pub verifier_len: u32,
    pub verifier: Option<&'a [u8]>,

    pub reply_state: u32,
    pub accept_state: u32,

    pub prog_data_size: u32,
    pub prog_data: &'a [u8],
}

// top of request packet, just to get to procedure
#[derive(Debug, PartialEq, Eq)]
pub struct RpcRequestPacketPartial {
    pub hdr: RpcPacketHeader,

    pub rpcver: u32,
    pub program: u32,
    pub progver: u32,
    pub procedure: u32,
}

pub fn parse_rpc_request_partial(i: &[u8]) -> IResult<&[u8], RpcRequestPacketPartial> {
    let (i, hdr) = parse_rpc_packet_header(i)?;
    let (i, rpcver) = be_u32(i)?;
    let (i, program) = be_u32(i)?;
    let (i, progver) = be_u32(i)?;
    let (i, procedure) = be_u32(i)?;
    let req = RpcRequestPacketPartial {
        hdr,
        rpcver,
        program,
        progver,
        procedure,
    };
    Ok((i, req))
}

#[derive(Debug, PartialEq, Eq)]
pub struct RpcPacket<'a> {
    pub hdr: RpcPacketHeader,

    pub rpcver: u32,
    pub program: u32,
    pub progver: u32,
    pub procedure: u32,

    pub creds_flavor: u32,
    pub creds_len: u32,
    pub creds: RpcRequestCreds<'a>,

    pub verifier_flavor: u32,
    pub verifier_len: u32,
    pub verifier: &'a [u8],

    pub prog_data_size: u32,
    pub prog_data: &'a [u8],
}

/// Parse request RPC record.
///
/// Can be called from 2 paths:
///  1. we have all data -> do full parsing
///  2. we have partial data (large records) -> allow partial prog_data parsing
///
/// Arguments:
/// * `complete`: do full parsing, including of `prog_data`
///
pub fn parse_rpc(start_i: &[u8], complete: bool) -> IResult<&[u8], RpcPacket<'_>> {
    let (i, hdr) = parse_rpc_packet_header(start_i)?;
    let rec_size = hdr.frag_len as usize + 4;

    let (i, rpcver) = be_u32(i)?;
    let (i, program) = be_u32(i)?;
    let (i, progver) = be_u32(i)?;
    let (i, procedure) = be_u32(i)?;

    let (i, creds_flavor) = be_u32(i)?;
    let (i, creds_len) = verify(be_u32, |&size| size < RPC_MAX_CREDS_SIZE)(i)?;
    let (i, creds_buf) = take(creds_len as usize)(i)?;
    let (_, creds) = match creds_flavor {
        1 => parse_rpc_request_creds_unix(creds_buf)?,
        6 => parse_rpc_request_creds_gssapi(creds_buf)?,
        _ => parse_rpc_request_creds_unknown(creds_buf)?,
    };

    let (i, verifier_flavor) = be_u32(i)?;
    let (i, verifier_len) = verify(be_u32, |&size| size < RPC_MAX_VERIFIER_SIZE)(i)?;
    let (i, verifier) = take(verifier_len as usize)(i)?;

    let consumed = start_i.len() - i.len();
    if consumed > rec_size {
        return Err(Err::Error(make_error(i, ErrorKind::LengthValue)));
    }

    let data_size : u32 = (rec_size - consumed) as u32;
    let (i, prog_data) = if !complete {
        rest(i)?
    } else {
        take(data_size)(i)?
    };

    let packet = RpcPacket {
        hdr,

        rpcver,
        program,
        progver,
        procedure,

        creds_flavor,
        creds_len,
        creds,

        verifier_flavor,
        verifier_len,
        verifier,

        prog_data_size: data_size,
        prog_data,
    };
    Ok((i, packet))
}

/// Parse reply RPC record.
///
/// Can be called from 2 paths:
///  1. we have all data -> do full parsing
///  2. we have partial data (large records) -> allow partial prog_data parsing
///
/// Arguments:
/// * `complete`: do full parsing, including of `prog_data`
///
pub fn parse_rpc_reply(start_i: &[u8], complete: bool) -> IResult<&[u8], RpcReplyPacket<'_>> {
    let (i, hdr) = parse_rpc_packet_header(start_i)?;
    let rec_size = hdr.frag_len + 4;

    let (i, reply_state) = verify(be_u32, |&v| v <= 1)(i)?;

    let (i, verifier_flavor) = be_u32(i)?;
    let (i, verifier_len) = verify(be_u32, |&size| size < RPC_MAX_VERIFIER_SIZE)(i)?;
    let (i, verifier) = cond(verifier_len > 0, take(verifier_len as usize))(i)?;

    let (i, accept_state) = be_u32(i)?;

    let consumed = start_i.len() - i.len();
    if consumed > rec_size as usize {
        return Err(Err::Error(make_error(i, ErrorKind::LengthValue)));
    }

    let data_size : u32 = (rec_size as usize - consumed) as u32;
    let (i, prog_data) = if !complete {
        rest(i)?
    } else {
        take(data_size)(i)?
    };
    let packet = RpcReplyPacket {
        hdr,

        verifier_flavor,
        verifier_len,
        verifier,

        reply_state,
        accept_state,

        prog_data_size: data_size,
        prog_data,
    };
    Ok((i, packet))
}

pub fn parse_rpc_udp_packet_header(i: &[u8]) -> IResult<&[u8], RpcPacketHeader> {
    let (i, xid) = be_u32(i)?;
    let (i, msgtype) = verify(be_u32, |&v| v <= 1)(i)?;
    let hdr = RpcPacketHeader {
        frag_is_last: false,
        frag_len: 0,

        xid,
        msgtype,
    };
    Ok((i, hdr))
}

pub fn parse_rpc_udp_request(i: &[u8]) -> IResult<&[u8], RpcPacket<'_>> {
    let (i, hdr) = parse_rpc_udp_packet_header(i)?;

    let (i, rpcver) = be_u32(i)?;
    let (i, program) = be_u32(i)?;
    let (i, progver) = be_u32(i)?;
    let (i, procedure) = be_u32(i)?;

    let (i, creds_flavor) = be_u32(i)?;
    let (i, creds_len) = verify(be_u32, |&size| size < RPC_MAX_CREDS_SIZE)(i)?;
    let (i, creds_buf) = take(creds_len as usize)(i)?;
    let (_, creds) = match creds_flavor {
        1 => parse_rpc_request_creds_unix(creds_buf)?,
        6 => parse_rpc_request_creds_gssapi(creds_buf)?,
        _ => parse_rpc_request_creds_unknown(creds_buf)?,
    };

    let (i, verifier_flavor) = be_u32(i)?;
    let (i, verifier_len) = verify(be_u32, |&size| size < RPC_MAX_VERIFIER_SIZE)(i)?;
    let (i, verifier) = take(verifier_len as usize)(i)?;

    let data_size : u32 = i.len() as u32;
    let (i, prog_data) = rest(i)?;
    let packet = RpcPacket {
        hdr,

        rpcver,
        program,
        progver,
        procedure,

        creds_flavor,
        creds_len,
        creds,

        verifier_flavor,
        verifier_len,
        verifier,

        prog_data_size: data_size,
        prog_data,
    };
    Ok((i, packet))
}

pub fn parse_rpc_udp_reply(i: &[u8]) -> IResult<&[u8], RpcReplyPacket<'_>> {
    let (i, hdr) = parse_rpc_udp_packet_header(i)?;

    let (i, verifier_flavor) = be_u32(i)?;
    let (i, verifier_len) = verify(be_u32, |&size| size < RPC_MAX_VERIFIER_SIZE)(i)?;
    let (i, verifier) = cond(verifier_len > 0, take(verifier_len as usize))(i)?;

    let (i, reply_state) = verify(be_u32, |&v| v <= 1)(i)?;
    let (i, accept_state) = be_u32(i)?;

    let data_size : u32 = i.len() as u32;
    let (i, prog_data) = rest(i)?;
    let packet = RpcReplyPacket {
        hdr,

        verifier_flavor,
        verifier_len,
        verifier,

        reply_state,
        accept_state,

        prog_data_size: data_size,
        prog_data,
    };
    Ok((i, packet))
}

#[cfg(test)]
mod tests {
    use crate::nfs::rpc_records::*;
    use nom7::Err::Incomplete;
    use nom7::Needed;

    #[test]
    fn test_partial_input_too_short() {
        let buf: &[u8] = &[
            0x80, 0x00, 0x00, 0x9c, // flags
            0x8e, 0x28, 0x02, 0x7e  // xid
        ];

        let r = parse_rpc_request_partial(buf);
        match r {
            Err(Incomplete(s)) => { assert_eq!(s, Needed::new(4)); },
            _ => { panic!("failed {:?}",r); }
        }
    }
    #[test]
    fn test_partial_input_ok() {
        let buf: &[u8] = &[
            0x80, 0x00, 0x00, 0x9c, // flags
            0x8e, 0x28, 0x02, 0x7e, // xid
            0x00, 0x00, 0x00, 0x01, // msgtype
            0x00, 0x00, 0x00, 0x02, // rpcver
            0x00, 0x00, 0x00, 0x03, // program
            0x00, 0x00, 0x00, 0x04, // progver
            0x00, 0x00, 0x00, 0x05, // procedure
        ];
        let expected = RpcRequestPacketPartial {
            hdr: RpcPacketHeader {
                    frag_is_last: true,
                    frag_len: 156,
                    xid: 2384986750,
                    msgtype: 1
                },
            rpcver: 2,
            program: 3,
            progver: 4,
            procedure: 5
        };
        let r = parse_rpc_request_partial(buf);
        match r {
            Ok((rem, hdr)) => {
                assert_eq!(rem.len(), 0);
                assert_eq!(hdr, expected);
            },
            _ => { panic!("failed {:?}",r); }
        }
    }
}
