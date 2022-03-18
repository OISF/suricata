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

use nom::{be_u32, rest};
use nom::IResult;

pub const RPC_MAX_MACHINE_SIZE: u32 = 256; // Linux kernel defines 64.
pub const RPC_MAX_CREDS_SIZE: u32 = 4096; // Linux kernel defines 400.
pub const RPC_MAX_VERIFIER_SIZE: u32 = 4096; // Linux kernel defines 400.

#[derive(Debug,PartialEq)]
pub enum RpcRequestCreds<'a> {
    Unix(RpcRequestCredsUnix<'a>),
    GssApi(RpcRequestCredsGssApi<'a>),
    Unknown(&'a[u8]),
}

#[derive(Debug,PartialEq)]
pub struct RpcRequestCredsUnix<'a> {
    pub stamp: u32,
    pub machine_name_len: u32,
    pub machine_name_buf: &'a[u8],
    pub uid: u32,
    pub gid: u32,
    pub aux_gids: Option<Vec<u32>>,
    // list of gids
}

//named!(parse_rpc_creds_unix_aux_gids<Vec<u32>>,
//    many0!(be_u32)
//);

named!(parse_rpc_request_creds_unix<RpcRequestCreds>,
    do_parse!(
        stamp: be_u32
    >>  machine_name_len: verify!(be_u32, |size| size < RPC_MAX_MACHINE_SIZE)
    >>  machine_name_buf: take!(machine_name_len)
    >>  uid: be_u32
    >>  gid: be_u32
    //>>aux_gids: parse_rpc_creds_unix_aux_gids
    >> (RpcRequestCreds::Unix(RpcRequestCredsUnix {
            stamp:stamp,
            machine_name_len:machine_name_len,
            machine_name_buf:machine_name_buf,
            uid:uid,
            gid:gid,
            aux_gids:None,
        }))
));

#[derive(Debug,PartialEq)]
pub struct RpcRequestCredsGssApi<'a> {
    pub version: u32,
    pub procedure: u32,
    pub seq_num: u32,
    pub service: u32,

    pub ctx: &'a[u8],
}

named!(parse_rpc_request_creds_gssapi<RpcRequestCreds>,
    do_parse!(
        version: be_u32
    >>  procedure: be_u32
    >>  seq_num: be_u32
    >>  service: be_u32
    >>  ctx_len: be_u32
    >>  ctx: take!(ctx_len)
    >> (RpcRequestCreds::GssApi(RpcRequestCredsGssApi {
            version: version,
            procedure: procedure,
            seq_num: seq_num,
            service: service,
            ctx: ctx,
        }))
));

named!(parse_rpc_request_creds_unknown<RpcRequestCreds>,
    do_parse!(
        blob: rest
    >> (RpcRequestCreds::Unknown(blob) )
));

#[derive(Debug,PartialEq)]
pub struct RpcGssApiIntegrity<'a> {
    pub seq_num: u32,
    pub data: &'a[u8],
}

// Parse the GSSAPI Integrity envelope to get to the
// data we care about.
named!(pub parse_rpc_gssapi_integrity<RpcGssApiIntegrity>,
    do_parse!(
        len: verify!(be_u32, |size| size < RPC_MAX_CREDS_SIZE)
    >>  seq_num: be_u32
    >>  data: take!(len)
    >> (RpcGssApiIntegrity {
            seq_num: seq_num,
            data: data,
        })
));

#[derive(Debug,PartialEq)]
pub struct RpcPacketHeader<> {
    pub frag_is_last: bool,
    pub frag_len: u32,
    pub xid: u32,
    pub msgtype: u32,
}

named!(pub parse_rpc_packet_header<RpcPacketHeader>,
    do_parse!(
        fraghdr: bits!(tuple!(
                take_bits!(u8, 1),       // is_last
                verify!(take_bits!(u32, 31), |v| v >= 24)))    // len

        >> xid: be_u32
        >> msgtype: verify!(be_u32, |v| v <= 1)
        >> (
            RpcPacketHeader {
                frag_is_last:fraghdr.0 == 1,
                frag_len:fraghdr.1,
                xid:xid,
                msgtype:msgtype,
            }
        ))
);

#[derive(Debug,PartialEq)]
pub struct RpcReplyPacket<'a> {
    pub hdr: RpcPacketHeader<>,

    pub verifier_flavor: u32,
    pub verifier_len: u32,
    pub verifier: Option<&'a[u8]>,

    pub reply_state: u32,
    pub accept_state: u32,

    pub prog_data: &'a[u8],
}

// top of request packet, just to get to procedure
#[derive(Debug)]
pub struct RpcRequestPacketPartial {
    pub hdr: RpcPacketHeader,

    pub rpcver: u32,
    pub program: u32,
    pub progver: u32,
    pub procedure: u32,
}

named!(pub parse_rpc_request_partial<RpcRequestPacketPartial>,
   do_parse!(
       hdr: parse_rpc_packet_header
       >> rpcver: be_u32
       >> program: be_u32
       >> progver: be_u32
       >> procedure: be_u32
       >> (
            RpcRequestPacketPartial {
                hdr:hdr,
                rpcver:rpcver,
                program:program,
                progver:progver,
                procedure:procedure,
            }
          ))
);

#[derive(Debug,PartialEq)]
pub struct RpcPacket<'a> {
    pub hdr: RpcPacketHeader<>,

    pub rpcver: u32,
    pub program: u32,
    pub progver: u32,
    pub procedure: u32,

    pub creds_flavor: u32,
    pub creds: RpcRequestCreds<'a>,

    pub verifier_flavor: u32,
    pub verifier_len: u32,
    pub verifier: &'a[u8],

    pub prog_data: &'a[u8],
}

pub fn parse_rpc(start_i: &[u8]) -> IResult<&[u8], RpcPacket> {
    let (i, hdr) = parse_rpc_packet_header(start_i)?;
    let rec_size = hdr.frag_len as usize + 4;

    let (i, rpcver) = be_u32(i)?;
    let (i, program) = be_u32(i)?;
    let (i, progver) = be_u32(i)?;
    let (i, procedure) = be_u32(i)?;

    let (i, creds_flavor) = be_u32(i)?;
    let (i, creds_len) = verify!(i, be_u32, |size| size < RPC_MAX_CREDS_SIZE)?;
    let (i, creds) = flat_map!(i, take!(creds_len), switch!(value!(creds_flavor),
        1 => call!(parse_rpc_request_creds_unix)    |
        6 => call!(parse_rpc_request_creds_gssapi)  |
        _ => call!(parse_rpc_request_creds_unknown) ))?;

    let (i, verifier_flavor) = be_u32(i)?;
    let (i, verifier_len) = verify!(i, be_u32, |size| size < RPC_MAX_VERIFIER_SIZE)?;
    let (i, verifier) = take!(i, verifier_len as usize)?;

    let consumed = start_i.len() - i.len();
    if consumed > rec_size as usize {
        return Err(nom::Err::Error(error_position!(i, nom::ErrorKind::LengthValue)));
    }

    let (i, prog_data) = rest(i)?;

    Ok((i, RpcPacket {
        hdr,
        rpcver,
        program,
        progver,
        procedure,
        creds_flavor,
        creds,
        verifier_flavor,
        verifier_len,
        verifier,
        prog_data,
    }))
}

// to be called with data <= hdr.frag_len + 4. Sending more data is undefined.
named!(pub parse_rpc_reply<RpcReplyPacket>,
   do_parse!(
       hdr: parse_rpc_packet_header

       >> reply_state: verify!(be_u32, |v| v <= 1)

       >> verifier_flavor: be_u32
       >> verifier_len: verify!(be_u32, |size| size < RPC_MAX_VERIFIER_SIZE)
       >> verifier: cond!(verifier_len > 0, take!(verifier_len as usize))

       >> accept_state: be_u32

       >> pl: rest

       >> (
           RpcReplyPacket {
                hdr:hdr,

                verifier_flavor:verifier_flavor,
                verifier_len:verifier_len,
                verifier:verifier,

                reply_state:reply_state,
                accept_state:accept_state,

                prog_data:pl,
           }
   ))
);

named!(pub parse_rpc_udp_packet_header<RpcPacketHeader>,
    do_parse!(
        xid: be_u32
        >> msgtype: verify!(be_u32, |v| v <= 1)
        >> (
            RpcPacketHeader {
                frag_is_last:false,
                frag_len:0,
                xid:xid,
                msgtype:msgtype,
            }
        ))
);

named!(pub parse_rpc_udp_request<RpcPacket>,
   do_parse!(
       hdr: parse_rpc_udp_packet_header

       >> rpcver: be_u32
       >> program: be_u32
       >> progver: be_u32
       >> procedure: be_u32

       >> creds_flavor: be_u32
       >> creds_len: verify!(be_u32, |size| size < RPC_MAX_CREDS_SIZE)
       >> creds: flat_map!(take!(creds_len), switch!(value!(creds_flavor),
            1 => call!(parse_rpc_request_creds_unix)    |
            6 => call!(parse_rpc_request_creds_gssapi)  |
            _ => call!(parse_rpc_request_creds_unknown) ))

       >> verifier_flavor: be_u32
       >> verifier_len: verify!(be_u32, |size| size < RPC_MAX_VERIFIER_SIZE)
       >> verifier: take!(verifier_len as usize)

       >> pl: rest

       >> (
           RpcPacket {
                hdr:hdr,

                rpcver:rpcver,
                program:program,
                progver:progver,
                procedure:procedure,

                creds_flavor:creds_flavor,
                creds:creds,

                verifier_flavor:verifier_flavor,
                verifier_len:verifier_len,
                verifier:verifier,

                prog_data:pl,
           }
   ))
);

named!(pub parse_rpc_udp_reply<RpcReplyPacket>,
   do_parse!(
       hdr: parse_rpc_udp_packet_header

       >> verifier_flavor: be_u32
       >> verifier_len: verify!(be_u32, |size| size < RPC_MAX_VERIFIER_SIZE)
       >> verifier: cond!(verifier_len > 0, take!(verifier_len as usize))

       >> reply_state: verify!(be_u32, |v| v <= 1)
       >> accept_state: be_u32

       >> pl: rest

       >> (
           RpcReplyPacket {
                hdr:hdr,

                verifier_flavor:verifier_flavor,
                verifier_len:verifier_len,
                verifier:verifier,

                reply_state:reply_state,
                accept_state:accept_state,

                prog_data:pl,
           }
   ))
);

#[cfg(test)]
mod tests {
    use crate::nfs::rpc_records::*;
    use nom::Err::Incomplete;
    use nom::Needed::Size;

    #[test]
    fn test_parse_input_too_short() {
        let buf: &[u8] = &[
            0x80, 0x0, 0x0, 0x9c, 0x8e, 0x28, 0x2, 0x7e
        ];
        let r = parse_rpc_request_partial(buf);
        match r {
            Err(Incomplete(e)) => { assert_eq!(e, Size(4)); },
             _ => { panic!("failed {:?}",r); }
       }
    }
}

