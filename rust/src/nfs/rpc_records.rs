/* Copyright (C) 2017 Open Information Security Foundation
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

//! Nom parsers for RPC & NFSv3

use nom::{be_u32, rest};

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

named!(pub parse_rfc_request_creds_unix<RpcRequestCredsUnix>,
    do_parse!(
           stamp: be_u32
        >> machine_name_len: be_u32
        >> machine_name_buf: take!(machine_name_len)
        >> uid: be_u32
        >> gid: be_u32
        //>> aux_gids: parse_rpc_creds_unix_aux_gids

        >> (
            RpcRequestCredsUnix {
                stamp:stamp,
                machine_name_len:machine_name_len,
                machine_name_buf:machine_name_buf,
                uid:uid,
                gid:gid,
                aux_gids:None,
            }
        ))
);

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
                take_bits!(u32, 31)))    // len

        >> xid: be_u32
        >> msgtype: be_u32
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
    pub creds_len: u32,
    pub creds: Option<&'a[u8]>,
    pub creds_unix:Option<RpcRequestCredsUnix<'a>>,

    pub verifier_flavor: u32,
    pub verifier_len: u32,
    pub verifier: Option<&'a[u8]>,

    pub prog_data: &'a[u8],
}

named!(pub parse_rpc<RpcPacket>,
   do_parse!(
       hdr: parse_rpc_packet_header

       >> rpcver: be_u32
       >> program: be_u32
       >> progver: be_u32
       >> procedure: be_u32

       >> creds_flavor: be_u32
       >> creds_len: be_u32
       >> creds: cond!(creds_flavor != 1 && creds_len > 0, take!(creds_len as usize))
       >> creds_unix: cond!(creds_len > 0 && creds_flavor == 1, flat_map!(take!((creds_len) as usize),parse_rfc_request_creds_unix))

       >> verifier_flavor: be_u32
       >> verifier_len: be_u32
       >> verifier: cond!(verifier_len > 0, take!(verifier_len as usize))

       >> pl: rest

       >> (
           RpcPacket {
                hdr:hdr,

                rpcver:rpcver,
                program:program,
                progver:progver,
                procedure:procedure,

                creds_flavor:creds_flavor,
                creds_len:creds_len,
                creds:creds,
                creds_unix:creds_unix,

                verifier_flavor:verifier_flavor,
                verifier_len:verifier_len,
                verifier:verifier,

                prog_data:pl,
           }
   ))
);

// to be called with data <= hdr.frag_len + 4. Sending more data is undefined.
named!(pub parse_rpc_reply<RpcReplyPacket>,
   do_parse!(
       hdr: parse_rpc_packet_header

       >> verifier_flavor: be_u32
       >> verifier_len: be_u32
       >> verifier: cond!(verifier_len > 0, take!(verifier_len as usize))

       >> reply_state: be_u32
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
        >> msgtype: be_u32
        >> (
            RpcPacketHeader {
                frag_is_last:false,
                frag_len:0,

                xid:xid,
                msgtype:msgtype,
            }
        ))
);

#[derive(Debug,PartialEq)]
pub struct RpcUdpRequestPacket<'a> {
    pub hdr: RpcPacketHeader<>,

    pub rpcver: u32,
    pub program: u32,
    pub progver: u32,
    pub procedure: u32,

    pub creds_flavor: u32,
    pub creds_len: u32,
    pub creds: Option<&'a[u8]>,
    pub creds_unix:Option<RpcRequestCredsUnix<'a>>,

    pub verifier_flavor: u32,
    pub verifier_len: u32,
    pub verifier: Option<&'a[u8]>,

    pub prog_data: &'a[u8],
}

named!(pub parse_rpc_udp_request<RpcPacket>,
   do_parse!(
       hdr: parse_rpc_udp_packet_header

       >> rpcver: be_u32
       >> program: be_u32
       >> progver: be_u32
       >> procedure: be_u32

       >> creds_flavor: be_u32
       >> creds_len: be_u32
       >> creds: cond!(creds_flavor != 1 && creds_len > 0, take!(creds_len as usize))
       >> creds_unix: cond!(creds_len > 0 && creds_flavor == 1, flat_map!(take!((creds_len) as usize),parse_rfc_request_creds_unix))

       >> verifier_flavor: be_u32
       >> verifier_len: be_u32
       >> verifier: cond!(verifier_len > 0, take!(verifier_len as usize))

       >> pl: rest

       >> (
           RpcPacket {
                hdr:hdr,

                rpcver:rpcver,
                program:program,
                progver:progver,
                procedure:procedure,

                creds_flavor:creds_flavor,
                creds_len:creds_len,
                creds:creds,
                creds_unix:creds_unix,

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
       >> verifier_len: be_u32
       >> verifier: cond!(verifier_len > 0, take!(verifier_len as usize))

       >> reply_state: be_u32
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
