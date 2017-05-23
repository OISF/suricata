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

use nom::{be_u32, be_u64, rest};

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
pub struct Nfs3Handle<'a> {
    pub len: u32,
    pub value: &'a[u8],
}

named!(pub parse_nfs3_handle<Nfs3Handle>,
    do_parse!(
        obj_len: be_u32
        >> obj: take!(obj_len)
        >> (
            Nfs3Handle {
                len:obj_len,
                value:obj,
            }
        ))
);

#[derive(Debug,PartialEq)]
pub struct Nfs3ReplyCreate<'a> {
    pub status: u32,
    pub handle: Option<Nfs3Handle<'a>>,
}

named!(pub parse_nfs3_response_create<Nfs3ReplyCreate>,
    do_parse!(
        status: be_u32
        >> handle_has_value: be_u32
        >> handle: cond!(handle_has_value == 1, parse_nfs3_handle)
        >> (
            Nfs3ReplyCreate {
               status:status,
               handle:handle,
            }
        ))
);

#[derive(Debug,PartialEq)]
pub struct Nfs3ReplyLookup<'a> {
    pub status: u32,
    pub handle: Nfs3Handle<'a>,
}

named!(pub parse_nfs3_response_lookup<Nfs3ReplyLookup>,
    do_parse!(
        status: be_u32
        >> handle: parse_nfs3_handle
        >> (
            Nfs3ReplyLookup {
                status:status,
                handle:handle,
            }
        ))
);

#[derive(Debug,PartialEq)]
pub struct Nfs3RequestCreate<'a> {
    pub handle: Nfs3Handle<'a>,
    pub name_len: u32,
    pub create_mode: u32,
    pub verifier: &'a[u8],
    pub name_vec: Vec<u8>,
}

named!(pub parse_nfs3_request_create<Nfs3RequestCreate>,
    do_parse!(
            handle: parse_nfs3_handle
        >>  name_len: be_u32
        >>  name: take!(name_len)
        >>  create_mode: be_u32
        >>  verifier: rest
        >> (
            Nfs3RequestCreate {
                handle:handle,
                name_len:name_len,
                create_mode:create_mode,
                verifier:verifier,
                name_vec:name.to_vec(),
            }
        ))
);

#[derive(Debug,PartialEq)]
pub struct Nfs3RequestRemove<'a> {
    pub handle: Nfs3Handle<'a>,
    pub name_len: u32,
    pub name_vec: Vec<u8>,
}

named!(pub parse_nfs3_request_remove<Nfs3RequestRemove>,
    do_parse!(
            handle: parse_nfs3_handle
        >>  name_len: be_u32
        >>  name: take!(name_len)
        >>  fill_bytes: rest
        >> (
            Nfs3RequestRemove {
                handle:handle,
                name_len:name_len,
                name_vec:name.to_vec(),
            }
        ))
);

#[derive(Debug,PartialEq)]
pub struct Nfs3RequestRename<'a> {
    pub from_handle: Nfs3Handle<'a>,
    pub from_name_vec: Vec<u8>,
    pub to_handle: Nfs3Handle<'a>,
    pub to_name_vec: Vec<u8>,
}

named!(pub parse_nfs3_request_rename<Nfs3RequestRename>,
    do_parse!(
            from_handle: parse_nfs3_handle
        >>  from_name_len: be_u32
        >>  from_name: take!(from_name_len)
        >>  from_fill_bytes: cond!(from_name_len % 4 != 0, take!(4 - from_name_len % 4))
        >>  to_handle: parse_nfs3_handle
        >>  to_name_len: be_u32
        >>  to_name: take!(to_name_len)
        >>  to_fill_bytes: rest
        >> (
            Nfs3RequestRename {
                from_handle:from_handle,
                from_name_vec:from_name.to_vec(),
                to_handle:to_handle,
                to_name_vec:to_name.to_vec(),
            }
        ))
);

#[derive(Debug,PartialEq)]
pub struct Nfs3RequestGetAttr<'a> {
    pub handle: Nfs3Handle<'a>,
}

named!(pub parse_nfs3_request_getattr<Nfs3RequestGetAttr>,
    do_parse!(
            handle: parse_nfs3_handle
        >> (
            Nfs3RequestGetAttr {
                handle:handle,
            }
        ))
);

#[derive(Debug,PartialEq)]
pub struct Nfs3RequestAccess<'a> {
    pub handle: Nfs3Handle<'a>,
    pub check_access: u32,
}

named!(pub parse_nfs3_request_access<Nfs3RequestAccess>,
    do_parse!(
            handle: parse_nfs3_handle
        >>  check_access: be_u32
        >> (
            Nfs3RequestAccess {
                handle:handle,
                check_access:check_access,
            }
        ))
);

#[derive(Debug,PartialEq)]
pub struct Nfs3RequestCommit<'a> {
    pub handle: Nfs3Handle<'a>,
}

named!(pub parse_nfs3_request_commit<Nfs3RequestCommit>,
    do_parse!(
            handle: parse_nfs3_handle
        >>  offset: be_u64
        >>  count: be_u32
        >> (
            Nfs3RequestCommit {
                handle:handle,
            }
        ))
);

#[derive(Debug,PartialEq)]
pub struct Nfs3RequestRead<'a> {
    pub handle: Nfs3Handle<'a>,
    pub offset: u64,
}

named!(pub parse_nfs3_request_read<Nfs3RequestRead>,
    do_parse!(
            handle: parse_nfs3_handle
        >>  offset: be_u64
        >>  count: be_u32
        >> (
            Nfs3RequestRead {
                handle:handle,
                offset:offset,
            }
        ))
);

#[derive(Debug,PartialEq)]
pub struct Nfs3RequestLookup<'a> {
    pub handle: Nfs3Handle<'a>,

    pub name_vec: Vec<u8>,
}

named!(pub parse_nfs3_request_lookup<Nfs3RequestLookup>,
    do_parse!(
            handle: parse_nfs3_handle
        >>  name_len: be_u32
        >>  name_contents: take!(name_len)
        >>  name_padding: rest
        >> (
            Nfs3RequestLookup {
                handle:handle,
                name_vec:name_contents.to_vec(),
            }
        ))
);


#[derive(Debug,PartialEq)]
pub struct Nfs3ResponseReaddirplusEntryC<'a> {
    pub name_vec: Vec<u8>,
    pub handle: Option<Nfs3Handle<'a>>,
}

named!(pub parse_nfs3_response_readdirplus_entry<Nfs3ResponseReaddirplusEntryC>,
    do_parse!(
        file_id: be_u64
        >> name_len: be_u32
        >> name_content: take!(name_len)
        >> fill_bytes: cond!(name_len % 4 != 0, take!(4 - name_len % 4))
        >> cookie: take!(8)
        >> attr_value_follows: be_u32
        >> attr: cond!(attr_value_follows==1, take!(84))
        >> handle_value_follows: be_u32
        >> handle: cond!(handle_value_follows==1, parse_nfs3_handle)
        >> (
                Nfs3ResponseReaddirplusEntryC {
                    name_vec:name_content.to_vec(),
                    handle:handle,
                }
           )
        )
);

#[derive(Debug,PartialEq)]
pub struct Nfs3ResponseReaddirplusEntry<'a> {
    pub entry: Option<Nfs3ResponseReaddirplusEntryC<'a>>,
}

named!(pub parse_nfs3_response_readdirplus_entry_cond<Nfs3ResponseReaddirplusEntry>,
    do_parse!(
        value_follows: be_u32
        >> entry: cond!(value_follows==1, parse_nfs3_response_readdirplus_entry)
        >> (
            Nfs3ResponseReaddirplusEntry {
                entry:entry,
            }
           ))
);

#[derive(Debug,PartialEq)]
pub struct Nfs3ResponseReaddirplus<'a> {
    pub status: u32,
    pub data: &'a[u8],
}

named!(pub parse_nfs3_response_readdirplus<Nfs3ResponseReaddirplus>,
    do_parse!(
        status: be_u32
        >> dir_attr_follows: be_u32
        >> dir_attr: cond!(dir_attr_follows == 1, take!(84))
        >> verifier: take!(8)
        >> data: rest

        >> ( Nfs3ResponseReaddirplus {
                status:status,
                data:data,
        } ))
);

#[derive(Debug,PartialEq)]
pub struct Nfs3RequestReaddirplus<'a> {
    pub handle: Nfs3Handle<'a>,

    pub cookie: u32,
    pub verifier: &'a[u8],
    pub dircount: u32,
    pub maxcount: u32,
}

named!(pub parse_nfs3_request_readdirplus<Nfs3RequestReaddirplus>,
    do_parse!(
            handle: parse_nfs3_handle
        >>  cookie: be_u32
        >>  verifier: take!(8)
        >>  dircount: be_u32
        >>  maxcount: be_u32
        >> (
            Nfs3RequestReaddirplus {
                handle:handle,
                cookie:cookie,
                verifier:verifier,
                dircount:dircount,
                maxcount:maxcount,
            }
        ))
);

#[derive(Debug,PartialEq)]
pub struct Nfs3RequestWrite<'a> {
    pub handle: Nfs3Handle<'a>,

    pub offset: u64,
    pub count: u32,
    pub stable: u32,
    pub file_len: u32,
    pub file_data: &'a[u8],
}

named!(pub parse_nfs3_request_write<Nfs3RequestWrite>,
    do_parse!(
            handle: parse_nfs3_handle
        >>  offset: be_u64
        >>  count: be_u32
        >>  stable: be_u32
        >>  file_len: be_u32
        >>  file_data: rest // likely partial
        >> (
            Nfs3RequestWrite {
                handle:handle,
                offset:offset,
                count:count,
                stable:stable,
                file_len:file_len,
                file_data:file_data,
            }
        ))
);

#[derive(Debug,PartialEq)]
pub struct Nfs3ReplyRead<'a> {
    pub status: u32,
    pub attr_follows: u32,
    pub attr_blob: &'a[u8],
    pub count: u32,
    pub eof: bool,
    pub data_len: u32,
    pub data: &'a[u8], // likely partial
}

named!(pub parse_nfs3_reply_read<Nfs3ReplyRead>,
    do_parse!(
            status: be_u32
        >>  attr_follows: be_u32
        >>  attr_blob: take!(84) // fixed size?
        >>  count: be_u32
        >>  eof: be_u32
        >>  data_len: be_u32
        >>  data_contents: rest
        >> (
            Nfs3ReplyRead {
                status:status,
                attr_follows:attr_follows,
                attr_blob:attr_blob,
                count:count,
                eof:eof != 0,
                data_len:data_len,
                data:data_contents,
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
