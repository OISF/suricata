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

use nom;
use nom::{rest, le_u8, le_u16, le_u32, le_u64, IResult};
use smb::smb::*;

#[derive(Debug,PartialEq)]
pub struct Smb2SecBlobRecord<'a> {
    pub data: &'a[u8],
}

named!(pub parse_smb2_sec_blob<Smb2SecBlobRecord>,
    do_parse!(
         data: rest
         >> ( Smb2SecBlobRecord {
                data: data,
            })
));

#[derive(Debug,PartialEq)]
pub struct Smb2RecordDir<> {
    pub request: bool,
}

named!(pub parse_smb2_record_direction<Smb2RecordDir>,
    do_parse!(
            _server_component: tag!(b"\xfeSMB")
        >>  _skip: take!(12)
        >>  flags: le_u8
        >> (Smb2RecordDir {
                request: flags & 0x01 == 0,
           })
));

#[derive(Debug,PartialEq)]
pub struct Smb2Record<'a> {
    pub direction: u8,    // 0 req, 1 res
    pub nt_status: u32,
    pub command: u16,
    pub message_id: u64,
    pub tree_id: u32,
    pub async_id: u64,
    pub session_id: u64,
    pub data: &'a[u8],
}

impl<'a> Smb2Record<'a> {
    pub fn is_async(&self) -> bool {
        self.async_id != 0
    }
}

named!(pub parse_smb2_request_record<Smb2Record>,
    do_parse!(
            _server_component: tag!(b"\xfeSMB")
        >>  hlen: le_u16
        >>  _credit_charge: le_u16
        >>  _channel_seq: le_u16
        >>  _reserved: take!(2)
        >>  command: le_u16
        >>  _credits_requested: le_u16
        >>  flags: bits!(tuple!(
                take_bits!(u8, 2),      // reserved / unused
                take_bits!(u8, 1),      // replay op
                take_bits!(u8, 1),      // dfs op
                take_bits!(u32, 24),    // reserved / unused
                take_bits!(u8, 1),      // signing
                take_bits!(u8, 1),      // chained
                take_bits!(u8, 1),      // async
                take_bits!(u8, 1)       // response
            ))
        >> chain_offset: le_u32
        >> message_id: le_u64
        >> _process_id: le_u32
        >> tree_id: le_u32
        >> session_id: le_u64
        >> _signature: take!(16)
        // there is probably a cleaner way to do this
        >> data_c: cond!(chain_offset > hlen as u32, take!(chain_offset - hlen as u32))
        >> data_r: cond!(chain_offset <= hlen as u32, rest)
        >> (Smb2Record {
                direction: flags.7,
                nt_status: 0,
                command:command,
                message_id: message_id,
                tree_id: tree_id,
                async_id: 0,
                session_id: session_id,
                data: if data_c != None { data_c.unwrap() } else { data_r.unwrap() }
           })
));

#[derive(Debug,PartialEq)]
pub struct Smb2NegotiateProtocolRequestRecord<'a> {
    pub dialects_vec: Vec<u16>,
    pub client_guid: &'a[u8],
}

named!(pub parse_smb2_request_negotiate_protocol<Smb2NegotiateProtocolRequestRecord>,
    do_parse!(
            _struct_size: take!(2)
        >>  dialects_count: le_u16
        >>  _sec_mode: le_u16
        >>  _reserved1: le_u16
        >>  _capabilities: le_u32
        >>  client_guid: take!(16)
        >>  _ctx_offset: le_u32
        >>  _ctx_cnt: le_u16
        >>  _reserved2: le_u16
        >>  dia_vec: count!(le_u16, dialects_count as usize)
        >>  (Smb2NegotiateProtocolRequestRecord {
                dialects_vec: dia_vec,
                client_guid: client_guid,
            })
));

#[derive(Debug,PartialEq)]
pub struct Smb2NegotiateProtocolResponseRecord<'a> {
    pub dialect: u16,
    pub server_guid: &'a[u8],
}

named!(pub parse_smb2_response_negotiate_protocol<Smb2NegotiateProtocolResponseRecord>,
    do_parse!(
            _struct_size: take!(2)
        >>  _skip1: take!(2)
        >>  dialect: le_u16
        >>  _ctx_cnt: le_u16
        >>  server_guid: take!(16)
        >>  (Smb2NegotiateProtocolResponseRecord {
                dialect,
                server_guid
            })
));

named!(pub parse_smb2_response_negotiate_protocol_error<Smb2NegotiateProtocolResponseRecord>,
    do_parse!(
            _struct_size: take!(2)
        >>  _skip1: take!(2)
        >>  (Smb2NegotiateProtocolResponseRecord {
                dialect: 0,
                server_guid: &[],
            })
));


#[derive(Debug,PartialEq)]
pub struct Smb2SessionSetupRequestRecord<'a> {
    pub data: &'a[u8],
}

named!(pub parse_smb2_request_session_setup<Smb2SessionSetupRequestRecord>,
    do_parse!(
            _struct_size: take!(2)
        >>  _flags: le_u8
        >>  _security_mode: le_u8
        >>  _capabilities: le_u32
        >>  _channel: le_u32
        >>  _sec_offset: le_u16
        >>  _sec_len: le_u16
        >>  _prev_ssn_id: take!(8)
        >>  data: rest
        >>  (Smb2SessionSetupRequestRecord {
                data:data,
            })
));


#[derive(Debug,PartialEq)]
pub struct Smb2TreeConnectRequestRecord<'a> {
    pub share_name: &'a[u8],
}

named!(pub parse_smb2_request_tree_connect<Smb2TreeConnectRequestRecord>,
    do_parse!(
            _struct_size: take!(2)
        >>  _offset_length: take!(4)
        >>  data: rest
        >>  (Smb2TreeConnectRequestRecord {
                share_name:data,
            })
));

#[derive(Debug,PartialEq)]
pub struct Smb2TreeConnectResponseRecord<> {
    pub share_type: u8,
}

named!(pub parse_smb2_response_tree_connect<Smb2TreeConnectResponseRecord>,
    do_parse!(
            _struct_size: take!(2)
        >>  share_type: le_u8
        >>  _share_flags: le_u32
        >>  _share_caps: le_u32
        >>  _access_mask: le_u32
        >>  (Smb2TreeConnectResponseRecord {
                share_type
            })
));


#[derive(Debug,PartialEq)]
pub struct Smb2CreateRequestRecord<'a> {
    pub disposition: u32,
    pub create_options: u32,
    pub data: &'a[u8],
}

named!(pub parse_smb2_request_create<Smb2CreateRequestRecord>,
    do_parse!(
            _skip1: take!(36)
        >>  disposition: le_u32
        >>  create_options: le_u32
        >>  _file_name_offset: le_u16
        >>  file_name_length: le_u16
        >>  _skip2: take!(8)
        >>  data: take!(file_name_length)
        >>  _skip3: rest
        >>  (Smb2CreateRequestRecord {
                disposition,
                create_options,
                data
            })
));

#[derive(Debug,PartialEq)]
pub struct Smb2IOCtlRequestRecord<'a> {
    pub is_pipe: bool,
    pub function: u32,
    pub guid: &'a[u8],
    pub data: &'a[u8],
}

named!(pub parse_smb2_request_ioctl<Smb2IOCtlRequestRecord>,
    do_parse!(
            _skip: take!(2)  // structure size
        >>  take!(2)        // reserved
        >>  func: le_u32
        >>  guid: take!(16)
        >>  _indata_offset: le_u32
        >>  indata_len: le_u32
        >>  take!(4)
        >>  _outdata_offset: le_u32
        >>  _outdata_len: le_u32
        >>  take!(12)
        >>  data: take!(indata_len)
        >>  (Smb2IOCtlRequestRecord {
                is_pipe: (func == 0x0011c017),
                function: func,
                guid:guid,
                data:data,
            })
));

#[derive(Debug,PartialEq)]
pub struct Smb2IOCtlResponseRecord<'a> {
    pub is_pipe: bool,
    pub guid: &'a[u8],
    pub data: &'a[u8],
    pub indata_len: u32,
    pub outdata_len: u32,
    pub indata_offset: u32,
    pub outdata_offset: u32,
}

named!(pub parse_smb2_response_ioctl<Smb2IOCtlResponseRecord>,
    do_parse!(
            _skip: take!(2)  // structure size
        >>  take!(2)        // reserved
        >>  func: le_u32
        >>  guid: take!(16)
        >>  indata_offset: le_u32
        >>  indata_len: le_u32
        >>  outdata_offset: le_u32
        >>  outdata_len: le_u32
        >>  take!(8)
        >>  take!(indata_len)
        >>  data: take!(outdata_len)
        >>  (Smb2IOCtlResponseRecord {
                is_pipe: (func == 0x0011c017),
                guid:guid,
                data:data,
                indata_len:indata_len,
                outdata_len:outdata_len,
                indata_offset:indata_offset,
                outdata_offset:outdata_offset,
            })
));

#[derive(Debug,PartialEq)]
pub struct Smb2CloseRequestRecord<'a> {
    pub guid: &'a[u8],
}

named!(pub parse_smb2_request_close<Smb2CloseRequestRecord>,
    do_parse!(
            _skip: take!(8)
        >>  guid: take!(16)
        >>  (Smb2CloseRequestRecord {
                guid
            })
));

#[derive(Debug)]
pub struct Smb2SetInfoRequestRenameRecord<'a> {
    pub name: &'a[u8],
}

named!(pub parse_smb2_request_setinfo_rename<Smb2SetInfoRequestRenameRecord>,
    do_parse!(
            _replace: le_u8
        >>  _reserved: take!(7)
        >>  _root_handle: take!(8)
        >>  name_len: le_u32
        >>  name: take!(name_len)
        >> (Smb2SetInfoRequestRenameRecord {
                name
            })
));

#[derive(Debug)]
pub struct Smb2SetInfoRequestRecord<'a> {
    pub guid: &'a[u8],
    pub class: u8,
    pub infolvl: u8,
    pub rename: Option<Smb2SetInfoRequestRenameRecord<'a>>,
}

named!(pub parse_smb2_request_setinfo<Smb2SetInfoRequestRecord>,
    do_parse!(
            _struct_size: le_u16
        >>  class: le_u8
        >>  infolvl: le_u8
        >>  setinfo_size: le_u32
        >>  _setinfo_offset: le_u16
        >>  _reserved: take!(2)
        >>  _additional_info: le_u32
        >>  guid: take!(16)
        >>  rename: cond!(class == 1 && infolvl == 10, flat_map!(take!(setinfo_size),parse_smb2_request_setinfo_rename))
        >> (Smb2SetInfoRequestRecord {
                guid: guid,
                class: class,
                infolvl: infolvl,
                rename: rename,
            })
));

#[derive(Debug,PartialEq)]
pub struct Smb2WriteRequestRecord<'a> {
    pub wr_len: u32,
    pub wr_offset: u64,
    pub guid: &'a[u8],
    pub data: &'a[u8],
}

// can be called on incomplete records
named!(pub parse_smb2_request_write<Smb2WriteRequestRecord>,
    do_parse!(
            _skip1: take!(4)
        >>  wr_len: le_u32
        >>  wr_offset: le_u64
        >>  guid: take!(16)
        >>  _channel: le_u32
        >>  _remaining_bytes: le_u32
        >>  _write_flags: le_u32
        >>  _skip2: take!(4)
        >>  data: apply!(parse_smb2_data, wr_len)
        >>  (Smb2WriteRequestRecord {
                wr_len:wr_len,
                wr_offset:wr_offset,
                guid:guid,
                data:data,
            })
));

#[derive(Debug,PartialEq)]
pub struct Smb2ReadRequestRecord<'a> {
    pub rd_len: u32,
    pub rd_offset: u64,
    pub guid: &'a[u8],
}

named!(pub parse_smb2_request_read<Smb2ReadRequestRecord>,
    do_parse!(
            _skip1: take!(4)
        >>  rd_len: le_u32
        >>  rd_offset: le_u64
        >>  guid: take!(16)
        >>  _min_count: le_u32
        >>  _channel: le_u32
        >>  _remaining_bytes: le_u32
        >>  _skip2: take!(4)
        >>  (Smb2ReadRequestRecord {
                rd_len:rd_len,
                rd_offset:rd_offset,
                guid:guid,
            })
));

#[derive(Debug,PartialEq)]
pub struct Smb2ReadResponseRecord<'a> {
    pub len: u32,
    pub data: &'a[u8],
}

// parse read/write data. If all is available, 'take' it.
// otherwise just return what we have. So this may return
// partial data.
fn parse_smb2_data<'a>(i: &'a[u8], len: u32)
    -> IResult<&'a[u8], &'a[u8]>
{
    if len as usize > i.len() {
        rest(i)
    } else {
        take!(i, len)
    }
}

// can be called on incomplete records
named!(pub parse_smb2_response_read<Smb2ReadResponseRecord>,
    do_parse!(
            _struct_size: le_u16
        >>  _data_offset: le_u16
        >>  rd_len: le_u32
        >>  _rd_rem: le_u32
        >>  _padding: take!(4)
        >>  data: apply!(parse_smb2_data, rd_len)
        >>  (Smb2ReadResponseRecord {
                len : rd_len,
                data : data,
            })
));

#[derive(Debug,PartialEq)]
pub struct Smb2CreateResponseRecord<'a> {
    pub guid: &'a[u8],
    pub create_ts: SMBFiletime,
    pub last_access_ts: SMBFiletime,
    pub last_write_ts: SMBFiletime,
    pub last_change_ts: SMBFiletime,
    pub size: u64,
}

named!(pub parse_smb2_response_create<Smb2CreateResponseRecord>,
    do_parse!(
            _ssize: le_u16
        >>  _oplock: le_u8
        >>  _resp_flags: le_u8
        >>  _create_action: le_u32
        >>  create_ts: le_u64
        >>  last_access_ts: le_u64
        >>  last_write_ts: le_u64
        >>  last_change_ts: le_u64
        >>  _alloc_size: le_u64
        >>  eof: le_u64
        >>  _attrs: le_u32
        >>  _padding: take!(4)
        >>  guid: take!(16)
        >>  _skip2: take!(8)
        >>  (Smb2CreateResponseRecord {
                guid : guid,
                create_ts: SMBFiletime::new(create_ts),
                last_access_ts: SMBFiletime::new(last_access_ts),
                last_write_ts: SMBFiletime::new(last_write_ts),
                last_change_ts: SMBFiletime::new(last_change_ts),
                size: eof,
            })
));

#[derive(Debug,PartialEq)]
pub struct Smb2WriteResponseRecord<> {
    pub wr_cnt: u32,
}

named!(pub parse_smb2_response_write<Smb2WriteResponseRecord>,
    do_parse!(
            _skip1: take!(4)
        >>  wr_cnt: le_u32
        >>  _skip2: take!(6)
        >>  (Smb2WriteResponseRecord {
                wr_cnt : wr_cnt,
            })
));

named!(pub parse_smb2_response_record<Smb2Record>,
    do_parse!(
            tag!(b"\xfeSMB")
        >>  hlen: le_u16
        >>  _credit_charge: le_u16
        >>  nt_status: le_u32
        >>  command: le_u16
        >>  _credit_granted: le_u16
        >>  flags: bits!(tuple!(
                take_bits!(u8, 2),      // reserved / unused
                take_bits!(u8, 1),      // replay op
                take_bits!(u8, 1),      // dfs op
                take_bits!(u32, 24),    // reserved / unused
                take_bits!(u8, 1),      // signing
                take_bits!(u8, 1),      // chained
                take_bits!(u8, 1),      // async
                take_bits!(u8, 1)       // response
            ))
        >> chain_offset: le_u32
        >> message_id: le_u64
        >> _process_id: cond!(flags.6==0, le_u32)
        >> tree_id: cond!(flags.6==0, le_u32)
        >> async_id: cond!(flags.6==1, le_u64)
        >> session_id: le_u64
        >> _signature: take!(16)
        // there is probably a cleaner way to do this
        >> data_c: cond!(chain_offset > hlen as u32, take!(chain_offset - hlen as u32))
        >> data_r: cond!(chain_offset <= hlen as u32, rest)
        >> (Smb2Record {
                direction: flags.7,
                nt_status: nt_status,
                message_id: message_id,
                tree_id: tree_id.unwrap_or(0),
                async_id: async_id.unwrap_or(0),
                session_id: session_id,
                command:command,
                data: data_c.or(data_r).unwrap()
           })
));

pub fn search_smb_record<'a>(i: &'a [u8]) -> nom::IResult<&'a [u8], &'a [u8]> {
    let mut d = i;
    while d.len() >= 4 {
        if &d[1..4] == b"SMB" &&
            (d[0] == 0xfe || d[0] == 0xff || d[0] == 0xfd)
        {
            return Ok((&d[4..], d));
        }
        d = &d[1..];
    }
    Err(nom::Err::Incomplete(nom::Needed::Size(4 as usize - d.len())))
}
