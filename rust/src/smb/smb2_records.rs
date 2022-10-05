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

use crate::smb::smb::*;
use crate::smb::nbss_records::NBSS_MSGTYPE_SESSION_MESSAGE;
use nom7::bytes::streaming::{tag, take};
use nom7::combinator::{cond, map_parser, rest};
use nom7::error::{make_error, ErrorKind};
use nom7::multi::count;
use nom7::number::streaming::{le_u8, le_u16, le_u32, le_u64};
use nom7::{Err, IResult, Needed};

const SMB2_FLAGS_SERVER_TO_REDIR: u32 = 0x0000_0001;
const SMB2_FLAGS_ASYNC_COMMAND: u32 = 0x0000_0002;

#[derive(Debug,PartialEq, Eq)]
pub struct Smb2SecBlobRecord<'a> {
    pub data: &'a[u8],
}

pub fn parse_smb2_sec_blob(i: &[u8]) -> IResult<&[u8], Smb2SecBlobRecord> {
    let (i, data) = rest(i)?;
    Ok((i, Smb2SecBlobRecord { data }))
}

#[derive(Debug,PartialEq, Eq)]
pub struct Smb2RecordDir<> {
    pub request: bool,
}

pub fn parse_smb2_record_direction(i: &[u8]) -> IResult<&[u8], Smb2RecordDir> {
    let (i, _server_component) = tag(b"\xfeSMB")(i)?;
    let (i, _skip) = take(12_usize)(i)?;
    let (i, flags) = le_u8(i)?;
    let record = Smb2RecordDir {
        request: flags & 0x01 == 0,
    };
    Ok((i, record))
}

#[derive(Debug,PartialEq, Eq)]
pub struct Smb2Record<'a> {
    pub direction: u8,    // 0 req, 1 res
    pub header_len: u16,
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

    pub fn is_request(&self) -> bool {
        self.direction == 0
    }

    pub fn is_response(&self) -> bool {
        self.direction == 1
    }
}

#[derive(Debug)]
struct SmbFlags {
    direction: u8,
    async_command: u8,
}

fn parse_smb2_flags(i: &[u8]) -> IResult<&[u8], SmbFlags> {
    let (i, val) = le_u32(i)?;
    let direction = if val & SMB2_FLAGS_SERVER_TO_REDIR != 0 { 1 } else { 0 };
    let async_command = if val & SMB2_FLAGS_ASYNC_COMMAND != 0 { 1 } else { 0 };
    Ok((i, SmbFlags {
        direction,
        async_command,
    }))
}

pub fn parse_smb2_request_record(i: &[u8]) -> IResult<&[u8], Smb2Record> {
    let (i, _server_component) = tag(b"\xfeSMB")(i)?;
    let (i, hlen) = le_u16(i)?;
    let (i, _credit_charge) = le_u16(i)?;
    let (i, _channel_seq) = le_u16(i)?;
    let (i, _reserved) = take(2_usize)(i)?;
    let (i, command) = le_u16(i)?;
    let (i, _credits_requested) = le_u16(i)?;
    let (i, flags) = parse_smb2_flags(i)?;
    let (i, chain_offset) = le_u32(i)?;
    let (i, message_id) = le_u64(i)?;
    let (i, _process_id) = le_u32(i)?;
    let (i, tree_id) = le_u32(i)?;
    let (i, session_id) = le_u64(i)?;
    let (i, _signature) = take(16_usize)(i)?;
    let (i, data) = if chain_offset > hlen as u32 {
        take(chain_offset - hlen as u32)(i)?
    } else {
        rest(i)?
    };
    let record = Smb2Record {
        direction: flags.direction,
        header_len: hlen,
        nt_status: 0,
        command,
        message_id,
        tree_id,
        async_id: 0,
        session_id,
        data,
    };
    Ok((i, record))
}

#[derive(Debug,PartialEq, Eq)]
pub struct Smb2NegotiateProtocolRequestRecord<'a> {
    pub dialects_vec: Vec<u16>,
    pub client_guid: &'a[u8],
}

pub fn parse_smb2_request_negotiate_protocol(i: &[u8]) -> IResult<&[u8], Smb2NegotiateProtocolRequestRecord> {
    let (i, _struct_size) = take(2_usize)(i)?;
    let (i, dialects_count) = le_u16(i)?;
    let (i, _sec_mode) = le_u16(i)?;
    let (i, _reserved1) = le_u16(i)?;
    let (i, _capabilities) = le_u32(i)?;
    let (i, client_guid) = take(16_usize)(i)?;
    let (i, _ctx_offset) = le_u32(i)?;
    let (i, _ctx_cnt) = le_u16(i)?;
    let (i, _reserved2) = le_u16(i)?;
    let (i, dia_vec) = count(le_u16, dialects_count as usize)(i)?;
    let record = Smb2NegotiateProtocolRequestRecord {
        dialects_vec: dia_vec,
        client_guid,
    };
    Ok((i, record))
}

#[derive(Debug,PartialEq, Eq)]
pub struct Smb2NegotiateProtocolResponseRecord<'a> {
    pub dialect: u16,
    pub server_guid: &'a[u8],
    pub max_trans_size: u32,
    pub max_read_size: u32,
    pub max_write_size: u32,
}

pub fn parse_smb2_response_negotiate_protocol(i: &[u8]) -> IResult<&[u8], Smb2NegotiateProtocolResponseRecord> {
    let (i, _struct_size) = take(2_usize)(i)?;
    let (i, _skip1) = take(2_usize)(i)?;
    let (i, dialect) = le_u16(i)?;
    let (i, _ctx_cnt) = le_u16(i)?;
    let (i, server_guid) = take(16_usize)(i)?;
    let (i, _capabilities) = le_u32(i)?;
    let (i, max_trans_size) = le_u32(i)?;
    let (i, max_read_size) = le_u32(i)?;
    let (i, max_write_size) = le_u32(i)?;
    let record = Smb2NegotiateProtocolResponseRecord {
        dialect,
        server_guid,
        max_trans_size,
        max_read_size,
        max_write_size
    };
    Ok((i, record))
}

pub fn parse_smb2_response_negotiate_protocol_error(i: &[u8]) -> IResult<&[u8], Smb2NegotiateProtocolResponseRecord> {
    let (i, _struct_size) = take(2_usize)(i)?;
    let (i, _skip1) = take(2_usize)(i)?;
    let record = Smb2NegotiateProtocolResponseRecord {
        dialect: 0,
        server_guid: &[],
        max_trans_size: 0,
        max_read_size: 0,
        max_write_size: 0
    };
    Ok((i, record))
}


#[derive(Debug,PartialEq, Eq)]
pub struct Smb2SessionSetupRequestRecord<'a> {
    pub data: &'a[u8],
}

pub fn parse_smb2_request_session_setup(i: &[u8]) -> IResult<&[u8], Smb2SessionSetupRequestRecord> {
    let (i, _struct_size) = take(2_usize)(i)?;
    let (i, _flags) = le_u8(i)?;
    let (i, _security_mode) = le_u8(i)?;
    let (i, _capabilities) = le_u32(i)?;
    let (i, _channel) = le_u32(i)?;
    let (i, _sec_offset) = le_u16(i)?;
    let (i, _sec_len) = le_u16(i)?;
    let (i, _prev_ssn_id) = take(8_usize)(i)?;
    let (i, data) = rest(i)?;
    let record = Smb2SessionSetupRequestRecord { data };
    Ok((i, record))
}

#[derive(Debug,PartialEq, Eq)]
pub struct Smb2TreeConnectRequestRecord<'a> {
    pub share_name: &'a[u8],
}

pub fn parse_smb2_request_tree_connect(i: &[u8]) -> IResult<&[u8], Smb2TreeConnectRequestRecord> {
    let (i, _struct_size) = take(2_usize)(i)?;
    let (i, _offset_length) = take(4_usize)(i)?;
    let (i, data) = rest(i)?;
    let record = Smb2TreeConnectRequestRecord {
        share_name:data,
    };
    Ok((i, record))
}

#[derive(Debug,PartialEq, Eq)]
pub struct Smb2TreeConnectResponseRecord<> {
    pub share_type: u8,
}

pub fn parse_smb2_response_tree_connect(i: &[u8]) -> IResult<&[u8], Smb2TreeConnectResponseRecord> {
    let (i, _struct_size) = take(2_usize)(i)?;
    let (i, share_type) = le_u8(i)?;
    let (i, _share_flags) = le_u32(i)?;
    let (i, _share_caps) = le_u32(i)?;
    let (i, _access_mask) = le_u32(i)?;
    let record = Smb2TreeConnectResponseRecord { share_type };
    Ok((i, record))
}

#[derive(Debug,PartialEq, Eq)]
pub struct Smb2CreateRequestRecord<'a> {
    pub disposition: u32,
    pub create_options: u32,
    pub data: &'a[u8],
}

pub fn parse_smb2_request_create(i: &[u8]) -> IResult<&[u8], Smb2CreateRequestRecord> {
    let (i, _skip1) = take(36_usize)(i)?;
    let (i, disposition) = le_u32(i)?;
    let (i, create_options) = le_u32(i)?;
    let (i, _file_name_offset) = le_u16(i)?;
    let (i, file_name_length) = le_u16(i)?;
    let (i, _skip2) = take(8_usize)(i)?;
    let (i, data) = take(file_name_length)(i)?;
    let (i, _skip3) = rest(i)?;
    let record = Smb2CreateRequestRecord {
        disposition,
        create_options,
        data
    };
    Ok((i, record))
}

#[derive(Debug,PartialEq, Eq)]
pub struct Smb2IOCtlRequestRecord<'a> {
    pub is_pipe: bool,
    pub function: u32,
    pub guid: &'a[u8],
    pub data: &'a[u8],
}

pub fn parse_smb2_request_ioctl(i: &[u8]) -> IResult<&[u8], Smb2IOCtlRequestRecord> {
    let (i, _skip) = take(2_usize)  (i)?;// structure size
    let (i, _) = take(2_usize)        (i)?;// reserved
    let (i, func) = le_u32(i)?;
    let (i, guid) = take(16_usize)(i)?;
    let (i, _indata_offset) = le_u32(i)?;
    let (i, indata_len) = le_u32(i)?;
    let (i, _) = take(4_usize)(i)?;
    let (i, _outdata_offset) = le_u32(i)?;
    let (i, _outdata_len) = le_u32(i)?;
    let (i, _) = take(12_usize)(i)?;
    let (i, data) = take(indata_len)(i)?;
    let record = Smb2IOCtlRequestRecord {
        is_pipe: (func == 0x0011c017),
        function: func,
        guid,
        data,
    };
    Ok((i, record))
}

#[derive(Debug,PartialEq, Eq)]
pub struct Smb2IOCtlResponseRecord<'a> {
    pub is_pipe: bool,
    pub guid: &'a[u8],
    pub data: &'a[u8],
    pub indata_len: u32,
    pub outdata_len: u32,
    pub indata_offset: u32,
    pub outdata_offset: u32,
}

pub fn parse_smb2_response_ioctl(i: &[u8]) -> IResult<&[u8], Smb2IOCtlResponseRecord> {
    let (i, _skip) = take(2_usize)(i)?; // structure size
    let (i, _) = take(2_usize)(i)?; // reserved
    let (i, func) = le_u32(i)?;
    let (i, guid) = take(16_usize)(i)?;
    let (i, indata_offset) = le_u32(i)?;
    let (i, indata_len) = le_u32(i)?;
    let (i, outdata_offset) = le_u32(i)?;
    let (i, outdata_len) = le_u32(i)?;
    let (i, _) = take(8_usize)(i)?;
    let (i, _) = take(indata_len)(i)?;
    let (i, data) = take(outdata_len)(i)?;
    let record = Smb2IOCtlResponseRecord {
        is_pipe: (func == 0x0011c017),
        guid,
        data,
        indata_len,
        outdata_len,
        indata_offset,
        outdata_offset,
    };
    Ok((i, record))
}

#[derive(Debug,PartialEq, Eq)]
pub struct Smb2CloseRequestRecord<'a> {
    pub guid: &'a[u8],
}

pub fn parse_smb2_request_close(i: &[u8]) -> IResult<&[u8], Smb2CloseRequestRecord> {
    let (i, _skip) = take(8_usize)(i)?;
    let (i, guid) = take(16_usize)(i)?;
    let record = Smb2CloseRequestRecord { guid };
    Ok((i, record))
}

#[derive(Debug)]
pub struct Smb2SetInfoRequestRenameRecord<'a> {
    pub name: &'a[u8],
}

pub fn parse_smb2_request_setinfo_rename(i: &[u8]) -> IResult<&[u8], Smb2SetInfoRequestData> {
    let (i, _replace) = le_u8(i)?;
    let (i, _reserved) = take(7_usize)(i)?;
    let (i, _root_handle) = take(8_usize)(i)?;
    let (i, name_len) = le_u32(i)?;
    let (i, name) = take(name_len)(i)?;
    let record = Smb2SetInfoRequestData::RENAME(Smb2SetInfoRequestRenameRecord { name });
    Ok((i, record))
}

#[derive(Debug)]
pub struct Smb2SetInfoRequestDispoRecord {
    pub delete: bool,
}

pub fn parse_smb2_request_setinfo_disposition(i: &[u8]) -> IResult<&[u8], Smb2SetInfoRequestData> {
    let (i, info) = le_u8(i)?;
    let record = Smb2SetInfoRequestData::DISPOSITION(Smb2SetInfoRequestDispoRecord {
        delete: info & 1 != 0,
    });
    Ok((i, record))
}

#[derive(Debug)]
pub enum Smb2SetInfoRequestData<'a> {
    DISPOSITION(Smb2SetInfoRequestDispoRecord),
    RENAME(Smb2SetInfoRequestRenameRecord<'a>),
    UNHANDLED,
}

#[derive(Debug)]
pub struct Smb2SetInfoRequestRecord<'a> {
    pub guid: &'a[u8],
    pub class: u8,
    pub infolvl: u8,
    pub data: Smb2SetInfoRequestData<'a>,
}

fn parse_smb2_request_setinfo_data(
    i: &[u8], class: u8, infolvl: u8,
) -> IResult<&[u8], Smb2SetInfoRequestData> {
    if class == 1 {
        // constants from [MS-FSCC] section 2.4
        match infolvl {
            10 => {
                return parse_smb2_request_setinfo_rename(i);
            }
            0xd => {
                return parse_smb2_request_setinfo_disposition(i);
            }
            _ => {}
        }
    }
    Ok((i, Smb2SetInfoRequestData::UNHANDLED))
}

pub fn parse_smb2_request_setinfo(i: &[u8]) -> IResult<&[u8], Smb2SetInfoRequestRecord> {
    let (i, _struct_size) = le_u16(i)?;
    let (i, class) = le_u8(i)?;
    let (i, infolvl) = le_u8(i)?;
    let (i, setinfo_size) = le_u32(i)?;
    let (i, _setinfo_offset) = le_u16(i)?;
    let (i, _reserved) = take(2_usize)(i)?;
    let (i, _additional_info) = le_u32(i)?;
    let (i, guid) = take(16_usize)(i)?;
    let (i, data) = map_parser(
        take(setinfo_size),
        |b| parse_smb2_request_setinfo_data(b, class, infolvl)
    )(i)?;
    let record = Smb2SetInfoRequestRecord {
        guid,
        class,
        infolvl,
        data,
    };
    Ok((i, record))
}

#[derive(Debug,PartialEq, Eq)]
pub struct Smb2WriteRequestRecord<'a> {
    pub wr_len: u32,
    pub wr_offset: u64,
    pub guid: &'a[u8],
    pub data: &'a[u8],
}

// can be called on incomplete records
pub fn parse_smb2_request_write(i: &[u8]) -> IResult<&[u8], Smb2WriteRequestRecord> {
    let (i, _skip1) = take(4_usize)(i)?;
    let (i, wr_len) = le_u32(i)?;
    let (i, wr_offset) = le_u64(i)?;
    let (i, guid) = take(16_usize)(i)?;
    let (i, _channel) = le_u32(i)?;
    let (i, _remaining_bytes) = le_u32(i)?;
    let (i, _write_flags) = le_u32(i)?;
    let (i, _skip2) = take(4_usize)(i)?;
    let (i, data) = parse_smb2_data(i, wr_len)?;
    let record = Smb2WriteRequestRecord {
        wr_len,
        wr_offset,
        guid,
        data,
    };
    Ok((i, record))
}

#[derive(Debug,PartialEq, Eq)]
pub struct Smb2ReadRequestRecord<'a> {
    pub rd_len: u32,
    pub rd_offset: u64,
    pub guid: &'a[u8],
}

pub fn parse_smb2_request_read(i: &[u8]) -> IResult<&[u8], Smb2ReadRequestRecord> {
    let (i, _skip1) = take(4_usize)(i)?;
    let (i, rd_len) = le_u32(i)?;
    let (i, rd_offset) = le_u64(i)?;
    let (i, guid) = take(16_usize)(i)?;
    let (i, _min_count) = le_u32(i)?;
    let (i, _channel) = le_u32(i)?;
    let (i, _remaining_bytes) = le_u32(i)?;
    let (i, _skip2) = take(4_usize)(i)?;
    let record = Smb2ReadRequestRecord {
        rd_len,
        rd_offset,
        guid,
    };
    Ok((i, record))
}

#[derive(Debug,PartialEq, Eq)]
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
        take(len)(i)
    }
}

// can be called on incomplete records
pub fn parse_smb2_response_read(i: &[u8]) -> IResult<&[u8], Smb2ReadResponseRecord> {
    let (i, _struct_size) = le_u16(i)?;
    let (i, _data_offset) = le_u16(i)?;
    let (i, rd_len) = le_u32(i)?;
    let (i, _rd_rem) = le_u32(i)?;
    let (i, _padding) = take(4_usize)(i)?;
    let (i, data) = parse_smb2_data(i, rd_len)?;
    let record = Smb2ReadResponseRecord {
        len: rd_len,
        data,
    };
    Ok((i, record))
}

#[derive(Debug,PartialEq, Eq)]
pub struct Smb2CreateResponseRecord<'a> {
    pub guid: &'a[u8],
    pub create_ts: SMBFiletime,
    pub last_access_ts: SMBFiletime,
    pub last_write_ts: SMBFiletime,
    pub last_change_ts: SMBFiletime,
    pub size: u64,
}

pub fn parse_smb2_response_create(i: &[u8]) -> IResult<&[u8], Smb2CreateResponseRecord> {
    let (i, _ssize) = le_u16(i)?;
    let (i, _oplock) = le_u8(i)?;
    let (i, _resp_flags) = le_u8(i)?;
    let (i, _create_action) = le_u32(i)?;
    let (i, create_ts) = le_u64(i)?;
    let (i, last_access_ts) = le_u64(i)?;
    let (i, last_write_ts) = le_u64(i)?;
    let (i, last_change_ts) = le_u64(i)?;
    let (i, _alloc_size) = le_u64(i)?;
    let (i, eof) = le_u64(i)?;
    let (i, _attrs) = le_u32(i)?;
    let (i, _padding) = take(4_usize)(i)?;
    let (i, guid) = take(16_usize)(i)?;
    let (i, _skip2) = take(8_usize)(i)?;
    let record = Smb2CreateResponseRecord {
        guid,
        create_ts: SMBFiletime::new(create_ts),
        last_access_ts: SMBFiletime::new(last_access_ts),
        last_write_ts: SMBFiletime::new(last_write_ts),
        last_change_ts: SMBFiletime::new(last_change_ts),
        size: eof,
    };
    Ok((i, record))
}

#[derive(Debug,PartialEq, Eq)]
pub struct Smb2WriteResponseRecord<> {
    pub wr_cnt: u32,
}

pub fn parse_smb2_response_write(i: &[u8]) -> IResult<&[u8], Smb2WriteResponseRecord> {
    let (i, _skip1) = take(4_usize)(i)?;
    let (i, wr_cnt) = le_u32(i)?;
    let (i, _skip2) = take(6_usize)(i)?;
    let record = Smb2WriteResponseRecord { wr_cnt };
    Ok((i, record))
}

pub fn parse_smb2_response_record(i: &[u8]) -> IResult<&[u8], Smb2Record> {
    let (i, _) = tag(b"\xfeSMB")(i)?;
    let (i, hlen) = le_u16(i)?;
    let (i, _credit_charge) = le_u16(i)?;
    let (i, nt_status) = le_u32(i)?;
    let (i, command) = le_u16(i)?;
    let (i, _credit_granted) = le_u16(i)?;
    let (i, flags) = parse_smb2_flags(i)?;
    let (i, chain_offset) = le_u32(i)?;
    let (i, message_id) = le_u64(i)?;
    let (i, _process_id) = cond(flags.async_command == 0, le_u32)(i)?;
    let (i, tree_id) = cond(flags.async_command == 0, le_u32)(i)?;
    let (i, async_id) = cond(flags.async_command == 1, le_u64)(i)?;
    let (i, session_id) = le_u64(i)?;
    let (i, _signature) = take(16_usize)(i)?;
    let (i, data) = if chain_offset > hlen as u32 {
        take(chain_offset - hlen as u32)(i)?
    } else {
        rest(i)?
    };
    let record = Smb2Record {
        direction: flags.direction,
        header_len: hlen,
        nt_status,
        message_id,
        tree_id: tree_id.unwrap_or(0),
        async_id: async_id.unwrap_or(0),
        session_id,
        command,
        data,
    };
    Ok((i, record))
}

fn smb_basic_search(d: &[u8]) -> usize {
    let needle = b"SMB";
    let mut r = 0 as usize;
    // this could be replaced by aho-corasick
    let iter = d.windows(needle.len());
    for window in iter {
        if window == needle {
            return r;
        }
        r = r + 1;
    }
    0
}

pub fn search_smb_record<'a>(i: &'a [u8]) -> IResult<&'a [u8], &'a [u8]> {
    let mut d = i;
    while d.len() >= 4 {
        let index = smb_basic_search(d);
        if index == 0 {
            return Err(Err::Error(make_error(d, ErrorKind::Eof)));
        }
        if d[index - 1] == 0xfe || d[index - 1] == 0xff || d[index - 1] == 0xfd {
            // if we have enough data, check nbss
            if index < 5 || d[index-5] == NBSS_MSGTYPE_SESSION_MESSAGE {
                return Ok((&d[index + 3..], &d[index - 1..]));
            }
        }
        d = &d[index + 3..];
    }
    Err(Err::Incomplete(Needed::new(4 as usize - d.len())))
}
