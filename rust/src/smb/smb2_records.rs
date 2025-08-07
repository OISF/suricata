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

use crate::smb::nbss_records::NBSS_MSGTYPE_SESSION_MESSAGE;
use crate::smb::smb::*;
use nom7::bytes::streaming::{tag, take};
use nom7::combinator::{cond, map_parser, rest};
use nom7::error::{make_error, ErrorKind};
use nom7::multi::count;
use nom7::number::streaming::{le_u16, le_u32, le_u64, le_u8};
use nom7::{Err, IResult, Needed};

const SMB2_FLAGS_SERVER_TO_REDIR: u32 = 0x0000_0001;
const SMB2_FLAGS_ASYNC_COMMAND: u32 = 0x0000_0002;

#[derive(Debug, PartialEq, Eq)]
pub struct Smb2SecBlobRecord<'a> {
    pub data: &'a [u8],
}

pub fn parse_smb2_sec_blob(i: &[u8]) -> IResult<&[u8], Smb2SecBlobRecord<'_>> {
    let (i, data) = rest(i)?;
    Ok((i, Smb2SecBlobRecord { data }))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Smb2RecordDir {
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

#[derive(Debug, PartialEq, Eq)]
pub struct Smb2Record<'a> {
    pub direction: u8, // 0 req, 1 res
    pub header_len: u16,
    pub nt_status: u32,
    pub command: u16,
    pub message_id: u64,
    pub tree_id: u32,
    pub async_id: u64,
    pub session_id: u64,
    pub data: &'a [u8],
}

impl Smb2Record<'_> {
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
    let direction = u8::from(val & SMB2_FLAGS_SERVER_TO_REDIR != 0);
    let async_command = u8::from(val & SMB2_FLAGS_ASYNC_COMMAND != 0);
    Ok((
        i,
        SmbFlags {
            direction,
            async_command,
        },
    ))
}

pub fn parse_smb2_request_record(i: &[u8]) -> IResult<&[u8], Smb2Record<'_>> {
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

#[derive(Debug, PartialEq, Eq)]
pub struct Smb2NegotiateProtocolRequestRecord<'a> {
    pub dialects_vec: Vec<u16>,
    pub client_guid: &'a [u8],
}

pub fn parse_smb2_request_negotiate_protocol(
    i: &[u8],
) -> IResult<&[u8], Smb2NegotiateProtocolRequestRecord<'_>> {
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

#[derive(Debug, PartialEq, Eq)]
pub struct Smb2NegotiateProtocolResponseRecord<'a> {
    pub dialect: u16,
    pub server_guid: &'a [u8],
    pub max_trans_size: u32,
    pub max_read_size: u32,
    pub max_write_size: u32,
}

pub fn parse_smb2_response_negotiate_protocol(
    i: &[u8],
) -> IResult<&[u8], Smb2NegotiateProtocolResponseRecord<'_>> {
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
        max_write_size,
    };
    Ok((i, record))
}

pub fn parse_smb2_response_negotiate_protocol_error(
    i: &[u8],
) -> IResult<&[u8], Smb2NegotiateProtocolResponseRecord<'_>> {
    let (i, _struct_size) = take(2_usize)(i)?;
    let (i, _skip1) = take(2_usize)(i)?;
    let record = Smb2NegotiateProtocolResponseRecord {
        dialect: 0,
        server_guid: &[],
        max_trans_size: 0,
        max_read_size: 0,
        max_write_size: 0,
    };
    Ok((i, record))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Smb2SessionSetupRequestRecord<'a> {
    pub data: &'a [u8],
}

pub fn parse_smb2_request_session_setup(i: &[u8]) -> IResult<&[u8], Smb2SessionSetupRequestRecord<'_>> {
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

#[derive(Debug, PartialEq, Eq)]
pub struct Smb2TreeConnectRequestRecord<'a> {
    pub share_name: &'a [u8],
}

pub fn parse_smb2_request_tree_connect(i: &[u8]) -> IResult<&[u8], Smb2TreeConnectRequestRecord<'_>> {
    let (i, _struct_size) = take(2_usize)(i)?;
    let (i, _offset_length) = take(4_usize)(i)?;
    let (i, data) = rest(i)?;
    let record = Smb2TreeConnectRequestRecord { share_name: data };
    Ok((i, record))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Smb2TreeConnectResponseRecord {
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

#[derive(Debug, PartialEq, Eq)]
pub struct Smb2CreateRequestRecord<'a> {
    pub disposition: u32,
    pub create_options: u32,
    pub data: &'a [u8],
}

pub fn parse_smb2_request_create(i: &[u8]) -> IResult<&[u8], Smb2CreateRequestRecord<'_>> {
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
        data,
    };
    Ok((i, record))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Smb2IOCtlRequestRecord<'a> {
    pub is_pipe: bool,
    pub function: u32,
    pub guid: &'a [u8],
    pub data: &'a [u8],
}

pub fn parse_smb2_request_ioctl(i: &[u8]) -> IResult<&[u8], Smb2IOCtlRequestRecord<'_>> {
    let (i, _skip) = take(2_usize)(i)?; // structure size
    let (i, _) = take(2_usize)(i)?; // reserved
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

#[derive(Debug, PartialEq, Eq)]
pub struct Smb2IOCtlResponseRecord<'a> {
    pub is_pipe: bool,
    pub guid: &'a [u8],
    pub data: &'a [u8],
    pub indata_len: u32,
    pub outdata_len: u32,
    pub indata_offset: u32,
    pub outdata_offset: u32,
}

pub fn parse_smb2_response_ioctl(i: &[u8]) -> IResult<&[u8], Smb2IOCtlResponseRecord<'_>> {
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

#[derive(Debug, PartialEq, Eq)]
pub struct Smb2CloseRequestRecord<'a> {
    pub guid: &'a [u8],
}

pub fn parse_smb2_request_close(i: &[u8]) -> IResult<&[u8], Smb2CloseRequestRecord<'_>> {
    let (i, _skip) = take(8_usize)(i)?;
    let (i, guid) = take(16_usize)(i)?;
    let record = Smb2CloseRequestRecord { guid };
    Ok((i, record))
}

#[derive(Debug, PartialEq)]
pub struct Smb2SetInfoRequestRenameRecord<'a> {
    pub name: &'a [u8],
}

pub fn parse_smb2_request_setinfo_rename(i: &[u8]) -> IResult<&[u8], Smb2SetInfoRequestData<'_>> {
    let (i, _replace) = le_u8(i)?;
    let (i, _reserved) = take(7_usize)(i)?;
    let (i, _root_handle) = take(8_usize)(i)?;
    let (i, name_len) = le_u32(i)?;
    let (i, name) = take(name_len)(i)?;
    let record = Smb2SetInfoRequestData::RENAME(Smb2SetInfoRequestRenameRecord { name });
    Ok((i, record))
}

#[derive(Debug, PartialEq)]
pub struct Smb2SetInfoRequestDispoRecord {
    pub delete: bool,
}

pub fn parse_smb2_request_setinfo_disposition(i: &[u8]) -> IResult<&[u8], Smb2SetInfoRequestData<'_>> {
    let (i, info) = le_u8(i)?;
    let record = Smb2SetInfoRequestData::DISPOSITION(Smb2SetInfoRequestDispoRecord {
        delete: info & 1 != 0,
    });
    Ok((i, record))
}

#[derive(Debug, PartialEq)]
pub enum Smb2SetInfoRequestData<'a> {
    DISPOSITION(Smb2SetInfoRequestDispoRecord),
    RENAME(Smb2SetInfoRequestRenameRecord<'a>),
    UNHANDLED,
}

#[derive(Debug)]
pub struct Smb2SetInfoRequestRecord<'a> {
    pub guid: &'a [u8],
    pub class: u8,
    pub infolvl: u8,
    pub data: Smb2SetInfoRequestData<'a>,
}

fn parse_smb2_request_setinfo_data(
    i: &[u8], class: u8, infolvl: u8,
) -> IResult<&[u8], Smb2SetInfoRequestData<'_>> {
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
    return Ok((i, Smb2SetInfoRequestData::UNHANDLED));
}

pub fn parse_smb2_request_setinfo(i: &[u8]) -> IResult<&[u8], Smb2SetInfoRequestRecord<'_>> {
    let (i, _struct_size) = le_u16(i)?;
    let (i, class) = le_u8(i)?;
    let (i, infolvl) = le_u8(i)?;
    let (i, setinfo_size) = le_u32(i)?;
    let (i, _setinfo_offset) = le_u16(i)?;
    let (i, _reserved) = take(2_usize)(i)?;
    let (i, _additional_info) = le_u32(i)?;
    let (i, guid) = take(16_usize)(i)?;
    let (i, data) = map_parser(take(setinfo_size), |b| {
        parse_smb2_request_setinfo_data(b, class, infolvl)
    })(i)?;
    let record = Smb2SetInfoRequestRecord {
        guid,
        class,
        infolvl,
        data,
    };
    Ok((i, record))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Smb2WriteRequestRecord<'a> {
    pub wr_len: u32,
    pub wr_offset: u64,
    pub guid: &'a [u8],
    pub data: &'a [u8],
}

// can be called on incomplete records
pub fn parse_smb2_request_write(i: &[u8]) -> IResult<&[u8], Smb2WriteRequestRecord<'_>> {
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

#[derive(Debug, PartialEq, Eq)]
pub struct Smb2ReadRequestRecord<'a> {
    pub rd_len: u32,
    pub rd_offset: u64,
    pub guid: &'a [u8],
}

pub fn parse_smb2_request_read(i: &[u8]) -> IResult<&[u8], Smb2ReadRequestRecord<'_>> {
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

#[derive(Debug, PartialEq, Eq)]
pub struct Smb2ReadResponseRecord<'a> {
    pub len: u32,
    pub data: &'a [u8],
}

// parse read/write data. If all is available, 'take' it.
// otherwise just return what we have. So this may return
// partial data.
fn parse_smb2_data(i: &[u8], len: u32) -> IResult<&[u8], &[u8]> {
    if len as usize > i.len() {
        rest(i)
    } else {
        take(len)(i)
    }
}

// can be called on incomplete records
pub fn parse_smb2_response_read(i: &[u8]) -> IResult<&[u8], Smb2ReadResponseRecord<'_>> {
    let (i, _struct_size) = le_u16(i)?;
    let (i, _data_offset) = le_u16(i)?;
    let (i, rd_len) = le_u32(i)?;
    let (i, _rd_rem) = le_u32(i)?;
    let (i, _padding) = take(4_usize)(i)?;
    let (i, data) = parse_smb2_data(i, rd_len)?;
    let record = Smb2ReadResponseRecord { len: rd_len, data };
    Ok((i, record))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Smb2CreateResponseRecord<'a> {
    pub guid: &'a [u8],
    pub create_ts: SMBFiletime,
    pub last_access_ts: SMBFiletime,
    pub last_write_ts: SMBFiletime,
    pub last_change_ts: SMBFiletime,
    pub size: u64,
}

pub fn parse_smb2_response_create(i: &[u8]) -> IResult<&[u8], Smb2CreateResponseRecord<'_>> {
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

#[derive(Debug, PartialEq, Eq)]
pub struct Smb2WriteResponseRecord {
    pub wr_cnt: u32,
}

pub fn parse_smb2_response_write(i: &[u8]) -> IResult<&[u8], Smb2WriteResponseRecord> {
    let (i, _skip1) = take(4_usize)(i)?;
    let (i, wr_cnt) = le_u32(i)?;
    let (i, _skip2) = take(6_usize)(i)?;
    let record = Smb2WriteResponseRecord { wr_cnt };
    Ok((i, record))
}

pub fn parse_smb2_response_record(i: &[u8]) -> IResult<&[u8], Smb2Record<'_>> {
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
    // this could be replaced by aho-corasick
    let iter = d.windows(needle.len());
    for (r, window) in iter.enumerate() {
        if window == needle {
            return r;
        }
    }
    return 0;
}

pub fn search_smb_record(i: &[u8]) -> IResult<&[u8], &[u8]> {
    let mut d = i;
    while d.len() >= 4 {
        let index = smb_basic_search(d);
        if index == 0 {
            return Err(Err::Error(make_error(d, ErrorKind::Eof)));
        }
        if d[index - 1] == 0xfe || d[index - 1] == 0xff || d[index - 1] == 0xfd {
            // if we have enough data, check nbss
            if index < 5 || d[index - 5] == NBSS_MSGTYPE_SESSION_MESSAGE {
                return Ok((&d[index + 3..], &d[index - 1..]));
            }
        }
        d = &d[index + 3..];
    }
    Err(Err::Incomplete(Needed::new(4_usize - d.len())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smb::smb2::smb2_dialect_string;
    use std::convert::TryInto;
    fn guid_to_string(guid: &[u8]) -> String {
        if guid.len() == 16 {
            let output = format!("{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                    guid[3],  guid[2],  guid[1],  guid[0],
                    guid[5],  guid[4],  guid[7],  guid[6],
                    guid[9],  guid[8],  guid[11], guid[10],
                    guid[15], guid[14], guid[13], guid[12]);
            output
        } else {
            "".to_string()
        }
    }
    #[test]
    fn test_parse_smb2_request_record() {
        let data = hex::decode("fe534d42400000000000000000000100010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let result = parse_smb2_request_record(&data).unwrap();
        let record: Smb2Record = result.1;
        assert_eq!(
            record,
            Smb2Record {
                direction: 1,
                header_len: 64,
                nt_status: 0,
                command: 0,
                message_id: 0,
                tree_id: 0,
                async_id: 0,
                session_id: 0,
                data: &[],
            }
        );
    }
    #[test]
    fn test_parse_smb2_request_negotiate_protocol() {
        // https://github.com/bro/bro/blob/master/testing/btest/Traces/smb/smb3_negotiate_context.pcap
        // smb3_negotiate_context.pcap no.12
        let data = hex::decode("24000800010000007f00000016ab4fd9625676488cd1707d08e52b5878000000020000000202100222022402000302031003110300000000010026000000000001002000010067e5f669ff3e0ad12e89ad84ceb1d35dfee53ede3e4858a6d1a9099ac1635a9600000200060000000000020001000200").unwrap();
        let result = parse_smb2_request_negotiate_protocol(&data).unwrap();
        let record: Smb2NegotiateProtocolRequestRecord = result.1;
        let dialects: Vec<String> = record
            .dialects_vec
            .iter()
            .map(|d| smb2_dialect_string(*d))
            .collect();
        assert_eq!(
            dialects,
            ["2.02", "2.10", "2.22", "2.24", "3.00", "3.02", "3.10", "3.11"]
        );
        assert_eq!(
            guid_to_string(record.client_guid),
            "d94fab16-5662-4876-d18c-7d70582be508"
        ); // TODO: guid order
    }

    #[test]
    fn test_parse_smb2_response_tree_connect() {
        // https://github.com/bro/bro/blob/master/testing/btest/Traces/smb/smb2.pcap
        // filter:smb2 no.11
        let data = hex::decode("100001000008000000000000ff011f00").unwrap();
        let result = parse_smb2_response_tree_connect(&data).unwrap();
        let record: Smb2TreeConnectResponseRecord = result.1;
        assert_eq!(record.share_type, 1); // 1: SMB2_SHARE_TYPE_DISK
    }
    #[test]
    fn test_parse_smb2_request_create() {
        // https://raw.githubusercontent.com/bro/bro/master/testing/btest/Traces/smb/smb2.pcap
        // filter:smb2 no.26
        let data = hex::decode("390000000200000000000000000000000000000000000000810010008000000003000000020000002100200078000000800000005800000000007200760073002800000010000400000018001000000044486e510000000000000000000000000000000000000000180000001000040000001800000000004d78416300000000000000001000040000001800000000005146696400000000").unwrap();
        let result = parse_smb2_request_create(&data).unwrap();
        let record: Smb2CreateRequestRecord = result.1;
        assert_eq!(record.disposition, 2); // FILE_CREATE: 2
        assert_eq!(record.create_options, 0x200021);
        assert_eq!(record.data, &[]);
        let del = record.create_options & 0x0000_1000 != 0;
        let dir = record.create_options & 0x0000_0001 != 0;
        assert!(!del);
        assert!(dir);
    }
    #[test]
    fn test_parse_smb2_request_close() {
        // https://raw.githubusercontent.com/bro/bro/master/testing/btest/Traces/smb/smb2.pcap
        // filter:smb2 no.24
        let data = hex::decode("1800000000000000490000000000000005000000ffffffff").unwrap();
        let result = parse_smb2_request_close(&data).unwrap();
        let record: Smb2CloseRequestRecord = result.1;
        assert_eq!(
            guid_to_string(record.guid),
            "00000049-0000-0000-0005-0000ffffffff"
        );
    }

    #[test]
    fn test_parse_smb2_request_setinfo() {
        // https://raw.githubusercontent.com/bro/bro/master/testing/btest/Traces/smb/smb2.pcap
        // filter:tcp.stream eq 0 no.36
        let data = hex::decode(
            "210001140800000060000000000000004d0000000000000009000000ffffffff4b06170000000000",
        )
        .unwrap();
        let result = parse_smb2_request_setinfo(&data).unwrap();
        let record: Smb2SetInfoRequestRecord = result.1;
        assert_eq!(record.class, 1);
        assert_eq!(record.infolvl, 20);
        assert_eq!(record.data, Smb2SetInfoRequestData::UNHANDLED);
        assert_eq!(
            guid_to_string(record.guid),
            "0000004d-0000-0000-0009-0000ffffffff"
        );
    }

    #[test]
    fn test_parse_smb2_request_read() {
        // https://raw.githubusercontent.com/bro/bro/master/testing/btest/Traces/smb/smb2.pcap
        // filter:smb2 no.20
        let data = hex::decode("31005000000400000000000000000000490000000000000005000000ffffffff00000000000000000000000000000000").unwrap();
        let result = parse_smb2_request_read(&data).unwrap();
        let record: Smb2ReadRequestRecord = result.1;
        assert_eq!(record.rd_len, 1024);
        assert_eq!(record.rd_offset, 0);
        assert_eq!(
            guid_to_string(record.guid),
            "00000049-0000-0000-0005-0000ffffffff"
        );
    }

    #[test]
    fn test_parse_smb2_request_write() {
        // https://raw.githubusercontent.com/bro/bro/master/testing/btest/Traces/smb/smb2.pcap
        // filter:tcp.stream eq 0 no.18
        let data = hex::decode("31007000740000000000000000000000490000000000000005000000ffffffff0000000000000000000000000000000005000b03100000007400000001000000b810b810000000000200000000000100c84f324b7016d30112785a47bf6ee18803000000045d888aeb1cc9119fe808002b1048600200000001000100c84f324b7016d30112785a47bf6ee188030000002c1cb76c12984045030000000000000001000000").unwrap();
        let result = parse_smb2_request_write(&data).unwrap();
        let record: Smb2WriteRequestRecord = result.1;
        assert_eq!(record.wr_len, 116);
        assert_eq!(record.wr_offset, 0);
        assert_eq!(
            guid_to_string(record.guid),
            "00000049-0000-0000-0005-0000ffffffff"
        );
        assert_eq!(record.data.len(), 116);
    }

    #[test]
    fn test_parse_smb2_response_read() {
        // https://raw.githubusercontent.com/bro/bro/master/testing/btest/Traces/smb/smb2.pcap
        // filter:tcp.stream eq 0 no.21
        let data = hex::decode("110050005c000000000000000000000005000c03100000005c00000001000000b810b810b97200000d005c504950455c73727673766300000200000000000000045d888aeb1cc9119fe808002b10486002000000030003000000000000000000000000000000000000000000").unwrap();
        let result = parse_smb2_response_read(&data).unwrap();
        let record: Smb2ReadResponseRecord = result.1;
        assert_eq!(record.len, 92);
        assert_eq!(record.data.len(), 92);
    }
    #[test]
    fn test_parse_smb2_record_direction() {
        let data = hex::decode("fe534d42400000000000000000000100010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let result = parse_smb2_record_direction(&data).unwrap();
        let record: Smb2RecordDir = result.1;
        assert!(!record.request);
        let data = hex::decode("fe534d4240000000000000000100080000000000000000000100000000000000fffe000000000000000000000000000000000000000000000000000000000000").unwrap();
        let result = parse_smb2_record_direction(&data).unwrap();
        let record: Smb2RecordDir = result.1;
        assert!(record.request);
    }

    #[test]
    fn test_parse_smb2_request_tree_connect() {
        let data = hex::decode("0900000048002c005c005c003100390032002e003100360038002e003100390039002e003100330033005c004900500043002400").unwrap();
        let result = parse_smb2_request_tree_connect(&data);
        assert!(result.is_ok());
        let record = result.unwrap().1;
        assert!(record.share_name.len() > 2);
        let share_name_len = u16::from_le_bytes(record.share_name[0..2].try_into().unwrap());
        assert_eq!(share_name_len, 44);
        assert_eq!(record.share_name.len(), share_name_len as usize + 2);
        let mut share_name = record.share_name[2..].to_vec();
        share_name.retain(|&i| i != 0x00);
        assert_eq!(
            String::from_utf8_lossy(&share_name),
            "\\\\192.168.199.133\\IPC$"
        );
    }

    #[test]
    fn test_parse_smb2_response_record() {
        let data = hex::decode("fe534d4240000000000000000000010001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000041000100ff020000966eafa3357f0440a5f9643e1bfa8c56070000000000800000008000000080001064882d8527d201a1f3ae878427d20180004001000000006082013c06062b0601050502a08201303082012ca01a3018060a2b06010401823702021e060a2b06010401823702020aa282010c048201084e45474f45585453010000000000000060000000700000007fb23ba7cacc4e216323ca8472061efbd2c4f6d6b3017012f0bf4f7202ec684ee801ef64e55401ab86b1c9ebde4e39ea0000000000000000600000000100000000000000000000005c33530deaf90d4db2ec4ae3786ec3084e45474f45585453030000000100000040000000980000007fb23ba7cacc4e216323ca8472061efb5c33530deaf90d4db2ec4ae3786ec30840000000580000003056a05430523027802530233121301f06035504031318546f6b656e205369676e696e67205075626c6963204b65793027802530233121301f06035504031318546f6b656e205369676e696e67205075626c6963204b6579").unwrap();
        let result = parse_smb2_response_record(&data);
        assert!(result.is_ok());
        let record = result.unwrap().1;
        assert_eq!(record.direction, 1);
        assert_eq!(record.header_len, 64);
        assert_eq!(record.nt_status, 0);
        assert_eq!(
            record.command,
            crate::smb::smb2::SMB2_COMMAND_NEGOTIATE_PROTOCOL
        );
        assert_eq!(record.message_id, 0);
        assert_eq!(record.tree_id, 0);
        assert_eq!(record.async_id, 0);
        assert_eq!(record.session_id, 0);
        let neg_proto_result = parse_smb2_response_negotiate_protocol(record.data);
        assert!(neg_proto_result.is_ok());
        let neg_proto = neg_proto_result.unwrap().1;
        assert_eq!(
            guid_to_string(neg_proto.server_guid),
            "a3af6e96-7f35-4004-f9a5-3e64568cfa1b"
        );
        assert_eq!(neg_proto.dialect, 0x2ff);
        assert_eq!(smb2_dialect_string(neg_proto.dialect), "2.??".to_string());
        assert_eq!(neg_proto.max_trans_size, 0x800000);
        assert_eq!(neg_proto.max_read_size, 0x800000);
        assert_eq!(neg_proto.max_write_size, 0x800000);
    }

    #[test]
    fn test_todo_parse_smb2_response_negotiate_protocol_error() {
        // TODO: find pcap
    }

    #[test]
    fn test_parse_smb2_response_write() {
        let data = hex::decode("11000000a00000000000000000000000").unwrap();
        let result = parse_smb2_response_write(&data);
        assert!(result.is_ok());
        let record = result.unwrap().1;
        assert_eq!(record.wr_cnt, 160);
    }
    #[test]
    fn test_parse_smb2_response_create() {
        let data = hex::decode("5900000001000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000800000000000000001000000db3b5a009a29ea00000000000000000000000000").unwrap();
        let result = parse_smb2_response_create(&data);
        assert!(result.is_ok());
        let record = result.unwrap().1;
        assert_eq!(
            guid_to_string(record.guid),
            "00000001-3bdb-005a-299a-00ea00000000"
        );
        assert_eq!(record.create_ts, SMBFiletime::new(0));
        assert_eq!(record.last_access_ts, SMBFiletime::new(0));
        assert_eq!(record.last_write_ts, SMBFiletime::new(0));
        assert_eq!(record.last_change_ts, SMBFiletime::new(0));
        assert_eq!(record.size, 0);
    }
    #[test]
    fn test_parse_smb2_response_ioctl() {
        let data = hex::decode("31000000fc011400ffffffffffffffffffffffffffffffff7000000000000000700000003001000000000000000000009800000004000000010000000000000000ca9a3b0000000002000000c0a8c7850000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000010000000000000000ca9a3b000000001700000000000000fe8000000000000065b53a9792d191990000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let result = parse_smb2_response_ioctl(&data);
        assert!(result.is_ok());
        let record = result.unwrap().1;
        assert_eq!(record.indata_len, 0);
        assert_eq!(
            guid_to_string(record.guid),
            "ffffffff-ffff-ffff-ffff-ffffffffffff"
        );
        assert!(!record.is_pipe);
        assert_eq!(record.outdata_len, 304);
        assert_eq!(record.indata_offset, 112);
        assert_eq!(record.outdata_offset, 112);
    }

    #[test]
    fn test_parse_smb2_request_ioctl() {
        let data = hex::decode("39000000fc011400ffffffffffffffffffffffffffffffff7800000000000000000000007800000000000000000001000100000000000000").unwrap();
        let result = parse_smb2_request_ioctl(&data);
        assert!(result.is_ok());
        let record = result.unwrap().1;
        assert_eq!(
            guid_to_string(record.guid),
            "ffffffff-ffff-ffff-ffff-ffffffffffff"
        );
        assert!(!record.is_pipe);
        assert_eq!(record.function, 0x1401fc);
        assert_eq!(record.data, &[]);
    }
}
