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

use crate::common::nom7::take_until_and_consume;
use crate::smb::error::SmbError;
use crate::smb::smb::*;
use crate::smb::smb_records::*;
use nom7::bytes::streaming::{tag, take};
use nom7::combinator::{complete, cond, peek, rest, verify};
use nom7::multi::many1;
use nom7::number::streaming::{le_u8, le_u16, le_u32, le_u64};
use nom7::IResult;

pub const SMB1_HEADER_SIZE: usize = 32;

// SMB_FLAGS_REPLY in Microsoft docs.
const SMB1_FLAGS_RESPONSE: u8 = 0x80;

fn smb_get_unicode_string_with_offset(i: &[u8], offset: usize) -> IResult<&[u8], Vec<u8>, SmbError>
{
    let (i, _) = cond(offset % 2 == 1, take(1_usize))(i)?;
    smb_get_unicode_string(i)
}

/// take a string, unicode or ascii based on record
pub fn smb1_get_string<'a>(i: &'a[u8], r: &SmbRecord, offset: usize) -> IResult<&'a[u8], Vec<u8>, SmbError> {
    if r.has_unicode_support() {
        smb_get_unicode_string_with_offset(i, offset)
    } else {
        smb_get_ascii_string(i)
    }
}


#[derive(Debug,PartialEq)]
pub struct SmbParamBlockAndXHeader {
    pub wct: u8,
    pub andx_command: u8,
    pub andx_offset: u16,
}

pub fn smb1_parse_andx_header(i: &[u8]) -> IResult<&[u8], SmbParamBlockAndXHeader> {
    let (i, wct) = le_u8(i)?;
    let (i, andx_command) = le_u8(i)?;
    let (i, _) = take(1_usize)(i)?; // reserved
    let (i, andx_offset) = le_u16(i)?;
    let hdr = SmbParamBlockAndXHeader {
        wct,
        andx_command,
        andx_offset,
    };
    Ok((i, hdr))
}

#[derive(Debug,PartialEq)]
pub struct Smb1WriteRequestRecord<'a> {
    pub offset: u64,
    pub len: u32,
    pub fid: &'a[u8],
    pub data: &'a[u8],
}

pub fn parse_smb1_write_request_record(i: &[u8]) -> IResult<&[u8], Smb1WriteRequestRecord> {
    let (i, _wct) = le_u8(i)?;
    let (i, fid) = take(2_usize)(i)?;
    let (i, _count) = le_u16(i)?;
    let (i, offset) = le_u32(i)?;
    let (i, _remaining) = le_u16(i)?;
    let (i, _bcc) = le_u16(i)?;
    let (i, _buffer_format) = le_u8(i)?;
    let (i, data_len) = le_u16(i)?;
    let (i, file_data) = take(data_len)(i)?;
    let record = Smb1WriteRequestRecord {
        offset: offset as u64,
        len: data_len as u32,
        fid,
        data:file_data,
    };
    Ok((i, record))
}

pub fn parse_smb1_write_andx_request_record(i : &[u8], andx_offset: usize) -> IResult<&[u8], Smb1WriteRequestRecord> {
    let ax = andx_offset as u16;
    let (i, wct) = le_u8(i)?;
    let (i, _andx_command) = le_u8(i)?;
    let (i, _) = take(1_usize)(i)?; // reserved
    let (i, _andx_offset) = le_u16(i)?;
    let (i, fid) = take(2_usize)(i)?;
    let (i, offset) = le_u32(i)?;
    let (i, _) = take(4_usize)(i)?; // reserved
    let (i, _write_mode) = le_u16(i)?;
    let (i, _remaining) = le_u16(i)?;
    let (i, data_len_high) = le_u16(i)?;
    let (i, data_len_low) = le_u16(i)?;
    let (i, data_offset) = le_u16(i)?;
    let (i, high_offset) = cond(wct == 14, le_u32)(i)?;
    let (i, bcc) = le_u16(i)?;
    //spec [MS-CIFS].pdf says always take one byte padding
    let (i, _padding) = cond(bcc > data_len_low, |b| take(bcc - data_len_low)(b))(i)?; // TODO figure out how this works with data_len_high
    let (i, _padding_evasion) = cond(data_offset > ax+4+2*(wct as u16), |b| take(data_offset - (ax+4+2*(wct as u16)))(b))(i)?;
    let (i, file_data) = rest(i)?;
    let record = Smb1WriteRequestRecord {
        offset: if high_offset.is_some() { ((high_offset.unwrap() as u64) << 32)|(offset as u64) } else { 0 },
        len: (((data_len_high as u32) << 16) as u32)|(data_len_low as u32),
        fid,
        data: file_data,
    };
    Ok((i, record))
}

pub fn parse_smb1_write_and_close_request_record(i: &[u8]) -> IResult<&[u8], Smb1WriteRequestRecord> {
    let (i, _wct) = le_u8(i)?;
    let (i, fid) = take(2_usize)(i)?;
    let (i, count) = le_u16(i)?;
    let (i, offset) = le_u32(i)?;
    let (i, _last_write) = take(4_usize)(i)?;
    let (i, bcc) = le_u16(i)?;
    let (i, _padding) = cond(bcc > count, |b| take(bcc - count)(b))(i)?;
    let (i, file_data) = take(count)(i)?;
    let record = Smb1WriteRequestRecord {
        offset: offset as u64,
        len: count as u32,
        fid,
        data: file_data,
    };
    Ok((i, record))
}

#[derive(Debug,PartialEq)]
pub struct Smb1NegotiateProtocolResponseRecord<'a> {
    pub dialect_idx: u16,
    pub server_guid: &'a[u8],
}

pub fn parse_smb1_negotiate_protocol_response_record_error(i: &[u8])
    -> IResult<&[u8], Smb1NegotiateProtocolResponseRecord> {
     let (i, _wct) = le_u8(i)?;
     let (i, _bcc) = le_u16(i)?;
     let record = Smb1NegotiateProtocolResponseRecord {
         dialect_idx: 0,
         server_guid: &[],
     };
     Ok((i, record))
}

pub fn parse_smb1_negotiate_protocol_response_record_ok(i: &[u8])
    -> IResult<&[u8], Smb1NegotiateProtocolResponseRecord> {
    let (i, _wct) = le_u8(i)?;
    let (i, dialect_idx) = le_u16(i)?;
    let (i, _sec_mode) = le_u8(i)?;
    let (i, _) = take(16_usize)(i)?;
    let (i, _caps) = le_u32(i)?;
    let (i, _sys_time) = le_u64(i)?;
    let (i, _server_tz) = le_u16(i)?;
    let (i, _challenge_len) = le_u8(i)?;
    let (i, bcc) = le_u16(i)?;
    let (i, server_guid) = cond(bcc >= 16, take(16_usize))(i)?;
    let record = Smb1NegotiateProtocolResponseRecord {
        dialect_idx,
        server_guid: server_guid.unwrap_or(&[]),
    };
    Ok((i, record))
}

pub fn parse_smb1_negotiate_protocol_response_record(i: &[u8])
    -> IResult<&[u8], Smb1NegotiateProtocolResponseRecord> {
    let (i, wct) = peek(le_u8)(i)?;
    match wct {
        0 => parse_smb1_negotiate_protocol_response_record_error(i),
        _ => parse_smb1_negotiate_protocol_response_record_ok(i),
    }
}

#[derive(Debug,PartialEq)]
pub struct Smb1NegotiateProtocolRecord<'a> {
    pub dialects: Vec<&'a [u8]>,
}

pub fn parse_smb1_negotiate_protocol_record(i: &[u8])
    -> IResult<&[u8], Smb1NegotiateProtocolRecord> {
    let (i, _wtc) = le_u8(i)?;
    let (i, _bcc) = le_u16(i)?;
    // dialects is a list of [1 byte buffer format][string][0 terminator]
    let (i, dialects) = many1(complete(take_until_and_consume(b"\0")))(i)?;
    let record = Smb1NegotiateProtocolRecord { dialects };
    Ok((i, record))
}


#[derive(Debug,PartialEq)]
pub struct Smb1ResponseRecordTreeConnectAndX<'a> {
    pub service: &'a[u8],
    pub nativefs: &'a[u8],
}

pub fn parse_smb_connect_tree_andx_response_record(i: &[u8])
    -> IResult<&[u8], Smb1ResponseRecordTreeConnectAndX> {
    let (i, wct) = le_u8(i)?;
    let (i, _andx_command) = le_u8(i)?;
    let (i, _) = take(1_usize)(i)?; // reserved
    let (i, _andx_offset) = le_u16(i)?;
    let (i, _) = cond(wct >= 3, take(2_usize))(i)?; // optional support
    let (i, _) = cond(wct == 7, take(8_usize))(i)?; // access masks
    let (i, _bcc) = le_u16(i)?;
    let (i, service) = take_until_and_consume(b"\x00")(i)?;
    let (i, nativefs) = take_until_and_consume(b"\x00")(i)?;
    let record = Smb1ResponseRecordTreeConnectAndX {
        service,
        nativefs
    };
    Ok((i, record))
}

#[derive(Debug,PartialEq)]
pub struct SmbRecordTreeConnectAndX<'a> {
    pub path: Vec<u8>,
    pub service: &'a[u8],
}

pub fn parse_smb_connect_tree_andx_record<'a>(i: &'a[u8], r: &SmbRecord)
   -> IResult<&'a[u8], SmbRecordTreeConnectAndX<'a>, SmbError> {
   let (i, _skip1) = take(7_usize)(i)?;
   let (i, pwlen) = le_u16(i)?;
   let (i, _bcc) = le_u16(i)?;
   let (i, _pw) = take(pwlen)(i)?;
   let (i, path) = smb1_get_string(i, r, 11 + pwlen as usize)?;
   let (i, service) = take_until_and_consume(b"\x00")(i)?;
   let record = SmbRecordTreeConnectAndX {
       path,
       service
   };
   Ok((i, record))
}

#[derive(Debug,PartialEq)]
pub struct SmbRecordTransRequest<'a> {
    pub params: SmbRecordTransRequestParams,
    pub pipe: Option<SmbPipeProtocolRecord<'a>>,
    pub txname: Vec<u8>,
    pub data: SmbRecordTransRequestData<'a>,
}

#[derive(Debug,PartialEq)]
pub struct SmbPipeProtocolRecord<'a> {
    pub function: u16,
    pub fid: &'a[u8],
}

pub fn parse_smb_trans_request_record_pipe(i: &[u8])
    -> IResult<&[u8], SmbPipeProtocolRecord, SmbError> {
    let (i, fun) = le_u16(i)?;
    let (i, fid) = take(2_usize)(i)?;
    let record = SmbPipeProtocolRecord {
        function: fun,
        fid
    };
    Ok((i, record))
}


#[derive(Debug,PartialEq)]
pub struct SmbRecordTransRequestParams<> {
    pub max_data_cnt: u16,
    param_cnt: u16,
    param_offset: u16,
    data_cnt: u16,
    data_offset: u16,
    bcc: u16,
}

pub fn parse_smb_trans_request_record_params(i: &[u8])
    -> IResult<&[u8], (SmbRecordTransRequestParams, Option<SmbPipeProtocolRecord>), SmbError>
{
   let (i, wct) = le_u8(i)?;
   let (i, _total_param_cnt) = le_u16(i)?;
   let (i, _total_data_count) = le_u16(i)?;
   let (i, _max_param_cnt) = le_u16(i)?;
   let (i, max_data_cnt) = le_u16(i)?;
   let (i, _max_setup_cnt) = le_u8(i)?;
   let (i, _) = take(1_usize)(i)?; // reserved
   let (i, _) = take(2_usize)(i)?; // flags
   let (i, _timeout) = le_u32(i)?;
   let (i, _) = take(2_usize)(i)?; // reserved
   let (i, param_cnt) = le_u16(i)?;
   let (i, param_offset) = le_u16(i)?;
   let (i, data_cnt) = le_u16(i)?;
   let (i, data_offset) = le_u16(i)?;
   let (i, setup_cnt) = le_u8(i)?;
   let (i, _) = take(1_usize)(i)?; // reserved
   let (i, pipe) = cond(wct == 16 && setup_cnt == 2 && data_cnt > 0, parse_smb_trans_request_record_pipe)(i)?;
   let (i, bcc) = le_u16(i)?;
   let params = SmbRecordTransRequestParams {
            max_data_cnt,
            param_cnt,
            param_offset,
            data_cnt,
            data_offset,
            bcc
        };
   Ok((i, (params, pipe)))
}

#[derive(Debug,PartialEq)]
pub struct SmbRecordTransRequestData<'a> {
    pub data: &'a[u8],
}

pub fn parse_smb_trans_request_record_data(i: &[u8],
        pad1: usize, param_cnt: u16, pad2: usize, data_len: u16)
    -> IResult<&[u8], SmbRecordTransRequestData, SmbError>
{
    let (i, _) = take(pad1)(i)?;
    let (i, _) = take(param_cnt)(i)?;
    let (i, _) = take(pad2)(i)?;
    let (i, data) = take(data_len)(i)?;
    let req = SmbRecordTransRequestData { data };
    Ok((i, req))
}

pub fn parse_smb_trans_request_record<'a, 'b>(i: &'a[u8], r: &SmbRecord<'b>)
    -> IResult<&'a[u8], SmbRecordTransRequest<'a>, SmbError>
{
    let (rem, (params, pipe)) = parse_smb_trans_request_record_params(i)?;
    let mut offset = 32 + (i.len() - rem.len()); // init with SMB header
    SCLogDebug!("params {:?}: offset {}", params, offset);

    let (rem2, n) = smb1_get_string(rem, r, offset)?;
    offset += rem.len() - rem2.len();
    SCLogDebug!("n {:?}: offset {}", n, offset);

    // spec says pad to 4 bytes, but traffic shows this doesn't
    // always happen.
    let pad1 = if offset == params.param_offset as usize ||
                  offset == params.data_offset as usize {
        0
    } else {
        offset % 4
    };
    SCLogDebug!("pad1 {}", pad1);
    offset += pad1;
    offset += params.param_cnt as usize;

    let recdata = if params.data_cnt > 0 {
        // ignore padding rule if we're already at the correct
        // offset.
        let pad2 = if offset == params.data_offset as usize {
            0
        } else {
            offset % 4
        };
        SCLogDebug!("pad2 {}", pad2);

        let d = match parse_smb_trans_request_record_data(rem2,
                pad1, params.param_cnt, pad2, params.data_cnt) {
            Ok((_, rd)) => rd,
            Err(e) => { return Err(e); }
        };
        SCLogDebug!("d {:?}", d);
        d
    } else {
        SmbRecordTransRequestData { data: &[], } // no data
    };

    let res = SmbRecordTransRequest {
        params, pipe, txname: n, data: recdata,
    };
    Ok((rem, res))
}


#[derive(Debug,PartialEq)]
pub struct SmbRecordTransResponse<'a> {
    pub data_cnt: u16,
    pub bcc: u16,
    pub data: &'a[u8],
}

pub fn parse_smb_trans_response_error_record(i: &[u8]) -> IResult<&[u8], SmbRecordTransResponse> {
   let (i, _wct) = le_u8(i)?;
   let (i, bcc) = le_u16(i)?;
   let resp = SmbRecordTransResponse {
       data_cnt: 0,
       bcc,
       data: &[],
   };
   Ok((i, resp))
}

pub fn parse_smb_trans_response_regular_record(i: &[u8]) -> IResult<&[u8], SmbRecordTransResponse> {
   let (i, wct) = le_u8(i)?;
   let (i, _total_param_cnt) = le_u16(i)?;
   let (i, _total_data_count) = le_u16(i)?;
   let (i, _) = take(2_usize)(i)?; // reserved
   let (i, _param_cnt) = le_u16(i)?;
   let (i, _param_offset) = le_u16(i)?;
   let (i, _param_displacement) = le_u16(i)?;
   let (i, data_cnt) = le_u16(i)?;
   let (i, data_offset) = le_u16(i)?;
   let (i, _data_displacement) = le_u16(i)?;
   let (i, _setup_cnt) = le_u8(i)?;
   let (i, _) = take(1_usize)(i)?; // reserved
   let (i, bcc) = le_u16(i)?;
   let (i, _) = take(1_usize)(i)?; // padding
   let (i, _padding_evasion) = cond(
       data_offset > 36+2*(wct as u16),
       |b| take(data_offset - (36+2*(wct as u16)))(b)
    )(i)?;
   let (i, data) = take(data_cnt)(i)?;
   let resp = SmbRecordTransResponse {
       data_cnt,
       bcc,
       data
   };
   Ok((i, resp))
}

pub fn parse_smb_trans_response_record(i: &[u8]) -> IResult<&[u8], SmbRecordTransResponse> {
    let (i, wct) = peek(le_u8)(i)?;
    match wct {
        0 => parse_smb_trans_response_error_record(i),
        _ => parse_smb_trans_response_regular_record(i),
    }
}

#[derive(Debug,PartialEq)]
pub struct SmbRecordSetupAndX<'a> {
    pub sec_blob: &'a[u8],
}

pub fn parse_smb_setup_andx_record(i: &[u8]) -> IResult<&[u8], SmbRecordSetupAndX> {
    let (i, _skip1) = take(15_usize)(i)?;
    let (i, sec_blob_len) = le_u16(i)?;
    let (i, _skip2) = take(8_usize)(i)?;
    let (i, _bcc) = le_u16(i)?;
    let (i, sec_blob) = take(sec_blob_len)(i)?;
    let record = SmbRecordSetupAndX { sec_blob };
    Ok((i, record))
}

#[derive(Debug,PartialEq)]
pub struct SmbResponseRecordSetupAndX<'a> {
    pub sec_blob: &'a[u8],
}

fn response_setup_andx_record(i: &[u8]) -> IResult<&[u8], SmbResponseRecordSetupAndX> {
   let (i, _skip1) = take(7_usize)(i)?;
   let (i, sec_blob_len) = le_u16(i)?;
   let (i, _bcc) = le_u16(i)?;
   let (i, sec_blob) = take(sec_blob_len)(i)?;
   let record = SmbResponseRecordSetupAndX { sec_blob };
   Ok((i, record))
}

fn response_setup_andx_wct3_record(i: &[u8]) -> IResult<&[u8], SmbResponseRecordSetupAndX> {
   let (i, _skip1) = take(7_usize)(i)?;
   let (i, _bcc) = le_u16(i)?;
   let record = SmbResponseRecordSetupAndX {
        sec_blob: &[],
   };
   Ok((i, record))
}

fn response_setup_andx_error_record(i: &[u8]) -> IResult<&[u8], SmbResponseRecordSetupAndX> {
   let (i, _wct) = le_u8(i)?;
   let (i, _bcc) = le_u16(i)?;
   let record = SmbResponseRecordSetupAndX {
        sec_blob: &[],
   };
   Ok((i, record))
}

pub fn parse_smb_response_setup_andx_record(i: &[u8]) -> IResult<&[u8], SmbResponseRecordSetupAndX> {
    let (i, wct) = peek(le_u8)(i)?;
    match wct {
        0 => response_setup_andx_error_record(i),
        3 => response_setup_andx_wct3_record(i),
        _ => response_setup_andx_record(i),
    }
}

#[derive(Debug,PartialEq)]
pub struct SmbRequestReadAndXRecord<'a> {
    pub fid: &'a[u8],
    pub size: u64,
    pub offset: u64,
}

pub fn parse_smb_read_andx_request_record(i: &[u8]) -> IResult<&[u8], SmbRequestReadAndXRecord> {
    let (i, wct) = le_u8(i)?;
    let (i, _andx_command) = le_u8(i)?;
    let (i, _) = take(1_usize)(i)?; // reserved
    let (i, _andx_offset) = le_u16(i)?;
    let (i, fid) = take(2_usize)(i)?;
    let (i, offset) = le_u32(i)?;
    let (i, max_count_low) = le_u16(i)?;
    let (i, _) = take(2_usize)(i)?;
    let (i, max_count_high) = le_u32(i)?;
    let (i, _) = take(2_usize)(i)?;
    let (i, high_offset) = cond(wct == 12,le_u32)(i)?; // only from wct ==12?
    let record = SmbRequestReadAndXRecord {
        fid,
        size: (((max_count_high as u64) << 16)|max_count_low as u64),
        offset: if high_offset.is_some() { ((high_offset.unwrap() as u64) << 32)|(offset as u64) } else { 0 },
    };
    Ok((i, record))
}

#[derive(Debug,PartialEq)]
pub struct SmbResponseReadAndXRecord<'a> {
    pub len: u32,
    pub data: &'a[u8],
}

pub fn parse_smb_read_andx_response_record(i: &[u8]) -> IResult<&[u8], SmbResponseReadAndXRecord> {
    let (i, wct) = le_u8(i)?;
    let (i, _andx_command) = le_u8(i)?;
    let (i, _) = take(1_usize)(i)?; // reserved
    let (i, _andx_offset) = le_u16(i)?;
    let (i, _) = take(6_usize)(i)?;
    let (i, data_len_low) = le_u16(i)?;
    let (i, data_offset) = le_u16(i)?;
    let (i, data_len_high) = le_u32(i)?;
    let (i, _) = take(6_usize)(i)?; // reserved
    let (i, bcc) = le_u16(i)?;
    let (i, _padding) = cond(
        bcc > data_len_low,
        |b| take(bcc - data_len_low)(b)
    )(i)?; // TODO figure out how this works with data_len_high
    let (i, _padding_evasion) = cond(
        data_offset > 36+2*(wct as u16),
        |b| take(data_offset - (36+2*(wct as u16)))(b)
    )(i)?;
    let (i, file_data) = rest(i)?;

    let record = SmbResponseReadAndXRecord {
        len: (((data_len_high as u32) << 16)|data_len_low as u32),
        data: file_data,
   };
    Ok((i, record))
}

#[derive(Debug,PartialEq)]
pub struct SmbRequestRenameRecord {
    pub oldname: Vec<u8>,
    pub newname: Vec<u8>,
}

pub fn parse_smb_rename_request_record(i: &[u8]) -> IResult<&[u8], SmbRequestRenameRecord, SmbError> {
    let (i, _wct) = le_u8(i)?;
    let (i, _search_attr) = le_u16(i)?;
    let (i, _bcc) = le_u16(i)?;
    let (i, _oldtype) = le_u8(i)?;
    let (i, oldname) = smb_get_unicode_string(i)?;
    let (i, _newtype) = le_u8(i)?;
    let (i, newname) = smb_get_unicode_string_with_offset(i, 1)?; // HACK if we assume oldname is a series of utf16 chars offset would be 1
    let record = SmbRequestRenameRecord {
        oldname,
        newname
    };
    Ok((i, record))
}

#[derive(Debug,PartialEq)]
pub struct SmbRequestCreateAndXRecord<> {
    pub disposition: u32,
    pub create_options: u32,
    pub file_name: Vec<u8>,
}

pub fn parse_smb_create_andx_request_record<'a>(i: &'a[u8], r: &SmbRecord)
    -> IResult<&'a[u8], SmbRequestCreateAndXRecord<>, SmbError>
{
    let (i, _skip1) = take(6_usize)(i)?;
    let (i, file_name_len) = le_u16(i)?;
    let (i, _skip3) = take(28_usize)(i)?;
    let (i, disposition) = le_u32(i)?;
    let (i, create_options) = le_u32(i)?;
    let (i, _skip2) = take(5_usize)(i)?;
    let (i, bcc) = le_u16(i)?;
    let (i, file_name) = cond(
        bcc >= file_name_len,
        |b| smb1_get_string(b, r, (bcc - file_name_len) as usize)
    )(i)?;
    let (i, _skip3) = rest(i)?;
    let record = SmbRequestCreateAndXRecord {
        disposition,
        create_options,
        file_name: file_name.unwrap_or_default(),
    };
    Ok((i, record))
}

#[derive(Debug,PartialEq)]
pub struct Trans2RecordParamSetFileInfoDisposition<> {
    pub delete: bool,
}

pub fn parse_trans2_request_data_set_file_info_disposition(i: &[u8])
    -> IResult<&[u8], Trans2RecordParamSetFileInfoDisposition> {
    let (i, delete) = le_u8(i)?;
    let record = Trans2RecordParamSetFileInfoDisposition {
        delete: delete & 1 == 1,
    };
    Ok((i, record))
}

#[derive(Debug,PartialEq)]
pub struct Trans2RecordParamSetFileInfo<'a> {
    pub fid: &'a[u8],
    pub loi: u16,
}

pub fn parse_trans2_request_params_set_file_info(i: &[u8]) -> IResult<&[u8], Trans2RecordParamSetFileInfo> {
    let (i, fid) = take(2_usize)(i)?;
    let (i, loi) = le_u16(i)?;
    let record = Trans2RecordParamSetFileInfo { fid, loi };
    Ok((i, record))
}

#[derive(Debug,PartialEq)]
pub struct Trans2RecordParamSetFileInfoRename<'a> {
    pub replace: bool,
    pub newname: &'a[u8],
}

pub fn parse_trans2_request_data_set_file_info_rename(i: &[u8]) -> IResult<&[u8], Trans2RecordParamSetFileInfoRename> {
    let (i, replace) = le_u8(i)?;
    let (i, _reserved) = take(3_usize)(i)?;
    let (i, _root_dir) = take(4_usize)(i)?;
    let (i, newname_len) = le_u32(i)?;
    let (i, newname) = take(newname_len)(i)?;
    let record = Trans2RecordParamSetFileInfoRename {
        replace: replace==1,
        newname,
    };
    Ok((i, record))
}

#[derive(Debug,PartialEq)]
pub struct Trans2RecordParamSetPathInfo<> {
    pub loi: u16,
    pub oldname: Vec<u8>,
}

pub fn parse_trans2_request_params_set_path_info(i: &[u8]) -> IResult<&[u8], Trans2RecordParamSetPathInfo, SmbError> {
    let (i, loi) = le_u16(i)?;
    let (i, _reserved) = take(4_usize)(i)?;
    let (i, oldname) = smb_get_unicode_string(i)?;
    let record = Trans2RecordParamSetPathInfo { loi, oldname };
    Ok((i, record))
}

#[derive(Debug,PartialEq)]
pub struct Trans2RecordParamSetPathInfoRename<'a> {
    pub replace: bool,
    pub newname: &'a[u8],
}

pub fn parse_trans2_request_data_set_path_info_rename(i: &[u8]) -> IResult<&[u8], Trans2RecordParamSetPathInfoRename> {
    let (i, replace) = le_u8(i)?;
    let (i, _reserved) = take(3_usize)(i)?;
    let (i, _root_dir) = take(4_usize)(i)?;
    let (i, newname_len) = le_u32(i)?;
    let (i, newname) = take(newname_len)(i)?;
    let record = Trans2RecordParamSetPathInfoRename {
        replace: replace==1,
        newname
    };
    Ok((i, record))
}

#[derive(Debug,PartialEq)]
pub struct SmbRequestTrans2Record<'a> {
    pub subcmd: u16,
    pub setup_blob: &'a[u8],
    pub data_blob: &'a[u8],
}

pub fn parse_smb_trans2_request_record(i: &[u8]) -> IResult<&[u8], SmbRequestTrans2Record> {
    let (i, _wct) = le_u8(i)?;
    let (i, _total_param_cnt) = le_u16(i)?;
    let (i, _total_data_cnt) = le_u16(i)?;
    let (i, _max_param_cnt) = le_u16(i)?;
    let (i, _max_data_cnt) = le_u16(i)?;
    let (i, _max_setup_cnt) = le_u8(i)?;
    let (i, _reserved1) = take(1_usize)(i)?;
    let (i, _flags) = le_u16(i)?;
    let (i, _timeout) = le_u32(i)?;
    let (i, _reserved2) = take(2_usize)(i)?;
    let (i, param_cnt) = le_u16(i)?;
    let (i, param_offset) = verify(le_u16, |&v| v <= (u16::MAX - param_cnt))(i)?;
    let (i, data_cnt) = le_u16(i)?;
    let (i, data_offset) = le_u16(i)?;
    let (i, _setup_cnt) = le_u8(i)?;
    let (i, _reserved3) = take(1_usize)(i)?;
    let (i, subcmd) = le_u16(i)?;
    let (i, _bcc) = le_u16(i)?;
    //TODO test and use param_offset
    let (i, _padding) = take(3_usize)(i)?;
    let (i, setup_blob) = take(param_cnt)(i)?;
    let (i, _padding2) = cond(
        data_offset > param_offset + param_cnt,
        |b| take(data_offset - param_offset - param_cnt)(b)
    )(i)?;
    let (i, data_blob) = take(data_cnt)(i)?;

    let record = SmbRequestTrans2Record {
        subcmd,
        setup_blob,
        data_blob
    };
    Ok((i, record))
}

#[derive(Debug,PartialEq)]
pub struct SmbResponseCreateAndXRecord<'a> {
    pub fid: &'a[u8],
    pub create_ts: SMBFiletime,
    pub last_access_ts: SMBFiletime,
    pub last_write_ts: SMBFiletime,
    pub last_change_ts: SMBFiletime,
    pub file_size: u64,
}

pub fn parse_smb_create_andx_response_record(i: &[u8]) -> IResult<&[u8], SmbResponseCreateAndXRecord> {
    let (i, wct) = le_u8(i)?;
    let (i, _andx_command) = le_u8(i)?;
    let (i, _) = take(1_usize)(i)?; // reserved
    let (i, _andx_offset) = le_u16(i)?;
    let (i, _oplock_level) = le_u8(i)?;
    let (i, fid) = take(2_usize)(i)?;
    let (i, _create_action) = le_u32(i)?;
    let (i, create_ts) = le_u64(i)?;
    let (i, last_access_ts) = le_u64(i)?;
    let (i, last_write_ts) = le_u64(i)?;
    let (i, last_change_ts) = le_u64(i)?;
    let (i, _) = take(4_usize)(i)?;
    let (i, file_size) = le_u64(i)?;
    let (i, _eof) = le_u64(i)?;
    let (i, _file_type) = le_u16(i)?;
    let (i, _ipc_state) = le_u16(i)?;
    let (i, _is_dir) = le_u8(i)?;
    let (i, _) = cond(wct == 42, take(32_usize))(i)?;
    let (i, _bcc) = le_u16(i)?;
    let record = SmbResponseCreateAndXRecord {
        fid,
        create_ts: SMBFiletime::new(create_ts),
        last_access_ts: SMBFiletime::new(last_access_ts),
        last_write_ts: SMBFiletime::new(last_write_ts),
        last_change_ts: SMBFiletime::new(last_change_ts),
        file_size,
    };
    Ok((i, record))
}

#[derive(Debug,PartialEq)]
pub struct SmbRequestCloseRecord<'a> {
    pub fid: &'a[u8],
}

pub fn parse_smb1_close_request_record(i: &[u8]) -> IResult<&[u8], SmbRequestCloseRecord> {
    let (i, _) = take(1_usize)(i)?;
    let (i, fid) = take(2_usize)(i)?;
    let record = SmbRequestCloseRecord {
        fid,
    };
    Ok((i, record))
}

#[derive(Debug,PartialEq)]
pub struct SmbVersion<> {
    pub version: u8,
}

pub fn parse_smb_version(i: &[u8]) -> IResult<&[u8], SmbVersion> {
    let (i, version) = le_u8(i)?;
    let (i, _) = tag(b"SMB")(i)?;
    let version = SmbVersion { version };
    Ok((i, version))
}

#[derive(Debug,PartialEq)]
pub struct SmbRecord<'a> {
    pub command: u8,
    pub is_dos_error: bool,
    pub nt_status: u32,
    pub flags: u8,
    pub flags2: u16,

    pub tree_id: u16,
    pub user_id: u16,
    pub multiplex_id: u16,

    pub process_id: u32,
    pub ssn_id: u32,

    pub data: &'a[u8],
}

impl<'a> SmbRecord<'a> {
    pub fn has_unicode_support(&self) -> bool {
        self.flags2 & 0x8000_u16 != 0
    }
    pub fn is_dos_error(&self) -> bool {
        self.flags2 & 0x4000_u16 != 0
    }

    /// Return true if record is a request.
    pub fn is_request(&self) -> bool {
        self.flags & SMB1_FLAGS_RESPONSE == 0
    }

    /// Return true if record is a reply.
    pub fn is_response(&self) -> bool {
        self.flags & SMB1_FLAGS_RESPONSE != 0
    }
}

pub fn parse_smb_record(i: &[u8]) -> IResult<&[u8], SmbRecord> {
    let (i, _) = tag(b"\xffSMB")(i)?;
    let (i, command) = le_u8(i)?;
    let (i, nt_status) = le_u32(i)?;
    let (i, flags) = le_u8(i)?;
    let (i, flags2) = le_u16(i)?;
    let (i, process_id_high) = le_u16(i)?;
    let (i, _signature) = take(8_usize)(i)?;
    let (i, _reserved) = take(2_usize)(i)?;
    let (i, tree_id) = le_u16(i)?;
    let (i, process_id) = le_u16(i)?;
    let (i, user_id) = le_u16(i)?;
    let (i, multiplex_id) = le_u16(i)?;
    let (i, data) = rest(i)?;

    let record = SmbRecord {
        command,
        nt_status,
        flags,
        flags2,
        is_dos_error: (flags2 & 0x4000_u16 == 0),// && nt_status != 0),
        tree_id,
        user_id,
        multiplex_id,

        process_id: (process_id_high as u32) << 16 | process_id as u32,
        //ssn_id: (((process_id as u32)<< 16)|(user_id as u32)),
        ssn_id: user_id as u32,
        data,
    };
    Ok((i, record))
}
