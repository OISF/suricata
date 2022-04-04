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

use crate::smb::error::SmbError;
use crate::smb::smb::*;
use crate::smb::smb_records::*;
use nom::bytes::streaming:: take;
use nom::combinator::{cond, rest, verify};
use nom::number::streaming::{le_u8, le_u16, le_u32, le_u64};
use nom::IResult;


// SMB_FLAGS_REPLY in Microsoft docs.
const SMB1_FLAGS_RESPONSE: u8 = 0x80;

fn smb_get_unicode_string_with_offset(i: &[u8], offset: usize) -> IResult<&[u8], Vec<u8>, SmbError>
{
    do_parse!(i,
            cond!(offset % 2 == 1, take!(1))
        >>  s: call!(smb_get_unicode_string)
        >> ( s )
    )
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
pub struct Smb1WriteRequestRecord<'a> {
    pub offset: u64,
    pub len: u32,
    pub fid: &'a[u8],
    pub data: &'a[u8],
}

named!(pub parse_smb1_write_request_record<Smb1WriteRequestRecord>,
    do_parse!(
            _wct: le_u8
        >>  fid: take!(2)
        >>  _count: le_u16
        >>  offset: le_u32
        >>  _remaining: le_u16
        >>  _bcc: le_u16
        >>  _buffer_format: le_u8
        >>  data_len: le_u16
        >>  file_data: take!(data_len)
        >> (Smb1WriteRequestRecord {
                offset: offset as u64,
                len: data_len as u32,
                fid,
                data:file_data,
            }))
);

named!(pub parse_smb1_write_andx_request_record<Smb1WriteRequestRecord>,
    do_parse!(
            wct: le_u8
        >>  _andx_command: le_u8
        >>  take!(1)    // reserved
        >>  _andx_offset: le_u16
        >>  fid: take!(2)
        >>  offset: le_u32
        >>  take!(4)    // reserved
        >>  _write_mode: le_u16
        >>  _remaining: le_u16
        >>  data_len_high: le_u16
        >>  data_len_low: le_u16
        >>  data_offset: le_u16
        >>  high_offset: cond!(wct==14,le_u32)
        >>  bcc: le_u16
        //spec [MS-CIFS].pdf says always take one byte padding
        >>  _padding: cond!(bcc > data_len_low, take!(bcc - data_len_low)) // TODO figure out how this works with data_len_high
        >>  _padding_evasion: cond!(data_offset > 36+2*(wct as u16), take!(data_offset - (36+2*(wct as u16))))
        >>  file_data: rest
        >> (Smb1WriteRequestRecord {
                offset: if high_offset != None { ((high_offset.unwrap() as u64) << 32)|(offset as u64) } else { 0 },
                len: (((data_len_high as u32) << 16) as u32)|(data_len_low as u32),
                fid,
                data:file_data,
            }))
);

named!(pub parse_smb1_write_and_close_request_record<Smb1WriteRequestRecord>,
    do_parse!(
            _wct: le_u8
        >>  fid: take!(2)
        >>  count: le_u16
        >>  offset: le_u32
        >>  _last_write: take!(4)
        >>  bcc: le_u16
        >>  _padding: cond!(bcc > count, take!(bcc - count))
        >>  file_data: take!(count)
        >> (Smb1WriteRequestRecord {
                offset: offset as u64,
                len: count as u32,
                fid,
                data:file_data,
            }))
);

#[derive(Debug,PartialEq)]
pub struct Smb1NegotiateProtocolResponseRecord<'a> {
    pub dialect_idx: u16,
    pub server_guid: &'a[u8],
}

named!(pub parse_smb1_negotiate_protocol_response_record_error<Smb1NegotiateProtocolResponseRecord>,
    do_parse!(
            _wct: le_u8
         >> _bcc: le_u16
         >> ( Smb1NegotiateProtocolResponseRecord {
                dialect_idx: 0,
                server_guid: &[],
            })
));

named!(pub parse_smb1_negotiate_protocol_response_record_ok<Smb1NegotiateProtocolResponseRecord>,
    do_parse!(
            _wct: le_u8
        >>  dialect_idx: le_u16
        >>  _sec_mode: le_u8
        >>  take!(16)
        >>  _caps: le_u32
        >>  _sys_time: le_u64
        >>  _server_tz: le_u16
        >>  _challenge_len: le_u8
        >>  bcc: le_u16
        >>  server_guid: cond!(bcc >= 16, take!(16))
        >> (Smb1NegotiateProtocolResponseRecord {
                dialect_idx,
                server_guid: server_guid.unwrap_or(&[]),
            }))
);

named!(pub parse_smb1_negotiate_protocol_response_record<Smb1NegotiateProtocolResponseRecord>,
    switch!(peek!(le_u8),
        0 => call!(parse_smb1_negotiate_protocol_response_record_error) |
        _ => call!(parse_smb1_negotiate_protocol_response_record_ok)
    ));

#[derive(Debug,PartialEq)]
pub struct Smb1NegotiateProtocolRecord<'a> {
    pub dialects: Vec<&'a [u8]>,
}

named!(pub parse_smb1_negotiate_protocol_record<Smb1NegotiateProtocolRecord>,
    do_parse!(
           _wtc: le_u8
        >> _bcc: le_u16
        // dialects is a list of [1 byte buffer format][string][0 terminator]
        >> dialects: many1!(complete!(take_until_and_consume!("\0")))
        >> (Smb1NegotiateProtocolRecord {
                dialects
            }))
);


#[derive(Debug,PartialEq)]
pub struct Smb1ResponseRecordTreeConnectAndX<'a> {
    pub service: &'a[u8],
    pub nativefs: &'a[u8],
}

named!(pub parse_smb_connect_tree_andx_response_record<Smb1ResponseRecordTreeConnectAndX>,
    do_parse!(
            wct: le_u8
        >>  _andx_command: le_u8
        >>  take!(1)    // reserved
        >>  _andx_offset: le_u16
        >>  cond!(wct >= 3, take!(2))   // optional support
        >>  cond!(wct == 7, take!(8))   // access masks
        >>  _bcc: le_u16
        >>  service: take_until_and_consume!("\x00")
        >>  nativefs: take_until_and_consume!("\x00")
        >> (Smb1ResponseRecordTreeConnectAndX {
                service,
                nativefs
           }))
);

#[derive(Debug,PartialEq)]
pub struct SmbRecordTreeConnectAndX<'a> {
    pub path: Vec<u8>,
    pub service: &'a[u8],
}

pub fn parse_smb_connect_tree_andx_record<'a>(i: &'a[u8], r: &SmbRecord) -> IResult<&'a[u8], SmbRecordTreeConnectAndX<'a>, SmbError> {
    do_parse!(i,
       _skip1: take!(7)
       >> pwlen: le_u16
       >> _bcc: le_u16
       >> _pw: take!(pwlen)
       >> path: call!(smb1_get_string, r, 11 + pwlen as usize)
       >> service: take_until_and_consume!("\x00")
       >> (SmbRecordTreeConnectAndX {
                path,
                service
           }))
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

named!(pub parse_smb_trans_request_record_pipe<&[u8], SmbPipeProtocolRecord, SmbError>,
    do_parse!(
            fun: le_u16
        >>  fid: take!(2)
        >> (SmbPipeProtocolRecord {
                function: fun,
                fid
            })
    )
);


#[derive(Debug,PartialEq)]
pub struct SmbRecordTransRequestParams<> {
    pub max_data_cnt: u16,
    param_cnt: u16,
    param_offset: u16,
    data_cnt: u16,
    data_offset: u16,
    bcc: u16,
}

named!(pub parse_smb_trans_request_record_params<&[u8], (SmbRecordTransRequestParams, Option<SmbPipeProtocolRecord>), SmbError>,
    do_parse!(
          wct: le_u8
       >> _total_param_cnt: le_u16
       >> _total_data_count: le_u16
       >> _max_param_cnt: le_u16
       >> max_data_cnt: le_u16
       >> _max_setup_cnt: le_u8
       >> take!(1) // reserved
       >> take!(2) // flags
       >> _timeout: le_u32
       >> take!(2) // reserved
       >> param_cnt: le_u16
       >> param_offset: le_u16
       >> data_cnt: le_u16
       >> data_offset: le_u16
       >> setup_cnt: le_u8
       >> take!(1) // reserved
       >> pipe: cond!(wct == 16 && setup_cnt == 2 && data_cnt > 0, parse_smb_trans_request_record_pipe)
       >> bcc: le_u16
       >> (( SmbRecordTransRequestParams {
                max_data_cnt,
                param_cnt,
                param_offset,
                data_cnt,
                data_offset,
                bcc
            },
            pipe)))
);

#[derive(Debug,PartialEq)]
pub struct SmbRecordTransRequestData<'a> {
    pub data: &'a[u8],
}

pub fn parse_smb_trans_request_record_data(i: &[u8],
        pad1: usize, param_cnt: u16, pad2: usize, data_len: u16)
    -> IResult<&[u8], SmbRecordTransRequestData, SmbError>
{
    do_parse!(i,
            take!(pad1)
        >>  take!(param_cnt)
        >>  take!(pad2)
        >>  data: take!(data_len)
        >> (SmbRecordTransRequestData {
                data:data,
            })
    )
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
        params: params, pipe: pipe, txname: n, data: recdata,
    };
    Ok((&rem, res))
}


#[derive(Debug,PartialEq)]
pub struct SmbRecordTransResponse<'a> {
    pub data_cnt: u16,
    pub bcc: u16,
    pub data: &'a[u8],
}

named!(pub parse_smb_trans_response_error_record<SmbRecordTransResponse>,
    do_parse!(
          _wct: le_u8
       >> bcc: le_u16
       >> (SmbRecordTransResponse {
                data_cnt:0,
                bcc:bcc,
                data:&[],
           }))
);

named!(pub parse_smb_trans_response_regular_record<SmbRecordTransResponse>,
    do_parse!(
          wct: le_u8
       >> _total_param_cnt: le_u16
       >> _total_data_count: le_u16
       >> take!(2) // reserved
       >> _param_cnt: le_u16
       >> _param_offset: le_u16
       >> _param_displacement: le_u16
       >> data_cnt: le_u16
       >> data_offset: le_u16
       >> _data_displacement: le_u16
       >> _setup_cnt: le_u8
       >> take!(1) // reserved
       >> bcc: le_u16
       >> take!(1) // padding
       >> _padding_evasion: cond!(data_offset > 36+2*(wct as u16), take!(data_offset - (36+2*(wct as u16))))
       >> data: take!(data_cnt)
       >> (SmbRecordTransResponse {
                data_cnt,
                bcc,
                data
           }))
);

named!(pub parse_smb_trans_response_record<SmbRecordTransResponse>,
    switch!(peek!(le_u8), // wct
        0 => call!(parse_smb_trans_response_error_record) |
        _ => call!(parse_smb_trans_response_regular_record))
);

#[derive(Debug,PartialEq)]
pub struct SmbRecordSetupAndX<'a> {
    pub sec_blob: &'a[u8],
}

named!(pub parse_smb_setup_andx_record<SmbRecordSetupAndX>,
    do_parse!(
          _skip1: take!(15)
       >> sec_blob_len: le_u16
       >> _skip2: take!(8)
       >> _bcc: le_u16
       >> sec_blob: take!(sec_blob_len)
       >> (SmbRecordSetupAndX {
                sec_blob
           }))
);

#[derive(Debug,PartialEq)]
pub struct SmbResponseRecordSetupAndX<'a> {
    pub sec_blob: &'a[u8],
}

named!(response_setup_andx_record<SmbResponseRecordSetupAndX>,
    do_parse!(
          _skip1: take!(7)
       >> sec_blob_len: le_u16
       >> _bcc: le_u16
       >> sec_blob: take!(sec_blob_len)
       >> (SmbResponseRecordSetupAndX {
                sec_blob
           }))
);

named!(response_setup_andx_wct3_record<SmbResponseRecordSetupAndX>,
    do_parse!(
          _skip1: take!(7)
       >> _bcc: le_u16
       >> (SmbResponseRecordSetupAndX {
                sec_blob:&[],
           }))
);

named!(response_setup_andx_error_record<SmbResponseRecordSetupAndX>,
    do_parse!(
          _wct: le_u8
       >> _bcc: le_u16
       >> (SmbResponseRecordSetupAndX {
                sec_blob: &[],
           }))
);

named!(pub parse_smb_response_setup_andx_record<SmbResponseRecordSetupAndX>,
    switch!(peek!(le_u8), // wct
        0 => call!(response_setup_andx_error_record) |
        3 => call!(response_setup_andx_wct3_record)  |
        _ => call!(response_setup_andx_record))
);

#[derive(Debug,PartialEq)]
pub struct SmbRequestReadAndXRecord<'a> {
    pub fid: &'a[u8],
    pub size: u64,
    pub offset: u64,
}

named!(pub parse_smb_read_andx_request_record<SmbRequestReadAndXRecord>,
    do_parse!(
            wct: le_u8
        >>  _andx_command: le_u8
        >>  take!(1)    // reserved
        >>  _andx_offset: le_u16
        >>  fid: take!(2)
        >>  offset: le_u32
        >>  max_count_low: le_u16
        >>  take!(2)
        >>  max_count_high: le_u32
        >>  take!(2)
        >>  high_offset: cond!(wct==12,le_u32) // only from wct ==12?
        >> (SmbRequestReadAndXRecord {
                fid,
                size: (((max_count_high as u64) << 16)|max_count_low as u64),
                offset: if high_offset != None { ((high_offset.unwrap() as u64) << 32)|(offset as u64) } else { 0 },
           }))
);

#[derive(Debug,PartialEq)]
pub struct SmbResponseReadAndXRecord<'a> {
    pub len: u32,
    pub data: &'a[u8],
}

named!(pub parse_smb_read_andx_response_record<SmbResponseReadAndXRecord>,
    do_parse!(
            wct: le_u8
        >>  _andx_command: le_u8
        >>  take!(1)    // reserved
        >>  _andx_offset: le_u16
        >>  take!(6)
        >>  data_len_low: le_u16
        >>  data_offset: le_u16
        >>  data_len_high: le_u32
        >>  take!(6)    // reserved
        >>  bcc: le_u16
        >>  _padding: cond!(bcc > data_len_low, take!(bcc - data_len_low)) // TODO figure out how this works with data_len_high
        >>  _padding_evasion: cond!(data_offset > 36+2*(wct as u16), take!(data_offset - (36+2*(wct as u16))))
        >>  file_data: rest

        >> (SmbResponseReadAndXRecord {
                len: (((data_len_high as u32) << 16)|data_len_low as u32),
                data:file_data,
           }))
);

#[derive(Debug,PartialEq)]
pub struct SmbRequestRenameRecord {
    pub oldname: Vec<u8>,
    pub newname: Vec<u8>,
}

named!(pub parse_smb_rename_request_record<&[u8], SmbRequestRenameRecord, SmbError>,
    do_parse!(
            _wct: le_u8
        >>  _search_attr: le_u16
        >>  _bcc: le_u16
        >>  _oldtype: le_u8
        >>  oldname: smb_get_unicode_string
        >>  _newtype: le_u8
        >>  newname: call!(smb_get_unicode_string_with_offset, 1) // HACK if we assume oldname is a series of utf16 chars offset would be 1
        >> (SmbRequestRenameRecord {
                oldname,
                newname
           }))
);

#[derive(Debug,PartialEq)]
pub struct SmbRequestCreateAndXRecord<> {
    pub disposition: u32,
    pub create_options: u32,
    pub file_name: Vec<u8>,
}

pub fn parse_smb_create_andx_request_record<'a>(i: &'a[u8], r: &SmbRecord)
    -> IResult<&'a[u8], SmbRequestCreateAndXRecord<>, SmbError>
{
    do_parse!(i,
          _skip1: take!(6)
       >> file_name_len: le_u16
       >> _skip3: take!(28)
       >> disposition: le_u32
       >> create_options: le_u32
       >> _skip2: take!(5)
       >> bcc: le_u16
       >> file_name: cond!(bcc >= file_name_len, call!(smb1_get_string, r, (bcc - file_name_len) as usize))
       >> _skip3: rest
       >> (SmbRequestCreateAndXRecord {
                disposition: disposition,
                create_options: create_options,
                file_name: file_name.unwrap_or(Vec::new()),
           }))
}

#[derive(Debug,PartialEq)]
pub struct Trans2RecordParamSetFileInfoDisposition<> {
    pub delete: bool,
}

named!(pub parse_trans2_request_data_set_file_info_disposition<Trans2RecordParamSetFileInfoDisposition>,
    do_parse!(
            delete: le_u8
        >>  _reserved: take!(3)
        >> (Trans2RecordParamSetFileInfoDisposition {
                delete: delete & 1 == 1,
            })
));

#[derive(Debug,PartialEq)]
pub struct Trans2RecordParamSetFileInfo<'a> {
    pub fid: &'a[u8],
    pub loi: u16,
}

named!(pub parse_trans2_request_params_set_file_info<Trans2RecordParamSetFileInfo>,
    do_parse!(
            fid: take!(2)
        >>  loi: le_u16
        >> (Trans2RecordParamSetFileInfo {
                fid:fid,
                loi:loi,
            })
));

#[derive(Debug,PartialEq)]
pub struct Trans2RecordParamSetFileInfoRename<'a> {
    pub replace: bool,
    pub newname: &'a[u8],
}

named!(pub parse_trans2_request_data_set_file_info_rename<Trans2RecordParamSetFileInfoRename>,
    do_parse!(
            replace: le_u8
        >>  _reserved: take!(3)
        >>  _root_dir: take!(4)
        >>  newname_len: le_u32
        >>  newname: take!(newname_len)
        >> (Trans2RecordParamSetFileInfoRename {
                replace: replace==1,
                newname: newname,
            })
));

#[derive(Debug,PartialEq)]
pub struct Trans2RecordParamSetPathInfo<> {
    pub loi: u16,
    pub oldname: Vec<u8>,
}

named!(pub parse_trans2_request_params_set_path_info<&[u8], Trans2RecordParamSetPathInfo, SmbError>,
    do_parse!(
            loi: le_u16
        >>  _reserved: take!(4)
        >>  oldname: call!(smb_get_unicode_string)
        >> (Trans2RecordParamSetPathInfo {
                loi,
                oldname
            })
));

#[derive(Debug,PartialEq)]
pub struct Trans2RecordParamSetPathInfoRename<'a> {
    pub replace: bool,
    pub newname: &'a[u8],
}

named!(pub parse_trans2_request_data_set_path_info_rename<Trans2RecordParamSetPathInfoRename>,
    do_parse!(
            replace: le_u8
        >>  _reserved: take!(3)
        >>  _root_dir: take!(4)
        >>  newname_len: le_u32
        >>  newname: take!(newname_len)
        >> (Trans2RecordParamSetPathInfoRename {
                replace: replace==1,
                newname
            })
));

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

named!(pub parse_smb_create_andx_response_record<SmbResponseCreateAndXRecord>,
    do_parse!(
            wct: le_u8
        >>  _andx_command: le_u8
        >>  take!(1)    // reserved
        >>  _andx_offset: le_u16
        >>  _oplock_level: le_u8
        >>  fid: take!(2)
        >>  _create_action: le_u32
        >>  create_ts: le_u64
        >>  last_access_ts: le_u64
        >>  last_write_ts: le_u64
        >>  last_change_ts: le_u64
        >>  take!(4)
        >>  file_size: le_u64
        >>  _eof: le_u64
        >>  _file_type: le_u16
        >>  _ipc_state: le_u16
        >>  _is_dir: le_u8
        >>  cond!(wct == 42, take!(32))
        >>  _bcc: le_u16
        >> (SmbResponseCreateAndXRecord {
                fid:fid,
                create_ts: SMBFiletime::new(create_ts),
                last_access_ts: SMBFiletime::new(last_access_ts),
                last_write_ts: SMBFiletime::new(last_write_ts),
                last_change_ts: SMBFiletime::new(last_change_ts),
                file_size:file_size,
           }))
);

#[derive(Debug,PartialEq)]
pub struct SmbRequestCloseRecord<'a> {
    pub fid: &'a[u8],
}

named!(pub parse_smb1_close_request_record<SmbRequestCloseRecord>,
    do_parse!(
            take!(1)
        >>  fid: take!(2)
       >> (SmbRequestCloseRecord {
                fid:fid,
           }))
);

#[derive(Debug,PartialEq)]
pub struct SmbVersion<> {
    pub version: u8,
}

named!(pub parse_smb_version<SmbVersion>,
    do_parse!(
        version: le_u8
        >> tag!("SMB")
        >> (SmbVersion {
                version:version,
            }))
);

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

named!(pub parse_smb_record<SmbRecord>,
    do_parse!(
            tag!(b"\xffSMB")
        >>  command:le_u8
        >>  nt_status:le_u32
        >>  flags:le_u8
        >>  flags2:le_u16
        >>  process_id_high:le_u16
        >>  _signature:take!(8)
        >>  _reserved:take!(2)
        >>  tree_id:le_u16
        >>  process_id:le_u16
        >>  user_id:le_u16
        >>  multiplex_id:le_u16
        >>  data: rest

        >>  (SmbRecord {
                command:command,
                nt_status:nt_status,
                flags:flags,
                flags2:flags2,
                is_dos_error: (flags2 & 0x4000_u16 == 0),// && nt_status != 0),
                tree_id:tree_id,
                user_id:user_id,
                multiplex_id:multiplex_id,

                process_id: (process_id_high as u32) << 16 | process_id as u32,
                //ssn_id: (((process_id as u32)<< 16)|(user_id as u32)),
                ssn_id: user_id as u32,
                data:data,
            })
));
