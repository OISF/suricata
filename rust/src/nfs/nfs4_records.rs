/* Copyright (C) 2018 Open Information Security Foundation
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

//! Nom parsers for NFSv4 records
use nom7::bytes::streaming::{tag, take};
use nom7::combinator::{complete, cond, map, peek};
use nom7::error::{make_error, ErrorKind};
use nom7::multi::{count, many_till};
use nom7::number::streaming::{be_u32, be_u64};
use nom7::{Err, IResult};

use crate::nfs::types::*;

#[derive(Debug,PartialEq)]
pub enum Nfs4RequestContent<'a> {
    PutFH(Nfs4Handle<'a>),
    GetFH,
    SaveFH,
    PutRootFH,
    ReadDir,
    Commit,
    Open(Nfs4RequestOpen<'a>),
    Lookup(Nfs4RequestLookup<'a>),
    Read(Nfs4RequestRead<'a>),
    Write(Nfs4RequestWrite<'a>),
    Close(Nfs4StateId<'a>),
    Rename(Nfs4RequestRename<'a>),
    Create(Nfs4RequestCreate<'a>),
    OpenConfirm(Nfs4RequestOpenConfirm<'a>),
    Access(u32),
    GetAttr(Nfs4Attr),
    SetAttr(Nfs4RequestSetAttr<'a>),
    Renew(u64),
    Remove(&'a[u8]),
    DelegReturn(Nfs4StateId<'a>),
    SetClientId(Nfs4RequestSetClientId<'a>),
    SetClientIdConfirm,
    ExchangeId(Nfs4RequestExchangeId<'a>),
    Sequence(Nfs4RequestSequence<'a>),
}

#[derive(Debug,PartialEq)]
pub struct Nfs4Attr {
    attr_mask: u64,
}

fn nfs4_parse_attr_fields(i: &[u8]) -> IResult<&[u8], u32> {
    let (i, len) = be_u32(i)?;
    let (i, _) = take(len as usize)(i)?;
    Ok((i, len))
}

fn nfs4_parse_attrs(i: &[u8]) -> IResult<&[u8], Nfs4Attr> {
    let (i, attr_cnt) = be_u32(i)?;
    let (i, attr_mask1) = be_u32(i)?;
    let (i, attr_mask2) = cond(attr_cnt >= 2, be_u32)(i)?;
    let (i, _) = cond(attr_cnt == 3, be_u32)(i)?;
    let (i, _) = nfs4_parse_attr_fields(i)?;
    let attr = Nfs4Attr {
        attr_mask: ((attr_mask1 as u64) << 32) | attr_mask2.unwrap_or(0) as u64,
    };
    Ok((i, attr))
}

fn nfs4_parse_attrbits(i: &[u8]) -> IResult<&[u8], Nfs4Attr> {
    let (i, attr_cnt) = be_u32(i)?;
    let (i, attr_mask1) = be_u32(i)?;
    let (i, attr_mask2) = cond(attr_cnt >= 2, be_u32)(i)?;
    let (i, _) = cond(attr_cnt == 3, be_u32)(i)?;
    let attr = Nfs4Attr {
        attr_mask: ((attr_mask1 as u64) << 32) | attr_mask2.unwrap_or(0) as u64,
    };
    Ok((i, attr))
}

#[derive(Debug,PartialEq)]
pub struct Nfs4StateId<'a> {
    pub seqid: u32,
    pub data: &'a[u8],
}

fn nfs4_parse_stateid(i: &[u8]) -> IResult<&[u8], Nfs4StateId> {
    let (i, seqid) = be_u32(i)?;
    let (i, data) = take(12_usize)(i)?;
    let state = Nfs4StateId { seqid, data };
    Ok((i, state))
}

#[derive(Debug,PartialEq)]
pub struct Nfs4Handle<'a> {
    pub len: u32,
    pub value: &'a[u8],
}

fn nfs4_parse_handle(i: &[u8]) -> IResult<&[u8], Nfs4Handle> {
    let (i, len) = be_u32(i)?;
    let (i, value) = take(len as usize)(i)?;
    let handle = Nfs4Handle { len, value };
    Ok((i, handle))
}

fn nfs4_parse_nfsstring(i: &[u8]) -> IResult<&[u8], &[u8]> {
    let (i, len) = be_u32(i)?;
    let (i, data) = take(len as usize)(i)?;
    let (i, _fill_bytes) = cond(len % 4 != 0, take(4 - (len % 4)))(i)?;
    Ok((i, data))
}

fn nfs4_req_putfh(i: &[u8]) -> IResult<&[u8], Nfs4RequestContent> {
    map(nfs4_parse_handle, Nfs4RequestContent::PutFH)(i)
}

#[derive(Debug,PartialEq)]
pub struct Nfs4RequestSetClientId<'a> {
    pub client_id: &'a[u8],
    pub r_netid: &'a[u8],
    pub r_addr: &'a[u8],
}

fn nfs4_req_setclientid(i: &[u8]) -> IResult<&[u8], Nfs4RequestContent> {
    let (i, _client_verifier) = take(8_usize)(i)?;
    let (i, client_id) = nfs4_parse_nfsstring(i)?;
    let (i, _cb_program) = be_u32(i)?;
    let (i, r_netid) = nfs4_parse_nfsstring(i)?;
    let (i, r_addr) = nfs4_parse_nfsstring(i)?;
    let (i, _cb_id) = be_u32(i)?;
    let req = Nfs4RequestContent::SetClientId(Nfs4RequestSetClientId {
        client_id,
        r_netid,
        r_addr
    });
    Ok((i, req))
}

fn nfs4_req_setclientid_confirm(i: &[u8]) -> IResult<&[u8], Nfs4RequestContent> {
    let (i, _client_id) = take(8_usize)(i)?;
    let (i, _verifier) = take(8_usize)(i)?;
    Ok((i, Nfs4RequestContent::SetClientIdConfirm))
}

#[derive(Debug,PartialEq)]
pub struct Nfs4RequestCreate<'a> {
    pub ftype4: u32,
    pub filename: &'a[u8],
    pub link_content: &'a[u8],
}

fn nfs4_req_create(i: &[u8]) -> IResult<&[u8], Nfs4RequestContent> {
    let (i, ftype4) = be_u32(i)?;
    let (i, link_content) = cond(ftype4 == 5, nfs4_parse_nfsstring)(i)?;
    let (i, filename) = nfs4_parse_nfsstring(i)?;
    let (i, _attrs) = nfs4_parse_attrs(i)?;
    let req = Nfs4RequestContent::Create(Nfs4RequestCreate {
        ftype4,
        filename,
        link_content: link_content.unwrap_or(&[]),
    });
    Ok((i, req))
}

#[derive(Debug,PartialEq)]
pub enum Nfs4OpenRequestContent<'a> {
    Exclusive4(&'a[u8]),
    Unchecked4(Nfs4Attr),
    Guarded4(Nfs4Attr),
}

fn nfs4_req_open_unchecked4(i: &[u8]) -> IResult<&[u8], Nfs4OpenRequestContent> {
    map(nfs4_parse_attrs, Nfs4OpenRequestContent::Unchecked4)(i)
}

fn nfs4_req_open_guarded4(i: &[u8]) -> IResult<&[u8], Nfs4OpenRequestContent> {
    map(nfs4_parse_attrs, Nfs4OpenRequestContent::Guarded4)(i)
}

fn nfs4_req_open_exclusive4(i: &[u8]) -> IResult<&[u8], Nfs4OpenRequestContent> {
    map(take(8_usize), Nfs4OpenRequestContent::Exclusive4)(i)
}


fn nfs4_req_open_type(i: &[u8]) -> IResult<&[u8], Nfs4OpenRequestContent> {
    let (i, mode) = be_u32(i)?;
    let (i, data) = match mode {
        0 => nfs4_req_open_unchecked4(i)?,
        1 => nfs4_req_open_guarded4(i)?,
        2 => nfs4_req_open_exclusive4(i)?,
        _ => { return Err(Err::Error(make_error(i, ErrorKind::Switch))); }
    };
    Ok((i, data))
}

#[derive(Debug,PartialEq)]
pub struct Nfs4RequestOpen<'a> {
    pub open_type: u32,
    pub filename: &'a[u8],
    pub open_data: Option<Nfs4OpenRequestContent<'a>>,
}

fn nfs4_req_open(i: &[u8]) -> IResult<&[u8], Nfs4RequestContent> {
    let (i, _seq_id) = be_u32(i)?;
    let (i, _share_access) = be_u32(i)?;
    let (i, _share_deny) = be_u32(i)?;
    let (i, _client_id) = be_u64(i)?;
    let (i, owner_len) = be_u32(i)?;
    let (i, _) = cond(owner_len > 0, take(owner_len as usize))(i)?;
    let (i, open_type) = be_u32(i)?;
    let (i, open_data) = cond(open_type == 1, nfs4_req_open_type)(i)?;
    let (i, _claim_type) = be_u32(i)?;
    let (i, filename) = nfs4_parse_nfsstring(i)?;
    let req = Nfs4RequestContent::Open(Nfs4RequestOpen {
        open_type,
        filename,
        open_data
    });
    Ok((i, req))
}

fn nfs4_req_readdir(i: &[u8]) -> IResult<&[u8], Nfs4RequestContent> {
    let (i, _cookie) = be_u64(i)?;
    let (i, _cookie_verf) = be_u64(i)?;
    let (i, _dir_cnt) = be_u32(i)?;
    let (i, _max_cnt) = be_u32(i)?;
    let (i, _attr) = nfs4_parse_attrbits(i)?;
    Ok((i, Nfs4RequestContent::ReadDir))
}

#[derive(Debug,PartialEq)]
pub struct Nfs4RequestRename<'a> {
    pub oldname: &'a[u8],
    pub newname: &'a[u8],
}

fn nfs4_req_rename(i: &[u8]) -> IResult<&[u8], Nfs4RequestContent> {
    let (i, oldname) = nfs4_parse_nfsstring(i)?;
    let (i, newname) = nfs4_parse_nfsstring(i)?;
    let req = Nfs4RequestContent::Rename(Nfs4RequestRename {
        oldname,
        newname
    });
    Ok((i, req))
}

#[derive(Debug,PartialEq)]
pub struct Nfs4RequestLookup<'a> {
    pub filename: &'a[u8],
}

fn nfs4_req_lookup(i: &[u8]) -> IResult<&[u8], Nfs4RequestContent> {
    map(nfs4_parse_nfsstring, |filename| {
        Nfs4RequestContent::Lookup(Nfs4RequestLookup { filename })
    })(i)
}

fn nfs4_req_remove(i: &[u8]) -> IResult<&[u8], Nfs4RequestContent> {
    map(nfs4_parse_nfsstring, Nfs4RequestContent::Remove)(i)
}

#[derive(Debug,PartialEq)]
pub struct Nfs4RequestSetAttr<'a> {
    pub stateid: Nfs4StateId<'a>,
}

fn nfs4_req_setattr(i: &[u8]) -> IResult<&[u8], Nfs4RequestContent> {
    let (i, stateid) = nfs4_parse_stateid(i)?;
    let (i, _attrs) = nfs4_parse_attrs(i)?;
    let req = Nfs4RequestContent::SetAttr(Nfs4RequestSetAttr { stateid });
    Ok((i, req))
}

fn nfs4_req_getattr(i: &[u8]) -> IResult<&[u8], Nfs4RequestContent> {
    map(nfs4_parse_attrbits, Nfs4RequestContent::GetAttr)(i)
}

#[derive(Debug,PartialEq)]
pub struct Nfs4RequestWrite<'a> {
    pub stateid: Nfs4StateId<'a>,
    pub offset: u64,
    pub stable: u32,
    pub write_len: u32,
    pub data: &'a[u8],
}

fn nfs4_req_write(i: &[u8]) -> IResult<&[u8], Nfs4RequestContent> {
    let (i, stateid) = nfs4_parse_stateid(i)?;
    let (i, offset) = be_u64(i)?;
    let (i, stable) = be_u32(i)?;
    let (i, write_len) = be_u32(i)?;
    let (i, data) = take(write_len as usize)(i)?;
    let (i, _padding) = cond(write_len % 4 != 0, take(4 - (write_len % 4)))(i)?;
    let req = Nfs4RequestContent::Write(Nfs4RequestWrite {
        stateid,
        offset,
        stable,
        write_len,
        data,
    });
    Ok((i, req))
}

#[derive(Debug,PartialEq)]
pub struct Nfs4RequestRead<'a> {
    pub stateid: Nfs4StateId<'a>,
    pub offset: u64,
    pub count: u32,
}

fn nfs4_req_read(i: &[u8]) -> IResult<&[u8], Nfs4RequestContent> {
    let (i, stateid) = nfs4_parse_stateid(i)?;
    let (i, offset) = be_u64(i)?;
    let (i, count) = be_u32(i)?;
    let req = Nfs4RequestContent::Read(Nfs4RequestRead {
        stateid,
        offset,
        count,
    });
    Ok((i, req))
}

fn nfs4_req_close(i: &[u8]) -> IResult<&[u8], Nfs4RequestContent> {
    let (i, _seq_id) = be_u32(i)?;
    let (i, stateid) = nfs4_parse_stateid(i)?;
    Ok((i, Nfs4RequestContent::Close(stateid)))
}

#[derive(Debug,PartialEq)]
pub struct Nfs4RequestOpenConfirm<'a> {
    pub stateid: Nfs4StateId<'a>,
}

fn nfs4_req_open_confirm(i: &[u8]) -> IResult<&[u8], Nfs4RequestContent> {
    let (i, _seq_id) = be_u32(i)?;
    let (i, stateid) = nfs4_parse_stateid(i)?;
    let req = Nfs4RequestContent::OpenConfirm(Nfs4RequestOpenConfirm {
        stateid
    });
    Ok((i, req))
}

fn nfs4_req_delegreturn(i: &[u8]) -> IResult<&[u8], Nfs4RequestContent> {
    map(nfs4_parse_stateid, Nfs4RequestContent::DelegReturn)(i)
}

fn nfs4_req_renew(i: &[u8]) -> IResult<&[u8], Nfs4RequestContent> {
    map(be_u64, Nfs4RequestContent::Renew)(i)
}

fn nfs4_req_getfh(i: &[u8]) -> IResult<&[u8], Nfs4RequestContent> {
    Ok((i, Nfs4RequestContent::GetFH))
}

fn nfs4_req_savefh(i: &[u8]) -> IResult<&[u8], Nfs4RequestContent> {
    Ok((i, Nfs4RequestContent::SaveFH))
}

fn nfs4_req_putrootfh(i: &[u8]) -> IResult<&[u8], Nfs4RequestContent> {
    Ok((i, Nfs4RequestContent::PutRootFH))
}

fn nfs4_req_access(i: &[u8]) -> IResult<&[u8], Nfs4RequestContent> {
    map(be_u32, Nfs4RequestContent::Access)(i)
}

fn nfs4_req_commit(i: &[u8]) -> IResult<&[u8], Nfs4RequestContent> {
    let (i, _offset) = be_u64(i)?;
    let (i, _count) = be_u32(i)?;
    Ok((i, Nfs4RequestContent::Commit))
}

#[derive(Debug,PartialEq)]
pub struct Nfs4RequestExchangeId<'a> {
    pub client_string: &'a[u8],
    pub nii_domain: &'a[u8],
    pub nii_name: &'a[u8],
}

fn nfs4_req_exchangeid(i: &[u8]) -> IResult<&[u8], Nfs4RequestContent> {
    let (i, _verifier) = take(8_usize)(i)?;
    let (i, eia_clientstring) = nfs4_parse_nfsstring(i)?;
    let (i, _eia_clientflags) = be_u32(i)?;
    let (i, _eia_state_protect) = be_u32(i)?;
    let (i, _eia_client_impl_id) = be_u32(i)?;
    let (i, nii_domain) = nfs4_parse_nfsstring(i)?;
    let (i, nii_name) = nfs4_parse_nfsstring(i)?;
    let (i, _nii_data_sec) = be_u64(i)?;
    let (i, _nii_data_nsec) = be_u32(i)?;
    let req = Nfs4RequestContent::ExchangeId(Nfs4RequestExchangeId {
        client_string: eia_clientstring,
        nii_domain,
        nii_name
    });
    Ok((i, req))
}

#[derive(Debug,PartialEq)]
pub struct Nfs4RequestSequence<'a> {
    pub ssn_id: &'a[u8],
}

fn nfs4_req_sequence(i: &[u8]) -> IResult<&[u8], Nfs4RequestContent> {
    let (i, ssn_id) = take(16_usize)(i)?;
    let (i, _seq_id) = be_u32(i)?;
    let (i, _slot_id) = be_u32(i)?;
    let (i, _high_slot_id) = be_u32(i)?;
    let (i, _cache_this) = be_u32(i)?;
    let req = Nfs4RequestContent::Sequence(Nfs4RequestSequence {
        ssn_id
    });
    Ok((i, req))
}

fn parse_request_compound_command(i: &[u8]) -> IResult<&[u8], Nfs4RequestContent> {
    let (i, cmd) = be_u32(i)?;
    let (i, cmd_data) = match cmd {
        NFSPROC4_PUTFH => nfs4_req_putfh(i)?,
        NFSPROC4_READ => nfs4_req_read(i)?,
        NFSPROC4_WRITE => nfs4_req_write(i)?,
        NFSPROC4_GETFH => nfs4_req_getfh(i)?,
        NFSPROC4_SAVEFH => nfs4_req_savefh(i)?,
        NFSPROC4_OPEN => nfs4_req_open(i)?,
        NFSPROC4_CLOSE => nfs4_req_close(i)?,
        NFSPROC4_LOOKUP => nfs4_req_lookup(i)?,
        NFSPROC4_ACCESS => nfs4_req_access(i)?,
        NFSPROC4_COMMIT => nfs4_req_commit(i)?,
        NFSPROC4_GETATTR => nfs4_req_getattr(i)?,
        NFSPROC4_READDIR => nfs4_req_readdir(i)?,
        NFSPROC4_RENEW => nfs4_req_renew(i)?,
        NFSPROC4_OPEN_CONFIRM => nfs4_req_open_confirm(i)?,
        NFSPROC4_REMOVE => nfs4_req_remove(i)?,
        NFSPROC4_RENAME => nfs4_req_rename(i)?,
        NFSPROC4_CREATE => nfs4_req_create(i)?,
        NFSPROC4_DELEGRETURN => nfs4_req_delegreturn(i)?,
        NFSPROC4_SETATTR => nfs4_req_setattr(i)?,
        NFSPROC4_PUTROOTFH => nfs4_req_putrootfh(i)?,
        NFSPROC4_SETCLIENTID => nfs4_req_setclientid(i)?,
        NFSPROC4_SETCLIENTID_CONFIRM => nfs4_req_setclientid_confirm(i)?,
        NFSPROC4_SEQUENCE => nfs4_req_sequence(i)?,
        NFSPROC4_EXCHANGE_ID => nfs4_req_exchangeid(i)?,
        _ => { return Err(Err::Error(make_error(i, ErrorKind::Switch))); }
    };
    Ok((i, cmd_data))
}

#[derive(Debug,PartialEq)]
pub struct Nfs4RequestCompoundRecord<'a> {
    pub commands: Vec<Nfs4RequestContent<'a>>,
}

pub fn parse_nfs4_request_compound(i: &[u8]) -> IResult<&[u8], Nfs4RequestCompoundRecord> {
    let (i, tag_len) = be_u32(i)?;
    let (i, _tag) = cond(tag_len > 0, take(tag_len as usize))(i)?;
    let (i, _min_ver) = be_u32(i)?;
    let (i, ops_cnt) = be_u32(i)?;
    let (i, commands) = count(parse_request_compound_command, ops_cnt as usize)(i)?;
    Ok((i, Nfs4RequestCompoundRecord { commands }))
}

#[derive(Debug,PartialEq)]
pub enum Nfs4ResponseContent<'a> {
    PutFH(u32),
    PutRootFH(u32),
    GetFH(u32, Option<Nfs4Handle<'a>>),
    Lookup(u32),
    SaveFH(u32),
    Rename(u32),
    Write(u32, Option<Nfs4ResponseWrite>),
    Read(u32, Option<Nfs4ResponseRead<'a>>),
    Renew(u32),
    Open(u32, Option<Nfs4ResponseOpen<'a>>),
    OpenConfirm(u32, Option<Nfs4StateId<'a>>),
    Close(u32, Option<Nfs4StateId<'a>>),
    GetAttr(u32, Option<Nfs4Attr>),
    SetAttr(u32),
    Access(u32, Option<Nfs4ResponseAccess>),
    ReadDir(u32, Option<Nfs4ResponseReaddir<'a>>),
    Remove(u32),
    DelegReturn(u32),
    SetClientId(u32),
    SetClientIdConfirm(u32),
    Create(u32),
    Commit(u32),
    Sequence(u32, Option<Nfs4ResponseSequence<'a>>),
}

#[derive(Debug,PartialEq)]
pub struct Nfs4ResponseWrite {
    pub count: u32,
    pub committed: u32,
}

fn nfs4_res_write_ok(i: &[u8]) -> IResult<&[u8], Nfs4ResponseWrite> {
    let (i, count) = be_u32(i)?;
    let (i, committed) = be_u32(i)?;
    let (i, _verifier) = be_u64(i)?;
    Ok((i, Nfs4ResponseWrite { count, committed }))
}

fn nfs4_res_write(i: &[u8]) -> IResult<&[u8], Nfs4ResponseContent> {
    let (i, status) = be_u32(i)?;
    let (i, wd) = cond(status == 0, nfs4_res_write_ok)(i)?;
    Ok((i, Nfs4ResponseContent::Write(status, wd)))
}

#[derive(Debug,PartialEq)]
pub struct Nfs4ResponseRead<'a> {
    pub eof: bool,
    pub count: u32,
    pub data: &'a[u8],
}

fn nfs4_res_read_ok(i: &[u8]) -> IResult<&[u8], Nfs4ResponseRead> {
    let (i, eof) = be_u32(i)?;
    let (i, read_len) = be_u32(i)?;
    let (i, read_data) = take(read_len as usize)(i)?;
    let resp = Nfs4ResponseRead {
        eof: eof==1,
        count: read_len,
        data: read_data,
    };
    Ok((i, resp))
}

fn nfs4_res_read(i: &[u8]) -> IResult<&[u8], Nfs4ResponseContent> {
    let (i, status) = be_u32(i)?;
    let (i, rd) = cond(status == 0, nfs4_res_read_ok)(i)?;
    Ok((i, Nfs4ResponseContent::Read(status, rd)))
}

#[derive(Debug,PartialEq)]
pub struct Nfs4ResponseOpen<'a> {
    pub stateid: Nfs4StateId<'a>,
    pub result_flags: u32,
    pub delegation_type: u32,
    pub delegate_read: Option<Nfs4ResponseOpenDelegateRead<'a>>,
}

#[derive(Debug,PartialEq)]
pub struct Nfs4ResponseOpenDelegateRead<'a> {
    pub stateid: Nfs4StateId<'a>,
}

fn nfs4_res_open_ok_delegate_read(i: &[u8]) -> IResult<&[u8], Nfs4ResponseOpenDelegateRead> {
    let (i, stateid) = nfs4_parse_stateid(i)?;
    let (i, _recall) = be_u32(i)?;
    let (i, _ace_type) = be_u32(i)?;
    let (i, _ace_flags) = be_u32(i)?;
    let (i, _ace_mask) = be_u32(i)?;
    let (i, who_len) = be_u32(i)?;
    let (i, _who) = take(who_len as usize)(i)?;
    Ok((i, Nfs4ResponseOpenDelegateRead { stateid }))
}

fn nfs4_res_open_ok(i: &[u8]) -> IResult<&[u8], Nfs4ResponseOpen> {
    let (i, stateid) = nfs4_parse_stateid(i)?;
    let (i, _change_info) = take(20_usize)(i)?;
    let (i, result_flags) = be_u32(i)?;
    let (i, _attrs) = nfs4_parse_attrbits(i)?;
    let (i, delegation_type) = be_u32(i)?;
    let (i, delegate_read) = cond(delegation_type == 1, nfs4_res_open_ok_delegate_read)(i)?;
    let resp = Nfs4ResponseOpen {
        stateid,
        result_flags,
        delegation_type,
        delegate_read
    };
    Ok((i, resp))
}

fn nfs4_res_open(i: &[u8]) -> IResult<&[u8], Nfs4ResponseContent> {
    let (i, status) = be_u32(i)?;
    let (i, open_data) = cond(status == 0, nfs4_res_open_ok)(i)?;
    Ok((i, Nfs4ResponseContent::Open(status, open_data)))
}

#[derive(Debug,PartialEq)]
pub struct Nfs4ResponseReaddirEntry<'a> {
    pub name: &'a[u8],
}

#[derive(Debug,PartialEq)]
pub struct Nfs4ResponseReaddir<'a> {
    pub eof: bool,
    pub listing: Vec<Option<Nfs4ResponseReaddirEntry<'a>>>,
}

fn nfs4_res_readdir_entry_do(i: &[u8]) -> IResult<&[u8], Nfs4ResponseReaddirEntry> {
    let (i, _cookie) = be_u64(i)?;
    let (i, name) = nfs4_parse_nfsstring(i)?;
    let (i, _attrs) = nfs4_parse_attrs(i)?;
    Ok((i, Nfs4ResponseReaddirEntry { name }))
}

fn nfs4_res_readdir_entry(i: &[u8]) -> IResult<&[u8], Option<Nfs4ResponseReaddirEntry>> {
    let (i, value_follows) = be_u32(i)?;
    let (i, entry) = cond(value_follows == 1, nfs4_res_readdir_entry_do)(i)?;
    Ok((i, entry))
}

fn nfs4_res_readdir_ok(i: &[u8]) -> IResult<&[u8], Nfs4ResponseReaddir> {
    let (i, _verifier) = be_u64(i)?;
    // run parser until we find a 'value follows == 0'
    let (i, listing) = many_till(
        complete(nfs4_res_readdir_entry),
        peek(tag(b"\x00\x00\x00\x00")),
    )(i)?;
    // value follows == 0 checked by line above
    let (i, _value_follows) = be_u32(i)?;
    let (i, eof) = be_u32(i)?;
    Ok((
        i,
        Nfs4ResponseReaddir {
            eof: eof == 1,
            listing: listing.0,
        },
    ))
}

fn nfs4_res_readdir(i: &[u8]) -> IResult<&[u8], Nfs4ResponseContent> {
    let (i, status) = be_u32(i)?;
    let (i, rd) = cond(status == 0, nfs4_res_readdir_ok)(i)?;
    Ok((i, Nfs4ResponseContent::ReadDir(status, rd)))
}

fn nfs4_res_create_ok(i: &[u8]) -> IResult<&[u8], Nfs4Attr> {
    let (i, _change_info) = take(20_usize)(i)?;
    nfs4_parse_attrbits(i)
}

fn nfs4_res_create(i: &[u8]) -> IResult<&[u8], Nfs4ResponseContent> {
    let (i, status) = be_u32(i)?;
    let (i, _attrs) = cond(status == 0, nfs4_res_create_ok)(i)?;
    Ok((i, Nfs4ResponseContent::Create(status)))
}

fn nfs4_res_setattr_ok(i: &[u8]) -> IResult<&[u8], Nfs4Attr> {
    nfs4_parse_attrbits(i)
}

fn nfs4_res_setattr(i: &[u8]) -> IResult<&[u8], Nfs4ResponseContent> {
    let (i, status) = be_u32(i)?;
    let (i, _attrs) = cond(status == 0, nfs4_res_setattr_ok)(i)?;
    Ok((i, Nfs4ResponseContent::SetAttr(status)))
}

fn nfs4_res_getattr_ok(i: &[u8]) -> IResult<&[u8], Nfs4Attr> {
    nfs4_parse_attrs(i)
}

fn nfs4_res_getattr(i: &[u8]) -> IResult<&[u8], Nfs4ResponseContent> {
    let (i, status) = be_u32(i)?;
    let (i, attrs) = cond(status == 0, nfs4_res_getattr_ok)(i)?;
    Ok((i, Nfs4ResponseContent::GetAttr(status, attrs)))
}

fn nfs4_res_openconfirm(i: &[u8]) -> IResult<&[u8], Nfs4ResponseContent> {
    let (i, status) = be_u32(i)?;
    let (i, stateid) = cond(status == 0, nfs4_parse_stateid)(i)?;
    Ok((i, Nfs4ResponseContent::OpenConfirm(status, stateid)))
}

fn nfs4_res_close(i: &[u8]) -> IResult<&[u8], Nfs4ResponseContent> {
    let (i, status) = be_u32(i)?;
    let (i, stateid) = cond(status == 0, nfs4_parse_stateid)(i)?;
    Ok((i, Nfs4ResponseContent::Close(status, stateid)))
}

fn nfs4_res_remove(i: &[u8]) -> IResult<&[u8], Nfs4ResponseContent> {
    let (i, status) = be_u32(i)?;
    let (i, _) = cond(status == 0, take(20_usize))(i)?;
    Ok((i, Nfs4ResponseContent::Remove(status)))
}

fn nfs4_res_rename(i: &[u8]) -> IResult<&[u8], Nfs4ResponseContent> {
    map(be_u32, Nfs4ResponseContent::Rename)(i)
}

fn nfs4_res_savefh(i: &[u8]) -> IResult<&[u8], Nfs4ResponseContent> {
    map(be_u32, Nfs4ResponseContent::SaveFH)(i)
}

fn nfs4_res_lookup(i: &[u8]) -> IResult<&[u8], Nfs4ResponseContent> {
    map(be_u32, Nfs4ResponseContent::Lookup)(i)
}

fn nfs4_res_renew(i: &[u8]) -> IResult<&[u8], Nfs4ResponseContent> {
    map(be_u32, Nfs4ResponseContent::Renew)(i)
}

fn nfs4_res_getfh(i: &[u8]) -> IResult<&[u8], Nfs4ResponseContent> {
    let (i, status) = be_u32(i)?;
    let (i, fh) = cond(status == 0, nfs4_parse_handle)(i)?;
    Ok((i, Nfs4ResponseContent::GetFH(status, fh)))
}

fn nfs4_res_putfh(i: &[u8]) -> IResult<&[u8], Nfs4ResponseContent> {
    map(be_u32, Nfs4ResponseContent::PutFH)(i)
}

fn nfs4_res_putrootfh(i: &[u8]) -> IResult<&[u8], Nfs4ResponseContent> {
    map(be_u32, Nfs4ResponseContent::PutRootFH)(i)
}

fn nfs4_res_delegreturn(i: &[u8]) -> IResult<&[u8], Nfs4ResponseContent> {
    map(be_u32, Nfs4ResponseContent::DelegReturn)(i)
}

fn nfs4_res_setclientid(i: &[u8]) -> IResult<&[u8], Nfs4ResponseContent> {
    let (i, status) = be_u32(i)?;
    let (i, _client_id) = be_u64(i)?;
    let (i, _verifier) = be_u32(i)?;
    Ok((i, Nfs4ResponseContent::SetClientId(status)))
}

fn nfs4_res_setclientid_confirm(i: &[u8]) -> IResult<&[u8], Nfs4ResponseContent> {
    map(be_u32, Nfs4ResponseContent::SetClientIdConfirm)(i)
}

fn nfs4_res_commit(i: &[u8]) -> IResult<&[u8], Nfs4ResponseContent> {
    let (i, status) = be_u32(i)?;
    let (i, _verifier) = cond(status == 0, take(8_usize))(i)?;
    Ok((i, Nfs4ResponseContent::Commit(status)))
}

#[derive(Debug,PartialEq)]
pub struct Nfs4ResponseAccess {
    pub supported_types: u32,
    pub access_rights: u32,
}

fn nfs4_res_access_ok(i: &[u8]) -> IResult<&[u8], Nfs4ResponseAccess> {
    let (i, supported_types) = be_u32(i)?;
    let (i, access_rights) = be_u32(i)?;
    let resp = Nfs4ResponseAccess {
        supported_types,
        access_rights
    };
    Ok((i, resp))
}

fn nfs4_res_access(i: &[u8]) -> IResult<&[u8], Nfs4ResponseContent> {
    let (i, status) = be_u32(i)?;
    let (i, ad) = cond(status == 0, nfs4_res_access_ok)(i)?;
    Ok((i, Nfs4ResponseContent::Access(status, ad)))
}

#[derive(Debug,PartialEq)]
pub struct Nfs4ResponseSequence<'a> {
    pub ssn_id: &'a[u8],
}

fn nfs4_res_sequence_ok(i: &[u8]) -> IResult<&[u8], Nfs4ResponseSequence> {
    let (i, ssn_id) = take(16_usize)(i)?;
    let (i, _slots) = take(12_usize)(i)?;
    let (i, _flags) = be_u32(i)?;
    Ok((i, Nfs4ResponseSequence { ssn_id }))
}

fn nfs4_res_sequence(i: &[u8]) -> IResult<&[u8], Nfs4ResponseContent> {
    let (i, status) = be_u32(i)?;
    let (i, seq) = cond(status == 0, nfs4_res_sequence_ok)(i)?;
    Ok((i, Nfs4ResponseContent::Sequence(status, seq)))
}

fn nfs4_res_compound_command(i: &[u8]) -> IResult<&[u8], Nfs4ResponseContent> {
    let (i, cmd) = be_u32(i)?;
    let (i, cmd_data) = match cmd {
        NFSPROC4_READ => nfs4_res_read(i)?,
        NFSPROC4_WRITE => nfs4_res_write(i)?,
        NFSPROC4_ACCESS => nfs4_res_access(i)?,
        NFSPROC4_COMMIT => nfs4_res_commit(i)?,
        NFSPROC4_GETFH => nfs4_res_getfh(i)?,
        NFSPROC4_PUTFH => nfs4_res_putfh(i)?,
        NFSPROC4_SAVEFH => nfs4_res_savefh(i)?,
        NFSPROC4_RENAME => nfs4_res_rename(i)?,
        NFSPROC4_READDIR => nfs4_res_readdir(i)?,
        NFSPROC4_GETATTR => nfs4_res_getattr(i)?,
        NFSPROC4_SETATTR => nfs4_res_setattr(i)?,
        NFSPROC4_LOOKUP => nfs4_res_lookup(i)?,
        NFSPROC4_OPEN => nfs4_res_open(i)?,
        NFSPROC4_OPEN_CONFIRM => nfs4_res_openconfirm(i)?,
        NFSPROC4_CLOSE => nfs4_res_close(i)?,
        NFSPROC4_REMOVE => nfs4_res_remove(i)?,
        NFSPROC4_CREATE => nfs4_res_create(i)?,
        NFSPROC4_DELEGRETURN => nfs4_res_delegreturn(i)?,
        NFSPROC4_SETCLIENTID => nfs4_res_setclientid(i)?,
        NFSPROC4_SETCLIENTID_CONFIRM => nfs4_res_setclientid_confirm(i)?,
        NFSPROC4_PUTROOTFH => nfs4_res_putrootfh(i)?,
        NFSPROC4_SEQUENCE => nfs4_res_sequence(i)?,
        NFSPROC4_RENEW => nfs4_res_renew(i)?,
        _ => { return Err(Err::Error(make_error(i, ErrorKind::Switch))); }
    };
    Ok((i, cmd_data))
}

#[derive(Debug,PartialEq)]
pub struct Nfs4ResponseCompoundRecord<'a> {
    pub status: u32,
    pub commands: Vec<Nfs4ResponseContent<'a>>,
}

pub fn parse_nfs4_response_compound(i: &[u8]) -> IResult<&[u8], Nfs4ResponseCompoundRecord> {
    let (i, status) = be_u32(i)?;
    let (i, tag_len) = be_u32(i)?;
    let (i, _tag) = cond(tag_len > 0, take(tag_len as usize))(i)?;
    let (i, ops_cnt) = be_u32(i)?;
    let (i, commands) = count(nfs4_res_compound_command, ops_cnt as usize)(i)?;
    Ok((i, Nfs4ResponseCompoundRecord { status, commands }))
}
