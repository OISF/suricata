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

// Maximum number of operations per compound
// Linux defines NFSD_MAX_OPS_PER_COMPOUND to 16 (tested in Linux 5.15.1).
const NFSD_MAX_OPS_PER_COMPOUND: usize = 64;

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
    if ops_cnt as usize > NFSD_MAX_OPS_PER_COMPOUND {
        return Err(Err::Error(make_error(i, ErrorKind::Count)));
    }
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
    let (i, _seqid) = be_u32(i)?;
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
    if ops_cnt as usize > NFSD_MAX_OPS_PER_COMPOUND {
        return Err(Err::Error(make_error(i, ErrorKind::Count)));
    }
    let (i, commands) = count(nfs4_res_compound_command, ops_cnt as usize)(i)?;
    Ok((i, Nfs4ResponseCompoundRecord { status, commands }))
}

#[cfg(test)]
mod tests {
    use crate::nfs::nfs4_records::*;

    #[test]
    fn test_nfs4_request_compound() {
    // Operations: SEQUENCE, PUTFH, CLOSE
        #[rustfmt::skip]
        let buf: &[u8] = &[
            0x00, 0x00, 0x00, 0x00, /*Tag*/
            0x00, 0x00, 0x00, 0x01, /*min_ver*/
            0x00, 0x00, 0x00, 0x03, /*ops_cnt*/
        // SEQUENCE
            0x00, 0x00, 0x00, 0x35, /*op_code*/
            0x00, 0x00, 0x02, 0xd2, 0xe0, 0x14, 0x82, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x02,
            0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        // PUTFH
            0x00, 0x00, 0x00, 0x16, /*op_code*/
            0x00, 0x00, 0x00, 0x20, 0x01, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x84, 0x72, 0x00, 0x00, 0x23, 0xa6, 0xc0, 0x12,
            0x00, 0xf2, 0xfa, 0x80, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        // CLOSE
            0x00, 0x00, 0x00, 0x04, /*op_code*/
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x82, 0x14, 0xe0, 0x5b, 0x00, 0x88, 0xd9,
            0x04, 0x00, 0x00, 0x00,
        ];

        let sequence_buf: &[u8] = &buf[16..48];
        let putfh_buf: &[u8] = &buf[52..88];
        let close_buf: &[u8] = &buf[92..];

        let (_, req_sequence) = nfs4_req_sequence(sequence_buf).unwrap();
        let (_, req_putfh) = nfs4_req_putfh(putfh_buf).unwrap();
        let (_, req_close) = nfs4_req_close(close_buf).unwrap();

        let (_, compound_ops) = parse_nfs4_request_compound(buf).unwrap();
        assert_eq!(compound_ops.commands[0], req_sequence);
        assert_eq!(compound_ops.commands[1], req_putfh);
        assert_eq!(compound_ops.commands[2], req_close);
    }

    #[test]
    fn test_nfs4_request_setclientid() {
        #[rustfmt::skip]
        let buf: &[u8] = &[
            0x00, 0x00, 0x00, 0x23, /*opcode*/
            0x59, 0x1b, 0x09, 0x04, 0x28, 0x9c, 0x5d, 0x10, /*_verifier*/
            0x00, 0x00, 0x00, 0x2d, 0x4c, 0x69, 0x6e, 0x75, /*client_id*/
            0x78, 0x20, 0x4e, 0x46, 0x53, 0x76, 0x34, 0x2e,
            0x30, 0x20, 0x31, 0x30, 0x2e, 0x31, 0x39, 0x33,
            0x2e, 0x36, 0x37, 0x2e, 0x32, 0x32, 0x35, 0x2f,
            0x31, 0x30, 0x2e, 0x31, 0x39, 0x33, 0x2e, 0x36,
            0x37, 0x2e, 0x32, 0x31, 0x39, 0x20, 0x74, 0x63,
            0x70, 0x00, 0x00, 0x00,
            0x40, 0x00, 0x00, 0x00, /*_cb_program*/
            0x00, 0x00, 0x00, 0x03, 0x74, 0x63, 0x70, 0x00, /*r_netid*/
            0x00, 0x00, 0x00, 0x14, 0x31, 0x30, 0x2e, 0x31, /*r_addr*/
            0x39, 0x33, 0x2e, 0x36, 0x37, 0x2e, 0x32, 0x32,
            0x35, 0x2e, 0x31, 0x34, 0x30, 0x2e, 0x31, 0x38,
            0x00, 0x00, 0x00, 0x01, /*_cb_id*/
        ];

        let (_, req_client_id) = nfs4_parse_nfsstring(&buf[12..64]).unwrap();
        let (_, req_r_netid) = nfs4_parse_nfsstring(&buf[68 ..76]).unwrap();
        let (_, req_r_adrr) = nfs4_parse_nfsstring(&buf[76..100]).unwrap();

        let (_, resquest) = nfs4_req_setclientid(&buf[4..]).unwrap();
        match resquest {
            Nfs4RequestContent::SetClientId( req_setclientid ) => {
                assert_eq!(req_setclientid.client_id, req_client_id);
                assert_eq!(req_setclientid.r_netid, req_r_netid);
                assert_eq!(req_setclientid.r_addr, req_r_adrr);
            }
            _ => { panic!("Failure"); }
        }
    }

    #[test]
    fn test_nfs4_request_open() {
        #[rustfmt::skip]
        let buf: &[u8] = &[
            0x00, 0x00, 0x00, 0x12, /*opcode*/
            0x00, 0x00, 0x00, 0x00, /*_seq_id*/
            0x00, 0x00, 0x00, 0x02, /*_share_access*/
            0x00, 0x00, 0x00, 0x00, /*_share_deny*/
            0xe0, 0x14, 0x82, 0x00, 0x00, 0x00, 0x02, 0xd2, /*_client_id*/
        // OWNER
            0x00, 0x00, 0x00, 0x18, /*owner_len*/
            0x6f, 0x70, 0x65, 0x6e, 0x20, 0x69, 0x64, 0x3a,
            0x00, 0x00, 0x00, 0x2f, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x48, 0x0c, 0xae, 0x9b, 0x05, 0x08,
        // OPEN
            0x00, 0x00, 0x00, 0x01, /*open_type: OPEN4_CREATE*/
            0x00, 0x00, 0x00, 0x00, /*create_mode: UNCHECKED4*/
            0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x10, /*attr_mask*/
            0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x0c,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x01, 0xb4,
        // CLAIM_TYPE
            0x00, 0x00, 0x00, 0x00, /*_claim_type: CLAIM_NULL*/
            0x00, 0x00, 0x00, 0x04, 0x66, 0x69, 0x6c, 0x65, /*filename*/
        ];

        let (_, attr_buf) = nfs4_parse_attrbits(&buf[60..88]).unwrap();
        let (_, filename_buf) = nfs4_parse_nfsstring(&buf[92..]).unwrap();

        let (_, request) = nfs4_req_open(&buf[4..]).unwrap();
        match request {
            Nfs4RequestContent::Open(req_open) => {
                assert_eq!(req_open.open_type, 1);
                assert_eq!(req_open.open_data, Some(Nfs4OpenRequestContent::Unchecked4(attr_buf)));
                assert_eq!(req_open.filename, filename_buf);
            }
            _ => { panic!("Failure, {:?}", request); }
        }
    }

    #[test]
    fn test_nfs4_request_write() {
        #[rustfmt::skip]
        let buf: &[u8] = &[
            0x00, 0x00, 0x00, 0x26, /*op_code*/
            0x00, 0x00, 0x00, 0x00, 0x02, 0x82, 0x14, 0xe0, /*stateid*/
            0x5b, 0x00, 0x89, 0xd9, 0x04, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /*offset*/
            0x00, 0x00, 0x00, 0x02, /*stable*/
            0x00, 0x00, 0x00, 0x05, /*write_len*/
            0x74, 0x65, 0x73, 0x74, 0x0a, /*data*/
            0x00, 0x00, 0x00, /*_padding*/
        ];

        let (_, stateid_buf) = nfs4_parse_stateid(&buf[4..20]).unwrap();

        let (_, request) = nfs4_req_write(&buf[4..]).unwrap();
        match request {
            Nfs4RequestContent::Write(req_write) => {
                assert_eq!(req_write.stateid, stateid_buf);
                assert_eq!(req_write.offset, 0);
                assert_eq!(req_write.stable, 2);
                assert_eq!(req_write.write_len, 5);
                assert_eq!(req_write.data, "test\n".as_bytes());
            }
            _ => { panic!("Failure, {:?}", request); }
        }
    }

    #[test]
    fn test_nfs4_request_exchangeid() {
        #[rustfmt::skip]
        let buf: &[u8] = &[
            0x00, 0x00, 0x00, 0x2a, /*opcode*/
        // eia_clientowner
            0x5c, 0x8a, 0x9b, 0xfe, 0x0c, 0x09, 0x5e, 0x92, /*_verifier*/
            0x00, 0x00, 0x00, 0x17, 0x4c, 0x69, 0x6e, 0x75, /*eia_clientstring*/
            0x78, 0x20, 0x4e, 0x46, 0x53, 0x76, 0x34, 0x2e,
            0x31, 0x20, 0x6e, 0x65, 0x74, 0x61, 0x70, 0x70,
            0x2d, 0x32, 0x36, 0x00,
            0x00, 0x00, 0x01, 0x01, /*_eia_clientflags*/
            0x00, 0x00, 0x00, 0x00, /*_eia_state_protect*/
        // _eia_client_impl_id
            0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x0a, 0x6b, 0x65, 0x72, 0x6e, /*nii_domain*/
            0x65, 0x6c, 0x2e, 0x6f, 0x72, 0x67, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x45, 0x4c, 0x69, 0x6e, 0x75, /*nii_name*/
            0x78, 0x20, 0x33, 0x2e, 0x31, 0x30, 0x2e, 0x30,
            0x2d, 0x39, 0x35, 0x37, 0x2e, 0x65, 0x6c, 0x37,
            0x2e, 0x78, 0x38, 0x36, 0x5f, 0x36, 0x34, 0x20,
            0x23, 0x31, 0x20, 0x53, 0x4d, 0x50, 0x20, 0x54,
            0x68, 0x75, 0x20, 0x4f, 0x63, 0x74, 0x20, 0x34,
            0x20, 0x32, 0x30, 0x3a, 0x34, 0x38, 0x3a, 0x35,
            0x31, 0x20, 0x55, 0x54, 0x43, 0x20, 0x32, 0x30,
            0x31, 0x38, 0x20, 0x78, 0x38, 0x36, 0x5f, 0x36,
            0x34, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /*_nii_data_sec*/
            0x00, 0x00, 0x00, 0x00, /*_nii_data_nsec*/
        ];

        /*(   .Linux NFSv4.1 netapp-26 )*/
        let (_, client_string_buf) = nfs4_parse_nfsstring(&buf[12..40]).unwrap();
        /*(kernel.org\0\0\0\n)*/
        let (_, nii_domain_buf) = nfs4_parse_nfsstring(&buf[52..68]).unwrap();
        /* (   ELinux 3.10.0-957.el7.x86_64 #1 SMP Thu Oct 4 20:48:51 UTC 2018 x86_64   ) */
        let (_, nii_name_buf) = nfs4_parse_nfsstring(&buf[68..144]).unwrap();

        let (_, request) = nfs4_req_exchangeid(&buf[4..]).unwrap();
        match request {
            Nfs4RequestContent::ExchangeId(req_exchangeid) => {
                assert_eq!(req_exchangeid.client_string, client_string_buf);
                assert_eq!(req_exchangeid.nii_domain, nii_domain_buf);
                assert_eq!(req_exchangeid.nii_name, nii_name_buf);
            }
            _ => { panic!("Failure, {:?}", request); }
        }
    }

    #[test]
    fn test_nfs4_request_close() {
        #[rustfmt::skip]
        let buf: &[u8] = &[
            0x00, 0x00, 0x00, 0x04, /*opcode*/
            0x00, 0x00, 0x00, 0x00, /*_seq_id*/
            0x00, 0x00, 0x00, 0x01, 0x00, 0x82, 0x14, 0xe0, /*stateid*/
            0x5b, 0x00, 0x88, 0xd9, 0x04, 0x00, 0x00, 0x00,
        ];

        let (_, stateid_buf) = nfs4_parse_stateid(&buf[8..]).unwrap();

        let (_, request) = nfs4_req_close(&buf[4..]).unwrap();
        match request {
            Nfs4RequestContent::Close(req_stateid) => {
                assert_eq!(req_stateid, stateid_buf);
            }
            _ => { panic!("Failure, {:?}", request); }
        }
    }

    #[test]
    fn test_nfs4_request_sequenece() {
        #[rustfmt::skip]
        let buf: &[u8] = &[
            0x00, 0x00, 0x00, 0x35, /*opcode*/
            0x00, 0x00, 0x02, 0xd2, 0xe0, 0x14, 0x82, 0x00, /*ssn_id*/
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x02,
            0x00, 0x00, 0x00, 0x18, /*_seq_id*/
            0x00, 0x00, 0x00, 0x00, /*_slot_id*/
            0x00, 0x00, 0x00, 0x00, /*_high_slot_id*/
            0x00, 0x00, 0x00, 0x01, /*_catch_this*/
        ];

        let (_, req_sequence) = nfs4_req_sequence(&buf[4..]).unwrap();
        match req_sequence {
            Nfs4RequestContent::Sequence(seq_buf) => {
                assert_eq!(seq_buf.ssn_id, &buf[4..20]);
            }
            _ => { panic!("Failure, {:?}", req_sequence); }
        }
    }

    #[test]
    fn test_nfs4_request_lookup() {
        #[rustfmt::skip]
        let buf: &[u8] = &[
            0x00, 0x00, 0x00, 0x0f, /*opcode*/
            0x00, 0x00, 0x00, 0x04, 0x76, 0x6f, 0x6c, 0x31, /*fiename: (vol1)*/
        ];

        let (_, filename_buf) = nfs4_parse_nfsstring(&buf[4..]).unwrap();

        let (_, request) = nfs4_req_lookup(&buf[4..]).unwrap();
        match request {
            Nfs4RequestContent::Lookup(req_lookup) => {
                assert_eq!(req_lookup.filename, filename_buf);
            }
            _ => { panic!("Failure, {:?}", request); }
        }
    }

    #[test]
    fn test_nfs4_request_putfh() {
        #[rustfmt::skip]
        let buf: &[u8] = &[
            0x00, 0x00, 0x00, 0x16, /*opcode*/
            0x00, 0x00, 0x00, 0x20, /*handle_len*/
            0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /*handle*/
            0x00, 0x00, 0x00, 0x00, 0x84, 0x72, 0x00, 0x00,
            0x23, 0xa6, 0xc0, 0x12, 0x00, 0xf2, 0xfa, 0x80,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let (_, handle_buf) = nfs4_parse_handle(&buf[4..]).unwrap();

        let (_, result) = nfs4_req_putfh(&buf[4..]).unwrap();
        match result {
            Nfs4RequestContent::PutFH(putfh_handle) => {
                assert_eq!(putfh_handle.value, handle_buf.value);
                assert_eq!(putfh_handle.len, handle_buf.len);
            }
            _ => { panic!("Failure, {:?}", result); }
        }
    }

    #[test]
    fn test_nfs4_attrs() {
        #[rustfmt::skip]
        let buf: &[u8] = &[
            0x00, 0x00, 0x00, 0x09, /*opcode*/
            0x00, 0x00, 0x00, 0x03, /*attr_cnt*/
            0x00, 0x00, 0x20, 0x65, /*attr_mask[0]*/
            0x00, 0x00, 0x00, 0x00, /*attr_mask[1]*/
            0x00, 0x00, 0x08, 0x00, /*attr_mask[2]*/
        ];

        let (r, attr) = nfs4_parse_attrbits(&buf[4..]).unwrap();
        assert_eq!(r.len(), 0);
        // assert_eq!(attr.attr_mask, 35618163785728);
        assert_eq!(attr.attr_mask, ((0x00002065 as u64) << 32 | 0 as u64));
    }
    #[test]
    fn test_nfs4_response_compound() {
    // Operations: SEQUENCE, PUTFH, CLOSE
        #[rustfmt::skip]
        let buf: &[u8] = &[
            0x00, 0x00, 0x00, 0x00, /*status*/
            0x00, 0x00, 0x00, 0x00, /*Tag*/
            0x00, 0x00, 0x00, 0x03, /*ops_cnt*/
        // SEQUENCE
            0x00, 0x00, 0x00, 0x35, /*opcode*/
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xd2,
            0xe0, 0x14, 0x82, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00, 0x18,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3f,
            0x00, 0x00, 0x00, 0x3f, 0x00, 0x00, 0x00, 0x00,
        // PUTFH
            0x00, 0x00, 0x00, 0x16, /*opcode*/
            0x00, 0x00, 0x00, 0x00,
        // CLOSE
            0x00, 0x00, 0x00, 0x04, /*opcode*/
            0x00, 0x00, 0x00, 0x00, /*status*/
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

        ];

        let sequence_buf: &[u8] = &buf[16..56];
        let putfh_buf: &[u8] = &buf[60..64];
        let close_buf: &[u8] = &buf[68..];

        let (_, res_sequence) = nfs4_res_sequence(sequence_buf).unwrap();
        let (_, res_putfh) = nfs4_res_putfh(putfh_buf).unwrap();
        let (_, res_close) = nfs4_res_close(close_buf).unwrap();

        let (_, compound_ops) = parse_nfs4_response_compound(buf).unwrap();
        assert_eq!(compound_ops.status, 0);
        assert_eq!(compound_ops.commands[0], res_sequence);
        assert_eq!(compound_ops.commands[1], res_putfh);
        assert_eq!(compound_ops.commands[2], res_close);
    }

    #[test]
    fn test_nfs4_response_open() {
        #[rustfmt::skip]
        let buf: &[u8] = &[
            0x00, 0x00, 0x00, 0x12, /*opcode*/
            0x00, 0x00, 0x00, 0x00, /*status*/
        // open_data
            0x00, 0x00, 0x00, 0x01, 0x00, 0x82, 0x14, 0xe0, /*stateid*/
            0x5b, 0x00, 0x88, 0xd9, 0x04, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01, 0x16, 0xf8, 0x2f, 0xd5, /*_change_info*/
            0xdb, 0xb7, 0xfe, 0x38, 0x16, 0xf8, 0x2f, 0xdf,
            0x21, 0xa8, 0x2a, 0x48,
            0x00, 0x00, 0x00, 0x04, /*result_flags*/
            0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x10, /*_attrs*/
            0x00, 0x00, 0x00, 0x02, /*delegation_type*/
        // delegate_read
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
            0x00, 0x00, 0x00, 0x01, 0x02, 0x82, 0x14, 0xe0,
            0x5b, 0x00, 0x89, 0xd9, 0x04, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00
        ];

        let stateid_buf = &buf[8..24];
        let (_, res_stateid) = nfs4_parse_stateid(stateid_buf).unwrap();

        let open_data_buf = &buf[8..];
        let (_, res_open_data) = nfs4_res_open_ok(open_data_buf).unwrap();
        assert_eq!(res_open_data.stateid, res_stateid);
        assert_eq!(res_open_data.result_flags, 4);
        assert_eq!(res_open_data.delegation_type, 2);
        assert_eq!(res_open_data.delegate_read, None);

        let (_, response) = nfs4_res_open(&buf[4..]).unwrap();
        match response {
            Nfs4ResponseContent::Open(status, open_data) => {
                assert_eq!(status, 0);
                assert_eq!(open_data, Some(res_open_data));
            }
            _ => { panic!("Failure, {:?}", response); }
        }
    }

    #[test]
    fn test_nfs4_response_write() {
        #[rustfmt::skip]
        let buf: &[u8] = &[
            0x00, 0x00, 0x00, 0x26, /*opcode*/
            0x00, 0x00, 0x00, 0x00, /*status*/
            0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x02, /*wd*/
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        ];

        let (_, wd_buf) = nfs4_res_write_ok(&buf[8..]).unwrap();
        assert_eq!(wd_buf.count, 5);
        assert_eq!(wd_buf.committed, 2);

        let (_, result) = nfs4_res_write(&buf[4..]).unwrap();
        match result {
            Nfs4ResponseContent::Write(status, wd) => {
                assert_eq!(status, 0);
                assert_eq!(wd, Some(wd_buf));
            }
            _ => { panic!("Failure, {:?}", result); }
        }
    }

    #[test]
    fn test_nfs4_response_access() {
        #[rustfmt::skip]
        let buf: &[u8] = &[
            0x00, 0x00, 0x00, 0x03, /*opcode*/
            0x00, 0x00, 0x00, 0x00, /*status*/
            0x00, 0x00, 0x00, 0x1f, 0x00, 0x00, 0x00, 0x1f, /*ad*/
        ];

        let (_, ad_buf) = nfs4_res_access_ok(&buf[8..]).unwrap();
        assert_eq!(ad_buf.supported_types, 0x1f);
        assert_eq!(ad_buf.access_rights, 0x1f);

        let (_, result) = nfs4_res_access(&buf[4..]).unwrap();
        match result {
            Nfs4ResponseContent::Access(status, ad) => {
                assert_eq!(status, 0);
                assert_eq!(ad, Some(ad_buf));
            }
            _ => { panic!("Failure, {:?}", result); }
        }
    }

    #[test]
    fn test_nfs4_response_getfh() {
        #[rustfmt::skip]
        let buf: &[u8] = &[
            0x00, 0x00, 0x00, 0x0a, /*opcode*/
            0x00, 0x00, 0x00, 0x00, /*status*/
            0x00, 0x00, 0x00, 0x20, 0x01, 0x01, 0x00, 0x00, /*fh*/
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x40, 0x00, 0x00, 0x00, 0x8b, 0xae, 0xea, 0x7f,
            0xff, 0xf1, 0xfa, 0x80, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];

        let (_, fh_buf) = nfs4_parse_handle(&buf[8..]).unwrap();

        let (_, result) = nfs4_res_getfh(&buf[4..]).unwrap();
        match result {
            Nfs4ResponseContent::GetFH(status, fh) => {
                assert_eq!(status, 0);
                assert_eq!(fh, Some(fh_buf));
            }
            _ => { panic!("Failure, {:?}", result); }
        }
    }

    #[test]
    fn test_nfs4_response_getattr() {
        #[rustfmt::skip]
        let buf: &[u8] = &[
            0x00, 0x00, 0x00, 0x09, /*opcode*/
            0x00, 0x00, 0x00, 0x00, /*status*/
            0x00, 0x00, 0x00, 0x03, /*attr_cnt*/
            0x00, 0x00, 0x20, 0x65, 0x00, 0x00, 0x00, 0x00, /*attr_mask*/
            0x00, 0x00, 0x08, 0x00,
            0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x03, /*attrs*/
            0xfa, 0xfe, 0xbf, 0xff, 0x60, 0xfd, 0xff, 0xfe,
            0x00, 0x00, 0x08, 0x17, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x03,
            0x02, 0x00, 0x10, 0x00, 0x00, 0x24, 0x40, 0x32,
            0x00, 0x00, 0x00, 0x00
        ];

        let (_, attrs_buf) = nfs4_parse_attrs(&buf[8..]).unwrap();

        let (_, attr_fields) = nfs4_parse_attr_fields(&buf[24..]).unwrap();
        assert_eq!(attr_fields, 48);

        let (_, result) = nfs4_res_getattr(&buf[4..]).unwrap();
        match result {
            Nfs4ResponseContent::GetAttr(status, attrs) => {
                assert_eq!(status, 0);
                assert_eq!(attrs, Some(attrs_buf));
            }
            _ => { panic!("Failure, {:?}", result); }
        }
    }

    #[test]
    fn test_nfs4_response_readdir() {
        #[rustfmt::skip]
        let buf: &[u8] = &[
            0x00, 0x00, 0x00, 0x1a, /*opcode*/
            0x00, 0x00, 0x00, 0x00, /*Status: 0*/
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /*_verifier*/
        // directory_listing
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x55, 0xeb, 0x42, 0x33, /*entry0*/
            0x00, 0x00, 0x00, 0x06, 0x43, 0x65, 0x6e, 0x74, 0x4f, 0x53, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x02, 0x00, 0x18, 0x09, 0x1a, 0x00, 0xb0, 0xa2, 0x3a,
            0x00, 0x00, 0x00, 0xb8, 0x00, 0x00, 0x00, 0x02, 0xaf, 0x8f, 0x9b, 0x4e,
            0x29, 0xc4, 0xa2, 0x1d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
            0x01, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x52, 0x00,
            0xb0, 0x33, 0xf7, 0x54, 0x00, 0x00, 0x00, 0x00, 0x00, 0x52, 0x00, 0x0b,
            0x00, 0x00, 0x01, 0xfd, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x12,
            0x62, 0x69, 0x6e, 0x61, 0x72, 0x79, 0x40, 0x66, 0x69, 0x61, 0x6e, 0x65,
            0x2e, 0x69, 0x6e, 0x74, 0x72, 0x61, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12,
            0x62, 0x69, 0x6e, 0x61, 0x72, 0x79, 0x40, 0x66, 0x69, 0x61, 0x6e, 0x65,
            0x2e, 0x69, 0x6e, 0x74, 0x72, 0x61, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x4e, 0x1f, 0x17, 0xbc, 0x28, 0x86, 0x38, 0x31,
            0x00, 0x00, 0x00, 0x00, 0x4e, 0x9b, 0x8f, 0xaf, 0x1d, 0xa2, 0xc4, 0x29,
            0x00, 0x00, 0x00, 0x00, 0x4e, 0x9b, 0x8f, 0xaf, 0x1d, 0xa2, 0xc4, 0x29,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x52, 0x00, 0x0b,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, /*entry1*/
            0x00, 0x00, 0x00, 0x04, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00, 0x00, 0x02,
            0x00, 0x18, 0x09, 0x1a, 0x00, 0xb0, 0xa2, 0x3a, 0x00, 0x00, 0x00, 0xb0,
            0x00, 0x00, 0x00, 0x02, 0x83, 0x66, 0x9c, 0x4e, 0x25, 0x80, 0x82, 0x07,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x01, 0x00, 0x01, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x52, 0x00, 0xad, 0x37, 0xad, 0x2c,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x52, 0x00, 0x02, 0x00, 0x00, 0x03, 0xff,
            0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x10, 0x72, 0x6f, 0x6f, 0x74,
            0x40, 0x66, 0x69, 0x61, 0x6e, 0x65, 0x2e, 0x69, 0x6e, 0x74, 0x72, 0x61,
            0x00, 0x00, 0x00, 0x10, 0x72, 0x6f, 0x6f, 0x74, 0x40, 0x66, 0x69, 0x61,
            0x6e, 0x65, 0x2e, 0x69, 0x6e, 0x74, 0x72, 0x61, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x4d, 0x6a, 0x97, 0xdb, 0x33, 0x89, 0xba, 0x2d,
            0x00, 0x00, 0x00, 0x00, 0x4e, 0x9c, 0x66, 0x83, 0x07, 0x82, 0x80, 0x25,
            0x00, 0x00, 0x00, 0x00, 0x4e, 0x9c, 0x66, 0x83, 0x07, 0x82, 0x80, 0x25,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x52, 0x00, 0x02,
            0x00, 0x00, 0x00, 0x00, /*value_follows*/
            0x00, 0x00, 0x00, 0x01, /*EOF: YES*/
        ];

        let entry0_buf = &buf[16..240];
        let entry1_buf = &buf[240..452];

        let (_, res_entry0) = nfs4_res_readdir_entry_do(&entry0_buf[4..]).unwrap();
        assert_eq!(res_entry0.name, "CentOS".as_bytes());

        let (_, res_entry1) = nfs4_res_readdir_entry_do(&entry1_buf[4..]).unwrap();
        assert_eq!(res_entry1.name, "data".as_bytes());

        let (_, res_rd) = nfs4_res_readdir_ok(&buf[8..]).unwrap();
        assert_eq!(res_rd.eof, true);
        assert_eq!(res_rd.listing, [Some(res_entry0), Some(res_entry1)]);

        let (_, response) = nfs4_res_readdir(&buf[4..]).unwrap();
        match response {
            Nfs4ResponseContent::ReadDir(status, rd) => {
                assert_eq!(status, 0);
                assert_eq!(rd, Some(res_rd));
            }
            _ => { panic!("Failure!"); }
        }
    }

    #[test]
    fn test_nfs4_response_setclientid() {
        #[rustfmt::skip]
        let buf: &[u8] = &[
            0x00, 0x00, 0x00, 0x23, /*opcode*/
            0x00, 0x00, 0x00, 0x00, /*status*/
            0x14, 0x67, 0x8c, 0x00, 0x00, 0x00, 0x00, 0x01, /*_clientid*/
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /*_verifier*/
        ];

        let (_, response) = nfs4_res_setclientid(&buf[4..]).unwrap();
        match response {
            Nfs4ResponseContent::SetClientId(status) => {
                assert_eq!(status, 0);
            }
            _ => { panic!("Failure"); }
        }
    }
}
