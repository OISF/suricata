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
use nom7::combinator::{complete, cond, map, peek, verify};
use nom7::error::{make_error, ErrorKind};
use nom7::multi::{count, many_till};
use nom7::number::streaming::{be_u32, be_u64};
use nom7::{Err, IResult, Needed};

use crate::nfs::types::*;

/*https://datatracker.ietf.org/doc/html/rfc7530 - section 16.16 File Delegation Types */
const OPEN_DELEGATE_NONE: u32 = 0;
const OPEN_DELEGATE_READ: u32 = 1;
const OPEN_DELEGATE_WRITE: u32 = 2;

const RPCSEC_GSS: u32 = 6;

// Maximum number of operations per compound
// Linux defines NFSD_MAX_OPS_PER_COMPOUND to 16 (tested in Linux 5.15.1).
const NFSD_MAX_OPS_PER_COMPOUND: usize = 64;

#[derive(Debug, PartialEq, Eq)]
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
    Remove(&'a [u8]),
    DelegReturn(Nfs4StateId<'a>),
    SetClientId(Nfs4RequestSetClientId<'a>),
    SetClientIdConfirm,
    ExchangeId(Nfs4RequestExchangeId<'a>),
    Sequence(Nfs4RequestSequence<'a>),
    CreateSession(Nfs4RequestCreateSession<'a>),
    ReclaimComplete(u32),
    SecInfoNoName(u32),
    LayoutGet(Nfs4RequestLayoutGet<'a>),
    GetDevInfo(Nfs4RequestGetDevInfo<'a>),
    LayoutReturn(Nfs4RequestLayoutReturn<'a>),
    DestroySession(&'a [u8]),
    DestroyClientID(&'a [u8]),
}

#[derive(Debug, PartialEq, Eq)]
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

#[derive(Debug, PartialEq, Eq)]
pub struct Nfs4StateId<'a> {
    pub seqid: u32,
    pub data: &'a [u8],
}

fn nfs4_parse_stateid(i: &[u8]) -> IResult<&[u8], Nfs4StateId<'_>> {
    let (i, seqid) = be_u32(i)?;
    let (i, data) = take(12_usize)(i)?;
    let state = Nfs4StateId { seqid, data };
    Ok((i, state))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Nfs4Handle<'a> {
    pub len: u32,
    pub value: &'a [u8],
}

fn nfs4_parse_handle(i: &[u8]) -> IResult<&[u8], Nfs4Handle<'_>> {
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

#[derive(Debug, PartialEq, Eq)]
pub struct Nfs4RequestLayoutReturn<'a> {
    pub layout_type: u32,
    pub return_type: u32,
    pub length: u64,
    pub stateid: Nfs4StateId<'a>,
    pub lrf_data: &'a [u8],
}

fn nfs4_req_layoutreturn(i: &[u8]) -> IResult<&[u8], Nfs4RequestContent<'_>> {
    let (i, _reclaim) = verify(be_u32, |&v| v <= 1)(i)?;
    let (i, layout_type) = be_u32(i)?;
    let (i, _iq_mode) = be_u32(i)?;
    let (i, return_type) = be_u32(i)?;
    let (i, _offset) = be_u64(i)?;
    let (i, length) = be_u64(i)?;
    let (i, stateid) = nfs4_parse_stateid(i)?;
    let (i, lrf_data) = nfs4_parse_nfsstring(i)?;
    let req = Nfs4RequestContent::LayoutReturn(Nfs4RequestLayoutReturn {
        layout_type,
        return_type,
        length,
        stateid,
        lrf_data,
    });
    Ok((i, req))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Nfs4RequestGetDevInfo<'a> {
    pub device_id: &'a [u8],
    pub layout_type: u32,
    pub maxcount: u32,
    pub notify_mask: u32,
}

fn nfs4_req_getdevinfo(i: &[u8]) -> IResult<&[u8], Nfs4RequestContent<'_>> {
    let (i, device_id) = take(16_usize)(i)?;
    let (i, layout_type) = be_u32(i)?;
    let (i, maxcount) = be_u32(i)?;
    let (i, _) = be_u32(i)?;
    let (i, notify_mask) = be_u32(i)?;
    let req = Nfs4RequestContent::GetDevInfo(Nfs4RequestGetDevInfo {
        device_id,
        layout_type,
        maxcount,
        notify_mask,
    });
    Ok((i, req))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Nfs4RequestCreateSession<'a> {
    pub client_id: &'a [u8],
    pub seqid: u32,
    pub machine_name: &'a [u8],
}

fn nfs4_req_create_session(i: &[u8]) -> IResult<&[u8], Nfs4RequestContent<'_>> {
    // Parsed exactly op by op (clientid, seqid, flags, channel attrs, cb
    // prog/ver, machine name): a blanket rest() would swallow every following
    // op, so a later oversized WRITE is only "seen" once the full record buffers.
    let (i, client_id) = take(8_usize)(i)?;
    let (i, seqid) = be_u32(i)?;
    let (i, _flags) = be_u32(i)?;
    let (i, _fore_chan_attrs) = take(28_usize)(i)?;
    let (i, _back_chan_attrs) = take(28_usize)(i)?;
    let (i, _cb_program) = be_u32(i)?;
    let (i, _cb_version) = be_u32(i)?;
    let (i, _g_flavor) = be_u32(i)?;
    let (i, _g_stamp) = be_u32(i)?;
    let (i, machine_name) = nfs4_parse_nfsstring(i)?;

    let req = Nfs4RequestContent::CreateSession(Nfs4RequestCreateSession {
        client_id,
        seqid,
        machine_name,
    });
    Ok((i, req))
}

fn nfs4_req_putfh(i: &[u8]) -> IResult<&[u8], Nfs4RequestContent<'_>> {
    map(nfs4_parse_handle, Nfs4RequestContent::PutFH)(i)
}

#[derive(Debug, PartialEq, Eq)]
pub struct Nfs4RequestSetClientId<'a> {
    pub client_id: &'a [u8],
    pub r_netid: &'a [u8],
    pub r_addr: &'a [u8],
}

fn nfs4_req_setclientid(i: &[u8]) -> IResult<&[u8], Nfs4RequestContent<'_>> {
    let (i, _client_verifier) = take(8_usize)(i)?;
    let (i, client_id) = nfs4_parse_nfsstring(i)?;
    let (i, _cb_program) = be_u32(i)?;
    let (i, r_netid) = nfs4_parse_nfsstring(i)?;
    let (i, r_addr) = nfs4_parse_nfsstring(i)?;
    let (i, _cb_id) = be_u32(i)?;
    let req = Nfs4RequestContent::SetClientId(Nfs4RequestSetClientId {
        client_id,
        r_netid,
        r_addr,
    });
    Ok((i, req))
}

fn nfs4_req_setclientid_confirm(i: &[u8]) -> IResult<&[u8], Nfs4RequestContent<'_>> {
    let (i, _client_id) = take(8_usize)(i)?;
    let (i, _verifier) = take(8_usize)(i)?;
    Ok((i, Nfs4RequestContent::SetClientIdConfirm))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Nfs4RequestCreate<'a> {
    pub ftype4: u32,
    pub filename: &'a [u8],
    pub link_content: &'a [u8],
}

fn nfs4_req_create(i: &[u8]) -> IResult<&[u8], Nfs4RequestContent<'_>> {
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

#[derive(Debug, PartialEq, Eq)]
pub enum Nfs4OpenRequestContent<'a> {
    Exclusive4(&'a [u8]),
    Unchecked4(Nfs4Attr),
    Guarded4(Nfs4Attr),
    Exclusive4_1(&'a [u8]),
}

fn nfs4_req_open_unchecked4(i: &[u8]) -> IResult<&[u8], Nfs4OpenRequestContent<'_>> {
    map(nfs4_parse_attrs, Nfs4OpenRequestContent::Unchecked4)(i)
}

fn nfs4_req_open_guarded4(i: &[u8]) -> IResult<&[u8], Nfs4OpenRequestContent<'_>> {
    map(nfs4_parse_attrs, Nfs4OpenRequestContent::Guarded4)(i)
}

fn nfs4_req_open_exclusive4(i: &[u8]) -> IResult<&[u8], Nfs4OpenRequestContent<'_>> {
    map(take(8_usize), Nfs4OpenRequestContent::Exclusive4)(i)
}

fn nfs4_req_open_exclusive4_1(i: &[u8]) -> IResult<&[u8], Nfs4OpenRequestContent<'_>> {
    map(take(8_usize), Nfs4OpenRequestContent::Exclusive4_1)(i)
}

fn nfs4_req_open_type(i: &[u8]) -> IResult<&[u8], Nfs4OpenRequestContent<'_>> {
    let (i, mode) = be_u32(i)?;
    let (i, data) = match mode {
        0 => nfs4_req_open_unchecked4(i)?,
        1 => nfs4_req_open_guarded4(i)?,
        2 => nfs4_req_open_exclusive4(i)?,
        3 => nfs4_req_open_exclusive4_1(i)?,
        _ => {
            return Err(Err::Error(make_error(i, ErrorKind::Switch)));
        }
    };
    Ok((i, data))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Nfs4RequestOpen<'a> {
    pub open_type: u32,
    pub filename: &'a [u8],
    pub open_data: Option<Nfs4OpenRequestContent<'a>>,
}

fn nfs4_req_open(i: &[u8]) -> IResult<&[u8], Nfs4RequestContent<'_>> {
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
        open_data,
    });
    Ok((i, req))
}

fn nfs4_req_readdir(i: &[u8]) -> IResult<&[u8], Nfs4RequestContent<'_>> {
    let (i, _cookie) = be_u64(i)?;
    let (i, _cookie_verf) = be_u64(i)?;
    let (i, _dir_cnt) = be_u32(i)?;
    let (i, _max_cnt) = be_u32(i)?;
    let (i, _attr) = nfs4_parse_attrbits(i)?;
    Ok((i, Nfs4RequestContent::ReadDir))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Nfs4RequestRename<'a> {
    pub oldname: &'a [u8],
    pub newname: &'a [u8],
}

fn nfs4_req_rename(i: &[u8]) -> IResult<&[u8], Nfs4RequestContent<'_>> {
    let (i, oldname) = nfs4_parse_nfsstring(i)?;
    let (i, newname) = nfs4_parse_nfsstring(i)?;
    let req = Nfs4RequestContent::Rename(Nfs4RequestRename { oldname, newname });
    Ok((i, req))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Nfs4RequestLookup<'a> {
    pub filename: &'a [u8],
}

fn nfs4_req_destroy_session(i: &[u8]) -> IResult<&[u8], Nfs4RequestContent<'_>> {
    let (i, ssn_id) = take(16_usize)(i)?;
    Ok((i, Nfs4RequestContent::DestroySession(ssn_id)))
}

fn nfs4_req_lookup(i: &[u8]) -> IResult<&[u8], Nfs4RequestContent<'_>> {
    map(nfs4_parse_nfsstring, |filename| {
        Nfs4RequestContent::Lookup(Nfs4RequestLookup { filename })
    })(i)
}

fn nfs4_req_remove(i: &[u8]) -> IResult<&[u8], Nfs4RequestContent<'_>> {
    map(nfs4_parse_nfsstring, Nfs4RequestContent::Remove)(i)
}

fn nfs4_req_secinfo_no_name(i: &[u8]) -> IResult<&[u8], Nfs4RequestContent<'_>> {
    map(be_u32, Nfs4RequestContent::SecInfoNoName)(i)
}

#[derive(Debug, PartialEq, Eq)]
pub struct Nfs4RequestSetAttr<'a> {
    pub stateid: Nfs4StateId<'a>,
}

fn nfs4_req_setattr(i: &[u8]) -> IResult<&[u8], Nfs4RequestContent<'_>> {
    let (i, stateid) = nfs4_parse_stateid(i)?;
    let (i, _attrs) = nfs4_parse_attrs(i)?;
    let req = Nfs4RequestContent::SetAttr(Nfs4RequestSetAttr { stateid });
    Ok((i, req))
}

fn nfs4_req_getattr(i: &[u8]) -> IResult<&[u8], Nfs4RequestContent<'_>> {
    map(nfs4_parse_attrbits, Nfs4RequestContent::GetAttr)(i)
}

#[derive(Debug, PartialEq, Eq)]
pub struct Nfs4RequestWrite<'a> {
    pub stateid: Nfs4StateId<'a>,
    pub offset: u64,
    pub stable: u32,
    pub write_len: u32,
    pub data: &'a [u8],
}

fn nfs4_req_write(i: &[u8]) -> IResult<&[u8], Nfs4RequestContent<'_>> {
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

#[derive(Debug, PartialEq, Eq)]
pub struct Nfs4RequestRead<'a> {
    pub stateid: Nfs4StateId<'a>,
    pub offset: u64,
    pub count: u32,
}

fn nfs4_req_read(i: &[u8]) -> IResult<&[u8], Nfs4RequestContent<'_>> {
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

fn nfs4_req_close(i: &[u8]) -> IResult<&[u8], Nfs4RequestContent<'_>> {
    let (i, _seq_id) = be_u32(i)?;
    let (i, stateid) = nfs4_parse_stateid(i)?;
    Ok((i, Nfs4RequestContent::Close(stateid)))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Nfs4RequestOpenConfirm<'a> {
    pub stateid: Nfs4StateId<'a>,
}

fn nfs4_req_open_confirm(i: &[u8]) -> IResult<&[u8], Nfs4RequestContent<'_>> {
    let (i, _seq_id) = be_u32(i)?;
    let (i, stateid) = nfs4_parse_stateid(i)?;
    let req = Nfs4RequestContent::OpenConfirm(Nfs4RequestOpenConfirm { stateid });
    Ok((i, req))
}

fn nfs4_req_delegreturn(i: &[u8]) -> IResult<&[u8], Nfs4RequestContent<'_>> {
    map(nfs4_parse_stateid, Nfs4RequestContent::DelegReturn)(i)
}

fn nfs4_req_renew(i: &[u8]) -> IResult<&[u8], Nfs4RequestContent<'_>> {
    map(be_u64, Nfs4RequestContent::Renew)(i)
}

fn nfs4_req_getfh(i: &[u8]) -> IResult<&[u8], Nfs4RequestContent<'_>> {
    Ok((i, Nfs4RequestContent::GetFH))
}

fn nfs4_req_savefh(i: &[u8]) -> IResult<&[u8], Nfs4RequestContent<'_>> {
    Ok((i, Nfs4RequestContent::SaveFH))
}

fn nfs4_req_putrootfh(i: &[u8]) -> IResult<&[u8], Nfs4RequestContent<'_>> {
    Ok((i, Nfs4RequestContent::PutRootFH))
}

fn nfs4_req_access(i: &[u8]) -> IResult<&[u8], Nfs4RequestContent<'_>> {
    map(be_u32, Nfs4RequestContent::Access)(i)
}

fn nfs4_req_commit(i: &[u8]) -> IResult<&[u8], Nfs4RequestContent<'_>> {
    let (i, _offset) = be_u64(i)?;
    let (i, _count) = be_u32(i)?;
    Ok((i, Nfs4RequestContent::Commit))
}

fn nfs4_req_reclaim_complete(i: &[u8]) -> IResult<&[u8], Nfs4RequestContent<'_>> {
    map(
        verify(be_u32, |&v| v <= 1),
        Nfs4RequestContent::ReclaimComplete,
    )(i)
}

fn nfs4_req_destroy_clientid(i: &[u8]) -> IResult<&[u8], Nfs4RequestContent<'_>> {
    let (i, client_id) = take(8_usize)(i)?;
    Ok((i, Nfs4RequestContent::DestroyClientID(client_id)))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Nfs4RequestLayoutGet<'a> {
    pub layout_type: u32,
    pub length: u64,
    pub min_length: u64,
    pub stateid: Nfs4StateId<'a>,
}

fn nfs4_req_layoutget(i: &[u8]) -> IResult<&[u8], Nfs4RequestContent<'_>> {
    let (i, _layout_available) = verify(be_u32, |&v| v <= 1)(i)?;
    let (i, layout_type) = be_u32(i)?;
    let (i, _iq_mode) = be_u32(i)?;
    let (i, _offset) = be_u64(i)?;
    let (i, length) = be_u64(i)?;
    let (i, min_length) = be_u64(i)?;
    let (i, stateid) = nfs4_parse_stateid(i)?;
    let (i, _maxcount) = be_u32(i)?;
    let req = Nfs4RequestContent::LayoutGet(Nfs4RequestLayoutGet {
        layout_type,
        length,
        min_length,
        stateid,
    });
    Ok((i, req))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Nfs4RequestExchangeId<'a> {
    pub client_string: &'a [u8],
    pub nii_domain: &'a [u8],
    pub nii_name: &'a [u8],
}

fn nfs4_req_exchangeid(i: &[u8]) -> IResult<&[u8], Nfs4RequestContent<'_>> {
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
        nii_name,
    });
    Ok((i, req))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Nfs4RequestSequence<'a> {
    pub ssn_id: &'a [u8],
}

fn nfs4_req_sequence(i: &[u8]) -> IResult<&[u8], Nfs4RequestContent<'_>> {
    let (i, ssn_id) = take(16_usize)(i)?;
    let (i, _seq_id) = be_u32(i)?;
    let (i, _slot_id) = be_u32(i)?;
    let (i, _high_slot_id) = be_u32(i)?;
    let (i, _cache_this) = be_u32(i)?;
    let req = Nfs4RequestContent::Sequence(Nfs4RequestSequence { ssn_id });
    Ok((i, req))
}

fn parse_request_compound_command(i: &[u8]) -> IResult<&[u8], Nfs4RequestContent<'_>> {
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
        NFSPROC4_CREATE_SESSION => nfs4_req_create_session(i)?,
        NFSPROC4_RECLAIM_COMPLETE => nfs4_req_reclaim_complete(i)?,
        NFSPROC4_SECINFO_NO_NAME => nfs4_req_secinfo_no_name(i)?,
        NFSPROC4_LAYOUTGET => nfs4_req_layoutget(i)?,
        NFSPROC4_GETDEVINFO => nfs4_req_getdevinfo(i)?,
        NFSPROC4_LAYOUTRETURN => nfs4_req_layoutreturn(i)?,
        NFSPROC4_DESTROY_SESSION => nfs4_req_destroy_session(i)?,
        NFSPROC4_DESTROY_CLIENTID => nfs4_req_destroy_clientid(i)?,
        _ => {
            return Err(Err::Error(make_error(i, ErrorKind::Switch)));
        }
    };
    Ok((i, cmd_data))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Nfs4RequestCompoundRecord<'a> {
    pub commands: Vec<Nfs4RequestContent<'a>>,
}

pub fn parse_nfs4_request_compound(i: &[u8]) -> IResult<&[u8], Nfs4RequestCompoundRecord<'_>> {
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

// Self-contained leading-op advance for the scanners: declared length fields
// + XDR padding only (regular parsers are not wire-faithful); untabled ops fall back.

/// Consume `len` bytes plus their XDR padding (bound-checked so the skip
/// cannot wrap a usize on 32-bit targets).
fn skip_xdr_bytes(i: &[u8], len: usize) -> IResult<&[u8], ()> {
    let pad = (4 - (len % 4)) % 4;
    if i.len() < len || i.len() - len < pad {
        return Err(Err::Incomplete(Needed::new(1)));
    }
    Ok((&i[len + pad..], ()))
}

fn skip_fixed(i: &[u8], n: usize) -> IResult<&[u8], ()> {
    if i.len() < n {
        return Err(Err::Incomplete(Needed::new(1)));
    }
    Ok((&i[n..], ()))
}

/// Consume a length-prefixed XDR string (length + bytes + padding).
fn skip_len_bytes(i: &[u8]) -> IResult<&[u8], ()> {
    let (i, len) = be_u32(i)?;
    skip_xdr_bytes(i, len as usize)
}

/// Consume a declared sattr4 bitmap: attr_cnt + attr_cnt words, no blob.
fn skip_attrbits(i: &[u8]) -> IResult<&[u8], ()> {
    let (i, attr_cnt) = be_u32(i)?;
    skip_xdr_bytes(i, (attr_cnt as usize).saturating_mul(4))
}

/// Consume a declared fattr4: attr_cnt + attr_cnt words + the fields blob
/// (present even when empty).
fn skip_attrlist(i: &[u8]) -> IResult<&[u8], ()> {
    let (i, attr_cnt) = be_u32(i)?;
    let (i, ()) = skip_xdr_bytes(i, (attr_cnt as usize).saturating_mul(4))?;
    skip_len_bytes(i)
}

/// Consume a sattr4/fattr4 bitmap the way the parser reads it
/// (nfs4_parse_attrbits): attr_cnt + mask1 (always) + mask2 (cnt >= 2) + mask3
/// (cnt == 3). Unlike skip_attrbits this mirrors the parser, not the wire: the
/// OPEN requests/replies the parser supports carry the mask words it consumes,
/// and the scan must end where the parser ends.
fn skip_parser_attrbits(i: &[u8]) -> IResult<&[u8], ()> {
    let (i, attr_cnt) = be_u32(i)?;
    let (i, ()) = skip_fixed(i, 4)?;
    let i = if attr_cnt >= 2 {
        let (i, ()) = skip_fixed(i, 4)?;
        i
    } else {
        i
    };
    let i = if attr_cnt == 3 {
        let (i, ()) = skip_fixed(i, 4)?;
        i
    } else {
        i
    };
    Ok((i, ()))
}

/// Consume the fattr4/sattr4 fields blob: len + bytes, no XDR pad
/// (mirrors nfs4_parse_attr_fields).
fn skip_attr_fields(i: &[u8]) -> IResult<&[u8], ()> {
    let (i, len) = be_u32(i)?;
    if i.len() < len as usize {
        return Err(Err::Incomplete(Needed::new(1)));
    }
    Ok((&i[len as usize..], ()))
}

/// Advance past the arguments of a leading REQUEST op per the wire. Ok
/// (next op position) for tabled ops; Err(Incomplete) when the declared
/// fields are not all in the buffer yet; Err(Error(Switch)) for ops that
/// are not tabled (the caller falls back to the regular parser).
fn skip_request_lead_op(i: &[u8], cmd: u32) -> IResult<&[u8], ()> {
    match cmd {
        NFSPROC4_PUTFH => skip_len_bytes(i),
        NFSPROC4_GETFH | NFSPROC4_SAVEFH | NFSPROC4_PUTROOTFH => skip_fixed(i, 0),
        NFSPROC4_RENEW => skip_fixed(i, 8),
        NFSPROC4_RECLAIM_COMPLETE => skip_fixed(i, 4),
        // attribute bitmap (getattr4args)
        NFSPROC4_GETATTR => skip_attrbits(i),
        // stateid + the parser's attr list (bitmap + fields blob, even
        // when empty)
        NFSPROC4_SETATTR => {
            let (i, ()) = skip_fixed(i, 16)?;
            skip_attrlist(i)
        }
        // seq + stateid
        NFSPROC4_CLOSE | NFSPROC4_OPEN_CONFIRM => {
            let (i, ()) = skip_fixed(i, 4)?;
            skip_fixed(i, 16)
        }
        // offset + count
        NFSPROC4_COMMIT => skip_fixed(i, 12),
        // stateid + offset + count
        NFSPROC4_READ => {
            let (i, ()) = skip_fixed(i, 16)?;
            skip_fixed(i, 12)
        }
        // access bits
        NFSPROC4_ACCESS => skip_fixed(i, 4),
        // open4args as nfs4_req_open parses it: seq_id (4) + share_access +
        // share_deny + client_id (8) + owner (len + bytes, no XDR pad) +
        // open_type (+ open_data for type 1) + claim_type + name. The parser
        // reads no claim payload: payload-bearing claims desync it (their
        // stateid/fh is read as the name length), as do the other
        // open_types: not skippable.
        NFSPROC4_OPEN => {
            let (i, ()) = skip_fixed(i, 20)?;
            let (i, owner_len) = be_u32(i)?;
            if i.len() < owner_len as usize {
                return Err(Err::Incomplete(Needed::new(1)));
            }
            let i = &i[owner_len as usize..];
            let (i, open_type) = be_u32(i)?;
            let i = if open_type == 1 {
                let (i, mode) = be_u32(i)?;
                match mode {
                    // sattr4 like nfs4_parse_attrs: parser-shaped bitmap +
                    // the fields blob
                    0 | 1 => {
                        let (i, ()) = skip_parser_attrbits(i)?;
                        let (i, ()) = skip_attr_fields(i)?;
                        i
                    }
                    2 | 3 => {
                        let (i, ()) = skip_fixed(i, 8)?;
                        i
                    }
                    _ => return Err(Err::Error(make_error(i, ErrorKind::Switch))),
                }
            } else if open_type == 0 {
                i
            } else {
                return Err(Err::Error(make_error(i, ErrorKind::Switch)));
            };
            // claim4: the parser reads no claim payload (void claims
            // only): payload-bearing claims (FH, DELEGATE, FH_ONLY and the
            // v4.2 claims) desync it (the payload is read as the name
            // length). Only the claims void in every version (NULL=0,
            // UNIQUE=2) are skippable; the rest are a bounded rejection,
            // never Incomplete (buffering toward the record claim).
            let (i, claim_type) = be_u32(i)?;
            match claim_type {
                0 | 2 => {}
                _ => return Err(Err::Error(make_error(i, ErrorKind::Switch))),
            }
            skip_len_bytes(i)
        }
        // name (XDR string)
        NFSPROC4_LOOKUP | NFSPROC4_REMOVE => skip_len_bytes(i),
        // two names
        NFSPROC4_RENAME => {
            let (i, ()) = skip_len_bytes(i)?;
            skip_len_bytes(i)
        }
        // cookie + cookie verifier + counts + attribute bitmap
        NFSPROC4_READDIR => {
            let (i, ()) = skip_fixed(i, 24)?;
            skip_attrbits(i)
        }
        // stateid
        NFSPROC4_DELEGRETURN => skip_fixed(i, 16),
        // NB: CREATE_SESSION is intentionally NOT tabled: its variable-length
        // / union args can't be reliably skipped; the scanner treats it as
        // untabled and applies a bounded rejection (scan_*_compound_*_len_i).
        // ftype (+ link content when NF4LNK) + name + attribute list
        NFSPROC4_CREATE => {
            let (i, ftype) = be_u32(i)?;
            let i = if ftype == 3 || ftype == 4 {
                // nfset4: block/character device number (RFC 7530
                // createhow4 union)
                let (i, ()) = skip_fixed(i, 8)?;
                i
            } else {
                i
            };
            let i = if ftype == 5 {
                let (i, ()) = skip_len_bytes(i)?;
                i
            } else {
                i
            };
            let (i, ()) = skip_len_bytes(i)?;
            skip_attrlist(i)
        }
        // layout args
        NFSPROC4_LAYOUTGET => skip_fixed(i, 4 + 4 + 4 + 8 + 8 + 8 + 16 + 4),
        // device id + counts + the declared notify bitmap
        NFSPROC4_GETDEVINFO => {
            let (i, ()) = skip_fixed(i, 16 + 4 + 4)?;
            skip_attrbits(i)
        }
        // LAYOUTRETURN4args (RFC 8881 18.44): reclaim + layout type + iomode; only
        // FILE(1) carries lrf offset/length/stateid + body opaque (FSID/ALL carry nothing)
        NFSPROC4_LAYOUTRETURN => {
            let (i, ()) = skip_fixed(i, 4 + 4 + 4)?;
            let (i, ret_type) = be_u32(i)?;
            if ret_type == 1 {
                let (i, ()) = skip_fixed(i, 8 + 8 + 16)?;
                skip_len_bytes(i)
            } else {
                Ok((i, ()))
            }
        }
        NFSPROC4_DESTROY_SESSION => skip_fixed(i, 16),
        NFSPROC4_DESTROY_CLIENTID => skip_fixed(i, 8),
        NFSPROC4_SETCLIENTID_CONFIRM => skip_fixed(i, 16),
        // setclientid4args (RFC 7530 18.26): verifier + client_id + cb_program
        // + r_netid + r_addr + cb_id
        NFSPROC4_SETCLIENTID => {
            let (i, ()) = skip_fixed(i, 8)?;
            let (i, ()) = skip_len_bytes(i)?;
            let (i, ()) = skip_fixed(i, 4)?;
            let (i, ()) = skip_len_bytes(i)?;
            let (i, ()) = skip_len_bytes(i)?;
            skip_fixed(i, 4)
        }
        // exchange_id3 args: verifier + clientstring + 3 words + nii domain
        // + name + 12-byte date
        NFSPROC4_EXCHANGE_ID => {
            let (i, ()) = skip_fixed(i, 8)?;
            let (i, ()) = skip_len_bytes(i)?;
            let (i, ()) = skip_fixed(i, 12)?;
            let (i, ()) = skip_len_bytes(i)?;
            let (i, ()) = skip_len_bytes(i)?;
            skip_fixed(i, 12)
        }
        // 4-byte security flavor
        NFSPROC4_SECINFO_NO_NAME => skip_fixed(i, 4),
        NFSPROC4_SEQUENCE => skip_fixed(i, 16 + 16),
        _ => Err(Err::Error(make_error(i, ErrorKind::Switch))),
    }
}

/// Advance past the arguments of a leading RESPONSE op per the wire (see
/// skip_request_lead_op). A failed op carries its status only.
fn skip_response_lead_op(i: &[u8], cmd: u32) -> IResult<&[u8], ()> {
    let (i, status) = be_u32(i)?;
    if status != 0 {
        return Ok((i, ()));
    }
    match cmd {
        NFSPROC4_PUTFH
        | NFSPROC4_PUTROOTFH
        | NFSPROC4_RENEW
        | NFSPROC4_DELEGRETURN
        | NFSPROC4_LOOKUP
        | NFSPROC4_SAVEFH
        | NFSPROC4_SETCLIENTID_CONFIRM
        | NFSPROC4_RECLAIM_COMPLETE
        | NFSPROC4_DESTROY_SESSION
        | NFSPROC4_DESTROY_CLIENTID => Ok((i, ())),
        // two change_info4 structs (verifier before/after + atomic each)
        NFSPROC4_RENAME => skip_fixed(i, 40),
        // file handle
        NFSPROC4_GETFH => skip_len_bytes(i),
        // attribute list (fattr4: bitmap + fields blob, even when empty)
        NFSPROC4_GETATTR => skip_attrlist(i),
        // changed attributes bitmap
        NFSPROC4_SETATTR => skip_attrbits(i),
        // stateid
        NFSPROC4_CLOSE | NFSPROC4_OPEN_CONFIRM => skip_fixed(i, 16),
        // writeverf4
        NFSPROC4_COMMIT => skip_fixed(i, 8),
        // count + committed + writeverf4
        NFSPROC4_WRITE => skip_fixed(i, 16),
        // change info
        NFSPROC4_REMOVE => skip_fixed(i, 20),
        // change_info4 + attributes bitmap
        NFSPROC4_CREATE => {
            let (i, ()) = skip_fixed(i, 20)?;
            skip_attrbits(i)
        }
        // supported types + access rights
        NFSPROC4_ACCESS => skip_fixed(i, 8),
        // stateid + change_info + result_flags + fattr4 bitmap + file_delegation4 union
        NFSPROC4_OPEN => {
            let (i, ()) = skip_fixed(i, 16 + 20 + 4)?;
            let (i, ()) = skip_parser_attrbits(i)?;
            let (i, deleg) = be_u32(i)?;
            match deleg {
                // stateid + 4 words + who_len, then who (no XDR pad, mirrors the parser)
                OPEN_DELEGATE_READ => {
                    let (i, ()) = skip_fixed(i, 16 + 4 * 4)?;
                    let (i, who_len) = be_u32(i)?;
                    if i.len() < who_len as usize {
                        return Err(Err::Incomplete(Needed::new(1)));
                    }
                    Ok((&i[who_len as usize..], ()))
                }
                // stateid + 6 words, then who (nfsstring)
                OPEN_DELEGATE_WRITE => {
                    let (i, ()) = skip_fixed(i, 16 + 4 * 6)?;
                    skip_len_bytes(i)
                }
                OPEN_DELEGATE_NONE => Ok((i, ())),
                _ => Err(Err::Error(make_error(i, ErrorKind::Switch))),
            }
        }
        // nfs41_sequence_ok = ssn4(16) + seqid(4) + slots(12) + flags(4) = 36 bytes.
        // A typical NFSv4.1 reply leads with SEQUENCE; skipping its result reaches a
        // following READ (status already consumed above).
        NFSPROC4_SEQUENCE => skip_fixed(i, 36),
        // setclientid4resok: client_id + verifier
        NFSPROC4_SETCLIENTID => skip_fixed(i, 16),
        // exchange_id4resok: client_id + seqid + flags + state_protect + minorid
        // + majorid + scope + impl_id + nii + date
        NFSPROC4_EXCHANGE_ID => {
            let (i, ()) = skip_fixed(i, 8 + 4 + 4 + 4 + 8)?;
            let (i, ()) = skip_len_bytes(i)?;
            let (i, ()) = skip_len_bytes(i)?;
            let (i, ()) = skip_fixed(i, 4)?;
            let (i, ()) = skip_len_bytes(i)?;
            let (i, ()) = skip_len_bytes(i)?;
            skip_fixed(i, 12)
        }
        // secinfo_no_name_resok: flavors_cnt + count * flavor; a GSS flavor
        // carries an oid string + 8 bytes, others only the 4-byte type.
        // Each entry consumes at least 4 bytes, so the loop is bounded.
        NFSPROC4_SECINFO_NO_NAME => {
            let (i, cnt) = be_u32(i)?;
            let mut i = i;
            for _n in 0..cnt {
                let (i2, flavor) = be_u32(i)?;
                if flavor == RPCSEC_GSS {
                    let (i3, ()) = skip_len_bytes(i2)?;
                    let (i4, ()) = skip_fixed(i3, 8)?;
                    i = i4;
                } else {
                    i = i2;
                }
            }
            Ok((i, ()))
        }
        _ => Err(Err::Error(make_error(i, ErrorKind::Switch))),
    }
}

/// Outcome of the bounded v4 compound scanners
/// (scan_nfs4_request_compound_write_len / scan_nfs4_response_compound_read_len).
///
/// A structural scan error ([Nfs4CompoundScan::Malformed]) is definitive
/// from the buffered bytes: it must never be treated as "no oversized op",
/// failing open would let the record be buffered toward the
/// attacker-controlled record length (memory exhaustion).
#[derive(Debug, PartialEq, Eq)]
pub enum Nfs4CompoundScan {
    /// A WRITE/READ op claims more than the limit: reject the record even
    /// though its data is not (all) buffered.
    Oversized(u32),
    /// A within-limit file op is present but its data is not all buffered
    /// yet (or the scan needs more header bytes): the record must complete
    /// before the scan is conclusive.
    Incomplete,
    /// Structurally malformed compound (op count above the bound, unknown
    /// leading op, desynchronized fields): skip the record; do not buffer
    /// toward the claimed record length.
    Malformed,
    /// The scan completed and found no oversized file op.
    Clean,
}

/// Scan a (possibly incomplete) v4 request compound for a WRITE. A WRITE
/// whose claimed length exceeds `max` is reported as Oversized even with
/// incomplete data; completed within-limit WRITEs and leading ops are
/// skipped, so a later WRITE cannot hide behind them.
pub fn scan_nfs4_request_compound_write_len(i: &[u8], max: u32) -> Nfs4CompoundScan {
    match scan_nfs4_request_compound_write_len_i(i, max) {
        Ok((_, Some(v))) if v > max => Nfs4CompoundScan::Oversized(v),
        Ok((_, Some(_v))) => Nfs4CompoundScan::Incomplete,
        Ok((_, None)) => Nfs4CompoundScan::Clean,
        Err(Err::Incomplete(_)) => Nfs4CompoundScan::Incomplete,
        Err(_) => Nfs4CompoundScan::Malformed,
    }
}

/// Returns Ok((_, Some(claim))) when a WRITE is found (oversized claim,
/// or within-limit with incomplete data) and Ok((_, None)) when the
/// compound carries no WRITE at all.
fn scan_nfs4_request_compound_write_len_i(i: &[u8], max: u32) -> IResult<&[u8], Option<u32>> {
    // The tag is an XDR string: consume it with its padding (a non-aligned tag
    // shifts every later read early, making the compound look op-less).
    let (i, _tag) = nfs4_parse_nfsstring(i)?;
    let (i, _min_ver) = be_u32(i)?;
    let (i, ops_cnt) = be_u32(i)?;
    if ops_cnt as usize > NFSD_MAX_OPS_PER_COMPOUND {
        return Err(Err::Error(make_error(i, ErrorKind::Count)));
    }
    let mut cur = i;
    for idx in 0..ops_cnt as usize {
        let (next, cmd) = be_u32(cur)?;
        if cmd == NFSPROC4_WRITE {
            // stop at the claimed length; the data blob is not needed
            let (i, _stateid) = nfs4_parse_stateid(next)?;
            let (i, _offset) = be_u64(i)?;
            let (i, _stable) = be_u32(i)?;
            let (i, write_len) = be_u32(i)?;
            if write_len > max {
                // reject even if the (unbuffered) data is missing
                return Ok((i, Some(write_len)));
            }
            // XDR pads the data to a 32-bit boundary (mirrors nfs4_req_write);
            // the next op tag starts after it.
            let pad = (4 - (write_len % 4) as usize) % 4;
            // bound-check before the addition so the skip cannot wrap a
            // usize on 32-bit targets
            if write_len as usize > i.len() || i.len() - (write_len as usize) < pad {
                // the data (or its padding) is not all here yet: nothing after this
                // WRITE is visible; stop and let the record complete (re-runs longer).
                return Ok((i, Some(write_len)));
            }
            // a completed, within-limit WRITE: skip its data and padding
            // so a later WRITE in the same compound cannot hide behind it
            cur = &i[(write_len as usize) + pad..];
            continue;
        }
        // Leading ops are advanced per the wire (declared length fields +
        // XDR padding); see skip_request_lead_op.
        match skip_request_lead_op(next, cmd) {
            Ok((pos, _)) => cur = pos,
            Err(Err::Incomplete(_)) => return Err(Err::Incomplete(Needed::new(1))),
            Err(_) => {
                // Not in the safe skip table (variable-length / union args, cf.
                // CREATE_SESSION/OPEN). Last op -> nothing follows -> clean; otherwise
                // bounded rejection (Malformed), never Incomplete (OOM) or Clean (fail-open).
                if idx + 1 == ops_cnt as usize {
                    return Ok((cur, None));
                }
                return Err(Err::Error(make_error(cur, ErrorKind::Switch)));
            }
        }
    }
    // no WRITE op in the compound
    Ok((i, None))
}

/// Scan a (possibly incomplete) v4 response compound for a successful
/// READ. A READ whose claimed length exceeds `max` is reported as
/// Oversized even with incomplete data; failed READs, within-limit READs
/// and leading ops are skipped, so a later READ cannot hide behind them.
pub fn scan_nfs4_response_compound_read_len(i: &[u8], max: u32) -> Nfs4CompoundScan {
    match scan_nfs4_response_compound_read_len_i(i, max) {
        Ok((_, Some(v))) if v > max => Nfs4CompoundScan::Oversized(v),
        Ok((_, Some(_v))) => Nfs4CompoundScan::Incomplete,
        Ok((_, None)) => Nfs4CompoundScan::Clean,
        Err(Err::Incomplete(_)) => Nfs4CompoundScan::Incomplete,
        Err(_) => Nfs4CompoundScan::Malformed,
    }
}

/// Returns Ok((_, Some(claim))) when a successful READ is found
/// (oversized claim, or within-limit with incomplete data) and
/// Ok((_, None)) when the compound carries no successful READ at all.
fn scan_nfs4_response_compound_read_len_i(i: &[u8], max: u32) -> IResult<&[u8], Option<u32>> {
    let (i, _status) = be_u32(i)?;
    // The compound status reflects the last executed op only; earlier ops
    // may have returned data, so the scan continues regardless.
    let (i, _tag) = nfs4_parse_nfsstring(i)?; // XDR string: padding included
                                              /* compoundres4: no minorversion field (unlike the request's
                                               * compoundargs4); the operation count follows the tag. */
    let (i, ops_cnt) = be_u32(i)?;
    if ops_cnt as usize > NFSD_MAX_OPS_PER_COMPOUND {
        return Err(Err::Error(make_error(i, ErrorKind::Count)));
    }
    let mut cur = i;
    for idx in 0..ops_cnt as usize {
        let (next, cmd) = be_u32(cur)?;
        if cmd == NFSPROC4_READ {
            // stop at the claimed length; the data blob is not needed
            let (i, st) = be_u32(next)?;
            if st != 0 {
                // this READ failed: no result words follow the status (cf. nfs4_res_read).
                // Keep walking -- a later successful READ may still carry an oversized claim.
                cur = i;
                continue;
            }
            let (i, _eof) = verify(be_u32, |&v| v <= 1)(i)?;
            let (i, read_len) = be_u32(i)?;
            if read_len > max {
                // reject even if the (unbuffered) data is missing
                return Ok((i, Some(read_len)));
            }
            if i.len() < read_len as usize {
                // the data is not all here yet: stop and let the record complete
                // (the scan re-runs with the longer buffer)
                return Ok((i, Some(read_len)));
            }
            // XDR pads the data to a 32-bit boundary; the next op tag starts after it.
            // (nfs4_res_read_ok doesn't consume the padding; the scan follows the wire.)
            let pad = (4 - (read_len % 4) as usize) % 4;
            // bound-check before the addition so the skip cannot wrap a
            // usize on 32-bit targets
            if read_len as usize > i.len() || i.len() - (read_len as usize) < pad {
                // the data (or its padding) is not all here yet: nothing after this
                // READ is visible; stop and let the record complete (re-runs longer).
                return Ok((i, Some(read_len)));
            }
            // a completed, within-limit READ: skip its data and padding
            // so a later READ in the same compound cannot hide behind it
            cur = &i[(read_len as usize) + pad..];
            continue;
        }
        // Leading ops are advanced per the wire (declared length fields +
        // XDR padding); see skip_response_lead_op.
        match skip_response_lead_op(next, cmd) {
            Ok((pos, _)) => cur = pos,
            Err(Err::Incomplete(_)) => return Err(Err::Incomplete(Needed::new(1))),
            Err(_) => {
                // Not in the safe skip table (variable-length / union args). Last op
                // -> nothing follows -> clean; otherwise bounded rejection (Malformed),
                // never Incomplete (OOM) or Clean (fail-open).
                if idx + 1 == ops_cnt as usize {
                    return Ok((cur, None));
                }
                return Err(Err::Error(make_error(cur, ErrorKind::Switch)));
            }
        }
    }
    // no successful READ op in the compound
    Ok((i, None))
}

#[derive(Debug, PartialEq, Eq)]
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
    ExchangeId(u32, Option<Nfs4ResponseExchangeId<'a>>),
    Sequence(u32, Option<Nfs4ResponseSequence<'a>>),
    CreateSession(u32, Option<Nfs4ResponseCreateSession<'a>>),
    ReclaimComplete(u32),
    SecInfoNoName(u32),
    LayoutGet(u32, Option<Nfs4ResponseLayoutGet<'a>>),
    GetDevInfo(u32, Option<Nfs4ResponseGetDevInfo<'a>>),
    LayoutReturn(u32),
    DestroySession(u32),
    DestroyClientID(u32),
}

// might need improvement with a stateid_present = yes case
fn nfs4_res_layoutreturn(i: &[u8]) -> IResult<&[u8], Nfs4ResponseContent<'_>> {
    let (i, status) = be_u32(i)?;
    let (i, _stateid_present) = verify(be_u32, |&v| v <= 1)(i)?;
    Ok((i, Nfs4ResponseContent::LayoutReturn(status)))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Nfs4ResponseCreateSession<'a> {
    pub ssn_id: &'a [u8],
    pub seq_id: u32,
}

fn nfs4_parse_res_create_session(i: &[u8]) -> IResult<&[u8], Nfs4ResponseCreateSession<'_>> {
    let (i, ssn_id) = take(16_usize)(i)?;
    let (i, seq_id) = be_u32(i)?;
    let (i, _flags) = be_u32(i)?;
    let (i, _fore_chan_attrs) = take(28_usize)(i)?;
    let (i, _back_chan_attrs) = take(28_usize)(i)?;
    Ok((i, Nfs4ResponseCreateSession { ssn_id, seq_id }))
}

fn nfs4_res_create_session(i: &[u8]) -> IResult<&[u8], Nfs4ResponseContent<'_>> {
    let (i, status) = be_u32(i)?;
    let (i, create_ssn_data) = cond(status == 0, nfs4_parse_res_create_session)(i)?;
    Ok((
        i,
        Nfs4ResponseContent::CreateSession(status, create_ssn_data),
    ))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Nfs4ResponseExchangeId<'a> {
    pub client_id: &'a [u8],
    pub eir_minorid: u64,
    pub eir_majorid: &'a [u8],
    pub nii_domain: &'a [u8],
    pub nii_name: &'a [u8],
}

fn nfs4_parse_res_exchangeid(i: &[u8]) -> IResult<&[u8], Nfs4ResponseExchangeId<'_>> {
    let (i, client_id) = take(8_usize)(i)?;
    let (i, _seqid) = be_u32(i)?;
    let (i, _flags) = be_u32(i)?;
    let (i, _eia_state_protect) = be_u32(i)?;
    let (i, eir_minorid) = be_u64(i)?;
    let (i, eir_majorid) = nfs4_parse_nfsstring(i)?;
    let (i, _server_scope) = nfs4_parse_nfsstring(i)?;
    let (i, _eir_impl_id) = be_u32(i)?;
    let (i, nii_domain) = nfs4_parse_nfsstring(i)?;
    let (i, nii_name) = nfs4_parse_nfsstring(i)?;
    let (i, _nii_date_sec) = be_u64(i)?;
    let (i, _nii_date_nsec) = be_u32(i)?;
    Ok((
        i,
        Nfs4ResponseExchangeId {
            client_id,
            eir_minorid,
            eir_majorid,
            nii_domain,
            nii_name,
        },
    ))
}

fn nfs4_res_reclaim_complete(i: &[u8]) -> IResult<&[u8], Nfs4ResponseContent<'_>> {
    map(be_u32, Nfs4ResponseContent::ReclaimComplete)(i)
}

fn nfs4_res_exchangeid(i: &[u8]) -> IResult<&[u8], Nfs4ResponseContent<'_>> {
    let (i, status) = be_u32(i)?;
    let (i, xchngid_data) = cond(status == 0, nfs4_parse_res_exchangeid)(i)?;
    Ok((i, Nfs4ResponseContent::ExchangeId(status, xchngid_data)))
}

#[derive(Debug, PartialEq, Eq)]
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

fn nfs4_res_write(i: &[u8]) -> IResult<&[u8], Nfs4ResponseContent<'_>> {
    let (i, status) = be_u32(i)?;
    let (i, wd) = cond(status == 0, nfs4_res_write_ok)(i)?;
    Ok((i, Nfs4ResponseContent::Write(status, wd)))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Nfs4ResponseRead<'a> {
    pub eof: bool,
    pub count: u32,
    pub data: &'a [u8],
}

fn nfs4_res_read_ok(i: &[u8]) -> IResult<&[u8], Nfs4ResponseRead<'_>> {
    let (i, eof) = verify(be_u32, |&v| v <= 1)(i)?;
    let (i, read_len) = be_u32(i)?;
    let (i, read_data) = take(read_len as usize)(i)?;
    let resp = Nfs4ResponseRead {
        eof: eof == 1,
        count: read_len,
        data: read_data,
    };
    Ok((i, resp))
}

fn nfs4_res_read(i: &[u8]) -> IResult<&[u8], Nfs4ResponseContent<'_>> {
    let (i, status) = be_u32(i)?;
    let (i, rd) = cond(status == 0, nfs4_res_read_ok)(i)?;
    Ok((i, Nfs4ResponseContent::Read(status, rd)))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Nfs4ResponseOpen<'a> {
    pub stateid: Nfs4StateId<'a>,
    pub result_flags: u32,
    pub delegate: Nfs4ResponseFileDelegation<'a>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Nfs4ResponseFileDelegation<'a> {
    DelegateRead(Nfs4ResponseOpenDelegateRead<'a>),
    DelegateWrite(Nfs4ResponseOpenDelegateWrite<'a>),
    DelegateNone(u32),
}

#[derive(Debug, PartialEq, Eq)]
pub struct Nfs4ResponseOpenDelegateWrite<'a> {
    pub stateid: Nfs4StateId<'a>,
    pub who: &'a [u8],
}

fn nfs4_res_open_ok_delegate_write(i: &[u8]) -> IResult<&[u8], Nfs4ResponseFileDelegation<'_>> {
    let (i, stateid) = nfs4_parse_stateid(i)?;
    let (i, _recall) = be_u32(i)?;
    let (i, _space_limit) = be_u32(i)?;
    let (i, _filesize) = be_u32(i)?;
    let (i, _access_type) = be_u32(i)?;
    let (i, _ace_flags) = be_u32(i)?;
    let (i, _ace_mask) = be_u32(i)?;
    let (i, who) = nfs4_parse_nfsstring(i)?;
    Ok((
        i,
        Nfs4ResponseFileDelegation::DelegateWrite(Nfs4ResponseOpenDelegateWrite { stateid, who }),
    ))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Nfs4ResponseOpenDelegateRead<'a> {
    pub stateid: Nfs4StateId<'a>,
}

fn nfs4_res_open_ok_delegate_read(i: &[u8]) -> IResult<&[u8], Nfs4ResponseFileDelegation<'_>> {
    let (i, stateid) = nfs4_parse_stateid(i)?;
    let (i, _recall) = be_u32(i)?;
    let (i, _ace_type) = be_u32(i)?;
    let (i, _ace_flags) = be_u32(i)?;
    let (i, _ace_mask) = be_u32(i)?;
    let (i, who_len) = be_u32(i)?;
    let (i, _who) = take(who_len as usize)(i)?;
    Ok((
        i,
        Nfs4ResponseFileDelegation::DelegateRead(Nfs4ResponseOpenDelegateRead { stateid }),
    ))
}

fn nfs4_parse_file_delegation(i: &[u8]) -> IResult<&[u8], Nfs4ResponseFileDelegation<'_>> {
    let (i, delegation_type) = be_u32(i)?;
    let (i, file_delegation) = match delegation_type {
        OPEN_DELEGATE_READ => nfs4_res_open_ok_delegate_read(i)?,
        OPEN_DELEGATE_WRITE => nfs4_res_open_ok_delegate_write(i)?,
        OPEN_DELEGATE_NONE => (
            i,
            Nfs4ResponseFileDelegation::DelegateNone(OPEN_DELEGATE_NONE),
        ),
        _ => {
            return Err(Err::Error(make_error(i, ErrorKind::Switch)));
        }
    };
    Ok((i, file_delegation))
}

fn nfs4_res_open_ok(i: &[u8]) -> IResult<&[u8], Nfs4ResponseOpen<'_>> {
    let (i, stateid) = nfs4_parse_stateid(i)?;
    let (i, _change_info) = take(20_usize)(i)?;
    let (i, result_flags) = be_u32(i)?;
    let (i, _attrs) = nfs4_parse_attrbits(i)?;
    let (i, delegate) = nfs4_parse_file_delegation(i)?;
    let resp = Nfs4ResponseOpen {
        stateid,
        result_flags,
        delegate,
    };
    Ok((i, resp))
}

fn nfs4_res_open(i: &[u8]) -> IResult<&[u8], Nfs4ResponseContent<'_>> {
    let (i, status) = be_u32(i)?;
    let (i, open_data) = cond(status == 0, nfs4_res_open_ok)(i)?;
    Ok((i, Nfs4ResponseContent::Open(status, open_data)))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Nfs4ResponseGetDevInfo<'a> {
    pub layout_type: u32,
    pub r_netid: &'a [u8],
    pub r_addr: &'a [u8],
    pub notify_mask: u32,
}

fn nfs4_parse_res_getdevinfo(i: &[u8]) -> IResult<&[u8], Nfs4ResponseGetDevInfo<'_>> {
    let (i, layout_type) = be_u32(i)?;
    let (i, _) = be_u64(i)?;
    let (i, _device_index) = be_u32(i)?;
    let (i, _) = be_u64(i)?;
    let (i, r_netid) = nfs4_parse_nfsstring(i)?;
    let (i, r_addr) = nfs4_parse_nfsstring(i)?;
    let (i, notify_mask) = be_u32(i)?;
    Ok((
        i,
        Nfs4ResponseGetDevInfo {
            layout_type,
            r_netid,
            r_addr,
            notify_mask,
        },
    ))
}

fn nfs4_res_getdevinfo(i: &[u8]) -> IResult<&[u8], Nfs4ResponseContent<'_>> {
    let (i, status) = be_u32(i)?;
    let (i, getdevinfo) = cond(status == 0, nfs4_parse_res_getdevinfo)(i)?;
    Ok((i, Nfs4ResponseContent::GetDevInfo(status, getdevinfo)))
}

/*https://datatracker.ietf.org/doc/html/rfc5661#section-13.1*/
// in case of multiple file handles, return handles in a vector
#[derive(Debug, PartialEq, Eq)]
pub struct Nfs4ResponseLayoutGet<'a> {
    pub stateid: Nfs4StateId<'a>,
    pub length: u64,
    pub layout_type: u32,
    pub device_id: &'a [u8],
    pub file_handles: Vec<Nfs4Handle<'a>>,
}

fn nfs4_parse_res_layoutget(i: &[u8]) -> IResult<&[u8], Nfs4ResponseLayoutGet<'_>> {
    let (i, _return_on_close) = verify(be_u32, |&v| v <= 1)(i)?;
    let (i, stateid) = nfs4_parse_stateid(i)?;
    let (i, _layout_seg) = be_u32(i)?;
    let (i, _offset) = be_u64(i)?;
    let (i, length) = be_u64(i)?;
    let (i, _lo_mode) = be_u32(i)?;
    let (i, layout_type) = be_u32(i)?;
    let (i, _) = be_u32(i)?;
    let (i, device_id) = take(16_usize)(i)?;
    let (i, _nfl_util) = be_u32(i)?;
    let (i, _strip_index) = be_u32(i)?;
    let (i, _offset) = be_u64(i)?;
    let (i, fh_handles) = be_u32(i)?;
    // Each serialized handle is at least 4 bytes (be_u32 length prefix),
    // so no more than i.len()/4 handles can be present. Also cap at the
    // Linux kernel's NFS4_PNFS_MAX_STRIPE_CNT to bound count() preallocation.
    if fh_handles as usize > i.len() / 4 || fh_handles > 4096 {
        return Err(Err::Error(make_error(i, ErrorKind::Count)));
    }
    let (i, file_handles) = count(nfs4_parse_handle, fh_handles as usize)(i)?;
    Ok((
        i,
        Nfs4ResponseLayoutGet {
            stateid,
            length,
            layout_type,
            device_id,
            file_handles,
        },
    ))
}

fn nfs4_res_layoutget(i: &[u8]) -> IResult<&[u8], Nfs4ResponseContent<'_>> {
    let (i, status) = be_u32(i)?;
    let (i, lyg_data) = cond(status == 0, nfs4_parse_res_layoutget)(i)?;
    Ok((i, Nfs4ResponseContent::LayoutGet(status, lyg_data)))
}

// #[derive(Debug, PartialEq)]
// pub struct Nfs4FlavorRpcSecGss<'a> {
//     pub oid: &'a[u8],
//     pub qop: u32,
//     pub service: u32,
// }

fn nfs4_parse_rpcsec_gss(i: &[u8]) -> IResult<&[u8], u32> {
    let (i, _oid) = nfs4_parse_nfsstring(i)?;
    let (i, _qop) = be_u32(i)?;
    let (i, _service) = be_u32(i)?;
    Ok((i, RPCSEC_GSS))
}

fn nfs4_parse_flavors(i: &[u8]) -> IResult<&[u8], u32> {
    let (i, flavor_type) = be_u32(i)?;
    let (i, _flavor) = cond(flavor_type == RPCSEC_GSS, nfs4_parse_rpcsec_gss)(i)?;
    Ok((i, flavor_type))
}

fn nfs4_res_secinfo_no_name(i: &[u8]) -> IResult<&[u8], Nfs4ResponseContent<'_>> {
    let (i, status) = be_u32(i)?;
    let (i, flavors_cnt) = be_u32(i)?;
    // do not use nom's count as it allocates a Vector first
    // which results in oom if flavors_cnt is really big, bigger than i.len()
    let mut i2 = i;
    for _n in 0..flavors_cnt {
        let (i3, _flavor) = nfs4_parse_flavors(i2)?;
        i2 = i3;
    }
    Ok((i2, Nfs4ResponseContent::SecInfoNoName(status)))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Nfs4ResponseReaddirEntry<'a> {
    pub name: &'a [u8],
}

#[derive(Debug, PartialEq, Eq)]
pub struct Nfs4ResponseReaddir<'a> {
    pub eof: bool,
    pub listing: Vec<Option<Nfs4ResponseReaddirEntry<'a>>>,
}

fn nfs4_res_readdir_entry_do(i: &[u8]) -> IResult<&[u8], Nfs4ResponseReaddirEntry<'_>> {
    let (i, _cookie) = be_u64(i)?;
    let (i, name) = nfs4_parse_nfsstring(i)?;
    let (i, _attrs) = nfs4_parse_attrs(i)?;
    Ok((i, Nfs4ResponseReaddirEntry { name }))
}

fn nfs4_res_readdir_entry(i: &[u8]) -> IResult<&[u8], Option<Nfs4ResponseReaddirEntry<'_>>> {
    let (i, value_follows) = verify(be_u32, |&v| v <= 1)(i)?;
    let (i, entry) = cond(value_follows == 1, nfs4_res_readdir_entry_do)(i)?;
    Ok((i, entry))
}

fn nfs4_res_readdir_ok(i: &[u8]) -> IResult<&[u8], Nfs4ResponseReaddir<'_>> {
    let (i, _verifier) = be_u64(i)?;
    // run parser until we find a 'value follows == 0'
    let (i, listing) = many_till(
        complete(nfs4_res_readdir_entry),
        peek(tag(b"\x00\x00\x00\x00")),
    )(i)?;
    // value follows == 0 checked by line above
    let (i, _value_follows) = tag(b"\x00\x00\x00\x00")(i)?;
    let (i, eof) = verify(be_u32, |&v| v <= 1)(i)?;
    Ok((
        i,
        Nfs4ResponseReaddir {
            eof: eof == 1,
            listing: listing.0,
        },
    ))
}

fn nfs4_res_readdir(i: &[u8]) -> IResult<&[u8], Nfs4ResponseContent<'_>> {
    let (i, status) = be_u32(i)?;
    let (i, rd) = cond(status == 0, nfs4_res_readdir_ok)(i)?;
    Ok((i, Nfs4ResponseContent::ReadDir(status, rd)))
}

fn nfs4_res_create_ok(i: &[u8]) -> IResult<&[u8], Nfs4Attr> {
    let (i, _change_info) = take(20_usize)(i)?;
    nfs4_parse_attrbits(i)
}

fn nfs4_res_create(i: &[u8]) -> IResult<&[u8], Nfs4ResponseContent<'_>> {
    let (i, status) = be_u32(i)?;
    let (i, _attrs) = cond(status == 0, nfs4_res_create_ok)(i)?;
    Ok((i, Nfs4ResponseContent::Create(status)))
}

fn nfs4_res_setattr_ok(i: &[u8]) -> IResult<&[u8], Nfs4Attr> {
    nfs4_parse_attrbits(i)
}

fn nfs4_res_setattr(i: &[u8]) -> IResult<&[u8], Nfs4ResponseContent<'_>> {
    let (i, status) = be_u32(i)?;
    let (i, _attrs) = cond(status == 0, nfs4_res_setattr_ok)(i)?;
    Ok((i, Nfs4ResponseContent::SetAttr(status)))
}

fn nfs4_res_getattr_ok(i: &[u8]) -> IResult<&[u8], Nfs4Attr> {
    nfs4_parse_attrs(i)
}

fn nfs4_res_getattr(i: &[u8]) -> IResult<&[u8], Nfs4ResponseContent<'_>> {
    let (i, status) = be_u32(i)?;
    let (i, attrs) = cond(status == 0, nfs4_res_getattr_ok)(i)?;
    Ok((i, Nfs4ResponseContent::GetAttr(status, attrs)))
}

fn nfs4_res_openconfirm(i: &[u8]) -> IResult<&[u8], Nfs4ResponseContent<'_>> {
    let (i, status) = be_u32(i)?;
    let (i, stateid) = cond(status == 0, nfs4_parse_stateid)(i)?;
    Ok((i, Nfs4ResponseContent::OpenConfirm(status, stateid)))
}

fn nfs4_res_close(i: &[u8]) -> IResult<&[u8], Nfs4ResponseContent<'_>> {
    let (i, status) = be_u32(i)?;
    let (i, stateid) = cond(status == 0, nfs4_parse_stateid)(i)?;
    Ok((i, Nfs4ResponseContent::Close(status, stateid)))
}

fn nfs4_res_remove(i: &[u8]) -> IResult<&[u8], Nfs4ResponseContent<'_>> {
    let (i, status) = be_u32(i)?;
    let (i, _) = cond(status == 0, take(20_usize))(i)?;
    Ok((i, Nfs4ResponseContent::Remove(status)))
}

fn nfs4_res_rename(i: &[u8]) -> IResult<&[u8], Nfs4ResponseContent<'_>> {
    map(be_u32, Nfs4ResponseContent::Rename)(i)
}

fn nfs4_res_savefh(i: &[u8]) -> IResult<&[u8], Nfs4ResponseContent<'_>> {
    map(be_u32, Nfs4ResponseContent::SaveFH)(i)
}

fn nfs4_res_lookup(i: &[u8]) -> IResult<&[u8], Nfs4ResponseContent<'_>> {
    map(be_u32, Nfs4ResponseContent::Lookup)(i)
}

fn nfs4_res_renew(i: &[u8]) -> IResult<&[u8], Nfs4ResponseContent<'_>> {
    map(be_u32, Nfs4ResponseContent::Renew)(i)
}

fn nfs4_res_getfh(i: &[u8]) -> IResult<&[u8], Nfs4ResponseContent<'_>> {
    let (i, status) = be_u32(i)?;
    let (i, fh) = cond(status == 0, nfs4_parse_handle)(i)?;
    Ok((i, Nfs4ResponseContent::GetFH(status, fh)))
}

fn nfs4_res_putfh(i: &[u8]) -> IResult<&[u8], Nfs4ResponseContent<'_>> {
    map(be_u32, Nfs4ResponseContent::PutFH)(i)
}

fn nfs4_res_putrootfh(i: &[u8]) -> IResult<&[u8], Nfs4ResponseContent<'_>> {
    map(be_u32, Nfs4ResponseContent::PutRootFH)(i)
}

fn nfs4_res_delegreturn(i: &[u8]) -> IResult<&[u8], Nfs4ResponseContent<'_>> {
    map(be_u32, Nfs4ResponseContent::DelegReturn)(i)
}

fn nfs4_res_setclientid(i: &[u8]) -> IResult<&[u8], Nfs4ResponseContent<'_>> {
    let (i, status) = be_u32(i)?;
    let (i, _client_id) = be_u64(i)?;
    let (i, _verifier) = be_u32(i)?;
    Ok((i, Nfs4ResponseContent::SetClientId(status)))
}

fn nfs4_res_setclientid_confirm(i: &[u8]) -> IResult<&[u8], Nfs4ResponseContent<'_>> {
    map(be_u32, Nfs4ResponseContent::SetClientIdConfirm)(i)
}

fn nfs4_res_commit(i: &[u8]) -> IResult<&[u8], Nfs4ResponseContent<'_>> {
    let (i, status) = be_u32(i)?;
    let (i, _verifier) = cond(status == 0, take(8_usize))(i)?;
    Ok((i, Nfs4ResponseContent::Commit(status)))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Nfs4ResponseAccess {
    pub supported_types: u32,
    pub access_rights: u32,
}

fn nfs4_res_access_ok(i: &[u8]) -> IResult<&[u8], Nfs4ResponseAccess> {
    let (i, supported_types) = be_u32(i)?;
    let (i, access_rights) = be_u32(i)?;
    let resp = Nfs4ResponseAccess {
        supported_types,
        access_rights,
    };
    Ok((i, resp))
}

fn nfs4_res_access(i: &[u8]) -> IResult<&[u8], Nfs4ResponseContent<'_>> {
    let (i, status) = be_u32(i)?;
    let (i, ad) = cond(status == 0, nfs4_res_access_ok)(i)?;
    Ok((i, Nfs4ResponseContent::Access(status, ad)))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Nfs4ResponseSequence<'a> {
    pub ssn_id: &'a [u8],
}

fn nfs4_res_sequence_ok(i: &[u8]) -> IResult<&[u8], Nfs4ResponseSequence<'_>> {
    let (i, ssn_id) = take(16_usize)(i)?;
    let (i, _seqid) = be_u32(i)?;
    let (i, _slots) = take(12_usize)(i)?;
    let (i, _flags) = be_u32(i)?;
    Ok((i, Nfs4ResponseSequence { ssn_id }))
}

fn nfs4_res_sequence(i: &[u8]) -> IResult<&[u8], Nfs4ResponseContent<'_>> {
    let (i, status) = be_u32(i)?;
    let (i, seq) = cond(status == 0, nfs4_res_sequence_ok)(i)?;
    Ok((i, Nfs4ResponseContent::Sequence(status, seq)))
}

fn nfs4_res_destroy_session(i: &[u8]) -> IResult<&[u8], Nfs4ResponseContent<'_>> {
    map(be_u32, Nfs4ResponseContent::DestroySession)(i)
}

fn nfs4_res_destroy_clientid(i: &[u8]) -> IResult<&[u8], Nfs4ResponseContent<'_>> {
    map(be_u32, Nfs4ResponseContent::DestroyClientID)(i)
}

fn nfs4_res_compound_command(i: &[u8]) -> IResult<&[u8], Nfs4ResponseContent<'_>> {
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
        NFSPROC4_EXCHANGE_ID => nfs4_res_exchangeid(i)?,
        NFSPROC4_SEQUENCE => nfs4_res_sequence(i)?,
        NFSPROC4_RENEW => nfs4_res_renew(i)?,
        NFSPROC4_CREATE_SESSION => nfs4_res_create_session(i)?,
        NFSPROC4_RECLAIM_COMPLETE => nfs4_res_reclaim_complete(i)?,
        NFSPROC4_SECINFO_NO_NAME => nfs4_res_secinfo_no_name(i)?,
        NFSPROC4_LAYOUTGET => nfs4_res_layoutget(i)?,
        NFSPROC4_GETDEVINFO => nfs4_res_getdevinfo(i)?,
        NFSPROC4_LAYOUTRETURN => nfs4_res_layoutreturn(i)?,
        NFSPROC4_DESTROY_SESSION => nfs4_res_destroy_session(i)?,
        NFSPROC4_DESTROY_CLIENTID => nfs4_res_destroy_clientid(i)?,
        _ => {
            return Err(Err::Error(make_error(i, ErrorKind::Switch)));
        }
    };
    Ok((i, cmd_data))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Nfs4ResponseCompoundRecord<'a> {
    pub status: u32,
    pub commands: Vec<Nfs4ResponseContent<'a>>,
}

pub fn parse_nfs4_response_compound(i: &[u8]) -> IResult<&[u8], Nfs4ResponseCompoundRecord<'_>> {
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
        let (_, req_r_netid) = nfs4_parse_nfsstring(&buf[68..76]).unwrap();
        let (_, req_r_adrr) = nfs4_parse_nfsstring(&buf[76..100]).unwrap();

        let (_, resquest) = nfs4_req_setclientid(&buf[4..]).unwrap();
        match resquest {
            Nfs4RequestContent::SetClientId(req_setclientid) => {
                assert_eq!(req_setclientid.client_id, req_client_id);
                assert_eq!(req_setclientid.r_netid, req_r_netid);
                assert_eq!(req_setclientid.r_addr, req_r_adrr);
            }
            _ => {
                panic!("Failure");
            }
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
                assert_eq!(
                    req_open.open_data,
                    Some(Nfs4OpenRequestContent::Unchecked4(attr_buf))
                );
                assert_eq!(req_open.filename, filename_buf);
            }
            _ => {
                panic!("Failure, {:?}", request);
            }
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
            _ => {
                panic!("Failure, {:?}", request);
            }
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
            _ => {
                panic!("Failure, {:?}", request);
            }
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
            _ => {
                panic!("Failure, {:?}", request);
            }
        }
    }

    #[test]
    fn test_nfs4_request_sequence() {
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
            _ => {
                panic!("Failure, {:?}", req_sequence);
            }
        }
    }

    #[test]
    fn test_nfs4_request_lookup() {
        #[rustfmt::skip]
        let buf: &[u8] = &[
            0x00, 0x00, 0x00, 0x0f, /*opcode*/
            0x00, 0x00, 0x00, 0x04, 0x76, 0x6f, 0x6c, 0x31, /*filename: (vol1)*/
        ];

        let (_, filename_buf) = nfs4_parse_nfsstring(&buf[4..]).unwrap();

        let (_, request) = nfs4_req_lookup(&buf[4..]).unwrap();
        match request {
            Nfs4RequestContent::Lookup(req_lookup) => {
                assert_eq!(req_lookup.filename, filename_buf);
            }
            _ => {
                panic!("Failure, {:?}", request);
            }
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
            _ => {
                panic!("Failure, {:?}", result);
            }
        }
    }

    #[test]
    fn test_nfs4_request_create_session() {
        let buf: &[u8] = &[
            0x00, 0x00, 0x00, 0x2b, /*opcode*/
            0xe0, 0x14, 0x82, 0x00, 0x00, 0x00, 0x02, 0xd2, // create_session
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
            0x04, 0x14, 0x00, 0x10, 0x03, 0x88, 0x00, 0x00, 0x0d, 0x64, 0x00, 0x00, 0x00, 0x08,
            0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x10, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x0c, 0x09, 0x5e, 0x92, 0x00, 0x00, 0x00, 0x09,
            0x6e, 0x65, 0x74, 0x61, 0x70, 0x70, 0x2d, 0x32, 0x36, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let (_, request) = nfs4_req_create_session(&buf[4..]).unwrap();
        match request {
            Nfs4RequestContent::CreateSession(create_ssn) => {
                assert_eq!(create_ssn.client_id, &buf[4..12]);
                assert_eq!(create_ssn.seqid, 1);
                assert_eq!(create_ssn.machine_name, b"netapp-26");
            }
            _ => {
                panic!("Failure");
            }
        }
    }

    #[test]
    fn test_nfs4_request_layoutget() {
        let buf: &[u8] = &[
            0x00, 0x00, 0x00, 0x32, /*opcode*/
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // layoutget
            0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x02, 0x82, 0x14, 0xe0, 0x5b, 0x00, 0x89, 0xd9, 0x04, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
        ];

        let (_, stateid_buf) = nfs4_parse_stateid(&buf[40..56]).unwrap();
        assert_eq!(stateid_buf.seqid, 0);

        let (_, request) = nfs4_req_layoutget(&buf[4..]).unwrap();
        match request {
            Nfs4RequestContent::LayoutGet(lyg_data) => {
                assert_eq!(lyg_data.layout_type, 1);
                assert_eq!(lyg_data.min_length, 4096);
                assert_eq!(lyg_data.stateid, stateid_buf);
            }
            _ => {
                panic!("Failure");
            }
        }
    }

    #[test]
    fn test_nfs4_request_getdevinfo() {
        let buf: &[u8] = &[
            0x00, 0x00, 0x00, 0x2f, /*opcode*/
            0x01, 0x01, 0x00, 0x00, 0x00, 0xf2, 0xfa, 0x80, // getdevinfo
            0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01,
            0x3e, 0x20, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x06,
        ];

        let (_, request) = nfs4_req_getdevinfo(&buf[4..]).unwrap();
        match request {
            Nfs4RequestContent::GetDevInfo(getdevifo) => {
                assert_eq!(getdevifo.device_id, &buf[4..20]);
                assert_eq!(getdevifo.layout_type, 1);
                assert_eq!(getdevifo.maxcount, 81440);
                assert_eq!(getdevifo.notify_mask, 6);
            }
            _ => {
                panic!("Failure");
            }
        }
    }

    #[test]
    fn test_nfs4_request_layoutreturn() {
        let buf: &[u8] = &[
            0x00, 0x00, 0x00, 0x33, /*opcode*/
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // layoutreturn
            0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
            0x03, 0x82, 0x14, 0xe0, 0x5b, 0x00, 0x89, 0xd9, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];

        let (_, stateid_buf) = nfs4_parse_stateid(&buf[36..52]).unwrap();
        assert_eq!(stateid_buf.seqid, 1);

        let (_, request) = nfs4_req_layoutreturn(&buf[4..]).unwrap();
        match request {
            Nfs4RequestContent::LayoutReturn(layoutreturn) => {
                assert_eq!(layoutreturn.layout_type, 1);
                assert_eq!(layoutreturn.return_type, 1);
                assert_eq!(layoutreturn.stateid, stateid_buf);
            }
            _ => {
                panic!("Failure");
            }
        }
    }

    #[test]
    fn test_nfs4_request_destroy_session() {
        let buf: &[u8] = &[
            0x00, 0x00, 0x00, 0x2c, /*opcode*/
            0x00, 0x00, 0x02, 0xd2, 0xe0, 0x14, 0x82, 0x00, /*ssn_id*/
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x02,
        ];

        let (_, request) = nfs4_req_destroy_session(&buf[4..]).unwrap();
        match request {
            Nfs4RequestContent::DestroySession(ssn_id) => {
                assert_eq!(ssn_id, &buf[4..]);
            }
            _ => {
                panic!("Failure");
            }
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
        assert_eq!(attr.attr_mask, 0x00002065_u64 << 32);
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
            0x21, 0xa8, 0x2a, 0x48, 0x00, 0x00, 0x00, 0x04,
            0x00, 0x00, 0x00, 0x03,
            0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x02, /*_attrs*/
            0x00, 0x00, 0x00, 0x00,
        // delegate_write
            0x00, 0x00, 0x00, 0x02, /*delegation_type*/
            0x00, 0x00, 0x00, 0x01, 0x02, 0x82, 0x14, 0xe0,
            0x5b, 0x00, 0x89, 0xd9, 0x04, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];

        let stateid_buf = &buf[8..24];
        let (_, res_stateid) = nfs4_parse_stateid(stateid_buf).unwrap();

        let delegate_buf = &buf[64..];
        let (_, delegate) = nfs4_parse_file_delegation(delegate_buf).unwrap();

        let open_data_buf = &buf[8..];
        let (_, res_open_data) = nfs4_res_open_ok(open_data_buf).unwrap();
        assert_eq!(res_open_data.stateid, res_stateid);
        assert_eq!(res_open_data.result_flags, 4);
        assert_eq!(res_open_data.delegate, delegate);

        let (_, response) = nfs4_res_open(&buf[4..]).unwrap();
        match response {
            Nfs4ResponseContent::Open(status, open_data) => {
                assert_eq!(status, 0);
                assert_eq!(open_data, Some(res_open_data));
            }
            _ => {
                panic!("Failure, {:?}", response);
            }
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
            _ => {
                panic!("Failure, {:?}", result);
            }
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
            _ => {
                panic!("Failure, {:?}", result);
            }
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
            _ => {
                panic!("Failure, {:?}", result);
            }
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
            _ => {
                panic!("Failure, {:?}", result);
            }
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
        assert!(res_rd.eof);
        assert_eq!(res_rd.listing, [Some(res_entry0), Some(res_entry1)]);

        let (_, response) = nfs4_res_readdir(&buf[4..]).unwrap();
        match response {
            Nfs4ResponseContent::ReadDir(status, rd) => {
                assert_eq!(status, 0);
                assert_eq!(rd, Some(res_rd));
            }
            _ => {
                panic!("Failure!");
            }
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
            _ => {
                panic!("Failure");
            }
        }
    }

    #[test]
    fn test_nfs4_response_exchangeid() {
        let buf: &[u8] = &[
            0x00, 0x00, 0x00, 0x2a, /*opcode*/
            0x00, 0x00, 0x00, 0x00, /*status*/
            // exchange_id
            0xe0, 0x14, 0x82, 0x00, 0x00, 0x00, 0x02, 0xd2, 0x00, 0x00, 0x00, 0x01, 0x00, 0x06,
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x98, 0x3b, 0xa3, 0x1e, 0xd7, 0xa9, 0x11, 0xe8,
            0x00, 0x00, 0x00, 0x10, 0x98, 0x3b, 0xa3, 0x1e, 0xd7, 0xa9, 0x11, 0xe8, 0xbc, 0x0c,
            0x00, 0x0c, 0x29, 0xe9, 0x13, 0x93, 0x00, 0x00, 0x00, 0x10, 0x84, 0x8b, 0x93, 0x12,
            0xd7, 0xa9, 0x11, 0xe8, 0xbc, 0x0c, 0x00, 0x0c, 0x29, 0xe9, 0x13, 0x93, 0x00, 0x00,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x6e, 0x65, 0x74, 0x61, 0x70, 0x70, 0x2e, 0x63,
            0x6f, 0x6d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x24, 0x4e, 0x65, 0x74, 0x41, 0x70, 0x70,
            0x20, 0x52, 0x65, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x20, 0x56, 0x6f, 0x6f, 0x64, 0x6f,
            0x6f, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x72, 0x5f, 0x5f, 0x39, 0x2e, 0x36, 0x2e, 0x30,
            0x00, 0x00, 0x26, 0x0d, 0xcf, 0x5b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let (_, xchangeid) = nfs4_parse_res_exchangeid(&buf[8..]).unwrap();

        let (_, response) = nfs4_res_exchangeid(&buf[4..]).unwrap();
        match response {
            Nfs4ResponseContent::ExchangeId(status, xchngid_data) => {
                assert_eq!(status, 0);
                assert_eq!(xchngid_data, Some(xchangeid));
            }
            _ => {
                panic!("Failure");
            }
        }
    }

    #[test]
    fn test_nfs4_response_create_session() {
        let buf: &[u8] = &[
            0x00, 0x00, 0x00, 0x2b, /*opcode*/
            0x00, 0x00, 0x00, 0x00, /*status*/
            // create_session
            0x00, 0x00, 0x02, 0xd2, 0xe0, 0x14, 0x82, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x04, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x18, 0x00, 0x00, 0x01, 0x40, 0x00, 0x00, 0x00, 0x02, 0x80, 0x00, 0x00,
            0x00, 0x08, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];

        let (_, create_ssn) = nfs4_parse_res_create_session(&buf[8..]).unwrap();

        let (_, response) = nfs4_res_create_session(&buf[4..]).unwrap();
        match response {
            Nfs4ResponseContent::CreateSession(status, create_ssn_data) => {
                assert_eq!(status, 0);
                assert_eq!(create_ssn_data, Some(create_ssn));
            }
            _ => {
                panic!("Failure");
            }
        }
    }

    #[test]
    fn test_nfs4_response_layoutget() {
        let buf: &[u8] = &[
            0x00, 0x00, 0x00, 0x32, /*opcode*/
            0x00, 0x00, 0x00, 0x00, /*status*/
            // layoutget
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x82, 0x14, 0xe0, 0x5b, 0x00,
            0x89, 0xd9, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00,
            0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x58, 0x01, 0x01, 0x00, 0x00,
            0x00, 0xf2, 0xfa, 0x80, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x30, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x84, 0x72, 0x00, 0x00, 0x23, 0xa6, 0xc0, 0x12,
            0x00, 0xf2, 0xfa, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01,
            0x00, 0x00, 0x00, 0xf2, 0xfa, 0x80, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
        ];

        let (_, stateid) = nfs4_parse_stateid(&buf[12..28]).unwrap();

        let (_, lyg_data) = nfs4_parse_res_layoutget(&buf[8..]).unwrap();
        assert_eq!(lyg_data.stateid, stateid);
        assert_eq!(lyg_data.layout_type, 1);
        assert_eq!(lyg_data.device_id, &buf[60..76]);

        let (_, response) = nfs4_res_layoutget(&buf[4..]).unwrap();
        match response {
            Nfs4ResponseContent::LayoutGet(status, lyg) => {
                assert_eq!(status, 0);
                assert_eq!(lyg, Some(lyg_data));
            }
            _ => {
                panic!("Failure");
            }
        }
    }

    #[test]
    fn test_nfs4_response_getdevinfo() {
        let buf: &[u8] = &[
            0x00, 0x00, 0x00, 0x2f, /*opcode*/
            0x00, 0x00, 0x00, 0x00, /*status*/
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x2c, // getdevinfo
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x74, 0x63, 0x70, 0x00, 0x00, 0x00, 0x00, 0x10,
            0x31, 0x39, 0x32, 0x2e, 0x31, 0x36, 0x38, 0x2e, 0x30, 0x2e, 0x36, 0x31, 0x2e, 0x38,
            0x2e, 0x31, 0x00, 0x00, 0x00, 0x00,
        ];

        let (_, getdevinfo) = nfs4_parse_res_getdevinfo(&buf[8..]).unwrap();
        assert_eq!(getdevinfo.layout_type, 1);
        assert_eq!(getdevinfo.r_netid, b"tcp");
        assert_eq!(getdevinfo.r_addr, b"192.168.0.61.8.1");

        let (_, response) = nfs4_res_getdevinfo(&buf[4..]).unwrap();
        match response {
            Nfs4ResponseContent::GetDevInfo(status, getdevinfo_data) => {
                assert_eq!(status, 0);
                assert_eq!(getdevinfo_data, Some(getdevinfo))
            }
            _ => {
                panic!("Failure");
            }
        }
    }

    #[test]
    fn test_nfs4_request_open_exclusive4_1() {
        #[rustfmt::skip]
        let buf: &[u8] = &[
            0x00, 0x00, 0x00, 0x12, /*opcode*/
            0x00, 0x00, 0x00, 0x00, /*_seq_id*/
            0x00, 0x00, 0x00, 0x02, /*_share_access*/
            0x00, 0x00, 0x00, 0x00, /*_share_deny*/
            0x91, 0xe9, 0xf1, 0x68, 0x59, 0x18, 0x8d, 0xec, /*_client_id*/
        // OWNER
            0x00, 0x00, 0x00, 0x18, /*owner_len*/
            0x6f, 0x70, 0x65, 0x6e, 0x20, 0x69, 0x64, 0x3a,
            0x00, 0x00, 0x00, 0x74, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x7a, 0xa1, 0x15, 0xa6, 0x3d, 0xaa,
        // OPEN
            0x00, 0x00, 0x00, 0x01, /*open_type: OPEN4_CREATE*/
            0x00, 0x00, 0x00, 0x03, /*create_mode: EXCLUSIVE4_1*/
            0x9a, 0xf1, 0xf6, 0x18, 0xdc, 0xe2, 0x00, 0x00, /*verifier*/
            0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x08,  /*attr_mask*/
            0x00, 0x00, 0x01, 0xa4, 0x00, 0x00, 0x00, 0x12, /*_reco_attr*/
        // CLAIM_TYPE
            0x00, 0x00, 0x00, 0x00, /*_claim_type: CLAIM_NULL*/
            0x0, 0x0, 0x0, 0x8, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x70, 0x6e, 0x67, /*filename*/
        ];

        let (_, filename_buf) = nfs4_parse_nfsstring(&buf[96..]).unwrap();

        let (_, request) = nfs4_req_open(&buf[4..]).unwrap();
        match request {
            Nfs4RequestContent::Open(req_open) => {
                assert_eq!(req_open.open_type, 1);
                assert_eq!(req_open.filename, filename_buf);
                assert_eq!(
                    req_open.open_data,
                    Some(Nfs4OpenRequestContent::Exclusive4_1(&buf[60..68]))
                );
            }
            _ => {
                panic!("Failure, {:?}", request);
            }
        }
    }

    fn be32(v: u32) -> [u8; 4] {
        v.to_be_bytes()
    }

    // compound header: XDR string tag + minver + op count
    fn compound_head(ops_cnt: u32) -> Vec<u8> {
        let mut v: Vec<u8> = Vec::new();
        v.extend_from_slice(&be32(0)); // tag length 0
        v.extend_from_slice(&be32(0)); // minor version
        v.extend_from_slice(&be32(ops_cnt));
        v
    }

    // a v4 WRITE op carrying the given claimed length, no data
    fn write_op(write_len: u32) -> Vec<u8> {
        let mut v: Vec<u8> = Vec::new();
        v.extend_from_slice(&be32(NFSPROC4_WRITE));
        v.extend_from_slice(&be32(1)); // stateid seqid
        v.extend_from_slice(&[0u8; 12]); // stateid data
        v.extend_from_slice(&[0u8; 8]); // offset
        v.extend_from_slice(&be32(2)); // stable: FILE_SYNC
        v.extend_from_slice(&be32(write_len));
        v
    }

    // a v4 READ (success) op carrying the given claimed length, no data
    fn read_op(read_len: u32) -> Vec<u8> {
        let mut v: Vec<u8> = Vec::new();
        v.extend_from_slice(&be32(NFSPROC4_READ));
        v.extend_from_slice(&be32(0)); // status: OK
        v.extend_from_slice(&be32(0)); // eof
        v.extend_from_slice(&be32(read_len));
        v
    }

    // a v4 PUTFH request op with a file handle of the given length
    fn putfh_req_op(fh_len: u32) -> Vec<u8> {
        let mut v: Vec<u8> = Vec::new();
        v.extend_from_slice(&be32(NFSPROC4_PUTFH));
        v.extend_from_slice(&be32(fh_len));
        v.resize(v.len() + fh_len as usize, 0);
        let pad = (4 - (fh_len as usize % 4)) % 4;
        v.resize(v.len() + pad, 0);
        v
    }

    // a v4 GETFH request op (no args)
    fn getfh_req_op() -> Vec<u8> {
        be32(NFSPROC4_GETFH).to_vec()
    }

    // a v4 READ request op (stateid + offset + count)
    fn read_req_op(count: u32) -> Vec<u8> {
        let mut v: Vec<u8> = Vec::new();
        v.extend_from_slice(&be32(NFSPROC4_READ));
        v.extend_from_slice(&[0u8; 16]); // stateid
        v.extend_from_slice(&[0u8; 8]); // offset
        v.extend_from_slice(&be32(count));
        v
    }

    // a successful v4 OPEN response op (delegate NONE, empty attrs)
    fn open_res_op() -> Vec<u8> {
        let mut v: Vec<u8> = Vec::new();
        v.extend_from_slice(&be32(NFSPROC4_OPEN));
        v.extend_from_slice(&be32(0)); // status: OK
        v.extend_from_slice(&[0u8; 16]); // stateid
        v.extend_from_slice(&[0u8; 20]); // change_info
        v.extend_from_slice(&be32(0)); // result_flags
        v.extend_from_slice(&be32(0)); // fattr4 attr_cnt (0)
        v.extend_from_slice(&be32(0)); // mask1 (the parser always reads it)
        v.extend_from_slice(&be32(OPEN_DELEGATE_NONE)); // file_delegation4 type
        v
    }

    // a successful v4 GETFH response op with a file handle of the given length
    fn getfh_res_op(fh_len: u32) -> Vec<u8> {
        let mut v: Vec<u8> = Vec::new();
        v.extend_from_slice(&be32(NFSPROC4_GETFH));
        v.extend_from_slice(&be32(0)); // status: OK
        v.extend_from_slice(&be32(fh_len));
        v.resize(v.len() + fh_len as usize, 0);
        let pad = (4 - (fh_len as usize % 4)) % 4;
        v.resize(v.len() + pad, 0);
        v
    }

    #[test]
    fn test_scan_request_compound_oversized_write() {
        let mut buf = compound_head(1);
        buf.extend_from_slice(&write_op(4096));
        assert_eq!(
            scan_nfs4_request_compound_write_len(&buf, 1024),
            Nfs4CompoundScan::Oversized(4096)
        );
    }

    #[test]
    fn test_scan_request_compound_within_limit_write_incomplete() {
        // claimed 8 <= max, but the write data is not buffered yet
        let mut buf = compound_head(1);
        buf.extend_from_slice(&write_op(8));
        assert_eq!(
            scan_nfs4_request_compound_write_len(&buf, 1024),
            Nfs4CompoundScan::Incomplete
        );
    }

    #[test]
    fn test_scan_request_compound_no_write() {
        // a completed compound without any WRITE op
        let mut buf = compound_head(1);
        buf.extend_from_slice(&be32(NFSPROC4_GETATTR));
        buf.extend_from_slice(&be32(1)); // attr bitmap word count
        buf.extend_from_slice(&be32(0x0000_00ff));
        assert_eq!(
            scan_nfs4_request_compound_write_len(&buf, 1024),
            Nfs4CompoundScan::Clean
        );
    }

    #[test]
    fn test_scan_request_compound_too_many_ops_is_malformed() {
        // op count above the bound is a structural error, not "no write"
        let mut buf = compound_head(100);
        buf.extend_from_slice(&[0u8; 8]);
        assert_eq!(
            scan_nfs4_request_compound_write_len(&buf, 1024),
            Nfs4CompoundScan::Malformed
        );
    }

    #[test]
    fn test_scan_request_compound_untabled_lead_op_is_malformed() {
        // RESTOREFH is a valid op but is not parsed; a desync must not
        // degrade to "no oversized op"
        let mut buf = compound_head(2);
        buf.extend_from_slice(&be32(NFSPROC4_RESTOREFH));
        buf.extend_from_slice(&be32(NFSPROC4_PUTFH));
        buf.extend_from_slice(&be32(32)); // fh length
        buf.extend_from_slice(&[0x11u8; 32]);
        assert_eq!(
            scan_nfs4_request_compound_write_len(&buf, 1024),
            Nfs4CompoundScan::Malformed
        );
    }

    /// CREATE_SESSION op per the layout the parser follows:
    /// clientid(8) + 80 fixed bytes (seqid..g_stamp) + machine name
    fn create_session_op(name: &[u8]) -> Vec<u8> {
        let mut v: Vec<u8> = Vec::new();
        v.extend_from_slice(&be32(NFSPROC4_CREATE_SESSION));
        v.extend_from_slice(&[0x22u8; 8]); // clientid4
        v.extend_from_slice(&[0x33u8; 80]); // seqid..g_stamp
        v.extend_from_slice(&be32(name.len() as u32));
        v.extend_from_slice(name);
        let pad = (4 - (name.len() % 4)) % 4;
        v.resize(v.len() + pad, 0);
        v
    }

    #[test]
    fn test_scan_request_compound_create_session_hides_oversized_write() {
        // a leading CREATE_SESSION has variable-length channel/RDMA args the scanner
        // can't advance past: bounded rejection (Malformed), never Incomplete (OOM)
        // or Clean (fail open), so a following oversized WRITE isn't buffered.
        let mut buf = compound_head(2);
        buf.extend_from_slice(&create_session_op(b"suri"));
        buf.extend_from_slice(&be32(NFSPROC4_WRITE));
        buf.extend_from_slice(&[0u8; 16]); // stateid
        buf.extend_from_slice(&[0u8; 8]); // offset
        buf.extend_from_slice(&be32(2)); // stable
        buf.extend_from_slice(&be32(10 * 1024 * 1024)); // write_len
        assert_eq!(
            scan_nfs4_request_compound_write_len(&buf, 1024),
            Nfs4CompoundScan::Malformed
        );
    }

    #[test]
    fn test_scan_request_compound_create_session_last_op_is_clean() {
        // CREATE_SESSION as the *last* op: nothing follows, so there is no
        // oversized WRITE to hide -- the scan concludes clean (no OOM).
        let mut buf = compound_head(1);
        buf.extend_from_slice(&create_session_op(b"suri"));
        assert_eq!(
            scan_nfs4_request_compound_write_len(&buf, 1024),
            Nfs4CompoundScan::Clean
        );
    }

    #[test]
    fn test_scan_request_compound_open_last_op_is_clean() {
        // OPEN as the last op: nothing follows -- conclude clean.
        let mut buf = compound_head(1);
        buf.extend_from_slice(&be32(NFSPROC4_OPEN));
        buf.extend_from_slice(&[0u8; 40]);
        assert_eq!(
            scan_nfs4_request_compound_write_len(&buf, 1024),
            Nfs4CompoundScan::Clean
        );
    }

    #[test]
    fn test_scan_request_compound_read_getfh_no_write() {
        // a leading READ is a valid op the full parser supports: the scanner
        // must skip it (not reject the compound) and reach the trailing GETFH.
        let mut buf = compound_head(3);
        buf.extend_from_slice(&putfh_req_op(16));
        buf.extend_from_slice(&read_req_op(8));
        buf.extend_from_slice(&getfh_req_op());
        assert_eq!(
            scan_nfs4_request_compound_write_len(&buf, 1024),
            Nfs4CompoundScan::Clean
        );
    }

    // a v4 OPEN request op as nfs4_req_open parses it: seq_id + share_access
    // + share_deny + client_id + owner (len + bytes, no pad) + open_type
    // (+ open_data for type 1) + claim_type (void claim, no payload) + name
    fn open_req_op(open_type: u32, mode: u32, claim_type: u32, claim_payload: &[u8]) -> Vec<u8> {
        let mut v: Vec<u8> = Vec::new();
        v.extend_from_slice(&be32(NFSPROC4_OPEN));
        v.extend_from_slice(&[0u8; 20]); // seq_id + share_access + share_deny + client_id
        v.extend_from_slice(&be32(0)); // owner len 0
        v.extend_from_slice(&be32(open_type));
        if open_type == 1 {
            v.extend_from_slice(&be32(mode));
            match mode {
                0 | 1 => {
                    v.extend_from_slice(&be32(0)); // attr_cnt (0)
                    v.extend_from_slice(&be32(0)); // mask1 (the parser always reads it)
                    v.extend_from_slice(&be32(0)); // fields blob len 0
                }
                _ => v.extend_from_slice(&[0u8; 8]), // exclusive4 words
            }
        }
        v.extend_from_slice(&be32(claim_type)); // claim_type
        v.extend_from_slice(claim_payload);
        v.extend_from_slice(&be32(3)); // name len
        v.extend_from_slice(b"foo");
        v.push(0); // XDR pad
        v
    }

    #[test]
    fn test_scan_request_compound_read_then_within_limit_write() {
        // the READ is skipped so a following within-limit WRITE is reached
        // (not hidden behind it).
        let mut buf = compound_head(3);
        buf.extend_from_slice(&putfh_req_op(16));
        buf.extend_from_slice(&read_req_op(8));
        buf.extend_from_slice(&write_op(8)); // within-limit, no data buffered
        assert_eq!(
            scan_nfs4_request_compound_write_len(&buf, 1024),
            Nfs4CompoundScan::Incomplete
        );
    }

    #[test]
    fn test_scan_request_compound_open_getfh_no_write() {
        // a leading CLAIM_NULL OPEN is a valid op the full parser supports:
        // the scanner must skip it (not reject the compound) and reach the
        // trailing GETFH.
        let mut buf = compound_head(2);
        buf.extend_from_slice(&open_req_op(0, 0, 0, &[]));
        buf.extend_from_slice(&getfh_req_op());
        assert_eq!(
            scan_nfs4_request_compound_write_len(&buf, 1024),
            Nfs4CompoundScan::Clean
        );
    }

    #[test]
    fn test_scan_request_compound_open_payload_claim_rejected() {
        // a payload-bearing claim (FH=1, DELEGATE=3, FH_ONLY=4, the v4.2
        // claims 5+) desyncs the parser (the stateid/fh is read as the name
        // length): the scanner must reject the compound boundedly
        // (Malformed), not buffer (Incomplete) and not report the oversized
        // WRITE behind it.
        let mut stateid = be32(1).to_vec();
        stateid.resize(16, 0);
        for claim_type in [1u32, 3, 4, 8, 9] {
            let mut buf = compound_head(2);
            buf.extend_from_slice(&open_req_op(0, 0, claim_type, &stateid));
            buf.extend_from_slice(&write_op(10 * 1024 * 1024));
            assert_eq!(
                scan_nfs4_request_compound_write_len(&buf, 1024),
                Nfs4CompoundScan::Malformed,
                "claim_type {}",
                claim_type
            );
        }
    }

    #[test]
    fn test_scan_request_compound_open_hides_oversized_write() {
        // the OPEN is skipped so a following oversized WRITE is reached (not
        // hidden behind it): the record is rejected, not buffered.
        let mut buf = compound_head(2);
        buf.extend_from_slice(&open_req_op(0, 0, 0, &[]));
        buf.extend_from_slice(&write_op(10 * 1024 * 1024));
        assert_eq!(
            scan_nfs4_request_compound_write_len(&buf, 1024),
            Nfs4CompoundScan::Oversized(10 * 1024 * 1024)
        );
    }

    #[test]
    fn test_scan_request_compound_open_exclusive_getfh_no_write() {
        // open_type 1 with an exclusive open_data (8 words) is skipped the
        // same way.
        let mut buf = compound_head(2);
        buf.extend_from_slice(&open_req_op(1, 2, 0, &[]));
        buf.extend_from_slice(&getfh_req_op());
        assert_eq!(
            scan_nfs4_request_compound_write_len(&buf, 1024),
            Nfs4CompoundScan::Clean
        );
    }

    #[test]
    fn test_nfs4_req_create_session_exact_wire_length() {
        // the parser must stop at the op boundary: a following op tag
        // stays in the remainder instead of being swallowed (rest())
        let mut op = create_session_op(b"suri")[4..].to_vec(); // the
                                                               // helper emits the op tag too; the parser gets the args only
        let next = be32(NFSPROC4_GETATTR);
        op.extend_from_slice(&next);
        let op = op.as_slice();
        let (rem, content) = nfs4_req_create_session(op).unwrap();
        assert_eq!(rem, &next[..]);
        match content {
            Nfs4RequestContent::CreateSession(ref cs) => {
                assert_eq!(cs.machine_name, b"suri".as_slice());
                assert_eq!(cs.seqid, 0x33333333);
            }
            _ => panic!("unexpected content"),
        }
    }

    // response compound head: compound status + XDR string tag + op count
    // (no minor version field, unlike the request)
    fn response_compound_head(ops_cnt: u32) -> Vec<u8> {
        let mut v: Vec<u8> = Vec::new();
        v.extend_from_slice(&be32(0)); // compound status
        v.extend_from_slice(&be32(0)); // tag length 0
        v.extend_from_slice(&be32(ops_cnt));
        v
    }

    #[test]
    fn test_scan_response_compound_oversized_read() {
        let mut buf = response_compound_head(1);
        buf.extend_from_slice(&read_op(4096));
        assert_eq!(
            scan_nfs4_response_compound_read_len(&buf, 1024),
            Nfs4CompoundScan::Oversized(4096)
        );
    }

    #[test]
    fn test_scan_response_compound_within_limit_read_incomplete() {
        let mut buf = response_compound_head(1);
        buf.extend_from_slice(&read_op(8));
        assert_eq!(
            scan_nfs4_response_compound_read_len(&buf, 1024),
            Nfs4CompoundScan::Incomplete
        );
    }

    #[test]
    fn test_scan_response_compound_no_read() {
        let mut buf = response_compound_head(1);
        buf.extend_from_slice(&be32(NFSPROC4_PUTFH)); // no args, status ok
        buf.extend_from_slice(&be32(0));
        assert_eq!(
            scan_nfs4_response_compound_read_len(&buf, 1024),
            Nfs4CompoundScan::Clean
        );
    }

    #[test]
    fn test_scan_response_compound_too_many_ops_is_malformed() {
        let mut buf = response_compound_head(100);
        buf.extend_from_slice(&[0u8; 8]);
        assert_eq!(
            scan_nfs4_response_compound_read_len(&buf, 1024),
            Nfs4CompoundScan::Malformed
        );
    }

    #[test]
    fn test_scan_response_compound_untabled_lead_op_is_malformed() {
        // an untabled leading op (RESTOREFH) with a following op can't be advanced
        // past: bounded rejection (Malformed), so a following oversized READ isn't buffered.
        let mut buf = response_compound_head(2);
        buf.extend_from_slice(&be32(NFSPROC4_RESTOREFH));
        buf.extend_from_slice(&be32(0)); // op status
        buf.extend_from_slice(&be32(NFSPROC4_READ));
        buf.extend_from_slice(&be32(0)); // READ status
        buf.extend_from_slice(&be32(1)); // eof
        buf.extend_from_slice(&be32(10 * 1024 * 1024)); // read_len
        assert_eq!(
            scan_nfs4_response_compound_read_len(&buf, 1024),
            Nfs4CompoundScan::Malformed
        );
    }

    #[test]
    fn test_scan_response_compound_untabled_last_op_is_clean() {
        // an untabled op as the *last* op: nothing follows, so there is no
        // oversized READ to hide -- conclude clean.
        let mut buf = response_compound_head(1);
        buf.extend_from_slice(&be32(NFSPROC4_RESTOREFH));
        buf.extend_from_slice(&be32(0)); // op status
        assert_eq!(
            scan_nfs4_response_compound_read_len(&buf, 1024),
            Nfs4CompoundScan::Clean
        );
    }

    #[test]
    fn test_scan_response_compound_sequence_hides_oversized_read() {
        // a SEQUENCE op (the typical NFSv4.1 reply lead) followed by an oversized READ:
        // the scanner must skip the 36-byte SEQUENCE result to reach the READ, or it
        // rejects the compound (Malformed) and loses the file inspection.
        let mut buf = response_compound_head(2);
        // SEQUENCE: tag + status(0) + ssn4(16) + seqid(4) + slots(12) + flags(4)
        buf.extend_from_slice(&be32(NFSPROC4_SEQUENCE));
        buf.extend_from_slice(&be32(0)); // status ok
        buf.extend_from_slice(&[0x11u8; 36]); // sequence_ok result
                                              // READ: tag + status(0) + eof + read_len (oversized)
        buf.extend_from_slice(&be32(NFSPROC4_READ));
        buf.extend_from_slice(&be32(0)); // status ok
        buf.extend_from_slice(&be32(1)); // eof
        buf.extend_from_slice(&be32(10 * 1024 * 1024)); // read_len
        assert_eq!(
            scan_nfs4_response_compound_read_len(&buf, 1024),
            Nfs4CompoundScan::Oversized(10 * 1024 * 1024)
        );
    }

    #[test]
    fn test_scan_response_compound_sequence_then_within_limit_read() {
        // SEQUENCE + a within-limit READ: the scanner skips the SEQUENCE
        // result and the (empty) READ, concluding clean.
        let mut buf = response_compound_head(2);
        buf.extend_from_slice(&be32(NFSPROC4_SEQUENCE));
        buf.extend_from_slice(&be32(0));
        buf.extend_from_slice(&[0x11u8; 36]);
        buf.extend_from_slice(&be32(NFSPROC4_READ));
        buf.extend_from_slice(&be32(0));
        buf.extend_from_slice(&be32(0)); // eof
        buf.extend_from_slice(&be32(0)); // read_len 0
        assert_eq!(
            scan_nfs4_response_compound_read_len(&buf, 1024),
            Nfs4CompoundScan::Clean
        );
    }

    #[test]
    fn test_scan_response_compound_open_getfh_no_read() {
        // a leading OPEN is a valid op the full parser supports: the scanner
        // must skip its result (not reject the compound) and reach the GETFH.
        let mut buf = response_compound_head(2);
        buf.extend_from_slice(&open_res_op());
        buf.extend_from_slice(&getfh_res_op(16));
        assert_eq!(
            scan_nfs4_response_compound_read_len(&buf, 1024),
            Nfs4CompoundScan::Clean
        );
    }

    #[test]
    fn test_scan_response_compound_open_then_within_limit_read() {
        // the OPEN is skipped so a following within-limit READ is reached
        // (not hidden behind it).
        let mut buf = response_compound_head(3);
        buf.extend_from_slice(&open_res_op());
        buf.extend_from_slice(&getfh_res_op(16));
        buf.extend_from_slice(&read_op(8)); // within-limit, no data buffered
        assert_eq!(
            scan_nfs4_response_compound_read_len(&buf, 1024),
            Nfs4CompoundScan::Incomplete
        );
    }
}
