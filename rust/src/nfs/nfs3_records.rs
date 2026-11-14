/* Copyright (C) 2017-2022 Open Information Security Foundation
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

use crate::nfs::nfs_records::*;
use nom7::bytes::streaming::take;
use nom7::combinator::{complete, cond, rest, verify};

use nom7::multi::{length_data, many0};
use nom7::number::streaming::{be_u32, be_u64};
use nom7::IResult;
use std::cmp;

#[derive(Debug, PartialEq, Eq)]
pub struct Nfs3Handle<'a> {
    pub len: u32,
    pub value: &'a [u8],
}

pub fn parse_nfs3_handle(i: &[u8]) -> IResult<&[u8], Nfs3Handle<'_>> {
    let (i, len) = be_u32(i)?;
    let (i, value) = take(len as usize)(i)?;
    let handle = Nfs3Handle { len, value };
    Ok((i, handle))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Nfs3ReplyCreate<'a> {
    pub status: u32,
    pub handle: Option<Nfs3Handle<'a>>,
}

pub fn parse_nfs3_response_create(i: &[u8]) -> IResult<&[u8], Nfs3ReplyCreate<'_>> {
    let (i, status) = be_u32(i)?;
    let (i, handle_has_value) = verify(be_u32, |&v| v <= 1)(i)?;
    let (i, handle) = cond(handle_has_value == 1, parse_nfs3_handle)(i)?;
    let reply = Nfs3ReplyCreate { status, handle };
    Ok((i, reply))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Nfs3ReplyLookup<'a> {
    pub status: u32,
    pub handle: Nfs3Handle<'a>,
}

pub fn parse_nfs3_response_lookup(i: &[u8]) -> IResult<&[u8], Nfs3ReplyLookup<'_>> {
    let (i, status) = be_u32(i)?;
    let (i, handle) = parse_nfs3_handle(i)?;
    let reply = Nfs3ReplyLookup { status, handle };
    Ok((i, reply))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Nfs3RequestCreate<'a> {
    pub handle: Nfs3Handle<'a>,
    pub name_len: u32,
    pub create_mode: u32,
    pub verifier: &'a [u8],
    pub name_vec: Vec<u8>,
}

pub fn parse_nfs3_request_create(i: &[u8]) -> IResult<&[u8], Nfs3RequestCreate<'_>> {
    let (i, handle) = parse_nfs3_handle(i)?;
    let (i, name_len) = be_u32(i)?;
    let (i, name) = take(name_len as usize)(i)?;
    let (i, _fill_bytes) = cond(name_len % 4 != 0, take(4 - (name_len % 4)))(i)?;
    let (i, create_mode) = be_u32(i)?;
    let (i, verifier) = rest(i)?;
    let req = Nfs3RequestCreate {
        handle,
        name_len,
        create_mode,
        verifier,
        name_vec: name.to_vec(),
    };
    Ok((i, req))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Nfs3RequestRemove<'a> {
    pub handle: Nfs3Handle<'a>,
    pub name_len: u32,
    pub name_vec: Vec<u8>,
}

pub fn parse_nfs3_request_remove(i: &[u8]) -> IResult<&[u8], Nfs3RequestRemove<'_>> {
    let (i, handle) = parse_nfs3_handle(i)?;
    let (i, name_len) = be_u32(i)?;
    let (i, name) = take(name_len as usize)(i)?;
    let (i, _fill_bytes) = rest(i)?;
    let req = Nfs3RequestRemove {
        handle,
        name_len,
        name_vec: name.to_vec(),
    };
    Ok((i, req))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Nfs3RequestRmdir<'a> {
    pub handle: Nfs3Handle<'a>,
    pub name_vec: Vec<u8>,
}

pub fn parse_nfs3_request_rmdir(i: &[u8]) -> IResult<&[u8], Nfs3RequestRmdir<'_>> {
    let (i, handle) = parse_nfs3_handle(i)?;
    let (i, name_len) = be_u32(i)?;
    let (i, name) = take(name_len as usize)(i)?;
    let (i, _fill_bytes) = cond(name_len % 4 != 0, take(4 - (name_len % 4)))(i)?;
    let req = Nfs3RequestRmdir {
        handle,
        name_vec: name.to_vec(),
    };
    Ok((i, req))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Nfs3RequestMkdir<'a> {
    pub handle: Nfs3Handle<'a>,
    pub name_vec: Vec<u8>,
}

pub fn parse_nfs3_request_mkdir(i: &[u8]) -> IResult<&[u8], Nfs3RequestMkdir<'_>> {
    let (i, handle) = parse_nfs3_handle(i)?;
    let (i, name_len) = be_u32(i)?;
    let (i, name) = take(name_len as usize)(i)?;
    let (i, _fill_bytes) = cond(name_len % 4 != 0, take(4 - (name_len % 4)))(i)?;
    let (i, _attributes) = rest(i)?;
    let req = Nfs3RequestMkdir {
        handle,
        name_vec: name.to_vec(),
    };
    Ok((i, req))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Nfs3RequestRename<'a> {
    pub from_handle: Nfs3Handle<'a>,
    pub from_name_vec: Vec<u8>,
    pub to_handle: Nfs3Handle<'a>,
    pub to_name_vec: Vec<u8>,
}

pub fn parse_nfs3_request_rename(i: &[u8]) -> IResult<&[u8], Nfs3RequestRename<'_>> {
    let (i, from_handle) = parse_nfs3_handle(i)?;
    let (i, from_name_len) = be_u32(i)?;
    let (i, from_name) = take(from_name_len as usize)(i)?;
    let (i, _from_fill_bytes) = cond(from_name_len % 4 != 0, take(4 - (from_name_len % 4)))(i)?;

    let (i, to_handle) = parse_nfs3_handle(i)?;
    let (i, to_name_len) = be_u32(i)?;
    let (i, to_name) = take(to_name_len as usize)(i)?;
    let (i, _from_fill_bytes) = rest(i)?;
    let req = Nfs3RequestRename {
        from_handle,
        from_name_vec: from_name.to_vec(),
        to_handle,
        to_name_vec: to_name.to_vec(),
    };
    Ok((i, req))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Nfs3RequestGetAttr<'a> {
    pub handle: Nfs3Handle<'a>,
}

pub fn parse_nfs3_request_getattr(i: &[u8]) -> IResult<&[u8], Nfs3RequestGetAttr<'_>> {
    let (i, handle) = parse_nfs3_handle(i)?;
    Ok((i, Nfs3RequestGetAttr { handle }))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Nfs3RequestAccess<'a> {
    pub handle: Nfs3Handle<'a>,
    pub check_access: u32,
}

pub fn parse_nfs3_request_access(i: &[u8]) -> IResult<&[u8], Nfs3RequestAccess<'_>> {
    let (i, handle) = parse_nfs3_handle(i)?;
    let (i, check_access) = be_u32(i)?;
    let req = Nfs3RequestAccess {
        handle,
        check_access,
    };
    Ok((i, req))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Nfs3RequestCommit<'a> {
    pub handle: Nfs3Handle<'a>,
}

pub fn parse_nfs3_request_commit(i: &[u8]) -> IResult<&[u8], Nfs3RequestCommit<'_>> {
    let (i, handle) = parse_nfs3_handle(i)?;
    let (i, _offset) = be_u64(i)?;
    let (i, _count) = be_u32(i)?;
    Ok((i, Nfs3RequestCommit { handle }))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Nfs3RequestRead<'a> {
    pub handle: Nfs3Handle<'a>,
    pub offset: u64,
}

pub fn parse_nfs3_request_read(i: &[u8]) -> IResult<&[u8], Nfs3RequestRead<'_>> {
    let (i, handle) = parse_nfs3_handle(i)?;
    let (i, offset) = be_u64(i)?;
    let (i, _count) = be_u32(i)?;
    Ok((i, Nfs3RequestRead { handle, offset }))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Nfs3RequestLookup<'a> {
    pub handle: Nfs3Handle<'a>,
    pub name_vec: Vec<u8>,
}

pub fn parse_nfs3_request_lookup(i: &[u8]) -> IResult<&[u8], Nfs3RequestLookup<'_>> {
    let (i, handle) = parse_nfs3_handle(i)?;
    let (i, name_contents) = length_data(be_u32)(i)?;
    let (i, _name_padding) = rest(i)?;
    let req = Nfs3RequestLookup {
        handle,
        name_vec: name_contents.to_vec(),
    };
    Ok((i, req))
}

/// fattr3 (RFC 1813 3.2.4): 84 bytes. size/used are size3 = uint64
/// (RFC 1813 3.1.2), so the attr block is 4 + 80.
fn parse_nfs3_fattr3(i: &[u8]) -> IResult<&[u8], u32> {
    // RFC 1813 2.6 numbers ftype3 0..=7 (NF3SOCK=6, NF3FIFO=7); RFC 1094 5.3
    // stops at 5. Servers also emit 0 in zero-filled attr blocks, so reject
    // only what cannot be a type. Mainline never validated this.
    let (i, ftype) = verify(be_u32, |&v| v <= 7)(i)?;
    let (i, _attr) = take(80_usize)(i)?;
    Ok((i, ftype))
}

/// post_op_attr (RFC 1813): a follows bool + the fattr3 when set.
fn parse_nfs3_post_op_attr(i: &[u8]) -> IResult<&[u8], bool> {
    let (i, follows) = verify(be_u32, |&v| v <= 1)(i)?;
    let (i, _) = cond(follows == 1, parse_nfs3_fattr3)(i)?;
    Ok((i, follows == 1))
}

/// wcc_data (RFC 1813 3.5.5): pre_op_attr (bool + wcc_attr {size,
/// mtime, ctime} = 24 bytes when set) + post_op_attr.
fn parse_nfs3_wcc_data(i: &[u8]) -> IResult<&[u8], ()> {
    let (i, pre) = verify(be_u32, |&v| v <= 1)(i)?;
    let (i, _) = cond(pre == 1, take(24_usize))(i)?;
    let (i, _) = parse_nfs3_post_op_attr(i)?;
    Ok((i, ()))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Nfs3ResponseReaddirplusEntryC<'a> {
    pub name_vec: Vec<u8>,
    /// the entry's name_handle (post_op_fh3), when present
    pub handle: Option<Nfs3Handle<'a>>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Nfs3ResponseReaddirplusEntry<'a> {
    pub entry: Option<Nfs3ResponseReaddirplusEntryC<'a>>,
}

/// entryplus3 (RFC 1813 3.3.17): fileid, name, cookie, post_op_attr,
/// post_op_fh3 name_handle.
pub fn parse_nfs3_response_readdirplus_entry(
    i: &[u8],
) -> IResult<&[u8], Nfs3ResponseReaddirplusEntryC<'_>> {
    let (i, _file_id) = be_u64(i)?;
    let (i, name_len) = verify(be_u32, |&v| v <= 1024)(i)?;
    let (i, name_contents) = take(name_len as usize)(i)?;
    let (i, _fill_bytes) = cond(name_len % 4 != 0, take(4 - (name_len % 4)))(i)?;
    let (i, _cookie) = be_u64(i)?;
    let (i, _) = parse_nfs3_post_op_attr(i)?;
    let (i, handle_follows) = verify(be_u32, |&v| v <= 1)(i)?;
    let (i, handle) = cond(handle_follows == 1, parse_nfs3_handle)(i)?;
    let resp = Nfs3ResponseReaddirplusEntryC {
        name_vec: name_contents.to_vec(),
        handle,
    };
    Ok((i, resp))
}

/// the value_follows prefix of the dirlistplus3 XDR pointer chain
pub fn parse_nfs3_response_readdirplus_entry_cond(
    i: &[u8],
) -> IResult<&[u8], Nfs3ResponseReaddirplusEntry<'_>> {
    let (i, value_follows) = verify(be_u32, |&v| v <= 1)(i)?;
    let (i, entry) = cond(value_follows == 1, parse_nfs3_response_readdirplus_entry)(i)?;
    Ok((i, Nfs3ResponseReaddirplusEntry { entry }))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Nfs3ResponseReaddirplus<'a> {
    pub status: u32,
    /// dirlistplus3: the value_follows entry chain (eof at the tail)
    pub data: &'a [u8],
}

/// READDIRPLUS3resok (RFC 1813 3.3.17): post_op_attr dir_attributes +
/// cookieverf3 (8 bytes) + dirlistplus3; error replies carry only the
/// status.
pub fn parse_nfs3_response_readdirplus(i: &[u8]) -> IResult<&[u8], Nfs3ResponseReaddirplus<'_>> {
    let (i, status) = be_u32(i)?;
    let (i, data) = if status == 0 {
        let (i, _) = parse_nfs3_post_op_attr(i)?;
        let (i, _cookieverf) = take(8_usize)(i)?;
        rest(i)?
    } else {
        rest(i)?
    };
    let resp = Nfs3ResponseReaddirplus { status, data };
    Ok((i, resp))
}

/// the dirlistplus3 entry chain, flattened (the eof tail stays over)
pub(crate) fn many0_nfs3_response_readdirplus_entries(
    input: &[u8],
) -> IResult<&[u8], Vec<Nfs3ResponseReaddirplusEntryC<'_>>> {
    let (i, wrapped) = many0(complete(parse_nfs3_response_readdirplus_entry_cond))(input)?;
    Ok((i, wrapped.into_iter().filter_map(|w| w.entry).collect()))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Nfs3RequestReaddirplus<'a> {
    pub handle: Nfs3Handle<'a>,
    pub cookie: u64,
    pub verifier: &'a [u8],
    pub dircount: u32,
    pub maxcount: u32,
}

pub fn parse_nfs3_request_readdirplus(i: &[u8]) -> IResult<&[u8], Nfs3RequestReaddirplus<'_>> {
    let (i, handle) = parse_nfs3_handle(i)?;
    let (i, cookie) = be_u64(i)?;
    let (i, verifier) = take(8_usize)(i)?;
    let (i, dircount) = be_u32(i)?;
    let (i, maxcount) = be_u32(i)?;
    let req = Nfs3RequestReaddirplus {
        handle,
        cookie,
        verifier,
        dircount,
        maxcount,
    };
    Ok((i, req))
}

// RFC 1813 3.12.1: same as READDIRPLUS without the dircount field
#[derive(Debug, PartialEq, Eq)]
pub struct Nfs3RequestReaddir<'a> {
    pub handle: Nfs3Handle<'a>,
    pub cookie: u64,
    pub verifier: &'a [u8],
    pub maxcount: u32,
}

pub fn parse_nfs3_request_readdir(i: &[u8]) -> IResult<&[u8], Nfs3RequestReaddir<'_>> {
    let (i, handle) = parse_nfs3_handle(i)?;
    let (i, cookie) = be_u64(i)?;
    let (i, verifier) = take(8_usize)(i)?;
    let (i, maxcount) = be_u32(i)?;
    let req = Nfs3RequestReaddir {
        handle,
        cookie,
        verifier,
        maxcount,
    };
    Ok((i, req))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Nfs3ResponseReaddirEntry {
    pub name_vec: Vec<u8>,
    pub cookie: u64,
    pub file_id: u64,
}

/// entry3 (RFC 1813 3.3.15): fileid, name, cookie. No attributes: the
/// attributes are only in entryplus3.
pub fn parse_nfs3_response_readdir_entry(i: &[u8]) -> IResult<&[u8], Nfs3ResponseReaddirEntry> {
    let (i, file_id) = be_u64(i)?;
    let (i, name_len) = verify(be_u32, |&v| v <= 1024)(i)?;
    let (i, name_contents) = take(name_len as usize)(i)?;
    let (i, _fill_bytes) = cond(name_len % 4 != 0, take(4 - (name_len % 4)))(i)?;
    let (i, cookie) = be_u64(i)?;
    let entry = Nfs3ResponseReaddirEntry {
        name_vec: name_contents.to_vec(),
        cookie,
        file_id,
    };
    Ok((i, entry))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Nfs3ResponseReaddirEntryC {
    pub entry: Option<Nfs3ResponseReaddirEntry>,
}

/// the value_follows prefix of the dirlist3 XDR pointer chain
#[cfg(test)]
fn parse_nfs3_response_readdir_entry_cond(i: &[u8]) -> IResult<&[u8], Nfs3ResponseReaddirEntryC> {
    let (i, value_follows) = verify(be_u32, |&v| v <= 1)(i)?;
    let (i, entry) = cond(value_follows == 1, parse_nfs3_response_readdir_entry)(i)?;
    Ok((i, Nfs3ResponseReaddirEntryC { entry }))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Nfs3ResponseReaddir<'a> {
    pub status: u32,
    /// dirlist3: the value_follows entry chain (eof at the tail)
    pub data: &'a [u8],
}

/// READDIR3resok (RFC 1813 3.3.15): post_op_attr dir_attributes +
/// cookieverf3 (8 bytes) + dirlist3; error replies carry only the status.
pub fn parse_nfs3_response_readdir(i: &[u8]) -> IResult<&[u8], Nfs3ResponseReaddir<'_>> {
    let (i, status) = be_u32(i)?;
    let (i, data) = if status == 0 {
        let (i, _) = parse_nfs3_post_op_attr(i)?;
        let (i, _cookieverf) = take(8_usize)(i)?;
        rest(i)?
    } else {
        rest(i)?
    };
    let resp = Nfs3ResponseReaddir { status, data };
    Ok((i, resp))
}

/// the dirlist3 entry chain, flattened (the eof tail stays over)
#[cfg(test)]
pub(crate) fn many0_nfs3_response_readdir_entries(
    input: &[u8],
) -> IResult<&[u8], Vec<Nfs3ResponseReaddirEntry>> {
    let (i, wrapped) = many0(complete(parse_nfs3_response_readdir_entry_cond))(input)?;
    Ok((i, wrapped.into_iter().filter_map(|w| w.entry).collect()))
}

/// nfsstring3 / nfspath3: length + string, 4-byte aligned
fn parse_nfs3_name(i: &[u8]) -> IResult<&[u8], Vec<u8>> {
    // no length bound: RFC 1813 3.2 puts none on filename3 or nfspath3, and
    // take() already fails when the record runs out
    let (i, name_len) = be_u32(i)?;
    let pad = if name_len % 4 == 0 {
        0
    } else {
        4 - name_len % 4
    };
    let (i, name) = take(name_len as usize)(i)?;
    let (i, _pad) = cond(pad > 0, take(pad as usize))(i)?;
    Ok((i, name.to_vec()))
}

/// nfspath3 (RFC 1813 2.6): a string3 with no length bound, so the
/// nfsname3 1024 limit does not apply. Bounded at PATH_MAX (4096), what
/// Linux allows for a symlink target; consumed, never logged.
fn parse_nfs3_path(i: &[u8]) -> IResult<&[u8], Vec<u8>> {
    let (i, len) = verify(be_u32, |&v| v <= 4096)(i)?;
    let pad = if len % 4 == 0 { 0 } else { 4 - len % 4 };
    let (i, s) = take(len as usize)(i)?;
    let (i, _pad) = cond(pad > 0, take(pad as usize))(i)?;
    Ok((i, s.to_vec()))
}

// RFC 1813 time_how + optional client time (the 8-byte nfstime3 only for
// SET_TO_CLIENT_TIME == 2)
type Nfs3TimeHow = (u32, Option<(u64, u32)>);

// RFC 1813 3.2.4: sattr3 -- optional mode/uid/gid/size values plus
// atime/mtime set_atime/set_mtime unions and the sattrguard3 guard.
#[derive(Debug, PartialEq, Eq)]
pub struct Nfs3SetAttr {
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub size: Option<u64>,
    /// (time_how, client time when how == 2)
    pub atime: Nfs3TimeHow,
    /// (time_how, client time when how == 2)
    pub mtime: Nfs3TimeHow,
    /// (check, server time when check)
    pub guard: (bool, Option<(u64, u32)>),
}

// time_how (RFC 1813 3.2.2): 0 = DONT_CHANGE, 1 = SET_TO_SERVER_TIME,
// 2 = SET_TO_CLIENT_TIME (the only arm carrying an 8-byte nfstime3)
fn parse_nfs3_time_how(i: &[u8]) -> IResult<&[u8], Nfs3TimeHow> {
    let (i, how) = verify(be_u32, |&v| v <= 2)(i)?;
    if how == 2 {
        let (i, t) = parse_nfs3_nfstime(i)?;
        Ok((i, (how, Some(t))))
    } else {
        Ok((i, (how, None)))
    }
}

// nfstime3 (RFC 1813 3.2.1): 4-byte seconds + 4-byte nanoseconds
fn parse_nfs3_nfstime(i: &[u8]) -> IResult<&[u8], (u64, u32)> {
    let (i, sec) = be_u32(i)?;
    let (i, nsec) = be_u32(i)?;
    Ok((i, (sec as u64, nsec)))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Nfs3RequestSetattr<'a> {
    pub handle: Nfs3Handle<'a>,
    pub attr: Nfs3SetAttr,
}

// sattr3 without the guard (RFC 1813 3.2.4): optional mode/uid/gid/size
// then the atime/mtime time_how unions
fn parse_nfs3_sattr3(i: &[u8]) -> IResult<&[u8], Nfs3SetAttr> {
    let (i, f) = verify(be_u32, |&v| v <= 1)(i)?;
    let (i, mode) = cond(f == 1, be_u32)(i)?;
    let (i, f) = verify(be_u32, |&v| v <= 1)(i)?;
    let (i, uid) = cond(f == 1, be_u32)(i)?;
    let (i, f) = verify(be_u32, |&v| v <= 1)(i)?;
    let (i, gid) = cond(f == 1, be_u32)(i)?;
    let (i, f) = verify(be_u32, |&v| v <= 1)(i)?;
    let (i, size) = cond(f == 1, be_u64)(i)?;
    // atime before mtime on the wire; the set_atime/set_mtime unions
    // carry the 8-byte nfstime3 only for SET_TO_CLIENT_TIME (2)
    let (i, atime) = parse_nfs3_time_how(i)?;
    let (i, mtime) = parse_nfs3_time_how(i)?;
    Ok((
        i,
        Nfs3SetAttr {
            mode,
            uid,
            gid,
            size,
            atime,
            mtime,
            guard: (false, None),
        },
    ))
}

pub fn parse_nfs3_request_setattr(i: &[u8]) -> IResult<&[u8], Nfs3RequestSetattr<'_>> {
    let (i, handle) = parse_nfs3_handle(i)?;
    let (i, mut attr) = parse_nfs3_sattr3(i)?;
    // sattrguard3: check flag, raw 8-byte server time only when check
    let (i, g) = verify(be_u32, |&v| v <= 1)(i)?;
    let (i, gtime) = cond(g == 1, parse_nfs3_nfstime)(i)?;
    attr.guard = (g == 1, gtime);
    let req = Nfs3RequestSetattr { handle, attr };
    Ok((i, req))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Nfs3ResponseSetattr {
    pub status: u32,
}

// SETATTR3resok (RFC 1813 3.3.14): the wcc_data only -- the post-op
// attributes ride inside it (wcc_data = pre_op_attr + post_op_attr).
pub fn parse_nfs3_response_setattr(i: &[u8]) -> IResult<&[u8], Nfs3ResponseSetattr> {
    let (i, status) = be_u32(i)?;
    // the wcc must be consumed: the record boundary rides its end
    let (i, _) = if status == 0 {
        parse_nfs3_wcc_data(i)
    } else {
        Ok((i, ()))
    }?;
    let resp = Nfs3ResponseSetattr { status };
    Ok((i, resp))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Nfs3RequestWrite<'a> {
    pub handle: Nfs3Handle<'a>,
    pub offset: u64,
    pub count: u32,
    pub stable: u32,
    pub file_len: u32,
    pub file_data: &'a [u8],
}

/// Complete data expected
pub fn parse_nfs3_data_complete(
    i: &[u8], file_len: usize, fill_bytes: usize,
) -> IResult<&[u8], &[u8]> {
    let (i, file_data) = take(file_len)(i)?;
    let (i, _) = cond(fill_bytes > 0, take(fill_bytes))(i)?;
    Ok((i, file_data))
}

/// Partial data. We have all file_len, but need to consider fill_bytes
pub fn parse_nfs3_data_partial(
    i: &[u8], file_len: usize, fill_bytes: usize,
) -> IResult<&[u8], &[u8]> {
    let (i, file_data) = take(file_len)(i)?;
    let fill_bytes = cmp::min(fill_bytes, i.len());
    let (i, _) = cond(fill_bytes > 0, take(fill_bytes))(i)?;
    Ok((i, file_data))
}

/// Parse WRITE record. Consider 3 cases:
/// 1. we have the complete RPC data
/// 2. we have incomplete data but enough for all file data (partial fill bytes)
/// 3. we have incomplete file data
pub fn parse_nfs3_request_write(i: &[u8], complete: bool) -> IResult<&[u8], Nfs3RequestWrite<'_>> {
    let (i, handle) = parse_nfs3_handle(i)?;
    let (i, offset) = be_u64(i)?;
    let (i, count) = be_u32(i)?;
    let (i, stable) = verify(be_u32, |&v| v <= 2)(i)?;
    let (i, file_len) = verify(be_u32, |&v| v <= count)(i)?;
    let fill_bytes = if file_len % 4 != 0 {
        4 - file_len % 4
    } else {
        0
    };
    // Handle the various file data parsing logics
    let (i, file_data) = if complete {
        parse_nfs3_data_complete(i, file_len as usize, fill_bytes as usize)?
    } else if i.len() >= file_len as usize {
        parse_nfs3_data_partial(i, file_len as usize, fill_bytes as usize)?
    } else {
        rest(i)?
    };
    let req = Nfs3RequestWrite {
        handle,
        offset,
        count,
        stable,
        file_len,
        file_data,
    };
    Ok((i, req))
}

pub fn parse_nfs3_reply_read(i: &[u8], complete: bool) -> IResult<&[u8], NfsReplyRead<'_>> {
    let (i, status) = be_u32(i)?;
    let (i, attr_follows) = verify(be_u32, |&v| v <= 1)(i)?;
    let (i, attr_blob_opt) = cond(attr_follows == 1, take(84_usize))(i)?;
    let attr_blob = attr_blob_opt.unwrap_or(&[]);
    let (i, count) = be_u32(i)?;
    let (i, eof) = verify(be_u32, |&v| v <= 1)(i)?;
    let (i, data_len) = verify(be_u32, |&v| v <= count)(i)?;
    let fill_bytes = if data_len % 4 != 0 {
        4 - data_len % 4
    } else {
        0
    };
    // Handle the various file data parsing logics
    let (i, data) = if complete {
        parse_nfs3_data_complete(i, data_len as usize, fill_bytes as usize)?
    } else if i.len() >= data_len as usize {
        parse_nfs3_data_partial(i, data_len as usize, fill_bytes as usize)?
    } else {
        rest(i)?
    };
    let reply = NfsReplyRead {
        status,
        attr_follows,
        attr_blob,
        count,
        eof: eof != 0,
        data_len,
        data,
    };
    Ok((i, reply))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Nfs3Fsinfores {
    pub status: u32,
    /// maximum size for reads (rtmax) that the server supports
    pub rtm: u32,
    /// recommended size for reads
    pub rtpref: u32,
    /// preferred read transfer multiple
    pub rtmult: u32,
    /// maximum size for writes (wtmax) that the server supports
    pub wtm: u32,
    /// recommended size for writes
    pub wtpref: u32,
    /// preferred write transfer multiple
    pub wtmult: u32,
    /// preferred transfer size for directory operations
    pub dtpref: u32,
    /// maximum file size
    pub maxfilesize: u64,
    /// recommended granularity of time changes
    pub time_delta: (u64, u32),
    /// bitmap of supported operations (FNF3_* properties)
    pub properties: u32,
}

pub fn parse_nfs3_response_fsinfo(i: &[u8]) -> IResult<&[u8], Nfs3Fsinfores> {
    let (i, status) = be_u32(i)?;
    if status == 0 {
        // FSINFO3resok (RFC 1813 3.3.19): obj_attributes, rtmax, rtpref,
        // rtmult, wtmax, wtpref, wtmult, dtpref, maxfilesize, time_delta,
        // properties
        let (i, _) = parse_nfs3_post_op_attr(i)?;
        let (i, rtm) = be_u32(i)?;
        let (i, rtpref) = be_u32(i)?;
        let (i, rtmult) = be_u32(i)?;
        let (i, wtm) = be_u32(i)?;
        let (i, wtpref) = be_u32(i)?;
        let (i, wtmult) = be_u32(i)?;
        let (i, dtpref) = be_u32(i)?;
        let (i, maxfilesize) = be_u64(i)?;
        let (i, td) = parse_nfs3_nfstime(i)?;
        let (i, properties) = be_u32(i)?;
        Ok((
            i,
            Nfs3Fsinfores {
                status,
                rtm,
                rtpref,
                rtmult,
                wtm,
                wtpref,
                wtmult,
                dtpref,
                maxfilesize,
                time_delta: td,
                properties,
            },
        ))
    } else {
        // FSINFO3resfail: obj_attributes only
        let (i, _) = parse_nfs3_post_op_attr(i)?;
        Ok((
            i,
            Nfs3Fsinfores {
                status,
                rtm: 0,
                rtpref: 0,
                rtmult: 0,
                wtm: 0,
                wtpref: 0,
                wtmult: 0,
                dtpref: 0,
                maxfilesize: 0,
                time_delta: (0, 0),
                properties: 0,
            },
        ))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Nfs3RequestMknod<'a> {
    pub handle: Nfs3Handle<'a>,
    pub name_vec: Vec<u8>,
}

/// v3 MKNOD (RFC 1813): dirhandle + name + sattr3 + specdata3. Wire the
/// directory handle and the new node name; the attributes and device numbers
/// are not logged.
pub fn parse_nfs3_request_mknod(i: &[u8]) -> IResult<&[u8], Nfs3RequestMknod<'_>> {
    let (i, handle) = parse_nfs3_handle(i)?;
    let (i, name_len) = be_u32(i)?;
    let (i, name) = take(name_len as usize)(i)?;
    let (i, _name_pad) = cond(name_len % 4 != 0, take(4 - (name_len % 4)))(i)?;
    let (i, _attrs_and_dev) = rest(i)?; // sattr3 + specdata3 (not logged)
    let req = Nfs3RequestMknod {
        handle,
        name_vec: name.to_vec(),
    };
    Ok((i, req))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Nfs3RequestLink<'a> {
    /// the file being linked
    pub handle: Nfs3Handle<'a>,
    /// the directory the link is created in
    pub linkdir: Nfs3Handle<'a>,
    /// the link's name (diropargs3 link.name)
    pub linkname: Vec<u8>,
}

/// v3 LINK (RFC 1813 3.3.15): nfs_fh3 file + diropargs3 link (dir + name).
pub fn parse_nfs3_request_link(i: &[u8]) -> IResult<&[u8], Nfs3RequestLink<'_>> {
    let (i, handle) = parse_nfs3_handle(i)?;
    let (i, linkdir) = parse_nfs3_handle(i)?;
    let (i, linkname) = parse_nfs3_name(i)?;
    let req = Nfs3RequestLink {
        handle,
        linkdir,
        linkname,
    };
    Ok((i, req))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Nfs3RequestSymlink<'a> {
    /// the directory the symlink is created in
    pub handle: Nfs3Handle<'a>,
    /// the new symlink's name
    pub name_vec: Vec<u8>,
    /// the target path (symlinkdata3 symlink_data)
    pub target_path: Vec<u8>,
}

/// v3 SYMLINK (RFC 1813 3.3.10): diropargs3 where (dir + name) +
/// symlinkdata3 (sattr3 symlink_attributes + nfspath3 symlink_data target
/// path). The attribute data and target path are consumed, not logged.
pub fn parse_nfs3_request_symlink(i: &[u8]) -> IResult<&[u8], Nfs3RequestSymlink<'_>> {
    let (i, handle) = parse_nfs3_handle(i)?;
    let (i, name) = parse_nfs3_name(i)?;
    let (i, _attrs) = parse_nfs3_sattr3(i)?;
    let (i, target_path) = parse_nfs3_path(i)?;
    Ok((
        i,
        Nfs3RequestSymlink {
            handle,
            name_vec: name,
            target_path,
        },
    ))
}

/// Unit tests
#[cfg(test)]
mod tests {
    use crate::nfs::nfs3_records::*;

    // fattr3 (rfc 1813): ftype + 80 bytes of nfsv3attributes3 = 84 bytes
    fn fattr3() -> Vec<u8> {
        let mut v = 1u32.to_be_bytes().to_vec(); // NREG
        v.extend(std::iter::repeat_n(0u8, 80));
        v
    }

    #[test]
    fn test_nfs3_response_fsinfo() {
        // FSINFO3resok (RFC 1813 3.3.19): status + post_op_attr + the
        // eleven resok words (maxfilesize is a size3 = u64, time_delta an
        // nfstime3)
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&0u32.to_be_bytes()); // status NFS3_OK
        buf.extend_from_slice(&1u32.to_be_bytes()); // post_op_attr: follows
        buf.extend_from_slice(&fattr3()); // 84-byte fattr3
        buf.extend_from_slice(&65536u32.to_be_bytes()); // rtmax
        buf.extend_from_slice(&1024u32.to_be_bytes()); // rtpref
        buf.extend_from_slice(&4u32.to_be_bytes()); // rtmult
        buf.extend_from_slice(&65536u32.to_be_bytes()); // wtmax
        buf.extend_from_slice(&1024u32.to_be_bytes()); // wtpref
        buf.extend_from_slice(&4u32.to_be_bytes()); // wtmult
        buf.extend_from_slice(&1024u32.to_be_bytes()); // dtpref
        let mfs: u64 = 1 << 40;
        buf.extend_from_slice(&mfs.to_be_bytes()); // maxfilesize
        buf.extend_from_slice(&1u32.to_be_bytes()); // time_delta sec
        buf.extend_from_slice(&0u32.to_be_bytes()); // time_delta nsec
        buf.extend_from_slice(&0u32.to_be_bytes()); // properties

        let (_, response) = parse_nfs3_response_fsinfo(&buf).unwrap();
        assert_eq!(response.status, 0);
        assert_eq!(response.rtm, 65536);
        assert_eq!(response.rtpref, 1024);
        assert_eq!(response.rtmult, 4);
        assert_eq!(response.wtm, 65536);
        assert_eq!(response.wtpref, 1024);
        assert_eq!(response.wtmult, 4);
        assert_eq!(response.dtpref, 1024);
        assert_eq!(response.maxfilesize, 1u64 << 40);
        assert_eq!(response.time_delta, (1, 0));
        assert_eq!(response.properties, 0);

        // FSINFO3resfail: status + post_op_attr only
        let mut errbuf: Vec<u8> = Vec::new();
        errbuf.extend_from_slice(&5u32.to_be_bytes()); // NFS3ERR_IO
        errbuf.extend_from_slice(&0u32.to_be_bytes()); // post_op_attr: not
        let (_, expected) = parse_nfs3_response_fsinfo(&errbuf).unwrap();
        assert_eq!(expected.status, 5);
        assert_eq!(expected.rtm, 0);
        assert_eq!(expected.wtm, 0);
    }

    #[test]
    fn test_nfs3_response_create() {
        #[rustfmt::skip]
        let buf: &[u8] = &[
            0x00, 0x00, 0x00, 0x00, /*Status: NFS3_OK (0)*/
            0x00, 0x00, 0x00, 0x01, /*handle_follows: (1)*/
            0x00, 0x00, 0x00, 0x20, /*handle_len: (32)*/
            0x00, 0x10, 0x10, 0x85, 0x00, 0x00, 0x03, 0xe7, /*handle*/
            0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0xa6, 0x54,
            0x00, 0x00, 0x00, 0x1b, 0x00, 0x0a, 0x00, 0x00,
            0x00, 0x00, 0xb2, 0x5a, 0x00, 0x00, 0x00, 0x29,
        ];

        let (_, expected_handle) = parse_nfs3_handle(&buf[8..]).unwrap();

        let (_, response) = parse_nfs3_response_create(buf).unwrap();
        assert_eq!(response.status, 0);
        assert_eq!(response.handle, Some(expected_handle));
    }

    #[test]
    fn test_nfs3_response_lookup() {
        #[rustfmt::skip]
        let buf: &[u8] = &[
            0x00, 0x00, 0x00, 0x00, /*Status: NFS3_OK (0)*/
            0x00, 0x00, 0x00, 0x20, /*handle_len: (32)*/
            0x00, 0x10, 0x10, 0x85, 0x00, 0x00, 0x03, 0xe7, /*handle*/
            0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0xa3, 0xec,
            0x00, 0x00, 0x00, 0x0e, 0x00, 0x0a, 0x00, 0x00,
            0x00, 0x00, 0xb2, 0x5a, 0x00, 0x00, 0x00, 0x29,
        ];

        let (_, expected_handle) = parse_nfs3_handle(&buf[4..]).unwrap();

        let (_, response) = parse_nfs3_response_lookup(buf).unwrap();
        assert_eq!(response.status, 0);
        assert_eq!(response.handle, expected_handle);
    }

    #[test]
    fn test_nfs3_request_create() {
        #[rustfmt::skip]
        let buf: &[u8] = &[
        // [handle]
            0x00, 0x00, 0x00, 0x20, /*handle_len*/
            0x00, 0x10, 0x10, 0x85, 0x00, 0x00, 0x03, 0xe7, /*handle*/
            0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0xa3, 0xe7,
            0x00, 0x00, 0x00, 0x10, 0x00, 0x0a, 0x00, 0x00,
            0x00, 0x00, 0xb2, 0x5a, 0x00, 0x00, 0x00, 0x29,
        // [name]
            0x00, 0x00, 0x00, 0x01, /*name_len: (1)*/
            0x68, /*name_contents: (h)*/
            0x00, 0x00, 0x00, /*_fill_bytes*/
            0x00, 0x00, 0x00, 0x00, /*create_mode: UNCHECKED (0)*/
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0xa4, /*verifier*/
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];

        let (_, expected_handle) = parse_nfs3_handle(&buf[..36]).unwrap();

        let (r, request) = parse_nfs3_request_create(buf).unwrap();
        assert_eq!(r.len(), 0);
        assert_eq!(request.handle, expected_handle);
        assert_eq!(request.name_len, 1);
        assert_eq!(request.create_mode, 0);
        assert_eq!(request.verifier.len(), 44);
        assert_eq!(request.name_vec, br#"h"#.to_vec());
    }

    #[test]
    fn test_nfs3_request_remove() {
        #[rustfmt::skip]
        let buf: &[u8] = &[
        // [handle]
            0x00, 0x00, 0x00, 0x20, /*handle_len*/
            0x00, 0x10, 0x10, 0x85, 0x00, 0x00, 0x03, 0xe7, /*handle*/
            0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0xa3, 0xe7,
            0x00, 0x00, 0x00, 0x10, 0x00, 0x0a, 0x00, 0x00,
            0x00, 0x00, 0xb2, 0x5a, 0x00, 0x00, 0x00, 0x29,
        // [name]
            0x00, 0x00, 0x00, 0x01, /*name_len: (1)*/
            0x68, /*name_contents: (h)*/
            0x00, 0x00, 0x00, /*_fill_bytes*/
        ];

        let (_, expected_handle) = parse_nfs3_handle(&buf[..36]).unwrap();

        let (r, request) = parse_nfs3_request_remove(buf).unwrap();
        assert_eq!(r.len(), 0);
        assert_eq!(request.handle, expected_handle);
        assert_eq!(request.name_len, 1);
        assert_eq!(request.name_vec, br#"h"#.to_vec());
    }

    #[test]
    fn test_nfs3_request_rmdir() {
        #[rustfmt::skip]
        let buf: &[u8] = &[
        //[handle]
            0x00, 0x00, 0x00, 0x20, /*handle_len: (32)*/
            0x00, 0x10, 0x10, 0x85, 0x00, 0x00, 0x03, 0xe7, /*handle*/
            0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0xb2, 0x5a,
            0x00, 0x00, 0x00, 0x29, 0x00, 0x0a, 0x00, 0x00,
            0x00, 0x00, 0xb2, 0x5a, 0x00, 0x00, 0x00, 0x29,
        // [name]
            0x00, 0x00, 0x00, 0x01, /*name_len: (1)*/
            0x64, /*name_contents: (d)*/
            0x00, 0x00, 0x00, /*_fill_bytes*/
        ];

        let (_, expected_handle) = parse_nfs3_handle(&buf[..36]).unwrap();

        let (r, request) = parse_nfs3_request_rmdir(buf).unwrap();
        assert_eq!(r.len(), 0);
        assert_eq!(request.handle, expected_handle);
        assert_eq!(request.name_vec, br#"d"#.to_vec());
    }

    #[test]
    fn test_nfs3_request_mkdir() {
        #[rustfmt::skip]
        let buf: &[u8] = &[
        // [handle]
            0x00, 0x00, 0x00, 0x20, /*handle_len: (32)*/
            0x00, 0x10, 0x10, 0x85, 0x00, 0x00, 0x03, 0xe7, /*handle*/
            0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0xb2, 0x5a,
            0x00, 0x00, 0x00, 0x29, 0x00, 0x0a, 0x00, 0x00,
            0x00, 0x00, 0xb2, 0x5a, 0x00, 0x00, 0x00, 0x29,
        // [name]
            0x00, 0x00, 0x00, 0x01, /*name_len: (1)*/
            0x64, /*name_contents: (d)*/
            0x00, 0x00, 0x00, /*_fill_bytes*/
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0xed, /*attributes*/
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];

        let (_, expected_handle) = parse_nfs3_handle(&buf[..36]).unwrap();

        let (_r, request) = parse_nfs3_request_mkdir(buf).unwrap();
        assert_eq!(request.handle, expected_handle);
        assert_eq!(request.name_vec, br#"d"#.to_vec());
    }

    #[test]
    fn test_nfs3_request_rename() {
        #[rustfmt::skip]
        let buf: &[u8] = &[
        // [from_handle]
            0x00, 0x00, 0x00, 0x20, /*handle_len: (32)*/
            0x00, 0x10, 0x10, 0x85, 0x00, 0x00, 0x03, 0xe7, /*handle*/
            0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0xb2, 0x5a,
            0x00, 0x00, 0x00, 0x29, 0x00, 0x0a, 0x00, 0x00,
            0x00, 0x00, 0xb2, 0x5a, 0x00, 0x00, 0x00, 0x29,
        // [from_name]
            0x00, 0x00, 0x00, 0x01, /*name_len: (1)*/
            0x61, /*name: (a)*/
            0x00, 0x00, 0x00, /*_fill_bytes*/
        // [to_handle]
            0x00, 0x00, 0x00, 0x20, /*handle_len*/
            0x00, 0x10, 0x10, 0x85, 0x00, 0x00, 0x03, 0xe7, /*handle*/
            0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0xb2, 0x5a,
            0x00, 0x00, 0x00, 0x29, 0x00, 0x0a, 0x00, 0x00,
            0x00, 0x00, 0xb2, 0x5a, 0x00, 0x00, 0x00, 0x29,
        // [to_name]
            0x00, 0x00, 0x00, 0x02, /*name_len: (2)*/
            0x61, 0x6d, /*name: (am)*/
            0x00, 0x00, /*_fill_bytes*/
        ];

        let (_, expected_from_handle) = parse_nfs3_handle(&buf[..36]).unwrap();
        let (_, expected_to_handle) = parse_nfs3_handle(&buf[44..80]).unwrap();

        let (r, request) = parse_nfs3_request_rename(buf).unwrap();
        assert_eq!(r.len(), 0);

        assert_eq!(request.from_handle, expected_from_handle);
        assert_eq!(request.from_name_vec, br#"a"#.to_vec());

        assert_eq!(request.to_handle, expected_to_handle);
        assert_eq!(request.to_name_vec, br#"am"#.to_vec());
    }

    #[test]
    fn test_nfs3_request_getattr() {
        #[rustfmt::skip]
        let buf: &[u8] = &[
            0x00, 0x00, 0x00, 0x20, /*handle_len: (32)*/
            0x00, 0x10, 0x10, 0x85, 0x00, 0x00, 0x03, 0xe7, /*handle*/
            0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0xb2, 0x5a,
            0x00, 0x00, 0x00, 0x29, 0x00, 0x0a, 0x00, 0x00,
            0x00, 0x00, 0xb2, 0x5a, 0x00, 0x00, 0x00, 0x29,
        ];

        let (_, expected_handle) = parse_nfs3_handle(buf).unwrap();

        let (r, request) = parse_nfs3_request_getattr(buf).unwrap();
        assert_eq!(r.len(), 0);
        assert_eq!(request.handle, expected_handle);
    }

    #[test]
    fn test_nfs3_request_access() {
        #[rustfmt::skip]
        let buf: &[u8] = &[
            0x00, 0x00, 0x00, 0x20, /*handle_len: (32)*/
            0x00, 0x10, 0x10, 0x85, 0x00, 0x00, 0x03, 0xe7, /*handle*/
            0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0xa6, 0x54,
            0x00, 0x00, 0x00, 0x1b, 0x00, 0x0a, 0x00, 0x00,
            0x00, 0x00, 0xb2, 0x5a, 0x00, 0x00, 0x00, 0x29,
            0x00, 0x00, 0x00, 0x0c, /*check_access: (12)*/
        ];

        let (_, expected_handle) = parse_nfs3_handle(&buf[..36]).unwrap();

        let (r, request) = parse_nfs3_request_access(buf).unwrap();
        assert_eq!(r.len(), 0);
        assert_eq!(request.handle, expected_handle);
        assert_eq!(request.check_access, 12);
    }

    #[test]
    fn test_nfs3_request_commit() {
        // packet_bytes -- used [READ Call] message digest
        #[rustfmt::skip]
        let buf: &[u8] = &[
            0x00, 0x00, 0x00, 0x20, /*handle_len: (32)*/
            0x00, 0x10, 0x10, 0x85, 0x00, 0x00, 0x03, 0xe7, /*handle*/
            0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0xb2, 0x5d,
            0x00, 0x00, 0x00, 0x2a, 0x00, 0x0a, 0x00, 0x00,
            0x00, 0x00, 0xb2, 0x5a, 0x00, 0x00, 0x00, 0x29,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /*offset: (0)*/
            0x00, 0x00, 0x40, 0x00, /*count:*/
        ];

        let (_, expected_handle) = parse_nfs3_handle(&buf[..36]).unwrap();

        let (r, request) = parse_nfs3_request_commit(buf).unwrap();
        assert_eq!(r.len(), 0);
        assert_eq!(request.handle, expected_handle);
    }

    #[test]
    fn test_nfs3_request_read() {
        #[rustfmt::skip]
        let buf: &[u8] = &[
            0x00, 0x00, 0x00, 0x20, /*handle_len: (32)*/
            0x00, 0x10, 0x10, 0x85, 0x00, 0x00, 0x03, 0xe7, /*handle*/
            0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0xb2, 0x5d,
            0x00, 0x00, 0x00, 0x2a, 0x00, 0x0a, 0x00, 0x00,
            0x00, 0x00, 0xb2, 0x5a, 0x00, 0x00, 0x00, 0x29,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /*offset: (0)*/
            0x00, 0x00, 0x40, 0x00, /*_count*/
        ];

        let (_, expected_handle) = parse_nfs3_handle(&buf[..36]).unwrap();

        let (r, request) = parse_nfs3_request_read(buf).unwrap();
        assert_eq!(r.len(), 0);
        assert_eq!(request.handle, expected_handle);
        assert_eq!(request.offset, 0);
    }

    #[test]
    fn test_nfs3_request_lookup() {
        #[rustfmt::skip]
        let buf: &[u8] = &[
        // [handle]
            0x00, 0x00, 0x00, 0x20, /*handle_len: (32)*/
            0x00, 0x10, 0x10, 0x85, 0x00, 0x00, 0x03, 0xe7, /*handle*/
            0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0xb2, 0x5a,
            0x00, 0x00, 0x00, 0x29, 0x00, 0x0a, 0x00, 0x00,
            0x00, 0x00, 0xb2, 0x5a, 0x00, 0x00, 0x00, 0x29,
        // [name]
            0x00, 0x00, 0x00, 0x03, /*name_len: (3)*/
            0x62, 0x6c, 0x6e, /*name: (bln)*/
            0x00, /*_fill_bytes*/
        ];

        let (_, expected_handle) = parse_nfs3_handle(&buf[..36]).unwrap();

        let (r, request) = parse_nfs3_request_lookup(buf).unwrap();
        assert_eq!(r.len(), 0);
        assert_eq!(request.handle, expected_handle);
        assert_eq!(request.name_vec, br#"bln"#);
    }

    fn rdp_entry_buf(buf: &mut Vec<u8>, name: &[u8], fileid: u64, handle: &[u8]) {
        // entryplus3: fileid, name, cookie, post_op_attr, post_op_fh3
        buf.extend_from_slice(&fileid.to_be_bytes());
        buf.extend_from_slice(&(name.len() as u32).to_be_bytes());
        buf.extend_from_slice(name);
        buf.resize(buf.len() + (4 - name.len() % 4) % 4, 0);
        buf.extend_from_slice(&0x7c1b_c6afu64.to_be_bytes()); // cookie
        buf.extend_from_slice(&1u32.to_be_bytes()); // post_op_attr follows
        buf.extend_from_slice(&fattr3());
        buf.extend_from_slice(&1u32.to_be_bytes()); // namehandle follows
        buf.extend_from_slice(&(handle.len() as u32).to_be_bytes());
        buf.extend_from_slice(handle);
    }

    const RDP_HANDLE0: &[u8] = &[
        0x01, 0x00, 0x07, 0x01, 0x01, 0x00, 0xd4, 0x09, 0x00, 0x00, 0x00, 0x00, 0x5e, 0x85, 0xf3,
        0x66, 0x1a, 0x9d, 0xc3, 0x63, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x66, 0x0c, 0x4a, 0xff, 0x6b, 0x99,
    ];
    const RDP_HANDLE1: &[u8] = &[
        0x01, 0x00, 0x07, 0x01, 0x01, 0x00, 0xd4, 0x09, 0x00, 0x00, 0x00, 0x00, 0x5e, 0x85, 0xf3,
        0x66, 0x1a, 0x9d, 0xc3, 0x63, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00,
        0x66, 0x0c, 0x4c, 0xff, 0x6b, 0x99,
    ];

    fn rdp_reply_buf() -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&0u32.to_be_bytes()); // status OK
        buf.extend_from_slice(&1u32.to_be_bytes()); // dir_attr follows
        buf.extend_from_slice(&fattr3());
        buf.extend_from_slice(&[0u8; 8]); // cookieverf3
        let mut e0: Vec<u8> = Vec::new();
        rdp_entry_buf(&mut e0, b"..", 0x0c66_0001, RDP_HANDLE0);
        buf.extend_from_slice(&1u32.to_be_bytes()); // value_follows
        buf.extend_from_slice(&e0);
        let mut e1: Vec<u8> = Vec::new();
        rdp_entry_buf(&mut e1, b".", 0x0c66_0003, RDP_HANDLE1);
        buf.extend_from_slice(&1u32.to_be_bytes()); // value_follows
        buf.extend_from_slice(&e1);
        buf.extend_from_slice(&0u32.to_be_bytes()); // eof: value_follows = 0
        buf
    }

    #[test]
    fn test_nfs3_response_readdirplus() {
        let buf = rdp_reply_buf();
        let (r, resp) = parse_nfs3_response_readdirplus(&buf).unwrap();
        assert_eq!(r.len(), 0);
        assert_eq!(resp.status, 0);
        // dirlistplus3 starts at the first value_follows word
        let (r, entries) = many0_nfs3_response_readdirplus_entries(resp.data).unwrap();
        assert_eq!(r.len(), 0); // the eof tail is consumed
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name_vec, b".."[..].to_vec());
        assert_eq!(entries[0].handle.as_ref().unwrap().len, 36);
        assert_eq!(entries[1].name_vec, b"."[..].to_vec());
        assert_eq!(entries[1].handle.as_ref().unwrap().len, 36);

        // error replies carry only the status
        let err: &[u8] = &18u32.to_be_bytes(); // NFS3_ERR_STALE
        let (r, resp) = parse_nfs3_response_readdirplus(err).unwrap();
        assert_eq!(r.len(), 0);
        assert_eq!(resp.status, 18);
        assert!(resp.data.is_empty());
    }

    #[test]
    fn test_nfs3_response_readdirplus_malformed() {
        // entry chain truncated mid-entry: the many0 walk leaves the
        // spliced tail
        let buf = rdp_reply_buf();
        let short = &buf[..buf.len() - 50];
        let (_, resp) = parse_nfs3_response_readdirplus(short).unwrap();
        let (r, _) = many0_nfs3_response_readdirplus_entries(resp.data).unwrap();
        assert!(!r.is_empty());

        // fattr type out of range (the dir post_op_attr fattr starts at 8)
        let mut buf = rdp_reply_buf();
        buf[8..12].copy_from_slice(&8u32.to_be_bytes());
        assert!(parse_nfs3_response_readdirplus(&buf).is_err());

        // NF3FIFO (7) is a valid ftype3 and must not stop the walk
        let mut buf = rdp_reply_buf();
        buf[8..12].copy_from_slice(&7u32.to_be_bytes());
        assert!(parse_nfs3_response_readdirplus(&buf).is_ok());

        // entry name length beyond the nfsstring3 bound (the first entry's
        // name field: 100B header + 4B value_follows + 8B fileid)
        let mut buf = rdp_reply_buf();
        buf[112..116].copy_from_slice(&1025u32.to_be_bytes());
        let (_, resp) = parse_nfs3_response_readdirplus(&buf).unwrap();
        // many0 stops at the bad entry and leaves the remainder over
        let (r, entries) = many0_nfs3_response_readdirplus_entries(resp.data).unwrap();
        assert!(entries.is_empty());
        assert!(!r.is_empty());
    }

    #[test]
    fn test_nfs3_response_readdirplus_entry() {
        let mut buf: Vec<u8> = Vec::new();
        rdp_entry_buf(&mut buf, b".", 0x0c66_0003, RDP_HANDLE1);
        let (r, e) = parse_nfs3_response_readdirplus_entry(&buf).unwrap();
        assert_eq!(r.len(), 0);
        assert_eq!(e.name_vec, b".".to_vec());
        assert_eq!(e.handle.as_ref().unwrap().value, RDP_HANDLE1);

        // namehandle absent: the flag is zero and no handle follows
        let mut buf: Vec<u8> = Vec::new();
        rdp_entry_buf(&mut buf, b"file", 0x1234, RDP_HANDLE0);
        buf.truncate(buf.len() - 44); // drop flag + len + the 36B handle
        buf.extend_from_slice(&0u32.to_be_bytes()); // namehandle flag = 0
        let (r, e) = parse_nfs3_response_readdirplus_entry(&buf).unwrap();
        assert_eq!(r.len(), 0);
        assert!(e.handle.is_none());
    }

    #[test]
    fn test_nfs3_request_readdirplus() {
        #[rustfmt::skip]
        let buf: &[u8] = &[
            0x00, 0x00, 0x00, 0x24, /*handle_len*/
            0x01, 0x00, 0x07, 0x01, 0x01, 0x00, 0xd4, 0x09, /*handle*/
            0x00, 0x00, 0x00, 0x00, 0x5e, 0x85, 0xf3, 0x66,
            0x1a, 0x9d, 0xc3, 0x63, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x66, 0x0c,
            0x4c, 0xff, 0x6b, 0x99,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /*cookie*/
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /*verifier*/
            0x00, 0x00, 0x02, 0x00, /*dircount*/
            0x00, 0x00, 0x10, 0x00, /*maxcount*/
        ];

        let (_, expected_handle) = parse_nfs3_handle(&buf[..40]).unwrap();
        assert_eq!(expected_handle.len, 36);
        assert_eq!(expected_handle.value, &buf[4..40]);

        let (r, request) = parse_nfs3_request_readdirplus(buf).unwrap();
        assert_eq!(r.len(), 0);
        assert_eq!(request.handle, expected_handle);
        assert_eq!(request.cookie, 0);
        assert_eq!(request.verifier, "\0\0\0\0\0\0\0\0".as_bytes());
        assert_eq!(request.verifier.len(), 8);
        assert_eq!(request.dircount, 512);
        assert_eq!(request.maxcount, 4096);
    }

    #[test]
    fn test_nfs3_request_write() {
        #[rustfmt::skip]
        let buf: &[u8] = &[
        // [handle]
            0x00, 0x00, 0x00, 0x20, /*handle_len: (32)*/
            0x00, 0x10, 0x10, 0x85, 0x00, 0x00, 0x03, 0xe7, /*handle*/
            0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0xa6, 0x54,
            0x00, 0x00, 0x00, 0x1b, 0x00, 0x0a, 0x00, 0x00,
            0x00, 0x00, 0xb2, 0x5a, 0x00, 0x00, 0x00, 0x29,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /*offset: (0)*/
            0x00, 0x00, 0x00, 0x11, /*count: (17)*/
            0x00, 0x00, 0x00, 0x01, /*stable: <DATA_SYNC> (1)*/
        // [data]
            0x00, 0x00, 0x00, 0x11, /*file_len: (17)*/
            0x68, 0x61, 0x6c, 0x6c, 0x6f, 0x0a, 0x74, 0x68, /*file_data: ("hallo\nthe b file\n")*/
            0x65, 0x20, 0x62, 0x20, 0x66, 0x69, 0x6c, 0x65,
            0x0a,
            0x00, 0x00, 0x00, /*_data_padding*/
        ];

        let (_, expected_handle) = parse_nfs3_handle(&buf[..36]).unwrap();

        let (r, request) = parse_nfs3_request_write(buf, true).unwrap();
        assert_eq!(r.len(), 0);
        assert_eq!(request.handle, expected_handle);
        assert_eq!(request.offset, 0);
        assert_eq!(request.count, 17);
        assert_eq!(request.stable, 1);
        assert_eq!(request.file_len, 17);
        assert_eq!(request.file_data, "hallo\nthe b file\n".as_bytes());
    }

    #[test]
    fn test_nfs3_reply_read() {
        #[rustfmt::skip]
        let buf: &[u8] = &[
            0x00, 0x00, 0x00, 0x00, /*Status: NFS3_OK (0)*/
            0x00, 0x00, 0x00, 0x01, /*attributes_follows: (1)*/
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x81, 0xa4, /*attr_blob*/
            0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x10, 0x10, 0x85, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xb2, 0x5d, 0x38, 0x47, 0x76, 0x25,
            0x23, 0xc3, 0x46, 0x00, 0x38, 0x47, 0x71, 0xc4,
            0x21, 0xf9, 0x82, 0x80, 0x38, 0x47, 0x76, 0x25,
            0x1e, 0x65, 0xfb, 0x81,
            0x00, 0x00, 0x00, 0x0b, /*count: (11)*/
            0x00, 0x00, 0x00, 0x01, /*EOF: (true)*/
        // [data]
            0x00, 0x00, 0x00, 0x0b, /*data_len: (11)*/
            0x74, 0x68, 0x65, 0x20, 0x62, 0x20, 0x66, 0x69,
            0x6c, 0x65, 0x0a, /*data: ("the b file\n")*/
            0x00, /*_data_padding*/
        ];

        let (r, reply) = parse_nfs3_reply_read(buf, true).unwrap();
        assert_eq!(r.len(), 0);
        assert_eq!(reply.status, 0);
        assert_eq!(reply.attr_follows, 1);
        assert_eq!(reply.attr_blob.len(), 84);
        assert_eq!(reply.count, 11);
        assert!(reply.eof);
        assert_eq!(reply.data_len, 11);
        assert_eq!(reply.data, "the b file\n".as_bytes());
    }

    #[test]
    fn test_nfs3_request_readdir() {
        // fh 16B "01..10" + cookie 8 + verf 8 + maxcount 8192
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&12u32.to_be_bytes()); // fh len
        buf.extend(1..=12u8);
        buf.extend_from_slice(&16u64.to_be_bytes());
        buf.extend_from_slice(&[0u8; 8]);
        buf.extend_from_slice(&8192u32.to_be_bytes());

        let (r, req) = parse_nfs3_request_readdir(&buf).unwrap();
        assert_eq!(r.len(), 0);
        assert_eq!(req.cookie, 16);
        assert_eq!(req.maxcount, 8192);
        assert_eq!(req.handle.value.len(), 12);
    }

    fn readdir_entry(name: &str, cookie: u64, file_id: u64) -> Vec<u8> {
        // entry3 (rfc 1813 3.3.15): fileid, name, cookie. No attributes:
        // those are only in entryplus3.
        let mut e: Vec<u8> = Vec::new();
        e.extend_from_slice(&file_id.to_be_bytes());
        let nl = name.len() as u32;
        e.extend_from_slice(&nl.to_be_bytes());
        e.extend_from_slice(name.as_bytes());
        if nl % 4 != 0 {
            e.extend(std::iter::repeat_n(0u8, 4 - (nl % 4) as usize));
        }
        e.extend_from_slice(&cookie.to_be_bytes());
        e
    }

    /// end of a dirlist3: the null next-entry pointer, then eof
    fn dirlist_end(eof: bool) -> Vec<u8> {
        let mut v = 0u32.to_be_bytes().to_vec();
        v.extend_from_slice(&(eof as u32).to_be_bytes());
        v
    }

    #[test]
    fn test_nfs3_response_readdir() {
        let e1 = readdir_entry("a", 1, 100);
        let e2 = readdir_entry("b", 8, 200);
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&0u32.to_be_bytes()); // status
        buf.extend_from_slice(&1u32.to_be_bytes()); // dir_attr follows
        buf.extend_from_slice(&fattr3());
        buf.extend_from_slice(&[0u8; 8]); // cookieverf
        buf.extend_from_slice(&1u32.to_be_bytes()); // value_follows
        buf.extend_from_slice(&e1);
        buf.extend_from_slice(&1u32.to_be_bytes()); // value_follows
        buf.extend_from_slice(&e2);
        buf.extend_from_slice(&dirlist_end(false)); // next NULL + eof

        let (r, resp) = parse_nfs3_response_readdir(&buf).unwrap();
        assert_eq!(r.len(), 0);
        assert_eq!(resp.status, 0);
        let (_, entries) = many0_nfs3_response_readdir_entries(resp.data).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name_vec, b"a");
        assert_eq!(entries[0].cookie, 1);
        assert_eq!(entries[0].file_id, 100);
        assert_eq!(entries[1].name_vec, b"b");
    }

    #[test]
    fn test_nfs3_response_readdir_empty_and_malformed() {
        // empty list: eof right after the header
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.extend_from_slice(&fattr3());
        buf.extend_from_slice(&[0u8; 8]);
        buf.extend_from_slice(&dirlist_end(false)); // next NULL + eof
        let (_, resp) = parse_nfs3_response_readdir(&buf).unwrap();
        let (_, entries) = many0_nfs3_response_readdir_entries(resp.data).unwrap();
        assert!(entries.is_empty());

        // a spliced tail is left over: the walk stops early
        let mut e1 = readdir_entry("a", 1, 100);
        e1.truncate(e1.len() - 8); // cut the entry at its cookie
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.extend_from_slice(&fattr3());
        buf.extend_from_slice(&[0u8; 8]);
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.extend_from_slice(&e1);
        let (_, resp) = parse_nfs3_response_readdir(&buf).unwrap();
        let (r, _) = many0_nfs3_response_readdir_entries(resp.data).unwrap();
        assert!(!r.is_empty());
    }

    #[test]
    fn test_nfs3_request_setattr() {
        let mut buf: Vec<u8> = Vec::new();
        // fh 12B
        buf.extend_from_slice(&12u32.to_be_bytes());
        buf.extend(1..=12u8);
        // sattr3: mode/uid/gid/size set, atime SET_TO_CLIENT_TIME (2) with
        // the 8-byte nfstime3 client time, mtime SET_TO_SERVER_TIME (1)
        // without one, then the sattrguard3 guard (check = 0)
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.extend_from_slice(&0o100644u32.to_be_bytes());
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.extend_from_slice(&1000u32.to_be_bytes());
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.extend_from_slice(&1000u32.to_be_bytes());
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.extend_from_slice(&4096u64.to_be_bytes());
        buf.extend_from_slice(&2u32.to_be_bytes()); // atime: SET_TO_CLIENT_TIME
        buf.extend_from_slice(&944207371u32.to_be_bytes()); // atime sec
        buf.extend_from_slice(&520000000u32.to_be_bytes()); // atime nsec
        buf.extend_from_slice(&1u32.to_be_bytes()); // mtime: SET_TO_SERVER_TIME
        buf.extend_from_slice(&0u32.to_be_bytes()); // guard: no check

        let (r, req) = parse_nfs3_request_setattr(&buf).unwrap();
        assert_eq!(r.len(), 0);
        assert_eq!(req.attr.mode, Some(0o100644));
        assert_eq!(req.attr.uid, Some(1000));
        assert_eq!(req.attr.gid, Some(1000));
        assert_eq!(req.attr.size, Some(4096));
        assert_eq!(req.attr.atime, (2, Some((944207371, 520000000))));
        assert_eq!(req.attr.mtime, (1, None));
        assert_eq!(req.attr.guard, (false, None));
    }

    #[test]
    fn test_nfs3_response_setattr() {
        // wcc_data: pre_op_attr (set: wcc_attr = size + 2 nfstime3) +
        // post_op_attr (set: fattr3)
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&0u32.to_be_bytes()); // status
        buf.extend_from_slice(&1u32.to_be_bytes()); // wcc before: set
        buf.extend_from_slice(&4096u64.to_be_bytes()); // size (size3 = uint64)
        buf.extend_from_slice(&[3u8; 8]); // mtime nfstime3
        buf.extend_from_slice(&[4u8; 8]); // ctime nfstime3
        buf.extend_from_slice(&1u32.to_be_bytes()); // wcc after: set
        buf.extend_from_slice(&fattr3());

        let (r, resp) = parse_nfs3_response_setattr(&buf).unwrap();
        assert_eq!(r.len(), 0);
        assert_eq!(resp.status, 0);

        // error status: no wcc
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&1u32.to_be_bytes()); // status NFS3ERR_PERM
        let (r, resp) = parse_nfs3_response_setattr(&buf).unwrap();
        assert_eq!(r.len(), 0);
        assert_eq!(resp.status, 1);

        // wcc before absent: only the post_op_attr
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.extend_from_slice(&fattr3());
        let (r, resp) = parse_nfs3_response_setattr(&buf).unwrap();
        assert_eq!(r.len(), 0);
        assert_eq!(resp.status, 0);
    }

    #[test]
    fn test_nfs3_request_mknod() {
        let mut buf: Vec<u8> = Vec::new();
        // dirhandle (32 bytes)
        buf.extend_from_slice(&32u32.to_be_bytes());
        buf.extend_from_slice(&[
            0x00, 0x10, 0x10, 0x85, 0x00, 0x00, 0x03, 0xe7, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00,
            0xb2, 0x5a, 0x00, 0x00, 0x00, 0x29, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0xb2, 0x5a,
            0x00, 0x00, 0x00, 0x29,
        ]);
        // name (nfspath3): count=1, "m", 3 pad bytes
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.extend_from_slice(b"m");
        buf.extend_from_slice(&[0u8; 3]); // pad
                                          // sattr3 + specdata3 (not logged, just present)
        buf.extend_from_slice(&[0u8; 48]);

        let (r, req) = parse_nfs3_request_mknod(&buf).unwrap();
        assert_eq!(r.len(), 0);
        assert_eq!(req.handle.len, 32);
        assert_eq!(req.name_vec, b"m".to_vec());
    }

    #[test]
    fn test_nfs3_request_link() {
        let mut buf: Vec<u8> = Vec::new();
        // file handle (32 bytes)
        buf.extend_from_slice(&32u32.to_be_bytes());
        buf.extend_from_slice(&[
            0x00, 0x10, 0x10, 0x85, 0x00, 0x00, 0x03, 0xe7, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00,
            0xb2, 0x5a, 0x00, 0x00, 0x00, 0x29, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0xb2, 0x5a,
            0x00, 0x00, 0x00, 0x29,
        ]);
        // linkdir handle (32 bytes)
        buf.extend_from_slice(&32u32.to_be_bytes());
        buf.extend_from_slice(&[
            0x00, 0x20, 0x20, 0x95, 0x00, 0x00, 0x04, 0xf7, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00,
            0xc2, 0x6a, 0x00, 0x00, 0x00, 0x39, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0xc2, 0x6a,
            0x00, 0x00, 0x00, 0x39,
        ]);
        // diropargs3 link.name: "bln", 1 pad byte (4-byte aligned)
        buf.extend_from_slice(&3u32.to_be_bytes());
        buf.extend_from_slice(b"bln");
        buf.extend_from_slice(&[0u8; 1]);

        let (r, req) = parse_nfs3_request_link(&buf).unwrap();
        assert_eq!(r.len(), 0);
        assert_eq!(req.handle.len, 32);
        assert_eq!(req.linkdir.len, 32);
        assert_ne!(req.handle.value, req.linkdir.value);
        assert_eq!(req.linkname, b"bln".to_vec());
    }

    fn symlink_dir_handle(buf: &mut Vec<u8>) {
        buf.extend_from_slice(&32u32.to_be_bytes());
        buf.extend_from_slice(&[
            0x00, 0x10, 0x10, 0x85, 0x00, 0x00, 0x03, 0xe7, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00,
            0xb2, 0x5a, 0x00, 0x00, 0x00, 0x29, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0xb2, 0x5a,
            0x00, 0x00, 0x00, 0x29,
        ]);
    }

    #[test]
    fn test_nfs3_request_symlink() {
        // SYMLINK3args (RFC 1813 3.3.10): diropargs3 where (dir + name) +
        // symlinkdata3 (sattr3 + nfspath3 target), all attrs unset
        let mut buf: Vec<u8> = Vec::new();
        symlink_dir_handle(&mut buf);
        // where.name: "blns"
        buf.extend_from_slice(&4u32.to_be_bytes());
        buf.extend_from_slice(b"blns");
        // sattr3: everything unset (mode/uid/gid/size = 0, atime/mtime = 0)
        buf.extend(std::iter::repeat_n(0u8, 24)); // six unset words
                                                  // symlink_data (target path): "/tmp/target", 1 pad byte
        buf.extend_from_slice(&11u32.to_be_bytes());
        buf.extend_from_slice(b"/tmp/target");
        buf.extend_from_slice(&[0u8; 1]);

        let (r, req) = parse_nfs3_request_symlink(&buf).unwrap();
        assert_eq!(r.len(), 0);
        assert_eq!(req.handle.len, 32);
        assert_eq!(req.name_vec, b"blns".to_vec());
        assert_eq!(req.target_path, b"/tmp/target".to_vec());
    }

    #[test]
    fn test_nfs3_request_symlink_attrs_set() {
        // same layout with a mode set in the symlink_attributes sattr3
        let mut buf: Vec<u8> = Vec::new();
        symlink_dir_handle(&mut buf);
        buf.extend_from_slice(&4u32.to_be_bytes());
        buf.extend_from_slice(b"blns");
        // sattr3: mode set, rest unset
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.extend_from_slice(&0o777u32.to_be_bytes());
        buf.extend(std::iter::repeat_n(0u8, 20)); // five unset words
        buf.extend_from_slice(&3u32.to_be_bytes());
        buf.extend_from_slice(b"abc");
        buf.extend_from_slice(&[0u8; 1]);

        let (r, req) = parse_nfs3_request_symlink(&buf).unwrap();
        assert_eq!(r.len(), 0);
        assert_eq!(req.name_vec, b"blns".to_vec());
        assert_eq!(req.target_path, b"abc".to_vec());
    }

    #[test]
    fn test_nfs3_request_symlink_malformed() {
        // truncated record
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&32u32.to_be_bytes());
        buf.extend_from_slice(&[0u8; 32]);
        buf.extend_from_slice(&16u32.to_be_bytes());
        assert!(parse_nfs3_request_symlink(&buf).is_err());

        // a name that looks like a handle (NULs): parsed as the name,
        // then the record runs out inside the sattr3 -> rejected
        let mut buf: Vec<u8> = Vec::new();
        symlink_dir_handle(&mut buf);
        buf.extend_from_slice(&4u32.to_be_bytes());
        buf.extend_from_slice(&[0x00, 0x10, 0x10, 0x85]);
        buf.extend_from_slice(&4u32.to_be_bytes());
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        assert!(parse_nfs3_request_symlink(&buf).is_err());

        // overlong handle: parsed, the record then runs out in the
        // sattr3/target -> rejected
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&65u32.to_be_bytes());
        buf.extend_from_slice(&[0u8; 65]);
        assert!(parse_nfs3_request_symlink(&buf).is_err());
    }
}
