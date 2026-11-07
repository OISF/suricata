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
use nom7::error::{make_error, ErrorKind};
use nom7::multi::{length_data, many0};
use nom7::number::streaming::{be_u32, be_u64};
use nom7::{Err, IResult};
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
    let (i, ftype) = verify(be_u32, |&v| v <= 6)(i)?;
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
    pub handle: Option<Nfs3Handle<'a>>,
}

pub fn parse_nfs3_response_readdirplus_entry(
    i: &[u8],
) -> IResult<&[u8], Nfs3ResponseReaddirplusEntryC<'_>> {
    let (i, _file_id) = be_u64(i)?;
    let (i, name_len) = be_u32(i)?;
    let (i, name_contents) = take(name_len as usize)(i)?;
    let (i, _fill_bytes) = cond(name_len % 4 != 0, take(4 - (name_len % 4)))(i)?;
    let (i, _cookie) = take(8_usize)(i)?;
    let (i, attr_value_follows) = verify(be_u32, |&v| v <= 1)(i)?;
    let (i, _attr) = cond(attr_value_follows == 1, take(84_usize))(i)?;
    let (i, handle_value_follows) = verify(be_u32, |&v| v <= 1)(i)?;
    let (i, handle) = cond(handle_value_follows == 1, parse_nfs3_handle)(i)?;
    let resp = Nfs3ResponseReaddirplusEntryC {
        name_vec: name_contents.to_vec(),
        handle,
    };
    Ok((i, resp))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Nfs3ResponseReaddirplusEntry<'a> {
    pub entry: Option<Nfs3ResponseReaddirplusEntryC<'a>>,
}

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
    pub data: &'a [u8],
}

pub fn parse_nfs3_response_readdirplus(i: &[u8]) -> IResult<&[u8], Nfs3ResponseReaddirplus<'_>> {
    let (i, status) = be_u32(i)?;
    let (i, dir_attr_follows) = verify(be_u32, |&v| v <= 1)(i)?;
    let (i, _dir_attr) = cond(dir_attr_follows == 1, take(84_usize))(i)?;
    let (i, _verifier) = be_u64(i)?;
    let (i, data) = rest(i)?;
    let resp = Nfs3ResponseReaddirplus { status, data };
    Ok((i, resp))
}

pub(crate) fn many0_nfs3_response_readdirplus_entries(
    input: &[u8],
) -> IResult<&[u8], Vec<Nfs3ResponseReaddirplusEntry<'_>>> {
    many0(complete(parse_nfs3_response_readdirplus_entry_cond))(input)
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

/// entry3 (RFC 1813 3.3.15): fileid, name, cookie, post_op_attr.
pub fn parse_nfs3_response_readdir_entry(i: &[u8]) -> IResult<&[u8], Nfs3ResponseReaddirEntry> {
    let (i, file_id) = be_u64(i)?;
    let (i, name_len) = verify(be_u32, |&v| v <= 1024)(i)?;
    let (i, name_contents) = take(name_len as usize)(i)?;
    let (i, _fill_bytes) = cond(name_len % 4 != 0, take(4 - (name_len % 4)))(i)?;
    let (i, cookie) = be_u64(i)?;
    let (i, _) = parse_nfs3_post_op_attr(i)?;
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

// RFC 1813 15.13: sattr3 -- each field is a follows-flag-optional value
#[derive(Debug, PartialEq, Eq)]
pub struct Nfs3SetAttr {
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub size: Option<u64>,
    pub mtime: Option<(u64, u32)>,
    pub atime: Option<(u64, u32)>,
    pub ctime: u32,
}

fn parse_nfs3_somtime(i: &[u8]) -> IResult<&[u8], (u64, u32)> {
    let (i, sec) = be_u64(i)?;
    let (i, nsec) = be_u32(i)?;
    Ok((i, (sec, nsec)))
}

fn parse_nfs3_verf3(i: &[u8]) -> IResult<&[u8], &[u8]> {
    // opaque<16>: length-prefixed, padded to 4 bytes
    let (i, len) = verify(be_u32, |&v| v <= 16)(i)?;
    let (i, data) = take(len as usize)(i)?;
    let (i, _fill) = cond(len % 4 != 0, take(4 - (len % 4)))(i)?;
    Ok((i, data))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Nfs3RequestSetattr<'a> {
    pub handle: Nfs3Handle<'a>,
    pub attr: Nfs3SetAttr,
}

pub fn parse_nfs3_request_setattr(i: &[u8]) -> IResult<&[u8], Nfs3RequestSetattr<'_>> {
    let (i, handle) = parse_nfs3_handle(i)?;
    let (i, f) = verify(be_u32, |&v| v <= 1)(i)?;
    let (i, mode) = cond(f == 1, be_u32)(i)?;
    let (i, f) = verify(be_u32, |&v| v <= 1)(i)?;
    let (i, uid) = cond(f == 1, be_u32)(i)?;
    let (i, f) = verify(be_u32, |&v| v <= 1)(i)?;
    let (i, gid) = cond(f == 1, be_u32)(i)?;
    let (i, f) = verify(be_u32, |&v| v <= 1)(i)?;
    let (i, size) = cond(f == 1, be_u64)(i)?;
    let (i, f) = verify(be_u32, |&v| v <= 1)(i)?;
    let (i, mtime) = cond(f == 1, parse_nfs3_somtime)(i)?;
    let (i, f) = verify(be_u32, |&v| v <= 1)(i)?;
    let (i, atime) = cond(f == 1, parse_nfs3_somtime)(i)?;
    // ctimehow: SET_DONT (0) or SET_SERVER (1) in the XDR sense; the
    // wire allows 0..=1, but accept the documented ctimehow range
    let (i, ctime) = verify(be_u32, |&v| v <= 2)(i)?;
    let attr = Nfs3SetAttr {
        mode,
        uid,
        gid,
        size,
        mtime,
        atime,
        ctime,
    };
    let req = Nfs3RequestSetattr { handle, attr };
    Ok((i, req))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Nfs3ResponseSetattr<'a> {
    pub status: u32,
    pub wcc_before_verf: Option<&'a [u8]>,
    pub wcc_after_verf: Option<&'a [u8]>,
}

// RFC 1813 3.5.5: wcc_data { before: weak_callback; after: weak_callback }
pub fn parse_nfs3_response_setattr(i: &[u8]) -> IResult<&[u8], Nfs3ResponseSetattr<'_>> {
    let (i, status) = be_u32(i)?;
    let (i, f) = verify(be_u32, |&v| v <= 1)(i)?;
    let (i, wcc_before_verf) = cond(f == 1, parse_nfs3_verf3)(i)?;
    let (i, f) = verify(be_u32, |&v| v <= 1)(i)?;
    let (i, wcc_after_verf) = cond(f == 1, parse_nfs3_verf3)(i)?;
    let resp = Nfs3ResponseSetattr {
        status,
        wcc_before_verf,
        wcc_after_verf,
    };
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
fn parse_nfs3_data_complete(i: &[u8], file_len: usize, fill_bytes: usize) -> IResult<&[u8], &[u8]> {
    let (i, file_data) = take(file_len)(i)?;
    let (i, _) = cond(fill_bytes > 0, take(fill_bytes))(i)?;
    Ok((i, file_data))
}

/// Partial data. We have all file_len, but need to consider fill_bytes
fn parse_nfs3_data_partial(i: &[u8], file_len: usize, fill_bytes: usize) -> IResult<&[u8], &[u8]> {
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
    /// maximum size for writes (wtmax) that the server supports
    pub wtm: u32,
    /// recommended size for writes
    pub wtpref: u32,
    /// preferred transfer size for directory operations
    pub dtpref: u32,
    /// no-vec memory size
    pub nvmem: u32,
    /// maximum number of bytes per READDIR/READDIRPLUS
    pub maxcount: u32,
}

pub fn parse_nfs3_response_fsinfo(i: &[u8]) -> IResult<&[u8], Nfs3Fsinfores> {
    let (i, status) = be_u32(i)?;
    if status == 0 {
        // nfs3_fsinforesok: tsz rtm rtpref wtm wtpref dtpref nvmem maxcount
        let (i, _tsz) = be_u32(i)?;
        let (i, rtm) = be_u32(i)?;
        let (i, rtpref) = be_u32(i)?;
        let (i, wtm) = be_u32(i)?;
        let (i, wtpref) = be_u32(i)?;
        let (i, dtpref) = be_u32(i)?;
        let (i, nvmem) = be_u32(i)?;
        let (i, maxcount) = be_u32(i)?;
        Ok((
            i,
            Nfs3Fsinfores {
                status,
                rtm,
                rtpref,
                wtm,
                wtpref,
                dtpref,
                nvmem,
                maxcount,
            },
        ))
    } else {
        Ok((
            i,
            Nfs3Fsinfores {
                status,
                rtm: 0,
                rtpref: 0,
                wtm: 0,
                wtpref: 0,
                dtpref: 0,
                nvmem: 0,
                maxcount: 0,
            },
        ))
    }
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
        #[rustfmt::skip]
        let buf: &[u8] = &[
            0x00, 0x00, 0x00, 0x00, /*status: NFS3_OK (0)*/
            0x00, 0x00, 0x00, 0x20, /*tsz: 32*/
            0x00, 0x01, 0x00, 0x00, /*rtm (rtmax): 65536*/
            0x00, 0x00, 0x04, 0x00, /*rtpref: 1024*/
            0x00, 0x01, 0x00, 0x00, /*wtm (wtmax): 65536*/
            0x00, 0x00, 0x04, 0x00, /*wtpref: 1024*/
            0x00, 0x00, 0x04, 0x00, /*dtpref: 1024*/
            0x00, 0x00, 0x08, 0x00, /*nvmem: 2048*/
            0x00, 0x01, 0x00, 0x00, /*maxcount: 65536*/
            0x00, /*streaming be_u32 lookahead guard*/
        ];
        let (_, response) = parse_nfs3_response_fsinfo(buf).unwrap();
        assert_eq!(response.status, 0);
        assert_eq!(response.rtm, 65536);
        assert_eq!(response.rtpref, 1024);
        assert_eq!(response.wtm, 65536);
        assert_eq!(response.wtpref, 1024);
        assert_eq!(response.dtpref, 1024);
        assert_eq!(response.nvmem, 2048);
        assert_eq!(response.maxcount, 65536);

        // error status: no resok fields present
        let errbuf: &[u8] = &[0x00, 0x00, 0x00, 0x05 /*status: NFS3ERR_IO (5)*/];
        let (_, expected) = parse_nfs3_response_fsinfo(errbuf).unwrap();
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

    #[test]
    fn test_nfs3_response_readdirplus() {
        #[rustfmt::skip]
        let buf: &[u8] = &[
            0x00, 0x00, 0x00, 0x00, /*status*/
            0x00, 0x00, 0x00, 0x01, /*dir_attr_follows*/
            0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x41, 0xc0, /*_dir_attr*/
            0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x03, 0xe8,
            0x00, 0x00, 0x03, 0xe8, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x63, 0xc3, 0x9d, 0x1a,
            0x66, 0xf3, 0x85, 0x5e, 0x00, 0x00, 0x00, 0x00,
            0x0c, 0x66, 0x00, 0x03, 0x59, 0x39, 0x5a, 0x3a,
            0x18, 0x13, 0x9c, 0xb2, 0x55, 0xe1, 0x59, 0xd4,
            0x0e, 0xa0, 0xc0, 0x41, 0x55, 0xe1, 0x59, 0xd4,
            0x0e, 0xa0, 0xc0, 0x41,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /*_verifier*/
        // [data]
            0x00, 0x00, 0x00, 0x01, /*value_follows*/
            0x00, 0x00, 0x00, 0x00, 0x0c, 0x66, 0x00, 0x01, /*entry0*/
            0x00, 0x00, 0x00, 0x02, 0x2e, 0x2e, 0x00, 0x00, /*name_contents: \2e\2e */
            0x00, 0x00, 0x00, 0x00, 0x7c, 0x1b, 0xc6, 0xaf,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02,
            0x00, 0x00, 0x41, 0xc0, 0x00, 0x00, 0x00, 0x05,
            0x00, 0x00, 0x03, 0xe8, 0x00, 0x00, 0x03, 0xe8,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x63, 0xc3, 0x9d, 0x1a, 0x66, 0xf3, 0x85, 0x5e,
            0x00, 0x00, 0x00, 0x00, 0x0c, 0x66, 0x00, 0x01,
            0x59, 0x38, 0xa1, 0xa1, 0x04, 0x29, 0xd9, 0x59,
            0x4e, 0xbf, 0xf1, 0x51, 0x09, 0x2c, 0xa1, 0xda,
            0x4e, 0xbf, 0xf1, 0x51, 0x09, 0x2c, 0xa1, 0xda,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x24,
            0x01, 0x00, 0x07, 0x01, 0x01, 0x00, 0xd4, 0x09, /*handle*/
            0x00, 0x00, 0x00, 0x00, 0x5e, 0x85, 0xf3, 0x66,
            0x1a, 0x9d, 0xc3, 0x63, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x66, 0x0c,
            0x4a, 0xff, 0x6b, 0x99,
            0x00, 0x00, 0x00, 0x01, /*value_follows*/
            0x00, 0x00, 0x00, 0x00, 0x0c, 0x66, 0x00, 0x03, /*entry1*/
            0x00, 0x00, 0x00, 0x01, 0x2e, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02,
            0x00, 0x00, 0x41, 0xc0, 0x00, 0x00, 0x00, 0x02,
            0x00, 0x00, 0x03, 0xe8, 0x00, 0x00, 0x03, 0xe8,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x63, 0xc3, 0x9d, 0x1a, 0x66, 0xf3, 0x85, 0x5e,
            0x00, 0x00, 0x00, 0x00, 0x0c, 0x66, 0x00, 0x03,
            0x59, 0x39, 0x5a, 0x3a, 0x18, 0x13, 0x9c, 0xb2,
            0x55, 0xe1, 0x59, 0xd4, 0x0e, 0xa0, 0xc0, 0x41,
            0x55, 0xe1, 0x59, 0xd4, 0x0e, 0xa0, 0xc0, 0x41,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x24,
            0x01, 0x00, 0x07, 0x01, 0x01, 0x00, 0xd4, 0x09, /*handle*/
            0x00, 0x00, 0x00, 0x00, 0x5e, 0x85, 0xf3, 0x66,
            0x1a, 0x9d, 0xc3, 0x63, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x66, 0x0c,
            0x4c, 0xff, 0x6b, 0x99, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01,
        ];

        let data_buf = &buf[100..];

        let (_, response) = parse_nfs3_response_readdirplus(buf).unwrap();
        assert_eq!(response.status, 0);
        assert_eq!(response.data, data_buf);

        // test for multiple entries
        let entry0_buf = &data_buf[4..160];
        let entry1_buf = &data_buf[164..320];

        let (_, entry0) = parse_nfs3_response_readdirplus_entry(entry0_buf).unwrap();
        let (_, entry1) = parse_nfs3_response_readdirplus_entry(entry1_buf).unwrap();

        let (r, entries) = many0_nfs3_response_readdirplus_entries(data_buf).unwrap();
        assert_eq!(r.len(), 4);
        assert_eq!(
            entries[0],
            Nfs3ResponseReaddirplusEntry {
                entry: Some(entry0)
            }
        );
        assert_eq!(
            entries[1],
            Nfs3ResponseReaddirplusEntry {
                entry: Some(entry1)
            }
        );
    }

    #[test]
    fn test_nfs3_response_readdirplus_entry() {
        #[rustfmt::skip]
        let buf: &[u8] = &[
            0x00, 0x00, 0x00, 0x01, /*value_follows*/
            0x00, 0x00, 0x00, 0x00, 0x0c, 0x66, 0x00, 0x03, /*entry*/
            0x00, 0x00, 0x00, 0x01, 0x2e, 0x00, 0x00, 0x00, /*name_contents: 2e*/
            0x00, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02,
            0x00, 0x00, 0x41, 0xc0, 0x00, 0x00, 0x00, 0x02,
            0x00, 0x00, 0x03, 0xe8, 0x00, 0x00, 0x03, 0xe8,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x63, 0xc3, 0x9d, 0x1a, 0x66, 0xf3, 0x85, 0x5e,
            0x00, 0x00, 0x00, 0x00, 0x0c, 0x66, 0x00, 0x03,
            0x59, 0x39, 0x5a, 0x3a, 0x18, 0x13, 0x9c, 0xb2,
            0x55, 0xe1, 0x59, 0xd4, 0x0e, 0xa0, 0xc0, 0x41,
            0x55, 0xe1, 0x59, 0xd4, 0x0e, 0xa0, 0xc0, 0x41,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x24,
            0x01, 0x00, 0x07, 0x01, 0x01, 0x00, 0xd4, 0x09, /*handle*/
            0x00, 0x00, 0x00, 0x00, 0x5e, 0x85, 0xf3, 0x66,
            0x1a, 0x9d, 0xc3, 0x63, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x66, 0x0c,
            0x4c, 0xff, 0x6b, 0x99,
        ];

        let (_, entry_handle) = parse_nfs3_handle(&buf[120..]).unwrap();
        assert_eq!(entry_handle.len, 36);
        assert_eq!(entry_handle.value, &buf[124..]);

        let (_, response) = parse_nfs3_response_readdirplus_entry_cond(buf).unwrap();
        match response {
            Nfs3ResponseReaddirplusEntry {
                entry: Some(entry_c),
            } => {
                assert_eq!(entry_c.name_vec, ".".as_bytes());
                assert_eq!(entry_c.handle, Some(entry_handle));
            }
            _ => {
                panic!("Failure");
            }
        }
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
        // entry3 (rfc 1813): fileid, name, cookie, post_op_attr
        let mut e: Vec<u8> = Vec::new();
        e.extend_from_slice(&file_id.to_be_bytes());
        let nl = name.len() as u32;
        e.extend_from_slice(&nl.to_be_bytes());
        e.extend_from_slice(name.as_bytes());
        if nl % 4 != 0 {
            e.extend(std::iter::repeat_n(0u8, 4 - (nl % 4) as usize));
        }
        e.extend_from_slice(&cookie.to_be_bytes());
        e.extend_from_slice(&1u32.to_be_bytes()); // post_op_attr follows
        e.extend_from_slice(&fattr3());
        e
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
        buf.extend_from_slice(&0u32.to_be_bytes()); // eof

        let (r, resp) = parse_nfs3_response_readdir(&buf).unwrap();
        assert_eq!(r.len(), 0);
        assert_eq!(resp.status, 0);
        let (r, entries) = many0_nfs3_response_readdir_entries(resp.data).unwrap();
        assert_eq!(r.len(), 0);
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
        buf.extend_from_slice(&0u32.to_be_bytes()); // eof
        let (_, resp) = parse_nfs3_response_readdir(&buf).unwrap();
        let (r, entries) = many0_nfs3_response_readdir_entries(resp.data).unwrap();
        assert_eq!(r.len(), 0);
        assert!(entries.is_empty());

        // a spliced tail is left over: the walk stops early
        let e1 = readdir_entry("a", 1, 100);
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.extend_from_slice(&fattr3());
        buf.extend_from_slice(&[0u8; 8]);
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.extend_from_slice(&e1);
        buf.truncate(buf.len() - 44); // cut the entry mid-fattr
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
        // sattr3: mode set, uid set, gid set, size set, times unset,
        // ctime SET_DONT (0)
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.extend_from_slice(&0o100644u32.to_be_bytes());
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.extend_from_slice(&1000u32.to_be_bytes());
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.extend_from_slice(&1000u32.to_be_bytes());
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.extend_from_slice(&4096u64.to_be_bytes());
        buf.extend_from_slice(&0u32.to_be_bytes()); // mtime: not set
        buf.extend_from_slice(&0u32.to_be_bytes()); // atime: not set
        buf.extend_from_slice(&0u32.to_be_bytes()); // ctime: SET_DONT

        let (r, req) = parse_nfs3_request_setattr(&buf).unwrap();
        assert_eq!(r.len(), 0);
        assert_eq!(req.attr.mode, Some(0o100644));
        assert_eq!(req.attr.uid, Some(1000));
        assert_eq!(req.attr.gid, Some(1000));
        assert_eq!(req.attr.size, Some(4096));
        assert_eq!(req.attr.mtime, None);
        assert_eq!(req.attr.atime, None);
        assert_eq!(req.attr.ctime, 0);
    }

    #[test]
    fn test_nfs3_response_setattr() {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&0u32.to_be_bytes()); // status
                                                    // wcc before: set, 8-byte verf
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.extend_from_slice(&8u32.to_be_bytes());
        buf.extend_from_slice(&[1u8; 8]);
        // wcc after: set, 10-byte verf (needs 2B padding)
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.extend_from_slice(&10u32.to_be_bytes());
        buf.extend_from_slice(&[2u8; 10]);
        buf.extend_from_slice(&[0u8; 2]);

        let (r, resp) = parse_nfs3_response_setattr(&buf).unwrap();
        assert_eq!(r.len(), 0);
        assert_eq!(resp.status, 0);
        assert_eq!(resp.wcc_before_verf, Some(&[1u8; 8][..]));
        assert_eq!(resp.wcc_after_verf, Some(&[2u8; 10][..]));

        // both wcc absent, error status
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&1u32.to_be_bytes()); // status NFS3ERR_PERM
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf.extend_from_slice(&0u32.to_be_bytes());
        let (_, resp) = parse_nfs3_response_setattr(&buf).unwrap();
        assert_eq!(resp.status, 1);
        assert_eq!(resp.wcc_before_verf, None);
        assert_eq!(resp.wcc_after_verf, None);
    }
}
