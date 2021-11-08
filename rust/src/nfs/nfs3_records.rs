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

//! Nom parsers for RPC & NFSv3

use crate::nfs::nfs_records::*;
use nom7::bytes::streaming::take;
use nom7::combinator::{complete, cond, rest};
use nom7::multi::{length_data, many0};
use nom7::number::streaming::{be_u32, be_u64};
use nom7::IResult;

#[derive(Debug, PartialEq)]
pub struct Nfs3Handle<'a> {
    pub len: u32,
    pub value: &'a [u8],
}

pub fn parse_nfs3_handle(i: &[u8]) -> IResult<&[u8], Nfs3Handle> {
    let (i, len) = be_u32(i)?;
    let (i, value) = take(len as usize)(i)?;
    let handle = Nfs3Handle { len, value };
    Ok((i, handle))
}

#[derive(Debug, PartialEq)]
pub struct Nfs3ReplyCreate<'a> {
    pub status: u32,
    pub handle: Option<Nfs3Handle<'a>>,
}

pub fn parse_nfs3_response_create(i: &[u8]) -> IResult<&[u8], Nfs3ReplyCreate> {
    let (i, status) = be_u32(i)?;
    let (i, handle_has_value) = be_u32(i)?;
    let (i, handle) = cond(handle_has_value == 1, parse_nfs3_handle)(i)?;
    let reply = Nfs3ReplyCreate { status, handle };
    Ok((i, reply))
}

#[derive(Debug, PartialEq)]
pub struct Nfs3ReplyLookup<'a> {
    pub status: u32,
    pub handle: Nfs3Handle<'a>,
}

pub fn parse_nfs3_response_lookup(i: &[u8]) -> IResult<&[u8], Nfs3ReplyLookup> {
    let (i, status) = be_u32(i)?;
    let (i, handle) = parse_nfs3_handle(i)?;
    let reply = Nfs3ReplyLookup { status, handle };
    Ok((i, reply))
}

#[derive(Debug, PartialEq)]
pub struct Nfs3RequestCreate<'a> {
    pub handle: Nfs3Handle<'a>,
    pub name_len: u32,
    pub create_mode: u32,
    pub verifier: &'a [u8],
    pub name_vec: Vec<u8>,
}

pub fn parse_nfs3_request_create(i: &[u8]) -> IResult<&[u8], Nfs3RequestCreate> {
    let (i, handle) = parse_nfs3_handle(i)?;
    let (i, name_len) = be_u32(i)?;
    let (i, name) = take(name_len as usize)(i)?;
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

#[derive(Debug, PartialEq)]
pub struct Nfs3RequestRemove<'a> {
    pub handle: Nfs3Handle<'a>,
    pub name_len: u32,
    pub name_vec: Vec<u8>,
}

pub fn parse_nfs3_request_remove(i: &[u8]) -> IResult<&[u8], Nfs3RequestRemove> {
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

#[derive(Debug, PartialEq)]
pub struct Nfs3RequestRmdir<'a> {
    pub handle: Nfs3Handle<'a>,
    pub name_vec: Vec<u8>,
}

pub fn parse_nfs3_request_rmdir(i: &[u8]) -> IResult<&[u8], Nfs3RequestRmdir> {
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

#[derive(Debug, PartialEq)]
pub struct Nfs3RequestMkdir<'a> {
    pub handle: Nfs3Handle<'a>,
    pub name_vec: Vec<u8>,
}

pub fn parse_nfs3_request_mkdir(i: &[u8]) -> IResult<&[u8], Nfs3RequestMkdir> {
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

#[derive(Debug, PartialEq)]
pub struct Nfs3RequestRename<'a> {
    pub from_handle: Nfs3Handle<'a>,
    pub from_name_vec: Vec<u8>,
    pub to_handle: Nfs3Handle<'a>,
    pub to_name_vec: Vec<u8>,
}

pub fn parse_nfs3_request_rename(i: &[u8]) -> IResult<&[u8], Nfs3RequestRename> {
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

#[derive(Debug, PartialEq)]
pub struct Nfs3RequestGetAttr<'a> {
    pub handle: Nfs3Handle<'a>,
}

pub fn parse_nfs3_request_getattr(i: &[u8]) -> IResult<&[u8], Nfs3RequestGetAttr> {
    let (i, handle) = parse_nfs3_handle(i)?;
    Ok((i, Nfs3RequestGetAttr { handle }))
}

#[derive(Debug, PartialEq)]
pub struct Nfs3RequestAccess<'a> {
    pub handle: Nfs3Handle<'a>,
    pub check_access: u32,
}

pub fn parse_nfs3_request_access(i: &[u8]) -> IResult<&[u8], Nfs3RequestAccess> {
    let (i, handle) = parse_nfs3_handle(i)?;
    let (i, check_access) = be_u32(i)?;
    let req = Nfs3RequestAccess {
        handle,
        check_access,
    };
    Ok((i, req))
}

#[derive(Debug, PartialEq)]
pub struct Nfs3RequestCommit<'a> {
    pub handle: Nfs3Handle<'a>,
}

pub fn parse_nfs3_request_commit(i: &[u8]) -> IResult<&[u8], Nfs3RequestCommit> {
    let (i, handle) = parse_nfs3_handle(i)?;
    let (i, _offset) = be_u64(i)?;
    let (i, _count) = be_u32(i)?;
    Ok((i, Nfs3RequestCommit { handle }))
}

#[derive(Debug, PartialEq)]
pub struct Nfs3RequestRead<'a> {
    pub handle: Nfs3Handle<'a>,
    pub offset: u64,
}

pub fn parse_nfs3_request_read(i: &[u8]) -> IResult<&[u8], Nfs3RequestRead> {
    let (i, handle) = parse_nfs3_handle(i)?;
    let (i, offset) = be_u64(i)?;
    let (i, _count) = be_u32(i)?;
    Ok((i, Nfs3RequestRead { handle, offset }))
}

#[derive(Debug, PartialEq)]
pub struct Nfs3RequestLookup<'a> {
    pub handle: Nfs3Handle<'a>,

    pub name_vec: Vec<u8>,
}

pub fn parse_nfs3_request_lookup(i: &[u8]) -> IResult<&[u8], Nfs3RequestLookup> {
    let (i, handle) = parse_nfs3_handle(i)?;
    let (i, name_contents) = length_data(be_u32)(i)?;
    let (i, _name_padding) = rest(i)?;
    let req = Nfs3RequestLookup {
        handle,
        name_vec: name_contents.to_vec(),
    };
    Ok((i, req))
}

#[derive(Debug, PartialEq)]
pub struct Nfs3ResponseReaddirplusEntryC<'a> {
    pub name_vec: Vec<u8>,
    pub handle: Option<Nfs3Handle<'a>>,
}

pub fn parse_nfs3_response_readdirplus_entry(
    i: &[u8],
) -> IResult<&[u8], Nfs3ResponseReaddirplusEntryC> {
    let (i, _file_id) = be_u64(i)?;
    let (i, name_len) = be_u32(i)?;
    let (i, name_contents) = take(name_len as usize)(i)?;
    let (i, _fill_bytes) = cond(name_len % 4 != 0, take(4 - (name_len % 4)))(i)?;
    let (i, _cookie) = take(8_usize)(i)?;
    let (i, attr_value_follows) = be_u32(i)?;
    let (i, _attr) = cond(attr_value_follows == 1, take(84_usize))(i)?;
    let (i, handle_value_follows) = be_u32(i)?;
    let (i, handle) = cond(handle_value_follows == 1, parse_nfs3_handle)(i)?;
    let resp = Nfs3ResponseReaddirplusEntryC {
        name_vec: name_contents.to_vec(),
        handle,
    };
    Ok((i, resp))
}

#[derive(Debug, PartialEq)]
pub struct Nfs3ResponseReaddirplusEntry<'a> {
    pub entry: Option<Nfs3ResponseReaddirplusEntryC<'a>>,
}

pub fn parse_nfs3_response_readdirplus_entry_cond(
    i: &[u8],
) -> IResult<&[u8], Nfs3ResponseReaddirplusEntry> {
    let (i, value_follows) = be_u32(i)?;
    let (i, entry) = cond(value_follows == 1, parse_nfs3_response_readdirplus_entry)(i)?;
    Ok((i, Nfs3ResponseReaddirplusEntry { entry }))
}

#[derive(Debug, PartialEq)]
pub struct Nfs3ResponseReaddirplus<'a> {
    pub status: u32,
    pub data: &'a [u8],
}

pub fn parse_nfs3_response_readdirplus(i: &[u8]) -> IResult<&[u8], Nfs3ResponseReaddirplus> {
    let (i, status) = be_u32(i)?;
    let (i, dir_attr_follows) = be_u32(i)?;
    let (i, _dir_attr) = cond(dir_attr_follows == 1, take(84_usize))(i)?;
    let (i, data) = rest(i)?;
    let resp = Nfs3ResponseReaddirplus { status, data };
    Ok((i, resp))
}

pub(crate) fn many0_nfs3_response_readdirplus_entries<'a>(
    input: &'a [u8],
) -> IResult<&'a [u8], Vec<Nfs3ResponseReaddirplusEntry<'a>>> {
    many0(complete(parse_nfs3_response_readdirplus_entry_cond))(input)
}

#[derive(Debug, PartialEq)]
pub struct Nfs3RequestReaddirplus<'a> {
    pub handle: Nfs3Handle<'a>,

    pub cookie: u32,
    pub verifier: &'a [u8],
    pub dircount: u32,
    pub maxcount: u32,
}

pub fn parse_nfs3_request_readdirplus(i: &[u8]) -> IResult<&[u8], Nfs3RequestReaddirplus> {
    let (i, handle) = parse_nfs3_handle(i)?;
    let (i, cookie) = be_u32(i)?;
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

#[derive(Debug, PartialEq)]
pub struct Nfs3RequestWrite<'a> {
    pub handle: Nfs3Handle<'a>,

    pub offset: u64,
    pub count: u32,
    pub stable: u32,
    pub file_len: u32,
    pub file_data: &'a [u8],
}

pub fn parse_nfs3_request_write(i: &[u8]) -> IResult<&[u8], Nfs3RequestWrite> {
    let (i, handle) = parse_nfs3_handle(i)?;
    let (i, offset) = be_u64(i)?;
    let (i, count) = be_u32(i)?;
    let (i, stable) = be_u32(i)?;
    let (i, file_len) = be_u32(i)?;
    let (i, file_data) = rest(i)?;
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
/*
#[derive(Debug,PartialEq)]
pub struct Nfs3ReplyRead<'a> {
    pub status: u32,
    pub attr_follows: u32,
    pub attr_blob: &'a[u8],
    pub count: u32,
    pub eof: bool,
    pub data_len: u32,
    pub data: &'a[u8], // likely partial
}
*/
pub fn parse_nfs3_reply_read(i: &[u8]) -> IResult<&[u8], NfsReplyRead> {
    let (i, status) = be_u32(i)?;
    let (i, attr_follows) = be_u32(i)?;
    let (i, attr_blob) = take(84_usize)(i)?; // fixed size?
    let (i, count) = be_u32(i)?;
    let (i, eof) = be_u32(i)?;
    let (i, data_len) = be_u32(i)?;
    let (i, data) = rest(i)?;
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
