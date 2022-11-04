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

use std::cmp;
use crate::nfs::nfs_records::*;
use nom7::bytes::streaming::take;
use nom7::combinator::{complete, cond, rest, verify};
use nom7::multi::{length_data, many0};
use nom7::number::streaming::{be_u32, be_u64};
use nom7::IResult;

#[derive(Debug, PartialEq, Eq)]
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

#[derive(Debug, PartialEq, Eq)]
pub struct Nfs3ReplyCreate<'a> {
    pub status: u32,
    pub handle: Option<Nfs3Handle<'a>>,
}

pub fn parse_nfs3_response_create(i: &[u8]) -> IResult<&[u8], Nfs3ReplyCreate> {
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

pub fn parse_nfs3_response_lookup(i: &[u8]) -> IResult<&[u8], Nfs3ReplyLookup> {
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

pub fn parse_nfs3_request_create(i: &[u8]) -> IResult<&[u8], Nfs3RequestCreate> {
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

#[derive(Debug, PartialEq, Eq)]
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

#[derive(Debug, PartialEq, Eq)]
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

#[derive(Debug, PartialEq, Eq)]
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

#[derive(Debug, PartialEq, Eq)]
pub struct Nfs3RequestGetAttr<'a> {
    pub handle: Nfs3Handle<'a>,
}

pub fn parse_nfs3_request_getattr(i: &[u8]) -> IResult<&[u8], Nfs3RequestGetAttr> {
    let (i, handle) = parse_nfs3_handle(i)?;
    Ok((i, Nfs3RequestGetAttr { handle }))
}

#[derive(Debug, PartialEq, Eq)]
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

#[derive(Debug, PartialEq, Eq)]
pub struct Nfs3RequestCommit<'a> {
    pub handle: Nfs3Handle<'a>,
}

pub fn parse_nfs3_request_commit(i: &[u8]) -> IResult<&[u8], Nfs3RequestCommit> {
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

pub fn parse_nfs3_request_read(i: &[u8]) -> IResult<&[u8], Nfs3RequestRead> {
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

#[derive(Debug, PartialEq, Eq)]
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
) -> IResult<&[u8], Nfs3ResponseReaddirplusEntry> {
    let (i, value_follows) = verify(be_u32, |&v| v <= 1)(i)?;
    let (i, entry) = cond(value_follows == 1, parse_nfs3_response_readdirplus_entry)(i)?;
    Ok((i, Nfs3ResponseReaddirplusEntry { entry }))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Nfs3ResponseReaddirplus<'a> {
    pub status: u32,
    pub data: &'a [u8],
}

pub fn parse_nfs3_response_readdirplus(i: &[u8]) -> IResult<&[u8], Nfs3ResponseReaddirplus> {
    let (i, status) = be_u32(i)?;
    let (i, dir_attr_follows) = verify(be_u32, |&v| v <= 1)(i)?;
    let (i, _dir_attr) = cond(dir_attr_follows == 1, take(84_usize))(i)?;
    let (i, _verifier) = be_u64(i)?;
    let (i, data) = rest(i)?;
    let resp = Nfs3ResponseReaddirplus { status, data };
    Ok((i, resp))
}

pub(crate) fn many0_nfs3_response_readdirplus_entries<'a>(
    input: &'a [u8],
) -> IResult<&'a [u8], Vec<Nfs3ResponseReaddirplusEntry<'a>>> {
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

pub fn parse_nfs3_request_readdirplus(i: &[u8]) -> IResult<&[u8], Nfs3RequestReaddirplus> {
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
pub fn parse_nfs3_request_write(i: &[u8], complete: bool) -> IResult<&[u8], Nfs3RequestWrite> {
    let (i, handle) = parse_nfs3_handle(i)?;
    let (i, offset) = be_u64(i)?;
    let (i, count) = be_u32(i)?;
    let (i, stable) = verify(be_u32, |&v| v <= 2)(i)?;
    let (i, file_len) = verify(be_u32, |&v| v <= count)(i)?;
    let fill_bytes = if file_len % 4 != 0 { 4 - file_len % 4 } else { 0 };
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

pub fn parse_nfs3_reply_read(i: &[u8], complete: bool) -> IResult<&[u8], NfsReplyRead> {
    let (i, status) = be_u32(i)?;
    let (i, attr_follows) = verify(be_u32, |&v| v <= 1)(i)?;
    let (i, attr_blob) = take(84_usize)(i)?; // fixed size?
    let (i, count) = be_u32(i)?;
    let (i, eof) = verify(be_u32, |&v| v <= 1)(i)?;
    let (i, data_len) = verify(be_u32, |&v| v <= count)(i)?;
    let fill_bytes = if data_len % 4 != 0 { 4 - data_len % 4 } else { 0 };
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

#[cfg(test)]
mod tests {
    use crate::nfs::nfs3_records::*;

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

        let result = parse_nfs3_request_create(buf).unwrap();
        match result {
            (r, request) => {
                assert_eq!(r.len(), 0);
                assert_eq!(request.handle, expected_handle);
                assert_eq!(request.name_len, 1);
                assert_eq!(request.create_mode, 0);
                assert_eq!(request.verifier.len(), 44);
                assert_eq!(request.name_vec, br#"h"#.to_vec());
            }
        }
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

        let result = parse_nfs3_request_remove(buf).unwrap();
        match result {
            (r, request) => {
                assert_eq!(r.len(), 0);
                assert_eq!(request.handle, expected_handle);
                assert_eq!(request.name_len, 1);
                assert_eq!(request.name_vec, br#"h"#.to_vec());
            }
        }
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

        let result = parse_nfs3_request_rmdir(buf).unwrap();
        match result {
            (r, request) => {
                assert_eq!(r.len(), 0);
                assert_eq!(request.handle, expected_handle);
                assert_eq!(request.name_vec, br#"d"#.to_vec());
            }
        }
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

        let result = parse_nfs3_request_mkdir(buf).unwrap();
        match result {
            (_r, request) => {
                assert_eq!(request.handle, expected_handle);
                assert_eq!(request.name_vec, br#"d"#.to_vec());
            }
        }
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

        let result = parse_nfs3_request_rename(buf).unwrap();
        match result {
            (r, request) => {
                assert_eq!(r.len(), 0);

                assert_eq!(request.from_handle, expected_from_handle);
                assert_eq!(request.from_name_vec, br#"a"#.to_vec());

                assert_eq!(request.to_handle, expected_to_handle);
                assert_eq!(request.to_name_vec, br#"am"#.to_vec());
            }
        }
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

        let result = parse_nfs3_request_getattr(buf).unwrap();
        match result {
            (r, request) => {
                assert_eq!(r.len(), 0);
                assert_eq!(request.handle, expected_handle);
            }
        }
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

        let result = parse_nfs3_request_access(buf).unwrap();
        match result {
            (r, request) => {
                assert_eq!(r.len(), 0);
                assert_eq!(request.handle, expected_handle);
                assert_eq!(request.check_access, 12);
            }
        }
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

        let result = parse_nfs3_request_commit(buf).unwrap();
        match result {
            (r, request) => {
                assert_eq!(r.len(), 0);
                assert_eq!(request.handle, expected_handle);
            }
        }
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

        let result = parse_nfs3_request_read(buf).unwrap();
        match result {
            (r, request) => {
                assert_eq!(r.len(), 0);
                assert_eq!(request.handle, expected_handle);
                assert_eq!(request.offset, 0);
            }
        }
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

        let result = parse_nfs3_request_lookup(buf).unwrap();
        match result {
            (r, request) => {
                assert_eq!(r.len(), 0);
                assert_eq!(request.handle, expected_handle);
                assert_eq!(request.name_vec, br#"bln"#);
            }
        }
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

        let response = many0_nfs3_response_readdirplus_entries(data_buf).unwrap();
        match response {
            (r, entries) => {
                assert_eq!(r.len(), 4);
                assert_eq!(entries[0], Nfs3ResponseReaddirplusEntry { entry: Some(entry0) });
                assert_eq!(entries[1], Nfs3ResponseReaddirplusEntry { entry: Some(entry1) });
            }
        }
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
            Nfs3ResponseReaddirplusEntry { entry: Some(entry_c) } => {
                assert_eq!(entry_c.name_vec, ".".as_bytes());
                assert_eq!(entry_c.handle, Some(entry_handle));
            }
            _ => { panic!("Failure"); }
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

        let result = parse_nfs3_request_readdirplus(buf).unwrap();
        match result {
            (r, request) => {
                assert_eq!(r.len(), 0);
                assert_eq!(request.handle, expected_handle);
                assert_eq!(request.cookie, 0);
                assert_eq!(request.verifier, "\0\0\0\0\0\0\0\0".as_bytes());
                assert_eq!(request.verifier.len(), 8);
                assert_eq!(request.dircount, 512);
                assert_eq!(request.maxcount, 4096);
            }
        }
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

        let result = parse_nfs3_request_write(buf, true).unwrap();
        match result {
            (r, request) => {
                assert_eq!(r.len(), 0);
                assert_eq!(request.handle, expected_handle);
                assert_eq!(request.offset, 0);
                assert_eq!(request.count, 17);
                assert_eq!(request.stable, 1);
                assert_eq!(request.file_len, 17);
                assert_eq!(request.file_data, "hallo\nthe b file\n".as_bytes());
            }
        }
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

        let result = parse_nfs3_reply_read(buf, true).unwrap();
        match result {
            (r, reply) => {
                assert_eq!(r.len(), 0);
                assert_eq!(reply.status, 0);
                assert_eq!(reply.attr_follows, 1);
                assert_eq!(reply.attr_blob.len(), 84);
                assert_eq!(reply.count, 11);
                assert_eq!(reply.eof, true);
                assert_eq!(reply.data_len, 11);
                assert_eq!(reply.data, "the b file\n".as_bytes());
            }
        }
    }
}
