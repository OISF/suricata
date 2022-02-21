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
use nom::IResult;
use nom::combinator::rest;
use nom::combinator::verify;
use nom::number::streaming::{be_u32, be_u64};
use nom::bytes::complete::take;
use nom::combinator::cond;
use crate::nfs::nfs_records::*;

#[derive(Debug,PartialEq)]
pub struct Nfs3Handle<'a> {
    pub len: u32,
    pub value: &'a[u8],
}

named!(pub parse_nfs3_handle<Nfs3Handle>,
    do_parse!(
        obj_len: be_u32
        >> obj: take!(obj_len)
        >> (
            Nfs3Handle {
                len:obj_len,
                value:obj,
            }
        ))
);

#[derive(Debug,PartialEq)]
pub struct Nfs3ReplyCreate<'a> {
    pub status: u32,
    pub handle: Option<Nfs3Handle<'a>>,
}

named!(pub parse_nfs3_response_create<Nfs3ReplyCreate>,
    do_parse!(
        status: be_u32
        >> handle_has_value: verify!(be_u32, |&v| v <= 1)
        >> handle: cond!(handle_has_value == 1, parse_nfs3_handle)
        >> (
            Nfs3ReplyCreate {
               status:status,
               handle:handle,
            }
        ))
);

#[derive(Debug,PartialEq)]
pub struct Nfs3ReplyLookup<'a> {
    pub status: u32,
    pub handle: Nfs3Handle<'a>,
}

named!(pub parse_nfs3_response_lookup<Nfs3ReplyLookup>,
    do_parse!(
        status: be_u32
        >> handle: parse_nfs3_handle
        >> (
            Nfs3ReplyLookup {
                status:status,
                handle:handle,
            }
        ))
);

#[derive(Debug,PartialEq)]
pub struct Nfs3RequestCreate<'a> {
    pub handle: Nfs3Handle<'a>,
    pub name_len: u32,
    pub create_mode: u32,
    pub verifier: &'a[u8],
    pub name_vec: Vec<u8>,
}

named!(pub parse_nfs3_request_create<Nfs3RequestCreate>,
    do_parse!(
            handle: parse_nfs3_handle
        >>  name_len: be_u32
        >>  name: take!(name_len)
        >>  create_mode: be_u32
        >>  verifier: rest
        >> (
            Nfs3RequestCreate {
                handle:handle,
                name_len:name_len,
                create_mode:create_mode,
                verifier:verifier,
                name_vec:name.to_vec(),
            }
        ))
);

#[derive(Debug,PartialEq)]
pub struct Nfs3RequestRemove<'a> {
    pub handle: Nfs3Handle<'a>,
    pub name_len: u32,
    pub name_vec: Vec<u8>,
}

named!(pub parse_nfs3_request_remove<Nfs3RequestRemove>,
    do_parse!(
            handle: parse_nfs3_handle
        >>  name_len: be_u32
        >>  name: take!(name_len)
        >>  _fill_bytes: rest
        >> (
            Nfs3RequestRemove {
                handle:handle,
                name_len:name_len,
                name_vec:name.to_vec(),
            }
        ))
);

#[derive(Debug,PartialEq)]
pub struct Nfs3RequestRmdir<'a> {
    pub handle: Nfs3Handle<'a>,
    pub name_vec: Vec<u8>,
}

named!(pub parse_nfs3_request_rmdir<Nfs3RequestRmdir>,
    do_parse!(
            dir_handle: parse_nfs3_handle
        >>  name_len: be_u32
        >>  name: take!(name_len)
        >>  _fill_bytes: cond!(name_len % 4 != 0, take!(4 - name_len % 4))
        >> (
            Nfs3RequestRmdir {
                handle:dir_handle,
                name_vec:name.to_vec(),
            }
        ))
);

#[derive(Debug,PartialEq)]
pub struct Nfs3RequestMkdir<'a> {
    pub handle: Nfs3Handle<'a>,
    pub name_vec: Vec<u8>,
}

named!(pub parse_nfs3_request_mkdir<Nfs3RequestMkdir>,
    do_parse!(
            dir_handle: parse_nfs3_handle
        >>  name_len: be_u32
        >>  name: take!(name_len)
        >>  _fill_bytes: cond!(name_len % 4 != 0, take!(4 - name_len % 4))
        >>  _attributes: rest
        >> (
            Nfs3RequestMkdir {
                handle:dir_handle,
                name_vec:name.to_vec(),
            }
        ))
);

#[derive(Debug,PartialEq)]
pub struct Nfs3RequestRename<'a> {
    pub from_handle: Nfs3Handle<'a>,
    pub from_name_vec: Vec<u8>,
    pub to_handle: Nfs3Handle<'a>,
    pub to_name_vec: Vec<u8>,
}

named!(pub parse_nfs3_request_rename<Nfs3RequestRename>,
    do_parse!(
            from_handle: parse_nfs3_handle
        >>  from_name_len: be_u32
        >>  from_name: take!(from_name_len)
        >>  _from_fill_bytes: cond!(from_name_len % 4 != 0, take!(4 - from_name_len % 4))
        >>  to_handle: parse_nfs3_handle
        >>  to_name_len: be_u32
        >>  to_name: take!(to_name_len)
        >>  _to_fill_bytes: rest
        >> (
            Nfs3RequestRename {
                from_handle,
                from_name_vec:from_name.to_vec(),
                to_handle,
                to_name_vec:to_name.to_vec(),
            }
        ))
);

#[derive(Debug,PartialEq)]
pub struct Nfs3RequestGetAttr<'a> {
    pub handle: Nfs3Handle<'a>,
}

named!(pub parse_nfs3_request_getattr<Nfs3RequestGetAttr>,
    do_parse!(
            handle: parse_nfs3_handle
        >> (
            Nfs3RequestGetAttr {
                handle:handle,
            }
        ))
);

#[derive(Debug,PartialEq)]
pub struct Nfs3RequestAccess<'a> {
    pub handle: Nfs3Handle<'a>,
    pub check_access: u32,
}

named!(pub parse_nfs3_request_access<Nfs3RequestAccess>,
    do_parse!(
            handle: parse_nfs3_handle
        >>  check_access: be_u32
        >> (
            Nfs3RequestAccess {
                handle:handle,
                check_access:check_access,
            }
        ))
);

#[derive(Debug,PartialEq)]
pub struct Nfs3RequestCommit<'a> {
    pub handle: Nfs3Handle<'a>,
}

named!(pub parse_nfs3_request_commit<Nfs3RequestCommit>,
    do_parse!(
            handle: parse_nfs3_handle
        >>  _offset: be_u64
        >>  _count: be_u32
        >> (
            Nfs3RequestCommit {
                handle
            }
        ))
);

#[derive(Debug,PartialEq)]
pub struct Nfs3RequestRead<'a> {
    pub handle: Nfs3Handle<'a>,
    pub offset: u64,
}

named!(pub parse_nfs3_request_read<Nfs3RequestRead>,
    do_parse!(
            handle: parse_nfs3_handle
        >>  offset: be_u64
        >>  _count: be_u32
        >> (
            Nfs3RequestRead {
                handle,
                offset
            }
        ))
);

#[derive(Debug,PartialEq)]
pub struct Nfs3RequestLookup<'a> {
    pub handle: Nfs3Handle<'a>,

    pub name_vec: Vec<u8>,
}

named!(pub parse_nfs3_request_lookup<Nfs3RequestLookup>,
    do_parse!(
            handle: parse_nfs3_handle
        >>  name_len: be_u32
        >>  name_contents: take!(name_len)
        >>  _name_padding: rest
        >> (
            Nfs3RequestLookup {
                handle,
                name_vec:name_contents.to_vec(),
            }
        ))
);


#[derive(Debug,PartialEq)]
pub struct Nfs3ResponseReaddirplusEntryC<'a> {
    pub name_vec: Vec<u8>,
    pub handle: Option<Nfs3Handle<'a>>,
}

named!(pub parse_nfs3_response_readdirplus_entry<Nfs3ResponseReaddirplusEntryC>,
    do_parse!(
           _file_id: be_u64
        >> name_len: be_u32
        >> name_content: take!(name_len)
        >> _fill_bytes: cond!(name_len % 4 != 0, take!(4 - name_len % 4))
        >> _cookie: take!(8)
        >> attr_value_follows: verify!(be_u32, |&v| v <= 1)
        >> _attr: cond!(attr_value_follows==1, take!(84))
        >> handle_value_follows: verify!(be_u32, |&v| v <= 1)
        >> handle: cond!(handle_value_follows==1, parse_nfs3_handle)
        >> (
                Nfs3ResponseReaddirplusEntryC {
                    name_vec:name_content.to_vec(),
                    handle,
                }
           )
        )
);

#[derive(Debug,PartialEq)]
pub struct Nfs3ResponseReaddirplusEntry<'a> {
    pub entry: Option<Nfs3ResponseReaddirplusEntryC<'a>>,
}

named!(pub parse_nfs3_response_readdirplus_entry_cond<Nfs3ResponseReaddirplusEntry>,
    do_parse!(
           value_follows: verify!(be_u32, |&v| v <= 1)
        >> entry: cond!(value_follows==1, parse_nfs3_response_readdirplus_entry)
        >> (
            Nfs3ResponseReaddirplusEntry {
                entry
            }
           ))
);

#[derive(Debug,PartialEq)]
pub struct Nfs3ResponseReaddirplus<'a> {
    pub status: u32,
    pub data: &'a[u8],
}

named!(pub parse_nfs3_response_readdirplus<Nfs3ResponseReaddirplus>,
    do_parse!(
        status: be_u32
        >> dir_attr_follows: verify!(be_u32, |&v| v <= 1)
        >> _dir_attr: cond!(dir_attr_follows == 1, take!(84))
        >> _verifier: take!(8)
        >> data: rest

        >> ( Nfs3ResponseReaddirplus {
                status,
                data
        } ))
);

pub(crate) fn many0_nfs3_response_readdirplus_entries<'a>(input: &'a [u8]) -> IResult<&'a[u8], Vec<Nfs3ResponseReaddirplusEntry<'a>>> {
    many0!(input, complete!(parse_nfs3_response_readdirplus_entry_cond))
}

#[derive(Debug,PartialEq)]
pub struct Nfs3RequestReaddirplus<'a> {
    pub handle: Nfs3Handle<'a>,

    pub cookie: u32,
    pub verifier: &'a[u8],
    pub dircount: u32,
    pub maxcount: u32,
}

named!(pub parse_nfs3_request_readdirplus<Nfs3RequestReaddirplus>,
    do_parse!(
            handle: parse_nfs3_handle
        >>  cookie: be_u32
        >>  verifier: take!(8)
        >>  dircount: be_u32
        >>  maxcount: be_u32
        >> (
            Nfs3RequestReaddirplus {
                handle:handle,
                cookie:cookie,
                verifier:verifier,
                dircount:dircount,
                maxcount:maxcount,
            }
        ))
);

#[derive(Debug,PartialEq)]
pub struct Nfs3RequestWrite<'a> {
    pub handle: Nfs3Handle<'a>,

    pub offset: u64,
    pub count: u32,
    pub stable: u32,
    pub file_len: u32,
    pub file_data: &'a[u8],
}

/// Complete data expected
fn parse_nfs3_data_complete(i: &[u8], file_len: usize, fill_bytes: usize) -> IResult<&[u8], &[u8]> {
    let (i, file_data) = take(file_len as usize)(i)?;
    let (i, _) = cond(fill_bytes > 0, take(fill_bytes))(i)?;
    Ok((i, file_data))
}

/// Partial data. We have all file_len, but need to consider fill_bytes
fn parse_nfs3_data_partial(i: &[u8], file_len: usize, fill_bytes: usize) -> IResult<&[u8], &[u8]> {
    let (i, file_data) = take(file_len as usize)(i)?;
    let fill_bytes = cmp::min(fill_bytes as usize, i.len());
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
    use super::*;

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
