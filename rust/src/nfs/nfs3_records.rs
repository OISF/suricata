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
    let (i, attr_value_follows) = be_u32(i)?;   // packet with this structure?
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
    //pub cookie: u32,
    pub cookie: u64, // cookie is a u64 size
    pub verifier: &'a [u8],
    pub dircount: u32,
    //pub maxcount: u32,
}

pub fn parse_nfs3_request_readdirplus(i: &[u8]) -> IResult<&[u8], Nfs3RequestReaddirplus> {
    let (i, handle) = parse_nfs3_handle(i)?;
    let (i, cookie) = be_u64(i)?;
    let (i, verifier) = take(8_usize)(i)?;
    let (i, dircount) = be_u32(i)?;
   // let (i, maxcount) = be_u32(i)?;
    let req = Nfs3RequestReaddirplus {
        handle,
        cookie,
        verifier,
        dircount,
       // maxcount,
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
    let (i, file_data) = take(file_len as usize)(i)?;
    let (i, _file_padding) = cond(file_len % 4 !=0, take(4 - (file_len % 4)))(i)?;
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
    let (i, data) = take(data_len as usize)(i)?;
    let (i, _data_padding) = cond(data_len % 4 !=0, take(4 - data_len % 4))(i)?;
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
    use nom7::bytes::streaming::take;

    // helper function to extract nfs3_handle from packets at different offsets
    fn extract_handle(input: &[u8], offset: usize) -> Nfs3Handle {
        let i: IResult<&[u8], &[u8]> = take(offset as usize)(input);
        match i {
            Ok((r, s)) => {
                assert_eq!(s.len() as usize, offset);
                let (_, handle) = parse_nfs3_handle(r).expect("Parsing nfs3_handle failed!");
                handle
            }
            Err(error) => { panic!("extracting nfs3_handle failed {:?}", error); }
        }
    }

    #[test]
    fn test_nfs3_response_create() {

        // packet_bytes
        let buf: &[u8] = &[

        // Status: NFS3_OK (0)
            0x00, 0x00, 0x00, 0x00,

        // handle_follows: (1)
            0x00, 0x00, 0x00, 0x01,

        // [handle]
        // handle_len: (32)
            0x00, 0x00, 0x00, 0x20,

        // handle
            0x00, 0x10, 0x10, 0x85, 0x00, 0x00, 0x03, 0xe7,
            0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0xa6, 0x54,
            0x00, 0x00, 0x00, 0x1b, 0x00, 0x0a, 0x00, 0x00,
            0x00, 0x00, 0xb2, 0x5a, 0x00, 0x00, 0x00, 0x29,

        // unneeded blob
        /*  0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x81, 0xa4, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x10, 0x85,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa6, 0x54,
            0x38, 0x47, 0x76, 0x25, 0x22, 0x92, 0x19, 0x01,
            0x38, 0x47, 0x76, 0x25, 0x22, 0x92, 0x19, 0x01,
            0x38, 0x47, 0x76, 0x25, 0x22, 0x92, 0x19, 0x01,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x60, 0x38, 0x47, 0x76, 0x25,
            0x21, 0xf9, 0x82, 0x82, 0x38, 0x47, 0x76, 0x25,
            0x21, 0xf9, 0x82, 0x82, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x41, 0xed,
            0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x10, 0x10, 0x85, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xa3, 0xe7, 0x38, 0x47, 0x76, 0x25,
            0x21, 0xf9, 0x82, 0x82, 0x38, 0x47, 0x76, 0x25,
            0x22, 0x92, 0x19, 0x00, 0x38, 0x47, 0x76, 0x25,
            0x22, 0x92, 0x19, 0x00,
        */
        ];

        // asserion: (1) is this a good practice?
        // manually extract handle from packets each time we parse against it
        let expected_handle = Nfs3Handle {
            len: 32,
            value: &[
                0x00, 0x10, 0x10, 0x85, 0x00, 0x00, 0x03, 0xe7,
                0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0xa6, 0x54,
                0x00, 0x00, 0x00, 0x1b, 0x00, 0x0a, 0x00, 0x00,
                0x00, 0x00, 0xb2, 0x5a, 0x00, 0x00, 0x00, 0x29,
            ],
        };

        let result = parse_nfs3_response_create(buf);
        match result {
            Ok((_r, reply)) => {
                assert_eq!(reply.status, 0);

                // assertion: (1)
                assert_eq!(reply.handle, Some(expected_handle));

                // assertion: (2) using extract_handle helper?
                assert_eq!(reply.handle, Some(extract_handle(buf, 8)));
            }
            Err(error) => {panic!("Parsing failed {:?}", error); }
        }
    }

    #[test]
    fn test_nfs2_response_lookup() {

        // packet_bytes
        let buf: &[u8] = &[

        // Status: NFS3_OK (0)
            0x00, 0x00, 0x00, 0x00,

        // handle_len: (32)
            0x00, 0x00, 0x00, 0x20,

        // handle
            0x00, 0x10, 0x10, 0x85, 0x00, 0x00, 0x03, 0xe7,
            0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0xa3, 0xec,
            0x00, 0x00, 0x00, 0x0e, 0x00, 0x0a, 0x00, 0x00,
            0x00, 0x00, 0xb2, 0x5a, 0x00, 0x00, 0x00, 0x29,

        // unneeded_blob
        /*  0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x81, 0xa4, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x10, 0x85,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa3, 0xec,
            0x38, 0x47, 0x76, 0x0b, 0x1e, 0xfe, 0x92, 0x00,
            0x38, 0x47, 0x76, 0x25, 0x1c, 0x03, 0xa1, 0x80,
            0x38, 0x47, 0x76, 0x25, 0x1d, 0x34, 0xce, 0x81,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02,
            0x00, 0x00, 0x41, 0xed, 0x00, 0x00, 0x00, 0x02,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x60,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x10, 0x85,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb2, 0x5a,
            0x38, 0x47, 0x76, 0x25, 0x20, 0x2f, 0xbf, 0x00,
            0x38, 0x47, 0x76, 0x25, 0x25, 0x8d, 0x09, 0x82,
            0x38, 0x47, 0x76, 0x25, 0x25, 0x8d, 0x09, 0x82 */
        ];

        let result = parse_nfs3_response_lookup(buf);
        match result {
            Ok((_r, reply)) => {
                assert_eq!(reply.status, 0);
                assert_eq!(reply.handle, extract_handle(buf, 4));
            }
            Err(error) => { panic!("Parsing failed {:?}", error); }
        }
    }

    #[test]
    fn test_nfs3_request_create() {

        // packet_bytes
        let buf: &[u8] = &[

        // [handle]
        // handle_len
            0x00, 0x00, 0x00, 0x20,

        // handle
            0x00, 0x10, 0x10, 0x85, 0x00, 0x00, 0x03, 0xe7,
            0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0xa3, 0xe7,
            0x00, 0x00, 0x00, 0x10, 0x00, 0x0a, 0x00, 0x00,
            0x00, 0x00, 0xb2, 0x5a, 0x00, 0x00, 0x00, 0x29,

        // [name]
        // name_len: (1)
            0x00, 0x00, 0x00, 0x01,

        // name_contents: (h)
            0x68,

        // _fill_bytes
            0x00, 0x00, 0x00,

        // create_mode: UNCHECKED (0)
            0x00, 0x00, 0x00, 0x00,

        // verifier
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0xa4,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];

        let result = parse_nfs3_request_create(buf);
        match result {
            Ok((r, request)) => {
                assert_eq!(r.len(), 0);
                assert_eq!(request.handle, extract_handle(buf, 0 as usize));
                assert_eq!(request.name_len, 1);
                assert_eq!(request.create_mode, 0);
                assert_eq!(request.verifier.len(), 44);
                assert_eq!(request.name_vec, br#"h"#.to_vec());
            }
            Err(error) => { panic!("Parsing failed {:?}", error); }
        }
    }

    #[test]
    fn test_nfs3_request_remove() {

        // packet_bytes
        let buf: &[u8] = &[

        // [handle]
        // handle_len
            0x00, 0x00, 0x00, 0x20,

        // handle
            0x00, 0x10, 0x10, 0x85, 0x00, 0x00, 0x03, 0xe7,
            0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0xa3, 0xe7,
            0x00, 0x00, 0x00, 0x10, 0x00, 0x0a, 0x00, 0x00,
            0x00, 0x00, 0xb2, 0x5a, 0x00, 0x00, 0x00, 0x29,

        // [name]
        // name_len: (1)
            0x00, 0x00, 0x00, 0x01,

        // name_contents: (h)
            0x68,

        // _fill_bytes
            0x00, 0x00, 0x00,
        ];

        let result = parse_nfs3_request_remove(buf);
        match result {
            Ok((r, request)) => {
                assert_eq!(r.len(), 0);
                assert_eq!(request.handle, extract_handle(buf, 0));
                assert_eq!(request.name_len, 1);
                assert_eq!(request.name_vec, br#"h"#.to_vec());
            }
            Err(error) => { panic!("Parsing failed {:?}", error); }
        }
    }

    #[test]
    fn test_nfs3_request_rmdir() {

        // packet_bytes
        let buf: &[u8] = &[

        //[handle]
        // handle_len: (32)
            0x00, 0x00, 0x00, 0x20,

        // handle
            0x00, 0x10, 0x10, 0x85, 0x00, 0x00, 0x03, 0xe7,
            0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0xb2, 0x5a,
            0x00, 0x00, 0x00, 0x29, 0x00, 0x0a, 0x00, 0x00,
            0x00, 0x00, 0xb2, 0x5a, 0x00, 0x00, 0x00, 0x29,

        // [name]
        // name_len: (1)
            0x00, 0x00, 0x00, 0x01,

        // name_contents: (d)
            0x64,

        // _fill_bytes
            0x00, 0x00, 0x00,
        ];

        let result = parse_nfs3_request_rmdir(buf);
        match result {
            Ok((r, request)) => {
                assert_eq!(r.len(), 0);
                assert_eq!(request.handle, extract_handle(buf, 0));
                assert_eq!(request.name_vec, br#"d"#.to_vec());
            }
            Err(error) => { panic!("Parsing failed {:?}", error); }
        }
    }

    #[test]
    fn test_nfs3_request_mkdir() {

        // packet_bytes
        let buf: &[u8] = &[

        // [handle]
        // handle_len: (32)
            0x00, 0x00, 0x00, 0x20,

        // handle
            0x00, 0x10, 0x10, 0x85, 0x00, 0x00, 0x03, 0xe7,
            0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0xb2, 0x5a,
            0x00, 0x00, 0x00, 0x29, 0x00, 0x0a, 0x00, 0x00,
            0x00, 0x00, 0xb2, 0x5a, 0x00, 0x00, 0x00, 0x29,

        // [name]
        // name_len: (1)
            0x00, 0x00, 0x00, 0x01,

        // name_contents: (d)
            0x64,

        // _fill_bytes
            0x00, 0x00, 0x00,

        // attributes
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0xed,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];

        let result = parse_nfs3_request_mkdir(buf);
        match result {
            Ok((_r, request)) => {
                assert_eq!(request.handle, extract_handle(buf, 0));
                assert_eq!(request.name_vec, br#"d"#.to_vec());
            }
            Err(error) => { panic!("Parsing failed {:?}", error); }
        }
    }

    #[test]
    fn test_nfs3_request_rename() {

        // packet_bytes
        let buf: &[u8] = &[

        // [from_handle]
        // handle_len: (32)
            0x00, 0x00, 0x00, 0x20,

        // handle
            0x00, 0x10, 0x10, 0x85, 0x00, 0x00, 0x03, 0xe7,
            0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0xb2, 0x5a,
            0x00, 0x00, 0x00, 0x29, 0x00, 0x0a, 0x00, 0x00,
            0x00, 0x00, 0xb2, 0x5a, 0x00, 0x00, 0x00, 0x29,

        // [from_name]
        // name_len: (1)
            0x00, 0x00, 0x00, 0x01,

        // name: (a)
            0x61,

        // _fill_bytes
            0x00, 0x00, 0x00,

        // [to_handle]
        // handle_len
            0x00, 0x00, 0x00, 0x20,

        // handle
            0x00, 0x10, 0x10, 0x85, 0x00, 0x00, 0x03, 0xe7,
            0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0xb2, 0x5a,
            0x00, 0x00, 0x00, 0x29, 0x00, 0x0a, 0x00, 0x00,
            0x00, 0x00, 0xb2, 0x5a, 0x00, 0x00, 0x00, 0x29,

        // [to_name]
        // name_len: (2)
            0x00, 0x00, 0x00, 0x02,

        // name: (am)
            0x61, 0x6d,

        // _fill_bytes
            0x00, 0x00,
        ];

        let result = parse_nfs3_request_rename(buf);
        match result {
            Ok((r, request)) => {
                assert_eq!(r.len(), 0);

                assert_eq!(request.from_handle, extract_handle(buf, 0));
                assert_eq!(request.from_name_vec, br#"a"#.to_vec());

                assert_eq!(request.to_handle, extract_handle(buf, 44));
                assert_eq!(request.to_name_vec, br#"am"#.to_vec());
            }
            Err(error) => { panic!("Parsing failed {:?}", error); }
        }
    }

    #[test]
    fn test_nfs3_request_getattr() {

        // packet_bytes
        let buf: &[u8] = &[

        // [handle]
        // handle_len: (32)
            0x00, 0x00, 0x00, 0x20,

        // handle
            0x00, 0x10, 0x10, 0x85, 0x00, 0x00, 0x03, 0xe7,
            0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0xb2, 0x5a,
            0x00, 0x00, 0x00, 0x29, 0x00, 0x0a, 0x00, 0x00,
            0x00, 0x00, 0xb2, 0x5a, 0x00, 0x00, 0x00, 0x29,
        ];

        let result = parse_nfs3_request_getattr(buf);
        match result {
            Ok((r, request)) => {
                assert_eq!(r.len(), 0);
                assert_eq!(request.handle, extract_handle(buf, 0));
            }
            Err(error) => { panic!("Parsing failed {:?}", error); }
        }
    }

    #[test]
    fn test_nfs3_request_access() {

        // packet_bytes
        let buf: &[u8] = &[

        // [handle]
        // handle_len: (32)
            0x00, 0x00, 0x00, 0x20,

        // handle
            0x00, 0x10, 0x10, 0x85, 0x00, 0x00, 0x03, 0xe7,
            0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0xa6, 0x54,
            0x00, 0x00, 0x00, 0x1b, 0x00, 0x0a, 0x00, 0x00,
            0x00, 0x00, 0xb2, 0x5a, 0x00, 0x00, 0x00, 0x29,

        // check_access: (12)
            0x00, 0x00, 0x00, 0x0c,
        ];

        let result = parse_nfs3_request_access(buf);
        match result {
            Ok((r, request)) => {
                assert_eq!(r.len(), 0);
                assert_eq!(request.handle, extract_handle(buf, 0));
                assert_eq!(request.check_access, 12);
            }
            Err(error) => { panic!("Parsing failed {:?}", error); }
        }
    }

    #[test]
    fn test_nfs3_request_commit() {

        // packet_bytes -- used [READ Call] message digest
        let buf: &[u8] = &[

        // [handle]
        // handle_len: (32)
            0x00, 0x00, 0x00, 0x20,

        // handle
            0x00, 0x10, 0x10, 0x85, 0x00, 0x00, 0x03, 0xe7,
            0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0xb2, 0x5d,
            0x00, 0x00, 0x00, 0x2a, 0x00, 0x0a, 0x00, 0x00,
            0x00, 0x00, 0xb2, 0x5a, 0x00, 0x00, 0x00, 0x29,

        // offset: (0)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

        // count:
            0x00, 0x00, 0x40, 0x00,
        ];

        let result = parse_nfs3_request_commit(buf);
        match result {
            Ok((r, request)) => {
                assert_eq!(r.len(), 0);
                assert_eq!(request.handle, extract_handle(buf, 0));
            }
            Err(error) => { panic!("Parsing failed {:?}", error); }
        }
    }

    #[test]
    fn test_nfs3_request_read() {

        // packet_bytes
        let buf: &[u8] = &[

        // [handle]
        // handle_len: (32)
            0x00, 0x00, 0x00, 0x20,

        // handle
            0x00, 0x10, 0x10, 0x85, 0x00, 0x00, 0x03, 0xe7,
            0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0xb2, 0x5d,
            0x00, 0x00, 0x00, 0x2a, 0x00, 0x0a, 0x00, 0x00,
            0x00, 0x00, 0xb2, 0x5a, 0x00, 0x00, 0x00, 0x29,

        // offset: (0)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

        // _count
            0x00, 0x00, 0x40, 0x00,
        ];

        let result = parse_nfs3_request_read(buf);
        match result {
            Ok((r, request)) => {
                assert_eq!(r.len(), 0);
                assert_eq!(request.handle, extract_handle(buf, 0));
                assert_eq!(request.offset, 0);
            }
            Err(error) => { panic!("Parsing failed {:?}", error); }
        }
    }

    #[test]
    fn test_nfs3_request_lookup() {

        // packet_bytes
        let buf: &[u8] = &[

        // [handle]
        // handle_len: (32)
            0x00, 0x00, 0x00, 0x20,

        // handle
            0x00, 0x10, 0x10, 0x85, 0x00, 0x00, 0x03, 0xe7,
            0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0xb2, 0x5a,
            0x00, 0x00, 0x00, 0x29, 0x00, 0x0a, 0x00, 0x00,
            0x00, 0x00, 0xb2, 0x5a, 0x00, 0x00, 0x00, 0x29,

        // [name]
        // name_len: (3)
            0x00, 0x00, 0x00, 0x03,

        // name: (bln)
            0x62, 0x6c, 0x6e,

        // _fill_bytes
            0x00,
        ];

        let result = parse_nfs3_request_lookup(buf);
        match result {
            Ok((r, request)) => {
                assert_eq!(r.len(), 0);
                assert_eq!(request.handle, extract_handle(buf, 0));
                assert_eq!(request.name_vec, br#"bln"#);
            }
            Err(error) => { panic!("Parsing failed {:?}", error); }
        }
    }

    #[test]
    fn test_nfs3_request_readdirplus() {

        // packet_bytes
        let buf: &[u8] = &[

        // [handle]
        // handle_len
            0x00, 0x00, 0x00, 0x20,

        // handle
            0x00, 0x10, 0x10, 0x85, 0x00, 0x00, 0x03, 0xe7,
            0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0xa3, 0xe7,
            0x00, 0x00, 0x00, 0x10, 0x00, 0x0a, 0x00, 0x00,
            0x00, 0x00, 0xb2, 0x5a, 0x00, 0x00, 0x00, 0x29,

        // cookie: (0)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

        // verifier: ("\0")
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

        // count: (1024)
            0x00, 0x00, 0x04, 0x00,
        ];

        let result = parse_nfs3_request_readdirplus(buf);
        match result {
            Ok((r, request)) => {
                assert_eq!(r.len(), 0);
                assert_eq!(request.handle, extract_handle(buf, 0));
                assert_eq!(request.cookie, 0);
                assert_eq!(request.verifier, "\0\0\0\0\0\0\0\0".as_bytes());
                assert_eq!(request.verifier.len(), 8);
                assert_eq!(request.dircount, 1024);
            }
            Err(error) => { panic!("Parsing failed {:?}", error); }
        }
    }

    #[test]
    fn test_nfs3_request_write() {

        // packet_bytes
        let buf: &[u8] = &[

        // [handle]
        // handle_len: (32)
            0x00, 0x00, 0x00, 0x20,

        // handle
            0x00, 0x10, 0x10, 0x85, 0x00, 0x00, 0x03, 0xe7,
            0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0xa6, 0x54,
            0x00, 0x00, 0x00, 0x1b, 0x00, 0x0a, 0x00, 0x00,
            0x00, 0x00, 0xb2, 0x5a, 0x00, 0x00, 0x00, 0x29,

        // offset: (0)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

        // count: (17)
            0x00, 0x00, 0x00, 0x11,

        // stable: <DATA_SYNC> (1)
            0x00, 0x00, 0x00, 0x01,

        // [data]
        // file_len: (17)
            0x00, 0x00, 0x00, 0x11,

        // file_data: ("hallo\nthe b file\n")
            0x68, 0x61, 0x6c, 0x6c, 0x6f, 0x0a, 0x74, 0x68,
            0x65, 0x20, 0x62, 0x20, 0x66, 0x69, 0x6c, 0x65,
            0x0a,

        // _data_padding
            0x00, 0x00, 0x00,
        ];

        let result = parse_nfs3_request_write(buf);
        match result {
            Ok((r, request)) => {
                assert_eq!(r.len(), 0);
                assert_eq!(request.handle, extract_handle(buf, 0));
                assert_eq!(request.offset, 0);
                assert_eq!(request.count, 17);
                assert_eq!(request.stable, 1);
                assert_eq!(request.file_len, 17);
                assert_eq!(request.file_data, "hallo\nthe b file\n".as_bytes());
            }
            Err(error) => { panic!("Parsing failed {:?}", error); }
        }
    }

    #[test]
    fn test_nfs3_reply_read() {

        // packet_bytes
        let buf: &[u8] = &[

        // Status: NFS3_OK (0)
            0x00, 0x00, 0x00, 0x00,

        // attributes_follows: (1)
            0x00, 0x00, 0x00, 0x01,

        // attr_blob
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x81, 0xa4,
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

        // count: (11)
            0x00, 0x00, 0x00, 0x0b,

        // EOF: (true)
            0x00, 0x00, 0x00, 0x01,

        // data_len: (11)
            0x00, 0x00, 0x00, 0x0b,

        // data: ("the b file\n")
            0x74, 0x68, 0x65, 0x20, 0x62, 0x20, 0x66, 0x69,
            0x6c, 0x65, 0x0a,

        // _data_padding
            0x00,
        ];

        let result = parse_nfs3_reply_read(buf);
        match result {
            Ok((r, reply)) => {
                assert_eq!(r.len(), 0);
                assert_eq!(reply.status, 0);
                assert_eq!(reply.attr_follows, 1);
                assert_eq!(reply.attr_blob.len(), 84);
                assert_eq!(reply.count, 11);
                assert_eq!(reply.eof, true);
                assert_eq!(reply.data_len, 11);
                assert_eq!(reply.data, "the b file\n".as_bytes());
            }
            Err(error) => { panic!("Parsing failed {:?}", error); }
        }
    }
}
