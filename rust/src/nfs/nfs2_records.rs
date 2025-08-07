/* Copyright (C) 2017-2020 Open Information Security Foundation
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

//! Nom parsers for NFSv2 records

use crate::nfs::nfs_records::*;
use nom7::bytes::streaming::take;
use nom7::combinator::{rest, cond};
use nom7::number::streaming::be_u32;
use nom7::IResult;

#[derive(Debug,PartialEq, Eq)]
pub struct Nfs2Handle<'a> {
    pub value: &'a[u8],
}

pub fn parse_nfs2_handle(i: &[u8]) -> IResult<&[u8], Nfs2Handle<'_>> {
    let (i, value) = take(32_usize)(i)?;
    Ok((i, Nfs2Handle { value }))
}

#[derive(Debug,PartialEq, Eq)]
pub struct Nfs2RequestLookup<'a> {
    pub handle: Nfs2Handle<'a>,
    pub name_vec: Vec<u8>,
}

pub fn parse_nfs2_request_lookup(i: &[u8]) -> IResult<&[u8], Nfs2RequestLookup<'_>> {
    let (i, handle) = parse_nfs2_handle(i)?;
    let (i, name_len) = be_u32(i)?;
    let (i, name_contents) = take(name_len as usize)(i)?;
    let (i, _name_padding) = rest(i)?;
    let req = Nfs2RequestLookup {
        handle,
        name_vec: name_contents.to_vec(),
    };
    Ok((i, req))
}

#[derive(Debug,PartialEq, Eq)]
pub struct Nfs2RequestRead<'a> {
    pub handle: Nfs2Handle<'a>,
    pub offset: u32,
}

pub fn parse_nfs2_request_read(i: &[u8]) -> IResult<&[u8], Nfs2RequestRead<'_>> {
    let (i, handle) = parse_nfs2_handle(i)?;
    let (i, offset) = be_u32(i)?;
    let (i, _count) = be_u32(i)?;
    let req = Nfs2RequestRead { handle, offset };
    Ok((i, req))
}

pub fn parse_nfs2_reply_read(i: &[u8]) -> IResult<&[u8], NfsReplyRead<'_>> {
    let (i, status) = be_u32(i)?;
    let (i, attr_blob) = take(68_usize)(i)?;
    let (i, data_len) = be_u32(i)?;
    let (i, data_contents) = take(data_len)(i)?;
    let fill_bytes = 4 - (data_len % 4);
    let (i, _) = cond(fill_bytes != 0, take(fill_bytes))(i)?;
    let reply = NfsReplyRead {
        status,
        attr_follows: 1,
        attr_blob,
        count: data_len,
        eof: false,
        data_len,
        data: data_contents,
    };
    Ok((i, reply))
}

#[derive(Debug,PartialEq, Eq)]
pub struct Nfs2Attributes<> {
    pub atype: u32,
    pub asize: u32,
}

pub fn parse_nfs2_attribs(i: &[u8]) -> IResult<&[u8], Nfs2Attributes> {
    let (i, atype) = be_u32(i)?;
    let (i, _blob1) = take(16_usize)(i)?;
    let (i, asize) = be_u32(i)?;
    let (i, _blob2) = take(44_usize)(i)?;
    let attrs = Nfs2Attributes { atype, asize };
    Ok((i, attrs))
}

#[cfg(test)]
mod tests {
    use crate::nfs::nfs2_records::*;

    #[test]
    fn test_nfs2_handle() {
        #[rustfmt::skip]
        let buf: &[u8] = &[
            0x00, 0x10, 0x10, 0x85, 0x00, 0x00, 0x03, 0xe7, /*file_handle*/
            0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0xb2, 0x5a,
            0x00, 0x00, 0x00, 0x29, 0x00, 0x0a, 0x00, 0x00,
            0x00, 0x00, 0xb2, 0x5a, 0x00, 0x00, 0x00, 0x29
        ];

        let (r, res) = parse_nfs2_handle(buf).unwrap();
        assert_eq!(r.len(), 0);
        assert_eq!(res.value, buf);
    }

    #[test]
    fn test_nfs2_request_lookup() {
        #[rustfmt::skip]
        let buf: &[u8] = &[
            0x00, 0x10, 0x10, 0x85, 0x00, 0x00, 0x03, 0xe7, /*file_handle*/
            0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0xb2, 0x5a,
            0x00, 0x00, 0x00, 0x29, 0x00, 0x0a, 0x00, 0x00,
            0x00, 0x00, 0xb2, 0x5a, 0x00, 0x00, 0x00, 0x29,
            0x00, 0x00, 0x00, 0x02, 0x61, 0x6d, 0x00, 0x00, /*name*/
        ];

        let (_, handle) = parse_nfs2_handle(buf).unwrap();
        assert_eq!(handle.value, &buf[..32]);

        let (r, request) = parse_nfs2_request_lookup(buf).unwrap();
        assert_eq!(r.len(), 0);
        assert_eq!(request.handle, handle);
        assert_eq!(request.name_vec, b"am".to_vec());
    }

    #[test]
    fn test_nfs2_request_read() {
        #[rustfmt::skip]
        let buf: &[u8] = &[
            0x00, 0x10, 0x10, 0x85, 0x00, 0x00, 0x03, 0xe7, /*file_handle*/
            0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0xb2, 0x5d,
            0x00, 0x00, 0x00, 0x2a, 0x00, 0x0a, 0x00, 0x00,
            0x00, 0x00, 0xb2, 0x5a, 0x00, 0x00, 0x00, 0x29,
            0x00, 0x00, 0x00, 0x00, /*offset*/
            0x00, 0x00, 0x20, 0x00, /*count*/
            0x00, 0x00, 0x20, 0x00, /*_total_count*/
        ];

        let (_, handle) = parse_nfs2_handle(buf).unwrap();
        assert_eq!(handle.value, &buf[..32]);

        let (r, request) = parse_nfs2_request_read(buf).unwrap();
        assert_eq!(r.len(), 4);
        assert_eq!(request.handle, handle);
        assert_eq!(request.offset, 0);
    }

    #[test]
    fn test_nfs2_reply_read() {
        #[rustfmt::skip]
        let buf: &[u8] = &[
            0x00, 0x00, 0x00, 0x00, /*Status: NFS_OK - (0)*/
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x81, 0xa4, /*attr_blob*/
            0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0b,
            0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x02, 0x00, 0x10, 0x10, 0x85,
            0x00, 0x00, 0xb2, 0x5d, 0x38, 0x47, 0x75, 0xea,
            0x00, 0x0b, 0x71, 0xb0, 0x38, 0x47, 0x71, 0xc4,
            0x00, 0x08, 0xb2, 0x90, 0x38, 0x47, 0x75, 0xea,
            0x00, 0x09, 0x00, 0xb0,
            0x00, 0x00, 0x00, 0x0b, /*data_len*/
            0x74, 0x68, 0x65, 0x20, 0x62, 0x20, 0x66, 0x69, /*data_contents: ("the b file")*/
            0x6c, 0x65, 0x0a,
            0x00, /*_data_padding*/
        ];

        let (r, response) = parse_nfs2_reply_read(buf).unwrap();
        assert_eq!(r.len(), 0);
        assert_eq!(response.status, 0);
        assert_eq!(response.attr_follows, 1);
        assert_eq!(response.attr_blob.len(), 68);
        assert_eq!(response.count, response.data_len);
        assert!(!response.eof);
        assert_eq!(response.data_len, 11);
        assert_eq!(response.data, &buf[76..87]);
    }

    #[test]
    fn test_nfs2_attributes() {
        #[rustfmt::skip]
        let buf: &[u8] = &[
            0x00, 0x00, 0x00, 0x01, /*Type: Regular File (1)*/
            0x00, 0x00, 0x81, 0xa4, 0x00, 0x00, 0x00, 0x01, /*attr: _blob1*/
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, /*size: 0*/
            0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, /*attr: _blob2*/
            0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x10, 0x85,
            0x00, 0x00, 0xa3, 0xe7, 0x38, 0x47, 0x75, 0xea,
            0x00, 0x08, 0x16, 0x50, 0x38, 0x47, 0x75, 0xea,
            0x00, 0x08, 0x16, 0x50, 0x38, 0x47, 0x75, 0xea,
            0x00, 0x08, 0x16, 0x50
        ];

        let (r, res) = parse_nfs2_attribs(buf).unwrap();
        assert_eq!(r.len(), 0);
        assert_eq!(res.atype, 1);
        assert_eq!(res.asize, 0);
    }
}
