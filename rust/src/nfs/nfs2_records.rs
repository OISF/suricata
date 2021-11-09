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
use nom7::combinator::rest;
use nom7::number::streaming::be_u32;
use nom7::IResult;

#[derive(Debug,PartialEq)]
pub struct Nfs2Handle<'a> {
    pub value: &'a[u8],
}

pub fn parse_nfs2_handle(i: &[u8]) -> IResult<&[u8], Nfs2Handle> {
    let (i, value) = take(32_usize)(i)?;
    Ok((i, Nfs2Handle { value }))
}

#[derive(Debug,PartialEq)]
pub struct Nfs2RequestLookup<'a> {
    pub handle: Nfs2Handle<'a>,
    pub name_vec: Vec<u8>,
}

pub fn parse_nfs2_request_lookup(i: &[u8]) -> IResult<&[u8], Nfs2RequestLookup> {
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

#[derive(Debug,PartialEq)]
pub struct Nfs2RequestRead<'a> {
    pub handle: Nfs2Handle<'a>,
    pub offset: u32,
}

pub fn parse_nfs2_request_read(i: &[u8]) -> IResult<&[u8], Nfs2RequestRead> {
    let (i, handle) = parse_nfs2_handle(i)?;
    let (i, offset) = be_u32(i)?;
    let (i, _count) = be_u32(i)?;
    let req = Nfs2RequestRead { handle, offset };
    Ok((i, req))
}

pub fn parse_nfs2_reply_read(i: &[u8]) -> IResult<&[u8], NfsReplyRead> {
    let (i, status) = be_u32(i)?;
    let (i, attr_blob) = take(68_usize)(i)?;
    let (i, data_len) = be_u32(i)?;
    let (i, data_contents) = rest(i)?;
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

#[derive(Debug,PartialEq)]
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
