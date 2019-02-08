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

//! Nom parsers for NFSv2 records
use nom::{be_u32, rest};
use nfs::nfs_records::*;

#[derive(Debug,PartialEq)]
pub struct Nfs2Handle<'a> {
    pub value: &'a[u8],
}

named!(pub parse_nfs2_handle<Nfs2Handle>,
    do_parse!(
        handle: take!(32)
        >> (
            Nfs2Handle {
                value:handle,
            }
        ))
);

#[derive(Debug,PartialEq)]
pub struct Nfs2RequestLookup<'a> {
    pub handle: Nfs2Handle<'a>,
    pub name_vec: Vec<u8>,
}

named!(pub parse_nfs2_request_lookup<Nfs2RequestLookup>,
    do_parse!(
            handle: parse_nfs2_handle
        >>  name_len: be_u32
        >>  name_contents: take!(name_len)
        >>  _name_padding: rest
        >> (
            Nfs2RequestLookup {
                handle,
                name_vec:name_contents.to_vec(),
            }
        ))
);

#[derive(Debug,PartialEq)]
pub struct Nfs2RequestRead<'a> {
    pub handle: Nfs2Handle<'a>,
    pub offset: u32,
}

named!(pub parse_nfs2_request_read<Nfs2RequestRead>,
    do_parse!(
            handle: parse_nfs2_handle
        >>  offset: be_u32
        >>  _count: be_u32
        >> (
            Nfs2RequestRead {
                handle,
                offset
            }
        ))
);

named!(pub parse_nfs2_reply_read<NfsReplyRead>,
    do_parse!(
            status: be_u32
        >>  attr_blob: take!(68)
        >>  data_len: be_u32
        >>  data_contents: rest
        >> (
            NfsReplyRead {
                status,
                attr_follows:1,
                attr_blob,
                count:data_len,
                eof:false,
                data_len,
                data:data_contents,
            }
        ))
);

#[derive(Debug,PartialEq)]
pub struct Nfs2Attributes<> {
    pub atype: u32,
    pub asize: u32,
}

named!(pub parse_nfs2_attribs<Nfs2Attributes>,
    do_parse!(
            atype: be_u32
        >>  _blob1: take!(16)
        >>  asize: be_u32
        >>  _blob2: take!(44)
        >> (
            Nfs2Attributes {
                atype,
                asize
            }
        ))
);
