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
use nom::number::streaming::{be_u32, be_u64};

use crate::nfs::types::*;

// Maximum number of operations per compound
// Linux defines NFSD_MAX_OPS_PER_COMPOUND to 16 (tested in Linux 5.15.1).
const NFSD_MAX_OPS_PER_COMPOUND: u32 = 64;

#[derive(Debug,PartialEq)]
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
    Remove(&'a[u8]),
    DelegReturn(Nfs4StateId<'a>),
    SetClientId(Nfs4RequestSetClientId<'a>),
    SetClientIdConfirm,
    ExchangeId(Nfs4RequestExchangeId<'a>),
    Sequence(Nfs4RequestSequence<'a>),
}

#[derive(Debug,PartialEq)]
pub struct Nfs4Attr {
    attr_mask: u64,
}

named!(nfs4_parse_attr_fields<u32>,
    do_parse!(
        len: be_u32
    >>  take!(len)
    >> (len)
));

named!(nfs4_parse_attrs<Nfs4Attr>,
    do_parse!(
        attr_cnt: be_u32
    >>  attr_mask1: be_u32
    >>  attr_mask2: cond!(attr_cnt >= 2, be_u32)
    >>  cond!(attr_cnt == 3, be_u32)
    >>  nfs4_parse_attr_fields
    >> ( Nfs4Attr {
            attr_mask: ((attr_mask1 as u64) << 32) | attr_mask2.unwrap_or(0) as u64,
        } )
));

named!(nfs4_parse_attrbits<Nfs4Attr>,
    do_parse!(
        attr_cnt: be_u32
    >>  attr_mask1: be_u32
    >>  attr_mask2: cond!(attr_cnt >= 2, be_u32)
    >>  cond!(attr_cnt == 3, be_u32)
    >> ( Nfs4Attr {
            attr_mask: ((attr_mask1 as u64) << 32) | attr_mask2.unwrap_or(0) as u64,
        } )
));

#[derive(Debug,PartialEq)]
pub struct Nfs4StateId<'a> {
    pub seqid: u32,
    pub data: &'a[u8],
}

named!(nfs4_parse_stateid<Nfs4StateId>,
    do_parse!(
            seqid: be_u32
        >>  data: take!(12)
        >> ( Nfs4StateId {
                seqid: seqid,
                data: data,
            })
        )
);

#[derive(Debug,PartialEq)]
pub struct Nfs4Handle<'a> {
    pub len: u32,
    pub value: &'a[u8],
}

named!(nfs4_parse_handle<Nfs4Handle>,
    do_parse!(
            obj_len: be_u32
        >>  obj: take!(obj_len)
        >> ( Nfs4Handle {
                len: obj_len,
                value: obj,
            })
));

named!(nfs4_parse_nfsstring<&[u8]>,
    do_parse!(
            len: be_u32
        >>  data: take!(len)
        >>  _fill_bytes: cond!(len % 4 != 0, take!(4 - len % 4))
        >> ( data )
));

named!(nfs4_req_putfh<Nfs4RequestContent>,
    do_parse!(
            h: nfs4_parse_handle
        >> ( Nfs4RequestContent::PutFH(h) )
));

#[derive(Debug,PartialEq)]
pub struct Nfs4RequestSetClientId<'a> {
    pub client_id: &'a[u8],
    pub r_netid: &'a[u8],
    pub r_addr: &'a[u8],
}

named!(nfs4_req_setclientid<Nfs4RequestContent>,
    do_parse!(
            _client_verifier: take!(8)
        >>  client_id: nfs4_parse_nfsstring
        >>  _cb_program: be_u32
        >>  r_netid: nfs4_parse_nfsstring
        >>  r_addr: nfs4_parse_nfsstring
        >>  _cb_id: be_u32
        >> (Nfs4RequestContent::SetClientId(Nfs4RequestSetClientId {
                client_id,
                r_netid,
                r_addr
            }))
));

named!(nfs4_req_setclientid_confirm<Nfs4RequestContent>,
    do_parse!(
            _client_id: take!(8)
        >>  _verifier: take!(8)
        >> (Nfs4RequestContent::SetClientIdConfirm)
));

#[derive(Debug,PartialEq)]
pub struct Nfs4RequestCreate<'a> {
    pub ftype4: u32,
    pub filename: &'a[u8],
    pub link_content: &'a[u8],
}

named!(nfs4_req_create<Nfs4RequestContent>,
    do_parse!(
            ftype4: be_u32
        >>  link_content: cond!(ftype4 == 5, nfs4_parse_nfsstring)
        >>  filename: nfs4_parse_nfsstring
        >>  _attrs: nfs4_parse_attrs
        >> ( Nfs4RequestContent::Create(Nfs4RequestCreate {
                ftype4: ftype4,
                filename: filename,
                link_content: link_content.unwrap_or(&[]),
            })
        ))
);

#[derive(Debug,PartialEq)]
pub enum Nfs4OpenRequestContent<'a> {
    Exclusive4(&'a[u8]),
    Unchecked4(Nfs4Attr),
    Guarded4(Nfs4Attr),
}

named!(nfs4_req_open_unchecked4<Nfs4OpenRequestContent>,
    do_parse!(
            attrs: nfs4_parse_attrs
        >> ( Nfs4OpenRequestContent::Unchecked4(attrs) )
));

named!(nfs4_req_open_guarded4<Nfs4OpenRequestContent>,
    do_parse!(
            attrs: nfs4_parse_attrs
        >> ( Nfs4OpenRequestContent::Guarded4(attrs) )
));

named!(nfs4_req_open_exclusive4<Nfs4OpenRequestContent>,
    do_parse!(
            ver: take!(8)
        >> ( Nfs4OpenRequestContent::Exclusive4(ver) )
));


named!(nfs4_req_open_type<Nfs4OpenRequestContent>,
    do_parse!(
            mode: be_u32
        >>  data: switch!(value!(mode),
                0 => call!(nfs4_req_open_unchecked4)  |
                1 => call!(nfs4_req_open_guarded4)    |
                2 => call!(nfs4_req_open_exclusive4))
        >> ( data )
));

#[derive(Debug,PartialEq)]
pub struct Nfs4RequestOpen<'a> {
    pub open_type: u32,
    pub filename: &'a[u8],
    pub open_data: Option<Nfs4OpenRequestContent<'a>>,
}

named!(nfs4_req_open<Nfs4RequestContent>,
    do_parse!(
            _seqid: be_u32
        >>  _share_access: be_u32
        >>  _share_deny: be_u32
        >>  _client_id: be_u64
        >>  owner_len: be_u32
        >>  cond!(owner_len > 0, take!(owner_len))
        >>  open_type: be_u32
        >>  open_data: cond!(open_type == 1, nfs4_req_open_type)
        >>  _claim_type: be_u32
        >>  filename: nfs4_parse_nfsstring
        >> ( Nfs4RequestContent::Open(Nfs4RequestOpen {
                open_type,
                filename,
                open_data
            })
        ))
);

named!(nfs4_req_readdir<Nfs4RequestContent>,
    do_parse!(
            _cookie: be_u64
        >>  _cookie_verf: be_u64
        >>  _dir_cnt: be_u32
        >>  _max_cnt: be_u32
        >>  _attr: nfs4_parse_attrbits
        >> ( Nfs4RequestContent::ReadDir )
    )
);

#[derive(Debug,PartialEq)]
pub struct Nfs4RequestRename<'a> {
    pub oldname: &'a[u8],
    pub newname: &'a[u8],
}

named!(nfs4_req_rename<Nfs4RequestContent>,
    do_parse!(
            oldname: nfs4_parse_nfsstring
        >>  newname: nfs4_parse_nfsstring
        >> ( Nfs4RequestContent::Rename(Nfs4RequestRename {
                oldname,
                newname
            })
        ))
);

#[derive(Debug,PartialEq)]
pub struct Nfs4RequestLookup<'a> {
    pub filename: &'a[u8],
}

named!(nfs4_req_lookup<Nfs4RequestContent>,
    do_parse!(
            filename: nfs4_parse_nfsstring
        >> ( Nfs4RequestContent::Lookup(Nfs4RequestLookup {
                filename
            })
        ))
);

named!(nfs4_req_remove<Nfs4RequestContent>,
    do_parse!(
            filename: nfs4_parse_nfsstring
        >> ( Nfs4RequestContent::Remove(filename) )
));

#[derive(Debug,PartialEq)]
pub struct Nfs4RequestSetAttr<'a> {
    pub stateid: Nfs4StateId<'a>,
}

named!(nfs4_req_setattr<Nfs4RequestContent>,
    do_parse!(
            stateid: nfs4_parse_stateid
        >>  _attrs: nfs4_parse_attrs
        >> (Nfs4RequestContent::SetAttr(Nfs4RequestSetAttr {
                stateid
            }))
));

named!(nfs4_req_getattr<Nfs4RequestContent>,
    do_parse!(
            attrs: nfs4_parse_attrbits
        >> ( Nfs4RequestContent::GetAttr(attrs) )
    )
);

#[derive(Debug,PartialEq)]
pub struct Nfs4RequestWrite<'a> {
    pub stateid: Nfs4StateId<'a>,
    pub offset: u64,
    pub stable: u32,
    pub write_len: u32,
    pub data: &'a[u8],
}

named!(nfs4_req_write<Nfs4RequestContent>,
    do_parse!(
            stateid: nfs4_parse_stateid
        >>  offset: be_u64
        >>  stable: be_u32
        >>  write_len: be_u32
        >>  data: take!(write_len)
        >>  _padding: cond!(write_len % 4 != 0, take!(4 - write_len % 4))
        >> (Nfs4RequestContent::Write(Nfs4RequestWrite {
                stateid: stateid,
                offset: offset,
                stable: stable,
                write_len: write_len,
                data: data,
            }))
));

#[derive(Debug,PartialEq)]
pub struct Nfs4RequestRead<'a> {
    pub stateid: Nfs4StateId<'a>,
    pub offset: u64,
    pub count: u32,
}

named!(nfs4_req_read<Nfs4RequestContent>,
    do_parse!(
            stateid: nfs4_parse_stateid
        >>  offset: be_u64
        >>  count: be_u32
        >> ( Nfs4RequestContent::Read(Nfs4RequestRead {
                stateid: stateid,
                offset: offset,
                count: count,
            })
        ))
);

named!(nfs4_req_close<Nfs4RequestContent>,
    do_parse!(
            _seqid: be_u32
        >>  stateid: nfs4_parse_stateid
        >> ( Nfs4RequestContent::Close(stateid) )
));

#[derive(Debug,PartialEq)]
pub struct Nfs4RequestOpenConfirm<'a> {
    pub stateid: Nfs4StateId<'a>,
}

named!(nfs4_req_open_confirm<Nfs4RequestContent>,
    do_parse!(
            stateid: nfs4_parse_stateid
        >>  _seqid: be_u32
        >> ( Nfs4RequestContent::OpenConfirm(Nfs4RequestOpenConfirm {
                stateid
            })
        ))
);

named!(nfs4_req_delegreturn<Nfs4RequestContent>,
    do_parse!(
            a: nfs4_parse_stateid
        >> ( Nfs4RequestContent::DelegReturn(a) )
    )
);

named!(nfs4_req_renew<Nfs4RequestContent>,
    do_parse!(
            a: be_u64
        >> ( Nfs4RequestContent::Renew(a) )
    )
);

named!(nfs4_req_getfh<Nfs4RequestContent>,
    do_parse!( ( Nfs4RequestContent::GetFH ) ));

named!(nfs4_req_savefh<Nfs4RequestContent>,
    do_parse!( ( Nfs4RequestContent::SaveFH ) ));

named!(nfs4_req_putrootfh<Nfs4RequestContent>,
    do_parse!( ( Nfs4RequestContent::PutRootFH ) ));

named!(nfs4_req_access<Nfs4RequestContent>,
    do_parse!(
            a: be_u32
        >> ( Nfs4RequestContent::Access(a) )
    )
);

named!(nfs4_req_commit<Nfs4RequestContent>,
    do_parse!(
            _offset: be_u64
        >>  _count: be_u32
        >> ( Nfs4RequestContent::Commit )
    )
);

#[derive(Debug,PartialEq)]
pub struct Nfs4RequestExchangeId<'a> {
    pub client_string: &'a[u8],
    pub nii_domain: &'a[u8],
    pub nii_name: &'a[u8],
}

named!(nfs4_req_exchangeid<Nfs4RequestContent>,
    do_parse!(
        _verifier: take!(8)
    >>  eia_clientstring: nfs4_parse_nfsstring
    >>  _eia_clientflags: be_u32
    >>  _eia_state_protect: be_u32
    >>  _eia_client_impl_id: be_u32
    >>  nii_domain: nfs4_parse_nfsstring
    >>  nii_name: nfs4_parse_nfsstring
    >>  _nii_data_sec: be_u64
    >>  _nii_data_nsec: be_u32
    >> (Nfs4RequestContent::ExchangeId(
            Nfs4RequestExchangeId {
                client_string: eia_clientstring,
                nii_domain,
                nii_name
            }
        ))
));

#[derive(Debug,PartialEq)]
pub struct Nfs4RequestSequence<'a> {
    pub ssn_id: &'a[u8],
}

named!(nfs4_req_sequence<Nfs4RequestContent>,
    do_parse!(
        ssn_id: take!(16)
    >>  _seq_id: be_u32
    >>  _slot_id: be_u32
    >>  _high_slot_id: be_u32
    >>  _cache_this: be_u32
    >> (Nfs4RequestContent::Sequence(
            Nfs4RequestSequence {
                ssn_id
            }
        ))
));

named!(parse_request_compound_command<Nfs4RequestContent>,
    do_parse!(
        cmd: be_u32
    >>  cmd_data: switch!(value!(cmd),
            NFSPROC4_PUTFH                  => call!(nfs4_req_putfh)                |
            NFSPROC4_READ                   => call!(nfs4_req_read)                 |
            NFSPROC4_WRITE                  => call!(nfs4_req_write)                |
            NFSPROC4_GETFH                  => call!(nfs4_req_getfh)                |
            NFSPROC4_SAVEFH                 => call!(nfs4_req_savefh)               |
            NFSPROC4_OPEN                   => call!(nfs4_req_open)                 |
            NFSPROC4_CLOSE                  => call!(nfs4_req_close)                |
            NFSPROC4_LOOKUP                 => call!(nfs4_req_lookup)               |
            NFSPROC4_ACCESS                 => call!(nfs4_req_access)               |
            NFSPROC4_COMMIT                 => call!(nfs4_req_commit)               |
            NFSPROC4_GETATTR                => call!(nfs4_req_getattr)              |
            NFSPROC4_READDIR                => call!(nfs4_req_readdir)              |
            NFSPROC4_RENEW                  => call!(nfs4_req_renew)                |
            NFSPROC4_OPEN_CONFIRM           => call!(nfs4_req_open_confirm)         |
            NFSPROC4_REMOVE                 => call!(nfs4_req_remove)               |
            NFSPROC4_RENAME                 => call!(nfs4_req_rename)               |
            NFSPROC4_CREATE                 => call!(nfs4_req_create)               |
            NFSPROC4_DELEGRETURN            => call!(nfs4_req_delegreturn)          |
            NFSPROC4_SETATTR                => call!(nfs4_req_setattr)              |
            NFSPROC4_PUTROOTFH              => call!(nfs4_req_putrootfh)            |
            NFSPROC4_SETCLIENTID            => call!(nfs4_req_setclientid)          |
            NFSPROC4_SETCLIENTID_CONFIRM    => call!(nfs4_req_setclientid_confirm)  |
            NFSPROC4_SEQUENCE               => call!(nfs4_req_sequence)             |
            NFSPROC4_EXCHANGE_ID            => call!(nfs4_req_exchangeid)
            )
        >> ( cmd_data )
));

#[derive(Debug,PartialEq)]
pub struct Nfs4RequestCompoundRecord<'a> {
    pub commands: Vec<Nfs4RequestContent<'a>>,
}

named!(pub parse_nfs4_request_compound<Nfs4RequestCompoundRecord>,
    do_parse!(
            tag_len: be_u32
        >>  _tag: cond!(tag_len > 0, take!(tag_len))
        >>  _min_ver: be_u32
        >>  ops_cnt: verify!(be_u32, |&v| v <= NFSD_MAX_OPS_PER_COMPOUND)
        >>  commands: count!(parse_request_compound_command, ops_cnt as usize)
        >> (Nfs4RequestCompoundRecord {
                commands
            })
));

#[derive(Debug,PartialEq)]
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
    Sequence(u32, Option<Nfs4ResponseSequence<'a>>),
}

#[derive(Debug,PartialEq)]
pub struct Nfs4ResponseWrite {
    pub count: u32,
    pub committed: u32,
}

named!(nfs4_res_write_ok<Nfs4ResponseWrite>,
    do_parse!(
            count: be_u32
        >>  committed: be_u32
        >>  _verifier: be_u64
        >> (Nfs4ResponseWrite {
                count,
                committed
           })
));

named!(nfs4_res_write<Nfs4ResponseContent>,
    do_parse!(
            status: be_u32
        >>  wd: cond!(status == 0, nfs4_res_write_ok)
        >> (Nfs4ResponseContent::Write(status, wd) )
));

#[derive(Debug,PartialEq)]
pub struct Nfs4ResponseRead<'a> {
    pub eof: bool,
    pub count: u32,
    pub data: &'a[u8],
}

named!(nfs4_res_read_ok<Nfs4ResponseRead>,
    do_parse!(
            eof: verify!(be_u32, |&v| v <= 1)
        >>  read_len: be_u32
        >>  read_data: take!(read_len)
        >> (Nfs4ResponseRead {
                eof: eof==1,
                count: read_len,
                data: read_data,
            })
));

named!(nfs4_res_read<Nfs4ResponseContent>,
    do_parse!(
            status: be_u32
        >>  rd: cond!(status == 0, nfs4_res_read_ok)
        >> (Nfs4ResponseContent::Read(status, rd) )
));

#[derive(Debug,PartialEq)]
pub struct Nfs4ResponseOpen<'a> {
    pub stateid: Nfs4StateId<'a>,
    pub result_flags: u32,
    pub delegation_type: u32,
    pub delegate_read: Option<Nfs4ResponseOpenDelegateRead<'a>>,
}

#[derive(Debug,PartialEq)]
pub struct Nfs4ResponseOpenDelegateRead<'a> {
    pub stateid: Nfs4StateId<'a>,
}

named!(nfs4_res_open_ok_delegate_read<Nfs4ResponseOpenDelegateRead>,
    do_parse!(
            stateid: nfs4_parse_stateid
        >>  _recall: be_u32
        >>  _ace_type: be_u32
        >>  _ace_flags: be_u32
        >>  _ace_mask: be_u32
        >>  who_len: be_u32
        >>  _who: take!(who_len)
        >> (Nfs4ResponseOpenDelegateRead {
                stateid
            })
));

named!(nfs4_res_open_ok<Nfs4ResponseOpen>,
    do_parse!(
            stateid: nfs4_parse_stateid
        >>  _change_info: take!(20)
        >>  result_flags: be_u32
        >>  _attrs: nfs4_parse_attrbits
        >>  delegation_type: be_u32
        >>  delegate_read: cond!(delegation_type == 1, nfs4_res_open_ok_delegate_read)
        >> ( Nfs4ResponseOpen {
                 stateid,
                 result_flags,
                 delegation_type,
                 delegate_read
             } )
));

named!(nfs4_res_open<Nfs4ResponseContent>,
    do_parse!(
            status: be_u32
        >>  open_data: cond!(status == 0, nfs4_res_open_ok)
        >> ( Nfs4ResponseContent::Open(status, open_data) )
));

#[derive(Debug,PartialEq)]
pub struct Nfs4ResponseReaddirEntry<'a> {
    pub name: &'a[u8],
}

#[derive(Debug,PartialEq)]
pub struct Nfs4ResponseReaddir<'a> {
    pub eof: bool,
    pub listing: Vec<Option<Nfs4ResponseReaddirEntry<'a>>>,
}

named!(nfs4_res_readdir_entry_do<Nfs4ResponseReaddirEntry>,
    do_parse!(
            _cookie: be_u64
        >>  name: nfs4_parse_nfsstring
        >>  _attrs: nfs4_parse_attrs
        >> ( Nfs4ResponseReaddirEntry {
                name: name,
            })
));

named!(nfs4_res_readdir_entry<Option<Nfs4ResponseReaddirEntry>>,
    do_parse!(
            value_follows: verify!(be_u32, |&v| v <= 1)
        >>  entry: cond!(value_follows == 1, nfs4_res_readdir_entry_do)
        >> (entry)
));

named!(nfs4_res_readdir_ok<Nfs4ResponseReaddir>,
    do_parse!(
            _verifier: be_u64
        // run parser until we find a 'value follows == 0'
        >>  listing: many_till!(complete!(call!(nfs4_res_readdir_entry)), peek!(tag!(b"\x00\x00\x00\x00")))
        // value follows == 0 checked by line above
        >>  _value_follows: tag!(b"\x00\x00\x00\x00")
        >>  eof: verify!(be_u32, |&v| v <= 1)
        >> ( Nfs4ResponseReaddir { eof: eof==1, listing: listing.0 })
));

named!(nfs4_res_readdir<Nfs4ResponseContent>,
    do_parse!(
            status: be_u32
        >>  rd: cond!(status == 0, nfs4_res_readdir_ok)
        >> ( Nfs4ResponseContent::ReadDir(status, rd) )
));

named!(nfs4_res_create_ok<Nfs4Attr>,
    do_parse!(
            _change_info: take!(20)
        >>  attrs: nfs4_parse_attrbits
        >> ( attrs )
));

named!(nfs4_res_create<Nfs4ResponseContent>,
    do_parse!(
            status: be_u32
        >>  _attrs: cond!(status == 0, nfs4_res_create_ok)
        >> ( Nfs4ResponseContent::Create(status) )
));

named!(nfs4_res_setattr_ok<Nfs4Attr>,
    do_parse!(
            attrs: nfs4_parse_attrbits
        >> ( attrs )
));

named!(nfs4_res_setattr<Nfs4ResponseContent>,
    do_parse!(
            status: be_u32
        >>  _attrs: cond!(status == 0, nfs4_res_setattr_ok)
        >> ( Nfs4ResponseContent::SetAttr(status) )
));

named!(nfs4_res_getattr_ok<Nfs4Attr>,
    do_parse!(
            attrs: nfs4_parse_attrs
        >> ( attrs )
));

named!(nfs4_res_getattr<Nfs4ResponseContent>,
    do_parse!(
            status: be_u32
        >>  attrs: cond!(status == 0, nfs4_res_getattr_ok)
        >> ( Nfs4ResponseContent::GetAttr(status, attrs) )
));

named!(nfs4_res_openconfirm<Nfs4ResponseContent>,
    do_parse!(
            status: be_u32
        >>  stateid: cond!(status == 0, nfs4_parse_stateid)
        >> ( Nfs4ResponseContent::OpenConfirm(status, stateid) )
));

named!(nfs4_res_close<Nfs4ResponseContent>,
    do_parse!(
            status: be_u32
        >>  stateid: cond!(status == 0, nfs4_parse_stateid)
        >> ( Nfs4ResponseContent::Close(status, stateid) )
));

named!(nfs4_res_remove<Nfs4ResponseContent>,
    do_parse!(
            status: be_u32
        >>  cond!(status == 0, take!(20))   // change_info
        >> ( Nfs4ResponseContent::Remove(status) )
));

named!(nfs4_res_rename<Nfs4ResponseContent>,
    do_parse!(
            status: be_u32
        >> ( Nfs4ResponseContent::Rename(status) )
));

named!(nfs4_res_savefh<Nfs4ResponseContent>,
    do_parse!(
            status: be_u32
        >> ( Nfs4ResponseContent::SaveFH(status) )
));

named!(nfs4_res_lookup<Nfs4ResponseContent>,
    do_parse!(
            status: be_u32
        >> ( Nfs4ResponseContent::Lookup(status) )
));

named!(nfs4_res_renew<Nfs4ResponseContent>,
    do_parse!(
            status: be_u32
        >> ( Nfs4ResponseContent::Renew(status) )
));

named!(nfs4_res_getfh<Nfs4ResponseContent>,
    do_parse!(
            status: be_u32
        >>  fh: cond!(status == 0, nfs4_parse_handle)
        >> ( Nfs4ResponseContent::GetFH(status, fh) )
));

named!(nfs4_res_putfh<Nfs4ResponseContent>,
    do_parse!(
            status: be_u32
        >> ( Nfs4ResponseContent::PutFH(status) )
));

named!(nfs4_res_putrootfh<Nfs4ResponseContent>,
    do_parse!(
            status: be_u32
        >> ( Nfs4ResponseContent::PutRootFH(status) )
));

named!(nfs4_res_delegreturn<Nfs4ResponseContent>,
    do_parse!(
            status: be_u32
        >> ( Nfs4ResponseContent::DelegReturn(status) )
));

named!(nfs4_res_setclientid<Nfs4ResponseContent>,
    do_parse!(
            status: be_u32
        >>  _client_id: be_u64
        >>  _verifier: be_u32
        >> ( Nfs4ResponseContent::SetClientId(status) )
));

named!(nfs4_res_setclientid_confirm<Nfs4ResponseContent>,
    do_parse!(
            status: be_u32
        >> ( Nfs4ResponseContent::SetClientIdConfirm(status) )
));

named!(nfs4_res_commit<Nfs4ResponseContent>,
    do_parse!(
            status: be_u32
        >>  _verifier: cond!(status == 0, take!(8))
        >> ( Nfs4ResponseContent::Commit(status))
));

#[derive(Debug,PartialEq)]
pub struct Nfs4ResponseAccess {
    pub supported_types: u32,
    pub access_rights: u32,
}

named!(nfs4_res_access_ok<Nfs4ResponseAccess>,
    do_parse!(
            s: be_u32
        >>  a: be_u32
        >> (Nfs4ResponseAccess {
                supported_types: s,
                access_rights: a,
            })
));

named!(nfs4_res_access<Nfs4ResponseContent>,
    do_parse!(
            status: be_u32
        >>  ad: cond!(status == 0, nfs4_res_access_ok)
        >> ( Nfs4ResponseContent::Access(
                status, ad, ))
));


#[derive(Debug,PartialEq)]
pub struct Nfs4ResponseSequence<'a> {
    pub ssn_id: &'a[u8],
}

named!(nfs4_res_sequence_ok<Nfs4ResponseSequence>,
    do_parse!(
            ssn_id: take!(16)
        >>  _slots: take!(12)
        >>  _flags: be_u32
        >> ( Nfs4ResponseSequence {
                ssn_id: ssn_id,
            })
));

named!(nfs4_res_sequence<Nfs4ResponseContent>,
    do_parse!(
            status: be_u32
        >>  seq: cond!(status == 0, nfs4_res_sequence_ok)
        >> ( Nfs4ResponseContent::Sequence(status, seq) )
));

named!(nfs4_res_compound_command<Nfs4ResponseContent>,
    do_parse!(
        cmd: be_u32
    >>  cmd_data: switch!(value!(cmd),
            NFSPROC4_READ                   => call!(nfs4_res_read)                |
            NFSPROC4_WRITE                  => call!(nfs4_res_write)               |
            NFSPROC4_ACCESS                 => call!(nfs4_res_access)              |
            NFSPROC4_COMMIT                 => call!(nfs4_res_commit)              |
            NFSPROC4_GETFH                  => call!(nfs4_res_getfh)               |
            NFSPROC4_PUTFH                  => call!(nfs4_res_putfh)               |
            NFSPROC4_SAVEFH                 => call!(nfs4_res_savefh)              |
            NFSPROC4_RENAME                 => call!(nfs4_res_rename)              |
            NFSPROC4_READDIR                => call!(nfs4_res_readdir)             |
            NFSPROC4_GETATTR                => call!(nfs4_res_getattr)             |
            NFSPROC4_SETATTR                => call!(nfs4_res_setattr)             |
            NFSPROC4_LOOKUP                 => call!(nfs4_res_lookup)              |
            NFSPROC4_OPEN                   => call!(nfs4_res_open)                |
            NFSPROC4_OPEN_CONFIRM           => call!(nfs4_res_openconfirm)         |
            NFSPROC4_CLOSE                  => call!(nfs4_res_close)               |
            NFSPROC4_REMOVE                 => call!(nfs4_res_remove)              |
            NFSPROC4_CREATE                 => call!(nfs4_res_create)              |
            NFSPROC4_DELEGRETURN            => call!(nfs4_res_delegreturn)         |
            NFSPROC4_SETCLIENTID            => call!(nfs4_res_setclientid)         |
            NFSPROC4_SETCLIENTID_CONFIRM    => call!(nfs4_res_setclientid_confirm) |
            NFSPROC4_PUTROOTFH              => call!(nfs4_res_putrootfh)           |
            NFSPROC4_SEQUENCE               => call!(nfs4_res_sequence)            |
            NFSPROC4_RENEW                  => call!(nfs4_res_renew))
    >> (cmd_data)
));

#[derive(Debug,PartialEq)]
pub struct Nfs4ResponseCompoundRecord<'a> {
    pub status: u32,
    pub commands: Vec<Nfs4ResponseContent<'a>>,
}

named!(pub parse_nfs4_response_compound<Nfs4ResponseCompoundRecord>,
    do_parse!(
            status: be_u32
        >>  tag_len: be_u32
        >>  _tag: cond!(tag_len > 0, take!(tag_len))
        >>  ops_cnt: verify!(be_u32, |&v| v <= NFSD_MAX_OPS_PER_COMPOUND)
        >>  commands: count!(nfs4_res_compound_command, ops_cnt as usize)
        >> (Nfs4ResponseCompoundRecord {
                status: status,
                commands: commands,
            })
));
