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

use nom::{rest, le_u8, le_u16, le_u32};

#[derive(Debug,PartialEq)]
pub struct NTLMSSPVersion {
    pub ver_major: u8,
    pub ver_minor: u8,
    pub ver_build: u16,
    pub ver_ntlm_rev: u8,
}

impl NTLMSSPVersion {
    pub fn to_string(&self) -> String {
        format!("{}.{} build {} rev {}",
                self.ver_major, self.ver_minor,
                self.ver_build, self.ver_ntlm_rev)
    }
}

named!(parse_ntlm_auth_version<NTLMSSPVersion>,
    do_parse!(
            ver_major: le_u8
         >> ver_minor: le_u8
         >> ver_build: le_u16
         >> take!(3)
         >> ver_ntlm_rev: le_u8
         >> ( NTLMSSPVersion {
                ver_major: ver_major,
                ver_minor: ver_minor,
                ver_build: ver_build,
                ver_ntlm_rev: ver_ntlm_rev,
             })
));

#[derive(Debug,PartialEq)]
pub struct NTLMSSPAuthRecord<'a> {
    pub domain: &'a[u8],
    pub user: &'a[u8],
    pub host: &'a[u8],
    pub version: Option<NTLMSSPVersion>,
}

pub fn parse_ntlm_auth_record(i: &[u8]) -> nom::IResult<&[u8], NTLMSSPAuthRecord> {
    let record_len = i.len() + 12; // idenfier (8) and type (4) are cut before we are called

    let (i, _lm_blob_len) = verify!(i, le_u16, |v| (v as usize) < record_len)?;
    let (i, _lm_blob_maxlen) = le_u16(i)?;
    let (i, _lm_blob_offset) = verify!(i, le_u32, |v| (v as usize) < record_len)?;

    let (i, _ntlmresp_blob_len) = verify!(i, le_u16, |v| (v as usize) < record_len)?;
    let (i, _ntlmresp_blob_maxlen) = le_u16(i)?;
    let (i, _ntlmresp_blob_offset) = verify!(i, le_u32, |v| (v as usize) < record_len)?;

    let (i, domain_blob_len) = verify!(i, le_u16, |v| (v as usize) < record_len)?;
    let (i, _domain_blob_maxlen) = le_u16(i)?;
    let (i, domain_blob_offset) = verify!(i, le_u32, |v| (v as usize) < record_len)?;

    let (i, user_blob_len) = verify!(i, le_u16, |v| (v as usize) < record_len)?;
    let (i, _user_blob_maxlen) = le_u16(i)?;
    let (i, _user_blob_offset) = verify!(i, le_u32, |v| (v as usize) < record_len)?;

    let (i, host_blob_len) = verify!(i, le_u16, |v| (v as usize) < record_len)?;
    let (i, _host_blob_maxlen) = le_u16(i)?;
    let (i, _host_blob_offset) = verify!(i, le_u32, |v| (v as usize) < record_len)?;

    let (i, _ssnkey_blob_len) = verify!(i, le_u16, |v| (v as usize) < record_len)?;
    let (i, _ssnkey_blob_maxlen) = le_u16(i)?;
    let (i, _ssnkey_blob_offset) = verify!(i, le_u32, |v| (v as usize) < record_len)?;

    let (i, nego_flags) = bits!(i, tuple!(take_bits!(u8, 6),take_bits!(u8,1),take_bits!(u32,25)))?;

    let (i, version) = cond!(i, nego_flags.1==1, parse_ntlm_auth_version)?;

    // subtrack 12 as idenfier (8) and type (4) are cut before we are called
    // subtract 60 for the len/offset/maxlen fields above
    let i = if nego_flags.1 == 1 && domain_blob_offset > 72 {
        take!(i, domain_blob_offset - (12 + 16))?.0
    } else {
        i
    };
    //let (i, _) = cond!(i, nego_flags.1==1 && domain_blob_offset > 72, |b| take!(domain_blob_offset - (12 + 60)))?;
    // or 52 if we have no version
    let i = if nego_flags.1 == 0 && domain_blob_offset > 64 {
        take!(i, domain_blob_offset - (12 + 52))?.0
    } else {
        i
    };
    //let (i, _) = cond!(i, nego_flags.1==0 && domain_blob_offset > 64, |b| take!(domain_blob_offset - (12 + 52)))?;

    let (i, domain_blob) = take!(i, domain_blob_len)?;
    let (i, user_blob) = take!(i, user_blob_len)?;
    let (i, host_blob) = take!(i, host_blob_len)?;

    let record = NTLMSSPAuthRecord {
        domain: domain_blob,
        user: user_blob,
        host: host_blob,

        version,
    };
    Ok((i, record))
}

#[derive(Debug,PartialEq)]
pub struct NTLMSSPRecord<'a> {
    pub msg_type: u32,
    pub data: &'a[u8],
}

named!(pub parse_ntlmssp<NTLMSSPRecord>,
    do_parse!(
            take_until_and_consume!("NTLMSSP\x00")
        >>  msg_type: le_u32
        >>  data: rest
        >>  (NTLMSSPRecord {
                msg_type:msg_type,
                data:data,
            })
));
