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

use nom::IResult;
use nom::combinator::{cond, rest};
use nom::number::streaming::{le_u8, le_u16, le_u32};
use nom::bytes::streaming:: take;

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

fn parse_ntlm_auth_nego_flags(i:&[u8]) -> IResult<&[u8],(u8,u8,u32)> {
    bits!(i, tuple!(take_bits!(6u8),take_bits!(1u8),take_bits!(25u32)))
}

pub fn parse_ntlm_auth_record(i: &[u8]) -> IResult<&[u8], NTLMSSPAuthRecord> {
    let (i, _lm_blob_len) = le_u16(i)?;
    let (i, _lm_blob_maxlen) = le_u16(i)?;
    let (i, _lm_blob_offset) = le_u32(i)?;

    let (i, _ntlmresp_blob_len) = le_u16(i)?;
    let (i, _ntlmresp_blob_maxlen) = le_u16(i)?;
    let (i, _ntlmresp_blob_offset) = le_u32(i)?;

    let (i, domain_blob_len) = le_u16(i)?;
    let (i, _domain_blob_maxlen) = le_u16(i)?;
    let (i, domain_blob_offset) = le_u32(i)?;

    let (i, user_blob_len) = le_u16(i)?;
    let (i, _user_blob_maxlen) = le_u16(i)?;
    let (i, _user_blob_offset) = le_u32(i)?;

    let (i, host_blob_len) = le_u16(i)?;
    let (i, _host_blob_maxlen) = le_u16(i)?;
    let (i, _host_blob_offset) = le_u32(i)?;

    let (i, _ssnkey_blob_len) = le_u16(i)?;
    let (i, _ssnkey_blob_maxlen) = le_u16(i)?;
    let (i, _ssnkey_blob_offset) = le_u32(i)?;

    let (i, nego_flags) = parse_ntlm_auth_nego_flags(i)?;
    let (i, version) = cond(nego_flags.1==1, parse_ntlm_auth_version)(i)?;

    // subtrack 12 as idenfier (8) and type (4) are cut before we are called
    // subtract 60 for the len/offset/maxlen fields above
    let (i, _) = cond(nego_flags.1==1 && domain_blob_offset > 72, |b| take(domain_blob_offset - (12 + 60))(b))(i)?;
    // or 52 if we have no version
    let (i, _) = cond(nego_flags.1==0 && domain_blob_offset > 64, |b| take(domain_blob_offset - (12 + 52))(b))(i)?;

    let (i, domain_blob) = take(domain_blob_len)(i)?;
    let (i, user_blob) = take(user_blob_len)(i)?;
    let (i, host_blob) = take(host_blob_len)(i)?;

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
            take_until!("NTLMSSP\x00")
        >>  tag!("NTLMSSP\x00")
        >>  msg_type: le_u32
        >>  data: rest
        >>  (NTLMSSPRecord {
                msg_type:msg_type,
                data:data,
            })
));
