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

use crate::common::nom7::{bits, take_until_and_consume};
use std::fmt;
use nom7::bits::streaming::take as take_bits;
use nom7::bytes::streaming::take;
use nom7::combinator::{cond, rest, verify};
use nom7::number::streaming::{le_u8, le_u16, le_u32};
use nom7::sequence::tuple;
use nom7::IResult;

#[derive(Debug,PartialEq)]
pub struct NTLMSSPVersion {
    pub ver_major: u8,
    pub ver_minor: u8,
    pub ver_build: u16,
    pub ver_ntlm_rev: u8,
}

impl fmt::Display for NTLMSSPVersion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}.{} build {} rev {}",
                self.ver_major, self.ver_minor,
                self.ver_build, self.ver_ntlm_rev)
    }
}

fn parse_ntlm_auth_version(i: &[u8]) -> IResult<&[u8], NTLMSSPVersion> {
    let (i, ver_major) = le_u8(i)?;
    let (i, ver_minor) = le_u8(i)?;
    let (i, ver_build) = le_u16(i)?;
    let (i, _) = take(3_usize)(i)?;
    let (i, ver_ntlm_rev) = le_u8(i)?;
    let version = NTLMSSPVersion {
        ver_major,
        ver_minor,
        ver_build,
        ver_ntlm_rev,
    };
    Ok((i, version))
}

#[derive(Debug,PartialEq)]
pub struct NTLMSSPAuthRecord<'a> {
    pub domain: &'a[u8],
    pub user: &'a[u8],
    pub host: &'a[u8],
    pub version: Option<NTLMSSPVersion>,
}

fn parse_ntlm_auth_nego_flags(i:&[u8]) -> IResult<&[u8],(u8,u8,u32)> {
    bits(tuple((
        take_bits(6u8),
        take_bits(1u8),
        take_bits(25u32),
    )))(i)
}

pub fn parse_ntlm_auth_record(i: &[u8]) -> IResult<&[u8], NTLMSSPAuthRecord> {
    let record_len = i.len() + 12; // identifier (8) and type (4) are cut before we are called

    let (i, _lm_blob_len) = verify(le_u16, |&v| (v as usize) < record_len)(i)?;
    let (i, _lm_blob_maxlen) = le_u16(i)?;
    let (i, _lm_blob_offset) = verify(le_u32, |&v| (v as usize) < record_len)(i)?;

    let (i, _ntlmresp_blob_len) = verify(le_u16, |&v| (v as usize) < record_len)(i)?;
    let (i, _ntlmresp_blob_maxlen) = le_u16(i)?;
    let (i, _ntlmresp_blob_offset) = verify(le_u32, |&v| (v as usize) < record_len)(i)?;

    let (i, domain_blob_len) = verify(le_u16, |&v| (v as usize) < record_len)(i)?;
    let (i, _domain_blob_maxlen) = le_u16(i)?;
    let (i, domain_blob_offset) = verify(le_u32, |&v| (v as usize) < record_len)(i)?;

    let (i, user_blob_len) = verify(le_u16, |&v| (v as usize) < record_len)(i)?;
    let (i, _user_blob_maxlen) = le_u16(i)?;
    let (i, _user_blob_offset) = verify(le_u32, |&v| (v as usize) < record_len)(i)?;

    let (i, host_blob_len) = verify(le_u16, |&v| (v as usize) < record_len)(i)?;
    let (i, _host_blob_maxlen) = le_u16(i)?;
    let (i, _host_blob_offset) = verify(le_u32, |&v| (v as usize) < record_len)(i)?;

    let (i, _ssnkey_blob_len) = verify(le_u16, |&v| (v as usize) < record_len)(i)?;
    let (i, _ssnkey_blob_maxlen) = le_u16(i)?;
    let (i, _ssnkey_blob_offset) = verify(le_u32, |&v| (v as usize) < record_len)(i)?;

    let (i, nego_flags) = parse_ntlm_auth_nego_flags(i)?;
    let (i, version) = cond(nego_flags.1==1, parse_ntlm_auth_version)(i)?;

    // subtract 12 as identifier (8) and type (4) are cut before we are called
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

pub fn parse_ntlmssp(i: &[u8]) -> IResult<&[u8], NTLMSSPRecord> {
    let (i, _) = take_until_and_consume(b"NTLMSSP\x00")(i)?;
    let (i, msg_type) = le_u32(i)?;
    let (i, data) = rest(i)?;
    let record = NTLMSSPRecord { msg_type, data };
    Ok((i, record))
}
