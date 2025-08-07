/* Copyright (C) 2017-2024 Open Information Security Foundation
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

use crate::common::nom7::take_until_and_consume;
use nom7::bytes::streaming::take;
use nom7::combinator::{cond, rest, verify};
use nom7::error::{make_error, ErrorKind};
use nom7::number::streaming::{le_u16, le_u32, le_u8};
use nom7::Err;
use nom7::IResult;
use std::fmt;

#[derive(Debug, PartialEq, Eq)]
pub struct NTLMSSPVersion {
    pub ver_major: u8,
    pub ver_minor: u8,
    pub ver_build: u16,
    pub ver_ntlm_rev: u8,
}

impl fmt::Display for NTLMSSPVersion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}.{} build {} rev {}",
            self.ver_major, self.ver_minor, self.ver_build, self.ver_ntlm_rev
        )
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

#[derive(Debug, PartialEq, Eq)]
pub struct NTLMSSPAuthRecord<'a> {
    pub domain: &'a [u8],
    pub user: &'a [u8],
    pub host: &'a [u8],
    pub version: Option<NTLMSSPVersion>,
    pub warning: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub struct NTLMSSPNegotiateFlags {
    pub version: bool,
    // others fields not done because not interesting yet
}

fn parse_ntlm_auth_nego_flags(i: &[u8]) -> IResult<&[u8], NTLMSSPNegotiateFlags> {
    let (i, raw) = le_u32(i)?;
    return Ok((
        i,
        NTLMSSPNegotiateFlags {
            version: (raw & 0x2000000) != 0,
        },
    ));
}

const NTLMSSP_IDTYPE_LEN: usize = 12;

fn extract_ntlm_substring(i: &[u8], offset: u32, length: u16) -> IResult<&[u8], &[u8]> {
    if offset < NTLMSSP_IDTYPE_LEN as u32 {
        return Err(Err::Error(make_error(i, ErrorKind::LengthValue)));
    }
    let start = offset as usize - NTLMSSP_IDTYPE_LEN;
    let end = offset as usize + length as usize - NTLMSSP_IDTYPE_LEN;
    if i.len() < end {
        return Err(Err::Error(make_error(i, ErrorKind::LengthValue)));
    }
    return Ok((i, &i[start..end]));
}

pub fn parse_ntlm_auth_record(i: &[u8]) -> IResult<&[u8], NTLMSSPAuthRecord<'_>> {
    let orig_i = i;
    let record_len = i.len() + NTLMSSP_IDTYPE_LEN; // identifier (8) and type (4) are cut before we are called

    // track start of the data offset
    let (i, _lm_blob_len) = verify(le_u16, |&v| (v as usize) < record_len)(i)?;
    let (i, _lm_blob_maxlen) = le_u16(i)?;
    let (i, lm_blob_offset) = verify(le_u32, |&v| (v as usize) < record_len)(i)?;
    let mut data_start = lm_blob_offset;

    let (i, _ntlmresp_blob_len) = verify(le_u16, |&v| (v as usize) < record_len)(i)?;
    let (i, _ntlmresp_blob_maxlen) = le_u16(i)?;
    let (i, ntlmresp_blob_offset) = verify(le_u32, |&v| (v as usize) < record_len)(i)?;
    data_start = std::cmp::min(data_start, ntlmresp_blob_offset);

    let (i, domain_blob_len) = verify(le_u16, |&v| (v as usize) < record_len)(i)?;
    let (i, _domain_blob_maxlen) = le_u16(i)?;
    let (i, domain_blob_offset) = verify(le_u32, |&v| (v as usize) < record_len)(i)?;
    data_start = std::cmp::min(data_start, domain_blob_offset);

    let (i, user_blob_len) = verify(le_u16, |&v| (v as usize) < record_len)(i)?;
    let (i, _user_blob_maxlen) = le_u16(i)?;
    let (i, user_blob_offset) = verify(le_u32, |&v| (v as usize) < record_len)(i)?;
    data_start = std::cmp::min(data_start, user_blob_offset);

    let (i, host_blob_len) = verify(le_u16, |&v| (v as usize) < record_len)(i)?;
    let (i, _host_blob_maxlen) = le_u16(i)?;
    let (i, host_blob_offset) = verify(le_u32, |&v| (v as usize) < record_len)(i)?;
    data_start = std::cmp::min(data_start, host_blob_offset);

    let (i, _ssnkey_blob_len) = verify(le_u16, |&v| (v as usize) < record_len)(i)?;
    let (i, _ssnkey_blob_maxlen) = le_u16(i)?;
    let (i, ssnkey_blob_offset) = verify(le_u32, |&v| (v as usize) < record_len)(i)?;
    data_start = std::cmp::min(data_start, ssnkey_blob_offset);

    let (i, nego_flags) = parse_ntlm_auth_nego_flags(i)?;

    // Check if we have space for the version before the "data" starts.
    let consumed = orig_i.len() - i.len() + NTLMSSP_IDTYPE_LEN;
    let has_space_for_version = data_start as usize >= consumed + 8 && nego_flags.version;

    let (_, version) = cond(has_space_for_version, parse_ntlm_auth_version)(i)?;

    // Caller does not care about remaining input...
    let (_, domain_blob) = extract_ntlm_substring(orig_i, domain_blob_offset, domain_blob_len)?;
    let (_, user_blob) = extract_ntlm_substring(orig_i, user_blob_offset, user_blob_len)?;
    let (_, host_blob) = extract_ntlm_substring(orig_i, host_blob_offset, host_blob_len)?;

    let mut warning = false;
    if (user_blob_offset > 0 && user_blob_offset < domain_blob_offset + domain_blob_len as u32)
        || (host_blob_offset > 0 && host_blob_offset < user_blob_offset + user_blob_len as u32)
    {
        // to set event in transaction
        warning = true;
    }

    let record = NTLMSSPAuthRecord {
        domain: domain_blob,
        user: user_blob,
        host: host_blob,
        warning,

        version,
    };
    Ok((i, record))
}

#[derive(Debug, PartialEq, Eq)]
pub struct NTLMSSPRecord<'a> {
    pub msg_type: u32,
    pub data: &'a [u8],
}

pub fn parse_ntlmssp(i: &[u8]) -> IResult<&[u8], NTLMSSPRecord<'_>> {
    let (i, _) = take_until_and_consume(b"NTLMSSP\x00")(i)?;
    let (i, msg_type) = le_u32(i)?;
    let (i, data) = rest(i)?;
    let record = NTLMSSPRecord { msg_type, data };
    Ok((i, record))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nom7::Err;
    #[test]
    fn test_parse_auth_nego_flags() {
        // ntlmssp.negotiateflags 1
        let blob = [0x15, 0x82, 0x88, 0xe2];
        let result = parse_ntlm_auth_nego_flags(&blob);
        match result {
            Ok((remainder, flags)) => {
                assert!(flags.version);
                assert_eq!(remainder.len(), 0);
            }
            Err(Err::Error(err)) => {
                panic!("Result should not be an error: {:?}.", err.code);
            }
            Err(Err::Incomplete(_)) => {
                panic!("Result should not have been incomplete.");
            }
            _ => {
                panic!("Unexpected behavior!");
            }
        }
        // ntlmssp.negotiateflags 0
        let blob = [0x15, 0x82, 0x88, 0xe0];
        let result = parse_ntlm_auth_nego_flags(&blob);
        match result {
            Ok((remainder, flags)) => {
                assert!(!flags.version);
                assert_eq!(remainder.len(), 0);
            }
            Err(Err::Error(err)) => {
                panic!("Result should not be an error: {:?}.", err.code);
            }
            Err(Err::Incomplete(_)) => {
                panic!("Result should not have been incomplete.");
            }
            _ => {
                panic!("Unexpected behavior!");
            }
        }
    }
}
