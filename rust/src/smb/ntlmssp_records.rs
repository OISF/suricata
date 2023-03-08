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
use nom::combinator::{cond, rest, verify};
use nom::number::streaming::{le_u8, le_u16, le_u32};
use nom::Err;
use nom::error::{ErrorKind, make_error};

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

#[derive(Debug, PartialEq, Eq)]
pub struct NTLMSSPNegotiateFlags {
    pub version: bool,
    // others fields not done because not interesting yet
}

fn parse_ntlm_auth_nego_flags(i: &[u8]) -> IResult<&[u8], NTLMSSPNegotiateFlags> {
    let (i, raw) = le_u32(i)?;
    return Ok((i, NTLMSSPNegotiateFlags{version: (raw & 0x2000000) != 0}));
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

pub fn parse_ntlm_auth_record(i: &[u8]) -> IResult<&[u8], NTLMSSPAuthRecord> {
    let orig_i = i;
    let record_len = i.len() + NTLMSSP_IDTYPE_LEN; // idenfier (8) and type (4) are cut before we are called

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
    let (i, user_blob_offset) = verify(le_u32, |&v| (v as usize) < record_len)(i)?;

    let (i, host_blob_len) = le_u16(i)?;
    let (i, _host_blob_maxlen) = le_u16(i)?;
    let (i, host_blob_offset) = verify(le_u32, |&v| (v as usize) < record_len)(i)?;

    let (i, _ssnkey_blob_len) = le_u16(i)?;
    let (i, _ssnkey_blob_maxlen) = le_u16(i)?;
    let (i, _ssnkey_blob_offset) = le_u32(i)?;

    let (i, nego_flags) = parse_ntlm_auth_nego_flags(i)?;
    let (_, version) = cond(nego_flags.version, parse_ntlm_auth_version)(i)?;

    // Caller does not care about remaining input...
    let (_, domain_blob) = extract_ntlm_substring(orig_i, domain_blob_offset, domain_blob_len)?;
    let (_, user_blob) = extract_ntlm_substring(orig_i, user_blob_offset, user_blob_len)?;
    let (_, host_blob) = extract_ntlm_substring(orig_i, host_blob_offset, host_blob_len)?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use nom::Err;
    #[test]
    fn test_parse_auth_nego_flags() {
        // ntlmssp.negotiateflags 1
        let blob = [0x15, 0x82, 0x88, 0xe2];
        let result = parse_ntlm_auth_nego_flags(&blob);
        match result {
            Ok((remainder, flags)) => {
                assert_eq!(flags.version, true);
                assert_eq!(remainder.len(), 0);
            }
            Err(Err::Error(err)) => {
                panic!("Result should not be an error: {:?}.", err);
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
                assert_eq!(flags.version, false);
                assert_eq!(remainder.len(), 0);
            }
            Err(Err::Error(err)) => {
                panic!("Result should not be an error: {:?}.", err);
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
