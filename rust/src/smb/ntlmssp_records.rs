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

named!(pub parse_ntlm_auth_record<NTLMSSPAuthRecord>,
    do_parse!(
            _lm_blob_len: le_u16
         >> _lm_blob_maxlen: le_u16
         >> _lm_blob_offset: le_u32

         >> _ntlmresp_blob_len: le_u16
         >> _ntlmresp_blob_maxlen: le_u16
         >> _ntlmresp_blob_offset: le_u32

         >> domain_blob_len: le_u16
         >> _domain_blob_maxlen: le_u16
         >> domain_blob_offset: le_u32

         >> user_blob_len: le_u16
         >> _user_blob_maxlen: le_u16
         >> _user_blob_offset: le_u32

         >> host_blob_len: le_u16
         >> _host_blob_maxlen: le_u16
         >> _host_blob_offset: le_u32

         >> _ssnkey_blob_len: le_u16
         >> _ssnkey_blob_maxlen: le_u16
         >> _ssnkey_blob_offset: le_u32

         >> nego_flags: bits!(tuple!(take_bits!(u8, 6),take_bits!(u8,1),take_bits!(u32,25)))
         >> version: cond!(nego_flags.1==1, parse_ntlm_auth_version)

         // subtrack 12 as idenfier (8) and type (4) are cut before we are called
         // subtract 60 for the len/offset/maxlen fields above
         >> cond!(nego_flags.1==1, take!(domain_blob_offset - (12 + 60)))
         // or 52 if we have no version
         >> cond!(nego_flags.1==0, take!(domain_blob_offset - (12 + 52)))

         >> domain_blob: take!(domain_blob_len)
         >> user_blob: take!(user_blob_len)
         >> host_blob: take!(host_blob_len)

         >> ( NTLMSSPAuthRecord {
                domain: domain_blob,
                user: user_blob,
                host: host_blob,

                version: version,
            })
));

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
