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

use nom::{rest, le_u16, le_u32};

#[derive(Debug,PartialEq)]
pub struct NTLMSSPAuthRecord<'a> {
    pub domain: &'a[u8],
    pub user: &'a[u8],
    pub host: &'a[u8],
}

named!(pub parse_ntlm_auth_record<NTLMSSPAuthRecord>,
    dbg_dmp!(do_parse!(
            lm_blob_len: le_u16
         >> lm_blob_maxlen: le_u16
         >> lm_blob_offset: le_u32

         >> ntlmresp_blob_len: le_u16
         >> ntlmresp_blob_maxlen: le_u16
         >> ntlmresp_blob_offset: le_u32

         >> domain_blob_len: le_u16
         >> domain_blob_maxlen: le_u16
         >> domain_blob_offset: le_u32

         >> user_blob_len: le_u16
         >> user_blob_maxlen: le_u16
         >> user_blob_offset: le_u32

         >> host_blob_len: le_u16
         >> host_blob_maxlen: le_u16
         >> host_blob_offset: le_u32

         >> ssnkey_blob_len: le_u16
         >> ssnkey_blob_maxlen: le_u16
         >> ssnkey_blob_offset: le_u32

         // subtrack 12 as idenfier (8) and type (4) are cut before we are called
         // subtract 48 for the len/offset/maxlen fields above
         >> take!(domain_blob_offset - (12 + 48))

         //>> lm_blob: take!(lm_blob_len)
         //>> ntlmresp_blob: take!(ntlmresp_blob_len)
         >> domain_blob: take!(domain_blob_len)
         >> user_blob: take!(user_blob_len)
         >> host_blob: take!(host_blob_len)

         >> ( NTLMSSPAuthRecord {
                domain: domain_blob,
                user: user_blob,
                host: host_blob,
            })
)));

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

