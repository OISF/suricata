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

use nom::{le_u16, le_u32, le_u64};

#[derive(Debug,PartialEq)]
pub struct Smb3TransformRecord<'a> {
    pub session_id: u64,
    pub enc_algo: u16,
    pub enc_data: &'a[u8],
}

named!(pub parse_smb3_transform_record<Smb3TransformRecord>,
    do_parse!(
            tag!(b"\xfdSMB")
        >>  _signature: take!(16)
        >>  _nonce: take!(16)
        >>  msg_size: le_u32
        >>  _reserved: le_u16
        >>  enc_algo: le_u16
        >>  session_id: le_u64
        >>  enc_data: take!(msg_size)
        >> ( Smb3TransformRecord {
                session_id,
                enc_algo,
                enc_data,
            })
));
