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

use nom::{rest};

pub const NBSS_MSGTYPE_SESSION_MESSAGE:         u8 = 0x00;
pub const NBSS_MSGTYPE_SESSION_REQUEST:         u8 = 0x81;
pub const NBSS_MSGTYPE_POSITIVE_SSN_RESPONSE:   u8 = 0x82;
pub const NBSS_MSGTYPE_NEGATIVE_SSN_RESPONSE:   u8 = 0x83;
pub const NBSS_MSGTYPE_RETARG_RESPONSE:         u8 = 0x84;
pub const NBSS_MSGTYPE_KEEP_ALIVE:              u8 = 0x85;

#[derive(Debug,PartialEq)]
pub struct NbssRecord<'a> {
    pub message_type: u8,
    pub length: u32,
    pub data: &'a[u8],
}

impl<'a> NbssRecord<'a> {
    pub fn is_valid(&self) -> bool {
        let valid = match self.message_type {
            NBSS_MSGTYPE_SESSION_MESSAGE |
            NBSS_MSGTYPE_SESSION_REQUEST |
            NBSS_MSGTYPE_POSITIVE_SSN_RESPONSE |
            NBSS_MSGTYPE_NEGATIVE_SSN_RESPONSE |
            NBSS_MSGTYPE_RETARG_RESPONSE |
            NBSS_MSGTYPE_KEEP_ALIVE => true,
            _ => false,
        };
        valid
    }
    pub fn is_smb(&self) -> bool {
        let valid = self.is_valid();
        let smb = if self.data.len() >= 4 &&
            self.data[1] == 'S' as u8 && self.data[2] == 'M' as u8 && self.data[3] == 'B' as u8 &&
            (self.data[0] == b'\xFE' || self.data[0] == b'\xFF' || self.data[0] == b'\xFD')
        {
            true
        } else {
            false
        };

        valid && smb
    }
}

named!(pub parse_nbss_record<NbssRecord>,
   do_parse!(
       type_and_len: bits!(tuple!(
               take_bits!(u8, 8),
               take_bits!(u32, 24)))
       >> data: take!(type_and_len.1 as usize)
       >> (NbssRecord {
            message_type:type_and_len.0,
            length:type_and_len.1,
            data:data,
        })
));

named!(pub parse_nbss_record_partial<NbssRecord>,
   do_parse!(
       type_and_len: bits!(tuple!(
               take_bits!(u8, 8),
               take_bits!(u32, 24)))
       >> data: rest
       >> (NbssRecord {
            message_type:type_and_len.0,
            length:type_and_len.1,
            data:data,
        })
));
