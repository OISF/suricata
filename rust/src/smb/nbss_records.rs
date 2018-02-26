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

#[derive(Debug,PartialEq)]
pub struct NbssRecord<'a> {
    pub message_type: u8,
    pub length: u32,
    pub data: &'a[u8],
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

#[derive(Debug,PartialEq)]
pub struct NbssRecordPartial<'a> {
    pub message_type: u8,
    pub length: u32,
    pub data: &'a[u8],
}

named!(pub parse_nbss_record_partial<NbssRecordPartial>,
   do_parse!(
       type_and_len: bits!(tuple!(
               take_bits!(u8, 8),
               take_bits!(u32, 24)))
       >> data: rest
       >> (NbssRecordPartial {
            message_type:type_and_len.0,
            length:type_and_len.1,
            data:data,
        })
));
