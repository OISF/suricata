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

use nom::combinator::rest;

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
    pub fn needs_more(&self) -> bool {
        return self.is_valid() && self.length >= 4 && self.data.len() < 4;
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
               take_bits!(8u8),
               take_bits!(24u32)))
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
               take_bits!(8u8),
               take_bits!(24u32)))
       >> data: rest
       >> (NbssRecord {
            message_type:type_and_len.0,
            length:type_and_len.1,
            data:data,
        })
));

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_parse_nbss_record() {
        let buff:&[u8] = &[
        /* message type */ 0x00,
        /* length */       0x00, 0x00, 0x55,
        /* data */         0xff, 0x53, 0x4d, 0x42, 0x72, 0x00, 0x00, 0x00, 0x00,
                           0x98, 0x53, 0xc8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
                           0xfe, 0x00, 0x00, 0x00, 0x00, 0x11, 0x05, 0x00, 0x03,
                           0x0a, 0x00, 0x01, 0x00, 0x04, 0x11, 0x00, 0x00, 0x00,
                           0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfd, 0xe3,
                           0x00, 0x80, 0x2a, 0x55, 0xc4, 0x38, 0x89, 0x03, 0xcd,
                           0x01, 0x2c, 0x01, 0x00, 0x10, 0x00, 0xfe, 0x82, 0xf1,
                           0x64, 0x0b, 0x66, 0xba, 0x4a, 0xbb, 0x81, 0xe1, 0xea,
                           0x54, 0xae, 0xb8, 0x66];

        let result = parse_nbss_record(&buff);
        match result {
            Ok((remainder, p)) => {
                assert_eq!(p.message_type, NBSS_MSGTYPE_SESSION_MESSAGE);
                assert_eq!(p.length, 85);
                assert_eq!(p.data.len(), 85);
                assert_ne!(p.message_type, NBSS_MSGTYPE_KEEP_ALIVE);

                // this packet had an acceptable length, we don't need more
                assert_eq!(p.needs_more(), false);

                // does this really look like smb?
                assert_eq!(p.is_smb(), true);

                // there should be nothing left
                assert_eq!(remainder.len(), 0);
            }
            Err(nom::Err::Error((_remainder, err))) => {
                panic!("Result should not be an error: {:?}.", err);
            }
            Err(nom::Err::Incomplete(_)) => {
                panic!("Result should not have been incomplete.");
            }
            _ => {
                panic!("Unexpected behavior!");
            }
        }

        // Non-SMB packet scenario
        let buff_not_smb:&[u8] = &[
            /* message type */ 0x00,
            /* length */       0x00, 0x00, 0x55,
            /* data !SMB */    0xff, 0x52, 0x4e, 0x41, 0x72, 0x00, 0x00, 0x00, 0x00,
                               0x98, 0x53, 0xc8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
                               0xfe, 0x00, 0x00, 0x00, 0x00, 0x11, 0x05, 0x00, 0x03,
                               0x0a, 0x00, 0x01, 0x00, 0x04, 0x11, 0x00, 0x00, 0x00,
                               0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfd, 0xe3,
                               0x00, 0x80, 0x2a, 0x55, 0xc4, 0x38, 0x89, 0x03, 0xcd,
                               0x01, 0x2c, 0x01, 0x00, 0x10, 0x00, 0xfe, 0x82, 0xf1,
                               0x64, 0x0b, 0x66, 0xba, 0x4a, 0xbb, 0x81, 0xe1, 0xea,
                               0x54, 0xae, 0xb8, 0x66];

        let result_not_smb = parse_nbss_record(&buff_not_smb);
        match result_not_smb {
            Ok((remainder, p_not_smb)) => {
                assert_eq!(p_not_smb.message_type, NBSS_MSGTYPE_SESSION_MESSAGE);
                assert_eq!(p_not_smb.length, 85);
                assert_eq!(p_not_smb.data.len(), 85);
                assert_ne!(p_not_smb.message_type, NBSS_MSGTYPE_KEEP_ALIVE);

                // this packet had an acceptable length, we don't need more
                assert_eq!(p_not_smb.needs_more(), false);

                // this packet doesn't have the SMB keyword
                // is_smb must be false
                assert_eq!(p_not_smb.is_smb(), false);

                // there should be nothing left
                assert_eq!(remainder.len(), 0);
            }
            Err(nom::Err::Error((_remainder, err))) => {
                panic!("Result should not be an error: {:?}.", err);
            }
            Err(nom::Err::Incomplete(_)) => {
                panic!("Result should not have been incomplete.");
            }
            _ => {
                panic!("Unexpected behavior!");
            }
        }
    }

    #[test]
    fn test_parse_nbss_record_partial() {
        let buff:&[u8] = &[
        /* message type */  0x00,
        /* length */        0x00, 0x00, 0x29,
        /* data < lenght*/  0xff, 0x53, 0x4d, 0x42, 0x04, 0x00, 0x00, 0x00,
                            0x00, 0x18, 0x43, 0xc8, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x02, 0x08, 0xbd, 0x20, 0x02, 0x08, 0x06, 0x00,
                            0x02, 0x40, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00];

        let result = parse_nbss_record_partial(&buff);
        match result {
            Ok((remainder, p)) => {
                assert_eq!(p.message_type, NBSS_MSGTYPE_SESSION_MESSAGE);
                assert_eq!(p.length, 41);
                assert_ne!(p.data.len(), 41);
                assert_ne!(p.message_type, NBSS_MSGTYPE_KEEP_ALIVE);

                // this packet had an acceptable length, we don't need more
                assert_eq!(p.needs_more(), false);

                // does this really look like smb?
                assert_eq!(p.is_smb(), true);

                // there should be nothing left
                assert_eq!(remainder.len(), 0);
            }
            Err(nom::Err::Error((_remainder, err))) => {
                panic!("Result should not be an error: {:?}.", err);
            }
            Err(nom::Err::Incomplete(_)) => {
                panic!("Result should not have returned as incomplete.");
            }
            _ => {
                panic!("Unexpected behavior!");
            }
        }

    }
}
