/* Copyright (C) 2020 Open Information Security Foundation
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

pub const PGSQL_LENGTH_SIZE: usize = 4;
pub const PGSQL_PROTO_SIZE: usize = 4;

// dummy code used for the frontend to signal an SSL handshake (04 d2 16 2f)
pub const PGSQL_SSL_DUMMY_PROTO_MAJOR: u16 = 1234;
pub const PGSQL_SSL_DUMMY_PROTO_MINOR: u16 = 5679;

// PostgreSQL Startup message packet
#[derive(Debug, PartialEq)]
pub struct PGSQLStartupPacket<'a> {
    pub length: u32,
    pub proto_version_major: u16,
    pub proto_version_minor: u16,
    pub data: &'a[u8],
}

impl<'a> PGSQLStartupPacket<'a> {
    
    pub fn is_valid(&self) -> bool {
        // currently, the protocol support only three major versions
        let valid_proto: bool = match self.proto_version_major {
            1 | 2 | 3 => true,
            _ => false,
        };
        valid_proto
    }
}

named!(pub parse_pgsql_startup_packet<PGSQLStartupPacket>,
    do_parse!(
        len: bits!(take_bits!(32u32))
        >> proto_version: bits!(tuple!(
            take_bits!(16u16),
            take_bits!(16u16)))
        >> data: take!(len as usize - (PGSQL_LENGTH_SIZE + PGSQL_PROTO_SIZE))
        >> (PGSQLStartupPacket {
            length: len,
            proto_version_major: proto_version.0,
            proto_version_minor: proto_version.1,
            data: data,
        })
));

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_parse_pgsql_startup_packet_complete() {
        // A valid Startup message
        let valid_buff:&[u8] = &[
        /* Length (82) */ 0x00, 0x00, 0x00, 0x52,
        /* Protocol Version */ 0x00, 0x03, 0x00, 0x00,
        /* Data */  0x75, 0x73, 0x65, 0x72, 0x00, 0x69, 0x6e, 0x64, 0x65, 0x78,
                    0x65, 0x72, 0x00, 0x64, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73,
                    0x65, 0x00, 0x69, 0x6e, 0x64, 0x65, 0x78, 0x65, 0x72, 0x00,
                    0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f,
                    0x6e, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x00, 0x70, 0x73, 0x71,
                    0x6c, 0x00, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x5f, 0x65,
                    0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x00, 0x55, 0x54,
                    0x46, 0x38, 0x00, 0x00];

        let result = parse_pgsql_startup_packet(&valid_buff);

        match result {
            Ok((remainder, packet)) => {
                assert_eq!(packet.length, 82);
                // data.len() after taking length and protcol away
                assert_eq!(packet.data.len(), 74);

                // there should be nothing left
                assert_eq!(remainder.len(), 0);

                // this packet has protocol version 3.0, so it is valid
                assert_eq!(packet.is_valid(), true);
            }
            Err(nom::Err::Error((remainder, err))) => {
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
    fn test_parse_pgsql_startup_packet_invalid_input() {
        // A non-valid Startup message. Length field is too short
        let invalid_length_field_buff:&[u8] = &[
        /* Length (7) */ 0x00, 0x00, 0x00, 0x07,
        /* Protocol Version */ 0x00, 0x03, 0x00];

        let result = parse_pgsql_startup_packet(&invalid_length_field_buff);

        match result {
            Ok((remainder, packet)) => {
                // this packet has length field too short so it is not valid
                assert_eq!(packet.is_valid(), false);
            }
            Err(nom::Err::Error((remainder, err))) => {
                panic!("Result should not be an error: {:?}.", err);
            }
            Err(nom::Err::Incomplete(needed)) => {
                assert!(invalid_length_field_buff.len() < 
                        (PGSQL_PROTO_SIZE + PGSQL_LENGTH_SIZE));
            }
            _ => {
                panic!("Unexpected behavior!");
            }
        }

        // A non-valid Startup message. Protocol version not allowed
        let invalid_proto_version_buff:&[u8] = &[
        /* Length (38) */       0x00, 0x00, 0x00, 0x26,
        /* Protocol Version */  0x00, 0x12, 0x00, 0x00,
        /* Data */  0x75, 0x73, 0x65, 0x72, 0x00, 0x69, 0x6e, 0x64, 0x65, 0x78,
                    0x65, 0x72, 0x00, 0x64, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73,
                    0x65, 0x00, 0x69, 0x6e, 0x64, 0x65, 0x78, 0x65, 0x72, 0x00];

        let result = parse_pgsql_startup_packet(&invalid_proto_version_buff);

        match result {
            Ok((remainder, packet)) => {
                // this packet has a protocol major version not supported ( > 3)
                assert_eq!(packet.is_valid(), false);

                // length shouldn't be an issue here
                assert_eq!(packet.length, 38);

                // there should be nothing left
                assert_eq!(remainder.len(), 0);
            }
            Err(nom::Err::Error((remainder, err))) => {
                panic!("Result should not be an error: {:?}.", err);
            }
            Err(nom::Err::Incomplete(needed)) => {
                panic!("Should be Ok, but needs {:?}", needed);
            }
            _ => {
                panic!("Unexpected behavior!");
            }
        }

        // A non-valid Startup message. Data length < length field indicates
        let invalid_data_length_buff:&[u8] = &[
        /* Length (38) */       0x00, 0x00, 0x00, 0x26,
        /* Protocol Version */  0x00, 0x12, 0x00, 0x00,
        /* Data */  0x75, 0x73, 0x65, 0x72, 0x00, 0x69, 0x6e, 0x64, 0x65, 0x78,
                    0x65, 0x72, 0x00, 0x64, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73,
                    0x72, 0x00, 0x64, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73];

        let result = parse_pgsql_startup_packet(&invalid_data_length_buff);

        match result {
            Ok((remainder, packet)) => {
                panic!("Data field wasn't complete, shouldn't have parsed Ok");
            }
            Err(nom::Err::Error((remainder, err))) => {
                panic!("Result should not be an error: {:?}.", err);
            }
            Err(nom::Err::Incomplete(needed)) => {
                assert_eq!(needed, nom::Needed::Size(30));
            }
            _ => {
                panic!("Unexpected behavior!");
            }
        }
    }
}
