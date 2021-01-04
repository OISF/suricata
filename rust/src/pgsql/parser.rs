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

 use nom::Err;
 use nom::error::ErrorKind;
 use nom::IResult;

pub const PGSQL_LENGTH_SIZE: usize = 4;
pub const PGSQL_PROTO_SIZE: usize = 4;

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
        let valid: bool = match self.proto_version_major {
            1 | 2 | 3 => true,
            _ => false,
        };
        valid
    }
}

named!(pub parse_pgsql_startup_packet<PGSQLStartupPacket>,
    do_parse!(
        len: bits!(take_bits!(32u32))
        >> proto_version: bits!(tuple!(
            take_bits!(16u16),
            take_bits!(16u16)))
        >> data: take!(len  as usize - PGSQL_LENGTH_SIZE - PGSQL_PROTO_SIZE)
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
    fn test_parse_pgsql_startup_packet() {
        // Startup message
        let buff:&[u8] = &[
        /* Length */ 0x00, 0x00, 0x00, 0x52,
        /* Protocol Version */ 0x00, 0x03, 0x00, 0x00,
        /* Data */  0x75, 0x73, 0x65, 0x72, 0x00, 0x69, 0x6e, 0x64, 0x65, 0x78,
                    0x65, 0x72, 0x00, 0x64, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73,
                    0x65, 0x00, 0x69, 0x6e, 0x64, 0x65, 0x78, 0x65, 0x72, 0x00,
                    0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f,
                    0x6e, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x00, 0x70, 0x73, 0x71,
                    0x6c, 0x00, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x5f, 0x65,
                    0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x00, 0x55, 0x54,
                    0x46, 0x38, 0x00, 0x00];

        let result = parse_pgsql_startup_packet(&buff);

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

}
