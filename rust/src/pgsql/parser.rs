/* Copyright (C) 2021 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Prog optional_params: ()ram under the terms of
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

use nom::{number::{complete::{be_u8, be_u16, be_u32}}};
use nom;
use nom::Err;
use nom::IResult;
use nom::error::ErrorKind;
use nom::combinator::rest;

pub const PGSQL_LENGTH_SIZE: usize = 4;
pub const PGSQL_PROTO_SIZE: usize = 4;

// dummy code used for the frontend to signal a Cancellation request
pub const PGSQL_CANCEL_DUMMY_PROTO_MAJOR: u16 = 1234;
pub const PGSQL_CANCEL_DUMMY_PROTO_MINOR: u16 = 5678;

// dummy code used for the frontend to signal an SSL handshake (04 d2 16 2f)
pub const PGSQL_SSL_DUMMY_PROTO_MAJOR: u16 = 1234;
pub const PGSQL_SSL_DUMMY_PROTO_MINOR: u16 = 5679;

// dummy code used for the frontend to signal a GSSAPI handshake
pub const PGSQL_GSSAPI_DUMMY_PROTO_MAJOR: u16 = 1234;
pub const PGSQL_GSSAPI_DUMMY_PROTO_MINOR: u16 = 5680;

// Identify whether a field or parameter is in Text (0) or Binary (1) type
pub const PGSQL_FORMAT_CODE_TEXT:   u16 = 0x0000;
pub const PGSQL_FORMAT_CODE_BINARY: u16 = 0x0001;

// PostgreSQL Startup message packet. Isn't it better if we call it header?
#[derive(Debug, PartialEq)]
pub struct PGSQLStartupPacket<'a> {
    pub length: u32, // TODO find out what is the maximum allowed length
    pub proto_version_major: u16,
    pub proto_version_minor: u16,
    pub params: PGSQLStartupParams,
    pub data: &'a[u8],
}

impl<'a> PGSQLStartupPacket<'a> {
    
    pub fn is_valid(&self) -> bool {
        // currently, the protocol support only three major versions
        let valid_proto: bool = match self.proto_version_major {
            1 | 2 | 3 => true,
            _ => false,
        };
        let valid_length = if self.length <= 8 { false } else { true };
        valid_proto && valid_length
    }
}

#[derive(Debug, PartialEq)]
pub struct PGSQLParamValue {
    param_name: Vec<u8>,
    param_value: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub struct PGSQLStartupParams {
    user: PGSQLParamValue,
    database: PGSQLParamValue,
}

named!(pub parse_startup_param_user<PGSQLParamValue>,
    do_parse!(
        user_tag: complete!(tag!("user"))
        >> complete!(complete!(tag!("\x00")))
        >> user: complete!(take_until1!("\x00"))
        >> return_error!(complete!(tag!("\x00")))
        >> (PGSQLParamValue{
            param_name: user_tag.to_vec(),
            param_value: user.to_vec(),
        })
));

named!(pub parse_startup_param_database<PGSQLParamValue>,
    do_parse!(
        key: complete!(tag!("database"))
        >> return_error!(complete!(tag!("\x00")))
        >> value: complete!(take_until1!("\x00"))
        >> return_error!(complete!(tag!("\x00")))
        >> (PGSQLParamValue {
            param_name: key.to_vec(),
            param_value: value.to_vec(),
        })
));

// TODO future versions should read more parameters. For now, just user and database 
named!(pub parse_startup_params<PGSQLStartupParams>,
    do_parse!(
        user: dbg_dmp!(parse_startup_param_user) //TODO understand if I have to do something else, considering user's position isn't fixed.
        >> database: dbg_dmp!(parse_startup_param_database)
        >> (PGSQLStartupParams{
            user: user,
            database: database,
        })
));

named!(pub parse_pgsql_startup_packet<PGSQLStartupPacket>,
    do_parse!(
        len: verify!(be_u32,|&x| x >= 8)
        >> proto_version_major: be_u16
        >> proto_version_minor: be_u16
        >> params: parse_startup_params
        //>> data: take!(len as usize - (PGSQL_PROTO_SIZE + PGSQL_LENGTH_SIZE))
        >> data: rest
        >> (PGSQLStartupPacket {
            length: len,
            proto_version_major: proto_version_major,
            proto_version_minor: proto_version_minor,
            params: params,
            data: data,
        })
));

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_param_database_param_valid() {
        let key_value_pair: &[u8] = &[
        /* database */  0x64, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65, 0x00,
        /* value */     0x69, 0x6e, 0x64, 0x65, 0x78, 0x65, 0x72, 0x00, 0x00];
        
        let result = parse_startup_param_database(&key_value_pair);

        match result {
            Ok((remainder, value)) => {
                assert_eq!(std::str::from_utf8(&value.param_name).unwrap(), "database");
                assert_eq!(std::str::from_utf8(&value.param_value).unwrap(), "indexer");
                assert_eq!(remainder.len(), 1);
                assert_eq!(remainder, [0x00]);
            }
            Err(nom::Err::Error((remainder, err))) => {
                panic!("Result should not be an error: {:?}.", err);
            }
            Err(nom::Err::Incomplete(needed)) => {
                panic!("Incomplete! {:?}", needed);
            }
            default => {
                panic!("Unexpected behavior!");
            }
        }

        let key_value_pair: &[u8] = &[
        /* database */  0x64, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65, 0x00,
        /* value */     0x69, 0x6e, 0x64, 0x65, 0x78, 0x65, 0x72, 0x00];
        
        let result = parse_startup_param_database(&key_value_pair);

        match result {
            Ok((remainder, value)) => {
                assert_eq!(std::str::from_utf8(&value.param_name).unwrap(), "database");
                assert_eq!(std::str::from_utf8(&value.param_value).unwrap(), "indexer");
                assert_eq!(remainder.len(), 0);
            }
            Err(nom::Err::Error((remainder, err))) => {
                panic!("Result should not be an error: {:?}.", err);
            }
            Err(nom::Err::Incomplete(needed)) => {
                panic!("Incomplete! {:?}", needed);
            }
            default => {
                panic!("Unexpected behavior!");
            }
        }
    }

    #[test]
    fn test_param_database_invalid() {
        let key_value_pair: &[u8] = &[
        /* database */  0x64, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65, 0x00,
        /* value */     0x69, 0x6e, 0x64, 0x65, 0x78, 0x65, 0x72];
        
        let result = parse_startup_param_database(&key_value_pair);

        match result {
            Ok((remainder, value)) => {
                panic!("Result should not be Ok(), input is missing 0 byte end.");
            }
            Err(Err::Error((remainder, err))) => {
                assert_eq!(err, nom::error::ErrorKind::Complete);
            }
            Err(nom::Err::Incomplete(needed)) => {
                panic!("Incomplete! {:?}", needed);
            }
            default => {
                panic!("Unexpected behavior!");
            }
        }
    }

    #[test]
    fn test_parse_valid_user_name() {
        let key_value_pair: &[u8] = &[
            /* user */      0x75, 0x73, 0x65, 0x72, 0x00,
            /* value */     0x69, 0x6e, 0x64, 0x65, 0x78, 0x65, 0x72, 0x00];

        let result = parse_startup_param_user(&key_value_pair);

        match result {
            Ok((remainder, value)) => {
                assert_eq!(std::str::from_utf8(&value.param_name).unwrap(), "user");
                assert_eq!(std::str::from_utf8(&value.param_value).unwrap(), "indexer");
                assert_eq!(remainder.len(), 0);
            }
            Err(nom::Err::Error((remainder, err))) => {
                panic!("Result should not be an error: {:?}.", err);
            }
            Err(nom::Err::Incomplete(needed)) => {
                panic!("Incomplete! {:?}", needed);
            }
            default => {
                panic!("Unexpected behavior!");
            }
        }
    }

    #[test]
    fn test_parse_invalid_user_tag() {
        // missing 0x00 after "user"
        let key_value_pair: &[u8] = &[
            /* user */      0x75, 0x73, 0x65, 0x72,
            /* value */     0x69, 0x6e, 0x64, 0x65, 0x78, 0x65, 0x72, 0x00];

        let result = parse_startup_param_user(&key_value_pair);

        match result {
            Ok((remainder, value)) => {
                panic!("Missing a ' ' tag, shouldn't be Ok()");
            }
            Err(nom::Err::Error((remainder, err))) => {
                assert_eq!(err, nom::error::ErrorKind::Tag);
            }
            Err(nom::Err::Incomplete(needed)) => {
                panic!("Should not be incomplete! {:?}", needed);
            }
            default => {
                panic!("Unexpected behavior!");
            }
        }
    }

    #[test]
    fn test_parse_invalid_user_param_invalid_end() {
        // missing 0x00 at the end...
        let key_value_pair: &[u8] = &[
            /* user */      0x75, 0x73, 0x65, 0x72, 0x00,
            /* value */     0x69, 0x6e, 0x64, 0x65, 0x78, 0x65, 0x72];

        let result = parse_startup_param_user(&key_value_pair);

        match result {
            Ok((remainder, value)) => {
                panic!("Missing a ' ' tag, shouldn't be Ok()");
            }
            Err(nom::Err::Error((remainder, err))) => {
                assert_eq!(err, nom::error::ErrorKind::Complete);
            }
            Err(nom::Err::Incomplete(needed)) => {
                panic!("Should not be incomplete! {:?}", needed);
            }
            default => {
                panic!("Unexpected behavior!");
            }
        }
    }

    #[test]
    fn test_parse_multiple_valid_params(){
        let key_value_pairs: &[u8] = &[
            /* user */      0x75, 0x73, 0x65, 0x72, 0x00,
            /* value */     0x69, 0x6e, 0x64, 0x65, 0x78, 0x65, 0x72, 0x00,
            /* database */  0x64, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65, 0x00,
            /* value */     0x69, 0x6e, 0x64, 0x65, 0x78, 0x65, 0x72, 0x00];

        let result = parse_startup_params(&key_value_pairs);

        match result {
            Ok((remainder, value)) => {
                assert_eq!(std::str::from_utf8(&value.user.param_name).unwrap(), "user");
                assert_eq!(std::str::from_utf8(&value.user.param_value).unwrap(), "indexer");
                assert_eq!(std::str::from_utf8(&value.database.param_name).unwrap(), "database");
                assert_eq!(std::str::from_utf8(&value.database.param_value).unwrap(), "indexer");
                assert_eq!(remainder.len(), 0);
            }
            Err(nom::Err::Error((remainder, err))) => {
                panic!("Result should not be an error: {:?}.", err);
            }
            Err(nom::Err::Incomplete(needed)) => {
                panic!("Incomplete! {:?}", needed);
            }
            default => {
                panic!("Unexpected behavior!");
            }
        }

        let key_value_pairs: &[u8] = &[
        /* user */      0x75, 0x73, 0x65, 0x72, 0x00,
        /* value */     0x69, 0x6e, 0x64, 0x65, 0x78, 0x65, 0x72, 0x00,
        /* database */  0x64, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65, 0x00,
        /* value */     0x69, 0x6e, 0x64, 0x65, 0x78, 0x65, 0x72, 0x00, 
        /* data */      0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69,
                        0x6f, 0x6e, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x00, 0x70, 
                        0x73, 0x71, 0x6c, 0x00, 0x63, 0x6c, 0x69, 0x65, 0x6e, 
                        0x74, 0x5f, 0x65, 0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 
                        0x67, 0x00, 0x55, 0x54, 0x46, 0x38, 0x00, 0x00];

        let result = parse_startup_params(&key_value_pairs);

        match result {
            Ok((remainder, value)) => {
                assert_eq!(std::str::from_utf8(&value.user.param_name).unwrap(), "user");
                assert_eq!(std::str::from_utf8(&value.user.param_value).unwrap(), "indexer");
                assert_eq!(std::str::from_utf8(&value.database.param_name).unwrap(), "database");
                assert_eq!(std::str::from_utf8(&value.database.param_value).unwrap(), "indexer");
                assert_eq!(remainder.len(), 44);
            }
            Err(nom::Err::Error((remainder, err))) => {
                panic!("Result should not be an error: {:?}.", err);
            }
            Err(nom::Err::Incomplete(needed)) => {
                panic!("Incomplete! {:?}", needed);
            }
            default => {
                panic!("Unexpected behavior!");
            }
        }
    }

    #[test]
    // TODO this isn't really testing the complete parsing, yet, for we don't parse the data here. right?
    fn test_parse_pgsql_startup_packet_complete() {
        // A valid Startup message
        let valid_buff: &[u8] = &[
        /* Length (82) */ 0x00, 0x00, 0x00, 0x52,
        /* Protocol Version */ 0x00, 0x03, 0x00, 0x00,
        /* user */      0x75, 0x73, 0x65, 0x72, 0x00,
        /* value */     0x69, 0x6e, 0x64, 0x65, 0x78, 0x65, 0x72, 0x00, 
        /* database */  0x64, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65, 0x00,
        /* value */     0x69, 0x6e, 0x64, 0x65, 0x78, 0x65, 0x72, 0x00,
        /* Data */      0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f,
                        0x6e, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x00, 0x70, 0x73, 0x71,
                        0x6c, 0x00, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x5f, 0x65,
                        0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x00, 0x55, 0x54,
                        0x46, 0x38, 0x00, 0x00];

        let result = parse_pgsql_startup_packet(&valid_buff);

        match result {
            Ok((remainder, packet)) => {
                assert_eq!(packet.length, 82);
                // "Data" here is what is left after we have parsed username 
                // // and database name, too. 
                assert_eq!(packet.data.len(), 44);

                // there should be nothing left
                assert_eq!(remainder.len(), 0); // TODO FIX

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
    fn test_parse_pgsql_startup_packet_invalid_input1() {
        // A non-valid Startup message. Length field is too short
        let invalid_length_field_buff:&[u8] = &[
        /* Length (1) */ 0x00, 0x00, 0x00, 0x01,
        /* Protocol Version */ 0x00, 0x03, 0x00, 0x00,
        /* Data */  0x65, 0x72, 0x00, 0x64, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73,
                    0x65, 0x00, 0x69, 0x6e, 0x64, 0x65, 0x78, 0x65, 0x72, 0x00];

        let result = parse_pgsql_startup_packet(&invalid_length_field_buff);

        match result {
            Ok((remainder, packet)) => {
                panic!("Expected match with Err.");
            }
            Err(nom::Err::Error((remainder, err))) => {
                assert_eq!(err, nom::error::ErrorKind::Verify);
            }
            Err(nom::Err::Incomplete(needed)) => {
                panic!("Should throw error, length is too short.");
            }
            _ => {
                panic!("Unexpected behavior!");
            }
        }
    }

    #[test]
    fn test_parse_pgsql_startup_packet_invalid_input2() {

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
    }

    #[test]
    fn test_parse_pgsql_startup_packet_incomplete() {
        // A non-valid Startup message. Data length < length field indicates
        let invalid_data_length_buff:&[u8] = &[
        /* Length (38) */       0x00, 0x00, 0x00, 0x26,
        /* Protocol Version */  0x00, 0x12, 0x00, 0x00,
        /* Data */  0x75, 0x73, 0x65, 0x72, 0x00, 0x69, 0x6e, 0x64, 0x65, 0x78,
                    0x65, 0x72, 0x00, 0x64, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73,
                    0x65, 0x00, 0x64, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65];

        let result = parse_pgsql_startup_packet(&invalid_data_length_buff);

        match result {
            Ok((remainder, packet)) => {
                panic!("Data field wasn't complete, shouldn't have parsed Ok");
            }
            Err(nom::Err::Error((remainder, err))) => {
                assert_eq!(err, nom::error::ErrorKind::Complete);
            }
            Err(nom::Err::Incomplete(needed)) => {
                panic!("Should not be considered incomplete.")
            }
            _ => {
                panic!("Unexpected behavior!");
            }
        }
    }
}
