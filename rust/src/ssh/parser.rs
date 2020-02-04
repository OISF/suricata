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

//nom5 use nom::bytes::complete::is_not;
use nom::{be_u32, be_u8, rest};

//may leave \r at the end to be removed
named!(pub ssh_parse_line<&[u8], &[u8]>,
    terminated!(
        is_not!("\r\n"),
        alt!( tag!("\n") | tag!("\r\n") |
              do_parse!(
                    bytes: tag!("\r") >>
                    not!(eof!()) >> (bytes)
                )
            )
    )
);

#[derive(PartialEq)]
pub struct SshBanner<'a> {
    pub protover: &'a [u8],
    pub swver: &'a [u8],
}

impl<'a> SshBanner<'a> {}

// Could be simplified adding dummy \n at the end
// or use nom5 nom::bytes::complete::is_not
named!(pub ssh_parse_banner<SshBanner>,
    do_parse!(
        tag!("SSH-") >>
        protover: alt!(is_not!("-") | rest) >>
        opt!( complete!( char!('-') ) ) >>
        swver: alt!( rest | eof!() ) >>
        (SshBanner{protover, swver})
    )
);

#[derive(PartialEq)]
pub struct SshRecordHeader {
    pub pkt_len: u32,
    padding_len: u8,
    pub msg_code: u8,
}

named!(pub ssh_parse_record_header<SshRecordHeader>,
    do_parse!(
        pkt_len: verify!(be_u32, |val:u32| val > 1) >>
        padding_len: be_u8 >>
        msg_code: be_u8 >>
        (SshRecordHeader{pkt_len, padding_len, msg_code})
    )
);

named!(pub ssh_parse_record<SshRecordHeader>,
    do_parse!(
        pkt_len: verify!(be_u32, |val:u32| val > 1) >>
        padding_len: be_u8 >>
        msg_code: be_u8 >>
        take!((pkt_len-2) as usize) >>
        (SshRecordHeader{pkt_len, padding_len, msg_code})
    )
);

#[cfg(test)]
mod tests {

    use super::*;

    /// Simple test of some valid data.
    #[test]
    fn test_ssh_parse_banner() {
        let buf = b"SSH-Single-";
        let result = ssh_parse_banner(buf);
        match result {
            Ok((_, message)) => {
                // Check the first message.
                assert_eq!(message.protover, b"Single");
                assert_eq!(message.swver, b"");
            }
            Err(err) => {
                panic!("Result should not be an error: {:?}.", err);
            }
        }
        let buf2 = b"SSH-2.0-Soft";
        let result2 = ssh_parse_banner(buf2);
        match result2 {
            Ok((_, message)) => {
                // Check the first message.
                assert_eq!(message.protover, b"2.0");
                assert_eq!(message.swver, b"Soft");
            }
            Err(err) => {
                panic!("Result should not be an error: {:?}.", err);
            }
        }
    }

    #[test]
    fn test_parse_line() {
        let buf = b"SSH-Single\n";
        let result = ssh_parse_line(buf);
        match result {
            Ok((_, message)) => {
                // Check the first message.
                assert_eq!(message, b"SSH-Single");
            }
            Err(err) => {
                panic!("Result should not be an error: {:?}.", err);
            }
        }
        let buf2 = b"SSH-Double\r\n";
        let result2 = ssh_parse_line(buf2);
        match result2 {
            Ok((_, message)) => {
                // Check the first message.
                assert_eq!(message, b"SSH-Double");
            }
            Err(err) => {
                panic!("Result should not be an error: {:?}.", err);
            }
        }
        let buf3 = b"SSH-Oops\rMore\r\n";
        let result3 = ssh_parse_line(buf3);
        match result3 {
            Ok((_, message)) => {
                // Check the first message.
                assert_eq!(message, b"SSH-Oops");
            }
            Err(err) => {
                panic!("Result should not be an error: {:?}.", err);
            }
        }
        let buf4 = b"SSH-Miss\r";
        let result4 = ssh_parse_line(buf4);
        match result4 {
            Ok((_, _)) => {
                panic!("Expected incomplete result");
            }
            Err(nom::Err::Incomplete(_)) => {
                //OK
                assert_eq!(1, 1);
            }
            Err(err) => {
                panic!("Result should not be an error: {:?}.", err);
            }
        }
    }

}
