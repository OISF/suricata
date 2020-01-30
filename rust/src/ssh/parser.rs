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

use nom::line_ending;

named!(pub ssh_parse_banner<&[u8], &[u8]>,
    terminated!(
        is_not!("\r\n"),
        line_ending
    )
);

#[cfg(test)]
mod tests {

    use super::*;

    /// Simple test of some valid data.
    #[test]
    fn test_parse_banner() {
        let buf = b"SSH-Single\n";
        let result = ssh_parse_banner(buf);
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
        let result2 = ssh_parse_banner(buf2);
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
        let result3 = ssh_parse_banner(buf3);
        match result3 {
            Ok((_, message)) => {
                // Check the first message.
                assert_eq!(message, b"SSH-Oops\rMore");
            }
            Err(err) => {
                panic!("Result should not be an error: {:?}.", err);
            }
        }
    }

}
