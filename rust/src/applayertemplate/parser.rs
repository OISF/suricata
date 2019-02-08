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

use std;

fn parse_len(input: &str) -> Result<u32, std::num::ParseIntError> {
    input.parse::<u32>()
}

named!(pub parse_message<String>,
       do_parse!(
           len:  map_res!(
                 map_res!(take_until_s!(":"), std::str::from_utf8), parse_len) >>
           _sep: take!(1) >>
           msg:  take_str!(len) >>
               (
                   msg.to_string()
               )
       ));

#[cfg(test)]
mod tests {

    use nom::*;
    use super::*;

    /// Simple test of some valid data.
    #[test]
    fn test_parse_valid() {
        let buf = b"12:Hello World!4:Bye.";

        let result = parse_message(buf);
        match result {
            Ok((remainder, message)) => {
                // Check the first message.
                assert_eq!(message, "Hello World!");

                // And we should have 6 bytes left.
                assert_eq!(remainder.len(), 6);
            }
            Err(Err::Incomplete(_)) => {
                panic!("Result should not have been incomplete.");
            }
            Err(Err::Error(err)) |
            Err(Err::Failure(err)) => {
                panic!("Result should not be an error: {:?}.", err);
            }
        }
    }

}
