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

use nom::*;

named!(pub parse_message<String>,
       do_parse!(
           len: be_u8 >>
           msg: take_str!(len) >>
               (
                   msg.to_string()
               )
       ));

#[cfg(test)]
mod tests {

    use super::*;

    /// Simple test of some valid data.
    #[test]
    fn test_parse_valid() {
        let buf: &[u8] = &[
            0x0c, // '12'

            0x48, // H
            0x65, // e
            0x6c, // l
            0x6c, // l
            0x6f, // o
            0x20, // <space>
            0x57, // W
            0x6f, // o
            0x72, // r
            0x6c, // l
            0x64, // d
            0x21, // !

            0x04, // '4'

            0x42, // B
            0x79, // y
            0x65, // e
            0x2e, // .
        ];

        let result = parse_message(buf);
        match result {
            IResult::Done(remainder, message) => {
                // Check the first message.
                assert_eq!(message, "Hello World!");

                // And we should have 5 bytes left.
                assert_eq!(remainder.len(), 5);
            }
            IResult::Incomplete(_) => {
                panic!("Result should not have been incomplete.");
            }
            IResult::Error(err) => {
                panic!("Result should not be an error: {:?}.", err);
            }
        }
    }

}
