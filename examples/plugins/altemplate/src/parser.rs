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

// same file as rust/src/applayertemplate/parser.rs except this comment

use nom7::{
    bytes::streaming::{take, take_until},
    combinator::map_res,
    IResult,
};
use std;

fn parse_len(input: &str) -> Result<u32, std::num::ParseIntError> {
    input.parse::<u32>()
}

pub(super) fn parse_message(i: &[u8]) -> IResult<&[u8], String> {
    let (i, len) = map_res(map_res(take_until(":"), std::str::from_utf8), parse_len)(i)?;
    let (i, _sep) = take(1_usize)(i)?;
    let (i, msg) = map_res(take(len as usize), std::str::from_utf8)(i)?;
    let result = msg.to_string();
    Ok((i, result))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nom7::Err;

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
            Err(Err::Error(err)) | Err(Err::Failure(err)) => {
                panic!("Result should not be an error: {:?}.", err);
            }
        }
    }
}
