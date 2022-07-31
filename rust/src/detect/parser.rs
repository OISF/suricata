/* Copyright (C) 2022 Open Information Security Foundation
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

use crate::detect::error::RuleParseError;

use nom7::bytes::complete::is_not;
use nom7::character::complete::multispace0;
use nom7::sequence::preceded;
use nom7::IResult;

static WHITESPACE: &str = " \t\r\n";
/// Parse all characters up until the next whitespace character.
pub fn take_until_whitespace(input: &str) -> IResult<&str, &str, RuleParseError<&str>> {
    nom7::bytes::complete::is_not(WHITESPACE)(input)
}

/// Parse the next token ignoring leading whitespace.
///
/// A token is the next sequence of chars until a terminating character. Leading whitespace
/// is ignore.
pub fn parse_token(input: &str) -> IResult<&str, &str, RuleParseError<&str>> {
    let terminators = "\n\r\t,;: ";
    preceded(multispace0, is_not(terminators))(input)
}
