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

use nom8::bytes::complete::is_not;
use nom8::character::complete::multispace0;
use nom8::sequence::preceded;
use nom8::{IResult, Parser};

#[derive(Debug)]
pub enum ResultValue {
    Numeric(u64),
    String(String),
}

static WHITESPACE: &str = " \t\r\n";
/// Parse all characters up until the next whitespace character.
pub fn take_until_whitespace(input: &str) -> IResult<&str, &str, RuleParseError<&str>> {
    nom8::bytes::complete::is_not(WHITESPACE).parse(input)
}

// Parsed as a u64 so the value can be validated against a u32 min/max if needed.
pub fn parse_var(input: &str) -> IResult<&str, ResultValue, RuleParseError<&str>> {
    let (input, value) = parse_token(input)?;
    if let Ok(val) = value.parse::<u64>() {
        Ok((input, ResultValue::Numeric(val)))
    } else {
        Ok((input, ResultValue::String(value.to_string())))
    }
}
/// Parse the next token ignoring leading whitespace.
///
/// A token is the next sequence of chars until a terminating character. Leading whitespace
/// is ignore.
pub fn parse_token(input: &str) -> IResult<&str, &str, RuleParseError<&str>> {
    let terminators = "\n\r\t,;: ";
    preceded(multispace0, is_not(terminators)).parse(input)
}
