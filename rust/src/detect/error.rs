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

use nom7::error::{ErrorKind, ParseError};

/// Custom rule parse errors.
///
/// Implemented based on the Nom example for implementing custom errors.
/// The string is an error message provided by the parsing logic, e.g.,
///      Incorrect usage because of "x", "y" and "z"
#[derive(Debug, PartialEq, Eq)]
pub enum RuleParseError<I> {
    InvalidByteMath(String),
    InvalidIPRep(String),
    InvalidTransformBase64(String),
    InvalidByteExtract(String),
    InvalidEntropy(String),

    Nom(I, ErrorKind),
}
impl<I> ParseError<I> for RuleParseError<I> {
    fn from_error_kind(input: I, kind: ErrorKind) -> Self {
        RuleParseError::Nom(input, kind)
    }

    fn append(_: I, _: ErrorKind, other: Self) -> Self {
        other
    }
}
