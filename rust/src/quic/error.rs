/* Copyright (C) 2021 Open Information Security Foundation
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
use nom7::Err;
use std::error::Error;
use std::fmt;

#[derive(Debug, PartialEq)]
pub enum QuicError {
    StreamTagNoMatch(u32),
    InvalidPacket,
    Incomplete,
    NomError(ErrorKind),
}

impl<I> ParseError<I> for QuicError {
    fn from_error_kind(_input: I, kind: ErrorKind) -> Self {
        QuicError::NomError(kind)
    }

    fn append(_input: I, kind: ErrorKind, _other: Self) -> Self {
        QuicError::NomError(kind)
    }
}

impl fmt::Display for QuicError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QuicError::StreamTagNoMatch(tag) => {
                write!(f, "Could not match stream tag: 0x{:x}", tag)
            }
            QuicError::Incomplete => write!(f, "Incomplete data"),
            QuicError::InvalidPacket => write!(f, "Invalid packet"),
            QuicError::NomError(e) => write!(f, "Internal parser error {:?}", e),
        }
    }
}

impl Error for QuicError {}

impl From<Err<QuicError>> for QuicError {
    fn from(err: Err<QuicError>) -> Self {
        match err {
            Err::Incomplete(_) => QuicError::Incomplete,
            Err::Error(e) => e,
            Err::Failure(e) => e,
        }
    }
}
