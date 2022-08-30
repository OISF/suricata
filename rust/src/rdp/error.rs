/* Copyright (C) 2019-2022 Open Information Security Foundation
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

// Author: Zach Kelly <zach.kelly@lmco.com>
// Author: Pierre Chifflier <chifflier@wzdftpd.net>
use nom::error::{ErrorKind, ParseError};

#[derive(Debug, PartialEq)]
pub enum RdpError {
    UnimplementedLengthDeterminant,
    NotX224Class0Error,
    NomError(ErrorKind),
}

impl<I> ParseError<I> for RdpError {
    fn from_error_kind(_input: I, kind: ErrorKind) -> Self {
        RdpError::NomError(kind)
    }
    fn append(_input: I, kind: ErrorKind, _other: Self) -> Self {
        RdpError::NomError(kind)
    }
}

impl nom::ErrorConvert<RdpError> for ((&[u8], usize), ErrorKind) {
    fn convert(self) -> RdpError {
        RdpError::NomError(self.1)
    }
}
