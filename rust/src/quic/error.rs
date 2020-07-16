/* Copyright (C) 2020 Open Information Security Foundation
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

#[derive(Debug, PartialEq)]
pub enum QuicError {
    InvalidPacket,
    Parse(String),
}

macro_rules! nom_to_quicerror {
    ($typ:ty) => {
        impl From<::nom::Err<($typ, ::nom::error::ErrorKind)>> for QuicError {
            fn from(err: ::nom::Err<($typ, ::nom::error::ErrorKind)>) -> Self {
                let msg = match err {
                    ::nom::Err::Incomplete(needed) => match needed {
                        ::nom::Needed::Size(_v) => format!("incomplete data, needs more"),
                        ::nom::Needed::Unknown => format!("incomplete data"),
                    },
                    ::nom::Err::Error(e) | ::nom::Err::Failure(e) => {
                        format!("parsing error has occurred: {}", e.1.description())
                    }
                };

                QuicError::Parse(msg)
            }
        }
    };
}

nom_to_quicerror!(&[u8]);
