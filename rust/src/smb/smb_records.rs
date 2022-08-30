/* Copyright (C) 2018-2022 Open Information Security Foundation
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

use crate::common::nom7::take_until_and_consume;
use crate::smb::error::SmbError;
use nom7::{Err, IResult};

/// parse a UTF16 string that is null terminated. Normally by 2 null
/// bytes, but at the end of the data it can also be a single null.
/// Skip every second byte.
pub fn smb_get_unicode_string(blob: &[u8]) -> IResult<&[u8], Vec<u8>, SmbError>
{
    SCLogDebug!("get_unicode_string: blob {} {:?}", blob.len(), blob);
    let mut name : Vec<u8> = Vec::new();
    let mut c = blob;
    while c.len() >= 1 {
        if c.len() == 1 && c[0] == 0 {
            let rem = &c[1..];
            SCLogDebug!("get_unicode_string: name {:?}", name);
            return Ok((rem, name))
        } else if c.len() == 1 {
            break;
        } else if c[0] == 0 && c[1] == 0 {
            let rem = &c[2..];
            SCLogDebug!("get_unicode_string: name {:?}", name);
            return Ok((rem, name))
        }
        name.push(c[0]);
        c = &c[2..];
    }
    Err(Err::Error(SmbError::BadEncoding))
}

// parse an ASCII string that is null terminated
pub fn smb_get_ascii_string(i: &[u8]) -> IResult<&[u8], Vec<u8>, SmbError> {
    let (i, s) = take_until_and_consume(b"\x00")(i)?;
    Ok((i, s.to_vec()))
}

