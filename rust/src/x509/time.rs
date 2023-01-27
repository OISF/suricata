/* Copyright (C) 2023 Open Information Security Foundation
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

use std::os::raw::c_char;
use time::macros::format_description;

/// Format a timestamp in an ISO format suitable for TLS logging.
///
/// Negative timestamp values are used for dates prior to 1970.
pub fn format_timestamp(timestamp: i64) -> Result<String, time::error::Error> {
    let format = format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]");
    let ts = time::OffsetDateTime::from_unix_timestamp(timestamp)?;
    let formatted = ts.format(&format)?;
    Ok(formatted)
}

/// Format a x509 ISO timestamp into the provided C buffer.
///
/// Returns false if an error occurs, otherwise true is returned if
/// the timestamp is properly formatted into the provided buffer.
///
/// # Safety
///
/// Access buffers from C that are expected to be valid.
#[no_mangle]
pub unsafe extern "C" fn sc_x509_format_timestamp(
    timestamp: i64, buf: *mut c_char, size: usize,
) -> bool {
    let timestamp = match format_timestamp(timestamp) {
        Ok(ts) => ts,
        Err(_) => return false,
    };
    crate::ffi::strings::copy_to_c_char(timestamp, buf, size)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_format_timestamp() {
        assert_eq!("1969-12-31T00:00:00", format_timestamp(-86400).unwrap());
        assert_eq!("2038-12-31T00:10:03", format_timestamp(2177367003).unwrap());
    }
}
