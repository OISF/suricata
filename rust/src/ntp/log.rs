/* Copyright (C) 2026 Open Information Security Foundation
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

use super::ntp::NTPTransaction;
use crate::jsonbuilder::{JsonBuilder, JsonError};

fn log(jb: &mut JsonBuilder, tx: &NTPTransaction) -> Result<(), JsonError> {
    jb.open_object("ntp")?;
    jb.set_uint("version", tx.version)?;
    jb.set_uint("mode", tx.mode)?;
    jb.set_uint("stratum", tx.stratum)?;
    jb.set_string(
        "reference_id",
        &format!(
            "{:02x}:{:02x}:{:02x}:{:02x}",
            tx.reference_id[0], tx.reference_id[1], tx.reference_id[2], tx.reference_id[3]
        ),
    )?;
    jb.close()?;
    Ok(())
}

pub(super) unsafe extern "C" fn ntp_log_json(
    tx: *const std::os::raw::c_void, jb: *mut std::os::raw::c_void,
) -> bool {
    let tx = cast_pointer!(tx, NTPTransaction);
    let jb = cast_pointer!(jb, JsonBuilder);
    log(jb, tx).is_ok()
}
