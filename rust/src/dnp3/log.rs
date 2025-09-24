/* Copyright (C) 2025 Open Information Security Foundation
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

use crate::detect::EnumString;
use crate::jsonbuilder::{JsonBuilder, JsonError};

use super::detect::Dnp3IndFlag;

fn log_iin(js: &mut JsonBuilder, iin: u16) -> Result<(), JsonError> {
    js.open_array("indicators")?;

    for i in 0..16 {
        if (iin & (1 << i)) != 0 {
            let ind = Dnp3IndFlag::from_u(1 << i).unwrap();
            js.append_string(ind.to_str())?;
        }
    }
    js.close()?;
    Ok(())
}

#[no_mangle]
pub unsafe extern "C" fn SCJsonDNP3LogIin(js: &mut JsonBuilder, iin: u16) -> bool {
    if iin == 0 {
        return false;
    }
    log_iin(js, iin).is_ok()
}
