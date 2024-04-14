/* Copyright (C) 2024 Open Information Security Foundation
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

use crate::detect::uint::{DetectIntType, DetectUintData, DetectUintMode};
use crate::jsonbuilder::{JsonBuilder, JsonError};

pub fn detect_uint_to_json<T: DetectIntType>(
    js: &mut JsonBuilder, du: &DetectUintData<T>,
) -> Result<(), JsonError>
where
    u64: From<T>,
{
    match du.mode {
        DetectUintMode::DetectUintModeEqual => {
            js.set_uint("equal", du.arg1.into())?;
        }
        DetectUintMode::DetectUintModeNe => {
            js.set_uint("diff", du.arg1.into())?;
        }
        DetectUintMode::DetectUintModeLt => {
            js.set_uint("lt", du.arg1.into())?;
        }
        DetectUintMode::DetectUintModeLte => {
            js.set_uint("lte", du.arg1.into())?;
        }
        DetectUintMode::DetectUintModeGt => {
            js.set_uint("gt", du.arg1.into())?;
        }
        DetectUintMode::DetectUintModeGte => {
            js.set_uint("gte", du.arg1.into())?;
        }
        DetectUintMode::DetectUintModeRange => {
            js.open_object("range")?;
            js.set_uint("min", du.arg1.into())?;
            js.set_uint("max", du.arg2.into())?;
            js.close()?;
        }
        DetectUintMode::DetectUintModeNegRg => {
            js.open_object("negated_range")?;
            js.set_uint("min", du.arg1.into())?;
            js.set_uint("max", du.arg2.into())?;
            js.close()?;
        }
        DetectUintMode::DetectUintModeBitmask => {
            js.open_object("bitmask")?;
            js.set_uint("mask", du.arg1.into())?;
            js.set_uint("value", du.arg2.into())?;
            js.close()?;
        }
        DetectUintMode::DetectUintModeNegBitmask => {
            js.open_object("negated_bitmask")?;
            js.set_uint("mask", du.arg1.into())?;
            js.set_uint("value", du.arg2.into())?;
            js.close()?;
        }
    }
    Ok(())
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectU16ToJson(
    js: &mut JsonBuilder, du: &DetectUintData<u16>,
) -> bool {
    return detect_uint_to_json(js, du).is_ok();
}
