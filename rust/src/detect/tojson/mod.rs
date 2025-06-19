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
    let arg1: u64 = du.arg1.into();
    let arg2: u64 = du.arg2.into();
    match du.mode {
        DetectUintMode::DetectUintModeEqual => {
            js.set_uint("equal", arg1)?;
        }
        DetectUintMode::DetectUintModeNe => {
            js.set_uint("diff", arg1)?;
        }
        DetectUintMode::DetectUintModeLt => {
            js.set_uint("lt", arg1)?;
        }
        DetectUintMode::DetectUintModeLte => {
            js.set_uint("lte", arg1)?;
        }
        DetectUintMode::DetectUintModeGt => {
            js.set_uint("gt", arg1)?;
        }
        DetectUintMode::DetectUintModeGte => {
            js.set_uint("gte", arg1)?;
        }
        DetectUintMode::DetectUintModeRange => {
            js.open_object("range")?;
            js.set_uint("min", arg1)?;
            js.set_uint("max", arg2)?;
            js.close()?;
        }
        DetectUintMode::DetectUintModeNegRg => {
            js.open_object("negated_range")?;
            js.set_uint("min", arg1)?;
            js.set_uint("max", arg2)?;
            js.close()?;
        }
        DetectUintMode::DetectUintModeBitmask => {
            js.open_object("bitmask")?;
            js.set_uint("mask", arg1)?;
            js.set_uint("value", arg2)?;
            js.close()?;
        }
        DetectUintMode::DetectUintModeNegBitmask => {
            js.open_object("negated_bitmask")?;
            js.set_uint("mask", arg1)?;
            js.set_uint("value", arg2)?;
            js.close()?;
        }
    }
    Ok(())
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectU8ToJson(
    js: &mut JsonBuilder, du: &DetectUintData<u8>,
) -> bool {
    return detect_uint_to_json(js, du).is_ok();
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectU16ToJson(
    js: &mut JsonBuilder, du: &DetectUintData<u16>,
) -> bool {
    return detect_uint_to_json(js, du).is_ok();
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectU32ToJson(
    js: &mut JsonBuilder, du: &DetectUintData<u32>,
) -> bool {
    return detect_uint_to_json(js, du).is_ok();
}
