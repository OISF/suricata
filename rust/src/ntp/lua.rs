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

use std::os::raw::c_int;

use super::ntp::NTPTransaction;
use crate::lua::*;

#[no_mangle]
pub extern "C" fn SCNtpLuaGetVersion(clua: &mut CLuaState, tx: &mut NTPTransaction) -> c_int {
    let lua = LuaState { lua: clua };
    lua.pushinteger(tx.version as i64);
    1
}

#[no_mangle]
pub extern "C" fn SCNtpLuaGetMode(clua: &mut CLuaState, tx: &mut NTPTransaction) -> c_int {
    let lua = LuaState { lua: clua };
    lua.pushinteger(tx.mode as i64);
    1
}

#[no_mangle]
pub extern "C" fn SCNtpLuaGetStratum(clua: &mut CLuaState, tx: &mut NTPTransaction) -> c_int {
    let lua = LuaState { lua: clua };
    lua.pushinteger(tx.stratum as i64);
    1
}

#[no_mangle]
pub extern "C" fn SCNtpLuaGetReferenceId(clua: &mut CLuaState, tx: &mut NTPTransaction) -> c_int {
    let lua = LuaState { lua: clua };
    lua.pushbytes(&tx.reference_id);
    1
}
