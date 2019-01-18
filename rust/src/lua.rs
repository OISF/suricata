/* Copyright (C) 2017 Open Information Security Foundation
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
use std::os::raw::c_int;
use std::os::raw::c_long;

/// The Rust place holder for lua_State.
pub enum CLuaState {}

extern {
    fn lua_createtable(lua: *mut CLuaState, narr: c_int, nrec: c_int);
    fn lua_settable(lua: *mut CLuaState, idx: c_long);
    fn lua_pushlstring(lua: *mut CLuaState, s: *const c_char, len: usize);
    fn lua_pushinteger(lua: *mut CLuaState, n: c_long);
}

pub struct LuaState {
    pub lua: *mut CLuaState,
}

impl LuaState {

    pub fn newtable(&self) {
        unsafe {
            lua_createtable(self.lua, 0, 0);
        }
    }

    pub fn settable(&self, idx: i64) {
        unsafe {
            lua_settable(self.lua, idx as c_long);
        }
    }

    pub fn pushstring(&self, val: &str) {
        unsafe {
            lua_pushlstring(self.lua, val.as_ptr() as *const c_char, val.len());
        }
    }

    pub fn pushinteger(&self, val: i64) {
        unsafe {
            lua_pushinteger(self.lua, val as c_long);
        }
    }
}
