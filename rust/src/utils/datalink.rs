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

// Author: Jeff Lucovsky <jlucovsky@oisf.net>

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;

fn get_datalink_value(map: &HashMap<i32, CString>, key: i32) -> Option<&CString> {
    map.get(&key)
}

fn add_datalink_value(map: &mut HashMap<i32, CString>, key: i32, value: &CStr) {
    if let Ok(str_value) = value.to_str() {
        if let Ok(cstring_value) = CString::new(str_value) {
            map.insert(key, cstring_value);
        }
    }
}

#[no_mangle]
pub extern "C" fn SCDatalinkInit() -> *mut HashMap<i32, CString> {
    let map: HashMap<i32, CString> = HashMap::new();
    Box::into_raw(Box::new(map))
}

#[no_mangle]
pub unsafe extern "C" fn SCDatalinkValueNameInsert(
    map: *mut HashMap<i32, CString>, key: i32, value: *const c_char,
) {
    if map.is_null() || value.is_null() {
        return;
    }

    let map = &mut *map;
    let c_str = CStr::from_ptr(value);

    add_datalink_value(map, key, c_str);
}

#[no_mangle]
pub unsafe extern "C" fn SCDatalinkValueToName(
    map: *mut HashMap<i32, CString>, key: i32,
) -> *const c_char {
    if map.is_null() {
        return std::ptr::null_mut();
    }

    let map = &*map;
    match get_datalink_value(map, key) {
        Some(value) => value.as_ptr(),
        None => ptr::null(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn SCDatalinkDeInit(map: *mut HashMap<i32, CString>) {
    if !map.is_null() {
        let _ = Box::from_raw(map); // Automatically dropped at end of scope
    }
}
