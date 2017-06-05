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

//! Expose portions of the libjansson API to Rust so Rust code can
//! populate a json_t and return it for logging by Suricata.

use std::ffi::CString;
use std::os::raw::c_char;

/// The Rust place holder for the json_t pointer.
pub enum JsonT {}

/// Expose the jansson functions we need.
extern {
    fn json_object() -> *mut JsonT;
    fn json_object_set_new(js: *mut JsonT, key: *const c_char,
                           val: *mut JsonT) -> u32;

    fn json_array() -> *mut JsonT;
    fn json_array_append_new(array: *mut JsonT, value: *mut JsonT);

    fn json_string(value: *const c_char) -> *mut JsonT;
    fn json_integer(val: u64) -> *mut JsonT;
    fn SCJsonBool(val: bool) -> *mut JsonT;
}

pub struct Json {
    pub js: *mut JsonT,
}

impl Json {

    pub fn object() -> Json {
        return Json{
            js: unsafe{json_object()},
        }
    }

    pub fn array() -> Json {
        return Json{
            js: unsafe{json_array()},
        }
    }

    pub fn unwrap(&self) -> *mut JsonT {
        return self.js;
    }

    pub fn set(&self, key: &str, val: Json) {
        unsafe {
            json_object_set_new(self.js,
                                CString::new(key).unwrap().as_ptr(),
                                val.js);
        }
    }

    pub fn set_string(&self, key: &str, val: &str) {
        unsafe{
            json_object_set_new(self.js,
                                CString::new(key).unwrap().as_ptr(),
                                json_string(CString::new(val).unwrap().as_ptr()));
        }
    }

    pub fn set_integer(&self, key: &str, val: u64) {
        unsafe {
            json_object_set_new(self.js,
                                CString::new(key).unwrap().as_ptr(),
                                json_integer(val));
        }
    }

    pub fn set_boolean(&self, key: &str, val: bool) {
        unsafe {
            json_object_set_new(self.js,
                                CString::new(key).unwrap().as_ptr(),
                                SCJsonBool(val));
        }
    }

    pub fn array_append(&self, val: Json) {
        unsafe {
            json_array_append_new(self.js, val.js);
        }
    }
}
