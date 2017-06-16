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

    pub fn set_string_from_bytes(&self, key: &str, val: &[u8]) {
        unsafe {
            json_object_set_new(self.js,
                                CString::new(key).unwrap().as_ptr(),
                                json_string(to_cstring(val).as_ptr()));
        }
    }

    pub fn set_string(&self, key: &str, val: &str) {
        unsafe {
            json_object_set_new(self.js,
                                CString::new(key).unwrap().as_ptr(),
                                json_string(to_cstring(val.as_bytes()).as_ptr()));
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

/// Convert an array of bytes into an ascii printable string replacing
/// non-printable characters (including NULL) with hex value.
///
/// Newer versions of Jansson have a json_stringn that will allow us
/// to create a string out of a byte array of unicode compliant bytes,
/// but until we can use it across all platforms this is probably the
/// best we can do.
fn to_cstring(val: &[u8]) -> CString {
    let mut safe = Vec::with_capacity(val.len());
    for c in val {
        if *c == 0 || *c > 0x7f {
            safe.extend(format!("\\x{:02x}", *c).as_bytes());
        } else {
            safe.push(*c);
        }
    }
    match CString::new(safe) {
        Ok(cstr) => cstr,
        _ => {
            CString::new("<failed to encode string>").unwrap()
        }
    }
}

#[cfg(test)]
mod tests {

    use json::to_cstring;

    #[test]
    fn test_to_string() {
        assert_eq!("A\\x00A",
                   to_cstring(&[0x41, 0x00, 0x41]).into_string().unwrap());
        assert_eq!("", to_cstring(&[]).into_string().unwrap());
        assert_eq!("\\x80\\xf1\\xf2\\xf3",
                   to_cstring(&[0x80, 0xf1, 0xf2, 0xf3]).into_string().unwrap());
    }

}
