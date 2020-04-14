/* Copyright (C) 2020 Open Information Security Foundation
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

#![allow(clippy::missing_safety_doc)]

use crate::json;
use std::ffi::CStr;
use std::os::raw::c_char;
use std::str::Utf8Error;

const INIT_SIZE: usize = 4096;

#[derive(Debug, PartialEq)]
pub enum JsonError {
    InvalidState,
    Utf8Error(Utf8Error),
}

impl std::error::Error for JsonError {}

impl std::fmt::Display for JsonError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            JsonError::InvalidState => write!(f, "invalid state"),
            JsonError::Utf8Error(ref e) => e.fmt(f),
        }
    }
}

impl From<Utf8Error> for JsonError {
    fn from(e: Utf8Error) -> Self {
        JsonError::Utf8Error(e)
    }
}

#[derive(Clone, Debug)]
enum Type {
    Object,
    Array,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum State {
    None,
    ObjectFirst,
    ObjectNth,
    ArrayFirst,
    ArrayNth,
}

#[derive(Debug, Clone)]
pub struct JsonBuilder {
    buf: String,
    state: Vec<State>,
    init_type: Type,
}

impl JsonBuilder {
    /// Returns a new JsonBuilder in object state.
    pub fn new_object() -> Self {
        Self::new_object_with_capacity(INIT_SIZE)
    }

    pub fn new_object_with_capacity(capacity: usize) -> Self {
        let mut buf = String::with_capacity(capacity);
        buf.push('{');
        Self {
            buf: buf,
            state: vec![State::None, State::ObjectFirst],
            init_type: Type::Object,
        }
    }

    /// Returns a new JsonBuilder in array state.
    pub fn new_array() -> Self {
        Self::new_array_with_capacity(INIT_SIZE)
    }

    pub fn new_array_with_capacity(capacity: usize) -> Self {
        let mut buf = String::with_capacity(capacity);
        buf.push('[');
        Self {
            buf: buf,
            state: vec![State::None, State::ArrayFirst],
            init_type: Type::Array,
        }
    }

    // Reset the builder to its initial state, without losing
    // the current capacity.
    pub fn reset(&mut self) {
        self.buf.truncate(0);
        match self.init_type {
            Type::Array => {
                self.buf.push('[');
                self.state = vec![State::None, State::ArrayFirst];
            }
            Type::Object => {
                self.buf.push('{');
                self.state = vec![State::None, State::ObjectFirst];
            }
        }
    }

    // Closes the currently open datatype (object or array).
    pub fn close(&mut self) -> Result<&mut Self, JsonError> {
        match self.current_state() {
            State::ObjectFirst | State::ObjectNth => {
                self.buf.push('}');
                self.pop_state();
                Ok(self)
            }
            State::ArrayFirst | State::ArrayNth => {
                self.buf.push(']');
                self.pop_state();
                Ok(self)
            }
            _ => Err(JsonError::InvalidState),
        }
    }

    // Return the current state of the JsonBuilder.
    fn current_state(&self) -> State {
        if self.state.is_empty() {
            State::None
        } else {
            self.state[self.state.len() - 1]
        }
    }

    /// Move to a new state.
    fn push_state(&mut self, state: State) {
        self.state.push(state);
    }

    /// Go back to the previous state.
    fn pop_state(&mut self) {
        self.state.pop();
    }

    /// Change the current state.
    fn set_state(&mut self, state: State) {
        let n = self.state.len() - 1;
        self.state[n] = state;
    }

    /// Open an object under the given key.
    ///
    /// For example:
    ///     Before: {
    ///     After:  {"key": {
    pub fn open_object(&mut self, key: &str) -> Result<&mut Self, JsonError> {
        match self.current_state() {
            State::ObjectFirst => {
                self.buf.push('"');
                self.set_state(State::ObjectNth);
            }
            State::ObjectNth => {
                self.buf.push_str(",\"");
            }
            _ => {
                return Err(JsonError::InvalidState);
            }
        }
        self.buf.push_str(key);
        self.buf.push_str("\":{");
        self.push_state(State::ObjectFirst);
        Ok(self)
    }

    /// Start an object.
    ///
    /// Like open_object but does not create the object under a key. An
    /// error will be returned if starting an object does not make
    /// sense for the current state.
    pub fn start_object(&mut self) -> Result<&mut Self, JsonError> {
        match self.current_state() {
            State::ArrayFirst => {}
            State::ArrayNth => {
                self.buf.push_str(",");
            }
            _ => {
                return Err(JsonError::InvalidState);
            }
        }
        self.buf.push_str("{");
        self.set_state(State::ArrayNth);
        self.push_state(State::ObjectFirst);
        Ok(self)
    }

    /// Open an array under the given key.
    ///
    /// For example:
    ///     Before: {
    ///     After:  {"key": [
    pub fn open_array(&mut self, key: &str) -> Result<&mut Self, JsonError> {
        match self.current_state() {
            State::ObjectFirst => {}
            State::ObjectNth => {
                self.buf.push_str(",");
            }
            _ => {
                return Err(JsonError::InvalidState);
            }
        }
        self.buf.push_str(&format!(r#""{}":["#, key));
        self.set_state(State::ObjectNth);
        self.push_state(State::ArrayFirst);
        Ok(self)
    }

    /// Add a string to an array.
    pub fn add_string(&mut self, val: &str) -> Result<&mut Self, JsonError> {
        match self.current_state() {
            State::ArrayFirst => {
                self.encode_string(val)?;
                self.set_state(State::ArrayNth);
                Ok(self)
            }
            State::ArrayNth => {
                self.buf.push_str(&format!(r#","{}""#, val));
                Ok(self)
            }
            _ => Err(JsonError::InvalidState),
        }
    }

    /// Add an unsigned integer to an array.
    pub fn add_uint(&mut self, val: u64) -> Result<&mut Self, JsonError> {
        match self.current_state() {
            State::ArrayFirst => {
                self.set_state(State::ArrayNth);
            }
            State::ArrayNth => {
                self.buf.push(',');
            }
            _ => {
                return Err(JsonError::InvalidState);
            }
        }
        self.buf.push_str(&val.to_string());
        Ok(self)
    }

    pub fn set_object(&mut self, key: &str, js: &JsonBuilder) -> Result<&mut Self, JsonError> {
        match self.current_state() {
            State::ObjectNth => {
                self.buf.push(',');
            }
            State::ObjectFirst => {
                self.set_state(State::ObjectNth);
            }
            _ => {
                return Err(JsonError::InvalidState);
            }
        }
        self.buf.push('"');
        self.buf.push_str(key);
        self.buf.push_str("\":");
        self.buf.push_str(&js.buf);
        Ok(self)
    }

    /// Append an object onto this array.
    ///
    /// '[' -> '[{...}'
    /// '[{...}' -> '[{...},{...}'
    pub fn append_object(&mut self, js: &JsonBuilder) -> Result<&mut Self, JsonError> {
        match self.current_state() {
            State::ArrayFirst => {
                self.set_state(State::ArrayNth);
            }
            State::ArrayNth => {
                self.buf.push(',');
            }
            _ => {
                return Err(JsonError::InvalidState);
            }
        }
        self.buf.push_str(&js.buf);
        Ok(self)
    }

    pub fn set_jsont(
        &mut self,
        key: &str,
        jsont: &mut json::JsonT,
    ) -> Result<&mut Self, JsonError> {
        match self.current_state() {
            State::ObjectNth => self.buf.push(','),
            State::ObjectFirst => self.set_state(State::ObjectNth),
            _ => return Err(JsonError::InvalidState),
        }
        self.buf.push('"');
        self.buf.push_str(key);
        self.buf.push_str("\":");
        self.append_jsont(jsont)?;
        Ok(self)
    }

    fn append_jsont(&mut self, jsont: &mut json::JsonT) -> Result<&mut Self, JsonError> {
        unsafe {
            let raw = json::json_dumps(jsont, 0);
            let rendered = std::ffi::CStr::from_ptr(raw).to_str()?;
            self.buf.push_str(rendered);
            libc::free(raw as *mut std::os::raw::c_void);
            Ok(self)
        }
    }

    /// Set a key and string value type on an object.
    #[inline(always)]
    pub fn set_string(&mut self, key: &str, val: &str) -> Result<&mut Self, JsonError> {
        match self.current_state() {
            State::ObjectNth => {
                self.buf.push(',');
            }
            State::ObjectFirst => {
                self.set_state(State::ObjectNth);
            }
            _ => {
                return Err(JsonError::InvalidState);
            }
        }
        self.buf.push('"');
        self.buf.push_str(key);
        self.buf.push_str("\":");
        self.encode_string(val)?;
        Ok(self)
    }

    /// Set a key and a string value (from bytes) on an object.
    pub fn set_string_from_bytes(&mut self, key: &str, val: &[u8]) -> Result<&mut Self, JsonError> {
        match std::str::from_utf8(val) {
            Ok(s) => self.set_string(key, s),
            Err(_) => self.set_string(key, "<failed to convert bytes to string>"),
        }
    }

    pub fn append_string_from_bytes(&mut self, val: &[u8]) -> Result<&mut Self, JsonError> {
        match std::str::from_utf8(val) {
            Ok(s) => self.add_string(s),
            Err(_) => self.add_string("<failed to convert bytes to string>"),
        }
    }

    /// Set a key and an unsigned integer type on an object.
    pub fn set_uint(&mut self, key: &str, val: u64) -> Result<&mut Self, JsonError> {
        match self.current_state() {
            State::ObjectNth => {
                self.buf.push(',');
            }
            State::ObjectFirst => {
                self.set_state(State::ObjectNth);
            }
            _ => {
                return Err(JsonError::InvalidState);
            }
        }
        self.buf.push('"');
        self.buf.push_str(key);
        self.buf.push_str("\":");
        self.buf.push_str(&val.to_string());
        Ok(self)
    }

    pub fn set_bool(&mut self, key: &str, val: bool) -> Result<&mut Self, JsonError> {
        match self.current_state() {
            State::ObjectNth => {
                self.buf.push(',');
            }
            State::ObjectFirst => {
                self.set_state(State::ObjectNth);
            }
            _ => {
                return Err(JsonError::InvalidState);
            }
        }
        self.buf.push('"');
        self.buf.push_str(key);
        self.buf.push_str("\":");
        if val {
            self.buf.push_str("true");
        } else {
            self.buf.push_str("false");
        }
        Ok(self)
    }

    pub fn capacity(&self) -> usize {
        self.buf.capacity()
    }

    /// Encode a string into the buffer, escaping as needed.
    #[inline(always)]
    fn encode_string(&mut self, val: &str) -> Result<(), JsonError> {
        let mut out = vec![0; (val.len() * 2) + 2];
        let mut offset = 0;
        out[offset] = b'"';
        offset += 1;
        for c in val.chars() {
            if offset + 5 > out.capacity() {
                out.reserve(out.capacity());
            }
            match c {
                '"' | '\\' | '/' => {
                    out[offset] = b'\\';
                    offset += 1;
                    out[offset] = c as u8;
                    offset += 1;
                }
                '\n' => {
                    out[offset] = b'\\';
                    offset += 1;
                    out[offset] = b'n';
                    offset += 1;
                }
                '\r' => {
                    out[offset] = b'\\';
                    offset += 1;
                    out[offset] = b'r';
                    offset += 1;
                }
                '\t' => {
                    out[offset] = b'\\';
                    offset += 1;
                    out[offset] = b't';
                    offset += 1;
                }
                // Form feed.
                '\u{000c}' => {
                    out[offset] = b'\\';
                    offset += 1;
                    out[offset] = b'f';
                    offset += 1;
                }
                // Backspace.
                '\u{0008}' => {
                    out[offset] = b'\\';
                    offset += 1;
                    out[offset] = b'b';
                    offset += 1;
                }
                _ => {
                    if (c as u8) < 0x20 || (c as u8) > 0x7e {
                        // Format the u8 to hex.
                        let hex = format!("\\\\x{:02x}", c as u8);
                        for c in hex.chars() {
                            out[offset] = c as u8;
                            offset += 1;
                        }
                    } else {
                        out[offset] = c as u8;
                        offset += 1
                    }
                }
            }
        }
        out[offset] = b'"';
        offset += 1;
        self.buf.push_str(std::str::from_utf8(&out[0..offset])?);
        Ok(())
    }
}

#[no_mangle]
pub extern "C" fn jb_new_object() -> *mut JsonBuilder {
    let boxed = Box::new(JsonBuilder::new_object());
    Box::into_raw(boxed)
}

#[no_mangle]
pub extern "C" fn jb_new_array() -> *mut JsonBuilder {
    let boxed = Box::new(JsonBuilder::new_array());
    Box::into_raw(boxed)
}

#[no_mangle]
pub extern "C" fn jb_clone(js: &mut JsonBuilder) -> *mut JsonBuilder {
    let clone = Box::new(js.clone());
    Box::into_raw(clone)
}

#[no_mangle]
pub unsafe extern "C" fn jb_free(js: &mut JsonBuilder) {
    let _: Box<JsonBuilder> = std::mem::transmute(js);
}

#[no_mangle]
pub extern "C" fn jb_capacity(jb: &mut JsonBuilder) -> usize {
    jb.capacity()
}

#[no_mangle]
pub extern "C" fn jb_reset(jb: &mut JsonBuilder) {
    jb.reset();
}

#[no_mangle]
pub unsafe extern "C" fn jb_open_object(js: &mut JsonBuilder, key: *const c_char) -> bool {
    if let Ok(s) = CStr::from_ptr(key).to_str() {
        js.open_object(s).is_ok()
    } else {
        false
    }
}

#[no_mangle]
pub unsafe extern "C" fn jb_start_object(js: &mut JsonBuilder) -> bool {
    js.start_object().is_ok()
}

#[no_mangle]
pub unsafe extern "C" fn jb_open_array(js: &mut JsonBuilder, key: *const c_char) -> bool {
    if let Ok(s) = CStr::from_ptr(key).to_str() {
        js.open_array(s).is_ok()
    } else {
        false
    }
}

#[no_mangle]
pub unsafe extern "C" fn jb_set_string(
    js: &mut JsonBuilder,
    key: *const c_char,
    val: *const c_char,
) -> bool {
    if let Ok(key) = CStr::from_ptr(key).to_str() {
        if let Ok(val) = CStr::from_ptr(val).to_str() {
            return js.set_string(key, val).is_ok();
        }
    }
    return false;
}

#[no_mangle]
pub unsafe extern "C" fn jb_set_jsont(
    jb: &mut JsonBuilder,
    key: *const c_char,
    jsont: &mut json::JsonT,
) -> bool {
    if let Ok(key) = CStr::from_ptr(key).to_str() {
        return jb.set_jsont(key, jsont).is_ok();
    }
    return false;
}

#[no_mangle]
pub unsafe extern "C" fn jb_append_object(jb: &mut JsonBuilder, obj: &JsonBuilder) -> bool {
    jb.append_object(obj).is_ok()
}

#[no_mangle]
pub unsafe extern "C" fn jb_set_object(
    js: &mut JsonBuilder,
    key: *const c_char,
    val: &mut JsonBuilder,
) -> bool {
    if let Ok(key) = CStr::from_ptr(key).to_str() {
        return js.set_object(key, val).is_ok();
    }
    return false;
}

#[no_mangle]
pub unsafe extern "C" fn jb_add_string(js: &mut JsonBuilder, val: *const c_char) -> bool {
    if let Ok(val) = CStr::from_ptr(val).to_str() {
        return js.add_string(val).is_ok();
    }
    return false;
}

#[no_mangle]
pub unsafe extern "C" fn jb_add_uint(js: &mut JsonBuilder, val: u64) -> bool {
    return js.add_uint(val).is_ok();
}

#[no_mangle]
pub unsafe extern "C" fn jb_set_uint(js: &mut JsonBuilder, key: *const c_char, val: u64) -> bool {
    if let Ok(key) = CStr::from_ptr(key).to_str() {
        return js.set_uint(key, val).is_ok();
    }
    return false;
}

#[no_mangle]
pub unsafe extern "C" fn jb_set_bool(js: &mut JsonBuilder, key: *const c_char, val: bool) -> bool {
    if let Ok(key) = CStr::from_ptr(key).to_str() {
        return js.set_bool(key, val).is_ok();
    }
    return false;
}

#[no_mangle]
pub unsafe extern "C" fn jb_close(js: &mut JsonBuilder) -> bool {
    js.close().is_ok()
}

#[no_mangle]
pub unsafe extern "C" fn jb_len(js: &JsonBuilder) -> usize {
    js.buf.len()
}

#[no_mangle]
pub unsafe extern "C" fn jb_ptr(js: &mut JsonBuilder) -> *const u8
{
    js.buf.as_ptr()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_object_in_object() -> Result<(), JsonError> {
        let mut js = JsonBuilder::new_object();

        js.open_object("object")?;
        assert_eq!(js.current_state(), State::ObjectFirst);
        assert_eq!(js.buf, r#"{"object":{"#);

        js.set_string("one", "one")?;
        assert_eq!(js.current_state(), State::ObjectNth);
        assert_eq!(js.buf, r#"{"object":{"one":"one""#);

        js.close()?;
        assert_eq!(js.current_state(), State::ObjectNth);
        assert_eq!(js.buf, r#"{"object":{"one":"one"}"#);

        js.close()?;
        assert_eq!(js.current_state(), State::None);
        assert_eq!(js.buf, r#"{"object":{"one":"one"}}"#);

        Ok(())
    }

    #[test]
    fn test_empty_array_in_object() -> Result<(), JsonError> {
        let mut js = JsonBuilder::new_object();

        js.open_array("array")?;
        assert_eq!(js.current_state(), State::ArrayFirst);

        js.close()?;
        assert_eq!(js.current_state(), State::ObjectNth);
        assert_eq!(js.buf, r#"{"array":[]"#);

        js.close()?;
        assert_eq!(js.buf, r#"{"array":[]}"#);

        Ok(())
    }

    #[test]
    fn test_array_in_object() -> Result<(), JsonError> {
        let mut js = JsonBuilder::new_object();

        // Attempt to add an item, should fail.
        assert_eq!(
            js.add_string("will fail").err().unwrap(),
            JsonError::InvalidState
        );

        js.open_array("array")?;
        assert_eq!(js.current_state(), State::ArrayFirst);

        js.add_string("one")?;
        assert_eq!(js.current_state(), State::ArrayNth);
        assert_eq!(js.buf, r#"{"array":["one""#);

        js.add_string("two")?;
        assert_eq!(js.current_state(), State::ArrayNth);
        assert_eq!(js.buf, r#"{"array":["one","two""#);

        js.add_uint(3)?;
        assert_eq!(js.current_state(), State::ArrayNth);
        assert_eq!(js.buf, r#"{"array":["one","two",3"#);

        js.close()?;
        assert_eq!(js.current_state(), State::ObjectNth);
        assert_eq!(js.buf, r#"{"array":["one","two",3]"#);

        js.close()?;
        assert_eq!(js.current_state(), State::None);
        assert_eq!(js.buf, r#"{"array":["one","two",3]}"#);

        Ok(())
    }

    #[test]
    fn basic_test() -> Result<(), JsonError> {
        let mut js = JsonBuilder::new_object();
        assert_eq!(js.current_state(), State::ObjectFirst);
        assert_eq!(js.buf, "{");

        js.set_string("one", "one")?;
        assert_eq!(js.current_state(), State::ObjectNth);
        assert_eq!(js.buf, r#"{"one":"one""#);

        js.set_string("two", "two")?;
        assert_eq!(js.current_state(), State::ObjectNth);
        assert_eq!(js.buf, r#"{"one":"one","two":"two""#);

        js.close()?;
        assert_eq!(js.current_state(), State::None);
        assert_eq!(js.buf, r#"{"one":"one","two":"two"}"#);

        Ok(())
    }

    #[test]
    fn test_combine() -> Result<(), JsonError> {
        let mut main = JsonBuilder::new_object();
        let mut obj = JsonBuilder::new_object();
        obj.close()?;

        let mut array = JsonBuilder::new_array();
        array.add_string("one")?;
        array.add_uint(2)?;
        array.close()?;
        main.set_object("object", &obj)?;
        main.set_object("array", &array)?;
        main.close()?;

        assert_eq!(main.buf, r#"{"object":{},"array":["one",2]}"#);

        Ok(())
    }

    #[test]
    fn test_objects_in_array() -> Result<(), JsonError> {
        let mut js = JsonBuilder::new_array();
        assert_eq!(js.buf, r#"["#);

        js.start_object()?;
        assert_eq!(js.buf, r#"[{"#);

        js.set_string("uid", "0")?;
        assert_eq!(js.buf, r#"[{"uid":"0""#);

        js.close()?;
        assert_eq!(js.buf, r#"[{"uid":"0"}"#);

        js.start_object()?;
        assert_eq!(js.buf, r#"[{"uid":"0"},{"#);

        js.set_string("username", "root")?;
        assert_eq!(js.buf, r#"[{"uid":"0"},{"username":"root""#);

        js.close()?;
        assert_eq!(js.buf, r#"[{"uid":"0"},{"username":"root"}"#);

        js.close()?;
        assert_eq!(js.buf, r#"[{"uid":"0"},{"username":"root"}]"#);

        Ok(())
    }

    #[test]
    fn test_grow() -> Result<(), JsonError> {
        let mut jb = JsonBuilder::new_object_with_capacity(1);
        assert_eq!(jb.capacity(), 1);
        jb.set_string("foo", "bar")?;
        assert!(jb.capacity() > 1);
        Ok(())
    }

    #[test]
    fn test_reset() -> Result<(), JsonError> {
        let mut jb = JsonBuilder::new_object();
        assert_eq!(jb.buf, "{");
        jb.set_string("foo", "bar")?;
        let cap = jb.capacity();
        jb.reset();
        assert_eq!(jb.buf, "{");
        assert_eq!(jb.capacity(), cap);
        Ok(())
    }

    #[test]
    fn test_encode_string_from_bytes() -> Result<(), JsonError> {
        let mut jb = JsonBuilder::new_array();
        let s = &[0x41, 0x41, 0x41, 0x00];
        jb.append_string_from_bytes(s)?;
        assert_eq!(jb.buf, r#"["AAA\\x00""#);
        Ok(())
    }
}
