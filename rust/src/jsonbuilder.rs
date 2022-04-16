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
#[repr(C)]
enum State {
    None = 0,
    ObjectFirst,
    ObjectNth,
    ArrayFirst,
    ArrayNth,
}

impl State {
    fn from_u64(v: u64) -> Result<State, JsonError> {
        let s = match v {
            0 => State::None,
            1 => State::ObjectFirst,
            2 => State::ObjectNth,
            3 => State::ArrayFirst,
            4 => State::ArrayNth,
            _ => {
                return Err(JsonError::InvalidState);
            }
        };
        Ok(s)
    }
}

/// A "mark" or saved state for a JsonBuilder object.
///
/// The name is full, and the types are u64 as this object is used
/// directly in C as well.
#[repr(C)]
pub struct JsonBuilderMark {
    position: u64,
    state_index: u64,
    state: u64,
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
            State::None => {
                debug_validate_fail!("invalid state");
                Err(JsonError::InvalidState)
            },
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

    pub fn get_mark(&self) -> JsonBuilderMark {
        JsonBuilderMark {
            position: self.buf.len() as u64,
            state: self.current_state() as u64,
            state_index: self.state.len() as u64,
        }
    }

    pub fn restore_mark(&mut self, mark: &JsonBuilderMark) -> Result<(), JsonError> {
        let state = State::from_u64(mark.state)?;
        if mark.position < (self.buf.len() as u64) && mark.state_index < (self.state.len() as u64) {
            self.buf.truncate(mark.position as usize);
            self.state.truncate(mark.state_index as usize);
            self.state[(mark.state_index as usize) - 1] = state;
        }
        Ok(())
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
                debug_validate_fail!("invalid state");
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
                self.buf.push(',');
            }
            _ => {
                debug_validate_fail!("invalid state");
                return Err(JsonError::InvalidState);
            }
        }
        self.buf.push('{');
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
                self.buf.push(',');
            }
            _ => {
                debug_validate_fail!("invalid state");
                return Err(JsonError::InvalidState);
            }
        }
        self.buf.push('"');
        self.buf.push_str(key);
        self.buf.push_str("\":[");
        self.set_state(State::ObjectNth);
        self.push_state(State::ArrayFirst);
        Ok(self)
    }

    /// Add a string to an array.
    pub fn append_string(&mut self, val: &str) -> Result<&mut Self, JsonError> {
        match self.current_state() {
            State::ArrayFirst => {
                self.encode_string(val)?;
                self.set_state(State::ArrayNth);
                Ok(self)
            }
            State::ArrayNth => {
                self.buf.push(',');
                self.encode_string(val)?;
                Ok(self)
            }
            _ => {
                debug_validate_fail!("invalid state");
                Err(JsonError::InvalidState)
            }
        }
    }

    pub fn append_string_from_bytes(&mut self, val: &[u8]) -> Result<&mut Self, JsonError> {
        match std::str::from_utf8(val) {
            Ok(s) => self.append_string(s),
            Err(_) => self.append_string(&string_from_bytes(val)),
        }
    }

    /// Add a string to an array.
    pub fn append_base64(&mut self, val: &[u8]) -> Result<&mut Self, JsonError> {
        match self.current_state() {
            State::ArrayFirst => {
                self.buf.push('"');
                base64::encode_config_buf(val, base64::STANDARD, &mut self.buf);
                self.buf.push('"');
                self.set_state(State::ArrayNth);
                Ok(self)
            }
            State::ArrayNth => {
                self.buf.push(',');
                self.buf.push('"');
                base64::encode_config_buf(val, base64::STANDARD, &mut self.buf);
                self.buf.push('"');
                Ok(self)
            }
            _ => {
                debug_validate_fail!("invalid state");
                Err(JsonError::InvalidState)
            }
        }
    }

    /// Add an unsigned integer to an array.
    pub fn append_uint(&mut self, val: u64) -> Result<&mut Self, JsonError> {
        match self.current_state() {
            State::ArrayFirst => {
                self.set_state(State::ArrayNth);
            }
            State::ArrayNth => {
                self.buf.push(',');
            }
            _ => {
                debug_validate_fail!("invalid state");
                return Err(JsonError::InvalidState);
            }
        }
        self.buf.push_str(&val.to_string());
        Ok(self)
    }

    pub fn append_float(&mut self, val: f64) -> Result<&mut Self, JsonError> {
        match self.current_state() {
            State::ArrayFirst => {
                self.set_state(State::ArrayNth);
            }
            State::ArrayNth => {
                self.buf.push(',');
            }
            _ => {
                debug_validate_fail!("invalid state");
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
                debug_validate_fail!("invalid state");
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
                debug_validate_fail!("invalid state");
                return Err(JsonError::InvalidState);
            }
        }
        self.buf.push_str(&js.buf);
        Ok(self)
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
                debug_validate_fail!("invalid state");
                return Err(JsonError::InvalidState);
            }
        }
        self.buf.push('"');
        self.buf.push_str(key);
        self.buf.push_str("\":");
        self.encode_string(val)?;
        Ok(self)
    }

    pub fn set_formatted(&mut self, formatted: &str) -> Result<&mut Self, JsonError> {
        match self.current_state() {
            State::ObjectNth => {
                self.buf.push(',');
            }
            State::ObjectFirst => {
                self.set_state(State::ObjectNth);
            }
            _ => {
                debug_validate_fail!("invalid state");
                return Err(JsonError::InvalidState);
            }
        }
        self.buf.push_str(formatted);
        Ok(self)
    }

    /// Set a key and a string value (from bytes) on an object.
    pub fn set_string_from_bytes(&mut self, key: &str, val: &[u8]) -> Result<&mut Self, JsonError> {
        match std::str::from_utf8(val) {
            Ok(s) => self.set_string(key, s),
            Err(_) => self.set_string(key, &string_from_bytes(val)),
        }
    }

    /// Set a key and a string field as the base64 encoded string of the value.
    pub fn set_base64(&mut self, key: &str, val: &[u8]) -> Result<&mut Self, JsonError> {
        match self.current_state() {
            State::ObjectNth => {
                self.buf.push(',');
            }
            State::ObjectFirst => {
                self.set_state(State::ObjectNth);
            }
            _ => {
                debug_validate_fail!("invalid state");
                return Err(JsonError::InvalidState);
            }
        }
        self.buf.push('"');
        self.buf.push_str(key);
        self.buf.push_str("\":\"");
        base64::encode_config_buf(val, base64::STANDARD, &mut self.buf);
        self.buf.push('"');

        Ok(self)
    }

    /// Set a key and a string field as the hex encoded string of the value.
    pub fn set_hex(&mut self, key: &str, val: &[u8]) -> Result<&mut Self, JsonError> {
        match self.current_state() {
            State::ObjectNth => {
                self.buf.push(',');
            }
            State::ObjectFirst => {
                self.set_state(State::ObjectNth);
            }
            _ => {
                debug_validate_fail!("invalid state");
                return Err(JsonError::InvalidState);
            }
        }
        self.buf.push('"');
        self.buf.push_str(key);
        self.buf.push_str("\":\"");
        for i in 0..val.len() {
            self.buf.push(HEX[(val[i] >>  4) as usize] as char);
            self.buf.push(HEX[(val[i] & 0xf) as usize] as char);
        }
        self.buf.push('"');

        Ok(self)
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
                debug_validate_fail!("invalid state");
                return Err(JsonError::InvalidState);
            }
        }
        self.buf.push('"');
        self.buf.push_str(key);
        self.buf.push_str("\":");
        self.buf.push_str(&val.to_string());
        Ok(self)
    }

    pub fn set_float(&mut self, key: &str, val: f64) -> Result<&mut Self, JsonError> {
        match self.current_state() {
            State::ObjectNth => {
                self.buf.push(',');
            }
            State::ObjectFirst => {
                self.set_state(State::ObjectNth);
            }
            _ => {
                debug_validate_fail!("invalid state");
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
                debug_validate_fail!("invalid state");
                return Err(JsonError::InvalidState);
            }
        }
        self.buf.push('"');
        self.buf.push_str(key);
        if val {
            self.buf.push_str("\":true");
        } else {
            self.buf.push_str("\":false");
        }
        Ok(self)
    }

    pub fn capacity(&self) -> usize {
        self.buf.capacity()
    }

    /// Encode a string into the buffer, escaping as needed.
    ///
    /// The string is encoded into an intermediate vector as its faster
    /// than building onto the buffer.
    #[inline(always)]
    fn encode_string(&mut self, val: &str) -> Result<(), JsonError> {
        let mut buf = vec![0; val.len() * 2 + 2];
        let mut offset = 0;
        let bytes = val.as_bytes();
        buf[offset] = b'"';
        offset += 1;
        for &x in bytes.iter() {
            if offset + 7 >= buf.capacity() {
                let mut extend = vec![0; buf.capacity()];
                buf.append(&mut extend);
            }
            let escape = ESCAPED[x as usize];
            if escape == 0 {
                buf[offset] = x;
                offset += 1;
            } else if escape == b'u' {
                buf[offset] = b'\\';
                offset += 1;
                buf[offset] = b'u';
                offset += 1;
                buf[offset] = b'0';
                offset += 1;
                buf[offset] = b'0';
                offset += 1;
                buf[offset] = HEX[(x >> 4 & 0xf) as usize];
                offset += 1;
                buf[offset] = HEX[(x & 0xf) as usize];
                offset += 1;
            } else {
                buf[offset] = b'\\';
                offset += 1;
                buf[offset] = escape;
                offset += 1;
            }
        }
        buf[offset] = b'"';
        offset += 1;
        match std::str::from_utf8(&buf[0..offset]) {
            Ok(s) => {
                self.buf.push_str(s);
            }
            Err(err) => {
                let error = format!(
                    "\"UTF8-ERROR: what=[escaped string] error={} output={:02x?} input={:02x?}\"",
                    err,
                    &buf[0..offset],
                    val.as_bytes(),
                );
                self.buf.push_str(&error);
            }
        }
        Ok(())
    }
}

/// A Suricata specific function to create a string from bytes when UTF-8 decoding fails.
///
/// For bytes over 0x0f, we encode as hex like "\xf2".
fn string_from_bytes(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.iter() {
        if *b < 128 {
            out.push(*b as char);
        } else {
            out.push_str(&format!("\\x{:02x}", *b));
        }
    }
    return out;
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
    let _ = Box::from_raw(js);
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
    js: &mut JsonBuilder, key: *const c_char, val: *const c_char,
) -> bool {
    if val.is_null() {
        return false;
    }
    if let Ok(key) = CStr::from_ptr(key).to_str() {
        if let Ok(val) = CStr::from_ptr(val).to_str() {
            return js.set_string(key, val).is_ok();
        }
    }
    return false;
}

#[no_mangle]
pub unsafe extern "C" fn jb_set_string_from_bytes(
    js: &mut JsonBuilder, key: *const c_char, bytes: *const u8, len: u32,
) -> bool {
    if bytes.is_null() || len == 0 {
        return false;
    }
    if let Ok(key) = CStr::from_ptr(key).to_str() {
        let val = std::slice::from_raw_parts(bytes, len as usize);
        return js.set_string_from_bytes(key, val).is_ok();
    }
    return false;
}

#[no_mangle]
pub unsafe extern "C" fn jb_set_base64(
    js: &mut JsonBuilder, key: *const c_char, bytes: *const u8, len: u32,
) -> bool {
    if bytes == std::ptr::null() || len == 0 {
        return false;
    }
    if let Ok(key) = CStr::from_ptr(key).to_str() {
        let val = std::slice::from_raw_parts(bytes, len as usize);
        return js.set_base64(key, val).is_ok();
    }
    return false;
}

#[no_mangle]
pub unsafe extern "C" fn jb_set_hex(
    js: &mut JsonBuilder, key: *const c_char, bytes: *const u8, len: u32,
) -> bool {
    if bytes == std::ptr::null() || len == 0 {
        return false;
    }
    if let Ok(key) = CStr::from_ptr(key).to_str() {
        let val = std::slice::from_raw_parts(bytes, len as usize);
        return js.set_hex(key, val).is_ok();
    }
    return false;
}

#[no_mangle]
pub unsafe extern "C" fn jb_set_formatted(js: &mut JsonBuilder, formatted: *const c_char) -> bool {
    if let Ok(formatted) = CStr::from_ptr(formatted).to_str() {
        return js.set_formatted(formatted).is_ok();
    }
    return false;
}

#[no_mangle]
pub unsafe extern "C" fn jb_append_object(jb: &mut JsonBuilder, obj: &JsonBuilder) -> bool {
    jb.append_object(obj).is_ok()
}

#[no_mangle]
pub unsafe extern "C" fn jb_set_object(
    js: &mut JsonBuilder, key: *const c_char, val: &mut JsonBuilder,
) -> bool {
    if let Ok(key) = CStr::from_ptr(key).to_str() {
        return js.set_object(key, val).is_ok();
    }
    return false;
}

#[no_mangle]
pub unsafe extern "C" fn jb_append_string(js: &mut JsonBuilder, val: *const c_char) -> bool {
    if val.is_null() {
        return false;
    }
    if let Ok(val) = CStr::from_ptr(val).to_str() {
        return js.append_string(val).is_ok();
    }
    return false;
}

#[no_mangle]
pub unsafe extern "C" fn jb_append_string_from_bytes(
    js: &mut JsonBuilder, bytes: *const u8, len: u32,
) -> bool {
    if bytes.is_null() || len == 0 {
        return false;
    }
    let val = std::slice::from_raw_parts(bytes, len as usize);
    return js.append_string_from_bytes(val).is_ok();
}

#[no_mangle]
pub unsafe extern "C" fn jb_append_base64(
    js: &mut JsonBuilder, bytes: *const u8, len: u32,
) -> bool {
    if bytes == std::ptr::null() || len == 0 {
        return false;
    }
    let val = std::slice::from_raw_parts(bytes, len as usize);
    return js.append_base64(val).is_ok();
}

#[no_mangle]
pub unsafe extern "C" fn jb_append_uint(js: &mut JsonBuilder, val: u64) -> bool {
    return js.append_uint(val).is_ok();
}

#[no_mangle]
pub unsafe extern "C" fn jb_append_float(js: &mut JsonBuilder, val: f64) -> bool {
    return js.append_float(val).is_ok();
}

#[no_mangle]
pub unsafe extern "C" fn jb_set_uint(js: &mut JsonBuilder, key: *const c_char, val: u64) -> bool {
    if let Ok(key) = CStr::from_ptr(key).to_str() {
        return js.set_uint(key, val).is_ok();
    }
    return false;
}

#[no_mangle]
pub unsafe extern "C" fn jb_set_float(js: &mut JsonBuilder, key: *const c_char, val: f64) -> bool {
    if let Ok(key) = CStr::from_ptr(key).to_str() {
        return js.set_float(key, val).is_ok();
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
pub unsafe extern "C" fn jb_ptr(js: &mut JsonBuilder) -> *const u8 {
    js.buf.as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn jb_get_mark(js: &mut JsonBuilder, mark: &mut JsonBuilderMark) {
    let m = js.get_mark();
    mark.position = m.position;
    mark.state_index = m.state_index;
    mark.state = m.state;
}

#[no_mangle]
pub unsafe extern "C" fn jb_restore_mark(js: &mut JsonBuilder, mark: &mut JsonBuilderMark) -> bool {
    js.restore_mark(mark).is_ok()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_set_bool() {
        let mut jb = JsonBuilder::new_object();
        jb.set_bool("first", true).unwrap();
        assert_eq!(jb.buf, r#"{"first":true"#);
        jb.set_bool("second", false).unwrap();
        assert_eq!(jb.buf, r#"{"first":true,"second":false"#);

        let mut jb = JsonBuilder::new_object();
        jb.set_bool("first", false).unwrap();
        assert_eq!(jb.buf, r#"{"first":false"#);
        jb.set_bool("second", true).unwrap();
        assert_eq!(jb.buf, r#"{"first":false,"second":true"#);
    }

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
    #[cfg(not(feature = "debug-validate"))]
    fn test_array_in_object() -> Result<(), JsonError> {
        let mut js = JsonBuilder::new_object();

        // Attempt to add an item, should fail.
        assert_eq!(
            js.append_string("will fail").err().unwrap(),
            JsonError::InvalidState
        );

        js.open_array("array")?;
        assert_eq!(js.current_state(), State::ArrayFirst);

        js.append_string("one")?;
        assert_eq!(js.current_state(), State::ArrayNth);
        assert_eq!(js.buf, r#"{"array":["one""#);

        js.append_string("two")?;
        assert_eq!(js.current_state(), State::ArrayNth);
        assert_eq!(js.buf, r#"{"array":["one","two""#);

        js.append_uint(3)?;
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
        array.append_string("one")?;
        array.append_uint(2)?;
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
    fn test_append_string_from_bytes() -> Result<(), JsonError> {
        let mut jb = JsonBuilder::new_array();
        let s = &[0x41, 0x41, 0x41, 0x00];
        jb.append_string_from_bytes(s)?;
        assert_eq!(jb.buf, r#"["AAA\u0000""#);

        let s = &[0x00, 0x01, 0x02, 0x03];
        let mut jb = JsonBuilder::new_array();
        jb.append_string_from_bytes(s)?;
        assert_eq!(jb.buf, r#"["\u0000\u0001\u0002\u0003""#);

        Ok(())
    }

    #[test]
    fn test_set_string_from_bytes() {
        let mut jb = JsonBuilder::new_object();
        jb.set_string_from_bytes("first", &[]).unwrap();
        assert_eq!(jb.buf, r#"{"first":"""#);
        jb.set_string_from_bytes("second", &[]).unwrap();
        assert_eq!(jb.buf, r#"{"first":"","second":"""#);
    }

    #[test]
    fn test_append_string_from_bytes_grow() -> Result<(), JsonError> {
        let s = &[0x00, 0x01, 0x02, 0x03];
        let mut jb = JsonBuilder::new_array();
        jb.append_string_from_bytes(s)?;

        for i in 1..1000 {
            let mut s = Vec::new();
            for _ in 0..i {
                s.push(0x41);
            }
            let mut jb = JsonBuilder::new_array();
            jb.append_string_from_bytes(&s)?;
        }

        Ok(())
    }

    #[test]
    fn test_invalid_utf8() {
        let mut jb = JsonBuilder::new_object();
        jb.set_string_from_bytes("invalid", &[0xf0, 0xf1, 0xf2])
            .unwrap();
        assert_eq!(jb.buf, r#"{"invalid":"\\xf0\\xf1\\xf2""#);

        let mut jb = JsonBuilder::new_array();
        jb.append_string_from_bytes(&[0xf0, 0xf1, 0xf2]).unwrap();
        assert_eq!(jb.buf, r#"["\\xf0\\xf1\\xf2""#);
    }

    #[test]
    fn test_marks() {
        let mut jb = JsonBuilder::new_object();
        jb.set_string("foo", "bar").unwrap();
        assert_eq!(jb.buf, r#"{"foo":"bar""#);
        assert_eq!(jb.current_state(), State::ObjectNth);
        assert_eq!(jb.state.len(), 2);
        let mark = jb.get_mark();

        // Mutate such that states are transitioned.
        jb.open_array("bar").unwrap();
        jb.start_object().unwrap();
        assert_eq!(jb.buf, r#"{"foo":"bar","bar":[{"#);
        assert_eq!(jb.current_state(), State::ObjectFirst);
        assert_eq!(jb.state.len(), 4);

        // Restore to mark.
        jb.restore_mark(&mark).unwrap();
        assert_eq!(jb.buf, r#"{"foo":"bar""#);
        assert_eq!(jb.current_state(), State::ObjectNth);
        assert_eq!(jb.state.len(), 2);
    }

    #[test]
    fn test_set_formatted() {
        let mut jb = JsonBuilder::new_object();
        jb.set_formatted("\"foo\":\"bar\"").unwrap();
        assert_eq!(jb.buf, r#"{"foo":"bar""#);
        jb.set_formatted("\"bar\":\"foo\"").unwrap();
        assert_eq!(jb.buf, r#"{"foo":"bar","bar":"foo""#);
        jb.close().unwrap();
        assert_eq!(jb.buf, r#"{"foo":"bar","bar":"foo"}"#);
    }

    #[test]
    fn test_set_float() {
        let mut jb = JsonBuilder::new_object();
        jb.set_float("one", 1.1).unwrap();
        jb.set_float("two", 2.2).unwrap();
        jb.close().unwrap();
        assert_eq!(jb.buf, r#"{"one":1.1,"two":2.2}"#);
    }

    #[test]
    fn test_append_float() {
        let mut jb = JsonBuilder::new_array();
        jb.append_float(1.1).unwrap();
        jb.append_float(2.2).unwrap();
        jb.close().unwrap();
        assert_eq!(jb.buf, r#"[1.1,2.2]"#);
    }
}

// Escape table as seen in serde-json (MIT/Apache license)

const QU: u8 = b'"';
const BS: u8 = b'\\';
const BB: u8 = b'b';
const TT: u8 = b't';
const NN: u8 = b'n';
const FF: u8 = b'f';
const RR: u8 = b'r';
const UU: u8 = b'u';
const __: u8 = 0;

// Look up table for characters that need escaping in a product string
static ESCAPED: [u8; 256] = [
    // 0   1   2   3   4   5   6   7   8   9   A   B   C   D   E   F
    UU, UU, UU, UU, UU, UU, UU, UU, BB, TT, NN, UU, FF, RR, UU, UU, // 0
    UU, UU, UU, UU, UU, UU, UU, UU, UU, UU, UU, UU, UU, UU, UU, UU, // 1
    __, __, QU, __, __, __, __, __, __, __, __, __, __, __, __, __, // 2
    __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, // 3
    __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, // 4
    __, __, __, __, __, __, __, __, __, __, __, __, BS, __, __, __, // 5
    __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, // 6
    __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, // 7
    __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, // 8
    __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, // 9
    __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, // A
    __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, // B
    __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, // C
    __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, // D
    __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, // E
    __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, // F
];

pub static HEX: [u8; 16] = [
    b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'a', b'b', b'c', b'd', b'e', b'f',
];
