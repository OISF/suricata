/* Copyright (C) 2018 Open Information Security Foundation
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

// same file as rust/src/applayertemplate/logger.rs except
// different paths for use statements
// open_object using altemplate instead of just template
// Jsonbuilder using C API due to  opaque implementation

use super::template::TemplateTransaction;
use std::ffi::{c_char, CString};
use suricata::cast_pointer;
use suricata::jsonbuilder::JsonError;

use std;

// Jsonbuilder opaque with implementation using C API to feel like usual
#[repr(C)]
pub struct JsonBuilder {
    _data: [u8; 0],
}

extern "C" {
    pub fn jb_set_string(jb: &mut JsonBuilder, key: *const c_char, val: *const c_char) -> bool;
    pub fn jb_close(jb: &mut JsonBuilder) -> bool;
    pub fn jb_open_object(jb: &mut JsonBuilder, key: *const c_char) -> bool;
}

impl JsonBuilder {
    pub fn close(&mut self) -> Result<(), JsonError> {
        if unsafe { !jb_close(self) } {
            return Err(JsonError::Memory);
        }
        Ok(())
    }
    pub fn open_object(&mut self, key: &str) -> Result<(), JsonError> {
        let keyc = CString::new(key).unwrap();
        if unsafe { !jb_open_object(self, keyc.as_ptr()) } {
            return Err(JsonError::Memory);
        }
        Ok(())
    }
    pub fn set_string(&mut self, key: &str, val: &str) -> Result<(), JsonError> {
        let keyc = CString::new(key).unwrap();
        let valc = CString::new(val.escape_default().to_string()).unwrap();
        if unsafe { !jb_set_string(self, keyc.as_ptr(), valc.as_ptr()) } {
            return Err(JsonError::Memory);
        }
        Ok(())
    }
}

fn log_template(tx: &TemplateTransaction, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.open_object("altemplate")?;
    if let Some(ref request) = tx.request {
        js.set_string("request", request)?;
    }
    if let Some(ref response) = tx.response {
        js.set_string("response", response)?;
    }
    js.close()?;
    Ok(())
}

#[no_mangle]
pub unsafe extern "C" fn rs_template_logger_log(
    tx: *const std::os::raw::c_void, js: *mut std::os::raw::c_void,
) -> bool {
    let tx = cast_pointer!(tx, TemplateTransaction);
    let js = cast_pointer!(js, JsonBuilder);
    log_template(tx, js).is_ok()
}
