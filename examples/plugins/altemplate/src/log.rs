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
// Addition of SCJsonBuilderWrapper to look like a rust app-layer
// even if we must use C API for SCJsonBuilder (because of its rust repr)

use super::template::TemplateTransaction;
use std::ffi::CString;
use suricata::cast_pointer;
use suricata_sys::jsonbuilder::{SCJbClose, SCJbOpenObject, SCJbSetString, SCJsonBuilder};

use std;

// syntax sugar around C API of SCJsonBuilder to feel like a normal app-layer in log_template
pub struct SCJsonBuilderWrapper {
    inner: *mut SCJsonBuilder,
}

impl SCJsonBuilderWrapper {
    fn close(&mut self) -> Result<(), ()> {
        if unsafe { !SCJbClose(self.inner) } {
            return Err(());
        }
        Ok(())
    }
    fn open_object(&mut self, key: &str) -> Result<(), ()> {
        let keyc = CString::new(key).unwrap();
        if unsafe { !SCJbOpenObject(self.inner, keyc.as_ptr()) } {
            return Err(());
        }
        Ok(())
    }
    fn set_string(&mut self, key: &str, val: &str) -> Result<(), ()> {
        let keyc = CString::new(key).unwrap();
        let valc = CString::new(val.escape_default().to_string()).unwrap();
        if unsafe { !SCJbSetString(self.inner, keyc.as_ptr(), valc.as_ptr()) } {
            return Err(());
        }
        Ok(())
    }
}

fn log_template(tx: &TemplateTransaction, js: &mut SCJsonBuilderWrapper) -> Result<(), ()> {
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

pub(super) unsafe extern "C" fn template_logger_log(
    tx: *const std::os::raw::c_void, js: *mut std::os::raw::c_void,
) -> bool {
    let tx = cast_pointer!(tx, TemplateTransaction);
    let js = cast_pointer!(js, SCJsonBuilder);
    let mut js = SCJsonBuilderWrapper { inner: js };
    log_template(tx, &mut js).is_ok()
}
