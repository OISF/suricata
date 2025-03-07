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
use suricata_core::cast_pointer;
use suricata_core::jsonbuilder::{JsonBuilder, JsonError};

use std;

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

pub(super) unsafe extern "C" fn template_logger_log(
    tx: *const std::os::raw::c_void, js: *mut std::os::raw::c_void,
) -> bool {
    let tx = cast_pointer!(tx, TemplateTransaction);
    let js = cast_pointer!(js, JsonBuilder);
    log_template(tx, js).is_ok()
}
