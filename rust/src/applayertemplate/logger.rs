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

use super::template::TemplateTransaction;
use crate::jsonbuilder::{JsonBuilder, JsonError};
use std;

// the wire length is a u32 parsed from the stream; keep a record well
// below the whole-record drop bound
const TEMPLATE_LOG_MAX_STRING: usize = 8 * 1024;

fn log_template(tx: &TemplateTransaction, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.open_object("template")?;
    if let Some(ref request) = tx.request {
        js.set_string_limited("request", request, TEMPLATE_LOG_MAX_STRING)?;
    }
    if let Some(ref response) = tx.response {
        js.set_string_limited("response", response, TEMPLATE_LOG_MAX_STRING)?;
    }
    js.close()?;
    Ok(())
}

#[no_mangle]
pub unsafe extern "C" fn SCTemplateLoggerLog(
    tx: *const std::os::raw::c_void, js: *mut std::os::raw::c_void,
) -> bool {
    let tx = cast_pointer!(tx, TemplateTransaction);
    let js = cast_pointer!(js, JsonBuilder);
    log_template(tx, js).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_template_strings_limited() {
        let mut tx = TemplateTransaction::default();
        tx.request = Some("a".repeat(TEMPLATE_LOG_MAX_STRING + 100));
        tx.response = Some("b".repeat(TEMPLATE_LOG_MAX_STRING + 1));
        let mut js = JsonBuilder::try_new_object().unwrap();
        log_template(&tx, &mut js).unwrap();
        let out = js.as_str();
        assert!(out.contains("[truncated 100 additional bytes]"));
        assert!(out.contains("[truncated 1 additional byte]"));
    }
}
