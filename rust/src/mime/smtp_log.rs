/* Copyright (C) 2022 Open Information Security Foundation
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

use super::mime;
use crate::jsonbuilder::{JsonBuilder, JsonError};
use crate::mime::smtp::{MimeSmtpMd5State, MimeStateSMTP};
use digest::Digest;
use digest::Update;
use md5::Md5;
use std::ffi::CStr;

fn log_subject_md5(js: &mut JsonBuilder, ctx: &MimeStateSMTP) -> Result<(), JsonError> {
    for h in &ctx.headers[..ctx.main_headers_nb] {
        if mime::slice_equals_lowercase(&h.name, b"subject") {
            let hash = format!("{:x}", Md5::new().chain(&h.value).finalize());
            js.set_string("subject_md5", &hash)?;
            break;
        }
    }
    return Ok(());
}

#[no_mangle]
pub unsafe extern "C" fn SCMimeSmtpLogSubjectMd5(
    js: &mut JsonBuilder, ctx: &MimeStateSMTP,
) -> bool {
    return log_subject_md5(js, ctx).is_ok();
}

fn log_body_md5(js: &mut JsonBuilder, ctx: &MimeStateSMTP) -> Result<(), JsonError> {
    if ctx.md5_state == MimeSmtpMd5State::MimeSmtpMd5Completed {
        let hash = format!("{:x}", ctx.md5_result);
        js.set_string("body_md5", &hash)?;
    }
    return Ok(());
}

#[no_mangle]
pub unsafe extern "C" fn SCMimeSmtpLogBodyMd5(js: &mut JsonBuilder, ctx: &MimeStateSMTP) -> bool {
    return log_body_md5(js, ctx).is_ok();
}

fn log_field_array(
    js: &mut JsonBuilder, ctx: &MimeStateSMTP, c: &str, e: &str,
) -> Result<(), JsonError> {
    let mark = js.get_mark();
    let mut found = false;
    js.open_array(c)?;

    for h in &ctx.headers[..ctx.main_headers_nb] {
        if mime::slice_equals_lowercase(&h.name, e.as_bytes()) {
            found = true;
            js.append_string(&String::from_utf8_lossy(&h.value))?;
        }
    }

    if found {
        js.close()?;
    } else {
        js.restore_mark(&mark)?;
    }

    return Ok(());
}

#[no_mangle]
pub unsafe extern "C" fn SCMimeSmtpLogFieldArray(
    js: &mut JsonBuilder, ctx: &MimeStateSMTP, email: *const std::os::raw::c_char,
    config: *const std::os::raw::c_char,
) -> bool {
    let e: &CStr = CStr::from_ptr(email); //unsafe
    if let Ok(email_field) = e.to_str() {
        let c: &CStr = CStr::from_ptr(config); //unsafe
        if let Ok(config_field) = c.to_str() {
            return log_field_array(js, ctx, config_field, email_field).is_ok();
        }
    }
    return false;
}

enum FieldCommaState {
    Start = 0, // skip leading spaces
    Field = 1,
    Quoted = 2, // do not take comma for split in quote
}

fn log_field_comma(
    js: &mut JsonBuilder, ctx: &MimeStateSMTP, c: &str, e: &str,
) -> Result<(), JsonError> {
    for h in &ctx.headers[..ctx.main_headers_nb] {
        if mime::slice_equals_lowercase(&h.name, e.as_bytes()) {
            let mark = js.get_mark();
            let mut has_not_empty_field = false;
            js.open_array(c)?;
            let mut start = 0;
            let mut state = FieldCommaState::Start;
            for i in 0..h.value.len() {
                match state {
                    FieldCommaState::Start => {
                        if h.value[i] == b' ' || h.value[i] == b'\t' {
                            start += 1;
                        } else if h.value[i] == b'"' {
                            state = FieldCommaState::Quoted;
                        } else {
                            state = FieldCommaState::Field;
                        }
                    }
                    FieldCommaState::Field => {
                        if h.value[i] == b',' {
                            if i > start {
                                js.append_string(&String::from_utf8_lossy(&h.value[start..i]))?;
                                has_not_empty_field = true;
                            }
                            start = i + 1;
                            state = FieldCommaState::Start;
                        } else if h.value[i] == b'"' {
                            state = FieldCommaState::Quoted;
                        }
                    }
                    FieldCommaState::Quoted => {
                        if h.value[i] == b'"' {
                            state = FieldCommaState::Field;
                        }
                    }
                }
            }
            if h.value.len() > start {
                // do not log empty string
                js.append_string(&String::from_utf8_lossy(&h.value[start..]))?;
                has_not_empty_field = true;
            }
            if has_not_empty_field {
                js.close()?;
            } else {
                js.restore_mark(&mark)?;
            }
            break;
        }
    }
    return Ok(());
}

#[no_mangle]
pub unsafe extern "C" fn SCMimeSmtpLogFieldComma(
    js: &mut JsonBuilder, ctx: &MimeStateSMTP, email: *const std::os::raw::c_char,
    config: *const std::os::raw::c_char,
) -> bool {
    let e: &CStr = CStr::from_ptr(email); //unsafe
    if let Ok(email_field) = e.to_str() {
        let c: &CStr = CStr::from_ptr(config); //unsafe
        if let Ok(config_field) = c.to_str() {
            return log_field_comma(js, ctx, config_field, email_field).is_ok();
        }
    }
    return false;
}

fn log_field_string(
    js: &mut JsonBuilder, ctx: &MimeStateSMTP, c: &str, e: &str,
) -> Result<(), JsonError> {
    for h in &ctx.headers[..ctx.main_headers_nb] {
        if mime::slice_equals_lowercase(&h.name, e.as_bytes()) {
            js.set_string(c, &String::from_utf8_lossy(&h.value))?;
            break;
        }
    }
    return Ok(());
}

#[no_mangle]
pub unsafe extern "C" fn SCMimeSmtpLogFieldString(
    js: &mut JsonBuilder, ctx: &MimeStateSMTP, email: *const std::os::raw::c_char,
    config: *const std::os::raw::c_char,
) -> bool {
    let e: &CStr = CStr::from_ptr(email); //unsafe
    if let Ok(email_field) = e.to_str() {
        let c: &CStr = CStr::from_ptr(config); //unsafe
        if let Ok(config_field) = c.to_str() {
            return log_field_string(js, ctx, config_field, email_field).is_ok();
        }
    }
    return false;
}

fn log_data_header(
    js: &mut JsonBuilder, ctx: &MimeStateSMTP, hname: &str,
) -> Result<(), JsonError> {
    for h in &ctx.headers[..ctx.main_headers_nb] {
        if mime::slice_equals_lowercase(&h.name, hname.as_bytes()) {
            js.set_string(hname, &String::from_utf8_lossy(&h.value))?;
            break;
        }
    }
    return Ok(());
}

fn log_data(js: &mut JsonBuilder, ctx: &MimeStateSMTP) -> Result<(), JsonError> {
    log_data_header(js, ctx, "from")?;
    log_field_comma(js, ctx, "to", "to")?;
    log_field_comma(js, ctx, "cc", "cc")?;

    js.set_string("status", "PARSE_DONE")?;

    if !ctx.attachments.is_empty() {
        js.open_array("attachment")?;
        for a in &ctx.attachments {
            js.append_string(&String::from_utf8_lossy(a))?;
        }
        js.close()?;
    }
    if !ctx.urls.is_empty() {
        js.open_array("url")?;
        for a in ctx.urls.iter().rev() {
            js.append_string(&String::from_utf8_lossy(a))?;
        }
        js.close()?;
    }

    return Ok(());
}

#[no_mangle]
pub unsafe extern "C" fn SCMimeSmtpLogData(js: &mut JsonBuilder, ctx: &MimeStateSMTP) -> bool {
    return log_data(js, ctx).is_ok();
}
