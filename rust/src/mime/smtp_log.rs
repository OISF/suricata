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

const SMTP_LOG_MAX_STRING: usize = 8 * 1024;
const SMTP_LOG_MAX_ATTACHMENTS: usize = 128;
const SMTP_LOG_MAX_ATTACH_BYTES: usize = 32 * 1024;
const SMTP_LOG_MAX_URLS: usize = 128;
const SMTP_LOG_MAX_URL_BYTES: usize = 64 * 1024;
const SMTP_LOG_MAX_EMAIL_ITEMS: usize = 64;
const SMTP_LOG_MAX_EMAIL_BYTES: usize = 32 * 1024;

fn smtp_append_limited(js: &mut JsonBuilder, data: &[u8], limit: usize) -> Result<bool, JsonError> {
    let cut = data.len() > limit;
    js.append_string_from_bytes_limited(data, limit)?;
    Ok(cut)
}

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
        js.set_string("body_md5", &ctx.md5_result)?;
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
    let mut count = 0usize;
    let mut bytes = 0usize;
    let mut truncated = false;
    js.open_array(c)?;

    for h in &ctx.headers[..ctx.main_headers_nb] {
        if mime::slice_equals_lowercase(&h.name, e.as_bytes()) {
            if count >= SMTP_LOG_MAX_EMAIL_ITEMS || bytes >= SMTP_LOG_MAX_EMAIL_BYTES {
                truncated = true;
                break;
            }
            found = true;
            let limit = h
                .value
                .len()
                .min(SMTP_LOG_MAX_STRING)
                .min(SMTP_LOG_MAX_EMAIL_BYTES - bytes);
            if smtp_append_limited(js, &h.value, limit)? {
                truncated = true;
            }
            bytes += limit;
            count += 1;
        }
    }

    if found {
        js.close()?;
    } else {
        js.restore_mark(&mark)?;
    }
    if truncated {
        js.set_bool("truncated", true)?;
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
            let mut count = 0usize;
            let mut bytes = 0usize;
            let mut truncated = false;
            let mut cap_reached = false;
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
                                if count >= SMTP_LOG_MAX_EMAIL_ITEMS
                                    || bytes >= SMTP_LOG_MAX_EMAIL_BYTES
                                {
                                    truncated = true;
                                    cap_reached = true;
                                    break;
                                }
                                let limit = (i - start)
                                    .min(SMTP_LOG_MAX_STRING)
                                    .min(SMTP_LOG_MAX_EMAIL_BYTES - bytes);
                                if smtp_append_limited(js, &h.value[start..i], limit)? {
                                    truncated = true;
                                }
                                bytes += limit;
                                count += 1;
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
            if h.value.len() > start && count < SMTP_LOG_MAX_EMAIL_ITEMS && !cap_reached {
                // do not log empty string
                let limit = (h.value.len() - start)
                    .min(SMTP_LOG_MAX_STRING)
                    .min(SMTP_LOG_MAX_EMAIL_BYTES - bytes);
                if smtp_append_limited(js, &h.value[start..], limit)? {
                    truncated = true;
                }
                has_not_empty_field = true;
            }
            if has_not_empty_field {
                js.close()?;
            } else {
                js.restore_mark(&mark)?;
            }
            if truncated {
                js.set_bool("truncated", true)?;
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
            js.set_string_from_bytes_limited(c, &h.value, SMTP_LOG_MAX_STRING)?;
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
            js.set_string_from_bytes_limited(hname, &h.value, SMTP_LOG_MAX_STRING)?;
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

    let mut truncated = false;
    if !ctx.attachments.is_empty() {
        let mut bytes = 0usize;
        let mut att_truncated = ctx.attachments.len() > SMTP_LOG_MAX_ATTACHMENTS;
        js.open_array("attachment")?;
        for a in ctx.attachments.iter().take(SMTP_LOG_MAX_ATTACHMENTS) {
            let remaining = SMTP_LOG_MAX_ATTACH_BYTES.saturating_sub(bytes);
            let limit = a.len().min(remaining).min(SMTP_LOG_MAX_STRING);
            if limit < a.len() {
                att_truncated = true;
            }
            bytes += limit;
            if smtp_append_limited(js, a, limit)? {
                att_truncated = true;
            }
            if bytes == SMTP_LOG_MAX_ATTACH_BYTES {
                break;
            }
        }
        js.close()?;
        if att_truncated {
            js.set_bool("attachments_truncated", true)?;
            truncated = true;
        }
    }
    if !ctx.urls.is_empty() {
        let mut bytes = 0usize;
        let mut emitted = 0usize;
        let mut url_truncated = ctx.urls.len() > SMTP_LOG_MAX_URLS;
        js.open_array("url")?;
        for a in ctx.urls.iter().rev().take(SMTP_LOG_MAX_URLS) {
            let remaining = SMTP_LOG_MAX_URL_BYTES.saturating_sub(bytes);
            let limit = a.len().min(remaining).min(SMTP_LOG_MAX_STRING);
            if limit < a.len() {
                url_truncated = true;
            }
            bytes += limit;
            if smtp_append_limited(js, a, limit)? {
                url_truncated = true;
            }
            emitted += 1;
            if bytes == SMTP_LOG_MAX_URL_BYTES {
                break;
            }
        }
        if emitted < ctx.urls.len().min(SMTP_LOG_MAX_URLS) {
            url_truncated = true;
        }
        js.close()?;
        if url_truncated {
            js.set_bool("urls_truncated", true)?;
            truncated = true;
        }
    }
    if truncated {
        js.set_bool("truncated", true)?;
    }

    return Ok(());
}

#[no_mangle]
pub unsafe extern "C" fn SCMimeSmtpLogData(js: &mut JsonBuilder, ctx: &MimeStateSMTP) -> bool {
    return log_data(js, ctx).is_ok();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filecontainer::FileContainer;
    use crate::mime::smtp::{mime_smtp_state_init, MimeHeader};

    fn init(fc: &mut FileContainer) -> MimeStateSMTP<'_> {
        mime_smtp_state_init(fc, std::ptr::null()).unwrap()
    }

    #[test]
    fn test_to_list_cap() {
        let mut fc = FileContainer::default();
        let mut st = init(&mut fc);
        let mut to = Vec::new();
        for i in 0..70 {
            to.extend_from_slice(format!("u{i}@example.org,").as_bytes());
        }
        st.main_headers_nb = 1;
        st.headers.push(MimeHeader {
            name: b"To".to_vec(),
            value: to,
        });
        let mut js = JsonBuilder::try_new_object().unwrap();
        log_field_comma(&mut js, &st, "to", "to").unwrap();
        assert_eq!(js.as_str().matches("@example.org").count(), 64);
        assert!(js.as_str().ends_with("],\"truncated\":true"));
    }

    #[test]
    fn test_shortened_address_keeps_trailing() {
        let mut fc = FileContainer::default();
        let mut st = init(&mut fc);
        let value = format!("{}, b@x", "A".repeat(9000));
        st.main_headers_nb = 1;
        st.headers.push(MimeHeader {
            name: b"To".to_vec(),
            value: value.into_bytes(),
        });
        let mut js = JsonBuilder::try_new_object().unwrap();
        log_field_comma(&mut js, &st, "to", "to").unwrap();
        assert!(js.as_str().contains("[truncated"));
        assert!(js.as_str().contains("b@x"), "{}", js.as_str());
    }
}
