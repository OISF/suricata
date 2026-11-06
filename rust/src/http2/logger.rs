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

use super::http2::{HTTP2Frame, HTTP2FrameTypeData, HTTP2RepeatedHeaders, HTTP2Transaction};
use super::parser;
use crate::detect::EnumString;
use crate::jsonbuilder::{JsonBuilder, JsonError};
use std;
use std::collections::HashMap;

#[derive(Hash, PartialEq, Eq, Debug)]
enum HeaderName {
    Method,
    Path,
    Host,
    UserAgent,
    Status,
    ContentLength,
}

// logger-owned caps: a header field is cut at 16 KiB, all headers of one
// direction at 32 KiB; cuts are flagged on the record
const HTTP2_LOG_MAX_HEADER_FIELD: usize = 16 * 1024;
const HTTP2_LOG_MAX_HEADERS_SIZE: usize = 32 * 1024;
const HTTP2_LOG_MAX_SETTINGS: usize = 128;
// per-entry object/key overhead, also charged for size updates and errors
const HTTP2_LOG_ENTRY_OVERHEAD: usize = 24;
const HTTP2_LOG_MAX_ENTRIES: usize = 1024;

struct HeaderLogBudget {
    remaining: usize,
    entries: usize,
    truncated: bool,
}

impl HeaderLogBudget {
    fn new() -> Self {
        Self {
            remaining: HTTP2_LOG_MAX_HEADERS_SIZE,
            entries: 0,
            truncated: false,
        }
    }

    fn room(&mut self, cost: usize) -> bool {
        if self.entries >= HTTP2_LOG_MAX_ENTRIES || cost > self.remaining {
            self.truncated = true;
            return false;
        }
        self.remaining -= cost;
        self.entries += 1;
        true
    }
}

fn log_http2_headers<'a>(
    blocks: &'a [parser::HTTP2FrameHeaderBlock], js: &mut JsonBuilder,
    common: &mut HashMap<HeaderName, &'a Vec<u8>>, repeated: &mut HTTP2RepeatedHeaders,
    budget: &mut HeaderLogBudget,
) -> Result<bool, JsonError> {
    let mut has_auth = false;
    let mut emitted = false;
    for block in blocks {
        match block.error {
            parser::HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess => {
                if repeated.add(block) {
                    continue;
                }
                if let Ok(name) = std::str::from_utf8(&block.name) {
                    match name.to_lowercase().as_ref() {
                        ":method" => {
                            common.insert(HeaderName::Method, &block.value);
                        }
                        ":path" => {
                            common.insert(HeaderName::Path, &block.value);
                        }
                        ":status" => {
                            common.insert(HeaderName::Status, &block.value);
                        }
                        "user-agent" => {
                            common.insert(HeaderName::UserAgent, &block.value);
                        }
                        ":authority" => {
                            has_auth = true;
                            common.insert(HeaderName::Host, &block.value);
                        }
                        "host" if !has_auth => {
                            common.insert(HeaderName::Host, &block.value);
                        }
                        "content-length" => {
                            common.insert(HeaderName::ContentLength, &block.value);
                        }
                        _ => {}
                    }
                }
                if budget.remaining <= HTTP2_LOG_ENTRY_OVERHEAD {
                    budget.truncated = true;
                    continue;
                }
                let name_len = std::cmp::min(
                    block.name.len(),
                    std::cmp::min(
                        HTTP2_LOG_MAX_HEADER_FIELD,
                        budget.remaining - HTTP2_LOG_ENTRY_OVERHEAD,
                    ),
                );
                if name_len < block.name.len() {
                    budget.truncated = true;
                }
                let value_limit = std::cmp::min(
                    block.value.len(),
                    budget.remaining - HTTP2_LOG_ENTRY_OVERHEAD - name_len,
                );
                if value_limit < block.value.len() {
                    budget.truncated = true;
                }
                if !budget.room(HTTP2_LOG_ENTRY_OVERHEAD + name_len + value_limit) {
                    continue;
                }
                emitted = true;
                js.start_object()?;
                js.set_string_from_bytes("name", &block.name[..name_len])?;
                js.set_string_from_bytes_limited("value", &block.value, value_limit)?;
                js.close()?;
            }
            parser::HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSizeUpdate => {
                if !budget.room(HTTP2_LOG_ENTRY_OVERHEAD + 16) {
                    continue;
                }
                emitted = true;
                js.start_object()?;
                js.set_uint("table_size_update", block.sizeupdate)?;
                js.close()?;
            }
            _ => {
                if !budget.room(HTTP2_LOG_ENTRY_OVERHEAD + 40) {
                    continue;
                }
                emitted = true;
                js.start_object()?;
                js.set_string("error", &block.error.to_string())?;
                js.close()?;
            }
        }
    }
    return Ok(emitted);
}

fn log_headers<'a>(
    frames: &'a Vec<HTTP2Frame>, js: &mut JsonBuilder,
    common: &mut HashMap<HeaderName, &'a Vec<u8>>, truncated: &mut bool,
) -> Result<bool, JsonError> {
    let mut has_headers = false;
    let mut repeated = HTTP2RepeatedHeaders::default();
    let mut budget = HeaderLogBudget::new();
    for frame in frames {
        match &frame.data {
            HTTP2FrameTypeData::HEADERS(hd) => {
                has_headers |=
                    log_http2_headers(&hd.blocks, js, common, &mut repeated, &mut budget)?;
            }
            HTTP2FrameTypeData::PUSHPROMISE(hd) => {
                has_headers |=
                    log_http2_headers(&hd.blocks, js, common, &mut repeated, &mut budget)?;
            }
            HTTP2FrameTypeData::CONTINUATION(hd) => {
                has_headers |=
                    log_http2_headers(&hd.blocks, js, common, &mut repeated, &mut budget)?;
            }
            _ => {}
        }
    }
    *truncated = budget.truncated;
    Ok(has_headers)
}

fn log_http2_frames(
    frames: &[HTTP2Frame], js: &mut JsonBuilder, settings_truncated: &mut bool,
) -> Result<bool, JsonError> {
    let mut has_settings = false;
    let mut settings_count = 0usize;
    for frame in frames {
        if let HTTP2FrameTypeData::SETTINGS(set) = &frame.data {
            if set.is_empty() {
                /* an empty SETTINGS frame (e.g. an ACK) has no entries and
                 * must not open an empty settings array */
                continue;
            }
            if !has_settings {
                js.open_array("settings")?;
                has_settings = true;
            }
            for e in set {
                if settings_count >= HTTP2_LOG_MAX_SETTINGS {
                    *settings_truncated = true;
                    break;
                }
                settings_count += 1;
                js.start_object()?;
                js.set_string(
                    "settings_id",
                    &format!("SETTINGS{}", e.id.to_string().to_uppercase()),
                )?;
                js.set_uint("settings_value", e.value as u64)?;
                js.close()?;
            }
        }
    }
    if has_settings {
        js.close()?;
    }

    let mut has_error_code = false;
    let mut has_priority = false;
    let mut has_multiple = false;
    for frame in frames {
        match &frame.data {
            HTTP2FrameTypeData::GOAWAY(goaway) => {
                if !has_error_code {
                    if let Some(errcode) = parser::HTTP2ErrorCode::from_u(goaway.errorcode) {
                        js.set_string("error_code", errcode.to_str())?;
                    } else {
                        js.set_string("error_code", &format!("unknown-{}", goaway.errorcode))?;
                    }
                    has_error_code = true;
                } else if !has_multiple {
                    js.set_string("has_multiple", "error_code")?;
                    has_multiple = true;
                }
            }
            HTTP2FrameTypeData::RSTSTREAM(rst) => {
                if !has_error_code {
                    if let Some(errcode) = parser::HTTP2ErrorCode::from_u(rst.errorcode) {
                        js.set_string("error_code", errcode.to_str())?;
                    } else {
                        js.set_string("error_code", &format!("unknown-{}", rst.errorcode))?;
                    }
                    has_error_code = true;
                } else if !has_multiple {
                    js.set_string("has_multiple", "error_code")?;
                    has_multiple = true;
                }
            }
            HTTP2FrameTypeData::PRIORITY(priority) => {
                if !has_priority {
                    js.set_uint("priority", priority.weight as u64)?;
                    has_priority = true;
                } else if !has_multiple {
                    js.set_string("has_multiple", "priority")?;
                    has_multiple = true;
                }
            }
            HTTP2FrameTypeData::HEADERS(hd) => {
                if let Some(ref priority) = hd.priority {
                    if !has_priority {
                        js.set_uint("priority", priority.weight as u64)?;
                        has_priority = true;
                    } else if !has_multiple {
                        js.set_string("has_multiple", "priority")?;
                        has_multiple = true;
                    }
                }
            }
            _ => {}
        }
    }
    return Ok(has_settings || has_error_code || has_priority);
}

fn log_http2(tx: &HTTP2Transaction, js: &mut JsonBuilder) -> Result<bool, JsonError> {
    js.open_object("http")?;
    js.set_string("version", "2")?;

    let mut common: HashMap<HeaderName, &Vec<u8>> = HashMap::new();

    let mut has_headers = false;

    // Request headers.
    let mark = js.get_mark();
    let mut truncated = false;
    js.open_array("request_headers")?;
    if log_headers(&tx.frames_ts, js, &mut common, &mut truncated)? {
        js.close()?;
        has_headers = true;
    } else {
        js.restore_mark(&mark)?;
    }
    if truncated {
        js.set_bool("request_headers_truncated", true)?;
    }

    // Response headers.
    let mark = js.get_mark();
    let mut truncated = false;
    js.open_array("response_headers")?;
    if log_headers(&tx.frames_tc, js, &mut common, &mut truncated)? {
        js.close()?;
        has_headers = true;
    } else {
        js.restore_mark(&mark)?;
    }
    if truncated {
        js.set_bool("response_headers_truncated", true)?;
    }

    for (name, value) in common {
        match name {
            HeaderName::Method => {
                js.set_string_from_bytes_limited("http_method", value, HTTP2_LOG_MAX_HEADER_FIELD)?;
            }
            HeaderName::Path => {
                js.set_string_from_bytes_limited("url", value, HTTP2_LOG_MAX_HEADER_FIELD)?;
            }
            HeaderName::Host => {
                js.set_string_from_bytes_limited("hostname", value, HTTP2_LOG_MAX_HEADER_FIELD)?;
            }
            HeaderName::UserAgent => {
                js.set_string_from_bytes_limited(
                    "http_user_agent",
                    value,
                    HTTP2_LOG_MAX_HEADER_FIELD,
                )?;
            }
            HeaderName::ContentLength => {
                if let Ok(value) = std::str::from_utf8(value) {
                    if let Ok(value) = value.parse::<u64>() {
                        js.set_uint("length", value)?;
                    }
                }
            }
            HeaderName::Status => {
                if let Ok(value) = std::str::from_utf8(value) {
                    if let Ok(value) = value.parse::<u64>() {
                        js.set_uint("status", value)?;
                    }
                }
            }
        }
    }

    // The rest of http2 logging is placed in an "http2" object.
    js.open_object("http2")?;

    js.set_uint("stream_id", tx.stream_id as u64)?;
    let mark = js.get_mark();
    let mut settings_truncated = false;
    js.open_object("request")?;
    let has_request = log_http2_frames(&tx.frames_ts, js, &mut settings_truncated)?;
    if has_request {
        js.close()?;
    } else {
        js.restore_mark(&mark)?;
    }

    let mark = js.get_mark();
    let mut settings_truncated_tc = false;
    js.open_object("response")?;
    let has_response = log_http2_frames(&tx.frames_tc, js, &mut settings_truncated_tc)?;
    if has_response {
        js.close()?;
    } else {
        js.restore_mark(&mark)?;
    }
    if settings_truncated || settings_truncated_tc {
        js.set_bool("settings_truncated", true)?;
    }

    js.close()?; // http2
    js.close()?; // http

    return Ok(has_request || has_response || has_headers);
}

#[no_mangle]
pub unsafe extern "C" fn SCHttp2LogJson(
    tx: *mut std::os::raw::c_void, js: &mut JsonBuilder,
) -> bool {
    let tx = cast_pointer!(tx, HTTP2Transaction);
    if let Ok(x) = log_http2(tx, js) {
        return x;
    }
    return false;
}
