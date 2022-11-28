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

use super::http2::{HTTP2Frame, HTTP2FrameTypeData, HTTP2Transaction};
use super::parser;
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

fn log_http2_headers<'a>(
    blocks: &'a [parser::HTTP2FrameHeaderBlock], js: &mut JsonBuilder,
    common: &mut HashMap<HeaderName, &'a Vec<u8>>,
) -> Result<(), JsonError> {
    for block in blocks {
        js.start_object()?;
        match block.error {
            parser::HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess => {
                js.set_string_from_bytes("name", &block.name)?;
                js.set_string_from_bytes("value", &block.value)?;
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
                        "host" => {
                            common.insert(HeaderName::Host, &block.value);
                        }
                        "content-length" => {
                            common.insert(HeaderName::ContentLength, &block.value);
                        }
                        _ => {}
                    }
                }
            }
            parser::HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSizeUpdate => {
                js.set_uint("table_size_update", block.sizeupdate)?;
            }
            _ => {
                js.set_string("error", &block.error.to_string())?;
            }
        }
        js.close()?;
    }
    return Ok(());
}

fn log_headers<'a>(
    frames: &'a Vec<HTTP2Frame>, js: &mut JsonBuilder,
    common: &mut HashMap<HeaderName, &'a Vec<u8>>,
) -> Result<bool, JsonError> {
    let mut has_headers = false;
    for frame in frames {
        match &frame.data {
            HTTP2FrameTypeData::HEADERS(hd) => {
                log_http2_headers(&hd.blocks, js, common)?;
                has_headers = true;
            }
            HTTP2FrameTypeData::PUSHPROMISE(hd) => {
                log_http2_headers(&hd.blocks, js, common)?;
                has_headers = true;
            }
            HTTP2FrameTypeData::CONTINUATION(hd) => {
                log_http2_headers(&hd.blocks, js, common)?;
                has_headers = true;
            }
            _ => {}
        }
    }
    Ok(has_headers)
}

fn log_http2_frames(frames: &[HTTP2Frame], js: &mut JsonBuilder) -> Result<bool, JsonError> {
    let mut has_settings = false;
    for frame in frames {
        if let HTTP2FrameTypeData::SETTINGS(set) = &frame.data {
            if !has_settings {
                js.open_array("settings")?;
                has_settings = true;
            }
            for e in set {
                js.start_object()?;
                js.set_string("settings_id", &e.id.to_string())?;
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
                    let errcode: Option<parser::HTTP2ErrorCode> =
                        num::FromPrimitive::from_u32(goaway.errorcode);
                    match errcode {
                        Some(errstr) => {
                            js.set_string("error_code", &errstr.to_string())?;
                        }
                        None => {
                            //use uint32
                            js.set_string("error_code", &goaway.errorcode.to_string())?;
                        }
                    }
                    has_error_code = true;
                } else if !has_multiple {
                    js.set_string("has_multiple", "error_code")?;
                    has_multiple = true;
                }
            }
            HTTP2FrameTypeData::RSTSTREAM(rst) => {
                if !has_error_code {
                    let errcode: Option<parser::HTTP2ErrorCode> =
                        num::FromPrimitive::from_u32(rst.errorcode);
                    match errcode {
                        Some(errstr) => {
                            js.set_string("error_code", &errstr.to_string())?;
                        }
                        None => {
                            //use uint32
                            js.set_string("error_code", &rst.errorcode.to_string())?;
                        }
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
    js.set_string("version", "2")?;

    let mut common: HashMap<HeaderName, &Vec<u8>> = HashMap::new();

    let mut has_headers = false;

    // Request headers.
    let mark = js.get_mark();
    js.open_array("request_headers")?;
    if log_headers(&tx.frames_ts, js, &mut common)? {
        js.close()?;
        has_headers = true;
    } else {
        js.restore_mark(&mark)?;
    }

    // Response headers.
    let mark = js.get_mark();
    js.open_array("response_headers")?;
    if log_headers(&tx.frames_tc, js, &mut common)? {
        js.close()?;
        has_headers = true;
    } else {
        js.restore_mark(&mark)?;
    }

    for (name, value) in common {
        match name {
            HeaderName::Method => {
                js.set_string_from_bytes("http_method", value)?;
            }
            HeaderName::Path => {
                js.set_string_from_bytes("url", value)?;
            }
            HeaderName::Host => {
                js.set_string_from_bytes("hostname", value)?;
            }
            HeaderName::UserAgent => {
                js.set_string_from_bytes("http_user_agent", value)?;
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
    js.open_object("request")?;
    let has_request = log_http2_frames(&tx.frames_ts, js)?;
    js.close()?;

    js.open_object("response")?;
    let has_response = log_http2_frames(&tx.frames_tc, js)?;
    js.close()?;

    // Close http2.
    js.close()?;

    return Ok(has_request || has_response || has_headers);
}

#[no_mangle]
pub unsafe extern "C" fn rs_http2_log_json(
    tx: *mut std::os::raw::c_void, js: &mut JsonBuilder,
) -> bool {
    let tx = cast_pointer!(tx, HTTP2Transaction);
    if let Ok(x) = log_http2(tx, js) {
        return x;
    }
    return false;
}
