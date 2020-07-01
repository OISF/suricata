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
use crate::log::*;
use std;

fn log_http2_headers(
    blocks: &Vec<parser::HTTP2FrameHeaderBlock>, js: &mut JsonBuilder,
) -> Result<(), JsonError> {
    for j in 0..blocks.len() {
        js.start_object()?;
        if blocks[j].error == parser::HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSuccess {
            js.set_string_from_bytes("name", &blocks[j].name)?;
            js.set_string_from_bytes("value", &blocks[j].value)?;
        } else {
            js.set_string("error", &blocks[j].error.to_string())?;
        }
        js.close()?;
    }
    return Ok(());
}

fn log_http2_frames(frames: &Vec<HTTP2Frame>, js: &mut JsonBuilder) -> Result<(), JsonError> {
    let mut has_settings = false;
    for i in 0..frames.len() {
        if let HTTP2FrameTypeData::SETTINGS(set) = &frames[i].data {
            if !has_settings {
                js.open_array("settings")?;
                has_settings = true;
            }
            for j in 0..set.len() {
                js.start_object()?;
                js.set_string("settings_id", &set[j].id.to_string())?;
                js.set_uint("settings_value", set[j].value as u64)?;
                js.close()?;
            }
        }
    }
    if has_settings {
        js.close()?;
    }

    let mut has_headers = false;
    for i in 0..frames.len() {
        match &frames[i].data {
            HTTP2FrameTypeData::HEADERS(hd) => {
                if !has_settings {
                    js.open_array("headers")?;
                    has_headers = true;
                }
                log_http2_headers(&hd.blocks, js)?;
            }
            HTTP2FrameTypeData::PUSHPROMISE(hd) => {
                if !has_settings {
                    js.open_array("headers")?;
                    has_headers = true;
                }
                log_http2_headers(&hd.blocks, js)?;
            }
            HTTP2FrameTypeData::CONTINUATION(hd) => {
                if !has_settings {
                    js.open_array("headers")?;
                    has_headers = true;
                }
                log_http2_headers(&hd.blocks, js)?;
            }
            _ => {}
        }
    }
    if has_headers {
        js.close()?;
    }

    let mut has_error_code = false;
    let mut has_priority = false;
    let mut has_window = false;
    let mut has_multiple = false;
    for i in 0..frames.len() {
        match &frames[i].data {
            HTTP2FrameTypeData::GOAWAY(goaway) => {
                if !has_error_code {
                    js.set_string("error_code", &goaway.errorcode.to_string())?;
                    has_error_code = true;
                } else if !has_multiple {
                    js.set_string("has_multiple", "error_code")?;
                    has_multiple = true;
                }
            }
            HTTP2FrameTypeData::RSTSTREAM(rst) => {
                if !has_error_code {
                    js.set_string("error_code", &rst.errorcode.to_string())?;
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
            HTTP2FrameTypeData::WINDOWUPDATE(wu) => {
                if !has_window {
                    js.set_uint("window", wu.sizeinc as u64)?;
                    has_window = true;
                } else if !has_multiple {
                    js.set_string("has_multiple", "window")?;
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
    return Ok(());
}

fn log_http2(tx: &HTTP2Transaction, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.set_uint("stream_id", tx.stream_id as u64)?;
    js.open_object("request")?;
    log_http2_frames(&tx.frames_ts, js)?;
    js.close()?;
    js.open_object("response")?;
    log_http2_frames(&tx.frames_tc, js)?;
    js.close()?;

    return Ok(());
}

#[no_mangle]
pub extern "C" fn rs_http2_log_json(tx: *mut std::os::raw::c_void, js: &mut JsonBuilder) -> bool {
    let tx = cast_pointer!(tx, HTTP2Transaction);
    return log_http2(tx, js).is_ok();
}
