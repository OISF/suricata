/* Copyright (C) 2017 Open Information Security Foundation
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

// This file exposes items from the core "C" code to Rust.

extern crate libc;

/// Opaque C types.
pub enum Flow {}
pub enum DetectEngineState {}
pub enum AppLayerDecoderEvents {}

// From stream.h.
pub const STREAM_TOSERVER: u8 = 0x04;
pub const STREAM_TOCLIENT: u8 = 0x08;

macro_rules!BIT_U64 {
    ($x:expr) => (1 << $x);
}

//
// Function types for calls into C.
//

#[allow(non_snake_case)]
pub type SCLogMessageFunc =
    extern "C" fn(level: libc::c_int,
                  filename: *const libc::c_char,
                  line: libc::c_uint,
                  function: *const libc::c_char,
                  code: libc::c_int,
                  message: *const libc::c_char) -> libc::c_int;

pub type DetectEngineStateFreeFunc =
    extern "C" fn(state: *mut DetectEngineState);

pub type AppLayerDecoderEventsSetEventRawFunc =
    extern "C" fn (events: *mut *mut AppLayerDecoderEvents,
                   event: libc::uint8_t);

pub type AppLayerDecoderEventsFreeEventsFunc =
    extern "C" fn (events: *mut *mut AppLayerDecoderEvents);

// A Suricata context that is passed in from C. This is alternative to
// using functions from Suricata directly, so they can be wrapped so
// Rust unit tests will still compile when they are not linked
// directly to the real function.
//
// This might add a little too much complexity to keep pure Rust test
// cases working.
#[allow(non_snake_case)]
#[repr(C)]
pub struct SuricataContext {
    SCLogMessage: SCLogMessageFunc,
    DetectEngineStateFree: DetectEngineStateFreeFunc,
    AppLayerDecoderEventsSetEventRaw: AppLayerDecoderEventsSetEventRawFunc,
    AppLayerDecoderEventsFreeEvents: AppLayerDecoderEventsFreeEventsFunc,
}

pub static mut SC: Option<&'static SuricataContext> = None;

#[no_mangle]
pub extern "C" fn rs_init(context: &'static mut SuricataContext)
{
    unsafe {
        SC = Some(context);
    }
}

/// SCLogMessage wrapper.
pub fn sc_log_message(level: libc::c_int,
                      filename: *const libc::c_char,
                      line: libc::c_uint,
                      function: *const libc::c_char,
                      code: libc::c_int,
                      message: *const libc::c_char) -> libc::c_int
{
    unsafe {
        if let Some(c) = SC {
            return (c.SCLogMessage)(level, filename, line, function,
                                  code, message);
        }
    }
    return 0;
}

/// DetectEngineStateFree wrapper.
pub fn sc_detect_engine_state_free(state: *mut DetectEngineState)
{
    unsafe {
        if let Some(c) = SC {
            (c.DetectEngineStateFree)(state);
        }
    }
}

/// AppLayerDecoderEventsSetEventRaw wrapper.
pub fn sc_app_layer_decoder_events_set_event_raw(
    events: *mut *mut AppLayerDecoderEvents, event: libc::uint8_t)
{
    unsafe {
        if let Some(c) = SC {
            (c.AppLayerDecoderEventsSetEventRaw)(events, event);
        }
    }
}

/// AppLayerDecoderEventsFreeEvents wrapper.
pub fn sc_app_layer_decoder_events_free_events(
    events: *mut *mut AppLayerDecoderEvents)
{
    unsafe {
        if let Some(c) = SC {
            (c.AppLayerDecoderEventsFreeEvents)(events);
        }
    }
}
