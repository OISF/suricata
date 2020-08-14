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

use std;
use crate::filecontainer::*;

/// Opaque C types.
pub type DetectEngineState = crate::ffi::DetectEngineState;
pub type AppLayerDecoderEvents = crate::ffi::AppLayerDecoderEvents;
pub enum AppLayerParserState {}

// From app-layer-events.h
pub type AppLayerEventType = std::os::raw::c_int;
pub const APP_LAYER_EVENT_TYPE_TRANSACTION : i32 = 1;
pub const APP_LAYER_EVENT_TYPE_PACKET      : i32 = 2;

// From stream.h.
pub const STREAM_START:    u8 = 0x01;
pub const STREAM_EOF:      u8 = 0x02;
pub const STREAM_TOSERVER: u8 = 0x04;
pub const STREAM_TOCLIENT: u8 = 0x08;
pub const STREAM_GAP:      u8 = 0x10;
pub const STREAM_DEPTH:    u8 = 0x20;
pub const STREAM_MIDSTREAM:u8 = 0x40;

// Application layer protocol identifiers (app-layer-protos.h)
pub type AppProto = std::os::raw::c_int;

pub const ALPROTO_UNKNOWN : AppProto = 0;
pub static mut ALPROTO_FAILED : AppProto = 0; // updated during init

pub const IPPROTO_TCP : i32 = 6;
pub const IPPROTO_UDP : i32 = 17;

macro_rules!BIT_U32 {
    ($x:expr) => (1 << $x);
}

macro_rules!BIT_U64 {
    ($x:expr) => (1 << $x);
}

// Defined in app-layer-protos.h
extern {
    pub fn StringToAppProto(proto_name: *const u8) -> AppProto;
}

//
// Function types for calls into C.
//

pub type AppLayerDecoderEventsSetEventRawFunc =
    extern "C" fn (events: *mut *mut AppLayerDecoderEvents,
                   event: u8);

pub type SuricataStreamingBufferConfig = crate::ffi::SuricataStreamingBufferConfig;

pub type SCFileOpenFileWithId = extern "C" fn (
        file_container: &FileContainer,
        sbcfg: &SuricataStreamingBufferConfig,
        track_id: u32,
        name: *const u8, name_len: u16,
        data: *const u8, data_len: u32,
        flags: u16) -> i32;
pub type SCFileCloseFileById = extern "C" fn (
        file_container: &FileContainer,
        track_id: u32,
        data: *const u8, data_len: u32,
        flags: u16) -> i32;
pub type SCFileAppendDataById = extern "C" fn (
        file_container: &FileContainer,
        track_id: u32,
        data: *const u8, data_len: u32) -> i32;
pub type SCFileAppendGAPById = extern "C" fn (
        file_container: &FileContainer,
        track_id: u32,
        data: *const u8, data_len: u32) -> i32;
pub type SCFilePrune = extern "C" fn (
        file_container: &FileContainer);
pub type SCFileContainerRecycle = extern "C" fn (
        file_container: &FileContainer);
pub type SCFileSetTx = extern "C" fn (
        file: &FileContainer,
        tx_id: u64);

#[allow(non_snake_case)]
#[repr(C)]
pub struct SuricataFileContext {
    pub files_sbcfg: &'static SuricataStreamingBufferConfig,
}

#[no_mangle]
pub extern "C" fn rs_init()
{
    unsafe {
        ALPROTO_FAILED = StringToAppProto("failed\0".as_ptr());
    }
}

/// DetectEngineStateFree wrapper.
pub fn sc_detect_engine_state_free(state: *mut crate::ffi::DetectEngineState)
{
    if let Some(f) = *crate::ffi::DetectEngineStateFree {
        f(state);
    }
}

/// AppLayerDecoderEventsSetEventRaw wrapper.
pub fn sc_app_layer_decoder_events_set_event_raw(
    events: *mut *mut AppLayerDecoderEvents, event: u8)
{
    if let Some(f) = *crate::ffi::AppLayerDecoderEventsSetEventRaw {
        f(events, event);
    }
}

/// AppLayerDecoderEventsFreeEvents wrapper.
pub fn sc_app_layer_decoder_events_free_events(
    events: *mut *mut AppLayerDecoderEvents)
{
    if let Some(f) = *crate::ffi::AppLayerDecoderEventsFreeEvents {
        f(events);
    }
}

/// Opaque flow type (defined in C)
pub enum Flow {}

/// Extern functions operating on Flow.
extern {
    pub fn FlowGetLastTimeAsParts(flow: &Flow, secs: *mut u64, usecs: *mut u64);
}

/// Rust implementation of Flow.
impl Flow {

    /// Return the time of the last flow update as a `Duration`
    /// since the epoch.
    pub fn get_last_time(&mut self) -> std::time::Duration {
        unsafe {
            let mut secs: u64 = 0;
            let mut usecs: u64 = 0;
            FlowGetLastTimeAsParts(self, &mut secs, &mut usecs);
            std::time::Duration::new(secs, usecs as u32 * 1000)
        }
    }
}
