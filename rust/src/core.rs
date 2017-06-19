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

use filecontainer::*;

/// Opaque C types.
pub enum Flow {}
pub enum DetectEngineState {}
pub enum AppLayerDecoderEvents {}

// From app-layer-events.h
pub type AppLayerEventType = libc::c_int;
pub const APP_LAYER_EVENT_TYPE_TRANSACTION : i32 = 1;
pub const APP_LAYER_EVENT_TYPE_PACKET      : i32 = 2;

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

pub struct SuricataStreamingBufferConfig;

//File *(*FileOpenFile)(FileContainer *, const StreamingBufferConfig *,
//       const uint8_t *name, uint16_t name_len,
//       const uint8_t *data, uint32_t data_len, uint16_t flags);
pub type SCFileOpenFileWithId = extern "C" fn (
        file_container: &FileContainer,
        sbcfg: &SuricataStreamingBufferConfig,
        track_id: u32,
        name: *const u8, name_len: u16,
        data: *const u8, data_len: u32,
        flags: u16) -> File;
//int (*FileCloseFile)(FileContainer *, const uint8_t *data, uint32_t data_len, uint16_t flags);
pub type SCFileCloseFileById = extern "C" fn (
        file_container: &FileContainer,
        track_id: u32,
        data: *const u8, data_len: u32,
        flags: u16) -> i32;
//int (*FileAppendData)(FileContainer *, const uint8_t *data, uint32_t data_len);
pub type SCFileAppendDataById = extern "C" fn (
        file_container: &FileContainer,
        track_id: u32,
        data: *const u8, data_len: u32) -> i32;
pub type SCFileAppendGAPById = extern "C" fn (
        file_container: &FileContainer,
        track_id: u32,
        data: *const u8, data_len: u32) -> i32;
// void FilePrune(FileContainer *ffc)
pub type SCFilePrune = extern "C" fn (
        file_container: &FileContainer);
// void FileContainerRecycle(FileContainer *ffc)
pub type SCFileContainerRecycle = extern "C" fn (
        file_container: &FileContainer);

pub type SCFileSetTx = extern "C" fn (
        file: &FileContainer,
        tx_id: u64);

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
    pub SCLogMessage: SCLogMessageFunc,
    DetectEngineStateFree: DetectEngineStateFreeFunc,
    AppLayerDecoderEventsSetEventRaw: AppLayerDecoderEventsSetEventRawFunc,
    AppLayerDecoderEventsFreeEvents: AppLayerDecoderEventsFreeEventsFunc,

    pub FileOpenFile: SCFileOpenFileWithId,
    pub FileCloseFile: SCFileCloseFileById,
    pub FileAppendData: SCFileAppendDataById,
    pub FileAppendGAP: SCFileAppendGAPById,
    pub FileContainerRecycle: SCFileContainerRecycle,
    pub FilePrune: SCFilePrune,
    pub FileSetTx: SCFileSetTx,
}

#[allow(non_snake_case)]
#[repr(C)]
pub struct SuricataFileContext {
    pub files_sbcfg: &'static SuricataStreamingBufferConfig,
}

pub static mut SC: Option<&'static SuricataContext> = None;

#[no_mangle]
pub extern "C" fn rs_init(context: &'static mut SuricataContext)
{
    unsafe {
        SC = Some(context);
    }
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
