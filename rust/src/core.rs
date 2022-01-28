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
use crate::debug_validate_fail;

/// Opaque C types.
pub enum DetectEngineState {}
pub enum AppLayerDecoderEvents {}
pub enum AppLayerParserState {}

// From app-layer-events.h
pub type AppLayerEventType = std::os::raw::c_int;
pub const APP_LAYER_EVENT_TYPE_TRANSACTION : i32 = 1;
pub const APP_LAYER_EVENT_TYPE_PACKET      : i32 = 2;

pub const STREAM_START:    u8 = 0x01;
pub const STREAM_EOF:      u8 = 0x02;
pub const STREAM_TOSERVER: u8 = 0x04;
pub const STREAM_TOCLIENT: u8 = 0x08;
pub const STREAM_GAP:      u8 = 0x10;
pub const STREAM_DISRUPTED:u8 = 0x20;
pub const STREAM_MIDSTREAM:u8 = 0x40;
pub const STREAM_FLUSH:    u8 = 0x80;
pub const DIR_BOTH:        u8 = 0b0000_1100;
const DIR_TOSERVER:        u8 = 0b0000_0100;
const DIR_TOCLIENT:        u8 = 0b0000_1000;

#[repr(C)]
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Direction {
    ToServer = 0x04,
    ToClient = 0x08,
}

impl Default for Direction {
    fn default() -> Self { Direction::ToServer }
}

impl From<u8> for Direction {
    fn from(d: u8) -> Self {
        if d & (DIR_TOSERVER | DIR_TOCLIENT) == (DIR_TOSERVER | DIR_TOCLIENT) {
            debug_validate_fail!("Both directions are set");
            Direction::ToServer
        } else if d & DIR_TOSERVER != 0 {
            Direction::ToServer
        } else if d & DIR_TOCLIENT != 0 {
            Direction::ToClient
        } else {
            debug_validate_fail!("Unknown direction!!");
            Direction::ToServer
        }
    }
}

impl From<Direction> for u8 {
    fn from(d: Direction) -> u8 {
        d as u8
    }
}

// Application layer protocol identifiers (app-layer-protos.h)
pub type AppProto = u16;

pub const ALPROTO_UNKNOWN : AppProto = 0;
pub static mut ALPROTO_FAILED : AppProto = 0; // updated during init

pub const IPPROTO_TCP : u8 = 6;
pub const IPPROTO_UDP : u8 = 17;

macro_rules!BIT_U8 {
    ($x:expr) => (1 << $x);
}

macro_rules!BIT_U16 {
    ($x:expr) => (1 << $x);
}

macro_rules!BIT_U32 {
    ($x:expr) => (1 << $x);
}

macro_rules!BIT_U64 {
    ($x:expr) => (1 << $x);
}

// Flow flags
pub const FLOW_DIR_REVERSED: u32 = BIT_U32!(26);

// Defined in app-layer-protos.h
extern {
    pub fn StringToAppProto(proto_name: *const u8) -> AppProto;
}

//
// Function types for calls into C.
//

#[allow(non_snake_case)]
pub type SCLogMessageFunc =
    extern "C" fn(level: std::os::raw::c_int,
                  filename: *const std::os::raw::c_char,
                  line: std::os::raw::c_uint,
                  function: *const std::os::raw::c_char,
                  code: std::os::raw::c_int,
                  message: *const std::os::raw::c_char) -> std::os::raw::c_int;

pub type DetectEngineStateFreeFunc =
    extern "C" fn(state: *mut DetectEngineState);

pub type AppLayerParserTriggerRawStreamReassemblyFunc =
    extern "C" fn (flow: *const Flow, direction: i32);
pub type AppLayerDecoderEventsSetEventRawFunc =
    extern "C" fn (events: *mut *mut AppLayerDecoderEvents,
                   event: u8);

pub type AppLayerDecoderEventsFreeEventsFunc =
    extern "C" fn (events: *mut *mut AppLayerDecoderEvents);

pub enum StreamingBufferConfig {}

// Opaque flow type (defined in C)
pub enum HttpRangeContainerBlock {}

pub type SCHttpRangeFreeBlock = extern "C" fn (
        c: *mut HttpRangeContainerBlock);
pub type SCHTPFileCloseHandleRange = extern "C" fn (
        fc: *mut FileContainer,
        flags: u16,
        c: *mut HttpRangeContainerBlock,
        data: *const u8,
        data_len: u32) -> bool;
pub type SCFileOpenFileWithId = extern "C" fn (
        file_container: &FileContainer,
        sbcfg: &StreamingBufferConfig,
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
    pub AppLayerParserTriggerRawStreamReassembly: AppLayerParserTriggerRawStreamReassemblyFunc,

    pub HttpRangeFreeBlock: SCHttpRangeFreeBlock,
    pub HTPFileCloseHandleRange: SCHTPFileCloseHandleRange,

    pub FileOpenFile: SCFileOpenFileWithId,
    pub FileCloseFile: SCFileCloseFileById,
    pub FileAppendData: SCFileAppendDataById,
    pub FileAppendGAP: SCFileAppendGAPById,
    pub FileContainerRecycle: SCFileContainerRecycle,
    pub FilePrune: SCFilePrune,
    pub FileSetTx: SCFileSetTx,

    pub AppLayerRegisterParser: extern fn(parser: *const crate::applayer::RustParser, alproto: AppProto) -> std::os::raw::c_int,
}

#[allow(non_snake_case)]
#[repr(C)]
pub struct SuricataFileContext {
    pub files_sbcfg: &'static StreamingBufferConfig,
}

extern {
    pub fn SCGetContext() -> &'static mut SuricataContext;
    pub fn SCLogGetLogLevel() -> i32;
}

pub static mut SC: Option<&'static SuricataContext> = None;

pub fn init_ffi(context: &'static SuricataContext)
{
    unsafe {
        SC = Some(context);
        ALPROTO_FAILED = StringToAppProto("failed\0".as_ptr());
    }
}

#[no_mangle]
pub extern "C" fn rs_init(context: &'static SuricataContext)
{
    init_ffi(context);
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

/// AppLayerParserTriggerRawStreamReassembly wrapper
pub fn sc_app_layer_parser_trigger_raw_stream_reassembly(flow: *const Flow, direction: i32) {
    unsafe {
        if let Some(c) = SC {
            (c.AppLayerParserTriggerRawStreamReassembly)(flow, direction);
        }
    }
}

/// AppLayerDecoderEventsSetEventRaw wrapper.
pub fn sc_app_layer_decoder_events_set_event_raw(
    events: *mut *mut AppLayerDecoderEvents, event: u8)
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

/// Opaque flow type (defined in C)
pub enum Flow {}

// Extern functions operating on Flow.
extern {
    pub fn FlowGetLastTimeAsParts(flow: &Flow, secs: *mut u64, usecs: *mut u64);
    pub fn FlowGetFlags(flow: &Flow) -> u32;
    pub fn FlowGetSourcePort(flow: &Flow) -> u16;
    pub fn FlowGetDestinationPort(flow: &Flow) -> u16;
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

    /// Return the flow flags.
    pub fn get_flags(&self) -> u32 {
        unsafe { FlowGetFlags(self) }
    }

    /// Return flow ports
    pub fn get_ports(&self) -> (u16, u16) {
        unsafe { (FlowGetSourcePort(self), FlowGetDestinationPort(self)) }
    }
}
