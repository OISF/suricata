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

//! This module exposes items from the core "C" code to Rust.

use std;
use suricata_sys::sys::{AppProto, AppProtoEnum, SCLogLevel};
#[cfg(not(test))]
use suricata_sys::sys::SCAppLayerParserTriggerRawStreamInspection;

use crate::filecontainer::*;
use crate::flow::Flow;

#[repr(C)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[allow(non_camel_case_types)]
pub enum AppLayerEventType {
    APP_LAYER_EVENT_TYPE_TRANSACTION = 1,
    APP_LAYER_EVENT_TYPE_PACKET = 2,
}

pub const STREAM_START:    u8 = 0x01;
pub const STREAM_EOF:      u8 = 0x02;
pub const STREAM_TOSERVER: u8 = 0x04;
pub const STREAM_TOCLIENT: u8 = 0x08;
pub const STREAM_GAP:      u8 = 0x10;
pub const STREAM_DEPTH:    u8 = 0x20;
pub const STREAM_MIDSTREAM:u8 = 0x40;

pub const ALPROTO_UNKNOWN : AppProto = AppProtoEnum::ALPROTO_UNKNOWN as AppProto;
pub const ALPROTO_FAILED : AppProto = AppProtoEnum::ALPROTO_FAILED as AppProto;

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


//
// Function types for calls into C.
//

#[allow(non_snake_case)]
pub type SCLogMessageFunc =
    extern "C" fn(level: SCLogLevel,
                  filename: *const std::os::raw::c_char,
                  line: std::os::raw::c_uint,
                  function: *const std::os::raw::c_char,
                  subsystem: *const std::os::raw::c_char,
                  message: *const std::os::raw::c_char) -> std::os::raw::c_int;

pub enum StreamingBufferConfig {}

// Opaque flow type (defined in C)
pub enum HttpRangeContainerBlock {}

pub type SCHttpRangeFreeBlock = extern "C" fn (
        c: *mut HttpRangeContainerBlock);
pub type SCHTPFileCloseHandleRange = extern "C" fn (
        sbcfg: &StreamingBufferConfig,
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
        sbcfg: &StreamingBufferConfig,
        track_id: u32,
        data: *const u8, data_len: u32,
        flags: u16) -> i32;
pub type SCFileAppendDataById = extern "C" fn (
        file_container: &FileContainer,
        sbcfg: &StreamingBufferConfig,
        track_id: u32,
        data: *const u8, data_len: u32) -> i32;
pub type SCFileAppendGAPById = extern "C" fn (
        file_container: &FileContainer,
        sbcfg: &StreamingBufferConfig,
        track_id: u32,
        data: *const u8, data_len: u32) -> i32;
pub type SCFileContainerRecycle = extern "C" fn (
        file_container: &FileContainer,
        sbcfg: &StreamingBufferConfig);

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

    pub HttpRangeFreeBlock: SCHttpRangeFreeBlock,
    pub HTPFileCloseHandleRange: SCHTPFileCloseHandleRange,

    pub FileOpenFile: SCFileOpenFileWithId,
    pub FileCloseFile: SCFileCloseFileById,
    pub FileAppendData: SCFileAppendDataById,
    pub FileAppendGAP: SCFileAppendGAPById,
    pub FileContainerRecycle: SCFileContainerRecycle,
}

#[allow(non_snake_case)]
#[repr(C)]
pub struct SuricataFileContext {
    pub files_sbcfg: &'static StreamingBufferConfig,
}

#[allow(unused_doc_comments)]
/// cbindgen:ignore
extern "C" {
    pub fn SCGetContext() -> &'static mut SuricataContext;
}

pub static mut SC: Option<&'static SuricataContext> = None;

pub fn init_ffi(context: &'static SuricataContext)
{
    unsafe {
        SC = Some(context);
    }
}

#[no_mangle]
pub extern "C" fn SCRustInit(context: &'static SuricataContext)
{
    init_ffi(context);
}

/// SCAppLayerParserTriggerRawStreamInspection wrapper
#[cfg(not(test))]
pub(crate) fn sc_app_layer_parser_trigger_raw_stream_inspection(flow: *mut Flow, direction: i32) {
    unsafe {
        SCAppLayerParserTriggerRawStreamInspection(flow, direction);
    }
}

#[cfg(test)]
pub(crate) fn sc_app_layer_parser_trigger_raw_stream_inspection(_flow: *const Flow, _direction: i32) {}
