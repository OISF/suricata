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

use suricata_sys::sys::{AppProto, AppProtoEnum};
#[cfg(not(test))]
use suricata_sys::sys::SCAppLayerParserTriggerRawStreamInspection;

use crate::flow::Flow;

pub use suricata_sys::sys::AppLayerEventType;

pub use suricata_ffi::STREAM_START;
pub use suricata_ffi::STREAM_EOF;
pub use suricata_ffi::STREAM_TOSERVER;
pub use suricata_ffi::STREAM_TOCLIENT;
pub use suricata_ffi::STREAM_GAP;
pub use suricata_ffi::STREAM_DEPTH;
pub use suricata_ffi::STREAM_MIDSTREAM;

pub const ALPROTO_UNKNOWN : AppProto = AppProtoEnum::ALPROTO_UNKNOWN as AppProto;
pub const ALPROTO_FAILED : AppProto = AppProtoEnum::ALPROTO_FAILED as AppProto;

pub use suricata_ffi::IPPROTO_TCP;
pub use suricata_ffi::IPPROTO_UDP;


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
pub(crate) use suricata_sys::sys::StreamingBufferConfig;

#[allow(non_snake_case)]
#[repr(C)]
pub struct SuricataFileContext {
    pub files_sbcfg: &'static StreamingBufferConfig,
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
