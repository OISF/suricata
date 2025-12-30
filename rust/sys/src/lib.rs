/* Copyright (C) 2025 Open Information Security Foundation
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

#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(clippy::all)]
#![allow(unpredictable_function_pointer_comparisons)]

pub mod jsonbuilder;
pub mod sys;

use crate::sys::AppLayerGetFileState;

impl AppLayerGetFileState {
    pub fn err() -> AppLayerGetFileState {
        AppLayerGetFileState { fc: std::ptr::null_mut(), cfg: std::ptr::null() }
    }
}

use crate::sys::AppLayerStateData;

impl AppLayerStateData {
    pub fn new() -> Self {
        AppLayerStateData::default()
    }
}

use crate::sys::AppLayerGetTxIterTuple;

impl AppLayerGetTxIterTuple {
    pub fn with_values(tx_ptr: *mut std::os::raw::c_void, tx_id: u64, has_next: bool) -> AppLayerGetTxIterTuple {
        AppLayerGetTxIterTuple {
            tx_ptr, tx_id, has_next,
        }
    }
    pub fn not_found() -> AppLayerGetTxIterTuple {
        AppLayerGetTxIterTuple {
            tx_ptr: std::ptr::null_mut(), tx_id: 0, has_next: false,
        }
    }
}

use crate::sys::StreamSlice;
use crate::sys::AppLayerTxConfig;

impl StreamSlice {

    /// Create a StreamSlice from a Rust slice. Useful in unit tests.
    #[cfg(test)]
    pub fn from_slice(slice: &[u8], flags: u8, offset: u64) -> Self {
        Self {
            input: slice.as_ptr(),
            input_len: slice.len() as u32,
            flags,
            offset
        }
    }

    pub fn is_gap(&self) -> bool {
        self.input.is_null() && self.input_len > 0
    }
    pub fn gap_size(&self) -> u32 {
        self.input_len
    }
    pub fn as_slice(&self) -> &[u8] {
        if self.input.is_null() && self.input_len == 0 {
            return &[];
        }
        unsafe { std::slice::from_raw_parts(self.input, self.input_len as usize) }
    }
    pub fn is_empty(&self) -> bool {
        self.input_len == 0
    }
    pub fn len(&self) -> u32 {
        self.input_len
    }
    pub fn offset_from(&self, slice: &[u8]) -> u32 {
        self.len() - slice.len() as u32
    }
    pub fn flags(&self) -> u8 {
        self.flags
    }
}

use crate::sys::AppLayerResult;

impl AppLayerResult {
    /// parser has successfully processed in the input, and has consumed all of it
    pub fn ok() -> Self {
        Default::default()
    }
    /// parser has hit an unrecoverable error. Returning this to the API
    /// leads to no further calls to the parser.
    pub fn err() -> Self {
        return Self {
            status: -1,
            ..Default::default()
        };
    }
    /// parser needs more data. Through 'consumed' it will indicate how many
    /// of the input bytes it has consumed. Through 'needed' it will indicate
    /// how many more bytes it needs before getting called again.
    /// Note: consumed should never be more than the input len
    ///       needed + consumed should be more than the input len
    pub fn incomplete(consumed: u32, needed: u32) -> Self {
        return Self {
            status: 1,
            consumed,
            needed,
        };
    }

    pub fn is_ok(self) -> bool {
        self.status == 0
    }

    pub fn is_err(self) -> bool {
        self.status == -1
    }

    pub fn is_incomplete(self) -> bool {
        self.status == 1
    }
}

impl From<bool> for AppLayerResult {
    fn from(v: bool) -> Self {
        if !v {
            Self::err()
        } else {
            Self::ok()
        }
    }
}

impl From<i32> for AppLayerResult {
    fn from(v: i32) -> Self {
        if v < 0 {
            Self::err()
        } else {
            Self::ok()
        }
    }
}

use crate::sys::AppLayerTxData;
use crate::sys::{SCDetectEngineStateFree, SCAppLayerDecoderEventsFreeEvents, SCGenericVarFree, SCAppLayerDecoderEventsSetEventRaw};

impl Drop for AppLayerTxData {
    fn drop(&mut self) {
        self.cleanup();
    }
}

// need to keep in sync with C flow.h
pub const FLOWFILE_NO_STORE_TS: u16 = 4u16;
pub const FLOWFILE_NO_STORE_TC: u16 = 8u16;
pub const FLOWFILE_STORE_TS: u16 = 0x1000;
pub const FLOWFILE_STORE_TC: u16 = 0x2000;

impl AppLayerTxData {
    #[cfg(not(test))]
    pub fn cleanup(&mut self) {
        if !self.de_state.is_null() {
            unsafe {
                SCDetectEngineStateFree(self.de_state);
            }
        }
        if !self.events.is_null() {
            unsafe {
                SCAppLayerDecoderEventsFreeEvents(&mut self.events);
            }
        }
        if !self.txbits.is_null() {
            unsafe {
                SCGenericVarFree(self.txbits);
            }
        }
    }

    #[cfg(test)]
    pub fn cleanup(&mut self) {}

    /// Create new AppLayerTxData for a transaction that covers both
    /// directions.
    pub fn new() -> Self {
        Self {
            config: AppLayerTxConfig::default(),
            logged: 0,
            files_opened: 0,
            files_logged: 0,
            files_stored: 0,
            file_flags: 0,
            file_tx: 0,
            guessed_applayer_logged: 0,
            updated_tc: true,
            updated_ts: true,
            flags: 0,
            detect_progress_ts: 0,
            detect_progress_tc: 0,
            de_state: std::ptr::null_mut(),
            events: std::ptr::null_mut(),
            txbits: std::ptr::null_mut(),
        }
    }

    pub fn init_files_opened(&mut self) {
        self.files_opened = 1;
    }

    pub fn incr_files_opened(&mut self) {
        self.files_opened += 1;
    }

    pub fn set_event(&mut self, _event: u8) {
        #[cfg(not(test))]
        unsafe {
            SCAppLayerDecoderEventsSetEventRaw(&mut self.events, _event);
        }
    }

    pub fn update_file_flags(&mut self, state_flags: u16) {
        if (self.file_flags & state_flags) != state_flags {
            // SCLogDebug!("updating tx file_flags {:04x} with state flags {:04x}", self.file_flags, state_flags);
            let mut nf = state_flags;
            // With keyword filestore:both,flow :
            // There may be some opened unclosed file in one direction without filestore
            // As such it has tx file_flags had FLOWFILE_NO_STORE_TS or TC
            // But a new file in the other direction may trigger filestore:both,flow
            // And thus set state_flags FLOWFILE_STORE_TS
            // If the file was opened without storing it, do not try to store just the end of it
            if (self.file_flags & FLOWFILE_NO_STORE_TS) != 0 && (state_flags & FLOWFILE_STORE_TS) != 0 {
                nf &= !FLOWFILE_STORE_TS;
            }
            if (self.file_flags & FLOWFILE_NO_STORE_TC) != 0 && (state_flags & FLOWFILE_STORE_TC) != 0 {
                nf &= !FLOWFILE_STORE_TC;
            }
            self.file_flags |= nf;
        }
    }
}
