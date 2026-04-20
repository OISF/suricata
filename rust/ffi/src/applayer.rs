/* Copyright (C) 2026 Open Information Security Foundation
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

//! App-layer utils.

use suricata_sys::sys::{AppLayerResult, StreamSlice};

#[macro_export]
macro_rules! export_tx_data_get {
    ($name:ident, $type:ty) => {
        unsafe extern "C" fn $name(
            tx: *mut std::os::raw::c_void,
        ) -> *mut suricata_sys::sys::AppLayerTxData {
            let tx = &mut *(tx as *mut $type);
            &mut tx.tx_data.0
        }
    };
}

#[macro_export]
macro_rules! export_state_data_get {
    ($name:ident, $type:ty) => {
        unsafe extern "C" fn $name(
            state: *mut std::os::raw::c_void,
        ) -> *mut suricata_sys::sys::AppLayerStateData {
            let state = &mut *(state as *mut $type);
            &mut state.state_data
        }
    };
}

pub trait AppLayerResultRust {
    fn ok() -> Self;
    fn err() -> Self;
    fn incomplete(consumed: u32, needed: u32) -> Self;
    fn is_ok(&self) -> bool;
    fn is_err(&self) -> bool;
    fn is_incomplete(&self) -> bool;
}

impl AppLayerResultRust for AppLayerResult {
    /// parser has successfully processed in the input, and has consumed all of it
    fn ok() -> Self {
        Default::default()
    }
    /// parser has hit an unrecoverable error. Returning this to the API
    /// leads to no further calls to the parser.
    fn err() -> Self {
        AppLayerResult {
            status: -1,
            ..Default::default()
        }
    }

    /// parser needs more data. Through 'consumed' it will indicate how many
    /// of the input bytes it has consumed. Through 'needed' it will indicate
    /// how many more bytes it needs before getting called again.
    /// Note: consumed should never be more than the input len
    ///       needed + consumed should be more than the input len
    fn incomplete(consumed: u32, needed: u32) -> Self {
        Self {
            status: 1,
            consumed,
            needed,
        }
    }

    fn is_ok(&self) -> bool {
        self.status == 0
    }

    fn is_err(&self) -> bool {
        self.status == -1
    }

    fn is_incomplete(&self) -> bool {
        self.status == 1
    }
}

pub trait StreamSliceRust {
    fn from_slice(slice: &[u8], flags: u8, offset: u64) -> Self;
    fn is_gap(&self) -> bool;
    fn gap_size(&self) -> u32;
    fn as_slice(&self) -> &[u8];
    fn is_empty(&self) -> bool;
    fn len(&self) -> u32;
    fn offset_from(&self, slice: &[u8]) -> u32;
    fn flags(&self) -> u8;
}

impl StreamSliceRust for StreamSlice {
    /// Create a StreamSlice from a Rust slice. Useful in unit tests.
    fn from_slice(slice: &[u8], flags: u8, offset: u64) -> Self {
        Self {
            input: slice.as_ptr(),
            input_len: slice.len() as u32,
            flags,
            offset,
        }
    }

    fn is_gap(&self) -> bool {
        self.input.is_null() && self.input_len > 0
    }
    fn gap_size(&self) -> u32 {
        self.input_len
    }
    fn as_slice(&self) -> &[u8] {
        if self.input.is_null() && self.input_len == 0 {
            return &[];
        }
        unsafe { std::slice::from_raw_parts(self.input, self.input_len as usize) }
    }
    fn is_empty(&self) -> bool {
        self.input_len == 0
    }
    fn len(&self) -> u32 {
        self.input_len
    }
    fn offset_from(&self, slice: &[u8]) -> u32 {
        self.len() - slice.len() as u32
    }
    fn flags(&self) -> u8 {
        self.flags
    }
}
