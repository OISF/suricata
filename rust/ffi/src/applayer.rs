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

use crate::cast_pointer;
use suricata_sys::sys::{
    AppLayerGetTxIterState, AppLayerGetTxIterTuple, AppLayerResult, AppProto, StreamSlice,
};

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

/* Flags for AppLayerParserState. */
// flag available                               BIT_U16(0)
pub const APP_LAYER_PARSER_NO_INSPECTION: u16 = 1 << 1;
pub const APP_LAYER_PARSER_NO_REASSEMBLY: u16 = 1 << 2;
pub const APP_LAYER_PARSER_NO_INSPECTION_PAYLOAD: u16 = 1 << 3;
pub const APP_LAYER_PARSER_BYPASS_READY: u16 = 1 << 4;
pub const APP_LAYER_PARSER_EOF_TS: u16 = 1 << 5;
pub const APP_LAYER_PARSER_EOF_TC: u16 = 1 << 6;
/* 2x vacancy */
pub const APP_LAYER_PARSER_SFRAME_TS: u16 = 1 << 9;
pub const APP_LAYER_PARSER_SFRAME_TC: u16 = 1 << 10;

/* Flags for AppLayerParserProtoCtx. */
pub const APP_LAYER_PARSER_OPT_ACCEPT_GAPS: u32 = 1 << 0;

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

trait AppLayerGetTxIterTupleRust {
    fn with_values(tx_ptr: *mut std::os::raw::c_void, tx_id: u64, has_next: bool) -> Self;
    fn not_found() -> Self;
}

impl AppLayerGetTxIterTupleRust for AppLayerGetTxIterTuple {
    fn with_values(
        tx_ptr: *mut std::os::raw::c_void, tx_id: u64, has_next: bool,
    ) -> AppLayerGetTxIterTuple {
        AppLayerGetTxIterTuple {
            tx_ptr,
            tx_id,
            has_next,
        }
    }
    fn not_found() -> AppLayerGetTxIterTuple {
        AppLayerGetTxIterTuple {
            tx_ptr: std::ptr::null_mut(),
            tx_id: 0,
            has_next: false,
        }
    }
}

/// Transaction trait.
///
/// This trait defines methods that a Transaction struct must implement
/// in order to define some generic helper functions.
pub trait Transaction {
    fn id(&self) -> u64;
}

pub trait State<Tx: Transaction> {
    /// Return the number of transactions in the state's transaction collection.
    fn get_transaction_count(&self) -> usize;

    /// Return a transaction by its index in the container.
    fn get_transaction_by_index(&self, index: usize) -> Option<&Tx>;

    fn get_transaction_iterator(&self, min_tx_id: u64, state: &mut u64) -> AppLayerGetTxIterTuple {
        let mut index = *state as usize;
        let len = self.get_transaction_count();
        while index < len {
            let tx = self.get_transaction_by_index(index).unwrap();
            if tx.id() < min_tx_id + 1 {
                index += 1;
                continue;
            }
            *state = index as u64;
            return AppLayerGetTxIterTuple::with_values(
                tx as *const _ as *mut _,
                tx.id() - 1,
                len - index > 1,
            );
        }
        AppLayerGetTxIterTuple::not_found()
    }
}

/// # Safety
///
/// state variable must be a valid state pointer from Suricata.
pub unsafe extern "C" fn state_get_tx_iterator<S: State<Tx>, Tx: Transaction>(
    _ipproto: u8, _alproto: AppProto, state: *mut std::os::raw::c_void, min_tx_id: u64,
    _max_tx_id: u64, istate: *mut AppLayerGetTxIterState,
) -> AppLayerGetTxIterTuple {
    let state = cast_pointer!(state, S);
    state.get_transaction_iterator(min_tx_id, &mut (*istate).un.u64_)
}
