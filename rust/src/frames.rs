/* Copyright (C) 2017-2021 Open Information Security Foundation
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

//! Module for bindings to the Suricata C frame API.

use crate::applayer::StreamSlice;
#[cfg(not(test))]
use crate::core::STREAM_TOSERVER;
use crate::direction::Direction;
use crate::flow::Flow;

#[cfg(not(test))]
use std::os::raw::c_void;
#[cfg(not(test))]
use suricata_sys::sys::{SCAppLayerFrameNewByRelativeOffset, SCAppLayerFrameSetTxIdById};
use suricata_sys::sys::{SCAppLayerFrameAddEventById, SCAppLayerFrameSetLengthById};

pub struct Frame {
    pub id: i64,
    direction: Direction,
}

impl std::fmt::Debug for Frame {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "frame: {}, direction: {}", self.id, self.direction)
    }
}

impl Frame {
    #[cfg(not(test))]
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub fn new(
        flow: *mut Flow, stream_slice: &StreamSlice, frame_start: &[u8], frame_len: i64,
        frame_type: u8, tx_id: Option<u64>,
    ) -> Option<Self> {
        let offset = frame_start.as_ptr() as usize - stream_slice.as_slice().as_ptr() as usize;
        SCLogDebug!(
            "offset {} stream_slice.len() {} frame_start.len() {}",
            offset,
            stream_slice.len(),
            frame_start.len()
        );
        let frame = unsafe {
            SCAppLayerFrameNewByRelativeOffset(
                flow,
                stream_slice as *const _ as *const c_void,
                offset as u32,
                frame_len,
                (stream_slice.flags() & STREAM_TOSERVER == 0).into(),
                frame_type,
            )
        };
        if !frame.is_null() {
            let id = unsafe { (*frame).id };
            let r = Self {
                id,
                direction: Direction::from(stream_slice.flags()),
            };
            if let Some(tx_id) = tx_id {
                unsafe {
                    SCAppLayerFrameSetTxIdById(flow, r.direction(), id, tx_id);
                };
            }
            Some(r)
        } else {
            None
        }
    }

    /// A variation of `new` for use when running Rust unit tests as
    /// the C functions for building a frame are not available for
    /// linkage.
    #[cfg(test)]
    pub fn new(
        _flow: *const Flow, _stream_slice: &StreamSlice, _frame_start: &[u8], _frame_len: i64,
        _frame_type: u8, _tx_id: Option<u64>,
    ) -> Option<Self> {
        None
    }

    /// Conversion function to get the direction in the correct form for the
    /// C frame methods which takes direction as a u32 value of 0 or 1 rather
    /// than the flag value used internally by Frame.
    fn direction(&self) -> i32 {
        match self.direction {
            Direction::ToServer => 0,
            Direction::ToClient => 1,
        }
    }

    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub fn set_len(&self, flow: *const Flow, len: i64) {
        unsafe {
            SCAppLayerFrameSetLengthById(flow, self.direction(), self.id, len);
        };
    }

    #[cfg(not(test))]
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub fn set_tx(&self, flow: *const Flow, tx_id: u64) {
        unsafe {
            SCAppLayerFrameSetTxIdById(flow, self.direction(), self.id, tx_id);
        };
    }

    /// A variation of `set_tx` for use when running Rust unit tests as
    /// the C functions for building a frame are not available for
    /// linkage.
    #[cfg(test)]
    pub fn set_tx(&self, _flow: *const Flow, _tx_id: u64) {}

    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub fn add_event(&self, flow: *const Flow, event: u8) {
        unsafe {
            SCAppLayerFrameAddEventById(flow, self.direction(), self.id, event);
        };
    }
}
