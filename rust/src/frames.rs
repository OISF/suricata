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

use crate::applayer::StreamSlice;
use crate::core::Flow;
use crate::core::STREAM_TOSERVER;
use crate::core::Direction;

#[repr(C)]
struct CFrame {
    _private: [u8; 0],
}

// Defined in app-layer-register.h
extern {
    fn AppLayerFrameNewByRelativeOffset(
        flow: *const Flow, stream_slice: *const StreamSlice, frame_start_rel: u32, len: i64,
        dir: i32, frame_type: u8,
    ) -> *const CFrame;
    fn AppLayerFrameAddEventById(flow: *const Flow, dir: i32, id: i64, event: u8);
    fn AppLayerFrameSetLengthById(flow: *const Flow, dir: i32, id: i64, len: i64);
    fn AppLayerFrameSetTxIdById(flow: *const Flow, dir: i32, id: i64, tx_id: u64);
    fn AppLayerFrameGetId(frame: *const CFrame) -> i64;
}

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
    pub fn new(
        flow: *const Flow, stream_slice: &StreamSlice, frame_start: &[u8], frame_len: i64,
        frame_type: u8,
    ) -> Option<Self> {
        let offset = frame_start.as_ptr() as usize - stream_slice.as_slice().as_ptr() as usize;
        SCLogDebug!("offset {} stream_slice.len() {} frame_start.len() {}", offset, stream_slice.len(), frame_start.len());
        // If running Rust unit tests this won't be compiled and None will be returned, as we don't
        // have the Suricata C code available for linkage.
        if cfg!(not(test)) {
            let frame = unsafe {
                AppLayerFrameNewByRelativeOffset(
                    flow,
                    stream_slice,
                    offset as u32,
                    frame_len,
                    if stream_slice.flags() & STREAM_TOSERVER != 0 { 0 } else { 1 },
                    frame_type,
                )
            };
            let id = unsafe { AppLayerFrameGetId(frame) };
            if id > 0 {
                Some(Self {
                    id,
                    direction: Direction::from(stream_slice.flags()),
                })
            } else {
                None
            }
        } else {
            None
        }
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

    pub fn set_len(&self, flow: *const Flow, len: i64) {
        unsafe {
            AppLayerFrameSetLengthById(flow, self.direction(), self.id, len);
        };
    }

    pub fn set_tx(&self, flow: *const Flow, tx_id: u64) {
        unsafe {
            AppLayerFrameSetTxIdById(flow, self.direction(), self.id, tx_id);
        };
    }

    pub fn add_event(&self, flow: *const Flow, event: u8) {
        unsafe {
            AppLayerFrameAddEventById(flow, self.direction(), self.id, event);
        };
    }
}
