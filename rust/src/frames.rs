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
    pub frame_id: i64,
}

impl std::fmt::Debug for Frame {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "frame: {}", self.frame_id)
    }
}

pub fn frame_set_len(flow: *const Flow, dir: i32, frame_id: i64, len: i64)
{
    unsafe { AppLayerFrameSetLengthById(flow, dir, frame_id, len) }
}

pub fn frame_set_tx(flow: *const Flow, dir: i32, frame_id: i64, tx_id: u64)
{
    unsafe { AppLayerFrameSetTxIdById(flow, dir, frame_id, tx_id) }
}

pub fn frame_add_event(flow: *const Flow, dir: i32, frame_id: i64, event: u8)
{
    unsafe { AppLayerFrameAddEventById(flow, dir, frame_id, event) }
}

impl Frame {
    pub fn new(
        flow: *const Flow, stream_slice: &StreamSlice, frame_start: &[u8], frame_len: i64,
        dir: i32, frame_type: u8,
    ) -> Self {
        let offset = frame_start.as_ptr() as usize - stream_slice.as_slice().as_ptr() as usize;
        SCLogDebug!("offset {} stream_slice.len() {} frame_start.len() {}", offset, stream_slice.len(), frame_start.len());
        let frame = unsafe {
            AppLayerFrameNewByRelativeOffset(
                flow,
                stream_slice,
                offset as u32,
                frame_len,
                dir,
                frame_type,
            )
        };
        let frame_id = unsafe { AppLayerFrameGetId(frame) };
        Self { frame_id }
    }

    pub fn new_ts(
        flow: *const Flow, stream_slice: &StreamSlice, frame_start: &[u8], frame_len: i64,
        frame_type: u8,
    ) -> Self {
        Self::new(flow, stream_slice, frame_start, frame_len, 0, frame_type)
    }

    pub fn new_tc(
        flow: *const Flow, stream_slice: &StreamSlice, frame_start: &[u8], frame_len: i64,
        frame_type: u8,
    ) -> Self {
        Self::new(flow, stream_slice, frame_start, frame_len, 1, frame_type)
    }
/*
    pub fn set_len(&self, len: i64) {
        unsafe {
            AppLayerFrameSetLengthById(self.frame_id, len);
        };
    }
    pub fn set_tx(&self, tx_id: u64) {
        unsafe {
            AppLayerFrameSetTxIdById(self.frame_id, tx_id);
        };
    }

    pub fn add_event(&self, event: u8) {
        unsafe {
            AppLayerFrameAddEventById(self.frame_id, event);
        };
    }
 */
}
