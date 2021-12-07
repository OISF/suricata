use crate::applayer::StreamSlice;
use crate::core::Flow;

#[repr(C)]
struct CFrame {
    _private: [u8; 0],
}

// Defined in app-layer-register.h
extern "C" {
    fn AppLayerFrameNewByRelativeOffset(
        flow: *const Flow, stream_slice: *const StreamSlice, frame_start_rel: u32, len: i32,
        dir: i32, frame_type: u8,
    ) -> *const CFrame;
    fn AppLayerFrameAddEvent(frame: *const CFrame, event: u8);
    fn AppLayerFrameSetTxId(frame: *const CFrame, tx_id: u64);
    fn AppLayerFrameGetId(frame: *const CFrame) -> i64;
}

pub struct Frame {
    frame: *const CFrame,
    pub frame_id: i64,
}

impl std::fmt::Debug for Frame {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "frame: {}", self.frame_id)
    }
}


impl Frame {
    pub fn new(
        flow: *const Flow, stream_slice: &StreamSlice, frame_start: &[u8], frame_len: i32,
        dir: i32, frame_type: u8,
    ) -> Self {
        let offset = stream_slice.len() as u64 - frame_start.len() as u64;
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
        Self { frame, frame_id }
    }

    pub fn new_ts(
        flow: *const Flow, stream_slice: &StreamSlice, frame_start: &[u8], frame_len: i32,
        frame_type: u8,
    ) -> Self {
        Self::new(flow, stream_slice, frame_start, frame_len, 0, frame_type)
    }

    pub fn new_tc(
        flow: *const Flow, stream_slice: &StreamSlice, frame_start: &[u8], frame_len: i32,
        frame_type: u8,
    ) -> Self {
        Self::new(flow, stream_slice, frame_start, frame_len, 1, frame_type)
    }

    pub fn set_tx(&self, tx_id: u64) {
        unsafe {
            AppLayerFrameSetTxId(self.frame, tx_id);
        };
    }

    pub fn add_event(&self, event: u8) {
        unsafe {
            AppLayerFrameAddEvent(self.frame, event);
        };
    }
}
