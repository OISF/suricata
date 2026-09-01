/* Copyright (C) 2018-2026 Open Information Security Foundation
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

use std;
use crate::core::*;
use crate::direction::Direction;
use crate::filetracker::*;
use crate::filecontainer::*;
use crate::smb::events::SMBEvent;
use crate::smb::smb::{SMB_CFG_MAX_READ_QUEUE_SIZE, SMB_CFG_MAX_WRITE_QUEUE_SIZE};

use crate::smb::smb::*;

/// File tracking transaction. Single direction only.
#[derive(Default, Debug)]
pub struct SMBTransactionFile {
    pub direction: Direction,
    pub fuid: Vec<u8>,
    pub file_name: Vec<u8>,
    pub share_name: Vec<u8>,
    pub file_tracker: FileTransferTracker,
    /// after a gap, this will be set to a time in the future. If the file
    /// receives no updates before that, it will be considered complete.
    pub post_gap_ts: u64,
    //pub files: Files,
}

impl SMBTransactionFile {
    pub fn new() -> Self {
        return Self {
            file_tracker: FileTransferTracker::new(),
            ..Default::default()
        }
    }

    pub fn update_file_flags(&mut self, flow_file_flags: u16) {
        let dir_flag = if self.direction == Direction::ToServer { STREAM_TOSERVER } else { STREAM_TOCLIENT };
        self.file_tracker.file_flags = unsafe { FileFlowFlagsToFlags(flow_file_flags, dir_flag) };
    }
}

/// little wrapper around the FileTransferTracker::new_chunk method
pub fn filetracker_newchunk(ft: &mut FileTransferTracker, name: &[u8], data: &[u8],
        chunk_offset: u64, chunk_size: u32, is_last: bool, xid: &u32)
{
    if let Some(sfcm) = unsafe { SURICATA_SMB_FILE_CONFIG } {
        ft.new_chunk(sfcm, name, data, chunk_offset,
                chunk_size, 0, is_last, xid);
    }
}

pub fn filetracker_trunc(ft: &mut FileTransferTracker)
{
    if let Some(sfcm) = unsafe { SURICATA_SMB_FILE_CONFIG } {
        ft.trunc(sfcm);
    }
}

pub fn filetracker_close(ft: &mut FileTransferTracker)
{
    if let Some(sfcm) = unsafe { SURICATA_SMB_FILE_CONFIG } {
        ft.close(sfcm);
    }
}

fn filetracker_update(ft: &mut FileTransferTracker, data: &[u8], gap_size: u32) -> u32
{
    if let Some(sfcm) = unsafe { SURICATA_SMB_FILE_CONFIG } {
        ft.update(sfcm, data, gap_size)
    } else {
        0
    }
}

impl SMBState {
    pub fn new_file_tx(&mut self, fuid: &[u8], file_name: &[u8], direction: Direction)
        -> Option<&mut SMBTransaction>
    {
        let mut tx = self.new_tx()?;
        tx.type_data = Some(SMBTransactionTypeData::FILE(SMBTransactionFile::new()));
        if let Some(SMBTransactionTypeData::FILE(ref mut d)) = tx.type_data {
            d.direction = direction;
            d.fuid = fuid.to_vec();
            d.file_name = file_name.to_vec();
            d.file_tracker.tx_id = tx.id - 1;
            tx.tx_data.update_file_flags(self.state_data.file_flags);
            d.update_file_flags(tx.tx_data.file_flags);
        }
        tx.tx_data.init_files_opened();
        tx.tx_data.file_tx = if direction == Direction::ToServer { STREAM_TOSERVER } else { STREAM_TOCLIENT }; // TODO direction to flag func?
        SCLogDebug!("SMB: new_file_tx: TX FILE created: ID {} NAME {}",
                tx.id, String::from_utf8_lossy(file_name));
        self.transactions.push_back(tx);
        self.transactions.back_mut()
    }

    /// get file tx for a open file. Returns None if a file for the fuid exists,
    /// but has already been closed.
    pub fn get_file_tx_by_fuid_with_open_file(&mut self, fuid: &[u8], direction: Direction)
        -> Option<&mut SMBTransaction>
    {
        let f = fuid.to_vec();
        for tx in &mut self.transactions {
            let found = match tx.type_data {
                Some(SMBTransactionTypeData::FILE(ref mut d)) => {
                    direction == d.direction && f == d.fuid && !d.file_tracker.is_done()
                },
                _ => { false },
            };

            if found {
                SCLogDebug!("SMB: Found SMB file TX with ID {}", tx.id);
                if let Some(SMBTransactionTypeData::FILE(ref mut d)) = tx.type_data {
                    tx.tx_data.update_file_flags(self.state_data.file_flags);
                    d.update_file_flags(tx.tx_data.file_flags);
                }
                tx.tx_data.updated_tc = true;
                tx.tx_data.updated_ts = true;
                return Some(tx);
            }
        }
        SCLogDebug!("SMB: Failed to find SMB TX with FUID {:?}", fuid);
        return None;
    }

    /// get file tx for a fuid. File may already have been closed.
    pub fn get_file_tx_by_fuid(&mut self, fuid: &[u8], direction: Direction)
        -> Option<&mut SMBTransaction>
    {
        let f = fuid.to_vec();
        for tx in &mut self.transactions {
            let found = match tx.type_data {
                Some(SMBTransactionTypeData::FILE(ref mut d)) => {
                    direction == d.direction && f == d.fuid
                },
                _ => { false },
            };

            if found {
                SCLogDebug!("SMB: Found SMB file TX with ID {}", tx.id);
                if let Some(SMBTransactionTypeData::FILE(ref mut d)) = tx.type_data {
                    tx.tx_data.update_file_flags(self.state_data.file_flags);
                    d.update_file_flags(tx.tx_data.file_flags);
                }
                tx.tx_data.updated_tc = true;
                tx.tx_data.updated_ts = true;
                return Some(tx);
            }
        }
        SCLogDebug!("SMB: Failed to find SMB TX with FUID {:?}", fuid);
        return None;
    }

    /// OOO-queue backstop (bytes): configured queue size, or a 1 GiB hard
    /// cap (16x the 64 MiB default) when limits are disabled.
    pub fn ooo_queue_backstop(direction: Direction) -> u64 {
        let queue_size = if direction == Direction::ToClient {
            unsafe { SMB_CFG_MAX_READ_QUEUE_SIZE }
        } else {
            unsafe { SMB_CFG_MAX_WRITE_QUEUE_SIZE }
        };
        if queue_size != 0 {
            u64::from(queue_size)
        } else {
            1 << 30 // 1 GiB hard backstop when the limits are disabled
        }
    }

    /// OOO-queue backstop (chunk count): configured count, or a 1024 hard
    /// cap (16x the default 64) when limits are off; chunks carry per-entry
    /// overhead independent of size.
    pub fn ooo_queue_backstop_cnt(direction: Direction) -> u64 {
        let queue_cnt = if direction == Direction::ToClient {
            unsafe { SMB_CFG_MAX_READ_QUEUE_CNT }
        } else {
            unsafe { SMB_CFG_MAX_WRITE_QUEUE_CNT }
        };
        if queue_cnt != 0 {
            u64::from(queue_cnt)
        } else {
            1024 // hard chunk-count backstop when the limits are disabled
        }
    }

    // update in progress chunks for file transfers
    // return how much data we consumed
    pub fn filetracker_update(&mut self, direction: Direction, data: &[u8], gap_size: u32) -> u32 {
        let mut chunk_left = if direction == Direction::ToServer {
            self.file_ts_left
        } else {
            self.file_tc_left
        };
        let file_handle = if direction == Direction::ToServer {
            self.file_ts_guid.to_vec()
        } else {
            self.file_tc_guid.to_vec()
        };

        let ssn_gap = self.ts_ssn_gap | self.tc_ssn_gap;
        // Backstop: cap the OOO queue on every open file tx (an interleaved
        // handle can hide a first file's queue), running even with chunk_left == 0.
        if ssn_gap {
            // Last-resort cap for OOO data in gapped streams: configured
            // size/count (1 GiB / 1024 when limits are off).
            let backstop = Self::ooo_queue_backstop(direction);
            let cnt_backstop = Self::ooo_queue_backstop_cnt(direction);
            for tx in &mut self.transactions {
                if let Some(SMBTransactionTypeData::FILE(ref mut tdf)) = tx.type_data {
                    if tdf.direction == direction && !tdf.file_tracker.is_done() {
                        let queued_data = tdf.file_tracker.get_queued_size();
                        let queued_cnt = tdf.file_tracker.get_inflight_cnt() as u64;
                        if queued_data > backstop || queued_cnt > cnt_backstop {
                            SCLogDebug!(
                                "QUEUED size {} / count {} > backstop {} / {} while we've seen GAPs. Truncating file.",
                                queued_data,
                                queued_cnt,
                                backstop,
                                cnt_backstop
                            );
                            filetracker_trunc(&mut tdf.file_tracker);
                            // Attribute the truncation to the file tx
                            // actually truncated (not the newest tx).
                            tx.set_event(SMBEvent::TruncatedFileData);
                            tx.tx_data.updated_ts = true;
                            tx.tx_data.updated_tc = true;
                        }
                    }
                }
            }
        }

        if chunk_left == 0 {
            return 0;
        }
        SCLogDebug!("chunk_left {} data {}", chunk_left, data.len());

        let data_to_handle_len = if chunk_left as usize >= data.len() {
            data.len()
        } else {
            chunk_left as usize
        };

        if chunk_left <= data.len() as u32 {
            chunk_left = 0;
        } else {
            chunk_left -= data.len() as u32;
        }

        if direction == Direction::ToServer {
            self.file_ts_left = chunk_left;
        } else {
            self.file_tc_left = chunk_left;
        }

        // get the tx and update it
        let consumed = match self.get_file_tx_by_fuid(&file_handle, direction) {
            Some(tx) => {
                if let Some(SMBTransactionTypeData::FILE(ref mut tdf)) = tx.type_data {
                    // reset timestamp if we get called after a gap
                    if tdf.post_gap_ts > 0 {
                        tdf.post_gap_ts = 0;
                    }

                    let file_data = &data[0..data_to_handle_len];
                    filetracker_update(&mut tdf.file_tracker, file_data, gap_size)
                } else {
                    0
                }
            },
            None => {
                SCLogDebug!("not found for handle {:?}", file_handle);
                0 },
        };

        return consumed;
    }
}

/// Event to raise if enqueuing `len` bytes at `offset` would exceed the
/// configured SMB queue limits. OOO data at a new offset grows the queue;
/// in-order appends drain it and are never rejected.
pub(crate) fn smb_queue_limit_event(
    ft: &FileTransferTracker, offset: u64, len: u64, to_client: bool,
) -> Option<SMBEvent> {
    let (max_size, max_cnt, ev_size, ev_cnt) = if to_client {
        (
            unsafe { SMB_CFG_MAX_READ_QUEUE_SIZE },
            unsafe { SMB_CFG_MAX_READ_QUEUE_CNT },
            SMBEvent::ReadQueueSizeExceeded,
            SMBEvent::ReadQueueCntExceeded,
        )
    } else {
        (
            unsafe { SMB_CFG_MAX_WRITE_QUEUE_SIZE },
            unsafe { SMB_CFG_MAX_WRITE_QUEUE_CNT },
            SMBEvent::WriteQueueSizeExceeded,
            SMBEvent::WriteQueueCntExceeded,
        )
    };
    if max_size != 0
        && ft.is_ooo_offset(offset)
        && ft.get_inflight_size() + len > u64::from(max_size)
    {
        return Some(ev_size);
    }
    if max_cnt != 0 && ft.new_chunk_entry(offset) && ft.get_inflight_cnt() + 1 > max_cnt as usize {
        return Some(ev_cnt);
    }
    None
}

use crate::applayer::AppLayerGetFileState;

pub(super) unsafe extern "C" fn smb_gettxfiles(tx: *mut std::ffi::c_void, direction: u8) -> AppLayerGetFileState {
    let tx = cast_pointer!(tx, SMBTransaction);
    if let Some(SMBTransactionTypeData::FILE(ref mut tdf)) = tx.type_data {
        let tx_dir : u8 = tdf.direction.into();
        if direction & tx_dir != 0 {
            if let Some(sfcm) = { SURICATA_SMB_FILE_CONFIG } {
                return AppLayerGetFileState { fc: &mut tdf.file_tracker.file, cfg: sfcm.files_sbcfg }
            }
        }
    }
    AppLayerGetFileState::err()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ooo_queue_backstop_thresholds() {
        // defaults: 64 MiB queue caps in both directions
        assert_eq!(SMBState::ooo_queue_backstop(Direction::ToClient), 67108864);
        assert_eq!(SMBState::ooo_queue_backstop(Direction::ToServer), 67108864);

        // enabled (non-zero) queue size: the backstop follows it
        unsafe {
            SMB_CFG_MAX_READ_QUEUE_SIZE = 4096;
        }
        unsafe {
            SMB_CFG_MAX_WRITE_QUEUE_SIZE = 8192;
        }
        assert_eq!(SMBState::ooo_queue_backstop(Direction::ToClient), 4096);
        assert_eq!(SMBState::ooo_queue_backstop(Direction::ToServer), 8192);

        // disabled (0) queue size: the 1 GiB hard cap applies
        unsafe {
            SMB_CFG_MAX_READ_QUEUE_SIZE = 0;
        }
        unsafe {
            SMB_CFG_MAX_WRITE_QUEUE_SIZE = 0;
        }
        assert_eq!(SMBState::ooo_queue_backstop(Direction::ToClient), 1 << 30);
        assert_eq!(SMBState::ooo_queue_backstop(Direction::ToServer), 1 << 30);

        // restore defaults
        unsafe {
            SMB_CFG_MAX_READ_QUEUE_SIZE = 67108864;
        }
        unsafe {
            SMB_CFG_MAX_WRITE_QUEUE_SIZE = 67108864;
        }
    }

    #[test]
    fn test_ooo_queue_backstop_cnt_thresholds() {
        // defaults: 64 chunks in both directions
        assert_eq!(SMBState::ooo_queue_backstop_cnt(Direction::ToClient), 64);
        assert_eq!(SMBState::ooo_queue_backstop_cnt(Direction::ToServer), 64);

        // enabled (non-zero) queue count: the backstop follows it
        unsafe {
            SMB_CFG_MAX_READ_QUEUE_CNT = 16;
        }
        unsafe {
            SMB_CFG_MAX_WRITE_QUEUE_CNT = 32;
        }
        assert_eq!(SMBState::ooo_queue_backstop_cnt(Direction::ToClient), 16);
        assert_eq!(SMBState::ooo_queue_backstop_cnt(Direction::ToServer), 32);

        // disabled (0) queue count: the 1024 hard cap applies
        unsafe {
            SMB_CFG_MAX_READ_QUEUE_CNT = 0;
        }
        unsafe {
            SMB_CFG_MAX_WRITE_QUEUE_CNT = 0;
        }
        assert_eq!(SMBState::ooo_queue_backstop_cnt(Direction::ToClient), 1024);
        assert_eq!(SMBState::ooo_queue_backstop_cnt(Direction::ToServer), 1024);

        // restore defaults
        unsafe {
            SMB_CFG_MAX_READ_QUEUE_CNT = 64;
        }
        unsafe {
            SMB_CFG_MAX_WRITE_QUEUE_CNT = 64;
        }
    }
}
