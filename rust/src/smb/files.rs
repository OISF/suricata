/* Copyright (C) 2018-2022 Open Information Security Foundation
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
use crate::filetracker::*;
use crate::filecontainer::*;

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
    pub files: Files,
}

impl SMBTransactionFile {
    pub fn new() -> Self {
        return Self {
            file_tracker: FileTransferTracker::new(),
            ..Default::default()
        }
    }

    pub fn update_file_flags(&mut self, flow_file_flags: u16) {
        self.files.flags_ts = unsafe { FileFlowFlagsToFlags(flow_file_flags, STREAM_TOSERVER) | FILE_USE_DETECT };
        self.files.flags_tc = unsafe { FileFlowFlagsToFlags(flow_file_flags, STREAM_TOCLIENT) | FILE_USE_DETECT };
    }
}

/// little wrapper around the FileTransferTracker::new_chunk method
pub fn filetracker_newchunk(ft: &mut FileTransferTracker, files: &mut FileContainer,
        flags: u16, name: &Vec<u8>, data: &[u8],
        chunk_offset: u64, chunk_size: u32, is_last: bool, xid: &u32)
{
    match unsafe {SURICATA_SMB_FILE_CONFIG} {
        Some(sfcm) => {
            ft.new_chunk(sfcm, files, flags, name, data, chunk_offset,
                    chunk_size, 0, is_last, xid); }
        None => panic!("no SURICATA_SMB_FILE_CONFIG"),
    }
}

impl SMBState {
    pub fn new_file_tx(&mut self, fuid: &Vec<u8>, file_name: &Vec<u8>, direction: Direction)
        -> &mut SMBTransaction
    {
        let mut tx = self.new_tx();
        tx.type_data = Some(SMBTransactionTypeData::FILE(SMBTransactionFile::new()));
        match tx.type_data {
            Some(SMBTransactionTypeData::FILE(ref mut d)) => {
                d.direction = direction;
                d.fuid = fuid.to_vec();
                d.file_name = file_name.to_vec();
                d.file_tracker.tx_id = tx.id - 1;
                tx.tx_data.update_file_flags(self.state_data.file_flags);
                d.update_file_flags(tx.tx_data.file_flags);
            },
            _ => { },
        }
        tx.tx_data.init_files_opened();
        SCLogDebug!("SMB: new_file_tx: TX FILE created: ID {} NAME {}",
                tx.id, String::from_utf8_lossy(file_name));
        self.transactions.push(tx);
        let tx_ref = self.transactions.last_mut();
        return tx_ref.unwrap();
    }

    pub fn get_file_tx_by_fuid(&mut self, fuid: &Vec<u8>, direction: Direction)
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
                    d.update_file_flags(tx.tx_data.file_flags); // TODO merge with tx.tx_data.update_file_flags ?
                }
                return Some(tx);
            }
        }
        SCLogDebug!("SMB: Failed to find SMB TX with FUID {:?}", fuid);
        return None;
    }

    // update in progress chunks for file transfers
    // return how much data we consumed
    pub fn filetracker_update(&mut self, direction: Direction, data: &[u8], gap_size: u32) -> u32 {
        let mut chunk_left = if direction == Direction::ToServer {
            self.file_ts_left
        } else {
            self.file_tc_left
        };
        if chunk_left == 0 {
            return 0
        }
        SCLogDebug!("chunk_left {} data {}", chunk_left, data.len());
        let file_handle = if direction == Direction::ToServer {
            self.file_ts_guid.to_vec()
        } else {
            self.file_tc_guid.to_vec()
        };

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

        let ssn_gap = self.ts_ssn_gap | self.tc_ssn_gap;
        // get the tx and update it
        let consumed = match self.get_file_tx_by_fuid(&file_handle, direction) {
            Some(tx) => {
                if let Some(SMBTransactionTypeData::FILE(ref mut tdf)) = tx.type_data {
                    let (files, flags) = tdf.files.get(direction);
                    if ssn_gap {
                        let queued_data = tdf.file_tracker.get_queued_size();
                        if queued_data > 2000000 { // TODO should probably be configurable
                            SCLogDebug!("QUEUED size {} while we've seen GAPs. Truncating file.", queued_data);
                            tdf.file_tracker.trunc(files, flags);
                        }
                    }

                    // reset timestamp if we get called after a gap
                    if tdf.post_gap_ts > 0 {
                        tdf.post_gap_ts = 0;
                    }

                    let file_data = &data[0..data_to_handle_len];
                    let cs = tdf.file_tracker.update(files, flags, file_data, gap_size);
                    cs
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

#[no_mangle]
pub unsafe extern "C" fn rs_smb_gettxfiles(tx_ptr: *mut std::ffi::c_void, direction: u8) -> * mut FileContainer {
    let tx = cast_pointer!(tx_ptr, SMBTransaction);
    if let Some(SMBTransactionTypeData::FILE(ref mut tdf)) = tx.type_data {
        let (files, _flags) = tdf.files.get(direction.into());
        files
    } else {
        std::ptr::null_mut()
    }
}
