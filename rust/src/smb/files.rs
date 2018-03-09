/* Copyright (C) 2018 Open Information Security Foundation
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

use core::*;
use log::*;
use filetracker::*;
use filecontainer::*;

use smb::smb::*;

/// File tracking transaction. Single direction only.
#[derive(Debug)]
pub struct SMBTransactionFile {
    pub direction: u8,
    pub guid: Vec<u8>,
    pub file_name: Vec<u8>,
    pub share_name: Vec<u8>,
    pub file_tracker: FileTransferTracker,
}

impl SMBTransactionFile {
    pub fn new() -> SMBTransactionFile {
        return SMBTransactionFile {
            direction: 0,
            guid: Vec::new(),
            file_name: Vec::new(),
            share_name: Vec::new(),
            file_tracker: FileTransferTracker::new(),
        }
    }
}

/// Wrapper around Suricata's internal file container logic.
#[derive(Debug)]
pub struct SMBFiles {
    pub files_ts: FileContainer,
    pub files_tc: FileContainer,
    pub flags_ts: u16,
    pub flags_tc: u16,
}

impl SMBFiles {
    pub fn new() -> SMBFiles {
        SMBFiles {
            files_ts:FileContainer::default(),
            files_tc:FileContainer::default(),
            flags_ts:0,
            flags_tc:0,
        }
    }
    pub fn free(&mut self) {
        self.files_ts.free();
        self.files_tc.free();
    }

    pub fn get(&mut self, direction: u8) -> (&mut FileContainer, u16)
    {
        if direction == STREAM_TOSERVER {
            (&mut self.files_ts, self.flags_ts)
        } else {
            (&mut self.files_tc, self.flags_tc)
        }
    }
}

/// little wrapper around the FileTransferTracker::new_chunk method
pub fn filetracker_newchunk(ft: &mut FileTransferTracker, files: &mut FileContainer,
        flags: u16, name: &Vec<u8>, data: &[u8],
        chunk_offset: u64, chunk_size: u32, fill_bytes: u8, is_last: bool, xid: &u32)
{
    match unsafe {SURICATA_SMB_FILE_CONFIG} {
        Some(sfcm) => {
            ft.new_chunk(sfcm, files, flags, &name, data, chunk_offset,
                    chunk_size, fill_bytes, is_last, xid); }
        None => panic!("BUG"),
    }
}

impl SMBState {
    pub fn new_file_tx(&mut self, file_guid: &Vec<u8>, file_name: &Vec<u8>, direction: u8)
        -> (&mut SMBTransaction, &mut FileContainer, u16)
    {
        let mut tx = self.new_tx();
        tx.type_data = Some(SMBTransactionTypeData::FILE(SMBTransactionFile::new()));
        match tx.type_data {
            Some(SMBTransactionTypeData::FILE(ref mut d)) => {
                d.direction = direction;
                d.guid = file_guid.to_vec();
                d.file_name = file_name.to_vec();
                d.file_tracker.tx_id = tx.id - 1;
            },
            _ => { },
        }
        SCLogDebug!("SMB: new_file_tx: TX FILE created: ID {} NAME {}",
                tx.id, String::from_utf8_lossy(file_name));
        self.transactions.push(tx);
        let tx_ref = self.transactions.last_mut();
        let (files, flags) = self.files.get(direction);
        return (tx_ref.unwrap(), files, flags)
    }

    pub fn get_file_tx_by_guid(&mut self, guid: &Vec<u8>, direction: u8)
        -> Option<(&mut SMBTransaction, &mut FileContainer, u16)>
    {
        let g = guid.to_vec();
        for tx in &mut self.transactions {
            let found = match tx.type_data {
                Some(SMBTransactionTypeData::FILE(ref mut d)) => {
                    direction == d.direction && g == d.guid
                },
                _ => { false },
            };

            if found {
                SCLogDebug!("SMB: Found SMB file TX with ID {}", tx.id);
                let (files, flags) = self.files.get(direction);
                return Some((tx, files, flags));
            }
        }
        SCLogDebug!("SMB: Failed to find SMB TX with GUID {:?}", guid);
        return None;
    }

    fn getfiles(&mut self, direction: u8) -> * mut FileContainer {
        //SCLogDebug!("direction: {}", direction);
        if direction == STREAM_TOCLIENT {
            &mut self.files.files_tc as *mut FileContainer
        } else {
            &mut self.files.files_ts as *mut FileContainer
        }
    }
    fn setfileflags(&mut self, direction: u8, flags: u16) {
        SCLogDebug!("direction: {}, flags: {}", direction, flags);
        if direction == 1 {
            self.files.flags_tc = flags;
        } else {
            self.files.flags_ts = flags;
        }
    }

    // update in progress chunks for file transfers
    // return how much data we consumed
    pub fn filetracker_update(&mut self, direction: u8, data: &[u8], gap_size: u32) -> u32 {
        let mut chunk_left = if direction == STREAM_TOSERVER {
            self.file_ts_left
        } else {
            self.file_tc_left
        };
        if chunk_left == 0 {
            return 0
        }
        SCLogDebug!("chunk_left {} data {}", chunk_left, data.len());
        let file_handle = if direction == STREAM_TOSERVER {
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

        if direction == STREAM_TOSERVER {
            self.file_ts_left = chunk_left;
        } else {
            self.file_tc_left = chunk_left;
        }

        let ssn_gap = self.ts_ssn_gap | self.tc_ssn_gap;
        // get the tx and update it
        let consumed = match self.get_file_tx_by_guid(&file_handle, direction) {
            Some((tx, files, flags)) => {
                if let Some(SMBTransactionTypeData::FILE(ref mut tdf)) = tx.type_data {
                    if ssn_gap {
                        let queued_data = tdf.file_tracker.get_queued_size();
                        if queued_data > 2000000 { // TODO should probably be configurable
                            SCLogDebug!("QUEUED size {} while we've seen GAPs. Truncating file.", queued_data);
                            tdf.file_tracker.trunc(files, flags);
                        }
                    }

                    let file_data = &data[0..data_to_handle_len];
                    let cs = tdf.file_tracker.update(files, flags, file_data, gap_size);
                    cs
                } else {
                    0
                }
            },
            None => {
                SCLogNotice!("not found for handle {:?}", file_handle);
                0 },
        };

        return consumed;
    }
}

#[no_mangle]
pub extern "C" fn rs_smb_getfiles(direction: u8, ptr: *mut SMBState) -> * mut FileContainer {
    if ptr.is_null() { panic!("NULL ptr"); };
    let parser = unsafe { &mut *ptr };
    parser.getfiles(direction)
}

#[no_mangle]
pub extern "C" fn rs_smb_setfileflags(direction: u8, ptr: *mut SMBState, flags: u16) {
    if ptr.is_null() { panic!("NULL ptr"); };
    let parser = unsafe { &mut *ptr };
    SCLogDebug!("direction {} flags {}", direction, flags);
    parser.setfileflags(direction, flags)
}

