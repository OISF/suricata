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

use std;
use crate::core::*;
use crate::filetracker::*;
use crate::filecontainer::*;

use crate::smb::smb::*;

use std::os::raw::c_uchar;

/// File tracking transaction. Single direction only.
#[derive(Debug)]
pub struct SMBTransactionFile {
    pub direction: Direction,
    pub fuid: Vec<u8>,
    pub file_name: Vec<u8>,
    pub share_name: Vec<u8>,
    pub file_tracker: FileTransferTracker,
    /// after a gap, this will be set to a time in the future. If the file
    /// receives no updates before that, it will be considered complete.
    pub post_gap_ts: u64,
    pub file_range: *mut FileRangeContainerBlock,
    pub multi: bool,
}

impl SMBTransactionFile {
    pub fn new() -> Self {
        return Self {
            file_tracker: FileTransferTracker::new(),
            file_range: std::ptr::null_mut(),
            multi: false,
            post_gap_ts: 0,
            direction: Direction::default(),
            fuid: Vec::new(),
            file_name: Vec::new(),
            share_name: Vec::new(),
        }
    }
}

impl Drop for SMBTransactionFile {
    fn drop(&mut self) {
        // should have been already closed
        debug_validate_bug_on!(!self.file_range.is_null());
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

// Defined in app-layer-htp-range.h
extern "C" {
    pub fn FileRangeAppendData(
        c: *mut FileRangeContainerBlock, data: *const c_uchar, data_len: u32,
    ) -> std::os::raw::c_int;
}

impl SMBState {
    pub fn new_file_tx(&mut self, fuid: &Vec<u8>, file_name: &Vec<u8>, direction: Direction)
        -> (&mut SMBTransaction, &mut FileContainer, u16)
    {
        let mut tx = self.new_tx();
        tx.type_data = Some(SMBTransactionTypeData::FILE(SMBTransactionFile::new()));
        match tx.type_data {
            Some(SMBTransactionTypeData::FILE(ref mut d)) => {
                d.direction = direction;
                d.fuid = fuid.to_vec();
                d.file_name = file_name.to_vec();
                d.file_tracker.tx_id = tx.id - 1;
            },
            _ => { },
        }
        tx.tx_data.init_files_opened();
        SCLogDebug!("SMB: new_file_tx: TX FILE created: ID {} NAME {}",
                tx.id, String::from_utf8_lossy(file_name));
        self.transactions.push(tx);
        let tx_ref = self.transactions.last_mut();
        let (files, flags) = self.files.get(direction);
        return (tx_ref.unwrap(), files, flags)
    }

    pub fn get_file_tx_by_fuid(&mut self, fuid: &Vec<u8>, direction: Direction)
        -> Option<(&mut SMBTransaction, &mut FileContainer, u16)>
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
                let (files, flags) = self.files.get(direction);
                return Some((tx, files, flags));
            }
        }
        SCLogDebug!("SMB: Failed to find SMB TX with FUID {:?}", fuid);
        return None;
    }

    fn getfiles(&mut self, direction: Direction) -> * mut FileContainer {
        //SCLogDebug!("direction: {:?}", direction);
        if direction == Direction::ToClient {
            &mut self.files.files_tc as *mut FileContainer
        } else {
            &mut self.files.files_ts as *mut FileContainer
        }
    }
    fn setfileflags(&mut self, direction: Direction, flags: u16) {
        SCLogDebug!("direction: {:?}, flags: {}", direction, flags);
        if direction == Direction::ToClient {
            self.files.flags_tc = flags;
        } else {
            self.files.flags_ts = flags;
        }
    }

    // update in progress chunks for file transfers
    // return how much data we consumed
    pub fn filetracker_update(&mut self, direction: Direction, data: &[u8], gap_size: u32, eof: bool) -> u32 {
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
            Some((tx, files, flags)) => {
                if let Some(SMBTransactionTypeData::FILE(ref mut tdf)) = tx.type_data {
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
                    if !tdf.file_range.is_null() {
                        unsafe {
                            FileRangeAppendData(tdf.file_range, file_data.as_ptr(), data_to_handle_len as u32);
                        }
                        if chunk_left == 0 || eof {
                            let added = if let Some(c) = unsafe { SC } {
                                let added = (c.HTPFileCloseHandleRange)(
                                    files,
                                    flags,
                                    tdf.file_range,
                                    std::ptr::null_mut(),
                                    0,
                                );
                                (c.FileRangeFreeBlock)(tdf.file_range);
                                added
                            } else {
                                false
                            };
                            tdf.file_range = std::ptr::null_mut();
                            if added {
                                tx.tx_data.incr_files_opened();
                            }
                        }
                    }

                    //TODOsmbmulti5 use eof ?
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
pub unsafe extern "C" fn rs_smb_getfiles(ptr: *mut std::ffi::c_void, direction: u8) -> * mut FileContainer {
    if ptr.is_null() { panic!("NULL ptr"); };
    let parser = cast_pointer!(ptr, SMBState);
    parser.getfiles(direction.into())
}

#[no_mangle]
pub unsafe extern "C" fn rs_smb_setfileflags(direction: u8, ptr: *mut SMBState, flags: u16) {
    if ptr.is_null() { panic!("NULL ptr"); };
    let parser = &mut *ptr;
    SCLogDebug!("direction {} flags {}", direction, flags);
    parser.setfileflags(direction.into(), flags)
}
