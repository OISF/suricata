/* Copyright (C) 2017 Open Information Security Foundation
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

use std::ptr;
use std::os::raw::{c_void};

use crate::core::*;

// Defined in util-file.h
extern {
    pub fn FileFlowToFlags(flow: *const Flow, flags: u8) -> u16;
}

pub struct File;
#[repr(C)]
#[derive(Debug)]
pub struct FileContainer {
    head: * mut c_void,
    tail: * mut c_void,
}

impl FileContainer {
    pub fn default() -> FileContainer {
        FileContainer { head:ptr::null_mut(), tail:ptr::null_mut() }
    }
    pub fn free(&mut self) {
        SCLogDebug!("freeing self");
        if let Some(f) = *crate::ffi::FileContainerRecycle {
            f(&self);
        } else {
            panic!("FileContainerRecycle function pointer not set");
        }
    }

    pub fn file_open(&mut self, cfg: &'static SuricataFileContext, track_id: &u32, name: &[u8], flags: u16) -> i32 {
        if let Some(f) = *crate::ffi::FileOpenFile {
            SCLogDebug!("FILE {:p} OPEN flags {:04X}", &self, flags);
            let res = f(&self, cfg.files_sbcfg, *track_id,
                    name.as_ptr(), name.len() as u16,
                    ptr::null(), 0u32, flags);
            res
        } else {
            panic!("FileOpenFile function pointer not set");
        }
    }

    pub fn file_append(&mut self, track_id: &u32, data: &[u8], is_gap: bool) -> i32 {
        SCLogDebug!("FILECONTAINER: append {}", data.len());
        if data.len() == 0 {
            return 0
        }
        if is_gap {
            SCLogDebug!("appending GAP");
            if let Some(f) = *crate::ffi::FileAppendGAP {
                f(&self, *track_id, data.as_ptr(), data.len() as u32)
            } else {
                panic!("FileAppendGAP function pointer not set");
            }
        } else {
            SCLogDebug!("appending file data");
            if let Some(f) = *crate::ffi::FileAppendData {
                f(&self, *track_id, data.as_ptr(), data.len() as u32)
            } else {
                panic!("FileAppendData function pointer net set");
            }
        }
    }

    pub fn file_close(&mut self, track_id: &u32, flags: u16) -> i32 {
        SCLogDebug!("FILECONTAINER: CLOSEing");
        if let Some(f) = *crate::ffi::FileCloseFile {
            f(&self, *track_id, ptr::null(), 0u32, flags)
        } else {
            panic!("FileCloseFile function pointer not set");
        }
    }

    pub fn files_prune(&mut self) {
        SCLogDebug!("FILECONTAINER: pruning");
        if let Some(f) = *crate::ffi::FilePrune {
            f(&self);
        } else {
            panic!("FilePrune function pointer not set");
        }
    }

    pub fn file_set_txid_on_last_file(&mut self, tx_id: u64) {
        if let Some(f) = *crate::ffi::FileSetTx {
            f(&self, tx_id);
        } else {
            panic!("FileSetTx function pointer not set");
        }
    }
}
