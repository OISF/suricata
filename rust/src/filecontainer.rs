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
pub const FILE_USE_DETECT:    u16 = BIT_U16!(13);

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
        match unsafe {SC} {
            None => panic!("BUG no suricata_config"),
            Some(c) => {
                (c.FileContainerRecycle)(&self);
            },
        }
    }

    pub fn file_open(&mut self, cfg: &'static SuricataFileContext, track_id: u32, name: &[u8], flags: u16) -> i32 {
        match unsafe {SC} {
            None => panic!("BUG no suricata_config"),
            Some(c) => {
                SCLogDebug!("FILE {:p} OPEN flags {:04X}", &self, flags);

                let res = (c.FileOpenFile)(&self, cfg.files_sbcfg, track_id,
                        name.as_ptr(), name.len() as u16,
                        ptr::null(), 0u32, flags);
                res
            }
        }
    }

    pub fn file_append(&mut self, track_id: &u32, data: &[u8], is_gap: bool) -> i32 {
        SCLogDebug!("FILECONTAINER: append {}", data.len());
        if data.len() == 0 {
            return 0
        }
        match unsafe {SC} {
            None => panic!("BUG no suricata_config"),
            Some(c) => {
                let res = match is_gap {
                    false => {
                        SCLogDebug!("appending file data");
                        let r = (c.FileAppendData)(&self, *track_id,
                                data.as_ptr(), data.len() as u32);
                        r
                    },
                    true => {
                        SCLogDebug!("appending GAP");
                        let r = (c.FileAppendGAP)(&self, *track_id,
                                data.as_ptr(), data.len() as u32);
                        r
                    },
                };
                res
            }
        }
    }

    pub fn file_close(&mut self, track_id: &u32, flags: u16) -> i32 {
        SCLogDebug!("FILECONTAINER: CLOSEing");

        match unsafe {SC} {
            None => panic!("BUG no suricata_config"),
            Some(c) => {
                let res = (c.FileCloseFile)(&self, *track_id, ptr::null(), 0u32, flags);
                res
            }
        }

    }

    pub fn files_prune(&mut self) {
        SCLogDebug!("FILECONTAINER: pruning");
        match unsafe {SC} {
            None => panic!("BUG no suricata_config"),
            Some(c) => {
                (c.FilePrune)(&self);
            }
        }
    }

    pub fn file_set_txid_on_last_file(&mut self, tx_id: u64) {
        match unsafe {SC} {
            None => panic!("BUG no suricata_config"),
            Some(c) => {
                (c.FileSetTx)(&self, tx_id);
            }
        }
    }
}
