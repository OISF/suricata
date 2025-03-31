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

//! This module handles file container operations (open, append, close).

use std::ptr;
use std::os::raw::{c_void};

use crate::core::*;

// Defined in util-file.h
/// cbindgen:ignore
extern "C" {
    pub fn FileFlowFlagsToFlags(flow_file_flags: u16, flags: u8) -> u16;
}

#[repr(C)]
#[derive(Debug)]
pub struct FileContainer {
    head: * mut c_void,
    tail: * mut c_void,
}

impl Default for FileContainer {
    fn default() -> Self { Self {
        head: ptr::null_mut(),
        tail: ptr::null_mut(),
    }}
}

impl FileContainer {
    pub fn free(&mut self, cfg: &'static SuricataFileContext) {
        SCLogDebug!("freeing self");
        if let Some(c) = unsafe {SC} {
            (c.FileContainerRecycle)(self, cfg.files_sbcfg);
        }
    }

    pub fn file_open(&mut self, cfg: &'static SuricataFileContext, track_id: u32, name: &[u8], flags: u16) -> i32 {
        match unsafe {SC} {
            None => panic!("BUG no suricata_config"),
            Some(c) => {
                SCLogDebug!("FILE {:p} OPEN flags {:04X}", &self, flags);

                let res = (c.FileOpenFile)(self, cfg.files_sbcfg, track_id,
                        name.as_ptr(), name.len() as u16,
                        ptr::null(), 0u32, flags);
                res
            }
        }
    }

    pub fn file_append(&mut self, cfg: &'static SuricataFileContext, track_id: &u32, data: &[u8], is_gap: bool) -> i32 {
        SCLogDebug!("FILECONTAINER: append {}", data.len());
        if data.is_empty() {
            return 0
        }
        match unsafe {SC} {
            None => panic!("BUG no suricata_config"),
            Some(c) => {
                let res = match is_gap {
                    false => {
                        SCLogDebug!("appending file data");
                        let r = (c.FileAppendData)(self, cfg.files_sbcfg, *track_id,
                                data.as_ptr(), data.len() as u32);
                        r
                    },
                    true => {
                        SCLogDebug!("appending GAP");
                        let r = (c.FileAppendGAP)(self, cfg.files_sbcfg, *track_id,
                                data.as_ptr(), data.len() as u32);
                        r
                    },
                };
                res
            }
        }
    }

    pub fn file_close(&mut self, cfg: &'static SuricataFileContext, track_id: &u32, flags: u16) -> i32 {
        SCLogDebug!("FILECONTAINER: CLOSEing");

        match unsafe {SC} {
            None => panic!("BUG no suricata_config"),
            Some(c) => {
                let res = (c.FileCloseFile)(self, cfg.files_sbcfg, *track_id, ptr::null(), 0u32, flags);
                res
            }
        }

    }
}
