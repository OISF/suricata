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

use std::os::raw::c_void;
use std::ptr;

use crate::core::*;

#[repr(C)]
#[derive(Debug)]
pub struct FileContainer {
    head: *mut c_void,
    tail: *mut c_void,
}

impl Default for FileContainer {
    fn default() -> Self {
        Self {
            head: ptr::null_mut(),
            tail: ptr::null_mut(),
        }
    }
}

// Defined in util-file.h
#[allow(unused_doc_comments)]
/// cbindgen:ignore
extern "C" {
    #[cfg(not(test))]
    pub fn FileContainerRecycle(file_container: &mut FileContainer, sbcfg: &StreamingBufferConfig);
    #[cfg(not(test))]
    pub fn FileAppendGAPById(
        file_container: &mut FileContainer, sbcfg: &StreamingBufferConfig, track_id: u32,
        data: *const u8, data_len: u32,
    ) -> i32;
    #[cfg(not(test))]
    pub fn FileAppendDataById(
        file_container: &mut FileContainer, sbcfg: &StreamingBufferConfig, track_id: u32,
        data: *const u8, data_len: u32,
    ) -> i32;
    #[cfg(not(test))]
    pub fn FileCloseFileById(
        file_container: &mut FileContainer, sbcfg: &StreamingBufferConfig, track_id: u32,
        data: *const u8, data_len: u32, flags: u16,
    ) -> i32;
    #[cfg(not(test))]
    pub fn FileOpenFileWithId(
        file_container: &mut FileContainer, sbcfg: &StreamingBufferConfig, track_id: u32,
        name: *const u8, name_len: u16, data: *const u8, data_len: u32, flags: u16,
    ) -> i32;
}

#[cfg(test)]
#[allow(non_snake_case)]
pub(super) unsafe fn FileContainerRecycle(_fc: &mut FileContainer, _sbcfg: &StreamingBufferConfig) {
}
#[cfg(test)]
#[allow(non_snake_case)]
pub(super) unsafe fn FileAppendGAPById(
    _fc: &mut FileContainer, _sbcfg: &StreamingBufferConfig, _track_id: u32, _data: *const u8,
    _data_len: u32,
) -> i32 {
    0
}
#[cfg(test)]
#[allow(non_snake_case)]
pub(super) unsafe fn FileAppendDataById(
    _fc: &mut FileContainer, _sbcfg: &StreamingBufferConfig, _track_id: u32, _data: *const u8,
    _data_len: u32,
) -> i32 {
    0
}
#[cfg(test)]
#[allow(non_snake_case)]
pub(super) unsafe fn FileCloseFileById(
    _fc: &mut FileContainer, _sbcfg: &StreamingBufferConfig, _track_id: u32, _data: *const u8,
    _data_len: u32, _flags: u16,
) -> i32 {
    0
}
#[cfg(test)]
#[allow(non_snake_case)]
pub(super) unsafe fn FileOpenFileWithId(
    _fc: &mut FileContainer, _sbcfg: &StreamingBufferConfig, _track_id: u32, _name: *const u8,
    _name_len: u16, _data: *const u8, _data_len: u32, _flags: u16,
) -> i32 {
    0
}

impl FileContainer {
    pub fn free(&mut self, cfg: &'static SuricataFileContext) {
        SCLogDebug!("freeing self");
        unsafe {
            FileContainerRecycle(self, cfg.files_sbcfg);
        }
    }

    pub fn file_open(
        &mut self, cfg: &'static SuricataFileContext, track_id: u32, name: &[u8], flags: u16,
    ) -> i32 {
        SCLogDebug!("FILE {:p} OPEN flags {:04X}", &self, flags);

        unsafe {
            FileOpenFileWithId(
                self,
                cfg.files_sbcfg,
                track_id,
                name.as_ptr(),
                name.len() as u16,
                ptr::null(),
                0u32,
                flags,
            )
        }
    }

    pub fn file_append(
        &mut self, cfg: &'static SuricataFileContext, track_id: &u32, data: &[u8], is_gap: bool,
    ) -> i32 {
        SCLogDebug!("FILECONTAINER: append {}", data.len());
        if data.is_empty() {
            return 0;
        }
        let res = match is_gap {
            false => {
                SCLogDebug!("appending file data");
                unsafe {
                    FileAppendDataById(
                        self,
                        cfg.files_sbcfg,
                        *track_id,
                        data.as_ptr(),
                        data.len() as u32,
                    )
                }
            }
            true => {
                SCLogDebug!("appending GAP");
                unsafe {
                    FileAppendGAPById(
                        self,
                        cfg.files_sbcfg,
                        *track_id,
                        data.as_ptr(),
                        data.len() as u32,
                    )
                }
            }
        };
        res
    }

    pub fn file_close(
        &mut self, cfg: &'static SuricataFileContext, track_id: &u32, flags: u16,
    ) -> i32 {
        SCLogDebug!("FILECONTAINER: CLOSEing");

        unsafe { FileCloseFileById(self, cfg.files_sbcfg, *track_id, ptr::null(), 0u32, flags) }
    }
}
