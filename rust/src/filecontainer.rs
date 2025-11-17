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

use crate::core::*;

pub use suricata_sys::sys::FileContainer;
#[cfg(not(test))]
use suricata_sys::sys::{
    FileAppendDataById, FileAppendGAPById, FileCloseFileById, FileContainerRecycle,
    FileOpenFileWithId,
};

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

pub trait FileContainerWrapper {
    fn free(&mut self, cfg: &'static SuricataFileContext);
    fn file_open(
        &mut self, cfg: &'static SuricataFileContext, track_id: u32, name: &[u8], flags: u16,
    ) -> i32;
    fn file_append(
        &mut self, cfg: &'static SuricataFileContext, track_id: &u32, data: &[u8], is_gap: bool,
    ) -> i32;
    fn file_close(&mut self, cfg: &'static SuricataFileContext, track_id: &u32, flags: u16) -> i32;
}

impl FileContainerWrapper for FileContainer {
    fn free(&mut self, cfg: &'static SuricataFileContext) {
        SCLogDebug!("freeing self");
        unsafe {
            FileContainerRecycle(self, cfg.files_sbcfg);
        }
    }

    fn file_open(
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

    fn file_append(
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

    fn file_close(&mut self, cfg: &'static SuricataFileContext, track_id: &u32, flags: u16) -> i32 {
        SCLogDebug!("FILECONTAINER: CLOSEing");

        unsafe { FileCloseFileById(self, cfg.files_sbcfg, *track_id, ptr::null(), 0u32, flags) }
    }
}
