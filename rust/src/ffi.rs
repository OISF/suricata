/* Copyright (C) 2020 Open Information Security Foundation
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

// As we're working with FFI here, suppress some compiler warnings that
// are purely about style.
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use lazy_static::lazy_static;

use crate::filecontainer::*;

/// Opaque C types.
pub enum DetectEngineState {}
pub enum AppLayerDecoderEvents {}
pub enum SuricataStreamingBufferConfig {}

pub type SCLogMessageFunc = extern "C" fn(
    level: std::os::raw::c_int,
    filename: *const std::os::raw::c_char,
    line: std::os::raw::c_uint,
    function: *const std::os::raw::c_char,
    code: std::os::raw::c_int,
    message: *const std::os::raw::c_char,
) -> std::os::raw::c_int;

pub type DetectEngineStateFreeFunc = extern "C" fn(state: *mut DetectEngineState);

pub type AppLayerDecoderEventsSetEventRawFunc =
    extern "C" fn(events: *mut *mut AppLayerDecoderEvents, event: u8);

pub type AppLayerDecoderEventsFreeEventsFunc =
    extern "C" fn(events: *mut *mut AppLayerDecoderEvents);

pub type SCFileOpenFileWithId = extern "C" fn(
    file_container: &FileContainer,
    sbcfg: &SuricataStreamingBufferConfig,
    track_id: u32,
    name: *const u8,
    name_len: u16,
    data: *const u8,
    data_len: u32,
    flags: u16,
) -> i32;

pub type SCFileCloseFileById = extern "C" fn(
    file_container: &FileContainer,
    track_id: u32,
    data: *const u8,
    data_len: u32,
    flags: u16,
) -> i32;

pub type SCFileAppendDataById = extern "C" fn(
    file_container: &FileContainer,
    track_id: u32,
    data: *const u8,
    data_len: u32,
) -> i32;

pub type SCFileAppendGAPById = extern "C" fn(
    file_container: &FileContainer,
    track_id: u32,
    data: *const u8,
    data_len: u32,
) -> i32;

pub type SCFilePrune = extern "C" fn(file_container: &FileContainer);

pub type SCFileContainerRecycle = extern "C" fn(file_container: &FileContainer);

pub type SCFileSetTx = extern "C" fn(file: &FileContainer, tx_id: u64);

/// Windows API functions for getting symbols from a process. Equivalent to dlopen/dlsym on Unix.
#[cfg(target_os = "windows")]
extern "C" {
    fn GetModuleHandleA(name: *const std::os::raw::c_char) -> *mut std::os::raw::c_void;
    fn GetProcAddress(
        module: *const std::os::raw::c_void, name: *const std::os::raw::c_char,
    ) -> *mut std::os::raw::c_void;
}

#[cfg(not(target_os = "windows"))]
unsafe fn load_symbol(name: &str) -> Option<*mut std::os::raw::c_void> {
    let cname = std::ffi::CString::new(name).unwrap();
    let sym = libc::dlsym(libc::RTLD_DEFAULT, cname.as_ptr());
    if sym != std::ptr::null_mut() {
        Some(sym)
    } else {
        None
    }
}

#[cfg(target_os = "windows")]
unsafe fn load_symbol(name: &str) -> Option<*mut std::os::raw::c_void> {
    let name = std::ffi::CString::new(name).unwrap();
    let handle = GetModuleHandleA(std::ptr::null_mut());
    if handle == std::ptr::null_mut() {
        return None;
    }
    let addr = GetProcAddress(handle, name.as_ptr());
    if addr != std::ptr::null_mut() {
        Some(addr)
    } else {
        None
    }
}

fn link_fn<T>(name: &str) -> Option<T> {
    let fun = unsafe { load_symbol(name).map(|sym| std::mem::transmute_copy(&sym)) };
    if fun.is_none() {
        println!("RUST-FFI-ERROR No function found with name {}", name);
    }
    fun
}

lazy_static! {
    pub static ref SCLogMessage: Option<SCLogMessageFunc> = link_fn("SCLogMessage");
    pub static ref DetectEngineStateFree: Option<DetectEngineStateFreeFunc> =
        link_fn("DetectEngineStateFree");
    pub static ref AppLayerDecoderEventsSetEventRaw: Option<AppLayerDecoderEventsSetEventRawFunc> =
        link_fn("AppLayerDecoderEventsSetEventRaw");
    pub static ref AppLayerDecoderEventsFreeEvents: Option<AppLayerDecoderEventsFreeEventsFunc> =
        link_fn("AppLayerDecoderEventsFreeEvents");
    pub static ref FileOpenFile: Option<SCFileOpenFileWithId> = link_fn("FileOpenFileWithId");
    pub static ref FileCloseFile: Option<SCFileCloseFileById> = link_fn("FileCloseFileById");
    pub static ref FileAppendData: Option<SCFileAppendDataById> = link_fn("FileAppendDataById");
    pub static ref FileAppendGAP: Option<SCFileAppendGAPById> = link_fn("FileAppendGAPById");
    pub static ref FileContainerRecycle: Option<SCFileContainerRecycle> =
        link_fn("FileContainerRecycle");
    pub static ref FilePrune: Option<SCFilePrune> = link_fn("FilePrune");
    pub static ref FileSetTx: Option<SCFileSetTx> = link_fn("FileContainerSetTx");
}
