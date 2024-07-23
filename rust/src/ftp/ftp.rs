/* Copyright (C) 2024 Open Information Security Foundation
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
use std::os::raw::{c_char, c_void};

use crate::ftp::constant::*;
use crate::conf::{conf_get, get_memval};

#[repr(C)]
//#[derive(Debug, Copy, Clone)]
pub struct FtpCommand {
    pub command_name: *const c_char,
    pub command: u8,
    pub command_length: u8,
}

impl FtpCommand {
    pub fn new() -> Self {
        FtpCommand {
            ..Default::default()
        }
    }
}
impl Default for FtpCommand {
    fn default() -> Self {
        FtpCommand {
            command_name: std::ptr::null_mut(),
            command: 0,
            command_length: 0,
        }
    }
}

#[repr(C)]
#[allow(dead_code)]
pub struct FtpTransferCmd {
    // Must be first -- required by app-layer expectation logic
    data_free: unsafe extern "C" fn(*mut c_void),
    pub flow_id: u64,
    pub file_name: *mut u8,
    pub file_len: u16,
    pub direction: u8,
    pub cmd: u8,
}

impl Default for FtpTransferCmd {
    fn default() -> Self {
        FtpTransferCmd {
            flow_id: 0,
            file_name: std::ptr::null_mut(),
            file_len: 0,
            direction: 0,
            cmd: FTP_STATE_NONE,
            data_free: default_free_fn,
        }
    }
}

unsafe extern "C" fn default_free_fn(_ptr: *mut c_void) {}
impl FtpTransferCmd {
    pub fn new() -> Self {
        FtpTransferCmd {
            ..Default::default()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn SCFTPGetConfigValues(memcap: *mut u64, max_tx: *mut u32, max_line_len: *mut u32) {
    if let Some(val) = conf_get("app-layer.protocols.ftp.memcap") {
        if let Ok(v) = get_memval(val) {
            *memcap = v;
            SCLogConfig!("FTP memcap: {}", v);
        } else {
            SCLogError!("Invalid value {} for ftp.memcap", val);
        }
    }
    if let Some(val) = conf_get("app-layer.protocols.ftp.max-tx") {
        if let Ok(v) = val.parse::<u32>() {
            *max_tx = v;
            SCLogConfig!("FTP max tx: {}", v);
        } else {
            SCLogError!("Invalid value {} for ftp.max-tx", val);
        }
    }
    // This value is often expressed with a unit suffix, e.g., 5kb, hence get_memval
    if let Some(val) = conf_get("app-layer.protocols.ftp.max-line-length") {
        if let Ok(v) = get_memval(val) {
            *max_line_len = v as u32;
            SCLogConfig!("FTP max line length: {}", v);
        } else {
            SCLogError!("Invalid value {} for ftp.max-line-length", val);
        }
    }
}

/// Returns *mut FtpTransferCmd
#[no_mangle]
pub unsafe extern "C" fn SCFTPTransferCmdNew() -> *mut FtpTransferCmd {
    SCLogDebug!("allocating ftp transfer cmd");
    let cmd = FtpTransferCmd::new();
    Box::into_raw(Box::new(cmd))
}

/// Params:
/// - transfer command: *mut FTPTransferCmd as void pointer
#[no_mangle]
pub unsafe extern "C" fn SCFTPTransferCmdFree(cmd: *mut FtpTransferCmd) {
    SCLogDebug!("freeing ftp transfer cmd");
    if !cmd.is_null() {
        let _transfer_cmd = Box::from_raw(cmd);
    }
}
