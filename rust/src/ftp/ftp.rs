/* Copyright (C) 2025 Open Information Security Foundation
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
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_void};
use std::ptr;

use crate::conf::{conf_get, get_memval};
use crate::ftp::constant::*;
use lazy_static::lazy_static;
use suricata_sys::sys::{MpmCtx, SCMpmAddPatternCI};

#[repr(C)]
pub struct DetectFtpModeData {
    pub active: bool,
}

#[repr(C)]
pub struct DetectFtpReplyReceivedData {
    pub received: bool,
}

#[repr(C)]
pub struct FtpCommand {
    command_name: CString,
    command: FtpRequestCommand,
    command_length: u8,
}

impl FtpCommand {
    fn new(command_name: &str, command: FtpRequestCommand) -> FtpCommand {
        let cstring = CString::new(command_name).unwrap();
        let length = cstring.as_bytes().len();
        FtpCommand {
            command_name: cstring,
            command,
            command_length: length as u8,
        }
    }
}

lazy_static! {
    static ref FTP_COMMANDS: Vec<FtpCommand> = vec![
        FtpCommand::new("PORT", FtpRequestCommand::FTP_COMMAND_PORT),
        FtpCommand::new("EPRT", FtpRequestCommand::FTP_COMMAND_EPRT),
        FtpCommand::new("AUTH_TLS", FtpRequestCommand::FTP_COMMAND_AUTH_TLS),
        FtpCommand::new("PASV", FtpRequestCommand::FTP_COMMAND_PASV),
        FtpCommand::new("EPSV", FtpRequestCommand::FTP_COMMAND_EPSV),
        FtpCommand::new("RETR", FtpRequestCommand::FTP_COMMAND_RETR),
        FtpCommand::new("STOR", FtpRequestCommand::FTP_COMMAND_STOR),
        FtpCommand::new("ABOR", FtpRequestCommand::FTP_COMMAND_ABOR),
        FtpCommand::new("ACCT", FtpRequestCommand::FTP_COMMAND_ACCT),
        FtpCommand::new("ALLO", FtpRequestCommand::FTP_COMMAND_ALLO),
        FtpCommand::new("APPE", FtpRequestCommand::FTP_COMMAND_APPE),
        FtpCommand::new("CDUP", FtpRequestCommand::FTP_COMMAND_CDUP),
        FtpCommand::new("CHMOD", FtpRequestCommand::FTP_COMMAND_CHMOD),
        FtpCommand::new("CWD", FtpRequestCommand::FTP_COMMAND_CWD),
        FtpCommand::new("DELE", FtpRequestCommand::FTP_COMMAND_DELE),
        FtpCommand::new("HELP", FtpRequestCommand::FTP_COMMAND_HELP),
        FtpCommand::new("IDLE", FtpRequestCommand::FTP_COMMAND_IDLE),
        FtpCommand::new("LIST", FtpRequestCommand::FTP_COMMAND_LIST),
        FtpCommand::new("MAIL", FtpRequestCommand::FTP_COMMAND_MAIL),
        FtpCommand::new("MDTM", FtpRequestCommand::FTP_COMMAND_MDTM),
        FtpCommand::new("MKD", FtpRequestCommand::FTP_COMMAND_MKD),
        FtpCommand::new("MLFL", FtpRequestCommand::FTP_COMMAND_MLFL),
        FtpCommand::new("MODE", FtpRequestCommand::FTP_COMMAND_MODE),
        FtpCommand::new("MRCP", FtpRequestCommand::FTP_COMMAND_MRCP),
        FtpCommand::new("MRSQ", FtpRequestCommand::FTP_COMMAND_MRSQ),
        FtpCommand::new("MSAM", FtpRequestCommand::FTP_COMMAND_MSAM),
        FtpCommand::new("MSND", FtpRequestCommand::FTP_COMMAND_MSND),
        FtpCommand::new("MSOM", FtpRequestCommand::FTP_COMMAND_MSOM),
        FtpCommand::new("NLST", FtpRequestCommand::FTP_COMMAND_NLST),
        FtpCommand::new("NOOP", FtpRequestCommand::FTP_COMMAND_NOOP),
        FtpCommand::new("PASS", FtpRequestCommand::FTP_COMMAND_PASS),
        FtpCommand::new("PWD", FtpRequestCommand::FTP_COMMAND_PWD),
        FtpCommand::new("QUIT", FtpRequestCommand::FTP_COMMAND_QUIT),
        FtpCommand::new("REIN", FtpRequestCommand::FTP_COMMAND_REIN),
        FtpCommand::new("REST", FtpRequestCommand::FTP_COMMAND_REST),
        FtpCommand::new("RMD", FtpRequestCommand::FTP_COMMAND_RMD),
        FtpCommand::new("RNFR", FtpRequestCommand::FTP_COMMAND_RNFR),
        FtpCommand::new("RNTO", FtpRequestCommand::FTP_COMMAND_RNTO),
        FtpCommand::new("SITE", FtpRequestCommand::FTP_COMMAND_SITE),
        FtpCommand::new("SIZE", FtpRequestCommand::FTP_COMMAND_SIZE),
        FtpCommand::new("SMNT", FtpRequestCommand::FTP_COMMAND_SMNT),
        FtpCommand::new("STAT", FtpRequestCommand::FTP_COMMAND_STAT),
        FtpCommand::new("STOU", FtpRequestCommand::FTP_COMMAND_STOU),
        FtpCommand::new("STRU", FtpRequestCommand::FTP_COMMAND_STRU),
        FtpCommand::new("SYST", FtpRequestCommand::FTP_COMMAND_SYST),
        FtpCommand::new("TYPE", FtpRequestCommand::FTP_COMMAND_TYPE),
        FtpCommand::new("UMASK", FtpRequestCommand::FTP_COMMAND_UMASK),
        FtpCommand::new("USER", FtpRequestCommand::FTP_COMMAND_USER),
        FtpCommand::new("UNKNOWN", FtpRequestCommand::FTP_COMMAND_UNKNOWN),
    ];
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn SCGetFtpCommandInfo(
    index: usize, name_ptr: *mut *const c_char, code_ptr: *mut u8, len_ptr: *mut u8,
) -> bool {
    if index <= FTP_COMMANDS.len() {
        unsafe {
            if !name_ptr.is_null() {
                *name_ptr = FTP_COMMANDS[index].command_name.as_ptr();
            }
            if !code_ptr.is_null() {
                *code_ptr = FTP_COMMANDS[index].command as u8;
            }
            if !len_ptr.is_null() {
                *len_ptr = FTP_COMMANDS[index].command_length;
            }
        }
        true
    } else {
        false
    }
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn SCFTPSetMpmState(ctx: *mut MpmCtx) {
    for index in 0..FTP_COMMANDS.len() {
        let name_ptr = FTP_COMMANDS[index].command_name.as_ptr();
        let len = FTP_COMMANDS[index].command_length;
        if len > 0 {
            SCMpmAddPatternCI(
                ctx,
                name_ptr as *const u8,
                len as u16,
                0,
                0,
                index as u32,
                index as u32,
                0,
            );
        }
    }
}

#[repr(C)]
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
            cmd: 0,
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
pub unsafe extern "C" fn SCFTPGetConfigValues(
    memcap: *mut u64, max_tx: *mut u32, max_line_len: *mut u32,
) {
    if let Some(val) = conf_get("app-layer.protocols.ftp.memcap") {
        if let Ok(v) = get_memval(val) {
            *memcap = v;
            SCLogConfig!("FTP memcap: {}", v);
        } else {
            SCLogWarning!(
                "Invalid value {} for ftp.memcap; defaulting to {}",
                val,
                *memcap
            );
        }
    }
    if let Some(val) = conf_get("app-layer.protocols.ftp.max-tx") {
        if let Ok(v) = val.parse::<u32>() {
            *max_tx = v;
            SCLogConfig!("FTP max tx: {}", v);
        } else {
            SCLogWarning!(
                "Invalid value {} for ftp.max-tx; defaulting to {}",
                val,
                *max_tx
            );
        }
    }
    // This value is often expressed with a unit suffix, e.g., 5kb, hence get_memval
    if let Some(val) = conf_get("app-layer.protocols.ftp.max-line-length") {
        if let Ok(v) = get_memval(val) {
            *max_line_len = v as u32;
            SCLogConfig!("FTP max line length: {}", v);
        } else {
            SCLogWarning!(
                "Invalid value {} for ftp.max-line-length; defaulting to {}",
                val,
                *max_line_len
            );
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn SCFTPParseReplyReceived(
    c_str: *const c_char,
) -> *mut DetectFtpReplyReceivedData {
    if c_str.is_null() {
        return ptr::null_mut();
    }

    // Convert C string to Rust string slice
    let Ok(input_str) = CStr::from_ptr(c_str).to_str() else {
        return ptr::null_mut();
    };

    // Check for case-insensitive match
    let received_val = match input_str.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => true,
        "false" | "0" | "no" | "off" => false,
        _ => return ptr::null_mut(), // invalid input
    };

    // Return a pointer to a heap-allocated struct
    let boxed = Box::new(DetectFtpReplyReceivedData {
        received: received_val,
    });
    Box::into_raw(boxed)
}

#[no_mangle]
pub unsafe extern "C" fn SCFTPFreeReplyReceivedData(ptr: *mut DetectFtpReplyReceivedData) {
    if !ptr.is_null() {
        drop(Box::from_raw(ptr));
    }
}
#[no_mangle]
pub unsafe extern "C" fn SCFTPParseMode(c_str: *const c_char) -> *mut DetectFtpModeData {
    if c_str.is_null() {
        return ptr::null_mut();
    }

    // Convert C string to Rust string slice
    let Ok(input_str) = CStr::from_ptr(c_str).to_str() else {
        return ptr::null_mut();
    };

    // Check for case-insensitive match
    let is_active = match input_str.trim().to_ascii_lowercase().as_str() {
        "active" => true,
        "passive" => false,
        _ => return ptr::null_mut(), // invalid input
    };

    // Return a pointer to a heap-allocated struct
    let boxed = Box::new(DetectFtpModeData { active: is_active });
    Box::into_raw(boxed)
}

#[no_mangle]
pub unsafe extern "C" fn SCFTPFreeModeData(ptr: *mut DetectFtpModeData) {
    if !ptr.is_null() {
        drop(Box::from_raw(ptr));
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
