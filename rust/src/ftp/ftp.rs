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
use std::ffi::CString;
use std::os::raw::{c_char, c_void};

use crate::conf::{conf_get, get_memval};
use crate::ftp::constant::*;
use lazy_static::lazy_static;

#[repr(C)]

/// cbindgen:ignore
struct FtpCommand {
    command_name: CString,
    command: u8,
    command_length: u8,
}

impl FtpCommand {
    fn new(command_name: &str, command: u8, command_length: u8) -> FtpCommand {
        let cstring = CString::new(command_name).unwrap();
        FtpCommand {
            command_name: cstring,
            command,
            command_length,
        }
    }
}

lazy_static! {
    static ref FTP_COMMANDS: Vec<FtpCommand> = vec![
        FtpCommand::new("PORT", FTP_COMMAND_PORT, 4),
        FtpCommand::new("EPRT", FTP_COMMAND_EPRT, 4),
        FtpCommand::new("AUTH_TLS", FTP_COMMAND_AUTH_TLS, 8),
        FtpCommand::new("PASV", FTP_COMMAND_PASV, 4),
        FtpCommand::new("EPSV", FTP_COMMAND_EPSV, 4),
        FtpCommand::new("RETR", FTP_COMMAND_RETR, 4),
        FtpCommand::new("STOR", FTP_COMMAND_STOR, 4),
        FtpCommand::new("ABOR", FTP_COMMAND_ABOR, 4),
        FtpCommand::new("ACCT", FTP_COMMAND_ACCT, 4),
        FtpCommand::new("ALLO", FTP_COMMAND_ALLO, 4),
        FtpCommand::new("APPE", FTP_COMMAND_APPE, 4),
        FtpCommand::new("CDUP", FTP_COMMAND_CDUP, 4),
        FtpCommand::new("CHMOD", FTP_COMMAND_CHMOD, 5),
        FtpCommand::new("CWD", FTP_COMMAND_CWD, 3),
        FtpCommand::new("DELE", FTP_COMMAND_DELE, 4),
        FtpCommand::new("HELP", FTP_COMMAND_HELP, 4),
        FtpCommand::new("IDLE", FTP_COMMAND_IDLE, 4),
        FtpCommand::new("LIST", FTP_COMMAND_LIST, 4),
        FtpCommand::new("MAIL", FTP_COMMAND_MAIL, 4),
        FtpCommand::new("MDTM", FTP_COMMAND_MDTM, 4),
        FtpCommand::new("MKD", FTP_COMMAND_MKD, 3),
        FtpCommand::new("MLFL", FTP_COMMAND_MLFL, 4),
        FtpCommand::new("MODE", FTP_COMMAND_MODE, 4),
        FtpCommand::new("MRCP", FTP_COMMAND_MRCP, 4),
        FtpCommand::new("MRSQ", FTP_COMMAND_MRSQ, 4),
        FtpCommand::new("MSAM", FTP_COMMAND_MSAM, 4),
        FtpCommand::new("MSND", FTP_COMMAND_MSND, 4),
        FtpCommand::new("MSOM", FTP_COMMAND_MSOM, 4),
        FtpCommand::new("NLST", FTP_COMMAND_NLST, 4),
        FtpCommand::new("NOOP", FTP_COMMAND_NOOP, 4),
        FtpCommand::new("PASS", FTP_COMMAND_PASS, 4),
        FtpCommand::new("PWD", FTP_COMMAND_PWD, 3),
        FtpCommand::new("QUIT", FTP_COMMAND_QUIT, 4),
        FtpCommand::new("REIN", FTP_COMMAND_REIN, 4),
        FtpCommand::new("REST", FTP_COMMAND_REST, 4),
        FtpCommand::new("RMD", FTP_COMMAND_RMD, 3),
        FtpCommand::new("RNFR", FTP_COMMAND_RNFR, 4),
        FtpCommand::new("RNTO", FTP_COMMAND_RNTO, 4),
        FtpCommand::new("SITE", FTP_COMMAND_SITE, 4),
        FtpCommand::new("SIZE", FTP_COMMAND_SIZE, 4),
        FtpCommand::new("SMNT", FTP_COMMAND_SMNT, 4),
        FtpCommand::new("STAT", FTP_COMMAND_STAT, 4),
        FtpCommand::new("STOU", FTP_COMMAND_STOU, 4),
        FtpCommand::new("STRU", FTP_COMMAND_STRU, 4),
        FtpCommand::new("SYST", FTP_COMMAND_SYST, 4),
        FtpCommand::new("TYPE", FTP_COMMAND_TYPE, 4),
        FtpCommand::new("UMASK", FTP_COMMAND_UMASK, 5),
        FtpCommand::new("USER", FTP_COMMAND_USER, 4),
        FtpCommand::new("UNKNOWN", FTP_COMMAND_UNKNOWN, 7),
        FtpCommand::new("MAX", FTP_COMMAND_MAX, 0),
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
                *code_ptr = FTP_COMMANDS[index].command;
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
pub extern "C" fn SCGetFtpCommandTableSize() -> usize {
    FTP_COMMANDS.len()
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
pub unsafe extern "C" fn SCFTPGetConfigValues(
    memcap: *mut u64, max_tx: *mut u32, max_line_len: *mut u32,
) {
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
