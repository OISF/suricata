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
use std::os::raw::c_void;

// FTP state progress values
pub const FTP_STATE_NONE: u8 = 0;
pub const FTP_STATE_IN_PROGRESS: u8 = 1;
pub const FTP_STATE_PORT_DONE: u8 = 2;
pub const FTP_STATE_FINISHED: u8 = 3;

// FTP Data progress values
pub const FTPDATA_STATE_IN_PROGRESS: u8 = 1;
pub const FTPDATA_STATE_FINISHED: u8 = 2;

// FTP request command values
pub const FTP_COMMAND_UNKNOWN: u8 = 0;
pub const FTP_COMMAND_ABOR: u8 = 1;
pub const FTP_COMMAND_ACCT: u8 = 2;
pub const FTP_COMMAND_ALLO: u8 = 3;
pub const FTP_COMMAND_APPE: u8 = 4;
pub const FTP_COMMAND_AUTH_TLS: u8 = 5;
pub const FTP_COMMAND_CDUP: u8 = 6;
pub const FTP_COMMAND_CHMOD: u8 = 7;
pub const FTP_COMMAND_CWD: u8 = 8;
pub const FTP_COMMAND_DELE: u8 = 9;
pub const FTP_COMMAND_EPSV: u8 = 10;
pub const FTP_COMMAND_HELP: u8 = 11;
pub const FTP_COMMAND_IDLE: u8 = 12;
pub const FTP_COMMAND_LIST: u8 = 13;
pub const FTP_COMMAND_MAIL: u8 = 14;
pub const FTP_COMMAND_MDTM: u8 = 15;
pub const FTP_COMMAND_MKD: u8 = 16;
pub const FTP_COMMAND_MLFL: u8 = 17;
pub const FTP_COMMAND_MODE: u8 = 18;
pub const FTP_COMMAND_MRCP: u8 = 19;
pub const FTP_COMMAND_MRSQ: u8 = 20;
pub const FTP_COMMAND_MSAM: u8 = 21;
pub const FTP_COMMAND_MSND: u8 = 22;
pub const FTP_COMMAND_MSOM: u8 = 23;
pub const FTP_COMMAND_NLST: u8 = 24;
pub const FTP_COMMAND_NOOP: u8 = 25;
pub const FTP_COMMAND_PASS: u8 = 26;
pub const FTP_COMMAND_PASV: u8 = 27;
pub const FTP_COMMAND_PORT: u8 = 28;
pub const FTP_COMMAND_PWD: u8 = 29;
pub const FTP_COMMAND_QUIT: u8 = 30;
pub const FTP_COMMAND_REIN: u8 = 31;
pub const FTP_COMMAND_REST: u8 = 32;
pub const FTP_COMMAND_RETR: u8 = 33;
pub const FTP_COMMAND_RMD: u8 = 34;
pub const FTP_COMMAND_RNFR: u8 = 35;
pub const FTP_COMMAND_RNTO: u8 = 36;
pub const FTP_COMMAND_SITE: u8 = 37;
pub const FTP_COMMAND_SIZE: u8 = 38;
pub const FTP_COMMAND_SMNT: u8 = 39;
pub const FTP_COMMAND_STAT: u8 = 40;
pub const FTP_COMMAND_STOR: u8 = 41;
pub const FTP_COMMAND_STOU: u8 = 42;
pub const FTP_COMMAND_STRU: u8 = 43;
pub const FTP_COMMAND_SYST: u8 = 44;
pub const FTP_COMMAND_TYPE: u8 = 45;
pub const FTP_COMMAND_UMASK: u8 = 46;
pub const FTP_COMMAND_USER: u8 = 47;
pub const FTP_COMMAND_EPRT: u8 = 48;
pub const FTP_COMMAND_MAX: u8 = 49;

#[repr(C)]
#[allow(dead_code)]
pub struct FtpTransferCmd {
    // Must be first -- required by app-layer expectation logic
    data_free: unsafe extern "C" fn(*mut c_void),
    pub flow_id: u64,
    pub file_name: *mut u8,
    pub file_len: u16,
    pub direction: u16,
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
