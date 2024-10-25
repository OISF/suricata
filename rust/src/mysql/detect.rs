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

// Author: QianKaiLin <linqiankai666@outlook.com>

/// Detect
/// Get the mysql query
use super::mysql::{MysqlTransaction, ALPROTO_MYSQL};
use crate::detect::{
    DetectBufferSetActiveList, DetectHelperBufferMpmRegister, DetectHelperGetData,
    DetectHelperGetMultiData, DetectHelperKeywordRegister, DetectHelperMultiBufferMpmRegister,
    DetectSignatureSetAppProto, SCSigTableElmt, SIGMATCH_NOOPT,
};
use std::os::raw::{c_int, c_void};

static mut G_MYSQL_COMMAND_BUFFER_ID: c_int = 0;
static mut G_MYSQL_ROWS_BUFFER_ID: c_int = 0;

#[no_mangle]
unsafe extern "C" fn SCMysqlCommandSetup(
    de: *mut c_void, s: *mut c_void, _raw: *const std::os::raw::c_char,
) -> c_int {
    if DetectSignatureSetAppProto(s, ALPROTO_MYSQL) != 0 {
        return -1;
    }
    if DetectBufferSetActiveList(de, s, G_MYSQL_COMMAND_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

#[no_mangle]
unsafe extern "C" fn SCMysqlGetCommand(
    de: *mut c_void, transforms: *const c_void, flow: *const c_void, flow_flags: u8,
    tx: *const c_void, list_id: c_int,
) -> *mut c_void {
    return DetectHelperGetData(
        de,
        transforms,
        flow,
        flow_flags,
        tx,
        list_id,
        SCMysqlGetCommandData,
    );
}

#[no_mangle]
unsafe extern "C" fn SCMysqlGetCommandData(
    tx: *const c_void, _flags: u8, buf: *mut *const u8, len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, MysqlTransaction);
    if let Some(command) = &tx.command {
        if !command.is_empty() {
            *buf = command.as_ptr();
            *len = command.len() as u32;
            return true;
        }
    }

    false
}

#[no_mangle]
unsafe extern "C" fn SCMysqlRowsSetup(
    de: *mut c_void, s: *mut c_void, _raw: *const std::os::raw::c_char,
) -> c_int {
    if DetectSignatureSetAppProto(s, ALPROTO_MYSQL) != 0 {
        return -1;
    }
    if DetectBufferSetActiveList(de, s, G_MYSQL_ROWS_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

#[no_mangle]
unsafe extern "C" fn SCMysqlGetRows(
    de: *mut c_void, transforms: *const c_void, flow: *const c_void, flow_flags: u8,
    tx: *const c_void, list_id: c_int, local_id: u32,
) -> *mut c_void {
    return DetectHelperGetMultiData(
        de,
        transforms,
        flow,
        flow_flags,
        tx,
        list_id,
        local_id,
        SCMysqlGetRowsData,
    );
}

/// Get the mysql rows at index i
#[no_mangle]
pub unsafe extern "C" fn SCMysqlGetRowsData(
    tx: *const c_void, _flow_flags: u8, local_id: u32, buf: *mut *const u8, len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, MysqlTransaction);
    if let Some(rows) = &tx.rows {
        if !rows.is_empty() {
            let index = local_id as usize;
            if let Some(row) = rows.get(index) {
                *buf = row.as_ptr();
                *len = row.len() as u32;
                return true;
            }
        }
    }

    false
}

#[no_mangle]
pub unsafe extern "C" fn ScDetectMysqlRegister() {
    let kw = SCSigTableElmt {
        name: b"mysql.command\0".as_ptr() as *const libc::c_char,
        desc: b"sticky buffer to match on the MySQL command\0".as_ptr() as *const libc::c_char,
        url: b"/rules/mysql-keywords.html#mysql-command\0".as_ptr() as *const libc::c_char,
        Setup: SCMysqlCommandSetup,
        flags: SIGMATCH_NOOPT,
        AppLayerTxMatch: None,
        Free: None,
    };
    let _g_mysql_command_kw_id = DetectHelperKeywordRegister(&kw);
    G_MYSQL_COMMAND_BUFFER_ID = DetectHelperBufferMpmRegister(
        b"mysql.command\0".as_ptr() as *const libc::c_char,
        b"mysql.command\0".as_ptr() as *const libc::c_char,
        ALPROTO_MYSQL,
        false,
        true,
        SCMysqlGetCommand,
    );
    let kw = SCSigTableElmt {
        name: b"mysql.rows\0".as_ptr() as *const libc::c_char,
        desc: b"sticky buffer to match on the MySQL Rows\0".as_ptr() as *const libc::c_char,
        url: b"/rules/mysql-keywords.html#mysql-rows\0".as_ptr() as *const libc::c_char,
        Setup: SCMysqlRowsSetup,
        flags: SIGMATCH_NOOPT,
        AppLayerTxMatch: None,
        Free: None,
    };
    let _g_mysql_rows_kw_id = DetectHelperKeywordRegister(&kw);
    G_MYSQL_ROWS_BUFFER_ID = DetectHelperMultiBufferMpmRegister(
        b"mysql.rows\0".as_ptr() as *const libc::c_char,
        b"mysql select statement resultset\0".as_ptr() as *const libc::c_char,
        ALPROTO_MYSQL,
        true,
        false,
        SCMysqlGetRows,
    );
}
