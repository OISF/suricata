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

use super::ssh::{SSHConnectionState, SSHTransaction, ALPROTO_SSH};
use crate::core::{STREAM_TOCLIENT, STREAM_TOSERVER};
use crate::detect::{helper_keyword_register_sticky_buffer, SigTableElmtStickyBuffer};
use crate::direction::Direction;
use std::os::raw::{c_int, c_void};
use std::ptr;
use suricata_sys::sys::{
    DetectEngineCtx, SCDetectBufferSetActiveList, SCDetectHelperBufferProgressMpmRegister,
    SCDetectHelperKeywordAliasRegister, SCDetectHelperKeywordRegister,
    SCDetectSignatureSetAppProto, SCSigTableAppLiteElmt, Signature,
};

#[no_mangle]
pub unsafe extern "C" fn SCSshTxGetProtocol(
    tx: *const c_void, direction: u8, buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, SSHTransaction);
    match direction.into() {
        Direction::ToServer => {
            let m = &tx.cli_hdr.protover;
            if !m.is_empty() {
                *buffer = m.as_ptr();
                *buffer_len = m.len() as u32;
                return true;
            }
        }
        Direction::ToClient => {
            let m = &tx.srv_hdr.protover;
            if !m.is_empty() {
                *buffer = m.as_ptr();
                *buffer_len = m.len() as u32;
                return true;
            }
        }
    }
    *buffer = ptr::null();
    *buffer_len = 0;

    return false;
}

#[no_mangle]
pub unsafe extern "C" fn SCSshTxGetSoftware(
    tx: *const c_void, direction: u8, buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, SSHTransaction);
    match direction.into() {
        Direction::ToServer => {
            let m = &tx.cli_hdr.swver;
            if !m.is_empty() {
                *buffer = m.as_ptr();
                *buffer_len = m.len() as u32;
                return true;
            }
        }
        Direction::ToClient => {
            let m = &tx.srv_hdr.swver;
            if !m.is_empty() {
                *buffer = m.as_ptr();
                *buffer_len = m.len() as u32;
                return true;
            }
        }
    }
    *buffer = ptr::null();
    *buffer_len = 0;
    return false;
}

#[no_mangle]
pub unsafe extern "C" fn SCSshTxGetHassh(
    tx: *mut std::os::raw::c_void, buffer: *mut *const u8, buffer_len: *mut u32, direction: u8,
) -> u8 {
    let tx = cast_pointer!(tx, SSHTransaction);
    match direction.into() {
        Direction::ToServer => {
            let m = &tx.cli_hdr.hassh;
            if !m.is_empty() {
                *buffer = m.as_ptr();
                *buffer_len = m.len() as u32;
                return 1;
            }
        }
        Direction::ToClient => {
            let m = &tx.srv_hdr.hassh;
            if !m.is_empty() {
                *buffer = m.as_ptr();
                *buffer_len = m.len() as u32;
                return 1;
            }
        }
    }
    *buffer = ptr::null();
    *buffer_len = 0;

    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn SCSshTxGetHasshString(
    tx: *mut std::os::raw::c_void, buffer: *mut *const u8, buffer_len: *mut u32, direction: u8,
) -> u8 {
    let tx = cast_pointer!(tx, SSHTransaction);
    match direction.into() {
        Direction::ToServer => {
            let m = &tx.cli_hdr.hassh_string;
            if !m.is_empty() {
                *buffer = m.as_ptr();
                *buffer_len = m.len() as u32;
                return 1;
            }
        }
        Direction::ToClient => {
            let m = &tx.srv_hdr.hassh_string;
            if !m.is_empty() {
                *buffer = m.as_ptr();
                *buffer_len = m.len() as u32;
                return 1;
            }
        }
    }
    *buffer = ptr::null();
    *buffer_len = 0;

    return 0;
}

unsafe extern "C" fn ssh_software_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_SSH) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_SSH_SOFTWARE_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn ssh_proto_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_SSH) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_SSH_PROTO_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn ssh_software_obsolete_setup(
    _de: *mut DetectEngineCtx, _s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    SCLogError!("ssh.softwareversion is obsolete, use now ssh.software");
    return -1;
}

unsafe extern "C" fn ssh_proto_obsolete_setup(
    _de: *mut DetectEngineCtx, _s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    SCLogError!("ssh.softwareversion is obsolete, use now ssh.software");
    return -1;
}

static mut G_SSH_SOFTWARE_BUFFER_ID: c_int = 0;
static mut G_SSH_PROTO_BUFFER_ID: c_int = 0;

#[no_mangle]
pub unsafe extern "C" fn SCDetectSshRegister() {
    let kw = SigTableElmtStickyBuffer {
        name: String::from("ssh.software"),
        desc: String::from("ssh.software sticky buffer"),
        url: String::from("/rules/ssh-keywords.html#ssh-software"),
        setup: ssh_software_setup,
    };
    let ssh_software_kw_id = helper_keyword_register_sticky_buffer(&kw);
    G_SSH_SOFTWARE_BUFFER_ID = SCDetectHelperBufferProgressMpmRegister(
        b"ssh_software\0".as_ptr() as *const libc::c_char,
        b"ssh software field\0".as_ptr() as *const libc::c_char,
        ALPROTO_SSH,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        Some(SCSshTxGetSoftware),
        SSHConnectionState::SshStateBannerDone as c_int,
    );
    SCDetectHelperKeywordAliasRegister(
        ssh_software_kw_id,
        b"ssh_software\0".as_ptr() as *const libc::c_char,
    );

    let kw = SCSigTableAppLiteElmt {
        name: b"ssh.softwareversion\0".as_ptr() as *const libc::c_char,
        desc: b"obsolete keyword, use now ssh.software\0".as_ptr() as *const libc::c_char,
        url: std::ptr::null(),
        AppLayerTxMatch: None,
        Setup: Some(ssh_software_obsolete_setup),
        Free: None,
        flags: 0,
    };
    _ = SCDetectHelperKeywordRegister(&kw);

    let kw = SCSigTableAppLiteElmt {
        name: b"ssh.protoversion\0".as_ptr() as *const libc::c_char,
        desc: b"obsolete keyword, use now ssh.proto\0".as_ptr() as *const libc::c_char,
        url: std::ptr::null(),
        AppLayerTxMatch: None,
        Setup: Some(ssh_proto_obsolete_setup),
        Free: None,
        flags: 0,
    };
    _ = SCDetectHelperKeywordRegister(&kw);

    let kw = SigTableElmtStickyBuffer {
        name: String::from("ssh.proto"),
        desc: String::from("ssh.proto sticky buffer"),
        url: String::from("/rules/ssh-keywords.html#ssh-proto"),
        setup: ssh_proto_setup,
    };
    let ssh_proto_kw_id = helper_keyword_register_sticky_buffer(&kw);
    G_SSH_PROTO_BUFFER_ID = SCDetectHelperBufferProgressMpmRegister(
        b"ssh.proto\0".as_ptr() as *const libc::c_char,
        b"ssh protocol version field\0".as_ptr() as *const libc::c_char,
        ALPROTO_SSH,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        Some(SCSshTxGetProtocol),
        SSHConnectionState::SshStateBannerDone as c_int,
    );
    SCDetectHelperKeywordAliasRegister(
        ssh_proto_kw_id,
        b"ssh_proto\0".as_ptr() as *const libc::c_char,
    );
}
