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

use super::ssh::{
    SCSshEnableHassh, SCSshHasshIsEnabled, SSHConnectionState, SSHTransaction, ALPROTO_SSH,
};
use crate::core::{STREAM_TOCLIENT, STREAM_TOSERVER};
use crate::detect::{helper_keyword_register_sticky_buffer, SigTableElmtStickyBuffer};
use crate::direction::Direction;
use std::os::raw::{c_int, c_void};
use std::ptr;
use suricata_sys::sys::{
    DetectEngineCtx, SCDetectBufferSetActiveList, SCDetectHelperBufferProgressMpmRegister,
    SCDetectHelperKeywordAliasRegister, SCDetectHelperKeywordRegister,
    SCDetectRegisterBufferLowerMd5Callbacks, SCDetectSignatureSetAppProto,
    SCSigMatchSilentErrorEnabled, SCSigTableAppLiteElmt, Signature,
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
    tx: *const c_void, direction: u8, buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, SSHTransaction);
    match direction.into() {
        Direction::ToServer => {
            let m = &tx.cli_hdr.hassh;
            if !m.is_empty() {
                *buffer = m.as_ptr();
                *buffer_len = m.len() as u32;
                return true;
            }
        }
        Direction::ToClient => {
            let m = &tx.srv_hdr.hassh;
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
pub unsafe extern "C" fn SCSshTxGetHasshString(
    tx: *const c_void, direction: u8, buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, SSHTransaction);
    match direction.into() {
        Direction::ToServer => {
            let m = &tx.cli_hdr.hassh_string;
            if !m.is_empty() {
                *buffer = m.as_ptr();
                *buffer_len = m.len() as u32;
                return true;
            }
        }
        Direction::ToClient => {
            let m = &tx.srv_hdr.hassh_string;
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

unsafe extern "C" fn ssh_hassh_string_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_SSH) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_SSH_HASSH_STR_BUFFER_ID) < 0 {
        return -1;
    }
    /* try to enable Hassh */
    SCSshEnableHassh();

    /* Check if Hassh is disabled */
    if !SCSshHasshIsEnabled() {
        if !SCSigMatchSilentErrorEnabled(de, DETECT_SSH_HASSH_STRING) {
            SCLogError!("hassh support is not enabled");
        }
        return -2;
    }
    return 0;
}

unsafe extern "C" fn ssh_hassh_server_string_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_SSH) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_SSH_HASSH_SRV_STR_BUFFER_ID) < 0 {
        return -1;
    }
    /* try to enable Hassh */
    SCSshEnableHassh();

    /* Check if Hassh is disabled */
    if !SCSshHasshIsEnabled() {
        if !SCSigMatchSilentErrorEnabled(de, DETECT_SSH_HASSH_SERVER_STRING) {
            SCLogError!("hassh support is not enabled");
        }
        return -2;
    }
    return 0;
}

unsafe extern "C" fn ssh_hassh_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_SSH) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_SSH_HASSH_BUFFER_ID) < 0 {
        return -1;
    }
    /* try to enable Hassh */
    SCSshEnableHassh();

    /* Check if Hassh is disabled */
    if !SCSshHasshIsEnabled() {
        if !SCSigMatchSilentErrorEnabled(de, DETECT_SSH_HASSH) {
            SCLogError!("hassh support is not enabled");
        }
        return -2;
    }
    return 0;
}

unsafe extern "C" fn ssh_hassh_server_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_SSH) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_SSH_HASSH_SRV_BUFFER_ID) < 0 {
        return -1;
    }
    /* try to enable Hassh */
    SCSshEnableHassh();

    /* Check if Hassh is disabled */
    if !SCSshHasshIsEnabled() {
        if !SCSigMatchSilentErrorEnabled(de, DETECT_SSH_HASSH_SERVER) {
            SCLogError!("hassh support is not enabled");
        }
        return -2;
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
static mut G_SSH_HASSH_STR_BUFFER_ID: c_int = 0;
static mut G_SSH_HASSH_SRV_STR_BUFFER_ID: c_int = 0;
static mut G_SSH_HASSH_BUFFER_ID: c_int = 0;
static mut G_SSH_HASSH_SRV_BUFFER_ID: c_int = 0;

static mut DETECT_SSH_HASSH_STRING: u16 = 0;
static mut DETECT_SSH_HASSH_SERVER_STRING: u16 = 0;
static mut DETECT_SSH_HASSH: u16 = 0;
static mut DETECT_SSH_HASSH_SERVER: u16 = 0;

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

    let kw = SigTableElmtStickyBuffer {
        name: String::from("ssh.hassh.string"),
        desc: String::from("ssh.hassh.string sticky buffer"),
        url: String::from("/rules/ssh-keywords.html#hassh.string"),
        setup: ssh_hassh_string_setup,
    };
    DETECT_SSH_HASSH_STRING = helper_keyword_register_sticky_buffer(&kw);
    G_SSH_HASSH_STR_BUFFER_ID = SCDetectHelperBufferProgressMpmRegister(
        b"ssh.hassh.string\0".as_ptr() as *const libc::c_char,
        b"Ssh Client Key Exchange methods For ssh Clients\0".as_ptr() as *const libc::c_char,
        ALPROTO_SSH,
        STREAM_TOSERVER,
        Some(SCSshTxGetHasshString),
        SSHConnectionState::SshStateBannerDone as c_int,
    );
    SCDetectHelperKeywordAliasRegister(
        DETECT_SSH_HASSH_STRING,
        b"ssh-hassh-string\0".as_ptr() as *const libc::c_char,
    );

    let kw = SigTableElmtStickyBuffer {
        name: String::from("ssh.hassh.server.string"),
        desc: String::from("ssh.hassh.server.string sticky buffer"),
        url: String::from("/rules/ssh-keywords.html#ssh.hassh.server.string"),
        setup: ssh_hassh_server_string_setup,
    };
    DETECT_SSH_HASSH_SERVER_STRING = helper_keyword_register_sticky_buffer(&kw);
    G_SSH_HASSH_SRV_STR_BUFFER_ID = SCDetectHelperBufferProgressMpmRegister(
        b"ssh.hassh.server.string\0".as_ptr() as *const libc::c_char,
        b"Ssh Client Key Exchange methods For ssh Servers\0".as_ptr() as *const libc::c_char,
        ALPROTO_SSH,
        STREAM_TOCLIENT,
        Some(SCSshTxGetHasshString),
        SSHConnectionState::SshStateBannerDone as c_int,
    );
    SCDetectHelperKeywordAliasRegister(
        DETECT_SSH_HASSH_SERVER_STRING,
        b"ssh-hassh-server-string\0".as_ptr() as *const libc::c_char,
    );

    let kw = SigTableElmtStickyBuffer {
        name: String::from("ssh.hassh"),
        desc: String::from("ssh.hassh sticky buffer"),
        url: String::from("/rules/ssh-keywords.html#hassh"),
        setup: ssh_hassh_setup,
    };
    DETECT_SSH_HASSH = helper_keyword_register_sticky_buffer(&kw);
    G_SSH_HASSH_BUFFER_ID = SCDetectHelperBufferProgressMpmRegister(
        b"ssh.hassh\0".as_ptr() as *const libc::c_char,
        b"Ssh Client Fingerprinting For Ssh Clients\0".as_ptr() as *const libc::c_char,
        ALPROTO_SSH,
        STREAM_TOSERVER,
        Some(SCSshTxGetHassh),
        SSHConnectionState::SshStateBannerDone as c_int,
    );
    SCDetectHelperKeywordAliasRegister(
        DETECT_SSH_HASSH,
        b"ssh-hassh\0".as_ptr() as *const libc::c_char,
    );
    SCDetectRegisterBufferLowerMd5Callbacks(b"ssh.hassh\0".as_ptr() as *const libc::c_char);

    let kw = SigTableElmtStickyBuffer {
        name: String::from("ssh.hassh.server"),
        desc: String::from("ssh.hassh.server sticky buffer"),
        url: String::from("/rules/ssh-keywords.html#ssh.hassh.server"),
        setup: ssh_hassh_server_setup,
    };
    DETECT_SSH_HASSH_SERVER = helper_keyword_register_sticky_buffer(&kw);
    G_SSH_HASSH_SRV_BUFFER_ID = SCDetectHelperBufferProgressMpmRegister(
        b"ssh.hassh.server\0".as_ptr() as *const libc::c_char,
        b"Ssh Client Fingerprinting For Ssh Servers\0".as_ptr() as *const libc::c_char,
        ALPROTO_SSH,
        STREAM_TOCLIENT,
        Some(SCSshTxGetHassh),
        SSHConnectionState::SshStateBannerDone as c_int,
    );
    SCDetectHelperKeywordAliasRegister(
        DETECT_SSH_HASSH_SERVER,
        b"ssh-hassh-server\0".as_ptr() as *const libc::c_char,
    );
    SCDetectRegisterBufferLowerMd5Callbacks(b"ssh.hassh.server\0".as_ptr() as *const libc::c_char);
}
