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

// written by Giuseppe Longo <giuseppe@glongo.it>

use crate::detect::{
    DetectBufferSetActiveList, DetectHelperBufferMpmRegister, DetectHelperGetData,
    DetectHelperKeywordRegister, DetectSignatureSetAppProto, SCSigTableElmt, SIGMATCH_NOOPT,
};
use crate::direction::Direction;
use crate::sip::sip::{SIPTransaction, ALPROTO_SIP};
use std::os::raw::{c_int, c_void};
use std::ptr;

static mut G_SDP_SESSION_NAME_BUFFER_ID: c_int = 0;

unsafe extern "C" fn sdp_session_name_setup(
    de: *mut c_void, s: *mut c_void, _raw: *const std::os::raw::c_char,
) -> c_int {
    if DetectSignatureSetAppProto(s, ALPROTO_SIP) != 0 {
        return -1;
    }
    if DetectBufferSetActiveList(de, s, G_SDP_SESSION_NAME_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn sdp_session_name_get(
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
        sdp_session_name_get_data,
    );
}

unsafe extern "C" fn sdp_session_name_get_data(
    tx: *const c_void, direction: u8, buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, SIPTransaction);
    let sdp_message = match direction.into() {
        Direction::ToServer => tx.request.as_ref().and_then(|req| req.body.as_ref()),
        Direction::ToClient => tx.response.as_ref().and_then(|resp| resp.body.as_ref()),
    };
    if let Some(sdp) = sdp_message {
        let session_name = &sdp.session_name;
        if !session_name.is_empty() {
            *buffer = session_name.as_ptr();
            *buffer_len = session_name.len() as u32;
            return true;
        }
    }
    *buffer = ptr::null();
    *buffer_len = 0;
    false
}

#[no_mangle]
pub unsafe extern "C" fn ScDetectSdpRegister() {
    let kw = SCSigTableElmt {
        name: b"sdp.session_name\0".as_ptr() as *const libc::c_char,
        desc: b"sticky buffer to match on the SDP session name field\0".as_ptr()
            as *const libc::c_char,
        url: b"/rules/sdp-keywords.html#sdp-session-name\0".as_ptr() as *const libc::c_char,
        Setup: sdp_session_name_setup,
        flags: SIGMATCH_NOOPT,
        AppLayerTxMatch: None,
        Free: None,
    };
    let _ = DetectHelperKeywordRegister(&kw);
    G_SDP_SESSION_NAME_BUFFER_ID = DetectHelperBufferMpmRegister(
        b"sdp.session_name\0".as_ptr() as *const libc::c_char,
        b"sdp.session_name\0".as_ptr() as *const libc::c_char,
        ALPROTO_SIP,
        true,
        true,
        sdp_session_name_get,
    );
}
