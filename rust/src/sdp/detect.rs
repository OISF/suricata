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
    DetectHelperGetMultiData, DetectHelperKeywordRegister, DetectHelperMultiBufferMpmRegister,
    DetectSignatureSetAppProto, SCSigTableElmt, SIGMATCH_NOOPT,
};
use crate::direction::Direction;
use crate::sip::sip::{SIPTransaction, ALPROTO_SIP};
use std::os::raw::{c_int, c_void};
use std::ptr;

static mut G_SDP_ORIGIN_BUFFER_ID: c_int = 0;
static mut G_SDP_SESSION_NAME_BUFFER_ID: c_int = 0;
static mut G_SDP_SESSION_INFO_BUFFER_ID: c_int = 0;
static mut G_SDP_URI_BUFFER_ID: c_int = 0;
static mut G_SDP_EMAIL_BUFFER_ID: c_int = 0;
static mut G_SDP_PHONE_NUMBER_BUFFER_ID: c_int = 0;
static mut G_SDP_CONNECTION_DATA_BUFFER_ID: c_int = 0;
static mut G_SDP_BANDWIDTH_BUFFER_ID: c_int = 0;
static mut G_SDP_TIME_BUFFER_ID: c_int = 0;
static mut G_SDP_REPEAT_TIME_BUFFER_ID: c_int = 0;
static mut G_SDP_TIMEZONE_BUFFER_ID: c_int = 0;
static mut G_SDP_ENCRYPTION_KEY_BUFFER_ID: c_int = 0;
static mut G_SDP_ATTRIBUTE_BUFFER_ID: c_int = 0;
static mut G_SDP_MEDIA_DESC_MEDIA_BUFFER_ID: c_int = 0;
static mut G_SDP_MEDIA_DESC_SESSION_INFO_BUFFER_ID: c_int = 0;

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

unsafe extern "C" fn sdp_session_info_setup(
    de: *mut c_void, s: *mut c_void, _raw: *const std::os::raw::c_char,
) -> c_int {
    if DetectSignatureSetAppProto(s, ALPROTO_SIP) != 0 {
        return -1;
    }
    if DetectBufferSetActiveList(de, s, G_SDP_SESSION_INFO_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn sdp_session_info_get(
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
        sdp_session_info_get_data,
    );
}

unsafe extern "C" fn sdp_session_info_get_data(
    tx: *const c_void, direction: u8, buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, SIPTransaction);
    let sdp_message = match direction.into() {
        Direction::ToServer => tx.request.as_ref().and_then(|req| req.body.as_ref()),
        Direction::ToClient => tx.response.as_ref().and_then(|resp| resp.body.as_ref()),
    };
    if let Some(sdp) = sdp_message {
        if let Some(ref s) = sdp.session_info {
            *buffer = s.as_ptr();
            *buffer_len = s.len() as u32;
            return true;
        }
    }
    *buffer = ptr::null();
    *buffer_len = 0;
    false
}

unsafe extern "C" fn sdp_origin_setup(
    de: *mut c_void, s: *mut c_void, _raw: *const std::os::raw::c_char,
) -> c_int {
    if DetectSignatureSetAppProto(s, ALPROTO_SIP) != 0 {
        return -1;
    }
    if DetectBufferSetActiveList(de, s, G_SDP_ORIGIN_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn sdp_origin_get(
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
        sdp_origin_get_data,
    );
}

unsafe extern "C" fn sdp_origin_get_data(
    tx: *const c_void, direction: u8, buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, SIPTransaction);
    let sdp_option = match direction.into() {
        Direction::ToServer => tx.request.as_ref().and_then(|req| req.body.as_ref()),
        Direction::ToClient => tx.response.as_ref().and_then(|resp| resp.body.as_ref()),
    };
    if let Some(sdp) = sdp_option {
        let origin = &sdp.origin;
        if !origin.is_empty() {
            *buffer = origin.as_ptr();
            *buffer_len = origin.len() as u32;
            return true;
        }
    }
    *buffer = ptr::null();
    *buffer_len = 0;
    false
}

unsafe extern "C" fn sdp_uri_setup(
    de: *mut c_void, s: *mut c_void, _raw: *const std::os::raw::c_char,
) -> c_int {
    if DetectSignatureSetAppProto(s, ALPROTO_SIP) != 0 {
        return -1;
    }
    if DetectBufferSetActiveList(de, s, G_SDP_URI_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn sdp_uri_get(
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
        sdp_uri_get_data,
    );
}

unsafe extern "C" fn sdp_uri_get_data(
    tx: *const c_void, direction: u8, buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, SIPTransaction);
    let sdp_option = match direction.into() {
        Direction::ToServer => tx.request.as_ref().and_then(|req| req.body.as_ref()),
        Direction::ToClient => tx.response.as_ref().and_then(|resp| resp.body.as_ref()),
    };
    if let Some(sdp) = sdp_option {
        if let Some(ref u) = sdp.uri {
            *buffer = u.as_ptr();
            *buffer_len = u.len() as u32;
            return true;
        }
    }
    *buffer = ptr::null();
    *buffer_len = 0;
    false
}

unsafe extern "C" fn sdp_email_setup(
    de: *mut c_void, s: *mut c_void, _raw: *const std::os::raw::c_char,
) -> c_int {
    if DetectSignatureSetAppProto(s, ALPROTO_SIP) != 0 {
        return -1;
    }
    if DetectBufferSetActiveList(de, s, G_SDP_EMAIL_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn sdp_email_get(
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
        sdp_email_get_data,
    );
}

unsafe extern "C" fn sdp_email_get_data(
    tx: *const c_void, direction: u8, buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, SIPTransaction);
    let sdp_option = match direction.into() {
        Direction::ToServer => tx.request.as_ref().and_then(|req| req.body.as_ref()),
        Direction::ToClient => tx.response.as_ref().and_then(|resp| resp.body.as_ref()),
    };
    if let Some(sdp) = sdp_option {
        if let Some(ref e) = sdp.email {
            *buffer = e.as_ptr();
            *buffer_len = e.len() as u32;
            return true;
        }
    }
    *buffer = ptr::null();
    *buffer_len = 0;
    false
}

unsafe extern "C" fn sdp_phone_number_setup(
    de: *mut c_void, s: *mut c_void, _raw: *const std::os::raw::c_char,
) -> c_int {
    if DetectSignatureSetAppProto(s, ALPROTO_SIP) != 0 {
        return -1;
    }
    if DetectBufferSetActiveList(de, s, G_SDP_PHONE_NUMBER_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn sdp_phone_number_get(
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
        sdp_phone_number_get_data,
    );
}

unsafe extern "C" fn sdp_phone_number_get_data(
    tx: *const c_void, direction: u8, buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, SIPTransaction);
    let sdp_option = match direction.into() {
        Direction::ToServer => tx.request.as_ref().and_then(|req| req.body.as_ref()),
        Direction::ToClient => tx.response.as_ref().and_then(|resp| resp.body.as_ref()),
    };
    if let Some(sdp) = sdp_option {
        if let Some(ref p) = sdp.phone_number {
            *buffer = p.as_ptr();
            *buffer_len = p.len() as u32;
            return true;
        }
    }
    *buffer = ptr::null();
    *buffer_len = 0;
    false
}

unsafe extern "C" fn sdp_conn_data_setup(
    de: *mut c_void, s: *mut c_void, _raw: *const std::os::raw::c_char,
) -> c_int {
    if DetectSignatureSetAppProto(s, ALPROTO_SIP) != 0 {
        return -1;
    }
    if DetectBufferSetActiveList(de, s, G_SDP_CONNECTION_DATA_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn sdp_conn_data_get(
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
        sdp_conn_data_get_data,
    );
}

unsafe extern "C" fn sdp_conn_data_get_data(
    tx: *const c_void, direction: u8, buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, SIPTransaction);
    let sdp_option = match direction.into() {
        Direction::ToServer => tx.request.as_ref().and_then(|req| req.body.as_ref()),
        Direction::ToClient => tx.response.as_ref().and_then(|resp| resp.body.as_ref()),
    };
    if let Some(sdp) = sdp_option {
        if let Some(ref c) = sdp.connection_data {
            *buffer = c.as_ptr();
            *buffer_len = c.len() as u32;
            return true;
        }
    }
    *buffer = ptr::null();
    *buffer_len = 0;
    false
}

unsafe extern "C" fn sdp_bandwidth_setup(
    de: *mut c_void, s: *mut c_void, _raw: *const std::os::raw::c_char,
) -> c_int {
    if DetectSignatureSetAppProto(s, ALPROTO_SIP) != 0 {
        return -1;
    }
    if DetectBufferSetActiveList(de, s, G_SDP_BANDWIDTH_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn sdp_bandwidth_get(
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
        sip_bandwidth_get_data,
    );
}

unsafe extern "C" fn sip_bandwidth_get_data(
    tx: *const c_void, flow_flags: u8, local_id: u32, buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, SIPTransaction);
    let direction = flow_flags.into();
    let sdp_option = match direction {
        Direction::ToServer => tx.request.as_ref().and_then(|req| req.body.as_ref()),
        Direction::ToClient => tx.response.as_ref().and_then(|resp| resp.body.as_ref()),
    };
    if let Some(sdp) = sdp_option {
        if let Some(ref b) = sdp.bandwidths {
            if (local_id as usize) < b.len() {
                let val = &b[local_id as usize];
                *buffer = val.as_ptr();
                *buffer_len = val.len() as u32;
                return true;
            }
        }
    }
    *buffer = ptr::null();
    *buffer_len = 0;
    false
}

unsafe extern "C" fn sdp_time_setup(
    de: *mut c_void, s: *mut c_void, _raw: *const std::os::raw::c_char,
) -> c_int {
    if DetectSignatureSetAppProto(s, ALPROTO_SIP) != 0 {
        return -1;
    }
    if DetectBufferSetActiveList(de, s, G_SDP_TIME_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn sdp_time_get(
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
        sdp_time_get_data,
    );
}

unsafe extern "C" fn sdp_time_get_data(
    tx: *const c_void, flow_flags: u8, local_id: u32, buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, SIPTransaction);
    let direction = flow_flags.into();
    let sdp_option = match direction {
        Direction::ToServer => tx.request.as_ref().and_then(|req| req.body.as_ref()),
        Direction::ToClient => tx.response.as_ref().and_then(|resp| resp.body.as_ref()),
    };
    if let Some(sdp) = sdp_option {
        if (local_id as usize) < sdp.time_description.len() {
            let time = &sdp.time_description[local_id as usize].time;
            *buffer = time.as_ptr();
            *buffer_len = time.len() as u32;
            return true;
        }
    }
    *buffer = ptr::null();
    *buffer_len = 0;
    false
}

unsafe extern "C" fn sdp_repeat_time_setup(
    de: *mut c_void, s: *mut c_void, _raw: *const std::os::raw::c_char,
) -> c_int {
    if DetectSignatureSetAppProto(s, ALPROTO_SIP) != 0 {
        return -1;
    }
    if DetectBufferSetActiveList(de, s, G_SDP_REPEAT_TIME_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn sdp_repeat_time_get(
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
        sdp_repeat_time_get_data,
    );
}

unsafe extern "C" fn sdp_repeat_time_get_data(
    tx: *const c_void, flow_flags: u8, local_id: u32, buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, SIPTransaction);
    let direction = flow_flags.into();
    let sdp_option = match direction {
        Direction::ToServer => tx.request.as_ref().and_then(|req| req.body.as_ref()),
        Direction::ToClient => tx.response.as_ref().and_then(|resp| resp.body.as_ref()),
    };
    if let Some(sdp) = sdp_option {
        if (local_id as usize) < sdp.time_description.len() {
            let time_desc = &sdp.time_description[local_id as usize];
            if let Some(ref r) = time_desc.repeat_time {
                *buffer = r.as_ptr();
                *buffer_len = r.len() as u32;
                return true;
            }
        }
    }
    *buffer = ptr::null();
    *buffer_len = 0;
    false
}

unsafe extern "C" fn sdp_timezone_setup(
    de: *mut c_void, s: *mut c_void, _raw: *const std::os::raw::c_char,
) -> c_int {
    if DetectSignatureSetAppProto(s, ALPROTO_SIP) != 0 {
        return -1;
    }
    if DetectBufferSetActiveList(de, s, G_SDP_TIMEZONE_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn sdp_timezone_get(
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
        sdp_timezone_get_data,
    );
}

unsafe extern "C" fn sdp_timezone_get_data(
    tx: *const c_void, direction: u8, buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, SIPTransaction);
    let sdp_option = match direction.into() {
        Direction::ToServer => tx.request.as_ref().and_then(|req| req.body.as_ref()),
        Direction::ToClient => tx.response.as_ref().and_then(|resp| resp.body.as_ref()),
    };
    if let Some(sdp) = sdp_option {
        if let Some(z) = &sdp.time_zone {
            *buffer = z.as_ptr();
            *buffer_len = z.len() as u32;
            return true;
        }
    }
    *buffer = ptr::null();
    *buffer_len = 0;
    false
}

unsafe extern "C" fn sdp_encryption_key_setup(
    de: *mut c_void, s: *mut c_void, _raw: *const std::os::raw::c_char,
) -> c_int {
    if DetectSignatureSetAppProto(s, ALPROTO_SIP) != 0 {
        return -1;
    }
    if DetectBufferSetActiveList(de, s, G_SDP_ENCRYPTION_KEY_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn sdp_encryption_key_get(
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
        sdp_encryption_key_get_data,
    );
}

unsafe extern "C" fn sdp_encryption_key_get_data(
    tx: *const c_void, direction: u8, buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, SIPTransaction);
    let sdp_option = match direction.into() {
        Direction::ToServer => tx.request.as_ref().and_then(|req| req.body.as_ref()),
        Direction::ToClient => tx.response.as_ref().and_then(|resp| resp.body.as_ref()),
    };
    if let Some(sdp) = sdp_option {
        if let Some(k) = &sdp.encryption_key {
            *buffer = k.as_ptr();
            *buffer_len = k.len() as u32;
            return true;
        }
    }
    *buffer = ptr::null();
    *buffer_len = 0;
    false
}

unsafe extern "C" fn sdp_attribute_setup(
    de: *mut c_void, s: *mut c_void, _raw: *const std::os::raw::c_char,
) -> c_int {
    if DetectSignatureSetAppProto(s, ALPROTO_SIP) != 0 {
        return -1;
    }
    if DetectBufferSetActiveList(de, s, G_SDP_ATTRIBUTE_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn sdp_attribute_get(
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
        sip_attribute_get_data,
    );
}

unsafe extern "C" fn sip_attribute_get_data(
    tx: *const c_void, flow_flags: u8, local_id: u32, buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, SIPTransaction);
    let direction = flow_flags.into();
    let sdp_option = match direction {
        Direction::ToServer => tx.request.as_ref().and_then(|req| req.body.as_ref()),
        Direction::ToClient => tx.response.as_ref().and_then(|resp| resp.body.as_ref()),
    };
    if let Some(sdp) = sdp_option {
        if let Some(ref a) = sdp.attributes {
            if (local_id as usize) < a.len() {
                let val = &a[local_id as usize];
                *buffer = val.as_ptr();
                *buffer_len = val.len() as u32;
                return true;
            }
        }
    }
    *buffer = ptr::null();
    *buffer_len = 0;
    false
}

unsafe extern "C" fn sdp_media_desc_media_setup(
    de: *mut c_void, s: *mut c_void, _raw: *const std::os::raw::c_char,
) -> c_int {
    if DetectSignatureSetAppProto(s, ALPROTO_SIP) != 0 {
        return -1;
    }
    if DetectBufferSetActiveList(de, s, G_SDP_MEDIA_DESC_MEDIA_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn sdp_media_desc_media_get(
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
        sip_media_desc_media_get_data,
    );
}

unsafe extern "C" fn sip_media_desc_media_get_data(
    tx: *const c_void, flow_flags: u8, local_id: u32, buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, SIPTransaction);
    let direction = flow_flags.into();
    let sdp_option = match direction {
        Direction::ToServer => tx.request.as_ref().and_then(|req| req.body.as_ref()),
        Direction::ToClient => tx.response.as_ref().and_then(|resp| resp.body.as_ref()),
    };
    if let Some(sdp) = sdp_option {
        if let Some(ref m) = sdp.media_description {
            if (local_id as usize) < m.len() {
                let val = &m[local_id as usize].media;
                *buffer = val.as_ptr();
                *buffer_len = val.len() as u32;
                return true;
            }
        }
    }
    *buffer = ptr::null();
    *buffer_len = 0;
    false
}

unsafe extern "C" fn sdp_media_desc_session_info_setup(
    de: *mut c_void, s: *mut c_void, _raw: *const std::os::raw::c_char,
) -> c_int {
    if DetectSignatureSetAppProto(s, ALPROTO_SIP) != 0 {
        return -1;
    }
    if DetectBufferSetActiveList(de, s, G_SDP_MEDIA_DESC_SESSION_INFO_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn sdp_media_desc_session_info_get(
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
        sip_media_desc_session_info_get_data,
    );
}

unsafe extern "C" fn sip_media_desc_session_info_get_data(
    tx: *const c_void, flow_flags: u8, local_id: u32, buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, SIPTransaction);
    let direction = flow_flags.into();
    let sdp_option = match direction {
        Direction::ToServer => tx.request.as_ref().and_then(|req| req.body.as_ref()),
        Direction::ToClient => tx.response.as_ref().and_then(|resp| resp.body.as_ref()),
    };
    if let Some(sdp) = sdp_option {
        if let Some(ref m) = sdp.media_description {
            if (local_id as usize) < m.len() {
                if let Some(i) = &m[local_id as usize].session_info {
                    *buffer = i.as_ptr();
                    *buffer_len = i.len() as u32;
                    return true;
                }
            }
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
    let kw = SCSigTableElmt {
        name: b"sdp.session_info\0".as_ptr() as *const libc::c_char,
        desc: b"sticky buffer to match on the SDP session info field\0".as_ptr()
            as *const libc::c_char,
        url: b"/rules/sdp-keywords.html#sdp-session-info\0".as_ptr() as *const libc::c_char,
        Setup: sdp_session_info_setup,
        flags: SIGMATCH_NOOPT,
        AppLayerTxMatch: None,
        Free: None,
    };
    let _ = DetectHelperKeywordRegister(&kw);
    G_SDP_SESSION_INFO_BUFFER_ID = DetectHelperBufferMpmRegister(
        b"sdp.session_info\0".as_ptr() as *const libc::c_char,
        b"sdp.session_info\0".as_ptr() as *const libc::c_char,
        ALPROTO_SIP,
        true,
        true,
        sdp_session_info_get,
    );
    let kw = SCSigTableElmt {
        name: b"sdp.origin\0".as_ptr() as *const libc::c_char,
        desc: b"sticky buffer to match on the SDP origin field\0".as_ptr() as *const libc::c_char,
        url: b"/rules/sdp-keywords.html#sdp-origin\0".as_ptr() as *const libc::c_char,
        Setup: sdp_origin_setup,
        flags: SIGMATCH_NOOPT,
        AppLayerTxMatch: None,
        Free: None,
    };
    let _ = DetectHelperKeywordRegister(&kw);
    G_SDP_ORIGIN_BUFFER_ID = DetectHelperBufferMpmRegister(
        b"sdp.origin\0".as_ptr() as *const libc::c_char,
        b"sdp.origin\0".as_ptr() as *const libc::c_char,
        ALPROTO_SIP,
        true,
        true,
        sdp_origin_get,
    );
    let kw = SCSigTableElmt {
        name: b"sdp.uri\0".as_ptr() as *const libc::c_char,
        desc: b"sticky buffer to match on the SDP uri field\0".as_ptr() as *const libc::c_char,
        url: b"/rules/sdp-keywords.html#sdp-uri\0".as_ptr() as *const libc::c_char,
        Setup: sdp_uri_setup,
        flags: SIGMATCH_NOOPT,
        AppLayerTxMatch: None,
        Free: None,
    };
    let _ = DetectHelperKeywordRegister(&kw);
    G_SDP_URI_BUFFER_ID = DetectHelperBufferMpmRegister(
        b"sdp.uri\0".as_ptr() as *const libc::c_char,
        b"sdp.uri\0".as_ptr() as *const libc::c_char,
        ALPROTO_SIP,
        true,
        true,
        sdp_uri_get,
    );
    let kw = SCSigTableElmt {
        name: b"sdp.email\0".as_ptr() as *const libc::c_char,
        desc: b"sticky buffer to match on the SDP email field\0".as_ptr() as *const libc::c_char,
        url: b"/rules/sdp-keywords.html#sdp-email\0".as_ptr() as *const libc::c_char,
        Setup: sdp_email_setup,
        flags: SIGMATCH_NOOPT,
        AppLayerTxMatch: None,
        Free: None,
    };
    let _ = DetectHelperKeywordRegister(&kw);
    G_SDP_EMAIL_BUFFER_ID = DetectHelperBufferMpmRegister(
        b"sdp.email\0".as_ptr() as *const libc::c_char,
        b"sdp.email\0".as_ptr() as *const libc::c_char,
        ALPROTO_SIP,
        true,
        true,
        sdp_email_get,
    );
    let kw = SCSigTableElmt {
        name: b"sdp.phone_number\0".as_ptr() as *const libc::c_char,
        desc: b"sticky buffer to match on the SDP phone number field\0".as_ptr()
            as *const libc::c_char,
        url: b"/rules/sdp-keywords.html#sdp-phone-number\0".as_ptr() as *const libc::c_char,
        Setup: sdp_phone_number_setup,
        flags: SIGMATCH_NOOPT,
        AppLayerTxMatch: None,
        Free: None,
    };
    let _ = DetectHelperKeywordRegister(&kw);
    G_SDP_PHONE_NUMBER_BUFFER_ID = DetectHelperBufferMpmRegister(
        b"sdp.phone_number\0".as_ptr() as *const libc::c_char,
        b"sdp.phone_number\0".as_ptr() as *const libc::c_char,
        ALPROTO_SIP,
        true,
        true,
        sdp_phone_number_get,
    );
    let kw = SCSigTableElmt {
        name: b"sdp.connection_data\0".as_ptr() as *const libc::c_char,
        desc: b"sticky buffer to match on the SDP connection data field\0".as_ptr()
            as *const libc::c_char,
        url: b"/rules/sdp-keywords.html#sdp-connection-data\0".as_ptr() as *const libc::c_char,
        Setup: sdp_conn_data_setup,
        flags: SIGMATCH_NOOPT,
        AppLayerTxMatch: None,
        Free: None,
    };
    let _ = DetectHelperKeywordRegister(&kw);
    G_SDP_CONNECTION_DATA_BUFFER_ID = DetectHelperBufferMpmRegister(
        b"sdp.connection_data\0".as_ptr() as *const libc::c_char,
        b"sdp.connection_data\0".as_ptr() as *const libc::c_char,
        ALPROTO_SIP,
        true,
        true,
        sdp_conn_data_get,
    );
    let kw = SCSigTableElmt {
        name: b"sdp.bandwidth\0".as_ptr() as *const libc::c_char,
        desc: b"sticky buffer to match on the SDP bandwidth field\0".as_ptr()
            as *const libc::c_char,
        url: b"/rules/sdp-keywords.html#sdp-bandwidth\0".as_ptr() as *const libc::c_char,
        Setup: sdp_bandwidth_setup,
        flags: SIGMATCH_NOOPT,
        AppLayerTxMatch: None,
        Free: None,
    };
    let _ = DetectHelperKeywordRegister(&kw);
    G_SDP_BANDWIDTH_BUFFER_ID = DetectHelperMultiBufferMpmRegister(
        b"sdp.bandwidth\0".as_ptr() as *const libc::c_char,
        b"sdp.bandwidth\0".as_ptr() as *const libc::c_char,
        ALPROTO_SIP,
        true,
        true,
        sdp_bandwidth_get,
    );
    let kw = SCSigTableElmt {
        name: b"sdp.time\0".as_ptr() as *const libc::c_char,
        desc: b"sticky buffer to match on the SDP time field\0".as_ptr() as *const libc::c_char,
        url: b"/rules/sdp-keywords.html#time\0".as_ptr() as *const libc::c_char,
        Setup: sdp_time_setup,
        flags: SIGMATCH_NOOPT,
        AppLayerTxMatch: None,
        Free: None,
    };
    let _ = DetectHelperKeywordRegister(&kw);
    G_SDP_TIME_BUFFER_ID = DetectHelperMultiBufferMpmRegister(
        b"sdp.time\0".as_ptr() as *const libc::c_char,
        b"sdp.time\0".as_ptr() as *const libc::c_char,
        ALPROTO_SIP,
        true,
        true,
        sdp_time_get,
    );
    let kw = SCSigTableElmt {
        name: b"sdp.repeat_time\0".as_ptr() as *const libc::c_char,
        desc: b"sticky buffer to match on the SDP repeat time field\0".as_ptr()
            as *const libc::c_char,
        url: b"/rules/sdp-keywords.html#repeat-time\0".as_ptr() as *const libc::c_char,
        Setup: sdp_repeat_time_setup,
        flags: SIGMATCH_NOOPT,
        AppLayerTxMatch: None,
        Free: None,
    };
    let _ = DetectHelperKeywordRegister(&kw);
    G_SDP_REPEAT_TIME_BUFFER_ID = DetectHelperMultiBufferMpmRegister(
        b"sdp.repeat_time\0".as_ptr() as *const libc::c_char,
        b"sdp.repeat_time\0".as_ptr() as *const libc::c_char,
        ALPROTO_SIP,
        true,
        true,
        sdp_repeat_time_get,
    );
    let kw = SCSigTableElmt {
        name: b"sdp.timezone\0".as_ptr() as *const libc::c_char,
        desc: b"sticky buffer to match on the SDP timezone field\0".as_ptr() as *const libc::c_char,
        url: b"/rules/sdp-keywords.html#timezone\0".as_ptr() as *const libc::c_char,
        Setup: sdp_timezone_setup,
        flags: SIGMATCH_NOOPT,
        AppLayerTxMatch: None,
        Free: None,
    };
    let _ = DetectHelperKeywordRegister(&kw);
    G_SDP_TIMEZONE_BUFFER_ID = DetectHelperBufferMpmRegister(
        b"sdp.timezone\0".as_ptr() as *const libc::c_char,
        b"sdp.timezone\0".as_ptr() as *const libc::c_char,
        ALPROTO_SIP,
        true,
        true,
        sdp_timezone_get,
    );
    let kw = SCSigTableElmt {
        name: b"sdp.encryption_key\0".as_ptr() as *const libc::c_char,
        desc: b"sticky buffer to match on the SDP encryption key field\0".as_ptr()
            as *const libc::c_char,
        url: b"/rules/sdp-keywords.html#encryption-key\0".as_ptr() as *const libc::c_char,
        Setup: sdp_encryption_key_setup,
        flags: SIGMATCH_NOOPT,
        AppLayerTxMatch: None,
        Free: None,
    };
    let _ = DetectHelperKeywordRegister(&kw);
    G_SDP_ENCRYPTION_KEY_BUFFER_ID = DetectHelperBufferMpmRegister(
        b"sdp.encryption_key\0".as_ptr() as *const libc::c_char,
        b"sdp.encription_key\0".as_ptr() as *const libc::c_char,
        ALPROTO_SIP,
        true,
        true,
        sdp_encryption_key_get,
    );
    let kw = SCSigTableElmt {
        name: b"sdp.attribute\0".as_ptr() as *const libc::c_char,
        desc: b"sticky buffer to match on the SDP attribute field\0".as_ptr()
            as *const libc::c_char,
        url: b"/rules/sdp-keywords.html#sdp-attribute\0".as_ptr() as *const libc::c_char,
        Setup: sdp_attribute_setup,
        flags: SIGMATCH_NOOPT,
        AppLayerTxMatch: None,
        Free: None,
    };
    let _ = DetectHelperKeywordRegister(&kw);
    G_SDP_ATTRIBUTE_BUFFER_ID = DetectHelperMultiBufferMpmRegister(
        b"sdp.attribute\0".as_ptr() as *const libc::c_char,
        b"sdp.attribute\0".as_ptr() as *const libc::c_char,
        ALPROTO_SIP,
        true,
        true,
        sdp_attribute_get,
    );
    let kw = SCSigTableElmt {
        name: b"sdp.media.media\0".as_ptr() as *const libc::c_char,
        desc: b"sticky buffer to match on the SDP media subfield of the media_description field\0"
            .as_ptr() as *const libc::c_char,
        url: b"/rules/sdp-keywords.html#media-description-media\0".as_ptr() as *const libc::c_char,
        Setup: sdp_media_desc_media_setup,
        flags: SIGMATCH_NOOPT,
        AppLayerTxMatch: None,
        Free: None,
    };
    let _ = DetectHelperKeywordRegister(&kw);
    G_SDP_MEDIA_DESC_MEDIA_BUFFER_ID = DetectHelperMultiBufferMpmRegister(
        b"sdp.media.media\0".as_ptr() as *const libc::c_char,
        b"sdp.media.media\0".as_ptr() as *const libc::c_char,
        ALPROTO_SIP,
        true,
        true,
        sdp_media_desc_media_get,
    );
    let kw = SCSigTableElmt {
        name: b"sdp.media.media_info\0".as_ptr() as *const libc::c_char,
        desc: b"sticky buffer to match on the SDP session info subfield of the media_description field\0".as_ptr()
            as *const libc::c_char,
        url: b"/rules/sdp-keywords.html#sdp-media-description-session-info\0".as_ptr() as *const libc::c_char,
        Setup: sdp_media_desc_session_info_setup,
        flags: SIGMATCH_NOOPT,
        AppLayerTxMatch: None,
        Free: None,
    };
    let _ = DetectHelperKeywordRegister(&kw);
    G_SDP_MEDIA_DESC_SESSION_INFO_BUFFER_ID = DetectHelperMultiBufferMpmRegister(
        b"sdp.media.media_info\0".as_ptr() as *const libc::c_char,
        b"sdp.media.media_info\0".as_ptr() as *const libc::c_char,
        ALPROTO_SIP,
        true,
        true,
        sdp_media_desc_session_info_get,
    );
}
