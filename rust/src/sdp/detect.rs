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

use crate::core::{STREAM_TOCLIENT, STREAM_TOSERVER};
use crate::detect::{
    helper_keyword_register_multi_buffer, helper_keyword_register_sticky_buffer,
    SigTableElmtStickyBuffer,
};
use crate::direction::Direction;
use crate::sip::sip::{SIPTransaction, ALPROTO_SIP};
use std::os::raw::{c_int, c_void};
use std::ptr;
use suricata_sys::sys::{
    DetectEngineCtx, DetectEngineThreadCtx, SCDetectBufferSetActiveList,
    SCDetectHelperBufferMpmRegister, SCDetectHelperMultiBufferMpmRegister,
    SCDetectSignatureSetAppProto, Signature,
};

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
static mut G_SDP_MEDIA_DESC_CONNECTION_DATA_BUFFER_ID: c_int = 0;
static mut G_SDP_MEDIA_DESC_ENCRYPTION_KEY_BUFFER_ID: c_int = 0;

unsafe extern "C" fn sdp_session_name_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_SIP) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_SDP_SESSION_NAME_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn sdp_session_name_get(
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
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_SIP) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_SDP_SESSION_INFO_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn sdp_session_info_get(
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
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_SIP) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_SDP_ORIGIN_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn sdp_origin_get(
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
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_SIP) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_SDP_URI_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn sdp_uri_get(
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
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_SIP) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_SDP_EMAIL_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn sdp_email_get(
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
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_SIP) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_SDP_PHONE_NUMBER_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn sdp_phone_number_get(
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
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_SIP) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_SDP_CONNECTION_DATA_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn sdp_conn_data_get(
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
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_SIP) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_SDP_BANDWIDTH_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn sip_bandwidth_get_data(
    _de: *mut DetectEngineThreadCtx, tx: *const c_void, flow_flags: u8, local_id: u32,
    buffer: *mut *const u8, buffer_len: *mut u32,
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
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_SIP) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_SDP_TIME_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn sdp_time_get_data(
    _de: *mut DetectEngineThreadCtx, tx: *const c_void, flow_flags: u8, local_id: u32,
    buffer: *mut *const u8, buffer_len: *mut u32,
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
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_SIP) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_SDP_REPEAT_TIME_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn sdp_repeat_time_get_data(
    _de: *mut DetectEngineThreadCtx, tx: *const c_void, flow_flags: u8, local_id: u32,
    buffer: *mut *const u8, buffer_len: *mut u32,
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
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_SIP) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_SDP_TIMEZONE_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn sdp_timezone_get(
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
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_SIP) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_SDP_ENCRYPTION_KEY_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn sdp_encryption_key_get(
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
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_SIP) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_SDP_ATTRIBUTE_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn sip_attribute_get_data(
    _de: *mut DetectEngineThreadCtx, tx: *const c_void, flow_flags: u8, local_id: u32,
    buffer: *mut *const u8, buffer_len: *mut u32,
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
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_SIP) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_SDP_MEDIA_DESC_MEDIA_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn sip_media_desc_media_get_data(
    _de: *mut DetectEngineThreadCtx, tx: *const c_void, flow_flags: u8, local_id: u32,
    buffer: *mut *const u8, buffer_len: *mut u32,
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
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_SIP) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_SDP_MEDIA_DESC_SESSION_INFO_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn sip_media_desc_session_info_get_data(
    _de: *mut DetectEngineThreadCtx, tx: *const c_void, flow_flags: u8, local_id: u32,
    buffer: *mut *const u8, buffer_len: *mut u32,
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

unsafe extern "C" fn sdp_media_desc_connection_data_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_SIP) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_SDP_MEDIA_DESC_CONNECTION_DATA_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn sip_media_desc_connection_data_get_data(
    _de: *mut DetectEngineThreadCtx, tx: *const c_void, flow_flags: u8, local_id: u32,
    buffer: *mut *const u8, buffer_len: *mut u32,
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
                if let Some(c) = &m[local_id as usize].connection_data {
                    *buffer = c.as_ptr();
                    *buffer_len = c.len() as u32;
                    return true;
                }
            }
        }
    }
    *buffer = ptr::null();
    *buffer_len = 0;
    false
}

unsafe extern "C" fn sdp_media_desc_encryption_key_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_SIP) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_SDP_MEDIA_DESC_ENCRYPTION_KEY_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn sip_media_desc_encryption_key_get_data(
    _de: *mut DetectEngineThreadCtx, tx: *const c_void, flow_flags: u8, local_id: u32,
    buffer: *mut *const u8, buffer_len: *mut u32,
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
                if let Some(k) = &m[local_id as usize].encryption_key {
                    *buffer = k.as_ptr();
                    *buffer_len = k.len() as u32;
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
pub unsafe extern "C" fn SCDetectSdpRegister() {
    let kw = SigTableElmtStickyBuffer {
        name: String::from("sdp.session_name"),
        desc: String::from("sticky buffer to match on the SDP session name field"),
        url: String::from("/rules/sdp-keywords.html#sdp-session-name"),
        setup: sdp_session_name_setup,
    };
    let _ = helper_keyword_register_sticky_buffer(&kw);
    G_SDP_SESSION_NAME_BUFFER_ID = SCDetectHelperBufferMpmRegister(
        b"sdp.session_name\0".as_ptr() as *const libc::c_char,
        b"sdp.session_name\0".as_ptr() as *const libc::c_char,
        ALPROTO_SIP,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        Some(sdp_session_name_get),
    );
    let kw = SigTableElmtStickyBuffer {
        name: String::from("sdp.session_info"),
        desc: String::from("sticky buffer to match on the SDP session info field"),
        url: String::from("/rules/sdp-keywords.html#sdp-session-info"),
        setup: sdp_session_info_setup,
    };
    let _ = helper_keyword_register_sticky_buffer(&kw);
    G_SDP_SESSION_INFO_BUFFER_ID = SCDetectHelperBufferMpmRegister(
        b"sdp.session_info\0".as_ptr() as *const libc::c_char,
        b"sdp.session_info\0".as_ptr() as *const libc::c_char,
        ALPROTO_SIP,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        Some(sdp_session_info_get),
    );
    let kw = SigTableElmtStickyBuffer {
        name: String::from("sdp.origin"),
        desc: String::from("sticky buffer to match on the SDP origin field"),
        url: String::from("/rules/sdp-keywords.html#sdp-origin"),
        setup: sdp_origin_setup,
    };
    let _ = helper_keyword_register_sticky_buffer(&kw);
    G_SDP_ORIGIN_BUFFER_ID = SCDetectHelperBufferMpmRegister(
        b"sdp.origin\0".as_ptr() as *const libc::c_char,
        b"sdp.origin\0".as_ptr() as *const libc::c_char,
        ALPROTO_SIP,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        Some(sdp_origin_get),
    );
    let kw = SigTableElmtStickyBuffer {
        name: String::from("sdp.uri"),
        desc: String::from("sticky buffer to match on the SDP uri field"),
        url: String::from("/rules/sdp-keywords.html#sdp-uri"),
        setup: sdp_uri_setup,
    };
    let _ = helper_keyword_register_sticky_buffer(&kw);
    G_SDP_URI_BUFFER_ID = SCDetectHelperBufferMpmRegister(
        b"sdp.uri\0".as_ptr() as *const libc::c_char,
        b"sdp.uri\0".as_ptr() as *const libc::c_char,
        ALPROTO_SIP,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        Some(sdp_uri_get),
    );
    let kw = SigTableElmtStickyBuffer {
        name: String::from("sdp.email"),
        desc: String::from("sticky buffer to match on the SDP email field"),
        url: String::from("/rules/sdp-keywords.html#sdp-email"),
        setup: sdp_email_setup,
    };
    let _ = helper_keyword_register_sticky_buffer(&kw);
    G_SDP_EMAIL_BUFFER_ID = SCDetectHelperBufferMpmRegister(
        b"sdp.email\0".as_ptr() as *const libc::c_char,
        b"sdp.email\0".as_ptr() as *const libc::c_char,
        ALPROTO_SIP,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        Some(sdp_email_get),
    );
    let kw = SigTableElmtStickyBuffer {
        name: String::from("sdp.phone_number"),
        desc: String::from("sticky buffer to match on the SDP phone number field"),
        url: String::from("/rules/sdp-keywords.html#sdp-phone-number"),
        setup: sdp_phone_number_setup,
    };
    let _ = helper_keyword_register_sticky_buffer(&kw);
    G_SDP_PHONE_NUMBER_BUFFER_ID = SCDetectHelperBufferMpmRegister(
        b"sdp.phone_number\0".as_ptr() as *const libc::c_char,
        b"sdp.phone_number\0".as_ptr() as *const libc::c_char,
        ALPROTO_SIP,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        Some(sdp_phone_number_get),
    );
    let kw = SigTableElmtStickyBuffer {
        name: String::from("sdp.connection_data"),
        desc: String::from("sticky buffer to match on the SDP connection data field"),
        url: String::from("/rules/sdp-keywords.html#sdp-connection-data"),
        setup: sdp_conn_data_setup,
    };
    let _ = helper_keyword_register_sticky_buffer(&kw);
    G_SDP_CONNECTION_DATA_BUFFER_ID = SCDetectHelperBufferMpmRegister(
        b"sdp.connection_data\0".as_ptr() as *const libc::c_char,
        b"sdp.connection_data\0".as_ptr() as *const libc::c_char,
        ALPROTO_SIP,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        Some(sdp_conn_data_get),
    );
    let kw = SigTableElmtStickyBuffer {
        name: String::from("sdp.bandwidth"),
        desc: String::from("sticky buffer to match on the SDP bandwidth field"),
        url: String::from("/rules/sdp-keywords.html#sdp-bandwidth"),
        setup: sdp_bandwidth_setup,
    };
    let _ = helper_keyword_register_multi_buffer(&kw);
    G_SDP_BANDWIDTH_BUFFER_ID = SCDetectHelperMultiBufferMpmRegister(
        b"sdp.bandwidth\0".as_ptr() as *const libc::c_char,
        b"sdp.bandwidth\0".as_ptr() as *const libc::c_char,
        ALPROTO_SIP,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        Some(sip_bandwidth_get_data),
    );
    let kw = SigTableElmtStickyBuffer {
        name: String::from("sdp.time"),
        desc: String::from("sticky buffer to match on the SDP time field"),
        url: String::from("/rules/sdp-keywords.html#time"),
        setup: sdp_time_setup,
    };
    let _ = helper_keyword_register_multi_buffer(&kw);
    G_SDP_TIME_BUFFER_ID = SCDetectHelperMultiBufferMpmRegister(
        b"sdp.time\0".as_ptr() as *const libc::c_char,
        b"sdp.time\0".as_ptr() as *const libc::c_char,
        ALPROTO_SIP,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        Some(sdp_time_get_data),
    );
    let kw = SigTableElmtStickyBuffer {
        name: String::from("sdp.repeat_time"),
        desc: String::from("sticky buffer to match on the SDP repeat time field"),
        url: String::from("/rules/sdp-keywords.html#repeat-time"),
        setup: sdp_repeat_time_setup,
    };
    let _ = helper_keyword_register_multi_buffer(&kw);
    G_SDP_REPEAT_TIME_BUFFER_ID = SCDetectHelperMultiBufferMpmRegister(
        b"sdp.repeat_time\0".as_ptr() as *const libc::c_char,
        b"sdp.repeat_time\0".as_ptr() as *const libc::c_char,
        ALPROTO_SIP,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        Some(sdp_repeat_time_get_data),
    );
    let kw = SigTableElmtStickyBuffer {
        name: String::from("sdp.timezone"),
        desc: String::from("sticky buffer to match on the SDP timezone field"),
        url: String::from("/rules/sdp-keywords.html#timezone"),
        setup: sdp_timezone_setup,
    };
    let _ = helper_keyword_register_sticky_buffer(&kw);
    G_SDP_TIMEZONE_BUFFER_ID = SCDetectHelperBufferMpmRegister(
        b"sdp.timezone\0".as_ptr() as *const libc::c_char,
        b"sdp.timezone\0".as_ptr() as *const libc::c_char,
        ALPROTO_SIP,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        Some(sdp_timezone_get),
    );
    let kw = SigTableElmtStickyBuffer {
        name: String::from("sdp.encryption_key"),
        desc: String::from("sticky buffer to match on the SDP encryption key field"),
        url: String::from("/rules/sdp-keywords.html#encryption-key"),
        setup: sdp_encryption_key_setup,
    };
    let _ = helper_keyword_register_sticky_buffer(&kw);
    G_SDP_ENCRYPTION_KEY_BUFFER_ID = SCDetectHelperBufferMpmRegister(
        b"sdp.encryption_key\0".as_ptr() as *const libc::c_char,
        b"sdp.encription_key\0".as_ptr() as *const libc::c_char,
        ALPROTO_SIP,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        Some(sdp_encryption_key_get),
    );
    let kw = SigTableElmtStickyBuffer {
        name: String::from("sdp.attribute"),
        desc: String::from("sticky buffer to match on the SDP attribute field"),
        url: String::from("/rules/sdp-keywords.html#sdp-attribute"),
        setup: sdp_attribute_setup,
    };
    let _ = helper_keyword_register_multi_buffer(&kw);
    G_SDP_ATTRIBUTE_BUFFER_ID = SCDetectHelperMultiBufferMpmRegister(
        b"sdp.attribute\0".as_ptr() as *const libc::c_char,
        b"sdp.attribute\0".as_ptr() as *const libc::c_char,
        ALPROTO_SIP,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        Some(sip_attribute_get_data),
    );
    let kw = SigTableElmtStickyBuffer {
        name: String::from("sdp.media.media"),
        desc: String::from(
            "sticky buffer to match on the SDP media subfield of the media_description field",
        ),
        url: String::from("/rules/sdp-keywords.html#media-description-media"),
        setup: sdp_media_desc_media_setup,
    };
    let _ = helper_keyword_register_multi_buffer(&kw);
    G_SDP_MEDIA_DESC_MEDIA_BUFFER_ID = SCDetectHelperMultiBufferMpmRegister(
        b"sdp.media.media\0".as_ptr() as *const libc::c_char,
        b"sdp.media.media\0".as_ptr() as *const libc::c_char,
        ALPROTO_SIP,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        Some(sip_media_desc_media_get_data),
    );
    let kw = SigTableElmtStickyBuffer {
        name: String::from("sdp.media.media_info"),
        desc: String::from("sticky buffer to match on the SDP session info subfield of the media_description field"),
        url: String::from("/rules/sdp-keywords.html#sdp-media-description-session-info"),
        setup: sdp_media_desc_session_info_setup,
    };
    let _ = helper_keyword_register_multi_buffer(&kw);
    G_SDP_MEDIA_DESC_SESSION_INFO_BUFFER_ID = SCDetectHelperMultiBufferMpmRegister(
        b"sdp.media.media_info\0".as_ptr() as *const libc::c_char,
        b"sdp.media.media_info\0".as_ptr() as *const libc::c_char,
        ALPROTO_SIP,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        Some(sip_media_desc_session_info_get_data),
    );
    let kw = SigTableElmtStickyBuffer {
        name: String::from("sdp.media.connection_data"),
        desc: String::from("sticky buffer to match on the SDP connection data subfield of the media_description field"),
        url: String::from("/rules/sdp-keywords.html#sdp-media-description-connection-data"),
        setup: sdp_media_desc_connection_data_setup,
    };
    let _ = helper_keyword_register_multi_buffer(&kw);
    G_SDP_MEDIA_DESC_CONNECTION_DATA_BUFFER_ID = SCDetectHelperMultiBufferMpmRegister(
        b"sdp.media.connection_data\0".as_ptr() as *const libc::c_char,
        b"sdp.media.connection_data\0".as_ptr() as *const libc::c_char,
        ALPROTO_SIP,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        Some(sip_media_desc_connection_data_get_data),
    );
    let kw = SigTableElmtStickyBuffer {
        name: String::from("sdp.media.encryption_key"),
        desc: String::from("sticky buffer to match on the SDP encryption key subfield of the media_description field"),
        url: String::from("/rules/sdp-keywords.html#sdp-media-description-encryption-key"),
        setup: sdp_media_desc_encryption_key_setup,
    };
    let _ = helper_keyword_register_multi_buffer(&kw);
    G_SDP_MEDIA_DESC_ENCRYPTION_KEY_BUFFER_ID = SCDetectHelperMultiBufferMpmRegister(
        b"sdp.media.encryption_key\0".as_ptr() as *const libc::c_char,
        b"sdp.media.encryption_key\0".as_ptr() as *const libc::c_char,
        ALPROTO_SIP,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        Some(sip_media_desc_encryption_key_get_data),
    );
}
