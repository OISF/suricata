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

// written by Sascha Steinbiss <sascha@steinbiss.name>

use crate::core::{STREAM_TOCLIENT, STREAM_TOSERVER};
use crate::detect::uint::{
    detect_match_uint, detect_parse_array_uint_enum, detect_parse_uint_bitflags,
    detect_uint_match_at_index, DetectBitflagModifier, DetectUintArrayData, DetectUintData,
    SCDetectU8Free, SCDetectU8Parse,
};
use crate::detect::{
    helper_keyword_register_multi_buffer, helper_keyword_register_sticky_buffer,
    SigTableElmtStickyBuffer, SIGMATCH_INFO_BITFLAGS_UINT, SIGMATCH_INFO_ENUM_UINT,
    SIGMATCH_INFO_MULTI_UINT, SIGMATCH_INFO_UINT8,
};
use suricata_sys::sys::{
    DetectEngineCtx, DetectEngineThreadCtx, Flow, SCDetectBufferSetActiveList,
    SCDetectHelperBufferMpmRegister, SCDetectHelperBufferRegister, SCDetectHelperKeywordRegister,
    SCDetectHelperMultiBufferMpmRegister, SCDetectSignatureSetAppProto, SCSigMatchAppendSMToList,
    SCSigTableAppLiteElmt, SigMatchCtx, Signature,
};

use super::mqtt::{MQTTState, MQTTTransaction, ALPROTO_MQTT};
use crate::conf::conf_get;
use crate::mqtt::mqtt_message::{MQTTMessage, MQTTOperation, MQTTTypeCode};
use std::ffi::CStr;
use std::os::raw::{c_int, c_void};
use std::ptr;
use std::str::FromStr;

fn mqtt_tx_has_type(tx: &MQTTTransaction, ctx: &DetectUintArrayData<u8>) -> c_int {
    return detect_uint_match_at_index::<MQTTMessage, u8>(
        &tx.msg,
        ctx,
        |msg| Some(msg.header.message_type as u8),
        tx.complete,
    );
}

unsafe extern "C" fn mqtt_conn_clientid_get_data(
    tx: *const c_void, _flags: u8, buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, MQTTTransaction);
    for msg in tx.msg.iter() {
        if let MQTTOperation::CONNECT(ref cv) = msg.op {
            let p = &cv.client_id;
            if !p.is_empty() {
                *buffer = p.as_ptr();
                *buffer_len = p.len() as u32;
                return true;
            }
        }
    }

    *buffer = ptr::null();
    *buffer_len = 0;
    return false;
}

unsafe extern "C" fn mqtt_conn_username_get_data(
    tx: *const c_void, _flags: u8, buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, MQTTTransaction);
    for msg in tx.msg.iter() {
        if let MQTTOperation::CONNECT(ref cv) = msg.op {
            if let Some(p) = &cv.username {
                if !p.is_empty() {
                    *buffer = p.as_ptr();
                    *buffer_len = p.len() as u32;
                    return true;
                }
            }
        }
    }

    *buffer = ptr::null();
    *buffer_len = 0;
    return false;
}

unsafe extern "C" fn mqtt_conn_password_get_data(
    tx: *const c_void, _flags: u8, buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, MQTTTransaction);
    for msg in tx.msg.iter() {
        if let MQTTOperation::CONNECT(ref cv) = msg.op {
            if let Some(p) = &cv.password {
                if !p.is_empty() {
                    *buffer = p.as_ptr();
                    *buffer_len = p.len() as u32;
                    return true;
                }
            }
        }
    }

    *buffer = ptr::null();
    *buffer_len = 0;
    return false;
}

unsafe extern "C" fn mqtt_conn_willtopic_get_data(
    tx: *const c_void, _flags: u8, buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, MQTTTransaction);
    for msg in tx.msg.iter() {
        if let MQTTOperation::CONNECT(ref cv) = msg.op {
            if let Some(p) = &cv.will_topic {
                if !p.is_empty() {
                    *buffer = p.as_ptr();
                    *buffer_len = p.len() as u32;
                    return true;
                }
            }
        }
    }

    *buffer = ptr::null();
    *buffer_len = 0;
    return false;
}

unsafe extern "C" fn mqtt_conn_willmsg_get_data(
    tx: *const c_void, _flags: u8, buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, MQTTTransaction);
    for msg in tx.msg.iter() {
        if let MQTTOperation::CONNECT(ref cv) = msg.op {
            if let Some(p) = &cv.will_message {
                if !p.is_empty() {
                    *buffer = p.as_ptr();
                    *buffer_len = p.len() as u32;
                    return true;
                }
            }
        }
    }

    *buffer = ptr::null();
    *buffer_len = 0;
    return false;
}

unsafe extern "C" fn mqtt_conn_protocolstring_get_data(
    tx: *const c_void, _flags: u8, buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, MQTTTransaction);
    for msg in tx.msg.iter() {
        if let MQTTOperation::CONNECT(ref cv) = msg.op {
            let p = &cv.protocol_string;
            if !p.is_empty() {
                *buffer = p.as_ptr();
                *buffer_len = p.len() as u32;
                return true;
            }
        }
    }

    *buffer = ptr::null();
    *buffer_len = 0;
    return false;
}

unsafe extern "C" fn mqtt_pub_topic_get_data(
    tx: *const c_void, _flags: u8, buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, MQTTTransaction);
    for msg in tx.msg.iter() {
        if let MQTTOperation::PUBLISH(ref pubv) = msg.op {
            let p = &pubv.topic;
            if !p.is_empty() {
                *buffer = p.as_ptr();
                *buffer_len = p.len() as u32;
                return true;
            }
        }
    }

    *buffer = ptr::null();
    *buffer_len = 0;
    return false;
}

unsafe extern "C" fn mqtt_pub_msg_get_data(
    tx: *const c_void, _flags: u8, buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, MQTTTransaction);
    for msg in tx.msg.iter() {
        if let MQTTOperation::PUBLISH(ref pubv) = msg.op {
            let p = &pubv.message;
            if !p.is_empty() {
                *buffer = p.as_ptr();
                *buffer_len = p.len() as u32;
                return true;
            }
        }
    }

    *buffer = ptr::null();
    *buffer_len = 0;
    return false;
}

fn mqtt_tx_get_reason_code(tx: &MQTTTransaction) -> Option<u8> {
    for msg in tx.msg.iter() {
        match msg.op {
            MQTTOperation::PUBACK(ref v)
            | MQTTOperation::PUBREL(ref v)
            | MQTTOperation::PUBREC(ref v)
            | MQTTOperation::PUBCOMP(ref v) => {
                if let Some(rcode) = v.reason_code {
                    return Some(rcode);
                }
            }
            MQTTOperation::AUTH(ref v) => {
                return Some(v.reason_code);
            }
            MQTTOperation::CONNACK(ref v) => {
                return Some(v.return_code);
            }
            MQTTOperation::DISCONNECT(ref v) => {
                if let Some(rcode) = v.reason_code {
                    return Some(rcode);
                }
            }
            _ => {}
        }
    }
    return None;
}

fn mqtt_tx_suback_unsuback_has_reason_code(
    tx: &MQTTTransaction, code: &DetectUintData<u8>,
) -> c_int {
    for msg in tx.msg.iter() {
        match msg.op {
            MQTTOperation::UNSUBACK(ref unsuback) => {
                if let Some(ref reason_codes) = unsuback.reason_codes {
                    for rc in reason_codes.iter() {
                        if detect_match_uint(code, *rc) {
                            return 1;
                        }
                    }
                }
            }
            MQTTOperation::SUBACK(ref suback) => {
                // in SUBACK these are stored as "QOS granted" historically
                for rc in suback.qoss.iter() {
                    if detect_match_uint(code, *rc) {
                        return 1;
                    }
                }
            }
            _ => {}
        }
    }
    return 0;
}

static mut UNSUB_TOPIC_MATCH_LIMIT: isize = 100;
static mut G_MQTT_UNSUB_TOPIC_BUFFER_ID: c_int = 0;
static mut G_MQTT_TYPE_KW_ID: u16 = 0;
static mut G_MQTT_TYPE_BUFFER_ID: c_int = 0;
static mut SUB_TOPIC_MATCH_LIMIT: isize = 100;
static mut G_MQTT_SUB_TOPIC_BUFFER_ID: c_int = 0;
static mut G_MQTT_REASON_CODE_KW_ID: u16 = 0;
static mut G_MQTT_REASON_CODE_BUFFER_ID: c_int = 0;
static mut G_MQTT_QOS_KW_ID: u16 = 0;
static mut G_MQTT_QOS_BUFFER_ID: c_int = 0;
static mut G_MQTT_PUB_TOPIC_BUFFER_ID: c_int = 0;
static mut G_MQTT_PUB_MSG_BUFFER_ID: c_int = 0;
static mut G_MQTT_PROTOCOL_VERSION_KW_ID: u16 = 0;
static mut G_MQTT_PROTOCOL_VERSION_BUFFER_ID: c_int = 0;
static mut G_MQTT_FLAGS_KW_ID: u16 = 0;
static mut G_MQTT_FLAGS_BUFFER_ID: c_int = 0;
static mut G_MQTT_CONN_WILLTOPIC_BUFFER_ID: c_int = 0;
static mut G_MQTT_CONN_WILLMSG_BUFFER_ID: c_int = 0;
static mut G_MQTT_CONN_USERNAME_BUFFER_ID: c_int = 0;
static mut G_MQTT_CONN_PROTOCOLSTRING_BUFFER_ID: c_int = 0;
static mut G_MQTT_CONN_PASSWORD_BUFFER_ID: c_int = 0;
static mut G_MQTT_CONN_CLIENTID_BUFFER_ID: c_int = 0;
static mut G_MQTT_CONNACK_SESSIONPRESENT_KW_ID: u16 = 0;
static mut G_MQTT_CONNACK_SESSIONPRESENT_BUFFER_ID: c_int = 0;
static mut G_MQTT_CONN_FLAGS_KW_ID: u16 = 0;
static mut G_MQTT_CONN_FLAGS_BUFFER_ID: c_int = 0;

unsafe extern "C" fn unsub_topic_get_data(
    _de: *mut DetectEngineThreadCtx, tx: *const c_void, _flow_flags: u8, local_id: u32,
    buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let ml = UNSUB_TOPIC_MATCH_LIMIT;
    if ml > 0 && local_id >= ml as u32 {
        return false;
    }
    let mut offset = 0;
    let tx = cast_pointer!(tx, MQTTTransaction);
    for msg in tx.msg.iter() {
        if let MQTTOperation::UNSUBSCRIBE(ref unsubv) = msg.op {
            if (local_id as usize) < unsubv.topics.len() + offset {
                let topic = &unsubv.topics[(local_id as usize) - offset];
                *buffer_len = topic.len() as u32;
                *buffer = topic.as_ptr();
                return true;
            } else {
                offset += unsubv.topics.len();
            }
        }
    }

    *buffer = ptr::null();
    *buffer_len = 0;
    return false;
}

unsafe extern "C" fn unsub_topic_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_MQTT) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_MQTT_UNSUB_TOPIC_BUFFER_ID) < 0 {
        return -1;
    }

    return 0;
}

unsafe extern "C" fn sub_topic_get_data(
    _de: *mut DetectEngineThreadCtx, tx: *const c_void, _flow_flags: u8, local_id: u32,
    buffer: *mut *const u8, buffer_len: *mut u32,
) -> bool {
    let ml = SUB_TOPIC_MATCH_LIMIT;
    if ml > 0 && local_id >= ml as u32 {
        return false;
    }
    let mut offset = 0;
    let tx = cast_pointer!(tx, MQTTTransaction);
    for msg in tx.msg.iter() {
        if let MQTTOperation::SUBSCRIBE(ref subv) = msg.op {
            if (local_id as usize) < subv.topics.len() + offset {
                let topic = &subv.topics[(local_id as usize) - offset];
                *buffer_len = topic.topic_name.len() as u32;
                *buffer = topic.topic_name.as_ptr();
                return true;
            } else {
                offset += subv.topics.len();
            }
        }
    }

    *buffer = ptr::null();
    *buffer_len = 0;
    return false;
}

unsafe extern "C" fn sub_topic_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_MQTT) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_MQTT_SUB_TOPIC_BUFFER_ID) < 0 {
        return -1;
    }

    return 0;
}

unsafe extern "C" fn mqtt_parse_type(
    ustr: *const std::os::raw::c_char,
) -> *mut DetectUintArrayData<u8> {
    let ft_name: &CStr = CStr::from_ptr(ustr); //unsafe
    if let Ok(s) = ft_name.to_str() {
        if let Some(ctx) = detect_parse_array_uint_enum::<u8, MQTTTypeCode>(s) {
            let boxed = Box::new(ctx);
            return Box::into_raw(boxed) as *mut _;
        }
    }
    return std::ptr::null_mut();
}

unsafe extern "C" fn mqtt_type_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, raw: *const libc::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_MQTT) != 0 {
        return -1;
    }
    let ctx = mqtt_parse_type(raw) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    if SCSigMatchAppendSMToList(
        de,
        s,
        G_MQTT_TYPE_KW_ID,
        ctx as *mut SigMatchCtx,
        G_MQTT_TYPE_BUFFER_ID,
    )
    .is_null()
    {
        mqtt_type_free(std::ptr::null_mut(), ctx);
        return -1;
    }
    return 0;
}

unsafe extern "C" fn mqtt_type_match(
    _de: *mut DetectEngineThreadCtx, _f: *mut Flow, _flags: u8, _state: *mut c_void,
    tx: *mut c_void, _sig: *const Signature, ctx: *const SigMatchCtx,
) -> c_int {
    let tx = cast_pointer!(tx, MQTTTransaction);
    let ctx = cast_pointer!(ctx, DetectUintArrayData<u8>);
    return mqtt_tx_has_type(tx, ctx);
}

unsafe extern "C" fn mqtt_type_free(_de: *mut DetectEngineCtx, ctx: *mut c_void) {
    // Just unbox...
    let ctx = cast_pointer!(ctx, DetectUintArrayData<u8>);
    std::mem::drop(Box::from_raw(ctx));
}

unsafe extern "C" fn mqtt_reason_code_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, raw: *const libc::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_MQTT) != 0 {
        return -1;
    }
    let ctx = SCDetectU8Parse(raw) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    if SCSigMatchAppendSMToList(
        de,
        s,
        G_MQTT_REASON_CODE_KW_ID,
        ctx as *mut SigMatchCtx,
        G_MQTT_REASON_CODE_BUFFER_ID,
    )
    .is_null()
    {
        mqtt_reason_code_free(std::ptr::null_mut(), ctx);
        return -1;
    }
    return 0;
}

unsafe extern "C" fn mqtt_reason_code_match(
    _de: *mut DetectEngineThreadCtx, _f: *mut Flow, _flags: u8, _state: *mut c_void,
    tx: *mut c_void, _sig: *const Signature, ctx: *const SigMatchCtx,
) -> c_int {
    let tx = cast_pointer!(tx, MQTTTransaction);
    let ctx = cast_pointer!(ctx, DetectUintData<u8>);
    if let Some(v) = mqtt_tx_get_reason_code(tx) {
        if detect_match_uint(ctx, v) {
            return 1;
        }
    }
    return mqtt_tx_suback_unsuback_has_reason_code(tx, ctx);
}

unsafe extern "C" fn mqtt_reason_code_free(_de: *mut DetectEngineCtx, ctx: *mut c_void) {
    // Just unbox...
    let ctx = cast_pointer!(ctx, DetectUintData<u8>);
    SCDetectU8Free(ctx);
}

unsafe extern "C" fn mqtt_parse_qos(ustr: *const std::os::raw::c_char) -> *mut u8 {
    let ft_name: &CStr = CStr::from_ptr(ustr); //unsafe
    if let Ok(s) = ft_name.to_str() {
        if let Ok(ctx) = u8::from_str(s.trim()) {
            if ctx <= 2 {
                let boxed = Box::new(ctx);
                return Box::into_raw(boxed) as *mut _;
            }
        }
    }
    return std::ptr::null_mut();
}

unsafe extern "C" fn mqtt_qos_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, raw: *const libc::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_MQTT) != 0 {
        return -1;
    }
    let ctx = mqtt_parse_qos(raw) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    if SCSigMatchAppendSMToList(
        de,
        s,
        G_MQTT_QOS_KW_ID,
        ctx as *mut SigMatchCtx,
        G_MQTT_QOS_BUFFER_ID,
    )
    .is_null()
    {
        mqtt_qos_free(std::ptr::null_mut(), ctx);
        return -1;
    }
    return 0;
}

fn mqtt_tx_has_qos(tx: &MQTTTransaction, qos: u8) -> c_int {
    for msg in tx.msg.iter() {
        if qos == msg.header.qos_level {
            return 1;
        }
    }
    return 0;
}

unsafe extern "C" fn mqtt_qos_match(
    _de: *mut DetectEngineThreadCtx, _f: *mut Flow, _flags: u8, _state: *mut c_void,
    tx: *mut c_void, _sig: *const Signature, ctx: *const SigMatchCtx,
) -> c_int {
    let tx = cast_pointer!(tx, MQTTTransaction);
    let ctx = cast_pointer!(ctx, u8);
    return mqtt_tx_has_qos(tx, *ctx);
}

unsafe extern "C" fn mqtt_qos_free(_de: *mut DetectEngineCtx, ctx: *mut c_void) {
    std::mem::drop(Box::from_raw(ctx as *mut u8));
}

unsafe extern "C" fn mqtt_parse_bool(ustr: *const std::os::raw::c_char) -> *mut bool {
    let ft_name: &CStr = CStr::from_ptr(ustr); //unsafe
    if let Ok(s) = ft_name.to_str() {
        if let Ok(ctx) = u8::from_str(s.trim()) {
            if ctx <= 2 {
                let boxed = Box::new(ctx);
                return Box::into_raw(boxed) as *mut _;
            }
        }
    }
    return std::ptr::null_mut();
}

unsafe extern "C" fn mqtt_connack_sessionpresent_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, raw: *const libc::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_MQTT) != 0 {
        return -1;
    }
    let ctx = mqtt_parse_bool(raw) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    if SCSigMatchAppendSMToList(
        de,
        s,
        G_MQTT_CONNACK_SESSIONPRESENT_KW_ID,
        ctx as *mut SigMatchCtx,
        G_MQTT_CONNACK_SESSIONPRESENT_BUFFER_ID,
    )
    .is_null()
    {
        mqtt_connack_sessionpresent_free(std::ptr::null_mut(), ctx);
        return -1;
    }
    return 0;
}

fn mqtt_tx_get_connack_sessionpresent(tx: &MQTTTransaction, session_present: bool) -> c_int {
    for msg in tx.msg.iter() {
        if let MQTTOperation::CONNACK(ref ca) = msg.op {
            if session_present == ca.session_present {
                return 1;
            }
        }
    }
    return 0;
}

unsafe extern "C" fn mqtt_connack_sessionpresent_match(
    _de: *mut DetectEngineThreadCtx, _f: *mut Flow, _flags: u8, _state: *mut c_void,
    tx: *mut c_void, _sig: *const Signature, ctx: *const SigMatchCtx,
) -> c_int {
    let tx = cast_pointer!(tx, MQTTTransaction);
    let ctx = cast_pointer!(ctx, bool);
    return mqtt_tx_get_connack_sessionpresent(tx, *ctx);
}

unsafe extern "C" fn mqtt_connack_sessionpresent_free(_de: *mut DetectEngineCtx, ctx: *mut c_void) {
    std::mem::drop(Box::from_raw(ctx as *mut bool));
}

unsafe extern "C" fn mqtt_pub_topic_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_MQTT) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_MQTT_PUB_TOPIC_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn mqtt_pub_msg_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_MQTT) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_MQTT_PUB_MSG_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn mqtt_protocol_version_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, raw: *const libc::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_MQTT) != 0 {
        return -1;
    }
    let ctx = SCDetectU8Parse(raw) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    if SCSigMatchAppendSMToList(
        de,
        s,
        G_MQTT_PROTOCOL_VERSION_KW_ID,
        ctx as *mut SigMatchCtx,
        G_MQTT_PROTOCOL_VERSION_BUFFER_ID,
    )
    .is_null()
    {
        mqtt_protocol_version_free(std::ptr::null_mut(), ctx);
        return -1;
    }
    return 0;
}

unsafe extern "C" fn mqtt_protocol_version_match(
    _de: *mut DetectEngineThreadCtx, _f: *mut Flow, _flags: u8, state: *mut c_void,
    _tx: *mut c_void, _sig: *const Signature, ctx: *const SigMatchCtx,
) -> c_int {
    let state = cast_pointer!(state, MQTTState);
    let ctx = cast_pointer!(ctx, DetectUintData<u8>);
    if detect_match_uint(ctx, state.protocol_version) {
        return 1;
    }
    return 0;
}

unsafe extern "C" fn mqtt_protocol_version_free(_de: *mut DetectEngineCtx, ctx: *mut c_void) {
    let ctx = cast_pointer!(ctx, DetectUintData<u8>);
    SCDetectU8Free(ctx);
}

#[repr(u8)]
#[derive(EnumStringU8)]
pub enum MqttFlag {
    Dup = 0x8,
    Retain = 0x1,
}

fn mqtt_flags_parse(s: &str) -> Option<DetectUintData<u8>> {
    detect_parse_uint_bitflags::<u8, MqttFlag>(s, DetectBitflagModifier::Plus, false)
}

unsafe extern "C" fn mqtt_parse_flags(
    ustr: *const std::os::raw::c_char,
) -> *mut DetectUintData<u8> {
    let ft_name: &CStr = CStr::from_ptr(ustr); //unsafe
    if let Ok(s) = ft_name.to_str() {
        if let Some(ctx) = mqtt_flags_parse(s) {
            let boxed = Box::new(ctx);
            return Box::into_raw(boxed) as *mut _;
        }
    }
    return std::ptr::null_mut();
}

unsafe extern "C" fn mqtt_flags_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, raw: *const libc::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_MQTT) != 0 {
        return -1;
    }
    let ctx = mqtt_parse_flags(raw) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    if SCSigMatchAppendSMToList(
        de,
        s,
        G_MQTT_FLAGS_KW_ID,
        ctx as *mut SigMatchCtx,
        G_MQTT_FLAGS_BUFFER_ID,
    )
    .is_null()
    {
        mqtt_flags_free(std::ptr::null_mut(), ctx);
        return -1;
    }
    return 0;
}

fn mqtt_tx_has_flags(tx: &MQTTTransaction, ctx: &DetectUintData<u8>) -> c_int {
    for msg in tx.msg.iter() {
        let mut v = 0;
        if msg.header.retain {
            v |= 1;
        }
        if msg.header.dup_flag {
            v |= 0x8;
        }
        if detect_match_uint(ctx, v) {
            return 1;
        }
    }
    return 0;
}

unsafe extern "C" fn mqtt_flags_match(
    _de: *mut DetectEngineThreadCtx, _f: *mut Flow, _flags: u8, _state: *mut c_void,
    tx: *mut c_void, _sig: *const Signature, ctx: *const SigMatchCtx,
) -> c_int {
    let tx = cast_pointer!(tx, MQTTTransaction);
    let ctx = cast_pointer!(ctx, DetectUintData<u8>);
    return mqtt_tx_has_flags(tx, ctx);
}

unsafe extern "C" fn mqtt_flags_free(_de: *mut DetectEngineCtx, ctx: *mut c_void) {
    let ctx = cast_pointer!(ctx, DetectUintData<u8>);
    SCDetectU8Free(ctx);
}

#[repr(u8)]
#[derive(EnumStringU8)]
#[allow(non_camel_case_types)]
pub enum MqttConnFlag {
    Username = 0x80,
    Password = 0x40,
    Will = 0x20,
    Will_retain = 0x4,
    Clean_session = 0x2,
}

fn mqtt_connflags_parse(s: &str) -> Option<DetectUintData<u8>> {
    detect_parse_uint_bitflags::<u8, MqttConnFlag>(s, DetectBitflagModifier::Plus, false)
}

unsafe extern "C" fn mqtt_parse_conn_flags(
    ustr: *const std::os::raw::c_char,
) -> *mut DetectUintData<u8> {
    let ft_name: &CStr = CStr::from_ptr(ustr); //unsafe
    if let Ok(s) = ft_name.to_str() {
        if let Some(ctx) = mqtt_connflags_parse(s) {
            let boxed = Box::new(ctx);
            return Box::into_raw(boxed) as *mut _;
        }
    }
    return std::ptr::null_mut();
}

unsafe extern "C" fn mqtt_conn_flags_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, raw: *const libc::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_MQTT) != 0 {
        return -1;
    }
    let ctx = mqtt_parse_conn_flags(raw) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    if SCSigMatchAppendSMToList(
        de,
        s,
        G_MQTT_CONN_FLAGS_KW_ID,
        ctx as *mut SigMatchCtx,
        G_MQTT_CONN_FLAGS_BUFFER_ID,
    )
    .is_null()
    {
        mqtt_conn_flags_free(std::ptr::null_mut(), ctx);
        return -1;
    }
    return 0;
}

fn mqtt_tx_has_conn_flags(tx: &MQTTTransaction, ctx: &DetectUintData<u8>) -> c_int {
    for msg in tx.msg.iter() {
        if let MQTTOperation::CONNECT(ref cv) = msg.op {
            if detect_match_uint(ctx, cv.rawflags) {
                return 1;
            }
        }
    }
    return 0;
}

unsafe extern "C" fn mqtt_conn_flags_match(
    _de: *mut DetectEngineThreadCtx, _f: *mut Flow, _flags: u8, _state: *mut c_void,
    tx: *mut c_void, _sig: *const Signature, ctx: *const SigMatchCtx,
) -> c_int {
    let tx = cast_pointer!(tx, MQTTTransaction);
    let ctx = cast_pointer!(ctx, DetectUintData<u8>);
    return mqtt_tx_has_conn_flags(tx, ctx);
}

unsafe extern "C" fn mqtt_conn_flags_free(_de: *mut DetectEngineCtx, ctx: *mut c_void) {
    let ctx = cast_pointer!(ctx, DetectUintData<u8>);
    SCDetectU8Free(ctx);
}

unsafe extern "C" fn mqtt_conn_willtopic_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_MQTT) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_MQTT_CONN_WILLTOPIC_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn mqtt_conn_willmsg_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_MQTT) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_MQTT_CONN_WILLMSG_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn mqtt_conn_username_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_MQTT) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_MQTT_CONN_USERNAME_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn mqtt_conn_protocolstring_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_MQTT) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_MQTT_CONN_PROTOCOLSTRING_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn mqtt_conn_password_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_MQTT) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_MQTT_CONN_PASSWORD_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

unsafe extern "C" fn mqtt_conn_clientid_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_MQTT) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_MQTT_CONN_CLIENTID_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectMqttRegister() {
    let keyword_name = b"mqtt.unsubscribe.topic\0".as_ptr() as *const libc::c_char;
    let kw = SigTableElmtStickyBuffer {
        name: String::from("mqtt.unsubscribe.topic"),
        desc: String::from("sticky buffer to match MQTT UNSUBSCRIBE topic"),
        url: String::from("/rules/mqtt-keywords.html#mqtt-unsubscribe-topic"),
        setup: unsub_topic_setup,
    };
    if let Some(val) = conf_get("app-layer.protocols.mqtt.unsubscribe-topic-match-limit") {
        if let Ok(v) = val.parse::<isize>() {
            UNSUB_TOPIC_MATCH_LIMIT = v;
        } else {
            SCLogError!("Invalid value for app-layer.protocols.mqtt.unsubscribe-topic-match-limit");
        }
    }
    let _g_mqtt_unsub_topic_kw_id = helper_keyword_register_multi_buffer(&kw);
    G_MQTT_UNSUB_TOPIC_BUFFER_ID = SCDetectHelperMultiBufferMpmRegister(
        keyword_name,
        b"unsubscribe topic query\0".as_ptr() as *const libc::c_char,
        ALPROTO_MQTT,
        STREAM_TOSERVER,
        Some(unsub_topic_get_data),
    );

    let kw = SCSigTableAppLiteElmt {
        name: b"mqtt.type\0".as_ptr() as *const libc::c_char,
        desc: b"match MQTT control packet type\0".as_ptr() as *const libc::c_char,
        url: b"/rules/mqtt-keywords.html#mqtt-type\0".as_ptr() as *const libc::c_char,
        AppLayerTxMatch: Some(mqtt_type_match),
        Setup: Some(mqtt_type_setup),
        Free: Some(mqtt_type_free),
        flags: SIGMATCH_INFO_UINT8 | SIGMATCH_INFO_MULTI_UINT | SIGMATCH_INFO_ENUM_UINT,
    };
    G_MQTT_TYPE_KW_ID = SCDetectHelperKeywordRegister(&kw);
    G_MQTT_TYPE_BUFFER_ID = SCDetectHelperBufferRegister(
        b"mqtt.type\0".as_ptr() as *const libc::c_char,
        ALPROTO_MQTT,
        STREAM_TOSERVER | STREAM_TOCLIENT,
    );

    let keyword_name = b"mqtt.subscribe.topic\0".as_ptr() as *const libc::c_char;
    let kw = SigTableElmtStickyBuffer {
        name: String::from("mqtt.subscribe.topic"),
        desc: String::from("sticky buffer to match MQTT SUBSCRIBE topic"),
        url: String::from("/rules/mqtt-keywords.html#mqtt-subscribe-topic"),
        setup: sub_topic_setup,
    };
    if let Some(val) = conf_get("app-layer.protocols.mqtt.subscribe-topic-match-limit") {
        if let Ok(v) = val.parse::<isize>() {
            SUB_TOPIC_MATCH_LIMIT = v;
        } else {
            SCLogError!("Invalid value for app-layer.protocols.mqtt.subscribe-topic-match-limit");
        }
    }
    let _g_mqtt_sub_topic_kw_id = helper_keyword_register_multi_buffer(&kw);
    G_MQTT_SUB_TOPIC_BUFFER_ID = SCDetectHelperMultiBufferMpmRegister(
        keyword_name,
        b"subscribe topic query\0".as_ptr() as *const libc::c_char,
        ALPROTO_MQTT,
        STREAM_TOSERVER,
        Some(sub_topic_get_data),
    );

    let kw = SCSigTableAppLiteElmt {
        name: b"mqtt.reason_code\0".as_ptr() as *const libc::c_char,
        desc: b"match MQTT 5.0+ reason code\0".as_ptr() as *const libc::c_char,
        //TODO alias "mqtt.connack.return_code"
        url: b"/rules/mqtt-keywords.html#mqtt-reason-code\0".as_ptr() as *const libc::c_char,
        AppLayerTxMatch: Some(mqtt_reason_code_match),
        Setup: Some(mqtt_reason_code_setup),
        Free: Some(mqtt_reason_code_free),
        flags: SIGMATCH_INFO_UINT8 | SIGMATCH_INFO_MULTI_UINT,
    };
    G_MQTT_REASON_CODE_KW_ID = SCDetectHelperKeywordRegister(&kw);
    G_MQTT_REASON_CODE_BUFFER_ID = SCDetectHelperBufferRegister(
        b"mqtt.reason_code\0".as_ptr() as *const libc::c_char,
        ALPROTO_MQTT,
        STREAM_TOSERVER | STREAM_TOCLIENT,
    );
    let kw = SCSigTableAppLiteElmt {
        name: b"mqtt.connack.session_present\0".as_ptr() as *const libc::c_char,
        desc: b"match MQTT CONNACK session present flag\0".as_ptr() as *const libc::c_char,
        url: b"/rules/mqtt-keywords.html#mqtt-connack-session-present\0".as_ptr()
            as *const libc::c_char,
        AppLayerTxMatch: Some(mqtt_connack_sessionpresent_match),
        Setup: Some(mqtt_connack_sessionpresent_setup),
        Free: Some(mqtt_connack_sessionpresent_free),
        flags: 0,
    };
    G_MQTT_CONNACK_SESSIONPRESENT_KW_ID = SCDetectHelperKeywordRegister(&kw);
    G_MQTT_CONNACK_SESSIONPRESENT_BUFFER_ID = SCDetectHelperBufferRegister(
        b"mqtt.connack.session_present\0".as_ptr() as *const libc::c_char,
        ALPROTO_MQTT,
        STREAM_TOCLIENT,
    );
    let kw = SCSigTableAppLiteElmt {
        name: b"mqtt.qos\0".as_ptr() as *const libc::c_char,
        desc: b"match MQTT fixed header QOS level\0".as_ptr() as *const libc::c_char,
        //TODO alias "mqtt.connack.return_code"
        url: b"/rules/mqtt-keywords.html#mqtt-qos\0".as_ptr() as *const libc::c_char,
        AppLayerTxMatch: Some(mqtt_qos_match),
        Setup: Some(mqtt_qos_setup),
        Free: Some(mqtt_qos_free),
        flags: 0,
    };
    G_MQTT_QOS_KW_ID = SCDetectHelperKeywordRegister(&kw);
    G_MQTT_QOS_BUFFER_ID = SCDetectHelperBufferRegister(
        b"mqtt.qos\0".as_ptr() as *const libc::c_char,
        ALPROTO_MQTT,
        STREAM_TOSERVER,
    );
    let kw = SigTableElmtStickyBuffer {
        name: String::from("mqtt.publish.topic"),
        desc: String::from("sticky buffer to match on the MQTT PUBLISH topic"),
        url: String::from("mqtt-keywords.html#mqtt-publish-topic"),
        setup: mqtt_pub_topic_setup,
    };
    let _g_mqtt_pub_topic_kw_id = helper_keyword_register_sticky_buffer(&kw);
    G_MQTT_PUB_TOPIC_BUFFER_ID = SCDetectHelperBufferMpmRegister(
        b"mqtt.publish.topic\0".as_ptr() as *const libc::c_char,
        b"MQTT PUBLISH topic\0".as_ptr() as *const libc::c_char,
        ALPROTO_MQTT,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        Some(mqtt_pub_topic_get_data),
    );
    let kw = SigTableElmtStickyBuffer {
        name: String::from("mqtt.publish.message"),
        desc: String::from("sticky buffer to match on the MQTT PUBLISH message"),
        url: String::from("mqtt-keywords.html#mqtt-publish-message"),
        setup: mqtt_pub_msg_setup,
    };
    let _g_mqtt_pub_msg_kw_id = helper_keyword_register_sticky_buffer(&kw);
    G_MQTT_PUB_MSG_BUFFER_ID = SCDetectHelperBufferMpmRegister(
        b"mqtt.publish.message\0".as_ptr() as *const libc::c_char,
        b"MQTT PUBLISH message\0".as_ptr() as *const libc::c_char,
        ALPROTO_MQTT,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        Some(mqtt_pub_msg_get_data),
    );
    let kw = SCSigTableAppLiteElmt {
        name: b"mqtt.protocol_version\0".as_ptr() as *const libc::c_char,
        desc: b"match MQTT protocol version\0".as_ptr() as *const libc::c_char,
        url: b"/rules/mqtt-keywords.html#mqtt-protocol-version\0".as_ptr() as *const libc::c_char,
        AppLayerTxMatch: Some(mqtt_protocol_version_match),
        Setup: Some(mqtt_protocol_version_setup),
        Free: Some(mqtt_protocol_version_free),
        flags: SIGMATCH_INFO_UINT8,
    };
    G_MQTT_PROTOCOL_VERSION_KW_ID = SCDetectHelperKeywordRegister(&kw);
    G_MQTT_PROTOCOL_VERSION_BUFFER_ID = SCDetectHelperBufferRegister(
        b"mqtt.protocol_version\0".as_ptr() as *const libc::c_char,
        ALPROTO_MQTT,
        STREAM_TOSERVER,
    );
    let kw = SCSigTableAppLiteElmt {
        name: b"mqtt.flags\0".as_ptr() as *const libc::c_char,
        desc: b"match MQTT fixed header flags\0".as_ptr() as *const libc::c_char,
        url: b"/rules/mqtt-keywords.html#mqtt-flags\0".as_ptr() as *const libc::c_char,
        AppLayerTxMatch: Some(mqtt_flags_match),
        Setup: Some(mqtt_flags_setup),
        Free: Some(mqtt_flags_free),
        flags: SIGMATCH_INFO_UINT8 | SIGMATCH_INFO_MULTI_UINT | SIGMATCH_INFO_BITFLAGS_UINT,
    };
    G_MQTT_FLAGS_KW_ID = SCDetectHelperKeywordRegister(&kw);
    G_MQTT_FLAGS_BUFFER_ID = SCDetectHelperBufferRegister(
        b"mqtt.flags\0".as_ptr() as *const libc::c_char,
        ALPROTO_MQTT,
        STREAM_TOSERVER,
    );
    let kw = SCSigTableAppLiteElmt {
        name: b"mqtt.connect.flags\0".as_ptr() as *const libc::c_char,
        desc: b"match MQTT CONNECT variable header flags\0".as_ptr() as *const libc::c_char,
        url: b"/rules/mqtt-keywords.html#mqtt-connect-flags\0".as_ptr() as *const libc::c_char,
        AppLayerTxMatch: Some(mqtt_conn_flags_match),
        Setup: Some(mqtt_conn_flags_setup),
        Free: Some(mqtt_conn_flags_free),
        flags: SIGMATCH_INFO_UINT8 | SIGMATCH_INFO_MULTI_UINT | SIGMATCH_INFO_BITFLAGS_UINT,
    };
    G_MQTT_CONN_FLAGS_KW_ID = SCDetectHelperKeywordRegister(&kw);
    G_MQTT_CONN_FLAGS_BUFFER_ID = SCDetectHelperBufferRegister(
        b"mqtt.connect.flags\0".as_ptr() as *const libc::c_char,
        ALPROTO_MQTT,
        STREAM_TOSERVER,
    );
    let kw = SigTableElmtStickyBuffer {
        name: String::from("mqtt.connect.willtopic"),
        desc: String::from("sticky buffer to match on the MQTT CONNECT will topic"),
        url: String::from("mqtt-keywords.html#mqtt-connect-willtopic"),
        setup: mqtt_conn_willtopic_setup,
    };
    let _g_mqtt_conn_willtopic_kw_id = helper_keyword_register_sticky_buffer(&kw);
    G_MQTT_CONN_WILLTOPIC_BUFFER_ID = SCDetectHelperBufferMpmRegister(
        b"mqtt.connect.willtopic\0".as_ptr() as *const libc::c_char,
        b"MQTT CONNECT will topic\0".as_ptr() as *const libc::c_char,
        ALPROTO_MQTT,
        STREAM_TOSERVER,
        Some(mqtt_conn_willtopic_get_data),
    );
    let kw = SigTableElmtStickyBuffer {
        name: String::from("mqtt.connect.willmessage"),
        desc: String::from("sticky buffer to match on the MQTT CONNECT will message"),
        url: String::from("mqtt-keywords.html#mqtt-connect-willmessage"),
        setup: mqtt_conn_willmsg_setup,
    };
    let _g_mqtt_conn_willmsg_kw_id = helper_keyword_register_sticky_buffer(&kw);
    G_MQTT_CONN_WILLMSG_BUFFER_ID = SCDetectHelperBufferMpmRegister(
        b"mqtt.connect.willmessage\0".as_ptr() as *const libc::c_char,
        b"MQTT CONNECT will message\0".as_ptr() as *const libc::c_char,
        ALPROTO_MQTT,
        STREAM_TOSERVER,
        Some(mqtt_conn_willmsg_get_data),
    );
    let kw = SigTableElmtStickyBuffer {
        name: String::from("mqtt.connect.username"),
        desc: String::from("sticky buffer to match on the MQTT CONNECT username"),
        url: String::from("mqtt-keywords.html#mqtt-connect-username"),
        setup: mqtt_conn_username_setup,
    };
    let _g_mqtt_conn_username_kw_id = helper_keyword_register_sticky_buffer(&kw);
    G_MQTT_CONN_USERNAME_BUFFER_ID = SCDetectHelperBufferMpmRegister(
        b"mqtt.connect.username\0".as_ptr() as *const libc::c_char,
        b"MQTT CONNECT username\0".as_ptr() as *const libc::c_char,
        ALPROTO_MQTT,
        STREAM_TOSERVER,
        Some(mqtt_conn_username_get_data),
    );
    let kw = SigTableElmtStickyBuffer {
        name: String::from("mqtt.connect.protocol_string"),
        desc: String::from("sticky buffer to match on the MQTT CONNECT protocol string"),
        url: String::from("mqtt-keywords.html#mqtt-connect-protocol_string"),
        setup: mqtt_conn_protocolstring_setup,
    };
    let _g_mqtt_conn_protostr_kw_id = helper_keyword_register_sticky_buffer(&kw);
    G_MQTT_CONN_PROTOCOLSTRING_BUFFER_ID = SCDetectHelperBufferMpmRegister(
        b"mqtt.connect.protocol_string\0".as_ptr() as *const libc::c_char,
        b"MQTT CONNECT protocol string\0".as_ptr() as *const libc::c_char,
        ALPROTO_MQTT,
        STREAM_TOSERVER,
        Some(mqtt_conn_protocolstring_get_data),
    );
    let kw = SigTableElmtStickyBuffer {
        name: String::from("mqtt.connect.password"),
        desc: String::from("sticky buffer to match on the MQTT CONNECT password"),
        url: String::from("mqtt-keywords.html#mqtt-connect-password"),
        setup: mqtt_conn_password_setup,
    };
    let _g_mqtt_conn_password_kw_id = helper_keyword_register_sticky_buffer(&kw);
    G_MQTT_CONN_PASSWORD_BUFFER_ID = SCDetectHelperBufferMpmRegister(
        b"mqtt.connect.password\0".as_ptr() as *const libc::c_char,
        b"MQTT CONNECT password\0".as_ptr() as *const libc::c_char,
        ALPROTO_MQTT,
        STREAM_TOSERVER,
        Some(mqtt_conn_password_get_data),
    );
    let kw = SigTableElmtStickyBuffer {
        name: String::from("mqtt.connect.clientid"),
        desc: String::from("sticky buffer to match on the MQTT CONNECT clientid"),
        url: String::from("mqtt-keywords.html#mqtt-connect-clientid"),
        setup: mqtt_conn_clientid_setup,
    };
    let _g_mqtt_conn_password_kw_id = helper_keyword_register_sticky_buffer(&kw);
    G_MQTT_CONN_CLIENTID_BUFFER_ID = SCDetectHelperBufferMpmRegister(
        b"mqtt.connect.clientid\0".as_ptr() as *const libc::c_char,
        b"MQTT CONNECT clientid\0".as_ptr() as *const libc::c_char,
        ALPROTO_MQTT,
        STREAM_TOSERVER,
        Some(mqtt_conn_clientid_get_data),
    );
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::detect::uint::DetectUintMode;
    use crate::direction::Direction;
    use crate::mqtt::mqtt::MQTTTransaction;
    use crate::mqtt::mqtt_message::*;
    use crate::mqtt::parser::FixedHeader;
    use std;

    #[test]
    fn mqtt_type_test_qos() {
        let ctx = unsafe { mqtt_parse_qos("0\0".as_ptr() as *const libc::c_char) };
        assert!(!ctx.is_null());
        assert_eq!(unsafe { *ctx }, 0);
        let ctx = unsafe { mqtt_parse_qos("   0\0".as_ptr() as *const libc::c_char) };
        assert!(!ctx.is_null());
        assert_eq!(unsafe { *ctx }, 0);
        let ctx = unsafe { mqtt_parse_qos("1\0".as_ptr() as *const libc::c_char) };
        assert!(!ctx.is_null());
        assert_eq!(unsafe { *ctx }, 1);
        let ctx = unsafe { mqtt_parse_qos("2\0".as_ptr() as *const libc::c_char) };
        assert!(!ctx.is_null());
        assert_eq!(unsafe { *ctx }, 2);
        let ctx = unsafe { mqtt_parse_qos("3\0".as_ptr() as *const libc::c_char) };
        assert!(ctx.is_null());
        let ctx = unsafe { mqtt_parse_qos("12\0".as_ptr() as *const libc::c_char) };
        assert!(ctx.is_null());
    }

    #[test]
    fn mqtt_parse_flags() {
        let ctx = mqtt_flags_parse("retain").unwrap();
        assert_eq!(ctx.arg1, 1);
        assert_eq!(ctx.arg2, 1);
        let ctx = mqtt_flags_parse("dup").unwrap();
        assert_eq!(ctx.arg1, 8);
        assert_eq!(ctx.arg2, 8);
        let ctx = mqtt_flags_parse("retain,dup").unwrap();
        assert_eq!(ctx.arg1, 8 | 1);
        assert_eq!(ctx.arg2, 8 | 1);
        let ctx = mqtt_flags_parse("dup, retain").unwrap();
        assert_eq!(ctx.arg1, 8 | 1);
        assert_eq!(ctx.arg2, 8 | 1);
        let ctx = mqtt_flags_parse("retain,!dup").unwrap();
        assert_eq!(ctx.arg1, 1 | 8);
        assert_eq!(ctx.arg2, 1);
        assert!(mqtt_flags_parse("ref").is_none());
        assert!(mqtt_flags_parse("dup,!").is_none());
        assert!(mqtt_flags_parse("dup,!dup",).is_none());
        assert!(mqtt_flags_parse("!retain,retain",).is_none());
    }

    #[test]
    fn mqtt_parse_conn_flags() {
        let ctx = mqtt_connflags_parse("username").unwrap();
        assert_eq!(ctx.arg1, 0x80);
        assert_eq!(ctx.arg2, 0x80);
        let ctx = mqtt_connflags_parse("username,password,will,will_retain,clean_session").unwrap();
        assert_eq!(ctx.arg1, 0xE6);
        assert_eq!(ctx.arg2, 0xE6);
        let ctx =
            mqtt_connflags_parse("!username,!password,!will,!will_retain,!clean_session").unwrap();
        assert_eq!(ctx.arg1, 0xE6);
        assert_eq!(ctx.arg2, 0);
        let ctx = mqtt_connflags_parse("   username,password").unwrap();
        assert_eq!(ctx.arg1, 0xC0);
        assert_eq!(ctx.arg2, 0xC0);
        assert!(mqtt_connflags_parse("foobar").is_none());
        assert!(mqtt_connflags_parse("will,!").is_none());
        assert!(mqtt_connflags_parse("").is_none());
        assert!(mqtt_connflags_parse("username, username").is_none());
        assert!(mqtt_connflags_parse("!username, username").is_none());
        assert!(mqtt_connflags_parse("!username,password,!password").is_none());
        assert!(mqtt_connflags_parse("will, username,password,   !will, will",).is_none());
    }

    #[test]
    fn mqtt_type_test_parse() {
        let ctx = detect_parse_array_uint_enum::<u8, MQTTTypeCode>("CONNECT").unwrap();
        assert_eq!(ctx.du.arg1, 1);
        assert_eq!(ctx.du.mode, DetectUintMode::DetectUintModeEqual);
        let ctx = detect_parse_array_uint_enum::<u8, MQTTTypeCode>("PINGRESP").unwrap();
        assert_eq!(ctx.du.arg1, 13);
        assert_eq!(ctx.du.mode, DetectUintMode::DetectUintModeEqual);
        let ctx = detect_parse_array_uint_enum::<u8, MQTTTypeCode>("auth").unwrap();
        assert_eq!(ctx.du.arg1, 15);
        assert_eq!(ctx.du.mode, DetectUintMode::DetectUintModeEqual);
        assert!(detect_parse_array_uint_enum::<u8, MQTTTypeCode>("invalidopt").is_none());
        let ctx = detect_parse_array_uint_enum::<u8, MQTTTypeCode>("unassigned").unwrap();
        assert_eq!(ctx.du.arg1, 0);
        assert_eq!(ctx.du.mode, DetectUintMode::DetectUintModeEqual);
    }

    #[test]
    fn test_multi_unsubscribe() {
        let mut t = MQTTTransaction::new(
            MQTTMessage {
                header: FixedHeader {
                    message_type: MQTTTypeCode::UNSUBSCRIBE,
                    dup_flag: false,
                    qos_level: 0,
                    retain: false,
                    remaining_length: 0,
                },
                op: MQTTOperation::UNSUBSCRIBE(MQTTUnsubscribeData {
                    message_id: 1,
                    topics: vec!["foo".to_string(), "baar".to_string()],
                    properties: None,
                }),
            },
            Direction::ToServer,
        );
        t.msg.push(MQTTMessage {
            header: FixedHeader {
                message_type: MQTTTypeCode::UNSUBSCRIBE,
                dup_flag: false,
                qos_level: 0,
                retain: false,
                remaining_length: 0,
            },
            op: MQTTOperation::UNSUBSCRIBE(MQTTUnsubscribeData {
                message_id: 1,
                topics: vec!["fieee".to_string(), "baaaaz".to_string()],
                properties: None,
            }),
        });
        let mut s: *const u8 = std::ptr::null_mut();
        let mut slen: u32 = 0;
        let tx = &t as *const _ as *mut _;
        let mut r =
            unsafe { unsub_topic_get_data(std::ptr::null_mut(), tx, 0, 0, &mut s, &mut slen) };
        assert!(r);
        let mut topic = String::from_utf8_lossy(unsafe { build_slice!(s, slen as usize) });
        assert_eq!(topic, "foo");
        r = unsafe { unsub_topic_get_data(std::ptr::null_mut(), tx, 0, 1, &mut s, &mut slen) };
        assert!(r);
        topic = String::from_utf8_lossy(unsafe { build_slice!(s, slen as usize) });
        assert_eq!(topic, "baar");
        r = unsafe { unsub_topic_get_data(std::ptr::null_mut(), tx, 0, 2, &mut s, &mut slen) };
        assert!(r);
        topic = String::from_utf8_lossy(unsafe { build_slice!(s, slen as usize) });
        assert_eq!(topic, "fieee");
        r = unsafe { unsub_topic_get_data(std::ptr::null_mut(), tx, 0, 3, &mut s, &mut slen) };
        assert!(r);
        topic = String::from_utf8_lossy(unsafe { build_slice!(s, slen as usize) });
        assert_eq!(topic, "baaaaz");
        r = unsafe { unsub_topic_get_data(std::ptr::null_mut(), tx, 0, 4, &mut s, &mut slen) };
        assert!(!r);
    }

    #[test]
    fn test_multi_subscribe() {
        let mut t = MQTTTransaction::new(
            MQTTMessage {
                header: FixedHeader {
                    message_type: MQTTTypeCode::SUBSCRIBE,
                    dup_flag: false,
                    qos_level: 0,
                    retain: false,
                    remaining_length: 0,
                },
                op: MQTTOperation::SUBSCRIBE(MQTTSubscribeData {
                    message_id: 1,
                    topics: vec![
                        MQTTSubscribeTopicData {
                            topic_name: "foo".to_string(),
                            qos: 0,
                        },
                        MQTTSubscribeTopicData {
                            topic_name: "baar".to_string(),
                            qos: 1,
                        },
                    ],
                    properties: None,
                }),
            },
            Direction::ToServer,
        );
        t.msg.push(MQTTMessage {
            header: FixedHeader {
                message_type: MQTTTypeCode::SUBSCRIBE,
                dup_flag: false,
                qos_level: 0,
                retain: false,
                remaining_length: 0,
            },
            op: MQTTOperation::SUBSCRIBE(MQTTSubscribeData {
                message_id: 1,
                topics: vec![
                    MQTTSubscribeTopicData {
                        topic_name: "fieee".to_string(),
                        qos: 0,
                    },
                    MQTTSubscribeTopicData {
                        topic_name: "baaaaz".to_string(),
                        qos: 1,
                    },
                ],
                properties: None,
            }),
        });
        let mut s: *const u8 = std::ptr::null_mut();
        let mut slen: u32 = 0;
        let tx = &t as *const _ as *mut _;
        let mut r =
            unsafe { sub_topic_get_data(std::ptr::null_mut(), tx, 0, 0, &mut s, &mut slen) };
        assert!(r);
        let mut topic = String::from_utf8_lossy(unsafe { build_slice!(s, slen as usize) });
        assert_eq!(topic, "foo");
        r = unsafe { sub_topic_get_data(std::ptr::null_mut(), tx, 0, 1, &mut s, &mut slen) };
        assert!(r);
        topic = String::from_utf8_lossy(unsafe { build_slice!(s, slen as usize) });
        assert_eq!(topic, "baar");
        r = unsafe { sub_topic_get_data(std::ptr::null_mut(), tx, 0, 2, &mut s, &mut slen) };
        assert!(r);
        topic = String::from_utf8_lossy(unsafe { build_slice!(s, slen as usize) });
        assert_eq!(topic, "fieee");
        r = unsafe { sub_topic_get_data(std::ptr::null_mut(), tx, 0, 3, &mut s, &mut slen) };
        assert!(r);
        topic = String::from_utf8_lossy(unsafe { build_slice!(s, slen as usize) });
        assert_eq!(topic, "baaaaz");
        r = unsafe { sub_topic_get_data(std::ptr::null_mut(), tx, 0, 4, &mut s, &mut slen) };
        assert!(!r);
    }
}
