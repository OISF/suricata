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

use crate::detect::uint::{
    detect_match_uint, detect_parse_uint, detect_parse_uint_enum, rs_detect_u8_free,
    rs_detect_u8_parse, DetectUintData, DetectUintMode,
};
use crate::detect::{
    DetectAppLayerMultiRegister, DetectBufferSetActiveList, DetectBufferTypeGetByName,
    DetectBufferTypeSetDescriptionByName, DetectBufferTypeSupportsMultiInstance,
    DetectHelperBufferMpmRegister, DetectHelperBufferRegister, DetectHelperGetData,
    DetectHelperGetMultiData, DetectHelperKeywordRegister, DetectSignatureSetAppProto,
    SCSigTableElmt, SigMatchAppendSMToList, SIGMATCH_INFO_STICKY_BUFFER, SIGMATCH_NOOPT,
    SIG_FLAG_TOSERVER,
};

use nom7::branch::alt;
use nom7::bytes::complete::{is_a, tag};
use nom7::combinator::{opt, value};
use nom7::multi::many1;
use nom7::IResult;

use super::mqtt::{MQTTState, MQTTTransaction, ALPROTO_MQTT};
use crate::conf::conf_get;
use crate::mqtt::mqtt_message::{MQTTOperation, MQTTTypeCode};
use std::ffi::CStr;
use std::os::raw::{c_int, c_void};
use std::ptr;
use std::str::FromStr;

fn mqtt_tx_has_type(tx: &MQTTTransaction, mtype: &DetectUintData<u8>) -> c_int {
    for msg in tx.msg.iter() {
        if detect_match_uint(mtype, msg.header.message_type as u8) {
            return 1;
        }
    }
    return 0;
}

unsafe extern "C" fn mqtt_tx_get_connect_clientid(
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

unsafe extern "C" fn mqtt_tx_get_connect_username(
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

unsafe extern "C" fn mqtt_tx_get_connect_password(
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

unsafe extern "C" fn mqtt_tx_get_connect_willtopic(
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

unsafe extern "C" fn mqtt_tx_get_connect_willmessage(
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

unsafe extern "C" fn mqtt_tx_get_connect_protocol_string(
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

unsafe extern "C" fn mqtt_tx_get_publish_topic(
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

unsafe extern "C" fn mqtt_tx_get_publish_message(
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

fn mqtt_tx_unsuback_has_reason_code(tx: &MQTTTransaction, code: &DetectUintData<u8>) -> c_int {
    for msg in tx.msg.iter() {
        if let MQTTOperation::UNSUBACK(ref unsuback) = msg.op {
            if let Some(ref reason_codes) = unsuback.reason_codes {
                for rc in reason_codes.iter() {
                    if detect_match_uint(code, *rc) {
                        return 1;
                    }
                }
            }
        }
    }
    return 0;
}

static mut UNSUB_TOPIC_MATCH_LIMIT: isize = 100;
static mut G_MQTT_UNSUB_TOPIC_BUFFER_ID: c_int = 0;
static mut G_MQTT_TYPE_KW_ID: c_int = 0;
static mut G_MQTT_TYPE_BUFFER_ID: c_int = 0;
static mut SUB_TOPIC_MATCH_LIMIT: isize = 100;
static mut G_MQTT_SUB_TOPIC_BUFFER_ID: c_int = 0;
static mut G_MQTT_REASON_CODE_KW_ID: c_int = 0;
static mut G_MQTT_REASON_CODE_BUFFER_ID: c_int = 0;
static mut G_MQTT_QOS_KW_ID: c_int = 0;
static mut G_MQTT_QOS_BUFFER_ID: c_int = 0;
static mut G_MQTT_PUB_TOPIC_BUFFER_ID: c_int = 0;
static mut G_MQTT_PUB_MSG_BUFFER_ID: c_int = 0;
static mut G_MQTT_PROTOCOL_VERSION_KW_ID: c_int = 0;
static mut G_MQTT_PROTOCOL_VERSION_BUFFER_ID: c_int = 0;
static mut G_MQTT_FLAGS_KW_ID: c_int = 0;
static mut G_MQTT_FLAGS_BUFFER_ID: c_int = 0;
static mut G_MQTT_CONN_WILLTOPIC_BUFFER_ID: c_int = 0;
static mut G_MQTT_CONN_WILLMSG_BUFFER_ID: c_int = 0;
static mut G_MQTT_CONN_USERNAME_BUFFER_ID: c_int = 0;
static mut G_MQTT_CONN_PROTOCOLSTRING_BUFFER_ID: c_int = 0;
static mut G_MQTT_CONN_PASSWORD_BUFFER_ID: c_int = 0;
static mut G_MQTT_CONN_CLIENTID_BUFFER_ID: c_int = 0;
static mut G_MQTT_CONNACK_SESSIONPRESENT_KW_ID: c_int = 0;
static mut G_MQTT_CONNACK_SESSIONPRESENT_BUFFER_ID: c_int = 0;
static mut G_MQTT_CONN_FLAGS_KW_ID: c_int = 0;
static mut G_MQTT_CONN_FLAGS_BUFFER_ID: c_int = 0;

unsafe extern "C" fn unsub_topic_get_data(
    tx: *const c_void, _flow_flags: u8, local_id: u32, buffer: *mut *const u8, buffer_len: *mut u32,
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
                if !topic.is_empty() {
                    *buffer_len = topic.len() as u32;
                    *buffer = topic.as_ptr();
                    return true;
                }
            } else {
                offset += unsubv.topics.len();
            }
        }
    }

    *buffer = ptr::null();
    *buffer_len = 0;
    return false;
}

unsafe extern "C" fn unsub_topic_get_data_wrapper(
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
        unsub_topic_get_data,
    );
}

unsafe extern "C" fn unsub_topic_setup(
    de: *mut c_void, s: *mut c_void, _raw: *const std::os::raw::c_char,
) -> c_int {
    if DetectSignatureSetAppProto(s, ALPROTO_MQTT) != 0 {
        return -1;
    }
    if DetectBufferSetActiveList(de, s, G_MQTT_UNSUB_TOPIC_BUFFER_ID) < 0 {
        return -1;
    }

    return 0;
}

unsafe extern "C" fn sub_topic_get_data(
    tx: *const c_void, _flow_flags: u8, local_id: u32, buffer: *mut *const u8, buffer_len: *mut u32,
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
                if !topic.topic_name.is_empty() {
                    *buffer_len = topic.topic_name.len() as u32;
                    *buffer = topic.topic_name.as_ptr();
                    return true;
                }
            } else {
                offset += subv.topics.len();
            }
        }
    }

    *buffer = ptr::null();
    *buffer_len = 0;
    return false;
}

unsafe extern "C" fn sub_topic_get_data_wrapper(
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
        sub_topic_get_data,
    );
}

unsafe extern "C" fn sub_topic_setup(
    de: *mut c_void, s: *mut c_void, _raw: *const std::os::raw::c_char,
) -> c_int {
    if DetectSignatureSetAppProto(s, ALPROTO_MQTT) != 0 {
        return -1;
    }
    if DetectBufferSetActiveList(de, s, G_MQTT_SUB_TOPIC_BUFFER_ID) < 0 {
        return -1;
    }

    return 0;
}

unsafe extern "C" fn mqtt_parse_type(ustr: *const std::os::raw::c_char) -> *mut DetectUintData<u8> {
    let ft_name: &CStr = CStr::from_ptr(ustr); //unsafe
    if let Ok(s) = ft_name.to_str() {
        if let Some(ctx) = detect_parse_uint_enum::<u8, MQTTTypeCode>(s) {
            let boxed = Box::new(ctx);
            return Box::into_raw(boxed) as *mut _;
        }
    }
    return std::ptr::null_mut();
}

unsafe extern "C" fn mqtt_type_setup(
    de: *mut c_void, s: *mut c_void, raw: *const libc::c_char,
) -> c_int {
    if DetectSignatureSetAppProto(s, ALPROTO_MQTT) != 0 {
        return -1;
    }
    let ctx = mqtt_parse_type(raw) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    if SigMatchAppendSMToList(de, s, G_MQTT_TYPE_KW_ID, ctx, G_MQTT_TYPE_BUFFER_ID).is_null() {
        mqtt_type_free(std::ptr::null_mut(), ctx);
        return -1;
    }
    return 0;
}

unsafe extern "C" fn mqtt_type_match(
    _de: *mut c_void, _f: *mut c_void, _flags: u8, _state: *mut c_void, tx: *mut c_void,
    _sig: *const c_void, ctx: *const c_void,
) -> c_int {
    let tx = cast_pointer!(tx, MQTTTransaction);
    let ctx = cast_pointer!(ctx, DetectUintData<u8>);
    return mqtt_tx_has_type(tx, ctx);
}

unsafe extern "C" fn mqtt_type_free(_de: *mut c_void, ctx: *mut c_void) {
    // Just unbox...
    let ctx = cast_pointer!(ctx, DetectUintData<u8>);
    rs_detect_u8_free(ctx);
}

unsafe extern "C" fn mqtt_reason_code_setup(
    de: *mut c_void, s: *mut c_void, raw: *const libc::c_char,
) -> c_int {
    if DetectSignatureSetAppProto(s, ALPROTO_MQTT) != 0 {
        return -1;
    }
    let ctx = rs_detect_u8_parse(raw) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    if SigMatchAppendSMToList(
        de,
        s,
        G_MQTT_REASON_CODE_KW_ID,
        ctx,
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
    _de: *mut c_void, _f: *mut c_void, _flags: u8, _state: *mut c_void, tx: *mut c_void,
    _sig: *const c_void, ctx: *const c_void,
) -> c_int {
    let tx = cast_pointer!(tx, MQTTTransaction);
    let ctx = cast_pointer!(ctx, DetectUintData<u8>);
    if let Some(v) = mqtt_tx_get_reason_code(tx) {
        if detect_match_uint(ctx, v) {
            return 1;
        }
    }
    return mqtt_tx_unsuback_has_reason_code(tx, ctx);
}

unsafe extern "C" fn mqtt_reason_code_free(_de: *mut c_void, ctx: *mut c_void) {
    // Just unbox...
    let ctx = cast_pointer!(ctx, DetectUintData<u8>);
    rs_detect_u8_free(ctx);
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
    de: *mut c_void, s: *mut c_void, raw: *const libc::c_char,
) -> c_int {
    if DetectSignatureSetAppProto(s, ALPROTO_MQTT) != 0 {
        return -1;
    }
    let ctx = mqtt_parse_qos(raw) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    if SigMatchAppendSMToList(de, s, G_MQTT_QOS_KW_ID, ctx, G_MQTT_QOS_BUFFER_ID).is_null() {
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
    _de: *mut c_void, _f: *mut c_void, _flags: u8, _state: *mut c_void, tx: *mut c_void,
    _sig: *const c_void, ctx: *const c_void,
) -> c_int {
    let tx = cast_pointer!(tx, MQTTTransaction);
    let ctx = cast_pointer!(ctx, u8);
    return mqtt_tx_has_qos(tx, *ctx);
}

unsafe extern "C" fn mqtt_qos_free(_de: *mut c_void, ctx: *mut c_void) {
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
    de: *mut c_void, s: *mut c_void, raw: *const libc::c_char,
) -> c_int {
    if DetectSignatureSetAppProto(s, ALPROTO_MQTT) != 0 {
        return -1;
    }
    let ctx = mqtt_parse_bool(raw) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    if SigMatchAppendSMToList(
        de,
        s,
        G_MQTT_CONNACK_SESSIONPRESENT_KW_ID,
        ctx,
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
    _de: *mut c_void, _f: *mut c_void, _flags: u8, _state: *mut c_void, tx: *mut c_void,
    _sig: *const c_void, ctx: *const c_void,
) -> c_int {
    let tx = cast_pointer!(tx, MQTTTransaction);
    let ctx = cast_pointer!(ctx, bool);
    return mqtt_tx_get_connack_sessionpresent(tx, *ctx);
}

unsafe extern "C" fn mqtt_connack_sessionpresent_free(_de: *mut c_void, ctx: *mut c_void) {
    std::mem::drop(Box::from_raw(ctx as *mut bool));
}

pub unsafe extern "C" fn mqtt_pub_topic_setup(
    de: *mut c_void, s: *mut c_void, _raw: *const std::os::raw::c_char,
) -> c_int {
    if DetectSignatureSetAppProto(s, ALPROTO_MQTT) != 0 {
        return -1;
    }
    if DetectBufferSetActiveList(de, s, G_MQTT_PUB_TOPIC_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

pub unsafe extern "C" fn mqtt_pub_topic_get_data(
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
        mqtt_tx_get_publish_topic,
    );
}

pub unsafe extern "C" fn mqtt_pub_msg_setup(
    de: *mut c_void, s: *mut c_void, _raw: *const std::os::raw::c_char,
) -> c_int {
    if DetectSignatureSetAppProto(s, ALPROTO_MQTT) != 0 {
        return -1;
    }
    if DetectBufferSetActiveList(de, s, G_MQTT_PUB_MSG_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

pub unsafe extern "C" fn mqtt_pub_msg_get_data(
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
        mqtt_tx_get_publish_message,
    );
}

unsafe extern "C" fn mqtt_protocol_version_setup(
    de: *mut c_void, s: *mut c_void, raw: *const libc::c_char,
) -> c_int {
    if DetectSignatureSetAppProto(s, ALPROTO_MQTT) != 0 {
        return -1;
    }
    let ctx = rs_detect_u8_parse(raw) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    if SigMatchAppendSMToList(
        de,
        s,
        G_MQTT_PROTOCOL_VERSION_KW_ID,
        ctx,
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
    _de: *mut c_void, _f: *mut c_void, _flags: u8, state: *mut c_void, _tx: *mut c_void,
    _sig: *const c_void, ctx: *const c_void,
) -> c_int {
    let state = cast_pointer!(state, MQTTState);
    let ctx = cast_pointer!(ctx, DetectUintData<u8>);
    if detect_match_uint(ctx, state.protocol_version) {
        return 1;
    }
    return 0;
}

unsafe extern "C" fn mqtt_protocol_version_free(_de: *mut c_void, ctx: *mut c_void) {
    let ctx = cast_pointer!(ctx, DetectUintData<u8>);
    rs_detect_u8_free(ctx);
}

// maybe to factor with websocket.flags
struct MqttParsedFlagItem {
    neg: bool,
    value: u8,
}

fn parse_flag_list_item(s: &str) -> IResult<&str, MqttParsedFlagItem> {
    let (s, _) = opt(is_a(" "))(s)?;
    let (s, neg) = opt(tag("!"))(s)?;
    let neg = neg.is_some();
    let (s, value) = alt((value(0x8, tag("dup")), value(0x1, tag("retain"))))(s)?;
    let (s, _) = opt(is_a(" ,"))(s)?;
    Ok((s, MqttParsedFlagItem { neg, value }))
}

fn parse_flag_list(s: &str) -> IResult<&str, Vec<MqttParsedFlagItem>> {
    return many1(parse_flag_list_item)(s);
}

fn parse_flags(s: &str) -> Option<DetectUintData<u8>> {
    // try first numerical value
    if let Ok((_, ctx)) = detect_parse_uint::<u8>(s) {
        return Some(ctx);
    }
    // otherwise, try strings for bitmask
    if let Ok((rem, l)) = parse_flag_list(s) {
        if !rem.is_empty() {
            SCLogWarning!("junk at the end of mqtt.flags");
            return None;
        }
        let mut arg1 = 0;
        let mut arg2 = 0;
        for elem in l.iter() {
            if elem.value & arg1 != 0 {
                SCLogWarning!("Repeated bitflag for mqtt.flags");
                return None;
            }
            arg1 |= elem.value;
            if !elem.neg {
                arg2 |= elem.value;
            }
        }
        let ctx = DetectUintData::<u8> {
            arg1,
            arg2,
            mode: DetectUintMode::DetectUintModeBitmask,
        };
        return Some(ctx);
    }
    return None;
}

unsafe extern "C" fn mqtt_parse_flags(
    ustr: *const std::os::raw::c_char,
) -> *mut DetectUintData<u8> {
    let ft_name: &CStr = CStr::from_ptr(ustr); //unsafe
    if let Ok(s) = ft_name.to_str() {
        if let Some(ctx) = parse_flags(s) {
            let boxed = Box::new(ctx);
            return Box::into_raw(boxed) as *mut _;
        }
    }
    return std::ptr::null_mut();
}

unsafe extern "C" fn mqtt_flags_setup(
    de: *mut c_void, s: *mut c_void, raw: *const libc::c_char,
) -> c_int {
    if DetectSignatureSetAppProto(s, ALPROTO_MQTT) != 0 {
        return -1;
    }
    let ctx = mqtt_parse_flags(raw) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    if SigMatchAppendSMToList(de, s, G_MQTT_FLAGS_KW_ID, ctx, G_MQTT_FLAGS_BUFFER_ID).is_null() {
        mqtt_flags_free(std::ptr::null_mut(), ctx);
        return -1;
    }
    return 0;
}

extern "C" fn rs_mqtt_tx_has_flags(tx: &MQTTTransaction, ctx: &DetectUintData<u8>) -> c_int {
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
    _de: *mut c_void, _f: *mut c_void, _flags: u8, _state: *mut c_void, tx: *mut c_void,
    _sig: *const c_void, ctx: *const c_void,
) -> c_int {
    let tx = cast_pointer!(tx, MQTTTransaction);
    let ctx = cast_pointer!(ctx, DetectUintData<u8>);
    return rs_mqtt_tx_has_flags(tx, ctx);
}

unsafe extern "C" fn mqtt_flags_free(_de: *mut c_void, ctx: *mut c_void) {
    let ctx = cast_pointer!(ctx, DetectUintData<u8>);
    rs_detect_u8_free(ctx);
}

fn parse_conn_flag_list_item(s: &str) -> IResult<&str, MqttParsedFlagItem> {
    let (s, _) = opt(is_a(" "))(s)?;
    let (s, neg) = opt(tag("!"))(s)?;
    let neg = neg.is_some();
    let (s, value) = alt((
        value(0x80, tag("username")),
        value(0x40, tag("password")),
        // longer version first
        value(0x4, tag("will_retain")),
        value(0x20, tag("will")),
        value(0x2, tag("clean_session")),
    ))(s)?;
    let (s, _) = opt(is_a(" ,"))(s)?;
    Ok((s, MqttParsedFlagItem { neg, value }))
}

fn parse_conn_flag_list(s: &str) -> IResult<&str, Vec<MqttParsedFlagItem>> {
    return many1(parse_conn_flag_list_item)(s);
}

fn parse_conn_flags(s: &str) -> Option<DetectUintData<u8>> {
    // try first numerical value
    if let Ok((_, ctx)) = detect_parse_uint::<u8>(s) {
        return Some(ctx);
    }
    // otherwise, try strings for bitmask
    if let Ok((rem, l)) = parse_conn_flag_list(s) {
        if !rem.is_empty() {
            SCLogWarning!("junk at the end of mqtt.connect.flags");
            return None;
        }
        let mut arg1 = 0;
        let mut arg2 = 0;
        for elem in l.iter() {
            if elem.value & arg1 != 0 {
                SCLogWarning!("Repeated bitflag for mqtt.connect.flags");
                return None;
            }
            arg1 |= elem.value;
            if !elem.neg {
                arg2 |= elem.value;
            }
        }
        let ctx = DetectUintData::<u8> {
            arg1,
            arg2,
            mode: DetectUintMode::DetectUintModeBitmask,
        };
        return Some(ctx);
    }
    return None;
}

unsafe extern "C" fn mqtt_parse_conn_flags(
    ustr: *const std::os::raw::c_char,
) -> *mut DetectUintData<u8> {
    let ft_name: &CStr = CStr::from_ptr(ustr); //unsafe
    if let Ok(s) = ft_name.to_str() {
        if let Some(ctx) = parse_conn_flags(s) {
            let boxed = Box::new(ctx);
            return Box::into_raw(boxed) as *mut _;
        }
    }
    return std::ptr::null_mut();
}

unsafe extern "C" fn mqtt_conn_flags_setup(
    de: *mut c_void, s: *mut c_void, raw: *const libc::c_char,
) -> c_int {
    if DetectSignatureSetAppProto(s, ALPROTO_MQTT) != 0 {
        return -1;
    }
    let ctx = mqtt_parse_conn_flags(raw) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    if SigMatchAppendSMToList(
        de,
        s,
        G_MQTT_CONN_FLAGS_KW_ID,
        ctx,
        G_MQTT_CONN_FLAGS_BUFFER_ID,
    )
    .is_null()
    {
        mqtt_conn_flags_free(std::ptr::null_mut(), ctx);
        return -1;
    }
    return 0;
}

fn rs_mqtt_tx_has_conn_flags(tx: &MQTTTransaction, ctx: &DetectUintData<u8>) -> c_int {
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
    _de: *mut c_void, _f: *mut c_void, _flags: u8, _state: *mut c_void, tx: *mut c_void,
    _sig: *const c_void, ctx: *const c_void,
) -> c_int {
    let tx = cast_pointer!(tx, MQTTTransaction);
    let ctx = cast_pointer!(ctx, DetectUintData<u8>);
    return rs_mqtt_tx_has_conn_flags(tx, ctx);
}

unsafe extern "C" fn mqtt_conn_flags_free(_de: *mut c_void, ctx: *mut c_void) {
    let ctx = cast_pointer!(ctx, DetectUintData<u8>);
    rs_detect_u8_free(ctx);
}

pub unsafe extern "C" fn mqtt_conn_willtopic_setup(
    de: *mut c_void, s: *mut c_void, _raw: *const std::os::raw::c_char,
) -> c_int {
    if DetectSignatureSetAppProto(s, ALPROTO_MQTT) != 0 {
        return -1;
    }
    if DetectBufferSetActiveList(de, s, G_MQTT_CONN_WILLTOPIC_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

pub unsafe extern "C" fn mqtt_conn_willtopic_get_data(
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
        mqtt_tx_get_connect_willtopic,
    );
}

pub unsafe extern "C" fn mqtt_conn_willmsg_setup(
    de: *mut c_void, s: *mut c_void, _raw: *const std::os::raw::c_char,
) -> c_int {
    if DetectSignatureSetAppProto(s, ALPROTO_MQTT) != 0 {
        return -1;
    }
    if DetectBufferSetActiveList(de, s, G_MQTT_CONN_WILLMSG_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

pub unsafe extern "C" fn mqtt_conn_willmsg_get_data(
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
        mqtt_tx_get_connect_willmessage,
    );
}

pub unsafe extern "C" fn mqtt_conn_username_setup(
    de: *mut c_void, s: *mut c_void, _raw: *const std::os::raw::c_char,
) -> c_int {
    if DetectSignatureSetAppProto(s, ALPROTO_MQTT) != 0 {
        return -1;
    }
    if DetectBufferSetActiveList(de, s, G_MQTT_CONN_USERNAME_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

pub unsafe extern "C" fn mqtt_conn_username_get_data(
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
        mqtt_tx_get_connect_username,
    );
}

pub unsafe extern "C" fn mqtt_conn_protocolstring_setup(
    de: *mut c_void, s: *mut c_void, _raw: *const std::os::raw::c_char,
) -> c_int {
    if DetectSignatureSetAppProto(s, ALPROTO_MQTT) != 0 {
        return -1;
    }
    if DetectBufferSetActiveList(de, s, G_MQTT_CONN_PROTOCOLSTRING_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

pub unsafe extern "C" fn mqtt_conn_protocolstring_get_data(
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
        mqtt_tx_get_connect_protocol_string,
    );
}

pub unsafe extern "C" fn mqtt_conn_password_setup(
    de: *mut c_void, s: *mut c_void, _raw: *const std::os::raw::c_char,
) -> c_int {
    if DetectSignatureSetAppProto(s, ALPROTO_MQTT) != 0 {
        return -1;
    }
    if DetectBufferSetActiveList(de, s, G_MQTT_CONN_PASSWORD_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

pub unsafe extern "C" fn mqtt_conn_password_get_data(
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
        mqtt_tx_get_connect_password,
    );
}

pub unsafe extern "C" fn mqtt_conn_clientid_setup(
    de: *mut c_void, s: *mut c_void, _raw: *const std::os::raw::c_char,
) -> c_int {
    if DetectSignatureSetAppProto(s, ALPROTO_MQTT) != 0 {
        return -1;
    }
    if DetectBufferSetActiveList(de, s, G_MQTT_CONN_CLIENTID_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

pub unsafe extern "C" fn mqtt_conn_clientid_get_data(
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
        mqtt_tx_get_connect_clientid,
    );
}

#[no_mangle]
pub unsafe extern "C" fn ScDetectMqttRegister() {
    let keyword_name = b"mqtt.unsubscribe.topic\0".as_ptr() as *const libc::c_char;
    let kw = SCSigTableElmt {
        name: keyword_name,
        desc: b"sticky buffer to match MQTT UNSUBSCRIBE topic\0".as_ptr() as *const libc::c_char,
        url: b"/rules/mqtt-keywords.html#mqtt-unsubscribe-topic\0".as_ptr() as *const libc::c_char,
        Setup: unsub_topic_setup,
        flags: SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER,
        AppLayerTxMatch: None,
        Free: None,
    };
    if let Some(val) = conf_get("app-layer.protocols.mqtt.unsubscribe-topic-match-limit") {
        if let Ok(v) = val.parse::<isize>() {
            UNSUB_TOPIC_MATCH_LIMIT = v;
        } else {
            SCLogError!("Invalid value for app-layer.protocols.mqtt.unsubscribe-topic-match-limit");
        }
    }
    let _g_mqtt_unsub_topic_kw_id = DetectHelperKeywordRegister(&kw);
    DetectAppLayerMultiRegister(
        keyword_name,
        ALPROTO_MQTT,
        SIG_FLAG_TOSERVER,
        0,
        unsub_topic_get_data_wrapper,
        2,
        0,
    );
    DetectBufferTypeSetDescriptionByName(
        keyword_name,
        b"unsubscribe topic query\0".as_ptr() as *const libc::c_char,
    );
    DetectBufferTypeSupportsMultiInstance(keyword_name);
    G_MQTT_UNSUB_TOPIC_BUFFER_ID = DetectBufferTypeGetByName(keyword_name);

    let kw = SCSigTableElmt {
        name: b"mqtt.type\0".as_ptr() as *const libc::c_char,
        desc: b"match MQTT control packet type\0".as_ptr() as *const libc::c_char,
        url: b"/rules/mqtt-keywords.html#mqtt-type\0".as_ptr() as *const libc::c_char,
        AppLayerTxMatch: Some(mqtt_type_match),
        Setup: mqtt_type_setup,
        Free: Some(mqtt_type_free),
        flags: 0,
    };
    G_MQTT_TYPE_KW_ID = DetectHelperKeywordRegister(&kw);
    G_MQTT_TYPE_BUFFER_ID = DetectHelperBufferRegister(
        b"mqtt.type\0".as_ptr() as *const libc::c_char,
        ALPROTO_MQTT,
        false, // only to server
        true,
    );

    let keyword_name = b"mqtt.subscribe.topic\0".as_ptr() as *const libc::c_char;
    let kw = SCSigTableElmt {
        name: keyword_name,
        desc: b"sticky buffer to match MQTT SUBSCRIBE topic\0".as_ptr() as *const libc::c_char,
        url: b"/rules/mqtt-keywords.html#mqtt-subscribe-topic\0".as_ptr() as *const libc::c_char,
        Setup: sub_topic_setup,
        flags: SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER,
        AppLayerTxMatch: None,
        Free: None,
    };
    if let Some(val) = conf_get("app-layer.protocols.mqtt.subscribe-topic-match-limit") {
        if let Ok(v) = val.parse::<isize>() {
            SUB_TOPIC_MATCH_LIMIT = v;
        } else {
            SCLogError!("Invalid value for app-layer.protocols.mqtt.subscribe-topic-match-limit");
        }
    }
    let _g_mqtt_sub_topic_kw_id = DetectHelperKeywordRegister(&kw);
    DetectAppLayerMultiRegister(
        keyword_name,
        ALPROTO_MQTT,
        SIG_FLAG_TOSERVER,
        0,
        sub_topic_get_data_wrapper,
        2,
        0,
    );
    DetectBufferTypeSetDescriptionByName(
        keyword_name,
        b"subscribe topic query\0".as_ptr() as *const libc::c_char,
    );
    DetectBufferTypeSupportsMultiInstance(keyword_name);
    G_MQTT_SUB_TOPIC_BUFFER_ID = DetectBufferTypeGetByName(keyword_name);

    let kw = SCSigTableElmt {
        name: b"mqtt.reason_code\0".as_ptr() as *const libc::c_char,
        desc: b"match MQTT 5.0+ reason code\0".as_ptr() as *const libc::c_char,
        //TODO alias "mqtt.connack.return_code"
        url: b"/rules/mqtt-keywords.html#mqtt-reason-code\0".as_ptr() as *const libc::c_char,
        AppLayerTxMatch: Some(mqtt_reason_code_match),
        Setup: mqtt_reason_code_setup,
        Free: Some(mqtt_reason_code_free),
        flags: 0,
    };
    G_MQTT_REASON_CODE_KW_ID = DetectHelperKeywordRegister(&kw);
    G_MQTT_REASON_CODE_BUFFER_ID = DetectHelperBufferRegister(
        b"mqtt.reason_code\0".as_ptr() as *const libc::c_char,
        ALPROTO_MQTT,
        false, // only to server
        true,
    );
    let kw = SCSigTableElmt {
        name: b"mqtt.connack.session_present\0".as_ptr() as *const libc::c_char,
        desc: b"match MQTT CONNACK session present flag\0".as_ptr() as *const libc::c_char,
        url: b"/rules/mqtt-keywords.html#mqtt-connack-session-present\0".as_ptr()
            as *const libc::c_char,
        AppLayerTxMatch: Some(mqtt_connack_sessionpresent_match),
        Setup: mqtt_connack_sessionpresent_setup,
        Free: Some(mqtt_connack_sessionpresent_free),
        flags: 0,
    };
    G_MQTT_CONNACK_SESSIONPRESENT_KW_ID = DetectHelperKeywordRegister(&kw);
    G_MQTT_CONNACK_SESSIONPRESENT_BUFFER_ID = DetectHelperBufferRegister(
        b"mqtt.connack.session_present\0".as_ptr() as *const libc::c_char,
        ALPROTO_MQTT,
        false, // only to server
        true,
    );
    let kw = SCSigTableElmt {
        name: b"mqtt.qos\0".as_ptr() as *const libc::c_char,
        desc: b"match MQTT fixed header QOS level\0".as_ptr() as *const libc::c_char,
        //TODO alias "mqtt.connack.return_code"
        url: b"/rules/mqtt-keywords.html#mqtt-qos\0".as_ptr() as *const libc::c_char,
        AppLayerTxMatch: Some(mqtt_qos_match),
        Setup: mqtt_qos_setup,
        Free: Some(mqtt_qos_free),
        flags: 0,
    };
    G_MQTT_QOS_KW_ID = DetectHelperKeywordRegister(&kw);
    G_MQTT_QOS_BUFFER_ID = DetectHelperBufferRegister(
        b"mqtt.qos\0".as_ptr() as *const libc::c_char,
        ALPROTO_MQTT,
        false, // only to server
        true,
    );
    let kw = SCSigTableElmt {
        name: b"mqtt.publish.topic\0".as_ptr() as *const libc::c_char,
        desc: b"sticky buffer to match on the MQTT PUBLISH topic\0".as_ptr() as *const libc::c_char,
        url: b"mqtt-keywords.html#mqtt-publish-topic\0".as_ptr() as *const libc::c_char,
        Setup: mqtt_pub_topic_setup,
        flags: SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER,
        AppLayerTxMatch: None,
        Free: None,
    };
    let _g_mqtt_pub_topic_kw_id = DetectHelperKeywordRegister(&kw);
    G_MQTT_PUB_TOPIC_BUFFER_ID = DetectHelperBufferMpmRegister(
        b"mqtt.publish.topic\0".as_ptr() as *const libc::c_char,
        b"MQTT PUBLISH topic\0".as_ptr() as *const libc::c_char,
        ALPROTO_MQTT,
        false,
        true,
        mqtt_pub_topic_get_data,
    );
    let kw = SCSigTableElmt {
        name: b"mqtt.publish.message\0".as_ptr() as *const libc::c_char,
        desc: b"sticky buffer to match on the MQTT PUBLISH message\0".as_ptr()
            as *const libc::c_char,
        url: b"mqtt-keywords.html#mqtt-publish-message\0".as_ptr() as *const libc::c_char,
        Setup: mqtt_pub_msg_setup,
        flags: SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER,
        AppLayerTxMatch: None,
        Free: None,
    };
    let _g_mqtt_pub_msg_kw_id = DetectHelperKeywordRegister(&kw);
    G_MQTT_PUB_MSG_BUFFER_ID = DetectHelperBufferMpmRegister(
        b"mqtt.publish.message\0".as_ptr() as *const libc::c_char,
        b"MQTT PUBLISH message\0".as_ptr() as *const libc::c_char,
        ALPROTO_MQTT,
        false,
        true,
        mqtt_pub_msg_get_data,
    );
    let kw = SCSigTableElmt {
        name: b"mqtt.protocol_version\0".as_ptr() as *const libc::c_char,
        desc: b"match MQTT protocol version\0".as_ptr() as *const libc::c_char,
        url: b"/rules/mqtt-keywords.html#mqtt-protocol-version\0".as_ptr() as *const libc::c_char,
        AppLayerTxMatch: Some(mqtt_protocol_version_match),
        Setup: mqtt_protocol_version_setup,
        Free: Some(mqtt_protocol_version_free),
        flags: 0,
    };
    G_MQTT_PROTOCOL_VERSION_KW_ID = DetectHelperKeywordRegister(&kw);
    G_MQTT_PROTOCOL_VERSION_BUFFER_ID = DetectHelperBufferRegister(
        b"mqtt.protocol_version\0".as_ptr() as *const libc::c_char,
        ALPROTO_MQTT,
        false, // only to server
        true,
    );
    let kw = SCSigTableElmt {
        name: b"mqtt.flags\0".as_ptr() as *const libc::c_char,
        desc: b"match MQTT fixed header flags\0".as_ptr() as *const libc::c_char,
        url: b"/rules/mqtt-keywords.html#mqtt-flags\0".as_ptr() as *const libc::c_char,
        AppLayerTxMatch: Some(mqtt_flags_match),
        Setup: mqtt_flags_setup,
        Free: Some(mqtt_flags_free),
        flags: 0,
    };
    G_MQTT_FLAGS_KW_ID = DetectHelperKeywordRegister(&kw);
    G_MQTT_FLAGS_BUFFER_ID = DetectHelperBufferRegister(
        b"mqtt.flags\0".as_ptr() as *const libc::c_char,
        ALPROTO_MQTT,
        false, // only to server
        true,
    );
    let kw = SCSigTableElmt {
        name: b"mqtt.connect.flags\0".as_ptr() as *const libc::c_char,
        desc: b"match MQTT CONNECT variable header flags\0".as_ptr() as *const libc::c_char,
        url: b"/rules/mqtt-keywords.html#mqtt-connect-flags\0".as_ptr() as *const libc::c_char,
        AppLayerTxMatch: Some(mqtt_conn_flags_match),
        Setup: mqtt_conn_flags_setup,
        Free: Some(mqtt_conn_flags_free),
        flags: 0,
    };
    G_MQTT_CONN_FLAGS_KW_ID = DetectHelperKeywordRegister(&kw);
    G_MQTT_CONN_FLAGS_BUFFER_ID = DetectHelperBufferRegister(
        b"mqtt.connect.flags\0".as_ptr() as *const libc::c_char,
        ALPROTO_MQTT,
        false, // only to server
        true,
    );
    let kw = SCSigTableElmt {
        name: b"mqtt.connect.willtopic\0".as_ptr() as *const libc::c_char,
        desc: b"sticky buffer to match on the MQTT CONNECT will topic\0".as_ptr()
            as *const libc::c_char,
        url: b"mqtt-keywords.html#mqtt-connect-willtopic\0".as_ptr() as *const libc::c_char,
        Setup: mqtt_conn_willtopic_setup,
        flags: SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER,
        AppLayerTxMatch: None,
        Free: None,
    };
    let _g_mqtt_conn_willtopic_kw_id = DetectHelperKeywordRegister(&kw);
    G_MQTT_CONN_WILLTOPIC_BUFFER_ID = DetectHelperBufferMpmRegister(
        b"mqtt.connect.willtopic\0".as_ptr() as *const libc::c_char,
        b"MQTT CONNECT will topic\0".as_ptr() as *const libc::c_char,
        ALPROTO_MQTT,
        false,
        true,
        mqtt_conn_willtopic_get_data,
    );
    let kw = SCSigTableElmt {
        name: b"mqtt.connect.willmessage\0".as_ptr() as *const libc::c_char,
        desc: b"sticky buffer to match on the MQTT CONNECT will message\0".as_ptr()
            as *const libc::c_char,
        url: b"mqtt-keywords.html#mqtt-connect-willmessage\0".as_ptr() as *const libc::c_char,
        Setup: mqtt_conn_willmsg_setup,
        flags: SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER,
        AppLayerTxMatch: None,
        Free: None,
    };
    let _g_mqtt_conn_willmsg_kw_id = DetectHelperKeywordRegister(&kw);
    G_MQTT_CONN_WILLMSG_BUFFER_ID = DetectHelperBufferMpmRegister(
        b"mqtt.connect.willmessage\0".as_ptr() as *const libc::c_char,
        b"MQTT CONNECT will message\0".as_ptr() as *const libc::c_char,
        ALPROTO_MQTT,
        false,
        true,
        mqtt_conn_willtopic_get_data,
    );
    let kw = SCSigTableElmt {
        name: b"mqtt.connect.username\0".as_ptr() as *const libc::c_char,
        desc: b"sticky buffer to match on the MQTT CONNECT username\0".as_ptr()
            as *const libc::c_char,
        url: b"mqtt-keywords.html#mqtt-connect-username\0".as_ptr() as *const libc::c_char,
        Setup: mqtt_conn_username_setup,
        flags: SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER,
        AppLayerTxMatch: None,
        Free: None,
    };
    let _g_mqtt_conn_username_kw_id = DetectHelperKeywordRegister(&kw);
    G_MQTT_CONN_USERNAME_BUFFER_ID = DetectHelperBufferMpmRegister(
        b"mqtt.connect.username\0".as_ptr() as *const libc::c_char,
        b"MQTT CONNECT username\0".as_ptr() as *const libc::c_char,
        ALPROTO_MQTT,
        false,
        true,
        mqtt_conn_username_get_data,
    );
    let kw = SCSigTableElmt {
        name: b"mqtt.connect.protocol_string\0".as_ptr() as *const libc::c_char,
        desc: b"sticky buffer to match on the MQTT CONNECT protocol string\0".as_ptr()
            as *const libc::c_char,
        url: b"mqtt-keywords.html#mqtt-connect-protocol_string\0".as_ptr() as *const libc::c_char,
        Setup: mqtt_conn_protocolstring_setup,
        flags: SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER,
        AppLayerTxMatch: None,
        Free: None,
    };
    let _g_mqtt_conn_protostr_kw_id = DetectHelperKeywordRegister(&kw);
    G_MQTT_CONN_PROTOCOLSTRING_BUFFER_ID = DetectHelperBufferMpmRegister(
        b"mqtt.connect.protocol_string\0".as_ptr() as *const libc::c_char,
        b"MQTT CONNECT protocol string\0".as_ptr() as *const libc::c_char,
        ALPROTO_MQTT,
        false,
        true,
        mqtt_conn_protocolstring_get_data,
    );
    let kw = SCSigTableElmt {
        name: b"mqtt.connect.password\0".as_ptr() as *const libc::c_char,
        desc: b"sticky buffer to match on the MQTT CONNECT password\0".as_ptr()
            as *const libc::c_char,
        url: b"mqtt-keywords.html#mqtt-connect-password\0".as_ptr() as *const libc::c_char,
        Setup: mqtt_conn_password_setup,
        flags: SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER,
        AppLayerTxMatch: None,
        Free: None,
    };
    let _g_mqtt_conn_password_kw_id = DetectHelperKeywordRegister(&kw);
    G_MQTT_CONN_PASSWORD_BUFFER_ID = DetectHelperBufferMpmRegister(
        b"mqtt.connect.password\0".as_ptr() as *const libc::c_char,
        b"MQTT CONNECT password\0".as_ptr() as *const libc::c_char,
        ALPROTO_MQTT,
        false,
        true,
        mqtt_conn_password_get_data,
    );
    let kw = SCSigTableElmt {
        name: b"mqtt.connect.clientid\0".as_ptr() as *const libc::c_char,
        desc: b"sticky buffer to match on the MQTT CONNECT clientid\0".as_ptr()
            as *const libc::c_char,
        url: b"mqtt-keywords.html#mqtt-connect-clientid\0".as_ptr() as *const libc::c_char,
        Setup: mqtt_conn_clientid_setup,
        flags: SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER,
        AppLayerTxMatch: None,
        Free: None,
    };
    let _g_mqtt_conn_password_kw_id = DetectHelperKeywordRegister(&kw);
    G_MQTT_CONN_CLIENTID_BUFFER_ID = DetectHelperBufferMpmRegister(
        b"mqtt.connect.clientid\0".as_ptr() as *const libc::c_char,
        b"MQTT CONNECT clientid\0".as_ptr() as *const libc::c_char,
        ALPROTO_MQTT,
        false,
        true,
        mqtt_conn_clientid_get_data,
    );
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::core::Direction;
    use crate::detect::uint::DetectUintMode;
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
        let ctx = parse_flags("retain").unwrap();
        assert_eq!(ctx.arg1, 1);
        assert_eq!(ctx.arg2, 1);
        let ctx = parse_flags("dup").unwrap();
        assert_eq!(ctx.arg1, 8);
        assert_eq!(ctx.arg2, 8);
        let ctx = parse_flags("retain,dup").unwrap();
        assert_eq!(ctx.arg1, 8 | 1);
        assert_eq!(ctx.arg2, 8 | 1);
        let ctx = parse_flags("dup, retain").unwrap();
        assert_eq!(ctx.arg1, 8 | 1);
        assert_eq!(ctx.arg2, 8 | 1);
        let ctx = parse_flags("retain,!dup").unwrap();
        assert_eq!(ctx.arg1, 1 | 8);
        assert_eq!(ctx.arg2, 1);
        assert!(parse_flags("ref").is_none());
        assert!(parse_flags("dup,!").is_none());
        assert!(parse_flags("dup,!dup").is_none());
        assert!(parse_flags("!retain,retain").is_none());
    }

    #[test]
    fn mqtt_parse_conn_flags() {
        let ctx = parse_conn_flags("username").unwrap();
        assert_eq!(ctx.arg1, 0x80);
        assert_eq!(ctx.arg2, 0x80);
        let ctx = parse_conn_flags("username,password,will,will_retain,clean_session").unwrap();
        assert_eq!(ctx.arg1, 0xE6);
        assert_eq!(ctx.arg2, 0xE6);
        let ctx =
            parse_conn_flags("!username,!password,!will,!will_retain,!clean_session").unwrap();
        assert_eq!(ctx.arg1, 0xE6);
        assert_eq!(ctx.arg2, 0);
        let ctx = parse_conn_flags("   username,password").unwrap();
        assert_eq!(ctx.arg1, 0xC0);
        assert_eq!(ctx.arg2, 0xC0);
        assert!(parse_conn_flags("foobar").is_none());
        assert!(parse_conn_flags("will,!").is_none());
        assert!(parse_conn_flags("").is_none());
        assert!(parse_conn_flags("username, username").is_none());
        assert!(parse_conn_flags("!username, username").is_none());
        assert!(parse_conn_flags("!username,password,!password").is_none());
        assert!(parse_conn_flags("will, username,password,   !will, will").is_none());
    }

    #[test]
    fn mqtt_type_test_parse() {
        let ctx = detect_parse_uint_enum::<u8, MQTTTypeCode>("CONNECT").unwrap();
        assert_eq!(ctx.arg1, 1);
        assert_eq!(ctx.mode, DetectUintMode::DetectUintModeEqual);
        let ctx = detect_parse_uint_enum::<u8, MQTTTypeCode>("PINGRESP").unwrap();
        assert_eq!(ctx.arg1, 13);
        assert_eq!(ctx.mode, DetectUintMode::DetectUintModeEqual);
        let ctx = detect_parse_uint_enum::<u8, MQTTTypeCode>("auth").unwrap();
        assert_eq!(ctx.arg1, 15);
        assert_eq!(ctx.mode, DetectUintMode::DetectUintModeEqual);
        assert!(detect_parse_uint_enum::<u8, MQTTTypeCode>("invalidopt").is_none());
        let ctx = detect_parse_uint_enum::<u8, MQTTTypeCode>("unassigned").unwrap();
        assert_eq!(ctx.arg1, 0);
        assert_eq!(ctx.mode, DetectUintMode::DetectUintModeEqual);
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
        let mut r = unsafe { unsub_topic_get_data(tx, 0, 0, &mut s, &mut slen) };
        assert!(r);
        let mut topic = String::from_utf8_lossy(unsafe { build_slice!(s, slen as usize) });
        assert_eq!(topic, "foo");
        r = unsafe { unsub_topic_get_data(tx, 0, 1, &mut s, &mut slen) };
        assert!(r);
        topic = String::from_utf8_lossy(unsafe { build_slice!(s, slen as usize) });
        assert_eq!(topic, "baar");
        r = unsafe { unsub_topic_get_data(tx, 0, 2, &mut s, &mut slen) };
        assert!(r);
        topic = String::from_utf8_lossy(unsafe { build_slice!(s, slen as usize) });
        assert_eq!(topic, "fieee");
        r = unsafe { unsub_topic_get_data(tx, 0, 3, &mut s, &mut slen) };
        assert!(r);
        topic = String::from_utf8_lossy(unsafe { build_slice!(s, slen as usize) });
        assert_eq!(topic, "baaaaz");
        r = unsafe { unsub_topic_get_data(tx, 0, 4, &mut s, &mut slen) };
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
        let mut r = unsafe { sub_topic_get_data(tx, 0, 0, &mut s, &mut slen) };
        assert!(r);
        let mut topic = String::from_utf8_lossy(unsafe { build_slice!(s, slen as usize) });
        assert_eq!(topic, "foo");
        r = unsafe { sub_topic_get_data(tx, 0, 1, &mut s, &mut slen) };
        assert!(r);
        topic = String::from_utf8_lossy(unsafe { build_slice!(s, slen as usize) });
        assert_eq!(topic, "baar");
        r = unsafe { sub_topic_get_data(tx, 0, 2, &mut s, &mut slen) };
        assert!(r);
        topic = String::from_utf8_lossy(unsafe { build_slice!(s, slen as usize) });
        assert_eq!(topic, "fieee");
        r = unsafe { sub_topic_get_data(tx, 0, 3, &mut s, &mut slen) };
        assert!(r);
        topic = String::from_utf8_lossy(unsafe { build_slice!(s, slen as usize) });
        assert_eq!(topic, "baaaaz");
        r = unsafe { sub_topic_get_data(tx, 0, 4, &mut s, &mut slen) };
        assert!(!r);
    }
}
