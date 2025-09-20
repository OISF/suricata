/* Copyright (C) 2019-2024 Open Information Security Foundation
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

use super::dns::{
    DNSAnswerEntry, DNSQueryEntry, DNSRcode, DNSRecordType, DNSTransaction, ALPROTO_DNS,
};
use crate::core::{STREAM_TOCLIENT, STREAM_TOSERVER};
use crate::detect::uint::{
    detect_match_uint, detect_parse_array_uint_enum, detect_parse_uint_enum,
    detect_uint_match_at_index, DetectUintArrayData, DetectUintData, SCDetectU16Free,
    SCDetectU8Free, SCDetectU8Parse,
};
use crate::detect::{
    helper_keyword_register_multi_buffer, SigTableElmtStickyBuffer, SIGMATCH_INFO_ENUM_UINT,
    SIGMATCH_INFO_MULTI_UINT, SIGMATCH_INFO_UINT16, SIGMATCH_INFO_UINT8,
};
use crate::direction::Direction;
use std::ffi::CStr;
use std::os::raw::{c_int, c_void};
use suricata_sys::sys::{
    DetectEngineCtx, DetectEngineThreadCtx, Flow, SCDetectBufferSetActiveList,
    SCDetectHelperBufferRegister, SCDetectHelperKeywordAliasRegister,
    SCDetectHelperKeywordRegister, SCDetectHelperMultiBufferProgressMpmRegister,
    SCDetectSignatureSetAppProto, SCSigMatchAppendSMToList, SCSigTableAppLiteElmt, SigMatchCtx,
    Signature,
};

/// Perform the DNS opcode match.
///
/// 1 will be returned on match, otherwise 0 will be returned.
unsafe extern "C" fn dns_opcode_match(
    _de: *mut DetectEngineThreadCtx, _f: *mut Flow, flags: u8, _state: *mut c_void,
    tx: *mut c_void, _sig: *const Signature, ctx: *const SigMatchCtx,
) -> c_int {
    let tx = cast_pointer!(tx, DNSTransaction);
    let ctx = cast_pointer!(ctx, DetectUintData<u8>);
    let header_flags = if flags & Direction::ToServer as u8 != 0 {
        if let Some(request) = &tx.request {
            request.header.flags
        } else {
            return 0;
        }
    } else if flags & Direction::ToClient as u8 != 0 {
        if let Some(response) = &tx.response {
            response.header.flags
        } else {
            return 0;
        }
    } else {
        // Not to server or to client??
        return 0;
    };
    let opcode = ((header_flags >> 11) & 0xf) as u8;

    if detect_match_uint(ctx, opcode) {
        return 1;
    }
    return 0;
}

/// Perform the DNS rcode match.
///
/// 1 will be returned on match, otherwise 0 will be returned.
unsafe extern "C" fn dns_rcode_match(
    _de: *mut DetectEngineThreadCtx, _f: *mut Flow, flags: u8, _state: *mut c_void,
    tx: *mut c_void, _sig: *const Signature, ctx: *const SigMatchCtx,
) -> c_int {
    let tx = cast_pointer!(tx, DNSTransaction);
    let ctx = cast_pointer!(ctx, DetectUintData<u16>);
    let header_flags = if flags & Direction::ToServer as u8 != 0 {
        if let Some(request) = &tx.request {
            request.header.flags
        } else {
            return 0;
        }
    } else if let Some(response) = &tx.response {
        response.header.flags
    } else {
        return 0;
    };

    let rcode = header_flags & 0xf;

    if detect_match_uint(ctx, rcode) {
        return 1;
    }
    return 0;
}

/// Perform the DNS rrtype match.
/// 1 will be returned on match, otherwise 0 will be returned.
unsafe extern "C" fn dns_rrtype_match(
    _de: *mut DetectEngineThreadCtx, _f: *mut Flow, flags: u8, _state: *mut c_void,
    tx: *mut c_void, _sig: *const Signature, ctx: *const SigMatchCtx,
) -> c_int {
    let tx = cast_pointer!(tx, DNSTransaction);
    let ctx = cast_pointer!(ctx, DetectUintArrayData<u16>);

    if flags & Direction::ToServer as u8 != 0 {
        if let Some(request) = &tx.request {
            return detect_uint_match_at_index::<DNSQueryEntry, u16>(
                &request.queries,
                ctx,
                |q| Some(q.rrtype),
                true,
            );
        }
    } else if flags & Direction::ToClient as u8 != 0 {
        if let Some(response) = &tx.response {
            return detect_uint_match_at_index::<DNSAnswerEntry, u16>(
                &response.answers,
                ctx,
                |a| Some(a.rrtype),
                true,
            );
        }
    }
    return 0;
}

static mut G_DNS_ANSWER_NAME_BUFFER_ID: c_int = 0;
static mut G_DNS_QUERY_NAME_BUFFER_ID: c_int = 0;
static mut G_DNS_QUERY_BUFFER_ID: c_int = 0;
static mut G_DNS_OPCODE_KW_ID: u16 = 0;
static mut G_DNS_OPCODE_BUFFER_ID: c_int = 0;
static mut G_DNS_RCODE_KW_ID: u16 = 0;
static mut G_DNS_RCODE_BUFFER_ID: c_int = 0;
static mut G_DNS_RRTYPE_KW_ID: u16 = 0;
static mut G_DNS_RRTYPE_BUFFER_ID: c_int = 0;

unsafe extern "C" fn dns_opcode_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, raw: *const libc::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_DNS) != 0 {
        return -1;
    }
    let ctx = SCDetectU8Parse(raw) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    if SCSigMatchAppendSMToList(
        de,
        s,
        G_DNS_OPCODE_KW_ID,
        ctx as *mut SigMatchCtx,
        G_DNS_OPCODE_BUFFER_ID,
    )
    .is_null()
    {
        dns_opcode_free(std::ptr::null_mut(), ctx);
        return -1;
    }
    return 0;
}

unsafe extern "C" fn dns_opcode_free(_de: *mut DetectEngineCtx, ctx: *mut c_void) {
    // Just unbox...
    let ctx = cast_pointer!(ctx, DetectUintData<u8>);
    SCDetectU8Free(ctx);
}

unsafe extern "C" fn dns_rcode_parse(ustr: *const std::os::raw::c_char) -> *mut DetectUintData<u8> {
    let ft_name: &CStr = CStr::from_ptr(ustr); //unsafe
    if let Ok(s) = ft_name.to_str() {
        if let Some(ctx) = detect_parse_uint_enum::<u16, DNSRcode>(s) {
            let boxed = Box::new(ctx);
            return Box::into_raw(boxed) as *mut _;
        }
    }
    return std::ptr::null_mut();
}

unsafe extern "C" fn dns_rcode_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, raw: *const libc::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_DNS) != 0 {
        return -1;
    }
    let ctx = dns_rcode_parse(raw) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    if SCSigMatchAppendSMToList(
        de,
        s,
        G_DNS_RCODE_KW_ID,
        ctx as *mut SigMatchCtx,
        G_DNS_RCODE_BUFFER_ID,
    )
    .is_null()
    {
        dns_rcode_free(std::ptr::null_mut(), ctx);
        return -1;
    }
    return 0;
}

unsafe extern "C" fn dns_rcode_free(_de: *mut DetectEngineCtx, ctx: *mut c_void) {
    // Just unbox...
    let ctx = cast_pointer!(ctx, DetectUintData<u16>);
    SCDetectU16Free(ctx);
}

unsafe extern "C" fn dns_rrtype_parse(
    ustr: *const std::os::raw::c_char,
) -> *mut DetectUintArrayData<u16> {
    let ft_name: &CStr = CStr::from_ptr(ustr); //unsafe
    if let Ok(s) = ft_name.to_str() {
        if let Some(ctx) = detect_parse_array_uint_enum::<u16, DNSRecordType>(s) {
            let boxed = Box::new(ctx);
            return Box::into_raw(boxed) as *mut _;
        }
    }
    return std::ptr::null_mut();
}

unsafe extern "C" fn dns_rrtype_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, raw: *const libc::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_DNS) != 0 {
        return -1;
    }
    let ctx = dns_rrtype_parse(raw) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    if SCSigMatchAppendSMToList(
        de,
        s,
        G_DNS_RRTYPE_KW_ID,
        ctx as *mut SigMatchCtx,
        G_DNS_RRTYPE_BUFFER_ID,
    )
    .is_null()
    {
        dns_rrtype_free(std::ptr::null_mut(), ctx);
        return -1;
    }
    return 0;
}

unsafe extern "C" fn dns_rrtype_free(_de: *mut DetectEngineCtx, ctx: *mut c_void) {
    let ctx = cast_pointer!(ctx, DetectUintArrayData<u16>);
    std::mem::drop(Box::from_raw(ctx));
}

unsafe extern "C" fn dns_detect_answer_name_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_DNS) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_DNS_ANSWER_NAME_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

/// Get the DNS response answer name and index i.
pub(crate) unsafe extern "C" fn dns_tx_get_answer_name(
    _de: *mut DetectEngineThreadCtx, tx: *const c_void, flags: u8, i: u32, buf: *mut *const u8,
    len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, DNSTransaction);
    let answers = if flags & Direction::ToClient as u8 != 0 {
        tx.response.as_ref().map(|response| &response.answers)
    } else {
        tx.request.as_ref().map(|request| &request.answers)
    };
    let index = i as usize;

    if let Some(answers) = answers {
        if let Some(answer) = answers.get(index) {
            if !answer.name.value.is_empty() {
                *buf = answer.name.value.as_ptr();
                *len = answer.name.value.len() as u32;
                return true;
            }
        }
    }

    false
}

unsafe extern "C" fn dns_detect_query_name_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_DNS) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_DNS_QUERY_NAME_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

/// Get the DNS response answer name and index i.
pub(crate) unsafe extern "C" fn dns_tx_get_query_name(
    _de: *mut DetectEngineThreadCtx, tx: *const c_void, flags: u8, i: u32, buf: *mut *const u8,
    len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, DNSTransaction);
    let queries = if flags & Direction::ToClient as u8 != 0 {
        tx.response.as_ref().map(|response| &response.queries)
    } else {
        tx.request.as_ref().map(|request| &request.queries)
    };
    let index = i as usize;

    if let Some(queries) = queries {
        if let Some(query) = queries.get(index) {
            if !query.name.value.is_empty() {
                *buf = query.name.value.as_ptr();
                *len = query.name.value.len() as u32;
                return true;
            }
        }
    }

    false
}

unsafe extern "C" fn dns_tx_get_query(
    _de: *mut DetectEngineThreadCtx, tx: *const c_void, _flags: u8, i: u32, buf: *mut *const u8,
    len: *mut u32,
) -> bool {
    return dns_tx_get_query_name(_de, tx, Direction::ToServer as u8, i, buf, len);
}

unsafe extern "C" fn dns_detect_query_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_DNS) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_DNS_QUERY_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectDNSRegister() {
    let kw = SigTableElmtStickyBuffer {
        name: String::from("dns.answer.name"),
        desc: String::from("DNS answer name sticky buffer"),
        url: String::from("/rules/dns-keywords.html#dns-answer-name"),
        setup: dns_detect_answer_name_setup,
    };
    let _g_dns_answer_name_kw_id = helper_keyword_register_multi_buffer(&kw);
    G_DNS_ANSWER_NAME_BUFFER_ID = SCDetectHelperMultiBufferProgressMpmRegister(
        b"dns.answer.name\0".as_ptr() as *const libc::c_char,
        b"dns answer name\0".as_ptr() as *const libc::c_char,
        ALPROTO_DNS,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        /* Register also in the TO_SERVER direction, even though this is not
        normal, it could be provided as part of a request. */
        Some(dns_tx_get_answer_name),
        1, // response complete
    );
    let kw = SCSigTableAppLiteElmt {
        name: b"dns.opcode\0".as_ptr() as *const libc::c_char,
        desc: b"Match the DNS header opcode flag.\0".as_ptr() as *const libc::c_char,
        url: b"rules/dns-keywords.html#dns-opcode\0".as_ptr() as *const libc::c_char,
        AppLayerTxMatch: Some(dns_opcode_match),
        Setup: Some(dns_opcode_setup),
        Free: Some(dns_opcode_free),
        flags: SIGMATCH_INFO_UINT8,
    };
    G_DNS_OPCODE_KW_ID = SCDetectHelperKeywordRegister(&kw);
    G_DNS_OPCODE_BUFFER_ID = SCDetectHelperBufferRegister(
        b"dns.opcode\0".as_ptr() as *const libc::c_char,
        ALPROTO_DNS,
        STREAM_TOSERVER | STREAM_TOCLIENT,
    );
    let kw = SigTableElmtStickyBuffer {
        name: String::from("dns.query.name"),
        desc: String::from("DNS query name sticky buffer"),
        url: String::from("/rules/dns-keywords.html#dns-query-name"),
        setup: dns_detect_query_name_setup,
    };
    let _g_dns_query_name_kw_id = helper_keyword_register_multi_buffer(&kw);
    G_DNS_QUERY_NAME_BUFFER_ID = SCDetectHelperMultiBufferProgressMpmRegister(
        b"dns.query.name\0".as_ptr() as *const libc::c_char,
        b"dns query name\0".as_ptr() as *const libc::c_char,
        ALPROTO_DNS,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        /* Register in both directions as the query is usually echoed back
        in the response. */
        Some(dns_tx_get_query_name),
        1, // request or response complete
    );
    let kw = SCSigTableAppLiteElmt {
        name: b"dns.rcode\0".as_ptr() as *const libc::c_char,
        desc: b"Match the DNS header rcode flag.\0".as_ptr() as *const libc::c_char,
        url: b"rules/dns-keywords.html#dns-rcode\0".as_ptr() as *const libc::c_char,
        AppLayerTxMatch: Some(dns_rcode_match),
        Setup: Some(dns_rcode_setup),
        Free: Some(dns_rcode_free),
        flags: SIGMATCH_INFO_UINT16 | SIGMATCH_INFO_ENUM_UINT,
    };
    G_DNS_RCODE_KW_ID = SCDetectHelperKeywordRegister(&kw);
    G_DNS_RCODE_BUFFER_ID = SCDetectHelperBufferRegister(
        b"dns.rcode\0".as_ptr() as *const libc::c_char,
        ALPROTO_DNS,
        STREAM_TOSERVER | STREAM_TOCLIENT,
    );
    let kw = SCSigTableAppLiteElmt {
        name: b"dns.rrtype\0".as_ptr() as *const libc::c_char,
        desc: b"Match the DNS rrtype in message body.\0".as_ptr() as *const libc::c_char,
        url: b"rules/dns-keywords.html#dns-rrtype\0".as_ptr() as *const libc::c_char,
        AppLayerTxMatch: Some(dns_rrtype_match),
        Setup: Some(dns_rrtype_setup),
        Free: Some(dns_rrtype_free),
        flags: SIGMATCH_INFO_UINT16 | SIGMATCH_INFO_MULTI_UINT | SIGMATCH_INFO_ENUM_UINT,
    };
    G_DNS_RRTYPE_KW_ID = SCDetectHelperKeywordRegister(&kw);
    G_DNS_RRTYPE_BUFFER_ID = SCDetectHelperBufferRegister(
        b"dns.rrtype\0".as_ptr() as *const libc::c_char,
        ALPROTO_DNS,
        STREAM_TOSERVER | STREAM_TOCLIENT,
    );
    let kw = SigTableElmtStickyBuffer {
        name: String::from("dns.query"),
        desc: String::from("sticky buffer to match DNS query-buffer"),
        url: String::from("/rules/dns-keywords.html#dns-query"),
        setup: dns_detect_query_setup,
    };
    let g_dns_query_name_kw_id = helper_keyword_register_multi_buffer(&kw);
    SCDetectHelperKeywordAliasRegister(
        g_dns_query_name_kw_id,
        b"dns_query\0".as_ptr() as *const libc::c_char,
    );
    G_DNS_QUERY_BUFFER_ID = SCDetectHelperMultiBufferProgressMpmRegister(
        b"dns_query\0".as_ptr() as *const libc::c_char,
        b"dns request query\0".as_ptr() as *const libc::c_char,
        ALPROTO_DNS,
        STREAM_TOSERVER,
        Some(dns_tx_get_query), // reuse, will be called only toserver
        1,                      // request complete
    );
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::detect::uint::{detect_parse_uint, DetectUintMode};

    #[test]
    fn parse_opcode_good() {
        assert_eq!(
            detect_parse_uint::<u8>("1").unwrap().1,
            DetectUintData {
                mode: DetectUintMode::DetectUintModeEqual,
                arg1: 1,
                arg2: 0,
            }
        );
        assert_eq!(
            detect_parse_uint::<u8>("123").unwrap().1,
            DetectUintData {
                mode: DetectUintMode::DetectUintModeEqual,
                arg1: 123,
                arg2: 0,
            }
        );
        assert_eq!(
            detect_parse_uint::<u8>("!123").unwrap().1,
            DetectUintData {
                mode: DetectUintMode::DetectUintModeNe,
                arg1: 123,
                arg2: 0,
            }
        );
        assert!(detect_parse_uint::<u8>("").is_err());
        assert!(detect_parse_uint::<u8>("!").is_err());
        assert!(detect_parse_uint::<u8>("!   ").is_err());
        assert!(detect_parse_uint::<u8>("!asdf").is_err());
    }

    #[test]
    fn test_match_opcode() {
        assert!(detect_match_uint(
            &DetectUintData {
                mode: DetectUintMode::DetectUintModeEqual,
                arg1: 0,
                arg2: 0,
            },
            0b0000_0000_0000_0000,
        ));

        assert!(!detect_match_uint(
            &DetectUintData {
                mode: DetectUintMode::DetectUintModeNe,
                arg1: 0,
                arg2: 0,
            },
            0b0000_0000_0000_0000,
        ));

        assert!(detect_match_uint(
            &DetectUintData {
                mode: DetectUintMode::DetectUintModeEqual,
                arg1: 4,
                arg2: 0,
            },
            ((0b0010_0000_0000_0000 >> 11) & 0xf) as u8,
        ));

        assert!(!detect_match_uint(
            &DetectUintData {
                mode: DetectUintMode::DetectUintModeNe,
                arg1: 4,
                arg2: 0,
            },
            ((0b0010_0000_0000_0000 >> 11) & 0xf) as u8,
        ));
    }

    #[test]
    fn parse_rcode_good() {
        assert_eq!(
            detect_parse_uint_enum::<u16, DNSRcode>("1").unwrap(),
            DetectUintData {
                mode: DetectUintMode::DetectUintModeEqual,
                arg1: 1,
                arg2: 0,
            }
        );
        assert_eq!(
            detect_parse_uint_enum::<u16, DNSRcode>("123").unwrap(),
            DetectUintData {
                mode: DetectUintMode::DetectUintModeEqual,
                arg1: 123,
                arg2: 0,
            }
        );
        assert_eq!(
            detect_parse_uint_enum::<u16, DNSRcode>("!123").unwrap(),
            DetectUintData {
                mode: DetectUintMode::DetectUintModeNe,
                arg1: 123,
                arg2: 0,
            }
        );
        assert_eq!(
            detect_parse_uint_enum::<u16, DNSRcode>("7-15").unwrap(),
            DetectUintData {
                mode: DetectUintMode::DetectUintModeRange,
                arg1: 7,
                arg2: 15,
            }
        );
        assert_eq!(
            detect_parse_uint_enum::<u16, DNSRcode>("nxdomain").unwrap(),
            DetectUintData {
                mode: DetectUintMode::DetectUintModeEqual,
                arg1: DNSRcode::NXDOMAIN as u16,
                arg2: 0,
            }
        );
        assert!(detect_parse_uint_enum::<u16, DNSRcode>("").is_none());
        assert!(detect_parse_uint_enum::<u16, DNSRcode>("!").is_none());
        assert!(detect_parse_uint_enum::<u16, DNSRcode>("!   ").is_none());
        assert!(detect_parse_uint_enum::<u16, DNSRcode>("!asdf").is_none());
    }

    #[test]
    fn test_match_rcode() {
        assert!(detect_match_uint(
            &DetectUintData {
                mode: DetectUintMode::DetectUintModeEqual,
                arg1: 0,
                arg2: 0,
            },
            0b0000_0000_0000_0000,
        ));

        assert!(!detect_match_uint(
            &DetectUintData {
                mode: DetectUintMode::DetectUintModeNe,
                arg1: 0,
                arg2: 0,
            },
            0b0000_0000_0000_0000,
        ));

        assert!(detect_match_uint(
            &DetectUintData {
                mode: DetectUintMode::DetectUintModeEqual,
                arg1: 4,
                arg2: 0,
            },
            4u8,
        ));

        assert!(!detect_match_uint(
            &DetectUintData {
                mode: DetectUintMode::DetectUintModeNe,
                arg1: 4,
                arg2: 0,
            },
            4u8,
        ));
    }

    #[test]
    fn parse_rrtype_good() {
        assert_eq!(
            detect_parse_uint_enum::<u16, DNSRecordType>("1").unwrap(),
            DetectUintData {
                mode: DetectUintMode::DetectUintModeEqual,
                arg1: 1,
                arg2: 0,
            }
        );
        assert_eq!(
            detect_parse_uint_enum::<u16, DNSRecordType>("123").unwrap(),
            DetectUintData {
                mode: DetectUintMode::DetectUintModeEqual,
                arg1: 123,
                arg2: 0,
            }
        );
        assert_eq!(
            detect_parse_uint_enum::<u16, DNSRecordType>("!123").unwrap(),
            DetectUintData {
                mode: DetectUintMode::DetectUintModeNe,
                arg1: 123,
                arg2: 0,
            }
        );
        assert_eq!(
            detect_parse_uint_enum::<u16, DNSRecordType>("7-15").unwrap(),
            DetectUintData {
                mode: DetectUintMode::DetectUintModeRange,
                arg1: 7,
                arg2: 15,
            }
        );
        assert_eq!(
            detect_parse_uint_enum::<u16, DNSRecordType>("a").unwrap(),
            DetectUintData {
                mode: DetectUintMode::DetectUintModeEqual,
                arg1: DNSRecordType::A as u16,
                arg2: 0,
            }
        );
        assert!(detect_parse_uint_enum::<u16, DNSRecordType>("").is_none());
        assert!(detect_parse_uint_enum::<u16, DNSRecordType>("!").is_none());
        assert!(detect_parse_uint_enum::<u16, DNSRecordType>("!   ").is_none());
        assert!(detect_parse_uint_enum::<u16, DNSRecordType>("!asdf").is_none());
    }

    #[test]
    fn test_match_rrtype() {
        assert!(detect_match_uint(
            &DetectUintData {
                mode: DetectUintMode::DetectUintModeEqual,
                arg1: 0,
                arg2: 0,
            },
            0b0000_0000_0000_0000,
        ));

        assert!(!detect_match_uint(
            &DetectUintData {
                mode: DetectUintMode::DetectUintModeNe,
                arg1: 0,
                arg2: 0,
            },
            0b0000_0000_0000_0000,
        ));

        assert!(detect_match_uint(
            &DetectUintData {
                mode: DetectUintMode::DetectUintModeEqual,
                arg1: 4,
                arg2: 0,
            },
            4u16,
        ));

        assert!(!detect_match_uint(
            &DetectUintData {
                mode: DetectUintMode::DetectUintModeNe,
                arg1: 4,
                arg2: 0,
            },
            4u16,
        ));
    }
}
