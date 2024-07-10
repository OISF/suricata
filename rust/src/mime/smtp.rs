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

use super::mime;
use crate::utils::scbase64;
use crate::core::StreamingBufferConfig;
use crate::filecontainer::FileContainer;
use digest::generic_array::{typenum::U16, GenericArray};
use digest::Digest;
use digest::Update;
use md5::Md5;
use std::ffi::CStr;
use std::os::raw::c_uchar;

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialOrd, PartialEq, Eq)]
pub enum MimeSmtpParserState {
    MimeSmtpStart = 0,
    MimeSmtpHeader = 1,
    MimeSmtpBody = 2,
    MimeSmtpParserError = 3,
}

impl Default for MimeSmtpParserState {
    fn default() -> Self {
        MimeSmtpParserState::MimeSmtpStart
    }
}

#[derive(Debug, Default)]
pub struct MimeHeader {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialOrd, PartialEq, Eq)]
pub enum MimeSmtpMd5State {
    MimeSmtpMd5Disabled = 0,
    MimeSmtpMd5Inited = 1,
    MimeSmtpMd5Started = 2,
    MimeSmtpMd5Completed = 3,
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialOrd, PartialEq, Eq)]
enum MimeSmtpContentType {
    Message = 0,
    PlainText = 1,
    Html = 2,
    Unknown = 3,
}

impl Default for MimeSmtpContentType {
    fn default() -> Self {
        MimeSmtpContentType::Message
    }
}

#[derive(Debug)]
pub struct MimeStateSMTP<'a> {
    pub(crate) state_flag: MimeSmtpParserState,
    pub(crate) headers: Vec<MimeHeader>,
    pub(crate) main_headers_nb: usize,
    filename: Vec<u8>,
    pub(crate) attachments: Vec<Vec<u8>>,
    pub(crate) urls: Vec<Vec<u8>>,
    boundaries: Vec<Vec<u8>>,
    encoding: MimeSmtpEncoding,
    decoder: Option<scbase64::Decoder>,
    content_type: MimeSmtpContentType,
    decoded_line: Vec<u8>,
    // small buffer for end of line
    // waiting to see if it is part of the boundary
    bufeol: [u8; 2],
    bufeolen: u8,
    files: &'a mut FileContainer,
    sbcfg: *const StreamingBufferConfig,
    md5: md5::Md5,
    pub(crate) md5_state: MimeSmtpMd5State,
    pub(crate) md5_result: GenericArray<u8, U16>,
}

pub fn mime_smtp_state_init(
    files: &mut FileContainer, sbcfg: *const StreamingBufferConfig,
) -> Option<MimeStateSMTP> {
    let r = MimeStateSMTP {
        state_flag: MimeSmtpParserState::MimeSmtpStart,
        headers: Vec::new(),
        main_headers_nb: 0,
        filename: Vec::new(),
        attachments: Vec::new(),
        urls: Vec::new(),
        boundaries: Vec::new(),
        decoded_line: Vec::new(),
        encoding: MimeSmtpEncoding::Plain,
        decoder: None,
        content_type: MimeSmtpContentType::Message,
        bufeol: [0; 2],
        bufeolen: 0,
        files,
        sbcfg,
        md5: Md5::new(),
        md5_state: MimeSmtpMd5State::MimeSmtpMd5Disabled,
        md5_result: [0; 16].into(),
    };
    return Some(r);
}

#[no_mangle]
pub unsafe extern "C" fn SCMimeSmtpStateInit(
    files: &mut FileContainer, sbcfg: *const StreamingBufferConfig,
) -> *mut MimeStateSMTP {
    if let Some(ctx) = mime_smtp_state_init(files, sbcfg) {
        let boxed = Box::new(ctx);
        return Box::into_raw(boxed) as *mut _;
    }
    return std::ptr::null_mut();
}

#[no_mangle]
pub unsafe extern "C" fn SCMimeSmtpStateFree(ctx: &mut MimeStateSMTP) {
    // Just unbox...
    std::mem::drop(Box::from_raw(ctx));
}

#[repr(u8)]
#[derive(Copy, Clone, PartialOrd, PartialEq, Eq)]
pub enum MimeSmtpParserResult {
    MimeSmtpNeedsMore = 0,
    MimeSmtpFileOpen = 1,
    MimeSmtpFileClose = 2,
    MimeSmtpFileChunk = 3,
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialOrd, PartialEq, Eq)]
pub enum MimeSmtpEncoding {
    Plain = 0,
    Base64 = 1,
    QuotedPrintable = 2,
}

impl Default for MimeSmtpEncoding {
    fn default() -> Self {
        MimeSmtpEncoding::Plain
    }
}

// Cannot use BIT_U32 macros as they do not get exported by cbindgen :-/
pub const MIME_ANOM_INVALID_BASE64: u32 = 0x1;
pub const MIME_ANOM_INVALID_QP: u32 = 0x2;
pub const MIME_ANOM_LONG_LINE: u32 = 0x4;
pub const MIME_ANOM_LONG_ENC_LINE: u32 = 0x8;
pub const MIME_ANOM_LONG_HEADER_NAME: u32 = 0x10;
pub const MIME_ANOM_LONG_HEADER_VALUE: u32 = 0x20;
//unused pub const MIME_ANOM_MALFORMED_MSG: u32 = 0x40;
pub const MIME_ANOM_LONG_BOUNDARY: u32 = 0x80;
pub const MIME_ANOM_LONG_FILENAME: u32 = 0x100;

fn mime_smtp_process_headers(ctx: &mut MimeStateSMTP) -> (u32, bool) {
    let mut sections_values = Vec::new();
    let mut warnings = 0;
    let mut encap = false;
    for h in &ctx.headers[ctx.main_headers_nb..] {
        if mime::slice_equals_lowercase(&h.name, b"content-disposition") {
            if ctx.filename.is_empty() {
                if let Some(value) =
                    mime::mime_find_header_token(&h.value, b"filename", &mut sections_values)
                {
                    let value = if value.len() > mime::RS_MIME_MAX_TOKEN_LEN {
                        warnings |= MIME_ANOM_LONG_FILENAME;
                        &value[..mime::RS_MIME_MAX_TOKEN_LEN]
                    } else {
                        value
                    };
                    ctx.filename.extend_from_slice(value);
                    let mut newname = Vec::new();
                    newname.extend_from_slice(value);
                    ctx.attachments.push(newname);
                    sections_values.clear();
                }
            }
        } else if mime::slice_equals_lowercase(&h.name, b"content-transfer-encoding") {
            if mime::slice_equals_lowercase(&h.value, b"base64") {
                ctx.encoding = MimeSmtpEncoding::Base64;
                ctx.decoder = Some(scbase64::Decoder::new());
            } else if mime::slice_equals_lowercase(&h.value, b"quoted-printable") {
                ctx.encoding = MimeSmtpEncoding::QuotedPrintable;
            }
        } else if mime::slice_equals_lowercase(&h.name, b"content-type") {
            if ctx.filename.is_empty() {
                if let Some(value) =
                    mime::mime_find_header_token(&h.value, b"name", &mut sections_values)
                {
                    let value = if value.len() > mime::RS_MIME_MAX_TOKEN_LEN {
                        warnings |= MIME_ANOM_LONG_FILENAME;
                        &value[..mime::RS_MIME_MAX_TOKEN_LEN]
                    } else {
                        value
                    };
                    ctx.filename.extend_from_slice(value);
                    let mut newname = Vec::new();
                    newname.extend_from_slice(value);
                    ctx.attachments.push(newname);
                    sections_values.clear();
                }
            }
            if let Some(value) =
                mime::mime_find_header_token(&h.value, b"boundary", &mut sections_values)
            {
                // start wih 2 additional hyphens
                let mut boundary = Vec::new();
                boundary.push(b'-');
                boundary.push(b'-');
                boundary.extend_from_slice(value);
                ctx.boundaries.push(boundary);
                if value.len() > MAX_BOUNDARY_LEN {
                    warnings |= MIME_ANOM_LONG_BOUNDARY;
                }
                sections_values.clear();
            }
            let ct = if let Some(x) = h.value.iter().position(|&x| x == b';') {
                &h.value[..x]
            } else {
                &h.value
            };
            match ct {
                b"text/plain" => {
                    ctx.content_type = MimeSmtpContentType::PlainText;
                }
                b"text/html" => {
                    ctx.content_type = MimeSmtpContentType::Html;
                }
                _ => {
                    if ct.starts_with(b"message/") {
                        encap = true;
                    }
                    ctx.content_type = MimeSmtpContentType::Unknown;
                }
            }
        }
    }
    return (warnings, encap);
}

extern "C" {
    // Defined in util-file.h
    pub fn FileAppendData(
        c: *mut FileContainer, sbcfg: *const StreamingBufferConfig, data: *const c_uchar,
        data_len: u32,
    ) -> std::os::raw::c_int;
    // Defined in util-spm-bs.h
    pub fn BasicSearchNocaseIndex(
        data: *const c_uchar, data_len: u32, needle: *const c_uchar, needle_len: u16,
    ) -> u32;
}

fn hex(i: u8) -> Option<u8> {
    if i.is_ascii_digit() {
        return Some(i - b'0');
    }
    if (b'A'..=b'F').contains(&i) {
        return Some(i - b'A' + 10);
    }
    return None;
}

const SMTP_MIME_MAX_DECODED_LINE_LENGTH: usize = 8192;

fn mime_smtp_finish_url(input: &[u8]) -> &[u8] {
    if let Some(x) = input.iter().position(|&x| {
        x == b' ' || x == b'"' || x == b'\'' || x == b'<' || x == b'>' || x == b']' || x == b'\t'
    }) {
        return &input[..x];
    }
    return input;
}

fn mime_smtp_extract_urls(urls: &mut Vec<Vec<u8>>, input_start: &[u8]) {
    //TODO optimize later : use mpm
    for s in unsafe { MIME_SMTP_CONFIG_EXTRACT_URL_SCHEMES.iter() } {
        let mut input = input_start;
        let mut start = unsafe {
            BasicSearchNocaseIndex(
                input.as_ptr(),
                input.len() as u32,
                s.as_ptr(),
                s.len() as u16,
            )
        };
        while (start as usize) < input.len() {
            let url = mime_smtp_finish_url(&input[start as usize..]);
            let mut urlv = Vec::with_capacity(url.len());
            if unsafe { !MIME_SMTP_CONFIG_LOG_URL_SCHEME } {
                urlv.extend_from_slice(&url[s.len()..]);
            } else {
                urlv.extend_from_slice(url);
            }
            urls.push(urlv);
            input = &input[start as usize + url.len()..];
            start = unsafe {
                BasicSearchNocaseIndex(
                    input.as_ptr(),
                    input.len() as u32,
                    s.as_ptr(),
                    s.len() as u16,
                )
            };
        }
    }
}

fn mime_smtp_find_url_strings(ctx: &mut MimeStateSMTP, input_new: &[u8]) {
    if unsafe { !MIME_SMTP_CONFIG_EXTRACT_URLS } {
        return;
    }

    let mut input = input_new;
    // use previosly buffered beginning of line if any
    if !ctx.decoded_line.is_empty() {
        ctx.decoded_line.extend_from_slice(input_new);
        input = &ctx.decoded_line;
    }
    // no input, no url
    if input.is_empty() {
        return;
    }

    if input[input.len() - 1] == b'\n' || input.len() > SMTP_MIME_MAX_DECODED_LINE_LENGTH {
        // easy case, no buffering to do
        mime_smtp_extract_urls(&mut ctx.urls, input);
        if !ctx.decoded_line.is_empty() {
            ctx.decoded_line.clear()
        }
    } else if let Some(x) = input.iter().rev().position(|&x| x == b'\n') {
        input = &input[..x];
        mime_smtp_extract_urls(&mut ctx.urls, input);
        if !ctx.decoded_line.is_empty() {
            ctx.decoded_line.drain(0..x);
        } else {
            ctx.decoded_line.extend_from_slice(&input_new[x..]);
        }
    } else if ctx.decoded_line.is_empty() {
        ctx.decoded_line.extend_from_slice(input_new);
    }
}

const MAX_LINE_LEN: u32 = 998; // Def in RFC 2045, excluding CRLF sequence
const MAX_ENC_LINE_LEN: usize = 76; /* Def in RFC 2045, excluding CRLF sequence */
const MAX_HEADER_NAME: usize = 75; /* 75 + ":" = 76 */
const MAX_HEADER_VALUE: usize = 2000; /* Default - arbitrary limit */
const MAX_BOUNDARY_LEN: usize = 254;

fn mime_smtp_parse_line(
    ctx: &mut MimeStateSMTP, i: &[u8], full: &[u8],
) -> (MimeSmtpParserResult, u32) {
    if ctx.md5_state == MimeSmtpMd5State::MimeSmtpMd5Started {
        Update::update(&mut ctx.md5, full);
    }
    let mut warnings = 0;
    match ctx.state_flag {
        MimeSmtpParserState::MimeSmtpStart => {
            if unsafe { MIME_SMTP_CONFIG_BODY_MD5 }
                && ctx.md5_state != MimeSmtpMd5State::MimeSmtpMd5Started
            {
                ctx.md5 = Md5::new();
                ctx.md5_state = MimeSmtpMd5State::MimeSmtpMd5Inited;
            }
            if i.is_empty() {
                let (w, encap_msg) = mime_smtp_process_headers(ctx);
                warnings |= w;
                if ctx.main_headers_nb == 0 {
                    ctx.main_headers_nb = ctx.headers.len();
                }
                if encap_msg {
                    ctx.state_flag = MimeSmtpParserState::MimeSmtpStart;
                    ctx.headers.truncate(ctx.main_headers_nb);
                    return (MimeSmtpParserResult::MimeSmtpNeedsMore, warnings);
                }
                ctx.state_flag = MimeSmtpParserState::MimeSmtpBody;
                return (MimeSmtpParserResult::MimeSmtpFileOpen, warnings);
            } else if let Ok((value, name)) = mime::mime_parse_header_line(i) {
                ctx.state_flag = MimeSmtpParserState::MimeSmtpHeader;
                let mut h = MimeHeader::default();
                h.name.extend_from_slice(name);
                h.value.extend_from_slice(value);
                if h.name.len() > MAX_HEADER_NAME {
                    warnings |= MIME_ANOM_LONG_HEADER_NAME;
                }
                if h.value.len() > MAX_HEADER_VALUE {
                    warnings |= MIME_ANOM_LONG_HEADER_VALUE;
                }
                ctx.headers.push(h);
            } // else event ?
        }
        MimeSmtpParserState::MimeSmtpHeader => {
            if i.is_empty() {
                let (w, encap_msg) = mime_smtp_process_headers(ctx);
                warnings |= w;
                if ctx.main_headers_nb == 0 {
                    ctx.main_headers_nb = ctx.headers.len();
                }
                if encap_msg {
                    ctx.state_flag = MimeSmtpParserState::MimeSmtpStart;
                    ctx.headers.truncate(ctx.main_headers_nb);
                    return (MimeSmtpParserResult::MimeSmtpNeedsMore, warnings);
                }
                ctx.state_flag = MimeSmtpParserState::MimeSmtpBody;
                return (MimeSmtpParserResult::MimeSmtpFileOpen, warnings);
            } else if i[0] == b' ' || i[0] == b'\t' {
                let last = ctx.headers.len() - 1;
                ctx.headers[last].value.extend_from_slice(&i[1..]);
            } else if let Ok((value, name)) = mime::mime_parse_header_line(i) {
                let mut h = MimeHeader::default();
                h.name.extend_from_slice(name);
                h.value.extend_from_slice(value);
                if h.name.len() > MAX_HEADER_NAME {
                    warnings |= MIME_ANOM_LONG_HEADER_NAME;
                }
                if h.value.len() > MAX_HEADER_VALUE {
                    warnings |= MIME_ANOM_LONG_HEADER_VALUE;
                }
                ctx.headers.push(h);
            }
        }
        MimeSmtpParserState::MimeSmtpBody => {
            if ctx.md5_state == MimeSmtpMd5State::MimeSmtpMd5Inited {
                ctx.md5_state = MimeSmtpMd5State::MimeSmtpMd5Started;
                Update::update(&mut ctx.md5, full);
            }
            let boundary = ctx.boundaries.last();
            if let Some(b) = boundary {
                if i.len() >= b.len() && &i[..b.len()] == b {
                    if ctx.encoding == MimeSmtpEncoding::Base64
                        && unsafe { MIME_SMTP_CONFIG_DECODE_BASE64 }
                    {
                        if let Some(ref mut decoder) = &mut ctx.decoder {
                            if decoder.nb > 0 {
                                // flush the base64 buffer with padding
                                let mut v = Vec::new();
                                for _i in 0..4 - decoder.nb {
                                    v.push(b'=');
                                }
                                if let Ok(dec) = scbase64::decode_rfc2045(decoder, &v) {
                                    unsafe {
                                        FileAppendData(
                                            ctx.files,
                                            ctx.sbcfg,
                                            dec.as_ptr(),
                                            dec.len() as u32,
                                        );
                                    }
                                }
                            }
                        }
                    }
                    ctx.state_flag = MimeSmtpParserState::MimeSmtpStart;
                    let toclose = !ctx.filename.is_empty();
                    ctx.filename.clear();
                    ctx.headers.truncate(ctx.main_headers_nb);
                    ctx.encoding = MimeSmtpEncoding::Plain;
                    if i.len() >= b.len() + 2 && i[b.len()] == b'-' && i[b.len() + 1] == b'-' {
                        ctx.boundaries.pop();
                    }
                    if toclose {
                        return (MimeSmtpParserResult::MimeSmtpFileClose, 0);
                    }
                    return (MimeSmtpParserResult::MimeSmtpNeedsMore, 0);
                }
            }
            if ctx.filename.is_empty() {
                if ctx.content_type == MimeSmtpContentType::PlainText
                    || ctx.content_type == MimeSmtpContentType::Html
                    || ctx.content_type == MimeSmtpContentType::Message
                {
                    match ctx.encoding {
                        MimeSmtpEncoding::Plain => {
                            mime_smtp_find_url_strings(ctx, full);
                        }
                        MimeSmtpEncoding::QuotedPrintable => {
                            mime_smtp_find_url_strings(ctx, full);
                        }
                        MimeSmtpEncoding::Base64 => {
                            if unsafe { MIME_SMTP_CONFIG_DECODE_BASE64 } {
                                if let Some(ref mut decoder) = &mut ctx.decoder {
                                    if i.len() > MAX_ENC_LINE_LEN {
                                        warnings |= MIME_ANOM_LONG_ENC_LINE;
                                    }
                                    if let Ok(dec) = scbase64::decode_rfc2045(decoder, i) {
                                        mime_smtp_find_url_strings(ctx, &dec);
                                    } else {
                                        warnings |= MIME_ANOM_INVALID_BASE64;
                                    }
                                }
                            }
                        }
                    }
                }
                return (MimeSmtpParserResult::MimeSmtpNeedsMore, warnings);
            }
            match ctx.encoding {
                MimeSmtpEncoding::Plain => {
                    mime_smtp_find_url_strings(ctx, full);
                    if ctx.bufeolen > 0 {
                        unsafe {
                            FileAppendData(
                                ctx.files,
                                ctx.sbcfg,
                                ctx.bufeol.as_ptr(),
                                ctx.bufeol.len() as u32,
                            );
                        }
                    }
                    unsafe {
                        FileAppendData(ctx.files, ctx.sbcfg, i.as_ptr(), i.len() as u32);
                    }
                    ctx.bufeolen = (full.len() - i.len()) as u8;
                    if ctx.bufeolen > 0 {
                        ctx.bufeol[..ctx.bufeolen as usize].copy_from_slice(&full[i.len()..]);
                    }
                }
                MimeSmtpEncoding::Base64 => {
                    if unsafe { MIME_SMTP_CONFIG_DECODE_BASE64 } {
                        if let Some(ref mut decoder) = &mut ctx.decoder {
                            if i.len() > MAX_ENC_LINE_LEN {
                                warnings |= MIME_ANOM_LONG_ENC_LINE;
                            }
                            if let Ok(dec) = scbase64::decode_rfc2045(decoder, i) {
                                mime_smtp_find_url_strings(ctx, &dec);
                                unsafe {
                                    FileAppendData(
                                        ctx.files,
                                        ctx.sbcfg,
                                        dec.as_ptr(),
                                        dec.len() as u32,
                                    );
                                }
                            } else {
                                warnings |= MIME_ANOM_INVALID_BASE64;
                            }
                        }
                    }
                }
                MimeSmtpEncoding::QuotedPrintable => {
                    if unsafe { MIME_SMTP_CONFIG_DECODE_QUOTED } {
                        if i.len() > MAX_ENC_LINE_LEN {
                            warnings |= MIME_ANOM_LONG_ENC_LINE;
                        }
                        let mut c = 0;
                        let mut eol_equal = false;
                        let mut quoted_buffer = Vec::with_capacity(i.len());
                        while c < i.len() {
                            if i[c] == b'=' {
                                if c == i.len() - 1 {
                                    eol_equal = true;
                                    break;
                                } else if c + 2 >= i.len() {
                                    // log event ?
                                    warnings |= MIME_ANOM_INVALID_QP;
                                    break;
                                }
                                if let Some(v) = hex(i[c + 1]) {
                                    if let Some(v2) = hex(i[c + 2]) {
                                        quoted_buffer.push((v << 4) | v2);
                                    } else {
                                        warnings |= MIME_ANOM_INVALID_QP;
                                    }
                                } else {
                                    warnings |= MIME_ANOM_INVALID_QP;
                                }
                                c += 3;
                            } else {
                                quoted_buffer.push(i[c]);
                                c += 1;
                            }
                        }
                        if !eol_equal {
                            quoted_buffer.extend_from_slice(&full[i.len()..]);
                        }
                        mime_smtp_find_url_strings(ctx, &quoted_buffer);
                        unsafe {
                            FileAppendData(
                                ctx.files,
                                ctx.sbcfg,
                                quoted_buffer.as_ptr(),
                                quoted_buffer.len() as u32,
                            );
                        }
                    }
                }
            }
            return (MimeSmtpParserResult::MimeSmtpFileChunk, warnings);
        }
        _ => {}
    }
    return (MimeSmtpParserResult::MimeSmtpNeedsMore, warnings);
}

#[no_mangle]
pub unsafe extern "C" fn SCSmtpMimeParseLine(
    input: *const u8, input_len: u32, delim_len: u8, warnings: *mut u32, ctx: &mut MimeStateSMTP,
) -> MimeSmtpParserResult {
    let full_line = build_slice!(input, input_len as usize + delim_len as usize);
    let line = &full_line[..input_len as usize];
    let (r, w) = mime_smtp_parse_line(ctx, line, full_line);
    *warnings = w;
    if input_len > MAX_LINE_LEN {
        *warnings |= MIME_ANOM_LONG_LINE;
    }
    return r;
}

fn mime_smtp_complete(ctx: &mut MimeStateSMTP) {
    if ctx.md5_state == MimeSmtpMd5State::MimeSmtpMd5Started {
        ctx.md5_state = MimeSmtpMd5State::MimeSmtpMd5Completed;
        ctx.md5_result = ctx.md5.finalize_reset();
    }
    // look for url in the last unfinished line
    mime_smtp_find_url_strings(ctx, &[b'\n']);
}

#[no_mangle]
pub unsafe extern "C" fn SCSmtpMimeComplete(ctx: &mut MimeStateSMTP) {
    mime_smtp_complete(ctx);
}

#[no_mangle]
pub unsafe extern "C" fn SCMimeSmtpGetState(ctx: &mut MimeStateSMTP) -> MimeSmtpParserState {
    return ctx.state_flag;
}

#[no_mangle]
pub unsafe extern "C" fn SCMimeSmtpGetFilename(
    ctx: &mut MimeStateSMTP, buffer: *mut *const u8, filename_len: *mut u16,
) {
    if !ctx.filename.is_empty() {
        *buffer = ctx.filename.as_ptr();
        if ctx.filename.len() < u16::MAX.into() {
            *filename_len = ctx.filename.len() as u16;
        } else {
            *filename_len = u16::MAX;
        }
    } else {
        *buffer = std::ptr::null_mut();
        *filename_len = 0;
    }
}

#[no_mangle]
pub unsafe extern "C" fn SCMimeSmtpGetHeader(
    ctx: &mut MimeStateSMTP, str: *const std::os::raw::c_char, buffer: *mut *const u8,
    buffer_len: *mut u32,
) -> bool {
    let name: &CStr = CStr::from_ptr(str); //unsafe
    for h in &ctx.headers[ctx.main_headers_nb..] {
        if mime::slice_equals_lowercase(&h.name, name.to_bytes()) {
            *buffer = h.value.as_ptr();
            *buffer_len = h.value.len() as u32;
            return true;
        }
    }
    *buffer = std::ptr::null_mut();
    *buffer_len = 0;
    return false;
}

#[no_mangle]
pub unsafe extern "C" fn SCMimeSmtpGetHeaderName(
    ctx: &mut MimeStateSMTP, buffer: *mut *const u8, buffer_len: *mut u32, num: u32,
) -> bool {
    if num as usize + ctx.main_headers_nb < ctx.headers.len() {
        *buffer = ctx.headers[ctx.main_headers_nb + num as usize]
            .name
            .as_ptr();
        *buffer_len = ctx.headers[ctx.main_headers_nb + num as usize].name.len() as u32;
        return true;
    }
    *buffer = std::ptr::null_mut();
    *buffer_len = 0;
    return false;
}

static mut MIME_SMTP_CONFIG_DECODE_BASE64: bool = true;
static mut MIME_SMTP_CONFIG_DECODE_QUOTED: bool = true;
static mut MIME_SMTP_CONFIG_BODY_MD5: bool = false;
static mut MIME_SMTP_CONFIG_HEADER_VALUE_DEPTH: u32 = 0;
static mut MIME_SMTP_CONFIG_EXTRACT_URLS: bool = true;
static mut MIME_SMTP_CONFIG_LOG_URL_SCHEME: bool = false;
static mut MIME_SMTP_CONFIG_EXTRACT_URL_SCHEMES: Vec<&str> = Vec::new();

#[no_mangle]
pub unsafe extern "C" fn SCMimeSmtpConfigDecodeBase64(val: std::os::raw::c_int) {
    MIME_SMTP_CONFIG_DECODE_BASE64 = val != 0;
}

#[no_mangle]
pub unsafe extern "C" fn SCMimeSmtpConfigDecodeQuoted(val: std::os::raw::c_int) {
    MIME_SMTP_CONFIG_DECODE_QUOTED = val != 0;
}

#[no_mangle]
pub unsafe extern "C" fn SCMimeSmtpConfigExtractUrls(val: std::os::raw::c_int) {
    MIME_SMTP_CONFIG_EXTRACT_URLS = val != 0;
}

#[no_mangle]
pub unsafe extern "C" fn SCMimeSmtpConfigLogUrlScheme(val: std::os::raw::c_int) {
    MIME_SMTP_CONFIG_LOG_URL_SCHEME = val != 0;
}

#[no_mangle]
pub unsafe extern "C" fn SCMimeSmtpConfigBodyMd5(val: std::os::raw::c_int) {
    MIME_SMTP_CONFIG_BODY_MD5 = val != 0;
}

#[no_mangle]
pub unsafe extern "C" fn SCMimeSmtpConfigHeaderValueDepth(val: u32) {
    MIME_SMTP_CONFIG_HEADER_VALUE_DEPTH = val;
}

#[no_mangle]
pub unsafe extern "C" fn SCMimeSmtpConfigExtractUrlsSchemeReset() {
    MIME_SMTP_CONFIG_EXTRACT_URL_SCHEMES.clear();
}

#[no_mangle]
pub unsafe extern "C" fn SCMimeSmtpConfigExtractUrlsSchemeAdd(
    str: *const std::os::raw::c_char,
) -> std::os::raw::c_int {
    let scheme: &CStr = CStr::from_ptr(str); //unsafe
    if let Ok(s) = scheme.to_str() {
        MIME_SMTP_CONFIG_EXTRACT_URL_SCHEMES.push(s);
        return 0;
    }
    return -1;
}
