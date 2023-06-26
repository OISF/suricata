#![deny(missing_docs)]
use crate::{
    bstr::Bstr,
    c_api::bstr::bstr_ptr,
    transaction::{Header, Headers},
};
use std::convert::TryFrom;

/// Get the first header value matching the key.
///
/// headers: Header table.
/// ckey: Header name to match.
///
/// Returns the header or NULL when not found or on error
/// # Safety
/// When calling this method, you have to ensure that headers is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_headers_get(
    headers: *const Headers,
    ckey: *const libc::c_char,
) -> *const Header {
    if let (Some(headers), Some(ckey)) = (headers.as_ref(), ckey.as_ref()) {
        headers
            .get_nocase_nozero(std::ffi::CStr::from_ptr(ckey).to_bytes())
            .map(|value| value as *const Header)
            .unwrap_or(std::ptr::null())
    } else {
        std::ptr::null()
    }
}

/// Get all headers flags
///
/// headers: Header table.
///
/// Returns the accumulated header flags or 0 on error.
/// # Safety
/// When calling this method, you have to ensure that headers is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_headers_flags(headers: *const Headers) -> u64 {
    headers
        .as_ref()
        .map(|headers| {
            headers
                .into_iter()
                .fold(0, |flags, header| flags | header.flags)
        })
        .unwrap_or(0)
}

/// Get the header at a given index.
///
/// headers: Header table.
/// index: Index into the table.
///
/// Returns the header or NULL when not found or on error
/// # Safety
/// When calling this method, you have to ensure that header is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_headers_get_index(
    headers: *const Headers,
    index: usize,
) -> *const Header {
    headers
        .as_ref()
        .map(|headers| {
            headers
                .elements
                .get(index)
                .map(|value| value as *const Header)
                .unwrap_or(std::ptr::null())
        })
        .unwrap_or(std::ptr::null())
}

/// Get the size of the headers table.
///
/// headers: Headers table.
///
/// Returns the size or -1 on error
/// # Safety
/// When calling this method, you have to ensure that header is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_headers_size(headers: *const Headers) -> isize {
    headers
        .as_ref()
        .map(|headers| isize::try_from(headers.size()).unwrap_or(-1))
        .unwrap_or(-1)
}

/// Get the name of a header.
///
/// header: Header pointer.
///
/// Returns the name or NULL on error.
/// # Safety
/// When calling this method, you have to ensure that header is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_header_name(header: *const Header) -> *const Bstr {
    header
        .as_ref()
        .map(|header| &header.name as *const Bstr)
        .unwrap_or(std::ptr::null())
}

/// Get the name of a header as a ptr.
///
/// header: Header pointer.
///
/// Returns the pointer or NULL on error.
/// # Safety
/// When calling this method, you have to ensure that header is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_header_name_ptr(header: *const Header) -> *const u8 {
    header
        .as_ref()
        .map(|header| bstr_ptr(&header.name) as *const u8)
        .unwrap_or(std::ptr::null())
}

/// Get the header flags
///
/// header: Header pointer.
///
/// Returns the header flags or 0 on error.
/// # Safety
/// When calling this method, you have to ensure that header is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_header_flags(header: *const Header) -> u64 {
    header.as_ref().map(|header| header.flags).unwrap_or(0)
}

/// Get the length of a header name.
///
/// tx: Header pointer.
///
/// Returns the length or -1 on error.
/// # Safety
/// When calling this method, you have to ensure that header is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_header_name_len(header: *const Header) -> isize {
    header
        .as_ref()
        .map(|header| isize::try_from(header.name.len()).unwrap_or(-1))
        .unwrap_or(-1)
}

/// Get the value of a header.
///
/// tx: Header pointer.
///
/// Returns the value or NULL on error.
/// # Safety
/// When calling this method, you have to ensure that header is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_header_value(header: *const Header) -> *const Bstr {
    header
        .as_ref()
        .map(|header| &header.value as *const Bstr)
        .unwrap_or(std::ptr::null())
}

/// Get the value of a header as a ptr.
///
/// tx: Header pointer.
///
/// Returns the pointer or NULL on error.
/// # Safety
/// When calling this method, you have to ensure that header is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_header_value_ptr(header: *const Header) -> *const u8 {
    header
        .as_ref()
        .map(|header| bstr_ptr(&header.value) as *const u8)
        .unwrap_or(std::ptr::null())
}

/// Get the length of a header value.
///
/// tx: Header pointer.
///
/// Returns the length or -1 on error.
/// # Safety
/// When calling this method, you have to ensure that header is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_header_value_len(header: *const Header) -> isize {
    header
        .as_ref()
        .map(|header| isize::try_from(header.value.len()).unwrap_or(-1))
        .unwrap_or(-1)
}
