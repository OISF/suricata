#![deny(missing_docs)]
use crate::util::get_version;
use std::ffi::CString;

/// Functions for working with Bstr.
pub mod bstr;
/// Functions for working with config.
pub mod config;
/// Functions for working with connection.
pub mod connection;
/// Functions for working with connection parser.
pub mod connection_parser;
/// Functions for working with headers.
pub mod header;
/// Functions for working with logs.
pub mod log;
/// Functions for working with transactions.
pub mod transaction;
/// Functions for working with request uri.
pub mod uri;

/// Returns the LibHTP version string.
#[no_mangle]
pub extern "C" fn htp_get_version() -> *const libc::c_char {
    get_version().as_ptr() as *const libc::c_char
}

/// Free rust allocated cstring
///
/// # Safety
/// This should only ever be called with a pointer that was earlier obtained by calling [CString::into_raw].
#[no_mangle]
pub unsafe extern "C" fn htp_free_cstring(input: *mut libc::c_char) {
    input.as_mut().map(|input| CString::from_raw(input));
}
