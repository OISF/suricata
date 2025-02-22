#![deny(missing_docs)]
use crate::log::{HtpLogCode, Log};
use std::{ffi::CString, os::raw::c_char};

/// Get the log's message string
///
/// Returns the log message as a cstring or NULL on error
/// The caller must free this result with htp_free_cstring
/// # Safety
/// When calling this method, you have to ensure that log is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_log_message(log: *const Log) -> *mut c_char {
    log.as_ref()
        .and_then(|log| CString::new(log.msg.msg.clone()).ok())
        .map(|msg| msg.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

/// Get a log's message file
///
/// Returns the file as a cstring or NULL on error
/// The caller must free this result with htp_free_cstring
/// # Safety
/// When calling this method, you have to ensure that log is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_log_file(log: *const Log) -> *mut c_char {
    log.as_ref()
        .and_then(|log| CString::new(log.msg.file.clone()).ok())
        .map(|msg| msg.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

/// Get a log's message code
///
/// Returns a code or HTP_LOG_CODE_ERROR on error
/// # Safety
/// When calling this method, you have to ensure that log is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_log_code(log: *const Log) -> HtpLogCode {
    log.as_ref()
        .map(|log| log.msg.code)
        .unwrap_or(HtpLogCode::ERROR)
}

/// Free log
/// # Safety
/// This function is unsafe because improper use may lead to memory problems. For example, a double-free may occur if the function is called twice on the same raw pointer.
#[no_mangle]
pub unsafe extern "C" fn htp_log_free(log: *mut Log) {
    if !log.is_null() {
        drop(Box::from_raw(log));
    }
}
