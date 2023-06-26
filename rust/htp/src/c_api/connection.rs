#![deny(missing_docs)]
use crate::{connection::Connection, log::Log};

/// Returns the request_data_counter
/// # Safety
/// When calling this method, you have to ensure that conn is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_conn_request_data_counter(conn: *const Connection) -> u64 {
    conn.as_ref()
        .map(|conn| conn.request_data_counter)
        .unwrap_or(0)
}

/// Returns the response_data_counter
/// # Safety
/// When calling this method, you have to ensure that conn is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_conn_response_data_counter(conn: *const Connection) -> u64 {
    conn.as_ref()
        .map(|conn| conn.response_data_counter)
        .unwrap_or(0)
}

/// Get the next logged message from the connection
///
/// Returns the next log or NULL on error.
/// The caller must free this result with htp_log_free
/// # Safety
/// When calling this method, you have to ensure that conn is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_conn_next_log(conn: *const Connection) -> *mut Log {
    conn.as_ref()
        .and_then(|conn| conn.get_next_log())
        .map(|log| Box::into_raw(Box::new(log)))
        .unwrap_or(std::ptr::null_mut())
}
