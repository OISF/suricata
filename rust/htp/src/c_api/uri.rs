use crate::{bstr::Bstr, uri::Uri};

/// Get the hostname of a uri.
///
/// Returns the hostname for uri or NULL on error.
/// # Safety
/// When calling this method, you have to ensure that uri is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_uri_hostname(uri: *const Uri) -> *const Bstr {
    uri.as_ref()
        .and_then(|uri| uri.hostname.as_ref())
        .map(|hostname| hostname as *const Bstr)
        .unwrap_or(std::ptr::null())
}

/// Get the path of a uri.
///
/// Returns the path for uri or NULL on error.
/// # Safety
/// When calling this method, you have to ensure that uri is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_uri_path(uri: *const Uri) -> *const Bstr {
    uri.as_ref()
        .and_then(|uri| uri.path.as_ref())
        .map(|path| path as *const Bstr)
        .unwrap_or(std::ptr::null())
}
