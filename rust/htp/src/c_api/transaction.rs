use crate::{
    bstr::Bstr, c_api::header::htp_headers_get, config::Config,
    connection_parser::ConnectionParser, decompressors::HtpContentEncoding,
    hook::DataExternalCallbackFn, request::HtpMethod, transaction::*, uri::Uri,
};
use std::{
    convert::{TryFrom, TryInto},
    rc::Rc,
};

/// Destroys the supplied transaction.
/// # Safety
/// When calling this method, you have to ensure that tx is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_tx_destroy(connp: *mut ConnectionParser, tx: *const Transaction) {
    if let (Some(connp), Some(tx)) = (connp.as_mut(), tx.as_ref()) {
        connp.remove_tx(tx.index)
    }
}

/// Get a transaction's normalized parsed uri.
///
/// tx: Transaction pointer.
/// # Safety
/// When calling this method, you have to ensure that tx is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_tx_normalized_uri(tx: *const Transaction) -> *const Bstr {
    if (*tx).cfg.decoder_cfg.normalized_uri_include_all {
        tx.as_ref()
            .and_then(|tx| tx.complete_normalized_uri.as_ref())
            .map(|uri| uri as *const Bstr)
            .unwrap_or(std::ptr::null())
    } else {
        tx.as_ref()
            .and_then(|tx| tx.partial_normalized_uri.as_ref())
            .map(|uri| uri as *const Bstr)
            .unwrap_or(std::ptr::null())
    }
}

/// Get the transaction's configuration.
///
/// tx: Transaction pointer.
///
/// Returns a pointer to the configuration or NULL on error.
/// # Safety
/// When calling this method, you have to ensure that tx is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_tx_cfg(tx: *const Transaction) -> *const Config {
    tx.as_ref()
        .map(|tx| Rc::as_ptr(&tx.cfg))
        .unwrap_or(std::ptr::null())
}

/// Returns the user data associated with this transaction or NULL on error.
/// # Safety
/// When calling this method, you have to ensure that tx is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_tx_get_user_data(tx: *const Transaction) -> *mut libc::c_void {
    tx.as_ref()
        .and_then(|val| val.user_data::<*mut libc::c_void>())
        .copied()
        .unwrap_or(std::ptr::null_mut())
}

/// Associates user data with this transaction.
/// # Safety
/// When calling this method, you have to ensure that tx is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_tx_set_user_data(tx: *mut Transaction, user_data: *mut libc::c_void) {
    if let Some(tx) = tx.as_mut() {
        tx.set_user_data(Box::new(user_data))
    }
}

/// Get a transaction's request line.
///
/// tx: Transaction pointer.
///
/// Returns the request line or NULL on error.
/// # Safety
/// When calling this method, you have to ensure that tx is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_tx_request_line(tx: *const Transaction) -> *const Bstr {
    tx.as_ref()
        .and_then(|tx| tx.request_line.as_ref())
        .map(|line| line as *const Bstr)
        .unwrap_or(std::ptr::null())
}

/// Get a transaction's request method.
///
/// tx: Transaction pointer.
///
/// Returns the request method or NULL on error.
/// # Safety
/// When calling this method, you have to ensure that tx is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_tx_request_method(tx: *const Transaction) -> *const Bstr {
    tx.as_ref()
        .and_then(|tx| tx.request_method.as_ref())
        .map(|method| method as *const Bstr)
        .unwrap_or(std::ptr::null())
}

/// Get the transaction's request method number.
///
/// tx: Transaction pointer.
///
/// Returns the request method number or ERROR on error.
/// # Safety
/// When calling this method, you have to ensure that tx is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_tx_request_method_number(tx: *const Transaction) -> HtpMethod {
    tx.as_ref()
        .map(|tx| tx.request_method_number)
        .unwrap_or(HtpMethod::ERROR)
}

/// Get a transaction's request uri.
///
/// tx: Transaction pointer.
///
/// Returns the request uri or NULL on error.
/// # Safety
/// When calling this method, you have to ensure that tx is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_tx_request_uri(tx: *const Transaction) -> *const Bstr {
    tx.as_ref()
        .and_then(|tx| tx.request_uri.as_ref())
        .map(|uri| uri as *const Bstr)
        .unwrap_or(std::ptr::null())
}

/// Get a transaction's request protocol.
///
/// tx: Transaction pointer.
///
/// Returns the protocol or NULL on error.
/// # Safety
/// When calling this method, you have to ensure that tx is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_tx_request_protocol(tx: *const Transaction) -> *const Bstr {
    tx.as_ref()
        .and_then(|tx| tx.request_protocol.as_ref())
        .map(|protocol| protocol as *const Bstr)
        .unwrap_or(std::ptr::null())
}

/// Get a transaction's request protocol number.
///
/// tx: Transaction pointer.
///
/// Returns the protocol number or ERROR on error.
/// # Safety
/// When calling this method, you have to ensure that tx is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_tx_request_protocol_number(tx: *const Transaction) -> HtpProtocol {
    tx.as_ref()
        .map(|tx| tx.request_protocol_number)
        .unwrap_or(HtpProtocol::ERROR)
}

/// Get whether a transaction's protocol is version 0.9.
///
/// tx: Transaction pointer.
///
/// Returns 1 if the version is 0.9 or 0 otherwise. A NULL argument will
/// also result in a return value of 0.
/// # Safety
/// When calling this method, you have to ensure that tx is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_tx_is_protocol_0_9(tx: *const Transaction) -> i32 {
    tx.as_ref().map(|tx| tx.is_protocol_0_9 as i32).unwrap_or(0)
}

/// Get whether a transaction contains a successful 101 Switching Protocol response to HTTP/2.0
///
/// tx: Transaction pointer.
///
/// Returns 1 if the transaction is an HTTP/2.0 upgrade or 0 otherwise. A NULL argument will
/// also result in a return value of 0.
/// # Safety
/// When calling this method, you have to ensure that tx is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_tx_is_http_2_upgrade(tx: *const Transaction) -> i32 {
    tx.as_ref()
        .map(|tx| tx.is_http_2_upgrade as i32)
        .unwrap_or(0)
}

/// Get a transaction's parsed uri.
///
/// tx: Transaction pointer.
///
/// Returns the parsed uri or NULL on error.
/// # Safety
/// When calling this method, you have to ensure that tx is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_tx_parsed_uri(tx: *const Transaction) -> *const Uri {
    tx.as_ref()
        .and_then(|tx| tx.parsed_uri.as_ref())
        .map(|uri| uri as *const Uri)
        .unwrap_or(std::ptr::null())
}

/// Get a transaction's request headers.
///
/// tx: Transaction pointer.
///
/// Returns the request headers or NULL on error.
/// # Safety
/// When calling this method, you have to ensure that tx is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_tx_request_headers(tx: *const Transaction) -> *const Headers {
    tx.as_ref()
        .map(|tx| &tx.request_headers as *const Headers)
        .unwrap_or(std::ptr::null())
}

/// Get a transaction's request headers size.
///
/// tx: Transaction pointer.
///
/// Returns the size or -1 on error.
/// # Safety
/// When calling this method, you have to ensure that tx is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_tx_request_headers_size(tx: *const Transaction) -> isize {
    tx.as_ref()
        .map(|tx| isize::try_from(tx.request_headers.size()).unwrap_or(-1))
        .unwrap_or(-1)
}

/// Get the first request header value matching the key from a transaction.
///
/// tx: Transaction pointer.
/// ckey: Header name to match.
///
/// Returns the header or NULL when not found or on error
/// # Safety
/// When calling this method, you have to ensure that tx is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_tx_request_header(
    tx: *const Transaction,
    ckey: *const libc::c_char,
) -> *const Header {
    tx.as_ref()
        .map(|tx| htp_headers_get(&tx.request_headers, ckey))
        .unwrap_or(std::ptr::null())
}

/// Get the request header at the given index.
///
/// tx: Transaction pointer.
/// index: request header table index.
///
/// Returns the header or NULL on error
/// # Safety
/// When calling this method, you have to ensure that tx is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_tx_request_header_index(
    tx: *const Transaction,
    index: usize,
) -> *const Header {
    tx.as_ref()
        .map(|tx| {
            tx.request_headers
                .elements
                .get(index)
                .map(|value| value as *const Header)
                .unwrap_or(std::ptr::null())
        })
        .unwrap_or(std::ptr::null())
}

/// Get a transaction's request transfer coding.
///
/// tx: Transaction pointer.
///
/// Returns the transfer coding or ERROR on error.
/// # Safety
/// When calling this method, you have to ensure that tx is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_tx_request_transfer_coding(
    tx: *const Transaction,
) -> HtpTransferCoding {
    tx.as_ref()
        .map(|tx| tx.request_transfer_coding)
        .unwrap_or(HtpTransferCoding::ERROR)
}

/// Get a transaction's request content encoding.
///
/// tx: Transaction pointer.
///
/// Returns the content encoding or ERROR on error.
/// # Safety
/// When calling this method, you have to ensure that tx is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_tx_request_content_encoding(
    tx: *const Transaction,
) -> HtpContentEncoding {
    tx.as_ref()
        .map(|tx| tx.request_content_encoding)
        .unwrap_or(HtpContentEncoding::ERROR)
}

/// Get a transaction's request content type.
///
/// tx: Transaction pointer.
///
/// Returns the content type or NULL on error.
/// # Safety
/// When calling this method, you have to ensure that tx is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_tx_request_content_type(tx: *const Transaction) -> *const Bstr {
    tx.as_ref()
        .and_then(|tx| tx.request_content_type.as_ref())
        .map(|content_type| content_type as *const Bstr)
        .unwrap_or(std::ptr::null())
}

/// Get a transaction's request content length.
///
/// tx: Transaction pointer.
///
/// Returns the content length or -1 on error.
/// # Safety
/// When calling this method, you have to ensure that tx is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_tx_request_content_length(tx: *const Transaction) -> i64 {
    tx.as_ref()
        .map(|tx| {
            tx.request_content_length
                .map(|len| len.try_into().ok().unwrap_or(-1))
                .unwrap_or(-1)
        })
        .unwrap_or(-1)
}

/// Get the transaction's request authentication type.
///
/// tx: Transaction pointer.
///
/// Returns the auth type or HTP_AUTH_ERROR on error.
/// # Safety
/// When calling this method, you have to ensure that tx is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_tx_request_auth_type(tx: *const Transaction) -> HtpAuthType {
    tx.as_ref()
        .map(|tx| tx.request_auth_type)
        .unwrap_or(HtpAuthType::ERROR)
}

/// Get a transaction's request hostname.
///
/// tx: Transaction pointer.
///
/// Returns the request hostname or NULL on error.
/// # Safety
/// When calling this method, you have to ensure that tx is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_tx_request_hostname(tx: *const Transaction) -> *const Bstr {
    tx.as_ref()
        .and_then(|tx| tx.request_hostname.as_ref())
        .map(|hostname| hostname as *const Bstr)
        .unwrap_or(std::ptr::null())
}

/// Get the transaction's request port number.
///
/// tx: Transaction pointer.
///
/// Returns the request port number or -1 on error.
/// # Safety
/// When calling this method, you have to ensure that tx is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_tx_request_port_number(tx: *const Transaction) -> i32 {
    tx.as_ref()
        .and_then(|tx| tx.request_port_number.as_ref())
        .map(|port| *port as i32)
        .unwrap_or(-1)
}

/// Get a transaction's request message length.
///
/// tx: Transaction pointer.
///
/// Returns the request message length or -1 on error.
/// # Safety
/// When calling this method, you have to ensure that tx is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_tx_request_message_len(tx: *const Transaction) -> i64 {
    tx.as_ref()
        .map(|tx| tx.request_message_len.try_into().ok().unwrap_or(-1))
        .unwrap_or(-1)
}

/// Get a transaction's request entity length.
///
/// tx: Transaction pointer.
///
/// Returns the request entity length or -1 on error.
/// # Safety
/// When calling this method, you have to ensure that tx is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_tx_request_entity_len(tx: *const Transaction) -> i64 {
    tx.as_ref()
        .map(|tx| tx.request_entity_len.try_into().ok().unwrap_or(-1))
        .unwrap_or(-1)
}

/// Get a transaction's response line.
///
/// tx: Transaction pointer.
///
/// Returns the response line or NULL on error.
/// # Safety
/// When calling this method, you have to ensure that tx is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_tx_response_line(tx: *const Transaction) -> *const Bstr {
    tx.as_ref()
        .and_then(|tx| tx.response_line.as_ref())
        .map(|response_line| response_line as *const Bstr)
        .unwrap_or(std::ptr::null())
}

/// Get a transaction's response protocol.
///
/// tx: Transaction pointer.
///
/// Returns the response protocol or NULL on error.
/// # Safety
/// When calling this method, you have to ensure that tx is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_tx_response_protocol(tx: *const Transaction) -> *const Bstr {
    tx.as_ref()
        .and_then(|tx| tx.response_protocol.as_ref())
        .map(|response_protocol| response_protocol as *const Bstr)
        .unwrap_or(std::ptr::null())
}

/// Get a transaction's response protocol number.
///
/// tx: Transaction pointer.
///
/// Returns the protocol number or ERROR on error.
/// # Safety
/// When calling this method, you have to ensure that tx is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_tx_response_protocol_number(tx: *const Transaction) -> HtpProtocol {
    tx.as_ref()
        .map(|tx| tx.response_protocol_number)
        .unwrap_or(HtpProtocol::ERROR)
}

/// Get the transaction's response status.
///
/// tx: Transaction pointer.
///
/// Returns the response status or NULL on error.
/// # Safety
/// When calling this method, you have to ensure that tx is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_tx_response_status(tx: *const Transaction) -> *const Bstr {
    tx.as_ref()
        .and_then(|tx| tx.response_status.as_ref())
        .map(|response_status| response_status as *const Bstr)
        .unwrap_or(std::ptr::null())
}

/// Get the transaction's response status number.
///
/// tx: Transaction pointer.
///
/// Returns the response status number or -1 on error.
/// # Safety
/// When calling this method, you have to ensure that tx is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_tx_response_status_number(tx: *const Transaction) -> i32 {
    tx.as_ref()
        .map(|tx| match tx.response_status_number {
            HtpResponseNumber::UNKNOWN => 0,
            HtpResponseNumber::INVALID => -1,
            HtpResponseNumber::VALID(status) => status as i32,
        })
        .unwrap_or(-1)
}
/// Get the transaction's response status expected number.
///
/// tx: Transaction pointer.
///
/// Returns the expected number or -1 on error.
/// # Safety
/// When calling this method, you have to ensure that tx is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_tx_response_status_expected_number(tx: *const Transaction) -> i32 {
    tx.as_ref()
        .map(|tx| tx.response_status_expected_number as i32)
        .unwrap_or(-1)
}

/// Get a transaction's response message.
///
/// tx: Transaction pointer.
///
/// Returns the response message or NULL on error.
/// # Safety
/// When calling this method, you have to ensure that tx is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_tx_response_message(tx: *const Transaction) -> *const Bstr {
    tx.as_ref()
        .and_then(|tx| tx.response_message.as_ref())
        .map(|response_message| response_message as *const Bstr)
        .unwrap_or(std::ptr::null())
}

/// Get a transaction's response headers.
///
/// tx: Transaction pointer.
///
/// Returns the response headers or NULL on error.
/// # Safety
/// When calling this method, you have to ensure that tx is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_tx_response_headers(tx: *const Transaction) -> *const Headers {
    tx.as_ref()
        .map(|tx| &tx.response_headers as *const Headers)
        .unwrap_or(std::ptr::null())
}

/// Get a transaction's response headers size.
///
/// tx: Transaction pointer.
///
/// Returns the size or -1 on error.
/// # Safety
/// When calling this method, you have to ensure that tx is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_tx_response_headers_size(tx: *const Transaction) -> isize {
    tx.as_ref()
        .map(|tx| isize::try_from(tx.response_headers.size()).unwrap_or(-1))
        .unwrap_or(-1)
}

/// Get the first response header value matching the key from a transaction.
///
/// tx: Transaction pointer.
/// ckey: Header name to match.
///
/// Returns the header or NULL when not found or on error
/// # Safety
/// When calling this method, you have to ensure that tx is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_tx_response_header(
    tx: *const Transaction,
    ckey: *const libc::c_char,
) -> *const Header {
    tx.as_ref()
        .map(|tx| htp_headers_get(&tx.response_headers, ckey))
        .unwrap_or(std::ptr::null())
}

/// Get the response header at the given index.
///
/// tx: Transaction pointer.
/// index: response header table index.
///
/// Returns the header or NULL on error
/// # Safety
/// When calling this method, you have to ensure that tx is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_tx_response_header_index(
    tx: *const Transaction,
    index: usize,
) -> *const Header {
    tx.as_ref()
        .map(|tx| {
            tx.response_headers
                .elements
                .get(index)
                .map(|value| value as *const Header)
                .unwrap_or(std::ptr::null())
        })
        .unwrap_or(std::ptr::null())
}

/// Get a transaction's response message length.
///
/// tx: Transaction pointer.
///
/// Returns the response message length or -1 on error.
/// # Safety
/// When calling this method, you have to ensure that tx is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_tx_response_message_len(tx: *const Transaction) -> i64 {
    tx.as_ref()
        .map(|tx| tx.response_message_len.try_into().ok().unwrap_or(-1))
        .unwrap_or(-1)
}

/// Get a transaction's response entity length.
///
/// tx: Transaction pointer.
///
/// Returns the response entity length or -1 on error.
/// # Safety
/// When calling this method, you have to ensure that tx is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_tx_response_entity_len(tx: *const Transaction) -> i64 {
    tx.as_ref()
        .map(|tx| tx.response_entity_len.try_into().ok().unwrap_or(-1))
        .unwrap_or(-1)
}

/// Get a transaction's response content length.
///
/// tx: Transaction pointer.
///
/// Returns the response content length or -1 on error.
/// # Safety
/// When calling this method, you have to ensure that tx is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_tx_response_content_length(tx: *const Transaction) -> i64 {
    tx.as_ref()
        .map(|tx| {
            tx.response_content_length
                .map(|len| len.try_into().ok().unwrap_or(-1))
                .unwrap_or(-1)
        })
        .unwrap_or(-1)
}

/// Get a transaction's response content type.
///
/// tx: Transaction pointer.
///
/// Returns the response content type or -1 on error.
/// # Safety
/// When calling this method, you have to ensure that tx is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_tx_response_content_type(tx: *const Transaction) -> *const Bstr {
    tx.as_ref()
        .and_then(|tx| tx.response_content_type.as_ref())
        .map(|response_content_type| response_content_type as *const Bstr)
        .unwrap_or(std::ptr::null())
}

/// Get the transaction's bit flags.
///
/// tx: Transaction pointer.
///
/// Returns the flags represented as an integer or 0 if the flags are empty
/// or a NULL ptr is passed as an argument.
/// # Safety
/// When calling this method, you have to ensure that tx is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_tx_flags(tx: *const Transaction) -> u64 {
    tx.as_ref().map(|tx| tx.flags).unwrap_or(0)
}

/// Get the transaction's request progress.
///
/// tx: Transaction pointer.
///
/// Returns the progress or HTP_REQUEST_ERROR on error.
/// # Safety
/// When calling this method, you have to ensure that tx is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_tx_request_progress(tx: *const Transaction) -> HtpRequestProgress {
    tx.as_ref()
        .map(|tx| tx.request_progress)
        .unwrap_or(HtpRequestProgress::ERROR)
}

/// Get the transaction's response progress.
///
/// tx: Transaction pointer.
///
/// Returns the progress or ERROR on error.
/// # Safety
/// When calling this method, you have to ensure that tx is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_tx_response_progress(tx: *const Transaction) -> HtpResponseProgress {
    tx.as_ref()
        .map(|tx| tx.response_progress)
        .unwrap_or(HtpResponseProgress::ERROR)
}

/// Get the transaction's index.
///
/// tx: Transaction pointer.
///
/// Returns an index or -1 on error.
/// # Safety
/// When calling this method, you have to ensure that tx is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_tx_index(tx: *const Transaction) -> isize {
    tx.as_ref()
        .map(|tx| isize::try_from(tx.index).unwrap_or(-1))
        .unwrap_or(-1)
}

/// Register callback for the transaction-specific RESPONSE_BODY_DATA hook.
/// # Safety
/// When calling this method, you have to ensure that tx is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_tx_register_response_body_data(
    tx: *mut Transaction,
    cbk_fn: DataExternalCallbackFn,
) {
    if let Some(tx) = tx.as_mut() {
        tx.hook_response_body_data.register_extern(cbk_fn)
    }
}

/// Get the data's transaction.
///
/// Returns the transaction or NULL on error.
/// # Safety
/// When calling this method, you have to ensure that data is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_tx_data_tx(data: *const Data) -> *const Transaction {
    data.as_ref()
        .map(|data| data.tx() as *const Transaction)
        .unwrap_or(std::ptr::null())
}

/// Get the data pointer.
///
/// Returns the data or NULL on error.
/// # Safety
/// When calling this method, you have to ensure that data is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_tx_data_data(data: *const Data) -> *const u8 {
    data.as_ref()
        .map(|data| data.data())
        .unwrap_or(std::ptr::null())
}

/// Get the length of the data.
///
/// Returns the length or -1 on error.
/// # Safety
/// When calling this method, you have to ensure that data is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_tx_data_len(data: *const Data) -> isize {
    data.as_ref()
        .map(|data| isize::try_from(data.len()).unwrap_or(-1))
        .unwrap_or(-1)
}

/// Get whether this data is empty.
///
/// Returns true if data is NULL or zero-length.
/// # Safety
/// When calling this method, you have to ensure that data is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_tx_data_is_empty(data: *const Data) -> bool {
    data.as_ref().map(|data| data.is_empty()).unwrap_or(true)
}
