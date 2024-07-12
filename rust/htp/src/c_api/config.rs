#![deny(missing_docs)]
use crate::{
    config::{Config, HtpServerPersonality, HtpUrlEncodingHandling},
    hook::{DataExternalCallbackFn, LogExternalCallbackFn, TxExternalCallbackFn},
    HtpStatus,
};
use std::convert::TryInto;

/// Creates a new configuration structure. Configuration structures created at
/// configuration time must not be changed afterwards in order to support lock-less
/// copying.
#[no_mangle]
pub extern "C" fn htp_config_create() -> *mut Config {
    let cfg: Config = Config::default();
    let b = Box::new(cfg);
    Box::into_raw(b)
}

/// Destroy a configuration structure.
/// # Safety
/// This function is unsafe because improper use may lead to memory problems. For example, a double-free may occur if the function is called twice on the same raw pointer.
#[no_mangle]
pub unsafe extern "C" fn htp_config_destroy(cfg: *mut Config) {
    if !cfg.is_null() {
        drop(Box::from_raw(cfg));
    }
}

/// Registers a callback that is invoked every time there is a log message with
/// severity equal and higher than the configured log level.
/// # Safety
/// When calling this method, you have to ensure that cfg is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_config_register_log(cfg: *mut Config, cbk_fn: LogExternalCallbackFn) {
    if let Some(cfg) = cfg.as_mut() {
        cfg.hook_log.register_extern(cbk_fn)
    }
}

/// Registers a REQUEST_BODY_DATA callback.
/// # Safety
/// When calling this method, you have to ensure that cfg is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_config_register_request_body_data(
    cfg: *mut Config,
    cbk_fn: DataExternalCallbackFn,
) {
    if let Some(cfg) = cfg.as_mut() {
        cfg.hook_request_body_data.register_extern(cbk_fn)
    }
}

/// Registers a REQUEST_COMPLETE callback.
/// # Safety
/// When calling this method, you have to ensure that cfg is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_config_register_request_complete(
    cfg: *mut Config,
    cbk_fn: TxExternalCallbackFn,
) {
    if let Some(cfg) = cfg.as_mut() {
        cfg.hook_request_complete.register_extern(cbk_fn)
    }
}

/// Registers a REQUEST_HEADERS callback.
/// # Safety
/// When calling this method, you have to ensure that cfg is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_config_register_request_headers(
    cfg: *mut Config,
    cbk_fn: TxExternalCallbackFn,
) {
    if let Some(cfg) = cfg.as_mut() {
        cfg.hook_request_headers.register_extern(cbk_fn)
    }
}

/// Registers a REQUEST_HEADER_DATA callback.
/// # Safety
/// When calling this method, you have to ensure that cfg is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_config_register_request_header_data(
    cfg: *mut Config,
    cbk_fn: DataExternalCallbackFn,
) {
    if let Some(cfg) = cfg.as_mut() {
        cfg.hook_request_header_data.register_extern(cbk_fn)
    }
}

/// Registers a REQUEST_LINE callback.
/// # Safety
/// When calling this method, you have to ensure that cfg is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_config_register_request_line(
    cfg: *mut Config,
    cbk_fn: TxExternalCallbackFn,
) {
    if let Some(cfg) = cfg.as_mut() {
        cfg.hook_request_line.register_extern(cbk_fn)
    }
}

/// Registers a REQUEST_START callback, which is invoked every time a new
/// request begins and before any parsing is done.
/// # Safety
/// When calling this method, you have to ensure that cfg is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_config_register_request_start(
    cfg: *mut Config,
    cbk_fn: TxExternalCallbackFn,
) {
    if let Some(cfg) = cfg.as_mut() {
        cfg.hook_request_start.register_extern(cbk_fn)
    }
}

/// Registers a HTP_REQUEST_TRAILER callback.
/// # Safety
/// When calling this method, you have to ensure that cfg is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_config_register_request_trailer(
    cfg: *mut Config,
    cbk_fn: TxExternalCallbackFn,
) {
    if let Some(cfg) = cfg.as_mut() {
        cfg.hook_request_trailer.register_extern(cbk_fn)
    }
}

/// Registers a REQUEST_TRAILER_DATA callback.
/// # Safety
/// When calling this method, you have to ensure that cfg is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_config_register_request_trailer_data(
    cfg: *mut Config,
    cbk_fn: DataExternalCallbackFn,
) {
    if let Some(cfg) = cfg.as_mut() {
        cfg.hook_request_trailer_data.register_extern(cbk_fn)
    }
}

/// Registers a RESPONSE_BODY_DATA callback.
/// # Safety
/// When calling this method, you have to ensure that cfg is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_config_register_response_body_data(
    cfg: *mut Config,
    cbk_fn: DataExternalCallbackFn,
) {
    if let Some(cfg) = cfg.as_mut() {
        cfg.hook_response_body_data.register_extern(cbk_fn)
    }
}

/// Registers a RESPONSE_COMPLETE callback.
/// # Safety
/// When calling this method, you have to ensure that cfg is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_config_register_response_complete(
    cfg: *mut Config,
    cbk_fn: TxExternalCallbackFn,
) {
    if let Some(cfg) = cfg.as_mut() {
        cfg.hook_response_complete.register_extern(cbk_fn)
    }
}

/// Registers a RESPONSE_HEADERS callback.
/// # Safety
/// When calling this method, you have to ensure that cfg is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_config_register_response_headers(
    cfg: *mut Config,
    cbk_fn: TxExternalCallbackFn,
) {
    if let Some(cfg) = cfg.as_mut() {
        cfg.hook_response_headers.register_extern(cbk_fn)
    }
}

/// Registers a RESPONSE_HEADER_DATA callback.
/// # Safety
/// When calling this method, you have to ensure that cfg is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_config_register_response_header_data(
    cfg: *mut Config,
    cbk_fn: DataExternalCallbackFn,
) {
    if let Some(cfg) = cfg.as_mut() {
        cfg.hook_response_header_data.register_extern(cbk_fn)
    }
}

/// Registers a RESPONSE_START callback.
/// # Safety
/// When calling this method, you have to ensure that cfg is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_config_register_response_start(
    cfg: *mut Config,
    cbk_fn: TxExternalCallbackFn,
) {
    if let Some(cfg) = cfg.as_mut() {
        cfg.hook_response_start.register_extern(cbk_fn)
    }
}

/// Registers a RESPONSE_TRAILER callback.
/// # Safety
/// When calling this method, you have to ensure that cfg is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_config_register_response_trailer(
    cfg: *mut Config,
    cbk_fn: TxExternalCallbackFn,
) {
    if let Some(cfg) = cfg.as_mut() {
        cfg.hook_response_trailer.register_extern(cbk_fn)
    }
}

/// Registers a RESPONSE_TRAILER_DATA callback.
/// # Safety
/// When calling this method, you have to ensure that cfg is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_config_register_response_trailer_data(
    cfg: *mut Config,
    cbk_fn: DataExternalCallbackFn,
) {
    if let Some(cfg) = cfg.as_mut() {
        cfg.hook_response_trailer_data.register_extern(cbk_fn)
    }
}

/// Registers a TRANSACTION_COMPLETE callback.
/// # Safety
/// When calling this method, you have to ensure that cfg is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_config_register_transaction_complete(
    cfg: *mut Config,
    cbk_fn: TxExternalCallbackFn,
) {
    if let Some(cfg) = cfg.as_mut() {
        cfg.hook_transaction_complete.register_extern(cbk_fn)
    }
}

/// Configures whether backslash characters are treated as path segment separators. They
/// are not on Unix systems, but are on Windows systems. If this setting is enabled, a path
/// such as "/one\two/three" will be converted to "/one/two/three".
/// # Safety
/// When calling this method, you have to ensure that cfg is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_config_set_backslash_convert_slashes(
    cfg: *mut Config,
    enabled: libc::c_int,
) {
    if let Some(cfg) = cfg.as_mut() {
        cfg.set_backslash_convert_slashes(enabled == 1)
    }
}

/// Sets the replacement character that will be used to in the lossy best-fit
/// mapping from multi-byte to single-byte streams. The question mark character
/// is used as the default replacement byte.
/// # Safety
/// When calling this method, you have to ensure that cfg is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_config_set_bestfit_replacement_byte(cfg: *mut Config, b: libc::c_int) {
    if let Some(cfg) = cfg.as_mut() {
        cfg.set_bestfit_replacement_byte(b as u8)
    }
}

/// Configures the maximum compression bomb size LibHTP will decompress.
/// # Safety
/// When calling this method, you have to ensure that cfg is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_config_set_compression_bomb_limit(
    cfg: *mut Config,
    bomblimit: libc::size_t,
) {
    if let Ok(bomblimit) = bomblimit.try_into() {
        if let Some(cfg) = cfg.as_mut() {
            cfg.compression_options.set_bomb_limit(bomblimit)
        }
    }
}

/// Configures the maximum compression time LibHTP will allow.
/// # Safety
/// When calling this method, you have to ensure that cfg is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_config_set_compression_time_limit(
    cfg: *mut Config,
    timelimit: libc::c_uint,
) {
    if let Some(cfg) = cfg.as_mut() {
        cfg.compression_options.set_time_limit(timelimit)
    }
}

/// Configures whether input data will be converted to lowercase. Useful for handling servers with
/// case-insensitive filesystems.
/// # Safety
/// When calling this method, you have to ensure that cfg is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_config_set_convert_lowercase(cfg: *mut Config, enabled: libc::c_int) {
    if let Some(cfg) = cfg.as_mut() {
        cfg.set_convert_lowercase(enabled == 1)
    }
}

/// Configures the maximum size of the buffer LibHTP will use when all data is not available
/// in the current buffer (e.g., a very long header line that might span several packets). This
/// limit is controlled by the field_limit parameter.
/// # Safety
/// When calling this method, you have to ensure that cfg is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_config_set_field_limit(cfg: *mut Config, field_limit: libc::size_t) {
    if let Some(cfg) = cfg.as_mut() {
        cfg.set_field_limit(field_limit)
    }
}

/// Configures the maximum memlimit LibHTP will pass to liblzma.
/// # Safety
/// When calling this method, you have to ensure that cfg is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_config_set_lzma_memlimit(cfg: *mut Config, memlimit: libc::size_t) {
    if let Some(cfg) = cfg.as_mut() {
        cfg.compression_options.set_lzma_memlimit(memlimit)
    }
}

/// Configures the maximum number of lzma layers to pass to the decompressor.
/// # Safety
/// When calling this method, you have to ensure that cfg is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_config_set_lzma_layers(cfg: *mut Config, limit: libc::c_int) {
    if let Some(cfg) = cfg.as_mut() {
        cfg.compression_options.set_lzma_layers(if limit <= 0 {
            None
        } else {
            limit.try_into().ok()
        })
    }
}

/// Configures the maximum number of live transactions per connection
/// # Safety
/// When calling this method, you have to ensure that cfg is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_config_set_max_tx(cfg: *mut Config, limit: u32) {
    if let Some(cfg) = cfg.as_mut() {
        cfg.max_tx = limit;
    }
}

/// Configures how the server reacts to encoded NUL bytes. Some servers will stop at
/// at NUL, while some will respond with 400 or 404. When the termination option is not
/// used, the NUL byte will remain in the path.
/// # Safety
/// When calling this method, you have to ensure that cfg is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_config_set_nul_encoded_terminates(
    cfg: *mut Config,
    enabled: libc::c_int,
) {
    if let Some(cfg) = cfg.as_mut() {
        cfg.set_nul_encoded_terminates(enabled == 1)
    }
}

/// Configures the handling of raw NUL bytes. If enabled, raw NUL terminates strings.
/// # Safety
/// When calling this method, you have to ensure that cfg is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_config_set_nul_raw_terminates(cfg: *mut Config, enabled: libc::c_int) {
    if let Some(cfg) = cfg.as_mut() {
        cfg.set_nul_raw_terminates(enabled == 1)
    }
}

/// Enable or disable request cookie parsing. Enabled by default.
/// # Safety
/// When calling this method, you have to ensure that cfg is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_config_set_parse_request_cookies(
    _cfg: *mut Config,
    _parse_request_cookies: libc::c_int,
) {
    // do nothing, but keep API
}

/// Configures whether consecutive path segment separators will be compressed. When enabled, a path
/// such as "/one//two" will be normalized to "/one/two". Backslash conversion and path segment separator
/// decoding are carried out before compression. For example, the path "/one\\/two\/%5cthree/%2f//four"
/// will be converted to "/one/two/three/four" (assuming all 3 options are enabled).
/// # Safety
/// When calling this method, you have to ensure that cfg is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_config_set_path_separators_compress(
    cfg: *mut Config,
    enabled: libc::c_int,
) {
    if let Some(cfg) = cfg.as_mut() {
        cfg.set_path_separators_compress(enabled == 1)
    }
}

/// Configures whether plus characters are converted to spaces when decoding URL-encoded strings. This
/// is appropriate to do for parameters, but not for URLs. Only applies to contexts where decoding
/// is taking place.
/// # Safety
/// When calling this method, you have to ensure that cfg is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_config_set_plusspace_decode(cfg: *mut Config, enabled: libc::c_int) {
    if let Some(cfg) = cfg.as_mut() {
        cfg.set_plusspace_decode(enabled == 1)
    }
}

/// Configures whether encoded path segment separators will be decoded. Apache does not do
/// this by default, but IIS does. If enabled, a path such as "/one%2ftwo" will be normalized
/// to "/one/two". If the backslash_separators option is also enabled, encoded backslash
/// characters will be converted too (and subsequently normalized to forward slashes).
/// # Safety
/// When calling this method, you have to ensure that cfg is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_config_set_path_separators_decode(
    cfg: *mut Config,
    enabled: libc::c_int,
) {
    if let Some(cfg) = cfg.as_mut() {
        cfg.set_path_separators_decode(enabled == 1)
    }
}

/// Configures whether request data is decompressed
/// # Safety
/// When calling this method, you have to ensure that cfg is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_config_set_request_decompression(
    cfg: *mut Config,
    enabled: libc::c_int,
) {
    if let Some(cfg) = cfg.as_mut() {
        cfg.set_request_decompression(enabled == 1)
    }
}

/// Configures many layers of compression we try to decompress.
/// # Safety
/// When calling this method, you have to ensure that cfg is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_config_set_decompression_layer_limit(
    cfg: *mut Config,
    limit: libc::c_int,
) {
    if let Some(cfg) = cfg.as_mut() {
        cfg.set_decompression_layer_limit(if limit <= 0 {
            None
        } else {
            limit.try_into().ok()
        })
    }
}

/// Enable or disable allowing spaces in URIs. Disabled by default.
/// # Safety
/// When calling this method the given cfg must be initialized or NULL.
#[no_mangle]
pub unsafe extern "C" fn htp_config_set_allow_space_uri(cfg: *mut Config, allow_space: bool) {
    if let Some(cfg) = cfg.as_mut() {
        cfg.set_allow_space_uri(allow_space)
    }
}

/// Configure desired server personality.
/// # Safety
/// When calling this method, you have to ensure that cfg is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_config_set_server_personality(
    cfg: *mut Config,
    personality: HtpServerPersonality,
) -> HtpStatus {
    cfg.as_mut()
        .map(|cfg| cfg.set_server_personality(personality).into())
        .unwrap_or(HtpStatus::ERROR)
}

/// Configures whether %u-encoded sequences are decoded. Such sequences
/// will be treated as invalid URL encoding if decoding is not desirable.
/// # Safety
/// When calling this method, you have to ensure that cfg is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_config_set_u_encoding_decode(cfg: *mut Config, enabled: libc::c_int) {
    if let Some(cfg) = cfg.as_mut() {
        cfg.set_u_encoding_decode(enabled == 1)
    }
}

/// Configures how the server handles to invalid URL encoding.
/// # Safety
/// When calling this method, you have to ensure that cfg is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_config_set_url_encoding_invalid_handling(
    cfg: *mut Config,
    handling: HtpUrlEncodingHandling,
) {
    if let Some(cfg) = cfg.as_mut() {
        cfg.set_url_encoding_invalid_handling(handling)
    }
}

/// Controls whether the data should be treated as UTF-8 and converted to a single-byte
/// stream using best-fit mapping.
/// # Safety
/// When calling this method, you have to ensure that cfg is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_config_set_utf8_convert_bestfit(
    cfg: *mut Config,
    enabled: libc::c_int,
) {
    if let Some(cfg) = cfg.as_mut() {
        cfg.set_utf8_convert_bestfit(enabled == 1)
    }
}

/// Configures whether to attempt to decode a double encoded query in the normalized uri
/// # Safety
/// When calling this method, you have to ensure that cfg is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_config_set_double_decode_normalized_query(
    cfg: *mut Config,
    set: bool,
) {
    if let Some(cfg) = cfg.as_mut() {
        cfg.set_double_decode_normalized_query(set)
    }
}

/// Configures whether to attempt to decode a double encoded path in the normalized uri
/// # Safety
/// When calling this method, you have to ensure that cfg is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_config_set_double_decode_normalized_path(cfg: *mut Config, set: bool) {
    if let Some(cfg) = cfg.as_mut() {
        cfg.set_double_decode_normalized_path(set)
    }
}

/// Configures whether to normalize URIs into a complete or partial form.
/// Pass `true` to use complete normalized URI or `false` to use partials.
/// # Safety
/// When calling this method, you have to ensure that cfg is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_config_set_normalized_uri_include_all(cfg: *mut Config, set: bool) {
    if let Some(cfg) = cfg.as_mut() {
        cfg.set_normalized_uri_include_all(set)
    }
}

/// Configures whether transactions will be automatically destroyed once they
/// are processed and all callbacks invoked. This option is appropriate for
/// programs that process transactions as they are processed.
/// # Safety
/// When calling this method, you have to ensure that cfg is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_config_set_tx_auto_destroy(
    cfg: *mut Config,
    tx_auto_destroy: libc::c_int,
) {
    if let Some(cfg) = cfg.as_mut() {
        cfg.set_tx_auto_destroy(tx_auto_destroy == 1)
    }
}

/// Configures whether incomplete transactions will be flushed when a connection is closed.
///
/// This will invoke the transaction complete callback for each incomplete transaction. The
/// transactions passed to the callback will not have their request and response state set
/// to complete - they will simply be passed with the state they have within the parser at
/// the time of the call.
///
/// This option is intended to be used when a connection is closing and we want to process
/// any incomplete transactions that were in flight, or which never completed due to packet
/// loss or parsing errors.
///
/// These transactions will also be removed from the parser when auto destroy is enabled.
///
/// # Safety
/// When calling this method, you have to ensure that cfg is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_config_set_flush_incomplete(
    cfg: *mut Config,
    flush_incomplete: libc::c_int,
) {
    if let Some(cfg) = cfg.as_mut() {
        cfg.set_flush_incomplete(flush_incomplete == 1)
    }
}

/// Enable or disable the built-in Urlencoded parser. Disabled by default.
/// The parser will parse query strings and request bodies with the appropriate MIME type.
/// # Safety
/// When calling this method, you have to ensure that cfg is either properly initialized or NULL
#[no_mangle]
pub unsafe extern "C" fn htp_config_set_parse_urlencoded(
    cfg: *mut Config,
    parse_urlencoded: libc::c_int,
) {
    if let Some(cfg) = cfg.as_mut() {
        cfg.set_parse_urlencoded(parse_urlencoded == 1)
    }
}
