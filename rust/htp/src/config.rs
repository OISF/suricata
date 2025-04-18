use crate::decompressors::Options;
use crate::{
    error::Result,
    hook::{DataHook, TxHook},
    unicode_bestfit_map::UnicodeBestfitMap,
    HtpStatus,
};

use crate::hook::{TxCreateCallbackFn, TxDestroyCallbackFn};

#[cfg(test)]
use crate::hook::{DataNativeCallbackFn, TxNativeCallbackFn};

/// Configuration for libhtp parsing.
#[derive(Clone)]
pub struct Config {
    /// The maximum size of the buffer that is used when the current
    /// input chunk does not contain all the necessary data (e.g., a header
    /// line that spans several packets).
    pub(crate) field_limit: usize,
    /// Server personality identifier.
    pub(crate) server_personality: HtpServerPersonality,
    /// Decoder configuration for url path.
    pub(crate) decoder_cfg: DecoderConfig,
    /// Transaction creation hook.
    /// Used by suricata to allocate its transaction (user data)
    /// And make libhtp.rs tx creation fail (return None) if suricata failed
    /// to do the C allocation.
    pub(crate) hook_tx_create: Option<TxCreateCallbackFn>,
    /// Transaction destroy hook.
    /// Used by suricata to free its transaction (user data)
    pub(crate) hook_tx_destroy: Option<TxDestroyCallbackFn>,
    /// Request start hook, invoked when the parser receives the first byte of a new
    /// request. Because an HTTP transaction always starts with a request, this hook
    /// doubles as a transaction start hook.
    pub(crate) hook_request_start: TxHook,
    /// Request line hook, invoked after a request line has been parsed.
    pub(crate) hook_request_line: TxHook,
    /// Receives raw request header data, starting immediately after the request line,
    /// including all headers as they are seen on the TCP connection, and including the
    /// terminating empty line. Not available on genuine HTTP/0.9 requests (because
    /// they don't use headers).
    pub(crate) hook_request_header_data: DataHook,
    /// Request headers hook, invoked after all request headers are seen.
    #[cfg(test)]
    pub(crate) hook_request_headers: TxHook,
    /// Request body data hook, invoked every time body data is available. Each
    /// invocation will provide a Data instance. Chunked data
    /// will be dechunked before the data is passed to this hook. Decompression
    /// is not currently implemented. At the end of the request body
    /// there will be a call with the data set to None.
    pub(crate) hook_request_body_data: DataHook,
    /// Receives raw request trailer data, which can be available on requests that have
    /// chunked bodies. The data starts immediately after the zero-length chunk
    /// and includes the terminating empty line.
    pub(crate) hook_request_trailer_data: DataHook,
    /// Request trailer hook, invoked after all trailer headers are seen,
    /// and if they are seen (not invoked otherwise).
    pub(crate) hook_request_trailer: TxHook,
    /// Request hook, invoked after a complete request is seen.
    pub(crate) hook_request_complete: TxHook,
    /// Response startup hook, invoked when a response transaction is found and
    /// processing started.
    pub(crate) hook_response_start: TxHook,
    /// Response line hook, invoked after a response line has been parsed.
    #[cfg(test)]
    pub(crate) hook_response_line: TxHook,
    /// Receives raw response header data, starting immediately after the status line
    /// and including all headers as they are seen on the TCP connection, and including the
    /// terminating empty line. Not available on genuine HTTP/0.9 responses (because
    /// they don't have response headers).
    pub(crate) hook_response_header_data: DataHook,
    /// Response headers book, invoked after all response headers have been seen.
    #[cfg(test)]
    pub(crate) hook_response_headers: TxHook,
    /// Response body data hook, invoked every time body data is available. Each
    /// invocation will provide a Data instance. Chunked data
    /// will be dechunked before the data is passed to this hook. By default,
    /// compressed data will be decompressed, but decompression can be disabled
    /// in configuration. At the end of the response body there will be a call
    /// with the data pointer set to NULL.
    pub(crate) hook_response_body_data: DataHook,
    /// Receives raw response trailer data, which can be available on responses that have
    /// chunked bodies. The data starts immediately after the zero-length chunk
    /// and includes the terminating empty line.
    pub(crate) hook_response_trailer_data: DataHook,
    /// Response trailer hook, invoked after all trailer headers have been processed,
    /// and only if the trailer exists.
    pub(crate) hook_response_trailer: TxHook,
    /// Response hook, invoked after a response has been seen. Because sometimes servers
    /// respond before receiving complete requests, a response_complete callback may be
    /// invoked prior to a request_complete callback.
    pub(crate) hook_response_complete: TxHook,
    /// Transaction complete hook, which is invoked once the entire transaction is
    /// considered complete (request and response are both complete). This is always
    /// the last hook to be invoked.
    #[cfg(test)]
    pub(crate) hook_transaction_complete: TxHook,
    /// Reaction to leading whitespace on the request line
    pub(crate) requestline_leading_whitespace_unwanted: HtpUnwanted,
    /// Whether to decompress compressed request bodies.
    pub(crate) request_decompression_enabled: bool,
    /// Configuration options for decompression.
    pub(crate) compression_options: Options,
    /// Maximum number of transactions
    pub(crate) max_tx: u32,
    /// Maximum number of headers
    pub(crate) number_headers_limit: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            field_limit: 18000,
            server_personality: HtpServerPersonality::MINIMAL,
            decoder_cfg: Default::default(),
            hook_tx_create: None,
            hook_tx_destroy: None,
            hook_request_start: TxHook::default(),
            hook_request_line: TxHook::default(),
            hook_request_header_data: DataHook::default(),
            #[cfg(test)]
            hook_request_headers: TxHook::default(),
            hook_request_body_data: DataHook::default(),
            hook_request_trailer_data: DataHook::default(),
            hook_request_trailer: TxHook::default(),
            hook_request_complete: TxHook::default(),
            hook_response_start: TxHook::default(),
            #[cfg(test)]
            hook_response_line: TxHook::default(),
            hook_response_header_data: DataHook::default(),
            #[cfg(test)]
            hook_response_headers: TxHook::default(),
            hook_response_body_data: DataHook::default(),
            hook_response_trailer_data: DataHook::default(),
            hook_response_trailer: TxHook::default(),
            hook_response_complete: TxHook::default(),
            #[cfg(test)]
            hook_transaction_complete: TxHook::default(),
            requestline_leading_whitespace_unwanted: HtpUnwanted::Ignore,
            request_decompression_enabled: false,
            compression_options: Options::default(),
            max_tx: 512,
            number_headers_limit: 1024,
        }
    }
}

/// Configuration options for decoding.
#[derive(Copy, Clone)]
pub(crate) struct DecoderConfig {
    ///Whether to double decode the path in normalized uri
    pub(crate) double_decode_normalized_path: bool,
    /// Whether to double decode the query in the normalized uri
    pub(crate) double_decode_normalized_query: bool,
    // Path-specific decoding options.
    /// Convert backslash characters to slashes.
    pub(crate) backslash_convert_slashes: bool,
    /// Convert to lowercase.
    pub(crate) convert_lowercase: bool,
    /// Compress slash characters.
    pub(crate) path_separators_compress: bool,
    /// Should we URL-decode encoded path segment separators?
    pub(crate) path_separators_decode: bool,
    /// Should we decode '+' characters to spaces?
    pub(crate) plusspace_decode: bool,
    // Special characters options.
    /// Controls how raw NUL bytes are handled.
    pub(crate) nul_raw_terminates: bool,
    /// Determines server response to a raw NUL byte in the path.
    pub(crate) nul_raw_unwanted: HtpUnwanted,
    /// Reaction to control characters.
    pub(crate) control_chars_unwanted: HtpUnwanted,
    /// Allow whitespace characters in request uri path
    pub(crate) allow_space_uri: bool,
    // URL encoding options.
    /// Should we decode %u-encoded characters?
    pub(crate) u_encoding_decode: bool,
    /// Reaction to %u encoding.
    pub(crate) u_encoding_unwanted: HtpUnwanted,
    /// Handling of invalid URL encodings.
    pub(crate) url_encoding_invalid_handling: HtpUrlEncodingHandling,
    /// Reaction to invalid URL encoding.
    pub(crate) url_encoding_invalid_unwanted: HtpUnwanted,
    /// Controls how encoded NUL bytes are handled.
    pub(crate) nul_encoded_terminates: bool,
    /// How are we expected to react to an encoded NUL byte?
    pub(crate) nul_encoded_unwanted: HtpUnwanted,
    // Normalized URI preference
    /// Controls whether the client wants the complete or partial normalized URI.
    pub(crate) normalized_uri_include_all: bool,
    // UTF-8 options.
    /// Controls how invalid UTF-8 characters are handled.
    pub(crate) utf8_invalid_unwanted: HtpUnwanted,
    /// Convert UTF-8 characters into bytes using best-fit mapping.
    pub(crate) utf8_convert_bestfit: bool,
    /// Best-fit map for UTF-8 decoding.
    pub(crate) bestfit_map: UnicodeBestfitMap,
}

impl Default for DecoderConfig {
    fn default() -> Self {
        Self {
            double_decode_normalized_path: false,
            double_decode_normalized_query: false,
            backslash_convert_slashes: false,
            convert_lowercase: false,
            path_separators_compress: false,
            path_separators_decode: false,
            plusspace_decode: true,
            nul_raw_terminates: false,
            nul_raw_unwanted: HtpUnwanted::Ignore,
            control_chars_unwanted: HtpUnwanted::Ignore,
            allow_space_uri: false,
            u_encoding_decode: false,
            u_encoding_unwanted: HtpUnwanted::Ignore,
            url_encoding_invalid_handling: HtpUrlEncodingHandling::PRESERVE_PERCENT,
            url_encoding_invalid_unwanted: HtpUnwanted::Ignore,
            nul_encoded_terminates: false,
            nul_encoded_unwanted: HtpUnwanted::Ignore,
            normalized_uri_include_all: false,
            utf8_invalid_unwanted: HtpUnwanted::Ignore,
            utf8_convert_bestfit: false,
            bestfit_map: UnicodeBestfitMap::default(),
        }
    }
}

/// Enumerates the possible server personalities.
#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum HtpServerPersonality {
    /// Minimal personality that performs as little work as possible. All optional
    /// features are disabled. This personality is a good starting point for customization.
    MINIMAL,
    /// A generic personality that aims to work reasonably well for all server types.
    GENERIC,
    /// The IDS personality tries to perform as much decoding as possible.
    IDS,
    /// Mimics the behavior of IIS 4.0, as shipped with Windows NT 4.0.
    IIS_4_0,
    /// Mimics the behavior of IIS 5.0, as shipped with Windows 2000.
    IIS_5_0,
    /// Mimics the behavior of IIS 5.1, as shipped with Windows XP Professional.
    IIS_5_1,
    /// Mimics the behavior of IIS 6.0, as shipped with Windows 2003.
    IIS_6_0,
    /// Mimics the behavior of IIS 7.0, as shipped with Windows 2008.
    IIS_7_0,
    /// Mimics the behavior of IIS 7.5, as shipped with Windows 7.
    IIS_7_5,
    /// Mimics the behavior of Apache 2.x.
    APACHE_2,
}

/// Enumerates the ways in which servers respond to malformed data.
#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) enum HtpUnwanted {
    /// Ignores problem.
    Ignore,
    /// Responds with HTTP 400 status code.
    Code400 = 400,
}

/// Enumerates the possible approaches to handling invalid URL-encodings.
#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum HtpUrlEncodingHandling {
    /// Ignore invalid URL encodings and leave the % in the data.
    PRESERVE_PERCENT,
    /// Ignore invalid URL encodings, but remove the % from the data.
    REMOVE_PERCENT,
    /// Decode invalid URL encodings.
    PROCESS_INVALID,
}

impl Config {
    /// Registers a request_complete callback, which is invoked when we see the
    /// first bytes of data from a request.
    #[cfg(test)]
    pub(crate) fn register_request_complete(&mut self, cbk_fn: TxNativeCallbackFn) {
        self.hook_request_complete.register(cbk_fn);
    }

    /// Registers a request_body_data callback, which is invoked whenever we see
    /// bytes of request body data.
    #[cfg(test)]
    pub(crate) fn register_request_body_data(&mut self, cbk_fn: DataNativeCallbackFn) {
        self.hook_request_body_data.register(cbk_fn);
    }

    /// Registers a request_header_data callback, which is invoked when we see header
    /// data. This callback receives raw header data as seen on the connection, including
    /// the terminating line and anything seen after the request line.
    #[cfg(test)]
    pub(crate) fn register_request_header_data(&mut self, cbk_fn: DataNativeCallbackFn) {
        self.hook_request_header_data.register(cbk_fn);
    }

    /// Registers a request_headers callback, which is invoked after we see all the
    /// request headers.
    #[cfg(test)]
    pub(crate) fn register_request_headers(&mut self, cbk_fn: TxNativeCallbackFn) {
        self.hook_request_headers.register(cbk_fn);
    }

    /// Registers a request_line callback, which is invoked after we parse the entire
    /// request line.
    #[cfg(test)]
    pub(crate) fn register_request_line(&mut self, cbk_fn: TxNativeCallbackFn) {
        self.hook_request_line.register(cbk_fn);
    }

    /// Registers a request_start callback, which is invoked every time a new
    /// request begins and before any parsing is done.
    #[cfg(test)]
    pub(crate) fn register_request_start(&mut self, cbk_fn: TxNativeCallbackFn) {
        self.hook_request_start.register(cbk_fn);
    }

    /// Registers a request_trailer_data callback, which may be invoked on requests with
    /// chunked bodies. This callback receives the raw response trailer data after the zero-length
    /// chunk including the terminating line.
    #[cfg(test)]
    pub(crate) fn register_request_trailer_data(&mut self, cbk_fn: DataNativeCallbackFn) {
        self.hook_request_trailer_data.register(cbk_fn);
    }

    /// Registers a response_body_data callback, which is invoked whenever we see
    /// bytes of response body data.
    #[cfg(test)]
    pub(crate) fn register_response_body_data(&mut self, cbk_fn: DataNativeCallbackFn) {
        self.hook_response_body_data.register(cbk_fn);
    }

    /// Registers a response_complete callback, which is invoked when we see the
    /// first bytes of data from a response.
    #[cfg(test)]
    pub(crate) fn register_response_complete(&mut self, cbk_fn: TxNativeCallbackFn) {
        self.hook_response_complete.register(cbk_fn);
    }

    /// Registers a response_header_data callback, which is invoked when we see header
    /// data. This callback receives raw header data as seen on the connection, including
    /// the terminating line and anything seen after the response line.
    #[cfg(test)]
    pub(crate) fn register_response_header_data(&mut self, cbk_fn: DataNativeCallbackFn) {
        self.hook_response_header_data.register(cbk_fn);
    }

    /// Registers a response_headers callback, which is invoked after we see all the
    /// response headers.
    #[cfg(test)]
    pub(crate) fn register_response_headers(&mut self, cbk_fn: TxNativeCallbackFn) {
        self.hook_response_headers.register(cbk_fn);
    }

    /// Registers a response_line callback, which is invoked after we parse the entire
    /// response line.
    #[cfg(test)]
    pub(crate) fn register_response_line(&mut self, cbk_fn: TxNativeCallbackFn) {
        self.hook_response_line.register(cbk_fn);
    }

    /// Registers a response_start callback, which is invoked when we see the
    /// first bytes of data from a response.
    #[cfg(test)]
    pub(crate) fn register_response_start(&mut self, cbk_fn: TxNativeCallbackFn) {
        self.hook_response_start.register(cbk_fn);
    }

    /// Registers a response_trailer_data callback, which may be invoked on responses with
    /// chunked bodies. This callback receives the raw response trailer data after the zero-length
    /// chunk and including the terminating line.
    #[cfg(test)]
    pub(crate) fn register_response_trailer_data(&mut self, cbk_fn: DataNativeCallbackFn) {
        self.hook_response_trailer_data.register(cbk_fn);
    }

    /// Registers a transaction_complete callback, which is invoked once the request and response
    /// are both complete.
    #[cfg(test)]
    pub(crate) fn register_transaction_complete(&mut self, cbk_fn: TxNativeCallbackFn) {
        self.hook_transaction_complete.register(cbk_fn);
    }

    /// Enable or disable the double decoding of the path in the normalized uri
    pub(crate) fn set_double_decode_normalized_path(
        &mut self, double_decode_normalized_path: bool,
    ) {
        self.decoder_cfg.double_decode_normalized_path = double_decode_normalized_path;
    }

    /// Enable or disable the double decoding of the query in the normalized uri
    pub(crate) fn set_double_decode_normalized_query(
        &mut self, double_decode_normalized_query: bool,
    ) {
        self.decoder_cfg.double_decode_normalized_query = double_decode_normalized_query;
    }

    /// Configures the maximum size of the buffer LibHTP will use when all data is not available
    /// in the current buffer (e.g., a very long header line that might span several packets). This
    /// limit is controlled by the field_limit parameter.
    pub(crate) fn set_field_limit(&mut self, field_limit: usize) {
        self.field_limit = field_limit;
    }

    /// Enable or disable spaces in URIs. Disabled by default.
    pub(crate) fn set_allow_space_uri(&mut self, allow_space: bool) {
        self.decoder_cfg.allow_space_uri = allow_space;
    }

    /// Configure desired server personality.
    /// Returns an Error if the personality is not supported.
    pub(crate) fn set_server_personality(
        &mut self, personality: HtpServerPersonality,
    ) -> Result<()> {
        match personality {
            HtpServerPersonality::MINIMAL => {}
            HtpServerPersonality::GENERIC => {
                self.set_backslash_convert_slashes(true);
                self.set_path_separators_decode(true);
                self.set_path_separators_compress(true);
            }
            HtpServerPersonality::IDS => {
                self.set_backslash_convert_slashes(true);
                self.set_path_separators_decode(true);
                self.set_path_separators_compress(true);
                self.set_convert_lowercase(true);
                self.set_utf8_convert_bestfit(true);
                self.set_u_encoding_decode(true);
                self.set_requestline_leading_whitespace_unwanted(HtpUnwanted::Ignore);
            }
            HtpServerPersonality::APACHE_2 => {
                self.set_backslash_convert_slashes(false);
                self.set_path_separators_decode(false);
                self.set_path_separators_compress(true);
                self.set_u_encoding_decode(false);
                self.set_url_encoding_invalid_handling(HtpUrlEncodingHandling::PRESERVE_PERCENT);
                self.set_url_encoding_invalid_unwanted(HtpUnwanted::Code400);
                self.set_control_chars_unwanted(HtpUnwanted::Ignore);
                self.set_requestline_leading_whitespace_unwanted(HtpUnwanted::Code400);
            }
            HtpServerPersonality::IIS_5_1 => {
                self.set_backslash_convert_slashes(true);
                self.set_path_separators_decode(true);
                self.set_path_separators_compress(true);
                self.set_u_encoding_decode(false);
                self.set_url_encoding_invalid_handling(HtpUrlEncodingHandling::PRESERVE_PERCENT);
                self.set_control_chars_unwanted(HtpUnwanted::Ignore);
                self.set_requestline_leading_whitespace_unwanted(HtpUnwanted::Ignore);
            }
            HtpServerPersonality::IIS_6_0 => {
                self.set_backslash_convert_slashes(true);
                self.set_path_separators_decode(true);
                self.set_path_separators_compress(true);
                self.set_u_encoding_decode(true);
                self.set_url_encoding_invalid_handling(HtpUrlEncodingHandling::PRESERVE_PERCENT);
                self.set_u_encoding_unwanted(HtpUnwanted::Code400);
                self.set_control_chars_unwanted(HtpUnwanted::Code400);
                self.set_requestline_leading_whitespace_unwanted(HtpUnwanted::Ignore);
            }
            HtpServerPersonality::IIS_7_0 | HtpServerPersonality::IIS_7_5 => {
                self.set_backslash_convert_slashes(true);
                self.set_path_separators_decode(true);
                self.set_path_separators_compress(true);
                self.set_u_encoding_decode(true);
                self.set_url_encoding_invalid_handling(HtpUrlEncodingHandling::PRESERVE_PERCENT);
                self.set_url_encoding_invalid_unwanted(HtpUnwanted::Code400);
                self.set_control_chars_unwanted(HtpUnwanted::Code400);
                self.set_requestline_leading_whitespace_unwanted(HtpUnwanted::Ignore);
            }
            _ => return Err(HtpStatus::ERROR),
        }
        // Remember the personality
        self.server_personality = personality;
        Ok(())
    }

    /// Sets the replacement character that will be used in the lossy best-fit
    /// mapping from multi-byte to single-byte streams. The question mark character
    /// is used as the default replacement byte.
    pub(crate) fn set_bestfit_replacement_byte(&mut self, b: u8) {
        self.decoder_cfg.bestfit_map.replacement_byte = b;
    }

    /// Configures how the server handles to invalid URL encoding.
    pub(crate) fn set_url_encoding_invalid_handling(&mut self, handling: HtpUrlEncodingHandling) {
        self.decoder_cfg.url_encoding_invalid_handling = handling;
    }

    /// Configures the handling of raw NUL bytes. If enabled, raw NUL terminates strings.
    pub(crate) fn set_nul_raw_terminates(&mut self, enabled: bool) {
        self.decoder_cfg.nul_raw_terminates = enabled;
    }

    /// Configures how the server reacts to encoded NUL bytes. Some servers will stop at
    /// at NUL, while some will respond with 400 or 404. When the termination option is not
    /// used, the NUL byte will remain in the path.
    pub(crate) fn set_nul_encoded_terminates(&mut self, enabled: bool) {
        self.decoder_cfg.nul_encoded_terminates = enabled;
    }

    /// Configures whether %u-encoded sequences are decoded. Such sequences
    /// will be treated as invalid URL encoding if decoding is not desirable.
    pub(crate) fn set_u_encoding_decode(&mut self, enabled: bool) {
        self.decoder_cfg.u_encoding_decode = enabled;
    }

    /// Configures whether backslash characters are treated as path segment separators. They
    /// are not on Unix systems, but are on Windows systems. If this setting is enabled, a path
    /// such as "/one\two/three" will be converted to "/one/two/three".
    pub(crate) fn set_backslash_convert_slashes(&mut self, enabled: bool) {
        self.decoder_cfg.backslash_convert_slashes = enabled;
    }

    /// Configures whether encoded path segment separators will be decoded. Apache does not do
    /// this by default, but IIS does. If enabled, a path such as "/one%2ftwo" will be normalized
    /// to "/one/two". If the backslash_separators option is also enabled, encoded backslash
    /// characters will be converted too (and subsequently normalized to forward slashes).
    pub(crate) fn set_path_separators_decode(&mut self, enabled: bool) {
        self.decoder_cfg.path_separators_decode = enabled;
    }

    /// Configures whether consecutive path segment separators will be compressed. When enabled, a path
    /// such as "/one//two" will be normalized to "/one/two". Backslash conversion and path segment separator
    /// decoding are carried out before compression. For example, the path "/one\\/two\/%5cthree/%2f//four"
    /// will be converted to "/one/two/three/four" (assuming all 3 options are enabled).
    pub(crate) fn set_path_separators_compress(&mut self, enabled: bool) {
        self.decoder_cfg.path_separators_compress = enabled;
    }

    /// Configures whether plus characters are converted to spaces when decoding URL-encoded strings. This
    /// is appropriate to do for parameters, but not for URLs. Only applies to contexts where decoding
    /// is taking place.
    pub(crate) fn set_plusspace_decode(&mut self, enabled: bool) {
        self.decoder_cfg.plusspace_decode = enabled;
    }

    /// Configures whether input data will be converted to lowercase. Useful for handling servers with
    /// case-insensitive filesystems.
    pub(crate) fn set_convert_lowercase(&mut self, enabled: bool) {
        self.decoder_cfg.convert_lowercase = enabled;
    }

    /// Controls whether the data should be treated as UTF-8 and converted to a single-byte
    /// stream using best-fit mapping.
    pub(crate) fn set_utf8_convert_bestfit(&mut self, enabled: bool) {
        self.decoder_cfg.utf8_convert_bestfit = enabled;
    }

    /// Configures reaction to %u-encoded sequences in input data.
    pub(crate) fn set_u_encoding_unwanted(&mut self, unwanted: HtpUnwanted) {
        self.decoder_cfg.u_encoding_unwanted = unwanted;
    }

    /// Controls reaction to raw control characters in the data.
    pub(crate) fn set_control_chars_unwanted(&mut self, unwanted: HtpUnwanted) {
        self.decoder_cfg.control_chars_unwanted = unwanted;
    }

    /// Controls whether to use complete or partial URI normalization
    pub(crate) fn set_normalized_uri_include_all(&mut self, set: bool) {
        self.decoder_cfg.normalized_uri_include_all = set;
    }

    /// Configures how the server reacts to invalid URL encoding.
    pub(crate) fn set_url_encoding_invalid_unwanted(&mut self, unwanted: HtpUnwanted) {
        self.decoder_cfg.url_encoding_invalid_unwanted = unwanted;
    }

    /// Configures how the server reacts to leading whitespace on the request line.
    pub(crate) fn set_requestline_leading_whitespace_unwanted(&mut self, unwanted: HtpUnwanted) {
        self.requestline_leading_whitespace_unwanted = unwanted;
    }

    /// Configures whether request data is decompressed.
    pub(crate) fn set_request_decompression(&mut self, set: bool) {
        self.request_decompression_enabled = set;
    }

    /// Configures many layers of compression we try to decompress.
    pub(crate) fn set_decompression_layer_limit(&mut self, limit: Option<u32>) {
        self.compression_options.set_layer_limit(limit);
    }
}
