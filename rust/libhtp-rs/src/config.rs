use crate::decompressors::Options;
use crate::{
    error::Result,
    hook::{
        DataHook, DataNativeCallbackFn, LogHook, LogNativeCallbackFn, TxHook, TxNativeCallbackFn,
    },
    log::HtpLogLevel,
    transaction::Param,
    unicode_bestfit_map::UnicodeBestfitMap,
    HtpStatus,
};

/// Configuration for libhtp parsing.
#[derive(Clone)]
pub struct Config {
    /// The maximum size of the buffer that is used when the current
    /// input chunk does not contain all the necessary data (e.g., a header
    /// line that spans several packets).
    pub field_limit: usize,
    /// Log level, which will be used when deciding whether to store or
    /// ignore the messages issued by the parser.
    pub log_level: HtpLogLevel,
    /// Whether to delete each transaction after the last hook is invoked. This
    /// feature should be used when parsing traffic streams in real time.
    pub tx_auto_destroy: bool,
    /// Server personality identifier.
    pub server_personality: HtpServerPersonality,
    /// The function to use to transform parameters after parsing.
    pub parameter_processor: Option<fn(_: &mut Param) -> Result<()>>,
    /// Decoder configuration for url path.
    pub decoder_cfg: DecoderConfig,
    /// Whether to decompress compressed response bodies.
    pub response_decompression_enabled: bool,
    /// Whether to parse urlencoded data.
    pub parse_urlencoded: bool,
    /// Whether to parse HTTP Authentication headers.
    pub parse_request_auth: bool,
    /// Request start hook, invoked when the parser receives the first byte of a new
    /// request. Because an HTTP transaction always starts with a request, this hook
    /// doubles as a transaction start hook.
    pub hook_request_start: TxHook,
    /// Request line hook, invoked after a request line has been parsed.
    pub hook_request_line: TxHook,
    /// Request URI normalization hook, for overriding default normalization of URI.
    pub hook_request_uri_normalize: TxHook,
    /// Receives raw request header data, starting immediately after the request line,
    /// including all headers as they are seen on the TCP connection, and including the
    /// terminating empty line. Not available on genuine HTTP/0.9 requests (because
    /// they don't use headers).
    pub hook_request_header_data: DataHook,
    /// Request headers hook, invoked after all request headers are seen.
    pub hook_request_headers: TxHook,
    /// Request body data hook, invoked every time body data is available. Each
    /// invocation will provide a Data instance. Chunked data
    /// will be dechunked before the data is passed to this hook. Decompression
    /// is not currently implemented. At the end of the request body
    /// there will be a call with the data set to None.
    pub hook_request_body_data: DataHook,
    /// Receives raw request trailer data, which can be available on requests that have
    /// chunked bodies. The data starts immediately after the zero-length chunk
    /// and includes the terminating empty line.
    pub hook_request_trailer_data: DataHook,
    /// Request trailer hook, invoked after all trailer headers are seen,
    /// and if they are seen (not invoked otherwise).
    pub hook_request_trailer: TxHook,
    /// Request hook, invoked after a complete request is seen.
    pub hook_request_complete: TxHook,
    /// Response startup hook, invoked when a response transaction is found and
    /// processing started.
    pub hook_response_start: TxHook,
    /// Response line hook, invoked after a response line has been parsed.
    pub hook_response_line: TxHook,
    /// Receives raw response header data, starting immediately after the status line
    /// and including all headers as they are seen on the TCP connection, and including the
    /// terminating empty line. Not available on genuine HTTP/0.9 responses (because
    /// they don't have response headers).
    pub hook_response_header_data: DataHook,
    /// Response headers book, invoked after all response headers have been seen.
    pub hook_response_headers: TxHook,
    /// Response body data hook, invoked every time body data is available. Each
    /// invocation will provide a Data instance. Chunked data
    /// will be dechunked before the data is passed to this hook. By default,
    /// compressed data will be decompressed, but decompression can be disabled
    /// in configuration. At the end of the response body there will be a call
    /// with the data pointer set to NULL.
    pub hook_response_body_data: DataHook,
    /// Receives raw response trailer data, which can be available on responses that have
    /// chunked bodies. The data starts immediately after the zero-length chunk
    /// and includes the terminating empty line.
    pub hook_response_trailer_data: DataHook,
    /// Response trailer hook, invoked after all trailer headers have been processed,
    /// and only if the trailer exists.
    pub hook_response_trailer: TxHook,
    /// Response hook, invoked after a response has been seen. Because sometimes servers
    /// respond before receiving complete requests, a response_complete callback may be
    /// invoked prior to a request_complete callback.
    pub hook_response_complete: TxHook,
    /// Transaction complete hook, which is invoked once the entire transaction is
    /// considered complete (request and response are both complete). This is always
    /// the last hook to be invoked.
    pub hook_transaction_complete: TxHook,
    /// Log hook, invoked every time the library wants to log.
    pub hook_log: LogHook,
    /// Reaction to leading whitespace on the request line
    pub requestline_leading_whitespace_unwanted: HtpUnwanted,
    /// Whether to decompress compressed request bodies.
    pub request_decompression_enabled: bool,
    /// Configuration options for decompression.
    pub compression_options: Options,
    /// Flush incomplete transactions
    pub flush_incomplete: bool,
    /// Maximum number of transactions
    pub max_tx: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            field_limit: 18000,
            log_level: HtpLogLevel::NOTICE,
            tx_auto_destroy: false,
            server_personality: HtpServerPersonality::MINIMAL,
            parameter_processor: None,
            decoder_cfg: Default::default(),
            response_decompression_enabled: true,
            parse_urlencoded: false,
            parse_request_auth: true,
            hook_request_start: TxHook::default(),
            hook_request_line: TxHook::default(),
            hook_request_uri_normalize: TxHook::default(),
            hook_request_header_data: DataHook::default(),
            hook_request_headers: TxHook::default(),
            hook_request_body_data: DataHook::default(),
            hook_request_trailer_data: DataHook::default(),
            hook_request_trailer: TxHook::default(),
            hook_request_complete: TxHook::default(),
            hook_response_start: TxHook::default(),
            hook_response_line: TxHook::default(),
            hook_response_header_data: DataHook::default(),
            hook_response_headers: TxHook::default(),
            hook_response_body_data: DataHook::default(),
            hook_response_trailer_data: DataHook::default(),
            hook_response_trailer: TxHook::default(),
            hook_response_complete: TxHook::default(),
            hook_transaction_complete: TxHook::default(),
            hook_log: LogHook::default(),
            requestline_leading_whitespace_unwanted: HtpUnwanted::IGNORE,
            request_decompression_enabled: false,
            compression_options: Options::default(),
            flush_incomplete: false,
            max_tx: 512,
        }
    }
}

/// Configuration options for decoding.
#[derive(Copy, Clone)]
pub struct DecoderConfig {
    ///Whether to double decode the path in normalized uri
    pub double_decode_normalized_path: bool,
    /// Whether to double decode the query in the normalized uri
    pub double_decode_normalized_query: bool,
    // Path-specific decoding options.
    /// Convert backslash characters to slashes.
    pub backslash_convert_slashes: bool,
    /// Convert to lowercase.
    pub convert_lowercase: bool,
    /// Compress slash characters.
    pub path_separators_compress: bool,
    /// Should we URL-decode encoded path segment separators?
    pub path_separators_decode: bool,
    /// Should we decode '+' characters to spaces?
    pub plusspace_decode: bool,
    /// Reaction to encoded path separators.
    pub path_separators_encoded_unwanted: HtpUnwanted,
    // Special characters options.
    /// Controls how raw NUL bytes are handled.
    pub nul_raw_terminates: bool,
    /// Determines server response to a raw NUL byte in the path.
    pub nul_raw_unwanted: HtpUnwanted,
    /// Reaction to control characters.
    pub control_chars_unwanted: HtpUnwanted,
    /// Allow whitespace characters in request uri path
    pub allow_space_uri: bool,
    // URL encoding options.
    /// Should we decode %u-encoded characters?
    pub u_encoding_decode: bool,
    /// Reaction to %u encoding.
    pub u_encoding_unwanted: HtpUnwanted,
    /// Handling of invalid URL encodings.
    pub url_encoding_invalid_handling: HtpUrlEncodingHandling,
    /// Reaction to invalid URL encoding.
    pub url_encoding_invalid_unwanted: HtpUnwanted,
    /// Controls how encoded NUL bytes are handled.
    pub nul_encoded_terminates: bool,
    /// How are we expected to react to an encoded NUL byte?
    pub nul_encoded_unwanted: HtpUnwanted,
    // Normalized URI preference
    /// Controls whether the client wants the complete or partial normalized URI.
    pub normalized_uri_include_all: bool,
    // UTF-8 options.
    /// Controls how invalid UTF-8 characters are handled.
    pub utf8_invalid_unwanted: HtpUnwanted,
    /// Convert UTF-8 characters into bytes using best-fit mapping.
    pub utf8_convert_bestfit: bool,
    /// Best-fit map for UTF-8 decoding.
    pub bestfit_map: UnicodeBestfitMap,
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
            path_separators_encoded_unwanted: HtpUnwanted::IGNORE,
            nul_raw_terminates: false,
            nul_raw_unwanted: HtpUnwanted::IGNORE,
            control_chars_unwanted: HtpUnwanted::IGNORE,
            allow_space_uri: false,
            u_encoding_decode: false,
            u_encoding_unwanted: HtpUnwanted::IGNORE,
            url_encoding_invalid_handling: HtpUrlEncodingHandling::PRESERVE_PERCENT,
            url_encoding_invalid_unwanted: HtpUnwanted::IGNORE,
            nul_encoded_terminates: false,
            nul_encoded_unwanted: HtpUnwanted::IGNORE,
            normalized_uri_include_all: false,
            utf8_invalid_unwanted: HtpUnwanted::IGNORE,
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
pub enum HtpUnwanted {
    /// Ignores problem.
    IGNORE,
    /// Responds with HTTP 400 status code.
    CODE_400 = 400,
    /// Responds with HTTP 404 status code.
    CODE_404 = 404,
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
    /// Registers a callback that is invoked every time there is a log message with
    /// severity equal and higher than the configured log level.
    pub fn register_log(&mut self, cbk_fn: LogNativeCallbackFn) {
        self.hook_log.register(cbk_fn);
    }

    /// Registers a request_complete callback, which is invoked when we see the
    /// first bytes of data from a request.
    pub fn register_request_complete(&mut self, cbk_fn: TxNativeCallbackFn) {
        self.hook_request_complete.register(cbk_fn);
    }

    /// Registers a request_body_data callback, which is invoked whenever we see
    /// bytes of request body data.
    pub fn register_request_body_data(&mut self, cbk_fn: DataNativeCallbackFn) {
        self.hook_request_body_data.register(cbk_fn);
    }

    /// Registers a request_header_data callback, which is invoked when we see header
    /// data. This callback receives raw header data as seen on the connection, including
    /// the terminating line and anything seen after the request line.
    pub fn register_request_header_data(&mut self, cbk_fn: DataNativeCallbackFn) {
        self.hook_request_header_data.register(cbk_fn);
    }

    /// Registers a request_headers callback, which is invoked after we see all the
    /// request headers.
    pub fn register_request_headers(&mut self, cbk_fn: TxNativeCallbackFn) {
        self.hook_request_headers.register(cbk_fn);
    }

    /// Registers a request_line callback, which is invoked after we parse the entire
    /// request line.
    pub fn register_request_line(&mut self, cbk_fn: TxNativeCallbackFn) {
        self.hook_request_line.register(cbk_fn);
    }

    /// Registers a request_start callback, which is invoked every time a new
    /// request begins and before any parsing is done.
    pub fn register_request_start(&mut self, cbk_fn: TxNativeCallbackFn) {
        self.hook_request_start.register(cbk_fn);
    }

    /// Registers a request_trailer callback, which is invoked when all trailer headers
    /// are seen, if present.
    pub fn register_request_trailer(&mut self, cbk_fn: TxNativeCallbackFn) {
        self.hook_request_trailer.register(cbk_fn);
    }

    /// Registers a request_trailer_data callback, which may be invoked on requests with
    /// chunked bodies. This callback receives the raw response trailer data after the zero-length
    /// chunk including the terminating line.
    pub fn register_request_trailer_data(&mut self, cbk_fn: DataNativeCallbackFn) {
        self.hook_request_trailer_data.register(cbk_fn);
    }

    /// Registers a response_body_data callback, which is invoked whenever we see
    /// bytes of response body data.
    pub fn register_response_body_data(&mut self, cbk_fn: DataNativeCallbackFn) {
        self.hook_response_body_data.register(cbk_fn);
    }

    /// Registers a response_complete callback, which is invoked when we see the
    /// first bytes of data from a response.
    pub fn register_response_complete(&mut self, cbk_fn: TxNativeCallbackFn) {
        self.hook_response_complete.register(cbk_fn);
    }

    /// Registers a response_header_data callback, which is invoked when we see header
    /// data. This callback receives raw header data as seen on the connection, including
    /// the terminating line and anything seen after the response line.
    pub fn register_response_header_data(&mut self, cbk_fn: DataNativeCallbackFn) {
        self.hook_response_header_data.register(cbk_fn);
    }

    /// Registers a response_headers callback, which is invoked after we see all the
    /// response headers.
    #[allow(dead_code)]
    pub fn register_response_headers(&mut self, cbk_fn: TxNativeCallbackFn) {
        self.hook_response_headers.register(cbk_fn);
    }

    /// Registers a response_line callback, which is invoked after we parse the entire
    /// response line.
    #[allow(dead_code)]
    pub fn register_response_line(&mut self, cbk_fn: TxNativeCallbackFn) {
        self.hook_response_line.register(cbk_fn);
    }

    /// Registers a response_start callback, which is invoked when we see the
    /// first bytes of data from a response.
    pub fn register_response_start(&mut self, cbk_fn: TxNativeCallbackFn) {
        self.hook_response_start.register(cbk_fn);
    }

    /// Registers a response_trailer callback, which is invoked if when all
    /// trailer headers are seen, if present.
    pub fn register_response_trailer(&mut self, cbk_fn: TxNativeCallbackFn) {
        self.hook_response_trailer.register(cbk_fn);
    }

    /// Registers a response_trailer_data callback, which may be invoked on responses with
    /// chunked bodies. This callback receives the raw response trailer data after the zero-length
    /// chunk and including the terminating line.
    pub fn register_response_trailer_data(&mut self, cbk_fn: DataNativeCallbackFn) {
        self.hook_response_trailer_data.register(cbk_fn);
    }

    /// Registers a transaction_complete callback, which is invoked once the request and response
    /// are both complete.
    pub fn register_transaction_complete(&mut self, cbk_fn: TxNativeCallbackFn) {
        self.hook_transaction_complete.register(cbk_fn);
    }

    /// Enable or disable the double decoding of the path in the normalized uri
    pub fn set_double_decode_normalized_path(&mut self, double_decode_normalized_path: bool) {
        self.decoder_cfg.double_decode_normalized_path = double_decode_normalized_path;
    }

    /// Enable or disable the double decoding of the query in the normalized uri
    pub fn set_double_decode_normalized_query(&mut self, double_decode_normalized_query: bool) {
        self.decoder_cfg.double_decode_normalized_query = double_decode_normalized_query;
    }

    /// Enable or disable the built-in Urlencoded parser. Disabled by default.
    /// The parser will parse query strings and request bodies with the appropriate MIME type.
    pub fn set_parse_urlencoded(&mut self, parse_urlencoded: bool) {
        self.parse_urlencoded = parse_urlencoded;
    }

    /// Configures the maximum size of the buffer LibHTP will use when all data is not available
    /// in the current buffer (e.g., a very long header line that might span several packets). This
    /// limit is controlled by the field_limit parameter.
    pub fn set_field_limit(&mut self, field_limit: usize) {
        self.field_limit = field_limit;
    }

    /// Enable or disable spaces in URIs. Disabled by default.
    pub fn set_allow_space_uri(&mut self, allow_space: bool) {
        self.decoder_cfg.allow_space_uri = allow_space;
    }

    /// Configure desired server personality.
    /// Returns an Error if the personality is not supported.
    pub fn set_server_personality(&mut self, personality: HtpServerPersonality) -> Result<()> {
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
                self.set_requestline_leading_whitespace_unwanted(HtpUnwanted::IGNORE);
            }
            HtpServerPersonality::APACHE_2 => {
                self.set_backslash_convert_slashes(false);
                self.set_path_separators_decode(false);
                self.set_path_separators_compress(true);
                self.set_u_encoding_decode(false);
                self.set_url_encoding_invalid_handling(HtpUrlEncodingHandling::PRESERVE_PERCENT);
                self.set_url_encoding_invalid_unwanted(HtpUnwanted::CODE_400);
                self.set_control_chars_unwanted(HtpUnwanted::IGNORE);
                self.set_requestline_leading_whitespace_unwanted(HtpUnwanted::CODE_400);
            }
            HtpServerPersonality::IIS_5_1 => {
                self.set_backslash_convert_slashes(true);
                self.set_path_separators_decode(true);
                self.set_path_separators_compress(true);
                self.set_u_encoding_decode(false);
                self.set_url_encoding_invalid_handling(HtpUrlEncodingHandling::PRESERVE_PERCENT);
                self.set_control_chars_unwanted(HtpUnwanted::IGNORE);
                self.set_requestline_leading_whitespace_unwanted(HtpUnwanted::IGNORE);
            }
            HtpServerPersonality::IIS_6_0 => {
                self.set_backslash_convert_slashes(true);
                self.set_path_separators_decode(true);
                self.set_path_separators_compress(true);
                self.set_u_encoding_decode(true);
                self.set_url_encoding_invalid_handling(HtpUrlEncodingHandling::PRESERVE_PERCENT);
                self.set_u_encoding_unwanted(HtpUnwanted::CODE_400);
                self.set_control_chars_unwanted(HtpUnwanted::CODE_400);
                self.set_requestline_leading_whitespace_unwanted(HtpUnwanted::IGNORE);
            }
            HtpServerPersonality::IIS_7_0 | HtpServerPersonality::IIS_7_5 => {
                self.set_backslash_convert_slashes(true);
                self.set_path_separators_decode(true);
                self.set_path_separators_compress(true);
                self.set_u_encoding_decode(true);
                self.set_url_encoding_invalid_handling(HtpUrlEncodingHandling::PRESERVE_PERCENT);
                self.set_url_encoding_invalid_unwanted(HtpUnwanted::CODE_400);
                self.set_control_chars_unwanted(HtpUnwanted::CODE_400);
                self.set_requestline_leading_whitespace_unwanted(HtpUnwanted::IGNORE);
            }
            _ => return Err(HtpStatus::ERROR),
        }
        // Remember the personality
        self.server_personality = personality;
        Ok(())
    }

    /// Configures whether transactions will be automatically destroyed once they
    /// are processed and all callbacks invoked. This option is appropriate for
    /// programs that process transactions as they are processed.
    pub fn set_tx_auto_destroy(&mut self, tx_auto_destroy: bool) {
        self.tx_auto_destroy = tx_auto_destroy;
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
    pub fn set_flush_incomplete(&mut self, flush_incomplete: bool) {
        self.flush_incomplete = flush_incomplete;
    }

    /// Configures a best-fit map, which is used whenever characters longer than one byte
    /// need to be converted to a single-byte. By default a Windows 1252 best-fit map is used.
    pub fn set_bestfit_map(&mut self, map: UnicodeBestfitMap) {
        self.decoder_cfg.bestfit_map = map;
    }

    /// Sets the replacement character that will be used in the lossy best-fit
    /// mapping from multi-byte to single-byte streams. The question mark character
    /// is used as the default replacement byte.
    pub fn set_bestfit_replacement_byte(&mut self, b: u8) {
        self.decoder_cfg.bestfit_map.replacement_byte = b;
    }

    /// Configures how the server handles to invalid URL encoding.
    pub fn set_url_encoding_invalid_handling(&mut self, handling: HtpUrlEncodingHandling) {
        self.decoder_cfg.url_encoding_invalid_handling = handling;
    }

    /// Configures the handling of raw NUL bytes. If enabled, raw NUL terminates strings.
    pub fn set_nul_raw_terminates(&mut self, enabled: bool) {
        self.decoder_cfg.nul_raw_terminates = enabled;
    }

    /// Configures how the server reacts to encoded NUL bytes. Some servers will stop at
    /// at NUL, while some will respond with 400 or 404. When the termination option is not
    /// used, the NUL byte will remain in the path.
    pub fn set_nul_encoded_terminates(&mut self, enabled: bool) {
        self.decoder_cfg.nul_encoded_terminates = enabled;
    }

    /// Configures whether %u-encoded sequences are decoded. Such sequences
    /// will be treated as invalid URL encoding if decoding is not desirable.
    pub fn set_u_encoding_decode(&mut self, enabled: bool) {
        self.decoder_cfg.u_encoding_decode = enabled;
    }

    /// Configures whether backslash characters are treated as path segment separators. They
    /// are not on Unix systems, but are on Windows systems. If this setting is enabled, a path
    /// such as "/one\two/three" will be converted to "/one/two/three".
    pub fn set_backslash_convert_slashes(&mut self, enabled: bool) {
        self.decoder_cfg.backslash_convert_slashes = enabled;
    }

    /// Configures whether encoded path segment separators will be decoded. Apache does not do
    /// this by default, but IIS does. If enabled, a path such as "/one%2ftwo" will be normalized
    /// to "/one/two". If the backslash_separators option is also enabled, encoded backslash
    /// characters will be converted too (and subsequently normalized to forward slashes).
    pub fn set_path_separators_decode(&mut self, enabled: bool) {
        self.decoder_cfg.path_separators_decode = enabled;
    }

    /// Configures whether consecutive path segment separators will be compressed. When enabled, a path
    /// such as "/one//two" will be normalized to "/one/two". Backslash conversion and path segment separator
    /// decoding are carried out before compression. For example, the path "/one\\/two\/%5cthree/%2f//four"
    /// will be converted to "/one/two/three/four" (assuming all 3 options are enabled).
    pub fn set_path_separators_compress(&mut self, enabled: bool) {
        self.decoder_cfg.path_separators_compress = enabled;
    }

    /// Configures whether plus characters are converted to spaces when decoding URL-encoded strings. This
    /// is appropriate to do for parameters, but not for URLs. Only applies to contexts where decoding
    /// is taking place.
    pub fn set_plusspace_decode(&mut self, enabled: bool) {
        self.decoder_cfg.plusspace_decode = enabled;
    }

    /// Configures whether input data will be converted to lowercase. Useful for handling servers with
    /// case-insensitive filesystems.
    pub fn set_convert_lowercase(&mut self, enabled: bool) {
        self.decoder_cfg.convert_lowercase = enabled;
    }

    /// Controls whether the data should be treated as UTF-8 and converted to a single-byte
    /// stream using best-fit mapping.
    pub fn set_utf8_convert_bestfit(&mut self, enabled: bool) {
        self.decoder_cfg.utf8_convert_bestfit = enabled;
    }

    /// Configures reaction to %u-encoded sequences in input data.
    pub fn set_u_encoding_unwanted(&mut self, unwanted: HtpUnwanted) {
        self.decoder_cfg.u_encoding_unwanted = unwanted;
    }

    /// Controls reaction to raw control characters in the data.
    pub fn set_control_chars_unwanted(&mut self, unwanted: HtpUnwanted) {
        self.decoder_cfg.control_chars_unwanted = unwanted;
    }

    /// Controls whether to use complete or partial URI normalization
    pub fn set_normalized_uri_include_all(&mut self, set: bool) {
        self.decoder_cfg.normalized_uri_include_all = set;
    }

    /// Configures how the server reacts to invalid URL encoding.
    pub fn set_url_encoding_invalid_unwanted(&mut self, unwanted: HtpUnwanted) {
        self.decoder_cfg.url_encoding_invalid_unwanted = unwanted;
    }

    /// Configures how the server reacts to leading whitespace on the request line.
    pub fn set_requestline_leading_whitespace_unwanted(&mut self, unwanted: HtpUnwanted) {
        self.requestline_leading_whitespace_unwanted = unwanted;
    }

    /// Configures whether request data is decompressed.
    pub fn set_request_decompression(&mut self, set: bool) {
        self.request_decompression_enabled = set;
    }

    /// Configures many layers of compression we try to decompress.
    pub fn set_decompression_layer_limit(&mut self, limit: Option<u32>) {
        self.compression_options.set_layer_limit(limit);
    }
}
