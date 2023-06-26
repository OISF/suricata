use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

/// Different codes used for logging.
#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum HtpLogCode {
    /// Default
    UNKNOWN = 0,
    /// Gzip Decompression Failed
    GZIP_DECOMPRESSION_FAILED,
    /// Request field missing a colon.
    REQUEST_FIELD_MISSING_COLON,
    /// Response field missing a colon.
    RESPONSE_FIELD_MISSING_COLON,
    /// Request chunk length parsing failed.
    INVALID_REQUEST_CHUNK_LEN,
    /// Response chunked-length parsing failed.
    INVALID_RESPONSE_CHUNK_LEN,
    /// Response chunk exension.
    REQUEST_CHUNK_EXTENSION,
    /// Response chunk exension.
    RESPONSE_CHUNK_EXTENSION,
    /// Request has too many headers.
    REQUEST_TOO_MANY_HEADERS,
    /// Response has too many headers.
    RESPONSE_TOO_MANY_HEADERS,
    /// Request transfer-encoding invalid.
    INVALID_TRANSFER_ENCODING_VALUE_IN_REQUEST,
    /// Response transfer-encoding invalid.
    INVALID_TRANSFER_ENCODING_VALUE_IN_RESPONSE,
    /// Request content-length parsing failed.
    INVALID_CONTENT_LENGTH_FIELD_IN_REQUEST,
    /// Response content-length parsing failed.
    INVALID_CONTENT_LENGTH_FIELD_IN_RESPONSE,
    /// Request has a duplicate content-length field.
    DUPLICATE_CONTENT_LENGTH_FIELD_IN_REQUEST,
    /// Response has a duplicate content-length field.
    DUPLICATE_CONTENT_LENGTH_FIELD_IN_RESPONSE,
    /// 100 Continue response status already seen.
    CONTINUE_ALREADY_SEEN,
    /// Unable to match response to a request.
    UNABLE_TO_MATCH_RESPONSE_TO_REQUEST,
    /// Request server port is invalid.
    INVALID_SERVER_PORT_IN_REQUEST,
    /// Authority port is invalid.
    INVALID_AUTHORITY_PORT,
    /// Request header name is incorrectly formed.
    REQUEST_HEADER_INVALID,
    /// Response header name is incorrectly formed.
    RESPONSE_HEADER_INVALID,
    /// Host header is missing.
    MISSING_HOST_HEADER,
    /// Host header is ambiguous.
    HOST_HEADER_AMBIGUOUS,
    /// Request has invalid line folding.
    INVALID_REQUEST_FIELD_FOLDING,
    /// Response has invalid line folding.
    INVALID_RESPONSE_FIELD_FOLDING,
    /// Request buffer field is over the limit.
    REQUEST_FIELD_TOO_LONG,
    /// Response buffer field is over the limit.
    RESPONSE_FIELD_TOO_LONG,
    /// Mismatch between request server port and tcp port.
    REQUEST_SERVER_PORT_TCP_PORT_MISMATCH,
    /// Uri hostname is invalid.
    URI_HOST_INVALID,
    /// Header hostname is invalid.
    HEADER_HOST_INVALID,
    /// Non compliant delimiter between method and URI in request line.
    METHOD_DELIM_NON_COMPLIANT,
    /// Parsed request-uri contains a non compliant delimiter.
    URI_DELIM_NON_COMPLIANT,
    /// Request line has leading whitespace.
    REQUEST_LINE_LEADING_WHITESPACE,
    /// Response content encoding lzma layers is greater than limit.
    RESPONSE_TOO_MANY_LZMA_LAYERS,
    /// Request content encoding lzma layers is greater than limit.
    REQUEST_TOO_MANY_LZMA_LAYERS,
    /// Too many request or response encoding layers
    TOO_MANY_ENCODING_LAYERS,
    /// Response header content-encoding header is invalid
    ABNORMAL_CE_HEADER,
    /// Request authorization header unrecognized
    AUTH_UNRECOGNIZED,
    /// Request header has been seen more than once.
    REQUEST_HEADER_REPETITION,
    /// response header has been seen more than once.
    RESPONSE_HEADER_REPETITION,
    /// Response content-type is multipart-byteranges (unsupported).
    RESPONSE_MULTIPART_BYTERANGES,
    /// Response transfer-encoding has an abnormal chunked value.
    RESPONSE_ABNORMAL_TRANSFER_ENCODING,
    /// Response chunked transfer-encoding on HTTP/0.9 or HTTP/1.0.
    RESPONSE_CHUNKED_OLD_PROTO,
    /// Response protocol invalid.
    RESPONSE_INVALID_PROTOCOL,
    /// Response status invalid.
    RESPONSE_INVALID_STATUS,
    /// Response line is incomplete.
    REQUEST_LINE_INCOMPLETE,
    /// Request uri has double encoding.
    DOUBLE_ENCODED_URI,
    /// Request line is invalid.
    REQUEST_LINE_INVALID,
    /// Unexpected request body present.
    REQUEST_BODY_UNEXPECTED,
    /// Reached LZMA memory limit.
    LZMA_MEMLIMIT_REACHED,
    /// Reached configured time limit for decompression or reached bomb limit.
    COMPRESSION_BOMB,
    /// Unexpected response body present.
    RESPONSE_BODY_UNEXPECTED,
    /// Content-length parsing contains extra leading characters.
    CONTENT_LENGTH_EXTRA_DATA_START,
    /// Content-length parsing contains extra trailing characters
    CONTENT_LENGTH_EXTRA_DATA_END,
    /// 101 Switching Protocol seen with a content-length.
    SWITCHING_PROTO_WITH_CONTENT_LENGTH,
    /// End of line is deformed.
    DEFORMED_EOL,
    /// Parsing error encountered in request or response.
    PARSER_STATE_ERROR,
    /// Missing outbound transaction while state is not idle.
    MISSING_OUTBOUND_TRANSACTION_DATA,
    /// Missing inbound transaction while state is not idle.
    MISSING_INBOUND_TRANSACTION_DATA,
    /// Supplied data chunk has a length of zero.
    ZERO_LENGTH_DATA_CHUNKS,
    /// Request Line method is unknown.
    REQUEST_LINE_UNKNOWN_METHOD,
    /// Request line method is unknown and no protocol information was found.
    REQUEST_LINE_UNKNOWN_METHOD_NO_PROTOCOL,
    /// Request line method is unknown and protocol is invalid.
    REQUEST_LINE_UNKNOWN_METHOD_INVALID_PROTOCOL,
    /// Request line protocol information was not found.
    REQUEST_LINE_NO_PROTOCOL,
    /// Response line protocol is invalid.
    RESPONSE_LINE_INVALID_PROTOCOL,
    /// Response line status number is out of range.
    RESPONSE_LINE_INVALID_RESPONSE_STATUS,
    /// Response parsing progress is at an invalid state.
    RESPONSE_BODY_INTERNAL_ERROR,
    /// Request body data callback produced a error.
    REQUEST_BODY_DATA_CALLBACK_ERROR,
    /// Response header name is empty.
    RESPONSE_INVALID_EMPTY_NAME,
    /// Request header name is empty.
    REQUEST_INVALID_EMPTY_NAME,
    /// Response header name has extra whitespace after name.
    RESPONSE_INVALID_LWS_AFTER_NAME,
    /// Response header name is not a valid token.
    RESPONSE_HEADER_NAME_NOT_TOKEN,
    /// Request header name has extra whitespace after name.
    REQUEST_INVALID_LWS_AFTER_NAME,
    /// LZMA decompression is disabled.
    LZMA_DECOMPRESSION_DISABLED,
    /// Tried to open a connection that is already open.
    CONNECTION_ALREADY_OPEN,
    /// Protocol parsing detected leading or trailing data.
    PROTOCOL_CONTAINS_EXTRA_DATA,
    /// Invalid gap detected.
    INVALID_GAP,
    /// Compression bomb due to double lzma encoding.
    COMPRESSION_BOMB_DOUBLE_LZMA,
    /// Invalid content-encoding detected.
    INVALID_CONTENT_ENCODING,
    /// Error retrieving a log message's code
    ERROR,
}

/// Enumerates all log levels.
#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Debug)]
pub(crate) enum HtpLogLevel {
    /// Designates fatal error.
    Error,
    /// Designates hazardous situations.
    Warning,
    /// Default log level value.
    Notice,
    /// Designates useful information,
    Info,
}
#[derive(Clone)]
/// Logger struct
pub(crate) struct Logger {
    /// The sender half of a logging channel
    pub(crate) sender: Rc<RefCell<VecDeque<Log>>>,
    /// Log level used when deciding whether to store or
    /// ignore the messages issued by the parser.
    pub(crate) level: HtpLogLevel,
}

impl Logger {
    /// Returns a new logger instance
    pub(crate) fn new(sender: &Rc<RefCell<VecDeque<Log>>>) -> Logger {
        Self {
            sender: sender.clone(),
            level: HtpLogLevel::Notice,
        }
    }
    /// Logs a message to the logger channel.
    pub(crate) fn log(
        &mut self, _file: &str, _line: u32, level: HtpLogLevel, code: HtpLogCode, msg: String,
    ) {
        // Ignore messages below our log level.
        if level <= self.level {
            let mut sender = self.sender.borrow_mut();
            sender.push_back(Log::new(Message::new(code, msg)));
        }
    }
}

#[derive(Clone)]
/// Represents a single Message entry for a log
pub(crate) struct Message {
    /// Log message string.
    pub(crate) msg: String,
    //level: HtpLogLevel,
    /// Message code.
    pub(crate) code: HtpLogCode,
    //pub(crate) file: String,
    //line: u32,
}

impl Message {
    /// Returns a new Message instance
    pub(crate) fn new(code: HtpLogCode, msg: String) -> Message {
        Self { code, msg }
    }
}

/// Represents a single log entry.
#[derive(Clone)]
pub struct Log {
    /// Log message.
    pub(crate) msg: Message,
}

impl Log {
    /// Returns a new Log instance.
    pub(crate) fn new(msg: Message) -> Log {
        Self { msg }
    }
}

/// Logs a message at the given level.
#[macro_export]
macro_rules! htp_log {
    ($logger:expr, $level:expr, $code:expr, $msg:expr) => {{
        use $crate::log::{HtpLogCode, HtpLogLevel};
        $logger.log(file!(), line!(), $level, $code, $msg.to_string());
    }};
}

/// Logs a message at the info level.
#[macro_export]
macro_rules! htp_info {
    ($logger:expr, $code:expr, $msg:expr) => {
        htp_log!($logger, HtpLogLevel::Info, $code, $msg);
    };
}

/// Logs a message at the warning level.
#[macro_export]
macro_rules! htp_warn {
    ($logger:expr, $code:expr, $msg:expr) => {
        htp_log!($logger, HtpLogLevel::Warning, $code, $msg);
    };
}

/// Logs a message at the error level.
#[macro_export]
macro_rules! htp_error {
    ($logger:expr, $code:expr, $msg:expr) => {
        htp_log!($logger, HtpLogLevel::Error, $code, $msg);
    };
}

/// Logs a message at the warning level, ensuring that it ones logs the message once.
#[macro_export]
macro_rules! htp_warn_once {
    ($logger:expr, $code:expr, $msg:expr, $tx_flags:expr, $flags:expr, $flag:expr) => {
        // Log only once per transaction.
        if !$tx_flags.is_set($flag) {
            htp_warn!($logger, $code, $msg);
        }
        $tx_flags.set($flag);
        $flags.set($flag);
    };
}
