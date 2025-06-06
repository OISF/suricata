use crate::{
    bstr::Bstr,
    c_api::transaction::htp_tx_get_user_data,
    config::{Config, HtpUnwanted},
    connection_parser::ParserData,
    decompressors::{Decompressor, HtpContentEncoding},
    error::Result,
    headers::{Parser as HeaderParser, Side},
    hook::DataHook,
    log::Logger,
    parsers::{parse_authorization, parse_content_length, parse_content_type, parse_hostport},
    request::HtpMethod,
    uri::Uri,
    util::{validate_hostname, FlagOperations, HtpFlags},
    HtpStatus,
};

use std::any::Any;
#[cfg(test)]
use std::cmp::Ordering;

#[derive(Debug, Clone)]
/// This structure is used to pass transaction data (for example
/// request and response body buffers) to callbacks.
pub struct Data<'a> {
    /// Transaction pointer.
    tx: *mut Transaction,
    /// Ref to the parser data.
    data: &'a ParserData<'a>,
}

impl<'a> Data<'a> {
    /// Construct a new Data.
    pub(crate) fn new(tx: *mut Transaction, data: &'a ParserData<'a>) -> Self {
        Self { tx, data }
    }

    /// Returns the transaction associated with the Data.
    pub(crate) fn tx(&self) -> *mut Transaction {
        self.tx
    }

    /// Returns a pointer to the raw data associated with Data.
    pub(crate) fn data(&self) -> *const u8 {
        self.data.data_ptr()
    }

    /// Returns the length of the data.
    pub(crate) fn len(&self) -> usize {
        self.data.len()
    }

    /// Determine whether this data is empty.
    pub(crate) fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns a reference to the internal ParserData struct.
    pub(crate) fn parser_data(&self) -> &ParserData<'_> {
        self.data
    }
}

/// Enumerates the possible request and response body codings.
#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) enum HtpTransferCoding {
    /// Body coding not determined yet.
    Unknown,
    /// No body.
    NoBody,
    /// Identity coding is used, which means that the body was sent as is.
    Identity,
    /// Chunked encoding.
    Chunked,
    /// We could not recognize the encoding.
    Invalid,
}

/// Enumerates the possible server personalities.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) enum HtpResponseNumber {
    /// Default
    Unknown,
    /// Could not resolve response number
    Invalid,
    /// Valid response number
    Valid(u16),
}

impl HtpResponseNumber {
    /// Determine if the response status number is in the given range.
    pub(crate) fn in_range(self, min: u16, max: u16) -> bool {
        use HtpResponseNumber::*;
        match self {
            Unknown | Invalid => false,
            Valid(ref status) => status >= &min && status <= &max,
        }
    }

    /// Determine if the response status number matches the
    /// given status number.
    pub(crate) fn eq_num(self, num: u16) -> bool {
        use HtpResponseNumber::*;
        match self {
            Unknown | Invalid => false,
            Valid(ref status) => status == &num,
        }
    }
}

/// Represents a single request or response header.
#[derive(Clone, Debug)]
pub struct Header {
    /// Header name.
    pub name: Bstr,
    /// Header value.
    pub value: Bstr,
    /// Parsing flags; a combination of: HTP_FIELD_INVALID, HTP_FIELD_FOLDED, HTP_FIELD_REPEATED.
    pub flags: u64,
}

/// Table of request or response headers.
#[derive(Clone, Debug)]
pub struct Headers {
    /// Entries in the table.
    pub elements: Vec<Header>,
}

impl Headers {
    /// Make a new owned Headers Table with given capacity
    pub(crate) fn with_capacity(size: usize) -> Self {
        Self {
            elements: Vec::with_capacity(size),
        }
    }

    /// Search the Headers table for the first tuple with a tuple key matching the given slice, ignoring ascii case and any zeros in self
    ///
    /// Returns None if no match is found.
    pub(crate) fn get_nocase_nozero<K: AsRef<[u8]>>(&self, key: K) -> Option<&Header> {
        self.elements
            .iter()
            .find(|x| x.name.cmp_nocase_nozero(key.as_ref()))
    }

    /// Search the Headers table for the first tuple with a tuple key matching the given slice, ignoring ascii case and any zeros in self
    ///
    /// Returns None if no match is found.
    pub(crate) fn get_nocase_nozero_mut<K: AsRef<[u8]>>(&mut self, key: K) -> Option<&mut Header> {
        self.elements
            .iter_mut()
            .find(|x| x.name.cmp_nocase_nozero(key.as_ref()))
    }

    /// Search the Headers table for the first tuple with a key matching the given slice, ingnoring ascii case in self
    ///
    /// Returns None if no match is found.
    pub(crate) fn get_nocase_mut<K: AsRef<[u8]>>(&mut self, key: K) -> Option<&mut Header> {
        self.elements
            .iter_mut()
            .find(|x| x.name.cmp_nocase(key.as_ref()))
    }

    /// Search the Headers table for the first tuple with a key matching the given slice, ingnoring ascii case in self
    ///
    /// Returns None if no match is found.
    pub(crate) fn get_nocase<K: AsRef<[u8]>>(&self, key: K) -> Option<&Header> {
        self.elements
            .iter()
            .find(|x| x.name.cmp_nocase(key.as_ref()))
    }

    /// Returns the number of elements in the Headers table
    pub(crate) fn size(&self) -> usize {
        self.elements.len()
    }
}

impl<'a> IntoIterator for &'a Headers {
    type Item = &'a Header;
    type IntoIter = std::slice::Iter<'a, Header>;

    fn into_iter(self) -> std::slice::Iter<'a, Header> {
        self.elements.iter()
    }
}

impl IntoIterator for Headers {
    type Item = Header;
    type IntoIter = std::vec::IntoIter<Header>;

    fn into_iter(self) -> std::vec::IntoIter<Header> {
        self.elements.into_iter()
    }
}

impl Header {
    /// Construct a new header.
    #[cfg(test)]
    pub(crate) fn new(name: Bstr, value: Bstr) -> Self {
        Self::new_with_flags(name, value, 0)
    }

    /// Construct a new header with flags.
    pub(crate) fn new_with_flags(name: Bstr, value: Bstr, flags: u64) -> Self {
        Self { name, value, flags }
    }
}

/// Possible states of a progressing transaction. Internally, progress will change
/// to the next state when the processing activities associated with that state
/// begin. For example, when we start to process request line bytes, the request
/// state will change from NOT_STARTED to LINE.*
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Debug)]
pub enum HtpResponseProgress {
    /// Default state.
    NOT_STARTED,
    /// Response Line.
    LINE,
    /// Response Headers.
    HEADERS,
    /// Response Body.
    BODY,
    /// Trailer data.
    TRAILER,
    /// Response completed.
    COMPLETE,
    /// Error involving response side of transaction.
    ERROR,
    /// Response gap.
    GAP,
}

/// Possible states of a progressing transaction. Internally, progress will change
/// to the next state when the processing activities associated with that state
/// begin. For example, when we start to process request line bytes, the request
/// state will change from NOT_STARTED to LINE.*
#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Debug)]
pub enum HtpRequestProgress {
    /// Default state.
    NOT_STARTED,
    /// In request line state.
    LINE,
    /// In request headers state.
    HEADERS,
    /// In request body state.
    BODY,
    /// Trailer data.
    TRAILER,
    /// Request is completed.
    COMPLETE,
    /// Error involving request side of transaction.
    ERROR,
    /// In request gap state.
    GAP,
}

/// Enumerates the possible values for authentication type.
#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum HtpAuthType {
    /// This is the default value that is used before
    /// the presence of authentication is determined (e.g.,
    /// before request headers are seen).
    Unknown,
    /// No authentication.
    NONE,
    /// HTTP Basic authentication used.
    BASIC,
    /// HTTP Digest authentication used.
    DIGEST,
    /// HTTP Bearer authentication used.
    BEARER,
    /// Unrecognized authentication method.
    UNRECOGNIZED = 9,
    /// Error retrieving the auth type.
    ERROR,
}

/// Protocol version constants.
#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Debug)]
pub enum HtpProtocol {
    /// Error with the transaction side.
    Error = -3,
    /// Could not resolve protocol version number.
    Invalid = -2,
    /// Default protocol value.
    Unknown = -1,
    /// HTTP/0.9 version.
    V0_9 = 9,
    /// HTTP/1.0 version.
    V1_0 = 100,
    /// HTTP/1.1 version.
    V1_1 = 101,
}

/// Represents a single HTTP transaction, which is a combination of a request and a response.
pub struct Transaction {
    /// The logger structure associated with this transaction
    pub(crate) logger: Logger,
    /// The configuration structure associated with this transaction.
    pub(crate) cfg: &'static Config,
    /// The user data associated with this transaction.
    pub(crate) user_data: Option<Box<dyn Any>>,
    // Request fields
    /// Contains a count of how many empty lines were skipped before the request line.
    pub(crate) request_ignored_lines: u32,
    /// The first line of this request.
    pub(crate) request_line: Option<Bstr>,
    /// Request method.
    pub(crate) request_method: Option<Bstr>,
    /// Request method, as number. Available only if we were able to recognize the request method.
    pub(crate) request_method_number: HtpMethod,
    /// Request URI, raw, as given to us on the request line. This field can take different forms,
    /// for example authority for CONNECT methods, absolute URIs for proxy requests, and the query
    /// string when one is provided. Use Transaction::parsed_uri if you need to access to specific
    /// URI elements. Can be NULL if the request line contains only a request method (which is
    /// an extreme case of HTTP/0.9, but passes in practice.
    pub(crate) request_uri: Option<Bstr>,
    /// Request protocol, as text. Can be NULL if no protocol was specified.
    pub(crate) request_protocol: Option<Bstr>,
    /// Protocol version as a number. Multiply the high version number by 100, then add the low
    /// version number. You should prefer to work the pre-defined HtpProtocol constants.
    pub(crate) request_protocol_number: HtpProtocol,
    /// Is this request using HTTP/0.9? We need a separate field for this purpose because
    /// the protocol version alone is not sufficient to determine if HTTP/0.9 is used. For
    /// example, if you submit "GET / HTTP/0.9" to Apache, it will not treat the request
    /// as HTTP/0.9.
    pub(crate) is_protocol_0_9: bool,
    /// This structure holds the individual components parsed out of the request URI, with
    /// appropriate normalization and transformation applied, per configuration. No information
    /// is added. In extreme cases when no URI is provided on the request line, all fields
    /// will be NULL. (Well, except for port_number, which will be -1.) To inspect raw data, use
    /// Transaction::request_uri or Transaction::parsed_uri_raw.
    pub(crate) parsed_uri: Option<Uri>,
    /// This structure holds the individual components parsed out of the request URI, but
    /// without any modification. The purpose of this field is to allow you to look at the data as it
    /// was supplied on the request line. Fields can be NULL, depending on what data was supplied.
    /// The port_number field is always -1.
    pub(crate) parsed_uri_raw: Option<Uri>,
    ///  This structure holds the whole normalized uri, including path, query, fragment, scheme, username, password, hostname, and port
    pub(crate) complete_normalized_uri: Option<Bstr>,
    ///  This structure holds the normalized uri, including path, query, and fragment
    pub(crate) partial_normalized_uri: Option<Bstr>,
    /// HTTP 1.1 RFC
    ///
    /// 4.3 Message Body
    ///
    /// The message-body (if any) of an HTTP message is used to carry the
    /// entity-body associated with the request or response. The message-body
    /// differs from the entity-body only when a transfer-coding has been
    /// applied, as indicated by the Transfer-Encoding header field (section
    /// 14.41).
    ///
    /// ```text
    ///     message-body = entity-body
    ///                  | <entity-body encoded as per Transfer-Encoding>
    /// ```
    ///
    /// The length of the request message-body. In most cases, this value
    /// will be the same as request_entity_len. The values will be different
    /// if request compression or chunking were applied. In that case,
    /// request_message_len contains the length of the request body as it
    /// has been seen over TCP; request_entity_len contains length after
    /// de-chunking and decompression.
    pub(crate) request_message_len: u64,
    /// The length of the request entity-body. In most cases, this value
    /// will be the same as request_message_len. The values will be different
    /// if request compression or chunking were applied. In that case,
    /// request_message_len contains the length of the request body as it
    /// has been seen over TCP; request_entity_len contains length after
    /// de-chunking and decompression.
    pub(crate) request_entity_len: u64,
    /// Parsed request headers.
    pub(crate) request_headers: Headers,
    /// Request transfer coding. Can be one of UNKNOWN (body presence not
    /// determined yet), IDENTITY, CHUNKED, NO_BODY,
    /// and UNRECOGNIZED.
    pub(crate) request_transfer_coding: HtpTransferCoding,
    /// Request body compression, which indicates if compression is used
    /// for the request body. This field is an interpretation of the information
    /// available in request headers.
    pub(crate) request_content_encoding: HtpContentEncoding,
    /// Request body compression processing information, which is related to how
    /// the library is going to process (or has processed) a request body. Changing
    /// this field mid-processing can influence library actions. For example, setting
    /// this field to NONE in a request_headers callback will prevent
    /// decompression.
    pub(crate) request_content_encoding_processing: HtpContentEncoding,
    /// This field will contain the request content type when that information
    /// is available in request headers. The contents of the field will be converted
    /// to lowercase and any parameters (e.g., character set information) removed.
    pub(crate) request_content_type: Option<Bstr>,
    /// Request decompressor used to decompress request body data.
    pub(crate) request_decompressor: Option<Decompressor>,
    /// Contains the value specified in the Content-Length header. The value of this
    /// field will be None from the beginning of the transaction and until request
    /// headers are processed. It will stay None if the C-L header was not provided,
    /// or if the value in it cannot be parsed.
    pub(crate) request_content_length: Option<u64>,
    /// Transaction-specific REQUEST_BODY_DATA hook. Behaves as
    /// the configuration hook with the same name.
    pub(crate) hook_request_body_data: DataHook,
    /// Transaction-specific RESPONSE_BODY_DATA hook. Behaves as
    /// the configuration hook with the same name.
    pub(crate) hook_response_body_data: DataHook,
    /// Authentication type used in the request.
    pub(crate) request_auth_type: HtpAuthType,
    /// Authentication username.
    pub(crate) request_auth_username: Option<Bstr>,
    /// Authentication password. Available only when Transaction::request_auth_type is HTP_AUTH_BASIC.
    pub(crate) request_auth_password: Option<Bstr>,
    /// Authentication token. Available only when Transaction::request_auth_type is HTP_AUTH_BEARER.
    pub(crate) request_auth_token: Option<Bstr>,
    /// Request hostname. Per the RFC, the hostname will be taken from the Host header
    /// when available. If the host information is also available in the URI, it is used
    /// instead of whatever might be in the Host header. Can be NULL. This field does
    /// not contain port information.
    pub(crate) request_hostname: Option<Bstr>,
    /// Request port number, if presented. The rules for Transaction::request_host apply. Set to
    /// None by default.
    pub(crate) request_port_number: Option<u16>,

    // Response fields
    /// How many empty lines did we ignore before reaching the status line?
    pub(crate) response_ignored_lines: u32,
    /// Response line.
    pub(crate) response_line: Option<Bstr>,
    /// Response protocol, as text. Can be NULL.
    pub(crate) response_protocol: Option<Bstr>,
    /// Response protocol as number. Available only if we were able to parse the protocol version,
    /// INVALID otherwise. UNKNOWN until parsing is attempted.
    pub(crate) response_protocol_number: HtpProtocol,
    /// Response status code, as text. Starts as NULL and can remain NULL on
    /// an invalid response that does not specify status code.
    pub(crate) response_status: Option<Bstr>,
    /// Response status code, available only if we were able to parse it, HTP_STATUS_INVALID
    /// otherwise. HTP_STATUS_UNKNOWN until parsing is attempted.
    pub(crate) response_status_number: HtpResponseNumber,
    /// This field is set by the protocol decoder with it thinks that the
    /// backend server will reject a request with a particular status code.
    pub(crate) response_status_expected_number: HtpUnwanted,
    /// The message associated with the response status code. Can be NULL.
    pub(crate) response_message: Option<Bstr>,
    /// Have we seen the server respond with a 100 response?
    pub(crate) seen_100continue: bool,
    /// Parsed response headers. Contains instances of Header.
    pub(crate) response_headers: Headers,
    /// Is this a response a HTTP/2.0 upgrade?
    pub(crate) is_http_2_upgrade: bool,

    /// HTTP 1.1 RFC
    ///
    /// 4.3 Message Body
    ///
    /// The message-body (if any) of an HTTP message is used to carry the
    /// entity-body associated with the request or response. The message-body
    /// differs from the entity-body only when a transfer-coding has been
    /// applied, as indicated by the Transfer-Encoding header field (section
    /// 14.41).
    ///
    /// ```text
    ///     message-body = entity-body
    ///                  | <entity-body encoded as per Transfer-Encoding>
    /// ```
    ///
    /// The length of the response message-body. In most cases, this value
    /// will be the same as response_entity_len. The values will be different
    /// if response compression or chunking were applied. In that case,
    /// response_message_len contains the length of the response body as it
    /// has been seen over TCP; response_entity_len contains the length after
    /// de-chunking and decompression.
    pub(crate) response_message_len: u64,
    /// The length of the response entity-body. In most cases, this value
    /// will be the same as response_message_len. The values will be different
    /// if request compression or chunking were applied. In that case,
    /// response_message_len contains the length of the response body as it
    /// has been seen over TCP; response_entity_len contains length after
    /// de-chunking and decompression.
    pub(crate) response_entity_len: u64,
    /// Contains the value specified in the Content-Length header. The value of this
    /// field will be -1 from the beginning of the transaction and until response
    /// headers are processed. It will stay None if the C-L header was not provided,
    /// or if the value in it cannot be parsed.
    pub(crate) response_content_length: Option<u64>,
    /// Response transfer coding, which indicates if there is a response body,
    /// and how it is transported (e.g., as-is, or chunked).
    pub(crate) response_transfer_coding: HtpTransferCoding,
    /// Response body compression, which indicates if compression is used
    /// for the response body. This field is an interpretation of the information
    /// available in response headers.
    pub(crate) response_content_encoding: HtpContentEncoding,
    /// Response body compression processing information, which is related to how
    /// the library is going to process (or has processed) a response body. Changing
    /// this field mid-processing can influence library actions. For example, setting
    /// this field to NONE in a RESPONSE_HEADERS callback will prevent
    /// decompression.
    pub(crate) response_content_encoding_processing: HtpContentEncoding,
    /// This field will contain the response content type when that information
    /// is available in response headers. The contents of the field will be converted
    /// to lowercase and any parameters (e.g., character set information) removed.
    pub(crate) response_content_type: Option<Bstr>,
    /// Response decompressor used to decompress response body data.
    pub(crate) response_decompressor: Option<Decompressor>,

    // Common fields
    /// Parsing flags; a combination of: HTP_REQUEST_INVALID_T_E, HTP_INVALID_FOLDING,
    /// HTP_REQUEST_SMUGGLING, HTP_MULTI_PACKET_HEAD, and HTP_FIELD_UNPARSEABLE.
    pub(crate) flags: u64,
    /// Request progress.
    pub(crate) request_progress: HtpRequestProgress,
    /// Response progress.
    pub(crate) response_progress: HtpResponseProgress,
    /// Transaction index on the connection.
    pub(crate) index: usize,
    /// Total repetitions for headers in request.
    pub(crate) request_header_repetitions: u16,
    /// Total repetitions for headers in response.
    pub(crate) response_header_repetitions: u16,
    /// Request header parser
    pub(crate) request_header_parser: HeaderParser,
    /// Response header parser
    pub(crate) response_header_parser: HeaderParser,
}

impl std::fmt::Debug for Transaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Transaction")
            .field("request_line", &self.request_line)
            .field("request_method", &self.request_method)
            .field("request_method_number", &self.request_method_number)
            .field("request_uri", &self.request_uri)
            .field("request_protocol", &self.request_protocol)
            .field("request_protocol_number", &self.request_protocol_number)
            .field("is_protocol_0_9", &self.is_protocol_0_9)
            .field("parsed_uri", &self.parsed_uri)
            .field("parsed_uri_raw", &self.parsed_uri_raw)
            .field("complete_normalized_uri", &self.complete_normalized_uri)
            .field("partial_normalized_uri", &self.partial_normalized_uri)
            .field("request_message_len", &self.request_message_len)
            .field("request_entity_len", &self.request_entity_len)
            .field("request_headers", &self.request_headers)
            .field("request_transfer_coding", &self.request_transfer_coding)
            .field("request_content_encoding", &self.request_content_encoding)
            .field(
                "request_content_encoding_processing",
                &self.request_content_encoding_processing,
            )
            .field("request_content_type", &self.request_content_type)
            .field("request_content_length", &self.request_content_length)
            .field("request_auth_type", &self.request_auth_type)
            .field("request_auth_username", &self.request_auth_username)
            .field("request_auth_password", &self.request_auth_password)
            .field("request_auth_token", &self.request_auth_token)
            .field("request_hostname", &self.request_hostname)
            .field("request_port_number", &self.request_port_number)
            .field("request_ignored_lines", &self.request_ignored_lines)
            .field("response_ignored_lines", &self.response_ignored_lines)
            .field("response_line", &self.response_line)
            .field("response_protocol", &self.response_protocol)
            .field("response_protocol_number", &self.response_protocol_number)
            .field("response_status", &self.response_status)
            .field("response_status_number", &self.response_status_number)
            .field(
                "response_status_expected_number",
                &self.response_status_expected_number,
            )
            .field("response_message", &self.response_message)
            .field("seen_100continue", &self.seen_100continue)
            .field("response_headers", &self.response_headers)
            .field("is_http_2_upgrade", &self.is_http_2_upgrade)
            .field("response_message_len", &self.response_message_len)
            .field("response_entity_len", &self.response_entity_len)
            .field("response_content_length", &self.response_content_length)
            .field("response_transfer_coding", &self.response_transfer_coding)
            .field("response_content_encoding", &self.response_content_encoding)
            .field(
                "response_content_encoding_processing",
                &self.response_content_encoding_processing,
            )
            .field("response_content_type", &self.response_content_type)
            .field("flags", &self.flags)
            .field("request_progress", &self.request_progress)
            .field("response_progress", &self.response_progress)
            .field("index", &self.index)
            .field(
                "request_header_repetitions",
                &self.request_header_repetitions,
            )
            .field(
                "response_header_repetitions",
                &self.response_header_repetitions,
            )
            .finish()
    }
}

impl Drop for Transaction {
    fn drop(&mut self) {
        if self.user_data.is_none() {
            return;
        }
        if let Some(cb) = self.cfg.hook_tx_destroy {
            unsafe { cb(htp_tx_get_user_data(self)) };
        }
    }
}

impl Transaction {
    /// Construct a new transaction.
    pub(crate) fn new(
        cfg: &'static Config, logger: &Logger, index: usize, req: bool,
    ) -> Option<Self> {
        let mut tx = Self {
            logger: logger.clone(),
            cfg,
            user_data: None,
            request_ignored_lines: 0,
            request_line: None,
            request_method: None,
            request_method_number: HtpMethod::Unknown,
            request_uri: None,
            request_protocol: None,
            request_protocol_number: HtpProtocol::Unknown,
            is_protocol_0_9: false,
            parsed_uri: None,
            parsed_uri_raw: None,
            complete_normalized_uri: None,
            partial_normalized_uri: None,
            request_message_len: 0,
            request_entity_len: 0,
            request_headers: Headers::with_capacity(32),
            request_transfer_coding: HtpTransferCoding::Unknown,
            request_content_encoding: HtpContentEncoding::None,
            request_content_encoding_processing: HtpContentEncoding::None,
            request_content_type: None,
            request_content_length: None,
            request_decompressor: None,
            hook_request_body_data: DataHook::default(),
            hook_response_body_data: DataHook::default(),
            request_auth_type: HtpAuthType::Unknown,
            request_auth_username: None,
            request_auth_password: None,
            request_auth_token: None,
            request_hostname: None,
            request_port_number: None,
            response_ignored_lines: 0,
            response_line: None,
            response_protocol: None,
            response_protocol_number: HtpProtocol::Unknown,
            response_status: None,
            response_status_number: HtpResponseNumber::Unknown,
            response_status_expected_number: HtpUnwanted::Ignore,
            response_message: None,
            seen_100continue: false,
            response_headers: Headers::with_capacity(32),
            is_http_2_upgrade: false,
            response_message_len: 0,
            response_entity_len: 0,
            response_content_length: None,
            response_transfer_coding: HtpTransferCoding::Unknown,
            response_content_encoding: HtpContentEncoding::None,
            response_content_encoding_processing: HtpContentEncoding::None,
            response_content_type: None,
            response_decompressor: None,
            flags: 0,
            request_progress: HtpRequestProgress::NOT_STARTED,
            response_progress: HtpResponseProgress::NOT_STARTED,
            index,
            request_header_repetitions: 0,
            response_header_repetitions: 0,
            request_header_parser: HeaderParser::new(Side::Request),
            response_header_parser: HeaderParser::new(Side::Response),
        };
        if let Some(cb) = cfg.hook_tx_create {
            let r = unsafe { cb(req) };
            if r.is_null() {
                return None;
            }
            tx.set_user_data(Box::new(r));
        }
        Some(tx)
    }

    /// Has this transaction started?
    pub(crate) fn is_started(&self) -> bool {
        !(self.request_progress == HtpRequestProgress::NOT_STARTED
            && self.response_progress == HtpResponseProgress::NOT_STARTED)
    }

    /// Set the user data.
    pub(crate) fn set_user_data(&mut self, data: Box<dyn Any + 'static>) {
        self.user_data = Some(data);
    }

    /// Get a reference to the user data.
    pub(crate) fn user_data<T: 'static>(&self) -> Option<&T> {
        self.user_data
            .as_ref()
            .and_then(|ud| ud.downcast_ref::<T>())
    }

    /// Get a mutable reference to the user data.
    #[cfg(test)]
    pub(crate) fn user_data_mut<T: 'static>(&mut self) -> Option<&mut T> {
        self.user_data
            .as_mut()
            .and_then(|ud| ud.downcast_mut::<T>())
    }

    /// Determine if the request has a body.
    pub(crate) fn request_has_body(&self) -> bool {
        self.request_transfer_coding == HtpTransferCoding::Identity
            || self.request_transfer_coding == HtpTransferCoding::Chunked
    }

    /// Process the extracted request headers and set the appropriate flags
    pub(crate) fn process_request_headers(&mut self) -> Result<()> {
        // Determine if we have a request body, and how it is packaged.
        let cl_opt = self.request_headers.get_nocase_nozero("content-length");
        // Check for the Transfer-Encoding header, which would indicate a chunked request body.
        if let Some(te) = self.request_headers.get_nocase_nozero("transfer-encoding") {
            // Make sure it contains "chunked" only.
            // TODO The HTTP/1.1 RFC also allows the T-E header to contain "identity", which
            //      presumably should have the same effect as T-E header absence. However, Apache
            //      (2.2.22 on Ubuntu 12.04 LTS) instead errors out with "Unknown Transfer-Encoding: identity".
            //      And it behaves strangely, too, sending a 501 and proceeding to process the request
            //      (e.g., PHP is run), but without the body. It then closes the connection.
            if te.value.index_of_nocase_nozero("chunked").is_none() {
                // Invalid T-E header value.
                self.request_transfer_coding = HtpTransferCoding::Invalid;
                self.flags.set(HtpFlags::REQUEST_INVALID_T_E);
                self.flags.set(HtpFlags::REQUEST_INVALID)
            } else {
                // Chunked encoding is a HTTP/1.1 feature, so check that an earlier protocol
                // version is not used. The flag will also be set if the protocol could not be parsed.
                //
                // TODO IIS 7.0, for example, would ignore the T-E header when it
                //      it is used with a protocol below HTTP 1.1. This should be a
                //      personality trait.
                if self.request_protocol_number < HtpProtocol::V1_1 {
                    self.flags.set(HtpFlags::REQUEST_INVALID_T_E);
                    self.flags.set(HtpFlags::REQUEST_SMUGGLING);
                }
                // If the T-E header is present we are going to use it.
                self.request_transfer_coding = HtpTransferCoding::Chunked;
                // We are still going to check for the presence of C-L.
                if cl_opt.is_some() {
                    // According to the HTTP/1.1 RFC (section 4.4):
                    //
                    // "The Content-Length header field MUST NOT be sent
                    //  if these two lengths are different (i.e., if a Transfer-Encoding
                    //  header field is present). If a message is received with both a
                    //  Transfer-Encoding header field and a Content-Length header field,
                    //  the latter MUST be ignored."
                    //
                    self.flags.set(HtpFlags::REQUEST_SMUGGLING)
                }
            }
        } else if let Some(cl) = cl_opt {
            // Check for a folded C-L header.
            if cl.flags.is_set(HtpFlags::FIELD_FOLDED) {
                self.flags.set(HtpFlags::REQUEST_SMUGGLING)
            }
            // Check for multiple C-L headers.
            if cl.flags.is_set(HtpFlags::FIELD_REPEATED) {
                self.flags.set(HtpFlags::REQUEST_SMUGGLING)
                // TODO Personality trait to determine which C-L header to parse.
                //      At the moment we're parsing the combination of all instances,
                //      which is bound to fail (because it will contain commas).
            }
            // Get the body length.
            self.request_content_length =
                parse_content_length(cl.value.as_slice(), Some(&mut self.logger));
            if self.request_content_length.is_some() {
                // We have a request body of known length.
                self.request_transfer_coding = HtpTransferCoding::Identity
            } else {
                self.request_transfer_coding = HtpTransferCoding::Invalid;
                self.flags.set(HtpFlags::REQUEST_INVALID_C_L);
                self.flags.set(HtpFlags::REQUEST_INVALID)
            }
        } else {
            // No body.
            self.request_transfer_coding = HtpTransferCoding::NoBody
        }
        // If we could not determine the correct body handling,
        // consider the request invalid.
        if self.request_transfer_coding == HtpTransferCoding::Unknown {
            self.request_transfer_coding = HtpTransferCoding::Invalid;
            self.flags.set(HtpFlags::REQUEST_INVALID)
        }

        // Determine hostname.
        // Use the hostname from the URI, when available.
        if let Some(hostname) = self.get_parsed_uri_hostname() {
            self.request_hostname = Some(Bstr::from(hostname.as_slice()));
        }

        if let Some(port_number) = self.get_parsed_uri_port_number() {
            self.request_port_number = Some(*port_number);
        }
        // Examine the Host header.
        if let Some(header) = self.request_headers.get_nocase_nozero_mut("host") {
            // Host information available in the headers.
            if let Ok((_, (hostname, port_nmb, valid))) = parse_hostport(&header.value) {
                if !valid {
                    self.flags.set(HtpFlags::HOSTH_INVALID)
                }
                // The host information in the headers is valid.
                // Is there host information in the URI?
                if self.request_hostname.is_none() {
                    // There is no host information in the URI. Place the
                    // hostname from the headers into the parsed_uri structure.
                    let mut hostname = Bstr::from(hostname);
                    hostname.make_ascii_lowercase();
                    self.request_hostname = Some(hostname);
                    if let Some((_, port)) = port_nmb {
                        self.request_port_number = port;
                    }
                } else {
                    // The host information appears in the URI and in the headers. The
                    // HTTP RFC states that we should ignore the header copy.
                    // Check for different hostnames.
                    if let Some(host) = &self.request_hostname {
                        if !host.cmp_nocase(hostname) {
                            self.flags.set(HtpFlags::HOST_AMBIGUOUS)
                        }
                    }

                    if let Some((_, port)) = port_nmb {
                        // Check for different ports.
                        if self.request_port_number.is_some() && self.request_port_number != port {
                            self.flags.set(HtpFlags::HOST_AMBIGUOUS)
                        }
                    }
                }
            } else if self.request_hostname.is_some() {
                // Invalid host information in the headers.
                // Raise the flag, even though the host information in the headers is invalid.
                self.flags.set(HtpFlags::HOST_AMBIGUOUS)
            }
        } else {
            // No host information in the headers.
            // HTTP/1.1 requires host information in the headers.
            if self.request_protocol_number >= HtpProtocol::V1_1 {
                self.flags.set(HtpFlags::HOST_MISSING)
            }
        }
        // Determine Content-Type.
        if let Some(ct) = self.request_headers.get_nocase_nozero("content-type") {
            self.request_content_type = Some(parse_content_type(ct.value.as_slice())?);
        }
        // Parse authentication information.
        parse_authorization(self).or_else(|rc| {
            if rc == HtpStatus::DECLINED {
                // Don't fail the stream if an authorization header is invalid, just set a flag.
                self.flags.set(HtpFlags::AUTH_INVALID);
                Ok(())
            } else {
                Err(rc)
            }
        })?;
        Ok(())
    }

    /// Sanity check the response line, logging if there is an invalid protocol or status number.
    pub(crate) fn validate_response_line(&mut self) {
        // Is the response line valid?
        if self.response_protocol_number == HtpProtocol::Invalid {
            htp_warn!(
                self.logger,
                HtpLogCode::RESPONSE_LINE_INVALID_PROTOCOL,
                "Invalid response line: invalid protocol"
            );
            self.flags.set(HtpFlags::STATUS_LINE_INVALID)
        }
        if !self.response_status_number.in_range(100, 999) {
            htp_warn!(
                self.logger,
                HtpLogCode::RESPONSE_LINE_INVALID_RESPONSE_STATUS,
                "Invalid response line: invalid response status."
            );
            self.response_status_number = HtpResponseNumber::Invalid;
            self.flags.set(HtpFlags::STATUS_LINE_INVALID)
        }
    }

    /// Parse the raw request line
    pub(crate) fn parse_request_line(&mut self) -> Result<()> {
        // Determine how to process the request URI.
        let mut parsed_uri = Uri::with_config(self.cfg.decoder_cfg);
        if self.request_method_number == HtpMethod::CONNECT {
            // When CONNECT is used, the request URI contains an authority string.
            parsed_uri.parse_uri_hostport(
                self.request_uri.as_ref().ok_or(HtpStatus::ERROR)?,
                &mut self.flags,
            );
        } else if let Some(uri) = self.request_uri.as_ref() {
            parsed_uri.parse_uri(uri.as_slice());
        }
        self.parsed_uri_raw = Some(parsed_uri);
        // Parse the request URI into Transaction::parsed_uri_raw.
        // Build Transaction::parsed_uri, but only if it was not explicitly set already.
        if self.parsed_uri.is_none() {
            // Keep the original URI components, but create a copy which we can normalize and use internally.
            self.normalize_parsed_uri();
        }

        // Check parsed_uri hostname.
        if let Some(hostname) = self.get_parsed_uri_hostname() {
            if !validate_hostname(hostname.as_slice()) {
                self.flags.set(HtpFlags::HOSTU_INVALID)
            }
        }
        Ok(())
    }

    #[cfg(test)]
    /// Determines if both request and response are complete.
    pub(crate) fn is_complete(&self) -> bool {
        // A transaction is considered complete only when both the request and
        // response are complete. (Sometimes a complete response can be seen
        // even while the request is ongoing.)
        self.request_progress == HtpRequestProgress::COMPLETE
            && self.response_progress == HtpResponseProgress::COMPLETE
    }

    /// Return a reference to the uri hostname.
    pub(crate) fn get_parsed_uri_hostname(&self) -> Option<&Bstr> {
        self.parsed_uri
            .as_ref()
            .and_then(|parsed_uri| parsed_uri.hostname.as_ref())
    }

    /// Return a reference to the uri port_number.
    pub(crate) fn get_parsed_uri_port_number(&self) -> Option<&u16> {
        self.parsed_uri
            .as_ref()
            .and_then(|parsed_uri| parsed_uri.port_number.as_ref())
    }

    /// Normalize a previously-parsed request URI.
    pub(crate) fn normalize_parsed_uri(&mut self) {
        let mut uri = Uri::with_config(self.cfg.decoder_cfg);
        if let Some(incomplete) = &self.parsed_uri_raw {
            uri.scheme = incomplete.normalized_scheme();
            uri.username = incomplete.normalized_username(&mut self.flags);
            uri.password = incomplete.normalized_password(&mut self.flags);
            uri.hostname = incomplete.normalized_hostname(&mut self.flags);
            uri.port_number = incomplete.normalized_port(&mut self.flags);
            uri.query = incomplete.query.clone();
            uri.fragment = incomplete.normalized_fragment(&mut self.flags);
            uri.path = incomplete
                .normalized_path(&mut self.flags, &mut self.response_status_expected_number);
        }
        self.parsed_uri = Some(uri);
    }
}

impl PartialEq for Transaction {
    /// Determines if other references the same transaction.
    fn eq(&self, other: &Self) -> bool {
        self.index == other.index
    }
}

#[test]
fn GetNocaseNozero() {
    let mut t = Headers::with_capacity(2);
    let v1 = Bstr::from("Value1");
    let mut k = Bstr::from("K\x00\x00\x00\x00ey\x001");
    let mut h = Header::new(k, v1.clone());
    t.elements.push(h);
    k = Bstr::from("K\x00e\x00\x00Y2");
    let v2 = Bstr::from("Value2");
    h = Header::new(k, v2.clone());
    t.elements.push(h);

    let mut result = t.get_nocase_nozero("key1");
    let mut res = result.unwrap();
    assert_eq!(
        Ordering::Equal,
        res.name.cmp_slice("K\x00\x00\x00\x00ey\x001")
    );
    assert_eq!(v1, res.value);

    result = t.get_nocase_nozero("KeY1");
    res = result.unwrap();
    assert_eq!(
        Ordering::Equal,
        res.name.cmp_slice("K\x00\x00\x00\x00ey\x001")
    );
    assert_eq!(v1, res.value);

    result = t.get_nocase_nozero("KEY2");
    res = result.unwrap();
    assert_eq!(Ordering::Equal, res.name.cmp_slice("K\x00e\x00\x00Y2"));
    assert_eq!(v2, res.value);

    result = t.get_nocase("key1");
    assert!(result.is_none());
}
