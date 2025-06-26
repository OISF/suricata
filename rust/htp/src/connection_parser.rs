use crate::{
    bstr::Bstr,
    config::Config,
    connection::{Connection, ConnectionFlags},
    decompressors::HtpContentEncoding,
    error::Result,
    hook::DataHook,
    log::Logger,
    transaction::{HtpRequestProgress, HtpResponseProgress, HtpTransferCoding, Transaction},
    transactions::Transactions,
    util::{FlagOperations, HtpFlags},
    HtpStatus,
};
use std::{any::Any, borrow::Cow, cell::Cell, net::IpAddr, time::SystemTime};
use time::OffsetDateTime;

/// Enumerates parsing state.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum State {
    /// Default state.
    None,
    /// State once a transaction is processed or about to be processed.
    Idle,
    /// State for request/response line parsing.
    Line,
    /// State for header parsing.
    Headers,
    /// State for finalizing chunked body data parsing.
    BodyChunkedDataEnd,
    /// State for chunked body data.
    BodyChunkedData,
    /// Parse the chunked length state.
    BodyChunkedLength,
    /// State to determine encoding of body data.
    BodyDetermine,
    /// State for finalizing transaction side.
    Finalize,
    // Used by request_state only
    /// State for determining the request protocol.
    Protocol,
    /// State to determine if there is a CONNECT request.
    ConnectCheck,
    /// State to determine if inbound parsing needs to be suspended.
    ConnectProbeData,
    /// State to determine if inbound parsing can continue if it was suspended.
    ConnectWaitResponse,
    /// State to process request body data.
    BodyIdentity,
    /// State to consume remaining data in request buffer for the HTTP 0.9 case.
    IgnoreDataAfterHTTP09,
    // Used by response_state only
    /// State to consume response remaining body data when content-length is unknown.
    BodyIdentityStreamClose,
    /// State to consume response body data when content-length is known.
    BodyIdentityCLKnown,
}

/// Enumerates all stream states. Each connection has two streams, one
/// inbound and one outbound. Their states are tracked separately.
#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum HtpStreamState {
    /// Default stream state.
    NEW,
    /// State when connection is open.
    OPEN,
    /// State when connection is closed.
    CLOSED,
    /// State when stream produces a fatal error.
    ERROR,
    /// State for a tunnelled stream.
    TUNNEL,
    /// State when parsing is suspended and not consumed in order. This is to
    /// allow processing on another stream.
    DATA_OTHER,
    /// State when we should stop parsing the associated connection.
    STOP,
    /// State when all current data in the stream has been processed.
    DATA,
}

#[derive(Debug, Default, Clone)]
/// This structure is used to pass data (for example
/// request and response body buffers or gaps) to parsers.
pub(crate) struct ParserData<'a> {
    /// Ref to the data buffer.
    data: Option<Cow<'a, [u8]>>,
    // Length of data gap. Only set if is a gap.
    gap_len: Option<usize>,
    // Current position offset of the data to parse
    position: Cell<usize>,
    // Current callback data position
    callback_position: usize,
}

impl ParserData<'_> {
    /// Returns a pointer to the raw data associated with Data.
    /// This returns a pointer to the entire data chunk.
    pub(crate) fn data_ptr(&self) -> *const u8 {
        self.data()
            .as_ref()
            .map(|data| data.as_ptr())
            .unwrap_or(std::ptr::null())
    }

    /// Returns the unconsumed data
    pub(crate) fn data(&self) -> Option<&[u8]> {
        let data = self.data.as_ref()?;
        if self.position.get() <= data.len() {
            Some(&data[self.position.get()..])
        } else {
            None
        }
    }

    /// Returns the length of the unconsumed data.
    pub(crate) fn len(&self) -> usize {
        if let Some(gap_len) = self.gap_len {
            if self.position.get() >= gap_len {
                0
            } else {
                gap_len - self.position.get()
            }
        } else {
            self.as_slice().len()
        }
    }

    /// Returns how much data has been consumed so far
    fn consumed_len(&self) -> usize {
        self.position.get()
    }

    /// Return an immutable slice view of the unconsumed data.
    pub(crate) fn as_slice(&self) -> &[u8] {
        if let Some(data) = self.data.as_ref() {
            if self.position.get() <= data.len() {
                return &data[self.position.get()..];
            }
        }
        b""
    }

    /// Determines if this chunk is a gap or not
    pub(crate) fn is_gap(&self) -> bool {
        self.gap_len.is_some()
    }

    /// Determine whether there is no more data to consume.
    pub(crate) fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Set the position offset into the data for parsing
    fn set_position(&self, position: usize) {
        self.position.set(position);
    }

    /// Advances the internal position where we are parsing
    pub(crate) fn consume(&self, consumed: usize) {
        self.set_position(self.position.get() + consumed);
    }

    /// Decrements the internal position where we are parsing
    fn unconsume(&self, unconsume: usize) {
        if unconsume < self.position.get() {
            self.set_position(self.position.get() - unconsume);
        } else {
            self.set_position(0);
        }
    }

    /// Make an owned version of this data.
    #[cfg(test)]
    pub(crate) fn into_owned(self) -> ParserData<'static> {
        ParserData {
            data: self.data.map(|d| Cow::Owned(d.into_owned())),
            gap_len: self.gap_len,
            position: self.position,
            callback_position: self.callback_position,
        }
    }

    /// Callback data is raw data buffer content that is passed to the
    /// application via the header and trailer data hooks.
    ///
    /// This function will return any data that has been consumed but not
    /// yet returned from this function.
    pub(crate) fn callback_data(&mut self) -> &[u8] {
        if let Some(data) = self.data.as_ref() {
            if self.position.get() <= data.len() && self.callback_position <= self.position.get() {
                let d = &data[self.callback_position..self.position.get()];
                self.callback_position = self.position.get();
                return d;
            }
        }
        b""
    }

    /// Sets the callback start location to the current parsing location
    pub(crate) fn reset_callback_start(&mut self) {
        self.callback_position = self.position.get();
    }
}

impl<'a> From<Option<&'a [u8]>> for ParserData<'a> {
    fn from(data: Option<&'a [u8]>) -> Self {
        ParserData {
            data: data.map(Cow::Borrowed),
            gap_len: None,
            position: Cell::new(0),
            callback_position: 0,
        }
    }
}

impl<'a> From<&'a [u8]> for ParserData<'a> {
    fn from(data: &'a [u8]) -> Self {
        ParserData {
            data: Some(Cow::Borrowed(data)),
            gap_len: None,
            position: Cell::new(0),
            callback_position: 0,
        }
    }
}

impl From<Vec<u8>> for ParserData<'static> {
    fn from(data: Vec<u8>) -> Self {
        ParserData {
            data: Some(Cow::Owned(data)),
            gap_len: None,
            position: Cell::new(0),
            callback_position: 0,
        }
    }
}

impl<'a> From<&'a Vec<u8>> for ParserData<'a> {
    fn from(data: &'a Vec<u8>) -> Self {
        ParserData {
            data: Some(Cow::Borrowed(data.as_slice())),
            gap_len: None,
            position: Cell::new(0),
            callback_position: 0,
        }
    }
}

impl From<usize> for ParserData<'_> {
    fn from(gap_len: usize) -> Self {
        ParserData {
            data: None,
            gap_len: Some(gap_len),
            position: Cell::new(0),
            callback_position: 0,
        }
    }
}

impl From<(*const u8, usize)> for ParserData<'_> {
    fn from((data, len): (*const u8, usize)) -> Self {
        if data.is_null() {
            if len > 0 {
                ParserData::from(len)
            } else {
                ParserData::from(b"".as_ref())
            }
        } else {
            unsafe { ParserData::from(std::slice::from_raw_parts(data, len)) }
        }
    }
}

/// Stores information about the parsing process and associated transactions.
pub struct ConnectionParser {
    // General fields
    /// The logger structure associated with this parser
    pub(crate) logger: Logger,
    /// A reference to the current parser configuration structure.
    pub(crate) cfg: &'static Config,
    /// The connection structure associated with this parser.
    pub(crate) conn: Connection,
    /// Opaque user data associated with this parser.
    pub(crate) user_data: Option<Box<dyn Any>>,
    // Request parser fields
    /// Parser inbound status. Starts as OK, but may turn into ERROR.
    pub(crate) request_status: HtpStreamState,
    /// Parser outbound status. Starts as OK, but may turn into ERROR.
    pub(crate) response_status: HtpStreamState,
    /// When true, this field indicates that there is unprocessed inbound data, and
    /// that the response parsing code should stop at the end of the current request
    /// in order to allow more requests to be produced.
    pub(crate) response_data_other_at_tx_end: bool,
    /// The time when the last request data chunk was received.
    pub(crate) request_timestamp: OffsetDateTime,
    /// How many bytes from the last input chunk have we consumed
    /// This is mostly used from callbacks, where the caller
    /// wants to know how far into the last chunk the parser is.
    pub(crate) request_bytes_consumed: usize,
    /// How many data chunks does the inbound connection stream consist of?
    pub(crate) request_chunk_count: usize,
    /// The index of the first chunk used in the current request.
    pub(crate) request_chunk_request_index: usize,
    /// Used to buffer a line of inbound data when buffering cannot be avoided.
    pub(crate) request_buf: Bstr,
    /// Stores the current value of a folded request header. Such headers span
    /// multiple lines, and are processed only when all data is available.
    pub(crate) request_header: Option<Bstr>,
    /// The request body length declared in a valid request header. The key here
    /// is "valid". This field will not be populated if the request contains both
    /// a Transfer-Encoding header and a Content-Length header.
    pub(crate) request_content_length: Option<u64>,
    /// Holds the remaining request body length that we expect to read. This
    /// field will be available only when the length of a request body is known
    /// in advance, i.e. when request headers contain a Content-Length header.
    pub(crate) request_body_data_left: Option<u64>,
    /// Holds the amount of data that needs to be read from the
    /// current data chunk. Only used with chunked request bodies.
    pub(crate) request_chunked_length: Option<u64>,
    /// Current request parser state.
    pub(crate) request_state: State,
    /// Previous request parser state. Used to detect state changes.
    pub(crate) request_state_previous: State,
    /// The hook that should be receiving raw connection data.
    pub(crate) request_data_receiver_hook: Option<DataHook>,

    // Response parser fields
    /// The time when the last response data chunk was received.
    pub(crate) response_timestamp: OffsetDateTime,
    /// How many bytes from the last input chunk have we consumed
    /// This is mostly used from callbacks, where the caller
    /// wants to know how far into the last chunk the parser is.
    pub(crate) response_bytes_consumed: usize,
    /// Used to buffer a line of outbound data when buffering cannot be avoided.
    pub(crate) response_buf: Bstr,
    /// Stores the current value of a folded response header. Such headers span
    /// multiple lines, and are processed only when all data is available.
    pub(crate) response_header: Option<Bstr>,
    /// The length of the current response body as presented in the
    /// Content-Length response header.
    pub(crate) response_content_length: Option<u64>,
    /// The remaining length of the current response body, if known. Set to None otherwise.
    pub(crate) response_body_data_left: Option<u64>,
    /// Holds the amount of data that needs to be read from the
    /// current response data chunk. Only used with chunked response bodies.
    pub(crate) response_chunked_length: Option<u64>,
    /// Current response parser state.
    pub(crate) response_state: State,
    /// Previous response parser state.
    pub(crate) response_state_previous: State,
    /// The hook that should be receiving raw connection data.
    pub(crate) response_data_receiver_hook: Option<DataHook>,

    /// Transactions processed by this parser
    transactions: Transactions,
}

impl std::fmt::Debug for ConnectionParser {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("ConnectionParser")
            .field("request_status", &self.request_status)
            .field("response_status", &self.response_status)
            .field("request_index", &self.request_index())
            .field("response_index", &self.response_index())
            .finish()
    }
}

impl ConnectionParser {
    /// Creates a new ConnectionParser with a preconfigured `Config` struct.
    pub(crate) fn new(cfg: &'static Config) -> Self {
        let conn = Connection::default();
        let logger = Logger::new(conn.get_sender());
        Self {
            logger: logger.clone(),
            cfg,
            conn,
            user_data: None,
            request_status: HtpStreamState::NEW,
            response_status: HtpStreamState::NEW,
            response_data_other_at_tx_end: false,
            request_timestamp: OffsetDateTime::from(SystemTime::now()),
            request_bytes_consumed: 0,
            request_chunk_count: 0,
            request_chunk_request_index: 0,
            request_buf: Bstr::new(),
            request_header: None,
            request_content_length: None,
            request_body_data_left: None,
            request_chunked_length: None,
            request_state: State::Idle,
            request_state_previous: State::None,
            request_data_receiver_hook: None,
            response_timestamp: OffsetDateTime::from(SystemTime::now()),
            response_bytes_consumed: 0,
            response_buf: Bstr::new(),
            response_header: None,
            response_content_length: None,
            response_body_data_left: None,
            response_chunked_length: None,
            response_state: State::Idle,
            response_state_previous: State::None,
            response_data_receiver_hook: None,
            transactions: Transactions::new(cfg, &logger),
        }
    }

    /// Get the current request transaction
    pub(crate) fn request(&mut self) -> Option<&Transaction> {
        self.transactions.request()
    }

    /// Get the current request transaction
    pub(crate) fn request_mut(&mut self) -> Option<&mut Transaction> {
        self.transactions.request_mut()
    }

    /// Get the current response transaction
    pub(crate) fn response(&mut self) -> Option<&Transaction> {
        self.transactions.response()
    }

    /// Get the current response transaction
    pub(crate) fn response_mut(&mut self) -> Option<&mut Transaction> {
        self.transactions.response_mut()
    }

    /// Advance to the next request
    /// Returns the next request transaction id
    pub(crate) fn request_next(&mut self) -> usize {
        // Detect pipelining.
        if self.transactions.request_index() > self.transactions.response_index() {
            self.conn.flags.set(ConnectionFlags::PIPELINED)
        }
        self.transactions.request_next()
    }

    /// Advance to the next response
    /// Returns the next response transaction id
    pub(crate) fn response_next(&mut self) -> usize {
        self.transactions.response_next()
    }

    /// Get the index of the request transaction
    pub(crate) fn request_index(&self) -> usize {
        self.transactions.request_index()
    }

    /// Get the index of the response transaction
    pub(crate) fn response_index(&self) -> usize {
        self.transactions.response_index()
    }

    /// Get the number of transactions processed up to now
    pub(crate) fn tx_size(&self) -> usize {
        self.transactions.size()
    }

    /// Get a specific transaction
    pub(crate) fn tx(&self, index: usize) -> Option<&Transaction> {
        self.transactions.get(index)
    }

    /// Get a specific transaction by its index
    pub(crate) fn tx_index(&mut self, index: usize) -> Option<&mut Transaction> {
        self.transactions.get_index(index)
    }

    /// Get a specific transaction
    pub(crate) fn tx_mut(&mut self, index: usize) -> Option<&mut Transaction> {
        self.transactions.get_mut(index)
    }

    /// Handle the current state to be processed.
    pub(crate) fn handle_request_state(&mut self, data: &mut ParserData) -> Result<()> {
        match self.request_state {
            State::None => Err(HtpStatus::ERROR),
            State::Idle => self.request_idle(data),
            State::IgnoreDataAfterHTTP09 => self.request_ignore_data_after_http_0_9(data),
            State::Line => self.request_line(data),
            State::Protocol => self.request_protocol(data),
            State::Headers => self.request_headers(data),
            State::ConnectWaitResponse => self.request_connect_wait_response(),
            State::ConnectCheck => self.request_connect_check(),
            State::ConnectProbeData => self.request_connect_probe_data(data),
            State::BodyDetermine => self.request_body_determine(),
            State::BodyChunkedData => self.request_body_chunked_data(data),
            State::BodyChunkedLength => self.request_body_chunked_length(data),
            State::BodyChunkedDataEnd => self.request_body_chunked_data_end(data),
            State::BodyIdentity => self.request_body_identity(data),
            State::Finalize => self.request_finalize(data),
            // These are only used by response_state
            _ => Err(HtpStatus::ERROR),
        }
    }

    /// Handle the current state to be processed.
    pub(crate) fn handle_response_state(&mut self, data: &mut ParserData) -> Result<()> {
        match self.response_state {
            State::None => Err(HtpStatus::ERROR),
            State::Idle => self.response_idle(data),
            State::Line => self.response_line(data),
            State::Headers => self.response_headers(data),
            State::BodyDetermine => self.response_body_determine(data),
            State::BodyChunkedData => self.response_body_chunked_data(data),
            State::BodyChunkedLength => self.response_body_chunked_length(data),
            State::BodyChunkedDataEnd => self.response_body_chunked_data_end(data),
            State::Finalize => self.response_finalize(data),
            State::BodyIdentityStreamClose => self.response_body_identity_stream_close(data),
            State::BodyIdentityCLKnown => self.response_body_identity_cl_known(data),
            // These are only used by request_state
            _ => Err(HtpStatus::ERROR),
        }
    }

    /// Closes the connection associated with the supplied parser.
    pub(crate) fn request_close(&mut self, timestamp: Option<OffsetDateTime>) {
        // Update internal flags
        if self.request_status != HtpStreamState::ERROR {
            self.request_status = HtpStreamState::CLOSED
        }
        // Call the parsers one last time, which will allow them
        // to process the events that depend on stream closure
        self.request_data(ParserData::default(), timestamp);
    }

    /// Closes the connection associated with the supplied parser.
    pub(crate) fn close(&mut self, timestamp: Option<OffsetDateTime>) {
        // Close the underlying connection.
        self.conn.close(timestamp);
        // Update internal flags
        if self.request_status != HtpStreamState::ERROR {
            self.request_status = HtpStreamState::CLOSED
        }
        if self.response_status != HtpStreamState::ERROR {
            self.response_status = HtpStreamState::CLOSED
        }
        // Call the parsers one last time, which will allow them
        // to process the events that depend on stream closure
        self.request_data(ParserData::default(), timestamp);
        self.response_data(ParserData::default(), timestamp);
    }

    /// This function is most likely not used and/or not needed.
    pub(crate) fn request_reset(&mut self) {
        self.request_content_length = None;
        self.request_body_data_left = None;
        self.request_chunk_request_index = self.request_chunk_count;
    }

    /// Returns the number of bytes consumed from the current data chunks so far.
    pub(crate) fn request_data_consumed(&self) -> usize {
        self.request_bytes_consumed
    }

    /// Consume the given number of bytes from the ParserData and update
    /// the internal counter for how many bytes consumed so far.
    pub(crate) fn request_data_consume(&mut self, input: &ParserData, consumed: usize) {
        input.consume(consumed);
        self.request_bytes_consumed = input.consumed_len();
    }

    /// Unconsume the given number of bytes from the ParserData and update the
    /// the internal counter for how many bytes are consumed.
    /// If the requested number of bytes is larger than the number of bytes
    /// already consumed then the parser will be unwound to the beginning.
    pub(crate) fn request_data_unconsume(&mut self, input: &mut ParserData, unconsume: usize) {
        input.unconsume(unconsume);
        self.request_bytes_consumed = input.consumed_len();
    }

    /// Consume the given number of bytes from the ParserData and update
    /// the internal counter for how many bytes consumed so far.
    pub(crate) fn response_data_consume(&mut self, input: &ParserData, consumed: usize) {
        input.consume(consumed);
        self.response_bytes_consumed = input.consumed_len();
    }

    /// Unconsume the given number of bytes from the ParserData and update the
    /// the internal counter for how many bytes are consumed.
    /// If the requested number of bytes is larger than the number of bytes
    /// already consumed then the parser will be unwound to the beginning.
    pub(crate) fn response_data_unconsume(&mut self, input: &mut ParserData, unconsume: usize) {
        input.unconsume(unconsume);
        self.response_bytes_consumed = input.consumed_len();
    }

    /// Returns the number of bytes consumed from the most recent outbound data chunk. Normally, an invocation
    /// of response_data() will consume all data from the supplied buffer, but there are circumstances
    /// where only partial consumption is possible. In such cases DATA_OTHER will be returned.
    /// Consumed bytes are no longer necessary, but the remainder of the buffer will be saved
    /// for later.
    pub(crate) fn response_data_consumed(&self) -> usize {
        self.response_bytes_consumed
    }

    /// Opens connection.
    pub(crate) fn open(
        &mut self, client_addr: Option<IpAddr>, client_port: Option<u16>,
        server_addr: Option<IpAddr>, server_port: Option<u16>, timestamp: Option<OffsetDateTime>,
    ) {
        // Check connection parser state first.
        if self.request_status != HtpStreamState::NEW || self.response_status != HtpStreamState::NEW
        {
            htp_error!(
                self.logger,
                HtpLogCode::CONNECTION_ALREADY_OPEN,
                "Connection is already open"
            );
            return;
        }
        self.conn.open(
            client_addr,
            client_port,
            server_addr,
            server_port,
            timestamp,
        );
        self.request_status = HtpStreamState::OPEN;
        self.response_status = HtpStreamState::OPEN;
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

    /// Initialize request parsing, change state to LINE,
    /// and invoke all registered callbacks.
    ///
    /// Returns HtpStatus::OK on success; HtpStatus::ERROR on error, HtpStatus::STOP if one of the
    /// callbacks does not want to follow the transaction any more.
    pub(crate) fn state_request_start(&mut self) -> Result<()> {
        // Change state into request line parsing.
        self.request_state = State::Line;
        let req = self.request_mut();
        if req.is_none() {
            return Err(HtpStatus::ERROR);
        }
        req.unwrap().request_progress = HtpRequestProgress::LINE;
        // Run hook REQUEST_START.
        self.cfg
            .hook_request_start
            .clone()
            .run_all(self, self.request_index())?;
        Ok(())
    }

    /// Change transaction state to HEADERS and invoke all
    /// registered callbacks.
    ///
    /// Returns HtpStatus::OK on success; HtpStatus::ERROR on error, HtpStatus::STOP if one of the
    /// callbacks does not want to follow the transaction any more.
    pub(crate) fn state_request_headers(&mut self, input: &mut ParserData) -> Result<()> {
        // Finalize sending raw header data
        self.request_receiver_finalize_clear(input)?;
        // If we're in HTP_REQ_HEADERS that means that this is the
        // first time we're processing headers in a request. Otherwise,
        // we're dealing with trailing headers.
        let req = self.request();
        if req.is_none() {
            return Err(HtpStatus::ERROR);
        }
        let request_progress = req.unwrap().request_progress;
        if request_progress > HtpRequestProgress::HEADERS {
            // Request trailers.
            // Run hook HTP_REQUEST_TRAILER.
            self.cfg
                .hook_request_trailer
                .clone()
                .run_all(self, self.request_index())?;
            // Completed parsing this request; finalize it now.
            self.request_state = State::Finalize;
        } else if request_progress >= HtpRequestProgress::LINE {
            // Request headers.
            // Did this request arrive in multiple data chunks?
            let req = self.transactions.request_mut().unwrap();
            if self.request_chunk_count != self.request_chunk_request_index {
                req.flags.set(HtpFlags::MULTI_PACKET_HEAD)
            }
            req.process_request_headers()?;
            // Run hook REQUEST_HEADERS.
            #[cfg(test)]
            self.cfg
                .hook_request_headers
                .clone()
                .run_all(self, self.request_index())?;
            self.request_initialize_decompressors()?;

            // We still proceed if the request is invalid.
            self.request_state = State::ConnectCheck;
        } else {
            htp_warn!(
                self.logger,
                HtpLogCode::RESPONSE_BODY_INTERNAL_ERROR,
                format!(
                    "[Internal Error] Invalid tx progress: {:?}",
                    request_progress
                )
            );
            return Err(HtpStatus::ERROR);
        }
        Ok(())
    }

    /// Change transaction state to PROTOCOL and invoke all
    /// registered callbacks.
    ///
    /// Returns HtpStatus::OK on success; HtpStatus::ERROR on error, HtpStatus::STOP if one of the
    /// callbacks does not want to follow the transaction any more.
    pub(crate) fn state_request_line(&mut self) -> Result<()> {
        let req = self.request_mut();
        if req.is_none() {
            return Err(HtpStatus::ERROR);
        }
        req.unwrap().parse_request_line()?;
        // Run hook REQUEST_LINE.
        self.cfg
            .hook_request_line
            .clone()
            .run_all(self, self.request_index())?;
        let logger = self.logger.clone();
        let req = self.request_mut().unwrap();
        if let Some(parsed_uri) = req.parsed_uri.as_mut() {
            let (partial_normalized_uri, complete_normalized_uri) =
                parsed_uri.generate_normalized_uri(Some(logger));
            req.partial_normalized_uri = partial_normalized_uri;
            req.complete_normalized_uri = complete_normalized_uri;
        }
        // Move on to the next phase.
        self.request_state = State::Protocol;
        Ok(())
    }

    /// Advance state after processing request headers.
    ///
    /// Returns HtpStatus::OK on success; HtpStatus::ERROR on error, HtpStatus::STOP
    /// if one of the callbacks does not want to follow the transaction any more.
    pub(crate) fn state_request_complete(&mut self, input: &mut ParserData) -> Result<()> {
        let req = self.request_mut();
        if req.is_none() {
            return Err(HtpStatus::ERROR);
        }
        let req = req.unwrap();
        if req.request_progress != HtpRequestProgress::COMPLETE {
            // Finalize request body.
            if req.request_has_body() {
                self.request_body_data(None)?;
            }
            self.request_mut().unwrap().request_progress = HtpRequestProgress::COMPLETE;
            // Run hook REQUEST_COMPLETE.
            self.cfg
                .hook_request_complete
                .clone()
                .run_all(self, self.request_index())?;

            // Clear request data
            self.request_receiver_finalize_clear(input)?;
        }
        // Determine what happens next, and remove this transaction from the parser.
        self.request_state = if self.request().unwrap().is_protocol_0_9 {
            State::IgnoreDataAfterHTTP09
        } else {
            State::Idle
        };
        // Check if the entire transaction is complete.
        self.finalize(self.request_index())?;
        self.request_next();
        Ok(())
    }

    /// Determine if the transaction is complete and run any hooks.
    fn finalize(&mut self, _tx_index: usize) -> Result<()> {
        #[cfg(test)]
        if let Some(tx) = self.tx(_tx_index) {
            if !tx.is_complete() {
                return Ok(());
            }
            // Disconnect transaction from the parser.
            // Run hook TRANSACTION_COMPLETE.
            self.cfg
                .hook_transaction_complete
                .clone()
                .run_all(self, _tx_index)?;
        }
        Ok(())
    }

    /// Advance state to LINE, or BODY if http version is 0.9.
    ///
    /// Returns HtpStatus::OK on success; HtpStatus::ERROR on error, HtpStatus::STOP
    /// if one of the callbacks does not want to follow the transaction any more.
    pub(crate) fn state_response_start(&mut self) -> Result<()> {
        // Change state into response line parsing, except if we're following
        // a HTTP/0.9 request (no status line or response headers).
        let tx = self.response_mut();
        if tx.is_none() {
            return Err(HtpStatus::ERROR);
        }
        let tx = tx.unwrap();

        if tx.is_protocol_0_9 {
            tx.response_transfer_coding = HtpTransferCoding::Identity;
            tx.response_content_encoding_processing = HtpContentEncoding::None;
            tx.response_progress = HtpResponseProgress::BODY;
            self.response_state = State::BodyIdentityStreamClose;
            self.response_body_data_left = None
        } else {
            tx.response_progress = HtpResponseProgress::LINE;
            self.response_state = State::Line
        }
        // Run hook RESPONSE_START.
        self.cfg
            .hook_response_start
            .clone()
            .run_all(self, self.response_index())?;
        // If at this point we have no method and no uri and our status
        // is still REQ_LINE, we likely have timed out request
        // or a overly long request
        let tx = self.response_mut().unwrap();
        if tx.request_method.is_none()
            && tx.request_uri.is_none()
            && self.request_state == State::Line
        {
            htp_warn!(
                self.logger,
                HtpLogCode::REQUEST_LINE_INCOMPLETE,
                "Request line incomplete"
            );
        }
        Ok(())
    }

    /// Advance state after processing response headers.
    ///
    /// Returns HtpStatus::OK on success; HtpStatus::ERROR on error, HtpStatus::STOP
    /// if one of the callbacks does not want to follow the transaction any more.
    pub(crate) fn state_response_headers(&mut self, input: &mut ParserData) -> Result<()> {
        // Finalize sending raw header data.
        self.response_receiver_finalize_clear(input)?;
        // Run hook RESPONSE_HEADERS.
        #[cfg(test)]
        self.cfg
            .hook_response_headers
            .clone()
            .run_all(self, self.response_index())?;
        self.response_initialize_decompressors()
    }

    /// Change transaction state to RESPONSE_LINE and invoke registered callbacks.
    ///
    /// Returns HtpStatus::OK on success; HtpStatus::ERROR on error, HtpStatus::STOP
    /// if one of the callbacks does not want to follow the transaction any more.
    pub(crate) fn state_response_line(&mut self) -> Result<()> {
        // Is the response line valid?
        let tx = self.response_mut();
        if tx.is_none() {
            return Err(HtpStatus::ERROR);
        }
        let tx = tx.unwrap();

        tx.validate_response_line();
        #[cfg(test)]
        let index = tx.index;
        // Run hook HTP_RESPONSE_LINE
        #[cfg(test)]
        return self.cfg.hook_response_line.clone().run_all(self, index);
        #[cfg(not(test))]
        return Ok(());
    }

    /// Change transaction state to COMPLETE and invoke registered callbacks.
    ///
    /// Returns HtpStatus::OK on success; HtpStatus::ERROR on error, HtpStatus::STOP
    /// if one of the callbacks does not want to follow the transaction any more.
    pub(crate) fn state_response_complete(&mut self, input: &mut ParserData) -> Result<()> {
        let response_index = self.response_index();
        let tx = self.response_mut();
        if tx.is_none() {
            return Err(HtpStatus::ERROR);
        }
        let tx = tx.unwrap();
        if tx.response_progress != HtpResponseProgress::COMPLETE {
            tx.response_progress = HtpResponseProgress::COMPLETE;
            // Run the last RESPONSE_BODY_DATA HOOK, but only if there was a response body present.
            if tx.response_transfer_coding != HtpTransferCoding::NoBody {
                let _ = self.response_body_data(None);
            }
            // Run hook RESPONSE_COMPLETE.
            self.cfg
                .hook_response_complete
                .clone()
                .run_all(self, response_index)?;

            // Clear the data receivers hook if any
            self.response_receiver_finalize_clear(input)?;
        }
        // Check if we want to signal the caller to send request data
        self.request_parser_check_waiting()?;
        // Otherwise finalize the transaction
        self.finalize(response_index)?;
        self.response_next();
        self.response_state = State::Idle;
        Ok(())
    }

    /// Check if we had previously signalled the caller to give us response
    /// data, and now we are ready to receive it
    fn request_parser_check_waiting(&mut self) -> Result<()> {
        // Check if the inbound parser is waiting on us. If it is, that means that
        // there might be request data that the inbound parser hasn't consumed yet.
        // If we don't stop parsing we might encounter a response without a request,
        // which is why we want to return straight away before processing any data.
        //
        // This situation will occur any time the parser needs to see the server
        // respond to a particular situation before it can decide how to proceed. For
        // example, when a CONNECT is sent, different paths are used when it is accepted
        // and when it is not accepted.
        //
        // It is not enough to check only in_status here. Because of pipelining, it's possible
        // that many inbound transactions have been processed, and that the parser is
        // waiting on a response that we have not seen yet.
        if self.response_status == HtpStreamState::DATA_OTHER
            && self.response_index() == self.request_index()
        {
            return Err(HtpStatus::DATA_OTHER);
        }

        // Do we have a signal to yield to inbound processing at
        // the end of the next transaction?
        if self.response_data_other_at_tx_end {
            // We do. Let's yield then.
            self.response_data_other_at_tx_end = false;
            if self.response_index() == self.request_index() {
                return Err(HtpStatus::DATA_OTHER);
            }
        }
        Ok(())
    }

    /// Remove the given transaction from the parser
    pub(crate) fn remove_tx(&mut self, tx_id: usize) {
        self.transactions.remove(tx_id);
    }
}
