use crate::{
    bstr::Bstr,
    config::{HtpServerPersonality, HtpUnwanted},
    connection::ConnectionFlags,
    connection_parser::{ConnectionParser, HtpStreamState, ParserData, State},
    decompressors::{Decompressor, HtpContentEncoding},
    error::Result,
    headers::HeaderFlags,
    hook::DataHook,
    parsers::{parse_chunked_length, parse_content_length, parse_protocol},
    transaction::{
        Data, Header, HtpProtocol, HtpRequestProgress, HtpResponseProgress, HtpTransferCoding,
    },
    util::{
        chomp, is_line_ignorable, is_space, is_valid_chunked_length_data, split_on_predicate,
        take_is_space, take_not_is_space, take_till_lf, take_till_lf_null, take_until_null,
        trimmed, FlagOperations, HtpFlags,
    },
    HtpStatus,
};
use nom::sequence::tuple;
use std::{
    cmp::{min, Ordering},
    mem::take,
};
use time::OffsetDateTime;

/// Enumerate HTTP methods.
#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum HtpMethod {
    /// Used by default, until the method is determined (e.g., before
    /// the request line is processed.
    UNKNOWN,
    /// HEAD
    HEAD,
    /// GET
    GET,
    /// PUT
    PUT,
    /// POST
    POST,
    /// DELETE
    DELETE,
    /// CONNECT
    CONNECT,
    /// OPTIONS
    OPTIONS,
    /// TRACE
    TRACE,
    /// PATCH
    PATCH,
    /// PROPFIND
    PROPFIND,
    /// PROPPATCH
    PROPPATCH,
    /// MKCOL
    MKCOL,
    /// COPY
    COPY,
    /// MOVE
    MOVE,
    /// LOCK
    LOCK,
    /// UNLOCK
    UNLOCK,
    /// VERSION_CONTROL
    VERSION_CONTROL,
    /// CHECKOUT
    CHECKOUT,
    /// UNCHECKOUT
    UNCHECKOUT,
    /// CHECKIN
    CHECKIN,
    /// UPDATE
    UPDATE,
    /// LABEL
    LABEL,
    /// REPORT
    REPORT,
    /// MKWORKSPACE
    MKWORKSPACE,
    /// MKACTIVITY
    MKACTIVITY,
    /// BASELINE_CONTROL
    BASELINE_CONTROL,
    /// MERGE
    MERGE,
    /// INVALID
    INVALID,
    /// ERROR
    ERROR,
}

impl HtpMethod {
    /// Creates a new HtpMethod from the slice.
    fn new(method: &[u8]) -> Self {
        match method {
            b"GET" => HtpMethod::GET,
            b"PUT" => HtpMethod::PUT,
            b"POST" => HtpMethod::POST,
            b"DELETE" => HtpMethod::DELETE,
            b"CONNECT" => HtpMethod::CONNECT,
            b"OPTIONS" => HtpMethod::OPTIONS,
            b"TRACE" => HtpMethod::TRACE,
            b"PATCH" => HtpMethod::PATCH,
            b"PROPFIND" => HtpMethod::PROPFIND,
            b"PROPPATCH" => HtpMethod::PROPPATCH,
            b"MKCOL" => HtpMethod::MKCOL,
            b"COPY" => HtpMethod::COPY,
            b"MOVE" => HtpMethod::MOVE,
            b"LOCK" => HtpMethod::LOCK,
            b"UNLOCK" => HtpMethod::UNLOCK,
            b"VERSION-CONTROL" => HtpMethod::VERSION_CONTROL,
            b"CHECKOUT" => HtpMethod::CHECKOUT,
            b"UNCHECKOUT" => HtpMethod::UNCHECKOUT,
            b"CHECKIN" => HtpMethod::CHECKIN,
            b"UPDATE" => HtpMethod::UPDATE,
            b"LABEL" => HtpMethod::LABEL,
            b"REPORT" => HtpMethod::REPORT,
            b"MKWORKSPACE" => HtpMethod::MKWORKSPACE,
            b"MKACTIVITY" => HtpMethod::MKACTIVITY,
            b"BASELINE-CONTROL" => HtpMethod::BASELINE_CONTROL,
            b"MERGE" => HtpMethod::MERGE,
            b"INVALID" => HtpMethod::INVALID,
            b"HEAD" => HtpMethod::HEAD,
            _ => HtpMethod::UNKNOWN,
        }
    }
}
impl ConnectionParser {
    /// Sends outstanding connection data to the currently active data receiver hook.
    fn request_receiver_send_data(&mut self, data: &mut ParserData) -> Result<()> {
        let data = ParserData::from(data.callback_data());
        let req = self.request_mut();
        if req.is_none() {
            return Err(HtpStatus::ERROR);
        }
        let mut tx_data = Data::new(req.unwrap(), &data);
        if let Some(hook) = &self.request_data_receiver_hook {
            hook.run_all(self, &mut tx_data)?;
        } else {
            return Ok(());
        };
        Ok(())
    }

    /// Configures the data receiver hook.
    fn request_receiver_set(&mut self, data_receiver_hook: Option<DataHook>) -> Result<()> {
        self.request_data_receiver_hook = data_receiver_hook;
        Ok(())
    }

    /// Finalizes an existing data receiver hook by sending any outstanding data to it. The
    /// hook is then removed so that it receives no more data.
    pub fn request_receiver_finalize_clear(&mut self, input: &mut ParserData) -> Result<()> {
        if self.request_data_receiver_hook.is_none() {
            return Ok(());
        }
        let rc = self.request_receiver_send_data(input);
        self.request_data_receiver_hook = None;
        rc
    }

    /// Handles request parser state changes. At the moment, this function is used only
    /// to configure data receivers, which are sent raw connection data.
    fn request_handle_state_change(&mut self, input: &mut ParserData) -> Result<()> {
        if self.request_state_previous == self.request_state {
            return Ok(());
        }

        if self.request_state == State::HEADERS {
            // ensured by caller
            let req = self.request().unwrap();
            let header_fn = Some(req.cfg.hook_request_header_data.clone());
            let trailer_fn = Some(req.cfg.hook_request_trailer_data.clone());
            input.reset_callback_start();

            match req.request_progress {
                HtpRequestProgress::HEADERS => self.request_receiver_set(header_fn),
                HtpRequestProgress::TRAILER => self.request_receiver_set(trailer_fn),
                _ => Ok(()),
            }?;
        }
        // Initially, I had the finalization of raw data sending here, but that
        // caused the last REQUEST_HEADER_DATA hook to be invoked after the
        // REQUEST_HEADERS hook -- which I thought made no sense. For that reason,
        // the finalization is now initiated from the request header processing code,
        // which is less elegant but provides a better user experience. Having some
        // (or all) hooks to be invoked on state change might work better.
        self.request_state_previous = self.request_state;
        Ok(())
    }

    /// If there is any data left in the inbound data chunk, this function will preserve
    /// it for later consumption. The maximum amount accepted for buffering is controlled
    /// by Config::field_limit.
    fn check_request_buffer_limit(&mut self, len: usize) -> Result<()> {
        if len == 0 {
            return Ok(());
        }
        // Check the hard (buffering) limit.
        let mut newlen: usize = self.request_buf.len().wrapping_add(len);
        // When calculating the size of the buffer, take into account the
        // space we're using for the request header buffer.
        if let Some(header) = &self.request_header {
            newlen = newlen.wrapping_add(header.len())
        }
        let field_limit = self.cfg.field_limit;
        if newlen > field_limit {
            htp_error!(
                self.logger,
                HtpLogCode::REQUEST_FIELD_TOO_LONG,
                format!(
                    "Request buffer over the limit: size {} limit {}.",
                    newlen, field_limit
                )
            );
            return Err(HtpStatus::ERROR);
        }
        Ok(())
    }

    /// Performs a check for a CONNECT transaction to decide whether inbound
    /// parsing needs to be suspended.
    ///
    /// Returns OK if the request does not use CONNECT, or HtpStatus::DATA_OTHER if
    /// inbound parsing needs to be suspended until we hear from the
    /// other side.
    pub fn request_connect_check(&mut self) -> Result<()> {
        let req = self.request();
        if req.is_none() {
            return Err(HtpStatus::ERROR);
        }

        // If the request uses the CONNECT method, then there will
        // not be a request body, but first we need to wait to see the
        // response in order to determine if the tunneling request
        // was a success.
        if req.unwrap().request_method_number == HtpMethod::CONNECT {
            self.request_state = State::CONNECT_WAIT_RESPONSE;
            self.request_status = HtpStreamState::DATA_OTHER;
            return Err(HtpStatus::DATA_OTHER);
        }
        // Continue to the next step to determine
        // the presence of request body
        self.request_state = State::BODY_DETERMINE;
        Ok(())
    }

    /// Determines whether inbound parsing needs to continue or stop. In
    /// case the data appears to be plain text HTTP, we try to continue.
    ///
    /// Returns OK if the parser can resume parsing, HtpStatus::DATA_BUFFER if
    /// we need more data.
    pub fn request_connect_probe_data(&mut self, input: &mut ParserData) -> Result<()> {
        let data = if let Ok((_, data)) = take_till_lf_null(input.as_slice()) {
            data
        } else {
            return self.handle_request_absent_lf(input);
        };

        if !self.request_buf.is_empty() {
            self.check_request_buffer_limit(data.len())?;
        }
        // copy, will still need buffer data for next state.
        let mut buffered = self.request_buf.clone();
        buffered.add(data);

        // The request method starts at the beginning of the
        // line and ends with the first whitespace character.
        // We skip leading whitespace as IIS allows this.
        let res = tuple((take_is_space, take_not_is_space))(buffered.as_slice());
        if let Ok((_, (_, method))) = res {
            if HtpMethod::new(method) == HtpMethod::UNKNOWN {
                self.request_status = HtpStreamState::TUNNEL;
                self.response_status = HtpStreamState::TUNNEL
            } else {
                return self.state_request_complete(input);
            }
        };
        Ok(())
    }

    /// Determines whether inbound parsing, which was suspended after
    /// encountering a CONNECT transaction, can proceed (after receiving
    /// the response).
    ///
    /// Returns OK if the parser can resume parsing, HtpStatus::DATA_OTHER if
    /// it needs to continue waiting.
    pub fn request_connect_wait_response(&mut self) -> Result<()> {
        let req = self.request();
        if req.is_none() {
            return Err(HtpStatus::ERROR);
        }
        let req = req.unwrap();

        // Check that we saw the response line of the current inbound transaction.
        if req.response_progress <= HtpResponseProgress::LINE {
            return Err(HtpStatus::DATA_OTHER);
        }
        // A 2xx response means a tunnel was established. Anything
        // else means we continue to follow the HTTP stream.
        if req.response_status_number.in_range(200, 299) {
            // TODO Check that the server did not accept a connection to itself.
            // The requested tunnel was established: we are going
            // to probe the remaining data on this stream to see
            // if we need to ignore it or parse it
            self.request_state = State::CONNECT_PROBE_DATA;
        } else {
            // No tunnel; continue to the next transaction
            self.request_state = State::FINALIZE
        }
        Ok(())
    }

    /// Consumes bytes until the end of the current line.
    ///
    /// Returns OK on state change, ERROR on error, or HtpStatus::DATA_BUFFER
    /// when more data is needed.
    pub fn request_body_chunked_data_end(&mut self, input: &mut ParserData) -> Result<()> {
        let req = self.request_mut();
        if req.is_none() {
            return Err(HtpStatus::ERROR);
        }
        let req = req.unwrap();

        // TODO We shouldn't really see anything apart from CR and LF,
        //      so we should warn about anything else.
        if let Ok((_, line)) = take_till_lf(input.as_slice()) {
            let len = line.len();
            req.request_message_len = req.request_message_len.wrapping_add(len as u64);
            self.request_data_consume(input, len);
            self.request_state = State::BODY_CHUNKED_LENGTH;
            Ok(())
        } else {
            req.request_message_len = req.request_message_len.wrapping_add(input.len() as u64);
            self.handle_request_absent_lf(input)
        }
    }

    /// Processes a chunk of data.
    ///
    /// Returns OK on state change, ERROR on error, or HtpStatus::DATA_BUFFER
    /// when more data is needed.
    pub fn request_body_chunked_data(&mut self, input: &mut ParserData) -> Result<()> {
        // Determine how many bytes we can consume.
        let bytes_to_consume: usize = min(
            input.len(),
            self.request_chunked_length.unwrap_or(0) as usize,
        );
        // If the input buffer is empty, ask for more data.
        if bytes_to_consume == 0 {
            return Err(HtpStatus::DATA);
        }
        // Consume the data.
        self.request_body_data(Some(&input.as_slice()[0..bytes_to_consume]))?;

        // Adjust counters.
        self.request_data_consume(input, bytes_to_consume);
        if let Some(len) = self.request_chunked_length.as_mut() {
            *len -= bytes_to_consume as u64;
            if *len == 0 {
                // End of the chunk.
                self.request_state = State::BODY_CHUNKED_DATA_END;
                return Ok(());
            }
        }
        // Ask for more data.
        Err(HtpStatus::DATA)
    }

    /// Extracts chunk length.
    /// Returns OK on state change, ERROR on error, or HtpStatus::DATA_BUFFER
    /// when more data is needed.
    pub fn request_body_chunked_length(&mut self, input: &mut ParserData) -> Result<()> {
        let mut data = input.as_slice();
        loop {
            if let Ok((remaining, line)) = take_till_lf(data) {
                self.request_data_consume(input, line.len());
                if !self.request_buf.is_empty() {
                    self.check_request_buffer_limit(line.len())?;
                }
                let req = self.request_mut();
                if req.is_none() {
                    return Err(HtpStatus::ERROR);
                }
                let req = req.unwrap();

                if line.eq(b"\n") {
                    req.request_message_len =
                        req.request_message_len.wrapping_add(line.len() as u64);
                    //Empty chunk len. Try to continue parsing.
                    data = remaining;
                    continue;
                }
                let mut data = self.request_buf.clone();
                data.add(line);
                let req = self.request_mut().unwrap();
                req.request_message_len = req.request_message_len.wrapping_add(data.len() as u64);
                // Handle chunk length.
                let (len, ext) = parse_chunked_length(&data)?;
                self.request_chunked_length = len;
                if ext {
                    htp_warn!(
                        self.logger,
                        HtpLogCode::REQUEST_CHUNK_EXTENSION,
                        "Request chunk extension"
                    );
                }
                let len = len.as_ref().ok_or(HtpStatus::ERROR).map_err(|e| {
                    // Invalid chunk length
                    htp_error!(
                        self.logger,
                        HtpLogCode::INVALID_REQUEST_CHUNK_LEN,
                        "Request chunk encoding: Invalid chunk length"
                    );
                    e
                })?;
                match len.cmp(&0) {
                    Ordering::Equal => {
                        // End of data
                        self.request_state = State::HEADERS;
                        self.request_mut().unwrap().request_progress = HtpRequestProgress::TRAILER
                    }
                    Ordering::Greater => {
                        // More data available.
                        self.request_state = State::BODY_CHUNKED_DATA
                    }
                    _ => {}
                }
                return Ok(());
            } else {
                // Check if the data we have seen so far is invalid
                return if !is_valid_chunked_length_data(data) {
                    // Contains leading junk non hex_ascii data
                    // Invalid chunk length
                    htp_error!(
                        self.logger,
                        HtpLogCode::INVALID_REQUEST_CHUNK_LEN,
                        "Request chunk encoding: Invalid chunk length"
                    );
                    Err(HtpStatus::ERROR)
                } else {
                    self.handle_request_absent_lf(input)
                };
            }
        }
    }

    /// Processes identity request body.
    ///
    /// Returns OK on state change, ERROR on error, or HtpStatus::DATA_BUFFER
    /// when more data is needed.
    pub fn request_body_identity(&mut self, data: &mut ParserData) -> Result<()> {
        let left = self.request_body_data_left.ok_or(HtpStatus::ERROR)?;
        // Determine how many bytes we can consume.
        let bytes_to_consume: usize = min(data.len(), left as usize);
        // If the input buffer is empty, ask for more data.
        if bytes_to_consume == 0 {
            return Err(HtpStatus::DATA);
        }
        if data.is_gap() {
            let req = self.request_mut();
            if req.is_none() {
                return Err(HtpStatus::ERROR);
            }
            let req = req.unwrap();
            req.request_message_len = req
                .request_message_len
                .wrapping_add(bytes_to_consume as u64);
            // Create a new gap of the appropriate length
            let parser_data = ParserData::from(bytes_to_consume);
            // Send the gap to the data hooks
            let mut tx_data = Data::new(req, &parser_data);
            self.request_run_hook_body_data(&mut tx_data)?;
        } else {
            // Consume the data.
            self.request_body_data(Some(&data.as_slice()[0..bytes_to_consume]))?;
        }

        // Adjust the counters.
        self.request_data_consume(data, bytes_to_consume);
        self.request_body_data_left = Some(left - bytes_to_consume as u64);

        // Have we seen the entire request body?
        if self.request_body_data_left > Some(0) {
            //Ask for more data;
            return Err(HtpStatus::DATA);
        }
        // End of request body.
        self.request_state = State::FINALIZE;
        // Sends close signal to decompressors, outputting any partially decompressed data
        self.request_body_data(None)
    }

    /// Determines presence (and encoding) of a request body.
    ///
    /// Returns OK on state change, ERROR on error, or HtpStatus::DATA_BUFFER
    /// when more data is needed.
    pub fn request_body_determine(&mut self) -> Result<()> {
        let req = self.request_mut();
        if req.is_none() {
            return Err(HtpStatus::ERROR);
        }
        let req = req.unwrap();

        // Determine the next state based on the presence of the request
        // body, and the coding used.
        match req.request_transfer_coding {
            HtpTransferCoding::CHUNKED => {
                req.request_progress = HtpRequestProgress::BODY;
                self.request_state = State::BODY_CHUNKED_LENGTH
            }
            HtpTransferCoding::IDENTITY => {
                if req.request_content_length > Some(0) {
                    req.request_progress = HtpRequestProgress::BODY;
                }
                self.request_content_length = req.request_content_length;
                self.request_body_data_left = self.request_content_length;
                if self.request_content_length > Some(0) {
                    self.request_state = State::BODY_IDENTITY
                } else {
                    self.request_state = State::FINALIZE
                }
            }
            HtpTransferCoding::NO_BODY => {
                // This request does not have a body, which
                // means that we're done with it
                self.request_state = State::FINALIZE
            }
            _ => {
                // Should not be here
                return Err(HtpStatus::ERROR);
            }
        }
        Ok(())
    }

    /// Parses request headers.
    /// Returns OK on state change, ERROR on error, or HtpStatus::DATA_BUFFER
    /// when more data is needed.
    pub fn request_headers(&mut self, input: &mut ParserData) -> Result<()> {
        let data = input.as_slice();
        if self.request_status == HtpStreamState::CLOSED {
            let req = self.request_mut();
            if req.is_none() {
                return Err(HtpStatus::ERROR);
            }
            let req = req.unwrap();

            req.request_header_parser.set_complete(true);
            // Parse previous header, if any.
            req.request_progress = HtpRequestProgress::TRAILER;
            if let Some(request_header) = self.request_header.take() {
                self.parse_request_headers(request_header.as_slice())?;
            }
            self.request_buf.clear();
            // We've seen all the request headers.
            return self.state_request_headers(input);
        }
        let mut taken = false;
        let request_header = if let Some(mut request_header) = self.request_header.take() {
            request_header.add(data);
            taken = true;
            request_header
        } else {
            Bstr::new()
        };
        let data2 = if taken {
            request_header.as_slice()
        } else {
            data
        };

        let (remaining, eoh) = self.parse_request_headers(data2)?;
        //TODO: Update the request state machine so that we don't have to have this EOL check
        let eol = remaining.len() == data2.len()
            && (remaining.starts_with(b"\r\n") || remaining.starts_with(b"\n"));
        if eoh
            //If the input started with an EOL, we assume this is the end of the headers
            || eol
        {
            if remaining.len() < data.len() {
                self.request_data_consume(input, data.len() - remaining.len());
            } else if eol {
                if remaining.starts_with(b"\r\n") {
                    self.request_data_consume(input, min(data.len(), 2));
                } else if remaining.starts_with(b"\n") {
                    self.request_data_consume(input, min(data.len(), 1));
                }
            }
            // We've seen all the request headers.
            self.state_request_headers(input)
        } else {
            self.request_data_consume(input, data.len());
            self.check_request_buffer_limit(remaining.len())?;
            let remaining = Bstr::from(remaining);
            self.request_header.replace(remaining);
            Err(HtpStatus::DATA_BUFFER)
        }
    }

    /// Determines request protocol.
    /// Returns OK on state change, ERROR on error, or HtpStatus::DATA_BUFFER
    /// when more data is needed.
    pub fn request_protocol(&mut self, input: &mut ParserData) -> Result<()> {
        let req = self.request_mut();
        if req.is_none() {
            return Err(HtpStatus::ERROR);
        }
        let req = req.unwrap();

        // Is this a short-style HTTP/0.9 request? If it is,
        // we will not want to parse request headers.
        if !req.is_protocol_0_9 {
            // Switch to request header parsing.
            req.request_progress = HtpRequestProgress::HEADERS;
            self.request_state = State::HEADERS
        } else {
            if let Ok((rem, _)) = take_is_space(input.as_slice()) {
                if !rem.is_empty() {
                    // we have more than spaces, no HTTP/0.9
                    req.is_protocol_0_9 = false;
                    req.request_progress = HtpRequestProgress::HEADERS;
                    htp_warn!(
                        self.logger,
                        HtpLogCode::REQUEST_LINE_NO_PROTOCOL,
                        "Request line: missing protocol"
                    );
                    // Switch to request header parsing.
                    self.request_state = State::HEADERS;
                    return Ok(());
                }
            }
            // We're done with this request.
            self.request_state = State::FINALIZE;
        }
        Ok(())
    }

    /// Parse the request line.
    ///
    /// Returns OK on state change, ERROR on error, or HtpStatus::DATA_BUFFER
    /// when more data is needed.
    fn request_line_complete(&mut self, line: &[u8]) -> Result<()> {
        self.check_request_buffer_limit(line.len())?;
        if line.is_empty() {
            return Err(HtpStatus::DATA);
        }
        let perso = self.cfg.server_personality;
        let req = self.request_mut();
        if req.is_none() {
            return Err(HtpStatus::ERROR);
        }
        let req = req.unwrap();

        // Is this a line that should be ignored?
        if is_line_ignorable(perso, line) {
            // We have an empty/whitespace line, which we'll note, ignore and move on.
            req.request_ignored_lines = req.request_ignored_lines.wrapping_add(1);
            return Ok(());
        }
        // Process request line.
        let data = chomp(line);
        req.request_line = Some(Bstr::from(data));
        self.parse_request_line(data)?;
        // Finalize request line parsing.
        self.state_request_line()?;
        Ok(())
    }

    /// Parses request line.
    ///
    /// Returns OK on state change, ERROR on error, or HtpStatus::DATA_BUFFER
    /// when more data is needed.
    pub fn request_line(&mut self, input: &mut ParserData) -> Result<()> {
        match take_till_lf(input.as_slice()) {
            Ok((_, line)) => {
                // We have a line ending, so consume the input
                // and grab any buffered data
                let mut data = take(&mut self.request_buf);
                data.add(line);
                self.request_data_consume(input, line.len());
                self.request_line_complete(data.as_slice())
            }
            _ => {
                if self.request_status == HtpStreamState::CLOSED {
                    let mut data = take(&mut self.request_buf);
                    data.add(input.as_slice());
                    self.request_data_consume(input, input.len());
                    self.request_line_complete(data.as_slice())
                } else {
                    self.handle_request_absent_lf(input)
                }
            }
        }
    }

    /// Extract one request header. A header can span multiple lines, in
    /// which case they will be folded into one before parsing is attempted.
    fn process_request_header(&mut self, header: Header) -> Result<()> {
        // Try to parse the header.
        // ensured by caller
        let req = self.request_mut().unwrap();
        let mut repeated = false;
        let reps = req.request_header_repetitions;
        let mut update_reps = false;
        // Do we already have a header with the same name?
        if let Some(h_existing) = req.request_headers.get_nocase_mut(header.name.as_slice()) {
            if !h_existing.flags.is_set(HeaderFlags::FIELD_REPEATED) {
                // This is the second occurence for this header.
                repeated = true;
            } else if reps < 64 {
                update_reps = true;
            } else {
                return Ok(());
            }
            // For simplicity reasons, we count the repetitions of all headers
            h_existing.flags.set(HeaderFlags::FIELD_REPEATED);
            // Having multiple C-L headers is against the RFC but
            // servers may ignore the subsequent headers if the values are the same.
            if header.name.cmp_nocase("Content-Length") == Ordering::Equal {
                // Don't use string comparison here because we want to
                // ignore small formatting differences.
                let existing_cl = parse_content_length(&h_existing.value, None);
                let new_cl = parse_content_length(&header.value, None);
                // Ambiguous response C-L value.
                if existing_cl.is_none() || new_cl.is_none() || existing_cl != new_cl {
                    htp_warn!(
                        self.logger,
                        HtpLogCode::DUPLICATE_CONTENT_LENGTH_FIELD_IN_REQUEST,
                        "Ambiguous request C-L value"
                    );
                }
            } else {
                // Add to the existing header.
                h_existing.value.extend_from_slice(b", ");
                h_existing.value.extend_from_slice(header.value.as_slice());
            }
        } else {
            req.request_headers.elements.push(header);
        }
        let req = self.request_mut().unwrap();
        if update_reps {
            req.request_header_repetitions = req.request_header_repetitions.wrapping_add(1)
        }
        if repeated {
            htp_warn!(
                self.logger,
                HtpLogCode::REQUEST_HEADER_REPETITION,
                "Repetition for header"
            );
        }
        Ok(())
    }

    /// Parse request headers
    fn parse_request_headers<'a>(&mut self, data: &'a [u8]) -> Result<(&'a [u8], bool)> {
        let req = self.request_mut();
        if req.is_none() {
            return Err(HtpStatus::ERROR);
        }

        let rc = req.unwrap().request_header_parser.headers()(data);
        if let Ok((remaining, (headers, eoh))) = rc {
            for h in headers {
                let mut flags = 0;
                let name_flags = h.name.flags;
                // Ignore LWS after field-name.
                if name_flags.is_set(HeaderFlags::NAME_TRAILING_WHITESPACE) {
                    // Log only once per transaction.
                    htp_warn_once!(
                        self.logger,
                        HtpLogCode::REQUEST_INVALID_LWS_AFTER_NAME,
                        "Request field invalid: LWS after name",
                        self.request_mut().unwrap().flags,
                        flags,
                        HtpFlags::FIELD_INVALID
                    );
                }
                //If name has leading whitespace, probably invalid folding
                if name_flags.is_set(HeaderFlags::NAME_LEADING_WHITESPACE) {
                    // Invalid folding.
                    // Warn only once per transaction.
                    htp_warn_once!(
                        self.logger,
                        HtpLogCode::INVALID_REQUEST_FIELD_FOLDING,
                        "Invalid request field folding",
                        self.request_mut().unwrap().flags,
                        flags,
                        HtpFlags::INVALID_FOLDING
                    );
                }
                // Check that field-name is a token
                if name_flags.is_set(HeaderFlags::NAME_NON_TOKEN_CHARS) {
                    // Incorrectly formed header name.
                    // Log only once per transaction.
                    htp_warn_once!(
                        self.logger,
                        HtpLogCode::REQUEST_HEADER_INVALID,
                        "Request header name is not a token",
                        self.request_mut().unwrap().flags,
                        flags,
                        HtpFlags::FIELD_INVALID
                    );
                }
                // No colon?
                if name_flags.is_set(HeaderFlags::MISSING_COLON) {
                    // Log only once per transaction.
                    // We handle this case as a header with an empty name, with the value equal
                    // to the entire input string.
                    // TODO Apache will respond to this problem with a 400.
                    // Now extract the name and the value
                    htp_warn_once!(
                        self.logger,
                        HtpLogCode::REQUEST_FIELD_MISSING_COLON,
                        "Request field invalid: colon missing",
                        self.request_mut().unwrap().flags,
                        flags,
                        HtpFlags::FIELD_UNPARSEABLE
                    );
                } else if name_flags.is_set(HeaderFlags::NAME_EMPTY) {
                    // Empty header name.
                    // Log only once per transaction.
                    htp_warn_once!(
                        self.logger,
                        HtpLogCode::REQUEST_INVALID_EMPTY_NAME,
                        "Request field invalid: empty name",
                        self.request_mut().unwrap().flags,
                        flags,
                        HtpFlags::FIELD_INVALID
                    );
                }
                self.process_request_header(Header::new_with_flags(
                    h.name.name.into(),
                    h.value.value.into(),
                    flags,
                ))?;
            }
            Ok((remaining, eoh))
        } else {
            Ok((data, false))
        }
    }

    /// Parses a single request line.
    pub fn parse_request_line(&mut self, request_line: &[u8]) -> Result<()> {
        let req = self.request_mut();
        if req.is_none() {
            return Err(HtpStatus::ERROR);
        }
        let req = req.unwrap();

        req.request_line = Some(Bstr::from(request_line));
        let mut mstart: bool = false;
        let mut data: &[u8] = request_line;
        if self.cfg.server_personality == HtpServerPersonality::APACHE_2 {
            //Null terminates
            if let Ok((_, before_null)) = take_until_null(data) {
                data = before_null
            }
        }
        // The request method starts at the beginning of the
        // line and ends with the first whitespace character.
        let mut method_parser = tuple
                                // skip past leading whitespace. IIS allows this
                               ((take_is_space,
                               take_not_is_space,
                                // Ignore whitespace after request method. The RFC allows
                                 // for only one SP, but then suggests any number of SP and HT
                                 // should be permitted. Apache uses isspace(), which is even
                                 // more permitting, so that's what we use here.
                               take_is_space
                               ));

        if let Ok((remaining, (ls, method, ws))) = method_parser(data) {
            if !ls.is_empty() {
                htp_warn!(
                    self.logger,
                    HtpLogCode::REQUEST_LINE_LEADING_WHITESPACE,
                    "Request line: leading whitespace"
                );

                let requestline_leading_whitespace_unwanted =
                    self.cfg.requestline_leading_whitespace_unwanted;
                if requestline_leading_whitespace_unwanted != HtpUnwanted::IGNORE {
                    // reset mstart so that we copy the whitespace into the method
                    mstart = true;
                    // set expected response code to this anomaly
                    let req = self.request_mut().unwrap();
                    req.response_status_expected_number = requestline_leading_whitespace_unwanted
                }
            }

            let req = self.request_mut().unwrap();
            if mstart {
                req.request_method = Some(Bstr::from([ls, method].concat()));
            } else {
                req.request_method = Some(Bstr::from(method));
            }

            if let Some(request_method) = &req.request_method {
                req.request_method_number = HtpMethod::new(request_method.as_slice());
            }

            // Too much performance overhead for fuzzing
            if ws.iter().any(|&c| c != 0x20) {
                htp_warn!(
                    self.logger,
                    HtpLogCode::METHOD_DELIM_NON_COMPLIANT,
                    "Request line: non-compliant delimiter between Method and URI"
                );
            }

            if remaining.is_empty() {
                // No, this looks like a HTTP/0.9 request.
                let req = self.request_mut().unwrap();
                req.is_protocol_0_9 = true;
                req.request_protocol_number = HtpProtocol::V0_9;
                if req.request_method_number == HtpMethod::UNKNOWN {
                    htp_warn!(
                        self.logger,
                        HtpLogCode::REQUEST_LINE_UNKNOWN_METHOD,
                        "Request line: unknown method only"
                    );
                }
                return Ok(());
            }

            let remaining = trimmed(remaining);

            let (mut uri, mut protocol) =
                split_on_predicate(remaining, self.cfg.decoder_cfg.allow_space_uri, true, |c| {
                    *c == 0x20
                });

            if uri.len() == remaining.len() && uri.iter().any(|&c| is_space(c)) {
                // warn regardless if we've seen non-compliant chars
                htp_warn!(
                    self.logger,
                    HtpLogCode::URI_DELIM_NON_COMPLIANT,
                    "Request line: URI contains non-compliant delimiter"
                );
                // if we've seen some 'bad' delimiters, we retry with those
                let uri_protocol = split_on_predicate(
                    remaining,
                    self.cfg.decoder_cfg.allow_space_uri,
                    true,
                    |c| is_space(*c),
                );
                uri = uri_protocol.0;
                protocol = uri_protocol.1;
            }

            let req = self.request_mut().unwrap();
            req.request_uri = Some(Bstr::from(uri));

            // Is there protocol information available?
            if protocol.is_empty() {
                // No, this looks like a HTTP/0.9 request.
                req.is_protocol_0_9 = true;
                req.request_protocol_number = HtpProtocol::V0_9;
                if req.request_method_number == HtpMethod::UNKNOWN {
                    htp_warn!(
                        self.logger,
                        HtpLogCode::REQUEST_LINE_UNKNOWN_METHOD_NO_PROTOCOL,
                        "Request line: unknown method and no protocol"
                    );
                }
                return Ok(());
            }

            // The protocol information continues until the end of the line.
            req.request_protocol = Some(Bstr::from(protocol));
            self.request_mut().unwrap().request_protocol_number =
                parse_protocol(protocol, &mut self.logger);
            let req = self.request().unwrap();
            if req.request_method_number == HtpMethod::UNKNOWN
                && req.request_protocol_number == HtpProtocol::INVALID
            {
                htp_warn!(
                    self.logger,
                    HtpLogCode::REQUEST_LINE_UNKNOWN_METHOD_INVALID_PROTOCOL,
                    "Request line: unknown method and invalid protocol"
                );
            }
        }
        Ok(())
    }

    /// Consumes request body data.
    /// This function assumes that handling of chunked encoding is implemented
    /// by the container. When you're done submitting body data, invoke a state
    /// change (to REQUEST) to finalize any processing that might be pending.
    /// The supplied data is fully consumed and there is no expectation that it
    /// will be available afterwards. The protocol parsing code makes no copies
    /// of the data, but some parsers might.
    ///
    /// Returns HtpStatus::OK on success or HtpStatus::ERROR if the request transaction
    /// is invalid or response body data hook fails.
    pub fn request_body_data(&mut self, data: Option<&[u8]>) -> Result<()> {
        // None data is used to indicate the end of request body.
        // Keep track of body size before decompression.
        let req = self.request_mut();
        if req.is_none() {
            return Err(HtpStatus::ERROR);
        }
        let req = req.unwrap();

        req.request_message_len = req
            .request_message_len
            .wrapping_add(data.unwrap_or(b"").len() as u64);
        match req.request_content_encoding_processing {
            HtpContentEncoding::GZIP
            | HtpContentEncoding::DEFLATE
            | HtpContentEncoding::ZLIB
            | HtpContentEncoding::LZMA => {
                // Send data buffer to the decompressor if it exists
                if req.request_decompressor.is_none() && data.is_none() {
                    return Ok(());
                }
                let mut decompressor = req.request_decompressor.take().ok_or(HtpStatus::ERROR)?;
                if let Some(data) = data {
                    decompressor
                        .decompress(data)
                        .map_err(|_| HtpStatus::ERROR)?;
                    if decompressor.time_spent()
                        > self.cfg.compression_options.get_time_limit() as u64
                    {
                        htp_log!(
                            self.logger,
                            HtpLogLevel::ERROR,
                            HtpLogCode::COMPRESSION_BOMB,
                            format!(
                                "Compression bomb: spent {} us decompressing",
                                decompressor.time_spent(),
                            )
                        );
                        decompressor.set_passthrough(true);
                    }
                    // put the decompressor back in its slot
                    let req = self.request_mut().unwrap();
                    req.request_decompressor.replace(decompressor);
                } else {
                    // don't put the decompressor back in its slot
                    // ignore errors
                    let _ = decompressor.finish();
                }
            }
            HtpContentEncoding::NONE => {
                // When there's no decompression, request_entity_len.
                // is identical to request_message_len.
                // None data is used to indicate the end of request body.
                // Keep track of the body length.
                req.request_entity_len += data.unwrap_or(b"").len() as u64;
                // Send data to the callbacks.
                let data = ParserData::from(data);
                let mut data = Data::new(req, &data);
                self.request_run_hook_body_data(&mut data).map_err(|e| {
                    htp_error!(
                        self.logger,
                        HtpLogCode::REQUEST_BODY_DATA_CALLBACK_ERROR,
                        format!("Request body data callback returned error ({:?})", e)
                    );
                    e
                })?
            }
            HtpContentEncoding::ERROR => {
                htp_error!(
                    self.logger,
                    HtpLogCode::INVALID_CONTENT_ENCODING,
                    "Expected a valid content encoding"
                );
                return Err(HtpStatus::ERROR);
            }
        }
        Ok(())
    }

    /// Initialize the request decompression engine. We can deal with three
    /// scenarios:
    ///
    /// 1. Decompression is enabled, compression indicated in headers, and we decompress.
    ///
    /// 2. As above, but the user disables decompression by setting response_content_encoding
    ///    to COMPRESSION_NONE.
    ///
    /// 3. Decompression is disabled and we do not attempt to enable it, but the user
    ///    forces decompression by setting response_content_encoding to one of the
    ///    supported algorithms.
    pub fn request_initialize_decompressors(&mut self) -> Result<()> {
        let req = self.request_mut();
        if req.is_none() {
            return Err(HtpStatus::ERROR);
        }
        let req = req.unwrap();
        let ce = req
            .request_headers
            .get_nocase_nozero("content-encoding")
            .map(|val| val.value.clone());
        // Process multiple encodings if there is no match on fast path
        let mut slow_path = false;

        // Fast path - try to match directly on the encoding value
        req.request_content_encoding = if let Some(ce) = &ce {
            if ce.cmp_nocase_nozero(b"gzip") == Ordering::Equal
                || ce.cmp_nocase_nozero(b"x-gzip") == Ordering::Equal
            {
                HtpContentEncoding::GZIP
            } else if ce.cmp_nocase_nozero(b"deflate") == Ordering::Equal
                || ce.cmp_nocase_nozero(b"x-deflate") == Ordering::Equal
            {
                HtpContentEncoding::DEFLATE
            } else if ce.cmp_nocase_nozero(b"lzma") == Ordering::Equal {
                HtpContentEncoding::LZMA
            } else if ce.cmp_nocase_nozero(b"inflate") == Ordering::Equal
                || ce.cmp_nocase_nozero(b"none") == Ordering::Equal
            {
                HtpContentEncoding::NONE
            } else {
                slow_path = true;
                HtpContentEncoding::NONE
            }
        } else {
            HtpContentEncoding::NONE
        };

        // Configure decompression, if enabled in the configuration.
        self.request_mut()
            .unwrap()
            .request_content_encoding_processing = if self.cfg.request_decompression_enabled {
            self.request().unwrap().request_content_encoding
        } else {
            slow_path = false;
            HtpContentEncoding::NONE
        };

        let req = self.request_mut().unwrap();
        let request_content_encoding_processing = req.request_content_encoding_processing;
        let compression_options = self.cfg.compression_options;
        match &request_content_encoding_processing {
            HtpContentEncoding::GZIP
            | HtpContentEncoding::DEFLATE
            | HtpContentEncoding::ZLIB
            | HtpContentEncoding::LZMA => {
                self.request_prepend_decompressor(request_content_encoding_processing)?;
            }
            HtpContentEncoding::NONE => {
                if slow_path {
                    if let Some(ce) = &ce {
                        let mut layers = 0;
                        for encoding in ce.split(|c| *c == b',' || *c == b' ') {
                            if encoding.is_empty() {
                                continue;
                            }
                            layers += 1;

                            if let Some(limit) = compression_options.get_layer_limit() {
                                // decompression layer depth check
                                if layers > limit {
                                    htp_warn!(
                                        self.logger,
                                        HtpLogCode::TOO_MANY_ENCODING_LAYERS,
                                        "Too many request content encoding layers"
                                    );
                                    break;
                                }
                            }

                            let encoding = Bstr::from(encoding);
                            let encoding = if encoding.index_of_nocase(b"gzip").is_some() {
                                if !(encoding.cmp_slice(b"gzip") == Ordering::Equal
                                    || encoding.cmp_slice(b"x-gzip") == Ordering::Equal)
                                {
                                    htp_warn!(
                                        self.logger,
                                        HtpLogCode::ABNORMAL_CE_HEADER,
                                        "C-E gzip has abnormal value"
                                    );
                                }
                                HtpContentEncoding::GZIP
                            } else if encoding.index_of_nocase(b"deflate").is_some() {
                                if !(encoding.cmp_slice(b"deflate") == Ordering::Equal
                                    || encoding.cmp_slice(b"x-deflate") == Ordering::Equal)
                                {
                                    htp_warn!(
                                        self.logger,
                                        HtpLogCode::ABNORMAL_CE_HEADER,
                                        "C-E deflate has abnormal value"
                                    );
                                }
                                HtpContentEncoding::DEFLATE
                            } else if encoding.cmp_slice(b"lzma") == Ordering::Equal {
                                if let Some(limit) = compression_options.get_lzma_layers() {
                                    // LZMA decompression layer depth check
                                    if layers > limit {
                                        htp_warn!(
                                            self.logger,
                                            HtpLogCode::REQUEST_TOO_MANY_LZMA_LAYERS,
                                            "Compression bomb: multiple encoding with lzma"
                                        );
                                        break;
                                    }
                                }
                                HtpContentEncoding::LZMA
                            } else if encoding.cmp_slice(b"inflate") == Ordering::Equal
                                || encoding.cmp_slice(b"none") == Ordering::Equal
                            {
                                HtpContentEncoding::NONE
                            } else {
                                htp_warn!(
                                    self.logger,
                                    HtpLogCode::ABNORMAL_CE_HEADER,
                                    "C-E unknown setting"
                                );
                                HtpContentEncoding::NONE
                            };
                            self.request_prepend_decompressor(encoding)?;
                        }
                    }
                }
            }
            HtpContentEncoding::ERROR => {
                htp_error!(
                    self.logger,
                    HtpLogCode::INVALID_CONTENT_ENCODING,
                    "Expected a valid content encoding"
                );
                return Err(HtpStatus::ERROR);
            }
        }
        Ok(())
    }

    /// Prepend a decompressor to the request
    fn request_prepend_decompressor(&mut self, encoding: HtpContentEncoding) -> Result<()> {
        let compression_options = self.cfg.compression_options;
        if encoding != HtpContentEncoding::NONE {
            // ensured by caller
            let req = self.request_mut().unwrap();
            if let Some(decompressor) = req.request_decompressor.take() {
                req.request_decompressor
                    .replace(decompressor.prepend(encoding, compression_options)?);
            } else {
                // The processing encoding will be the first one encountered
                req.request_content_encoding_processing = encoding;

                // Add the callback first because it will be called last in
                // the chain of writers

                // TODO: fix lifetime error and remove this line!
                let connp_ptr: *mut ConnectionParser = self as *mut ConnectionParser;
                let decompressor = unsafe {
                    Decompressor::new_with_callback(
                        encoding,
                        Box::new(move |data: Option<&[u8]>| -> std::io::Result<usize> {
                            (*connp_ptr).request_decompressor_callback(data)
                        }),
                        compression_options,
                    )?
                };
                let req = self.request_mut().unwrap();
                req.request_decompressor.replace(decompressor);
            }
        }
        Ok(())
    }

    fn request_decompressor_callback(&mut self, data: Option<&[u8]>) -> std::io::Result<usize> {
        // If no data is passed, call the hooks with NULL to signify the end of the
        // request body.
        let parser_data = ParserData::from(data);
        // ensured by only caller
        let req = self.request_mut().unwrap();
        let mut tx_data = Data::new(req, &parser_data);

        // Keep track of actual request body length.
        req.request_entity_len = req.request_entity_len.wrapping_add(tx_data.len() as u64);

        // Invoke all callbacks.
        self.request_run_hook_body_data(&mut tx_data)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "body data hook failed"))?;

        let compression_options = self.cfg.compression_options;
        let req = self.request_mut().unwrap();
        if let Some(decompressor) = &mut req.request_decompressor {
            if decompressor.callback_inc() % compression_options.get_time_test_freq() == 0 {
                if let Some(time_spent) = decompressor.timer_reset() {
                    if time_spent > compression_options.get_time_limit() as u64 {
                        decompressor.set_passthrough(true);
                        htp_log!(
                            self.logger,
                            HtpLogLevel::ERROR,
                            HtpLogCode::COMPRESSION_BOMB,
                            format!("Compression bomb: spent {} us decompressing", time_spent)
                        );
                    }
                }
            }
        }

        // output > ratio * input ?
        let ratio = compression_options.get_bomb_ratio();
        let req = self.request().unwrap();
        let exceeds_ratio = if let Some(ratio) = req.request_message_len.checked_mul(ratio) {
            req.request_entity_len > ratio
        } else {
            // overflow occured
            true
        };

        let bomb_limit = compression_options.get_bomb_limit();
        let request_entity_len = req.request_entity_len;
        let request_message_len = req.request_message_len;
        if request_entity_len > bomb_limit && exceeds_ratio {
            htp_log!(
                self.logger,
                HtpLogLevel::ERROR,
                HtpLogCode::COMPRESSION_BOMB,
                format!(
                    "Compression bomb: decompressed {} bytes out of {}",
                    request_entity_len, request_message_len,
                )
            );
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "compression_bomb_limit reached",
            ));
        }
        Ok(tx_data.len())
    }

    /// Finalizes request.
    ///
    /// Returns OK on state change, ERROR on error, or HtpStatus::DATA_BUFFER
    /// when more data is needed.
    pub fn request_finalize(&mut self, input: &mut ParserData) -> Result<()> {
        if input.is_gap() {
            return self.state_request_complete(input);
        }
        let mut work = input.as_slice();
        if self.request_status != HtpStreamState::CLOSED {
            let request_next_byte = input.as_slice().first();
            if request_next_byte.is_none() {
                return self.state_request_complete(input);
            }

            if let Ok((_, line)) = take_till_lf(work) {
                self.request_data_consume(input, line.len());
                work = line;
            } else {
                return self.handle_request_absent_lf(input);
            }
        }

        if !self.request_buf.is_empty() {
            self.check_request_buffer_limit(work.len())?;
        }
        let mut data = take(&mut self.request_buf);
        let buf_len = data.len();
        data.add(work);

        if data.is_empty() {
            //closing
            return self.state_request_complete(input);
        }
        let res = tuple((take_is_space, take_not_is_space))(&data);

        if let Ok((_, (_, method))) = res {
            if method.is_empty() {
                // empty whitespace line
                let rc = self.request_body_data(Some(&data));
                self.request_buf.clear();
                return rc;
            }
            if HtpMethod::new(method) == HtpMethod::UNKNOWN {
                if self.request_body_data_left.unwrap_or(0) == 0 {
                    // log only once per transaction
                    htp_warn!(
                        self.logger,
                        HtpLogCode::REQUEST_BODY_UNEXPECTED,
                        "Unexpected request body"
                    );
                } else {
                    self.request_body_data_left = Some(1);
                }
                // Interpret remaining bytes as body data
                let rc = self.request_body_data(Some(&data));
                self.request_buf.clear();
                return rc;
            } // else continue
            self.request_body_data_left = None;
        }
        // didnt use data, restore
        self.request_buf.add(&data[0..buf_len]);
        //unread last end of line so that request_line works
        self.request_data_unconsume(input, data.len());
        self.state_request_complete(input)
    }

    /// Consumes whatever is left in the buffer after detecting an http/0.9 session.
    pub fn request_ignore_data_after_http_0_9(&mut self, data: &mut ParserData) -> Result<()> {
        if !data.is_empty() {
            self.conn.flags.set(ConnectionFlags::HTTP_0_9_EXTRA)
        }
        self.request_data_consume(data, data.len());
        Err(HtpStatus::DATA)
    }

    /// The idle state is where the parser will end up after a transaction is processed.
    /// If there is more data available, a new request will be started.
    ///
    /// Returns OK on state change, ERROR on error, or HTP_DATA when more data is needed.
    pub fn request_idle(&mut self, data: &mut ParserData) -> Result<()> {
        // We want to start parsing the next request (and change
        // the state from IDLE) only if there's at least one
        // byte of data available. Otherwise we could be creating
        // new structures even if there's no more data on the
        // connection.
        if data.is_empty() {
            // we may have buffered some data, if we are closing, we want to process it
            if self.request_status != HtpStreamState::CLOSED || self.request_buf.is_empty() {
                return Err(HtpStatus::DATA);
            }
        }
        self.request_reset();
        // Change state to TRANSACTION_START
        // Ignore the result.
        let _ = self.state_request_start();
        Ok(())
    }

    /// Buffer incomplete request data and verify that field_limit
    /// constraint is met.
    fn handle_request_absent_lf(&mut self, data: &ParserData) -> Result<()> {
        self.check_request_buffer_limit(data.len())?;
        self.request_buf.add(data.as_slice());
        self.request_data_consume(data, data.len());
        Err(HtpStatus::DATA_BUFFER)
    }

    /// Run the REQUEST_BODY_DATA hook.
    fn request_run_hook_body_data(&mut self, d: &mut Data) -> Result<()> {
        // Do not invoke callbacks with an empty data chunk
        let req = self.request_mut().unwrap();
        if !d.data().is_null() && d.is_empty() {
            return Ok(());
        }
        req.hook_request_body_data.clone().run_all(self, d)?;
        // Run configuration hooks second
        self.cfg.hook_request_body_data.run_all(self, d)?;
        Ok(())
    }

    /// Process a chunk of inbound (client or request) data.
    pub fn request_data(
        &mut self,
        mut chunk: ParserData,
        timestamp: Option<OffsetDateTime>,
    ) -> HtpStreamState {
        // Reset the bytes consumed counter
        self.request_bytes_consumed = 0;

        // Return if the connection is in stop state.
        if self.request_status == HtpStreamState::STOP {
            htp_info!(
                self.logger,
                HtpLogCode::PARSER_STATE_ERROR,
                "Inbound parser is in STOP state"
            );
            return HtpStreamState::STOP;
        }
        // Return if the connection had a fatal error earlier
        if self.request_status == HtpStreamState::ERROR {
            htp_error!(
                self.logger,
                HtpLogCode::PARSER_STATE_ERROR,
                "Inbound parser is in ERROR state"
            );
            return HtpStreamState::ERROR;
        }

        // If the length of the supplied data chunk is zero, proceed
        // only if the stream has been closed. We do not allow zero-sized
        // chunks in the API, but we use them internally to force the parsers
        // to finalize parsing.
        if chunk.is_empty() && self.request_status != HtpStreamState::CLOSED {
            htp_error!(
                self.logger,
                HtpLogCode::ZERO_LENGTH_DATA_CHUNKS,
                "Zero-length data chunks are not allowed"
            );
            return HtpStreamState::CLOSED;
        }
        // Remember the timestamp of the current request data chunk
        if let Some(timestamp) = timestamp {
            self.request_timestamp = timestamp;
        }

        // Store the current chunk information
        self.request_chunk_count = self.request_chunk_count.wrapping_add(1);
        self.conn.track_inbound_data(chunk.len());
        // Return without processing any data if the stream is in tunneling
        // mode (which it would be after an initial CONNECT transaction).
        if self.request_status == HtpStreamState::TUNNEL {
            return HtpStreamState::TUNNEL;
        }
        if self.response_status == HtpStreamState::DATA_OTHER {
            self.response_status = HtpStreamState::DATA
        }
        //handle gap
        if chunk.is_gap() {
            // Mark the transaction as having a gap
            let idx = self.request_index();
            let req = self.request_mut();
            if req.is_none() {
                return HtpStreamState::ERROR;
            }
            let req = req.unwrap();

            req.flags.set(HtpFlags::REQUEST_MISSING_BYTES);

            if idx == 0 && req.request_progress == HtpRequestProgress::NOT_STARTED {
                // We have a leading gap on the first transaction.
                // Force the parser to start if it hasn't already.
                self.request_mut().unwrap().request_progress = HtpRequestProgress::GAP;
                self.request_status = HtpStreamState::ERROR;
                return HtpStreamState::ERROR;
            }
        }

        loop
        // Invoke a processor, in a loop, until an error
        // occurs or until we run out of data. Many processors
        // will process a request, each pointing to the next
        // processor that needs to run.
        // Return if there's been an error or if we've run out of data. We are relying
        // on processors to supply error messages, so we'll keep quiet here.
        {
            // handle gap
            if chunk.is_gap()
                && self.request_state != State::BODY_IDENTITY
                && self.request_state != State::IGNORE_DATA_AFTER_HTTP_0_9
                && self.request_state != State::FINALIZE
            {
                // go to request_connect_probe_data ?
                htp_error!(
                    self.logger,
                    HtpLogCode::INVALID_GAP,
                    "Gaps are not allowed during this state"
                );
                return HtpStreamState::CLOSED;
            }
            let mut rc = self.handle_request_state(&mut chunk);

            if rc.is_ok() {
                if self.request_status == HtpStreamState::TUNNEL {
                    return HtpStreamState::TUNNEL;
                }
                rc = self.request_handle_state_change(&mut chunk)
            }
            match rc {
                // Continue looping.
                Ok(_) => {}
                // Do we need more data?
                Err(HtpStatus::DATA) | Err(HtpStatus::DATA_BUFFER) => {
                    // Ignore result.
                    let _ = self.request_receiver_send_data(&mut chunk);
                    self.request_status = HtpStreamState::DATA;
                    return HtpStreamState::DATA;
                }
                // Check for suspended parsing.
                Err(HtpStatus::DATA_OTHER) => {
                    // We might have actually consumed the entire data chunk?
                    if chunk.is_empty() {
                        // Do not send STREAM_DATE_DATA_OTHER if we've consumed the entire chunk.
                        self.request_status = HtpStreamState::DATA;
                        return HtpStreamState::DATA;
                    } else {
                        // Partial chunk consumption.
                        self.request_status = HtpStreamState::DATA_OTHER;
                        return HtpStreamState::DATA_OTHER;
                    }
                }
                // Check for the stop signal.
                Err(HtpStatus::STOP) => {
                    self.request_status = HtpStreamState::STOP;
                    return HtpStreamState::STOP;
                }
                // Permanent stream error.
                Err(_) => {
                    self.request_status = HtpStreamState::ERROR;
                    return HtpStreamState::ERROR;
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(b"GET", HtpMethod::GET)]
    #[case(b"PUT", HtpMethod::PUT)]
    #[case(b"POST", HtpMethod::POST)]
    #[case(b"PoST", HtpMethod::UNKNOWN)]
    #[case(b"post", HtpMethod::UNKNOWN)]
    #[case(b"NOT_METHOD", HtpMethod::UNKNOWN)]
    fn test_method(#[case] input: &[u8], #[case] expected: HtpMethod) {
        assert_eq!(HtpMethod::new(input), expected);
    }
}
