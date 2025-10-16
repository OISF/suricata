use crate::{
    bstr::Bstr,
    connection_parser::{ConnectionParser, HtpStreamState, ParserData, State},
    decompressors::{Decompressor, HtpContentEncoding},
    error::Result,
    headers::HeaderFlags,
    hook::DataHook,
    parsers::{parse_chunked_length, parse_content_length, parse_protocol, parse_status},
    request::HtpMethod,
    transaction::{
        Data, Header, HtpProtocol, HtpRequestProgress, HtpResponseNumber, HtpResponseProgress,
        HtpTransferCoding,
    },
    uri::Uri,
    util::{
        chomp, is_chunked_ctl_line, is_line_ignorable, is_space, is_valid_chunked_length_data,
        take_ascii_whitespace, take_is_space, take_is_space_or_null, take_not_is_space,
        take_till_eol, take_till_lf, treat_response_line_as_body, FlagOperations, HtpFlags,
    },
    HtpStatus,
};
use nom::{bytes::streaming::take_till as streaming_take_till, error::ErrorKind, sequence::tuple};
use std::{
    cmp::{min, Ordering},
    mem::take,
};
use time::OffsetDateTime;

impl ConnectionParser {
    /// Sends outstanding connection data to the currently active data receiver hook.
    fn response_receiver_send_data(&mut self, data: &mut ParserData) -> Result<()> {
        let data = ParserData::from(data.callback_data());
        let resp = self.response_mut();
        if resp.is_none() {
            return Err(HtpStatus::ERROR);
        }
        let mut tx_data = Data::new(resp.unwrap(), &data);
        if let Some(hook) = &self.response_data_receiver_hook {
            hook.run_all(self, &mut tx_data)?;
        } else {
            return Ok(());
        };
        Ok(())
    }

    /// Finalizes an existing data receiver hook by sending any outstanding data to it. The
    /// hook is then removed so that it receives no more data.
    pub(crate) fn response_receiver_finalize_clear(
        &mut self, input: &mut ParserData,
    ) -> Result<()> {
        if self.response_data_receiver_hook.is_none() {
            return Ok(());
        }
        let rc = self.response_receiver_send_data(input);
        self.response_data_receiver_hook = None;
        rc
    }

    /// Configures the data receiver hook.
    fn response_receiver_set(&mut self, data_receiver_hook: Option<DataHook>) -> Result<()> {
        self.response_data_receiver_hook = data_receiver_hook;
        Ok(())
    }

    /// Handles response parser state changes. At the moment, this function is used only
    /// to configure data receivers, which are sent raw connection data.
    fn response_handle_state_change(&mut self, input: &mut ParserData) -> Result<()> {
        if self.response_state_previous == self.response_state {
            return Ok(());
        }

        if self.response_state == State::Headers {
            let resp = self.response_mut();
            if resp.is_none() {
                return Err(HtpStatus::ERROR);
            }
            let resp = resp.unwrap();
            let header_fn = Some(resp.cfg.hook_response_header_data.clone());
            let trailer_fn = Some(resp.cfg.hook_response_trailer_data.clone());
            input.reset_callback_start();

            match resp.response_progress {
                HtpResponseProgress::HEADERS => self.response_receiver_set(header_fn),
                HtpResponseProgress::TRAILER => self.response_receiver_set(trailer_fn),
                _ => Ok(()),
            }?;
        }
        // Same comment as in request_handle_state_change(). Below is a copy.
        // Initially, I had the finalization of raw data sending here, but that
        // caused the last REQUEST_HEADER_DATA hook to be invoked after the
        // REQUEST_HEADERS hook -- which I thought made no sense. For that reason,
        // the finalization is now initiated from the request header processing code,
        // which is less elegant but provides a better user experience. Having some
        // (or all) hooks to be invoked on state change might work better.
        self.response_state_previous = self.response_state;
        Ok(())
    }

    /// The maximum amount accepted for buffering is controlled
    /// by htp_config_t::field_limit.
    fn check_response_buffer_limit(&mut self, len: usize) -> Result<()> {
        if len == 0 {
            return Ok(());
        }
        // Check the hard (buffering) limit.
        let mut newlen: usize = self.response_buf.len().wrapping_add(len);
        // When calculating the size of the buffer, take into account the
        // space we're using for the response header buffer.
        if let Some(response_header) = &self.response_header {
            newlen = newlen.wrapping_add(response_header.len());
        }
        let field_limit = self.cfg.field_limit;
        if newlen > field_limit {
            htp_error!(
                self.logger,
                HtpLogCode::RESPONSE_FIELD_TOO_LONG,
                format!(
                    "Response the buffer limit: size {} limit {}.",
                    newlen, field_limit
                )
            );
            return Err(HtpStatus::ERROR);
        }
        Ok(())
    }

    /// Consumes bytes until the end of the current line.
    ///
    /// Returns HtpStatus::OK on state change, HtpStatus::Error on error, or HtpStatus::DATA
    /// when more data is needed.
    pub(crate) fn response_body_chunked_data_end(&mut self, input: &ParserData) -> Result<()> {
        // TODO We shouldn't really see anything apart from CR and LF,
        //      so we should warn about anything else.
        let resp = self.response_mut();
        if resp.is_none() {
            return Err(HtpStatus::ERROR);
        }
        let resp = resp.unwrap();

        if let Ok((_, line)) = take_till_lf(input.as_slice()) {
            let len = line.len();
            self.response_data_consume(input, len);
            let resp = self.response_mut().unwrap();
            resp.response_message_len = resp.response_message_len.wrapping_add(len as u64);
            self.response_state = State::BodyChunkedLength;
            Ok(())
        } else {
            // Advance to end. Dont need to buffer
            resp.response_message_len = resp.response_message_len.wrapping_add(input.len() as u64);
            self.response_data_consume(input, input.len());
            Err(HtpStatus::DATA_BUFFER)
        }
    }

    /// Processes a chunk of data.
    ///
    /// Returns HtpStatus::OK on state change, HtpStatus::Error on error, or
    /// HtpStatus::DATA when more data is needed.
    pub(crate) fn response_body_chunked_data(&mut self, input: &ParserData) -> Result<()> {
        if self.response_status == HtpStreamState::CLOSED {
            self.response_state = State::Finalize;
            // Sends close signal to decompressors
            return self.response_body_data(input.data());
        }
        let bytes_to_consume = min(
            input.len(),
            self.response_chunked_length.unwrap_or(0) as usize,
        );
        if bytes_to_consume == 0 {
            return Err(HtpStatus::DATA);
        }
        // Consume the data.
        self.response_body_data(Some(&input.as_slice()[0..bytes_to_consume]))?;
        // Adjust the counters.
        self.response_data_consume(input, bytes_to_consume);
        if let Some(len) = &mut self.response_chunked_length {
            *len -= bytes_to_consume as u64;
            // Have we seen the entire chunk?
            if *len == 0 {
                self.response_state = State::BodyChunkedDataEnd;
                return Ok(());
            }
        }

        Err(HtpStatus::DATA)
    }

    /// Extracts chunk length.
    ///
    /// Returns Ok(()) on success, Err(HTP_ERROR) on error, or Err(HTP_DATA) when more data is needed.
    pub(crate) fn response_body_chunked_length(&mut self, input: &mut ParserData) -> Result<()> {
        let mut data = input.as_slice();
        loop {
            let buf_empty = self.response_buf.is_empty();
            let resp = self.response_mut();
            if resp.is_none() {
                return Err(HtpStatus::ERROR);
            }
            let resp = resp.unwrap();

            match take_till_lf(data) {
                Ok((remaining, line)) => {
                    self.response_data_consume(input, line.len());
                    if !buf_empty {
                        self.check_response_buffer_limit(line.len())?;
                    }
                    let mut data2 = take(&mut self.response_buf);
                    data2.add(line);
                    if is_chunked_ctl_line(&data2) {
                        let resp = self.response_mut().unwrap();
                        resp.response_message_len =
                            (resp.response_message_len).wrapping_add(data2.len() as u64);
                        //Empty chunk len. Try to continue parsing.
                        data = remaining;
                        continue;
                    }
                    let resp = self.response_mut().unwrap();
                    resp.response_message_len =
                        (resp.response_message_len).wrapping_add(data2.len() as u64);

                    match parse_chunked_length(&data2) {
                        Ok((len, ext)) => {
                            self.response_chunked_length = len;
                            if ext {
                                htp_warn!(
                                    self.logger,
                                    HtpLogCode::RESPONSE_CHUNK_EXTENSION,
                                    "Response chunk extension"
                                );
                            }
                            // Handle chunk length
                            if let Some(len) = len {
                                match len.cmp(&0) {
                                    Ordering::Equal => {
                                        // End of data
                                        self.response_state = State::Headers;
                                        self.response_mut().unwrap().response_progress =
                                            HtpResponseProgress::TRAILER
                                    }
                                    Ordering::Greater => {
                                        // More data available.
                                        self.response_state = State::BodyChunkedData
                                    }
                                    _ => {}
                                }
                            } else {
                                return Ok(()); // empty chunk length line, lets try to continue
                            }
                        }
                        Err(_) => {
                            // unconsume so response_body_identity_stream_close doesn't miss the first bytes
                            self.response_data_unconsume(input, line.len());
                            self.response_state = State::BodyIdentityStreamClose;
                            self.response_mut().unwrap().response_transfer_coding =
                                HtpTransferCoding::Identity;
                            htp_error!(
                                self.logger,
                                HtpLogCode::INVALID_RESPONSE_CHUNK_LEN,
                                "Response chunk encoding: Invalid chunk length"
                            );
                        }
                    }

                    return Ok(());
                }
                _ => {
                    // Check if the data we have seen so far is invalid
                    if buf_empty && !is_valid_chunked_length_data(data) {
                        // Contains leading junk non hex_ascii data
                        resp.response_transfer_coding = HtpTransferCoding::Identity;
                        self.response_state = State::BodyIdentityStreamClose;
                        htp_error!(
                            self.logger,
                            HtpLogCode::INVALID_RESPONSE_CHUNK_LEN,
                            "Response chunk encoding: Invalid chunk length"
                        );
                        return Ok(());
                    } else {
                        return self.handle_response_absent_lf(input);
                    }
                }
            }
        }
    }

    /// Processes an identity response body of known length.
    ///
    /// Returns HtpStatus::OK on state change, HtpStatus::ERROR on error, or
    /// HtpStatus::DATA when more data is needed.
    pub(crate) fn response_body_identity_cl_known(&mut self, data: &mut ParserData) -> Result<()> {
        if self.response_status == HtpStreamState::CLOSED {
            self.response_state = State::Finalize;
            // Sends close signal to decompressors
            return self.response_body_data(data.data());
        }
        let left = self.response_body_data_left.ok_or(HtpStatus::ERROR)?;
        let bytes_to_consume = std::cmp::min(data.len() as u64, left);
        if bytes_to_consume == 0 {
            return Err(HtpStatus::DATA);
        }
        if data.is_gap() {
            let resp = self.response_mut();
            if resp.is_none() {
                return Err(HtpStatus::ERROR);
            }
            let resp = resp.unwrap();

            if resp.response_content_encoding_processing == HtpContentEncoding::None {
                resp.response_message_len =
                    resp.response_message_len.wrapping_add(bytes_to_consume);
                // Create a new gap of the appropriate length
                let parser_data = ParserData::from(bytes_to_consume as usize);
                // Send the gap to the data hooks
                let mut tx_data = Data::new(resp, &parser_data);
                self.response_run_hook_body_data(&mut tx_data)?;
            } else {
                // end decompression on gap
                self.response_body_data(None)?;
            }
        } else {
            // Consume the data.
            self.response_body_data(Some(&data.as_slice()[0..bytes_to_consume as usize]))?;
        }
        // Adjust the counters.
        self.response_data_consume(data, bytes_to_consume as usize);
        self.response_body_data_left = Some(left - bytes_to_consume);
        // Have we seen the entire response body?
        if self.response_body_data_left > Some(0) {
            return Err(HtpStatus::DATA);
        }
        // End of response body.
        self.response_state = State::Finalize;
        // Sends close signal to decompressors, outputting any partially decompressed data
        self.response_body_data(None)
    }

    /// Processes identity response body of unknown length. In this case, we assume the
    /// response body consumes all data until the end of the stream.
    ///
    /// Returns HtpStatus::OK on state change, HtpStatus::ERROR on error, or HtpStatus::DATA
    /// when more data is needed.
    pub(crate) fn response_body_identity_stream_close(&mut self, data: &ParserData) -> Result<()> {
        if !data.is_empty() {
            // Consume all data from the input buffer.
            self.response_body_data(data.data())?;
            // Adjust the counters.
            self.response_data_consume(data, data.len());
        }
        // Have we seen the entire response body?
        if self.response_status == HtpStreamState::CLOSED {
            self.response_state = State::Finalize;
            return Ok(());
        }

        Err(HtpStatus::DATA)
    }

    /// Determines presence (and encoding) of a response body.
    pub(crate) fn response_body_determine(&mut self, input: &mut ParserData) -> Result<()> {
        // If the request uses the CONNECT method, then not only are we
        // to assume there's no body, but we need to ignore all
        // subsequent data in the stream.
        let response_tx = self.response_mut();
        if response_tx.is_none() {
            return Err(HtpStatus::ERROR);
        }
        let response_tx = response_tx.unwrap();

        if response_tx.request_method_number == HtpMethod::CONNECT {
            if response_tx.response_status_number.in_range(200, 299) {
                // This is a successful CONNECT stream, which means
                // we need to switch into tunneling mode: on the
                // request side we'll now probe the tunnel data to see
                // if we need to parse or ignore it. So on the response
                // side we wrap up the tx and wait.
                self.response_state = State::Finalize;
                // we may have response headers
                return self.state_response_headers(input);
            } else if response_tx.response_status_number.eq_num(407) {
                // proxy telling us to auth
                if self.request_status != HtpStreamState::ERROR {
                    self.request_status = HtpStreamState::DATA
                }
            } else {
                // This is a failed CONNECT stream, which means that
                // we can unblock request parsing
                if self.request_status != HtpStreamState::ERROR {
                    self.request_status = HtpStreamState::DATA
                }
                // We are going to continue processing this transaction,
                // adding a note for ourselves to stop at the end (because
                // we don't want to see the beginning of a new transaction).
                self.response_data_other_at_tx_end = true
            }
        }
        let response_tx = self.response_mut().unwrap();
        let cl_opt = response_tx
            .response_headers
            .get_nocase_nozero("content-length")
            .cloned();
        let te_opt = response_tx
            .response_headers
            .get_nocase_nozero("transfer-encoding")
            .cloned();
        // Check for "101 Switching Protocol" response.
        // If it's seen, it means that traffic after empty line following headers
        // is no longer HTTP. We can treat it similarly to CONNECT.
        // Unlike CONNECT, however, upgrades from HTTP to HTTP seem
        // rather unlikely, so don't try to probe tunnel for nested HTTP,
        // and switch to tunnel mode right away.
        if response_tx.response_status_number.eq_num(101) {
            if response_tx
                .response_headers
                .get_nocase_nozero("upgrade")
                .map(|upgrade| upgrade.value.index_of_nocase_nozero("h2c").is_some())
                .unwrap_or(false)
            {
                response_tx.is_http_2_upgrade = true;
            }
            if te_opt.is_none() && cl_opt.is_none() {
                self.response_state = State::Finalize;
                if self.request_status != HtpStreamState::ERROR {
                    self.request_status = HtpStreamState::TUNNEL
                }
                self.response_status = HtpStreamState::TUNNEL;
                // we may have response headers
                return self.state_response_headers(input);
            } else {
                htp_warn!(
                    self.logger,
                    HtpLogCode::SWITCHING_PROTO_WITH_CONTENT_LENGTH,
                    "Switching Protocol with Content-Length"
                );
            }
        }
        // Check for an interim "100 Continue" response. Ignore it if found, and revert back to RES_LINE.
        else if response_tx.response_status_number.eq_num(100) && te_opt.is_none() {
            match cl_opt
                .as_ref()
                .and_then(|cl| parse_content_length(cl.value.as_slice(), Some(&mut self.logger)))
            {
                // 100 Continue with a Content-Length > 0 isn't treated as a 100 Continue,
                // so we do nothing here.
                Some(x) if x > 0 => (),
                // Otherwise we treat it as a continue and prep for the next response
                _ => {
                    let response_tx = self.response_mut().unwrap();
                    if response_tx.seen_100continue {
                        htp_error!(
                            self.logger,
                            HtpLogCode::CONTINUE_ALREADY_SEEN,
                            "Already seen 100-Continue."
                        );
                    }
                    // Expecting to see another response line next.
                    self.response_state = State::Line;
                    let response_tx = self.response_mut().unwrap();
                    // Ignore any response headers seen so far.
                    response_tx.response_headers.elements.clear();
                    response_tx.response_progress = HtpResponseProgress::LINE;
                    response_tx.seen_100continue = true;
                    return Ok(());
                }
            }
        }
        // A request can indicate it waits for headers validation
        // before sending its body cf
        // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Expect
        else if response_tx.response_status_number.in_range(400, 499)
            && self.request_content_length > Some(0)
            && self.request_body_data_left == self.request_content_length
        {
            let response_tx = self.response_mut().unwrap();
            if let Some(expect) = response_tx.request_headers.get_nocase("expect") {
                if expect.value.eq_slice("100-continue") {
                    self.request_state = State::Finalize;
                }
            }
        }

        // 1. Any response message which MUST NOT include a message-body
        //  (such as the 1xx, 204, and 304 responses and any response to a HEAD
        //  request) is always terminated by the first empty line after the
        //  header fields, regardless of the entity-header fields present in the
        //  message.
        let response_tx = self.response_mut().unwrap();
        if response_tx.request_method_number == HtpMethod::HEAD {
            // There's no response body whatsoever
            response_tx.response_transfer_coding = HtpTransferCoding::NoBody;
            self.response_state = State::Finalize
        } else if response_tx.response_status_number.in_range(100, 199)
            || response_tx.response_status_number.eq_num(204)
            || response_tx.response_status_number.eq_num(304)
        {
            // There should be no response body
            // but browsers interpret content sent by the server as such
            if te_opt.is_none() && cl_opt.is_none() {
                response_tx.response_transfer_coding = HtpTransferCoding::NoBody;
                self.response_state = State::Finalize
            } else {
                htp_warn!(
                    self.logger,
                    HtpLogCode::RESPONSE_BODY_UNEXPECTED,
                    "Unexpected Response body"
                );
            }
        }
        // Hack condition to check that we do not assume "no body"
        let mut multipart_byteranges = false;
        if self.response_state != State::Finalize {
            // We have a response body
            let response_tx = self.response_mut().unwrap();
            let response_content_type = if let Some(ct) = response_tx
                .response_headers
                .get_nocase_nozero("content-type")
            {
                // TODO Some platforms may do things differently here.
                let response_content_type = if let Ok((_, ct)) =
                    streaming_take_till::<_, _, (&[u8], ErrorKind)>(|c| c == b';' || is_space(c))(
                        &ct.value,
                    ) {
                    ct
                } else {
                    &ct.value
                };

                let mut response_content_type = Bstr::from(response_content_type);
                response_content_type.make_ascii_lowercase();
                if response_content_type
                    .index_of_nocase("multipart/byteranges")
                    .is_some()
                {
                    multipart_byteranges = true;
                }
                Some(response_content_type)
            } else {
                None
            };

            if response_content_type.is_some() {
                response_tx.response_content_type = response_content_type;
            }
            // 2. If a Transfer-Encoding header field (section 14.40) is present and
            //   indicates that the "chunked" transfer coding has been applied, then
            //   the length is defined by the chunked encoding (section 3.6).
            if let Some(te) =
                te_opt.and_then(|te| te.value.index_of_nocase_nozero("chunked").and(Some(te)))
            {
                if !te.value.cmp_nocase("chunked") {
                    htp_warn!(
                        self.logger,
                        HtpLogCode::RESPONSE_ABNORMAL_TRANSFER_ENCODING,
                        "Transfer-encoding has abnormal chunked value"
                    );
                }
                // 3. If a Content-Length header field (section 14.14) is present, its
                // spec says chunked is HTTP/1.1 only, but some browsers accept it
                // with 1.0 as well
                let response_tx = self.response_mut().unwrap();
                if response_tx.response_protocol_number < HtpProtocol::V1_1 {
                    htp_warn!(
                        self.logger,
                        HtpLogCode::RESPONSE_CHUNKED_OLD_PROTO,
                        "Chunked transfer-encoding on HTTP/0.9 or HTTP/1.0"
                    );
                }
                // If the T-E header is present we are going to use it.
                let response_tx = self.response_mut().unwrap();
                response_tx.response_transfer_coding = HtpTransferCoding::Chunked;
                // We are still going to check for the presence of C-L
                if cl_opt.is_some() {
                    // This is a violation of the RFC
                    response_tx.flags.set(HtpFlags::REQUEST_SMUGGLING)
                }
                response_tx.response_progress = HtpResponseProgress::BODY;
                self.response_state = State::BodyChunkedLength
            } else if let Some(cl) = cl_opt {
                //   value in bytes represents the length of the message-body.
                // We know the exact length
                response_tx.response_transfer_coding = HtpTransferCoding::Identity;
                // Check for multiple C-L headers
                if cl.flags.is_set(HtpFlags::FIELD_REPEATED) {
                    response_tx.flags.set(HtpFlags::REQUEST_SMUGGLING)
                }
                // Get body length
                let response_content_length =
                    parse_content_length((*cl.value).as_slice(), Some(&mut self.logger));
                self.response_mut().unwrap().response_content_length = response_content_length;
                self.response_content_length = response_content_length;
                self.response_body_data_left = response_content_length;
                if let Some(len) = response_content_length {
                    if len != 0 {
                        self.response_state = State::BodyIdentityCLKnown;
                        self.response_mut().unwrap().response_progress = HtpResponseProgress::BODY
                    } else {
                        self.response_state = State::Finalize
                    }
                } else {
                    htp_error!(
                        self.logger,
                        HtpLogCode::INVALID_CONTENT_LENGTH_FIELD_IN_RESPONSE,
                        "Invalid C-L field in response"
                    );
                    return Err(HtpStatus::ERROR);
                }
            } else {
                // 4. If the message uses the media type "multipart/byteranges", which is
                //   self-delimiting, then that defines the length. This media type MUST
                //   NOT be used unless the sender knows that the recipient can parse it;
                //   the presence in a request of a Range header with multiple byte-range
                //   specifiers implies that the client can parse multipart/byteranges
                //   responses.
                // TODO Handle multipart/byteranges
                if multipart_byteranges {
                    htp_error!(
                        self.logger,
                        HtpLogCode::RESPONSE_MULTIPART_BYTERANGES,
                        "C-T multipart/byteranges in responses not supported"
                    );
                    return Err(HtpStatus::ERROR);
                }
                // 5. By the server closing the connection. (Closing the connection
                //   cannot be used to indicate the end of a request body, since that
                //   would leave no possibility for the server to send back a response.)
                response_tx.response_transfer_coding = HtpTransferCoding::Identity;
                response_tx.response_progress = HtpResponseProgress::BODY;
                self.response_state = State::BodyIdentityStreamClose;
                self.response_body_data_left = None
            }
        }
        // NOTE We do not need to check for short-style HTTP/0.9 requests here because
        //      that is done earlier, before response line parsing begins
        self.state_response_headers(input)
    }

    /// Parses response line.
    ///
    /// Returns HtpStatus::OK on state change, HtpStatus::ERROR on error, or HtpStatus::DATA
    /// when more data is needed.
    pub(crate) fn response_line(&mut self, input: &ParserData) -> Result<()> {
        match take_till_eol(input.as_slice()) {
            Ok((_, (line, _))) => {
                // We have a line ending, so consume the input
                // and grab any buffered data.
                let mut data = take(&mut self.response_buf);
                data.add(line);
                self.response_data_consume(input, line.len());
                self.response_line_complete(data.as_slice(), input)
            }
            _ => {
                if self.response_status == HtpStreamState::CLOSED {
                    let mut data = take(&mut self.response_buf);
                    data.add(input.as_slice());
                    self.response_data_consume(input, input.len());
                    self.response_line_complete(data.as_slice(), input)
                } else {
                    self.handle_response_absent_lf(input)
                }
            }
        }
    }

    /// Parse the complete response line.
    ///
    /// Returns OK on state change, ERROR on error, or HtpStatus::DATA_BUFFER
    /// when more data is needed.
    fn response_line_complete(&mut self, line: &[u8], input: &ParserData) -> Result<()> {
        self.check_response_buffer_limit(line.len())?;
        if line.is_empty() {
            return Err(HtpStatus::DATA);
        }
        let response_tx = self.response_mut();
        if response_tx.is_none() {
            return Err(HtpStatus::ERROR);
        }
        if is_line_ignorable(self.cfg.server_personality, line) {
            if self.response_status == HtpStreamState::CLOSED {
                self.response_state = State::Finalize
            }
            // We have an empty/whitespace line, which we'll note, ignore and move on
            let response_tx = self.response_mut().unwrap();
            response_tx.response_ignored_lines = response_tx.response_ignored_lines.wrapping_add(1);
            // TODO How many lines are we willing to accept?
            // Start again
            return Ok(());
        }
        // Deallocate previous response line allocations, which we would have on a 100 response.
        let response_tx = self.response_mut().unwrap();
        response_tx.response_line = None;
        response_tx.response_protocol = None;
        response_tx.response_status = None;
        response_tx.response_message = None;

        // Process response line.
        // If the response line is invalid, determine if it _looks_ like
        // a response line. If it does not look like a line, process the
        // data as a response body because that is what browsers do.
        if treat_response_line_as_body(line) {
            // if we have a next line beginning with H, skip this one
            if input.len() > 1 && (input.as_slice()[0] == b'H' || chomp(line).len() <= 2) {
                response_tx.response_ignored_lines =
                    response_tx.response_ignored_lines.wrapping_add(1);
                return Ok(());
            }
            response_tx.response_content_encoding_processing = HtpContentEncoding::None;
            self.response_body_data(Some(line))?;
            // Continue to process response body. Because we don't have
            // any headers to parse, we assume the body continues until
            // the end of the stream.
            // Have we seen the entire response body?
            if input.is_empty() {
                let response_tx = self.response_mut().unwrap();
                response_tx.response_transfer_coding = HtpTransferCoding::Identity;
                response_tx.response_progress = HtpResponseProgress::BODY;
                self.response_body_data_left = None;
                self.response_state = State::Finalize
            }
            return Ok(());
        }
        self.parse_response_line(line)?;
        self.state_response_line()?;
        // Move on to the next phase.
        self.response_state = State::Headers;
        self.response_mut().unwrap().response_progress = HtpResponseProgress::HEADERS;
        Ok(())
    }

    /// Parses the response line.
    pub(crate) fn parse_response_line(&mut self, response_line: &[u8]) -> Result<()> {
        let response_tx = self.response_mut();
        if response_tx.is_none() {
            return Err(HtpStatus::ERROR);
        }
        let response_tx = response_tx.unwrap();

        response_tx.response_line = Some(Bstr::from(response_line));
        response_tx.response_protocol_number = HtpProtocol::Invalid;
        response_tx.response_status = None;
        response_tx.response_status_number = HtpResponseNumber::Invalid;
        response_tx.response_message = None;

        let mut response_line_parser = tuple((
            take_is_space_or_null,
            take_not_is_space,
            take_is_space,
            take_not_is_space,
            take_ascii_whitespace(),
        ));

        let (message, (_ls, response_protocol, ws1, status_code, ws2)) =
            response_line_parser(response_line)?;
        if response_protocol.is_empty() {
            return Ok(());
        }

        response_tx.response_protocol = Some(Bstr::from(response_protocol));
        self.response_mut().unwrap().response_protocol_number =
            parse_protocol(response_protocol, &mut self.logger);

        if ws1.is_empty() || status_code.is_empty() {
            return Ok(());
        }

        let response_tx = self.response_mut().unwrap();
        response_tx.response_status = Some(Bstr::from(status_code));
        response_tx.response_status_number = parse_status(status_code);

        if ws2.is_empty() {
            return Ok(());
        }

        response_tx.response_message = Some(Bstr::from(chomp(message)));
        Ok(())
    }

    /// Response header parser.
    ///
    ///Returns a tuple of the unparsed data and a boolean indicating if the EOH was seen.
    fn parse_response_headers<'a>(&mut self, data: &'a [u8]) -> Result<(&'a [u8], bool)> {
        let resp = self.response_mut();
        if resp.is_none() {
            return Err(HtpStatus::ERROR);
        }

        let rc = resp.unwrap().response_header_parser.headers()(data);
        if let Ok((remaining, (headers, eoh))) = rc {
            for h in headers {
                let mut flags = 0;
                let name_flags = &h.name.flags;
                let value_flags = &h.value.flags;
                if value_flags.is_set(HeaderFlags::DEFORMED_EOL)
                    || name_flags.is_set(HeaderFlags::DEFORMED_EOL)
                {
                    htp_warn!(
                        self.logger,
                        HtpLogCode::DEFORMED_EOL,
                        "Weird response end of lines mix"
                    );
                }
                // Ignore LWS after field-name.
                if name_flags.is_set(HeaderFlags::NAME_TRAILING_WHITESPACE) {
                    htp_warn_once!(
                        self.logger,
                        HtpLogCode::RESPONSE_INVALID_LWS_AFTER_NAME,
                        "Request field invalid: LWS after name",
                        self.response_mut().unwrap().flags,
                        flags,
                        HtpFlags::FIELD_INVALID
                    );
                }
                //If there was leading whitespace, probably was invalid folding.
                if name_flags.is_set(HeaderFlags::NAME_LEADING_WHITESPACE) {
                    htp_warn_once!(
                        self.logger,
                        HtpLogCode::INVALID_RESPONSE_FIELD_FOLDING,
                        "Invalid response field folding",
                        self.response_mut().unwrap().flags,
                        flags,
                        HtpFlags::INVALID_FOLDING
                    );
                    flags.set(HtpFlags::FIELD_INVALID);
                }
                // Check that field-name is a token
                if name_flags.is_set(HeaderFlags::NAME_NON_TOKEN_CHARS) {
                    // Incorrectly formed header name.
                    htp_warn_once!(
                        self.logger,
                        HtpLogCode::RESPONSE_HEADER_NAME_NOT_TOKEN,
                        "Response header name is not a token",
                        self.response_mut().unwrap().flags,
                        flags,
                        HtpFlags::FIELD_INVALID
                    );
                }
                // No colon?
                if name_flags.is_set(HeaderFlags::MISSING_COLON) {
                    // We handle this case as a header with an empty name, with the value equal
                    // to the entire input string.
                    // TODO Apache will respond to this problem with a 400.
                    // Now extract the name and the value
                    htp_warn_once!(
                        self.logger,
                        HtpLogCode::RESPONSE_FIELD_MISSING_COLON,
                        "Response field invalid: colon missing",
                        self.response_mut().unwrap().flags,
                        flags,
                        HtpFlags::FIELD_UNPARSEABLE
                    );
                    flags.set(HtpFlags::FIELD_INVALID);
                } else if name_flags.is_set(HeaderFlags::NAME_EMPTY) {
                    // Empty header name.
                    htp_warn_once!(
                        self.logger,
                        HtpLogCode::RESPONSE_INVALID_EMPTY_NAME,
                        "Response field invalid: empty name",
                        self.response_mut().unwrap().flags,
                        flags,
                        HtpFlags::FIELD_INVALID
                    );
                }
                self.process_response_header(Header::new_with_flags(
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

    /// Response header line(s) processor, which assembles folded lines
    /// into a single buffer before invoking the parsing function.
    fn process_response_header(&mut self, header: Header) -> Result<()> {
        let mut repeated = false;
        let hl = self.cfg.number_headers_limit as usize;
        let resp = self.response_mut();
        if resp.is_none() {
            return Err(HtpStatus::ERROR);
        }
        let resp = resp.unwrap();

        let reps = resp.response_header_repetitions;
        let mut update_reps = false;
        // Do we already have a header with the same name?
        if let Some(h_existing) = resp.response_headers.get_nocase_mut(header.name.as_slice()) {
            if !h_existing.flags.is_set(HeaderFlags::FIELD_REPEATED) {
                // This is the second occurence for this header.
                repeated = true;
            } else if reps < 64 {
                update_reps = true;
            } else {
                return Ok(());
            }
            h_existing.flags.set(HeaderFlags::FIELD_REPEATED);
            // For simplicity reasons, we count the repetitions of all headers
            // Having multiple C-L headers is against the RFC but many
            // browsers ignore the subsequent headers if the values are the same.
            if header.name.cmp_nocase("Content-Length") {
                // Don't use string comparison here because we want to
                // ignore small formatting differences.
                let existing_cl = parse_content_length(&h_existing.value, None);
                let new_cl = parse_content_length(&(header.value), None);
                if existing_cl.is_none() || new_cl.is_none() || existing_cl != new_cl {
                    // Ambiguous response C-L value.
                    htp_warn!(
                        self.logger,
                        HtpLogCode::DUPLICATE_CONTENT_LENGTH_FIELD_IN_RESPONSE,
                        "Ambiguous response C-L value"
                    );
                }
            } else {
                // Add to the existing header.
                h_existing.value.extend_from_slice(b", ");
                h_existing.value.extend_from_slice(header.value.as_slice());
            }
        } else {
            if resp.response_headers.elements.len() > hl {
                if !resp.flags.is_set(HtpFlags::HEADERS_TOO_MANY) {
                    htp_warn!(
                        self.logger,
                        HtpLogCode::RESPONSE_TOO_MANY_HEADERS,
                        "Too many response headers"
                    );
                    let resp = self.response_mut().unwrap();
                    resp.flags.set(HtpFlags::HEADERS_TOO_MANY);
                }
                return Err(HtpStatus::ERROR);
            }
            resp.response_headers.elements.push(header);
        }
        let resp = self.response_mut().unwrap();
        if update_reps {
            resp.response_header_repetitions = resp.response_header_repetitions.wrapping_add(1)
        }
        if repeated {
            htp_warn!(
                self.logger,
                HtpLogCode::RESPONSE_HEADER_REPETITION,
                "Repetition for header"
            );
        }
        Ok(())
    }
    /// Parses response headers.
    ///
    /// Returns HtpStatus::OK on state change, HtpStatus::ERROR on error, or HtpStatus::DATA when more data is needed.
    pub(crate) fn response_headers(&mut self, input: &mut ParserData) -> Result<()> {
        let response_index = self.response_index();
        if self.response_status == HtpStreamState::CLOSED {
            let resp = self.response_mut();
            if resp.is_none() {
                return Err(HtpStatus::ERROR);
            }
            let resp = resp.unwrap();
            resp.response_header_parser.set_complete(true);
            // Parse previous header, if any.
            if let Some(response_header) = self.response_header.take() {
                self.parse_response_headers(response_header.as_slice())?;
            }
            // Finalize sending raw trailer data.
            self.response_receiver_finalize_clear(input)?;
            // Run hook response_TRAILER
            self.cfg
                .hook_response_trailer
                .clone()
                .run_all(self, response_index)?;
            self.response_state = State::Finalize;
            return Ok(());
        }
        if let Ok((_, line)) = take_till_lf(input.as_slice()) {
            if self.response_header.is_some() {
                self.check_response_buffer_limit(line.len())?;
            }
        } else {
            let data = input.as_slice();
            self.response_data_consume(input, data.len());
            self.check_response_buffer_limit(data.len())?;
            if let Some(rh) = &mut self.response_header {
                rh.extend_from_slice(data);
            } else {
                self.response_header = Some(Bstr::from(data));
            }
            return Err(HtpStatus::DATA_BUFFER);
        }
        let response_header = if let Some(mut response_header) = self.response_header.take() {
            response_header.add(input.as_slice());
            response_header
        } else {
            Bstr::from(input.as_slice())
        };

        let (remaining, eoh) = self.parse_response_headers(response_header.as_slice())?;
        //TODO: Update the response state machine so that we don't have to have this EOL check
        let eol = remaining.len() == response_header.len()
            && (remaining.eq(b"\r\n") || remaining.eq(b"\n"));
        // If remaining is EOL or header parsing saw EOH this is end of headers
        if eoh || eol {
            if eol {
                //Consume the EOL so it isn't included in data processing
                self.response_data_consume(input, input.len());
            } else if remaining.len() <= input.len() {
                self.response_data_consume(input, input.len() - remaining.len());
            }
            // We've seen all response headers. At terminator.
            self.response_state =
                if self.response().unwrap().response_progress == HtpResponseProgress::HEADERS {
                    // Response headers.
                    // The next step is to determine if this response has a body.
                    State::BodyDetermine
                } else {
                    // Response trailer.
                    // Finalize sending raw trailer data.
                    self.response_receiver_finalize_clear(input)?;
                    // Run hook response_TRAILER.
                    self.cfg
                        .hook_response_trailer
                        .clone()
                        .run_all(self, response_index)?;
                    // The next step is to finalize this response.
                    State::Finalize
                };
            Ok(())
        } else {
            self.response_data_consume(input, input.len());
            self.check_response_buffer_limit(remaining.len())?;
            let remaining = Bstr::from(remaining);
            self.response_header.replace(remaining);
            Err(HtpStatus::DATA_BUFFER)
        }
    }

    /// Consumes response body data.
    /// This function assumes that handling of chunked encoding is implemented
    /// by the container. When you're done submitting body data, invoking a state
    /// change (to RESPONSE) will finalize any processing that might be pending.
    ///
    /// The response body data will be decompressed if two conditions are met: one,
    /// decompression is enabled in configuration and two, if the response headers
    /// indicate compression. Alternatively, you can control decompression from
    /// a RESPONSE_HEADERS callback, by setting tx->response_content_encoding either
    /// to COMPRESSION_NONE (to disable compression), or to one of the supported
    /// decompression algorithms.
    ///
    /// Returns HtpStatus::OK on success or HtpStatus::ERROR if the request transaction
    /// is invalid or response body data hook fails.
    pub(crate) fn response_body_data(&mut self, data: Option<&[u8]>) -> Result<()> {
        // None data is used to indicate the end of response body.
        // Keep track of body size before decompression.
        let resp = self.response_mut();
        if resp.is_none() {
            return Err(HtpStatus::ERROR);
        }
        let resp = resp.unwrap();

        resp.response_message_len = resp
            .response_message_len
            .wrapping_add(data.unwrap_or(b"").len() as u64);

        match resp.response_content_encoding_processing {
            HtpContentEncoding::Gzip
            | HtpContentEncoding::Deflate
            | HtpContentEncoding::Zlib
            | HtpContentEncoding::Brotli
            | HtpContentEncoding::Lzma => {
                // Send data buffer to the decompressor if it exists
                if resp.response_decompressor.is_none() && data.is_none() {
                    return Ok(());
                }
                let mut decompressor = resp.response_decompressor.take().ok_or(HtpStatus::ERROR)?;
                if let Some(data) = data {
                    let _ = decompressor.decompress(data);

                    if decompressor.time_spent()
                        > self.cfg.compression_options.get_time_limit() as u64
                    {
                        htp_error!(
                            self.logger,
                            HtpLogCode::COMPRESSION_BOMB,
                            format!(
                                "Compression bomb: spent {} us decompressing",
                                decompressor.time_spent(),
                            )
                        );
                        decompressor.set_passthrough(true);
                    }
                    // put the decompressor back in its slot
                    self.response_mut()
                        .unwrap()
                        .response_decompressor
                        .replace(decompressor);
                } else {
                    // don't put the decompressor back in its slot
                    // ignore errors
                    let _ = decompressor.finish();
                }
            }
            HtpContentEncoding::None => {
                // When there's no decompression, response_entity_len.
                // is identical to response_message_len.
                let data = ParserData::from(data);
                let mut tx_data = Data::new(resp, &data);
                resp.response_entity_len =
                    resp.response_entity_len.wrapping_add(tx_data.len() as u64);
                self.response_run_hook_body_data(&mut tx_data)?;
            }
        }
        Ok(())
    }

    /// Initialize the response decompression engine. We can deal with three
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
    pub(crate) fn response_initialize_decompressors(&mut self) -> Result<()> {
        let resp = self.response_mut();
        if resp.is_none() {
            return Err(HtpStatus::ERROR);
        }
        let resp = resp.unwrap();

        let ce = resp
            .response_headers
            .get_nocase_nozero("content-encoding")
            .map(|val| val.value.clone());
        // Process multiple encodings if there is no match on fast path
        let mut slow_path = false;

        // Fast path - try to match directly on the encoding value
        resp.response_content_encoding = if let Some(ce) = &ce {
            if ce.cmp_nocase_nozero(b"gzip") || ce.cmp_nocase_nozero(b"x-gzip") {
                HtpContentEncoding::Gzip
            } else if ce.cmp_nocase_nozero(b"deflate") || ce.cmp_nocase_nozero(b"x-deflate") {
                HtpContentEncoding::Deflate
            } else if ce.cmp_nocase_nozero(b"lzma") {
                HtpContentEncoding::Lzma
            } else if ce.cmp_nocase_nozero(b"br") {
                HtpContentEncoding::Brotli
            } else if ce.cmp_nocase_nozero(b"inflate") || ce.cmp_nocase_nozero(b"none") {
                HtpContentEncoding::None
            } else {
                slow_path = true;
                HtpContentEncoding::None
            }
        } else {
            HtpContentEncoding::None
        };

        // Configure decompression, if enabled in the configuration.
        resp.response_content_encoding_processing = resp.response_content_encoding;

        let response_content_encoding_processing = resp.response_content_encoding_processing;
        let compression_options = self.cfg.compression_options;
        match &response_content_encoding_processing {
            HtpContentEncoding::Gzip
            | HtpContentEncoding::Deflate
            | HtpContentEncoding::Zlib
            | HtpContentEncoding::Brotli
            | HtpContentEncoding::Lzma => {
                self.response_prepend_decompressor(response_content_encoding_processing)?;
            }
            HtpContentEncoding::None => {
                if slow_path {
                    if let Some(ce) = &ce {
                        let mut layers = 0;
                        let mut lzma_layers = 0;
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
                                        "Too many response content encoding layers"
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
                                HtpContentEncoding::Gzip
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
                                HtpContentEncoding::Deflate
                            } else if encoding.cmp_slice(b"lzma") == Ordering::Equal {
                                lzma_layers += 1;
                                if let Some(limit) = compression_options.get_lzma_layers() {
                                    // Lzma layer depth check
                                    if lzma_layers > limit {
                                        htp_warn!(
                                            self.logger,
                                            HtpLogCode::RESPONSE_TOO_MANY_LZMA_LAYERS,
                                            "Too many response content encoding lzma layers"
                                        );
                                        break;
                                    }
                                }
                                HtpContentEncoding::Lzma
                            } else if encoding.cmp_slice(b"inflate") == Ordering::Equal
                                || encoding.cmp_slice(b"none") == Ordering::Equal
                                || encoding.cmp_slice(b"identity") == Ordering::Equal
                            {
                                HtpContentEncoding::None
                            } else {
                                htp_warn!(
                                    self.logger,
                                    HtpLogCode::ABNORMAL_CE_HEADER,
                                    "C-E unknown setting"
                                );
                                HtpContentEncoding::None
                            };

                            self.response_prepend_decompressor(encoding)?;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn response_decompressor_callback(&mut self, data: Option<&[u8]>) -> std::io::Result<usize> {
        // If no data is passed, call the hooks with NULL to signify the end of the
        // response body.
        let parser_data = ParserData::from(data);
        let compression_options = self.cfg.compression_options;
        let resp = self.response_mut().unwrap();
        let mut tx_data = Data::new(resp, &parser_data);

        // Keep track of actual response body length.
        resp.response_entity_len = resp.response_entity_len.wrapping_add(tx_data.len() as u64);

        // Invoke all callbacks.
        self.response_run_hook_body_data(&mut tx_data)
            .map_err(|_| std::io::Error::other("body data hook failed"))?;
        let resp = self.response_mut().unwrap();
        if let Some(decompressor) = &mut resp.response_decompressor {
            if decompressor.callback_inc() % compression_options.get_time_test_freq() == 0 {
                if let Some(time_spent) = decompressor.timer_reset() {
                    if time_spent > compression_options.get_time_limit() as u64 {
                        decompressor.set_passthrough(true);
                        htp_error!(
                            self.logger,
                            HtpLogCode::COMPRESSION_BOMB,
                            format!("Compression bomb: spent {} us decompressing", time_spent)
                        );
                    }
                }
            }
        }

        // output > ratio * input ?
        let ratio = compression_options.get_bomb_ratio();
        let resp = self.response_mut().unwrap();
        let exceeds_ratio = if let Some(ratio) = resp.response_message_len.checked_mul(ratio) {
            resp.response_entity_len > ratio
        } else {
            // overflow occured
            true
        };

        let bomb_limit = compression_options.get_bomb_limit();
        let response_entity_len = resp.response_entity_len;
        let response_message_len = resp.response_message_len;
        if response_entity_len > bomb_limit && exceeds_ratio {
            htp_error!(
                self.logger,
                HtpLogCode::COMPRESSION_BOMB,
                format!(
                    "Compression bomb: decompressed {} bytes out of {}",
                    response_entity_len, response_message_len,
                )
            );
            return Err(std::io::Error::other("compression_bomb_limit reached"));
        }
        Ok(tx_data.len())
    }

    /// Prepend response decompressor
    fn response_prepend_decompressor(&mut self, encoding: HtpContentEncoding) -> Result<()> {
        let compression_options = self.cfg.compression_options;
        if encoding != HtpContentEncoding::None {
            // ensured by caller
            let resp = self.response_mut().unwrap();
            if let Some(decompressor) = resp.response_decompressor.take() {
                let decompressor = decompressor.prepend(encoding, compression_options)?;
                resp.response_decompressor.replace(decompressor);
            } else {
                // The processing encoding will be the first one encountered
                resp.response_content_encoding_processing = encoding;

                // Add the callback first because it will be called last in
                // the chain of writers

                // TODO: fix lifetime error and remove this line!
                let connp_ptr = self as *mut Self;
                let decompressor = unsafe {
                    Decompressor::new_with_callback(
                        encoding,
                        Box::new(move |data: Option<&[u8]>| -> std::io::Result<usize> {
                            (*connp_ptr).response_decompressor_callback(data)
                        }),
                        compression_options,
                    )?
                };
                self.response_mut()
                    .unwrap()
                    .response_decompressor
                    .replace(decompressor);
            }
        }
        Ok(())
    }

    /// Finalizes response parsing.
    pub(crate) fn response_finalize(&mut self, input: &mut ParserData) -> Result<()> {
        if input.is_gap() {
            return self.state_response_complete(input);
        }
        let mut work = input.as_slice();
        if self.response_status != HtpStreamState::CLOSED {
            let response_next_byte = input.as_slice().first();
            if response_next_byte.is_none() {
                return self.state_response_complete(input);
            }
            let lf = response_next_byte
                .map(|byte| *byte == b'\n')
                .unwrap_or(false);
            if !lf {
                if let Ok((_, line)) = take_till_lf(work) {
                    self.response_data_consume(input, line.len());
                    work = line;
                } else {
                    return self.handle_response_absent_lf(input);
                }
            } else {
                self.response_data_consume(input, work.len());
            }
        }
        if !self.response_buf.is_empty() {
            self.check_response_buffer_limit(work.len())?;
        }
        let mut data = take(&mut self.response_buf);
        let buf_len = data.len();
        data.add(work);

        if data.is_empty() {
            //closing
            return self.state_response_complete(input);
        }
        if treat_response_line_as_body(&data) {
            // Interpret remaining bytes as body data
            htp_warn!(
                self.logger,
                HtpLogCode::RESPONSE_BODY_UNEXPECTED,
                "Unexpected response body"
            );
            return self.response_body_data(Some(data.as_slice()));
        }
        // didnt use data, restore
        self.response_buf.add(&data[0..buf_len]);
        //unread last end of line so that RES_LINE works
        self.response_data_unconsume(input, data.len());
        self.state_response_complete(input)
    }

    /// The response idle state will initialize response processing, as well as
    /// finalize each transactions after we are done with it.
    ///
    /// Returns HtpStatus::OK on state change, HtpStatus::ERROR on error, or HtpStatus::DATA
    /// when more data is needed.
    pub(crate) fn response_idle(&mut self, input: &ParserData) -> Result<()> {
        // We want to start parsing the next response (and change
        // the state from IDLE) only if there's at least one
        // byte of data available. Otherwise we could be creating
        // new structures even if there's no more data on the
        // connection.
        if input.is_empty() {
            return Err(HtpStatus::DATA);
        }

        // Parsing a new response
        // Log if we have not seen the corresponding request yet
        let resp = self.response();
        if resp.is_none() {
            return Err(HtpStatus::ERROR);
        }
        if resp.unwrap().request_progress == HtpRequestProgress::NOT_STARTED {
            htp_error!(
                self.logger,
                HtpLogCode::UNABLE_TO_MATCH_RESPONSE_TO_REQUEST,
                "Unable to match response to request"
            );
            if self.request_state == State::Finalize {
                let _ = self.state_request_complete(&mut ParserData::from(None));
            }
            let tx = self.response_mut();
            if tx.is_none() {
                return Err(HtpStatus::ERROR);
            }
            let tx = tx.unwrap();

            let uri = Uri {
                path: Some(Bstr::from("/libhtp::request_uri_not_seen")),
                ..Default::default()
            };
            tx.request_uri = uri.path.clone();
            tx.parsed_uri = Some(uri);
            tx.request_progress = HtpRequestProgress::COMPLETE;
            self.request_next();
        }
        self.response_content_length = None;
        self.response_body_data_left = None;
        self.state_response_start()
    }

    /// Run the RESPONSE_BODY_DATA hook.
    fn response_run_hook_body_data(&mut self, d: &mut Data) -> Result<()> {
        // Do not invoke callbacks with an empty data chunk.
        if d.is_empty() {
            return Ok(());
        }
        let resp = self.response().unwrap();
        // Run transaction hooks first
        resp.hook_response_body_data.clone().run_all(self, d)?;
        // Run configuration hooks second
        self.cfg.hook_response_body_data.run_all(self, d)?;
        Ok(())
    }

    /// Process a chunk of outbound (server or response) data.
    pub(crate) fn response_data(
        &mut self, mut chunk: ParserData, timestamp: Option<OffsetDateTime>,
    ) -> HtpStreamState {
        // Reset consumed data tracker
        self.response_bytes_consumed = 0;

        // Return if the connection is in stop state
        if self.response_status == HtpStreamState::STOP {
            htp_info!(
                self.logger,
                HtpLogCode::PARSER_STATE_ERROR,
                "Outbound parser is in HTP_STREAM_STATE_STOP"
            );
            return HtpStreamState::STOP;
        }
        // Return if the connection has had a fatal error
        if self.response_status == HtpStreamState::ERROR {
            htp_error!(
                self.logger,
                HtpLogCode::PARSER_STATE_ERROR,
                "Outbound parser is in HTP_STREAM_STATE_ERROR"
            );
            return HtpStreamState::ERROR;
        }

        // If the length of the supplied data chunk is zero, proceed
        // only if the stream has been closed. We do not allow zero-sized
        // chunks in the API, but we use it internally to force the parsers
        // to finalize parsing.
        if chunk.is_empty() && self.response_status != HtpStreamState::CLOSED {
            htp_error!(
                self.logger,
                HtpLogCode::ZERO_LENGTH_DATA_CHUNKS,
                "Zero-length data chunks are not allowed"
            );
            return HtpStreamState::CLOSED;
        }
        // Remember the timestamp of the current response data chunk
        if let Some(timestamp) = timestamp {
            self.response_timestamp = timestamp;
        }

        // Store the current chunk information
        self.conn.track_outbound_data(chunk.len());
        // Return without processing any data if the stream is in tunneling
        // mode (which it would be after an initial CONNECT transaction.
        if self.response_status == HtpStreamState::TUNNEL {
            return HtpStreamState::TUNNEL;
        }
        if chunk.is_gap() {
            // Mark the transaction as having a gap
            let idx = self.request_index();
            let resp = self.response_mut();
            if resp.is_none() {
                return HtpStreamState::ERROR;
            }
            let resp = resp.unwrap();

            resp.flags.set(HtpFlags::RESPONSE_MISSING_BYTES);

            if idx == 0 && resp.response_progress == HtpResponseProgress::NOT_STARTED {
                // We have a leading gap on the first transaction.
                return HtpStreamState::CLOSED;
            }
        }

        loop
        // Invoke a processor, in a loop, until an error
        // occurs or until we run out of data. Many processors
        // will process a request, each pointing to the next
        // processor that needs to run.
        // Return if there's been an error
        // or if we've run out of data. We are relying
        // on processors to add error messages, so we'll
        // keep quiet here.
        {
            if chunk.is_gap()
                && self.response_state != State::BodyIdentityCLKnown
                && self.response_state != State::BodyIdentityStreamClose
                && self.response_state != State::Finalize
            {
                htp_error!(
                    self.logger,
                    HtpLogCode::INVALID_GAP,
                    "Gaps are not allowed during this state"
                );
                return HtpStreamState::CLOSED;
            }
            let mut rc = self.handle_response_state(&mut chunk);

            if rc.is_ok() {
                if self.response_status == HtpStreamState::TUNNEL {
                    return HtpStreamState::TUNNEL;
                }
                rc = self.response_handle_state_change(&mut chunk);
            }
            match rc {
                // Continue looping.
                Ok(_) => {}
                // Do we need more data?
                Err(HtpStatus::DATA) | Err(HtpStatus::DATA_BUFFER) => {
                    // Ignore result.
                    let _ = self.response_receiver_send_data(&mut chunk);
                    self.response_status = HtpStreamState::DATA;
                    return HtpStreamState::DATA;
                }
                // Check for stop
                Err(HtpStatus::STOP) => {
                    self.response_status = HtpStreamState::STOP;
                    return HtpStreamState::STOP;
                }
                // Check for suspended parsing
                Err(HtpStatus::DATA_OTHER) => {
                    // We might have actually consumed the entire data chunk?
                    if chunk.is_empty() {
                        self.response_status = HtpStreamState::DATA;
                        // Do not send STREAM_DATE_DATA_OTHER if we've
                        // consumed the entire chunk
                        return HtpStreamState::DATA;
                    } else {
                        self.response_status = HtpStreamState::DATA_OTHER;
                        // Partial chunk consumption
                        return HtpStreamState::DATA_OTHER;
                    }
                }
                // Permanent stream error.
                Err(_) => {
                    self.response_status = HtpStreamState::ERROR;
                    return HtpStreamState::ERROR;
                }
            }
        }
    }

    /// Advance out buffer cursor and buffer data.
    fn handle_response_absent_lf(&mut self, data: &ParserData) -> Result<()> {
        self.check_response_buffer_limit(data.len())?;
        self.response_buf.add(data.as_slice());
        self.response_data_consume(data, data.len());
        Err(HtpStatus::DATA_BUFFER)
    }
}
