use crate::{
    bstr::Bstr,
    connection_parser::ConnectionParser,
    error::Result,
    headers::Flags as HeaderFlags,
    parsers::{parse_content_length, parse_protocol, parse_status},
    transaction::{Header, HtpProtocol, HtpResponseNumber},
    util::{
        take_ascii_whitespace, take_is_space, take_is_space_or_null, take_not_is_space,
        FlagOperations, HtpFlags,
    },
    HtpStatus,
};
use nom::{error::ErrorKind, sequence::tuple};
use std::cmp::Ordering;

impl ConnectionParser {
    /// Generic response line parser.
    pub(crate) fn parse_response_line_generic(&mut self, response_line: &[u8]) -> Result<()> {
        let response_tx = self.response_mut();
        response_tx.response_protocol_number = HtpProtocol::Invalid;
        response_tx.response_status = None;
        response_tx.response_status_number = HtpResponseNumber::Invalid;
        response_tx.response_message = None;

        let response_line_parser = tuple::<_, _, (_, ErrorKind), _>((
            take_is_space_or_null,
            take_not_is_space,
            take_is_space,
            take_not_is_space,
            take_ascii_whitespace(),
        ));

        if let Ok((message, (_ls, response_protocol, ws1, status_code, ws2))) =
            response_line_parser(response_line)
        {
            if response_protocol.is_empty() {
                return Ok(());
            }

            response_tx.response_protocol = Some(Bstr::from(response_protocol));
            self.response_mut().response_protocol_number =
                parse_protocol(response_protocol, &mut self.logger);

            if ws1.is_empty() || status_code.is_empty() {
                return Ok(());
            }

            let response_tx = self.response_mut();
            response_tx.response_status = Some(Bstr::from(status_code));
            response_tx.response_status_number = parse_status(status_code);

            if ws2.is_empty() {
                return Ok(());
            }

            response_tx.response_message = Some(Bstr::from(message));
        } else {
            return Err(HtpStatus::ERROR);
        }
        Ok(())
    }

    /// Generic response header parser.
    ///
    ///Returns a tuple of the unparsed data and a boolean indicating if the EOH was seen.
    pub(crate) fn process_response_headers_generic<'a>(
        &mut self,
        data: &'a [u8],
    ) -> Result<(&'a [u8], bool)> {
        let rc = self.response_mut().response_header_parser.headers()(data);
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
                        self.response_mut().flags,
                        flags,
                        HtpFlags::FIELD_INVALID
                    );
                }
                //If there was leading whitespace, probably was invalid folding.
                if name_flags.is_set(HeaderFlags::NAME_LEADING_WHITESPACE) {
                    htp_warn_once!(
                        self.logger,
                        HtpLogCode::Invalid_RESPONSE_FIELD_FOLDING,
                        "Invalid response field folding",
                        self.response_mut().flags,
                        flags,
                        HtpFlags::Invalid_FOLDING
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
                        self.response_mut().flags,
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
                        self.response_mut().flags,
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
                        self.response_mut().flags,
                        flags,
                        HtpFlags::FIELD_INVALID
                    );
                }
                self.process_response_header_generic(Header::new_with_flags(
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

    /// Generic response header line(s) processor, which assembles folded lines
    /// into a single buffer before invoking the parsing function.
    fn process_response_header_generic(&mut self, header: Header) -> Result<()> {
        let mut repeated = false;
        let reps = self.response().response_header_repetitions;
        let mut update_reps = false;
        // Do we already have a header with the same name?
        if let Some((_, h_existing)) = self
            .response_mut()
            .response_headers
            .get_nocase_mut(header.name.as_slice())
        {
            // Keep track of repeated same-name headers.
            if !h_existing.flags.is_set(HtpFlags::FIELD_REPEATED) {
                // This is the second occurence for this header.
                repeated = true;
            } else if reps < 64 {
                update_reps = true;
            } else {
                return Ok(());
            }
            h_existing.flags.set(HtpFlags::FIELD_REPEATED);
            // For simplicity reasons, we count the repetitions of all headers
            // Having multiple C-L headers is against the RFC but many
            // browsers ignore the subsequent headers if the values are the same.
            if header.name.cmp_nocase("Content-Length") == Ordering::Equal {
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
            self.response_mut()
                .response_headers
                .add(header.name.clone(), header);
        }
        if update_reps {
            self.response_mut().response_header_repetitions =
                self.response().response_header_repetitions.wrapping_add(1)
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
}
