use crate::{
    bstr::Bstr,
    config::{Config, MultipartConfig},
    error::Result,
    headers::{Flags as HeaderFlags, Parser as HeadersParser, Side},
    hook::FileDataHook,
    list::List,
    parsers::parse_content_type,
    table::Table,
    transaction::{Header, Headers},
    util::{
        is_space, take_ascii_whitespace, take_is_space, take_until_no_case, File, FlagOperations,
        HtpFileSource,
    },
    HtpStatus,
};
use nom::{
    branch::alt,
    bytes::complete::{tag, tag_no_case, take, take_till, take_until, take_while},
    character::complete::char,
    character::is_space as nom_is_space,
    combinator::{map, not, opt, peek},
    multi::fold_many1,
    number::complete::be_u8,
    sequence::tuple,
    IResult,
};
use std::rc::Rc;

/// Export Multipart flags.
#[derive(Debug)]
pub struct Flags;

impl Flags {
    /// Seen a LF line in the payload. LF lines are not allowed, but
    /// some clients do use them and some backends do accept them. Mixing
    /// LF and CRLF lines within some payload might be unusual.
    pub const LF_LINE: u64 = 0x0001;
    /// Seen a CRLF line in the payload. This is normal and expected.
    pub const CRLF_LINE: u64 = 0x0002;
    /// Seen LWS after a boundary instance in the body. Unusual.
    pub const BBOUNDARY_LWS_AFTER: u64 = 0x0004;
    /// Seen non-LWS content after a boundary instance in the body. Highly unusual.
    pub const BBOUNDARY_NLWS_AFTER: u64 = 0x0008;

    /// Payload has a preamble part. Might not be that unusual.
    pub const HAS_PREAMBLE: u64 = 0x0010;

    /// Payload has an epilogue part. Unusual.
    pub const HAS_EPILOGUE: u64 = 0x0020;

    /// The last boundary was seen in the payload. Absence of the last boundary
    /// may not break parsing with some (most?) backends, but it means that the payload
    /// is not well formed. Can occur if the client gives up, or if the connection is
    /// interrupted. Incomplete payloads should be blocked whenever possible.
    pub const SEEN_LAST_BOUNDARY: u64 = 0x0040;

    /// There was a part after the last boundary. This is highly irregular
    /// and indicative of evasion.
    pub const PART_AFTER_LAST_BOUNDARY: u64 = 0x0080;

    /// The payloads ends abruptly, without proper termination. Can occur if the client gives up,
    /// or if the connection is interrupted. When this flag is raised, PART_INCOMPLETE
    /// will also be raised for the part that was only partially processed. (But the opposite may not
    /// always be the case -- there are other ways in which a part can be left incomplete.)
    pub const INCOMPLETE: u64 = 0x0100;
    /// The boundary in the Content-Type header is invalid.
    pub const HBOUNDARY_INVALID: u64 = 0x0200;

    /// The boundary in the Content-Type header is unusual. This may mean that evasion
    /// is attempted, but it could also mean that we have encountered a client that does
    /// not do things in the way it should.
    pub const HBOUNDARY_UNUSUAL: u64 = 0x0400;

    /// The boundary in the Content-Type header is quoted. This is very unusual,
    /// and may be indicative of an evasion attempt.
    pub const HBOUNDARY_QUOTED: u64 = 0x0800;
    /// Header folding was used in part headers. Very unusual.
    pub const PART_HEADER_FOLDING: u64 = 0x1000;

    /// A part of unknown type was encountered, which probably means that the part is lacking
    /// a Content-Disposition header, or that the header is invalid. Highly unusual.
    pub const PART_UNKNOWN: u64 = 0x2000;
    /// There was a repeated part header, possibly in an attempt to confuse the parser. Very unusual.
    pub const PART_HEADER_REPEATED: u64 = 0x4000;
    /// Unknown part header encountered.
    pub const PART_HEADER_UNKNOWN: u64 = 0x8000;
    /// Invalid part header encountered.
    pub const PART_HEADER_INVALID: u64 = 0x10000;
    /// Part type specified in the C-D header is neither MULTIPART_PART_TEXT nor MULTIPART_PART_FILE.
    pub const CD_TYPE_INVALID: u64 = 0x20000;
    /// Content-Disposition part header with multiple parameters with the same name.
    pub const CD_PARAM_REPEATED: u64 = 0x40000;
    /// Unknown Content-Disposition parameter.
    pub const CD_PARAM_UNKNOWN: u64 = 0x80000;
    /// Invalid Content-Disposition syntax.
    pub const CD_SYNTAX_INVALID: u64 = 0x10_0000;

    /// There is an abruptly terminated part. This can happen when the payload itself is abruptly
    /// terminated (in which case INCOMPLETE) will be raised. However, it can also
    /// happen when a boundary is seen before any part data.
    pub const PART_INCOMPLETE: u64 = 0x20_0000;
    /// A NUL byte was seen in a part header area.
    pub const NUL_BYTE: u64 = 0x40_0000;
    /// A collection of flags that all indicate an invalid C-D header.
    pub const CD_INVALID: u64 = (Self::CD_TYPE_INVALID
        | Self::CD_PARAM_REPEATED
        | Self::CD_PARAM_UNKNOWN
        | Self::CD_SYNTAX_INVALID);
    /// A collection of flags that all indicate an invalid part.
    pub const PART_INVALID: u64 = (Self::CD_INVALID
        | Self::NUL_BYTE
        | Self::PART_UNKNOWN
        | Self::PART_HEADER_REPEATED
        | Self::PART_INCOMPLETE
        | Self::PART_HEADER_UNKNOWN
        | Self::PART_HEADER_INVALID);
    /// A collection of flags that all indicate an invalid Multipart payload.
    pub const INVALID: u64 = (Self::PART_INVALID
        | Self::PART_AFTER_LAST_BOUNDARY
        | Self::INCOMPLETE
        | Self::HBOUNDARY_INVALID);
    /// A collection of flags that all indicate an unusual Multipart payload.
    pub const UNUSUAL: u64 = (Self::INVALID
        | Self::PART_HEADER_FOLDING
        | Self::BBOUNDARY_NLWS_AFTER
        | Self::HAS_EPILOGUE
        | Self::HBOUNDARY_UNUSUAL
        | Self::HBOUNDARY_QUOTED);
    /// A collection of flags that all indicate an unusual Multipart payload, with a low sensitivity to irregularities.
    pub const UNUSUAL_PARANOID: u64 =
        (Self::UNUSUAL | Self::LF_LINE | Self::BBOUNDARY_LWS_AFTER | Self::HAS_PREAMBLE);
}

/// Keeps track of multipart parsing.
#[derive(Clone)]
pub struct Parser {
    /// Contains information regarding multipart body.
    pub multipart: Multipart,
    /// Config structure for multipart parsing.
    pub cfg: MultipartConfig,
    /// Request file data hook invoked whenever file data is available.
    pub hook: FileDataHook,
    /// Number of extracted files.
    pub file_count: u32,
    // Internal parsing fields; move into a private structure
    /// Parser state; one of MULTIPART_STATE_* constants.
    parser_state: HtpMultipartState,

    /// Keeps track of the current position in the boundary matching progress.
    /// When this field reaches boundary_len, we have a boundary match.
    pub boundary_match_pos: usize,

    /// Index of part that is currently being processed.
    pub current_part_idx: Option<usize>,

    /// This parser consists of two layers: the outer layer is charged with
    /// finding parts, and the internal layer handles part data. There is an
    /// interesting interaction between the two parsers. Because the
    /// outer layer is seeing every line (it has to, in order to test for
    /// boundaries), it also effectively also splits input into lines. The
    /// inner parser deals with two areas: first is the headers, which are
    /// line based, followed by binary data. When parsing headers, the inner
    /// parser can reuse the lines identified by the outer parser. In this
    /// variable we keep the current parsing mode of the part, which helps
    /// us process input data more efficiently. The possible values are
    /// LINE and DATA.
    current_part_mode: HtpMultipartMode,

    /// Used for buffering when a potential boundary is fragmented
    /// across many input data buffers. On a match, the data stored here is
    /// discarded. When there is no match, the buffer is processed as data
    /// (belonging to the currently active part).
    pub boundary_candidate: Bstr,
    /// Used for buffering when part header data arrives in pieces.
    pub part_header: Bstr,
    /// Header line to be parsed.
    pub pending_header_line: Bstr,
    /// Working buffer for part header parsing.
    pub to_consume: Bstr,

    /// Stores text part pieces until the entire part is seen, at which
    /// point the pieces are assembled into a single buffer, and the
    /// builder cleared.
    pub part_data_pieces: Bstr,

    /// The offset of the current boundary candidate, relative to the most
    /// recent data chunk (first unprocessed chunk of data).
    pub boundary_candidate_pos: usize,

    /// When we encounter a CR as the last byte in a buffer, we don't know
    /// if the byte is part of a CRLF combination. If it is, then the CR
    /// might be a part of a boundary. But if it is not, it's current
    /// part's data. Because we know how to handle everything before the
    /// CR, we do, and we use this flag to indicate that a CR byte is
    /// effectively being buffered. This is probably a case of premature
    /// optimization, but I am going to leave it in for now.
    pub cr_aside: bool,
}

/// Creates a new multipart/form-data parser.
/// The ownership of the boundary parameter is transferred to the parser.
///
/// Returns New parser instance
impl Parser {
    /// Create new Parser with `Config`, boundary data and flags.
    pub fn new(cfg: &Rc<Config>, boundary: &[u8], flags: u64) -> Self {
        Self {
            multipart: Multipart {
                boundary_len: boundary.len() + 2,
                boundary: Bstr::from([b"--", boundary].concat()),
                boundary_count: 0,
                parts: List::with_capacity(64),
                flags,
            },
            cfg: cfg.multipart_cfg.clone(),
            hook: cfg.hook_request_file_data.clone(),
            file_count: 0,
            // We're starting in boundary-matching mode. The first boundary can appear without the
            // CRLF, and our starting state expects that. If we encounter non-boundary data, the
            // state will switch to data mode. Then, if the data is CRLF or LF, we will go back
            // to boundary matching. Thus, we handle all the possibilities.
            parser_state: HtpMultipartState::BOUNDARY,
            boundary_match_pos: 0,
            current_part_idx: None,
            current_part_mode: HtpMultipartMode::LINE,
            boundary_candidate: Bstr::with_capacity(boundary.len()),
            part_header: Bstr::with_capacity(64),
            pending_header_line: Bstr::with_capacity(64),
            to_consume: Bstr::new(),
            part_data_pieces: Bstr::with_capacity(64),
            boundary_candidate_pos: 0,
            cr_aside: false,
        }
    }

    /// Returns the part currently being processed.
    pub fn get_current_part(&mut self) -> Result<&mut Part> {
        self.current_part_idx
            .and_then(move |idx| self.multipart.parts.get_mut(idx))
            .ok_or(HtpStatus::ERROR)
    }

    /// Handles a boundary event, which means that it will finalize a part if one exists.
    fn handle_boundary(&mut self) -> Result<()> {
        if self.current_part_idx.is_some() {
            self.finalize_part_data()?;
            // We're done with this part
            self.current_part_idx = None;
            // Revert to line mode
            self.current_part_mode = HtpMultipartMode::LINE
        }
        Ok(())
    }

    /// Handles data, creating new parts as necessary.
    fn handle_data(&mut self, is_line: bool) -> Result<()> {
        if self.to_consume.is_empty() {
            return Ok(());
        }
        // Do we have a part already?
        if self.current_part_idx.is_none() {
            // Create a new part.
            let mut part = Part::default();
            // Set current part.
            if self.multipart.boundary_count == 0 {
                part.type_0 = HtpMultipartType::PREAMBLE;
                self.multipart.flags.set(Flags::HAS_PREAMBLE);
                self.current_part_mode = HtpMultipartMode::DATA
            } else {
                // Part after preamble.
                self.current_part_mode = HtpMultipartMode::LINE
            }
            // Add part to the list.
            self.multipart.parts.push(part);
            self.current_part_idx = Some(self.multipart.parts.len() - 1);
        }

        let rc = if self.current_part_idx.is_some() {
            let data = self.to_consume.clone();
            self.handle_part_data(data.as_slice(), is_line)
        } else {
            Ok(())
        };

        self.to_consume.clear();
        rc
    }

    /// Handles part data, updating flags, and creating new headers as necessary.
    pub fn handle_part_data(&mut self, to_consume: &[u8], is_line: bool) -> Result<()> {
        // End of the line.
        let mut line: Option<Bstr> = None;
        // Keep track of raw part length.
        self.get_current_part()?.len += to_consume.len();
        // If we're processing a part that came after the last boundary, then we're not sure if it
        // is the epilogue part or some other part (in case of evasion attempt). For that reason we
        // will keep all its data in the part_data_pieces structure. If it ends up not being the
        // epilogue, this structure will be cleared.
        if self.multipart.flags.is_set(Flags::SEEN_LAST_BOUNDARY)
            && self.get_current_part()?.type_0 == HtpMultipartType::UNKNOWN
        {
            self.part_data_pieces.add(to_consume);
        }
        if self.current_part_mode == HtpMultipartMode::LINE {
            // Line mode.
            if is_line {
                // If this line came to us in pieces, combine them now into a single buffer.
                if !self.part_header.is_empty() {
                    // Allocate string
                    let mut header = Bstr::with_capacity(self.part_header.len() + to_consume.len());
                    header.add(self.part_header.as_slice());
                    header.add(self.to_consume.as_slice());
                    line = Some(header);
                    self.part_header.clear();
                }
                let data = line
                    .as_ref()
                    .map(|line| line.as_slice())
                    .unwrap_or(to_consume);
                // Is it an empty line?
                if data.is_empty() || data.eq(b"\r\n") || data.eq(b"\n") {
                    self.pending_header_line.add(data);
                    // Empty line; process headers and switch to data mode.
                    // Process the pending header, if any.
                    if !self.pending_header_line.is_empty()
                        && self.parse_header() == Err(HtpStatus::ERROR)
                    {
                        return Err(HtpStatus::ERROR);
                    }
                    if self.parse_c_d() == Err(HtpStatus::ERROR) {
                        return Err(HtpStatus::ERROR);
                    }
                    if let Some((_, header)) = self
                        .get_current_part()?
                        .headers
                        .get_nocase_nozero("content-type")
                    {
                        self.get_current_part()?.content_type =
                            Some(parse_content_type(header.value.as_slice())?);
                    }
                    self.current_part_mode = HtpMultipartMode::DATA;
                    self.part_header.clear();
                    let file_count = self.file_count;
                    let cfg = self.cfg.clone();
                    let part = self.get_current_part()?;
                    match &mut part.file {
                        Some(file) => {
                            // Changing part type because we have a filename.
                            part.type_0 = HtpMultipartType::FILE;
                            if cfg.extract_request_files
                                && file_count < cfg.extract_request_files_limit
                            {
                                file.create(&cfg.tmpdir)?;
                                self.file_count += 1;
                            }
                        }
                        None => {
                            if !self.get_current_part()?.name.is_empty() {
                                // Changing part type because we have a name.
                                self.get_current_part()?.type_0 = HtpMultipartType::TEXT;
                                self.part_data_pieces.clear();
                            }
                        }
                    }
                } else if let Some(header) = line {
                    self.pending_header_line.add(header.as_slice());
                } else {
                    self.pending_header_line.add(data);
                }
            } else {
                // Not end of line; keep the data chunk for later.
                self.part_header.add(to_consume);
            }
        } else {
            // Data mode; keep the data chunk for later (but not if it is a file).
            match self.get_current_part()?.type_0 {
                HtpMultipartType::FILE => {
                    // Invoke file data callbacks.
                    // Ignore error.
                    let _ = self.run_request_file_data_hook(false);
                    // Optionally, store the data in a file.
                    if let Some(file) = &mut self.get_current_part()?.file {
                        return file.write(to_consume);
                    }
                }
                _ => {
                    // Make a copy of the data in RAM.
                    self.part_data_pieces.add(to_consume);
                }
            }
        }
        Ok(())
    }

    /// Processes set-aside data.
    fn process_aside(&mut self, matched: bool) {
        // The stored data pieces can contain up to one line. If we're in data mode and there
        // was no boundary match, things are straightforward -- we process everything as data.
        // If there was a match, we need to take care to not send the line ending as data, nor
        // anything that follows (because it's going to be a part of the boundary). Similarly,
        // when we are in line mode, we need to split the first data chunk, processing the first
        // part as line and the second part as data.
        // Do we need to do any chunk splitting?
        if matched || self.current_part_mode == HtpMultipartMode::LINE {
            // Line mode or boundary match
            if matched {
                if self.to_consume.last() == Some(&(b'\n')) {
                    self.to_consume.pop();
                }
                if self.to_consume.last() == Some(&(b'\r')) {
                    self.to_consume.pop();
                }
            } else {
                // Process the CR byte, if set aside.
                if self.cr_aside {
                    self.to_consume.add("\r");
                }
            }
            // Ignore result.
            let _ = self.handle_data(self.current_part_mode == HtpMultipartMode::LINE);
            self.cr_aside = false;
            // We know that we went to match a boundary because
            // we saw a new line. Now we have to find that line and
            // process it. It's either going to be in the current chunk,
            // or in the first stored chunk.

            // Split the first chunk.
            // In line mode, we are OK with line endings.
            // This should be unnecessary, but as a precaution check for min value:
            let pos = std::cmp::min(self.boundary_candidate_pos, self.boundary_candidate.len());
            self.to_consume.add(&self.boundary_candidate[..pos]);
            // Ignore result.
            let _ = self.handle_data(!matched);
            // The second part of the split chunks belongs to the boundary
            // when matched, data otherwise.
            if !matched {
                self.to_consume.add(&self.boundary_candidate[pos..]);
            }
        } else {
            // Do not send data if there was a boundary match. The stored
            // data belongs to the boundary.
            // Data mode and no match.
            // In data mode, we process the lone CR byte as data.

            // Treat as part data, when there is not a match.
            if self.cr_aside {
                self.to_consume.add("\r");
                self.cr_aside = false;
            }
            // We then process any pieces that we might have stored, also as data.
            self.to_consume.add(self.boundary_candidate.as_slice());
        }
        self.boundary_candidate.clear();
        // Ignore result.
        let _ = self.handle_data(false);
    }

    /// Finalize parsing.
    pub fn finalize(&mut self) -> Result<()> {
        if self.current_part_idx.is_some() {
            // Process buffered data, if any.
            self.process_aside(false);
            // Finalize the last part.
            self.finalize_part_data()?;
            // It is OK to end abruptly in the epilogue part, but not in any other.
            if self.get_current_part()?.type_0 != HtpMultipartType::EPILOGUE {
                self.multipart.flags.set(Flags::INCOMPLETE)
            }
        }
        self.boundary_candidate.clear();
        Ok(())
    }

    /// Finalizes part processing.
    pub fn finalize_part_data(&mut self) -> Result<()> {
        // Determine if this part is the epilogue.
        if self.multipart.flags.is_set(Flags::SEEN_LAST_BOUNDARY) {
            if self.get_current_part()?.type_0 == HtpMultipartType::UNKNOWN {
                // Assume that the unknown part after the last boundary is the epilogue.
                self.get_current_part()?.type_0 = HtpMultipartType::EPILOGUE;

                // But if we've already seen a part we thought was the epilogue,
                // raise PART_UNKNOWN. Multiple epilogues are not allowed.
                if self.multipart.flags.is_set(Flags::HAS_EPILOGUE) {
                    self.multipart.flags.set(Flags::PART_UNKNOWN)
                }
                self.multipart.flags.set(Flags::HAS_EPILOGUE)
            } else {
                self.multipart.flags.set(Flags::PART_AFTER_LAST_BOUNDARY)
            }
        }
        // Sanity checks.
        // Have we seen complete part headers? If we have not, that means that the part ended prematurely.
        if self.get_current_part()?.type_0 != HtpMultipartType::EPILOGUE
            && self.current_part_mode != HtpMultipartMode::DATA
        {
            self.multipart.flags.set(Flags::PART_INCOMPLETE)
        }
        // Have we been able to determine the part type? If not, this means
        // that the part did not contain the C-D header.
        if self.get_current_part()?.type_0 == HtpMultipartType::UNKNOWN {
            self.multipart.flags.set(Flags::PART_UNKNOWN)
        }
        // Finalize part value.
        if self.get_current_part()?.type_0 == HtpMultipartType::FILE {
            // Notify callbacks about the end of the file.
            // Ignore result.
            let _ = self.run_request_file_data_hook(true);
        } else if !self.part_data_pieces.is_empty() {
            let data = self.part_data_pieces.clone();
            self.get_current_part()?.value.clear();
            self.get_current_part()?.value.add(data.as_slice());
            self.part_data_pieces.clear();
        }
        Ok(())
    }

    /// Returns the multipart structure created by the parser.
    pub fn get_multipart(&mut self) -> &mut Multipart {
        &mut self.multipart
    }

    /// Handle part data. This function will also buffer a CR character if
    /// it is the last byte in the buffer.
    fn parse_state_data<'a>(&mut self, input: &'a [u8]) -> &'a [u8] {
        if let Ok((remaining, mut consumed)) = take_till::<_, _, (&[u8], nom::error::ErrorKind)>(
            |c: u8| c == b'\r' || c == b'\n',
        )(input)
        {
            if let Ok((left, _)) = tag::<_, _, (&[u8], nom::error::ErrorKind)>("\r\n")(remaining) {
                consumed = &input[..consumed.len() + 2];
                self.multipart.flags.set(Flags::CRLF_LINE);
                // Prepare to switch to boundary testing.
                self.parser_state = HtpMultipartState::BOUNDARY;
                self.boundary_match_pos = 0;
                self.to_consume.add(consumed);
                return left;
            } else if let Ok((left, _)) = char::<_, (&[u8], nom::error::ErrorKind)>('\r')(remaining)
            {
                if left.is_empty() {
                    // We have CR as the last byte in input. We are going to process
                    // what we have in the buffer as data, except for the CR byte,
                    // which we're going to leave for later. If it happens that a
                    // CR is followed by a LF and then a boundary, the CR is going
                    // to be discarded.
                    self.cr_aside = true
                } else {
                    // This is not a new line; advance over the
                    // byte and clear the CR set-aside flag.
                    consumed = &input[..consumed.len() + 1];
                    self.cr_aside = false;
                }
                self.to_consume.add(consumed);
                return left;
            } else if let Ok((left, _)) = char::<_, (&[u8], nom::error::ErrorKind)>('\n')(remaining)
            {
                // Check for a LF-terminated line.
                // Advance over LF.
                // Did we have a CR in the previous input chunk?
                consumed = &input[..consumed.len() + 1];
                if !self.cr_aside {
                    self.multipart.flags.set(Flags::LF_LINE)
                } else {
                    self.to_consume.add("\r");
                    self.cr_aside = false;
                    self.multipart.flags.set(Flags::CRLF_LINE)
                }
                self.to_consume.add(consumed);
                // Prepare to switch to boundary testing.
                self.boundary_match_pos = 0;
                self.parser_state = HtpMultipartState::BOUNDARY;
                return left;
            } else if self.cr_aside {
                (self.to_consume).add("\r");
                self.cr_aside = false;
            }
            (self.to_consume).add(consumed);
            // Ignore result.
            let _ = self.handle_data(false);
            remaining
        } else {
            input
        }
    }

    /// Handle possible boundary.
    fn parse_state_boundary<'a>(&mut self, input: &'a [u8]) -> &'a [u8] {
        if self.multipart.boundary.len() < self.boundary_match_pos {
            // This should never hit
            // Process stored (buffered) data.
            self.process_aside(false);
            // Return back where data parsing left off.
            self.parser_state = HtpMultipartState::DATA;
            return input;
        }
        let len = std::cmp::min(
            self.multipart.boundary.len() - self.boundary_match_pos,
            input.len(),
        );
        if let Ok((remaining, consumed)) = tag::<&[u8], _, (&[u8], nom::error::ErrorKind)>(
            &self.multipart.boundary[self.boundary_match_pos..self.boundary_match_pos + len]
                .to_vec(),
        )(input)
        {
            self.boundary_match_pos = self.boundary_match_pos.wrapping_add(len);
            if self.boundary_match_pos == self.multipart.boundary_len {
                // Boundary match!
                // Process stored (buffered) data.
                self.process_aside(true);
                // Keep track of how many boundaries we've seen.
                self.multipart.boundary_count += 1;
                if self.multipart.flags.is_set(Flags::SEEN_LAST_BOUNDARY) {
                    self.multipart.flags.set(Flags::PART_AFTER_LAST_BOUNDARY)
                }
                // Run boundary match.
                let _ = self.handle_boundary();
                // We now need to check if this is the last boundary in the payload
                self.parser_state = HtpMultipartState::BOUNDARY_IS_LAST1;
            } else {
                // No more data in the input buffer; store (buffer) the unprocessed
                // part for later, for after we find out if this is a boundary.
                self.boundary_candidate.add(consumed);
            }
            remaining
        } else {
            // Boundary mismatch.
            // Process stored (buffered) data.
            self.process_aside(false);
            // Return back where data parsing left off.
            self.parser_state = HtpMultipartState::DATA;
            input
        }
    }

    /// Determine if we have another boundary to process or not.
    /// Examine the first byte after the last boundary character. If it is
    /// a dash, then we maybe processing the last boundary in the payload. If
    /// it is not, move to eat all bytes until the end of the line.
    fn parse_state_last1<'a>(&mut self, input: &'a [u8]) -> &'a [u8] {
        if let Ok((remaining, _)) = char::<_, (&[u8], nom::error::ErrorKind)>('-')(input) {
            // Found one dash, now go to check the next position.
            self.parser_state = HtpMultipartState::BOUNDARY_IS_LAST2;
            remaining
        } else {
            // This is not the last boundary. Change state but
            // do not advance the position, allowing the next
            // state to process the byte.
            self.parser_state = HtpMultipartState::BOUNDARY_EAT_LWS;
            input
        }
    }

    /// Determine if we have another boundary to process or not.
    /// Examine the byte after the first dash; expected to be another dash.
    /// If not, eat all bytes until the end of the line.
    fn parse_state_last2<'a>(&mut self, input: &'a [u8]) -> &'a [u8] {
        if let Ok((remaining, _)) = char::<_, (&[u8], nom::error::ErrorKind)>('-')(input) {
            // This is indeed the last boundary in the payload.
            self.multipart.flags.set(Flags::SEEN_LAST_BOUNDARY);
            self.parser_state = HtpMultipartState::BOUNDARY_EAT_LWS;
            remaining
        } else {
            // The second character is not a dash, and so this is not
            // the final boundary. Raise the flag for the first dash,
            // and change state to consume the rest of the boundary line.
            self.multipart.flags.set(Flags::BBOUNDARY_NLWS_AFTER);
            self.parser_state = HtpMultipartState::BOUNDARY_EAT_LWS;
            input
        }
    }

    /// Determines state of boundary parsing. Advances state if we're done with boundary
    /// processing.
    fn parse_state_lws<'a>(&mut self, input: &'a [u8]) -> &'a [u8] {
        if let Ok((remaining, _)) = tag::<_, _, (&[u8], nom::error::ErrorKind)>("\r\n")(input) {
            // CRLF line ending; we're done with boundary processing; data bytes follow.
            self.multipart.flags.set(Flags::CRLF_LINE);
            self.parser_state = HtpMultipartState::DATA;
            remaining
        } else if let Ok((remaining, byte)) = be_u8::<(&[u8], nom::error::ErrorKind)>(input) {
            if byte == b'\n' {
                // LF line ending; we're done with boundary processing; data bytes follow.
                self.multipart.flags.set(Flags::LF_LINE);
                self.parser_state = HtpMultipartState::DATA;
            } else if nom_is_space(byte) {
                // Linear white space is allowed here.
                self.multipart.flags.set(Flags::BBOUNDARY_LWS_AFTER);
            } else {
                // Unexpected byte; consume, but remain in the same state.
                self.multipart.flags.set(Flags::BBOUNDARY_NLWS_AFTER);
            }
            remaining
        } else {
            input
        }
    }

    /// Parses a chunk of multipart/form-data data. This function should be called
    /// as many times as necessary until all data has been consumed.
    pub fn parse(&mut self, mut input: &[u8]) -> HtpStatus {
        while !input.is_empty() {
            match self.parser_state {
                HtpMultipartState::DATA => {
                    input = self.parse_state_data(input);
                }
                HtpMultipartState::BOUNDARY => {
                    input = self.parse_state_boundary(input);
                }
                HtpMultipartState::BOUNDARY_IS_LAST1 => {
                    input = self.parse_state_last1(input);
                }
                HtpMultipartState::BOUNDARY_IS_LAST2 => {
                    input = self.parse_state_last2(input);
                }
                HtpMultipartState::BOUNDARY_EAT_LWS => {
                    input = self.parse_state_lws(input);
                }
            }
        }
        HtpStatus::OK
    }

    /// Parses one part header.
    ///
    /// Returns HtpStatus::OK on success, HtpStatus::DECLINED on parsing error, HtpStatus::ERROR
    /// on fatal error.
    pub fn parse_header(&mut self) -> Result<()> {
        // We do not allow NUL bytes here.
        if self.pending_header_line.as_slice().contains(&(b'\0')) {
            self.multipart.flags.set(Flags::NUL_BYTE);
            return Err(HtpStatus::DECLINED);
        }
        // Extract the name and the value
        let parser = HeadersParser::new(Side::Request);
        if let Ok((remaining, (headers, _))) = parser.headers()(self.pending_header_line.as_slice())
        {
            let remaining = remaining.to_vec();
            for header in headers {
                let value_flags = &header.value.flags;
                let name_flags = &header.name.flags;
                if value_flags.is_set(HeaderFlags::FOLDING) {
                    self.multipart.flags.set(Flags::PART_HEADER_FOLDING)
                }
                if value_flags.is_set(HeaderFlags::VALUE_EMPTY)
                    || name_flags.is_set(HeaderFlags::NAME_LEADING_WHITESPACE)
                    || name_flags.is_set(HeaderFlags::NAME_EMPTY)
                    || name_flags.is_set(HeaderFlags::NAME_NON_TOKEN_CHARS)
                    || name_flags.is_set(HeaderFlags::NAME_TRAILING_WHITESPACE)
                {
                    // Invalid name and/or value found
                    self.multipart.flags.set(Flags::PART_HEADER_INVALID);
                }
                // Now extract the name and the value.
                let header = Header::new(header.name.name.into(), header.value.value.into());
                if !header.name.eq_nocase("content-disposition")
                    && !header.name.eq_nocase("content-type")
                {
                    self.multipart.flags.set(Flags::PART_HEADER_UNKNOWN)
                }
                // Check if the header already exists.
                if let Some((_, h_existing)) = self
                    .get_current_part()?
                    .headers
                    .get_nocase_mut(header.name.as_slice())
                {
                    h_existing.value.extend_from_slice(b", ");
                    h_existing.value.extend_from_slice(header.value.as_slice());
                    // Keep track of same-name headers.
                    // FIXME: Normalize the flags? define the symbol in both Flags and Flags and set the value in both from their own namespace
                    h_existing.flags.set(Flags::PART_HEADER_REPEATED);
                    self.multipart.flags.set(Flags::PART_HEADER_REPEATED)
                } else {
                    self.get_current_part()?
                        .headers
                        .add(header.name.clone(), header);
                }
            }
            self.pending_header_line.clear();
            self.pending_header_line.add(remaining);
        } else {
            // Invalid name and/or value found
            self.multipart.flags.set(Flags::PART_HEADER_INVALID);
            return Err(HtpStatus::DECLINED);
        }
        Ok(())
    }

    /// Parses the Content-Disposition part header.
    ///
    /// Returns OK on success (header found and parsed), DECLINED if there is no C-D header or if
    ///         it could not be processed, and ERROR on fatal error.
    pub fn parse_c_d(&mut self) -> Result<()> {
        // Find the C-D header.
        let part = self.get_current_part()?;
        let header = {
            if let Some((_, header)) = part.headers.get_nocase_nozero_mut("content-disposition") {
                header
            } else {
                self.multipart.flags.set(Flags::PART_UNKNOWN);
                return Err(HtpStatus::DECLINED);
            }
        };

        // Require "form-data" at the beginning of the header.
        if let Ok((_, params)) = content_disposition((*header.value).as_slice()) {
            for (param_name, param_value) in params {
                match param_name {
                    b"name" => {
                        // If we've reached the end of the string that means the
                        // value was not terminated properly (the second double quote is missing).
                        // Expecting the terminating double quote.
                        // Over the terminating double quote.
                        // Finally, process the parameter value.
                        // Check that we have not seen the name parameter already.
                        if !part.name.is_empty() {
                            self.multipart.flags.set(Flags::CD_PARAM_REPEATED);
                            return Err(HtpStatus::DECLINED);
                        }
                        part.name.clear();
                        part.name.add(param_value);
                    }
                    b"filename" => {
                        // Check that we have not seen the filename parameter already.
                        match part.file {
                            Some(_) => {
                                self.multipart.flags.set(Flags::CD_PARAM_REPEATED);
                                return Err(HtpStatus::DECLINED);
                            }
                            None => {
                                part.file = Some(File::new(
                                    HtpFileSource::MULTIPART,
                                    Some(Bstr::from(param_value)),
                                ));
                            }
                        };
                    }
                    _ => {
                        // Unknown parameter.
                        self.multipart.flags.set(Flags::CD_PARAM_UNKNOWN);
                        return Err(HtpStatus::DECLINED);
                    }
                }
            }
        } else {
            self.multipart.flags.set(Flags::CD_SYNTAX_INVALID);
            return Err(HtpStatus::DECLINED);
        }
        Ok(())
    }

    /// Send file data to request file data callback.
    pub fn run_request_file_data_hook(&mut self, is_end: bool) -> Result<()> {
        //TODO: do without these clones!
        let data = self.to_consume.clone();
        let data = if !is_end { data.as_slice() } else { b"" };
        let hook = self.hook.clone();
        match &mut self.get_current_part()?.file {
            // Combine value pieces into a single buffer.
            // Keep track of the file length.
            Some(file) => {
                // Send data to callbacks
                file.handle_file_data(hook, data.as_ptr(), data.len())
            }
            None => Ok(()),
        }
    }
}

/// Holds information related to a part.
#[derive(Clone)]
pub struct Part {
    /// Part type; see the * constants.
    pub type_0: HtpMultipartType,
    /// Raw part length (i.e., headers and data).
    pub len: usize,
    /// Part name, from the Content-Disposition header. Can be empty.
    pub name: Bstr,

    /// Part value; the contents depends on the type of the part:
    /// 1) empty for files; 2) contains complete part contents for
    /// preamble and epilogue parts (they have no headers), and
    /// 3) data only (headers excluded) for text and unknown parts.
    pub value: Bstr,
    /// Part content type, from the Content-Type header. Can be None.
    pub content_type: Option<Bstr>,
    /// Part headers (Header instances), using header name as the key.
    pub headers: Headers,
    /// File data, available only for FILE parts.
    pub file: Option<File>,
}

impl Default for Part {
    fn default() -> Self {
        Self {
            type_0: HtpMultipartType::UNKNOWN,
            len: 0,
            name: Bstr::with_capacity(64),
            value: Bstr::with_capacity(64),
            content_type: None,
            headers: Table::with_capacity(4),
            file: None,
        }
    }
}

impl Drop for Part {
    fn drop(&mut self) {
        self.file = None;
        self.headers.elements.clear();
    }
}

/// Enumerates the current multipart mode.
/// cbindgen:rename-all=QualifiedScreamingSnakeCase
#[repr(C)]
#[derive(Copy, Clone, PartialEq, Debug)]
enum HtpMultipartMode {
    /// When in line mode, the parser is handling part headers.
    LINE,
    /// When in data mode, the parser is consuming part data.
    DATA,
}

/// Enumerates the multipart parsing state.
/// cbindgen:rename-all=QualifiedScreamingSnakeCase
#[repr(C)]
#[derive(Copy, Clone, PartialEq, Debug)]
enum HtpMultipartState {
    /// Processing data, waiting for a new line (which might indicate a new boundary).
    DATA,
    /// Testing a potential boundary.
    BOUNDARY,
    /// Checking the first byte after a boundary.
    BOUNDARY_IS_LAST1,
    /// Checking the second byte after a boundary.
    BOUNDARY_IS_LAST2,
    /// Consuming linear whitespace after a boundary.
    BOUNDARY_EAT_LWS,
}

/// Enumerates the multipart type.
/// cbindgen:rename-all=QualifiedScreamingSnakeCase
#[repr(C)]
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum HtpMultipartType {
    /// Unknown part.
    UNKNOWN,
    /// Text (parameter) part.
    TEXT,
    /// File part.
    FILE,
    /// Free-text part before the first boundary.
    PREAMBLE,
    /// Free-text part after the last boundary.
    EPILOGUE,
}

/// Holds information related to a multipart body.
#[derive(Clone)]
pub struct Multipart {
    /// Multipart boundary.
    pub boundary: Bstr,
    /// Boundary length.
    pub boundary_len: usize,
    /// How many boundaries were there?
    pub boundary_count: i32,
    /// List of parts, in the order in which they appeared in the body.
    pub parts: List<Part>,
    /// Parsing flags.
    pub flags: u64,
}

/// Extracts and decodes a C-D header param name and value following a form-data. This is impossible to do correctly without a
/// parsing personality because most browsers are broken:
///  - Firefox encodes " as \", and \ is not encoded.
///  - Chrome encodes " as %22.
///  - IE encodes " as \", and \ is not encoded.
///  - Opera encodes " as \" and \ as \\.
fn content_disposition_param() -> impl Fn(&[u8]) -> IResult<&[u8], (&[u8], Vec<u8>)> {
    move |input| {
        let (mut remaining_input, param_name) = map(
            tuple((
                take_ascii_whitespace(),
                char(';'),
                take_ascii_whitespace(),
                take_while(|c: u8| c != b'=' && !c.is_ascii_whitespace()),
                take_ascii_whitespace(),
                char('='),
                take_ascii_whitespace(),
                char('\"'), //must start with opening quote
            )),
            |(_, _, _, param_name, _, _, _, _)| param_name,
        )(input)?;
        // Unescape any escaped " and \ and find the closing "
        let mut param_value = Vec::new();
        loop {
            let (left, (value, to_insert)) = tuple((
                take_while(|c| c != b'\"' && c != b'\\'),
                opt(tuple((char('\\'), alt((char('\"'), char('\\')))))),
            ))(remaining_input)?;
            remaining_input = left;
            param_value.extend_from_slice(value);
            if let Some((_, to_insert)) = to_insert {
                // Insert the character
                param_value.push(to_insert as u8);
            } else {
                // Must end with a quote or it is invalid
                let (left, _) = char('\"')(remaining_input)?;
                remaining_input = left;
                break;
            }
        }
        Ok((remaining_input, (param_name, param_value)))
    }
}

/// Extracts and decodes a C-D header param names and values. This is impossible to do correctly without a
/// parsing personality because most browsers are broken:
///  - Firefox encodes " as \", and \ is not encoded.
///  - Chrome encodes " as %22.
///  - IE encodes " as \", and \ is not encoded.
///  - Opera encodes " as \" and \ as \\.
fn content_disposition(input: &[u8]) -> IResult<&[u8], Vec<(&[u8], Vec<u8>)>> {
    // Multiple header values are seperated by a ", ": https://tools.ietf.org/html/rfc7230#section-3.2.2
    map(
        tuple((
            tag("form-data"),
            fold_many1(
                tuple((
                    content_disposition_param(),
                    take_ascii_whitespace(),
                    opt(tuple((tag(","), take_ascii_whitespace(), tag("form-data")))),
                    take_ascii_whitespace(),
                )),
                Vec::new(),
                |mut acc: Vec<(&[u8], Vec<u8>)>, (param, _, _, _)| {
                    acc.push(param);
                    acc
                },
            ),
            take_ascii_whitespace(),
            opt(tag(";")), // Allow trailing semicolon,
            take_ascii_whitespace(),
            not(take(1usize)), // We should have no data left, or we exited parsing prematurely
        )),
        |(_, result, _, _, _, _)| result,
    )(input)
}
/// Validates a multipart boundary according to RFC 1341:
///
///    The only mandatory parameter for the multipart  Content-Type
///    is  the  boundary  parameter,  which  consists  of  1  to 70
///    characters from a set of characters known to be very  robust
///    through  email  gateways,  and  NOT ending with white space.
///    (If a boundary appears to end with white  space,  the  white
///    space  must be presumed to have been added by a gateway, and
///    should  be  deleted.)   It  is  formally  specified  by  the
///    following BNF:
///
///    boundary := 0*69<bchars> bcharsnospace
///
///    bchars := bcharsnospace / " "
///
///    bcharsnospace :=    DIGIT / ALPHA / "'" / "(" / ")" / "+" / "_"
///                          / "," / "-" / "." / "/" / ":" / "=" / "?"
///
///    Chrome: Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryT4AfwQCOgIxNVwlD
///    Firefox: Content-Type: multipart/form-data; boundary=---------------------------21071316483088
///    MSIE: Content-Type: multipart/form-data; boundary=---------------------------7dd13e11c0452
///    Opera: Content-Type: multipart/form-data; boundary=----------2JL5oh7QWEDwyBllIRc7fh
///    Safari: Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryre6zL3b0BelnTY5S
///
/// Returns in flags the appropriate Flags
fn validate_boundary(boundary: &[u8], flags: &mut u64) {
    // The RFC allows up to 70 characters. In real life,
    // boundaries tend to be shorter.
    if boundary.is_empty() || boundary.len() > 70 {
        flags.set(Flags::HBOUNDARY_INVALID)
    }
    // Check boundary characters. This check is stricter than the
    // RFC, which seems to allow many separator characters.
    for byte in boundary {
        if !byte.is_ascii_alphanumeric() && *byte != b'-' {
            match *byte as char {
                '\'' | '(' | ')' | '+' | '_' | ',' | '.' | '/' | ':' | '=' | '?' => {
                    // These characters are allowed by the RFC, but not common.
                    flags.set(Flags::HBOUNDARY_UNUSUAL)
                }
                _ => {
                    // Invalid character.
                    flags.set(Flags::HBOUNDARY_INVALID)
                }
            }
        }
    }
}

/// Validates the content type by checking if there are multiple boundary occurrences or any occurrence contains uppercase characters
///
/// Returns in flags the appropriate Flags
fn validate_content_type(content_type: &[u8], flags: &mut u64) {
    if let Ok((_, (f, _))) = fold_many1(
        tuple((
            take_until_no_case(b"boundary"),
            tag_no_case("boundary"),
            take_until("="),
            tag("="),
        )),
        (0, false),
        |(mut flags, mut seen_prev): (u64, bool), (_, boundary, _, _): (_, &[u8], _, _)| {
            for byte in boundary {
                if byte.is_ascii_uppercase() {
                    flags.set(Flags::HBOUNDARY_INVALID);
                    break;
                }
            }
            if seen_prev {
                // Seen multiple boundaries
                flags.set(Flags::HBOUNDARY_INVALID)
            }
            seen_prev = true;
            (flags, seen_prev)
        },
    )(content_type)
    {
        flags.set(f);
    } else {
        // There must be at least one occurrence!
        flags.set(Flags::HBOUNDARY_INVALID);
    }
}

/// Attempts to locate and extract the boundary from an input slice, returning a tuple of the matched
/// boundary and any leading/trailing whitespace and non whitespace characters that might be relevant
fn boundary() -> impl Fn(
    &[u8],
) -> IResult<
    &[u8],
    (
        &[u8],
        &[u8],
        &[u8],
        Option<char>,
        &[u8],
        Option<char>,
        &[u8],
        &[u8],
    ),
> {
    move |input| {
        map(
            tuple((
                take_until_no_case(b"boundary"),
                tag_no_case("boundary"),
                take_is_space,
                take_until("="),
                tag("="),
                take_is_space,
                peek(opt(char('\"'))),
                alt((
                    map(tuple((tag("\""), take_until("\""))), |(_, boundary)| {
                        boundary
                    }),
                    map(
                        tuple((
                            take_while(|c: u8| c != b',' && c != b';' && !is_space(c)),
                            opt(alt((char(','), char(';')))), //Skip the matched character if we matched one without hitting the end
                        )),
                        |(boundary, _)| boundary,
                    ),
                )),
                peek(opt(char('\"'))),
                take_is_space,
                take_while(|c| !is_space(c)),
            )),
            |(
                _,
                _,
                spaces_before_equal,
                chars_before_equal,
                _,
                spaces_after_equal,
                opening_quote,
                boundary,
                closing_quote,
                spaces_after_boundary,
                chars_after_boundary,
            )| {
                (
                    spaces_before_equal,
                    chars_before_equal,
                    spaces_after_equal,
                    opening_quote,
                    boundary,
                    closing_quote,
                    spaces_after_boundary,
                    chars_after_boundary,
                )
            },
        )(input)
    }
}

/// Looks for boundary in the supplied Content-Type request header.
///
/// Returns in multipart_flags: Multipart flags, which are not compatible from general LibHTP flags.
///
/// Returns boundary if found, None otherwise.
/// Flags may be set on even without successfully locating the boundary. For
/// example, if a boundary could not be extracted but there is indication that
/// one is present, the HBOUNDARY_INVALID flag will be set.
pub fn find_boundary<'a>(content_type: &'a [u8], flags: &mut u64) -> Option<&'a [u8]> {
    // Our approach is to ignore the MIME type and instead just look for
    // the boundary. This approach is more reliable in the face of various
    // evasion techniques that focus on submitting invalid MIME types.
    // Reset flags.
    *flags = 0;
    // Correlate with the MIME type. This might be a tad too
    // sensitive because it may catch non-browser access with sloppy
    // implementations, but let's go with it for now.
    if !content_type.starts_with(b"multipart/form-data;") {
        flags.set(Flags::HBOUNDARY_INVALID)
    }
    // Look for the boundary, case insensitive.
    if let Ok((
        _,
        (
            spaces_before_equal,
            chars_before_equal,
            spaces_after_equal,
            opening_quote,
            boundary,
            closing_quote,
            spaces_after_boundary,
            chars_after_boundary,
        ),
    )) = boundary()(content_type)
    {
        if !spaces_before_equal.is_empty()
            || !spaces_after_equal.is_empty()
            || opening_quote.is_some()
            || (chars_after_boundary.is_empty() && !spaces_after_boundary.is_empty())
        {
            // It is unusual to see whitespace before and/or after the equals sign.
            // Unusual to have a quoted boundary
            // Unusual but allowed to have only whitespace after the boundary
            flags.set(Flags::HBOUNDARY_UNUSUAL)
        }
        if !chars_before_equal.is_empty()
            || (opening_quote.is_some() && closing_quote.is_none())
            || (opening_quote.is_none() && closing_quote.is_some())
            || !chars_after_boundary.is_empty()
        {
            // Seeing a non-whitespace character before equal sign may indicate evasion
            // Having an opening quote, but no closing quote is invalid
            // Seeing any character after the boundary, other than whitespace is invalid
            flags.set(Flags::HBOUNDARY_INVALID)
        }
        if boundary.is_empty() {
            flags.set(Flags::HBOUNDARY_INVALID);
            return None;
        }
        // Validate boundary characters.
        validate_boundary(boundary, flags);
        validate_content_type(content_type, flags);
        Some(boundary)
    } else {
        flags.set(Flags::HBOUNDARY_INVALID);
        None
    }
}

#[test]
fn Boundary() {
    let inputs: Vec<&[u8]> = vec![
        b"multipart/form-data; boundary=myboundarydata",
        b"multipart/form-data; BounDary=myboundarydata",
        b"multipart/form-data; boundary   =myboundarydata",
        b"multipart/form-data; boundary=   myboundarydata",
        b"multipart/form-data; boundary=myboundarydata ",
        b"multipart/form-data; boundary=myboundarydata, ",
        b"multipart/form-data; boundary=myboundarydata, boundary=secondboundarydata",
        b"multipart/form-data; boundary=myboundarydata; ",
        b"multipart/form-data; boundary=myboundarydata; boundary=secondboundarydata",
        b"multipart/form-data; boundary=\"myboundarydata\"",
        b"multipart/form-data; boundary=   \"myboundarydata\"",
        b"multipart/form-data; boundary=\"myboundarydata\"  ",
    ];

    for input in inputs {
        let (_, (_, _, _, _, b, _, _, _)) = boundary()(input).unwrap();
        assert_eq!(b, b"myboundarydata");
    }

    let (_, (_, _, _, _, b, _, _, _)) =
        boundary()(b"multipart/form-data; boundary=\"myboundarydata").unwrap();
    assert_eq!(b, b"\"myboundarydata");

    let (_, (_, _, _, _, b, _, _, _)) =
        boundary()(b"multipart/form-data; boundary=   myboundarydata\"").unwrap();
    assert_eq!(b, b"myboundarydata\"");
}

#[test]
fn ValidateBoundary() {
    let inputs: Vec<&[u8]> = vec![
        b"Unusual\'Boundary",
        b"Unusual(Boundary",
        b"Unusual)Boundary",
        b"Unusual+Boundary",
        b"Unusual_Boundary",
        b"Unusual,Boundary",
        b"Unusual.Boundary",
        b"Unusual/Boundary",
        b"Unusual:Boundary",
        b"Unusual=Boundary",
        b"Unusual?Boundary",
        b"Invalid>Boundary",
        b"InvalidBoundaryTOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOLONG",
        b"", //Invalid...Need at least one byte
        b"InvalidUnusual.~Boundary",
    ];
    let outputs: Vec<u64> = vec![
        Flags::HBOUNDARY_UNUSUAL,
        Flags::HBOUNDARY_UNUSUAL,
        Flags::HBOUNDARY_UNUSUAL,
        Flags::HBOUNDARY_UNUSUAL,
        Flags::HBOUNDARY_UNUSUAL,
        Flags::HBOUNDARY_UNUSUAL,
        Flags::HBOUNDARY_UNUSUAL,
        Flags::HBOUNDARY_UNUSUAL,
        Flags::HBOUNDARY_UNUSUAL,
        Flags::HBOUNDARY_UNUSUAL,
        Flags::HBOUNDARY_UNUSUAL,
        Flags::HBOUNDARY_INVALID,
        Flags::HBOUNDARY_INVALID,
        Flags::HBOUNDARY_INVALID,
        Flags::HBOUNDARY_INVALID | Flags::HBOUNDARY_UNUSUAL,
    ];

    for i in 0..inputs.len() {
        let mut flags = 0;
        validate_boundary(inputs[i], &mut flags);
        assert_eq!(outputs[i], flags);
    }
}

#[test]
fn ValidateContentType() {
    let inputs: Vec<&[u8]> = vec![
        b"multipart/form-data; boundary   = stuff, boundary=stuff",
        b"multipart/form-data; boundary=stuffm BounDary=stuff",
        b"multipart/form-data; Boundary=stuff",
        b"multipart/form-data; bouNdary=stuff",
        b"multipart/form-data; boundary=stuff",
    ];
    let outputs: Vec<u64> = vec![
        Flags::HBOUNDARY_INVALID,
        Flags::HBOUNDARY_INVALID,
        Flags::HBOUNDARY_INVALID,
        Flags::HBOUNDARY_INVALID,
        0,
    ];

    for i in 0..inputs.len() {
        let mut flags = 0;
        validate_content_type(inputs[i], &mut flags);
        assert_eq!(outputs[i], flags);
    }
}
