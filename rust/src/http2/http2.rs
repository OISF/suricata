/* Copyright (C) 2020 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

use super::files::*;
#[cfg(feature = "decompression")]
use super::decompression;
use super::parser;
use crate::applayer::{self, *};
use crate::core::{
    self, AppProto, Flow, SuricataFileContext, ALPROTO_FAILED, ALPROTO_UNKNOWN, IPPROTO_TCP,
    STREAM_TOCLIENT, STREAM_TOSERVER,
};
use crate::filecontainer::*;
use crate::filetracker::*;
use nom;
use std;
use std::ffi::{CStr, CString};
use std::fmt;
use std::io;
use std::mem::transmute;

static mut ALPROTO_HTTP2: AppProto = ALPROTO_UNKNOWN;

const HTTP2_DEFAULT_MAX_FRAME_SIZE: u32 = 16384;
const HTTP2_MAX_HANDLED_FRAME_SIZE: usize = 65536;
const HTTP2_MIN_HANDLED_FRAME_SIZE: usize = 256;

pub static mut SURICATA_HTTP2_FILE_CONFIG: Option<&'static SuricataFileContext> = None;

#[no_mangle]
pub extern "C" fn rs_http2_init(context: &'static mut SuricataFileContext) {
    unsafe {
        SURICATA_HTTP2_FILE_CONFIG = Some(context);
    }
}

#[repr(u8)]
#[derive(Copy, Clone, PartialOrd, PartialEq)]
pub enum HTTP2ConnectionState {
    Http2StateInit = 0,
    Http2StateMagicDone = 1,
}

const HTTP2_FRAME_HEADER_LEN: usize = 9;
const HTTP2_MAGIC_LEN: usize = 24;
const HTTP2_FRAME_GOAWAY_LEN: usize = 4;
const HTTP2_FRAME_RSTSTREAM_LEN: usize = 4;
const HTTP2_FRAME_PRIORITY_LEN: usize = 5;
const HTTP2_FRAME_WINDOWUPDATE_LEN: usize = 4;
//TODO make this configurable
pub const HTTP2_MAX_TABLESIZE: u32 = 0x10000; // 65536

#[repr(u8)]
#[derive(Copy, Clone, PartialOrd, PartialEq, Debug)]
pub enum HTTP2FrameUnhandledReason {
    UnknownType = 0,
    TooLong = 1,
    ParsingError = 2,
    Incomplete = 3,
}

impl fmt::Display for HTTP2FrameUnhandledReason {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug)]
pub struct HTTP2FrameUnhandled {
    pub reason: HTTP2FrameUnhandledReason,
}

#[derive(Debug)]
pub enum HTTP2FrameTypeData {
    PRIORITY(parser::HTTP2FramePriority),
    GOAWAY(parser::HTTP2FrameGoAway),
    RSTSTREAM(parser::HTTP2FrameRstStream),
    SETTINGS(Vec<parser::HTTP2FrameSettings>),
    WINDOWUPDATE(parser::HTTP2FrameWindowUpdate),
    HEADERS(parser::HTTP2FrameHeaders),
    PUSHPROMISE(parser::HTTP2FramePushPromise),
    CONTINUATION(parser::HTTP2FrameContinuation),
    PING,
    DATA,
    //not a defined frame
    UNHANDLED(HTTP2FrameUnhandled),
}

#[repr(u8)]
#[derive(Copy, Clone, PartialOrd, PartialEq, Debug)]
pub enum HTTP2TransactionState {
    HTTP2StateIdle = 0,
    HTTP2StateOpen = 1,
    HTTP2StateReserved = 2,
    HTTP2StateDataClient = 3,
    HTTP2StateHalfClosedClient = 4,
    HTTP2StateDataServer = 5,
    HTTP2StateHalfClosedServer = 6,
    HTTP2StateClosed = 7,
    //not a RFC-defined state, used for stream 0 frames appyling to the global connection
    HTTP2StateGlobal = 8,
}

#[derive(Debug)]
pub struct HTTP2Frame {
    pub header: parser::HTTP2FrameHeader,
    pub data: HTTP2FrameTypeData,
}

#[derive(Debug)]
pub struct HTTP2Transaction {
    tx_id: u64,
    pub stream_id: u32,
    pub state: HTTP2TransactionState,
    child_stream_id: u32,

    pub frames_tc: Vec<HTTP2Frame>,
    pub frames_ts: Vec<HTTP2Frame>,

    #[cfg(feature = "decompression")]
    decoder: decompression::HTTP2Decoder,

    de_state: Option<*mut core::DetectEngineState>,
    events: *mut core::AppLayerDecoderEvents,
    tx_data: AppLayerTxData,
    ft_tc: FileTransferTracker,
    ft_ts: FileTransferTracker,

    //temporary escaped header for detection
    //must be attached to transaction for memory management (be freed at the right time)
    pub escaped: Vec<Vec<u8>>,
}

impl HTTP2Transaction {
    pub fn new() -> HTTP2Transaction {
        HTTP2Transaction {
            tx_id: 0,
            stream_id: 0,
            child_stream_id: 0,
            state: HTTP2TransactionState::HTTP2StateIdle,
            frames_tc: Vec::new(),
            frames_ts: Vec::new(),
            #[cfg(feature = "decompression")]
            decoder: decompression::HTTP2Decoder::new(),
            de_state: None,
            events: std::ptr::null_mut(),
            tx_data: AppLayerTxData::new(),
            ft_tc: FileTransferTracker::new(),
            ft_ts: FileTransferTracker::new(),
            escaped: Vec::with_capacity(16),
        }
    }

    pub fn free(&mut self) {
        if self.events != std::ptr::null_mut() {
            core::sc_app_layer_decoder_events_free_events(&mut self.events);
        }
        if let Some(state) = self.de_state {
            core::sc_detect_engine_state_free(state);
        }
    }

    #[cfg(not(feature = "decompression"))]
    fn handle_headers(&mut self, _blocks: &Vec<parser::HTTP2FrameHeaderBlock>, _dir: u8) {}

    #[cfg(feature = "decompression")]
    fn handle_headers(&mut self, blocks: &Vec<parser::HTTP2FrameHeaderBlock>, dir: u8) {
        for i in 0..blocks.len() {
            if blocks[i].name == b"content-encoding" {
                self.decoder.http2_encoding_fromvec(&blocks[i].value, dir);
            }
        }
    }

    fn decompress<'a>(
        &'a mut self, input: &'a [u8], dir: u8, sfcm: &'static SuricataFileContext, over: bool,
        files: &mut FileContainer, flags: u16,
    ) -> io::Result<()> {
        #[cfg(feature = "decompression")]
        let mut output = Vec::with_capacity(decompression::HTTP2_DECOMPRESSION_CHUNK_SIZE);
        #[cfg(feature = "decompression")]
        let decompressed = self.decoder.decompress(input, &mut output, dir)?;
        #[cfg(not(feature = "decompression"))]
        let decompressed = input;

        let xid: u32 = self.tx_id as u32;
        if dir == STREAM_TOCLIENT {
            self.ft_tc.tx_id = self.tx_id - 1;
            if !self.ft_tc.file_open {
                // we are now sure that new_chunk will open a file
                // even if it may close it right afterwards
                self.tx_data.incr_files_opened();
            }
            self.ft_tc.new_chunk(
                sfcm,
                files,
                flags,
                b"",
                decompressed,
                self.ft_tc.tracked, //offset = append
                decompressed.len() as u32,
                0,
                over,
                &xid,
            );
        } else {
            self.ft_ts.tx_id = self.tx_id - 1;
            if !self.ft_ts.file_open {
                self.tx_data.incr_files_opened();
            }
            self.ft_ts.new_chunk(
                sfcm,
                files,
                flags,
                b"",
                decompressed,
                self.ft_ts.tracked, //offset = append
                decompressed.len() as u32,
                0,
                over,
                &xid,
            );
        };
        return Ok(());
    }

    fn handle_frame(
        &mut self, header: &parser::HTTP2FrameHeader, data: &HTTP2FrameTypeData, dir: u8,
    ) {
        //handle child_stream_id changes
        match data {
            HTTP2FrameTypeData::PUSHPROMISE(hs) => {
                if dir == STREAM_TOCLIENT {
                    //we could set an event if self.child_stream_id != 0
                    if header.flags & parser::HTTP2_FLAG_HEADER_END_HEADERS == 0 {
                        self.child_stream_id = hs.stream_id;
                    }
                    self.state = HTTP2TransactionState::HTTP2StateReserved;
                }
                self.handle_headers(&hs.blocks, dir);
            }
            HTTP2FrameTypeData::CONTINUATION(hs) => {
                if dir == STREAM_TOCLIENT
                    && header.flags & parser::HTTP2_FLAG_HEADER_END_HEADERS != 0
                {
                    self.child_stream_id = 0;
                }
                self.handle_headers(&hs.blocks, dir);
            }
            HTTP2FrameTypeData::HEADERS(hs) => {
                if dir == STREAM_TOCLIENT {
                    self.child_stream_id = 0;
                }
                self.handle_headers(&hs.blocks, dir);
            }
            HTTP2FrameTypeData::RSTSTREAM(_) => {
                self.child_stream_id = 0;
            }
            _ => {}
        }
        //handle closing state changes
        match data {
            HTTP2FrameTypeData::HEADERS(_) | HTTP2FrameTypeData::DATA => {
                if header.flags & parser::HTTP2_FLAG_HEADER_EOS != 0 {
                    match self.state {
                        HTTP2TransactionState::HTTP2StateHalfClosedClient
                        | HTTP2TransactionState::HTTP2StateDataServer => {
                            if dir == STREAM_TOCLIENT {
                                self.state = HTTP2TransactionState::HTTP2StateClosed;
                            }
                        }
                        HTTP2TransactionState::HTTP2StateHalfClosedServer => {
                            if dir == STREAM_TOSERVER {
                                self.state = HTTP2TransactionState::HTTP2StateClosed;
                            }
                        }
                        // do not revert back to a half closed state
                        HTTP2TransactionState::HTTP2StateClosed => {}
                        HTTP2TransactionState::HTTP2StateGlobal => {}
                        _ => {
                            if dir == STREAM_TOCLIENT {
                                self.state = HTTP2TransactionState::HTTP2StateHalfClosedServer;
                            } else {
                                self.state = HTTP2TransactionState::HTTP2StateHalfClosedClient;
                            }
                        }
                    }
                } else if header.ftype == parser::HTTP2FrameType::DATA as u8 {
                    //not end of stream
                    if dir == STREAM_TOSERVER {
                        if self.state < HTTP2TransactionState::HTTP2StateDataClient {
                            self.state = HTTP2TransactionState::HTTP2StateDataClient;
                        }
                    } else {
                        if self.state < HTTP2TransactionState::HTTP2StateDataServer {
                            self.state = HTTP2TransactionState::HTTP2StateDataServer;
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

impl Drop for HTTP2Transaction {
    fn drop(&mut self) {
        self.free();
    }
}

#[repr(u32)]
pub enum HTTP2Event {
    InvalidFrameHeader = 0,
    InvalidClientMagic,
    InvalidFrameData,
    InvalidHeader,
    InvalidFrameLength,
    ExtraHeaderData,
    LongFrameData,
    StreamIdReuse,
    InvalidHTTP1Settings,
    FailedDecompression,
}

impl HTTP2Event {
    fn from_i32(value: i32) -> Option<HTTP2Event> {
        match value {
            0 => Some(HTTP2Event::InvalidFrameHeader),
            1 => Some(HTTP2Event::InvalidClientMagic),
            2 => Some(HTTP2Event::InvalidFrameData),
            3 => Some(HTTP2Event::InvalidHeader),
            4 => Some(HTTP2Event::InvalidFrameLength),
            5 => Some(HTTP2Event::ExtraHeaderData),
            6 => Some(HTTP2Event::LongFrameData),
            7 => Some(HTTP2Event::StreamIdReuse),
            8 => Some(HTTP2Event::InvalidHTTP1Settings),
            9 => Some(HTTP2Event::FailedDecompression),
            _ => None,
        }
    }
}

pub struct HTTP2DynTable {
    pub table: Vec<parser::HTTP2FrameHeaderBlock>,
    pub current_size: usize,
    pub max_size: usize,
    pub overflow: u8,
}

impl HTTP2DynTable {
    pub fn new() -> Self {
        Self {
            table: Vec::with_capacity(64),
            current_size: 0,
            max_size: 4096, //default value
            overflow: 0,
        }
    }
}

pub struct HTTP2State {
    tx_id: u64,
    request_frame_size: u32,
    response_frame_size: u32,
    dynamic_headers_ts: HTTP2DynTable,
    dynamic_headers_tc: HTTP2DynTable,
    transactions: Vec<HTTP2Transaction>,
    progress: HTTP2ConnectionState,
    pub files: HTTP2Files,
}

impl HTTP2State {
    pub fn new() -> Self {
        Self {
            tx_id: 0,
            request_frame_size: 0,
            response_frame_size: 0,
            // the headers are encoded on one byte
            // with a fixed number of static headers, and
            // a variable number of dynamic headers
            dynamic_headers_ts: HTTP2DynTable::new(),
            dynamic_headers_tc: HTTP2DynTable::new(),
            transactions: Vec::new(),
            progress: HTTP2ConnectionState::Http2StateInit,
            files: HTTP2Files::new(),
        }
    }

    pub fn free(&mut self) {
        self.transactions.clear();
        self.files.free();
    }

    pub fn set_event(&mut self, event: HTTP2Event) {
        let len = self.transactions.len();
        if len == 0 {
            return;
        }
        let tx = &mut self.transactions[len - 1];
        let ev = event as u8;
        core::sc_app_layer_decoder_events_set_event_raw(&mut tx.events, ev);
    }

    // Free a transaction by ID.
    fn free_tx(&mut self, tx_id: u64) {
        let len = self.transactions.len();
        let mut found = false;
        let mut index = 0;
        for i in 0..len {
            let tx = &self.transactions[i];
            if tx.tx_id == tx_id + 1 {
                found = true;
                index = i;
                break;
            }
        }
        if found {
            self.transactions.remove(index);
        }
    }

    pub fn get_tx(&mut self, tx_id: u64) -> Option<&HTTP2Transaction> {
        for tx in &mut self.transactions {
            if tx.tx_id == tx_id + 1 {
                return Some(tx);
            }
        }
        return None;
    }

    fn find_tx_index(&mut self, sid: u32) -> usize {
        for i in 0..self.transactions.len() {
            //reverse order should be faster
            let idx = self.transactions.len() - 1 - i;
            if sid == self.transactions[idx].stream_id {
                return idx + 1;
            }
        }
        return 0;
    }

    fn find_child_stream_id(&mut self, sid: u32) -> u32 {
        for i in 0..self.transactions.len() {
            //reverse order should be faster
            if sid == self.transactions[self.transactions.len() - 1 - i].stream_id {
                if self.transactions[self.transactions.len() - 1 - i].child_stream_id > 0 {
                    return self.transactions[self.transactions.len() - 1 - i].child_stream_id;
                }
                return sid;
            }
        }
        return sid;
    }

    fn create_global_tx(&mut self) -> &mut HTTP2Transaction {
        //special transaction with only one frame
        //as it affects the global connection, there is no end to it
        let mut tx = HTTP2Transaction::new();
        self.tx_id += 1;
        tx.tx_id = self.tx_id;
        tx.state = HTTP2TransactionState::HTTP2StateGlobal;
        self.transactions.push(tx);
        return self.transactions.last_mut().unwrap();
    }

    pub fn find_or_create_tx(
        &mut self, header: &parser::HTTP2FrameHeader, data: &HTTP2FrameTypeData, dir: u8,
    ) -> &mut HTTP2Transaction {
        if header.stream_id == 0 {
            return self.create_global_tx();
        }
        let sid = match data {
            //yes, the right stream_id for Suricata is not the header one
            HTTP2FrameTypeData::PUSHPROMISE(hs) => hs.stream_id,
            HTTP2FrameTypeData::CONTINUATION(_) => {
                if dir == STREAM_TOCLIENT {
                    //continuation of a push promise
                    self.find_child_stream_id(header.stream_id)
                } else {
                    header.stream_id
                }
            }
            _ => header.stream_id,
        };
        let index = self.find_tx_index(sid);
        if index > 0 {
            if self.transactions[index - 1].state == HTTP2TransactionState::HTTP2StateClosed {
                //these frames can be received in this state for a short period
                if header.ftype != parser::HTTP2FrameType::RSTSTREAM as u8
                    && header.ftype != parser::HTTP2FrameType::WINDOWUPDATE as u8
                    && header.ftype != parser::HTTP2FrameType::PRIORITY as u8
                {
                    self.set_event(HTTP2Event::StreamIdReuse);
                }
            }
            return &mut self.transactions[index - 1];
        } else {
            let mut tx = HTTP2Transaction::new();
            self.tx_id += 1;
            tx.tx_id = self.tx_id;
            tx.stream_id = sid;
            tx.state = HTTP2TransactionState::HTTP2StateOpen;
            self.transactions.push(tx);
            return self.transactions.last_mut().unwrap();
        }
    }

    fn process_headers(&mut self, blocks: &Vec<parser::HTTP2FrameHeaderBlock>, dir: u8) {
        let (mut update, mut sizeup) = (false, 0);
        for i in 0..blocks.len() {
            if blocks[i].error >= parser::HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeError {
                self.set_event(HTTP2Event::InvalidHeader);
            } else if blocks[i].error
                == parser::HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeSizeUpdate
            {
                update = true;
                if blocks[i].sizeupdate > sizeup {
                    sizeup = blocks[i].sizeupdate;
                }
            }
        }
        if update {
            //borrow checker forbids to pass directly dyn_headers
            let dyn_headers = if dir == STREAM_TOCLIENT {
                &mut self.dynamic_headers_tc
            } else {
                &mut self.dynamic_headers_ts
            };
            dyn_headers.max_size = sizeup as usize;
        }
    }

    fn parse_frame_data(
        &mut self, ftype: u8, input: &[u8], complete: bool, hflags: u8, dir: u8,
    ) -> HTTP2FrameTypeData {
        match num::FromPrimitive::from_u8(ftype) {
            Some(parser::HTTP2FrameType::GOAWAY) => {
                if input.len() < HTTP2_FRAME_GOAWAY_LEN {
                    self.set_event(HTTP2Event::InvalidFrameLength);
                    return HTTP2FrameTypeData::UNHANDLED(HTTP2FrameUnhandled {
                        reason: HTTP2FrameUnhandledReason::Incomplete,
                    });
                }
                match parser::http2_parse_frame_goaway(input) {
                    Ok((_, goaway)) => {
                        return HTTP2FrameTypeData::GOAWAY(goaway);
                    }
                    Err(_) => {
                        self.set_event(HTTP2Event::InvalidFrameData);
                        return HTTP2FrameTypeData::UNHANDLED(HTTP2FrameUnhandled {
                            reason: HTTP2FrameUnhandledReason::ParsingError,
                        });
                    }
                }
            }
            Some(parser::HTTP2FrameType::SETTINGS) => {
                match parser::http2_parse_frame_settings(input) {
                    Ok((_, set)) => {
                        for i in 0..set.len() {
                            if set[i].id == parser::HTTP2SettingsId::SETTINGSHEADERTABLESIZE {
                                //reverse order as this is what we accept from the other endpoint
                                let dyn_headers = if dir == STREAM_TOCLIENT {
                                    &mut self.dynamic_headers_ts
                                } else {
                                    &mut self.dynamic_headers_tc
                                };
                                dyn_headers.max_size = set[i].value as usize;
                                if set[i].value > HTTP2_MAX_TABLESIZE {
                                    //mark potential overflow
                                    dyn_headers.overflow = 1;
                                } else {
                                    //reset in case peer set a lower value, to be tested
                                    dyn_headers.overflow = 0;
                                }
                            }
                        }
                        //we could set an event on remaining data
                        return HTTP2FrameTypeData::SETTINGS(set);
                    }
                    Err(nom::Err::Incomplete(_)) => {
                        if complete {
                            self.set_event(HTTP2Event::InvalidFrameData);
                            return HTTP2FrameTypeData::UNHANDLED(HTTP2FrameUnhandled {
                                reason: HTTP2FrameUnhandledReason::ParsingError,
                            });
                        } else {
                            return HTTP2FrameTypeData::UNHANDLED(HTTP2FrameUnhandled {
                                reason: HTTP2FrameUnhandledReason::TooLong,
                            });
                        }
                    }
                    Err(_) => {
                        self.set_event(HTTP2Event::InvalidFrameData);
                        return HTTP2FrameTypeData::UNHANDLED(HTTP2FrameUnhandled {
                            reason: HTTP2FrameUnhandledReason::ParsingError,
                        });
                    }
                }
            }
            Some(parser::HTTP2FrameType::RSTSTREAM) => {
                if input.len() != HTTP2_FRAME_RSTSTREAM_LEN {
                    self.set_event(HTTP2Event::InvalidFrameLength);
                    return HTTP2FrameTypeData::UNHANDLED(HTTP2FrameUnhandled {
                        reason: HTTP2FrameUnhandledReason::Incomplete,
                    });
                } else {
                    match parser::http2_parse_frame_rststream(input) {
                        Ok((_, rst)) => {
                            return HTTP2FrameTypeData::RSTSTREAM(rst);
                        }
                        Err(_) => {
                            self.set_event(HTTP2Event::InvalidFrameData);
                            return HTTP2FrameTypeData::UNHANDLED(HTTP2FrameUnhandled {
                                reason: HTTP2FrameUnhandledReason::ParsingError,
                            });
                        }
                    }
                }
            }
            Some(parser::HTTP2FrameType::PRIORITY) => {
                if input.len() != HTTP2_FRAME_PRIORITY_LEN {
                    self.set_event(HTTP2Event::InvalidFrameLength);
                    return HTTP2FrameTypeData::UNHANDLED(HTTP2FrameUnhandled {
                        reason: HTTP2FrameUnhandledReason::Incomplete,
                    });
                } else {
                    match parser::http2_parse_frame_priority(input) {
                        Ok((_, priority)) => {
                            return HTTP2FrameTypeData::PRIORITY(priority);
                        }
                        Err(_) => {
                            self.set_event(HTTP2Event::InvalidFrameData);
                            return HTTP2FrameTypeData::UNHANDLED(HTTP2FrameUnhandled {
                                reason: HTTP2FrameUnhandledReason::ParsingError,
                            });
                        }
                    }
                }
            }
            Some(parser::HTTP2FrameType::WINDOWUPDATE) => {
                if input.len() != HTTP2_FRAME_WINDOWUPDATE_LEN {
                    self.set_event(HTTP2Event::InvalidFrameLength);
                    return HTTP2FrameTypeData::UNHANDLED(HTTP2FrameUnhandled {
                        reason: HTTP2FrameUnhandledReason::Incomplete,
                    });
                } else {
                    match parser::http2_parse_frame_windowupdate(input) {
                        Ok((_, wu)) => {
                            return HTTP2FrameTypeData::WINDOWUPDATE(wu);
                        }
                        Err(_) => {
                            self.set_event(HTTP2Event::InvalidFrameData);
                            return HTTP2FrameTypeData::UNHANDLED(HTTP2FrameUnhandled {
                                reason: HTTP2FrameUnhandledReason::ParsingError,
                            });
                        }
                    }
                }
            }
            Some(parser::HTTP2FrameType::PUSHPROMISE) => {
                let dyn_headers = if dir == STREAM_TOCLIENT {
                    &mut self.dynamic_headers_tc
                } else {
                    &mut self.dynamic_headers_ts
                };
                match parser::http2_parse_frame_push_promise(input, hflags, dyn_headers) {
                    Ok((_, hs)) => {
                        self.process_headers(&hs.blocks, dir);
                        return HTTP2FrameTypeData::PUSHPROMISE(hs);
                    }
                    Err(nom::Err::Incomplete(_)) => {
                        if complete {
                            self.set_event(HTTP2Event::InvalidFrameData);
                            return HTTP2FrameTypeData::UNHANDLED(HTTP2FrameUnhandled {
                                reason: HTTP2FrameUnhandledReason::ParsingError,
                            });
                        } else {
                            return HTTP2FrameTypeData::UNHANDLED(HTTP2FrameUnhandled {
                                reason: HTTP2FrameUnhandledReason::TooLong,
                            });
                        }
                    }
                    Err(_) => {
                        self.set_event(HTTP2Event::InvalidFrameData);
                        return HTTP2FrameTypeData::UNHANDLED(HTTP2FrameUnhandled {
                            reason: HTTP2FrameUnhandledReason::ParsingError,
                        });
                    }
                }
            }
            Some(parser::HTTP2FrameType::DATA) => {
                return HTTP2FrameTypeData::DATA;
            }
            Some(parser::HTTP2FrameType::CONTINUATION) => {
                let dyn_headers = if dir == STREAM_TOCLIENT {
                    &mut self.dynamic_headers_tc
                } else {
                    &mut self.dynamic_headers_ts
                };
                match parser::http2_parse_frame_continuation(input, dyn_headers) {
                    Ok((_, hs)) => {
                        self.process_headers(&hs.blocks, dir);
                        return HTTP2FrameTypeData::CONTINUATION(hs);
                    }
                    Err(nom::Err::Incomplete(_)) => {
                        if complete {
                            self.set_event(HTTP2Event::InvalidFrameData);
                            return HTTP2FrameTypeData::UNHANDLED(HTTP2FrameUnhandled {
                                reason: HTTP2FrameUnhandledReason::ParsingError,
                            });
                        } else {
                            return HTTP2FrameTypeData::UNHANDLED(HTTP2FrameUnhandled {
                                reason: HTTP2FrameUnhandledReason::TooLong,
                            });
                        }
                    }
                    Err(_) => {
                        self.set_event(HTTP2Event::InvalidFrameData);
                        return HTTP2FrameTypeData::UNHANDLED(HTTP2FrameUnhandled {
                            reason: HTTP2FrameUnhandledReason::ParsingError,
                        });
                    }
                }
            }
            Some(parser::HTTP2FrameType::HEADERS) => {
                let dyn_headers = if dir == STREAM_TOCLIENT {
                    &mut self.dynamic_headers_tc
                } else {
                    &mut self.dynamic_headers_ts
                };
                match parser::http2_parse_frame_headers(input, hflags, dyn_headers) {
                    Ok((hrem, hs)) => {
                        self.process_headers(&hs.blocks, dir);
                        if hrem.len() > 0 {
                            SCLogDebug!("Remaining data for HTTP2 headers");
                            self.set_event(HTTP2Event::ExtraHeaderData);
                        }
                        return HTTP2FrameTypeData::HEADERS(hs);
                    }
                    Err(nom::Err::Incomplete(_)) => {
                        if complete {
                            self.set_event(HTTP2Event::InvalidFrameData);
                            return HTTP2FrameTypeData::UNHANDLED(HTTP2FrameUnhandled {
                                reason: HTTP2FrameUnhandledReason::ParsingError,
                            });
                        } else {
                            return HTTP2FrameTypeData::UNHANDLED(HTTP2FrameUnhandled {
                                reason: HTTP2FrameUnhandledReason::TooLong,
                            });
                        }
                    }
                    Err(_) => {
                        self.set_event(HTTP2Event::InvalidFrameData);
                        return HTTP2FrameTypeData::UNHANDLED(HTTP2FrameUnhandled {
                            reason: HTTP2FrameUnhandledReason::ParsingError,
                        });
                    }
                }
            }
            Some(parser::HTTP2FrameType::PING) => {
                return HTTP2FrameTypeData::PING;
            }
            _ => {
                return HTTP2FrameTypeData::UNHANDLED(HTTP2FrameUnhandled {
                    reason: HTTP2FrameUnhandledReason::UnknownType,
                });
            }
        }
    }

    fn parse_frames(&mut self, mut input: &[u8], il: usize, dir: u8) -> AppLayerResult {
        while input.len() > 0 {
            match parser::http2_parse_frame_header(input) {
                Ok((rem, head)) => {
                    let hl = head.length as usize;

                    //we check for completeness first
                    if rem.len() < hl {
                        //but limit ourselves so as not to exhaust memory
                        if hl < HTTP2_MAX_HANDLED_FRAME_SIZE {
                            return AppLayerResult::incomplete(
                                (il - input.len()) as u32,
                                (HTTP2_FRAME_HEADER_LEN + hl) as u32,
                            );
                        } else if rem.len() < HTTP2_MIN_HANDLED_FRAME_SIZE {
                            return AppLayerResult::incomplete(
                                (il - input.len()) as u32,
                                (HTTP2_FRAME_HEADER_LEN + HTTP2_MIN_HANDLED_FRAME_SIZE) as u32,
                            );
                        } else {
                            self.set_event(HTTP2Event::LongFrameData);
                            self.request_frame_size = head.length - (rem.len() as u32);
                        }
                    }

                    //get a safe length for the buffer
                    let (hlsafe, complete) = if rem.len() < hl {
                        (rem.len(), false)
                    } else {
                        (hl, true)
                    };

                    if head.length == 0 && head.ftype == parser::HTTP2FrameType::SETTINGS as u8 {
                        input = &rem[hlsafe..];
                        continue;
                    }
                    let txdata = self.parse_frame_data(
                        head.ftype,
                        &rem[..hlsafe],
                        complete,
                        head.flags,
                        dir,
                    );

                    let tx = self.find_or_create_tx(&head, &txdata, dir);
                    tx.handle_frame(&head, &txdata, dir);
                    let over = head.flags & parser::HTTP2_FLAG_HEADER_EOS != 0;
                    let ftype = head.ftype;
                    let sid = head.stream_id;
                    let padded = head.flags & parser::HTTP2_FLAG_HEADER_PADDED != 0;
                    if dir == STREAM_TOSERVER {
                        tx.frames_ts.push(HTTP2Frame {
                            header: head,
                            data: txdata,
                        });
                    } else {
                        tx.frames_tc.push(HTTP2Frame {
                            header: head,
                            data: txdata,
                        });
                    }
                    if ftype == parser::HTTP2FrameType::DATA as u8 {
                        match unsafe { SURICATA_HTTP2_FILE_CONFIG } {
                            Some(sfcm) => {
                                //borrow checker forbids to reuse directly tx
                                let index = self.find_tx_index(sid);
                                if index > 0 {
                                    let tx_same = &mut self.transactions[index - 1];
                                    let (files, flags) = self.files.get(dir);
                                    let mut dinput = &rem[..hlsafe];
                                    if padded && rem.len() > 0 && usize::from(rem[0]) < hlsafe{
                                        dinput = &rem[1..hlsafe - usize::from(rem[0])];
                                    }
                                    match tx_same.decompress(
                                        dinput,
                                        dir,
                                        sfcm,
                                        over,
                                        files,
                                        flags,
                                    ) {
                                        Err(_e) => {
                                            self.set_event(HTTP2Event::FailedDecompression);
                                        }
                                        _ => {}
                                    }
                                }
                            }
                            None => panic!("no SURICATA_HTTP2_FILE_CONFIG"),
                        }
                    }
                    input = &rem[hlsafe..];
                }
                Err(nom::Err::Incomplete(_)) => {
                    //we may have consumed data from previous records
                    return AppLayerResult::incomplete(
                        (il - input.len()) as u32,
                        HTTP2_FRAME_HEADER_LEN as u32,
                    );
                }
                Err(_) => {
                    self.set_event(HTTP2Event::InvalidFrameHeader);
                    return AppLayerResult::err();
                }
            }
        }
        return AppLayerResult::ok();
    }

    fn parse_ts(&mut self, mut input: &[u8]) -> AppLayerResult {
        //very first : skip magic
        let mut magic_consumed = 0;
        if self.progress < HTTP2ConnectionState::Http2StateMagicDone {
            //skip magic
            if input.len() >= HTTP2_MAGIC_LEN {
                //skip magic
                match std::str::from_utf8(&input[..HTTP2_MAGIC_LEN]) {
                    Ok("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") => {
                        input = &input[HTTP2_MAGIC_LEN..];
                        magic_consumed = HTTP2_MAGIC_LEN;
                    }
                    Ok(&_) => {
                        self.set_event(HTTP2Event::InvalidClientMagic);
                    }
                    Err(_) => {
                        return AppLayerResult::err();
                    }
                }
                self.progress = HTTP2ConnectionState::Http2StateMagicDone;
            } else {
                //still more buffer
                return AppLayerResult::incomplete(0 as u32, HTTP2_MAGIC_LEN as u32);
            }
        }
        //first consume frame bytes
        let il = input.len();
        if self.request_frame_size > 0 {
            let ilen = input.len() as u32;
            if self.request_frame_size >= ilen {
                self.request_frame_size -= ilen;
                return AppLayerResult::ok();
            } else {
                let start = self.request_frame_size as usize;
                input = &input[start..];
                self.request_frame_size = 0;
            }
        }

        //then parse all we can
        let r = self.parse_frames(input, il, STREAM_TOSERVER);
        if r.status == 1 {
            //adds bytes consumed by banner to incomplete result
            return AppLayerResult::incomplete(r.consumed + magic_consumed as u32, r.needed);
        } else {
            return r;
        }
    }

    fn parse_tc(&mut self, mut input: &[u8]) -> AppLayerResult {
        //first consume frame bytes
        let il = input.len();
        if self.response_frame_size > 0 {
            let ilen = input.len() as u32;
            if self.response_frame_size >= ilen {
                self.response_frame_size -= ilen;
                return AppLayerResult::ok();
            } else {
                let start = self.response_frame_size as usize;
                input = &input[start..];
                self.response_frame_size = 0;
            }
        }
        //then parse all we can
        return self.parse_frames(input, il, STREAM_TOCLIENT);
    }

    fn tx_iterator(
        &mut self, min_tx_id: u64, state: &mut u64,
    ) -> Option<(&HTTP2Transaction, u64, bool)> {
        let mut index = *state as usize;
        let len = self.transactions.len();

        while index < len {
            let tx = &self.transactions[index];
            if tx.tx_id < min_tx_id + 1 {
                index += 1;
                continue;
            }
            *state = index as u64;
            return Some((tx, tx.tx_id - 1, (len - index) > 1));
        }

        return None;
    }
}

// C exports.

export_tx_get_detect_state!(rs_http2_tx_get_detect_state, HTTP2Transaction);
export_tx_set_detect_state!(rs_http2_tx_set_detect_state, HTTP2Transaction);

export_tx_data_get!(rs_http2_get_tx_data, HTTP2Transaction);

/// C entry point for a probing parser.
#[no_mangle]
pub extern "C" fn rs_http2_probing_parser_tc(
    _flow: *const Flow, _direction: u8, input: *const u8, input_len: u32, _rdir: *mut u8,
) -> AppProto {
    if input != std::ptr::null_mut() {
        let slice = build_slice!(input, input_len as usize);
        match parser::http2_parse_frame_header(slice) {
            Ok((_, header)) => {
                if header.reserved != 0
                    || header.length > HTTP2_DEFAULT_MAX_FRAME_SIZE
                    || header.flags & 0xFE != 0
                    || header.ftype != parser::HTTP2FrameType::SETTINGS as u8
                {
                    return unsafe { ALPROTO_FAILED };
                }
                return unsafe { ALPROTO_HTTP2 };
            }
            Err(nom::Err::Incomplete(_)) => {
                return ALPROTO_UNKNOWN;
            }
            Err(_) => {
                return unsafe { ALPROTO_FAILED };
            }
        }
    }
    return ALPROTO_UNKNOWN;
}

// Extern functions operating on HTTP2.
extern "C" {
    pub fn HTTP2MimicHttp1Request(
        orig_state: *mut std::os::raw::c_void, new_state: *mut std::os::raw::c_void,
    );
}

#[no_mangle]
pub extern "C" fn rs_http2_state_new(
    orig_state: *mut std::os::raw::c_void, _orig_proto: AppProto,
) -> *mut std::os::raw::c_void {
    let state = HTTP2State::new();
    let boxed = Box::new(state);
    let r = unsafe { transmute(boxed) };
    if orig_state != std::ptr::null_mut() {
        //we could check ALPROTO_HTTP == orig_proto
        unsafe {
            HTTP2MimicHttp1Request(orig_state, r);
        }
    }
    return r;
}

#[no_mangle]
pub extern "C" fn rs_http2_state_free(state: *mut std::os::raw::c_void) {
    // Just unbox...
    let mut state: Box<HTTP2State> = unsafe { transmute(state) };
    state.free();
}

#[no_mangle]
pub extern "C" fn rs_http2_state_tx_free(state: *mut std::os::raw::c_void, tx_id: u64) {
    let state = cast_pointer!(state, HTTP2State);
    state.free_tx(tx_id);
}

#[no_mangle]
pub extern "C" fn rs_http2_parse_ts(
    flow: *const Flow, state: *mut std::os::raw::c_void, _pstate: *mut std::os::raw::c_void,
    input: *const u8, input_len: u32, _data: *const std::os::raw::c_void, _flags: u8,
) -> AppLayerResult {
    let state = cast_pointer!(state, HTTP2State);
    let buf = build_slice!(input, input_len as usize);

    state.files.flags_ts = unsafe { FileFlowToFlags(flow, STREAM_TOSERVER) };
    state.files.flags_ts = state.files.flags_ts | FILE_USE_DETECT;
    return state.parse_ts(buf);
}

#[no_mangle]
pub extern "C" fn rs_http2_parse_tc(
    flow: *const Flow, state: *mut std::os::raw::c_void, _pstate: *mut std::os::raw::c_void,
    input: *const u8, input_len: u32, _data: *const std::os::raw::c_void, _flags: u8,
) -> AppLayerResult {
    let state = cast_pointer!(state, HTTP2State);
    let buf = build_slice!(input, input_len as usize);
    state.files.flags_tc = unsafe { FileFlowToFlags(flow, STREAM_TOCLIENT) };
    state.files.flags_tc = state.files.flags_tc | FILE_USE_DETECT;
    return state.parse_tc(buf);
}

#[no_mangle]
pub extern "C" fn rs_http2_state_get_tx(
    state: *mut std::os::raw::c_void, tx_id: u64,
) -> *mut std::os::raw::c_void {
    let state = cast_pointer!(state, HTTP2State);
    match state.get_tx(tx_id) {
        Some(tx) => {
            return unsafe { transmute(tx) };
        }
        None => {
            return std::ptr::null_mut();
        }
    }
}

#[no_mangle]
pub extern "C" fn rs_http2_state_get_tx_count(state: *mut std::os::raw::c_void) -> u64 {
    let state = cast_pointer!(state, HTTP2State);
    return state.tx_id;
}

#[no_mangle]
pub extern "C" fn rs_http2_state_progress_completion_status(_direction: u8) -> std::os::raw::c_int {
    return HTTP2TransactionState::HTTP2StateClosed as i32;
}

#[no_mangle]
pub extern "C" fn rs_http2_tx_get_state(tx: *mut std::os::raw::c_void) -> HTTP2TransactionState {
    let tx = cast_pointer!(tx, HTTP2Transaction);
    return tx.state;
}

#[no_mangle]
pub extern "C" fn rs_http2_tx_get_alstate_progress(
    tx: *mut std::os::raw::c_void, _direction: u8,
) -> std::os::raw::c_int {
    return rs_http2_tx_get_state(tx) as i32;
}

#[no_mangle]
pub extern "C" fn rs_http2_state_get_events(
    tx: *mut std::os::raw::c_void,
) -> *mut core::AppLayerDecoderEvents {
    let tx = cast_pointer!(tx, HTTP2Transaction);
    return tx.events;
}

#[no_mangle]
pub extern "C" fn rs_http2_state_get_event_info(
    event_name: *const std::os::raw::c_char, event_id: *mut std::os::raw::c_int,
    event_type: *mut core::AppLayerEventType,
) -> std::os::raw::c_int {
    if event_name == std::ptr::null() {
        return -1;
    }
    let c_event_name: &CStr = unsafe { CStr::from_ptr(event_name) };
    let event = match c_event_name.to_str() {
        Ok(s) => {
            match s {
                "invalid_frame_header" => HTTP2Event::InvalidFrameHeader as i32,
                "invalid_client_magic" => HTTP2Event::InvalidClientMagic as i32,
                "invalid_frame_data" => HTTP2Event::InvalidFrameData as i32,
                "invalid_header" => HTTP2Event::InvalidHeader as i32,
                "invalid_frame_length" => HTTP2Event::InvalidFrameLength as i32,
                "extra_header_data" => HTTP2Event::ExtraHeaderData as i32,
                "long_frame_data" => HTTP2Event::LongFrameData as i32,
                "stream_id_reuse" => HTTP2Event::StreamIdReuse as i32,
                "invalid_http1_settings" => HTTP2Event::InvalidHTTP1Settings as i32,
                "failed_decompression" => HTTP2Event::FailedDecompression as i32,
                _ => -1, // unknown event
            }
        }
        Err(_) => -1, // UTF-8 conversion failed
    };
    unsafe {
        *event_type = core::APP_LAYER_EVENT_TYPE_TRANSACTION;
        *event_id = event as std::os::raw::c_int;
    };
    0
}

#[no_mangle]
pub extern "C" fn rs_http2_state_get_event_info_by_id(
    event_id: std::os::raw::c_int, event_name: *mut *const std::os::raw::c_char,
    event_type: *mut core::AppLayerEventType,
) -> i8 {
    if let Some(e) = HTTP2Event::from_i32(event_id as i32) {
        let estr = match e {
            HTTP2Event::InvalidFrameHeader => "invalid_frame_header\0",
            HTTP2Event::InvalidClientMagic => "invalid_client_magic\0",
            HTTP2Event::InvalidFrameData => "invalid_frame_data\0",
            HTTP2Event::InvalidHeader => "invalid_header\0",
            HTTP2Event::InvalidFrameLength => "invalid_frame_length\0",
            HTTP2Event::ExtraHeaderData => "extra_header_data\0",
            HTTP2Event::LongFrameData => "long_frame_data\0",
            HTTP2Event::StreamIdReuse => "stream_id_reuse\0",
            HTTP2Event::InvalidHTTP1Settings => "invalid_http1_settings\0",
            HTTP2Event::FailedDecompression => "failed_decompression\0",
        };
        unsafe {
            *event_name = estr.as_ptr() as *const std::os::raw::c_char;
            *event_type = core::APP_LAYER_EVENT_TYPE_TRANSACTION;
        };
        0
    } else {
        -1
    }
}
#[no_mangle]
pub extern "C" fn rs_http2_state_get_tx_iterator(
    _ipproto: u8, _alproto: AppProto, state: *mut std::os::raw::c_void, min_tx_id: u64,
    _max_tx_id: u64, istate: &mut u64,
) -> applayer::AppLayerGetTxIterTuple {
    let state = cast_pointer!(state, HTTP2State);
    match state.tx_iterator(min_tx_id, istate) {
        Some((tx, out_tx_id, has_next)) => {
            let c_tx = unsafe { transmute(tx) };
            let ires = applayer::AppLayerGetTxIterTuple::with_values(c_tx, out_tx_id, has_next);
            return ires;
        }
        None => {
            return applayer::AppLayerGetTxIterTuple::not_found();
        }
    }
}

#[no_mangle]
pub extern "C" fn rs_http2_getfiles(
    state: *mut std::os::raw::c_void, direction: u8,
) -> *mut FileContainer {
    let state = cast_pointer!(state, HTTP2State);
    if direction == STREAM_TOCLIENT {
        &mut state.files.files_tc as *mut FileContainer
    } else {
        &mut state.files.files_ts as *mut FileContainer
    }
}

// Parser name as a C style string.
const PARSER_NAME: &'static [u8] = b"http2\0";

#[no_mangle]
pub unsafe extern "C" fn rs_http2_register_parser() {
    let default_port = CString::new("[80]").unwrap();
    let parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const std::os::raw::c_char,
        default_port: default_port.as_ptr(),
        ipproto: IPPROTO_TCP,
        probe_ts: None, // big magic string should be enough
        probe_tc: Some(rs_http2_probing_parser_tc),
        min_depth: HTTP2_FRAME_HEADER_LEN as u16,
        max_depth: HTTP2_MAGIC_LEN as u16,
        state_new: rs_http2_state_new,
        state_free: rs_http2_state_free,
        tx_free: rs_http2_state_tx_free,
        parse_ts: rs_http2_parse_ts,
        parse_tc: rs_http2_parse_tc,
        get_tx_count: rs_http2_state_get_tx_count,
        get_tx: rs_http2_state_get_tx,
        tx_get_comp_st: rs_http2_state_progress_completion_status,
        tx_get_progress: rs_http2_tx_get_alstate_progress,
        get_de_state: rs_http2_tx_get_detect_state,
        set_de_state: rs_http2_tx_set_detect_state,
        get_events: Some(rs_http2_state_get_events),
        get_eventinfo: Some(rs_http2_state_get_event_info),
        get_eventinfo_byid: Some(rs_http2_state_get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_files: Some(rs_http2_getfiles),
        get_tx_iterator: Some(rs_http2_state_get_tx_iterator),
        get_tx_data: rs_http2_get_tx_data,
        apply_tx_config: None,
        flags: 0,
        truncate: None,
    };

    let ip_proto_str = CString::new("tcp").unwrap();

    if AppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_HTTP2 = alproto;
        if AppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
        SCLogDebug!("Rust http2 parser registered.");
    } else {
        SCLogNotice!("Protocol detector and parser disabled for HTTP2.");
    }
}
