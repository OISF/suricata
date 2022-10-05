/* Copyright (C) 2020-2022 Open Information Security Foundation
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

use super::decompression;
use super::detect;
use super::parser;
use super::range;

use crate::applayer::{self, *};
use crate::conf::conf_get;
use crate::core::*;
use crate::filecontainer::*;
use crate::filetracker::*;
use nom7::Err;
use std;
use std::collections::VecDeque;
use std::ffi::CString;
use std::fmt;
use std::io;

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
#[derive(Copy, Clone, PartialOrd, PartialEq, Eq)]
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
pub static mut HTTP2_MAX_TABLESIZE: u32 = 65536; // 0x10000
static mut HTTP2_MAX_STREAMS: usize = 4096; // 0x1000

#[repr(u8)]
#[derive(Copy, Clone, PartialOrd, PartialEq, Eq, Debug)]
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
#[derive(Copy, Clone, PartialOrd, PartialEq, Eq, Debug)]
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
    //not a RFC-defined state, dropping this old tx because we have too many
    HTTP2StateTodrop = 9,
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

    decoder: decompression::HTTP2Decoder,
    pub file_range: *mut HttpRangeContainerBlock,

    pub tx_data: AppLayerTxData,
    pub ft_tc: FileTransferTracker,
    ft_ts: FileTransferTracker,

    //temporary escaped header for detection
    //must be attached to transaction for memory management (be freed at the right time)
    pub escaped: Vec<Vec<u8>>,

    pub files: Files,
}

impl Transaction for HTTP2Transaction {
    fn id(&self) -> u64 {
        self.tx_id
    }
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
            decoder: decompression::HTTP2Decoder::new(),
            file_range: std::ptr::null_mut(),
            tx_data: AppLayerTxData::new(),
            ft_tc: FileTransferTracker::new(),
            ft_ts: FileTransferTracker::new(),
            escaped: Vec::with_capacity(16),
            files: Files::default(),
        }
    }

    pub fn free(&mut self) {
        if !self.file_range.is_null() {
            match unsafe { SC } {
                None => panic!("BUG no suricata_config"),
                Some(c) => {
                    //TODO get a file container instead of NULL
                    (c.HTPFileCloseHandleRange)(
                        std::ptr::null_mut(),
                        0,
                        self.file_range,
                        std::ptr::null_mut(),
                        0,
                    );
                    (c.HttpRangeFreeBlock)(self.file_range);
                    self.file_range = std::ptr::null_mut();
                }
            }
        }
    }

    pub fn set_event(&mut self, event: HTTP2Event) {
        self.tx_data.set_event(event as u8);
    }

    fn handle_headers(&mut self, blocks: &Vec<parser::HTTP2FrameHeaderBlock>, dir: Direction) {
        for i in 0..blocks.len() {
            if blocks[i].name == b"content-encoding" {
                self.decoder.http2_encoding_fromvec(&blocks[i].value, dir);
            }
        }
    }

    pub fn update_file_flags(&mut self, flow_file_flags: u16) {
        self.files.flags_ts = unsafe { FileFlowFlagsToFlags(flow_file_flags, STREAM_TOSERVER) | FILE_USE_DETECT };
        self.files.flags_tc = unsafe { FileFlowFlagsToFlags(flow_file_flags, STREAM_TOCLIENT) | FILE_USE_DETECT };
    }

    fn decompress<'a>(
        &'a mut self, input: &'a [u8], dir: Direction, sfcm: &'static SuricataFileContext, over: bool, flow: *const Flow,
    ) -> io::Result<()> {
        let mut output = Vec::with_capacity(decompression::HTTP2_DECOMPRESSION_CHUNK_SIZE);
        let decompressed = self.decoder.decompress(input, &mut output, dir)?;
        let xid: u32 = self.tx_id as u32;
        if dir == Direction::ToClient {
            self.ft_tc.tx_id = self.tx_id - 1;
            if !self.ft_tc.file_open {
                // we are now sure that new_chunk will open a file
                // even if it may close it right afterwards
                self.tx_data.incr_files_opened();
                if let Ok(value) = detect::http2_frames_get_header_value_vec(
                    self,
                    Direction::ToClient,
                    "content-range",
                ) {
                    match range::http2_parse_check_content_range(&value) {
                        Ok((_, v)) => {
                            range::http2_range_open(self, &v, flow, sfcm, Direction::ToClient, decompressed);
                            if over && !self.file_range.is_null() {
                                range::http2_range_close(self, Direction::ToClient, &[])
                            }
                        }
                        _ => {
                            self.set_event(HTTP2Event::InvalidRange);
                        }
                    }
                }
            } else {
                if !self.file_range.is_null() {
                    if over {
                        range::http2_range_close(self, Direction::ToClient, decompressed)
                    } else {
                        range::http2_range_append(self.file_range, decompressed)
                    }
                }
            }
            let (files, flags) = self.files.get(Direction::ToClient);
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
            let (files, flags) = self.files.get(Direction::ToServer);
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
        Ok(())
    }

    fn handle_frame(
        &mut self, header: &parser::HTTP2FrameHeader, data: &HTTP2FrameTypeData, dir: Direction,
    ) {
        //handle child_stream_id changes
        match data {
            HTTP2FrameTypeData::PUSHPROMISE(hs) => {
                if dir == Direction::ToClient {
                    //we could set an event if self.child_stream_id != 0
                    if header.flags & parser::HTTP2_FLAG_HEADER_END_HEADERS == 0 {
                        self.child_stream_id = hs.stream_id;
                    }
                    self.state = HTTP2TransactionState::HTTP2StateReserved;
                }
                self.handle_headers(&hs.blocks, dir);
            }
            HTTP2FrameTypeData::CONTINUATION(hs) => {
                if dir == Direction::ToClient
                    && header.flags & parser::HTTP2_FLAG_HEADER_END_HEADERS != 0
                {
                    self.child_stream_id = 0;
                }
                self.handle_headers(&hs.blocks, dir);
            }
            HTTP2FrameTypeData::HEADERS(hs) => {
                if dir == Direction::ToClient {
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
                            if dir == Direction::ToClient {
                                self.state = HTTP2TransactionState::HTTP2StateClosed;
                            }
                        }
                        HTTP2TransactionState::HTTP2StateHalfClosedServer => {
                            if dir == Direction::ToServer {
                                self.state = HTTP2TransactionState::HTTP2StateClosed;
                            }
                        }
                        // do not revert back to a half closed state
                        HTTP2TransactionState::HTTP2StateClosed => {}
                        HTTP2TransactionState::HTTP2StateGlobal => {}
                        _ => {
                            if dir == Direction::ToClient {
                                self.state = HTTP2TransactionState::HTTP2StateHalfClosedServer;
                            } else {
                                self.state = HTTP2TransactionState::HTTP2StateHalfClosedClient;
                            }
                        }
                    }
                } else if header.ftype == parser::HTTP2FrameType::DATA as u8 {
                    //not end of stream
                    if dir == Direction::ToServer {
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

#[derive(AppLayerEvent)]
pub enum HTTP2Event {
    InvalidFrameHeader,
    InvalidClientMagic,
    InvalidFrameData,
    InvalidHeader,
    InvalidFrameLength,
    ExtraHeaderData,
    LongFrameData,
    StreamIdReuse,
    InvalidHTTP1Settings,
    FailedDecompression,
    InvalidRange,
    HeaderIntegerOverflow,
    TooManyStreams,
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
    state_data: AppLayerStateData,
    tx_id: u64,
    request_frame_size: u32,
    response_frame_size: u32,
    dynamic_headers_ts: HTTP2DynTable,
    dynamic_headers_tc: HTTP2DynTable,
    transactions: VecDeque<HTTP2Transaction>,
    progress: HTTP2ConnectionState,
}

impl State<HTTP2Transaction> for HTTP2State {
    fn get_transaction_count(&self) -> usize {
        self.transactions.len()
    }

    fn get_transaction_by_index(&self, index: usize) -> Option<&HTTP2Transaction> {
        self.transactions.get(index)
    }
}

impl HTTP2State {
    pub fn new() -> Self {
        Self {
            state_data: AppLayerStateData::new(),
            tx_id: 0,
            request_frame_size: 0,
            response_frame_size: 0,
            // the headers are encoded on one byte
            // with a fixed number of static headers, and
            // a variable number of dynamic headers
            dynamic_headers_ts: HTTP2DynTable::new(),
            dynamic_headers_tc: HTTP2DynTable::new(),
            transactions: VecDeque::new(),
            progress: HTTP2ConnectionState::Http2StateInit,
        }
    }

    pub fn free(&mut self) {
        // this should be in HTTP2Transaction::free
        // but we need state's file container cf https://redmine.openinfosecfoundation.org/issues/4444
        for tx in &mut self.transactions {
            if !tx.file_range.is_null() {
                match unsafe { SC } {
                    None => panic!("BUG no suricata_config"),
                    Some(c) => {
                        (c.HTPFileCloseHandleRange)(
                            &mut tx.files.files_tc,
                            0,
                            tx.file_range,
                            std::ptr::null_mut(),
                            0,
                        );
                        (c.HttpRangeFreeBlock)(tx.file_range);
                        tx.file_range = std::ptr::null_mut();
                    }
                }
            }
        }
        self.transactions.clear();
    }

    pub fn set_event(&mut self, event: HTTP2Event) {
        let len = self.transactions.len();
        if len == 0 {
            return;
        }
        let tx = &mut self.transactions[len - 1];
        tx.tx_data.set_event(event as u8);
    }

    // Free a transaction by ID.
    fn free_tx(&mut self, tx_id: u64) {
        let len = self.transactions.len();
        let mut found = false;
        let mut index = 0;
        for i in 0..len {
            let tx = &mut self.transactions[i];
            if tx.tx_id == tx_id + 1 {
                found = true;
                index = i;
                // this should be in HTTP2Transaction::free
                // but we need state's file container cf https://redmine.openinfosecfoundation.org/issues/4444
                if !tx.file_range.is_null() {
                    match unsafe { SC } {
                        None => panic!("BUG no suricata_config"),
                        Some(c) => {
                            (c.HTPFileCloseHandleRange)(
                                &mut tx.files.files_tc,
                                0,
                                tx.file_range,
                                std::ptr::null_mut(),
                                0,
                            );
                            (c.HttpRangeFreeBlock)(tx.file_range);
                            tx.file_range = std::ptr::null_mut();
                        }
                    }
                }
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
                tx.tx_data.update_file_flags(self.state_data.file_flags);
                tx.update_file_flags(tx.tx_data.file_flags);
                return Some(tx);
            }
        }
        None
    }

    fn find_tx_index(&mut self, sid: u32) -> usize {
        for i in 0..self.transactions.len() {
            //reverse order should be faster
            let idx = self.transactions.len() - 1 - i;
            if sid == self.transactions[idx].stream_id {
                return idx + 1;
            }
        }
        0
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
        sid
    }

    fn create_global_tx(&mut self) -> &mut HTTP2Transaction {
        //special transaction with only one frame
        //as it affects the global connection, there is no end to it
        let mut tx = HTTP2Transaction::new();
        self.tx_id += 1;
        tx.tx_id = self.tx_id;
        tx.state = HTTP2TransactionState::HTTP2StateGlobal;
        tx.tx_data.update_file_flags(self.state_data.file_flags);
        // TODO can this tx hold files?
        tx.tx_data.file_tx = STREAM_TOSERVER|STREAM_TOCLIENT; // might hold files in both directions
        tx.update_file_flags(tx.tx_data.file_flags);
        self.transactions.push_back(tx);
        return self.transactions.back_mut().unwrap();
    }

    pub fn find_or_create_tx(
        &mut self, header: &parser::HTTP2FrameHeader, data: &HTTP2FrameTypeData, dir: Direction,
    ) -> &mut HTTP2Transaction {
        if header.stream_id == 0 {
            return self.create_global_tx();
        }
        let sid = match data {
            //yes, the right stream_id for Suricata is not the header one
            HTTP2FrameTypeData::PUSHPROMISE(hs) => hs.stream_id,
            HTTP2FrameTypeData::CONTINUATION(_) => {
                if dir == Direction::ToClient {
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

            let tx = &mut self.transactions[index - 1];
            tx.tx_data.update_file_flags(self.state_data.file_flags);
            tx.update_file_flags(tx.tx_data.file_flags);
            tx
        } else {
            let mut tx = HTTP2Transaction::new();
            self.tx_id += 1;
            tx.tx_id = self.tx_id;
            tx.stream_id = sid;
            tx.state = HTTP2TransactionState::HTTP2StateOpen;
            // do not use SETTINGS_MAX_CONCURRENT_STREAMS as it can grow too much
            if self.transactions.len() > unsafe { HTTP2_MAX_STREAMS } {
                // set at least one another transaction to the drop state
                for tx_old in &mut self.transactions {
                    if tx_old.state != HTTP2TransactionState::HTTP2StateTodrop {
                        // use a distinct state, even if we do not log it
                        tx_old.set_event(HTTP2Event::TooManyStreams);
                        tx_old.state = HTTP2TransactionState::HTTP2StateTodrop;
                        break;
                    }
                }
            }
            tx.tx_data.update_file_flags(self.state_data.file_flags);
            tx.update_file_flags(tx.tx_data.file_flags);
            tx.tx_data.file_tx = STREAM_TOSERVER|STREAM_TOCLIENT; // might hold files in both directions
            self.transactions.push_back(tx);
            return self.transactions.back_mut().unwrap();
        }
    }

    fn process_headers(&mut self, blocks: &Vec<parser::HTTP2FrameHeaderBlock>, dir: Direction) {
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
            } else if blocks[i].error
                == parser::HTTP2HeaderDecodeStatus::HTTP2HeaderDecodeIntegerOverflow
            {
                self.set_event(HTTP2Event::HeaderIntegerOverflow);
            }
        }
        if update {
            //borrow checker forbids to pass directly dyn_headers
            let dyn_headers = if dir == Direction::ToClient {
                &mut self.dynamic_headers_tc
            } else {
                &mut self.dynamic_headers_ts
            };
            dyn_headers.max_size = sizeup as usize;
        }
    }

    fn parse_frame_data(
        &mut self, ftype: u8, input: &[u8], complete: bool, hflags: u8, dir: Direction,
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
                        HTTP2FrameTypeData::GOAWAY(goaway)
                    }
                    Err(_) => {
                        self.set_event(HTTP2Event::InvalidFrameData);
                        HTTP2FrameTypeData::UNHANDLED(HTTP2FrameUnhandled {
                            reason: HTTP2FrameUnhandledReason::ParsingError,
                        })
                    }
                }
            }
            Some(parser::HTTP2FrameType::SETTINGS) => {
                match parser::http2_parse_frame_settings(input) {
                    Ok((_, set)) => {
                        for i in 0..set.len() {
                            if set[i].id == parser::HTTP2SettingsId::SETTINGSHEADERTABLESIZE {
                                //reverse order as this is what we accept from the other endpoint
                                let dyn_headers = if dir == Direction::ToClient {
                                    &mut self.dynamic_headers_ts
                                } else {
                                    &mut self.dynamic_headers_tc
                                };
                                dyn_headers.max_size = set[i].value as usize;
                                if set[i].value > unsafe { HTTP2_MAX_TABLESIZE } {
                                    //mark potential overflow
                                    dyn_headers.overflow = 1;
                                } else {
                                    //reset in case peer set a lower value, to be tested
                                    dyn_headers.overflow = 0;
                                }
                            }
                        }
                        //we could set an event on remaining data
                        HTTP2FrameTypeData::SETTINGS(set)
                    }
                    Err(Err::Incomplete(_)) => {
                        if complete {
                            self.set_event(HTTP2Event::InvalidFrameData);
                            HTTP2FrameTypeData::UNHANDLED(HTTP2FrameUnhandled {
                                reason: HTTP2FrameUnhandledReason::ParsingError,
                            })
                        } else {
                            HTTP2FrameTypeData::UNHANDLED(HTTP2FrameUnhandled {
                                reason: HTTP2FrameUnhandledReason::TooLong,
                            })
                        }
                    }
                    Err(_) => {
                        self.set_event(HTTP2Event::InvalidFrameData);
                        HTTP2FrameTypeData::UNHANDLED(HTTP2FrameUnhandled {
                            reason: HTTP2FrameUnhandledReason::ParsingError,
                        })
                    }
                }
            }
            Some(parser::HTTP2FrameType::RSTSTREAM) => {
                if input.len() != HTTP2_FRAME_RSTSTREAM_LEN {
                    self.set_event(HTTP2Event::InvalidFrameLength);
                    HTTP2FrameTypeData::UNHANDLED(HTTP2FrameUnhandled {
                        reason: HTTP2FrameUnhandledReason::Incomplete,
                    })
                } else {
                    match parser::http2_parse_frame_rststream(input) {
                        Ok((_, rst)) => {
                            HTTP2FrameTypeData::RSTSTREAM(rst)
                        }
                        Err(_) => {
                            self.set_event(HTTP2Event::InvalidFrameData);
                            HTTP2FrameTypeData::UNHANDLED(HTTP2FrameUnhandled {
                                reason: HTTP2FrameUnhandledReason::ParsingError,
                            })
                        }
                    }
                }
            }
            Some(parser::HTTP2FrameType::PRIORITY) => {
                if input.len() != HTTP2_FRAME_PRIORITY_LEN {
                    self.set_event(HTTP2Event::InvalidFrameLength);
                    HTTP2FrameTypeData::UNHANDLED(HTTP2FrameUnhandled {
                        reason: HTTP2FrameUnhandledReason::Incomplete,
                    })
                } else {
                    match parser::http2_parse_frame_priority(input) {
                        Ok((_, priority)) => {
                            HTTP2FrameTypeData::PRIORITY(priority)
                        }
                        Err(_) => {
                            self.set_event(HTTP2Event::InvalidFrameData);
                            HTTP2FrameTypeData::UNHANDLED(HTTP2FrameUnhandled {
                                reason: HTTP2FrameUnhandledReason::ParsingError,
                            })
                        }
                    }
                }
            }
            Some(parser::HTTP2FrameType::WINDOWUPDATE) => {
                if input.len() != HTTP2_FRAME_WINDOWUPDATE_LEN {
                    self.set_event(HTTP2Event::InvalidFrameLength);
                    HTTP2FrameTypeData::UNHANDLED(HTTP2FrameUnhandled {
                        reason: HTTP2FrameUnhandledReason::Incomplete,
                    })
                } else {
                    match parser::http2_parse_frame_windowupdate(input) {
                        Ok((_, wu)) => {
                            HTTP2FrameTypeData::WINDOWUPDATE(wu)
                        }
                        Err(_) => {
                            self.set_event(HTTP2Event::InvalidFrameData);
                            HTTP2FrameTypeData::UNHANDLED(HTTP2FrameUnhandled {
                                reason: HTTP2FrameUnhandledReason::ParsingError,
                            })
                        }
                    }
                }
            }
            Some(parser::HTTP2FrameType::PUSHPROMISE) => {
                let dyn_headers = if dir == Direction::ToClient {
                    &mut self.dynamic_headers_tc
                } else {
                    &mut self.dynamic_headers_ts
                };
                match parser::http2_parse_frame_push_promise(input, hflags, dyn_headers) {
                    Ok((_, hs)) => {
                        self.process_headers(&hs.blocks, dir);
                        HTTP2FrameTypeData::PUSHPROMISE(hs)
                    }
                    Err(Err::Incomplete(_)) => {
                        if complete {
                            self.set_event(HTTP2Event::InvalidFrameData);
                            HTTP2FrameTypeData::UNHANDLED(HTTP2FrameUnhandled {
                                reason: HTTP2FrameUnhandledReason::ParsingError,
                            })
                        } else {
                            HTTP2FrameTypeData::UNHANDLED(HTTP2FrameUnhandled {
                                reason: HTTP2FrameUnhandledReason::TooLong,
                            })
                        }
                    }
                    Err(_) => {
                        self.set_event(HTTP2Event::InvalidFrameData);
                        HTTP2FrameTypeData::UNHANDLED(HTTP2FrameUnhandled {
                            reason: HTTP2FrameUnhandledReason::ParsingError,
                        })
                    }
                }
            }
            Some(parser::HTTP2FrameType::DATA) => {
                HTTP2FrameTypeData::DATA
            }
            Some(parser::HTTP2FrameType::CONTINUATION) => {
                let dyn_headers = if dir == Direction::ToClient {
                    &mut self.dynamic_headers_tc
                } else {
                    &mut self.dynamic_headers_ts
                };
                match parser::http2_parse_frame_continuation(input, dyn_headers) {
                    Ok((_, hs)) => {
                        self.process_headers(&hs.blocks, dir);
                        HTTP2FrameTypeData::CONTINUATION(hs)
                    }
                    Err(Err::Incomplete(_)) => {
                        if complete {
                            self.set_event(HTTP2Event::InvalidFrameData);
                            HTTP2FrameTypeData::UNHANDLED(HTTP2FrameUnhandled {
                                reason: HTTP2FrameUnhandledReason::ParsingError,
                            })
                        } else {
                            HTTP2FrameTypeData::UNHANDLED(HTTP2FrameUnhandled {
                                reason: HTTP2FrameUnhandledReason::TooLong,
                            })
                        }
                    }
                    Err(_) => {
                        self.set_event(HTTP2Event::InvalidFrameData);
                        HTTP2FrameTypeData::UNHANDLED(HTTP2FrameUnhandled {
                            reason: HTTP2FrameUnhandledReason::ParsingError,
                        })
                    }
                }
            }
            Some(parser::HTTP2FrameType::HEADERS) => {
                let dyn_headers = if dir == Direction::ToClient {
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
                        HTTP2FrameTypeData::HEADERS(hs)
                    }
                    Err(Err::Incomplete(_)) => {
                        if complete {
                            self.set_event(HTTP2Event::InvalidFrameData);
                            HTTP2FrameTypeData::UNHANDLED(HTTP2FrameUnhandled {
                                reason: HTTP2FrameUnhandledReason::ParsingError,
                            })
                        } else {
                            HTTP2FrameTypeData::UNHANDLED(HTTP2FrameUnhandled {
                                reason: HTTP2FrameUnhandledReason::TooLong,
                            })
                        }
                    }
                    Err(_) => {
                        self.set_event(HTTP2Event::InvalidFrameData);
                        HTTP2FrameTypeData::UNHANDLED(HTTP2FrameUnhandled {
                            reason: HTTP2FrameUnhandledReason::ParsingError,
                        })
                    }
                }
            }
            Some(parser::HTTP2FrameType::PING) => {
                HTTP2FrameTypeData::PING
            }
            _ => {
                HTTP2FrameTypeData::UNHANDLED(HTTP2FrameUnhandled {
                    reason: HTTP2FrameUnhandledReason::UnknownType,
                })
            }
        }
    }

    fn parse_frames(
        &mut self, mut input: &[u8], il: usize, dir: Direction, flow: *const Flow,
    ) -> AppLayerResult {
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
                    if dir == Direction::ToServer {
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
                                    let mut tx_same = &mut self.transactions[index - 1];
                                    if dir == Direction::ToServer {
                                        tx_same.ft_tc.tx_id = tx_same.tx_id - 1;
                                    } else {
                                        tx_same.ft_ts.tx_id = tx_same.tx_id - 1;
                                    };

                                    match tx_same.decompress(
                                        &rem[..hlsafe],
                                        dir,
                                        sfcm,
                                        over,
                                        flow,
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
                Err(Err::Incomplete(_)) => {
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
        AppLayerResult::ok()
    }

    fn parse_ts(&mut self, mut input: &[u8], flow: *const Flow) -> AppLayerResult {
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
        let r = self.parse_frames(input, il, Direction::ToServer, flow);
        if r.status == 1 {
            //adds bytes consumed by banner to incomplete result
            AppLayerResult::incomplete(r.consumed + magic_consumed as u32, r.needed)
        } else {
            r
        }
    }

    fn parse_tc(&mut self, mut input: &[u8], flow: *const Flow) -> AppLayerResult {
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
        self.parse_frames(input, il, Direction::ToClient, flow)
    }
}

// C exports.

export_tx_data_get!(rs_http2_get_tx_data, HTTP2Transaction);
export_state_data_get!(rs_http2_get_state_data, HTTP2State);

/// C entry point for a probing parser.
#[no_mangle]
pub unsafe extern "C" fn rs_http2_probing_parser_tc(
    _flow: *const Flow, _direction: u8, input: *const u8, input_len: u32, _rdir: *mut u8,
) -> AppProto {
    if !input.is_null() {
        let slice = build_slice!(input, input_len as usize);
        match parser::http2_parse_frame_header(slice) {
            Ok((_, header)) => {
                if header.reserved != 0
                    || header.length > HTTP2_DEFAULT_MAX_FRAME_SIZE
                    || header.flags & 0xFE != 0
                    || header.ftype != parser::HTTP2FrameType::SETTINGS as u8
                {
                    return ALPROTO_FAILED;
                }
                return ALPROTO_HTTP2;
            }
            Err(Err::Incomplete(_)) => {
                return ALPROTO_UNKNOWN;
            }
            Err(_) => {
                return ALPROTO_FAILED;
            }
        }
    }
    ALPROTO_UNKNOWN
}

// Extern functions operating on HTTP2.
extern "C" {
    pub fn HTTP2MimicHttp1Request(
        orig_state: *mut std::os::raw::c_void, new_state: *mut std::os::raw::c_void,
    );
}

// Suppress the unsafe warning here as creating a state for an app-layer
// is typically not unsafe.
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn rs_http2_state_new(
    orig_state: *mut std::os::raw::c_void, _orig_proto: AppProto,
) -> *mut std::os::raw::c_void {
    let state = HTTP2State::new();
    let boxed = Box::new(state);
    let r = Box::into_raw(boxed) as *mut _;
    if !orig_state.is_null() {
        //we could check ALPROTO_HTTP1 == orig_proto
        unsafe {
            HTTP2MimicHttp1Request(orig_state, r);
        }
    }
    r
}

#[no_mangle]
pub unsafe extern "C" fn rs_http2_state_free(state: *mut std::os::raw::c_void) {
    let mut state: Box<HTTP2State> = Box::from_raw(state as _);
    state.free();
}

#[no_mangle]
pub unsafe extern "C" fn rs_http2_state_tx_free(state: *mut std::os::raw::c_void, tx_id: u64) {
    let state = cast_pointer!(state, HTTP2State);
    state.free_tx(tx_id);
}

#[no_mangle]
pub unsafe extern "C" fn rs_http2_parse_ts(
    flow: *const Flow, state: *mut std::os::raw::c_void, _pstate: *mut std::os::raw::c_void,
    stream_slice: StreamSlice, _data: *const std::os::raw::c_void,
) -> AppLayerResult {
    let state = cast_pointer!(state, HTTP2State);
    let buf = stream_slice.as_slice();
    state.parse_ts(buf, flow)
}

#[no_mangle]
pub unsafe extern "C" fn rs_http2_parse_tc(
    flow: *const Flow, state: *mut std::os::raw::c_void, _pstate: *mut std::os::raw::c_void,
    stream_slice: StreamSlice, _data: *const std::os::raw::c_void,
) -> AppLayerResult {
    let state = cast_pointer!(state, HTTP2State);
    let buf = stream_slice.as_slice();
    state.parse_tc(buf, flow)
}

#[no_mangle]
pub unsafe extern "C" fn rs_http2_state_get_tx(
    state: *mut std::os::raw::c_void, tx_id: u64,
) -> *mut std::os::raw::c_void {
    let state = cast_pointer!(state, HTTP2State);
    match state.get_tx(tx_id) {
        Some(tx) => {
            tx as *const _ as *mut _
        }
        None => {
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_http2_state_get_tx_count(state: *mut std::os::raw::c_void) -> u64 {
    let state = cast_pointer!(state, HTTP2State);
    state.tx_id
}

#[no_mangle]
pub unsafe extern "C" fn rs_http2_tx_get_state(
    tx: *mut std::os::raw::c_void,
) -> HTTP2TransactionState {
    let tx = cast_pointer!(tx, HTTP2Transaction);
    tx.state
}

#[no_mangle]
pub unsafe extern "C" fn rs_http2_tx_get_alstate_progress(
    tx: *mut std::os::raw::c_void, _direction: u8,
) -> std::os::raw::c_int {
    rs_http2_tx_get_state(tx) as i32
}

#[no_mangle]
pub unsafe extern "C" fn rs_http2_getfiles(
    tx: *mut std::os::raw::c_void, direction: u8,
) -> *mut FileContainer {
    let tx = cast_pointer!(tx, HTTP2Transaction);
    if direction == Direction::ToClient.into() {
        &mut tx.files.files_tc as *mut FileContainer
    } else {
        &mut tx.files.files_ts as *mut FileContainer
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
        tx_comp_st_ts: HTTP2TransactionState::HTTP2StateClosed as i32,
        tx_comp_st_tc: HTTP2TransactionState::HTTP2StateClosed as i32,
        tx_get_progress: rs_http2_tx_get_alstate_progress,
        get_eventinfo: Some(HTTP2Event::get_event_info),
        get_eventinfo_byid: Some(HTTP2Event::get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_tx_files: Some(rs_http2_getfiles),
        get_tx_iterator: Some(applayer::state_get_tx_iterator::<HTTP2State, HTTP2Transaction>),
        get_tx_data: rs_http2_get_tx_data,
        get_state_data: rs_http2_get_state_data,
        apply_tx_config: None,
        flags: 0,
        truncate: None,
        get_frame_id_by_name: None,
        get_frame_name_by_id: None,
    };

    let ip_proto_str = CString::new("tcp").unwrap();

    if AppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_HTTP2 = alproto;
        if AppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
        if let Some(val) = conf_get("app-layer.protocols.http2.max-streams") {
            if let Ok(v) = val.parse::<usize>() {
                HTTP2_MAX_STREAMS = v;
            } else {
                SCLogError!("Invalid value for http2.max-streams");
            }
        }
        if let Some(val) = conf_get("app-layer.protocols.http2.max-table-size") {
            if let Ok(v) = val.parse::<u32>() {
                HTTP2_MAX_TABLESIZE = v;
            } else {
                SCLogError!("Invalid value for http2.max-table-size");
            }
        }
        SCLogDebug!("Rust http2 parser registered.");
    } else {
        SCLogNotice!("Protocol detector and parser disabled for HTTP2.");
    }
}
