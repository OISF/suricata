/* Copyright (C) 2017 Open Information Security Foundation
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

//! Gap handling and Chunk-based file transfer tracker module.
//!
//! GAP handling. If a data gap is encountered, the file is truncated
//! and new data is no longer pushed down to the lower level APIs.
//! The tracker does continue to follow the file
//
//! Tracks chunk based file transfers. Chunks may be transferred out
//! of order, but cannot be transferred in parallel. So only one
//! chunk at a time.
//!
//! Author: Victor Julien <victor@inliniac.net>

use crate::core::*;
use std::collections::HashMap;
use std::collections::hash_map::Entry::{Occupied, Vacant};
use crate::filecontainer::*;

#[derive(Debug)]
struct FileChunk {
    contains_gap: bool,
    chunk: Vec<u8>,
}

impl FileChunk {
    pub fn new(size: u32) -> FileChunk {
        FileChunk {
            contains_gap: false,
            chunk: Vec::with_capacity(size as usize),
        }
    }
}

#[derive(Debug)]
#[derive(Default)]
pub struct FileTransferTracker {
    pub tracked: u64,
    cur_ooo: u64,   // how many bytes do we have queued from ooo chunks
    track_id: u32,
    chunk_left: u32,

    pub file: FileContainer,
    pub file_flags: u16,

    pub tx_id: u64,

    fill_bytes: u8,
    pub file_open: bool,
    file_closed: bool,
    chunk_is_last: bool,
    chunk_is_ooo: bool,
    file_is_truncated: bool,

    chunks: HashMap<u64, FileChunk>,
    cur_ooo_chunk_offset: u64,

    in_flight: u64,
}

impl FileTransferTracker {
    pub fn new() -> FileTransferTracker {
        FileTransferTracker {
            chunks:HashMap::new(),
            ..Default::default()
        }
    }

    pub fn is_done(&self) -> bool {
        !self.file_open
    }

    pub fn is_initialized(&self) -> bool {
        return self.file_open || self.file_is_truncated || self.file_closed;
    }

    fn open(&mut self, config: &'static SuricataFileContext, name: &[u8]) -> i32
    {
        let r = self.file.file_open(config, self.track_id, name, self.file_flags);
        if r == 0 {
            self.file_open = true;
        }
        r
    }

    pub fn close(&mut self, config: &'static SuricataFileContext)
    {
        if !self.file_is_truncated {
            SCLogDebug!("closing file with id {}", self.track_id);
            self.file.file_close(config, &self.track_id, self.file_flags);
        }
        self.file_open = false;
        self.file_closed = true;
        self.tracked = 0;
    }

    pub fn trunc (&mut self, config: &'static SuricataFileContext)
    {
        if self.file_is_truncated || !self.file_open {
            return;
        }
        let myflags = self.file_flags | 1; // TODO util-file.c::FILE_TRUNCATED
        self.file.file_close(config, &self.track_id, myflags);
        SCLogDebug!("truncated file");
        self.file_is_truncated = true;
        self.chunks.clear();
        self.in_flight = 0;
        self.cur_ooo = 0;
    }

    pub fn new_chunk(&mut self, config: &'static SuricataFileContext,
            name: &[u8], data: &[u8], chunk_offset: u64, chunk_size: u32,
            fill_bytes: u8, is_last: bool, xid: &u32) -> u32
    {
        if self.chunk_left != 0 || self.fill_bytes != 0 {
            SCLogDebug!("current chunk incomplete: truncating");
            self.trunc(config);
        }

        SCLogDebug!("NEW CHUNK: chunk_size {} fill_bytes {}", chunk_size, fill_bytes);

        // for now assume that is_last means its really the last chunk
        // so no out of order chunks coming after. This means that if
        // the last chunk is out or order, we've missed chunks before.
        if chunk_offset != self.tracked {
            SCLogDebug!("NEW CHUNK IS OOO: expected {}, got {}", self.tracked, chunk_offset);
            if is_last {
                SCLogDebug!("last chunk is out of order, this means we missed data before");
                self.trunc(config);
            }
            self.chunk_is_ooo = true;
            self.cur_ooo_chunk_offset = chunk_offset;
        }

        self.chunk_left = chunk_size;
        self.fill_bytes = fill_bytes;
        self.chunk_is_last = is_last;

        if self.file_is_truncated || self.file_closed {
            return 0;
        }
        if !self.file_open {
            SCLogDebug!("NEW CHUNK: FILE OPEN");
            self.track_id = *xid;
            self.open(config, name);
        }

        if self.file_open {
            let res = self.update(config, data, 0);
            SCLogDebug!("NEW CHUNK: update res {:?}", res);
            return res;
        }

        0
    }

    /// update the file tracker
    /// If gap_size > 0 'data' should not be used.
    /// return how much we consumed of data
    pub fn update(&mut self, config: &'static SuricataFileContext, data: &[u8], gap_size: u32) -> u32
    {
        if self.file_is_truncated {
            let consumed = std::cmp::min(data.len() as u32, self.chunk_left);
            self.chunk_left = self.chunk_left.saturating_sub(data.len() as u32);
            return consumed;
        }
        let mut consumed = 0_usize;
        let is_gap = gap_size > 0;
        if is_gap || gap_size > 0 {
            SCLogDebug!("is_gap {} size {} ooo? {}", is_gap, gap_size, self.chunk_is_ooo);
        }

        if self.chunk_left == 0 && self.fill_bytes == 0 {
            //SCLogDebug!("UPDATE: nothing to do");
            if self.chunk_is_last {
                SCLogDebug!("last empty chunk, closing");
                self.close(config);
                self.chunk_is_last = false;
            }
            return 0
        } else if self.chunk_left == 0 {
            SCLogDebug!("FILL BYTES {} from prev run", self.fill_bytes);
            if data.len() >= self.fill_bytes as usize {
                consumed += self.fill_bytes as usize;
                self.fill_bytes = 0;
                SCLogDebug!("CHUNK(pre) fill bytes now 0");
            } else {
                consumed += data.len();
                self.fill_bytes -= data.len() as u8;
                SCLogDebug!("CHUNK(pre) fill bytes now still {}", self.fill_bytes);
            }
            SCLogDebug!("FILL BYTES: returning {}", consumed);
            return consumed as u32
        }
        SCLogDebug!("UPDATE: data {} chunk_left {}", data.len(), self.chunk_left);

        if self.chunk_left > 0 {
            if self.chunk_left <= data.len() as u32 {
                let d = &data[0..self.chunk_left as usize];

                if !self.chunk_is_ooo {
                    let res = self.file.file_append(config, &self.track_id, d, is_gap);
                    match res {
                        0   => { },
                        -2  => {
                            self.file_is_truncated = true;
                        },
                        _ => {
                            SCLogDebug!("got error so truncating file");
                            self.file_is_truncated = true;
                        },
                    }

                    self.tracked += self.chunk_left as u64;
                } else {
                    SCLogDebug!("UPDATE: appending data {} to ooo chunk at offset {}/{}",
                            d.len(), self.cur_ooo_chunk_offset, self.tracked);
                    let c = match self.chunks.entry(self.cur_ooo_chunk_offset) {
                        Vacant(entry) => {
                            entry.insert(FileChunk::new(self.chunk_left))
                        },
                        Occupied(entry) => entry.into_mut(),
                    };
                    self.cur_ooo += d.len() as u64;
                    c.contains_gap |= is_gap;
                    c.chunk.extend(d);

                    self.in_flight += d.len() as u64;
                    SCLogDebug!("{:p} in_flight {}", self, self.in_flight);
                }

                consumed += self.chunk_left as usize;
                if self.fill_bytes > 0 {
                    let extra = data.len() - self.chunk_left as usize;
                    if extra >= self.fill_bytes as usize {
                        consumed += self.fill_bytes as usize;
                        self.fill_bytes = 0;
                        SCLogDebug!("CHUNK(post) fill bytes now 0");
                    } else {
                        consumed += extra;
                        self.fill_bytes -= extra as u8;
                        SCLogDebug!("CHUNK(post) fill bytes now still {}", self.fill_bytes);
                    }
                    self.chunk_left = 0;
                } else {
                    self.chunk_left = 0;

                    if !self.chunk_is_ooo {
                        loop {
                            let _offset = self.tracked;
                            match self.chunks.remove(&self.tracked) {
                                Some(c) => {
                                    self.in_flight -= c.chunk.len() as u64;

                                    let res = self.file.file_append(config, &self.track_id, &c.chunk, c.contains_gap);
                                    match res {
                                        0   => { },
                                        -2  => {
                                            self.file_is_truncated = true;
                                        },
                                        _ => {
                                            SCLogDebug!("got error so truncating file");
                                            self.file_is_truncated = true;
                                        },
                                    }

                                    self.tracked += c.chunk.len() as u64;
                                    self.cur_ooo -= c.chunk.len() as u64;

                                    SCLogDebug!("STORED OOO CHUNK at offset {}, tracked now {}, stored len {}", _offset, self.tracked, c.chunk.len());
                                },
                                _ => {
                                    SCLogDebug!("NO STORED CHUNK found at _offset {}", self.tracked);
                                    break;
                                },
                            };
                        }
                    } else {
                        SCLogDebug!("UPDATE: complete ooo chunk. Offset {}", self.cur_ooo_chunk_offset);

                        self.chunk_is_ooo = false;
                        self.cur_ooo_chunk_offset = 0;
                    }
                }
                if self.chunk_is_last {
                    SCLogDebug!("last chunk, closing");
                    self.close(config);
                    self.chunk_is_last = false;
                } else {
                    SCLogDebug!("NOT last chunk, keep going");
                }

            } else {
                if !self.chunk_is_ooo {
                    let res = self.file.file_append(config, &self.track_id, data, is_gap);
                    match res {
                        0   => { },
                        -2  => {
                            self.file_is_truncated = true;
                        },
                        _ => {
                            SCLogDebug!("got error so truncating file");
                            self.file_is_truncated = true;
                        },
                    }
                    self.tracked += data.len() as u64;
                } else {
                    let c = match self.chunks.entry(self.cur_ooo_chunk_offset) {
                        Vacant(entry) => entry.insert(FileChunk::new(32768)),
                        Occupied(entry) => entry.into_mut(),
                    };
                    c.chunk.extend(data);
                    c.contains_gap |= is_gap;
                    self.cur_ooo += data.len() as u64;
                    self.in_flight += data.len() as u64;
                }

                self.chunk_left -= data.len() as u32;
                consumed += data.len();
            }
        }
        consumed as u32
    }

    pub fn get_queued_size(&self) -> u64 {
        self.cur_ooo
    }

    pub fn get_inflight_size(&self) -> u64 {
        self.in_flight
    }
    pub fn get_inflight_cnt(&self) -> usize {
        self.chunks.len()
    }
}
