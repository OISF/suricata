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

/**
 *  \file
 *  \author Victor Julien <victor@inliniac.net>
 *
 * Tracks chunk based file transfers. Chunks may be transfered out
 * of order, but cannot be transfered in parallel. So only one
 * chunk at a time.
 *
 * GAP handling. If a data gap is encountered, the file is truncated
 * and new data is no longer pushed down to the lower level APIs.
 * The tracker does continue to follow the file.
 */

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

    pub tx_id: u64,

    fill_bytes: u8,
    pub file_open: bool,
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

    fn open(&mut self, config: &'static SuricataFileContext,
            files: &mut FileContainer, flags: u16, name: &[u8]) -> i32
    {
        let r = files.file_open(config, &self.track_id, name, flags);
        if r == 0 {
            self.file_open = true;
        }
        r
    }

    pub fn close(&mut self, files: &mut FileContainer, flags: u16) {
        if !self.file_is_truncated {
            SCLogDebug!("closing file with id {}", self.track_id);
            files.file_close(&self.track_id, flags);
        }
        self.file_open = false;
        self.tracked = 0;
    }

    pub fn trunc (&mut self, files: &mut FileContainer, flags: u16) {
        if self.file_is_truncated || !self.file_open {
            return;
        }
        let myflags = flags | 1; // TODO util-file.c::FILE_TRUNCATED
        files.file_close(&self.track_id, myflags);
        SCLogDebug!("truncated file");
        self.file_is_truncated = true;
    }

    pub fn create(&mut self, _name: &[u8], _file_size: u64) {
        if self.file_open { panic!("close existing file first"); }

        SCLogDebug!("CREATE: name {:?} file_size {}", _name, _file_size);
    }

    pub fn new_chunk(&mut self, config: &'static SuricataFileContext,
            files: &mut FileContainer, flags: u16,
            name: &[u8], data: &[u8], chunk_offset: u64, chunk_size: u32,
            fill_bytes: u8, is_last: bool, xid: &u32) -> u32
    {
        if self.chunk_left != 0 || self.fill_bytes != 0 {
            SCLogDebug!("current chunk incomplete: truncating");
            self.trunc(files, flags);
        }

        SCLogDebug!("NEW CHUNK: chunk_size {} fill_bytes {}", chunk_size, fill_bytes);

        // for now assume that is_last means its really the last chunk
        // so no out of order chunks coming after. This means that if
        // the last chunk is out or order, we've missed chunks before.
        if chunk_offset != self.tracked {
            SCLogDebug!("NEW CHUNK IS OOO: expected {}, got {}", self.tracked, chunk_offset);
            if is_last {
                SCLogDebug!("last chunk is out of order, this means we missed data before");
                self.trunc(files, flags);
            }
            self.chunk_is_ooo = true;
            self.cur_ooo_chunk_offset = chunk_offset;
        }

        self.chunk_left = chunk_size;
        self.fill_bytes = fill_bytes;
        self.chunk_is_last = is_last;

        if !self.file_open {
            SCLogDebug!("NEW CHUNK: FILE OPEN");
            self.track_id = *xid;
            self.open(config, files, flags, name);
        }

        if self.file_open {
            let res = self.update(files, flags, data, 0);
            SCLogDebug!("NEW CHUNK: update res {:?}", res);
            return res;
        }

        0
    }

    /// update the file tracker
    /// If gap_size > 0 'data' should not be used.
    /// return how much we consumed of data
    pub fn update(&mut self, files: &mut FileContainer, flags: u16, data: &[u8], gap_size: u32) -> u32 {
        let mut consumed = 0_usize;
        let is_gap = gap_size > 0;
        if is_gap || gap_size > 0 {
            SCLogDebug!("is_gap {} size {} ooo? {}", is_gap, gap_size, self.chunk_is_ooo);
        }

        if self.chunk_left == 0 && self.fill_bytes == 0 {
            //SCLogDebug!("UPDATE: nothing to do");
            if self.chunk_is_last {
                SCLogDebug!("last empty chunk, closing");
                self.close(files, flags);
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
                    let res = files.file_append(&self.track_id, d, is_gap);
                    match res {
                        0   => { },
                        -2  => {
                            self.file_is_truncated = true;
                        },
                        _ => {
                            SCLogDebug!("got error so truncing file");
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

                                    let res = files.file_append(&self.track_id, &c.chunk, c.contains_gap);
                                    match res {
                                        0   => { },
                                        -2  => {
                                            self.file_is_truncated = true;
                                        },
                                        _ => {
                                            SCLogDebug!("got error so truncing file");
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
                    self.close(files, flags);
                    self.chunk_is_last = false;
                } else {
                    SCLogDebug!("NOT last chunk, keep going");
                }

            } else {
                if !self.chunk_is_ooo {
                    let res = files.file_append(&self.track_id, data, is_gap);
                    match res {
                        0   => { },
                        -2  => {
                            self.file_is_truncated = true;
                        },
                        _ => {
                            SCLogDebug!("got error so truncing file");
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
