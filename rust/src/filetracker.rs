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

// written by Victor Julien
extern crate libc;
use log::*;
use core::*;
use std::collections::HashMap;
use std::collections::hash_map::Entry::{Occupied, Vacant};
use filecontainer::*;

#[derive(Debug)]
pub struct FileTransferTracker {
    file_size: u64,
    tracked: u64,
    track_id: u32,
    chunk_left: u32,

    pub tx_id: u64,

    fill_bytes: u8,
    pub file_open: bool,
    chunk_is_last: bool,
    chunk_is_ooo: bool,

    chunks: HashMap<u64, Vec<u8>>,
    cur_ooo_chunk_offset: u64,
}

impl FileTransferTracker {
    pub fn new() -> FileTransferTracker {
        FileTransferTracker {
            file_size:0,
            tracked:0,
            track_id:0,
            chunk_left:0,
            tx_id:0,
            fill_bytes:0,
            file_open:false,
            chunk_is_last:false,
            chunk_is_ooo:false,
            cur_ooo_chunk_offset:0,
            chunks:HashMap::new(),
        }
    }

    fn open(&mut self, config: &'static SuricataFileContext,
            files: &mut FileContainer, flags: u16, name: &[u8]) -> i32
    {
        let r = files.file_open(config, &self.track_id, name, flags);
        if r == 0 {
            files.file_set_txid_on_last_file(self.tx_id);
        }
        self.file_open = true;
        r
    }

    pub fn close(&mut self, files: &mut FileContainer, flags: u16) {
        files.file_close(&self.track_id, flags);
        self.file_open = false;
        self.tracked = 0;
        files.files_prune();
    }

    pub fn create(&mut self, name: &[u8], file_size: u64) {
        if self.file_open == true { panic!("close existing file first"); }

        SCLogDebug!("CREATE: name {:?} file_size {}", name, file_size);
    }

    pub fn new_chunk(&mut self, config: &'static SuricataFileContext,
            files: &mut FileContainer, flags: u16,
            name: &[u8], data: &[u8], chunk_offset: u64, chunk_size: u32,
            fill_bytes: u8, is_last: bool, xid: &u32) -> u32
    {
        if self.chunk_left != 0 { panic!("complete existing chunk first"); }
        if self.fill_bytes != 0 { panic!("complete existing fill bytes first"); }

        SCLogDebug!("NEW CHUNK: chunk_size {} fill_bytes {}", chunk_size, fill_bytes);

        if chunk_offset != self.tracked {
            SCLogDebug!("NEW CHUNK IS OOO: expected {}, got {}", self.tracked, chunk_offset);
            self.chunk_is_ooo = true;
            self.cur_ooo_chunk_offset = chunk_offset;
        }

        self.chunk_left = chunk_size;
        self.fill_bytes = fill_bytes;
        self.chunk_is_last = is_last;

        if self.file_open == false {
            SCLogDebug!("NEW CHUNK: FILE OPEN");
            self.track_id = *xid;
            self.open(config, files, flags, name);
        }

        let res = self.update(files, flags, data);
        SCLogDebug!("NEW CHUNK: update res {:?}", res);
        res
    }

    /// return how much we consumed of data
    pub fn update(&mut self, files: &mut FileContainer, flags: u16, data: &[u8]) -> u32 {
        let mut consumed = 0 as usize;
        if self.chunk_left + self.fill_bytes as u32 == 0 {
            //SCLogDebug!("UPDATE: nothing to do");
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

                if self.chunk_is_ooo == false {
                    let res = files.file_append(&self.track_id, d);
                    if res != 0 { panic!("append failed"); }

                    self.tracked += self.chunk_left as u64;
                } else {
                    SCLogDebug!("UPDATE: appending data {} to ooo chunk at offset {}/{}",
                            d.len(), self.cur_ooo_chunk_offset, self.tracked);
                    let c = match self.chunks.entry(self.cur_ooo_chunk_offset) {
                        Vacant(entry) => {
                            entry.insert(Vec::with_capacity(self.chunk_left as usize))
                        },
                        Occupied(entry) => entry.into_mut(),
                    };
                    c.extend(d);
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
                    //return consumed as u32
                } else {
                    self.chunk_left = 0;

                    if self.chunk_is_ooo == false {
                        loop {
                            let offset = self.tracked;
                            match self.chunks.remove(&self.tracked) {
                                Some(a) => {
                                    let res = files.file_append(&self.track_id, &a);
                                    if res != 0 { panic!("append failed"); }

                                    self.tracked += a.len() as u64;

                                    SCLogDebug!("STORED OOO CHUNK at offset {}, tracked now {}, stored len {}", offset, self.tracked, a.len());
                                },
                                _ => {
                                    SCLogDebug!("NO STORED CHUNK found at offset {}", self.tracked);
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
                if self.chunk_is_last == true {
                    SCLogDebug!("last chunk, closing");
                    self.close(files, flags);
                    self.chunk_is_last = false;
                } else {
                    SCLogDebug!("NOT last chunk, keep going");
                }

            } else {
                if self.chunk_is_ooo == false {
                    let res = files.file_append(&self.track_id, data);
                    if res != 0 { panic!("append failed"); }
                    self.tracked += data.len() as u64;
                } else {
                    let c = match self.chunks.entry(self.cur_ooo_chunk_offset) {
                        Vacant(entry) => entry.insert(Vec::with_capacity(32768)),
                        Occupied(entry) => entry.into_mut(),
                    };
                    c.extend(data);
                }

                self.chunk_left -= data.len() as u32;
                consumed += data.len();
            }
        }
        files.files_prune();
        consumed as u32
    }
}
