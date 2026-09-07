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
    // Consumed but not stored: a discarded retransmission, so a split record's
    // continuation is skipped without touching the file.
    chunk_consume_only: bool,
    // Consume-and-discard before the in-progress chunk stores: the part of a
    // backward chunk's covered prefix its first fragment did not buffer (see
    // the new_chunk re-anchor); the continuation carries it first.
    chunk_pending_discard: u32,

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
        // no chunk state survives a close
        self.chunk_consume_only = false;
    }

    pub fn trunc (&mut self, config: &'static SuricataFileContext)
    {
        if self.file_is_truncated || !self.file_open {
            // no file state to drop: clear the discard markers as well
            self.chunk_consume_only = false;
            self.chunk_pending_discard = 0;
            return;
        }
        let myflags = self.file_flags | 1; // TODO util-file.c::FILE_TRUNCATED
        self.file.file_close(config, &self.track_id, myflags);
        SCLogDebug!("truncated file");
        self.file_is_truncated = true;
        self.chunk_consume_only = false;
        self.chunk_pending_discard = 0;
        self.chunks.clear();
        self.in_flight = 0;
        self.cur_ooo = 0;
    }

    pub fn new_chunk(
        &mut self, config: &'static SuricataFileContext, name: &[u8], data: &[u8],
        chunk_offset: u64, chunk_size: u32, fill_bytes: u8, is_last: bool, xid: &u32,
    ) -> u32 {
        // Shadowed so a partial-overlap trim below can re-anchor the chunk
        // at the tracked offset instead of discarding its new tail.
        let mut data = data;
        let mut chunk_offset = chunk_offset;
        let mut chunk_size = chunk_size;

        // A new chunk arms fresh discard state; the re-anchor below sets the
        // real value when a fragment leaves uncovered covered prefix behind.
        self.chunk_pending_discard = 0;

        if self.chunk_left != 0 || self.fill_bytes != 0 {
            if self.chunk_consume_only {
                // an unconsumed discarded chunk holds no file state:
                // reset it without truncating the file
                self.chunk_consume_only = false;
                self.chunk_left = 0;
                self.fill_bytes = 0;
            } else {
                SCLogDebug!("current chunk incomplete: truncating");
                self.trunc(config);
            }
        }

        SCLogDebug!("NEW CHUNK: chunk_size {} fill_bytes {}", chunk_size, fill_bytes);

        // for now assume that is_last means its really the last chunk
        // so no out of order chunks coming after. This means that if
        // the last chunk is out or order, we've missed chunks before.
        //
        // Chunk before `tracked` but extending past it: drop the covered prefix,
        // re-anchor at `tracked`, keep the LOGICAL tail (chunk_size - overlap),
        // not the buffered tail (else a fragmented chunk finishes early).
        // Trigger on the logical extent, not the buffered one: a partial record
        // can carry all its buffered bytes inside the tracked region while the
        // chunk still extends past it (else the retransmission arm below would
        // consume its new tail instead of storing it).
        if chunk_offset < self.tracked {
            let overlap = (self.tracked - chunk_offset) as usize;
            if chunk_size as usize > overlap {
                let drop = overlap.min(data.len());
                SCLogDebug!(
                    "NEW CHUNK partial overlap {}/{}: dropping {} covered bytes, logical tail {} ({} buffered this fragment)",
                    chunk_offset,
                    self.tracked,
                    drop,
                    (chunk_size as usize) - overlap,
                    data.len() - drop
                );
                data = &data[drop..];
                chunk_offset = self.tracked;
                chunk_size = chunk_size.saturating_sub(overlap as u32);
                // The continuation still carries the covered prefix this
                // fragment did not buffer: discard it as it arrives, only
                // the new extent is stored.
                self.chunk_pending_discard = (overlap - drop) as u32;
            }
        }
        if chunk_offset < self.tracked {
            // Retransmission of a tracked region: discard (never queue), and arm a
            // consume-only chunk so a split record's continuation is consumed cleanly.
            SCLogDebug!(
                "NEW CHUNK retransmits tracked offset {}/{}; dropping",
                chunk_offset,
                self.tracked
            );
            if is_last {
                // Terminal backward write: the file can no longer complete (the queue
                // only drains at `tracked`); truncate now so it is logged and released.
                self.trunc(config);
            }
            self.chunk_left = chunk_size;
            self.fill_bytes = fill_bytes;
            self.chunk_is_ooo = false;
            self.chunk_is_last = false;
            self.chunk_consume_only = true;
            if !self.file_open {
                return 0;
            }
            return self.update(config, data, 0);
        }
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

        if self.file_is_truncated {
            // File can't store data, but a split record's payload + XDR padding must
            // still be consumed (as the truncated update path does) to stay in sync.
            if !data.is_empty() {
                return self.update(config, data, 0);
            }
            return 0;
        }
        if self.file_closed {
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
    pub fn update(
        &mut self, config: &'static SuricataFileContext, data: &[u8], gap_size: u32,
    ) -> u32 {
        // A backward chunk's re-anchor may leave a covered prefix its
        // continuation carries before any storable byte: consume-and-discard
        // it first (see chunk_pending_discard).
        let mut data = data;
        let mut consumed = 0_usize;
        if self.chunk_pending_discard > 0 {
            let d = std::cmp::min(data.len(), self.chunk_pending_discard as usize);
            data = &data[d..];
            self.chunk_pending_discard -= d as u32;
            consumed += d;
            if data.is_empty() {
                return consumed as u32;
            }
        }
        if self.file_is_truncated || self.chunk_consume_only {
            // Consumed but not stored (truncated file or discarded retransmission): consume the
            // chunk data and the record's XDR padding together so the next record starts at a frame.
            let mut c = std::cmp::min(data.len() as u32, self.chunk_left);
            self.chunk_left = self.chunk_left.saturating_sub(c);
            if self.chunk_left == 0 && self.fill_bytes > 0 {
                let extra = (data.len() as u32).saturating_sub(c);
                let f = std::cmp::min(extra, self.fill_bytes as u32);
                c += f;
                self.fill_bytes = self.fill_bytes.saturating_sub(f as u8);
            }
            if self.chunk_left == 0 && self.fill_bytes == 0 {
                self.chunk_consume_only = false;
            }
            return consumed as u32 + c;
        }
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
            return consumed as u32;
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
                }
                self.chunk_left = 0;

                // Chunk completed in this call, padded or not: settle its state either
                // way (skipping leaves the OOO marker/offset stale for the next record).
                if !self.chunk_is_ooo {
                    loop {
                        let _offset = self.tracked;
                        match self.chunks.remove(&self.tracked) {
                            Some(c) => {
                                self.in_flight -= c.chunk.len() as u64;

                                let res = self.file.file_append(
                                    config,
                                    &self.track_id,
                                    &c.chunk,
                                    c.contains_gap,
                                );
                                match res {
                                    0 => {}
                                    -2 => {
                                        self.file_is_truncated = true;
                                    }
                                    _ => {
                                        SCLogDebug!("got error so truncating file");
                                        self.file_is_truncated = true;
                                    }
                                }

                                self.tracked += c.chunk.len() as u64;
                                self.cur_ooo -= c.chunk.len() as u64;

                                SCLogDebug!(
                                    "STORED OOO CHUNK at offset {}, tracked now {}, stored len {}",
                                    _offset,
                                    self.tracked,
                                    c.chunk.len()
                                );
                            }
                            _ => {
                                SCLogDebug!("NO STORED CHUNK found at _offset {}", self.tracked);
                                break;
                            }
                        };
                    }
                } else {
                    SCLogDebug!(
                        "UPDATE: complete ooo chunk. Offset {}",
                        self.cur_ooo_chunk_offset
                    );

                    self.chunk_is_ooo = false;
                    self.cur_ooo_chunk_offset = 0;
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

    /// The XDR padding bytes of the record whose chunk data is in flight.
    pub fn get_fill_bytes(&self) -> u8 {
        self.fill_bytes
    }

    /// True if an append at `offset` is out of order and grows the OOO queue.
    pub fn is_ooo_offset(&self, offset: u64) -> bool {
        offset > self.tracked
    }

    /// True if an append at `offset` creates a new OOO chunk-map entry
    /// (not a continuation of an already enqueued chunk).
    pub fn new_chunk_entry(&self, offset: u64) -> bool {
        self.is_ooo_offset(offset) && !self.chunks.contains_key(&offset)
    }

    /// True if the chunk currently being filled is out of order.
    pub fn current_chunk_is_ooo(&self) -> bool {
        self.chunk_is_ooo
    }
}

#[cfg(test)]
mod tests {
    use crate::core::{StreamingBufferConfig, SuricataFileContext};
    use crate::filetracker::FileTransferTracker;

    // the FFI file ops are no-ops under cfg(test), so a default context is
    // safe to use with the tracker
    static TEST_SBCFG: StreamingBufferConfig = StreamingBufferConfig::Test;
    static TEST_FC: SuricataFileContext = SuricataFileContext {
        files_sbcfg: &TEST_SBCFG,
    };

    #[test]
    fn test_partial_overlap_chunk_keeps_tail_past_tracked() {
        // tracked=4096; a chunk at offset 3072 of length 2048 spans 3072..5120.
        // The covered 1024-byte prefix is discarded; the new tail (4096..5120)
        // is stored, not lost (a permanent inspection/extraction gap).
        let xid: u32 = 0x42;
        let mut ft = FileTransferTracker::new();
        let head = vec![0u8; 4096];
        ft.new_chunk(&TEST_FC, b"f", &head, 0, 4096, 0, false, &xid);
        assert_eq!(ft.tracked, 4096);

        let overlap = vec![0u8; 2048];
        ft.new_chunk(&TEST_FC, b"f", &overlap, 3072, 2048, 0, false, &xid);
        // the 1024-byte tail past the tracked region must be stored
        assert_eq!(ft.tracked, 5120);
    }

    #[test]
    fn test_partial_overlap_fragmented_chunk_keeps_logical_tail() {
        // tracked=4096. A chunk at offset 3072 of LOGICAL size 8192, first fragment
        // only 4096 buffered bytes (3072..7168): drop the covered 1024-byte prefix,
        // keep the LOGICAL tail (4096..11264), not just the buffered tail.
        let xid: u32 = 0x44;
        let mut ft = FileTransferTracker::new();
        let head = vec![0u8; 4096];
        ft.new_chunk(&TEST_FC, b"f", &head, 0, 4096, 0, false, &xid);
        assert_eq!(ft.tracked, 4096);

        // first fragment: 4096 buffered bytes of the 8192-byte logical chunk
        let frag1 = vec![0u8; 4096];
        ft.new_chunk(&TEST_FC, b"f", &frag1, 3072, 8192, 0, false, &xid);
        // covered 1024-byte prefix dropped, buffered tail (3072 bytes) stored
        // (tracked -> 7168), chunk still expects its remaining 4096 logical bytes.
        assert_eq!(ft.tracked, 7168);

        // second fragment: the remaining 4096 logical bytes (7168..11264). The
        // logical-tail size makes it consume exactly 4096 and complete, where the
        // buggy buffered-tail size would leave the chunk already complete.
        let frag2 = vec![0u8; 4096];
        let consumed = ft.update(&TEST_FC, &frag2, 0);
        assert_eq!(consumed, 4096);
        assert_eq!(ft.tracked, 11264);
    }

    #[test]
    fn test_fully_covered_chunk_is_discarded() {
        // a chunk entirely within the tracked region is a pure
        // retransmission: discarded wholesale, tracked unchanged.
        let xid: u32 = 0x43;
        let mut ft = FileTransferTracker::new();
        let head = vec![0u8; 4096];
        ft.new_chunk(&TEST_FC, b"f", &head, 0, 4096, 0, false, &xid);
        assert_eq!(ft.tracked, 4096);

        let retrans = vec![0u8; 512];
        ft.new_chunk(&TEST_FC, b"f", &retrans, 100, 512, 0, false, &xid);
        assert_eq!(ft.tracked, 4096);
    }

    #[test]
    fn test_partial_overlap_fragment_inside_tracked_keeps_logical_tail() {
        // tracked=4096. A chunk at offset 3072 of LOGICAL size 4096 spans
        // 3072..7168, but the first fragment only buffers 1000 bytes
        // (3072..4072): all buffered bytes are inside the tracked region while
        // the logical chunk extends 952 bytes past it. The re-anchor must
        // trigger on the logical extent (not the buffered one) so the
        // arriving continuation is stored, not consumed away; and the 24
        // covered bytes the continuation still carries (4072..4096) are
        // discarded, not stored.
        let xid: u32 = 0x45;
        let mut ft = FileTransferTracker::new();
        let head = vec![0u8; 4096];
        ft.new_chunk(&TEST_FC, b"f", &head, 0, 4096, 0, false, &xid);
        assert_eq!(ft.tracked, 4096);

        // first fragment: 1000 buffered bytes, all covered (overlap = 1024)
        let frag1 = vec![0xAAu8; 1000];
        ft.new_chunk(&TEST_FC, b"f", &frag1, 3072, 4096, 0, false, &xid);
        // nothing new stored yet: covered prefix dropped, chunk re-anchored at
        // 4096 with a 3072-byte logical tail still to come
        assert_eq!(ft.tracked, 4096);

        // continuation: 24 covered bytes (4072..4096) followed by the logical
        // tail 4096..7168. The full 3096-byte continuation must be consumed
        // (the pre-fix re-anchor shrank the chunk by the whole overlap, so the
        // chunk finished after 3072 bytes and the trailing 24 spilled into the
        // next record's framing)
        let mut frag2 = vec![0xAAu8; 24];
        frag2.extend(vec![0xBBu8; 3072]);
        let consumed = ft.update(&TEST_FC, &frag2, 0);
        assert_eq!(consumed, 3096);
        assert_eq!(ft.tracked, 7168);

        // another record's chunk right after: framing is intact
        let frag3 = vec![0xCCu8; 100];
        ft.new_chunk(&TEST_FC, b"f", &frag3, 7168, 100, 0, false, &xid);
        assert_eq!(ft.tracked, 7268);
    }
}
