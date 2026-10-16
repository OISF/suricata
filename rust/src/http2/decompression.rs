/* Copyright (C) 2021 Open Information Security Foundation
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

use super::http2::HTTP2_COMPRESSION_BOMB_LIMIT;
use crate::direction::Direction;
use brotli::{BrotliDecompressStream, BrotliResult, BrotliState, HuffmanCode};
use flate2::read::{DeflateDecoder, GzDecoder};
use std;
use std::io;
use std::io::{Cursor, Read, Write};
use std::sync::atomic::{AtomicUsize, Ordering};

pub const HTTP2_DECOMPRESSION_CHUNK_SIZE: usize = 0x1000; // 4096

pub(super) const DEFAULT_BOMB_RATIO: u64 = 2048;

const HTTP2_BROTLI_DEFAULT_MEMCAP: usize = 256 * 1024 * 1024;
pub(super) static HTTP2_BROTLI_MEMCAP: AtomicUsize = AtomicUsize::new(HTTP2_BROTLI_DEFAULT_MEMCAP);
static HTTP2_BROTLI_MEMUSE: AtomicUsize = AtomicUsize::new(0);

#[repr(u8)]
#[derive(Copy, Clone, PartialOrd, PartialEq, Eq, Debug)]
pub enum HTTP2ContentEncoding {
    Unknown = 0,
    Gzip = 1,
    Br = 2,
    Deflate = 3,
    Unrecognized = 4,
}

//a cursor turning EOF into blocking errors
#[derive(Debug)]
pub struct HTTP2cursor {
    pub cursor: Cursor<Vec<u8>>,
}

impl HTTP2cursor {
    pub fn new() -> HTTP2cursor {
        HTTP2cursor {
            cursor: Cursor::new(Vec::new()),
        }
    }

    pub fn set_position(&mut self, pos: u64) {
        return self.cursor.set_position(pos);
    }

    pub fn clear(&mut self) {
        self.cursor.get_mut().clear();
        self.cursor.set_position(0);
    }
}

// we need to implement this as flate2 and brotli crates
// will read from this object
impl Read for HTTP2cursor {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        //use the cursor, except it turns eof into blocking error
        let r = self.cursor.read(buf);
        match r {
            Err(ref err) => {
                if err.kind() == io::ErrorKind::UnexpectedEof {
                    return Err(io::ErrorKind::WouldBlock.into());
                }
            }
            Ok(0) => {
                //regular EOF turned into blocking error
                return Err(io::ErrorKind::WouldBlock.into());
            }
            Ok(_n) => {}
        }
        return r;
    }
}

#[derive(Default)]
struct HTTP2BrotliMemory<T: Clone + Default> {
    data: Vec<T>,
    charged: usize,
}

impl<T: Clone + Default> brotli::SliceWrapper<T> for HTTP2BrotliMemory<T> {
    fn slice(&self) -> &[T] {
        &self.data
    }
}

impl<T: Clone + Default> brotli::SliceWrapperMut<T> for HTTP2BrotliMemory<T> {
    fn slice_mut(&mut self) -> &mut [T] {
        &mut self.data
    }
}

impl<T: Clone + Default> Drop for HTTP2BrotliMemory<T> {
    fn drop(&mut self) {
        drop(std::mem::take(&mut self.data));
        HTTP2_BROTLI_MEMUSE.fetch_sub(self.charged, Ordering::Relaxed);
    }
}

#[derive(Clone, Copy, Default)]
struct ScMemcapAlloc<T: Clone + Default> {
    pub _default_value: T,
}

fn http2_brotli_reserve(size: usize) -> bool {
    // needs MSRV 1.95 to use try_update
    #[allow(deprecated)]
    return HTTP2_BROTLI_MEMUSE
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
            used.checked_add(size)
                .filter(|total| *total <= HTTP2_BROTLI_MEMCAP.load(Ordering::Relaxed))
        })
        .is_ok();
}

// from private brotli_decompressor::huffman::BROTLI_HUFFMAN_MAX_TABLE_SIZE;
const BROTLI_HUFFMAN_MAX_TABLE_SIZE: usize = 1080;

#[allow(deprecated)]
fn http2_brotli_alloc<T: Clone + Default>(len: usize, unit_size: usize) -> HTTP2BrotliMemory<T> {
    let charged = match len.checked_mul(unit_size) {
        Some(bytes) => bytes,
        None => return HTTP2BrotliMemory::default(),
    };
    if unit_size > 4 || (unit_size == 4 && len <= 3 * BROTLI_HUFFMAN_MAX_TABLE_SIZE) {
        // HuffmanCode or
        // u32 unchecked allocation in brotli-decompressor-5.0.0 decode.rs:2847, 3240 entries
        // always charge, but do not fail
        // needs MSRV 1.95 to use try_update
        if HTTP2_BROTLI_MEMUSE
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                used.checked_add(charged)
            })
            .is_err()
        {
            return HTTP2BrotliMemory::default();
        }
    } else if charged > 0 && !http2_brotli_reserve(charged) {
        return HTTP2BrotliMemory::default();
    }
    let mut data = Vec::new();
    if data.try_reserve_exact(len).is_err() {
        HTTP2_BROTLI_MEMUSE.fetch_sub(charged, Ordering::Relaxed);
        return HTTP2BrotliMemory::default();
    }
    data.resize(len, T::default());
    HTTP2BrotliMemory { data, charged }
}

impl<T: Clone + Default> brotli::Allocator<T> for ScMemcapAlloc<T> {
    type AllocatedMemory = HTTP2BrotliMemory<T>;

    fn alloc_cell(&mut self, len: usize) -> Self::AllocatedMemory {
        http2_brotli_alloc(len, std::mem::size_of::<T>())
    }

    fn free_cell(&mut self, _data: Self::AllocatedMemory) {}
}

pub(super) struct BrotliDecompressor {
    state: BrotliState<ScMemcapAlloc<u8>, ScMemcapAlloc<u32>, ScMemcapAlloc<HuffmanCode>>,
    cursor: HTTP2cursor,
}

impl BrotliDecompressor {
    pub fn new(cursor: HTTP2cursor) -> BrotliDecompressor {
        BrotliDecompressor {
            state: BrotliState::new_strict(
                ScMemcapAlloc::<u8>::default(),
                ScMemcapAlloc::<u32>::default(),
                ScMemcapAlloc::<HuffmanCode>::default(),
            ),
            cursor,
        }
    }
}

// we need to implement this as flate2 and brotli crates
// will read from this object
impl Read for BrotliDecompressor {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let start_offset = 0;
        let mut output_offset = 0;
        let mut available_out = buf.len() - output_offset;
        let mut input_offset = self.cursor.cursor.position() as usize;
        let mut available_in = self.cursor.cursor.get_ref().len() - input_offset;
        let mut written = 0;
        match BrotliDecompressStream(
            &mut available_in,
            &mut input_offset,
            self.cursor.cursor.get_mut(),
            &mut available_out,
            &mut output_offset,
            buf,
            &mut written,
            &mut self.state,
        ) {
            BrotliResult::ResultSuccess => {
                self.cursor.cursor.set_position(input_offset as u64);
                return Ok(output_offset - start_offset);
            }
            BrotliResult::NeedsMoreInput => {
                self.cursor.cursor.set_position(input_offset as u64);
                return Ok(output_offset - start_offset);
            }
            BrotliResult::NeedsMoreOutput => {
                self.cursor.cursor.set_position(input_offset as u64);
                return Ok(output_offset - start_offset);
            }
            BrotliResult::ResultFailure => {
                return Err(io::Error::other("Brotli decompression failed"));
            }
        }
    }
}

pub enum HTTP2Decompresser {
    Unassigned,
    // Box because large.
    Gzip(Box<GzDecoder<HTTP2cursor>>),
    // Box because large.
    Brotli(Box<BrotliDecompressor>),
    // This one is not so large, at 88 bytes as of doing this, but box
    // for consistency.
    Deflate(Box<DeflateDecoder<HTTP2cursor>>),
}

impl std::fmt::Debug for HTTP2Decompresser {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            HTTP2Decompresser::Unassigned => write!(f, "UNASSIGNED"),
            HTTP2Decompresser::Gzip(_) => write!(f, "GZIP"),
            HTTP2Decompresser::Brotli(_) => write!(f, "BROTLI"),
            HTTP2Decompresser::Deflate(_) => write!(f, "DEFLATE"),
        }
    }
}

#[derive(Debug)]
pub(super) struct HTTP2DecoderHalf {
    encoding: HTTP2ContentEncoding,
    decoder: HTTP2Decompresser,
    pub input_len: u64,
    pub output_len: u64,
}

pub trait GetMutCursor {
    fn get_mut(&mut self) -> &mut HTTP2cursor;
}

impl GetMutCursor for GzDecoder<HTTP2cursor> {
    fn get_mut(&mut self) -> &mut HTTP2cursor {
        return self.get_mut();
    }
}

impl GetMutCursor for DeflateDecoder<HTTP2cursor> {
    fn get_mut(&mut self) -> &mut HTTP2cursor {
        return self.get_mut();
    }
}

impl GetMutCursor for BrotliDecompressor {
    fn get_mut(&mut self) -> &mut HTTP2cursor {
        return &mut self.cursor;
    }
}

fn http2_decompress<'a>(
    decoder: &mut (impl Read + GetMutCursor), input: &'a [u8], output: &'a mut Vec<u8>,
) -> io::Result<&'a [u8]> {
    match decoder.get_mut().cursor.write_all(input) {
        Ok(()) => {}
        Err(e) => {
            return Err(e);
        }
    }
    let mut offset = 0;
    decoder.get_mut().set_position(0);
    output.resize(HTTP2_DECOMPRESSION_CHUNK_SIZE, 0);
    loop {
        match decoder.read(&mut output[offset..]) {
            Ok(0) => {
                break;
            }
            Ok(n) => {
                offset += n;
                if offset == output.len() {
                    if output.len() > unsafe { HTTP2_COMPRESSION_BOMB_LIMIT as usize }
                    {
                        return Err(io::Error::new(
                            io::ErrorKind::OutOfMemory,
                            "Decompression bomb detected",
                        ));
                    }
                    output.resize(output.len() + HTTP2_DECOMPRESSION_CHUNK_SIZE, 0);
                }
            }
            Err(e) => {
                if e.kind() == io::ErrorKind::WouldBlock {
                    break;
                }
                return Err(e);
            }
        }
    }
    //brotli does not consume all input if it reaches some end
    decoder.get_mut().clear();
    return Ok(&output[..offset]);
}

impl HTTP2DecoderHalf {
    pub fn new() -> HTTP2DecoderHalf {
        HTTP2DecoderHalf {
            encoding: HTTP2ContentEncoding::Unknown,
            decoder: HTTP2Decompresser::Unassigned,
            input_len: 0,
            output_len: 0,
        }
    }

    pub fn http2_encoding_fromvec(&mut self, input: &[u8]) {
        //use first encoding...
        if self.encoding == HTTP2ContentEncoding::Unknown {
            if input.eq_ignore_ascii_case(b"gzip") {
                self.encoding = HTTP2ContentEncoding::Gzip;
                self.decoder =
                    HTTP2Decompresser::Gzip(Box::new(GzDecoder::new(HTTP2cursor::new())));
            } else if input.eq_ignore_ascii_case(b"deflate") {
                self.encoding = HTTP2ContentEncoding::Deflate;
                self.decoder =
                    HTTP2Decompresser::Deflate(Box::new(DeflateDecoder::new(HTTP2cursor::new())));
            } else if input.eq_ignore_ascii_case(b"br") {
                self.encoding = HTTP2ContentEncoding::Br;
                self.decoder = HTTP2Decompresser::Brotli(Box::new(BrotliDecompressor::new(
                    HTTP2cursor::new(),
                )));
            } else {
                self.encoding = HTTP2ContentEncoding::Unrecognized;
            }
        }
    }

    pub fn decompress<'a>(
        &mut self, input: &'a [u8], output: &'a mut Vec<u8>,
    ) -> io::Result<&'a [u8]> {
        match self.decoder {
            HTTP2Decompresser::Gzip(ref mut gzip_decoder) => {
                let r = http2_decompress(&mut *gzip_decoder.as_mut(), input, output);
                match r {
                    Err(_) => {
                        self.decoder = HTTP2Decompresser::Unassigned;
                    }
                    Ok(o) => {
                        self.output_len += o.len() as u64;
                    }
                }
                self.input_len += input.len() as u64;
                return r;
            }
            HTTP2Decompresser::Brotli(ref mut br_decoder) => {
                let r = http2_decompress(&mut *br_decoder.as_mut(), input, output);
                match r {
                    Err(_) => {
                        self.decoder = HTTP2Decompresser::Unassigned;
                    }
                    Ok(o) => {
                        self.output_len += o.len() as u64;
                    }
                }
                self.input_len += input.len() as u64;
                return r;
            }
            HTTP2Decompresser::Deflate(ref mut df_decoder) => {
                let r = http2_decompress(&mut *df_decoder.as_mut(), input, output);
                match r {
                    Err(_) => {
                        self.decoder = HTTP2Decompresser::Unassigned;
                    }
                    Ok(o) => {
                        self.output_len += o.len() as u64;
                    }
                }
                self.input_len += input.len() as u64;
                return r;
            }
            _ => {}
        }
        return Ok(input);
    }
}

#[derive(Debug)]
pub(super) struct HTTP2Decoder {
    pub decoder_tc: HTTP2DecoderHalf,
    pub decoder_ts: HTTP2DecoderHalf,
}

impl HTTP2Decoder {
    pub fn new() -> HTTP2Decoder {
        HTTP2Decoder {
            decoder_tc: HTTP2DecoderHalf::new(),
            decoder_ts: HTTP2DecoderHalf::new(),
        }
    }

    pub fn http2_encoding_fromvec(&mut self, input: &[u8], dir: Direction) {
        if dir == Direction::ToClient {
            self.decoder_tc.http2_encoding_fromvec(input);
        } else {
            self.decoder_ts.http2_encoding_fromvec(input);
        }
    }

    pub fn decompress<'a>(
        &mut self, input: &'a [u8], output: &'a mut Vec<u8>, dir: Direction,
    ) -> io::Result<&'a [u8]> {
        if dir == Direction::ToClient {
            return self.decoder_tc.decompress(input, output);
        } else {
            return self.decoder_ts.decompress(input, output);
        }
    }
}
