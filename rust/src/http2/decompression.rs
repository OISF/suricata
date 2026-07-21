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
use brotli;
use flate2::read::{DeflateDecoder, GzDecoder};
use std;
use std::io;
use std::io::{BufReader, Cursor, Read, Write};
use zstd;

pub const HTTP2_DECOMPRESSION_CHUNK_SIZE: usize = 0x1000; // 4096

pub(super) const DEFAULT_BOMB_RATIO: u64 = 2048;

#[repr(u8)]
#[derive(Copy, Clone, PartialOrd, PartialEq, Eq, Debug)]
pub enum HTTP2ContentEncoding {
    Unknown = 0,
    Gzip = 1,
    Br = 2,
    Deflate = 3,
    Zstd = 4,
    Unrecognized = 5,
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

pub enum HTTP2Decompresser {
    Unassigned,
    // Box because large.
    Gzip(Box<GzDecoder<HTTP2cursor>>),
    // Box because large.
    Brotli(Box<brotli::Decompressor<HTTP2cursor>>),
    // This one is not so large, at 88 bytes as of doing this, but box
    // for consistency.
    Deflate(Box<DeflateDecoder<HTTP2cursor>>),

    // usage of 'static, alternative could be trait instead of enum
    Zstd(Box<zstd::stream::read::Decoder<'static, BufReader<HTTP2cursor>>>),
}

impl std::fmt::Debug for HTTP2Decompresser {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            HTTP2Decompresser::Unassigned => write!(f, "UNASSIGNED"),
            HTTP2Decompresser::Gzip(_) => write!(f, "GZIP"),
            HTTP2Decompresser::Brotli(_) => write!(f, "BROTLI"),
            HTTP2Decompresser::Deflate(_) => write!(f, "DEFLATE"),
            HTTP2Decompresser::Zstd(_) => write!(f, "ZSTD"),
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
    fn get_mutc(&mut self) -> &mut HTTP2cursor;
}

impl GetMutCursor for GzDecoder<HTTP2cursor> {
    fn get_mutc(&mut self) -> &mut HTTP2cursor {
        return self.get_mut();
    }
}

impl GetMutCursor for DeflateDecoder<HTTP2cursor> {
    fn get_mutc(&mut self) -> &mut HTTP2cursor {
        return self.get_mut();
    }
}

impl GetMutCursor for brotli::Decompressor<HTTP2cursor> {
    fn get_mutc(&mut self) -> &mut HTTP2cursor {
        return self.get_mut();
    }
}

impl GetMutCursor for zstd::stream::read::Decoder<'_, BufReader<HTTP2cursor>> {
    fn get_mutc(&mut self) -> &mut HTTP2cursor {
        return self.get_mut().get_mut();
    }
}

fn http2_decompress<'a>(
    decoder: &mut (impl Read + GetMutCursor), input: &'a [u8], output: &'a mut Vec<u8>,
) -> io::Result<&'a [u8]> {
    match decoder.get_mutc().cursor.write_all(input) {
        Ok(()) => {}
        Err(e) => {
            return Err(e);
        }
    }
    let mut offset = 0;
    decoder.get_mutc().set_position(0);
    output.resize(HTTP2_DECOMPRESSION_CHUNK_SIZE, 0);
    loop {
        match decoder.read(&mut output[offset..]) {
            Ok(0) => {
                break;
            }
            Ok(n) => {
                offset += n;
                if offset == output.len() {
                    if output.len() > unsafe { HTTP2_COMPRESSION_BOMB_LIMIT as usize } {
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
    decoder.get_mutc().clear();
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
            if input == b"gzip" {
                self.encoding = HTTP2ContentEncoding::Gzip;
                self.decoder =
                    HTTP2Decompresser::Gzip(Box::new(GzDecoder::new(HTTP2cursor::new())));
            } else if input == b"deflate" {
                self.encoding = HTTP2ContentEncoding::Deflate;
                self.decoder =
                    HTTP2Decompresser::Deflate(Box::new(DeflateDecoder::new(HTTP2cursor::new())));
            } else if input == b"br" {
                self.encoding = HTTP2ContentEncoding::Br;
                self.decoder = HTTP2Decompresser::Brotli(Box::new(brotli::Decompressor::new(
                    HTTP2cursor::new(),
                    HTTP2_DECOMPRESSION_CHUNK_SIZE,
                )));
            } else if input == b"zstd" {
                self.encoding = HTTP2ContentEncoding::Zstd;
                if let Ok(mut z) = zstd::stream::read::Decoder::new(HTTP2cursor::new()) {
                    if z.window_log_max(23).is_ok() {
                        self.decoder = HTTP2Decompresser::Zstd(Box::new(z));
                    } else {
                        SCLogWarning!("Failed to set zstd window log max");
                        self.decoder = HTTP2Decompresser::Unassigned;
                    }
                } else {
                    SCLogWarning!("Failed to create zstd decoder");
                    self.decoder = HTTP2Decompresser::Unassigned;
                }
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
            HTTP2Decompresser::Zstd(ref mut zstd_decoder) => {
                let r = http2_decompress(&mut *zstd_decoder.as_mut(), input, output);
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
