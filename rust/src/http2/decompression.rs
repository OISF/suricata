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

use crate::core::STREAM_TOCLIENT;
use brotli;
use flate2::read::{DeflateDecoder, GzDecoder};
use std;
use std::io;
use std::io::{Cursor, Read, Write};

pub const HTTP2_DECOMPRESSION_CHUNK_SIZE: usize = 0x1000; // 4096

#[repr(u8)]
#[derive(Copy, Clone, PartialOrd, PartialEq, Debug)]
pub enum HTTP2ContentEncoding {
    HTTP2ContentEncodingUnknown = 0,
    HTTP2ContentEncodingGzip = 1,
    HTTP2ContentEncodingBr = 2,
    HTTP2ContentEncodingDeflate = 3,
    HTTP2ContentEncodingUnrecognized = 4,
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
    UNASSIGNED,
    GZIP(GzDecoder<HTTP2cursor>),
    BROTLI(brotli::Decompressor<HTTP2cursor>),
    DEFLATE(DeflateDecoder<HTTP2cursor>),
}

impl std::fmt::Debug for HTTP2Decompresser {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            HTTP2Decompresser::UNASSIGNED => write!(f, "UNASSIGNED"),
            HTTP2Decompresser::GZIP(_) => write!(f, "GZIP"),
            HTTP2Decompresser::BROTLI(_) => write!(f, "BROTLI"),
            HTTP2Decompresser::DEFLATE(_) => write!(f, "DEFLATE"),
        }
    }
}

#[derive(Debug)]
struct HTTP2DecoderHalf {
    encoding: HTTP2ContentEncoding,
    decoder: HTTP2Decompresser,
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

impl GetMutCursor for brotli::Decompressor<HTTP2cursor> {
    fn get_mut(&mut self) -> &mut HTTP2cursor {
        return self.get_mut();
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

    decoder.get_mut().set_position(0);
    return Ok(&output[..offset]);
}

impl HTTP2DecoderHalf {
    pub fn new() -> HTTP2DecoderHalf {
        HTTP2DecoderHalf {
            encoding: HTTP2ContentEncoding::HTTP2ContentEncodingUnknown,
            decoder: HTTP2Decompresser::UNASSIGNED,
        }
    }

    pub fn http2_encoding_fromvec(&mut self, input: &[u8]) {
        //use first encoding...
        if self.encoding == HTTP2ContentEncoding::HTTP2ContentEncodingUnknown {
            if input == b"gzip" {
                self.encoding = HTTP2ContentEncoding::HTTP2ContentEncodingGzip;
                self.decoder = HTTP2Decompresser::GZIP(GzDecoder::new(HTTP2cursor::new()));
            } else if input == b"deflate" {
                self.encoding = HTTP2ContentEncoding::HTTP2ContentEncodingDeflate;
                self.decoder = HTTP2Decompresser::DEFLATE(DeflateDecoder::new(HTTP2cursor::new()));
            } else if input == b"br" {
                self.encoding = HTTP2ContentEncoding::HTTP2ContentEncodingBr;
                self.decoder = HTTP2Decompresser::BROTLI(brotli::Decompressor::new(
                    HTTP2cursor::new(),
                    HTTP2_DECOMPRESSION_CHUNK_SIZE,
                ));
            } else {
                self.encoding = HTTP2ContentEncoding::HTTP2ContentEncodingUnrecognized;
            }
        }
    }

    pub fn decompress<'a>(
        &mut self, input: &'a [u8], output: &'a mut Vec<u8>,
    ) -> io::Result<&'a [u8]> {
        match self.decoder {
            HTTP2Decompresser::GZIP(ref mut gzip_decoder) => {
                let r = http2_decompress(gzip_decoder, input, output);
                match r {
                    Err(_) => {
                        self.decoder = HTTP2Decompresser::UNASSIGNED;
                    }
                    _ => {}
                }
                return r;
            }
            HTTP2Decompresser::BROTLI(ref mut br_decoder) => {
                let r = http2_decompress(br_decoder, input, output);
                match r {
                    Err(_) => {
                        self.decoder = HTTP2Decompresser::UNASSIGNED;
                    }
                    _ => {}
                }
                return r;
            }
            HTTP2Decompresser::DEFLATE(ref mut df_decoder) => {
                let r = http2_decompress(df_decoder, input, output);
                match r {
                    Err(_) => {
                        self.decoder = HTTP2Decompresser::UNASSIGNED;
                    }
                    _ => {}
                }
                return r;
            }
            _ => {}
        }
        return Ok(input);
    }
}

#[derive(Debug)]
pub struct HTTP2Decoder {
    decoder_tc: HTTP2DecoderHalf,
    decoder_ts: HTTP2DecoderHalf,
}

impl HTTP2Decoder {
    pub fn new() -> HTTP2Decoder {
        HTTP2Decoder {
            decoder_tc: HTTP2DecoderHalf::new(),
            decoder_ts: HTTP2DecoderHalf::new(),
        }
    }

    pub fn http2_encoding_fromvec(&mut self, input: &[u8], dir: u8) {
        if dir == STREAM_TOCLIENT {
            self.decoder_tc.http2_encoding_fromvec(input);
        } else {
            self.decoder_ts.http2_encoding_fromvec(input);
        }
    }

    pub fn decompress<'a>(
        &mut self, input: &'a [u8], output: &'a mut Vec<u8>, dir: u8,
    ) -> io::Result<&'a [u8]> {
        if dir == STREAM_TOCLIENT {
            return self.decoder_tc.decompress(input, output);
        } else {
            return self.decoder_ts.decompress(input, output);
        }
    }
}
