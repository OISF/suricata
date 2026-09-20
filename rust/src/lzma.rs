/* Copyright (C) 2022 Open Information Security Foundation
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

//! lzma decompression utility module.

use lzma_rs::decompress::{Options, Stream};
use lzma_rs::error::Error;
use std::cell::Cell;
use std::io::{self, ErrorKind, Write};
use std::os::raw::c_void;
use std::ptr;

type LzmaOutputGrowFn = unsafe extern "C" fn(output: *mut c_void, min_size: u32) -> *mut u8;

struct LzmaOutput<'a> {
    /// Opaque C InspectionBuffer passed back to the growth callback.
    output: *mut c_void,
    /// Bytes reserved before the decompressed data, for example the FWS header.
    output_offset: usize,
    /// Maximum decompressed bytes to retain, excluding output_offset.
    output_limit: usize,
    /// Ensures that the C inspection buffer has the requested total capacity.
    output_grow: LzmaOutputGrowFn,
    /// Number of decompressed bytes already written after output_offset.
    position: &'a Cell<usize>,
    /// Records output-limit exhaustion before lzma-rs can wrap the writer error.
    full: &'a Cell<bool>,
    /// Records a failed C buffer expansion separately from other I/O errors.
    alloc_failed: &'a Cell<bool>,
}

impl Write for LzmaOutput<'_> {
    /// Accept a decompressed chunk from lzma-rs, grow the C inspection buffer as needed, and
    /// copy no more than output_limit. The external Cells preserve the result if lzma-rs wraps
    /// a short write or consumes the writer after an error.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let position = self.position.get();
        let written = buf.len().min(self.output_limit - position);
        if written == 0 {
            self.full.set(true);
            return Ok(0);
        }

        let required = self.output_offset + position + written;
        debug_assert!(required <= u32::MAX as usize);
        let output = unsafe { (self.output_grow)(self.output, required as u32) };
        if output.is_null() {
            self.alloc_failed.set(true);
            return Err(io::Error::other("failed to grow LZMA output"));
        }

        unsafe {
            ptr::copy_nonoverlapping(
                buf.as_ptr(),
                output.add(self.output_offset + position),
                written,
            );
        }
        self.position.set(position + written);
        if written < buf.len() {
            self.full.set(true);
        }
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Propagate lzma crate errors
#[repr(C)]
pub enum LzmaStatus {
    LzmaOk,
    LzmaOutputFull,
    LzmaOutputAllocError,
    LzmaIoError,
    LzmaHeaderTooShortError,
    LzmaError,
    LzmaMemoryError,
    LzmaXzError,
}

impl From<Error> for LzmaStatus {
    fn from(e: Error) -> LzmaStatus {
        match e {
            Error::IoError(e) if e.kind() == ErrorKind::WriteZero => LzmaStatus::LzmaOutputFull,
            Error::IoError(_) => LzmaStatus::LzmaIoError,
            Error::HeaderTooShort(_) => LzmaStatus::LzmaHeaderTooShortError,
            Error::LzmaError(e) => {
                if e.contains("exceeded memory limit") {
                    LzmaStatus::LzmaMemoryError
                } else {
                    LzmaStatus::LzmaError
                }
            }
            Error::XzError(_) => LzmaStatus::LzmaXzError,
        }
    }
}

impl From<std::io::Error> for LzmaStatus {
    fn from(e: std::io::Error) -> LzmaStatus {
        if e.kind() == ErrorKind::WriteZero {
            LzmaStatus::LzmaOutputFull
        } else {
            LzmaStatus::LzmaIoError
        }
    }
}

/// Use the lzma algorithm to decompress a chunk of data.
#[no_mangle]
pub unsafe extern "C" fn lzma_decompress(
    input: *const u8, input_len: &mut usize, output: *mut c_void, output_offset: u32,
    output_limit: u32, output_len: &mut usize,
    output_grow: unsafe extern "C" fn(output: *mut c_void, min_size: u32) -> *mut u8,
    memlimit: usize,
) -> LzmaStatus {
    let input = std::slice::from_raw_parts(input, *input_len);
    *output_len = 0;
    let output_position = Cell::new(0);
    let output_full = Cell::new(false);
    let output_alloc_failed = Cell::new(false);
    let output = LzmaOutput {
        output,
        output_offset: output_offset as usize,
        output_limit: output_limit as usize,
        output_grow,
        position: &output_position,
        full: &output_full,
        alloc_failed: &output_alloc_failed,
    };

    let options = Options {
        memlimit: Some(memlimit),
        allow_incomplete: true,
        ..Default::default()
    };

    let mut stream = Stream::new_with_options(&options, output);

    if let Err(e) = stream.write_all(input) {
        *output_len = output_position.get();
        return if output_alloc_failed.get() {
            LzmaStatus::LzmaOutputAllocError
        } else if output_full.get() {
            LzmaStatus::LzmaOutputFull
        } else {
            e.into()
        };
    }

    let status = match stream.finish() {
        Ok(_) => LzmaStatus::LzmaOk,
        Err(_) if output_alloc_failed.get() => LzmaStatus::LzmaOutputAllocError,
        Err(_) if output_full.get() => LzmaStatus::LzmaOutputFull,
        Err(e) => e.into(),
    };
    *output_len = output_position.get();
    status
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    struct TestOutput {
        data: Vec<u8>,
        grow_count: usize,
    }

    unsafe extern "C" fn test_output_grow(output: *mut c_void, min_size: u32) -> *mut u8 {
        let output = &mut *(output as *mut TestOutput);
        output.grow_count += 1;
        output.data.resize(min_size as usize, 0);
        output.data.as_mut_ptr()
    }

    fn assert_output_full(dict_size: u32) {
        let input = vec![b'A'; 8192];
        let mut compressed = Vec::new();
        lzma_rs::lzma_compress(&mut Cursor::new(&input), &mut compressed).unwrap();
        compressed[1..5].copy_from_slice(&dict_size.to_le_bytes());
        let mut input_len = compressed.len();
        let mut output = TestOutput {
            data: Vec::new(),
            grow_count: 0,
        };
        let mut output_len = 0;
        let status = unsafe {
            lzma_decompress(
                compressed.as_ptr(),
                &mut input_len,
                &mut output as *mut TestOutput as *mut c_void,
                8,
                64,
                &mut output_len,
                test_output_grow,
                50_000_000,
            )
        };

        assert!(matches!(status, LzmaStatus::LzmaOutputFull));
        assert_eq!(output_len, 64);
        assert!(output.grow_count > 0);
        assert_eq!(&output.data[8..8 + output_len], vec![b'A'; output_len]);
    }

    #[test]
    fn output_full_during_finish() {
        assert_output_full(8 * 1024 * 1024);
    }

    #[test]
    fn output_full_during_write() {
        assert_output_full(4096);
    }
}
