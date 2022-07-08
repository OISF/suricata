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

use lzma_rs::decompress::{Options, Stream};
use lzma_rs::error::Error;
use std::io::{Cursor, Write};

/// Propagate lzma crate errors
#[repr(C)]
pub enum LzmaStatus {
    LzmaOk,
    LzmaIoError,
    LzmaHeaderTooShortError,
    LzmaError,
    LzmaMemoryError,
    LzmaXzError,
}

impl From<Error> for LzmaStatus {
    fn from(e: Error) -> LzmaStatus {
        match e {
            Error::IoError(_) => LzmaStatus::LzmaIoError,
            Error::HeaderTooShort(_) => LzmaStatus::LzmaHeaderTooShortError,
            Error::LzmaError(e) => {
                if e.to_string().contains("exceeded memory limit") {
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
    fn from(_e: std::io::Error) -> LzmaStatus {
        LzmaStatus::LzmaIoError
    }
}

/// Use the lzma algorithm to decompress a chunk of data.
#[no_mangle]
pub unsafe extern "C" fn lzma_decompress(
    input: *const u8, input_len: &mut usize, output: *mut u8, output_len: &mut usize,
    memlimit: usize,
) -> LzmaStatus {
    let input = std::slice::from_raw_parts(input, *input_len);
    let output = std::slice::from_raw_parts_mut(output, *output_len);
    let output = Cursor::new(output);

    let options = Options {
        memlimit: Some(memlimit),
        allow_incomplete: true,
        ..Default::default()
    };

    let mut stream = Stream::new_with_options(&options, output);

    if let Err(e) = stream.write_all(input) {
        return e.into();
    }

    match stream.finish() {
        Ok(output) => {
            *output_len = output.position() as usize;
            LzmaStatus::LzmaOk
        }
        Err(e) => e.into(),
    }
}
