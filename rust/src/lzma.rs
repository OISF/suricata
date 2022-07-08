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
    LzmaXzError,
}

impl From<Error> for LzmaStatus {
    fn from(e: Error) -> LzmaStatus {
        match e {
            Error::IoError(_) => LzmaStatus::LzmaIoError,
            Error::HeaderTooShort(_) => LzmaStatus::LzmaHeaderTooShortError,
            Error::LzmaError(_) => LzmaStatus::LzmaError,
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
    allow_incomplete: bool, memlimit: usize,
) -> LzmaStatus {
    let input = std::slice::from_raw_parts(input, *input_len);
    let output = std::slice::from_raw_parts_mut(output, *output_len);
    let output = Cursor::new(output);

    let options = Options {
        memlimit: Some(memlimit),
        allow_incomplete,
        ..Default::default()
    };

    let mut stream = Stream::new_with_options(&options, output);

    if let Err(e) = stream.write_all(input) {
        if !allow_incomplete {
            return e.into();
        }
    }

    match stream.finish() {
        Ok(output) => {
            *output_len = output.position() as usize;
            LzmaStatus::LzmaOk
        }
        Err(e) => e.into(),
    }
}
