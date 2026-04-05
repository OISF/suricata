/* Copyright (C) 2024-2025 Open Information Security Foundation
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

//! Module for transforms

use std::ffi::CString;
use suricata_sys::sys::{
    SCDetectByteExtractGetBufferOffset, SCDetectByteRetrieveVarInfo, Signature,
};

/// Error returned when a byte variable cannot be resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ByteVarError {
    /// No variable with this name exists in the signature.
    NotFound,
    /// The variable name contains an interior NUL byte.
    InvalidName,
}

/// Look up a `byte_extract` or `byte_math` variable by name and return its
/// `byte_values` index.
///
/// # Safety
///
/// `s` must be a valid pointer to a `Signature` that is currently being set up.
pub(crate) unsafe fn resolve_byte_var(
    name: &str, s: *const Signature,
) -> Result<u8, ByteVarError> {
    let c_name = CString::new(name).map_err(|_| ByteVarError::InvalidName)?;
    let mut index: u8 = 0;

    if !SCDetectByteRetrieveVarInfo(c_name.as_ptr(), s, &mut index) {
        return Err(ByteVarError::NotFound);
    }
    Ok(index)
}

/// Byte_extract buffer location resolved at setup time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ByteExtractLocation {
    /// Absolute byte offset in the inspection buffer.
    pub offset: u16,
    /// Number of bytes to read starting at `offset`.
    pub nbytes: u8,
}

/// Get a byte_extract variable's absolute buffer offset and byte width on the
/// current buffer. Returns `None` if the variable is not a byte_extract on the
/// same buffer, uses a relative offset, or does not exist.
///
/// This is a workaround until a general pre-transform extraction phase is
/// added to the detection engine.
///
/// # Safety
///
/// `s` must be a valid pointer to a `Signature` that is currently being set up.
pub(crate) unsafe fn get_byte_extract_buffer_location(
    name: &str, s: *const Signature,
) -> Option<ByteExtractLocation> {
    let c_name = CString::new(name).ok()?;
    let mut offset: i16 = 0;
    let mut nbytes: u8 = 0;
    if !SCDetectByteExtractGetBufferOffset(c_name.as_ptr(), s, &mut offset, &mut nbytes) {
        return None;
    }
    if offset < 0 {
        return None;
    }
    Some(ByteExtractLocation {
        offset: offset as u16,
        nbytes,
    })
}

pub mod base64;
pub mod casechange;
pub mod compress_whitespace;
pub mod decompress;
pub mod domain;
pub mod dotprefix;
pub mod hash;
pub mod http_headers;
pub mod strip_whitespace;
pub mod subslice;
pub mod urldecode;
pub mod xor;
