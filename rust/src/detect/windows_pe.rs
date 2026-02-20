/* Copyright (C) 2026 Open Information Security Foundation
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

//! # Windows PE Detection Module
//!
//! This module provides the `executable` keyword for detecting Windows Portable Executable (PE)
//! files in network traffic. The keyword enables inspection of file data buffers to identify
//! valid PE file formats.
//!
//! ## Overview
//!
//! Windows PE files are the standard executable format for Windows operating systems. They consist of:
//! - A DOS header beginning with the "MZ" signature (0x5A4D)
//! - A DOS stub program
//! - A PE header beginning with the "PE\0\0" signature (0x00004550)
//! - COFF header and optional header containing metadata
//! - Section headers and section data
//!
//! ## Keyword Usage
//!
//! The `executable` keyword is a multi-buffer sticky buffer keyword that can be used with
//! content matching to detect PE files.
//!
//! ### Syntax
//!
//! ```text
//! windows_pe: architecture: x86_64;
//! windows_pe: size: >100000, <500000;
//! windows_pe: sections: >5, <50;
//! windows_pe: entry_point: >0x1000;
//! windows_pe: subsystem: 2;
//! ```
//!
//! ### Options
//!
//! - **architecture**: CPU architecture filter using friendly names (`x86`, `x86_64`, `arm`, `arm64`)
//!   - Maps to COFF Machine field: x86=0x014C, x86_64=0x8664, arm=0x01C0, arm64=0xAA64
//! - **size**: SizeOfImage field (uint32 expression, e.g. `>1000000`)
//! - **sections**: NumberOfSections field (uint16 expression, e.g. `<3`)
//! - **entry_point**: AddressOfEntryPoint RVA (uint32 expression, e.g. `>0x10000`)
//! - **subsystem**: PE subsystem (uint16, e.g. `2` for GUI, `3` for Console)
//! - **characteristics**: COFF characteristics flags (uint16, e.g. `0x2000` for DLL)
//! - **dll_characteristics**: DLL characteristics / security flags (uint16)
//!
//! ### Examples
//!
//! **Detect any Windows PE file download:**
//! ```text
//! alert http any any -> any any (msg:"Windows PE file detected"; \
//!     flow:established,to_client; \
//!     file.data; content:"MZ"; depth:2; \
//!     content:"PE|00 00|"; distance:0; \
//!     windows_pe: architecture: x86_64; \
//!     sid:1; rev:1;)
//! ```
//!
//! **Detect large x64 PE files (potential malware):**
//! ```text
//! alert http any any -> any any (msg:"Large x64 PE malware"; \
//!     flow:established,to_client; \
//!     file.data; content:"MZ"; depth:2; \
//!     windows_pe: architecture: x86_64, size: >5000000; \
//!     sid:2; rev:1;)
//! ```
//!
//! **Detect packed PE files (few sections):**
//! ```text
//! alert http any any -> any any (msg:"Packed PE detected"; \
//!     flow:established,to_client; \
//!     file.data; content:"MZ"; depth:2; \
//!     windows_pe: architecture: x86_64, sections: <3; \
//!     sid:3; rev:1;)
//! ```
//!
//! **Detect PE with suspicious entry point:**
//! ```text
//! alert http any any -> any any (msg:"PE with suspicious entry point"; \
//!     flow:established,to_client; \
//!     file.data; content:"MZ"; depth:2; \
//!     windows_pe: architecture: x86_64, entry_point: <0x1000; \
//!     sid:4; rev:1;)
//! ```
//!
//! **Detect GUI applications only:**
//! ```text
//! alert http any any -> any any (msg:"Windows GUI application"; \
//!     flow:established,to_client; \
//!     file.data; content:"MZ"; depth:2; \
//!     windows_pe: architecture: x86_64, subsystem: 2; \
//!     sid:5; rev:1;)
//! ```
//!
//! ## PE File Structure Validation
//!
//! A valid PE file must satisfy:
//! 1. **DOS Header Magic**: First 2 bytes must be "MZ" (0x4D 0x5A)
//! 2. **Minimum Size**: At least 64 bytes for the DOS header
//! 3. **PE Offset**: Valid offset at bytes 60-63 (little-endian) pointing to PE signature
//! 4. **PE Signature**: "PE\0\0" (0x50 0x45 0x00 0x00) at the PE offset location
//! 5. **Reasonable Bounds**: PE offset must be within file size and not exceed 0x10000
//!
//! ## Use Cases
//!
//! - **Malware Detection**: Identify potential malware executables in HTTP/SMTP traffic
//! - **Policy Enforcement**: Block executable downloads in corporate environments
//! - **Threat Hunting**: Track PE file transfers for forensic analysis
//! - **File Classification**: Categorize and log Windows executable traffic
//!
//! ## Performance Considerations
//!
//! - The keyword works best when combined with content matches to pre-filter data
//! - Use with `file.data` buffer for HTTP/SMTP file transfers
//! - Consider file size limits to avoid processing very large files
//!
//! ## References
//!
//! - Microsoft PE/COFF Specification
//! - [PE Format Documentation](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)

use crate::detect::uint::{detect_parse_uint, DetectUintData};
use crate::jsonbuilder::{JsonBuilder, JsonError};
use std::ffi::CStr;
use std::os::raw::c_char;

/// Classification of DOS stub type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DOSStubType {
    /// Standard Windows DOS runtime message
    Standard,
    /// Modified or custom DOS stub (indicates packing or customization)
    Modified,
    /// Minimal DOS stub with little content
    Minimal,
    /// Typical of UPX or other packer markers
    Packed,
}

/// PE file metadata extracted from headers
#[derive(Debug, Clone)]
pub struct PEMetadata {
    /// Offset where DOS header starts (typically 0)
    pub dos_header_offset: u32,
    /// Offset to PE signature (from PE offset field at DOS offset 60-63)
    pub pe_offset: u32,
    /// Machine type from COFF header (x86=0x014C, x64=0x8664, ARM=0x01C0, etc.)
    pub architecture: u16,
    /// Number of sections from COFF header
    pub num_sections: u16,
    /// SizeOfImage from optional header (total mapped size)
    pub size_of_image: u32,
    /// AddressOfEntryPoint from optional header (entry point RVA)
    pub entry_point_rva: u32,
    /// Classification of DOS stub type
    pub dos_stub_type: DOSStubType,
    /// Characteristics from COFF header (executable, dll, etc.)
    pub characteristics: u16,
    /// Subsystem from optional header (console, gui, driver, etc.)
    pub subsystem: u16,
    /// DLL characteristics from optional header
    pub dll_characteristics: u16,
}

/// Internal PE validation implementation
fn pe_validate(data: &[u8]) -> bool {
    // Minimum size for DOS header is 64 bytes (need PE offset at bytes 60-63)
    if data.len() < 64 {
        return false;
    }

    // Check DOS header magic "MZ"
    if &data[0..2] != b"MZ" {
        return false;
    }

    // Read PE offset from bytes 60-63 (little-endian)
    // This is the standard location in DOS header for PE offset
    let pe_offset = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;

    // Validate PE offset is reasonable (must be within file and have room for PE header)
    // PE header is at least 4 bytes for signature
    if pe_offset > 0x10000 || pe_offset + 4 > data.len() {
        return false;
    }

    // Check PE signature "PE\0\0" at the PE offset
    if &data[pe_offset..pe_offset + 4] != b"PE\0\0" {
        return false;
    }

    true
}

/// Analyze DOS stub to classify its type (OPTIMIZED)
///
/// Determines whether the DOS stub is standard, modified, minimal, or packed.
/// Uses a single-pass scan for efficiency instead of multiple iterator operations.
fn analyze_dos_stub(stub_data: &[u8]) -> DOSStubType {
    if stub_data.is_empty() {
        return DOSStubType::Minimal;
    }

    let mut non_zero_count = 0;
    let mut found_packed = false;

    // Single pass: check for patterns and count non-zero bytes
    for window_pos in 0..stub_data.len() {
        let bytes_left = stub_data.len() - window_pos;

        // Check for standard Windows DOS runtime message (cached check)
        if bytes_left >= 19 {
            if stub_data[window_pos..].starts_with(b"This program cannot") {
                return DOSStubType::Standard;
            }
        }

        // Check for common packer signatures (4 bytes)
        if !found_packed && bytes_left >= 4 {
            match &stub_data[window_pos..window_pos + 4] {
                b"UPX!" | b"UPX\0" => found_packed = true,
                b"ASPa"
                    if bytes_left >= 5 && &stub_data[window_pos..window_pos + 5] == b"ASPack" =>
                {
                    found_packed = true
                }
                b"PEti"
                    if bytes_left >= 5 && &stub_data[window_pos..window_pos + 6] == b"PEtite" =>
                {
                    found_packed = true
                }
                b"!UCL" => found_packed = true,
                _ => {}
            }
        }

        // Count non-zero bytes (take first 4 bytes per position for efficiency)
        if window_pos < stub_data.len() {
            if stub_data[window_pos] != 0 {
                non_zero_count += 1;
            }
            if non_zero_count > 10 {
                // Early exit: already found enough non-zero bytes
                if found_packed {
                    return DOSStubType::Packed;
                } else {
                    return DOSStubType::Modified;
                }
            }
        }
    }

    if found_packed {
        return DOSStubType::Packed;
    }

    if non_zero_count > 10 {
        return DOSStubType::Modified;
    }

    DOSStubType::Minimal
}

/// Parse PE header and extract metadata (OPTIMIZED)
///
/// Extracts COFF and Optional header information from a validated PE file.
/// Consolidates bounds checking upfront for efficiency.
/// Returns None if the data is not a valid PE or is too small.
fn parse_pe_metadata(data: &[u8]) -> Option<PEMetadata> {
    if !pe_validate(data) {
        return None;
    }

    // Read PE offset from DOS header bytes 60-63 (little-endian)
    let pe_offset = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;

    // Upfront bounds checking: we need at least up to optional_header_offset + 0x48
    // This includes all fields we might read (furthest is DllCharacteristics at +0x46 +2)
    let min_required = pe_offset + 24 + 0x48; // optional_header_offset + max_field_offset
    if data.len() < min_required {
        // Fall back to reading only what we can with zero defaults for missing fields
        return parse_pe_metadata_partial(data, pe_offset);
    }

    // All ranges are guaranteed safe due to upfront check
    // COFF header at pe_offset
    let machine_type = u16::from_le_bytes([data[pe_offset + 4], data[pe_offset + 5]]);
    let num_sections = u16::from_le_bytes([data[pe_offset + 6], data[pe_offset + 7]]);
    let characteristics = u16::from_le_bytes([data[pe_offset + 22], data[pe_offset + 23]]);

    // Optional header at pe_offset + 24
    let optional_header_offset = pe_offset + 24;
    let size_of_image = u32::from_le_bytes([
        data[optional_header_offset + 0x38],
        data[optional_header_offset + 0x39],
        data[optional_header_offset + 0x3A],
        data[optional_header_offset + 0x3B],
    ]);
    let entry_point_rva = u32::from_le_bytes([
        data[optional_header_offset + 0x10],
        data[optional_header_offset + 0x11],
        data[optional_header_offset + 0x12],
        data[optional_header_offset + 0x13],
    ]);
    let subsystem = u16::from_le_bytes([
        data[optional_header_offset + 0x44],
        data[optional_header_offset + 0x45],
    ]);
    let dll_characteristics = u16::from_le_bytes([
        data[optional_header_offset + 0x46],
        data[optional_header_offset + 0x47],
    ]);

    // Analyze DOS stub (data between end of DOS header and PE offset)
    let dos_stub_start = 64; // DOS header is 64 bytes
    let dos_stub_end = (pe_offset as usize).min(data.len());
    let dos_stub_type = if dos_stub_start < dos_stub_end {
        analyze_dos_stub(&data[dos_stub_start..dos_stub_end])
    } else {
        DOSStubType::Minimal
    };

    Some(PEMetadata {
        dos_header_offset: 0,
        pe_offset: pe_offset as u32,
        architecture: machine_type,
        num_sections,
        size_of_image,
        entry_point_rva,
        dos_stub_type,
        characteristics,
        subsystem,
        dll_characteristics,
    })
}

/// Partial PE metadata parsing for files that don't have all required fields
/// This is a fallback when the file is too short for full parsing
fn parse_pe_metadata_partial(data: &[u8], pe_offset: usize) -> Option<PEMetadata> {
    // Helper function to safely read u16 at offset within bounds check
    let safe_u16_at = |offset: usize| -> u16 {
        if offset + 2 <= data.len() {
            u16::from_le_bytes([data[offset], data[offset + 1]])
        } else {
            0
        }
    };

    // Helper function to safely read u32 at offset within bounds check
    let safe_u32_at = |offset: usize| -> u32 {
        if offset + 4 <= data.len() {
            u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ])
        } else {
            0
        }
    };

    let machine_type = safe_u16_at(pe_offset + 4);
    let num_sections = safe_u16_at(pe_offset + 6);
    let characteristics = safe_u16_at(pe_offset + 22);

    let optional_header_offset = pe_offset + 24;
    let size_of_image = safe_u32_at(optional_header_offset + 0x38);
    let entry_point_rva = safe_u32_at(optional_header_offset + 0x10);
    let subsystem = safe_u16_at(optional_header_offset + 0x44);
    let dll_characteristics = safe_u16_at(optional_header_offset + 0x46);

    let dos_stub_start = 64;
    let dos_stub_end = (pe_offset as usize).min(data.len());
    let dos_stub_type = if dos_stub_start < dos_stub_end {
        analyze_dos_stub(&data[dos_stub_start..dos_stub_end])
    } else {
        DOSStubType::Minimal
    };

    Some(PEMetadata {
        dos_header_offset: 0,
        pe_offset: pe_offset as u32,
        architecture: machine_type,
        num_sections,
        size_of_image,
        entry_point_rva,
        dos_stub_type,
        characteristics,
        subsystem,
        dll_characteristics,
    })
}

/// C-visible PE metadata structure for bulk extraction.
/// Used by the thread-local cache in detect-windows-pe.c to avoid
/// redundant PE header parsing across multiple sub-keywords.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SCDetectPeMetadata {
    pub valid: bool,
    pub architecture: u16,
    pub num_sections: u16,
    pub subsystem: u16,
    pub characteristics: u16,
    pub dll_characteristics: u16,
    pub size_of_image: u32,
    pub entry_point_rva: u32,
}

impl Default for SCDetectPeMetadata {
    fn default() -> Self {
        Self {
            valid: false,
            architecture: 0,
            num_sections: 0,
            subsystem: 0,
            characteristics: 0,
            dll_characteristics: 0,
            size_of_image: 0,
            entry_point_rva: 0,
        }
    }
}

/// Parse PE headers once and populate all metadata fields.
/// Returns true if the data is a valid PE file, false otherwise.
/// When returning false, fields in `out` are zeroed.
#[no_mangle]
pub unsafe extern "C" fn SCDetectPeMetadataParse(
    data: *const u8, data_len: u32, out: *mut SCDetectPeMetadata,
) -> bool {
    if out.is_null() {
        return false;
    }
    if data.is_null() || data_len < 64 {
        (*out) = SCDetectPeMetadata::default();
        return false;
    }
    let file_data = std::slice::from_raw_parts(data, data_len as usize);
    match parse_pe_metadata(file_data) {
        Some(m) => {
            (*out) = SCDetectPeMetadata {
                valid: true,
                architecture: m.architecture,
                num_sections: m.num_sections,
                subsystem: m.subsystem,
                characteristics: m.characteristics,
                dll_characteristics: m.dll_characteristics,
                size_of_image: m.size_of_image,
                entry_point_rva: m.entry_point_rva,
            };
            true
        }
        None => {
            (*out) = SCDetectPeMetadata::default();
            false
        }
    }
}

// ============================================================================
// Keyword context: parsed options for the windows_pe keyword
// ============================================================================

/// Context structure for the `executable` keyword.
///
/// All options are parsed in Rust by [`SCDetectWindowsPEParse`].
/// The C `FileMatch` callback calls matching logic in Rust.
///
/// Uint filter data is owned by this struct and stored as boxed types.
/// Using `detect_parse_uint::<T>()` directly avoids FFI overhead.
#[repr(C)]
pub struct DetectWindowsPEData {
    pub architecture: u16, // Machine type for architecture filter (0 = no filter)
    pub size: *mut DetectUintData<u32>,
    pub sections: *mut DetectUintData<u16>,
    pub entry_point: *mut DetectUintData<u32>,
    pub subsystem: *mut DetectUintData<u16>,
    pub characteristics: *mut DetectUintData<u16>,
    pub dll_characteristics: *mut DetectUintData<u16>,
}

impl Default for DetectWindowsPEData {
    fn default() -> Self {
        Self {
            architecture: 0,
            size: std::ptr::null_mut(),
            sections: std::ptr::null_mut(),
            entry_point: std::ptr::null_mut(),
            subsystem: std::ptr::null_mut(),
            characteristics: std::ptr::null_mut(),
            dll_characteristics: std::ptr::null_mut(),
        }
    }
}

impl Drop for DetectWindowsPEData {
    fn drop(&mut self) {
        // Free all owned boxed filter data
        if !self.size.is_null() {
            let _ = unsafe { Box::from_raw(self.size) };
        }
        if !self.sections.is_null() {
            let _ = unsafe { Box::from_raw(self.sections) };
        }
        if !self.entry_point.is_null() {
            let _ = unsafe { Box::from_raw(self.entry_point) };
        }
        if !self.subsystem.is_null() {
            let _ = unsafe { Box::from_raw(self.subsystem) };
        }
        if !self.characteristics.is_null() {
            let _ = unsafe { Box::from_raw(self.characteristics) };
        }
        if !self.dll_characteristics.is_null() {
            let _ = unsafe { Box::from_raw(self.dll_characteristics) };
        }
    }
}

fn process_executable_option(data: &mut DetectWindowsPEData, key: &str, val: &str) -> Option<()> {
    match key {
        "architecture" => {
            let v = val.to_ascii_lowercase();
            data.architecture = match v.as_str() {
                "x86" | "i386" | "i686" => 0x014C,
                "x86_64" | "x64" | "amd64" => 0x8664,
                "arm" => 0x01C0,
                "arm64" | "aarch64" => 0xAA64,
                _ => return None,
            };
        }
        "size" => {
            // Parse directly using Rust's detect_parse_uint, avoiding FFI overhead
            if let Ok((_, ctx)) = detect_parse_uint::<u32>(val) {
                let boxed = Box::new(ctx);
                data.size = Box::into_raw(boxed);
            } else {
                return None;
            }
        }
        "sections" => {
            // Parse directly using Rust's detect_parse_uint, avoiding FFI overhead
            if let Ok((_, ctx)) = detect_parse_uint::<u16>(val) {
                let boxed = Box::new(ctx);
                data.sections = Box::into_raw(boxed);
            } else {
                return None;
            }
        }
        "entry_point" => {
            // Parse directly using Rust's detect_parse_uint, avoiding FFI overhead
            if let Ok((_, ctx)) = detect_parse_uint::<u32>(val) {
                let boxed = Box::new(ctx);
                data.entry_point = Box::into_raw(boxed);
            } else {
                return None;
            }
        }
        "subsystem" => {
            // Parse directly using Rust's detect_parse_uint, avoiding FFI overhead
            if let Ok((_, ctx)) = detect_parse_uint::<u16>(val) {
                let boxed = Box::new(ctx);
                data.subsystem = Box::into_raw(boxed);
            } else {
                return None;
            }
        }
        "characteristics" => {
            // Parse directly using Rust's detect_parse_uint, avoiding FFI overhead
            if let Ok((_, ctx)) = detect_parse_uint::<u16>(val) {
                let boxed = Box::new(ctx);
                data.characteristics = Box::into_raw(boxed);
            } else {
                return None;
            }
        }
        "dll_characteristics" => {
            // Parse directly using Rust's detect_parse_uint, avoiding FFI overhead
            if let Ok((_, ctx)) = detect_parse_uint::<u16>(val) {
                let boxed = Box::new(ctx);
                data.dll_characteristics = Box::into_raw(boxed);
            } else {
                return None;
            }
        }
        _ => return None,
    }
    Some(())
}

/// Parse all options from the windows_pe keyword argument string.
///
/// Handles comma-separated `key: value` pairs.  Tokens without a colon
/// are treated as continuations of the previous value, which supports
/// uint range expressions like `size: >1000, <5000`.
///
/// Returns `None` on any parse error; partially-allocated C uint data
/// is freed automatically via the `Drop` impl on [`DetectWindowsPEData`].
fn parse_executable_options(input: &str) -> Option<DetectWindowsPEData> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Some(DetectWindowsPEData::default());
    }

    let mut data = DetectWindowsPEData::default();
    let mut cur_key = String::new();
    let mut cur_val = String::new();
    let mut have_kv = false;

    for tok_raw in trimmed.split(',') {
        let tok = tok_raw.trim();
        if tok.is_empty() {
            continue;
        }

        if let Some(colon_pos) = tok.find(':') {
            // Flush previous key-value pair
            if have_kv {
                process_executable_option(&mut data, &cur_key, &cur_val)?;
            }
            cur_key = tok[..colon_pos].trim().to_ascii_lowercase();
            cur_val = tok[colon_pos + 1..].trim().to_string();
            have_kv = true;
        } else {
            // Continuation of previous value (e.g. ">1000, <5000")
            if !have_kv {
                return None;
            }
            cur_val.push(',');
            cur_val.push_str(tok);
        }
    }

    // Flush final key-value pair
    if have_kv {
        process_executable_option(&mut data, &cur_key, &cur_val)?;
    }

    Some(data)
}

/// Parse windows_pe keyword options from a C string.
///
/// Follows the bytemath pattern: Rust owns the context struct.
/// C calls this from `DetectExecutableSetup`, stores the returned pointer,
/// and later frees it with [`SCDetectWindowsPEFree`].
///
/// A NULL `c_arg` means bare `executable;` with no options (default PE
/// validation, no metadata filters).
#[no_mangle]
pub unsafe extern "C" fn SCDetectWindowsPEParse(c_arg: *const c_char) -> *mut DetectWindowsPEData {
    if c_arg.is_null() {
        // No options -> default PE validation only
        return Box::into_raw(Box::new(DetectWindowsPEData::default()));
    }

    let arg = match CStr::from_ptr(c_arg).to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    match parse_executable_options(arg) {
        Some(data) => Box::into_raw(Box::new(data)),
        None => std::ptr::null_mut(),
    }
}

/// Free a [`DetectWindowsPEData`] allocated by [`SCDetectWindowsPEParse`].
///
/// The `Drop` impl on `DetectExecutableData` takes care of freeing any
/// C-allocated uint filter data (`DetectU32Data`, `DetectU16Data`).
#[no_mangle]
pub unsafe extern "C" fn SCDetectWindowsPEFree(ptr: *mut DetectWindowsPEData) {
    if !ptr.is_null() {
        let _ = Box::from_raw(ptr);
    }
}

/// Log PE metadata as JSON into a `JsonBuilder` (OPTIMIZED)
///
/// Uses fixed arrays and stack allocation instead of Vec to avoid heap allocation.
/// Writes a `"executable"` object with fields like machine, sections, subsystem, etc.
/// This is called from `EveFileInfo` in C when the file data starts with "MZ"
/// to enrich fileinfo events with PE-specific metadata.
///
/// Returns Ok(()) if PE metadata was successfully written, or the first JsonError encountered.
fn pe_log_json(data: &[u8], js: &mut JsonBuilder) -> Result<(), JsonError> {
    let meta = match parse_pe_metadata(data) {
        Some(m) => m,
        None => return Ok(()), // not a valid PE, nothing to log
    };

    js.open_object("executable")?;

    // Architecture (machine type) - hex value and human-readable name
    let arch_hex = format!("0x{:04x}", meta.architecture);
    let arch_name = match meta.architecture {
        0x014C => "x86",
        0x8664 => "x86-64",
        0x01C0 => "ARM",
        0xAA64 => "ARM64",
        _ => "unknown",
    };
    js.set_string("architecture", &arch_hex)?;
    js.set_string("architecture_name", arch_name)?;

    // Sections
    js.set_uint("sections", meta.num_sections as u64)?;

    // Subsystem with human-readable name
    let subsystem_name = match meta.subsystem {
        0 => "UNKNOWN",
        1 => "NATIVE",
        2 => "WINDOWS_GUI",
        3 => "WINDOWS_CUI",
        5 => "OS2_CUI",
        7 => "POSIX_CUI",
        9 => "WINDOWS_CE_GUI",
        10 => "EFI_APPLICATION",
        11 => "EFI_BOOT_SERVICE_DRIVER",
        12 => "EFI_RUNTIME_DRIVER",
        13 => "EFI_ROM",
        14 => "XBOX",
        16 => "WINDOWS_BOOT_APPLICATION",
        _ => "UNKNOWN",
    };
    js.set_string("subsystem", subsystem_name)?;
    js.set_uint("subsystem_id", meta.subsystem as u64)?;

    // PE characteristics - use stack array instead of Vec
    js.set_uint("characteristics", meta.characteristics as u64)?;

    // Stack-allocated array for characteristic names (max 5 possible)
    let mut char_traits: [&str; 5] = [""; 5];
    let mut char_count = 0;

    if meta.characteristics & 0x0002 != 0 && char_count < 5 {
        char_traits[char_count] = "EXECUTABLE_IMAGE";
        char_count += 1;
    }
    if meta.characteristics & 0x2000 != 0 && char_count < 5 {
        char_traits[char_count] = "DLL";
        char_count += 1;
    }
    if meta.characteristics & 0x0020 != 0 && char_count < 5 {
        char_traits[char_count] = "LARGE_ADDRESS_AWARE";
        char_count += 1;
    }
    if meta.characteristics & 0x0100 != 0 && char_count < 5 {
        char_traits[char_count] = "32BIT_MACHINE";
        char_count += 1;
    }

    if char_count > 0 {
        js.open_array("characteristics_names")?;
        for i in 0..char_count {
            js.append_string(char_traits[i])?;
        }
        js.close()?;
    }

    // DLL characteristics (security features) - use stack array instead of Vec
    js.set_uint("dll_characteristics", meta.dll_characteristics as u64)?;

    let mut sec_features: [&str; 5] = [""; 5];
    let mut sec_count = 0;

    if meta.dll_characteristics & 0x0020 != 0 && sec_count < 5 {
        sec_features[sec_count] = "HIGH_ENTROPY_VA";
        sec_count += 1;
    }
    if meta.dll_characteristics & 0x0040 != 0 && sec_count < 5 {
        sec_features[sec_count] = "DYNAMIC_BASE"; // ASLR
        sec_count += 1;
    }
    if meta.dll_characteristics & 0x0100 != 0 && sec_count < 5 {
        sec_features[sec_count] = "NX_COMPAT"; // DEP/NX
        sec_count += 1;
    }
    if meta.dll_characteristics & 0x0400 != 0 && sec_count < 5 {
        sec_features[sec_count] = "NO_SEH";
        sec_count += 1;
    }
    if meta.dll_characteristics & 0x4000 != 0 && sec_count < 5 {
        sec_features[sec_count] = "GUARD_CF"; // Control Flow Guard
        sec_count += 1;
    }

    if sec_count > 0 {
        js.open_array("security_features")?;
        for i in 0..sec_count {
            js.append_string(sec_features[i])?;
        }
        js.close()?;
    }

    // Entry point and image size
    js.set_uint("entry_point", meta.entry_point_rva as u64)?;
    js.set_uint("size_of_image", meta.size_of_image as u64)?;

    // PE offset (where PE header lives in the file)
    js.set_uint("pe_offset", meta.pe_offset as u64)?;

    js.close()?; // close "executable" object
    Ok(())
}

/// FFI entry point: log PE metadata as JSON.
///
/// Called from C code (`EveFileInfo` or `JsonBuildFileInfoRecord`) to add
/// PE metadata to fileinfo events in eve.json.
///
/// # Safety
/// `data` must point to `data_len` valid bytes. `js` must be a valid `JsonBuilder`.
#[no_mangle]
pub unsafe extern "C" fn SCPeLogJson(data: *const u8, data_len: u32, js: &mut JsonBuilder) -> bool {
    if data.is_null() || data_len < 64 {
        return false;
    }
    let file_data = std::slice::from_raw_parts(data, data_len as usize);

    // Quick check: must start with MZ
    if file_data.len() < 2 || file_data[0] != b'M' || file_data[1] != b'Z' {
        return false;
    }

    pe_log_json(file_data, js).is_ok()
}

/// Thread-local PE metadata cache indexed by file pointer.
///
/// Caches parsed PE metadata to avoid re-parsing the same file multiple times
/// within a single rule set evaluation. Each worker thread has its own cache
/// -- no locking needed.
///
/// Cache size is capped at 1000 entries. When exceeded, the entire cache is
/// cleared (simple but effective strategy for typical Suricata workloads where
/// files are processed sequentially within threads).
use std::cell::RefCell;
use std::collections::HashMap;

const PE_CACHE_MAX_ENTRIES: usize = 1000;

thread_local! {
    static PE_CACHE: RefCell<HashMap<*const std::ffi::c_void, SCDetectPeMetadata>> =
        RefCell::new(HashMap::new());
}

/// Retrieve PE metadata for a file, using cached result if available.
///
/// Implements simple cache eviction: when cache exceeds PE_CACHE_MAX_ENTRIES,
/// the entire cache is cleared. This strategy is effective for typical Suricata
/// workloads where files are processed sequentially.
///
/// # Safety
/// - `file_ptr` must be a valid non-null pointer to a File object
/// - `data` must point to `data_len` valid bytes from the file
/// - Caller must ensure `file_ptr` remains valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn SCDetectPeMetadataGetByFile(
    file_ptr: *const std::ffi::c_void, data: *const u8, data_len: u32,
) -> SCDetectPeMetadata {
    if file_ptr.is_null() || data.is_null() || data_len < 64 {
        return SCDetectPeMetadata::default();
    }

    // Try to get from cache
    let cached = PE_CACHE.with(|cache| cache.borrow().get(&file_ptr).copied());

    if let Some(meta) = cached {
        return meta;
    }

    // Not in cache, parse and insert
    let file_data = std::slice::from_raw_parts(data, data_len as usize);
    let meta = match parse_pe_metadata(file_data) {
        Some(m) => SCDetectPeMetadata {
            valid: true,
            architecture: m.architecture,
            num_sections: m.num_sections,
            subsystem: m.subsystem,
            characteristics: m.characteristics,
            dll_characteristics: m.dll_characteristics,
            size_of_image: m.size_of_image,
            entry_point_rva: m.entry_point_rva,
        },
        None => SCDetectPeMetadata::default(),
    };

    // Store in cache with eviction check
    PE_CACHE.with(|cache| {
        let mut cache_mut = cache.borrow_mut();

        // Check if we need to evict
        if cache_mut.len() >= PE_CACHE_MAX_ENTRIES {
            cache_mut.clear();
        }

        cache_mut.insert(file_ptr, meta);
    });

    meta
}

/// Check if PE metadata matches the filter criteria.
///
/// Returns 1 if all criteria match, 0 if any criteria don't match.
/// Handles NULL pointers for optional criterion fields (treated as "any value OK").
///
/// # Safety
/// - `meta` must point to a valid `SCDetectPeMetadata` struct
/// - `ctx` must point to a valid `DetectWindowsPEData` struct
/// - All pointers in `ctx` (size, sections, etc.) must be valid or NULL
#[no_mangle]
pub unsafe extern "C" fn SCDetectWindowsPEMatch(
    meta: *const SCDetectPeMetadata, ctx: *const DetectWindowsPEData,
) -> i32 {
    if meta.is_null() || ctx.is_null() {
        return 0;
    }

    let meta = &*meta;
    let ctx = &*ctx;

    // If metadata is not valid PE, no match
    if !meta.valid {
        return 0;
    }

    // Architecture filter (0 means no filter)
    if ctx.architecture != 0 && meta.architecture != ctx.architecture {
        return 0;
    }

    // Optional metadata filters using C's existing DetectU32Match / DetectU16Match
    // Import from detect-engine-uint.h
    extern "C" {
        fn DetectU32Match(val: u32, ctx: *const std::ffi::c_void) -> i32;
        fn DetectU16Match(val: u16, ctx: *const std::ffi::c_void) -> i32;
    }

    if !ctx.size.is_null() {
        if DetectU32Match(meta.size_of_image, ctx.size as *const std::ffi::c_void) == 0 {
            return 0;
        }
    }

    if !ctx.sections.is_null() {
        if DetectU16Match(meta.num_sections, ctx.sections as *const std::ffi::c_void) == 0 {
            return 0;
        }
    }

    if !ctx.entry_point.is_null() {
        if DetectU32Match(
            meta.entry_point_rva,
            ctx.entry_point as *const std::ffi::c_void,
        ) == 0
        {
            return 0;
        }
    }

    if !ctx.subsystem.is_null() {
        if DetectU16Match(meta.subsystem, ctx.subsystem as *const std::ffi::c_void) == 0 {
            return 0;
        }
    }

    if !ctx.characteristics.is_null() {
        if DetectU16Match(
            meta.characteristics,
            ctx.characteristics as *const std::ffi::c_void,
        ) == 0
        {
            return 0;
        }
    }

    if !ctx.dll_characteristics.is_null() {
        if DetectU16Match(
            meta.dll_characteristics,
            ctx.dll_characteristics as *const std::ffi::c_void,
        ) == 0
        {
            return 0;
        }
    }

    1
}

/// Combined file match operation: retrieve PE metadata and check if it matches.
///
/// This combines two operations into a single FFI call for efficiency:
/// 1. Retrieve PE metadata from file data (using thread-local cache)
/// 2. Check if metadata matches the filter criteria
///
/// Returns 1 if metadata is valid and all criteria match, 0 otherwise.
///
/// # Safety
/// - `file_ptr` must be a valid non-null pointer to a File object
/// - `data` must point to `data_len` valid bytes from the file
/// - `ctx` must point to a valid `DetectExecutableData` struct
/// - All pointers in `ctx` must be valid or NULL
#[no_mangle]
pub unsafe extern "C" fn SCDetectWindowsPEFileMatch(
    file_ptr: *const std::ffi::c_void, data: *const u8, data_len: u32,
    ctx: *const DetectWindowsPEData,
) -> i32 {
    if file_ptr.is_null() || data.is_null() || data_len < 64 || ctx.is_null() {
        return 0;
    }

    // Get PE metadata (cached by file pointer)
    let meta = SCDetectPeMetadataGetByFile(file_ptr, data, data_len);

    // Check if metadata matches criteria
    SCDetectWindowsPEMatch(&meta, ctx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pe_validate_minimal_pe() {
        // Minimal valid PE: DOS header with MZ and PE offset pointing to a valid PE
        let mut buf = vec![0u8; 100];

        // Set DOS header magic "MZ"
        buf[0] = b'M';
        buf[1] = b'Z';

        // Set PE offset (at bytes 60-63) to point to byte 64
        let pe_offset = 64u32;
        buf[60..64].copy_from_slice(&pe_offset.to_le_bytes());

        // Set PE signature at offset 64
        buf[64..68].copy_from_slice(b"PE\0\0");

        assert!(pe_validate(&buf));
    }

    #[test]
    fn test_pe_validate_real_pe_structure() {
        // Simulate a more realistic PE structure
        let mut buf = vec![0u8; 512];

        // DOS header
        buf[0..2].copy_from_slice(b"MZ");

        // PE offset at 60-63: point to offset 128
        let pe_offset = 128u32;
        buf[60..64].copy_from_slice(&pe_offset.to_le_bytes());

        // DOS stub (PE offset - 64 bytes of DOS header)
        for i in 64..128 {
            buf[i] = (i % 256) as u8;
        }

        // PE header at offset 128
        buf[128..132].copy_from_slice(b"PE\0\0");
        // Machine type (little-endian, e.g., 0x014C for x86)
        buf[132..134].copy_from_slice(&0x014Cu32.to_le_bytes()[..2]);

        assert!(pe_validate(&buf));
    }

    #[test]
    fn test_pe_validate_no_mz() {
        let mut buf = vec![0u8; 100];
        buf[0] = b'Z';
        buf[1] = b'M'; // Wrong order

        let pe_offset = 64u32;
        buf[60..64].copy_from_slice(&pe_offset.to_le_bytes());

        buf[64..68].copy_from_slice(b"PE\0\0");

        assert!(!pe_validate(&buf));
    }

    #[test]
    fn test_pe_validate_no_pe_signature() {
        let mut buf = vec![0u8; 100];

        buf[0..2].copy_from_slice(b"MZ");

        let pe_offset = 64u32;
        buf[60..64].copy_from_slice(&pe_offset.to_le_bytes());

        buf[64..68].copy_from_slice(b"XX\0\0"); // Wrong signature

        assert!(!pe_validate(&buf));
    }

    #[test]
    fn test_pe_validate_invalid_pe_offset() {
        let mut buf = vec![0u8; 100];

        buf[0..2].copy_from_slice(b"MZ");

        // PE offset beyond reasonable range
        let pe_offset = 0x20000u32;
        buf[60..64].copy_from_slice(&pe_offset.to_le_bytes());

        assert!(!pe_validate(&buf));
    }

    #[test]
    fn test_pe_validate_pe_offset_past_eof() {
        let mut buf = vec![0u8; 100];

        buf[0..2].copy_from_slice(b"MZ");

        // PE offset beyond buffer size
        let pe_offset = 200u32;
        buf[60..64].copy_from_slice(&pe_offset.to_le_bytes());

        assert!(!pe_validate(&buf));
    }

    #[test]
    fn test_pe_validate_too_small() {
        let buf = vec![0u8; 63]; // Less than 64 bytes
        assert!(!pe_validate(&buf));
    }

    #[test]
    fn test_pe_validate_exact_boundary() {
        let mut buf = vec![0u8; 68]; // Exactly 68 bytes (64 + 4 for signature)

        buf[0..2].copy_from_slice(b"MZ");

        let pe_offset = 64u32;
        buf[60..64].copy_from_slice(&pe_offset.to_le_bytes());

        buf[64..68].copy_from_slice(b"PE\0\0");

        assert!(pe_validate(&buf));
    }

    #[test]
    fn test_dos_stub_standard() {
        let stub = b"This program cannot be run in DOS mode.\r\r\n$";
        let stub_type = analyze_dos_stub(stub);
        assert_eq!(stub_type, DOSStubType::Standard);
    }

    #[test]
    fn test_dos_stub_packed_upx() {
        let mut stub = vec![0u8; 64];
        // Insert UPX! marker
        stub[0..4].copy_from_slice(b"UPX!");
        let stub_type = analyze_dos_stub(&stub);
        assert_eq!(stub_type, DOSStubType::Packed);
    }

    #[test]
    fn test_dos_stub_minimal() {
        let stub = vec![0u8; 32];
        let stub_type = analyze_dos_stub(&stub);
        assert_eq!(stub_type, DOSStubType::Minimal);
    }

    #[test]
    fn test_dos_stub_modified() {
        let mut stub = vec![0u8; 64];
        // Add enough non-zero bytes to trigger "modified" classification
        for i in 0..20 {
            stub[i] = (i as u8) + 1;
        }
        let stub_type = analyze_dos_stub(&stub);
        assert_eq!(stub_type, DOSStubType::Modified);
    }

    #[test]
    fn test_parse_pe_metadata_minimal() {
        let mut buf = vec![0u8; 300];

        // DOS header
        buf[0] = b'M';
        buf[1] = b'Z';

        // PE offset (64 bytes)
        let pe_offset = 64u32;
        buf[60..64].copy_from_slice(&pe_offset.to_le_bytes());

        // PE signature
        buf[64..68].copy_from_slice(b"PE\0\0");

        // Machine type (x86)
        buf[68..70].copy_from_slice(&0x014Cu16.to_le_bytes());

        // Number of sections
        buf[70..72].copy_from_slice(&0x0003u16.to_le_bytes());

        // Characteristics (executable)
        buf[86..88].copy_from_slice(&0x0102u16.to_le_bytes());

        let metadata = parse_pe_metadata(&buf).unwrap();
        assert_eq!(metadata.architecture, 0x014C);
        assert_eq!(metadata.num_sections, 3);
        assert_eq!(metadata.pe_offset, 64);
    }

    #[test]
    fn test_parse_pe_metadata_with_optional_header() {
        let mut buf = vec![0u8; 400];

        // DOS header
        buf[0..2].copy_from_slice(b"MZ");

        // PE offset
        let pe_offset = 128u32;
        buf[60..64].copy_from_slice(&pe_offset.to_le_bytes());

        // PE signature at offset 128
        buf[128..132].copy_from_slice(b"PE\0\0");

        // Machine type (x64)
        buf[132..134].copy_from_slice(&0x8664u16.to_le_bytes());

        // Number of sections
        buf[134..136].copy_from_slice(&0x0005u16.to_le_bytes());

        // Characteristics
        buf[150..152].copy_from_slice(&0x0022u16.to_le_bytes());

        // SizeOfOptionalHeader
        buf[148..150].copy_from_slice(&0x00F0u16.to_le_bytes());

        // Optional header starts at 152 (128 + 24)
        // SizeOfImage at optional_header + 0x38 = 152 + 56 = offset 208
        buf[208..212].copy_from_slice(&0x10000u32.to_le_bytes());

        // AddressOfEntryPoint at optional_header + 0x10 = 152 + 16 = offset 168
        buf[168..172].copy_from_slice(&0x4000u32.to_le_bytes());

        let metadata = parse_pe_metadata(&buf).unwrap();
        assert_eq!(metadata.architecture, 0x8664);
        assert_eq!(metadata.num_sections, 5);
        assert_eq!(metadata.size_of_image, 0x10000);
        assert_eq!(metadata.entry_point_rva, 0x4000);
    }

    #[test]
    fn test_parse_pe_metadata_invalid() {
        let buf = vec![0u8; 100];
        let metadata = parse_pe_metadata(&buf);
        assert!(metadata.is_none());
    }

    #[test]
    fn test_parse_pe_metadata_dos_stub_detection() {
        let mut buf = vec![0u8; 300];

        // DOS header
        buf[0..2].copy_from_slice(b"MZ");
        let pe_offset = 128u32;
        buf[60..64].copy_from_slice(&pe_offset.to_le_bytes());

        // DOS stub with standard message between bytes 64 and 128
        let stub = b"This program cannot be run in DOS mode.\r\r\n$";
        buf[64..64 + stub.len()].copy_from_slice(stub);

        // PE signature at offset 128
        buf[128..132].copy_from_slice(b"PE\0\0");

        // Minimal COFF header
        buf[132..134].copy_from_slice(&0x014Cu16.to_le_bytes());
        buf[134..136].copy_from_slice(&0x0001u16.to_le_bytes());

        let metadata = parse_pe_metadata(&buf).unwrap();
        assert_eq!(metadata.dos_stub_type, DOSStubType::Standard);
    }

    #[test]
    fn test_parse_machine_types() {
        // Test common machine types
        let machine_types = [
            (0x014C, "x86"),
            (0x8664, "x64"),
            (0x01C0, "ARM"),
            (0xAA64, "ARM64"),
        ];

        for (machine_type, _arch) in &machine_types {
            let mut buf = vec![0u8; 300];
            buf[0..2].copy_from_slice(b"MZ");
            buf[60..64].copy_from_slice(&64u32.to_le_bytes());
            buf[64..68].copy_from_slice(b"PE\0\0");
            buf[68..70].copy_from_slice(&(*machine_type as u16).to_le_bytes());
            buf[70..72].copy_from_slice(&0x0001u16.to_le_bytes());

            let metadata = parse_pe_metadata(&buf).unwrap();
            assert_eq!(metadata.architecture, *machine_type);
        }
    }
}
