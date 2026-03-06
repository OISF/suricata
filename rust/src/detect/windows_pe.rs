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
//! This module provides the `windows_pe` detection keyword for identifying Windows Portable
//! Executable (PE) files in network traffic. The keyword inspects file data buffers to validate
//! PE structure and match on header metadata.
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

use crate::detect::uint::{detect_match_uint, detect_parse_uint, DetectUintData};
use crate::jsonbuilder::{JsonBuilder, JsonError};
use std::ffi::CStr;
use std::collections::HashSet;
use std::os::raw::{c_char, c_int};
use suricata_sys::sys::{
    DetectEngineCtx, DetectEngineThreadCtx, File, Flow, SCDetectHelperFileKeywordRegister,
    SCDetectHelperGetFilesBufferId, SCDetectSignatureSetFileInspect, SCFileGetData,
    SCSigMatchAppendSMToList, SCSigTableFileLiteElmt, Signature, SigMatchCtx,
    SIGMATCH_OPTIONAL_OPT,
};

/// Flag: PE metadata has been parsed (valid or invalid).
pub const SC_FILE_PE_META_F_PARSED: u16 = 1 << 0;
/// Flag: PE metadata is valid (file is a valid PE).
pub const SC_FILE_PE_META_F_VALID: u16 = 1 << 1;

/// Cached Windows PE metadata stored in the `File` object.
///
/// Parsed once per file and cached to avoid redundant header parsing
/// across multiple keyword evaluations and logging calls.  Fields map
/// directly to COFF / Optional header values.
///
/// The `flags` field uses `SC_FILE_PE_META_F_PARSED` to indicate that
/// parsing has been attempted, and `SC_FILE_PE_META_F_VALID` to indicate
/// that the file is a valid PE.
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct SCFilePeMeta {
    pub flags: u16,
    pub architecture: u16,
    pub num_sections: u16,
    pub subsystem: u16,
    pub characteristics: u16,
    pub dll_characteristics: u16,
    /// Optional header magic (0x10b = PE32, 0x20b = PE32+).
    pub magic: u16,
    /// Number of imported DLLs from the Import Directory Table.
    pub num_imports: u16,
    /// SizeOfImage from the optional header.
    pub size_of_image: u32,
    /// AddressOfEntryPoint RVA from the optional header.
    pub entry_point_rva: u32,
    /// Offset to the PE signature in the file.
    pub pe_offset: u32,
    /// TimeDateStamp from the COFF header (Unix epoch seconds).
    pub timestamp: u32,
    /// Checksum from the optional header.
    pub checksum: u32,
    /// SizeOfHeaders from the optional header.
    pub size_of_headers: u32,
    /// Number of exported functions from the Export Directory.
    pub num_exports: u32,
    /// Non-zero if any section has both WRITE and EXECUTE permissions.
    pub has_wx_section: u8,
    pub padding_: [u8; 3],
}

extern "C" {
    fn SCDetectWindowsPEEnablePrefilter(keyword_id: u16, files_list_id: c_int);
    fn FilePeMetaGet(file: *const File, meta: *mut SCFilePeMeta) -> bool;
    fn FilePeMetaSet(file: *mut File, meta: *const SCFilePeMeta);
    fn FilePeImportsGet(file: *const File) -> *const std::os::raw::c_void;
    fn FilePeImportsSet(file: *mut File, imports: *mut std::os::raw::c_void);
}

/// PE file metadata extracted from headers
#[derive(Debug, Clone)]
struct PEMetadata {
    /// Offset to PE signature (from PE offset field at DOS offset 60-63)
    pe_offset: u32,
    /// Machine type from COFF header (x86=0x014C, x64=0x8664, ARM=0x01C0, etc.)
    architecture: u16,
    /// Number of sections from COFF header
    num_sections: u16,
    /// SizeOfImage from optional header (total mapped size)
    size_of_image: u32,
    /// AddressOfEntryPoint from optional header (entry point RVA)
    entry_point_rva: u32,
    /// Characteristics from COFF header (executable, dll, etc.)
    characteristics: u16,
    /// Subsystem from optional header (console, gui, driver, etc.)
    subsystem: u16,
    /// DLL characteristics from optional header
    dll_characteristics: u16,
    /// Optional header magic (PE32=0x10b, PE32+=0x20b)
    magic: u16,
    /// TimeDateStamp from COFF header
    timestamp: u32,
    /// Checksum from optional header
    checksum: u32,
    /// SizeOfHeaders from optional header
    size_of_headers: u32,
}

/// Validate a PE file and return the PE header offset on success.
///
/// Returns `Some(pe_offset)` when the data contains a valid MZ + PE\0\0
/// signature pair, `None` otherwise.  Callers should reuse the returned
/// offset instead of re-reading bytes 60-63.
fn pe_validate(data: &[u8]) -> Option<usize> {
    if data.len() < 64 {
        return None;
    }
    if data[0] != b'M' || data[1] != b'Z' {
        return None;
    }
    let pe_offset = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;
    if pe_offset > 0x10000 || pe_offset + 4 > data.len() {
        return None;
    }
    if &data[pe_offset..pe_offset + 4] != b"PE\0\0" {
        return None;
    }
    Some(pe_offset)
}

/// Parse PE header and extract metadata.
///
/// Extracts COFF and Optional header information from a validated PE file.
/// Consolidates bounds checking upfront for efficiency.
/// Returns None if the data is not a valid PE or is too small.
fn parse_pe_metadata(data: &[u8]) -> Option<PEMetadata> {
    let pe_offset = pe_validate(data)?;

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
    let timestamp = u32::from_le_bytes([
        data[pe_offset + 8],
        data[pe_offset + 9],
        data[pe_offset + 10],
        data[pe_offset + 11],
    ]);
    let characteristics = u16::from_le_bytes([data[pe_offset + 22], data[pe_offset + 23]]);

    // Optional header at pe_offset + 24
    let optional_header_offset = pe_offset + 24;
    let magic = u16::from_le_bytes([
        data[optional_header_offset],
        data[optional_header_offset + 1],
    ]);
    let entry_point_rva = u32::from_le_bytes([
        data[optional_header_offset + 0x10],
        data[optional_header_offset + 0x11],
        data[optional_header_offset + 0x12],
        data[optional_header_offset + 0x13],
    ]);
    let size_of_image = u32::from_le_bytes([
        data[optional_header_offset + 0x38],
        data[optional_header_offset + 0x39],
        data[optional_header_offset + 0x3A],
        data[optional_header_offset + 0x3B],
    ]);
    let size_of_headers = u32::from_le_bytes([
        data[optional_header_offset + 0x3C],
        data[optional_header_offset + 0x3D],
        data[optional_header_offset + 0x3E],
        data[optional_header_offset + 0x3F],
    ]);
    let checksum = u32::from_le_bytes([
        data[optional_header_offset + 0x40],
        data[optional_header_offset + 0x41],
        data[optional_header_offset + 0x42],
        data[optional_header_offset + 0x43],
    ]);
    let subsystem = u16::from_le_bytes([
        data[optional_header_offset + 0x44],
        data[optional_header_offset + 0x45],
    ]);
    let dll_characteristics = u16::from_le_bytes([
        data[optional_header_offset + 0x46],
        data[optional_header_offset + 0x47],
    ]);

    Some(PEMetadata {
        pe_offset: pe_offset as u32,
        architecture: machine_type,
        num_sections,
        size_of_image,
        entry_point_rva,
        characteristics,
        subsystem,
        dll_characteristics,
        magic,
        timestamp,
        checksum,
        size_of_headers,
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
    let timestamp = safe_u32_at(pe_offset + 8);
    let characteristics = safe_u16_at(pe_offset + 22);

    let optional_header_offset = pe_offset + 24;
    let magic = safe_u16_at(optional_header_offset);
    let entry_point_rva = safe_u32_at(optional_header_offset + 0x10);
    let size_of_image = safe_u32_at(optional_header_offset + 0x38);
    let size_of_headers = safe_u32_at(optional_header_offset + 0x3C);
    let checksum = safe_u32_at(optional_header_offset + 0x40);
    let subsystem = safe_u16_at(optional_header_offset + 0x44);
    let dll_characteristics = safe_u16_at(optional_header_offset + 0x46);

    Some(PEMetadata {
        pe_offset: pe_offset as u32,
        architecture: machine_type,
        num_sections,
        size_of_image,
        entry_point_rva,
        characteristics,
        subsystem,
        dll_characteristics,
        magic,
        timestamp,
        checksum,
        size_of_headers,
    })
}

// ============================================================================
// PE Import Table Parsing
// ============================================================================

/// Minimal section header info needed for RVA-to-file-offset conversion.
struct SectionInfo {
    name: [u8; 8],
    virtual_address: u32,
    virtual_size: u32,
    raw_data_offset: u32,
    raw_data_size: u32,
    characteristics: u32,
}

/// Convert an RVA to a file offset using section headers.
///
/// Walks the section table to find which section contains the RVA, then
/// computes the file offset as: `rva - section.virtual_address + section.raw_data_offset`.
fn rva_to_offset(rva: u32, sections: &[SectionInfo]) -> Option<usize> {
    for section in sections {
        if rva >= section.virtual_address
            && rva < section.virtual_address.saturating_add(section.virtual_size)
        {
            let delta = rva - section.virtual_address;
            if delta < section.raw_data_size {
                return Some(section.raw_data_offset.wrapping_add(delta) as usize);
            }
        }
    }
    None
}

/// Parse section headers from a validated PE file.
///
/// Section headers start immediately after the optional header:
/// `pe_offset + 24 + SizeOfOptionalHeader`.
fn parse_section_headers(data: &[u8], pe_offset: usize, num_sections: u16) -> Vec<SectionInfo> {
    if pe_offset + 24 > data.len() {
        return Vec::new();
    }
    let size_of_optional_header =
        u16::from_le_bytes([data[pe_offset + 20], data[pe_offset + 21]]) as usize;
    let sections_start = pe_offset + 24 + size_of_optional_header;
    let count = (num_sections as usize).min(96); // safety cap
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let base = sections_start + i * 40;
        if base + 40 > data.len() {
            break;
        }
        let mut name = [0u8; 8];
        name.copy_from_slice(&data[base..base + 8]);
        out.push(SectionInfo {
            name,
            virtual_size: u32::from_le_bytes([
                data[base + 8],
                data[base + 9],
                data[base + 10],
                data[base + 11],
            ]),
            virtual_address: u32::from_le_bytes([
                data[base + 12],
                data[base + 13],
                data[base + 14],
                data[base + 15],
            ]),
            raw_data_size: u32::from_le_bytes([
                data[base + 16],
                data[base + 17],
                data[base + 18],
                data[base + 19],
            ]),
            raw_data_offset: u32::from_le_bytes([
                data[base + 20],
                data[base + 21],
                data[base + 22],
                data[base + 23],
            ]),
            characteristics: u32::from_le_bytes([
                data[base + 36],
                data[base + 37],
                data[base + 38],
                data[base + 39],
            ]),
        });
    }
    out
}

/// Inner import parser that takes a pre-validated PE offset.
///
/// Avoids redundant `pe_validate` when the caller has already validated.
fn parse_pe_imports_with_offset(data: &[u8], pe_offset: usize) -> Option<Vec<String>> {
    let optional_header_offset = pe_offset + 24;

    // Need at least 2 bytes for Magic
    if optional_header_offset + 2 > data.len() {
        return None;
    }
    let magic = u16::from_le_bytes([
        data[optional_header_offset],
        data[optional_header_offset + 1],
    ]);

    // Determine offsets that depend on PE32 vs PE32+
    let (num_rva_off, data_dir_off) = match magic {
        0x10b => (optional_header_offset + 0x5C, optional_header_offset + 0x60), // PE32
        0x20b => (optional_header_offset + 0x6C, optional_header_offset + 0x70), // PE32+
        _ => return None,
    };

    // NumberOfRvaAndSizes must be >= 2 (export + import)
    if num_rva_off + 4 > data.len() {
        return None;
    }
    let num_rva_and_sizes = u32::from_le_bytes([
        data[num_rva_off],
        data[num_rva_off + 1],
        data[num_rva_off + 2],
        data[num_rva_off + 3],
    ]);
    if num_rva_and_sizes < 2 {
        return None;
    }

    // Import Directory is data-directory entry index 1 (each entry = 8 bytes)
    let import_entry = data_dir_off + 8;
    if import_entry + 8 > data.len() {
        return None;
    }
    let import_rva = u32::from_le_bytes([
        data[import_entry],
        data[import_entry + 1],
        data[import_entry + 2],
        data[import_entry + 3],
    ]);
    let import_size = u32::from_le_bytes([
        data[import_entry + 4],
        data[import_entry + 5],
        data[import_entry + 6],
        data[import_entry + 7],
    ]);
    if import_rva == 0 || import_size == 0 {
        return Some(Vec::new()); // PE has no imports
    }

    // Build section table for RVA translation
    let num_sections = u16::from_le_bytes([data[pe_offset + 6], data[pe_offset + 7]]);
    let sections = parse_section_headers(data, pe_offset, num_sections);

    let import_off = rva_to_offset(import_rva, &sections)?;

    let mut dlls = Vec::new();
    let max_entries: usize = 256; // safety limit

    for i in 0..max_entries {
        let ent = import_off + i * 20;
        if ent + 20 > data.len() {
            break;
        }

        // Import Directory entry bytes 12..16 = Name RVA
        let name_rva = u32::from_le_bytes([
            data[ent + 12],
            data[ent + 13],
            data[ent + 14],
            data[ent + 15],
        ]);

        // All-zero entry terminates the table
        if data[ent..ent + 20].iter().all(|&b| b == 0) {
            break;
        }
        if name_rva == 0 {
            continue;
        }

        let name_off = match rva_to_offset(name_rva, &sections) {
            Some(o) => o,
            None => continue,
        };
        if name_off >= data.len() {
            continue;
        }

        // Read null-terminated ASCII DLL name (max 260 chars)
        let max_len = 260.min(data.len() - name_off);
        let name_bytes = &data[name_off..name_off + max_len];
        let end = name_bytes.iter().position(|&b| b == 0).unwrap_or(max_len);
        if end > 0 {
            if let Ok(name) = std::str::from_utf8(&name_bytes[..end]) {
                dlls.push(name.to_ascii_lowercase());
            }
        }
    }

    Some(dlls)
}

/// Parse the export directory to extract the DLL name and number of exported functions.
///
/// Returns `(export_name, num_exports)`.  The export name is the internal
/// DLL name from the export directory (lowercased).
fn parse_pe_exports(data: &[u8], pe_offset: usize) -> (Option<String>, u32) {
    let optional_header_offset = pe_offset + 24;
    if optional_header_offset + 2 > data.len() {
        return (None, 0);
    }
    let magic = u16::from_le_bytes([data[optional_header_offset], data[optional_header_offset + 1]]);
    let (num_rva_off, data_dir_off) = match magic {
        0x10b => (optional_header_offset + 0x5C, optional_header_offset + 0x60),
        0x20b => (optional_header_offset + 0x6C, optional_header_offset + 0x70),
        _ => return (None, 0),
    };

    if num_rva_off + 4 > data.len() {
        return (None, 0);
    }
    let num_rva_sizes = u32::from_le_bytes([
        data[num_rva_off], data[num_rva_off + 1], data[num_rva_off + 2], data[num_rva_off + 3],
    ]);
    // Export directory is data directory index 0
    if num_rva_sizes < 1 || data_dir_off + 8 > data.len() {
        return (None, 0);
    }
    let export_rva = u32::from_le_bytes([
        data[data_dir_off], data[data_dir_off + 1], data[data_dir_off + 2], data[data_dir_off + 3],
    ]);
    if export_rva == 0 {
        return (None, 0);
    }

    let num_sections = u16::from_le_bytes([data[pe_offset + 6], data[pe_offset + 7]]);
    let sections = parse_section_headers(data, pe_offset, num_sections);
    let export_off = match rva_to_offset(export_rva, &sections) {
        Some(o) => o,
        None => return (None, 0),
    };

    // Export directory table: 40 bytes minimum
    if export_off + 40 > data.len() {
        return (None, 0);
    }

    let num_functions = u32::from_le_bytes([
        data[export_off + 20], data[export_off + 21],
        data[export_off + 22], data[export_off + 23],
    ]);
    let name_rva = u32::from_le_bytes([
        data[export_off + 12], data[export_off + 13],
        data[export_off + 14], data[export_off + 15],
    ]);

    let export_name = if name_rva != 0 {
        rva_to_offset(name_rva, &sections).and_then(|off| {
            if off >= data.len() {
                return None;
            }
            let max_len = 260.min(data.len() - off);
            let end = data[off..off + max_len].iter().position(|&b| b == 0).unwrap_or(max_len);
            if end > 0 {
                std::str::from_utf8(&data[off..off + end]).ok().map(|s| s.to_ascii_lowercase())
            } else {
                None
            }
        })
    } else {
        None
    };

    (export_name, num_functions)
}

/// Check if any section has both WRITE and EXECUTE characteristics.
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

fn has_wx_section(sections: &[SectionInfo]) -> bool {
    sections.iter().any(|s| {
        s.characteristics & IMAGE_SCN_MEM_WRITE != 0
            && s.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
    })
}

/// Get the printable name of a section header (up to 8 bytes, null-trimmed).
fn section_name_str(name: &[u8; 8]) -> &str {
    let end = name.iter().position(|&b| b == 0).unwrap_or(8);
    std::str::from_utf8(&name[..end]).unwrap_or("")
}

/// Cached PE metadata used to avoid redundant header parsing across
/// multiple sub-keyword evaluations on the same file.
#[repr(C)]
#[derive(Copy, Clone)]
struct SCDetectPeMetadata {
    valid: bool,
    architecture: u16,
    num_sections: u16,
    subsystem: u16,
    characteristics: u16,
    dll_characteristics: u16,
    magic: u16,
    num_imports: u16,
    size_of_image: u32,
    entry_point_rva: u32,
    pe_offset: u32,
    timestamp: u32,
    checksum: u32,
    size_of_headers: u32,
    num_exports: u32,
    has_wx_section: bool,
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
            magic: 0,
            num_imports: 0,
            size_of_image: 0,
            entry_point_rva: 0,
            pe_offset: 0,
            timestamp: 0,
            checksum: 0,
            size_of_headers: 0,
            num_exports: 0,
            has_wx_section: false,
        }
    }
}

// ============================================================================
// Keyword context: parsed options for the windows_pe keyword
// ============================================================================


/// Context structure for the `windows_pe` keyword.
///
/// All options are parsed in Rust by [`SCDetectWindowsPEParse`].
/// The C `FileMatch` callback calls matching logic in Rust.
///
/// Uint filter data is owned by this struct and stored as boxed types.
/// Using `detect_parse_uint::<T>()` directly avoids FFI overhead.
#[repr(C)]
pub struct DetectWindowsPEData {
    architecture: u16,
    pe_type: u16,     // magic filter: 0x10b=PE32, 0x20b=PE32+ (0 = no filter)
    size: *mut DetectUintData<u32>,
    sections: *mut DetectUintData<u16>,
    entry_point: *mut DetectUintData<u32>,
    subsystem: *mut DetectUintData<u16>,
    characteristics: *mut DetectUintData<u16>,
    dll_characteristics: *mut DetectUintData<u16>,
    timestamp: *mut DetectUintData<u32>,
    checksum: *mut DetectUintData<u32>,
    size_of_headers: *mut DetectUintData<u32>,
    num_imports: *mut DetectUintData<u16>,
    num_exports: *mut DetectUintData<u32>,
    import_dlls: Option<Box<Vec<String>>>,
    section_name: Option<Box<String>>,
    export_name: Option<Box<String>>,
    section_wx: bool,
    has_filters: bool,
}

impl Default for DetectWindowsPEData {
    fn default() -> Self {
        Self {
            architecture: 0,
            pe_type: 0,
            size: std::ptr::null_mut(),
            sections: std::ptr::null_mut(),
            entry_point: std::ptr::null_mut(),
            subsystem: std::ptr::null_mut(),
            characteristics: std::ptr::null_mut(),
            dll_characteristics: std::ptr::null_mut(),
            timestamp: std::ptr::null_mut(),
            checksum: std::ptr::null_mut(),
            size_of_headers: std::ptr::null_mut(),
            num_imports: std::ptr::null_mut(),
            num_exports: std::ptr::null_mut(),
            import_dlls: None,
            section_name: None,
            export_name: None,
            section_wx: false,
            has_filters: false,
        }
    }
}

impl Drop for DetectWindowsPEData {
    fn drop(&mut self) {
        unsafe {
            if !self.size.is_null() { let _ = Box::from_raw(self.size); }
            if !self.sections.is_null() { let _ = Box::from_raw(self.sections); }
            if !self.entry_point.is_null() { let _ = Box::from_raw(self.entry_point); }
            if !self.subsystem.is_null() { let _ = Box::from_raw(self.subsystem); }
            if !self.characteristics.is_null() { let _ = Box::from_raw(self.characteristics); }
            if !self.dll_characteristics.is_null() { let _ = Box::from_raw(self.dll_characteristics); }
            if !self.timestamp.is_null() { let _ = Box::from_raw(self.timestamp); }
            if !self.checksum.is_null() { let _ = Box::from_raw(self.checksum); }
            if !self.size_of_headers.is_null() { let _ = Box::from_raw(self.size_of_headers); }
            if !self.num_imports.is_null() { let _ = Box::from_raw(self.num_imports); }
            if !self.num_exports.is_null() { let _ = Box::from_raw(self.num_exports); }
            // import_dlls, section_name, export_name are Option<Box<...>> and drop automatically
        }
    }
}

fn process_executable_option(data: &mut DetectWindowsPEData, key: &str, val: &str) -> Option<()> {
    match key {
        "arch" => {
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
            if let Ok((_, ctx)) = detect_parse_uint::<u16>(val) {
                data.dll_characteristics = Box::into_raw(Box::new(ctx));
            } else {
                return None;
            }
        }
        "timestamp" => {
            if let Ok((_, ctx)) = detect_parse_uint::<u32>(val) {
                data.timestamp = Box::into_raw(Box::new(ctx));
            } else {
                return None;
            }
        }
        "checksum" => {
            if let Ok((_, ctx)) = detect_parse_uint::<u32>(val) {
                data.checksum = Box::into_raw(Box::new(ctx));
            } else {
                return None;
            }
        }
        "size_of_headers" => {
            if let Ok((_, ctx)) = detect_parse_uint::<u32>(val) {
                data.size_of_headers = Box::into_raw(Box::new(ctx));
            } else {
                return None;
            }
        }
        "num_imports" => {
            if let Ok((_, ctx)) = detect_parse_uint::<u16>(val) {
                data.num_imports = Box::into_raw(Box::new(ctx));
            } else {
                return None;
            }
        }
        "num_exports" => {
            if let Ok((_, ctx)) = detect_parse_uint::<u32>(val) {
                data.num_exports = Box::into_raw(Box::new(ctx));
            } else {
                return None;
            }
        }
        "pe_type" => {
            let v = val.trim().to_ascii_lowercase();
            data.pe_type = match v.as_str() {
                "pe32" => 0x10b,
                "pe32+" | "pe32plus" | "pe64" => 0x20b,
                _ => return None,
            };
        }
        "section_name" => {
            data.section_name = Some(Box::new(val.trim().to_lowercase()));
        }
        "export_name" => {
            data.export_name = Some(Box::new(val.trim().to_ascii_lowercase()));
        }
        "section_wx" => {
            data.section_wx = true;
        }
        _ => return None,
    }
    Some(())
}

/// Parse all options from the windows_pe keyword argument string.
///
/// Handles comma-separated `key value` pairs (standard Suricata style).
/// Tokens that do not start with an identifier character are treated as
/// continuations of the previous value, which supports uint range
/// expressions like `size >1000, <5000`.
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

        // A token that starts with a letter or underscore is a new key-value
        // pair: split on the first whitespace to separate key from value.
        if tok.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_') {
            if let Some(space_pos) = tok.find(|c: char| c.is_ascii_whitespace()) {
                // Flush previous key-value pair
                if have_kv {
                    process_executable_option(&mut data, &cur_key, &cur_val)?;
                }
                cur_key = tok[..space_pos].trim().to_ascii_lowercase();
                cur_val = tok[space_pos..].trim().to_string();
                have_kv = true;
                continue;
            }
            // Bare flag keywords (no value required)
            let bare_key = tok.to_ascii_lowercase();
            if bare_key == "section_wx" {
                if have_kv {
                    process_executable_option(&mut data, &cur_key, &cur_val)?;
                }
                process_executable_option(&mut data, &bare_key, "")?;
                cur_key.clear();
                cur_val.clear();
                have_kv = false;
                continue;
            }
            // A bare token containing a dot (e.g. "kernel32.dll") is a
            // DLL import name to match in the PE Import Directory Table.
            if tok.contains('.') {
                if have_kv {
                    process_executable_option(&mut data, &cur_key, &cur_val)?;
                }
                let name = tok.to_ascii_lowercase();
                match &mut data.import_dlls {
                    Some(dlls) => dlls.push(name),
                    None => data.import_dlls = Some(Box::new(vec![name])),
                }
                cur_key.clear();
                cur_val.clear();
                have_kv = false;
                continue;
            }
        }

        // No key-value pair found — treat as continuation of previous value
        // (e.g. "<5000" after "size >1000")
        if !have_kv {
            return None;
        }
        cur_val.push(',');
        cur_val.push_str(tok);
    }

    // Flush final key-value pair
    if have_kv {
        process_executable_option(&mut data, &cur_key, &cur_val)?;
    }

    data.has_filters = data.architecture != 0
        || !data.size.is_null()
        || !data.sections.is_null()
        || !data.entry_point.is_null()
        || !data.subsystem.is_null()
        || !data.characteristics.is_null()
        || !data.dll_characteristics.is_null()
        || data.import_dlls.is_some()
        || data.pe_type != 0
        || !data.timestamp.is_null()
        || !data.checksum.is_null()
        || !data.size_of_headers.is_null()
        || !data.num_imports.is_null()
        || !data.num_exports.is_null()
        || data.section_name.is_some()
        || data.export_name.is_some()
        || data.section_wx;

    Some(data)
}

/// Parse windows_pe keyword options from a C string.
///
/// Follows the bytemath pattern: Rust owns the context struct.
/// C calls this from `DetectWindowsPESetup`, stores the returned pointer,
/// and later frees it with [`SCDetectWindowsPEFree`].
///
/// A NULL `c_arg` means bare `windows_pe;` with no options (default PE
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
/// The `Drop` impl on `DetectWindowsPEData` takes care of freeing any
/// boxed uint filter data (`DetectUintData<u32>`, `DetectUintData<u16>`).
#[no_mangle]
pub unsafe extern "C" fn SCDetectWindowsPEFree(ptr: *mut DetectWindowsPEData) {
    if !ptr.is_null() {
        let _ = Box::from_raw(ptr);
    }
}

/// Log PE metadata
///
/// Uses fixed arrays and stack allocation instead of Vec to avoid heap allocation.
/// Writes a `"executable"` object with fields like machine, sections, subsystem, etc.
/// This is called from `EveFileInfo` in C when the file data starts with "MZ"
/// to enrich fileinfo events with PE-specific metadata.
///
/// Returns Ok(()) if PE metadata was successfully written, or the first JsonError encountered.
/// Write PE metadata fields into an open JSON builder context.
///
/// Called for both raw-buffer parsing and File-cache fallback paths.
fn pe_log_json_fields(
    meta: &SCDetectPeMetadata,
    imports: Option<&[String]>,
    sections: Option<&[SectionInfo]>,
    export_name: Option<&str>,
    js: &mut JsonBuilder,
) -> Result<(), JsonError> {
    js.open_object("executable")?;
    js.set_string("type", "windows_pe")?;

    // Architecture (machine type) - hex value and human-readable name
    // Use static strings for known architectures to avoid format! allocation.
    let (arch_hex, arch_name) = match meta.architecture {
        0x014C => ("0x014c", "x86"),
        0x8664 => ("0x8664", "x86-64"),
        0x01C0 => ("0x01c0", "ARM"),
        0xAA64 => ("0xaa64", "ARM64"),
        _ => ("", "unknown"),
    };
    if arch_hex.is_empty() {
        let s = format!("0x{:04x}", meta.architecture);
        js.set_string("arch", &s)?;
    } else {
        js.set_string("arch", arch_hex)?;
    }
    js.set_string("arch_name", arch_name)?;

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

    // PE characteristics - stack-allocated array (max 4 decoded flags)
    js.set_uint("characteristics", meta.characteristics as u64)?;
    let mut char_traits: [&str; 5] = [""; 5];
    let mut char_count = 0;
    if meta.characteristics & 0x0002 != 0 { char_traits[char_count] = "EXECUTABLE_IMAGE"; char_count += 1; }
    if meta.characteristics & 0x2000 != 0 { char_traits[char_count] = "DLL";              char_count += 1; }
    if meta.characteristics & 0x0020 != 0 { char_traits[char_count] = "LARGE_ADDRESS_AWARE"; char_count += 1; }
    if meta.characteristics & 0x0100 != 0 { char_traits[char_count] = "32BIT_MACHINE";    char_count += 1; }
    if char_count > 0 {
        js.open_array("characteristics_names")?;
        for trait_name in &char_traits[..char_count] {
            js.append_string(trait_name)?;
        }
        js.close()?;
    }

    // DLL characteristics (security features) - stack-allocated array (max 5 possible flags)
    js.set_uint("dll_characteristics", meta.dll_characteristics as u64)?;
    let mut sec_features: [&str; 5] = [""; 5];
    let mut sec_count = 0;
    if meta.dll_characteristics & 0x0020 != 0 { sec_features[sec_count] = "HIGH_ENTROPY_VA"; sec_count += 1; }
    if meta.dll_characteristics & 0x0040 != 0 { sec_features[sec_count] = "DYNAMIC_BASE";    sec_count += 1; } // ASLR
    if meta.dll_characteristics & 0x0100 != 0 { sec_features[sec_count] = "NX_COMPAT";       sec_count += 1; } // DEP/NX
    if meta.dll_characteristics & 0x0400 != 0 { sec_features[sec_count] = "NO_SEH";          sec_count += 1; }
    if meta.dll_characteristics & 0x4000 != 0 { sec_features[sec_count] = "GUARD_CF";        sec_count += 1; } // CFG
    if sec_count > 0 {
        js.open_array("security_features")?;
        for feature in &sec_features[..sec_count] {
            js.append_string(feature)?;
        }
        js.close()?;
    }

    // Entry point and image size
    js.set_uint("entry_point", meta.entry_point_rva as u64)?;
    js.set_uint("size_of_image", meta.size_of_image as u64)?;

    // PE offset (where PE header lives in the file)
    js.set_uint("pe_offset", meta.pe_offset as u64)?;

    // PE type (magic)
    let pe_type_name = match meta.magic {
        0x10b => "PE32",
        0x20b => "PE32+",
        _ => "unknown",
    };
    js.set_string("pe_type", pe_type_name)?;
    js.set_uint("magic", meta.magic as u64)?;

    // Timestamp, checksum, size_of_headers
    js.set_uint("timestamp", meta.timestamp as u64)?;
    js.set_uint("checksum", meta.checksum as u64)?;
    js.set_uint("size_of_headers", meta.size_of_headers as u64)?;

    // Import/export counts
    js.set_uint("num_imports", meta.num_imports as u64)?;
    js.set_uint("num_exports", meta.num_exports as u64)?;

    // W+X section indicator
    js.set_bool("has_wx_section", meta.has_wx_section)?;

    // Export DLL name
    if let Some(name) = export_name {
        js.set_string("export_name", name)?;
    }

    // Imported DLLs (when available from raw file data)
    if let Some(dlls) = imports {
        if !dlls.is_empty() {
            js.open_array("imports")?;
            for dll in dlls {
                js.append_string(dll)?;
            }
            js.close()?;
        }
    }

    // Section details
    if let Some(secs) = sections {
        if !secs.is_empty() {
            js.open_array("sections_detail")?;
            for s in secs {
                js.start_object()?;
                js.set_string("name", section_name_str(&s.name))?;
                js.set_uint("virtual_size", s.virtual_size as u64)?;
                js.set_uint("virtual_address", s.virtual_address as u64)?;
                js.set_uint("raw_data_size", s.raw_data_size as u64)?;
                js.set_uint("characteristics", s.characteristics as u64)?;
                let wx = s.characteristics & IMAGE_SCN_MEM_WRITE != 0
                    && s.characteristics & IMAGE_SCN_MEM_EXECUTE != 0;
                js.set_bool("wx", wx)?;
                js.close()?;
            }
            js.close()?;
        }
    }

    js.close()?; // close "executable" object
    Ok(())
}

/// Log PE metadata as JSON from cached `File` metadata.
///
/// Section details and export name are not available from the cached metadata
/// alone (they require raw file data), so they are omitted in this path.
fn pe_log_json_from_sc_meta(
    meta: &SCDetectPeMetadata, imports: Option<&[String]>, js: &mut JsonBuilder,
) -> Result<(), JsonError> {
    pe_log_json_fields(meta, imports, None, None, js)
}

fn detect_meta_from_file_meta(meta: &SCFilePeMeta) -> SCDetectPeMetadata {
    SCDetectPeMetadata {
        valid: (meta.flags & SC_FILE_PE_META_F_VALID) != 0,
        architecture: meta.architecture,
        num_sections: meta.num_sections,
        subsystem: meta.subsystem,
        characteristics: meta.characteristics,
        dll_characteristics: meta.dll_characteristics,
        magic: meta.magic,
        num_imports: meta.num_imports,
        size_of_image: meta.size_of_image,
        entry_point_rva: meta.entry_point_rva,
        pe_offset: meta.pe_offset,
        timestamp: meta.timestamp,
        checksum: meta.checksum,
        size_of_headers: meta.size_of_headers,
        num_exports: meta.num_exports,
        has_wx_section: meta.has_wx_section != 0,
    }
}

fn file_meta_from_detect_meta(meta: &SCDetectPeMetadata) -> SCFilePeMeta {
    let mut flags = SC_FILE_PE_META_F_PARSED;
    if meta.valid {
        flags |= SC_FILE_PE_META_F_VALID;
    }
    SCFilePeMeta {
        flags,
        architecture: meta.architecture,
        num_sections: meta.num_sections,
        subsystem: meta.subsystem,
        characteristics: meta.characteristics,
        dll_characteristics: meta.dll_characteristics,
        magic: meta.magic,
        num_imports: meta.num_imports,
        size_of_image: meta.size_of_image,
        entry_point_rva: meta.entry_point_rva,
        pe_offset: meta.pe_offset,
        timestamp: meta.timestamp,
        checksum: meta.checksum,
        size_of_headers: meta.size_of_headers,
        num_exports: meta.num_exports,
        has_wx_section: if meta.has_wx_section { 1 } else { 0 },
        padding_: [0; 3],
    }
}

unsafe fn file_meta_get(file: *const File) -> Option<SCDetectPeMetadata> {
    if file.is_null() {
        return None;
    }
    let mut raw: SCFilePeMeta = unsafe { std::mem::zeroed() };
    if !FilePeMetaGet(file, &mut raw) {
        return None;
    }
    if (raw.flags & SC_FILE_PE_META_F_PARSED) == 0 {
        return None;
    }
    Some(detect_meta_from_file_meta(&raw))
}

unsafe fn file_meta_set(file: *mut File, meta: &SCDetectPeMetadata) {
    if file.is_null() {
        return;
    }
    let raw = file_meta_from_detect_meta(meta);
    FilePeMetaSet(file, &raw);
}

/// Helper: build `SCDetectPeMetadata` from `PEMetadata` (avoids repeated field copy).
fn detect_meta_from_pe_meta(m: &PEMetadata) -> SCDetectPeMetadata {
    SCDetectPeMetadata {
        valid: true,
        architecture: m.architecture,
        num_sections: m.num_sections,
        subsystem: m.subsystem,
        characteristics: m.characteristics,
        dll_characteristics: m.dll_characteristics,
        magic: m.magic,
        num_imports: 0,
        size_of_image: m.size_of_image,
        entry_point_rva: m.entry_point_rva,
        pe_offset: m.pe_offset,
        timestamp: m.timestamp,
        checksum: m.checksum,
        size_of_headers: m.size_of_headers,
        num_exports: 0,
        has_wx_section: false,
    }
}

/// Build SCDetectPeMetadata with full supplementary data (sections, imports, exports).
fn detect_meta_full(
    m: &PEMetadata, sections: &[SectionInfo], num_imports: u16, num_exports: u32,
) -> SCDetectPeMetadata {
    let mut meta = detect_meta_from_pe_meta(m);
    meta.has_wx_section = has_wx_section(sections);
    meta.num_imports = num_imports;
    meta.num_exports = num_exports;
    meta
}

// ============================================================================
// Import list caching in the File object
// ============================================================================

/// Retrieve cached import list from File (opaque pointer → `Vec<String>`).
///
/// Returns `None` if no imports have been cached yet.
unsafe fn file_imports_get(file: *const File) -> Option<&'static [String]> {
    if file.is_null() {
        return None;
    }
    let ptr = FilePeImportsGet(file);
    if ptr.is_null() {
        return None;
    }
    let vec = &*(ptr as *const Vec<String>);
    Some(vec.as_slice())
}

/// Store a parsed import list in the File object.
///
/// The `Vec<String>` is heap-allocated and ownership is transferred to the
/// File; it will be freed by `SCFilePeImportsFree` when the File is freed.
unsafe fn file_imports_set(file: *mut File, imports: Vec<String>) {
    if file.is_null() {
        return;
    }
    let boxed = Box::new(imports);
    FilePeImportsSet(file, Box::into_raw(boxed) as *mut std::os::raw::c_void);
}

/// Retrieve or parse+cache the import list for a file.
///
/// If the File already has cached imports, returns a reference to them.
/// Otherwise parses from `file_data`, caches the result, and returns it.
unsafe fn get_pe_imports_by_file<'a>(
    file_ptr: *mut File, file_data: &[u8], pe_offset: usize,
) -> Option<&'a [String]> {
    // Try cache first.
    if let Some(cached) = file_imports_get(file_ptr as *const File) {
        return Some(cached);
    }
    // Parse, cache, and return.
    let imports = parse_pe_imports_with_offset(file_data, pe_offset)?;
    file_imports_set(file_ptr, imports);
    // Re-read from cache to get a stable reference.
    file_imports_get(file_ptr as *const File)
}

/// Free a Rust-allocated `Vec<String>` stored as an opaque pointer in File.
///
/// Called from C's `FileFree` via `SCFilePeImportsFree`.
#[no_mangle]
pub unsafe extern "C" fn SCFilePeImportsFree(ptr: *mut std::os::raw::c_void) {
    if !ptr.is_null() {
        let _ = Box::from_raw(ptr as *mut Vec<String>);
    }
}

/// Cache-aware FFI entry point: log PE metadata as JSON for a given file.
///
/// Checks the File cache first to avoid redundant parsing when detection
/// already populated the cache. Falls back to raw-buffer parsing when the
/// cache is empty and the streaming buffer still starts at offset 0.
///
/// # Safety
/// - `file` must be a valid non-null pointer to the File object
/// - `data` / `data_len` / `offset` come from `StreamingBufferGetData` on the file's sb
/// - `js` must be a valid `JsonBuilder`
#[no_mangle]
pub unsafe extern "C" fn SCPeLogJsonByFile(
    file: *const File,
    data: *const u8,
    data_len: u32,
    offset: u64,
    js: &mut JsonBuilder,
) -> bool {
    // Try File-cached metadata first (detection may have already parsed).
    if let Some(meta) = file_meta_get(file) {
        if meta.valid {
            let cached_imports = file_imports_get(file);
            return pe_log_json_from_sc_meta(&meta, cached_imports, js).is_ok();
        }
        // Parsed but invalid — not a PE.
        return false;
    }

    // Cache miss: parse from raw buffer if it starts at offset 0.
    if offset == 0 && !data.is_null() && data_len >= 64 {
        let file_data = std::slice::from_raw_parts(data, data_len as usize);
        if file_data[0] == b'M' && file_data[1] == b'Z' {
            let pe_meta = parse_pe_metadata(file_data);
            let meta = match pe_meta {
                Some(ref m) => {
                    let sections = parse_section_headers(file_data, m.pe_offset as usize, m.num_sections);
                    let imports = parse_pe_imports_with_offset(file_data, m.pe_offset as usize);
                    let num_imports = imports.as_ref().map_or(0, |v| v.len().min(u16::MAX as usize) as u16);
                    let (_, num_exports) = parse_pe_exports(file_data, m.pe_offset as usize);
                    let dm = detect_meta_full(m, &sections, num_imports, num_exports);
                    if let Some(imp) = imports {
                        file_imports_set(file as *mut File, imp);
                    }
                    dm
                }
                None => SCDetectPeMetadata::default(),
            };
            file_meta_set(file as *mut File, &meta);
            if meta.valid {
                // For the logging path, re-parse sections and export name from raw data
                // so we can include section details in the JSON output.
                if let Some(ref m) = pe_meta {
                    let sections = parse_section_headers(file_data, m.pe_offset as usize, m.num_sections);
                    let (export_name, _) = parse_pe_exports(file_data, m.pe_offset as usize);
                    let cached_imports = file_imports_get(file);
                    return pe_log_json_fields(
                        &meta, cached_imports, Some(&sections), export_name.as_deref(), js,
                    ).is_ok();
                }
                let cached_imports = file_imports_get(file);
                return pe_log_json_from_sc_meta(&meta, cached_imports, js).is_ok();
            }
            return true;
        }
    }
    false
}

/// Retrieve PE metadata for a file, using cached result if available.
///
/// # Safety
/// - `file_ptr` must be a valid non-null pointer to a File object
/// - `data` must point to `data_len` valid bytes from the file
/// - Caller must ensure `file_ptr` remains valid for the duration of this call
unsafe fn get_pe_metadata_by_file(
    file_ptr: *mut File, data: *const u8, data_len: u32,
) -> SCDetectPeMetadata {
    if file_ptr.is_null() || data.is_null() || data_len < 64 {
        return SCDetectPeMetadata::default();
    }

    // Try to get from File cache first.
    if let Some(meta) = file_meta_get(file_ptr as *const File) {
        return meta;
    }

    // Not cached, parse and store in File.
    let file_data = std::slice::from_raw_parts(data, data_len as usize);
    let meta = match parse_pe_metadata(file_data) {
        Some(m) => {
            let sections = parse_section_headers(file_data, m.pe_offset as usize, m.num_sections);
            let imports = parse_pe_imports_with_offset(file_data, m.pe_offset as usize);
            let num_imports = imports.as_ref().map_or(0, |v| v.len().min(u16::MAX as usize) as u16);
            let (_, num_exports) = parse_pe_exports(file_data, m.pe_offset as usize);
            let dm = detect_meta_full(&m, &sections, num_imports, num_exports);
            // Cache imports in File for later use by import matching / logging.
            if let Some(imp) = imports {
                file_imports_set(file_ptr, imp);
            }
            dm
        }
        None => SCDetectPeMetadata::default(),
    };

    file_meta_set(file_ptr, &meta);

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
unsafe fn pe_match(
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

    if !ctx.size.is_null()
        && !detect_match_uint(&*ctx.size, meta.size_of_image)
    {
        return 0;
    }

    if !ctx.sections.is_null()
        && !detect_match_uint(&*ctx.sections, meta.num_sections)
    {
        return 0;
    }

    if !ctx.entry_point.is_null()
        && !detect_match_uint(&*ctx.entry_point, meta.entry_point_rva)
    {
        return 0;
    }

    if !ctx.subsystem.is_null()
        && !detect_match_uint(&*ctx.subsystem, meta.subsystem)
    {
        return 0;
    }

    if !ctx.characteristics.is_null()
        && !detect_match_uint(&*ctx.characteristics, meta.characteristics)
    {
        return 0;
    }

    if !ctx.dll_characteristics.is_null()
        && !detect_match_uint(&*ctx.dll_characteristics, meta.dll_characteristics)
    {
        return 0;
    }

    // PE type (magic) filter
    if ctx.pe_type != 0 && meta.magic != ctx.pe_type {
        return 0;
    }

    if !ctx.timestamp.is_null()
        && !detect_match_uint(&*ctx.timestamp, meta.timestamp)
    {
        return 0;
    }

    if !ctx.checksum.is_null()
        && !detect_match_uint(&*ctx.checksum, meta.checksum)
    {
        return 0;
    }

    if !ctx.size_of_headers.is_null()
        && !detect_match_uint(&*ctx.size_of_headers, meta.size_of_headers)
    {
        return 0;
    }

    if !ctx.num_imports.is_null()
        && !detect_match_uint(&*ctx.num_imports, meta.num_imports)
    {
        return 0;
    }

    if !ctx.num_exports.is_null()
        && !detect_match_uint(&*ctx.num_exports, meta.num_exports)
    {
        return 0;
    }

    // W+X section filter
    if ctx.section_wx && !meta.has_wx_section {
        return 0;
    }

    1
}

/// Combined file match operation: retrieve PE metadata and check if it matches.
///
/// This combines two operations into a single FFI call for efficiency:
/// 1. Retrieve PE metadata from file data (cached in `File`)
/// 2. Check if metadata matches the filter criteria
/// 3. Check import filters against cached import list
///
/// Imports are parsed once per file and cached in the `File` object so
/// that multiple rules with import filters share the same parsed result.
/// For small needle counts (≤ 4 DLLs), a linear scan is used instead of
/// building a `HashSet`, which avoids heap allocation and hashing overhead.
///
/// Returns 1 if metadata is valid and all criteria match, 0 otherwise.
///
/// # Safety
/// - `file_ptr` must be a valid non-null pointer to a File object
/// - `data` must point to `data_len` valid bytes from the file
/// - `ctx` must point to a valid `DetectWindowsPEData` struct
/// - All pointers in `ctx` must be valid or NULL
#[no_mangle]
pub unsafe extern "C" fn SCDetectWindowsPEFileMatch(
    file_ptr: *mut File, data: *const u8, data_len: u32,
    ctx: *const DetectWindowsPEData,
) -> i32 {
    if file_ptr.is_null() || data.is_null() || data_len < 64 || ctx.is_null() {
        return 0;
    }

    let ctx_ref = &*ctx;

    // No filters — just validate PE signature without full header parse.
    // Full metadata will be parsed later by the logging path if needed.
    if !ctx_ref.has_filters {
        let file_data = std::slice::from_raw_parts(data, data_len as usize);
        return if pe_validate(file_data).is_some() { 1 } else { 0 };
    }

    // Has filters — need full metadata (cached by file pointer).
    let meta = get_pe_metadata_by_file(file_ptr, data, data_len);

    // Check if metadata matches criteria
    let result = pe_match(&meta, ctx);
    if result == 0 {
        return 0;
    }

    let file_data = std::slice::from_raw_parts(data, data_len as usize);

    // Check import filters if present, using cached imports from File.
    if let Some(ref needles) = ctx_ref.import_dlls {
        let imports = match get_pe_imports_by_file(
            file_ptr, file_data, meta.pe_offset as usize,
        ) {
            Some(dlls) => dlls,
            None => return 0,
        };

        // For small needle counts, linear search is faster than HashSet.
        if needles.len() <= 4 {
            for needle in needles.iter() {
                if !imports.iter().any(|dll| dll == needle) {
                    return 0;
                }
            }
        } else {
            let import_set: HashSet<&str> =
                imports.iter().map(|s| s.as_str()).collect();
            for needle in needles.iter() {
                if !import_set.contains(needle.as_str()) {
                    return 0;
                }
            }
        }
    }

    // Section name filter: check if any section matches the requested name.
    if let Some(ref needle) = ctx_ref.section_name {
        let sections = parse_section_headers(file_data, meta.pe_offset as usize, meta.num_sections);
        let found = sections.iter().any(|s| section_name_str(&s.name).eq_ignore_ascii_case(needle.as_str()));
        if !found {
            return 0;
        }
    }

    // Export name filter: check if the PE's export DLL name matches.
    if let Some(ref needle) = ctx_ref.export_name {
        let (export_name, _) = parse_pe_exports(file_data, meta.pe_offset as usize);
        match export_name {
            Some(ref name) if name == needle.as_str() => {}
            _ => return 0,
        }
    }

    1
}

// ============================================================================
// Keyword registration
// ============================================================================

static mut G_WINDOWS_PE_KW_ID: u16 = 0;
static mut G_WINDOWS_PE_FILE_LIST_ID: c_int = 0;

unsafe extern "C" fn windows_pe_file_match(
    _det_ctx: *mut DetectEngineThreadCtx,
    _flow: *mut Flow,
    _flags: u8,
    file: *mut File,
    _sig: *const Signature,
    ctx: *const SigMatchCtx,
) -> c_int {
    let pe_ctx = ctx as *const DetectWindowsPEData;
    let mut data_len: u32 = 0;
    let mut offset: u64 = 0;
    let data = SCFileGetData(file as *const File, &mut data_len, &mut offset);
    if data.is_null() || offset != 0 || data_len < 64 {
        return 0;
    }
    SCDetectWindowsPEFileMatch(file, data, data_len, pe_ctx)
}

unsafe extern "C" fn windows_pe_setup(
    de_ctx: *mut DetectEngineCtx,
    s: *mut Signature,
    raw: *const c_char,
) -> c_int {
    let data = SCDetectWindowsPEParse(raw);
    if data.is_null() {
        return -1;
    }
    if SCSigMatchAppendSMToList(
        de_ctx,
        s,
        G_WINDOWS_PE_KW_ID,
        data as *mut SigMatchCtx,
        G_WINDOWS_PE_FILE_LIST_ID,
    )
    .is_null()
    {
        SCDetectWindowsPEFree(data);
        return -1;
    }
    SCDetectSignatureSetFileInspect(s);
    0
}

unsafe extern "C" fn windows_pe_free(
    _de_ctx: *mut DetectEngineCtx,
    ptr: *mut std::os::raw::c_void,
) {
    if !ptr.is_null() {
        SCDetectWindowsPEFree(ptr as *mut DetectWindowsPEData);
    }
}

/// Register the `windows_pe` keyword and its file-match callback.
///
/// Called from `DetectWindowsPERegister` in detect-windows-pe.c during
/// engine initialisation.
#[no_mangle]
pub unsafe extern "C" fn SCDetectWindowsPERegister() {
    G_WINDOWS_PE_FILE_LIST_ID = SCDetectHelperGetFilesBufferId();

    let kw = SCSigTableFileLiteElmt {
        name: b"windows_pe\0".as_ptr() as *const c_char,
        desc: b"match Windows PE file format and metadata (arch, size, sections, entry_point, subsystem, characteristics, dll_characteristics, imported DLL names)\0".as_ptr() as *const c_char,
        url: b"/rules/file-keywords.html#windows_pe\0".as_ptr() as *const c_char,
        FileMatch: Some(windows_pe_file_match),
        Setup: Some(windows_pe_setup),
        Free: Some(windows_pe_free),
        flags: SIGMATCH_OPTIONAL_OPT,
    };
    G_WINDOWS_PE_KW_ID = SCDetectHelperFileKeywordRegister(&kw);
    SCDetectWindowsPEEnablePrefilter(G_WINDOWS_PE_KW_ID, G_WINDOWS_PE_FILE_LIST_ID);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse the list of imported DLL names from a PE file's Import Directory.
    fn parse_pe_imports(data: &[u8]) -> Option<Vec<String>> {
        parse_pe_imports_with_offset(data, pe_validate(data)?)
    }

    /// Parse raw PE bytes and log all metadata as JSON (test helper).
    fn pe_log_json(data: &[u8], js: &mut JsonBuilder) -> Result<(), JsonError> {
        let meta = match parse_pe_metadata(data) {
            Some(m) => m,
            None => return Ok(()),
        };
        let imports = parse_pe_imports(data);
        let sections = parse_section_headers(data, meta.pe_offset as usize, meta.num_sections);
        let num_imports = imports.as_ref().map_or(0, |v| v.len().min(u16::MAX as usize) as u16);
        let (export_name, num_exports) = parse_pe_exports(data, meta.pe_offset as usize);
        let wx = has_wx_section(&sections);
        let log_meta = SCDetectPeMetadata {
            valid: true,
            architecture: meta.architecture,
            num_sections: meta.num_sections,
            subsystem: meta.subsystem,
            characteristics: meta.characteristics,
            dll_characteristics: meta.dll_characteristics,
            magic: meta.magic,
            num_imports,
            size_of_image: meta.size_of_image,
            entry_point_rva: meta.entry_point_rva,
            pe_offset: meta.pe_offset,
            timestamp: meta.timestamp,
            checksum: meta.checksum,
            size_of_headers: meta.size_of_headers,
            num_exports,
            has_wx_section: wx,
        };
        pe_log_json_fields(
            &log_meta, imports.as_deref(), Some(&sections), export_name.as_deref(), js,
        )
    }
    use std::collections::HashSet;

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

        assert!(pe_validate(&buf).is_some());
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

        assert!(pe_validate(&buf).is_some());
    }

    #[test]
    fn test_pe_validate_no_mz() {
        let mut buf = vec![0u8; 100];
        buf[0] = b'Z';
        buf[1] = b'M'; // Wrong order

        let pe_offset = 64u32;
        buf[60..64].copy_from_slice(&pe_offset.to_le_bytes());

        buf[64..68].copy_from_slice(b"PE\0\0");

        assert!(pe_validate(&buf).is_none());
    }

    #[test]
    fn test_pe_validate_no_pe_signature() {
        let mut buf = vec![0u8; 100];

        buf[0..2].copy_from_slice(b"MZ");

        let pe_offset = 64u32;
        buf[60..64].copy_from_slice(&pe_offset.to_le_bytes());

        buf[64..68].copy_from_slice(b"XX\0\0"); // Wrong signature

        assert!(pe_validate(&buf).is_none());
    }

    #[test]
    fn test_pe_validate_invalid_pe_offset() {
        let mut buf = vec![0u8; 100];

        buf[0..2].copy_from_slice(b"MZ");

        // PE offset beyond reasonable range
        let pe_offset = 0x20000u32;
        buf[60..64].copy_from_slice(&pe_offset.to_le_bytes());

        assert!(pe_validate(&buf).is_none());
    }

    #[test]
    fn test_pe_validate_pe_offset_past_eof() {
        let mut buf = vec![0u8; 100];

        buf[0..2].copy_from_slice(b"MZ");

        // PE offset beyond buffer size
        let pe_offset = 200u32;
        buf[60..64].copy_from_slice(&pe_offset.to_le_bytes());

        assert!(pe_validate(&buf).is_none());
    }

    #[test]
    fn test_pe_validate_too_small() {
        let buf = vec![0u8; 63]; // Less than 64 bytes
        assert!(pe_validate(&buf).is_none());
    }

    #[test]
    fn test_pe_validate_exact_boundary() {
        let mut buf = vec![0u8; 68]; // Exactly 68 bytes (64 + 4 for signature)

        buf[0..2].copy_from_slice(b"MZ");

        let pe_offset = 64u32;
        buf[60..64].copy_from_slice(&pe_offset.to_le_bytes());

        buf[64..68].copy_from_slice(b"PE\0\0");

        assert!(pe_validate(&buf).is_some());
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

    #[test]
    fn test_pe_log_json_type_field() {
        // Build a minimal valid PE buffer that pe_log_json can parse.
        let mut buf = vec![0u8; 300];

        // DOS header: MZ magic
        buf[0..2].copy_from_slice(b"MZ");
        // e_lfanew = 64 (PE header at offset 64)
        let pe_offset = 64u32;
        buf[60..64].copy_from_slice(&pe_offset.to_le_bytes());

        // PE signature at offset 64
        buf[64..68].copy_from_slice(b"PE\0\0");

        // COFF header: machine = 0x014C (x86), num_sections = 1
        buf[68..70].copy_from_slice(&0x014Cu16.to_le_bytes());
        buf[70..72].copy_from_slice(&0x0001u16.to_le_bytes());

        // Run pe_log_json and capture output
        let mut js = JsonBuilder::try_new_object().expect("JsonBuilder::try_new_object failed");
        pe_log_json(&buf, &mut js).expect("pe_log_json failed");
        js.close().expect("close failed");
        let output = unsafe {
            let ptr = crate::jsonbuilder::SCJbPtr(&mut js);
            let len = crate::jsonbuilder::SCJbLen(&js);
            std::str::from_utf8(std::slice::from_raw_parts(ptr, len)).unwrap().to_string()
        };

        // Verify the `type` field is present and set to "windows_pe"
        assert!(
            output.contains("\"type\":\"windows_pe\""),
            "Expected '\"type\":\"windows_pe\"' in JSON output, got: {}",
            output
        );
    }

    /// Helper: build a minimal PE32 buffer with an import table that imports
    /// the given list of DLL names.  The buffer layout is:
    ///
    ///   0x000  DOS header (64 bytes, MZ magic, e_lfanew = 0x40)
    ///   0x040  PE signature + COFF header (24 bytes)
    ///   0x058  PE32 Optional header (0x60 = 96 bytes standard fields)
    ///          • Magic = 0x10b (PE32)
    ///          • NumberOfRvaAndSizes = 16 at +0x5C
    ///          • Import Directory RVA/Size at data dir index 1
    ///   0x0B8  Data directories (16 × 8 = 128 bytes)
    ///   0x138  Section headers (1 section, 40 bytes)
    ///          • VirtualAddress = 0x1000, VirtualSize = 0x2000
    ///          • PointerToRawData = 0x200, SizeOfRawData = 0x2000
    ///   0x200  Raw section data
    ///          • Import Directory entries at section-relative offset 0
    ///          • DLL name strings placed after the entries
    fn build_pe_with_imports(dll_names: &[&str]) -> Vec<u8> {
        let mut buf = vec![0u8; 0x2200]; // plenty of room

        // DOS header
        buf[0..2].copy_from_slice(b"MZ");
        let pe_offset: u32 = 0x40;
        buf[60..64].copy_from_slice(&pe_offset.to_le_bytes());

        // PE signature
        buf[0x40..0x44].copy_from_slice(b"PE\0\0");

        // COFF header
        buf[0x44..0x46].copy_from_slice(&0x014Cu16.to_le_bytes()); // Machine: x86
        buf[0x46..0x48].copy_from_slice(&1u16.to_le_bytes());      // NumberOfSections
        // SizeOfOptionalHeader: 96 standard + 128 data dirs = 224 = 0xE0
        buf[0x54..0x56].copy_from_slice(&0x00E0u16.to_le_bytes());
        buf[0x56..0x58].copy_from_slice(&0x0102u16.to_le_bytes()); // Characteristics

        // Optional header
        let opt = 0x58usize; // pe_offset + 24
        buf[opt..opt + 2].copy_from_slice(&0x010bu16.to_le_bytes()); // Magic: PE32

        // NumberOfRvaAndSizes at opt + 0x5C
        buf[opt + 0x5C..opt + 0x60].copy_from_slice(&16u32.to_le_bytes());

        // Data directory index 1 = Import Directory (each entry 8 bytes, index 1 starts at opt+0x60+8)
        let import_dd = opt + 0x60 + 8;
        // Import table lives at the start of our section: RVA = 0x1000
        let import_rva: u32 = 0x1000;
        let num_entries = dll_names.len();
        let import_size: u32 = ((num_entries + 1) * 20) as u32; // +1 for null terminator entry
        buf[import_dd..import_dd + 4].copy_from_slice(&import_rva.to_le_bytes());
        buf[import_dd + 4..import_dd + 8].copy_from_slice(&import_size.to_le_bytes());

        // Section header at 0x138 (opt + 0xE0)
        let sh = opt + 0xE0;
        buf[sh..sh + 8].copy_from_slice(b".idata\0\0");
        buf[sh + 8..sh + 12].copy_from_slice(&0x2000u32.to_le_bytes());   // VirtualSize
        buf[sh + 12..sh + 16].copy_from_slice(&0x1000u32.to_le_bytes());  // VirtualAddress
        buf[sh + 16..sh + 20].copy_from_slice(&0x2000u32.to_le_bytes());  // SizeOfRawData
        buf[sh + 20..sh + 24].copy_from_slice(&0x0200u32.to_le_bytes());  // PointerToRawData

        // Section raw data starts at file offset 0x200.
        // Import directory entries at the beginning, names follow after.
        let raw_base = 0x200usize;
        let names_start_rva = import_rva + import_size; // right after entries
        let mut name_cursor = (import_size) as usize; // section-relative offset for names

        for (i, dll) in dll_names.iter().enumerate() {
            let ent = raw_base + i * 20;
            // Bytes 12..16 = Name RVA
            let name_rva = names_start_rva + (name_cursor - import_size as usize) as u32;
            buf[ent + 12..ent + 16].copy_from_slice(&name_rva.to_le_bytes());

            // Write the DLL name string at the computed offset
            let name_file_off = raw_base + name_cursor;
            buf[name_file_off..name_file_off + dll.len()].copy_from_slice(dll.as_bytes());
            buf[name_file_off + dll.len()] = 0; // null terminator
            name_cursor += dll.len() + 1;
        }
        // The null terminator entry (all zeros) is already present since buf is zero-initialized.

        buf
    }

    #[test]
    fn test_parse_pe_imports_basic() {
        let buf = build_pe_with_imports(&["KERNEL32.dll", "USER32.dll", "WS2_32.dll"]);
        let imports = parse_pe_imports(&buf).expect("should parse imports");
        assert_eq!(imports.len(), 3);
        assert!(imports.contains(&"kernel32.dll".to_string()));
        assert!(imports.contains(&"user32.dll".to_string()));
        assert!(imports.contains(&"ws2_32.dll".to_string()));
    }

    #[test]
    fn test_parse_pe_imports_empty() {
        // Build a PE with import directory RVA=0 (no imports)
        let mut buf = vec![0u8; 0x400];
        buf[0..2].copy_from_slice(b"MZ");
        buf[60..64].copy_from_slice(&0x40u32.to_le_bytes());
        buf[0x40..0x44].copy_from_slice(b"PE\0\0");
        buf[0x44..0x46].copy_from_slice(&0x014Cu16.to_le_bytes());
        buf[0x46..0x48].copy_from_slice(&1u16.to_le_bytes());
        buf[0x54..0x56].copy_from_slice(&0x00E0u16.to_le_bytes());
        let opt = 0x58usize;
        buf[opt..opt + 2].copy_from_slice(&0x010bu16.to_le_bytes());
        buf[opt + 0x5C..opt + 0x60].copy_from_slice(&16u32.to_le_bytes());
        // Import dir RVA = 0 → no imports
        let imports = parse_pe_imports(&buf).expect("should return empty vec");
        assert!(imports.is_empty());
    }

    #[test]
    fn test_parse_pe_imports_case_insensitive() {
        let buf = build_pe_with_imports(&["Kernel32.DLL"]);
        let imports = parse_pe_imports(&buf).unwrap();
        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0], "kernel32.dll"); // lowercased
    }

    #[test]
    fn test_parse_pe_imports_not_pe() {
        let buf = vec![0u8; 100];
        assert!(parse_pe_imports(&buf).is_none());
    }

    #[test]
    fn test_rva_to_offset_basic() {
        let sections = vec![SectionInfo {
            name: [0; 8],
            virtual_address: 0x1000,
            virtual_size: 0x2000,
            raw_data_offset: 0x400,
            raw_data_size: 0x2000,
            characteristics: 0,
        }];
        assert_eq!(rva_to_offset(0x1000, &sections), Some(0x400));
        assert_eq!(rva_to_offset(0x1100, &sections), Some(0x500));
        assert_eq!(rva_to_offset(0x0FFF, &sections), None); // before section
        assert_eq!(rva_to_offset(0x3000, &sections), None); // after section
    }

    #[test]
    fn test_parse_option_import_bare() {
        // Bare DLL name (new syntax)
        let data = parse_executable_options("kernel32.dll").unwrap();
        let dlls = data.import_dlls.as_ref().unwrap();
        assert_eq!(dlls.as_slice(), &["kernel32.dll"]);
    }

    #[test]
    fn test_parse_option_import_bare_mixed_case() {
        let data = parse_executable_options("WS2_32.DLL").unwrap();
        let dlls = data.import_dlls.as_ref().unwrap();
        assert_eq!(dlls.as_slice(), &["ws2_32.dll"]); // lowercased
    }

    #[test]
    fn test_parse_option_import_bare_combined() {
        // Bare DLL name combined with other options
        let data = parse_executable_options("arch x86, ws2_32.dll").unwrap();
        let dlls = data.import_dlls.as_ref().unwrap();
        assert_eq!(dlls.as_slice(), &["ws2_32.dll"]);
    }

    #[test]
    fn test_parse_option_import_multi_bare() {
        // Multiple DLL names comma-separated
        let data = parse_executable_options("ws2_32.dll, wininet.dll, kernel32.dll").unwrap();
        let dlls = data.import_dlls.as_ref().unwrap();
        assert_eq!(dlls.len(), 3);
        assert!(dlls.contains(&"ws2_32.dll".to_string()));
        assert!(dlls.contains(&"wininet.dll".to_string()));
        assert!(dlls.contains(&"kernel32.dll".to_string()));
    }

    #[test]
    fn test_parse_option_import_multi_with_options() {
        // Multiple DLLs mixed with other keyword options
        let data = parse_executable_options("arch x86, ws2_32.dll, wininet.dll").unwrap();
        assert_eq!(data.architecture, 0x014C);
        let dlls = data.import_dlls.as_ref().unwrap();
        assert_eq!(dlls.len(), 2);
        assert!(dlls.contains(&"ws2_32.dll".to_string()));
        assert!(dlls.contains(&"wininet.dll".to_string()));
    }

    #[test]
    fn test_parse_option_import_prefix_rejected() {
        // The "import" prefix is no longer supported — bare DLL names only.
        assert!(parse_executable_options("import kernel32.dll").is_none());
    }

    #[test]
    fn test_pe_log_json_includes_imports() {
        let buf = build_pe_with_imports(&["KERNEL32.dll", "ADVAPI32.dll"]);
        let mut js = JsonBuilder::try_new_object().expect("JsonBuilder::try_new_object failed");
        pe_log_json(&buf, &mut js).expect("pe_log_json failed");
        js.close().expect("close failed");
        let output = unsafe {
            let ptr = crate::jsonbuilder::SCJbPtr(&mut js);
            let len = crate::jsonbuilder::SCJbLen(&js);
            std::str::from_utf8(std::slice::from_raw_parts(ptr, len)).unwrap().to_string()
        };
        assert!(
            output.contains("\"imports\""),
            "Expected 'imports' array in JSON output, got: {}",
            output
        );
        assert!(
            output.contains("kernel32.dll"),
            "Expected 'kernel32.dll' in imports, got: {}",
            output
        );
        assert!(
            output.contains("advapi32.dll"),
            "Expected 'advapi32.dll' in imports, got: {}",
            output
        );
    }

    // ================================================================
    // PE32+ (64-bit) import parsing tests
    // ================================================================

    /// Build a PE32+ (x86_64) binary with the given import DLL names.
    fn build_pe32plus_with_imports(dll_names: &[&str]) -> Vec<u8> {
        let mut buf = vec![0u8; 0x2200];

        // DOS header
        buf[0..2].copy_from_slice(b"MZ");
        let pe_offset: u32 = 0x40;
        buf[60..64].copy_from_slice(&pe_offset.to_le_bytes());

        // PE signature
        buf[0x40..0x44].copy_from_slice(b"PE\0\0");

        // COFF header
        buf[0x44..0x46].copy_from_slice(&0x8664u16.to_le_bytes()); // Machine: x86_64
        buf[0x46..0x48].copy_from_slice(&1u16.to_le_bytes());      // NumberOfSections
        // SizeOfOptionalHeader: 112 standard + 128 data dirs = 240 = 0xF0
        buf[0x54..0x56].copy_from_slice(&0x00F0u16.to_le_bytes());
        buf[0x56..0x58].copy_from_slice(&0x0022u16.to_le_bytes()); // Characteristics

        // Optional header
        let opt = 0x58usize;
        buf[opt..opt + 2].copy_from_slice(&0x020bu16.to_le_bytes()); // Magic: PE32+

        // NumberOfRvaAndSizes at opt + 0x6C (PE32+)
        buf[opt + 0x6C..opt + 0x70].copy_from_slice(&16u32.to_le_bytes());

        // Import directory data directory at opt + 0x70 + 8 (index 1)
        let import_dd = opt + 0x70 + 8;
        let import_rva: u32 = 0x1000;
        let num_entries = dll_names.len();
        let import_size: u32 = ((num_entries + 1) * 20) as u32;
        buf[import_dd..import_dd + 4].copy_from_slice(&import_rva.to_le_bytes());
        buf[import_dd + 4..import_dd + 8].copy_from_slice(&import_size.to_le_bytes());

        // Section header at opt + 0xF0
        let sh = opt + 0xF0;
        buf[sh..sh + 8].copy_from_slice(b".idata\0\0");
        buf[sh + 8..sh + 12].copy_from_slice(&0x2000u32.to_le_bytes());
        buf[sh + 12..sh + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[sh + 16..sh + 20].copy_from_slice(&0x2000u32.to_le_bytes());
        buf[sh + 20..sh + 24].copy_from_slice(&0x0200u32.to_le_bytes());

        let raw_base = 0x200usize;
        let names_start_rva = import_rva + import_size;
        let mut name_cursor = import_size as usize;

        for (i, dll) in dll_names.iter().enumerate() {
            let ent = raw_base + i * 20;
            let name_rva = names_start_rva + (name_cursor - import_size as usize) as u32;
            buf[ent + 12..ent + 16].copy_from_slice(&name_rva.to_le_bytes());

            let name_file_off = raw_base + name_cursor;
            buf[name_file_off..name_file_off + dll.len()].copy_from_slice(dll.as_bytes());
            buf[name_file_off + dll.len()] = 0;
            name_cursor += dll.len() + 1;
        }

        buf
    }

    #[test]
    fn test_parse_pe_imports_pe32plus() {
        let buf = build_pe32plus_with_imports(&["KERNEL32.dll", "ntdll.dll"]);
        let imports = parse_pe_imports(&buf).expect("PE32+ imports should parse");
        assert_eq!(imports.len(), 2);
        assert!(imports.contains(&"kernel32.dll".to_string()));
        assert!(imports.contains(&"ntdll.dll".to_string()));
    }

    #[test]
    fn test_parse_pe_imports_pe32plus_single() {
        let buf = build_pe32plus_with_imports(&["VCRUNTIME140.dll"]);
        let imports = parse_pe_imports(&buf).expect("single PE32+ import");
        assert_eq!(imports, vec!["vcruntime140.dll"]);
    }

    #[test]
    fn test_parse_pe_imports_pe32plus_many() {
        // 10 DLLs in a PE32+ binary
        let names: Vec<&str> = vec![
            "KERNEL32.dll", "ntdll.dll", "USER32.dll", "GDI32.dll",
            "ADVAPI32.dll", "SHELL32.dll", "ole32.dll", "OLEAUT32.dll",
            "WS2_32.dll", "WININET.dll",
        ];
        let buf = build_pe32plus_with_imports(&names);
        let imports = parse_pe_imports(&buf).expect("many PE32+ imports");
        assert_eq!(imports.len(), 10);
        assert!(imports.contains(&"kernel32.dll".to_string()));
        assert!(imports.contains(&"wininet.dll".to_string()));
        assert!(imports.contains(&"oleaut32.dll".to_string()));
    }

    // ================================================================
    // Single-import and DLL name edge cases
    // ================================================================

    #[test]
    fn test_parse_pe_imports_single_dll() {
        let buf = build_pe_with_imports(&["msvcrt.dll"]);
        let imports = parse_pe_imports(&buf).unwrap();
        assert_eq!(imports, vec!["msvcrt.dll"]);
    }

    #[test]
    fn test_parse_pe_imports_duplicate_dlls() {
        // A PE with the same DLL listed twice (unusual, but valid per format)
        let buf = build_pe_with_imports(&["KERNEL32.dll", "KERNEL32.dll"]);
        let imports = parse_pe_imports(&buf).unwrap();
        assert_eq!(imports.len(), 2);
        assert!(imports.iter().all(|d| d == "kernel32.dll"));
    }

    #[test]
    fn test_parse_pe_imports_long_dll_name() {
        // DLL name near the 260-char max
        let long_name = format!("{}.dll", "A".repeat(250));
        let buf = build_pe_with_imports(&[&long_name]);
        let imports = parse_pe_imports(&buf).unwrap();
        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0], long_name.to_ascii_lowercase());
    }

    // ================================================================
    // Invalid / truncated PE import table scenarios
    // ================================================================

    #[test]
    fn test_parse_pe_imports_bad_magic() {
        // Valid MZ+PE signature, but bogus optional header magic
        let mut buf = build_pe_with_imports(&["KERNEL32.dll"]);
        buf[0x58..0x5A].copy_from_slice(&0xFFFFu16.to_le_bytes()); // corrupt magic
        assert!(parse_pe_imports(&buf).is_none());
    }

    #[test]
    fn test_parse_pe_imports_import_size_zero() {
        // import_rva is nonzero but import_size is zero → no imports
        let mut buf = build_pe_with_imports(&["KERNEL32.dll"]);
        // Import DD size field: opt(0x58) + 0x60 + 8 + 4 = 0xC4
        let import_dd_size = 0x58 + 0x60 + 8 + 4;
        buf[import_dd_size..import_dd_size + 4].copy_from_slice(&0u32.to_le_bytes());
        let imports = parse_pe_imports(&buf).unwrap();
        assert!(imports.is_empty());
    }

    #[test]
    fn test_parse_pe_imports_num_rva_too_small() {
        // NumberOfRvaAndSizes < 2 → no import directory accessible
        let mut buf = build_pe_with_imports(&["KERNEL32.dll"]);
        // NumberOfRvaAndSizes at opt + 0x5C = 0x58 + 0x5C = 0xB4
        buf[0xB4..0xB8].copy_from_slice(&1u32.to_le_bytes());
        assert!(parse_pe_imports(&buf).is_none());
    }

    #[test]
    fn test_parse_pe_imports_truncated_at_entries() {
        // Truncate the file so import directory entries are partially present
        let buf = build_pe_with_imports(&["KERNEL32.dll", "USER32.dll"]);
        // Import entries start at file offset 0x200; truncate in the middle
        let truncated = buf[..0x210].to_vec(); // only 16 bytes of first entry (need 20)
        // rva_to_offset will resolve, but entry will be cut short → loop breaks
        let imports = parse_pe_imports(&truncated);
        // May return Some with 0 entries or None depending on section bounds
        if let Some(dlls) = imports {
            // Should have parsed 0 entries since first entry is incomplete
            assert!(dlls.is_empty());
        }
    }

    #[test]
    fn test_parse_pe_imports_name_rva_unresolvable() {
        // Set a DLL's Name RVA to a value outside any section
        let mut buf = build_pe_with_imports(&["KERNEL32.dll", "USER32.dll"]);
        // First entry Name RVA at file offset 0x200 + 12
        // Point it to an RVA that doesn't map to any section
        buf[0x200 + 12..0x200 + 16].copy_from_slice(&0xFFFF0000u32.to_le_bytes());
        let imports = parse_pe_imports(&buf).unwrap();
        // First entry skipped (bad RVA), second entry still parsed
        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0], "user32.dll");
    }

    // ================================================================
    // rva_to_offset with multiple sections
    // ================================================================

    #[test]
    fn test_rva_to_offset_multiple_sections() {
        let sections = vec![
            SectionInfo {
                name: [0; 8],
                virtual_address: 0x1000,
                virtual_size: 0x1000,
                raw_data_offset: 0x400,
                raw_data_size: 0x1000,
                characteristics: 0,
            },
            SectionInfo {
                name: [0; 8],
                virtual_address: 0x2000,
                virtual_size: 0x2000,
                raw_data_offset: 0x1400,
                raw_data_size: 0x2000,
                characteristics: 0,
            },
            SectionInfo {
                name: [0; 8],
                virtual_address: 0x5000,
                virtual_size: 0x1000,
                raw_data_offset: 0x3400,
                raw_data_size: 0x800,
                characteristics: 0,
            },
        ];
        // First section
        assert_eq!(rva_to_offset(0x1000, &sections), Some(0x400));
        assert_eq!(rva_to_offset(0x1FFF, &sections), Some(0x13FF));
        // Second section
        assert_eq!(rva_to_offset(0x2000, &sections), Some(0x1400));
        assert_eq!(rva_to_offset(0x2500, &sections), Some(0x1900));
        // Third section
        assert_eq!(rva_to_offset(0x5000, &sections), Some(0x3400));
        // Third section — delta exceeds raw_data_size (0x800)
        assert_eq!(rva_to_offset(0x5900, &sections), None);
        // Gap between sections
        assert_eq!(rva_to_offset(0x4000, &sections), None);
        // Before all sections
        assert_eq!(rva_to_offset(0x0500, &sections), None);
    }

    #[test]
    fn test_rva_to_offset_empty_sections() {
        let sections: Vec<SectionInfo> = vec![];
        assert_eq!(rva_to_offset(0x1000, &sections), None);
    }

    // ================================================================
    // parse_section_headers edge cases
    // ================================================================

    #[test]
    fn test_parse_section_headers_multiple() {
        let buf = build_pe_with_imports(&["KERNEL32.dll"]);
        // This PE has 1 section; verify parsing returns it
        let pe_offset = u32::from_le_bytes([buf[60], buf[61], buf[62], buf[63]]) as usize;
        let num_sections = u16::from_le_bytes([buf[pe_offset + 6], buf[pe_offset + 7]]);
        let sections = parse_section_headers(&buf, pe_offset, num_sections);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].virtual_address, 0x1000);
        assert_eq!(sections[0].raw_data_offset, 0x200);
    }

    #[test]
    fn test_parse_section_headers_truncated() {
        // Build a PE but truncate before section headers complete
        let buf = build_pe_with_imports(&["KERNEL32.dll"]);
        let pe_offset = u32::from_le_bytes([buf[60], buf[61], buf[62], buf[63]]) as usize;
        // Claim 5 sections but only provide data for 1
        let sections = parse_section_headers(&buf[..0x160].to_vec(), pe_offset, 5);
        // Should parse only 1 section (the one that fits)
        assert_eq!(sections.len(), 1);
    }

    #[test]
    fn test_parse_section_headers_zero_sections() {
        let buf = build_pe_with_imports(&["KERNEL32.dll"]);
        let pe_offset = u32::from_le_bytes([buf[60], buf[61], buf[62], buf[63]]) as usize;
        let sections = parse_section_headers(&buf, pe_offset, 0);
        assert!(sections.is_empty());
    }

    // ================================================================
    // Parser + parsed-object matching integration tests
    // ================================================================

    /// Helper: parse options and return whether a PE with the given DLLs
    /// would match the import filter (simulates detection logic).
    fn imports_match(option_str: &str, pe_dlls: &[&str]) -> bool {
        let data = match parse_executable_options(option_str) {
            Some(d) => d,
            None => return false,
        };
        let needles = match &data.import_dlls {
            None => return true, // no import filter
            Some(dlls) => dlls,
        };
        let lowered: Vec<String> = pe_dlls.iter().map(|s| s.to_ascii_lowercase()).collect();
        let import_set: HashSet<&str> = lowered.iter().map(|s| s.as_str()).collect();
        needles.iter().all(|n| import_set.contains(n.as_str()))
    }

    #[test]
    fn test_match_single_dll_present() {
        assert!(imports_match("kernel32.dll", &["kernel32.dll", "user32.dll"]));
    }

    #[test]
    fn test_match_single_dll_absent() {
        assert!(!imports_match("ws2_32.dll", &["kernel32.dll", "user32.dll"]));
    }

    #[test]
    fn test_match_multi_dll_all_present() {
        assert!(imports_match(
            "ws2_32.dll, wininet.dll",
            &["kernel32.dll", "ws2_32.dll", "wininet.dll", "advapi32.dll"],
        ));
    }

    #[test]
    fn test_match_multi_dll_one_missing() {
        assert!(!imports_match(
            "ws2_32.dll, urlmon.dll",
            &["kernel32.dll", "ws2_32.dll", "wininet.dll"],
        ));
    }

    #[test]
    fn test_match_multi_dll_all_missing() {
        assert!(!imports_match(
            "urlmon.dll, wldap32.dll",
            &["kernel32.dll", "user32.dll"],
        ));
    }

    #[test]
    fn test_match_case_insensitive() {
        assert!(imports_match("KERNEL32.DLL", &["kernel32.dll"]));
        assert!(imports_match("kernel32.dll", &["KERNEL32.DLL"]));
    }

    #[test]
    fn test_match_no_import_filter() {
        // No DLLs in keyword → matches any PE
        assert!(imports_match("arch x86", &["kernel32.dll"]));
    }

    #[test]
    fn test_match_against_empty_imports() {
        // PE has no imports, but rule requires one
        assert!(!imports_match("kernel32.dll", &[]));
    }

    #[test]
    fn test_match_combined_options_with_dlls() {
        // Verifies parsed object has both arch and DLL filters populated
        let data = parse_executable_options("arch x86_64, ws2_32.dll, advapi32.dll, sections <10").unwrap();
        assert_eq!(data.architecture, 0x8664);
        assert!(!data.sections.is_null());
        let dlls = data.import_dlls.as_ref().unwrap();
        assert_eq!(dlls.len(), 2);
        assert_eq!(dlls[0], "ws2_32.dll");
        assert_eq!(dlls[1], "advapi32.dll");
    }

    #[test]
    fn test_match_dlls_interspersed_with_options() {
        // DLLs interspersed with keyword options
        let data = parse_executable_options("kernel32.dll, arch x86, ws2_32.dll, subsystem 3").unwrap();
        assert_eq!(data.architecture, 0x014C);
        assert!(!data.subsystem.is_null());
        let dlls = data.import_dlls.as_ref().unwrap();
        assert_eq!(dlls.len(), 2);
        assert!(dlls.contains(&"kernel32.dll".to_string()));
        assert!(dlls.contains(&"ws2_32.dll".to_string()));
    }

    #[test]
    fn test_parse_and_check_pe32_imports() {
        // End-to-end: build a PE32, parse its imports, match against parsed options
        let pe = build_pe_with_imports(&["KERNEL32.dll", "WS2_32.dll", "ADVAPI32.dll"]);
        let imports = parse_pe_imports(&pe).unwrap();

        // Rule: ws2_32.dll, advapi32.dll — should match
        let data = parse_executable_options("ws2_32.dll, advapi32.dll").unwrap();
        let needles = data.import_dlls.as_ref().unwrap();
        let import_set: HashSet<&str> = imports.iter().map(|s| s.as_str()).collect();
        assert!(needles.iter().all(|n| import_set.contains(n.as_str())));
    }

    #[test]
    fn test_parse_and_check_pe32plus_imports() {
        // End-to-end: build a PE32+, parse its imports, match against parsed options
        let pe = build_pe32plus_with_imports(&["ntdll.dll", "KERNEL32.dll", "WININET.dll"]);
        let imports = parse_pe_imports(&pe).unwrap();

        // Rule: wininet.dll — should match
        let data = parse_executable_options("wininet.dll").unwrap();
        let needles = data.import_dlls.as_ref().unwrap();
        let import_set: HashSet<&str> = imports.iter().map(|s| s.as_str()).collect();
        assert!(needles.iter().all(|n| import_set.contains(n.as_str())));

        // Rule: urlmon.dll — should NOT match
        let data2 = parse_executable_options("urlmon.dll").unwrap();
        let needles2 = data2.import_dlls.as_ref().unwrap();
        assert!(!needles2.iter().all(|n| import_set.contains(n.as_str())));
    }

    #[test]
    fn test_parse_and_check_partial_match_fails() {
        // Only 2 of 3 requested DLLs are present → must fail
        let pe = build_pe_with_imports(&["KERNEL32.dll", "WS2_32.dll"]);
        let imports = parse_pe_imports(&pe).unwrap();
        let data = parse_executable_options("kernel32.dll, ws2_32.dll, wininet.dll").unwrap();
        let needles = data.import_dlls.as_ref().unwrap();
        let import_set: HashSet<&str> = imports.iter().map(|s| s.as_str()).collect();
        assert!(!needles.iter().all(|n| import_set.contains(n.as_str())));
    }

    // ================================================================
    // New fields: parsing and option tests
    // ================================================================

    #[test]
    fn test_parse_pe_metadata_new_fields() {
        let mut buf = vec![0u8; 300];
        buf[0..2].copy_from_slice(b"MZ");
        let pe_offset = 64u32;
        buf[60..64].copy_from_slice(&pe_offset.to_le_bytes());
        buf[64..68].copy_from_slice(b"PE\0\0");
        buf[68..70].copy_from_slice(&0x014Cu16.to_le_bytes()); // machine
        buf[70..72].copy_from_slice(&1u16.to_le_bytes()); // num_sections

        // Timestamp at pe_offset+8
        buf[72..76].copy_from_slice(&0x5F3B4C00u32.to_le_bytes());
        // Characteristics
        buf[86..88].copy_from_slice(&0x0102u16.to_le_bytes());

        // Optional header at pe_offset+24 = 88
        let opt = 88;
        buf[opt..opt + 2].copy_from_slice(&0x010bu16.to_le_bytes()); // magic PE32
        // SizeOfHeaders at opt+0x3C
        buf[opt + 0x3C..opt + 0x40].copy_from_slice(&0x400u32.to_le_bytes());
        // Checksum at opt+0x40
        buf[opt + 0x40..opt + 0x44].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());

        let meta = parse_pe_metadata(&buf).unwrap();
        assert_eq!(meta.magic, 0x10b);
        assert_eq!(meta.timestamp, 0x5F3B4C00);
        assert_eq!(meta.checksum, 0xDEADBEEF);
        assert_eq!(meta.size_of_headers, 0x400);
    }

    #[test]
    fn test_parse_option_pe_type() {
        let data = parse_executable_options("pe_type pe32").unwrap();
        assert_eq!(data.pe_type, 0x10b);

        let data = parse_executable_options("pe_type pe32+").unwrap();
        assert_eq!(data.pe_type, 0x20b);

        let data = parse_executable_options("pe_type pe64").unwrap();
        assert_eq!(data.pe_type, 0x20b);

        assert!(parse_executable_options("pe_type invalid").is_none());
    }

    #[test]
    fn test_parse_option_timestamp() {
        let data = parse_executable_options("timestamp >0").unwrap();
        assert!(!data.timestamp.is_null());
    }

    #[test]
    fn test_parse_option_checksum() {
        let data = parse_executable_options("checksum 0").unwrap();
        assert!(!data.checksum.is_null());
    }

    #[test]
    fn test_parse_option_size_of_headers() {
        let data = parse_executable_options("size_of_headers >0x200").unwrap();
        assert!(!data.size_of_headers.is_null());
    }

    #[test]
    fn test_parse_option_num_imports() {
        let data = parse_executable_options("num_imports >5").unwrap();
        assert!(!data.num_imports.is_null());
    }

    #[test]
    fn test_parse_option_num_exports() {
        let data = parse_executable_options("num_exports >0").unwrap();
        assert!(!data.num_exports.is_null());
    }

    #[test]
    fn test_parse_option_section_name() {
        let data = parse_executable_options("section_name .text").unwrap();
        assert_eq!(data.section_name.as_deref().map(String::as_str), Some(".text"));

        // Verify case-insensitive: needle is lowercased at parse time
        let data2 = parse_executable_options("section_name .UPX0").unwrap();
        assert_eq!(data2.section_name.as_deref().map(String::as_str), Some(".upx0"));
    }

    #[test]
    fn test_parse_option_export_name() {
        let data = parse_executable_options("export_name mydll.dll").unwrap();
        assert_eq!(data.export_name.as_deref().map(String::as_str), Some("mydll.dll"));
    }

    #[test]
    fn test_parse_option_section_wx() {
        let data = parse_executable_options("section_wx").unwrap();
        assert!(data.section_wx);
    }

    #[test]
    fn test_parse_option_combined_new_fields() {
        let data = parse_executable_options(
            "arch x86, pe_type pe32, timestamp >0, section_wx, num_imports >3"
        ).unwrap();
        assert_eq!(data.architecture, 0x014C);
        assert_eq!(data.pe_type, 0x10b);
        assert!(!data.timestamp.is_null());
        assert!(data.section_wx);
        assert!(!data.num_imports.is_null());
    }

    #[test]
    fn test_has_wx_section_true() {
        let sections = vec![SectionInfo {
            name: *b".text\0\0\0",
            virtual_address: 0x1000,
            virtual_size: 0x1000,
            raw_data_offset: 0x400,
            raw_data_size: 0x1000,
            characteristics: IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE,
        }];
        assert!(has_wx_section(&sections));
    }

    #[test]
    fn test_has_wx_section_false() {
        let sections = vec![
            SectionInfo {
                name: *b".text\0\0\0",
                virtual_address: 0x1000,
                virtual_size: 0x1000,
                raw_data_offset: 0x400,
                raw_data_size: 0x1000,
                characteristics: IMAGE_SCN_MEM_EXECUTE, // execute only, no write
            },
            SectionInfo {
                name: *b".data\0\0\0",
                virtual_address: 0x2000,
                virtual_size: 0x1000,
                raw_data_offset: 0x1400,
                raw_data_size: 0x1000,
                characteristics: IMAGE_SCN_MEM_WRITE, // write only, no execute
            },
        ];
        assert!(!has_wx_section(&sections));
    }

    #[test]
    fn test_section_name_str() {
        assert_eq!(section_name_str(b".text\0\0\0"), ".text");
        assert_eq!(section_name_str(b".reloc\0\0"), ".reloc");
        assert_eq!(section_name_str(b"12345678"), "12345678"); // full 8 chars, no null
        assert_eq!(section_name_str(b"\0\0\0\0\0\0\0\0"), "");
    }

    #[test]
    fn test_parse_section_headers_names_and_characteristics() {
        // Build a PE with imports and check section name/characteristics parsing
        let buf = build_pe_with_imports(&["KERNEL32.dll"]);
        let pe_offset = u32::from_le_bytes([buf[60], buf[61], buf[62], buf[63]]) as usize;
        let num_sections = u16::from_le_bytes([buf[pe_offset + 6], buf[pe_offset + 7]]);
        let sections = parse_section_headers(&buf, pe_offset, num_sections);
        assert_eq!(sections.len(), 1);
        assert_eq!(section_name_str(&sections[0].name), ".idata");
    }

    /// Build a PE32 with an export directory.
    fn build_pe_with_exports(dll_name: &str, num_functions: u32) -> Vec<u8> {
        let mut buf = vec![0u8; 0x2200];

        // DOS header
        buf[0..2].copy_from_slice(b"MZ");
        let pe_offset: u32 = 0x40;
        buf[60..64].copy_from_slice(&pe_offset.to_le_bytes());

        // PE signature
        buf[0x40..0x44].copy_from_slice(b"PE\0\0");

        // COFF header
        buf[0x44..0x46].copy_from_slice(&0x014Cu16.to_le_bytes()); // Machine: x86
        buf[0x46..0x48].copy_from_slice(&1u16.to_le_bytes());      // NumberOfSections
        buf[0x54..0x56].copy_from_slice(&0x00E0u16.to_le_bytes()); // SizeOfOptionalHeader
        buf[0x56..0x58].copy_from_slice(&0x0102u16.to_le_bytes()); // Characteristics

        // Optional header
        let opt = 0x58usize;
        buf[opt..opt + 2].copy_from_slice(&0x010bu16.to_le_bytes()); // Magic: PE32
        buf[opt + 0x5C..opt + 0x60].copy_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes

        // Export directory data directory at index 0 (opt+0x60)
        let export_dd = opt + 0x60;
        let export_rva: u32 = 0x1000;
        buf[export_dd..export_dd + 4].copy_from_slice(&export_rva.to_le_bytes());
        buf[export_dd + 4..export_dd + 8].copy_from_slice(&40u32.to_le_bytes()); // size

        // Section header at opt+0xE0
        let sh = opt + 0xE0;
        buf[sh..sh + 8].copy_from_slice(b".edata\0\0");
        buf[sh + 8..sh + 12].copy_from_slice(&0x2000u32.to_le_bytes());  // VirtualSize
        buf[sh + 12..sh + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
        buf[sh + 16..sh + 20].copy_from_slice(&0x2000u32.to_le_bytes()); // SizeOfRawData
        buf[sh + 20..sh + 24].copy_from_slice(&0x0200u32.to_le_bytes()); // PointerToRawData

        // Export directory at file offset 0x200 (section base)
        let exp = 0x200usize;
        // NumberOfFunctions at +20
        buf[exp + 20..exp + 24].copy_from_slice(&num_functions.to_le_bytes());
        // Name RVA at +12 — point to after the export dir table
        let name_rva: u32 = 0x1000 + 40; // section_va + 40
        buf[exp + 12..exp + 16].copy_from_slice(&name_rva.to_le_bytes());

        // Write DLL name at file offset 0x200 + 40
        let name_off = exp + 40;
        buf[name_off..name_off + dll_name.len()].copy_from_slice(dll_name.as_bytes());
        buf[name_off + dll_name.len()] = 0;

        buf
    }

    #[test]
    fn test_parse_pe_exports_basic() {
        let buf = build_pe_with_exports("mylib.dll", 42);
        let pe_offset = 0x40;
        let (name, count) = parse_pe_exports(&buf, pe_offset);
        assert_eq!(name.as_deref(), Some("mylib.dll"));
        assert_eq!(count, 42);
    }

    #[test]
    fn test_parse_pe_exports_no_exports() {
        // Build a PE with no export directory (RVA=0)
        let mut buf = vec![0u8; 0x400];
        buf[0..2].copy_from_slice(b"MZ");
        buf[60..64].copy_from_slice(&0x40u32.to_le_bytes());
        buf[0x40..0x44].copy_from_slice(b"PE\0\0");
        buf[0x44..0x46].copy_from_slice(&0x014Cu16.to_le_bytes());
        buf[0x46..0x48].copy_from_slice(&1u16.to_le_bytes());
        buf[0x54..0x56].copy_from_slice(&0x00E0u16.to_le_bytes());
        let opt = 0x58usize;
        buf[opt..opt + 2].copy_from_slice(&0x010bu16.to_le_bytes());
        buf[opt + 0x5C..opt + 0x60].copy_from_slice(&16u32.to_le_bytes());
        let (name, count) = parse_pe_exports(&buf, 0x40);
        assert!(name.is_none());
        assert_eq!(count, 0);
    }

    #[test]
    fn test_pe_log_json_new_fields() {
        let mut buf = vec![0u8; 300];
        buf[0..2].copy_from_slice(b"MZ");
        buf[60..64].copy_from_slice(&64u32.to_le_bytes());
        buf[64..68].copy_from_slice(b"PE\0\0");
        buf[68..70].copy_from_slice(&0x014Cu16.to_le_bytes());
        buf[70..72].copy_from_slice(&1u16.to_le_bytes());
        // timestamp
        buf[72..76].copy_from_slice(&12345u32.to_le_bytes());
        // optional header at 88
        let opt = 88;
        buf[opt..opt + 2].copy_from_slice(&0x010bu16.to_le_bytes()); // PE32
        buf[opt + 0x3C..opt + 0x40].copy_from_slice(&0x200u32.to_le_bytes()); // size_of_headers
        buf[opt + 0x40..opt + 0x44].copy_from_slice(&0xABCDu32.to_le_bytes()); // checksum

        let mut js = JsonBuilder::try_new_object().expect("new");
        pe_log_json(&buf, &mut js).expect("log");
        js.close().expect("close");
        let output = unsafe {
            let ptr = crate::jsonbuilder::SCJbPtr(&mut js);
            let len = crate::jsonbuilder::SCJbLen(&js);
            std::str::from_utf8(std::slice::from_raw_parts(ptr, len)).unwrap().to_string()
        };
        assert!(output.contains("\"pe_type\":\"PE32\""), "pe_type missing: {}", output);
        assert!(output.contains("\"magic\":267"), "magic missing: {}", output); // 0x10b = 267
        assert!(output.contains("\"timestamp\":12345"), "timestamp missing: {}", output);
        assert!(output.contains("\"checksum\":43981"), "checksum missing: {}", output); // 0xABCD
        assert!(output.contains("\"size_of_headers\":512"), "size_of_headers missing: {}", output);
        assert!(output.contains("\"has_wx_section\":false"), "has_wx_section missing: {}", output);
    }
}
