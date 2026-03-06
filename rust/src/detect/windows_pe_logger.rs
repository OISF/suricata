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

//! Windows PE JSON logging.
//!
//! Separated from the detection module (`windows_pe`) so that detection
//! and output concerns do not mix.

use crate::detect::windows_pe::{
    detect_meta_full, file_imports_get, file_imports_set, file_meta_get, file_meta_set,
    parse_pe_exports, parse_pe_imports_with_offset, parse_pe_metadata, parse_section_headers,
    section_name_str, SCDetectPeMetadata, SectionInfo, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_WRITE,
};
use crate::jsonbuilder::{JsonBuilder, JsonError};
use suricata_sys::sys::File;

/// Build JSON representation of PE metadata.
///
/// Called for both raw-buffer parsing and File-cache fallback paths.
pub(crate) fn pe_log_json_fields(
    meta: &SCDetectPeMetadata,
    imports: Option<&[String]>,
    sections: Option<&[SectionInfo]>,
    export_name: Option<&str>,
    js: &mut JsonBuilder,
) -> Result<(), JsonError> {
    js.open_object("executable")?;
    js.set_string("type", "windows_pe")?;

    // Architecture (machine type) - hex value and human-readable name
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

    js.set_uint("sections", meta.num_sections as u64)?;

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

    js.set_uint("dll_characteristics", meta.dll_characteristics as u64)?;
    let mut sec_features: [&str; 5] = [""; 5];
    let mut sec_count = 0;
    if meta.dll_characteristics & 0x0020 != 0 { sec_features[sec_count] = "HIGH_ENTROPY_VA"; sec_count += 1; }
    if meta.dll_characteristics & 0x0040 != 0 { sec_features[sec_count] = "DYNAMIC_BASE";    sec_count += 1; }
    if meta.dll_characteristics & 0x0100 != 0 { sec_features[sec_count] = "NX_COMPAT";       sec_count += 1; }
    if meta.dll_characteristics & 0x0400 != 0 { sec_features[sec_count] = "NO_SEH";          sec_count += 1; }
    if meta.dll_characteristics & 0x4000 != 0 { sec_features[sec_count] = "GUARD_CF";        sec_count += 1; }
    if sec_count > 0 {
        js.open_array("security_features")?;
        for feature in &sec_features[..sec_count] {
            js.append_string(feature)?;
        }
        js.close()?;
    }

    js.set_uint("entry_point", meta.entry_point_rva as u64)?;
    js.set_uint("size_of_image", meta.size_of_image as u64)?;
    js.set_uint("pe_offset", meta.pe_offset as u64)?;

    let pe_type_name = match meta.magic {
        0x10b => "PE32",
        0x20b => "PE32+",
        _ => "unknown",
    };
    js.set_string("pe_type", pe_type_name)?;
    js.set_uint("magic", meta.magic as u64)?;

    js.set_uint("timestamp", meta.timestamp as u64)?;
    js.set_uint("checksum", meta.checksum as u64)?;
    js.set_uint("size_of_headers", meta.size_of_headers as u64)?;

    js.set_uint("num_imports", meta.num_imports as u64)?;
    js.set_uint("num_exports", meta.num_exports as u64)?;

    js.set_bool("has_wx_section", meta.has_wx_section)?;

    if let Some(name) = export_name {
        js.set_string("export_name", name)?;
    }

    if let Some(dlls) = imports {
        if !dlls.is_empty() {
            js.open_array("imports")?;
            for dll in dlls {
                js.append_string(dll)?;
            }
            js.close()?;
        }
    }

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

    js.close()?;
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
            let mut meta = match parse_pe_metadata(file_data) {
                Some(m) => m,
                None => {
                    file_meta_set(file as *mut File, &SCDetectPeMetadata::default());
                    return true;
                }
            };
            let sections = parse_section_headers(
                file_data, meta.pe_offset as usize, meta.num_sections,
            );
            let imports = parse_pe_imports_with_offset(
                file_data, meta.pe_offset as usize, &sections,
            );
            let num_imports =
                imports.as_ref().map_or(0, |v| v.len().min(u16::MAX as usize) as u16);
            let (export_name, num_exports) =
                parse_pe_exports(file_data, meta.pe_offset as usize, &sections);

            detect_meta_full(&mut meta, &sections, num_imports, num_exports);
            if let Some(imp) = imports {
                file_imports_set(file as *mut File, imp);
            }
            file_meta_set(file as *mut File, &meta);

            let cached_imports = file_imports_get(file);
            return pe_log_json_fields(
                &meta, cached_imports, Some(&sections), export_name.as_deref(), js,
            ).is_ok();
        }
    }
    false
}
