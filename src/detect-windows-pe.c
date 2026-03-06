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

/**
 * \file
 *
 * \author Jeff Lucovsky <jlucovsky@oisf.net>
 *
 * Implements the windows_pe keyword for detecting Windows PE files in
 * network traffic with optional metadata matching.
 *
 * The windows_pe keyword can be used alone or with option(s):
 *
 *   windows_pe;
 *   windows_pe: arch <arch>
 *               [, size <uint32>][, sections <uint16>]
 *               [, entry_point <uint32>]
 *               [, subsystem <uint16>][, characteristics <uint16>]
 *               [, dll_characteristics <uint16>];
 *
 * Option parsing is performed in Rust (SCDetectWindowsPEParse) following
 * the pattern established by detect-bytemath.c / byte_math.rs.
 */

#include "suricata-common.h"
#include "detect-windows-pe.h"
#include "util-file.h"
#include "rust.h"

/* Forward declaration for Rust FFI */
extern void SCDetectWindowsPERegister(void);

void DetectWindowsPERegister(void)
{
    SCDetectWindowsPERegister();
}

/* Stub implementations for File PE metadata caching.
 * These satisfy the linker until util-file.c provides the real
 * implementations backed by pe_meta/pe_imports fields on File. */

typedef struct SCFilePeMeta SCFilePeMeta;

bool FilePeMetaGet(const File *file, SCFilePeMeta *meta)
{
    return false;
}

void FilePeMetaSet(File *file, const SCFilePeMeta *meta)
{
}

const void *FilePeImportsGet(const File *file)
{
    return NULL;
}

void FilePeImportsSet(File *file, void *imports)
{
}
