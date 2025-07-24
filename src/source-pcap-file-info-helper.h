/* Copyright (C) 2025 Open Information Security Foundation
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
 * \author Lukas Sismis <lsismis@oisf.net>
 */

#include "suricata-common.h"

#ifndef SURICATA_SOURCE_PCAP_FILE_INFO_HELPER_H
#define SURICATA_SOURCE_PCAP_FILE_INFO_HELPER_H

// Initialized once by RX thread, used by all threads, read only
typedef struct PcapFileInfo_ {
    char *filename;
    SC_ATOMIC_DECLARE(uint32_t, ref);
} PcapFileInfo;

PcapFileInfo *PcapFileInfoAddReference(PcapFileInfo *pfi);
PcapFileInfo *PcapFileInfoInit(const char *filename);
void PcapFileInfoDeref(PcapFileInfo *pfi);

#endif /* SURICATA_SOURCE_PCAP_FILE_INFO_HELPER_H */
