/* Copyright (C) 2007-2010 Open Information Security Foundation
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
 * \author Danny Browning <danny.browning@protectwise.com>
 */

#include "suricata-common.h"
#include "tm-threads.h"

#ifndef __SOURCE_PCAP_FILE_HELPER_H__
#define __SOURCE_PCAP_FILE_HELPER_H__

typedef struct PcapFileGlobalVars_ {
    uint64_t cnt; /** packet counter */
    ChecksumValidationMode conf_checksum_mode;
    ChecksumValidationMode checksum_mode;
    SC_ATOMIC_DECLARE(unsigned int, invalid_checksums);
} PcapFileGlobalVars;

/**
 * Data that is shared amongst File, Directory, and Thread level vars
 */
typedef struct PcapFileSharedVars_
{
    char *bpf_string;

    uint32_t tenant_id;

    struct timespec last_processed;

    bool should_delete;

    ThreadVars *tv;
    TmSlot *slot;

    /* counters */
    uint64_t pkts;
    uint64_t bytes;
    uint64_t files;

    uint8_t done;
    uint32_t errs;

    /** callback result -- set if one of the thread module failed. */
    int cb_result;
} PcapFileSharedVars;

/**
 * Data specific to a single pcap file
 */
typedef struct PcapFileFileVars_
{
    char *filename;
    pcap_t *pcap_handle;

    int datalink;
    struct bpf_program filter;

    PcapFileSharedVars *shared;
} PcapFileFileVars;

typedef int (*Decoder)(ThreadVars *, DecodeThreadVars *, Packet *, uint8_t *, uint32_t, PacketQueue *);

/**
 * Dispatch a file for processing, where the information necessary to process that
 * file is as PcapFileFileVars object.
 * @param ptv PcapFileFileVars object to be processed
 * @return
 */
TmEcode PcapFileDispatch(PcapFileFileVars *ptv);

/**
 * From a PcapFileFileVars, prepare the filename for processing by setting
 * pcap_handle, datalink, and filter
 * @param pfv PcapFileFileVars object to populate
 * @return
 */
TmEcode InitPcapFile(PcapFileFileVars *pfv);

/**
 * Cleanup resources associated with a PcapFileFileVars object.
 * @param pfv Object to be cleaned up
 */
void CleanupPcapFileFileVars(PcapFileFileVars *pfv);

/**
 * Determine if a datalink type is valid, setting a decoder function if valid.
 * @param datalink Datalink type to validate
 * @param decoder Pointer to decoder to set if valid
 * @return TM_ECODE_OK if valid datalink type and decoder has been set.
 */
TmEcode ValidateLinkType(int datalink, Decoder *decoder);

#endif /* __SOURCE_PCAP_FILE_HELPER_H__ */
