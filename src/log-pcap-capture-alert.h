/* Copyright (C) 2020 Open Information Security Foundation
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

#ifndef __LOG_PCAP_CAPTURE_ALERT_H__
#define __LOG_PCAP_CAPTURE_ALERT_H__

#include "log-pcap.h"

#define MAX_CAPTURE_DIRS_PER_DIR 1000
#define MAX_CAPTURES_PER_DIR 1000
#define MAX_CAPTURES_PER_ALERT 10

#define PCAP_SUFFIX ".pcap"

/**
 *  This is the tagged pcap dumping information used when the capture upon alert of the pcap-log
 *  module is enabled in combination with a signature containing the "tag:session;" keyword.
 */
typedef struct TaggedPcapEntry_ {
    pcap_dumper_t *pcap_dumper;
    pcap_t *pcap_dead_handle;
    time_t time;
    int thread_id;
    uint32_t unique_id;
    uint32_t signature_id;
    uint64_t size_current;
    uint64_t size_limit;
    uint32_t file_cnt;
} TaggedPcapEntry;

void GeneratePcapFiles(ThreadVars *tv, PcapLogThreadData *td,
                              const Packet *p);
void CleanUpTaggedPcap(TaggedPcapEntry *tpe);
#endif /*__LOG_PCAP_CAPTURE_ALERT_H__*/
