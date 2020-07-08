/* Copyright (C) 2007-2020 Open Information Security Foundation
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
 *  This adds support for creating .pcap output files for each tagged flow.
 *  File information is stored with the tag, rather than the flow. The reasons
 *  for this are multi-fold:
 *  1) Flows are locking on changes while tags are not.
 *  2) A flow may have multiple tags.
 *  3) Tags know when to stop following the flow (Thus when to close the file)
 *  4) A flow id can be used to lookup a flow's tags (Trivial and non-locking).
 */
#ifndef __DETECT_TAG_PCAP_H__
#define __DETECT_TAG_PCAP_H__

#include "suricata-common.h"
#include "suricata.h"
#include "decode.h"
#include "log-pcap-stream.h"
#include "pcap.h"

struct Signature_;
typedef struct Signature_ Signature;
struct TcpSession_;
typedef struct TcpSession_ TcpSession;

typedef struct TaggedPcapEntry_ {
    pcap_dumper_t *pcap_dumper;
    pcap_t *pcap_dead_handle;
    char pcap_file_path[PATH_MAX];
} TaggedPcapEntry;


void InitializePcapLogFilenameSupport(const char *output_directory);
void GenerateStreamFilepath(char *result_path_buf, size_t result_buf_size,
        const Packet *p, const Signature *sig, int thread_id, uint32_t
        unique_id);
TaggedPcapEntry *SetupTaggedPcap(const Packet *p, const Signature *sig, int
        thread_id, int unique_id);
void CleanUpTaggedPcap(TaggedPcapEntry *tpe);
void DumpTaggedPacket(pcap_dumper_t *dump_handle, const Packet *p);
void LogTcpSession(TcpSession *session, pcap_dumper_t *dump_handle, const
        Packet *p);
#endif /*__DETECT_TAG_PCAP_H__*/
