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
 * \file
 *
 * \author Danny Browning <danny.browning@protectwise.com>
 *
 * File based pcap packet acquisition support
 */

#include "source-pcap-file-helper.h"
#include "util-checksum.h"
#include "util-profiling.h"
#include "source-pcap-file.h"
#include "util-exception-policy.h"

extern int max_pending_packets;
extern PcapFileGlobalVars pcap_g;

static void PcapFileCallbackLoop(char *user, struct pcap_pkthdr *h, u_char *pkt);

void CleanupPcapFileFileVars(PcapFileFileVars *pfv)
{
    if (pfv != NULL) {
        if (pfv->pcap_handle != NULL) {
            pcap_close(pfv->pcap_handle);
            pfv->pcap_handle = NULL;
        }
        if (pfv->filename != NULL) {
            if (pfv->shared != NULL && pfv->shared->should_delete) {
                SCLogDebug("Deleting pcap file %s", pfv->filename);
                if (unlink(pfv->filename) != 0) {
                    SCLogWarning(SC_ERR_PCAP_FILE_DELETE_FAILED,
                                 "Failed to delete %s", pfv->filename);
                }
            }
            SCFree(pfv->filename);
            pfv->filename = NULL;
        }
        pfv->shared = NULL;
        SCFree(pfv);
    }
}

void PcapFileCallbackLoop(char *user, struct pcap_pkthdr *h, u_char *pkt)
{
    SCEnter();
#ifdef DEBUG
    if (unlikely((pcap_g.cnt + 1ULL) == g_eps_pcap_packet_loss)) {
        SCLogNotice("skipping packet %" PRIu64, g_eps_pcap_packet_loss);
        pcap_g.cnt++;
        SCReturn;
    }
#endif
    PcapFileFileVars *ptv = (PcapFileFileVars *)user;
    Packet *p = PacketGetFromQueueOrAlloc();

    if (unlikely(p == NULL)) {
        SCReturn;
    }
    PACKET_PROFILING_TMM_START(p, TMM_RECEIVEPCAPFILE);

    PKT_SET_SRC(p, PKT_SRC_WIRE);
    p->ts.tv_sec = h->ts.tv_sec;
    p->ts.tv_usec = h->ts.tv_usec % 1000000;
    SCLogDebug("p->ts.tv_sec %"PRIuMAX"", (uintmax_t)p->ts.tv_sec);
    p->datalink = ptv->datalink;
    p->pcap_cnt = ++pcap_g.cnt;

    p->pcap_v.tenant_id = ptv->shared->tenant_id;
    ptv->shared->pkts++;
    ptv->shared->bytes += h->caplen;

    if (unlikely(PacketCopyData(p, pkt, h->caplen))) {
        TmqhOutputPacketpool(ptv->shared->tv, p);
        PACKET_PROFILING_TMM_END(p, TMM_RECEIVEPCAPFILE);
        SCReturn;
    }

    /* We only check for checksum disable */
    if (pcap_g.checksum_mode == CHECKSUM_VALIDATION_DISABLE) {
        p->flags |= PKT_IGNORE_CHECKSUM;
    } else if (pcap_g.checksum_mode == CHECKSUM_VALIDATION_AUTO) {
        if (ChecksumAutoModeCheck(ptv->shared->pkts, p->pcap_cnt,
                                  SC_ATOMIC_GET(pcap_g.invalid_checksums))) {
            pcap_g.checksum_mode = CHECKSUM_VALIDATION_DISABLE;
            p->flags |= PKT_IGNORE_CHECKSUM;
        }
    }

    PACKET_PROFILING_TMM_END(p, TMM_RECEIVEPCAPFILE);

    if (TmThreadsSlotProcessPkt(ptv->shared->tv, ptv->shared->slot, p) != TM_ECODE_OK) {
        pcap_breakloop(ptv->pcap_handle);
        ptv->shared->cb_result = TM_ECODE_FAILED;
    }

    SCReturn;
}

char pcap_filename[PATH_MAX] = "unknown";

const char *PcapFileGetFilename(void)
{
    return pcap_filename;
}

/**
 *  \brief Main PCAP file reading Loop function
 */
TmEcode PcapFileDispatch(PcapFileFileVars *ptv)
{
    SCEnter();

    /* initialize all the thread's initial timestamp */
    if (likely(ptv->first_pkt_hdr != NULL)) {
        TmThreadsInitThreadsTimestamp(&ptv->first_pkt_ts);
        PcapFileCallbackLoop((char *)ptv, ptv->first_pkt_hdr,
                (u_char *)ptv->first_pkt_data);
        ptv->first_pkt_hdr = NULL;
        ptv->first_pkt_data = NULL;
    }

    int packet_q_len = 64;
    TmEcode loop_result = TM_ECODE_OK;
    strlcpy(pcap_filename, ptv->filename, sizeof(pcap_filename));

    while (loop_result == TM_ECODE_OK) {
        if (suricata_ctl_flags & SURICATA_STOP) {
            SCReturnInt(TM_ECODE_OK);
        }

        /* make sure we have at least one packet in the packet pool, to prevent
         * us from alloc'ing packets at line rate */
        PacketPoolWait();

        /* Right now we just support reading packets one at a time. */
        int r = pcap_dispatch(ptv->pcap_handle, packet_q_len,
                          (pcap_handler)PcapFileCallbackLoop, (u_char *)ptv);
        if (unlikely(r == -1)) {
            SCLogError(SC_ERR_PCAP_DISPATCH, "error code %" PRId32 " %s for %s",
                       r, pcap_geterr(ptv->pcap_handle), ptv->filename);
            if (ptv->shared->cb_result == TM_ECODE_FAILED) {
                SCReturnInt(TM_ECODE_FAILED);
            }
            loop_result = TM_ECODE_DONE;
        } else if (unlikely(r == 0)) {
            SCLogInfo("pcap file %s end of file reached (pcap err code %" PRId32 ")",
                      ptv->filename, r);
            ptv->shared->files++;
            loop_result = TM_ECODE_DONE;
        } else if (ptv->shared->cb_result == TM_ECODE_FAILED) {
            SCLogError(SC_ERR_PCAP_DISPATCH,
                       "Pcap callback PcapFileCallbackLoop failed for %s", ptv->filename);
            loop_result = TM_ECODE_FAILED;
        }
        StatsSyncCountersIfSignalled(ptv->shared->tv);
    }

    SCReturnInt(loop_result);
}

/** \internal
 *  \brief get the timestamp of the first packet and rewind
 *  \param pfv pcap file variables for storing the timestamp
 *  \retval bool true on success, false on error
 */
static bool PeekFirstPacketTimestamp(PcapFileFileVars *pfv)
{
    int r = pcap_next_ex(pfv->pcap_handle, &pfv->first_pkt_hdr, &pfv->first_pkt_data);
    if (r <= 0 || pfv->first_pkt_hdr == NULL) {
        SCLogError(SC_ERR_PCAP_OPEN_OFFLINE,
                "failed to get first packet timestamp. pcap_next_ex(): %d", r);
        return false;
    }
    /* timestamp in pfv->first_pkt_hdr may not be 'struct timeval' so
     * do a manual copy of the members. */
    pfv->first_pkt_ts.tv_sec = pfv->first_pkt_hdr->ts.tv_sec;
    pfv->first_pkt_ts.tv_usec = pfv->first_pkt_hdr->ts.tv_usec;
    return true;
}

TmEcode InitPcapFile(PcapFileFileVars *pfv)
{
    char errbuf[PCAP_ERRBUF_SIZE] = "";

    if(unlikely(pfv->filename == NULL)) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "Filename was null");
        SCReturnInt(TM_ECODE_FAILED);
    }

    pfv->pcap_handle = pcap_open_offline(pfv->filename, errbuf);
    if (pfv->pcap_handle == NULL) {
        SCLogError(SC_ERR_FOPEN, "%s", errbuf);
        SCReturnInt(TM_ECODE_FAILED);
    }

    if (pfv->shared != NULL && pfv->shared->bpf_string != NULL) {
        SCLogInfo("using bpf-filter \"%s\"", pfv->shared->bpf_string);

        if (pcap_compile(pfv->pcap_handle, &pfv->filter, pfv->shared->bpf_string, 1, 0) < 0) {
            SCLogError(SC_ERR_BPF, "bpf compilation error %s for %s",
                       pcap_geterr(pfv->pcap_handle), pfv->filename);
            SCReturnInt(TM_ECODE_FAILED);
        }

        if (pcap_setfilter(pfv->pcap_handle, &pfv->filter) < 0) {
            SCLogError(SC_ERR_BPF,"could not set bpf filter %s for %s",
                       pcap_geterr(pfv->pcap_handle), pfv->filename);
            pcap_freecode(&pfv->filter);
            SCReturnInt(TM_ECODE_FAILED);
        }
        pcap_freecode(&pfv->filter);
    }

    pfv->datalink = pcap_datalink(pfv->pcap_handle);
    SCLogDebug("datalink %" PRId32 "", pfv->datalink);

    if (!PeekFirstPacketTimestamp(pfv))
        SCReturnInt(TM_ECODE_FAILED);

    DecoderFunc UnusedFnPtr;
    TmEcode validated = ValidateLinkType(pfv->datalink, &UnusedFnPtr);
    SCReturnInt(validated);
}

TmEcode ValidateLinkType(int datalink, DecoderFunc *DecoderFn)
{
    switch (datalink) {
        case LINKTYPE_LINUX_SLL:
            *DecoderFn = DecodeSll;
            break;
        case LINKTYPE_ETHERNET:
            *DecoderFn = DecodeEthernet;
            break;
        case LINKTYPE_PPP:
            *DecoderFn = DecodePPP;
            break;
        case LINKTYPE_IPV4:
        case LINKTYPE_RAW:
        case LINKTYPE_RAW2:
        case LINKTYPE_GRE_OVER_IP:
            *DecoderFn = DecodeRaw;
            break;
        case LINKTYPE_NULL:
            *DecoderFn = DecodeNull;
            break;
        case LINKTYPE_CISCO_HDLC:
            *DecoderFn = DecodeCHDLC;
            break;

        default:
            SCLogError(SC_ERR_UNIMPLEMENTED,
                    "datalink type %"PRId32" not (yet) supported in module PcapFile.",
                    datalink);
            SCReturnInt(TM_ECODE_FAILED);
    }

    SCReturnInt(TM_ECODE_OK);
}
