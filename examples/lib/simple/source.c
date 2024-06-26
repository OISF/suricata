/* Copyright (C) 2024 Open Information Security Foundation
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

#include "suricata.h"
#include "threadvars.h"
#include "tm-modules.h"
#include "tm-threads-common.h"
#include "tm-threads.h"

#include "source.h"

#include <pcap/pcap.h>

struct ThreadData {
    pcap_t *pcap;
};

static TmEcode ReceiveThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    SCLogNotice("initdata=%p, data=%p", initdata, *data);

    struct ThreadData *td = SCCalloc(1, sizeof(struct ThreadData));
    BUG_ON(td == NULL);

    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    td->pcap = pcap_open_offline("dummy.pcap", pcap_errbuf);
    if (td->pcap == NULL) {
        SCLogError("Failed to open dummy.pcap: %s", pcap_errbuf);
        SCFree(td);
        return TM_ECODE_FAILED;
    }
    SCLogNotice("td=%p", td);
    *data = (void *)td;

    return TM_ECODE_OK;
}

static TmEcode ReceiveThreadDeinit(ThreadVars *tv, void *data)
{
    SCLogNotice("...");

    struct ThreadData *td = data;
    pcap_close(td->pcap);
    SCFree(td);

    return TM_ECODE_OK;
}

static TmEcode ReceiveLoop(ThreadVars *tv, void *data, void *slot)
{
    SCEnter();
    struct ThreadData *td = data;
    SCLogNotice("tv=%p, data=%p, slot=%p", tv, data, slot);

    if (suricata_ctl_flags & SURICATA_STOP) {
        SCReturnInt(TM_ECODE_OK);
    }

    TmSlot *s = ((TmSlot *)slot)->slot_next;

    /* Notify we are running and processing packets. */
    TmThreadsSetFlag(tv, THV_RUNNING);

    for (;;) {
        if (suricata_ctl_flags & SURICATA_STOP) {
            SCReturnInt(TM_ECODE_OK);
        }

        PacketPoolWait();

        struct pcap_pkthdr *pkt_header = NULL;
        const u_char *pkt_data = NULL;

        int pcap_r = pcap_next_ex(td->pcap, &pkt_header, &pkt_data);
        switch (pcap_r) {
            case 1:
                break;
            case PCAP_ERROR_BREAK:
                goto done;
            default:
                SCLogError("pcap_next_ex failed: %s", pcap_geterr(td->pcap));
                return TM_ECODE_FAILED;
        }

        Packet *p = PacketGetFromQueueOrAlloc();
        if (unlikely(p == NULL)) {
            return TM_ECODE_FAILED;
        }
        PKT_SET_SRC(p, PKT_SRC_WIRE);
        p->ts = SCTIME_FROM_TIMEVAL_UNTRUSTED(&pkt_header->ts);
        p->datalink = LINKTYPE_ETHERNET;

        if (unlikely(PacketCopyData(p, pkt_data, pkt_header->caplen) != 0)) {
            TmqhOutputPacketpool(tv, p);
            return TM_ECODE_FAILED;
        }

        if (TmThreadsSlotProcessPkt(tv, s, p) != TM_ECODE_OK) {
            SCLogError("TmThreadsSlotProcessPkt failed");
            return TM_ECODE_FAILED;
        }
    }

done:

    EngineStop();
    return TM_ECODE_OK;
}

static void ReceiveThreadExitPrintStats(ThreadVars *tv, void *data)
{
    SCLogNotice("...");
}

static TmEcode DecodeThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    SCLogNotice("...");

    DecodeThreadVars *dtv = DecodeThreadVarsAlloc(tv);
    if (dtv == NULL) {
        SCReturnInt(TM_ECODE_FAILED);
    }
    DecodeRegisterPerfCounters(dtv, tv);
    *data = (void *)dtv;

    return TM_ECODE_OK;
}

static TmEcode DecodeThreadDeinit(ThreadVars *tv, void *data)
{
    SCLogNotice("...");

    if (data != NULL) {
        DecodeThreadVarsFree(tv, data);
    }
    SCReturnInt(TM_ECODE_OK);

    return TM_ECODE_OK;
}

static TmEcode Decode(ThreadVars *tv, Packet *p, void *data)
{
    SCLogNotice("...");

    DecodeLinkLayer(tv, data, p->datalink, p, GET_PKT_DATA(p), GET_PKT_LEN(p));

    return TM_ECODE_OK;
}

void RegisterCapturePluginReceive(int slot)
{
    tmm_modules[slot].name = "ReceiveCiCapture";
    tmm_modules[slot].ThreadInit = ReceiveThreadInit;
    tmm_modules[slot].Func = NULL;
    tmm_modules[slot].PktAcqLoop = ReceiveLoop;
    tmm_modules[slot].PktAcqBreakLoop = NULL;
    tmm_modules[slot].ThreadExitPrintStats = ReceiveThreadExitPrintStats;
    tmm_modules[slot].ThreadDeinit = ReceiveThreadDeinit;
    tmm_modules[slot].cap_flags = 0;
    tmm_modules[slot].flags = TM_FLAG_RECEIVE_TM;
}

void RegisterCapturePluginDecode(int slot)
{
    tmm_modules[slot].name = "DecodeCiCapture";
    tmm_modules[slot].ThreadInit = DecodeThreadInit;
    tmm_modules[slot].Func = Decode;
    tmm_modules[slot].ThreadExitPrintStats = NULL;
    tmm_modules[slot].ThreadDeinit = DecodeThreadDeinit;
    tmm_modules[slot].cap_flags = 0;
    tmm_modules[slot].flags = TM_FLAG_DECODE_TM;
}
