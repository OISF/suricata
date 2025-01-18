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
#include "packet.h"

#include "source.h"

/* DNS request for suricata.io. */
static const unsigned char DNS_REQUEST[94] = {
    0xa0, 0x36, 0x9f, 0x4c, 0x4c, 0x28, 0x50, 0xeb, /* .6.LL(P. */
    0xf6, 0x7d, 0xea, 0x54, 0x08, 0x00, 0x45, 0x00, /* .}.T..E. */
    0x00, 0x50, 0x19, 0xae, 0x00, 0x00, 0x40, 0x11, /* .P....@. */
    0x4a, 0xc4, 0x0a, 0x10, 0x01, 0x0b, 0x0a, 0x10, /* J....... */
    0x01, 0x01, 0x95, 0x97, 0x00, 0x35, 0x00, 0x3c, /* .....5.< */
    0x90, 0x6e, 0xdb, 0x12, 0x01, 0x20, 0x00, 0x01, /* .n... .. */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x73, /* .......s */
    0x75, 0x72, 0x69, 0x63, 0x61, 0x74, 0x61, 0x02, /* uricata. */
    0x69, 0x6f, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, /* io...... */
    0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x00, 0x00, /* .)...... */
    0x00, 0x0c, 0x00, 0x0a, 0x00, 0x08, 0x88, 0x51, /* .......Q */
    0x20, 0xaf, 0x46, 0xc5, 0xdc, 0xce              /*  .F... */
};

static TmEcode ReceiveThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    SCLogNotice("...");
    return TM_ECODE_OK;
}

static TmEcode ReceiveThreadDeinit(ThreadVars *tv, void *data)
{
    SCLogNotice("...");
    return TM_ECODE_OK;
}

static TmEcode ReceiveLoop(ThreadVars *tv, void *data, void *slot)
{
    SCLogNotice("...");

    if (suricata_ctl_flags & SURICATA_STOP) {
        SCReturnInt(TM_ECODE_OK);
    }

    TmSlot *s = ((TmSlot *)slot)->slot_next;

    /* Notify we are running and processing packets. */
    TmThreadsSetFlag(tv, THV_RUNNING);

    PacketPoolWait();
    Packet *p = PacketGetFromQueueOrAlloc();
    if (unlikely(p == NULL)) {
        return TM_ECODE_FAILED;
    }
    SCPacketSetSource(p, PKT_SRC_WIRE);
    struct timeval now;
    gettimeofday(&now, NULL);
    SCPacketSetTime(p, SCTIME_FROM_TIMEVAL(&now));
    SCPacketSetDatalink(p, LINKTYPE_ETHERNET);
    p->flags |= PKT_IGNORE_CHECKSUM;

    if (unlikely(PacketCopyData(p, DNS_REQUEST, sizeof(DNS_REQUEST)) != 0)) {
        TmqhOutputPacketpool(tv, p);
        return TM_ECODE_FAILED;
    }

    if (TmThreadsSlotProcessPkt(tv, s, p) != TM_ECODE_OK) {
        return TM_ECODE_FAILED;
    }

    EngineStop();
    return TM_ECODE_DONE;
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

void TmModuleReceiveCiCaptureRegister(int slot)
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

void TmModuleDecodeCiCaptureRegister(int slot)
{
    tmm_modules[slot].name = "DecodeCiCapture";
    tmm_modules[slot].ThreadInit = DecodeThreadInit;
    tmm_modules[slot].Func = Decode;
    tmm_modules[slot].ThreadExitPrintStats = NULL;
    tmm_modules[slot].ThreadDeinit = DecodeThreadDeinit;
    tmm_modules[slot].cap_flags = 0;
    tmm_modules[slot].flags = TM_FLAG_DECODE_TM;
}
