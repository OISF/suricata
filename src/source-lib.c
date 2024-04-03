/* Copyright (C) 2023-2024 Open Information Security Foundation
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

/** \file
 *
 *  \author Angelo Mirabella <angelo.mirabella@broadcom.com>
 *
 *  LIB packet and stream decoding support
 *
 */

#include "suricata-common.h"
#include "source-lib.h"
#include "util-device.h"

static TmEcode DecodeLibThreadInit(ThreadVars *tv, const void *initdata, void **data);
static TmEcode DecodeLibThreadDeinit(ThreadVars *tv, void *data);
static TmEcode DecodeLib(ThreadVars *tv, Packet *p, void *data);

/* Set time to the first packet timestamp when replaying a PCAP. */
static bool time_set = false;

/** \brief register a "Decode" module for suricata as a library.
 *
 *  The "Decode" module is the first module invoked when processing a packet */
void TmModuleDecodeLibRegister(void)
{
    tmm_modules[TMM_DECODELIB].name = "DecodeLib";
    tmm_modules[TMM_DECODELIB].ThreadInit = DecodeLibThreadInit;
    tmm_modules[TMM_DECODELIB].Func = DecodeLib;
    tmm_modules[TMM_DECODELIB].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODELIB].ThreadDeinit = DecodeLibThreadDeinit;
    tmm_modules[TMM_DECODELIB].cap_flags = 0;
    tmm_modules[TMM_DECODELIB].flags = TM_FLAG_DECODE_TM;
}

/** \brief initialize the "Decode" module.
 *
 * \param tv                    Pointer to the per-thread structure.
 * \param initdata              Pointer to initialization context.
 * \param data                  Pointer to the initialized context.
 * \return                      Error code.
 */
TmEcode DecodeLibThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    SCEnter();
    DecodeThreadVars *dtv = NULL;

    dtv = DecodeThreadVarsAlloc(tv);

    if (dtv == NULL)
        SCReturnInt(TM_ECODE_FAILED);

    DecodeRegisterPerfCounters(dtv, tv);

    *data = (void *)dtv;

    SCReturnInt(TM_ECODE_OK);
}

/** \brief deinitialize the "Decode" module.
 *
 * \param tv                    Pointer to the per-thread structure.
 * \param data                  Pointer to the context.
 * \return                      Error code.
 */
TmEcode DecodeLibThreadDeinit(ThreadVars *tv, void *data)
{
    if (data != NULL)
        DecodeThreadVarsFree(tv, data);

    time_set = false;
    SCReturnInt(TM_ECODE_OK);
}

/** \brief main decoding function.
 *
 *  This method receives a packet and tries to identify layer 2 to 4 layers.
 *
 * \param tv                    Pointer to the per-thread structure.
 * \param p                     Pointer to the packet.
 * \param data                  Pointer to the context.
 * \return                      Error code.
 */
TmEcode DecodeLib(ThreadVars *tv, Packet *p, void *data)
{
    SCEnter();
    DecodeThreadVars *dtv = (DecodeThreadVars *)data;

    BUG_ON(PKT_IS_PSEUDOPKT(p));

    /* update counters */
    DecodeUpdatePacketCounters(tv, dtv, p);

    /* If suri has set vlan during reading, we increase vlan counter */
    if (p->vlan_idx) {
        StatsIncr(tv, dtv->counter_vlan);
    }

    /* call the decoder */
    DecodeLinkLayer(tv, dtv, p->datalink, p, GET_PKT_DATA(p), GET_PKT_LEN(p));

    PacketDecodeFinalize(tv, dtv, p);

    SCReturnInt(TM_ECODE_OK);
}

/** \brief process a single packet.
 *
 * \param tv                    Pointer to the per-thread structure.
 * \param data                  Pointer to the raw packet.
 * \param datalink              Datalink type.
 * \param ts                    Timeval structure.
 * \param len                   Packet length.
 * \param tenant_id             Tenant id of the detection engine to use.
 * \param flags                 Packet flags (packet checksum, rule profiling...).
 * \param iface                 Sniffing interface this packet comes from (can be NULL).
 * \return                      Error code.
 */
int TmModuleLibHandlePacket(ThreadVars *tv, const uint8_t *data, int datalink, struct timeval ts,
        uint32_t len, uint32_t tenant_id, uint32_t flags, const char *iface)
{

    /* If the packet is NULL, consider it as a read timeout. */
    if (data == NULL) {
        TmThreadsSetFlag(tv, THV_CAPTURE_INJECT_PKT);
        TmThreadsCaptureHandleTimeout(tv, NULL);
        SCReturnInt(TM_ECODE_OK);
    }

    Packet *p = PacketGetFromQueueOrAlloc();
    if (unlikely(p == NULL)) {
        SCReturnInt(TM_ECODE_FAILED);
    }

    /* If we are processing a PCAP and it is the first packet we need to set the timestamp. */
    SCTime_t timestamp = SCTIME_FROM_TIMEVAL(&ts);
    if (!time_set && !TimeModeIsLive()) {
        TmThreadsInitThreadsTimestamp(timestamp);
        time_set = true;
    }

    PKT_SET_SRC(p, PKT_SRC_WIRE);
    p->ts = timestamp;
    p->datalink = datalink;
    p->tenant_id = tenant_id;
    p->flags |= flags;

    /* Set the sniffing interface. */
    if (iface) {
        p->livedev = LiveGetDevice(iface);
    }

    if (PacketSetData(p, data, len) == -1) {
        TmqhOutputPacketpool(tv, p);
        SCReturnInt(TM_ECODE_FAILED);
    }

    SCLogDebug("pktlen: %" PRIu32 " (pkt %p, pkt data %p)", GET_PKT_LEN(p), p, GET_PKT_DATA(p));

    if (TmThreadsSlotProcessPkt(tv, tv->tm_slots, p) != TM_ECODE_OK) {
        SCReturnInt(TM_ECODE_FAILED);
    }

    SCReturnInt(TM_ECODE_OK);
}
