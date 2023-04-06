/*
 *  Interface to the suricata library.
 */

/** \file
 *
 *  \author Angelo Mirabella <mirabellaa@vmware.com>
 *
 *  LIB packet decoding support
 *
 */

#include "suricata-common.h"
#include "source-lib.h"
#include "decode.h"
#include "tm-modules.h"
#include "tm-threads.h"
#include "tmqh-packetpool.h"
#include "util-time.h"

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

/** \brief process a single packet
 *
 * \param tv                    Pointer to the per-thread structure.
 * \param data                  Pointer to the raw packet.
 * \param datalink              Datalink type.
 * \param ts                    Timeval structure.
 * \param len                   Packet length.
 * \param ignore_pkt_checksum   Boolean indicating if we should ignore the packet checksum.
 * \return                      Struct containing generated alerts if any.
 */
int TmModuleLibHandlePacket(ThreadVars *tv, const uint8_t *data, int datalink, struct timeval ts,
        uint32_t len, int ignore_pkt_checksum)
{

    Packet *p = PacketGetFromQueueOrAlloc();

    if (unlikely(p == NULL)) {
        SCReturnInt(TM_ECODE_FAILED);
    }

    /* If we are processing a PCAP and it is the first packet we need to set the timestamp. */
    if (!time_set && !TimeModeIsLive()) {
        TmThreadsInitThreadsTimestamp(SCTIME_FROM_TIMEVAL(&ts));
        time_set = true;
    }

    PKT_SET_SRC(p, PKT_SRC_WIRE);
    p->ts = SCTIME_FROM_TIMEVAL(&ts);

    p->datalink = datalink;

    if (PacketSetData(p, data, len) == -1) {
        TmqhOutputPacketpool(tv, p);
        SCReturnInt(TM_ECODE_FAILED);
    }
    SCLogDebug("pktlen: %" PRIu32 " (pkt %p, pkt data %p)", GET_PKT_LEN(p), p, GET_PKT_DATA(p));

    /* We only check for checksum disable */
    if (ignore_pkt_checksum) {
        p->flags |= PKT_IGNORE_CHECKSUM;
    }

    if (TmThreadsSlotProcessPkt(tv, tv->tm_slots, p) != TM_ECODE_OK) {
        SCReturnInt(TM_ECODE_FAILED);
    }

    SCReturnInt(TM_ECODE_OK);
}
