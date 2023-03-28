/** \file
 *
 *  \author Angelo Mirabella <mirabellaa@vmware.com>
 *
 *  LIB packet and stream decoding support
 *
 */

#include "suricata-common.h"
#include "source-lib.h"
#include "decode.h"
#include "tm-modules.h"
#include "tm-threads.h"
#include "tmqh-packetpool.h"

static TmEcode DecodeLibThreadInit(ThreadVars *tv, const void *initdata, void **data);
static TmEcode DecodeLibThreadDeinit(ThreadVars *tv, void *data);
static TmEcode DecodeLib(ThreadVars *tv, Packet *p, void *data);

/** \brief register a "Decode" module for suricata as a library.
 *
 *  The "Decode" module is the first module invoked when processing a packet */
void TmModuleDecodeLibRegister(void) {
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
TmEcode DecodeLibThreadInit(ThreadVars *tv, const void *initdata, void **data) {
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
TmEcode DecodeLibThreadDeinit(ThreadVars *tv, void *data) {
    if (data != NULL)
        DecodeThreadVarsFree(tv, data);
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
TmEcode DecodeLib(ThreadVars *tv, Packet *p, void *data) {
    SCEnter();
    DecodeThreadVars *dtv = (DecodeThreadVars *)data;

    BUG_ON(PKT_IS_PSEUDOPKT(p));

    /* update counters */
    DecodeUpdatePacketCounters(tv, dtv, p);

    /* If suri has set vlan during reading, we increase vlan counter */
    if (p->vlan_idx) {
        StatsIncr(tv, dtv->counter_vlan);
    }

    /* call the decoder for non stream packets */
    if (!PKT_IS_STREAM_SEG(p)) {
        DecodeLinkLayer(tv, dtv, p->datalink, p, GET_PKT_DATA(p), GET_PKT_LEN(p));
    }

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
 * \param ignore_pkt_checksum   Boolean indicating if we should ignore the packet checksum.
 * \param tenant_uuid           Tenant uuid (16 bytes) to associate a flow to a tenant.
 * \param tenant_id             Tenant id of the detection engine to use.
 * \param user_ctx              Pointer to a user-defined context object.
 * \return                      Error code.
 */
int TmModuleLibHandlePacket(ThreadVars *tv, const uint8_t *data, int datalink,
                            struct timeval ts, uint32_t len, int ignore_pkt_checksum,
                            uint64_t *tenant_uuid, uint32_t tenant_id, void *user_ctx) {

    Packet *p = PacketGetFromQueueOrAlloc();

    if (unlikely(p == NULL)) {
        SCReturnInt(TM_ECODE_FAILED);
    }

    PKT_SET_SRC(p, PKT_SRC_WIRE);
    p->ts = SCTIME_FROM_TIMEVAL(&ts);

    p->datalink = datalink;
    p->tenant_uuid[0] = tenant_uuid[0];
    p->tenant_uuid[1] = tenant_uuid[1];
    p->tenant_id = tenant_id;
    p->user_ctx = user_ctx;

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

/** \brief setup a stream packet.
 *
 * \param p               Pointer to the packet to setup.
 * \param finfo           Pointer to the flow information.
 * \param tenant_uuid     Tenant uuid (16 bytes) to associate a flow to a tenant.
 * \param tenant_id       Tenant id of the detection engine to use.
 * \param user_ctx        Pointer to a user-defined context object.
 */
static inline Packet * StreamPacketSetup(FlowStreamInfo *finfo, uint64_t *tenant_uuid,
                                         uint32_t tenant_id, void *user_ctx) {
    Packet *p = PacketGetFromQueueOrAlloc();

    if (unlikely(p == NULL)) {
        return NULL;
    }

    PKT_SET_SRC(p, PKT_SRC_WIRE);
    p->tenant_uuid[0] = tenant_uuid[0];
    p->tenant_uuid[1] = tenant_uuid[1];
    p->tenant_id = tenant_id;
    p->user_ctx = user_ctx;
    p->datalink = DLT_RAW;
    p->proto = IPPROTO_TCP;
    p->ts = SCTIME_FROM_TIMEVAL(&finfo->ts);
    p->flags |= PKT_STREAM_EST;
    /* Mark this packet as stream reassembled. */
    p->flags |= PKT_SKIP_STREAM;

    if (finfo->direction == 0) {
        p->flowflags |= FLOW_PKT_TOSERVER;
    } else {
        p->flowflags |= FLOW_PKT_TOCLIENT;
    }
    p->flowflags |= FLOW_PKT_ESTABLISHED;

    /* Copy over the flow info to generate the proper hash. */
    if (finfo->src.family == AF_INET) {
        p->src.addr_data32[0] = finfo->src.address_un_data32[0];
        p->src.addr_data32[1] = 0;
        p->src.addr_data32[2] = 0;
        p->src.addr_data32[3] = 0;
        p->dst.addr_data32[0] = finfo->dst.address_un_data32[0];
        p->dst.addr_data32[1] = 0;
        p->dst.addr_data32[2] = 0;
        p->dst.addr_data32[3] = 0;

        /* Check if we have enough room in direct data. We need ipv4 hdr + tcp hdr.
         * Force an allocation if it is not the case.
         */
        if (GET_PKT_DIRECT_MAX_SIZE(p) < 40) {
            if (PacketCallocExtPkt(p, 40) == -1) {
                goto error;
            }
        }
        /* set the ip header */
        p->ip4h = (IPV4Hdr *)GET_PKT_DATA(p);
        /* version 4 and length 20 bytes for the tcp header */
        p->ip4h->ip_verhl = 0x45;
        p->ip4h->ip_tos = 0;
        p->ip4h->ip_len = htons(40);
        p->ip4h->ip_id = 0;
        p->ip4h->ip_off = 0;
        p->ip4h->ip_ttl = 64;
        p->ip4h->ip_proto = IPPROTO_TCP;
        p->ip4h->s_ip_src.s_addr = p->src.addr_data32[0];
        p->ip4h->s_ip_dst.s_addr = p->dst.addr_data32[0];

        /* set the tcp header */
        p->tcph = (TCPHdr *)((uint8_t *)GET_PKT_DATA(p) + 20);

        SET_PKT_LEN(p, 40); /* ipv4 hdr + tcp hdr */
    } else if (finfo->src.family == AF_INET6) {
        p->src.addr_data32[0] = finfo->src.address_un_data32[0];
        p->src.addr_data32[1] = finfo->src.address_un_data32[1];
        p->src.addr_data32[2] = finfo->src.address_un_data32[2];
        p->src.addr_data32[3] = finfo->src.address_un_data32[3];
        p->dst.addr_data32[0] = finfo->dst.address_un_data32[0];
        p->dst.addr_data32[1] = finfo->dst.address_un_data32[1];
        p->dst.addr_data32[2] = finfo->dst.address_un_data32[2];
        p->dst.addr_data32[3] = finfo->dst.address_un_data32[3];

        /* Check if we have enough room in direct data. We need ipv6 hdr + tcp hdr.
        * Force an allocation if it is not the case.
        */
        if (GET_PKT_DIRECT_MAX_SIZE(p) < 60) {
            if (PacketCallocExtPkt(p, 60) == -1) {
                goto error;
            }
        }
        /* set the ip header */
        p->ip6h = (IPV6Hdr *)GET_PKT_DATA(p);
        /* version 6 */
        p->ip6h->s_ip6_vfc = 0x60;
        p->ip6h->s_ip6_flow = 0;
        p->ip6h->s_ip6_nxt = IPPROTO_TCP;
        p->ip6h->s_ip6_plen = htons(20);
        p->ip6h->s_ip6_hlim = 64;
        p->ip6h->s_ip6_src[0] = p->src.addr_data32[0];
        p->ip6h->s_ip6_src[1] = p->src.addr_data32[1];
        p->ip6h->s_ip6_src[2] = p->src.addr_data32[2];
        p->ip6h->s_ip6_src[3] = p->src.addr_data32[3];
        p->ip6h->s_ip6_dst[0] = p->dst.addr_data32[0];
        p->ip6h->s_ip6_dst[1] = p->dst.addr_data32[1];
        p->ip6h->s_ip6_dst[2] = p->dst.addr_data32[2];
        p->ip6h->s_ip6_dst[3] = p->dst.addr_data32[3];

        /* set the tcp header */
        p->tcph = (TCPHdr *)((uint8_t *)GET_PKT_DATA(p) + 40);

        SET_PKT_LEN(p, 60); /* ipv6 hdr + tcp hdr */
    }

    p->src.family = finfo->src.family;
    p->dst.family = finfo->dst.family;
    p->sp = finfo->sp;
    p->dp = finfo->dp;
    p->tcph->th_offx2 = 0x50;
    p->tcph->th_flags |= TH_ACK;
    p->tcph->th_win = 10;
    p->tcph->th_urp = 0;
    p->tcph->th_sport = htons(p->sp);
    p->tcph->th_dport = htons(p->dp);

    return p;

error:
    return NULL;
}

/** \brief process a single stream segment.
 *
 * \param tv                    Pointer to the per-thread structure.
 * \param finfo                 Pointer to the flow information.
 * \param data                  Pointer to the raw packet.
 * \param len                   Packet length.
 * \param tenant_uuid           Tenant uuid (16 bytes) to associate a flow to a tenant.
 * \param tenant_id             Tenant id of the detection engine to use.
 * \param user_ctx              Pointer to a user-defined context object.
 * \return                      Error code.
 */
int TmModuleLibHandleStream(ThreadVars *tv, FlowStreamInfo *finfo, const uint8_t *data,
                            uint32_t len, uint64_t *tenant_uuid, uint32_t tenant_id,
                            void *user_ctx) {
    Packet *p = StreamPacketSetup(finfo, tenant_uuid, tenant_id, user_ctx);
    if (unlikely(p == NULL)) {
        SCReturnInt(TM_ECODE_FAILED);
    }

    /* Set payload. */
    p->payload = (uint8_t *)data;
    p->payload_len = len;
    p->flags |= PKT_ZERO_COPY;

    FlowSetupStreamPacket(p);

    if (TmThreadsSlotProcessPkt(tv, tv->tm_slots, p) != TM_ECODE_OK) {
        SCReturnInt(TM_ECODE_FAILED);
    }

    SCReturnInt(TM_ECODE_OK);
}
