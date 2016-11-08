#define _GNU_SOURCE

#include "suricata-common.h"
#include "suricata.h"
#include "conf.h"
#include "decode.h"
#include "packet-queue.h"
#include "threads.h"
#include "threadvars.h"
#include "tm-queuehandlers.h"
#include "tm-threads.h"
#include "util-debug.h"
#include "util-checksum.h"
#include "util-privs.h"
#include "util-device.h"
#include "util-host-info.h"
#include "runmodes.h"
#include "pkt-var.h"
#include "util-profiling.h"
#include "host.h"


#include "dpdk-include-common.h"
#include "source-dpdkintel.h"

extern uint8_t  portSpeed10;
extern uint8_t  portSpeed100;
extern uint8_t  portSpeed1000;
extern uint8_t  portSpeed10000;
uint8_t portSpeed [16];
extern launchPtr launchFunc[5];
/*
 * brief Structure to hold thread specific variables.
 */
typedef struct DpdkIntelThreadVars_t_
{
    /* To Do: fill with DPDK eth dev details */
    struct rte_eth_dev_info dev_info;

    /* DPDK Ring Buff to deque the pkt desc */
    uint8_t ringBuffId;

    /* counters */
    uint64_t bytes;
    uint64_t pkts;

    ThreadVars *tv;
    TmSlot *slot;

    int vlan_disabled;

    /* To Do: is this required?*/
    /* threads count */
    int threads; 

    char *interface;
    char *outIface;

    uint8_t dpdk_port_id;
    uint8_t promiscous;

    uint8_t inIfaceId;
    uint8_t outIfaceId;

    int copy_mode;

    LiveDevice *livedev;
    ChecksumValidationMode checksum_mode;
} DpdkIntelThreadVars_t;

uint8_t          boolSetCpuPort = 0;
static uint8_t   cpuOffset = 0;
static uint32_t  portConfigured = 0;
dpdkFrameStats_t dpdkStats [16];
DpdkCoreConfig_t coreConfig;

struct rte_mbuf *rbQueue[8][1024];

extern struct   rte_ring *srb [16];
extern file_config_t file_config;
extern uint64_t coreSet;

extern stats_matchPattern_t stats_matchPattern;
extern DpdkIntelPortMap portMap [16];

TmEcode ReceiveDpdkLoop(ThreadVars *tv, void *data, void *slot);
TmEcode ReceiveDpdkThreadInit(ThreadVars *, void *, void **);
TmEcode ReceiveDpdkThreadDeinit(ThreadVars *, void *);

TmEcode DecodeDpdkThreadInit(ThreadVars *, void *, void **);
TmEcode DecodeDpdk(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode DecodeDpdkThreadDeinit(ThreadVars *tv, void *data);
void ReceiveDpdkThreadExitStats(ThreadVars *, void *);


TmEcode DpdkSendFrame(struct rte_mbuf *m, uint8_t port, uint16_t num);
static inline Packet * DpdkIntelProcessPacket(DpdkIntelThreadVars_t *ptv, struct rte_mbuf *m);

extern int max_pending_packets;

#ifdef HAVE_DPDKINTEL

#define LIBDPDK_PROMISC     1
#define LIBDPDK_REENTRANT   0
#define LIBDPDK_WAIT_FOR_INCOMING 1

extern file_config_t file_config;

ThreadVars       *decodeTv;
DecodeThreadVars *decodeDtv;


/**
 * \brief Registration Function for RecieveDpdk.
 * \todo Unit tests are needed for this module.
 */
void TmModuleReceiveDpdkRegister (void) {
    tmm_modules[TMM_RECEIVEDPDK].name = "DpdkIntelReceive";
    tmm_modules[TMM_RECEIVEDPDK].ThreadInit = ReceiveDpdkThreadInit;
    tmm_modules[TMM_RECEIVEDPDK].Func = NULL;
    tmm_modules[TMM_RECEIVEDPDK].PktAcqLoop = ReceiveDpdkLoop;
    tmm_modules[TMM_RECEIVEDPDK].ThreadExitPrintStats = ReceiveDpdkThreadExitStats;
    tmm_modules[TMM_RECEIVEDPDK].ThreadDeinit = ReceiveDpdkThreadDeinit;
    tmm_modules[TMM_RECEIVEDPDK].RegisterTests = NULL;
    tmm_modules[TMM_RECEIVEDPDK].flags = TM_FLAG_RECEIVE_TM;
}

/**
 * \brief Registration Function for DecodeDpdk.
 * \todo Unit tests are needed for this module.
 */
void TmModuleDecodeDpdkRegister (void) {
    tmm_modules[TMM_DECODEDPDK].name = "DpdkIntelDecode";
    tmm_modules[TMM_DECODEDPDK].ThreadInit = DecodeDpdkThreadInit;
    tmm_modules[TMM_DECODEDPDK].Func = DecodeDpdk;
    tmm_modules[TMM_DECODEDPDK].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODEDPDK].ThreadDeinit = DecodeDpdkThreadDeinit;
    tmm_modules[TMM_DECODEDPDK].RegisterTests = NULL;
    tmm_modules[TMM_DECODEDPDK].flags = TM_FLAG_DECODE_TM;
}

void DpdkIntelReleasePacket(Packet *p)
{
    uint8_t portId = (p->dpdkIntel_outPort);
    void *m = (struct rte_mbuf *) p->dpdkIntel_mbufPtr;

    SCLogDebug(" TX packet through port %d for %p", portId, m);

    /* Use this thread's context to free the packet. */
    if (DPDKINTEL_GENCFG.OpMode == IPS || DPDKINTEL_GENCFG.OpMode == BYPASS)
    {
       if (rte_eth_tx_burst(portId, 0, (struct rte_mbuf **)&m, 1) != 1) {
           //SCLogError(SC_ERR_DPDKINTEL_DPDKAPI, " Unable to TX via port %d for %p in OpMode %d", 
                       //portId, m, DPDKINTEL_GENCFG.OpMode);
           rte_pktmbuf_free(m);
       }

       PacketFreeOrRelease (p);
       return;
    }

    SCLogDebug(" Free frame as its IDS ");
    rte_pktmbuf_free(m);
    PacketFreeOrRelease(p);

    return;
}




static inline void DpdkIntelDumpCounters(DpdkIntelThreadVars_t *ptv)
{
   /*
    - get stats from port_id
    - calculate total recv & dropped {err, no mbuff, ..etc.} of dpdk_port_id
    - update the process thread variables (ptv) with the following information
    - 
    */
    struct rte_eth_stats stats;
    rte_eth_stats_get(ptv->inIfaceId, &stats);

    SCLogDebug(" Interface to Dump Stats & Err is %u", ptv->inIfaceId);

    SCLogNotice("Intf : %u", ptv->inIfaceId);
    SCLogNotice(" + ring full %"PRIu64", enq err %"PRIu64
                ", tx err %"PRIu64", Packet alloc fail %"PRIu64
                ", Packet Process Fail %"PRIu64,
                 dpdkStats [portMap [ptv->inIfaceId].inport].ring_full,
                 dpdkStats [portMap [ptv->inIfaceId].inport].enq_err,
                 dpdkStats [portMap [ptv->inIfaceId].outport].tx_err,
                 dpdkStats [portMap [ptv->inIfaceId].inport].sc_pkt_null,
                 dpdkStats [portMap [ptv->inIfaceId].inport].sc_fail);

   /* fetch errr stats of DPDK info */
    SCLogNotice(" + Errors RX: %"PRIu64" TX: %"PRIu64" Mbuff: %"PRIu64, 
                 stats.ierrors, stats.oerrors, stats.rx_nombuf);
    SCLogNotice(" + Queue Dropped pkts: %"PRIu64, stats.q_errors[0]);
    //SCLogNotice(" + Bad CRC: %"PRIu64" LEN: %"PRIu64, stats.ibadcrc, stats.ibadlen);
    SCLogNotice(" ---------------------------------------------------------- ");

#ifdef PACKET_STATISTICS
#endif
    return;
}


/**
 * \brief Dpdk Packet Process function.
 *
 * This function fills in our packet structure from DPDK.
 * From here the packets are picked up by the  DecodeDpdk thread.
 *
 * param
   - user pointer to DpdkIntelThreadVars_t
 * - h pointer to mbuf packet header
 *
 * return
 * - p pointer to the current packet
 */
static inline Packet *DpdkIntelProcessPacket(DpdkIntelThreadVars_t *ptv, struct rte_mbuf *m)
{
    int caplen = m->pkt_len;
    char *pkt = ((char *)m->buf_addr + m->data_off);

    /* ToDo: each mbuff has private memory area - phase 2 
     *       We can store Packet information in the head room
     *       This will reduce the memory alloc or get for Packet
     */

    Packet *p = PacketGetFromQueueOrAlloc();
    if (unlikely(p == NULL)) {
        //ptv->drops += ;
        SCLogError(SC_ERR_MEM_ALLOC, "Failed to get Packet Buffer for DPDK mbuff!");
        return NULL;
    }

    SCLogDebug(" Suricata packet %p for bte %d", p, caplen);

    PACKET_RECYCLE(p);
    PKT_SET_SRC(p, PKT_SRC_WIRE);
    p->datalink = LINKTYPE_ETHERNET;
    p->livedev = ptv->livedev;
    gettimeofday(&p->ts, NULL);
    PacketSetData(p, (uint8_t *) pkt, caplen);

    ptv->bytes += caplen;
    ptv->pkts++;

    /* dpdk Intel sepcific details */
    p->dpdkIntel_mbufPtr = (void *) m;
    p->dpdkIntel_ringId = ptv->ringBuffId;
    p->dpdkIntel_inPort = ptv->inIfaceId;
    p->dpdkIntel_outPort = ptv->outIfaceId;

    p->ReleasePacket = DpdkIntelReleasePacket;

    return p;
}


TmEcode DpdkSendFrame(struct rte_mbuf *m, uint8_t port, uint16_t num)
{
    unsigned queueid = 0, ret = 0;

    ret = rte_eth_tx_burst(port, (uint16_t) queueid, &m, num);
    if (unlikely(ret < num)) {
        SCLogDebug(SC_ERR_PORT_ENGINE_GENERIC, "Failed to send Packet %d", ret);
        rte_pktmbuf_free(m);
        return TM_ECODE_FAILED;
    }

    SCLogDebug("Packet Send \n");
    return TM_ECODE_OK;
}


/**
 * \brief Recieves packets from an interface via DPDK.
 *
 *  This function recieves packets from an interface and passes to Decode thread.
 *
 * param 
   - tv pointer to ThreadVars
 * - data pointer that gets cast into DpdkIntelThreadVars_t for ptv
 * - slot slot containing task information
 * retval
   - TM_ECODE_OK on success
 * - TM_ECODE_FAILED on failure
 */
TmEcode ReceiveDpdkLoop(ThreadVars *tv, void *data, void *slot)
{
    SCEnter();

    unsigned int packet_q_len = 0, j;
    DpdkIntelThreadVars_t *ptv = (DpdkIntelThreadVars_t *)data;
    Packet *p = NULL;
    TmSlot *s = (TmSlot *)slot;
    //time_t last_dump = 0;
    //struct timeval current_time;

    ptv->slot = s->slot_next;

    SCLogDebug("RX-TX Intf Id in %d out %d\n", ptv->inIfaceId, ptv->outIfaceId);

    if (rte_eth_dev_start(ptv->inIfaceId) < 0) {
        SCLogError(SC_ERR_DPDKINTEL_CONFIG_FAILED, " failed RX-TX start on port %d\n", ptv->inIfaceId);
        SCReturnInt(TM_ECODE_FAILED);
    }

    while(1) {
        if (suricata_ctl_flags & (SURICATA_STOP | SURICATA_KILL)) {
            SCReturnInt(TM_ECODE_OK);
        }

        /* invoke rte_api for getting packets*/
        packet_q_len = rte_ring_dequeue_burst(srb[ptv->ringBuffId], 
                                              (void *)&rbQueue[ptv->ringBuffId],
                                              /*64*/128);
        SCLogDebug("rte dequeue ringId: %d count: %d", ptv->ringBuffId, packet_q_len);
        /* ToDo: update counters - phase 2 */
        if (likely(packet_q_len)) {
            /*printf("rte dequeue count: %d", packet_q_len);*/
            for (j = 0; ((j < PREFETCH_OFFSET) && (j < packet_q_len)); j++) {
                rte_prefetch0(rte_pktmbuf_mtod(rbQueue[ptv->ringBuffId][j], void *));
            }

            for (j = 0; j < (packet_q_len - PREFETCH_OFFSET); j++) {
                struct rte_mbuf *tmp = rbQueue[ptv->ringBuffId][j];
                /* Prefetch others and process prev prefetched packets */
                rte_prefetch0(rte_pktmbuf_mtod(rbQueue[ptv->ringBuffId][j + PREFETCH_OFFSET], void *));

                SCLogDebug(" User data %x ", tmp->udata64);

                p = DpdkIntelProcessPacket(ptv, tmp);
                if (NULL == p) {
                    SCLogError(SC_ERR_DPDKINTEL_SCAPI, "failed to Process to Suricata");
                    /* update counters */
                    dpdkStats[ptv->inIfaceId].sc_pkt_null++;
                    rte_pktmbuf_free(tmp);
                    continue;
                }

                SCLogDebug("Acquired Suricata Pkt %p", p);
                SCLogDebug(" mbuff %p len %u offset %u ", tmp, tmp->pkt_len, tmp->data_off);

                SET_PKT_LEN(p, tmp->pkt_len);

                /* 
                   packet data copy it will be consuming cycles and memory
                   Alternatively we pass the mbuff which contains all info
                 */
                p->dpdkIntel_mbufPtr = tmp;

#if 0
    SCLogDebug(" Forwarding frame from ring buffer!!");
    DpdkSendFrame(tmp, ptv->outIfaceId, 1);
    continue;
#endif
                SCLogDebug("Invoking thread slot process!!");
                if (unlikely(TmThreadsSlotProcessPkt(ptv->tv, ptv->slot, p) != TM_ECODE_OK)) {
                   TmqhOutputPacketpool(ptv->tv, p);
                    /* update counters */
                    dpdkStats[ptv->inIfaceId].sc_fail++;
                    rte_pktmbuf_free(tmp);
                    continue;
               }
            }

            for (; j < packet_q_len; j++) {
                struct rte_mbuf *tmp = rbQueue[ptv->ringBuffId][j];

                SCLogDebug(" User data %x ", tmp->udata64);

                p = DpdkIntelProcessPacket(ptv, tmp);
                if (NULL == p) {
                    SCLogError(SC_ERR_DPDKINTEL_SCAPI, "failed to Process to Suricata");
                    /* update counters */
                    dpdkStats[ptv->inIfaceId].sc_pkt_null++;
                    rte_pktmbuf_free(tmp);
                    continue;
                }

                SCLogDebug("Acquired Suricata Pkt %p", p);
                SCLogDebug(" mbuff %p len %u offset %u ", tmp, tmp->pkt_len, tmp->data_off);

                SET_PKT_LEN(p, tmp->pkt_len);

                /* 
                   packet data copy it will be consuming cycles and memory
                   Alternatively we pass the mbuff which contains all info
                 */
                p->dpdkIntel_mbufPtr = tmp;

#if 0
    SCLogDebug(" Forwarding frame from ring buffer!!");
    DpdkSendFrame(tmp, ptv->outIfaceId, 1);
    continue;
#endif
                SCLogDebug("Invoking thread slot process!!");
            }
        } /* dequed frames from ring buffer */

    }

#if 0
    SCLogNotice(" Forwarding frame from ring buffer!!");
    DpdkSendFrame(tmp, ptv->outIfaceId, 1);
    continue;
#endif
    SCReturnInt(TM_ECODE_OK);

}

/**
 * \brief Init function for RecieveDpdk.
 *
 * This is a setup function for recieving packets
 * via dpdk.
 *
 * \param:
 * - tv pointer to ThreadVars
 * - initdata pointer to the interface passed from the user
 * - data pointer gets populated with DpdkIntelThreadVars_t
 *
 * \retval:
 * - TM_ECODE_OK on success
 * - TM_ECODE_FAILED on error
 */
TmEcode ReceiveDpdkThreadInit(ThreadVars *tv, void *initdata, void **data) 
{
    int32_t intfId = 0;
    static uint32_t startedPorts = 0x00;

    DpdkIntelIfaceConfig_t *dpdkconf = (DpdkIntelIfaceConfig_t *) initdata;
    if (dpdkconf == NULL)
    {
        SCLogError(SC_ERR_DPDKINTEL_RECEIVE_REGISTER_FAILED, "DPDK-Intel Initialization Data absent");
        return TM_ECODE_FAILED;
    }

    if (!boolSetCpuPort) {
        portConfigured = DPDKINTEL_GENCFG.Portset;
        cpuOffset = file_config.dpdkCpuOffset;
        boolSetCpuPort = 1;
    }

    /* config file port index starts from 1 to 32 */
    /* dpdk port index starts from 0 to 31 */
    intfId = atoi(dpdkconf->iface);
    SCLogDebug(" * DPDK Interface to configure is %s %d ", dpdkconf->iface, intfId);
   
    DpdkIntelThreadVars_t *ditv = SCMalloc(sizeof(DpdkIntelThreadVars_t));
    if (unlikely(ditv == NULL))
    {
        SCLogError(SC_ERR_DPDKINTEL_RECEIVE_REGISTER_FAILED, "DPDK-Intel Thread Variables create failed!!");
        return TM_ECODE_FAILED;
    }
    memset(ditv, 0, sizeof(DpdkIntelThreadVars_t));
    ditv->tv = tv;
   
    /* config file interface is stored in interface & outIface*/ 
    ditv->interface = SCStrdup(dpdkconf->iface);
    if (unlikely(ditv->interface == NULL)) { 
        SCLogError(SC_ERR_DPDKINTEL_RECEIVE_REGISTER_FAILED, "Unable to allocate device string");
        SCReturnInt(TM_ECODE_FAILED);
    }
    ditv->outIface = SCStrdup(dpdkconf->outIface);
    if (unlikely(ditv->outIface == NULL)) { 
        SCLogError(SC_ERR_DPDKINTEL_RECEIVE_REGISTER_FAILED, "Unable to allocate output device string");
        SCReturnInt(TM_ECODE_FAILED);
    }

    /* DPDK in & out Interfaces */
    ditv->inIfaceId  = intfId;
    ditv->outIfaceId = atoi(dpdkconf->outIface);

    SCLogDebug(" ***** DPDK Ports In %d & Out %d", ditv->inIfaceId, ditv->outIfaceId);

    ditv->ringBuffId    = dpdkconf->ringBufferId;
    ditv->threads       = dpdkconf->threads;
    ditv->copy_mode     = dpdkconf->copy_mode;
    ditv->promiscous    = dpdkconf->promiscous;
    ditv->checksum_mode = dpdkconf->checksumMode;
   // ditv->ids_ports     = (DPDKINTEL_GENCFG.OpMode == IDS)?DPDKINTEL_GENCFG.Portset:0;

    *data = (void *)ditv;
#if 0
    if (!(portConfigured & (1 << (intfId)))) {
        SCLogError(SC_ERR_UNKNOWN_VALUE, "Unexpected intf %s", dpdkconf->iface);
        SCReturnInt(TM_ECODE_FAILED);
    }
#endif
    if (cpuOffset > DPDKINTEL_DEVCFG.cpus) {
        SCLogError(SC_ERR_UNKNOWN_VALUE, "Unexpected CPU offset %u for max CPU %d", 
                    cpuOffset, DPDKINTEL_DEVCFG.cpus);
        SCReturnInt(TM_ECODE_FAILED);
    }

    /* invoke for the last port in pair */
    startedPorts |= (1 << ditv->inIfaceId);
    if (startedPorts & (1 << ditv->outIfaceId)) {
        SCLogDebug(" Ring Buffer %d ", ditv->ringBuffId);
        SCLogDebug("Launching pair interface process on in %d out %d",
                   ditv->inIfaceId, ditv->outIfaceId);
        //rte_eal_remote_launch(ReceiveDpdkPackets, ditv, cpuOffset++);
 
        SCLogDebug(" ------------ Core current %u master %u", 
                    rte_lcore_id(),rte_get_master_lcore());
       
    }
    SCLogDebug("!!!!!!!!cpu Offset %d",cpuOffset);
    portConfigured = portConfigured ^ (1 << (intfId));

#if 0
    dpdkconf->DerefFunc(dpdkconf);
#endif

    SCLogDebug("completed thread initialization for dpdk receive\n");
    return TM_ECODE_OK;
}

/**
 * \brief This function prints stats to the screen at exit.
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into DpdkIntelThreadVars_t for ptv
 */
void ReceiveDpdkThreadExitStats(ThreadVars *tv, void *data) {
    DpdkIntelThreadVars_t *ditv = (DpdkIntelThreadVars_t *)data;

    DpdkIntelDumpCounters(ditv);
    SCLogInfo("(%s) Packets %" PRIu64 ", bytes %" PRIu64 "", tv->name, ditv->pkts, ditv->bytes);

    return;
}

/**
 * \brief DeInit function closes pd at exit.
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into DpdkIntelThreadVars_t for ptvi
 * \retval TM_ECODE_OK is always returned
 */
TmEcode ReceiveDpdkThreadDeinit(ThreadVars *tv, void *data)
{
    DpdkIntelThreadVars_t *ptv = (DpdkIntelThreadVars_t *)data;

    /* stop the dpdk port in use */
    dpdkPortUnSet(ptv->inIfaceId);

    if (NULL != ptv)
        SCFree(ptv);

    return TM_ECODE_OK;
}

/**
 * \brief This function passes off to link type decoders.
 *
 * DecodeDpdk reads packets from the PacketQueue. Inside of libpcap version of
 *
 * \param tv pointer to ThreadVars
 * \param p pointer to the current packet
 * \param data pointer that gets cast into DpdkIntelThreadVars_t for ptv
 * \param pq pointer to the current PacketQueue
 *
 * \todo Verify that PF_RING only deals with ethernet traffic
 *
 * \warning This function bypasses the pkt buf and len macro's
 *
 * \retval TM_ECODE_OK is always returned
 */
TmEcode DecodeDpdk(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    DecodeThreadVars *dtv = (DecodeThreadVars *)data;
    struct rte_mbuf *dptr = (struct rte_mbuf *)p->dpdkIntel_mbufPtr;

    SCLogDebug(" DecodeDpdk mbuff %p len %d plen %d", 
                 dptr, dptr->pkt_len, GET_PKT_LEN(p));

    /* XXX HACK: flow timeout can call us for injected pseudo packets
     *           see bug: https://redmine.openinfosecfoundation.org/issues/1107 */
    if (p->flags & PKT_PSEUDO_STREAM_END)
        return TM_ECODE_OK;

    /* update counters */
    StatsIncr(dtv->counter_pkts, tv->sc_perf_pca);
//    SCPerfCounterIncr(dtv->counter_pkts_per_sec, tv->sc_perf_pca);

    StatsAddUI64(dtv->counter_bytes, tv->sc_perf_pca, GET_PKT_LEN(p));
#if 0
    SCPerfCounterAddDouble(dtv->counter_bytes_per_sec, tv->sc_perf_pca, GET_PKT_LEN(p));
    SCPerfCounterAddDouble(dtv->counter_mbit_per_sec, tv->sc_perf_pca,
                           (GET_PKT_LEN(p) * 8)/1000000.0 );
#endif

    StatsAddUI64(dtv->counter_avg_pkt_size, tv->sc_perf_pca, GET_PKT_LEN(p));
    StatsSetUI64(dtv->counter_max_pkt_size, tv->sc_perf_pca, GET_PKT_LEN(p));

    /* If suri has set vlan during reading, we increase vlan counter */
    if (p->vlan_idx) {
        StatsIncr(dtv->counter_vlan, tv->sc_perf_pca);
    }

    DecodeEthernet(tv, dtv, p, ((uint8_t *)dptr->buf_addr + dptr->data_off), dptr->pkt_len, pq);

    //TODO: check return code of DecodeEthernet and release mbuf for failures.
    PacketDecodeFinalize(tv, dtv, p);

    return TM_ECODE_OK;
}

/**
 * \brief This an Init function for DecodeDpdk
 *
 * \param
   - tv pointer to ThreadVars
 * - initdata pointer to initilization data.
 * - data pointer that gets cast into DpdkIntelThreadVars_t for ptv
 * \retval
   - TM_ECODE_OK is returned on success
 * - TM_ECODE_FAILED is returned on error
 */
TmEcode DecodeDpdkThreadInit(ThreadVars *tv, void *initdata, void **data)
{
    DecodeThreadVars *dtv = NULL;

    dtv = DecodeThreadVarsAlloc(tv);

    if (dtv == NULL)
        SCReturnInt(TM_ECODE_FAILED);

    decodeTv  = tv;
    decodeDtv = dtv;

    DecodeRegisterPerfCounters(dtv, tv);

    *data = (void *)dtv;
    return TM_ECODE_OK;
}

TmEcode DecodeDpdkThreadDeinit(ThreadVars *tv, void *data)
{
    if (data != NULL)
        DecodeThreadVarsFree(tv, data);
    SCReturnInt(TM_ECODE_OK);
}

int32_t ReceiveDpdkPkts_IPS_10_100(__attribute__((unused)) void *arg)
{
    int32_t nb_rx = 0;
    int32_t enq = 0, ret = 0, j = 0;
    struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
    struct rte_eth_stats stats;

    uint32_t portBmpMap = *(uint32_t *) arg;

    SCLogNotice("============ IPS inside %s =============", __func__);
    SCLogNotice("port %u, core %u, enable %d, socket %d phy %d", 
            portBmpMap,
            rte_lcore_id(),
            rte_lcore_is_enabled(rte_lcore_id()),
            rte_lcore_to_socket_id(rte_lcore_id()),
            rte_socket_id());

    while(1)
    {
        uint8_t index = 0x00;
        uint16_t tmpMap = portBmpMap;

        if (suricata_ctl_flags & (SURICATA_STOP | SURICATA_KILL)) {
            while (tmpMap) 
            {
                if (tmpMap & 0x01) {
                    if (0 == rte_eth_stats_get(portMap [index].inport, &stats))
                        SCLogNotice("inf %u pkts RX %"PRIu64" TX %"PRIu64" MISS %"PRIu64,
                                    portMap [index].inport, 
                                    stats.ipackets, 
                                    stats.opackets, 
                                    stats.imissed);
                }
                tmpMap = tmpMap >> 1;
                index++;
            }

            break;
        } /* end of suricata_ctl_flags */

        while (tmpMap) 
        {

            if (tmpMap & 0x01) {
                uint8_t inPort   = portMap [index].inport;
                uint8_t outPort  = portMap [index].outport;
                uint16_t RingId  = 0x00;

                nb_rx = rte_eth_rx_burst(inPort, 0, pkts_burst, MAX_PKT_BURST);
                if (likely(nb_rx > 0)) {
                    SCLogDebug("Port %u Frames: %u", inPort, nb_rx);
                    if (unlikely(stats_matchPattern.totalRules == 0)) {
                        //rte_delay_us(1);
                        ret = rte_eth_tx_burst(outPort, 0, (struct rte_mbuf **)&pkts_burst, nb_rx);
                        if (unlikely ((nb_rx - ret) != 0))
                        {
                            dpdkStats [outPort].tx_err += (nb_rx - ret);

                            SCLogDebug(SC_ERR_DPDKINTEL_DPDKAPI, 
                                          "Failed to send Packet %d ret : %d",
                                          outPort, ret);

                            for (; ret < nb_rx; ret++)
                                rte_pktmbuf_free(pkts_burst[ret]);
                        }
                        continue;
                    } /* end of totalRules */

                    RingId = inPort; /* Ring Index same as port Index from DPDK */

                    if (unlikely(1 == rte_ring_full(srb [RingId]))) {
                        dpdkStats [inPort].ring_full++;
                        for (ret = 0; ret < nb_rx; ret++)
                            rte_pktmbuf_free(pkts_burst[ret]);
                        continue;
                    } /* end of ring full */

                    for (j = 0; ((j < PREFETCH_OFFSET) && (j < nb_rx)); j++) {
                        rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[j], void *));
                    }

                    for (j = 0; j < (nb_rx - PREFETCH_OFFSET); j++) {     
                        struct rte_mbuf *m = pkts_burst[j];
                        rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[j + PREFETCH_OFFSET], void *));

                        SCLogDebug("add frame to RB %u len %d for %p",
                                     RingId, m->pkt_len, m);

                        enq = rte_ring_enqueue_burst(srb [RingId], (void *)&m, 1);
                        if (unlikely(enq != 1)) {
                            dpdkStats [inPort].enq_err++;
                            SCLogDebug(
                                       " RingEnq %d core :%u full %d",
                                       enq, rte_lcore_id(),
                                       rte_ring_full(srb [RingId]));
                            rte_pktmbuf_free(m);
                            continue;
                        }
                    }

                    for (; j < nb_rx; j++) {
                        struct rte_mbuf *m = pkts_burst[j];
                        SCLogDebug("add frame to RB %u len %d for %p",
                                     RingId, m->pkt_len, m);

                        enq = rte_ring_enqueue_burst(srb [RingId], (void *)&m, 1);
                        if (unlikely(enq != 1)) {
                            dpdkStats [inPort].enq_err++;
                            SCLogDebug(
                                       " RingEnq %d core :%u full %d",
                                       enq, rte_lcore_id(),
                                       rte_ring_full(srb [RingId]));
                            rte_pktmbuf_free(m);
                            continue;
                        }
                    }
                    /* End of enqueue */
                } /* end of 1st intf*/

                nb_rx = rte_eth_rx_burst(outPort, 0, pkts_burst, MAX_PKT_BURST);
                if (likely(nb_rx > 0)) {
                    SCLogDebug("Port %u Frames: %u", outPort, nb_rx);
                    if (unlikely(stats_matchPattern.totalRules == 0)) {
                        //rte_delay_us(1);
                        ret = rte_eth_tx_burst(inPort, 0, (struct rte_mbuf **)&pkts_burst, nb_rx);
                        if (unlikely ((nb_rx - ret) != 0))
                        {
                            dpdkStats [inPort].tx_err += (nb_rx - ret);

                            SCLogDebug(SC_ERR_DPDKINTEL_DPDKAPI, 
                                          "Failed to send Packet %d ret : %d",
                                          inPort, ret);

                            for (; ret < nb_rx; ret++)
                                rte_pktmbuf_free(pkts_burst[ret]);
                        }
                        continue;
                    } /* end of totalRules */

                    RingId = outPort; /* Ring Index same as port Index from DPDK */

                    if (unlikely(1 == rte_ring_full(srb [RingId]))) {
                        dpdkStats [outPort].ring_full++;
                        for (ret = 0; ret < nb_rx; ret++)
                            rte_pktmbuf_free(pkts_burst[ret]);
                        continue;
                    } /* end of ring full */

                    for (j = 0; ((j < PREFETCH_OFFSET) && (j < nb_rx)); j++) {
                        rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[j], void *));
                    }

                    for (j = 0; j < (nb_rx - PREFETCH_OFFSET); j++) {     
                        struct rte_mbuf *m = pkts_burst[j];
                        rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[j + PREFETCH_OFFSET], void *));

                        SCLogDebug("add frame to RB %u len %d for %p",
                                     RingId, m->pkt_len, m);

                        enq = rte_ring_enqueue_burst(srb [RingId], (void *)&m, 1);
                        if (unlikely(enq != 1)) {
                            dpdkStats [outPort].enq_err++;
                            SCLogDebug(
                                       " RingEnq %d core :%u full %d",
                                       enq, rte_lcore_id(),
                                       rte_ring_full(srb [RingId]));
                            rte_pktmbuf_free(m);
                            continue;
                        }
                    } 

                    for (; j < nb_rx; j++) {
                        struct rte_mbuf *m = pkts_burst[j];

                        SCLogDebug("add frame to RB %u len %d for %p",
                                     RingId, m->pkt_len, m);

                        enq = rte_ring_enqueue_burst(srb [RingId], (void *)&m, 1);
                        if (unlikely(enq != 1)) {
                            dpdkStats [outPort].enq_err++;
                            SCLogDebug(
                                       " RingEnq %d core :%u full %d",
                                       enq, rte_lcore_id(),
                                       rte_ring_full(srb [RingId]));
                            rte_pktmbuf_free(m);
                            continue;
                        }
                    }
                    /* End of enqueue */
                } /* end of 2nd intf */
            }

            tmpMap = tmpMap >> 1;
            index++;
        }

    } /* end of while */

    return 0;
}

int32_t ReceiveDpdkPkts_IPS_1000(__attribute__((unused)) void *arg)
{
    int32_t nb_rx = 0;
    int32_t enq = 0, ret = 0, j = 0;
    struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
    struct rte_eth_stats stats;

    uint16_t inPort    = ((*(uint16_t *) arg) & 0x00FF) >> 0;
    uint16_t outPort   = ((*(uint16_t *) arg) & 0xFF00) >> 8;
    uint16_t RingId  = 0x00;

    SCLogDebug("============ IPS inside %s =============", __func__);
    SCLogNotice("port IN %u OUT %u, core %u, enable %d, socket %d phy %d", 
            inPort, outPort,
            rte_lcore_id(),
            rte_lcore_is_enabled(rte_lcore_id()),
            rte_lcore_to_socket_id(rte_lcore_id()),
            rte_socket_id());

    while(1)
    {
        if (suricata_ctl_flags & (SURICATA_STOP | SURICATA_KILL)) {
            if (0 == rte_eth_stats_get(inPort, &stats)) 
                SCLogNotice("inf %u pkts RX %"PRIu64" TX %"PRIu64" MISS %"PRIu64,
                            inPort, 
                            stats.ipackets, 
                            stats.opackets, 
                            stats.imissed);

            if (0 == rte_eth_stats_get(outPort, &stats)) 
                SCLogNotice("inf %u pkts RX %"PRIu64" TX %"PRIu64" MISS %"PRIu64,
                            outPort, 
                            stats.ipackets, 
                            stats.opackets, 
                            stats.imissed);

            break;
        } /* end of suricata_ctl_flags */

        nb_rx = rte_eth_rx_burst(inPort, 0, pkts_burst, MAX_PKT_BURST);
        if (likely(nb_rx > 0)) {
            SCLogDebug("Port %u Frames: %u", inPort, nb_rx);
            if (unlikely(stats_matchPattern.totalRules == 0)) {
                rte_delay_us(1);
                ret = rte_eth_tx_burst(outPort, 0, (struct rte_mbuf **)&pkts_burst, nb_rx);
                if (unlikely ((nb_rx - ret) != 0))
                {
                    dpdkStats [outPort].tx_err += (nb_rx - ret);

                    SCLogDebug(SC_ERR_DPDKINTEL_DPDKAPI, 
                                           "Failed to send Packet %d ret : %d",
                                            outPort, ret);

                    for (; ret < nb_rx; ret++)
                        rte_pktmbuf_free(pkts_burst[ret]);
                }
                continue;
            } /* end of totalRules */

            RingId = inPort; /* Ring Index same as port Index from DPDK */

            if (unlikely(1 == rte_ring_full(srb [RingId]))) {
                dpdkStats [inPort].ring_full++;
                for (ret = 0; ret < nb_rx; ret++)
                    rte_pktmbuf_free(pkts_burst[ret]);
                continue;
            } /* end of ring full */

            for (j = 0; ((j < nb_rx) && (j < nb_rx)); j++) {
		    rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[j], void *));
            }

            for (j = 0; j < (nb_rx - PREFETCH_OFFSET); j++) {
                struct rte_mbuf *m = pkts_burst[j];
                rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[j + PREFETCH_OFFSET], void *));

                SCLogDebug("add frame to RB %u len %d for %p",
                             RingId, m->pkt_len, m);

                enq = rte_ring_enqueue_burst(srb [RingId], (void *)&m, 1);
                if (unlikely(enq != 1)) {
                    dpdkStats [inPort].enq_err++;
                    SCLogDebug(
                               " RingEnq %d core :%u full %d",
                               enq, rte_lcore_id(),
                               rte_ring_full(srb [RingId]));
                    rte_pktmbuf_free(m);
                    continue;
                }
            }

            for (; j < nb_rx; j++) {
                struct rte_mbuf *m = pkts_burst[j];
                SCLogDebug("add frame to RB %u len %d for %p",
                             RingId, m->pkt_len, m);

                enq = rte_ring_enqueue_burst(srb [RingId], (void *)&m, 1);
                if (unlikely(enq != 1)) {
                    dpdkStats [inPort].enq_err++;
                    SCLogDebug(
                               " RingEnq %d core :%u full %d",
                               enq, rte_lcore_id(),
                               rte_ring_full(srb [RingId]));
                    rte_pktmbuf_free(m);
                    continue;
                }
            }
            /* End of enqueue */
        } /* end of 1st intf*/

        nb_rx = rte_eth_rx_burst(outPort, 0, pkts_burst, MAX_PKT_BURST);
        if (likely(nb_rx > 0)) {
            SCLogDebug("Port %u Frames: %u", outPort, nb_rx);
            if (unlikely(stats_matchPattern.totalRules == 0)) {
                rte_delay_us(1);
                ret = rte_eth_tx_burst(inPort, 0, (struct rte_mbuf **)&pkts_burst, nb_rx);
                if (unlikely ((nb_rx - ret) != 0))
                {
                    dpdkStats [inPort].tx_err += (nb_rx - ret);

                    SCLogDebug(SC_ERR_DPDKINTEL_DPDKAPI, 
                                           "Failed to send Packet %d ret : %d",
                                            inPort, ret);

                    for (; ret < nb_rx; ret++)
                        rte_pktmbuf_free(pkts_burst[ret]);
                }
                continue;
            } /* end of totalRules */

            RingId = outPort; /* Ring Index same as port Index from DPDK */

            if (unlikely(1 == rte_ring_full(srb [RingId]))) {
                dpdkStats [outPort].ring_full++;
                for (ret = 0; ret < nb_rx; ret++)
                    rte_pktmbuf_free(pkts_burst[ret]);
                continue;
            } /* end of ring full */

            for (j = 0; ((j < PREFETCH_OFFSET) && (j < nb_rx)); j++) {
                rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[j], void *));
            }

            for (j = 0; j < (nb_rx - PREFETCH_OFFSET); j++) {
                struct rte_mbuf *m = pkts_burst[j];
                rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[j + PREFETCH_OFFSET], void *));

                SCLogDebug("add frame to RB %u len %d for %p",
                             RingId, m->pkt_len, m);

                enq = rte_ring_enqueue_burst(srb [RingId], (void *)&m, 1);
                if (unlikely(enq != 1)) {
                    dpdkStats [outPort].enq_err++;
                    SCLogDebug(
                               " RingEnq %d core :%u full %d",
                               enq, rte_lcore_id(),
                               rte_ring_full(srb [RingId]));
                    rte_pktmbuf_free(m);
                    continue;
                }
            } 

            for (; j < nb_rx; j++) {
                struct rte_mbuf *m = pkts_burst[j];

                SCLogDebug("add frame to RB %u len %d for %p",
                             RingId, m->pkt_len, m);

                enq = rte_ring_enqueue_burst(srb [RingId], (void *)&m, 1);
                if (unlikely(enq != 1)) {
                    dpdkStats [outPort].enq_err++;
                    SCLogDebug(
                               " RingEnq %d core :%u full %d",
                               enq, rte_lcore_id(),
                               rte_ring_full(srb [RingId]));
                    rte_pktmbuf_free(m);
                    continue;
                }
            }
            /* End of enqueue */
        }

    } /* end of while */

    return 0;
}

int32_t ReceiveDpdkPkts_IPS_10000(__attribute__((unused)) void *arg)
{
    int32_t nb_rx = 0;
    int32_t enq = 0;
    int32_t ret = 0, j = 0;
    struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
    struct rte_eth_stats stats;

    uint16_t inPort  = ((*(uint16_t *) arg) & 0x00FF) >> 0;
    uint16_t outPort = ((*(uint16_t *) arg) & 0xFF00) >> 8;
    uint16_t ringId  = inPort; /* ringID as same as input port number*/

    SCLogNotice("============ IPS inside %s =============", __func__);
    SCLogNotice(" port %u, core %u, enable %d, socket %d phy %d", 
            inPort,
            rte_lcore_id(),
            rte_lcore_is_enabled(rte_lcore_id()),
            rte_lcore_to_socket_id(rte_lcore_id()),
            rte_socket_id());

    while(1)
    {
        if (suricata_ctl_flags & (SURICATA_STOP | SURICATA_KILL)) {
            if (0 == rte_eth_stats_get(inPort, &stats)) {
                SCLogNotice("inf %u pkts RX %"PRIu64" TX %"PRIu64" MISS %"PRIu64,
                            inPort, 
                            stats.ipackets, 
                            stats.opackets, 
                            stats.imissed);
            }

            break;
        } /* end of suricata_ctl_flags */

        nb_rx = rte_eth_rx_burst(inPort, 0, pkts_burst, MAX_PKT_BURST);
        if (likely(nb_rx > 0)) {
            SCLogDebug("Port %u Frames: %u", inPort, nb_rx);

            if (unlikely(stats_matchPattern.totalRules == 0)) {
                //rte_delay_us(1);
                ret = rte_eth_tx_burst(outPort, 0, (struct rte_mbuf **)&pkts_burst, nb_rx);
                if (unlikely ((nb_rx - ret) != 0))
                {
                    dpdkStats [outPort].tx_err += (nb_rx - ret);

                    SCLogDebug(SC_ERR_DPDKINTEL_DPDKAPI, 
                                           "Failed to send Packet %d ret : %d",
                                            outPort, ret);

                    for (; ret < nb_rx; ret++)
                        rte_pktmbuf_free(pkts_burst[ret]);
                }
                continue;
            } /* end of totalRules */

            if (unlikely(1 == rte_ring_full(srb [ringId]))) {
                dpdkStats [inPort].ring_full++;
                for (ret = 0; ret < nb_rx; ret++)
                    rte_pktmbuf_free(pkts_burst[ret]);
                continue;
            } /* end of ring full */

            for (j = 0; ((j < PREFETCH_OFFSET) && (j < nb_rx)); j++) {
                rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[j], void *));
            }

            for (j = 0; j < (nb_rx - PREFETCH_OFFSET); j++) {
                struct rte_mbuf *m = pkts_burst[j];
                rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[j + PREFETCH_OFFSET], void *));

                SCLogDebug("add frame to RB %u len %d for %p",
                             ringId, m->pkt_len, m);

                enq = rte_ring_enqueue_burst(srb [ringId], (void *)&m, 1);
                if (unlikely(enq != 1)) {
                    dpdkStats [inPort].enq_err++;
                    SCLogDebug(
                               " RingEnq %d core :%u full %d",
                               enq, rte_lcore_id(),
                               rte_ring_full(srb [ringId]));
                    rte_pktmbuf_free(m);
                    continue;
                }
            } 

            for (; j < PREFETCH_OFFSET; j++) {
                struct rte_mbuf *m = pkts_burst[j];

                SCLogDebug("add frame to RB %u len %d for %p",
                             ringId, m->pkt_len, m);

                enq = rte_ring_enqueue_burst(srb [ringId], (void *)&m, 1);
                if (unlikely(enq != 1)) {
                    dpdkStats [inPort].enq_err++;
                    SCLogDebug(
                               " RingEnq %d core :%u full %d",
                               enq, rte_lcore_id(),
                               rte_ring_full(srb [ringId]));
                    rte_pktmbuf_free(m);
                    continue;
                }
            } 
            /* End of enqueue */
        }
    } /* end of while */

    return 0;
}

int32_t ReceiveDpdkPkts_IPS(__attribute__((unused)) void *arg)
{
    return 0;
}

int32_t ReceiveDpdkPkts_IDS(__attribute__((unused)) void *arg)
{
    SCLogNotice("Frame Parser for IDS Mode");
    int32_t nb_rx = 0;
    int32_t enq = 0, portIndex;
    int32_t ret = 0, j = 0;
    struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
    struct rte_eth_stats stats;

    SCLogNotice(" ports %x, core %u, enble %d, scket %d phy %d", 
            DPDKINTEL_GENCFG.Port/* port count */, rte_lcore_id(),
            rte_lcore_is_enabled(rte_lcore_id()),
            rte_lcore_to_socket_id(rte_lcore_id()),
            rte_socket_id());

    if (unlikely(DPDKINTEL_GENCFG.Port == 0))
    {
        SCLogError(SC_ERR_DPDKINTEL_CONFIG_FAILED, "No Ports for IDS mode");
        return -1;
    }


    while(1) {
        if (suricata_ctl_flags & (SURICATA_STOP | SURICATA_KILL)) {
            for (portIndex = 0; portIndex < DPDKINTEL_GENCFG.Port; portIndex++)
            {
                if (0 == rte_eth_stats_get(portMap [portIndex].inport, &stats)) {
                    SCLogNotice("port  %u pkts RX %"PRIu64" TX %"PRIu64" MISS %"PRIu64
                                "ring full %"PRIu64" enq err %"PRIu64" tx err %"PRIu64
                                "SC Pkt fail %"PRIu64" SC Process Fail %"PRIu64,
                                portMap [portIndex].inport, stats.ipackets, 
                                stats.opackets, stats.imissed,
                                dpdkStats [portMap [portIndex].inport].ring_full,
                                dpdkStats[portMap [portIndex].inport].enq_err,
                                dpdkStats[portMap [portIndex].outport].tx_err,
                                dpdkStats[portMap [portIndex].inport].sc_pkt_null,
                                dpdkStats[portMap [portIndex].inport].sc_fail);
                }
            }

            SCReturnInt(TM_ECODE_OK);
        }

        for (portIndex = 0; portIndex < DPDKINTEL_GENCFG.Port; portIndex++)
        {
            nb_rx = rte_eth_rx_burst(portMap [portIndex].inport, 0, pkts_burst, MAX_PKT_BURST);
            if (likely(nb_rx > 0)) {
                SCLogDebug("Port %u Frames: %u", portId[index], nb_rx);

                if (unlikely(stats_matchPattern.totalRules == 0))
                {
                    ret = 0;
                    while (ret < nb_rx)
                    {
                        rte_pktmbuf_free(pkts_burst[ret]);
                        ret++;
                    }
                    continue;
                }

                if (unlikely(1 == rte_ring_full(srb [portMap [portIndex].ringid]))) {
                    dpdkStats [portMap [portIndex].inport].ring_full++;
                    for (ret = 0; ret < nb_rx; ret++)
                    {
                        rte_pktmbuf_free(pkts_burst[ret]);
                    }
                    continue;
                }

                for (j = 0; ((j < PREFETCH_OFFSET) && (j < nb_rx)); j++) {
                    rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[j], void *));
                }

                for (j = 0; j < (nb_rx - PREFETCH_OFFSET); j++) {
                    struct rte_mbuf *m = pkts_burst[j];
                    rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[j + PREFETCH_OFFSET], void *));

                    SCLogDebug("add frame to RB %u len %d for %p",
                                 portMap [portIndex].ringid, m->pkt_len, m);

                    /* ToDo: update the stats under Debug mode */

                    enq = rte_ring_enqueue_burst(srb [portMap [portIndex].ringid], (void *)&m, 1);
                    if (unlikely(enq != 1)) {
                        dpdkStats [portMap [portIndex].inport].enq_err++;
                        SCLogDebug(
                                   " RingEnq %d core :%u full %d",
                                   enq, rte_lcore_id(),
                                   rte_ring_full(srb [portMap [portIndex].ringid]));
                        rte_pktmbuf_free(m);
                        continue;
                    }
                }

                for (; j < nb_rx; j++) {
                    struct rte_mbuf *m = pkts_burst[j];

                    SCLogDebug("add frame to RB %u len %d for %p",
                                 portMap [portIndex].ringid, m->pkt_len, m);

                    /* ToDo: update the stats under Debug mode */

                    enq = rte_ring_enqueue_burst(srb [portMap [portIndex].ringid], (void *)&m, 1);
                    if (unlikely(enq != 1)) {
                        dpdkStats [portMap [portIndex].inport].enq_err++;
                        SCLogDebug(
                                   " RingEnq %d core :%u full %d",
                                   enq, rte_lcore_id(),
                                   rte_ring_full(srb [portMap [portIndex].ringid]));
                        rte_pktmbuf_free(m);
                        continue;
                    }
                }
            }
        }
    }

    return 0;
}

int32_t ReceiveDpdkPkts_BYPASS(__attribute__((unused)) void *arg)
{
    uint8_t portIndex;
    int32_t nb_rx = 0, ret = 0;
    struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
    struct rte_eth_stats stats;

    SCLogNotice(" BYPASS: ports %u, core %u, enble %d, scket %d phy %d", 
            DPDKINTEL_GENCFG.Port, rte_lcore_id(),
            rte_lcore_is_enabled(rte_lcore_id()),
            rte_lcore_to_socket_id(rte_lcore_id()),
            rte_socket_id());

    while (1) {
        if (suricata_ctl_flags & (SURICATA_STOP | SURICATA_KILL)) {
            for (portIndex = 0; portIndex < DPDKINTEL_GENCFG.Port; portIndex++) 
            {
                if (0 == rte_eth_stats_get(portMap [portIndex].inport, &stats)) {
                    SCLogNotice("port In %u pkt in %"PRIu64" out %"PRIu64" miss %"PRIu64,
                            portMap [portIndex].inport, 
                            stats.ipackets, stats.opackets, stats.imissed);
                }
            }
            
            SCReturnInt(TM_ECODE_OK);
        }

        for (portIndex = 0; portIndex < DPDKINTEL_GENCFG.Port; portIndex++) 
        {
            nb_rx = rte_eth_rx_burst(portMap [portIndex].inport, 0, pkts_burst, MAX_PKT_BURST);
            if (likely(nb_rx > 0)) {
                SCLogDebug("Port %u Frames: %u", portMap [portIndex].inport, nb_rx);

                rte_delay_us(1);
                ret = rte_eth_tx_burst(portMap [portIndex].outport, 0, (struct rte_mbuf **)&pkts_burst, nb_rx);
                if (unlikely ((nb_rx - ret) != 0))
                {
                    /* Update Counters */
                    dpdkStats [portMap [portIndex].outport].tx_err += (nb_rx - ret);
                    SCLogDebug(SC_ERR_DPDKINTEL_DPDKAPI, 
                               "Failed to send Packet %d ret : %d", 
                               portMap [portIndex].outport, ret);
                    for (; ret < nb_rx; ret++)
                    {
                        rte_pktmbuf_free(pkts_burst[ret]);
                    }
                }
                continue;
            }
        }
    }

    return 0;
}

int32_t launchDpdkFrameParser(void)
{
    uint16_t portIndexBmp_10_100 = 0x00;
    uint16_t portIndexBmp_1000   = 0x00;
    uint16_t portIndexBmp_10000  = 0x00;

    uint16_t portIndex = 0x00;

    uint32_t reqCores = 0x00, availCores = 0x00;
    struct rte_eth_link linkSpeed;

    SCLogDebug(" Core current %u master %u",
               rte_lcore_id(),rte_get_master_lcore());

    if (rte_lcore_id() != rte_get_master_lcore()) {
        SCLogError(SC_ERR_DPDKINTEL_CONFIG_FAILED,
                   " DPDK should be started in master core only!!"
                   " Core current %u master %u",
                   rte_lcore_id(),rte_get_master_lcore());
        exit(EXIT_FAILURE);
    }

    /* check if enough dpdk core are available to launch for interfaces */
    if (portSpeed10 | portSpeed100)
    {
        SCLogDebug(" 10 or 100");
        reqCores++;
    }

    if (portSpeed10000)
    {
        SCLogDebug(" 10000");
        reqCores += portSpeed10000;
    }

    if (portSpeed1000) 
    {
        SCLogDebug(" 1000");
        reqCores = portSpeed1000/2;
        if (portSpeed1000 & 0x01) /* check if remainder is present */
            reqCores++;
    }
    availCores = getCpuCOunt(getDpdkIntelCpu());

    SCLogDebug(" ----------- DPDK INTEL req: %u avail: %u", reqCores, availCores);
    if (availCores < reqCores)
    {
        SCLogError(SC_ERR_DPDKINTEL_CONFIG_FAILED, "DPDK cores insufficent!!");
        exit(EXIT_FAILURE);
    }

    /* fetch the interface speed to set to desired bit map */
    for (reqCores = 0; reqCores < DPDKINTEL_GENCFG.Port; reqCores++)
    {
        rte_eth_link_get_nowait(portMap[portIndex].inport, &linkSpeed);
        //rte_eth_link_get(portMap[portIndex].inport, &linkSpeed);
        if ((portSpeed10 | portSpeed100) &&
        #if RTE_VER_RELEASE < 16
            ((linkSpeed.link_speed == ETH_LINK_SPEED_10) ||
             (linkSpeed.link_speed == ETH_LINK_SPEED_100)) 
        #else
            ((linkSpeed.link_speed == ETH_SPEED_NUM_10M) ||
             (linkSpeed.link_speed == ETH_SPEED_NUM_100M)) 
        #endif
           )
        {
            portIndexBmp_10_100 =  portIndexBmp_10_100 | (1 << reqCores);
        }
        else if ((portSpeed10000) &&
        #if RTE_VER_RELEASE < 16
                 (linkSpeed.link_speed == ETH_LINK_SPEED_10G)
        #else
                 (linkSpeed.link_speed == ETH_SPEED_NUM_10G)
        #endif
                )
        {
            portIndexBmp_10000 =  portIndexBmp_10000 | (1 << reqCores);
        }
        else if ((portSpeed1000) &&
        #if RTE_VER_RELEASE < 16
                 (linkSpeed.link_speed == ETH_LINK_SPEED_1000)
        #else
                 (linkSpeed.link_speed == ETH_SPEED_NUM_1G)
        #endif
                )
        {
            portIndexBmp_1000 =  portIndexBmp_1000 | (1 << reqCores);
        }
        else
        {
            SCLogError(SC_ERR_DPDKINTEL_CONFIG_FAILED, "Unknown speed %d for Intf %u", linkSpeed.link_speed, portMap[portIndex].inport);
            exit(EXIT_FAILURE);
        }
    }

    SCLogDebug("10-100 Mb/s %x", portIndexBmp_10_100);
    SCLogDebug("1000 Mb/s %x", portIndexBmp_1000);
    SCLogDebug("10000 Mb/s %x", portIndexBmp_10000);

    /* ToDo: use function pointer array to invoke for IDS|IPS */

    /* launch logic per interface speed for operation mode */
    if (DPDKINTEL_GENCFG.OpMode == IPS) {

        if (portIndexBmp_10_100)
            rte_eal_remote_launch(ReceiveDpdkPkts_IPS_10_100, 
                                  &portIndexBmp_10_100,  getCpuIndex());

        if (portIndexBmp_1000)
        {
            uint32_t portBmpSet = 0x00, ports = 0x00;

            portIndex = 0x00;
            while (portIndexBmp_1000)
            {
                if (portIndexBmp_1000 & 0x01) 
                {
                    if (!(portBmpSet & (1 << portMap[portIndex].inport | 
                                        1 << portMap[portIndex].outport)))
                    {
                        ports = (portMap[portIndex].inport << 0 )| 
                                (portMap[portIndex].outport << 8);

                        SCLogDebug(" Ports In-Out %x", ports);

                        rte_eal_remote_launch(ReceiveDpdkPkts_IPS_1000, 
                                  &ports, getCpuIndex());

                        portBmpSet = portBmpSet | ((1 << portMap[portIndex].inport) |
                                                   (1 << portMap[portIndex].outport));
                    }

                }

                portIndexBmp_1000 = portIndexBmp_1000 >> 1;
                portIndex++;
            }
        }

        if (portIndexBmp_10000)
        {
            portIndex = 0x00;
            while (portIndexBmp_10000)
            {
                if (portIndexBmp_10000 & 0x01)
                    rte_eal_remote_launch(ReceiveDpdkPkts_IPS_10000, 
                                   &portMap[portIndex].inport,  getCpuIndex());

                portIndexBmp_10000 = portIndexBmp_10000 >> 1;
                portIndex++;
            }
        }

        SCLogNotice("DPDK Started in IPS Mode!!!");
    }
    else if (DPDKINTEL_GENCFG.OpMode == IDS) {
        if (portIndexBmp_10_100)
            rte_eal_remote_launch(ReceiveDpdkPkts_IDS, 
                                  &portIndexBmp_10_100, getCpuIndex());
        if (portIndexBmp_1000)
            rte_eal_remote_launch(ReceiveDpdkPkts_IDS, 
                                  &portIndexBmp_1000, getCpuIndex());
        if (portIndexBmp_10000)
            rte_eal_remote_launch(ReceiveDpdkPkts_IDS, 
                                  &portIndexBmp_10000, getCpuIndex());
        SCLogNotice("DPDK Started in IDS Mode!!!");
    }
    else if (DPDKINTEL_GENCFG.OpMode == BYPASS) {
        if (portIndexBmp_10_100)
            rte_eal_remote_launch(ReceiveDpdkPkts_BYPASS, 
                                  &portIndexBmp_10_100, getCpuIndex());
        if (portIndexBmp_1000)
            rte_eal_remote_launch(ReceiveDpdkPkts_BYPASS, 
                                  &portIndexBmp_1000, getCpuIndex());
        if (portIndexBmp_10000)
            rte_eal_remote_launch(ReceiveDpdkPkts_BYPASS, 
                                  &portIndexBmp_10000, getCpuIndex());
        SCLogNotice("DPDK Started in BYPASS Mode!!!");
    }
    return 0;
}

#endif /* HAVE_DPDKINTEL */
/* eof */
