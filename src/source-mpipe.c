/* Copyright (C) 2013 Open Information Security Foundation
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
 * \author Tom DeCanio <decanio.tom@gmail.com>
 * \author Tilera Corporation <suricata@tilera.com>
 *
 * Tilera TILE-Gx mpipe ingress packet support.
 */

#include "suricata-common.h"
#include "suricata.h"
#include "host.h"
#include "decode.h"
#include "packet-queue.h"
#include "threads.h"
#include "threadvars.h"
#include "tm-queuehandlers.h"
#include "tm-threads.h"
#include "runmode-tile.h"
#include "source-mpipe.h"
#include "conf.h"
#include "util-debug.h"
#include "util-error.h"
#include "util-privs.h"
#include "util-device.h"
#include "util-mem.h"
#include "util-profiling.h"
#include "tmqh-packetpool.h"
#include "pkt-var.h"

#ifdef HAVE_MPIPE

#include <mde-version.h>
#include <tmc/alloc.h>
#include <arch/sim.h>
#include <arch/atomic.h>
#include <arch/cycle.h>
#include <gxio/mpipe.h>
#include <gxio/trio.h>
#if MDE_VERSION_CODE >= MDE_VERSION(4,1,0)
#include <gxpci/gxpci.h>
#else
#include <gxpci.h>
#endif
#include <tmc/cpus.h>
#include <tmc/spin.h>
#include <tmc/sync.h>
#include <tmc/task.h>
#include <tmc/perf.h>
#include <arch/sim.h>

/* Align "p" mod "align", assuming "p" is a "void*". */
#define ALIGN(p, align) do { (p) += -(long)(p) & ((align) - 1); } while(0)

#define VERIFY(VAL, WHAT)                                       \
    do {                                                        \
        int __val = (VAL);                                      \
        if (__val < 0)                                          \
            tmc_task_die("Failure in '%s': %d: %s.",            \
                         (WHAT), __val, gxio_strerror(__val));  \
    } while (0)

#define VERIFY_GXPCI(VAL, WHAT)                                 \
    do {                                                        \
        int __val = (VAL);                                      \
        if (__val < 0)                                          \
            tmc_task_die("Failure in '%s': %d: %s.",            \
                         (WHAT), __val, gxpci_strerror(__val)); \
    } while (0)

#define min(a,b) (((a) < (b)) ? (a) : (b))
#define max(a,b) (((a) > (b)) ? (a) : (b))

extern uint8_t suricata_ctl_flags;
size_t tile_vhuge_size;
static void *packet_page = NULL;

/** storage for mpipe device names */
typedef struct MpipeDevice_ {
    char *dev;  /**< the device (e.g. "xgbe1") */
    TAILQ_ENTRY(MpipeDevice_) next;
} MpipeDevice;


/** private device list */
static TAILQ_HEAD(, MpipeDevice_) mpipe_devices =
    TAILQ_HEAD_INITIALIZER(mpipe_devices);

static uint16_t first_stack;
static uint32_t headroom = 2;

/**
 * \brief Structure to hold thread specific variables.
 */
typedef struct MpipeThreadVars_
{
    /* data link type for the thread */
    int datalink;

    ChecksumValidationMode checksum_mode;

    /* counters */
    uint32_t pkts;
    uint64_t bytes;
    uint32_t errs;

    ThreadVars *tv;
    TmSlot *slot;

    Packet *in_p;

    /** stats/counters */
    uint16_t max_mpipe_depth;
    uint16_t mpipe_drop;
    uint16_t counter_no_buffers_0;
    uint16_t counter_no_buffers_1;
    uint16_t counter_no_buffers_2;
    uint16_t counter_no_buffers_3;
    uint16_t counter_no_buffers_4;
    uint16_t counter_no_buffers_5;
    uint16_t counter_no_buffers_6;
    uint16_t counter_no_buffers_7;

} MpipeThreadVars;

TmEcode ReceiveMpipeLoop(ThreadVars *tv, void *data, void *slot);
TmEcode ReceiveMpipeThreadInit(ThreadVars *, void *, void **);
void ReceiveMpipeThreadExitStats(ThreadVars *, void *);

TmEcode DecodeMpipeThreadInit(ThreadVars *, void *, void **);
TmEcode DecodeMpipe(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);

/* Assumes Only 10G links (interfaces) are used. */
#define MAX_CHANNELS 32   /* can probably find this in the MDE */

/*
 * mpipe configuration.
 */

/* The mpipe context (shared by all workers) */
static gxio_mpipe_context_t context_body;
static gxio_mpipe_context_t* context = &context_body;

/* The ingress queues (one per worker) */
static gxio_mpipe_iqueue_t** iqueues;

/* The egress queues (one per port) */
static gxio_mpipe_equeue_t equeue_body[MAX_CHANNELS];
static gxio_mpipe_equeue_t *equeue[MAX_CHANNELS];

/* the number of entries in an equeue ring */
static const int equeue_entries = 2048;

/* Array of mpipe links */
static gxio_mpipe_link_t mpipe_link[MAX_CHANNELS];

/* Per interface configuration data */
static MpipeIfaceConfig *mpipe_conf[MAX_CHANNELS];

/* Per interface TAP/IPS configuration */

/* egress equeue associated with each ingress channel */
static MpipePeerVars channel_to_equeue[MAX_CHANNELS];

/**
 * \brief Registration Function for ReceiveMpipe.
 * \todo Unit tests are needed for this module.
 */
void TmModuleReceiveMpipeRegister (void)
{
    tmm_modules[TMM_RECEIVEMPIPE].name = "ReceiveMpipe";
    tmm_modules[TMM_RECEIVEMPIPE].ThreadInit = ReceiveMpipeThreadInit;
    tmm_modules[TMM_RECEIVEMPIPE].Func = NULL;
    tmm_modules[TMM_RECEIVEMPIPE].PktAcqLoop = ReceiveMpipeLoop;
    tmm_modules[TMM_RECEIVEMPIPE].ThreadExitPrintStats = ReceiveMpipeThreadExitStats;
    tmm_modules[TMM_RECEIVEMPIPE].ThreadDeinit = NULL;
    tmm_modules[TMM_RECEIVEMPIPE].RegisterTests = NULL;
    tmm_modules[TMM_RECEIVEMPIPE].cap_flags = SC_CAP_NET_RAW;
    tmm_modules[TMM_RECEIVEMPIPE].flags = TM_FLAG_RECEIVE_TM;
}

/**
 * \brief Registraction Function for DecodeNetio.
 * \todo Unit tests are needed for this module.
 */
void TmModuleDecodeMpipeRegister (void)
{
    tmm_modules[TMM_DECODEMPIPE].name = "DecodeMpipe";
    tmm_modules[TMM_DECODEMPIPE].ThreadInit = DecodeMpipeThreadInit;
    tmm_modules[TMM_DECODEMPIPE].Func = DecodeMpipe;
    tmm_modules[TMM_DECODEMPIPE].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODEMPIPE].ThreadDeinit = NULL;
    tmm_modules[TMM_DECODEMPIPE].RegisterTests = NULL;
    tmm_modules[TMM_DECODEMPIPE].cap_flags = 0;
    tmm_modules[TMM_DECODEMPIPE].flags = TM_FLAG_DECODE_TM;
}

void MpipeFreePacket(void *arg)
{
    Packet *p = (Packet *)arg;
    int result;
    gxio_mpipe_iqueue_t* iqueue = iqueues[p->mpipe_v.rank];
    int bucket = p->mpipe_v.idesc.bucket_id;
    gxio_mpipe_credit(iqueue->context, iqueue->ring, bucket, 1);
    if (unlikely(p->mpipe_v.copy_mode == MPIPE_COPY_MODE_IPS)) {
        if (unlikely(p->action & ACTION_DROP)) {
            goto drop;
        }
        gxio_mpipe_edesc_t edesc;
        edesc.words[0] = 0;
        edesc.words[1] = 0;
        edesc.bound = 1;
        edesc.xfer_size = p->mpipe_v.idesc.l2_size;
        edesc.va = p->mpipe_v.idesc.va;
        edesc.stack_idx = p->mpipe_v.idesc.stack_idx;
        edesc.hwb = 1;
        edesc.size = p->mpipe_v.idesc.size;
        int channel = p->mpipe_v.idesc.channel;
        result = gxio_mpipe_equeue_put(channel_to_equeue[channel].peer_equeue, edesc);
        if (unlikely(result != 0)) {
            SCLogInfo("mpipe equeue put failed: %d", result);
        }
    } else if (unlikely(p->mpipe_v.copy_mode == MPIPE_COPY_MODE_TAP)) {
        gxio_mpipe_edesc_t edesc;
        edesc.words[0] = 0;
        edesc.words[1] = 0;
        edesc.bound = 1;
        edesc.xfer_size = p->mpipe_v.idesc.l2_size;
        edesc.va = p->mpipe_v.idesc.va;
        edesc.stack_idx = p->mpipe_v.idesc.stack_idx;
        edesc.hwb = 1;
        edesc.size = p->mpipe_v.idesc.size;
        int channel = p->mpipe_v.idesc.channel;
        result = gxio_mpipe_equeue_put(channel_to_equeue[channel].peer_equeue, edesc);
        if (unlikely(result != 0)) {
            SCLogInfo("mpipe equeue put failed: %d", result);
        }
    } else {
drop:
        gxio_mpipe_push_buffer(context,
                               p->mpipe_v.idesc.stack_idx,
                               (void*)(intptr_t)p->mpipe_v.idesc.va);
    }
}

/**
 * \brief Mpipe Packet Process function.
 *
 * This function fills in our packet structure from mpipe.
 * From here the packets are picked up by the  DecodeMpipe thread.
 *
 * \param user pointer to MpipeThreadVars passed from pcap_dispatch
 * \param h pointer to gxio packet header
 * \param pkt pointer to current packet
 */
static inline 
Packet *MpipeProcessPacket(MpipeThreadVars *ptv, gxio_mpipe_idesc_t *idesc)
{
    int caplen = idesc->l2_size;
    u_char *pkt = gxio_mpipe_idesc_get_va(idesc);
    Packet *p = (Packet *)(pkt - sizeof(Packet) - headroom/*2*/);

    PACKET_RECYCLE(p);
    PKT_SET_SRC(p, PKT_SRC_WIRE);

    ptv->bytes += caplen;
    ptv->pkts++;

    gettimeofday(&p->ts, NULL);

    p->datalink = ptv->datalink;
    SET_PKT_LEN(p, caplen);
    p->pkt = pkt;

    /* copy only the fields we use later */
    p->mpipe_v.idesc.bucket_id = idesc->bucket_id;
    p->mpipe_v.idesc.nr = idesc->nr;
    p->mpipe_v.idesc.cs = idesc->cs;
    p->mpipe_v.idesc.va = idesc->va;
    p->mpipe_v.idesc.stack_idx = idesc->stack_idx;
    if (unlikely((p->mpipe_v.copy_mode = channel_to_equeue[idesc->channel].copy_mode) !=
             MPIPE_COPY_MODE_NONE)) {
        p->mpipe_v.idesc.size = idesc->size;
        p->mpipe_v.idesc.l2_size = idesc->l2_size;
        p->mpipe_v.idesc.channel = idesc->channel;
    }

    if (ptv->checksum_mode == CHECKSUM_VALIDATION_DISABLE)
        p->flags |= PKT_IGNORE_CHECKSUM;

    return p;
}

static uint16_t xlate_stack(MpipeThreadVars *ptv, int stack_idx)
{
    uint16_t counter;

    switch(stack_idx - first_stack) {
    case 0:
        counter = ptv->counter_no_buffers_0;
        break;
    case 1:
        counter = ptv->counter_no_buffers_1;
        break;
    case 2:
        counter = ptv->counter_no_buffers_2;
        break;
    case 3:
        counter = ptv->counter_no_buffers_3;
        break;
    case 4:
        counter = ptv->counter_no_buffers_4;
        break;
    case 5:
        counter = ptv->counter_no_buffers_5;
        break;
    case 6:
        counter = ptv->counter_no_buffers_6;
        break;
    case 7:
        counter = ptv->counter_no_buffers_7;
        break;
    default:
        counter = ptv->counter_no_buffers_7;
        break;
    }
    return counter;
}

/**
 * \brief Receives packets from an interface via gxio mpipe.
 */
TmEcode ReceiveMpipeLoop(ThreadVars *tv, void *data, void *slot)
{
    MpipeThreadVars *ptv = (MpipeThreadVars *)data;
    TmSlot *s = (TmSlot *)slot;
    ptv->slot = s->slot_next;
    Packet *p = NULL;
    int cpu = tmc_cpus_get_my_cpu();
    int rank = cpu - 1;
    int max_queued = 0;
    char *ctype;

    SCEnter();

    ptv->checksum_mode = CHECKSUM_VALIDATION_DISABLE;
    if (ConfGet("mpipe.checksum-checks", &ctype) == 1) {
        if (strcmp(ctype, "yes") == 0) {
            ptv->checksum_mode = CHECKSUM_VALIDATION_ENABLE;
        } else if (strcmp(ctype, "no") == 0)  {
            ptv->checksum_mode = CHECKSUM_VALIDATION_DISABLE;
        } else {
            SCLogError(SC_ERR_INVALID_ARGUMENT, 
                       "Invalid value for checksum-check for mpipe");
        }
    }

    gxio_mpipe_iqueue_t* iqueue = iqueues[rank];

    for (;;) {
        if (suricata_ctl_flags & (SURICATA_STOP | SURICATA_KILL)) {
            SCReturnInt(TM_ECODE_FAILED);
        }

        gxio_mpipe_idesc_t *idesc;

        int n = gxio_mpipe_iqueue_try_peek(iqueue, &idesc);
        if (likely(n > 0)) {
            int i;
          
            int m = min(n, 16);

            /* Prefetch the idescs (64 bytes each). */
            for (i = 0; i < m; i++) {
                __insn_prefetch(&idesc[i]);
            }
            if (unlikely(n > max_queued)) {
                SCPerfCounterSetUI64(ptv->max_mpipe_depth,
                                     tv->sc_perf_pca,
                                     (uint64_t)n);
                max_queued = n;
            }
            for (i = 0; i < m; i++, idesc++) {
                if (likely(!gxio_mpipe_idesc_has_error(idesc))) {
                    p = MpipeProcessPacket(ptv, idesc);
                    p->mpipe_v.rank = rank;
                    TmThreadsSlotProcessPkt(ptv->tv, ptv->slot, p);
                } else {
                    if (idesc->be) {
                      /* Buffer Error - No buffer available, so mPipe
                       * dropped the packet. */
                      SCPerfCounterIncr(xlate_stack(ptv, idesc->stack_idx),
                                        tv->sc_perf_pca);
                    } else {
                      /* Bad packet. CRC error */
                        SCPerfCounterIncr(ptv->mpipe_drop, tv->sc_perf_pca);
                        gxio_mpipe_iqueue_drop(iqueue, idesc);
                    }
                    gxio_mpipe_iqueue_release(iqueue, idesc);
                }
            }
            // Move forward M packets in ingress ring.
            gxio_mpipe_iqueue_advance(iqueue, m);
        }
        SCPerfSyncCountersIfSignalled(tv, 0);
    }

    SCReturnInt(TM_ECODE_OK);
}

TmEcode MpipeRegisterPipeStage(void *td)
{
    SCEnter();

    SCReturnInt(TM_ECODE_OK);
}

static void MpipeRegisterPerfCounters(MpipeThreadVars *ptv, ThreadVars *tv)
{
    /* register counters */
    ptv->max_mpipe_depth = SCPerfTVRegisterCounter("mpipe.max_mpipe_depth",
                                                    tv,
                                                    SC_PERF_TYPE_UINT64,
                                                    "NULL");
    ptv->mpipe_drop = SCPerfTVRegisterCounter("mpipe.drop",
                                              tv,
                                              SC_PERF_TYPE_UINT64,
                                              "NULL");
    ptv->counter_no_buffers_0 = SCPerfTVRegisterCounter("mpipe.no_buf0", tv,
                                                        SC_PERF_TYPE_UINT64,
                                                        "NULL");
    ptv->counter_no_buffers_1 = SCPerfTVRegisterCounter("mpipe.no_buf1", tv,
                                                        SC_PERF_TYPE_UINT64,
                                                        "NULL");
    ptv->counter_no_buffers_2 = SCPerfTVRegisterCounter("mpipe.no_buf2", tv,
                                                        SC_PERF_TYPE_UINT64,
                                                        "NULL");
    ptv->counter_no_buffers_3 = SCPerfTVRegisterCounter("mpipe.no_buf3", tv,
                                                        SC_PERF_TYPE_UINT64,
                                                        "NULL");
    ptv->counter_no_buffers_4 = SCPerfTVRegisterCounter("mpipe.no_buf4", tv,
                                                        SC_PERF_TYPE_UINT64,
                                                        "NULL");
    ptv->counter_no_buffers_5 = SCPerfTVRegisterCounter("mpipe.no_buf5", tv,
                                                        SC_PERF_TYPE_UINT64,
                                                        "NULL");
    ptv->counter_no_buffers_6 = SCPerfTVRegisterCounter("mpipe.no_buf6", tv,
                                                        SC_PERF_TYPE_UINT64,
                                                        "NULL");
    ptv->counter_no_buffers_7 = SCPerfTVRegisterCounter("mpipe.no_buf7", tv,
                                                        SC_PERF_TYPE_UINT64,
                                                        "NULL");
    tv->sc_perf_pca = SCPerfGetAllCountersArray(&tv->sc_perf_pctx);
    SCPerfAddToClubbedTMTable(tv->name, &tv->sc_perf_pctx);
}

static const gxio_mpipe_buffer_size_enum_t gxio_buffer_sizes[] = {
            GXIO_MPIPE_BUFFER_SIZE_128,
            GXIO_MPIPE_BUFFER_SIZE_256,
            GXIO_MPIPE_BUFFER_SIZE_512,
            GXIO_MPIPE_BUFFER_SIZE_1024,
            GXIO_MPIPE_BUFFER_SIZE_1664,
            GXIO_MPIPE_BUFFER_SIZE_4096,
            GXIO_MPIPE_BUFFER_SIZE_10368,
            GXIO_MPIPE_BUFFER_SIZE_16384
        };

static const unsigned int buffer_sizes[] = {
            128,
            256,
            512,
            1024,
            1664,
            4096,
            10368,
            16384
        };

/* Relative weighting for the number of buffers of each size.
 */
static struct {
       float weight;
} buffer_scale[] = {
      { 0 }, /* 128 */
      { 4 }, /* 256 */
      { 0 }, /* 512 */
      { 0 }, /* 1024 */
      { 4 }, /* 1664 */
      { 0 }, /* 4096 */
      { 0 }, /* 10386 */
      { 0 }  /* 16384 */
};


TmEcode ReceiveMpipeThreadInit(ThreadVars *tv, void *initdata, void **data)
{
    SCEnter();
    int cpu = tmc_cpus_get_my_cpu();
    int rank = (cpu-1); // FIXME: Assumes worker CPUs start at 1.
    unsigned int num_buffers;
    int num_buckets = 4096; 
    unsigned int total_buffers = 0;
    unsigned int num_workers = TileNumPipelines;
    unsigned int stack_count = 0;
    if (initdata == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "initdata == NULL");
        SCReturnInt(TM_ECODE_FAILED);
    }

    MpipeThreadVars *ptv = SCMalloc(sizeof(MpipeThreadVars));
    if (ptv == NULL)
        SCReturnInt(TM_ECODE_FAILED);

    memset(ptv, 0, sizeof(MpipeThreadVars));

    ptv->tv = tv;
    ptv->datalink = LINKTYPE_ETHERNET;

    int result;
    char *link_name = (char *)initdata;
  
    /* Bind to a single cpu. */
    cpu_set_t cpus;
    result = tmc_cpus_get_my_affinity(&cpus);
    VERIFY(result, "tmc_cpus_get_my_affinity()");
    result = tmc_cpus_set_my_cpu(tmc_cpus_find_first_cpu(&cpus));
    VERIFY(result, "tmc_cpus_set_my_cpu()");

    if (rank == 0) {
        unsigned int i = 0;

        if (ConfGetNode("mpipe.stack") != NULL) {
            unsigned i;
            float weight;
            for (i = 0; i < (sizeof(buffer_scale)/sizeof(buffer_scale[0])); i++)
                buffer_scale[i].weight = 0;
	    if (ConfGetFloat("mpipe.stack.size128", &weight)) {
                buffer_scale[0].weight = weight;
	    }
	    if (ConfGetFloat("mpipe.stack.size256", &weight)) {
                buffer_scale[1].weight = weight;
	    }
	    if (ConfGetFloat("mpipe.stack.size512", &weight)) {
                buffer_scale[2].weight = weight;
	    }
	    if (ConfGetFloat("mpipe.stack.size1024", &weight)) {
                buffer_scale[3].weight = weight;
	    }
	    if (ConfGetFloat("mpipe.stack.size1664", &weight)) {
                buffer_scale[4].weight = weight;
	    }
	    if (ConfGetFloat("mpipe.stack.size4096", &weight)) {
                buffer_scale[5].weight = weight;
	    }
	    if (ConfGetFloat("mpipe.stack.size10386", &weight)) {
                buffer_scale[6].weight = weight;
	    }
	    if (ConfGetFloat("mpipe.stack.size16384", &weight)) {
                buffer_scale[7].weight = weight;
	    }
        }
        intmax_t value = 0;
        if (ConfGetInt("mpipe.buckets", &value) == 1) {
            /* range check */
            if ((value >= 1) && (value <= 4096)) {
                num_buckets = (int) value;
            } else {
                SCLogError(SC_ERR_INVALID_ARGUMENT, "Illegal mpipe.buckets value.");
            }
        }

        if (strcmp(link_name, "multi") == 0) {
            int nlive = LiveGetDeviceCount();
            int instance = gxio_mpipe_link_instance(LiveGetDeviceName(0));
            for (int i = 1; i < nlive; i++) {
                link_name = LiveGetDeviceName(i);
                if (gxio_mpipe_link_instance(link_name) != instance) {
                    SCLogError(SC_ERR_INVALID_ARGUMENT, 
                               "All interfaces not on same mpipe instance");
                    SCReturnInt(TM_ECODE_FAILED);
                }
            }
            gxio_mpipe_init(context, instance);
            VERIFY(result, "gxio_mpipe_init()");
            /* open ingress interfaces */
            for (int i = 0; i < nlive; i++) {
                link_name = LiveGetDeviceName(i);
                SCLogInfo("opening interface %s", link_name);
                result = gxio_mpipe_link_open(&mpipe_link[i], context,
                                              link_name, 0);
                VERIFY(result, "gxio_mpipe_link_open()");
                mpipe_conf[i] = ParseMpipeConfig(link_name);
            }
            /* find and open egress interfaces */
            for (int i = 0; i < nlive; i++) {
                MpipeIfaceConfig *aconf = mpipe_conf[i];
                if (aconf != NULL) {
                    if(aconf->copy_mode != MPIPE_COPY_MODE_NONE) {
                        int channel;
                        /* Initialize and equeue */
                        result = gxio_mpipe_alloc_edma_rings(context, 1, 0, 0);
                        VERIFY(result, "gxio_mpipe_alloc_edma_rings");
                        uint32_t ering = result;
                        size_t edescs_size = equeue_entries *
                                                sizeof(gxio_mpipe_edesc_t);
                        tmc_alloc_t edescs_alloc = TMC_ALLOC_INIT;
                        tmc_alloc_set_pagesize(&edescs_alloc, edescs_size);
                        void *edescs = tmc_alloc_map(&edescs_alloc, edescs_size);
                        if (edescs == NULL) {
                            SCLogError(SC_ERR_FATAL,
                                       "Failed to allocate egress descriptors");
                            SCReturnInt(TM_ECODE_FAILED);
                        }
                        /* retrieve channel of outbound interface */
                        for (int j = 0; j < nlive; j++) {
                            if (strcmp(aconf->out_iface,
                                       mpipe_conf[j]->iface) == 0) {
                                channel = gxio_mpipe_link_channel(&mpipe_link[j]);
                                SCLogInfo("egress link: %s is channel: %d", 
                                          aconf->out_iface, channel);
                                result = gxio_mpipe_equeue_init(equeue[i],
                                                                context,
                                                                ering,
                                                                channel,
                                                                edescs,
                                                                edescs_size,
                                                                0);
                                VERIFY(result, "gxio_mpipe_equeue_init");
                                channel = gxio_mpipe_link_channel(&mpipe_link[i]);
                                SCLogInfo("ingress link: %s is channel: %d copy_mode: %d", 
                                          aconf->iface, channel, aconf->copy_mode);
                                channel_to_equeue[channel].peer_equeue = equeue[i];
                                channel_to_equeue[channel].copy_mode = aconf->copy_mode;
                                break;
                            }
                        }
                    }
                }
            }
        } else {
            SCLogInfo("using single interface %s", (char *)initdata);

            /* Start the driver. */
            result = gxio_mpipe_init(context, gxio_mpipe_link_instance(link_name));
            VERIFY(result, "gxio_mpipe_init()");

            gxio_mpipe_link_t link;
            result = gxio_mpipe_link_open(&link, context, link_name, 0);
            VERIFY(result, "gxio_mpipe_link_open()");
        }

        /* Allocate some ingress queues. */
        iqueues = calloc(num_workers, sizeof(*iqueues));
        if (iqueues == NULL)
             tmc_task_die("Failure in 'calloc()'.");

        /* Allocate some NotifRings. */
        result = gxio_mpipe_alloc_notif_rings(context,
                                              num_workers,
                                              0, 0);
        VERIFY(result, "gxio_mpipe_alloc_notif_rings()");
        int ring = result;

        /* Init the NotifRings. */
        size_t notif_ring_entries = 2048;
        size_t notif_ring_size = notif_ring_entries * sizeof(gxio_mpipe_idesc_t);
        for (unsigned int i = 0; i < num_workers; i++) {
            tmc_alloc_t alloc = TMC_ALLOC_INIT;
            tmc_alloc_set_home(&alloc, 1 + i); // FIXME: static worker to Core mapping
            if (notif_ring_size > (size_t)getpagesize())
                tmc_alloc_set_huge(&alloc);
            unsigned int needed = notif_ring_size + sizeof(gxio_mpipe_iqueue_t);
            void *iqueue_mem = tmc_alloc_map(&alloc, needed);
            if (iqueue_mem == NULL)
                tmc_task_die("Failure in 'tmc_alloc_map()'.");
            gxio_mpipe_iqueue_t *iqueue = iqueue_mem + notif_ring_size;
            result = gxio_mpipe_iqueue_init(iqueue, context, ring + i,
                                            iqueue_mem, notif_ring_size, 0);
            VERIFY(result, "gxio_mpipe_iqueue_init()");
            iqueues[i] = iqueue;
        }

        /* Count required buffer stacks and normalize weights to sum to 1.0. */
        {
            float total_weight = 0;
            int max_stack_count = sizeof(gxio_buffer_sizes) / 
              sizeof(gxio_buffer_sizes[0]);
            for (int i = 0; i < max_stack_count; i++) {
                if (buffer_scale[i].weight != 0) {
                    ++stack_count;
                    total_weight += buffer_scale[i].weight;
                }
            }
            /* Convert each weight to a value between 0 and 1. inclusive. */
            for (int i = 0; i < max_stack_count; i++) {
                if (buffer_scale[i].weight != 0) {
                    buffer_scale[i].weight /= total_weight;
                }
             }
        }

        SCLogInfo("DEBUG: %u non-zero sized stacks", stack_count);

        /* Allocate one of the largest pages to hold our buffer stack,
         * notif ring, and packets.  First get a bit map of the
         * available page sizes. */
        unsigned long available_pagesizes = tmc_alloc_get_pagesizes();

        /* Try the largest available page size first to see if any
         * pages of that size can be allocated. */
        for (unsigned int i = sizeof(available_pagesizes) * 8 - 1; i;  i--) {
            unsigned long size = 1UL<<i;
            if (available_pagesizes & size) {
                tile_vhuge_size = (size_t)size;

                tmc_alloc_t alloc = TMC_ALLOC_INIT;
                tmc_alloc_set_huge(&alloc);
                tmc_alloc_set_home(&alloc, TMC_ALLOC_HOME_HASH);
                if (tmc_alloc_set_pagesize_exact(&alloc, tile_vhuge_size) == NULL)
                    continue; // Couldn't get the page size requested
                packet_page = tmc_alloc_map(&alloc, tile_vhuge_size);
                if (packet_page)
                    break;
              }
          }
          assert(packet_page);
          void* packet_mem = packet_page;
          SCLogInfo("DEBUG: tile_vhuge_size %lu", tile_vhuge_size);

          /* Allocate a NotifGroup. */
          result = gxio_mpipe_alloc_notif_groups(context, 1, 0, 0);
          VERIFY(result, "gxio_mpipe_alloc_notif_groups()");
          int group = result;

          /* Allocate buckets. */
          result = gxio_mpipe_alloc_buckets(context, num_buckets, 0, 0);
          if (result == GXIO_MPIPE_ERR_NO_BUCKET) {
              SCLogError(SC_ERR_INVALID_ARGUMENT,
                         "Could not allocate mpipe buckets. "
                         "Try a smaller mpipe.buckets value in suricata.yaml");
              tmc_task_die("Could not allocate mpipe buckets");
          }
          int bucket = result;

          /* Init group and buckets, preserving packet order among flows. */
          gxio_mpipe_bucket_mode_t mode = GXIO_MPIPE_BUCKET_STATIC_FLOW_AFFINITY;
          char *balance;
          if (ConfGet("mpipe.load-balance", &balance) == 1) {
              if (balance) {
                  if (strcmp(balance, "static") == 0) {
                      mode = GXIO_MPIPE_BUCKET_STATIC_FLOW_AFFINITY;
                      SCLogInfo("Using \"static\" flow affinity.");
                  } else if (strcmp(balance, "dynamic") == 0) {
                      mode = GXIO_MPIPE_BUCKET_DYNAMIC_FLOW_AFFINITY;
                      SCLogInfo("Using \"dynamic\" flow affinity.");
                  } else {
                      SCLogInfo("Illegal load balancing mode %s using \"static\"",
                                balance);
                  }
              }
          }
          result = gxio_mpipe_init_notif_group_and_buckets(context, group,
                                                           ring, num_workers,
                                                           bucket, num_buckets, 
                                                           mode);
          VERIFY(result, "gxio_mpipe_init_notif_group_and_buckets()");
          
          /* Allocate one Huge page just to store buffer stacks, since they are 
           *  only ever accessed by mPipe.
           */
          size_t stack_page_size = tmc_alloc_get_huge_pagesize();
          tmc_alloc_t alloc = TMC_ALLOC_INIT;
          tmc_alloc_set_huge(&alloc);
          void *buffer_stack_page = tmc_alloc_map(&alloc, stack_page_size);
          void *buffer_stack_mem = buffer_stack_page;
          void *buffer_stack_mem_end = buffer_stack_mem + stack_page_size;
          assert(buffer_stack_mem);

          /* Allocate buffer stacks. */
          result = gxio_mpipe_alloc_buffer_stacks(context, stack_count, 0, 0);
          VERIFY(result, "gxio_mpipe_alloc_buffer_stacks()");
          int stack = result;
          first_stack = (uint16_t)stack;

          /* Divide up the Very Huge page into packet buffers. */
          i = 0;
          for (unsigned int stackidx = stack;
               stackidx < stack + stack_count;
               stackidx++, i++) {

              /* Skip empty buffer stacks. */
              for (;buffer_scale[i].weight == 0; i++) ;

              /* Bytes from the Huge page used for this buffer stack. */
              size_t packet_buffer_slice = tile_vhuge_size * buffer_scale[i].weight;
              unsigned int buffer_size = buffer_sizes[i];
              num_buffers = packet_buffer_slice / (buffer_size + sizeof(Packet));
              
              SCLogInfo("Initializing stackidx:%d size=%d stack_mem=%.2fMB buffers=%d",
                        stackidx, buffer_size, packet_buffer_slice/(1024.0 * 1024), 
                        num_buffers);

              SCLogInfo("buffer size=%d Packet+buf=%d CL",
                        buffer_size, (int)(buffer_size + sizeof(Packet)) / 64);

              /* Initialize the buffer stack. Must be aligned mod 64K. */
              size_t stack_bytes = gxio_mpipe_calc_buffer_stack_bytes(num_buffers);
              gxio_mpipe_buffer_size_enum_t buf_size = gxio_buffer_sizes[i];
              result = gxio_mpipe_init_buffer_stack(context, stackidx, buf_size,
                                                    buffer_stack_mem, stack_bytes, 0);
              VERIFY(result, "gxio_mpipe_init_buffer_stack()");
              buffer_stack_mem += stack_bytes;
              
              /* Buffer stack must be aligned to 64KB page boundary. */
              ALIGN(buffer_stack_mem, 0x10000);
              assert(buffer_stack_mem < buffer_stack_mem_end);
              
              /* Register the entire huge page of memory which contains all
               * the buffers.
               */
              result = gxio_mpipe_register_page(context, stackidx, packet_page,
                                                tile_vhuge_size, 0);
              VERIFY(result, "gxio_mpipe_register_page()");
              
              /* And register the memory holding the buffer stack. */
              result = gxio_mpipe_register_page(context, stackidx, 
                                                buffer_stack_page,
                                                stack_page_size, 0);
              VERIFY(result, "gxio_mpipe_register_page()");
              
              total_buffers += num_buffers;
              
              SCLogInfo("Adding %d %d byte packet buffers",
                        num_buffers, buffer_size);
              
              /* Push some buffers onto the stack. */
              for (unsigned int j = 0; j < num_buffers; j++) {
                  Packet *p = (Packet *)packet_mem;
                  memset(p, 0, sizeof(Packet));
                  PACKET_INITIALIZE(p);
                  p->flags |= PKT_MPIPE;
                  
                  gxio_mpipe_push_buffer(context, stackidx, packet_mem + sizeof(Packet));
                  packet_mem += (sizeof(Packet) + buffer_size);
              }

              /* Paranoia. */
              assert(packet_mem <= packet_page + tile_vhuge_size);

          }
          SCLogInfo("%d total packet buffers", total_buffers);

          /* Register for packets. */
          gxio_mpipe_rules_t rules;
          gxio_mpipe_rules_init(&rules, context);
          gxio_mpipe_rules_begin(&rules, bucket, num_buckets, NULL);
          result = gxio_mpipe_rules_commit(&rules);
          VERIFY(result, "gxio_mpipe_rules_commit()");
    }

    MpipeRegisterPerfCounters(ptv, tv);

    *data = (void *)ptv;
    SCReturnInt(TM_ECODE_OK);
}

TmEcode ReceiveMpipeInit(void)
{
    SCEnter();

    SCLogInfo("TileNumPipelines: %d", TileNumPipelines);

    for (int i = 0; i < MAX_CHANNELS; i++) {
        equeue[i] = &equeue_body[i];
    }

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief This function prints stats to the screen at exit.
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into NetiohreadVars for ptv
 */
void ReceiveMpipeThreadExitStats(ThreadVars *tv, void *data)
{
    SCEnter();
    SCReturn;
}

TmEcode DecodeMpipeThreadInit(ThreadVars *tv, void *initdata, void **data)
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

TmEcode DecodeMpipe(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, 
                    PacketQueue *postq)
{
    SCEnter();
    DecodeThreadVars *dtv = (DecodeThreadVars *)data;

    /* update counters */
    SCPerfCounterIncr(dtv->counter_pkts, tv->sc_perf_pca);
    SCPerfCounterIncr(dtv->counter_pkts_per_sec, tv->sc_perf_pca);

    SCPerfCounterAddUI64(dtv->counter_bytes, tv->sc_perf_pca, p->pktlen);

    SCPerfCounterAddUI64(dtv->counter_avg_pkt_size, tv->sc_perf_pca, p->pktlen);
    SCPerfCounterSetUI64(dtv->counter_max_pkt_size, tv->sc_perf_pca, p->pktlen);

    /* call the decoder */
    switch(p->datalink) {
    case LINKTYPE_ETHERNET:
        DecodeEthernet(tv, dtv, p, p->pkt, p->pktlen, pq);
        break;
    default:
        printf("DecodeMpipe INVALID datatype p %p datalink %x\n", p, 
               p->datalink);
        break;
    }
 
    SCReturnInt(TM_ECODE_OK);
}

/**
 *  \brief Add a mpipe device for monitoring
 *
 *  \param dev string with the device name
 *
 *  \retval 0 on success.
 *  \retval -1 on failure.
 */
int MpipeLiveRegisterDevice(char *dev)
{
    MpipeDevice *nd = SCMalloc(sizeof(MpipeDevice));
    if (nd == NULL) {
        return -1;
    }

    nd->dev = SCStrdup(dev);
    TAILQ_INSERT_TAIL(&mpipe_devices, nd, next);

    SCLogDebug("Mpipe device \"%s\" registered.", dev);
    return 0;
}

/**
 *  \brief Get the number of registered devices
 *
 *  \retval cnt the number of registered devices
 */
int MpipeLiveGetDeviceCount(void)
{
    int i = 0;
    MpipeDevice *nd;

    TAILQ_FOREACH(nd, &mpipe_devices, next) {
        i++;
    }

    return i;
}

#endif // HAVE_MPIPE
