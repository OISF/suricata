/* Copyright (C) 2011-2014 Open Information Security Foundation
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
 * \author Ken Steele, Tilera Corporation <suricata@tilera.com>
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
#include "tm-threads-common.h"
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
        if (__val < 0) {                                        \
            SCLogError(SC_ERR_INVALID_ARGUMENT,(WHAT));         \
            SCReturnInt(TM_ECODE_FAILED);                       \
        }                                                       \
    } while (0)

#define min(a,b) (((a) < (b)) ? (a) : (b))

/** storage for mpipe device names */
typedef struct MpipeDevice_ {
    char *dev;  /**< the device (e.g. "xgbe1") */
    TAILQ_ENTRY(MpipeDevice_) next;
} MpipeDevice;


/** private device list */
static TAILQ_HEAD(, MpipeDevice_) mpipe_devices =
    TAILQ_HEAD_INITIALIZER(mpipe_devices);

static int first_stack;
static uint32_t headroom = 2;

/**
 * \brief Structure to hold thread specific variables.
 */
typedef struct MpipeThreadVars_
{
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
TmEcode DecodeMpipeThreadDeinit(ThreadVars *tv, void *data);
TmEcode DecodeMpipe(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
static int MpipeReceiveOpenIqueue(int rank);

#define MAX_CHANNELS 32   /* can probably find this in the MDE */

/*
 * mpipe configuration.
 */

/* The mpipe context (shared by all workers) */
static gxio_mpipe_context_t context_body;
static gxio_mpipe_context_t* context = &context_body;

/* First allocated Notification ring for iQueues. */
static int first_notif_ring;

/* The ingress queue for this worker thread */
static __thread gxio_mpipe_iqueue_t* thread_iqueue;

/* The egress queues (one per port) */
static gxio_mpipe_equeue_t equeue[MAX_CHANNELS];

/* the number of entries in an equeue ring */
static const int equeue_entries = 8192;

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
    tmm_modules[TMM_DECODEMPIPE].ThreadDeinit = DecodeMpipeThreadDeinit;
    tmm_modules[TMM_DECODEMPIPE].RegisterTests = NULL;
    tmm_modules[TMM_DECODEMPIPE].cap_flags = 0;
    tmm_modules[TMM_DECODEMPIPE].flags = TM_FLAG_DECODE_TM;
}

/* Release Packet without sending. */
void MpipeReleasePacket(Packet *p)
{
    /* Use this thread's context to free the packet. */
    // TODO: Check for dual mPipes.
    gxio_mpipe_iqueue_t* iqueue = thread_iqueue;
    int bucket = p->mpipe_v.idesc.bucket_id;
    gxio_mpipe_credit(iqueue->context, iqueue->ring, bucket, 1);

    gxio_mpipe_push_buffer(iqueue->context,
                           p->mpipe_v.idesc.stack_idx,
                           (void*)(intptr_t)p->mpipe_v.idesc.va);
}

/* Unconditionally send packet, then release packet buffer. */
void MpipeReleasePacketCopyTap(Packet *p)
{
    gxio_mpipe_iqueue_t* iqueue = thread_iqueue;
    int bucket = p->mpipe_v.idesc.bucket_id;
    gxio_mpipe_credit(iqueue->context, iqueue->ring, bucket, 1);
    gxio_mpipe_edesc_t edesc;
    edesc.words[0] = 0;
    edesc.words[1] = 0;
    edesc.bound = 1;
    edesc.xfer_size = p->mpipe_v.idesc.l2_size;
    edesc.va = p->mpipe_v.idesc.va;
    edesc.stack_idx = p->mpipe_v.idesc.stack_idx;
    edesc.hwb = 1; /* mPIPE will return packet buffer to proper stack. */
    edesc.size = p->mpipe_v.idesc.size;
    int channel = p->mpipe_v.idesc.channel;
    /* Tell mPIPE to egress the packet. */
    gxio_mpipe_equeue_put(channel_to_equeue[channel].peer_equeue, edesc);
}

/* Release Packet and send copy if action is not DROP. */
void MpipeReleasePacketCopyIPS(Packet *p)
{
    if (unlikely(PACKET_TEST_ACTION(p, ACTION_DROP))) {
        /* Return packet buffer without sending the packet. */
        MpipeReleasePacket(p);
    } else {
        /* Send packet */
        MpipeReleasePacketCopyTap(p);
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

    p->datalink = LINKTYPE_ETHERNET;
    /* No need to check return value, since the only error is pkt == NULL which can't happen here. */
    PacketSetData(p, pkt, caplen);

    /* copy only the fields we use later */
    p->mpipe_v.idesc.bucket_id = idesc->bucket_id;
    p->mpipe_v.idesc.nr = idesc->nr;
    p->mpipe_v.idesc.cs = idesc->cs;
    p->mpipe_v.idesc.va = idesc->va;
    p->mpipe_v.idesc.stack_idx = idesc->stack_idx;
    MpipePeerVars *equeue_info = &channel_to_equeue[idesc->channel];
    if (equeue_info->copy_mode != MPIPE_COPY_MODE_NONE) {
        p->mpipe_v.idesc.size = idesc->size;
        p->mpipe_v.idesc.l2_size = idesc->l2_size;
        p->mpipe_v.idesc.channel = idesc->channel;
        p->ReleasePacket = equeue_info->ReleasePacket;
    } else {
        p->ReleasePacket = MpipeReleasePacket;
    }

    if (ptv->checksum_mode == CHECKSUM_VALIDATION_DISABLE)
        p->flags |= PKT_IGNORE_CHECKSUM;

    return p;
}

static uint16_t XlateStack(MpipeThreadVars *ptv, int stack_idx)
{
    switch(stack_idx - first_stack) {
    case 0:
        return ptv->counter_no_buffers_0;
    case 1:
        return ptv->counter_no_buffers_1;
    case 2:
        return ptv->counter_no_buffers_2;
    case 3:
        return ptv->counter_no_buffers_3;
    case 4:
        return ptv->counter_no_buffers_4;
    case 5:
        return ptv->counter_no_buffers_5;
    case 6:
        return ptv->counter_no_buffers_6;
    case 7:
        return ptv->counter_no_buffers_7;
    default:
        return ptv->counter_no_buffers_7;
    }
}

static void SendNoOpPacket(ThreadVars *tv, TmSlot *slot)
{
    Packet *p = PacketPoolGetPacket();
    if (p == NULL) {
        return;
    }

    p->datalink = DLT_RAW;
    p->proto = IPPROTO_TCP;

    /* So that DecodeMpipe ignores is. */
    p->flags |= PKT_PSEUDO_STREAM_END;

    p->flow = NULL;

    TmThreadsSlotProcessPkt(tv, slot, p);
}

/**
 * \brief Receives packets from an interface via gxio mpipe.
 */
TmEcode ReceiveMpipeLoop(ThreadVars *tv, void *data, void *slot)
{
    SCEnter();

    MpipeThreadVars *ptv = (MpipeThreadVars *)data;
    TmSlot *s = (TmSlot *)slot;
    ptv->slot = s->slot_next;
    Packet *p = NULL;
    int rank = tv->rank;
    int max_queued = 0;
    char *ctype;

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

    /* Open Ingress Queue for this worker thread. */
    MpipeReceiveOpenIqueue(rank);
    gxio_mpipe_iqueue_t* iqueue = thread_iqueue;
    int update_counter = 0;
    uint64_t last_packet_time = get_cycle_count();

    for (;;) {

        /* Check to see how many packets are available to process. */
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
                StatsSetUI64(tv, ptv->max_mpipe_depth,
                                     (uint64_t)n);
                max_queued = n;
            }
            for (i = 0; i < m; i++, idesc++) {
                if (likely(!gxio_mpipe_idesc_has_error(idesc))) {
                    p = MpipeProcessPacket(ptv, idesc);
                    p->mpipe_v.rank = rank;
                    if (TmThreadsSlotProcessPkt(ptv->tv, ptv->slot, p) != TM_ECODE_OK) {
                        TmqhOutputPacketpool(ptv->tv, p);
                        SCReturnInt(TM_ECODE_FAILED);
                    }
                } else {
                    if (idesc->be) {
                        /* Buffer Error - No buffer available, so mPipe
                         * dropped the packet. */
                        StatsIncr(tv, XlateStack(ptv, idesc->stack_idx));
                    } else {
                        /* Bad packet. CRC error */
                        StatsIncr(tv, ptv->mpipe_drop);
                        gxio_mpipe_iqueue_drop(iqueue, idesc);
                    }
                    gxio_mpipe_iqueue_release(iqueue, idesc);
                }
            }
            /* Move forward M packets in ingress ring. */
            gxio_mpipe_iqueue_advance(iqueue, m);

            last_packet_time = get_cycle_count();
        }
        if (update_counter-- <= 0) {
            /* Only periodically update and check for termination. */
            StatsSyncCountersIfSignalled(tv);
            update_counter = 10000;

            if (suricata_ctl_flags != 0) {
              break;
            }

            // If no packet has been received for some period of time, process a NOP packet
            // just to make sure that pseudo packets from the Flow manager get processed.
            uint64_t now = get_cycle_count();
            if (now - last_packet_time > 100000000) {
                SendNoOpPacket(ptv->tv, ptv->slot);
                last_packet_time = now;
            }
        }
    }
    SCReturnInt(TM_ECODE_OK);
}

static void MpipeRegisterPerfCounters(MpipeThreadVars *ptv, ThreadVars *tv)
{
    /* register counters */
    ptv->max_mpipe_depth = StatsRegisterCounter("mpipe.max_mpipe_depth", tv);
    ptv->mpipe_drop = StatsRegisterCounter("mpipe.drop", tv);
    ptv->counter_no_buffers_0 = StatsRegisterCounter("mpipe.no_buf0", tv);
    ptv->counter_no_buffers_1 = StatsRegisterCounter("mpipe.no_buf1", tv);
    ptv->counter_no_buffers_2 = StatsRegisterCounter("mpipe.no_buf2", tv);
    ptv->counter_no_buffers_3 = StatsRegisterCounter("mpipe.no_buf3", tv);
    ptv->counter_no_buffers_4 = StatsRegisterCounter("mpipe.no_buf4", tv);
    ptv->counter_no_buffers_5 = StatsRegisterCounter("mpipe.no_buf5", tv);
    ptv->counter_no_buffers_6 = StatsRegisterCounter("mpipe.no_buf6", tv);
    ptv->counter_no_buffers_7 = StatsRegisterCounter("mpipe.no_buf7", tv);
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

static const int buffer_sizes[] = {
    128,
    256,
    512,
    1024,
    1664,
    4096,
    10368,
    16384
};

static int NormalizeBufferWeights(float buffer_weights[], int num_weights)
{
    int stack_count = 0;
    /* Count required buffer stacks and normalize weights to sum to 1.0. */
    float total_weight = 0;
    for (int i = 0; i < num_weights; i++) {
        if (buffer_weights[i] != 0) {
            ++stack_count;
            total_weight += buffer_weights[i];
        }
    }
    /* Convert each weight to a value between 0 and 1. inclusive. */
    for (int i = 0; i < num_weights; i++) {
        if (buffer_weights[i] != 0) {
            buffer_weights[i] /= total_weight;
        }
    }

    SCLogInfo("DEBUG: %u non-zero sized stacks", stack_count);
    return stack_count;
}

static TmEcode ReceiveMpipeAllocatePacketBuffers(void)
{
    SCEnter();
    int num_buffers;
    int result;
    int total_buffers = 0;

    /* Relative weighting for the number of buffers of each size.
     */
    float buffer_weight[] = {
        0 , /* 128 */
        4 , /* 256 */
        0 , /* 512 */
        0 , /* 1024 */
        4 , /* 1664 */
        0 , /* 4096 */
        0 , /* 10386 */
        0   /* 16384 */
    };

    int num_weights = sizeof(buffer_weight)/sizeof(buffer_weight[0]);
    if (ConfGetNode("mpipe.stack") != NULL) {
        float weight;
        for (int i = 0; i < num_weights; i++)
            buffer_weight[i] = 0;
        if (ConfGetFloat("mpipe.stack.size128", &weight))
            buffer_weight[0] = weight;
        if (ConfGetFloat("mpipe.stack.size256", &weight))
            buffer_weight[1] = weight;
        if (ConfGetFloat("mpipe.stack.size512", &weight))
            buffer_weight[2] = weight;
        if (ConfGetFloat("mpipe.stack.size1024", &weight))
            buffer_weight[3] = weight;
        if (ConfGetFloat("mpipe.stack.size1664", &weight))
            buffer_weight[4] = weight;
        if (ConfGetFloat("mpipe.stack.size4096", &weight))
            buffer_weight[5] = weight;
        if (ConfGetFloat("mpipe.stack.size10386", &weight))
            buffer_weight[6] = weight;
        if (ConfGetFloat("mpipe.stack.size16384", &weight))
            buffer_weight[7] = weight;
    }

    int stack_count = NormalizeBufferWeights(buffer_weight, num_weights);

    /* Allocate one of the largest pages to hold our buffer stack,
     * notif ring, and packets.  First get a bit map of the
     * available page sizes. */
    unsigned long available_pagesizes = tmc_alloc_get_pagesizes();

    void *packet_page = NULL;
    size_t tile_vhuge_size = 64 * 1024;

    /* Try the largest available page size first to see if any
     * pages of that size can be allocated. */
    for (int i = sizeof(available_pagesizes) * 8 - 1; i;  i--) {
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
    SCLogInfo("DEBUG: tile_vhuge_size %"PRIuMAX, (uintmax_t)tile_vhuge_size);
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
    first_stack = stack;
    
    /* Divide up the Very Huge page into packet buffers. */
    int i = 0;
    for (int ss = 0; ss < stack_count; i++, ss++) {
        /* Skip empty buffer stacks. */
        for (;buffer_weight[i] == 0; i++) ;
  
        int stackidx = first_stack + ss;
        /* Bytes from the Huge page used for this buffer stack. */
        size_t packet_buffer_slice = tile_vhuge_size * buffer_weight[i];
        int buffer_size = buffer_sizes[i];
        num_buffers = packet_buffer_slice / (buffer_size + sizeof(Packet));

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
        for (int j = 0; j < num_buffers; j++) {
            Packet *p = (Packet *)packet_mem;
            memset(p, 0, sizeof(Packet));
            PACKET_INITIALIZE(p);
          
            gxio_mpipe_push_buffer(context, stackidx, 
                                   packet_mem + sizeof(Packet));
            packet_mem += (sizeof(Packet) + buffer_size);
        }
        
        /* Paranoia. */
        assert(packet_mem <= packet_page + tile_vhuge_size);
    }
    SCLogInfo("%d total packet buffers", total_buffers);
    SCReturnInt(TM_ECODE_OK);
}

static TmEcode ReceiveMpipeCreateBuckets(int ring, int num_workers, 
                                         int *first_bucket, int *num_buckets)
{
    SCEnter();
    int result;
    int min_buckets = 256;

    /* Allocate a NotifGroup. */
    int group = gxio_mpipe_alloc_notif_groups(context, 1, 0, 0);
    VERIFY(group, "gxio_mpipe_alloc_notif_groups()");

    intmax_t value = 0;
    if (ConfGetInt("mpipe.buckets", &value) == 1) {
        /* range check */
        if ((value >= 1) && (value <= 4096)) {
            /* Must be a power of 2, so round up to next power of 2. */
            int ceiling_log2 = 64 - __builtin_clz((int64_t)value - 1);
            *num_buckets = 1 << (ceiling_log2);
        } else {
            SCLogError(SC_ERR_INVALID_ARGUMENT,
                       "Illegal mpipe.buckets value (%ld). must be between 1 and 4096.", value);
        }
    }
    if (ConfGetInt("mpipe.min-buckets", &value) == 1) {
        /* range check */
        if ((value >= 1) && (value <= 4096)) {
            /* Must be a power of 2, so round up to next power of 2. */
            int ceiling_log2 = 64 - __builtin_clz((int64_t)value - 1);
            min_buckets = 1 << (ceiling_log2);
        } else {
            SCLogError(SC_ERR_INVALID_ARGUMENT,
                     "Illegal min-mpipe.buckets value (%ld). must be between 1 and 4096.", value);
        }
    }

    /* Allocate buckets. Keep trying half the number of requested buckets until min-bucket is reached. */
    while (1) {
        *first_bucket = gxio_mpipe_alloc_buckets(context, *num_buckets, 0, 0);
        if (*first_bucket != GXIO_MPIPE_ERR_NO_BUCKET)
            break;
        /* Failed to allocate the requested number of buckets. Keep
         * trying less buckets until min-buckets is reached.
         */
        if (*num_buckets <= min_buckets) {
            SCLogError(SC_ERR_INVALID_ARGUMENT,
                    "Could not allocate (%d) mpipe buckets. "
                    "Try a smaller mpipe.buckets value in suricata.yaml", *num_buckets);
            SCReturnInt(TM_ECODE_FAILED);
        }
        /* Cut the number of requested buckets in half and try again. */
        *num_buckets /= 2;
    }

    /* Init group and buckets, preserving packet order among flows. */
    gxio_mpipe_bucket_mode_t mode = GXIO_MPIPE_BUCKET_STATIC_FLOW_AFFINITY;
    char *balance;
    if (ConfGet("mpipe.load-balance", &balance) == 1) {
        if (balance) {
            if (strcmp(balance, "static") == 0) {
                mode = GXIO_MPIPE_BUCKET_STATIC_FLOW_AFFINITY;
                SCLogInfo("Using \"static\" flow affinity load balancing with %d buckets.", *num_buckets);
            } else if (strcmp(balance, "dynamic") == 0) {
                mode = GXIO_MPIPE_BUCKET_DYNAMIC_FLOW_AFFINITY;
                SCLogInfo("Using \"dynamic\" flow affinity load balancing with %d buckets.", *num_buckets);
            } else if (strcmp(balance, "sticky") == 0) {
                mode = GXIO_MPIPE_BUCKET_STICKY_FLOW_LOCALITY;
                SCLogInfo("Using \"sticky\" load balancing with %d buckets.", *num_buckets);
            } else if (strcmp(balance, "round-robin") == 0) {
                mode = GXIO_MPIPE_BUCKET_ROUND_ROBIN;
            } else {
                SCLogWarning(SC_ERR_INVALID_ARGUMENT,
                             "Illegal load balancing mode \"%s\"", balance);
                balance = "static";
            }
        }
    } else {
        balance = "static";
    }
    SCLogInfo("Using \"%s\" load balancing with %d buckets.", balance, *num_buckets);

    result = gxio_mpipe_init_notif_group_and_buckets(context, group,
                                                     ring, num_workers,
                                                     *first_bucket,
                                                     *num_buckets,
                                                     mode);
    VERIFY(result, "gxio_mpipe_init_notif_group_and_buckets()");

    SCReturnInt(TM_ECODE_OK);
}

/* \brief Register mPIPE classifier rules to start receiving packets.
 *
 * \param Index of the first classifier bucket
 * \param Number of classifier buckets.
 *
 * \return result code where <0 is an error.
 */
static int ReceiveMpipeRegisterRules(int bucket, int num_buckets)
{
    /* Register for packets. */
    gxio_mpipe_rules_t rules;
    gxio_mpipe_rules_init(&rules, context);
    gxio_mpipe_rules_begin(&rules, bucket, num_buckets, NULL);
    /* Give Suricata priority over Linux to receive packets. */
    gxio_mpipe_rules_set_priority(&rules, -100);
    return gxio_mpipe_rules_commit(&rules);
}

/* \brief Initialize mPIPE ingress ring
 *
 * \param name of interface to open
 * \param Array of port configuations
 *
 * \return Output port channel number, or -1 on error
 */
static int MpipeReceiveOpenIqueue(int rank)
{
    /* Initialize the NotifRings. */
    size_t notif_ring_entries = 2048;
    intmax_t value = 0;
    if (ConfGetInt("mpipe.iqueue-packets", &value) == 1) {
        /* range check */
        if (value == 128 || value == 512 || value == 2048 || value == (64 * 1024)) {
            notif_ring_entries = value;
        } else {
            SCLogError(SC_ERR_INVALID_ARGUMENT, "Illegal mpipe.iqueue_packets value. must be 128, 512, 2048 or 65536.");
        }
    }

    size_t notif_ring_size = notif_ring_entries * sizeof(gxio_mpipe_idesc_t);

    tmc_alloc_t alloc = TMC_ALLOC_INIT;
    /* Allocate the memory locally on this thread's CPU. */
    tmc_alloc_set_home(&alloc, TMC_ALLOC_HOME_TASK);
    /* Allocate all the memory on one page. Which is required for the
       notif ring, not the iqueue. */
    if (notif_ring_size > (size_t)getpagesize())
        tmc_alloc_set_huge(&alloc);
    int needed = notif_ring_size + sizeof(gxio_mpipe_iqueue_t);
    // TODO - Save the rest of the Huge Page for other allocations.
    void *iqueue_mem = tmc_alloc_map(&alloc, needed);
    if (iqueue_mem == NULL) {
      SCLogError(SC_ERR_FATAL, "Failed to allocate memory for mPIPE iQueue");
        return TM_ECODE_FAILED;
    }

    thread_iqueue = iqueue_mem + notif_ring_size;
    int result = gxio_mpipe_iqueue_init(thread_iqueue, context, first_notif_ring + rank,
                                        iqueue_mem, notif_ring_size, 0);
    if (result < 0) {
        VERIFY(result, "gxio_mpipe_iqueue_init()");
    }

    return TM_ECODE_OK;
}

/* \brief Initialize on MPIPE egress port
 *
 * Initialize one mPIPE egress port for use in IPS mode.
 * The port must be one of the input ports.
 *
 * \param name of interface to open
 * \param Array of port configuations
 *
 * \return Output port channel number, or -1 on error
 */
static int MpipeReceiveOpenEgress(char *out_iface, int iface_idx,
                                  int copy_mode,
                                  MpipeIfaceConfig *mpipe_conf[])
{
    int channel;
    int nlive = LiveGetDeviceCount();
    int result;

    /* Initialize an equeue */
    result = gxio_mpipe_alloc_edma_rings(context, 1, 0, 0);
    if (result < 0) {
        SCLogError(SC_ERR_FATAL, "Failed to allocate mPIPE egress ring");
        return result;
    }
    uint32_t ering = result;
    size_t edescs_size = equeue_entries * sizeof(gxio_mpipe_edesc_t);
    tmc_alloc_t edescs_alloc = TMC_ALLOC_INIT;
    tmc_alloc_set_pagesize(&edescs_alloc, edescs_size);
    void *edescs = tmc_alloc_map(&edescs_alloc, edescs_size);
    if (edescs == NULL) {
        SCLogError(SC_ERR_FATAL,
                   "Failed to allocate egress descriptors");
        return -1;
    }
    /* retrieve channel of outbound interface */
    for (int j = 0; j < nlive; j++) {
        if (strcmp(out_iface, mpipe_conf[j]->iface) == 0) {
            channel = gxio_mpipe_link_channel(&mpipe_link[j]);
            SCLogInfo("egress link: %s is channel: %d", 
                      out_iface, channel);
            result = gxio_mpipe_equeue_init(&equeue[iface_idx],
                                            context,
                                            ering,
                                            channel,
                                            edescs,
                                            edescs_size,
                                            0);
            if (result < 0) {
                SCLogError(SC_ERR_FATAL,
                           "mPIPE Failed to initialize egress queue");
                return -1;
            }
            /* Record the mapping from ingress port to egress port.
             * The egress information is stored indexed by ingress channel.
             */
            channel = gxio_mpipe_link_channel(&mpipe_link[iface_idx]);
            channel_to_equeue[channel].peer_equeue = &equeue[iface_idx];
            channel_to_equeue[channel].copy_mode = copy_mode;
            if (copy_mode == MPIPE_COPY_MODE_IPS)
                channel_to_equeue[channel].ReleasePacket = MpipeReleasePacketCopyIPS;
            else
                channel_to_equeue[channel].ReleasePacket = MpipeReleasePacketCopyTap;
            
            SCLogInfo("ingress link: %s is channel: %d copy_mode: %d", 
                      out_iface, channel, copy_mode);

            return channel;
        }
    }

    /* Did not find matching interface name */
    SCLogError(SC_ERR_INVALID_ARGUMENT, "Could not find egress interface: %s",
               out_iface);
    return -1;
}

TmEcode ReceiveMpipeThreadInit(ThreadVars *tv, void *initdata, void **data)
{
    SCEnter();
    int rank = tv->rank;
    int num_buckets = 4096; 
    int num_workers = tile_num_pipelines;

    if (initdata == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "initdata == NULL");
        SCReturnInt(TM_ECODE_FAILED);
    }

    MpipeThreadVars *ptv = SCMalloc(sizeof(MpipeThreadVars));
    if (unlikely(ptv == NULL))
        SCReturnInt(TM_ECODE_FAILED);

    memset(ptv, 0, sizeof(MpipeThreadVars));

    ptv->tv = tv;

    int result;
    char *link_name = (char *)initdata;
  
    MpipeRegisterPerfCounters(ptv, tv);

    *data = (void *)ptv;

    /* Only rank 0 does initialization of mpipe */
    if (rank != 0)
        SCReturnInt(TM_ECODE_OK);

    /* Initialize and configure mPIPE, which is only done by one core. */

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
        result = gxio_mpipe_init(context, instance);
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
        /* find and open egress interfaces for IPS modes */
        for (int i = 0; i < nlive; i++) {
            MpipeIfaceConfig *aconf = mpipe_conf[i];
            if (aconf != NULL) {
                if (aconf->copy_mode != MPIPE_COPY_MODE_NONE) {
                    int channel = MpipeReceiveOpenEgress(aconf->out_iface,
                                                         i, aconf->copy_mode,
                                                         mpipe_conf);
                    if (channel < 0) {
                        SCReturnInt(TM_ECODE_FAILED);
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
    /* Allocate some NotifRings. */
    result = gxio_mpipe_alloc_notif_rings(context,
                                          num_workers,
                                          0, 0);
    VERIFY(result, "gxio_mpipe_alloc_notif_rings()");
    first_notif_ring = result;

    int first_bucket = 0;
    int rc;
    rc = ReceiveMpipeCreateBuckets(first_notif_ring, num_workers,
                                   &first_bucket, &num_buckets);
    if (rc != TM_ECODE_OK)
        SCReturnInt(rc);

    rc = ReceiveMpipeAllocatePacketBuffers();
    if (rc != TM_ECODE_OK)
        SCReturnInt(rc);

    result = ReceiveMpipeRegisterRules(first_bucket, num_buckets);
    if (result < 0) {
        SCLogError(SC_ERR_INVALID_ARGUMENT,
                   "Registering mPIPE classifier rules, %s", 
                   gxio_strerror(result));
        SCReturnInt(TM_ECODE_FAILED);
    }

    SCReturnInt(TM_ECODE_OK);
}

TmEcode ReceiveMpipeInit(void)
{
    SCEnter();

    SCLogInfo("tile_num_pipelines: %d", tile_num_pipelines);

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

TmEcode DecodeMpipeThreadDeinit(ThreadVars *tv, void *data)
{
    if (data != NULL)
        DecodeThreadVarsFree(tv, data);
    SCReturnInt(TM_ECODE_OK);
}

TmEcode DecodeMpipe(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, 
                    PacketQueue *postq)
{
    SCEnter();
    DecodeThreadVars *dtv = (DecodeThreadVars *)data;

    /* XXX HACK: flow timeout can call us for injected pseudo packets
     *           see bug: https://redmine.openinfosecfoundation.org/issues/1107 */
    if (p->flags & PKT_PSEUDO_STREAM_END)
        return TM_ECODE_OK;

    /* update counters */
    DecodeUpdatePacketCounters(tv, dtv, p);

    /* call the decoder */
    DecodeEthernet(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p), pq);

    PacketDecodeFinalize(tv, dtv, p);

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
    if (unlikely(nd == NULL)) {
        return -1;
    }

    nd->dev = SCStrdup(dev);
    if (unlikely(nd->dev == NULL)) {
        SCFree(nd);
        return -1;
    }
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
