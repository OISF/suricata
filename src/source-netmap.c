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
*  \defgroup netmap Netmap running mode
*
*  @{
*/

/**
* \file
*
* \author Aleksey Katargin <gureedo@gmail.com>
*
* Netmap socket acquisition support
*
*/

#include "suricata-common.h"
#include "config.h"
#include "suricata.h"
#include "decode.h"
#include "packet-queue.h"
#include "threads.h"
#include "threadvars.h"
#include "tm-queuehandlers.h"
#include "tm-modules.h"
#include "tm-threads.h"
#include "tm-threads-common.h"
#include "conf.h"
#include "util-debug.h"
#include "util-device.h"
#include "util-error.h"
#include "util-privs.h"
#include "util-optimize.h"
#include "util-checksum.h"
#include "util-ioctl.h"
#include "util-host-info.h"
#include "tmqh-packetpool.h"
#include "source-netmap.h"
#include "runmodes.h"

#ifdef __SC_CUDA_SUPPORT__

#include "util-cuda.h"
#include "util-cuda-buffer.h"
#include "util-mpm-ac.h"
#include "util-cuda-handlers.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "util-cuda-vars.h"

#endif /* __SC_CUDA_SUPPORT__ */

#ifdef HAVE_NETMAP

#if HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#if HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif

#include <net/netmap_user.h>

#endif /* HAVE_NETMAP */

#include "util-ioctl.h"

extern intmax_t max_pending_packets;

#ifndef HAVE_NETMAP

TmEcode NoNetmapSupportExit(ThreadVars *, const void *, void **);

void TmModuleReceiveNetmapRegister (void)
{
    tmm_modules[TMM_RECEIVENETMAP].name = "ReceiveNetmap";
    tmm_modules[TMM_RECEIVENETMAP].ThreadInit = NoNetmapSupportExit;
    tmm_modules[TMM_RECEIVENETMAP].Func = NULL;
    tmm_modules[TMM_RECEIVENETMAP].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_RECEIVENETMAP].ThreadDeinit = NULL;
    tmm_modules[TMM_RECEIVENETMAP].RegisterTests = NULL;
    tmm_modules[TMM_RECEIVENETMAP].cap_flags = 0;
    tmm_modules[TMM_RECEIVENETMAP].flags = TM_FLAG_RECEIVE_TM;
}

/**
* \brief Registration Function for DecodeNetmap.
* \todo Unit tests are needed for this module.
*/
void TmModuleDecodeNetmapRegister (void)
{
    tmm_modules[TMM_DECODENETMAP].name = "DecodeNetmap";
    tmm_modules[TMM_DECODENETMAP].ThreadInit = NoNetmapSupportExit;
    tmm_modules[TMM_DECODENETMAP].Func = NULL;
    tmm_modules[TMM_DECODENETMAP].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODENETMAP].ThreadDeinit = NULL;
    tmm_modules[TMM_DECODENETMAP].RegisterTests = NULL;
    tmm_modules[TMM_DECODENETMAP].cap_flags = 0;
    tmm_modules[TMM_DECODENETMAP].flags = TM_FLAG_DECODE_TM;
}

/**
* \brief this function prints an error message and exits.
*/
TmEcode NoNetmapSupportExit(ThreadVars *tv, const void *initdata, void **data)
{
    SCLogError(SC_ERR_NO_NETMAP,"Error creating thread %s: you do not have "
            "support for netmap enabled, please recompile "
            "with --enable-netmap", tv->name);
    exit(EXIT_FAILURE);
}

#else /* We have NETMAP support */

#define max(a, b) (((a) > (b)) ? (a) : (b))

#define POLL_TIMEOUT 100

#if defined(__linux__)
#define POLL_EVENTS (POLLHUP|POLLRDHUP|POLLERR|POLLNVAL)

#ifndef IFF_PPROMISC
#define IFF_PPROMISC IFF_PROMISC
#endif

#else
#define POLL_EVENTS (POLLHUP|POLLERR|POLLNVAL)
#endif

enum {
    NETMAP_OK,
    NETMAP_FAILURE,
};

enum {
    NETMAP_FLAG_ZERO_COPY = 1,
};

/**
 * \brief Netmap ring isntance.
 */
typedef struct NetmapRing
{
    int fd;
    struct netmap_ring *rx;
    struct netmap_ring *tx;
    int dst_ring_from;
    int dst_ring_to;
    int dst_next_ring;
    SCSpinlock tx_lock;
} NetmapRing;

/**
 * \brief Netmap device instance.
 */
typedef struct NetmapDevice_
{
    char ifname[IFNAMSIZ];
    void *mem;
    size_t memsize;
    struct netmap_if *nif;
    int rings_cnt;
    int rx_rings_cnt;
    int tx_rings_cnt;
    /* hw rings + sw ring */
    NetmapRing *rings;
    unsigned int ref;
    SC_ATOMIC_DECLARE(unsigned int, threads_run);
    TAILQ_ENTRY(NetmapDevice_) next;
} NetmapDevice;

/**
 * \brief Module thread local variables.
 */
typedef struct NetmapThreadVars_
{
    /* receive inteface */
    NetmapDevice *ifsrc;
    /* dst interface for IPS mode */
    NetmapDevice *ifdst;

    int src_ring_from;
    int src_ring_to;
    int thread_idx;
    int flags;
    struct bpf_program bpf_prog;

    /* internal shit */
    TmSlot *slot;
    ThreadVars *tv;
    LiveDevice *livedev;

    /* copy from config */
    int copy_mode;
    ChecksumValidationMode checksum_mode;

    /* counters */
    uint64_t pkts;
    uint64_t bytes;
    uint64_t drops;
    uint16_t capture_kernel_packets;
    uint16_t capture_kernel_drops;


} NetmapThreadVars;

typedef TAILQ_HEAD(NetmapDeviceList_, NetmapDevice_) NetmapDeviceList;

static NetmapDeviceList netmap_devlist = TAILQ_HEAD_INITIALIZER(netmap_devlist);
static SCMutex netmap_devlist_lock = SCMUTEX_INITIALIZER;

/** \brief get RSS RX-queue count
 *  \retval rx_rings RSS RX queue count or 1 on error
 */
int NetmapGetRSSCount(const char *ifname)
{
    struct nmreq nm_req;
    int rx_rings = 1;

    SCMutexLock(&netmap_devlist_lock);

    /* open netmap */
    int fd = open("/dev/netmap", O_RDWR);
    if (fd == -1) {
        SCLogError(SC_ERR_NETMAP_CREATE,
                "Couldn't open netmap device, error %s",
                strerror(errno));
        goto error_open;
    }

    /* query netmap info */
    memset(&nm_req, 0, sizeof(nm_req));
    strlcpy(nm_req.nr_name, ifname, sizeof(nm_req.nr_name));
    nm_req.nr_version = NETMAP_API;

    if (ioctl(fd, NIOCGINFO, &nm_req) != 0) {
        SCLogError(SC_ERR_NETMAP_CREATE,
                "Couldn't query netmap for %s, error %s",
                ifname, strerror(errno));
        goto error_fd;
    };

    rx_rings = nm_req.nr_rx_rings;

error_fd:
    close(fd);
error_open:
    SCMutexUnlock(&netmap_devlist_lock);
    return rx_rings;
}

/**
 * \brief Open interface in netmap mode.
 * \param ifname Interface name.
 * \param promisc Enable promiscuous mode.
 * \param dev Pointer to requested netmap device instance.
 * \param verbose Verbose error logging.
 * \return Zero on success.
 */
static int NetmapOpen(char *ifname, int promisc, NetmapDevice **pdevice, int verbose)
{
    NetmapDevice *pdev = NULL;
    struct nmreq nm_req;

    *pdevice = NULL;

    SCMutexLock(&netmap_devlist_lock);

    /* search interface in our already opened list */
    TAILQ_FOREACH(pdev, &netmap_devlist, next) {
        if (strcmp(ifname, pdev->ifname) == 0) {
            *pdevice = pdev;
            pdev->ref++;
            SCMutexUnlock(&netmap_devlist_lock);
            return 0;
        }
    }

    /* not found, create new record */
    pdev = SCMalloc(sizeof(*pdev));
    if (unlikely(pdev == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "Memory allocation failed");
        goto error;
    }

    memset(pdev, 0, sizeof(*pdev));
    SC_ATOMIC_INIT(pdev->threads_run);
    strlcpy(pdev->ifname, ifname, sizeof(pdev->ifname));

    /* open netmap */
    int fd = open("/dev/netmap", O_RDWR);
    if (fd == -1) {
        SCLogError(SC_ERR_NETMAP_CREATE,
                   "Couldn't open netmap device, error %s",
                   strerror(errno));
        goto error_pdev;
    }

    /* check interface is up */
    int if_flags = GetIfaceFlags(ifname);
    if (if_flags == -1) {
        if (verbose) {
            SCLogError(SC_ERR_NETMAP_CREATE,
                       "Can not access to interface '%s'",
                       ifname);
        }
        goto error_fd;
    }
    if ((if_flags & IFF_UP) == 0) {
        SCLogWarning(SC_ERR_NETMAP_CREATE, "Interface '%s' is down", ifname);
        goto error_fd;
    }
    /* if needed, try to set iface in promisc mode */
    if (promisc && (if_flags & (IFF_PROMISC|IFF_PPROMISC)) == 0) {
        if_flags |= IFF_PPROMISC;
        SetIfaceFlags(ifname, if_flags);
    }

    /* query netmap info */
    memset(&nm_req, 0, sizeof(nm_req));
    strlcpy(nm_req.nr_name, ifname, sizeof(nm_req.nr_name));
    nm_req.nr_version = NETMAP_API;

    if (ioctl(fd, NIOCGINFO, &nm_req) != 0) {
        if (verbose) {
            SCLogError(SC_ERR_NETMAP_CREATE,
                       "Couldn't query netmap for %s, error %s",
                       ifname, strerror(errno));
        }
        goto error_fd;
    };

    pdev->memsize = nm_req.nr_memsize;
    pdev->rx_rings_cnt = nm_req.nr_rx_rings;
    pdev->tx_rings_cnt = nm_req.nr_tx_rings;
    pdev->rings_cnt = max(pdev->rx_rings_cnt, pdev->tx_rings_cnt);

    /* hw rings + sw ring */
    pdev->rings = SCMalloc(sizeof(*pdev->rings) * (pdev->rings_cnt + 1));
    if (unlikely(pdev->rings == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "Memory allocation failed");
        goto error_fd;
    }
    memset(pdev->rings, 0, sizeof(*pdev->rings) * (pdev->rings_cnt + 1));

    /* open individual instance for each ring */
    int success_cnt = 0;
    for (int i = 0; i <= pdev->rings_cnt; i++) {
        NetmapRing *pring = &pdev->rings[i];
        pring->fd = open("/dev/netmap", O_RDWR);
        if (pring->fd == -1) {
            SCLogError(SC_ERR_NETMAP_CREATE,
                       "Couldn't open netmap device: %s",
                       strerror(errno));
            break;
        }

        if (i < pdev->rings_cnt) {
            nm_req.nr_flags = NR_REG_ONE_NIC;
            nm_req.nr_ringid = i | NETMAP_NO_TX_POLL;
        } else {
            nm_req.nr_flags = NR_REG_SW;
            nm_req.nr_ringid = NETMAP_NO_TX_POLL;
        }
        if (ioctl(pring->fd, NIOCREGIF, &nm_req) != 0) {
            SCLogError(SC_ERR_NETMAP_CREATE,
                       "Couldn't register %s with netmap: %s",
                       ifname, strerror(errno));
            break;
        }

        if (pdev->mem == NULL) {
            pdev->mem = mmap(0, pdev->memsize, PROT_WRITE | PROT_READ,
                             MAP_SHARED, pring->fd, 0);
            if (pdev->mem == MAP_FAILED) {
                SCLogError(SC_ERR_NETMAP_CREATE,
                           "Couldn't mmap netmap device: %s",
                           strerror(errno));
                break;
            }
            pdev->nif = NETMAP_IF(pdev->mem, nm_req.nr_offset);
        }

        if ((i < pdev->rx_rings_cnt) || (i == pdev->rings_cnt)) {
            pring->rx = NETMAP_RXRING(pdev->nif, i);
        }
        if ((i < pdev->tx_rings_cnt) || (i == pdev->rings_cnt)) {
            pring->tx = NETMAP_TXRING(pdev->nif, i);
        }
        SCSpinInit(&pring->tx_lock, 0);
        success_cnt++;
    }

    if (success_cnt != (pdev->rings_cnt + 1)) {
        for(int i = 0; i < success_cnt; i++) {
            close(pdev->rings[i].fd);
        }
        if (pdev->mem) {
            munmap(pdev->mem, pdev->memsize);
        }
        SCFree(pdev->rings);
        goto error_fd;
    }

    close(fd);
    *pdevice = pdev;

    TAILQ_INSERT_TAIL(&netmap_devlist, pdev, next);
    SCMutexUnlock(&netmap_devlist_lock);

    return 0;

error_fd:
    close(fd);
error_pdev:
    SCFree(pdev);
error:
    SCMutexUnlock(&netmap_devlist_lock);
    return -1;
}

/**
 * \brief Close or dereference netmap device instance.
 * \param pdev Netmap device instance.
 * \return Zero on success.
 */
static int NetmapClose(NetmapDevice *dev)
{
    NetmapDevice *pdev, *tmp;

    SCMutexLock(&netmap_devlist_lock);

    TAILQ_FOREACH_SAFE(pdev, &netmap_devlist, next, tmp) {
        if (pdev == dev) {
            pdev->ref--;
            if (!pdev->ref) {
                munmap(pdev->mem, pdev->memsize);
                // First close SW ring (https://github.com/luigirizzo/netmap/issues/144)
                for (int i = pdev->rings_cnt; i >= 0; i--) {
                    NetmapRing *pring = &pdev->rings[i];
                    close(pring->fd);
                    SCSpinDestroy(&pring->tx_lock);
                }
                SCFree(pdev->rings);
                TAILQ_REMOVE(&netmap_devlist, pdev, next);
                SCFree(pdev);
            }
            SCMutexUnlock(&netmap_devlist_lock);
            return 0;
        }
    }

    SCMutexUnlock(&netmap_devlist_lock);
    return -1;
}

/**
 * \brief PcapDumpCounters
 * \param ntv
 */
static inline void NetmapDumpCounters(NetmapThreadVars *ntv)
{
    StatsAddUI64(ntv->tv, ntv->capture_kernel_packets, ntv->pkts);
    StatsAddUI64(ntv->tv, ntv->capture_kernel_drops, ntv->drops);
    (void) SC_ATOMIC_ADD(ntv->livedev->drop, ntv->drops);
    (void) SC_ATOMIC_ADD(ntv->livedev->pkts, ntv->pkts);
    ntv->drops = 0;
    ntv->pkts = 0;
}

/**
 * \brief Init function for ReceiveNetmap.
 * \param tv pointer to ThreadVars
 * \param initdata pointer to the interface passed from the user
 * \param data pointer gets populated with NetmapThreadVars
 */
static TmEcode ReceiveNetmapThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    SCEnter();
    NetmapIfaceConfig *aconf = (NetmapIfaceConfig *)initdata;

    if (initdata == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "initdata == NULL");
        SCReturnInt(TM_ECODE_FAILED);
    }

    NetmapThreadVars *ntv = SCMalloc(sizeof(*ntv));
    if (unlikely(ntv == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "Memory allocation failed");
        goto error;
    }
    memset(ntv, 0, sizeof(*ntv));

    ntv->tv = tv;
    ntv->checksum_mode = aconf->in.checksum_mode;
    ntv->copy_mode = aconf->in.copy_mode;

    ntv->livedev = LiveGetDevice(aconf->iface_name);
    if (ntv->livedev == NULL) {
        SCLogError(SC_ERR_INVALID_VALUE, "Unable to find Live device");
        goto error_ntv;
    }

    if (NetmapOpen(aconf->in.iface, aconf->in.promisc, &ntv->ifsrc, 1) != 0) {
        goto error_ntv;
    }

    if (unlikely(!aconf->in.sw_ring && !ntv->ifsrc->rx_rings_cnt)) {
        SCLogError(SC_ERR_NETMAP_CREATE,
                   "Input interface '%s' does not have Rx rings",
                   aconf->iface_name);
        goto error_src;
    }

    if (unlikely(aconf->in.sw_ring && aconf->in.threads > 1)) {
        SCLogError(SC_ERR_INVALID_VALUE,
                   "Interface '%s+'. "
                   "Thread count can't be greater than 1 for SW ring.",
                   aconf->iface_name);
        goto error_src;
    } else if (unlikely(aconf->in.threads > ntv->ifsrc->rx_rings_cnt)) {
        SCLogError(SC_ERR_INVALID_VALUE,
                   "Thread count can't be greater than Rx ring count. "
                   "Configured %d threads for interface '%s' with %d Rx rings.",
                   aconf->in.threads, aconf->iface_name, ntv->ifsrc->rx_rings_cnt);
        goto error_src;
    }

    if (aconf->in.sw_ring) {
        ntv->thread_idx = 0;
    } else {
        do {
            ntv->thread_idx = SC_ATOMIC_GET(ntv->ifsrc->threads_run);
        } while (SC_ATOMIC_CAS(&ntv->ifsrc->threads_run, ntv->thread_idx, ntv->thread_idx + 1) == 0);
    }

    /* calculate thread rings binding */
    if (aconf->in.sw_ring) {
        ntv->src_ring_from = ntv->src_ring_to = ntv->ifsrc->rings_cnt;
    } else {
        int tmp = (ntv->ifsrc->rx_rings_cnt + 1) / aconf->in.threads;
        ntv->src_ring_from = ntv->thread_idx * tmp;
        ntv->src_ring_to = ntv->src_ring_from + tmp - 1;
        if (ntv->thread_idx == (aconf->in.threads - 1)) {
            ntv->src_ring_to = ntv->ifsrc->rx_rings_cnt - 1;
        }
    }
    SCLogDebug("netmap: %s thread:%d rings:%d-%d", aconf->iface_name,
               ntv->thread_idx, ntv->src_ring_from, ntv->src_ring_to);

    if (aconf->in.copy_mode != NETMAP_COPY_MODE_NONE) {
        if (NetmapOpen(aconf->out.iface, aconf->out.promisc, &ntv->ifdst, 1) != 0) {
            goto error_src;
        }

        if (unlikely(!aconf->out.sw_ring && !ntv->ifdst->tx_rings_cnt)) {
            SCLogError(SC_ERR_NETMAP_CREATE,
                       "Output interface '%s' does not have Tx rings",
                       aconf->out.iface);
            goto error_dst;
        }

        /* calculate dst rings bindings */
        for (int i = ntv->src_ring_from; i <= ntv->src_ring_to; i++) {
            NetmapRing *ring = &ntv->ifsrc->rings[i];
            if (aconf->out.sw_ring) {
                ring->dst_ring_from = ring->dst_ring_to = ntv->ifdst->rings_cnt;
            } else if (ntv->ifdst->tx_rings_cnt > ntv->ifsrc->rx_rings_cnt) {
                int tmp = (ntv->ifdst->tx_rings_cnt + 1) / ntv->ifsrc->rx_rings_cnt;
                ring->dst_ring_from = i * tmp;
                ring->dst_ring_to = ring->dst_ring_from + tmp - 1;
                if (i == (ntv->src_ring_to - 1)) {
                    ring->dst_ring_to = ntv->ifdst->tx_rings_cnt - 1;
                }
            } else {
                ring->dst_ring_from = ring->dst_ring_to =
                        i % ntv->ifdst->tx_rings_cnt;
            }
            ring->dst_next_ring = ring->dst_ring_from;

            SCLogDebug("netmap: %s(%d)->%s(%d-%d)",
                       aconf->in.iface, i, aconf->out.iface,
                       ring->dst_ring_from, ring->dst_ring_to);
        }
    }

    /* basic counters */
    ntv->capture_kernel_packets = StatsRegisterCounter("capture.kernel_packets",
            ntv->tv);
    ntv->capture_kernel_drops = StatsRegisterCounter("capture.kernel_drops",
            ntv->tv);

    /* enable zero-copy mode for workers runmode */
    char const *active_runmode = RunmodeGetActive();
    if ((aconf->in.copy_mode != NETMAP_COPY_MODE_NONE) && active_runmode &&
            strcmp("workers", active_runmode) == 0) {
        ntv->flags |= NETMAP_FLAG_ZERO_COPY;
        SCLogPerf("Enabling zero copy mode for %s->%s",
                  aconf->in.iface, aconf->out.iface);
    } else {
        uint16_t ring_size = ntv->ifsrc->rings[0].rx->num_slots;
        if (ring_size > max_pending_packets) {
            SCLogError(SC_ERR_NETMAP_CREATE,
                       "Packet pool size (%" PRIuMAX ") must be greater or equal than %s ring size (%" PRIu16 "). "
                       "Increase max_pending_packets option.",
                       max_pending_packets, aconf->iface_name, ring_size);
            goto error_dst;
        }
    }

    if (aconf->in.bpf_filter) {
        SCLogConfig("Using BPF '%s' on iface '%s'",
                  aconf->in.bpf_filter, ntv->ifsrc->ifname);
        if (pcap_compile_nopcap(default_packet_size,  /* snaplen_arg */
                    LINKTYPE_ETHERNET,    /* linktype_arg */
                    &ntv->bpf_prog,       /* program */
                    aconf->in.bpf_filter, /* const char *buf */
                    1,                    /* optimize */
                    PCAP_NETMASK_UNKNOWN  /* mask */
                    ) == -1)
        {
            SCLogError(SC_ERR_NETMAP_CREATE, "Filter compilation failed.");
            goto error_dst;
        }
    }

    *data = (void *)ntv;
    aconf->DerefFunc(aconf);
    SCReturnInt(TM_ECODE_OK);

error_dst:
    if (aconf->in.copy_mode != NETMAP_COPY_MODE_NONE) {
        NetmapClose(ntv->ifdst);
    }
error_src:
    NetmapClose(ntv->ifsrc);
error_ntv:
    SCFree(ntv);
error:
    aconf->DerefFunc(aconf);
    SCReturnInt(TM_ECODE_FAILED);
}

/**
 * \brief Output packet to destination interface or drop.
 * \param ntv Thread local variables.
 * \param p Source packet.
 */
static TmEcode NetmapWritePacket(NetmapThreadVars *ntv, Packet *p)
{
    if (ntv->copy_mode == NETMAP_COPY_MODE_IPS) {
        if (PACKET_TEST_ACTION(p, ACTION_DROP)) {
            return TM_ECODE_OK;
        }
    }

    /* map src ring_id to dst ring_id */
    NetmapRing *rxring = &ntv->ifsrc->rings[p->netmap_v.ring_id];
    NetmapRing *txring = &ntv->ifdst->rings[p->netmap_v.dst_ring_id];

    SCSpinLock(&txring->tx_lock);

    if (!nm_ring_space(txring->tx)) {
        ntv->drops++;
        SCSpinUnlock(&txring->tx_lock);
        return TM_ECODE_FAILED;
    }

    struct netmap_slot *ts = &txring->tx->slot[txring->tx->cur];

    if (ntv->flags & NETMAP_FLAG_ZERO_COPY) {
        struct netmap_slot *rs = &rxring->rx->slot[p->netmap_v.slot_id];

        /* swap slot buffers */
        uint32_t tmp_idx;
        tmp_idx = ts->buf_idx;
        ts->buf_idx = rs->buf_idx;
        rs->buf_idx = tmp_idx;

        ts->len = rs->len;

        ts->flags |= NS_BUF_CHANGED;
        rs->flags |= NS_BUF_CHANGED;
    } else {
        unsigned char *slot_data = (unsigned char *)NETMAP_BUF(txring->tx, ts->buf_idx);
        memcpy(slot_data, GET_PKT_DATA(p), GET_PKT_LEN(p));
        ts->len = GET_PKT_LEN(p);
        ts->flags |= NS_BUF_CHANGED;
    }

    txring->tx->head = txring->tx->cur = nm_ring_next(txring->tx, txring->tx->cur);
    if ((ntv->flags & NETMAP_FLAG_ZERO_COPY) == 0) {
        ioctl(txring->fd, NIOCTXSYNC, 0);
    }

    SCSpinUnlock(&txring->tx_lock);

    return TM_ECODE_OK;
}

/**
 * \brief Packet release routine.
 * \param p Packet.
 */
static void NetmapReleasePacket(Packet *p)
{
    NetmapThreadVars *ntv = (NetmapThreadVars *)p->netmap_v.ntv;

    /* Need to be in copy mode and need to detect early release
       where Ethernet header could not be set (and pseudo packet) */
    if ((ntv->copy_mode != NETMAP_COPY_MODE_NONE) && !PKT_IS_PSEUDOPKT(p)) {
        NetmapWritePacket(ntv, p);
    }

    PacketFreeOrRelease(p);
}

/**
 * \brief Read packets from ring and pass them further.
 * \param ntv Thread local variables.
 * \param ring_id Ring id to read.
 */
static int NetmapRingRead(NetmapThreadVars *ntv, int ring_id)
{
    SCEnter();

    NetmapRing *ring = &ntv->ifsrc->rings[ring_id];
    struct netmap_ring *rx = ring->rx;
    uint32_t avail = nm_ring_space(rx);
    uint32_t cur = rx->cur;

    if (!(ntv->flags & NETMAP_FLAG_ZERO_COPY)) {
        PacketPoolWaitForN(avail);
    }

    while (likely(avail-- > 0)) {
        struct netmap_slot *slot = &rx->slot[cur];
        unsigned char *slot_data = (unsigned char *)NETMAP_BUF(rx, slot->buf_idx);

        if (ntv->bpf_prog.bf_len) {
            struct pcap_pkthdr pkthdr = { {0, 0}, slot->len, slot->len };
            if (pcap_offline_filter(&ntv->bpf_prog, &pkthdr, slot_data) == 0) {
                /* rejected by bpf */
                cur = nm_ring_next(rx, cur);
                continue;
            }
        }

        Packet *p = PacketPoolGetPacket();
        if (unlikely(p == NULL)) {
            SCReturnInt(NETMAP_FAILURE);
        }

        PKT_SET_SRC(p, PKT_SRC_WIRE);
        p->livedev = ntv->livedev;
        p->datalink = LINKTYPE_ETHERNET;
        p->ts = rx->ts;
        ntv->pkts++;
        ntv->bytes += slot->len;

        /* checksum validation */
        if (ntv->checksum_mode == CHECKSUM_VALIDATION_DISABLE) {
            p->flags |= PKT_IGNORE_CHECKSUM;
        } else if (ntv->checksum_mode == CHECKSUM_VALIDATION_AUTO) {
            if (ntv->livedev->ignore_checksum) {
                p->flags |= PKT_IGNORE_CHECKSUM;
            } else if (ChecksumAutoModeCheck(ntv->pkts,
                        SC_ATOMIC_GET(ntv->livedev->pkts),
                        SC_ATOMIC_GET(ntv->livedev->invalid_checksums))) {
                ntv->livedev->ignore_checksum = 1;
                p->flags |= PKT_IGNORE_CHECKSUM;
            }
        }

        if (ntv->flags & NETMAP_FLAG_ZERO_COPY) {
            if (PacketSetData(p, slot_data, slot->len) == -1) {
                TmqhOutputPacketpool(ntv->tv, p);
                SCReturnInt(NETMAP_FAILURE);
            }
        } else {
            if (PacketCopyData(p, slot_data, slot->len) == -1) {
                TmqhOutputPacketpool(ntv->tv, p);
                SCReturnInt(NETMAP_FAILURE);
            }
        }

        p->ReleasePacket = NetmapReleasePacket;
        p->netmap_v.ring_id = ring_id;
        p->netmap_v.slot_id = cur;
        p->netmap_v.dst_ring_id = ring->dst_next_ring;
        p->netmap_v.ntv = ntv;

        if (ring->dst_ring_from != ring->dst_ring_to) {
            ring->dst_next_ring++;
            if (ring->dst_next_ring == ring->dst_ring_to) {
                ring->dst_next_ring = ring->dst_ring_from;
            }
        }

        SCLogDebug("pktlen: %" PRIu32 " (pkt %p, pkt data %p)",
                   GET_PKT_LEN(p), p, GET_PKT_DATA(p));

        if (TmThreadsSlotProcessPkt(ntv->tv, ntv->slot, p) != TM_ECODE_OK) {
            TmqhOutputPacketpool(ntv->tv, p);
            SCReturnInt(NETMAP_FAILURE);
        }

        cur = nm_ring_next(rx, cur);
    }
    rx->head = rx->cur = cur;

    SCReturnInt(NETMAP_OK);
}

/**
 *  \brief Main netmap reading loop function
 */
static TmEcode ReceiveNetmapLoop(ThreadVars *tv, void *data, void *slot)
{
    SCEnter();

    TmSlot *s = (TmSlot *)slot;
    NetmapThreadVars *ntv = (NetmapThreadVars *)data;
    struct pollfd *fds;
    int rings_count = ntv->src_ring_to - ntv->src_ring_from + 1;

    ntv->slot = s->slot_next;

    fds = SCMalloc(sizeof(*fds) * rings_count);
    if (unlikely(fds == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "Memory allocation failed");
        SCReturnInt(TM_ECODE_FAILED);
    }

    for (int i = 0; i < rings_count; i++) {
        fds[i].fd = ntv->ifsrc->rings[ntv->src_ring_from + i].fd;
        fds[i].events = POLLIN;
    }

    for(;;) {
        if (suricata_ctl_flags != 0) {
            break;
        }

        /* make sure we have at least one packet in the packet pool,
         * to prevent us from alloc'ing packets at line rate */
        PacketPoolWait();

        int r = poll(fds, rings_count, POLL_TIMEOUT);

        if (r < 0) {
            /* error */
            if(errno != EINTR)
                SCLogError(SC_ERR_NETMAP_READ,
                           "Error polling netmap from iface '%s': (%d" PRIu32 ") %s",
                           ntv->ifsrc->ifname, errno, strerror(errno));
            continue;
        } else if (r == 0) {
            /* no events, timeout */
            SCLogDebug("(%s:%d-%d) Poll timeout", ntv->ifsrc->ifname,
                       ntv->src_ring_from, ntv->src_ring_to);

            /* poll timed out, lets see if we need to inject a fake packet  */
            TmThreadsCaptureInjectPacket(tv, ntv->slot, NULL);
            continue;
        }

        for (int i = 0; i < rings_count; i++) {
            if (fds[i].revents & POLL_EVENTS) {
                if (fds[i].revents & POLLERR) {
                    SCLogError(SC_ERR_NETMAP_READ,
                               "Error reading data from iface '%s': (%d" PRIu32 ") %s",
                               ntv->ifsrc->ifname, errno, strerror(errno));
                } else if (fds[i].revents & POLLNVAL) {
                    SCLogError(SC_ERR_NETMAP_READ,
                               "Invalid polling request");
                }
                continue;
            }

            if (likely(fds[i].revents & POLLIN)) {
                int src_ring_id = ntv->src_ring_from + i;
                NetmapRingRead(ntv, src_ring_id);

                if ((ntv->copy_mode != NETMAP_COPY_MODE_NONE) &&
                    (ntv->flags & NETMAP_FLAG_ZERO_COPY)) {

                    NetmapRing *src_ring = &ntv->ifsrc->rings[src_ring_id];

                    /* sync dst tx rings */
                    for (int j = src_ring->dst_ring_from; j <= src_ring->dst_ring_to; j++) {
                        NetmapRing *dst_ring = &ntv->ifdst->rings[j];
                        /* if locked, another loop already do sync */
                        if (SCSpinTrylock(&dst_ring->tx_lock) == 0) {
                            ioctl(dst_ring->fd, NIOCTXSYNC, 0);
                            SCSpinUnlock(&dst_ring->tx_lock);
                        }
                    }
                }
            }
        }

        NetmapDumpCounters(ntv);
        StatsSyncCountersIfSignalled(tv);
    }

    SCFree(fds);
    StatsSyncCountersIfSignalled(tv);
    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief This function prints stats to the screen at exit.
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into NetmapThreadVars for ntv
 */
static void ReceiveNetmapThreadExitStats(ThreadVars *tv, void *data)
{
    SCEnter();
    NetmapThreadVars *ntv = (NetmapThreadVars *)data;

    NetmapDumpCounters(ntv);
    SCLogPerf("(%s) Kernel: Packets %" PRIu64 ", dropped %" PRIu64 ", bytes %" PRIu64 "",
              tv->name,
              StatsGetLocalCounterValue(tv, ntv->capture_kernel_packets),
              StatsGetLocalCounterValue(tv, ntv->capture_kernel_drops),
              ntv->bytes);
}

/**
 * \brief
 * \param tv
 * \param data Pointer to NetmapThreadVars.
 */
static TmEcode ReceiveNetmapThreadDeinit(ThreadVars *tv, void *data)
{
    SCEnter();

    NetmapThreadVars *ntv = (NetmapThreadVars *)data;

    if (ntv->ifsrc) {
        NetmapClose(ntv->ifsrc);
        ntv->ifsrc = NULL;
    }
    if (ntv->ifdst) {
        NetmapClose(ntv->ifdst);
        ntv->ifdst = NULL;
    }
    if (ntv->bpf_prog.bf_insns) {
        pcap_freecode(&ntv->bpf_prog);
    }

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief Prepare netmap decode thread.
 * \param tv Thread local avariables.
 * \param initdata Thread config.
 * \param data Pointer to DecodeThreadVars placed here.
 */
static TmEcode DecodeNetmapThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    SCEnter();
    DecodeThreadVars *dtv = NULL;

    dtv = DecodeThreadVarsAlloc(tv);

    if (dtv == NULL)
        SCReturnInt(TM_ECODE_FAILED);

    DecodeRegisterPerfCounters(dtv, tv);

    *data = (void *)dtv;

#ifdef __SC_CUDA_SUPPORT__
    if (CudaThreadVarsInit(&dtv->cuda_vars) < 0)
        SCReturnInt(TM_ECODE_FAILED);
#endif

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief This function passes off to link type decoders.
 *
 * DecodeNetmap reads packets from the PacketQueue and passes
 * them off to the proper link type decoder.
 *
 * \param t pointer to ThreadVars
 * \param p pointer to the current packet
 * \param data pointer that gets cast into NetmapThreadVars for ntv
 * \param pq pointer to the current PacketQueue
 * \param postpq
 */
static TmEcode DecodeNetmap(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    SCEnter();

    DecodeThreadVars *dtv = (DecodeThreadVars *)data;

    /* XXX HACK: flow timeout can call us for injected pseudo packets
     *           see bug: https://redmine.openinfosecfoundation.org/issues/1107 */
    if (p->flags & PKT_PSEUDO_STREAM_END)
        SCReturnInt(TM_ECODE_OK);

    /* update counters */
    DecodeUpdatePacketCounters(tv, dtv, p);

    DecodeEthernet(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p), pq);

    PacketDecodeFinalize(tv, dtv, p);

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief
 * \param tv
 * \param data Pointer to DecodeThreadVars.
 */
static TmEcode DecodeNetmapThreadDeinit(ThreadVars *tv, void *data)
{
    SCEnter();

    if (data != NULL)
        DecodeThreadVarsFree(tv, data);

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief Registration Function for RecieveNetmap.
 */
void TmModuleReceiveNetmapRegister(void)
{
    tmm_modules[TMM_RECEIVENETMAP].name = "ReceiveNetmap";
    tmm_modules[TMM_RECEIVENETMAP].ThreadInit = ReceiveNetmapThreadInit;
    tmm_modules[TMM_RECEIVENETMAP].Func = NULL;
    tmm_modules[TMM_RECEIVENETMAP].PktAcqLoop = ReceiveNetmapLoop;
    tmm_modules[TMM_RECEIVENETMAP].PktAcqBreakLoop = NULL;
    tmm_modules[TMM_RECEIVENETMAP].ThreadExitPrintStats = ReceiveNetmapThreadExitStats;
    tmm_modules[TMM_RECEIVENETMAP].ThreadDeinit = ReceiveNetmapThreadDeinit;
    tmm_modules[TMM_RECEIVENETMAP].RegisterTests = NULL;
    tmm_modules[TMM_RECEIVENETMAP].cap_flags = SC_CAP_NET_RAW;
    tmm_modules[TMM_RECEIVENETMAP].flags = TM_FLAG_RECEIVE_TM;
}

/**
 * \brief Registration Function for DecodeNetmap.
 */
void TmModuleDecodeNetmapRegister(void)
{
    tmm_modules[TMM_DECODENETMAP].name = "DecodeNetmap";
    tmm_modules[TMM_DECODENETMAP].ThreadInit = DecodeNetmapThreadInit;
    tmm_modules[TMM_DECODENETMAP].Func = DecodeNetmap;
    tmm_modules[TMM_DECODENETMAP].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODENETMAP].ThreadDeinit = DecodeNetmapThreadDeinit;
    tmm_modules[TMM_DECODENETMAP].RegisterTests = NULL;
    tmm_modules[TMM_DECODENETMAP].cap_flags = 0;
    tmm_modules[TMM_DECODENETMAP].flags = TM_FLAG_DECODE_TM;
}

#endif /* HAVE_NETMAP */
/* eof */
/**
* @}
*/
