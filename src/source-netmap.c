/* Copyright (C) 2011,2013 Open Information Security Foundation
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
 *  \defgroup Netmap run mode
 *
 *  @{
 */

/**
 * \file
 *
 * \author Tom DeCanio <td@npulsetech.com>
 *
 * Netmap acquisition support
 * 
 * Derrived in part from source code written by Luigi Rizzo.
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
#include "tmqh-packetpool.h"
#include "source-netmap.h"
#include "runmodes.h"

#ifdef HAVE_NETMAP

#if HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#if HAVE_LINUX_IF_ETHER_H
#include <linux/if_ether.h>
#endif

#if HAVE_LINUX_IF_PACKET_H
#include <linux/if_packet.h>
#endif

#if HAVE_LINUX_IF_ARP_H
#include <linux/if_arp.h>
#endif

#if HAVE_LINUX_FILTER_H
#include <linux/filter.h>
#endif

#if HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif

#include <net/netmap.h>
#include <net/netmap_user.h>

#endif /* HAVE_NETMAP */

extern uint8_t suricata_ctl_flags;
extern int max_pending_packets;

#ifndef HAVE_NETMAP

TmEcode NoNetmapSupportExit(ThreadVars *, void *, void **);

void TmModuleReceiveNetmapRegister (void) {
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
void TmModuleDecodeNetmapRegister (void) {
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
TmEcode NoNetmapSupportExit(ThreadVars *tv, void *initdata, void **data)
{
    SCLogError(SC_ERR_NO_AF_PACKET,"Error creating thread %s: you do not have "
               "support for Netmap enabled, please recompile "
               "with --enable-netmap", tv->name);
    exit(EXIT_FAILURE);
}

#else /* We have Netmap support */

#define NETMAP_IFACE_NAME_LENGTH 48

#define NETMAP_STATE_DOWN 0
#define NETMAP_STATE_UP 1

#define NETMAP_RECONNECT_TIMEOUT 500000
#define NETMAP_DOWN_COUNTER_INTERVAL 40

#define POLL_TIMEOUT 100

#ifndef TP_STATUS_USER_BUSY
/* for new use latest bit available in tp_status */
#define TP_STATUS_USER_BUSY (1 << 31)
#endif

enum {
    NETMAP_READ_OK,
    NETMAP_READ_FAILURE,
    NETMAP_FAILURE,
    NETMAP_KERNEL_DROP,
};

union thdr {
    struct tpacket2_hdr *h2;
    void *raw;
};

/**
 * \brief Structure to hold thread specific variables.
 */
typedef struct NetmapThreadVars_
{
    /* thread specific socket */
    int socket;
    /* handle state */
    unsigned char netmap_state;

    /* data link type for the thread */
    int datalink;
    int cooked;

    /* counters */
    uint32_t pkts;
    uint64_t bytes;
    uint32_t errs;

    ThreadVars *tv;
    TmSlot *slot;

    uint8_t *data; /** Per function and thread data */
    int datalen; /** Length of per function and thread data */

    char iface[NETMAP_IFACE_NAME_LENGTH];
    LiveDevice *livedev;
    int down_count;

    /* Filter */
    char *bpf_filter;

    /* socket buffer size */
    int buffer_size;
    int promisc;
    ChecksumValidationMode checksum_mode;

    /* IPS stuff */
    char out_iface[NETMAP_IFACE_NAME_LENGTH];
    NetmapPeer *mpeer;

    int flags;

    int thread_no;

    int cluster_id;
    int cluster_type;

    int threads;
    int copy_mode;

    /* Netmap stuff starts here */
    int rx_fd;
    int tx_fd;
    char *mem;                          /* userspace mmap address */
    u_int memsize;
    u_int begin, end;                   /* first...last+1 rings to check */
    u_int head[16];                     /* tracks cur */
    struct netmap_if *nifp;             /* netmap_if for rx packets */
    struct netmap_if *tx_nifp;          /* netmap_if for tx packets if TAP/IPS*/
    struct netmap_ring *tx, *rx;        /* shortcuts */

    uint32_t if_flags;
    uint32_t if_reqcap;
    uint32_t if_curcap;

} NetmapThreadVars;

TmEcode ReceiveNetmap(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode ReceiveNetmapThreadInit(ThreadVars *, void *, void **);
void ReceiveNetmapThreadExitStats(ThreadVars *, void *);
TmEcode ReceiveNetmapThreadDeinit(ThreadVars *, void *);
TmEcode ReceiveNetmapLoop(ThreadVars *tv, void *data, void *slot);

TmEcode DecodeNetmapThreadInit(ThreadVars *, void *, void **);
TmEcode DecodeNetmap(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);

TmEcode NetmapSetBPFFilter(NetmapThreadVars *ptv);
static int NetmapGetIfnumByDev(int fd, const char *ifname, int verbose);

/**
 * \brief Registration Function for RecieveNetmap.
 * \todo Unit tests are needed for this module.
 */
void TmModuleReceiveNetmapRegister (void) {
    tmm_modules[TMM_RECEIVENETMAP].name = "ReceiveNetmap";
    tmm_modules[TMM_RECEIVENETMAP].ThreadInit = ReceiveNetmapThreadInit;
    tmm_modules[TMM_RECEIVENETMAP].Func = NULL;
    tmm_modules[TMM_RECEIVENETMAP].PktAcqLoop = ReceiveNetmapLoop;
    tmm_modules[TMM_RECEIVENETMAP].ThreadExitPrintStats = ReceiveNetmapThreadExitStats;
    tmm_modules[TMM_RECEIVENETMAP].ThreadDeinit = NULL;
    tmm_modules[TMM_RECEIVENETMAP].RegisterTests = NULL;
    tmm_modules[TMM_RECEIVENETMAP].cap_flags = SC_CAP_NET_RAW;
    tmm_modules[TMM_RECEIVENETMAP].flags = TM_FLAG_RECEIVE_TM;
}

/**
 *  \defgroup Netmap peers list
 *
 * Netmap has an IPS mode were interface are peered: packet from
 * on interface are sent the peered interface and the other way. The ::NetmapPeer
 * list is maitaining the list of peers. Each ::NetmapPeer is storing the needed
 * information to be able to send packet on the interface.
 * A element of the list must not be destroyed during the run of Suricata as it
 * is used by ::Packet and other threads.
 *
 *  @{
 */

typedef struct NetmapPeersList_ {
    TAILQ_HEAD(, NetmapPeer_) peers; /**< Head of list of fragments. */
    int cnt;
    int peered;
    int turn; /**< Next value for initialisation order */
    SC_ATOMIC_DECLARE(int, reached); /**< Counter used to synchronize start */
} NetmapPeersList;

SC_ATOMIC_DECL_AND_INIT(int, NetmapThreadOrdinal);

/**
 * \brief Update the peer.
 *
 * Update the NetmapPeer of a thread ie set new state, socket number
 * or iface index.
 *
 */
void NetmapPeerUpdate(NetmapThreadVars *ptv)
{
    if (ptv->mpeer == NULL) {
        return;
    }
    (void)SC_ATOMIC_SET(ptv->mpeer->if_idx, NetmapGetIfnumByDev(ptv->socket, ptv->iface, 0));
    //(void)SC_ATOMIC_SET(ptv->mpeer->socket, ptv->socket);
    (void)SC_ATOMIC_SET(ptv->mpeer->state, ptv->netmap_state);
}

/**
 * \brief Clean and free ressource used by an ::NetmapPeer
 */
void NetmapPeerClean(NetmapPeer *peer)
{
    //SCMutexDestroy(&peer->peer_protect);
    SC_ATOMIC_DESTROY(peer->if_idx);
    SC_ATOMIC_DESTROY(peer->state);
    SCFree(peer);
}

NetmapPeersList peerslist;


/**
 * \brief Init the global list of ::NetmapPeer
 */
TmEcode NetmapPeersListInit()
{
    SCEnter();
    TAILQ_INIT(&peerslist.peers);
    peerslist.peered = 0;
    peerslist.cnt = 0;
    peerslist.turn = 0;
    SC_ATOMIC_INIT(peerslist.reached);
    (void) SC_ATOMIC_SET(peerslist.reached, 0);
    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief Check that all ::NetmapPeer got a peer
 *
 * \retval TM_ECODE_FAILED if some threads are not peered or TM_ECODE_OK else.
 */
TmEcode NetmapPeersListCheck()
{
#define NETMAP_PEERS_MAX_TRY 4
#define NETMAP_PEERS_WAIT 20000
    int try = 0;
    SCEnter();
    while (try < NETMAP_PEERS_MAX_TRY) {
        if (peerslist.cnt != peerslist.peered) {
            usleep(NETMAP_PEERS_WAIT);
        } else {
            SCReturnInt(TM_ECODE_OK);
        }
        try++;
    }
    SCLogError(SC_ERR_NETMAP_CREATE, "Threads number not equal");
    SCReturnInt(TM_ECODE_FAILED);
}

/**
 * \brief Declare a new Netmap thread to Netmap peers list.
 */
TmEcode NetmapPeersListAdd(NetmapThreadVars *ptv)
{
    SCEnter();
    NetmapPeer *peer = SCMalloc(sizeof(NetmapPeer));
    NetmapPeer *pitem;
    int mtu, out_mtu;

    if (unlikely(peer == NULL)) {
        SCReturnInt(TM_ECODE_FAILED);
    }
    memset(peer, 0, sizeof(NetmapPeer));
    SC_ATOMIC_INIT(peer->if_idx);
    SC_ATOMIC_INIT(peer->state);
    peer->flags = ptv->flags;
    peer->turn = peerslist.turn++;

    //SCMutexInit(&peer->peer_protect, NULL);

    (void)SC_ATOMIC_SET(peer->state, NETMAP_STATE_DOWN);
    strlcpy(peer->iface, ptv->iface, NETMAP_IFACE_NAME_LENGTH);
    ptv->mpeer = peer;
    /* add element to iface list */
    TAILQ_INSERT_TAIL(&peerslist.peers, peer, next);

    if (ptv->copy_mode != NETMAP_COPY_MODE_NONE) {
        peerslist.cnt++;

        /* Iter to find a peer */
        TAILQ_FOREACH(pitem, &peerslist.peers, next) {
            if (pitem->peer)
                continue;
            if (strcmp(pitem->iface, ptv->out_iface))
                continue;
            peer->peer = pitem;
            pitem->peer = peer;
            mtu = GetIfaceMTU(ptv->iface);
            out_mtu = GetIfaceMTU(ptv->out_iface);
            if (mtu != out_mtu) {
                SCLogError(SC_ERR_NETMAP_CREATE,
                        "MTU on %s (%d) and %s (%d) are not equal, "
                        "transmission of packets bigger than %d will fail.",
                        ptv->iface, mtu,
                        ptv->out_iface, out_mtu,
                        (out_mtu > mtu) ? mtu : out_mtu);
            }
            peerslist.peered += 2;
            break;
        }
    }

    NetmapPeerUpdate(ptv);

    SCReturnInt(TM_ECODE_OK);
}

int NetmapPeersListWaitTurn(NetmapPeer *peer)
{
    /* If turn is zero, we already have started threads once */
    if (peerslist.turn == 0)
        return 0;

    if (peer->turn == SC_ATOMIC_GET(peerslist.reached))
        return 0;
    return 1;
}

void NetmapPeersListReachedInc()
{
    if (peerslist.turn == 0)
        return;

    if (SC_ATOMIC_ADD(peerslist.reached, 1) == peerslist.turn) {
        SCLogInfo("All Netmap capture threads are running.");
        (void)SC_ATOMIC_SET(peerslist.reached, 0);
        /* Set turn to 0 to skip syncrhonization when ReceiveNetmapLoop is
         * restarted.
         */
        peerslist.turn = 0;
    }
}

/**
 * \brief Clean the global peers list.
 */
void NetmapPeersListClean()
{
    NetmapPeer *pitem;

    while ((pitem = TAILQ_FIRST(&peerslist.peers))) {
        TAILQ_REMOVE(&peerslist.peers, pitem, next);
        NetmapPeerClean(pitem);
    }
}

/**
 * @}
 */

/**
 * \brief Registration Function for DecodeNetmap.
 * \todo Unit tests are needed for this module.
 */
void TmModuleDecodeNetmapRegister (void) {
    tmm_modules[TMM_DECODENETMAP].name = "DecodeNetmap";
    tmm_modules[TMM_DECODENETMAP].ThreadInit = DecodeNetmapThreadInit;
    tmm_modules[TMM_DECODENETMAP].Func = DecodeNetmap;
    tmm_modules[TMM_DECODENETMAP].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODENETMAP].ThreadDeinit = NULL;
    tmm_modules[TMM_DECODENETMAP].RegisterTests = NULL;
    tmm_modules[TMM_DECODENETMAP].cap_flags = 0;
    tmm_modules[TMM_DECODENETMAP].flags = TM_FLAG_DECODE_TM;
}


static int NetmapOpen(NetmapThreadVars *ptv, char *devname, int verbose);

static inline void NetmapDumpCounters(NetmapThreadVars *ptv)
{
#ifdef PACKET_STATISTICS
    struct tpacket_stats kstats;
    socklen_t len = sizeof (struct tpacket_stats);
    if (getsockopt(ptv->socket, SOL_PACKET, PACKET_STATISTICS,
                &kstats, &len) > -1) {
        SCLogDebug("(%s) Kernel: Packets %" PRIu32 ", dropped %" PRIu32 "",
                ptv->tv->name,
                kstats.tp_packets, kstats.tp_drops);
        (void) SC_ATOMIC_ADD(ptv->livedev->drop, kstats.tp_drops);
    }
#endif
}

/* Atomic increment a 32 bit counter.
 * These operate on resources shared with the Netmap driver
 * so these couldn't use the usual primitives in util-atomic.h
 */
static inline uint32_t NetmapAtomicIncr(uint32_t *x)
{
#ifdef SCAtomicAddAndFetch
    return SCAtomicAddAndFetch(x, 1);
#else
#error not implemented yet
    /* this is going to be ugly and suboptimal */
#endif
}

/* Atomic decrement a 32 bit counter.
 * These operate on resources shared with the Netmap driver
 * so these couldn't use the usual primitives in util-atomic.h
 */
static inline uint32_t NetmapAtomicDecr(uint32_t *x)
{
#ifdef SCAtomicSubAndFetch
    return SCAtomicSubAndFetch(x, 1);
#else
#error not implemented yet
    /* this is going to be ugly and suboptimal */
#endif
}

TmEcode NetmapWritePacket(Packet *p)
{
    struct netmap_ring *rxring, *txring;
    struct netmap_slot *rs, *ts;
    u_int j, k;

    if (p->netmap_v.copy_mode == NETMAP_COPY_MODE_IPS) {
        if (PACKET_TEST_ACTION(p, ACTION_DROP)) {
            return TM_ECODE_OK;
        }
    }

    if (SC_ATOMIC_GET(p->netmap_v.peer->state) == NETMAP_STATE_DOWN)
        return TM_ECODE_OK;

    if (p->ethh == NULL) {
        SCLogWarning(SC_ERR_INVALID_VALUE, "Should have an Ethernet header");
        return TM_ECODE_FAILED;
    }

    rxring = p->netmap_v.rx;
    txring = p->netmap_v.tx;
    j = p->netmap_v.rx_slot; /* RX */
    k = txring->cur;         /* TX */
    SCLogInfo("Flipping ring %d rx slot %d for tx slot %d",
              p->netmap_v.rx_ring, j, k);
    rs = &rxring->slot[j];
    ts = &txring->slot[k];
    uint32_t pkt;
    pkt = ts->buf_idx;
    ts->buf_idx = rs->buf_idx;
    rs->buf_idx = pkt;
    ts->len = rs->len;
    /* report the buffer change. */
    ts->flags |= NS_BUF_CHANGED;
    rs->flags |= NS_BUF_CHANGED;
    k = NETMAP_RING_NEXT(txring, k);
    txring->cur = k;

    return TM_ECODE_OK;
}

void NetmapReleaseDataFromRing(Packet *p)
{
    struct netmap_ring *rxring = p->netmap_v.rx;

    /* Need to be in copy mode and need to detect early release
       where Ethernet header could not be set (and pseudo packet) */
    if ((p->netmap_v.copy_mode != NETMAP_COPY_MODE_NONE) && !PKT_IS_PSEUDOPKT(p)) {
        NetmapWritePacket(p);
    }
    /* TBD: need to make this work across threads */
    //rxring->reserved--;
    NetmapAtomicDecr(&rxring->reserved);
}

void NetmapReleasePacket(Packet *p)
{
    NetmapReleaseDataFromRing(p);
    PacketFreeOrRelease(p);
}


void NetmapSwitchState(NetmapThreadVars *ptv, int state)
{
    ptv->netmap_state = state;
    ptv->down_count = 0;

    NetmapPeerUpdate(ptv);
}

/**
 * \brief Try to reopen socket
 *
 * \retval 0 in case of success, negative if error occurs or a condition
 * is not met.
 */
static int NetmapTryReopen(NetmapThreadVars *ptv)
{
    int netmap_activate_r;

    ptv->down_count++;

    netmap_activate_r = NetmapOpen(ptv, ptv->iface, 0);
    if (netmap_activate_r != 0) {
        if (ptv->down_count % NETMAP_DOWN_COUNTER_INTERVAL == 0) {
            SCLogWarning(SC_ERR_NETMAP_CREATE, "Can not open iface '%s'",
                         ptv->iface);
        }
        return netmap_activate_r;
    }

    SCLogInfo("Interface '%s' is back", ptv->iface);
    return 0;
}

/**
 *  \brief Main Netmap packet reading Loop function
 */
TmEcode ReceiveNetmapLoop(ThreadVars *tv, void *data, void *slot)
{
    SCEnter();

    Packet *p = NULL;
    uint16_t packet_q_len = 0;
    NetmapThreadVars *ptv = (NetmapThreadVars *)data;
    struct pollfd fds;
    int r;
    u_int i;
    TmSlot *s = (TmSlot *)slot;

    ptv->slot = s->slot_next;

    if (ptv->netmap_state == NETMAP_STATE_DOWN) {
        /* Wait for our turn, threads before us must have opened the socket */
        while (NetmapPeersListWaitTurn(ptv->mpeer)) {
            usleep(1000);
        }
        r = NetmapOpen(ptv, ptv->iface, 1);
        if (r < 0) {
            SCLogError(SC_ERR_NETMAP_CREATE, "Couldn't init Netmap fd: %s",
                       ptv->iface);
        }
        NetmapPeersListReachedInc();
    }
    if (ptv->netmap_state == NETMAP_STATE_UP) {
        SCLogInfo("Thread %s:%d using Netmap %s fd %d UP",
                  tv->name, ptv->thread_no, ptv->iface, ptv->rx_fd);
    }

    fds.fd = ptv->rx_fd;
    fds.events = POLLIN;
#ifdef NOTYET
    if (ptv->copy_mode != NETMAP_COPY_MODE_NONE)
        fds.events |= POLLOUT;
#endif

    while (1) {
        /* Start by checking the state of our interface */
        if (unlikely(ptv->netmap_state == NETMAP_STATE_DOWN)) {
            int dbreak = 0;

            do {
                usleep(NETMAP_RECONNECT_TIMEOUT);
                if (suricata_ctl_flags != 0) {
                    dbreak = 1;
                    break;
                }
                r = NetmapTryReopen(ptv);
                fds.fd = ptv->socket;
            } while (r < 0);
            if (dbreak == 1)
                break;
        }

        /* make sure we have at least one packet in the packet pool, to prevent
         * us from alloc'ing packets at line rate */
        do {
            packet_q_len = PacketPoolSize();
            if (unlikely(packet_q_len == 0)) {
                PacketPoolWait();
            }
        } while (packet_q_len == 0);

        r = poll(&fds, 1, POLL_TIMEOUT);

        if (suricata_ctl_flags != 0) {
            break;
        }

        if (unlikely(r <= 0)) {
            SCPerfSyncCountersIfSignalled(tv);
            continue;
        }

        for (i = ptv->begin; i < ptv->end; i++) {

            struct netmap_ring *ring = NETMAP_RXRING(ptv->nifp, i);
            if (ring->avail > 0) {
                SCLogDebug("ring[%d]->avail: %" PRIu32 "", i, ring->avail);
            }
            u_int cur = ring->cur;
#if 0
            int avail = ring->avail;
            for (avail = ring->avail; avail > 0; avail--) {
#else
            for ( ; ring->avail > 0 ; ring->avail-- ) {
#endif
                p = PacketGetFromQueueOrAlloc();
                if (unlikely(p == NULL)) {
                    break;
                }
                PKT_SET_SRC(p, PKT_SRC_WIRE);

                struct netmap_slot *slot = &ring->slot[cur];

                uint8_t *pkt = (uint8_t *)NETMAP_BUF(ring, slot->buf_idx);
                int len = slot->len;
                ptv->pkts++;
                ptv->bytes += len;
//#define DEBUG_PACKET_DUMPER
#ifdef DEBUG_PACKET_DUMPER
                SCLogInfo("Got a packet %s pktlen: %" PRIu32 " (pkt %p, pkt data %p)\n",
                           ptv->iface, len, p, pkt);
                int j;
                for (j = 0; j < len; j++) {
                    printf("%02x ", pkt[j]);
                    if (((j+1)%16) ==0) printf("\n");
                }
                printf("\n");
#endif

                p->datalink = ptv->datalink;
                if (likely(PacketSetData(p, pkt, len) != -1)) {
                    /* TBD: need to do something more efficient than this */
                    gettimeofday(&p->ts, NULL);
                    SCLogDebug("pktlen: %" PRIu32 " (pkt %p, pkt data %p)",
                               GET_PKT_LEN(p), p, GET_PKT_DATA(p));
                    p->netmap_v.rx = ring;
                    p->netmap_v.rx_ring = i;
                    p->netmap_v.rx_slot = cur;
                    p->ReleasePacket = NetmapReleasePacket;
                    p->netmap_v.copy_mode = ptv->copy_mode;
                    if (ptv->copy_mode != NETMAP_COPY_MODE_NONE) {
                        p->netmap_v.tx = NETMAP_TXRING(ptv->tx_nifp, i);
                        p->netmap_v.peer = ptv->mpeer->peer;
                        //ring->reserved++;
                    } else {
                        p->netmap_v.peer = NULL;
                    }

                    /* We only check for checksum disable */
                    if (ptv->checksum_mode == CHECKSUM_VALIDATION_DISABLE) {
                        p->flags |= PKT_IGNORE_CHECKSUM;
                    } else if (ptv->checksum_mode == CHECKSUM_VALIDATION_AUTO) {
                        if (ptv->livedev->ignore_checksum) {
                            p->flags |= PKT_IGNORE_CHECKSUM;
                        } else if (ChecksumAutoModeCheck(ptv->pkts,
                                    SC_ATOMIC_GET(ptv->livedev->pkts),
                                    SC_ATOMIC_GET(ptv->livedev->invalid_checksums))) {
                            ptv->livedev->ignore_checksum = 1;
                            p->flags |= PKT_IGNORE_CHECKSUM;
                        }
                    } else {
                        p->flags |= PKT_IGNORE_CHECKSUM;
                    }

                    if (TmThreadsSlotProcessPkt(ptv->tv, ptv->slot, p) !=
                         TM_ECODE_OK) {
                        TmqhOutputPacketpool(ptv->tv, p);
                    }

                } else {
                    TmqhOutputPacketpool(ptv->tv, p);
                }
                (void) SC_ATOMIC_ADD(ptv->livedev->pkts, 1);
                ring->cur = NETMAP_RING_NEXT(ring, cur);        
                //if (ptv->copy_mode != NETMAP_COPY_MODE_NONE) {
                //    ring->avail -= 1;
                //}
                NetmapAtomicDecr(&ring->reserved);
            }
        }
        SCPerfSyncCountersIfSignalled(tv);
    }

    SCReturnInt(TM_ECODE_OK);
}

static int NetmapGetIfnumByDev(int fd, const char *ifname, int verbose)
{
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

    if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1) {
           if (verbose)
               SCLogError(SC_ERR_NETMAP_CREATE, "Unable to find iface %s: %s",
                          ifname, strerror(errno));
        return -1;
    }

    return ifr.ifr_ifindex;
}

static int NetmapGetDevLinktype(int fd, const char *ifname)
{
    return LINKTYPE_ETHERNET;
}

static int NetmapOpen(NetmapThreadVars *ptv, char *devname, int verbose)
{
    int fd, err, l;
    struct nmreq req;
    int devqueues = 1;
  
    ptv->rx_fd = fd = open("/dev/netmap", O_RDWR);
    if (fd < 0) {
        SCLogError(SC_ERR_NETMAP_CREATE, "Couldn't open /dev/netmap, error %s", strerror(errno));
        goto error;
    }
    memset(&req, 0, sizeof(req));
    req.nr_version = NETMAP_API;
    strncpy(req.nr_name, ptv->iface, sizeof(req.nr_name));
    req.nr_ringid = 0;
    err = ioctl(fd, NIOCGINFO, &req);
    if (err) {
        SCLogError(SC_ERR_NETMAP_CREATE, "Cannot get info on %s, error %s ver %d",
                   ptv->iface, strerror(errno), req.nr_version);
        goto error;
    }
    devqueues = req.nr_rx_rings;
    if ((devqueues % ptv->threads) != 0) {
        SCLogError(SC_ERR_NETMAP_CREATE,
                   "Number of NIC queues (%d) should be an integer multiple"
                   " of the number of threads (%d).",
                   devqueues, ptv->threads);
        exit(EXIT_FAILURE);
    }
    if (ptv->threads > devqueues) {
        SCLogError(SC_ERR_NETMAP_CREATE,
                   "Too many threads %d. NIC has %d only queues.",
                   ptv->threads, devqueues);
        exit(EXIT_FAILURE);
    }
    ptv->memsize = l = req.nr_memsize;
    SCLogDebug("Device map size is %"PRIu32" Kb", ptv->memsize >> 10);
    
    if ((ptv->flags & NETMAP_WORKERS_MODE) && (devqueues == ptv->threads))
        req.nr_ringid = ptv->thread_no | NETMAP_HW_RING;
    else
        req.nr_ringid = 0;

    if (ptv->copy_mode == NETMAP_COPY_MODE_NONE) {
        req.nr_ringid |= NETMAP_NO_TX_POLL;
    }
    err = ioctl(fd, NIOCREGIF, &req);
    if (err) {
        SCLogError(SC_ERR_NETMAP_CREATE, "Unable to register %s",
                   ptv->iface);
        goto error;
    }
    if (ptv->mem == NULL) {
        ptv->mem = mmap(0, l, PROT_WRITE|PROT_READ, MAP_SHARED, fd, 0);
        if (ptv->mem == MAP_FAILED) {
            SCLogError(SC_ERR_NETMAP_CREATE, "Unable to mmap %s, error %s",
                   ptv->iface, strerror(errno));
            ptv->mem = NULL;
            goto error;
        }
    }

    ptv->nifp = NETMAP_IF(ptv->mem, req.nr_offset);
    if (ptv->flags & NETMAP_WORKERS_MODE) {
        int rings_per_thread = devqueues / ptv->threads;
        ptv->begin = (ptv->thread_no * rings_per_thread) & NETMAP_RING_MASK;
        ptv->end = ptv->begin + rings_per_thread;
        ptv->tx = NETMAP_TXRING(ptv->nifp, ptv->begin);
        ptv->rx = NETMAP_RXRING(ptv->nifp, ptv->begin);
    } else {
        ptv->begin = 0;
        ptv->end = devqueues; /* XXX max of the two */
        ptv->tx = NETMAP_TXRING(ptv->nifp, 0);
        ptv->rx = NETMAP_RXRING(ptv->nifp, 0);
    }
    SCLogDebug("First ring %"PRIu32" Last ring %"PRIu32,
               ptv->begin, ptv->end-1);

    /*
     * If copy_mode is set (IDS/TAP) then we need to open the transmit
     * interface.
     */
    if (ptv->copy_mode != NETMAP_COPY_MODE_NONE) {

        if ((ptv->flags & NETMAP_WORKERS_MODE) == 0) {
            SCLogError(SC_ERR_NETMAP_CREATE,
                       "%s mode only supported for \"workers\" runmode.",
                       (ptv->copy_mode == NETMAP_COPY_MODE_TAP) ?
                            "TAP" : "IPS" );
            exit(EXIT_FAILURE);
        }

        ptv->tx_fd = fd = open("/dev/netmap", O_RDWR);
        if (fd < 0) {
            SCLogError(SC_ERR_NETMAP_CREATE, "Couldn't open /dev/netmap, error %s", strerror(errno));
            goto error;
        }
        memset(&req, 0, sizeof(req));
        req.nr_version = NETMAP_API;
        strncpy(req.nr_name, ptv->out_iface, sizeof(req.nr_name));
        req.nr_ringid = 0;
        err = ioctl(fd, NIOCGINFO, &req);
        if (err) {
            SCLogError(SC_ERR_NETMAP_CREATE, "Cannot get info on %s, error %s ver %d",
                       ptv->iface, strerror(errno), req.nr_version);
            goto error;
        }
        devqueues = req.nr_tx_rings;
        if (devqueues < ptv->threads) {
            SCLogError(SC_ERR_NETMAP_CREATE,
                       "Too many threads %d. NIC has %d only queues.",
                       ptv->threads, devqueues);
            exit(EXIT_FAILURE);
        }
        ptv->memsize = l = req.nr_memsize;
        SCLogDebug("Device map size is %"PRIu32" Kb", ptv->memsize >> 10);
    
        if ((ptv->flags & NETMAP_WORKERS_MODE) && (devqueues == ptv->threads))
            req.nr_ringid = ptv->thread_no | NETMAP_HW_RING;
        else
            req.nr_ringid = 0;

        err = ioctl(fd, NIOCREGIF, &req);
        if (err) {
            SCLogError(SC_ERR_NETMAP_CREATE, "Unable to register %s",
                       ptv->iface);
            goto error;
        }
        if (ptv->mem == NULL) {
            ptv->mem = mmap(0, l, PROT_WRITE|PROT_READ, MAP_SHARED, fd, 0);
            if (ptv->mem == MAP_FAILED) {
                SCLogError(SC_ERR_NETMAP_CREATE, "Unable to mmap %s, error %s",
                       ptv->iface, strerror(errno));
                ptv->mem = NULL;
                goto error;
            }
        }

        ptv->tx_nifp = NETMAP_IF(ptv->mem, req.nr_offset);
        if (ptv->flags & NETMAP_WORKERS_MODE) {
            ptv->tx = NETMAP_TXRING(ptv->tx_nifp, ptv->begin);
        } else {
            ptv->tx = NETMAP_TXRING(ptv->tx_nifp, 0);
        }
    }

    ptv->datalink = NetmapGetDevLinktype(ptv->socket, ptv->iface);
    switch (ptv->datalink) {
        case ARPHRD_PPP:
        case ARPHRD_ATM:
            ptv->cooked = 1;
    }

    /* Init is ok */
    NetmapSwitchState(ptv, NETMAP_STATE_UP);
    return (0);

error:
    if (ptv->rx_fd) {
        close(ptv->rx_fd);
        ptv->rx_fd = 0;
    }
    if (ptv->tx_fd) {
        close(ptv->tx_fd);
        ptv->tx_fd = 0;
    }
    return -1;
}

/**
 * \brief Init function for ReceiveNetmap.
 *
 * \param tv pointer to ThreadVars
 * \param initdata pointer to the interface passed from the user
 * \param data pointer gets populated with NetmapThreadVars
 *
 * \todo Create a general Netmap setup function.
 */
TmEcode ReceiveNetmapThreadInit(ThreadVars *tv, void *initdata, void **data) {
    SCEnter();
    NetmapIfaceConfig *netmapconfig = initdata;

    if (initdata == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "initdata == NULL");
        SCReturnInt(TM_ECODE_FAILED);
    }

    NetmapThreadVars *ptv = SCMalloc(sizeof(NetmapThreadVars));
    if (unlikely(ptv == NULL)) {
        netmapconfig->DerefFunc(netmapconfig);
        SCReturnInt(TM_ECODE_FAILED);
    }
    memset(ptv, 0, sizeof(NetmapThreadVars));

    ptv->tv = tv;
    ptv->cooked = 0;

    ptv->thread_no = SC_ATOMIC_ADD(NetmapThreadOrdinal, 1) - 1;
    SCLogInfo("Initing Netmap %d", ptv->thread_no);

    strlcpy(ptv->iface, netmapconfig->iface, NETMAP_IFACE_NAME_LENGTH);
    ptv->iface[NETMAP_IFACE_NAME_LENGTH - 1]= '\0';

    ptv->livedev = LiveGetDevice(ptv->iface);
    if (ptv->livedev == NULL) {
        SCLogError(SC_ERR_INVALID_VALUE, "Unable to find Live device");
        SCFree(ptv);
        SCReturnInt(TM_ECODE_FAILED);
    }

    ptv->promisc = netmapconfig->promisc;
    ptv->checksum_mode = netmapconfig->checksum_mode;
    ptv->bpf_filter = NULL;

    ptv->threads = netmapconfig->threads;
    ptv->flags = netmapconfig->flags;

    if (netmapconfig->bpf_filter) {
        ptv->bpf_filter = netmapconfig->bpf_filter;
    }


    char *active_runmode = RunmodeGetActive();
    if (active_runmode && !strcmp("workers", active_runmode)) {
        ptv->flags |= NETMAP_WORKERS_MODE;
    }
    ptv->flags |= NETMAP_ZERO_COPY;

    ptv->copy_mode = netmapconfig->copy_mode;
    if (ptv->copy_mode != NETMAP_COPY_MODE_NONE) {
        strlcpy(ptv->out_iface, netmapconfig->out_iface, NETMAP_IFACE_NAME_LENGTH);
        ptv->out_iface[NETMAP_IFACE_NAME_LENGTH - 1]= '\0';
        /* Warn about BPF filter consequence */
        if (ptv->bpf_filter) {
            SCLogWarning(SC_WARN_UNCOMMON, "Enabling a BPF filter in IPS mode result"
                      " in dropping all non matching packets.");
        }
    }

    if (NetmapPeersListAdd(ptv) == TM_ECODE_FAILED) {
        SCFree(ptv);
        netmapconfig->DerefFunc(netmapconfig);
        SCReturnInt(TM_ECODE_FAILED);
    }

#define T_DATA_SIZE 70000
    ptv->data = SCMalloc(T_DATA_SIZE);
    if (ptv->data == NULL) {
        netmapconfig->DerefFunc(netmapconfig);
        SCFree(ptv);
        SCReturnInt(TM_ECODE_FAILED);
    }
    ptv->datalen = T_DATA_SIZE;
#undef T_DATA_SIZE

    *data = (void *)ptv;

    netmapconfig->DerefFunc(netmapconfig);
    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief This function prints stats to the screen at exit.
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into NetmapThreadVars for ptv
 */
void ReceiveNetmapThreadExitStats(ThreadVars *tv, void *data) {
    SCEnter();
    NetmapThreadVars *ptv = (NetmapThreadVars *)data;

#ifdef NOTYET
#ifdef PACKET_STATISTICS
    NetmapDumpCounters(ptv);
    SCLogInfo("(%s) Kernel: Packets %" PRIu64 ", dropped %" PRIu64 "",
            tv->name,
            (uint64_t) SCPerfGetLocalCounterValue(ptv->capture_kernel_packets, tv->sc_perf_pca),
            (uint64_t) SCPerfGetLocalCounterValue(ptv->capture_kernel_drops, tv->sc_perf_pca));
#endif
#endif

    SCLogInfo("(%s) Packets %" PRIu32 ", bytes %" PRIu64 "", tv->name, ptv->pkts, ptv->bytes);
}

/**
 * \brief DeInit function closes Netmap fd at exit.
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into NetmapThreadVars for ptv
 */
TmEcode ReceiveNetmapThreadDeinit(ThreadVars *tv, void *data) {
    NetmapThreadVars *ptv = (NetmapThreadVars *)data;

    NetmapSwitchState(ptv, NETMAP_STATE_DOWN);

    if (ptv->data != NULL) {
        SCFree(ptv->data);
        ptv->data = NULL;
    }
    ptv->datalen = 0;

    ptv->bpf_filter = NULL;

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
 * \param data pointer that gets cast into NetmapThreadVars for ptv
 * \param pq pointer to the current PacketQueue
 */
TmEcode DecodeNetmap(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    SCEnter();
    DecodeThreadVars *dtv = (DecodeThreadVars *)data;

    /* update counters */
    SCPerfCounterIncr(dtv->counter_pkts, tv->sc_perf_pca);
    SCPerfCounterIncr(dtv->counter_pkts_per_sec, tv->sc_perf_pca);

    SCPerfCounterAddUI64(dtv->counter_bytes, tv->sc_perf_pca, GET_PKT_LEN(p));
#if 0
    SCPerfCounterAddDouble(dtv->counter_bytes_per_sec, tv->sc_perf_pca, GET_PKT_LEN(p));
    SCPerfCounterAddDouble(dtv->counter_mbit_per_sec, tv->sc_perf_pca,
                           (GET_PKT_LEN(p) * 8)/1000000.0);
#endif

    SCPerfCounterAddUI64(dtv->counter_avg_pkt_size, tv->sc_perf_pca, GET_PKT_LEN(p));
    SCPerfCounterSetUI64(dtv->counter_max_pkt_size, tv->sc_perf_pca, GET_PKT_LEN(p));

    /* call the decoder */
    switch(p->datalink) {
        case LINKTYPE_LINUX_SLL:
            DecodeSll(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p), pq);
            break;
        case LINKTYPE_ETHERNET:
            DecodeEthernet(tv, dtv, p,GET_PKT_DATA(p), GET_PKT_LEN(p), pq);
            break;
        case LINKTYPE_PPP:
            DecodePPP(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p), pq);
            break;
        case LINKTYPE_RAW:
            DecodeRaw(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p), pq);
            break;
        default:
            SCLogError(SC_ERR_DATALINK_UNIMPLEMENTED, "Error: datalink type %" PRId32 " not yet supported in module DecodeNetmap", p->datalink);
            break;
    }

    SCReturnInt(TM_ECODE_OK);
}

TmEcode DecodeNetmapThreadInit(ThreadVars *tv, void *initdata, void **data)
{
    SCEnter();
    DecodeThreadVars *dtv = NULL;

    dtv = DecodeThreadVarsAlloc();

    if (dtv == NULL)
        SCReturnInt(TM_ECODE_FAILED);

    DecodeRegisterPerfCounters(dtv, tv);

    *data = (void *)dtv;

    SCReturnInt(TM_ECODE_OK);
}

#endif /* HAVE_NETMAP */
/* eof */
/**
 * @}
 */
