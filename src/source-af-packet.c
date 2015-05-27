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
 *  \defgroup afppacket AF_PACKET running mode
 *
 *  @{
 */

/**
 * \file
 *
 * \author Eric Leblond <eric@regit.org>
 *
 * AF_PACKET socket acquisition support
 *
 * \todo watch other interface event to detect suppression of the monitored
 *       interface
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
#include "source-af-packet.h"
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

#ifdef HAVE_AF_PACKET

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

#endif /* HAVE_AF_PACKET */

extern int max_pending_packets;

#ifndef HAVE_AF_PACKET

TmEcode NoAFPSupportExit(ThreadVars *, void *, void **);

void TmModuleReceiveAFPRegister (void)
{
    tmm_modules[TMM_RECEIVEAFP].name = "ReceiveAFP";
    tmm_modules[TMM_RECEIVEAFP].ThreadInit = NoAFPSupportExit;
    tmm_modules[TMM_RECEIVEAFP].Func = NULL;
    tmm_modules[TMM_RECEIVEAFP].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_RECEIVEAFP].ThreadDeinit = NULL;
    tmm_modules[TMM_RECEIVEAFP].RegisterTests = NULL;
    tmm_modules[TMM_RECEIVEAFP].cap_flags = 0;
    tmm_modules[TMM_RECEIVEAFP].flags = TM_FLAG_RECEIVE_TM;
}

/**
 * \brief Registration Function for DecodeAFP.
 * \todo Unit tests are needed for this module.
 */
void TmModuleDecodeAFPRegister (void)
{
    tmm_modules[TMM_DECODEAFP].name = "DecodeAFP";
    tmm_modules[TMM_DECODEAFP].ThreadInit = NoAFPSupportExit;
    tmm_modules[TMM_DECODEAFP].Func = NULL;
    tmm_modules[TMM_DECODEAFP].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODEAFP].ThreadDeinit = NULL;
    tmm_modules[TMM_DECODEAFP].RegisterTests = NULL;
    tmm_modules[TMM_DECODEAFP].cap_flags = 0;
    tmm_modules[TMM_DECODEAFP].flags = TM_FLAG_DECODE_TM;
}

/**
 * \brief this function prints an error message and exits.
 */
TmEcode NoAFPSupportExit(ThreadVars *tv, void *initdata, void **data)
{
    SCLogError(SC_ERR_NO_AF_PACKET,"Error creating thread %s: you do not have "
               "support for AF_PACKET enabled, on Linux host please recompile "
               "with --enable-af-packet", tv->name);
    exit(EXIT_FAILURE);
}

#else /* We have AF_PACKET support */

#define AFP_IFACE_NAME_LENGTH 48

#define AFP_STATE_DOWN 0
#define AFP_STATE_UP 1

#define AFP_RECONNECT_TIMEOUT 500000
#define AFP_DOWN_COUNTER_INTERVAL 40

#define POLL_TIMEOUT 100

#ifndef TP_STATUS_USER_BUSY
/* for new use latest bit available in tp_status */
#define TP_STATUS_USER_BUSY (1 << 31)
#endif

#ifndef TP_STATUS_VLAN_VALID
#define TP_STATUS_VLAN_VALID (1 << 4)
#endif

/** protect pfring_set_bpf_filter, as it is not thread safe */
static SCMutex afpacket_bpf_set_filter_lock = SCMUTEX_INITIALIZER;

enum {
    AFP_READ_OK,
    AFP_READ_FAILURE,
    AFP_FAILURE,
    AFP_KERNEL_DROP,
};

enum {
    AFP_FATAL_ERROR = 1,
    AFP_RECOVERABLE_ERROR,
};

union thdr {
    struct tpacket2_hdr *h2;
    void *raw;
};

/**
 * \brief Structure to hold thread specific variables.
 */
typedef struct AFPThreadVars_
{
    /* thread specific socket */
    int socket;
    /* handle state */
    unsigned char afp_state;

    /* data link type for the thread */
    int datalink;
    int cooked;

    /* counters */
    uint64_t pkts;
    uint64_t bytes;
    uint64_t errs;

    ThreadVars *tv;
    TmSlot *slot;

    uint8_t *data; /** Per function and thread data */
    int datalen; /** Length of per function and thread data */

    int vlan_disabled;

    char iface[AFP_IFACE_NAME_LENGTH];
    LiveDevice *livedev;
    int down_count;

    /* Filter */
    char *bpf_filter;

    /* socket buffer size */
    int buffer_size;
    int promisc;
    ChecksumValidationMode checksum_mode;

    /* IPS stuff */
    char out_iface[AFP_IFACE_NAME_LENGTH];
    AFPPeer *mpeer;

    int flags;
    uint16_t capture_kernel_packets;
    uint16_t capture_kernel_drops;

    int cluster_id;
    int cluster_type;

    int threads;
    int copy_mode;

    struct tpacket_req req;
    unsigned int tp_hdrlen;
    unsigned int ring_buflen;
    char *ring_buf;
    char *frame_buf;
    unsigned int frame_offset;
    int ring_size;

} AFPThreadVars;

TmEcode ReceiveAFP(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode ReceiveAFPThreadInit(ThreadVars *, void *, void **);
void ReceiveAFPThreadExitStats(ThreadVars *, void *);
TmEcode ReceiveAFPThreadDeinit(ThreadVars *, void *);
TmEcode ReceiveAFPLoop(ThreadVars *tv, void *data, void *slot);

TmEcode DecodeAFPThreadInit(ThreadVars *, void *, void **);
TmEcode DecodeAFPThreadDeinit(ThreadVars *tv, void *data);
TmEcode DecodeAFP(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);

TmEcode AFPSetBPFFilter(AFPThreadVars *ptv);
static int AFPGetIfnumByDev(int fd, const char *ifname, int verbose);
static int AFPGetDevFlags(int fd, const char *ifname);
static int AFPDerefSocket(AFPPeer* peer);
static int AFPRefSocket(AFPPeer* peer);

/**
 * \brief Registration Function for RecieveAFP.
 * \todo Unit tests are needed for this module.
 */
void TmModuleReceiveAFPRegister (void)
{
    tmm_modules[TMM_RECEIVEAFP].name = "ReceiveAFP";
    tmm_modules[TMM_RECEIVEAFP].ThreadInit = ReceiveAFPThreadInit;
    tmm_modules[TMM_RECEIVEAFP].Func = NULL;
    tmm_modules[TMM_RECEIVEAFP].PktAcqLoop = ReceiveAFPLoop;
    tmm_modules[TMM_RECEIVEAFP].ThreadExitPrintStats = ReceiveAFPThreadExitStats;
    tmm_modules[TMM_RECEIVEAFP].ThreadDeinit = NULL;
    tmm_modules[TMM_RECEIVEAFP].RegisterTests = NULL;
    tmm_modules[TMM_RECEIVEAFP].cap_flags = SC_CAP_NET_RAW;
    tmm_modules[TMM_RECEIVEAFP].flags = TM_FLAG_RECEIVE_TM;
}


/**
 *  \defgroup afppeers AFP peers list
 *
 * AF_PACKET has an IPS mode were interface are peered: packet from
 * on interface are sent the peered interface and the other way. The ::AFPPeer
 * list is maitaining the list of peers. Each ::AFPPeer is storing the needed
 * information to be able to send packet on the interface.
 * A element of the list must not be destroyed during the run of Suricata as it
 * is used by ::Packet and other threads.
 *
 *  @{
 */

typedef struct AFPPeersList_ {
    TAILQ_HEAD(, AFPPeer_) peers; /**< Head of list of fragments. */
    int cnt;
    int peered;
    int turn; /**< Next value for initialisation order */
    SC_ATOMIC_DECLARE(int, reached); /**< Counter used to synchronize start */
} AFPPeersList;

/**
 * \brief Update the peer.
 *
 * Update the AFPPeer of a thread ie set new state, socket number
 * or iface index.
 *
 */
void AFPPeerUpdate(AFPThreadVars *ptv)
{
    if (ptv->mpeer == NULL) {
        return;
    }
    (void)SC_ATOMIC_SET(ptv->mpeer->if_idx, AFPGetIfnumByDev(ptv->socket, ptv->iface, 0));
    (void)SC_ATOMIC_SET(ptv->mpeer->socket, ptv->socket);
    (void)SC_ATOMIC_SET(ptv->mpeer->state, ptv->afp_state);
}

/**
 * \brief Clean and free ressource used by an ::AFPPeer
 */
void AFPPeerClean(AFPPeer *peer)
{
    if (peer->flags & AFP_SOCK_PROTECT)
        SCMutexDestroy(&peer->sock_protect);
    SC_ATOMIC_DESTROY(peer->socket);
    SC_ATOMIC_DESTROY(peer->if_idx);
    SC_ATOMIC_DESTROY(peer->state);
    SCFree(peer);
}

AFPPeersList peerslist;


/**
 * \brief Init the global list of ::AFPPeer
 */
TmEcode AFPPeersListInit()
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
 * \brief Check that all ::AFPPeer got a peer
 *
 * \retval TM_ECODE_FAILED if some threads are not peered or TM_ECODE_OK else.
 */
TmEcode AFPPeersListCheck()
{
#define AFP_PEERS_MAX_TRY 4
#define AFP_PEERS_WAIT 20000
    int try = 0;
    SCEnter();
    while (try < AFP_PEERS_MAX_TRY) {
        if (peerslist.cnt != peerslist.peered) {
            usleep(AFP_PEERS_WAIT);
        } else {
            SCReturnInt(TM_ECODE_OK);
        }
        try++;
    }
    SCLogError(SC_ERR_AFP_CREATE, "Threads number not equals");
    SCReturnInt(TM_ECODE_FAILED);
}

/**
 * \brief Declare a new AFP thread to AFP peers list.
 */
TmEcode AFPPeersListAdd(AFPThreadVars *ptv)
{
    SCEnter();
    AFPPeer *peer = SCMalloc(sizeof(AFPPeer));
    AFPPeer *pitem;
    int mtu, out_mtu;

    if (unlikely(peer == NULL)) {
        SCReturnInt(TM_ECODE_FAILED);
    }
    memset(peer, 0, sizeof(AFPPeer));
    SC_ATOMIC_INIT(peer->socket);
    SC_ATOMIC_INIT(peer->sock_usage);
    SC_ATOMIC_INIT(peer->if_idx);
    SC_ATOMIC_INIT(peer->state);
    peer->flags = ptv->flags;
    peer->turn = peerslist.turn++;

    if (peer->flags & AFP_SOCK_PROTECT) {
        SCMutexInit(&peer->sock_protect, NULL);
    }

    (void)SC_ATOMIC_SET(peer->sock_usage, 0);
    (void)SC_ATOMIC_SET(peer->state, AFP_STATE_DOWN);
    strlcpy(peer->iface, ptv->iface, AFP_IFACE_NAME_LENGTH);
    ptv->mpeer = peer;
    /* add element to iface list */
    TAILQ_INSERT_TAIL(&peerslist.peers, peer, next);

    if (ptv->copy_mode != AFP_COPY_MODE_NONE) {
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
                SCLogError(SC_ERR_AFP_CREATE,
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

    AFPPeerUpdate(ptv);

    SCReturnInt(TM_ECODE_OK);
}

int AFPPeersListWaitTurn(AFPPeer *peer)
{
    /* If turn is zero, we already have started threads once */
    if (peerslist.turn == 0)
        return 0;

    if (peer->turn == SC_ATOMIC_GET(peerslist.reached))
        return 0;
    return 1;
}

void AFPPeersListReachedInc()
{
    if (peerslist.turn == 0)
        return;

    if (SC_ATOMIC_ADD(peerslist.reached, 1) == peerslist.turn) {
        SCLogInfo("All AFP capture threads are running.");
        (void)SC_ATOMIC_SET(peerslist.reached, 0);
        /* Set turn to 0 to skip syncrhonization when ReceiveAFPLoop is
         * restarted.
         */
        peerslist.turn = 0;
    }
}

static int AFPPeersListStarted()
{
    return !peerslist.turn;
}

/**
 * \brief Clean the global peers list.
 */
void AFPPeersListClean()
{
    AFPPeer *pitem;

    while ((pitem = TAILQ_FIRST(&peerslist.peers))) {
        TAILQ_REMOVE(&peerslist.peers, pitem, next);
        AFPPeerClean(pitem);
    }
}

/**
 * @}
 */

/**
 * \brief Registration Function for DecodeAFP.
 * \todo Unit tests are needed for this module.
 */
void TmModuleDecodeAFPRegister (void)
{
    tmm_modules[TMM_DECODEAFP].name = "DecodeAFP";
    tmm_modules[TMM_DECODEAFP].ThreadInit = DecodeAFPThreadInit;
    tmm_modules[TMM_DECODEAFP].Func = DecodeAFP;
    tmm_modules[TMM_DECODEAFP].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODEAFP].ThreadDeinit = DecodeAFPThreadDeinit;
    tmm_modules[TMM_DECODEAFP].RegisterTests = NULL;
    tmm_modules[TMM_DECODEAFP].cap_flags = 0;
    tmm_modules[TMM_DECODEAFP].flags = TM_FLAG_DECODE_TM;
}


static int AFPCreateSocket(AFPThreadVars *ptv, char *devname, int verbose);

static inline void AFPDumpCounters(AFPThreadVars *ptv)
{
#ifdef PACKET_STATISTICS
    struct tpacket_stats kstats;
    socklen_t len = sizeof (struct tpacket_stats);
    if (getsockopt(ptv->socket, SOL_PACKET, PACKET_STATISTICS,
                &kstats, &len) > -1) {
        SCLogDebug("(%s) Kernel: Packets %" PRIu32 ", dropped %" PRIu32 "",
                ptv->tv->name,
                kstats.tp_packets, kstats.tp_drops);
        StatsAddUI64(ptv->tv, ptv->capture_kernel_packets, kstats.tp_packets);
        StatsAddUI64(ptv->tv, ptv->capture_kernel_drops, kstats.tp_drops);
        (void) SC_ATOMIC_ADD(ptv->livedev->drop, (uint64_t) kstats.tp_drops);
        (void) SC_ATOMIC_ADD(ptv->livedev->pkts, (uint64_t) kstats.tp_packets);
    }
#endif
}

/**
 * \brief AF packet read function.
 *
 * This function fills
 * From here the packets are picked up by the DecodeAFP thread.
 *
 * \param user pointer to AFPThreadVars
 * \retval TM_ECODE_FAILED on failure and TM_ECODE_OK on success
 */
int AFPRead(AFPThreadVars *ptv)
{
    Packet *p = NULL;
    /* XXX should try to use read that get directly to packet */
    int offset = 0;
    int caplen;
    struct sockaddr_ll from;
    struct iovec iov;
    struct msghdr msg;
    struct cmsghdr *cmsg;
    union {
        struct cmsghdr cmsg;
        char buf[CMSG_SPACE(sizeof(struct tpacket_auxdata))];
    } cmsg_buf;
    unsigned char aux_checksum = 0;

    msg.msg_name = &from;
    msg.msg_namelen = sizeof(from);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = &cmsg_buf;
    msg.msg_controllen = sizeof(cmsg_buf);
    msg.msg_flags = 0;

    if (ptv->cooked)
        offset = SLL_HEADER_LEN;
    else
        offset = 0;
    iov.iov_len = ptv->datalen - offset;
    iov.iov_base = ptv->data + offset;

    caplen = recvmsg(ptv->socket, &msg, MSG_TRUNC);

    if (caplen < 0) {
        SCLogWarning(SC_ERR_AFP_READ, "recvmsg failed with error code %" PRId32,
                errno);
        SCReturnInt(AFP_READ_FAILURE);
    }

    p = PacketGetFromQueueOrAlloc();
    if (p == NULL) {
        SCReturnInt(AFP_FAILURE);
    }
    PKT_SET_SRC(p, PKT_SRC_WIRE);

    /* get timestamp of packet via ioctl */
    if (ioctl(ptv->socket, SIOCGSTAMP, &p->ts) == -1) {
        SCLogWarning(SC_ERR_AFP_READ, "recvmsg failed with error code %" PRId32,
                errno);
        TmqhOutputPacketpool(ptv->tv, p);
        SCReturnInt(AFP_READ_FAILURE);
    }

    ptv->pkts++;
    ptv->bytes += caplen + offset;
    p->livedev = ptv->livedev;

    /* add forged header */
    if (ptv->cooked) {
        SllHdr * hdrp = (SllHdr *)ptv->data;
        /* XXX this is minimalist, but this seems enough */
        hdrp->sll_protocol = from.sll_protocol;
    }

    p->datalink = ptv->datalink;
    SET_PKT_LEN(p, caplen + offset);
    if (PacketCopyData(p, ptv->data, GET_PKT_LEN(p)) == -1) {
        TmqhOutputPacketpool(ptv->tv, p);
        SCReturnInt(AFP_FAILURE);
    }
    SCLogDebug("pktlen: %" PRIu32 " (pkt %p, pkt data %p)",
               GET_PKT_LEN(p), p, GET_PKT_DATA(p));

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
        aux_checksum = 1;
    }

    /* List is NULL if we don't have activated auxiliary data */
    for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        struct tpacket_auxdata *aux;

        if (cmsg->cmsg_len < CMSG_LEN(sizeof(struct tpacket_auxdata)) ||
                cmsg->cmsg_level != SOL_PACKET ||
                cmsg->cmsg_type != PACKET_AUXDATA)
            continue;

        aux = (struct tpacket_auxdata *)CMSG_DATA(cmsg);

        if (aux_checksum && (aux->tp_status & TP_STATUS_CSUMNOTREADY)) {
            p->flags |= PKT_IGNORE_CHECKSUM;
        }
        break;
    }

    if (TmThreadsSlotProcessPkt(ptv->tv, ptv->slot, p) != TM_ECODE_OK) {
        TmqhOutputPacketpool(ptv->tv, p);
        SCReturnInt(AFP_FAILURE);
    }
    SCReturnInt(AFP_READ_OK);
}

TmEcode AFPWritePacket(Packet *p)
{
    struct sockaddr_ll socket_address;
    int socket;

    if (p->afp_v.copy_mode == AFP_COPY_MODE_IPS) {
        if (PACKET_TEST_ACTION(p, ACTION_DROP)) {
            return TM_ECODE_OK;
        }
    }

    if (SC_ATOMIC_GET(p->afp_v.peer->state) == AFP_STATE_DOWN)
        return TM_ECODE_OK;

    if (p->ethh == NULL) {
        SCLogWarning(SC_ERR_INVALID_VALUE, "Should have an Ethernet header");
        return TM_ECODE_FAILED;
    }
    /* Index of the network device */
    socket_address.sll_ifindex = SC_ATOMIC_GET(p->afp_v.peer->if_idx);
    /* Address length*/
    socket_address.sll_halen = ETH_ALEN;
    /* Destination MAC */
    memcpy(socket_address.sll_addr, p->ethh, 6);

    /* Send packet, locking the socket if necessary */
    if (p->afp_v.peer->flags & AFP_SOCK_PROTECT)
        SCMutexLock(&p->afp_v.peer->sock_protect);
    socket = SC_ATOMIC_GET(p->afp_v.peer->socket);
    if (sendto(socket, GET_PKT_DATA(p), GET_PKT_LEN(p), 0,
               (struct sockaddr*) &socket_address,
               sizeof(struct sockaddr_ll)) < 0) {
        SCLogWarning(SC_ERR_SOCKET, "Sending packet failed on socket %d: %s",
                  socket,
                  strerror(errno));
        if (p->afp_v.peer->flags & AFP_SOCK_PROTECT)
            SCMutexUnlock(&p->afp_v.peer->sock_protect);
        return TM_ECODE_FAILED;
    }
    if (p->afp_v.peer->flags & AFP_SOCK_PROTECT)
        SCMutexUnlock(&p->afp_v.peer->sock_protect);

    return TM_ECODE_OK;
}

void AFPReleaseDataFromRing(Packet *p)
{
    /* Need to be in copy mode and need to detect early release
       where Ethernet header could not be set (and pseudo packet) */
    if ((p->afp_v.copy_mode != AFP_COPY_MODE_NONE) && !PKT_IS_PSEUDOPKT(p)) {
        AFPWritePacket(p);
    }

    if (AFPDerefSocket(p->afp_v.mpeer) == 0)
        goto cleanup;

    if (p->afp_v.relptr) {
        union thdr h;
        h.raw = p->afp_v.relptr;
        h.h2->tp_status = TP_STATUS_KERNEL;
    }

cleanup:
    AFPV_CLEANUP(&p->afp_v);
}

void AFPReleasePacket(Packet *p)
{
    AFPReleaseDataFromRing(p);
    PacketFreeOrRelease(p);
}

/**
 * \brief AF packet read function for ring
 *
 * This function fills
 * From here the packets are picked up by the DecodeAFP thread.
 *
 * \param user pointer to AFPThreadVars
 * \retval TM_ECODE_FAILED on failure and TM_ECODE_OK on success
 */
int AFPReadFromRing(AFPThreadVars *ptv)
{
    Packet *p = NULL;
    union thdr h;
    struct sockaddr_ll *from;
    uint8_t emergency_flush = 0;
    int read_pkts = 0;
    int loop_start = -1;


    /* Loop till we have packets available */
    while (1) {
        if (unlikely(suricata_ctl_flags != 0)) {
            break;
        }

        /* Read packet from ring */
        h.raw = (((union thdr **)ptv->frame_buf)[ptv->frame_offset]);
        if (h.raw == NULL) {
            SCReturnInt(AFP_FAILURE);
        }

        if ((! h.h2->tp_status) || (h.h2->tp_status & TP_STATUS_USER_BUSY)) {
            if (read_pkts == 0) {
                if (loop_start == -1) {
                    loop_start = ptv->frame_offset;
                } else if (unlikely(loop_start == (int)ptv->frame_offset)) {
                    SCReturnInt(AFP_READ_OK);
                }
                if (++ptv->frame_offset >= ptv->req.tp_frame_nr) {
                    ptv->frame_offset = 0;
                }
                continue;
            }
            if ((emergency_flush) && (ptv->flags & AFP_EMERGENCY_MODE)) {
                SCReturnInt(AFP_KERNEL_DROP);
            } else {
                SCReturnInt(AFP_READ_OK);
            }
        }

        read_pkts++;
        loop_start = -1;

        /* Our packet is still used by suricata, we exit read loop to
         * gain some time */
        if (h.h2->tp_status & TP_STATUS_USER_BUSY) {
            SCReturnInt(AFP_READ_OK);
        }

        if ((ptv->flags & AFP_EMERGENCY_MODE) && (emergency_flush == 1)) {
            h.h2->tp_status = TP_STATUS_KERNEL;
            goto next_frame;
        }

        p = PacketGetFromQueueOrAlloc();
        if (p == NULL) {
            SCReturnInt(AFP_FAILURE);
        }
        PKT_SET_SRC(p, PKT_SRC_WIRE);

        /* Suricata will treat packet so telling it is busy, this
         * status will be reset to 0 (ie TP_STATUS_KERNEL) in the release
         * function. */
        h.h2->tp_status |= TP_STATUS_USER_BUSY;

        from = (void *)h.raw + TPACKET_ALIGN(ptv->tp_hdrlen);

        ptv->pkts++;
        ptv->bytes += h.h2->tp_len;
        p->livedev = ptv->livedev;

        /* add forged header */
        if (ptv->cooked) {
            SllHdr * hdrp = (SllHdr *)ptv->data;
            /* XXX this is minimalist, but this seems enough */
            hdrp->sll_protocol = from->sll_protocol;
        }

        p->datalink = ptv->datalink;
        if (h.h2->tp_len > h.h2->tp_snaplen) {
            SCLogDebug("Packet length (%d) > snaplen (%d), truncating",
                    h.h2->tp_len, h.h2->tp_snaplen);
        }

        /* get vlan id from header */
        if ((!ptv->vlan_disabled) &&
            (h.h2->tp_status & TP_STATUS_VLAN_VALID || h.h2->tp_vlan_tci)) {
            p->vlan_id[0] = h.h2->tp_vlan_tci;
            p->vlan_idx = 1;
            p->vlanh[0] = NULL;
        }

        if (ptv->flags & AFP_ZERO_COPY) {
            if (PacketSetData(p, (unsigned char*)h.raw + h.h2->tp_mac, h.h2->tp_snaplen) == -1) {
                TmqhOutputPacketpool(ptv->tv, p);
                SCReturnInt(AFP_FAILURE);
            } else {
                p->afp_v.relptr = h.raw;
                p->ReleasePacket = AFPReleasePacket;
                p->afp_v.mpeer = ptv->mpeer;
                AFPRefSocket(ptv->mpeer);

                p->afp_v.copy_mode = ptv->copy_mode;
                if (p->afp_v.copy_mode != AFP_COPY_MODE_NONE) {
                    p->afp_v.peer = ptv->mpeer->peer;
                } else {
                    p->afp_v.peer = NULL;
                }
            }
        } else {
            if (PacketCopyData(p, (unsigned char*)h.raw + h.h2->tp_mac, h.h2->tp_snaplen) == -1) {
                TmqhOutputPacketpool(ptv->tv, p);
                SCReturnInt(AFP_FAILURE);
            }
        }
        /* Timestamp */
        p->ts.tv_sec = h.h2->tp_sec;
        p->ts.tv_usec = h.h2->tp_nsec/1000;
        SCLogDebug("pktlen: %" PRIu32 " (pkt %p, pkt data %p)",
                GET_PKT_LEN(p), p, GET_PKT_DATA(p));

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
            if (h.h2->tp_status & TP_STATUS_CSUMNOTREADY) {
                p->flags |= PKT_IGNORE_CHECKSUM;
            }
        }
        if (h.h2->tp_status & TP_STATUS_LOSING) {
            emergency_flush = 1;
            AFPDumpCounters(ptv);
        }

        /* release frame if not in zero copy mode */
        if (!(ptv->flags &  AFP_ZERO_COPY)) {
            h.h2->tp_status = TP_STATUS_KERNEL;
        }

        if (TmThreadsSlotProcessPkt(ptv->tv, ptv->slot, p) != TM_ECODE_OK) {
            h.h2->tp_status = TP_STATUS_KERNEL;
            if (++ptv->frame_offset >= ptv->req.tp_frame_nr) {
                ptv->frame_offset = 0;
            }
            TmqhOutputPacketpool(ptv->tv, p);
            SCReturnInt(AFP_FAILURE);
        }

next_frame:
        if (++ptv->frame_offset >= ptv->req.tp_frame_nr) {
            ptv->frame_offset = 0;
            /* Get out of loop to be sure we will reach maintenance tasks */
            SCReturnInt(AFP_READ_OK);
        }
    }

    SCReturnInt(AFP_READ_OK);
}

/**
 * \brief Reference socket
 *
 * \retval O in case of failure, 1 in case of success
 */
static int AFPRefSocket(AFPPeer* peer)
{
    if (unlikely(peer == NULL))
        return 0;

    (void)SC_ATOMIC_ADD(peer->sock_usage, 1);
    return 1;
}


/**
 * \brief Dereference socket
 *
 * \retval 1 if socket is still alive, 0 if not
 */
static int AFPDerefSocket(AFPPeer* peer)
{
    if (peer == NULL)
        return 1;

    if (SC_ATOMIC_SUB(peer->sock_usage, 1) == 0) {
        if (SC_ATOMIC_GET(peer->state) == AFP_STATE_DOWN) {
            SCLogInfo("Cleaning socket connected to '%s'", peer->iface);
            close(SC_ATOMIC_GET(peer->socket));
            return 0;
        }
    }
    return 1;
}

void AFPSwitchState(AFPThreadVars *ptv, int state)
{
    ptv->afp_state = state;
    ptv->down_count = 0;

    AFPPeerUpdate(ptv);

    /* Do cleaning if switching to down state */
    if (state == AFP_STATE_DOWN) {
        if (ptv->frame_buf) {
            /* only used in reading phase, we can free it */
            SCFree(ptv->frame_buf);
            ptv->frame_buf = NULL;
        }
        if (ptv->socket != -1) {
            /* we need to wait for all packets to return data */
            if (SC_ATOMIC_SUB(ptv->mpeer->sock_usage, 1) == 0) {
                SCLogInfo("Cleaning socket connected to '%s'", ptv->iface);
                close(ptv->socket);
                ptv->socket = -1;
            }
        }
    }
    if (state == AFP_STATE_UP) {
         (void)SC_ATOMIC_SET(ptv->mpeer->sock_usage, 1);
    }
}

static int AFPReadAndDiscard(AFPThreadVars *ptv, struct timeval *synctv)
{
    struct sockaddr_ll from;
    struct iovec iov;
    struct msghdr msg;
    struct timeval ts;
    union {
        struct cmsghdr cmsg;
        char buf[CMSG_SPACE(sizeof(struct tpacket_auxdata))];
    } cmsg_buf;


    if (unlikely(suricata_ctl_flags != 0)) {
        return 1;
    }

    msg.msg_name = &from;
    msg.msg_namelen = sizeof(from);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = &cmsg_buf;
    msg.msg_controllen = sizeof(cmsg_buf);
    msg.msg_flags = 0;

    iov.iov_len = ptv->datalen;
    iov.iov_base = ptv->data;

    recvmsg(ptv->socket, &msg, MSG_TRUNC);

    if (ioctl(ptv->socket, SIOCGSTAMP, &ts) == -1) {
        /* FIXME */
        return -1;
    }

    if ((ts.tv_sec > synctv->tv_sec) ||
        (ts.tv_sec >= synctv->tv_sec &&
         ts.tv_usec > synctv->tv_usec)) {
        return 1;
    }
    return 0;
}

static int AFPReadAndDiscardFromRing(AFPThreadVars *ptv, struct timeval *synctv)
{
    union thdr h;

    if (unlikely(suricata_ctl_flags != 0)) {
        return 1;
    }

    /* Read packet from ring */
    h.raw = (((union thdr **)ptv->frame_buf)[ptv->frame_offset]);
    if (h.raw == NULL) {
        return -1;
    }

    if (((time_t)h.h2->tp_sec > synctv->tv_sec) ||
        ((time_t)h.h2->tp_sec == synctv->tv_sec &&
        (suseconds_t) (h.h2->tp_nsec / 1000) > synctv->tv_usec)) {
        return 1;
    }

    h.h2->tp_status = TP_STATUS_KERNEL;
    if (++ptv->frame_offset >= ptv->req.tp_frame_nr) {
        ptv->frame_offset = 0;
    }


    return 0;
}

/** \brief wait for all afpacket threads to fully init
 *
 *  Discard packets before all threads are ready, as the cluster
 *  setup is not complete yet.
 *
 *  if AFPPeersListStarted() returns true init is complete
 *
 *  \retval r 1 = happy, otherwise unhappy
 */
static int AFPSynchronizeStart(AFPThreadVars *ptv)
{
    int r;
    struct timeval synctv;
    struct pollfd fds;

    fds.fd = ptv->socket;
    fds.events = POLLIN;

    /* Set timeval to end of the world */
    synctv.tv_sec = 0xffffffff;
    synctv.tv_usec = 0xffffffff;

    while (1) {
        r = poll(&fds, 1, POLL_TIMEOUT);
        if (r > 0 &&
                (fds.revents & (POLLHUP|POLLRDHUP|POLLERR|POLLNVAL))) {
            SCLogWarning(SC_ERR_AFP_READ, "poll failed %02x",
                    fds.revents & (POLLHUP|POLLRDHUP|POLLERR|POLLNVAL));
            return 0;
        } else if (r > 0) {
            if (AFPPeersListStarted() && synctv.tv_sec == (time_t) 0xffffffff) {
                gettimeofday(&synctv, NULL);
            }
            if (ptv->flags & AFP_RING_MODE) {
                r = AFPReadAndDiscardFromRing(ptv, &synctv);
            } else {
                r = AFPReadAndDiscard(ptv, &synctv);
            }
            SCLogDebug("Discarding on %s", ptv->tv->name);
            switch (r) {
                case 1:
                    SCLogInfo("Starting to read on %s", ptv->tv->name);
                    return 1;
                case -1:
                    return r;
            }
        /* no packets */
        } else if (r == 0 && AFPPeersListStarted()) {
            SCLogInfo("Starting to read on %s", ptv->tv->name);
            return 1;
        } else if (r < 0) { /* only exit on error */
            SCLogWarning(SC_ERR_AFP_READ, "poll failed with retval %d", r);
            return 0;
        }
    }
    return 1;
}

/**
 * \brief Try to reopen socket
 *
 * \retval 0 in case of success, negative if error occurs or a condition
 * is not met.
 */
static int AFPTryReopen(AFPThreadVars *ptv)
{
    int afp_activate_r;

    ptv->down_count++;


    /* Don't reconnect till we have packet that did not release data */
    if (SC_ATOMIC_GET(ptv->mpeer->sock_usage) != 0) {
        return -1;
    }

    afp_activate_r = AFPCreateSocket(ptv, ptv->iface, 0);
    if (afp_activate_r != 0) {
        if (ptv->down_count % AFP_DOWN_COUNTER_INTERVAL == 0) {
            SCLogWarning(SC_ERR_AFP_CREATE, "Can not open iface '%s'",
                         ptv->iface);
        }
        return afp_activate_r;
    }

    SCLogInfo("Interface '%s' is back", ptv->iface);
    return 0;
}

/**
 *  \brief Main AF_PACKET reading Loop function
 */
TmEcode ReceiveAFPLoop(ThreadVars *tv, void *data, void *slot)
{
    SCEnter();

    AFPThreadVars *ptv = (AFPThreadVars *)data;
    struct pollfd fds;
    int r;
    TmSlot *s = (TmSlot *)slot;
    time_t last_dump = 0;
    struct timeval current_time;

    ptv->slot = s->slot_next;

    if (ptv->afp_state == AFP_STATE_DOWN) {
        /* Wait for our turn, threads before us must have opened the socket */
        while (AFPPeersListWaitTurn(ptv->mpeer)) {
            usleep(1000);
            if (suricata_ctl_flags != 0) {
                break;
            }
        }
        r = AFPCreateSocket(ptv, ptv->iface, 1);
        if (r < 0) {
            switch (-r) {
                case AFP_FATAL_ERROR:
                    SCLogError(SC_ERR_AFP_CREATE, "Couldn't init AF_PACKET socket, fatal error");
                    /* fatal is fatal, we want suri to exit */
                    EngineKill();
                    //tv->aof = THV_ENGINE_EXIT;
                    SCReturnInt(TM_ECODE_FAILED);
                case AFP_RECOVERABLE_ERROR:
                    SCLogWarning(SC_ERR_AFP_CREATE, "Couldn't init AF_PACKET socket, retrying soon");
            }
        }
        AFPPeersListReachedInc();
    }
    if (ptv->afp_state == AFP_STATE_UP) {
        SCLogInfo("Thread %s using socket %d", tv->name, ptv->socket);
        AFPSynchronizeStart(ptv);
    }

    fds.fd = ptv->socket;
    fds.events = POLLIN;

    while (1) {
        /* Start by checking the state of our interface */
        if (unlikely(ptv->afp_state == AFP_STATE_DOWN)) {
            int dbreak = 0;

            do {
                usleep(AFP_RECONNECT_TIMEOUT);
                if (suricata_ctl_flags != 0) {
                    dbreak = 1;
                    break;
                }
                r = AFPTryReopen(ptv);
                fds.fd = ptv->socket;
            } while (r < 0);
            if (dbreak == 1)
                break;
        }

        /* make sure we have at least one packet in the packet pool, to prevent
         * us from alloc'ing packets at line rate */
        PacketPoolWait();

        r = poll(&fds, 1, POLL_TIMEOUT);

        if (suricata_ctl_flags != 0) {
            break;
        }

        if (r > 0 &&
                (fds.revents & (POLLHUP|POLLRDHUP|POLLERR|POLLNVAL))) {
            if (fds.revents & (POLLHUP | POLLRDHUP)) {
                AFPSwitchState(ptv, AFP_STATE_DOWN);
                continue;
            } else if (fds.revents & POLLERR) {
                char c;
                /* Do a recv to get errno */
                if (recv(ptv->socket, &c, sizeof c, MSG_PEEK) != -1)
                    continue; /* what, no error? */
                SCLogError(SC_ERR_AFP_READ,
                           "Error reading data from iface '%s': (%d" PRIu32 ") %s",
                           ptv->iface, errno, strerror(errno));
                AFPSwitchState(ptv, AFP_STATE_DOWN);
                continue;
            } else if (fds.revents & POLLNVAL) {
                SCLogError(SC_ERR_AFP_READ, "Invalid polling request");
                AFPSwitchState(ptv, AFP_STATE_DOWN);
                continue;
            }
        } else if (r > 0) {
            if (ptv->flags & AFP_RING_MODE) {
                r = AFPReadFromRing(ptv);
            } else {
                /* AFPRead will call TmThreadsSlotProcessPkt on read packets */
                r = AFPRead(ptv);
            }
            switch (r) {
                case AFP_READ_FAILURE:
                    /* AFPRead in error: best to reset the socket */
                    SCLogError(SC_ERR_AFP_READ,
                           "AFPRead error reading data from iface '%s': (%d" PRIu32 ") %s",
                           ptv->iface, errno, strerror(errno));
                    AFPSwitchState(ptv, AFP_STATE_DOWN);
                    continue;
                case AFP_FAILURE:
                    AFPSwitchState(ptv, AFP_STATE_DOWN);
                    SCReturnInt(TM_ECODE_FAILED);
                    break;
                case AFP_READ_OK:
                    /* Trigger one dump of stats every second */
                    TimeGet(&current_time);
                    if (current_time.tv_sec != last_dump) {
                        AFPDumpCounters(ptv);
                        last_dump = current_time.tv_sec;
                    }
                    break;
                case AFP_KERNEL_DROP:
                    AFPDumpCounters(ptv);
                    break;
            }
        } else if ((r < 0) && (errno != EINTR)) {
            SCLogError(SC_ERR_AFP_READ, "Error reading data from iface '%s': (%d" PRIu32 ") %s",
                       ptv->iface,
                       errno, strerror(errno));
            AFPSwitchState(ptv, AFP_STATE_DOWN);
            continue;
        }
        StatsSyncCountersIfSignalled(tv);
    }

    AFPDumpCounters(ptv);
    StatsSyncCountersIfSignalled(tv);
    SCReturnInt(TM_ECODE_OK);
}

static int AFPGetDevFlags(int fd, const char *ifname)
{
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

    if (ioctl(fd, SIOCGIFFLAGS, &ifr) == -1) {
        SCLogError(SC_ERR_AFP_CREATE, "Unable to find type for iface \"%s\": %s",
                   ifname, strerror(errno));
        return -1;
    }

    return ifr.ifr_flags;
}


static int AFPGetIfnumByDev(int fd, const char *ifname, int verbose)
{
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

    if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1) {
           if (verbose)
               SCLogError(SC_ERR_AFP_CREATE, "Unable to find iface %s: %s",
                          ifname, strerror(errno));
        return -1;
    }

    return ifr.ifr_ifindex;
}

static int AFPGetDevLinktype(int fd, const char *ifname)
{
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
        SCLogError(SC_ERR_AFP_CREATE, "Unable to find type for iface \"%s\": %s",
                   ifname, strerror(errno));
        return -1;
    }

    switch (ifr.ifr_hwaddr.sa_family) {
        case ARPHRD_LOOPBACK:
            return LINKTYPE_ETHERNET;
        case ARPHRD_PPP:
            return LINKTYPE_RAW;
        default:
            return ifr.ifr_hwaddr.sa_family;
    }
}

static int AFPComputeRingParams(AFPThreadVars *ptv, int order)
{
    /* Compute structure:
       Target is to store all pending packets
       with a size equal to MTU + auxdata
       And we keep a decent number of block

       To do so:
       Compute frame_size (aligned to be able to fit in block
       Check which block size we need. Blocksize is a 2^n * pagesize
       We then need to get order, big enough to have
       frame_size < block size
       Find number of frame per block (divide)
       Fill in packet_req

       Compute frame size:
       described in packet_mmap.txt
       dependant on snaplen (need to use a variable ?)
snaplen: MTU ?
tp_hdrlen determine_version in daq_afpacket
in V1:  sizeof(struct tpacket_hdr);
in V2: val in getsockopt(instance->fd, SOL_PACKET, PACKET_HDRLEN, &val, &len)
frame size: TPACKET_ALIGN(snaplen + TPACKET_ALIGN(TPACKET_ALIGN(tp_hdrlen) + sizeof(struct sockaddr_ll) + ETH_HLEN) - ETH_HLEN);

     */
    int tp_hdrlen = sizeof(struct tpacket_hdr);
    int snaplen = default_packet_size;

    if (snaplen == 0) {
        snaplen = GetIfaceMaxPacketSize(ptv->iface);
        if (snaplen <= 0) {
            SCLogWarning(SC_ERR_INVALID_VALUE,
                         "Unable to get MTU, setting snaplen to sane default of 1514");
            snaplen = 1514;
        }
    }

    ptv->req.tp_frame_size = TPACKET_ALIGN(snaplen +TPACKET_ALIGN(TPACKET_ALIGN(tp_hdrlen) + sizeof(struct sockaddr_ll) + ETH_HLEN) - ETH_HLEN);
    ptv->req.tp_block_size = getpagesize() << order;
    int frames_per_block = ptv->req.tp_block_size / ptv->req.tp_frame_size;
    if (frames_per_block == 0) {
        SCLogInfo("frame size to big");
        return -1;
    }
    ptv->req.tp_frame_nr = ptv->ring_size;
    ptv->req.tp_block_nr = ptv->req.tp_frame_nr / frames_per_block + 1;
    /* exact division */
    ptv->req.tp_frame_nr = ptv->req.tp_block_nr * frames_per_block;
    SCLogInfo("AF_PACKET RX Ring params: block_size=%d block_nr=%d frame_size=%d frame_nr=%d",
              ptv->req.tp_block_size, ptv->req.tp_block_nr,
              ptv->req.tp_frame_size, ptv->req.tp_frame_nr);
    return 1;
}

static int AFPCreateSocket(AFPThreadVars *ptv, char *devname, int verbose)
{
    int r;
    int ret = AFP_FATAL_ERROR;
    struct packet_mreq sock_params;
    struct sockaddr_ll bind_address;
    int order;
    unsigned int i;
    int if_idx;

    /* open socket */
    ptv->socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (ptv->socket == -1) {
        SCLogError(SC_ERR_AFP_CREATE, "Couldn't create a AF_PACKET socket, error %s", strerror(errno));
        goto error;
    }
    if_idx = AFPGetIfnumByDev(ptv->socket, devname, verbose);
    /* bind socket */
    memset(&bind_address, 0, sizeof(bind_address));
    bind_address.sll_family = AF_PACKET;
    bind_address.sll_protocol = htons(ETH_P_ALL);
    bind_address.sll_ifindex = if_idx;
    if (bind_address.sll_ifindex == -1) {
        if (verbose)
            SCLogError(SC_ERR_AFP_CREATE, "Couldn't find iface %s", devname);
        ret = AFP_RECOVERABLE_ERROR;
        goto socket_err;
    }

    if (ptv->promisc != 0) {
        /* Force promiscuous mode */
        memset(&sock_params, 0, sizeof(sock_params));
        sock_params.mr_type = PACKET_MR_PROMISC;
        sock_params.mr_ifindex = bind_address.sll_ifindex;
        r = setsockopt(ptv->socket, SOL_PACKET, PACKET_ADD_MEMBERSHIP,(void *)&sock_params, sizeof(sock_params));
        if (r < 0) {
            SCLogError(SC_ERR_AFP_CREATE,
                    "Couldn't switch iface %s to promiscuous, error %s",
                    devname, strerror(errno));
            goto frame_err;
        }
    }

    if (ptv->checksum_mode == CHECKSUM_VALIDATION_KERNEL) {
        int val = 1;
        if (setsockopt(ptv->socket, SOL_PACKET, PACKET_AUXDATA, &val,
                    sizeof(val)) == -1 && errno != ENOPROTOOPT) {
            SCLogWarning(SC_ERR_NO_AF_PACKET,
                         "'kernel' checksum mode not supported, failling back to full mode.");
            ptv->checksum_mode = CHECKSUM_VALIDATION_ENABLE;
        }
    }

    /* set socket recv buffer size */
    if (ptv->buffer_size != 0) {
        /*
         * Set the socket buffer size to the specified value.
         */
        SCLogInfo("Setting AF_PACKET socket buffer to %d", ptv->buffer_size);
        if (setsockopt(ptv->socket, SOL_SOCKET, SO_RCVBUF,
                       &ptv->buffer_size,
                       sizeof(ptv->buffer_size)) == -1) {
            SCLogError(SC_ERR_AFP_CREATE,
                    "Couldn't set buffer size to %d on iface %s, error %s",
                    ptv->buffer_size, devname, strerror(errno));
            goto frame_err;
        }
    }

    r = bind(ptv->socket, (struct sockaddr *)&bind_address, sizeof(bind_address));
    if (r < 0) {
        if (verbose) {
            if (errno == ENETDOWN) {
                SCLogError(SC_ERR_AFP_CREATE,
                        "Couldn't bind AF_PACKET socket, iface %s is down",
                        devname);
            } else {
                SCLogError(SC_ERR_AFP_CREATE,
                        "Couldn't bind AF_PACKET socket to iface %s, error %s",
                        devname, strerror(errno));
            }
        }
        ret = AFP_RECOVERABLE_ERROR;
        goto frame_err;
    }

#ifdef HAVE_PACKET_FANOUT
    /* add binded socket to fanout group */
    if (ptv->threads > 1) {
        uint32_t option = 0;
        uint16_t mode = ptv->cluster_type;
        uint16_t id = ptv->cluster_id;
        option = (mode << 16) | (id & 0xffff);
        r = setsockopt(ptv->socket, SOL_PACKET, PACKET_FANOUT,(void *)&option, sizeof(option));
        if (r < 0) {
            SCLogError(SC_ERR_AFP_CREATE,
                       "Coudn't set fanout mode, error %s",
                       strerror(errno));
            goto frame_err;
        }
    }
#endif

    int if_flags = AFPGetDevFlags(ptv->socket, ptv->iface);
    if (if_flags == -1) {
        if (verbose) {
            SCLogError(SC_ERR_AFP_READ,
                    "Can not acces to interface '%s'",
                    ptv->iface);
        }
        ret = AFP_RECOVERABLE_ERROR;
        goto frame_err;
    }
    if ((if_flags & IFF_UP) == 0) {
        if (verbose) {
            SCLogError(SC_ERR_AFP_READ,
                    "Interface '%s' is down",
                    ptv->iface);
        }
        ret = AFP_RECOVERABLE_ERROR;
        goto frame_err;
    }

    if (ptv->flags & AFP_RING_MODE) {
        int val = TPACKET_V2;
        unsigned int len = sizeof(val);
        if (getsockopt(ptv->socket, SOL_PACKET, PACKET_HDRLEN, &val, &len) < 0) {
            if (errno == ENOPROTOOPT) {
                SCLogError(SC_ERR_AFP_CREATE,
                           "Too old kernel giving up (need 2.6.27 at least)");
            }
            SCLogError(SC_ERR_AFP_CREATE, "Error when retrieving packet header len");
            goto socket_err;
        }
        ptv->tp_hdrlen = val;

        val = TPACKET_V2;
        if (setsockopt(ptv->socket, SOL_PACKET, PACKET_VERSION, &val,
                    sizeof(val)) < 0) {
            SCLogError(SC_ERR_AFP_CREATE,
                       "Can't activate TPACKET_V2 on packet socket: %s",
                       strerror(errno));
            goto socket_err;
        }

        /* Allocate RX ring */
#define DEFAULT_ORDER 3
        for (order = DEFAULT_ORDER; order >= 0; order--) {
            if (AFPComputeRingParams(ptv, order) != 1) {
                SCLogInfo("Ring parameter are incorrect. Please correct the devel");
            }

            r = setsockopt(ptv->socket, SOL_PACKET, PACKET_RX_RING, (void *) &ptv->req, sizeof(ptv->req));
            if (r < 0) {
                if (errno == ENOMEM) {
                    SCLogInfo("Memory issue with ring parameters. Retrying.");
                    continue;
                }
                SCLogError(SC_ERR_MEM_ALLOC,
                        "Unable to allocate RX Ring for iface %s: (%d) %s",
                        devname,
                        errno,
                        strerror(errno));
                goto socket_err;
            } else {
                break;
            }
        }

        if (order < 0) {
            SCLogError(SC_ERR_MEM_ALLOC,
                    "Unable to allocate RX Ring for iface %s (order 0 failed)",
                    devname);
            goto socket_err;
        }

        /* Allocate the Ring */
        ptv->ring_buflen = ptv->req.tp_block_nr * ptv->req.tp_block_size;
        ptv->ring_buf = mmap(0, ptv->ring_buflen, PROT_READ|PROT_WRITE,
                MAP_SHARED, ptv->socket, 0);
        if (ptv->ring_buf == MAP_FAILED) {
            SCLogError(SC_ERR_MEM_ALLOC, "Unable to mmap");
            goto socket_err;
        }
        /* allocate a ring for each frame header pointer*/
        ptv->frame_buf = SCMalloc(ptv->req.tp_frame_nr * sizeof (union thdr *));
        if (ptv->frame_buf == NULL) {
            SCLogError(SC_ERR_MEM_ALLOC, "Unable to allocate frame buf");
            goto mmap_err;
        }
        memset(ptv->frame_buf, 0, ptv->req.tp_frame_nr * sizeof (union thdr *));
        /* fill the header ring with proper frame ptr*/
        ptv->frame_offset = 0;
        for (i = 0; i < ptv->req.tp_block_nr; ++i) {
            void *base = &ptv->ring_buf[i * ptv->req.tp_block_size];
            unsigned int j;
            for (j = 0; j < ptv->req.tp_block_size / ptv->req.tp_frame_size; ++j, ++ptv->frame_offset) {
                (((union thdr **)ptv->frame_buf)[ptv->frame_offset]) = base;
                base += ptv->req.tp_frame_size;
            }
        }
        ptv->frame_offset = 0;
    }

    SCLogInfo("Using interface '%s' via socket %d", (char *)devname, ptv->socket);


    ptv->datalink = AFPGetDevLinktype(ptv->socket, ptv->iface);
    switch (ptv->datalink) {
        case ARPHRD_PPP:
        case ARPHRD_ATM:
            ptv->cooked = 1;
            break;
    }

    TmEcode rc;
    rc = AFPSetBPFFilter(ptv);
    if (rc == TM_ECODE_FAILED) {
        SCLogError(SC_ERR_AFP_CREATE, "Set AF_PACKET bpf filter \"%s\" failed.", ptv->bpf_filter);
        goto frame_err;
    }

    /* Init is ok */
    AFPSwitchState(ptv, AFP_STATE_UP);
    return 0;

frame_err:
    if (ptv->frame_buf)
        SCFree(ptv->frame_buf);
mmap_err:
    /* Packet mmap does the cleaning when socket is closed */
socket_err:
    close(ptv->socket);
    ptv->socket = -1;
error:
    return -ret;
}

TmEcode AFPSetBPFFilter(AFPThreadVars *ptv)
{
    struct bpf_program filter;
    struct sock_fprog  fcode;
    int rc;

    if (!ptv->bpf_filter)
        return TM_ECODE_OK;

    SCMutexLock(&afpacket_bpf_set_filter_lock);

    SCLogInfo("Using BPF '%s' on iface '%s'",
              ptv->bpf_filter,
              ptv->iface);
    if (pcap_compile_nopcap(default_packet_size,  /* snaplen_arg */
                ptv->datalink,    /* linktype_arg */
                &filter,       /* program */
                ptv->bpf_filter, /* const char *buf */
                0,             /* optimize */
                0              /* mask */
                ) == -1) {
        SCLogError(SC_ERR_AFP_CREATE, "Filter compilation failed.");
        SCMutexUnlock(&afpacket_bpf_set_filter_lock);
        return TM_ECODE_FAILED;
    }
    SCMutexUnlock(&afpacket_bpf_set_filter_lock);

    if (filter.bf_insns == NULL) {
        SCLogError(SC_ERR_AFP_CREATE, "Filter badly setup.");
        return TM_ECODE_FAILED;
    }

    fcode.len    = filter.bf_len;
    fcode.filter = (struct sock_filter*)filter.bf_insns;

    rc = setsockopt(ptv->socket, SOL_SOCKET, SO_ATTACH_FILTER, &fcode, sizeof(fcode));

    if(rc == -1) {
        SCLogError(SC_ERR_AFP_CREATE, "Failed to attach filter: %s", strerror(errno));
        return TM_ECODE_FAILED;
    }

    return TM_ECODE_OK;
}


/**
 * \brief Init function for ReceiveAFP.
 *
 * \param tv pointer to ThreadVars
 * \param initdata pointer to the interface passed from the user
 * \param data pointer gets populated with AFPThreadVars
 *
 * \todo Create a general AFP setup function.
 */
TmEcode ReceiveAFPThreadInit(ThreadVars *tv, void *initdata, void **data)
{
    SCEnter();
    AFPIfaceConfig *afpconfig = initdata;

    if (initdata == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "initdata == NULL");
        SCReturnInt(TM_ECODE_FAILED);
    }

    AFPThreadVars *ptv = SCMalloc(sizeof(AFPThreadVars));
    if (unlikely(ptv == NULL)) {
        afpconfig->DerefFunc(afpconfig);
        SCReturnInt(TM_ECODE_FAILED);
    }
    memset(ptv, 0, sizeof(AFPThreadVars));

    ptv->tv = tv;
    ptv->cooked = 0;

    strlcpy(ptv->iface, afpconfig->iface, AFP_IFACE_NAME_LENGTH);
    ptv->iface[AFP_IFACE_NAME_LENGTH - 1]= '\0';

    ptv->livedev = LiveGetDevice(ptv->iface);
    if (ptv->livedev == NULL) {
        SCLogError(SC_ERR_INVALID_VALUE, "Unable to find Live device");
        SCFree(ptv);
        SCReturnInt(TM_ECODE_FAILED);
    }

    ptv->buffer_size = afpconfig->buffer_size;
    ptv->ring_size = afpconfig->ring_size;

    ptv->promisc = afpconfig->promisc;
    ptv->checksum_mode = afpconfig->checksum_mode;
    ptv->bpf_filter = NULL;

    ptv->threads = 1;
#ifdef HAVE_PACKET_FANOUT
    ptv->cluster_type = PACKET_FANOUT_LB;
    ptv->cluster_id = 1;
    /* We only set cluster info if the number of reader threads is greater than 1 */
    if (afpconfig->threads > 1) {
            ptv->cluster_id = afpconfig->cluster_id;
            ptv->cluster_type = afpconfig->cluster_type;
            ptv->threads = afpconfig->threads;
    }
#endif
    ptv->flags = afpconfig->flags;

    if (afpconfig->bpf_filter) {
        ptv->bpf_filter = afpconfig->bpf_filter;
    }

#ifdef PACKET_STATISTICS
    ptv->capture_kernel_packets = StatsRegisterCounter("capture.kernel_packets",
            ptv->tv);
    ptv->capture_kernel_drops = StatsRegisterCounter("capture.kernel_drops",
            ptv->tv);
#endif

    char *active_runmode = RunmodeGetActive();

    if (active_runmode && !strcmp("workers", active_runmode)) {
        ptv->flags |= AFP_ZERO_COPY;
        SCLogInfo("Enabling zero copy mode");
    } else {
        /* If we are using copy mode we need a lock */
        ptv->flags |= AFP_SOCK_PROTECT;
    }

    /* If we are in RING mode, then we can use ZERO copy
     * by using the data release mechanism */
    if (ptv->flags & AFP_RING_MODE) {
        ptv->flags |= AFP_ZERO_COPY;
        SCLogInfo("Enabling zero copy mode by using data release call");
    }

    ptv->copy_mode = afpconfig->copy_mode;
    if (ptv->copy_mode != AFP_COPY_MODE_NONE) {
        strlcpy(ptv->out_iface, afpconfig->out_iface, AFP_IFACE_NAME_LENGTH);
        ptv->out_iface[AFP_IFACE_NAME_LENGTH - 1]= '\0';
        /* Warn about BPF filter consequence */
        if (ptv->bpf_filter) {
            SCLogWarning(SC_WARN_UNCOMMON, "Enabling a BPF filter in IPS mode result"
                      " in dropping all non matching packets.");
        }
    }


    if (AFPPeersListAdd(ptv) == TM_ECODE_FAILED) {
        SCFree(ptv);
        afpconfig->DerefFunc(afpconfig);
        SCReturnInt(TM_ECODE_FAILED);
    }

#define T_DATA_SIZE 70000
    ptv->data = SCMalloc(T_DATA_SIZE);
    if (ptv->data == NULL) {
        afpconfig->DerefFunc(afpconfig);
        SCFree(ptv);
        SCReturnInt(TM_ECODE_FAILED);
    }
    ptv->datalen = T_DATA_SIZE;
#undef T_DATA_SIZE

    *data = (void *)ptv;

    afpconfig->DerefFunc(afpconfig);

    /* A bit strange to have this here but we only have vlan information
     * during reading so we need to know if we want to keep vlan during
     * the capture phase */
    int vlanbool = 0;
    if ((ConfGetBool("vlan.use-for-tracking", &vlanbool)) == 1 && vlanbool == 0) {
        ptv->vlan_disabled = 1;
    }

    /* If kernel is older than 3.0, VLAN is not stripped so we don't
     * get the info from packet extended header but we will use a standard
     * parsing of packet data (See Linux commit bcc6d47903612c3861201cc3a866fb604f26b8b2) */
    if (! SCKernelVersionIsAtLeast(3, 0)) {
        ptv->vlan_disabled = 1;
    }

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief This function prints stats to the screen at exit.
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into AFPThreadVars for ptv
 */
void ReceiveAFPThreadExitStats(ThreadVars *tv, void *data)
{
    SCEnter();
    AFPThreadVars *ptv = (AFPThreadVars *)data;

#ifdef PACKET_STATISTICS
    AFPDumpCounters(ptv);
    SCLogInfo("(%s) Kernel: Packets %" PRIu64 ", dropped %" PRIu64 "",
            tv->name,
            StatsGetLocalCounterValue(tv, ptv->capture_kernel_packets),
            StatsGetLocalCounterValue(tv, ptv->capture_kernel_drops));
#endif

    SCLogInfo("(%s) Packets %" PRIu64 ", bytes %" PRIu64 "", tv->name, ptv->pkts, ptv->bytes);
}

/**
 * \brief DeInit function closes af packet socket at exit.
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into AFPThreadVars for ptv
 */
TmEcode ReceiveAFPThreadDeinit(ThreadVars *tv, void *data)
{
    AFPThreadVars *ptv = (AFPThreadVars *)data;

    AFPSwitchState(ptv, AFP_STATE_DOWN);

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
 * DecodeAFP reads packets from the PacketQueue and passes
 * them off to the proper link type decoder.
 *
 * \param t pointer to ThreadVars
 * \param p pointer to the current packet
 * \param data pointer that gets cast into AFPThreadVars for ptv
 * \param pq pointer to the current PacketQueue
 */
TmEcode DecodeAFP(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    SCEnter();
    DecodeThreadVars *dtv = (DecodeThreadVars *)data;

    /* XXX HACK: flow timeout can call us for injected pseudo packets
     *           see bug: https://redmine.openinfosecfoundation.org/issues/1107 */
    if (p->flags & PKT_PSEUDO_STREAM_END)
        return TM_ECODE_OK;

    /* update counters */
    DecodeUpdatePacketCounters(tv, dtv, p);

    /* If suri has set vlan during reading, we increase vlan counter */
    if (p->vlan_idx) {
        StatsIncr(tv, dtv->counter_vlan);
    }

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
            SCLogError(SC_ERR_DATALINK_UNIMPLEMENTED, "Error: datalink type %" PRId32 " not yet supported in module DecodeAFP", p->datalink);
            break;
    }

    PacketDecodeFinalize(tv, dtv, p);

    SCReturnInt(TM_ECODE_OK);
}

TmEcode DecodeAFPThreadInit(ThreadVars *tv, void *initdata, void **data)
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

TmEcode DecodeAFPThreadDeinit(ThreadVars *tv, void *data)
{
    if (data != NULL)
        DecodeThreadVarsFree(tv, data);
    SCReturnInt(TM_ECODE_OK);
}

#endif /* HAVE_AF_PACKET */
/* eof */
/**
 * @}
 */
