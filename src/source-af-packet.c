/* Copyright (C) 2011-2018 Open Information Security Foundation
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
 */

#define PCAP_DONT_INCLUDE_PCAP_BPF_H 1
#define SC_PCAP_DONT_INCLUDE_PCAP_H 1
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
#include "util-cpu.h"
#include "util-debug.h"
#include "util-device.h"
#include "util-ebpf.h"
#include "util-error.h"
#include "util-privs.h"
#include "util-optimize.h"
#include "util-checksum.h"
#include "util-ioctl.h"
#include "util-host-info.h"
#include "tmqh-packetpool.h"
#include "source-af-packet.h"
#include "runmodes.h"
#include "flow-storage.h"

#ifdef HAVE_AF_PACKET

#if HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#ifdef HAVE_PACKET_EBPF
#include "util-ebpf.h"
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#endif

struct bpf_program {
    unsigned int bf_len;
    struct bpf_insn *bf_insns;
};

#ifdef HAVE_PCAP_H
#include <pcap.h>
#endif

#ifdef HAVE_PCAP_PCAP_H
#include <pcap/pcap.h>
#endif

#include "util-bpf.h"

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

#ifdef HAVE_HW_TIMESTAMPING
#include <linux/net_tstamp.h>
#endif

#endif /* HAVE_AF_PACKET */

extern int max_pending_packets;

#ifndef HAVE_AF_PACKET

TmEcode NoAFPSupportExit(ThreadVars *, const void *, void **);

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
TmEcode NoAFPSupportExit(ThreadVars *tv, const void *initdata, void **data)
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

enum {
    AFP_READ_OK,
    AFP_READ_FAILURE,
    /** Error during treatment by other functions of Suricata */
    AFP_SURI_FAILURE,
    AFP_KERNEL_DROP,
};

enum {
    AFP_FATAL_ERROR = 1,
    AFP_RECOVERABLE_ERROR,
};

union thdr {
    struct tpacket2_hdr *h2;
#ifdef HAVE_TPACKET_V3
    struct tpacket3_hdr *h3;
#endif
    void *raw;
};

static int AFPBypassCallback(Packet *p);
static int AFPXDPBypassCallback(Packet *p);

#define MAX_MAPS 32
/**
 * \brief Structure to hold thread specific variables.
 */
typedef struct AFPThreadVars_
{
    union AFPRing {
        char *v2;
        struct iovec *v3;
    } ring;

    /* counters */
    uint64_t pkts;

    ThreadVars *tv;
    TmSlot *slot;
    LiveDevice *livedev;
    /* data link type for the thread */
    uint32_t datalink;

#ifdef HAVE_PACKET_EBPF
    /* File descriptor of the IPv4 flow bypass table maps */
    int v4_map_fd;
    /* File descriptor of the IPv6 flow bypass table maps */
    int v6_map_fd;
#endif

    unsigned int frame_offset;

    ChecksumValidationMode checksum_mode;

    /* references to packet and drop counters */
    uint16_t capture_kernel_packets;
    uint16_t capture_kernel_drops;
    uint16_t capture_errors;

    /* handle state */
    uint8_t afp_state;
    uint8_t copy_mode;
    unsigned int flags;

    /* IPS peer */
    AFPPeer *mpeer;

    /* no mmap mode */
    uint8_t *data; /** Per function and thread data */
    int datalen; /** Length of per function and thread data */
    int cooked;

    /*
     *  Init related members
     */

    /* thread specific socket */
    int socket;

    int ring_size;
    int block_size;
    int block_timeout;
    /* socket buffer size */
    int buffer_size;
    /* Filter */
    const char *bpf_filter;
    int ebpf_lb_fd;
    int ebpf_filter_fd;

    int promisc;

    int down_count;

    int cluster_id;
    int cluster_type;

    int threads;

    union AFPTpacketReq {
        struct tpacket_req v2;
#ifdef HAVE_TPACKET_V3
        struct tpacket_req3 v3;
#endif
    } req;

    char iface[AFP_IFACE_NAME_LENGTH];
    /* IPS output iface */
    char out_iface[AFP_IFACE_NAME_LENGTH];

    /* mmap'ed ring buffer */
    unsigned int ring_buflen;
    uint8_t *ring_buf;

    uint8_t xdp_mode;

#ifdef HAVE_PACKET_EBPF
    struct ebpf_timeout_config ebpf_t_config;
#endif

} AFPThreadVars;

TmEcode ReceiveAFP(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode ReceiveAFPThreadInit(ThreadVars *, const void *, void **);
void ReceiveAFPThreadExitStats(ThreadVars *, void *);
TmEcode ReceiveAFPThreadDeinit(ThreadVars *, void *);
TmEcode ReceiveAFPLoop(ThreadVars *tv, void *data, void *slot);

TmEcode DecodeAFPThreadInit(ThreadVars *, const void *, void **);
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
    tmm_modules[TMM_RECEIVEAFP].PktAcqBreakLoop = NULL;
    tmm_modules[TMM_RECEIVEAFP].ThreadExitPrintStats = ReceiveAFPThreadExitStats;
    tmm_modules[TMM_RECEIVEAFP].ThreadDeinit = ReceiveAFPThreadDeinit;
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
static void AFPPeerUpdate(AFPThreadVars *ptv)
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
static void AFPPeerClean(AFPPeer *peer)
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
static TmEcode AFPPeersListAdd(AFPThreadVars *ptv)
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

static int AFPPeersListWaitTurn(AFPPeer *peer)
{
    /* If turn is zero, we already have started threads once */
    if (peerslist.turn == 0)
        return 0;

    if (peer->turn == SC_ATOMIC_GET(peerslist.reached))
        return 0;
    return 1;
}

static void AFPPeersListReachedInc(void)
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

static int AFPPeersListStarted(void)
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
static int AFPRead(AFPThreadVars *ptv)
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
        SCReturnInt(AFP_SURI_FAILURE);
    }
    PKT_SET_SRC(p, PKT_SRC_WIRE);
    if (ptv->flags & AFP_BYPASS) {
        p->BypassPacketsFlow = AFPBypassCallback;
#ifdef HAVE_PACKET_EBPF
        p->afp_v.v4_map_fd = ptv->v4_map_fd;
        p->afp_v.v6_map_fd = ptv->v6_map_fd;
        p->afp_v.nr_cpus = ptv->ebpf_t_config.cpus_count;
#endif
    }
    if (ptv->flags & AFP_XDPBYPASS) {
        p->BypassPacketsFlow = AFPXDPBypassCallback;
#ifdef HAVE_PACKET_EBPF
        p->afp_v.v4_map_fd = ptv->v4_map_fd;
        p->afp_v.v6_map_fd = ptv->v6_map_fd;
        p->afp_v.nr_cpus = ptv->ebpf_t_config.cpus_count;
#endif
    }

    /* get timestamp of packet via ioctl */
    if (ioctl(ptv->socket, SIOCGSTAMP, &p->ts) == -1) {
        SCLogWarning(SC_ERR_AFP_READ, "recvmsg failed with error code %" PRId32,
                errno);
        TmqhOutputPacketpool(ptv->tv, p);
        SCReturnInt(AFP_READ_FAILURE);
    }

    ptv->pkts++;
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
        SCReturnInt(AFP_SURI_FAILURE);
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
        SCReturnInt(AFP_SURI_FAILURE);
    }
    SCReturnInt(AFP_READ_OK);
}

/**
 * \brief AF packet write function.
 *
 * This function has to be called before the memory
 * related to Packet in ring buffer is released.
 *
 * \param pointer to Packet
 * \param version of capture: TPACKET_V2 or TPACKET_V3
 * \retval TM_ECODE_FAILED on failure and TM_ECODE_OK on success
 *
 */
static TmEcode AFPWritePacket(Packet *p, int version)
{
    struct sockaddr_ll socket_address;
    int socket;
    uint8_t *pstart;
    size_t plen;
    union thdr h;
    uint16_t vlan_tci = 0;

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

    h.raw = p->afp_v.relptr;

    if (version == TPACKET_V2) {
        /* Copy VLAN header from ring memory. For post june 2011 kernel we test
         * the flag. It is not defined for older kernel so we go best effort
         * and test for non zero value of the TCI header. */
        if (h.h2->tp_status & TP_STATUS_VLAN_VALID || h.h2->tp_vlan_tci) {
            vlan_tci = h.h2->tp_vlan_tci;
        }
    } else {
#ifdef HAVE_TPACKET_V3
        if (h.h3->tp_status & TP_STATUS_VLAN_VALID || h.h3->hv1.tp_vlan_tci) {
            vlan_tci = h.h3->hv1.tp_vlan_tci;
        }
#else
        /* Should not get here */
        BUG_ON(1);
#endif
    }

    if (vlan_tci != 0) {
        pstart = GET_PKT_DATA(p) - VLAN_HEADER_LEN;
        plen = GET_PKT_LEN(p) + VLAN_HEADER_LEN;
        /* move ethernet addresses */
        memmove(pstart, GET_PKT_DATA(p), 2 * ETH_ALEN);
        /* write vlan info */
        *(uint16_t *)(pstart + 2 * ETH_ALEN) = htons(0x8100);
        *(uint16_t *)(pstart + 2 * ETH_ALEN + 2) = htons(vlan_tci);
    } else {
        pstart = GET_PKT_DATA(p);
        plen = GET_PKT_LEN(p);
    }

    if (sendto(socket, pstart, plen, 0,
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

static void AFPReleaseDataFromRing(Packet *p)
{
    /* Need to be in copy mode and need to detect early release
       where Ethernet header could not be set (and pseudo packet) */
    if ((p->afp_v.copy_mode != AFP_COPY_MODE_NONE) && !PKT_IS_PSEUDOPKT(p)) {
        AFPWritePacket(p, TPACKET_V2);
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

#ifdef HAVE_TPACKET_V3
static void AFPReleasePacketV3(Packet *p)
{
    /* Need to be in copy mode and need to detect early release
       where Ethernet header could not be set (and pseudo packet) */
    if ((p->afp_v.copy_mode != AFP_COPY_MODE_NONE) && !PKT_IS_PSEUDOPKT(p)) {
        AFPWritePacket(p, TPACKET_V3);
    }
    PacketFreeOrRelease(p);
}
#endif

static void AFPReleasePacket(Packet *p)
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
static int AFPReadFromRing(AFPThreadVars *ptv)
{
    Packet *p = NULL;
    union thdr h;
    uint8_t emergency_flush = 0;
    int read_pkts = 0;
    int loop_start = -1;


    /* Loop till we have packets available */
    while (1) {
        if (unlikely(suricata_ctl_flags != 0)) {
            break;
        }

        /* Read packet from ring */
        h.raw = (((union thdr **)ptv->ring.v2)[ptv->frame_offset]);
        if (unlikely(h.raw == NULL)) {
            /* Impossible we reach this point in normal condition, so trigger
             * a failure in reading */
            SCReturnInt(AFP_READ_FAILURE);
        }

        if ((! h.h2->tp_status) || (h.h2->tp_status & TP_STATUS_USER_BUSY)) {
            if (read_pkts == 0) {
                if (loop_start == -1) {
                    loop_start = ptv->frame_offset;
                } else if (unlikely(loop_start == (int)ptv->frame_offset)) {
                    SCReturnInt(AFP_READ_OK);
                }
                if (++ptv->frame_offset >= ptv->req.v2.tp_frame_nr) {
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
            SCReturnInt(AFP_SURI_FAILURE);
        }
        PKT_SET_SRC(p, PKT_SRC_WIRE);
        if (ptv->flags & AFP_BYPASS) {
            p->BypassPacketsFlow = AFPBypassCallback;
#ifdef HAVE_PACKET_EBPF
            p->afp_v.v4_map_fd = ptv->v4_map_fd;
            p->afp_v.v6_map_fd = ptv->v6_map_fd;
            p->afp_v.nr_cpus = ptv->ebpf_t_config.cpus_count;
#endif
        }
        if (ptv->flags & AFP_XDPBYPASS) {
            p->BypassPacketsFlow = AFPXDPBypassCallback;
#ifdef HAVE_PACKET_EBPF
            p->afp_v.v4_map_fd = ptv->v4_map_fd;
            p->afp_v.v6_map_fd = ptv->v6_map_fd;
            p->afp_v.nr_cpus = ptv->ebpf_t_config.cpus_count;
#endif
        }

        /* Suricata will treat packet so telling it is busy, this
         * status will be reset to 0 (ie TP_STATUS_KERNEL) in the release
         * function. */
        h.h2->tp_status |= TP_STATUS_USER_BUSY;

        ptv->pkts++;
        p->livedev = ptv->livedev;
        p->datalink = ptv->datalink;

        if (h.h2->tp_len > h.h2->tp_snaplen) {
            SCLogDebug("Packet length (%d) > snaplen (%d), truncating",
                    h.h2->tp_len, h.h2->tp_snaplen);
        }

        /* get vlan id from header */
        if ((!(ptv->flags & AFP_VLAN_DISABLED)) &&
            (h.h2->tp_status & TP_STATUS_VLAN_VALID || h.h2->tp_vlan_tci)) {
            p->vlan_id[0] = h.h2->tp_vlan_tci & 0x0fff;
            p->vlan_idx = 1;
            p->vlanh[0] = NULL;
        }

        if (ptv->flags & AFP_ZERO_COPY) {
            if (PacketSetData(p, (unsigned char*)h.raw + h.h2->tp_mac, h.h2->tp_snaplen) == -1) {
                TmqhOutputPacketpool(ptv->tv, p);
                SCReturnInt(AFP_SURI_FAILURE);
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
                /* As we can possibly fail to copy the data due to invalid data, let's
                 * skip this packet and switch to the next one.
                 */
                h.h2->tp_status = TP_STATUS_KERNEL;
                if (++ptv->frame_offset >= ptv->req.v2.tp_frame_nr) {
                    ptv->frame_offset = 0;
                }
                TmqhOutputPacketpool(ptv->tv, p);
                SCReturnInt(AFP_SURI_FAILURE);
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
            if (++ptv->frame_offset >= ptv->req.v2.tp_frame_nr) {
                ptv->frame_offset = 0;
            }
            TmqhOutputPacketpool(ptv->tv, p);
            SCReturnInt(AFP_SURI_FAILURE);
        }

next_frame:
        if (++ptv->frame_offset >= ptv->req.v2.tp_frame_nr) {
            ptv->frame_offset = 0;
            /* Get out of loop to be sure we will reach maintenance tasks */
            SCReturnInt(AFP_READ_OK);
        }
    }

    SCReturnInt(AFP_READ_OK);
}

#ifdef HAVE_TPACKET_V3
static inline void AFPFlushBlock(struct tpacket_block_desc *pbd)
{
    pbd->hdr.bh1.block_status = TP_STATUS_KERNEL;
}

static inline int AFPParsePacketV3(AFPThreadVars *ptv, struct tpacket_block_desc *pbd, struct tpacket3_hdr *ppd)
{
    Packet *p = PacketGetFromQueueOrAlloc();
    if (p == NULL) {
        SCReturnInt(AFP_SURI_FAILURE);
    }
    PKT_SET_SRC(p, PKT_SRC_WIRE);
    if (ptv->flags & AFP_BYPASS) {
        p->BypassPacketsFlow = AFPBypassCallback;
#ifdef HAVE_PACKET_EBPF
        p->afp_v.v4_map_fd = ptv->v4_map_fd;
        p->afp_v.v6_map_fd = ptv->v6_map_fd;
        p->afp_v.nr_cpus = ptv->ebpf_t_config.cpus_count;
#endif
    } else if (ptv->flags & AFP_XDPBYPASS) {
        p->BypassPacketsFlow = AFPXDPBypassCallback;
#ifdef HAVE_PACKET_EBPF
        p->afp_v.v4_map_fd = ptv->v4_map_fd;
        p->afp_v.v6_map_fd = ptv->v6_map_fd;
        p->afp_v.nr_cpus = ptv->ebpf_t_config.cpus_count;
#endif
    }

    ptv->pkts++;
    p->livedev = ptv->livedev;
    p->datalink = ptv->datalink;

    if ((!(ptv->flags & AFP_VLAN_DISABLED)) &&
            (ppd->tp_status & TP_STATUS_VLAN_VALID || ppd->hv1.tp_vlan_tci)) {
        p->vlan_id[0] = ppd->hv1.tp_vlan_tci & 0x0fff;
        p->vlan_idx = 1;
        p->vlanh[0] = NULL;
    }

    if (ptv->flags & AFP_ZERO_COPY) {
        if (PacketSetData(p, (unsigned char*)ppd + ppd->tp_mac, ppd->tp_snaplen) == -1) {
            TmqhOutputPacketpool(ptv->tv, p);
            SCReturnInt(AFP_SURI_FAILURE);
        }
        p->afp_v.relptr = ppd;
        p->ReleasePacket = AFPReleasePacketV3;
        p->afp_v.mpeer = ptv->mpeer;
        AFPRefSocket(ptv->mpeer);

        p->afp_v.copy_mode = ptv->copy_mode;
        if (p->afp_v.copy_mode != AFP_COPY_MODE_NONE) {
            p->afp_v.peer = ptv->mpeer->peer;
        } else {
            p->afp_v.peer = NULL;
        }
    } else {
        if (PacketCopyData(p, (unsigned char*)ppd + ppd->tp_mac, ppd->tp_snaplen) == -1) {
            TmqhOutputPacketpool(ptv->tv, p);
            SCReturnInt(AFP_SURI_FAILURE);
        }
    }
    /* Timestamp */
    p->ts.tv_sec = ppd->tp_sec;
    p->ts.tv_usec = ppd->tp_nsec/1000;
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
        if (ppd->tp_status & TP_STATUS_CSUMNOTREADY) {
            p->flags |= PKT_IGNORE_CHECKSUM;
        }
    }

    if (TmThreadsSlotProcessPkt(ptv->tv, ptv->slot, p) != TM_ECODE_OK) {
        TmqhOutputPacketpool(ptv->tv, p);
        SCReturnInt(AFP_SURI_FAILURE);
    }

    SCReturnInt(AFP_READ_OK);
}

static inline int AFPWalkBlock(AFPThreadVars *ptv, struct tpacket_block_desc *pbd)
{
    int num_pkts = pbd->hdr.bh1.num_pkts, i;
    uint8_t *ppd;
    int ret = 0;

    ppd = (uint8_t *)pbd + pbd->hdr.bh1.offset_to_first_pkt;
    for (i = 0; i < num_pkts; ++i) {
        ret = AFPParsePacketV3(ptv, pbd,
                               (struct tpacket3_hdr *)ppd);
        switch (ret) {
            case AFP_READ_OK:
                break;
            case AFP_SURI_FAILURE:
                /* Internal error but let's just continue and
                 * treat thenext packet */
                break;
            case AFP_READ_FAILURE:
                SCReturnInt(AFP_READ_FAILURE);
            default:
                SCReturnInt(ret);
        }
        ppd = ppd + ((struct tpacket3_hdr *)ppd)->tp_next_offset;
    }

    SCReturnInt(AFP_READ_OK);
}
#endif /* HAVE_TPACKET_V3 */

/**
 * \brief AF packet read function for ring
 *
 * This function fills
 * From here the packets are picked up by the DecodeAFP thread.
 *
 * \param user pointer to AFPThreadVars
 * \retval TM_ECODE_FAILED on failure and TM_ECODE_OK on success
 */
static int AFPReadFromRingV3(AFPThreadVars *ptv)
{
#ifdef HAVE_TPACKET_V3
    struct tpacket_block_desc *pbd;
    int ret = 0;

    /* Loop till we have packets available */
    while (1) {
        if (unlikely(suricata_ctl_flags != 0)) {
            SCLogInfo("Exiting AFP V3 read loop");
            break;
        }

        pbd = (struct tpacket_block_desc *) ptv->ring.v3[ptv->frame_offset].iov_base;

        /* block is not ready to be read */
        if ((pbd->hdr.bh1.block_status & TP_STATUS_USER) == 0) {
            SCReturnInt(AFP_READ_OK);
        }

        ret = AFPWalkBlock(ptv, pbd);
        if (unlikely(ret != AFP_READ_OK)) {
            AFPFlushBlock(pbd);
            SCReturnInt(ret);
        }

        AFPFlushBlock(pbd);
        ptv->frame_offset = (ptv->frame_offset + 1) % ptv->req.v3.tp_block_nr;
        /* return to maintenance task after one loop on the ring */
        if (ptv->frame_offset == 0) {
            SCReturnInt(AFP_READ_OK);
        }
    }
#endif
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

static void AFPSwitchState(AFPThreadVars *ptv, int state)
{
    ptv->afp_state = state;
    ptv->down_count = 0;

    AFPPeerUpdate(ptv);

    /* Do cleaning if switching to down state */
    if (state == AFP_STATE_DOWN) {
#ifdef HAVE_TPACKET_V3
        if (ptv->flags & AFP_TPACKET_V3) {
            if (!ptv->ring.v3) {
                SCFree(ptv->ring.v3);
                ptv->ring.v3 = NULL;
            }
        } else {
#endif
            if (ptv->ring.v2) {
                /* only used in reading phase, we can free it */
                SCFree(ptv->ring.v2);
                ptv->ring.v2 = NULL;
            }
#ifdef HAVE_TPACKET_V3
        }
#endif
        if (ptv->socket != -1) {
            /* we need to wait for all packets to return data */
            if (SC_ATOMIC_SUB(ptv->mpeer->sock_usage, 1) == 0) {
                SCLogDebug("Cleaning socket connected to '%s'", ptv->iface);
                munmap(ptv->ring_buf, ptv->ring_buflen);
                close(ptv->socket);
                ptv->socket = -1;
            }
        }
    }
    if (state == AFP_STATE_UP) {
         (void)SC_ATOMIC_SET(ptv->mpeer->sock_usage, 1);
    }
}

static int AFPReadAndDiscard(AFPThreadVars *ptv, struct timeval *synctv,
                             uint64_t *discarded_pkts)
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

    (void)recvmsg(ptv->socket, &msg, MSG_TRUNC);

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

static int AFPReadAndDiscardFromRing(AFPThreadVars *ptv, struct timeval *synctv,
                                     uint64_t *discarded_pkts)
{
    union thdr h;

    if (unlikely(suricata_ctl_flags != 0)) {
        return 1;
    }

#ifdef HAVE_TPACKET_V3
    if (ptv->flags & AFP_TPACKET_V3) {
        int ret = 0;
        struct tpacket_block_desc *pbd;
        pbd = (struct tpacket_block_desc *) ptv->ring.v3[ptv->frame_offset].iov_base;
        *discarded_pkts += pbd->hdr.bh1.num_pkts;
        struct tpacket3_hdr *ppd =
            (struct tpacket3_hdr *)((uint8_t *)pbd + pbd->hdr.bh1.offset_to_first_pkt);
        if (((time_t)ppd->tp_sec > synctv->tv_sec) ||
                ((time_t)ppd->tp_sec == synctv->tv_sec &&
                 (suseconds_t) (ppd->tp_nsec / 1000) > (suseconds_t)synctv->tv_usec)) {
            ret = 1;
        }
        AFPFlushBlock(pbd);
        ptv->frame_offset = (ptv->frame_offset + 1) % ptv->req.v3.tp_block_nr;
        return ret;

    } else
#endif
    {
        /* Read packet from ring */
        h.raw = (((union thdr **)ptv->ring.v2)[ptv->frame_offset]);
        if (h.raw == NULL) {
            return -1;
        }
        (*discarded_pkts)++;
        if (((time_t)h.h2->tp_sec > synctv->tv_sec) ||
                ((time_t)h.h2->tp_sec == synctv->tv_sec &&
                 (suseconds_t) (h.h2->tp_nsec / 1000) > synctv->tv_usec)) {
            return 1;
        }

        h.h2->tp_status = TP_STATUS_KERNEL;
        if (++ptv->frame_offset >= ptv->req.v2.tp_frame_nr) {
            ptv->frame_offset = 0;
        }
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
static int AFPSynchronizeStart(AFPThreadVars *ptv, uint64_t *discarded_pkts)
{
    struct timeval synctv;
    struct pollfd fds;

    fds.fd = ptv->socket;
    fds.events = POLLIN;

    /* Set timeval to end of the world */
    synctv.tv_sec = 0xffffffff;
    synctv.tv_usec = 0xffffffff;

    while (1) {
        int r = poll(&fds, 1, POLL_TIMEOUT);
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
                r = AFPReadAndDiscardFromRing(ptv, &synctv, discarded_pkts);
            } else {
                r = AFPReadAndDiscard(ptv, &synctv, discarded_pkts);
            }
            SCLogDebug("Discarding on %s", ptv->tv->name);
            switch (r) {
                case 1:
                    SCLogDebug("Starting to read on %s", ptv->tv->name);
                    return 1;
                case -1:
                    return r;
            }
        /* no packets */
        } else if (r == 0 && AFPPeersListStarted()) {
            SCLogDebug("Starting to read on %s", ptv->tv->name);
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
    ptv->down_count++;

    /* Don't reconnect till we have packet that did not release data */
    if (SC_ATOMIC_GET(ptv->mpeer->sock_usage) != 0) {
        return -1;
    }

    int afp_activate_r = AFPCreateSocket(ptv, ptv->iface, 0);
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
    time_t current_time;
    int (*AFPReadFunc) (AFPThreadVars *);
    uint64_t discarded_pkts = 0;

    ptv->slot = s->slot_next;

    if (ptv->flags & AFP_RING_MODE) {
        if (ptv->flags & AFP_TPACKET_V3) {
            AFPReadFunc = AFPReadFromRingV3;
        } else {
            AFPReadFunc = AFPReadFromRing;
        }
    } else {
        AFPReadFunc = AFPRead;
    }

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
                    SCReturnInt(TM_ECODE_FAILED);
                case AFP_RECOVERABLE_ERROR:
                    SCLogWarning(SC_ERR_AFP_CREATE, "Couldn't init AF_PACKET socket, retrying soon");
            }
        }
        AFPPeersListReachedInc();
    }
    if (ptv->afp_state == AFP_STATE_UP) {
        SCLogDebug("Thread %s using socket %d", tv->name, ptv->socket);
        AFPSynchronizeStart(ptv, &discarded_pkts);
        /* let's reset counter as we will start the capture at the
         * next function call */
#ifdef PACKET_STATISTICS
         struct tpacket_stats kstats;
         socklen_t len = sizeof (struct tpacket_stats);
         if (getsockopt(ptv->socket, SOL_PACKET, PACKET_STATISTICS,
                     &kstats, &len) > -1) {
             uint64_t pkts = 0;
             SCLogDebug("(%s) Kernel socket startup: Packets %" PRIu32
                     ", dropped %" PRIu32 "",
                     ptv->tv->name,
                     kstats.tp_packets, kstats.tp_drops);
             pkts = kstats.tp_packets - discarded_pkts - kstats.tp_drops;
             StatsAddUI64(ptv->tv, ptv->capture_kernel_packets, pkts);
             (void) SC_ATOMIC_ADD(ptv->livedev->pkts, pkts);
         }
#endif
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
                           "Error reading data from iface '%s': (%d) %s",
                           ptv->iface, errno, strerror(errno));
                AFPSwitchState(ptv, AFP_STATE_DOWN);
                continue;
            } else if (fds.revents & POLLNVAL) {
                SCLogError(SC_ERR_AFP_READ, "Invalid polling request");
                AFPSwitchState(ptv, AFP_STATE_DOWN);
                continue;
            }
        } else if (r > 0) {
            r = AFPReadFunc(ptv);
            switch (r) {
                case AFP_READ_OK:
                    /* Trigger one dump of stats every second */
                    current_time = time(NULL);
                    if (current_time != last_dump) {
                        AFPDumpCounters(ptv);
                        last_dump = current_time;
                    }
                    break;
                case AFP_READ_FAILURE:
                    /* AFPRead in error: best to reset the socket */
                    SCLogError(SC_ERR_AFP_READ,
                           "AFPRead error reading data from iface '%s': (%d) %s",
                           ptv->iface, errno, strerror(errno));
                    AFPSwitchState(ptv, AFP_STATE_DOWN);
                    continue;
                case AFP_SURI_FAILURE:
                    StatsIncr(ptv->tv, ptv->capture_errors);
                    break;
                case AFP_KERNEL_DROP:
                    AFPDumpCounters(ptv);
                    break;
            }
        } else if (unlikely(r == 0)) {
            /* Trigger one dump of stats every second */
            current_time = time(NULL);
            if (current_time != last_dump) {
                AFPDumpCounters(ptv);
                last_dump = current_time;
            }
            /* poll timed out, lets see handle our timeout path */
            TmThreadsCaptureHandleTimeout(tv, ptv->slot, NULL);

        } else if ((r < 0) && (errno != EINTR)) {
            SCLogError(SC_ERR_AFP_READ, "Error reading data from iface '%s': (%d) %s",
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
        case ARPHRD_NONE:
            return LINKTYPE_RAW;
        default:
            return ifr.ifr_hwaddr.sa_family;
    }
}

int AFPGetLinkType(const char *ifname)
{
    int ltype;

    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd == -1) {
        SCLogError(SC_ERR_AFP_CREATE, "Couldn't create a AF_PACKET socket, error %s", strerror(errno));
        return LINKTYPE_RAW;
    }

    ltype =  AFPGetDevLinktype(fd, ifname);
    close(fd);

    return ltype;
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

    ptv->req.v2.tp_frame_size = TPACKET_ALIGN(snaplen +TPACKET_ALIGN(TPACKET_ALIGN(tp_hdrlen) + sizeof(struct sockaddr_ll) + ETH_HLEN) - ETH_HLEN);
    ptv->req.v2.tp_block_size = getpagesize() << order;
    int frames_per_block = ptv->req.v2.tp_block_size / ptv->req.v2.tp_frame_size;
    if (frames_per_block == 0) {
        SCLogError(SC_ERR_INVALID_VALUE, "Frame size bigger than block size");
        return -1;
    }
    ptv->req.v2.tp_frame_nr = ptv->ring_size;
    ptv->req.v2.tp_block_nr = ptv->req.v2.tp_frame_nr / frames_per_block + 1;
    /* exact division */
    ptv->req.v2.tp_frame_nr = ptv->req.v2.tp_block_nr * frames_per_block;
    SCLogPerf("AF_PACKET RX Ring params: block_size=%d block_nr=%d frame_size=%d frame_nr=%d",
              ptv->req.v2.tp_block_size, ptv->req.v2.tp_block_nr,
              ptv->req.v2.tp_frame_size, ptv->req.v2.tp_frame_nr);
    return 1;
}

#ifdef HAVE_TPACKET_V3
static int AFPComputeRingParamsV3(AFPThreadVars *ptv)
{
    ptv->req.v3.tp_block_size = ptv->block_size;
    ptv->req.v3.tp_frame_size = 2048;
    int frames_per_block = 0;
    int tp_hdrlen = sizeof(struct tpacket3_hdr);
    int snaplen = default_packet_size;

    if (snaplen == 0) {
        snaplen = GetIfaceMaxPacketSize(ptv->iface);
        if (snaplen <= 0) {
            SCLogWarning(SC_ERR_INVALID_VALUE,
                         "Unable to get MTU, setting snaplen to sane default of 1514");
            snaplen = 1514;
        }
    }

    ptv->req.v3.tp_frame_size = TPACKET_ALIGN(snaplen +TPACKET_ALIGN(TPACKET_ALIGN(tp_hdrlen) + sizeof(struct sockaddr_ll) + ETH_HLEN) - ETH_HLEN);
    frames_per_block = ptv->req.v3.tp_block_size / ptv->req.v3.tp_frame_size;

    if (frames_per_block == 0) {
        SCLogError(SC_ERR_INVALID_VALUE,
                   "Block size is too small, it should be at least %d",
                   ptv->req.v3.tp_frame_size);
        return -1;
    }
    ptv->req.v3.tp_block_nr = ptv->ring_size / frames_per_block + 1;
    /* exact division */
    ptv->req.v3.tp_frame_nr = ptv->req.v3.tp_block_nr * frames_per_block;
    ptv->req.v3.tp_retire_blk_tov = ptv->block_timeout;
    ptv->req.v3.tp_feature_req_word = TP_FT_REQ_FILL_RXHASH;
    SCLogPerf("AF_PACKET V3 RX Ring params: block_size=%d block_nr=%d frame_size=%d frame_nr=%d (mem: %d)",
              ptv->req.v3.tp_block_size, ptv->req.v3.tp_block_nr,
              ptv->req.v3.tp_frame_size, ptv->req.v3.tp_frame_nr,
              ptv->req.v3.tp_block_size * ptv->req.v3.tp_block_nr
              );
    return 1;
}
#endif

static int AFPSetupRing(AFPThreadVars *ptv, char *devname)
{
    int val;
    unsigned int len = sizeof(val), i;
    int order;
    int r, mmap_flag;

#ifdef HAVE_TPACKET_V3
    if (ptv->flags & AFP_TPACKET_V3) {
        val = TPACKET_V3;
    } else
#endif
    {
        val = TPACKET_V2;
    }
    if (getsockopt(ptv->socket, SOL_PACKET, PACKET_HDRLEN, &val, &len) < 0) {
        if (errno == ENOPROTOOPT) {
            if (ptv->flags & AFP_TPACKET_V3) {
                SCLogError(SC_ERR_AFP_CREATE,
                        "Too old kernel giving up (need 3.2 for TPACKET_V3)");
            } else {
                SCLogError(SC_ERR_AFP_CREATE,
                        "Too old kernel giving up (need 2.6.27 at least)");
            }
        }
        SCLogError(SC_ERR_AFP_CREATE, "Error when retrieving packet header len");
        return AFP_FATAL_ERROR;
    }

    val = TPACKET_V2;
#ifdef HAVE_TPACKET_V3
    if (ptv->flags & AFP_TPACKET_V3) {
        val = TPACKET_V3;
    }
#endif
    if (setsockopt(ptv->socket, SOL_PACKET, PACKET_VERSION, &val,
                sizeof(val)) < 0) {
        SCLogError(SC_ERR_AFP_CREATE,
                "Can't activate TPACKET_V2/TPACKET_V3 on packet socket: %s",
                strerror(errno));
        return AFP_FATAL_ERROR;
    }

#ifdef HAVE_HW_TIMESTAMPING
    int req = SOF_TIMESTAMPING_RAW_HARDWARE;
    if (setsockopt(ptv->socket, SOL_PACKET, PACKET_TIMESTAMP, (void *) &req,
                sizeof(req)) < 0) {
        SCLogWarning(SC_ERR_AFP_CREATE,
                "Can't activate hardware timestamping on packet socket: %s",
                strerror(errno));
    }
#endif

    /* Let's reserve head room so we can add the VLAN header in IPS
     * or TAP mode before write the packet */
    if (ptv->copy_mode != AFP_COPY_MODE_NONE) {
        /* Only one vlan is extracted from AFP header so
         * one VLAN header length is enough. */
        int reserve = VLAN_HEADER_LEN;
        if (setsockopt(ptv->socket, SOL_PACKET, PACKET_RESERVE, (void *) &reserve,
                    sizeof(reserve)) < 0) {
            SCLogError(SC_ERR_AFP_CREATE,
                    "Can't activate reserve on packet socket: %s",
                    strerror(errno));
            return AFP_FATAL_ERROR;
        }
    }

    /* Allocate RX ring */
#ifdef HAVE_TPACKET_V3
    if (ptv->flags & AFP_TPACKET_V3) {
        if (AFPComputeRingParamsV3(ptv) != 1) {
            return AFP_FATAL_ERROR;
        }
        r = setsockopt(ptv->socket, SOL_PACKET, PACKET_RX_RING,
                (void *) &ptv->req.v3, sizeof(ptv->req.v3));
        if (r < 0) {
            SCLogError(SC_ERR_MEM_ALLOC,
                    "Unable to allocate RX Ring for iface %s: (%d) %s",
                    devname,
                    errno,
                    strerror(errno));
            return AFP_FATAL_ERROR;
        }
    } else {
#endif
        for (order = AFP_BLOCK_SIZE_DEFAULT_ORDER; order >= 0; order--) {
            if (AFPComputeRingParams(ptv, order) != 1) {
                SCLogInfo("Ring parameter are incorrect. Please correct the devel");
                return AFP_FATAL_ERROR;
            }

            r = setsockopt(ptv->socket, SOL_PACKET, PACKET_RX_RING,
                    (void *) &ptv->req, sizeof(ptv->req));

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
                return AFP_FATAL_ERROR;
            } else {
                break;
            }
        }
        if (order < 0) {
            SCLogError(SC_ERR_MEM_ALLOC,
                    "Unable to allocate RX Ring for iface %s (order 0 failed)",
                    devname);
            return AFP_FATAL_ERROR;
        }
#ifdef HAVE_TPACKET_V3
    }
#endif

    /* Allocate the Ring */
#ifdef HAVE_TPACKET_V3
    if (ptv->flags & AFP_TPACKET_V3) {
        ptv->ring_buflen = ptv->req.v3.tp_block_nr * ptv->req.v3.tp_block_size;
    } else {
#endif
        ptv->ring_buflen = ptv->req.v2.tp_block_nr * ptv->req.v2.tp_block_size;
#ifdef HAVE_TPACKET_V3
    }
#endif
    mmap_flag = MAP_SHARED;
    if (ptv->flags & AFP_MMAP_LOCKED)
        mmap_flag |= MAP_LOCKED;
    ptv->ring_buf = mmap(0, ptv->ring_buflen, PROT_READ|PROT_WRITE,
            mmap_flag, ptv->socket, 0);
    if (ptv->ring_buf == MAP_FAILED) {
        SCLogError(SC_ERR_MEM_ALLOC, "Unable to mmap, error %s",
                   strerror(errno));
        goto mmap_err;
    }
#ifdef HAVE_TPACKET_V3
    if (ptv->flags & AFP_TPACKET_V3) {
        ptv->ring.v3 = SCMalloc(ptv->req.v3.tp_block_nr * sizeof(*ptv->ring.v3));
        if (!ptv->ring.v3) {
            SCLogError(SC_ERR_MEM_ALLOC, "Unable to malloc ptv ring.v3");
            goto postmmap_err;
        }
        for (i = 0; i < ptv->req.v3.tp_block_nr; ++i) {
            ptv->ring.v3[i].iov_base = ptv->ring_buf + (i * ptv->req.v3.tp_block_size);
            ptv->ring.v3[i].iov_len = ptv->req.v3.tp_block_size;
        }
    } else {
#endif
        /* allocate a ring for each frame header pointer*/
        ptv->ring.v2 = SCMalloc(ptv->req.v2.tp_frame_nr * sizeof (union thdr *));
        if (ptv->ring.v2 == NULL) {
            SCLogError(SC_ERR_MEM_ALLOC, "Unable to allocate frame buf");
            goto postmmap_err;
        }
        memset(ptv->ring.v2, 0, ptv->req.v2.tp_frame_nr * sizeof (union thdr *));
        /* fill the header ring with proper frame ptr*/
        ptv->frame_offset = 0;
        for (i = 0; i < ptv->req.v2.tp_block_nr; ++i) {
            void *base = &(ptv->ring_buf[i * ptv->req.v2.tp_block_size]);
            unsigned int j;
            for (j = 0; j < ptv->req.v2.tp_block_size / ptv->req.v2.tp_frame_size; ++j, ++ptv->frame_offset) {
                (((union thdr **)ptv->ring.v2)[ptv->frame_offset]) = base;
                base += ptv->req.v2.tp_frame_size;
            }
        }
        ptv->frame_offset = 0;
#ifdef HAVE_TPACKET_V3
    }
#endif

    return 0;

postmmap_err:
    munmap(ptv->ring_buf, ptv->ring_buflen);
    if (ptv->ring.v2)
        SCFree(ptv->ring.v2);
    if (ptv->ring.v3)
        SCFree(ptv->ring.v3);
mmap_err:
    /* Packet mmap does the cleaning when socket is closed */
    return AFP_FATAL_ERROR;
}

/** \brief test if we can use FANOUT. Older kernels like those in
 *         CentOS6 have HAVE_PACKET_FANOUT defined but fail to work
 */
int AFPIsFanoutSupported(void)
{
#ifdef HAVE_PACKET_FANOUT
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0)
        return 0;

    uint16_t mode = PACKET_FANOUT_HASH | PACKET_FANOUT_FLAG_DEFRAG;
    uint16_t id = 1;
    uint32_t option = (mode << 16) | (id & 0xffff);
    int r = setsockopt(fd, SOL_PACKET, PACKET_FANOUT,(void *)&option, sizeof(option));
    close(fd);

    if (r < 0) {
        SCLogPerf("fanout not supported by kernel: %s", strerror(errno));
        return 0;
    }
    return 1;
#else
    return 0;
#endif
}

#ifdef HAVE_PACKET_EBPF

static int SockFanoutSeteBPF(AFPThreadVars *ptv)
{
    int pfd = ptv->ebpf_lb_fd;
    if (pfd == -1) {
        SCLogError(SC_ERR_INVALID_VALUE,
                   "Fanout file descriptor is invalid");
        return -1;
    }

    if (setsockopt(ptv->socket, SOL_PACKET, PACKET_FANOUT_DATA, &pfd, sizeof(pfd))) {
        SCLogError(SC_ERR_INVALID_VALUE, "Error setting ebpf");
        return -1;
    }
    SCLogInfo("Activated eBPF on socket");

    return 0;
}

static int SetEbpfFilter(AFPThreadVars *ptv)
{
    int pfd = ptv->ebpf_filter_fd;
    if (pfd == -1) {
        SCLogError(SC_ERR_INVALID_VALUE,
                   "Filter file descriptor is invalid");
        return -1;
    }

    if (setsockopt(ptv->socket, SOL_SOCKET, SO_ATTACH_BPF, &pfd, sizeof(pfd))) {
        SCLogError(SC_ERR_INVALID_VALUE, "Error setting ebpf: %s", strerror(errno));
        return -1;
    }
    SCLogInfo("Activated eBPF filter on socket");

    return 0;
}
#endif

static int AFPCreateSocket(AFPThreadVars *ptv, char *devname, int verbose)
{
    int r;
    int ret = AFP_FATAL_ERROR;
    struct packet_mreq sock_params;
    struct sockaddr_ll bind_address;
    int if_idx;

    /* open socket */
    ptv->socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (ptv->socket == -1) {
        SCLogError(SC_ERR_AFP_CREATE, "Couldn't create a AF_PACKET socket, error %s", strerror(errno));
        goto error;
    }

    if_idx = AFPGetIfnumByDev(ptv->socket, devname, verbose);

    if (if_idx == -1) {
        goto socket_err;
    }

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

    int if_flags = AFPGetDevFlags(ptv->socket, ptv->iface);
    if (if_flags == -1) {
        if (verbose) {
            SCLogError(SC_ERR_AFP_READ,
                    "Couldn't get flags for interface '%s'",
                    ptv->iface);
        }
        ret = AFP_RECOVERABLE_ERROR;
        goto socket_err;
    } else if ((if_flags & (IFF_UP | IFF_RUNNING)) == 0) {
        if (verbose) {
            SCLogError(SC_ERR_AFP_READ,
                    "Interface '%s' is down",
                    ptv->iface);
        }
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
            goto socket_err;
        }
    }

    if (ptv->checksum_mode == CHECKSUM_VALIDATION_KERNEL) {
        int val = 1;
        if (setsockopt(ptv->socket, SOL_PACKET, PACKET_AUXDATA, &val,
                    sizeof(val)) == -1 && errno != ENOPROTOOPT) {
            SCLogWarning(SC_ERR_NO_AF_PACKET,
                         "'kernel' checksum mode not supported, falling back to full mode.");
            ptv->checksum_mode = CHECKSUM_VALIDATION_ENABLE;
        }
    }

    /* set socket recv buffer size */
    if (ptv->buffer_size != 0) {
        /*
         * Set the socket buffer size to the specified value.
         */
        SCLogPerf("Setting AF_PACKET socket buffer to %d", ptv->buffer_size);
        if (setsockopt(ptv->socket, SOL_SOCKET, SO_RCVBUF,
                       &ptv->buffer_size,
                       sizeof(ptv->buffer_size)) == -1) {
            SCLogError(SC_ERR_AFP_CREATE,
                    "Couldn't set buffer size to %d on iface %s, error %s",
                    ptv->buffer_size, devname, strerror(errno));
            goto socket_err;
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
        goto socket_err;
    }


#ifdef HAVE_PACKET_FANOUT
    /* add binded socket to fanout group */
    if (ptv->threads > 1) {
        uint16_t mode = ptv->cluster_type;
        uint16_t id = ptv->cluster_id;
        uint32_t option = (mode << 16) | (id & 0xffff);
        r = setsockopt(ptv->socket, SOL_PACKET, PACKET_FANOUT,(void *)&option, sizeof(option));
        if (r < 0) {
            SCLogError(SC_ERR_AFP_CREATE,
                       "Couldn't set fanout mode, error %s",
                       strerror(errno));
            goto socket_err;
        }
    }
#endif

#ifdef HAVE_PACKET_EBPF
    if (ptv->cluster_type == PACKET_FANOUT_EBPF) {
        r = SockFanoutSeteBPF(ptv);
        if (r < 0) {
            SCLogError(SC_ERR_AFP_CREATE,
                       "Coudn't set EBPF, error %s",
                       strerror(errno));
            goto socket_err;
        }
    }
#endif

    if (ptv->flags & AFP_RING_MODE) {
        ret = AFPSetupRing(ptv, devname);
        if (ret != 0)
            goto socket_err;
    }

    SCLogDebug("Using interface '%s' via socket %d", (char *)devname, ptv->socket);

    ptv->datalink = AFPGetDevLinktype(ptv->socket, ptv->iface);
    switch (ptv->datalink) {
        case ARPHRD_PPP:
        case ARPHRD_ATM:
            ptv->cooked = 1;
            break;
    }

    TmEcode rc = AFPSetBPFFilter(ptv);
    if (rc == TM_ECODE_FAILED) {
        ret = AFP_FATAL_ERROR;
        goto socket_err;
    }

    /* Init is ok */
    AFPSwitchState(ptv, AFP_STATE_UP);
    return 0;

socket_err:
    close(ptv->socket);
    ptv->socket = -1;
    if (ptv->flags & AFP_TPACKET_V3) {
        if (ptv->ring.v3) {
            SCFree(ptv->ring.v3);
            ptv->ring.v3 = NULL;
        }
    } else {
        if (ptv->ring.v2) {
            SCFree(ptv->ring.v2);
            ptv->ring.v2 = NULL;
        }
    }

error:
    return -ret;
}

TmEcode AFPSetBPFFilter(AFPThreadVars *ptv)
{
    struct bpf_program filter;
    struct sock_fprog  fcode;
    int rc;

#ifdef HAVE_PACKET_EBPF
    if (ptv->ebpf_filter_fd != -1) {
        return SetEbpfFilter(ptv);
    }
#endif

    if (!ptv->bpf_filter)
        return TM_ECODE_OK;

    SCLogInfo("Using BPF '%s' on iface '%s'",
              ptv->bpf_filter,
              ptv->iface);

    char errbuf[PCAP_ERRBUF_SIZE];
    if (SCBPFCompile(default_packet_size,  /* snaplen_arg */
                ptv->datalink,    /* linktype_arg */
                &filter,       /* program */
                ptv->bpf_filter, /* const char *buf */
                1,             /* optimize */
                0,              /* mask */
                errbuf,
                sizeof(errbuf)) == -1) {
        SCLogError(SC_ERR_AFP_CREATE, "Failed to compile BPF \"%s\": %s",
                   ptv->bpf_filter,
                   errbuf);
        return TM_ECODE_FAILED;
    }

    fcode.len    = filter.bf_len;
    fcode.filter = (struct sock_filter*)filter.bf_insns;

    rc = setsockopt(ptv->socket, SOL_SOCKET, SO_ATTACH_FILTER, &fcode, sizeof(fcode));

    SCBPFFree(&filter);
    if(rc == -1) {
        SCLogError(SC_ERR_AFP_CREATE, "Failed to attach filter: %s", strerror(errno));
        return TM_ECODE_FAILED;
    }

    return TM_ECODE_OK;
}

#ifdef HAVE_PACKET_EBPF
/**
 * Insert a half flow in the kernel bypass table
 *
 * \param mapfd file descriptor of the protocol bypass table
 * \param key data to use as key in the table
 * \return 0 in case of error, 1 if success
 */
static int AFPInsertHalfFlow(int mapd, void *key, unsigned int nr_cpus)
{
    BPF_DECLARE_PERCPU(struct pair, value, nr_cpus);
    unsigned int i;

    if (mapd == -1) {
        return 0;
    }

    /* We use a per CPU structure so we have to set an array of values as the kernel
     * is not duplicating the data on each CPU by itself. */
    for (i = 0; i < nr_cpus; i++) {
        BPF_PERCPU(value, i).packets = 0;
        BPF_PERCPU(value, i).bytes = 0;
    }
    if (bpf_map_update_elem(mapd, key, value, BPF_NOEXIST) != 0) {
        switch (errno) {
            /* no more place in the hash */
            case E2BIG:
                return 0;
            /* no more place in the hash for some hardware bypass */
            case EAGAIN:
                return 0;
            /* if we already have the key then bypass is a success */
            case EEXIST:
                return 1;
            /* Not supposed to be there so issue a error */
            default:
                SCLogError(SC_ERR_BPF, "Can't update eBPF map: %s (%d)",
                        strerror(errno),
                        errno);
                return 0;
        }
    }
    return 1;
}

static int AFPSetFlowStorage(Packet *p, int map_fd, void *key0, void* key1,
                             int family)
{
    FlowBypassInfo *fc = FlowGetStorageById(p->flow, GetFlowBypassInfoID());
    if (fc) {
        EBPFBypassData *eb = SCCalloc(1, sizeof(EBPFBypassData));
        if (eb == NULL) {
            EBPFDeleteKey(map_fd, key0);
            EBPFDeleteKey(map_fd, key1);
            LiveDevAddBypassFail(p->livedev, 1, family);
            SCFree(key0);
            SCFree(key1);
            return 0;
        }
        eb->key[0] = key0;
        eb->key[1] = key1;
        eb->mapfd = map_fd;
        eb->cpus_count = p->afp_v.nr_cpus;
        fc->BypassUpdate = EBPFBypassUpdate;
        fc->BypassFree = EBPFBypassFree;
        fc->bypass_data = eb;
    } else {
        EBPFDeleteKey(map_fd, key0);
        EBPFDeleteKey(map_fd, key1);
        LiveDevAddBypassFail(p->livedev, 1, family);
        SCFree(key0);
        SCFree(key1);
        return 0;
    }

    LiveDevAddBypassStats(p->livedev, 1, family);
    LiveDevAddBypassSuccess(p->livedev, 1, family);
    return 1;
}

#endif

/**
 * Bypass function for AF_PACKET capture in eBPF mode
 *
 * This function creates two half flows in the map shared with the kernel
 * to trigger bypass.
 *
 * The implementation of bypass is done via an IPv4 and an IPv6 flow table.
 * This table contains the list of half flows to bypass. The in-kernel filter
 * will skip/drop the packet if they belong to a flow in one of the flows
 * table.
 *
 * \param p the packet belonging to the flow to bypass
 * \return 0 if unable to bypass, 1 if success
 */
static int AFPBypassCallback(Packet *p)
{
#ifdef HAVE_PACKET_EBPF
    SCLogDebug("Calling af_packet callback function");
    /* Only bypass TCP and UDP */
    if (!(PKT_IS_TCP(p) || PKT_IS_UDP(p))) {
        return 0;
    }

    /* If we don't have a flow attached to packet the eBPF map entries
     * will be destroyed at first flow bypass manager pass as we won't
     * find any associated entry */
    if (p->flow == NULL) {
        return 0;
    }
    /* Bypassing tunneled packets is currently not supported
     * because we can't discard the inner packet only due to
     * primitive parsing in eBPF */
    if (IS_TUNNEL_PKT(p)) {
        return 0;
    }
    if (PKT_IS_IPV4(p)) {
        SCLogDebug("add an IPv4");
        if (p->afp_v.v4_map_fd == -1) {
            return 0;
        }
        struct flowv4_keys *keys[2];
        keys[0] = SCCalloc(1, sizeof(struct flowv4_keys));
        if (keys[0] == NULL) {
            return 0;
        }
        keys[0]->src = htonl(GET_IPV4_SRC_ADDR_U32(p));
        keys[0]->dst = htonl(GET_IPV4_DST_ADDR_U32(p));
        keys[0]->port16[0] = GET_TCP_SRC_PORT(p);
        keys[0]->port16[1] = GET_TCP_DST_PORT(p);
        keys[0]->vlan0 = p->vlan_id[0];
        keys[0]->vlan1 = p->vlan_id[1];

        if (IPV4_GET_IPPROTO(p) == IPPROTO_TCP) {
            keys[0]->ip_proto = 1;
        } else {
            keys[0]->ip_proto = 0;
        }
        if (AFPInsertHalfFlow(p->afp_v.v4_map_fd, keys[0],
                              p->afp_v.nr_cpus) == 0) {
            LiveDevAddBypassFail(p->livedev, 1, AF_INET);
            SCFree(keys[0]);
            return 0;
        }
        keys[1]= SCCalloc(1, sizeof(struct flowv4_keys));
        if (keys[1] == NULL) {
            EBPFDeleteKey(p->afp_v.v4_map_fd, keys[0]);
            LiveDevAddBypassFail(p->livedev, 1, AF_INET);
            SCFree(keys[0]);
            return 0;
        }
        keys[1]->src = htonl(GET_IPV4_DST_ADDR_U32(p));
        keys[1]->dst = htonl(GET_IPV4_SRC_ADDR_U32(p));
        keys[1]->port16[0] = GET_TCP_DST_PORT(p);
        keys[1]->port16[1] = GET_TCP_SRC_PORT(p);
        keys[1]->vlan0 = p->vlan_id[0];
        keys[1]->vlan1 = p->vlan_id[1];

        keys[1]->ip_proto = keys[0]->ip_proto;
        if (AFPInsertHalfFlow(p->afp_v.v4_map_fd, keys[1],
                              p->afp_v.nr_cpus) == 0) {
            EBPFDeleteKey(p->afp_v.v4_map_fd, keys[0]);
            LiveDevAddBypassFail(p->livedev, 1, AF_INET);
            SCFree(keys[0]);
            SCFree(keys[1]);
            return 0;
        }
        EBPFUpdateFlow(p->flow, p, NULL);
        return AFPSetFlowStorage(p, p->afp_v.v4_map_fd, keys[0], keys[1], AF_INET);
    }
    /* For IPv6 case we don't handle extended header in eBPF */
    if (PKT_IS_IPV6(p) &&
        ((IPV6_GET_NH(p) == IPPROTO_TCP) || (IPV6_GET_NH(p) == IPPROTO_UDP))) {
        int i;
        if (p->afp_v.v6_map_fd == -1) {
            return 0;
        }
        SCLogDebug("add an IPv6");
        struct flowv6_keys *keys[2];
        keys[0] = SCCalloc(1, sizeof(struct flowv6_keys));
        if (keys[0] == NULL) {
            LiveDevAddBypassFail(p->livedev, 1, AF_INET6);
            return 0;
        }
        for (i = 0; i < 4; i++) {
            keys[0]->src[i] = ntohl(GET_IPV6_SRC_ADDR(p)[i]);
            keys[0]->dst[i] = ntohl(GET_IPV6_DST_ADDR(p)[i]);
        }
        keys[0]->port16[0] = GET_TCP_SRC_PORT(p);
        keys[0]->port16[1] = GET_TCP_DST_PORT(p);
        keys[0]->vlan0 = p->vlan_id[0];
        keys[0]->vlan1 = p->vlan_id[1];

        if (IPV6_GET_NH(p) == IPPROTO_TCP) {
            keys[0]->ip_proto = 1;
        } else {
            keys[0]->ip_proto = 0;
        }
        if (AFPInsertHalfFlow(p->afp_v.v6_map_fd, keys[0],
                              p->afp_v.nr_cpus) == 0) {
            LiveDevAddBypassFail(p->livedev, 1, AF_INET6);
            SCFree(keys[0]);
            return 0;
        }
        keys[1]= SCCalloc(1, sizeof(struct flowv6_keys));
        if (keys[1] == NULL) {
            EBPFDeleteKey(p->afp_v.v6_map_fd, keys[0]);
            LiveDevAddBypassFail(p->livedev, 1, AF_INET6);
            SCFree(keys[0]);
            return 0;
        }
        for (i = 0; i < 4; i++) {
            keys[1]->src[i] = ntohl(GET_IPV6_DST_ADDR(p)[i]);
            keys[1]->dst[i] = ntohl(GET_IPV6_SRC_ADDR(p)[i]);
        }
        keys[1]->port16[0] = GET_TCP_DST_PORT(p);
        keys[1]->port16[1] = GET_TCP_SRC_PORT(p);
        keys[1]->vlan0 = p->vlan_id[0];
        keys[1]->vlan1 = p->vlan_id[1];

        keys[1]->ip_proto = keys[0]->ip_proto;
        if (AFPInsertHalfFlow(p->afp_v.v6_map_fd, keys[1],
                              p->afp_v.nr_cpus) == 0) {
            EBPFDeleteKey(p->afp_v.v6_map_fd, keys[0]);
            LiveDevAddBypassFail(p->livedev, 1, AF_INET6);
            SCFree(keys[0]);
            SCFree(keys[1]);
            return 0;
        }
        if (p->flow)
            EBPFUpdateFlow(p->flow, p, NULL);
        return AFPSetFlowStorage(p, p->afp_v.v6_map_fd, keys[0], keys[1], AF_INET6);
    }
#endif
    return 0;
}

/**
 * Bypass function for AF_PACKET capture in XDP mode
 *
 * This function creates two half flows in the map shared with the kernel
 * to trigger bypass. This function is similar to AFPBypassCallback() but
 * the bytes order is changed for some data due to the way we get the data
 * in the XDP case.
 *
 * \param p the packet belonging to the flow to bypass
 * \return 0 if unable to bypass, 1 if success
 */
static int AFPXDPBypassCallback(Packet *p)
{
#ifdef HAVE_PACKET_XDP
    SCLogDebug("Calling af_packet callback function");
    /* Only bypass TCP and UDP */
    if (!(PKT_IS_TCP(p) || PKT_IS_UDP(p))) {
        return 0;
    }

    /* If we don't have a flow attached to packet the eBPF map entries
     * will be destroyed at first flow bypass manager pass as we won't
     * find any associated entry */
    if (p->flow == NULL) {
        return 0;
    }
    /* Bypassing tunneled packets is currently not supported
     * because we can't discard the inner packet only due to
     * primitive parsing in eBPF */
    if (IS_TUNNEL_PKT(p)) {
        return 0;
    }
    if (PKT_IS_IPV4(p)) {
        struct flowv4_keys *keys[2];
        keys[0]= SCCalloc(1, sizeof(struct flowv4_keys));
        if (keys[0] == NULL) {
            LiveDevAddBypassFail(p->livedev, 1, AF_INET);
            return 0;
        }
        if (p->afp_v.v4_map_fd == -1) {
            SCFree(keys[0]);
            return 0;
        }
        keys[0]->src = p->src.addr_data32[0];
        keys[0]->dst = p->dst.addr_data32[0];
        /* In the XDP filter we get port from parsing of packet and not from skb
         * (as in eBPF filter) so we need to pass from host to network order */
        keys[0]->port16[0] = htons(p->sp);
        keys[0]->port16[1] = htons(p->dp);
        keys[0]->vlan0 = p->vlan_id[0];
        keys[0]->vlan1 = p->vlan_id[1];
        if (IPV4_GET_IPPROTO(p) == IPPROTO_TCP) {
            keys[0]->ip_proto = 1;
        } else {
            keys[0]->ip_proto = 0;
        }
        if (AFPInsertHalfFlow(p->afp_v.v4_map_fd, keys[0],
                              p->afp_v.nr_cpus) == 0) {
            LiveDevAddBypassFail(p->livedev, 1, AF_INET);
            SCFree(keys[0]);
            return 0;
        }
        keys[1]= SCCalloc(1, sizeof(struct flowv4_keys));
        if (keys[1] == NULL) {
            EBPFDeleteKey(p->afp_v.v4_map_fd, keys[0]);
            LiveDevAddBypassFail(p->livedev, 1, AF_INET);
            SCFree(keys[0]);
            return 0;
        }
        keys[1]->src = p->dst.addr_data32[0];
        keys[1]->dst = p->src.addr_data32[0];
        keys[1]->port16[0] = htons(p->dp);
        keys[1]->port16[1] = htons(p->sp);
        keys[1]->vlan0 = p->vlan_id[0];
        keys[1]->vlan1 = p->vlan_id[1];
        keys[1]->ip_proto = keys[0]->ip_proto;
        if (AFPInsertHalfFlow(p->afp_v.v4_map_fd, keys[1],
                              p->afp_v.nr_cpus) == 0) {
            EBPFDeleteKey(p->afp_v.v4_map_fd, keys[0]);
            LiveDevAddBypassFail(p->livedev, 1, AF_INET);
            SCFree(keys[0]);
            SCFree(keys[1]);
            return 0;
        }
        return AFPSetFlowStorage(p, p->afp_v.v4_map_fd, keys[0], keys[1], AF_INET);
    }
    /* For IPv6 case we don't handle extended header in eBPF */
    if (PKT_IS_IPV6(p) &&
        ((IPV6_GET_NH(p) == IPPROTO_TCP) || (IPV6_GET_NH(p) == IPPROTO_UDP))) {
        SCLogDebug("add an IPv6");
        if (p->afp_v.v6_map_fd == -1) {
            return 0;
        }
        int i;
        struct flowv6_keys *keys[2];
        keys[0] = SCCalloc(1, sizeof(struct flowv6_keys));
        if (keys[0] == NULL) {
            return 0;
        }

        for (i = 0; i < 4; i++) {
            keys[0]->src[i] = GET_IPV6_SRC_ADDR(p)[i];
            keys[0]->dst[i] = GET_IPV6_DST_ADDR(p)[i];
        }
        keys[0]->port16[0] = htons(GET_TCP_SRC_PORT(p));
        keys[0]->port16[1] = htons(GET_TCP_DST_PORT(p));
        keys[0]->vlan0 = p->vlan_id[0];
        keys[0]->vlan1 = p->vlan_id[1];
        if (IPV6_GET_NH(p) == IPPROTO_TCP) {
            keys[0]->ip_proto = 1;
        } else {
            keys[0]->ip_proto = 0;
        }
        if (AFPInsertHalfFlow(p->afp_v.v6_map_fd, keys[0],
                              p->afp_v.nr_cpus) == 0) {
            LiveDevAddBypassFail(p->livedev, 1, AF_INET6);
            SCFree(keys[0]);
            return 0;
        }
        keys[1]= SCCalloc(1, sizeof(struct flowv6_keys));
        if (keys[1] == NULL) {
            EBPFDeleteKey(p->afp_v.v6_map_fd, keys[0]);
            LiveDevAddBypassFail(p->livedev, 1, AF_INET6);
            SCFree(keys[0]);
            return 0;
        }
        for (i = 0; i < 4; i++) {
            keys[1]->src[i] = GET_IPV6_DST_ADDR(p)[i];
            keys[1]->dst[i] = GET_IPV6_SRC_ADDR(p)[i];
        }
        keys[1]->port16[0] = htons(GET_TCP_DST_PORT(p));
        keys[1]->port16[1] = htons(GET_TCP_SRC_PORT(p));
        keys[1]->vlan0 = p->vlan_id[0];
        keys[1]->vlan1 = p->vlan_id[1];
        keys[1]->ip_proto = keys[0]->ip_proto;
        if (AFPInsertHalfFlow(p->afp_v.v6_map_fd, keys[1],
                              p->afp_v.nr_cpus) == 0) {
            EBPFDeleteKey(p->afp_v.v6_map_fd, keys[0]);
            LiveDevAddBypassFail(p->livedev, 1, AF_INET6);
            SCFree(keys[0]);
            SCFree(keys[1]);
            return 0;
        }
        return AFPSetFlowStorage(p, p->afp_v.v6_map_fd, keys[0], keys[1], AF_INET6);
    }
#endif
    return 0;
}


bool g_flowv4_ok = true;
bool g_flowv6_ok = true;

/**
 * \brief Init function for ReceiveAFP.
 *
 * \param tv pointer to ThreadVars
 * \param initdata pointer to the interface passed from the user
 * \param data pointer gets populated with AFPThreadVars
 *
 * \todo Create a general AFP setup function.
 */
TmEcode ReceiveAFPThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    SCEnter();
    AFPIfaceConfig *afpconfig = (AFPIfaceConfig *)initdata;

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
    ptv->block_size = afpconfig->block_size;
    ptv->block_timeout = afpconfig->block_timeout;

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
    ptv->ebpf_lb_fd = afpconfig->ebpf_lb_fd;
    ptv->ebpf_filter_fd = afpconfig->ebpf_filter_fd;
    ptv->xdp_mode = afpconfig->xdp_mode;
#ifdef HAVE_PACKET_EBPF
    ptv->ebpf_t_config.cpus_count = UtilCpuGetNumProcessorsConfigured();

    if (ptv->flags & (AFP_BYPASS|AFP_XDPBYPASS)) {
        ptv->v4_map_fd = EBPFGetMapFDByName(ptv->iface, "flow_table_v4");
        if (ptv->v4_map_fd == -1) {
            if (g_flowv4_ok == false) {
                SCLogError(SC_ERR_INVALID_VALUE, "Can't find eBPF map fd for '%s'",
                           "flow_table_v4");
                g_flowv4_ok = true;
            }
        }
        ptv->v6_map_fd = EBPFGetMapFDByName(ptv->iface, "flow_table_v6");
        if (ptv->v6_map_fd  == -1) {
            if (g_flowv6_ok) {
                SCLogError(SC_ERR_INVALID_VALUE, "Can't find eBPF map fd for '%s'",
                           "flow_table_v6");
                g_flowv6_ok = false;
            }
        }
    }
    ptv->ebpf_t_config = afpconfig->ebpf_t_config;
#endif

#ifdef PACKET_STATISTICS
    ptv->capture_kernel_packets = StatsRegisterCounter("capture.kernel_packets",
            ptv->tv);
    ptv->capture_kernel_drops = StatsRegisterCounter("capture.kernel_drops",
            ptv->tv);
    ptv->capture_errors = StatsRegisterCounter("capture.errors",
            ptv->tv);
#endif

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
        ptv->flags |= AFP_VLAN_DISABLED;
    }

    /* If kernel is older than 3.0, VLAN is not stripped so we don't
     * get the info from packet extended header but we will use a standard
     * parsing of packet data (See Linux commit bcc6d47903612c3861201cc3a866fb604f26b8b2) */
    if (! SCKernelVersionIsAtLeast(3, 0)) {
        ptv->flags |= AFP_VLAN_DISABLED;
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
    SCLogPerf("(%s) Kernel: Packets %" PRIu64 ", dropped %" PRIu64 "",
            tv->name,
            StatsGetLocalCounterValue(tv, ptv->capture_kernel_packets),
            StatsGetLocalCounterValue(tv, ptv->capture_kernel_drops));
#endif
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

#ifdef HAVE_PACKET_XDP
    if ((ptv->ebpf_t_config.flags & EBPF_XDP_CODE) &&
        (!(ptv->ebpf_t_config.flags & EBPF_PINNED_MAPS))) {
        EBPFSetupXDP(ptv->iface, -1, ptv->xdp_mode);
    }
#endif
    if (ptv->data != NULL) {
        SCFree(ptv->data);
        ptv->data = NULL;
    }
    ptv->datalen = 0;

    ptv->bpf_filter = NULL;
    if ((ptv->flags & AFP_TPACKET_V3) && ptv->ring.v3) {
        SCFree(ptv->ring.v3);
    } else {
        if (ptv->ring.v2)
            SCFree(ptv->ring.v2);
    }

    SCFree(ptv);
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
    switch (p->datalink) {
        case LINKTYPE_ETHERNET:
            DecodeEthernet(tv, dtv, p,GET_PKT_DATA(p), GET_PKT_LEN(p), pq);
            break;
        case LINKTYPE_LINUX_SLL:
            DecodeSll(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p), pq);
            break;
        case LINKTYPE_PPP:
            DecodePPP(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p), pq);
            break;
        case LINKTYPE_RAW:
        case LINKTYPE_GRE_OVER_IP:
            DecodeRaw(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p), pq);
            break;
        case LINKTYPE_NULL:
            DecodeNull(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p), pq);
            break;
        default:
            SCLogError(SC_ERR_DATALINK_UNIMPLEMENTED, "Error: datalink type %" PRId32 " not yet supported in module DecodeAFP", p->datalink);
            break;
    }

    PacketDecodeFinalize(tv, dtv, p);

    SCReturnInt(TM_ECODE_OK);
}

TmEcode DecodeAFPThreadInit(ThreadVars *tv, const void *initdata, void **data)
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
