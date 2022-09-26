/* Copyright (C) 2011-2021 Open Information Security Foundation
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
#include "suricata.h"
#include "packet.h"
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
#include "util-datalink.h"
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
#include "util-validate.h"
#include "action-globals.h"

#ifdef HAVE_AF_PACKET

#if HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#if HAVE_LINUX_SOCKIOS_H
#include <linux/sockios.h>
#endif

#ifdef HAVE_PACKET_EBPF
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

/* kernel flags defined for RX ring tp_status */
#ifndef TP_STATUS_KERNEL
#define TP_STATUS_KERNEL 0
#endif
#ifndef TP_STATUS_USER
#define TP_STATUS_USER BIT_U32(0)
#endif
#ifndef TP_STATUS_COPY
#define TP_STATUS_COPY BIT_U32(1)
#endif
#ifndef TP_STATUS_LOSING
#define TP_STATUS_LOSING BIT_U32(2)
#endif
#ifndef TP_STATUS_CSUMNOTREADY
#define TP_STATUS_CSUMNOTREADY BIT_U32(3)
#endif
#ifndef TP_STATUS_VLAN_VALID
#define TP_STATUS_VLAN_VALID BIT_U32(4)
#endif
#ifndef TP_STATUS_BLK_TMO
#define TP_STATUS_BLK_TMO BIT_U32(5)
#endif
#ifndef TP_STATUS_VLAN_TPID_VALID
#define TP_STATUS_VLAN_TPID_VALID BIT_U32(6)
#endif
#ifndef TP_STATUS_CSUM_VALID
#define TP_STATUS_CSUM_VALID BIT_U32(7)
#endif

#ifndef TP_STATUS_TS_SOFTWARE
#define TP_STATUS_TS_SOFTWARE BIT_U32(29)
#endif
#ifndef TP_STATUS_TS_SYS_HARDWARE
#define TP_STATUS_TS_SYS_HARDWARE BIT_U32(30) /* kernel comment says: "deprecated, never set" */
#endif
#ifndef TP_STATUS_TS_RAW_HARDWARE
#define TP_STATUS_TS_RAW_HARDWARE BIT_U32(31)
#endif

#ifndef TP_STATUS_USER_BUSY
/* HACK special setting in the tp_status field for frames we are
 * still working on. This can happen in autofp mode where the
 * capture thread goes around the ring and finds a frame that still
 * hasn't been released by a worker thread.
 *
 * We use bits 29, 30, 31. 29 and 31 are software and hardware
 * timestamps. 30 should not be set by the kernel at all. Combined
 * they should never be set on the rx-ring together.
 *
 * The excessive casting is for handling the fact that the kernel
 * defines almost all of these as int flags, not unsigned ints. */
#define TP_STATUS_USER_BUSY                                                                        \
    (uint32_t)((uint32_t)TP_STATUS_TS_SOFTWARE | (uint32_t)TP_STATUS_TS_SYS_HARDWARE |             \
               (uint32_t)TP_STATUS_TS_RAW_HARDWARE)
#endif
#define FRAME_BUSY(tp_status)                                                                      \
    (((uint32_t)(tp_status) & (uint32_t)TP_STATUS_USER_BUSY) == (uint32_t)TP_STATUS_USER_BUSY)

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

#ifdef HAVE_PACKET_EBPF
static int AFPBypassCallback(Packet *p);
static int AFPXDPBypassCallback(Packet *p);
#endif

#define MAX_MAPS 32
/**
 * \brief Structure to hold thread specific variables.
 */
typedef struct AFPThreadVars_
{
    union AFPRing {
        union thdr **v2;
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
    uint16_t afpacket_spin;
    uint16_t capture_afp_poll;
    uint16_t capture_afp_poll_signal;
    uint16_t capture_afp_poll_timeout;
    uint16_t capture_afp_poll_data;
    uint16_t capture_afp_poll_err;
    uint16_t capture_afp_send_err;

    uint64_t send_errors_logged; /**< snapshot of send errors logged. */

    /* handle state */
    uint8_t afp_state;
    uint8_t copy_mode;
    unsigned int flags;

    /* IPS peer */
    AFPPeer *mpeer;

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

    int promisc;

    int down_count;

    uint16_t cluster_id;
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

#ifdef HAVE_PACKET_EBPF
    uint8_t xdp_mode;
    int ebpf_lb_fd;
    int ebpf_filter_fd;
    struct ebpf_timeout_config ebpf_t_config;
#endif

} AFPThreadVars;

static TmEcode ReceiveAFPThreadInit(ThreadVars *, const void *, void **);
static void ReceiveAFPThreadExitStats(ThreadVars *, void *);
static TmEcode ReceiveAFPThreadDeinit(ThreadVars *, void *);
static TmEcode ReceiveAFPLoop(ThreadVars *tv, void *data, void *slot);

static TmEcode DecodeAFPThreadInit(ThreadVars *, const void *, void **);
static TmEcode DecodeAFPThreadDeinit(ThreadVars *tv, void *data);
static TmEcode DecodeAFP(ThreadVars *, Packet *, void *);

static TmEcode AFPSetBPFFilter(AFPThreadVars *ptv);
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

    if ((SC_ATOMIC_ADD(peerslist.reached, 1) + 1) == peerslist.turn) {
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

        const uint64_t value = SC_ATOMIC_GET(ptv->mpeer->send_errors);
        if (value > ptv->send_errors_logged) {
            StatsAddUI64(ptv->tv, ptv->capture_afp_send_err, value - ptv->send_errors_logged);
            ptv->send_errors_logged = value;
        }
    }
#endif
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
static void AFPWritePacket(Packet *p, int version)
{
    struct sockaddr_ll socket_address;
    int socket;

    if (p->afp_v.copy_mode == AFP_COPY_MODE_IPS) {
        if (PacketCheckAction(p, ACTION_DROP)) {
            return;
        }
    }

    if (p->ethh == NULL) {
        SCLogWarning(SC_ERR_INVALID_VALUE, "Should have an Ethernet header");
        return;
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

    if (sendto(socket, GET_PKT_DATA(p), GET_PKT_LEN(p), 0, (struct sockaddr *)&socket_address,
                sizeof(struct sockaddr_ll)) < 0) {
        if (SC_ATOMIC_ADD(p->afp_v.peer->send_errors, 1) == 0) {
            SCLogWarning(SC_ERR_SOCKET, "sending packet failed on socket %d: %s", socket,
                    strerror(errno));
        }
    }
    if (p->afp_v.peer->flags & AFP_SOCK_PROTECT)
        SCMutexUnlock(&p->afp_v.peer->sock_protect);
}

static void AFPReleaseDataFromRing(Packet *p)
{
    DEBUG_VALIDATE_BUG_ON(PKT_IS_PSEUDOPKT(p));

    /* Need to be in copy mode and need to detect early release
       where Ethernet header could not be set (and pseudo packet) */
    if (p->afp_v.copy_mode != AFP_COPY_MODE_NONE) {
        AFPWritePacket(p, TPACKET_V2);
    }

    BUG_ON(p->afp_v.relptr == NULL);

    union thdr h;
    h.raw = p->afp_v.relptr;
    h.h2->tp_status = TP_STATUS_KERNEL;

    (void)AFPDerefSocket(p->afp_v.mpeer);

    AFPV_CLEANUP(&p->afp_v);
}

#ifdef HAVE_TPACKET_V3
static void AFPReleasePacketV3(Packet *p)
{
    DEBUG_VALIDATE_BUG_ON(PKT_IS_PSEUDOPKT(p));

    /* Need to be in copy mode and need to detect early release
       where Ethernet header could not be set (and pseudo packet) */
    if (p->afp_v.copy_mode != AFP_COPY_MODE_NONE) {
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

/** \internal
 *  \brief recoverable error - release packet and
 *         return AFP_SURI_FAILURE
 */
static inline int AFPSuriFailure(AFPThreadVars *ptv, union thdr h)
{
    h.h2->tp_status = TP_STATUS_KERNEL;
    if (++ptv->frame_offset >= ptv->req.v2.tp_frame_nr) {
        ptv->frame_offset = 0;
    }
    SCReturnInt(AFP_SURI_FAILURE);
}

static inline void AFPReadApplyBypass(const AFPThreadVars *ptv, Packet *p)
{
#ifdef HAVE_PACKET_EBPF
    if (ptv->flags & AFP_BYPASS) {
        p->BypassPacketsFlow = AFPBypassCallback;
        p->afp_v.v4_map_fd = ptv->v4_map_fd;
        p->afp_v.v6_map_fd = ptv->v6_map_fd;
        p->afp_v.nr_cpus = ptv->ebpf_t_config.cpus_count;
    }
    if (ptv->flags & AFP_XDPBYPASS) {
        p->BypassPacketsFlow = AFPXDPBypassCallback;
        p->afp_v.v4_map_fd = ptv->v4_map_fd;
        p->afp_v.v6_map_fd = ptv->v6_map_fd;
        p->afp_v.nr_cpus = ptv->ebpf_t_config.cpus_count;
    }
#endif
}

/** \internal
 *  \brief setup packet for AFPReadFromRing
 */
static void AFPReadFromRingSetupPacket(
        AFPThreadVars *ptv, union thdr h, const unsigned int tp_status, Packet *p)
{
    PKT_SET_SRC(p, PKT_SRC_WIRE);

    /* flag the packet as TP_STATUS_USER_BUSY, which is ignore by the kernel, but
     * acts as an indicator that we've reached a frame that is not yet released by
     * us in autofp mode. It will be cleared when the frame gets released to the kernel. */
    h.h2->tp_status |= TP_STATUS_USER_BUSY;
    p->livedev = ptv->livedev;
    p->datalink = ptv->datalink;
    ptv->pkts++;

    AFPReadApplyBypass(ptv, p);

    if (h.h2->tp_len > h.h2->tp_snaplen) {
        SCLogDebug("Packet length (%d) > snaplen (%d), truncating", h.h2->tp_len, h.h2->tp_snaplen);
    }

    /* get vlan id from header */
    if ((ptv->flags & AFP_VLAN_IN_HEADER) &&
            (tp_status & TP_STATUS_VLAN_VALID || h.h2->tp_vlan_tci)) {
        p->vlan_id[0] = h.h2->tp_vlan_tci & 0x0fff;
        p->vlan_idx = 1;
        p->afp_v.vlan_tci = h.h2->tp_vlan_tci;
    }

    (void)PacketSetData(p, (unsigned char *)h.raw + h.h2->tp_mac, h.h2->tp_snaplen);

    p->ReleasePacket = AFPReleasePacket;
    p->afp_v.relptr = h.raw;
    if (ptv->flags & AFP_NEED_PEER) {
        p->afp_v.mpeer = ptv->mpeer;
        AFPRefSocket(ptv->mpeer);
    } else {
        p->afp_v.mpeer = NULL;
    }
    p->afp_v.copy_mode = ptv->copy_mode;
    p->afp_v.peer = (p->afp_v.copy_mode == AFP_COPY_MODE_NONE) ? NULL : ptv->mpeer->peer;

    /* Timestamp */
    p->ts.tv_sec = h.h2->tp_sec;
    p->ts.tv_usec = h.h2->tp_nsec / 1000;
    SCLogDebug("pktlen: %" PRIu32 " (pkt %p, pkt data %p)", GET_PKT_LEN(p), p, GET_PKT_DATA(p));

    /* We only check for checksum disable */
    if (ptv->checksum_mode == CHECKSUM_VALIDATION_DISABLE) {
        p->flags |= PKT_IGNORE_CHECKSUM;
    } else if (ptv->checksum_mode == CHECKSUM_VALIDATION_AUTO) {
        if (ChecksumAutoModeCheck(ptv->pkts, SC_ATOMIC_GET(ptv->livedev->pkts),
                    SC_ATOMIC_GET(ptv->livedev->invalid_checksums))) {
            ptv->checksum_mode = CHECKSUM_VALIDATION_DISABLE;
            p->flags |= PKT_IGNORE_CHECKSUM;
        }
    } else {
        if (tp_status & TP_STATUS_CSUMNOTREADY) {
            p->flags |= PKT_IGNORE_CHECKSUM;
        }
    }
}

static inline int AFPReadFromRingWaitForPacket(AFPThreadVars *ptv)
{
    union thdr h;
    struct timeval start_time;
    gettimeofday(&start_time, NULL);
    uint64_t busy_loop_iter = 0;

    /* busy wait loop until we have packets available */
    while (1) {
        if (unlikely(suricata_ctl_flags != 0)) {
            break;
        }
        h.raw = (((union thdr **)ptv->ring.v2)[ptv->frame_offset]);
        if (unlikely(h.raw == NULL)) {
            return AFP_READ_FAILURE;
        }
        const unsigned int tp_status = h.h2->tp_status;
        if (tp_status == TP_STATUS_KERNEL) {
            busy_loop_iter++;

            struct timeval cur_time;
            memset(&cur_time, 0, sizeof(cur_time));
            uint64_t milliseconds =
                    ((cur_time.tv_sec - start_time.tv_sec) * 1000) +
                    (((1000000 + cur_time.tv_usec - start_time.tv_usec) / 1000) - 1000);
            if (milliseconds > 1000) {
                break;
            }
            continue;
        }
        break;
    }
    if (busy_loop_iter) {
        StatsAddUI64(ptv->tv, ptv->afpacket_spin, busy_loop_iter);
    }
    return AFP_READ_OK;
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
    union thdr h;
    bool emergency_flush = false;
    const unsigned int start_pos = ptv->frame_offset;

    /* poll() told us there are frames, so lets wait for at least
     * one frame to become available. */
    if (AFPReadFromRingWaitForPacket(ptv) != AFP_READ_OK)
        return AFP_READ_FAILURE;

    /* process the frames in the ring */
    while (1) {
        if (unlikely(suricata_ctl_flags != 0)) {
            break;
        }
        h.raw = (((union thdr **)ptv->ring.v2)[ptv->frame_offset]);
        if (unlikely(h.raw == NULL)) {
            return AFP_READ_FAILURE;
        }
        const unsigned int tp_status = h.h2->tp_status;
        /* if we find a kernel frame we are done */
        if (unlikely(tp_status == TP_STATUS_KERNEL)) {
            break;
        }
        /* if in autofp mode the frame is still busy, return to poll */
        if (unlikely(FRAME_BUSY(tp_status))) {
            break;
        }
        emergency_flush |= ((tp_status & TP_STATUS_LOSING) != 0);

        if ((ptv->flags & AFP_EMERGENCY_MODE) && emergency_flush) {
            h.h2->tp_status = TP_STATUS_KERNEL;
            goto next_frame;
        }

        Packet *p = PacketGetFromQueueOrAlloc();
        if (p == NULL) {
            return AFPSuriFailure(ptv, h);
        }
        AFPReadFromRingSetupPacket(ptv, h, tp_status, p);

        if (TmThreadsSlotProcessPkt(ptv->tv, ptv->slot, p) != TM_ECODE_OK) {
            return AFPSuriFailure(ptv, h);
        }
next_frame:
        if (++ptv->frame_offset >= ptv->req.v2.tp_frame_nr) {
            ptv->frame_offset = 0;
            /* Get out of loop to be sure we will reach maintenance tasks */
            if (ptv->frame_offset == start_pos)
                break;
        }
    }
    if (emergency_flush) {
        AFPDumpCounters(ptv);
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

    AFPReadApplyBypass(ptv, p);

    ptv->pkts++;
    p->livedev = ptv->livedev;
    p->datalink = ptv->datalink;

    if ((ptv->flags & AFP_VLAN_IN_HEADER) &&
            (ppd->tp_status & TP_STATUS_VLAN_VALID || ppd->hv1.tp_vlan_tci)) {
        p->vlan_id[0] = ppd->hv1.tp_vlan_tci & 0x0fff;
        p->vlan_idx = 1;
        p->afp_v.vlan_tci = (uint16_t)ppd->hv1.tp_vlan_tci;
    }

    (void)PacketSetData(p, (unsigned char *)ppd + ppd->tp_mac, ppd->tp_snaplen);

    p->ReleasePacket = AFPReleasePacketV3;
    p->afp_v.relptr = NULL;
    p->afp_v.mpeer = NULL;
    p->afp_v.copy_mode = ptv->copy_mode;
    p->afp_v.peer = (p->afp_v.copy_mode == AFP_COPY_MODE_NONE) ? NULL : ptv->mpeer->peer;

    /* Timestamp */
    p->ts.tv_sec = ppd->tp_sec;
    p->ts.tv_usec = ppd->tp_nsec/1000;
    SCLogDebug("pktlen: %" PRIu32 " (pkt %p, pkt data %p)",
            GET_PKT_LEN(p), p, GET_PKT_DATA(p));

    /* We only check for checksum disable */
    if (ptv->checksum_mode == CHECKSUM_VALIDATION_DISABLE) {
        p->flags |= PKT_IGNORE_CHECKSUM;
    } else if (ptv->checksum_mode == CHECKSUM_VALIDATION_AUTO) {
        if (ChecksumAutoModeCheck(ptv->pkts,
                    SC_ATOMIC_GET(ptv->livedev->pkts),
                    SC_ATOMIC_GET(ptv->livedev->invalid_checksums))) {
            ptv->checksum_mode = CHECKSUM_VALIDATION_DISABLE;
            p->flags |= PKT_IGNORE_CHECKSUM;
        }
    } else {
        if (ppd->tp_status & TP_STATUS_CSUMNOTREADY) {
            p->flags |= PKT_IGNORE_CHECKSUM;
        }
    }

    if (TmThreadsSlotProcessPkt(ptv->tv, ptv->slot, p) != TM_ECODE_OK) {
        SCReturnInt(AFP_SURI_FAILURE);
    }

    SCReturnInt(AFP_READ_OK);
}

static inline int AFPWalkBlock(AFPThreadVars *ptv, struct tpacket_block_desc *pbd)
{
    const int num_pkts = pbd->hdr.bh1.num_pkts;
    uint8_t *ppd = (uint8_t *)pbd + pbd->hdr.bh1.offset_to_first_pkt;

    for (int i = 0; i < num_pkts; ++i) {
        int ret = AFPParsePacketV3(ptv, pbd, (struct tpacket3_hdr *)ppd);
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
    /* Loop till we have packets available */
    while (1) {
        if (unlikely(suricata_ctl_flags != 0)) {
            SCLogInfo("Exiting AFP V3 read loop");
            break;
        }

        struct tpacket_block_desc *pbd =
                (struct tpacket_block_desc *)ptv->ring.v3[ptv->frame_offset].iov_base;

        /* block is not ready to be read */
        if ((pbd->hdr.bh1.block_status & TP_STATUS_USER) == 0) {
            SCReturnInt(AFP_READ_OK);
        }

        int ret = AFPWalkBlock(ptv, pbd);
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

    if (SC_ATOMIC_SUB(peer->sock_usage, 1) == 1) {
        return 0;
    }
    return 1;
}

static void AFPCloseSocket(AFPThreadVars *ptv)
{
    if (ptv->mpeer != NULL)
        BUG_ON(SC_ATOMIC_GET(ptv->mpeer->sock_usage) != 0);

    if (ptv->flags & AFP_TPACKET_V3) {
#ifdef HAVE_TPACKET_V3
        if (ptv->ring.v3) {
            SCFree(ptv->ring.v3);
            ptv->ring.v3 = NULL;
        }
#endif
    } else {
        if (ptv->ring.v2) {
            /* only used in reading phase, we can free it */
            SCFree(ptv->ring.v2);
            ptv->ring.v2 = NULL;
        }
    }
    if (ptv->socket != -1) {
        SCLogDebug("Cleaning socket connected to '%s'", ptv->iface);
        munmap(ptv->ring_buf, ptv->ring_buflen);
        close(ptv->socket);
        ptv->socket = -1;
    }
}

static void AFPSwitchState(AFPThreadVars *ptv, uint8_t state)
{
    ptv->afp_state = state;
    ptv->down_count = 0;

    if (state == AFP_STATE_DOWN) {
        /* cleanup is done on thread cleanup or try reopen
         * as there may still be packets in autofp that
         * are referencing us */
        (void)SC_ATOMIC_SUB(ptv->mpeer->sock_usage, 1);
    }
    if (state == AFP_STATE_UP) {
        AFPPeerUpdate(ptv);
        (void)SC_ATOMIC_SET(ptv->mpeer->sock_usage, 1);
    }
}

static int AFPReadAndDiscardFromRing(AFPThreadVars *ptv, struct timeval *synctv,
                                     uint64_t *discarded_pkts)
{
    if (unlikely(suricata_ctl_flags != 0)) {
        return 1;
    }

#ifdef HAVE_TPACKET_V3
    if (ptv->flags & AFP_TPACKET_V3) {
        int ret = 0;
        struct tpacket_block_desc *pbd =
                (struct tpacket_block_desc *)ptv->ring.v3[ptv->frame_offset].iov_base;
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
        union thdr h;
        h.raw = (((union thdr **)ptv->ring.v2)[ptv->frame_offset]);
        if (h.raw == NULL) {
            return -1;
        }
        if (h.h2->tp_status == TP_STATUS_KERNEL)
            return 0;

        if (((time_t)h.h2->tp_sec > synctv->tv_sec) ||
                ((time_t)h.h2->tp_sec == synctv->tv_sec &&
                 (suseconds_t) (h.h2->tp_nsec / 1000) > synctv->tv_usec)) {
            return 1;
        }

        (*discarded_pkts)++;
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
            r = AFPReadAndDiscardFromRing(ptv, &synctv, discarded_pkts);
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

    /* ref cnt 0, we can close the old socket */
    AFPCloseSocket(ptv);

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

    if (ptv->flags & AFP_TPACKET_V3) {
        AFPReadFunc = AFPReadFromRingV3;
    } else {
        AFPReadFunc = AFPReadFromRing;
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

    // Indicate that the thread is actually running its application level code (i.e., it can poll
    // packets)
    TmThreadsSetFlag(tv, THV_RUNNING);

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

        StatsIncr(ptv->tv, ptv->capture_afp_poll);

        r = poll(&fds, 1, POLL_TIMEOUT);

        if (suricata_ctl_flags != 0) {
            break;
        }

        if (r > 0 &&
                (fds.revents & (POLLHUP|POLLRDHUP|POLLERR|POLLNVAL))) {
            StatsIncr(ptv->tv, ptv->capture_afp_poll_signal);
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
            StatsIncr(ptv->tv, ptv->capture_afp_poll_data);
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
            StatsIncr(ptv->tv, ptv->capture_afp_poll_timeout);
            /* Trigger one dump of stats every second */
            current_time = time(NULL);
            if (current_time != last_dump) {
                AFPDumpCounters(ptv);
                last_dump = current_time;
            }
            /* poll timed out, lets see handle our timeout path */
            TmThreadsCaptureHandleTimeout(tv, NULL);

        } else if ((r < 0) && (errno != EINTR)) {
            StatsIncr(ptv->tv, ptv->capture_afp_poll_err);
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

    DatalinkSetGlobalType(ltype);

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

    /* Reserve head room for a VLAN header. One vlan is extracted from AFP header
     * so one VLAN header length is enough. */
    int reserve = VLAN_HEADER_LEN;
    if (setsockopt(ptv->socket, SOL_PACKET, PACKET_RESERVE, (void *)&reserve, sizeof(reserve)) <
            0) {
        SCLogError(
                SC_ERR_AFP_CREATE, "Can't activate reserve on packet socket: %s", strerror(errno));
        return AFP_FATAL_ERROR;
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
        ptv->ring.v2 = SCCalloc(ptv->req.v2.tp_frame_nr, sizeof(union thdr *));
        if (ptv->ring.v2 == NULL) {
            SCLogError(SC_ERR_MEM_ALLOC, "Unable to allocate frame buf");
            goto postmmap_err;
        }
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
int AFPIsFanoutSupported(uint16_t cluster_id)
{
#ifdef HAVE_PACKET_FANOUT
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0)
        return 0;

    uint32_t mode = PACKET_FANOUT_HASH | PACKET_FANOUT_FLAG_DEFRAG;
    uint32_t option = (mode << 16) | cluster_id;
    int r = setsockopt(fd, SOL_PACKET, PACKET_FANOUT,(void *)&option, sizeof(option));
    close(fd);

    if (r < 0) {
        SCLogError(SC_ERR_INVALID_VALUE, "fanout not supported by kernel: "
                "Kernel too old or cluster-id %d already in use.", cluster_id);
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
        uint32_t mode = ptv->cluster_type;
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

    ret = AFPSetupRing(ptv, devname);
    if (ret != 0)
        goto socket_err;

    SCLogDebug("Using interface '%s' via socket %d", (char *)devname, ptv->socket);

    ptv->datalink = AFPGetDevLinktype(ptv->socket, ptv->iface);

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

    if (filter.bf_len > USHRT_MAX) {
        return TM_ECODE_FAILED;
    }
    fcode.len = (unsigned short)filter.bf_len;
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
        if (fc->bypass_data != NULL) {
            // bypass already activated
            SCFree(key0);
            SCFree(key1);
            return 1;
        }
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
    return 0;
}

bool g_flowv4_ok = true;
bool g_flowv6_ok = true;

#endif /* HAVE_PACKET_EBPF */

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
#ifdef HAVE_PACKET_EBPF
    ptv->ebpf_lb_fd = afpconfig->ebpf_lb_fd;
    ptv->ebpf_filter_fd = afpconfig->ebpf_filter_fd;
    ptv->xdp_mode = afpconfig->xdp_mode;
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

    ptv->afpacket_spin = StatsRegisterAvgCounter("capture.afpacket.busy_loop_avg", ptv->tv);

    ptv->capture_afp_poll = StatsRegisterCounter("capture.afpacket.polls", ptv->tv);
    ptv->capture_afp_poll_signal = StatsRegisterCounter("capture.afpacket.poll_signal", ptv->tv);
    ptv->capture_afp_poll_timeout = StatsRegisterCounter("capture.afpacket.poll_timeout", ptv->tv);
    ptv->capture_afp_poll_data = StatsRegisterCounter("capture.afpacket.poll_data", ptv->tv);
    ptv->capture_afp_poll_err = StatsRegisterCounter("capture.afpacket.poll_errors", ptv->tv);
    ptv->capture_afp_send_err = StatsRegisterCounter("capture.afpacket.send_errors", ptv->tv);
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

    *data = (void *)ptv;

    afpconfig->DerefFunc(afpconfig);

    /* If kernel is older than 3.0, VLAN is not stripped so we don't
     * get the info from packet extended header but we will use a standard
     * parsing of packet data (See Linux commit bcc6d47903612c3861201cc3a866fb604f26b8b2) */
    if (SCKernelVersionIsAtLeast(3, 0)) {
        ptv->flags |= AFP_VLAN_IN_HEADER;
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

/** \internal
 *  \brief add a VLAN header into the raw data for inspection, logging
 *         and sending out in IPS mode
 *
 *  The kernel doesn't provide the first VLAN header the raw packet data,
 *  but instead feeds it to us through meta data. For logging and IPS
 *  we need to put it back into the raw data. Luckily there is some head
 *  room in the original data so its enough to move the ethernet header
 *  a bit to make space for the VLAN header.
 */
static void UpdateRawDataForVLANHdr(Packet *p)
{
    if (p->afp_v.vlan_tci != 0) {
        uint8_t *pstart = GET_PKT_DATA(p) - VLAN_HEADER_LEN;
        size_t plen = GET_PKT_LEN(p) + VLAN_HEADER_LEN;
        /* move ethernet addresses */
        memmove(pstart, GET_PKT_DATA(p), 2 * ETH_ALEN);
        /* write vlan info */
        *(uint16_t *)(pstart + 2 * ETH_ALEN) = htons(0x8100);
        *(uint16_t *)(pstart + 2 * ETH_ALEN + 2) = htons(p->afp_v.vlan_tci);

        /* update the packet raw data pointer to start at the new offset */
        (void)PacketSetData(p, pstart, plen);
        /* update ethernet header pointer to point to the new start of the data */
        p->ethh = (void *)pstart;
    }
}

/**
 * \brief This function passes off to link type decoders.
 *
 * DecodeAFP decodes packets from AF_PACKET and passes
 * them off to the proper link type decoder.
 *
 * \param t pointer to ThreadVars
 * \param p pointer to the current packet
 * \param data pointer that gets cast into AFPThreadVars for ptv
 */
TmEcode DecodeAFP(ThreadVars *tv, Packet *p, void *data)
{
    SCEnter();

    const bool afp_vlan_hdr = p->vlan_idx != 0;
    DecodeThreadVars *dtv = (DecodeThreadVars *)data;

    DEBUG_VALIDATE_BUG_ON(PKT_IS_PSEUDOPKT(p));

    /* update counters */
    DecodeUpdatePacketCounters(tv, dtv, p);

    /* call the decoder */
    DecodeLinkLayer(tv, dtv, p->datalink, p, GET_PKT_DATA(p), GET_PKT_LEN(p));
    /* post-decoding put vlan hdr back into the raw data) */
    if (afp_vlan_hdr) {
        StatsIncr(tv, dtv->counter_vlan);
        UpdateRawDataForVLANHdr(p);
    }

    PacketDecodeFinalize(tv, dtv, p);

    SCReturnInt(TM_ECODE_OK);
}

TmEcode DecodeAFPThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    SCEnter();
    DecodeThreadVars *dtv = DecodeThreadVarsAlloc(tv);
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
