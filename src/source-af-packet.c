/* Copyright (C) 2011 Open Information Security Foundation
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
 * \author Eric Leblond <eric@regit.org>
 *
 * AF_PACKET socket acquisition support
 *
 * Fanouts socket from David Miller:
 * we need to support the split of flow in different socket
 * option:
 *  - packet_fanout type
 *  - fanout ID ?? seems it could be useful
 *  - protocol is the IEEE 802.3 protocol number in network order (filtering
 *    is great)
 *  - runmode -> family of threads in parallel (acccount)
 *  - add a new ratio or threads number (overwritten by cpu_affinity)
 *  - add af_max_read_packets for batched reading
 *
 * architecture
 *  loop with read
 *  code needed for iface name to int mapping
 * socket opening
 *   socket call
 *   bind
 *   must switch to promiscous mode -> use PACKET_MR_PROMISC socket option
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
#include "tmqh-packetpool.h"
#include "source-af-packet.h"
#include "runmodes.h"

#ifdef HAVE_AF_PACKET
#include <sys/ioctl.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>

#include <pcap/pcap.h>
#include <pcap/bpf.h>
#include <linux/filter.h>
#endif

#include <sys/mman.h>

extern uint8_t suricata_ctl_flags;
extern int max_pending_packets;

#ifndef HAVE_AF_PACKET

TmEcode NoAFPSupportExit(ThreadVars *, void *, void **);

void TmModuleReceiveAFPRegister (void) {
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
void TmModuleDecodeAFPRegister (void) {
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

#define POLL_TIMEOUT 100

/** protect pfring_set_bpf_filter, as it is not thread safe */
static SCMutex afpacket_bpf_set_filter_lock = PTHREAD_MUTEX_INITIALIZER;

enum {
    AFP_READ_OK,
    AFP_READ_FAILURE,
    AFP_FAILURE,
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
    uint32_t pkts;
    uint64_t bytes;
    uint32_t errs;

    ThreadVars *tv;
    TmSlot *slot;

    uint8_t *data; /** Per function and thread data */
    int datalen; /** Length of per function and thread data */

    char iface[AFP_IFACE_NAME_LENGTH];
    LiveDevice *livedev;

    /* Filter */
    char *bpf_filter;

    /* socket buffer size */
    int buffer_size;
    int promisc;
    ChecksumValidationMode checksum_mode;

    int flags;
    uint16_t capture_kernel_packets;
    uint16_t capture_kernel_drops;

    int cluster_id;
    int cluster_type;

    int threads;

    struct tpacket_req req;
    unsigned int tp_hdrlen;
    unsigned int ring_buflen;
    char *ring_buf;
    char *frame_buf;
    unsigned int frame_offset;
} AFPThreadVars;

TmEcode ReceiveAFP(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode ReceiveAFPThreadInit(ThreadVars *, void *, void **);
void ReceiveAFPThreadExitStats(ThreadVars *, void *);
TmEcode ReceiveAFPThreadDeinit(ThreadVars *, void *);
TmEcode ReceiveAFPLoop(ThreadVars *tv, void *data, void *slot);

TmEcode DecodeAFPThreadInit(ThreadVars *, void *, void **);
TmEcode DecodeAFP(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);

TmEcode AFPSetBPFFilter(AFPThreadVars *ptv);

/**
 * \brief Registration Function for RecieveAFP.
 * \todo Unit tests are needed for this module.
 */
void TmModuleReceiveAFPRegister (void) {
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
 * \brief Registration Function for DecodeAFP.
 * \todo Unit tests are needed for this module.
 */
void TmModuleDecodeAFPRegister (void) {
    tmm_modules[TMM_DECODEAFP].name = "DecodeAFP";
    tmm_modules[TMM_DECODEAFP].ThreadInit = DecodeAFPThreadInit;
    tmm_modules[TMM_DECODEAFP].Func = DecodeAFP;
    tmm_modules[TMM_DECODEAFP].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODEAFP].ThreadDeinit = NULL;
    tmm_modules[TMM_DECODEAFP].RegisterTests = NULL;
    tmm_modules[TMM_DECODEAFP].cap_flags = 0;
    tmm_modules[TMM_DECODEAFP].flags = TM_FLAG_DECODE_TM;
}

static int AFPCreateSocket(AFPThreadVars *ptv, char *devname, int verbose);

static inline void AFPDumpCounters(AFPThreadVars *ptv, int forced)
{
    if (((ptv->pkts & 0xff) == 0) || forced) {
#ifdef PACKET_STATISTICS
        struct tpacket_stats kstats;
        socklen_t len = sizeof (struct tpacket_stats);
        if (getsockopt(ptv->socket, SOL_PACKET, PACKET_STATISTICS,
                    &kstats, &len) > -1) {
            SCLogDebug("(%s) Kernel: Packets %" PRIu32 ", dropped %" PRIu32 "",
                    ptv->tv->name,
                    kstats.tp_packets, kstats.tp_drops);
            SCPerfCounterAddUI64(ptv->capture_kernel_packets, ptv->tv->sc_perf_pca, kstats.tp_packets);
            SCPerfCounterAddUI64(ptv->capture_kernel_drops, ptv->tv->sc_perf_pca, kstats.tp_drops);
        }
#endif
    }
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

    /* get timestamp of packet via ioctl */
    if (ioctl(ptv->socket, SIOCGSTAMP, &p->ts) == -1) {
        SCLogWarning(SC_ERR_AFP_READ, "recvmsg failed with error code %" PRId32,
                errno);
        TmqhOutputPacketpool(ptv->tv, p);
        SCReturnInt(AFP_READ_FAILURE);
    }

    ptv->pkts++;
    ptv->bytes += caplen + offset;
    (void) SC_ATOMIC_ADD(ptv->livedev->pkts, 1);
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
    int read_pkts = 0;

    /* Loop till we have packets available */
    while (1) {
        /* Read packet from ring */
        h.raw = (((union thdr **)ptv->frame_buf)[ptv->frame_offset]);
        if (h.raw == NULL) {
            SCReturnInt(AFP_FAILURE);
        }
        if (h.h2->tp_status == TP_STATUS_KERNEL) {
            if (read_pkts == 0) {
               if (++ptv->frame_offset >= ptv->req.tp_frame_nr) {
                   ptv->frame_offset = 0;
               }
               continue;
            }
            SCReturnInt(AFP_READ_OK);
        }

        read_pkts++;

        p = PacketGetFromQueueOrAlloc();
        if (p == NULL) {
            SCReturnInt(AFP_FAILURE);
        }

        ptv->pkts++;
        ptv->bytes += h.h2->tp_len;
        (void) SC_ATOMIC_ADD(ptv->livedev->pkts, 1);
        p->livedev = ptv->livedev;

        /* add forged header */
        if (ptv->cooked) {
            SllHdr * hdrp = (SllHdr *)ptv->data;
            struct sockaddr_ll *from = (void *)h.raw + TPACKET_ALIGN(ptv->tp_hdrlen);
            /* XXX this is minimalist, but this seems enough */
            hdrp->sll_protocol = from->sll_protocol;
        }

        p->datalink = ptv->datalink;
        if (h.h2->tp_len > h.h2->tp_snaplen) {
            SCLogDebug("Packet length (%d) > snaplen (%d), truncating",
                    h.h2->tp_len, h.h2->tp_snaplen);
        }
        if (ptv->flags & AFP_ZERO_COPY) {
            if (PacketSetData(p, (unsigned char*)h.raw + h.h2->tp_mac, h.h2->tp_snaplen) == -1) {
                TmqhOutputPacketpool(ptv->tv, p);
                SCReturnInt(AFP_FAILURE);
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

        if (TmThreadsSlotProcessPkt(ptv->tv, ptv->slot, p) != TM_ECODE_OK) {
            h.h2->tp_status = TP_STATUS_KERNEL;
            if (++ptv->frame_offset >= ptv->req.tp_frame_nr) {
                ptv->frame_offset = 0;
            }
            TmqhOutputPacketpool(ptv->tv, p);
            SCReturnInt(AFP_FAILURE);
        }

        h.h2->tp_status = TP_STATUS_KERNEL;
        if (++ptv->frame_offset >= ptv->req.tp_frame_nr) {
            ptv->frame_offset = 0;
        }
    }

    SCReturnInt(AFP_READ_OK);
}



static int AFPTryReopen(AFPThreadVars *ptv)
{
    int afp_activate_r;

    ptv->afp_state = AFP_STATE_DOWN;

    afp_activate_r = AFPCreateSocket(ptv, ptv->iface, 0);
    if (afp_activate_r != 0) {
        return afp_activate_r;
    }

    SCLogInfo("Recovering interface listening");
    ptv->afp_state = AFP_STATE_UP;
    return 0;
}

/**
 *  \brief Main AF_PACKET reading Loop function
 */
TmEcode ReceiveAFPLoop(ThreadVars *tv, void *data, void *slot)
{
    uint16_t packet_q_len = 0;
    AFPThreadVars *ptv = (AFPThreadVars *)data;
    TmSlot *s = (TmSlot *)slot;
    ptv->slot = s->slot_next;
    struct pollfd fds;
    int r;

    SCEnter();

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

        if (r > 0 &&
                (fds.revents & (POLLHUP|POLLRDHUP|POLLERR|POLLNVAL))) {
            if (fds.revents & (POLLHUP | POLLRDHUP)) {
                close(ptv->socket);
                ptv->afp_state = AFP_STATE_DOWN;
                continue;
            } else if (fds.revents & POLLERR) {
                char c;
                /* Do a recv to get errno */
                if (recv(ptv->socket, &c, sizeof c, MSG_PEEK) != -1)
                    continue; /* what, no error? */
                SCLogError(SC_ERR_AFP_READ, "Error reading data from socket: (%d" PRIu32 ") %s",
                        errno, strerror(errno));
                close(ptv->socket);
                ptv->afp_state = AFP_STATE_DOWN;
                continue;
            } else if (fds.revents & POLLNVAL) {
                SCLogError(SC_ERR_AFP_READ, "Invalid polling request");
                close(ptv->socket);
                ptv->afp_state = AFP_STATE_DOWN;
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
                    SCLogError(SC_ERR_AFP_READ, "AFPRead error reading data from socket: (%d" PRIu32 ") %s",
                            errno, strerror(errno));
                    close(ptv->socket);
                    ptv->afp_state = AFP_STATE_DOWN;
                    continue;
                case AFP_FAILURE:
                    SCReturnInt(TM_ECODE_FAILED);
                    break;
                case AFP_READ_OK:
                    AFPDumpCounters(ptv, 0);
                    break;
            }
        } else if ((r < 0) && (errno != EINTR)) {
            SCLogError(SC_ERR_AFP_READ, "Error reading data from socket: (%d" PRIu32 ") %s",
                       errno, strerror(errno));
            close(ptv->socket);
            ptv->afp_state = AFP_STATE_DOWN;
            continue;
        }
        SCPerfSyncCountersIfSignalled(tv, 0);
    }

    SCReturnInt(TM_ECODE_OK);
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

    ptv->req.tp_frame_size = TPACKET_ALIGN(snaplen +TPACKET_ALIGN(TPACKET_ALIGN(tp_hdrlen) + sizeof(struct sockaddr_ll) + ETH_HLEN) - ETH_HLEN);
    ptv->req.tp_block_size = getpagesize() << order;
    int frames_per_block = ptv->req.tp_block_size / ptv->req.tp_frame_size;
    if (frames_per_block == 0) {
        SCLogInfo("frame size to big");
        return -1;
    }
    ptv->req.tp_frame_nr = max_pending_packets; /* Warrior mode */
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
    struct packet_mreq sock_params;
    struct sockaddr_ll bind_address;
    int order;
    unsigned int i;

    /* open socket */
    ptv->socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (ptv->socket == -1) {
        SCLogError(SC_ERR_AFP_CREATE, "Couldn't create a AF_PACKET socket, error %s", strerror(errno));
        return -1;
    }
    SCLogDebug("using interface %s", (char *)devname);
    /* bind socket */
    memset(&bind_address, 0, sizeof(bind_address));
    bind_address.sll_family = AF_PACKET;
    bind_address.sll_protocol = htons(ETH_P_ALL);
    bind_address.sll_ifindex = AFPGetIfnumByDev(ptv->socket, devname, verbose);
    if (bind_address.sll_ifindex == -1) {
        if (verbose)
            SCLogError(SC_ERR_AFP_CREATE, "Couldn't find iface %s", devname);
        return -1;
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
            return -1;
        }
        ptv->tp_hdrlen = val;

        val = TPACKET_V2;
        if (setsockopt(ptv->socket, SOL_PACKET, PACKET_VERSION, &val,
                    sizeof(val)) < 0) {
            SCLogError(SC_ERR_AFP_CREATE,
                       "Can't activate TPACKET_V2 on packet socket: %s",
                       strerror(errno));
            return -1;
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
                return -1;
            } else {
                break;
            }
        }

        if (order < 0) {
            SCLogError(SC_ERR_MEM_ALLOC,
                    "Unable to allocate RX Ring for iface %s (order 0 failed)",
                    devname);
            return -1;
        }

        /* Allocate the Ring */
        ptv->ring_buflen = ptv->req.tp_block_nr * ptv->req.tp_block_size;
        ptv->ring_buf = mmap(0, ptv->ring_buflen, PROT_READ|PROT_WRITE,
                MAP_SHARED, ptv->socket, 0);
        if (ptv->ring_buf == MAP_FAILED) {
            SCLogError(SC_ERR_MEM_ALLOC, "Unable to mmap");
            return -1;
        }
        /* allocate a ring for each frame header pointer*/
        ptv->frame_buf = SCMalloc(ptv->req.tp_frame_nr * sizeof (union thdr *));
        if (ptv->frame_buf == NULL) {
            SCLogError(SC_ERR_MEM_ALLOC, "Unable to allocate frame buf");
            return -1;
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
                        devname,
                        strerror(errno));
            }
        }
        close(ptv->socket);
        return -1;
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
                    devname,
                    strerror(errno));
            close(ptv->socket);
            return -1;
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
                    ptv->buffer_size,
                    devname,
                    strerror(errno));
            close(ptv->socket);
            return -1;
        }
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
            close(ptv->socket);
            return -1;
        }
    }
#endif

    ptv->datalink = AFPGetDevLinktype(ptv->socket, ptv->iface);
    switch (ptv->datalink) {
        case ARPHRD_PPP:
        case ARPHRD_ATM:
            ptv->cooked = 1;
    }

    TmEcode rc;
    rc = AFPSetBPFFilter(ptv);
    if (rc == TM_ECODE_FAILED) {
        SCLogError(SC_ERR_AFP_CREATE, "Set AF_PACKET bpf filter \"%s\" failed.", ptv->bpf_filter);
        return -1;
    }

    /* Init is ok */
    ptv->afp_state = AFP_STATE_UP;
    return 0;
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

    SCMutexUnlock(&afpacket_bpf_set_filter_lock);
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
TmEcode ReceiveAFPThreadInit(ThreadVars *tv, void *initdata, void **data) {
    SCEnter();
    int r;
    AFPIfaceConfig *afpconfig = initdata;

    if (initdata == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "initdata == NULL");
        SCReturnInt(TM_ECODE_FAILED);
    }

    AFPThreadVars *ptv = SCMalloc(sizeof(AFPThreadVars));
    if (ptv == NULL) {
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
    ptv->capture_kernel_packets = SCPerfTVRegisterCounter("capture.kernel_packets",
            ptv->tv,
            SC_PERF_TYPE_UINT64,
            "NULL");
    ptv->capture_kernel_drops = SCPerfTVRegisterCounter("capture.kernel_drops",
            ptv->tv,
            SC_PERF_TYPE_UINT64,
            "NULL");
#endif

    char *active_runmode = RunmodeGetActive();

    if (active_runmode && !strcmp("workers", active_runmode)) {
        ptv->flags |= AFP_ZERO_COPY;
        SCLogInfo("Enabling zero copy mode");
    }

    r = AFPCreateSocket(ptv, ptv->iface, 1);
    if (r < 0) {
        SCLogError(SC_ERR_AFP_CREATE, "Couldn't init AF_PACKET socket");
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
    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief This function prints stats to the screen at exit.
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into AFPThreadVars for ptv
 */
void ReceiveAFPThreadExitStats(ThreadVars *tv, void *data) {
    SCEnter();
    AFPThreadVars *ptv = (AFPThreadVars *)data;

#ifdef PACKET_STATISTICS
    AFPDumpCounters(ptv, 1);
    SCLogInfo("(%s) Kernel: Packets %" PRIu64 ", dropped %" PRIu64 "",
            tv->name,
            (uint64_t) SCPerfGetLocalCounterValue(ptv->capture_kernel_packets, tv->sc_perf_pca),
            (uint64_t) SCPerfGetLocalCounterValue(ptv->capture_kernel_drops, tv->sc_perf_pca));
#endif

    SCLogInfo("(%s) Packets %" PRIu32 ", bytes %" PRIu64 "", tv->name, ptv->pkts, ptv->bytes);
}

/**
 * \brief DeInit function closes af packet socket at exit.
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into AFPThreadVars for ptv
 */
TmEcode ReceiveAFPThreadDeinit(ThreadVars *tv, void *data) {
    AFPThreadVars *ptv = (AFPThreadVars *)data;

    if (ptv->data != NULL) {
        SCFree(ptv->data);
        ptv->data = NULL;
    }
    ptv->datalen = 0;

    ptv->bpf_filter = NULL;

    close(ptv->socket);
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
            SCLogError(SC_ERR_DATALINK_UNIMPLEMENTED, "Error: datalink type %" PRId32 " not yet supported in module DecodeAFP", p->datalink);
            break;
    }

    SCReturnInt(TM_ECODE_OK);
}

TmEcode DecodeAFPThreadInit(ThreadVars *tv, void *initdata, void **data)
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

#endif /* HAVE_AF_PACKET */
/* eof */
