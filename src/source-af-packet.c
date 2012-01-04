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

#ifdef HAVE_AF_PACKET
#include <sys/ioctl.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#endif

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

enum {
    AFP_READ_OK,
    AFP_READ_FAILURE,
    AFP_FAILURE,
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

    /* socket buffer size */
    int buffer_size;
    int promisc;
    ChecksumValidationMode checksum_mode;

    int cluster_id;
    int cluster_type;

    int threads;

} AFPThreadVars;

TmEcode ReceiveAFP(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode ReceiveAFPThreadInit(ThreadVars *, void *, void **);
void ReceiveAFPThreadExitStats(ThreadVars *, void *);
TmEcode ReceiveAFPThreadDeinit(ThreadVars *, void *);
TmEcode ReceiveAFPLoop(ThreadVars *tv, void *data, void *slot);

TmEcode DecodeAFPThreadInit(ThreadVars *, void *, void **);
TmEcode DecodeAFP(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);

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
}

static int AFPCreateSocket(AFPThreadVars *ptv, char *devname, int verbose);


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
    SC_ATOMIC_ADD(ptv->livedev->pkts, 1);
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
        /* List is NULL if we don't have activated auxiliary data */
        for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
            struct tpacket_auxdata *aux;

            if (cmsg->cmsg_len < CMSG_LEN(sizeof(struct tpacket_auxdata)) ||
                    cmsg->cmsg_level != SOL_PACKET ||
                    cmsg->cmsg_type != PACKET_AUXDATA)
                continue;

            aux = (struct tpacket_auxdata *)CMSG_DATA(cmsg);

            if (aux->tp_status & TP_STATUS_CSUMNOTREADY) {
                p->flags |= PKT_IGNORE_CHECKSUM;
            }
            break;
        }
    }

    if (TmThreadsSlotProcessPkt(ptv->tv, ptv->slot, p) != TM_ECODE_OK) {
        TmqhOutputPacketpool(ptv->tv, p);
        SCReturnInt(AFP_FAILURE);
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
            /* AFPRead will call TmThreadsSlotProcessPkt on read packets */
            r = AFPRead(ptv);
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

static int AFPCreateSocket(AFPThreadVars *ptv, char *devname, int verbose)
{
    int r;
    struct packet_mreq sock_params;
    struct sockaddr_ll bind_address;
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

    ptv->afp_state = AFP_STATE_UP;
    return 0;
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
        SCReturnInt(TM_ECODE_FAILED);
    }

    ptv->buffer_size = afpconfig->buffer_size;

    ptv->promisc = afpconfig->promisc;
    ptv->checksum_mode = afpconfig->checksum_mode;

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

    r = AFPCreateSocket(ptv, ptv->iface, 1);
    if (r < 0) {
        SCLogError(SC_ERR_AFP_CREATE, "Couldn't init AF_PACKET socket");
        SCFree(ptv);
        afpconfig->DerefFunc(afpconfig);
        SCReturnInt(TM_ECODE_FAILED);
    }

    ptv->datalink = AFPGetDevLinktype(ptv->socket, ptv->iface);
    switch (ptv->datalink) {
        case ARPHRD_PPP:
        case ARPHRD_ATM:
            ptv->cooked = 1;
    }

#define T_DATA_SIZE 70000
    ptv->data = SCMalloc(T_DATA_SIZE);
    if (ptv->data == NULL) {
        afpconfig->DerefFunc(afpconfig);
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
    struct tpacket_stats kstats;
    socklen_t len = sizeof (struct tpacket_stats);
#endif

#ifdef PACKET_STATISTICS
    if (getsockopt(ptv->socket, SOL_PACKET, PACKET_STATISTICS,
                &kstats, &len) > -1) {
        SCLogInfo("(%s) Kernel: Packets %" PRIu32 ", dropped %" PRIu32 "",
                tv->name,
                kstats.tp_packets, kstats.tp_drops);
    }
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
