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
    - packet_fanout type
    - fanout ID ?? seems it could be useful
    - protocol is the IEEE 802.3 protocol number in network order (filtering is great)
    - runmode -> family of threads in parallel (acccount)
    - add a new ratio or threads number (overwritten by cpu_affinity)
    - add af_max_read_packets for batched reading
 *
 * architecture
 *  loop with read
 *  code needed for iface name to int mapping
 * socket opening
 *   socket call
 *   bind
 *   must switch to promiscous mode -> use PACKET_MR_PROMISC socket option
 *
 * \todo watch other interface event to detect suppression of the monitored interface
 */

#include "suricata-common.h"
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
#include "util-error.h"
#include "util-privs.h"
#include "tmqh-packetpool.h"
#include "source-af-packet.h"

#include <sys/ioctl.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>

extern uint8_t suricata_ctl_flags;
extern int max_pending_packets;

/** control how many packets we may read in one go */
static int afp_max_read_packets = 0;
/** max packets < 65536 */
#define AFP_FILE_MAX_PKTS 256
#define AFP_IFACE_NAME_LENGTH 48

#define AFP_STATE_DOWN 0
#define AFP_STATE_UP 1

#define AFP_RECONNECT_TIMEOUT 500000

#define POLL_TIMEOUT 100

#define AFP_BUFSIZE 4096

/**
 * \brief Structure to hold thread specific variables.
 */
typedef struct AFPThreadVars_
{
    /* thread specific socket */
    int socket;
    /* handle state */
    unsigned char afp_state;
    char iface[AFP_IFACE_NAME_LENGTH];

    /* data link type for the thread */
    int datalink;
    int cooked;

    /* counters */
    uint32_t pkts;
    uint64_t bytes;
    uint32_t errs;

    /* AFP buffer size */
    int AFP_buffer_size;

    ThreadVars *tv;

    Packet *in_p;

    Packet *array[AFP_FILE_MAX_PKTS];
    uint16_t array_idx;

    int fanout;

    char *data; /** Per function and thread data */
    int datalen; /** Length of per function and thread data */
} AFPThreadVars;

TmEcode ReceiveAFP(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode ReceiveAFPThreadInit(ThreadVars *, void *, void **);
void ReceiveAFPThreadExitStats(ThreadVars *, void *);
TmEcode ReceiveAFPThreadDeinit(ThreadVars *, void *);

TmEcode DecodeAFPThreadInit(ThreadVars *, void *, void **);
TmEcode DecodeAFP(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);

/**
 * \brief Registration Function for RecieveAFP.
 * \todo Unit tests are needed for this module.
 */
void TmModuleReceiveAFPRegister (void) {
    tmm_modules[TMM_RECEIVEAFP].name = "ReceiveAFP";
    tmm_modules[TMM_RECEIVEAFP].ThreadInit = ReceiveAFPThreadInit;
    tmm_modules[TMM_RECEIVEAFP].Func = ReceiveAFP;
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

static int createsocket(AFPThreadVars *ptv, char *devname, int verbose);

/**
 * \brief AF packet read function.
 *
 * This function fills
 * From here the packets are picked up by the DecodeAFP thread.
 *
 * \param user pointer to AFPThreadVars
 * \retval TM_ECODE_FAILED on failure and TM_ECODE_OK on success
 */
TmEcode AFPRead(AFPThreadVars *ptv)
{
    Packet *p = NULL;
    /* XXX should try to use read that get directly to packet */
    uint8_t buf[AFP_BUFSIZE];
    int offset = 0;
    int caplen;
    struct sockaddr_ll from;
    struct iovec iov;
    struct msghdr msg;
#if 0
    struct cmsghdr *cmsg;
    union {
        struct cmsghdr cmsg;
        char buf[CMSG_SPACE(sizeof(struct tpacket_auxdata))];
    } cmsg_buf;
#endif

    msg.msg_name = &from;
    msg.msg_namelen = sizeof(from);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
#if 0
    msg.msg_control = &cmsg_buf;
    msg.msg_controllen = sizeof(cmsg_buf);
#endif
    msg.msg_flags = 0;

    if (ptv->cooked)
        offset = SLL_HEADER_LEN;
    else
        offset = 0;
    iov.iov_len = AFP_BUFSIZE - offset;
    iov.iov_base = buf + offset;

    caplen = recvmsg(ptv->socket, &msg, MSG_TRUNC);

    if (caplen < 0) {
        SCLogWarning(SC_ERR_AFP_READ, "recvmsg failed with error code %" PRId32,
                errno);
        SCReturnInt(TM_ECODE_FAILED);
    }
    if (ptv->array_idx == 0) {
        p = ptv->in_p;
    } else {
        p = PacketGetFromQueueOrAlloc();
    }

    if (p == NULL) {
        TmqhOutputPacketpool(ptv->tv, p);
        SCReturnInt(TM_ECODE_FAILED);
    }

    /* get timestamp of packet via ioctl */
    if (ioctl(ptv->socket, SIOCGSTAMP, &p->ts) == -1) {
        SCLogWarning(SC_ERR_AFP_READ, "recvmsg failed with error code %" PRId32,
                errno);
        TmqhOutputPacketpool(ptv->tv, p);
        SCReturnInt(TM_ECODE_FAILED);
    }

    ptv->pkts++;
    ptv->bytes += caplen + offset;

    /* add forged header */
    if (ptv->cooked) {
        SllHdr * hdrp = (SllHdr *)buf;
        /* XXX this is minimalist, but this seems enough */
        hdrp->sll_protocol = from.sll_protocol;
    }

    p->datalink = ptv->datalink;
    SET_PKT_LEN(p, caplen + offset);
    if (PacketCopyData(p, buf, GET_PKT_LEN(p)) == -1) {
        TmqhOutputPacketpool(ptv->tv, p);
        SCReturnInt(TM_ECODE_FAILED);
    }
    SCLogDebug("pktlen: %" PRIu32 " (pkt %02x, pkt data %02x)",
               GET_PKT_LEN(p), *pkt, *GET_PKT_DATA(p));

    /* store the packet in our array */
    ptv->array[ptv->array_idx] = p;
    ptv->array_idx++;
    SCReturnInt(TM_ECODE_OK);
}

static int AFPTryReopen(AFPThreadVars *ptv)
{
    int afp_activate_r;

    ptv->afp_state = AFP_STATE_DOWN;

    afp_activate_r = createsocket(ptv, ptv->iface, 0);
    if (afp_activate_r != 0) {
        return afp_activate_r;
    }

    SCLogInfo("Recovering interface listening");
    ptv->afp_state = AFP_STATE_UP;
    return 0;
}

/**
 * \brief Recieves packets from an interface via AF_PACKET socket
 *
 *  This function recieves packets from an interface and passes
 *  the packet on to the AFP callback function.
 *
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into AFPThreadVars for ptv
 * \param pq pointer to the PacketQueue (not used here but part of the api)
 * \retval TM_ECODE_FAILED on failure and TM_ECODE_OK on success
 */
TmEcode ReceiveAFP(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq) {
    SCEnter();
    uint16_t packet_q_len = 0;
    struct pollfd fds;
    TmEcode ret;
    uint16_t cnt = 0;

    AFPThreadVars *ptv = (AFPThreadVars *)data;

    /* test AFP handle */
    if (ptv->afp_state == AFP_STATE_DOWN) {
        int r;
        do {
            usleep(AFP_RECONNECT_TIMEOUT);
            if (suricata_ctl_flags != 0) {
                break;
            }
            r = AFPTryReopen(ptv);
        } while (r < 0);
    }

    /* make sure we have at least one packet in the packet pool, to prevent
     * us from alloc'ing packets at line rate */
    while (packet_q_len == 0) {
        packet_q_len = PacketPoolSize();
        if (packet_q_len == 0) {
            PacketPoolWait();
        }
    }

    if (postpq == NULL)
        afp_max_read_packets = 1;

    ptv->array_idx = 0;
    ptv->in_p = p;

    fds.fd = ptv->socket;
    fds.events = POLLIN;

    int r = 0;
    while (r >= 0) {
        r = poll(&fds, 1, POLL_TIMEOUT);

        if (r > 0) {

            ret = AFPRead(ptv);
            if (ret != TM_ECODE_OK) {
                SCReturnInt(TM_ECODE_FAILED);
            }
            if (suricata_ctl_flags != 0) {
                break;
            }
            if (cnt++ >= afp_max_read_packets)
                break;
        }
        if (r < 0) {
            int dbreak = 0;
            SCLogError(SC_ERR_AFP_READ, "Error reading data from socket: (%d" PRIu32 ") %s",
                       errno, strerror(errno));
            do {
                usleep(AFP_RECONNECT_TIMEOUT);
                if (suricata_ctl_flags != 0) {
                    dbreak = 1;
                    break;
                }
                r = AFPTryReopen(ptv);
            } while (r < 0);
            if (dbreak) {
                r = 0;
                break;
            }
        }
        if ( r == 0) {
            if (suricata_ctl_flags != 0) {
                break;
            }
            if (cnt > 0)
                break;
        }
    }

    for (cnt = 0; cnt < ptv->array_idx; cnt++) {
        Packet *pp = ptv->array[cnt];

        /* enqueue all but the first in the postpq, the first
         * pkt is handled by the tv "out handler" */
        if (cnt > 0) {
            PacketEnqueue(postpq, pp);
        }
    }

    if (r < 0) {
        SCLogError(SC_ERR_AFP_DISPATCH, "error code %" PRId32,
                r);

        SCReturnInt(TM_ECODE_OK);
    }

    if (suricata_ctl_flags != 0) {
        SCReturnInt(TM_ECODE_FAILED);
    }

    SCReturnInt(TM_ECODE_OK);
}

static int getifnumbydev(int fd, const char *ifname, int verbose)
{
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

    if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1) {
           if (verbose)
               SCLogError(SC_ERR_AFP_CREATE, "Unable to find iface %s: %s",
                          ifname, strerror(errno));
        return -1;
    }

    return ifr.ifr_ifindex;
}

static int getdevlinktype(int fd, const char *ifname)
{
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
        SCLogError(SC_ERR_AFP_CREATE, "Unable to find type for iface \"%s\": %s",
                   ifname, strerror(errno));
        return -1;
    }

    return ifr.ifr_hwaddr.sa_family;
}

static int createsocket(AFPThreadVars *ptv, char *devname, int verbose)
{
    int r;
    struct packet_mreq sock_params;
    struct sockaddr_ll bind_address;
    /* open socket */
    ptv->socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (ptv->socket == -1) {
        SCLogError(SC_ERR_AFP_CREATE, "Coudn't create a AF_PACKET socket, error %s", strerror(errno));
        return -1;
    }
    SCLogInfo("using interface %s", (char *)devname);
    /* bind socket */
    memset(&bind_address, 0, sizeof(bind_address));
    bind_address.sll_family = AF_PACKET;
    bind_address.sll_protocol = htons(ETH_P_ALL);
    bind_address.sll_ifindex = getifnumbydev(ptv->socket, devname, verbose);
    if (bind_address.sll_ifindex == -1) {
        if (verbose)
            SCLogError(SC_ERR_AFP_CREATE, "Coudn't find iface %s", devname);
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
    /* Force promiscuous mode */
    memset(&sock_params, 0, sizeof(sock_params));
    sock_params.mr_type = PACKET_MR_PROMISC;
    sock_params.mr_ifindex = bind_address.sll_ifindex;
    r = setsockopt(ptv->socket, SOL_PACKET, PACKET_ADD_MEMBERSHIP,(void *)&sock_params, sizeof(sock_params));
    if (r < 0) {
        SCLogError(SC_ERR_AFP_CREATE,
                   "Coudn't switch iface %s to promiscuous, error %s",
                   devname,
                   strerror(errno));
        return -1;
    }
#ifdef HAVE_PACKET_FANOUT
    /* add binded socket to fanout group */
    if (ptv->fanout) {
        uint32_t option = 0;
        uint16_t mode = PACKET_FANOUT_HASH;
        uint16_t id = 1;
        option = (mode << 16) | (id & 0xffff);
        r = setsockopt(ptv->socket, SOL_PACKET, PACKET_FANOUT,(void *)&option, sizeof(option));
        if (r < 0) {
            SCLogError(SC_ERR_AFP_CREATE,
                       "Coudn't set fanout mode, error %s",
                       strerror(errno));
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
    int value;

    /* use max_pending_packets as AFP read size unless it's bigger than
     * our size limit */
    afp_max_read_packets = (AFP_FILE_MAX_PKTS < max_pending_packets) ?
        AFP_FILE_MAX_PKTS : max_pending_packets;

    if (initdata == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "initdata == NULL");
        SCReturnInt(TM_ECODE_FAILED);
    }

    AFPThreadVars *ptv = SCMalloc(sizeof(AFPThreadVars));
    if (ptv == NULL)
        SCReturnInt(TM_ECODE_FAILED);
    memset(ptv, 0, sizeof(AFPThreadVars));

    ptv->tv = tv;
    ptv->cooked = 0;

    strncpy(ptv->iface, initdata, AFP_IFACE_NAME_LENGTH);
    ptv->iface[AFP_IFACE_NAME_LENGTH - 1]= '\0';

    r = createsocket(ptv, initdata, 1);
    if (r < 0) {
        SCLogError(SC_ERR_AFP_CREATE, "Coudn't init AF_PACKET socket");
        SCFree(ptv);
        SCReturnInt(TM_ECODE_FAILED);
    }

    ptv->datalink = getdevlinktype(ptv->socket, ptv->iface);
    switch (ptv->datalink) {
        case ARPHRD_PPP:
        case ARPHRD_ATM:
            ptv->cooked = 1;
    }

    if ((ConfGetBool("af-packet.fanout", &value)) == 1) {
        ptv->fanout = value;
    } else {
        ptv->fanout = 0;
    }

    *data = (void *)ptv;
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
/**
* \todo Counter output
*/
}

/**
 * \brief DeInit function closes af packet socket at exit.
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into AFPThreadVars for ptv
 */
TmEcode ReceiveAFPThreadDeinit(ThreadVars *tv, void *data) {
    AFPThreadVars *ptv = (AFPThreadVars *)data;

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

/* eof */
