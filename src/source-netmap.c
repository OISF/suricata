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
*  \defgroup netmap Netmap running mode
*
*  @{
*/

/**
* \file
*
* \author Aleksey Katargin <gureedo@gmail.com>
* \author Victor Julien <victor@inliniac.net>
*
* Netmap socket acquisition support
*
* Many thanks to Luigi Rizzo for guidance and support.
*
*/


#include "suricata-common.h"
#include "suricata.h"
#include "decode.h"
#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"
#include "conf.h"
#include "util-bpf.h"
#include "util-debug.h"
#include "util-device.h"
#include "util-error.h"
#include "util-privs.h"
#include "util-optimize.h"
#include "util-checksum.h"
#include "util-validate.h"

#include "tmqh-packetpool.h"
#include "source-netmap.h"
#include "runmodes.h"

#ifdef HAVE_NETMAP

#if HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#if HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif

#define NETMAP_WITH_LIBS
#ifdef DEBUG
#define DEBUG_NETMAP_USER
#endif
#include <net/netmap_user.h>

#endif /* HAVE_NETMAP */

#include "util-ioctl.h"

#ifndef HAVE_NETMAP

/**
* \brief this function prints an error message and exits.
*/
static TmEcode NoNetmapSupportExit(ThreadVars *tv, const void *initdata, void **data)
{
    SCLogError(SC_ERR_NO_NETMAP,"Error creating thread %s: you do not have "
            "support for netmap enabled, please recompile "
            "with --enable-netmap", tv->name);
    exit(EXIT_FAILURE);
}

void TmModuleReceiveNetmapRegister (void)
{
    tmm_modules[TMM_RECEIVENETMAP].name = "ReceiveNetmap";
    tmm_modules[TMM_RECEIVENETMAP].ThreadInit = NoNetmapSupportExit;
    tmm_modules[TMM_RECEIVENETMAP].flags = TM_FLAG_RECEIVE_TM;
}

/**
* \brief Registration Function for DecodeNetmap.
*/
void TmModuleDecodeNetmapRegister (void)
{
    tmm_modules[TMM_DECODENETMAP].name = "DecodeNetmap";
    tmm_modules[TMM_DECODENETMAP].ThreadInit = NoNetmapSupportExit;
    tmm_modules[TMM_DECODENETMAP].flags = TM_FLAG_DECODE_TM;
}

#else /* We have NETMAP support */

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
 * \brief Netmap device instance. Each ring for each device gets its own
 *        device.
 */
typedef struct NetmapDevice_
{
    struct nm_desc *nmd;
    unsigned int ref;
    SC_ATOMIC_DECLARE(unsigned int, threads_run);
    TAILQ_ENTRY(NetmapDevice_) next;
    // actual ifname can only be 16, but we store a bit more,
    // like the options string and a 'netmap:' prefix.
    char ifname[32];
    int ring;
    int direction; // 0 rx, 1 tx
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

    int flags;
    struct bpf_program bpf_prog;

    /* suricata internals */
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
 *  \retval rx_rings RSS RX queue count or 0 on error
 */
int NetmapGetRSSCount(const char *ifname)
{
    struct nmreq nm_req;
    int rx_rings = 0;

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
static int NetmapOpen(NetmapIfaceSettings *ns,
    NetmapDevice **pdevice, int verbose, int read, bool zerocopy)
{
    SCEnter();
    SCLogDebug("ifname %s", ns->iface);

    char base_name[IFNAMSIZ];
    strlcpy(base_name, ns->iface, sizeof(base_name));
    if (strlen(base_name) > 0 &&
            (base_name[strlen(base_name)-1] == '^' ||
             base_name[strlen(base_name)-1] == '*'))
    {
        base_name[strlen(base_name)-1] = '\0';
    }

    if (ns->real) {
        /* check interface is up */
        int if_flags = GetIfaceFlags(base_name);
        if (if_flags == -1) {
            if (verbose) {
                SCLogError(SC_ERR_NETMAP_CREATE,
                        "Can not access to interface '%s' (%s)",
                        base_name, ns->iface);
            }
            goto error;
        }

        /* bring iface up if it is down */
        if ((if_flags & IFF_UP) == 0) {
            SCLogError(SC_ERR_NETMAP_CREATE, "interface '%s' (%s) is down", base_name, ns->iface);
            goto error;
        }
        /* if needed, try to set iface in promisc mode */
        if (ns->promisc && (if_flags & (IFF_PROMISC|IFF_PPROMISC)) == 0) {
            if_flags |= IFF_PPROMISC;
            SetIfaceFlags(base_name, if_flags); // TODO reset at exit
            // TODO move to parse config?
        }
    }
    NetmapDevice *pdev = NULL, *spdev = NULL;
    pdev = SCMalloc(sizeof(*pdev));
    if (unlikely(pdev == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "Memory allocation failed");
        goto error;
    }
    memset(pdev, 0, sizeof(*pdev));
    SC_ATOMIC_INIT(pdev->threads_run);

    SCMutexLock(&netmap_devlist_lock);

    const int direction = (read != 1);
    int ring = 0;
    /* search interface in our already opened list */
    TAILQ_FOREACH(spdev, &netmap_devlist, next) {
        SCLogDebug("spdev %s", spdev->ifname);
        if (direction == spdev->direction && strcmp(ns->iface, spdev->ifname) == 0) {
            ring = spdev->ring + 1;
        }
    }
    SCLogDebug("netmap/%s: using ring %d", ns->iface, ring);

    const char *opt_R = "R";
    const char *opt_T = "T";
    const char *opt_x = "x"; // not for IPS
    const char *opt_z = "z"; // zero copy, not for IPS

    // FreeBSD 11 doesn't have R and T.
#if NETMAP_API<=11
    opt_R = "";
    opt_T = "";
#endif
    /* assemble options string */
    char optstr[16];
    if (ns->ips)
        opt_x = "";
// z seems to not play well with multiple opens of a real dev on linux
//    if (!zerocopy || ips)
    opt_z = "";

    // loop to retry opening if unsupported options are used
retry:
    snprintf(optstr, sizeof(optstr), "%s%s%s", opt_z, opt_x, direction == 0 ? opt_R : opt_T);

    char devname[64];
    if (strncmp(ns->iface, "netmap:", 7) == 0) {
        snprintf(devname, sizeof(devname), "%s}%d%s%s",
                ns->iface, ring, strlen(optstr) ? "/" : "", optstr);
    } else if (strlen(ns->iface) > 5 && strncmp(ns->iface, "vale", 4) == 0 && isdigit(ns->iface[4])) {
        snprintf(devname, sizeof(devname), "%s", ns->iface);
    } else if (ns->iface[strlen(ns->iface)-1] == '*' ||
            ns->iface[strlen(ns->iface)-1] == '^') {
        SCLogDebug("device with SW-ring enabled (ns->iface): %s",ns->iface);
        snprintf(devname, sizeof(devname), "netmap:%s", ns->iface);
        SCLogDebug("device with SW-ring enabled (devname): %s",devname);
        /* just a single ring, so don't use ring param */
    } else if (ring == 0 && ns->threads == 1) {
        snprintf(devname, sizeof(devname), "netmap:%s%s%s",
                ns->iface, strlen(optstr) ? "/" : "", optstr);
    } else {
        snprintf(devname, sizeof(devname), "netmap:%s-%d%s%s",
                ns->iface, ring, strlen(optstr) ? "/" : "", optstr);
    }
    strlcpy(pdev->ifname, ns->iface, sizeof(pdev->ifname));

    pdev->nmd = nm_open(devname, NULL, 0, NULL);
    if (pdev->nmd == NULL) {
        if (errno == EINVAL && opt_z[0] == 'z') {
            SCLogNotice("got '%s' EINVAL: going to retry without 'z'", devname);
            opt_z = "";
            goto retry;
        } else if (errno == EINVAL && opt_x[0] == 'x') {
            SCLogNotice("dev '%s' got EINVAL: going to retry without 'x'", devname);
            opt_x = "";
            goto retry;
        }

        SCLogError(SC_ERR_NETMAP_CREATE, "opening devname %s failed: %s",
                devname, strerror(errno));
        exit(EXIT_FAILURE);
    }
    SCLogDebug("devname %s %s opened", devname, ns->iface);

    pdev->direction = direction;
    pdev->ring = ring;
    TAILQ_INSERT_TAIL(&netmap_devlist, pdev, next);

    SCLogNotice("opened %s from %s: %p", devname, ns->iface, pdev->nmd);
    SCMutexUnlock(&netmap_devlist_lock);
    *pdevice = pdev;

    return 0;
error:
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
                nm_close(pdev->nmd);
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

    /* enable zero-copy mode for workers runmode */
    char const *active_runmode = RunmodeGetActive();
    if (strcmp("workers", active_runmode) == 0) {
        ntv->flags |= NETMAP_FLAG_ZERO_COPY;
        SCLogDebug("Enabling zero copy mode for %s", aconf->in.iface);
    }

    if (NetmapOpen(&aconf->in, &ntv->ifsrc, 1, 1,
                (ntv->flags & NETMAP_FLAG_ZERO_COPY) != 0) != 0) {
        goto error_ntv;
    }

    if (unlikely(aconf->in.sw_ring && aconf->in.threads > 1)) {
        SCLogError(SC_ERR_INVALID_VALUE,
                   "Interface '%s+'. "
                   "Thread count can't be greater than 1 for SW ring.",
                   aconf->iface_name);
        goto error_src;
    }

    if (aconf->in.copy_mode != NETMAP_COPY_MODE_NONE) {
        SCLogDebug("IPS: opening out iface %s", aconf->out.iface);
        if (NetmapOpen(&aconf->out, &ntv->ifdst,
                    1, 0, false) != 0) {
            goto error_src;
        }
    }

    /* basic counters */
    ntv->capture_kernel_packets = StatsRegisterCounter("capture.kernel_packets",
            ntv->tv);
    ntv->capture_kernel_drops = StatsRegisterCounter("capture.kernel_drops",
            ntv->tv);

    if (aconf->in.bpf_filter) {
        SCLogConfig("Using BPF '%s' on iface '%s'",
                  aconf->in.bpf_filter, ntv->ifsrc->ifname);
        char errbuf[PCAP_ERRBUF_SIZE];
        if (SCBPFCompile(default_packet_size,  /* snaplen_arg */
                    LINKTYPE_ETHERNET,    /* linktype_arg */
                    &ntv->bpf_prog,       /* program */
                    aconf->in.bpf_filter, /* const char *buf */
                    1,                    /* optimize */
                    PCAP_NETMASK_UNKNOWN,  /* mask */
                    errbuf,
                    sizeof(errbuf)) == -1)
        {
            SCLogError(SC_ERR_NETMAP_CREATE, "Failed to compile BPF \"%s\": %s",
                   aconf->in.bpf_filter,
                   errbuf);
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
    DEBUG_VALIDATE_BUG_ON(ntv->ifdst == NULL);

    if (nm_inject(ntv->ifdst->nmd, GET_PKT_DATA(p), GET_PKT_LEN(p)) == 0) {
        SCLogDebug("failed to send %s -> %s",
                ntv->ifsrc->ifname, ntv->ifdst->ifname);
        ntv->drops++;
    }
    SCLogDebug("sent succesfully: %s(%d)->%s(%d) (%u)",
		    ntv->ifsrc->ifname, ntv->ifsrc->ring,
            ntv->ifdst->ifname, ntv->ifdst->ring, GET_PKT_LEN(p));

    ioctl(ntv->ifdst->nmd->fd, NIOCTXSYNC, 0);
    return TM_ECODE_OK;
}

/**
 * \brief Packet release routine.
 * \param p Packet.
 */
static void NetmapReleasePacket(Packet *p)
{
    NetmapThreadVars *ntv = (NetmapThreadVars *)p->netmap_v.ntv;

    if ((ntv->copy_mode != NETMAP_COPY_MODE_NONE) && !PKT_IS_PSEUDOPKT(p)) {
        NetmapWritePacket(ntv, p);
    }

    PacketFreeOrRelease(p);
}

static void NetmapCallback(u_char *user, const struct nm_pkthdr *ph, const u_char *d)
{
    NetmapThreadVars *ntv = (NetmapThreadVars *)user;

    if (ntv->bpf_prog.bf_len) {
        struct pcap_pkthdr pkthdr = { {0, 0}, ph->len, ph->len };
        if (pcap_offline_filter(&ntv->bpf_prog, &pkthdr, d) == 0) {
            return;
        }
    }

    Packet *p = PacketPoolGetPacket();
    if (unlikely(p == NULL)) {
        return;
    }

    PKT_SET_SRC(p, PKT_SRC_WIRE);
    p->livedev = ntv->livedev;
    p->datalink = LINKTYPE_ETHERNET;
    p->ts = ph->ts;
    ntv->pkts++;
    ntv->bytes += ph->len;

    if (ntv->flags & NETMAP_FLAG_ZERO_COPY) {
        if (PacketSetData(p, (uint8_t *)d, ph->len) == -1) {
            TmqhOutputPacketpool(ntv->tv, p);
            return;
        }
    } else {
        if (PacketCopyData(p, (uint8_t *)d, ph->len) == -1) {
            TmqhOutputPacketpool(ntv->tv, p);
            return;
        }
    }

    p->ReleasePacket = NetmapReleasePacket;
    p->netmap_v.ntv = ntv;

    SCLogDebug("pktlen: %" PRIu32 " (pkt %p, pkt data %p)",
            GET_PKT_LEN(p), p, GET_PKT_DATA(p));

    if (TmThreadsSlotProcessPkt(ntv->tv, ntv->slot, p) != TM_ECODE_OK) {
        TmqhOutputPacketpool(ntv->tv, p);
        return;
    }
    return;
}

/**
 *  \brief Main netmap reading loop function
 */
static TmEcode ReceiveNetmapLoop(ThreadVars *tv, void *data, void *slot)
{
    SCEnter();

    TmSlot *s = (TmSlot *)slot;
    NetmapThreadVars *ntv = (NetmapThreadVars *)data;
    struct pollfd fds;

    ntv->slot = s->slot_next;
    fds.fd = ntv->ifsrc->nmd->fd;
    fds.events = POLLIN;

    for(;;) {
        if (unlikely(suricata_ctl_flags != 0)) {
            break;
        }

        /* make sure we have at least one packet in the packet pool,
         * to prevent us from alloc'ing packets at line rate */
        PacketPoolWait();

        int r = poll(&fds, 1, POLL_TIMEOUT);
        if (r < 0) {
            /* error */
            if (errno != EINTR)
                SCLogError(SC_ERR_NETMAP_READ,
                           "Error polling netmap from iface '%s': (%d" PRIu32 ") %s",
                           ntv->ifsrc->ifname, errno, strerror(errno));
            continue;

        } else if (r == 0) {
            /* no events, timeout */
            //SCLogDebug("(%s:%d-%d) Poll timeout", ntv->ifsrc->ifname,
            //           ntv->src_ring_from, ntv->src_ring_to);

            /* sync counters */
            NetmapDumpCounters(ntv);
            StatsSyncCountersIfSignalled(tv);

            /* poll timed out, lets handle the timeout */
            TmThreadsCaptureHandleTimeout(tv, ntv->slot, NULL);
            continue;
        }

        if (unlikely(fds.revents & POLL_EVENTS)) {
            if (fds.revents & POLLERR) {
                //SCLogError(SC_ERR_NETMAP_READ,
                //        "Error reading data from iface '%s': (%d" PRIu32 ") %s",
                //        ntv->ifsrc->ifname, errno, strerror(errno));
            } else if (fds.revents & POLLNVAL) {
                SCLogError(SC_ERR_NETMAP_READ,
                        "Invalid polling request");
            }
            continue;
        }

        if (likely(fds.revents & POLLIN)) {
            nm_dispatch(ntv->ifsrc->nmd, -1, NetmapCallback, (void *)ntv);
        }

        NetmapDumpCounters(ntv);
        StatsSyncCountersIfSignalled(tv);
    }

    NetmapDumpCounters(ntv);
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
        SCBPFFree(&ntv->bpf_prog);
    }

    SCFree(ntv);

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

    DecodeThreadVars *dtv = DecodeThreadVarsAlloc(tv);
    if (dtv == NULL)
        SCReturnInt(TM_ECODE_FAILED);

    DecodeRegisterPerfCounters(dtv, tv);

    *data = (void *)dtv;

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
 * \brief Registration Function for ReceiveNetmap.
 */
void TmModuleReceiveNetmapRegister(void)
{
    tmm_modules[TMM_RECEIVENETMAP].name = "ReceiveNetmap";
    tmm_modules[TMM_RECEIVENETMAP].ThreadInit = ReceiveNetmapThreadInit;
    tmm_modules[TMM_RECEIVENETMAP].PktAcqLoop = ReceiveNetmapLoop;
    tmm_modules[TMM_RECEIVENETMAP].ThreadExitPrintStats = ReceiveNetmapThreadExitStats;
    tmm_modules[TMM_RECEIVENETMAP].ThreadDeinit = ReceiveNetmapThreadDeinit;
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
    tmm_modules[TMM_DECODENETMAP].ThreadDeinit = DecodeNetmapThreadDeinit;
    tmm_modules[TMM_DECODENETMAP].cap_flags = 0;
    tmm_modules[TMM_DECODENETMAP].flags = TM_FLAG_DECODE_TM;
}

#endif /* HAVE_NETMAP */

/**
* @}
*/
