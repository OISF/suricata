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
*  \defgroup netmap Netmap running mode
*
*  @{
*/

/**
 * \file
 *
 * \author Aleksey Katargin <gureedo@gmail.com>
 * \author Victor Julien <victor@inliniac.net>
 * \author Bill Meeks <billmeeks8@gmail.com>
 *
 * Netmap socket acquisition support
 *
 * Many thanks to Luigi Rizzo for guidance and support.
 *
 */

#include "suricata.h"
#include "suricata-common.h"
#include "tm-threads.h"
#include "packet.h"
#include "util-bpf.h"
#include "util-privs.h"
#include "util-validate.h"
#include "util-datalink.h"

#include "source-netmap.h"

#ifdef HAVE_NETMAP

#define NETMAP_WITH_LIBS
#ifdef DEBUG
#define DEBUG_NETMAP_USER
#endif

#include <net/netmap_user.h>
#include <libnetmap.h>

#endif /* HAVE_NETMAP */

#include "util-ioctl.h"

#ifndef HAVE_NETMAP

/**
* \brief this function prints an error message and exits.
*/
static TmEcode NoNetmapSupportExit(ThreadVars *tv, const void *initdata, void **data)
{
    FatalError(SC_ERR_NO_NETMAP,
            "Error creating thread %s: Netmap is not enabled. "
            "Make sure to pass --enable-netmap to configure when building.",
            tv->name);
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

#include "action-globals.h"

#define POLL_TIMEOUT 100

#if defined(__linux__)
#define POLL_EVENTS (POLLHUP|POLLRDHUP|POLLERR|POLLNVAL)

#ifndef IFF_PPROMISC
#define IFF_PPROMISC IFF_PROMISC
#endif

#else
#define POLL_EVENTS (POLLHUP|POLLERR|POLLNVAL)
#endif

enum { NETMAP_FLAG_ZERO_COPY = 1, NETMAP_FLAG_EXCL_RING_ACCESS = 2 };

/**
 * \brief Netmap device instance. Each ring for each device gets its own
 *        device.
 */
typedef struct NetmapDevice_
{
    struct nmport_d *nmd;
    unsigned int ref;
    SC_ATOMIC_DECLARE(unsigned int, threads_run);
    TAILQ_ENTRY(NetmapDevice_) next;
    // actual ifname can only be 16, but we store a bit more,
    // like the options string and a 'netmap:' prefix.
    char ifname[32];
    int ring;
    int direction; // 0 rx, 1 tx

    // autofp: Used to lock a destination ring while we are sending data.
    SCMutex netmap_dev_lock;
} NetmapDevice;

/**
 * \brief Module thread local variables.
 */
typedef struct NetmapThreadVars_
{
    /* receive interface */
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
    struct nmreq_port_info_get req;
    struct nmreq_header hdr;
    int rx_rings = 0;

    /* we need the base interface name to query queues */
    char base_name[IFNAMSIZ];
    strlcpy(base_name, ifname, sizeof(base_name));
    if (strlen(base_name) > 0 &&
            (base_name[strlen(base_name) - 1] == '^' || base_name[strlen(base_name) - 1] == '*')) {
        base_name[strlen(base_name) - 1] = '\0';
    }

    SCMutexLock(&netmap_devlist_lock);

    /* open netmap device */
    int fd = open("/dev/netmap", O_RDWR);
    if (fd == -1) {
        SCLogError(SC_ERR_NETMAP_CREATE,
                "Couldn't open netmap device, error %s",
                strerror(errno));
        goto error_open;
    }

    /* query netmap interface info */
    memset(&req, 0, sizeof(req));
    memset(&hdr, 0, sizeof(hdr));
    hdr.nr_version = NETMAP_API;
    hdr.nr_reqtype = NETMAP_REQ_PORT_INFO_GET;
    hdr.nr_body = (uintptr_t)&req;
    strlcpy(hdr.nr_name, base_name, sizeof(hdr.nr_name));

    if (ioctl(fd, NIOCCTRL, &hdr) != 0) {
        SCLogError(SC_ERR_NETMAP_CREATE, "Couldn't query netmap for info about %s, error %s",
                ifname, strerror(errno));
        goto error_fd;
    };

    /* return RX rings count if it equals TX rings count */
    if (req.nr_rx_rings == req.nr_tx_rings) {
        rx_rings = req.nr_rx_rings;
    }

error_fd:
    close(fd);
error_open:
    SCMutexUnlock(&netmap_devlist_lock);
    return rx_rings;
}

static void NetmapDestroyDevice(NetmapDevice *pdev)
{
    nmport_close(pdev->nmd);
    SCMutexDestroy(&pdev->netmap_dev_lock);
    SCFree(pdev);
}

/**
 * \brief Close or dereference netmap device instance.
 * \param dev Netmap device instance.
 * \return Zero on success.
 */
static int NetmapClose(NetmapDevice *dev)
{
    NetmapDevice *pdev, *tmp;

    SCMutexLock(&netmap_devlist_lock);

    TAILQ_FOREACH_SAFE (pdev, &netmap_devlist, next, tmp) {
        if (pdev == dev) {
            pdev->ref--;
            if (!pdev->ref) {
                NetmapDestroyDevice(pdev);
            }
            SCMutexUnlock(&netmap_devlist_lock);
            return 0;
        }
    }

    SCMutexUnlock(&netmap_devlist_lock);
    return -1;
}

/**
 * \brief Close all open netmap device instances.
 */
static void NetmapCloseAll(void)
{
    NetmapDevice *pdev, *tmp;

    SCMutexLock(&netmap_devlist_lock);

    TAILQ_FOREACH_SAFE (pdev, &netmap_devlist, next, tmp) {
        NetmapDestroyDevice(pdev);
    }

    SCMutexUnlock(&netmap_devlist_lock);
}

/**
 * \brief Open interface in netmap mode.
 * \param ifname Interface name.
 * \param promisc Enable promiscuous mode.
 * \param dev Pointer to requested netmap device instance.
 * \param verbose Verbose error logging.
 * \param read Indicates direction: RX or TX
 * \param zerocopy 1 if zerocopy access requested
 * \param soft Use Host stack (software) interface
 * \return Zero on success.
 */
static int NetmapOpen(NetmapIfaceSettings *ns, NetmapDevice **pdevice, int verbose, int read,
        bool zerocopy, bool soft)
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
                SCLogError(SC_ERR_NETMAP_CREATE, "Cannot access network interface '%s' (%s)",
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
    pdev = SCCalloc(1, sizeof(*pdev));
    if (unlikely(pdev == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "Memory allocation failed");
        goto error;
    }
    SC_ATOMIC_INIT(pdev->threads_run);

    SCMutexLock(&netmap_devlist_lock);

    const int direction = (read != 1);
    int ring = 0;
    /* Search for interface in our already opened list. */
    /* We will find it when opening multiple rings on   */
    /* the device when it exposes multiple RSS queues.  */
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

    /* assemble options string */
    char optstr[16];
    if (ns->ips)
        opt_x = "";
    // z seems to not play well with multiple opens of a real dev on linux
    opt_z = "";

    /*
     * How netmap endpoint names are selected:
     *
     * The following logic within the "retry" loop builds endpoint names.
     *
     * IPS Mode:
     * There are two endpoints: one hardware NIC and either a hardware NIC or host stack "NIC".
     *
     * IDS Mode:
     * One endpoint -- usually a hardware NIC.
     *
     * IPS mode -- with one endpoint a host stack "NIC":
     * When using multiple rings/threads, then the open of the initial Ring 0 MUST
     * instruct netmap to open multiple Host Stack rings (as the default is to open only a single
     * pair). This is also critical for the HW NIC endpoint. This is done by adding
     * “@conf:host-rings=x” suffix option (where “x” is the number of host rings desired)
     * to BOTH endpoint nmport_open_desc() calls for ring 0 (hardware and host stack).
     * For subsequent additional ring open calls, omit the suffix option specifying host ring count.
     *
     * IPS mode -- both endpoints are hardware NICs:
     * Do NOT pass any suffix option (even for Ring 0). You do not need to tell netmap how many
     * rings, because it already knows the correct value from the NIC driver itself. Specifying a
     * desired ring count when both ends are Hardware NICs confuses netmap, and it seems to default
     * to using only a single hardware ring. In this scenario, specify only the specific ring number
     * being opened.
     */

    // loop to retry opening if unsupported options are used
retry:
    snprintf(optstr, sizeof(optstr), "%s%s%s", opt_z, opt_x, direction == 0 ? opt_R : opt_T);

    char devname[128];
    if (strncmp(ns->iface, "netmap:", 7) == 0) {
        snprintf(devname, sizeof(devname), "%s}%d%s%s",
                ns->iface, ring, strlen(optstr) ? "/" : "", optstr);
    } else if (strlen(ns->iface) > 5 && strncmp(ns->iface, "vale", 4) == 0 && isdigit(ns->iface[4])) {
        snprintf(devname, sizeof(devname), "%s", ns->iface);
    } else if (ring == 0 && ns->threads == 1) {
        /* just a single thread and ring, so don't use ring param */
        snprintf(devname, sizeof(devname), "netmap:%s%s%s",
                ns->iface, strlen(optstr) ? "/" : "", optstr);
        SCLogDebug("device with %s-ring enabled (devname): %s", soft ? "SW" : "HW", devname);
    } else {
        /* Going to be using multiple threads and rings */
        if (ns->sw_ring) {
            /* Opening a host stack interface */
            if (ring == 0) {
                /* Ring 0, so tell netmap how many host rings we want created */
                snprintf(devname, sizeof(devname), "netmap:%s%d%s%s@conf:host-rings=%d", ns->iface,
                        ring, strlen(optstr) ? "/" : "", optstr, ns->threads);
            } else {
                /* Software (host) ring, but not initial open of ring 0 */
                snprintf(devname, sizeof(devname), "netmap:%s%d%s%s", ns->iface, ring,
                        strlen(optstr) ? "/" : "", optstr);
            }
            SCLogDebug("device with SW-ring enabled (devname): %s", devname);
        } else if (ring == 0 && soft) {
            /* Ring 0 of HW endpoint, and other endpoint is SW stack,
             * so request SW host stack rings to match HW rings count.
             */
            snprintf(devname, sizeof(devname), "netmap:%s-%d%s%s@conf:host-rings=%d", ns->iface,
                    ring, strlen(optstr) ? "/" : "", optstr, ns->threads);
            SCLogDebug("device with HW-ring enabled (devname): %s", devname);
        } else {
            /* Hardware ring other than ring 0, or both endpoints are HW
             * and there is no host stack (SW) endpoint */
            snprintf(devname, sizeof(devname), "netmap:%s-%d%s%s", ns->iface, ring,
                    strlen(optstr) ? "/" : "", optstr);
            SCLogDebug("device with HW-ring enabled (devname): %s", devname);
        }
    }

    strlcpy(pdev->ifname, ns->iface, sizeof(pdev->ifname));

    /* have the netmap API parse device name and prepare the port descriptor for us */
    pdev->nmd = nmport_prepare(devname);

    if (pdev->nmd != NULL) {
        /* For RX devices, set the nr_mode flag we need on the netmap port TX rings prior to opening
         */
        if (read) {
            pdev->nmd->reg.nr_flags |= NR_NO_TX_POLL;
        }

        /* Now attempt to actually open the netmap port descriptor */
        if (nmport_open_desc(pdev->nmd) < 0) {
            /* the open failed, so clean-up the descriptor and fall through to error handler */
            nmport_close(pdev->nmd);
            pdev->nmd = NULL;
        }
    }

    if (pdev->nmd == NULL) {
        if (errno == EINVAL) {
            if (opt_z[0] == 'z') {
                SCLogNotice("got '%s' EINVAL: going to retry without 'z'", devname);
                opt_z = "";
                goto retry;
            } else if (opt_x[0] == 'x') {
                SCLogNotice("dev '%s' got EINVAL: going to retry without 'x'", devname);
                opt_x = "";
                goto retry;
            }
        }

        NetmapCloseAll();
        FatalError(SC_ERR_FATAL, "opening devname %s failed: %s", devname, strerror(errno));
    }

    /* Work around bug in libnetmap library where "cur_{r,t}x_ring" values not initialized */
    SCLogDebug("%s -- cur rings: [%d, %d] first rings: [%d, %d]", devname, pdev->nmd->cur_rx_ring,
            pdev->nmd->cur_tx_ring, pdev->nmd->first_rx_ring, pdev->nmd->first_tx_ring);
    pdev->nmd->cur_rx_ring = pdev->nmd->first_rx_ring;
    pdev->nmd->cur_tx_ring = pdev->nmd->first_tx_ring;

    SCLogInfo("devname [fd: %d] %s %s opened", pdev->nmd->fd, devname, ns->iface);

    pdev->direction = direction;
    pdev->ring = ring;
    SCMutexInit(&pdev->netmap_dev_lock, NULL);
    TAILQ_INSERT_TAIL(&netmap_devlist, pdev, next);

    SCMutexUnlock(&netmap_devlist_lock);
    *pdevice = pdev;

    return 0;
error:
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

    NetmapThreadVars *ntv = SCCalloc(1, sizeof(*ntv));
    if (unlikely(ntv == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "Memory allocation failed");
        goto error;
    }

    ntv->livedev = LiveGetDevice(aconf->iface_name);
    if (ntv->livedev == NULL) {
        SCLogError(SC_ERR_INVALID_VALUE, "Unable to find Live device");
        goto error_ntv;
    }

    ntv->tv = tv;
    ntv->checksum_mode = aconf->in.checksum_mode;
    ntv->copy_mode = aconf->in.copy_mode;

    /* enable zero-copy mode for workers runmode */
    char const *active_runmode = RunmodeGetActive();
    if (strcmp("workers", active_runmode) == 0) {
        ntv->flags |= NETMAP_FLAG_ZERO_COPY;
        SCLogDebug("Enabling zero copy mode for %s", aconf->in.iface);
    } else if (strcmp("autofp", active_runmode) == 0) {
        ntv->flags |= NETMAP_FLAG_EXCL_RING_ACCESS;
    }

    /* Need to insure open of ring 0 conveys requested ring count for open */
    bool soft = aconf->in.sw_ring || aconf->out.sw_ring;
    if (NetmapOpen(&aconf->in, &ntv->ifsrc, 1, 1, (ntv->flags & NETMAP_FLAG_ZERO_COPY) != 0,
                soft) != 0) {
        goto error_ntv;
    }

    if (aconf->in.copy_mode != NETMAP_COPY_MODE_NONE) {
        if (NetmapOpen(&aconf->out, &ntv->ifdst, 1, 0, (ntv->flags & NETMAP_FLAG_ZERO_COPY) != 0,
                    soft) != 0) {
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

    SCLogDebug("thread: %s polling on fd: %d", tv->name, ntv->ifsrc->nmd->fd);

    DatalinkSetGlobalType(LINKTYPE_ETHERNET);

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
        if (PacketCheckAction(p, ACTION_DROP)) {
            return TM_ECODE_OK;
        }
    }
    DEBUG_VALIDATE_BUG_ON(ntv->ifdst == NULL);

    /* Lock the destination netmap ring while writing to it */
    if (ntv->flags & NETMAP_FLAG_EXCL_RING_ACCESS) {
        SCMutexLock(&ntv->ifdst->netmap_dev_lock);
    }

    /* attempt to write the packet into the netmap ring buffer(s) */
    if (nmport_inject(ntv->ifdst->nmd, GET_PKT_DATA(p), GET_PKT_LEN(p)) == 0) {
        if (ntv->flags & NETMAP_FLAG_EXCL_RING_ACCESS) {
            SCMutexUnlock(&ntv->ifdst->netmap_dev_lock);
        }
        SCLogDebug("failed to send %s -> %s", ntv->ifsrc->ifname, ntv->ifdst->ifname);
        ntv->drops++;
        return TM_ECODE_FAILED;
    }

    SCLogDebug("sent successfully: %s(%d)->%s(%d) (%u)", ntv->ifsrc->ifname, ntv->ifsrc->ring,
            ntv->ifdst->ifname, ntv->ifdst->ring, GET_PKT_LEN(p));

    /* Instruct netmap to push the data on the TX ring on the destination port */
    ioctl(ntv->ifdst->nmd->fd, NIOCTXSYNC, 0);
    if (ntv->flags & NETMAP_FLAG_EXCL_RING_ACCESS) {
        SCMutexUnlock(&ntv->ifdst->netmap_dev_lock);
    }
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

static void NetmapProcessPacket(NetmapThreadVars *ntv, const struct nm_pkthdr *ph)
{
    if (ntv->bpf_prog.bf_len) {
        struct pcap_pkthdr pkthdr = { {0, 0}, ph->len, ph->len };
        if (pcap_offline_filter(&ntv->bpf_prog, &pkthdr, ph->buf) == 0) {
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
        if (PacketSetData(p, (uint8_t *)ph->buf, ph->len) == -1) {
            TmqhOutputPacketpool(ntv->tv, p);
            return;
        }
    } else {
        if (PacketCopyData(p, (uint8_t *)ph->buf, ph->len) == -1) {
            TmqhOutputPacketpool(ntv->tv, p);
            return;
        }
    }

    p->ReleasePacket = NetmapReleasePacket;
    p->netmap_v.ntv = ntv;

    SCLogDebug("pktlen: %" PRIu32 " (pkt %p, pkt data %p)",
            GET_PKT_LEN(p), p, GET_PKT_DATA(p));

    (void)TmThreadsSlotProcessPkt(ntv->tv, ntv->slot, p);
}

/**
 * \brief Copy netmap rings data into Packet structures.
 * \param *d nmport_d (or nm_desc) netmap if structure.
 * \param cnt int count of packets to read (-1 = all).
 * \param *ntv NetmapThreadVars.
 */
static TmEcode NetmapReadPackets(struct nmport_d *d, int cnt, NetmapThreadVars *ntv)
{
    struct nm_pkthdr hdr;
    int last_ring = d->last_rx_ring - d->first_rx_ring + 1;
    int cur_ring, got = 0, cur_rx_ring = d->cur_rx_ring;

    memset(&hdr, 0, sizeof(hdr));
    hdr.flags = NM_MORE_PKTS;

    if (cnt == 0)
        cnt = -1;

    for (cur_ring = 0; cur_ring < last_ring && cnt != got; cur_ring++, cur_rx_ring++) {
        struct netmap_ring *ring;

        if (cur_rx_ring > d->last_rx_ring)
            cur_rx_ring = d->first_rx_ring;

        ring = NETMAP_RXRING(d->nifp, cur_rx_ring);

        /* cycle through the non-empty ring slots to fetch their data */
        for (; !nm_ring_empty(ring) && cnt != got; got++) {
            u_int idx, i;
            u_char *oldbuf;
            struct netmap_slot *slot;

            if (hdr.buf) { /* from previous round */
                NetmapProcessPacket(ntv, &hdr);
            }

            i = ring->cur;
            slot = &ring->slot[i];
            idx = slot->buf_idx;
            d->cur_rx_ring = cur_rx_ring;
            hdr.slot = slot;
            oldbuf = hdr.buf = (u_char *)NETMAP_BUF(ring, idx);
            hdr.len = hdr.caplen = slot->len;

            /* loop through the ring slots to get packet data */
            while (slot->flags & NS_MOREFRAG) {
                /* packet can be fragmented across multiple slots, */
                /* so loop until we find the slot with the flag    */
                /* cleared, signalling the end of the packet data. */
                u_char *nbuf;
                u_int oldlen = slot->len;
                i = nm_ring_next(ring, i);
                slot = &ring->slot[i];
                hdr.len += slot->len;
                nbuf = (u_char *)NETMAP_BUF(ring, slot->buf_idx);

                if (oldbuf != NULL && nbuf - oldbuf == ring->nr_buf_size &&
                        oldlen == ring->nr_buf_size) {
                    hdr.caplen += slot->len;
                    oldbuf = nbuf;
                } else {
                    oldbuf = NULL;
                }
            }

            hdr.ts = ring->ts;
            ring->head = ring->cur = nm_ring_next(ring, i);
        }
    }

    if (hdr.buf) { /* from previous round */
        hdr.flags = 0;
        NetmapProcessPacket(ntv, &hdr);
    }
    return got;
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

    SCLogDebug("thread %s polling on %d", tv->name, fds.fd);

    // Indicate that the thread is actually running its application level code (i.e., it can poll
    // packets)
    TmThreadsSetFlag(tv, THV_RUNNING);

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
            /* sync counters */
            NetmapDumpCounters(ntv);
            StatsSyncCountersIfSignalled(tv);

            /* poll timed out, lets handle the timeout */
            TmThreadsCaptureHandleTimeout(tv, NULL);
            continue;
        }

        if (unlikely(fds.revents & POLL_EVENTS)) {
            if (fds.revents & POLLERR) {
                SCLogError(SC_ERR_NETMAP_READ,
                        "Error reading netmap data via polling from iface '%s': (%d" PRIu32 ") %s",
                        ntv->ifsrc->ifname, errno, strerror(errno));
            } else if (fds.revents & POLLNVAL) {
                SCLogError(SC_ERR_NETMAP_READ, "Invalid polling request");
            }
            continue;
        }

        if (likely(fds.revents & POLLIN)) {
            /* have data on RX ring, so copy to Packet for processing */
            NetmapReadPackets(ntv->ifsrc->nmd, -1, ntv);
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
 * \param tv Thread local variables.
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
 * \param t pointer to ThreadVars
 * \param p pointer to the current packet
 * \param data pointer that gets cast into NetmapThreadVars for ntv
 */
static TmEcode DecodeNetmap(ThreadVars *tv, Packet *p, void *data)
{
    SCEnter();

    DecodeThreadVars *dtv = (DecodeThreadVars *)data;

    BUG_ON(PKT_IS_PSEUDOPKT(p));

    /* update counters */
    DecodeUpdatePacketCounters(tv, dtv, p);

    DecodeEthernet(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p));

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
