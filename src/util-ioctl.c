/* Copyright (C) 2010 Open Information Security Foundation
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
 */

#include "suricata-common.h"
#include "conf.h"

#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#ifdef HAVE_LINUX_ETHTOOL_H
#include <linux/types.h>
#include <linux/ethtool.h>
#ifdef HAVE_LINUX_SOCKIOS_H
#include <linux/sockios.h>
#else
#error "ethtool.h present but sockios.h is missing"
#endif /* HAVE_LINUX_SOCKIOS_H */
#endif /* HAVE_LINUX_ETHTOOL_H */

#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif

/**
 * \brief output a majorant of hardware header length
 *
 * \param Name of a network interface
 */
int GetIfaceMaxHWHeaderLength(const char *pcap_dev)
{
    if ((!strcmp("eth", pcap_dev))
            ||
            (!strcmp("br", pcap_dev))
            ||
            (!strcmp("bond", pcap_dev))
            ||
            (!strcmp("wlan", pcap_dev))
            ||
            (!strcmp("tun", pcap_dev))
            ||
            (!strcmp("tap", pcap_dev))
            ||
            (!strcmp("lo", pcap_dev))) {
        /* Add possible VLAN tag or Qing headers */
        return 8 + ETHERNET_HEADER_LEN;
    }

    if (!strcmp("ppp", pcap_dev))
        return SLL_HEADER_LEN;
    /* SLL_HEADER_LEN is the biggest one and
       add possible VLAN tag and Qing headers */
    return 8 + SLL_HEADER_LEN;
}

/**
 * \brief output the link MTU
 *
 * \param Name of link
 * \retval -1 in case of error, 0 if MTU can not be found
 */
int GetIfaceMTU(const char *pcap_dev)
{
#ifdef SIOCGIFMTU
    struct ifreq ifr;
    int fd;

    (void)strlcpy(ifr.ifr_name, pcap_dev, sizeof(ifr.ifr_name));
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        return -1;
    }

    if (ioctl(fd, SIOCGIFMTU, (char *)&ifr) < 0) {
        SCLogWarning(SC_ERR_SYSCALL,
                "Failure when trying to get MTU via ioctl for '%s': %s (%d)",
                pcap_dev, strerror(errno), errno);
        close(fd);
        return -1;
    }
    close(fd);
    SCLogInfo("Found an MTU of %d for '%s'", ifr.ifr_mtu,
            pcap_dev);
    return ifr.ifr_mtu;
#else
    /* ioctl is not defined, let's pretend returning 0 is ok */
    return 0;
#endif
}

/**
 * \brief output max packet size for a link
 *
 * This does a best effort to find the maximum packet size
 * for the link. In case of uncertainty, it will output a
 * majorant to be sure avoid the cost of dynamic allocation.
 *
 * \param Name of a network interface
 * \retval 0 in case of error
 */
int GetIfaceMaxPacketSize(const char *pcap_dev)
{
    if ((pcap_dev == NULL) || strlen(pcap_dev) == 0)
        return 0;

    int mtu = GetIfaceMTU(pcap_dev);
    switch (mtu) {
        case 0:
        case -1:
            return 0;
    }
    int ll_header = GetIfaceMaxHWHeaderLength(pcap_dev);
    if (ll_header == -1) {
        /* be conservative, choose a big one */
        ll_header = 16;
    }
    return ll_header + mtu;
}

#if defined HAVE_LINUX_ETHTOOL_H && defined SIOCETHTOOL
static int GetEthtoolValue(const char *dev, int cmd, uint32_t *value)
{
    struct ifreq ifr;
    int fd;
    struct ethtool_value ethv;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        return -1;
    }
    (void)strlcpy(ifr.ifr_name, dev, sizeof(ifr.ifr_name));

    ethv.cmd = cmd;
    ifr.ifr_data = (void *) &ethv;
    if (ioctl(fd, SIOCETHTOOL, (char *)&ifr) < 0) {
        SCLogWarning(SC_ERR_SYSCALL,
                  "Failure when trying to get feature via ioctl for '%s': %s (%d)",
                  dev, strerror(errno), errno);
        close(fd);
        return -1;
    }

    *value = ethv.data;
    close(fd);
    return 0;
}

static int GetIfaceOffloadingLinux(const char *dev)
{
    int ret = 0;
    char *lro = "unset", *gro = "unset", *tso = "unset", *gso = "unset";
    char *sg = "unset";
    uint32_t value = 0;

#ifdef ETHTOOL_GGRO
    if (GetEthtoolValue(dev, ETHTOOL_GGRO, &value) == 0 && value != 0) {
        gro = "SET";
        ret = 1;
    }
#endif
#ifdef ETHTOOL_GTSO
    if (GetEthtoolValue(dev, ETHTOOL_GTSO, &value) == 0 && value != 0) {
        tso = "SET";
        ret = 1;
    }
#endif
#ifdef ETHTOOL_GGSO
    if (GetEthtoolValue(dev, ETHTOOL_GGSO, &value) == 0 && value != 0) {
        gso = "SET";
        ret = 1;
    }
#endif
#ifdef ETHTOOL_GSG
    if (GetEthtoolValue(dev, ETHTOOL_GSG, &value) == 0 && value != 0) {
        sg = "SET";
        ret = 1;
    }
#endif
#ifdef ETHTOOL_GFLAGS
    if (GetEthtoolValue(dev, ETHTOOL_GFLAGS, &value) == 0) {
        if (value & ETH_FLAG_LRO) {
            lro = "SET";
            ret = 1;
        }
    }
#endif
    SCLogInfo("NIC offloading on %s: SG: %s, GRO: %s, LRO: %s, "
            "TSO: %s, GSO: %s", dev, sg, gro, lro, tso, gso);
    return ret;
}

#endif /* defined HAVE_LINUX_ETHTOOL_H && defined SIOCETHTOOL */

/**
 * \brief output offloading status of the link
 *
 * Test interface for offloading features. If one of them is
 * activated then suricata mays received packets merge at reception.
 * The result is oversized packets and this may cause some serious
 * problem in some capture mode where the size of the packet is
 * limited (AF_PACKET in V2 more for example).
 *
 * \param Name of link
 * \retval -1 in case of error, 0 if none, 1 if some
 */
int GetIfaceOffloading(const char *dev)
{
#if defined HAVE_LINUX_ETHTOOL_H && defined SIOCETHTOOL
    return GetIfaceOffloadingLinux(dev);
#endif
    return 0;
}

int GetIfaceRSSQueuesNum(const char *pcap_dev)
{
#if defined HAVE_LINUX_ETHTOOL_H && defined ETHTOOL_GRXRINGS
    struct ifreq ifr;
    struct ethtool_rxnfc nfccmd;
    int fd;

    (void)strlcpy(ifr.ifr_name, pcap_dev, sizeof(ifr.ifr_name));
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        SCLogWarning(SC_ERR_SYSCALL,
                "Failure when opening socket for ioctl: %s (%d)",
                strerror(errno), errno);
        return -1;
    }

    nfccmd.cmd = ETHTOOL_GRXRINGS;
    ifr.ifr_data = (void*) &nfccmd;

    if (ioctl(fd, SIOCETHTOOL, (char *)&ifr) < 0) {
        if (errno != ENOTSUP) {
            SCLogWarning(SC_ERR_SYSCALL,
                         "Failure when trying to get number of RSS queue ioctl for '%s': %s (%d)",
                         pcap_dev, strerror(errno), errno);
        }
        close(fd);
        return 0;
    }
    close(fd);
    SCLogInfo("Found %d RX RSS queues for '%s'", (int)nfccmd.data,
            pcap_dev);
    return (int)nfccmd.data;
#else
    return 0;
#endif
}
