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
            (!strcmp("lo", pcap_dev)))
        return ETHERNET_HEADER_LEN;

    if (!strcmp("ppp", pcap_dev))
        return SLL_HEADER_LEN;
    /* SLL_HEADER_LEN is the biggest one */
    return SLL_HEADER_LEN;
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
                "Failure when trying to get MTU via ioctl: %d",
                errno);
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
    int ll_header = GetIfaceMaxHWHeaderLength(pcap_dev);
    int mtu = 0;

    if ((pcap_dev == NULL) || strlen(pcap_dev) == 0)
        return 0;

    mtu = GetIfaceMTU(pcap_dev);
    switch (mtu) {
        case 0:
        case -1:
            return 0;
    }
    if (ll_header == -1) {
        /* be conservative, choose a big one */
        ll_header = 16;
    }
    return ll_header + mtu;
}

/**
 * \brief output offloading status of the link
 *
 * Test interface for GRO and LRO features. If one of them is
 * activated then suricata mays received packets merge at reception.
 * The result is oversized packets and this may cause some serious
 * problem in some capture mode where the size of the packet is
 * limited (AF_PACKET in V2 more for example).
 *
 * ETHTOOL_GGRO ETH_FLAG_LRO
 *
 * \param Name of link
 * \retval -1 in case of error, 0 if none, 1 if some
 */
int GetIfaceOffloading(const char *pcap_dev)
{
#if defined (ETHTOOL_GGRO) && defined (ETHTOOL_GFLAGS)
    struct ifreq ifr;
    int fd;
    struct ethtool_value ethv;
    int ret = 0;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        return -1;
    }
    (void)strlcpy(ifr.ifr_name, pcap_dev, sizeof(ifr.ifr_name));

    /* First get GRO */
    ethv.cmd = ETHTOOL_GGRO;
    ifr.ifr_data = (void *) &ethv;
    if (ioctl(fd, SIOCETHTOOL, (char *)&ifr) < 0) {
        SCLogWarning(SC_ERR_SYSCALL,
                  "Failure when trying to get feature via ioctl: %s (%d)",
                  strerror(errno), errno);
        close(fd);
        return -1;
    } else {
        if (ethv.data) {
            SCLogInfo("Generic Receive Offload is set on %s", pcap_dev);
            ret = 1;
        } else {
            SCLogInfo("Generic Receive Offload is unset on %s", pcap_dev);
        }
    }

    /* Then get LRO which is set in a flag */
    ethv.data = 0;
    ethv.cmd = ETHTOOL_GFLAGS;
    ifr.ifr_data = (void *) &ethv;
    if (ioctl(fd, SIOCETHTOOL, (char *)&ifr) < 0) {
        SCLogWarning(SC_ERR_SYSCALL,
                  "Failure when trying to get feature via ioctl: %s (%d)",
                  strerror(errno), errno);
        close(fd);
        return -1;
    } else {
        if (ethv.data & ETH_FLAG_LRO) {
            SCLogInfo("Large Receive Offload is set on %s", pcap_dev);
            ret = 1;
        } else {
            SCLogInfo("Large Receive Offload is unset on %s", pcap_dev);
        }
    }

    close(fd);

    return ret;
#else
    /* ioctl is not defined, let's pretend returning 0 is ok */
    return 0;
#endif
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
                "Failure when opening socket for ioctl: %d",
                errno);
        return -1;
    }

    nfccmd.cmd = ETHTOOL_GRXRINGS;
    ifr.ifr_data = (void*) &nfccmd;

    if (ioctl(fd, SIOCETHTOOL, (char *)&ifr) < 0) {
        if (errno != ENOTSUP) {
            SCLogWarning(SC_ERR_SYSCALL,
                         "Failure when trying to get number of RSS queue ioctl: %d",
                         errno);
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
