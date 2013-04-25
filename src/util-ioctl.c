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
 * \author Eric Leblond <eleblond@edenwall.com>
 */

#include "suricata-common.h"
#include "conf.h"

#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif

/**
 * \brief output a majorant of hardware header length
 *
 * \param Name of a network interface
 */
int GetIfaceMaxHWHeaderLength(char *pcap_dev)
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
            (!strcmp("lo", pcap_dev))
       )
        return ETHERNET_HEADER_LEN;
    if (
            (!strcmp("ppp", pcap_dev))
       )
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
int GetIfaceMTU(char *pcap_dev)
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
        SCLogInfo("Failure when trying to get MTU via ioctl: %d",
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
int GetIfaceMaxPacketSize(char *pcap_dev)
{
    int ll_header = GetIfaceMaxHWHeaderLength(pcap_dev);
    int mtu = GetIfaceMTU(pcap_dev);
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
