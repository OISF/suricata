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
#include "util-device.h"

int GetIfaceMTU(const char *pcap_dev);
int GetIfaceMaxPacketSize(const char *pcap_dev);
int GetIfaceOffloading(const char *dev, int csum, int other);
int GetIfaceRSSQueuesNum(const char *pcap_dev);
#ifdef SIOCGIFFLAGS
int GetIfaceFlags(const char *ifname);
#endif
#ifdef SIOCSIFFLAGS
int SetIfaceFlags(const char *ifname, int flags);
#endif
#ifdef SIOCGIFCAP
int GetIfaceCaps(const char *ifname);
#endif
#ifdef SIOCSIFCAP
int SetIfaceCaps(const char *ifname, int caps);
#endif
int DisableIfaceOffloading(LiveDevice *dev, int csum, int other);
void RestoreIfaceOffloading(LiveDevice *dev);
