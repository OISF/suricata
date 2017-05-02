/* Copyright (C) 2014 Open Information Security Foundation
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
* \author Aleksey Katargin <gureedo@gmail.com>
*/

#ifndef __SOURCE_NETMAP_H__
#define __SOURCE_NETMAP_H__

#include "queue.h"

/* copy modes */
enum {
    NETMAP_COPY_MODE_NONE,
    NETMAP_COPY_MODE_TAP,
    NETMAP_COPY_MODE_IPS,
};

#define NETMAP_IFACE_NAME_LENGTH    48

typedef struct NetmapIfaceSettings_
{
    /* real inner interface name */
    char iface[NETMAP_IFACE_NAME_LENGTH];

    int threads;
    /* sw ring flag for out_iface */
    int sw_ring;
    int promisc;
    int copy_mode;
    ChecksumValidationMode checksum_mode;
    const char *bpf_filter;
} NetmapIfaceSettings;

typedef struct NetmapIfaceConfig_
{
    /* semantic interface name */
    char iface_name[NETMAP_IFACE_NAME_LENGTH];

    /* settings for out capture device*/
    NetmapIfaceSettings in;

    /* semantic interface name */
    char *out_iface_name;

    /* settings for outgoing iface for IPS/TAP */
    NetmapIfaceSettings out;

    SC_ATOMIC_DECLARE(unsigned int, ref);
    void (*DerefFunc)(void *);
} NetmapIfaceConfig;

typedef struct NetmapPacketVars_
{
    int ring_id;
    int slot_id;
    int dst_ring_id;
    /* NetmapThreadVars */
    void *ntv;
} NetmapPacketVars;

int NetmapGetRSSCount(const char *ifname);

void TmModuleReceiveNetmapRegister (void);
void TmModuleDecodeNetmapRegister (void);

#endif /* __SOURCE_NETMAP_H__ */
