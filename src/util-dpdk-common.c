/* Copyright (C) 2025 Open Information Security Foundation
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
 * \author Lukas Sismis <lukas.sismis@oisf.net>
 */

#include "suricata-common.h"
#include "util-debug.h"
#include "util-dpdk-common.h"

#ifdef HAVE_DPDK

int DPDKDeviceResourcesInit(DPDKDeviceResources **dpdk_vars, uint16_t mp_cnt)
{
    SCEnter();
    *dpdk_vars = SCCalloc(1, sizeof(*dpdk_vars[0]));
    if (*dpdk_vars == NULL) {
        SCLogError("failed to allocate memory for packet mempools structure");
        SCReturnInt(-ENOMEM);
    }

    (*dpdk_vars)->pkt_mp = SCCalloc(mp_cnt, sizeof((*dpdk_vars)->pkt_mp[0]));
    if ((*dpdk_vars)->pkt_mp == NULL) {
        SCLogError("failed to allocate memory for packet mempools");
        SCReturnInt(-ENOMEM);
    }
    (*dpdk_vars)->pkt_mp_capa = mp_cnt;
    (*dpdk_vars)->pkt_mp_cnt = 0;

    SCReturnInt(0);
}

void DPDKDeviceResourcesDeinit(DPDKDeviceResources **dpdk_vars)
{
    if ((*dpdk_vars) != NULL) {
        if ((*dpdk_vars)->pkt_mp != NULL) {
            for (int j = 0; j < (*dpdk_vars)->pkt_mp_capa; j++) {
                if ((*dpdk_vars)->pkt_mp[j] != NULL) {
                    rte_mempool_free((*dpdk_vars)->pkt_mp[j]);
                }
            }
            SCFree((*dpdk_vars)->pkt_mp);
            (*dpdk_vars)->pkt_mp_capa = 0;
            (*dpdk_vars)->pkt_mp_cnt = 0;
            (*dpdk_vars)->pkt_mp = NULL;
        }
        SCFree(*dpdk_vars);
        *dpdk_vars = NULL;
    }
}

#endif /* HAVE_DPDK */