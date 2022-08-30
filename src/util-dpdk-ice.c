/* Copyright (C) 2021-2022 Open Information Security Foundation
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
 *  \defgroup dpdk DPDK Intel ICE driver helpers functions
 *
 *  @{
 */

/**
 * \file
 *
 * \author Lukas Sismis <lukas.sismis@gmail.com>
 *
 * DPDK driver's helper functions
 *
 */

#include "util-dpdk-ice.h"

#ifdef HAVE_DPDK

void iceDeviceSetRSSHashFunction(uint64_t *rss_hf)
{
    if (RTE_VER_YEAR <= 19)
        *rss_hf = ETH_RSS_FRAG_IPV4 | ETH_RSS_NONFRAG_IPV4_OTHER | ETH_RSS_FRAG_IPV6 |
                  ETH_RSS_NONFRAG_IPV6_OTHER;
    else
        *rss_hf = ETH_RSS_IPV4 | ETH_RSS_FRAG_IPV4 | ETH_RSS_NONFRAG_IPV4_OTHER | ETH_RSS_IPV6 |
                  ETH_RSS_FRAG_IPV6 | ETH_RSS_NONFRAG_IPV6_OTHER;
}

#endif /* HAVE_DPDK */
/**
 * @}
 */
