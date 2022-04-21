/* Copyright (C) 2022 Open Information Security Foundation
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
 * \author Lukas Sismis <sismis@cesnet.com>
 *
 */

#ifndef SURICATA_PREFILTER_H
#define SURICATA_PREFILTER_H

#define _POSIX_C_SOUCRE 200809L

#include <rte_eal.h>

#include "dev-conf.h"

struct main_ring {
    uint16_t ring_from_pf_arr_len;
    struct rte_ring **ring_from_pf_arr;
    uint16_t ring_to_pf_arr_len;
    struct rte_ring **ring_to_pf_arr;
};

struct resource_ctx {
    uint16_t main_rings_cnt;
    struct main_ring *main_rings;
    struct pf_stats *app_stats;
};

#endif // SURICATA_PREFILTER_H
