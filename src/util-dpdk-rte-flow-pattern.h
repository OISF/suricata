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
 *  \defgroup dpdk DPDK rte_flow rules util functions
 *
 *  @{
 */

/**
 * \file
 *
 * \author Adam Kiripolsky <adam.kiripolsky@cesnet.cz>
 *
 * DPDK rte_flow rules util functions
 *
 */

#ifndef SURICATA_RTE_FLOW_RULES_PATTERN_H
#define SURICATA_RTE_FLOW_RULES_PATTERN_H

#ifdef HAVE_DPDK

#include "util-dpdk.h"
#include <rte_ethdev.h>

int ParsePattern(char *pattern, uint8_t *data, unsigned int size, struct rte_flow_item **items);

#endif /* HAVE_DPDK */
#endif /* SURICATA_RTE_FLOW_RULES_PATTERN_H */
/**
 * @}
 */
