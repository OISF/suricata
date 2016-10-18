/* Copyright (C) 2007-2010 Open Information Security Foundation
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
 * \author Vipin Varghese <vipinpv85@gmail.com>
 */

#ifndef __SOURCE_DPDK_H__
#define __SOURCE_DPDK_H__

#define PFRING_IFACE_NAME_LENGTH 48

#include "rte_launch.h"
#include <config.h>

#include "rte_config.h"
#include "rte_ethdev.h"
#include "rte_ether.h"
#include "rte_branch_prediction.h"

#include "util-atomic.h"


#define DPDKINTEL_IFACE_NAME_LENGTH 5
#define PREFETCH_OFFSET             4

typedef int32_t (*launchPtr) (__attribute__((unused)) void *arg);

typedef struct DpdkIntelIfaceConfig
{
    char iface[DPDKINTEL_IFACE_NAME_LENGTH];

    /* number of threads */
    int threads;

    /* ring size in number of packets */
    int ringSize;
    int ringBufferId;
    
    uint8_t checksumMode;
    uint8_t promiscous;

    /* cluster param */
    int cluster_id;
    int cluster_type;

    /* misc use flags including ring mode */
    int flags;
    int copy_mode;

    char *bpfFilter;
    char *outIface;

    SC_ATOMIC_DECLARE(unsigned int, ref);
} DpdkIntelIfaceConfig_t;



void TmModuleReceiveDpdkRegister (void);
void TmModuleDecodeDpdkRegister (void);

int PfringConfGetThreads(void);
void PfringLoadConfig(void);

int32_t launchDpdkFrameParser(void);
int32_t ReceiveDpdkPkts_IPS(__attribute__((unused)) void *arg);
int32_t ReceiveDpdkPkts_IDS(__attribute__((unused)) void *arg);
int32_t ReceiveDpdkPkts_BYPASS(__attribute__((unused)) void *arg);
int32_t ReceiveDpdkPkts_IPS_10_100(__attribute__((unused)) void *arg);
int32_t ReceiveDpdkPkts_IPS_1000(__attribute__((unused)) void *arg);
int32_t ReceiveDpdkPkts_IPS_10000(__attribute__((unused)) void *arg);
#endif /* __SOURCE_DPDKINTEL_H__ */
