/* Copyright (C) 2007-2022 Open Information Security Foundation
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
 * \author William Metcalf <william.metcalf@gmail.com>
 */

#ifndef __SOURCE_PFRING_H__
#define __SOURCE_PFRING_H__

#define PFRING_IFACE_NAME_LENGTH 48

typedef struct PfringThreadVars_ PfringThreadVars;

/* PfringIfaceConfig flags */
#define PFRING_CONF_FLAGS_CLUSTER (1 << 0)
#define PFRING_CONF_FLAGS_BYPASS  (1 << 1)

typedef struct PfringIfaceConfig_
{
    uint32_t flags;

    /* cluster param */
    int cluster_id;
    unsigned int ctype;

    char iface[PFRING_IFACE_NAME_LENGTH];
    /* number of threads */
    int threads;

    char *bpf_filter;

    ChecksumValidationMode checksum_mode;
    SC_ATOMIC_DECLARE(unsigned int, ref);
    void (*DerefFunc)(void *);
} PfringIfaceConfig;

/**
 * \brief per packet Pfring vars
 *
 * This structure is used to pass packet metadata in callbacks.
 */
typedef struct PfringPacketVars_
{
    PfringThreadVars *ptv;
    uint32_t flow_id;
} PfringPacketVars;


void TmModuleReceivePfringRegister (void);
void TmModuleDecodePfringRegister (void);

int PfringConfGetThreads(void);
void PfringLoadConfig(void);

/* We don't have to use an enum that sucks in our code */
#define CLUSTER_FLOW 0
#define CLUSTER_ROUND_ROBIN 1
#define CLUSTER_FLOW_5_TUPLE 4
#endif /* __SOURCE_PFRING_H__ */
