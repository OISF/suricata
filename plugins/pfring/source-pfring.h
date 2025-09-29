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
 * \author William Metcalf <william.metcalf@gmail.com>
 */

#ifndef SURICATA_SOURCE_PFRING_H
#define SURICATA_SOURCE_PFRING_H

#define PFRING_IFACE_NAME_LENGTH 48

typedef struct PfringThreadVars_ PfringThreadVars;

/* PfringIfaceConfig flags */
#define PFRING_CONF_FLAGS_CLUSTER (1 << 0)
#define PFRING_CONF_FLAGS_BYPASS  (1 << 1)

typedef struct PfringIfaceConfig_ {
    uint32_t flags;

    /* cluster param */
    int cluster_id;
    unsigned int ctype;

    char iface[PFRING_IFACE_NAME_LENGTH];
    /* number of threads */
    uint16_t threads;

    const char *bpf_filter;

    ChecksumValidationMode checksum_mode;
    SC_ATOMIC_DECLARE(unsigned int, ref);
    void (*DerefFunc)(void *);
} PfringIfaceConfig;

/**
 * \brief per packet Pfring vars
 *
 * This structure is used to pass packet metadata in callbacks.
 */
typedef struct PfringPacketVars_ {
    PfringThreadVars *ptv;
    uint32_t flow_id;
} PfringPacketVars;

void TmModuleReceivePfringRegister(int slot);
void TmModuleDecodePfringRegister(int slot);

int PfringConfGetThreads(void);
void PfringLoadConfig(void);

/*
 * We don't have to use an enum that sucks in our code
 * these values must match with cluster_type in the kernel
 * include file pf_ring.h
 */
#define CLUSTER_FLOW               0
#define CLUSTER_ROUND_ROBIN        1
#define CLUSTER_FLOW_5_TUPLE       4
#define CLUSTER_INNER_FLOW         6
#define CLUSTER_INNER_FLOW_2_TUPLE 7
#define CLUSTER_INNER_FLOW_4_TUPLE 8
#define CLUSTER_INNER_FLOW_5_TUPLE 9
#endif /* SURICATA_SOURCE_PFRING_H */
