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

#ifndef __SOURCE_PFRING_H__
#define __SOURCE_PFRING_H__

#define PFRING_IFACE_NAME_LENGTH 48

#define PFRING_RING_PROTECT (1<<0)

#define PFRING_COPY_MODE_NONE   0
#define PFRING_COPY_MODE_TAP    1
#define PFRING_COPY_MODE_IPS    2

#include <config.h>
#ifdef HAVE_PFRING
#include <pfring.h>
#endif

typedef struct PfringIfaceConfig_
{
    /* cluster param */
    int cluster_id;
#ifdef HAVE_PFRING
    cluster_type ctype;
#endif
    char iface[PFRING_IFACE_NAME_LENGTH];
    /* number of threads */
    int threads;

    char *bpf_filter;

    int copy_mode;
    char *out_interface;
    int flush_packet;

    ChecksumValidationMode checksum_mode;
    SC_ATOMIC_DECLARE(unsigned int, ref);
    void (*DerefFunc)(void *);
} PfringIfaceConfig;

typedef struct PfringPeer_ {
    char iface[PFRING_IFACE_NAME_LENGTH];
#ifdef HAVE_PFRING
    pfring *pd;
#endif
    SCMutex ring_protect;
    int flags;
    int turn;
    struct PfringPeer_ *peer;
    TAILQ_ENTRY(PfringPeer_) next;
} PfringPeer;

typedef struct PfringPacketVars_
{
    int copy_mode;
    int flush_packet;
    PfringPeer *peer;
    PfringPeer *mpeer;
} PfringPacketVars;

void TmModuleReceivePfringRegister (void);
void TmModuleDecodePfringRegister (void);

TmEcode PfringPeersListInit();
TmEcode PfringPeersListCheck();
void PfringPeersListClean();

int PfringConfGetThreads(void);
void PfringLoadConfig(void);

/* We don't have to use an enum that sucks in our code */
#define CLUSTER_FLOW 0
#define CLUSTER_ROUND_ROBIN 1
#define CLUSTER_FLOW_5_TUPLE 4
#endif /* __SOURCE_PFRING_H__ */
