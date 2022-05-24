/* Copyright (C) 2018 Open Information Security Foundation
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
 * \author Eric Leblond <eric@regit.org>
 */

#ifndef __UTIL_EBPF_H__
#define __UTIL_EBPF_H__

#include "flow-bypass.h"

#ifdef HAVE_PACKET_EBPF

#define XDP_FLAGS_UPDATE_IF_NOEXIST	(1U << 0)
#define XDP_FLAGS_SKB_MODE		(1U << 1)
#define XDP_FLAGS_DRV_MODE		(1U << 2)
#define XDP_FLAGS_HW_MODE		(1U << 3)


struct flowv4_keys {
    __be32 src;
    __be32 dst;
    union {
        __be32 ports;
        __be16 port16[2];
    };
    __u8 ip_proto:1;
    __u16 vlan0:15;
    __u16 vlan1;
};

struct flowv6_keys {
    __be32 src[4];
    __be32 dst[4];
    union {
        __be32 ports;
        __be16 port16[2];
    };
    __u8 ip_proto:1;
    __u16 vlan0:15;
    __u16 vlan1;
};

struct pair {
    uint64_t packets;
    uint64_t bytes;
};

typedef struct EBPFBypassData_ {
    void *key[2];
    int mapfd;
    int cpus_count;
} EBPFBypassData;

#define EBPF_SOCKET_FILTER  (1<<0)
#define EBPF_XDP_CODE       (1<<1)
#define EBPF_PINNED_MAPS    (1<<2)
#define EBPF_XDP_HW_MODE    (1<<3)

int EBPFGetMapFDByName(const char *iface, const char *name);
int EBPFLoadFile(const char *iface, const char *path, const char * section,
                 int *val, struct ebpf_timeout_config *config);
int EBPFSetupXDP(const char *iface, int fd, uint8_t flags);

int EBPFCheckBypassedFlowTimeout(ThreadVars *th_v, struct flows_stats *bypassstats,
                                        struct timespec *curtime,
                                        void *data);
int EBPFCheckBypassedFlowCreate(ThreadVars *th_v, struct timespec *curtime, void *data);

void EBPFRegisterExtension(void);

void EBPFBuildCPUSet(ConfNode *node, char *iface);

int EBPFSetPeerIface(const char *iface, const char *out_iface);

int EBPFUpdateFlow(Flow *f, Packet *p, void *data);
bool EBPFBypassUpdate(Flow *f, void *data, time_t tsec, void *mpc);
void EBPFBypassFree(void *data);

void EBPFDeleteKey(int fd, void *key);

#ifdef BUILD_UNIX_SOCKET
TmEcode EBPFGetBypassedStats(json_t *cmd, json_t *answer, void *data);
#endif

#define __bpf_percpu_val_align  __attribute__((__aligned__(8)))

#define BPF_DECLARE_PERCPU(type, name, nr_cpus)                          \
        struct { type v; /* padding */ } __bpf_percpu_val_align \
                name[nr_cpus]
#define BPF_PERCPU(name, cpu) name[(cpu)].v


#endif

#endif
