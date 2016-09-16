/* Copyright (C) 2016 Open Information Security Foundation
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
 * \ingroup afppacket
 *
 * @{
 */

/**
 * \file
 *
 * \author Eric Leblond <eric@regit.org>
 *
 * eBPF utility
 *
 */

#define PCAP_DONT_INCLUDE_PCAP_BPF_H 1
#define SC_PCAP_DONT_INCLUDE_PCAP_H 1

#include "suricata-common.h"

#include "util-ebpf.h"

#ifdef HAVE_PACKET_EBPF

#include <linux/bpf.h>
#include <bpf/libbpf.h>
#include "config.h"

#define BPF_MAP_MAX_COUNT 16

#define MAX_ERRNO   4095

#define IS_ERR_VALUE(x) unlikely((x) >= (unsigned long)-MAX_ERRNO)

static inline long IS_ERR(const void *ptr)
{
    return IS_ERR_VALUE((unsigned long)ptr);
}

struct bpf_map_item {
    const char * name;
    int fd;
};

static struct bpf_map_item bpf_map_array[BPF_MAP_MAX_COUNT];
static int bpf_map_last = 0;

int EBPFGetMapFDByName(const char *name)
{
    int i;

    if (name == NULL)
        return -1;
    for (i = 0; i < BPF_MAP_MAX_COUNT; i++) {
        if (!bpf_map_array[i].name)
            continue;
        if (!strcmp(bpf_map_array[i].name, name)) {
            SCLogDebug("Got fd %d for eBPF map '%s'", bpf_map_array[i].fd, name);
            return bpf_map_array[i].fd;
        }
    }
    return -1;
}

int EBPFLoadFile(const char *path, const char * section, int *val)
{
    int err, found, pfd;
    struct bpf_object *bpfobj = NULL;
    struct bpf_program *bpfprog = NULL;
    struct bpf_map *map = NULL;
    /* FIXME we will need to close BPF at exit of runmode */
    if (! path) {
        SCLogError(SC_ERR_INVALID_VALUE, "No file defined to load eBPF from");
        return -1;
    }

    bpfobj = bpf_object__open(path);

    if (IS_ERR(bpfobj)) {
        SCLogError(SC_ERR_INVALID_VALUE,
                   "Unable to load eBPF objects in '%s'",
                   path);
        return -1;
    }

    found = 0;
    bpf_object__for_each_program(bpfprog, bpfobj) {
        const char *title = bpf_program__title(bpfprog, 0);
        if (!strcmp(title, section)) {
            bpf_program__set_type(bpfprog, BPF_PROG_TYPE_SOCKET_FILTER);
            found = 1;
            break;
        }
    }

    if (found == 0) {
        SCLogError(SC_ERR_INVALID_VALUE,
                   "Unable to find eBPF section '%s'",
                   section);
        return -1;
    }
    err = bpf_object__load(bpfobj);

    if (err < 0) {
        if (err == -EPERM) {
            SCLogError(SC_ERR_MEM_ALLOC,
                    "Permission issue when loading eBPF object try to "
                    "increase memlock limit: %s (%d)",
                    strerror(err),
                    err);
        } else {
            SCLogError(SC_ERR_INVALID_VALUE,
                    "Unable to load eBPF object: %s (%d)",
                    strerror(err),
                    err);
        }
        return -1;
    }

    /* store the map in our array */
    bpf_map__for_each(map, bpfobj) {
        SCLogDebug("Got a map '%s' with fd '%d'", bpf_map__name(map), bpf_map__fd(map));
        bpf_map_array[bpf_map_last].fd = bpf_map__fd(map);
        bpf_map_array[bpf_map_last].name = SCStrdup(bpf_map__name(map));
        bpf_map_last++;
        if (bpf_map_last == BPF_MAP_MAX_COUNT) {
            SCLogError(SC_ERR_NOT_SUPPORTED, "Too much BPF map in eBPF files");
            return -1;
        }
    }

    pfd = bpf_program__fd(bpfprog);

    if (pfd == -1) {
        SCLogError(SC_ERR_INVALID_VALUE,
                   "Unable to find %s section", section);
        return -1;
    }

    *val = pfd;
    return 0;
}

int EBPFForEachFlowV4Table(const char *name,
                              int (*FlowCallback)(int fd, struct flowv4_keys *key, struct pair *value, void *data),
                              struct flows_stats *flowstats,
                              void *data)
{
    int mapfd = EBPFGetMapFDByName(name);
    struct flowv4_keys key = {}, next_key;
    struct pair value = {0, 0, 0};
    int ret, found = 0;
    if (bpf_map__get_next_key(mapfd, &key, &next_key) != 0) {
        return found;
    }
    while (bpf_map__get_next_key(mapfd, &key, &next_key) == 0) {
        bpf_map__lookup_elem(mapfd, &key, &value);
        ret = FlowCallback(mapfd, &key, &value, data);
        if (ret) {
            flowstats->count++;
            flowstats->packets += value.packets;
            flowstats->bytes += value.bytes;
            found = 1;
        }
        key = next_key;
    }

    bpf_map__lookup_elem(mapfd, &key, &value);
    ret = FlowCallback(mapfd, &key, &value, data);
    if (ret) {
        flowstats->count++;
        flowstats->packets += value.packets;
        flowstats->bytes += value.bytes;
        found = 1;
    }

    return found;
}

void EBPFDeleteKey(int fd, void *key)
{
    bpf_map__delete_elem(fd, key);
}

#endif
