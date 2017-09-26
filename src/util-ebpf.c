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
#include <bpf/bpf.h>
#include <net/if.h>
#include "config.h"

#define BPF_MAP_MAX_COUNT 16

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

#define bpf__is_error(ee) ee
#define bpf__get_error(ee) 1

int EBPFLoadFile(const char *path, const char * section, int *val, uint8_t flags)
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

    if (libbpf_get_error(bpfobj)) {
        char err_buf[128];
        libbpf_strerror(bpf__get_error(bpfobj), err_buf,
                        sizeof(err_buf));
        SCLogError(SC_ERR_INVALID_VALUE,
                   "Unable to load eBPF objects in '%s': %s",
                   path, err_buf);
        return -1;
    }

    found = 0;
    bpf_object__for_each_program(bpfprog, bpfobj) {
        const char *title = bpf_program__title(bpfprog, 0);
        if (!strcmp(title, section)) {
            if (flags & EBPF_SOCKET_FILTER) {
                bpf_program__set_socket_filter(bpfprog);
            } else {
                bpf_program__set_xdp(bpfprog);
            }
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

int EBPFSetupXDP(const char *iface, int fd)
{
    unsigned int ifindex = if_nametoindex(iface);
    if (ifindex == 0) {
        SCLogError(SC_ERR_INVALID_VALUE,
                "Unknown interface '%s'", iface);
        return -1;
    } else {
        /* Fix me use option to set XDP_FLAGS_SKB_MODE  or XDP_FLAGS_DRV_MODE */
        bpf_set_link_xdp_fd(ifindex, fd, 2);
    }
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
    if (bpf_map_get_next_key(mapfd, &key, &next_key) != 0) {
        return found;
    }
    while (bpf_map_get_next_key(mapfd, &key, &next_key) == 0) {
        bpf_map_lookup_elem(mapfd, &key, &value);
        ret = FlowCallback(mapfd, &key, &value, data);
        if (ret) {
            flowstats->count++;
            flowstats->packets += value.packets;
            flowstats->bytes += value.bytes;
            found = 1;
        }
        key = next_key;
    }

    bpf_map_lookup_elem(mapfd, &key, &value);
    ret = FlowCallback(mapfd, &key, &value, data);
    if (ret) {
        flowstats->count++;
        flowstats->packets += value.packets;
        flowstats->bytes += value.bytes;
        found = 1;
    }

    return found;
}

int EBPFForEachFlowV6Table(const char *name,
                              int (*FlowCallback)(int fd, struct flowv6_keys *key, struct pair *value, void *data),
                              struct flows_stats *flowstats,
                              void *data)
{
    int mapfd = EBPFGetMapFDByName(name);
    struct flowv6_keys key = {}, next_key;
    struct pair value = {0, 0, 0};
    int ret, found = 0;
    if (bpf_map_get_next_key(mapfd, &key, &next_key) != 0) {
        return found;
    }
    while (bpf_map_get_next_key(mapfd, &key, &next_key) == 0) {
        bpf_map_lookup_elem(mapfd, &key, &value);
        ret = FlowCallback(mapfd, &key, &value, data);
        if (ret) {
            flowstats->count++;
            flowstats->packets += value.packets;
            flowstats->bytes += value.bytes;
            found = 1;
        }
        key = next_key;
    }

    bpf_map_lookup_elem(mapfd, &key, &value);
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
    bpf_map_delete_elem(fd, key);
}

#endif
