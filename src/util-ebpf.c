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
#include "flow-bypass.h"

#ifdef HAVE_PACKET_EBPF

#include <sys/time.h>
#include <sys/resource.h>

#include "util-ebpf.h"
#include "util-cpu.h"
#include "util-device.h"

#include "device-storage.h"

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include "config.h"

#define BPF_MAP_MAX_COUNT 16

#define BYPASSED_FLOW_TIMEOUT   60

static int g_livedev_storage_id = -1;

struct bpf_map_item {
    char * name;
    int fd;
};

struct bpf_maps_info {
    struct bpf_map_item array[BPF_MAP_MAX_COUNT];
    int last;
};

static void BpfMapsInfoFree(void *bpf)
{
    struct bpf_maps_info *bpfinfo = (struct bpf_maps_info *)bpf;
    int i;
    for (i = 0; i < bpfinfo->last; i ++) {
        if (bpfinfo->array[i].name) {
            SCFree(bpfinfo->array[i].name);
        }
    }
    SCFree(bpfinfo);
}

static void EBPFDeleteKey(int fd, void *key)
{
    bpf_map_delete_elem(fd, key);
}

static struct bpf_maps_info *EBPFGetBpfMap(const char *iface)
{
    LiveDevice *livedev = LiveGetDevice(iface);
    if (livedev == NULL)
        return NULL;
    void *data = LiveDevGetStorageById(livedev, g_livedev_storage_id);

    return (struct bpf_maps_info *)data;
}

int EBPFGetMapFDByName(const char *iface, const char *name)
{
    int i;

    if (iface == NULL || name == NULL)
        return -1;
    struct bpf_maps_info *bpf_maps = EBPFGetBpfMap(iface);
    if (bpf_maps == NULL)
        return -1;

    for (i = 0; i < BPF_MAP_MAX_COUNT; i++) {
        if (!bpf_maps->array[i].name)
            continue;
        if (!strcmp(bpf_maps->array[i].name, name)) {
            SCLogDebug("Got fd %d for eBPF map '%s'", bpf_maps->array[i].fd, name);
            return bpf_maps->array[i].fd;
        }
    }
    return -1;
}

/** 
 * Load a section of an eBPF file
 *
 * This function loads a section inside an eBPF and return
 * via a parameter the file descriptor that will be used to
 * inject the eBPF code into the kernel via a syscall.
 *
 * \param path the path of the eBPF file to load
 * \param section the section in the eBPF file to load
 * \param val a pointer to an integer that will be the file desc
 * \return -1 in case of error and 0 in case of success
 */
int EBPFLoadFile(const char *iface, const char *path, const char * section,
                 int *val, uint8_t flags)
{
    int err, pfd;
    bool found = false;
    struct bpf_object *bpfobj = NULL;
    struct bpf_program *bpfprog = NULL;
    struct bpf_map *map = NULL;

    if (iface == NULL)
        return -1;
    LiveDevice *livedev = LiveGetDevice(iface);
    if (livedev == NULL)
        return -1;

    if (! path) {
        SCLogError(SC_ERR_INVALID_VALUE, "No file defined to load eBPF from");
        return -1;
    }

    /* Sending the eBPF code to the kernel requires a large amount of
     * locked memory so we set it to unlimited to avoid a ENOPERM error */
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &r) != 0) {
        SCLogError(SC_ERR_MEM_ALLOC, "Unable to lock memory: %s (%d)",
                   strerror(errno), errno);
        return -1;
    }

    bpfobj = bpf_object__open(path);
    long error = libbpf_get_error(bpfobj);
    if (error) {
        char err_buf[128];
        libbpf_strerror(error, err_buf,
                        sizeof(err_buf));
        SCLogError(SC_ERR_INVALID_VALUE,
                   "Unable to load eBPF objects in '%s': %s",
                   path, err_buf);
        return -1;
    }

    bpf_object__for_each_program(bpfprog, bpfobj) {
        const char *title = bpf_program__title(bpfprog, 0);
        if (!strcmp(title, section)) {
            if (flags & EBPF_SOCKET_FILTER) {
                bpf_program__set_socket_filter(bpfprog);
            } else {
                bpf_program__set_xdp(bpfprog);
            }
            found = true;
            break;
        }
    }

    if (found == false) {
        SCLogError(SC_ERR_INVALID_VALUE,
                   "No section '%s' in '%s' file. Will not be able to use the file",
                   section,
                   path);
        return -1;
    }

    err = bpf_object__load(bpfobj);
    if (err < 0) {
        if (err == -EPERM) {
            SCLogError(SC_ERR_MEM_ALLOC,
                    "Permission issue when loading eBPF object: "
                    "%s (%d)",
                    strerror(err),
                    err);
        } else {
            char buf[129];
            libbpf_strerror(err, buf, sizeof(buf));
            SCLogError(SC_ERR_INVALID_VALUE,
                    "Unable to load eBPF object: %s (%d)",
                    buf,
                    err);
        }
        return -1;
    }

    struct bpf_maps_info *bpf_map_data = SCCalloc(1, sizeof(*bpf_map_data));
    if (bpf_map_data == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Can't allocate bpf map array");
        return -1;
    }

    /* store the map in our array */
    bpf_map__for_each(map, bpfobj) {
        if (bpf_map_data->last == BPF_MAP_MAX_COUNT) {
            SCLogError(SC_ERR_NOT_SUPPORTED, "Too many BPF maps in eBPF files");
            break;
        }
        SCLogDebug("Got a map '%s' with fd '%d'", bpf_map__name(map), bpf_map__fd(map));
        bpf_map_data->array[bpf_map_data->last].fd = bpf_map__fd(map);
        bpf_map_data->array[bpf_map_data->last].name = SCStrdup(bpf_map__name(map));
        if (!bpf_map_data->array[bpf_map_data->last].name) {
            SCLogError(SC_ERR_MEM_ALLOC, "Unable to duplicate map name");
            BpfMapsInfoFree(bpf_map_data);
            return -1;
        }
        bpf_map_data->last++;
    }

    LiveDevSetStorageById(livedev, g_livedev_storage_id, bpf_map_data);

    pfd = bpf_program__fd(bpfprog);
    if (pfd == -1) {
        SCLogError(SC_ERR_INVALID_VALUE,
                   "Unable to find %s section", section);
        return -1;
    }

    *val = pfd;
    return 0;
}


int EBPFSetupXDP(const char *iface, int fd, uint8_t flags)
{
#ifdef HAVE_PACKET_XDP
    unsigned int ifindex = if_nametoindex(iface);
    if (ifindex == 0) {
        SCLogError(SC_ERR_INVALID_VALUE,
                "Unknown interface '%s'", iface);
        return -1;
    }
    int err = bpf_set_link_xdp_fd(ifindex, fd, flags);
    if (err != 0) {
        char buf[129];
        libbpf_strerror(err, buf, sizeof(buf));
        SCLogError(SC_ERR_INVALID_VALUE, "Unable to set XDP on '%s': %s (%d)",
                iface, buf, err);
        return -1;
    }
#endif
    return 0;
}


static int EBPFForEachFlowV4Table(const char *iface, const char *name,
                              int (*FlowCallback)(int fd, struct flowv4_keys *key, struct pair *value, void *data),
                              struct flows_stats *flowstats,
                              void *data)
{
    int mapfd = EBPFGetMapFDByName(iface, name);
    struct flowv4_keys key = {}, next_key;
    int found = 0;
    unsigned int i;
    unsigned int nr_cpus = UtilCpuGetNumProcessorsConfigured();
    if (nr_cpus == 0) {
        SCLogWarning(SC_ERR_INVALID_VALUE, "Unable to get CPU count");
        return 0;
    }

    while (bpf_map_get_next_key(mapfd, &key, &next_key) == 0) {
        int iret = 1;
        uint64_t pkts_cnt = 0;
        uint64_t bytes_cnt = 0;
        struct pair values_array[nr_cpus];
        memset(values_array, 0, sizeof(values_array));
        int res = bpf_map_lookup_elem(mapfd, &key, values_array);
        if (res < 0) {
            SCLogDebug("no entry in v4 table for %d -> %d", key.port16[0], key.port16[1]);
            key = next_key;
            continue;
        }
        for (i = 0; i < nr_cpus; i++) {
            int ret = FlowCallback(mapfd, &key, &values_array[i], data);
            if (ret) {
                /* no packet for the flow on this CPU, let's start accumulating
                   value we can compute the counters */
                SCLogDebug("%d:%lu: Adding pkts %lu bytes %lu", i, values_array[i].time / 1000000000,
                            values_array[i].packets, values_array[i].bytes);
                pkts_cnt += values_array[i].packets;
                bytes_cnt += values_array[i].bytes;
            } else {
                /* Packet seen on one CPU so we keep the flow */
                iret = 0;
                break;
            }
        }
        /* No packet seen, we discard the flow  and do accounting */
        if (iret) {
            SCLogDebug("Got no packet for %d -> %d", key.port16[0], key.port16[1]);
            SCLogDebug("Dead with pkts %lu bytes %lu", pkts_cnt, bytes_cnt);
            flowstats->count++;
            flowstats->packets += pkts_cnt;
            flowstats->bytes += bytes_cnt;
            found = 1;
            EBPFDeleteKey(mapfd, &key);
        }
        key = next_key;
    }

    return found;
}

static int EBPFForEachFlowV6Table(const char *iface, const char *name,
                              int (*FlowCallback)(int fd, struct flowv6_keys *key, struct pair *value, void *data),
                              struct flows_stats *flowstats,
                              void *data)
{
    int mapfd = EBPFGetMapFDByName(iface, name);
    struct flowv6_keys key = {}, next_key;
    int found = 0;
    unsigned int i;
    unsigned int nr_cpus = UtilCpuGetNumProcessorsConfigured();
    if (nr_cpus == 0) {
        SCLogWarning(SC_ERR_INVALID_VALUE, "Unable to get CPU count");
        return 0;
    }

    while (bpf_map_get_next_key(mapfd, &key, &next_key) == 0) {
        int iret = 1;
        uint64_t pkts_cnt = 0;
        uint64_t bytes_cnt = 0;
        struct pair values_array[nr_cpus];
        memset(values_array, 0, sizeof(values_array));
        int res = bpf_map_lookup_elem(mapfd, &key, values_array);
        if (res < 0) {
            SCLogDebug("no entry in v6 table for %d -> %d", key.port16[0], key.port16[1]);
            key = next_key;
            continue;
        }
        for (i = 0; i < nr_cpus; i++) {
            int ret = FlowCallback(mapfd, &key, &values_array[i], data);
            if (ret) {
                pkts_cnt += values_array[i].packets;
                bytes_cnt += values_array[i].bytes;
            } else {
                iret = 0;
                break;
            }
        }
        if (iret) {
            flowstats->count++;
            flowstats->packets += pkts_cnt;
            flowstats->bytes += bytes_cnt;
            found = 1;
            EBPFDeleteKey(mapfd, &key);
        }
        key = next_key;
    }

    return found;
}

static int EBPFBypassedFlowV4Timeout(int fd, struct flowv4_keys *key, struct pair *value, void *data)
{
    struct timespec *curtime = (struct timespec *)data;
    SCLogDebug("Got curtime %" PRIu64 " and value %" PRIu64 " (sp:%d, dp:%d) %u",
               curtime->tv_sec, value->time / 1000000000,
               key->port16[0], key->port16[1], key->ip_proto
              );

    if (curtime->tv_sec - value->time / 1000000000 > BYPASSED_FLOW_TIMEOUT) {
        SCLogDebug("Got no packet for %d -> %d at %" PRIu64,
                   key->port16[0], key->port16[1], value->time);
        return 1;
    }
    return 0;
}

static int EBPFBypassedFlowV6Timeout(int fd, struct flowv6_keys *key, struct pair *value, void *data)
{
    struct timespec *curtime = (struct timespec *)data;
    SCLogDebug("Got curtime %" PRIu64 " and value %" PRIu64 " (sp:%d, dp:%d)",
               curtime->tv_sec, value->time / 1000000000,
               key->port16[0], key->port16[1]
              );

    if (curtime->tv_sec - value->time / 1000000000 > BYPASSED_FLOW_TIMEOUT) {
        SCLogDebug("Got no packet for %d -> %d at %" PRIu64,
                   key->port16[0], key->port16[1], value->time);
        return 1;
    }
    return 0;
}

int EBPFCheckBypassedFlowTimeout(struct flows_stats *bypassstats,
                                        struct timespec *curtime)
{
    struct flows_stats l_bypassstats = { 0, 0, 0};
    int ret = 0;
    int tcount = 0;
    LiveDevice *ldev = NULL, *ndev;

    while(LiveDeviceForEach(&ldev, &ndev)) {
        tcount = EBPFForEachFlowV4Table(ldev->dev, "flow_table_v4", EBPFBypassedFlowV4Timeout,
                &l_bypassstats, curtime);
        if (tcount) {
            bypassstats->count = l_bypassstats.count;
            bypassstats->packets = l_bypassstats.packets ;
            bypassstats->bytes = l_bypassstats.bytes;
            ret = 1;
        }
        memset(&l_bypassstats, 0, sizeof(l_bypassstats));
        tcount = EBPFForEachFlowV6Table(ldev->dev, "flow_table_v6", EBPFBypassedFlowV6Timeout,
                &l_bypassstats, curtime);
        if (tcount) {
            bypassstats->count += l_bypassstats.count;
            bypassstats->packets += l_bypassstats.packets ;
            bypassstats->bytes += l_bypassstats.bytes;
            ret = 1;
        }
    }
    return ret;
}

void EBPFRegisterExtension(void)
{
    g_livedev_storage_id = LiveDevStorageRegister("bpfmap", sizeof(void *), NULL, BpfMapsInfoFree);
}


#ifdef HAVE_PACKET_XDP

static uint32_t g_redirect_iface_cpu_counter = 0;

static int EBPFAddCPUToMap(const char *iface, uint32_t i)
{
    int cpumap = EBPFGetMapFDByName(iface, "cpu_map");
    uint32_t queue_size = 4096;
    int ret;

    if (cpumap < 0) {
        SCLogError(SC_ERR_AFP_CREATE, "Can't find cpu_map");
        return -1;
    }
    ret = bpf_map_update_elem(cpumap, &i, &queue_size, 0);
    if (ret) {
        SCLogError(SC_ERR_AFP_CREATE, "Create CPU entry failed (err:%d)", ret);
        return -1;
    }
    int cpus_available = EBPFGetMapFDByName(iface, "cpus_available");
    if (cpus_available < 0) {
        SCLogError(SC_ERR_AFP_CREATE, "Can't find cpus_available map");
        return -1;
    }

    ret = bpf_map_update_elem(cpus_available, &g_redirect_iface_cpu_counter, &i, 0);
    if (ret) {
        SCLogError(SC_ERR_AFP_CREATE, "Create CPU entry failed (err:%d)", ret);
        return -1;
    }
    return 0;
}

static void EBPFRedirectMapAddCPU(int i, void *data)
{
    if (EBPFAddCPUToMap(data, i) < 0) {
        SCLogError(SC_ERR_INVALID_VALUE,
                "Unable to add CPU %d to set", i);
    } else {
        g_redirect_iface_cpu_counter++;
    }
}

void EBPFBuildCPUSet(ConfNode *node, char *iface)
{
    uint32_t key0 = 0;
    int mapfd = EBPFGetMapFDByName(iface, "cpus_count");
    if (mapfd < 0) {
        SCLogError(SC_ERR_INVALID_VALUE,
                "Unable to find 'cpus_count' map");
        return;
    }
    g_redirect_iface_cpu_counter = 0;
    if (node == NULL) {
        bpf_map_update_elem(mapfd, &key0, &g_redirect_iface_cpu_counter,
                        BPF_ANY);
        return;
    }
    BuildCpusetWithCallback("xdp-cpu-redirect", node,
            EBPFRedirectMapAddCPU,
            iface);
    bpf_map_update_elem(mapfd, &key0, &g_redirect_iface_cpu_counter,
                        BPF_ANY);
}

#endif /* HAVE_PACKET_XDP */

#endif
