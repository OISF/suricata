/* Copyright (C) 2018-2021 Open Information Security Foundation
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
#include "util-affinity.h"
#include "util-cpu.h"
#include "util-device.h"

#include "device-storage.h"
#include "flow-storage.h"
#include "flow.h"
#include "flow-hash.h"
#include "tm-threads.h"

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include "autoconf.h"

#define BPF_MAP_MAX_COUNT 16

#define BYPASSED_FLOW_TIMEOUT   60

static LiveDevStorageId g_livedev_storage_id = { .id = -1 };
static FlowStorageId g_flow_storage_id = { .id = -1 };

struct bpf_map_item {
    char iface[IFNAMSIZ];
    char * name;
    int fd;
    uint8_t to_unlink;
};

struct bpf_maps_info {
    struct bpf_map_item array[BPF_MAP_MAX_COUNT];
    int last;
};

typedef struct BypassedIfaceList_ {
    LiveDevice *dev;
    struct BypassedIfaceList_ *next;
} BypassedIfaceList;

static void BpfMapsInfoFree(void *bpf)
{
    struct bpf_maps_info *bpfinfo = (struct bpf_maps_info *)bpf;
    int i;
    for (i = 0; i < bpfinfo->last; i ++) {
        if (bpfinfo->array[i].name) {
            if (bpfinfo->array[i].to_unlink) {
                char pinnedpath[PATH_MAX];
                int ret = snprintf(pinnedpath, sizeof(pinnedpath),
                        "/sys/fs/bpf/suricata-%s-%s",
                        bpfinfo->array[i].iface,
                        bpfinfo->array[i].name);
                if (ret > 0) {
                    /* Unlink the pinned entry */
                    ret = unlink(pinnedpath);
                    if (ret == -1) {
                        int error = errno;
                        SCLogWarning(SC_ERR_SYSCALL,
                                     "Unable to remove %s: %s (%d)",
                                     pinnedpath,
                                     strerror(error),
                                     error);
                    }
                } else {
                    SCLogWarning(SC_ERR_SPRINTF, "Unable to remove map %s",
                                 bpfinfo->array[i].name);
                }
            }
            SCFree(bpfinfo->array[i].name);
        }
    }
    SCFree(bpfinfo);
}

static void BypassedListFree(void *ifl)
{
    BypassedIfaceList *mifl = (BypassedIfaceList *)ifl;
    BypassedIfaceList *nifl;
    while (mifl) {
        nifl = mifl->next;
        SCFree(mifl);
        mifl = nifl;
    }
}

void EBPFDeleteKey(int fd, void *key)
{
    int ret = bpf_map_delete_elem(fd, key);
    if (ret < 0) {
        SCLogWarning(SC_ERR_SYSCALL,
                     "Unable to delete entry: %s (%d)",
                     strerror(errno),
                     errno);
    }
}

static struct bpf_maps_info *EBPFGetBpfMap(const char *iface)
{
    LiveDevice *livedev = LiveGetDevice(iface);
    if (livedev == NULL)
        return NULL;
    void *data = LiveDevGetStorageById(livedev, g_livedev_storage_id);

    return (struct bpf_maps_info *)data;
}

/**
 * Get file descriptor of a map in the scope of a interface
 *
 * \param iface the interface where the map need to be looked for
 * \param name the name of the map
 * \return the file descriptor or -1 in case of error
 */
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

static int EBPFLoadPinnedMapsFile(LiveDevice *livedev, const char *file)
{
    char pinnedpath[1024];
    snprintf(pinnedpath, sizeof(pinnedpath),
            "/sys/fs/bpf/suricata-%s-%s",
            livedev->dev,
            file);

    return bpf_obj_get(pinnedpath);
}

static int EBPFLoadPinnedMaps(LiveDevice *livedev, struct ebpf_timeout_config *config)
{
    int fd_v4 = -1, fd_v6 = -1;

    /* First try to load the eBPF check map and return if found */
    if (config->pinned_maps_name) {
        int ret = EBPFLoadPinnedMapsFile(livedev, config->pinned_maps_name);
        if (ret == 0) {
            /* pinned maps found, let's just exit as XDP filter is in place */
            return ret;
        }
    }

    if (config->mode == AFP_MODE_XDP_BYPASS) {
        /* Get flow v4 table */
        fd_v4 = EBPFLoadPinnedMapsFile(livedev, "flow_table_v4");
        if (fd_v4 < 0) {
            return fd_v4;
        }

        /* Get flow v6 table */
        fd_v6 = EBPFLoadPinnedMapsFile(livedev, "flow_table_v6");
        if (fd_v6 < 0) {
            SCLogWarning(SC_ERR_INVALID_ARGUMENT,
                    "Found a flow_table_v4 map but no flow_table_v6 map");
            return fd_v6;
        }
    }

    struct bpf_maps_info *bpf_map_data = SCCalloc(1, sizeof(*bpf_map_data));
    if (bpf_map_data == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Can't allocate bpf map array");
        return -1;
    }

    if (config->mode == AFP_MODE_XDP_BYPASS) {
        bpf_map_data->array[0].fd = fd_v4;
        bpf_map_data->array[0].name = SCStrdup("flow_table_v4");
        if (bpf_map_data->array[0].name == NULL) {
            goto alloc_error;
        }
        bpf_map_data->array[1].fd = fd_v6;
        bpf_map_data->array[1].name = SCStrdup("flow_table_v6");
        if (bpf_map_data->array[1].name == NULL) {
            goto alloc_error;
        }
        bpf_map_data->last = 2;
    } else {
        bpf_map_data->last = 0;
    }

    /* Load other known maps: cpu_map, cpus_available, tx_peer, tx_peer_int */
    int fd = EBPFLoadPinnedMapsFile(livedev, "cpu_map");
    if (fd >= 0) {
        bpf_map_data->array[bpf_map_data->last].fd = fd;
        bpf_map_data->array[bpf_map_data->last].name = SCStrdup("cpu_map");
        if (bpf_map_data->array[bpf_map_data->last].name == NULL) {
            goto alloc_error;
        }
        bpf_map_data->last++;
    }
    fd = EBPFLoadPinnedMapsFile(livedev, "cpus_available");
    if (fd >= 0) {
        bpf_map_data->array[bpf_map_data->last].fd = fd;
        bpf_map_data->array[bpf_map_data->last].name = SCStrdup("cpus_available");
        if (bpf_map_data->array[bpf_map_data->last].name == NULL) {
            goto alloc_error;
        }
        bpf_map_data->last++;
    }
    fd = EBPFLoadPinnedMapsFile(livedev, "tx_peer");
    if (fd >= 0) {
        bpf_map_data->array[bpf_map_data->last].fd = fd;
        bpf_map_data->array[bpf_map_data->last].name = SCStrdup("tx_peer");
        if (bpf_map_data->array[bpf_map_data->last].name == NULL) {
            goto alloc_error;
        }
        bpf_map_data->last++;
    }
    fd = EBPFLoadPinnedMapsFile(livedev, "tx_peer_int");
    if (fd >= 0) {
        bpf_map_data->array[bpf_map_data->last].fd = fd;
        bpf_map_data->array[bpf_map_data->last].name = SCStrdup("tx_peer_int");
        if (bpf_map_data->array[bpf_map_data->last].name == NULL) {
            goto alloc_error;
        }
        bpf_map_data->last++;
    }

    /* Attach the bpf_maps_info to the LiveDevice via the device storage */
    LiveDevSetStorageById(livedev, g_livedev_storage_id, bpf_map_data);
    /* Declare that device will use bypass stats */
    LiveDevUseBypass(livedev);

    return 0;

alloc_error:
    for (int i = 0; i < bpf_map_data->last; i++) {
        SCFree(bpf_map_data->array[i].name);
    }
    bpf_map_data->last = 0;
    SCLogError(SC_ERR_MEM_ALLOC, "Can't allocate bpf map name");
    return -1;
}

/**
 * Load a section of an eBPF file
 *
 * This function loads a section inside an eBPF and return
 * via the parameter val the file descriptor that will be used to
 * inject the eBPF code into the kernel via a syscall.
 *
 * \param path the path of the eBPF file to load
 * \param section the section in the eBPF file to load
 * \param val a pointer to an integer that will be the file desc
 * \return -1 in case of error, 0 in case of success, 1 if pinned maps is loaded
 */
int EBPFLoadFile(const char *iface, const char *path, const char * section,
                 int *val, struct ebpf_timeout_config *config)
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

    if (config->flags & EBPF_XDP_CODE && config->flags & EBPF_PINNED_MAPS) {
        /* We try to get our flow table maps and if we have them we can simply return */
        if (EBPFLoadPinnedMaps(livedev, config) == 0) {
            SCLogInfo("Loaded pinned maps, will use already loaded eBPF filter");
            return 1;
        }
    }

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

    /* Open the eBPF file and parse it */
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

    if (config->flags & EBPF_XDP_HW_MODE) {
        unsigned int ifindex = if_nametoindex(iface);
        bpf_object__for_each_program(bpfprog, bpfobj) {
            bpf_program__set_ifindex(bpfprog, ifindex);
        }
        bpf_map__for_each(map, bpfobj) {
            bpf_map__set_ifindex(map, ifindex);
        }
    }

    /* Let's check that our section is here */
    bpf_object__for_each_program(bpfprog, bpfobj) {
#ifdef HAVE_BPF_PROGRAM__SECTION_NAME
        const char *title = bpf_program__section_name(bpfprog);
#else
        const char *title = bpf_program__title(bpfprog, 0);
#endif
        if (!strcmp(title, section)) {
            if (config->flags & EBPF_SOCKET_FILTER) {
#ifdef HAVE_BPF_PROGRAM__SET_TYPE
                bpf_program__set_type(bpfprog, BPF_PROG_TYPE_SOCKET_FILTER);
#else
                /* Fall back to legacy API */
                bpf_program__set_socket_filter(bpfprog);
#endif
            } else {
#ifdef HAVE_BPF_PROGRAM__SET_TYPE
                bpf_program__set_type(bpfprog, BPF_PROG_TYPE_XDP);
#else
                /* Fall back to legacy API */
                bpf_program__set_xdp(bpfprog);
#endif
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
            SCLogError(SC_ERR_SYSCALL,
                    "Permission issue when loading eBPF object"
                    " (check libbpf error on stdout)");
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

    /* Kernel and userspace are sharing data via map. Userspace access to the
     * map via a file descriptor. So we need to store the map to fd info. For
     * that we use bpf_maps_info:: */
    struct bpf_maps_info *bpf_map_data = SCCalloc(1, sizeof(*bpf_map_data));
    if (bpf_map_data == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Can't allocate bpf map array");
        return -1;
    }

    /* Store the maps in bpf_maps_info:: */
    bpf_map__for_each(map, bpfobj) {
        if (bpf_map_data->last == BPF_MAP_MAX_COUNT) {
            SCLogError(SC_ERR_NOT_SUPPORTED, "Too many BPF maps in eBPF files");
            break;
        }
        SCLogDebug("Got a map '%s' with fd '%d'", bpf_map__name(map), bpf_map__fd(map));
        bpf_map_data->array[bpf_map_data->last].fd = bpf_map__fd(map);
        bpf_map_data->array[bpf_map_data->last].name = SCStrdup(bpf_map__name(map));
        snprintf(bpf_map_data->array[bpf_map_data->last].iface, IFNAMSIZ,
                 "%s", iface);
        if (!bpf_map_data->array[bpf_map_data->last].name) {
            SCLogError(SC_ERR_MEM_ALLOC, "Unable to duplicate map name");
            BpfMapsInfoFree(bpf_map_data);
            return -1;
        }
        bpf_map_data->array[bpf_map_data->last].to_unlink = 0;
        if (config->flags & EBPF_PINNED_MAPS) {
            SCLogConfig("Pinning: %d to %s", bpf_map_data->array[bpf_map_data->last].fd,
                    bpf_map_data->array[bpf_map_data->last].name);
            char buf[1024];
            snprintf(buf, sizeof(buf), "/sys/fs/bpf/suricata-%s-%s", iface,
                    bpf_map_data->array[bpf_map_data->last].name);
            int ret = bpf_obj_pin(bpf_map_data->array[bpf_map_data->last].fd, buf);
            if (ret != 0) {
                SCLogWarning(SC_ERR_AFP_CREATE, "Can not pin: %s", strerror(errno));
            }
            /* Don't unlink pinned maps in XDP mode to avoid a state reset */
            if (config->flags & EBPF_XDP_CODE) {
                bpf_map_data->array[bpf_map_data->last].to_unlink = 0;
            } else {
                bpf_map_data->array[bpf_map_data->last].to_unlink = 1;
            }
        }
        bpf_map_data->last++;
    }

    /* Attach the bpf_maps_info to the LiveDevice via the device storage */
    LiveDevSetStorageById(livedev, g_livedev_storage_id, bpf_map_data);
    LiveDevUseBypass(livedev);

    /* Finally we get the file descriptor for our eBPF program. We will use
     * the fd to attach the program to the socket (eBPF case) or to the device
     * (XDP case). */
    pfd = bpf_program__fd(bpfprog);
    if (pfd == -1) {
        SCLogError(SC_ERR_INVALID_VALUE,
                   "Unable to find %s section", section);
        return -1;
    }

    SCLogInfo("Successfully loaded eBPF file '%s' on '%s'", path, iface);
    *val = pfd;
    return 0;
}

/**
 * Attach a XDP program identified by its file descriptor to a device
 *
 * \param iface the name of interface
 * \param fd the eBPF/XDP program file descriptor
 * \param a flag to pass to attach function mostly used to set XDP mode
 * \return -1 in case of error, 0 if success
 */
int EBPFSetupXDP(const char *iface, int fd, uint8_t flags)
{
#ifdef HAVE_PACKET_XDP
    unsigned int ifindex = if_nametoindex(iface);
    if (ifindex == 0) {
        SCLogError(SC_ERR_INVALID_VALUE,
                "Unknown interface '%s'", iface);
        return -1;
    }
#ifdef HAVE_BPF_XDP_ATTACH
    int err = bpf_xdp_attach(ifindex, fd, flags, NULL);
#else
    /* Fall back to legacy API */
    int err = bpf_set_link_xdp_fd(ifindex, fd, flags);
#endif
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

/**
 * Create a Flow in the table for a Flowkey
 *
 * \return false (this create function never returns true)
 */
static bool EBPFCreateFlowForKey(struct flows_stats *flowstats, LiveDevice *dev, void *key,
                                 size_t skey, FlowKey *flow_key, struct timespec *ctime,
                                 uint64_t pkts_cnt, uint64_t bytes_cnt,
                                 int mapfd, int cpus_count)
{
    Flow *f = NULL;
    uint32_t hash = FlowKeyGetHash(flow_key);

    f = FlowGetFromFlowKey(flow_key, ctime, hash);
    if (f == NULL)
        return false;

    /* set accounting, we can't know the direction, so let's just start to
     * server then if we already have something in to server to client. We need
     * these numbers as we will use it to see if we have new traffic coming
     * on the flow */
    FlowBypassInfo *fc = FlowGetStorageById(f, GetFlowBypassInfoID());
    if (fc == NULL) {
        fc = SCCalloc(sizeof(FlowBypassInfo), 1);
        if (fc) {
            FlowUpdateState(f, FLOW_STATE_CAPTURE_BYPASSED);
            FlowSetStorageById(f, GetFlowBypassInfoID(), fc);
            fc->BypassUpdate = EBPFBypassUpdate;
            fc->BypassFree = EBPFBypassFree;
            fc->todstpktcnt = pkts_cnt;
            fc->todstbytecnt = bytes_cnt;
            f->livedev = dev;
            EBPFBypassData *eb = SCCalloc(1, sizeof(EBPFBypassData));
            if (eb == NULL) {
                SCFree(fc);
                FLOWLOCK_UNLOCK(f);
                return false;
            }
            void *mkey = SCCalloc(1, skey);
            if (mkey == NULL) {
                SCFree(fc);
                SCFree(eb);
                FLOWLOCK_UNLOCK(f);
                return false;
            }
            memcpy(mkey, key, skey);
            eb->key[0] = mkey;
            eb->mapfd = mapfd;
            eb->cpus_count = cpus_count;
            fc->bypass_data = eb;
            flowstats->count++;
        } else {
            FLOWLOCK_UNLOCK(f);
            return false;
        }
    } else {
        EBPFBypassData *eb = (EBPFBypassData *) fc->bypass_data;
        if (eb == NULL) {
            FLOWLOCK_UNLOCK(f);
            return false;
        }
        /* if both keys are here, then it is a flow bypassed by this
         * instance so we ignore it */
        if (eb->key[0] && eb->key[1]) {
            FLOWLOCK_UNLOCK(f);
            return false;
        }
        fc->tosrcpktcnt = pkts_cnt;
        fc->tosrcbytecnt = bytes_cnt;
        void *mkey = SCCalloc(1, skey);
        if (mkey == NULL) {
            FLOWLOCK_UNLOCK(f);
            return false;
        }
        memcpy(mkey, key, skey);
        eb->key[1] = mkey;
    }
    f->livedev = dev;
    FLOWLOCK_UNLOCK(f);
    return false;
}

void EBPFBypassFree(void *data)
{
    EBPFBypassData *eb = (EBPFBypassData *)data;
    if (eb == NULL)
        return;
    SCFree(eb->key[0]);
    if (eb->key[1]) {
        SCFree(eb->key[1]);
    }
    SCFree(eb);
    return;
}

/**
 *
 * Compare eBPF half flow to Flow
 *
 * \return true if entries have activity, false if not
 */

static bool EBPFBypassCheckHalfFlow(Flow *f, FlowBypassInfo *fc,
                                    EBPFBypassData *eb, void *key,
                                    int index)
{
    int i;
    uint64_t pkts_cnt = 0;
    uint64_t bytes_cnt = 0;
    /* We use a per CPU structure so we will get a array of values. But if nr_cpus
     * is 1 then we have a global hash. */
    BPF_DECLARE_PERCPU(struct pair, values_array, eb->cpus_count);
    memset(values_array, 0, sizeof(values_array));
    int res = bpf_map_lookup_elem(eb->mapfd, key, values_array);
    if (res < 0) {
        SCLogDebug("errno: (%d) %s", errno, strerror(errno));
        return false;
    }
    for (i = 0; i < eb->cpus_count; i++) {
        /* let's start accumulating value so we can compute the counters */
        SCLogDebug("%d: Adding pkts %lu bytes %lu", i,
                BPF_PERCPU(values_array, i).packets,
                BPF_PERCPU(values_array, i).bytes);
        pkts_cnt += BPF_PERCPU(values_array, i).packets;
        bytes_cnt += BPF_PERCPU(values_array, i).bytes;
    }
    if (index == 0) {
        if (pkts_cnt != fc->todstpktcnt) {
            fc->todstpktcnt = pkts_cnt;
            fc->todstbytecnt = bytes_cnt;
            return true;
        }
    } else {
        if (pkts_cnt != fc->tosrcpktcnt) {
            fc->tosrcpktcnt = pkts_cnt;
            fc->tosrcbytecnt = bytes_cnt;
            return true;
        }
    }

    return false;
}

/** Check both half flows for update
 *
 * Update lastts in the flow and do accounting
 *
 * */
bool EBPFBypassUpdate(Flow *f, void *data, time_t tsec)
{
    EBPFBypassData *eb = (EBPFBypassData *)data;
    if (eb == NULL) {
        return false;
    }
    FlowBypassInfo *fc = FlowGetStorageById(f, GetFlowBypassInfoID());
    if (fc == NULL) {
        return false;
    }
    bool activity = EBPFBypassCheckHalfFlow(f, fc, eb, eb->key[0], 0);
    activity |= EBPFBypassCheckHalfFlow(f, fc, eb, eb->key[1], 1);
    if (!activity) {
        SCLogDebug("Delete entry: %u (%ld)", FLOW_IS_IPV6(f), FlowGetId(f));
        /* delete the entries if no time update */
        EBPFDeleteKey(eb->mapfd, eb->key[0]);
        EBPFDeleteKey(eb->mapfd, eb->key[1]);
        SCLogDebug("Done delete entry: %u", FLOW_IS_IPV6(f));
    } else {
        f->lastts.tv_sec = tsec;
        return true;
    }
    return false;
}

typedef bool (*OpFlowForKey)(struct flows_stats * flowstats, LiveDevice*dev, void *key,
                            size_t skey, FlowKey *flow_key, struct timespec *ctime,
                            uint64_t pkts_cnt, uint64_t bytes_cnt,
                            int mapfd, int cpus_count);

/**
 * Bypassed flows iterator for IPv4
 *
 * This function iterates on all the flows of the IPv4 table
 * running a callback function on each flow.
 */
static int EBPFForEachFlowV4Table(ThreadVars *th_v, LiveDevice *dev, const char *name,
                                  struct timespec *ctime,
                                  struct ebpf_timeout_config *tcfg,
                                  OpFlowForKey EBPFOpFlowForKey
                                  )
{
    struct flows_stats flowstats = { 0, 0, 0};
    int mapfd = EBPFGetMapFDByName(dev->dev, name);
    if (mapfd == -1)
        return -1;

    struct flowv4_keys key = {}, next_key;
    int found = 0;
    unsigned int i;
    uint64_t hash_cnt = 0;

    if (tcfg->cpus_count == 0) {
        return 0;
    }

    bool dead_flow = false;
    while (bpf_map_get_next_key(mapfd, &key, &next_key) == 0) {
        uint64_t bytes_cnt = 0;
        uint64_t pkts_cnt = 0;
        hash_cnt++;
        if (dead_flow) {
            EBPFDeleteKey(mapfd, &key);
            dead_flow = false;
        }
        /* We use a per CPU structure so we will get a array of values. But if nr_cpus
         * is 1 then we have a global hash. */
        BPF_DECLARE_PERCPU(struct pair, values_array, tcfg->cpus_count);
        memset(values_array, 0, sizeof(values_array));
        int res = bpf_map_lookup_elem(mapfd, &next_key, values_array);
        if (res < 0) {
            SCLogDebug("no entry in v4 table for %d -> %d", key.port16[0], key.port16[1]);
            SCLogDebug("errno: (%d) %s", errno, strerror(errno));
            key = next_key;
            continue;
        }
        for (i = 0; i < tcfg->cpus_count; i++) {
            /* let's start accumulating value so we can compute the counters */
            SCLogDebug("%d: Adding pkts %lu bytes %lu", i,
                       BPF_PERCPU(values_array, i).packets,
                       BPF_PERCPU(values_array, i).bytes);
            pkts_cnt += BPF_PERCPU(values_array, i).packets;
            bytes_cnt += BPF_PERCPU(values_array, i).bytes;
        }
        /* Get the corresponding Flow in the Flow table to compare and update
         * its counters and lastseen if needed */
        FlowKey flow_key;
        if (tcfg->mode == AFP_MODE_XDP_BYPASS) {
            flow_key.sp = ntohs(next_key.port16[0]);
            flow_key.dp = ntohs(next_key.port16[1]);
            flow_key.src.addr_data32[0] = next_key.src;
            flow_key.dst.addr_data32[0] = next_key.dst;
        } else {
            flow_key.sp = next_key.port16[0];
            flow_key.dp = next_key.port16[1];
            flow_key.src.addr_data32[0] = ntohl(next_key.src);
            flow_key.dst.addr_data32[0] = ntohl(next_key.dst);
        }
        flow_key.src.family = AF_INET;
        flow_key.src.addr_data32[1] = 0;
        flow_key.src.addr_data32[2] = 0;
        flow_key.src.addr_data32[3] = 0;
        flow_key.dst.family = AF_INET;
        flow_key.dst.addr_data32[1] = 0;
        flow_key.dst.addr_data32[2] = 0;
        flow_key.dst.addr_data32[3] = 0;
        flow_key.vlan_id[0] = next_key.vlan0;
        flow_key.vlan_id[1] = next_key.vlan1;
        flow_key.vlan_id[2] = next_key.vlan2;
        if (next_key.ip_proto == 1) {
            flow_key.proto = IPPROTO_TCP;
        } else {
            flow_key.proto = IPPROTO_UDP;
        }
        flow_key.recursion_level = 0;
        dead_flow = EBPFOpFlowForKey(&flowstats, dev, &next_key, sizeof(next_key), &flow_key,
                                     ctime, pkts_cnt, bytes_cnt,
                                     mapfd, tcfg->cpus_count);
        if (dead_flow) {
            found = 1;
        }

        if (TmThreadsCheckFlag(th_v, THV_KILL)) {
            return 0;
        }

        key = next_key;
    }
    if (dead_flow) {
        EBPFDeleteKey(mapfd, &key);
        found = 1;
    }
    SC_ATOMIC_ADD(dev->bypassed, flowstats.packets);

    LiveDevAddBypassStats(dev, flowstats.count, AF_INET);
    SCLogInfo("IPv4 bypassed flow table size: %" PRIu64, hash_cnt);

    return found;
}

/**
 * Bypassed flows iterator for IPv6
 *
 * This function iterates on all the flows of the IPv4 table
 * running a callback function on each flow.
 */
static int EBPFForEachFlowV6Table(ThreadVars *th_v,
                                  LiveDevice *dev, const char *name,
                                  struct timespec *ctime,
                                  struct ebpf_timeout_config *tcfg,
                                  OpFlowForKey EBPFOpFlowForKey
                                  )
{
    struct flows_stats flowstats = { 0, 0, 0};
    int mapfd = EBPFGetMapFDByName(dev->dev, name);
    if (mapfd == -1)
        return -1;

    struct flowv6_keys key = {}, next_key;
    int found = 0;
    unsigned int i;
    uint64_t hash_cnt = 0;

    if (tcfg->cpus_count == 0) {
        SCLogWarning(SC_ERR_INVALID_VALUE, "CPU count should not be 0");
        return 0;
    }

    uint64_t pkts_cnt = 0;
    while (bpf_map_get_next_key(mapfd, &key, &next_key) == 0) {
        uint64_t bytes_cnt = 0;
        hash_cnt++;
        if (pkts_cnt > 0) {
            EBPFDeleteKey(mapfd, &key);
        }
        pkts_cnt = 0;
        /* We use a per CPU structure so we will get a array of values. But if nr_cpus
         * is 1 then we have a global hash. */
        BPF_DECLARE_PERCPU(struct pair, values_array, tcfg->cpus_count);
        memset(values_array, 0, sizeof(values_array));
        int res = bpf_map_lookup_elem(mapfd, &next_key, values_array);
        if (res < 0) {
            SCLogDebug("no entry in v4 table for %d -> %d", key.port16[0], key.port16[1]);
            key = next_key;
            continue;
        }
        for (i = 0; i < tcfg->cpus_count; i++) {
            /* let's start accumulating value so we can compute the counters */
            SCLogDebug("%d: Adding pkts %lu bytes %lu", i,
                       BPF_PERCPU(values_array, i).packets,
                       BPF_PERCPU(values_array, i).bytes);
            pkts_cnt += BPF_PERCPU(values_array, i).packets;
            bytes_cnt += BPF_PERCPU(values_array, i).bytes;
        }
        /* Get the corresponding Flow in the Flow table to compare and update
         * its counters  and lastseen if needed */
        FlowKey flow_key;
        if (tcfg->mode == AFP_MODE_XDP_BYPASS) {
            flow_key.sp = ntohs(next_key.port16[0]);
            flow_key.dp = ntohs(next_key.port16[1]);
            flow_key.src.family = AF_INET6;
            flow_key.src.addr_data32[0] = next_key.src[0];
            flow_key.src.addr_data32[1] = next_key.src[1];
            flow_key.src.addr_data32[2] = next_key.src[2];
            flow_key.src.addr_data32[3] = next_key.src[3];
            flow_key.dst.family = AF_INET6;
            flow_key.dst.addr_data32[0] = next_key.dst[0];
            flow_key.dst.addr_data32[1] = next_key.dst[1];
            flow_key.dst.addr_data32[2] = next_key.dst[2];
            flow_key.dst.addr_data32[3] = next_key.dst[3];
        } else {
            flow_key.sp = next_key.port16[0];
            flow_key.dp = next_key.port16[1];
            flow_key.src.family = AF_INET6;
            flow_key.src.addr_data32[0] = ntohl(next_key.src[0]);
            flow_key.src.addr_data32[1] = ntohl(next_key.src[1]);
            flow_key.src.addr_data32[2] = ntohl(next_key.src[2]);
            flow_key.src.addr_data32[3] = ntohl(next_key.src[3]);
            flow_key.dst.family = AF_INET6;
            flow_key.dst.addr_data32[0] = ntohl(next_key.dst[0]);
            flow_key.dst.addr_data32[1] = ntohl(next_key.dst[1]);
            flow_key.dst.addr_data32[2] = ntohl(next_key.dst[2]);
            flow_key.dst.addr_data32[3] = ntohl(next_key.dst[3]);
        }
        flow_key.vlan_id[0] = next_key.vlan0;
        flow_key.vlan_id[1] = next_key.vlan1;
        flow_key.vlan_id[2] = next_key.vlan2;
        if (next_key.ip_proto == 1) {
            flow_key.proto = IPPROTO_TCP;
        } else {
            flow_key.proto = IPPROTO_UDP;
        }
        flow_key.recursion_level = 0;
        pkts_cnt = EBPFOpFlowForKey(&flowstats, dev, &next_key, sizeof(next_key), &flow_key,
                                    ctime, pkts_cnt, bytes_cnt,
                                    mapfd, tcfg->cpus_count);
        if (pkts_cnt > 0) {
            found = 1;
        }

        if (TmThreadsCheckFlag(th_v, THV_KILL)) {
            return 0;
        }

        key = next_key;
    }
    if (pkts_cnt > 0) {
        EBPFDeleteKey(mapfd, &key);
        found = 1;
    }
    SC_ATOMIC_ADD(dev->bypassed, flowstats.packets);

    LiveDevAddBypassStats(dev, flowstats.count, AF_INET6);
    SCLogInfo("IPv6 bypassed flow table size: %" PRIu64, hash_cnt);
    return found;
}


int EBPFCheckBypassedFlowCreate(ThreadVars *th_v, struct timespec *curtime, void *data)
{
    LiveDevice *ldev = NULL, *ndev;
    struct ebpf_timeout_config *cfg = (struct ebpf_timeout_config *)data;
    while(LiveDeviceForEach(&ldev, &ndev)) {
        EBPFForEachFlowV4Table(th_v, ldev, "flow_table_v4",
                curtime,
                cfg, EBPFCreateFlowForKey);
        EBPFForEachFlowV6Table(th_v, ldev, "flow_table_v6",
                curtime,
                cfg, EBPFCreateFlowForKey);
    }

    return 0;
}

void EBPFRegisterExtension(void)
{
    g_livedev_storage_id = LiveDevStorageRegister("bpfmap", sizeof(void *), NULL, BpfMapsInfoFree);
    g_flow_storage_id = FlowStorageRegister("bypassedlist", sizeof(void *), NULL, BypassedListFree);
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

/**
 * Setup peer interface in XDP system
 *
 * Ths function set up the peer interface in the XDP maps used by the
 * bypass filter. The first map tx_peer has  type device map and is
 * used to store the peer. The second map tx_peer_int is used by the
 * code to check if we have a peer defined for this interface.
 *
 * As the map are per device we just need maps with one single element.
 * In both case, we use the key 0 to enter element so XDP kernel code
 * is using the same key.
 */
int EBPFSetPeerIface(const char *iface, const char *out_iface)
{
    int mapfd = EBPFGetMapFDByName(iface, "tx_peer");
    if (mapfd < 0) {
        SCLogError(SC_ERR_INVALID_VALUE,
                   "Unable to find 'tx_peer' map");
        return -1;
    }
    int intmapfd = EBPFGetMapFDByName(iface, "tx_peer_int");
    if (intmapfd < 0) {
        SCLogError(SC_ERR_INVALID_VALUE,
                   "Unable to find 'tx_peer_int' map");
        return -1;
    }

    int key0 = 0;
    unsigned int peer_index = if_nametoindex(out_iface);
    if (peer_index == 0) {
        SCLogError(SC_ERR_INVALID_VALUE, "No iface '%s'", out_iface);
        return -1;
    }
    int ret = bpf_map_update_elem(mapfd, &key0, &peer_index, BPF_ANY);
    if (ret) {
        SCLogError(SC_ERR_AFP_CREATE, "Create peer entry failed (err:%d)", ret);
        return -1;
    }
    ret = bpf_map_update_elem(intmapfd, &key0, &peer_index, BPF_ANY);
    if (ret) {
        SCLogError(SC_ERR_AFP_CREATE, "Create peer entry failed (err:%d)", ret);
        return -1;
    }
    return 0;
}

/**
 * Bypass the flow on all ifaces it is seen on. This is used
 * in IPS mode.
 */

int EBPFUpdateFlow(Flow *f, Packet *p, void *data)
{
    BypassedIfaceList *ifl = (BypassedIfaceList *)FlowGetStorageById(f, g_flow_storage_id);
    if (ifl == NULL) {
        ifl = SCCalloc(1, sizeof(*ifl));
        if (ifl == NULL) {
            return 0;
        }
        ifl->dev = p->livedev;
        FlowSetStorageById(f, g_flow_storage_id, ifl);
        return 1;
    }
    /* Look for packet iface in the list */
    BypassedIfaceList *ldev = ifl;
    while (ldev) {
        if (p->livedev == ldev->dev) {
            return 1;
        }
        ldev = ldev->next;
    }
    /* Call bypass function if ever not in the list */
    p->BypassPacketsFlow(p);

    /* Add iface to the list */
    BypassedIfaceList *nifl = SCCalloc(1, sizeof(*nifl));
    if (nifl == NULL) {
        return 0;
    }
    nifl->dev = p->livedev;
    nifl->next = ifl;
    FlowSetStorageById(f, g_flow_storage_id, nifl);
    return 1;
}

#endif /* HAVE_PACKET_XDP */

#endif
