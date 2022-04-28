/* Copyright (C) 2011-2021 Open Information Security Foundation
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

#include "suricata-common.h"
#include "conf.h"
#include "util-device.h"
#include "util-ioctl.h"
#include "util-misc.h"
#include "util-dpdk.h"

#include "device-storage.h"

#define MAX_DEVNAME 10

static LiveDevStorageId g_bypass_storage_id = { .id = -1 };

/**
 * \file
 *
 * \author Eric Leblond <eric@regit.org>
 *
 *  \brief Utility functions to handle device list
 */

/** private device list */
static TAILQ_HEAD(, LiveDevice_) live_devices =
    TAILQ_HEAD_INITIALIZER(live_devices);

/** List of the name of devices
 *
 * As we don't know the size of the Storage on devices
 * before the parsing we need to wait and use this list
 * to create later the LiveDevice via LiveDeviceFinalize()
 */
static TAILQ_HEAD(, LiveDeviceName_) pre_live_devices =
    TAILQ_HEAD_INITIALIZER(pre_live_devices);

typedef struct BypassInfo_ {
    SC_ATOMIC_DECLARE(uint64_t, ipv4_hash_count);
    SC_ATOMIC_DECLARE(uint64_t, ipv4_fail);
    SC_ATOMIC_DECLARE(uint64_t, ipv4_success);
    SC_ATOMIC_DECLARE(uint64_t, ipv6_hash_count);
    SC_ATOMIC_DECLARE(uint64_t, ipv6_fail);
    SC_ATOMIC_DECLARE(uint64_t, ipv6_success);
} BypassInfo;

/** if set to 0 when we don't have real devices */
static int live_devices_stats = 1;


static int LiveSafeDeviceName(const char *devname,
                              char *newdevname, size_t destlen);

static int g_live_devices_disable_offloading = 1;

void LiveSetOffloadDisable(void)
{
    g_live_devices_disable_offloading = 1;
}

void LiveSetOffloadWarn(void)
{
    g_live_devices_disable_offloading = 0;
}

int LiveGetOffload(void)
{
    return g_live_devices_disable_offloading;
}

/**
 *  \brief Add a device for monitoring
 *
 * To be used during option parsing. When a device has
 * to be created during runmode init, use LiveRegisterDevice()
 *
 *  \param dev string with the device name
 *
 *  \retval 0 on success.
 *  \retval -1 on failure.
 */
int LiveRegisterDeviceName(const char *dev)
{
    LiveDeviceName *pd = NULL;

    pd = SCCalloc(1, sizeof(LiveDeviceName));
    if (unlikely(pd == NULL)) {
        return -1;
    }

    pd->dev = SCStrdup(dev);
    if (unlikely(pd->dev == NULL)) {
        SCFree(pd);
        return -1;
    }

    TAILQ_INSERT_TAIL(&pre_live_devices, pd, next);

    SCLogDebug("Device \"%s\" registered.", dev);
    return 0;
}

/**
 *  \brief Add a pcap device for monitoring and create structure
 *
 *  \param dev string with the device name
 *
 *  \retval 0 on success.
 *  \retval -1 on failure.
 */
int LiveRegisterDevice(const char *dev)
{
    LiveDevice *pd = NULL;

    pd = SCCalloc(1, sizeof(LiveDevice) + LiveDevStorageSize());
    if (unlikely(pd == NULL)) {
        return -1;
    }

    int id = LiveGetDeviceCount();
    if (id > UINT16_MAX) {
        SCFree(pd);
        return -1;
    }

    pd->dev = SCStrdup(dev);
    if (unlikely(pd->dev == NULL)) {
        SCFree(pd);
        return -1;
    }
    /* create a short version to be used in thread names */
    LiveSafeDeviceName(pd->dev, pd->dev_short, sizeof(pd->dev_short));

    SC_ATOMIC_INIT(pd->pkts);
    SC_ATOMIC_INIT(pd->drop);
    SC_ATOMIC_INIT(pd->invalid_checksums);
    pd->id = (uint16_t) id;
    TAILQ_INSERT_TAIL(&live_devices, pd, next);

    SCLogDebug("Device \"%s\" registered and created.", dev);
    return 0;
}

/**
 *  \brief Get the number of registered devices
 *
 *  \retval cnt the number of registered devices
 */
int LiveGetDeviceCount(void)
{
    int i = 0;
    LiveDevice *pd;

    TAILQ_FOREACH(pd, &live_devices, next) {
        i++;
    }

    return i;
}

/**
 *  \brief Get a pointer to the device name at idx
 *
 *  \param number idx of the device in our list
 *
 *  \retval ptr pointer to the string containing the device
 *  \retval NULL on error
 */
const char *LiveGetDeviceName(int number)
{
    int i = 0;
    LiveDevice *pd;

    TAILQ_FOREACH(pd, &live_devices, next) {
        if (i == number) {
            return pd->dev;
        }

        i++;
    }

    return NULL;
}

/**
 *  \brief Get the number of pre registered devices
 *
 *  \retval cnt the number of pre registered devices
 */
int LiveGetDeviceNameCount(void)
{
    int i = 0;
    LiveDeviceName *pd;

    TAILQ_FOREACH(pd, &pre_live_devices, next) {
        i++;
    }

    return i;
}

/**
 *  \brief Get a pointer to the pre device name at idx
 *
 *  \param number idx of the pre device in our list
 *
 *  \retval ptr pointer to the string containing the device
 *  \retval NULL on error
 */
const char *LiveGetDeviceNameName(int number)
{
    int i = 0;
    LiveDeviceName *pd;

    TAILQ_FOREACH(pd, &pre_live_devices, next) {
        if (i == number) {
            return pd->dev;
        }

        i++;
    }

    return NULL;
}



/** \internal
 *  \brief Shorten a device name that is to long
 *
 *  \param device name from config and destination for modified
 *
 *  \retval None, is added to destination char *newdevname
 */
static int LiveSafeDeviceName(const char *devname, char *newdevname, size_t destlen)
{
    const size_t devnamelen = strlen(devname);

    /* If we have to shorten the interface name */
    if (devnamelen > MAX_DEVNAME) {

        /* IF the dest length is over 10 chars long it will not do any
         * good for the shortening. The shortening is done due to the
         * max length of pthread names (15 chars) and we use 3 chars
         * for the threadname indicator eg. "W#-" and one-two chars for
         * the thread number. And if the destination buffer is under
         * 6 chars there is no point in shortening it since we must at
         * least enter two periods (.) into the string.
         */
        if ((destlen-1) > 10 || (destlen-1) < 6) {
            return 1;
        }

        ShortenString(devname, newdevname, destlen, '.');

        SCLogInfo("Shortening device name to: %s", newdevname);
    } else {
        strlcpy(newdevname, devname, destlen);
    }
    return 0;
}

/**
 *  \brief Get a pointer to the device at idx
 *
 *  \param number idx of the device in our list
 *
 *  \retval ptr pointer to the string containing the device
 *  \retval NULL on error
 */
LiveDevice *LiveGetDevice(const char *name)
{
    int i = 0;
    LiveDevice *pd;

    if (name == NULL) {
        SCLogWarning(SC_ERR_INVALID_VALUE, "Name of device should not be null");
        return NULL;
    }

    TAILQ_FOREACH(pd, &live_devices, next) {
        if (!strcmp(name, pd->dev)) {
            return pd;
        }

        i++;
    }

    return NULL;
}

const char *LiveGetShortName(const char *dev)
{
    LiveDevice *live_dev = LiveGetDevice(dev);
    if (live_dev == NULL)
        return NULL;
    return live_dev->dev_short;
}

int LiveBuildDeviceList(const char *runmode)
{
    return LiveBuildDeviceListCustom(runmode, "interface");
}

int LiveBuildDeviceListCustom(const char *runmode, const char *itemname)
{
    ConfNode *base = ConfGetNode(runmode);
    ConfNode *child;
    int i = 0;

    if (base == NULL)
        return 0;

    TAILQ_FOREACH(child, &base->head, next) {
        ConfNode *subchild;
        TAILQ_FOREACH(subchild, &child->head, next) {
            if ((!strcmp(subchild->name, itemname))) {
                if (!strcmp(subchild->val, "default"))
                    break;
                SCLogConfig("Adding %s %s from config file",
                          itemname, subchild->val);
                LiveRegisterDeviceName(subchild->val);
                i++;
            }
        }
    }

    return i;
}

/** Call this function to disable stat on live devices
 *
 * This can be useful in the case, this is not a real interface.
 */
void LiveDeviceHasNoStats()
{
    live_devices_stats = 0;
}

int LiveDeviceListClean()
{
    SCEnter();
    LiveDevice *pd, *tpd;

    TAILQ_FOREACH_SAFE(pd, &live_devices, next, tpd) {
        if (live_devices_stats) {
            SCLogNotice("Stats for '%s':  pkts: %" PRIu64 ", drop: %" PRIu64
                        " (%.2f%%), invalid chksum: %" PRIu64,
                    pd->dev, SC_ATOMIC_GET(pd->pkts), SC_ATOMIC_GET(pd->drop),
                    100 * ((double)SC_ATOMIC_GET(pd->drop)) / (double)SC_ATOMIC_GET(pd->pkts),
                    SC_ATOMIC_GET(pd->invalid_checksums));
        }

        RestoreIfaceOffloading(pd);
        DPDKCloseDevice(pd);

        if (pd->dev)
            SCFree(pd->dev);
        LiveDevFreeStorage(pd);
        SCFree(pd);
    }

    SCReturnInt(TM_ECODE_OK);
}

#ifdef BUILD_UNIX_SOCKET
TmEcode LiveDeviceIfaceStat(json_t *cmd, json_t *answer, void *data)
{
    SCEnter();
    LiveDevice *pd;
    const char * name = NULL;
    json_t *jarg = json_object_get(cmd, "iface");
    if(!json_is_string(jarg)) {
        json_object_set_new(answer, "message", json_string("Iface is not a string"));
        SCReturnInt(TM_ECODE_FAILED);
    }
    name = json_string_value(jarg);
    if (name == NULL) {
        json_object_set_new(answer, "message", json_string("Iface name is NULL"));
        SCReturnInt(TM_ECODE_FAILED);
    }

    TAILQ_FOREACH(pd, &live_devices, next) {
        if (!strcmp(name, pd->dev)) {
            json_t *jdata = json_object();
            if (jdata == NULL) {
                json_object_set_new(answer, "message",
                        json_string("internal error at json object creation"));
                SCReturnInt(TM_ECODE_FAILED);
            }
            json_object_set_new(jdata, "pkts",
                                json_integer(SC_ATOMIC_GET(pd->pkts)));
            json_object_set_new(jdata, "invalid-checksums",
                                json_integer(SC_ATOMIC_GET(pd->invalid_checksums)));
            json_object_set_new(jdata, "drop",
                                json_integer(SC_ATOMIC_GET(pd->drop)));
            json_object_set_new(jdata, "bypassed",
                                json_integer(SC_ATOMIC_GET(pd->bypassed)));
            json_object_set_new(answer, "message", jdata);
            SCReturnInt(TM_ECODE_OK);
        }
    }
    json_object_set_new(answer, "message", json_string("Iface does not exist"));
    SCReturnInt(TM_ECODE_FAILED);
}

TmEcode LiveDeviceIfaceList(json_t *cmd, json_t *answer, void *data)
{
    SCEnter();
    json_t *jdata;
    json_t *jarray;
    LiveDevice *pd;
    int i = 0;

    jdata = json_object();
    if (jdata == NULL) {
        json_object_set_new(answer, "message",
                            json_string("internal error at json object creation"));
        return TM_ECODE_FAILED;
    }
    jarray = json_array();
    if (jarray == NULL) {
        json_object_set_new(answer, "message",
                            json_string("internal error at json object creation"));
        return TM_ECODE_FAILED;
    }
    TAILQ_FOREACH(pd, &live_devices, next) {
        json_array_append_new(jarray, json_string(pd->dev));
        i++;
    }

    json_object_set_new(jdata, "count", json_integer(i));
    json_object_set_new(jdata, "ifaces", jarray);
    json_object_set_new(answer, "message", jdata);
    SCReturnInt(TM_ECODE_OK);
}

#endif /* BUILD_UNIX_SOCKET */

LiveDevice *LiveDeviceForEach(LiveDevice **ldev, LiveDevice **ndev)
{
    if (*ldev == NULL) {
        *ldev = TAILQ_FIRST(&live_devices);
        *ndev = TAILQ_NEXT(*ldev, next);
        return *ldev;
    } else {
        *ldev = *ndev;
        if (*ldev) {
            *ndev = TAILQ_NEXT(*ldev, next);
        }
        return *ldev;
    }
    return NULL;
}

/**
 * Create registered devices
 *
 * This function creates all needed LiveDevice from
 * the LiveDeviceName list created via LiveRegisterDevice()
 */
void LiveDeviceFinalize(void)
{
    LiveDeviceName *ld, *pld;
    SCLogDebug("Finalize live device");
    /* Iter on devices and register them */
    TAILQ_FOREACH_SAFE(ld, &pre_live_devices, next, pld) {
        if (ld->dev) {
            LiveRegisterDevice(ld->dev);
            SCFree(ld->dev);
        }
        SCFree(ld);
    }
}

static void LiveDevExtensionFree(void *x)
{
    if (x)
        SCFree(x);
}

/**
 * Register bypass stats storage
 */
void LiveDevRegisterExtension(void)
{
    g_bypass_storage_id = LiveDevStorageRegister("bypass_stats", sizeof(void *),
                                                 NULL, LiveDevExtensionFree);
}

/**
 * Prepare a LiveDevice so we can set bypass stats
 */
int LiveDevUseBypass(LiveDevice *dev)
{
    BypassInfo *bpinfo = SCCalloc(1, sizeof(*bpinfo));
    if (bpinfo == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Can't allocate bypass info structure");
        return -1;
    }

    SC_ATOMIC_INIT(bpinfo->ipv4_hash_count);
    SC_ATOMIC_INIT(bpinfo->ipv4_hash_count);

    LiveDevSetStorageById(dev, g_bypass_storage_id, bpinfo);
    return 0;
}

/**
 * Set number of currently bypassed flows for a protocol family
 *
 * \param dev pointer to LiveDevice to set stats for
 * \param cnt number of currently bypassed flows
 * \param family AF_INET to set IPv4 count or AF_INET6 to set IPv6 count
 */
void LiveDevSetBypassStats(LiveDevice *dev, uint64_t cnt, int family)
{
    BypassInfo *bpfdata = LiveDevGetStorageById(dev, g_bypass_storage_id);
    if (bpfdata) {
        if (family == AF_INET) {
            SC_ATOMIC_SET(bpfdata->ipv4_hash_count, cnt);
        } else if (family == AF_INET6) {
            SC_ATOMIC_SET(bpfdata->ipv6_hash_count, cnt);
        }
    }
}

/**
 * Increase number of currently bypassed flows for a protocol family
 *
 * \param dev pointer to LiveDevice to set stats for
 * \param cnt number of flows to add
 * \param family AF_INET to set IPv4 count or AF_INET6 to set IPv6 count
 */
void LiveDevAddBypassStats(LiveDevice *dev, uint64_t cnt, int family)
{
    BypassInfo *bpfdata = LiveDevGetStorageById(dev, g_bypass_storage_id);
    if (bpfdata) {
        if (family == AF_INET) {
            SC_ATOMIC_ADD(bpfdata->ipv4_hash_count, cnt);
        } else if (family == AF_INET6) {
            SC_ATOMIC_ADD(bpfdata->ipv6_hash_count, cnt);
        }
    }
}

/**
 * Decrease number of currently bypassed flows for a protocol family
 *
 * \param dev pointer to LiveDevice to set stats for
 * \param cnt number of flows to remove
 * \param family AF_INET to set IPv4 count or AF_INET6 to set IPv6 count
 */
void LiveDevSubBypassStats(LiveDevice *dev, uint64_t cnt, int family)
{
    BypassInfo *bpfdata = LiveDevGetStorageById(dev, g_bypass_storage_id);
    if (bpfdata) {
        if (family == AF_INET) {
            SC_ATOMIC_SUB(bpfdata->ipv4_hash_count, cnt);
        } else if (family == AF_INET6) {
            SC_ATOMIC_SUB(bpfdata->ipv6_hash_count, cnt);
        }
    }
}

/**
 * Increase number of failed captured flows for a protocol family
 *
 * \param dev pointer to LiveDevice to set stats for
 * \param cnt number of flows to add
 * \param family AF_INET to set IPv4 count or AF_INET6 to set IPv6 count
 */
void LiveDevAddBypassFail(LiveDevice *dev, uint64_t cnt, int family)
{
    BypassInfo *bpfdata = LiveDevGetStorageById(dev, g_bypass_storage_id);
    if (bpfdata) {
        if (family == AF_INET) {
            SC_ATOMIC_ADD(bpfdata->ipv4_fail, cnt);
        } else if (family == AF_INET6) {
            SC_ATOMIC_ADD(bpfdata->ipv6_fail, cnt);
        }
    }
}

/**
 * Increase number of currently successfully bypassed flows for a protocol family
 *
 * \param dev pointer to LiveDevice to set stats for
 * \param cnt number of flows to add
 * \param family AF_INET to set IPv4 count or AF_INET6 to set IPv6 count
 */
void LiveDevAddBypassSuccess(LiveDevice *dev, uint64_t cnt, int family)
{
    BypassInfo *bpfdata = LiveDevGetStorageById(dev, g_bypass_storage_id);
    if (bpfdata) {
        if (family == AF_INET) {
            SC_ATOMIC_ADD(bpfdata->ipv4_success, cnt);
        } else if (family == AF_INET6) {
            SC_ATOMIC_ADD(bpfdata->ipv6_success, cnt);
        }
    }
}

#ifdef BUILD_UNIX_SOCKET
TmEcode LiveDeviceGetBypassedStats(json_t *cmd, json_t *answer, void *data)
{
    LiveDevice *ldev = NULL, *ndev = NULL;

    json_t *ifaces = NULL;
    while(LiveDeviceForEach(&ldev, &ndev)) {
        BypassInfo *bpinfo = LiveDevGetStorageById(ldev, g_bypass_storage_id);
        if (bpinfo) {
            uint64_t ipv4_hash_count = SC_ATOMIC_GET(bpinfo->ipv4_hash_count);
            uint64_t ipv6_hash_count = SC_ATOMIC_GET(bpinfo->ipv6_hash_count);
            uint64_t ipv4_success = SC_ATOMIC_GET(bpinfo->ipv4_success);
            uint64_t ipv4_fail = SC_ATOMIC_GET(bpinfo->ipv4_fail);
            uint64_t ipv6_success = SC_ATOMIC_GET(bpinfo->ipv6_success);
            uint64_t ipv6_fail = SC_ATOMIC_GET(bpinfo->ipv6_fail);
            json_t *iface = json_object();
            if (ifaces == NULL) {
                ifaces = json_object();
                if (ifaces == NULL) {
                    json_object_set_new(answer, "message",
                            json_string("internal error at json object creation"));
                    return TM_ECODE_FAILED;
                }
            }
            json_object_set_new(iface, "ipv4_maps_count", json_integer(ipv4_hash_count));
            json_object_set_new(iface, "ipv4_success", json_integer(ipv4_success));
            json_object_set_new(iface, "ipv4_fail", json_integer(ipv4_fail));
            json_object_set_new(iface, "ipv6_maps_count", json_integer(ipv6_hash_count));
            json_object_set_new(iface, "ipv6_success", json_integer(ipv6_success));
            json_object_set_new(iface, "ipv6_fail", json_integer(ipv6_fail));
            json_object_set_new(ifaces, ldev->dev, iface);
        }
    }
    if (ifaces) {
        json_object_set_new(answer, "message", ifaces);
        SCReturnInt(TM_ECODE_OK);
    }

    json_object_set_new(answer, "message",
                        json_string("No interface using bypass"));
    SCReturnInt(TM_ECODE_FAILED);
}
#endif
