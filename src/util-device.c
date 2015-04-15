/* Copyright (C) 2011-2012 Open Information Security Foundation
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

#define MAX_DEVNAME 12
#define DEVNAME_CHUNCK 5

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

/** if set to 0 when we don't have real devices */
static int live_devices_stats = 1;

/**
 *  \brief Add a pcap device for monitoring
 *
 *  \param dev string with the device name
 *
 *  \retval 0 on success.
 *  \retval -1 on failure.
 */
int LiveRegisterDevice(char *dev)
{
    LiveDevice *pd = SCMalloc(sizeof(LiveDevice));
    if (unlikely(pd == NULL)) {
        return -1;
    }

    pd->dev = SCStrdup(dev);
    if (unlikely(pd->dev == NULL)) {
        SCFree(pd);
        return -1;
    }
    SC_ATOMIC_INIT(pd->pkts);
    SC_ATOMIC_INIT(pd->drop);
    SC_ATOMIC_INIT(pd->invalid_checksums);
    pd->ignore_checksum = 0;
    TAILQ_INSERT_TAIL(&live_devices, pd, next);

    SCLogDebug("Device \"%s\" registered.", dev);
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
char *LiveGetDeviceName(int number)
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
 *  \brief Shorten a device name that is to long
 *
 *  \param device name from config and destination for modified
 *
 *  \retval None, is added to destination char *newdevname
 */
int LiveSafeDeviceName(const char *devname, char *newdevname, size_t destlen)
{
    size_t devnamelen = strlen(devname);

    // If we have to shorten the interface name
    if (devnamelen > MAX_DEVNAME) {
    
        // We need 13 chars to do this shortening
        if (destlen < 13) {
            return 1;
        }
    
        size_t length;
        length = strlcpy(newdevname, devname, DEVNAME_CHUNCK);
        length = strlcat(newdevname, "...", DEVNAME_CHUNCK+3);
        length = strlcat(newdevname, devname+(devnamelen-DEVNAME_CHUNCK), length+DEVNAME_CHUNCK);
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
LiveDevice *LiveGetDevice(char *name)
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



int LiveBuildDeviceList(char * runmode)
{
    return LiveBuildDeviceListCustom(runmode, "interface");
}

int LiveBuildDeviceListCustom(char * runmode, char * itemname)
{
    ConfNode *base = ConfGetNode(runmode);
    ConfNode *child;
    int i = 0;

    if (base == NULL)
        return 0;

    TAILQ_FOREACH(child, &base->head, next) {
        if (!strcmp(child->val, itemname)) {
            ConfNode *subchild;
            TAILQ_FOREACH(subchild, &child->head, next) {
                if ((!strcmp(subchild->name, itemname))) {
                    if (!strcmp(subchild->val, "default"))
                        break;
                    SCLogInfo("Adding %s %s from config file",
                              itemname, subchild->val);
                    LiveRegisterDevice(subchild->val);
                    i++;
                }
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
            SCLogNotice("Stats for '%s':  pkts: %" PRIu64", drop: %" PRIu64 " (%.2f%%), invalid chksum: %" PRIu64,
                    pd->dev,
                    SC_ATOMIC_GET(pd->pkts),
                    SC_ATOMIC_GET(pd->drop),
                    100 * (SC_ATOMIC_GET(pd->drop) * 1.0) / SC_ATOMIC_GET(pd->pkts),
                    SC_ATOMIC_GET(pd->invalid_checksums));
        }
        if (pd->dev)
            SCFree(pd->dev);
        SC_ATOMIC_DESTROY(pd->pkts);
        SC_ATOMIC_DESTROY(pd->drop);
        SC_ATOMIC_DESTROY(pd->invalid_checksums);
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
        json_array_append(jarray, json_string(pd->dev));
        i++;
    }

    json_object_set_new(jdata, "count", json_integer(i));
    json_object_set_new(jdata, "ifaces", jarray);
    json_object_set_new(answer, "message", jdata);
    SCReturnInt(TM_ECODE_OK);
}
#endif /* BUILD_UNIX_SOCKET */
