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

#ifndef __UTIL_DEVICE_H__
#define __UTIL_DEVICE_H__

#include "queue.h"
#include "unix-manager.h"

/** storage for live device names */
typedef struct LiveDevice_ {
    char *dev;  /**< the device (e.g. "eth0") */
    int ignore_checksum;
    SC_ATOMIC_DECLARE(uint64_t, pkts);
    SC_ATOMIC_DECLARE(uint64_t, drop);
    SC_ATOMIC_DECLARE(uint64_t, invalid_checksums);
    TAILQ_ENTRY(LiveDevice_) next;
} LiveDevice;


int LiveRegisterDevice(char *dev);
int LiveGetDeviceCount(void);
char *LiveGetDeviceName(int number);
void LiveSafeDeviceName(const char *devname, char *newdevname);
LiveDevice *LiveGetDevice(char *dev);
int LiveBuildDeviceList(char * base);
void LiveDeviceHasNoStats(void);
int LiveDeviceListClean(void);
int LiveBuildDeviceListCustom(char * base, char * itemname);

#ifdef BUILD_UNIX_SOCKET
TmEcode LiveDeviceIfaceStat(json_t *cmd, json_t *server_msg, void *data);
TmEcode LiveDeviceIfaceList(json_t *cmd, json_t *server_msg, void *data);
#endif

#endif /* __UTIL_DEVICE_H__ */
