/* Copyright (C) 2011-2025 Open Information Security Foundation
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

#ifndef SURICATA_UTIL_DEVICE_H
#define SURICATA_UTIL_DEVICE_H

#ifdef __cplusplus
extern "C"
{
#endif

#define OFFLOAD_FLAG_SG     (1<<0)
#define OFFLOAD_FLAG_TSO    (1<<1)
#define OFFLOAD_FLAG_GSO    (1<<2)
#define OFFLOAD_FLAG_GRO    (1<<3)
#define OFFLOAD_FLAG_LRO    (1<<4)
#define OFFLOAD_FLAG_RXCSUM (1<<5)
#define OFFLOAD_FLAG_TXCSUM (1<<6)
#define OFFLOAD_FLAG_TOE    (1<<7)

void LiveSetOffloadDisable(void);
void LiveSetOffloadWarn(void);
int LiveGetOffload(void);

/**
 * \brief Public definition of LiveDevice.
 *
 * The private definition can be found in util-device-private.h.
 */
typedef struct LiveDevice_ LiveDevice;

void LiveDevRegisterExtension(void);

int LiveRegisterDeviceName(const char *dev);
int LiveRegisterDevice(const char *dev);
int LiveDevUseBypass(LiveDevice *dev);
void LiveDevAddBypassStats(LiveDevice *dev, uint64_t cnt, int family);
void LiveDevSubBypassStats(LiveDevice *dev, uint64_t cnt, int family);
void LiveDevAddBypassFail(LiveDevice *dev, uint64_t cnt, int family);
void LiveDevAddBypassSuccess(LiveDevice *dev, uint64_t cnt, int family);
int LiveGetDeviceCountWithoutAssignedThreading(void);
int LiveGetDeviceCount(void);
const char *LiveGetDeviceName(int number);
LiveDevice *LiveGetDevice(const char *dev);
const char *LiveGetShortName(const char *dev);
int LiveBuildDeviceList(const char *base);
void LiveDeviceHasNoStats(void);
int LiveDeviceListClean(void);
int LiveBuildDeviceListCustom(const char *base, const char *itemname);

LiveDevice *LiveDeviceForEach(LiveDevice **ldev, LiveDevice **ndev);

void LiveDeviceFinalize(void);

#ifdef BUILD_UNIX_SOCKET
TmEcode LiveDeviceIfaceStat(json_t *cmd, json_t *server_msg, void *data);
TmEcode LiveDeviceIfaceList(json_t *cmd, json_t *server_msg, void *data);
TmEcode LiveDeviceGetBypassedStats(json_t *cmd, json_t *answer, void *data);
#endif

uint64_t LiveDevicePktsGet(LiveDevice *dev);
void LiveDevicePktsIncr(LiveDevice *dev);
void LiveDevicePktsAdd(LiveDevice *dev, uint64_t n);
void LiveDeviceDropAdd(LiveDevice *dev, uint64_t n);
void LiveDeviceBypassedAdd(LiveDevice *dev, uint64_t n);
uint64_t LiveDeviceInvalidChecksumsGet(LiveDevice *dev);

#ifdef __cplusplus
}
#endif

#endif /* SURICATA_UTIL_DEVICE_H */
