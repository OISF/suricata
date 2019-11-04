/* Copyright (C) 2017 Open Information Security Foundation
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
 * \author Phil Young <py@napatech.com>
 *
 */

#ifndef __UTIL_NAPATECH_H__
#define __UTIL_NAPATECH_H__

#ifdef HAVE_NAPATECH
#include <nt.h>

typedef struct NapatechPacketVars_ {
    uint64_t stream_id;
    NtNetBuf_t nt_packet_buf;
    ThreadVars *tv;
} NapatechPacketVars;

typedef struct NapatechStreamConfig_ {
    uint16_t stream_id;
    bool is_active;
    bool initialized;
} NapatechStreamConfig;

typedef struct NapatechCurrentStats_ {
    uint64_t current_packets;
    uint64_t current_drops;
    uint64_t current_bytes;
} NapatechCurrentStats;

#define MAX_STREAMS 256

extern void NapatechStartStats(void);


#define NAPATECH_ERROR(err_type, status) {  \
    char errorBuffer[1024]; \
    NT_ExplainError((status), errorBuffer, sizeof (errorBuffer) - 1); \
    SCLogError((err_type), "Napatech Error: %s", errorBuffer);   \
    }

#define NAPATECH_NTPL_ERROR(ntpl_cmd, ntpl_info, status) { \
    char errorBuffer[1024]; \
    NT_ExplainError(status, errorBuffer, sizeof (errorBuffer) - 1); \
    SCLogError(SC_ERR_NAPATECH_STREAMS_REGISTER_FAILED, \
               "     NTPL failed: %s", errorBuffer); \
    SCLogError(SC_ERR_NAPATECH_STREAMS_REGISTER_FAILED, \
               "         cmd: %s", ntpl_cmd); \
    if (strncmp(ntpl_info.u.errorData.errBuffer[0], "", 256) != 0) \
        SCLogError(SC_ERR_NAPATECH_STREAMS_REGISTER_FAILED, \
                   "         %s", ntpl_info.u.errorData.errBuffer[0]); \
    if (strncmp(ntpl_info.u.errorData.errBuffer[1], "", 256) != 0) \
        SCLogError(SC_ERR_NAPATECH_STREAMS_REGISTER_FAILED, \
                   "         %s", ntpl_info.u.errorData.errBuffer[1]); \
    if (strncmp(ntpl_info.u.errorData.errBuffer[2], "", 256) != 0) \
        SCLogError(SC_ERR_NAPATECH_STREAMS_REGISTER_FAILED, \
                   "         %s", ntpl_info.u.errorData.errBuffer[2]); \
}


NapatechCurrentStats NapatechGetCurrentStats(uint16_t id);
int NapatechGetStreamConfig(NapatechStreamConfig stream_config[]);
bool NapatechSetupNuma(uint32_t stream, uint32_t numa);
uint32_t NapatechSetupTraffic(uint32_t first_stream, uint32_t last_stream, uint32_t *filter_id, uint32_t *hash_id);
bool NapatechDeleteFilter(uint32_t filter_id);
#endif //HAVE_NAPATECH
#endif /* __UTIL_NAPATECH_H__ */
