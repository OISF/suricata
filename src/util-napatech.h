/* Copyright (C) 2022 Open Information Security Foundation
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

typedef struct NapatechPacketVars_
{
    uint64_t stream_id;
    NtNetBuf_t nt_packet_buf;
    NtNetStreamRx_t rx_stream;
    NtFlowStream_t flow_stream;
    ThreadVars *tv;
#ifdef NAPATECH_ENABLE_BYPASS
    NtDyn3Descr_t *dyn3;
    int bypass;
#endif
} NapatechPacketVars;

typedef struct NapatechStreamConfig_
{
    uint8_t stream_id;
    bool is_active;
    bool initialized;
} NapatechStreamConfig;

typedef struct NapatechCurrentStats_
{
    uint64_t current_packets;
    uint64_t current_bytes;
    uint64_t current_drop_packets;
    uint64_t current_drop_bytes;
} NapatechCurrentStats;

#define MAX_HOSTBUFFER 4
#define MAX_STREAMS 256
#define MAX_PORTS 80
#define MAX_ADAPTERS 8
#define HB_HIGHWATER 2048 //1982

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

// #define ENABLE_NT_DEBUG
#ifdef ENABLE_NT_DEBUG
    void NapatechPrintIP(uint32_t address);

    #define NAPATECH_DEBUG(...) printf(__VA_ARGS__)
    #define NAPATECH_PRINTIP(a) NapatechPrintIP(uint32_t address)
#else
    #define NAPATECH_DEBUG(...)
    #define NAPATECH_PRINTIP(a)
#endif

NapatechCurrentStats NapatechGetCurrentStats(uint16_t id);
int NapatechGetStreamConfig(NapatechStreamConfig stream_config[]);
bool NapatechSetupNuma(uint32_t stream, uint32_t numa);
uint32_t NapatechSetupTraffic(uint32_t first_stream, uint32_t last_stream);
uint32_t NapatechDeleteFilters(void);

#ifdef NAPATECH_ENABLE_BYPASS

/* */
#define NAPATECH_KEYTYPE_IPV4 3
#define NAPATECH_KEYTYPE_IPV4_SPAN 4
#define NAPATECH_KEYTYPE_IPV6 5
#define NAPATECH_KEYTYPE_IPV6_SPAN 6
#define NAPATECH_FLOWTYPE_DROP 7
#define NAPATECH_FLOWTYPE_PASS 8

int NapatechVerifyBypassSupport(void);
int NapatechGetNumAdapters(void);


int NapatechIsBypassSupported(void);

#endif /* NAPATECH_ENABLE_BYPASS */
#endif /* HAVE_NAPATECH */
#endif /* __UTIL_NAPATECH_H__ */
