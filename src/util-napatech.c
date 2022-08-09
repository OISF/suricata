/* Copyright (C) 2017-2021 Open Information Security Foundation
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
 * \author Napatech Inc.
 * \author Phil Young <py@napatech.com>
 *
 *
 */
#include "suricata-common.h"

#ifdef HAVE_NAPATECH
#include "suricata.h"
#include "util-device.h"
#include "util-cpu.h"
#include "util-byte.h"
#include "threadvars.h"
#include "tm-threads.h"
#include "util-napatech.h"
#include "source-napatech.h"

#ifdef NAPATECH_ENABLE_BYPASS

/*
 * counters to track the number of flows programmed on
 * the adapter.
 */
typedef struct FlowStatsCounters_
{
    uint16_t active_bypass_flows;
    uint16_t total_bypass_flows;
} FlowStatsCounters;


static int bypass_supported;
int NapatechIsBypassSupported(void)
{
    return bypass_supported;
}

/**
 * \brief  Returns the number of Napatech Adapters in the system.
 *
 * \return count of the Napatech adapters present in the system.
 */
int NapatechGetNumAdapters(void)
{
    NtInfoStream_t hInfo;
    NtInfo_t hInfoSys;
    int status;
    static int num_adapters = -1;

    if (num_adapters == -1) {
        if ((status = NT_InfoOpen(&hInfo, "InfoStream")) != NT_SUCCESS) {
            NAPATECH_ERROR(SC_ERR_NAPATECH_OPEN_FAILED, status);
            exit(EXIT_FAILURE);
        }

        hInfoSys.cmd = NT_INFO_CMD_READ_SYSTEM;
        if ((status = NT_InfoRead(hInfo, &hInfoSys)) != NT_SUCCESS) {
            NAPATECH_ERROR(SC_ERR_NAPATECH_OPEN_FAILED, status);
            exit(EXIT_FAILURE);
        }

        num_adapters = hInfoSys.u.system.data.numAdapters;

        NT_InfoClose(hInfo);
    }

    return num_adapters;
}

/**
 * \brief  Verifies that the Napatech adapters support bypass.
 *
 * Attempts to opens a FlowStream on each adapter present in the system.
 * If successful then bypass is supported
 *
 * \return 1 if Bypass functionality is supported; zero otherwise.
 */
int NapatechVerifyBypassSupport(void)
{
    int status;
    int adapter = 0;
    int num_adapters = NapatechGetNumAdapters();
    SCLogInfo("Found %d Napatech adapters.", num_adapters);
    NtFlowStream_t hFlowStream;

    if (!NapatechUseHWBypass()) {
        /* HW Bypass is disabled in the conf file */
        return 0;
    }

    for (adapter = 0; adapter < num_adapters; ++adapter) {
        NtFlowAttr_t attr;
        char flow_name[80];

        NT_FlowOpenAttrInit(&attr);
        NT_FlowOpenAttrSetAdapterNo(&attr, adapter);

        snprintf(flow_name, sizeof(flow_name), "Flow stream %d", adapter );
        SCLogInfo("Opening flow programming stream:  %s\n", flow_name);
        if ((status = NT_FlowOpen_Attr(&hFlowStream, flow_name, &attr)) != NT_SUCCESS) {
            SCLogWarning(SC_WARN_COMPATIBILITY, "Napatech bypass functionality not supported by the FPGA version on adapter %d - disabling support.", adapter);
            bypass_supported = 0;
            return 0;
        }
        NT_FlowClose(hFlowStream);
    }

    bypass_supported = 1;
    return bypass_supported;
}


/**
 * \brief  Updates statistic counters for Napatech FlowStats
 *
 * \param tv     Thread variable to ThreadVars
 * \param hInfo  Handle to the Napatech InfoStream.
 * \param hstat_stream  Handle to the Napatech Statistics Stream.
 * \param flow_counters The flow counters statistics to update.
 * \param clear_stats  Indicates if statistics on the card should be reset to zero.
 *
 */
static void UpdateFlowStats(
        ThreadVars *tv,
        NtInfoStream_t hInfo,
        NtStatStream_t hstat_stream,
        FlowStatsCounters flow_counters,
        int clear_stats
        )
{
    NtStatistics_t hStat;
    int status;

    uint64_t programed = 0;
    uint64_t removed = 0;
    int adapter = 0;

    for (adapter = 0; adapter < NapatechGetNumAdapters(); ++adapter) {
        hStat.cmd = NT_STATISTICS_READ_CMD_FLOW_V0;
        hStat.u.flowData_v0.clear = clear_stats;
        hStat.u.flowData_v0.adapterNo = adapter;
        if ((status = NT_StatRead(hstat_stream, &hStat)) != NT_SUCCESS) {
            NAPATECH_ERROR(SC_ERR_NAPATECH_INIT_FAILED, status);
            exit(1);
        }
        programed = hStat.u.flowData_v0.learnDone;
        removed = hStat.u.flowData_v0.unlearnDone
                + hStat.u.flowData_v0.automaticUnlearnDone
                + hStat.u.flowData_v0.timeoutUnlearnDone;
    }

        StatsSetUI64(tv, flow_counters.active_bypass_flows, programed - removed);
        StatsSetUI64(tv, flow_counters.total_bypass_flows, programed);
}

#endif /* NAPATECH_ENABLE_BYPASS */


/*-----------------------------------------------------------------------------
 *-----------------------------------------------------------------------------
 * Statistics code
 *-----------------------------------------------------------------------------
 */
typedef struct PacketCounters_
{
    uint16_t pkts;
    uint16_t byte;
    uint16_t drop_pkts;
    uint16_t drop_byte;
} PacketCounters;

NapatechCurrentStats total_stats;
NapatechCurrentStats current_stats[MAX_STREAMS];

NapatechCurrentStats NapatechGetCurrentStats(uint16_t id)
{

    return current_stats[id];
}

enum CONFIG_SPECIFIER {
    CONFIG_SPECIFIER_UNDEFINED = 0,
    CONFIG_SPECIFIER_RANGE,
    CONFIG_SPECIFIER_INDIVIDUAL
};

#define MAX_HOSTBUFFERS 8

/**
 * \brief  Test to see if any of the configured streams are active
 *
 * \param hInfo Handle to Napatech Info Stream.
 * \param hStatsStream Handle to Napatech Statistics stream
 * \param stream_config array of stream configuration structures
 * \param num_inst
 *
 */
static uint16_t TestStreamConfig(
        NtInfoStream_t hInfo,
        NtStatStream_t hstat_stream,
        NapatechStreamConfig stream_config[],
        uint16_t num_inst)
{
    uint16_t num_active = 0;

    for (uint16_t inst = 0; inst < num_inst; ++inst) {
        int status;
        NtStatistics_t stat; // Stat handle.

        /* Check to see if it is an active stream */
        memset(&stat, 0, sizeof (NtStatistics_t));

        /* Read usage data for the chosen stream ID */
        stat.cmd = NT_STATISTICS_READ_CMD_USAGE_DATA_V0;
        stat.u.usageData_v0.streamid = (uint8_t) stream_config[inst].stream_id;

        if ((status = NT_StatRead(hstat_stream, &stat)) != NT_SUCCESS) {
            NAPATECH_ERROR(SC_ERR_NAPATECH_INIT_FAILED, status);
            return 0;
        }

        if (stat.u.usageData_v0.data.numHostBufferUsed > 0) {
            stream_config[inst].is_active = true;
            num_active++;
        } else {
            stream_config[inst].is_active = false;
        }
    }

    return num_active;
}

/**
 * \brief  Updates Napatech packet counters
 *
 * \param tv Pointer to TheardVars structure
 * \param hInfo Handle to Napatech Info Stream.
 * \param hstat_stream Handle to Napatech Statistics stream
 * \param num_streams the number of streams that are currently active
 * \param stream_config array of stream configuration structures
 * \param total_counters - cumulative count of all packets received.
 * \param dispatch_host, - Count of packets that were delivered to the host buffer
 * \param dispatch_drop - count of packets that were dropped as a result of a rule
 * \param dispatch_fwd - count of packets forwarded out the egress port as the result of a rule
 * \param is_inline - are we running in inline mode?
 * \param enable_stream_stats - are per thread/stream statistics enabled.
 * \param stream_counters - counters for each thread/stream configured.
 *
 * \return The number of active streams that were updated.
 *
 */
static uint32_t UpdateStreamStats(ThreadVars *tv,
        NtInfoStream_t hInfo,
        NtStatStream_t hstat_stream,
        uint16_t num_streams,
        NapatechStreamConfig stream_config[],
        PacketCounters total_counters,
        PacketCounters dispatch_host,
        PacketCounters dispatch_drop,
        PacketCounters dispatch_fwd,
        int is_inline,
        int enable_stream_stats,
        PacketCounters stream_counters[]
        ) {
    static uint64_t rxPktsStart[MAX_STREAMS] = {0};
    static uint64_t rxByteStart[MAX_STREAMS] = {0};
    static uint64_t dropPktStart[MAX_STREAMS] = {0};
    static uint64_t dropByteStart[MAX_STREAMS] = {0};

    int status;
    NtInfo_t hStreamInfo;
    NtStatistics_t hStat; // Stat handle.

    /* Query the system to get the number of streams currently instantiated */
    hStreamInfo.cmd = NT_INFO_CMD_READ_STREAM;
    if ((status = NT_InfoRead(hInfo, &hStreamInfo)) != NT_SUCCESS) {
        NAPATECH_ERROR(SC_ERR_NAPATECH_INIT_FAILED, status);
        exit(EXIT_FAILURE);
    }

    uint16_t num_active;
    if ((num_active = TestStreamConfig(hInfo, hstat_stream, stream_config, num_streams)) == 0) {
        /* None of the configured streams are active */
        return 0;
    }

    /* At least one stream is active so proceed with the stats. */
    uint16_t inst_id = 0;
    uint32_t stream_cnt = 0;
    for (stream_cnt = 0; stream_cnt < num_streams; ++stream_cnt) {
        while (inst_id < num_streams) {
            if (stream_config[inst_id].is_active) {
                break;
            } else {
                ++inst_id;
            }
        }
        if (inst_id == num_streams)
            break;

        /* Read usage data for the chosen stream ID */
        memset(&hStat, 0, sizeof (NtStatistics_t));
        hStat.cmd = NT_STATISTICS_READ_CMD_USAGE_DATA_V0;
        hStat.u.usageData_v0.streamid = (uint8_t) stream_config[inst_id].stream_id;

        if ((status = NT_StatRead(hstat_stream, &hStat)) != NT_SUCCESS) {
            NAPATECH_ERROR(SC_ERR_NAPATECH_INIT_FAILED, status);
            return 0;
        }

        uint16_t stream_id = stream_config[inst_id].stream_id;
        if (stream_config[inst_id].is_active) {
            uint64_t rx_pkts_total = 0;
            uint64_t rx_byte_total = 0;
            uint64_t drop_pkts_total = 0;
            uint64_t drop_byte_total = 0;

            for (uint32_t hbCount = 0; hbCount < hStat.u.usageData_v0.data.numHostBufferUsed; hbCount++) {
                if (unlikely(stream_config[inst_id].initialized == false)) {
                    rxPktsStart[stream_id] += hStat.u.usageData_v0.data.hb[hbCount].stat.rx.frames;
                    rxByteStart[stream_id] += hStat.u.usageData_v0.data.hb[hbCount].stat.rx.bytes;
                    dropPktStart[stream_id] += hStat.u.usageData_v0.data.hb[hbCount].stat.drop.frames;
                    dropByteStart[stream_id] += hStat.u.usageData_v0.data.hb[hbCount].stat.drop.bytes;
                    stream_config[inst_id].initialized = true;
                } else {
                    rx_pkts_total += hStat.u.usageData_v0.data.hb[hbCount].stat.rx.frames;
                    rx_byte_total += hStat.u.usageData_v0.data.hb[hbCount].stat.rx.bytes;
                    drop_pkts_total += hStat.u.usageData_v0.data.hb[hbCount].stat.drop.frames;
                    drop_byte_total += hStat.u.usageData_v0.data.hb[hbCount].stat.drop.bytes;
                }
            }

            current_stats[stream_id].current_packets = rx_pkts_total - rxPktsStart[stream_id];
            current_stats[stream_id].current_bytes = rx_byte_total - rxByteStart[stream_id];
            current_stats[stream_id].current_drop_packets = drop_pkts_total - dropPktStart[stream_id];
            current_stats[stream_id].current_drop_bytes = drop_byte_total - dropByteStart[stream_id];
        }

        if (enable_stream_stats) {
            StatsSetUI64(tv, stream_counters[inst_id].pkts, current_stats[stream_id].current_packets);
            StatsSetUI64(tv, stream_counters[inst_id].byte, current_stats[stream_id].current_bytes);
            StatsSetUI64(tv, stream_counters[inst_id].drop_pkts, current_stats[stream_id].current_drop_packets);
            StatsSetUI64(tv, stream_counters[inst_id].drop_byte, current_stats[stream_id].current_drop_bytes);
        }

        ++inst_id;
    }

    uint32_t stream_id;
    for (stream_id = 0; stream_id < num_streams; ++stream_id) {

#ifndef NAPATECH_ENABLE_BYPASS
        total_stats.current_packets += current_stats[stream_id].current_packets;
        total_stats.current_bytes += current_stats[stream_id].current_bytes;
#endif /* NAPATECH_ENABLE_BYPASS */
        total_stats.current_drop_packets += current_stats[stream_id].current_drop_packets;
        total_stats.current_drop_bytes += current_stats[stream_id].current_drop_bytes;
    }


#ifndef NAPATECH_ENABLE_BYPASS
    StatsSetUI64(tv, total_counters.pkts, total_stats.current_packets);
    StatsSetUI64(tv, total_counters.byte, total_stats.current_bytes);
#endif /* NAPATECH_ENABLE_BYPASS */

    StatsSetUI64(tv, total_counters.drop_pkts, total_stats.current_drop_packets);
    StatsSetUI64(tv, total_counters.drop_byte, total_stats.current_drop_bytes);

    total_stats.current_packets = 0;
    total_stats.current_bytes = 0;
    total_stats.current_drop_packets = 0;
    total_stats.current_drop_bytes = 0;

    /* Read usage data for the chosen stream ID */
    memset(&hStat, 0, sizeof (NtStatistics_t));

#ifdef NAPATECH_ENABLE_BYPASS
    hStat.cmd = NT_STATISTICS_READ_CMD_QUERY_V3;
    hStat.u.query_v3.clear = 0;
#else  /* NAPATECH_ENABLE_BYPASS */
    /* Older versions of the API have a different structure. */
    hStat.cmd = NT_STATISTICS_READ_CMD_QUERY_V2;
    hStat.u.query_v2.clear = 0;
#endif  /* !NAPATECH_ENABLE_BYPASS */

    if ((status = NT_StatRead(hstat_stream, &hStat)) != NT_SUCCESS) {
        if (status == NT_STATUS_TIMEOUT) {
            SCLogInfo("Statistics timed out - will retry next time.");
            return 0;
        } else {
            NAPATECH_ERROR(SC_ERR_NAPATECH_INIT_FAILED, status);
            return 0;
        }
    }

#ifdef NAPATECH_ENABLE_BYPASS

    int adapter = 0;
    uint64_t total_dispatch_host_pkts = 0;
    uint64_t total_dispatch_host_byte = 0;
    uint64_t total_dispatch_drop_pkts = 0;
    uint64_t total_dispatch_drop_byte = 0;
    uint64_t total_dispatch_fwd_pkts = 0;
    uint64_t total_dispatch_fwd_byte = 0;

    for (adapter = 0; adapter < NapatechGetNumAdapters();  ++adapter) {
        total_dispatch_host_pkts += hStat.u.query_v3.data.adapter.aAdapters[adapter].color.aColor[0].pkts;
        total_dispatch_host_byte += hStat.u.query_v3.data.adapter.aAdapters[adapter].color.aColor[0].octets;

        total_dispatch_drop_pkts +=   hStat.u.query_v3.data.adapter.aAdapters[adapter].color.aColor[1].pkts
                                    + hStat.u.query_v3.data.adapter.aAdapters[adapter].color.aColor[3].pkts;
        total_dispatch_drop_byte +=   hStat.u.query_v3.data.adapter.aAdapters[adapter].color.aColor[1].octets
                                    + hStat.u.query_v3.data.adapter.aAdapters[adapter].color.aColor[3].octets;

        total_dispatch_fwd_pkts +=   hStat.u.query_v3.data.adapter.aAdapters[adapter].color.aColor[2].pkts
                                   + hStat.u.query_v3.data.adapter.aAdapters[adapter].color.aColor[4].pkts;
        total_dispatch_fwd_byte +=   hStat.u.query_v3.data.adapter.aAdapters[adapter].color.aColor[2].octets
                                   + hStat.u.query_v3.data.adapter.aAdapters[adapter].color.aColor[4].octets;

        total_stats.current_packets += hStat.u.query_v3.data.adapter.aAdapters[adapter].color.aColor[0].pkts
                                     + hStat.u.query_v3.data.adapter.aAdapters[adapter].color.aColor[1].pkts
                                     + hStat.u.query_v3.data.adapter.aAdapters[adapter].color.aColor[2].pkts
                                     + hStat.u.query_v3.data.adapter.aAdapters[adapter].color.aColor[3].pkts;

        total_stats.current_bytes = hStat.u.query_v3.data.adapter.aAdapters[adapter].color.aColor[0].octets
                                  + hStat.u.query_v3.data.adapter.aAdapters[adapter].color.aColor[1].octets
                                  + hStat.u.query_v3.data.adapter.aAdapters[adapter].color.aColor[2].octets;
    }

    StatsSetUI64(tv, dispatch_host.pkts, total_dispatch_host_pkts);
    StatsSetUI64(tv, dispatch_host.byte, total_dispatch_host_byte);

    StatsSetUI64(tv, dispatch_drop.pkts, total_dispatch_drop_pkts);
    StatsSetUI64(tv, dispatch_drop.byte, total_dispatch_drop_byte);

    if (is_inline) {
        StatsSetUI64(tv, dispatch_fwd.pkts, total_dispatch_fwd_pkts);
        StatsSetUI64(tv, dispatch_fwd.byte, total_dispatch_fwd_byte);
    }

    StatsSetUI64(tv, total_counters.pkts, total_stats.current_packets);
    StatsSetUI64(tv, total_counters.byte, total_stats.current_bytes);

#endif /* NAPATECH_ENABLE_BYPASS */

    return num_active;
}

/**
 * \brief Statistics processing loop
 *
 * Instantiated on the stats thread. Periodically retrieves
 * statistics from the Napatech card and updates the packet counters
 *
 * \param arg Pointer that is cast into a TheardVars structure
 */
static void *NapatechStatsLoop(void *arg)
{
    ThreadVars *tv = (ThreadVars *) arg;

    int status;
    NtInfoStream_t hInfo;
    NtStatStream_t hstat_stream;
    int is_inline = 0;
    int enable_stream_stats = 0;
    PacketCounters stream_counters[MAX_STREAMS];

    if (ConfGetBool("napatech.inline", &is_inline) == 0) {
        is_inline = 0;
    }

    if (ConfGetBool("napatech.enable-stream-stats", &enable_stream_stats) == 0) {
        /* default is "no" */
        enable_stream_stats = 0;
    }

    NapatechStreamConfig stream_config[MAX_STREAMS];
    uint16_t stream_cnt = NapatechGetStreamConfig(stream_config);

    /* Open the info and Statistics */
    if ((status = NT_InfoOpen(&hInfo, "StatsLoopInfoStream")) != NT_SUCCESS) {
        NAPATECH_ERROR(SC_ERR_NAPATECH_INIT_FAILED, status);
        return NULL;
    }

    if ((status = NT_StatOpen(&hstat_stream, "StatsLoopStatsStream")) != NT_SUCCESS) {
        NAPATECH_ERROR(SC_ERR_NAPATECH_INIT_FAILED, status);
        return NULL;
    }

    NtStatistics_t hStat;
    memset(&hStat, 0, sizeof (NtStatistics_t));

#ifdef NAPATECH_ENABLE_BYPASS
    hStat.cmd = NT_STATISTICS_READ_CMD_QUERY_V3;
    hStat.u.query_v3.clear = 1;
#else /* NAPATECH_ENABLE_BYPASS */
    hStat.cmd = NT_STATISTICS_READ_CMD_QUERY_V2;
    hStat.u.query_v2.clear = 1;
#endif /* !NAPATECH_ENABLE_BYPASS */

    if ((status = NT_StatRead(hstat_stream, &hStat)) != NT_SUCCESS) {
        NAPATECH_ERROR(SC_ERR_NAPATECH_INIT_FAILED, status);
        return 0;
    }

    PacketCounters total_counters;
    memset(&total_counters, 0, sizeof(total_counters));

    PacketCounters dispatch_host;
    memset(&dispatch_host, 0, sizeof(dispatch_host));

    PacketCounters dispatch_drop;
    memset(&dispatch_drop, 0, sizeof(dispatch_drop));

    PacketCounters dispatch_fwd;
    memset(&dispatch_fwd, 0, sizeof(dispatch_fwd));

    total_counters.pkts = StatsRegisterCounter("napa_total.pkts", tv);
    dispatch_host.pkts = StatsRegisterCounter("napa_dispatch_host.pkts", tv);
    dispatch_drop.pkts = StatsRegisterCounter("napa_dispatch_drop.pkts", tv);
    if (is_inline) {
        dispatch_fwd.pkts = StatsRegisterCounter("napa_dispatch_fwd.pkts", tv);
    }

    total_counters.byte = StatsRegisterCounter("napa_total.byte", tv);
    dispatch_host.byte = StatsRegisterCounter("napa_dispatch_host.byte", tv);
    dispatch_drop.byte = StatsRegisterCounter("napa_dispatch_drop.byte", tv);
    if (is_inline) {
        dispatch_fwd.byte = StatsRegisterCounter("napa_dispatch_fwd.byte", tv);
    }

    total_counters.drop_pkts = StatsRegisterCounter("napa_total.overflow_drop_pkts", tv);
    total_counters.drop_byte = StatsRegisterCounter("napa_total.overflow_drop_byte", tv);

    if (enable_stream_stats) {
        for (int i = 0; i < stream_cnt; ++i) {
            char *pkts_buf = SCCalloc(1, 32);
            if (unlikely(pkts_buf == NULL)) {
                        FatalError(SC_ERR_FATAL,
                                   "Failed to allocate memory for NAPATECH stream counter.");
            }

            snprintf(pkts_buf, 32, "napa%d.pkts", stream_config[i].stream_id);
            stream_counters[i].pkts = StatsRegisterCounter(pkts_buf, tv);

            char *byte_buf = SCCalloc(1, 32);
            if (unlikely(byte_buf == NULL)) {
                        FatalError(SC_ERR_FATAL,
                                   "Failed to allocate memory for NAPATECH stream counter.");
            }
            snprintf(byte_buf, 32, "napa%d.bytes", stream_config[i].stream_id);
            stream_counters[i].byte = StatsRegisterCounter(byte_buf, tv);

            char *drop_pkts_buf = SCCalloc(1, 32);
            if (unlikely(drop_pkts_buf == NULL)) {
                        FatalError(SC_ERR_FATAL,
                                   "Failed to allocate memory for NAPATECH stream counter.");
            }
            snprintf(drop_pkts_buf, 32, "napa%d.drop_pkts", stream_config[i].stream_id);
            stream_counters[i].drop_pkts = StatsRegisterCounter(drop_pkts_buf, tv);

            char *drop_byte_buf = SCCalloc(1, 32);
            if (unlikely(drop_byte_buf == NULL)) {
                        FatalError(SC_ERR_FATAL,
                                   "Failed to allocate memory for NAPATECH stream counter.");
            }
            snprintf(drop_byte_buf, 32, "napa%d.drop_byte", stream_config[i].stream_id);
            stream_counters[i].drop_byte = StatsRegisterCounter(drop_byte_buf, tv);
        }
    }

#ifdef NAPATECH_ENABLE_BYPASS
    FlowStatsCounters flow_counters;
    if (bypass_supported) {
        flow_counters.active_bypass_flows = StatsRegisterCounter("napa_bypass.active_flows", tv);
        flow_counters.total_bypass_flows = StatsRegisterCounter("napa_bypass.total_flows", tv);
    }
#endif /* NAPATECH_ENABLE_BYPASS */

    StatsSetupPrivate(tv);

    StatsSetUI64(tv, total_counters.pkts, 0);
    StatsSetUI64(tv, total_counters.byte, 0);
    StatsSetUI64(tv, total_counters.drop_pkts, 0);
    StatsSetUI64(tv, total_counters.drop_byte, 0);

#ifdef NAPATECH_ENABLE_BYPASS
    if (bypass_supported) {
        StatsSetUI64(tv, dispatch_host.pkts, 0);
        StatsSetUI64(tv, dispatch_drop.pkts, 0);

        if (is_inline) {
            StatsSetUI64(tv, dispatch_fwd.pkts, 0);
        }

        StatsSetUI64(tv, dispatch_host.byte, 0);
        StatsSetUI64(tv, dispatch_drop.byte, 0);
        if (is_inline) {
            StatsSetUI64(tv, dispatch_fwd.byte, 0);
        }

        if (enable_stream_stats) {
            for (int i = 0; i < stream_cnt; ++i) {
                StatsSetUI64(tv, stream_counters[i].pkts, 0);
                StatsSetUI64(tv, stream_counters[i].byte, 0);
                StatsSetUI64(tv, stream_counters[i].drop_pkts, 0);
                StatsSetUI64(tv, stream_counters[i].drop_byte, 0);
            }
        }

        StatsSetUI64(tv, flow_counters.active_bypass_flows, 0);
        StatsSetUI64(tv, flow_counters.total_bypass_flows, 0);
        UpdateFlowStats(tv, hInfo, hstat_stream, flow_counters, 1);
    }
#endif /* NAPATECH_ENABLE_BYPASS */

    uint32_t num_active = UpdateStreamStats(tv, hInfo, hstat_stream,
            stream_cnt, stream_config, total_counters,
            dispatch_host, dispatch_drop, dispatch_fwd,
            is_inline, enable_stream_stats, stream_counters);

    if (!NapatechIsAutoConfigEnabled() && (num_active < stream_cnt)) {
        SCLogInfo("num_active: %d,  stream_cnt: %d", num_active, stream_cnt);
        SCLogWarning(SC_ERR_NAPATECH_CONFIG_STREAM,
                "Some or all of the configured streams are not created.  Proceeding with active streams.");
    }

    TmThreadsSetFlag(tv, THV_INIT_DONE);
    while (1) {
        if (TmThreadsCheckFlag(tv, THV_KILL)) {
            SCLogDebug("NapatechStatsLoop THV_KILL detected");
            break;
        }

        UpdateStreamStats(tv, hInfo, hstat_stream,
                stream_cnt, stream_config, total_counters,
                dispatch_host, dispatch_drop, dispatch_fwd,
                is_inline, enable_stream_stats,
                stream_counters);

#ifdef NAPATECH_ENABLE_BYPASS
        if (bypass_supported) {
            UpdateFlowStats(tv, hInfo, hstat_stream, flow_counters, 0);
        }
#endif /* NAPATECH_ENABLE_BYPASS */

        StatsSyncCountersIfSignalled(tv);
        usleep(1000000);
    }

    /* CLEAN UP NT Resources and Close the info stream */
    if ((status = NT_InfoClose(hInfo)) != NT_SUCCESS) {
        NAPATECH_ERROR(SC_ERR_NAPATECH_INIT_FAILED, status);
        return NULL;
    }

    /* Close the statistics stream */
    if ((status = NT_StatClose(hstat_stream)) != NT_SUCCESS) {
        NAPATECH_ERROR(SC_ERR_NAPATECH_INIT_FAILED, status);
        return NULL;
    }

    SCLogDebug("Exiting NapatechStatsLoop");
    TmThreadsSetFlag(tv, THV_RUNNING_DONE);
    TmThreadWaitForFlag(tv, THV_DEINIT);
    TmThreadsSetFlag(tv, THV_CLOSED);

    return NULL;
}

#define MAX_HOSTBUFFER 4
#define MAX_STREAMS 256
#define HB_HIGHWATER 2048 //1982

/**
 * \brief  Tests whether a particular stream_id is actively registered
 *
 * \param stream_id - ID of the stream to look up
 * \param num_registered - The total number of registered streams
 * \param registered_streams - An array containing actively registered streams.
 *
 * \return Bool indicating is the specified stream is registered.
 *
 */
static bool RegisteredStream(uint16_t stream_id, uint16_t num_registered,
                             NapatechStreamConfig registered_streams[])
{
    for (uint16_t reg_id = 0; reg_id < num_registered; ++reg_id) {
        if (stream_id == registered_streams[reg_id].stream_id) {
            return true;
        }
    }
    return false;
}

/**
 * \brief Count the number of worker threads defined in the conf file.
 *
 * \return - The number of worker threads defined by the configuration
 */
static uint32_t CountWorkerThreads(void)
{
    int worker_count = 0;

    ConfNode *affinity;
    ConfNode *root = ConfGetNode("threading.cpu-affinity");

    if (root != NULL) {

        TAILQ_FOREACH(affinity, &root->head, next)
        {
            if (strcmp(affinity->val, "decode-cpu-set") == 0 ||
                    strcmp(affinity->val, "stream-cpu-set") == 0 ||
                    strcmp(affinity->val, "reject-cpu-set") == 0 ||
                    strcmp(affinity->val, "output-cpu-set") == 0) {
                continue;
            }

            if (strcmp(affinity->val, "worker-cpu-set") == 0) {
                ConfNode *node = ConfNodeLookupChild(affinity->head.tqh_first, "cpu");
                ConfNode *lnode;

                enum CONFIG_SPECIFIER cpu_spec = CONFIG_SPECIFIER_UNDEFINED;

                TAILQ_FOREACH(lnode, &node->head, next)
                {
                    uint8_t start, end;
                    char *end_str;
                    if (strncmp(lnode->val, "all", 4) == 0) {
                        /* check that the sting in the config file is correctly specified */
                        if (cpu_spec != CONFIG_SPECIFIER_UNDEFINED) {
                                    FatalError(SC_ERR_FATAL,
                                               "Only one Napatech port specifier type allowed.");
                        }
                        cpu_spec = CONFIG_SPECIFIER_RANGE;
                        worker_count = UtilCpuGetNumProcessorsConfigured();
                    } else if ((end_str = strchr(lnode->val, '-'))) {
                        /* check that the sting in the config file is correctly specified */
                        if (cpu_spec != CONFIG_SPECIFIER_UNDEFINED) {
                                    FatalError(SC_ERR_FATAL,
                                               "Only one Napatech port specifier type allowed.");
                        }
                        cpu_spec = CONFIG_SPECIFIER_RANGE;


                        if (StringParseUint8(&start, 10, end_str - lnode->val, (const char *)lnode->val) < 0) {
                            FatalError(SC_ERR_INVALID_VALUE, "Napatech invalid"
                                       " worker range start: '%s'", lnode->val);
                        }
                        if (StringParseUint8(&end, 10, 0, (const char *) (end_str + 1)) < 0) {
                            FatalError(SC_ERR_INVALID_VALUE, "Napatech invalid"
                                       " worker range end: '%s'", (end_str != NULL) ? (const char *)(end_str + 1) : "Null");
                        }
                        if (end < start) {
                            FatalError(SC_ERR_INVALID_VALUE, "Napatech invalid"
                                       " worker range start: '%d' is greater than end: '%d'", start, end);
                        }
                        worker_count = end - start + 1;

                    } else {
                        /* check that the sting in the config file is correctly specified */
                        if (cpu_spec == CONFIG_SPECIFIER_RANGE) {
                                    FatalError(SC_ERR_FATAL,
                                               "Napatech port range specifiers cannot be combined with individual stream specifiers.");
                        }
                        cpu_spec = CONFIG_SPECIFIER_INDIVIDUAL;
                        ++worker_count;
                    }
                }
                break;
            }
        }
    }
    return worker_count;
}

/**
 * \brief Reads and parses the stream configuration defined in the config file.
 *
 * \param stream_config - array to be filled in with active stream info.
 *
 * \return the number of streams configured or -1 if an error occurred
 *
  */
int NapatechGetStreamConfig(NapatechStreamConfig stream_config[])
{
    int status;
    char error_buffer[80]; // Error buffer
    NtStatStream_t hstat_stream;
    NtStatistics_t hStat; // Stat handle.
    NtInfoStream_t info_stream;
    NtInfo_t info;
    uint16_t instance_cnt = 0;
    int use_all_streams = 0;
    int set_cpu_affinity = 0;
    ConfNode *ntstreams;
    uint16_t stream_id = 0;
    uint8_t start = 0;
    uint8_t end = 0;

    for (uint16_t i = 0; i < MAX_STREAMS; ++i) {
        stream_config[i].stream_id = 0;
        stream_config[i].is_active = false;
        stream_config[i].initialized = false;
    }

    if (ConfGetBool("napatech.use-all-streams", &use_all_streams) == 0) {
        /* default is "no" */
        use_all_streams = 0;
    }

    if ((status = NT_InfoOpen(&info_stream, "SuricataStreamInfo")) != NT_SUCCESS) {
        NAPATECH_ERROR(SC_ERR_NAPATECH_STREAMS_REGISTER_FAILED, status);
        return -1;
    }

    if ((status = NT_StatOpen(&hstat_stream, "StatsStream")) != NT_SUCCESS) {
        NAPATECH_ERROR(SC_ERR_NAPATECH_STREAMS_REGISTER_FAILED, status);
        return -1;
    }

    if (use_all_streams) {
        info.cmd = NT_INFO_CMD_READ_STREAM;
        if ((status = NT_InfoRead(info_stream, &info)) != NT_SUCCESS) {
            NAPATECH_ERROR(SC_ERR_NAPATECH_STREAMS_REGISTER_FAILED, status);
            return -1;
        }

        while (instance_cnt < info.u.stream.data.count) {

            /*
             *  For each stream ID query the number of host-buffers used by
             * the stream.  If zero, then that streamID is not used; skip
             * over it and continue until we get a streamID with a non-zero
             * count of the host-buffers.
             */
            memset(&hStat, 0, sizeof (NtStatistics_t));

            /* Read usage data for the chosen stream ID */
            hStat.cmd = NT_STATISTICS_READ_CMD_USAGE_DATA_V0;
            hStat.u.usageData_v0.streamid = (uint8_t) stream_id;

            if ((status = NT_StatRead(hstat_stream, &hStat)) != NT_SUCCESS) {
                /* Get the status code as text */
                NT_ExplainError(status, error_buffer, sizeof (error_buffer));
                SCLogError(SC_ERR_NAPATECH_INIT_FAILED, "NT_StatRead() failed: %s\n", error_buffer);
                return -1;
            }

            if (hStat.u.usageData_v0.data.numHostBufferUsed == 0) {
                ++stream_id;
                continue;
            }

            /* if we get here it is an active  stream */
            stream_config[instance_cnt].stream_id = stream_id++;
            stream_config[instance_cnt].is_active = true;
            instance_cnt++;
        }

    } else {
        (void)ConfGetBool("threading.set-cpu-affinity", &set_cpu_affinity);
        if (NapatechIsAutoConfigEnabled() && (set_cpu_affinity == 1)) {
            start = 0;
            end = CountWorkerThreads() - 1;
        } else {
            /* When not using the default streams we need to
             * parse the array of streams from the conf */
            if ((ntstreams = ConfGetNode("napatech.streams")) == NULL) {
                SCLogError(SC_ERR_RUNMODE, "Failed retrieving napatech.streams from Config");
                if (NapatechIsAutoConfigEnabled() && (set_cpu_affinity == 0)) {
                    SCLogError(SC_ERR_RUNMODE,
                            "if set-cpu-affinity: no in conf then napatech.streams must be defined");
                }
                exit(EXIT_FAILURE);
            }

            /* Loop through all stream numbers in the array and register the devices */
            ConfNode *stream;
            enum CONFIG_SPECIFIER stream_spec = CONFIG_SPECIFIER_UNDEFINED;
            instance_cnt = 0;

            TAILQ_FOREACH(stream, &ntstreams->head, next)
            {

                if (stream == NULL) {
                    SCLogError(SC_ERR_NAPATECH_INIT_FAILED, "Couldn't Parse Stream Configuration");
                    return -1;
                }

                char *end_str = strchr(stream->val, '-');
                if (end_str) {
                    if (stream_spec != CONFIG_SPECIFIER_UNDEFINED) {
                        SCLogError(SC_ERR_NAPATECH_PARSE_CONFIG,
                                "Only one Napatech stream range specifier allowed.");
                        return -1;
                    }
                    stream_spec = CONFIG_SPECIFIER_RANGE;

                    if (StringParseUint8(&start, 10, end_str - stream->val,
                                (const char *)stream->val) < 0) {
                        FatalError(SC_ERR_INVALID_VALUE, "Napatech invalid "
                                   "stream id start: '%s'", stream->val);
                    }
                    if (StringParseUint8(&end, 10, 0, (const char *) (end_str + 1)) < 0) {
                        FatalError(SC_ERR_INVALID_VALUE, "Napatech invalid "
                                   "stream id end: '%s'", (end_str != NULL) ? (const char *)(end_str + 1) : "Null");
                    }
                } else {
                    if (stream_spec == CONFIG_SPECIFIER_RANGE) {
                                FatalError(SC_ERR_FATAL,
                                           "Napatech range and individual specifiers cannot be combined.");
                    }
                    stream_spec = CONFIG_SPECIFIER_INDIVIDUAL;
                    if (StringParseUint8(&stream_config[instance_cnt].stream_id,
                                          10, 0, (const char *)stream->val) < 0) {
                        FatalError(SC_ERR_INVALID_VALUE, "Napatech invalid "
                                   "stream id: '%s'", stream->val);
                    }
                    start = stream_config[instance_cnt].stream_id;
                    end = stream_config[instance_cnt].stream_id;
                }
            }
        }

        for (stream_id = start; stream_id <= end; ++stream_id) {
            /* if we get here it is configured in the .yaml file */
            stream_config[instance_cnt].stream_id = stream_id;

            /* Check to see if it is an active stream */
            memset(&hStat, 0, sizeof (NtStatistics_t));

            /* Read usage data for the chosen stream ID */
            hStat.cmd = NT_STATISTICS_READ_CMD_USAGE_DATA_V0;
            hStat.u.usageData_v0.streamid =
                    (uint8_t) stream_config[instance_cnt].stream_id;

            if ((status = NT_StatRead(hstat_stream, &hStat)) != NT_SUCCESS) {
                NAPATECH_ERROR(SC_ERR_NAPATECH_INIT_FAILED, status);
                return -1;
            }

            if (hStat.u.usageData_v0.data.numHostBufferUsed > 0) {
                stream_config[instance_cnt].is_active = true;
            }
            instance_cnt++;
        }
    }

    /* Close the statistics stream */
    if ((status = NT_StatClose(hstat_stream)) != NT_SUCCESS) {
        NAPATECH_ERROR(SC_ERR_NAPATECH_INIT_FAILED, status);
        return -1;
    }

    if ((status = NT_InfoClose(info_stream)) != NT_SUCCESS) {
        NAPATECH_ERROR(SC_ERR_NAPATECH_INIT_FAILED, status);
        return -1;
    }

    return instance_cnt;
}

static void *NapatechBufMonitorLoop(void *arg)
{
    ThreadVars *tv = (ThreadVars *) arg;

    NtInfo_t hStreamInfo;
    NtStatistics_t hStat; // Stat handle.
    NtInfoStream_t hInfo;
    NtStatStream_t hstat_stream;
    int status; // Status variable

    const uint32_t alertInterval = 25;

#ifndef NAPATECH_ENABLE_BYPASS
    uint32_t OB_fill_level[MAX_STREAMS] = {0};
    uint32_t OB_alert_level[MAX_STREAMS] = {0};
    uint32_t ave_OB_fill_level[MAX_STREAMS] = {0};
#endif /* NAPATECH_ENABLE_BYPASS */

    uint32_t HB_fill_level[MAX_STREAMS] = {0};
    uint32_t HB_alert_level[MAX_STREAMS] = {0};
    uint32_t ave_HB_fill_level[MAX_STREAMS] = {0};

    /* Open the info and Statistics */
    if ((status = NT_InfoOpen(&hInfo, "InfoStream")) != NT_SUCCESS) {
        NAPATECH_ERROR(SC_ERR_NAPATECH_INIT_FAILED, status);
        exit(EXIT_FAILURE);
    }

    if ((status = NT_StatOpen(&hstat_stream, "StatsStream")) != NT_SUCCESS) {
        NAPATECH_ERROR(SC_ERR_NAPATECH_INIT_FAILED, status);
        exit(EXIT_FAILURE);
    }

    /* Read the info on all streams instantiated in the system */
    hStreamInfo.cmd = NT_INFO_CMD_READ_STREAM;
    if ((status = NT_InfoRead(hInfo, &hStreamInfo)) != NT_SUCCESS) {
        NAPATECH_ERROR(SC_ERR_NAPATECH_INIT_FAILED, status);
        exit(EXIT_FAILURE);
    }

    NapatechStreamConfig registered_streams[MAX_STREAMS];
    int num_registered = NapatechGetStreamConfig(registered_streams);
    if (num_registered == -1) {
        exit(EXIT_FAILURE);
    }

    TmThreadsSetFlag(tv, THV_INIT_DONE);
    while (1) {
        if (TmThreadsCheckFlag(tv, THV_KILL)) {
            SCLogDebug("NapatechBufMonitorLoop THV_KILL detected");
            break;
        }

        usleep(200000);

        /* Read the info on all streams instantiated in the system */
        hStreamInfo.cmd = NT_INFO_CMD_READ_STREAM;
        if ((status = NT_InfoRead(hInfo, &hStreamInfo)) != NT_SUCCESS) {
            NAPATECH_ERROR(SC_ERR_NAPATECH_INIT_FAILED, status);
            exit(EXIT_FAILURE);
        }

        char pktCntStr[4096];
        memset(pktCntStr, 0, sizeof (pktCntStr));

        uint32_t stream_id = 0;
        uint32_t stream_cnt = 0;
        uint32_t num_streams = hStreamInfo.u.stream.data.count;

        for (stream_cnt = 0; stream_cnt < num_streams; ++stream_cnt) {

            do {

                /* Read usage data for the chosen stream ID */
                hStat.cmd = NT_STATISTICS_READ_CMD_USAGE_DATA_V0;
                hStat.u.usageData_v0.streamid = (uint8_t) stream_id;

                if ((status = NT_StatRead(hstat_stream, &hStat)) != NT_SUCCESS) {
                    NAPATECH_ERROR(SC_ERR_NAPATECH_INIT_FAILED, status);
                    exit(EXIT_FAILURE);
                }

                if (hStat.u.usageData_v0.data.numHostBufferUsed == 0) {
                    ++stream_id;
                    continue;
                }
            } while (hStat.u.usageData_v0.data.numHostBufferUsed == 0);

            if (RegisteredStream(stream_id, num_registered, registered_streams)) {

#ifndef NAPATECH_ENABLE_BYPASS
                ave_OB_fill_level[stream_id] = 0;
#endif /* NAPATECH_ENABLE_BYPASS */

                ave_HB_fill_level[stream_id] = 0;

                for (uint32_t hb_count = 0; hb_count < hStat.u.usageData_v0.data.numHostBufferUsed; hb_count++) {

#ifndef NAPATECH_ENABLE_BYPASS
                    OB_fill_level[hb_count] =
                            ((100 * hStat.u.usageData_v0.data.hb[hb_count].onboardBuffering.used) /
                            hStat.u.usageData_v0.data.hb[hb_count].onboardBuffering.size);

                    if (OB_fill_level[hb_count] > 100) {
                        OB_fill_level[hb_count] = 100;
                    }
#endif /* NAPATECH_ENABLE_BYPASS */
                    uint32_t bufSize = hStat.u.usageData_v0.data.hb[hb_count].enQueuedAdapter / 1024
                            + hStat.u.usageData_v0.data.hb[hb_count].deQueued / 1024
                            + hStat.u.usageData_v0.data.hb[hb_count].enQueued / 1024
                            - HB_HIGHWATER;

                    HB_fill_level[hb_count] = (uint32_t)
                            ((100 * hStat.u.usageData_v0.data.hb[hb_count].deQueued / 1024) /
                            bufSize);

#ifndef NAPATECH_ENABLE_BYPASS
                    ave_OB_fill_level[stream_id] += OB_fill_level[hb_count];
#endif /* NAPATECH_ENABLE_BYPASS */

                    ave_HB_fill_level[stream_id] += HB_fill_level[hb_count];
                }

#ifndef NAPATECH_ENABLE_BYPASS
                ave_OB_fill_level[stream_id] /= hStat.u.usageData_v0.data.numHostBufferUsed;
#endif /* NAPATECH_ENABLE_BYPASS */

                ave_HB_fill_level[stream_id] /= hStat.u.usageData_v0.data.numHostBufferUsed;

                /* Host Buffer Fill Level warnings... */
                if (ave_HB_fill_level[stream_id] >= (HB_alert_level[stream_id] + alertInterval)) {

                    while (ave_HB_fill_level[stream_id] >= HB_alert_level[stream_id] + alertInterval) {
                        HB_alert_level[stream_id] += alertInterval;
                    }
                    SCLogPerf("nt%d - Increasing Host Buffer Fill Level : %4d%%",
                            stream_id, ave_HB_fill_level[stream_id] - 1);
                }

                if (HB_alert_level[stream_id] > 0) {
                    if ((ave_HB_fill_level[stream_id] <= (HB_alert_level[stream_id] - alertInterval))) {
                        SCLogPerf("nt%d - Decreasing Host Buffer Fill Level: %4d%%",
                                stream_id, ave_HB_fill_level[stream_id]);

                        while (ave_HB_fill_level[stream_id] <= (HB_alert_level[stream_id] - alertInterval)) {
                            if ((HB_alert_level[stream_id]) > 0) {
                                HB_alert_level[stream_id] -= alertInterval;
                            } else break;
                        }
                    }
                }

#ifndef NAPATECH_ENABLE_BYPASS
                /* On Board SDRAM Fill Level warnings... */
                if (ave_OB_fill_level[stream_id] >= (OB_alert_level[stream_id] + alertInterval)) {
                    while (ave_OB_fill_level[stream_id] >= OB_alert_level[stream_id] + alertInterval) {
                        OB_alert_level[stream_id] += alertInterval;

                    }
                    SCLogPerf("nt%d - Increasing Adapter SDRAM Fill Level: %4d%%",
                            stream_id, ave_OB_fill_level[stream_id]);
                }

                if (OB_alert_level[stream_id] > 0) {
                    if ((ave_OB_fill_level[stream_id] <= (OB_alert_level[stream_id] - alertInterval))) {
                        SCLogPerf("nt%d - Decreasing Adapter SDRAM Fill Level : %4d%%",
                                stream_id, ave_OB_fill_level[stream_id]);

                        while (ave_OB_fill_level[stream_id] <= (OB_alert_level[stream_id] - alertInterval)) {
                            if ((OB_alert_level[stream_id]) > 0) {
                                OB_alert_level[stream_id] -= alertInterval;
                            } else break;
                        }
                    }
                }
#endif /* NAPATECH_ENABLE_BYPASS */
            }
            ++stream_id;
        }
    }

    if ((status = NT_InfoClose(hInfo)) != NT_SUCCESS) {
        NAPATECH_ERROR(SC_ERR_NAPATECH_INIT_FAILED, status);
        exit(EXIT_FAILURE);
    }

    /* Close the statistics stream */
    if ((status = NT_StatClose(hstat_stream)) != NT_SUCCESS) {
        NAPATECH_ERROR(SC_ERR_NAPATECH_INIT_FAILED, status);
        exit(EXIT_FAILURE);
    }

    SCLogDebug("Exiting NapatechStatsLoop");
    TmThreadsSetFlag(tv, THV_RUNNING_DONE);
    TmThreadWaitForFlag(tv, THV_DEINIT);
    TmThreadsSetFlag(tv, THV_CLOSED);

    return NULL;
}


void NapatechStartStats(void)
{
    /* Creates the Statistic threads */
    ThreadVars *stats_tv = TmThreadCreate("NapatechStats",
            NULL, NULL,
            NULL, NULL,
            "custom", NapatechStatsLoop, 0);

    if (stats_tv == NULL) {
                FatalError(SC_ERR_FATAL,
                           "Error creating a thread for NapatechStats - Killing engine.");
    }

    if (TmThreadSpawn(stats_tv) != 0) {
                FatalError(SC_ERR_FATAL,
                           "Failed to spawn thread for NapatechStats - Killing engine.");
    }

#ifdef NAPATECH_ENABLE_BYPASS
    if (bypass_supported) {
        SCLogInfo("Napatech bypass functionality enabled.");
    }
#endif /* NAPATECH_ENABLE_BYPASS */

    ThreadVars *buf_monitor_tv = TmThreadCreate("NapatechBufMonitor",
            NULL, NULL,
            NULL, NULL,
            "custom", NapatechBufMonitorLoop, 0);

    if (buf_monitor_tv == NULL) {
                FatalError(SC_ERR_FATAL,
                           "Error creating a thread for NapatechBufMonitor - Killing engine.");
    }

    if (TmThreadSpawn(buf_monitor_tv) != 0) {
                FatalError(SC_ERR_FATAL,
                           "Failed to spawn thread for NapatechBufMonitor - Killing engine.");
    }


    return;
}

bool NapatechSetupNuma(uint32_t stream, uint32_t numa)
{
    uint32_t status = 0;
    static NtConfigStream_t hconfig;

    char ntpl_cmd[64];
    snprintf(ntpl_cmd, 64, "setup[numanode=%d] = streamid == %d", numa, stream);

    NtNtplInfo_t ntpl_info;

    if ((status = NT_ConfigOpen(&hconfig, "ConfigStream")) != NT_SUCCESS) {
        NAPATECH_ERROR(SC_ERR_NAPATECH_STREAMS_REGISTER_FAILED, status);
        return false;
    }

    if ((status = NT_NTPL(hconfig, ntpl_cmd, &ntpl_info, NT_NTPL_PARSER_VALIDATE_NORMAL)) == NT_SUCCESS) {
        status = ntpl_info.ntplId;

    } else {
        NAPATECH_NTPL_ERROR(ntpl_cmd, ntpl_info, status);
        return false;
    }

    return status;
}

static uint32_t NapatechSetHashmode(void)
{
    uint32_t status = 0;
    const char *hash_mode;
    static NtConfigStream_t hconfig;
    char ntpl_cmd[64];
    NtNtplInfo_t ntpl_info;

    uint32_t filter_id = 0;

    /* Get the hashmode from the conf file. */
    ConfGet("napatech.hashmode", &hash_mode);

    snprintf(ntpl_cmd, 64, "hashmode = %s", hash_mode);

    /* Issue the NTPL command */
    if ((status = NT_ConfigOpen(&hconfig, "ConfigStream")) != NT_SUCCESS) {
        NAPATECH_ERROR(SC_ERR_NAPATECH_STREAMS_REGISTER_FAILED, status);
        return false;
    }

    if ((status = NT_NTPL(hconfig, ntpl_cmd, &ntpl_info,
            NT_NTPL_PARSER_VALIDATE_NORMAL)) == NT_SUCCESS) {
        filter_id = ntpl_info.ntplId;
        SCLogConfig("Napatech hashmode: %s ID: %d", hash_mode, status);
    } else {
        NAPATECH_NTPL_ERROR(ntpl_cmd, ntpl_info, status);
        status = 0;
    }

    return filter_id;
}

static uint32_t GetStreamNUMAs(uint32_t stream_id, int stream_numas[])
{
    NtStatistics_t hStat; // Stat handle.
    NtStatStream_t hstat_stream;
    int status; // Status variable

    for (int i = 0; i < MAX_HOSTBUFFERS; ++i)
        stream_numas[i] = -1;

    if ((status = NT_StatOpen(&hstat_stream, "StatsStream")) != NT_SUCCESS) {
        NAPATECH_ERROR(SC_ERR_NAPATECH_INIT_FAILED, status);
        exit(EXIT_FAILURE);
    }

    char pktCntStr[4096];
    memset(pktCntStr, 0, sizeof (pktCntStr));


    /* Read usage data for the chosen stream ID */
    hStat.cmd = NT_STATISTICS_READ_CMD_USAGE_DATA_V0;
    hStat.u.usageData_v0.streamid = (uint8_t) stream_id;

    if ((status = NT_StatRead(hstat_stream, &hStat)) != NT_SUCCESS) {
        NAPATECH_ERROR(SC_ERR_NAPATECH_INIT_FAILED, status);
        exit(EXIT_FAILURE);
    }

    for (uint32_t hb_id = 0; hb_id < hStat.u.usageData_v0.data.numHostBufferUsed; ++hb_id) {
        stream_numas[hb_id] = hStat.u.usageData_v0.data.hb[hb_id].numaNode;
    }

    return hStat.u.usageData_v0.data.numHostBufferUsed;
}

static int NapatechSetFilter(NtConfigStream_t hconfig, char *ntpl_cmd)
{
    int status = 0;
    int local_filter_id = 0;

    NtNtplInfo_t ntpl_info;
    if ((status = NT_NTPL(hconfig, ntpl_cmd, &ntpl_info,
            NT_NTPL_PARSER_VALIDATE_NORMAL)) == NT_SUCCESS) {
        SCLogConfig("NTPL filter assignment \"%s\" returned filter id %4d",
                ntpl_cmd, local_filter_id);
    } else {
        NAPATECH_NTPL_ERROR(ntpl_cmd, ntpl_info, status);
        exit(EXIT_FAILURE);
    }

    return local_filter_id;
}

uint32_t NapatechDeleteFilters(void)
{
    uint32_t status = 0;
    static NtConfigStream_t hconfig;
    char ntpl_cmd[64];
    NtNtplInfo_t ntpl_info;

    if ((status = NT_ConfigOpen(&hconfig, "ConfigStream")) != NT_SUCCESS) {
        NAPATECH_ERROR(SC_ERR_NAPATECH_STREAMS_REGISTER_FAILED, status);
        exit(EXIT_FAILURE);
    }

    snprintf(ntpl_cmd, 64, "delete = all");
    if ((status = NT_NTPL(hconfig, ntpl_cmd, &ntpl_info,
            NT_NTPL_PARSER_VALIDATE_NORMAL)) == NT_SUCCESS) {
        status = ntpl_info.ntplId;
    } else {
        NAPATECH_NTPL_ERROR(ntpl_cmd, ntpl_info, status);
        status = 0;
    }

    NT_ConfigClose(hconfig);

    return status;
}


uint32_t NapatechSetupTraffic(uint32_t first_stream, uint32_t last_stream)
{
#define PORTS_SPEC_SIZE 64

    struct ports_spec_s {
        uint8_t first[MAX_PORTS];
        uint8_t second[MAX_PORTS];
        bool all;
        char str[PORTS_SPEC_SIZE];
    } ports_spec;

    ports_spec.all = false;

    ConfNode *ntports;
    int iteration = 0;
    int status = 0;
    NtConfigStream_t hconfig;
    char ntpl_cmd[512];
    int is_inline = 0;
#ifdef NAPATECH_ENABLE_BYPASS
    int is_span_port[MAX_PORTS] = { 0 };
#endif

    char span_ports[128];
    memset(span_ports, 0, sizeof(span_ports));

    if (ConfGetBool("napatech.inline", &is_inline) == 0) {
        is_inline = 0;
    }

    NapatechSetHashmode();

    if ((status = NT_ConfigOpen(&hconfig, "ConfigStream")) != NT_SUCCESS) {
        NAPATECH_ERROR(SC_ERR_NAPATECH_INIT_FAILED, status);
        exit(EXIT_FAILURE);
    }

    if (first_stream == last_stream) {
        snprintf(ntpl_cmd, sizeof (ntpl_cmd),
            "Setup[state=inactive] = StreamId == %d",
             first_stream);
    } else {
        snprintf(ntpl_cmd, sizeof (ntpl_cmd),
            "Setup[state=inactive] = StreamId == (%d..%d)",
             first_stream, last_stream);
    }
    NapatechSetFilter(hconfig, ntpl_cmd);

#ifdef NAPATECH_ENABLE_BYPASS
    if (NapatechUseHWBypass()) {
        SCLogInfo("Napatech Hardware Bypass enabled.");
    } else {
        SCLogInfo("Napatech Hardware Bypass available but disabled.");
    }
#else
    if (NapatechUseHWBypass()) {
        SCLogInfo("Napatech Hardware Bypass requested in conf but is not available.");
        exit(EXIT_FAILURE);
    } else {
        SCLogInfo("Napatech Hardware Bypass disabled.");
    }
#endif

    if (is_inline) {
        SCLogInfo("Napatech configured for inline mode.");
    } else {

        SCLogInfo("Napatech configured for passive (non-inline) mode.");
    }

    /* When not using the default streams we need to parse
     * the array of streams from the conf
     */
    if ((ntports = ConfGetNode("napatech.ports")) == NULL) {
        FatalError(SC_ERR_FATAL, "Failed retrieving napatech.ports from Conf");
    }

    /* Loop through all ports in the array */
    ConfNode *port;
    enum CONFIG_SPECIFIER stream_spec = CONFIG_SPECIFIER_UNDEFINED;

    if (NapatechUseHWBypass()) {
        SCLogInfo("Listening on the following Napatech ports:");
    }
    /* Build the NTPL command using values in the config file. */
    TAILQ_FOREACH(port, &ntports->head, next)
    {
        if (port == NULL) {
                    FatalError(SC_ERR_FATAL,
                               "Couldn't Parse Port Configuration");
        }

        if (NapatechUseHWBypass()) {
#ifdef NAPATECH_ENABLE_BYPASS
            if (strchr(port->val, '-')) {
                stream_spec = CONFIG_SPECIFIER_RANGE;

                ByteExtractStringUint8(&ports_spec.first[iteration], 10, 0, port->val);
                ByteExtractStringUint8(&ports_spec.second[iteration], 10, 0, strchr(port->val, '-')+1);

                if (ports_spec.first[iteration] == ports_spec.second[iteration]) {
                    if (is_inline) {
                        FatalError(SC_ERR_FATAL,
                                "Error with napatech.ports in conf file.  When running in inline "
                                "mode the two ports specifying a segment must be different.");
                    } else {
                        /* SPAN port configuration */
                        is_span_port[ports_spec.first[iteration]] = 1;

                        if (strlen(span_ports) == 0) {
                            snprintf(span_ports, sizeof (span_ports), "%d", ports_spec.first[iteration]);
                        } else {
                            char temp[16];
                            snprintf(temp, sizeof(temp), ",%d", ports_spec.first[iteration]);
                            strlcat(span_ports, temp, sizeof(span_ports));
                        }

                    }
                }

                if (NapatechGetAdapter(ports_spec.first[iteration]) != NapatechGetAdapter(ports_spec.first[iteration])) {
                    SCLogError(SC_ERR_NAPATECH_PARSE_CONFIG,
                            "Invalid napatech.ports specification in conf file.");
                    SCLogError(SC_ERR_NAPATECH_PARSE_CONFIG,
                            "Two ports on a segment must reside on the same adapter.  port %d is on adapter %d, port %d is on adapter %d.",
                            ports_spec.first[iteration],
                            NapatechGetAdapter(ports_spec.first[iteration]),
                            ports_spec.second[iteration],
                            NapatechGetAdapter(ports_spec.second[iteration])
                            );
                    exit(EXIT_FAILURE);
                }

                NapatechSetPortmap(ports_spec.first[iteration], ports_spec.second[iteration]);
                if (ports_spec.first[iteration] == ports_spec.second[iteration]) {
                    SCLogInfo("    span_port: %d", ports_spec.first[iteration]);
                } else {
                    SCLogInfo("    %s: %d - %d", is_inline ? "inline_ports" : "tap_ports", ports_spec.first[iteration], ports_spec.second[iteration]);
                }

                if (iteration == 0) {
                    if (ports_spec.first[iteration] == ports_spec.second[iteration]) {
                        snprintf(ports_spec.str, sizeof (ports_spec.str), "%d", ports_spec.first[iteration]);
                    } else {
                        snprintf(ports_spec.str, sizeof (ports_spec.str), "%d,%d", ports_spec.first[iteration], ports_spec.second[iteration]);
                    }
                } else {
                    char temp[16];
                    if (ports_spec.first[iteration] == ports_spec.second[iteration]) {
                        snprintf(temp, sizeof(temp), ",%d", ports_spec.first[iteration]);
                    } else {
                        snprintf(temp, sizeof(temp), ",%d,%d", ports_spec.first[iteration], ports_spec.second[iteration]);
                    }
                    strlcat(ports_spec.str, temp, sizeof(ports_spec.str));
                }
            } else {
                        FatalError(SC_ERR_FATAL,
                                   "When using hardware flow bypass ports must be specified as segments. E.g. ports: [0-1, 0-2]");
            }
#endif
        } else { // !NapatechUseHWBypass()
            if (strncmp(port->val, "all", 3) == 0) {
                /* check that the sting in the config file is correctly specified */
                if (stream_spec != CONFIG_SPECIFIER_UNDEFINED) {
                            FatalError(SC_ERR_FATAL,
                                       "Only one Napatech port specifier type is allowed.");
                }
                stream_spec = CONFIG_SPECIFIER_RANGE;

                ports_spec.all = true;
                snprintf(ports_spec.str, sizeof (ports_spec.str), "all");
            } else if (strchr(port->val, '-')) {
                /* check that the sting in the config file is correctly specified */
                if (stream_spec != CONFIG_SPECIFIER_UNDEFINED) {
                            FatalError(SC_ERR_FATAL,
                                       "Only one Napatech port specifier is allowed when hardware bypass is disabled. (E.g. ports: [0-4], NOT ports: [0-1,2-3])");
                }
                stream_spec = CONFIG_SPECIFIER_RANGE;

                ByteExtractStringUint8(&ports_spec.first[iteration], 10, 0, port->val);
                ByteExtractStringUint8(&ports_spec.second[iteration], 10, 0, strchr(port->val, '-') + 1);
                snprintf(ports_spec.str, sizeof (ports_spec.str), "(%d..%d)", ports_spec.first[iteration], ports_spec.second[iteration]);
            } else {
                /* check that the sting in the config file is correctly specified */
                if (stream_spec == CONFIG_SPECIFIER_RANGE) {
                            FatalError(SC_ERR_FATAL,
                                       "Napatech port range specifiers cannot be combined with individual stream specifiers.");
                }
                stream_spec = CONFIG_SPECIFIER_INDIVIDUAL;

                ByteExtractStringUint8(&ports_spec.first[iteration], 10, 0, port->val);

                /* Determine the ports to use on the NTPL assign statement*/
                if (iteration == 0) {
                    snprintf(ports_spec.str, sizeof (ports_spec.str), "%s", port->val);
                } else {
                    strlcat(ports_spec.str,  ",", sizeof(ports_spec.str));
                    strlcat(ports_spec.str,  port->val, sizeof(ports_spec.str));
                }
            }
        } // if !NapatechUseHWBypass()
        ++iteration;
    } /* TAILQ_FOREACH */

#ifdef NAPATECH_ENABLE_BYPASS
    if (bypass_supported) {
        if (is_inline) {
            char inline_setup_cmd[512];
            if (first_stream == last_stream) {
                snprintf(inline_setup_cmd, sizeof (ntpl_cmd),
                    "Setup[TxDescriptor=Dyn;TxPorts=%s;RxCRC=False;TxPortPos=112;UseWL=True] = StreamId == %d",
                    ports_spec.str, first_stream);
            } else {
                snprintf(inline_setup_cmd, sizeof (ntpl_cmd),
                    "Setup[TxDescriptor=Dyn;TxPorts=%s;RxCRC=False;TxPortPos=112;UseWL=True] = StreamId == (%d..%d)",
                    ports_spec.str, first_stream, last_stream);
            }
            NapatechSetFilter(hconfig, inline_setup_cmd);
        }
        /* Build the NTPL command */
        snprintf(ntpl_cmd, sizeof (ntpl_cmd),
                "assign[priority=3;streamid=(%d..%d);colormask=0x10000000;"
                "Descriptor=DYN3,length=24,colorbits=32,Offset0=Layer3Header[0],Offset1=Layer4Header[0]]= %s%s",
                first_stream, last_stream, ports_spec.all ? "" : "port==", ports_spec.str);
        NapatechSetFilter(hconfig, ntpl_cmd);


        snprintf(ntpl_cmd, sizeof (ntpl_cmd),
                "assign[priority=2;streamid=(%d..%d);colormask=0x11000000;"
                "Descriptor=DYN3,length=24,colorbits=32,Offset0=Layer3Header[0],Offset1=Layer4Header[0]"
                "]= %s%s and (Layer3Protocol==IPV4)",
                first_stream, last_stream, ports_spec.all ? "" : "port==", ports_spec.str);
        NapatechSetFilter(hconfig, ntpl_cmd);


        snprintf(ntpl_cmd, sizeof (ntpl_cmd),
                "assign[priority=2;streamid=(%d..%d);colormask=0x14000000;"
                "Descriptor=DYN3,length=24,colorbits=32,Offset0=Layer3Header[0],Offset1=Layer4Header[0]]= %s%s and (Layer3Protocol==IPV6)",
                first_stream, last_stream, ports_spec.all ? "" : "port==", ports_spec.str);
        NapatechSetFilter(hconfig, ntpl_cmd);

        snprintf(ntpl_cmd, sizeof (ntpl_cmd),
                "assign[priority=2;streamid=(%d..%d);colormask=0x10100000;"
                "Descriptor=DYN3,length=24,colorbits=32,Offset0=Layer3Header[0],Offset1=Layer4Header[0]]= %s%s and (Layer4Protocol==TCP)",
                first_stream, last_stream, ports_spec.all ? "" : "port==", ports_spec.str);
        NapatechSetFilter(hconfig, ntpl_cmd);

        snprintf(ntpl_cmd, sizeof (ntpl_cmd),
                "assign[priority=2;streamid=(%d..%d);colormask=0x10200000;"
                "Descriptor=DYN3,length=24,colorbits=32,Offset0=Layer3Header[0],Offset1=Layer4Header[0]"
                "]= %s%s and (Layer4Protocol==UDP)",
                first_stream, last_stream, ports_spec.all ? "" : "port==", ports_spec.str);
        NapatechSetFilter(hconfig, ntpl_cmd);

        if (strlen(span_ports) > 0) {
            snprintf(ntpl_cmd, sizeof (ntpl_cmd),
                    "assign[priority=2;streamid=(%d..%d);colormask=0x00001000;"
                    "Descriptor=DYN3,length=24,colorbits=32,Offset0=Layer3Header[0],Offset1=Layer4Header[0]"
                    "]= port==%s",
                    first_stream, last_stream, span_ports);
            NapatechSetFilter(hconfig, ntpl_cmd);
        }

        snprintf(ntpl_cmd, sizeof (ntpl_cmd),
                "KeyType[name=KT%u]={sw_32_32,sw_16_16}",
                NAPATECH_KEYTYPE_IPV4);
        NapatechSetFilter(hconfig, ntpl_cmd);

        snprintf(ntpl_cmd, sizeof (ntpl_cmd),
                "KeyDef[name=KDEF%u;KeyType=KT%u;ipprotocolfield=OUTER]=(Layer3Header[12]/32/32,Layer4Header[0]/16/16)",
                NAPATECH_KEYTYPE_IPV4, NAPATECH_KEYTYPE_IPV4);
        NapatechSetFilter(hconfig, ntpl_cmd);

        snprintf(ntpl_cmd, sizeof (ntpl_cmd),
                "KeyType[name=KT%u]={32,32,16,16}",
                NAPATECH_KEYTYPE_IPV4_SPAN);
        NapatechSetFilter(hconfig, ntpl_cmd);

        snprintf(ntpl_cmd, sizeof (ntpl_cmd),
                "KeyDef[name=KDEF%u;KeyType=KT%u;ipprotocolfield=OUTER;keysort=sorted]=(Layer3Header[12]/32,Layer3Header[16]/32,Layer4Header[0]/16,Layer4Header[2]/16)",
                NAPATECH_KEYTYPE_IPV4_SPAN, NAPATECH_KEYTYPE_IPV4_SPAN);
        NapatechSetFilter(hconfig, ntpl_cmd);

        /* IPv6 5tuple for inline and tap ports */
        snprintf(ntpl_cmd, sizeof (ntpl_cmd),
                "KeyType[name=KT%u]={sw_128_128,sw_16_16}",
                NAPATECH_KEYTYPE_IPV6);
        NapatechSetFilter(hconfig, ntpl_cmd);

        snprintf(ntpl_cmd, sizeof (ntpl_cmd),
                "KeyDef[name=KDEF%u;KeyType=KT%u;ipprotocolfield=OUTER]=(Layer3Header[8]/128/128,Layer4Header[0]/16/16)",
                NAPATECH_KEYTYPE_IPV6, NAPATECH_KEYTYPE_IPV6);
        NapatechSetFilter(hconfig, ntpl_cmd);

        /* IPv6 5tuple for SPAN Ports */
        snprintf(ntpl_cmd, sizeof (ntpl_cmd),
                "KeyType[name=KT%u]={128,128,16,16}",
                NAPATECH_KEYTYPE_IPV6_SPAN);
        NapatechSetFilter(hconfig, ntpl_cmd);

        snprintf(ntpl_cmd, sizeof (ntpl_cmd),
                "KeyDef[name=KDEF%u;KeyType=KT%u;ipprotocolfield=OUTER;keysort=sorted]=(Layer3Header[8]/128,Layer3Header[24]/128,Layer4Header[0]/16,Layer4Header[2]/16)",
                NAPATECH_KEYTYPE_IPV6_SPAN, NAPATECH_KEYTYPE_IPV6_SPAN);
        NapatechSetFilter(hconfig, ntpl_cmd);


        int pair;
        char ports_ntpl_a[64];
        char ports_ntpl_b[64];
        memset(ports_ntpl_a, 0, sizeof(ports_ntpl_a));
        memset(ports_ntpl_b, 0, sizeof(ports_ntpl_b));

        for (pair = 0; pair < iteration; ++pair) {
            char port_str[8];

            if (!is_span_port[ports_spec.first[pair]]) {
                snprintf(port_str, sizeof(port_str), "%s%u ", strlen(ports_ntpl_a) == 0 ? "" : ",", ports_spec.first[pair]);
                strlcat(ports_ntpl_a, port_str, sizeof(ports_ntpl_a));

                snprintf(port_str, sizeof(port_str), "%s%u ", strlen(ports_ntpl_b) == 0 ? "" : ",", ports_spec.second[pair]);
                strlcat(ports_ntpl_b, port_str, sizeof(ports_ntpl_b));
            }
        }

        if (strlen(ports_ntpl_a) > 0) {
            /* This is the assign for dropping upstream traffic */
            snprintf(ntpl_cmd, sizeof (ntpl_cmd),
                    "assign[priority=1;streamid=drop;colormask=0x1]=(Layer3Protocol==IPV4)and(port == %s)and(Key(KDEF%u,KeyID=%u)==%u)",
                    ports_ntpl_a,
                    NAPATECH_KEYTYPE_IPV4,
                    NAPATECH_KEYTYPE_IPV4,
                    NAPATECH_FLOWTYPE_DROP);
            NapatechSetFilter(hconfig, ntpl_cmd);
        }

        if (strlen(ports_ntpl_b) > 0) {
            /* This is the assign for dropping downstream traffic */
            snprintf(ntpl_cmd, sizeof (ntpl_cmd),
                    "assign[priority=1;streamid=drop;colormask=0x1]=(Layer3Protocol==IPV4)and(port == %s)and(Key(KDEF%u,KeyID=%u,fieldaction=swap)==%u)",
                    ports_ntpl_b, //ports_spec.str,
                    NAPATECH_KEYTYPE_IPV4,
                    NAPATECH_KEYTYPE_IPV4,
                    NAPATECH_FLOWTYPE_DROP);
            NapatechSetFilter(hconfig, ntpl_cmd);
        }

        if (strlen(span_ports) > 0) {
            /* This is the assign for dropping SPAN Port traffic */
            snprintf(ntpl_cmd, sizeof (ntpl_cmd),
                    "assign[priority=1;streamid=drop;colormask=0x1]=(Layer3Protocol==IPV4)and(port == %s)and(Key(KDEF%u,KeyID=%u)==%u)",
                    span_ports,
                    NAPATECH_KEYTYPE_IPV4_SPAN,
                    NAPATECH_KEYTYPE_IPV4_SPAN,
                    NAPATECH_FLOWTYPE_DROP);
            NapatechSetFilter(hconfig, ntpl_cmd);
        }

        if (is_inline) {
            for (pair = 0; pair < iteration; ++pair) {
                /* This is the assignment for forwarding traffic */
                snprintf(ntpl_cmd, sizeof (ntpl_cmd),
                        "assign[priority=1;streamid=drop;DestinationPort=%d;colormask=0x2]=(Layer3Protocol==IPV4)and(port == %d)and(Key(KDEF%u,KeyID=%u)==%u)",
                        ports_spec.second[pair],
                        ports_spec.first[pair],
                        NAPATECH_KEYTYPE_IPV4,
                        NAPATECH_KEYTYPE_IPV4,
                        NAPATECH_FLOWTYPE_PASS);
                NapatechSetFilter(hconfig, ntpl_cmd);

                snprintf(ntpl_cmd, sizeof (ntpl_cmd),
                        "assign[priority=1;streamid=drop;DestinationPort=%d;colormask=0x2]=(Layer3Protocol==IPV4)and(port == %d)and(Key(KDEF%u,KeyID=%u,fieldaction=swap)==%u)",
                        ports_spec.first[pair],
                        ports_spec.second[pair],
                        NAPATECH_KEYTYPE_IPV4,
                        NAPATECH_KEYTYPE_IPV4,
                        NAPATECH_FLOWTYPE_PASS);
                NapatechSetFilter(hconfig, ntpl_cmd);
            }
        }

        if (strlen(ports_ntpl_a) > 0) {
            /* This is the assign for dropping upstream traffic */
            snprintf(ntpl_cmd, sizeof (ntpl_cmd),
                    "assign[priority=1;streamid=drop;colormask=0x1]=(Layer3Protocol==IPV6)and(port == %s)and(Key(KDEF%u,KeyID=%u)==%u)",
                    ports_ntpl_a,
                    NAPATECH_KEYTYPE_IPV6,
                    NAPATECH_KEYTYPE_IPV6,
                    NAPATECH_FLOWTYPE_DROP);
            NapatechSetFilter(hconfig, ntpl_cmd);
        }

        if (strlen(ports_ntpl_b) > 0) {
            /* This is the assign for dropping downstream traffic */
            snprintf(ntpl_cmd, sizeof (ntpl_cmd),
                    "assign[priority=1;streamid=drop;colormask=0x1]=(Layer3Protocol==IPV6)and(port == %s)and(Key(KDEF%u,KeyID=%u,fieldaction=swap)==%u)",
                    ports_ntpl_b, //ports_spec.str,
                    NAPATECH_KEYTYPE_IPV6,
                    NAPATECH_KEYTYPE_IPV6,
                    NAPATECH_FLOWTYPE_DROP);
            NapatechSetFilter(hconfig, ntpl_cmd);
        }

        if (strlen(span_ports) > 0) {
            /* This is the assign for dropping SPAN Port traffic */
            snprintf(ntpl_cmd, sizeof (ntpl_cmd),
                    "assign[priority=1;streamid=drop;colormask=0x1]=(Layer3Protocol==IPV6)and(port == %s)and(Key(KDEF%u,KeyID=%u)==%u)",
                    span_ports,
                    NAPATECH_KEYTYPE_IPV6_SPAN,
                    NAPATECH_KEYTYPE_IPV6_SPAN,
                    NAPATECH_FLOWTYPE_DROP);
            NapatechSetFilter(hconfig, ntpl_cmd);
        }

        if (is_inline) {
            for (pair = 0; pair < iteration; ++pair) {
                snprintf(ntpl_cmd, sizeof (ntpl_cmd),
                         "assign[priority=1;streamid=drop;DestinationPort=%d;colormask=0x4]=(Layer3Protocol==IPV6)and(port==%d)and(Key(KDEF%u,KeyID=%u)==%u)",
                          ports_spec.second[pair],
                          ports_spec.first[pair],
                            NAPATECH_KEYTYPE_IPV6,
                          NAPATECH_KEYTYPE_IPV6,
                          NAPATECH_FLOWTYPE_PASS);
                 NapatechSetFilter(hconfig, ntpl_cmd);

                 snprintf(ntpl_cmd, sizeof (ntpl_cmd),
                          "assign[priority=1;streamid=drop;DestinationPort=%d;colormask=0x4]=(Layer3Protocol==IPV6)and(port==%d)and(Key(KDEF%u,KeyID=%u,fieldaction=swap)==%u)",
                          ports_spec.first[pair],
                          ports_spec.second[pair],
                          NAPATECH_KEYTYPE_IPV6,
                          NAPATECH_KEYTYPE_IPV6,
                        NAPATECH_FLOWTYPE_PASS);
                  NapatechSetFilter(hconfig, ntpl_cmd);
            }
        }
    } else {
        if (is_inline) {
                    FatalError(SC_ERR_FATAL,
                               "Napatech Inline operation not supported by this FPGA version.");
        }

        if (NapatechIsAutoConfigEnabled()){
            snprintf(ntpl_cmd, sizeof (ntpl_cmd), "assign[streamid=(%d..%d);colormask=0x0] = %s%s",
                    first_stream, last_stream, ports_spec.all ? "" : "port==", ports_spec.str);
            NapatechSetFilter(hconfig, ntpl_cmd);
        }
    }

#else /* NAPATECH_ENABLE_BYPASS */
    snprintf(ntpl_cmd, sizeof (ntpl_cmd), "assign[streamid=(%d..%d)] = %s%s",
            first_stream, last_stream, ports_spec.all ? "" : "port==", ports_spec.str);
    NapatechSetFilter(hconfig, ntpl_cmd);

#endif /* !NAPATECH_ENABLE_BYPASS */

    SCLogConfig("Host-buffer NUMA assignments: ");
    int numa_nodes[MAX_HOSTBUFFERS];
    uint32_t stream_id;
    for (stream_id = first_stream; stream_id < last_stream; ++stream_id) {
        char temp1[256];
        char temp2[256];

        uint32_t num_host_buffers = GetStreamNUMAs(stream_id, numa_nodes);

        snprintf(temp1, 256, "    stream %d: ", stream_id);

        for (uint32_t hb_id = 0; hb_id < num_host_buffers; ++hb_id) {
            snprintf(temp2, 256, "%d ", numa_nodes[hb_id]);
            strlcat(temp1, temp2, sizeof(temp1));
        }

        SCLogConfig("%s", temp1);
    }

    if (first_stream == last_stream) {
        snprintf(ntpl_cmd, sizeof (ntpl_cmd),
            "Setup[state=active] = StreamId == %d",
             first_stream);
    } else {
        snprintf(ntpl_cmd, sizeof (ntpl_cmd),
            "Setup[state=active] = StreamId == (%d..%d)",
             first_stream, last_stream);
    }
    NapatechSetFilter(hconfig, ntpl_cmd);

    NT_ConfigClose(hconfig);

    return status;
}

#endif // HAVE_NAPATECH
