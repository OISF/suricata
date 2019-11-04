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
#include "threadvars.h"
#include "tm-threads.h"

/*-----------------------------------------------------------------------------
 *-----------------------------------------------------------------------------
 * Statistics code
 *-----------------------------------------------------------------------------
 */

typedef struct StreamCounters_ {
    uint16_t pkts;
    uint16_t byte;
    uint16_t drop;
} StreamCounters;


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

static uint16_t TestStreamConfig(
        NtInfoStream_t hInfo,
        NtStatStream_t hStatStream,
        NapatechStreamConfig stream_config[],
        uint16_t num_inst)
{

    uint16_t num_active = 0;

    for (uint16_t inst = 0; inst < num_inst; ++inst) {
        int status;
        char buffer[80]; // Error buffer
        NtStatistics_t stat; // Stat handle.

        /* Check to see if it is an active stream */
        memset(&stat, 0, sizeof (NtStatistics_t));

        /* Read usage data for the chosen stream ID */
        stat.cmd = NT_STATISTICS_READ_CMD_USAGE_DATA_V0;
        stat.u.usageData_v0.streamid = (uint8_t) stream_config[inst].stream_id;

        if ((status = NT_StatRead(hStatStream, &stat)) != NT_SUCCESS) {
            /* Get the status code as text */
            NT_ExplainError(status, buffer, sizeof (buffer));
            SCLogError(SC_ERR_NAPATECH_INIT_FAILED,
                    "NT_StatRead():2 failed: %s\n", buffer);
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

static uint32_t UpdateStreamStats(ThreadVars *tv,
        NtInfoStream_t hInfo,
        NtStatStream_t hStatStream,
        uint16_t num_streams,
        NapatechStreamConfig stream_config[],
        StreamCounters streamCounters[]
        )
{
    static uint64_t rxPktsStart[MAX_STREAMS] = {0};
    static uint64_t rxByteStart[MAX_STREAMS] = {0};
    static uint64_t dropStart[MAX_STREAMS] = {0};

    int status;
    char error_buffer[80]; // Error buffer
    NtInfo_t hStreamInfo;
    NtStatistics_t hStat; // Stat handle.

    /* Query the system to get the number of streams currently instantiated */
    hStreamInfo.cmd = NT_INFO_CMD_READ_STREAM;
    if ((status = NT_InfoRead(hInfo, &hStreamInfo)) != NT_SUCCESS) {
        NT_ExplainError(status, error_buffer, sizeof (error_buffer) - 1);
        SCLogError(SC_ERR_NAPATECH_INIT_FAILED,
                "NT_InfoRead() failed: %s\n", error_buffer);
        exit(EXIT_FAILURE);
    }

    uint16_t num_active;
    if ((num_active = TestStreamConfig(hInfo, hStatStream,
            stream_config, num_streams)) == 0) {
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

        if ((status = NT_StatRead(hStatStream, &hStat)) != NT_SUCCESS) {
            /* Get the status code as text */
            NT_ExplainError(status, error_buffer, sizeof (error_buffer));
            SCLogError(SC_ERR_NAPATECH_INIT_FAILED,
                    "NT_StatRead() failed: %s\n", error_buffer);
            return 0;
        }

        uint16_t stream_id = stream_config[inst_id].stream_id;
        if (stream_config[inst_id].is_active) {
            uint64_t rxPktsTotal = 0;
            uint64_t rxByteTotal = 0;
            uint64_t dropTotal = 0;

            for (uint32_t hbCount = 0; hbCount < hStat.u.usageData_v0.data.numHostBufferUsed; hbCount++) {
                if (unlikely(stream_config[inst_id].initialized == false)) {
                    rxPktsStart[stream_id] += hStat.u.usageData_v0.data.hb[hbCount].stat.rx.frames;
                    rxByteStart[stream_id] += hStat.u.usageData_v0.data.hb[hbCount].stat.rx.bytes;
                    dropStart[stream_id] += hStat.u.usageData_v0.data.hb[hbCount].stat.drop.frames;
                    stream_config[inst_id].initialized = true;
                } else {
                    rxPktsTotal += hStat.u.usageData_v0.data.hb[hbCount].stat.rx.frames;
                    rxByteTotal += hStat.u.usageData_v0.data.hb[hbCount].stat.rx.bytes;
                    dropTotal += hStat.u.usageData_v0.data.hb[hbCount].stat.drop.frames;
                }
            }

            current_stats[stream_id].current_packets = rxPktsTotal - rxPktsStart[stream_id];
            current_stats[stream_id].current_bytes = rxByteTotal - rxByteStart[stream_id];
            current_stats[stream_id].current_drops = dropTotal - dropStart[stream_id];
        }

        StatsSetUI64(tv, streamCounters[inst_id].pkts, current_stats[stream_id].current_packets);
        StatsSetUI64(tv, streamCounters[inst_id].byte, current_stats[stream_id].current_bytes);
        StatsSetUI64(tv, streamCounters[inst_id].drop, current_stats[stream_id].current_drops);

        ++inst_id;
    }
    return num_active;
}

static void *NapatechStatsLoop(void *arg)
{
    ThreadVars *tv = (ThreadVars *) arg;

    int status;
    char error_buffer[80]; // Error buffer
    NtInfoStream_t hInfo;
    NtStatStream_t hStatStream;

    NapatechStreamConfig stream_config[MAX_STREAMS];
    uint16_t stream_cnt = NapatechGetStreamConfig(stream_config);

    /* Open the info and Statistics */
    if ((status = NT_InfoOpen(&hInfo, "StatsLoopInfoStream")) != NT_SUCCESS) {
        NT_ExplainError(status, error_buffer, sizeof (error_buffer) - 1);
        SCLogError(SC_ERR_RUNMODE, "NT_InfoOpen() failed: %s\n", error_buffer);
        return NULL;
    }

    if ((status = NT_StatOpen(&hStatStream, "StatsLoopStatsStream")) != NT_SUCCESS) {
        /* Get the status code as text */
        NT_ExplainError(status, error_buffer, sizeof (error_buffer));
        SCLogError(SC_ERR_RUNMODE, "NT_StatOpen() failed: %s\n", error_buffer);
        return NULL;
    }

    StreamCounters streamCounters[MAX_STREAMS];
    for (int i = 0; i < stream_cnt; ++i) {
        char *pkts_buf = SCCalloc(1, 32);
        if (unlikely(pkts_buf == NULL)) {
            SCLogError(SC_ERR_MEM_ALLOC,
                    "Failed to allocate memory for NAPATECH stream counter.");
            exit(EXIT_FAILURE);
        }

        snprintf(pkts_buf, 32, "nt%d.pkts", stream_config[i].stream_id);
        streamCounters[i].pkts = StatsRegisterCounter(pkts_buf, tv);

        char *byte_buf = SCCalloc(1, 32);
        if (unlikely(byte_buf == NULL)) {
            SCLogError(SC_ERR_MEM_ALLOC,
                    "Failed to allocate memory for NAPATECH stream counter.");
            exit(EXIT_FAILURE);
        }
        snprintf(byte_buf, 32, "nt%d.bytes", stream_config[i].stream_id);
        streamCounters[i].byte = StatsRegisterCounter(byte_buf, tv);

        char *drop_buf = SCCalloc(1, 32);
        if (unlikely(drop_buf == NULL)) {
            SCLogError(SC_ERR_MEM_ALLOC,
                    "Failed to allocate memory for NAPATECH stream counter.");
            exit(EXIT_FAILURE);
        }
        snprintf(drop_buf, 32, "nt%d.drop", stream_config[i].stream_id);
        streamCounters[i].drop = StatsRegisterCounter(drop_buf, tv);
    }

    StatsSetupPrivate(tv);

    for (int i = 0; i < stream_cnt; ++i) {
        StatsSetUI64(tv, streamCounters[i].pkts, 0);
        StatsSetUI64(tv, streamCounters[i].byte, 0);
        StatsSetUI64(tv, streamCounters[i].drop, 0);
    }

    uint32_t num_active = UpdateStreamStats(tv, hInfo, hStatStream,
            stream_cnt, stream_config, streamCounters);

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

        UpdateStreamStats(tv, hInfo, hStatStream,
                stream_cnt, stream_config, streamCounters);

        StatsSyncCountersIfSignalled(tv);
        usleep(1000000);
    }

    /* CLEAN UP NT Resources and Close the info stream */
    if ((status = NT_InfoClose(hInfo)) != NT_SUCCESS) {
        NT_ExplainError(status, error_buffer, sizeof (error_buffer) - 1);
        SCLogError(SC_ERR_RUNMODE, "NT_InfoClose() failed: %s\n", error_buffer);
        return NULL;
    }

    /* Close the statistics stream */
    if ((status = NT_StatClose(hStatStream)) != NT_SUCCESS) {
        /* Get the status code as text */
        NT_ExplainError(status, error_buffer, sizeof (error_buffer));
        SCLogError(SC_ERR_RUNMODE, "NT_StatClose() failed: %s\n", error_buffer);
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
                    if (strncmp(lnode->val, "all", 4) == 0) {
                        /* check that the sting in the config file is correctly specified */
                        if (cpu_spec != CONFIG_SPECIFIER_UNDEFINED) {
                            SCLogError(SC_ERR_NAPATECH_PARSE_CONFIG,
                                    "Only one Napatech port specifier type allowed.");
                            exit(EXIT_FAILURE);
                        }
                        cpu_spec = CONFIG_SPECIFIER_RANGE;
                        worker_count = UtilCpuGetNumProcessorsConfigured();
                    } else if (strchr(lnode->val, '-')) {
                        /* check that the sting in the config file is correctly specified */
                        if (cpu_spec != CONFIG_SPECIFIER_UNDEFINED) {
                            SCLogError(SC_ERR_NAPATECH_PARSE_CONFIG,
                                    "Only one Napatech port specifier type allowed.");
                            exit(EXIT_FAILURE);
                        }
                        cpu_spec = CONFIG_SPECIFIER_RANGE;

                        char copystr[16];
                        strlcpy(copystr, lnode->val, 16);

                        start = atoi(copystr);
                        end = atoi(strchr(copystr, '-') + 1);
                        worker_count = end - start + 1;

                    } else {
                        /* check that the sting in the config file is correctly specified */
                        if (cpu_spec == CONFIG_SPECIFIER_RANGE) {
                            SCLogError(SC_ERR_NAPATECH_PARSE_CONFIG,
                                    "Napatech port range specifiers cannot be combined with individual stream specifiers.");
                            exit(EXIT_FAILURE);
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

int NapatechGetStreamConfig(NapatechStreamConfig stream_config[])
{
    int status;
    char error_buffer[80]; // Error buffer
    NtStatStream_t hStatStream;
    NtStatistics_t hStat; // Stat handle.
    NtInfoStream_t info_stream;
    NtInfo_t info;
    uint16_t instance_cnt = 0;
    int use_all_streams = 0;
    int set_cpu_affinity = 0;
    ConfNode *ntstreams;
    uint16_t stream_id = 0;
    uint16_t start = 0;
    uint16_t end = 0;

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
        NT_ExplainError(status, error_buffer, sizeof (error_buffer) - 1);
        SCLogError(SC_ERR_NAPATECH_STREAMS_REGISTER_FAILED,
                "NT_InfoOpen failed: %s", error_buffer);
        return -1;
    }

    if ((status = NT_StatOpen(&hStatStream, "StatsStream")) != NT_SUCCESS) {
        /* Get the status code as text */
        NT_ExplainError(status, error_buffer, sizeof (error_buffer));
        SCLogError(SC_ERR_RUNMODE, "NT_StatOpen() failed: %s\n", error_buffer);
        return -1;
    }

    if (use_all_streams) {
        info.cmd = NT_INFO_CMD_READ_STREAM;
        if ((status = NT_InfoRead(info_stream, &info)) != NT_SUCCESS) {
            NT_ExplainError(status, error_buffer, sizeof (error_buffer) - 1);
            SCLogError(SC_ERR_NAPATECH_STREAMS_REGISTER_FAILED,
                    "NT_InfoRead failed: %s", error_buffer);
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

            if ((status = NT_StatRead(hStatStream, &hStat)) != NT_SUCCESS) {
                /* Get the status code as text */
                NT_ExplainError(status, error_buffer, sizeof (error_buffer));
                SCLogError(SC_ERR_NAPATECH_INIT_FAILED,
                        "NT_StatRead() failed: %s\n", error_buffer);
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
        ConfGetBool("threading.set-cpu-affinity", &set_cpu_affinity);
        if (NapatechIsAutoConfigEnabled() && (set_cpu_affinity == 1)) {
            start = 0;
            end = CountWorkerThreads() - 1;
        } else {
            /* When not using the default streams we need to
             * parse the array of streams from the conf */
            if ((ntstreams = ConfGetNode("napatech.streams")) == NULL) {
                SCLogError(SC_ERR_RUNMODE,
                        "Failed retrieving napatech.streams from Config");
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
                    SCLogError(SC_ERR_NAPATECH_STREAMS_REGISTER_FAILED,
                            "Couldn't Parse Stream Configuration");
                    return -1;
                }

                if (strchr(stream->val, '-')) {
                    if (stream_spec != CONFIG_SPECIFIER_UNDEFINED) {
                        SCLogError(SC_ERR_NAPATECH_PARSE_CONFIG,
                                "Only one Napatech stream range specifier allowed.");
                        return -1;
                    }
                    stream_spec = CONFIG_SPECIFIER_RANGE;

                    char copystr[16];
                    strlcpy(copystr, stream->val, 16);

                    start = atoi(copystr);
                    end = atoi(strchr(copystr, '-') + 1);
                } else {
                    if (stream_spec == CONFIG_SPECIFIER_RANGE) {
                        SCLogError(SC_ERR_NAPATECH_PARSE_CONFIG,
                                "Napatech range and individual specifiers cannot be combined.");
                        exit(EXIT_FAILURE);
                    }
                    stream_spec = CONFIG_SPECIFIER_INDIVIDUAL;

                    stream_config[instance_cnt].stream_id = atoi(stream->val);
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

            if ((status = NT_StatRead(hStatStream, &hStat)) != NT_SUCCESS) {
                /* Get the status code as text */
                NT_ExplainError(status, error_buffer, sizeof (error_buffer));
                SCLogError(SC_ERR_NAPATECH_INIT_FAILED,
                        "NT_StatRead() failed: %s\n", error_buffer);
                return -1;
            }

            if (hStat.u.usageData_v0.data.numHostBufferUsed > 0) {
                stream_config[instance_cnt].is_active = true;
            }
            instance_cnt++;
        }
    }

    /* Close the statistics stream */
    if ((status = NT_StatClose(hStatStream)) != NT_SUCCESS) {
        /* Get the status code as text */
        NT_ExplainError(status, error_buffer, sizeof (error_buffer));
        SCLogError(SC_ERR_RUNMODE, "NT_StatClose() failed: %s\n", error_buffer);
        return -1;
    }

    if ((status = NT_InfoClose(info_stream)) != NT_SUCCESS) {
        NT_ExplainError(status, error_buffer, sizeof (error_buffer) - 1);
        SCLogError(SC_ERR_NAPATECH_STREAMS_REGISTER_FAILED,
                "NT_InfoClose failed: %s", error_buffer);
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
    NtStatStream_t hStatStream;

    char error_buffer[NT_ERRBUF_SIZE]; // Error buffer
    int status; // Status variable

    const uint32_t alertInterval = 25;

    uint32_t OB_fill_level[MAX_STREAMS] = {0};
    uint32_t OB_alert_level[MAX_STREAMS] = {0};
    uint32_t ave_OB_fill_level[MAX_STREAMS] = {0};

    uint32_t HB_fill_level[MAX_STREAMS] = {0};
    uint32_t HB_alert_level[MAX_STREAMS] = {0};
    uint32_t ave_HB_fill_level[MAX_STREAMS] = {0};

    /* Open the info and Statistics */
    if ((status = NT_InfoOpen(&hInfo, "InfoStream")) != NT_SUCCESS) {
        NT_ExplainError(status, error_buffer, sizeof (error_buffer) - 1);
        SCLogError(SC_ERR_NAPATECH_INIT_FAILED,
                "NT_InfoOpen() failed: %s\n", error_buffer);
        exit(EXIT_FAILURE);
    }

    if ((status = NT_StatOpen(&hStatStream, "StatsStream")) != NT_SUCCESS) {
        /* Get the status code as text */
        NT_ExplainError(status, error_buffer, sizeof (error_buffer));
        SCLogError(SC_ERR_NAPATECH_INIT_FAILED,
                "NT_StatOpen() failed: %s\n", error_buffer);
        exit(EXIT_FAILURE);
    }

    /* Read the info on all streams instantiated in the system */
    hStreamInfo.cmd = NT_INFO_CMD_READ_STREAM;
    if ((status = NT_InfoRead(hInfo, &hStreamInfo)) != NT_SUCCESS) {
        NT_ExplainError(status, error_buffer, sizeof (error_buffer) - 1);
        SCLogError(SC_ERR_NAPATECH_INIT_FAILED,
                "NT_InfoRead() failed: %s\n", error_buffer);
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
            NT_ExplainError(status, error_buffer, sizeof (error_buffer) - 1);
            SCLogError(SC_ERR_NAPATECH_INIT_FAILED,
                    "NT_InfoRead() failed: %s\n", error_buffer);
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

                if ((status = NT_StatRead(hStatStream, &hStat)) != NT_SUCCESS) {
                    /* Get the status code as text */
                    NT_ExplainError(status, error_buffer, sizeof (error_buffer));
                    SCLogError(SC_ERR_NAPATECH_INIT_FAILED,
                            "NT_StatRead() failed: %s\n", error_buffer);
                    exit(EXIT_FAILURE);
                }

                if (hStat.u.usageData_v0.data.numHostBufferUsed == 0) {
                    ++stream_id;
                    continue;
                }
            } while (hStat.u.usageData_v0.data.numHostBufferUsed == 0);

            if (RegisteredStream(stream_id, num_registered, registered_streams)) {
                ave_OB_fill_level[stream_id] = 0;
                ave_HB_fill_level[stream_id] = 0;

                for (uint32_t hb_count = 0;
                        hb_count < hStat.u.usageData_v0.data.numHostBufferUsed;
                        hb_count++) {

                    OB_fill_level[hb_count] =
                            ((100 * hStat.u.usageData_v0.data.hb[hb_count].onboardBuffering.used) /
                            hStat.u.usageData_v0.data.hb[hb_count].onboardBuffering.size);

                    if (OB_fill_level[hb_count] > 100) {
                        OB_fill_level[hb_count] = 100;
                    }

                    uint32_t bufSize = hStat.u.usageData_v0.data.hb[hb_count].enQueuedAdapter / 1024
                            + hStat.u.usageData_v0.data.hb[hb_count].deQueued / 1024
                            + hStat.u.usageData_v0.data.hb[hb_count].enQueued / 1024
                            - HB_HIGHWATER;

                    HB_fill_level[hb_count] = (uint32_t)
                            ((100 * hStat.u.usageData_v0.data.hb[hb_count].deQueued / 1024) /
                            bufSize);

                    ave_OB_fill_level[stream_id] += OB_fill_level[hb_count];
                    ave_HB_fill_level[stream_id] += HB_fill_level[hb_count];
                }

                ave_OB_fill_level[stream_id] /= hStat.u.usageData_v0.data.numHostBufferUsed;
                ave_HB_fill_level[stream_id] /= hStat.u.usageData_v0.data.numHostBufferUsed;

                /* Host Buffer Fill Level warnings... */
                if (ave_HB_fill_level[stream_id] >= (HB_alert_level[stream_id] + alertInterval)) {

                    while (ave_HB_fill_level[stream_id] >= HB_alert_level[stream_id]
                            + alertInterval) {

                        HB_alert_level[stream_id] += alertInterval;
                    }
                    SCLogInfo("nt%d - Increasing Host Buffer Fill Level : %4d%%",
                            stream_id, ave_HB_fill_level[stream_id] - 1);
                }

                if (HB_alert_level[stream_id] > 0) {
                    if ((ave_HB_fill_level[stream_id] <= (HB_alert_level[stream_id] - alertInterval))) {
                        SCLogInfo("nt%d - Decreasing Host Buffer Fill Level: %4d%%",
                                stream_id, ave_HB_fill_level[stream_id]);

                        while (ave_HB_fill_level[stream_id] <= (HB_alert_level[stream_id] - alertInterval)) {
                            if ((HB_alert_level[stream_id]) > 0) {
                                HB_alert_level[stream_id] -= alertInterval;
                            } else break;
                        }
                    }
                }

                /* On Board SDRAM Fill Level warnings... */
                if (ave_OB_fill_level[stream_id] >= (OB_alert_level[stream_id] + alertInterval)) {
                    while (ave_OB_fill_level[stream_id] >= OB_alert_level[stream_id] + alertInterval) {
                        OB_alert_level[stream_id] += alertInterval;

                    }
                    SCLogInfo("nt%d - Increasing Adapter SDRAM Fill Level: %4d%%",
                            stream_id, ave_OB_fill_level[stream_id]);
                }

                if (OB_alert_level[stream_id] > 0) {
                    if ((ave_OB_fill_level[stream_id] <= (OB_alert_level[stream_id] - alertInterval))) {
                        SCLogInfo("nt%d - Decreasing Adapter SDRAM Fill Level : %4d%%",
                                stream_id, ave_OB_fill_level[stream_id]);

                        while (ave_OB_fill_level[stream_id] <= (OB_alert_level[stream_id] - alertInterval)) {
                            if ((OB_alert_level[stream_id]) > 0) {
                                OB_alert_level[stream_id] -= alertInterval;
                            } else break;
                        }
                    }
                }
            }
            ++stream_id;
        }
    }

    if ((status = NT_InfoClose(hInfo)) != NT_SUCCESS) {
        NT_ExplainError(status, error_buffer, sizeof (error_buffer) - 1);
        SCLogError(SC_ERR_NAPATECH_INIT_FAILED, "NT_InfoClose() failed: %s\n", error_buffer);
        exit(EXIT_FAILURE);
    }

    /* Close the statistics stream */
    if ((status = NT_StatClose(hStatStream)) != NT_SUCCESS) {
        /* Get the status code as text */
        NT_ExplainError(status, error_buffer, sizeof (error_buffer));
        SCLogError(SC_ERR_NAPATECH_INIT_FAILED, "NT_StatClose() failed: %s\n", error_buffer);
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
        SCLogError(SC_ERR_THREAD_CREATE,
                "Error creating a thread for NapatechStats - Killing engine.");
        exit(EXIT_FAILURE);
    }

    if (TmThreadSpawn(stats_tv) != 0) {
        SCLogError(SC_ERR_THREAD_SPAWN,
                "Failed to spawn thread for NapatechStats - Killing engine.");
        exit(EXIT_FAILURE);
    }

    ThreadVars *buf_monitor_tv = TmThreadCreate("NapatechBufMonitor",
            NULL, NULL,
            NULL, NULL,
            "custom", NapatechBufMonitorLoop, 0);

    if (buf_monitor_tv == NULL) {
        SCLogError(SC_ERR_THREAD_CREATE,
                "Error creating a thread for NapatechBufMonitor - Killing engine.");
        exit(EXIT_FAILURE);
    }

    if (TmThreadSpawn(buf_monitor_tv) != 0) {
        SCLogError(SC_ERR_THREAD_SPAWN,
                "Failed to spawn thread for NapatechBufMonitor - Killing engine.");
        exit(EXIT_FAILURE);
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

static bool NapatechSetHashmode(uint32_t *filter_id)
{
    uint32_t status = 0;
    const char *hash_mode;
    static NtConfigStream_t hconfig;
    char ntpl_cmd[64];
    NtNtplInfo_t ntpl_info;

    *filter_id = 0;

    /* Get the hashmode from the conf file. */
    ConfGetValue("napatech.hashmode", &hash_mode);

    snprintf(ntpl_cmd, 64, "hashmode = %s", hash_mode);

    /* Issue the NTPL command */
    if ((status = NT_ConfigOpen(&hconfig, "ConfigStream")) != NT_SUCCESS) {
        NAPATECH_ERROR(SC_ERR_NAPATECH_STREAMS_REGISTER_FAILED, status);
        return false;
    }

    if ((status = NT_NTPL(hconfig, ntpl_cmd, &ntpl_info,
            NT_NTPL_PARSER_VALIDATE_NORMAL)) == NT_SUCCESS) {
        *filter_id = ntpl_info.ntplId;
        SCLogInfo("Napatech hashmode: %s ID: %d", hash_mode, status);
    } else {
        NAPATECH_NTPL_ERROR(ntpl_cmd, ntpl_info, status);
        status = 0;
    }

    return status;
}

static uint32_t GetStreamNUMAs(uint32_t stream_id, int stream_numas[])
{
    NtStatistics_t hStat; // Stat handle.
    NtStatStream_t hStatStream;
    int status; // Status variable

    for (int i = 0; i < MAX_HOSTBUFFERS; ++i)
        stream_numas[i] = -1;

    if ((status = NT_StatOpen(&hStatStream, "StatsStream")) != NT_SUCCESS) {
        NAPATECH_ERROR(SC_ERR_NAPATECH_INIT_FAILED, status);
        exit(EXIT_FAILURE);
    }

    char pktCntStr[4096];
    memset(pktCntStr, 0, sizeof (pktCntStr));


    /* Read usage data for the chosen stream ID */
    hStat.cmd = NT_STATISTICS_READ_CMD_USAGE_DATA_V0;
    hStat.u.usageData_v0.streamid = (uint8_t) stream_id;

    if ((status = NT_StatRead(hStatStream, &hStat)) != NT_SUCCESS) {
        NAPATECH_ERROR(SC_ERR_NAPATECH_INIT_FAILED, status);
        exit(EXIT_FAILURE);
    }

    for (uint32_t hb_id = 0; hb_id < hStat.u.usageData_v0.data.numHostBufferUsed; ++hb_id) {
        stream_numas[hb_id] = hStat.u.usageData_v0.data.hb[hb_id].numaNode;
    }

    return hStat.u.usageData_v0.data.numHostBufferUsed;
}

uint32_t NapatechSetupTraffic(uint32_t first_stream, uint32_t last_stream,
        uint32_t *filter_id, uint32_t *hash_id)
{
#define PORTS_SPEC_SIZE 64

    char ports_spec[PORTS_SPEC_SIZE];
    ConfNode *ntports;
    bool first_iteration = true;
    int status = 0;
    static NtConfigStream_t hconfig;
    char ntpl_cmd[128];

    NapatechSetHashmode(hash_id);

    /* When not using the default streams we need to parse
     * the array of streams from the conf
     */
    if ((ntports = ConfGetNode("napatech.ports")) == NULL) {
        SCLogError(SC_ERR_RUNMODE, "Failed retrieving napatech.ports from Conf");
        exit(EXIT_FAILURE);
    }

    /* Loop through all ports in the array */
    ConfNode *port;
    enum CONFIG_SPECIFIER stream_spec = CONFIG_SPECIFIER_UNDEFINED;

    /* Build the NTPL command using values in the config file. */
    TAILQ_FOREACH(port, &ntports->head, next)
    {
        if (port == NULL) {
            SCLogError(SC_ERR_NAPATECH_STREAMS_REGISTER_FAILED,
                    "Couldn't Parse Port Configuration");
            exit(EXIT_FAILURE);
        }

        uint8_t start, end;
        if (strncmp(port->val, "all", 3) == 0) {
            /* check that the sting in the config file is correctly specified */
            if (stream_spec != CONFIG_SPECIFIER_UNDEFINED) {
                SCLogError(SC_ERR_NAPATECH_PARSE_CONFIG,
                        "Only one Napatech port specifier type allowed.");
                exit(EXIT_FAILURE);
            }
            stream_spec = CONFIG_SPECIFIER_RANGE;

            snprintf(ports_spec, sizeof(ports_spec), "all");
        } else if (strchr(port->val, '-')) {
            /* check that the sting in the config file is correctly specified */
            if (stream_spec != CONFIG_SPECIFIER_UNDEFINED) {
                SCLogError(SC_ERR_NAPATECH_PARSE_CONFIG,
                        "Only one Napatech port specifier type allowed.");
                exit(EXIT_FAILURE);
            }
            stream_spec = CONFIG_SPECIFIER_RANGE;

            char copystr[16];
            strlcpy(copystr, port->val, sizeof(copystr));

            start = atoi(copystr);
            end = atoi(strchr(copystr, '-') + 1);
            snprintf(ports_spec, sizeof(ports_spec), "port == (%d..%d)", start, end);

        } else {
            /* check that the sting in the config file is correctly specified */
            if (stream_spec == CONFIG_SPECIFIER_RANGE) {
                SCLogError(SC_ERR_NAPATECH_PARSE_CONFIG,
                        "Napatech port range specifiers cannot be combined with individual stream specifiers.");
                exit(EXIT_FAILURE);
            }
            stream_spec = CONFIG_SPECIFIER_INDIVIDUAL;

            /* Determine the ports to use on the NTPL assign statement*/
            if (first_iteration) {
                snprintf(ports_spec, sizeof(ports_spec), "port==%s", port->val);
                first_iteration = false;
            } else {
                char temp[PORTS_SPEC_SIZE];
                snprintf(temp, sizeof(temp), "%s,%s",ports_spec,port->val);
                snprintf(ports_spec, sizeof(ports_spec), "%s", temp);
            }
        }
    }

    /* Build the NTPL command */
    snprintf(ntpl_cmd, sizeof(ntpl_cmd), "assign[streamid=(%d..%d)] = %s",
            first_stream, last_stream, ports_spec);

    NtNtplInfo_t ntpl_info;

    if ((status = NT_ConfigOpen(&hconfig, "ConfigStream")) != NT_SUCCESS) {
        NAPATECH_ERROR(SC_ERR_NAPATECH_INIT_FAILED, status);
        exit(EXIT_FAILURE);
    }

    if ((status = NT_NTPL(hconfig, ntpl_cmd, &ntpl_info,
            NT_NTPL_PARSER_VALIDATE_NORMAL)) == NT_SUCCESS) {
        *filter_id = ntpl_info.ntplId;
        status = ntpl_info.u.errorData.errCode;
        SCLogInfo("NTPL filter assignment \"%s\" returned filter id %4d",
                ntpl_cmd, *filter_id);
    } else {
        NAPATECH_NTPL_ERROR(ntpl_cmd, ntpl_info, status);
        status = ntpl_info.u.errorData.errCode;
        return false;
    }

    SCLogInfo("Host-buffer NUMA assignments: ");
    int numa_nodes[MAX_HOSTBUFFERS];
    uint32_t stream_id;
    for (stream_id = first_stream; stream_id < last_stream; ++stream_id) {
        char temp1[256];
        char temp2[256];

        uint32_t num_host_buffers = GetStreamNUMAs(stream_id, numa_nodes);

        snprintf(temp1, 256, "    stream %d:", stream_id);

        for (uint32_t hb_id = 0; hb_id < num_host_buffers; ++hb_id) {
            snprintf(temp2, 256, "%s %d ", temp1, numa_nodes[hb_id]);
            snprintf(temp1, 256, "%s", temp2);
        }

        SCLogInfo("%s", temp1);
    }

    return status;
}

bool NapatechDeleteFilter(uint32_t filter_id)
{
    uint32_t status = 0;
    static NtConfigStream_t hconfig;
    char ntpl_cmd[64];
    NtNtplInfo_t ntpl_info;

    /* issue an NTPL command to delete the filter */
    snprintf(ntpl_cmd, 64, "delete = %d", filter_id);

    if ((status = NT_ConfigOpen(&hconfig, "ConfigStream")) != NT_SUCCESS) {
        NAPATECH_ERROR(SC_ERR_NAPATECH_STREAMS_REGISTER_FAILED, status);
        exit(EXIT_FAILURE);
    }

    if ((status = NT_NTPL(hconfig, ntpl_cmd, &ntpl_info,
            NT_NTPL_PARSER_VALIDATE_NORMAL)) == NT_SUCCESS) {
        status = ntpl_info.ntplId;
        SCLogInfo("Removed Napatech filter %d. ", filter_id);
    } else {
        NAPATECH_NTPL_ERROR(ntpl_cmd, ntpl_info, status);
        status = 0;
    }

    return status;
}

#endif // HAVE_NAPATECH
