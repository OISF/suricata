/* Copyright (C) 2019 Open Information Security Foundation
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
#include "app-layer-parser.h"
#include "flow-manager.h"
#include "tm-threads.h"
#include "flow-timeout.h"
#include "ippair.h"
#include "stream-tcp.h"
#include "defrag.h"
#include "app-layer.h"
#include "suricata.h"
#include "util-signal.h"
#include "util-misc.h"

#ifdef HAVE_RUST
#include "rust.h"
#include "rust-core-gen.h"
#endif

#ifndef AFLFUZZ_NO_RANDOM
int g_disable_randomness = 0;
#else
int g_disable_randomness = 1;
#endif

/** Maximum packets to simultaneously process. */
intmax_t max_pending_packets;

/** global indicating if detection is enabled */
int g_detect_disabled = 0;

/** suricata engine control flags */
volatile uint8_t suricata_ctl_flags = 0;

/** Run mode selected */
int run_mode = RUNMODE_UNKNOWN;

enum EngineMode g_engine_mode = ENGINE_MODE_IDS;
uint8_t host_mode = SURI_HOST_IS_SNIFFER_ONLY;

/*
 * Flag to indicate if the engine is at the initialization
 * or already processing packets. 3 stages: SURICATA_INIT,
 * SURICATA_RUNTIME and SURICATA_FINALIZE
 */
SC_ATOMIC_DECLARE(unsigned int, engine_stage);

int coverage_unittests;
int g_ut_modules;
int g_ut_covered;

/**
 * \brief Used to indicate that the current task is done.
 *
 * This is mainly used by pcap-file to tell it has finished
 * to treat a pcap files when running in unix-socket mode.
 */
void EngineDone(void)
{
    suricata_ctl_flags |= SURICATA_DONE;
}

/** \brief make sure threads can stop the engine by calling this
 *  function. Purpose: pcap file mode needs to be able to tell the
 *  engine the file eof is reached. */
void EngineStop(void)
{
    suricata_ctl_flags |= SURICATA_STOP;
}

int EngineModeIsIPS(void)
{
    return (g_engine_mode == ENGINE_MODE_IPS);
}

static void SCPrintElapsedTime(struct timeval *start_time)
{
    if (start_time == NULL)
        return;
    struct timeval end_time;
    memset(&end_time, 0, sizeof(end_time));
    gettimeofday(&end_time, NULL);
    uint64_t milliseconds = ((end_time.tv_sec - start_time->tv_sec) * 1000) +
        (((1000000 + end_time.tv_usec - start_time->tv_usec) / 1000) - 1000);
    SCLogInfo("time elapsed %.3fs", (float)milliseconds/(float)1000);
}

/* clean up / shutdown code for both the main modes and for
 * unix socket mode.
 *
 * Will be run once per pcap in unix-socket mode */
void PostRunDeinit(const int runmode, struct timeval *start_time)
{
    if (runmode == RUNMODE_UNIX_SOCKET)
        return;

    /* needed by FlowForceReassembly */
    PacketPoolInit();

    /* handle graceful shutdown of the flow engine, it's helper
     * threads and the packet threads */
    FlowDisableFlowManagerThread();
    TmThreadDisableReceiveThreads();
    FlowForceReassembly();
    TmThreadDisablePacketThreads();
    SCPrintElapsedTime(start_time);
    FlowDisableFlowRecyclerThread();

    /* kill the stats threads */
    TmThreadKillThreadsFamily(TVT_MGMT);
    TmThreadClearThreadsFamily(TVT_MGMT);

    /* kill packet threads -- already in 'disabled' state */
    TmThreadKillThreadsFamily(TVT_PPT);
    TmThreadClearThreadsFamily(TVT_PPT);

    PacketPoolDestroy();

    /* mgt and ppt threads killed, we can run non thread-safe
     * shutdown functions */
    StatsReleaseResources();
    DecodeUnregisterCounters();
    RunModeShutDown();
    FlowShutdown();
    IPPairShutdown();
    HostCleanup();
    StreamTcpFreeConfig(STREAM_VERBOSE);
    DefragDestroy();

    TmqResetQueues();
#ifdef PROFILING
    if (profiling_rules_enabled)
    SCProfilingDump();
    SCProfilingDestroy();
#endif
}


/* initialization code for both the main modes and for
 * unix socket mode.
 *
 * Will be run once per pcap in unix-socket mode */
void PreRunInit(const int runmode)
{
    if (runmode == RUNMODE_UNIX_SOCKET)
        return;

    StatsInit();
#ifdef PROFILING
    SCProfilingRulesGlobalInit();
    SCProfilingKeywordsGlobalInit();
    SCProfilingPrefilterGlobalInit();
    SCProfilingSghsGlobalInit();
    SCProfilingInit();
#endif /* PROFILING */
    DefragInit();
    FlowInitConfig(FLOW_QUIET);
    IPPairInitConfig(FLOW_QUIET);
    StreamTcpInitConfig(STREAM_VERBOSE);
    AppLayerParserPostStreamSetup();
    AppLayerRegisterGlobalCounters();
}


/* tasks we need to run before packets start flowing,
 * but after we dropped privs */
void PreRunPostPrivsDropInit(const int runmode)
{
    if (runmode == RUNMODE_UNIX_SOCKET)
        return;

    StatsSetupPostConfigPreOutput();
    RunModeInitializeOutputs();
    StatsSetupPostConfigPostOutput();
}

int RunmodeGetCurrent(void)
{
    return run_mode;
}

int RunmodeIsUnittests(void)
{
    if (run_mode == RUNMODE_UNITTEST)
        return 1;

    return 0;
}

int SuriHasSigFile(void)
{
    return (suricata.sig_file != NULL);
}

SuricataContext context;

// Global initialization common to all runmodes
int InitGlobal() {
#ifdef HAVE_RUST
    context.SCLogMessage = SCLogMessage;
    context.DetectEngineStateFree = DetectEngineStateFree;
    context.AppLayerDecoderEventsSetEventRaw =
    AppLayerDecoderEventsSetEventRaw;
    context.AppLayerDecoderEventsFreeEvents = AppLayerDecoderEventsFreeEvents;

    context.FileOpenFileWithId = FileOpenFileWithId;
    context.FileCloseFileById = FileCloseFileById;
    context.FileAppendDataById = FileAppendDataById;
    context.FileAppendGAPById = FileAppendGAPById;
    context.FileContainerRecycle = FileContainerRecycle;
    context.FilePrune = FilePrune;
    context.FileSetTx = FileContainerSetTx;

    rs_init(&context);
#endif

    SC_ATOMIC_INIT(engine_stage);

    /* initialize the logging subsys */
    SCLogInitLogModule(NULL);

    (void)SCSetThreadName("Suricata-Main");

    /* Ignore SIGUSR2 as early as possble. We redeclare interest
     * once we're done launching threads. The goal is to either die
     * completely or handle any and all SIGUSR2s correctly.
     */
#ifndef OS_WIN32
    UtilSignalHandlerSetup(SIGUSR2, SIG_IGN);
    if (UtilSignalBlock(SIGUSR2)) {
        SCLogError(SC_ERR_INITIALIZATION, "SIGUSR2 initialization error");
        return EXIT_FAILURE;
    }
#endif

    ParseSizeInit();
    RunModeRegisterRunModes();

    /* Initialize the configuration module. */
    ConfInit();

    return 0;
}
