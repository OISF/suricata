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
#include "util-pidfile.h"
#include "util-daemon.h"
#include "util-privs.h"
#include "util-ioctl.h"
#include "util-byte.h"
#include "util-host-os-info.h"
#include "tm-queuehandlers.h"
#include "util-cidr.h"
#include "util-proto-name.h"
#include "detect-engine-tag.h"
#include "detect-engine-threshold.h"
#include "host-bit.h"
#include "ippair-bit.h"
#include "detect-engine-address.h"
#include "detect-engine-port.h"
#include "app-layer-htp.h"
#include "util-magic.h"
#include "util-decode-asn1.h"
#include "util-coredump-config.h"

#include "flow-bypass.h"
#include "source-nfq-prototypes.h"
#include "source-pcap-file.h"
#include "source-pfring.h"
#include "source-erf-file.h"
#include "source-erf-dag.h"
#include "source-napatech.h"
#include "respond-reject.h"
#include "output.h"
#include "source-windivert-prototypes.h"

#include "detect-fast-pattern.h"
#include "util-threshold-config.h"

#ifdef HAVE_NSS
#include <prinit.h>
#include <nss.h>
#endif

#ifdef HAVE_RUST
#include "rust.h"
#include "rust-core-gen.h"
#endif

/** disable randomness to get reproducible results accross runs */
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

/** Engine mode: inline (ENGINE_MODE_IPS) or just
 * detection mode (ENGINE_MODE_IDS by default) */
enum EngineMode g_engine_mode = ENGINE_MODE_IDS;

/** Host mode: set if box is sniffing only
 * or is a router */
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

/** set caps or not */
int sc_set_caps = FALSE;

/** highest mtu of the interfaces we monitor */
int g_default_mtu = 0;

/** determine (without branching) if we include the vlan_ids when hashing or
 * comparing flows */
uint16_t g_vlan_mask = 0xffff;

/*
 * we put this here, because we only use it here in init.
 */
volatile sig_atomic_t sigint_count = 0;
volatile sig_atomic_t sighup_count = 0;
volatile sig_atomic_t sigterm_count = 0;
volatile sig_atomic_t sigusr2_count = 0;

bool g_system = false;


/* Max packets processed simultaniously per thread. */
#define DEFAULT_MAX_PENDING_PACKETS 1024


/** signal handlers
 *
 *  WARNING: don't use the SCLog* API in the handlers. The API is complex
 *  with memory allocation possibly happening, calls to syslog, json message
 *  construction, etc.
 */

void SignalHandlerSigint(/*@unused@*/ int sig)
{
    sigint_count = 1;
}
void SignalHandlerSigterm(/*@unused@*/ int sig)
{
    sigterm_count = 1;
}
#ifndef OS_WIN32
/**
 * SIGUSR2 handler.  Just set sigusr2_count.  The main loop will act on
 * it.
 */
void SignalHandlerSigusr2(int sig)
{
    if (sigusr2_count < 2)
        sigusr2_count++;
}

/**
 * SIGHUP handler.  Just set sighup_count.  The main loop will act on
 * it.
 */
void SignalHandlerSigHup(/*@unused@*/ int sig)
{
    sighup_count = 1;
}
#endif

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

void EngineModeSetIPS(void)
{
    g_engine_mode = ENGINE_MODE_IPS;
}

int EngineModeIsIDS(void)
{
    return (g_engine_mode == ENGINE_MODE_IDS);
}

void EngineModeSetIDS(void)
{
    g_engine_mode = ENGINE_MODE_IDS;
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

static int MayDaemonize(SCInstance *suri)
{
    if (suri->daemon == 1 && suri->pid_filename == NULL) {
        const char *pid_filename;

        if (ConfGet("pid-file", &pid_filename) == 1) {
            SCLogInfo("Use pid file %s from config file.", pid_filename);
        } else {
            pid_filename = DEFAULT_PID_FILENAME;
        }
        /* The pid file name may be in config memory, but is needed later. */
        suri->pid_filename = SCStrdup(pid_filename);
        if (suri->pid_filename == NULL) {
            SCLogError(SC_ERR_MEM_ALLOC, "strdup failed: %s", strerror(errno));
            return TM_ECODE_FAILED;
        }
    }

    if (suri->pid_filename != NULL && SCPidfileTestRunning(suri->pid_filename) != 0) {
        SCFree(suri->pid_filename);
        suri->pid_filename = NULL;
        return TM_ECODE_FAILED;
    }

    if (suri->daemon == 1) {
        Daemonize();
    }

    if (suri->pid_filename != NULL) {
        if (SCPidfileCreate(suri->pid_filename) != 0) {
            SCFree(suri->pid_filename);
            suri->pid_filename = NULL;
            SCLogError(SC_ERR_PIDFILE_DAEMON,
                    "Unable to create PID file, concurrent run of"
                    " Suricata can occur.");
            SCLogError(SC_ERR_PIDFILE_DAEMON,
                    "PID file creation WILL be mandatory for daemon mode"
                    " in future version");
        }
    }

    return TM_ECODE_OK;
}

static int InitSignalHandler(SCInstance *suri)
{
    /* registering signals we use */
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    UtilSignalHandlerSetup(SIGINT, SignalHandlerSigint);
    UtilSignalHandlerSetup(SIGTERM, SignalHandlerSigterm);
#endif
#ifndef OS_WIN32
    UtilSignalHandlerSetup(SIGHUP, SignalHandlerSigHup);
    UtilSignalHandlerSetup(SIGPIPE, SIG_IGN);
    UtilSignalHandlerSetup(SIGSYS, SIG_IGN);

    /* Try to get user/group to run suricata as if
       command line as not decide of that */
    if (suri->do_setuid == FALSE && suri->do_setgid == FALSE) {
        const char *id;
        if (ConfGet("run-as.user", &id) == 1) {
            suri->do_setuid = TRUE;
            suri->user_name = id;
        }
        if (ConfGet("run-as.group", &id) == 1) {
            suri->do_setgid = TRUE;
            suri->group_name = id;
        }
    }
    /* Get the suricata user ID to given user ID */
    if (suri->do_setuid == TRUE) {
        if (SCGetUserID(suri->user_name, suri->group_name,
                        &suri->userid, &suri->groupid) != 0) {
            SCLogError(SC_ERR_UID_FAILED, "failed in getting user ID");
            return TM_ECODE_FAILED;
        }

        sc_set_caps = TRUE;
    /* Get the suricata group ID to given group ID */
    } else if (suri->do_setgid == TRUE) {
        if (SCGetGroupID(suri->group_name, &suri->groupid) != 0) {
            SCLogError(SC_ERR_GID_FAILED, "failed in getting group ID");
            return TM_ECODE_FAILED;
        }

        sc_set_caps = TRUE;
    }
#endif /* OS_WIN32 */

    return TM_ECODE_OK;
}

static int ConfigGetCaptureValue(SCInstance *suri)
{
    /* Pull the max pending packets from the config, if not found fall
     * back on a sane default. */
    if (ConfGetInt("max-pending-packets", &max_pending_packets) != 1)
        max_pending_packets = DEFAULT_MAX_PENDING_PACKETS;
    if (max_pending_packets >= 65535) {
        SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY,
                "Maximum max-pending-packets setting is 65534. "
                "Please check %s for errors", suri->conf_filename);
        return TM_ECODE_FAILED;
    }

    SCLogDebug("Max pending packets set to %"PRIiMAX, max_pending_packets);

    /* Pull the default packet size from the config, if not found fall
     * back on a sane default. */
    const char *temp_default_packet_size;
    if ((ConfGet("default-packet-size", &temp_default_packet_size)) != 1) {
        int mtu = 0;
        int lthread;
        int nlive;
        int strip_trailing_plus = 0;
        switch (suri->run_mode) {
#ifdef WINDIVERT
            case RUNMODE_WINDIVERT:
                /* by default, WinDivert collects from all devices */
                mtu = GetGlobalMTUWin32();

                if (mtu > 0) {
                    g_default_mtu = mtu;
                    /* SLL_HEADER_LEN is the longest header + 8 for VLAN */
                    default_packet_size = mtu + SLL_HEADER_LEN + 8;
                    break;
                }

                g_default_mtu = DEFAULT_MTU;
                default_packet_size = DEFAULT_PACKET_SIZE;
                break;
#endif /* WINDIVERT */
            case RUNMODE_NETMAP:
                /* in netmap igb0+ has a special meaning, however the
                 * interface really is igb0 */
                strip_trailing_plus = 1;
                /* fall through */
            case RUNMODE_PCAP_DEV:
            case RUNMODE_AFP_DEV:
            case RUNMODE_PFRING:
                nlive = LiveGetDeviceCount();
                for (lthread = 0; lthread < nlive; lthread++) {
                    const char *live_dev = LiveGetDeviceName(lthread);
                    char dev[128]; /* need to be able to support GUID names on Windows */
                    (void)strlcpy(dev, live_dev, sizeof(dev));

                    if (strip_trailing_plus) {
                        size_t len = strlen(dev);
                        if (len &&
                                (dev[len-1] == '+' ||
                                 dev[len-1] == '^' ||
                                 dev[len-1] == '*'))
                        {
                            dev[len-1] = '\0';
                        }
                    }
                    mtu = GetIfaceMTU(dev);
                    g_default_mtu = MAX(mtu, g_default_mtu);

                    unsigned int iface_max_packet_size = GetIfaceMaxPacketSize(dev);
                    if (iface_max_packet_size > default_packet_size)
                        default_packet_size = iface_max_packet_size;
                }
                if (default_packet_size)
                    break;
                /* fall through */
            default:
                g_default_mtu = DEFAULT_MTU;
                default_packet_size = DEFAULT_PACKET_SIZE;
        }
    } else {
        if (ParseSizeStringU32(temp_default_packet_size, &default_packet_size) < 0) {
            SCLogError(SC_ERR_SIZE_PARSE, "Error parsing max-pending-packets "
                       "from conf file - %s.  Killing engine",
                       temp_default_packet_size);
            return TM_ECODE_FAILED;
        }
    }

    SCLogDebug("Default packet size set to %"PRIu32, default_packet_size);

    return TM_ECODE_OK;
}

static int PostDeviceFinalizedSetup(SCInstance *suri)
{
    SCEnter();

#ifdef HAVE_AF_PACKET
    if (suri->run_mode == RUNMODE_AFP_DEV) {
        if (AFPRunModeIsIPS()) {
            SCLogInfo("AF_PACKET: Setting IPS mode");
            EngineModeSetIPS();
        }
    }
#endif
#ifdef HAVE_NETMAP
    if (suri->run_mode == RUNMODE_NETMAP) {
        if (NetmapRunModeIsIPS()) {
            SCLogInfo("Netmap: Setting IPS mode");
            EngineModeSetIPS();
        }
    }
#endif

    SCReturnInt(TM_ECODE_OK);
}

static void PostConfLoadedSetupHostMode(void)
{
    const char *hostmode = NULL;

    if (ConfGetValue("host-mode", &hostmode) == 1) {
        if (!strcmp(hostmode, "router")) {
            host_mode = SURI_HOST_IS_ROUTER;
        } else if (!strcmp(hostmode, "sniffer-only")) {
            host_mode = SURI_HOST_IS_SNIFFER_ONLY;
        } else {
            if (strcmp(hostmode, "auto") != 0) {
                WarnInvalidConfEntry("host-mode", "%s", "auto");
            }
            if (EngineModeIsIPS()) {
                host_mode = SURI_HOST_IS_ROUTER;
            } else {
                host_mode = SURI_HOST_IS_SNIFFER_ONLY;
            }
        }
    } else {
        if (EngineModeIsIPS()) {
            host_mode = SURI_HOST_IS_ROUTER;
            SCLogInfo("No 'host-mode': suricata is in IPS mode, using "
                      "default setting 'router'");
        } else {
            host_mode = SURI_HOST_IS_SNIFFER_ONLY;
            SCLogInfo("No 'host-mode': suricata is in IDS mode, using "
                      "default setting 'sniffer-only'");
        }
    }

}

/**
 * This function is meant to contain code that needs
 * to be run once the configuration has been loaded.
 */
int PostConfLoadedSetup(SCInstance *suri)
{
    /* do this as early as possible #1577 #1955 */
#ifdef HAVE_LUAJIT
    if (LuajitSetupStatesPool() != 0) {
        SCReturnInt(TM_ECODE_FAILED);
    }
#endif

    /* load the pattern matchers */
    MpmTableSetup();
    SpmTableSetup();

    int disable_offloading;
    if (ConfGetBool("capture.disable-offloading", &disable_offloading) == 0)
        disable_offloading = 1;
    if (disable_offloading) {
        LiveSetOffloadDisable();
    } else {
        LiveSetOffloadWarn();
    }

    if (suri->checksum_validation == -1) {
        const char *cv = NULL;
        if (ConfGetValue("capture.checksum-validation", &cv) == 1) {
            if (strcmp(cv, "none") == 0) {
                suri->checksum_validation = 0;
            } else if (strcmp(cv, "all") == 0) {
                suri->checksum_validation = 1;
            }
        }
    }
    switch (suri->checksum_validation) {
        case 0:
            ConfSet("stream.checksum-validation", "0");
            break;
        case 1:
            ConfSet("stream.checksum-validation", "1");
            break;
    }

    if (suri->runmode_custom_mode) {
        ConfSet("runmode", suri->runmode_custom_mode);
    }

    StorageInit();
#ifdef HAVE_PACKET_EBPF
    EBPFRegisterExtension();
    LiveDevRegisterExtension();
#endif
    RegisterFlowBypassInfo();
    AppLayerSetup();

    /* Suricata will use this umask if provided. By default it will use the
       umask passed on from the shell. */
    const char *custom_umask;
    if (ConfGet("umask", &custom_umask) == 1) {
        uint16_t mask;
        if (ByteExtractStringUint16(&mask, 8, strlen(custom_umask),
                                    custom_umask) > 0) {
            umask((mode_t)mask);
        }
    }

    /* Check for the existance of the default logging directory which we pick
     * from suricata.yaml.  If not found, shut the engine down */
    suri->log_dir = ConfigGetLogDirectory();

    if (ConfigCheckLogDirectory(suri->log_dir) != TM_ECODE_OK) {
        SCLogError(SC_ERR_LOGDIR_CONFIG, "The logging directory \"%s\" "
                "supplied by %s (default-log-dir) doesn't exist. "
                "Shutting down the engine", suri->log_dir, suri->conf_filename);
        SCReturnInt(TM_ECODE_FAILED);
    }

    if (ConfigGetCaptureValue(suri) != TM_ECODE_OK) {
        SCReturnInt(TM_ECODE_FAILED);
    }

#ifdef NFQ
    if (suri->run_mode == RUNMODE_NFQ)
        NFQInitConfig(FALSE);
#endif

    /* Load the Host-OS lookup. */
    SCHInfoLoadFromConfig();

    if (suri->run_mode == RUNMODE_ENGINE_ANALYSIS) {
        SCLogInfo("== Carrying out Engine Analysis ==");
        const char *temp = NULL;
        if (ConfGet("engine-analysis", &temp) == 0) {
            SCLogInfo("no engine-analysis parameter(s) defined in conf file.  "
                      "Please define/enable them in the conf to use this "
                      "feature.");
            SCReturnInt(TM_ECODE_FAILED);
        }
    }

    /* hardcoded initialization code */
    SigTableSetup(); /* load the rule keywords */
    TmqhSetup();

    CIDRInit();
    SCProtoNameInit();

    TagInitCtx();
    PacketAlertTagInit();
    ThresholdInit();
    HostBitInitCtx();
    IPPairBitInitCtx();

    if (DetectAddressTestConfVars() < 0) {
        SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY,
                "basic address vars test failed. Please check %s for errors",
                suri->conf_filename);
        SCReturnInt(TM_ECODE_FAILED);
    }
    if (DetectPortTestConfVars() < 0) {
        SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY,
                "basic port vars test failed. Please check %s for errors",
                suri->conf_filename);
        SCReturnInt(TM_ECODE_FAILED);
    }

    RegisterAllModules();

    AppLayerHtpNeedFileInspection();

    StorageFinalize();

    TmModuleRunInit();

    if (MayDaemonize(suri) != TM_ECODE_OK)
        SCReturnInt(TM_ECODE_FAILED);

    if (InitSignalHandler(suri) != TM_ECODE_OK)
        SCReturnInt(TM_ECODE_FAILED);


#ifdef HAVE_NSS
    if (suri->run_mode != RUNMODE_CONF_TEST) {
        /* init NSS for hashing */
        PR_Init(PR_USER_THREAD, PR_PRIORITY_NORMAL, 0);
        NSS_NoDB_Init(NULL);
    }
#endif

    if (suri->disabled_detect) {
        SCLogConfig("detection engine disabled");
        /* disable raw reassembly */
        (void)ConfSetFinal("stream.reassembly.raw", "false");
    }

    HostInitConfig(HOST_VERBOSE);
#ifdef HAVE_MAGIC
    if (MagicInit() != 0)
        SCReturnInt(TM_ECODE_FAILED);
#endif
    SCAsn1LoadConfig();

    CoredumpLoadConfig();

    DecodeGlobalConfig();

    LiveDeviceFinalize();

    /* set engine mode if L2 IPS */
    if (PostDeviceFinalizedSetup(&suricata) != TM_ECODE_OK) {
        exit(EXIT_FAILURE);
    }

    /* hostmode depends on engine mode being set */
    PostConfLoadedSetupHostMode();

    PreRunInit(suri->run_mode);

    SCReturnInt(TM_ECODE_OK);
}

void RegisterAllModules(void)
{
    // zero all module storage
    memset(tmm_modules, 0, TMM_SIZE * sizeof(TmModule));

    /* commanders */
    TmModuleUnixManagerRegister();
    /* managers */
    TmModuleFlowManagerRegister();
    TmModuleFlowRecyclerRegister();
    TmModuleBypassedFlowManagerRegister();
    /* nfq */
    TmModuleReceiveNFQRegister();
    TmModuleVerdictNFQRegister();
    TmModuleDecodeNFQRegister();
    /* ipfw */
    TmModuleReceiveIPFWRegister();
    TmModuleVerdictIPFWRegister();
    TmModuleDecodeIPFWRegister();
    /* pcap live */
    TmModuleReceivePcapRegister();
    TmModuleDecodePcapRegister();
    /* pcap file */
    TmModuleReceivePcapFileRegister();
    TmModuleDecodePcapFileRegister();
    /* af-packet */
    TmModuleReceiveAFPRegister();
    TmModuleDecodeAFPRegister();
    /* netmap */
    TmModuleReceiveNetmapRegister();
    TmModuleDecodeNetmapRegister();
    /* pfring */
    TmModuleReceivePfringRegister();
    TmModuleDecodePfringRegister();
    /* dag file */
    TmModuleReceiveErfFileRegister();
    TmModuleDecodeErfFileRegister();
    /* dag live */
    TmModuleReceiveErfDagRegister();
    TmModuleDecodeErfDagRegister();
    /* napatech */
    TmModuleNapatechStreamRegister();
    TmModuleNapatechDecodeRegister();

    /* flow worker */
    TmModuleFlowWorkerRegister();
    /* respond-reject */
    TmModuleRespondRejectRegister();

    /* log api */
    TmModuleLoggerRegister();
    TmModuleStatsLoggerRegister();

    TmModuleDebugList();
    /* nflog */
    TmModuleReceiveNFLOGRegister();
    TmModuleDecodeNFLOGRegister();

    /* windivert */
    TmModuleReceiveWinDivertRegister();
    TmModuleVerdictWinDivertRegister();
    TmModuleDecodeWinDivertRegister();
}

void GlobalsInitPreConfig(void)
{
    memset(trans_q, 0, sizeof(trans_q));

    /* Initialize the trans_q mutex */
    int blah;
    int r = 0;
    for(blah=0;blah<256;blah++) {
        r |= SCMutexInit(&trans_q[blah].mutex_q, NULL);
        r |= SCCondInit(&trans_q[blah].cond_q, NULL);
   }

    if (r != 0) {
        SCLogInfo("Trans_Q Mutex not initialized correctly");
        exit(EXIT_FAILURE);
    }

    TimeInit();
    SupportFastPatternForSigMatchTypes();
    SCThresholdConfGlobalInit();
}
