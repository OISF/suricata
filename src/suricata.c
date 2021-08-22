/* Copyright (C) 2007-2022 Open Information Security Foundation
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
 * \author Victor Julien <victor@inliniac.net>
 */

#include "suricata-common.h"

#if HAVE_GETOPT_H
#include <getopt.h>
#endif

#if HAVE_SIGNAL_H
#include <signal.h>
#endif
#ifndef OS_WIN32
#ifdef HAVE_SYS_RESOURCE_H
// setrlimit
#include <sys/resource.h>
#endif
#endif

#if HAVE_LIBSYSTEMD
#include <systemd/sd-daemon.h>
#endif

#include "suricata.h"

#include "conf.h"
#include "conf-yaml-loader.h"

#include "decode.h"
#include "defrag.h"
#include "flow.h"
#include "stream-tcp.h"
#include "ippair.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-address.h"
#include "detect-engine-alert.h"
#include "detect-engine-port.h"
#include "detect-engine-tag.h"
#include "detect-engine-threshold.h"
#include "detect-fast-pattern.h"

#include "datasets.h"

#include "feature.h"

#include "flow-bypass.h"
#include "flow-manager.h"
#include "flow-timeout.h"
#include "flow-worker.h"

#include "flow-bit.h"
#include "host-bit.h"
#include "ippair-bit.h"

#include "app-layer.h"
#include "app-layer-parser.h"
#include "app-layer-htp.h"
#include "app-layer-htp-range.h"

#include "output.h"
#include "output-filestore.h"

#include "respond-reject.h"

#include "runmode-af-packet.h"
#include "runmode-netmap.h"
#include "runmode-unittests.h"

#include "source-nfq.h"
#include "source-nfq-prototypes.h"
#include "source-nflog.h"
#include "source-ipfw.h"
#include "source-pcap.h"
#include "source-pcap-file.h"
#include "source-pcap-file-helper.h"
#include "source-pfring.h"
#include "source-erf-file.h"
#include "source-erf-dag.h"
#include "source-napatech.h"
#include "source-af-packet.h"
#include "source-netmap.h"
#include "source-dpdk.h"
#include "source-windivert.h"
#include "source-windivert-prototypes.h"

#include "unix-manager.h"

#include "util-classification-config.h"
#include "util-threshold-config.h"
#include "util-reference-config.h"

#include "tmqh-packetpool.h"
#include "tm-queuehandlers.h"

#include "util-byte.h"
#include "util-conf.h"
#include "util-coredump-config.h"
#include "util-cpu.h"
#include "util-daemon.h"
#include "util-device.h"
#include "util-dpdk.h"
#include "util-ebpf.h"
#include "util-host-os-info.h"
#include "util-ioctl.h"
#include "util-landlock.h"
#include "util-luajit.h"
#include "util-macset.h"
#include "util-misc.h"
#include "util-mpm-hs.h"
#include "util-pidfile.h"
#include "util-plugin.h"
#include "util-privs.h"
#include "util-profiling.h"
#include "util-proto-name.h"
#include "util-running-modes.h"
#include "util-signal.h"
#include "util-time.h"

/*
 * we put this here, because we only use it here in main.
 */
volatile sig_atomic_t sigint_count = 0;
volatile sig_atomic_t sighup_count = 0;
volatile sig_atomic_t sigterm_count = 0;
volatile sig_atomic_t sigusr2_count = 0;

/*
 * Flag to indicate if the engine is at the initialization
 * or already processing packets. 3 stages: SURICATA_INIT,
 * SURICATA_RUNTIME and SURICATA_FINALIZE
 */
SC_ATOMIC_DECLARE(unsigned int, engine_stage);

/* Max packets processed simultaniously per thread. */
#define DEFAULT_MAX_PENDING_PACKETS 1024

/** suricata engine control flags */
volatile uint8_t suricata_ctl_flags = 0;

/** Run mode selected */
int run_mode = RUNMODE_UNKNOWN;

/** Engine mode: inline (ENGINE_MODE_IPS) or just
  * detection mode (ENGINE_MODE_IDS by default) */
static enum EngineMode g_engine_mode = ENGINE_MODE_IDS;

/** Host mode: set if box is sniffing only
 * or is a router */
uint8_t host_mode = SURI_HOST_IS_SNIFFER_ONLY;

/** Maximum packets to simultaneously process. */
intmax_t max_pending_packets;

/** global indicating if detection is enabled */
int g_detect_disabled = 0;

/** set caps or not */
int sc_set_caps = FALSE;

/** highest mtu of the interfaces we monitor */
int g_default_mtu = 0;

bool g_system = false;

/** disable randomness to get reproducible results accross runs */
#ifndef AFLFUZZ_NO_RANDOM
int g_disable_randomness = 0;
#else
int g_disable_randomness = 1;
#endif

/** determine (without branching) if we include the vlan_ids when hashing or
  * comparing flows */
uint16_t g_vlan_mask = 0xffff;

/* flag to disable hashing almost globally, to be similar to disabling nss
 * support */
bool g_disable_hashing = false;

/** Suricata instance */
SCInstance suricata;

int SuriHasSigFile(void)
{
    return (suricata.sig_file != NULL);
}

int EngineModeIsIPS(void)
{
    return (g_engine_mode == ENGINE_MODE_IPS);
}

int EngineModeIsIDS(void)
{
    return (g_engine_mode == ENGINE_MODE_IDS);
}

void EngineModeSetIPS(void)
{
    g_engine_mode = ENGINE_MODE_IPS;
}

void EngineModeSetIDS(void)
{
    g_engine_mode = ENGINE_MODE_IDS;
}

#ifdef UNITTESTS
int RunmodeIsUnittests(void)
{
    if (run_mode == RUNMODE_UNITTEST)
        return 1;

    return 0;
}
#endif

int RunmodeGetCurrent(void)
{
    return run_mode;
}

/** signal handlers
 *
 *  WARNING: don't use the SCLog* API in the handlers. The API is complex
 *  with memory allocation possibly happening, calls to syslog, json message
 *  construction, etc.
 */

#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
static void SignalHandlerSigint(/*@unused@*/ int sig)
{
    sigint_count = 1;
}
static void SignalHandlerSigterm(/*@unused@*/ int sig)
{
    sigterm_count = 1;
}
#ifndef OS_WIN32
#if HAVE_LIBUNWIND
#define UNW_LOCAL_ONLY
#include <libunwind.h>
static void SignalHandlerUnexpected(int sig_num, siginfo_t *info, void *context)
{
    char msg[SC_LOG_MAX_LOG_MSG_LEN];
    unw_cursor_t cursor;
    /* Restore defaults for signals to avoid loops */
    signal(SIGABRT, SIG_DFL);
    signal(SIGSEGV, SIG_DFL);
    int r;
    if ((r = unw_init_local(&cursor, (unw_context_t *)(context)) != 0)) {
        fprintf(stderr, "unable to obtain stack trace: unw_init_local: %s\n", unw_strerror(r));
        goto terminate;
    }

    char *temp = msg;
    int cw = snprintf(temp, SC_LOG_MAX_LOG_MSG_LEN - (temp - msg), "stacktrace:sig %d:", sig_num);
    temp += cw;
    r = 1;
    while (r > 0) {
        if (unw_is_signal_frame(&cursor) == 0) {
            unw_word_t off;
            char name[256];
            if (unw_get_proc_name(&cursor, name, sizeof(name), &off) == UNW_ENOMEM) {
                cw = snprintf(temp, SC_LOG_MAX_LOG_MSG_LEN - (temp - msg), "[unknown]:");
            } else {
                cw = snprintf(
                        temp, SC_LOG_MAX_LOG_MSG_LEN - (temp - msg), "%s+0x%08" PRIx64, name, off);
            }
            temp += cw;
        }

        r = unw_step(&cursor);
        if (r > 0) {
            cw = snprintf(temp, SC_LOG_MAX_LOG_MSG_LEN - (temp - msg), ";");
            temp += cw;
        }
    }
    SCLogError(SC_ERR_SIGNAL, "%s", msg);

terminate:
    // Propagate signal to watchers, if any
    kill(getpid(), sig_num);
}
#undef UNW_LOCAL_ONLY
#endif /* HAVE_LIBUNWIND */
#endif /* !OS_WIN32 */
#endif

#ifndef OS_WIN32
/**
 * SIGUSR2 handler.  Just set sigusr2_count.  The main loop will act on
 * it.
 */
static void SignalHandlerSigusr2(int sig)
{
    if (sigusr2_count < 2)
        sigusr2_count++;
}

/**
 * SIGHUP handler.  Just set sighup_count.  The main loop will act on
 * it.
 */
static void SignalHandlerSigHup(/*@unused@*/ int sig)
{
    sighup_count = 1;
}
#endif

void GlobalsInitPreConfig(void)
{
    TimeInit();
    SupportFastPatternForSigMatchTypes();
    SCThresholdConfGlobalInit();
    SCProtoNameInit();
}

static void GlobalsDestroy(SCInstance *suri)
{
    HostShutdown();
    HTPFreeConfig();
    HTPAtExitPrintStats();

    AppLayerHtpPrintStats();

    /* TODO this can do into it's own func */
    DetectEngineCtx *de_ctx = DetectEngineGetCurrent();
    if (de_ctx) {
        DetectEngineMoveToFreeList(de_ctx);
        DetectEngineDeReference(&de_ctx);
    }
    DetectEnginePruneFreeList();

    AppLayerDeSetup();
    DatasetsSave();
    DatasetsDestroy();
    HttpRangeContainersDestroy();
    TagDestroyCtx();

    LiveDeviceListClean();
    OutputDeregisterAll();
    FeatureTrackingRelease();
    SCProtoNameRelease();
    TimeDeinit();
    if (!suri->disabled_detect) {
        SCReferenceConfDeinit();
        SCClassConfDeinit();
    }
    TmqhCleanup();
    TmModuleRunDeInit();
    ParseSizeDeinit();

#ifdef HAVE_DPDK
    DPDKCleanupEAL();
#endif

#ifdef HAVE_AF_PACKET
    AFPPeersListClean();
#endif

#ifdef NFQ
    NFQContextsClean();
#endif

#ifdef BUILD_HYPERSCAN
    MpmHSGlobalCleanup();
#endif

    ConfDeInit();
#ifdef HAVE_LUAJIT
    LuajitFreeStatesPool();
#endif
    SCLogDeInitLogModule();
    DetectParseFreeRegexes();
    SCThresholdConfGlobalFree();

    SCPidfileRemove(suri->pid_filename);
    SCFree(suri->pid_filename);
    suri->pid_filename = NULL;
}

/**
 * \brief Used to send OS specific notification of running threads
 *
 * \retval TmEcode TM_ECODE_OK on success; TM_ECODE_FAILED on failure.
 */
static void OnNotifyRunning(void)
{
#if HAVE_LIBSYSTEMD
    if (sd_notify(0, "READY=1") < 0) {
        SCLogWarning(SC_ERR_SYSCALL, "failed to notify systemd");
        /* Please refer to:
         * https://www.freedesktop.org/software/systemd/man/sd_notify.html#Return%20Value
         * for discussion on why failure should not be considered an error */
    }
#endif
}

/** \brief make sure threads can stop the engine by calling this
 *  function. Purpose: pcap file mode needs to be able to tell the
 *  engine the file eof is reached. */
void EngineStop(void)
{
    suricata_ctl_flags |= SURICATA_STOP;
}

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

static int SetBpfString(int argc, char *argv[])
{
    char *bpf_filter = NULL;
    uint32_t bpf_len = 0;
    int tmpindex = 0;

    /* attempt to parse remaining args as bpf filter */
    tmpindex = argc;
    while(argv[tmpindex] != NULL) {
        bpf_len+=strlen(argv[tmpindex]) + 1;
        tmpindex++;
    }

    if (bpf_len == 0)
        return TM_ECODE_OK;

    if (EngineModeIsIPS()) {
        SCLogError(SC_ERR_NOT_SUPPORTED,
                   "BPF filter not available in IPS mode."
                   " Use firewall filtering if possible.");
        return TM_ECODE_FAILED;
    }

    bpf_filter = SCMalloc(bpf_len);
    if (unlikely(bpf_filter == NULL))
        return TM_ECODE_OK;
    memset(bpf_filter, 0x00, bpf_len);

    tmpindex = optind;
    while(argv[tmpindex] != NULL) {
        strlcat(bpf_filter, argv[tmpindex],bpf_len);
        if(argv[tmpindex + 1] != NULL) {
            strlcat(bpf_filter," ", bpf_len);
        }
        tmpindex++;
    }

    if(strlen(bpf_filter) > 0) {
        if (ConfSetFinal("bpf-filter", bpf_filter) != 1) {
            SCLogError(SC_ERR_FATAL, "Failed to set bpf filter.");
            SCFree(bpf_filter);
            return TM_ECODE_FAILED;
        }
    }
    SCFree(bpf_filter);

    return TM_ECODE_OK;
}

static void SetBpfStringFromFile(char *filename)
{
    char *bpf_filter = NULL;
    char *bpf_comment_tmp = NULL;
    char *bpf_comment_start =  NULL;
    uint32_t bpf_len = 0;
#ifdef OS_WIN32
    struct _stat st;
#else
    struct stat st;
#endif /* OS_WIN32 */
    FILE *fp = NULL;
    size_t nm = 0;

    if (EngineModeIsIPS()) {
                   FatalError(SC_ERR_FATAL,
                              "BPF filter not available in IPS mode."
                              " Use firewall filtering if possible.");
    }

    fp = fopen(filename, "r");
    if (fp == NULL) {
        SCLogError(SC_ERR_FOPEN, "Failed to open file %s", filename);
        exit(EXIT_FAILURE);
    }

#ifdef OS_WIN32
    if (_fstat(_fileno(fp), &st) != 0) {
#else
    if (fstat(fileno(fp), &st) != 0) {
#endif /* OS_WIN32 */
        SCLogError(SC_ERR_FOPEN, "Failed to stat file %s", filename);
        exit(EXIT_FAILURE);
    }
    bpf_len = st.st_size + 1;

    bpf_filter = SCMalloc(bpf_len);
    if (unlikely(bpf_filter == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "Failed to allocate buffer for bpf filter in file %s", filename);
        exit(EXIT_FAILURE);
    }
    memset(bpf_filter, 0x00, bpf_len);

    nm = fread(bpf_filter, 1, bpf_len - 1, fp);
    if ((ferror(fp) != 0) || (nm != (bpf_len - 1))) {
        SCLogError(SC_ERR_BPF, "Failed to read complete BPF file %s", filename);
        SCFree(bpf_filter);
        fclose(fp);
        exit(EXIT_FAILURE);
    }
    fclose(fp);
    bpf_filter[nm] = '\0';

    if(strlen(bpf_filter) > 0) {
        /*replace comments with space*/
        bpf_comment_start = bpf_filter;
        while((bpf_comment_tmp = strchr(bpf_comment_start, '#')) != NULL) {
            while((*bpf_comment_tmp !='\0') &&
                (*bpf_comment_tmp != '\r') && (*bpf_comment_tmp != '\n'))
            {
                *bpf_comment_tmp++ = ' ';
            }
            bpf_comment_start = bpf_comment_tmp;
        }
        /*remove remaining '\r' and '\n' */
        while((bpf_comment_tmp = strchr(bpf_filter, '\r')) != NULL) {
            *bpf_comment_tmp = ' ';
        }
        while((bpf_comment_tmp = strchr(bpf_filter, '\n')) != NULL) {
            *bpf_comment_tmp = ' ';
        }
        /* cut trailing spaces */
        while (strlen(bpf_filter) > 0 &&
                bpf_filter[strlen(bpf_filter)-1] == ' ')
        {
            bpf_filter[strlen(bpf_filter)-1] = '\0';
        }
        if (strlen(bpf_filter) > 0) {
            if(ConfSetFinal("bpf-filter", bpf_filter) != 1) {
                SCLogError(SC_ERR_FOPEN, "ERROR: Failed to set bpf filter!");
                SCFree(bpf_filter);
                exit(EXIT_FAILURE);
            }
        }
    }
    SCFree(bpf_filter);
}

static void PrintUsage(const char *progname)
{
#ifdef REVISION
    printf("%s %s (%s)\n", PROG_NAME, PROG_VER, xstr(REVISION));
#else
    printf("%s %s\n", PROG_NAME, PROG_VER);
#endif
    printf("USAGE: %s [OPTIONS] [BPF FILTER]\n\n", progname);
    printf("\t-c <path>                            : path to configuration file\n");
    printf("\t-T                                   : test configuration file (use with -c)\n");
    printf("\t-i <dev or ip>                       : run in pcap live mode\n");
    printf("\t-F <bpf filter file>                 : bpf filter file\n");
    printf("\t-r <path>                            : run in pcap file/offline mode\n");
#ifdef NFQ
    printf("\t-q <qid[:qid]>                       : run in inline nfqueue mode (use colon to specify a range of queues)\n");
#endif /* NFQ */
#ifdef IPFW
    printf("\t-d <divert port>                     : run in inline ipfw divert mode\n");
#endif /* IPFW */
    printf("\t-s <path>                            : path to signature file loaded in addition to suricata.yaml settings (optional)\n");
    printf("\t-S <path>                            : path to signature file loaded exclusively (optional)\n");
    printf("\t-l <dir>                             : default log directory\n");
#ifndef OS_WIN32
    printf("\t-D                                   : run as daemon\n");
#else
    printf("\t--service-install                    : install as service\n");
    printf("\t--service-remove                     : remove service\n");
    printf("\t--service-change-params              : change service startup parameters\n");
#endif /* OS_WIN32 */
    printf("\t-k [all|none]                        : force checksum check (all) or disabled it (none)\n");
    printf("\t-V                                   : display Suricata version\n");
    printf("\t-v                                   : be more verbose (use multiple times to increase verbosity)\n");
#ifdef UNITTESTS
    printf("\t-u                                   : run the unittests and exit\n");
    printf("\t-U, --unittest-filter=REGEX          : filter unittests with a regex\n");
    printf("\t--list-unittests                     : list unit tests\n");
    printf("\t--fatal-unittests                    : enable fatal failure on unittest error\n");
    printf("\t--unittests-coverage                 : display unittest coverage report\n");
#endif /* UNITTESTS */
    printf("\t--list-app-layer-protos              : list supported app layer protocols\n");
    printf("\t--list-keywords[=all|csv|<kword>]    : list keywords implemented by the engine\n");
    printf("\t--list-runmodes                      : list supported runmodes\n");
    printf("\t--runmode <runmode_id>               : specific runmode modification the engine should run.  The argument\n"
           "\t                                       supplied should be the id for the runmode obtained by running\n"
           "\t                                       --list-runmodes\n");
    printf("\t--engine-analysis                    : print reports on analysis of different sections in the engine and exit.\n"
           "\t                                       Please have a look at the conf parameter engine-analysis on what reports\n"
           "\t                                       can be printed\n");
    printf("\t--pidfile <file>                     : write pid to this file\n");
    printf("\t--init-errors-fatal                  : enable fatal failure on signature init error\n");
    printf("\t--disable-detection                  : disable detection engine\n");
    printf("\t--dump-config                        : show the running configuration\n");
    printf("\t--dump-features                      : display provided features\n");
    printf("\t--build-info                         : display build information\n");
    printf("\t--pcap[=<dev>]                       : run in pcap mode, no value select interfaces from suricata.yaml\n");
    printf("\t--pcap-file-continuous               : when running in pcap mode with a directory, continue checking directory for pcaps until interrupted\n");
    printf("\t--pcap-file-delete                   : when running in replay mode (-r with directory or file), will delete pcap files that have been processed when done\n");
    printf("\t--pcap-file-recursive                : will descend into subdirectories when running in replay mode (-r)\n");
#ifdef HAVE_PCAP_SET_BUFF
    printf("\t--pcap-buffer-size                   : size of the pcap buffer value from 0 - %i\n",INT_MAX);
#endif /* HAVE_SET_PCAP_BUFF */
#ifdef HAVE_DPDK
    printf("\t--dpdk                               : run in dpdk mode, uses interfaces from "
           "suricata.yaml\n");
#endif
#ifdef HAVE_AF_PACKET
    printf("\t--af-packet[=<dev>]                  : run in af-packet mode, no value select interfaces from suricata.yaml\n");
#endif
#ifdef HAVE_NETMAP
    printf("\t--netmap[=<dev>]                     : run in netmap mode, no value select interfaces from suricata.yaml\n");
#endif
#ifdef HAVE_PFRING
    printf("\t--pfring[=<dev>]                     : run in pfring mode, use interfaces from suricata.yaml\n");
    printf("\t--pfring-int <dev>                   : run in pfring mode, use interface <dev>\n");
    printf("\t--pfring-cluster-id <id>             : pfring cluster id \n");
    printf("\t--pfring-cluster-type <type>         : pfring cluster type for PF_RING 4.1.2 and later cluster_round_robin|cluster_flow\n");
#endif /* HAVE_PFRING */
    printf("\t--simulate-ips                       : force engine into IPS mode. Useful for QA\n");
#ifdef HAVE_LIBCAP_NG
    printf("\t--user <user>                        : run suricata as this user after init\n");
    printf("\t--group <group>                      : run suricata as this group after init\n");
#endif /* HAVE_LIBCAP_NG */
    printf("\t--erf-in <path>                      : process an ERF file\n");
#ifdef HAVE_DAG
    printf("\t--dag <dagX:Y>                       : process ERF records from DAG interface X, stream Y\n");
#endif
#ifdef HAVE_NAPATECH
    printf("\t--napatech                           : run Napatech Streams using the API\n");
#endif
#ifdef BUILD_UNIX_SOCKET
    printf("\t--unix-socket[=<file>]               : use unix socket to control suricata work\n");
#endif
#ifdef WINDIVERT
    printf("\t--windivert <filter>                 : run in inline WinDivert mode\n");
    printf("\t--windivert-forward <filter>         : run in inline WinDivert mode, as a gateway\n");
#endif
#ifdef HAVE_LIBNET11
    printf("\t--reject-dev <dev>                   : send reject packets from this interface\n");
#endif
    printf("\t--set name=value                     : set a configuration value\n");
    printf("\n");
    printf("\nTo run the engine with default configuration on "
            "interface eth0 with signature file \"signatures.rules\", run the "
            "command as:\n\n%s -c suricata.yaml -s signatures.rules -i eth0 \n\n",
            progname);
}

static void PrintBuildInfo(void)
{
    const char *bits = "<unknown>-bits";
    const char *endian = "<unknown>-endian";
    char features[2048] = "";
    const char *tls;

    printf("This is %s version %s\n", PROG_NAME, GetProgramVersion());

#ifdef DEBUG
    strlcat(features, "DEBUG ", sizeof(features));
#endif
#ifdef DEBUG_VALIDATION
    strlcat(features, "DEBUG_VALIDATION ", sizeof(features));
#endif
#ifdef UNITTESTS
    strlcat(features, "UNITTESTS ", sizeof(features));
#endif
#ifdef NFQ
    strlcat(features, "NFQ ", sizeof(features));
#endif
#ifdef IPFW
    strlcat(features, "IPFW ", sizeof(features));
#endif
#ifdef HAVE_PCAP_SET_BUFF
    strlcat(features, "PCAP_SET_BUFF ", sizeof(features));
#endif
#ifdef HAVE_PFRING
    strlcat(features, "PF_RING ", sizeof(features));
#endif
#ifdef HAVE_AF_PACKET
    strlcat(features, "AF_PACKET ", sizeof(features));
#endif
#ifdef HAVE_NETMAP
    strlcat(features, "NETMAP ", sizeof(features));
#endif
#ifdef HAVE_PACKET_FANOUT
    strlcat(features, "HAVE_PACKET_FANOUT ", sizeof(features));
#endif
#ifdef HAVE_DAG
    strlcat(features, "DAG ", sizeof(features));
#endif
#ifdef HAVE_LIBCAP_NG
    strlcat(features, "LIBCAP_NG ", sizeof(features));
#endif
#ifdef HAVE_LIBNET11
    strlcat(features, "LIBNET1.1 ", sizeof(features));
#endif
#ifdef HAVE_HTP_URI_NORMALIZE_HOOK
    strlcat(features, "HAVE_HTP_URI_NORMALIZE_HOOK ", sizeof(features));
#endif
#ifdef PCRE2_HAVE_JIT
    strlcat(features, "PCRE_JIT ", sizeof(features));
#endif
    /* For compatibility, just say we have HAVE_NSS. */
    strlcat(features, "HAVE_NSS ", sizeof(features));
    /* HTTP2_DECOMPRESSION is not an optional feature in this major version */
    strlcat(features, "HTTP2_DECOMPRESSION ", sizeof(features));
#ifdef HAVE_LUA
    strlcat(features, "HAVE_LUA ", sizeof(features));
#endif
#ifdef HAVE_LUAJIT
    strlcat(features, "HAVE_LUAJIT ", sizeof(features));
#endif
    strlcat(features, "HAVE_LIBJANSSON ", sizeof(features));
#ifdef PROFILING
    strlcat(features, "PROFILING ", sizeof(features));
#endif
#ifdef PROFILE_LOCKING
    strlcat(features, "PROFILE_LOCKING ", sizeof(features));
#endif
#if defined(TLS_C11) || defined(TLS_GNU)
    strlcat(features, "TLS ", sizeof(features));
#endif
#if defined(TLS_C11)
    strlcat(features, "TLS_C11 ", sizeof(features));
#elif defined(TLS_GNU)
    strlcat(features, "TLS_GNU ", sizeof(features));
#endif
#ifdef HAVE_MAGIC
    strlcat(features, "MAGIC ", sizeof(features));
#endif
    strlcat(features, "RUST ", sizeof(features));
    if (strlen(features) == 0) {
        strlcat(features, "none", sizeof(features));
    }

    printf("Features: %s\n", features);

    /* SIMD stuff */
    memset(features, 0x00, sizeof(features));
#if defined(__SSE4_2__)
    strlcat(features, "SSE_4_2 ", sizeof(features));
#endif
#if defined(__SSE4_1__)
    strlcat(features, "SSE_4_1 ", sizeof(features));
#endif
#if defined(__SSE3__)
    strlcat(features, "SSE_3 ", sizeof(features));
#endif
    if (strlen(features) == 0) {
        strlcat(features, "none", sizeof(features));
    }
    printf("SIMD support: %s\n", features);

    /* atomics stuff */
    memset(features, 0x00, sizeof(features));
#if defined(__GCC_HAVE_SYNC_COMPARE_AND_SWAP_1)
    strlcat(features, "1 ", sizeof(features));
#endif
#if defined(__GCC_HAVE_SYNC_COMPARE_AND_SWAP_2)
    strlcat(features, "2 ", sizeof(features));
#endif
#if defined(__GCC_HAVE_SYNC_COMPARE_AND_SWAP_4)
    strlcat(features, "4 ", sizeof(features));
#endif
#if defined(__GCC_HAVE_SYNC_COMPARE_AND_SWAP_8)
    strlcat(features, "8 ", sizeof(features));
#endif
#if defined(__GCC_HAVE_SYNC_COMPARE_AND_SWAP_16)
    strlcat(features, "16 ", sizeof(features));
#endif
    if (strlen(features) == 0) {
        strlcat(features, "none", sizeof(features));
    } else {
        strlcat(features, "byte(s)", sizeof(features));
    }
    printf("Atomic intrinsics: %s\n", features);

#if __WORDSIZE == 64
    bits = "64-bits";
#elif __WORDSIZE == 32
    bits = "32-bits";
#endif

#if __BYTE_ORDER == __BIG_ENDIAN
    endian = "Big-endian";
#elif __BYTE_ORDER == __LITTLE_ENDIAN
    endian = "Little-endian";
#endif

    printf("%s, %s architecture\n", bits, endian);
#ifdef __GNUC__
    printf("GCC version %s, C version %"PRIiMAX"\n", __VERSION__, (intmax_t)__STDC_VERSION__);
#else
    printf("C version %"PRIiMAX"\n", (intmax_t)__STDC_VERSION__);
#endif

#if __SSP__ == 1
    printf("compiled with -fstack-protector\n");
#endif
#if __SSP_ALL__ == 2
    printf("compiled with -fstack-protector-all\n");
#endif
/*
 * Workaround for special defines of _FORTIFY_SOURCE like
 * FORTIFY_SOURCE=((defined __OPTIMIZE && OPTIMIZE > 0) ? 2 : 0)
 * which is used by Gentoo for example and would result in the error
 * 'defined' undeclared when _FORTIFY_SOURCE used via %d in printf func
 *
 */
#if _FORTIFY_SOURCE == 2
    printf("compiled with _FORTIFY_SOURCE=2\n");
#elif _FORTIFY_SOURCE == 1
    printf("compiled with _FORTIFY_SOURCE=1\n");
#elif _FORTIFY_SOURCE == 0
    printf("compiled with _FORTIFY_SOURCE=0\n");
#endif
#ifdef CLS
    printf("L1 cache line size (CLS)=%d\n", CLS);
#endif
#if defined(TLS_C11)
    tls = "_Thread_local";
#elif defined(TLS_GNU)
    tls = "__thread";
#else
#error "Unsupported thread local"
#endif
    printf("thread local storage method: %s\n", tls);

    printf("compiled with %s, linked against %s\n",
           HTP_VERSION_STRING_FULL, htp_get_version());
    printf("\n");
#include "build-info.h"
}

int coverage_unittests;
int g_ut_modules;
int g_ut_covered;

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

    /* Dpdk */
    TmModuleReceiveDPDKRegister();
    TmModuleDecodeDPDKRegister();
}

static TmEcode LoadYamlConfig(SCInstance *suri)
{
    SCEnter();

    if (suri->conf_filename == NULL)
        suri->conf_filename = DEFAULT_CONF_FILE;

    if (ConfYamlLoadFile(suri->conf_filename) != 0) {
        /* Error already displayed. */
        SCReturnInt(TM_ECODE_FAILED);
    }

    SCReturnInt(TM_ECODE_OK);
}

static TmEcode ParseInterfacesList(const int runmode, char *pcap_dev)
{
    SCEnter();

    /* run the selected runmode */
    if (runmode == RUNMODE_PCAP_DEV) {
        if (strlen(pcap_dev) == 0) {
            int ret = LiveBuildDeviceList("pcap");
            if (ret == 0) {
                SCLogError(SC_ERR_INITIALIZATION, "No interface found in config for pcap");
                SCReturnInt(TM_ECODE_FAILED);
            }
        }
    } else if (runmode == RUNMODE_PFRING) {
        /* FIXME add backward compat support */
        /* iface has been set on command line */
        if (strlen(pcap_dev)) {
            if (ConfSetFinal("pfring.live-interface", pcap_dev) != 1) {
                SCLogError(SC_ERR_INITIALIZATION, "Failed to set pfring.live-interface");
                SCReturnInt(TM_ECODE_FAILED);
            }
        } else {
            /* not an error condition if we have a 1.0 config */
            LiveBuildDeviceList("pfring");
        }
#ifdef HAVE_DPDK
    } else if (runmode == RUNMODE_DPDK) {
        char iface_selector[] = "dpdk.interfaces";
        int ret = LiveBuildDeviceList(iface_selector);
        if (ret == 0) {
            SCLogError(
                    SC_ERR_INITIALIZATION, "No interface found in config for %s", iface_selector);
            SCReturnInt(TM_ECODE_FAILED);
        }
#endif
#ifdef HAVE_AF_PACKET
    } else if (runmode == RUNMODE_AFP_DEV) {
        /* iface has been set on command line */
        if (strlen(pcap_dev)) {
            if (ConfSetFinal("af-packet.live-interface", pcap_dev) != 1) {
                SCLogError(SC_ERR_INITIALIZATION, "Failed to set af-packet.live-interface");
                SCReturnInt(TM_ECODE_FAILED);
            }
        } else {
            int ret = LiveBuildDeviceList("af-packet");
            if (ret == 0) {
                SCLogError(SC_ERR_INITIALIZATION, "No interface found in config for af-packet");
                SCReturnInt(TM_ECODE_FAILED);
            }
        }
#endif
#ifdef HAVE_NETMAP
    } else if (runmode == RUNMODE_NETMAP) {
        /* iface has been set on command line */
        if (strlen(pcap_dev)) {
            if (ConfSetFinal("netmap.live-interface", pcap_dev) != 1) {
                SCLogError(SC_ERR_INITIALIZATION, "Failed to set netmap.live-interface");
                SCReturnInt(TM_ECODE_FAILED);
            }
        } else {
            int ret = LiveBuildDeviceList("netmap");
            if (ret == 0) {
                SCLogError(SC_ERR_INITIALIZATION, "No interface found in config for netmap");
                SCReturnInt(TM_ECODE_FAILED);
            }
        }
#endif
#ifdef HAVE_NFLOG
    } else if (runmode == RUNMODE_NFLOG) {
        int ret = LiveBuildDeviceListCustom("nflog", "group");
        if (ret == 0) {
            SCLogError(SC_ERR_INITIALIZATION, "No group found in config for nflog");
            SCReturnInt(TM_ECODE_FAILED);
        }
#endif
    }

    SCReturnInt(TM_ECODE_OK);
}

static void SCInstanceInit(SCInstance *suri, const char *progname)
{
    memset(suri, 0x00, sizeof(*suri));

    suri->progname = progname;
    suri->run_mode = RUNMODE_UNKNOWN;

    memset(suri->pcap_dev, 0, sizeof(suri->pcap_dev));
    suri->sig_file = NULL;
    suri->sig_file_exclusive = FALSE;
    suri->pid_filename = NULL;
    suri->regex_arg = NULL;

    suri->keyword_info = NULL;
    suri->runmode_custom_mode = NULL;
#ifndef OS_WIN32
    suri->user_name = NULL;
    suri->group_name = NULL;
    suri->do_setuid = FALSE;
    suri->do_setgid = FALSE;
#endif /* OS_WIN32 */
    suri->userid = 0;
    suri->groupid = 0;
    suri->delayed_detect = 0;
    suri->daemon = 0;
    suri->offline = 0;
    suri->verbose = 0;
    /* use -1 as unknown */
    suri->checksum_validation = -1;
#if HAVE_DETECT_DISABLED==1
    g_detect_disabled = suri->disabled_detect = 1;
#else
    g_detect_disabled = suri->disabled_detect = 0;
#endif
}

const char *GetDocURL(void)
{
    const char *prog_ver = GetProgramVersion();
    if (strstr(prog_ver, "RELEASE") != NULL) {
        return DOC_URL "suricata-" PROG_VER;
    }
    return DOC_URL "latest";
}

/** \brief get string with program version
 *
 *  Get the program version as passed to us from AC_INIT
 *
 *  Add 'RELEASE' is no '-dev' in the version. Add the REVISION if passed
 *  to us.
 *
 *  Possible outputs:
 *  release:      '5.0.1 RELEASE'
 *  dev with rev: '5.0.1-dev (64a789bbf 2019-10-18)'
 *  dev w/o rev:  '5.0.1-dev'
 */
const char *GetProgramVersion(void)
{
    if (strstr(PROG_VER, "-dev") == NULL) {
        return PROG_VER " RELEASE";
    } else {
#ifdef REVISION
        return PROG_VER " (" xstr(REVISION) ")";
#else
        return PROG_VER;
#endif
    }
}

static TmEcode PrintVersion(void)
{
    printf("This is %s version %s\n", PROG_NAME, GetProgramVersion());
    return TM_ECODE_OK;
}

static TmEcode LogVersion(SCInstance *suri)
{
    const char *mode = suri->system ? "SYSTEM" : "USER";
    SCLogNotice("This is %s version %s running in %s mode",
            PROG_NAME, GetProgramVersion(), mode);
    return TM_ECODE_OK;
}

static void SCSetStartTime(SCInstance *suri)
{
    memset(&suri->start_time, 0, sizeof(suri->start_time));
    gettimeofday(&suri->start_time, NULL);
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

static int ParseCommandLineAfpacket(SCInstance *suri, const char *in_arg)
{
#ifdef HAVE_AF_PACKET
    if (suri->run_mode == RUNMODE_UNKNOWN) {
        suri->run_mode = RUNMODE_AFP_DEV;
        if (in_arg) {
            LiveRegisterDeviceName(in_arg);
            memset(suri->pcap_dev, 0, sizeof(suri->pcap_dev));
            strlcpy(suri->pcap_dev, in_arg, sizeof(suri->pcap_dev));
        }
    } else if (suri->run_mode == RUNMODE_AFP_DEV) {
        if (in_arg) {
            LiveRegisterDeviceName(in_arg);
        } else {
            SCLogInfo("Multiple af-packet option without interface on each is useless");
        }
    } else {
        SCLogError(SC_ERR_MULTIPLE_RUN_MODE, "more than one run mode "
                "has been specified");
        PrintUsage(suri->progname);
        return TM_ECODE_FAILED;
    }
    return TM_ECODE_OK;
#else
    SCLogError(SC_ERR_NO_AF_PACKET,"AF_PACKET not enabled. On Linux "
            "host, make sure to pass --enable-af-packet to "
            "configure when building.");
    return TM_ECODE_FAILED;
#endif
}

static int ParseCommandLineDpdk(SCInstance *suri, const char *in_arg)
{
#ifdef HAVE_DPDK
    if (suri->run_mode == RUNMODE_UNKNOWN) {
        suri->run_mode = RUNMODE_DPDK;
    } else if (suri->run_mode == RUNMODE_DPDK) {
        SCLogInfo("Multiple dpdk options have no effect on Suricata");
    } else {
        SCLogError(SC_ERR_MULTIPLE_RUN_MODE, "more than one run mode "
                                             "has been specified");
        PrintUsage(suri->progname);
        return TM_ECODE_FAILED;
    }
    return TM_ECODE_OK;
#else
    SCLogError(SC_ERR_NO_DPDK, "DPDK not enabled. On Linux "
                               "host, make sure to pass --enable-dpdk to "
                               "configure when building.");
    return TM_ECODE_FAILED;
#endif
}

static int ParseCommandLinePcapLive(SCInstance *suri, const char *in_arg)
{
#if defined(OS_WIN32) && !defined(HAVE_LIBWPCAP)
    /* If running on Windows without Npcap, bail early as live capture is not supported. */
    FatalError(SC_ERR_FATAL,
            "Live capture not available. To support live capture compile against Npcap.");
#endif
    memset(suri->pcap_dev, 0, sizeof(suri->pcap_dev));

    if (in_arg != NULL) {
        /* some windows shells require escaping of the \ in \Device. Otherwise
         * the backslashes are stripped. We put them back here. */
        if (strlen(in_arg) > 9 && strncmp(in_arg, "DeviceNPF", 9) == 0) {
            snprintf(suri->pcap_dev, sizeof(suri->pcap_dev), "\\Device\\NPF%s", in_arg+9);
        } else {
            strlcpy(suri->pcap_dev, in_arg, sizeof(suri->pcap_dev));
            PcapTranslateIPToDevice(suri->pcap_dev, sizeof(suri->pcap_dev));
        }

        if (strcmp(suri->pcap_dev, in_arg) != 0) {
            SCLogInfo("translated %s to pcap device %s", in_arg, suri->pcap_dev);
        } else if (strlen(suri->pcap_dev) > 0 && isdigit((unsigned char)suri->pcap_dev[0])) {
            SCLogError(SC_ERR_PCAP_TRANSLATE, "failed to find a pcap device for IP %s", in_arg);
            return TM_ECODE_FAILED;
        }
    }

    if (suri->run_mode == RUNMODE_UNKNOWN) {
        suri->run_mode = RUNMODE_PCAP_DEV;
        if (in_arg) {
            LiveRegisterDeviceName(suri->pcap_dev);
        }
    } else if (suri->run_mode == RUNMODE_PCAP_DEV) {
        LiveRegisterDeviceName(suri->pcap_dev);
    } else {
        SCLogError(SC_ERR_MULTIPLE_RUN_MODE, "more than one run mode "
                "has been specified");
        PrintUsage(suri->progname);
        return TM_ECODE_FAILED;
    }
    return TM_ECODE_OK;
}

/**
 * Helper function to check if log directory is writable
 */
static bool IsLogDirectoryWritable(const char* str)
{
    if (access(str, W_OK) == 0)
        return true;
    return false;
}

static TmEcode ParseCommandLine(int argc, char** argv, SCInstance *suri)
{
    int opt;

    int dump_config = 0;
    int dump_features = 0;
    int list_app_layer_protocols = 0;
    int list_unittests = 0;
    int list_runmodes = 0;
    int list_keywords = 0;
    int build_info = 0;
    int conf_test = 0;
    int engine_analysis = 0;
    int ret = TM_ECODE_OK;

#ifdef UNITTESTS
    coverage_unittests = 0;
    g_ut_modules = 0;
    g_ut_covered = 0;
#endif

    // clang-format off
    struct option long_opts[] = {
        {"dump-config", 0, &dump_config, 1},
        {"dump-features", 0, &dump_features, 1},
        {"pfring", optional_argument, 0, 0},
        {"pfring-int", required_argument, 0, 0},
        {"pfring-cluster-id", required_argument, 0, 0},
        {"pfring-cluster-type", required_argument, 0, 0},
#ifdef HAVE_DPDK
        {"dpdk", 0, 0, 0},
#endif
        {"af-packet", optional_argument, 0, 0},
        {"netmap", optional_argument, 0, 0},
        {"pcap", optional_argument, 0, 0},
        {"pcap-file-continuous", 0, 0, 0},
        {"pcap-file-delete", 0, 0, 0},
        {"pcap-file-recursive", 0, 0, 0},
        {"simulate-ips", 0, 0 , 0},
        {"no-random", 0, &g_disable_randomness, 1},
        {"strict-rule-keywords", optional_argument, 0, 0},

        {"capture-plugin", required_argument, 0, 0},
        {"capture-plugin-args", required_argument, 0, 0},

#ifdef BUILD_UNIX_SOCKET
        {"unix-socket", optional_argument, 0, 0},
#endif
        {"pcap-buffer-size", required_argument, 0, 0},
        {"unittest-filter", required_argument, 0, 'U'},
        {"list-app-layer-protos", 0, &list_app_layer_protocols, 1},
        {"list-unittests", 0, &list_unittests, 1},
        {"list-runmodes", 0, &list_runmodes, 1},
        {"list-keywords", optional_argument, &list_keywords, 1},
        {"runmode", required_argument, NULL, 0},
        {"engine-analysis", 0, &engine_analysis, 1},
#ifdef OS_WIN32
		{"service-install", 0, 0, 0},
		{"service-remove", 0, 0, 0},
		{"service-change-params", 0, 0, 0},
#endif /* OS_WIN32 */
        {"pidfile", required_argument, 0, 0},
        {"init-errors-fatal", 0, 0, 0},
        {"disable-detection", 0, 0, 0},
        {"disable-hashing", 0, 0, 0},
        {"fatal-unittests", 0, 0, 0},
        {"unittests-coverage", 0, &coverage_unittests, 1},
        {"user", required_argument, 0, 0},
        {"group", required_argument, 0, 0},
        {"erf-in", required_argument, 0, 0},
        {"dag", required_argument, 0, 0},
        {"napatech", 0, 0, 0},
        {"build-info", 0, &build_info, 1},
        {"data-dir", required_argument, 0, 0},
#ifdef WINDIVERT
        {"windivert", required_argument, 0, 0},
        {"windivert-forward", required_argument, 0, 0},
#endif
#ifdef HAVE_LIBNET11
        {"reject-dev", required_argument, 0, 0},
#endif
        {"set", required_argument, 0, 0},
#ifdef HAVE_NFLOG
        {"nflog", optional_argument, 0, 0},
#endif
        {"simulate-packet-flow-memcap", required_argument, 0, 0},
        {"simulate-applayer-error-at-offset-ts", required_argument, 0, 0},
        {"simulate-applayer-error-at-offset-tc", required_argument, 0, 0},
        {"simulate-packet-loss", required_argument, 0, 0},
        {"simulate-packet-tcp-reassembly-memcap", required_argument, 0, 0},
        {"simulate-packet-tcp-ssn-memcap", required_argument, 0, 0},
        {"simulate-packet-defrag-memcap", required_argument, 0, 0},
        {"simulate-alert-queue-realloc-failure", 0, 0, 0},

        {NULL, 0, NULL, 0}
    };
    // clang-format on

    /* getopt_long stores the option index here. */
    int option_index = 0;

    char short_opts[] = "c:TDhi:l:q:d:r:us:S:U:VF:vk:";

    while ((opt = getopt_long(argc, argv, short_opts, long_opts, &option_index)) != -1) {
        switch (opt) {
        case 0:
            if (strcmp((long_opts[option_index]).name , "pfring") == 0 ||
                strcmp((long_opts[option_index]).name , "pfring-int") == 0) {
#ifdef HAVE_PFRING
                suri->run_mode = RUNMODE_PFRING;
                if (optarg != NULL) {
                    memset(suri->pcap_dev, 0, sizeof(suri->pcap_dev));
                    strlcpy(suri->pcap_dev, optarg,
                            ((strlen(optarg) < sizeof(suri->pcap_dev)) ?
                             (strlen(optarg) + 1) : sizeof(suri->pcap_dev)));
                    LiveRegisterDeviceName(optarg);
                }
#else
                SCLogError(SC_ERR_NO_PF_RING,"PF_RING not enabled. Make sure "
                        "to pass --enable-pfring to configure when building.");
                return TM_ECODE_FAILED;
#endif /* HAVE_PFRING */
            }
            else if(strcmp((long_opts[option_index]).name , "pfring-cluster-id") == 0){
#ifdef HAVE_PFRING
                if (ConfSetFinal("pfring.cluster-id", optarg) != 1) {
                    fprintf(stderr, "ERROR: Failed to set pfring.cluster-id.\n");
                    return TM_ECODE_FAILED;
                }
#else
                SCLogError(SC_ERR_NO_PF_RING,"PF_RING not enabled. Make sure "
                        "to pass --enable-pfring to configure when building.");
                return TM_ECODE_FAILED;
#endif /* HAVE_PFRING */
            }
            else if(strcmp((long_opts[option_index]).name , "pfring-cluster-type") == 0){
#ifdef HAVE_PFRING
                if (ConfSetFinal("pfring.cluster-type", optarg) != 1) {
                    fprintf(stderr, "ERROR: Failed to set pfring.cluster-type.\n");
                    return TM_ECODE_FAILED;
                }
#else
                SCLogError(SC_ERR_NO_PF_RING,"PF_RING not enabled. Make sure "
                        "to pass --enable-pfring to configure when building.");
                return TM_ECODE_FAILED;
#endif /* HAVE_PFRING */
            }
            else if (strcmp((long_opts[option_index]).name , "capture-plugin") == 0){
                suri->run_mode = RUNMODE_PLUGIN;
                suri->capture_plugin_name = optarg;
            }
            else if (strcmp((long_opts[option_index]).name , "capture-plugin-args") == 0){
                suri->capture_plugin_args = optarg;
            } else if (strcmp((long_opts[option_index]).name, "dpdk") == 0) {
                if (ParseCommandLineDpdk(suri, optarg) != TM_ECODE_OK) {
                    return TM_ECODE_FAILED;
                }
            } else if (strcmp((long_opts[option_index]).name, "af-packet") == 0) {
                if (ParseCommandLineAfpacket(suri, optarg) != TM_ECODE_OK) {
                    return TM_ECODE_FAILED;
                }
            } else if (strcmp((long_opts[option_index]).name, "netmap") == 0) {
#ifdef HAVE_NETMAP
                if (suri->run_mode == RUNMODE_UNKNOWN) {
                    suri->run_mode = RUNMODE_NETMAP;
                    if (optarg) {
                        LiveRegisterDeviceName(optarg);
                        memset(suri->pcap_dev, 0, sizeof(suri->pcap_dev));
                        strlcpy(suri->pcap_dev, optarg,
                                ((strlen(optarg) < sizeof(suri->pcap_dev)) ?
                                 (strlen(optarg) + 1) : sizeof(suri->pcap_dev)));
                    }
                } else if (suri->run_mode == RUNMODE_NETMAP) {
                    if (optarg) {
                        LiveRegisterDeviceName(optarg);
                    } else {
                        SCLogInfo("Multiple netmap option without interface on each is useless");
                        break;
                    }
                } else {
                    SCLogError(SC_ERR_MULTIPLE_RUN_MODE, "more than one run mode "
                            "has been specified");
                    PrintUsage(argv[0]);
                    return TM_ECODE_FAILED;
                }
#else
                    SCLogError(SC_ERR_NO_NETMAP, "NETMAP not enabled.");
                    return TM_ECODE_FAILED;
#endif
            } else if (strcmp((long_opts[option_index]).name, "nflog") == 0) {
#ifdef HAVE_NFLOG
                if (suri->run_mode == RUNMODE_UNKNOWN) {
                    suri->run_mode = RUNMODE_NFLOG;
                    LiveBuildDeviceListCustom("nflog", "group");
                }
#else
                SCLogError(SC_ERR_NFLOG_NOSUPPORT, "NFLOG not enabled.");
                return TM_ECODE_FAILED;
#endif /* HAVE_NFLOG */
            } else if (strcmp((long_opts[option_index]).name, "pcap") == 0) {
                if (ParseCommandLinePcapLive(suri, optarg) != TM_ECODE_OK) {
                    return TM_ECODE_FAILED;
                }
            } else if (strcmp((long_opts[option_index]).name, "simulate-ips") == 0) {
                SCLogInfo("Setting IPS mode");
                EngineModeSetIPS();
            } else if (strcmp((long_opts[option_index]).name, "init-errors-fatal") == 0) {
                if (ConfSetFinal("engine.init-failure-fatal", "1") != 1) {
                    fprintf(stderr, "ERROR: Failed to set engine init-failure-fatal.\n");
                    return TM_ECODE_FAILED;
                }
#ifdef BUILD_UNIX_SOCKET
            } else if (strcmp((long_opts[option_index]).name , "unix-socket") == 0) {
                if (suri->run_mode == RUNMODE_UNKNOWN) {
                    suri->run_mode = RUNMODE_UNIX_SOCKET;
                    if (optarg) {
                        if (ConfSetFinal("unix-command.filename", optarg) != 1) {
                            fprintf(stderr, "ERROR: Failed to set unix-command.filename.\n");
                            return TM_ECODE_FAILED;
                        }

                    }
                } else {
                    SCLogError(SC_ERR_MULTIPLE_RUN_MODE, "more than one run mode "
                            "has been specified");
                    PrintUsage(argv[0]);
                    return TM_ECODE_FAILED;
                }
#endif
            }
            else if(strcmp((long_opts[option_index]).name, "list-app-layer-protocols") == 0) {
                /* listing all supported app layer protocols */
            }
            else if(strcmp((long_opts[option_index]).name, "list-unittests") == 0) {
#ifdef UNITTESTS
                suri->run_mode = RUNMODE_LIST_UNITTEST;
#else
                fprintf(stderr, "ERROR: Unit tests not enabled. Make sure to pass --enable-unittests to configure when building.\n");
                return TM_ECODE_FAILED;
#endif /* UNITTESTS */
            } else if (strcmp((long_opts[option_index]).name, "list-runmodes") == 0) {
                suri->run_mode = RUNMODE_LIST_RUNMODES;
                return TM_ECODE_OK;
            } else if (strcmp((long_opts[option_index]).name, "list-keywords") == 0) {
                if (optarg) {
                    if (strcmp("short",optarg)) {
                        suri->keyword_info = optarg;
                    }
                }
            } else if (strcmp((long_opts[option_index]).name, "runmode") == 0) {
                suri->runmode_custom_mode = optarg;
            } else if(strcmp((long_opts[option_index]).name, "engine-analysis") == 0) {
                // do nothing for now
            }
#ifdef OS_WIN32
            else if(strcmp((long_opts[option_index]).name, "service-install") == 0) {
                suri->run_mode = RUNMODE_INSTALL_SERVICE;
                return TM_ECODE_OK;
            }
            else if(strcmp((long_opts[option_index]).name, "service-remove") == 0) {
                suri->run_mode = RUNMODE_REMOVE_SERVICE;
                return TM_ECODE_OK;
            }
            else if(strcmp((long_opts[option_index]).name, "service-change-params") == 0) {
                suri->run_mode = RUNMODE_CHANGE_SERVICE_PARAMS;
                return TM_ECODE_OK;
            }
#endif /* OS_WIN32 */
            else if(strcmp((long_opts[option_index]).name, "pidfile") == 0) {
                suri->pid_filename = SCStrdup(optarg);
                if (suri->pid_filename == NULL) {
                    SCLogError(SC_ERR_MEM_ALLOC, "strdup failed: %s",
                        strerror(errno));
                    return TM_ECODE_FAILED;
                }
            }
            else if(strcmp((long_opts[option_index]).name, "disable-detection") == 0) {
                g_detect_disabled = suri->disabled_detect = 1;
            } else if (strcmp((long_opts[option_index]).name, "disable-hashing") == 0) {
                g_disable_hashing = true;
            } else if (strcmp((long_opts[option_index]).name, "fatal-unittests") == 0) {
#ifdef UNITTESTS
                unittests_fatal = 1;
#else
                fprintf(stderr, "ERROR: Unit tests not enabled. Make sure to pass --enable-unittests to configure when building.\n");
                return TM_ECODE_FAILED;
#endif /* UNITTESTS */
            } else if (strcmp((long_opts[option_index]).name, "user") == 0) {
#ifndef HAVE_LIBCAP_NG
                SCLogError(SC_ERR_LIBCAP_NG_REQUIRED, "libcap-ng is required to"
                        " drop privileges, but it was not compiled into Suricata.");
                return TM_ECODE_FAILED;
#else
                suri->user_name = optarg;
                suri->do_setuid = TRUE;
#endif /* HAVE_LIBCAP_NG */
            } else if (strcmp((long_opts[option_index]).name, "group") == 0) {
#ifndef HAVE_LIBCAP_NG
                SCLogError(SC_ERR_LIBCAP_NG_REQUIRED, "libcap-ng is required to"
                        " drop privileges, but it was not compiled into Suricata.");
                return TM_ECODE_FAILED;
#else
                suri->group_name = optarg;
                suri->do_setgid = TRUE;
#endif /* HAVE_LIBCAP_NG */
            } else if (strcmp((long_opts[option_index]).name, "erf-in") == 0) {
                suri->run_mode = RUNMODE_ERF_FILE;
                if (ConfSetFinal("erf-file.file", optarg) != 1) {
                    fprintf(stderr, "ERROR: Failed to set erf-file.file\n");
                    return TM_ECODE_FAILED;
                }
            } else if (strcmp((long_opts[option_index]).name, "dag") == 0) {
#ifdef HAVE_DAG
                if (suri->run_mode == RUNMODE_UNKNOWN) {
                    suri->run_mode = RUNMODE_DAG;
                }
                else if (suri->run_mode != RUNMODE_DAG) {
                    SCLogError(SC_ERR_MULTIPLE_RUN_MODE,
                        "more than one run mode has been specified");
                    PrintUsage(argv[0]);
                    return TM_ECODE_FAILED;
                }
                LiveRegisterDeviceName(optarg);
#else
                SCLogError(SC_ERR_DAG_REQUIRED, "libdag and a DAG card are required"
						" to receive packets using --dag.");
                return TM_ECODE_FAILED;
#endif /* HAVE_DAG */
            } else if (strcmp((long_opts[option_index]).name, "napatech") == 0) {
#ifdef HAVE_NAPATECH
                suri->run_mode = RUNMODE_NAPATECH;
#else
                SCLogError(SC_ERR_NAPATECH_REQUIRED, "libntapi and a Napatech adapter are required"
                                                     " to capture packets using --napatech.");
                return TM_ECODE_FAILED;
#endif /* HAVE_NAPATECH */
            } else if (strcmp((long_opts[option_index]).name, "pcap-buffer-size") == 0) {
#ifdef HAVE_PCAP_SET_BUFF
                if (ConfSetFinal("pcap.buffer-size", optarg) != 1) {
                    fprintf(stderr, "ERROR: Failed to set pcap-buffer-size.\n");
                    return TM_ECODE_FAILED;
                }
#else
                SCLogError(SC_ERR_NO_PCAP_SET_BUFFER_SIZE, "The version of libpcap you have"
                        " doesn't support setting buffer size.");
#endif /* HAVE_PCAP_SET_BUFF */
            } else if (strcmp((long_opts[option_index]).name, "build-info") == 0) {
                suri->run_mode = RUNMODE_PRINT_BUILDINFO;
                return TM_ECODE_OK;
            } else if (strcmp((long_opts[option_index]).name, "windivert-forward") == 0) {
#ifdef WINDIVERT
                if (suri->run_mode == RUNMODE_UNKNOWN) {
                    suri->run_mode = RUNMODE_WINDIVERT;
                    if (WinDivertRegisterQueue(true, optarg) == -1) {
                        exit(EXIT_FAILURE);
                    }
                } else if (suri->run_mode == RUNMODE_WINDIVERT) {
                    if (WinDivertRegisterQueue(true, optarg) == -1) {
                        exit(EXIT_FAILURE);
                    }
                } else {
                    SCLogError(SC_ERR_MULTIPLE_RUN_MODE, "more than one run mode "
                                                        "has been specified");
                    PrintUsage(argv[0]);
                    exit(EXIT_FAILURE);
                }
            }
            else if(strcmp((long_opts[option_index]).name, "windivert") == 0) {
                if (suri->run_mode == RUNMODE_UNKNOWN) {
                    suri->run_mode = RUNMODE_WINDIVERT;
                    if (WinDivertRegisterQueue(false, optarg) == -1) {
                        exit(EXIT_FAILURE);
                    }
                } else if (suri->run_mode == RUNMODE_WINDIVERT) {
                    if (WinDivertRegisterQueue(false, optarg) == -1) {
                        exit(EXIT_FAILURE);
                    }
                } else {
                    SCLogError(SC_ERR_MULTIPLE_RUN_MODE, "more than one run mode "
                                                        "has been specified");
                    PrintUsage(argv[0]);
                    exit(EXIT_FAILURE);
                }
#else
                SCLogError(SC_ERR_WINDIVERT_NOSUPPORT,"WinDivert not enabled. Make sure to pass --enable-windivert to configure when building.");
                return TM_ECODE_FAILED;
#endif /* WINDIVERT */
            } else if(strcmp((long_opts[option_index]).name, "reject-dev") == 0) {
#ifdef HAVE_LIBNET11
                BUG_ON(optarg == NULL); /* for static analysis */
                extern char *g_reject_dev;
                extern uint16_t g_reject_dev_mtu;
                g_reject_dev = optarg;
                int mtu = GetIfaceMTU(g_reject_dev);
                if (mtu > 0) {
                    g_reject_dev_mtu = (uint16_t)mtu;
                }
#else
                SCLogError(SC_ERR_LIBNET_NOT_ENABLED,
                        "Libnet 1.1 support not enabled. Compile Suricata with libnet support.");
                return TM_ECODE_FAILED;
#endif
            }
            else if (strcmp((long_opts[option_index]).name, "set") == 0) {
                if (optarg != NULL) {
                    /* Quick validation. */
                    char *val = strchr(optarg, '=');
                    if (val == NULL) {
                                FatalError(SC_ERR_FATAL,
                                           "Invalid argument for --set, must be key=val.");
                    }
                    if (!ConfSetFromString(optarg, 1)) {
                        fprintf(stderr, "Failed to set configuration value %s.",
                                optarg);
                        exit(EXIT_FAILURE);
                    }
                }
            }
            else if (strcmp((long_opts[option_index]).name, "pcap-file-continuous") == 0) {
                if (ConfSetFinal("pcap-file.continuous", "true") != 1) {
                    SCLogError(SC_ERR_CMD_LINE, "Failed to set pcap-file.continuous");
                    return TM_ECODE_FAILED;
                }
            }
            else if (strcmp((long_opts[option_index]).name, "pcap-file-delete") == 0) {
                if (ConfSetFinal("pcap-file.delete-when-done", "true") != 1) {
                    SCLogError(SC_ERR_CMD_LINE, "Failed to set pcap-file.delete-when-done");
                    return TM_ECODE_FAILED;
                }
            }
            else if (strcmp((long_opts[option_index]).name, "pcap-file-recursive") == 0) {
                if (ConfSetFinal("pcap-file.recursive", "true") != 1) {
                    SCLogError(SC_ERR_CMD_LINE, "ERROR: Failed to set pcap-file.recursive");
                    return TM_ECODE_FAILED;
                }
            }
            else if (strcmp((long_opts[option_index]).name, "data-dir") == 0) {
                if (optarg == NULL) {
                    SCLogError(SC_ERR_INITIALIZATION, "no option argument (optarg) for -d");
                    return TM_ECODE_FAILED;
                }

                if (ConfigSetDataDirectory(optarg) != TM_ECODE_OK) {
                    SCLogError(SC_ERR_FATAL, "Failed to set data directory.");
                    return TM_ECODE_FAILED;
                }
                if (ConfigCheckDataDirectory(optarg) != TM_ECODE_OK) {
                    SCLogError(SC_ERR_LOGDIR_CMDLINE, "The data directory \"%s\""
                            " supplied at the commandline (-d %s) doesn't "
                            "exist. Shutting down the engine.", optarg, optarg);
                    return TM_ECODE_FAILED;
                }
                suri->set_datadir = true;
            } else if (strcmp((long_opts[option_index]).name , "strict-rule-keywords") == 0){
                if (optarg == NULL) {
                    suri->strict_rule_parsing_string = SCStrdup("all");
                } else {
                    suri->strict_rule_parsing_string = SCStrdup(optarg);
                }
                if (suri->strict_rule_parsing_string == NULL) {
                    FatalError(SC_ERR_MEM_ALLOC, "failed to duplicate 'strict' string");
                }
            } else {
                int r = ExceptionSimulationCommandlineParser(
                        (long_opts[option_index]).name, optarg);
                if (r < 0)
                    return TM_ECODE_FAILED;
            }
            break;
        case 'c':
            suri->conf_filename = optarg;
            break;
        case 'T':
            SCLogInfo("Running suricata under test mode");
            conf_test = 1;
            if (ConfSetFinal("engine.init-failure-fatal", "1") != 1) {
                fprintf(stderr, "ERROR: Failed to set engine init-failure-fatal.\n");
                return TM_ECODE_FAILED;
            }
            break;
#ifndef OS_WIN32
        case 'D':
            suri->daemon = 1;
            break;
#endif /* OS_WIN32 */
        case 'h':
            suri->run_mode = RUNMODE_PRINT_USAGE;
            return TM_ECODE_OK;
        case 'i':
            if (optarg == NULL) {
                SCLogError(SC_ERR_INITIALIZATION, "no option argument (optarg) for -i");
                return TM_ECODE_FAILED;
            }
#ifdef HAVE_AF_PACKET
            if (ParseCommandLineAfpacket(suri, optarg) != TM_ECODE_OK) {
                return TM_ECODE_FAILED;
            }
#else /* not afpacket */
            /* warn user if netmap or pf-ring are available */
#if defined HAVE_PFRING || HAVE_NETMAP
            int i = 0;
#ifdef HAVE_PFRING
            i++;
#endif
#ifdef HAVE_NETMAP
            i++;
#endif
            SCLogWarning(SC_WARN_FASTER_CAPTURE_AVAILABLE, "faster capture "
                    "option%s %s available:"
#ifdef HAVE_PFRING
                    " PF_RING (--pfring-int=%s)"
#endif
#ifdef HAVE_NETMAP
                    " NETMAP (--netmap=%s)"
#endif
                    ". Use --pcap=%s to suppress this warning",
                    i == 1 ? "" : "s", i == 1 ? "is" : "are"
#ifdef HAVE_PFRING
                    , optarg
#endif
#ifdef HAVE_NETMAP
                    , optarg
#endif
                    , optarg
                    );
#endif /* have faster methods */
            if (ParseCommandLinePcapLive(suri, optarg) != TM_ECODE_OK) {
                return TM_ECODE_FAILED;
            }
#endif
            break;
        case 'l':
            if (optarg == NULL) {
                SCLogError(SC_ERR_INITIALIZATION, "no option argument (optarg) for -l");
                return TM_ECODE_FAILED;
            }

            if (ConfigSetLogDirectory(optarg) != TM_ECODE_OK) {
                SCLogError(SC_ERR_FATAL, "Failed to set log directory.");
                return TM_ECODE_FAILED;
            }
            if (ConfigCheckLogDirectoryExists(optarg) != TM_ECODE_OK) {
                SCLogError(SC_ERR_LOGDIR_CMDLINE, "The logging directory \"%s\""
                        " supplied at the commandline (-l %s) doesn't "
                        "exist. Shutting down the engine.", optarg, optarg);
                return TM_ECODE_FAILED;
            }
            if (!IsLogDirectoryWritable(optarg)) {
                SCLogError(SC_ERR_LOGDIR_CMDLINE, "The logging directory \"%s\""
                        " supplied at the commandline (-l %s) is not "
                        "writable. Shutting down the engine.", optarg, optarg);
                return TM_ECODE_FAILED;
            }
            suri->set_logdir = true;

            break;
        case 'q':
#ifdef NFQ
            if (suri->run_mode == RUNMODE_UNKNOWN) {
                suri->run_mode = RUNMODE_NFQ;
                EngineModeSetIPS();
                if (NFQParseAndRegisterQueues(optarg) == -1)
                    return TM_ECODE_FAILED;
            } else if (suri->run_mode == RUNMODE_NFQ) {
                if (NFQParseAndRegisterQueues(optarg) == -1)
                    return TM_ECODE_FAILED;
            } else {
                SCLogError(SC_ERR_MULTIPLE_RUN_MODE, "more than one run mode "
                                                     "has been specified");
                PrintUsage(argv[0]);
                return TM_ECODE_FAILED;
            }
#else
            SCLogError(SC_ERR_NFQ_NOSUPPORT,"NFQUEUE not enabled. Make sure to pass --enable-nfqueue to configure when building.");
            return TM_ECODE_FAILED;
#endif /* NFQ */
            break;
        case 'd':
#ifdef IPFW
            if (suri->run_mode == RUNMODE_UNKNOWN) {
                suri->run_mode = RUNMODE_IPFW;
                EngineModeSetIPS();
                if (IPFWRegisterQueue(optarg) == -1)
                    return TM_ECODE_FAILED;
            } else if (suri->run_mode == RUNMODE_IPFW) {
                if (IPFWRegisterQueue(optarg) == -1)
                    return TM_ECODE_FAILED;
            } else {
                SCLogError(SC_ERR_MULTIPLE_RUN_MODE, "more than one run mode "
                                                     "has been specified");
                PrintUsage(argv[0]);
                return TM_ECODE_FAILED;
            }
#else
            SCLogError(SC_ERR_IPFW_NOSUPPORT,"IPFW not enabled. Make sure to pass --enable-ipfw to configure when building.");
            return TM_ECODE_FAILED;
#endif /* IPFW */
            break;
        case 'r':
            BUG_ON(optarg == NULL); /* for static analysis */
            if (suri->run_mode == RUNMODE_UNKNOWN) {
                suri->run_mode = RUNMODE_PCAP_FILE;
            } else {
                SCLogError(SC_ERR_MULTIPLE_RUN_MODE, "more than one run mode "
                                                     "has been specified");
                PrintUsage(argv[0]);
                return TM_ECODE_FAILED;
            }
#ifdef OS_WIN32
            struct _stat buf;
            if(_stat(optarg, &buf) != 0) {
#else
            struct stat buf;
            if (stat(optarg, &buf) != 0) {
#endif /* OS_WIN32 */
                SCLogError(SC_ERR_INITIALIZATION, "ERROR: Pcap file does not exist\n");
                return TM_ECODE_FAILED;
            }
            if (ConfSetFinal("pcap-file.file", optarg) != 1) {
                SCLogError(SC_ERR_INITIALIZATION, "ERROR: Failed to set pcap-file.file\n");
                return TM_ECODE_FAILED;
            }

            break;
        case 's':
            if (suri->sig_file != NULL) {
                SCLogError(SC_ERR_CMD_LINE, "can't have multiple -s options or mix -s and -S.");
                return TM_ECODE_FAILED;
            }
            suri->sig_file = optarg;
            break;
        case 'S':
            if (suri->sig_file != NULL) {
                SCLogError(SC_ERR_CMD_LINE, "can't have multiple -S options or mix -s and -S.");
                return TM_ECODE_FAILED;
            }
            suri->sig_file = optarg;
            suri->sig_file_exclusive = TRUE;
            break;
        case 'u':
#ifdef UNITTESTS
            if (suri->run_mode == RUNMODE_UNKNOWN) {
                suri->run_mode = RUNMODE_UNITTEST;
            } else {
                SCLogError(SC_ERR_MULTIPLE_RUN_MODE, "more than one run mode has"
                                                     " been specified");
                PrintUsage(argv[0]);
                return TM_ECODE_FAILED;
            }
#else
            fprintf(stderr, "ERROR: Unit tests not enabled. Make sure to pass --enable-unittests to configure when building.\n");
            return TM_ECODE_FAILED;
#endif /* UNITTESTS */
            break;
        case 'U':
#ifdef UNITTESTS
            suri->regex_arg = optarg;

            if(strlen(suri->regex_arg) == 0)
                suri->regex_arg = NULL;
#endif
            break;
        case 'V':
            suri->run_mode = RUNMODE_PRINT_VERSION;
            return TM_ECODE_OK;
        case 'F':
            if (optarg == NULL) {
                SCLogError(SC_ERR_INITIALIZATION, "no option argument (optarg) for -F");
                return TM_ECODE_FAILED;
            }

            SetBpfStringFromFile(optarg);
            break;
        case 'v':
            suri->verbose++;
            break;
        case 'k':
            if (optarg == NULL) {
                SCLogError(SC_ERR_INITIALIZATION, "no option argument (optarg) for -k");
                return TM_ECODE_FAILED;
            }
            if (!strcmp("all", optarg))
                suri->checksum_validation = 1;
            else if (!strcmp("none", optarg))
                suri->checksum_validation = 0;
            else {
                SCLogError(SC_ERR_INITIALIZATION, "option '%s' invalid for -k", optarg);
                return TM_ECODE_FAILED;
            }
            break;
        default:
            PrintUsage(argv[0]);
            return TM_ECODE_FAILED;
        }
    }

    if (suri->disabled_detect && suri->sig_file != NULL) {
        SCLogError(SC_ERR_INITIALIZATION, "can't use -s/-S when detection is disabled");
        return TM_ECODE_FAILED;
    }

    /* save the runmode from the commandline (if any) */
    suri->aux_run_mode = suri->run_mode;

    if (list_app_layer_protocols)
        suri->run_mode = RUNMODE_LIST_APP_LAYERS;
    if (list_keywords)
        suri->run_mode = RUNMODE_LIST_KEYWORDS;
    if (list_unittests)
        suri->run_mode = RUNMODE_LIST_UNITTEST;
    if (dump_config)
        suri->run_mode = RUNMODE_DUMP_CONFIG;
    if (dump_features)
        suri->run_mode = RUNMODE_DUMP_FEATURES;
    if (conf_test)
        suri->run_mode = RUNMODE_CONF_TEST;
    if (engine_analysis)
        suri->run_mode = RUNMODE_ENGINE_ANALYSIS;

    suri->offline = IsRunModeOffline(suri->run_mode);
    g_system = suri->system = IsRunModeSystem(suri->run_mode);

    ret = SetBpfString(optind, argv);
    if (ret != TM_ECODE_OK)
        return ret;

    return TM_ECODE_OK;
}

#ifdef OS_WIN32
static int WindowsInitService(int argc, char **argv)
{
    if (SCRunningAsService()) {
        char path[MAX_PATH];
        char *p = NULL;
        strlcpy(path, argv[0], MAX_PATH);
        if ((p = strrchr(path, '\\'))) {
            *p = '\0';
        }
        if (!SetCurrentDirectory(path)) {
            SCLogError(SC_ERR_FATAL, "Can't set current directory to: %s", path);
            return -1;
        }
        SCLogInfo("Current directory is set to: %s", path);
        SCServiceInit(argc, argv);
    }

    /* Windows socket subsystem initialization */
    WSADATA wsaData;
    if (0 != WSAStartup(MAKEWORD(2, 2), &wsaData)) {
        SCLogError(SC_ERR_FATAL, "Can't initialize Windows sockets: %d", WSAGetLastError());
        return -1;
    }

    return 0;
}
#endif /* OS_WIN32 */

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

/* Initialize the user and group Suricata is to run as. */
static int InitRunAs(SCInstance *suri)
{
#ifndef OS_WIN32
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
#endif
    return TM_ECODE_OK;
}

static int InitSignalHandler(SCInstance *suri)
{
    /* registering signals we use */
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    UtilSignalHandlerSetup(SIGINT, SignalHandlerSigint);
    UtilSignalHandlerSetup(SIGTERM, SignalHandlerSigterm);
#if HAVE_LIBUNWIND
    int enabled;
    if (ConfGetBool("logging.stacktrace-on-signal", &enabled) == 0) {
        enabled = 1;
    }

    if (enabled) {
        SCLogInfo("Preparing unexpected signal handling");
        struct sigaction stacktrace_action;
        memset(&stacktrace_action, 0, sizeof(stacktrace_action));
        stacktrace_action.sa_sigaction = SignalHandlerUnexpected;
        stacktrace_action.sa_flags = SA_SIGINFO;
        sigaction(SIGSEGV, &stacktrace_action, NULL);
        sigaction(SIGABRT, &stacktrace_action, NULL);
    }
#endif /* HAVE_LIBUNWIND */
#endif
#ifndef OS_WIN32
    UtilSignalHandlerSetup(SIGHUP, SignalHandlerSigHup);
    UtilSignalHandlerSetup(SIGPIPE, SIG_IGN);
    UtilSignalHandlerSetup(SIGSYS, SIG_IGN);
#endif /* OS_WIN32 */

    return TM_ECODE_OK;
}

/* initialization code for both the main modes and for
 * unix socket mode.
 *
 * Will be run once per pcap in unix-socket mode */
void PreRunInit(const int runmode)
{
    HttpRangeContainersInit();
    if (runmode == RUNMODE_UNIX_SOCKET)
        return;

    StatsInit();
#ifdef PROFILE_RULES
    SCProfilingRulesGlobalInit();
#endif
#ifdef PROFILING
    SCProfilingKeywordsGlobalInit();
    SCProfilingPrefilterGlobalInit();
    SCProfilingSghsGlobalInit();
#endif /* PROFILING */
#ifdef PROFILE_RULES
    SCProfilingInit();
#endif
    DefragInit();
    FlowInitConfig(FLOW_QUIET);
    IPPairInitConfig(FLOW_QUIET);
    StreamTcpInitConfig(STREAM_VERBOSE);
    AppLayerParserPostStreamSetup();
    AppLayerRegisterGlobalCounters();
    OutputFilestoreRegisterGlobalCounters();
}

/* tasks we need to run before packets start flowing,
 * but after we dropped privs */
void PreRunPostPrivsDropInit(const int runmode)
{
    StatsSetupPostConfigPreOutput();
    RunModeInitializeOutputs();
    DatasetsInit();

    if (runmode == RUNMODE_UNIX_SOCKET) {
        /* As the above did some necessary startup initialization, it
         * also setup some outputs where only one is allowed, so
         * deinitialize to the state that unix-mode does after every
         * pcap. */
        PostRunDeinit(RUNMODE_PCAP_FILE, NULL);
        return;
    }

    StatsSetupPostConfigPostOutput();
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


static int StartInternalRunMode(SCInstance *suri, int argc, char **argv)
{
    /* Treat internal running mode */
    switch(suri->run_mode) {
        case RUNMODE_LIST_KEYWORDS:
            return ListKeywords(suri->keyword_info);
        case RUNMODE_LIST_APP_LAYERS:
            if (suri->conf_filename != NULL) {
                return ListAppLayerProtocols(suri->conf_filename);
            } else {
                return ListAppLayerProtocols(DEFAULT_CONF_FILE);
            }
        case RUNMODE_PRINT_VERSION:
            PrintVersion();
            return TM_ECODE_DONE;
        case RUNMODE_PRINT_BUILDINFO:
            PrintBuildInfo();
            return TM_ECODE_DONE;
        case RUNMODE_PRINT_USAGE:
            PrintUsage(argv[0]);
            return TM_ECODE_DONE;
        case RUNMODE_LIST_RUNMODES:
            RunModeListRunmodes();
            return TM_ECODE_DONE;
        case RUNMODE_LIST_UNITTEST:
            RunUnittests(1, suri->regex_arg);
        case RUNMODE_UNITTEST:
            RunUnittests(0, suri->regex_arg);
#ifdef OS_WIN32
        case RUNMODE_INSTALL_SERVICE:
            if (SCServiceInstall(argc, argv)) {
                return TM_ECODE_FAILED;
            }
            SCLogInfo("Suricata service has been successfuly installed.");
            return TM_ECODE_DONE;
        case RUNMODE_REMOVE_SERVICE:
            if (SCServiceRemove(argc, argv)) {
                return TM_ECODE_FAILED;
            }
            SCLogInfo("Suricata service has been successfuly removed.");
            return TM_ECODE_DONE;
        case RUNMODE_CHANGE_SERVICE_PARAMS:
            if (SCServiceChangeParams(argc, argv)) {
                return TM_ECODE_FAILED;
            }
            SCLogInfo("Suricata service startup parameters has been successfuly changed.");
            return TM_ECODE_DONE;
#endif /* OS_WIN32 */
        default:
            /* simply continue for other running mode */
            break;
    }
    return TM_ECODE_OK;
}

static int FinalizeRunMode(SCInstance *suri, char **argv)
{
    switch (suri->run_mode) {
        case RUNMODE_UNKNOWN:
            PrintUsage(argv[0]);
            return TM_ECODE_FAILED;
        default:
            break;
    }
    /* Set the global run mode and offline flag. */
    run_mode = suri->run_mode;

    if (!CheckValidDaemonModes(suri->daemon, suri->run_mode)) {
        return TM_ECODE_FAILED;
    }

    return TM_ECODE_OK;
}

static void SetupDelayedDetect(SCInstance *suri)
{
    /* In offline mode delayed init of detect is a bad idea */
    if (suri->offline) {
        suri->delayed_detect = 0;
    } else {
        if (ConfGetBool("detect.delayed-detect", &suri->delayed_detect) != 1) {
            ConfNode *denode = NULL;
            ConfNode *decnf = ConfGetNode("detect-engine");
            if (decnf != NULL) {
                TAILQ_FOREACH(denode, &decnf->head, next) {
                    if (strcmp(denode->val, "delayed-detect") == 0) {
                        (void)ConfGetChildValueBool(denode, "delayed-detect", &suri->delayed_detect);
                    }
                }
            }
        }
    }

    SCLogConfig("Delayed detect %s", suri->delayed_detect ? "enabled" : "disabled");
    if (suri->delayed_detect) {
        SCLogInfo("Packets will start being processed before signatures are active.");
    }

}

static int LoadSignatures(DetectEngineCtx *de_ctx, SCInstance *suri)
{
    if (SigLoadSignatures(de_ctx, suri->sig_file, suri->sig_file_exclusive) < 0) {
        SCLogError(SC_ERR_NO_RULES_LOADED, "Loading signatures failed.");
        if (de_ctx->failure_fatal)
            return TM_ECODE_FAILED;
    }

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
                nlive = LiveGetDeviceNameCount();
                for (lthread = 0; lthread < nlive; lthread++) {
                    const char *live_dev = LiveGetDeviceNameName(lthread);
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

static void PostRunStartedDetectSetup(const SCInstance *suri)
{
#ifndef OS_WIN32
    /* registering signal handlers we use. We setup usr2 here, so that one
     * can't call it during the first sig load phase or while threads are still
     * starting up. */
    if (DetectEngineEnabled() && suri->delayed_detect == 0) {
        UtilSignalHandlerSetup(SIGUSR2, SignalHandlerSigusr2);
        UtilSignalUnblock(SIGUSR2);
    }
#endif
    if (suri->delayed_detect) {
        /* force 'reload', this will load the rules and swap engines */
        DetectEngineReload(suri);
        SCLogNotice("Signature(s) loaded, Detect thread(s) activated.");
#ifndef OS_WIN32
        UtilSignalHandlerSetup(SIGUSR2, SignalHandlerSigusr2);
        UtilSignalUnblock(SIGUSR2);
#endif
    }
}

void PostConfLoadedDetectSetup(SCInstance *suri)
{
    DetectEngineCtx *de_ctx = NULL;
    if (!suri->disabled_detect) {
        SCClassConfInit();
        SCReferenceConfInit();
        SetupDelayedDetect(suri);
        int mt_enabled = 0;
        (void)ConfGetBool("multi-detect.enabled", &mt_enabled);
        int default_tenant = 0;
        if (mt_enabled)
            (void)ConfGetBool("multi-detect.default", &default_tenant);
        if (DetectEngineMultiTenantSetup() == -1) {
            FatalError(SC_ERR_FATAL, "initializing multi-detect "
                       "detection engine contexts failed.");
        }
        if (suri->delayed_detect && suri->run_mode != RUNMODE_CONF_TEST) {
            de_ctx = DetectEngineCtxInitStubForDD();
        } else if (mt_enabled && !default_tenant && suri->run_mode != RUNMODE_CONF_TEST) {
            de_ctx = DetectEngineCtxInitStubForMT();
        } else {
            de_ctx = DetectEngineCtxInit();
        }
        if (de_ctx == NULL) {
            FatalError(SC_ERR_FATAL, "initializing detection engine "
                       "context failed.");
        }

        if (de_ctx->type == DETECT_ENGINE_TYPE_NORMAL) {
            if (LoadSignatures(de_ctx, suri) != TM_ECODE_OK)
                exit(EXIT_FAILURE);
        }

        gettimeofday(&de_ctx->last_reload, NULL);
        DetectEngineAddToMaster(de_ctx);
        DetectEngineBumpVersion();
    }
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

    if (ConfGet("host-mode", &hostmode) == 1) {
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

static void SetupUserMode(SCInstance *suri)
{
    /* apply 'user mode' config updates here */
    if (suri->system == false) {
        if (suri->set_logdir == false) {
            /* override log dir to current work dir" */
            if (ConfigSetLogDirectory((char *)".") != TM_ECODE_OK) {
                FatalError(SC_ERR_LOGDIR_CONFIG, "could not set USER mode logdir");
            }
        }
        if (suri->set_datadir == false) {
            /* override data dir to current work dir" */
            if (ConfigSetDataDirectory((char *)".") != TM_ECODE_OK) {
                FatalError(SC_ERR_LOGDIR_CONFIG, "could not set USER mode datadir");
            }
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
        if (ConfGet("capture.checksum-validation", &cv) == 1) {
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
    if (suri->run_mode == RUNMODE_AFP_DEV) {
        EBPFRegisterExtension();
        LiveDevRegisterExtension();
    }
#endif
    RegisterFlowBypassInfo();

    MacSetRegisterFlowStorage();

    AppLayerSetup();

    /* Suricata will use this umask if provided. By default it will use the
       umask passed on from the shell. */
    const char *custom_umask;
    if (ConfGet("umask", &custom_umask) == 1) {
        uint16_t mask;
        if (StringParseUint16(&mask, 8, (uint16_t)strlen(custom_umask), custom_umask) > 0) {
            umask((mode_t)mask);
        }
    }


    if (ConfigGetCaptureValue(suri) != TM_ECODE_OK) {
        SCReturnInt(TM_ECODE_FAILED);
    }

#ifdef NFQ
    if (suri->run_mode == RUNMODE_NFQ)
        NFQInitConfig(false);
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
    SigTableApplyStrictCommandlineOption(suri->strict_rule_parsing_string);
    TmqhSetup();

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

    FeatureTrackingRegister(); /* must occur prior to output mod registration */
    RegisterAllModules();
#ifdef HAVE_PLUGINS
    SCPluginsLoad(suri->capture_plugin_name, suri->capture_plugin_args);
#endif
    AppLayerHtpNeedFileInspection();

    StorageFinalize();

    TmModuleRunInit();

    if (MayDaemonize(suri) != TM_ECODE_OK)
        SCReturnInt(TM_ECODE_FAILED);

    if (InitSignalHandler(suri) != TM_ECODE_OK)
        SCReturnInt(TM_ECODE_FAILED);

    /* Check for the existance of the default logging directory which we pick
     * from suricata.yaml.  If not found, shut the engine down */
    suri->log_dir = ConfigGetLogDirectory();

    if (ConfigCheckLogDirectoryExists(suri->log_dir) != TM_ECODE_OK) {
        SCLogError(SC_ERR_LOGDIR_CONFIG, "The logging directory \"%s\" "
                "supplied by %s (default-log-dir) doesn't exist. "
                "Shutting down the engine", suri->log_dir, suri->conf_filename);
        SCReturnInt(TM_ECODE_FAILED);
    }
    if (!IsLogDirectoryWritable(suri->log_dir)) {
        SCLogError(SC_ERR_LOGDIR_CONFIG, "The logging directory \"%s\" "
                "supplied by %s (default-log-dir) is not writable. "
                "Shutting down the engine", suri->log_dir, suri->conf_filename);
        SCReturnInt(TM_ECODE_FAILED);
    }

    if (suri->disabled_detect) {
        SCLogConfig("detection engine disabled");
        /* disable raw reassembly */
        (void)ConfSetFinal("stream.reassembly.raw", "false");
    }

    HostInitConfig(HOST_VERBOSE);

    CoredumpLoadConfig();

    DecodeGlobalConfig();

    LiveDeviceFinalize();

    /* set engine mode if L2 IPS */
    if (PostDeviceFinalizedSetup(suri) != TM_ECODE_OK) {
        exit(EXIT_FAILURE);
    }

    /* hostmode depends on engine mode being set */
    PostConfLoadedSetupHostMode();

    PreRunInit(suri->run_mode);

    SCReturnInt(TM_ECODE_OK);
}

static void SuricataMainLoop(SCInstance *suri)
{
    while(1) {
        if (sigterm_count || sigint_count) {
            suricata_ctl_flags |= SURICATA_STOP;
        }

        if (suricata_ctl_flags & SURICATA_STOP) {
            SCLogNotice("Signal Received.  Stopping engine.");
            break;
        }

        TmThreadCheckThreadState();

        if (sighup_count > 0) {
            OutputNotifyFileRotation();
            sighup_count--;
        }

        if (sigusr2_count > 0) {
            if (!(DetectEngineReloadIsStart())) {
                DetectEngineReloadStart();
                DetectEngineReload(suri);
                DetectEngineReloadSetIdle();
                sigusr2_count--;
            }

        } else if (DetectEngineReloadIsStart()) {
            DetectEngineReload(suri);
            DetectEngineReloadSetIdle();
        }

        usleep(10* 1000);
    }
}

/**
 * \brief Global initialization common to all runmodes.
 *
 * This can be used by fuzz targets.
 */

int InitGlobal(void) {
    rs_init(&suricata_context);

    SC_ATOMIC_INIT(engine_stage);

    /* initialize the logging subsys */
    SCLogInitLogModule(NULL);

    SCSetThreadName("Suricata-Main");

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

int SuricataMain(int argc, char **argv)
{
    SCInstanceInit(&suricata, argv[0]);

    if (InitGlobal() != 0) {
        exit(EXIT_FAILURE);
    }

#ifdef OS_WIN32
    /* service initialization */
    if (WindowsInitService(argc, argv) != 0) {
        exit(EXIT_FAILURE);
    }
#endif /* OS_WIN32 */

    if (ParseCommandLine(argc, argv, &suricata) != TM_ECODE_OK) {
        exit(EXIT_FAILURE);
    }

    if (FinalizeRunMode(&suricata, argv) != TM_ECODE_OK) {
        exit(EXIT_FAILURE);
    }

    switch (StartInternalRunMode(&suricata, argc, argv)) {
        case TM_ECODE_DONE:
            exit(EXIT_SUCCESS);
        case TM_ECODE_FAILED:
            exit(EXIT_FAILURE);
    }

    /* Initializations for global vars, queues, etc (memsets, mutex init..) */
    GlobalsInitPreConfig();

    /* Load yaml configuration file if provided. */
    if (LoadYamlConfig(&suricata) != TM_ECODE_OK) {
        exit(EXIT_FAILURE);
    }

    if (suricata.run_mode == RUNMODE_DUMP_CONFIG) {
        ConfDump();
        exit(EXIT_SUCCESS);
    }

    int vlan_tracking = 1;
    if (ConfGetBool("vlan.use-for-tracking", &vlan_tracking) == 1 && !vlan_tracking) {
        /* Ignore vlan_ids when comparing flows. */
        g_vlan_mask = 0x0000;
    }
    SCLogDebug("vlan tracking is %s", vlan_tracking == 1 ? "enabled" : "disabled");

    SetupUserMode(&suricata);
    InitRunAs(&suricata);

    /* Since our config is now loaded we can finish configurating the
     * logging module. */
    SCLogLoadConfig(suricata.daemon, suricata.verbose, suricata.userid, suricata.groupid);

    LogVersion(&suricata);
    UtilCpuPrintSummary();

    if (ParseInterfacesList(suricata.aux_run_mode, suricata.pcap_dev) != TM_ECODE_OK) {
        exit(EXIT_FAILURE);
    }

    if (PostConfLoadedSetup(&suricata) != TM_ECODE_OK) {
        exit(EXIT_FAILURE);
    }

    SCDropMainThreadCaps(suricata.userid, suricata.groupid);

    /* Re-enable coredumps after privileges are dropped. */
    CoredumpEnable();

    PreRunPostPrivsDropInit(suricata.run_mode);

    LandlockSandboxing(&suricata);

    PostConfLoadedDetectSetup(&suricata);
    if (suricata.run_mode == RUNMODE_ENGINE_ANALYSIS) {
        goto out;
    } else if (suricata.run_mode == RUNMODE_CONF_TEST){
        SCLogNotice("Configuration provided was successfully loaded. Exiting.");
        goto out;
    } else if (suricata.run_mode == RUNMODE_DUMP_FEATURES) {
        FeatureDump();
        goto out;
    }

    SCSetStartTime(&suricata);
    RunModeDispatch(suricata.run_mode, suricata.runmode_custom_mode,
            suricata.capture_plugin_name, suricata.capture_plugin_args);
    if (suricata.run_mode != RUNMODE_UNIX_SOCKET) {
        UnixManagerThreadSpawnNonRunmode();
    }

    /* Wait till all the threads have been initialized */
    if (TmThreadWaitOnThreadInit() == TM_ECODE_FAILED) {
        FatalError(SC_ERR_FATAL, "Engine initialization failed, "
                   "aborting...");
    }

    int limit_nproc = 0;
    if (ConfGetBool("security.limit-noproc", &limit_nproc) == 0) {
        limit_nproc = 0;
    }
    if (limit_nproc) {
#ifdef HAVE_SYS_RESOURCE_H
#ifdef linux
        if (geteuid() == 0) {
            SCLogWarning(SC_ERR_SYSCONF, "setrlimit has no effet when running as root.");
        }
#endif
        struct rlimit r = { 0, 0 };
        if (setrlimit(RLIMIT_NPROC, &r) != 0) {
            SCLogWarning(SC_ERR_SYSCONF, "setrlimit failed to prevent process creation.");
        }
#else
        SCLogWarning(SC_ERR_SYSCONF, "setrlimit unavailable.");
#endif
    }

    SC_ATOMIC_SET(engine_stage, SURICATA_RUNTIME);
    PacketPoolPostRunmodes();

    /* Un-pause all the paused threads */
    TmThreadContinueThreads();

    /* Must ensure all threads are fully operational before continuing with init process */
    if (TmThreadWaitOnThreadRunning() != TM_ECODE_OK) {
        exit(EXIT_FAILURE);
    }

    /* Print notice and send OS specific notification of threads in running state */
    OnNotifyRunning();

    PostRunStartedDetectSetup(&suricata);

    SCPledge();
    SuricataMainLoop(&suricata);

    /* Update the engine stage/status flag */
    SC_ATOMIC_SET(engine_stage, SURICATA_DEINIT);

    UnixSocketKillSocketThread();
    PostRunDeinit(suricata.run_mode, &suricata.start_time);
    /* kill remaining threads */
    TmThreadKillThreads();

out:
    GlobalsDestroy(&suricata);

    exit(EXIT_SUCCESS);
}
