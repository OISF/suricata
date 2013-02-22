/* Copyright (C) 2007-2010 Open Information Security Foundation
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
#include "config.h"

#if HAVE_GETOPT_H
#include <getopt.h>
#endif

#if HAVE_SIGNAL_H
#include <signal.h>
#endif

#ifdef HAVE_NSS
#include <prinit.h>
#include <nss.h>
#endif

#include "suricata.h"
#include "decode.h"
#include "detect.h"
#include "packet-queue.h"
#include "threads.h"
#include "threadvars.h"

#include "util-atomic.h"
#include "util-spm.h"
#include "util-hash.h"
#include "util-hashlist.h"
#include "util-bloomfilter.h"
#include "util-bloomfilter-counting.h"
#include "util-pool.h"
#include "util-byte.h"
#include "util-cpu.h"
#include "util-action.h"
#include "util-pidfile.h"
#include "util-ioctl.h"
#include "util-device.h"
#include "util-misc.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-address.h"
#include "detect-engine-proto.h"
#include "detect-engine-port.h"
#include "detect-engine-mpm.h"
#include "detect-engine-sigorder.h"
#include "detect-engine-payload.h"
#include "detect-engine-dcepayload.h"
#include "detect-engine-uri.h"
#include "detect-engine-hcbd.h"
#include "detect-engine-hsbd.h"
#include "detect-engine-hhd.h"
#include "detect-engine-hrhd.h"
#include "detect-engine-hmd.h"
#include "detect-engine-hcd.h"
#include "detect-engine-hrud.h"
#include "detect-engine-hsmd.h"
#include "detect-engine-hscd.h"
#include "detect-engine-hua.h"
#include "detect-engine-hhhd.h"
#include "detect-engine-hrhhd.h"
#include "detect-engine-state.h"
#include "detect-engine-tag.h"
#include "detect-fast-pattern.h"

#include "tm-queuehandlers.h"
#include "tm-queues.h"
#include "tm-threads.h"

#include "tmqh-flow.h"

#include "conf.h"
#include "conf-yaml-loader.h"

#include "alert-fastlog.h"
#include "alert-unified2-alert.h"
#include "alert-debuglog.h"
#include "alert-prelude.h"
#include "alert-syslog.h"
#include "alert-pcapinfo.h"

#include "log-droplog.h"
#include "log-httplog.h"
#include "log-tlslog.h"
#include "log-pcap.h"
#include "log-file.h"
#include "log-filestore.h"

#include "stream-tcp.h"

#include "source-nfq.h"
#include "source-nfq-prototypes.h"

#include "source-ipfw.h"

#include "source-pcap.h"
#include "source-pcap-file.h"

#include "source-pfring.h"

#include "source-erf-file.h"
#include "source-erf-dag.h"
#include "source-napatech.h"

#include "source-af-packet.h"

#include "respond-reject.h"

#include "flow.h"
#include "flow-timeout.h"
#include "flow-manager.h"
#include "flow-var.h"
#include "flow-bit.h"
#include "flow-alert-sid.h"
#include "pkt-var.h"

#include "host.h"
#include "unix-manager.h"

#include "app-layer-detect-proto.h"
#include "app-layer-parser.h"
#include "app-layer-smb.h"
#include "app-layer-dcerpc.h"
#include "app-layer-dcerpc-udp.h"
#include "app-layer-htp.h"
#include "app-layer-ftp.h"
#include "app-layer-ssl.h"
#include "app-layer-ssh.h"
#include "app-layer-smtp.h"

#include "util-radix-tree.h"
#include "util-host-os-info.h"
#include "util-cidr.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-time.h"
#include "util-rule-vars.h"
#include "util-classification-config.h"
#include "util-threshold-config.h"
#include "util-reference-config.h"
#include "util-profiling.h"
#include "util-magic.h"
#include "util-signal.h"

#include "util-coredump-config.h"

#include "defrag.h"

#include "runmodes.h"

#include "util-cuda.h"
#include "util-decode-asn1.h"
#include "util-debug.h"
#include "util-error.h"
#include "detect-engine-siggroup.h"
#include "util-daemon.h"
#include "reputation.h"

/* holds the cuda b2g module */
#include "util-mpm-b2g-cuda.h"
#include "util-cuda-handlers.h"
#include "cuda-packet-batcher.h"

#include "output.h"
#include "util-privs.h"

#include "tmqh-packetpool.h"

#include "util-ringbuffer.h"
#include "util-mem.h"
#include "util-memcmp.h"
#include "util-proto-name.h"
#include "util-spm-bm.h"

/*
 * we put this here, because we only use it here in main.
 */
volatile sig_atomic_t sigint_count = 0;
volatile sig_atomic_t sighup_count = 0;
volatile sig_atomic_t sigterm_count = 0;

/*
 * Flag to indicate if the engine is at the initialization
 * or already processing packets. 2 stages: SURICATA_INIT,
 * SURICATA_RUNTIME and SURICATA_FINALIZE
 */
SC_ATOMIC_DECLARE(unsigned int, engine_stage);

/* Max packets processed simultaniously. */
#define DEFAULT_MAX_PENDING_PACKETS 1024

int rule_reload = 0;

/** suricata engine control flags */
uint8_t suricata_ctl_flags = 0;

/** Run mode selected */
int run_mode = RUNMODE_UNKNOWN;

/** engine_analysis.  disabled(0) by default, unless enabled by the user by
  * running the engine with --engine-analysis */
int engine_analysis = 0;

/** Engine mode: inline (ENGINE_MODE_IPS) or just
  * detection mode (ENGINE_MODE_IDS by default) */
uint8_t engine_mode = ENGINE_MODE_IDS;

/** Maximum packets to simultaneously process. */
intmax_t max_pending_packets;

/** set caps or not */
int sc_set_caps;

char *conf_filename = NULL;

int RunmodeIsUnittests(void) {
    if (run_mode == RUNMODE_UNITTEST)
        return 1;

    return 0;
}

int RunmodeGetCurrent(void)
{
    return run_mode;
}

static void SignalHandlerSigint(/*@unused@*/ int sig) {
    sigint_count = 1;
    suricata_ctl_flags |= SURICATA_STOP;
}
static void SignalHandlerSigterm(/*@unused@*/ int sig) {
    sigterm_count = 1;
    suricata_ctl_flags |= SURICATA_KILL;
}

void SignalHandlerSigusr2Disabled(int sig)
{
    SCLogInfo("Live rule reload not enabled in config.");

    return;
}

void SignalHandlerSigusr2SigFileStartup(int sig)
{
    SCLogInfo("Live rule reload not possible if -s or -S option used at runtime.");

    return;
}

void SignalHandlerSigusr2Idle(int sig)
{
    if (run_mode == RUNMODE_UNKNOWN || run_mode == RUNMODE_UNITTEST) {
        SCLogInfo("Ruleset load signal USR2 triggered for wrong runmode");
        return;
    }

    SCLogInfo("Ruleset load in progress.  New ruleset load "
              "allowed after current is done");

    return;
}

void SignalHandlerSigusr2(int sig)
{
    if (run_mode == RUNMODE_UNKNOWN || run_mode == RUNMODE_UNITTEST) {
        SCLogInfo("Ruleset load signal USR2 triggered for wrong runmode");
        return;
    }

    if (suricata_ctl_flags != 0) {
        SCLogInfo("Live rule swap no longer possible. Engine in shutdown mode.");
        return;
    }

    UtilSignalHandlerSetup(SIGUSR2, SignalHandlerSigusr2Idle);

    DetectEngineSpawnLiveRuleSwapMgmtThread();

    return;
}

#if 0
static void SignalHandlerSighup(/*@unused@*/ int sig) {
    sighup_count = 1;
    suricata_ctl_flags |= SURICATA_SIGHUP;
}
#endif

#ifdef DBG_MEM_ALLOC
#ifndef _GLOBAL_MEM_
#define _GLOBAL_MEM_
/* This counter doesn't complain realloc's(), it's gives
 * an aproximation for the startup */
size_t global_mem = 0;
#ifdef DBG_MEM_ALLOC_SKIP_STARTUP
uint8_t print_mem_flag = 0;
#else
uint8_t print_mem_flag = 1;
#endif
#endif
#endif

void GlobalInits()
{
    memset(trans_q, 0, sizeof(trans_q));
    memset(data_queues, 0, sizeof(data_queues));

    /* Initialize the trans_q mutex */
    int blah;
    int r = 0;
    for(blah=0;blah<256;blah++) {
        r |= SCMutexInit(&trans_q[blah].mutex_q, NULL);
        r |= SCCondInit(&trans_q[blah].cond_q, NULL);

        r |= SCMutexInit(&data_queues[blah].mutex_q, NULL);
        r |= SCCondInit(&data_queues[blah].cond_q, NULL);
   }

    if (r != 0) {
        SCLogInfo("Trans_Q Mutex not initialized correctly");
        exit(EXIT_FAILURE);
    }
}

/* XXX hack: make sure threads can stop the engine by calling this
   function. Purpose: pcap file mode needs to be able to tell the
   engine the file eof is reached. */
void EngineStop(void) {
    suricata_ctl_flags |= SURICATA_STOP;
}

void EngineKill(void) {
    suricata_ctl_flags |= SURICATA_KILL;
}

/**
 * \brief Used to indicate that the current task is done.
 *
 * This is mainly used by pcap-file to tell it has finished
 * to treat a pcap files when running in unix-socket mode.
 */
void EngineDone(void) {
    suricata_ctl_flags |= SURICATA_DONE;
}

static void SetBpfString(int optind, char *argv[]) {
    char *bpf_filter = NULL;
    uint32_t bpf_len = 0;
    int tmpindex = 0;

    /* attempt to parse remaining args as bpf filter */
    tmpindex = optind;
    while(argv[tmpindex] != NULL) {
        bpf_len+=strlen(argv[tmpindex]) + 1;
        tmpindex++;
    }

    if (bpf_len == 0)
        return;

    bpf_filter = SCMalloc(bpf_len);
    if (unlikely(bpf_filter == NULL))
        return;
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
        if (ConfSet("bpf-filter", bpf_filter, 0) != 1) {
            fprintf(stderr, "ERROR: Failed to set bpf filter.\n");
            exit(EXIT_FAILURE);
        }
    }
    SCFree(bpf_filter);
}
static void SetBpfStringFromFile(char *filename) {
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

#ifdef OS_WIN32
    if(_stat(filename, &st) != 0) {
#else
    if(stat(filename, &st) != 0) {
#endif /* OS_WIN32 */
        SCLogError(SC_ERR_FOPEN, "Failed to stat file %s", filename);
        exit(EXIT_FAILURE);
    }
    bpf_len = st.st_size + 1;

    fp = fopen(filename,"r");
    if (fp == NULL) {
        SCLogError(SC_ERR_FOPEN, "Failed to open file %s", filename);
        exit(EXIT_FAILURE);
    }

    bpf_filter = SCMalloc(bpf_len * sizeof(char));
    if (unlikely(bpf_filter == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "Failed to allocate buffer for bpf filter in file %s", filename);
        exit(EXIT_FAILURE);
    }
    memset(bpf_filter, 0x00, bpf_len);

    nm = fread(bpf_filter, bpf_len - 1, 1, fp);
    if((ferror(fp) != 0)||( nm != 1)) {
        *bpf_filter='\0';
    }
    fclose(fp);

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
        if(ConfSet("bpf-filter", bpf_filter, 0) != 1) {
            SCLogError(SC_ERR_FOPEN, "ERROR: Failed to set bpf filter!");
            SCFree(bpf_filter);
            exit(EXIT_FAILURE);
        }
    }
    SCFree(bpf_filter);
}

void usage(const char *progname)
{
#ifdef REVISION
    printf("%s %s (rev %s)\n", PROG_NAME, PROG_VER, xstr(REVISION));
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
    printf("\t-q <qid>                             : run in inline nfqueue mode\n");
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
    printf("\t-V                                   : display Suricata version\n");
#ifdef UNITTESTS
    printf("\t-u                                   : run the unittests and exit\n");
    printf("\t-U, --unittest-filter=REGEX          : filter unittests with a regex\n");
    printf("\t--list-unittests                     : list unit tests\n");
    printf("\t--fatal-unittests                    : enable fatal failure on unittest error\n");
#endif /* UNITTESTS */
    printf("\t--list-app-layer-protos              : list supported app layer protocols\n");
    printf("\t--list-keywords[=all|csv|<kword>]    : list keywords implemented by the engine\n");
#ifdef __SC_CUDA_SUPPORT__
    printf("\t--list-cuda-cards                    : list cuda supported cards\n");
#endif
    printf("\t--list-runmodes                      : list supported runmodes\n");
    printf("\t--runmode <runmode_id>               : specific runmode modification the engine should run.  The argument\n"
           "\t                                       supplied should be the id for the runmode obtained by running\n"
           "\t                                       --list-runmodes\n");
    printf("\t--engine-analysis                    : print reports on analysis of different sections in the engine and exit.\n"
           "\t                                       Please have a look at the conf parameter engine-analysis on what reports\n"
           "\t                                       can be printed\n");
    printf("\t--pidfile <file>                     : write pid to this file (only for daemon mode)\n");
    printf("\t--init-errors-fatal                  : enable fatal failure on signature init error\n");
    printf("\t--dump-config                        : show the running configuration\n");
    printf("\t--build-info                         : display build information\n");
    printf("\t--pcap[=<dev>]                       : run in pcap mode, no value select interfaces from suricata.yaml\n");
#ifdef HAVE_PCAP_SET_BUFF
    printf("\t--pcap-buffer-size                   : size of the pcap buffer value from 0 - %i\n",INT_MAX);
#endif /* HAVE_SET_PCAP_BUFF */
#ifdef HAVE_AF_PACKET
    printf("\t--af-packet[=<dev>]                  : run in af-packet mode, no value select interfaces from suricata.yaml\n");
#endif
#ifdef HAVE_PFRING
    printf("\t--pfring[=<dev>]                     : run in pfring mode, use interfaces from suricata.yaml\n");
    printf("\t--pfring-int <dev>                   : run in pfring mode, use interface <dev>\n");
    printf("\t--pfring-cluster-id <id>             : pfring cluster id \n");
    printf("\t--pfring-cluster-type <type>         : pfring cluster type for PF_RING 4.1.2 and later cluster_round_robin|cluster_flow\n");
#endif /* HAVE_PFRING */
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
    printf("\t--unix-socket[=<file>]       : use unix socket to control suricata work\n");
#endif
    printf("\n");
    printf("\nTo run the engine with default configuration on "
            "interface eth0 with signature file \"signatures.rules\", run the "
            "command as:\n\n%s -c suricata.yaml -s signatures.rules -i eth0 \n\n",
            progname);
}

void SCPrintBuildInfo(void) {
    char *bits = "<unknown>-bits";
    char *endian = "<unknown>-endian";
    char features[2048] = "";

#ifdef REVISION
    printf("This is %s version %s (rev %s)\n", PROG_NAME, PROG_VER, xstr(REVISION));
#elif defined RELEASE
    printf("This is %s version %s RELEASE\n", PROG_NAME, PROG_VER);
#else
    printf("This is %s version %s\n", PROG_NAME, PROG_VER);
#endif

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
#if LIBPCAP_VERSION_MAJOR == 1
    strlcat(features, "LIBPCAP_VERSION_MAJOR=1 ", sizeof(features));
#elif LIBPCAP_VERSION_MAJOR == 0
    strlcat(features, "LIBPCAP_VERSION_MAJOR=0 ", sizeof(features));
#endif
#ifdef __SC_CUDA_SUPPORT__
    strlcat(features, "CUDA ", sizeof(features));
#endif
#ifdef HAVE_PFRING
    strlcat(features, "PF_RING ", sizeof(features));
#endif
#ifdef HAVE_AF_PACKET
    strlcat(features, "AF_PACKET ", sizeof(features));
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
#ifdef HAVE_HTP_TX_GET_RESPONSE_HEADERS_RAW
    strlcat(features, "HAVE_HTP_TX_GET_RESPONSE_HEADERS_RAW ", sizeof(features));
#endif
#ifdef PCRE_HAVE_JIT
    strlcat(features, "PCRE_JIT ", sizeof(features));
#endif
#ifdef HAVE_NSS
    strlcat(features, "HAVE_NSS ", sizeof(features));
#endif
#ifdef HAVE_LUAJIT
    strlcat(features, "HAVE_LUAJIT ", sizeof(features));
#endif
#ifdef HAVE_LIBJANSSON
    strlcat(features, "HAVE_LIBJANSSON ", sizeof(features));
#endif
#ifdef PROFILING
    strlcat(features, "PROFILING ", sizeof(features));
#endif
#ifdef PROFILE_LOCKING
    strlcat(features, "PROFILE_LOCKING ", sizeof(features));
#endif
    if (strlen(features) == 0) {
        strlcat(features, "none", sizeof(features));
    }

    printf("Features: %s\n", features);

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

#ifdef __GCC_HAVE_SYNC_COMPARE_AND_SWAP_1
    printf("  __GCC_HAVE_SYNC_COMPARE_AND_SWAP_1\n");
#endif
#ifdef __GCC_HAVE_SYNC_COMPARE_AND_SWAP_2
    printf("  __GCC_HAVE_SYNC_COMPARE_AND_SWAP_2\n");
#endif
#ifdef __GCC_HAVE_SYNC_COMPARE_AND_SWAP_4
    printf("  __GCC_HAVE_SYNC_COMPARE_AND_SWAP_4\n");
#endif
#ifdef __GCC_HAVE_SYNC_COMPARE_AND_SWAP_8
    printf("  __GCC_HAVE_SYNC_COMPARE_AND_SWAP_8\n");
#endif
#ifdef __GCC_HAVE_SYNC_COMPARE_AND_SWAP_16
    printf("  __GCC_HAVE_SYNC_COMPARE_AND_SWAP_16\n");
#endif

#if __SSP__ == 1
    printf("compiled with -fstack-protector\n");
#endif
#if __SSP_ALL__ == 2
    printf("compiled with -fstack-protector-all\n");
#endif
#ifdef _FORTIFY_SOURCE
    printf("compiled with _FORTIFY_SOURCE=%d\n", _FORTIFY_SOURCE);
#endif

    printf("compiled with libhtp %s, linked against %s\n", HTP_BASE_VERSION_TEXT, htp_get_version());

#include "build-info.h"
}

int main(int argc, char **argv)
{
    int opt;
    char pcap_dev[128];
    char *sig_file = NULL;
    int sig_file_exclusive = FALSE;
    int conf_test = 0;
    char *pid_filename = NULL;
#ifdef UNITTESTS
    char *regex_arg = NULL;
#endif
    int dump_config = 0;
    int list_app_layer_protocols = 0;
    int list_unittests = 0;
    int list_cuda_cards = 0;
    int list_runmodes = 0;
    int list_keywords = 0;
    const char *keyword_info = NULL;
    const char *runmode_custom_mode = NULL;
    int daemon = 0;
#ifndef OS_WIN32
    char *user_name = NULL;
    char *group_name = NULL;
    uint8_t do_setuid = FALSE;
    uint8_t do_setgid = FALSE;
    uint32_t userid = 0;
    uint32_t groupid = 0;
#endif /* OS_WIN32 */
    int build_info = 0;
    int delayed_detect = 0;

    char *log_dir;
#ifdef OS_WIN32
    struct _stat buf;
#else
    struct stat buf;
#endif /* OS_WIN32 */

    sc_set_caps = FALSE;

    SC_ATOMIC_INIT(engine_stage);

    /* initialize the logging subsys */
    SCLogInitLogModule(NULL);

    if (SCSetThreadName("Suricata-Main") < 0) {
        SCLogWarning(SC_ERR_THREAD_INIT, "Unable to set thread name");
    }

    RunModeRegisterRunModes();

    /* By default use IDS mode, but if nfq or ipfw
     * are specified, IPS mode will overwrite this */
    SET_ENGINE_MODE_IDS(engine_mode);

    memset(pcap_dev, 0, sizeof(pcap_dev));

#ifdef OS_WIN32
	/* service initialization */
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
		daemon = 1;
		SCServiceInit(argc, argv);
	}

	/* Windows socket subsystem initialization */
	WSADATA wsaData;
	if (0 != WSAStartup(MAKEWORD(2, 2), &wsaData)) {
		SCLogError(SC_ERR_FATAL, "Can't initialize Windows sockets: %d", WSAGetLastError());
		exit(EXIT_FAILURE);
	}
#endif /* OS_WIN32 */

    /* Initialize the configuration module. */
    ConfInit();

    struct option long_opts[] = {
        {"dump-config", 0, &dump_config, 1},
        {"pfring", optional_argument, 0, 0},
        {"pfring-int", required_argument, 0, 0},
        {"pfring-cluster-id", required_argument, 0, 0},
        {"pfring-cluster-type", required_argument, 0, 0},
        {"af-packet", optional_argument, 0, 0},
        {"pcap", optional_argument, 0, 0},
#ifdef BUILD_UNIX_SOCKET
        {"unix-socket", optional_argument, 0, 0},
#endif
        {"pcap-buffer-size", required_argument, 0, 0},
        {"unittest-filter", required_argument, 0, 'U'},
        {"list-app-layer-protos", 0, &list_app_layer_protocols, 1},
        {"list-unittests", 0, &list_unittests, 1},
        {"list-cuda-cards", 0, &list_cuda_cards, 1},
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
        {"fatal-unittests", 0, 0, 0},
        {"user", required_argument, 0, 0},
        {"group", required_argument, 0, 0},
        {"erf-in", required_argument, 0, 0},
        {"dag", required_argument, 0, 0},
        {"napatech", 0, 0, 0},
        {"build-info", 0, &build_info, 1},
        {NULL, 0, NULL, 0}
    };

    /* getopt_long stores the option index here. */
    int option_index = 0;

    char short_opts[] = "c:TDhi:l:q:d:r:us:S:U:VF:";

    while ((opt = getopt_long(argc, argv, short_opts, long_opts, &option_index)) != -1) {
        switch (opt) {
        case 0:
            if (strcmp((long_opts[option_index]).name , "pfring") == 0 ||
                strcmp((long_opts[option_index]).name , "pfring-int") == 0) {
#ifdef HAVE_PFRING
                run_mode = RUNMODE_PFRING;
                if (optarg != NULL) {
                    memset(pcap_dev, 0, sizeof(pcap_dev));
                    strlcpy(pcap_dev, optarg,
                            ((strlen(optarg) < sizeof(pcap_dev)) ?
                             (strlen(optarg) + 1) : sizeof(pcap_dev)));
                    LiveRegisterDevice(optarg);
                }
#else
                SCLogError(SC_ERR_NO_PF_RING,"PF_RING not enabled. Make sure "
                        "to pass --enable-pfring to configure when building.");
                exit(EXIT_FAILURE);
#endif /* HAVE_PFRING */
            }
            else if(strcmp((long_opts[option_index]).name , "pfring-cluster-id") == 0){
#ifdef HAVE_PFRING
                if (ConfSet("pfring.cluster-id", optarg, 0) != 1) {
                    fprintf(stderr, "ERROR: Failed to set pfring.cluster-id.\n");
                    exit(EXIT_FAILURE);
                }
#else
                SCLogError(SC_ERR_NO_PF_RING,"PF_RING not enabled. Make sure "
                        "to pass --enable-pfring to configure when building.");
                exit(EXIT_FAILURE);
#endif /* HAVE_PFRING */
            }
            else if(strcmp((long_opts[option_index]).name , "pfring-cluster-type") == 0){
#ifdef HAVE_PFRING
                if (ConfSet("pfring.cluster-type", optarg, 0) != 1) {
                    fprintf(stderr, "ERROR: Failed to set pfring.cluster-type.\n");
                    exit(EXIT_FAILURE);
                }
#else
                SCLogError(SC_ERR_NO_PF_RING,"PF_RING not enabled. Make sure "
                        "to pass --enable-pfring to configure when building.");
                exit(EXIT_FAILURE);
#endif /* HAVE_PFRING */
            }
            else if (strcmp((long_opts[option_index]).name , "af-packet") == 0){
#ifdef HAVE_AF_PACKET
                if (run_mode == RUNMODE_UNKNOWN) {
                    run_mode = RUNMODE_AFP_DEV;
                    if (optarg) {
                        LiveRegisterDevice(optarg);
                        memset(pcap_dev, 0, sizeof(pcap_dev));
                        strlcpy(pcap_dev, optarg,
                                ((strlen(optarg) < sizeof(pcap_dev)) ?
                                 (strlen(optarg) + 1) : sizeof(pcap_dev)));
                    }
                } else if (run_mode == RUNMODE_AFP_DEV) {
                    SCLogWarning(SC_WARN_PCAP_MULTI_DEV_EXPERIMENTAL, "using "
                            "multiple devices to get packets is experimental.");
                    if (optarg) {
                        LiveRegisterDevice(optarg);
                    } else {
                        SCLogInfo("Multiple af-packet option without interface on each is useless");
                        break;
                    }
                } else {
                    SCLogError(SC_ERR_MULTIPLE_RUN_MODE, "more than one run mode "
                            "has been specified");
                    usage(argv[0]);
                    exit(EXIT_FAILURE);
                }
#else
                SCLogError(SC_ERR_NO_AF_PACKET,"AF_PACKET not enabled. On Linux "
                        "host, make sure to pass --enable-af-packet to "
                        "configure when building.");
                exit(EXIT_FAILURE);
#endif
            } else if (strcmp((long_opts[option_index]).name , "pcap") == 0) {
                if (run_mode == RUNMODE_UNKNOWN) {
                    run_mode = RUNMODE_PCAP_DEV;
                    if (optarg) {
                        LiveRegisterDevice(optarg);
                        memset(pcap_dev, 0, sizeof(pcap_dev));
                        strlcpy(pcap_dev, optarg,
                                ((strlen(optarg) < sizeof(pcap_dev)) ?
                                 (strlen(optarg) + 1) : sizeof(pcap_dev)));
                    }
                } else if (run_mode == RUNMODE_PCAP_DEV) {
#ifdef OS_WIN32
                    SCLogError(SC_ERR_PCAP_MULTI_DEV_NO_SUPPORT, "pcap multi dev "
                            "support is not (yet) supported on Windows.");
                    exit(EXIT_FAILURE);
#else
                    SCLogWarning(SC_WARN_PCAP_MULTI_DEV_EXPERIMENTAL, "using "
                            "multiple pcap devices to get packets is experimental.");
                    LiveRegisterDevice(optarg);
#endif
                } else {
                    SCLogError(SC_ERR_MULTIPLE_RUN_MODE, "more than one run mode "
                            "has been specified");
                    usage(argv[0]);
                    exit(EXIT_FAILURE);
                }
            } else if(strcmp((long_opts[option_index]).name, "init-errors-fatal") == 0) {
                if (ConfSet("engine.init-failure-fatal", "1", 0) != 1) {
                    fprintf(stderr, "ERROR: Failed to set engine init-failure-fatal.\n");
                    exit(EXIT_FAILURE);
                }
#ifdef BUILD_UNIX_SOCKET
            } else if (strcmp((long_opts[option_index]).name , "unix-socket") == 0) {
                if (run_mode == RUNMODE_UNKNOWN) {
                    run_mode = RUNMODE_UNIX_SOCKET;
                    if (optarg) {
                        if (ConfSet("unix-command.filename", optarg, 0) != 1) {
                            fprintf(stderr, "ERROR: Failed to set unix-command.filename.\n");
                            exit(EXIT_FAILURE);
                        }

                    }
                } else {
                    SCLogError(SC_ERR_MULTIPLE_RUN_MODE, "more than one run mode "
                            "has been specified");
                    usage(argv[0]);
                    exit(EXIT_FAILURE);
                }
#endif
            }
            else if(strcmp((long_opts[option_index]).name, "list-app-layer-protocols") == 0) {
                /* listing all supported app layer protocols */
            }
            else if(strcmp((long_opts[option_index]).name, "list-unittests") == 0) {
#ifdef UNITTESTS
                /* Set run_mode to unit tests. */
                run_mode = RUNMODE_UNITTEST;
#else
                fprintf(stderr, "ERROR: Unit tests not enabled. Make sure to pass --enable-unittests to configure when building.\n");
                exit(EXIT_FAILURE);
#endif /* UNITTESTS */
            } else if(strcmp((long_opts[option_index]).name, "list-cuda-cards") == 0) {
#ifndef __SC_CUDA_SUPPORT__
                fprintf(stderr, "ERROR: Cuda not enabled. Make sure to pass "
                        "--enable-cuda to configure when building.\n");
                exit(EXIT_FAILURE);
#endif /* UNITTESTS */
            } else if (strcmp((long_opts[option_index]).name, "list-runmodes") == 0) {
                RunModeListRunmodes();
                exit(EXIT_SUCCESS);
            } else if (strcmp((long_opts[option_index]).name, "list-keywords") == 0) {
                if (optarg) {
                    if (strcmp("short",optarg)) {
                        keyword_info = optarg;
                    }
                }
            } else if (strcmp((long_opts[option_index]).name, "runmode") == 0) {
                runmode_custom_mode = optarg;
            } else if(strcmp((long_opts[option_index]).name, "engine-analysis") == 0) {
                // do nothing for now
            }
#ifdef OS_WIN32
            else if(strcmp((long_opts[option_index]).name, "service-install") == 0) {
				if (SCServiceInstall(argc, argv)) {
					exit(EXIT_FAILURE);
				}
				SCLogInfo("Suricata service has been successfuly installed.");
				exit(EXIT_SUCCESS);
            }
            else if(strcmp((long_opts[option_index]).name, "service-remove") == 0) {
				if (SCServiceRemove(argc, argv)) {
					exit(EXIT_FAILURE);
				}
				SCLogInfo("Suricata service has been successfuly removed.");
				exit(EXIT_SUCCESS);
            }
            else if(strcmp((long_opts[option_index]).name, "service-change-params") == 0) {
				if (SCServiceChangeParams(argc, argv)) {
					exit(EXIT_FAILURE);
				}
				SCLogInfo("Suricata service startup parameters has been successfuly changed.");
				exit(EXIT_SUCCESS);
            }
#endif /* OS_WIN32 */
            else if(strcmp((long_opts[option_index]).name, "pidfile") == 0) {
                pid_filename = optarg;
            }
            else if(strcmp((long_opts[option_index]).name, "fatal-unittests") == 0) {
#ifdef UNITTESTS
                if (ConfSet("unittests.failure-fatal", "1", 0) != 1) {
                    fprintf(stderr, "ERROR: Failed to set unittests failure-fatal.\n");
                    exit(EXIT_FAILURE);
                }
#else
                fprintf(stderr, "ERROR: Unit tests not enabled. Make sure to pass --enable-unittests to configure when building.\n");
                exit(EXIT_FAILURE);
#endif /* UNITTESTS */
            }
            else if(strcmp((long_opts[option_index]).name, "user") == 0) {
#ifndef HAVE_LIBCAP_NG
                SCLogError(SC_ERR_LIBCAP_NG_REQUIRED, "libcap-ng is required to"
                        " drop privileges, but it was not compiled into Suricata.");
                exit(EXIT_FAILURE);
#else
                user_name = optarg;
                do_setuid = TRUE;
#endif /* HAVE_LIBCAP_NG */
            }
            else if(strcmp((long_opts[option_index]).name, "group") == 0) {
#ifndef HAVE_LIBCAP_NG
                SCLogError(SC_ERR_LIBCAP_NG_REQUIRED, "libcap-ng is required to"
                        " drop privileges, but it was not compiled into Suricata.");
                exit(EXIT_FAILURE);
#else
                group_name = optarg;
                do_setgid = TRUE;
#endif /* HAVE_LIBCAP_NG */
            }
            else if (strcmp((long_opts[option_index]).name, "erf-in") == 0) {
                run_mode = RUNMODE_ERF_FILE;
                if (ConfSet("erf-file.file", optarg, 0) != 1) {
                    fprintf(stderr, "ERROR: Failed to set erf-file.file\n");
                    exit(EXIT_FAILURE);
                }
            }
            else if (strcmp((long_opts[option_index]).name, "dag") == 0) {
#ifdef HAVE_DAG
                if (run_mode == RUNMODE_UNKNOWN) {
                    run_mode = RUNMODE_DAG;
                }
                else if (run_mode != RUNMODE_DAG) {
                    SCLogError(SC_ERR_MULTIPLE_RUN_MODE,
                        "more than one run mode has been specified");
                    usage(argv[0]);
                    exit(EXIT_FAILURE);
                }
                LiveRegisterDevice(optarg);
#else
                SCLogError(SC_ERR_DAG_REQUIRED, "libdag and a DAG card are required"
						" to receieve packets using --dag.");
                exit(EXIT_FAILURE);
#endif /* HAVE_DAG */
		}
        else if (strcmp((long_opts[option_index]).name, "napatech") == 0) {
#ifdef HAVE_NAPATECH
            run_mode = RUNMODE_NAPATECH;
#else
            SCLogError(SC_ERR_NAPATECH_REQUIRED, "libntapi and a Napatech adapter are required"
                                                 " to capture packets using --napatech.");
            exit(EXIT_FAILURE);
#endif /* HAVE_NAPATECH */
			}
            else if(strcmp((long_opts[option_index]).name, "pcap-buffer-size") == 0) {
#ifdef HAVE_PCAP_SET_BUFF
                if (ConfSet("pcap.buffer-size", optarg, 0) != 1) {
                    fprintf(stderr, "ERROR: Failed to set pcap-buffer-size.\n");
                    exit(EXIT_FAILURE);
                }
#else
                SCLogError(SC_ERR_NO_PCAP_SET_BUFFER_SIZE, "The version of libpcap you have"
                        " doesn't support setting buffer size.");
#endif /* HAVE_PCAP_SET_BUFF */
            }
            else if(strcmp((long_opts[option_index]).name, "build-info") == 0) {
                SCPrintBuildInfo();
                exit(EXIT_SUCCESS);
            }
            break;
        case 'c':
            conf_filename = optarg;
            break;
        case 'T':
            SCLogInfo("Running suricata under test mode");
            conf_test = 1;
            if (ConfSet("engine.init-failure-fatal", "1", 0) != 1) {
                fprintf(stderr, "ERROR: Failed to set engine init-failure-fatal.\n");
                exit(EXIT_FAILURE);
            }
            break;
#ifndef OS_WIN32
        case 'D':
            daemon = 1;
            break;
#endif /* OS_WIN32 */
        case 'h':
            usage(argv[0]);
            exit(EXIT_SUCCESS);
            break;
        case 'i':
            memset(pcap_dev, 0, sizeof(pcap_dev));

            /* some windows shells require escaping of the \ in \Device. Otherwise
             * the backslashes are stripped. We put them back here. */
            if (strlen(optarg) > 9 && strncmp(optarg, "DeviceNPF", 9) == 0) {
                snprintf(pcap_dev, sizeof(pcap_dev), "\\Device\\NPF%s", optarg+9);
            } else {
                strlcpy(pcap_dev, optarg, ((strlen(optarg) < sizeof(pcap_dev)) ? (strlen(optarg)+1) : (sizeof(pcap_dev))));
                PcapTranslateIPToDevice(pcap_dev, sizeof(pcap_dev));
            }

            if (strcmp(pcap_dev, optarg) != 0) {
                SCLogInfo("translated %s to pcap device %s", optarg, pcap_dev);
            } else if (strlen(pcap_dev) > 0 && isdigit((unsigned char)pcap_dev[0])) {
                SCLogError(SC_ERR_PCAP_TRANSLATE, "failed to find a pcap device for IP %s", optarg);
                exit(EXIT_FAILURE);
            }

            if (run_mode == RUNMODE_UNKNOWN) {
                run_mode = RUNMODE_PCAP_DEV;
                LiveRegisterDevice(pcap_dev);
            } else if (run_mode == RUNMODE_PCAP_DEV) {
#ifdef OS_WIN32
                SCLogError(SC_ERR_PCAP_MULTI_DEV_NO_SUPPORT, "pcap multi dev "
                        "support is not (yet) supported on Windows.");
                exit(EXIT_FAILURE);
#else
                SCLogWarning(SC_WARN_PCAP_MULTI_DEV_EXPERIMENTAL, "using "
                        "multiple pcap devices to get packets is experimental.");
                LiveRegisterDevice(pcap_dev);
#endif
            } else {
                SCLogError(SC_ERR_MULTIPLE_RUN_MODE, "more than one run mode "
                                                     "has been specified");
                usage(argv[0]);
                exit(EXIT_FAILURE);
            }
            break;
        case 'l':
            if (ConfSet("default-log-dir", optarg, 0) != 1) {
                fprintf(stderr, "ERROR: Failed to set log directory.\n");
                exit(EXIT_FAILURE);
            }
            if (stat(optarg, &buf) != 0) {
                SCLogError(SC_ERR_LOGDIR_CMDLINE, "The logging directory \"%s\""
                        " supplied at the commandline (-l %s) doesn't "
                        "exist. Shutting down the engine.", optarg, optarg);
                exit(EXIT_FAILURE);
            }
            break;
        case 'q':
#ifdef NFQ
            if (run_mode == RUNMODE_UNKNOWN) {
                run_mode = RUNMODE_NFQ;
                SET_ENGINE_MODE_IPS(engine_mode);
                if (NFQRegisterQueue(optarg) == -1)
                    exit(EXIT_FAILURE);
            } else if (run_mode == RUNMODE_NFQ) {
                if (NFQRegisterQueue(optarg) == -1)
                    exit(EXIT_FAILURE);
            } else {
                SCLogError(SC_ERR_MULTIPLE_RUN_MODE, "more than one run mode "
                                                     "has been specified");
                usage(argv[0]);
                exit(EXIT_FAILURE);
            }
#else
            SCLogError(SC_ERR_NFQ_NOSUPPORT,"NFQUEUE not enabled. Make sure to pass --enable-nfqueue to configure when building.");
            exit(EXIT_FAILURE);
#endif /* NFQ */
            break;
        case 'd':
#ifdef IPFW
            if (run_mode == RUNMODE_UNKNOWN) {
                run_mode = RUNMODE_IPFW;
                SET_ENGINE_MODE_IPS(engine_mode);
                if (IPFWRegisterQueue(optarg) == -1)
                    exit(EXIT_FAILURE);
            } else if (run_mode == RUNMODE_IPFW) {
                if (IPFWRegisterQueue(optarg) == -1)
                    exit(EXIT_FAILURE);
            } else {
                SCLogError(SC_ERR_MULTIPLE_RUN_MODE, "more than one run mode "
                                                     "has been specified");
                usage(argv[0]);
                exit(EXIT_SUCCESS);
            }
#else
            SCLogError(SC_ERR_IPFW_NOSUPPORT,"IPFW not enabled. Make sure to pass --enable-ipfw to configure when building.");
            exit(EXIT_FAILURE);
#endif /* IPFW */
            break;
        case 'r':
            if (run_mode == RUNMODE_UNKNOWN) {
                run_mode = RUNMODE_PCAP_FILE;
            } else {
                SCLogError(SC_ERR_MULTIPLE_RUN_MODE, "more than one run mode "
                                                     "has been specified");
                usage(argv[0]);
                exit(EXIT_SUCCESS);
            }
            if (ConfSet("pcap-file.file", optarg, 0) != 1) {
                fprintf(stderr, "ERROR: Failed to set pcap-file.file\n");
                exit(EXIT_FAILURE);
            }
            break;
        case 's':
            if (sig_file != NULL) {
                SCLogError(SC_ERR_CMD_LINE, "can't have multiple -s options or mix -s and -S.");
                exit(EXIT_FAILURE);
            }
            sig_file = optarg;
            break;
        case 'S':
            if (sig_file != NULL) {
                SCLogError(SC_ERR_CMD_LINE, "can't have multiple -S options or mix -s and -S.");
                exit(EXIT_FAILURE);
            }
            sig_file = optarg;
            sig_file_exclusive = TRUE;
            break;
        case 'u':
#ifdef UNITTESTS
            if (run_mode == RUNMODE_UNKNOWN) {
                run_mode = RUNMODE_UNITTEST;
            } else {
                SCLogError(SC_ERR_MULTIPLE_RUN_MODE, "more than one run mode has"
                                                     " been specified");
                usage(argv[0]);
                exit(EXIT_SUCCESS);
            }
#else
            fprintf(stderr, "ERROR: Unit tests not enabled. Make sure to pass --enable-unittests to configure when building.\n");
            exit(EXIT_FAILURE);
#endif /* UNITTESTS */
            break;
        case 'U':
#ifdef UNITTESTS
            regex_arg = optarg;

            if(strlen(regex_arg) == 0)
            regex_arg = NULL;
#endif
            break;
        case 'V':
#ifdef REVISION
            printf("This is %s version %s (rev %s)\n", PROG_NAME, PROG_VER, xstr(REVISION));
#elif defined RELEASE
            printf("This is %s version %s RELEASE\n", PROG_NAME, PROG_VER);
#else
            printf("This is %s version %s\n", PROG_NAME, PROG_VER);
#endif
            exit(EXIT_SUCCESS);
        case 'F':
            SetBpfStringFromFile(optarg);
            break;
        default:
            usage(argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    if (!list_keywords && !list_app_layer_protocols) {
#ifdef REVISION
        SCLogInfo("This is %s version %s (rev %s)", PROG_NAME, PROG_VER, xstr(REVISION));
#elif defined RELEASE
        SCLogInfo("This is %s version %s RELEASE", PROG_NAME, PROG_VER);
#else
        SCLogInfo("This is %s version %s", PROG_NAME, PROG_VER);
#endif
    }

#ifndef HAVE_HTP_TX_GET_RESPONSE_HEADERS_RAW
    SCLogWarning(SC_WARN_OUTDATED_LIBHTP, "libhtp < 0.2.7 detected. Keyword "
        "http_raw_header will not be able to inspect response headers.");
#endif

    SetBpfString(optind, argv);

    if (!list_keywords && !list_app_layer_protocols)
        UtilCpuPrintSummary();

#ifdef __SC_CUDA_SUPPORT__
    /* Init the CUDA environment */
    SCCudaInitCudaEnvironment();
    if (list_cuda_cards) {
        SCCudaListCards();
        exit(EXIT_SUCCESS);
    }
#endif

    if (!CheckValidDaemonModes(daemon, run_mode)) {
        exit(EXIT_FAILURE);
    }

    /* Initializations for global vars, queues, etc (memsets, mutex init..) */
    GlobalInits();
    TimeInit();
    SupportFastPatternForSigMatchTypes();

    /* load the pattern matchers */
    MpmTableSetup();

    if (run_mode != RUNMODE_UNITTEST &&
            !list_keywords &&
            !list_app_layer_protocols) {
        if (conf_filename == NULL)
            conf_filename = DEFAULT_CONF_FILE;
    }

    /** \todo we need an api for these */
    /* Load yaml configuration file if provided. */
    if (conf_filename != NULL) {
#ifdef UNITTESTS
        if (run_mode == RUNMODE_UNITTEST) {
            SCLogError(SC_ERR_CMD_LINE, "should not use a configuration file with unittests");
            exit(EXIT_FAILURE);
        }
#endif
        if (ConfYamlLoadFile(conf_filename) != 0) {
            /* Error already displayed. */
            exit(EXIT_FAILURE);
        }

        ConfNode *file;
        ConfNode *includes = ConfGetNode("include");
        if (includes != NULL) {
            TAILQ_FOREACH(file, &includes->head, next) {
                char *ifile = ConfLoadCompleteIncludePath(file->val);
                SCLogInfo("Including: %s", ifile);

                if (ConfYamlLoadFile(ifile) != 0) {
                    /* Error already displayed. */
                    exit(EXIT_FAILURE);
                }
            }
        }

        ConfNode *denode = NULL;
        ConfNode *decnf = ConfGetNode("detect-engine");
        if (decnf != NULL) {
            TAILQ_FOREACH(denode, &decnf->head, next) {
                if (strcmp(denode->val, "rule-reload") == 0) {
                    (void)ConfGetChildValueBool(denode, "rule-reload", &rule_reload);
                    SCLogInfo("Live rule reloads %s", rule_reload ? "enabled" : "disabled");
                }
            }
        }
    }

    AppLayerDetectProtoThreadInit();
    if (list_app_layer_protocols) {
        AppLayerListSupportedProtocols();
        exit(EXIT_SUCCESS);
    }
    AppLayerParsersInitPostProcess();

    if (dump_config) {
        ConfDump();
        exit(EXIT_SUCCESS);
    }

    /* Check for the existance of the default logging directory which we pick
     * from suricata.yaml.  If not found, shut the engine down */
    if (ConfGet("default-log-dir", &log_dir) != 1) {
#ifdef OS_WIN32
        log_dir = _getcwd(NULL, 0);
        if (log_dir == NULL) {
            log_dir = DEFAULT_LOG_DIR;
        }
#else
        log_dir = DEFAULT_LOG_DIR;
#endif /* OS_WIN32 */
    }

    if (!list_keywords && !list_app_layer_protocols) {
#ifdef OS_WIN32
        if (_stat(log_dir, &buf) != 0) {
#else
        if (stat(log_dir, &buf) != 0) {
#endif /* OS_WIN32 */
            SCLogError(SC_ERR_LOGDIR_CONFIG, "The logging directory \"%s\" "
                        "supplied by %s (default-log-dir) doesn't exist. "
                        "Shutting down the engine", log_dir, conf_filename);
            exit(EXIT_FAILURE);
        }
    }

    /* Pull the max pending packets from the config, if not found fall
     * back on a sane default. */
    if (ConfGetInt("max-pending-packets", &max_pending_packets) != 1)
        max_pending_packets = DEFAULT_MAX_PENDING_PACKETS;
    if (max_pending_packets >= 65535) {
        SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY,
                "Maximum max-pending-packets setting is 65534. "
                "Please check %s for errors", conf_filename);
        exit(EXIT_FAILURE);
    }

    SCLogDebug("Max pending packets set to %"PRIiMAX, max_pending_packets);

    /* Pull the default packet size from the config, if not found fall
     * back on a sane default. */
    char *temp_default_packet_size;
    if ((ConfGet("default-packet-size", &temp_default_packet_size)) != 1) {
        switch (run_mode) {
            case RUNMODE_PCAP_DEV:
            case RUNMODE_AFP_DEV:
            case RUNMODE_PFRING:
                /* FIXME this don't work effficiently in multiinterface */
                /* find payload for interface and use it */
                default_packet_size = GetIfaceMaxPayloadSize(pcap_dev);
                if (default_packet_size)
                    break;
            default:
                default_packet_size = DEFAULT_PACKET_SIZE;
        }
    } else {
        if (ParseSizeStringU32(temp_default_packet_size, &default_packet_size) < 0) {
            SCLogError(SC_ERR_SIZE_PARSE, "Error parsing max-pending-packets "
                       "from conf file - %s.  Killing engine",
                       temp_default_packet_size);
            exit(EXIT_FAILURE);
        }
    }

    SCLogDebug("Default packet size set to %"PRIu32, default_packet_size);

#ifdef NFQ
    if (run_mode == RUNMODE_NFQ)
        NFQInitConfig(FALSE);
#endif

    /* Since our config is now loaded we can finish configurating the
     * logging module. */
    SCLogLoadConfig(daemon);

#ifdef __SC_CUDA_SUPPORT__
    /* load the cuda configuration */
    SCCudaHlGetYamlConf();
#endif /* __SC_CUDA_SUPPORT__ */

    /* Load the Host-OS lookup. */
    SCHInfoLoadFromConfig();
    if (!list_keywords && !list_app_layer_protocols &&
        (run_mode != RUNMODE_UNIX_SOCKET)) {
        DefragInit();
    }

    if (run_mode == RUNMODE_UNKNOWN) {
        if (!engine_analysis && !list_keywords && !conf_test) {
            usage(argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    if (engine_analysis) {
        SCLogInfo("== Carrying out Engine Analysis ==");
        char *temp = NULL;
        if (ConfGet("engine-analysis", &temp) == 0) {
            SCLogInfo("no engine-analysis parameter(s) defined in conf file.  "
                      "Please define/enable them in the conf to use this "
                      "feature.");
            exit(EXIT_FAILURE);
        }
    }

    /* create table for O(1) lowercase conversion lookup.  It was removed, but
     * we still need it for cuda.  So resintalling it back into the codebase */
    uint8_t c = 0;
    memset(g_u8_lowercasetable, 0x00, sizeof(g_u8_lowercasetable));
    for ( ; c < 255; c++) {
        if (c >= 'A' && c <= 'Z')
            g_u8_lowercasetable[c] = (c + ('a' - 'A'));
        else
            g_u8_lowercasetable[c] = c;
    }

    /* hardcoded initialization code */
    SigTableSetup(); /* load the rule keywords */
    if (list_keywords) {
        SigTableList(keyword_info);
        exit(EXIT_FAILURE);
    }
    TmqhSetup();

    CIDRInit();
    SigParsePrepare();
    //PatternMatchPrepare(mpm_ctx, MPM_B2G);
    if (run_mode != RUNMODE_UNIX_SOCKET) {
        SCPerfInitCounterApi();
    }
#ifdef PROFILING
    SCProfilingRulesGlobalInit();
    SCProfilingInit();
#endif /* PROFILING */
    SCReputationInitCtx();
    SCProtoNameInit();

    TagInitCtx();

    if (DetectAddressTestConfVars() < 0) {
        SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY,
                "basic address vars test failed. Please check %s for errors", conf_filename);
        exit(EXIT_FAILURE);
    }
    if (DetectPortTestConfVars() < 0) {
        SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY,
                "basic port vars test failed. Please check %s for errors", conf_filename);
        exit(EXIT_FAILURE);
    }


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

    /* stream engine */
    TmModuleStreamTcpRegister();
    /* detection */
    TmModuleDetectRegister();
    /* respond-reject */
    TmModuleRespondRejectRegister();

    /* fast log */
    TmModuleAlertFastLogRegister();
    TmModuleAlertFastLogIPv4Register();
    TmModuleAlertFastLogIPv6Register();
    /* debug log */
    TmModuleAlertDebugLogRegister();
    /* prelue log */
    TmModuleAlertPreludeRegister();
    /* syslog log */
    TmModuleAlertSyslogRegister();
    TmModuleAlertSyslogIPv4Register();
    TmModuleAlertSyslogIPv6Register();
    /* unified2 log */
    TmModuleUnified2AlertRegister();
    /* pcap info log */
    TmModuleAlertPcapInfoRegister();
    /* drop log */
    TmModuleLogDropLogRegister();
    /* http log */
    TmModuleLogHttpLogRegister();
    TmModuleLogHttpLogIPv4Register();
    TmModuleLogHttpLogIPv6Register();
    TmModuleLogTlsLogRegister();
    TmModuleLogTlsLogIPv4Register();
    TmModuleLogTlsLogIPv6Register();
    /* pcap log */
    TmModulePcapLogRegister();
    /* file log */
    TmModuleLogFileLogRegister();
    TmModuleLogFilestoreRegister();
    /* cuda */
#ifdef __SC_CUDA_SUPPORT__
    TmModuleCudaMpmB2gRegister();
    TmModuleCudaPacketBatcherRegister();
#endif
    TmModuleDebugList();

    AppLayerHtpNeedFileInspection();

    DetectEngineRegisterAppInspectionEngines();

    if (rule_reload) {
        if (sig_file == NULL)
            UtilSignalHandlerSetup(SIGUSR2, SignalHandlerSigusr2Idle);
        else
            UtilSignalHandlerSetup(SIGUSR2, SignalHandlerSigusr2SigFileStartup);
    } else {
        UtilSignalHandlerSetup(SIGUSR2, SignalHandlerSigusr2Disabled);
    }

#ifdef UNITTESTS

    if (run_mode == RUNMODE_UNITTEST) {
#ifdef DBG_MEM_ALLOC
    SCLogInfo("Memory used at startup: %"PRIdMAX, (intmax_t)global_mem);
#endif
        /* test and initialize the unittesting subsystem */
        if(regex_arg == NULL){
            regex_arg = ".*";
            UtRunSelftest(regex_arg); /* inits and cleans up again */
        }

        AppLayerHtpEnableRequestBodyCallback();
        AppLayerHtpNeedFileInspection();

        UtInitialize();
        UTHRegisterTests();
        SCReputationRegisterTests();
        TmModuleRegisterTests();
        SigTableRegisterTests();
        HashTableRegisterTests();
        HashListTableRegisterTests();
        BloomFilterRegisterTests();
        BloomFilterCountingRegisterTests();
        PoolRegisterTests();
        ByteRegisterTests();
        MpmRegisterTests();
        FlowBitRegisterTests();
        FlowAlertSidRegisterTests();
        SCPerfRegisterTests();
        DecodePPPRegisterTests();
        DecodeVLANRegisterTests();
        HTPParserRegisterTests();
        SSLParserRegisterTests();
        SSHParserRegisterTests();
        SMBParserRegisterTests();
        DCERPCParserRegisterTests();
        DCERPCUDPParserRegisterTests();
        FTPParserRegisterTests();
        DecodeRawRegisterTests();
        DecodePPPOERegisterTests();
        DecodeICMPV4RegisterTests();
        DecodeICMPV6RegisterTests();
        DecodeIPV4RegisterTests();
        DecodeIPV6RegisterTests();
        DecodeTCPRegisterTests();
        DecodeUDPV4RegisterTests();
        DecodeGRERegisterTests();
        DecodeAsn1RegisterTests();
        AlpDetectRegisterTests();
        ConfRegisterTests();
        ConfYamlRegisterTests();
        TmqhFlowRegisterTests();
        FlowRegisterTests();
        SCSigRegisterSignatureOrderingTests();
        SCRadixRegisterTests();
        DefragRegisterTests();
        SigGroupHeadRegisterTests();
        SCHInfoRegisterTests();
        SCRuleVarsRegisterTests();
        AppLayerParserRegisterTests();
        ThreadMacrosRegisterTests();
        UtilSpmSearchRegistertests();
        UtilActionRegisterTests();
        SCClassConfRegisterTests();
        SCThresholdConfRegisterTests();
        SCRConfRegisterTests();
#ifdef __SC_CUDA_SUPPORT__
        SCCudaRegisterTests();
#endif
        PayloadRegisterTests();
        DcePayloadRegisterTests();
        UriRegisterTests();
#ifdef PROFILING
        SCProfilingRegisterTests();
#endif
        DeStateRegisterTests();
        DetectRingBufferRegisterTests();
        MemcmpRegisterTests();
        DetectEngineHttpClientBodyRegisterTests();
        DetectEngineHttpServerBodyRegisterTests();
        DetectEngineHttpHeaderRegisterTests();
        DetectEngineHttpRawHeaderRegisterTests();
        DetectEngineHttpMethodRegisterTests();
        DetectEngineHttpCookieRegisterTests();
        DetectEngineHttpRawUriRegisterTests();
        DetectEngineHttpStatMsgRegisterTests();
        DetectEngineHttpStatCodeRegisterTests();
        DetectEngineHttpUARegisterTests();
        DetectEngineHttpHHRegisterTests();
        DetectEngineHttpHRHRegisterTests();
        DetectEngineRegisterTests();
        SCLogRegisterTests();
        SMTPParserRegisterTests();
        MagicRegisterTests();
        UtilMiscRegisterTests();
        DetectAddressTests();
        DetectProtoTests();
        DetectPortTests();
        SCAtomicRegisterTests();
        if (list_unittests) {
            UtListTests(regex_arg);
        }
        else {
            uint32_t failed = UtRunTests(regex_arg);
            UtCleanup();
#ifdef __SC_CUDA_SUPPORT__
            /* need this in case any of the cuda dispatcher threads are still
             * running, kill them, so that we can free the cuda contexts.  We
             * need to free those cuda contexts so that next when we call
             * deregister functions, we will need to attach to those contexts
             * the contexts and its associated data */
            TmThreadKillThreads();
            SCCudaHlDeRegisterAllRegisteredModules();
#endif
            if (failed) {
                exit(EXIT_FAILURE);
            }
        }

#ifdef DBG_MEM_ALLOC
        SCLogInfo("Total memory used (without SCFree()): %"PRIdMAX, (intmax_t)global_mem);
#endif

        exit(EXIT_SUCCESS);
    }
#endif /* UNITTESTS */

    TmModuleRunInit();

    if (daemon == 1) {
        if (pid_filename == NULL) {
            if (ConfGet("pid-file", &pid_filename) == 1) {
                SCLogInfo("Use pid file %s from config file.", pid_filename);
           } else {
                pid_filename = DEFAULT_PID_FILENAME;
           }
        }
        if (SCPidfileTestRunning(pid_filename) != 0) {
            pid_filename = NULL;
            exit(EXIT_FAILURE);
        }
        Daemonize();
        if (SCPidfileCreate(pid_filename) != 0) {
            pid_filename = NULL;
#if 1
            SCLogError(SC_ERR_PIDFILE_DAEMON,
                       "Unable to create PID file, concurrent run of"
                       " Suricata can occur.");
            SCLogError(SC_ERR_PIDFILE_DAEMON,
                       "PID file creation WILL be mandatory for daemon mode"
                       " in future version");
#else
            exit(EXIT_FAILURE);
#endif
        }
    } else {
        if (pid_filename != NULL) {
            SCLogError(SC_ERR_PIDFILE_DAEMON, "The pidfile file option applies "
                    "only to the daemon modes");
            pid_filename = NULL;
            exit(EXIT_FAILURE);
        }
    }

#ifdef HAVE_NSS
    /* init NSS for md5 */
    PR_Init(PR_USER_THREAD, PR_PRIORITY_NORMAL, 0);
    NSS_NoDB_Init(NULL);
#endif

    /* registering signals we use */
    UtilSignalHandlerSetup(SIGINT, SignalHandlerSigint);
    UtilSignalHandlerSetup(SIGTERM, SignalHandlerSigterm);
    UtilSignalHandlerSetup(SIGPIPE, SIG_IGN);
    UtilSignalHandlerSetup(SIGSYS, SIG_IGN);

#ifndef OS_WIN32
	/* SIGHUP is not implemnetd on WIN32 */
    //UtilSignalHandlerSetup(SIGHUP, SignalHandlerSighup);

    /* Try to get user/group to run suricata as if
       command line as not decide of that */
    if (do_setuid == FALSE && do_setgid == FALSE) {
        char *id;
        if (ConfGet("run-as.user", &id) == 1) {
            do_setuid = TRUE;
            user_name = id;
        }
        if (ConfGet("run-as.group", &id) == 1) {
            do_setgid = TRUE;
            group_name = id;
        }
    }
    /* Get the suricata user ID to given user ID */
    if (do_setuid == TRUE) {
        if (SCGetUserID(user_name, group_name, &userid, &groupid) != 0) {
            SCLogError(SC_ERR_UID_FAILED, "failed in getting user ID");
            exit(EXIT_FAILURE);
        }

        sc_set_caps = TRUE;
    /* Get the suricata group ID to given group ID */
    } else if (do_setgid == TRUE) {
        if (SCGetGroupID(group_name, &groupid) != 0) {
            SCLogError(SC_ERR_GID_FAILED, "failed in getting group ID");
            exit(EXIT_FAILURE);
        }

        sc_set_caps = TRUE;
    }
#endif /* OS_WIN32 */

    PacketPoolInit(max_pending_packets);
    HostInitConfig(HOST_VERBOSE);
    if (run_mode != RUNMODE_UNIX_SOCKET) {
        FlowInitConfig(FLOW_VERBOSE);
    }

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        SCLogError(SC_ERR_INITIALIZATION, "initializing detection engine "
            "context failed.");
        exit(EXIT_FAILURE);
    }

    SCClassConfLoadClassficationConfigFile(de_ctx);
    SCRConfLoadReferenceConfigFile(de_ctx);

    if (ActionInitConfig() < 0) {
        exit(EXIT_FAILURE);
    }

    if (MagicInit() != 0)
        exit(EXIT_FAILURE);

    /* In offline mode delayed init of detect is a bad idea */
    if ((run_mode == RUNMODE_PCAP_FILE) ||
        (run_mode == RUNMODE_ERF_FILE) ||
        engine_analysis) {
        delayed_detect = 0;
    } else {
        ConfNode *denode = NULL;
        ConfNode *decnf = ConfGetNode("detect-engine");
        if (decnf != NULL) {
            TAILQ_FOREACH(denode, &decnf->head, next) {
                if (strcmp(denode->val, "delayed-detect") == 0) {
                    (void)ConfGetChildValueBool(denode, "delayed-detect", &delayed_detect);
                }
            }
        }
    }
    de_ctx->delayed_detect = delayed_detect;

    SCLogInfo("Delayed detect %s", delayed_detect ? "enabled" : "disabled");
    if (delayed_detect) {
        SCLogInfo("Packets will start being processed before signatures are active.");
    }

    if (!delayed_detect) {
        if (SigLoadSignatures(de_ctx, sig_file, sig_file_exclusive) < 0) {
            if (sig_file == NULL) {
                SCLogError(SC_ERR_OPENING_FILE, "Signature file has not been provided");
            } else {
                SCLogError(SC_ERR_NO_RULES_LOADED, "Loading signatures failed.");
            }
            if (de_ctx->failure_fatal)
                exit(EXIT_FAILURE);
        }
        if (engine_analysis) {
            exit(EXIT_SUCCESS);
        }
    }

    /* registering singal handlers we use.  We register usr2 here, so that one
     * can't call it during the first sig load phase */
    if (sig_file == NULL && rule_reload == 1)
        UtilSignalHandlerSetup(SIGUSR2, SignalHandlerSigusr2);

#ifdef __SC_CUDA_SUPPORT__
    SCCudaPBSetUpQueuesAndBuffers();
#endif /* __SC_CUDA_SUPPORT__ */

    SCThresholdConfInitContext(de_ctx,NULL);
    SCAsn1LoadConfig();

    CoredumpLoadConfig();

    struct timeval start_time;
    memset(&start_time, 0, sizeof(start_time));
    gettimeofday(&start_time, NULL);

    SCDropMainThreadCaps(userid, groupid);

    if (run_mode != RUNMODE_UNIX_SOCKET) {
        RunModeInitializeOutputs();
    }

    /* run the selected runmode */
    if (run_mode == RUNMODE_PCAP_DEV) {
        if (strlen(pcap_dev) == 0) {
            int ret = LiveBuildDeviceList("pcap");
            if (ret == 0) {
                fprintf(stderr, "ERROR: No interface found in config for pcap\n");
                exit(EXIT_FAILURE);
            }
        }
#ifdef HAVE_PFRING
    } else if (run_mode == RUNMODE_PFRING) {
        /* FIXME add backward compat support */
        /* iface has been set on command line */
        if (strlen(pcap_dev)) {
            if (ConfSet("pfring.live-interface", pcap_dev, 0) != 1) {
                fprintf(stderr, "ERROR: Failed to set pfring.live-interface\n");
                exit(EXIT_FAILURE);
            }
        } else {
            /* not an error condition if we have a 1.0 config */
            LiveBuildDeviceList("pfring");
        }
#endif /* HAVE_PFRING */
    } else if (run_mode == RUNMODE_AFP_DEV) {
        /* iface has been set on command line */
        if (strlen(pcap_dev)) {
            if (ConfSet("af-packet.live-interface", pcap_dev, 0) != 1) {
                fprintf(stderr, "ERROR: Failed to set af-packet.live-interface\n");
                exit(EXIT_FAILURE);
            }
        } else {
            int ret = LiveBuildDeviceList("af-packet");
            if (ret == 0) {
                fprintf(stderr, "ERROR: No interface found in config for af-packet\n");
                exit(EXIT_FAILURE);
            }
        }
    }

    if(conf_test == 1){
        SCLogInfo("Configuration provided was successfully loaded. Exiting.");
        exit(EXIT_SUCCESS);
    }

    RunModeDispatch(run_mode, runmode_custom_mode, de_ctx);

#ifdef __SC_CUDA_SUPPORT__
    if (PatternMatchDefaultMatcher() == MPM_B2G_CUDA) {
        /* start the dispatcher thread for this module */
        if (B2gCudaStartDispatcherThreadRC("SC_RULES_CONTENT_B2G_CUDA") == -1)
            exit(EXIT_FAILURE);
    }
#endif

    /* In Unix socket runmode, Flow manager is started on demand */
    if (run_mode != RUNMODE_UNIX_SOCKET) {
        /* Spawn the unix socket manager thread */
        int unix_socket = 0;
        if (ConfGetBool("unix-command.enabled", &unix_socket) != 1)
            unix_socket = 0;
        if (unix_socket == 1) {
            UnixManagerThreadSpawn(de_ctx, 0);
#ifdef BUILD_UNIX_SOCKET
            UnixManagerRegisterCommand("iface-stat", LiveDeviceIfaceStat, NULL,
                                       UNIX_CMD_TAKE_ARGS);
            UnixManagerRegisterCommand("iface-list", LiveDeviceIfaceList, NULL, 0);
#endif
        }
        /* Spawn the flow manager thread */
        FlowManagerThreadSpawn();
        StreamTcpInitConfig(STREAM_VERBOSE);
    }

    /* Spawn the L7 App Detect thread */
    //AppLayerDetectProtoThreadSpawn();

    /* Spawn the perf counter threads.  Let these be the last one spawned */
    if (run_mode != RUNMODE_UNIX_SOCKET) {
        SCPerfSpawnThreads();
    }

    /* Check if the alloted queues have at least 1 reader and writer */
    TmValidateQueueState();

    /* Wait till all the threads have been initialized */
    if (TmThreadWaitOnThreadInit() == TM_ECODE_FAILED) {
        SCLogError(SC_ERR_INITIALIZATION, "Engine initialization failed, "
                   "aborting...");
        exit(EXIT_FAILURE);
    }

    (void) SC_ATOMIC_CAS(&engine_stage, SURICATA_INIT, SURICATA_RUNTIME);

    /* Un-pause all the paused threads */
    TmThreadContinueThreads();

    if (delayed_detect) {
        if (SigLoadSignatures(de_ctx, sig_file, sig_file_exclusive) < 0) {
            if (sig_file == NULL) {
                SCLogError(SC_ERR_OPENING_FILE, "Signature file has not been provided");
            } else {
                SCLogError(SC_ERR_NO_RULES_LOADED, "Loading signatures failed.");
            }
            if (de_ctx->failure_fatal)
                exit(EXIT_FAILURE);
        }
        TmThreadActivateDummySlot();
        SCLogInfo("Signature(s) loaded, Detect thread(s) activated.");
    }


#ifdef DBG_MEM_ALLOC
    SCLogInfo("Memory used at startup: %"PRIdMAX, (intmax_t)global_mem);
#ifdef DBG_MEM_ALLOC_SKIP_STARTUP
    print_mem_flag = 1;
#endif
#endif

    int engine_retval = EXIT_SUCCESS;
    while(1) {
        if (suricata_ctl_flags & (SURICATA_KILL | SURICATA_STOP)) {
            SCLogInfo("Signal Received.  Stopping engine.");

            break;
        }

        TmThreadCheckThreadState();

        usleep(10* 1000);
    }

    /* Update the engine stage/status flag */
    (void) SC_ATOMIC_CAS(&engine_stage, SURICATA_RUNTIME, SURICATA_DEINIT);

#ifdef __SC_CUDA_SUPPORT__
    SCCudaPBKillBatchingPackets();
#endif

    UnixSocketKillSocketThread();

    if (run_mode != RUNMODE_UNIX_SOCKET) {
        /* First we need to kill the flow manager thread */
        FlowKillFlowManagerThread();
    }

    /* Disable packet acquire thread first */
    TmThreadDisableThreadsWithTMS(TM_FLAG_RECEIVE_TM | TM_FLAG_DECODE_TM);

    if (run_mode != RUNMODE_UNIX_SOCKET) {
        FlowForceReassembly();
    }

    struct timeval end_time;
    memset(&end_time, 0, sizeof(end_time));
    gettimeofday(&end_time, NULL);
    uint64_t milliseconds = ((end_time.tv_sec - start_time.tv_sec) * 1000) +
        (((1000000 + end_time.tv_usec - start_time.tv_usec) / 1000) - 1000);
    SCLogInfo("time elapsed %.3fs", (float)milliseconds/(float)1000);

    if (rule_reload == 1) {
        /* Disable detect threads first.  This is required by live rule swap */
        TmThreadDisableThreadsWithTMS(TM_FLAG_RECEIVE_TM | TM_FLAG_DECODE_TM |
                                      TM_FLAG_STREAM_TM | TM_FLAG_DETECT_TM);

        /* wait if live rule swap is in progress */
        if (UtilSignalIsHandler(SIGUSR2, SignalHandlerSigusr2Idle)) {
            SCLogInfo("Live rule swap in progress.  Waiting for it to end "
                    "before we shut the engine/threads down");
            while (UtilSignalIsHandler(SIGUSR2, SignalHandlerSigusr2Idle)) {
                /* sleep for 0.5 seconds */
                usleep(500000);
            }
            SCLogInfo("Received notification that live rule swap is done.  "
                    "Continuing with engine/threads shutdown");
        }
    }

    DetectEngineCtx *global_de_ctx = DetectEngineGetGlobalDeCtx();
    if (run_mode != RUNMODE_UNIX_SOCKET) {
        BUG_ON(global_de_ctx == NULL);
    }

    TmThreadKillThreads();

    if (run_mode != RUNMODE_UNIX_SOCKET) {
        SCPerfReleaseResources();
        FlowShutdown();
        StreamTcpFreeConfig(STREAM_VERBOSE);
    }
    HostShutdown();

    HTPFreeConfig();
    HTPAtExitPrintStats();

#ifdef DBG_MEM_ALLOC
    SCLogInfo("Total memory used (without SCFree()): %"PRIdMAX, (intmax_t)global_mem);
#ifdef DBG_MEM_ALLOC_SKIP_STARTUP
    print_mem_flag = 0;
#endif
#endif

    SCPidfileRemove(pid_filename);

    /** \todo review whats needed here */
#ifdef __SC_CUDA_SUPPORT__
    if (PatternMatchDefaultMatcher() == MPM_B2G_CUDA) {
        /* all threadvars related to cuda should be free by now, which means
         * the cuda contexts would be floating */
        if (SCCudaHlPushCudaContextFromModule("SC_RULES_CONTENT_B2G_CUDA") == -1) {
            SCLogError(SC_ERR_CUDA_HANDLER_ERROR, "Call to "
                       "SCCudaHlPushCudaContextForModule() failed during the "
                       "shutdown phase just before the call to SigGroupCleanup()");
        }
    }
#endif
#ifdef __SC_CUDA_SUPPORT__
    if (PatternMatchDefaultMatcher() == MPM_B2G_CUDA) {
        /* pop the cuda context we just pushed before the call to SigGroupCleanup() */
        if (SCCudaCtxPopCurrent(NULL) == -1) {
            SCLogError(SC_ERR_CUDA_HANDLER_ERROR, "Call to SCCudaCtxPopCurrent() "
                       "during the shutdown phase just before the call to "
                       "SigGroupCleanup()");
            return 0;
        }
    }
#endif

    AppLayerHtpPrintStats();

    if (global_de_ctx) {
        DetectEngineCtxFree(global_de_ctx);
    }
    AlpProtoDestroy();

    TagDestroyCtx();

    RunModeShutDown();
    OutputDeregisterAll();
    TimeDeinit();
    SCProtoNameDeInit();
    if (run_mode != RUNMODE_UNIX_SOCKET) {
        DefragDestroy();
    }
    PacketPoolDestroy();
    MagicDeinit();
    TmqhCleanup();
    TmModuleRunDeInit();

#ifdef HAVE_AF_PACKET
    AFPPeersListClean();
#endif

#ifdef PROFILING
    if (profiling_rules_enabled)
        SCProfilingDump();
    SCProfilingDestroy();
#endif

#ifdef __SC_CUDA_SUPPORT__
    /* all cuda contexts attached to any threads should be free by now.
     * if any host_thread is still attached to any cuda_context, they need
     * to pop them by the time we reach here, if they aren't using those
     * cuda contexts in any way */
    SCCudaHlDeRegisterAllRegisteredModules();
#endif
#ifdef OS_WIN32
	if (daemon) {
		return 0;
	}
#endif /* OS_WIN32 */

    SC_ATOMIC_DESTROY(engine_stage);

    exit(engine_retval);
}
