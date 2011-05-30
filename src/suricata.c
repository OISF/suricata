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

#include <getopt.h>
#include <signal.h>
#include <pthread.h>

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

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-sigorder.h"
#include "detect-engine-payload.h"
#include "detect-engine-dcepayload.h"
#include "detect-engine-uri.h"
#include "detect-engine-state.h"
#include "detect-engine-tag.h"

#include "tm-queuehandlers.h"
#include "tm-queues.h"
#include "tm-modules.h"
#include "tm-threads.h"

#include "tmqh-flow.h"

#include "conf.h"
#include "conf-yaml-loader.h"

#include "alert-fastlog.h"
#include "alert-unified-log.h"
#include "alert-unified-alert.h"
#include "alert-unified2-alert.h"
#include "alert-debuglog.h"
#include "alert-prelude.h"

#include "log-httplog.h"

#include "stream-tcp.h"

#include "source-nfq.h"
#include "source-nfq-prototypes.h"

#include "source-ipfw.h"

#include "source-pcap.h"
#include "source-pcap-file.h"

#include "source-pfring.h"

#include "source-erf-file.h"
#include "source-erf-dag.h"

#include "respond-reject.h"

#include "flow.h"
#include "flow-var.h"
#include "flow-bit.h"
#include "flow-alert-sid.h"
#include "pkt-var.h"

#include "app-layer-detect-proto.h"
#include "app-layer-parser.h"
#include "app-layer-tls.h"
#include "app-layer-smb.h"
#include "app-layer-dcerpc.h"
#include "app-layer-dcerpc-udp.h"
#include "app-layer-htp.h"
#include "app-layer-ftp.h"
#include "app-layer-ssl.h"
#include "app-layer-ssh.h"

#include "util-radix-tree.h"
#include "util-host-os-info.h"
#include "util-cidr.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-time.h"
#include "util-rule-vars.h"
#include "util-classification-config.h"
#include "util-threshold-config.h"
#include "util-profiling.h"

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
#define DEFAULT_MAX_PENDING_PACKETS 50

/** suricata engine control flags */
uint8_t suricata_ctl_flags = 0;

/** Run mode selected */
int run_mode = MODE_UNKNOWN;

/** Engine mode: inline (ENGINE_MODE_IPS) or just
  * detection mode (ENGINE_MODE_IDS by default) */
uint8_t engine_mode = ENGINE_MODE_IDS;

/** Maximum packets to simultaneously process. */
intmax_t max_pending_packets;

/** set caps or not */
int sc_set_caps;

int RunmodeIsUnittests(void) {
    if (run_mode == MODE_UNITTEST)
        return 1;

    return 0;
}

static void SignalHandlerSigint(/*@unused@*/ int sig) {
    sigint_count = 1;
    suricata_ctl_flags |= SURICATA_STOP;
}
static void SignalHandlerSigterm(/*@unused@*/ int sig) {
    sigterm_count = 1;
    suricata_ctl_flags |= SURICATA_KILL;
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

static void
SignalHandlerSetup(int sig, void (*handler)())
{
#if defined (OS_WIN32)
	signal(sig, handler);
#else
    struct sigaction action;

    action.sa_handler = handler;
    sigemptyset(&(action.sa_mask));
    sigaddset(&(action.sa_mask),sig);
    action.sa_flags = 0;
    sigaction(sig, &action, 0);
#endif /* OS_WIN32 */
}

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
    if (bpf_filter == NULL)
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

void usage(const char *progname)
{
#ifdef REVISION
    printf("%s %s (rev %s)\n", PROG_NAME, PROG_VER, xstr(REVISION));
#else
    printf("%s %s\n", PROG_NAME, PROG_VER);
#endif
    printf("USAGE: %s\n\n", progname);
    printf("\t-c <path>                    : path to configuration file\n");
    printf("\t-i <dev or ip>               : run in pcap live mode\n");
    printf("\t-r <path>                    : run in pcap file/offline mode\n");
#ifdef NFQ
    printf("\t-q <qid>                     : run in inline nfqueue mode\n");
#endif /* NFQ */
#ifdef IPFW
    printf("\t-d <divert port>             : run in inline ipfw divert mode\n");
#endif /* IPFW */
    printf("\t-s <path>                    : path to signature file (optional)\n");
    printf("\t-l <dir>                     : default log directory\n");
#ifndef OS_WIN32
    printf("\t-D                           : run as daemon\n");
#else
	printf("\t--service-install            : install as service\n");
	printf("\t--service-remove             : remove service\n");
	printf("\t--service-change-params      : change service startup parameters\n");
#endif /* OS_WIN32 */
#ifdef UNITTESTS
    printf("\t-u                           : run the unittests and exit\n");
    printf("\t-U, --unittest-filter=REGEX  : filter unittests with a regex\n");
    printf("\t--list-unittests             : list unit tests\n");
    printf("\t--fatal-unittests            : enable fatal failure on unittest error\n");
#endif /* UNITTESTS */
    printf("\t--pidfile <file>             : write pid to this file (only for daemon mode)\n");
    printf("\t--init-errors-fatal          : enable fatal failure on signature init error\n");
    printf("\t--dump-config                : show the running configuration\n");
#ifdef HAVE_PCAP_SET_BUFF
    printf("\t--pcap-buffer-size           : size of the pcap buffer value from 0 - %i\n",INT_MAX);
#endif /* HAVE_SET_PCAP_BUFF */
#ifdef HAVE_PFRING
    printf("\t--pfring-int <dev>           : run in pfring mode\n");
    printf("\t--pfring-cluster-id <id>     : pfring cluster id \n");
    printf("\t--pfring-cluster-type <type> : pfring cluster type for PF_RING 4.1.2 and later cluster_round_robin|cluster_flow\n");
#endif /* HAVE_PFRING */
#ifdef HAVE_LIBCAP_NG
    printf("\t--user <user>                : run suricata as this user after init\n");
    printf("\t--group <group>              : run suricata as this group after init\n");
#endif /* HAVE_LIBCAP_NG */
    printf("\t--erf-in <path>              : process an ERF file\n");
#ifdef HAVE_DAG
    printf("\t--dag <dag0,dag1,...>        : process ERF records from 0,1,...,n DAG input streams\n");
#endif
    printf("\n");
    printf("\nTo run the engine with default configuration on "
            "interface eth0 with signature file \"signatures.rules\", run the "
            "command as:\n\n%s -c suricata.yaml -s signatures.rules -i eth0 \n\n",
            progname);
}

int main(int argc, char **argv)
{
    int opt;
    char *pcap_file = NULL;
    char pcap_dev[128];
    char *pfring_dev = NULL;
    char *sig_file = NULL;
    char *nfq_id = NULL;
    char *conf_filename = NULL;
    char *pid_filename = NULL;
#ifdef UNITTESTS
    char *regex_arg = NULL;
#endif
    int dump_config = 0;
    int list_unittests = 0;
    int list_cuda_cards = 0;
    int daemon = 0;
    char *user_name = NULL;
    char *group_name = NULL;
    uint8_t do_setuid = FALSE;
    uint8_t do_setgid = FALSE;
    uint32_t userid = 0;
    uint32_t groupid = 0;
    char *erf_file = NULL;
    char *dag_input = NULL;

    char *log_dir;
    struct stat buf;

    sc_set_caps = FALSE;

    SC_ATOMIC_INIT(engine_stage);

    /* initialize the logging subsys */
    SCLogInitLogModule(NULL);

    /* By default use IDS mode, but if nfq or ipfw
     * are specified, IPS mode will overwrite this */
    SET_ENGINE_MODE_IDS(engine_mode);

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

#ifdef REVISION
    SCLogInfo("This is %s version %s (rev %s)", PROG_NAME, PROG_VER, xstr(REVISION));
#else
    SCLogInfo("This is %s version %s", PROG_NAME, PROG_VER);
#endif

    /* Initialize the configuration module. */
    ConfInit();

    struct option long_opts[] = {
        {"dump-config", 0, &dump_config, 1},
        {"pfring-int",  required_argument, 0, 0},
        {"pfring-cluster-id",  required_argument, 0, 0},
        {"pfring-cluster-type",  required_argument, 0, 0},
        {"pcap-buffer-size", required_argument, 0, 0},
        {"unittest-filter", required_argument, 0, 'U'},
        {"list-unittests", 0, &list_unittests, 1},
        {"list-cuda-cards", 0, &list_cuda_cards, 1},
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
        {NULL, 0, NULL, 0}
    };

    /* getopt_long stores the option index here. */
    int option_index = 0;

    char short_opts[] = "c:Dhi:l:q:d:r:us:U:V";

    while ((opt = getopt_long(argc, argv, short_opts, long_opts, &option_index)) != -1) {
        switch (opt) {
        case 0:
            if(strcmp((long_opts[option_index]).name , "pfring-int") == 0){
#ifdef HAVE_PFRING
                run_mode = MODE_PFRING;
                if (ConfSet("pfring.interface", optarg, 0) != 1) {
                    fprintf(stderr, "ERROR: Failed to set pfring interface.\n");
                    exit(EXIT_FAILURE);
                }
#else
                SCLogError(SC_ERR_NO_PF_RING,"PF_RING not enabled. Make sure to pass --enable-pfring to configure when building.");
                exit(EXIT_FAILURE);
#endif /* HAVE_PFRING */
            }
            else if(strcmp((long_opts[option_index]).name , "pfring-cluster-id") == 0){
#ifdef HAVE_PFRING
                if (ConfSet("pfring.cluster-id", optarg, 0) != 1) {
                    fprintf(stderr, "ERROR: Failed to set pfring cluster-id.\n");
                    exit(EXIT_FAILURE);
                }
#else
                SCLogError(SC_ERR_NO_PF_RING,"PF_RING not enabled. Make sure to pass --enable-pfring to configure when building.");
                exit(EXIT_FAILURE);
#endif /* HAVE_PFRING */
            }
            else if(strcmp((long_opts[option_index]).name , "pfring-cluster-type") == 0){
#ifdef HAVE_PFRING
                if (ConfSet("pfring.cluster-type", optarg, 0) != 1) {
                    fprintf(stderr, "ERROR: Failed to set pfring cluster-type.\n");
                    exit(EXIT_FAILURE);
                }
#else
                SCLogError(SC_ERR_NO_PF_RING,"PF_RING not enabled. Make sure to pass --enable-pfring to configure when building.");
                exit(EXIT_FAILURE);
#endif /* HAVE_PFRING */
            }
            else if(strcmp((long_opts[option_index]).name, "init-errors-fatal") == 0) {
                if (ConfSet("engine.init_failure_fatal", "1", 0) != 1) {
                    fprintf(stderr, "ERROR: Failed to set engine init_failure_fatal.\n");
                    exit(EXIT_FAILURE);
                }
            }
            else if(strcmp((long_opts[option_index]).name, "list-unittests") == 0) {
#ifdef UNITTESTS
                /* Set run_mode to unit tests. */
                run_mode = MODE_UNITTEST;
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
                if (ConfSet("unittests.failure_fatal", "1", 0) != 1) {
                    fprintf(stderr, "ERROR: Failed to set unittests failure_fatal.\n");
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
                run_mode = MODE_ERF_FILE;
                erf_file = optarg;
            }
			else if (strcmp((long_opts[option_index]).name, "dag") == 0) {
#ifdef HAVE_DAG
				run_mode = MODE_DAG;
				dag_input = optarg;
#else
				SCLogError(SC_ERR_DAG_REQUIRED, "libdag and a DAG card are required"
						" to receieve packets using --dag.");
				exit(EXIT_FAILURE);
#endif /* HAVE_DAG */
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
            break;
        case 'c':
            conf_filename = optarg;
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
            if (run_mode == MODE_UNKNOWN) {
                run_mode = MODE_PCAP_DEV;
            } else {
                SCLogError(SC_ERR_MULTIPLE_RUN_MODE, "more than one run mode "
                                                     "has been specified");
                usage(argv[0]);
                exit(EXIT_FAILURE);
            }
			memset(pcap_dev, 0, sizeof(pcap_dev));
			      strncpy(pcap_dev, optarg, ((strlen(optarg) < sizeof(pcap_dev)) ? (strlen(optarg)) : (sizeof(pcap_dev)-1)));
            break;
        case 'l':
            if (ConfSet("default-log-dir", optarg, 0) != 1) {
                fprintf(stderr, "ERROR: Failed to set log directory.\n");
                exit(EXIT_FAILURE);
            }
            if (stat(optarg, &buf) != 0) {
                SCLogError(SC_ERR_LOGDIR_CMDLINE, "The logging directory \"%s\" "
                        "upplied at the commandline (-l %s) doesn't "
                        "exist. Shutting down the engine.", optarg, optarg);
                exit(EXIT_FAILURE);
            }
            break;
        case 'q':
#ifdef NFQ
            if (run_mode == MODE_UNKNOWN) {
                run_mode = MODE_NFQ;
                SET_ENGINE_MODE_IPS(engine_mode);
            } else {
                SCLogError(SC_ERR_MULTIPLE_RUN_MODE, "more than one run mode "
                                                     "has been specified");
                usage(argv[0]);
                exit(EXIT_SUCCESS);
            }
            nfq_id = optarg;
#else
            SCLogError(SC_ERR_NFQ_NOSUPPORT,"NFQUEUE not enabled. Make sure to pass --enable-nfqueue to configure when building.");
            exit(EXIT_FAILURE);
#endif /* NFQ */
            break;
        case 'd':
#ifdef IPFW
            if (run_mode == MODE_UNKNOWN) {
                run_mode = MODE_IPFW;
                SET_ENGINE_MODE_IPS(engine_mode);
            } else {
                SCLogError(SC_ERR_MULTIPLE_RUN_MODE, "more than one run mode "
                                                     "has been specified");
                usage(argv[0]);
                exit(EXIT_SUCCESS);
            }
            if (ConfSet("ipfw-divert-port", optarg, 0) != 1) {
                fprintf(stderr, "ERROR: Failed to set ipfw_divert_port\n");
                exit(EXIT_FAILURE);
            }
#else
            SCLogError(SC_ERR_IPFW_NOSUPPORT,"IPFW not enabled. Make sure to pass --enable-ipfw to configure when building.");
            exit(EXIT_FAILURE);
#endif /* IPFW */
            break;
        case 'r':
            if (run_mode == MODE_UNKNOWN) {
                run_mode = MODE_PCAP_FILE;
            } else {
                SCLogError(SC_ERR_MULTIPLE_RUN_MODE, "more than one run mode "
                                                     "has been specified");
                usage(argv[0]);
                exit(EXIT_SUCCESS);
            }
            pcap_file = optarg;
            break;
        case 's':
            sig_file = optarg;
            break;
        case 'u':
#ifdef UNITTESTS
            if (run_mode == MODE_UNKNOWN) {
                run_mode = MODE_UNITTEST;
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
            printf("\nThis is %s version %s (rev %s)\n\n", PROG_NAME, PROG_VER, xstr(REVISION));
#else
            printf("\nThis is %s version %s\n\n", PROG_NAME, PROG_VER);
#endif
            exit(EXIT_SUCCESS);
        default:
            usage(argv[0]);
            exit(EXIT_FAILURE);
        }
    }
    SetBpfString(optind, argv);

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

    /* Load yaml configuration file if provided. */
    if (conf_filename != NULL) {
        if (ConfYamlLoadFile(conf_filename) != 0) {
            /* Error already displayed. */
            exit(EXIT_FAILURE);
        }
    } else if (run_mode != MODE_UNITTEST){
        SCLogError(SC_ERR_OPENING_FILE, "Configuration file has not been provided");
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    if (dump_config) {
        ConfDump();
        exit(EXIT_SUCCESS);
    }

    /* Check for the existance of the default logging directory which we pick
     * from suricata.yaml.  If not found, shut the engine down */
    if (ConfGet("default-log-dir", &log_dir) != 1)
        log_dir = DEFAULT_LOG_DIR;
    if (stat(log_dir, &buf) != 0) {
        SCLogError(SC_ERR_LOGDIR_CONFIG, "The logging directory \"%s\" "
                    "supplied by %s (default-log-dir) doesn't exist. "
                    "Shutting down the engine", log_dir, conf_filename);
        exit(EXIT_FAILURE);
    }

    /* Pull the max pending packets from the config, if not found fall
     * back on a sane default. */
    if (ConfGetInt("max-pending-packets", &max_pending_packets) != 1)
        max_pending_packets = DEFAULT_MAX_PENDING_PACKETS;
    SCLogDebug("Max pending packets set to %"PRIiMAX, max_pending_packets);

    /* Since our config is now loaded we can finish configurating the
     * logging module. */
    SCLogLoadConfig();

    /* Load the Host-OS lookup. */
    SCHInfoLoadFromConfig();
    DefragInit();

    if (run_mode == MODE_UNKNOWN) {
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    /* create table for O(1) lowercase conversion lookup */
    uint8_t c = 0;
    for ( ; c < 255; c++) {
       if (c >= 'A' && c <= 'Z')
           g_u8_lowercasetable[c] = (c + ('a' - 'A'));
       else
           g_u8_lowercasetable[c] = c;
    }
    /* hardcoded initialization code */
    MpmTableSetup(); /* load the pattern matchers */
    SigTableSetup(); /* load the rule keywords */
    TmqhSetup();

    CIDRInit();
    SigParsePrepare();
    //PatternMatchPrepare(mpm_ctx, MPM_B2G);
    SCPerfInitCounterApi();
#ifdef PROFILING
    SCProfilingInit();
#endif /* PROFILING */
    SCReputationInitCtx();

    TagInitCtx();

    TmModuleReceiveNFQRegister();
    TmModuleVerdictNFQRegister();
    TmModuleDecodeNFQRegister();
    TmModuleReceiveIPFWRegister();
    TmModuleVerdictIPFWRegister();
    TmModuleDecodeIPFWRegister();
    TmModuleReceivePcapRegister();
    TmModuleDecodePcapRegister();
    TmModuleReceivePfringRegister();
    TmModuleDecodePfringRegister();
    TmModuleReceivePcapFileRegister();
    TmModuleDecodePcapFileRegister();
    TmModuleDetectRegister();
    TmModuleAlertFastLogRegister();
    TmModuleAlertDebugLogRegister();
    TmModuleAlertPreludeRegister();
    TmModuleRespondRejectRegister();
    TmModuleAlertFastLogIPv4Register();
    TmModuleAlertFastLogIPv6Register();
    TmModuleAlertUnifiedLogRegister();
    TmModuleAlertUnifiedAlertRegister();
    TmModuleUnified2AlertRegister();
    TmModuleStreamTcpRegister();
    TmModuleLogHttpLogRegister();
    TmModuleLogHttpLogIPv4Register();
    TmModuleLogHttpLogIPv6Register();
#ifdef __SC_CUDA_SUPPORT__
    TmModuleCudaMpmB2gRegister();
    TmModuleCudaPacketBatcherRegister();
#endif
    TmModuleReceiveErfFileRegister();
    TmModuleDecodeErfFileRegister();
    TmModuleReceiveErfDagRegister();
    TmModuleDecodeErfDagRegister();
    TmModuleDebugList();

    /** \todo we need an api for these */
    AppLayerDetectProtoThreadInit();
    RegisterAppLayerParsers();
    RegisterHTPParsers();
    RegisterTLSParsers();
    RegisterSMBParsers();
    RegisterDCERPCParsers();
    RegisterDCERPCUDPParsers();
    RegisterFTPParsers();
    RegisterSSLParsers();
    RegisterSSHParsers();
    AppLayerParsersInitPostProcess();

#ifdef UNITTESTS

    if (run_mode == MODE_UNITTEST) {
#ifdef DBG_MEM_ALLOC
    SCLogInfo("Memory used at startup: %"PRIdMAX, (intmax_t)global_mem);
#endif
        /* test and initialize the unittesting subsystem */
        if(regex_arg == NULL){
            regex_arg = ".*";
            UtRunSelftest(regex_arg); /* inits and cleans up again */
        }

        AppLayerHtpEnableRequestBodyCallback();
        AppLayerHtpRegisterExtraCallbacks();

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
        TLSParserRegisterTests();
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
        SCLogRegisterTests();
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
        SSLParserRegisterTests();
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

    if (daemon == 1) {
        Daemonize();
        if (pid_filename != NULL) {
            if (SCPidfileCreate(pid_filename) != 0) {
                pid_filename = NULL;
                exit(EXIT_FAILURE);
            }
        }
    } else {
        if (pid_filename != NULL) {
            SCLogError(SC_ERR_PIDFILE_DAEMON, "The pidfile file option applies "
                    "only to the daemon modes");
            pid_filename = NULL;
            exit(EXIT_FAILURE);
        }
    }

    /* registering signals we use */
    SignalHandlerSetup(SIGINT, SignalHandlerSigint);
    SignalHandlerSetup(SIGTERM, SignalHandlerSigterm);

#ifndef OS_WIN32
	/* SIGHUP is not implemnetd on WIN32 */
    //SignalHandlerSetup(SIGHUP, SignalHandlerSighup);

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

    /* pre allocate packets */
    SCLogDebug("preallocating packets... packet size %" PRIuMAX "", (uintmax_t)sizeof(Packet));
    int i = 0;
    for (i = 0; i < max_pending_packets; i++) {
        /* XXX pkt alloc function */
        Packet *p = SCMalloc(sizeof(Packet));
        if (p == NULL) {
            SCLogError(SC_ERR_FATAL, "Fatal error encountered while allocating a packet. Exiting...");
            exit(EXIT_FAILURE);
        }
        PACKET_INITIALIZE(p);

        PacketPoolStorePacket(p);
    }
    SCLogInfo("preallocated %"PRIiMAX" packets. Total memory %"PRIuMAX"",
        max_pending_packets, (uintmax_t)(max_pending_packets*sizeof(Packet)));

    FlowInitConfig(FLOW_VERBOSE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        SCLogError(SC_ERR_INITIALIZATION, "initializing detection engine "
            "context failed.");
        exit(EXIT_FAILURE);
    }

    SCClassConfLoadClassficationConfigFile(de_ctx);

    ActionInitConfig();

    if (SigLoadSignatures(de_ctx, sig_file) < 0) {
        if (sig_file == NULL) {
            SCLogError(SC_ERR_OPENING_FILE, "Signature file has not been provided");
        } else {
            SCLogError(SC_ERR_NO_RULES_LOADED, "Loading signatures failed.");
        }
        if (de_ctx->failure_fatal)
            exit(EXIT_FAILURE);
    }


#ifdef PROFILING
    SCProfilingInitRuleCounters(de_ctx);
#endif /* PROFILING */

#ifdef __SC_CUDA_SUPPORT__
    SCCudaPBSetUpQueuesAndBuffers();
#endif /* __SC_CUDA_SUPPORT__ */

    AppLayerHtpRegisterExtraCallbacks();
    SCThresholdConfInitContext(de_ctx,NULL);
    SCAsn1LoadConfig();

    struct timeval start_time;
    memset(&start_time, 0, sizeof(start_time));
    gettimeofday(&start_time, NULL);

    SCDropMainThreadCaps(userid, groupid);

    RunModeInitializeOutputs();

    /* run the selected runmode */
    if (run_mode == MODE_PCAP_DEV) {
        //RunModeIdsPcap3(de_ctx, pcap_dev);
        //RunModeIdsPcap2(de_ctx, pcap_dev);
        //RunModeIdsPcap(de_ctx, pcap_dev);
        PcapTranslateIPToDevice(pcap_dev, sizeof(pcap_dev));
        RunModeIdsPcapAuto(de_ctx, pcap_dev);
    }
    else if (run_mode == MODE_PCAP_FILE) {
        //RunModeFilePcap(de_ctx, pcap_file);
        //RunModeFilePcap2(de_ctx, pcap_file);
        RunModeFilePcapAuto(de_ctx, pcap_file);
        //RunModeFilePcapAutoFp(de_ctx, pcap_file);
        //RunModeFilePcapAuto2(de_ctx, pcap_file);
    }
    else if (run_mode == MODE_PFRING) {
        //RunModeIdsPfring3(de_ctx, pfring_dev);
        //RunModeIdsPfring2(de_ctx, pfring_dev);
        //RunModeIdsPfring(de_ctx, pfring_dev);
        //RunModeIdsPfring4(de_ctx, pfring_dev);
        RunModeIdsPfringAuto(de_ctx, pfring_dev);
    }
    else if (run_mode == MODE_NFQ) {
        //RunModeIpsNFQ(de_ctx, nfq_id);
        RunModeIpsNFQAuto(de_ctx, nfq_id);
    }
    else if (run_mode == MODE_IPFW) {
        //RunModeIpsIPFW(de_ctx);
        RunModeIpsIPFWAuto(de_ctx);
    }
    else if (run_mode == MODE_ERF_FILE) {
        RunModeErfFileAuto(de_ctx, erf_file);
    }
    else if (run_mode == MODE_DAG) {
        RunModeErfDagAuto(de_ctx, dag_input);
    }
    else {
        SCLogError(SC_ERR_UNKNOWN_RUN_MODE, "Unknown runtime mode. Aborting");
        exit(EXIT_FAILURE);
    }

#ifdef __SC_CUDA_SUPPORT__
    if (PatternMatchDefaultMatcher() == MPM_B2G_CUDA) {
        /* start the dispatcher thread for this module */
        if (B2gCudaStartDispatcherThreadRC("SC_RULES_CONTENT_B2G_CUDA") == -1)
            exit(EXIT_FAILURE);
    }
#endif

    /* Spawn the flow manager thread */
    FlowManagerThreadSpawn();

    StreamTcpInitConfig(STREAM_VERBOSE);

    /* Spawn the L7 App Detect thread */
    //AppLayerDetectProtoThreadSpawn();

    /* Spawn the perf counter threads.  Let these be the last one spawned */
    SCPerfSpawnThreads();

    /* Check if the alloted queues have at least 1 reader and writer */
    TmValidateQueueState();

    /* Wait till all the threads have been initialized */
    if (TmThreadWaitOnThreadInit() == TM_ECODE_FAILED) {
        SCLogError(SC_ERR_INITIALIZATION, "Engine initialization failed, "
                   "aborting...");
        exit(EXIT_FAILURE);
    }

    SC_ATOMIC_CAS(&engine_stage, SURICATA_INIT, SURICATA_RUNTIME);

    /* Un-pause all the paused threads */
    TmThreadContinueThreads();

#ifdef DBG_MEM_ALLOC
    SCLogInfo("Memory used at startup: %"PRIdMAX, (intmax_t)global_mem);
#ifdef DBG_MEM_ALLOC_SKIP_STARTUP
    print_mem_flag = 1;
#endif
#endif

    while(1) {
        if (suricata_ctl_flags != 0) {
            SCLogInfo("signal received");

            if (suricata_ctl_flags & SURICATA_STOP)  {
                SCLogInfo("EngineStop received");

                /* Stop the engine so it quits after processing the pcap file
                 * but first make sure all packets are processed by all other
                 * threads. */
                char done = 0;
                do {
                    if (suricata_ctl_flags & SURICATA_KILL)
                        break;

                    /* if all packets are returned to the packetpool
                     * we are done */
                    if (PacketPoolSize() == max_pending_packets)
                        done = 1;

                    if (done == 0) {
                        usleep(100);
                    }
                } while (done == 0);

                SCLogInfo("all packets processed by threads, stopping engine");
            }

            struct timeval end_time;
            memset(&end_time, 0, sizeof(end_time));
            gettimeofday(&end_time, NULL);

            SCLogInfo("time elapsed %" PRIuMAX "s", (uintmax_t)(end_time.tv_sec - start_time.tv_sec));

#ifdef __SC_CUDA_SUPPORT__
            SCCudaPBKillBatchingPackets();
#endif

            TmThreadKillThreads();
            SCPerfReleaseResources();
            break;
        }

        TmThreadCheckThreadState();

        usleep(100);
    }

    /* Update the engine stage/status flag */
    SC_ATOMIC_CAS(&engine_stage, SURICATA_RUNTIME, SURICATA_DEINIT);


    FlowShutdown();
    FlowPrintQueueInfo();
    StreamTcpFreeConfig(STREAM_VERBOSE);
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
    SigGroupCleanup(de_ctx);
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

    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    AlpProtoDestroy();

    TagDestroyCtx();

    RunModeShutDown();
    OutputDeregisterAll();
    TimeDeinit();

#ifdef PROFILING
    if (profiling_rules_enabled)
        SCProfilingDump(stdout);
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
    exit(EXIT_SUCCESS);
}
