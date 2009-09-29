/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#include "eidps-common.h"

#include <getopt.h>

#include "eidps.h"
#include "decode.h"
#include "detect.h"
#include "packet-queue.h"
#include "threads.h"
#include "threadvars.h"

#include "util-binsearch.h"
#include "util-hash.h"
#include "util-hashlist.h"
#include "util-bloomfilter.h"
#include "util-bloomfilter-counting.h"
#include "util-pool.h"
#include "util-byte.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-sigorder.h"

#include "tm-queuehandlers.h"
#include "tm-queues.h"
#include "tm-modules.h"
#include "tm-threads.h"

#include "tmqh-flow.h"

#include "alert-fastlog.h"
#include "alert-unified-log.h"
#include "alert-unified-alert.h"
#include "alert-unified2-alert.h"
#include "alert-debuglog.h"

#include "log-httplog.h"

#include "stream-tcp.h"

#include "source-nfq.h"
#include "source-nfq-prototypes.h"

#include "source-pcap.h"
#include "source-pcap-file.h"

#include "source-pfring.h"

#include "respond-reject.h"

#include "flow.h"
#include "flow-var.h"
#include "flow-bit.h"
#include "pkt-var.h"

#include "app-layer-detect-proto.h"
#include "app-layer-parser.h"
#include "app-layer-http.h"
#include "app-layer-tls.h"

#include "util-radix-tree.h"
#include "util-cidr.h"
#include "util-unittest.h"
#include "util-time.h"

#include "conf.h"
#include "conf-yaml-loader.h"

#include "runmodes.h"
#include "util-debug.h"

#include "util-debug.h"
#include "util-error.h"

/*
 * we put this here, because we only use it here in main.
 */
volatile sig_atomic_t sigint_count = 0;
volatile sig_atomic_t sighup_count = 0;
volatile sig_atomic_t sigterm_count = 0;

#define EIDPS_SIGINT  0x01
#define EIDPS_SIGHUP  0x02
#define EIDPS_SIGTERM 0x04
#define EIDPS_STOP    0x08
#define EIDPS_KILL    0x10

/* Run mode. */
enum {
    MODE_UNKNOWN = 0,
    MODE_PCAP_DEV,
    MODE_PCAP_FILE,
    MODE_PFRING,
    MODE_NFQ,
    MODE_UNITTEST
};

static uint8_t sigflags = 0;

static void SignalHandlerSigint(/*@unused@*/ int sig) { sigint_count = 1; sigflags |= EIDPS_SIGINT; }
static void SignalHandlerSigterm(/*@unused@*/ int sig) { sigterm_count = 1; sigflags |= EIDPS_SIGTERM; }
static void SignalHandlerSighup(/*@unused@*/ int sig) { sighup_count = 1; sigflags |= EIDPS_SIGHUP; }

static void
SignalHandlerSetup(int sig, void (*handler)())
{
    struct sigaction action;

    action.sa_handler = handler;
    sigemptyset(&(action.sa_mask));
    sigaddset(&(action.sa_mask),sig);
    action.sa_flags = 0;
    sigaction(sig, &action, 0);
}

Packet *SetupPktWait (void)
{
    Packet *p = NULL;
    do {
        mutex_lock(&packet_q.mutex_q);
        p = PacketDequeue(&packet_q);
        mutex_unlock(&packet_q.mutex_q);

        if (p == NULL) {
            //TmqDebugList();
            usleep(1000); /* sleep 1ms */

            /* XXX check for recv'd signals, so
             * we can exit on signals received */
        }
    } while (p == NULL);

    memset(p, 0, sizeof(Packet));

    return p;
}

Packet *SetupPkt (void)
{
    Packet *p = NULL;

    mutex_lock(&packet_q.mutex_q);
    p = PacketDequeue(&packet_q);
    mutex_unlock(&packet_q.mutex_q);

    if (p == NULL) {
        TmqDebugList();

        p = malloc(sizeof(Packet));
        if (p == NULL) {
            printf("ERROR: malloc failed: %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }

        memset(p, 0, sizeof(Packet));

        pthread_mutex_init(&p->mutex_rtv_cnt, NULL);

        SCLogDebug("allocated a new packet...");
    }

    /* reset the packet csum fields */
    RESET_PACKET_CSUMS(p);

    return p;
}

Packet *TunnelPktSetup(ThreadVars *t, DecodeThreadVars *dtv, Packet *parent, uint8_t *pkt, uint16_t len, uint8_t proto)
{
    //printf("TunnelPktSetup: pkt %p, len %" PRIu32 ", proto %" PRIu32 "\n", pkt, len, proto);

    /* get us a packet */
    Packet *p = SetupPkt();
#if 0
    do {
        mutex_lock(&packet_q.mutex_q);
        p = PacketDequeue(&packet_q);
        mutex_unlock(&packet_q.mutex_q);

        if (p == NULL) {
            //TmqDebugList();
            usleep(1000); /* sleep 1ms */

            /* XXX check for recv'd signals, so
             * we can exit on signals received */
        }
    } while (p == NULL);
#endif
    mutex_lock(&mutex_pending);
    pending++;
#ifdef DBG_PERF
    if (pending > dbg_maxpending)
        dbg_maxpending = pending;
#endif /* DBG_PERF */
    mutex_unlock(&mutex_pending);

    /* set the root ptr to the lowest layer */
    if (parent->root != NULL)
        p->root = parent->root;
    else
        p->root = parent;

    /* copy packet and set lenght, proto */
    p->tunnel_proto = proto;
    p->pktlen = len;
    memcpy(&p->pkt, pkt, len);
    p->recursion_level = parent->recursion_level + 1;

    /* set tunnel flags */
    SET_TUNNEL_PKT(p);
    TUNNEL_INCR_PKT_TPR(p);
    return p;
}

/* XXX hack: make sure threads can stop the engine by calling this
   function. Purpose: pcap file mode needs to be able to tell the
   engine the file eof is reached. */
void EngineStop(void) {
    sigflags |= EIDPS_STOP;
}

void EngineKill(void) {
    sigflags |= EIDPS_KILL;
}

void usage(const char *progname)
{
    printf("USAGE: %s\n\n", progname);
    printf("\t-c <path>: path to configuration file\n");
    printf("\t-i <dev> : run in pcap live mode\n");
    printf("\t-r <path>: run in pcap file/offline mode\n");
    printf("\t-q <qid> : run in inline nfqueue mode\n");
    printf("\t-s <path>: path to signature file (optional)\n");
    printf("\t-l <dir> : default log directory\n");
#ifdef UNITTESTS
    printf("\t-u       : run the unittests and exit\n");
#endif /* UNITTESTS */
    printf("\n");
}

int main(int argc, char **argv)
{
    int opt;
    int mode = MODE_UNKNOWN;
    char *pcap_file = NULL;
    char *pcap_dev = NULL;
    char *pfring_dev = NULL;
    char *sig_file = NULL;
    int nfq_id = 0;
    char *conf_filename = NULL;
    int dump_config = 0;

    /* initialize the logging subsys */
    SCLogInitLogModule(NULL);

    /* Initialize the configuration module. */
    ConfInit();

    struct option long_opts[] = {
        {"dump-config", 0, &dump_config, 1},
        {"pfring-int",  required_argument, 0, 0},
        {"pfring-clusterid",  required_argument, 0, 0},
        {NULL, 0, NULL, 0}
    };

    /* getopt_long stores the option index here. */
    int option_index = 0;

    char short_opts[] = "c:hi:l:q:r:us:";

    while ((opt = getopt_long(argc, argv, short_opts, long_opts, &option_index)) != -1) {
        switch (opt) {
        case 0:
            if(strcmp((long_opts[option_index]).name , "pfring-int") == 0){
                mode = MODE_PFRING;
                if (ConfSet("pfring.interface", optarg, 0) != 1) {
                    fprintf(stderr, "ERROR: Failed to set pfring interface.\n");
                    exit(EXIT_FAILURE);
                }
            }
            else if(strcmp((long_opts[option_index]).name , "pfring-clusterid") == 0){
                printf ("clusterid %s\n",optarg);
                if (ConfSet("pfring.clusterid", optarg, 0) != 1) {
                    fprintf(stderr, "ERROR: Failed to set pfring clusterid.\n");
                    exit(EXIT_FAILURE);
                }
            }
            break;
        case 'c':
            conf_filename = optarg;
            break;
        case 'h':
            usage(argv[0]);
            exit(EXIT_SUCCESS);
            break;
        case 'i':
            mode = MODE_PCAP_DEV;
            pcap_dev = optarg;
            break;
        case 'l':
            if (ConfSet("default-log-dir", optarg, 0) != 1) {
                fprintf(stderr, "ERROR: Failed to set log directory.\n");
                exit(EXIT_FAILURE);
            }
            break;
        case 'q':
            mode = MODE_NFQ;
            nfq_id = atoi(optarg); /* strtol? */
            break;
        case 'r':
            mode = MODE_PCAP_FILE;
            pcap_file = optarg;
            break;
        case 's':
            sig_file = optarg;
            break;
        case 'u':
#ifdef UNITTESTS
            mode = MODE_UNITTEST;
#else
            fprintf(stderr, "ERROR: Unit tests not enabled. Make sure to pass --enable-unittests to configure when building.\n");
            exit(EXIT_FAILURE);
#endif /* UNITTESTS */
            break;
        default:
            usage(argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    /* Load yaml configuration file if provided. */
    if (conf_filename != NULL) {
        LoadYamlConf(conf_filename);
    }

    if (dump_config) {
        ConfDump();
        exit(EXIT_SUCCESS);
    }

    if (mode == MODE_UNKNOWN) {
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

    BinSearchInit();
    CIDRInit();
    SigParsePrepare();
    PatternMatchPrepare(mpm_ctx, MPM_B2G);
    PerfInitCounterApi();

    /** \todo we need an api for these */
    AppLayerDetectProtoThreadInit();
    RegisterAppLayerParsers();
    RegisterHTTPParsers();
    RegisterTLSParsers();
    AppLayerParsersInitPostProcess();

    TmModuleReceiveNFQRegister();
    TmModuleVerdictNFQRegister();
    TmModuleDecodeNFQRegister();
    TmModuleReceivePcapRegister();
    TmModuleDecodePcapRegister();
    TmModuleReceivePfringRegister();
    TmModuleDecodePfringRegister();
    TmModuleReceivePcapFileRegister();
    TmModuleDecodePcapFileRegister();
    TmModuleDetectRegister();
    TmModuleAlertFastlogRegister();
    TmModuleAlertDebuglogRegister();
    TmModuleRespondRejectRegister();
    TmModuleAlertFastlogIPv4Register();
    TmModuleAlertFastlogIPv6Register();
    TmModuleAlertUnifiedLogRegister();
    TmModuleAlertUnifiedAlertRegister();
    TmModuleUnified2AlertRegister();
    TmModuleStreamTcpRegister();
    TmModuleLogHttplogRegister();
    TmModuleLogHttplogIPv4Register();
    TmModuleLogHttplogIPv6Register();
    TmModuleDebugList();

#ifdef UNITTESTS
    if (mode == MODE_UNITTEST) {
        /* test and initialize the unittesting subsystem */
        UtRunSelftest(); /* inits and cleans up again */
        UtInitialize();
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
        PerfRegisterTests();
        DecodePPPRegisterTests();
        HTTPParserRegisterTests();
        TLSParserRegisterTests();
        DecodePPPOERegisterTests();
        DecodeICMPV4RegisterTests();
        DecodeICMPV6RegisterTests();
        DecodeIPV4RegisterTests();
        DecodeTCPRegisterTests();
        DecodeUDPV4RegisterTests();
        DecodeGRERegisterTests();
        AlpDetectRegisterTests();
        ConfRegisterTests();
        TmqhFlowRegisterTests();
        FlowRegisterTests();
        SCSigRegisterSignatureOrderingTests();
        SCLogRegisterTests();
        SCRadixRegisterTests();
        uint32_t failed = UtRunTests();
        UtCleanup();
        if (failed) exit(EXIT_FAILURE);
        else        exit(EXIT_SUCCESS);
    }
#endif /* UNITTESTS */

    /* registering signals we use */
    SignalHandlerSetup(SIGINT, SignalHandlerSigint);
    SignalHandlerSetup(SIGTERM, SignalHandlerSigterm);
    SignalHandlerSetup(SIGHUP, SignalHandlerSighup);

    /* initialize packet queues */
    memset(&packet_q,0,sizeof(packet_q));
    memset(&trans_q, 0,sizeof(trans_q));

    /* pre allocate packets */
    SCLogInfo("preallocating packets... packet size %" PRIuMAX "", (uintmax_t)sizeof(Packet));
    int i = 0;
    for (i = 0; i < MAX_PENDING; i++) {
        /* XXX pkt alloc function */
        Packet *p = malloc(sizeof(Packet));
        if (p == NULL) {
            printf("ERROR: malloc failed: %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }
        memset(p, 0, sizeof(Packet));
        pthread_mutex_init(&p->mutex_rtv_cnt, NULL);

        PacketEnqueue(&packet_q,p);
    }
    SCLogInfo("preallocating packets... done: total memory %"PRIuMAX"", (uintmax_t)(MAX_PENDING*sizeof(Packet)));

    FlowInitConfig(FLOW_VERBOSE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();

    /** Create file contexts for output modules */
    /* ascii */
    LogFileCtx *af_logfile_ctx = AlertFastlogInitCtx(NULL);
    LogFileCtx *ad_logfile_ctx = AlertDebuglogInitCtx(NULL);
    LogFileCtx *lh_logfile_ctx = LogHttplogInitCtx(NULL);
    /* unified */
    LogFileCtx *aul_logfile_ctx = AlertUnifiedLogInitCtx(NULL);
    LogFileCtx *aua_logfile_ctx = AlertUnifiedAlertInitCtx(NULL);
    LogFileCtx *au2a_logfile_ctx = Unified2AlertInitCtx(NULL);

    if (SigLoadSignatures(de_ctx, sig_file) < 0) {
        printf("ERROR: loading signatures failed.\n");
        exit(EXIT_FAILURE);
    }

    struct timeval start_time;
    memset(&start_time, 0, sizeof(start_time));
    gettimeofday(&start_time, NULL);

    if (mode == MODE_PCAP_DEV) {
        //RunModeIdsPcap3(de_ctx, pcap_dev, af_logfile_ctx, ad_logfile_ctx, lh_logfile_ctx, aul_logfile_ctx, aua_logfile_ctx, au2a_logfile_ctx);
        RunModeIdsPcap2(de_ctx, pcap_dev, af_logfile_ctx, ad_logfile_ctx, lh_logfile_ctx, aul_logfile_ctx, aua_logfile_ctx, au2a_logfile_ctx);
        //RunModeIdsPcap(de_ctx, pcap_dev, af_logfile_ctx, ad_logfile_ctx, lh_logfile_ctx, aul_logfile_ctx, aua_logfile_ctx, au2a_logfile_ctx);
    }
    else if (mode == MODE_PCAP_FILE) {
        RunModeFilePcap(de_ctx, pcap_file, af_logfile_ctx, ad_logfile_ctx, lh_logfile_ctx, aul_logfile_ctx, aua_logfile_ctx, au2a_logfile_ctx);
        //RunModeFilePcap2(de_ctx, pcap_file, af_logfile_ctx, ad_logfile_ctx, lh_logfile_ctx, aul_logfile_ctx, aua_logfile_ctx, au2a_logfile_ctx);
    }
    else if (mode == MODE_PFRING) {
        //RunModeIdsPfring3(de_ctx, pfring_dev, af_logfile_ctx, ad_logfile_ctx, lh_logfile_ctx, aul_logfile_ctx, aua_logfile_ctx, au2a_logfile_ctx);
        RunModeIdsPfring2(de_ctx, pfring_dev, af_logfile_ctx, ad_logfile_ctx, lh_logfile_ctx, aul_logfile_ctx, aua_logfile_ctx, au2a_logfile_ctx);
        //RunModeIdsPfring(de_ctx, pfring_dev, af_logfile_ctx, ad_logfile_ctx, lh_logfile_ctx, aul_logfile_ctx, aua_logfile_ctx, au2a_logfile_ctx);
    }
    else if (mode == MODE_NFQ) {
        RunModeIpsNFQ(de_ctx, af_logfile_ctx, ad_logfile_ctx, lh_logfile_ctx, aul_logfile_ctx, aua_logfile_ctx, au2a_logfile_ctx);
    }
    else {
        printf("ERROR: Unknown runtime mode.\n");
        exit(EXIT_FAILURE);
    }

    /* Spawn the flow manager thread */
    FlowManagerThreadSpawn();

    StreamTcpInitConfig(STREAM_VERBOSE);

    /* Spawn the L7 App Detect thread */
    //AppLayerDetectProtoThreadSpawn();

    /* Spawn the perf counter threads.  Let these be the last one spawned */
    PerfSpawnThreads();

    /* Check if the alloted queues have at least 1 reader and writer */
    TmValidateQueueState();

    /* Wait till all the threads have been initialized */
    if (TmThreadWaitOnThreadInit() == -1) {
        printf("ERROR: Engine initialization failed, aborting...\n");
        exit(EXIT_FAILURE);
    }

    /* Un-pause all the paused threads */
    TmThreadContinueThreads();

    while(1) {
        if (sigflags) {
            SCLogInfo("signal received");

            if (sigflags & EIDPS_STOP)  {
                SCLogInfo("SIGINT or EngineStop received");

                /* Stop the engine so it quits after processing the pcap file
                 * but first make sure all packets are processed by all other
                 * threads. */
                char done = 0;
                do {
                    if (sigflags & EIDPS_SIGTERM || sigflags & EIDPS_KILL)
                        break;

                    mutex_lock(&mutex_pending);
                    if (pending == 0)
                        done = 1;
                    mutex_unlock(&mutex_pending);

                    if (done == 0) {
                        usleep(100);
                    }
                } while (done == 0);

                SCLogInfo("all packets processed by threads, stopping engine");
            }
            if (sigflags & EIDPS_SIGHUP) {
                SCLogInfo("SIGHUP received");
            }
            if (sigflags & EIDPS_SIGTERM) {
                SCLogInfo("SIGTERM received");
            }

            struct timeval end_time;
            memset(&end_time, 0, sizeof(end_time));
            gettimeofday(&end_time, NULL);

            SCLogInfo("time elapsed %" PRIuMAX "s", (uintmax_t)(end_time.tv_sec - start_time.tv_sec));

            TmThreadKillThreads();
            PerfReleaseResources();
            break;
        }

        TmThreadCheckThreadState();

        usleep(100);
    }

    FlowShutdown();
    FlowPrintQueueInfo();
    StreamTcpFreeConfig(STREAM_VERBOSE);
    HTTPAtExitPrintStats();

    /** \todo review whats needed here */
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    /** Destroy file contexts for output modules */
    LogFileFreeCtx(af_logfile_ctx);
    LogFileFreeCtx(lh_logfile_ctx);
    LogFileFreeCtx(ad_logfile_ctx);
    LogFileFreeCtx(aul_logfile_ctx);
    LogFileFreeCtx(aua_logfile_ctx);
    LogFileFreeCtx(au2a_logfile_ctx);

    exit(EXIT_SUCCESS);
}
