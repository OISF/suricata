/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/signal.h>
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

#include "detect-parse.h"
#include "detect-engine-mpm.h"

#include "tm-queuehandlers.h"
#include "tm-queues.h"
#include "tm-modules.h"
#include "tm-threads.h"

#include "alert-fastlog.h"
#include "alert-unified-log.h"
#include "alert-unified-alert.h"
#include "alert-debuglog.h"

#include "log-httplog.h"

#include "stream-tcp.h"

#include "source-nfq.h"
#include "source-nfq-prototypes.h"

#include "source-pcap.h"
#include "source-pcap-file.h"

#include "respond-reject.h"

#include "flow.h"
#include "flow-var.h"
#include "flow-bit.h"
#include "pkt-var.h"

#include "l7-app-detect.h"

#include "util-cidr.h"
#include "util-unittest.h"
#include "util-time.h"

/*
 * we put this here, because we only use it here in main.
 */
static int sigint_count = 0;
static int sighup_count = 0;
static int sigterm_count = 0;

#define EIDPS_SIGINT  0x01
#define EIDPS_SIGHUP  0x02
#define EIDPS_SIGTERM 0x04
#define EIDPS_STOP    0x08
#define EIDPS_KILL    0x10

/* Run mode. */
enum {
    MODE_PCAP_DEV = 0,
    MODE_PCAP_FILE,
    MODE_NFQ,
    MODE_UNITTEST
};

static u_int8_t sigflags = 0;

static void handle_sigint(/*@unused@*/ int sig) { sigint_count = 1; sigflags |= EIDPS_SIGINT; }
static void handle_sigterm(/*@unused@*/ int sig) { sigterm_count = 1; sigflags |= EIDPS_SIGTERM; }
static void handle_sighup(/*@unused@*/ int sig) { sighup_count = 1; sigflags |= EIDPS_SIGHUP; }

static void
setup_signal_handler(int sig, void (*handler)())
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
            exit(1);
        }

        memset(p, 0, sizeof(Packet));

        printf("SetupPkt: allocated a new packet...\n");
    }

    return p;
}

Packet *TunnelPktSetup(ThreadVars *t, Packet *parent, u_int8_t *pkt, u_int16_t len, u_int8_t proto)
{
    //printf("TunnelPktSetup: pkt %p, len %u, proto %u\n", pkt, len, proto);

    /* get us a packet */
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

int RunModeIdsPcap(char *iface) {
    TimeModeSetLive();

    /* create the threads */
    ThreadVars *tv_receivepcap = TmThreadCreate("ReceivePcap","packetpool","packetpool","pickup-queue","simple","1slot_noinout", NULL, 0);
    if (tv_receivepcap == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(1);
    }
    TmModule *tm_module = TmModuleGetByName("ReceivePcap");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed for ReceivePcap\n");
        exit(1);
    }
    Tm1SlotSetFunc(tv_receivepcap,tm_module,(void *)iface);

    if (TmThreadSpawn(tv_receivepcap, TVT_PPT, THV_USE | THV_PAUSE) != 0) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(1);
    }

    ThreadVars *tv_decode1 = TmThreadCreate("Decode1","pickup-queue","simple","decode-queue1","simple","1slot", NULL, 0);
    if (tv_decode1 == NULL) {
        printf("ERROR: TmThreadsCreate failed for Decode1\n");
        exit(1);
    }
    tm_module = TmModuleGetByName("DecodePcap");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName DecodePcap failed\n");
        exit(1);
    }
    Tm1SlotSetFunc(tv_decode1,tm_module,NULL);

    if (TmThreadSpawn(tv_decode1, TVT_PPT, THV_USE | THV_PAUSE) != 0) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(1);
    }

    ThreadVars *tv_stream1 = TmThreadCreate("Stream1","decode-queue1","simple","stream-queue1","simple","1slot", NULL, 0);
    if (tv_stream1 == NULL) {
        printf("ERROR: TmThreadsCreate failed for Stream1\n");
        exit(1);
    }
    tm_module = TmModuleGetByName("StreamTcp");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName StreamTcp failed\n");
        exit(1);
    }
    Tm1SlotSetFunc(tv_stream1,tm_module,NULL);

    if (TmThreadSpawn(tv_stream1, TVT_PPT, THV_USE | THV_PAUSE) != 0) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(1);
    }

    ThreadVars *tv_detect1 = TmThreadCreate("Detect1","stream-queue1","simple","verdict-queue","simple","1slot", NULL, 0);
    if (tv_detect1 == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(1);
    }
    tm_module = TmModuleGetByName("Detect");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName Detect failed\n");
        exit(1);
    }
    Tm1SlotSetFunc(tv_detect1,tm_module,(void *)g_de_ctx);

    if (TmThreadSpawn(tv_detect1, TVT_PPT, THV_USE | THV_PAUSE) != 0) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(1);
    }

    ThreadVars *tv_detect2 = TmThreadCreate("Detect2","stream-queue1","simple","verdict-queue","simple","1slot", NULL, 0);
    if (tv_detect2 == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(1);
    }
    tm_module = TmModuleGetByName("Detect");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName Detect failed\n");
        exit(1);
    }
    Tm1SlotSetFunc(tv_detect2,tm_module,(void *)g_de_ctx);

    if (TmThreadSpawn(tv_detect2, TVT_PPT, THV_USE | THV_PAUSE) != 0) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(1);
    }

    ThreadVars *tv_rreject = TmThreadCreate("RespondReject","verdict-queue","simple","alert-queue1","simple","1slot", NULL, 0);
    if (tv_rreject == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(1);
    }
    tm_module = TmModuleGetByName("RespondReject");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for RespondReject failed\n");
        exit(1);
    }
    Tm1SlotSetFunc(tv_rreject,tm_module,NULL);

    if (TmThreadSpawn(tv_rreject, TVT_PPT, THV_USE | THV_PAUSE) != 0) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(1);
    }

    ThreadVars *tv_alert = TmThreadCreate("AlertFastlog&Httplog","alert-queue1","simple","alert-queue2","simple","2slot", NULL, 0);
    if (tv_alert == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(1);
    }
    tm_module = TmModuleGetByName("AlertFastlog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for AlertFastlog failed\n");
        exit(1);
    }
    Tm2SlotSetFunc1(tv_alert,tm_module,NULL);

    tm_module = TmModuleGetByName("LogHttplog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed\n");
        exit(1);
    }
    Tm2SlotSetFunc2(tv_alert,tm_module,NULL);

    if (TmThreadSpawn(tv_alert, TVT_PPT, THV_USE | THV_PAUSE) != 0) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(1);
    }

    ThreadVars *tv_unified = TmThreadCreate("AlertUnifiedLog","alert-queue2","simple","alert-queue3","simple","2slot", NULL, 0);
    if (tv_unified == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(1);
    }

    tm_module = TmModuleGetByName("AlertUnifiedLog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for AlertUnifiedLog failed\n");
        exit(1);
    }
    Tm2SlotSetFunc1(tv_unified,tm_module,NULL);

    tm_module = TmModuleGetByName("AlertUnifiedAlert");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for AlertUnifiedAlert failed\n");
        exit(1);
    }
    Tm2SlotSetFunc2(tv_unified,tm_module,NULL);

    if (TmThreadSpawn(tv_unified, TVT_PPT, THV_USE | THV_PAUSE) != 0) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(1);
    }

    ThreadVars *tv_debugalert = TmThreadCreate("AlertDebuglog","alert-queue3","simple","packetpool","packetpool","1slot", NULL, 0);
    if (tv_debugalert == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(1);
    }
    tm_module = TmModuleGetByName("AlertDebuglog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed\n");
        exit(1);
    }
    Tm1SlotSetFunc(tv_debugalert,tm_module,NULL);

    if (TmThreadSpawn(tv_debugalert, TVT_PPT, THV_USE | THV_PAUSE) != 0) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(1);
    }

    return 0;
}

int RunModeIpsNFQ(void) {
    TimeModeSetLive();

    /* create the threads */
    ThreadVars *tv_receivenfq = TmThreadCreate("ReceiveNFQ","packetpool","packetpool","pickup-queue","simple","1slot_noinout", NULL, 0);
    if (tv_receivenfq == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(1);
    }
    TmModule *tm_module = TmModuleGetByName("ReceiveNFQ");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed for ReceiveNFQ\n");
        exit(1);
    }
    Tm1SlotSetFunc(tv_receivenfq,tm_module,NULL);

    if (TmThreadSpawn(tv_receivenfq, TVT_PPT, THV_USE | THV_PAUSE) != 0) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(1);
    }

    ThreadVars *tv_decode1 = TmThreadCreate("Decode1","pickup-queue","simple","decode-queue1","simple","1slot", NULL, 0);
    if (tv_decode1 == NULL) {
        printf("ERROR: TmThreadsCreate failed for Decode1\n");
        exit(1);
    }
    tm_module = TmModuleGetByName("DecodeNFQ");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName DecodeNFQ failed\n");
        exit(1);
    }
    Tm1SlotSetFunc(tv_decode1,tm_module,NULL);

    if (TmThreadSpawn(tv_decode1, TVT_PPT, THV_USE | THV_PAUSE) != 0) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(1);
    }

    ThreadVars *tv_stream1 = TmThreadCreate("Stream1","decode-queue1","simple","stream-queue1","simple","1slot", NULL, 0);
    if (tv_stream1 == NULL) {
        printf("ERROR: TmThreadsCreate failed for Stream1\n");
        exit(1);
    }
    tm_module = TmModuleGetByName("StreamTcp");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName StreamTcp failed\n");
        exit(1);
    }
    Tm1SlotSetFunc(tv_stream1,tm_module,NULL);

    if (TmThreadSpawn(tv_stream1, TVT_PPT, THV_USE | THV_PAUSE) != 0) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(1);
    }

    ThreadVars *tv_detect1 = TmThreadCreate("Detect1","stream-queue1","simple","verdict-queue","simple","1slot", NULL, 0);
    if (tv_detect1 == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(1);
    }
    tm_module = TmModuleGetByName("Detect");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName Detect failed\n");
        exit(1);
    }
    Tm1SlotSetFunc(tv_detect1,tm_module,(void *)g_de_ctx);

    if (TmThreadSpawn(tv_detect1, TVT_PPT, THV_USE | THV_PAUSE) != 0) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(1);
    }

    ThreadVars *tv_detect2 = TmThreadCreate("Detect2","stream-queue1","simple","verdict-queue","simple","1slot", NULL, 0);
    if (tv_detect2 == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(1);
    }
    tm_module = TmModuleGetByName("Detect");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName Detect failed\n");
        exit(1);
    }
    Tm1SlotSetFunc(tv_detect2,tm_module,(void *)g_de_ctx);

    if (TmThreadSpawn(tv_detect2, TVT_PPT, THV_USE | THV_PAUSE) != 0) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(1);
    }

    ThreadVars *tv_verdict = TmThreadCreate("Verdict","verdict-queue","simple","respond-queue","simple","1slot", NULL, 0);
    if (tv_verdict == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(1);
    }
    tm_module = TmModuleGetByName("VerdictNFQ");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName VerdictNFQ failed\n");
        exit(1);
    }
    Tm1SlotSetFunc(tv_verdict,tm_module,NULL);

    if (TmThreadSpawn(tv_verdict, TVT_PPT, THV_USE | THV_PAUSE) != 0) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(1);
    }

    ThreadVars *tv_rreject = TmThreadCreate("RespondReject","respond-queue","simple","alert-queue1","simple","1slot", NULL, 0);
    if (tv_rreject == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(1);
    }
    tm_module = TmModuleGetByName("RespondReject");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for RespondReject failed\n");
        exit(1);
    }
    Tm1SlotSetFunc(tv_rreject,tm_module,NULL);

    if (TmThreadSpawn(tv_rreject, TVT_PPT, THV_USE | THV_PAUSE) != 0) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(1);
    }

    ThreadVars *tv_alert = TmThreadCreate("AlertFastlog&Httplog","alert-queue1","simple","alert-queue2","simple","2slot", NULL, 0);
    if (tv_alert == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(1);
    }
    tm_module = TmModuleGetByName("AlertFastlog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for AlertFastlog failed\n");
        exit(1);
    }
    Tm2SlotSetFunc1(tv_alert,tm_module,NULL);

    tm_module = TmModuleGetByName("LogHttplog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed\n");
        exit(1);
    }
    Tm2SlotSetFunc2(tv_alert,tm_module,NULL);

    if (TmThreadSpawn(tv_alert, TVT_PPT, THV_USE | THV_PAUSE) != 0) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(1);
    }

    ThreadVars *tv_unified = TmThreadCreate("AlertUnifiedLog","alert-queue2","simple","alert-queue3","simple","2slot", NULL, 0);
    if (tv_unified == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(1);
    }

    tm_module = TmModuleGetByName("AlertUnifiedLog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for AlertUnifiedLog failed\n");
        exit(1);
    }
    Tm2SlotSetFunc1(tv_unified,tm_module,NULL);

    tm_module = TmModuleGetByName("AlertUnifiedAlert");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for AlertUnifiedAlert failed\n");
        exit(1);
    }
    Tm2SlotSetFunc2(tv_unified,tm_module,NULL);

    if (TmThreadSpawn(tv_unified, TVT_PPT, THV_USE | THV_PAUSE) != 0) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(1);
    }

    ThreadVars *tv_debugalert = TmThreadCreate("AlertDebuglog","alert-queue3","simple","packetpool","packetpool","1slot", NULL, 0);
    if (tv_debugalert == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(1);
    }
    tm_module = TmModuleGetByName("AlertDebuglog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed\n");
        exit(1);
    }
    Tm1SlotSetFunc(tv_debugalert,tm_module,NULL);

    if (TmThreadSpawn(tv_debugalert, TVT_PPT, THV_USE | THV_PAUSE) != 0) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(1);
    }

    return 0;
}

int RunModeFilePcap(char *file) {
    printf("RunModeFilePcap: file %s\n", file);
    TimeModeSetOffline();

    /* create the threads */
    ThreadVars *tv_receivepcap = TmThreadCreate("ReceivePcapFile","packetpool","packetpool","pickup-queue","simple","1slot", NULL, 0);
    if (tv_receivepcap == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(1);
    }
    TmModule *tm_module = TmModuleGetByName("ReceivePcapFile");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed for ReceivePcap\n");
        exit(1);
    }
    Tm1SlotSetFunc(tv_receivepcap,tm_module,file);

    if (TmThreadSpawn(tv_receivepcap, TVT_PPT, THV_USE | THV_PAUSE) != 0) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(1);
    }

    ThreadVars *tv_decode1 = TmThreadCreate("Decode1","pickup-queue","simple","decode-queue1","simple","1slot", NULL, 0);
    if (tv_decode1 == NULL) {
        printf("ERROR: TmThreadsCreate failed for Decode1\n");
        exit(1);
    }
    tm_module = TmModuleGetByName("DecodePcapFile");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName DecodePcap failed\n");
        exit(1);
    }
    Tm1SlotSetFunc(tv_decode1,tm_module,NULL);

    if (TmThreadSpawn(tv_decode1, TVT_PPT, THV_USE | THV_PAUSE) != 0) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(1);
    }
//#if 0
    ThreadVars *tv_stream1 = TmThreadCreate("Stream1","decode-queue1","simple","stream-queue1","simple","1slot", NULL, 0);
    if (tv_stream1 == NULL) {
        printf("ERROR: TmThreadsCreate failed for Stream1\n");
        exit(1);
    }
    tm_module = TmModuleGetByName("StreamTcp");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName StreamTcp failed\n");
        exit(1);
    }
    Tm1SlotSetFunc(tv_stream1,tm_module,NULL);

    if (TmThreadSpawn(tv_stream1, TVT_PPT, THV_USE | THV_PAUSE) != 0) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(1);
    }

    ThreadVars *tv_detect1 = TmThreadCreate("Detect1","stream-queue1","simple","alert-queue1","simple","1slot", NULL, 0);
//#endif
    //ThreadVars *tv_detect1 = TmThreadCreate("Detect1","decode-queue1","simple","alert-queue1","simple","1slot");
    if (tv_detect1 == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(1);
    }
    tm_module = TmModuleGetByName("Detect");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName Detect failed\n");
        exit(1);
    }
    Tm1SlotSetFunc(tv_detect1,tm_module,(void *)g_de_ctx);

    if (TmThreadSpawn(tv_detect1, TVT_PPT, THV_USE | THV_PAUSE) != 0) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(1);
    }

    ThreadVars *tv_detect2 = TmThreadCreate("Detect2","stream-queue1","simple","alert-queue1","simple","1slot", NULL, 0);
    if (tv_detect2 == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(1);
    }
    tm_module = TmModuleGetByName("Detect");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName Detect failed\n");
        exit(1);
    }
    Tm1SlotSetFunc(tv_detect2,tm_module,(void *)g_de_ctx);

    if (TmThreadSpawn(tv_detect2, TVT_PPT, THV_USE | THV_PAUSE) != 0) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(1);
    }

    ThreadVars *tv_alert = TmThreadCreate("AlertFastlog&Httplog","alert-queue1","simple","alert-queue2","simple","2slot", NULL, 0);
    if (tv_alert == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(1);
    }
    tm_module = TmModuleGetByName("AlertFastlog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for AlertFastlog failed\n");
        exit(1);
    }
    Tm2SlotSetFunc1(tv_alert,tm_module,NULL);

    tm_module = TmModuleGetByName("LogHttplog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed\n");
        exit(1);
    }
    Tm2SlotSetFunc2(tv_alert,tm_module,NULL);

    if (TmThreadSpawn(tv_alert, TVT_PPT, THV_USE | THV_PAUSE) != 0) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(1);
    }

    ThreadVars *tv_unified = TmThreadCreate("AlertUnifiedLog","alert-queue2","simple","alert-queue3","simple","2slot", NULL, 0);
    if (tv_unified == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(1);
    }

    tm_module = TmModuleGetByName("AlertUnifiedLog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for AlertUnifiedLog failed\n");
        exit(1);
    }
    Tm2SlotSetFunc1(tv_unified,tm_module,NULL);

    tm_module = TmModuleGetByName("AlertUnifiedAlert");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for AlertUnifiedAlert failed\n");
        exit(1);
    }
    Tm2SlotSetFunc2(tv_unified,tm_module,NULL);

    if (TmThreadSpawn(tv_unified, TVT_PPT, THV_USE | THV_PAUSE) != 0) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(1);
    }

    ThreadVars *tv_debugalert = TmThreadCreate("AlertDebuglog","alert-queue3","simple","packetpool","packetpool","1slot", NULL, 0);
    if (tv_debugalert == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(1);
    }
    tm_module = TmModuleGetByName("AlertDebuglog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed\n");
        exit(1);
    }
    Tm1SlotSetFunc(tv_debugalert,tm_module,NULL);

    if (TmThreadSpawn(tv_debugalert, TVT_PPT, THV_USE | THV_PAUSE) != 0) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(1);
    }
    return 0;
}

/**
 * \brief Single thread version of the Pcap file processing.
 */
int RunModeFilePcap2(char *file) {
    printf("RunModeFilePcap2: file %s\n", file);
    TimeModeSetOffline();

    /* create the threads */
    ThreadVars *tv = TmThreadCreate("PcapFile","packetpool","packetpool","packetpool","packetpool","varslot", NULL, 0);
    if (tv == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(1);
    }

    TmModule *tm_module = TmModuleGetByName("ReceivePcapFile");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed for ReceivePcap\n");
        exit(1);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,file);

    tm_module = TmModuleGetByName("DecodePcapFile");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName DecodePcap failed\n");
        exit(1);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,NULL);

    tm_module = TmModuleGetByName("StreamTcp");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName StreamTcp failed\n");
        exit(1);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,NULL);

    tm_module = TmModuleGetByName("Detect");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName Detect failed\n");
        exit(1);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,(void *)g_de_ctx);

    tm_module = TmModuleGetByName("AlertFastlog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for AlertFastlog failed\n");
        exit(1);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,NULL);

    tm_module = TmModuleGetByName("LogHttplog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed\n");
        exit(1);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,NULL);

    tm_module = TmModuleGetByName("AlertUnifiedLog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for AlertUnifiedLog failed\n");
        exit(1);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,NULL);

    tm_module = TmModuleGetByName("AlertUnifiedAlert");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for AlertUnifiedAlert failed\n");
        exit(1);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,NULL);

    tm_module = TmModuleGetByName("AlertDebuglog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed\n");
        exit(1);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,NULL);

    if (TmThreadSpawn(tv, TVT_PPT, THV_USE | THV_PAUSE) != 0) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(1);
    }

    return 0;
}

int main(int argc, char **argv)
{
    sigset_t set;
    int opt;
    int mode;
    char *pcap_file;
    char *pcap_dev;
    int nfq_id;

    sigaddset(&set, SIGINT); 
    /* registering signals we use */
    setup_signal_handler(SIGINT, handle_sigint);
    setup_signal_handler(SIGTERM, handle_sigterm);
    setup_signal_handler(SIGHUP, handle_sighup);
    //pthread_sigmask(SIG_BLOCK, &set, 0);

    while ((opt = getopt(argc, argv, "i:q:r:u")) != -1) {
        switch (opt) {
        case 'i':
            mode = MODE_PCAP_DEV;
            pcap_dev = optarg;
            break;
        case 'q':
            mode = MODE_NFQ;
            nfq_id = atoi(optarg); /* strtol? */
            break;
        case 'r':
            mode = MODE_PCAP_FILE;
            pcap_file = optarg;
            break;
        case 'u':
#ifdef UNITTESTS
            mode = MODE_UNITTEST;
#else
            fprintf(stderr, "ERROR: Unit tests not enabled.\n");
            exit(1);
#endif /* UNITTESTS */
            break;
        default:
            printf("USAGE: todo\n");
            exit(1);
        }
    }

    /* create table for O(1) lowercase conversion lookup */
    u_int8_t c = 0;
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
    PatternMatchPrepare(mpm_ctx);
    PerfInitCounterApi();

    /* XXX we need an api for this */
    L7AppDetectThreadInit();

    TmModuleReceiveNFQRegister();
    TmModuleVerdictNFQRegister();
    TmModuleDecodeNFQRegister();
    TmModuleReceivePcapRegister();
    TmModuleDecodePcapRegister();
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
    TmModuleLogHttplogRegister();
    TmModuleLogHttplogIPv4Register();
    TmModuleLogHttplogIPv6Register();
    TmModuleStreamTcpRegister();
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
        MpmRegisterTests();
        FlowBitRegisterTests();
        SigRegisterTests();
        PerfRegisterTests();
        DecodePPPRegisterTests();
        UtRunTests();
        UtCleanup();
        exit(0);
    }
#endif /* UNITTESTS */

    //LoadConfig();
    //exit(1);

    /* initialize packet queues */
    memset(&packet_q,0,sizeof(packet_q));
    memset(&trans_q, 0,sizeof(trans_q));

    /* pre allocate packets */
    printf("Preallocating packets... packet size %u\n", sizeof(Packet));
    int i = 0;
    for (i = 0; i < MAX_PENDING; i++) {
        /* XXX pkt alloc function */
        Packet *p = malloc(sizeof(Packet));
        if (p == NULL) {
            printf("ERROR: malloc failed: %s\n", strerror(errno));
            exit(1);
        }
        memset(p, 0, sizeof(Packet));

        PacketEnqueue(&packet_q,p);
    }
    printf("Preallocating packets... done\n");

    FlowInitConfig(FLOW_VERBOSE);

    SigLoadSignatures();

    struct timeval start_time;
    memset(&start_time, 0, sizeof(start_time));
    gettimeofday(&start_time, NULL);

    if (mode == MODE_PCAP_DEV) {
        RunModeIdsPcap(pcap_dev);
    }
    else if (mode == MODE_PCAP_FILE) {
        RunModeFilePcap(pcap_file);
        //RunModeFilePcap2(pcap_file);
    }
    else if (mode == MODE_NFQ) {
        RunModeIpsNFQ();
    }
    else {
        printf("ERROR: Unknown runtime mode.\n");
        exit(1);
    }

    /* Spawn the flow manager thread */
    FlowManagerThreadSpawn();

    /* Spawn the L7 App Detect thread */
    L7AppDetectThreadSpawn();

    /* Spawn the perf counter threads */
    PerfSpawnThreads();

    /* Un-pause all the paused threads */
    TmThreadContinueThreads();

    while(1) {
        if (sigflags) {
            printf("signal received\n");

            if (sigflags & EIDPS_STOP)  {
                printf ("SIGINT or EngineStop received\n");

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

                printf("main: all packets processed by threads, stopping engine\n");
            }
            if (sigflags & EIDPS_SIGHUP)  printf ("SIGHUP\n");
            if (sigflags & EIDPS_SIGTERM) printf ("SIGTERM\n");

            struct timeval end_time;
            memset(&end_time, 0, sizeof(end_time));
            gettimeofday(&end_time, NULL);

            printf("time elapsed %lus\n", end_time.tv_sec - start_time.tv_sec);

            TmThreadKillThreads();

            PerfReleaseResources();
#if 0
#ifdef DBG_PERF
            printf("th_v[0].nfq_t->dbg_maxreadsize %d\n", th_v[0].nfq_t->dbg_maxreadsize);
            //printf("th_v[1].nfq_t->dbg_maxreadsize %d\n", th_v[1].nfq_t->dbg_maxreadsize);
#endif /* DBG_PERF */
            printf("NFQ Stats 0: pkts %u, errs %u\n", th_v[0].nfq_t->pkts, th_v[0].nfq_t->errs);
            //printf("NFQ Stats 1: pkts %u, errs %u\n", th_v[1].nfq_t->pkts, th_v[1].nfq_t->errs);
            PatternMatcherThreadInfo(&th_v[3]);
            PatternMatcherThreadInfo(&th_v[4]);
#ifdef DBG_PERF
            printf("trans_q[0].dbg_maxlen %u\n", trans_q[0].dbg_maxlen);
            printf("trans_q[1].dbg_maxlen %u\n", trans_q[1].dbg_maxlen);
            printf("trans_q[2].dbg_maxlen %u\n", trans_q[2].dbg_maxlen);
            printf("trans_q[3].dbg_maxlen %u\n", trans_q[3].dbg_maxlen);
            printf("trans_q[4].dbg_maxlen %u\n", trans_q[4].dbg_maxlen);

            printf("dbg_maxpending %u\n", dbg_maxpending);
#endif /* DBG_PERF */
#endif
            break;//pthread_exit(NULL);
        }

        usleep(100);
    }

    FlowShutdown();
    FlowPrintFlows();

    SigGroupCleanup();
    SigCleanSignatures();

    pthread_exit(NULL);
}
