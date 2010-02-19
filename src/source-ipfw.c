/* Copyright (c) 2009 Open Information Security Foundation */

/** \file
 *  \author Nick Rogness <nick@rogness.net>
 */

#include "suricata-common.h"
#include "suricata.h"
#include "decode.h"
#include "packet-queue.h"
#include "threads.h"
#include "threadvars.h"
#include "tm-queuehandlers.h"
#include "tm-modules.h"
#include "tm-threads.h"
#include "source-ipfw.h"
#include "util-debug.h"
#include "conf.h"

#define IPFW_ACCEPT 0
#define IPFW_DROP 1

#define IPFW_SOCKET_POLL_MSEC 300

#ifndef IP_MAXPACKET
#define IP_MAXPACKET 65535
#endif

#ifndef IPFW
/* Handle the case if --enable-ipfw was not used
 *
 */

TmEcode NoIPFWSupportExit(ThreadVars *, void *, void **);

void TmModuleReceiveIPFWRegister (void) {
    tmm_modules[TMM_RECEIVEIPFW].name = "ReceiveIPFW";
    tmm_modules[TMM_RECEIVEIPFW].ThreadInit = NoIPFWSupportExit;
    tmm_modules[TMM_RECEIVEIPFW].Func = NULL;
    tmm_modules[TMM_RECEIVEIPFW].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_RECEIVEIPFW].ThreadDeinit = NULL;
    tmm_modules[TMM_RECEIVEIPFW].RegisterTests = NULL;
}

void TmModuleVerdictIPFWRegister (void) {
    tmm_modules[TMM_VERDICTIPFW].name = "VerdictIPFW";
    tmm_modules[TMM_VERDICTIPFW].ThreadInit = NoIPFWSupportExit;
    tmm_modules[TMM_VERDICTIPFW].Func = NULL;
    tmm_modules[TMM_VERDICTIPFW].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_VERDICTIPFW].ThreadDeinit = NULL;
    tmm_modules[TMM_VERDICTIPFW].RegisterTests = NULL;
}

void TmModuleDecodeIPFWRegister (void) {
    tmm_modules[TMM_DECODEIPFW].name = "DecodeIPFW";
    tmm_modules[TMM_DECODEIPFW].ThreadInit = NoIPFWSupportExit;
    tmm_modules[TMM_DECODEIPFW].Func = NULL;
    tmm_modules[TMM_DECODEIPFW].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODEIPFW].ThreadDeinit = NULL;
    tmm_modules[TMM_DECODEIPFW].RegisterTests = NULL;
}

TmEcode NoIPFWSupportExit(ThreadVars *tv, void *initdata, void **data) {

    SCLogError(SC_ERR_IPFW_NOSUPPORT,"Error creating thread %s: you do not have support for ipfw "
           "enabled please recompile with --enable-ipfw", tv->name);
    exit(EXIT_FAILURE);
}

#else /* We have IPFW compiled in */

extern int max_pending_packets;

/**
 * \brief Structure to hold thread specific variables.
 */
typedef struct IPFWThreadVars_
{

    /* data link type for the thread, probably not needed */
    int datalink;

    /* counters */
    uint32_t pkts;
    uint64_t bytes;
    uint32_t errs;
    uint32_t accepted;
    uint32_t dropped;

} IPFWThreadVars;

/* Global socket handler for the divert socket */
struct sockaddr_in ipfw_sin;
socklen_t ipfw_sinlen;
int ipfw_sock;
static SCMutex ipfw_socket_lock;

/* IPFW Prototypes */
TmEcode ReceiveIPFWThreadInit(ThreadVars *, void *, void **);
TmEcode ReceiveIPFW(ThreadVars *, Packet *, void *, PacketQueue *);
void ReceiveIPFWThreadExitStats(ThreadVars *, void *);
TmEcode ReceiveIPFWThreadDeinit(ThreadVars *, void *);

TmEcode IPFWSetVerdict(ThreadVars *, IPFWThreadVars *, Packet *);
TmEcode VerdictIPFW(ThreadVars *, Packet *, void *, PacketQueue *);
TmEcode VerdictIPFWThreadInit(ThreadVars *, void *, void **);
void VerdictIPFWThreadExitStats(ThreadVars *, void *);
TmEcode VerdictIPFWThreadDeinit(ThreadVars *, void *);

TmEcode DecodeIPFWThreadInit(ThreadVars *, void *, void **);
TmEcode DecodeIPFW(ThreadVars *, Packet *, void *, PacketQueue *);

/**
 * \brief Registration Function for RecieveIPFW.
 * \todo Unit tests are needed for this module.
 */
void TmModuleReceiveIPFWRegister (void) {
    tmm_modules[TMM_RECEIVEIPFW].name = "ReceiveIPFW";
    tmm_modules[TMM_RECEIVEIPFW].ThreadInit = ReceiveIPFWThreadInit;
    tmm_modules[TMM_RECEIVEIPFW].Func = ReceiveIPFW;
    tmm_modules[TMM_RECEIVEIPFW].ThreadExitPrintStats = ReceiveIPFWThreadExitStats;
    tmm_modules[TMM_RECEIVEIPFW].ThreadDeinit = ReceiveIPFWThreadDeinit;
    tmm_modules[TMM_RECEIVEIPFW].RegisterTests = NULL;
}

/**
 * \brief Registration Function for VerdictIPFW.
 * \todo Unit tests are needed for this module.
 */
void TmModuleVerdictIPFWRegister (void) {
    tmm_modules[TMM_VERDICTIPFW].name = "VerdictIPFW";
    tmm_modules[TMM_VERDICTIPFW].ThreadInit = VerdictIPFWThreadInit;
    tmm_modules[TMM_VERDICTIPFW].Func = VerdictIPFW;
    tmm_modules[TMM_VERDICTIPFW].ThreadExitPrintStats = VerdictIPFWThreadExitStats;
    tmm_modules[TMM_VERDICTIPFW].ThreadDeinit = VerdictIPFWThreadDeinit;
    tmm_modules[TMM_VERDICTIPFW].RegisterTests = NULL;
}

/**
 * \brief Registration Function for DecodeIPFW.
 * \todo Unit tests are needed for this module.
 */
void TmModuleDecodeIPFWRegister (void) {
    tmm_modules[TMM_DECODEIPFW].name = "DecodeIPFW";
    tmm_modules[TMM_DECODEIPFW].ThreadInit = DecodeIPFWThreadInit;
    tmm_modules[TMM_DECODEIPFW].Func = DecodeIPFW;
    tmm_modules[TMM_DECODEIPFW].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODEIPFW].ThreadDeinit = NULL;
    tmm_modules[TMM_DECODEIPFW].RegisterTests = NULL;
}

/**
 * \brief Recieves packets from an interface via ipfw divert socket.
 * \todo Unit tests are needed for this module.
 *
 *  This function recieves packets from an ipfw divert socket and passes
 *  the packet on to the queue
 *
 * \param tv pointer to ThreadVars
 * \param p pointer to Packet
 * \param data pointer that gets cast into IPFWThreadVars for ptv
 * \param pq pointer to the PacketQueue (not used here but part of the api)
 * \retval TM_ECODE_FAILED on failure and TM_ECODE_OK on success
 */
TmEcode ReceiveIPFW(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq) {
    IPFWThreadVars *ptv = (IPFWThreadVars *)data;
    char pkt[IP_MAXPACKET];
    int pktlen=0;
    int r = 0;
    struct pollfd IPFWpoll;
    struct timeval IPFWts;
    SCEnter();

    //printf("Entering RecieveIPFW\n");

    IPFWpoll.fd=ipfw_sock;
    IPFWpoll.events= POLLRDNORM;

    /* Read packets from divert socket */
    while (r == 0) {

       /* Did we receive a signal to shutdown */
        if ( TmThreadsCheckFlag(tv, THV_KILL) || TmThreadsCheckFlag(tv, THV_PAUSE)) {
            SCLogInfo("Received ThreadShutdown: IPFW divert socket polling interrupted");
            SCReturnInt(TM_ECODE_OK);
        }

        /* Poll the socket for status */
        if ( (poll(&IPFWpoll,1,IPFW_SOCKET_POLL_MSEC)) > 0) {
            if ( IPFWpoll.revents & (POLLRDNORM | POLLERR) )
		r++;
        }

    } /* end while */

    SCMutexLock(&ipfw_socket_lock);
    if ((pktlen = recvfrom(ipfw_sock, pkt, sizeof(pkt), 0,(struct sockaddr *)&ipfw_sin, &ipfw_sinlen)) == -1) {

        /* We received an error on socket read */
        if (errno == EINTR || errno == EWOULDBLOCK) {
            /* Nothing for us to process */
            SCMutexUnlock(&ipfw_socket_lock);
            SCReturnInt(TM_ECODE_OK);

        } else {
            SCLogWarning(SC_WARN_IPFW_RECV,"Read from IPFW divert socket failed: %s",strerror(errno));
            SCMutexUnlock(&ipfw_socket_lock);
            SCReturnInt(TM_ECODE_FAILED);
        }

    } else {
        /* We have a packet to process */
        memset (&IPFWts, 0, sizeof(struct timeval));
        gettimeofday(&IPFWts, NULL);
        r++;
    }

    SCMutexUnlock(&ipfw_socket_lock);

    SCLogDebug("Received Packet Len: %d",pktlen);

    /* Is the packet queue full, wait if so */
    SCMutexLock(&mutex_pending);
    if (pending > max_pending_packets) {
        pthread_cond_wait(&cond_pending, &mutex_pending);
    }
    SCMutexUnlock(&mutex_pending);

    /* Setup packet */
    p = tv->tmqh_in(tv);

    p->ts.tv_sec = IPFWts.tv_sec;
    p->ts.tv_usec = IPFWts.tv_usec;

    ptv->pkts++;
    ptv->bytes += pktlen;

    p->datalink = ptv->datalink;
    p->pktlen = pktlen;
    memcpy(p->pkt, pkt, p->pktlen);
    SCLogDebug("Packet info: p->pktlen: %" PRIu32 " (pkt %02x, p->pkt %02x)", p->pktlen, *pkt, *p->pkt);

    /* pass on... */
    tv->tmqh_out(tv, p);

    SCReturnInt(TM_ECODE_OK);

}

/**
 * \brief Init function for RecieveIPFW.
 *
 * This is a setup function for recieving packets
 * via ipfw divert, binds a socket, and prepares to
 * to read from it.
 *
 * \param tv pointer to ThreadVars
 * \param initdata pointer to the divert port passed from the user
 * \param data pointer gets populated with IPFWThreadVars
 *
 */
TmEcode ReceiveIPFWThreadInit(ThreadVars *tv, void *initdata, void **data) {

    struct timeval timev;

    uint16_t divert_port=0;
    char *tmpdivertport;

    sigset_t sigs;
    sigfillset(&sigs);
    pthread_sigmask(SIG_UNBLOCK, &sigs, NULL);

    SCEnter();

    /* divert socket port to listen/send on */
    if ( (ConfGet("ipfw-divert-port", &tmpdivertport)) != 1 ) {
        SCLogError(SC_ERR_IPFW_NOPORT,"Please supply an IPFW divert port");
        SCReturnInt(TM_ECODE_FAILED);

    } else {

	if (atoi(tmpdivertport) > 0 && atoi(tmpdivertport) <= 65535) {
            divert_port = (uint16_t)atoi(tmpdivertport);
            SCLogInfo("Using IPFW divert port %u",divert_port);

        } else {
            SCLogError(SC_ERR_IPFW_BIND,"Divert port: %s is invalid",tmpdivertport);
            SCReturnInt(TM_ECODE_FAILED);
        }
    }

    /* Setup Threadvars */
    IPFWThreadVars *ptv = SCMalloc(sizeof(IPFWThreadVars));
    if (ptv == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC,"Error Allocating memory for IPFW Receive PTV: %s",strerror(errno));
        SCReturnInt(TM_ECODE_FAILED);
    }
    memset(ptv, 0, sizeof(IPFWThreadVars));

    SCMutexInit(&ipfw_socket_lock, NULL);
    /* We need a divert socket to play with */
    if ((ipfw_sock = socket(PF_INET, SOCK_RAW, IPPROTO_DIVERT)) == -1) {
        SCLogError(SC_ERR_IPFW_SOCK,"Can't create divert socket: %s", strerror(errno));
        SCReturnInt(TM_ECODE_FAILED);
    }

    /* set a timeout to the socket so we can check for a signal
     * in case we don't get packets for a longer period. */
    timev.tv_sec = 1;
    timev.tv_usec = 0;

    if(setsockopt(ipfw_sock, SOL_SOCKET, SO_RCVTIMEO, &timev, sizeof(timev)) == -1) {
        SCLogWarning(SC_WARN_IPFW_SETSOCKOPT,"Can't set IPFW divert socket timeout: %s", strerror(errno));
        SCReturnInt(TM_ECODE_FAILED);
    }

    ipfw_sinlen=sizeof(ipfw_sin);
    memset(&ipfw_sin, 0, ipfw_sinlen);
    ipfw_sin.sin_family = PF_INET;
    ipfw_sin.sin_addr.s_addr = INADDR_ANY;
    ipfw_sin.sin_port = htons(divert_port);

    /* Bind that SOB */
    if (bind(ipfw_sock, (struct sockaddr *)&ipfw_sin, ipfw_sinlen) == -1) {
        SCLogError(SC_ERR_IPFW_BIND,"Can't bind divert socket on port %d: %s",divert_port,strerror(errno));
        SCReturnInt(TM_ECODE_FAILED);
    }

    ptv->datalink = DLT_RAW;

    *data = (void *)ptv;

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief This function prints stats to the screen at exit.
 * \todo Unit tests are needed for this module.
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into IPFWThreadVars for ptv
 */
void ReceiveIPFWThreadExitStats(ThreadVars *tv, void *data) {
    IPFWThreadVars *ptv = (IPFWThreadVars *)data;

    SCEnter();

    SCLogInfo("(%s) Packets %" PRIu32 ", bytes %" PRIu64 "", tv->name, ptv->pkts, ptv->bytes);

    SCReturn;
}

/**
 * \brief DeInit function closes divert socket at exit.
 * \todo Unit tests are needed for this module.
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into IPFWThreadVars for ptv
 */
TmEcode ReceiveIPFWThreadDeinit(ThreadVars *tv, void *data) {
    IPFWThreadVars *ptv = (IPFWThreadVars *)data;

    SCEnter();

    /* Attempt to shut the socket down...close instead? */
    if ( (shutdown(ipfw_sock,SHUT_RD)) < 0 ) {
        SCLogWarning(SC_WARN_IPFW_UNBIND,"Unable to disable ipfw socket: %s",strerror(errno));
        SCReturnInt(TM_ECODE_FAILED);
    }

    data = (void *)ptv;

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief This function passes off to link type decoders.
 * \todo Unit tests are needed for this module.
 *
 * DecodeIPFW reads packets from the PacketQueue and passes
 * them off to the proper link type decoder.
 *
 * \param tv pointer to ThreadVars
 * \param p pointer to the current packet
 * \param data pointer that gets cast into IPFWThreadVars for ptv
 * \param pq pointer to the PacketQueue
 */
TmEcode DecodeIPFW(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq)
{
    IPV4Hdr *ip4h = (IPV4Hdr *)p->pkt;
    IPV6Hdr *ip6h = (IPV6Hdr *)p->pkt;
    DecodeThreadVars *dtv = (DecodeThreadVars *)data;

    SCEnter();

    /* update counters */
    SCPerfCounterIncr(dtv->counter_pkts, tv->sc_perf_pca);
    SCPerfCounterAddUI64(dtv->counter_bytes, tv->sc_perf_pca, p->pktlen);
    SCPerfCounterAddUI64(dtv->counter_avg_pkt_size, tv->sc_perf_pca, p->pktlen);
    SCPerfCounterSetUI64(dtv->counter_max_pkt_size, tv->sc_perf_pca, p->pktlen);

    /* Process IP packets */
    if (IPV4_GET_RAW_VER(ip4h) == 4) {
        SCLogDebug("DecodeIPFW ip4 processing");
        DecodeIPV4(tv, dtv, p, p->pkt, p->pktlen, pq);

    } else if(IPV6_GET_RAW_VER(ip6h) == 6) {
        SCLogDebug("DecodeIPFW ip6 processing");
        DecodeIPV6(tv, dtv, p, p->pkt, p->pktlen, pq);

    } else {
        /* We don't support anything besides IP packets for now, bridged packets? */
        SCLogInfo("IPFW unknown protocol support %02x", *p->pkt);
       SCReturnInt(TM_ECODE_FAILED);
    }

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief This function initializes the DecodeThreadVariables
 *
 *
 * \param tv pointer to ThreadVars
 * \param initdata pointer for passing in args
 * \param data pointer that gets cast into IPFWThreadVars for ptv
 */
TmEcode DecodeIPFWThreadInit(ThreadVars *tv, void *initdata, void **data)
{
    DecodeThreadVars *dtv = NULL;

    if ( (dtv = SCMalloc(sizeof(DecodeThreadVars))) == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC,"Error Allocating memory for IPFW Decode DTV: %s",strerror(errno));
        SCReturnInt(TM_ECODE_FAILED);
    }
    memset(dtv, 0, sizeof(DecodeThreadVars));

    DecodeRegisterPerfCounters(dtv, tv);

    *data = (void *)dtv;

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief This function sets the Verdict and processes the packet
 *
 *
 * \param tv pointer to ThreadVars
 * \param p pointer to the Packet
 */
TmEcode IPFWSetVerdict(ThreadVars *tv, IPFWThreadVars *ptv, Packet *p) {
    uint32_t verdict;
    struct pollfd IPFWpoll;

    SCEnter();

    IPFWpoll.fd=ipfw_sock;
    IPFWpoll.events= POLLWRNORM;

    if (p->action & ACTION_REJECT || p->action & ACTION_REJECT_BOTH ||
        p->action & ACTION_REJECT_DST || p->action & ACTION_DROP) {
        verdict = IPFW_DROP;
    } else {
        verdict = IPFW_ACCEPT;
    }

    if (verdict == IPFW_ACCEPT) {
        SCLogDebug("IPFW Verdict is to Accept");
        ptv->accepted++;


        /* For divert sockets, accepting means writing the
         * packet back to the socket for ipfw to pick up
         */
        SCLogDebug("IPFWSetVerdict writing to socket %d, %p, %u", ipfw_sock,p->pkt,p->pktlen);


        while ( (poll(&IPFWpoll,1,IPFW_SOCKET_POLL_MSEC)) < 1) {

            /* Did we receive a signal to shutdown */
            if (TmThreadsCheckFlag(tv, THV_KILL) || TmThreadsCheckFlag(tv, THV_PAUSE)) {
                SCLogInfo("Received ThreadShutdown: IPFW divert socket writing interrupted");
                SCReturnInt(TM_ECODE_OK);
            }
        }

        SCMutexLock(&ipfw_socket_lock);
        if (sendto(ipfw_sock, p->pkt, p->pktlen, 0,(struct sockaddr *)&ipfw_sin, ipfw_sinlen) == -1) {
            SCLogWarning(SC_WARN_IPFW_XMIT,"Write to ipfw divert socket failed: %s",strerror(errno));
            SCMutexUnlock(&ipfw_socket_lock);
            SCReturnInt(TM_ECODE_FAILED);
        }

        SCMutexUnlock(&ipfw_socket_lock);

        SCLogDebug("Sent Packet back into IPFW Len: %d",p->pktlen);

    } /* end IPFW_ACCEPT */


    if (verdict == IPFW_DROP) {
        SCLogDebug("IPFW SetVerdict is to DROP");
        ptv->dropped++;

        /* For divert sockets, dropping means not writing the packet back to the socket.
         * Need to see if there is some better way to free the packet from the queue */

    } /* end IPFW_DROP */

    SCReturnInt(TM_ECODE_OK);
}


/**
 * \brief This function handles the Verdict processing
 * \todo Unit tests are needed for this module.
 *
 *
 * \param tv pointer to ThreadVars
 * \param p pointer to the Packet
 * \param data pointer that gets cast into IPFWThreadVars for ptv
 * \param pq pointer for the Packet Queue access (Not used)
 */
TmEcode VerdictIPFW(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq) {
    IPFWThreadVars *ptv = (IPFWThreadVars *)data;
    TmEcode retval = TM_ECODE_OK;

    SCEnter();

    /* This came from NFQ.
     *  if this is a tunnel packet we check if we are ready to verdict
     * already. */
    if (IS_TUNNEL_PKT(p)) {
        char verdict = 1;

        pthread_mutex_t *m = p->root ? &p->root->mutex_rtv_cnt : &p->mutex_rtv_cnt;
        SCMutexLock(m);
        /* if there are more tunnel packets than ready to verdict packets,
         * we won't verdict this one
         */
        if (TUNNEL_PKT_TPR(p) > TUNNEL_PKT_RTV(p)) {
            SCLogDebug("VerdictIPFW: not ready to verdict yet: TUNNEL_PKT_TPR(p) > TUNNEL_PKT_RTV(p) = %" PRId32 " > %" PRId32 "", TUNNEL_PKT_TPR(p), TUNNEL_PKT_RTV(p));
            verdict = 0;
        }
        SCMutexUnlock(m);

        /* don't verdict if we are not ready */
        if (verdict == 1) {
            SCLogDebug("Setting verdict on tunnel");
            retval=IPFWSetVerdict(tv, ptv, p->root ? p->root : p);

        } else
            TUNNEL_INCR_PKT_RTV(p);

    } else {
        /* no tunnel, verdict normally */
        SCLogDebug("Setting verdict on non-tunnel");
        retval=IPFWSetVerdict(tv, ptv, p);

    } /* IS_TUNNEL_PKT end */

    SCReturnInt(retval);
}

/**
 * \brief This function initializes the VerdictThread
 *
 *
 * \param t pointer to ThreadVars
 * \param initdata pointer for passing in args
 * \param data pointer that gets cast into IPFWThreadVars for ptv
 */
TmEcode VerdictIPFWThreadInit(ThreadVars *tv, void *initdata, void **data) {

    IPFWThreadVars *ptv = NULL;

    SCEnter();

    /* Setup Thread vars */
    if ( (ptv = SCMalloc(sizeof(IPFWThreadVars))) == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC,"Error Allocating memory for IPFW Verdict PTV: %s", strerror(errno));
        SCReturnInt(TM_ECODE_FAILED);
    }
    memset(ptv, 0, sizeof(IPFWThreadVars));


    *data = (void *)ptv;

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief This function deinitializes the VerdictThread
 *
 *
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into IPFWThreadVars for ptv
 */
TmEcode VerdictIPFWThreadDeinit(ThreadVars *tv, void *data) {

    SCEnter();

    /* We don't need to do anything...not sure quite yet */


    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief This function prints stats for the VerdictThread
 *
 *
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into IPFWThreadVars for ptv
 */
void VerdictIPFWThreadExitStats(ThreadVars *tv, void *data) {
    IPFWThreadVars *ptv = (IPFWThreadVars *)data;
    SCLogInfo("IPFW Processing: - (%s) Pkts accepted %" PRIu32 ", dropped %" PRIu32 "", tv->name, ptv->accepted, ptv->dropped);
}

#endif /* End ifdef IPFW */

/* eof */

