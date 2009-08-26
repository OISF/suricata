/* Basic detection engine */

#include <pcre.h>

#include "eidps.h"
#include "debug.h"
#include "detect.h"
#include "flow.h"

#include "detect-parse.h"
#include "detect-engine.h"

#include "detect-engine-siggroup.h"
#include "detect-engine-address.h"
#include "detect-engine-proto.h"
#include "detect-engine-port.h"
#include "detect-engine-mpm.h"
#include "detect-engine-iponly.h"

#include "detect-decode-event.h"

#include "detect-content.h"
#include "detect-uricontent.h"
#include "detect-pcre.h"
#include "detect-depth.h"
#include "detect-nocase.h"
#include "detect-recursive.h"
#include "detect-rawbytes.h"
#include "detect-within.h"
#include "detect-distance.h"
#include "detect-offset.h"
#include "detect-sid.h"
#include "detect-priority.h"
#include "detect-classtype.h"
#include "detect-reference.h"
#include "detect-threshold.h"
#include "detect-metadata.h"
#include "detect-msg.h"
#include "detect-rev.h"
#include "detect-flow.h"
#include "detect-dsize.h"
#include "detect-flowvar.h"
#include "detect-pktvar.h"
#include "detect-noalert.h"
#include "detect-flowbits.h"

#include "action-globals.h"
#include "tm-modules.h"

#include "pkt-var.h"

#include "util-print.h"
#include "util-unittest.h"

#include "util-hashlist.h"

SigMatch *SigMatchAlloc(void);
void SigMatchFree(SigMatch *sm);
void DetectExitPrintStats(ThreadVars *tv, void *data);

/* tm module api functions */
int Detect(ThreadVars *, Packet *, void *, PacketQueue *);
int DetectThreadInit(ThreadVars *, void *, void **);
int DetectThreadDeinit(ThreadVars *, void *);

void TmModuleDetectRegister (void) {
    tmm_modules[TMM_DETECT].name = "Detect";
    tmm_modules[TMM_DETECT].Init = DetectThreadInit;
    tmm_modules[TMM_DETECT].Func = Detect;
    tmm_modules[TMM_DETECT].ExitPrintStats = DetectExitPrintStats;
    tmm_modules[TMM_DETECT].Deinit = DetectThreadDeinit;
    tmm_modules[TMM_DETECT].RegisterTests = SigRegisterTests;
}

void DetectExitPrintStats(ThreadVars *tv, void *data) {
    DetectEngineThreadCtx *det_ctx = (DetectEngineThreadCtx *)data;
    if (det_ctx == NULL)
        return;

    printf(" - (%s) (1byte) Pkts %" PRIu32 ", Scanned %" PRIu32 " (%02.1f), Searched %" PRIu32 " (%02.1f): %02.1f%%.\n", tv->name,
        det_ctx->pkts, det_ctx->pkts_scanned1,
        (float)(det_ctx->pkts_scanned1/(float)(det_ctx->pkts)*100),
        det_ctx->pkts_searched1,
        (float)(det_ctx->pkts_searched1/(float)(det_ctx->pkts)*100),
        (float)(det_ctx->pkts_searched1/(float)(det_ctx->pkts_scanned1)*100));
    printf(" - (%s) (2byte) Pkts %" PRIu32 ", Scanned %" PRIu32 " (%02.1f), Searched %" PRIu32 " (%02.1f): %02.1f%%.\n", tv->name,
        det_ctx->pkts, det_ctx->pkts_scanned2,
        (float)(det_ctx->pkts_scanned2/(float)(det_ctx->pkts)*100),
        det_ctx->pkts_searched2,
        (float)(det_ctx->pkts_searched2/(float)(det_ctx->pkts)*100),
        (float)(det_ctx->pkts_searched2/(float)(det_ctx->pkts_scanned2)*100));
    printf(" - (%s) (3byte) Pkts %" PRIu32 ", Scanned %" PRIu32 " (%02.1f), Searched %" PRIu32 " (%02.1f): %02.1f%%.\n", tv->name,
        det_ctx->pkts, det_ctx->pkts_scanned3,
        (float)(det_ctx->pkts_scanned3/(float)(det_ctx->pkts)*100),
        det_ctx->pkts_searched3,
        (float)(det_ctx->pkts_searched3/(float)(det_ctx->pkts)*100),
        (float)(det_ctx->pkts_searched3/(float)(det_ctx->pkts_scanned3)*100));
    printf(" - (%s) (4byte) Pkts %" PRIu32 ", Scanned %" PRIu32 " (%02.1f), Searched %" PRIu32 " (%02.1f): %02.1f%%.\n", tv->name,
        det_ctx->pkts, det_ctx->pkts_scanned4,
        (float)(det_ctx->pkts_scanned4/(float)(det_ctx->pkts)*100),
        det_ctx->pkts_searched4,
        (float)(det_ctx->pkts_searched4/(float)(det_ctx->pkts)*100),
        (float)(det_ctx->pkts_searched4/(float)(det_ctx->pkts_scanned4)*100));
    printf(" - (%s) (+byte) Pkts %" PRIu32 ", Scanned %" PRIu32 " (%02.1f), Searched %" PRIu32 " (%02.1f): %02.1f%%.\n", tv->name,
        det_ctx->pkts, det_ctx->pkts_scanned,
        (float)(det_ctx->pkts_scanned/(float)(det_ctx->pkts)*100),
        det_ctx->pkts_searched,
        (float)(det_ctx->pkts_searched/(float)(det_ctx->pkts)*100),
        (float)(det_ctx->pkts_searched/(float)(det_ctx->pkts_scanned)*100));

    printf(" - (%s) URI (1byte) Uri's %" PRIu32 ", Scanned %" PRIu32 " (%02.1f), Searched %" PRIu32 " (%02.1f): %02.1f%%.\n", tv->name,
        det_ctx->uris, det_ctx->pkts_uri_scanned1,
        (float)(det_ctx->pkts_uri_scanned1/(float)(det_ctx->uris)*100),
        det_ctx->pkts_uri_searched1,
        (float)(det_ctx->pkts_uri_searched1/(float)(det_ctx->uris)*100),
        (float)(det_ctx->pkts_uri_searched1/(float)(det_ctx->pkts_uri_scanned1)*100));
    printf(" - (%s) URI (2byte) Uri's %" PRIu32 ", Scanned %" PRIu32 " (%02.1f), Searched %" PRIu32 " (%02.1f): %02.1f%%.\n", tv->name,
        det_ctx->uris, det_ctx->pkts_uri_scanned2,
        (float)(det_ctx->pkts_uri_scanned2/(float)(det_ctx->uris)*100),
        det_ctx->pkts_uri_searched2,
        (float)(det_ctx->pkts_uri_searched2/(float)(det_ctx->uris)*100),
        (float)(det_ctx->pkts_uri_searched2/(float)(det_ctx->pkts_uri_scanned2)*100));
    printf(" - (%s) URI (3byte) Uri's %" PRIu32 ", Scanned %" PRIu32 " (%02.1f), Searched %" PRIu32 " (%02.1f): %02.1f%%.\n", tv->name,
        det_ctx->uris, det_ctx->pkts_uri_scanned3,
        (float)(det_ctx->pkts_uri_scanned3/(float)(det_ctx->uris)*100),
        det_ctx->pkts_uri_searched3,
        (float)(det_ctx->pkts_uri_searched3/(float)(det_ctx->uris)*100),
        (float)(det_ctx->pkts_uri_searched3/(float)(det_ctx->pkts_uri_scanned3)*100));
    printf(" - (%s) URI (4byte) Uri's %" PRIu32 ", Scanned %" PRIu32 " (%02.1f), Searched %" PRIu32 " (%02.1f): %02.1f%%.\n", tv->name,
        det_ctx->uris, det_ctx->pkts_uri_scanned4,
        (float)(det_ctx->pkts_uri_scanned4/(float)(det_ctx->uris)*100),
        det_ctx->pkts_uri_searched4,
        (float)(det_ctx->pkts_uri_searched4/(float)(det_ctx->uris)*100),
        (float)(det_ctx->pkts_uri_searched4/(float)(det_ctx->pkts_uri_scanned4)*100));
    printf(" - (%s) URI (+byte) Uri's %" PRIu32 ", Scanned %" PRIu32 " (%02.1f), Searched %" PRIu32 " (%02.1f): %02.1f%%.\n", tv->name,
        det_ctx->uris, det_ctx->pkts_uri_scanned,
        (float)(det_ctx->pkts_uri_scanned/(float)(det_ctx->uris)*100),
        det_ctx->pkts_uri_searched,
        (float)(det_ctx->pkts_uri_searched/(float)(det_ctx->uris)*100),
        (float)(det_ctx->pkts_uri_searched/(float)(det_ctx->pkts_uri_scanned)*100));
}

/** \brief Load a file with signatures
 *  \retval -1 error
 *  \retval 0 ok
 */
int DetectLoadSigFile(DetectEngineCtx *de_ctx, char *sig_file) {
    Signature *prevsig = NULL;
    Signature *sig = NULL;
    int good = 0, bad = 0;

    /* set the prevsig to the last sig of the existing list, if any */
    if (de_ctx->sig_list != NULL) {
        for (prevsig = de_ctx->sig_list;
             prevsig->next != NULL;
             prevsig = prevsig->next);
    }

    FILE *fp = fopen(sig_file, "r");
    if (fp == NULL) {
        printf("ERROR, could not open sigs file\n");
        return -1;
    }
    char line[8192] = "";
    while(fgets(line, (int)sizeof(line), fp) != NULL) {
        /** \todo multi line support */

        /* ignore comments and empty lines */
        if (line[0] == '\n' || line[0] == ' ' || line[0] == '#' || line[0] == '\t')
            continue;

        sig = SigInit(de_ctx, line);
        if (sig != NULL) {
            if (de_ctx->sig_list == NULL) {
                de_ctx->sig_list = sig;
            } else {
                prevsig->next = sig;
            }
            prevsig = sig;
            good++;
        } else {
            bad++;
        }
    }
    fclose(fp);
    printf("DetectLoadSigFile: %" PRId32 " successfully loaded from file. %" PRId32 " sigs failed to load\n", good, bad);

    return 0;
}

int SigLoadSignatures (DetectEngineCtx *de_ctx, char *sig_file)
{
    Signature *prevsig = NULL, *sig;

    /* The next 3 rules handle HTTP header capture. */

    /* http_uri -- for uricontent */
    sig = SigInit(de_ctx, "alert tcp any any -> any $HTTP_PORTS (msg:\"HTTP GET URI cap\"; flow:to_server; content:\"GET \"; depth:4; pcre:\"/^GET (?P<pkt_http_uri>.*) HTTP\\/\\d\\.\\d\\r\\n/G\"; noalert; sid:1;)");
    if (sig) {
        prevsig = sig;
        de_ctx->sig_list = sig;
    }
    sig = SigInit(de_ctx, "alert tcp any any -> any $HTTP_PORTS (msg:\"HTTP POST URI cap\"; flow:to_server; content:\"POST \"; depth:5; pcre:\"/^POST (?P<pkt_http_uri>.*) HTTP\\/\\d\\.\\d\\r\\n/G\"; noalert; sid:2;)");
    if (sig == NULL)
        return -1;
    prevsig->next = sig;
    prevsig = sig;

    /* http_host -- for the log-httplog module */
    sig = SigInit(de_ctx, "alert tcp any any -> any $HTTP_PORTS (msg:\"HTTP host cap\"; flow:to_server; content:\"|0d 0a|Host:\"; pcre:\"/^Host: (?P<pkt_http_host>.*)\\r\\n/m\"; noalert; sid:3;)");
    if (sig == NULL)
        return -1;
    prevsig->next = sig;
    prevsig = sig;

    /* http_ua -- for the log-httplog module */
    sig = SigInit(de_ctx, "alert tcp any any -> any $HTTP_PORTS (msg:\"HTTP UA cap\"; flow:to_server; content:\"|0d 0a|User-Agent:\"; pcre:\"/^User-Agent: (?P<pkt_http_ua>.*)\\r\\n/m\"; noalert; sid:4;)");
    if (sig == NULL)
        return -1;
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx, "alert tcp any any -> any any (msg:\"ipv4 pkt too small\"; decode-event:ipv4.pkt_too_small; sid:5;)");
    if (sig == NULL)
        return -1;
    prevsig->next = sig;
    prevsig = sig;
/*
    sig = SigInit(de_ctx,"alert udp any any -> any any (msg:\"ViCtOr nocase test\"; sid:4; rev:13; content:\"ViCtOr!!\"; offset:100; depth:150; nocase; content:\"ViCtOr!!\"; nocase; offset:99; depth:150;)");
    if (sig == NULL)
        return;
    prevsig->next = sig;
    prevsig = sig;


    sig = SigInit(de_ctx,"alert ip any any -> 1.2.3.4 any (msg:\"ViCtOr case test\"; sid:2001; content:\"ViCtOr\"; depth:150;)");
    if (sig == NULL)
        return;
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx,"alert ip any any -> 1.2.3.4 any (msg:\"IP ONLY\"; sid:2002;)");
    if (sig == NULL)
        return;
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx,"alert ip ANY any -> 192.168.0.0/16 any (msg:\"offset, depth, within test\"; flow:to_client; sid:2002; content:HTTP; depth:4; content:Server:; offset:15; within:100; depth:200;)");
    if (sig == NULL)
        return;
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx,"alert ip 1.2.3.4 any -> any any (msg:\"Inliniac blog within test\"; flow:to_client; sid:2003; content:inliniac; content:blog; within:9;)");
    if (sig == NULL)
        return;
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx,"alert ip 2001::1 any -> 2001::3 any (msg:\"abcdefg distance 1 test\"; flow:to_server; sid:2004; content:abcd; content:efgh; within:4; distance:0; content:ijkl; within:4; distance:0;)");
    if (sig == NULL)
        return;
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx,"alert ip 2001::5 any -> 2001::7 any (msg:\"abcdef distance 0 test\"; flow:to_server; sid:2005; content:abcdef; content:ghijklmnop; distance:0;)");
    if (sig == NULL)
        return;
    prevsig->next = sig;
    prevsig = sig;


    sig = SigInit(de_ctx,"alert ip 10.0.0.0/8 any -> 4.3.2.1 any (msg:\"abcdefg distance 1 test\"; flow:to_server; sid:2006; content:abcdef; content:ghijklmnop; distance:1;)");
    if (sig == NULL)
        return;
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx,"alert tcp 172.16.1.0/24 any -> 0.0.0.0/0 any (msg:\"HTTP response code cap\"; flow:to_client; content:HTTP; depth:4; pcre:\"/^HTTP\\/\\d\\.\\d (?<http_response>[0-9]+) [A-z\\s]+\\r\\n/\"; depth:50; sid:3;)");
    if (sig == NULL)
        return;
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx,"alert tcp 172.16.2.0/24 any -> 10.10.10.10 any (msg:\"HTTP server code cap\"; flow:to_client; content:Server:; depth:500; pcre:\"/^Server: (?<http_server>.*)\\r\\n/m\"; sid:4;)");
    if (sig == NULL)
        return;
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx,"alert tcp 192.168.0.1 any -> 1.0.2.1 any (msg:\"\to_client nocase test\"; flow:to_client; content:Servere:; nocase; sid:400;)");
    if (sig == NULL)
        return;
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx,"alert tcp 192.168.0.4 any -> 1.2.0.1 any (msg:\"HTTP UA code cap\"; flow:to_server; content:User-Agent:; depth:300; pcre:\"/^User-Agent: (?<http_ua>.*)\\r\\n/m\"; sid:5;)");
    if (sig == NULL)
        return;
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx,"alert tcp 192.168.0.12 any -> 0.0.0.0/0 any (msg:\"HTTP http_host flowvar www.inliniac.net\"; flow:to_server; flowvar:http_host,\"www.inliniac.net\"; sid:7;)");
    if (sig) {
        prevsig->next = sig;
        prevsig = sig;
    }
    sig = SigInit(de_ctx,"alert tcp 192.168.0.0/16 any -> 0.0.0.0/0 any (msg:\"HTTP http_uri flowvar MattJonkman\"; flow:to_server; flowvar:http_uri,\"MattJonkman\"; sid:8;)");
    if (sig) {
        prevsig->next = sig;
        prevsig = sig;
    }
    sig = SigInit(de_ctx,"alert tcp 0.0.0.0/0 any -> 0.0.0.0/0 any (msg:\"HTTP uricontent VictorJulien\"; flow:to_server; uricontent:\"VictorJulien\"; nocase; sid:9;)");
    if (sig) {
        prevsig->next = sig;
        prevsig = sig;
    }
    sig = SigInit(de_ctx,"alert tcp 0.0.0.0/0 any -> 10.0.0.0/8 any (msg:\"HTTP uricontent VictorJulien\"; flow:to_server; uricontent:\"VictorJulien\"; nocase; sid:5;)");
    if (sig) {
        prevsig->next = sig;
        prevsig = sig;
    }
*/

    if(sig_file != NULL){
        int r = DetectLoadSigFile(de_ctx, sig_file);
        if (r < 0)
            return -1;
    }

    /* Setup the signature group lookup structure and
     * pattern matchers */
    SigGroupBuild(de_ctx);
    return 0;
}

/* check if a certain sid alerted, this is used in the test functions */
int PacketAlertCheck(Packet *p, uint32_t sid)
{
    uint16_t i = 0;
    int match = 0;

    for (i = 0; i < p->alerts.cnt; i++) {
        if (p->alerts.alerts[i].sid == sid)
            match++;
    }

    return match;
}

int PacketAlertAppend(Packet *p, uint8_t gid, uint32_t sid, uint8_t rev, uint8_t prio, char *msg)
{
    /* XXX overflow check? */

    p->alerts.alerts[p->alerts.cnt].gid = gid;
    p->alerts.alerts[p->alerts.cnt].sid = sid;
    p->alerts.alerts[p->alerts.cnt].rev = rev;
    p->alerts.alerts[p->alerts.cnt].prio = prio;
    p->alerts.alerts[p->alerts.cnt].msg = msg;
    p->alerts.cnt++;

    return 0;
}

static inline SigGroupHead *SigMatchSignaturesGetSgh(ThreadVars *th_v, DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx, Packet *p) {
    int ds,f;
    SigGroupHead *sgh = NULL;

    /* select the dsize_gh */
    if (p->payload_len <= 100)
        ds = 0;
    else
        ds = 1;

    /* select the flow_gh */
    if (p->flowflags & FLOW_PKT_TOCLIENT)
        f = 0;
    else
        f = 1;

    /* find the right mpm instance */
    DetectAddressGroup *ag = DetectAddressLookupGroup(de_ctx->dsize_gh[ds].flow_gh[f].src_gh[p->proto],&p->src);
    if (ag != NULL) {
        /* source group found, lets try a dst group */
        ag = DetectAddressLookupGroup(ag->dst_gh,&p->dst);
        if (ag != NULL) {
            if (ag->port == NULL) {
                sgh = ag->sh;

                //printf("SigMatchSignatures: mc %p, mcu %p\n", det_ctx->mc, det_ctx->mcu);
                //printf("sigs %" PRIu32 "\n", ag->sh->sig_cnt);
            } else {
                //printf("SigMatchSignatures: we have ports\n");

                DetectPort *sport = DetectPortLookupGroup(ag->port,p->sp);
                if (sport != NULL) {
                    DetectPort *dport = DetectPortLookupGroup(sport->dst_ph,p->dp);
                    if (dport != NULL) {
                        sgh = dport->sh;
                    }
                }
            }
        }
    }

    return sgh;
}

int SigMatchSignatures(ThreadVars *th_v, DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx, Packet *p)
{
    int match = 0, fmatch = 0;
    Signature *s = NULL;
    SigMatch *sm = NULL;
    uint32_t idx,sig;

    det_ctx->pkts++;

    /* match the ip only signatures */
    if ((p->flowflags & FLOW_PKT_TOSERVER && !(p->flowflags & FLOW_PKT_TOSERVER_IPONLY_SET)) ||
        (p->flowflags & FLOW_PKT_TOCLIENT && !(p->flowflags & FLOW_PKT_TOCLIENT_IPONLY_SET))) {
         IPOnlyMatchPacket(de_ctx, &de_ctx->io_ctx, &det_ctx->io_ctx, p);
         /* save in the flow that we scanned this direction... locking is
          * done in the FlowSetIPOnlyFlag function. */
         if (p->flow != NULL)
             FlowSetIPOnlyFlag(p->flow, p->flowflags & FLOW_PKT_TOSERVER ? 1 : 0);
    }

    /* we assume we don't have an uri when we start inspection */
    det_ctx->de_have_httpuri = 0;

    det_ctx->sgh = SigMatchSignaturesGetSgh(th_v, de_ctx, det_ctx, p);
    /* if we didn't get a sig group head, we
     * have nothing to do.... */
    if (det_ctx->sgh == NULL) {
        //printf("SigMatchSignatures: no sgh\n");
        return 0;
    }

    if (p->payload_len > 0 && det_ctx->sgh->mpm_ctx != NULL) {
        /* run the pattern matcher against the packet */
        if (det_ctx->sgh->mpm_content_maxlen > p->payload_len) {
            //printf("Not scanning as pkt payload is smaller than the largest content length we need to match");
        } else {
            uint32_t cnt = 0;
//printf("scan: (%p, maxlen %" PRIu32 ", cnt %" PRIu32 ")\n", det_ctx->sgh, det_ctx->sgh->mpm_content_maxlen, det_ctx->sgh->sig_cnt);
            /* scan, but only if the noscan flag isn't set */
            if (!(det_ctx->sgh->flags & SIG_GROUP_HEAD_MPM_NOSCAN)) {
                if (det_ctx->sgh->mpm_content_maxlen == 1)      det_ctx->pkts_scanned1++;
                else if (det_ctx->sgh->mpm_content_maxlen == 2) det_ctx->pkts_scanned2++;
                else if (det_ctx->sgh->mpm_content_maxlen == 3) det_ctx->pkts_scanned3++;
                else if (det_ctx->sgh->mpm_content_maxlen == 4) det_ctx->pkts_scanned4++;
                else                                        det_ctx->pkts_scanned++;

                cnt += PacketPatternScan(th_v, det_ctx, p);
            }
//if (cnt != det_ctx->pmq.searchable)
//printf("post scan: cnt %" PRIu32 ", searchable %" PRIu32 "\n", cnt, det_ctx->pmq.searchable);
            if (det_ctx->sgh->flags & SIG_GROUP_HEAD_MPM_NOSCAN || det_ctx->pmq.searchable > 0) {
//printf("now search\n");
                if (det_ctx->sgh->mpm_content_maxlen == 1)      det_ctx->pkts_searched1++;
                else if (det_ctx->sgh->mpm_content_maxlen == 2) det_ctx->pkts_searched2++;
                else if (det_ctx->sgh->mpm_content_maxlen == 3) det_ctx->pkts_searched3++;
                else if (det_ctx->sgh->mpm_content_maxlen == 4) det_ctx->pkts_searched4++;
                else                                        det_ctx->pkts_searched++;

                cnt += PacketPatternMatch(th_v, det_ctx, p);

//                printf("RAW: cnt %" PRIu32 ", det_ctx->pmq.sig_id_array_cnt %" PRIu32 "\n", cnt, det_ctx->pmq.sig_id_array_cnt);
            }
            det_ctx->pmq.searchable = 0;
        }
    }

    /* inspect the sigs against the packet */
    for (idx = 0; idx < det_ctx->sgh->sig_cnt; idx++) {
    //for (idx = 0; idx < det_ctx->pmq.sig_id_array_cnt; idx++) {
        sig = det_ctx->sgh->match_array[idx];
        //sig = det_ctx->pmq.sig_id_array[idx];
        s = de_ctx->sig_array[sig];

        /* filter out sigs that want pattern matches, but
         * have no matches */
        if (!(det_ctx->pmq.sig_bitarray[(sig / 8)] & (1<<(sig % 8))) &&
            (s->flags & SIG_FLAG_MPM))
            continue;

        //printf("idx %" PRIu32 ", det_ctx->pmq.sig_id_array_cnt %" PRIu32 ", s->id %" PRIu32 " (MPM? %s)\n", idx, det_ctx->pmq.sig_id_array_cnt, s->id, s->flags & SIG_FLAG_MPM ? "TRUE":"FALSE");
        //printf("Sig %" PRIu32 "\n", s->id);
        /* check the source & dst port in the sig */
        if (p->proto == IPPROTO_TCP || p->proto == IPPROTO_UDP) {
            if (!(s->flags & SIG_FLAG_DP_ANY)) {
                DetectPort *dport = DetectPortLookupGroup(s->dp,p->dp);
                if (dport == NULL)
                    continue;

            }
            if (!(s->flags & SIG_FLAG_SP_ANY)) {
                DetectPort *sport = DetectPortLookupGroup(s->sp,p->sp);
                if (sport == NULL)
                    continue;
            }
        }

        /* check the source address */
        if (!(s->flags & SIG_FLAG_SRC_ANY)) {
            DetectAddressGroup *saddr = DetectAddressLookupGroup(&s->src,&p->src);
            if (saddr == NULL)
                continue;
        }
        /* check the destination address */
        if (!(s->flags & SIG_FLAG_DST_ANY)) {
            DetectAddressGroup *daddr = DetectAddressLookupGroup(&s->dst,&p->dst);
            if (daddr == NULL)
                continue;
        }

        /* reset pkt ptr and offset */
        det_ctx->pkt_ptr = NULL;
        det_ctx->pkt_off = 0;

        if (s->flags & SIG_FLAG_RECURSIVE) {
            uint8_t rmatch = 0;
            det_ctx->pkt_cnt = 0;

            do {
                sm = s->match;
                while (sm) {
                    match = sigmatch_table[sm->type].Match(th_v, det_ctx, p, s, sm);
                    if (match) {
                        /* okay, try the next match */
                        sm = sm->next;

                        /* only if the last matched as well, we have a hit */
                        if (sm == NULL) {
                            if (!(s->flags & SIG_FLAG_NOALERT)) {
                                /* only add once */
                                if (rmatch == 0) {
                                    PacketAlertAppend(p, 1, s->id, s->rev, s->prio, s->msg);

                                    /* set verdict on packet */
                                    p->action = s->action;
                                }
                            }
                            rmatch = fmatch = 1;
                            det_ctx->pkt_cnt++;
                        }
                    } else {
                        /* done with this sig */
                        sm = NULL;
                        rmatch = 0;
                    }
                }
                /* Limit the number of times we do this recursive thing.
                 * XXX is this a sane limit? Should it be configurable? */
                if (det_ctx->pkt_cnt == 10)
                    break;
            } while (rmatch);
        } else {
            sm = s->match;
            while (sm) {
                match = sigmatch_table[sm->type].Match(th_v, det_ctx, p, s, sm);
                if (match) {
                    /* okay, try the next match */
                    sm = sm->next;

                    /* only if the last matched as well, we have a hit */
                    if (sm == NULL) {
                        fmatch = 1;
//printf("DE : sig %" PRIu32 " matched\n", s->id);
                        if (!(s->flags & SIG_FLAG_NOALERT)) {
                            PacketAlertAppend(p, 1, s->id, s->rev, s->prio, s->msg);

                            /* set verdict on packet */
                            p->action = s->action;
                        }
                    }
                } else {
                    /* done with this sig */
                    sm = NULL;
                }
            }
        }
    }

    /* cleanup pkt specific part of the patternmatcher */
    PacketPatternCleanup(th_v, det_ctx);
    return fmatch;
}

/* tm module api functions */
int Detect(ThreadVars *t, Packet *p, void *data, PacketQueue *pq) {
    DetectEngineThreadCtx *det_ctx = (DetectEngineThreadCtx *)data;
    DetectEngineCtx *de_ctx = det_ctx->de_ctx;

    int r = SigMatchSignatures(t,de_ctx,det_ctx,p);
    if (r >= 0) {
        return 0;
    }

    // PerfCounterIncr(det_ctx->counter_alerts, t->pca);

    return 1;
}

int DetectThreadInit(ThreadVars *t, void *initdata, void **data)
{
    return DetectEngineThreadCtxInit(t,initdata,data);
}

int DetectThreadDeinit(ThreadVars *t, void *data) {
    return DetectEngineThreadCtxDeinit(t,data);
}

void SigCleanSignatures(DetectEngineCtx *de_ctx)
{
    Signature *s = NULL, *ns;

    if (de_ctx == NULL)
        return;

    for (s = de_ctx->sig_list; s != NULL;) {
        ns = s->next;
        SigFree(s);
        s = ns;
    }

    DetectEngineResetMaxSigId(de_ctx);
}

/* return codes:
 * 1: sig is ip only
 * 0: sig is not ip only
 *
 */
static int SignatureIsIPOnly(DetectEngineCtx *de_ctx, Signature *s) {
    /* in the case of tcp/udp, only consider sigs that
     * don't have ports set ip-only. */
    if (!(s->proto.flags & DETECT_PROTO_ANY)) {
        if (s->proto.proto[(IPPROTO_TCP/8)] & (1<<(IPPROTO_TCP%8)) ||
            s->proto.proto[(IPPROTO_UDP/8)] & (1<<(IPPROTO_UDP%8))) {
            if (!(s->flags & SIG_FLAG_SP_ANY))
                return 0;

            if (!(s->flags & SIG_FLAG_DP_ANY))
                return 0;
        }
    }

    SigMatch *sm = s->match;
    if (sm == NULL)
        goto iponly;

    for ( ; sm != NULL; sm = sm->next) {
        if (sm->type == DETECT_CONTENT) {
            return 0;
        } else if (sm->type == DETECT_URICONTENT) {
            return 0;
        } else if (sm->type == DETECT_PCRE) {
            return 0;
        } else if (sm->type == DETECT_FLOW) {
            return 0;
        } else if (sm->type == DETECT_PKTVAR) {
            return 0;
        } else if (sm->type == DETECT_FLOWVAR) {
            return 0;
        } else if (sm->type == DETECT_FLOWBITS) {
            return 0;
        } else if (sm->type == DETECT_DSIZE) {
            return 0;
        } else if (sm->type == DETECT_DECODE_EVENT) {
            return 0;
        }
    }

iponly:
    if (!(de_ctx->flags & DE_QUIET)) {
        printf("IP-ONLY (%" PRIu32 "): source %s, dest %s\n", s->id,
        s->flags & SIG_FLAG_SRC_ANY ? "ANY" : "SET",
        s->flags & SIG_FLAG_DST_ANY ? "ANY" : "SET");
    }
    return 1;
}

/* add all signatures to their own source address group */
int SigAddressPrepareStage1(DetectEngineCtx *de_ctx) {
    Signature *tmp_s = NULL;
    DetectAddressGroup *gr = NULL;
    uint32_t cnt = 0, cnt_iponly = 0;

    //DetectAddressGroupPrintMemory();
    //DetectSigGroupPrintMemory();
    //DetectPortPrintMemory();

    if (!(de_ctx->flags & DE_QUIET)) {
        printf("* Building signature grouping structure, stage 1: "
               "adding signatures to signature source addresses...\n");
    }

    de_ctx->sig_array_len = DetectEngineGetMaxSigId(de_ctx);
    de_ctx->sig_array_size = (de_ctx->sig_array_len * sizeof(Signature *));
    de_ctx->sig_array = (Signature **)malloc(de_ctx->sig_array_size);
    if (de_ctx->sig_array == NULL)
        goto error;
    memset(de_ctx->sig_array,0,de_ctx->sig_array_size);

    if (!(de_ctx->flags & DE_QUIET)) {
        printf(" - Signature lookup array: %" PRIu32 " sigs, %" PRIu32 " bytes.\n",
            de_ctx->sig_array_len, de_ctx->sig_array_size);
    }

    /* now for every rule add the source group */
    for (tmp_s = de_ctx->sig_list; tmp_s != NULL; tmp_s = tmp_s->next) {

        de_ctx->sig_array[tmp_s->num] = tmp_s;
        //printf(" + Signature %" PRIu32 ", internal id %" PRIu32 ", ptrs %p %p ", tmp_s->id, tmp_s->num, tmp_s, de_ctx->sig_array[tmp_s->num]);

        /* see if the sig is ip only */
        if (SignatureIsIPOnly(de_ctx, tmp_s) == 1) {
            tmp_s->flags |= SIG_FLAG_IPONLY;
            cnt_iponly++;
            //printf("(IP only)\n");
        } else {
            //printf("\n");
            //if (tmp_s->proto.flags & DETECT_PROTO_ANY) {
            //printf("Signature %" PRIu32 " applies to all protocols.\n",tmp_s->id);
            //}
        }

/* DEBUG */
        uint16_t colen = 0;
        char copresent = 0;
        SigMatch *sm;
        DetectContentData *co;
        for (sm = tmp_s->match; sm != NULL; sm = sm->next) {
            if (sm->type != DETECT_CONTENT)
                continue;

            copresent = 1;
            co = (DetectContentData *)sm->ctx;
            if (co->content_len > colen)
                colen = co->content_len;
        }

        if (copresent && colen == 1) {
            printf("==> Signature %8u content maxlen 1: ", tmp_s->id);
            int proto;
            for (proto = 0; proto < 256; proto++) {
                if (tmp_s->proto.proto[(proto/8)] & (1<<(proto%8)))
                    printf ("%" PRId32 " ", proto);
            }
            printf("\n");
        }
/* DEBUG */


        for (gr = tmp_s->src.ipv4_head; gr != NULL; gr = gr->next) {
            //printf("Stage1: ip4 ");DetectAddressDataPrint(gr->ad);printf("\n");
            if (SigGroupHeadAppendSig(de_ctx, &gr->sh,tmp_s) < 0) {
                goto error;
            }
            cnt++;
        }
        for (gr = tmp_s->src.ipv6_head; gr != NULL; gr = gr->next) {
            if (SigGroupHeadAppendSig(de_ctx, &gr->sh,tmp_s) < 0) {
                goto error;
            }
            cnt++;
        }
        for (gr = tmp_s->src.any_head; gr != NULL; gr = gr->next) {
            if (SigGroupHeadAppendSig(de_ctx, &gr->sh,tmp_s) < 0) {
                goto error;
            }
            cnt++;
        }
        de_ctx->sig_cnt++;
    }

    //DetectAddressGroupPrintMemory();
    //DetectSigGroupPrintMemory();
    //DetectPortPrintMemory();

    if (!(de_ctx->flags & DE_QUIET)) {
        printf(" * %" PRIu32 " signatures processed. %" PRIu32 " are IP-only rules.\n",
            de_ctx->sig_cnt, cnt_iponly);
        printf("* Building signature grouping structure, stage 1: "
               "adding signatures to signature source addresses... done\n");
    }
    return 0;
error:
    printf("SigAddressPrepareStage1 error\n");
    return -1;
}

static int DetectEngineLookupBuildSourceAddressList(DetectEngineCtx *de_ctx, DetectEngineLookupFlow *flow_gh, Signature *s, int family) {
    DetectAddressGroup *gr = NULL, *lookup_gr = NULL, *head = NULL;
    int proto;

    if (family == AF_INET) {
        head = s->src.ipv4_head;
    } else if (family == AF_INET6) {
        head = s->src.ipv6_head;
    } else {
        head = s->src.any_head;
    }

    /* for each source address group in the signature... */
    for (gr = head; gr != NULL; gr = gr->next) {
        /* ...and each protocol the signature matches on... */
        for (proto = 0; proto < 256; proto++) {
            if ((s->proto.proto[(proto/8)] & (1<<(proto%8))) || (s->proto.flags & DETECT_PROTO_ANY)) {
                /* ...see if the group is in the tmp list, and if not add it. */
                if (family == AF_INET) {
                    lookup_gr = DetectAddressGroupLookup(flow_gh->tmp_gh[proto]->ipv4_head,gr->ad);
                } else if (family == AF_INET6) {
                    lookup_gr = DetectAddressGroupLookup(flow_gh->tmp_gh[proto]->ipv6_head,gr->ad);
                } else {
                    lookup_gr = DetectAddressGroupLookup(flow_gh->tmp_gh[proto]->any_head,gr->ad);
                }

                if (lookup_gr == NULL) {
                    DetectAddressGroup *grtmp = DetectAddressGroupInit();
                    if (grtmp == NULL) {
                        goto error;
                    }
                    DetectAddressData *adtmp = DetectAddressDataCopy(gr->ad);
                    if (adtmp == NULL) {
                        goto error;
                    }
                    grtmp->ad = adtmp;
                    grtmp->cnt = 1;

                    SigGroupHeadAppendSig(de_ctx, &grtmp->sh, s);

                    /* add to the lookup list */
                    if (family == AF_INET) {
                        DetectAddressGroupAdd(&flow_gh->tmp_gh[proto]->ipv4_head, grtmp);
                    } else if (family == AF_INET6) {
                        DetectAddressGroupAdd(&flow_gh->tmp_gh[proto]->ipv6_head, grtmp);
                    } else {
                        DetectAddressGroupAdd(&flow_gh->tmp_gh[proto]->any_head, grtmp);
                    }
                } else {
                    /* our group will only have one sig, this one. So add that. */
                    SigGroupHeadAppendSig(de_ctx, &lookup_gr->sh, s);
                    lookup_gr->cnt++;
                }
            }
        }
        SigGroupHeadFree(gr->sh);
        gr->sh = NULL;
    }

    return 0;
error:
    return -1;
}

static uint32_t g_detectengine_ip4_small = 0;
static uint32_t g_detectengine_ip4_big = 0;
static uint32_t g_detectengine_ip4_small_toclient = 0;
static uint32_t g_detectengine_ip4_small_toserver = 0;
static uint32_t g_detectengine_ip4_big_toclient = 0;
static uint32_t g_detectengine_ip4_big_toserver = 0;

static uint32_t g_detectengine_ip6_small = 0;
static uint32_t g_detectengine_ip6_big = 0;
static uint32_t g_detectengine_ip6_small_toclient = 0;
static uint32_t g_detectengine_ip6_small_toserver = 0;
static uint32_t g_detectengine_ip6_big_toclient = 0;
static uint32_t g_detectengine_ip6_big_toserver = 0;

static uint32_t g_detectengine_any_small = 0;
static uint32_t g_detectengine_any_big = 0;
static uint32_t g_detectengine_any_small_toclient = 0;
static uint32_t g_detectengine_any_small_toserver = 0;
static uint32_t g_detectengine_any_big_toclient = 0;
static uint32_t g_detectengine_any_big_toserver = 0;

/* add signature to the right flow groups
 */
static int DetectEngineLookupFlowAddSig(DetectEngineCtx *de_ctx, DetectEngineLookupDsize *ds, Signature *s, int family, int dsize) {
    uint8_t flags = 0;

    SigMatch *sm = s->match;
    for ( ; sm != NULL; sm = sm->next) {
        if (sm->type != DETECT_FLOW)
            continue;

        DetectFlowData *df = (DetectFlowData *)sm->ctx;
        if (df == NULL)
            continue;

        flags = df->flags;
    }

    if (flags & FLOW_PKT_TOCLIENT) {
        /* only toclient */
        DetectEngineLookupBuildSourceAddressList(de_ctx, &ds->flow_gh[0], s, family);

        if (family == AF_INET)
            dsize ? g_detectengine_ip4_big_toclient++ : g_detectengine_ip4_small_toclient++;
        else if (family == AF_INET6)
            dsize ? g_detectengine_ip6_big_toclient++ : g_detectengine_ip6_small_toclient++;
        else
            dsize ? g_detectengine_any_big_toclient++ : g_detectengine_any_small_toclient++;
    } else if (flags & FLOW_PKT_TOSERVER) {
        /* only toserver */
        DetectEngineLookupBuildSourceAddressList(de_ctx, &ds->flow_gh[1], s, family);

        if (family == AF_INET)
            dsize ? g_detectengine_ip4_big_toserver++ : g_detectengine_ip4_small_toserver++;
        else if (family == AF_INET6)
            dsize ? g_detectengine_ip6_big_toserver++ : g_detectengine_ip6_small_toserver++;
        else
            dsize ? g_detectengine_any_big_toserver++ : g_detectengine_any_small_toserver++;
    } else {
        /* both */
        DetectEngineLookupBuildSourceAddressList(de_ctx, &ds->flow_gh[0], s, family);
        DetectEngineLookupBuildSourceAddressList(de_ctx, &ds->flow_gh[1], s, family);

        if (family == AF_INET) {
            dsize ? g_detectengine_ip4_big_toclient++ : g_detectengine_ip4_small_toclient++;
            dsize ? g_detectengine_ip4_big_toserver++ : g_detectengine_ip4_small_toserver++;
        } else if (family == AF_INET6) {
            dsize ? g_detectengine_ip6_big_toserver++ : g_detectengine_ip6_small_toserver++;
            dsize ? g_detectengine_ip6_big_toclient++ : g_detectengine_ip6_small_toclient++;
        } else {
            dsize ? g_detectengine_any_big_toclient++ : g_detectengine_any_small_toclient++;
            dsize ? g_detectengine_any_big_toserver++ : g_detectengine_any_small_toserver++;
        }
    }

    return 0;
}

/* Add a sig to the dsize groupheads it belongs in. Meant to keep
 * sigs for small packets out of the 'normal' detection so the small
 * patterns won't influence as much traffic.
 *
 */
static int DetectEngineLookupDsizeAddSig(DetectEngineCtx *de_ctx, Signature *s, int family) {
    uint16_t low = 0, high = 65535;

    SigMatch *sm = s->match;
    for ( ; sm != NULL; sm = sm->next) {
        if (sm->type != DETECT_DSIZE)
            continue;

        DetectDsizeData *dd = (DetectDsizeData *)sm->ctx;
        if (dd == NULL)
            continue;

        if (dd->mode == DETECTDSIZE_LT) {
            low = 0;
            high = dd->dsize - 1;
        } else if (dd->mode == DETECTDSIZE_GT) {
            low = dd->dsize + 1;
            high = 65535;
        } else if (dd->mode == DETECTDSIZE_EQ) {
            low = dd->dsize;
            high = dd->dsize;
        } else if (dd->mode == DETECTDSIZE_RA) {
            low = dd->dsize;
            high = dd->dsize2;
        }

        break;
    }

    if (low <= 100) {
        /* add to 'low' group */
        DetectEngineLookupFlowAddSig(de_ctx, &de_ctx->dsize_gh[0], s, family, 0);
        if (family == AF_INET)
            g_detectengine_ip4_small++;
        else if (family == AF_INET6)
            g_detectengine_ip6_small++;
        else
            g_detectengine_any_small++;
    }
    if (high > 100) {
        /* add to 'high' group */
        DetectEngineLookupFlowAddSig(de_ctx, &de_ctx->dsize_gh[1], s, family, 1);
        if (family == AF_INET)
            g_detectengine_ip4_big++;
        else if (family == AF_INET6)
            g_detectengine_ip6_big++;
        else
            g_detectengine_any_big++;
    }

    return 0;
}

static DetectAddressGroup *GetHeadPtr(DetectAddressGroupsHead *head, int family) {
    DetectAddressGroup *grhead;

    if (head == NULL)
        return NULL;

    if (family == AF_INET) {
        grhead = head->ipv4_head;
    } else if (family == AF_INET6) {
        grhead = head->ipv6_head;
    } else {
        grhead = head->any_head;
    }

    return grhead;
}

#define MAX_UNIQ_TOCLIENT_SRC_GROUPS 2
#define MAX_UNIQ_TOCLIENT_DST_GROUPS 2
#define MAX_UNIQ_TOCLIENT_SP_GROUPS 2
#define MAX_UNIQ_TOCLIENT_DP_GROUPS 3

#define MAX_UNIQ_TOSERVER_SRC_GROUPS 2
#define MAX_UNIQ_TOSERVER_DST_GROUPS 4
#define MAX_UNIQ_TOSERVER_SP_GROUPS 2
#define MAX_UNIQ_TOSERVER_DP_GROUPS 25

#define MAX_UNIQ_SMALL_TOCLIENT_SRC_GROUPS 2
#define MAX_UNIQ_SMALL_TOCLIENT_DST_GROUPS 2
#define MAX_UNIQ_SMALL_TOCLIENT_SP_GROUPS 2
#define MAX_UNIQ_SMALL_TOCLIENT_DP_GROUPS 2

#define MAX_UNIQ_SMALL_TOSERVER_SRC_GROUPS 2
#define MAX_UNIQ_SMALL_TOSERVER_DST_GROUPS 2
#define MAX_UNIQ_SMALL_TOSERVER_SP_GROUPS 2
#define MAX_UNIQ_SMALL_TOSERVER_DP_GROUPS 8

//#define SMALL_MPM(c) 0
#define SMALL_MPM(c) ((c) == 1)
// || (c) == 2)
// || (c) == 3)

int CreateGroupedAddrListCmpCnt(DetectAddressGroup *a, DetectAddressGroup *b) {
    if (a->cnt > b->cnt)
        return 1;
    return 0;
}

int CreateGroupedAddrListCmpMpmMaxlen(DetectAddressGroup *a, DetectAddressGroup *b) {
    if (a->sh == NULL || b->sh == NULL)
        return 0;

    if (SMALL_MPM(a->sh->mpm_content_maxlen))
        return 1;

    if (a->sh->mpm_content_maxlen < b->sh->mpm_content_maxlen)
        return 1;
    return 0;
}

/* set unique_groups to 0 for no grouping.
 *
 * srchead is a ordered "inserted" list w/o internal overlap
 *
 */
int CreateGroupedAddrList(DetectEngineCtx *de_ctx, DetectAddressGroup *srchead, int family, DetectAddressGroupsHead *newhead, uint32_t unique_groups, int (*CompareFunc)(DetectAddressGroup *, DetectAddressGroup *), uint32_t max_idx) {
    DetectAddressGroup *tmplist = NULL, *tmplist2 = NULL, *joingr = NULL;
    char insert = 0;
    DetectAddressGroup *gr, *next_gr;
    uint32_t groups = 0;

    /* insert the addresses into the tmplist, where it will
     * be sorted descending on 'cnt'. */
    for (gr = srchead; gr != NULL; gr = gr->next) {
        SigGroupHeadSetMpmMaxlen(de_ctx, gr->sh);

        if (SMALL_MPM(gr->sh->mpm_content_maxlen) && unique_groups > 0)
            unique_groups++;

        //printf(" 1 -= Address "); DetectAddressDataPrint(gr->ad); printf("\n");
        //printf(" :  "); DbgPrintSigs2(gr->sh);

        groups++;

        /* alloc a copy */
        DetectAddressGroup *newtmp = DetectAddressGroupInit();
        if (newtmp == NULL) {
            goto error;
        }
        DetectAddressData *adtmp = DetectAddressDataCopy(gr->ad);
        if (adtmp == NULL) {
            goto error;
        }
        newtmp->ad = adtmp;
        newtmp->cnt = gr->cnt;

        SigGroupHeadCopySigs(de_ctx, gr->sh,&newtmp->sh);
        DetectPort *port = gr->port;
        for ( ; port != NULL; port = port->next) {
            DetectPortInsertCopy(de_ctx,&newtmp->port, port);
        }

        /* insert it */
        DetectAddressGroup *tmpgr = tmplist, *prevtmpgr = NULL;
        if (tmplist == NULL) {
            /* empty list, set head */
            tmplist = newtmp;
        } else {
            /* look for the place to insert */
            for ( ; tmpgr != NULL&&!insert; tmpgr = tmpgr->next) {
                if (CompareFunc(gr, tmpgr)) {
                //if (gr->cnt > tmpgr->cnt) {
                    if (tmpgr == tmplist) {
                        newtmp->next = tmplist;
                        tmplist = newtmp;
                    } else {
                        newtmp->next = prevtmpgr->next;
                        prevtmpgr->next = newtmp;
                    }
                    insert = 1;
                }
                prevtmpgr = tmpgr;
            }
            if (insert == 0) {
                newtmp->next = NULL;
                prevtmpgr->next = newtmp;
            }
            insert = 0;
        }
    }

    uint32_t i = unique_groups;
    if (i == 0) i = groups;

    for (gr = tmplist; gr != NULL; ) {
        if (i == 0) {
            if (joingr == NULL) {
                joingr = DetectAddressGroupInit();
                if (joingr == NULL) {
                    goto error;
                }
                DetectAddressData *adtmp = DetectAddressDataCopy(gr->ad);
                if (adtmp == NULL) {
                    goto error;
                }
                joingr->ad = adtmp;
                joingr->cnt = gr->cnt;

                SigGroupHeadCopySigs(de_ctx,gr->sh,&joingr->sh);

                DetectPort *port = gr->port;
                for ( ; port != NULL; port = port->next) {
                    DetectPortInsertCopy(de_ctx,&joingr->port, port);
                }
            } else {
                DetectAddressGroupJoin(de_ctx, joingr, gr);
            }
        } else {
            DetectAddressGroup *newtmp = DetectAddressGroupInit();
            if (newtmp == NULL) {
                goto error;
            }
            DetectAddressData *adtmp = DetectAddressDataCopy(gr->ad);
            if (adtmp == NULL) {
                goto error;
            }
            newtmp->ad = adtmp;
            newtmp->cnt = gr->cnt;

            SigGroupHeadCopySigs(de_ctx,gr->sh,&newtmp->sh);

            DetectPort *port = gr->port;
            for ( ; port != NULL; port = port->next) {
                DetectPortInsertCopy(de_ctx,&newtmp->port, port);
            }

            if (tmplist2 == NULL) {
                tmplist2 = newtmp;
            } else {
                newtmp->next = tmplist2;
                tmplist2 = newtmp;
            }
        }
        if (i)i--;

        next_gr = gr->next;
        DetectAddressGroupFree(gr);
        gr = next_gr;
    }

    /* we now have a tmplist2 containing the 'unique' groups and
     * possibly a joingr that covers the rest. Now build the newhead
     * that we will pass back to the caller.
     *
     * Start with inserting the unique groups */
    for (gr = tmplist2; gr != NULL; ) {
//        printf(" 2 -= U Address "); DetectAddressDataPrint(gr->ad); printf(" :  "); DbgPrintSigs2(gr->sh);
        DetectAddressGroup *newtmp = DetectAddressGroupInit();
        if (newtmp == NULL) {
            goto error;
        }
        DetectAddressData *adtmp = DetectAddressDataCopy(gr->ad);
        if (adtmp == NULL) {
            goto error;
        }
        newtmp->ad = adtmp;
        newtmp->cnt = gr->cnt;

        SigGroupHeadCopySigs(de_ctx, gr->sh,&newtmp->sh);

        DetectPort *port = gr->port;
        for ( ; port != NULL; port = port->next) {
            DetectPortInsertCopy(de_ctx, &newtmp->port, port);
        }

        DetectAddressGroupInsert(de_ctx, newhead, newtmp);

        next_gr = gr->next;
//        DetectAddressGroupFree(gr);
        gr = next_gr;
    }
    /* if present, insert the joingr that covers the rest */
    if (joingr != NULL) {
//        printf(" 3 -= J Address "); DetectAddressDataPrint(joingr->ad); printf(" :  "); DbgPrintSigs2(joingr->sh);
        DetectAddressGroupInsert(de_ctx, newhead, joingr);
#if 0
        /* mark the groups that are not unique */
        DetectAddressGroup *ag = GetHeadPtr(newhead,family);
        DetectAddressGroup *agr = NULL;

        for (agr = ag; agr != NULL; agr = agr->next) {
            DetectAddressGroup *sgr = tmplist2;
            for ( ; sgr != NULL; sgr = sgr->next) {
                int r = DetectAddressCmp(agr->ad,sgr->ad);
                if (r == ADDRESS_ES || r == ADDRESS_EB) {
//                    printf("AGR "); DetectAddressDataPrint(agr->ad);printf(" -> ");
//                    printf(" sgr "); DetectAddressDataPrint(sgr->ad);printf("\n");
                }
            }
        }
#endif
    }

    for (gr = newhead->ipv4_head; gr != NULL; gr = gr->next) {
        //printf(" 4 -= R Address "); DetectAddressDataPrint(gr->ad); printf(" :  "); DbgPrintSigs2(gr->sh);
    }

    return 0;
error:
    return -1;
}

int CreateGroupedPortListCmpCnt(DetectPort *a, DetectPort *b) {
    if (a->cnt > b->cnt)
        return 1;
    return 0;
}

int CreateGroupedPortListCmpMpmMaxlen(DetectPort *a, DetectPort *b) {
    if (a->sh == NULL || b->sh == NULL)
        return 0;

    if (SMALL_MPM(a->sh->mpm_content_maxlen))
        return 1;

    if (a->sh->mpm_content_maxlen < b->sh->mpm_content_maxlen)
        return 1;
    return 0;
}

static uint32_t g_groupportlist_maxgroups = 0;
static uint32_t g_groupportlist_groupscnt = 0;
static uint32_t g_groupportlist_totgroups = 0;

int CreateGroupedPortList(DetectEngineCtx *de_ctx,HashListTable *port_hash, DetectPort **newhead, uint32_t unique_groups, int (*CompareFunc)(DetectPort *, DetectPort *), uint32_t max_idx) {
    DetectPort *tmplist = NULL, *tmplist2 = NULL, *joingr = NULL;
    char insert = 0;
    DetectPort *gr, *next_gr;
    uint32_t groups = 0;

    HashListTableBucket *htb = HashListTableGetListHead(port_hash);

    /* insert the addresses into the tmplist, where it will
     * be sorted descending on 'cnt'. */
    for ( ; htb != NULL; htb = HashListTableGetListNext(htb)) {
        gr = (DetectPort *)HashListTableGetListData(htb);
        SigGroupHeadSetMpmMaxlen(de_ctx, gr->sh);

        if (SMALL_MPM(gr->sh->mpm_content_maxlen) && unique_groups > 0)
            unique_groups++;

        groups++;

        //printf(":-:1:-: Port "); DetectPortPrint(gr); printf(" (cnt %" PRIu32 ", cost %" PRIu32 ", maxlen %" PRIu32 ") ", gr->cnt, gr->sh->cost, gr->sh->mpm_content_maxlen);DbgSghContainsSig(de_ctx,gr->sh,2001330);

        /* alloc a copy */
        DetectPort *newtmp = DetectPortCopySingle(de_ctx,gr);
        if (newtmp == NULL) {
            goto error;
        }

        /* insert it */
        DetectPort *tmpgr = tmplist, *prevtmpgr = NULL;
        if (tmplist == NULL) {
            /* empty list, set head */
            tmplist = newtmp;
        } else {
            /* look for the place to insert */
            for ( ; tmpgr != NULL&&!insert; tmpgr = tmpgr->next) {
                if (CompareFunc(gr, tmpgr)) {
                //if (gr->cnt > tmpgr->cnt) {
                    if (tmpgr == tmplist) {
                        newtmp->next = tmplist;
                        tmplist = newtmp;
                    } else {
                        newtmp->next = prevtmpgr->next;
                        prevtmpgr->next = newtmp;
                    }
                    insert = 1;
                }
                prevtmpgr = tmpgr;
            }
            if (insert == 0) {
                newtmp->next = NULL;
                prevtmpgr->next = newtmp;
            }
            insert = 0;
        }
    }

    uint32_t i = unique_groups;
    if (i == 0) i = groups;

    if (unique_groups > g_groupportlist_maxgroups)
        g_groupportlist_maxgroups = unique_groups;
    g_groupportlist_groupscnt++;
    g_groupportlist_totgroups += unique_groups;

    for (gr = tmplist; gr != NULL; ) {
        if (i == 0) {
            if (joingr == NULL) {
                joingr = DetectPortCopySingle(de_ctx,gr);
                if (joingr == NULL) {
                    goto error;
                }
            } else {
                DetectPortJoin(de_ctx,joingr, gr);
            }
        } else {
            DetectPort *newtmp = DetectPortCopySingle(de_ctx,gr);
            if (newtmp == NULL) {
                goto error;
            }

            if (tmplist2 == NULL) {
                tmplist2 = newtmp;
            } else {
                newtmp->next = tmplist2;
                tmplist2 = newtmp;
            }
        }
        if (i)i--;

        next_gr = gr->next;
        DetectPortFree(gr);
        gr = next_gr;
    }

    /* we now have a tmplist2 containing the 'unique' groups and
     * possibly a joingr that covers the rest. Now build the newhead
     * that we will pass back to the caller.
     *
     * Start with inserting the unique groups */
    for (gr = tmplist2; gr != NULL; ) {
        //printf(":-:7:-: Unique Port "); DetectPortPrint(gr); printf(" (cnt %" PRIu32 ", cost %" PRIu32 ") ", gr->cnt, gr->sh->cost); DbgSghContainsSig(de_ctx,gr->sh,2001330);
        DetectPort *newtmp = DetectPortCopySingle(de_ctx,gr);
        if (newtmp == NULL) {
            goto error;
        }

        DetectPortInsert(de_ctx,newhead,newtmp);

        next_gr = gr->next;
        DetectPortFree(gr);
        gr = next_gr;
    }
    /* if present, insert the joingr that covers the rest */
    if (joingr != NULL) {
        //printf(":-:8:-: Join Port "); DetectPortPrint(joingr); printf(" (cnt %" PRIu32 ", cost %" PRIu32 ") ", joingr->cnt, joingr->sh->cost); DbgSghContainsSig(de_ctx,joingr->sh,2001330);
        DetectPortInsert(de_ctx,newhead,joingr);
    }

    for (gr = *newhead; gr != NULL; gr = gr->next) {
        //printf(":-:9:-: Port "); DetectPortPrint(gr); printf(" (cnt %" PRIu32 ", cost %" PRIu32 ") ", gr->cnt, gr->sh->cost); DbgSghContainsSig(de_ctx,gr->sh,2001330);
        //printf("  -= Port "); DetectPortPrint(gr); printf(" : "); DbgPrintSigs2(gr->sh);
    }

    return 0;
error:
    return -1;
}

/* fill the global src group head, with the sigs included */
int SigAddressPrepareStage2(DetectEngineCtx *de_ctx) {
    Signature *tmp_s = NULL;
    DetectAddressGroup *gr = NULL;
    uint32_t sigs = 0;

    if (!(de_ctx->flags & DE_QUIET)) {
        printf("* Building signature grouping structure, stage 2: "
               "building source address list...\n");
    }

    IPOnlyInit(de_ctx, &de_ctx->io_ctx);

    int ds, f, proto;
    for (ds = 0; ds < DSIZE_STATES; ds++) {
        for (f = 0; f < FLOW_STATES; f++) {
            for (proto = 0; proto < 256; proto++) {
                de_ctx->dsize_gh[ds].flow_gh[f].src_gh[proto] = DetectAddressGroupsHeadInit();
                if (de_ctx->dsize_gh[ds].flow_gh[f].src_gh[proto] == NULL) {
                    goto error;
                }
                de_ctx->dsize_gh[ds].flow_gh[f].tmp_gh[proto] = DetectAddressGroupsHeadInit();
                if (de_ctx->dsize_gh[ds].flow_gh[f].tmp_gh[proto] == NULL) {
                    goto error;
                }
            }
        }
    }

    /* now for every rule add the source group to our temp lists */
    for (tmp_s = de_ctx->sig_list; tmp_s != NULL; tmp_s = tmp_s->next) {
        if (!(tmp_s->flags & SIG_FLAG_IPONLY)) {
            DetectEngineLookupDsizeAddSig(de_ctx, tmp_s, AF_INET);
            DetectEngineLookupDsizeAddSig(de_ctx, tmp_s, AF_INET6);
            DetectEngineLookupDsizeAddSig(de_ctx, tmp_s, AF_UNSPEC);
        } else {
            IPOnlyAddSignature(de_ctx, &de_ctx->io_ctx, tmp_s);
        }

        sigs++;
    }

    /* create the final src addr list based on the tmplist. */
    for (ds = 0; ds < DSIZE_STATES; ds++) {
        for (f = 0; f < FLOW_STATES; f++) {
            for (proto = 0; proto < 256; proto++) {
                int groups = ds ? (f ? MAX_UNIQ_TOSERVER_SRC_GROUPS : MAX_UNIQ_TOCLIENT_SRC_GROUPS) :
                                  (f ? MAX_UNIQ_SMALL_TOSERVER_SRC_GROUPS : MAX_UNIQ_SMALL_TOCLIENT_SRC_GROUPS);

                CreateGroupedAddrList(de_ctx,
                    de_ctx->dsize_gh[ds].flow_gh[f].tmp_gh[proto]->ipv4_head, AF_INET,
                    de_ctx->dsize_gh[ds].flow_gh[f].src_gh[proto], groups,
                    CreateGroupedAddrListCmpMpmMaxlen, DetectEngineGetMaxSigId(de_ctx));
                CreateGroupedAddrList(de_ctx,
                    de_ctx->dsize_gh[ds].flow_gh[f].tmp_gh[proto]->ipv6_head, AF_INET6,
                    de_ctx->dsize_gh[ds].flow_gh[f].src_gh[proto], groups,
                    CreateGroupedAddrListCmpMpmMaxlen, DetectEngineGetMaxSigId(de_ctx));
                CreateGroupedAddrList(de_ctx,
                    de_ctx->dsize_gh[ds].flow_gh[f].tmp_gh[proto]->any_head, AF_UNSPEC,
                    de_ctx->dsize_gh[ds].flow_gh[f].src_gh[proto], groups,
                    CreateGroupedAddrListCmpMpmMaxlen, DetectEngineGetMaxSigId(de_ctx));

                DetectAddressGroupsHeadFree(de_ctx->dsize_gh[ds].flow_gh[f].tmp_gh[proto]);
                de_ctx->dsize_gh[ds].flow_gh[f].tmp_gh[proto] = NULL;
            }
        }
    }
    //DetectAddressGroupPrintMemory();
    //DetectSigGroupPrintMemory();

    //printf("g_src_gh strt\n");
    //DetectAddressGroupPrintList(g_src_gh->ipv4_head);
    //printf("g_src_gh end\n");

    IPOnlyPrepare(de_ctx);
    IPOnlyPrint(de_ctx, &de_ctx->io_ctx);

    if (!(de_ctx->flags & DE_QUIET)) {
        printf("* %" PRIu32 " total signatures:\n", sigs);
        printf(" *         %5u in ipv4 small group, %" PRIu32 " in rest\n", g_detectengine_ip4_small,g_detectengine_ip4_big);
        printf(" *         %5u in ipv6 small group, %" PRIu32 " in rest\n", g_detectengine_ip6_small,g_detectengine_ip6_big);
        printf(" *         %5u in any small group,  %" PRIu32 " in rest\n", g_detectengine_any_small,g_detectengine_any_big);
        printf(" * Small   %5u in ipv4 toserver group, %" PRIu32 " in toclient\n",
            g_detectengine_ip4_small_toserver,g_detectengine_ip4_small_toclient);
        printf(" *         %5u in ipv6 toserver group, %" PRIu32 " in toclient\n",
            g_detectengine_ip6_small_toserver,g_detectengine_ip6_small_toclient);
        printf(" *         %5u in any toserver group,  %" PRIu32 " in toclient\n",
            g_detectengine_any_small_toserver,g_detectengine_any_small_toclient);
        printf(" * Big     %5u in ipv4 toserver group, %" PRIu32 " in toclient\n",
            g_detectengine_ip4_big_toserver,g_detectengine_ip4_big_toclient);
        printf(" *         %5u in ipv6 toserver group, %" PRIu32 " in toclient\n",
            g_detectengine_ip6_big_toserver,g_detectengine_ip6_big_toclient);
        printf(" *         %5u in any toserver group,  %" PRIu32 " in toclient\n",
            g_detectengine_any_big_toserver,g_detectengine_any_big_toclient);
    }

    /* TCP */
    uint32_t cnt_any = 0, cnt_ipv4 = 0, cnt_ipv6 = 0;
    for (ds = 0; ds < DSIZE_STATES; ds++) {
        for (f = 0; f < FLOW_STATES; f++) {
            for (gr = de_ctx->dsize_gh[ds].flow_gh[f].src_gh[6]->any_head; gr != NULL; gr = gr->next) {
                cnt_any++;
            }
        }
    }
    for (ds = 0; ds < DSIZE_STATES; ds++) {
        for (f = 0; f < FLOW_STATES; f++) {
            for (gr = de_ctx->dsize_gh[ds].flow_gh[f].src_gh[6]->ipv4_head; gr != NULL; gr = gr->next) {
                cnt_ipv4++;
            }
        }
    }
    for (ds = 0; ds < DSIZE_STATES; ds++) {
        for (f = 0; f < FLOW_STATES; f++) {
            for (gr = de_ctx->dsize_gh[ds].flow_gh[f].src_gh[6]->ipv6_head; gr != NULL; gr = gr->next) {
                cnt_ipv6++;
            }
        }
    }
    if (!(de_ctx->flags & DE_QUIET)) {
        printf(" * TCP Source address blocks:     any: %4u, ipv4: %4u, ipv6: %4u.\n", cnt_any, cnt_ipv4, cnt_ipv6);
    }

    cnt_any = 0, cnt_ipv4 = 0, cnt_ipv6 = 0;
    for (ds = 0; ds < DSIZE_STATES; ds++) {
        for (f = 0; f < FLOW_STATES; f++) {
            for (gr = de_ctx->dsize_gh[ds].flow_gh[f].src_gh[17]->any_head; gr != NULL; gr = gr->next) {
                cnt_any++;
            }
        }
    }
    for (ds = 0; ds < DSIZE_STATES; ds++) {
        for (f = 0; f < FLOW_STATES; f++) {
            for (gr = de_ctx->dsize_gh[ds].flow_gh[f].src_gh[17]->ipv4_head; gr != NULL; gr = gr->next) {
                cnt_ipv4++;
            }
        }
    }
    for (ds = 0; ds < DSIZE_STATES; ds++) {
        for (f = 0; f < FLOW_STATES; f++) {
            for (gr = de_ctx->dsize_gh[ds].flow_gh[f].src_gh[17]->ipv6_head; gr != NULL; gr = gr->next) {
                cnt_ipv6++;
            }
        }
    }
    if (!(de_ctx->flags & DE_QUIET)) {
        printf(" * UDP Source address blocks:     any: %4u, ipv4: %4u, ipv6: %4u.\n", cnt_any, cnt_ipv4, cnt_ipv6);
    }

    cnt_any = 0, cnt_ipv4 = 0, cnt_ipv6 = 0;
    for (ds = 0; ds < DSIZE_STATES; ds++) {
        for (f = 0; f < FLOW_STATES; f++) {
            for (gr = de_ctx->dsize_gh[ds].flow_gh[f].src_gh[1]->any_head; gr != NULL; gr = gr->next) {
                cnt_any++;
            }
        }
    }
    for (ds = 0; ds < DSIZE_STATES; ds++) {
        for (f = 0; f < FLOW_STATES; f++) {
            for (gr = de_ctx->dsize_gh[ds].flow_gh[f].src_gh[1]->ipv4_head; gr != NULL; gr = gr->next) {
                cnt_ipv4++;
            }
        }
    }
    for (ds = 0; ds < DSIZE_STATES; ds++) {
        for (f = 0; f < FLOW_STATES; f++) {
            for (gr = de_ctx->dsize_gh[ds].flow_gh[f].src_gh[1]->ipv6_head; gr != NULL; gr = gr->next) {
                cnt_ipv6++;
            }
        }
    }
    if (!(de_ctx->flags & DE_QUIET)) {
        printf(" * ICMP Source address blocks:    any: %4u, ipv4: %4u, ipv6: %4u.\n", cnt_any, cnt_ipv4, cnt_ipv6);
    }

    if (!(de_ctx->flags & DE_QUIET)) {
        printf("* Building signature grouping structure, stage 2: building source address list... done\n");
    }

    return 0;
error:
    printf("SigAddressPrepareStage2 error\n");
    return -1;
}

static int BuildDestinationAddressHeads(DetectEngineCtx *de_ctx, DetectAddressGroupsHead *head, int family, int dsize, int flow) {
    Signature *tmp_s = NULL;
    DetectAddressGroup *gr = NULL, *sgr = NULL, *lookup_gr = NULL;
    uint32_t max_idx = 0;

    DetectAddressGroup *grhead = NULL, *grdsthead = NULL, *grsighead = NULL;

    /* based on the family, select the list we are using in the head */
    grhead = GetHeadPtr(head,family);

    /* loop through the global source address list */
    for (gr = grhead; gr != NULL; gr = gr->next) {
        //printf(" * Source group: "); DetectAddressDataPrint(gr->ad); printf("\n");

        /* initialize the destination group head */
        gr->dst_gh = DetectAddressGroupsHeadInit();
        if (gr->dst_gh == NULL) {
            goto error;
        }

        /* use a tmp list for speeding up insertions */
        DetectAddressGroup *tmp_gr_list = NULL;

        /* loop through all signatures in this source address group
         * and build the temporary destination address list for it */
        uint32_t sig;
        for (sig = 0; sig < de_ctx->sig_array_len; sig++) {
            if (!(gr->sh->sig_array[(sig/8)] & (1<<(sig%8))))
                continue;

            tmp_s = de_ctx->sig_array[sig];
            if (tmp_s == NULL)
                continue;

            max_idx = sig;

            /* build the temp list */
            grsighead = GetHeadPtr(&tmp_s->dst, family);
            for (sgr = grsighead; sgr != NULL; sgr = sgr->next) {
                if ((lookup_gr = DetectAddressGroupLookup(tmp_gr_list,sgr->ad)) == NULL) {
                    DetectAddressGroup *grtmp = DetectAddressGroupInit();
                    if (grtmp == NULL) {
                        goto error;
                    }
                    DetectAddressData *adtmp = DetectAddressDataCopy(sgr->ad);
                    if (adtmp == NULL) {
                        goto error;
                    }
                    grtmp->ad = adtmp;

                    DetectAddressGroupAdd(&tmp_gr_list,grtmp);

                    SigGroupHeadAppendSig(de_ctx,&grtmp->sh,tmp_s);
                    grtmp->cnt = 1;
                } else {
                    /* our group will only have one sig, this one. So add that. */
                    SigGroupHeadAppendSig(de_ctx,&lookup_gr->sh,tmp_s);
                    lookup_gr->cnt++;
                }
            }

        }

        /* Create the destination address list, keeping in
         * mind the limits we use. */
        int groups = dsize ? (flow ? MAX_UNIQ_TOSERVER_DST_GROUPS : MAX_UNIQ_TOCLIENT_DST_GROUPS) :
                             (flow ? MAX_UNIQ_SMALL_TOSERVER_DST_GROUPS : MAX_UNIQ_SMALL_TOCLIENT_DST_GROUPS);
        CreateGroupedAddrList(de_ctx, tmp_gr_list, family, gr->dst_gh, groups, CreateGroupedAddrListCmpMpmMaxlen, max_idx);

        /* see if the sig group head of each address group is the
         * same as an earlier one. If it is, free our head and use
         * a pointer to the earlier one. This saves _a lot_ of memory.
         */
        grdsthead = GetHeadPtr(gr->dst_gh, family);
        for (sgr = grdsthead; sgr != NULL; sgr = sgr->next) {
            //printf(" * Destination group: "); DetectAddressDataPrint(sgr->ad); printf("\n");

            /* Because a pattern matcher context uses quite some
             * memory, we first check if we can reuse it from
             * another group head. */
            SigGroupHead *sgh = SigGroupHeadHashLookup(de_ctx, sgr->sh);
            if (sgh == NULL) {
                /* put the contents in our sig group head */
                SigGroupHeadSetSigCnt(sgr->sh, max_idx);
                SigGroupHeadBuildMatchArray(de_ctx,sgr->sh, max_idx);

                /* content */
                SigGroupHeadLoadContent(de_ctx, sgr->sh);
                if (sgr->sh->content_size == 0) {
                    de_ctx->mpm_none++;
                } else {
                    /* now have a look if we can reuse a mpm ctx */
                    SigGroupHead *mpmsh = SigGroupHeadMpmHashLookup(de_ctx, sgr->sh);
                    if (mpmsh == NULL) {
                        SigGroupHeadMpmHashAdd(de_ctx, sgr->sh);

                        de_ctx->mpm_unique++;
                    } else {
                        sgr->sh->mpm_ctx = mpmsh->mpm_ctx;
                        sgr->sh->flags |= SIG_GROUP_HEAD_MPM_COPY;
                        SigGroupHeadClearContent(sgr->sh);

                        de_ctx->mpm_reuse++;
                    }
                }

                /* uricontent */
                SigGroupHeadLoadUricontent(de_ctx, sgr->sh);
                if (sgr->sh->uri_content_size == 0) {
                    de_ctx->mpm_uri_none++;
                } else {
                    /* now have a look if we can reuse a uri mpm ctx */
                    SigGroupHead *mpmsh = SigGroupHeadMpmUriHashLookup(de_ctx, sgr->sh);
                    if (mpmsh == NULL) {
                        SigGroupHeadMpmUriHashAdd(de_ctx, sgr->sh);
                        de_ctx->mpm_uri_unique++;
                    } else {
                        sgr->sh->mpm_uri_ctx = mpmsh->mpm_uri_ctx;
                        sgr->sh->flags |= SIG_GROUP_HEAD_MPM_URI_COPY;
                        SigGroupHeadClearUricontent(sgr->sh);

                        de_ctx->mpm_uri_reuse++;
                    }
                }

                /* init the pattern matcher, this will respect the copy
                 * setting */
                if (PatternMatchPrepareGroup(de_ctx, sgr->sh) < 0) {
                    printf("PatternMatchPrepareGroup failed\n");
                    goto error;
                }
                if (sgr->sh->mpm_ctx != NULL) {
                    if (de_ctx->mpm_max_patcnt < sgr->sh->mpm_ctx->pattern_cnt)
                        de_ctx->mpm_max_patcnt = sgr->sh->mpm_ctx->pattern_cnt;

                    de_ctx->mpm_tot_patcnt += sgr->sh->mpm_ctx->pattern_cnt;
                }
                if (sgr->sh->mpm_uri_ctx != NULL) {
                    if (de_ctx->mpm_uri_max_patcnt < sgr->sh->mpm_uri_ctx->pattern_cnt)
                        de_ctx->mpm_uri_max_patcnt = sgr->sh->mpm_uri_ctx->pattern_cnt;

                    de_ctx->mpm_uri_tot_patcnt += sgr->sh->mpm_uri_ctx->pattern_cnt;
                }
                /* dbg */
                if (!(sgr->sh->flags & SIG_GROUP_HEAD_MPM_COPY) && sgr->sh->mpm_ctx) {
                    de_ctx->mpm_memory_size += sgr->sh->mpm_ctx->memory_size;
                }
                if (!(sgr->sh->flags & SIG_GROUP_HEAD_MPM_URI_COPY) && sgr->sh->mpm_uri_ctx) {
                    de_ctx->mpm_memory_size += sgr->sh->mpm_uri_ctx->memory_size;
                }

                SigGroupHeadHashAdd(de_ctx, sgr->sh);
                de_ctx->gh_unique++;
            } else {
                SigGroupHeadFree(sgr->sh);
                sgr->sh = sgh;

                de_ctx->gh_reuse++;
                sgr->flags |= ADDRESS_GROUP_SIGGROUPHEAD_COPY;
            }
        }

        /* free the temp list */
        DetectAddressGroupCleanupList(tmp_gr_list);
        /* clear now unneeded sig group head */
        SigGroupHeadFree(gr->sh);
        gr->sh = NULL;
    }

    return 0;
error:
    return -1;
}

static int BuildDestinationAddressHeadsWithBothPorts(DetectEngineCtx *de_ctx, DetectAddressGroupsHead *head, int family, int dsize, int flow) {
    Signature *tmp_s = NULL;
    DetectAddressGroup *src_gr = NULL, *dst_gr = NULL, *sig_gr = NULL, *lookup_gr = NULL;
    DetectAddressGroup *src_gr_head = NULL, *dst_gr_head = NULL, *sig_gr_head = NULL;
    uint32_t max_idx = 0;

    /* loop through the global source address list */
    src_gr_head = GetHeadPtr(head,family);
    for (src_gr = src_gr_head; src_gr != NULL; src_gr = src_gr->next) {
        //printf(" * Source group: "); DetectAddressDataPrint(src_gr->ad); printf("\n");

        /* initialize the destination group head */
        src_gr->dst_gh = DetectAddressGroupsHeadInit();
        if (src_gr->dst_gh == NULL) {
            goto error;
        }

        /* use a tmp list for speeding up insertions */
        DetectAddressGroup *tmp_gr_list = NULL;

        /* loop through all signatures in this source address group
         * and build the temporary destination address list for it */
        uint32_t sig;
        for (sig = 0; sig < de_ctx->sig_array_len; sig++) {
            if (!(src_gr->sh->sig_array[(sig/8)] & (1<<(sig%8))))
                continue;

            tmp_s = de_ctx->sig_array[sig];
            if (tmp_s == NULL)
                continue;

            //printf(" * Source group: "); DetectAddressDataPrint(src_gr->ad); printf("\n");

            max_idx = sig;

            /* build the temp list */
            sig_gr_head = GetHeadPtr(&tmp_s->dst,family);
            for (sig_gr = sig_gr_head; sig_gr != NULL; sig_gr = sig_gr->next) {
                //printf("  * Sig dst addr: "); DetectAddressDataPrint(sig_gr->ad); printf("\n");

                if ((lookup_gr = DetectAddressGroupLookup(tmp_gr_list, sig_gr->ad)) == NULL) {
                    DetectAddressGroup *grtmp = DetectAddressGroupInit();
                    if (grtmp == NULL) {
                        goto error;
                    }
                    DetectAddressData *adtmp = DetectAddressDataCopy(sig_gr->ad);
                    if (adtmp == NULL) {
                        goto error;
                    }
                    grtmp->ad = adtmp;
                    SigGroupHeadAppendSig(de_ctx, &grtmp->sh, tmp_s);
                    grtmp->cnt = 1;

                    DetectAddressGroupAdd(&tmp_gr_list,grtmp);
                } else {
                    /* our group will only have one sig, this one. So add that. */
                    SigGroupHeadAppendSig(de_ctx, &lookup_gr->sh, tmp_s);
                    lookup_gr->cnt++;
                }

                SigGroupHeadFree(sig_gr->sh);
                sig_gr->sh = NULL;
            }
        }

        /* Create the destination address list, keeping in
         * mind the limits we use. */
        int groups = dsize ? (flow ? MAX_UNIQ_TOSERVER_DST_GROUPS : MAX_UNIQ_TOCLIENT_DST_GROUPS) :
                             (flow ? MAX_UNIQ_SMALL_TOSERVER_DST_GROUPS : MAX_UNIQ_SMALL_TOCLIENT_DST_GROUPS);
        CreateGroupedAddrList(de_ctx, tmp_gr_list, family, src_gr->dst_gh, groups, CreateGroupedAddrListCmpMpmMaxlen, max_idx);

        /* add the ports to the dst address groups and the sigs
         * to the ports */
        dst_gr_head = GetHeadPtr(src_gr->dst_gh,family);
        for (dst_gr = dst_gr_head; dst_gr != NULL; dst_gr = dst_gr->next) {
            //printf("  * Destination group: "); DetectAddressDataPrint(dst_gr->ad); printf("\n");

            if (dst_gr->sh == NULL)
                continue;

            /* we will reuse address sig group heads at this points,
             * because if the sigs are the same, the ports will be
             * the same. Saves memory and a lot of init time. */
            SigGroupHead *lookup_sgh = SigGroupHeadHashLookup(de_ctx, dst_gr->sh);
            if (lookup_sgh == NULL) {
                DetectPortSpHashReset(de_ctx);

                uint32_t sig2;
                for (sig2 = 0; sig2 < max_idx+1; sig2++) {
                    if (!(dst_gr->sh->sig_array[(sig2/8)] & (1<<(sig2%8))))
                        continue;

                    Signature *s = de_ctx->sig_array[sig2];
                    if (s == NULL)
                        continue;

                    //printf("  + Destination group (grouped): "); DetectAddressDataPrint(dst_gr->ad); printf("\n");

                    DetectPort *sdp = s->sp;
                    for ( ; sdp != NULL; sdp = sdp->next) {
                        DetectPort *lookup_port = DetectPortSpHashLookup(de_ctx, sdp);
                        if (lookup_port == NULL) {
                            DetectPort *port = DetectPortCopySingle(de_ctx,sdp);
                            if (port == NULL)
                                goto error;

                            SigGroupHeadAppendSig(de_ctx, &port->sh, s);
                            DetectPortSpHashAdd(de_ctx, port);
                            port->cnt = 1;
                        } else {
                            SigGroupHeadAppendSig(de_ctx, &lookup_port->sh, s);
                            lookup_port->cnt++;
                        }
                    }
                }

                int spgroups = dsize ? (flow ? MAX_UNIQ_TOSERVER_SP_GROUPS : MAX_UNIQ_TOCLIENT_SP_GROUPS) :
                                       (flow ? MAX_UNIQ_SMALL_TOSERVER_SP_GROUPS : MAX_UNIQ_SMALL_TOCLIENT_SP_GROUPS);
                CreateGroupedPortList(de_ctx, de_ctx->sport_hash_table, &dst_gr->port, spgroups, CreateGroupedPortListCmpMpmMaxlen, max_idx);
                dst_gr->flags |= ADDRESS_GROUP_HAVEPORT;

                SigGroupHeadHashAdd(de_ctx, dst_gr->sh);

                dst_gr->sh->port = dst_gr->port;
                /* mark this head for deletion once we no longer need
                 * the hash. We're only using the port ptr, so no problem
                 * when we remove this after initialization is done */
                dst_gr->sh->flags |= SIG_GROUP_HEAD_FREE;

                /* for each destination port we setup the siggrouphead here */
                DetectPort *sp = dst_gr->port;
                for ( ; sp != NULL; sp = sp->next) {
                    //printf("   * Src Port(range): "); DetectPortPrint(sp); printf("\n");

                    if (sp->sh == NULL)
                        continue;

                    /* we will reuse address sig group heads at this points,
                     * because if the sigs are the same, the ports will be
                     * the same. Saves memory and a lot of init time. */
                    SigGroupHead *lookup_sp_sgh = SigGroupHeadSPortHashLookup(de_ctx, sp->sh);
                    if (lookup_sp_sgh == NULL) {
                        DetectPortDpHashReset(de_ctx);
                        uint32_t sig2;
                        for (sig2 = 0; sig2 < max_idx+1; sig2++) {
                            if (!(sp->sh->sig_array[(sig2/8)] & (1<<(sig2%8))))
                                continue;

                            Signature *s = de_ctx->sig_array[sig2];
                            if (s == NULL)
                                continue;

                            DetectPort *sdp = s->dp;
                            for ( ; sdp != NULL; sdp = sdp->next) {
                                DetectPort *lookup_port = DetectPortDpHashLookup(de_ctx,sdp);
                                if (lookup_port == NULL) {
                                    DetectPort *port = DetectPortCopySingle(de_ctx,sdp);
                                    if (port == NULL)
                                        goto error;

                                    SigGroupHeadAppendSig(de_ctx, &port->sh, s);
                                    DetectPortDpHashAdd(de_ctx,port);
                                    port->cnt = 1;
                                } else {
                                    SigGroupHeadAppendSig(de_ctx, &lookup_port->sh, s);
                                    lookup_port->cnt++;
                                }
                            }
                        }

                        int dpgroups = dsize ? (flow ? MAX_UNIQ_TOSERVER_DP_GROUPS : MAX_UNIQ_TOCLIENT_DP_GROUPS) :
                                               (flow ? MAX_UNIQ_SMALL_TOSERVER_DP_GROUPS : MAX_UNIQ_SMALL_TOCLIENT_DP_GROUPS);
                        CreateGroupedPortList(de_ctx, de_ctx->dport_hash_table, 
                            &sp->dst_ph, dpgroups,
                            CreateGroupedPortListCmpMpmMaxlen, max_idx);

                        SigGroupHeadSPortHashAdd(de_ctx, sp->sh);

                        sp->sh->port = sp->dst_ph;
                        /* mark this head for deletion once we no longer need
                         * the hash. We're only using the port ptr, so no problem
                         * when we remove this after initialization is done */
                        sp->sh->flags |= SIG_GROUP_HEAD_FREE;

                        /* for each destination port we setup the siggrouphead here */
                        DetectPort *dp = sp->dst_ph;
                        for ( ; dp != NULL; dp = dp->next) {
                            //printf("   * Dst Port(range): "); DetectPortPrint(dp); printf(" ");
                            //printf("\n");

                            if (dp->sh == NULL)
                                continue;

                            /* Because a pattern matcher context uses quite some
                             * memory, we first check if we can reuse it from
                             * another group head. */
                            SigGroupHead *lookup_dp_sgh = SigGroupHeadDPortHashLookup(de_ctx, dp->sh);
                            if (lookup_dp_sgh == NULL) {
                                SigGroupHeadSetSigCnt(dp->sh, max_idx);
                                SigGroupHeadBuildMatchArray(de_ctx,dp->sh, max_idx);

                                SigGroupHeadLoadContent(de_ctx, dp->sh);
                                if (dp->sh->content_size == 0) {
                                    de_ctx->mpm_none++;
                                } else {
                                    /* now have a look if we can reuse a mpm ctx */
                                    SigGroupHead *mpmsh = SigGroupHeadMpmHashLookup(de_ctx, dp->sh);
                                    if (mpmsh == NULL) {
                                        SigGroupHeadMpmHashAdd(de_ctx, dp->sh);

                                        de_ctx->mpm_unique++;
                                    } else {
                                        /* XXX write dedicated function for this */
                                        dp->sh->mpm_ctx = mpmsh->mpm_ctx;
                                        if (mpmsh->flags & SIG_GROUP_HEAD_MPM_NOSCAN)
                                            dp->sh->flags |= SIG_GROUP_HEAD_MPM_NOSCAN;
                                        dp->sh->mpm_content_maxlen = mpmsh->mpm_content_maxlen;
                                        dp->sh->flags |= SIG_GROUP_HEAD_MPM_COPY;
                                        SigGroupHeadClearContent(dp->sh);

                                        de_ctx->mpm_reuse++;
                                    }
                                }

                                SigGroupHeadLoadUricontent(de_ctx, dp->sh);
                                if (dp->sh->uri_content_size == 0) {
                                    de_ctx->mpm_uri_none++;
                                } else {
                                    /* now have a look if we can reuse a uri mpm ctx */
                                    SigGroupHead *mpmsh = SigGroupHeadMpmUriHashLookup(de_ctx, dp->sh);
                                    if (mpmsh == NULL) {
                                        SigGroupHeadMpmUriHashAdd(de_ctx, dp->sh);

                                        de_ctx->mpm_uri_unique++;
                                    } else {
                                        dp->sh->mpm_uri_ctx = mpmsh->mpm_uri_ctx;
                                        dp->sh->flags |= SIG_GROUP_HEAD_MPM_URI_COPY;
                                        SigGroupHeadClearUricontent(dp->sh);

                                        de_ctx->mpm_uri_reuse++;
                                    }
                                }

                                /* init the pattern matcher, this will respect the copy
                                 * setting */
                                if (PatternMatchPrepareGroup(de_ctx, dp->sh) < 0) {
                                    printf("PatternMatchPrepareGroup failed\n");
                                    goto error;
                                }
                                if (dp->sh->mpm_ctx != NULL) {
                                    if (de_ctx->mpm_max_patcnt < dp->sh->mpm_ctx->pattern_cnt)
                                        de_ctx->mpm_max_patcnt = dp->sh->mpm_ctx->pattern_cnt;

                                    de_ctx->mpm_tot_patcnt += dp->sh->mpm_ctx->pattern_cnt;
                                }
                                if (dp->sh->mpm_uri_ctx != NULL) {
                                    if (de_ctx->mpm_uri_max_patcnt < dp->sh->mpm_uri_ctx->pattern_cnt)
                                        de_ctx->mpm_uri_max_patcnt = dp->sh->mpm_uri_ctx->pattern_cnt;

                                    de_ctx->mpm_uri_tot_patcnt += dp->sh->mpm_uri_ctx->pattern_cnt;
                                }
                                /* dbg */
                                if (!(dp->sh->flags & SIG_GROUP_HEAD_MPM_COPY) && dp->sh->mpm_ctx) {
                                    de_ctx->mpm_memory_size += dp->sh->mpm_ctx->memory_size;
                                }
                                if (!(dp->sh->flags & SIG_GROUP_HEAD_MPM_URI_COPY) && dp->sh->mpm_uri_ctx) {
                                    de_ctx->mpm_memory_size += dp->sh->mpm_uri_ctx->memory_size;
                                }

                                SigGroupHeadDPortHashAdd(de_ctx, dp->sh);
                                de_ctx->gh_unique++;
                            } else {
                                SigGroupHeadFree(dp->sh);

                                dp->sh = lookup_dp_sgh;
                                dp->flags |= PORT_SIGGROUPHEAD_COPY;

                                de_ctx->gh_reuse++;
                            }
                        }
                    /* sig group head found in hash, free it and use the hashed one */
                    } else {
                        SigGroupHeadFree(sp->sh);

                        sp->sh = lookup_sp_sgh;
                        sp->flags |= PORT_SIGGROUPHEAD_COPY;

                        sp->dst_ph = lookup_sp_sgh->port;
                        sp->flags |= PORT_GROUP_PORTS_COPY;

                        de_ctx->gh_reuse++;
                    }
                }
            } else {
                SigGroupHeadFree(dst_gr->sh);

                dst_gr->sh = lookup_sgh;
                dst_gr->flags |= ADDRESS_GROUP_SIGGROUPHEAD_COPY;

                dst_gr->port = lookup_sgh->port;
                dst_gr->flags |= PORT_GROUP_PORTS_COPY;

                de_ctx->gh_reuse++;
            }
        }
        /* free the temp list */
        DetectAddressGroupCleanupList(tmp_gr_list);
        /* clear now unneeded sig group head */
        SigGroupHeadFree(src_gr->sh);
        src_gr->sh = NULL;
    }

    return 0;
error:
    return -1;
}

int SigAddressPrepareStage3(DetectEngineCtx *de_ctx) {
    int r;

    if (!(de_ctx->flags & DE_QUIET)) {
        printf("* Building signature grouping structure, stage 3: "
               "building destination address lists...\n");
    }
    //DetectAddressGroupPrintMemory();
    //DetectSigGroupPrintMemory();
    //DetectPortPrintMemory();

    int ds, f, proto;
    for (ds = 0; ds < DSIZE_STATES; ds++) {
        for (f = 0; f < FLOW_STATES; f++) {
            r = BuildDestinationAddressHeadsWithBothPorts(de_ctx, de_ctx->dsize_gh[ds].flow_gh[f].src_gh[6],AF_INET,ds,f);
            if (r < 0) {
                printf ("BuildDestinationAddressHeads(src_gh[6],AF_INET) failed\n");
                goto error;
            }
            r = BuildDestinationAddressHeadsWithBothPorts(de_ctx, de_ctx->dsize_gh[ds].flow_gh[f].src_gh[17],AF_INET,ds,f);
            if (r < 0) {
                printf ("BuildDestinationAddressHeads(src_gh[17],AF_INET) failed\n");
                goto error;
            }
            r = BuildDestinationAddressHeadsWithBothPorts(de_ctx, de_ctx->dsize_gh[ds].flow_gh[f].src_gh[6],AF_INET6,ds,f);
            if (r < 0) {
                printf ("BuildDestinationAddressHeads(src_gh[6],AF_INET) failed\n");
                goto error;
            }
            r = BuildDestinationAddressHeadsWithBothPorts(de_ctx, de_ctx->dsize_gh[ds].flow_gh[f].src_gh[17],AF_INET6,ds,f);
            if (r < 0) {
                printf ("BuildDestinationAddressHeads(src_gh[17],AF_INET) failed\n");
                goto error;
            }
            r = BuildDestinationAddressHeadsWithBothPorts(de_ctx, de_ctx->dsize_gh[ds].flow_gh[f].src_gh[6],AF_UNSPEC,ds,f);
            if (r < 0) {
                printf ("BuildDestinationAddressHeads(src_gh[6],AF_INET) failed\n");
                goto error;
            }
            r = BuildDestinationAddressHeadsWithBothPorts(de_ctx, de_ctx->dsize_gh[ds].flow_gh[f].src_gh[17],AF_UNSPEC,ds,f);
            if (r < 0) {
                printf ("BuildDestinationAddressHeads(src_gh[17],AF_INET) failed\n");
                goto error;
            }

            for (proto = 0; proto < 256; proto++) {
                if (proto == IPPROTO_TCP || proto == IPPROTO_UDP)
                    continue;

                r = BuildDestinationAddressHeads(de_ctx, de_ctx->dsize_gh[ds].flow_gh[f].src_gh[proto],AF_INET,ds,f);
                if (r < 0) {
                    printf ("BuildDestinationAddressHeads(src_gh[%" PRId32 "],AF_INET) failed\n", proto);
                    goto error;
                }
                r = BuildDestinationAddressHeads(de_ctx, de_ctx->dsize_gh[ds].flow_gh[f].src_gh[proto],AF_INET6,ds,f);
                if (r < 0) {
                    printf ("BuildDestinationAddressHeads(src_gh[%" PRId32 "],AF_INET6) failed\n", proto);
                    goto error;
                }
                r = BuildDestinationAddressHeads(de_ctx, de_ctx->dsize_gh[ds].flow_gh[f].src_gh[proto],AF_UNSPEC,ds,f); /* for any */
                if (r < 0) {
                    printf ("BuildDestinationAddressHeads(src_gh[%" PRId32 "],AF_UNSPEC) failed\n", proto);
                    goto error;
                }
            }
        }
    }

    /* cleanup group head (uri)content_array's */
    SigGroupHeadFreeMpmArrays(de_ctx);
    /* cleanup group head sig arrays */
    SigGroupHeadFreeSigArrays(de_ctx);
    /* cleanup heads left over in *WithPorts */
    /* XXX VJ breaks SigGroupCleanup */
    //SigGroupHeadFreeHeads();

    /* cleanup the hashes now since we won't need them
     * after the initialization phase. */
    SigGroupHeadHashFree(de_ctx);
    SigGroupHeadDPortHashFree(de_ctx);
    SigGroupHeadSPortHashFree(de_ctx);
    SigGroupHeadMpmHashFree(de_ctx);
    SigGroupHeadMpmUriHashFree(de_ctx);
    DetectPortDpHashFree(de_ctx);
    DetectPortSpHashFree(de_ctx);

    if (!(de_ctx->flags & DE_QUIET)) {
        printf("* MPM memory %" PRIuMAX " (dynamic %" PRIu32 ", ctxs %" PRIuMAX ", avg per ctx %" PRIu32 ")\n",
            de_ctx->mpm_memory_size + ((de_ctx->mpm_unique + de_ctx->mpm_uri_unique) * (uintmax_t)sizeof(MpmCtx)),
            de_ctx->mpm_memory_size, ((de_ctx->mpm_unique + de_ctx->mpm_uri_unique) * (uintmax_t)sizeof(MpmCtx)),
            de_ctx->mpm_unique ? de_ctx->mpm_memory_size / de_ctx->mpm_unique: 0);

        printf(" * Max sig id %" PRIu32 ", array size %" PRIu32 "\n", DetectEngineGetMaxSigId(de_ctx), DetectEngineGetMaxSigId(de_ctx) / 8 + 1);
        printf("* Signature group heads: unique %" PRIu32 ", copies %" PRIu32 ".\n", de_ctx->gh_unique, de_ctx->gh_reuse);
        printf("* MPM instances: %" PRIu32 " unique, copies %" PRIu32 " (none %" PRIu32 ").\n",
                de_ctx->mpm_unique, de_ctx->mpm_reuse, de_ctx->mpm_none);
        printf("* MPM (URI) instances: %" PRIu32 " unique, copies %" PRIu32 " (none %" PRIu32 ").\n",
                de_ctx->mpm_uri_unique, de_ctx->mpm_uri_reuse, de_ctx->mpm_uri_none);
        printf("* MPM max patcnt %" PRIu32 ", avg %" PRIu32 "\n", de_ctx->mpm_max_patcnt, de_ctx->mpm_unique?de_ctx->mpm_tot_patcnt/de_ctx->mpm_unique:0);
        if (de_ctx->mpm_uri_tot_patcnt && de_ctx->mpm_uri_unique)
            printf("* MPM (URI) max patcnt %" PRIu32 ", avg %" PRIu32 " (%" PRIu32 "/%" PRIu32 ")\n", de_ctx->mpm_uri_max_patcnt, de_ctx->mpm_uri_tot_patcnt/de_ctx->mpm_uri_unique, de_ctx->mpm_uri_tot_patcnt, de_ctx->mpm_uri_unique);
        printf("  = port maxgroups: %" PRIu32 ", avg %" PRIu32 ", tot %" PRIu32 "\n", g_groupportlist_maxgroups, g_groupportlist_totgroups/g_groupportlist_groupscnt, g_groupportlist_totgroups);
        printf("* Building signature grouping structure, stage 3: building destination address lists... done\n");
    }
    return 0;
error:
    printf("SigAddressPrepareStage3 error\n");
    return -1;
}

int SigAddressCleanupStage1(DetectEngineCtx *de_ctx) {
    if (!(de_ctx->flags & DE_QUIET)) {
        printf("* Cleaning up signature grouping structure, stage 1...\n");
    }

    int ds, f, proto;
    for (ds = 0; ds < DSIZE_STATES; ds++) {
        for (f = 0; f < FLOW_STATES; f++) {
            for (proto = 0; proto < 256; proto++) {
                /* XXX fix this */
                DetectAddressGroupsHeadFree(de_ctx->dsize_gh[ds].flow_gh[f].src_gh[proto]);
                de_ctx->dsize_gh[ds].flow_gh[f].src_gh[proto] = NULL;
            }
        }
    }

    IPOnlyDeinit(de_ctx, &de_ctx->io_ctx);

    if (!(de_ctx->flags & DE_QUIET)) {
        printf("* Cleaning up signature grouping structure, stage 1... done\n");
    }
    return 0;
}

void DbgPrintSigs(DetectEngineCtx *de_ctx, SigGroupHead *sgh) {
    if (sgh == NULL) {
        printf("\n");
        return;
    }

    uint32_t sig;
    for (sig = 0; sig < sgh->sig_cnt; sig++) {
        printf("%" PRIu32 " ", de_ctx->sig_array[sgh->match_array[sig]]->id);
    }
    printf("\n");
}

void DbgPrintSigs2(DetectEngineCtx *de_ctx, SigGroupHead *sgh) {
    if (sgh == NULL) {
        printf("\n");
        return;
    }

    uint32_t sig;
    for (sig = 0; sig < DetectEngineGetMaxSigId(de_ctx); sig++) {
        if (sgh->sig_array[(sig/8)] & (1<<(sig%8))) {
            printf("%" PRIu32 " ", de_ctx->sig_array[sig]->id);
        }
    }
    printf("\n");
}

void DbgSghContainsSig(DetectEngineCtx *de_ctx, SigGroupHead *sgh, uint32_t sid) {
    if (sgh == NULL) {
        printf("\n");
        return;
    }

    uint32_t sig;
    for (sig = 0; sig < DetectEngineGetMaxSigId(de_ctx); sig++) {
        if (!(sgh->sig_array[(sig/8)] & (1<<(sig%8))))
            continue;

        Signature *s = de_ctx->sig_array[sig];
        if (s == NULL)
            continue;

        if (sid == s->id) {
            printf("%" PRIu32 " ", de_ctx->sig_array[sig]->id);
        }
    }
    printf("\n");
}

/* shortcut for debugging. If enabled Stage5 will
 * print sigid's for all groups */
//#define PRINTSIGS

/* just printing */
int SigAddressPrepareStage5(DetectEngineCtx *de_ctx) {
    DetectAddressGroupsHead *global_dst_gh = NULL;
    DetectAddressGroup *global_src_gr = NULL, *global_dst_gr = NULL;
    int i;

    printf("* Building signature grouping structure, stage 5: print...\n");

    int ds, f, proto;
    for (ds = 0; ds < DSIZE_STATES; ds++) {
        for (f = 0; f < FLOW_STATES; f++) {
            for (proto = 0; proto < 256; proto++) {
                if (proto != 6)
                    continue;

                for (global_src_gr = de_ctx->dsize_gh[ds].flow_gh[f].src_gh[proto]->ipv4_head; global_src_gr != NULL;
                        global_src_gr = global_src_gr->next)
                {
                    printf("1 Src Addr: "); DetectAddressDataPrint(global_src_gr->ad);
                    //printf(" (sh %p)\n", global_src_gr->sh);
                    printf("\n");

                    global_dst_gh = global_src_gr->dst_gh;
                    if (global_dst_gh == NULL)
                        continue;

                    for (global_dst_gr = global_dst_gh->ipv4_head;
                            global_dst_gr != NULL;
                            global_dst_gr = global_dst_gr->next)
                    {
                        printf(" 2 Dst Addr: "); DetectAddressDataPrint(global_dst_gr->ad);
                        //printf(" (sh %p) ", global_dst_gr->sh);
                        if (global_dst_gr->sh) {
                            if (global_dst_gr->sh->flags & ADDRESS_GROUP_SIGGROUPHEAD_COPY) {
                                printf("(COPY)\n");
                            } else {
                                printf("\n");
                            }
                        }
                        DetectPort *sp = global_dst_gr->port;
                        for ( ; sp != NULL; sp = sp->next) {
                            printf("  3 Src port(range): "); DetectPortPrint(sp);
                            //printf(" (sh %p)", sp->sh);
                            printf("\n");
                            DetectPort *dp = sp->dst_ph;
                            for ( ; dp != NULL; dp = dp->next) {
                                printf("   4 Dst port(range): "); DetectPortPrint(dp);
                                printf(" (sigs %" PRIu32 ", maxlen %" PRIu32 ")", dp->sh->sig_cnt, dp->sh->mpm_content_maxlen);
#ifdef PRINTSIGS
                                printf(" - ");
                                for (i = 0; i < dp->sh->sig_cnt; i++) {
                                    Signature *s = de_ctx->sig_array[dp->sh->match_array[i]];
                                    printf("%" PRIu32 " ", s->id);
                                }
#endif
                                printf(" - ");
                                for (i = 0; i < dp->sh->sig_cnt; i++) {
                                    Signature *s = de_ctx->sig_array[dp->sh->match_array[i]];
                                    if (s->id == 2008335 || s->id == 2001329 || s->id == 2001330 ||
                                            s->id == 2001331 || s->id == 2003321 || s->id == 2003322)
                                        printf("%" PRIu32 " ", s->id);
                                }
                                printf("\n");
                            }
                        }
                    }
                    for (global_dst_gr = global_dst_gh->any_head;
                            global_dst_gr != NULL;
                            global_dst_gr = global_dst_gr->next)
                    {
                        printf(" - "); DetectAddressDataPrint(global_dst_gr->ad);
                        //printf(" (sh %p) ", global_dst_gr->sh);
                        if (global_dst_gr->sh) {
                            if (global_dst_gr->sh->flags & ADDRESS_GROUP_SIGGROUPHEAD_COPY) {
                                printf("(COPY)\n");
                            } else {
                                printf("\n");
                            }
                        }
                        DetectPort *sp = global_dst_gr->port;
                        for ( ; sp != NULL; sp = sp->next) {
                            printf("  * Src port(range): "); DetectPortPrint(sp); printf("\n");
                            DetectPort *dp = sp->dst_ph;
                            for ( ; dp != NULL; dp = dp->next) {
                                printf("   * Dst port(range): "); DetectPortPrint(dp);
                                printf(" (sigs %" PRIu32 ")", dp->sh->sig_cnt);
#ifdef PRINTSIGS
                                printf(" - ");
                                for (i = 0; i < dp->sh->sig_cnt; i++) {
                                    Signature *s = de_ctx->sig_array[dp->sh->match_array[i]];
                                    printf("%" PRIu32 " ", s->id);
                                }
#endif
                                printf("\n");
                            }
                        }
                    }
                }
#if 0
                for (global_src_gr = de_ctx->src_gh[proto]->ipv6_head; global_src_gr != NULL;
                        global_src_gr = global_src_gr->next)
                {
                    printf("- "); DetectAddressDataPrint(global_src_gr->ad);
                    //printf(" (sh %p)\n", global_src_gr->sh);

                    global_dst_gh = global_src_gr->dst_gh;
                    if (global_dst_gh == NULL)
                        continue;

                    for (global_dst_gr = global_dst_gh->ipv6_head;
                            global_dst_gr != NULL;
                            global_dst_gr = global_dst_gr->next)
                    {
                        printf(" - "); DetectAddressDataPrint(global_dst_gr->ad);
                        //printf(" (sh %p) ", global_dst_gr->sh);
                        if (global_dst_gr->sh) {
                            if (global_dst_gr->sh->flags & ADDRESS_GROUP_SIGGROUPHEAD_COPY) {
                                printf("(COPY)\n");
                            } else {
                                printf("\n");
                            }
                        }
                        DetectPort *sp = global_dst_gr->port;
                        for ( ; sp != NULL; sp = sp->next) {
                            printf("  * Src port(range): "); DetectPortPrint(sp); printf("\n");
                            DetectPort *dp = sp->dst_ph;
                            for ( ; dp != NULL; dp = dp->next) {
                                printf("   * Dst port(range): "); DetectPortPrint(dp);
                                printf(" (sigs %" PRIu32 ")", dp->sh->sig_cnt);
#ifdef PRINTSIGS
                                printf(" - ");
                                for (i = 0; i < dp->sh->sig_cnt; i++) {
                                    Signature *s = de_ctx->sig_array[dp->sh->match_array[i]];
                                    printf("%" PRIu32 " ", s->id);
                                }
#endif
                                printf("\n");
                            }
                        }
                    }
                    for (global_dst_gr = global_dst_gh->any_head;
                            global_dst_gr != NULL;
                            global_dst_gr = global_dst_gr->next)
                    {
                        printf(" - "); DetectAddressDataPrint(global_dst_gr->ad);
                        //printf(" (sh %p) ", global_dst_gr->sh);
                        if (global_dst_gr->sh) {
                            if (global_dst_gr->sh->flags & ADDRESS_GROUP_SIGGROUPHEAD_COPY) {
                                printf("(COPY)\n");
                            } else {
                                printf("\n");
                            }
                        }
                        DetectPort *sp = global_dst_gr->port;
                        for ( ; sp != NULL; sp = sp->next) {
                            printf("  * Src port(range): "); DetectPortPrint(sp); printf("\n");
                            DetectPort *dp = sp->dst_ph;
                            for ( ; dp != NULL; dp = dp->next) {
                                printf("   * Dst port(range): "); DetectPortPrint(dp);
                                printf(" (sigs %" PRIu32 ")", dp->sh->sig_cnt);
#ifdef PRINTSIGS
                                printf(" - ");
                                for (i = 0; i < dp->sh->sig_cnt; i++) {
                                    Signature *s = de_ctx->sig_array[dp->sh->match_array[i]];
                                    printf("%" PRIu32 " ", s->id);
                                }
#endif
                                printf("\n");
                            }
                        }
                    }
                }

                for (global_src_gr = de_ctx->src_gh[proto]->any_head; global_src_gr != NULL;
                        global_src_gr = global_src_gr->next)
                {
                    printf("- "); DetectAddressDataPrint(global_src_gr->ad);
                    //printf(" (sh %p)\n", global_src_gr->sh);

                    global_dst_gh = global_src_gr->dst_gh;
                    if (global_dst_gh == NULL)
                        continue;

                    for (global_dst_gr = global_dst_gh->any_head;
                            global_dst_gr != NULL;
                            global_dst_gr = global_dst_gr->next)
                    {
                        printf(" - "); DetectAddressDataPrint(global_dst_gr->ad);
                        //printf(" (sh %p) ", global_dst_gr->sh);
                        if (global_dst_gr->sh) {
                            if (global_dst_gr->sh->flags & ADDRESS_GROUP_SIGGROUPHEAD_COPY) {
                                printf("(COPY)\n");
                            } else {
                                printf("\n");
                            }
                        }
                        DetectPort *sp = global_dst_gr->port;
                        for ( ; sp != NULL; sp = sp->next) {
                            printf("  * Src port(range): "); DetectPortPrint(sp); printf("\n");
                            DetectPort *dp = sp->dst_ph;
                            for ( ; dp != NULL; dp = dp->next) {
                                printf("   * Dst port(range): "); DetectPortPrint(dp);
                                printf(" (sigs %" PRIu32 ")", dp->sh->sig_cnt);
#ifdef PRINTSIGS
                                printf(" - ");
                                for (i = 0; i < dp->sh->sig_cnt; i++) {
                                    Signature *s = de_ctx->sig_array[dp->sh->match_array[i]];
                                    printf("%" PRIu32 " ", s->id);
                                }
#endif
                                printf("\n");
                            }
                        }
                    } 
                    for (global_dst_gr = global_dst_gh->ipv4_head;
                            global_dst_gr != NULL;
                            global_dst_gr = global_dst_gr->next)
                    {
                        printf(" - "); DetectAddressDataPrint(global_dst_gr->ad);
                        //printf(" (sh %p) ", global_dst_gr->sh);
                        if (global_dst_gr->sh) {
                            if (global_dst_gr->sh->flags & ADDRESS_GROUP_SIGGROUPHEAD_COPY) {
                                printf("(COPY)\n");
                            } else {
                                printf("\n");
                            }
                        }
                        DetectPort *sp = global_dst_gr->port;
                        for ( ; sp != NULL; sp = sp->next) {
                            printf("  * Src port(range): "); DetectPortPrint(sp); printf("\n");
                            DetectPort *dp = sp->dst_ph;
                            for ( ; dp != NULL; dp = dp->next) {
                                printf("   * Dst port(range): "); DetectPortPrint(dp);
                                printf(" (sigs %" PRIu32 ")", dp->sh->sig_cnt);
#ifdef PRINTSIGS
                                printf(" - ");
                                for (i = 0; i < dp->sh->sig_cnt; i++) {
                                    Signature *s = de_ctx->sig_array[dp->sh->match_array[i]];
                                    printf("%" PRIu32 " ", s->id);
                                }
#endif
                                printf("\n");
                            }
                        }
                    }
                    for (global_dst_gr = global_dst_gh->ipv6_head;
                            global_dst_gr != NULL;
                            global_dst_gr = global_dst_gr->next)
                    {
                        printf(" - "); DetectAddressDataPrint(global_dst_gr->ad);
                        //printf(" (sh %p) ", global_dst_gr->sh);
                        if (global_dst_gr->sh) {
                            if (global_dst_gr->sh->flags & ADDRESS_GROUP_SIGGROUPHEAD_COPY) {
                                printf("(COPY)\n");
                            } else {
                                printf("\n");
                            }
                        }
                        DetectPort *sp = global_dst_gr->port;
                        for ( ; sp != NULL; sp = sp->next) {
                            printf("  * Src port(range): "); DetectPortPrint(sp); printf("\n");
                            DetectPort *dp = sp->dst_ph;
                            for ( ; dp != NULL; dp = dp->next) {
                                printf("   * Dst port(range): "); DetectPortPrint(dp);
                                printf(" (sigs %" PRIu32 ")", dp->sh->sig_cnt);
#ifdef PRINTSIGS
                                printf(" - ");
                                for (i = 0; i < dp->sh->sig_cnt; i++) {
                                    Signature *s = de_ctx->sig_array[dp->sh->match_array[i]];
                                    printf("%" PRIu32 " ", s->id);
                                }
#endif
                                printf("\n");
                            }
                        }
                    }
                }
#endif
            }
        }
    }
    printf("* Building signature grouping structure, stage 5: print... done\n");
    return 0;
}

int SigGroupBuild (DetectEngineCtx *de_ctx) {
    SigAddressPrepareStage1(de_ctx);
    SigAddressPrepareStage2(de_ctx);
    SigAddressPrepareStage3(de_ctx);
//abort();
//    SigAddressPrepareStage5();
    DbgPrintScanSearchStats();
//    DetectAddressGroupPrintMemory();
//    DetectSigGroupPrintMemory();
//    DetectPortPrintMemory();
//SigGroupGetSrcAddress(NULL);
    return 0;
}

int SigGroupCleanup (DetectEngineCtx *de_ctx) {
    SigAddressCleanupStage1(de_ctx);
    return 0;
}

int SigGroupGetSrcAddress(DetectAddressGroupsHead *src) {
    uint32_t ip = 0x04030201; /* 1.2.3.4 */

    printf("ip & 0x000000ff %8u 0x%08X >> 0  %" PRIu32 "\n", ip & 0x000000ff, ip & 0x000000ff, (ip & 0x000000ff) >> 0);
    printf("ip & 0x0000ff00 %8u 0x%08X >> 8  %" PRIu32 "\n", ip & 0x0000ff00, ip & 0x0000ff00, (ip & 0x0000ff00) >> 8);
    printf("ip & 0x00ff0000 %8u 0x%08X >> 16 %" PRIu32 "\n", ip & 0x00ff0000, ip & 0x00ff0000, (ip & 0x00ff0000) >> 16);
    printf("ip & 0xff000000 %8u 0x%08X >> 24 %" PRIu32 "\n", ip & 0xff000000, ip & 0xff000000, (ip & 0xff000000) >> 24);

    return 0;
}

void SigTableSetup(void) {
    memset(sigmatch_table, 0, sizeof(sigmatch_table));

    DetectAddressRegister();
    DetectProtoRegister();
    DetectPortRegister();

    DetectSidRegister();
    DetectPriorityRegister();
    DetectRevRegister();
    DetectClasstypeRegister();
    DetectReferenceRegister();
    DetectThresholdRegister();
    DetectMetadataRegister();
    DetectMsgRegister();
    DetectContentRegister();
    DetectUricontentRegister();
    DetectPcreRegister();
    DetectDepthRegister();
    DetectNocaseRegister();
    DetectRecursiveRegister();
    DetectRawbytesRegister();
    DetectWithinRegister();
    DetectDistanceRegister();
    DetectOffsetRegister();
    DetectFlowRegister();
    DetectDsizeRegister();
    DetectFlowvarRegister();
    DetectPktvarRegister();
    DetectNoalertRegister();
    DetectFlowbitsRegister();
    DetectDecodeEventRegister();

    uint8_t i = 0;
    for (i = 0; i < DETECT_TBLSIZE; i++) {
        if (sigmatch_table[i].RegisterTests == NULL) {
            printf("Warning: detection plugin %s has no unittest "
                   "registration function.\n", sigmatch_table[i].name);
        }
    }
}

void SigTableRegisterTests(void) {
    /* register the tests */
    uint8_t i = 0;
    for (i = 0; i < DETECT_TBLSIZE; i++) {
        if (sigmatch_table[i].RegisterTests != NULL) {
            sigmatch_table[i].RegisterTests();
        }
    }
}

/*
 * TESTS
 */

#ifdef UNITTESTS
#include "flow-util.h"

static int SigTest01Real (int mpm_type) {
    uint8_t *buf = (uint8_t *)
                    "GET /one/ HTTP/1.1\r\n"
                    "Host: one.example.org\r\n"
                    "\r\n\r\n"
                    "GET /two/ HTTP/1.1\r\n"
                    "Host: two.example.org\r\n"
                    "\r\n\r\n";
    uint16_t buflen = strlen((char *)buf);
    Packet p;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.payload = buf;
    p.payload_len = buflen;
    p.proto = IPPROTO_TCP;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:\"GET \"; depth:4; pcre:\"/GET (?P<pkt_http_uri>.*) HTTP\\/\\d\\.\\d\\r\\n/G\"; recursive; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    PatternMatchPrepare(mpm_ctx, mpm_type);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    if (PacketAlertCheck(&p, 1) == 0) {
        result = 0;
        goto end;
    }

    //printf("URI0 \"%s\", len %" PRIu32 "\n", p.http_uri.raw[0], p.http_uri.raw_size[0]);
    //printf("URI1 \"%s\", len %" PRIu32 "\n", p.http_uri.raw[1], p.http_uri.raw_size[1]);

    if (p.http_uri.raw_size[0] == 5 &&
        memcmp(p.http_uri.raw[0], "/one/", 5) == 0 &&
        p.http_uri.raw_size[1] == 5 &&
        memcmp(p.http_uri.raw[1], "/two/", 5) == 0)
    {
        result = 1;
    }

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    PatternMatchDestroy(mpm_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    return result;
}

static int SigTest01B2g (void) {
    return SigTest01Real(MPM_B2G);
}
static int SigTest01B3g (void) {
    return SigTest01Real(MPM_B3G);
}
static int SigTest01Wm (void) {
    return SigTest01Real(MPM_WUMANBER);
}

static int SigTest02Real (int mpm_type) {
    uint8_t *buf = (uint8_t *)
                    "GET /one/ HTTP/1.1\r\n"
                    "Host: one.example.org\r\n"
                    "\r\n\r\n"
                    "GET /two/ HTTP/1.1\r\n"
                    "Host: two.example.org\r\n"
                    "\r\n\r\n";
    uint16_t buflen = strlen((char *)buf);
    Packet p;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.payload = buf;
    p.payload_len = buflen;
    p.proto = IPPROTO_TCP;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"HTTP TEST\"; content:\"Host: one.example.org\"; offset:20; depth:41; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    PatternMatchPrepare(mpm_ctx,mpm_type);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    if (PacketAlertCheck(&p, 1))
        result = 1;

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    PatternMatchDestroy(mpm_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    return result;
}
static int SigTest02B2g (void) {
    return SigTest02Real(MPM_B2G);
}
static int SigTest02B3g (void) {
    return SigTest02Real(MPM_B3G);
}
static int SigTest02Wm (void) {
    return SigTest02Real(MPM_WUMANBER);
}


static int SigTest03Real (int mpm_type) {
    uint8_t *buf = (uint8_t *)
                    "GET /one/ HTTP/1.1\r\n"
                    "Host: one.example.org\r\n"
                    "\r\n\r\n"
                    "GET /two/ HTTP/1.1\r\n"
                    "Host: two.example.org\r\n"
                    "\r\n\r\n";
    uint16_t buflen = strlen((char *)buf);
    Packet p;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.payload = buf;
    p.payload_len = buflen;
    p.proto = IPPROTO_TCP;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"HTTP TEST\"; content:\"Host: one.example.org\"; offset:20; depth:40; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    PatternMatchPrepare(mpm_ctx, mpm_type);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    if (!PacketAlertCheck(&p, 1))
        result = 1;

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    PatternMatchDestroy(mpm_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    return result;
}
static int SigTest03B2g (void) {
    return SigTest03Real(MPM_B2G);
}
static int SigTest03B3g (void) {
    return SigTest03Real(MPM_B3G);
}
static int SigTest03Wm (void) {
    return SigTest03Real(MPM_WUMANBER);
}


static int SigTest04Real (int mpm_type) {
    uint8_t *buf = (uint8_t *)
                    "GET /one/ HTTP/1.1\r\n"
                    "Host: one.example.org\r\n"
                    "\r\n\r\n"
                    "GET /two/ HTTP/1.1\r\n"
                    "Host: two.example.org\r\n"
                    "\r\n\r\n";
    uint16_t buflen = strlen((char *)buf);

    Packet p;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.payload = buf;
    p.payload_len = buflen;
    p.proto = IPPROTO_TCP;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"HTTP TEST\"; content:\"Host:\"; offset:20; depth:25; content:\"Host:\"; distance:47; within:52; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    PatternMatchPrepare(mpm_ctx, mpm_type);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    if (PacketAlertCheck(&p, 1))
        result = 1;

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    PatternMatchDestroy(mpm_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    return result;
}
static int SigTest04B2g (void) {
    return SigTest04Real(MPM_B2G);
}
static int SigTest04B3g (void) {
    return SigTest04Real(MPM_B3G);
}
static int SigTest04Wm (void) {
    return SigTest04Real(MPM_WUMANBER);
}


static int SigTest05Real (int mpm_type) {
    uint8_t *buf = (uint8_t *)
                    "GET /one/ HTTP/1.1\r\n"    /* 20 */
                    "Host: one.example.org\r\n" /* 23, 43 */
                    "\r\n\r\n"                  /* 4,  47 */
                    "GET /two/ HTTP/1.1\r\n"    /* 20, 67 */
                    "Host: two.example.org\r\n" /* 23, 90 */
                    "\r\n\r\n";                 /* 4,  94 */
    uint16_t buflen = strlen((char *)buf);
    Packet p;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.payload = buf;
    p.payload_len = buflen;
    p.proto = IPPROTO_TCP;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"HTTP TEST\"; content:\"Host:\"; offset:20; depth:25; content:\"Host:\"; distance:48; within:52; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    PatternMatchPrepare(mpm_ctx, mpm_type);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    if (!PacketAlertCheck(&p, 1))
        result = 1;

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    PatternMatchDestroy(mpm_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    return result;
}
static int SigTest05B2g (void) {
    return SigTest05Real(MPM_B2G);
}
static int SigTest05B3g (void) {
    return SigTest05Real(MPM_B3G);
}
static int SigTest05Wm (void) {
    return SigTest05Real(MPM_WUMANBER);
}


static int SigTest06Real (int mpm_type) {
    uint8_t *buf = (uint8_t *)
                    "GET /one/ HTTP/1.1\r\n"    /* 20 */
                    "Host: one.example.org\r\n" /* 23, 43 */
                    "\r\n\r\n"                  /* 4,  47 */
                    "GET /two/ HTTP/1.1\r\n"    /* 20, 67 */
                    "Host: two.example.org\r\n" /* 23, 90 */
                    "\r\n\r\n";                 /* 4,  94 */
    uint16_t buflen = strlen((char *)buf);
    Packet p;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.payload = buf;
    p.payload_len = buflen;
    p.proto = IPPROTO_TCP;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:\"GET \"; depth:4; pcre:\"/GET (?P<pkt_http_uri>.*) HTTP\\/\\d\\.\\d\\r\\n/G\"; recursive; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }
    de_ctx->sig_list->next = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"HTTP URI test\"; uricontent:\"two\"; sid:2;)");
    if (de_ctx->sig_list->next == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    PatternMatchPrepare(mpm_ctx, mpm_type);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    if (PacketAlertCheck(&p, 1) && PacketAlertCheck(&p, 2))
        result = 1;
    else
        printf("sid:1 %s, sid:2 %s: ",
            PacketAlertCheck(&p, 1) ? "OK" : "FAIL",
            PacketAlertCheck(&p, 2) ? "OK" : "FAIL");

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    PatternMatchDestroy(mpm_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    return result;
}
static int SigTest06B2g (void) {
    return SigTest06Real(MPM_B2G);
}
static int SigTest06B3g (void) {
    return SigTest06Real(MPM_B3G);
}
static int SigTest06Wm (void) {
    return SigTest06Real(MPM_WUMANBER);
}


static int SigTest07Real (int mpm_type) {
    uint8_t *buf = (uint8_t *)
                    "GET /one/ HTTP/1.1\r\n"    /* 20 */
                    "Host: one.example.org\r\n" /* 23, 43 */
                    "\r\n\r\n"                  /* 4,  47 */
                    "GET /two/ HTTP/1.1\r\n"    /* 20, 67 */
                    "Host: two.example.org\r\n" /* 23, 90 */
                    "\r\n\r\n";                 /* 4,  94 */
    uint16_t buflen = strlen((char *)buf);
    Packet p;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.payload = buf;
    p.payload_len = buflen;
    p.proto = IPPROTO_TCP;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:\"GET \"; depth:4; pcre:\"/GET (?P<pkt_http_uri>.*) HTTP\\/\\d\\.\\d\\r\\n/G\"; recursive; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }
    de_ctx->sig_list->next = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"HTTP URI test\"; uricontent:\"three\"; sid:2;)");
    if (de_ctx->sig_list->next == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    PatternMatchPrepare(mpm_ctx, mpm_type);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    if (PacketAlertCheck(&p, 1) && PacketAlertCheck(&p, 2))
        result = 0;
    else
        result = 1;

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    PatternMatchDestroy(mpm_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    return result;
}
static int SigTest07B2g (void) {
    return SigTest07Real(MPM_B2G);
}
static int SigTest07B3g (void) {
    return SigTest07Real(MPM_B3G);
}
static int SigTest07Wm (void) {
    return SigTest07Real(MPM_WUMANBER);
}


static int SigTest08Real (int mpm_type) {
    uint8_t *buf = (uint8_t *)
                    "GET /one/ HTTP/1.0\r\n"    /* 20 */
                    "Host: one.example.org\r\n" /* 23, 43 */
                    "\r\n\r\n"                  /* 4,  47 */
                    "GET /two/ HTTP/1.0\r\n"    /* 20, 67 */
                    "Host: two.example.org\r\n" /* 23, 90 */
                    "\r\n\r\n";                 /* 4,  94 */
    uint16_t buflen = strlen((char *)buf);
    Packet p;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.payload = buf;
    p.payload_len = buflen;
    p.proto = IPPROTO_TCP;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:\"GET \"; depth:4; pcre:\"/GET (?P<pkt_http_uri>.*) HTTP\\/1\\.0\\r\\n/G\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }
    de_ctx->sig_list->next = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"HTTP URI test\"; uricontent:\"one\"; sid:2;)");
    if (de_ctx->sig_list->next == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    PatternMatchPrepare(mpm_ctx, mpm_type);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    if (PacketAlertCheck(&p, 1) && PacketAlertCheck(&p, 2))
        result = 1;
    else
        printf("sid:1 %s, sid:2 %s: ",
            PacketAlertCheck(&p, 1) ? "OK" : "FAIL",
            PacketAlertCheck(&p, 2) ? "OK" : "FAIL");

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    PatternMatchDestroy(mpm_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    return result;
}
static int SigTest08B2g (void) {
    return SigTest08Real(MPM_B2G);
}
static int SigTest08B3g (void) {
    return SigTest08Real(MPM_B3G);
}
static int SigTest08Wm (void) {
    return SigTest08Real(MPM_WUMANBER);
}


static int SigTest09Real (int mpm_type) {
    uint8_t *buf = (uint8_t *)
                    "GET /one/ HTTP/1.0\r\n"    /* 20 */
                    "Host: one.example.org\r\n" /* 23, 43 */
                    "\r\n\r\n"                  /* 4,  47 */
                    "GET /two/ HTTP/1.0\r\n"    /* 20, 67 */
                    "Host: two.example.org\r\n" /* 23, 90 */
                    "\r\n\r\n";                 /* 4,  94 */
    uint16_t buflen = strlen((char *)buf);
    Packet p;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.payload = buf;
    p.payload_len = buflen;
    p.proto = IPPROTO_TCP;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:\"GET \"; depth:4; pcre:\"/GET (?P<pkt_http_uri>.*) HTTP\\/1\\.0\\r\\n/G\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }
    de_ctx->sig_list->next = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"HTTP URI test\"; uricontent:\"two\"; sid:2;)");
    if (de_ctx->sig_list->next == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    PatternMatchPrepare(mpm_ctx, mpm_type);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    if (PacketAlertCheck(&p, 1) && PacketAlertCheck(&p, 2))
        result = 0;
    else
        result = 1;

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    PatternMatchDestroy(mpm_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    return result;
}
static int SigTest09B2g (void) {
    return SigTest09Real(MPM_B2G);
}
static int SigTest09B3g (void) {
    return SigTest09Real(MPM_B3G);
}
static int SigTest09Wm (void) {
    return SigTest09Real(MPM_WUMANBER);
}


static int SigTest10Real (int mpm_type) {
    uint8_t *buf = (uint8_t *)
                    "ABC";
    uint16_t buflen = strlen((char *)buf);
    Packet p;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.payload = buf;
    p.payload_len = buflen;
    p.proto = IPPROTO_TCP;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"Long content test (1)\"; content:\"ABCD\"; depth:4; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }
    de_ctx->sig_list->next = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"Long content test (2)\"; content:\"VWXYZ\"; sid:2;)");
    if (de_ctx->sig_list->next == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    PatternMatchPrepare(mpm_ctx, mpm_type);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    if (PacketAlertCheck(&p, 1) && PacketAlertCheck(&p, 2))
        result = 0;
    else
        result = 1;

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    PatternMatchDestroy(mpm_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    return result;
}
static int SigTest10B2g (void) {
    return SigTest10Real(MPM_B2G);
}
static int SigTest10B3g (void) {
    return SigTest10Real(MPM_B3G);
}
static int SigTest10Wm (void) {
    return SigTest10Real(MPM_WUMANBER);
}


static int SigTest11Real (int mpm_type) {
    uint8_t *buf = (uint8_t *)
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+";
    uint16_t buflen = strlen((char *)buf);
    Packet p;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.payload = buf;
    p.payload_len = buflen;
    p.proto = IPPROTO_TCP;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"Scan vs Search (1)\"; content:\"ABCDEFGHIJ\"; content:\"klmnop\"; content:\"1234\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }
    de_ctx->sig_list->next = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"Scan vs Search (2)\"; content:\"VWXYZabcde\"; content:\"5678\"; content:\"89\"; sid:2;)");
    if (de_ctx->sig_list->next == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    PatternMatchPrepare(mpm_ctx, mpm_type);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    if (PacketAlertCheck(&p, 1) && PacketAlertCheck(&p, 2))
        result = 1;
    else
        result = 0;

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    PatternMatchDestroy(mpm_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    return result;
}
static int SigTest11B2g (void) {
    return SigTest11Real(MPM_B2G);
}
static int SigTest11B3g (void) {
    return SigTest11Real(MPM_B3G);
}
static int SigTest11Wm (void) {
    return SigTest11Real(MPM_WUMANBER);
}


static int SigTest12Real (int mpm_type) {
    uint8_t *buf = (uint8_t *)
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+";
    uint16_t buflen = strlen((char *)buf);
    Packet p;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.payload = buf;
    p.payload_len = buflen;
    p.proto = IPPROTO_TCP;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"Content order test\"; content:\"ABCDEFGHIJ\"; content:\"klmnop\"; content:\"1234\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    PatternMatchPrepare(mpm_ctx, mpm_type);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    if (PacketAlertCheck(&p, 1))
        result = 1;
    else
        result = 0;

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    PatternMatchDestroy(mpm_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    return result;
}
static int SigTest12B2g (void) {
    return SigTest12Real(MPM_B2G);
}
static int SigTest12B3g (void) {
    return SigTest12Real(MPM_B3G);
}
static int SigTest12Wm (void) {
    return SigTest12Real(MPM_WUMANBER);
}


static int SigTest13Real (int mpm_type) {
    uint8_t *buf = (uint8_t *)
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+";
    uint16_t buflen = strlen((char *)buf);
    Packet p;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.payload = buf;
    p.payload_len = buflen;
    p.proto = IPPROTO_TCP;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"Content order test\"; content:\"ABCDEFGHIJ\"; content:\"1234\"; content:\"klmnop\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    PatternMatchPrepare(mpm_ctx, mpm_type);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    if (PacketAlertCheck(&p, 1))
        result = 1;
    else
        result = 0;

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    PatternMatchDestroy(mpm_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    return result;
}
static int SigTest13B2g (void) {
    return SigTest13Real(MPM_B2G);
}
static int SigTest13B3g (void) {
    return SigTest13Real(MPM_B3G);
}
static int SigTest13Wm (void) {
    return SigTest13Real(MPM_WUMANBER);
}


static int SigTest14Real (int mpm_type) {
    uint8_t *buf = (uint8_t *)
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+";
    uint16_t buflen = strlen((char *)buf);
    Packet p;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.payload = buf;
    p.payload_len = buflen;
    p.proto = IPPROTO_TCP;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"Content order test\"; content:\"ABCDEFGHIJ\"; content:\"1234\"; content:\"klmnop\"; distance:0; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    PatternMatchPrepare(mpm_ctx, mpm_type);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    if (PacketAlertCheck(&p, 1))
        result = 0;
    else
        result = 1;

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    PatternMatchDestroy(mpm_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    return result;
}
static int SigTest14B2g (void) {
    return SigTest14Real(MPM_B2G);
}
static int SigTest14B3g (void) {
    return SigTest14Real(MPM_B3G);
}
static int SigTest14Wm (void) {
    return SigTest14Real(MPM_WUMANBER);
}


static int SigTest15Real (int mpm_type) {
    uint8_t *buf = (uint8_t *)
                    "CONNECT 213.92.8.7:31204 HTTP/1.1";
    uint16_t buflen = strlen((char *)buf);
    Packet p;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.payload = buf;
    p.payload_len = buflen;
    p.proto = IPPROTO_TCP;
    p.dp = 80;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any !$HTTP_PORTS (msg:\"ET POLICY Inbound HTTP CONNECT Attempt on Off-Port\"; content:\"CONNECT \"; nocase; depth:8; content:\" HTTP/1.\"; nocase; within:1000; classtype:misc-activity; sid:2008284; rev:2;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    PatternMatchPrepare(mpm_ctx, mpm_type);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    if (PacketAlertCheck(&p, 2008284))
        result = 0;
    else
        result = 1;

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    PatternMatchDestroy(mpm_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    return result;
}
static int SigTest15B2g (void) {
    return SigTest15Real(MPM_B2G);
}
static int SigTest15B3g (void) {
    return SigTest15Real(MPM_B3G);
}
static int SigTest15Wm (void) {
    return SigTest15Real(MPM_WUMANBER);
}


static int SigTest16Real (int mpm_type) {
    uint8_t *buf = (uint8_t *)
                    "CONNECT 213.92.8.7:31204 HTTP/1.1";
    uint16_t buflen = strlen((char *)buf);
    Packet p;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.payload = buf;
    p.payload_len = buflen;
    p.proto = IPPROTO_TCP;
    p.dp = 1234;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any !$HTTP_PORTS (msg:\"ET POLICY Inbound HTTP CONNECT Attempt on Off-Port\"; content:\"CONNECT \"; nocase; depth:8; content:\" HTTP/1.\"; nocase; within:1000; classtype:misc-activity; sid:2008284; rev:2;)");
    if (de_ctx->sig_list == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    PatternMatchPrepare(mpm_ctx, mpm_type);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    if (PacketAlertCheck(&p, 2008284))
        result = 1;
    else
        printf("sid:2008284 %s: ", PacketAlertCheck(&p, 2008284) ? "OK" : "FAIL");

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    PatternMatchDestroy(mpm_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    return result;
}
static int SigTest16B2g (void) {
    return SigTest16Real(MPM_B2G);
}
static int SigTest16B3g (void) {
    return SigTest16Real(MPM_B3G);
}
static int SigTest16Wm (void) {
    return SigTest16Real(MPM_WUMANBER);
}


static int SigTest17Real (int mpm_type) {
    uint8_t *buf = (uint8_t *)
                    "GET /one/ HTTP/1.1\r\n"    /* 20 */
                    "Host: one.example.org\r\n" /* 23, 43 */
                    "\r\n\r\n"                  /* 4,  47 */
                    "GET /two/ HTTP/1.1\r\n"    /* 20, 67 */
                    "Host: two.example.org\r\n" /* 23, 90 */
                    "\r\n\r\n";                 /* 4,  94 */
    uint16_t buflen = strlen((char *)buf);
    Packet p;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.payload = buf;
    p.payload_len = buflen;
    p.proto = IPPROTO_TCP;
    p.dp = 80;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any $HTTP_PORTS (msg:\"HTTP host cap\"; content:\"Host:\"; pcre:\"/^Host: (?P<pkt_http_host>.*)\\r\\n/m\"; noalert; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    PatternMatchPrepare(mpm_ctx, mpm_type);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    PktVar *pv_hn = PktVarGet(&p, "http_host");
    if (pv_hn != NULL) {
        if (memcmp(pv_hn->value, "one.example.org", pv_hn->value_len < 15 ? pv_hn->value_len : 15) == 0)
            result = 1;
        else {
            printf("\"");
            PrintRawUriFp(stdout, pv_hn->value, pv_hn->value_len);
            printf("\" != \"one.example.org\": ");
        }
    } else {
        printf("Pkt var http_host not captured: ");
    }

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    PatternMatchDestroy(mpm_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    return result;
}
static int SigTest17B2g (void) {
    return SigTest17Real(MPM_B2G);
}
static int SigTest17B3g (void) {
    return SigTest17Real(MPM_B3G);
}
static int SigTest17Wm (void) {
    return SigTest17Real(MPM_WUMANBER);
}


static int SigTest18Real (int mpm_type) {
    uint8_t *buf = (uint8_t *)
                    "220 (vsFTPd 2.0.5)\r\n";
    uint16_t buflen = strlen((char *)buf);
    Packet p;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.payload = buf;
    p.payload_len = buflen;
    p.proto = IPPROTO_TCP;
    p.dp = 34260;
    p.sp = 21;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any !21:902 -> any any (msg:\"ET MALWARE Suspicious 220 Banner on Local Port\"; content:\"220\"; offset:0; depth:4; pcre:\"/220[- ]/\"; classtype:non-standard-protocol; sid:2003055; rev:4;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    PatternMatchPrepare(mpm_ctx, mpm_type);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    if (!PacketAlertCheck(&p, 2003055))
        result = 1;
    else
        printf("signature shouldn't match, but did: ");

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    PatternMatchDestroy(mpm_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    return result;
}
static int SigTest18B2g (void) {
    return SigTest18Real(MPM_B2G);
}
static int SigTest18B3g (void) {
    return SigTest18Real(MPM_B3G);
}
static int SigTest18Wm (void) {
    return SigTest18Real(MPM_WUMANBER);
}


int SigTest19Real (int mpm_type) {
    uint8_t *buf = (uint8_t *)
                    "220 (vsFTPd 2.0.5)\r\n";
    uint16_t buflen = strlen((char *)buf);
    Packet p;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    p.src.family = AF_INET;
    p.src.addr_data32[0] = 0x0102080a;
    p.dst.addr_data32[0] = 0x04030201;
    p.dst.family = AF_INET;
    p.payload = buf;
    p.payload_len = buflen;
    p.proto = IPPROTO_TCP;
    p.dp = 34260;
    p.sp = 21;
    p.flowflags |= FLOW_PKT_TOSERVER;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert ip $HOME_NET any -> 1.2.3.4 any (msg:\"IP-ONLY test (1)\"; sid:999; rev:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    PatternMatchPrepare(mpm_ctx, mpm_type);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);
    //DetectEngineIPOnlyThreadInit(de_ctx,&det_ctx->io_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    if (PacketAlertCheck(&p, 999))
        result = 1;
    else
        printf("signature didn't match, but should have: ");

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    PatternMatchDestroy(mpm_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    return result;
}
static int SigTest19B2g (void) {
    return SigTest19Real(MPM_B2G);
}
static int SigTest19B3g (void) {
    return SigTest19Real(MPM_B3G);
}
static int SigTest19Wm (void) {
    return SigTest19Real(MPM_WUMANBER);
}

static int SigTest20Real (int mpm_type) {
    uint8_t *buf = (uint8_t *)
                    "220 (vsFTPd 2.0.5)\r\n";
    uint16_t buflen = strlen((char *)buf);
    Packet p;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    p.src.family = AF_INET;
    p.src.addr_data32[0] = 0x0102080a;
    p.dst.addr_data32[0] = 0x04030201;
    p.dst.family = AF_INET;
    p.payload = buf;
    p.payload_len = buflen;
    p.proto = IPPROTO_TCP;
    p.dp = 34260;
    p.sp = 21;
    p.flowflags |= FLOW_PKT_TOSERVER;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert ip $HOME_NET any -> [99.99.99.99,1.2.3.0/24,1.1.1.1,3.0.0.0/8] any (msg:\"IP-ONLY test (2)\"; sid:999; rev:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    PatternMatchPrepare(mpm_ctx, mpm_type);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);
    //DetectEngineIPOnlyThreadInit(de_ctx,&det_ctx->io_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    if (PacketAlertCheck(&p, 999))
        result = 1;
    else
        printf("signature didn't match, but should have: ");

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    PatternMatchDestroy(mpm_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    return result;
}
static int SigTest20B2g (void) {
    return SigTest20Real(MPM_B2G);
}
static int SigTest20B3g (void) {
    return SigTest20Real(MPM_B3G);
}
static int SigTest20Wm (void) {
    return SigTest20Real(MPM_WUMANBER);
}


static int SigTest21Real (int mpm_type) {
    ThreadVars th_v;
    memset(&th_v, 0, sizeof(th_v));
    DetectEngineThreadCtx *det_ctx;
    int result = 0;

    Flow f;
    memset(&f, 0, sizeof(f));

    /* packet 1 */
    uint8_t *buf1 = (uint8_t *)"GET /one/ HTTP/1.0\r\n"
                    "\r\n\r\n";
    uint16_t buf1len = strlen((char *)buf1);
    Packet p1;

    memset(&p1, 0, sizeof(p1));
    p1.src.family = AF_INET;
    p1.dst.family = AF_INET;
    p1.payload = buf1;
    p1.payload_len = buf1len;
    p1.proto = IPPROTO_TCP;
    p1.flow = &f;

    /* packet 2 */
    uint8_t *buf2 = (uint8_t *)"GET /two/ HTTP/1.0\r\n"
                    "\r\n\r\n";
    uint16_t buf2len = strlen((char *)buf2);
    Packet p2;

    memset(&p2, 0, sizeof(p2));
    p2.src.family = AF_INET;
    p2.dst.family = AF_INET;
    p2.payload = buf2;
    p2.payload_len = buf2len;
    p2.proto = IPPROTO_TCP;
    p2.flow = &f;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"FLOWBIT SET\"; content:\"/one/\"; flowbits:set,TEST.one; flowbits:noalert; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }
    de_ctx->sig_list->next = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"FLOWBIT TEST\"; content:\"/two/\"; flowbits:isset,TEST.one; sid:2;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    PatternMatchPrepare(mpm_ctx, mpm_type);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p1);
    if (PacketAlertCheck(&p1, 1)) {
        printf("sid 1 alerted, but shouldn't: ");
        goto end;
    }
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p2);
    if (PacketAlertCheck(&p2, 2))
        result = 1;

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    PatternMatchDestroy(mpm_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    return result;
}
static int SigTest21B2g (void) {
    return SigTest21Real(MPM_B2G);
}
static int SigTest21B3g (void) {
    return SigTest21Real(MPM_B3G);
}
static int SigTest21Wm (void) {
    return SigTest21Real(MPM_WUMANBER);
}


static int SigTest22Real (int mpm_type) {
    ThreadVars th_v;
    memset(&th_v, 0, sizeof(th_v));
    DetectEngineThreadCtx *det_ctx;
    int result = 0;

    Flow f;
    memset(&f, 0, sizeof(f));

    /* packet 1 */
    uint8_t *buf1 = (uint8_t *)"GET /one/ HTTP/1.0\r\n"
                    "\r\n\r\n";
    uint16_t buf1len = strlen((char *)buf1);
    Packet p1;

    memset(&p1, 0, sizeof(p1));
    p1.src.family = AF_INET;
    p1.dst.family = AF_INET;
    p1.payload = buf1;
    p1.payload_len = buf1len;
    p1.proto = IPPROTO_TCP;
    p1.flow = &f;

    /* packet 2 */
    uint8_t *buf2 = (uint8_t *)"GET /two/ HTTP/1.0\r\n"
                    "\r\n\r\n";
    uint16_t buf2len = strlen((char *)buf2);
    Packet p2;

    memset(&p2, 0, sizeof(p2));
    p2.src.family = AF_INET;
    p2.dst.family = AF_INET;
    p2.payload = buf2;
    p2.payload_len = buf2len;
    p2.proto = IPPROTO_TCP;
    p2.flow = &f;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"FLOWBIT SET\"; content:\"/one/\"; flowbits:set,TEST.one; flowbits:noalert; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }
    de_ctx->sig_list->next = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"FLOWBIT TEST\"; content:\"/two/\"; flowbits:isset,TEST.abc; sid:2;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    PatternMatchPrepare(mpm_ctx, mpm_type);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p1);
    if (PacketAlertCheck(&p1, 1)) {
        printf("sid 1 alerted, but shouldn't: ");
        goto end;
    }
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p2);
    if (!(PacketAlertCheck(&p2, 2)))
        result = 1;
    else
        printf("sid 2 alerted, but shouldn't: ");

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    PatternMatchDestroy(mpm_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    return result;
}
static int SigTest22B2g (void) {
    return SigTest22Real(MPM_B2G);
}
static int SigTest22B3g (void) {
    return SigTest22Real(MPM_B3G);
}
static int SigTest22Wm (void) {
    return SigTest22Real(MPM_WUMANBER);
}

static int SigTest23Real (int mpm_type) {
    ThreadVars th_v;
    memset(&th_v, 0, sizeof(th_v));
    DetectEngineThreadCtx *det_ctx;
    int result = 0;

    Flow f;
    memset(&f, 0, sizeof(f));

    /* packet 1 */
    uint8_t *buf1 = (uint8_t *)"GET /one/ HTTP/1.0\r\n"
                    "\r\n\r\n";
    uint16_t buf1len = strlen((char *)buf1);
    Packet p1;

    memset(&p1, 0, sizeof(p1));
    p1.src.family = AF_INET;
    p1.dst.family = AF_INET;
    p1.payload = buf1;
    p1.payload_len = buf1len;
    p1.proto = IPPROTO_TCP;
    p1.flow = &f;

    /* packet 2 */
    uint8_t *buf2 = (uint8_t *)"GET /two/ HTTP/1.0\r\n"
                    "\r\n\r\n";
    uint16_t buf2len = strlen((char *)buf2);
    Packet p2;

    memset(&p2, 0, sizeof(p2));
    p2.src.family = AF_INET;
    p2.dst.family = AF_INET;
    p2.payload = buf2;
    p2.payload_len = buf2len;
    p2.proto = IPPROTO_TCP;
    p2.flow = &f;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"FLOWBIT SET\"; content:\"/one/\"; flowbits:toggle,TEST.one; flowbits:noalert; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }
    de_ctx->sig_list->next = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"FLOWBIT TEST\"; content:\"/two/\"; flowbits:isset,TEST.one; sid:2;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    PatternMatchPrepare(mpm_ctx, mpm_type);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p1);
    if (PacketAlertCheck(&p1, 1)) {
        printf("sid 1 alerted, but shouldn't: ");
        goto end;
    }
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p2);
    if (PacketAlertCheck(&p2, 2))
        result = 1;
    else
        printf("sid 2 didn't alert, but should have: ");

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    PatternMatchDestroy(mpm_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    return result;
}
static int SigTest23B2g (void) {
    return SigTest23Real(MPM_B2G);
}
static int SigTest23B3g (void) {
    return SigTest23Real(MPM_B3G);
}
static int SigTest23Wm (void) {
    return SigTest23Real(MPM_WUMANBER);
}


#endif /* UNITTESTS */

void SigRegisterTests(void) {
#ifdef UNITTESTS
    SigParseRegisterTests();
    UtRegisterTest("SigTest01B2g -- HTTP URI cap", SigTest01B2g, 1);
    UtRegisterTest("SigTest01B3g -- HTTP URI cap", SigTest01B3g, 1);
    UtRegisterTest("SigTest01Wm -- HTTP URI cap", SigTest01Wm, 1);

    UtRegisterTest("SigTest02B2g -- Offset/Depth match", SigTest02B2g, 1);
    UtRegisterTest("SigTest02B3g -- Offset/Depth match", SigTest02B3g, 1);
    UtRegisterTest("SigTest02Wm -- Offset/Depth match", SigTest02Wm, 1);

    UtRegisterTest("SigTest03B2g -- offset/depth mismatch", SigTest03B2g, 1);
    UtRegisterTest("SigTest03B3g -- offset/depth mismatch", SigTest03B3g, 1);
    UtRegisterTest("SigTest03Wm -- offset/depth mismatch", SigTest03Wm, 1);

    UtRegisterTest("SigTest04B2g -- distance/within match", SigTest04B2g, 1);
    UtRegisterTest("SigTest04B3g -- distance/within match", SigTest04B3g, 1);
    UtRegisterTest("SigTest04Wm -- distance/within match", SigTest04Wm, 1);

    UtRegisterTest("SigTest05B2g -- distance/within mismatch", SigTest05B2g, 1);
    UtRegisterTest("SigTest05B3g -- distance/within mismatch", SigTest05B3g, 1);
    UtRegisterTest("SigTest05Wm -- distance/within mismatch", SigTest05Wm, 1);

    UtRegisterTest("SigTest06B2g -- uricontent HTTP/1.1 match test", SigTest06B2g, 1);
    UtRegisterTest("SigTest06B3g -- uricontent HTTP/1.1 match test", SigTest06B3g, 1);
    UtRegisterTest("SigTest06wm -- uricontent HTTP/1.1 match test", SigTest06Wm, 1);

    UtRegisterTest("SigTest07B2g -- uricontent HTTP/1.1 mismatch test", SigTest07B2g, 1);
    UtRegisterTest("SigTest07B3g -- uricontent HTTP/1.1 mismatch test", SigTest07B3g, 1);
    UtRegisterTest("SigTest07Wm -- uricontent HTTP/1.1 mismatch test", SigTest07Wm, 1);

    UtRegisterTest("SigTest08B2g -- uricontent HTTP/1.0 match test", SigTest08B2g, 1);
    UtRegisterTest("SigTest08B3g -- uricontent HTTP/1.0 match test", SigTest08B3g, 1);
    UtRegisterTest("SigTest08Wm -- uricontent HTTP/1.0 match test", SigTest08Wm, 1);

    UtRegisterTest("SigTest09B2g -- uricontent HTTP/1.0 mismatch test", SigTest09B2g, 1);
    UtRegisterTest("SigTest09B3g -- uricontent HTTP/1.0 mismatch test", SigTest09B3g, 1);
    UtRegisterTest("SigTest09Wm -- uricontent HTTP/1.0 mismatch test", SigTest09Wm, 1);

    UtRegisterTest("SigTest10B2g -- long content match, longer than pkt", SigTest10B2g, 1);
    UtRegisterTest("SigTest10B3g -- long content match, longer than pkt", SigTest10B3g, 1);
    UtRegisterTest("SigTest10Wm -- long content match, longer than pkt", SigTest10Wm, 1);

    UtRegisterTest("SigTest11B2g -- scan vs search", SigTest11B2g, 1);
    UtRegisterTest("SigTest11B3g -- scan vs search", SigTest11B3g, 1);
    UtRegisterTest("SigTest11Wm -- scan vs search", SigTest11Wm, 1);

    UtRegisterTest("SigTest12B2g -- content order matching, normal", SigTest12B2g, 1);
    UtRegisterTest("SigTest12B3g -- content order matching, normal", SigTest12B3g, 1);
    UtRegisterTest("SigTest12Wm -- content order matching, normal", SigTest12Wm, 1);

    UtRegisterTest("SigTest13B2g -- content order matching, diff order", SigTest13B2g, 1);
    UtRegisterTest("SigTest13B3g -- content order matching, diff order", SigTest13B3g, 1);
    UtRegisterTest("SigTest13Wm -- content order matching, diff order", SigTest13Wm, 1);

    UtRegisterTest("SigTest14B2g -- content order matching, distance 0", SigTest14B2g, 1);
    UtRegisterTest("SigTest14B3g -- content order matching, distance 0", SigTest14B3g, 1);
    UtRegisterTest("SigTest14Wm -- content order matching, distance 0", SigTest14Wm, 1);

    UtRegisterTest("SigTest15B2g -- port negation sig (no match)", SigTest15B2g, 1);
    UtRegisterTest("SigTest15B3g -- port negation sig (no match)", SigTest15B3g, 1);
    UtRegisterTest("SigTest15Wm -- port negation sig (no match)", SigTest15Wm, 1);

    UtRegisterTest("SigTest16B2g -- port negation sig (match)", SigTest16B2g, 1);
    UtRegisterTest("SigTest16B3g -- port negation sig (match)", SigTest16B3g, 1);
    UtRegisterTest("SigTest16Wm -- port negation sig (match)", SigTest16Wm, 1);

    UtRegisterTest("SigTest17B2g -- HTTP Host Pkt var capture", SigTest17B2g, 1);
    UtRegisterTest("SigTest17B3g -- HTTP Host Pkt var capture", SigTest17B3g, 1);
    UtRegisterTest("SigTest17Wm -- HTTP Host Pkt var capture", SigTest17Wm, 1);

    UtRegisterTest("SigTest18B2g -- Ftp negation sig test", SigTest18B2g, 1);
    UtRegisterTest("SigTest18B3g -- Ftp negation sig test", SigTest18B3g, 1);
    UtRegisterTest("SigTest18Wm -- Ftp negation sig test", SigTest18Wm, 1);

    UtRegisterTest("SigTest19B2g -- IP-ONLY test (1)", SigTest19B2g, 1);
    UtRegisterTest("SigTest19B3g -- IP-ONLY test (1)", SigTest19B3g, 1);
    UtRegisterTest("SigTest19Wm -- IP-ONLY test (1)", SigTest19Wm, 1);

    UtRegisterTest("SigTest20B2g -- IP-ONLY test (2)", SigTest20B2g, 1);
    UtRegisterTest("SigTest20B3g -- IP-ONLY test (2)", SigTest20B3g, 1);
    UtRegisterTest("SigTest20Wm -- IP-ONLY test (2)", SigTest20Wm, 1);

    UtRegisterTest("SigTest21B2g -- FLOWBIT test (1)", SigTest21B2g, 1);
    UtRegisterTest("SigTest21B3g -- FLOWBIT test (1)", SigTest21B3g, 1);
    UtRegisterTest("SigTest21Wm -- FLOWBIT test (1)", SigTest21Wm, 1);

    UtRegisterTest("SigTest22B2g -- FLOWBIT test (2)", SigTest22B2g, 1);
    UtRegisterTest("SigTest22B3g -- FLOWBIT test (2)", SigTest22B3g, 1);
    UtRegisterTest("SigTest22Wm -- FLOWBIT test (2)", SigTest22Wm, 1);

    UtRegisterTest("SigTest23B2g -- FLOWBIT test (3)", SigTest23B2g, 1);
    UtRegisterTest("SigTest23B3g -- FLOWBIT test (3)", SigTest23B3g, 1);
    UtRegisterTest("SigTest23Wm -- FLOWBIT test (3)", SigTest23Wm, 1);
#endif /* UNITTESTS */
}

