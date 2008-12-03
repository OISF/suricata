/* Basic detection engine datastructure */

#include <pcre.h>

#include "vips.h"
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

#include "action-globals.h"
#include "tm-modules.h"

#include "util-unittest.h"

static DetectEngineCtx *g_de_ctx = NULL;
static u_int32_t mpm_memory_size = 0;

SigMatch *SigMatchAlloc(void);
void SigMatchFree(SigMatch *sm);
int SignatureTupleCmp(SignatureTuple *a, SignatureTuple *b);
int SignatureTupleCmpRaw(DetectAddressGroup *src, DetectAddressGroup *dst, DetectPort *sp, DetectPort *dp, u_int8_t proto, SignatureTuple *b);

/* tm module api functions */
int Detect(ThreadVars *, Packet *, void *, PacketQueue *);
int DetectThreadInit(ThreadVars *, void **);
int DetectThreadDeinit(ThreadVars *, void *);

void TmModuleDetectRegister (void) {
    tmm_modules[TMM_DETECT].name = "Detect";
    tmm_modules[TMM_DETECT].Init = DetectThreadInit;
    tmm_modules[TMM_DETECT].Func = Detect;
    tmm_modules[TMM_DETECT].Deinit = DetectThreadDeinit;
    tmm_modules[TMM_DETECT].RegisterTests = NULL;
}

void SigLoadSignatures (void)
{
    Signature *prevsig = NULL, *sig;

    /* intialize the de_ctx */
    g_de_ctx = DetectEngineCtxInit();


    /* The next 3 rules handle HTTP header capture. */

    /* http_uri -- for uricontent */
    sig = SigInit("alert tcp any any -> any $HTTP_PORTS (msg:\"HTTP GET URI cap\"; flow:to_server; content:\"GET \"; depth:4; pcre:\"/^GET (?P<pkt_http_uri>.*) HTTP\\/\\d\\.\\d\\r\\n/G\"; noalert; sid:1;)");
    if (sig) {
        prevsig = sig;
        g_de_ctx->sig_list = sig;
    }
    sig = SigInit("alert tcp any any -> any $HTTP_PORTS (msg:\"HTTP POST URI cap\"; flow:to_server; content:\"POST \"; depth:5; pcre:\"/^POST (?P<pkt_http_uri>.*) HTTP\\/\\d\\.\\d\\r\\n/G\"; noalert; sid:2;)");
    if (sig == NULL)
        return;
    prevsig->next = sig;
    prevsig = sig;

    /* http_host -- for the log-httplog module */
    sig = SigInit("alert tcp any any -> any $HTTP_PORTS (msg:\"HTTP host cap\"; flow:to_server; content:\"Host:\"; pcre:\"/^Host: (?P<pkt_http_host>.*)\\r\\n/m\"; noalert; sid:3;)");
    if (sig == NULL)
        return;
    prevsig->next = sig;
    prevsig = sig;

    /* http_ua -- for the log-httplog module */
    sig = SigInit("alert tcp any any -> any $HTTP_PORTS (msg:\"HTTP UA cap\"; flow:to_server; content:\"User-Agent:\"; pcre:\"/^User-Agent: (?P<pkt_http_ua>.*)\\r\\n/m\"; noalert; sid:4;)");
    if (sig == NULL)
        return;
    prevsig->next = sig;
    prevsig = sig;

/*
    sig = SigInit("alert udp any any -> any any (msg:\"ViCtOr nocase test\"; sid:4; rev:13; content:\"ViCtOr\"; nocase; content:\"ViCtOr\"; nocase; depth:150;)");
    if (sig == NULL)
        return;
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit("alert ip any any -> 1.2.3.4 any (msg:\"ViCtOr case test\"; sid:2001; content:\"ViCtOr\"; depth:150;)");
    if (sig == NULL)
        return;
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit("alert ip any any -> 1.2.3.4 any (msg:\"IP ONLY\"; sid:2002;)");
    if (sig == NULL)
        return;
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit("alert ip ANY any -> 192.168.0.0/16 any (msg:\"offset, depth, within test\"; flow:to_client; sid:2002; content:HTTP; depth:4; content:Server:; offset:15; within:100; depth:200;)");
    if (sig == NULL)
        return;
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit("alert ip 1.2.3.4 any -> any any (msg:\"Inliniac blog within test\"; flow:to_client; sid:2003; content:inliniac; content:blog; within:9;)");
    if (sig == NULL)
        return;
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit("alert ip 2001::1 any -> 2001::3 any (msg:\"abcdefg distance 1 test\"; flow:to_server; sid:2004; content:abcd; content:efgh; within:4; distance:0; content:ijkl; within:4; distance:0;)");
    if (sig == NULL)
        return;
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit("alert ip 2001::5 any -> 2001::7 any (msg:\"abcdef distance 0 test\"; flow:to_server; sid:2005; content:abcdef; content:ghijklmnop; distance:0;)");
    if (sig == NULL)
        return;
    prevsig->next = sig;
    prevsig = sig;


    sig = SigInit("alert ip 10.0.0.0/8 any -> 4.3.2.1 any (msg:\"abcdefg distance 1 test\"; flow:to_server; sid:2006; content:abcdef; content:ghijklmnop; distance:1;)");
    if (sig == NULL)
        return;
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit("alert tcp 172.16.1.0/24 any -> 0.0.0.0/0 any (msg:\"HTTP response code cap\"; flow:to_client; content:HTTP; depth:4; pcre:\"/^HTTP\\/\\d\\.\\d (?<http_response>[0-9]+) [A-z\\s]+\\r\\n/\"; depth:50; sid:3;)");
    if (sig == NULL)
        return;
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit("alert tcp 172.16.2.0/24 any -> 10.10.10.10 any (msg:\"HTTP server code cap\"; flow:to_client; content:Server:; depth:500; pcre:\"/^Server: (?<http_server>.*)\\r\\n/m\"; sid:4;)");
    if (sig == NULL)
        return;
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit("alert tcp 192.168.0.1 any -> 1.0.2.1 any (msg:\"\to_client nocase test\"; flow:to_client; content:Servere:; nocase; sid:400;)");
    if (sig == NULL)
        return;
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit("alert tcp 192.168.0.4 any -> 1.2.0.1 any (msg:\"HTTP UA code cap\"; flow:to_server; content:User-Agent:; depth:300; pcre:\"/^User-Agent: (?<http_ua>.*)\\r\\n/m\"; sid:5;)");
    if (sig == NULL)
        return;
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit("alert tcp 192.168.0.12 any -> 0.0.0.0/0 any (msg:\"HTTP http_host flowvar www.inliniac.net\"; flow:to_server; flowvar:http_host,\"www.inliniac.net\"; sid:7;)");
    if (sig) {
        prevsig->next = sig;
        prevsig = sig;
    }
    sig = SigInit("alert tcp 192.168.0.0/16 any -> 0.0.0.0/0 any (msg:\"HTTP http_uri flowvar MattJonkman\"; flow:to_server; flowvar:http_uri,\"MattJonkman\"; sid:8;)");
    if (sig) {
        prevsig->next = sig;
        prevsig = sig;
    }
    sig = SigInit("alert tcp 0.0.0.0/0 any -> 0.0.0.0/0 any (msg:\"HTTP uricontent VictorJulien\"; flow:to_server; uricontent:\"VictorJulien\"; nocase; sid:9;)");
    if (sig) {
        prevsig->next = sig;
        prevsig = sig;
    }
    sig = SigInit("alert tcp 0.0.0.0/0 any -> 10.0.0.0/8 any (msg:\"HTTP uricontent VictorJulien\"; flow:to_server; uricontent:\"VictorJulien\"; nocase; sid:5;)");
    if (sig) {
        prevsig->next = sig;
        prevsig = sig;
    }
*/

#define LOADSIGS
#ifdef LOADSIGS
    int good = 0, bad = 0;
    //FILE *fp = fopen("/etc/vips/rules/bleeding-all.rules", "r");
    FILE *fp = fopen("/home/victor/rules/all.rules", "r");
    //FILE *fp = fopen("/home/victor/rules/vips-http.sigs", "r");
    //FILE *fp = fopen("/home/victor/rules/emerging-dshield.rules", "r");
    //FILE *fp = fopen("/home/victor/rules/emerging-web.rules", "r");
    //FILE *fp = fopen("/home/victor/rules/emerging-p2p.rules", "r");
    //FILE *fp = fopen("/home/victor/rules/emerging-web-small.rules", "r");
    //FILE *fp = fopen("/home/victor/rules/web-misc.rules", "r");
    //FILE *fp = fopen("/home/victor/rules/emerging-malware.rules", "r");
    //FILE *fp = fopen("/home/victor/rules/vips-all.sigs", "r");
    //FILE *fp = fopen("/home/victor/rules/all_noip.rules", "r");
    //FILE *fp = fopen("/home/victor/rules/all_iplists.rules", "r");
    //FILE *fp = fopen("/home/victor/rules/funky.rules", "r");
    //FILE *fp = fopen("/etc/vips/rules/zango.rules", "r");
    //FILE *fp = fopen("/home/victor/rules/vips-vrt-all.sigs", "r");
    //FILE *fp = fopen("/home/victor/rules/test-many-ips.rules", "r");
    if (fp == NULL) {
        printf("ERROR, could not open sigs file\n");
        exit(1);
    }
    char line[8192] = "";
    while(fgets(line, (int)sizeof(line), fp) != NULL) {
        if (line[0] == '\n' || line[0] == ' ' || line[0] == '#' || line[0] == '\t')
            continue;

        //if (i > 1000) break;

        sig = SigInit(line);
        if (sig) {
            prevsig->next = sig;
            prevsig = sig;
            good++;
        } else {
            bad++;
        }
    }
    fclose(fp);
    printf("SigLoadSignatures: %d successfully loaded from file. %d sigs failed to load\n", good, bad);
    printf("SigLoadSignatures: %u sigs with dstportany\n", DbgGetDstPortAnyCnt());

#endif

    /* Setup the signature group lookup structure and
     * pattern matchers */
    //DetectAddressGroupPrintMemory();
    //DetectSigGroupPrintMemory();
    //DetectPortPrintMemory();

    SigGroupBuild(g_de_ctx);
    //SigGroupCleanup();
    //DetectAddressGroupPrintMemory();
    //DetectSigGroupPrintMemory();
    //DetectPortPrintMemory();

//abort();
}

/* check if a certain sid alerted, this is used in the test functions */
int PacketAlertCheck(Packet *p, u_int32_t sid)
{
    u_int16_t i = 0;
    int match = 0;

    for (i = 0; i < p->alerts.cnt; i++) {
        if (p->alerts.alerts[i].sid == sid)
            match++;
    }

    return match;
}

int PacketAlertAppend(Packet *p, u_int8_t gid, u_int32_t sid, u_int8_t rev, u_int8_t prio, char *msg)
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

int SigMatchIPOnlySignatures(ThreadVars *th_v, PatternMatcherThread *pmt, Packet *p)
{
    int fmatch = 0;
    Signature *s = NULL;
    u_int32_t idx = 0, sig = 0;

    /* find the right mpm instance */
    DetectAddressGroup *g = DetectAddressLookupGroup(g_de_ctx->io_src_gh,&p->src);
    if (g != NULL) {
        /* source group found, lets try a dst group */
        g = DetectAddressLookupGroup(g->dst_gh,&p->dst);
    }
    //printf("SigMatchIPOnlySignatures: g %p\n", g);

    /* no matches, so return */
    if (g == NULL)
        return 0;

    /* inspect the sigs against the packet */
    for (idx = 0; idx < g->sh->sig_cnt; idx++) {
        sig = g->sh->match_array[idx];
        s = g_de_ctx->sig_array[sig];

        fmatch = 1;

        if (!(s->flags & SIG_FLAG_NOALERT)) {
            PacketAlertAppend(p, 1, s->id, s->rev, s->prio, s->msg);

            /* set verdict on packet */
            p->action = s->action;
        }
    }
    return fmatch;
}

int SigMatchSignatures(ThreadVars *th_v, PatternMatcherThread *pmt, Packet *p)
{
    int match = 0, fmatch = 0;
    Signature *s = NULL;
    SigMatch *sm = NULL;
    u_int32_t idx,sig;
    SigGroupHead *sgh = NULL;

    SigMatchIPOnlySignatures(th_v,pmt,p);

    /* we assume we don't have an uri when we start inspection */
    pmt->de_have_httpuri = 0;
    pmt->de_scanned_httpuri = 0;
    pmt->mc = NULL;
    pmt->mcu = NULL;

    /* find the right mpm instance */
    DetectAddressGroup *ag = DetectAddressLookupGroup(g_de_ctx->src_gh[p->proto],&p->src);
    if (ag != NULL) {
        /* source group found, lets try a dst group */
        ag = DetectAddressLookupGroup(ag->dst_gh,&p->dst);
        if (ag != NULL) {
            if (ag->port == NULL) {
                pmt->mc = ag->sh->mpm_ctx;
                pmt->mcu = ag->sh->mpm_uri_ctx;
                sgh = ag->sh;

                //printf("SigMatchSignatures: mc %p, mcu %p\n", pmt->mc, pmt->mcu);
                //printf("sigs %u\n", ag->sh->sig_cnt);
            } else {
                //printf("SigMatchSignatures: we have ports\n");

                DetectPort *sport = DetectPortLookupGroup(ag->port,p->sp);
                if (sport != NULL) {
                    DetectPort *dport = DetectPortLookupGroup(sport->dst_ph,p->dp);
                    if (dport != NULL) {
                        pmt->mc = dport->sh->mpm_ctx;
                        pmt->mcu = dport->sh->mpm_uri_ctx;
                        sgh = dport->sh;
                    }
                }
            }
        }
    }

    /* if we didn't get a sig group head, we
     * have nothing to do.... */
    if (sgh == NULL) {
        //printf("SigMatchSignatures: no sgh\n");
        return 0;
    }

    if (pmt->mc != NULL) {
        /* run the pattern matcher against the packet */
        //u_int32_t cnt = 
        PacketPatternMatch(th_v, pmt, p);
        //printf("cnt %u\n", cnt);
    }

    /* inspect the sigs against the packet */
    for (idx = 0; idx < sgh->sig_cnt; idx++) {
        sig = sgh->match_array[idx];
        s = g_de_ctx->sig_array[sig];

        if (!(s->flags & SIG_FLAG_SRC_ANY)) {
            DetectAddressGroup *saddr = DetectAddressLookupGroup(&s->src,&p->src);
            if (saddr == NULL)
                continue;
        }

        if (!(s->flags & SIG_FLAG_DST_ANY)) {
            DetectAddressGroup *daddr = DetectAddressLookupGroup(&s->dst,&p->dst);
            if (daddr == NULL)
                continue;
        }
        /* check the source port in the sig */
        if (p->proto == IPPROTO_TCP || p->proto == IPPROTO_UDP) {
            if (!(s->flags & SIG_FLAG_SP_ANY)) {
                DetectPort *sport = DetectPortLookupGroup(s->sp,p->sp);
                if (sport == NULL)
                    continue;
            }
            if (!(s->flags & SIG_FLAG_DP_ANY)) {
                DetectPort *dport = DetectPortLookupGroup(s->dp,p->dp);
                if (dport == NULL)
                    continue;
            }
        }
        /* reset pkt ptr and offset */
        pmt->pkt_ptr = NULL;
        pmt->pkt_off = 0;

        if (s->flags & SIG_FLAG_RECURSIVE) {
            u_int8_t rmatch = 0;
            pmt->pkt_cnt = 0;

            do {
                sm = s->match;
                while (sm) {
                    match = sigmatch_table[sm->type].Match(th_v, pmt, p, s, sm);
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
                            pmt->pkt_cnt++;
                        }
                    } else {
                        /* done with this sig */
                        sm = NULL;
                        rmatch = 0;
                    }
                }
                /* Limit the number of times we do this recursive thing.
                 * XXX is this a sane limit? Should it be configurable? */
                if (pmt->pkt_cnt == 10)
                    break;
            } while (rmatch);
        } else {
            sm = s->match;
            while (sm) {
                match = sigmatch_table[sm->type].Match(th_v, pmt, p, s, sm);
                if (match) {
                    /* okay, try the next match */
                    sm = sm->next;

                    /* only if the last matched as well, we have a hit */
                    if (sm == NULL) {
                        if (s->id > 100) {
                            printf("Signature %u matched: %s, flow: toserver %s toclient %s proto %u, SP %s (%u) DP %s (%u) sig sp: ",
                                    s->id, s->msg ? s->msg : "",
                                    p->flowflags & FLOW_PKT_TOSERVER ? "TRUE":"FALSE",
                                    p->flowflags & FLOW_PKT_TOCLIENT ? "TRUE":"FALSE",
                                    p->proto, s->flags & SIG_FLAG_SP_ANY ? "ANY":"NOTANY", p->sp,
                                    s->flags & SIG_FLAG_DP_ANY ? "ANY":"NOTANY", p->dp);
                            DetectPortPrint(s->sp); printf(" dp: ");
                            DetectPortPrint(s->dp); printf("\n");
                        }
                        fmatch = 1;

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
    PacketPatternCleanup(th_v, pmt);
    return fmatch;
}

/* tm module api functions */
int Detect(ThreadVars *t, Packet *p, void *data, PacketQueue *pq) {
    PatternMatcherThread *pmt = (PatternMatcherThread *)data;

    return SigMatchSignatures(t,pmt,p);
}

int DetectThreadInit(ThreadVars *t, void **data) {
    return PatternMatcherThreadInit(t,data);
}

int DetectThreadDeinit(ThreadVars *t, void *data) {
    return PatternMatcherThreadDeinit(t,data);
}

void SigCleanSignatures()
{
    Signature *s = NULL, *ns;

    for (s = g_de_ctx->sig_list; s != NULL;) {
        ns = s->next;
        SigFree(s);
        s = ns;
    }

    SigResetMaxId();
}

/* return codes:
 * 1: sig is ip only
 * 0: sig is not ip only
 *
 */
static int SignatureIsIPOnly(Signature *s) {
    SigMatch *sm;

    sm = s->match;
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
        } else if (sm->type == DETECT_FLOWVAR) {
            return 0;
        } else if (sm->type == DETECT_DSIZE) {
            return 0;
        }
    }

iponly:
    printf("IP-ONLY (%u): source %s, dest %s\n", s->id, s->flags & SIG_FLAG_SRC_ANY ? "ANY" : "SET", s->flags & SIG_FLAG_DST_ANY ? "ANY" : "SET");
    return 1;
}

/* add all signatures to their own source address group */
int SigAddressPrepareStage1(DetectEngineCtx *de_ctx) {
    Signature *tmp_s = NULL;
    DetectAddressGroup *gr = NULL;
    u_int32_t cnt = 0, cnt_iponly = 0;

    //DetectAddressGroupPrintMemory();
    //DetectSigGroupPrintMemory();
    //DetectPortPrintMemory();

    if (!(de_ctx->flags & DE_QUIET)) {
        printf("* Building signature grouping structure, stage 1: "
               "adding signatures to signature source addresses...\n");
    }

    de_ctx->sig_array_len = SigGetMaxId();
    de_ctx->sig_array_size = (de_ctx->sig_array_len * sizeof(Signature *));
    de_ctx->sig_array = (Signature **)malloc(de_ctx->sig_array_size);
    if (de_ctx->sig_array == NULL)
        goto error;
    memset(de_ctx->sig_array,0,de_ctx->sig_array_size);

    if (!(de_ctx->flags & DE_QUIET)) {
        printf(" - Signature lookup array: %u sigs, %u bytes.\n",
            de_ctx->sig_array_len, de_ctx->sig_array_size);
    }

    /* now for every rule add the source group */
    for (tmp_s = de_ctx->sig_list; tmp_s != NULL; tmp_s = tmp_s->next) {

        de_ctx->sig_array[tmp_s->num] = tmp_s;
        //printf(" + Signature %u, internal id %u, ptrs %p %p ", tmp_s->id, tmp_s->num, tmp_s, de_ctx->sig_array[tmp_s->num]);

        /* see if the sig is ip only */
        if (SignatureIsIPOnly(tmp_s) == 1) {
            tmp_s->flags |= SIG_FLAG_IPONLY;
            cnt_iponly++;
            //printf("(IP only)\n");
        } else {
            //printf("\n");
        }

        for (gr = tmp_s->src.ipv4_head; gr != NULL; gr = gr->next) {
            if (SigGroupHeadAppendSig(&gr->sh,tmp_s) < 0) {
                goto error;
            }
            cnt++;
        }
        for (gr = tmp_s->src.ipv6_head; gr != NULL; gr = gr->next) {
            if (SigGroupHeadAppendSig(&gr->sh,tmp_s) < 0) {
                goto error;
            }
            cnt++;
        }
        for (gr = tmp_s->src.any_head; gr != NULL; gr = gr->next) {
            if (SigGroupHeadAppendSig(&gr->sh,tmp_s) < 0) {
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
        printf(" * %u signatures processed. %u are IP-only rules.\n",
            de_ctx->sig_cnt, cnt_iponly);
        printf("* Building signature grouping structure, stage 1: "
               "adding signatures to signature source addresses... done\n");
    }
    return 0;
error:
    printf("SigAddressPrepareStage1 error\n");
    return -1;
}

static int BuildSourceAddressList(DetectEngineCtx *de_ctx, Signature *s, int family) {
    DetectAddressGroup *gr = NULL, *lookup_gr = NULL, *head = NULL;
    int proto;

    if (family == AF_INET) {
        head = s->src.ipv4_head;
    } else if (family == AF_INET6) {
        head = s->src.ipv6_head;
    } else {
        head = s->src.any_head;
    }

    /* Normal sigs are added per protocol. For performance reasons we deal with
     * ip address only sigs in a different way. */
    if (!(s->flags & SIG_FLAG_IPONLY) || !(s->proto.flags & DETECT_PROTO_ANY)) {
        /* for each source address group in the signature... */
        for (gr = head; gr != NULL; gr = gr->next) {
            /* ...and each protocol the signature matches on... */
            for (proto = 0; proto < 256; proto++) {
                if (s->proto.proto[(proto/8)] & (1<<(proto%8))) {
                    /* ...see if the group is in the tmp list, and if not add it. */
                    if (family == AF_INET) {
                        lookup_gr = DetectAddressGroupLookup(de_ctx->tmp_gh[proto]->ipv4_head,gr->ad);
                    } else if (family == AF_INET6) {
                        lookup_gr = DetectAddressGroupLookup(de_ctx->tmp_gh[proto]->ipv6_head,gr->ad);
                    } else {
                        lookup_gr = DetectAddressGroupLookup(de_ctx->tmp_gh[proto]->any_head,gr->ad);
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

                        SigGroupHeadAppendSig(&grtmp->sh, s);

                        /* add to the lookup list */
                        if (family == AF_INET) {
                            DetectAddressGroupAdd(&de_ctx->tmp_gh[proto]->ipv4_head, grtmp);
                        } else if (family == AF_INET6) {
                            DetectAddressGroupAdd(&de_ctx->tmp_gh[proto]->ipv6_head, grtmp);
                        } else {
                            DetectAddressGroupAdd(&de_ctx->tmp_gh[proto]->any_head, grtmp);
                        }
                    } else {
                        /* our group will only have one sig, this one. So add that. */
                        SigGroupHeadAppendSig(&lookup_gr->sh, s);
                        lookup_gr->cnt++;
                    }
                }
            }
            SigGroupHeadFree(gr->sh);
            gr->sh = NULL;
        }
    } else {
        /* for each source address group in the signature... */
        for (gr = head; gr != NULL; gr = gr->next) {
            /* ...see if the group is in the tmp list, and if not add it. */
            if (family == AF_INET) {
                lookup_gr = DetectAddressGroupLookup(de_ctx->io_tmp_gh->ipv4_head,gr->ad);
            } else if (family == AF_INET6) {
                lookup_gr = DetectAddressGroupLookup(de_ctx->io_tmp_gh->ipv6_head,gr->ad);
            } else {
                lookup_gr = DetectAddressGroupLookup(de_ctx->io_tmp_gh->any_head,gr->ad);
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

                if (family == AF_INET) {
                    DetectAddressGroupAdd(&de_ctx->io_tmp_gh->ipv4_head, grtmp);
                } else if (family == AF_INET6) {
                    DetectAddressGroupAdd(&de_ctx->io_tmp_gh->ipv6_head, grtmp);
                } else {
                    DetectAddressGroupAdd(&de_ctx->io_tmp_gh->any_head, grtmp);
                }

                SigGroupHeadAppendSig(&grtmp->sh, s);
            } else {
                /* our group will only have one sig, this one. So add that. */
                SigGroupHeadAppendSig(&lookup_gr->sh, s);
                lookup_gr->cnt++;
            }

            SigGroupHeadFree(gr->sh);
            gr->sh = NULL;
        }
    }

    return 0;
error:
    return -1;
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

#define MAX_UNIQ_GROUPS 8

/* set unique_groups to 0 for no grouping.
 *
 * srchead is a ordered "inserted" list w/o internal overlap
 *
 */
int CreateGroupedAddrList(DetectAddressGroup *srchead, int family, DetectAddressGroupsHead *newhead, u_int32_t unique_groups) {
    DetectAddressGroup *tmplist = NULL, *tmplist2 = NULL, *joingr = NULL;
    char insert = 0;
    DetectAddressGroup *gr, *next_gr;
    u_int32_t groups = 0;

    /* insert the addresses into the tmplist, where it will
     * be sorted descending on 'cnt'. */
    for (gr = srchead; gr != NULL; gr = gr->next) {
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

        SigGroupHeadCopySigs(gr->sh,&newtmp->sh);
        DetectPort *port = gr->port;
        for ( ; port != NULL; port = port->next) {
            DetectPortInsertCopy(&newtmp->port, port);
        }

        /* insert it */
        DetectAddressGroup *tmpgr = tmplist, *prevtmpgr = NULL;
        if (tmplist == NULL) {
            /* empty list, set head */
            tmplist = newtmp;
        } else {
            /* look for the place to insert */
            for ( ; tmpgr != NULL&&!insert; tmpgr = tmpgr->next) {
                if (gr->cnt > tmpgr->cnt) {
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

    u_int32_t i = unique_groups;
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

                SigGroupHeadCopySigs(gr->sh,&joingr->sh);

                DetectPort *port = gr->port;
                for ( ; port != NULL; port = port->next) {
                    DetectPortInsertCopy(&joingr->port, port);
                }
            } else {
                DetectAddressGroupJoin(joingr, gr);
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

            SigGroupHeadCopySigs(gr->sh,&newtmp->sh);

            DetectPort *port = gr->port;
            for ( ; port != NULL; port = port->next) {
                DetectPortInsertCopy(&newtmp->port, port);
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

        SigGroupHeadCopySigs(gr->sh,&newtmp->sh);

        DetectPort *port = gr->port;
        for ( ; port != NULL; port = port->next) {
            DetectPortInsertCopy(&newtmp->port, port);
        }

        DetectAddressGroupInsert(newhead,newtmp);

        next_gr = gr->next;
//        DetectAddressGroupFree(gr);
        gr = next_gr;
    }
    /* if present, insert the joingr that covers the rest */
    if (joingr != NULL) {
        DetectAddressGroupInsert(newhead,joingr);

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

    }

    //for (gr = newhead->ipv4_head; gr != NULL; gr = gr->next) {
    //    printf(" -= Address "); DetectAddressDataPrint(gr->ad); printf("\n");
    //}

    return 0;
error:
    return -1;
}

int CreateGroupedPortList(DetectPort *srchead, DetectPort **newhead, u_int32_t unique_groups) {
    DetectPort *tmplist = NULL, *tmplist2 = NULL, *joingr = NULL;
    char insert = 0;
    DetectPort *gr, *next_gr;

    /* insert the addresses into the tmplist, where it will
     * be sorted descending on 'cnt'. */
    for (gr = srchead; gr != NULL; gr = gr->next) {
        /* alloc a copy */
        DetectPort *newtmp = DetectPortCopySingle(gr);
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
                if (gr->cnt > tmpgr->cnt) {
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

    u_int32_t i = unique_groups;
    for (gr = tmplist; gr != NULL; ) {
        if (i == 0) {
            if (joingr == NULL) {
                joingr = DetectPortCopySingle(gr);
                if (joingr == NULL) {
                    goto error;
                }
            } else {
                DetectPortJoin(joingr, gr);
            }
        } else {
            DetectPort *newtmp = DetectPortCopySingle(gr);
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
        DetectPort *newtmp = DetectPortCopySingle(gr);
        if (newtmp == NULL) {
            goto error;
        }

        DetectPortInsert(newhead,newtmp);

        next_gr = gr->next;
        DetectPortFree(gr);
        gr = next_gr;
    }
    /* if present, insert the joingr that covers the rest */
    if (joingr != NULL) {
        DetectPortInsert(newhead,joingr);
    }

    //for (gr = *newhead; gr != NULL; gr = gr->next) {
    //    printf("  -= Port "); DetectPortPrint(gr); printf("\n");
    //}

    return 0;
error:
    return -1;
}

/* fill the global src group head, with the sigs included */
int SigAddressPrepareStage2(DetectEngineCtx *de_ctx) {
    Signature *tmp_s = NULL;
    DetectAddressGroup *gr = NULL;
    u_int32_t cnt = 0, sigs = 0, insert = 0;

    if (!(de_ctx->flags & DE_QUIET)) {
        printf("* Building signature grouping structure, stage 2: "
               "building source address list...\n");
    }

    int proto;
    for (proto = 0; proto < 256; proto++) {
        de_ctx->src_gh[proto] = DetectAddressGroupsHeadInit();
        if (de_ctx->src_gh[proto] == NULL) {
            goto error;
        }
        de_ctx->tmp_gh[proto] = DetectAddressGroupsHeadInit();
        if (de_ctx->tmp_gh[proto] == NULL) {
            goto error;
        }
    }
    /* IP ONLY heads */
    de_ctx->io_src_gh = DetectAddressGroupsHeadInit();
    if (de_ctx->io_src_gh == NULL) {
        goto error;
    }
    de_ctx->io_tmp_gh = DetectAddressGroupsHeadInit();
    if (de_ctx->io_tmp_gh == NULL) {
        goto error;
    }

    /* now for every rule add the source group to our temp lists */
    for (tmp_s = de_ctx->sig_list; tmp_s != NULL; tmp_s = tmp_s->next) {
        BuildSourceAddressList(de_ctx,tmp_s,AF_INET);
        BuildSourceAddressList(de_ctx,tmp_s,AF_INET6);
        BuildSourceAddressList(de_ctx,tmp_s,AF_UNSPEC);
        sigs++;
    }

    /* create the final src addr list based on the tmplist. */
    for (proto = 0; proto < 256; proto++) {
        CreateGroupedAddrList(de_ctx->tmp_gh[proto]->ipv4_head, AF_INET, de_ctx->src_gh[proto], MAX_UNIQ_GROUPS);
        CreateGroupedAddrList(de_ctx->tmp_gh[proto]->ipv6_head, AF_INET6, de_ctx->src_gh[proto], MAX_UNIQ_GROUPS);
        CreateGroupedAddrList(de_ctx->tmp_gh[proto]->any_head, AF_UNSPEC, de_ctx->src_gh[proto], MAX_UNIQ_GROUPS);

        //DetectAddressGroupsHeadFree(de_ctx->tmp_gh[proto]);
        free(de_ctx->tmp_gh[proto]);

       //printf("g_src_gh[%d] strt\n", proto);
       //if (proto == 6)DetectAddressGroupPrintList(de_ctx->src_gh[proto]->ipv4_head);
       //DetectAddressGroupPrintList(de_ctx->src_gh[proto]->ipv6_head);
       //DetectAddressGroupPrintList(de_ctx->src_gh[proto]->any_head);
       //printf("g_src_gh[%d] end\n", proto);
    }

    /* IP ONLY */
    for (gr = de_ctx->io_tmp_gh->ipv4_head; gr != NULL; ) {
        //printf("Inserting2'ing: "); DetectAddressDataPrint(gr->ad); printf("\n");
        DetectAddressGroup *grnext = gr->next;

        gr->next = NULL;
        if (DetectAddressGroupInsert(de_ctx->io_src_gh,gr) < 0)
            goto error;

        gr = grnext;
    }
    for (gr = de_ctx->io_tmp_gh->ipv6_head; gr != NULL; ) {
        //printf("Inserting2'ing: "); DetectAddressDataPrint(gr->ad); printf("\n");
        DetectAddressGroup *grnext = gr->next;

        gr->next = NULL;
        if (DetectAddressGroupInsert(de_ctx->io_src_gh,gr) < 0)
            goto error;

        gr = grnext;
    }
    free(de_ctx->io_tmp_gh);

    //DetectAddressGroupPrintMemory();
    //DetectSigGroupPrintMemory();

    //printf("g_src_gh strt\n");
    //DetectAddressGroupPrintList(g_src_gh->ipv4_head);
    //printf("g_src_gh end\n");

    if (!(de_ctx->flags & DE_QUIET)) {
        printf("* %u signatures, %u sigs appends, %u actual source address inserts\n", sigs,cnt,insert);
    }

    /* TCP */
    u_int32_t cnt_any = 0, cnt_ipv4 = 0, cnt_ipv6 = 0;
    for (gr = de_ctx->src_gh[6]->any_head; gr != NULL; gr = gr->next) {
        cnt_any++;
    }
    for (gr = de_ctx->src_gh[6]->ipv4_head; gr != NULL; gr = gr->next) {
        cnt_ipv4++;
    }
    for (gr = de_ctx->src_gh[6]->ipv6_head; gr != NULL; gr = gr->next) {
        cnt_ipv6++;
    }
    if (!(de_ctx->flags & DE_QUIET)) {
        printf(" * TCP Source address blocks:     any: %4u, ipv4: %4u, ipv6: %4u.\n", cnt_any, cnt_ipv4, cnt_ipv6);
    }

    cnt_any = 0, cnt_ipv4 = 0, cnt_ipv6 = 0;
    for (gr = de_ctx->src_gh[17]->any_head; gr != NULL; gr = gr->next) {
        cnt_any++;
    }
    for (gr = de_ctx->src_gh[17]->ipv4_head; gr != NULL; gr = gr->next) {
        cnt_ipv4++;
    }
    for (gr = de_ctx->src_gh[17]->ipv6_head; gr != NULL; gr = gr->next) {
        cnt_ipv6++;
    }
    if (!(de_ctx->flags & DE_QUIET)) {
        printf(" * UDP Source address blocks:     any: %4u, ipv4: %4u, ipv6: %4u.\n", cnt_any, cnt_ipv4, cnt_ipv6);
    }

    cnt_any = 0, cnt_ipv4 = 0, cnt_ipv6 = 0;
    for (gr = de_ctx->src_gh[1]->any_head; gr != NULL; gr = gr->next) {
        cnt_any++;
    }
    for (gr = de_ctx->src_gh[1]->ipv4_head; gr != NULL; gr = gr->next) {
        cnt_ipv4++;
    }
    for (gr = de_ctx->src_gh[1]->ipv6_head; gr != NULL; gr = gr->next) {
        cnt_ipv6++;
    }
    if (!(de_ctx->flags & DE_QUIET)) {
        printf(" * ICMP Source address blocks:    any: %4u, ipv4: %4u, ipv6: %4u.\n", cnt_any, cnt_ipv4, cnt_ipv6);
    }

    cnt_any = 0, cnt_ipv4 = 0, cnt_ipv6 = 0;
    for (gr = de_ctx->io_src_gh->any_head; gr != NULL; gr = gr->next) {
        cnt_any++;
    }
    for (gr = de_ctx->io_src_gh->ipv4_head; gr != NULL; gr = gr->next) {
        cnt_ipv4++;
    }
    for (gr = de_ctx->io_src_gh->ipv6_head; gr != NULL; gr = gr->next) {
        cnt_ipv6++;
    }
    if (!(de_ctx->flags & DE_QUIET)) {
        printf(" * IP-only Source address blocks: any: %4u, ipv4: %4u, ipv6: %4u.\n", cnt_any, cnt_ipv4, cnt_ipv6);
        printf("* Building signature grouping structure, stage 2: building source address list... done\n");
    }

    return 0;
error:
    printf("SigAddressPrepareStage2 error\n");
    return -1;
}

static int BuildDestinationAddressHeads(DetectEngineCtx *de_ctx, DetectAddressGroupsHead *head, int family) {
    Signature *tmp_s = NULL;
    DetectAddressGroup *gr = NULL, *sgr = NULL, *lookup_gr = NULL;
    u_int32_t max_idx = 0;

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
        u_int32_t sig;
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

                    SigGroupHeadAppendSig(&grtmp->sh,tmp_s);
                    grtmp->cnt = 1;
                } else {
                    /* our group will only have one sig, this one. So add that. */
                    SigGroupHeadAppendSig(&lookup_gr->sh,tmp_s);
                    lookup_gr->cnt++;
                }
            }

        }

        /* Create the destination address list, keeping in
         * mind the limits we use. */
        CreateGroupedAddrList(tmp_gr_list,family,gr->dst_gh,MAX_UNIQ_GROUPS);

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
            SigGroupHead *sgh = SigGroupHeadHashLookup(sgr->sh);
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
                    SigGroupHead *mpmsh = SigGroupHeadMpmHashLookup(sgr->sh);
                    if (mpmsh == NULL) {
                        SigGroupHeadMpmHashAdd(sgr->sh);

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
                    SigGroupHead *mpmsh = SigGroupHeadMpmUriHashLookup(sgr->sh);
                    if (mpmsh == NULL) {
                        SigGroupHeadMpmUriHashAdd(sgr->sh);
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
                    mpm_memory_size += sgr->sh->mpm_ctx->memory_size;
                }
                if (!(sgr->sh->flags & SIG_GROUP_HEAD_MPM_URI_COPY) && sgr->sh->mpm_uri_ctx) {
                    mpm_memory_size += sgr->sh->mpm_uri_ctx->memory_size;
                }

                SigGroupHeadHashAdd(sgr->sh);
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

static int BuildDestinationAddressHeadsIPOnly(DetectEngineCtx *de_ctx, DetectAddressGroupsHead *head, int family) {
    Signature *tmp_s = NULL;
    DetectAddressGroup *gr = NULL, *sgr = NULL, *lookup_gr = NULL;
    u_int32_t max_idx = 0;

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
        u_int32_t sig;
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

                    SigGroupHeadAppendSig(&grtmp->sh,tmp_s);
                    grtmp->cnt = 1;
                } else {
                    /* our group will only have one sig, this one. So add that. */
                    SigGroupHeadAppendSig(&lookup_gr->sh,tmp_s);
                    lookup_gr->cnt++;
                }
            }

        }

        /* Create the destination address list, keeping in
         * mind the limits we use. */
        CreateGroupedAddrList(tmp_gr_list,family,gr->dst_gh,0);

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
            SigGroupHead *sgh = SigGroupHeadHashLookup(sgr->sh);
            if (sgh == NULL) {
                /* put the contents in our sig group head */
                SigGroupHeadSetSigCnt(sgr->sh, max_idx);
                SigGroupHeadBuildMatchArray(de_ctx,sgr->sh, max_idx);

                SigGroupHeadHashAdd(sgr->sh);
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

static int BuildDestinationAddressHeadsWithBothPorts(DetectEngineCtx *de_ctx, DetectAddressGroupsHead *head, int family) {
    Signature *tmp_s = NULL;
    DetectAddressGroup *src_gr = NULL, *dst_gr = NULL, *sig_gr = NULL, *lookup_gr = NULL;
    DetectAddressGroup *src_gr_head = NULL, *dst_gr_head = NULL, *sig_gr_head = NULL;
    u_int32_t max_idx = 0;

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
        u_int32_t sig;
        for (sig = 0; sig < de_ctx->sig_array_len; sig++) {
            if (!(src_gr->sh->sig_array[(sig/8)] & (1<<(sig%8))))
                continue;

            tmp_s = de_ctx->sig_array[sig];
            if (tmp_s == NULL)
                continue;

            max_idx = sig;

            /* build the temp list */
            sig_gr_head = GetHeadPtr(&tmp_s->dst,family);
            for (sig_gr = sig_gr_head; sig_gr != NULL; sig_gr = sig_gr->next) {
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
                    SigGroupHeadAppendSig(&grtmp->sh,tmp_s);
                    grtmp->cnt = 1;

                    DetectAddressGroupAdd(&tmp_gr_list,grtmp);
                } else {
                    /* our group will only have one sig, this one. So add that. */
                    SigGroupHeadAppendSig(&lookup_gr->sh,tmp_s);
                    lookup_gr->cnt++;
                }

                SigGroupHeadFree(sig_gr->sh);
                sig_gr->sh = NULL;
            }
        }

        /* Create the destination address list, keeping in
         * mind the limits we use. */
        CreateGroupedAddrList(tmp_gr_list,family,src_gr->dst_gh,MAX_UNIQ_GROUPS);

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
            SigGroupHead *lookup_sgh = SigGroupHeadHashLookup(dst_gr->sh);
            if (lookup_sgh == NULL) {
                DetectPortSpHashReset();

                u_int32_t sig2;
                for (sig2 = 0; sig2 < max_idx+1; sig2++) {
                    if (!(dst_gr->sh->sig_array[(sig2/8)] & (1<<(sig2%8))))
                        continue;

                    Signature *s = de_ctx->sig_array[sig2];
                    if (s == NULL)
                        continue;

                    DetectPort *sdp = s->sp;
                    for ( ; sdp != NULL; sdp = sdp->next) {
                        DetectPort *lookup_port = DetectPortSpHashLookup(sdp);
                        if (lookup_port == NULL) {
                            DetectPort *port = DetectPortCopySingle(sdp);
                            if (port == NULL)
                                goto error;

                            SigGroupHeadAppendSig(&port->sh,s);
                            DetectPortSpHashAdd(port);
                            port->cnt = 1;
                        } else {
                            SigGroupHeadAppendSig(&lookup_port->sh,s);
                            lookup_port->cnt++;
                        }
                    }
                }

                DetectPort *p = DetectPortSpHashGetListPtr();
                CreateGroupedPortList(p, &dst_gr->port, MAX_UNIQ_GROUPS);
                if (p != NULL) {
                    DetectPort *next_p;
                    for (; p != NULL; ) {
                        next_p = p->next;
                        DetectPortFree(p);
                        p = next_p;
                    }
                }

                SigGroupHeadHashAdd(dst_gr->sh);

                dst_gr->sh->port = dst_gr->port;
                /* mark this head for deletion once we no longer need
                 * the hash. We're only using the port ptr, so no problem
                 * when we remove this after initialization is done */
                dst_gr->sh->flags |= SIG_GROUP_HEAD_FREE;

                /* for each destination port we setup the siggrouphead here */
                DetectPort *sp = dst_gr->port;
                for ( ; sp != NULL; sp = sp->next) {
                    //printf("   * Port(range): "); DetectPortPrint(sp); printf("\n");

                    if (sp->sh == NULL)
                        continue;

                    /* we will reuse address sig group heads at this points,
                     * because if the sigs are the same, the ports will be
                     * the same. Saves memory and a lot of init time. */
                    SigGroupHead *lookup_sp_sgh = SigGroupHeadSPortHashLookup(sp->sh);
                    if (lookup_sp_sgh == NULL) {
                        DetectPortHashReset();
                        u_int32_t sig2;
                        for (sig2 = 0; sig2 < max_idx+1; sig2++) {
                            if (!(sp->sh->sig_array[(sig2/8)] & (1<<(sig2%8))))
                                continue;

                            Signature *s = de_ctx->sig_array[sig2];
                            if (s == NULL)
                                continue;

                            DetectPort *sdp = s->dp;
                            for ( ; sdp != NULL; sdp = sdp->next) {
                                DetectPort *lookup_port = DetectPortHashLookup(sdp);
                                if (lookup_port == NULL) {
                                    DetectPort *port = DetectPortCopySingle(sdp);
                                    if (port == NULL)
                                        goto error;

                                    SigGroupHeadAppendSig(&port->sh,s);
                                    DetectPortHashAdd(port);
                                    port->cnt = 1;
                                } else {
                                    SigGroupHeadAppendSig(&lookup_port->sh,s);
                                    lookup_port->cnt++;
                                }
                            }
                        }

                        DetectPort *p = DetectPortHashGetListPtr();
                        CreateGroupedPortList(p,&sp->dst_ph,MAX_UNIQ_GROUPS);
                        if (p != NULL) {
                            DetectPort *next_p;
                            for (; p != NULL; ) {
                                next_p = p->next;
                                DetectPortFree(p);
                                p = next_p;
                            }
                        }

                        SigGroupHeadSPortHashAdd(sp->sh);

                        sp->sh->port = sp->dst_ph;
                        /* mark this head for deletion once we no longer need
                         * the hash. We're only using the port ptr, so no problem
                         * when we remove this after initialization is done */
                        sp->sh->flags |= SIG_GROUP_HEAD_FREE;

                        /* for each destination port we setup the siggrouphead here */
                        DetectPort *dp = sp->dst_ph;
                        for ( ; dp != NULL; dp = dp->next) {
                            //printf("   * Port(range): "); DetectPortPrint(dp); printf(" ");
                            //printf("\n");

                            if (dp->sh == NULL)
                                continue;

                            /* Because a pattern matcher context uses quite some
                             * memory, we first check if we can reuse it from
                             * another group head. */
                            SigGroupHead *lookup_dp_sgh = SigGroupHeadPortHashLookup(dp->sh);
                            if (lookup_dp_sgh == NULL) {
                                SigGroupHeadSetSigCnt(dp->sh, max_idx);
                                SigGroupHeadBuildMatchArray(de_ctx,dp->sh, max_idx);

                                SigGroupHeadLoadContent(de_ctx, dp->sh);
                                if (dp->sh->content_size == 0) {
                                    de_ctx->mpm_none++;
                                } else {
                                    /* now have a look if we can reuse a mpm ctx */
                                    SigGroupHead *mpmsh = SigGroupHeadMpmHashLookup(dp->sh);
                                    if (mpmsh == NULL) {
                                        SigGroupHeadMpmHashAdd(dp->sh);

                                        de_ctx->mpm_unique++;
                                    } else {
                                        dp->sh->mpm_ctx = mpmsh->mpm_ctx;
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
                                    SigGroupHead *mpmsh = SigGroupHeadMpmUriHashLookup(dp->sh);
                                    if (mpmsh == NULL) {
                                        SigGroupHeadMpmUriHashAdd(dp->sh);

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
                                    mpm_memory_size += dp->sh->mpm_ctx->memory_size;
                                }
                                if (!(dp->sh->flags & SIG_GROUP_HEAD_MPM_URI_COPY) && dp->sh->mpm_uri_ctx) {
                                    mpm_memory_size += dp->sh->mpm_uri_ctx->memory_size;
                                }

                                SigGroupHeadPortHashAdd(dp->sh);
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
    int i,r;

    if (!(de_ctx->flags & DE_QUIET)) {
        printf("* Building signature grouping structure, stage 3: "
               "building destination address lists...\n");
    }
    //DetectAddressGroupPrintMemory();
    //DetectSigGroupPrintMemory();
    //DetectPortPrintMemory();

    SigGroupHeadHashInit();
    SigGroupHeadPortHashInit();
    SigGroupHeadSPortHashInit();
    SigGroupHeadMpmHashInit();
    SigGroupHeadMpmUriHashInit();

    DetectPortHashInit();
    DetectPortSpHashInit();

    r = BuildDestinationAddressHeadsWithBothPorts(de_ctx, de_ctx->src_gh[6],AF_INET);
    if (r < 0) {
        printf ("BuildDestinationAddressHeads(src_gh[6],AF_INET) failed\n");
        goto error;
    }
//#if 0
    r = BuildDestinationAddressHeadsWithBothPorts(de_ctx, de_ctx->src_gh[17],AF_INET);
    if (r < 0) {
        printf ("BuildDestinationAddressHeads(src_gh[17],AF_INET) failed\n");
        goto error;
    }
    r = BuildDestinationAddressHeadsWithBothPorts(de_ctx, de_ctx->src_gh[6],AF_INET6);
    if (r < 0) {
        printf ("BuildDestinationAddressHeads(src_gh[6],AF_INET) failed\n");
        goto error;
    }
    r = BuildDestinationAddressHeadsWithBothPorts(de_ctx, de_ctx->src_gh[17],AF_INET6);
    if (r < 0) {
        printf ("BuildDestinationAddressHeads(src_gh[17],AF_INET) failed\n");
        goto error;
    }
    r = BuildDestinationAddressHeadsWithBothPorts(de_ctx, de_ctx->src_gh[6],AF_UNSPEC);
    if (r < 0) {
        printf ("BuildDestinationAddressHeads(src_gh[6],AF_INET) failed\n");
        goto error;
    }
    r = BuildDestinationAddressHeadsWithBothPorts(de_ctx, de_ctx->src_gh[17],AF_UNSPEC);
    if (r < 0) {
        printf ("BuildDestinationAddressHeads(src_gh[17],AF_INET) failed\n");
        goto error;
    }

    for (i = 0; i < 256; i++) {
        if (i == IPPROTO_TCP || i == IPPROTO_UDP)
            continue;

        r = BuildDestinationAddressHeads(de_ctx, de_ctx->src_gh[i],AF_INET);
        if (r < 0) {
            printf ("BuildDestinationAddressHeads(src_gh[%d],AF_INET) failed\n", i);
            goto error;
        }
        r = BuildDestinationAddressHeads(de_ctx, de_ctx->src_gh[i],AF_INET6);
        if (r < 0) {
            printf ("BuildDestinationAddressHeads(src_gh[%d],AF_INET6) failed\n", i);
            goto error;
        }
        r = BuildDestinationAddressHeads(de_ctx, de_ctx->src_gh[i],AF_UNSPEC); /* for any */
        if (r < 0) {
            printf ("BuildDestinationAddressHeads(src_gh[%d],AF_UNSPEC) failed\n", i);
            goto error;
        }
    }

    /* IP ONLY */
    r = BuildDestinationAddressHeadsIPOnly(de_ctx, de_ctx->io_src_gh,AF_INET);
    if (r < 0) {
        printf ("BuildDestinationAddressHeads(src_gh[%d],AF_INET) failed\n", i);
        goto error;
    }
    r = BuildDestinationAddressHeadsIPOnly(de_ctx, de_ctx->io_src_gh,AF_INET6);
    if (r < 0) {
        printf ("BuildDestinationAddressHeads(src_gh[%d],AF_INET6) failed\n", i);
        goto error;
    }
    r = BuildDestinationAddressHeadsIPOnly(de_ctx, de_ctx->io_src_gh,AF_UNSPEC); /* for any */
    if (r < 0) {
        printf ("BuildDestinationAddressHeads(src_gh[%d],AF_UNSPEC) failed\n", i);
        goto error;
    }
//#endif
    /* cleanup group head (uri)content_array's */
    SigGroupHeadFreeMpmArrays();
    /* cleanup group head sig arrays */
    SigGroupHeadFreeSigArrays();
    /* cleanup heads left over in *WithPorts */
    /* XXX VJ breaks SigGroupCleanup */
    //SigGroupHeadFreeHeads();

    /* cleanup the hashes */
    SigGroupHeadHashFree();
    SigGroupHeadPortHashFree();
    SigGroupHeadSPortHashFree();
    SigGroupHeadMpmHashFree();
    SigGroupHeadMpmUriHashFree();

    DetectPortHashFree();
    DetectPortSpHashFree();

    //DetectAddressGroupPrintMemory();
    //DetectSigGroupPrintMemory();
    //DetectPortPrintMemory();
//#endif
    if (!(de_ctx->flags & DE_QUIET)) {
        printf("* MPM memory %u (dynamic %u, ctxs %u)\n",
            mpm_memory_size + ((de_ctx->mpm_unique + de_ctx->mpm_uri_unique) * sizeof(MpmCtx)),
            mpm_memory_size, ((de_ctx->mpm_unique + de_ctx->mpm_uri_unique) * sizeof(MpmCtx)));

        printf(" * Max sig id %u, array size %u\n", SigGetMaxId(), SigGetMaxId() / 8 + 1);
        printf("* Signature group heads: unique %u, copies %u.\n", de_ctx->gh_unique, de_ctx->gh_reuse);
        printf("* MPM instances: %u unique, copies %u (none %u).\n",
                de_ctx->mpm_unique, de_ctx->mpm_reuse, de_ctx->mpm_none);
        printf("* MPM (URI) instances: %u unique, copies %u (none %u).\n",
                de_ctx->mpm_uri_unique, de_ctx->mpm_uri_reuse, de_ctx->mpm_uri_none);
        printf("* MPM max patcnt %u, avg %u\n", de_ctx->mpm_max_patcnt, de_ctx->mpm_tot_patcnt/de_ctx->mpm_unique);
        if (de_ctx->mpm_uri_tot_patcnt && de_ctx->mpm_uri_unique)
            printf("* MPM (URI) max patcnt %u, avg %u (%u/%u)\n", de_ctx->mpm_uri_max_patcnt, de_ctx->mpm_uri_tot_patcnt/de_ctx->mpm_uri_unique, de_ctx->mpm_uri_tot_patcnt, de_ctx->mpm_uri_unique);
        printf("* Building signature grouping structure, stage 3: building destination address lists... done\n");
    }
    return 0;
error:
    printf("SigAddressPrepareStage3 error\n");
    return -1;
}

int SigAddressCleanupStage1(DetectEngineCtx *de_ctx) {
    DetectAddressGroup *gr = NULL;

    if (!(de_ctx->flags & DE_QUIET)) {
        printf("* Cleaning up signature grouping structure, stage 1...\n");
    }

    int i;
    for (i = 0; i < 256; i++) {
        DetectAddressGroupsHeadFree(de_ctx->src_gh[i]);
        de_ctx->src_gh[i] = NULL;
    }
    DetectAddressGroupsHeadFree(de_ctx->io_src_gh);

    if (!(de_ctx->flags & DE_QUIET)) {
        printf("* Cleaning up signature grouping structure, stage 1... done\n");
    }
    return 0;
}

void DbgPrintSigs(SigGroupHead *sgh) {
    if (sgh == NULL) {
        printf("\n");
        return;
    }

    u_int32_t sig;
    for (sig = 0; sig < sgh->sig_cnt; sig++) {
        printf("%u ", g_de_ctx->sig_array[sgh->match_array[sig]]->id);
    }
    printf("\n");
}

void DbgPrintSigs2(SigGroupHead *sgh) {
    if (sgh == NULL) {
        printf("\n");
        return;
    }

    u_int32_t sig;
    for (sig = 0; sig < SigGetMaxId(); sig++) {
        if (sgh->sig_array[(sig/8)] & (1<<(sig%8))) {
            printf("%u ", g_de_ctx->sig_array[sig]->id);
        }
    }
    printf("\n");
}

/* shortcut for debugging. If enabled Stage5 will
 * print sigid's for all groups */
#define PRINTSIGS

/* just printing */
int SigAddressPrepareStage5(void) {
    DetectAddressGroupsHead *global_dst_gh = NULL;
    DetectAddressGroup *global_src_gr = NULL, *global_dst_gr = NULL;
    int i;

    printf("* Building signature grouping structure, stage 5: print...\n");

    int proto;
    for (proto = 0; proto < 256; proto++) {
        if (proto != 6)
            continue;

        for (global_src_gr = g_de_ctx->src_gh[proto]->ipv4_head; global_src_gr != NULL;
                global_src_gr = global_src_gr->next)
        {
            printf("- "); DetectAddressDataPrint(global_src_gr->ad);
            //printf(" (sh %p)\n", global_src_gr->sh);
            printf("\n");

            global_dst_gh = global_src_gr->dst_gh;
            if (global_dst_gh == NULL)
                continue;

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
                    printf("  * Src port(range): "); DetectPortPrint(sp);
                    //printf(" (sh %p)", sp->sh);
                    printf("\n");
                    DetectPort *dp = sp->dst_ph;
                    for ( ; dp != NULL; dp = dp->next) {
                        printf("   * Dst port(range): "); DetectPortPrint(dp);
                        //printf(" (sh %p)", dp->sh); 
#ifdef PRINTSIGS
                        printf(" - ");
                        for (i = 0; i < dp->sh->sig_cnt; i++) {
                            Signature *s = g_de_ctx->sig_array[dp->sh->match_array[i]];
                            printf("%u ", s->id);
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
#ifdef PRINTSIGS
                        printf(" - ");
                        for (i = 0; i < dp->sh->sig_cnt; i++) {
                            Signature *s = g_de_ctx->sig_array[dp->sh->match_array[i]];
                            printf("%u ", s->id);
                        }
#endif
                        printf("\n");
                    }
                }
            }
        }

        for (global_src_gr = g_de_ctx->src_gh[proto]->ipv6_head; global_src_gr != NULL;
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
#ifdef PRINTSIGS
                        printf(" - ");
                        for (i = 0; i < dp->sh->sig_cnt; i++) {
                            Signature *s = g_de_ctx->sig_array[dp->sh->match_array[i]];
                            printf("%u ", s->id);
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
#ifdef PRINTSIGS
                        printf(" - ");
                        for (i = 0; i < dp->sh->sig_cnt; i++) {
                            Signature *s = g_de_ctx->sig_array[dp->sh->match_array[i]];
                            printf("%u ", s->id);
                        }
#endif
                        printf("\n");
                    }
                }
            }
        }

        for (global_src_gr = g_de_ctx->src_gh[proto]->any_head; global_src_gr != NULL;
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
#ifdef PRINTSIGS
                        printf(" - ");
                        for (i = 0; i < dp->sh->sig_cnt; i++) {
                            Signature *s = g_de_ctx->sig_array[dp->sh->match_array[i]];
                            printf("%u ", s->id);
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
#ifdef PRINTSIGS
                        printf(" - ");
                        for (i = 0; i < dp->sh->sig_cnt; i++) {
                            Signature *s = g_de_ctx->sig_array[dp->sh->match_array[i]];
                            printf("%u ", s->id);
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
#ifdef PRINTSIGS
                        printf(" - ");
                        for (i = 0; i < dp->sh->sig_cnt; i++) {
                            Signature *s = g_de_ctx->sig_array[dp->sh->match_array[i]];
                            printf("%u ", s->id);
                        }
#endif
                        printf("\n");
                    }
                }
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
//    SigAddressPrepareStage5();

//    DetectAddressGroupPrintMemory();
//    DetectSigGroupPrintMemory();
//    DetectPortPrintMemory();
    return 0;
}

int SigGroupCleanup (void) {
    SigAddressCleanupStage1(g_de_ctx);
    return 0;
}

int SigGroupGetSrcAddress(DetectAddressGroupsHead *src) {
    u_int32_t ip = 0x04030201; /* 1.2.3.4 */

    printf("ip & 0x000000ff %8u 0x%08X >> 0  %u\n", ip & 0x000000ff, ip & 0x000000ff, (ip & 0x000000ff) >> 0);
    printf("ip & 0x0000ff00 %8u 0x%08X >> 8  %u\n", ip & 0x0000ff00, ip & 0x0000ff00, (ip & 0x0000ff00) >> 8);
    printf("ip & 0x00ff0000 %8u 0x%08X >> 16 %u\n", ip & 0x00ff0000, ip & 0x00ff0000, (ip & 0x00ff0000) >> 16);
    printf("ip & 0xff000000 %8u 0x%08X >> 24 %u\n", ip & 0xff000000, ip & 0xff000000, (ip & 0xff000000) >> 24);

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

    u_int8_t i = 0;
    for (i = 0; i < DETECT_TBLSIZE; i++) {
        if (sigmatch_table[i].RegisterTests == NULL) {
            printf("Warning: detection plugin %s has no unittest "
                   "registration function.\n", sigmatch_table[i].name);
        }
    }
}

void SigTableRegisterTests(void) {
    /* register the tests */
    u_int8_t i = 0;
    for (i = 0; i < DETECT_TBLSIZE; i++) {
        if (sigmatch_table[i].RegisterTests != NULL) {
            sigmatch_table[i].RegisterTests();
        }
    }
}

/*
 * TESTS
 */

#include "flow-util.h"

int SigTest01 (void) {
    u_int8_t *buf = (u_int8_t *)
                    "GET /one/ HTTP/1.1\r\n"
                    "Host: one.example.org\r\n"
                    "\r\n\r\n"
                    "GET /two/ HTTP/1.1\r\n"
                    "Host: two.example.org\r\n"
                    "\r\n\r\n";
    u_int16_t buflen = strlen((char *)buf);
    Packet p;
    ThreadVars th_v;
    PatternMatcherThread *pmt;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.tcp_payload = buf;
    p.tcp_payload_len = buflen;
    p.proto = IPPROTO_TCP;

    g_de_ctx = DetectEngineCtxInit();
    if (g_de_ctx == NULL) {
        goto end;
    }

    g_de_ctx->flags |= DE_QUIET;

    g_de_ctx->sig_list = SigInit("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:\"GET \"; depth:4; pcre:\"/GET (?P<pkt_http_uri>.*) HTTP\\/\\d\\.\\d\\r\\n/G\"; recursive; sid:1;)");
    if (g_de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(g_de_ctx);
    PatternMatchPrepare(mpm_ctx);
    PatternMatcherThreadInit(&th_v, (void *)&pmt);

    SigMatchSignatures(&th_v, pmt, &p);
    if (PacketAlertCheck(&p, 1) == 0) {
        result = 0;
        goto end;
    }

    //printf("URI0 \"%s\", len %u\n", p.http_uri.raw[0], p.http_uri.raw_size[0]);
    //printf("URI1 \"%s\", len %u\n", p.http_uri.raw[1], p.http_uri.raw_size[1]);

    if (p.http_uri.raw_size[0] == 5 &&
        memcmp(p.http_uri.raw[0], "/one/", 5) == 0 &&
        p.http_uri.raw_size[1] == 5 &&
        memcmp(p.http_uri.raw[1], "/two/", 5) == 0)
    {
        result = 1;
    }

    SigGroupCleanup();
    SigCleanSignatures();

    PatternMatcherThreadDeinit(&th_v, (void *)pmt);
    PatternMatchDestroy(mpm_ctx);
    DetectEngineCtxFree(g_de_ctx);
end:
    return result;
}

int SigTest02 (void) {
    u_int8_t *buf = (u_int8_t *)
                    "GET /one/ HTTP/1.1\r\n"
                    "Host: one.example.org\r\n"
                    "\r\n\r\n"
                    "GET /two/ HTTP/1.1\r\n"
                    "Host: two.example.org\r\n"
                    "\r\n\r\n";
    u_int16_t buflen = strlen((char *)buf);
    Packet p;
    ThreadVars th_v;
    PatternMatcherThread *pmt;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.tcp_payload = buf;
    p.tcp_payload_len = buflen;
    p.proto = IPPROTO_TCP;

    g_de_ctx = DetectEngineCtxInit();
    if (g_de_ctx == NULL) {
        goto end;
    }

    g_de_ctx->flags |= DE_QUIET;

    g_de_ctx->sig_list = SigInit("alert tcp any any -> any any (msg:\"HTTP TEST\"; content:\"Host: one.example.org\"; offset:20; depth:41; sid:1;)");
    if (g_de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(g_de_ctx);
    PatternMatchPrepare(mpm_ctx);
    PatternMatcherThreadInit(&th_v, (void *)&pmt);

    SigMatchSignatures(&th_v, pmt, &p);
    if (PacketAlertCheck(&p, 1))
        result = 1;

    SigGroupCleanup();
    SigCleanSignatures();

    PatternMatcherThreadDeinit(&th_v, (void *)pmt);
    PatternMatchDestroy(mpm_ctx);
    DetectEngineCtxFree(g_de_ctx);
end:
    return result;
}

int SigTest03 (void) {
    u_int8_t *buf = (u_int8_t *)
                    "GET /one/ HTTP/1.1\r\n"
                    "Host: one.example.org\r\n"
                    "\r\n\r\n"
                    "GET /two/ HTTP/1.1\r\n"
                    "Host: two.example.org\r\n"
                    "\r\n\r\n";
    u_int16_t buflen = strlen((char *)buf);
    Packet p;
    ThreadVars th_v;
    PatternMatcherThread *pmt;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.tcp_payload = buf;
    p.tcp_payload_len = buflen;
    p.proto = IPPROTO_TCP;

    g_de_ctx = DetectEngineCtxInit();
    if (g_de_ctx == NULL) {
        goto end;
    }

    g_de_ctx->flags |= DE_QUIET;

    g_de_ctx->sig_list = SigInit("alert tcp any any -> any any (msg:\"HTTP TEST\"; content:\"Host: one.example.org\"; offset:20; depth:40; sid:1;)");
    if (g_de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(g_de_ctx);
    PatternMatchPrepare(mpm_ctx);
    PatternMatcherThreadInit(&th_v, (void *)&pmt);

    SigMatchSignatures(&th_v, pmt, &p);
    if (!PacketAlertCheck(&p, 1))
        result = 1;

    SigGroupCleanup();
    SigCleanSignatures();

    PatternMatcherThreadDeinit(&th_v, (void *)pmt);
    PatternMatchDestroy(mpm_ctx);
    DetectEngineCtxFree(g_de_ctx);
end:
    return result;
}

int SigTest04 (void) {
    u_int8_t *buf = (u_int8_t *)
                    "GET /one/ HTTP/1.1\r\n"
                    "Host: one.example.org\r\n"
                    "\r\n\r\n"
                    "GET /two/ HTTP/1.1\r\n"
                    "Host: two.example.org\r\n"
                    "\r\n\r\n";
    u_int16_t buflen = strlen((char *)buf);

    Packet p;
    ThreadVars th_v;
    PatternMatcherThread *pmt;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.tcp_payload = buf;
    p.tcp_payload_len = buflen;
    p.proto = IPPROTO_TCP;

    g_de_ctx = DetectEngineCtxInit();
    if (g_de_ctx == NULL) {
        goto end;
    }

    g_de_ctx->flags |= DE_QUIET;

    g_de_ctx->sig_list = SigInit("alert tcp any any -> any any (msg:\"HTTP TEST\"; content:\"Host:\"; offset:20; depth:25; content:\"Host:\"; distance:47; within:52; sid:1;)");
    if (g_de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(g_de_ctx);
    PatternMatchPrepare(mpm_ctx);
    PatternMatcherThreadInit(&th_v, (void *)&pmt);

    SigMatchSignatures(&th_v, pmt, &p);
    if (PacketAlertCheck(&p, 1))
        result = 1;

    SigGroupCleanup();
    SigCleanSignatures();

    PatternMatcherThreadDeinit(&th_v, (void *)pmt);
    PatternMatchDestroy(mpm_ctx);
    DetectEngineCtxFree(g_de_ctx);
end:
    return result;
}

int SigTest05 (void) {
    u_int8_t *buf = (u_int8_t *)
                    "GET /one/ HTTP/1.1\r\n"    /* 20 */
                    "Host: one.example.org\r\n" /* 23, 43 */
                    "\r\n\r\n"                  /* 4,  47 */
                    "GET /two/ HTTP/1.1\r\n"    /* 20, 67 */
                    "Host: two.example.org\r\n" /* 23, 90 */
                    "\r\n\r\n";                 /* 4,  94 */
    u_int16_t buflen = strlen((char *)buf);
    Packet p;
    ThreadVars th_v;
    PatternMatcherThread *pmt;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.tcp_payload = buf;
    p.tcp_payload_len = buflen;
    p.proto = IPPROTO_TCP;

    g_de_ctx = DetectEngineCtxInit();
    if (g_de_ctx == NULL) {
        goto end;
    }

    g_de_ctx->flags |= DE_QUIET;

    g_de_ctx->sig_list = SigInit("alert tcp any any -> any any (msg:\"HTTP TEST\"; content:\"Host:\"; offset:20; depth:25; content:\"Host:\"; distance:48; within:52; sid:1;)");
    if (g_de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(g_de_ctx);
    PatternMatchPrepare(mpm_ctx);
    PatternMatcherThreadInit(&th_v, (void *)&pmt);

    SigMatchSignatures(&th_v, pmt, &p);
    if (!PacketAlertCheck(&p, 1))
        result = 1;

    SigGroupCleanup();
    SigCleanSignatures();

    PatternMatcherThreadDeinit(&th_v, (void *)pmt);
    PatternMatchDestroy(mpm_ctx);
    DetectEngineCtxFree(g_de_ctx);
end:
    return result;
}

int SigTest06 (void) {
    u_int8_t *buf = (u_int8_t *)
                    "GET /one/ HTTP/1.1\r\n"    /* 20 */
                    "Host: one.example.org\r\n" /* 23, 43 */
                    "\r\n\r\n"                  /* 4,  47 */
                    "GET /two/ HTTP/1.1\r\n"    /* 20, 67 */
                    "Host: two.example.org\r\n" /* 23, 90 */
                    "\r\n\r\n";                 /* 4,  94 */
    u_int16_t buflen = strlen((char *)buf);
    Packet p;
    ThreadVars th_v;
    PatternMatcherThread *pmt;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.tcp_payload = buf;
    p.tcp_payload_len = buflen;
    p.proto = IPPROTO_TCP;

    g_de_ctx = DetectEngineCtxInit();
    if (g_de_ctx == NULL) {
        goto end;
    }

    g_de_ctx->flags |= DE_QUIET;

    g_de_ctx->sig_list = SigInit("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:\"GET \"; depth:4; pcre:\"/GET (?P<pkt_http_uri>.*) HTTP\\/\\d\\.\\d\\r\\n/G\"; recursive; sid:1;)");
    if (g_de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }
    g_de_ctx->sig_list->next = SigInit("alert tcp any any -> any any (msg:\"HTTP URI test\"; uricontent:\"two\"; sid:2;)");
    if (g_de_ctx->sig_list->next == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(g_de_ctx);
    PatternMatchPrepare(mpm_ctx);
    PatternMatcherThreadInit(&th_v, (void *)&pmt);

    SigMatchSignatures(&th_v, pmt, &p);
    if (PacketAlertCheck(&p, 1) && PacketAlertCheck(&p, 2))
        result = 1;

    SigGroupCleanup();
    SigCleanSignatures();

    PatternMatcherThreadDeinit(&th_v, (void *)pmt);
    PatternMatchDestroy(mpm_ctx);
    DetectEngineCtxFree(g_de_ctx);
end:
    return result;
}

int SigTest07 (void) {
    u_int8_t *buf = (u_int8_t *)
                    "GET /one/ HTTP/1.1\r\n"    /* 20 */
                    "Host: one.example.org\r\n" /* 23, 43 */
                    "\r\n\r\n"                  /* 4,  47 */
                    "GET /two/ HTTP/1.1\r\n"    /* 20, 67 */
                    "Host: two.example.org\r\n" /* 23, 90 */
                    "\r\n\r\n";                 /* 4,  94 */
    u_int16_t buflen = strlen((char *)buf);
    Packet p;
    ThreadVars th_v;
    PatternMatcherThread *pmt;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.tcp_payload = buf;
    p.tcp_payload_len = buflen;
    p.proto = IPPROTO_TCP;

    g_de_ctx = DetectEngineCtxInit();
    if (g_de_ctx == NULL) {
        goto end;
    }

    g_de_ctx->flags |= DE_QUIET;

    g_de_ctx->sig_list = SigInit("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:\"GET \"; depth:4; pcre:\"/GET (?P<pkt_http_uri>.*) HTTP\\/\\d\\.\\d\\r\\n/G\"; recursive; sid:1;)");
    if (g_de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }
    g_de_ctx->sig_list->next = SigInit("alert tcp any any -> any any (msg:\"HTTP URI test\"; uricontent:\"three\"; sid:2;)");
    if (g_de_ctx->sig_list->next == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(g_de_ctx);
    PatternMatchPrepare(mpm_ctx);
    PatternMatcherThreadInit(&th_v, (void *)&pmt);

    SigMatchSignatures(&th_v, pmt, &p);
    if (PacketAlertCheck(&p, 1) && PacketAlertCheck(&p, 2))
        result = 0;
    else
        result = 1;

    SigGroupCleanup();
    SigCleanSignatures();

    PatternMatcherThreadDeinit(&th_v, (void *)pmt);
    PatternMatchDestroy(mpm_ctx);
    DetectEngineCtxFree(g_de_ctx);
end:
    return result;
}

int SigTest08 (void) {
    u_int8_t *buf = (u_int8_t *)
                    "GET /one/ HTTP/1.0\r\n"    /* 20 */
                    "Host: one.example.org\r\n" /* 23, 43 */
                    "\r\n\r\n"                  /* 4,  47 */
                    "GET /two/ HTTP/1.0\r\n"    /* 20, 67 */
                    "Host: two.example.org\r\n" /* 23, 90 */
                    "\r\n\r\n";                 /* 4,  94 */
    u_int16_t buflen = strlen((char *)buf);
    Packet p;
    ThreadVars th_v;
    PatternMatcherThread *pmt;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.tcp_payload = buf;
    p.tcp_payload_len = buflen;
    p.proto = IPPROTO_TCP;

    g_de_ctx = DetectEngineCtxInit();
    if (g_de_ctx == NULL) {
        goto end;
    }

    g_de_ctx->flags |= DE_QUIET;

    g_de_ctx->sig_list = SigInit("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:\"GET \"; depth:4; pcre:\"/GET (?P<pkt_http_uri>.*) HTTP\\/1\\.0\\r\\n/G\"; sid:1;)");
    if (g_de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }
    g_de_ctx->sig_list->next = SigInit("alert tcp any any -> any any (msg:\"HTTP URI test\"; uricontent:\"one\"; sid:2;)");
    if (g_de_ctx->sig_list->next == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(g_de_ctx);
    PatternMatchPrepare(mpm_ctx);
    PatternMatcherThreadInit(&th_v, (void *)&pmt);

    SigMatchSignatures(&th_v, pmt, &p);
    if (PacketAlertCheck(&p, 1) && PacketAlertCheck(&p, 2))
        result = 1;

    SigGroupCleanup();
    SigCleanSignatures();

    PatternMatcherThreadDeinit(&th_v, (void *)pmt);
    PatternMatchDestroy(mpm_ctx);
    DetectEngineCtxFree(g_de_ctx);
end:
    return result;
}

int SigTest09 (void) {
    u_int8_t *buf = (u_int8_t *)
                    "GET /one/ HTTP/1.0\r\n"    /* 20 */
                    "Host: one.example.org\r\n" /* 23, 43 */
                    "\r\n\r\n"                  /* 4,  47 */
                    "GET /two/ HTTP/1.0\r\n"    /* 20, 67 */
                    "Host: two.example.org\r\n" /* 23, 90 */
                    "\r\n\r\n";                 /* 4,  94 */
    u_int16_t buflen = strlen((char *)buf);
    Packet p;
    ThreadVars th_v;
    PatternMatcherThread *pmt;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.tcp_payload = buf;
    p.tcp_payload_len = buflen;
    p.proto = IPPROTO_TCP;

    g_de_ctx = DetectEngineCtxInit();
    if (g_de_ctx == NULL) {
        goto end;
    }

    g_de_ctx->flags |= DE_QUIET;

    g_de_ctx->sig_list = SigInit("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:\"GET \"; depth:4; pcre:\"/GET (?P<pkt_http_uri>.*) HTTP\\/1\\.0\\r\\n/G\"; sid:1;)");
    if (g_de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }
    g_de_ctx->sig_list->next = SigInit("alert tcp any any -> any any (msg:\"HTTP URI test\"; uricontent:\"two\"; sid:2;)");
    if (g_de_ctx->sig_list->next == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(g_de_ctx);
    PatternMatchPrepare(mpm_ctx);
    PatternMatcherThreadInit(&th_v, (void *)&pmt);

    SigMatchSignatures(&th_v, pmt, &p);
    if (PacketAlertCheck(&p, 1) && PacketAlertCheck(&p, 2))
        result = 0;
    else
        result = 1;

    SigGroupCleanup();
    SigCleanSignatures();
    PatternMatcherThreadDeinit(&th_v, (void *)pmt);
    PatternMatchDestroy(mpm_ctx);
    DetectEngineCtxFree(g_de_ctx);
end:
    return result;
}

void SigRegisterTests(void) {
    SigParseRegisterTests();
    UtRegisterTest("SigTest01 -- HTTP URI cap", SigTest01, 1);
    UtRegisterTest("SigTest02 -- Offset/Depth match", SigTest02, 1);
    UtRegisterTest("SigTest03 -- offset/depth mismatch", SigTest03, 1);
    UtRegisterTest("SigTest04 -- distance/within match", SigTest04, 1);
    UtRegisterTest("SigTest05 -- distance/within mismatch", SigTest05, 1);
    UtRegisterTest("SigTest06 -- uricontent HTTP/1.1 match test", SigTest06, 1);
    UtRegisterTest("SigTest07 -- uricontent HTTP/1.1 mismatch test", SigTest07, 1);
    UtRegisterTest("SigTest08 -- uricontent HTTP/1.0 match test", SigTest08, 1);
    UtRegisterTest("SigTest09 -- uricontent HTTP/1.0 mismatch test", SigTest09, 1);
}

