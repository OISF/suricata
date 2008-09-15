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
#include "detect-noalert.h"

#include "action-globals.h"
#include "tm-modules.h"

#include "util-unittest.h"

static DetectEngineCtx *g_de_ctx = NULL;
static u_int32_t mpm_memory_size = 0;

SigMatch *SigMatchAlloc(void);
void SigMatchFree(SigMatch *sm);

/* tm module api functions */
int Detect(ThreadVars *, Packet *, void *);
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
    sig = SigInit("alert tcp any any -> any $HTTP_PORTS (msg:\"HTTP URI cap\"; flow:to_server; content:\"GET \"; depth:4; pcre:\"/^GET (?P<http_uri>.*) HTTP\\/\\d\\.\\d\\r\\n/G\"; depth:400; noalert; sid:1;)");
    if (sig) {
        prevsig = sig;
        g_de_ctx->sig_list = sig;
    }

    /* http_host -- for the log-httplog module */
    sig = SigInit("alert tcp any any -> any $HTTP_PORTS (msg:\"HTTP host cap\"; flow:to_server; content:\"Host:\"; depth:400; pcre:\"/^Host: (?P<http_host>.*)\\r\\n/m\"; noalert; sid:2;)");
    if (sig == NULL)
        return;
    prevsig->next = sig;
    prevsig = sig;

    /* http_ua -- for the log-httplog module */
    sig = SigInit("alert tcp any any -> any $HTTP_PORTS (msg:\"HTTP UA cap\"; flow:to_server; content:\"User-Agent:\"; depth:400; pcre:\"/^User-Agent: (?P<http_ua>.*)\\r\\n/m\"; noalert; sid:3;)");
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

//#if 0
    int good = 0, bad = 0;
    FILE *fp = fopen("/etc/vips/rules/bleeding-all.rules", "r");
    //FILE *fp = fopen("/home/victor/rules/vips-http.sigs", "r");
    //FILE *fp = fopen("/home/victor/rules/emerging-dshield.rules", "r");
    //FILE *fp = fopen("/home/victor/rules/emerging-web.rules", "r");
    //FILE *fp = fopen("/home/victor/rules/emerging-web-small.rules", "r");
    //FILE *fp = fopen("/home/victor/rules/web-misc.rules", "r");
    //FILE *fp = fopen("/home/victor/rules/vips-all.sigs", "r");
    //FILE *fp = fopen("/home/victor/rules/all.rules", "r");
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

//#endif

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

                DetectPort *port = DetectPortLookupGroup(ag->port,p->dp);
                if (port != NULL) {
                    pmt->mc = port->sh->mpm_ctx;
                    pmt->mcu = port->sh->mpm_uri_ctx;
                    sgh = port->sh;
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

        /* XXX maybe a (re)set function? */
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
                        //printf("Signature %u matched: %s\n", s->id, s->msg ? s->msg : "");
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
int Detect(ThreadVars *t, Packet *p, void *data) {
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
        return 1;

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
            }

            SigGroupHeadFree(gr->sh);
            gr->sh = NULL;
        }
    }

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

    int i;
    for (i = 0; i < 256; i++) {
        de_ctx->src_gh[i] = DetectAddressGroupsHeadInit();
        if (de_ctx->src_gh[i] == NULL) {
            goto error;
        }
        de_ctx->tmp_gh[i] = DetectAddressGroupsHeadInit();
        if (de_ctx->tmp_gh[i] == NULL) {
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

    /* now for every rule add the source group to our temp list */
    for (tmp_s = de_ctx->sig_list; tmp_s != NULL; tmp_s = tmp_s->next) {
        BuildSourceAddressList(de_ctx,tmp_s,AF_INET);
        BuildSourceAddressList(de_ctx,tmp_s,AF_INET6);
        BuildSourceAddressList(de_ctx,tmp_s,AF_UNSPEC);
        sigs++;
    }

    //DetectAddressGroupPrintMemory();
    //DetectSigGroupPrintMemory();

    //printf("g_tmp_gh strt\n");
    //DetectAddressGroupPrintList(de_ctx->tmp_gh[6]->ipv4_head);
    //printf("g_tmp_gh end\n");

    for (i = 0; i < 256; i++) {
        for (gr = de_ctx->tmp_gh[i]->ipv4_head; gr != NULL; ) {
            //printf("Inserting2'ing (proto %3d): ",i); DetectAddressDataPrint(gr->ad); printf("\n");
            DetectAddressGroup *grnext = gr->next;

            gr->next = NULL;
            if (DetectAddressGroupInsert(de_ctx->src_gh[i],gr) < 0)
                goto error;

            gr = grnext;
        }
        for (gr = de_ctx->tmp_gh[i]->ipv6_head; gr != NULL; ) {
            //printf("Inserting2'ing (proto %3d): ",i); DetectAddressDataPrint(gr->ad); printf("\n");
            DetectAddressGroup *grnext = gr->next;

            gr->next = NULL;
            if (DetectAddressGroupInsert(de_ctx->src_gh[i],gr) < 0)
                goto error;

            gr = grnext;
        }
        for (gr = de_ctx->tmp_gh[i]->any_head; gr != NULL; ) {
            //printf("Inserting2'ing (proto %3d): ",i); DetectAddressDataPrint(gr->ad); printf("\n");
            DetectAddressGroup *grnext = gr->next;

            gr->next = NULL;
            if (DetectAddressGroupInsert(de_ctx->src_gh[i],gr) < 0)
                goto error;

            gr = grnext;
        }

        //DetectAddressGroupsHeadFree(de_ctx->tmp_gh[i]);
        free(de_ctx->tmp_gh[i]);

       //printf("g_src_gh[%d] strt\n", i);
       //if (i == 6)DetectAddressGroupPrintList(de_ctx->src_gh[i]->ipv4_head);
       //DetectAddressGroupPrintList(de_ctx->src_gh[i]->ipv6_head);
       //DetectAddressGroupPrintList(de_ctx->src_gh[i]->any_head);
       //printf("g_src_gh[%d] end\n", i);
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
    if (family == AF_INET) {
        grhead = head->ipv4_head;
    } else if (family == AF_INET6) {
        grhead = head->ipv6_head;
    } else {
        grhead = head->any_head;
    }

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

            if (family == AF_INET) {
                grsighead = tmp_s->dst.ipv4_head;
            } else if (family == AF_INET6) {
                grsighead = tmp_s->dst.ipv6_head;
            } else {
                grsighead = tmp_s->dst.any_head;
            }

            /* build the temp list */
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
                } else {
                    /* our group will only have one sig, this one. So add that. */
                    SigGroupHeadAppendSig(&lookup_gr->sh,tmp_s);
                }
            }

        }

        /* for each address in the tmp list, insert a copy */
        for (sgr = tmp_gr_list; sgr != NULL; sgr = sgr->next) {
            DetectAddressGroup *grtmp = DetectAddressGroupInit();
            if (grtmp == NULL) {
                goto error;
            }
            DetectAddressData *adtmp = DetectAddressDataCopy(sgr->ad);
            if (adtmp == NULL) {
                goto error;
            }
            grtmp->ad = adtmp;

            SigGroupHeadCopySigs(sgr->sh,&grtmp->sh);

            int r = DetectAddressGroupInsert(gr->dst_gh,grtmp);
            if (r < 0) {
                printf("DetectAddressGroupInsert failed\n");
                goto error;
            }
        }

        /* set the right dst ptr to work with */
        if (family == AF_INET) {
            grdsthead = gr->dst_gh->ipv4_head;
        } else if (family == AF_INET6) {
            grdsthead = gr->dst_gh->ipv6_head;
        } else {
            grdsthead = gr->dst_gh->any_head;
        }

        /* see if the sig group head of each address group is the
         * same as an earlier one. If it is, free our head and use
         * a pointer to the earlier one. This saves _a lot_ of memory.
         */
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

static int BuildDestinationAddressHeadsWithPorts(DetectEngineCtx *de_ctx, DetectAddressGroupsHead *head, int family) {
    Signature *tmp_s = NULL;
    DetectAddressGroup *gr = NULL, *sgr = NULL, *lookup_gr = NULL;
    DetectAddressGroup *grhead = NULL, *grdsthead = NULL, *grsighead = NULL;
    u_int32_t max_idx = 0;

    //printf("BuildDestinationAddressHeadsWithPorts: start\n");

    /* based on the family, select the list we are using in the head */
    if (family == AF_INET) {
        grhead = head->ipv4_head;
    } else if (family == AF_INET6) {
        grhead = head->ipv6_head;
    } else {
        grhead = head->any_head;
    }

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

            if (family == AF_INET) {
                grsighead = tmp_s->dst.ipv4_head;
            } else if (family == AF_INET6) {
                grsighead = tmp_s->dst.ipv6_head;
            } else {
                grsighead = tmp_s->dst.any_head;
            }

            /* build the temp list */
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
                } else {
                    /* our group will only have one sig, this one. So add that. */
                    SigGroupHeadAppendSig(&lookup_gr->sh,tmp_s);
                }

                SigGroupHeadFree(sgr->sh);
                sgr->sh = NULL;
            }
        }

        /* for each address in the tmp list, insert a copy */
        for (sgr = tmp_gr_list; sgr != NULL; sgr = sgr->next) {
            DetectAddressGroup *grtmp = DetectAddressGroupInit();
            if (grtmp == NULL) {
                goto error;
            }
            DetectAddressData *adtmp = DetectAddressDataCopy(sgr->ad);
            if (adtmp == NULL) {
                goto error;
            }
            grtmp->ad = adtmp;

            /* copy the sigs */
            SigGroupHeadCopySigs(sgr->sh,&grtmp->sh);

            DetectPort *port = sgr->port;
            for ( ; port != NULL; port = port->next) {
                DetectPortInsertCopy(&grtmp->port, port);
            }

            int r = DetectAddressGroupInsert(gr->dst_gh,grtmp);
            if (r < 0) {
                printf("DetectAddressGroupInsert failed\n");
                goto error;
            }
        }

        /* set the right dst ptr to work with */
        if (family == AF_INET) {
            grdsthead = gr->dst_gh->ipv4_head;
        } else if (family == AF_INET6) {
            grdsthead = gr->dst_gh->ipv6_head;
        } else {
            grdsthead = gr->dst_gh->any_head;
        }

        /* add the ports to the dst address groups and the sigs
         * to the ports */
        for (sgr = grdsthead; sgr != NULL; sgr = sgr->next) {
            if (sgr->sh == NULL)
                continue;

            /* we will reuse address sig group heads at this points,
             * because if the sigs are the same, the ports will be
             * the same. Saves memory and a lot of init time. */
            SigGroupHead *lookup_sgh = SigGroupHeadHashLookup(sgr->sh);
            if (lookup_sgh == NULL) {
                DetectPortHashReset();
                u_int32_t sig2;
                for (sig2 = 0; sig2 < max_idx+1; sig2++) {
                    if (!(sgr->sh->sig_array[(sig2/8)] & (1<<(sig2%8))))
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
                        } else {
                            SigGroupHeadAppendSig(&lookup_port->sh,s);
                        }
                    }
                }

                DetectPort *p = DetectPortHashGetListPtr();
                for (; p != NULL; ) {
                    DetectPort *next_p = p->next;
                    p->next = NULL; p->prev = NULL;
                    DetectPortInsert(&sgr->port,p);
                    p = next_p;
                }

                SigGroupHeadHashAdd(sgr->sh);

                sgr->sh->port = sgr->port;
                /* mark this head for deletion once we no longer need
                 * the hash. We're only using the port ptr, so no problem
                 * when we remove this after initialization is done */
                sgr->sh->flags |= SIG_GROUP_HEAD_FREE;

                /* for each destination port we setup the siggrouphead here */
                DetectPort *dp = sgr->port;
                for ( ; dp != NULL; dp = dp->next) {
                    //printf("   * Port(range): "); DetectPortPrint(dp); printf(" ");
                    //printf("\n");

                    if (dp->sh == NULL)
                        continue;

                    /* Because a pattern matcher context uses quite some
                     * memory, we first check if we can reuse it from
                     * another group head. */
                    SigGroupHead *sgh = SigGroupHeadPortHashLookup(dp->sh);
                    if (sgh == NULL) {
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
                        dp->sh = sgh;

                        de_ctx->gh_reuse++;
                        dp->flags |= PORT_SIGGROUPHEAD_COPY;
                    }
                }
            /* sig group head found in hash, free it and use the hashed one */
            } else {
                SigGroupHeadFree(sgr->sh);
                sgr->sh = lookup_sgh;
                sgr->flags |= ADDRESS_GROUP_SIGGROUPHEAD_COPY;

                sgr->port = lookup_sgh->port;
                sgr->flags |= ADDRESS_GROUP_PORTS_COPY;

                de_ctx->gh_reuse++;
            }
        }

        /* free the temp list */
        DetectAddressGroupCleanupList(tmp_gr_list);
        /* clear now unneeded sig group head */
        SigGroupHeadFree(gr->sh);
        gr->sh = NULL;
    }

    //printf("BuildDestinationAddressHeadsWithPorts: end\n");
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
    SigGroupHeadMpmHashInit();
    SigGroupHeadMpmUriHashInit();
    DetectPortHashInit();

//#if 0
    /* XXX ipv6 & any */
    r = BuildDestinationAddressHeadsWithPorts(de_ctx, de_ctx->src_gh[6],AF_INET);
    if (r < 0) {
        printf ("BuildDestinationAddressHeads(src_gh[6],AF_INET) failed\n");
        goto error;
    }
//#if 0
    r = BuildDestinationAddressHeadsWithPorts(de_ctx, de_ctx->src_gh[17],AF_INET);
    if (r < 0) {
        printf ("BuildDestinationAddressHeads(src_gh[17],AF_INET) failed\n");
        goto error;
    }
    r = BuildDestinationAddressHeadsWithPorts(de_ctx, de_ctx->src_gh[6],AF_INET6);
    if (r < 0) {
        printf ("BuildDestinationAddressHeads(src_gh[6],AF_INET) failed\n");
        goto error;
    }
//#if 0
    r = BuildDestinationAddressHeadsWithPorts(de_ctx, de_ctx->src_gh[17],AF_INET6);
    if (r < 0) {
        printf ("BuildDestinationAddressHeads(src_gh[17],AF_INET) failed\n");
        goto error;
    }
    r = BuildDestinationAddressHeadsWithPorts(de_ctx, de_ctx->src_gh[6],AF_UNSPEC);
    if (r < 0) {
        printf ("BuildDestinationAddressHeads(src_gh[6],AF_INET) failed\n");
        goto error;
    }
//#if 0
    r = BuildDestinationAddressHeadsWithPorts(de_ctx, de_ctx->src_gh[17],AF_UNSPEC);
    if (r < 0) {
        printf ("BuildDestinationAddressHeads(src_gh[17],AF_INET) failed\n");
        goto error;
    }
//#endif
    for (i = 0; i < 256; i++) {
        if (i == 6 || i == 17)
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
        //printf("Protocol %d, gh: u %u r %u mpm: u %u r %u\n",i, de_ctx->gh_unique, de_ctx->gh_reuse, de_ctx->mpm_unique, de_ctx->mpm_reuse);
    }

    /* IP ONLY */
    r = BuildDestinationAddressHeads(de_ctx, de_ctx->io_src_gh,AF_INET);
    if (r < 0) {
        printf ("BuildDestinationAddressHeads(src_gh[%d],AF_INET) failed\n", i);
        goto error;
    }
    r = BuildDestinationAddressHeads(de_ctx, de_ctx->io_src_gh,AF_INET6);
    if (r < 0) {
        printf ("BuildDestinationAddressHeads(src_gh[%d],AF_INET6) failed\n", i);
        goto error;
    }
    r = BuildDestinationAddressHeads(de_ctx, de_ctx->io_src_gh,AF_UNSPEC); /* for any */
    if (r < 0) {
        printf ("BuildDestinationAddressHeads(src_gh[%d],AF_UNSPEC) failed\n", i);
        goto error;
    }

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
    SigGroupHeadMpmHashFree();
    SigGroupHeadMpmUriHashFree();

    DetectPortHashFree();

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
        //DetectAddressGroupsHeadCleanup(de_ctx->src_gh[i]);
        DetectAddressGroupsHeadFree(de_ctx->src_gh[i]);
    }
    //DetectAddressGroupsHeadCleanup(de_ctx->io_src_gh);
    DetectAddressGroupsHeadFree(de_ctx->io_src_gh);

    if (!(de_ctx->flags & DE_QUIET)) {
        printf("* Cleaning up signature grouping structure, stage 1... done\n");
    }
    return 0;
}

/* shortcut for debugging. If enabled Stage5 will
 * print sigid's for all groups */
//#define PRINTSIGS

/* just printing */
int SigAddressPrepareStage5(void) {
    DetectAddressGroupsHead *global_dst_gh = NULL;
    DetectAddressGroup *global_src_gr = NULL, *global_dst_gr = NULL;

    printf("* Building signature grouping structure, stage 5: print...\n");

    int i;
    for (i = 0; i < 256; i++) {
        for (global_src_gr = g_de_ctx->src_gh[i]->ipv4_head; global_src_gr != NULL;
                global_src_gr = global_src_gr->next)
        {
            printf("- "); DetectAddressDataPrint(global_src_gr->ad); printf(" (sh %p)\n", global_src_gr->sh);

            global_dst_gh = global_src_gr->dst_gh;
            if (global_dst_gh == NULL)
                continue;

            for (global_dst_gr = global_dst_gh->ipv4_head;
                    global_dst_gr != NULL;
                    global_dst_gr = global_dst_gr->next)
            {
                printf(" - [%4u] ", global_dst_gr->sh ? global_dst_gr->sh->sig_cnt : 0); DetectAddressDataPrint(global_dst_gr->ad); printf(" (sh %p)\n", global_dst_gr->sh);
                if (global_dst_gr->sh) {
                        if (global_dst_gr->sh->flags & ADDRESS_GROUP_SIGGROUPHEAD_COPY) {
                            printf("(COPY)\n");
                        } else {
                            printf("\n");
                        }
                }
#ifdef PRINTSIGS
                if (global_dst_gr->sh && global_dst_gr->sh->head) {
                    printf ("  - ");
                    SigGroupContainer *sg; 
                    for (sg = global_dst_gr->sh->head; sg != NULL; sg = sg->next) {
                        printf("%u", sg->s->id);
                        if (sg->next) printf(",");
                        else printf("\n");
                    }
                }
#endif
            }
            for (global_dst_gr = global_dst_gh->any_head;
                    global_dst_gr != NULL;
                    global_dst_gr = global_dst_gr->next)
            {
                printf(" - [%4u] ", global_dst_gr->sh ? global_dst_gr->sh->sig_cnt : 0); DetectAddressDataPrint(global_dst_gr->ad); printf(" (sh %p)\n", global_dst_gr->sh);
                if (global_dst_gr->sh) {
                        if (global_dst_gr->sh->flags & ADDRESS_GROUP_SIGGROUPHEAD_COPY) {
                            printf("(COPY)\n");
                        } else {
                            printf("\n");
                        }
                }
#ifdef PRINTSIGS
                if (global_dst_gr->sh && global_dst_gr->sh->head) {
                    printf ("  - ");
                    SigGroupContainer *sg; 
                    for (sg = global_dst_gr->sh->head; sg != NULL; sg = sg->next) {
                        printf("%u", sg->s->id);
                        if (sg->next) printf(",");
                        else printf("\n");
                    }
                }
#endif
            }
        }

        for (global_src_gr = g_de_ctx->src_gh[i]->ipv6_head; global_src_gr != NULL;
                global_src_gr = global_src_gr->next)
        {
            printf("- "); DetectAddressDataPrint(global_src_gr->ad); printf(" (sh %p)\n", global_src_gr->sh);

            global_dst_gh = global_src_gr->dst_gh;
            if (global_dst_gh == NULL)
                continue;

            for (global_dst_gr = global_dst_gh->ipv6_head;
                    global_dst_gr != NULL;
                    global_dst_gr = global_dst_gr->next)
            {
                printf(" - [%4u] ", global_dst_gr->sh ? global_dst_gr->sh->sig_cnt : 0); DetectAddressDataPrint(global_dst_gr->ad); printf(" (sh %p)\n", global_dst_gr->sh);
                if (global_dst_gr->sh) {
                        if (global_dst_gr->sh->flags & ADDRESS_GROUP_SIGGROUPHEAD_COPY) {
                            printf("(COPY)\n");
                        } else {
                            printf("\n");
                        }
                }
#ifdef PRINTSIGS
                if (global_dst_gr->sh && global_dst_gr->sh->head) {
                    printf ("  - ");
                    SigGroupContainer *sg; 
                    for (sg = global_dst_gr->sh->head; sg != NULL; sg = sg->next) {
                        printf("%u", sg->s->id);
                        if (sg->next) printf(",");
                        else printf("\n");
                    }
                }
#endif
            }
            for (global_dst_gr = global_dst_gh->any_head;
                    global_dst_gr != NULL;
                    global_dst_gr = global_dst_gr->next)
            {
                printf(" - [%4u] ", global_dst_gr->sh ? global_dst_gr->sh->sig_cnt : 0); DetectAddressDataPrint(global_dst_gr->ad); printf(" (sh %p)\n", global_dst_gr->sh);
                if (global_dst_gr->sh) {
                        if (global_dst_gr->sh->flags & ADDRESS_GROUP_SIGGROUPHEAD_COPY) {
                            printf("(COPY)\n");
                        } else {
                            printf("\n");
                        }
                }
#ifdef PRINTSIGS
                if (global_dst_gr->sh && global_dst_gr->sh->head) {
                    printf ("  - ");
                    SigGroupContainer *sg; 
                    for (sg = global_dst_gr->sh->head; sg != NULL; sg = sg->next) {
                        printf("%u", sg->s->id);
                        if (sg->next) printf(",");
                        else printf("\n");
                    }
                }
#endif
            }
        }

        for (global_src_gr = g_de_ctx->src_gh[i]->any_head; global_src_gr != NULL;
                global_src_gr = global_src_gr->next)
        {
            printf("- "); DetectAddressDataPrint(global_src_gr->ad); printf(" (sh %p)\n", global_src_gr->sh);

            global_dst_gh = global_src_gr->dst_gh;
            if (global_dst_gh == NULL)
                continue;

            for (global_dst_gr = global_dst_gh->any_head;
                    global_dst_gr != NULL;
                    global_dst_gr = global_dst_gr->next)
            {
                printf(" - [%4u] ", global_dst_gr->sh ? global_dst_gr->sh->sig_cnt : 0); DetectAddressDataPrint(global_dst_gr->ad); printf(" (sh %p)\n", global_dst_gr->sh);
                if (global_dst_gr->sh) {
                        if (global_dst_gr->sh->flags & ADDRESS_GROUP_SIGGROUPHEAD_COPY) {
                            printf("(COPY)\n");
                        } else {
                            printf("\n");
                        }
                }
#ifdef PRINTSIGS
                if (global_dst_gr->sh && global_dst_gr->sh->head) {
                    printf ("  - ");
                    SigGroupContainer *sg; 
                    for (sg = global_dst_gr->sh->head; sg != NULL; sg = sg->next) {
                        printf("%u", sg->s->id);
                        if (sg->next) printf(",");
                        else printf("\n");
                    }
                }
#endif
            } 
            for (global_dst_gr = global_dst_gh->ipv4_head;
                    global_dst_gr != NULL;
                    global_dst_gr = global_dst_gr->next)
            {
                printf(" - [%4u] ", global_dst_gr->sh ? global_dst_gr->sh->sig_cnt : 0); DetectAddressDataPrint(global_dst_gr->ad); printf(" (sh %p)\n", global_dst_gr->sh);
                if (global_dst_gr->sh) {
                        if (global_dst_gr->sh->flags & ADDRESS_GROUP_SIGGROUPHEAD_COPY) {
                            printf("(COPY)\n");
                        } else {
                            printf("\n");
                        }
                }
#ifdef PRINTSIGS
                if (global_dst_gr->sh && global_dst_gr->sh->head) {
                    printf ("  - ");
                    SigGroupContainer *sg; 
                    for (sg = global_dst_gr->sh->head; sg != NULL; sg = sg->next) {
                        printf("%u", sg->s->id);
                        if (sg->next) printf(",");
                        else printf("\n");
                    }
                }
#endif
            }
            for (global_dst_gr = global_dst_gh->ipv6_head;
                    global_dst_gr != NULL;
                    global_dst_gr = global_dst_gr->next)
            {
                printf(" - [%4u] ", global_dst_gr->sh->sig_cnt); DetectAddressDataPrint(global_dst_gr->ad); printf(" (sh %p)\n", global_dst_gr->sh);
                if (global_dst_gr->sh) {
                        if (global_dst_gr->sh->flags & ADDRESS_GROUP_SIGGROUPHEAD_COPY) {
                            printf("(COPY)\n");
                        } else {
                            printf("\n");
                        }
                }
#ifdef PRINTSIGS
                if (global_dst_gr->sh && global_dst_gr->sh->head) {
                    printf ("  - ");
                    SigGroupContainer *sg; 
                    for (sg = global_dst_gr->sh->head; sg != NULL; sg = sg->next) {
                        printf("%u", sg->s->id);
                        if (sg->next) printf(",");
                        else printf("\n");
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
    //SigAddressPrepareStage5();
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

    g_de_ctx->sig_list = SigInit("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:\"GET \"; depth:4; pcre:\"/GET (?P<http_uri>.*) HTTP\\/\\d\\.\\d\\r\\n/G\"; recursive; sid:1;)");
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

    g_de_ctx->sig_list = SigInit("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:\"GET \"; depth:4; pcre:\"/GET (?P<http_uri>.*) HTTP\\/\\d\\.\\d\\r\\n/G\"; recursive; sid:1;)");
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

    g_de_ctx->sig_list = SigInit("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:\"GET \"; depth:4; pcre:\"/GET (?P<http_uri>.*) HTTP\\/\\d\\.\\d\\r\\n/G\"; recursive; sid:1;)");
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

    g_de_ctx->sig_list = SigInit("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:\"GET \"; depth:4; pcre:\"/GET (?P<http_uri>.*) HTTP\\/1\\.0\\r\\n/G\"; sid:1;)");
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

    g_de_ctx->sig_list = SigInit("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:\"GET \"; depth:4; pcre:\"/GET (?P<http_uri>.*) HTTP\\/1\\.0\\r\\n/G\"; sid:1;)");
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

