/* Basic detection engine datastructure */

#include <pcre.h>

#include "vips.h"
#include "debug.h"
#include "detect.h"
#include "flow.h"

#include "detect-parse.h"

#include "detect-address.h"
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
#include "detect-classtype.h"
#include "detect-reference.h"
#include "detect-threshold.h"
#include "detect-metadata.h"
#include "detect-msg.h"
#include "detect-rev.h"
#include "detect-flow.h"
#include "detect-dsize.h"
#include "detect-flowvar.h"

#include "action-globals.h"
#include "detect-mpm.h"
#include "tm-modules.h"

#include "util-unittest.h"

static Signature *sig_list;

SigMatch *SigMatchAlloc(void);
void SigMatchFree(SigMatch *sm);

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
    SigParsePrepare();

    sig = SigInit("alert tcp 192.168.0.0 any -> 0.0.0.0 any (msg:\"HTTP URI cap\"; flow:to_server; content:\"GET \"; depth:4; pcre:\"/^GET (?P<http_uri>.*) HTTP\\/\\d\\.\\d\\r\\n/G\"; depth:400; sid:1;)");
    if (sig) {
        prevsig = sig;
        sig_list = sig;
    }
    sig = SigInit("alert ip 192.168.0.0 any -> 80.126.224.247 any (msg:\"ViCtOr nocase test\"; sid:2000; rev:13; content:ViCtOr; nocase; depth:150;)");
    if (sig == NULL)
        return;
    prevsig->next = sig;
    prevsig = sig;
/*

    sig = SigInit("alert ip 192.168.0.0 any -> 80.126.224.247 any (msg:\"ViCtOr case test\"; sid:2001; content:ViCtOr; depth:150;)");
    if (sig == NULL)
        return;
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit("alert ip 192.168.0.0 any -> 80.126.224.247 any (msg:\"offset, depth, within test\"; flow:to_client; sid:2002; content:HTTP; depth:4; content:Server:; offset:15; within:100; depth:200;)");
    if (sig == NULL)
        return;
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit("alert ip 192.168.0.0 any -> 80.126.224.247 any (msg:\"Inliniac blog within test\"; flow:to_client; sid:2003; content:inliniac; content:blog; within:9;)");
    if (sig == NULL)
        return;
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit("alert ip 192.168.0.0 any -> 80.126.224.247 any (msg:\"abcdefg distance 1 test\"; flow:to_server; sid:2004; content:abcd; content:efgh; within:4; distance:0; content:ijkl; within:4; distance:0;)");
    if (sig == NULL)
        return;
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit("alert ip 192.168.0.0 any -> 80.126.224.247 any (msg:\"abcdef distance 0 test\"; flow:to_server; sid:2005; content:abcdef; content:ghijklmnop; distance:0;)");
    if (sig == NULL)
        return;
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit("alert ip 192.168.0.0 any -> 80.126.224.247 any (msg:\"abcdefg distance 1 test\"; flow:to_server; sid:2006; content:abcdef; content:ghijklmnop; distance:1;)");
    if (sig == NULL)
        return;
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit("alert tcp 192.168.0.0 any -> 0.0.0.0 any (msg:\"HTTP response code cap\"; flow:to_client; content:HTTP; depth:4; pcre:\"/^HTTP\\/\\d\\.\\d (?<http_response>[0-9]+) [A-z\\s]+\\r\\n/\"; depth:50; sid:3;)");
    if (sig == NULL)
        return;
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit("alert tcp 192.168.0.0 any -> 0.0.0.0 any (msg:\"HTTP server code cap\"; flow:to_client; content:Server:; depth:500; pcre:\"/^Server: (?<http_server>.*)\\r\\n/m\"; sid:4;)");
    if (sig == NULL)
        return;
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit("alert tcp 192.168.0.0 any -> 0.0.0.0 any (msg:\"\to_client nocase test\"; flow:to_client; content:Servere:; nocase; sid:400;)");
    if (sig == NULL)
        return;
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit("alert tcp 192.168.0.0 any -> 0.0.0.0 any (msg:\"HTTP UA code cap\"; flow:to_server; content:User-Agent:; depth:300; pcre:\"/^User-Agent: (?<http_ua>.*)\\r\\n/m\"; sid:5;)");
    if (sig == NULL)
        return;
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit("alert tcp 192.168.0.0 any -> 0.0.0.0 any (msg:\"HTTP host code cap\"; flow:to_server; content:Host:; depth:300; pcre:\"/^Host: (?<http_host>.*)\\r\\n/m\"; sid:6;)");
    if (sig == NULL)
        return;
    prevsig->next = sig;
    prevsig = sig;
*/
/*
    sig = SigInit("alert tcp 192.168.0.0 any -> 0.0.0.0 any (msg:\"HTTP http_host flowvar www.inliniac.net\"; flow:to_server; flowvar:http_host,\"www.inliniac.net\"; sid:7;)");
    if (sig) {
        prevsig->next = sig;
        prevsig = sig;
    }
*/
    sig = SigInit("alert tcp 192.168.0.0 any -> 0.0.0.0 any (msg:\"HTTP http_uri flowvar MattJonkman\"; flow:to_server; flowvar:http_uri,\"MattJonkman\"; sid:8;)");
    if (sig) {
        prevsig->next = sig;
        prevsig = sig;
    }

    sig = SigInit("alert tcp 192.168.0.0 any -> 0.0.0.0 any (msg:\"HTTP uricontent VictorJulien\"; flow:to_server; uricontent:\"VJ\"; sid:9;)");
    if (sig) {
        prevsig->next = sig;
        prevsig = sig;
    }
//#if 0
    int good = 0, bad = 0;
    FILE *fp = fopen("/etc/vips/rules/bleeding-all.rules", "r");
    //FILE *fp = fopen("/home/victor/rules/vips-http.sigs", "r");
    //FILE *fp = fopen("/home/victor/rules/vips-all.sigs", "r");
    //FILE *fp = fopen("/home/victor/rules/eml.rules", "r");
    //FILE *fp = fopen("/home/victor/rules/vips-vrt-all.sigs", "r");
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
    /* Setup the pattern matcher */

    PatternMatchPrepare(sig_list);

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

int PacketAlertAppend(Packet *p, u_int8_t gid, u_int32_t sid, u_int8_t rev, char *msg)
{
    /* XXX overflow check? */

    p->alerts.alerts[p->alerts.cnt].gid = gid;
    p->alerts.alerts[p->alerts.cnt].sid = sid;
    p->alerts.alerts[p->alerts.cnt].rev = rev;
    p->alerts.alerts[p->alerts.cnt].msg = msg;
    p->alerts.cnt++;

    return 0;
}

int SigMatchSignatures(ThreadVars *th_v, PatternMatcherThread *pmt, Packet *p)
{
    int match = 0, fmatch = 0;
    Signature *s = NULL;
    SigMatch *sm = NULL;

    /* we assume we don't have an uri when we start inspection */
    pmt->de_have_httpuri = 0;
    pmt->de_scanned_httpuri = 0;

    /* select the pattern matcher instance for this packet */
    if (p->flowflags & FLOW_PKT_TOSERVER)
        pmt->mpm_instance = MPM_INSTANCE_TOSERVER;
    else if (p->flowflags & FLOW_PKT_TOCLIENT)
        pmt->mpm_instance = MPM_INSTANCE_TOCLIENT;
    else 
        pmt->mpm_instance = 0;

    /* run the pattern matcher against the packet */
    //u_int32_t cnt = 
    PacketPatternMatch(th_v, pmt, p);
    //printf("cnt %u\n", cnt);

//#if 0
    /* inspect all sigs against the packet
     * XXX change this so we only inspect the relevant sigs */
    for (s = sig_list; s != NULL; s = s->next) {
        /* XXX maybe a (re)set function? */
        pmt->pkt_ptr = NULL;
        pmt->pkt_off = 0;

        if (s->flags & SIG_FLAG_RECURSIVE) {
            u_int8_t rmatch = 0;
            pmt->pkt_cnt = 0;

            do {
                sm = s->match;
                while (sm) {
                    //printf("Detect: th_v->pkt_ptr %p, th_v->pkt_off %u\n", th_v->pkt_ptr, th_v->pkt_off);
                    match = sigmatch_table[sm->type].Match(th_v, pmt, p, s, sm);
                    if (match) {
                        /* okay, try the next match */
                        sm = sm->next;

                        /* only if the last matched as well, we have a hit */
                        if (sm == NULL) {
                            /* only add once */
                            if (rmatch == 0) {
                                PacketAlertAppend(p, 1, s->id, s->rev, s->msg);

                                /* set verdict on packet */
                                p->action = s->action;
                            }
                            //printf("%u Signature %u matched: %s\n", th_v->pkt_cnt, s->id, s->msg ? s->msg : "");
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

                        PacketAlertAppend(p, 1, s->id, s->rev, s->msg);
                        /* set verdict on packet */
                        p->action = s->action;
                    }
                } else {
                    /* done with this sig */
                    sm = NULL;
                }
            }
        }
    }

    /* cleanup pkt specific part of the patternmatcher */
//#endif
    if (pmt->de_scanned_httpuri == 1)
        PacketPatternCleanup(th_v, pmt, pmt->mpm_instance+MPM_INSTANCE_URIOFFSET);

    PacketPatternCleanup(th_v, pmt, pmt->mpm_instance);
    return fmatch;
}

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

    for (s = sig_list; s != NULL;) {
        ns = s->next;
        SigFree(s);
        s = ns;
    }
}

void SigTableSetup(void) {
    memset(sigmatch_table, 0, sizeof(sigmatch_table));

    DetectSidRegister();
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
    DetectAddressRegister();

    /* register the tests */
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
    p.tcp_payload = buf;
    p.tcp_payload_len = buflen;

    SigParsePrepare();

    sig_list = SigInit("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:\"GET \"; depth:4; pcre:\"/GET (?P<http_uri>.*) HTTP\\/\\d\\.\\d\\r\\n/G\"; recursive; sid:1;)");
    if (sig_list == NULL) {
        result = 0;
        goto end;
    }

    PatternMatchPrepare(sig_list);
    PatternMatcherThreadInit(&th_v, (void *)&pmt);
    //printf("SigTest01: pmt %p\n", pmt);
    SigMatchSignatures(&th_v, pmt, &p);

    if (PacketAlertCheck(&p, 1) == 0) {
        result = 0;
        goto end;
    }

    //printf("URI0 \"%s\", len %u\n", th_v.http_uri.raw[0], th_v.http_uri.raw_size[0]);
    //printf("URI1 \"%s\", len %u\n", th_v.http_uri.raw[1], th_v.http_uri.raw_size[1]);

    if (p.http_uri.raw_size[0] == 5 &&
        memcmp(p.http_uri.raw[0], "/one/", 5) == 0 &&
        p.http_uri.raw_size[1] == 5 &&
        memcmp(p.http_uri.raw[1], "/two/", 5) == 0)
    {
        result = 1;
    }

    PatternMatcherThreadDeinit(&th_v, (void *)pmt);
    PatternMatchDestroy();
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
    p.tcp_payload = buf;
    p.tcp_payload_len = buflen;

    SigParsePrepare();

    sig_list = SigInit("alert tcp any any -> any any (msg:\"HTTP TEST\"; content:\"Host: one.example.org\"; offset:20; depth:41; sid:1;)");
    if (sig_list == NULL) {
        result = 0;
        goto end;
    }

    PatternMatchPrepare(sig_list);
    PatternMatcherThreadInit(&th_v, (void *)&pmt);
    SigMatchSignatures(&th_v, pmt, &p);

    if (PacketAlertCheck(&p, 1))
        result = 1;

    PatternMatcherThreadDeinit(&th_v, (void *)pmt);
    PatternMatchDestroy();
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
    p.tcp_payload = buf;
    p.tcp_payload_len = buflen;

    SigParsePrepare();

    sig_list = SigInit("alert tcp any any -> any any (msg:\"HTTP TEST\"; content:\"Host: one.example.org\"; offset:20; depth:40; sid:1;)");
    if (sig_list == NULL) {
        result = 0;
        goto end;
    }

    PatternMatchPrepare(sig_list);
    PatternMatcherThreadInit(&th_v, (void *)&pmt);
    SigMatchSignatures(&th_v, pmt, &p);

    if (!PacketAlertCheck(&p, 1))
        result = 1;

    PatternMatcherThreadDeinit(&th_v, (void *)pmt);
    PatternMatchDestroy();
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
    p.tcp_payload = buf;
    p.tcp_payload_len = buflen;

    SigParsePrepare();

    sig_list = SigInit("alert tcp any any -> any any (msg:\"HTTP TEST\"; content:\"Host:\"; offset:20; depth:25; content:\"Host:\"; distance:47; within:52; sid:1;)");
    if (sig_list == NULL) {
        result = 0;
        goto end;
    }

    PatternMatchPrepare(sig_list);
    PatternMatcherThreadInit(&th_v, (void *)&pmt);
    SigMatchSignatures(&th_v, pmt, &p);

    if (PacketAlertCheck(&p, 1))
        result = 1;

    PatternMatcherThreadDeinit(&th_v, (void *)pmt);
    PatternMatchDestroy();
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
    p.tcp_payload = buf;
    p.tcp_payload_len = buflen;

    SigParsePrepare();

    sig_list = SigInit("alert tcp any any -> any any (msg:\"HTTP TEST\"; content:\"Host:\"; offset:20; depth:25; content:\"Host:\"; distance:48; within:52; sid:1;)");
    if (sig_list == NULL) {
        result = 0;
        goto end;
    }

    PatternMatchPrepare(sig_list);
    PatternMatcherThreadInit(&th_v, (void *)&pmt);
    SigMatchSignatures(&th_v, pmt, &p);

    if (!PacketAlertCheck(&p, 1))
        result = 1;

    PatternMatcherThreadDeinit(&th_v, (void *)pmt);
    PatternMatchDestroy();
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
    p.tcp_payload = buf;
    p.tcp_payload_len = buflen;

    SigParsePrepare();

    sig_list = SigInit("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:\"GET \"; depth:4; pcre:\"/GET (?P<http_uri>.*) HTTP\\/\\d\\.\\d\\r\\n/G\"; recursive; sid:1;)");
    if (sig_list == NULL) {
        result = 0;
        goto end;
    }
    sig_list->next = SigInit("alert tcp any any -> any any (msg:\"HTTP URI test\"; uricontent:\"two\"; sid:2;)");
    if (sig_list->next == NULL) {
        result = 0;
        goto end;
    }

    PatternMatchPrepare(sig_list);
    PatternMatcherThreadInit(&th_v, (void *)&pmt);
    SigMatchSignatures(&th_v, pmt, &p);

    if (PacketAlertCheck(&p, 1) && PacketAlertCheck(&p, 2))
        result = 1;

    PatternMatcherThreadDeinit(&th_v, (void *)pmt);
    PatternMatchDestroy();
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
    p.tcp_payload = buf;
    p.tcp_payload_len = buflen;

    SigParsePrepare();

    sig_list = SigInit("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:\"GET \"; depth:4; pcre:\"/GET (?P<http_uri>.*) HTTP\\/\\d\\.\\d\\r\\n/G\"; recursive; sid:1;)");
    if (sig_list == NULL) {
        result = 0;
        goto end;
    }
    sig_list->next = SigInit("alert tcp any any -> any any (msg:\"HTTP URI test\"; uricontent:\"three\"; sid:2;)");
    if (sig_list->next == NULL) {
        result = 0;
        goto end;
    }

    PatternMatchPrepare(sig_list);
    PatternMatcherThreadInit(&th_v, (void *)&pmt);
    SigMatchSignatures(&th_v, pmt, &p);

    if (PacketAlertCheck(&p, 1) && PacketAlertCheck(&p, 2))
        result = 0;
    else
        result = 1;

    PatternMatcherThreadDeinit(&th_v, (void *)pmt);
    PatternMatchDestroy();
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
    p.tcp_payload = buf;
    p.tcp_payload_len = buflen;

    SigParsePrepare();

    sig_list = SigInit("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:\"GET \"; depth:4; pcre:\"/GET (?P<http_uri>.*) HTTP\\/1\\.0\\r\\n/G\"; sid:1;)");
    if (sig_list == NULL) {
        result = 0;
        goto end;
    }
    sig_list->next = SigInit("alert tcp any any -> any any (msg:\"HTTP URI test\"; uricontent:\"one\"; sid:2;)");
    if (sig_list->next == NULL) {
        result = 0;
        goto end;
    }

    PatternMatchPrepare(sig_list);
    PatternMatcherThreadInit(&th_v, (void *)&pmt);
    SigMatchSignatures(&th_v, pmt, &p);

    if (PacketAlertCheck(&p, 1) && PacketAlertCheck(&p, 2))
        result = 1;

    PatternMatcherThreadDeinit(&th_v, (void *)pmt);
    PatternMatchDestroy();
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
    p.tcp_payload = buf;
    p.tcp_payload_len = buflen;

    SigParsePrepare();

    sig_list = SigInit("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:\"GET \"; depth:4; pcre:\"/GET (?P<http_uri>.*) HTTP\\/1\\.0\\r\\n/G\"; sid:1;)");
    if (sig_list == NULL) {
        result = 0;
        goto end;
    }
    sig_list->next = SigInit("alert tcp any any -> any any (msg:\"HTTP URI test\"; uricontent:\"two\"; sid:2;)");
    if (sig_list->next == NULL) {
        result = 0;
        goto end;
    }

    PatternMatchPrepare(sig_list);
    PatternMatcherThreadInit(&th_v, (void *)&pmt);
    SigMatchSignatures(&th_v, pmt, &p);

    if (PacketAlertCheck(&p, 1) && PacketAlertCheck(&p, 2))
        result = 0;
    else
        result = 1;

    PatternMatcherThreadDeinit(&th_v, (void *)pmt);
    PatternMatchDestroy();
end:
    return result;
}

void SigRegisterTests(void) {
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

