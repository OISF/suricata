/* Basic detection engine datastructure */

#include <pcre.h>

#include "vips.h"
#include "debug.h"
#include "detect.h"
#include "flow.h"

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

#include "detect-mpm.h"
#include "tm-modules.h"

#include "util-unittest.h"

static Signature *sig_list;
static pcre *config_pcre = NULL;
static pcre *option_pcre = NULL;
static pcre_extra *config_pcre_extra = NULL;
static pcre_extra *option_pcre_extra = NULL;


#define CONFIG_PARTS 8

#define CONFIG_ACTION 0
#define CONFIG_PROTO  1
#define CONFIG_SRC    2
#define CONFIG_SP     3
#define CONFIG_DIREC  4
#define CONFIG_DST    5
#define CONFIG_DP     6
#define CONFIG_OPTS   7

//                    action       protocol       src                                  sp                       dir                   dst                                 dp                            options
#define CONFIG_PCRE "^([A-z]+)\\s+([A-z0-9]+)\\s+([\\[\\]A-z0-9\\.\\:_\\$\\!,//]+)\\s+([\\:A-z0-9_\\$\\!]+)\\s+(\\<-|-\\>|\\<\\>)\\s+([\\[\\]A-z0-9\\.\\:_\\$\\!,/]+)\\s+([\\:A-z0-9_\\$\\!]+)(?:\\s+\\((.*)?(?:\\s*)\\))?(?:(?:\\s*)\\n)?$"
#define OPTION_PARTS 3
#define OPTION_PCRE "^\\s*([A-z_0-9]+)(?:\\s*\\:(.*)(?<!\\\\))?;\\s*(?:\\s*(.*))?$"

/* prototypes */
int SigParse(Signature *s, char *sigstr);
Signature *SigAlloc (void);
void SigFree(Signature *s);
Signature *SigInit(char *sigstr);
void SigParsePrepare(void);
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
}

Signature *sig_tree_proto[256];
Signature *sig_tree_tcpsp[65536+1]; /* +1 for 'any' */
Signature *sig_tree_tcpdp[65536+1];
Signature *sig_tree_udpsp[65536+1];
Signature *sig_tree_udpdp[65536+1];

int SigBuildSearchTree(Signature *s) {
    memset(sig_tree_proto, 0, sizeof(sig_tree_proto));
    memset(sig_tree_tcpsp, 0, sizeof(sig_tree_tcpsp));
    memset(sig_tree_tcpdp, 0, sizeof(sig_tree_tcpdp));
    memset(sig_tree_udpsp, 0, sizeof(sig_tree_udpsp));
    memset(sig_tree_udpdp, 0, sizeof(sig_tree_udpdp));



    return 0;
}

Signature *SigAlloc (void) {
    Signature *sig = malloc(sizeof(Signature));
    if (sig == NULL)
        return NULL;

    memset(sig, 0, sizeof(Signature));
    return sig;
}

void SigFree(Signature *s) {
    if (s == NULL)
        return;

    SigMatch *sm = s->match, *nsm;
    while (sm != NULL) {
        nsm = sm->next;
        SigMatchFree(sm);
        sm = nsm;
    }

    if (s->msg) free(s->msg);
    free(s);
}

Signature *SigInit(char *sigstr) {
    Signature *sig = SigAlloc();
    if (sig == NULL)
        goto error;

    if (SigParse(sig, sigstr) < 0)
        goto error;

    return sig;

error:
    SigFree(sig);
    return NULL;

}

void SigParsePrepare(void) {
    char *regexstr = CONFIG_PCRE;
    const char *eb;
    int eo;
    int opts = 0;

    opts |= PCRE_UNGREEDY;
    config_pcre = pcre_compile(regexstr, opts, &eb, &eo, NULL);
    if(config_pcre == NULL)
    {
        printf("pcre compile of \"%s\" failed at offset %d: %s\n", regexstr, eo, eb);
        exit(1);
    }

    config_pcre_extra = pcre_study(config_pcre, 0, &eb);
    if(eb != NULL)
    {
        printf("pcre study failed: %s\n", eb);
        exit(1);
    }

    regexstr = OPTION_PCRE;
    opts |= PCRE_UNGREEDY;

    option_pcre = pcre_compile(regexstr, opts, &eb, &eo, NULL);
    if(option_pcre == NULL)
    {
        printf("pcre compile of \"%s\" failed at offset %d: %s\n", regexstr, eo, eb);
        exit(1);
    }

    option_pcre_extra = pcre_study(option_pcre, 0, &eb);
    if(eb != NULL)
    {
        printf("pcre study failed: %s\n", eb);
        exit(1);
    }
}

SigMatch *SigMatchAlloc(void) {
    SigMatch *sm = malloc(sizeof(SigMatch));
    if (sm == NULL)
        return NULL;

    memset(sm, 0, sizeof(SigMatch));
    return sm;
}

void SigMatchFree(SigMatch *sm) {
    if (sm == NULL)
        return;

    if (sigmatch_table[sm->type].Free != NULL) {
        sigmatch_table[sm->type].Free(sm);
    }
    free(sm);
}

SigTableElmt *SigTableGet(char *name) {
    SigTableElmt *st = NULL;
    int i = 0;

    for (i = 0; i < DETECT_TBLSIZE; i++) {
        st = &sigmatch_table[i];

        if (st->name != NULL) {
            if (strcmp(name,st->name) == 0)
                return st;
        }
    }

    return NULL;
}

/* Append 'new' SigMatch to the current Signature. If present
 * append it to Sigmatch 'm', otherwise place it in the root.
 */
void SigMatchAppend(Signature *s, SigMatch *m, SigMatch *new) {
    //printf("s:%p,m:%p,new:%p\n", s,m,new);

    if (m == NULL)
        m = s->match;

    if (s->match == NULL)
        s->match = new;
    else {
        m->next = new;
        new->prev = m;
    }
}

int SigParseOptions(Signature *s, SigMatch *m, char *optstr) {
#define MAX_SUBSTRINGS 30
    int ov[MAX_SUBSTRINGS];
    int ret = 0, i = 0;
    SigTableElmt *st = NULL;
    char *optname = NULL, *optvalue = NULL, *optmore = NULL;

    const char **arr = calloc(OPTION_PARTS+1, sizeof(char *));
    if (arr == NULL)
        return -1;

    ret = pcre_exec(option_pcre, option_pcre_extra, optstr, strlen(optstr), 0, 0, ov, MAX_SUBSTRINGS);
    /* if successful, we either have:
     *  2: keyword w/o value
     *  3: keyword w value, final opt OR keyword w/o value, more options coming
     *  4: keyword w value, more options coming
     */
    if (ret != 2 && ret != 3 && ret != 4) {
        printf("pcre_exec failed: ret %d, optstr \"%s\"\n", ret, optstr);
        goto error;
    }
    //printf("SigParseOptions: pcre_exec returned %d\n", ret);

    for (i = 1; i <= ret-1; i++) {
        pcre_get_substring(optstr, ov, MAX_SUBSTRINGS, i, &arr[i-1]);
        //printf("SigParseOptions: arr[%d] = \"%s\"\n", i-1, arr[i-1]);
    }
    arr[i-1]=NULL;

    /* Call option parsing */
    st = SigTableGet((char *)arr[0]);
    if (st == NULL) {
        printf("Unknown rule keyword '%s'.\n", (char *)arr[0]);
        goto error;
    }

    if (st->flags & SIGMATCH_NOOPT) {
        optname = (char *)arr[0];
        optvalue = NULL;
        if (ret == 3) optmore = (char *)arr[1];
        else if (ret == 4) optmore = (char *)arr[2];
        else optmore = NULL;
    } else {
        optname = (char *)arr[0];
        optvalue = (char *)arr[1];
        if (ret > 3) optmore = (char *)arr[2];
        else optmore = NULL;
    }

    /* setup may or may not add a new SigMatch to the list */
    if (st->Setup(s, m, optvalue) < 0)
        goto error;
    //printf("SigParseOptions: s->match:%p,m:%p\n", s->match, m);
    /* thats why we check for that here */
    if (m && m->next)
        m = m->next;
    else if (m == NULL && s->match != NULL)
        m = s->match;

    //printf("SigParseOptions: s->match:%p,m:%p\n", s->match, m);
    if (ret == 4 && optmore != NULL) {
        //printf("SigParseOptions: recursive call for more options... (s:%p,m:%p)\n", s, m);

        if (arr != NULL) free(arr);
        return(SigParseOptions(s, m, optmore));
    }

    if (arr != NULL) free(arr);
    return 0;

error:
    if (arr != NULL) free(arr);
    return -1;
}

/* src: flag = 0, dst: flag = 1
 *
 */
int SigParsePort(Signature *s, const char *portstr, char flag) {
    SigPort p;

    if (strcasecmp(portstr, "any") == 0) {
        if (flag == 0) {
            s->sp = 0;
            s->flags |= SIG_FLAG_SP_ANY;
        } else {
            s->dp = 0;
            s->flags |= SIG_FLAG_DP_ANY;
        }
    } else {
        p = atoi(portstr);

        if (flag == 0) {
            s->sp = p;
        } else {
            s->dp = p;
        }
    }

    return 0;
}

int SigParseBasics(Signature *s, char *sigstr, char ***result) {
#define MAX_SUBSTRINGS 30
    int ov[MAX_SUBSTRINGS];
    int ret = 0, i = 0;

    const char **arr = calloc(CONFIG_PARTS+1, sizeof(char *));
    if (arr == NULL)
        return -1;

    ret = pcre_exec(config_pcre, config_pcre_extra, sigstr, strlen(sigstr), 0, 0, ov, MAX_SUBSTRINGS);
    if (ret != 8 && ret != 9) {
        printf("SigParseBasics: pcre_exec failed: ret %d, sigstr \"%s\"\n", ret, sigstr);
        goto error;
    }
    DEBUGPRINT("SigParseBasics: pcre_exec returned %d", ret);

    for (i = 1; i <= ret-1; i++) {
        pcre_get_substring(sigstr, ov, MAX_SUBSTRINGS, i, &arr[i-1]);
        //printf("SigParseBasics: arr[%d] = \"%s\"\n", i-1, arr[i-1]);
    }
    arr[i-1]=NULL;

    if (SigParsePort(s, arr[CONFIG_SP], 0) < 0)
        goto error;
    if (SigParsePort(s, arr[CONFIG_DP], 1) < 0)
        goto error;

    *result = (char **)arr;
    DEBUGPRINT("SigParseBasics: %p %p", arr, *result);
    return 0;

error:
    if (arr) free(arr);
    *result = NULL;
    return -1;
}

int SigParse(Signature *s, char *sigstr) {
    char **basics;

    int ret = SigParseBasics(s, sigstr, &basics);
    if (ret < 0)
        return -1;

#ifdef DEBUG
    DEBUGPRINT("SigParse: %p", basics);
    int i;
    for (i = 0; basics[i] != NULL; i++) {
        DEBUGPRINT("SigParse: basics[%d]: %p, %s", i, basics[i], basics[i]);
    }
#endif /* DEBUG */

    /* we can have no options, so make sure we have them */
    if (basics[CONFIG_OPTS] != NULL) {
        ret = SigParseOptions(s, NULL, basics[CONFIG_OPTS]);
    }

    /* cleanup */
    if (basics) {
        int i = 0;
        while (basics[i] != NULL) {
            free(basics[i]);
            i++;
        }
        free(basics);
    }
    return ret;
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
    FILE *fp = fopen("/home/victor/rules/bleeding-all.rules", "r");
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

    pmt->de_have_httpuri = 0;
    pmt->de_scanned_httpuri = 0;

    /* match all keywords against this packet */
    if (p->flowflags & FLOW_PKT_TOSERVER)
        pmt->mpm_instance = MPM_INSTANCE_TOSERVER;
    else if (p->flowflags & FLOW_PKT_TOCLIENT)
        pmt->mpm_instance = MPM_INSTANCE_TOCLIENT;
    else 
        pmt->mpm_instance = 0;

    //u_int32_t cnt = 
    PacketPatternMatch(th_v, pmt, p);
    //printf("cnt %u\n", cnt);

//#if 0
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
                            if (rmatch == 0)
                                PacketAlertAppend(p, 1, s->id, s->rev, s->msg);

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
    return(PatternMatcherThreadInit(t,data));
}

int DetectThreadDeinit(ThreadVars *t, void *data) {
    return(PatternMatcherThreadDeinit(t,data));
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

