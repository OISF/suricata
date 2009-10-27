/* signature parser */

#include "eidps-common.h"
#include "debug.h"

#include "detect.h"
#include "detect-engine.h"
#include "detect-engine-address.h"
#include "detect-engine-port.h"

#include "flow.h"

#include "util-unittest.h"
#include "util-debug.h"

static pcre *config_pcre = NULL;
static pcre *option_pcre = NULL;
static pcre_extra *config_pcre_extra = NULL;
static pcre_extra *option_pcre_extra = NULL;

/* XXX this should be part of the DE */
//static uint32_t signum = 0;

static uint32_t dbg_srcportany_cnt = 0;
static uint32_t dbg_dstportany_cnt = 0;

#define CONFIG_PARTS 8

#define CONFIG_ACTION 0
#define CONFIG_PROTO  1
#define CONFIG_SRC    2
#define CONFIG_SP     3
#define CONFIG_DIREC  4
#define CONFIG_DST    5
#define CONFIG_DP     6
#define CONFIG_OPTS   7

//                    action       protocol       src                                      sp                        dir              dst                                    dp                            options
#define CONFIG_PCRE "^([A-z]+)\\s+([A-z0-9]+)\\s+([\\[\\]A-z0-9\\.\\:_\\$\\!\\-,\\/]+)\\s+([\\:A-z0-9_\\$\\!,]+)\\s+(-\\>|\\<\\>)\\s+([\\[\\]A-z0-9\\.\\:_\\$\\!\\-,/]+)\\s+([\\:A-z0-9_\\$\\!,]+)(?:\\s+\\((.*)?(?:\\s*)\\))?(?:(?:\\s*)\\n)?$"
#define OPTION_PARTS 3
#define OPTION_PCRE "^\\s*([A-z_0-9-]+)(?:\\s*\\:\\s*(.*)(?<!\\\\))?\\s*;\\s*(?:\\s*(.*))?\\s*$"

uint32_t DbgGetSrcPortAnyCnt(void) {
    return dbg_srcportany_cnt;
}

uint32_t DbgGetDstPortAnyCnt(void) {
    return dbg_dstportany_cnt;
}

SigMatch *SigMatchAlloc(void) {
    SigMatch *sm = malloc(sizeof(SigMatch));
    if (sm == NULL)
        return NULL;

    memset(sm, 0, sizeof(SigMatch));
    return sm;
}

/** \brief free a SigMatch
 *  \param sm SigMatch to free.
 */
void SigMatchFree(SigMatch *sm) {
    if (sm == NULL)
        return;

    /** free the ctx, for that we call the Free func */
    if (sm->ctx != NULL) {
        if (sigmatch_table[sm->type].Free != NULL) {
            sigmatch_table[sm->type].Free(sm->ctx);
        }
    }
    free(sm);
}

/* Get the detection module by name */
SigTableElmt *SigTableGet(char *name) {
    SigTableElmt *st = NULL;
    int i = 0;

    for (i = 0; i < DETECT_TBLSIZE; i++) {
        st = &sigmatch_table[i];

        if (st->name != NULL) {
            if (strcasecmp(name,st->name) == 0)
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

void SigParsePrepare(void) {
    char *regexstr = CONFIG_PCRE;
    const char *eb;
    int eo;
    int opts = 0;

    opts |= PCRE_UNGREEDY;
    config_pcre = pcre_compile(regexstr, opts, &eb, &eo, NULL);
    if(config_pcre == NULL)
    {
        printf("pcre compile of \"%s\" failed at offset %" PRId32 ": %s\n", regexstr, eo, eb);
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
        printf("pcre compile of \"%s\" failed at offset %" PRId32 ": %s\n", regexstr, eo, eb);
        exit(1);
    }

    option_pcre_extra = pcre_study(option_pcre, 0, &eb);
    if(eb != NULL)
    {
        printf("pcre study failed: %s\n", eb);
        exit(1);
    }
}

int SigParseOptions(DetectEngineCtx *de_ctx, Signature *s, SigMatch *m, char *optstr) {
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
        printf("pcre_exec failed: ret %" PRId32 ", optstr \"%s\"\n", ret, optstr);
        goto error;
    }

    /* extract the substrings */
    for (i = 1; i <= ret-1; i++) {
        pcre_get_substring(optstr, ov, MAX_SUBSTRINGS, i, &arr[i-1]);
        //printf("SigParseOptions: arr[%" PRId32 "] = \"%s\"\n", i-1, arr[i-1]);
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
        if (ret == 4) optmore = (char *)arr[2];
        else optmore = NULL;
    }

    /* setup may or may not add a new SigMatch to the list */
    if (st->Setup(de_ctx, s, m, optvalue) < 0)
        goto error;

    /* thats why we check for that here */
    if (m != NULL && m->next != NULL)
        m = m->next;
    else if (m == NULL && s->match != NULL)
        m = s->match;

    if (ret == 4 && optmore != NULL) {
        //printf("SigParseOptions: recursive call for more options... (s:%p,m:%p)\n", s, m);

        if (optname) pcre_free_substring(optname);
        if (optvalue) pcre_free_substring(optvalue);
        if (optstr) free(optstr);
        //if (optmore) pcre_free_substring(optmore);
        if (arr != NULL) free(arr);
        return SigParseOptions(de_ctx, s, m, optmore);
    }

    if (optname) pcre_free_substring(optname);
    if (optvalue) pcre_free_substring(optvalue);
    if (optmore) pcre_free_substring(optmore);
    if (optstr) free(optstr);
    if (arr != NULL) free(arr);
    return 0;

error:
    if (optname) pcre_free_substring(optname);
    if (optvalue) pcre_free_substring(optvalue);
    if (optmore) pcre_free_substring(optmore);
    if (optstr) free(optstr);
    if (arr != NULL) free(arr);
    return -1;
}

/* XXX implement this for real
 *
 */
int SigParseAddress(Signature *s, const char *addrstr, char flag) {
    char *addr = NULL;

    if (strcmp(addrstr, "$HOME_NET") == 0) {
        addr = "[192.168.0.0/16,10.8.0.0/16,127.0.0.1,2001:888:13c5:5AFE::/64,2001:888:13c5:CAFE::/64]";
        //addr = "[192.168.0.0/16,10.8.0.0/16,2001:888:13c5:5AFE::/64,2001:888:13c5:CAFE::/64]";
    } else if (strcmp(addrstr, "$EXTERNAL_NET") == 0) {
        addr = "[!192.168.0.0/16,2000::/3]";
    } else if (strcmp(addrstr, "$HTTP_SERVERS") == 0) {
        addr = "!192.168.0.0/16";
    } else if (strcmp(addrstr, "$SMTP_SERVERS") == 0) {
        addr = "!192.168.0.0/16";
    } else if (strcmp(addrstr, "$SQL_SERVERS") == 0) {
        addr = "!192.168.0.0/16";
    } else if (strcmp(addrstr, "$DNS_SERVERS") == 0) {
        addr = "any";
    } else if (strcmp(addrstr, "$TELNET_SERVERS") == 0) {
        addr = "any";
    } else if (strcmp(addrstr, "$AIM_SERVERS") == 0) {
        addr = "any";
    } else if (strcmp(addrstr, "any") == 0) {
        addr = "any";
    } else {
        addr = (char *)addrstr;
        //printf("SigParseAddress: addr \"%s\"\n", addrstr);
    }

    /* pass on to the address(list) parser */
    if (flag == 0) {
        if (strcasecmp(addrstr, "any") == 0)
            s->flags |= SIG_FLAG_SRC_ANY;

        if (DetectAddressGroupParse(&s->src, addr) < 0)
            goto error;
    } else {
        if (strcasecmp(addrstr, "any") == 0)
            s->flags |= SIG_FLAG_DST_ANY;

        if (DetectAddressGroupParse(&s->dst, addr) < 0)
            goto error;
    }

    return 0;

error:
    return -1;
}

/**
 * \brief Parses the protocol supplied by the Signature.
 *
 *        http://www.iana.org/assignments/protocol-numbers
 *
 * \param s        Pointer to the Signature instance to which the parsed
 *                 protocol has to be added.
 * \param protostr Pointer to the character string containing the protocol name.
 *
 * \retval  0 On successfully parsing the protocl sent as the argument.
 * \retval -1 On failure
 */
int SigParseProto(Signature *s, const char *protostr) {
    int r = DetectProtoParse(&s->proto, (char *)protostr);
    if (r < 0)
        return -1;

    return 0;
}

/**
 * \brief Parses the port(source or destination) field, from a Signature
 *
 * \param s       Pointer to the signature which has to be updated with the
 *                port information
 * \param portstr Pointer to the character string containing the port info
 * \param         Flag which indicates if the portstr received is sort or dst
 *                port.  For src port: flag = 0, dst port: flag = 1
 *
 * \retval  0 On success
 * \retval -1 On failure
 */
int SigParsePort(Signature *s, const char *portstr, char flag) {
    int r = 0;
    char *port;
    char negate = 0;

    /* XXX VJ exclude handling this for none UDP/TCP proto's */

    /* XXX hack, fix this */
    if (portstr[0] == '!' && portstr[1] == '$') {
        portstr++;
        negate = 1;
    }

    if (strcmp(portstr, "$HTTP_PORTS") == 0) {
        if (negate) port = "![80:81,88]";
        else port = "80:81,88";
    } else if (strcmp(portstr, "$SHELLCODE_PORTS") == 0) {
        port = "!80";
    } else if (strcmp(portstr, "$ORACLE_PORTS") == 0) {
        if (negate) port = "!1521";
        else port = "1521";
    } else if (strcmp(portstr, "$SSH_PORTS") == 0) {
        if (negate) port = "!22";
        else port = "22";
    } else {
        port = (char *)portstr;
    }

    if (flag == 0) {
        if (strcasecmp(port, "any") == 0)
            s->flags |= SIG_FLAG_SP_ANY;

        r = DetectPortParse(&s->sp, (char *)port);
    } else if (flag == 1) {
        if (strcasecmp(port, "any") == 0)
            s->flags |= SIG_FLAG_DP_ANY;

        r = DetectPortParse(&s->dp, (char *)port);
    }

    if (r < 0)
        return -1;

    return 0;
}

/**
 * \brief Parses the action that has been used by the Signature and allots it
 *        to its Signatue instance.
 *
 * \param s      Pointer to the Signatue instance to which the action belongs.
 * \param action Pointer to the action string used by the Signature.
 *
 * \retval  0 On successfully parsing the action string and adding it to the
 *            Signature.
 * \retval -1 On failure.
 */
int SigParseAction(Signature *s, const char *action) {
    if (strcasecmp(action, "alert") == 0) {
        s->action = ACTION_ALERT;
        return 0;
    } else if(strcasecmp(action, "drop") == 0) {
        s->action = ACTION_DROP;
        return 0;
    } else if(strcasecmp(action, "pass") == 0) {
        s->action = ACTION_PASS;
        return 0;
    } else if(strcasecmp(action, "reject") == 0) {
        s->action = ACTION_REJECT;
        return 0;
    } else if(strcasecmp(action, "rejectsrc") == 0) {
        s->action = ACTION_REJECT;
        return 0;
    } else if(strcasecmp(action, "rejectdst") == 0) {
        s->action = ACTION_REJECT_DST;
        return 0;
    } else if(strcasecmp(action, "rejectboth") == 0) {
        s->action = ACTION_REJECT_BOTH;
        return 0;
    } else {
        return -1;
    }
}

int SigParseBasics(Signature *s, char *sigstr, char ***result) {
#define MAX_SUBSTRINGS 30
    int ov[MAX_SUBSTRINGS];
    int ret = 0, i = 0;

    const char **arr = calloc(CONFIG_PARTS + 1, sizeof(char *));
    if (arr == NULL)
        return -1;

    ret = pcre_exec(config_pcre, config_pcre_extra, sigstr, strlen(sigstr), 0, 0, ov, MAX_SUBSTRINGS);
    if (ret != 8 && ret != 9) {
        printf("SigParseBasics: pcre_exec failed: ret %" PRId32 ", sigstr \"%s\"\n", ret, sigstr);
        goto error;
    }

    for (i = 1; i <= ret - 1; i++) {
        pcre_get_substring(sigstr, ov, MAX_SUBSTRINGS, i, &arr[i - 1]);
        //printf("SigParseBasics: arr[%" PRId32 "] = \"%s\"\n", i-1, arr[i-1]);
    }
    arr[i - 1] = NULL;

    /* Parse Action */
    if (SigParseAction(s, arr[CONFIG_ACTION]) < 0)
        goto error;

    /* Parse Proto */
    if (SigParseProto(s, arr[CONFIG_PROTO]) < 0)
        goto error;

    /* Parse Address & Ports */
    if (SigParseAddress(s, arr[CONFIG_SRC], 0) < 0)
       goto error;

    /* For "ip" we parse the ports as well, even though they will be just "any".
     *  We do this for later sgh building for the tcp and udp protocols. */
    if (strcasecmp(arr[CONFIG_PROTO],"tcp") == 0 ||
        strcasecmp(arr[CONFIG_PROTO],"udp") == 0 ||
        strcasecmp(arr[CONFIG_PROTO],"ip") == 0) {
        if (SigParsePort(s, arr[CONFIG_SP], 0) < 0)
            goto error;
        if (SigParsePort(s, arr[CONFIG_DP], 1) < 0)
            goto error;
    }
    if (SigParseAddress(s, arr[CONFIG_DST], 1) < 0)
        goto error;

    *result = (char **)arr;
    return 0;

error:
    if (arr != NULL) {
        for (i = 1; i <= ret - 1; i++) {
            if (arr[i - 1] == NULL)
                continue;

            pcre_free_substring(arr[i - 1]);
        }
        free(arr);
    }
    *result = NULL;
    return -1;
}

int SigParse(DetectEngineCtx *de_ctx, Signature *s, char *sigstr) {
    char **basics;

    int ret = SigParseBasics(s, sigstr, &basics);
    if (ret < 0) {
        //printf("SigParseBasics failed\n");
        return -1;
}

#ifdef DEBUG
    if (SCLogDebugEnabled()) {
        int i;
        for (i = 0; basics[i] != NULL; i++) {
            SCLogDebug("basics[%" PRId32 "]: %p, %s", i, basics[i], basics[i]);
        }
    }
#endif /* DEBUG */

    /* we can have no options, so make sure we have them */
    if (basics[CONFIG_OPTS] != NULL) {
        ret = SigParseOptions(de_ctx, s, NULL, strdup(basics[CONFIG_OPTS]));
    }

    /* cleanup */
    if (basics != NULL) {
        int i = 0;
        while (basics[i] != NULL) {
            free(basics[i]);
            i++;
        }
        free(basics);
    }

    return ret;
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

    DetectAddressGroupsHeadCleanup(&s->src);
    DetectAddressGroupsHeadCleanup(&s->dst);

    DetectPortCleanupList(s->sp);
    DetectPortCleanupList(s->dp);

    if (s->msg != NULL) free(s->msg);

    free(s);
}

/**
 * \brief Parses a signature and adds it to the Detection Engine Context
 *
 * \param de_ctx Pointer to the Detection Engine Context
 * \param sigstr Pointer to a character string containing the signature to be
 *               parsed
 *
 * \retval Pointer to the Signature instance on success; NULL on failure
 */
Signature *SigInit(DetectEngineCtx *de_ctx, char *sigstr) {
    Signature *sig = SigAlloc();
    if (sig == NULL)
        goto error;

    /* XXX one day we will support this the way Snort does,
     * through classifications.config */
    sig->prio = 3;

    if (SigParse(de_ctx, sig, sigstr) < 0)
        goto error;

    sig->num = de_ctx->signum;
    de_ctx->signum++;
    return sig;

error:
    SigFree(sig);
    return NULL;

}

/*
 * TESTS
 */

#ifdef UNITTESTS
int SigParseTest01 (void) {
    int result = 1;
    Signature *sig = NULL;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    sig = SigInit(de_ctx, "alert tcp 1.2.3.4 any -> !1.2.3.4 any (msg:\"SigParseTest01\"; sid:1;)");
    if (sig == NULL) {
        result = 0;
        goto end;
    }

    SigFree(sig);
    DetectEngineCtxFree(de_ctx);
end:
    return result;
}

int SigParseTest02 (void) {
    int result = 0;
    Signature *sig = NULL;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    sig = SigInit(de_ctx, "alert tcp any !21:902 -> any any (msg:\"ET MALWARE Suspicious 220 Banner on Local Port\"; content:\"220\"; offset:0; depth:4; pcre:\"/220[- ]/\"; classtype:non-standard-protocol; sid:2003055; rev:4;)");
    if (sig == NULL) {
        goto end;
    }

    DetectPort *port = NULL;
    int r = DetectPortParse(&port, "0:20");
    if (r < 0)
        goto end;

    if (DetectPortCmp(sig->sp, port) == PORT_EQ) {
        result = 1;
    } else {
        DetectPortPrint(port); printf(" != "); DetectPortPrint(sig->sp); printf(": ");
    }

    DetectPortCleanupList(port);
    SigFree(sig);
    DetectEngineCtxFree(de_ctx);
end:
    return result;
}

/**
 * \test SigParseTest03 test for invalid direction operator in rule
 */
int SigParseTest03 (void) {
    int result = 1;
    Signature *sig = NULL;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    sig = SigInit(de_ctx, "alert tcp 1.2.3.4 any <- !1.2.3.4 any (msg:\"SigParseTest03\"; sid:1;)");
    if (sig != NULL) {
        result = 0;
        printf("expected NULL got sig ptr %p: ",sig);
        SigFree(sig);
        goto end;
    }

end:
    DetectEngineCtxFree(de_ctx);
    return result;
}

int SigParseTest04 (void) {
    int result = 1;
    Signature *sig = NULL;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    sig = SigInit(de_ctx, "alert tcp 1.2.3.4 1024: -> !1.2.3.4 1024: (msg:\"SigParseTest04\"; sid:1;)");
    if (sig == NULL) {
        result = 0;
        goto end;
    }

    SigFree(sig);
    DetectEngineCtxFree(de_ctx);
end:
    return result;
}

/** \test Port validation */
int SigParseTest05 (void) {
    int result = 1;
    Signature *sig = NULL;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    sig = SigInit(de_ctx, "alert tcp 1.2.3.4 1024:65536 -> !1.2.3.4 any (msg:\"SigParseTest05\"; sid:1;)");
    if (sig != NULL) {
        result = 1;
        SigFree(sig);
        goto end;
    }

    DetectEngineCtxFree(de_ctx);
end:
    return result;
}

/**
 * \test check that we don't allow invalid negation options
 */
static int SigParseTestNegation01 (void) {
    int result = 0;
    DetectEngineCtx *de_ctx;
    Signature *s=NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;
    de_ctx->flags |= DE_QUIET;

    s = SigInit(de_ctx,"alert tcp !any any -> any any (msg:\"SigTest41-01 src address is !any \"; classtype:misc-activity; sid:410001; rev:1;)");
    if (s != NULL) {
        SigFree(s);
        goto end;
    }

    result = 1;
end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test check that we don't allow invalid negation options
 */
static int SigParseTestNegation02 (void) {
    int result = 0;
    DetectEngineCtx *de_ctx;
    Signature *s=NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;
    de_ctx->flags |= DE_QUIET;

    s = SigInit(de_ctx,"alert tcp any !any -> any any (msg:\"SigTest41-02 src ip is !any \"; classtype:misc-activity; sid:410002; rev:1;)");
    if (s != NULL) {
        SigFree(s);
        goto end;
    }

    result = 1;
end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}
/**
 * \test check that we don't allow invalid negation options
 */
static int SigParseTestNegation03 (void) {
    int result = 0;
    DetectEngineCtx *de_ctx;
    Signature *s=NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;
    de_ctx->flags |= DE_QUIET;

    s = SigInit(de_ctx,"alert tcp any any -> any [80:!80] (msg:\"SigTest41-03 dst port [80:!80] \"; classtype:misc-activity; sid:410003; rev:1;)");
    if (s != NULL) {
        SigFree(s);
        goto end;
    }

    result = 1;
end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}
/**
 * \test check that we don't allow invalid negation options
 */
static int SigParseTestNegation04 (void) {
    int result = 0;
    DetectEngineCtx *de_ctx;
    Signature *s=NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;
    de_ctx->flags |= DE_QUIET;

    s = SigInit(de_ctx,"alert tcp any any -> any [80,!80] (msg:\"SigTest41-03 dst port [80:!80] \"; classtype:misc-activity; sid:410003; rev:1;)");
    if (s != NULL) {
        SigFree(s);
        goto end;
    }

    result = 1;
end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}
/**
 * \test check that we don't allow invalid negation options
 */
static int SigParseTestNegation05 (void) {
    int result = 0;
    DetectEngineCtx *de_ctx;
    Signature *s=NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;
    de_ctx->flags |= DE_QUIET;

    s = SigInit(de_ctx,"alert tcp any any -> [192.168.0.2,!192.168.0.2] any (msg:\"SigTest41-04 dst ip [192.168.0.2,!192.168.0.2] \"; classtype:misc-activity; sid:410004; rev:1;)");
    if (s != NULL) {
        SigFree(s);
        goto end;
    }

    result = 1;
end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}
/**
 * \test check that we don't allow invalid negation options
 */
static int SigParseTestNegation06 (void) {
    int result = 0;
    DetectEngineCtx *de_ctx;
    Signature *s=NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;
    de_ctx->flags |= DE_QUIET;

    s = SigInit(de_ctx,"alert tcp any any -> any [100:1000,!1:20000] (msg:\"SigTest41-05 dst port [100:1000,!1:20000] \"; classtype:misc-activity; sid:410005; rev:1;)");
    if (s != NULL) {
        SigFree(s);
        goto end;
    }

    result = 1;
end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}
/**
 * \test check that we don't allow invalid negation options
 */
static int SigParseTestNegation07 (void) {
    int result = 0;
    DetectEngineCtx *de_ctx;
    Signature *s=NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;
    de_ctx->flags |= DE_QUIET;

    s = SigInit(de_ctx,"alert tcp any any -> [192.168.0.2,!192.168.0.0/24] any (msg:\"SigTest41-06 dst ip [192.168.0.2,!192.168.0.0/24] \"; classtype:misc-activity; sid:410006; rev:1;)");
    if (s != NULL) {
        SigFree(s);
        goto end;
    }

    result = 1;
end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}
#endif /* UNITTESTS */

void SigParseRegisterTests(void) {
#ifdef UNITTESTS
    UtRegisterTest("SigParseTest01", SigParseTest01, 1);
    UtRegisterTest("SigParseTest02", SigParseTest02, 1);
    UtRegisterTest("SigParseTest03", SigParseTest03, 1);
    UtRegisterTest("SigParseTest04", SigParseTest04, 1);
    UtRegisterTest("SigParseTest05", SigParseTest05, 1);
    UtRegisterTest("SigParseTestNegation01", SigParseTestNegation01, 1);
    UtRegisterTest("SigParseTestNegation02", SigParseTestNegation02, 1);
    UtRegisterTest("SigParseTestNegation03", SigParseTestNegation03, 1);
    UtRegisterTest("SigParseTestNegation04", SigParseTestNegation04, 1);
    UtRegisterTest("SigParseTestNegation05", SigParseTestNegation05, 1);
    UtRegisterTest("SigParseTestNegation06", SigParseTestNegation06, 1);
    UtRegisterTest("SigParseTestNegation07", SigParseTestNegation07, 1);
#endif /* UNITTESTS */
}

