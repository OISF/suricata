/* signature parser */

#include <pcre.h>

#include "vips.h"
#include "debug.h"
#include "detect.h"
#include "flow.h"

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

/* XXX implement this for real
 *
 */
int SigParseAddress(Signature *s, const char *addrstr, char flag) {
    char *addr = NULL;

    if (strcmp(addrstr,"$HOME_NET") == 0) {
        addr = "192.168.0.0/16";
    } else if (strcmp(addrstr,"$EXTERNAL_NET") == 0) {
        addr = "!192.168.0.0/16";
    } else if (strcmp(addrstr,"$HTTP_SERVERS") == 0) {
    } else if (strcmp(addrstr,"$SMTP_SERVERS") == 0) {
    } else if (strcmp(addrstr,"$SQL_SERVERS") == 0) {
    } else if (strcmp(addrstr,"$DNS_SERVERS") == 0) {
    } else if (strcmp(addrstr,"any") == 0) {

    } else {
        printf("addr \"%s\"\n", addrstr);
    }

    return 0;
}

int SigParseProto(Signature *s, const char *protostr) {
    if (strcasecmp(protostr,"tcp") == 0) {
    } else if (strcasecmp(protostr,"udp") == 0) {
    } else if (strcasecmp(protostr,"ip") == 0) {
    } else {
        printf("protostr \"%s\"\n", protostr);
    }

    return 0;
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
    } else {
        return -1;
    }
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

    /* Parse Action */
    if (SigParseAction(s, arr[CONFIG_ACTION]) < 0)
        goto error;

    /* Parse Proto */
    if (SigParseProto(s, arr[CONFIG_PROTO]) < 0)
        goto error;

    /* Parse Address & Ports */
    if (SigParseAddress(s, arr[CONFIG_SRC], 0) < 0)
        goto error;
    if (SigParsePort(s, arr[CONFIG_SP], 0) < 0)
        goto error;
    if (SigParseAddress(s, arr[CONFIG_DST], 1) < 0)
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

