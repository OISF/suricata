/* FLOW part of the detection engine. */

#include <pcre.h>

#include "debug.h"
#include "decode.h"
#include "detect.h"

#include "flow.h"
#include "flow-var.h"

#include "detect-flow.h"

#define PARSE_REGEX "([A-z_]+)(?:,([A-z_]+))?"
static pcre *parse_regex;
static pcre_extra *parse_regex_study;

int DetectFlowMatch (ThreadVars *, PatternMatcherThread *, Packet *, Signature *, SigMatch *);
int DetectFlowSetup (Signature *, SigMatch *, char *);

void DetectFlowRegister (void) {
    sigmatch_table[DETECT_FLOW].name = "flow";
    sigmatch_table[DETECT_FLOW].Match = DetectFlowMatch;
    sigmatch_table[DETECT_FLOW].Setup = DetectFlowSetup;
    sigmatch_table[DETECT_FLOW].Free  = NULL;
    sigmatch_table[DETECT_FLOW].RegisterTests = NULL;

    const char *eb;
    int eo;
    int opts = 0;

    parse_regex = pcre_compile(PARSE_REGEX, opts, &eb, &eo, NULL);
    if(parse_regex == NULL)
    {
        printf("pcre compile of \"%s\" failed at offset %d: %s\n", PARSE_REGEX, eo, eb);
        goto error;
    }

    parse_regex_study = pcre_study(parse_regex, 0, &eb);
    if(eb != NULL)
    {
        printf("pcre study failed: %s\n", eb);
        goto error;
    }
    return;

error:
    /* XXX */
    return;
}

/*
 * returns 0: no match
 *         1: match
 *        -1: error
 */

int DetectFlowMatch (ThreadVars *t, PatternMatcherThread *pmt, Packet *p, Signature *s, SigMatch *m)
{
    int ret = 0;

    DetectFlowData *fd = (DetectFlowData *)m->ctx;

    if (fd->flags & FLOW_PKT_TOSERVER && p->flowflags & FLOW_PKT_TOSERVER) {
        ret = 1;
    }
    else if (fd->flags & FLOW_PKT_TOCLIENT && p->flowflags & FLOW_PKT_TOCLIENT) {
        ret = 1;
    }

    //printf("DetectFlowMatch: returning %d\n", ret);
    return ret;
}

int DetectFlowSetup (Signature *s, SigMatch *m, char *flowstr)
{
    DetectFlowData *fd = NULL;
    SigMatch *sm = NULL;
    char *state = NULL, *dir = NULL, *stream = NULL;
#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];

    //printf("DetectFlowSetup: \'%s\'\n", flowstr);

    ret = pcre_exec(parse_regex, parse_regex_study, flowstr, strlen(flowstr), 0, 0, ov, MAX_SUBSTRINGS);
    if (ret > 1) {
        const char *str_ptr;
        res = pcre_get_substring((char *)flowstr, ov, MAX_SUBSTRINGS, 1, &str_ptr);
        if (res < 0) {
            printf("DetectFlowSetup: pcre_get_substring failed\n");
            return -1;
        }
        state = (char *)str_ptr;

        if (ret > 2) {
            res = pcre_get_substring((char *)flowstr, ov, MAX_SUBSTRINGS, 2, &str_ptr);
            if (res < 0) {
                printf("DetectFlowSetup: pcre_get_substring failed\n");
                return -1;
            }
            dir = (char *)str_ptr;
        }
        if (ret > 3) {
            res = pcre_get_substring((char *)flowstr, ov, MAX_SUBSTRINGS, 3, &str_ptr);
            if (res < 0) {
                printf("DetectFlowSetup: pcre_get_substring failed\n");
                return -1;
            }
            stream = (char *)str_ptr;
        }
    }
    //printf("ret %d state \'%s\', dir \'%s\', stream '%s'\n", ret, state, dir, stream);

    fd = malloc(sizeof(DetectFlowData));
    if (fd == NULL) {
        printf("DetectFlowSetup malloc failed\n");
        goto error;
    }
    fd->flags = 0;

    /* inspect our options and set the flags */
    if (state) {
        if (strcmp(state,"established") == 0) fd->flags |= FLOW_PKT_ESTABLISHED;
        if (strcmp(state,"stateless") == 0) fd->flags |= FLOW_PKT_STATELESS;
        if (strcmp(state,"to_client") == 0) fd->flags |= FLOW_PKT_TOCLIENT;
        if (strcmp(state,"to_server") == 0) fd->flags |= FLOW_PKT_TOSERVER;
        if (strcmp(state,"from_server") == 0) fd->flags |= FLOW_PKT_TOCLIENT;
        if (strcmp(state,"from_client") == 0) fd->flags |= FLOW_PKT_TOSERVER;
    }
    if (dir) {
        if (strcmp(dir,"established") == 0) fd->flags |= FLOW_PKT_ESTABLISHED;
        if (strcmp(dir,"stateless") == 0) fd->flags |= FLOW_PKT_STATELESS;
        if (strcmp(dir,"to_client") == 0) fd->flags |= FLOW_PKT_TOCLIENT;
        if (strcmp(dir,"to_server") == 0) fd->flags |= FLOW_PKT_TOSERVER;
        if (strcmp(dir,"from_server") == 0) fd->flags |= FLOW_PKT_TOCLIENT;
        if (strcmp(dir,"from_client") == 0) fd->flags |= FLOW_PKT_TOSERVER;
    }
    if (stream) {
        if (strcmp(stream,"established") == 0) fd->flags |= FLOW_PKT_ESTABLISHED;
        if (strcmp(stream,"stateless") == 0) fd->flags |= FLOW_PKT_STATELESS;
        if (strcmp(stream,"to_client") == 0) fd->flags |= FLOW_PKT_TOCLIENT;
        if (strcmp(stream,"to_server") == 0) fd->flags |= FLOW_PKT_TOSERVER;
        if (strcmp(stream,"from_server") == 0) fd->flags |= FLOW_PKT_TOCLIENT;
        if (strcmp(stream,"from_client") == 0) fd->flags |= FLOW_PKT_TOSERVER;
    }

    /* Okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_FLOW;
    sm->ctx = (void *)fd;

    SigMatchAppend(s,m,sm);

    return 0;

error:
    if (fd) free(fd);
    if (sm) free(sm);
    return -1;
}

