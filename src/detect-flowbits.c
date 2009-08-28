/* Simple Snort compatible flowbits implementation.
 *
 * Copyright (C) 2008 by Victor Julien <victor@inliniac.net>
 *
 *
 * Option looks like:
 *
 * flowbits:isset,SoberEhlo;
 *  - set
 *  - unset
 *  - toggle
 *  - isset
 *  - isnotset
 *
 * or
 *
 * flowbits:noalert;
 *
 */

#include <ctype.h>
#include <pcre.h>

#include "eidps-common.h"
#include "decode.h"
#include "detect.h"
#include "threads.h"
#include "flow.h"
#include "flow-bit.h"
#include "detect-flowbits.h"
#include "util-binsearch.h"

#include "util-var-name.h"

#define PARSE_REGEX         "([a-z]+)(?:,(.*))?"
static pcre *parse_regex;
static pcre_extra *parse_regex_study;

int DetectFlowbitMatch (ThreadVars *, DetectEngineThreadCtx *, Packet *, Signature *, SigMatch *);
int DetectFlowbitSetup (DetectEngineCtx *, Signature *, SigMatch *, char *);
void DetectFlowbitFree (void *);

void DetectFlowbitsRegister (void) {
    sigmatch_table[DETECT_FLOWBITS].name = "flowbits";
    sigmatch_table[DETECT_FLOWBITS].Match = DetectFlowbitMatch;
    sigmatch_table[DETECT_FLOWBITS].Setup = DetectFlowbitSetup;
    sigmatch_table[DETECT_FLOWBITS].Free  = DetectFlowbitFree;
    sigmatch_table[DETECT_FLOWBITS].RegisterTests  = NULL;

    const char *eb;
    int eo;
    int opts = 0;

    parse_regex = pcre_compile(PARSE_REGEX, opts, &eb, &eo, NULL);
    if(parse_regex == NULL)
    {
        printf("pcre compile of \"%s\" failed at offset %" PRId32 ": %s\n", PARSE_REGEX, eo, eb);
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
    return;
}


static int DetectFlowbitMatchToggle (Packet *p, DetectFlowbitsData *fd) {
    FlowBitToggle(p->flow,fd->idx);
    return 1;
}

static int DetectFlowbitMatchUnset (Packet *p, DetectFlowbitsData *fd) {
    FlowBitUnset(p->flow,fd->idx);
    return 1;
}

static int DetectFlowbitMatchSet (Packet *p, DetectFlowbitsData *fd) {
    FlowBitSet(p->flow,fd->idx);
    return 1;
}

static int DetectFlowbitMatchIsset (Packet *p, DetectFlowbitsData *fd) {
    return FlowBitIsset(p->flow,fd->idx);
}

static int DetectFlowbitMatchIsnotset (Packet *p, DetectFlowbitsData *fd) {
    return FlowBitIsnotset(p->flow,fd->idx);
}

/*
 * returns 0: no match
 *         1: match
 *        -1: error
 */

int DetectFlowbitMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx, Packet *p, Signature *s, SigMatch *m)
{
    DetectFlowbitsData *fd = (DetectFlowbitsData *)m->ctx;
    if (fd == NULL)
        return 0;

    switch (fd->cmd) {
        case DETECT_FLOWBITS_CMD_ISSET:
            return DetectFlowbitMatchIsset(p,fd);
        case DETECT_FLOWBITS_CMD_ISNOTSET:
            return DetectFlowbitMatchIsnotset(p,fd);
        case DETECT_FLOWBITS_CMD_SET:
            return DetectFlowbitMatchSet(p,fd);
        case DETECT_FLOWBITS_CMD_UNSET:
            return DetectFlowbitMatchUnset(p,fd);
        case DETECT_FLOWBITS_CMD_TOGGLE:
            return DetectFlowbitMatchToggle(p,fd);
        default:
            printf("ERROR: DetectFlowbitMatch unknown cmd %" PRIu32 "\n", fd->cmd);
            return 0;
    }

    return 0;
}

int DetectFlowbitSetup (DetectEngineCtx *de_ctx, Signature *s, SigMatch *m, char *rawstr)
{
    DetectFlowbitsData *cd = NULL;
    SigMatch *sm = NULL;
    char *str = rawstr;
    char dubbed = 0;
    char *fb_cmd_str = NULL, *fb_name = NULL;
    uint8_t fb_cmd = 0;
#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];

    ret = pcre_exec(parse_regex, parse_regex_study, rawstr, strlen(rawstr), 0, 0, ov, MAX_SUBSTRINGS);
    if (ret != 2 && ret != 3) {
        printf("ERROR: \"%s\" is not a valid setting for flowbits.\n", rawstr);
        return -1;
    }

    const char *str_ptr;
    res = pcre_get_substring((char *)rawstr, ov, MAX_SUBSTRINGS, 1, &str_ptr);
    if (res < 0) {
        printf("DetectPcreSetup: pcre_get_substring failed\n");
        return -1;
    }
    fb_cmd_str = (char *)str_ptr;

    if (ret == 3) {
        res = pcre_get_substring((char *)rawstr, ov, MAX_SUBSTRINGS, 2, &str_ptr);
        if (res < 0) {
            printf("DetectPcreSetup: pcre_get_substring failed\n");
            return -1;
        }
        fb_name = (char *)str_ptr;
    }

    if (strcmp(fb_cmd_str,"noalert") == 0) {
        fb_cmd = DETECT_FLOWBITS_CMD_NOALERT;
    } else if (strcmp(fb_cmd_str,"isset") == 0) {
        fb_cmd = DETECT_FLOWBITS_CMD_ISSET;
    } else if (strcmp(fb_cmd_str,"isnotset") == 0) {
        fb_cmd = DETECT_FLOWBITS_CMD_ISNOTSET;
    } else if (strcmp(fb_cmd_str,"set") == 0) {
        fb_cmd = DETECT_FLOWBITS_CMD_SET;
    } else if (strcmp(fb_cmd_str,"unset") == 0) {
        fb_cmd = DETECT_FLOWBITS_CMD_UNSET;
    } else if (strcmp(fb_cmd_str,"toggle") == 0) {
        fb_cmd = DETECT_FLOWBITS_CMD_TOGGLE;
    } else {
        printf("ERROR: flowbits action \"%s\" is not supported.\n", fb_cmd_str);
        return -1;
    }

    if (fb_cmd == DETECT_FLOWBITS_CMD_NOALERT) {
        s->flags |= SIG_FLAG_NOALERT;
        return 0;
    }

    cd = malloc(sizeof(DetectFlowbitsData));
    if (cd == NULL) {
        printf("DetectFlowbitsSetup malloc failed\n");
        goto error;
    }

    if (fb_name != NULL) {
        cd->idx = VariableNameGetIdx(de_ctx,fb_name,DETECT_FLOWBITS);
    } else {
        cd->idx = 0;
    }
    cd->cmd = fb_cmd;
    //printf("DetectFlowbitSetup: idx %" PRIu32 ", cmd %s, name %s\n", cd->idx, fb_cmd_str, fb_name ? fb_name : "(null)");

    /* Okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_FLOWBITS;
    sm->ctx = (void *)cd;

    SigMatchAppend(s,m,sm);

    if (dubbed) free(str);
    return 0;

error:
    if (dubbed) free(str);
    if (sm) free(sm);
    return -1;
}

void DetectFlowbitFree (void *ptr) {
    DetectFlowbitsData *fd = (DetectFlowbitsData *)ptr;

    if (fd == NULL)
        return;

    free(fd);
}

