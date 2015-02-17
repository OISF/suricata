/* Copyright (C) 2007-2010 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 *
 * FLOW part of the detection engine.
 */

#include "suricata-common.h"
#include "debug.h"
#include "decode.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"

#include "flow.h"
#include "flow-var.h"

#include "detect-flow.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-debug.h"

/**
 * \brief Regex for parsing our flow options
 */
#define PARSE_REGEX  "^\\s*([A-z_]+)\\s*(?:,\\s*([A-z_]+))?\\s*(?:,\\s*([A-z_]+))?\\s*$"

static pcre *parse_regex;
static pcre_extra *parse_regex_study;

int DetectFlowMatch (ThreadVars *, DetectEngineThreadCtx *, Packet *, Signature *, const SigMatchCtx *);
static int DetectFlowSetup (DetectEngineCtx *, Signature *, char *);
void DetectFlowRegisterTests(void);
void DetectFlowFree(void *);

/**
 * \brief Registration function for flow: keyword
 */
void DetectFlowRegister (void)
{
    sigmatch_table[DETECT_FLOW].name = "flow";
    sigmatch_table[DETECT_FLOW].desc = "match on direction and state of the flow";
    sigmatch_table[DETECT_FLOW].url = "https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Flow-keywords#Flow";
    sigmatch_table[DETECT_FLOW].Match = DetectFlowMatch;
    sigmatch_table[DETECT_FLOW].Setup = DetectFlowSetup;
    sigmatch_table[DETECT_FLOW].Free  = DetectFlowFree;
    sigmatch_table[DETECT_FLOW].RegisterTests = DetectFlowRegisterTests;

    const char *eb;
    int eo;
    int opts = 0;

    parse_regex = pcre_compile(PARSE_REGEX, opts, &eb, &eo, NULL);
    if(parse_regex == NULL)
    {
        SCLogError(SC_ERR_PCRE_COMPILE, "pcre compile of \"%s\" failed at offset %" PRId32 ": %s", PARSE_REGEX, eo, eb);
        goto error;
    }

    parse_regex_study = pcre_study(parse_regex, 0, &eb);
    if(eb != NULL)
    {
        SCLogError(SC_ERR_PCRE_STUDY, "pcre study failed: %s", eb);
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

/**
 * \brief This function is used to match flow flags set on a packet with those passed via flow:
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch that we will cast into DetectFlowData
 *
 * \retval 0 no match
 * \retval 1 match
 */
int DetectFlowMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx, Packet *p, Signature *s, const SigMatchCtx *ctx)
{
    SCEnter();

    SCLogDebug("pkt %p", p);

    if (p->flowflags & FLOW_PKT_TOSERVER) {
        SCLogDebug("FLOW_PKT_TOSERVER");
    } else if (p->flowflags & FLOW_PKT_TOCLIENT) {
        SCLogDebug("FLOW_PKT_TOCLIENT");
    }

    if (p->flowflags & FLOW_PKT_ESTABLISHED) {
        SCLogDebug("FLOW_PKT_ESTABLISHED");
    }

    uint8_t cnt = 0;
    const DetectFlowData *fd = (const DetectFlowData *)ctx;

    if ((fd->flags & DETECT_FLOW_FLAG_TOSERVER) && (p->flowflags & FLOW_PKT_TOSERVER)) {
        cnt++;
    } else if ((fd->flags & DETECT_FLOW_FLAG_TOCLIENT) && (p->flowflags & FLOW_PKT_TOCLIENT)) {
        cnt++;
    }

    if ((fd->flags & DETECT_FLOW_FLAG_ESTABLISHED) && (p->flowflags & FLOW_PKT_ESTABLISHED)) {
        cnt++;
    } else if (fd->flags & DETECT_FLOW_FLAG_STATELESS) {
        cnt++;
    }

    if (det_ctx->flags & DETECT_ENGINE_THREAD_CTX_STREAM_CONTENT_MATCH) {
        if (fd->flags & DETECT_FLOW_FLAG_ONLYSTREAM)
            cnt++;
    } else {
        if (fd->flags & DETECT_FLOW_FLAG_NOSTREAM)
            cnt++;
    }

    int ret = (fd->match_cnt == cnt) ? 1 : 0;
    SCLogDebug("returning %" PRId32 " cnt %" PRIu8 " fd->match_cnt %" PRId32 " fd->flags 0x%02X p->flowflags 0x%02X",
        ret, cnt, fd->match_cnt, fd->flags, p->flowflags);
    SCReturnInt(ret);
}

/**
 * \brief This function is used to parse flow options passed via flow: keyword
 *
 * \param flowstr Pointer to the user provided flow options
 *
 * \retval fd pointer to DetectFlowData on success
 * \retval NULL on failure
 */
DetectFlowData *DetectFlowParse (char *flowstr)
{
    DetectFlowData *fd = NULL;
    char *args[3] = {NULL,NULL,NULL};
#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];
    char str1[16] = "", str2[16] = "", str3[16] = "";

    ret = pcre_exec(parse_regex, parse_regex_study, flowstr, strlen(flowstr), 0, 0, ov, MAX_SUBSTRINGS);
    if (ret < 1 || ret > 4) {
        SCLogError(SC_ERR_PCRE_MATCH, "parse error, ret %" PRId32 ", string %s", ret, flowstr);
        goto error;
    }

    if (ret > 1) {
        res = pcre_copy_substring((char *)flowstr, ov, MAX_SUBSTRINGS, 1, str1, sizeof(str1));
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
            goto error;
        }
        args[0] = (char *)str1;

        if (ret > 2) {
            res = pcre_copy_substring((char *)flowstr, ov, MAX_SUBSTRINGS, 2, str2, sizeof(str2));
            if (res < 0) {
                SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
                goto error;
            }
            args[1] = (char *)str2;
        }
        if (ret > 3) {
            res = pcre_copy_substring((char *)flowstr, ov, MAX_SUBSTRINGS, 3, str3, sizeof(str3));
            if (res < 0) {
                SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
                goto error;
            }
            args[2] = (char *)str3;
        }
    }

    fd = SCMalloc(sizeof(DetectFlowData));
    if (unlikely(fd == NULL))
        goto error;
    fd->flags = 0;
    fd->match_cnt = 0;

    int i;
    for (i = 0; i < (ret - 1); i++) {
        if (args[i]) {
            /* inspect our options and set the flags */
            if (strcasecmp(args[i], "established") == 0) {
                if (fd->flags & DETECT_FLOW_FLAG_ESTABLISHED) {
                    SCLogError(SC_ERR_FLAGS_MODIFIER, "DETECT_FLOW_FLAG_ESTABLISHED flag is already set");
                    goto error;
                } else if (fd->flags & DETECT_FLOW_FLAG_STATELESS) {
                    SCLogError(SC_ERR_FLAGS_MODIFIER, "DETECT_FLOW_FLAG_STATELESS already set");
                    goto error;
                }
                fd->flags |= DETECT_FLOW_FLAG_ESTABLISHED;
            } else if (strcasecmp(args[i], "stateless") == 0) {
                if (fd->flags & DETECT_FLOW_FLAG_STATELESS) {
                    SCLogError(SC_ERR_FLAGS_MODIFIER, "DETECT_FLOW_FLAG_STATELESS flag is already set");
                    goto error;
                } else if (fd->flags & DETECT_FLOW_FLAG_ESTABLISHED) {
                    SCLogError(SC_ERR_FLAGS_MODIFIER, "cannot set DETECT_FLOW_FLAG_STATELESS, DETECT_FLOW_FLAG_ESTABLISHED already set");
                    goto error;
                }
                fd->flags |= DETECT_FLOW_FLAG_STATELESS;
            } else if (strcasecmp(args[i], "to_client") == 0 || strcasecmp(args[i], "from_server") == 0) {
                if (fd->flags & DETECT_FLOW_FLAG_TOCLIENT) {
                    SCLogError(SC_ERR_FLAGS_MODIFIER, "cannot set DETECT_FLOW_FLAG_TOCLIENT flag is already set");
                    goto error;
                } else if (fd->flags & DETECT_FLOW_FLAG_TOSERVER) {
                    SCLogError(SC_ERR_FLAGS_MODIFIER, "cannot set to_client, DETECT_FLOW_FLAG_TOSERVER already set");
                    goto error;
                }
                fd->flags |= DETECT_FLOW_FLAG_TOCLIENT;
            } else if (strcasecmp(args[i], "to_server") == 0 || strcasecmp(args[i], "from_client") == 0){
                if (fd->flags & DETECT_FLOW_FLAG_TOSERVER) {
                    SCLogError(SC_ERR_FLAGS_MODIFIER, "cannot set DETECT_FLOW_FLAG_TOSERVER flag is already set");
                    goto error;
                } else if (fd->flags & DETECT_FLOW_FLAG_TOCLIENT) {
                    SCLogError(SC_ERR_FLAGS_MODIFIER, "cannot set to_server, DETECT_FLOW_FLAG_TO_CLIENT flag already set");
                    goto error;
                }
                fd->flags |= DETECT_FLOW_FLAG_TOSERVER;
            } else if (strcasecmp(args[i], "only_stream") == 0) {
                if (fd->flags & DETECT_FLOW_FLAG_ONLYSTREAM) {
                    SCLogError(SC_ERR_FLAGS_MODIFIER, "cannot set only_stream flag is already set");
                    goto error;
                } else if (fd->flags & DETECT_FLOW_FLAG_NOSTREAM) {
                    SCLogError(SC_ERR_FLAGS_MODIFIER, "cannot set only_stream flag, DETECT_FLOW_FLAG_NOSTREAM already set");
                    goto error;
                }
                fd->flags |= DETECT_FLOW_FLAG_ONLYSTREAM;
            } else if (strcasecmp(args[i], "no_stream") == 0) {
                if (fd->flags & DETECT_FLOW_FLAG_NOSTREAM) {
                    SCLogError(SC_ERR_FLAGS_MODIFIER, "cannot set no_stream flag is already set");
                    goto error;
                } else if (fd->flags & DETECT_FLOW_FLAG_ONLYSTREAM) {
                    SCLogError(SC_ERR_FLAGS_MODIFIER, "cannot set no_stream flag, DETECT_FLOW_FLAG_ONLYSTREAM already set");
                    goto error;
                }
                fd->flags |= DETECT_FLOW_FLAG_NOSTREAM;
            } else {
                SCLogError(SC_ERR_INVALID_VALUE, "invalid flow option \"%s\"", args[i]);
                goto error;
            }

            fd->match_cnt++;
            //printf("args[%" PRId32 "]: %s match_cnt: %" PRId32 " flags: 0x%02X\n", i, args[i], fd->match_cnt, fd->flags);
        }
    }
    return fd;

error:
    if (fd != NULL)
        DetectFlowFree(fd);
    return NULL;

}

/**
 * \brief this function is used to add the parsed flowdata into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param flowstr pointer to the user provided flow options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
int DetectFlowSetup (DetectEngineCtx *de_ctx, Signature *s, char *flowstr)
{
    DetectFlowData *fd = NULL;
    SigMatch *sm = NULL;

    fd = DetectFlowParse(flowstr);
    if (fd == NULL)
        goto error;

    /*ensure only one flow option*/
    if (s->init_flags & SIG_FLAG_INIT_FLOW) {
        SCLogError (SC_ERR_INVALID_SIGNATURE, "A signature may have only one flow option.");
        goto error;
    }

    /* Okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_FLOW;
    sm->ctx = (SigMatchCtx *)fd;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);

    /* set the signature direction flags */
    if (fd->flags & DETECT_FLOW_FLAG_TOSERVER) {
        s->flags |= SIG_FLAG_TOSERVER;
    } else if (fd->flags & DETECT_FLOW_FLAG_TOCLIENT) {
        s->flags |= SIG_FLAG_TOCLIENT;
    } else {
        s->flags |= SIG_FLAG_TOSERVER;
        s->flags |= SIG_FLAG_TOCLIENT;
    }
    if (fd->flags & DETECT_FLOW_FLAG_ONLYSTREAM) {
        s->flags |= SIG_FLAG_REQUIRE_STREAM;
    }
    if (fd->flags & DETECT_FLOW_FLAG_NOSTREAM) {
        s->flags |= SIG_FLAG_REQUIRE_PACKET;
    } else {
        s->init_flags |= SIG_FLAG_INIT_FLOW;
    }

    return 0;

error:
    if (fd != NULL)
        DetectFlowFree(fd);
    if (sm != NULL)
        SCFree(sm);
    return -1;

}

/**
 * \brief this function will free memory associated with DetectFlowData
 *
 * \param fd pointer to DetectFlowData
 */
void DetectFlowFree(void *ptr)
{
    DetectFlowData *fd = (DetectFlowData *)ptr;
    SCFree(fd);
}

#ifdef UNITTESTS

/**
 * \test DetectFlowTestParse01 is a test to make sure that we return "something"
 *  when given valid flow opt
 */
int DetectFlowTestParse01 (void)
{
    int result = 0;
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse("established");
    if (fd != NULL) {
        DetectFlowFree(fd);
        result = 1;
    }

    return result;
}

/**
 * \test DetectFlowTestParse02 is a test for setting the established flow opt
 */
int DetectFlowTestParse02 (void)
{
    int result = 0;
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse("established");
    if (fd != NULL) {
        if (fd->flags == DETECT_FLOW_FLAG_ESTABLISHED && fd->match_cnt == 1) {
            result = 1;
        } else {
            printf("expected 0x%02X cnt %" PRId32 " got 0x%02X cnt %" PRId32 ": ", DETECT_FLOW_FLAG_ESTABLISHED, 1, fd->flags, fd->match_cnt);
        }
        DetectFlowFree(fd);
    }

    return result;
}

/**
 * \test DetectFlowTestParse03 is a test for setting the stateless flow opt
 */
int DetectFlowTestParse03 (void)
{
    int result = 0;
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse("stateless");
    if (fd != NULL) {
        if (fd->flags == DETECT_FLOW_FLAG_STATELESS && fd->match_cnt == 1) {
            result = 1;
        } else {
            printf("expected 0x%02X cnt %" PRId32 " got 0x%02X cnt %" PRId32 ": ", DETECT_FLOW_FLAG_STATELESS, 1, fd->flags, fd->match_cnt);
        }
        DetectFlowFree(fd);
    }

    return result;
}

/**
 * \test DetectFlowTestParse04 is a test for setting the to_client flow opt
 */
int DetectFlowTestParse04 (void)
{
    int result = 0;
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse("to_client");
    if (fd != NULL) {
        if (fd->flags == DETECT_FLOW_FLAG_TOCLIENT && fd->match_cnt == 1) {
            result = 1;
        } else {
            printf("expected 0x%02X cnt %" PRId32 " got 0x%02X cnt %" PRId32 ": ", DETECT_FLOW_FLAG_TOCLIENT, 1, fd->flags, fd->match_cnt);
        }
        DetectFlowFree(fd);
    }

    return result;
}

/**
 * \test DetectFlowTestParse05 is a test for setting the to_server flow opt
 */
int DetectFlowTestParse05 (void)
{
    int result = 0;
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse("to_server");
    if (fd != NULL) {
        if (fd->flags == DETECT_FLOW_FLAG_TOSERVER && fd->match_cnt == 1) {
            result = 1;
        } else {
            printf("expected 0x%02X cnt %" PRId32 " got 0x%02X cnt %" PRId32 ": ", DETECT_FLOW_FLAG_TOSERVER, 1, fd->flags, fd->match_cnt);
        }
        DetectFlowFree(fd);
    }

    return result;
}

/**
 * \test DetectFlowTestParse06 is a test for setting the from_server flow opt
 */
int DetectFlowTestParse06 (void)
{
    int result = 0;
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse("from_server");
    if (fd != NULL) {
        if (fd->flags == DETECT_FLOW_FLAG_TOCLIENT && fd->match_cnt == 1) {
            result = 1;
        } else {
            printf("expected 0x%02X cnt %" PRId32 " got 0x%02X cnt %" PRId32 ": ", DETECT_FLOW_FLAG_TOCLIENT, 1, fd->flags, fd->match_cnt);
        }
        DetectFlowFree(fd);
    }

    return result;
}

/**
 * \test DetectFlowTestParse07 is a test for setting the from_client flow opt
 */
int DetectFlowTestParse07 (void)
{
    int result = 0;
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse("from_client");
    if (fd != NULL) {
        if (fd->flags == DETECT_FLOW_FLAG_TOSERVER && fd->match_cnt == 1) {
            result = 1;
        } else {
            printf("expected 0x%02X cnt %" PRId32 " got 0x%02X cnt %" PRId32 ": ", DETECT_FLOW_FLAG_TOSERVER, 1, fd->flags, fd->match_cnt);
        }
        DetectFlowFree(fd);
    }

    return result;
}

/**
 * \test DetectFlowTestParse08 is a test for setting the established,to_client flow opts
 */
int DetectFlowTestParse08 (void)
{
    int result = 0;
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse("established,to_client");
    if (fd != NULL) {
        if (fd->flags & DETECT_FLOW_FLAG_ESTABLISHED && fd->flags & DETECT_FLOW_FLAG_TOCLIENT && fd->match_cnt == 2) {
            result = 1;
        } else {
            printf("expected: 0x%02X cnt %" PRId32 " got 0x%02X cnt %" PRId32 ": ", DETECT_FLOW_FLAG_ESTABLISHED + DETECT_FLOW_FLAG_TOCLIENT, 2, fd->flags, fd->match_cnt);
        }
        DetectFlowFree(fd);
    }

    return result;
}

/**
 * \test DetectFlowTestParse09 is a test for setting the to_client,stateless flow opts (order of state,dir reversed)
 */
int DetectFlowTestParse09 (void)
{
    int result = 0;
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse("to_client,stateless");
    if (fd != NULL) {
        if (fd->flags & DETECT_FLOW_FLAG_STATELESS && fd->flags & DETECT_FLOW_FLAG_TOCLIENT && fd->match_cnt == 2) {
            result = 1;
        } else {
            printf("expected: 0x%02X cnt %" PRId32 " got 0x%02X cnt %" PRId32 ": ", DETECT_FLOW_FLAG_STATELESS + DETECT_FLOW_FLAG_TOCLIENT, 2, fd->flags, fd->match_cnt);
        }
        DetectFlowFree(fd);
    }

    return result;
}

/**
 * \test DetectFlowTestParse10 is a test for setting the from_server,stateless flow opts (order of state,dir reversed)
 */
int DetectFlowTestParse10 (void)
{
    int result = 0;
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse("from_server,stateless");
    if (fd != NULL) {
        if (fd->flags & DETECT_FLOW_FLAG_STATELESS  && fd->flags & DETECT_FLOW_FLAG_TOCLIENT && fd->match_cnt == 2){
            result = 1;
        } else {
            printf("expected: 0x%02X cnt %" PRId32 " got 0x%02X cnt %" PRId32 ": ", DETECT_FLOW_FLAG_STATELESS + DETECT_FLOW_FLAG_TOCLIENT, 2, fd->flags, fd->match_cnt);
        }
        DetectFlowFree(fd);
    }

    return result;
}

/**
 * \test DetectFlowTestParse11 is a test for setting the from_server,stateless flow opts with spaces all around
 */
int DetectFlowTestParse11 (void)
{
    int result = 0;
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse(" from_server , stateless ");
    if (fd != NULL) {
        if (fd->flags & DETECT_FLOW_FLAG_STATELESS  && fd->flags & DETECT_FLOW_FLAG_TOCLIENT && fd->match_cnt == 2){
            result = 1;
        } else {
            printf("expected: 0x%02X cnt %" PRId32 " got 0x%02X cnt %" PRId32 ": ", DETECT_FLOW_FLAG_STATELESS + DETECT_FLOW_FLAG_TOCLIENT, 2, fd->flags, fd->match_cnt);
        }
        DetectFlowFree(fd);
    }

    return result;
}

/**
 * \test DetectFlowTestParseNocase01 is a test to make sure that we return "something"
 *  when given valid flow opt
 */
int DetectFlowTestParseNocase01 (void)
{
    int result = 0;
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse("ESTABLISHED");
    if (fd != NULL) {
        DetectFlowFree(fd);
        result = 1;
    }

    return result;
}

/**
 * \test DetectFlowTestParseNocase02 is a test for setting the established flow opt
 */
int DetectFlowTestParseNocase02 (void)
{
    int result = 0;
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse("ESTABLISHED");
    if (fd != NULL) {
        if (fd->flags == DETECT_FLOW_FLAG_ESTABLISHED && fd->match_cnt == 1) {
            result = 1;
        } else {
            printf("expected 0x%02X cnt %" PRId32 " got 0x%02X cnt %" PRId32 ": ", DETECT_FLOW_FLAG_ESTABLISHED, 1, fd->flags, fd->match_cnt);
        }
        DetectFlowFree(fd);
    }

    return result;
}

/**
 * \test DetectFlowTestParseNocase03 is a test for setting the stateless flow opt
 */
int DetectFlowTestParseNocase03 (void)
{
    int result = 0;
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse("STATELESS");
    if (fd != NULL) {
        if (fd->flags == DETECT_FLOW_FLAG_STATELESS && fd->match_cnt == 1) {
            result = 1;
        } else {
            printf("expected 0x%02X cnt %" PRId32 " got 0x%02X cnt %" PRId32 ": ", DETECT_FLOW_FLAG_STATELESS, 1, fd->flags, fd->match_cnt);
        }
        DetectFlowFree(fd);
    }

    return result;
}

/**
 * \test DetectFlowTestParseNocase04 is a test for setting the to_client flow opt
 */
int DetectFlowTestParseNocase04 (void)
{
    int result = 0;
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse("TO_CLIENT");
    if (fd != NULL) {
        if (fd->flags == DETECT_FLOW_FLAG_TOCLIENT && fd->match_cnt == 1) {
            result = 1;
        } else {
            printf("expected 0x%02X cnt %" PRId32 " got 0x%02X cnt %" PRId32 ": ", DETECT_FLOW_FLAG_TOCLIENT, 1, fd->flags, fd->match_cnt);
        }
        DetectFlowFree(fd);
    }

    return result;
}

/**
 * \test DetectFlowTestParseNocase05 is a test for setting the to_server flow opt
 */
int DetectFlowTestParseNocase05 (void)
{
    int result = 0;
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse("TO_SERVER");
    if (fd != NULL) {
        if (fd->flags == DETECT_FLOW_FLAG_TOSERVER && fd->match_cnt == 1) {
            result = 1;
        } else {
            printf("expected 0x%02X cnt %" PRId32 " got 0x%02X cnt %" PRId32 ": ", DETECT_FLOW_FLAG_TOSERVER, 1, fd->flags, fd->match_cnt);
        }
        DetectFlowFree(fd);
    }

    return result;
}

/**
 * \test DetectFlowTestParseNocase06 is a test for setting the from_server flow opt
 */
int DetectFlowTestParseNocase06 (void)
{
    int result = 0;
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse("FROM_SERVER");
    if (fd != NULL) {
        if (fd->flags == DETECT_FLOW_FLAG_TOCLIENT && fd->match_cnt == 1) {
            result = 1;
        } else {
            printf("expected 0x%02X cnt %" PRId32 " got 0x%02X cnt %" PRId32 ": ", DETECT_FLOW_FLAG_TOCLIENT, 1, fd->flags, fd->match_cnt);
        }
        DetectFlowFree(fd);
    }

    return result;
}

/**
 * \test DetectFlowTestParseNocase07 is a test for setting the from_client flow opt
 */
int DetectFlowTestParseNocase07 (void)
{
    int result = 0;
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse("FROM_CLIENT");
    if (fd != NULL) {
        if (fd->flags == DETECT_FLOW_FLAG_TOSERVER && fd->match_cnt == 1) {
            result = 1;
        } else {
            printf("expected 0x%02X cnt %" PRId32 " got 0x%02X cnt %" PRId32 ": ", DETECT_FLOW_FLAG_TOSERVER, 1, fd->flags, fd->match_cnt);
        }
        DetectFlowFree(fd);
    }

    return result;
}

/**
 * \test DetectFlowTestParseNocase08 is a test for setting the established,to_client flow opts
 */
int DetectFlowTestParseNocase08 (void)
{
    int result = 0;
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse("ESTABLISHED,TO_CLIENT");
    if (fd != NULL) {
        if (fd->flags & DETECT_FLOW_FLAG_ESTABLISHED && fd->flags & DETECT_FLOW_FLAG_TOCLIENT && fd->match_cnt == 2) {
            result = 1;
        } else {
            printf("expected: 0x%02X cnt %" PRId32 " got 0x%02X cnt %" PRId32 ": ", DETECT_FLOW_FLAG_ESTABLISHED + DETECT_FLOW_FLAG_TOCLIENT, 2, fd->flags, fd->match_cnt);
        }
        DetectFlowFree(fd);
    }

    return result;
}

/**
 * \test DetectFlowTestParseNocase09 is a test for setting the to_client,stateless flow opts (order of state,dir reversed)
 */
int DetectFlowTestParseNocase09 (void)
{
    int result = 0;
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse("TO_CLIENT,STATELESS");
    if (fd != NULL) {
        if (fd->flags & DETECT_FLOW_FLAG_STATELESS && fd->flags & DETECT_FLOW_FLAG_TOCLIENT && fd->match_cnt == 2) {
            result = 1;
        } else {
            printf("expected: 0x%02X cnt %" PRId32 " got 0x%02X cnt %" PRId32 ": ", DETECT_FLOW_FLAG_STATELESS + DETECT_FLOW_FLAG_TOCLIENT, 2, fd->flags, fd->match_cnt);
        }
        DetectFlowFree(fd);
    }

    return result;
}

/**
 * \test DetectFlowTestParseNocase10 is a test for setting the from_server,stateless flow opts (order of state,dir reversed)
 */
int DetectFlowTestParseNocase10 (void)
{
    int result = 0;
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse("FROM_SERVER,STATELESS");
    if (fd != NULL) {
        if (fd->flags & DETECT_FLOW_FLAG_STATELESS  && fd->flags & DETECT_FLOW_FLAG_TOCLIENT && fd->match_cnt == 2){
            result = 1;
        } else {
            printf("expected: 0x%02X cnt %" PRId32 " got 0x%02X cnt %" PRId32 ": ", DETECT_FLOW_FLAG_STATELESS + DETECT_FLOW_FLAG_TOCLIENT, 2, fd->flags, fd->match_cnt);
        }
        DetectFlowFree(fd);
    }

    return result;
}

/**
 * \test DetectFlowTestParseNocase11 is a test for setting the from_server,stateless flow opts with spaces all around
 */
int DetectFlowTestParseNocase11 (void)
{
    int result = 0;
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse(" FROM_SERVER , STATELESS ");
    if (fd != NULL) {
        if (fd->flags & DETECT_FLOW_FLAG_STATELESS  && fd->flags & DETECT_FLOW_FLAG_TOCLIENT && fd->match_cnt == 2){
            result = 1;
        } else {
            printf("expected: 0x%02X cnt %" PRId32 " got 0x%02X cnt %" PRId32 ": ", DETECT_FLOW_FLAG_STATELESS + DETECT_FLOW_FLAG_TOCLIENT, 2, fd->flags, fd->match_cnt);
        }
        DetectFlowFree(fd);
    }

    return result;
}


/**
 * \test DetectFlowTestParse12 is a test for setting an invalid seperator :
 */
int DetectFlowTestParse12 (void)
{
    int result = 1;
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse("from_server:stateless");
    if (fd != NULL) {
        printf("expected: NULL got 0x%02X %" PRId32 ": ",fd->flags, fd->match_cnt);
        result = 0;
        DetectFlowFree(fd);
    }

    return result;
}

/**
 * \test DetectFlowTestParse13 is a test for an invalid option
 */
int DetectFlowTestParse13 (void)
{
    int result = 1;
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse("invalidoptiontest");
    if (fd != NULL) {
        printf("expected: NULL got 0x%02X %" PRId32 ": ",fd->flags, fd->match_cnt);
        result = 0;
        DetectFlowFree(fd);
    }

    return result;
}
/**
 * \test DetectFlowTestParse14 is a test for a empty option
 */
int DetectFlowTestParse14 (void)
{
    int result = 1;
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse("");
    if (fd != NULL) {
        printf("expected: NULL got 0x%02X %" PRId32 ": ",fd->flags, fd->match_cnt);
        result = 0;
        DetectFlowFree(fd);
    }

    return result;
}

/**
 * \test DetectFlowTestParse15 is a test for an invalid combo of options established,stateless
 */
int DetectFlowTestParse15 (void)
{
    int result = 1;
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse("established,stateless");
    if (fd != NULL) {
        printf("expected: NULL got 0x%02X %" PRId32 ": ",fd->flags, fd->match_cnt);
        result = 0;
        DetectFlowFree(fd);
    }

    return result;
}

/**
 * \test DetectFlowTestParse16 is a test for an invalid combo of options to_client,to_server
 */
int DetectFlowTestParse16 (void)
{
    int result = 1;
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse("to_client,to_server");
    if (fd != NULL) {
        printf("expected: NULL got 0x%02X %" PRId32 ": ",fd->flags, fd->match_cnt);
        result = 0;
        DetectFlowFree(fd);
    }

    return result;
}

/**
 * \test DetectFlowTestParse16 is a test for an invalid combo of options to_client,from_server
 * flowbit flags are the same
 */
int DetectFlowTestParse17 (void)
{
    int result = 1;
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse("to_client,from_server");
    if (fd != NULL) {
        printf("expected: NULL got 0x%02X %" PRId32 ": ",fd->flags, fd->match_cnt);
        result = 0;
        DetectFlowFree(fd);
    }

    return result;
}

/**
 * \test DetectFlowTestParse18 is a test for setting the from_server,stateless,only_stream flow opts (order of state,dir reversed)
 */
int DetectFlowTestParse18 (void)
{
    int result = 0;
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse("from_server,established,only_stream");
    if (fd != NULL) {
        if (fd->flags & DETECT_FLOW_FLAG_ESTABLISHED && fd->flags & DETECT_FLOW_FLAG_TOCLIENT && fd->flags & DETECT_FLOW_FLAG_ONLYSTREAM && fd->match_cnt == 3) {
            result = 1;
        } else {
            printf("expected 0x%02X cnt %" PRId32 " got 0x%02X cnt %" PRId32 ": ", DETECT_FLOW_FLAG_ESTABLISHED + DETECT_FLOW_FLAG_TOCLIENT + DETECT_FLOW_FLAG_ONLYSTREAM, 3,
                    fd->flags, fd->match_cnt);
        }
        DetectFlowFree(fd);
    }

    return result;
}

/**
 * \test DetectFlowTestParseNocase18 is a test for setting the from_server,stateless,only_stream flow opts (order of state,dir reversed)
 */
int DetectFlowTestParseNocase18 (void)
{
    int result = 0;
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse("FROM_SERVER,ESTABLISHED,ONLY_STREAM");
    if (fd != NULL) {
        if (fd->flags & DETECT_FLOW_FLAG_ESTABLISHED && fd->flags & DETECT_FLOW_FLAG_TOCLIENT && fd->flags & DETECT_FLOW_FLAG_ONLYSTREAM && fd->match_cnt == 3) {
            result = 1;
        } else {
            printf("expected 0x%02X cnt %" PRId32 " got 0x%02X cnt %" PRId32 ": ", DETECT_FLOW_FLAG_ESTABLISHED + DETECT_FLOW_FLAG_TOCLIENT + DETECT_FLOW_FLAG_ONLYSTREAM, 3,
                    fd->flags, fd->match_cnt);
        }
        DetectFlowFree(fd);
    }

    return result;
}


/**
 * \test DetectFlowTestParse19 is a test for one to many options passed to DetectFlowParse
 */
int DetectFlowTestParse19 (void)
{
    int result = 1;
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse("from_server,established,only_stream,a");
    if (fd != NULL) {
        printf("expected: NULL got 0x%02X %" PRId32 ": ",fd->flags, fd->match_cnt);
        result = 0;
        DetectFlowFree(fd);
    }

    return result;
}

/**
 * \test DetectFlowTestParse20 is a test for setting from_server, established, no_stream
 */
int DetectFlowTestParse20 (void)
{
    int result = 0;
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse("from_server,established,no_stream");
    if (fd != NULL) {
        if (fd->flags & DETECT_FLOW_FLAG_ESTABLISHED && fd->flags & DETECT_FLOW_FLAG_TOCLIENT && fd->flags & DETECT_FLOW_FLAG_NOSTREAM && fd->match_cnt == 3) {
            result = 1;
        } else {
            printf("expected 0x%02X cnt %" PRId32 " got 0x%02X cnt %" PRId32 ": ", DETECT_FLOW_FLAG_ESTABLISHED + DETECT_FLOW_FLAG_TOCLIENT + DETECT_FLOW_FLAG_NOSTREAM, 3,
                    fd->flags, fd->match_cnt);
        }

        DetectFlowFree(fd);
    }

    return result;
}

/**
 * \test DetectFlowTestParse20 is a test for setting from_server, established, no_stream
 */
int DetectFlowTestParseNocase20 (void)
{
    int result = 0;
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse("FROM_SERVER,ESTABLISHED,NO_STREAM");
    if (fd != NULL) {
        if (fd->flags & DETECT_FLOW_FLAG_ESTABLISHED && fd->flags & DETECT_FLOW_FLAG_TOCLIENT && fd->flags & DETECT_FLOW_FLAG_NOSTREAM && fd->match_cnt == 3) {
            result = 1;
        } else {
            printf("expected 0x%02X cnt %" PRId32 " got 0x%02X cnt %" PRId32 ": ", DETECT_FLOW_FLAG_ESTABLISHED + DETECT_FLOW_FLAG_TOCLIENT + DETECT_FLOW_FLAG_NOSTREAM, 3,
                    fd->flags, fd->match_cnt);
        }

        DetectFlowFree(fd);
    }

    return result;
}

/**
 * \test DetectFlowTestParse21 is a test for an invalid opt between to valid opts
 */
int DetectFlowTestParse21 (void)
{
    int result = 1;
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse("from_server,a,no_stream");
    if (fd != NULL) {
        printf("expected: NULL got 0x%02X %" PRId32 ": ",fd->flags, fd->match_cnt);
        result = 0;
        DetectFlowFree(fd);
    }

    return result;
}

static int DetectFlowSigTest01(void)
{
    int result = 0;
    ThreadVars th_v;
    DecodeThreadVars dtv;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    uint8_t *buf = (uint8_t *)"supernovaduper";
    uint16_t buflen = strlen((char *)buf);

    Packet *p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);
    if (p->flow != NULL) {
        printf("packet has flow set\n");
        goto end;
    }

    char *sig1 = "alert tcp any any -> any any (msg:\"dummy\"; "
        "content:\"nova\"; flow:no_stream; sid:1;)";

    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&th_v, 0, sizeof(th_v));

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        printf("de_ctx == NULL: ");
        goto end;
    }
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, sig1);
    if (de_ctx->sig_list == NULL) {
        printf("signature == NULL: ");
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1) != 1) {
        goto end;
    }

    result = 1;

 end:
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);

    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

    if (p != NULL)
        UTHFreePacket(p);

    return result;
}
#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for DetectFlow
 */
void DetectFlowRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DetectFlowTestParse01", DetectFlowTestParse01, 1);
    UtRegisterTest("DetectFlowTestParse02", DetectFlowTestParse02, 1);
    UtRegisterTest("DetectFlowTestParse03", DetectFlowTestParse03, 1);
    UtRegisterTest("DetectFlowTestParse04", DetectFlowTestParse04, 1);
    UtRegisterTest("DetectFlowTestParse05", DetectFlowTestParse05, 1);
    UtRegisterTest("DetectFlowTestParse06", DetectFlowTestParse06, 1);
    UtRegisterTest("DetectFlowTestParse07", DetectFlowTestParse07, 1);
    UtRegisterTest("DetectFlowTestParse08", DetectFlowTestParse08, 1);
    UtRegisterTest("DetectFlowTestParse09", DetectFlowTestParse09, 1);
    UtRegisterTest("DetectFlowTestParse10", DetectFlowTestParse10, 1);
    UtRegisterTest("DetectFlowTestParse11", DetectFlowTestParse11, 1);
    UtRegisterTest("DetectFlowTestParseNocase01", DetectFlowTestParseNocase01, 1);
    UtRegisterTest("DetectFlowTestParseNocase02", DetectFlowTestParseNocase02, 1);
    UtRegisterTest("DetectFlowTestParseNocase03", DetectFlowTestParseNocase03, 1);
    UtRegisterTest("DetectFlowTestParseNocase04", DetectFlowTestParseNocase04, 1);
    UtRegisterTest("DetectFlowTestParseNocase05", DetectFlowTestParseNocase05, 1);
    UtRegisterTest("DetectFlowTestParseNocase06", DetectFlowTestParseNocase06, 1);
    UtRegisterTest("DetectFlowTestParseNocase07", DetectFlowTestParseNocase07, 1);
    UtRegisterTest("DetectFlowTestParseNocase08", DetectFlowTestParseNocase08, 1);
    UtRegisterTest("DetectFlowTestParseNocase09", DetectFlowTestParseNocase09, 1);
    UtRegisterTest("DetectFlowTestParseNocase10", DetectFlowTestParseNocase10, 1);
    UtRegisterTest("DetectFlowTestParseNocase11", DetectFlowTestParseNocase11, 1);
    UtRegisterTest("DetectFlowTestParse12", DetectFlowTestParse12, 1);
    UtRegisterTest("DetectFlowTestParse13", DetectFlowTestParse13, 1);
    UtRegisterTest("DetectFlowTestParse14", DetectFlowTestParse14, 1);
    UtRegisterTest("DetectFlowTestParse15", DetectFlowTestParse15, 1);
    UtRegisterTest("DetectFlowTestParse16", DetectFlowTestParse16, 1);
    UtRegisterTest("DetectFlowTestParse17", DetectFlowTestParse17, 1);
    UtRegisterTest("DetectFlowTestParse18", DetectFlowTestParse18, 1);
    UtRegisterTest("DetectFlowTestParseNocase18", DetectFlowTestParseNocase18, 1);
    UtRegisterTest("DetectFlowTestParse19", DetectFlowTestParse19, 1);
    UtRegisterTest("DetectFlowTestParse20", DetectFlowTestParse20, 1);
    UtRegisterTest("DetectFlowTestParseNocase20", DetectFlowTestParseNocase20, 1);
    UtRegisterTest("DetectFlowTestParse21", DetectFlowTestParse21, 1);

    UtRegisterTest("DetectFlowSigTest01", DetectFlowSigTest01, 1);
#endif /* UNITTESTS */
}
