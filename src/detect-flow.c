/* Copyright (C) 2007-2020 Open Information Security Foundation
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

#include "detect-parse.h"
#include "detect-engine-prefilter-common.h"

#include "detect-flow.h"

#ifdef UNITTESTS
#include "util-unittest-helper.h"
#include "util-unittest.h"
#include "detect-engine-build.h"
#include "detect-engine.h"
#endif
/**
 * \brief Regex for parsing our flow options
 */
#define PARSE_REGEX  "^\\s*([A-z_]+)\\s*(?:,\\s*([A-z_]+))?\\s*(?:,\\s*([A-z_]+))?\\s*$"

static DetectParseRegex parse_regex;

int DetectFlowMatch (DetectEngineThreadCtx *, Packet *,
        const Signature *, const SigMatchCtx *);
static int DetectFlowSetup (DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void DetectFlowRegisterTests(void);
#endif
void DetectFlowFree(DetectEngineCtx *, void *);

static int PrefilterSetupFlow(DetectEngineCtx *de_ctx, SigGroupHead *sgh);
static bool PrefilterFlowIsPrefilterable(const Signature *s);

/**
 * \brief Registration function for flow: keyword
 */
void DetectFlowRegister (void)
{
    sigmatch_table[DETECT_FLOW].name = "flow";
    sigmatch_table[DETECT_FLOW].desc = "match on direction and state of the flow";
    sigmatch_table[DETECT_FLOW].url = "/rules/flow-keywords.html#flow";
    sigmatch_table[DETECT_FLOW].Match = DetectFlowMatch;
    sigmatch_table[DETECT_FLOW].Setup = DetectFlowSetup;
    sigmatch_table[DETECT_FLOW].Free  = DetectFlowFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_FLOW].RegisterTests = DetectFlowRegisterTests;
#endif
    sigmatch_table[DETECT_FLOW].SupportsPrefilter = PrefilterFlowIsPrefilterable;
    sigmatch_table[DETECT_FLOW].SetupPrefilter = PrefilterSetupFlow;

    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex);
}

/**
 * \param pflags packet flags (p->flags)
 * \param pflowflags packet flow flags (p->flowflags)
 * \param tflags detection flags (det_ctx->flags)
 * \param dflags detect flow flags
 * \param match_cnt number of matches to trigger
 */
static inline int FlowMatch(const uint32_t pflags, const uint8_t pflowflags, const uint16_t tflags,
        const uint16_t dflags, const uint16_t match_cnt)
{
    uint8_t cnt = 0;

    if ((dflags & DETECT_FLOW_FLAG_NO_FRAG) &&
        (!(pflags & PKT_REBUILT_FRAGMENT))) {
        cnt++;
    } else if ((dflags & DETECT_FLOW_FLAG_ONLY_FRAG) &&
        (pflags & PKT_REBUILT_FRAGMENT)) {
        cnt++;
    }

    if ((dflags & DETECT_FLOW_FLAG_TOSERVER) && (pflowflags & FLOW_PKT_TOSERVER)) {
        cnt++;
    } else if ((dflags & DETECT_FLOW_FLAG_TOCLIENT) && (pflowflags & FLOW_PKT_TOCLIENT)) {
        cnt++;
    }

    if ((dflags & DETECT_FLOW_FLAG_ESTABLISHED) && (pflowflags & FLOW_PKT_ESTABLISHED)) {
        cnt++;
    } else if (dflags & DETECT_FLOW_FLAG_NOT_ESTABLISHED && (!(pflowflags & FLOW_PKT_ESTABLISHED))) {
        cnt++;
    } else if (dflags & DETECT_FLOW_FLAG_STATELESS) {
        cnt++;
    }

    if (tflags & DETECT_ENGINE_THREAD_CTX_STREAM_CONTENT_MATCH) {
        if (dflags & DETECT_FLOW_FLAG_ONLYSTREAM)
            cnt++;
    } else {
        if (dflags & DETECT_FLOW_FLAG_NOSTREAM)
            cnt++;
    }

    return (match_cnt == cnt) ? 1 : 0;
}

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
int DetectFlowMatch (DetectEngineThreadCtx *det_ctx, Packet *p,
        const Signature *s, const SigMatchCtx *ctx)
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

    const DetectFlowData *fd = (const DetectFlowData *)ctx;

    const int ret = FlowMatch(p->flags, p->flowflags, det_ctx->flags, fd->flags, fd->match_cnt);
    SCLogDebug("returning %" PRId32 " fd->match_cnt %" PRId32 " fd->flags 0x%02X p->flowflags 0x%02X",
        ret, fd->match_cnt, fd->flags, p->flowflags);
    SCReturnInt(ret);
}

/**
 * \brief This function is used to parse flow options passed via flow: keyword
 *
 * \param de_ctx Pointer to the detection engine context
 * \param flowstr Pointer to the user provided flow options
 *
 * \retval fd pointer to DetectFlowData on success
 * \retval NULL on failure
 */
static DetectFlowData *DetectFlowParse (DetectEngineCtx *de_ctx, const char *flowstr)
{
    DetectFlowData *fd = NULL;
    char *args[3] = {NULL,NULL,NULL};
    int ret = 0, res = 0;
    size_t pcre2len;
    char str1[16] = "", str2[16] = "", str3[16] = "";

    ret = DetectParsePcreExec(&parse_regex, flowstr, 0, 0);
    if (ret < 1 || ret > 4) {
        SCLogError(SC_ERR_PCRE_MATCH, "parse error, ret %" PRId32 ", string %s", ret, flowstr);
        goto error;
    }

    if (ret > 1) {
        pcre2len = sizeof(str1);
        res = SC_Pcre2SubstringCopy(parse_regex.match, 1, (PCRE2_UCHAR8 *)str1, &pcre2len);
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_copy_bynumber failed");
            goto error;
        }
        args[0] = (char *)str1;

        if (ret > 2) {
            pcre2len = sizeof(str2);
            res = pcre2_substring_copy_bynumber(
                    parse_regex.match, 2, (PCRE2_UCHAR8 *)str2, &pcre2len);
            if (res < 0) {
                SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_copy_bynumber failed");
                goto error;
            }
            args[1] = (char *)str2;
        }
        if (ret > 3) {
            pcre2len = sizeof(str3);
            res = pcre2_substring_copy_bynumber(
                    parse_regex.match, 3, (PCRE2_UCHAR8 *)str3, &pcre2len);
            if (res < 0) {
                SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_copy_bynumber failed");
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
            } else if (strcasecmp(args[i], "not_established") == 0) {
                if (fd->flags & DETECT_FLOW_FLAG_NOT_ESTABLISHED) {
                    SCLogError(SC_ERR_FLAGS_MODIFIER, "DETECT_FLOW_FLAG_NOT_ESTABLISHED flag is already set");
                    goto error;
                } else if (fd->flags & DETECT_FLOW_FLAG_NOT_ESTABLISHED) {
                    SCLogError(SC_ERR_FLAGS_MODIFIER, "cannot set DETECT_FLOW_FLAG_NOT_ESTABLISHED, DETECT_FLOW_FLAG_ESTABLISHED already set");
                    goto error;
                }
                fd->flags |= DETECT_FLOW_FLAG_NOT_ESTABLISHED;
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
            } else if (strcasecmp(args[i], "no_frag") == 0) {
                if (fd->flags & DETECT_FLOW_FLAG_NO_FRAG) {
                    SCLogError(SC_ERR_FLAGS_MODIFIER, "cannot set no_frag flag is already set");
                    goto error;
                } else if (fd->flags & DETECT_FLOW_FLAG_ONLY_FRAG) {
                    SCLogError(SC_ERR_FLAGS_MODIFIER, "cannot set no_frag flag, only_frag already set");
                    goto error;
                }
                fd->flags |= DETECT_FLOW_FLAG_NO_FRAG;
            } else if (strcasecmp(args[i], "only_frag") == 0) {
                if (fd->flags & DETECT_FLOW_FLAG_ONLY_FRAG) {
                    SCLogError(SC_ERR_FLAGS_MODIFIER, "cannot set only_frag flag is already set");
                    goto error;
                } else if (fd->flags & DETECT_FLOW_FLAG_NO_FRAG) {
                    SCLogError(SC_ERR_FLAGS_MODIFIER, "cannot set only_frag flag, no_frag already set");
                    goto error;
                }
                fd->flags |= DETECT_FLOW_FLAG_ONLY_FRAG;
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
        DetectFlowFree(de_ctx, fd);
    return NULL;

}

int DetectFlowSetupImplicit(Signature *s, uint32_t flags)
{
#define SIG_FLAG_BOTH (SIG_FLAG_TOSERVER|SIG_FLAG_TOCLIENT)
    BUG_ON(flags == 0);
    BUG_ON(flags & ~SIG_FLAG_BOTH);
    BUG_ON((flags & SIG_FLAG_BOTH) == SIG_FLAG_BOTH);

    SCLogDebug("want %08lx", flags & SIG_FLAG_BOTH);
    SCLogDebug("have %08lx", s->flags & SIG_FLAG_BOTH);

    if (flags & SIG_FLAG_TOSERVER) {
        if ((s->flags & SIG_FLAG_BOTH) == SIG_FLAG_BOTH) {
            /* both is set if we just have 'flow:established' */
            s->flags &= ~SIG_FLAG_TOCLIENT;
        } else if (s->flags & SIG_FLAG_TOCLIENT) {
            return -1;
        }
        s->flags |= SIG_FLAG_TOSERVER;
    } else {
        if ((s->flags & SIG_FLAG_BOTH) == SIG_FLAG_BOTH) {
            /* both is set if we just have 'flow:established' */
            s->flags &= ~SIG_FLAG_TOSERVER;
        } else if (s->flags & SIG_FLAG_TOSERVER) {
            return -1;
        }
        s->flags |= SIG_FLAG_TOCLIENT;
    }
    return 0;
#undef SIG_FLAG_BOTH
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
int DetectFlowSetup (DetectEngineCtx *de_ctx, Signature *s, const char *flowstr)
{
    /* ensure only one flow option */
    if (s->init_data->init_flags & SIG_FLAG_INIT_FLOW) {
        SCLogError (SC_ERR_INVALID_SIGNATURE, "A signature may have only one flow option.");
        return -1;
    }

    DetectFlowData *fd = DetectFlowParse(de_ctx, flowstr);
    if (fd == NULL)
        return -1;

    SigMatch *sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_FLOW;
    sm->ctx = (SigMatchCtx *)fd;

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
    } else if (fd->flags == DETECT_FLOW_FLAG_TOSERVER ||
               fd->flags == DETECT_FLOW_FLAG_TOCLIENT)
    {
        /* no direct flow is needed for just direction,
         * no sigmatch is needed either. */
        SigMatchFree(de_ctx, sm);
        sm = NULL;
    } else {
        s->init_data->init_flags |= SIG_FLAG_INIT_FLOW;
    }

    if (sm != NULL) {
        SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
    }
    return 0;

error:
    if (fd != NULL)
        DetectFlowFree(de_ctx, fd);
    return -1;

}

/**
 * \brief this function will free memory associated with DetectFlowData
 *
 * \param fd pointer to DetectFlowData
 */
void DetectFlowFree(DetectEngineCtx *de_ctx, void *ptr)
{
    DetectFlowData *fd = (DetectFlowData *)ptr;
    SCFree(fd);
}

static void
PrefilterPacketFlowMatch(DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx)
{
    const PrefilterPacketHeaderCtx *ctx = pectx;

    if (!PrefilterPacketHeaderExtraMatch(ctx, p))
        return;

    if (FlowMatch(p->flags, p->flowflags, det_ctx->flags, ctx->v1.u16[0], ctx->v1.u16[1])) {
        PrefilterAddSids(&det_ctx->pmq, ctx->sigs_array, ctx->sigs_cnt);
    }
}

static void
PrefilterPacketFlowSet(PrefilterPacketHeaderValue *v, void *smctx)
{
    const DetectFlowData *fb = smctx;
    v->u16[0] = fb->flags;
    v->u16[1] = fb->match_cnt;
}

static bool
PrefilterPacketFlowCompare(PrefilterPacketHeaderValue v, void *smctx)
{
    const DetectFlowData *fb = smctx;
    if (v.u16[0] == fb->flags && v.u16[1] == fb->match_cnt) {
        return true;
    }
    return false;
}

static int PrefilterSetupFlow(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    return PrefilterSetupPacketHeader(de_ctx, sgh, DETECT_FLOW,
        PrefilterPacketFlowSet,
        PrefilterPacketFlowCompare,
        PrefilterPacketFlowMatch);
}

static bool PrefilterFlowIsPrefilterable(const Signature *s)
{
    const SigMatch *sm;
    for (sm = s->init_data->smlists[DETECT_SM_LIST_MATCH] ; sm != NULL; sm = sm->next) {
        switch (sm->type) {
            case DETECT_FLOW:
                return true;
        }
    }
    return false;
}

#ifdef UNITTESTS

/**
 * \test DetectFlowTestParse01 is a test to make sure that we return "something"
 *  when given valid flow opt
 */
static int DetectFlowTestParse01 (void)
{
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse(NULL, "established");
    FAIL_IF_NULL(fd);
    DetectFlowFree(NULL, fd);
    PASS;
}

/**
 * \test DetectFlowTestParse02 is a test for setting the established flow opt
 */
static int DetectFlowTestParse02 (void)
{
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse(NULL, "established");
    FAIL_IF_NULL(fd);
    FAIL_IF_NOT(fd->flags == DETECT_FLOW_FLAG_ESTABLISHED &&
        fd->match_cnt == 1);
    PASS;
}

/**
 * \test DetectFlowTestParse03 is a test for setting the stateless flow opt
 */
static int DetectFlowTestParse03 (void)
{
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse(NULL, "stateless");
    FAIL_IF_NULL(fd);
    FAIL_IF_NOT(fd->flags == DETECT_FLOW_FLAG_STATELESS && fd->match_cnt == 1);
    DetectFlowFree(NULL, fd);
    PASS;
}

/**
 * \test DetectFlowTestParse04 is a test for setting the to_client flow opt
 */
static int DetectFlowTestParse04 (void)
{
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse(NULL, "to_client");
    FAIL_IF_NULL(fd);
    FAIL_IF_NOT(fd->flags == DETECT_FLOW_FLAG_TOCLIENT && fd->match_cnt == 1);
    DetectFlowFree(NULL, fd);
    PASS;
}

/**
 * \test DetectFlowTestParse05 is a test for setting the to_server flow opt
 */
static int DetectFlowTestParse05 (void)
{
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse(NULL, "to_server");
    FAIL_IF_NULL(fd);
    FAIL_IF_NOT(fd->flags == DETECT_FLOW_FLAG_TOSERVER && fd->match_cnt == 1);
    DetectFlowFree(NULL, fd);
    PASS;
}

/**
 * \test DetectFlowTestParse06 is a test for setting the from_server flow opt
 */
static int DetectFlowTestParse06 (void)
{
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse(NULL, "from_server");
    FAIL_IF_NULL(fd);
    FAIL_IF_NOT(fd->flags == DETECT_FLOW_FLAG_TOCLIENT && fd->match_cnt == 1);
    DetectFlowFree(NULL, fd);
    PASS;
}

/**
 * \test DetectFlowTestParse07 is a test for setting the from_client flow opt
 */
static int DetectFlowTestParse07 (void)
{
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse(NULL, "from_client");
    FAIL_IF_NULL(fd);
    FAIL_IF_NOT(fd->flags == DETECT_FLOW_FLAG_TOSERVER && fd->match_cnt == 1);
    DetectFlowFree(NULL, fd);
    PASS;
}

/**
 * \test DetectFlowTestParse08 is a test for setting the established,to_client flow opts
 */
static int DetectFlowTestParse08 (void)
{
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse(NULL, "established,to_client");
    FAIL_IF_NULL(fd);
    FAIL_IF_NOT(fd->flags & DETECT_FLOW_FLAG_ESTABLISHED && fd->flags & DETECT_FLOW_FLAG_TOCLIENT && fd->match_cnt == 2);
    DetectFlowFree(NULL, fd);
    PASS;
}

/**
 * \test DetectFlowTestParse09 is a test for setting the to_client,stateless flow opts (order of state,dir reversed)
 */
static int DetectFlowTestParse09 (void)
{
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse(NULL, "to_client,stateless");
    FAIL_IF_NULL(fd);
    FAIL_IF_NOT(fd->flags & DETECT_FLOW_FLAG_STATELESS &&
        fd->flags & DETECT_FLOW_FLAG_TOCLIENT &&
        fd->match_cnt == 2);
    DetectFlowFree(NULL, fd);
    PASS;
}

/**
 * \test DetectFlowTestParse10 is a test for setting the from_server,stateless flow opts (order of state,dir reversed)
 */
static int DetectFlowTestParse10 (void)
{
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse(NULL, "from_server,stateless");
    FAIL_IF_NULL(fd);
    FAIL_IF_NOT(fd->flags & DETECT_FLOW_FLAG_STATELESS &&
        fd->flags & DETECT_FLOW_FLAG_TOCLIENT &&
        fd->match_cnt == 2);
    DetectFlowFree(NULL, fd);
    PASS;
}

/**
 * \test DetectFlowTestParse11 is a test for setting the from_server,stateless flow opts with spaces all around
 */
static int DetectFlowTestParse11 (void)
{
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse(NULL, " from_server , stateless ");
    FAIL_IF_NULL(fd);
    FAIL_IF_NOT(fd->flags & DETECT_FLOW_FLAG_STATELESS &&
        fd->flags & DETECT_FLOW_FLAG_TOCLIENT &&
        fd->match_cnt == 2);
    DetectFlowFree(NULL, fd);
    PASS;
}

/**
 * \test DetectFlowTestParseNocase01 is a test to make sure that we return "something"
 *  when given valid flow opt
 */
static int DetectFlowTestParseNocase01 (void)
{
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse(NULL, "ESTABLISHED");
    FAIL_IF_NULL(fd);
    DetectFlowFree(NULL, fd);
    PASS;
}

/**
 * \test DetectFlowTestParseNocase02 is a test for setting the established flow opt
 */
static int DetectFlowTestParseNocase02 (void)
{
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse(NULL, "ESTABLISHED");
    FAIL_IF_NULL(fd);
    FAIL_IF_NOT(fd->flags == DETECT_FLOW_FLAG_ESTABLISHED &&
        fd->match_cnt == 1);
    DetectFlowFree(NULL, fd);
    PASS;
}

/**
 * \test DetectFlowTestParseNocase03 is a test for setting the stateless flow opt
 */
static int DetectFlowTestParseNocase03 (void)
{
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse(NULL, "STATELESS");
    FAIL_IF_NULL(fd);
    FAIL_IF_NOT(fd->flags == DETECT_FLOW_FLAG_STATELESS && fd->match_cnt == 1);         DetectFlowFree(NULL, fd);
    PASS;
}

/**
 * \test DetectFlowTestParseNocase04 is a test for setting the to_client flow opt
 */
static int DetectFlowTestParseNocase04 (void)
{
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse(NULL, "TO_CLIENT");
    FAIL_IF_NULL(fd);
    FAIL_IF_NOT(fd->flags == DETECT_FLOW_FLAG_TOCLIENT && fd->match_cnt == 1);
    DetectFlowFree(NULL, fd);
    PASS;
}

/**
 * \test DetectFlowTestParseNocase05 is a test for setting the to_server flow opt
 */
static int DetectFlowTestParseNocase05 (void)
{
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse(NULL, "TO_SERVER");
    FAIL_IF_NULL(fd);
    FAIL_IF_NOT(fd->flags == DETECT_FLOW_FLAG_TOSERVER && fd->match_cnt == 1);
    DetectFlowFree(NULL, fd);
    PASS;
}

/**
 * \test DetectFlowTestParseNocase06 is a test for setting the from_server flow opt
 */
static int DetectFlowTestParseNocase06 (void)
{
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse(NULL, "FROM_SERVER");
    FAIL_IF_NULL(fd);
    FAIL_IF_NOT(fd->flags == DETECT_FLOW_FLAG_TOCLIENT && fd->match_cnt == 1);
    DetectFlowFree(NULL, fd);
    PASS;
}

/**
 * \test DetectFlowTestParseNocase07 is a test for setting the from_client flow opt
 */
static int DetectFlowTestParseNocase07 (void)
{
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse(NULL, "FROM_CLIENT");
    FAIL_IF_NULL(fd);
    FAIL_IF_NOT(fd->flags == DETECT_FLOW_FLAG_TOSERVER && fd->match_cnt == 1);
    DetectFlowFree(NULL, fd);
    PASS;
}

/**
 * \test DetectFlowTestParseNocase08 is a test for setting the established,to_client flow opts
 */
static int DetectFlowTestParseNocase08 (void)
{
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse(NULL, "ESTABLISHED,TO_CLIENT");
    FAIL_IF_NULL(fd);
    FAIL_IF_NOT(fd->flags & DETECT_FLOW_FLAG_ESTABLISHED &&
        fd->flags & DETECT_FLOW_FLAG_TOCLIENT &&
        fd->match_cnt == 2);
    DetectFlowFree(NULL, fd);
    PASS;
}

/**
 * \test DetectFlowTestParseNocase09 is a test for setting the to_client,stateless flow opts (order of state,dir reversed)
 */
static int DetectFlowTestParseNocase09 (void)
{
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse(NULL, "TO_CLIENT,STATELESS");
    FAIL_IF_NULL(fd);
    FAIL_IF_NOT(fd->flags & DETECT_FLOW_FLAG_STATELESS &&
        fd->flags & DETECT_FLOW_FLAG_TOCLIENT &&
        fd->match_cnt == 2);
    DetectFlowFree(NULL, fd);
    PASS;
}

/**
 * \test DetectFlowTestParseNocase10 is a test for setting the from_server,stateless flow opts (order of state,dir reversed)
 */
static int DetectFlowTestParseNocase10 (void)
{
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse(NULL, "FROM_SERVER,STATELESS");
    FAIL_IF_NULL(fd);
    FAIL_IF_NOT(fd->flags & DETECT_FLOW_FLAG_STATELESS &&
        fd->flags & DETECT_FLOW_FLAG_TOCLIENT &&
        fd->match_cnt == 2);
    DetectFlowFree(NULL, fd);
    PASS;
}

/**
 * \test DetectFlowTestParseNocase11 is a test for setting the from_server,stateless flow opts with spaces all around
 */
static int DetectFlowTestParseNocase11 (void)
{
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse(NULL, " FROM_SERVER , STATELESS ");
    FAIL_IF_NULL(fd);
    FAIL_IF_NOT(fd->flags & DETECT_FLOW_FLAG_STATELESS &&
        fd->flags & DETECT_FLOW_FLAG_TOCLIENT &&
        fd->match_cnt == 2);
    DetectFlowFree(NULL, fd);
    PASS;
}

/**
 * \test DetectFlowTestParse12 is a test for setting an invalid seperator :
 */
static int DetectFlowTestParse12 (void)
{
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse(NULL, "from_server:stateless");
    FAIL_IF_NOT_NULL(fd);
    PASS;
}

/**
 * \test DetectFlowTestParse13 is a test for an invalid option
 */
static int DetectFlowTestParse13 (void)
{
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse(NULL, "invalidoptiontest");
    FAIL_IF_NOT_NULL(fd);
    PASS;
}

/**
 * \test DetectFlowTestParse14 is a test for a empty option
 */
static int DetectFlowTestParse14 (void)
{
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse(NULL, "");
    FAIL_IF_NOT_NULL(fd);
    PASS;
}

/**
 * \test DetectFlowTestParse15 is a test for an invalid combo of options established,stateless
 */
static int DetectFlowTestParse15 (void)
{
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse(NULL, "established,stateless");
    FAIL_IF_NOT_NULL(fd);
    PASS;
}

/**
 * \test DetectFlowTestParse16 is a test for an invalid combo of options to_client,to_server
 */
static int DetectFlowTestParse16 (void)
{
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse(NULL, "to_client,to_server");
    FAIL_IF_NOT_NULL(fd);
    PASS;
}

/**
 * \test DetectFlowTestParse16 is a test for an invalid combo of options to_client,from_server
 * flowbit flags are the same
 */
static int DetectFlowTestParse17 (void)
{
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse(NULL, "to_client,from_server");
    FAIL_IF_NOT_NULL(fd);
    PASS;
}

/**
 * \test DetectFlowTestParse18 is a test for setting the from_server,stateless,only_stream flow opts (order of state,dir reversed)
 */
static int DetectFlowTestParse18 (void)
{
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse(NULL, "from_server,established,only_stream");
    FAIL_IF_NULL(fd);
    FAIL_IF_NOT(fd->flags & DETECT_FLOW_FLAG_ESTABLISHED &&
        fd->flags & DETECT_FLOW_FLAG_TOCLIENT &&
        fd->flags & DETECT_FLOW_FLAG_ONLYSTREAM &&
        fd->match_cnt == 3);
    DetectFlowFree(NULL, fd);
    PASS;
}

/**
 * \test DetectFlowTestParseNocase18 is a test for setting the from_server,stateless,only_stream flow opts (order of state,dir reversed)
 */
static int DetectFlowTestParseNocase18 (void)
{
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse(NULL, "FROM_SERVER,ESTABLISHED,ONLY_STREAM");
    FAIL_IF_NULL(fd);
    FAIL_IF_NOT(fd->flags & DETECT_FLOW_FLAG_ESTABLISHED &&
        fd->flags & DETECT_FLOW_FLAG_TOCLIENT &&
        fd->flags & DETECT_FLOW_FLAG_ONLYSTREAM &&
        fd->match_cnt == 3);
    DetectFlowFree(NULL, fd);
    PASS;
}


/**
 * \test DetectFlowTestParse19 is a test for one to many options passed to DetectFlowParse
 */
static int DetectFlowTestParse19 (void)
{
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse(NULL, "from_server,established,only_stream,a");
    FAIL_IF_NOT_NULL(fd);
    PASS;
}

/**
 * \test DetectFlowTestParse20 is a test for setting from_server, established, no_stream
 */
static int DetectFlowTestParse20 (void)
{
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse(NULL, "from_server,established,no_stream");
    FAIL_IF_NULL(fd);
    FAIL_IF_NOT(fd->flags & DETECT_FLOW_FLAG_ESTABLISHED &&
        fd->flags & DETECT_FLOW_FLAG_TOCLIENT &&
        fd->flags & DETECT_FLOW_FLAG_NOSTREAM &&
        fd->match_cnt == 3);
    DetectFlowFree(NULL, fd);
    PASS;
}

/**
 * \test DetectFlowTestParse20 is a test for setting from_server, established, no_stream
 */
static int DetectFlowTestParseNocase20 (void)
{
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse(NULL, "FROM_SERVER,ESTABLISHED,NO_STREAM");
    FAIL_IF_NULL(fd);
    FAIL_IF_NOT(fd->flags & DETECT_FLOW_FLAG_ESTABLISHED &&
        fd->flags & DETECT_FLOW_FLAG_TOCLIENT &&
        fd->flags & DETECT_FLOW_FLAG_NOSTREAM &&
        fd->match_cnt == 3);
    DetectFlowFree(NULL, fd);
    PASS;
}

/**
 * \test DetectFlowTestParse21 is a test for an invalid opt between to valid opts
 */
static int DetectFlowTestParse21 (void)
{
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse(NULL, "from_server,a,no_stream");
    FAIL_IF_NOT_NULL(fd);
    PASS;
}

static int DetectFlowSigTest01(void)
{
    uint8_t *buf = (uint8_t *)"supernovaduper";
    uint16_t buflen = strlen((char *)buf);
    ThreadVars th_v;
    DecodeThreadVars dtv;
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&th_v, 0, sizeof(th_v));

    Packet *p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);
    FAIL_IF_NULL(p);

    const char *sig1 = "alert tcp any any -> any any (msg:\"dummy\"; "
        "content:\"nova\"; flow:no_stream; sid:1;)";

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, sig1);
    FAIL_IF_NULL(de_ctx->sig_list);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);
    FAIL_IF_NULL(det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(PacketAlertCheck(p, 1) != 1);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    UTHFreePacket(p);

    PASS;
}

/**
 * \test Test parsing of the not_established keyword.
 */
static int DetectFlowTestParseNotEstablished(void)
{
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse(NULL, "not_established");
    FAIL_IF_NULL(fd);
    FAIL_IF_NOT(fd->flags & DETECT_FLOW_FLAG_NOT_ESTABLISHED);
    DetectFlowFree(NULL, fd);
    PASS;
}

/**
 * \test Test parsing of the "no_frag" flow argument.
 */
static int DetectFlowTestParseNoFrag(void)
{
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse(NULL, "no_frag");
    FAIL_IF_NULL(fd);
    FAIL_IF_NOT(fd->flags & DETECT_FLOW_FLAG_NO_FRAG);
    DetectFlowFree(NULL, fd);
    PASS;
}

/**
 * \test Test parsing of the "only_frag" flow argument.
 */
static int DetectFlowTestParseOnlyFrag(void)
{
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse(NULL, "only_frag");
    FAIL_IF_NULL(fd);
    FAIL_IF_NOT(fd->flags & DETECT_FLOW_FLAG_ONLY_FRAG);
    DetectFlowFree(NULL, fd);
    PASS;
}

/**
 * \test Test that parsing of only_frag and no_frag together fails.
 */
static int DetectFlowTestParseNoFragOnlyFrag(void)
{
    DetectFlowData *fd = NULL;
    fd = DetectFlowParse(NULL, "no_frag,only_frag");
    FAIL_IF_NOT_NULL(fd);
    PASS;
}

/**
 * \test Test no_frag matching.
 */
static int DetectFlowTestNoFragMatch(void)
{
    uint32_t pflags = 0;
    DetectFlowData *fd = DetectFlowParse(NULL, "no_frag");
    FAIL_IF_NULL(fd);
    FAIL_IF_NOT(fd->flags & DETECT_FLOW_FLAG_NO_FRAG);
    FAIL_IF_NOT(fd->match_cnt == 1);
    FAIL_IF_NOT(FlowMatch(pflags, 0, 0, fd->flags, fd->match_cnt));
    pflags |= PKT_REBUILT_FRAGMENT;
    FAIL_IF(FlowMatch(pflags, 0, 0, fd->flags, fd->match_cnt));
    PASS;
}

/**
 * \test Test only_frag matching.
 */
static int DetectFlowTestOnlyFragMatch(void)
{
    uint32_t pflags = 0;
    DetectFlowData *fd = DetectFlowParse(NULL, "only_frag");
    FAIL_IF_NULL(fd);
    FAIL_IF_NOT(fd->flags & DETECT_FLOW_FLAG_ONLY_FRAG);
    FAIL_IF_NOT(fd->match_cnt == 1);
    FAIL_IF(FlowMatch(pflags, 0, 0, fd->flags, fd->match_cnt));
    pflags |= PKT_REBUILT_FRAGMENT;
    FAIL_IF_NOT(FlowMatch(pflags, 0, 0, fd->flags, fd->match_cnt));
    PASS;
}

/**
 * \brief this function registers unit tests for DetectFlow
 */
static void DetectFlowRegisterTests(void)
{
    UtRegisterTest("DetectFlowTestParse01", DetectFlowTestParse01);
    UtRegisterTest("DetectFlowTestParse02", DetectFlowTestParse02);
    UtRegisterTest("DetectFlowTestParse03", DetectFlowTestParse03);
    UtRegisterTest("DetectFlowTestParse04", DetectFlowTestParse04);
    UtRegisterTest("DetectFlowTestParse05", DetectFlowTestParse05);
    UtRegisterTest("DetectFlowTestParse06", DetectFlowTestParse06);
    UtRegisterTest("DetectFlowTestParse07", DetectFlowTestParse07);
    UtRegisterTest("DetectFlowTestParse08", DetectFlowTestParse08);
    UtRegisterTest("DetectFlowTestParse09", DetectFlowTestParse09);
    UtRegisterTest("DetectFlowTestParse10", DetectFlowTestParse10);
    UtRegisterTest("DetectFlowTestParse11", DetectFlowTestParse11);
    UtRegisterTest("DetectFlowTestParseNocase01", DetectFlowTestParseNocase01);
    UtRegisterTest("DetectFlowTestParseNocase02", DetectFlowTestParseNocase02);
    UtRegisterTest("DetectFlowTestParseNocase03", DetectFlowTestParseNocase03);
    UtRegisterTest("DetectFlowTestParseNocase04", DetectFlowTestParseNocase04);
    UtRegisterTest("DetectFlowTestParseNocase05", DetectFlowTestParseNocase05);
    UtRegisterTest("DetectFlowTestParseNocase06", DetectFlowTestParseNocase06);
    UtRegisterTest("DetectFlowTestParseNocase07", DetectFlowTestParseNocase07);
    UtRegisterTest("DetectFlowTestParseNocase08", DetectFlowTestParseNocase08);
    UtRegisterTest("DetectFlowTestParseNocase09", DetectFlowTestParseNocase09);
    UtRegisterTest("DetectFlowTestParseNocase10", DetectFlowTestParseNocase10);
    UtRegisterTest("DetectFlowTestParseNocase11", DetectFlowTestParseNocase11);
    UtRegisterTest("DetectFlowTestParse12", DetectFlowTestParse12);
    UtRegisterTest("DetectFlowTestParse13", DetectFlowTestParse13);
    UtRegisterTest("DetectFlowTestParse14", DetectFlowTestParse14);
    UtRegisterTest("DetectFlowTestParse15", DetectFlowTestParse15);
    UtRegisterTest("DetectFlowTestParse16", DetectFlowTestParse16);
    UtRegisterTest("DetectFlowTestParse17", DetectFlowTestParse17);
    UtRegisterTest("DetectFlowTestParse18", DetectFlowTestParse18);
    UtRegisterTest("DetectFlowTestParseNocase18", DetectFlowTestParseNocase18);
    UtRegisterTest("DetectFlowTestParse19", DetectFlowTestParse19);
    UtRegisterTest("DetectFlowTestParse20", DetectFlowTestParse20);
    UtRegisterTest("DetectFlowTestParseNocase20", DetectFlowTestParseNocase20);
    UtRegisterTest("DetectFlowTestParse21", DetectFlowTestParse21);
    UtRegisterTest("DetectFlowTestParseNotEstablished",
        DetectFlowTestParseNotEstablished);
    UtRegisterTest("DetectFlowTestParseNoFrag", DetectFlowTestParseNoFrag);
    UtRegisterTest("DetectFlowTestParseOnlyFrag",
        DetectFlowTestParseOnlyFrag);
    UtRegisterTest("DetectFlowTestParseNoFragOnlyFrag",
        DetectFlowTestParseNoFragOnlyFrag);
    UtRegisterTest("DetectFlowTestNoFragMatch", DetectFlowTestNoFragMatch);
    UtRegisterTest("DetectFlowTestOnlyFragMatch", DetectFlowTestOnlyFragMatch);

    UtRegisterTest("DetectFlowSigTest01", DetectFlowSigTest01);
}
#endif /* UNITTESTS */
