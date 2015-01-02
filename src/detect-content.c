/* Copyright (C) 2007-2014 Open Information Security Foundation
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
 * Simple content match part of the detection engine.
 */

#include "suricata-common.h"
#include "decode.h"
#include "detect.h"
#include "detect-content.h"
#include "detect-uricontent.h"
#include "detect-engine-mpm.h"
#include "detect-engine.h"
#include "detect-engine-state.h"
#include "detect-parse.h"
#include "util-mpm.h"
#include "flow.h"
#include "flow-util.h"
#include "flow-var.h"
#include "detect-flow.h"
#include "app-layer.h"
#include "util-unittest.h"
#include "util-print.h"
#include "util-debug.h"
#include "util-spm-bm.h"
#include "threads.h"
#include "util-unittest-helper.h"
#include "pkt-var.h"
#include "host.h"
#include "util-profiling.h"

int DetectContentMatch (ThreadVars *, DetectEngineThreadCtx *, Packet *, Signature *, SigMatch *);
int DetectContentSetup(DetectEngineCtx *, Signature *, char *);
void DetectContentRegisterTests(void);

void DetectContentRegister (void)
{
    sigmatch_table[DETECT_CONTENT].name = "content";
    sigmatch_table[DETECT_CONTENT].desc = "match on payload content";
    sigmatch_table[DETECT_CONTENT].url = "https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Payload_keywords#Content";
    sigmatch_table[DETECT_CONTENT].Match = NULL;
    sigmatch_table[DETECT_CONTENT].Setup = DetectContentSetup;
    sigmatch_table[DETECT_CONTENT].Free  = DetectContentFree;
    sigmatch_table[DETECT_CONTENT].RegisterTests = DetectContentRegisterTests;

    sigmatch_table[DETECT_CONTENT].flags |= SIGMATCH_PAYLOAD;
}

/* pass on the content_max_id */
uint32_t DetectContentMaxId(DetectEngineCtx *de_ctx)
{
    return MpmPatternIdStoreGetMaxId(de_ctx->mpm_pattern_id_store);
}

/**
 *  \brief Parse a content string, ie "abc|DE|fgh"
 *
 *  \param content_str null terminated string containing the content
 *  \param result result pointer to pass the fully parsed byte array
 *  \param result_len size of the resulted data
 *  \param flags flags to be set by this parsing function
 *
 *  \retval -1 error
 *  \retval 0 ok
 */
int DetectContentDataParse(const char *keyword, const char *contentstr,
        uint8_t **pstr, uint16_t *plen, uint32_t *flags)
{
    char *str = NULL;
    uint16_t len;
    uint16_t pos = 0;
    uint16_t slen = 0;

    slen = strlen(contentstr);
    if (slen == 0) {
        return -1;
    }

    /* skip the first spaces */
    while (pos < slen && isspace((unsigned char)contentstr[pos]))
        pos++;

    if (contentstr[pos] == '!') {
        *flags = DETECT_CONTENT_NEGATED;
        pos++;
    } else
        *flags = 0;

    if (contentstr[pos] == '\"' && ((slen - pos) <= 1))
        goto error;

    if (!(contentstr[pos] == '\"' && contentstr[slen - 1] == '\"')) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "%s keyword arguments "
                   "should be always enclosed in double quotes.  Invalid "
                   "content keyword passed in this rule - \"%s\"",
                   keyword, contentstr);
        goto error;
    }

    if ((str = SCStrdup(contentstr + pos + 1)) == NULL)
        goto error;
    str[strlen(str) - 1] = '\0';

    len = strlen(str);
    if (len == 0)
        goto error;

    SCLogDebug("\"%s\", len %" PRIu32 "", str, len);

    //SCLogDebug("DetectContentParse: \"%s\", len %" PRIu32 "", str, len);
    char converted = 0;

    {
        uint16_t i, x;
        uint8_t bin = 0;
        uint8_t escape = 0;
        uint8_t binstr[3] = "";
        uint8_t binpos = 0;
        uint16_t bin_count = 0;

        for (i = 0, x = 0; i < len; i++) {
            // SCLogDebug("str[%02u]: %c", i, str[i]);
            if (str[i] == '|') {
                bin_count++;
                if (bin) {
                    bin = 0;
                } else {
                    bin = 1;
                }
            } else if(!escape && str[i] == '\\') {
                escape = 1;
            } else {
                if (bin) {
                    if (isdigit((unsigned char)str[i]) ||
                            str[i] == 'A' || str[i] == 'a' ||
                            str[i] == 'B' || str[i] == 'b' ||
                            str[i] == 'C' || str[i] == 'c' ||
                            str[i] == 'D' || str[i] == 'd' ||
                            str[i] == 'E' || str[i] == 'e' ||
                            str[i] == 'F' || str[i] == 'f')
                    {
                        // SCLogDebug("part of binary: %c", str[i]);

                        binstr[binpos] = (char)str[i];
                        binpos++;

                        if (binpos == 2) {
                            uint8_t c = strtol((char *)binstr, (char **) NULL, 16) & 0xFF;
                            binpos = 0;
                            str[x] = c;
                            x++;
                            converted = 1;
                        }
                    } else if (str[i] == ' ') {
                        // SCLogDebug("space as part of binary string");
                    }
                    else if (str[i] != ',') {
                        SCLogError(SC_ERR_INVALID_SIGNATURE, "Invalid hex code in "
                                    "content - %s, hex %c. Invalidating signature", str, str[i]);
                        goto error;
                    }
                } else if (escape) {
                    if (str[i] == ':' ||
                        str[i] == ';' ||
                        str[i] == '\\' ||
                        str[i] == '\"')
                    {
                        str[x] = str[i];
                        x++;
                    } else {
                        //SCLogDebug("Can't escape %c", str[i]);
                        goto error;
                    }
                    escape = 0;
                    converted = 1;
                } else {
                    str[x] = str[i];
                    x++;
                }
            }
        }

        if (bin_count % 2 != 0) {
            SCLogError(SC_ERR_INVALID_SIGNATURE, "Invalid hex code assembly in "
                       "%s - %s.  Invalidating signature", keyword, contentstr);
            goto error;
        }

        if (converted) {
            len = x;
        }
    }

    *plen = len;
    *pstr = (uint8_t *)str;
    return 0;

error:
    if (str != NULL)
        SCFree(str);
    return -1;
}
/**
 * \brief DetectContentParse
 * \initonly
 */
DetectContentData *DetectContentParse (char *contentstr)
{
    DetectContentData *cd = NULL;
    uint8_t *content = NULL;
    uint16_t len = 0;
    uint32_t flags = 0;
    int ret;

    ret = DetectContentDataParse("content", contentstr, &content, &len, &flags);
    if (ret == -1) {
        return NULL;
    }

    cd = SCMalloc(sizeof(DetectContentData) + len);
    if (unlikely(cd == NULL)) {
        SCFree(content);
        exit(EXIT_FAILURE);
    }

    memset(cd, 0, sizeof(DetectContentData) + len);

    if (flags == DETECT_CONTENT_NEGATED)
        cd->flags |= DETECT_CONTENT_NEGATED;

    cd->content = (uint8_t *)cd + sizeof(DetectContentData);
    memcpy(cd->content, content, len);
    cd->content_len = len;

    /* Prepare Boyer Moore context for searching faster */
    cd->bm_ctx = BoyerMooreCtxInit(cd->content, cd->content_len);
    cd->depth = 0;
    cd->offset = 0;
    cd->within = 0;
    cd->distance = 0;

    SCFree(content);
    return cd;

}

DetectContentData *DetectContentParseEncloseQuotes(char *contentstr)
{
    char str[strlen(contentstr) + 3]; // 2 for quotes, 1 for \0

    str[0] = '\"';
    memcpy(str + 1, contentstr, strlen(contentstr));
    str[strlen(contentstr) + 1] = '\"';
    str[strlen(contentstr) + 2] = '\0';

    return DetectContentParse(str);
}

/**
 * \brief Helper function to print a DetectContentData
 */
void DetectContentPrint(DetectContentData *cd)
{
    int i = 0;
    if (cd == NULL) {
        SCLogDebug("DetectContentData \"cd\" is NULL");
        return;
    }
    char *tmpstr=SCMalloc(sizeof(char) * cd->content_len + 1);

    if (tmpstr != NULL) {
        for (i = 0; i < cd->content_len; i++) {
            if (isprint(cd->content[i]))
                tmpstr[i] = cd->content[i];
            else
                tmpstr[i] = '.';
        }
        tmpstr[i] = '\0';
        SCLogDebug("Content: \"%s\"", tmpstr);
        SCFree(tmpstr);
    } else {
        SCLogDebug("Content: ");
        for (i = 0; i < cd->content_len; i++)
            SCLogDebug("%c", cd->content[i]);
    }

    SCLogDebug("Content_id: %"PRIu32, cd->id);
    SCLogDebug("Content_len: %"PRIu16, cd->content_len);
    SCLogDebug("Depth: %"PRIu16, cd->depth);
    SCLogDebug("Offset: %"PRIu16, cd->offset);
    SCLogDebug("Within: %"PRIi32, cd->within);
    SCLogDebug("Distance: %"PRIi32, cd->distance);
    SCLogDebug("flags: %u ", cd->flags);
    SCLogDebug("negated: %s ", cd->flags & DETECT_CONTENT_NEGATED ? "true" : "false");
    SCLogDebug("relative match next: %s ", cd->flags & DETECT_CONTENT_RELATIVE_NEXT ? "true" : "false");
    if (cd->replace && cd->replace_len) {
        char *tmpstr=SCMalloc(sizeof(char) * cd->replace_len + 1);

        if (tmpstr != NULL) {
            for (i = 0; i < cd->replace_len; i++) {
                if (isprint(cd->replace[i]))
                    tmpstr[i] = cd->replace[i];
                else
                    tmpstr[i] = '.';
            }
            tmpstr[i] = '\0';
            SCLogDebug("Replace: \"%s\"", tmpstr);
            SCFree(tmpstr);
        } else {
            SCLogDebug("Replace: ");
            for (i = 0; i < cd->replace_len; i++)
                SCLogDebug("%c", cd->replace[i]);
        }
    }
    SCLogDebug("-----------");
}

/**
 * \brief Print list of DETECT_CONTENT SigMatch's allocated in a
 * SigMatch list, from the current sm to the end
 * \param sm pointer to the current SigMatch to start printing from
 */
void DetectContentPrintAll(SigMatch *sm)
{
#ifdef DEBUG
    if (SCLogDebugEnabled()) {
        int i = 0;

        if (sm == NULL)
            return;

        SigMatch *first_sm = sm;

       /* Print all of them */
        for (; first_sm != NULL; first_sm = first_sm->next) {
            if (first_sm->type == DETECT_CONTENT) {
                SCLogDebug("Printing SigMatch DETECT_CONTENT %d", ++i);
                DetectContentPrint((DetectContentData*)first_sm->ctx);
            }
        }
    }
#endif /* DEBUG */
}

/**
 * \brief Function to setup a content pattern.
 *
 * \param de_ctx pointer to the current detection_engine
 * \param s pointer to the current Signature
 * \param m pointer to the last parsed SigMatch
 * \param contentstr pointer to the current keyword content string
 * \retval -1 if error
 * \retval 0 if all was ok
 */
int DetectContentSetup(DetectEngineCtx *de_ctx, Signature *s, char *contentstr)
{
    DetectContentData *cd = NULL;
    SigMatch *sm = NULL;

    cd = DetectContentParse(contentstr);
    if (cd == NULL)
        goto error;
    DetectContentPrint(cd);

    int sm_list;
    if (s->list != DETECT_SM_LIST_NOTSET) {
        if (s->list == DETECT_SM_LIST_FILEDATA && s->alproto == ALPROTO_HTTP) {
            AppLayerHtpEnableResponseBodyCallback();
            s->alproto = ALPROTO_HTTP;
        }

        s->flags |= SIG_FLAG_APPLAYER;
        sm_list = s->list;
    } else {
        sm_list = DETECT_SM_LIST_PMATCH;
    }

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;
    sm->ctx = (void *)cd;
    sm->type = DETECT_CONTENT;
    SigMatchAppendSMToList(s, sm, sm_list);

    return 0;

error:
    DetectContentFree(cd);
    return -1;
}

/**
 * \brief this function will SCFree memory associated with DetectContentData
 *
 * \param cd pointer to DetectCotentData
 */
void DetectContentFree(void *ptr)
{
    SCEnter();
    DetectContentData *cd = (DetectContentData *)ptr;

    if (cd == NULL)
        SCReturn;

    BoyerMooreCtxDeInit(cd->bm_ctx);

    SCFree(cd);
    SCReturn;
}

#ifdef UNITTESTS /* UNITTESTS */

/**
 * \test DetectCotentParseTest01 this is a test to make sure we can deal with escaped colons
 */
int DetectContentParseTest01 (void)
{
    int result = 1;
    DetectContentData *cd = NULL;
    char *teststring = "\"abc\\:def\"";
    char *teststringparsed = "abc:def";

    cd = DetectContentParse(teststring);
    if (cd != NULL) {
        if (memcmp(cd->content, teststringparsed, strlen(teststringparsed)) != 0) {
            SCLogDebug("expected %s got ", teststringparsed);
            PrintRawUriFp(stdout,cd->content,cd->content_len);
            SCLogDebug(": ");
            result = 0;
            DetectContentFree(cd);
        }
    } else {
        SCLogDebug("expected %s got NULL: ", teststringparsed);
        result = 0;
    }
    return result;
}

/**
 * \test DetectCotentParseTest02 this is a test to make sure we can deal with escaped semi-colons
 */
int DetectContentParseTest02 (void)
{
    int result = 1;
    DetectContentData *cd = NULL;
    char *teststring = "\"abc\\;def\"";
    char *teststringparsed = "abc;def";

    cd = DetectContentParse(teststring);
    if (cd != NULL) {
        if (memcmp(cd->content, teststringparsed, strlen(teststringparsed)) != 0) {
            SCLogDebug("expected %s got ", teststringparsed);
            PrintRawUriFp(stdout,cd->content,cd->content_len);
            SCLogDebug(": ");
            result = 0;
            DetectContentFree(cd);
        }
    } else {
        SCLogDebug("expected %s got NULL: ", teststringparsed);
        result = 0;
    }
    return result;
}

/**
 * \test DetectCotentParseTest03 this is a test to make sure we can deal with escaped double-quotes
 */
int DetectContentParseTest03 (void)
{
    int result = 1;
    DetectContentData *cd = NULL;
    char *teststring = "\"abc\\\"def\"";
    char *teststringparsed = "abc\"def";

    cd = DetectContentParse(teststring);
    if (cd != NULL) {
        if (memcmp(cd->content, teststringparsed, strlen(teststringparsed)) != 0) {
            SCLogDebug("expected %s got ", teststringparsed);
            PrintRawUriFp(stdout,cd->content,cd->content_len);
            SCLogDebug(": ");
            result = 0;
            DetectContentFree(cd);
        }
    } else {
        SCLogDebug("expected %s got NULL: ", teststringparsed);
        result = 0;
    }
    return result;
}

/**
 * \test DetectCotentParseTest04 this is a test to make sure we can deal with escaped backslashes
 */
int DetectContentParseTest04 (void)
{
    int result = 1;
    DetectContentData *cd = NULL;
    char *teststring = "\"abc\\\\def\"";
    char *teststringparsed = "abc\\def";

    cd = DetectContentParse(teststring);
    if (cd != NULL) {
        uint16_t len = (cd->content_len > strlen(teststringparsed));
        if (memcmp(cd->content, teststringparsed, len) != 0) {
            SCLogDebug("expected %s got ", teststringparsed);
            PrintRawUriFp(stdout,cd->content,cd->content_len);
            SCLogDebug(": ");
            result = 0;
            DetectContentFree(cd);
        }
    } else {
        SCLogDebug("expected %s got NULL: ", teststringparsed);
        result = 0;
    }
    return result;
}

/**
 * \test DetectCotentParseTest05 test illegal escape
 */
int DetectContentParseTest05 (void)
{
    int result = 1;
    DetectContentData *cd = NULL;
    char *teststring = "\"abc\\def\"";

    cd = DetectContentParse(teststring);
    if (cd != NULL) {
        SCLogDebug("expected NULL got ");
        PrintRawUriFp(stdout,cd->content,cd->content_len);
        SCLogDebug(": ");
        result = 0;
        DetectContentFree(cd);
    }
    return result;
}

/**
 * \test DetectCotentParseTest06 test a binary content
 */
int DetectContentParseTest06 (void)
{
    int result = 1;
    DetectContentData *cd = NULL;
    char *teststring = "\"a|42|c|44|e|46|\"";
    char *teststringparsed = "abcdef";

    cd = DetectContentParse(teststring);
    if (cd != NULL) {
        uint16_t len = (cd->content_len > strlen(teststringparsed));
        if (memcmp(cd->content, teststringparsed, len) != 0) {
            SCLogDebug("expected %s got ", teststringparsed);
            PrintRawUriFp(stdout,cd->content,cd->content_len);
            SCLogDebug(": ");
            result = 0;
            DetectContentFree(cd);
        }
    } else {
        SCLogDebug("expected %s got NULL: ", teststringparsed);
        result = 0;
    }
    return result;
}

/**
 * \test DetectCotentParseTest07 test an empty content
 */
int DetectContentParseTest07 (void)
{
    int result = 1;
    DetectContentData *cd = NULL;
    char *teststring = "\"\"";

    cd = DetectContentParse(teststring);
    if (cd != NULL) {
        SCLogDebug("expected NULL got %p: ", cd);
        result = 0;
        DetectContentFree(cd);
    }
    return result;
}

/**
 * \test DetectCotentParseTest08 test an empty content
 */
int DetectContentParseTest08 (void)
{
    int result = 1;
    DetectContentData *cd = NULL;
    char *teststring = "\"\"";

    cd = DetectContentParse(teststring);
    if (cd != NULL) {
        SCLogDebug("expected NULL got %p: ", cd);
        result = 0;
        DetectContentFree(cd);
    }
    return result;
}

/**
 * \test Test packet Matches
 * \param raw_eth_pkt pointer to the ethernet packet
 * \param pktsize size of the packet
 * \param sig pointer to the signature to test
 * \param sid sid number of the signature
 * \retval return 1 if match
 * \retval return 0 if not
 */
int DetectContentLongPatternMatchTest(uint8_t *raw_eth_pkt, uint16_t pktsize, char *sig,
                      uint32_t sid)
{
    int result = 0;

    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    DecodeThreadVars dtv;

    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;

    memset(p, 0, SIZE_OF_PACKET);
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&th_v, 0, sizeof(th_v));

    FlowInitConfig(FLOW_QUIET);
    DecodeEthernet(&th_v, &dtv, p, raw_eth_pkt, pktsize, NULL);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, sig);
    if (de_ctx->sig_list == NULL) {
        goto end;
    }
    de_ctx->sig_list->next = NULL;

    if (de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->type == DETECT_CONTENT) {
        DetectContentData *co = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->ctx;
        if (co->flags & DETECT_CONTENT_RELATIVE_NEXT) {
            printf("relative next flag set on final match which is content: ");
            goto end;
        }
    }

    SCLogDebug("---DetectContentLongPatternMatchTest---");
    DetectContentPrintAll(de_ctx->sig_list->sm_lists[DETECT_SM_LIST_MATCH]);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, sid) != 1) {
        goto end;
    }

    result = 1;
end:
    if (de_ctx != NULL)
    {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
        if (det_ctx != NULL)
            DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
        DetectEngineCtxFree(de_ctx);
    }
    PACKET_RECYCLE(p);
    FlowShutdown();

    SCFree(p);
    return result;
}

/**
 * \brief Wrapper for DetectContentLongPatternMatchTest
 */
int DetectContentLongPatternMatchTestWrp(char *sig, uint32_t sid)
{
    /** Real packet with the following tcp data:
     * "Hi, this is a big test to check content matches of splitted"
     * "patterns between multiple chunks!"
     * (without quotes! :) )
     */
    uint8_t raw_eth_pkt[] = {
        0xff,0xff,0xff,0xff,0xff,0xff,0x00,0x00,
        0x00,0x00,0x00,0x00,0x08,0x00,0x45,0x00,
        0x00,0x85,0x00,0x01,0x00,0x00,0x40,0x06,
        0x7c,0x70,0x7f,0x00,0x00,0x01,0x7f,0x00,
        0x00,0x01,0x00,0x14,0x00,0x50,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x50,0x02,
        0x20,0x00,0xc9,0xad,0x00,0x00,0x48,0x69,
        0x2c,0x20,0x74,0x68,0x69,0x73,0x20,0x69,
        0x73,0x20,0x61,0x20,0x62,0x69,0x67,0x20,
        0x74,0x65,0x73,0x74,0x20,0x74,0x6f,0x20,
        0x63,0x68,0x65,0x63,0x6b,0x20,0x63,0x6f,
        0x6e,0x74,0x65,0x6e,0x74,0x20,0x6d,0x61,
        0x74,0x63,0x68,0x65,0x73,0x20,0x6f,0x66,
        0x20,0x73,0x70,0x6c,0x69,0x74,0x74,0x65,
        0x64,0x20,0x70,0x61,0x74,0x74,0x65,0x72,
        0x6e,0x73,0x20,0x62,0x65,0x74,0x77,0x65,
        0x65,0x6e,0x20,0x6d,0x75,0x6c,0x74,0x69,
        0x70,0x6c,0x65,0x20,0x63,0x68,0x75,0x6e,
        0x6b,0x73,0x21 }; /* end raw_eth_pkt */

    return DetectContentLongPatternMatchTest(raw_eth_pkt, (uint16_t)sizeof(raw_eth_pkt),
                             sig, sid);
}

/**
 * \test Check if we match a normal pattern (not splitted)
 */
int DetectContentLongPatternMatchTest01()
{
    char *sig = "alert tcp any any -> any any (msg:\"Nothing..\";"
                " content:\"Hi, this is a big test\"; sid:1;)";
    return DetectContentLongPatternMatchTestWrp(sig, 1);
}

/**
 * \test Check if we match a splitted pattern
 */
int DetectContentLongPatternMatchTest02()
{
    char *sig = "alert tcp any any -> any any (msg:\"Nothing..\";"
                " content:\"Hi, this is a big test to check content matches of"
                " splitted patterns between multiple chunks!\"; sid:1;)";
    return DetectContentLongPatternMatchTestWrp(sig, 1);
}

/**
 * \test Check that we don't match the signature if one of the splitted
 * chunks doesn't match the packet
 */
int DetectContentLongPatternMatchTest03()
{
    /** The last chunk of the content should not match */
    char *sig = "alert tcp any any -> any any (msg:\"Nothing..\";"
                " content:\"Hi, this is a big test to check content matches of"
                " splitted patterns between multiple splitted chunks!\"; sid:1;)";
    return (DetectContentLongPatternMatchTestWrp(sig, 1) == 0) ? 1: 0;
}

/**
 * \test Check if we match multiple content (not splitted)
 */
int DetectContentLongPatternMatchTest04()
{
    char *sig = "alert tcp any any -> any any (msg:\"Nothing..\"; "
                " content:\"Hi, this is\"; depth:15 ;content:\"a big test\"; "
                " within:15; content:\"to check content matches of\"; "
                " within:30; content:\"splitted patterns\"; distance:1; "
                " within:30; "
                " sid:1;)";
    return DetectContentLongPatternMatchTestWrp(sig, 1);
}

/**
 * \test Check that we match packets with multiple chunks and not chunks
 * Here we should specify only contents that fit in 32 bytes
 * Each of them with their modifier values
 */
int DetectContentLongPatternMatchTest05()
{
    char *sig = "alert tcp any any -> any any (msg:\"Nothing..\"; "
                " content:\"Hi, this is a big\"; depth:17; "
                " isdataat:30, relative; "
                " content:\"test\"; within: 5; distance:1; "
                " isdataat:15, relative; "
                " content:\"of splitted\"; within:37; distance:15; "
                " isdataat:20,relative; "
                " content:\"patterns\"; within:9; distance:1; "
                " isdataat:10, relative; "
                " sid:1;)";
    return DetectContentLongPatternMatchTestWrp(sig, 1);
}

/**
 * \test Check that we match packets with multiple chunks and not chunks
 * Here we should specify contents that fit and contents that must be splitted
 * Each of them with their modifier values
 */
int DetectContentLongPatternMatchTest06()
{
    char *sig = "alert tcp any any -> any any (msg:\"Nothing..\"; "
                " content:\"Hi, this is a big test to check cont\"; depth:36;"
                " content:\"ent matches\"; within:11; distance:0; "
                " content:\"of splitted patterns between multiple\"; "
                " within:38; distance:1; "
                " content:\"chunks!\"; within: 8; distance:1; "
                " sid:1;)";
    return DetectContentLongPatternMatchTestWrp(sig, 1);
}

/**
 * \test Check if we match contents that are in the payload
 * but not in the same order as specified in the signature
 */
int DetectContentLongPatternMatchTest07()
{
    char *sig = "alert tcp any any -> any any (msg:\"Nothing..\"; "
                " content:\"chunks!\"; "
                " content:\"content matches\"; offset:32; depth:47; "
                " content:\"of splitted patterns between multiple\"; "
                " content:\"Hi, this is a big\"; offset:0; depth:17; "
                " sid:1;)";
    return DetectContentLongPatternMatchTestWrp(sig, 1);
}

/**
 * \test Check if we match contents that are in the payload
 * but not in the same order as specified in the signature
 */
int DetectContentLongPatternMatchTest08()
{
    char *sig = "alert tcp any any -> any any (msg:\"Nothing..\"; "
                " content:\"ent matches\"; "
                " content:\"of splitted patterns between multiple\"; "
                " within:38; distance:1; "
                " content:\"chunks!\"; within: 8; distance:1; "
                " content:\"Hi, this is a big test to check cont\"; depth:36;"
                " sid:1;)";
    return DetectContentLongPatternMatchTestWrp(sig, 1);
}

/**
 * \test Check if we match contents that are in the payload
 * but not in the same order as specified in the signature
 */
int DetectContentLongPatternMatchTest09()
{
    char *sig = "alert tcp any any -> any any (msg:\"Nothing..\"; "
                " content:\"ent matches\"; "
                " content:\"of splitted patterns between multiple\"; "
                " offset:47; depth:85; "
                " content:\"chunks!\"; within: 8; distance:1; "
                " content:\"Hi, this is a big test to chec\"; depth:36;"
                " content:\"k cont\"; distance:0; within:6;"
                " sid:1;)";
    return DetectContentLongPatternMatchTestWrp(sig, 1);
}

/**
 * \test Check if we match two consecutive simple contents
 */
int DetectContentLongPatternMatchTest10()
{
    char *sig = "alert tcp any any -> any any (msg:\"Nothing..\"; "
                " content:\"Hi, this is a big test to check \"; "
                " content:\"con\"; "
                " sid:1;)";
    return DetectContentLongPatternMatchTestWrp(sig, 1);
}

/**
 * \test Check if we match two contents of length 1
 */
int DetectContentLongPatternMatchTest11()
{
    char *sig = "alert tcp any any -> any any (msg:\"Nothing..\"; "
                " content:\"H\"; "
                " content:\"i\"; "
                " sid:1;)";
    return DetectContentLongPatternMatchTestWrp(sig, 1);
}

int DetectContentParseTest09(void)
{
    int result = 0;
    DetectContentData *cd = NULL;
    char *teststring = "!\"boo\"";

    cd = DetectContentParse(teststring);
    if (cd != NULL) {
        if (cd->flags & DETECT_CONTENT_NEGATED)
            result = 1;

        DetectContentFree(cd);
    }

    return result;
}

int DetectContentParseTest10(void)
{
    int result = 0;
    DetectContentData *cd = NULL;
    char *teststring = "!\"boo\"";

    cd = DetectContentParse(teststring);
    if (cd != NULL) {
        if (cd->flags & DETECT_CONTENT_NEGATED)
            result = 1;

        DetectContentFree(cd);
    }
    return result;
}

int DetectContentParseNegTest11(void)
{
    int result = 0;
    DetectContentData *cd = NULL;
    char *teststring = "\"boo\"";

    cd = DetectContentParse(teststring);
    if (cd != NULL) {
        if (!(cd->flags & DETECT_CONTENT_NEGATED))
            result = 1;

        DetectContentFree(cd);
    }
    return result;
}

int DetectContentParseNegTest12(void)
{
    int result = 0;
    DetectContentData *cd = NULL;
    char *teststring = "\"boo\"";

    cd = DetectContentParse(teststring);
    if (cd != NULL) {
        if (!(cd->flags & DETECT_CONTENT_NEGATED))
            result = 1;

        DetectContentFree(cd);
    }
    return result;
}

int DetectContentParseNegTest13(void)
{
    int result = 0;
    DetectContentData *cd = NULL;
    char *teststring = "!\"boo\"";

    cd = DetectContentParse(teststring);
    if (cd != NULL) {
        if (cd->flags & DETECT_CONTENT_NEGATED)
            result = 1;

        DetectContentFree(cd);
    }
    return result;
}

int DetectContentParseNegTest14(void)
{
    int result = 0;
    DetectContentData *cd = NULL;
    char *teststring = "  \"!boo\"";

    cd = DetectContentParse(teststring);
    if (cd != NULL) {
        if (!(cd->flags & DETECT_CONTENT_NEGATED))
            result = 1;

        DetectContentFree(cd);
    }
    return result;
}

int DetectContentParseNegTest15(void)
{
    int result = 0;
    DetectContentData *cd = NULL;
    char *teststring = "  !\"boo\"";

    cd = DetectContentParse(teststring);
    if (cd != NULL) {
        if (cd->flags & DETECT_CONTENT_NEGATED)
            result = 1;

        DetectContentFree(cd);
    }
    return result;
}

int DetectContentParseNegTest16(void)
{
    int result = 0;
    DetectContentData *cd = NULL;
    char *teststring = "  \"boo\"";

    cd = DetectContentParse(teststring);
    if (cd != NULL) {
        result = (cd->content_len == 3 && memcmp(cd->content,"boo",3) == 0);
        DetectContentFree(cd);
    }
    return result;
}

/**
 * \test Test cases where if within specified is < content lenggth we invalidate
 *       the sig.
 */
int DetectContentParseTest17(void)
{
    int result = 0;
    char *sigstr = "alert tcp any any -> any any (msg:\"Dummy\"; "
        "content:\"one\"; content:\"two\"; within:2; sid:1;)";

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->sig_list = SigInit(de_ctx, sigstr);
    if (de_ctx->sig_list != NULL)
        goto end;

    result = 1;

end:
    SigCleanSignatures(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Test content for dce sig.
 */
int DetectContentParseTest18(void)
{
    Signature *s = SigAlloc();
    int result = 1;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        result = 0;
        goto end;
    }

    s->alproto = ALPROTO_DCERPC;

    result &= (DetectContentSetup(de_ctx, s, "\"one\"") == 0);
    result &= (s->sm_lists[DETECT_SM_LIST_DMATCH] == NULL && s->sm_lists[DETECT_SM_LIST_PMATCH] != NULL);

    SigFree(s);

    s = SigAlloc();
    if (s == NULL)
        return 0;

    result &= (DetectContentSetup(de_ctx, s, "\"one\"") == 0);
    result &= (s->sm_lists[DETECT_SM_LIST_DMATCH] == NULL && s->sm_lists[DETECT_SM_LIST_PMATCH] != NULL);

 end:
    SigFree(s);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Test content for dce sig.
 */

int DetectContentParseTest19(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 1;
    Signature *s = NULL;
    DetectContentData *data = NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"Testing dce iface, stub_data with content\"; "
                               "dce_iface:3919286a-b10c-11d0-9ba8-00c04fd92ef5; "
                               "dce_stub_data; "
                               "content:\"one\"; distance:0; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf ("failed dce iface, stub_data with content ");
        result = 0;
        goto end;
    }
    s = de_ctx->sig_list;
    if (s->sm_lists_tail[DETECT_SM_LIST_DMATCH] == NULL) {
        result = 0;
        goto end;
    }
    result &= (s->sm_lists_tail[DETECT_SM_LIST_DMATCH]->type == DETECT_CONTENT);
    result &= (s->sm_lists[DETECT_SM_LIST_PMATCH] == NULL);
    data = (DetectContentData *)s->sm_lists_tail[DETECT_SM_LIST_DMATCH]->ctx;
    if (data->flags & DETECT_CONTENT_RAWBYTES ||
        data->flags & DETECT_CONTENT_NOCASE ||
        data->flags & DETECT_CONTENT_WITHIN ||
        !(data->flags & DETECT_CONTENT_DISTANCE) ||
        data->flags & DETECT_CONTENT_FAST_PATTERN ||
        data->flags & DETECT_CONTENT_NEGATED ||
        result == 0) {
        result = 0;
        goto end;
    }

    s->next = SigInit(de_ctx, "alert tcp any any -> any any "
                      "(msg:\"Testing dce iface, stub_data with contents & distance, within\"; "
                      "dce_iface:3919286a-b10c-11d0-9ba8-00c04fd92ef5; "
                      "dce_stub_data; "
                      "content:\"one\"; distance:0; content:\"two\"; within:10; sid:1;)");
    if (s->next == NULL) {
        printf("failed dce iface, stub_data with content & distance, within");
        result = 0;
        goto end;
    }
    s = s->next;
    if (s->sm_lists_tail[DETECT_SM_LIST_DMATCH] == NULL) {
        result = 0;
        goto end;
    }
    result &= (s->sm_lists_tail[DETECT_SM_LIST_DMATCH]->type == DETECT_CONTENT);
    result &= (s->sm_lists[DETECT_SM_LIST_PMATCH] == NULL);
    data = (DetectContentData *)s->sm_lists_tail[DETECT_SM_LIST_DMATCH]->ctx;
    if (data->flags & DETECT_CONTENT_RAWBYTES ||
        data->flags & DETECT_CONTENT_NOCASE ||
        !(data->flags & DETECT_CONTENT_WITHIN) ||
        data->flags & DETECT_CONTENT_DISTANCE ||
        data->flags & DETECT_CONTENT_FAST_PATTERN ||
        data->flags & DETECT_CONTENT_NEGATED ||
        result == 0) {
        result = 0;
        goto end;
    }
    result &= (data->within == 10);
/*
    s->next = SigInit(de_ctx, "alert tcp any any -> any any "
                      "(msg:\"Testing dce iface, stub_data with contents & offset, depth\"; "
                      "dce_iface:3919286a-b10c-11d0-9ba8-00c04fd92ef5; "
                      "dce_stub_data; "
                      "content:\"one\"; offset:5; depth:9; "
                      "content:\"two\"; within:10; sid:1;)");
    if (s->next == NULL) {
        printf ("failed dce iface, stub_data with contents & offset, depth");
        result = 0;
        goto end;
    }
    s = s->next;
    if (s->sm_lists_tail[DETECT_SM_LIST_DMATCH] == NULL) {
        result = 0;
        goto end;
    }
    result &= (s->sm_lists_tail[DETECT_SM_LIST_DMATCH]->type == DETECT_CONTENT);
    result &= (s->sm_lists[DETECT_SM_LIST_PMATCH] == NULL);
    data = (DetectContentData *)s->sm_lists_tail[DETECT_SM_LIST_DMATCH]->ctx;
    if (data->flags & DETECT_CONTENT_RAWBYTES ||
        data->flags & DETECT_CONTENT_NOCASE ||
        data->flags & DETECT_CONTENT_WITHIN ||
        data->flags & DETECT_CONTENT_DISTANCE ||
        data->flags & DETECT_CONTENT_FAST_PATTERN ||
        data->flags & DETECT_CONTENT_NEGATED ||
        result == 0) {
        result = 0;
        goto end;
    }
    result &= (data->offset == 5 && data->depth == 9);
    data = (DetectContentData *)s->sm_lists[DETECT_SM_LIST_DMATCH]->ctx;
    if (data->flags & DETECT_CONTENT_RAWBYTES ||
        data->flags & DETECT_CONTENT_NOCASE ||
        !(data->flags & DETECT_CONTENT_WITHIN) ||
        data->flags & DETECT_CONTENT_DISTANCE ||
        data->flags & DETECT_CONTENT_FAST_PATTERN ||
        data->flags & DETECT_CONTENT_NEGATED ||
        result == 0) {
        result = 0;
        goto end;
    }

    s->next = SigInit(de_ctx, "alert tcp any any -> any any "
                      "(msg:\"Testing dce iface, stub with contents, distance\"; "
                      "dce_iface:3919286a-b10c-11d0-9ba8-00c04fd92ef5; "
                      "dce_stub_data; "
                      "content:\"one\"; distance:0; "
                      "content:\"two\"; distance:2; sid:1;)");
    if (s->next == NULL) {
        result = 0;
        goto end;
    }
    s = s->next;
    if (s->sm_lists_tail[DETECT_SM_LIST_DMATCH] == NULL) {
        result = 0;
        goto end;
    }
    result &= (s->sm_lists_tail[DETECT_SM_LIST_DMATCH]->type == DETECT_CONTENT);
    result &= (s->sm_lists[DETECT_SM_LIST_PMATCH] == NULL);
    data = (DetectContentData *)s->sm_lists_tail[DETECT_SM_LIST_DMATCH]->ctx;
    if (data->flags & DETECT_CONTENT_RAWBYTES ||
        data->flags & DETECT_CONTENT_NOCASE ||
        data->flags & DETECT_CONTENT_WITHIN ||
        !(data->flags & DETECT_CONTENT_DISTANCE) ||
        data->flags & DETECT_CONTENT_FAST_PATTERN ||
        data->flags & DETECT_CONTENT_NEGATED ||
        result == 0) {
        result = 0;
        goto end;
    }
    result &= (data->distance == 2);
*/
    s->next = SigInit(de_ctx, "alert tcp any any -> any any "
                      "(msg:\"Testing dce iface, stub with contents, distance, within\"; "
                      "dce_iface:3919286a-b10c-11d0-9ba8-00c04fd92ef5; "
                      "dce_stub_data; "
                      "content:\"one\"; distance:0; "
                      "content:\"two\"; within:10; distance:2; sid:1;)");
    if (s->next == NULL) {
        result = 0;
        goto end;
    }
    s = s->next;
    if (s->sm_lists_tail[DETECT_SM_LIST_DMATCH] == NULL) {
        result = 0;
        goto end;
    }
    result &= (s->sm_lists_tail[DETECT_SM_LIST_DMATCH]->type == DETECT_CONTENT);
    result &= (s->sm_lists[DETECT_SM_LIST_PMATCH] == NULL);
    data = (DetectContentData *)s->sm_lists_tail[DETECT_SM_LIST_DMATCH]->ctx;
    if (data->flags & DETECT_CONTENT_RAWBYTES ||
        data->flags & DETECT_CONTENT_NOCASE ||
        !(data->flags & DETECT_CONTENT_WITHIN) ||
        !(data->flags & DETECT_CONTENT_DISTANCE) ||
        data->flags & DETECT_CONTENT_FAST_PATTERN ||
        data->flags & DETECT_CONTENT_NEGATED ||
        result == 0) {
        result = 0;
        goto end;
    }
    result &= (data->within == 10 && data->distance == 2);
/*
    s->next = SigInit(de_ctx, "alert tcp any any -> any any "
                      "(msg:\"Testing dce iface, stub_data with content, offset\"; "
                      "dce_iface:3919286a-b10c-11d0-9ba8-00c04fd92ef5; "
                      "dce_stub_data; "
                      "content:\"one\"; offset:10; sid:1;)");
    if (s->next == NULL) {
        printf ("Failed dce iface, stub_data with content, offset ");
        result = 0;
        goto end;
    }
    s = s->next;
    if (s->sm_lists_tail[DETECT_SM_LIST_DMATCH] == NULL) {
        result = 0;
        goto end;
    }
    result &= (s->sm_lists_tail[DETECT_SM_LIST_DMATCH]->type == DETECT_CONTENT);
    result &= (s->sm_lists[DETECT_SM_LIST_PMATCH] == NULL);
    data = (DetectContentData *)s->sm_lists_tail[DETECT_SM_LIST_DMATCH]->ctx;
    if (data->flags & DETECT_CONTENT_RAWBYTES ||
        data->flags & DETECT_CONTENT_NOCASE ||
        data->flags & DETECT_CONTENT_WITHIN ||
        data->flags & DETECT_CONTENT_DISTANCE ||
        data->flags & DETECT_CONTENT_FAST_PATTERN ||
        data->flags & DETECT_CONTENT_NEGATED ||
        result == 0) {
        result = 0;
        goto end;
    }
    result &= (data->offset == 10);

    s->next = SigInit(de_ctx, "alert tcp any any -> any any "
                      "(msg:\"Testing dce iface, stub_data with content, depth\"; "
                      "dce_iface:3919286a-b10c-11d0-9ba8-00c04fd92ef5; "
                      "dce_stub_data; "
                      "content:\"one\"; depth:10; sid:1;)");
    if (s->next == NULL) {
        printf ("failed dce iface, stub_data with content, depth");
        result = 0;
        goto end;
    }
    s = s->next;
    if (s->sm_lists_tail[DETECT_SM_LIST_DMATCH] == NULL) {
        result = 0;
        goto end;
    }
    result &= (s->sm_lists_tail[DETECT_SM_LIST_DMATCH]->type == DETECT_CONTENT);
    result &= (s->sm_lists[DETECT_SM_LIST_PMATCH] == NULL);
    data = (DetectContentData *)s->sm_lists_tail[DETECT_SM_LIST_DMATCH]->ctx;
    if (data->flags & DETECT_CONTENT_RAWBYTES ||
        data->flags & DETECT_CONTENT_NOCASE ||
        data->flags & DETECT_CONTENT_WITHIN ||
        data->flags & DETECT_CONTENT_DISTANCE ||
        data->flags & DETECT_CONTENT_FAST_PATTERN ||
        data->flags & DETECT_CONTENT_NEGATED ||
        result == 0) {
        result = 0;
        goto end;
    }
    result &= (data->depth == 10);

    s->next = SigInit(de_ctx, "alert tcp any any -> any any "
                      "(msg:\"Testing dce iface, stub_data with content, offset, depth\"; "
                      "dce_iface:3919286a-b10c-11d0-9ba8-00c04fd92ef5; "
                      "dce_stub_data; "
                      "content:\"one\"; offset:10; depth:3; sid:1;)");
    if (s->next == NULL) {
        printf("failed dce iface, stub_data with content, offset, depth");
        result = 0;
        goto end;
    }
    s = s->next;
    if (s->sm_lists_tail[DETECT_SM_LIST_DMATCH] == NULL) {
        result = 0;
        goto end;
    }
    result &= (s->sm_lists_tail[DETECT_SM_LIST_DMATCH]->type == DETECT_CONTENT);
    result &= (s->sm_lists[DETECT_SM_LIST_PMATCH] == NULL);
    data = (DetectContentData *)s->sm_lists_tail[DETECT_SM_LIST_DMATCH]->ctx;
    if (data->flags & DETECT_CONTENT_RAWBYTES ||
        data->flags & DETECT_CONTENT_NOCASE ||
        data->flags & DETECT_CONTENT_WITHIN ||
        data->flags & DETECT_CONTENT_DISTANCE ||
        data->flags & DETECT_CONTENT_FAST_PATTERN ||
        data->flags & DETECT_CONTENT_NEGATED ||
        result == 0) {
        result = 0;
        goto end;
    }
    result &= (data->offset == 10 && data->depth == 13);
*/
    s->next = SigInit(de_ctx, "alert tcp any any -> any any "
                      "(msg:\"Testing content\"; "
                      "content:\"one\"; sid:1;)");
    if (s->next == NULL) {
        printf ("failed testing content");
        result = 0;
        goto end;
    }
    s = s->next;
    if (s->sm_lists_tail[DETECT_SM_LIST_DMATCH] != NULL) {
        result = 0;
        goto end;
    }
    result &= (s->sm_lists[DETECT_SM_LIST_PMATCH] != NULL);

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Test content for dce sig.
 */
int DetectContentParseTest20(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 1;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert udp any any -> any any "
                               "(msg:\"test\"; content:\"\"; sid:238012;)");
    if (de_ctx->sig_list != NULL) {
        result = 0;
        goto end;
    }

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Parsing test
 */
int DetectContentParseTest21(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 1;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert udp any any -> any any "
                               "(msg:\"test\"; content:\"; sid:238012;)");
    if (de_ctx->sig_list != NULL) {
        result = 0;
        goto end;
    }

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Parsing test
 */
int DetectContentParseTest22(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 1;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert udp any any -> any any "
                               "(msg:\"test\"; content:\"boo; sid:238012;)");
    if (de_ctx->sig_list != NULL) {
        result = 0;
        goto end;
    }

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Parsing test
 */
int DetectContentParseTest23(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 1;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert udp any any -> any any "
                               "(msg:\"test\"; content:boo\"; sid:238012;)");
    if (de_ctx->sig_list != NULL) {
        result = 0;
        goto end;
    }

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Parsing test
 */
int DetectContentParseTest24(void)
{
    DetectEngineCtx *de_ctx = NULL;
    DetectContentData *cd = 0;
    Signature *s = NULL;
    int result = 1;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    s = de_ctx->sig_list = SigInit(de_ctx,
                                   "alert udp any any -> any any "
                                   "(msg:\"test\"; content:    !\"boo\"; sid:238012;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL: ");
        result = 0;
        goto end;
    }

    if (s->sm_lists_tail[DETECT_SM_LIST_PMATCH] == NULL || s->sm_lists_tail[DETECT_SM_LIST_PMATCH]->ctx == NULL) {
        printf("de_ctx->pmatch_tail == NULL || de_ctx->pmatch_tail->ctx == NULL: ");
        result = 0;
        goto end;
    }

    cd = (DetectContentData *)s->sm_lists_tail[DETECT_SM_LIST_PMATCH]->ctx;
    result = (strncmp("boo", (char *)cd->content, cd->content_len) == 0);

end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Parsing test
 */
int DetectContentParseTest25(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 1;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert udp any any -> any any "
                               "(msg:\"test\"; content:\"|\"; sid:1;)");
    if (de_ctx->sig_list != NULL) {
        result = 0;
        goto end;
    }

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Parsing test
 */
int DetectContentParseTest26(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 1;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert udp any any -> any any "
                               "(msg:\"test\"; content:\"|af\"; sid:1;)");
    if (de_ctx->sig_list != NULL) {
        result = 0;
        goto end;
    }

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Parsing test
 */
int DetectContentParseTest27(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 1;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert udp any any -> any any "
                               "(msg:\"test\"; content:\"af|\"; sid:1;)");
    if (de_ctx->sig_list != NULL) {
        result = 0;
        goto end;
    }

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Parsing test
 */
int DetectContentParseTest28(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 1;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert udp any any -> any any "
                               "(msg:\"test\"; content:\"|af|\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Parsing test
 */
int DetectContentParseTest29(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 1;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert udp any any -> any any "
                               "(msg:\"test\"; content:\"aast|\"; sid:1;)");
    if (de_ctx->sig_list != NULL) {
        result = 0;
        goto end;
    }

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Parsing test
 */
int DetectContentParseTest30(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 1;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert udp any any -> any any "
                               "(msg:\"test\"; content:\"aast|af\"; sid:1;)");
    if (de_ctx->sig_list != NULL) {
        result = 0;
        goto end;
    }

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Parsing test
 */
int DetectContentParseTest31(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 1;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert udp any any -> any any "
                               "(msg:\"test\"; content:\"aast|af|\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Parsing test
 */
int DetectContentParseTest32(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 1;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert udp any any -> any any "
                               "(msg:\"test\"; content:\"|af|asdf\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Parsing test
 */
int DetectContentParseTest33(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 1;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert udp any any -> any any "
                               "(msg:\"test\"; content:\"|af|af|\"; sid:1;)");
    if (de_ctx->sig_list != NULL) {
        result = 0;
        goto end;
    }

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Parsing test
 */
int DetectContentParseTest34(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 1;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert udp any any -> any any "
                               "(msg:\"test\"; content:\"|af|af|af\"; sid:1;)");
    if (de_ctx->sig_list != NULL) {
        result = 0;
        goto end;
    }

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Parsing test
 */
int DetectContentParseTest35(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 1;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert udp any any -> any any "
                               "(msg:\"test\"; content:\"|af|af|af|\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Parsing test: file_data
 */
static int DetectContentParseTest36(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert tcp any any -> any any "
                               "(msg:\"test\"; file_data; content:\"abc\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("sig parse failed: ");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL) {
        printf("content still in PMATCH list: ");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_FILEDATA] == NULL) {
        printf("content not in FILEDATA list: ");
        goto end;
    }

    result = 1;
end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Parsing test: file_data
 */
static int DetectContentParseTest37(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert tcp any any -> any any "
                               "(msg:\"test\"; file_data; content:\"abc\"; content:\"def\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("sig parse failed: ");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL) {
        printf("content still in PMATCH list: ");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_FILEDATA] == NULL) {
        printf("content not in FILEDATA list: ");
        goto end;
    }

    result = 1;
end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Parsing test: file_data
 */
static int DetectContentParseTest38(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert tcp any any -> any any "
                               "(msg:\"test\"; file_data; content:\"abc\"; content:\"def\"; within:8; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("sig parse failed: ");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL) {
        printf("content still in PMATCH list: ");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_FILEDATA] == NULL) {
        printf("content not in FILEDATA list: ");
        goto end;
    }

    result = 1;
end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

static int SigTestPositiveTestContent(char *rule, uint8_t *buf)
{
    uint16_t buflen = strlen((char *)buf);
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, rule);
    if (de_ctx->sig_list == NULL) {
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
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);

        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
        DetectEngineCtxFree(de_ctx);
    }

    UTHFreePackets(&p, 1);
    return result;
}

/**
 * \test Parsing test: file_data, within relative to file_data
 */
static int DetectContentParseTest39(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert tcp any any -> any any "
                               "(msg:\"test\"; file_data; content:\"abc\"; within:8; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("sig parse failed: ");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL) {
        printf("content still in PMATCH list: ");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_FILEDATA] == NULL) {
        printf("content not in FILEDATA list: ");
        goto end;
    }

    result = 1;
end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Parsing test: file_data, distance relative to file_data
 */
static int DetectContentParseTest40(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert tcp any any -> any any "
                               "(msg:\"test\"; file_data; content:\"abc\"; distance:3; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("sig parse failed: ");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL) {
        printf("content still in PMATCH list: ");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_FILEDATA] == NULL) {
        printf("content not in FILEDATA list: ");
        goto end;
    }

    result = 1;
end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

int DetectContentParseTest41(void)
{
    int result = 1;
    DetectContentData *cd = NULL;
    int patlen = 257;
    char *teststring = SCMalloc(sizeof(char) * (patlen + 1));
    if (unlikely(teststring == NULL))
        return 0;
    int idx = 0;
    teststring[idx++] = '\"';
    for (int i = 0; i < (patlen - 2); idx++, i++) {
        teststring[idx] = 'a';
    }
    teststring[idx++] = '\"';
    teststring[idx++] = '\0';

    cd = DetectContentParse(teststring);
    if (cd == NULL) {
        SCLogDebug("expected not NULL");
        result = 0;
    }

    SCFree(teststring);
    DetectContentFree(cd);
    return result;
}

/**
 * Tests that content lengths > 255 are supported.
 */
int DetectContentParseTest42(void)
{
    int result = 1;
    DetectContentData *cd = NULL;
    int patlen = 258;
    char *teststring = SCMalloc(sizeof(char) * (patlen + 1));
    if (unlikely(teststring == NULL))
        return 0;
    int idx = 0;
    teststring[idx++] = '\"';
    for (int i = 0; i < (patlen - 2); idx++, i++) {
        teststring[idx] = 'a';
    }
    teststring[idx++] = '\"';
    teststring[idx++] = '\0';

    cd = DetectContentParse(teststring);
    if (cd == NULL) {
        SCLogDebug("expected not NULL");
        result = 0;
    }

    SCFree(teststring);
    DetectContentFree(cd);
    return result;
}

int DetectContentParseTest43(void)
{
    int result = 1;
    DetectContentData *cd = NULL;
    int patlen = 260;
    char *teststring = SCMalloc(sizeof(char) * (patlen + 1));
    if (unlikely(teststring == NULL))
        return 0;
    int idx = 0;
    teststring[idx++] = '\"';
    teststring[idx++] = '|';
    teststring[idx++] = '4';
    teststring[idx++] = '6';
    teststring[idx++] = '|';
    for (int i = 0; i < (patlen - 6); idx++, i++) {
        teststring[idx] = 'a';
    }
    teststring[idx++] = '\"';
    teststring[idx++] = '\0';

    cd = DetectContentParse(teststring);
    if (cd == NULL) {
        SCLogDebug("expected not NULL");
        result = 0;
    }

    SCFree(teststring);
    DetectContentFree(cd);
    return result;
}

/**
 * Tests that content lengths > 255 are supported.
 */
int DetectContentParseTest44(void)
{
    int result = 1;
    DetectContentData *cd = NULL;
    int patlen = 261;
    char *teststring = SCMalloc(sizeof(char) * (patlen + 1));
    if (unlikely(teststring == NULL))
        return 0;
    int idx = 0;
    teststring[idx++] = '\"';
    teststring[idx++] = '|';
    teststring[idx++] = '4';
    teststring[idx++] = '6';
    teststring[idx++] = '|';
    for (int i = 0; i < (patlen - 6); idx++, i++) {
        teststring[idx] = 'a';
    }
    teststring[idx++] = '\"';
    teststring[idx++] = '\0';

    cd = DetectContentParse(teststring);
    if (cd == NULL) {
        SCLogDebug("expected not NULL");
        result = 0;
    }

    SCFree(teststring);
    DetectContentFree(cd);
    return result;
}

static int SigTestNegativeTestContent(char *rule, uint8_t *buf)
{
    uint16_t buflen = strlen((char *)buf);
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 0;
    memset(&th_v, 0, sizeof(th_v));

    p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, rule);
    if (de_ctx->sig_list == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1) != 0) {
        goto end;
    }

    result = 1;
end:
    if (det_ctx != NULL) {
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    }
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }
    UTHFreePackets(&p, 1);
    return result;
}

/**
 * \test A positive test that checks that the content string doesn't contain
 *       the negated content
 */
static int SigTest41TestNegatedContent(void)
{
    return SigTestPositiveTestContent("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:!\"GES\"; sid:1;)", (uint8_t *)"GET /one/ HTTP/1.1\r\n Host: one.example.org\r\n\r\n\r\nGET /two/ HTTP/1.1\r\nHost: two.example.org\r\n\r\n\r\n");
}

/**
 * \test A positive test that checks that the content string doesn't contain
 *       the negated content within the specified depth
 */
static int SigTest42TestNegatedContent(void)
{                                                                                                                                                        // 01   5    10   15   20  24
    return SigTestPositiveTestContent("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:!\"twentythree\"; depth:22; offset:35; sid:1;)",  (uint8_t *)"one four nine fourteen twentythree thirtyfive fourtysix fiftysix");
}

/**
 * \test A negative test that checks that the content string doesn't contain
 *       the negated content within the specified depth, and also after the
 *       specified offset. Since the content is there, the match fails. 
 *
 *       Match is at offset:23, depth:34
 */
static int SigTest43TestNegatedContent(void)
{
    return SigTestNegativeTestContent("alert tcp any any -> any any (content:!\"twentythree\"; depth:34; offset:23; sid:1;)", (uint8_t *)"one four nine fourteen twentythree thirtyfive fourtysix fiftysix");
}

/**
 * \test A negative test that checks that the content string doesn't contain
 *       the negated content after the specified offset and within the specified
 *       depth.
 */
static int SigTest44TestNegatedContent(void)
{
    return SigTestPositiveTestContent("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:!\"twentythree\"; offset:40; depth:35; sid:1;)",  (uint8_t *)"one four nine fourteen twentythree thirtyfive fourtysix fiftysix");
}

/**
 * \test A positive test that uses a combination of content string with negated
 *       content string
 */
static int SigTest45TestNegatedContent(void)
{
    return SigTestPositiveTestContent("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:\"one\"; depth:5; content:!\"twentythree\"; depth:23; sid:1;)",  (uint8_t *)"one four nine fourteen twentythree thirtyfive fourtysix fiftysix");
}

/**
 * \test A negative test that uses a combination of content string with negated
 *       content string, with we receiving a failure for 'onee' itself.
 */
static int SigTest46TestNegatedContent(void)
{
    return SigTestNegativeTestContent("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:\"onee\"; content:!\"twentythree\"; depth:23; sid:1;)",  (uint8_t *)"one four nine fourteen twentythree thirtyfive fourtysix fiftysix");
}

/**
 * \test A negative test that uses a combination of content string with negated
 *       content string, with we receiving a failure of first content's offset
 *       condition
 */
static int SigTest47TestNegatedContent(void)
{
    return SigTestNegativeTestContent("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:\"one\"; offset:5; content:!\"twentythree\"; depth:23; sid:1;)",  (uint8_t *)"one four nine fourteen twentythree thirtyfive fourtysix fiftysix");
}

/**
 * \test A positive test that checks that we don't have a negated content within
 *       the specified length from the previous content match.
 */
static int SigTest48TestNegatedContent(void)
{
    return SigTestPositiveTestContent("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:\"GET\"; content:!\"GES\"; within:26; sid:1;)", (uint8_t *)"GET /one/ HTTP/1.1\r\n Host: one.example.org\r\n\r\n\r\nGET /two/ HTTP/1.1\r\nHost: two.example.org\r\n\r\n\r\n");
}

/**
 * \test A negative test that checks the combined use of content and negated
 *        content with the use of within
 */
static int SigTest49TestNegatedContent(void)
{
    return SigTestNegativeTestContent("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:\"GET\"; content:!\"Host\"; within:26; sid:1;)", (uint8_t *)"GET /one/ HTTP/1.1\r\n Host: one.example.org\r\n\r\n\r\nGET /two/ HTTP/1.1\r\nHost: two.example.org\r\n\r\n\r\n");
}

/**
 * \test A positive test that checks the combined use of content and negated
 *        content with the use of distance
 */
static int SigTest50TestNegatedContent(void)
{
    return SigTestPositiveTestContent("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:\"GET\"; content:!\"GES\"; distance:25; sid:1;)", (uint8_t *)"GET /one/ HTTP/1.1\r\n Host: one.example.org\r\n\r\n\r\nGET /two/ HTTP/1.1\r\nHost: two.example.org\r\n\r\n\r\n");
}

/**
 * \test A negative test that checks the combined use of content and negated
 *       content with the use of distance
 *
 * First GET at offset 0
 * First Host at offset 21
 */
static int SigTest51TestNegatedContent(void)
{
    return SigTestNegativeTestContent("alert tcp any any -> any any (content:\"GET\"; content:!\"Host\"; distance:17; sid:1;)", (uint8_t *)"GET /one/ HTTP/1.1\r\nHost: one.example.org\r\n\r\n\r\nGET /two/ HTTP/1.1\r\nHost: two.example.org\r\n\r\n\r\n");
}

/**
 * \test A negative test that checks the combined use of content and negated
 *       content, with the content not being present
 */
static int SigTest52TestNegatedContent(void)
{
    return SigTestNegativeTestContent("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:\"GES\"; content:!\"BOO\"; sid:1;)", (uint8_t *)"GET /one/ HTTP/1.1\r\n Host: one.example.org\r\n\r\n\r\nGET /two/ HTTP/1.1\r\nHost: two.example.org\r\n\r\n\r\n");
}

/**
 * \test A negative test that checks the combined use of content and negated
 *       content, in the presence of within
 */
static int SigTest53TestNegatedContent(void)
{
    return SigTestNegativeTestContent("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:\"one\"; content:!\"fourty\"; within:56; sid:1;)", (uint8_t *)"one four nine fourteen twentythree thirtyfive fourtysix fiftysix");
}

/**
 * \test A positive test that checks the combined use of content and negated
 *       content, in the presence of within
 */
static int SigTest54TestNegatedContent(void)
{
    return SigTestPositiveTestContent("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:\"one\"; content:!\"fourty\"; within:20; sid:1;)", (uint8_t *)"one four nine fourteen twentythree thirtyfive fourtysix fiftysix");
}

/**
 * \test A negative test that checks the use of negated content along with
 *       the presence of depth
 */
static int SigTest55TestNegatedContent(void)
{
    return SigTestNegativeTestContent("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:!\"one\"; depth:5; sid:1;)", (uint8_t *)"one four nine fourteen twentythree thirtyfive fourtysix fiftysix");
}

/**
 * \test A positive test that checks the combined use of 2 contents in the
 *       presence of within
 */
static int SigTest56TestNegatedContent(void)
{
    return SigTestPositiveTestContent("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:\"one\"; content:\"fourty\"; within:56; sid:1;)", (uint8_t *)"one four nine fourteen twentythree thirtyfive fourtysix fiftysix");
}

/**
 * \test A negative test that checks the combined use of content and negated
 *       content, in the presence of within
 */
static int SigTest57TestNegatedContent(void)
{
    return SigTestNegativeTestContent("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:\"one\"; content:!\"fourty\"; within:56; sid:1;)", (uint8_t *)"one four nine fourteen twentythree thirtyfive fourtysix fiftysix");
}

/**
 * \test A positive test that checks the combined use of content and negated
 *       content, in the presence of distance
 */
static int SigTest58TestNegatedContent(void)
{
    return SigTestPositiveTestContent("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:\"one\"; content:!\"fourty\"; distance:57; sid:1;)", (uint8_t *)"one four nine fourteen twentythree thirtyfive fourtysix fiftysix");
}

/**
 * \test A negative test that checks the combined use of content and negated
 *       content, in the presence of distance
 */
static int SigTest59TestNegatedContent(void)
{
    return SigTestNegativeTestContent("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:\"one\"; content:!\"fourty\"; distance:30; sid:1;)", (uint8_t *)"one four nine fourteen twentythree thirtyfive fourtysix fiftysix");
}

static int SigTest60TestNegatedContent(void)
{
    return SigTestNegativeTestContent("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:!\"one\"; content:\"fourty\"; sid:1;)", (uint8_t *)"one four nine fourteen twentythree thirtyfive fourtysix fiftysix");
}

static int SigTest61TestNegatedContent(void)
{
    return SigTestPositiveTestContent("alert tcp any any -> any any (content:\"one\"; depth:10; content:!\"fourty\"; within:30; sid:1;)", (uint8_t *)"one four nine fourteen twentythree thirtyfive fourtysix fiftysix");
}

/** \test Test negation in combination with within and depth
 *
 *  Match of "one" at offset:0, depth:3
 *  Match of "fourty" at offset:46, depth:52
 *
 *  This signature should not match for the test to pass.
 */
static int SigTest62TestNegatedContent(void)
{
    return SigTestNegativeTestContent("alert tcp any any -> any any (content:\"one\"; depth:10; content:!\"fourty\"; within:49; sid:1;)", (uint8_t *)"one four nine fourteen twentythree thirtyfive fourtysix fiftysix");
}

static int SigTest63TestNegatedContent(void)
{
    return SigTestNegativeTestContent("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:\"one\"; depth:10; content:!\"fourty\"; within:56; sid:1;)", (uint8_t *)"one four nine fourteen twentythree thirtyfive fourtysix fiftysix");
}

static int SigTest64TestNegatedContent(void)
{
    return SigTestPositiveTestContent("alert tcp any any -> any any (content:\"one\"; depth:10; content:!\"fourty\"; within:30; sid:1;)", (uint8_t *)"one four nine fourteen twentythree thirtyfive fourtysix fiftysix");
}

/** \test Test negation in combination with within and depth
 *
 *  Match of "one" at offset:0, depth:3
 *  Match of "fourty" at offset:46, depth:52
 *
 *  This signature should not match for the test to pass.
 */
static int SigTest65TestNegatedContent(void)
{
    return SigTestNegativeTestContent("alert tcp any any -> any any (content:\"one\"; depth:10; content:!\"fourty\"; distance:0; within:49; sid:1;)", (uint8_t *)"one four nine fourteen twentythree thirtyfive fourtysix fiftysix");
}

static int SigTest66TestNegatedContent(void)
{
    return SigTestPositiveTestContent("alert tcp any any -> any any (content:\"one\"; depth:10; content:!\"fourty\"; within:30; sid:1;)", (uint8_t *)"one four nine fourteen twentythree thirtyfive fourtysix fiftysix");
}

static int SigTest67TestNegatedContent(void)
{
    return SigTestNegativeTestContent("alert tcp any any -> any any (content:\"one\"; depth:10; content:!\"four\"; within:56; sid:1;)", (uint8_t *)"one four nine fourteen twentythree thirtyfive fourtysix fiftysix");
}

static int SigTest68TestNegatedContent(void)
{
    return SigTestPositiveTestContent("alert tcp any any -> any any (content:\"one\"; depth:10; content:\"nine\"; offset:8; content:!\"fourty\"; within:28; content:\"fiftysix\"; sid:1;)", (uint8_t *)"one four nine fourteen twentythree thirtyfive fourtysix fiftysix");
}

static int SigTest69TestNegatedContent(void)
{
    return SigTestNegativeTestContent("alert tcp any any -> any any (content:\"one\"; depth:10; content:\"nine\"; offset:8; content:!\"fourty\"; within:48; content:\"fiftysix\"; sid:1;)", (uint8_t *)"one four nine fourteen twentythree thirtyfive fourtysix fiftysix");
}

static int SigTest70TestNegatedContent(void)
{
    return SigTestNegativeTestContent("alert tcp any any -> any any (content:\"one\"; content:!\"fourty\"; within:52; distance:45 sid:1;)", (uint8_t *)"one four nine fourteen twentythree thirtyfive fourtysix fiftysix");
}

/** \test within and distance */
static int SigTest71TestNegatedContent(void)
{
    return SigTestNegativeTestContent("alert tcp any any -> any any (content:\"one\"; content:!\"fourty\"; within:40; distance:43; sid:1;)", (uint8_t *)"one four nine fourteen twentythree thirtyfive fourtysix fiftysix");
}

static int SigTest72TestNegatedContent(void)
{
    return SigTestNegativeTestContent("alert tcp any any -> any any (content:\"one\"; content:!\"fourty\"; within:49; distance:43; sid:1;)", (uint8_t *)"one four nine fourteen twentythree thirtyfive fourtysix fiftysix");
}

static int SigTest73TestNegatedContent(void)
{
    return SigTestNegativeTestContent("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:\"one\"; depth:5; content:!\"twentythree\"; depth:35; sid:1;)",  (uint8_t *)"one four nine fourteen twentythree thirtyfive fourtysix fiftysix");
}

static int SigTest74TestNegatedContent(void)
{
    return SigTestPositiveTestContent("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:\"USER\"; content:!\"PASS\"; sid:1;)",  (uint8_t *)"USER apple");
}

static int SigTest75TestNegatedContent(void)
{
    return SigTestPositiveTestContent("alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:\"USER\"; content:\"!PASS\"; sid:1;)",  (uint8_t *)"USER !PASS");
}

static int SigTest76TestBug134(void)
{
    uint8_t *buf = (uint8_t *)"test detect ${IFS} in traffic";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket( buf, buflen, IPPROTO_TCP);
    int result = 0;
    Flow f;

    memset(&f, 0, sizeof(Flow));
    FLOW_INITIALIZE(&f);

    p->dp = 515;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flow = &f;
    p->flags |= PKT_HAS_FLOW;

    char sig[] = "alert tcp any any -> any 515 "
            "(msg:\"detect IFS\"; flow:to_server,established; content:\"${IFS}\";"
            " depth:50; offset:0; sid:900091; rev:1;)";
    if (UTHPacketMatchSigMpm(p, sig, MPM_B2G) == 0) {
        result = 0;
        goto end;
    }

    result = 1;
end:
    if (p != NULL)
        UTHFreePacket(p);

    FLOW_DESTROY(&f);
    return result;
}

static int SigTest77TestBug139(void)
{
    uint8_t buf[] = {
        0x12, 0x23, 0x34, 0x35, 0x52, 0x52, 0x24, 0x42, 0x22, 0x24,
        0x52, 0x24, 0x82, 0x00, 0x00, 0x00, 0x00, 0x00, 0x24, 0x34 };
    uint16_t buflen = sizeof(buf);
    Packet *p = UTHBuildPacket( buf, buflen, IPPROTO_UDP);
    int result = 0;

    p->dp = 53;
    char sig[] = "alert udp any any -> any 53 (msg:\"dns testing\";"
                    " content:\"|00 00|\"; depth:5; offset:13; sid:9436601;"
                    " rev:1;)";
    if (UTHPacketMatchSigMpm(p, sig, MPM_B2G) == 0) {
        result = 0;
        goto end;
    }

    result = 1;
end:
    if (p != NULL)
        UTHFreePacket(p);
    return result;
}

static int DetectLongContentTestCommon(char *sig, uint32_t sid)
{
    /* Packet with 512 A's in it for testing long content. */
    static uint8_t pkt[739] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x45, 0x00,
        0x02, 0xd5, 0x4a, 0x18, 0x40, 0x00, 0x40, 0x06,
        0xd7, 0xd6, 0x0a, 0x10, 0x01, 0x0b, 0x0a, 0x10,
        0x01, 0x0a, 0xdb, 0x36, 0x00, 0x50, 0xca, 0xc5,
        0xcc, 0xd1, 0x95, 0x77, 0x0f, 0x7d, 0x80, 0x18,
        0x00, 0xe5, 0x77, 0x9d, 0x00, 0x00, 0x01, 0x01,
        0x08, 0x0a, 0x1d, 0xe0, 0x86, 0xc6, 0xfc, 0x73,
        0x49, 0xf3, 0x50, 0x4f, 0x53, 0x54, 0x20, 0x2f,
        0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e,
        0x31, 0x0d, 0x0a, 0x55, 0x73, 0x65, 0x72, 0x2d,
        0x41, 0x67, 0x65, 0x6e, 0x74, 0x3a, 0x20, 0x63,
        0x75, 0x72, 0x6c, 0x2f, 0x37, 0x2e, 0x33, 0x37,
        0x2e, 0x30, 0x0d, 0x0a, 0x48, 0x6f, 0x73, 0x74,
        0x3a, 0x20, 0x31, 0x30, 0x2e, 0x31, 0x36, 0x2e,
        0x31, 0x2e, 0x31, 0x30, 0x0d, 0x0a, 0x41, 0x63,
        0x63, 0x65, 0x70, 0x74, 0x3a, 0x20, 0x2a, 0x2f,
        0x2a, 0x0d, 0x0a, 0x43, 0x6f, 0x6e, 0x74, 0x65,
        0x6e, 0x74, 0x2d, 0x4c, 0x65, 0x6e, 0x67, 0x74,
        0x68, 0x3a, 0x20, 0x35, 0x32, 0x38, 0x0d, 0x0a,
        0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d,
        0x54, 0x79, 0x70, 0x65, 0x3a, 0x20, 0x61, 0x70,
        0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f,
        0x6e, 0x2f, 0x78, 0x2d, 0x77, 0x77, 0x77, 0x2d,
        0x66, 0x6f, 0x72, 0x6d, 0x2d, 0x75, 0x72, 0x6c,
        0x65, 0x6e, 0x63, 0x6f, 0x64, 0x65, 0x64, 0x0d,
        0x0a, 0x0d, 0x0a, 0x58, 0x58, 0x58, 0x58, 0x58,
        0x58, 0x58, 0x58, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x58, 0x58, 0x58, 0x58, 0x58,
        0x58, 0x58, 0x58
    };

    return DetectContentLongPatternMatchTest(pkt, (uint16_t)sizeof(pkt), sig,
        sid);
}

static int DetectLongContentTest1(void)
{
    /* Signature with 256 A's. */
    char *sig = "alert tcp any any -> any any (msg:\"Test Rule\"; content:\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"; sid:1;)";

    return DetectLongContentTestCommon(sig, 1);
}

static int DetectLongContentTest2(void)
{
    /* Signature with 512 A's. */
    char *sig = "alert tcp any any -> any any (msg:\"Test Rule\"; content:\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"; sid:1;)";

    return DetectLongContentTestCommon(sig, 1);
}

static int DetectLongContentTest3(void)
{
    /* Signature with 513 A's. */
    char *sig = "alert tcp any any -> any any (msg:\"Test Rule\"; content:\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"; sid:1;)";

    return !DetectLongContentTestCommon(sig, 1);
}

#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for DetectContent
 */
void DetectContentRegisterTests(void)
{
#ifdef UNITTESTS /* UNITTESTS */
    UtRegisterTest("DetectContentParseTest01", DetectContentParseTest01, 1);
    UtRegisterTest("DetectContentParseTest02", DetectContentParseTest02, 1);
    UtRegisterTest("DetectContentParseTest03", DetectContentParseTest03, 1);
    UtRegisterTest("DetectContentParseTest04", DetectContentParseTest04, 1);
    UtRegisterTest("DetectContentParseTest05", DetectContentParseTest05, 1);
    UtRegisterTest("DetectContentParseTest06", DetectContentParseTest06, 1);
    UtRegisterTest("DetectContentParseTest07", DetectContentParseTest07, 1);
    UtRegisterTest("DetectContentParseTest08", DetectContentParseTest08, 1);
    UtRegisterTest("DetectContentParseTest09", DetectContentParseTest09, 1);
    UtRegisterTest("DetectContentParseTest10", DetectContentParseTest10, 1);
    UtRegisterTest("DetectContentParseNegTest11", DetectContentParseNegTest11, 1);
    UtRegisterTest("DetectContentParseNegTest12", DetectContentParseNegTest12, 1);
    UtRegisterTest("DetectContentParseNegTest13", DetectContentParseNegTest13, 1);
    UtRegisterTest("DetectContentParseNegTest14", DetectContentParseNegTest14, 1);
    UtRegisterTest("DetectContentParseNegTest15", DetectContentParseNegTest15, 1);
    UtRegisterTest("DetectContentParseNegTest16", DetectContentParseNegTest16, 1);
    UtRegisterTest("DetectContentParseTest17", DetectContentParseTest17, 1);
    UtRegisterTest("DetectContentParseTest18", DetectContentParseTest18, 1);
    UtRegisterTest("DetectContentParseTest19", DetectContentParseTest19, 1);
    UtRegisterTest("DetectContentParseTest20", DetectContentParseTest20, 1);
    UtRegisterTest("DetectContentParseTest21", DetectContentParseTest21, 1);
    UtRegisterTest("DetectContentParseTest22", DetectContentParseTest22, 1);
    UtRegisterTest("DetectContentParseTest23", DetectContentParseTest23, 1);
    UtRegisterTest("DetectContentParseTest24", DetectContentParseTest24, 1);
    UtRegisterTest("DetectContentParseTest25", DetectContentParseTest25, 1);
    UtRegisterTest("DetectContentParseTest26", DetectContentParseTest26, 1);
    UtRegisterTest("DetectContentParseTest27", DetectContentParseTest27, 1);
    UtRegisterTest("DetectContentParseTest28", DetectContentParseTest28, 1);
    UtRegisterTest("DetectContentParseTest29", DetectContentParseTest29, 1);
    UtRegisterTest("DetectContentParseTest30", DetectContentParseTest30, 1);
    UtRegisterTest("DetectContentParseTest31", DetectContentParseTest31, 1);
    UtRegisterTest("DetectContentParseTest32", DetectContentParseTest32, 1);
    UtRegisterTest("DetectContentParseTest33", DetectContentParseTest33, 1);
    UtRegisterTest("DetectContentParseTest34", DetectContentParseTest34, 1);
    UtRegisterTest("DetectContentParseTest35", DetectContentParseTest35, 1);
    UtRegisterTest("DetectContentParseTest36", DetectContentParseTest36, 1);
    UtRegisterTest("DetectContentParseTest37", DetectContentParseTest37, 1);
    UtRegisterTest("DetectContentParseTest38", DetectContentParseTest38, 1);
    UtRegisterTest("DetectContentParseTest39", DetectContentParseTest39, 1);
    UtRegisterTest("DetectContentParseTest40", DetectContentParseTest40, 1);
    UtRegisterTest("DetectContentParseTest41", DetectContentParseTest41, 1);
    UtRegisterTest("DetectContentParseTest42", DetectContentParseTest42, 1);
    UtRegisterTest("DetectContentParseTest43", DetectContentParseTest43, 1);
    UtRegisterTest("DetectContentParseTest44", DetectContentParseTest44, 1);

    /* The reals */
    UtRegisterTest("DetectContentLongPatternMatchTest01", DetectContentLongPatternMatchTest01, 1);
    UtRegisterTest("DetectContentLongPatternMatchTest02", DetectContentLongPatternMatchTest02, 1);
    UtRegisterTest("DetectContentLongPatternMatchTest03", DetectContentLongPatternMatchTest03, 1);
    UtRegisterTest("DetectContentLongPatternMatchTest04", DetectContentLongPatternMatchTest04, 1);
    UtRegisterTest("DetectContentLongPatternMatchTest05", DetectContentLongPatternMatchTest05, 1);
    UtRegisterTest("DetectContentLongPatternMatchTest06", DetectContentLongPatternMatchTest06, 1);
    UtRegisterTest("DetectContentLongPatternMatchTest07", DetectContentLongPatternMatchTest07, 1);
    UtRegisterTest("DetectContentLongPatternMatchTest08", DetectContentLongPatternMatchTest08, 1);
    UtRegisterTest("DetectContentLongPatternMatchTest09", DetectContentLongPatternMatchTest09, 1);
    UtRegisterTest("DetectContentLongPatternMatchTest10", DetectContentLongPatternMatchTest10, 1);
    UtRegisterTest("DetectContentLongPatternMatchTest11", DetectContentLongPatternMatchTest11, 1);

    /* Negated content tests */
    UtRegisterTest("SigTest41TestNegatedContent", SigTest41TestNegatedContent, 1);
    UtRegisterTest("SigTest42TestNegatedContent", SigTest42TestNegatedContent, 1);
    UtRegisterTest("SigTest43TestNegatedContent", SigTest43TestNegatedContent, 1);
    UtRegisterTest("SigTest44TestNegatedContent", SigTest44TestNegatedContent, 1);
    UtRegisterTest("SigTest45TestNegatedContent", SigTest45TestNegatedContent, 1);
    UtRegisterTest("SigTest46TestNegatedContent", SigTest46TestNegatedContent, 1);
    UtRegisterTest("SigTest47TestNegatedContent", SigTest47TestNegatedContent, 1);
    UtRegisterTest("SigTest48TestNegatedContent", SigTest48TestNegatedContent, 1);
    UtRegisterTest("SigTest49TestNegatedContent", SigTest49TestNegatedContent, 1);
    UtRegisterTest("SigTest50TestNegatedContent", SigTest50TestNegatedContent, 1);
    UtRegisterTest("SigTest51TestNegatedContent", SigTest51TestNegatedContent, 1);
    UtRegisterTest("SigTest52TestNegatedContent", SigTest52TestNegatedContent, 1);
    UtRegisterTest("SigTest53TestNegatedContent", SigTest53TestNegatedContent, 1);
    UtRegisterTest("SigTest54TestNegatedContent", SigTest54TestNegatedContent, 1);
    UtRegisterTest("SigTest55TestNegatedContent", SigTest55TestNegatedContent, 1);
    UtRegisterTest("SigTest56TestNegatedContent", SigTest56TestNegatedContent, 1);
    UtRegisterTest("SigTest57TestNegatedContent", SigTest57TestNegatedContent, 1);
    UtRegisterTest("SigTest58TestNegatedContent", SigTest58TestNegatedContent, 1);
    UtRegisterTest("SigTest59TestNegatedContent", SigTest59TestNegatedContent, 1);
    UtRegisterTest("SigTest60TestNegatedContent", SigTest60TestNegatedContent, 1);
    UtRegisterTest("SigTest61TestNegatedContent", SigTest61TestNegatedContent, 1);
    UtRegisterTest("SigTest62TestNegatedContent", SigTest62TestNegatedContent, 1);
    UtRegisterTest("SigTest63TestNegatedContent", SigTest63TestNegatedContent, 1);
    UtRegisterTest("SigTest64TestNegatedContent", SigTest64TestNegatedContent, 1);
    UtRegisterTest("SigTest65TestNegatedContent", SigTest65TestNegatedContent, 1);
    UtRegisterTest("SigTest66TestNegatedContent", SigTest66TestNegatedContent, 1);
    UtRegisterTest("SigTest67TestNegatedContent", SigTest67TestNegatedContent, 1);
    UtRegisterTest("SigTest68TestNegatedContent", SigTest68TestNegatedContent, 1);
    UtRegisterTest("SigTest69TestNegatedContent", SigTest69TestNegatedContent, 1);
    UtRegisterTest("SigTest70TestNegatedContent", SigTest70TestNegatedContent, 1);
    UtRegisterTest("SigTest71TestNegatedContent", SigTest71TestNegatedContent, 1);
    UtRegisterTest("SigTest72TestNegatedContent", SigTest72TestNegatedContent, 1);
    UtRegisterTest("SigTest73TestNegatedContent", SigTest73TestNegatedContent, 1);
    UtRegisterTest("SigTest74TestNegatedContent", SigTest74TestNegatedContent, 1);
    UtRegisterTest("SigTest75TestNegatedContent", SigTest75TestNegatedContent, 1);

    UtRegisterTest("SigTest76TestBug134", SigTest76TestBug134, 1);
    UtRegisterTest("SigTest77TestBug139", SigTest77TestBug139, 1);

    UtRegisterTest("DetectLongContentTest1", DetectLongContentTest1, 1);
    UtRegisterTest("DetectLongContentTest2", DetectLongContentTest2, 1);
    UtRegisterTest("DetectLongContentTest3", DetectLongContentTest3, 1);
#endif /* UNITTESTS */
}
