/* Copyright (C) 2007-2022 Open Information Security Foundation
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
#include "detect-engine-build.h"
#include "detect-engine-state.h"
#include "detect-parse.h"
#include "detect-pcre.h"
#include "util-mpm.h"
#include "flow.h"
#include "flow-util.h"
#include "flow-var.h"
#include "detect-flow.h"
#include "app-layer.h"
#include "util-unittest.h"
#include "util-print.h"
#include "util-debug.h"
#include "util-spm.h"
#include "threads.h"
#include "util-unittest-helper.h"
#include "pkt-var.h"
#include "host.h"
#include "util-profiling.h"
#include "detect-dsize.h"

#ifdef UNITTESTS
static void DetectContentRegisterTests(void);
#endif

void DetectContentRegister (void)
{
    sigmatch_table[DETECT_CONTENT].name = "content";
    sigmatch_table[DETECT_CONTENT].desc = "match on payload content";
    sigmatch_table[DETECT_CONTENT].url = "/rules/payload-keywords.html#content";
    sigmatch_table[DETECT_CONTENT].Match = NULL;
    sigmatch_table[DETECT_CONTENT].Setup = DetectContentSetup;
    sigmatch_table[DETECT_CONTENT].Free  = DetectContentFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_CONTENT].RegisterTests = DetectContentRegisterTests;
#endif
    sigmatch_table[DETECT_CONTENT].flags = (SIGMATCH_QUOTES_MANDATORY|SIGMATCH_HANDLE_NEGATION);
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
        uint8_t **pstr, uint16_t *plen)
{
    char *str = NULL;
    size_t slen = 0;

    slen = strlen(contentstr);
    if (slen == 0) {
        return -1;
    }
    uint8_t buffer[slen + 1];
    strlcpy((char *)&buffer, contentstr, slen + 1);
    str = (char *)buffer;

    SCLogDebug("\"%s\", len %" PRIuMAX, str, (uintmax_t)slen);

    //SCLogDebug("DetectContentParse: \"%s\", len %" PRIu32 "", str, len);
    char converted = 0;

    {
        size_t i, x;
        uint8_t bin = 0;
        uint8_t escape = 0;
        uint8_t binstr[3] = "";
        uint8_t binpos = 0;
        uint16_t bin_count = 0;

        for (i = 0, x = 0; i < slen; i++) {
            // SCLogDebug("str[%02u]: %c", i, str[i]);
            if (str[i] == '|') {
                bin_count++;
                if (bin) {
                    if (binpos > 0) {
                        SCLogError(SC_ERR_INVALID_SIGNATURE,
                                "Incomplete hex code in content - %s. Invalidating signature.",
                                contentstr);
                        goto error;
                    }
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
                                    "content - %s, hex %c. Invalidating signature.", str, str[i]);
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
                        SCLogError(SC_ERR_INVALID_SIGNATURE, "'%c' has to be escaped", str[i-1]);
                        goto error;
                    }
                    escape = 0;
                    converted = 1;
                } else if (str[i] == '"') {
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "Invalid unescaped double quote within content section.");
                    goto error;
                } else {
                    str[x] = str[i];
                    x++;
                }
            }
        }

        if (bin_count % 2 != 0) {
            SCLogError(SC_ERR_INVALID_SIGNATURE, "Invalid hex code assembly in "
                       "%s - %s.  Invalidating signature.", keyword, contentstr);
            goto error;
        }

        if (converted) {
            slen = x;
        }
    }

    if (slen) {
        uint8_t *ptr = SCCalloc(1, slen);
        if (ptr == NULL) {
            return -1;
        }
        memcpy(ptr, str, slen);

        *plen = (uint16_t)slen;
        *pstr = ptr;
        return 0;
    }
error:
    return -1;
}
/**
 * \brief DetectContentParse
 * \initonly
 */
DetectContentData *DetectContentParse(SpmGlobalThreadCtx *spm_global_thread_ctx,
                                      const char *contentstr)
{
    DetectContentData *cd = NULL;
    uint8_t *content = NULL;
    uint16_t len = 0;
    int ret;

    ret = DetectContentDataParse("content", contentstr, &content, &len);
    if (ret == -1) {
        return NULL;
    }

    cd = SCCalloc(1, sizeof(DetectContentData) + len);
    if (unlikely(cd == NULL)) {
        SCFree(content);
        exit(EXIT_FAILURE);
    }

    cd->content = (uint8_t *)cd + sizeof(DetectContentData);
    memcpy(cd->content, content, len);
    cd->content_len = len;

    /* Prepare SPM search context. */
    cd->spm_ctx = SpmInitCtx(cd->content, cd->content_len, 0,
                             spm_global_thread_ctx);
    if (cd->spm_ctx == NULL) {
        SCFree(content);
        SCFree(cd);
        return NULL;
    }

    cd->depth = 0;
    cd->offset = 0;
    cd->within = 0;
    cd->distance = 0;

    SCFree(content);
    return cd;

}

DetectContentData *DetectContentParseEncloseQuotes(SpmGlobalThreadCtx *spm_global_thread_ctx,
                                                   const char *contentstr)
{
    return DetectContentParse(spm_global_thread_ctx, contentstr);
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
    char *tmpstr = SCMalloc(sizeof(char) * cd->content_len + 1);
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
        char *tmprstr = SCMalloc(sizeof(char) * cd->replace_len + 1);

        if (tmprstr != NULL) {
            for (i = 0; i < cd->replace_len; i++) {
                if (isprint(cd->replace[i]))
                    tmprstr[i] = cd->replace[i];
                else
                    tmprstr[i] = '.';
            }
            tmprstr[i] = '\0';
            SCLogDebug("Replace: \"%s\"", tmprstr);
            SCFree(tmprstr);
        } else {
            SCLogDebug("Replace: ");
            for (i = 0; i < cd->replace_len; i++)
                SCLogDebug("%c", cd->replace[i]);
        }
    }
    SCLogDebug("-----------");
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
int DetectContentSetup(DetectEngineCtx *de_ctx, Signature *s, const char *contentstr)
{
    DetectContentData *cd = NULL;
    SigMatch *sm = NULL;

    cd = DetectContentParse(de_ctx->spm_global_thread_ctx, contentstr);
    if (cd == NULL)
        goto error;
    if (s->init_data->negated == true) {
        cd->flags |= DETECT_CONTENT_NEGATED;
    }

    DetectContentPrint(cd);

    if (DetectBufferGetActiveList(de_ctx, s) == -1)
        goto error;

    int sm_list = s->init_data->list;
    if (sm_list == DETECT_SM_LIST_NOTSET) {
        sm_list = DETECT_SM_LIST_PMATCH;
    } else if (sm_list > DETECT_SM_LIST_MAX &&
            0 == (cd->flags & DETECT_CONTENT_NEGATED)) {
        /* Check transform compatibility */
        const char *tstr;
        if (!DetectEngineBufferTypeValidateTransform(
                    de_ctx, sm_list, cd->content, cd->content_len, &tstr)) {
            SCLogError(SC_ERR_INVALID_SIGNATURE,
                    "content string \"%s\" incompatible with %s transform",
                    contentstr, tstr);
            goto error;
        }
    }

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;
    sm->ctx = (void *)cd;
    sm->type = DETECT_CONTENT;
    SigMatchAppendSMToList(s, sm, sm_list);

    return 0;

error:
    DetectContentFree(de_ctx, cd);
    return -1;
}

/**
 * \brief this function will SCFree memory associated with DetectContentData
 *
 * \param cd pointer to DetectContentData
 */
void DetectContentFree(DetectEngineCtx *de_ctx, void *ptr)
{
    SCEnter();
    DetectContentData *cd = (DetectContentData *)ptr;

    if (cd == NULL)
        SCReturn;

    SpmDestroyCtx(cd->spm_ctx);

    SCFree(cd);
    SCReturn;
}

void SigParseRequiredContentSize(const Signature *s, int list, int *len, int *offset)
{
    SigMatch *sm = s->init_data->smlists[list];
    int max_offset = 0, total_len = 0;
    for (; sm != NULL; sm = sm->next) {
        if (sm->type != DETECT_CONTENT || sm->ctx == NULL) {
            continue;
        }

        DetectContentData *cd = (DetectContentData *)sm->ctx;
        if (cd->flags & DETECT_CONTENT_NEGATED && cd->content_len == cd->within) {
            SCLogDebug("negated ... within: %d", cd->within);
            continue;
        }
        SCLogDebug("content_len %d; distance: %d, offset: %d, depth: %d", cd->content_len,
                cd->distance, cd->offset, cd->depth);
        total_len += cd->content_len + cd->distance;
        max_offset = MAX(max_offset, cd->offset);
    }

    *len = total_len;
    *offset = max_offset;
}

/**
 *  \retval 1 valid
 *  \retval 0 invalid
 */
bool DetectContentPMATCHValidateCallback(const Signature *s)
{
    if (!(s->flags & SIG_FLAG_DSIZE)) {
        return true;
    }

    int max_right_edge_i = SigParseGetMaxDsize(s);
    if (max_right_edge_i < 0) {
        return true;
    }

    uint32_t max_right_edge = (uint32_t)max_right_edge_i;

    int min_dsize_required = SigParseMaxRequiredDsize(s);
    if (min_dsize_required >= 0) {
        SCLogDebug("min_dsize %d; max_right_edge %d", min_dsize_required, max_right_edge);
        if ((uint32_t)min_dsize_required > max_right_edge) {
            SCLogError(SC_ERR_INVALID_SIGNATURE,
                    "signature can't match as required content length %d exceeds dsize value %d",
                    min_dsize_required, max_right_edge);
            return false;
        }
    }

    return true;
}

/** \brief apply depth/offset and distance/within to content matches
 *
 *  The idea is that any limitation we can set is a win, as the mpm
 *  can use this to reduce match candidates.
 *
 *  E.g. if we have 'content:"1"; depth:1; content:"2"; distance:0; within:1;'
 *  we know that we can add 'offset:1; depth:2;' to the 2nd condition. This
 *  will then be used in mpm if the 2nd condition would be selected for mpm.
 *
 *  Another example: 'content:"1"; depth:1; content:"2"; distance:0;'. Here we
 *  cannot set a depth, but we can set an offset of 'offset:1;'. This will
 *  make the mpm a bit more precise.
 */
void DetectContentPropagateLimits(Signature *s)
{
#define VALIDATE(e)                                                                                \
    if (!(e)) {                                                                                    \
        return;                                                                                    \
    }
    BUG_ON(s == NULL || s->init_data == NULL);

    uint32_t list = 0;
    for (list = 0; list < s->init_data->smlists_array_size; list++) {
        uint16_t offset = 0;
        uint16_t offset_plus_pat = 0;
        uint16_t depth = 0;
        bool has_active_depth_chain = false;

        bool has_depth = false;
        bool has_ends_with = false;
        uint16_t ends_with_depth = 0;

        SigMatch *sm = s->init_data->smlists[list];
        for ( ; sm != NULL; sm = sm->next) {
            switch (sm->type) {
                case DETECT_CONTENT: {
                    DetectContentData *cd = (DetectContentData *)sm->ctx;
                    if ((cd->flags & (DETECT_CONTENT_DEPTH|DETECT_CONTENT_OFFSET|DETECT_CONTENT_WITHIN|DETECT_CONTENT_DISTANCE)) == 0) {
                        offset = depth = 0;
                        offset_plus_pat = cd->content_len;
                        SCLogDebug("reset");
                        has_active_depth_chain = false;
                        continue;
                    }
                    if (cd->flags & DETECT_CONTENT_NEGATED) {
                        offset = depth = 0;
                        offset_plus_pat = 0;
                        SCLogDebug("reset because of negation");
                        has_active_depth_chain = false;
                        continue;
                    }

                    if (cd->depth) {
                        has_depth = true;
                        has_active_depth_chain = true;
                    }

                    SCLogDebug("sm %p depth %u offset %u distance %d within %d", sm, cd->depth, cd->offset, cd->distance, cd->within);
                    SCLogDebug("stored: offset %u depth %u offset_plus_pat %u", offset, depth, offset_plus_pat);

                    if ((cd->flags & (DETECT_DEPTH | DETECT_CONTENT_WITHIN)) == 0) {
                        if (depth)
                            SCLogDebug("no within, reset depth");
                        depth = 0;
                        has_active_depth_chain = false;
                    }
                    if ((cd->flags & DETECT_CONTENT_DISTANCE) == 0) {
                        if (offset_plus_pat)
                            SCLogDebug("no distance, reset offset_plus_pat & offset");
                        offset_plus_pat = offset = 0;
                    }

                    SCLogDebug("stored: offset %u depth %u offset_plus_pat %u "
                               "has_active_depth_chain %s",
                            offset, depth, offset_plus_pat,
                            has_active_depth_chain ? "true" : "false");
                    if (cd->flags & DETECT_CONTENT_DISTANCE && cd->distance >= 0) {
                        VALIDATE((uint32_t)offset_plus_pat + cd->distance <= UINT16_MAX);
                        offset = cd->offset = (uint16_t)(offset_plus_pat + cd->distance);
                        SCLogDebug("updated content to have offset %u", cd->offset);
                    }
                    if (has_active_depth_chain) {
                        if (offset_plus_pat && cd->flags & DETECT_CONTENT_WITHIN &&
                                cd->within >= 0) {
                            if (depth && depth > offset_plus_pat) {
                                int32_t dist = 0;
                                if (cd->flags & DETECT_CONTENT_DISTANCE && cd->distance > 0) {
                                    dist = cd->distance;
                                    SCLogDebug("distance to add: %u. depth + dist %u", dist,
                                            depth + dist);
                                }
                                SCLogDebug("depth %u + cd->within %u", depth, cd->within);
                                VALIDATE(depth + cd->within + dist >= 0 &&
                                         depth + cd->within + dist <= UINT16_MAX);
                                depth = cd->depth = (uint16_t)(depth + cd->within + dist);
                            } else {
                                SCLogDebug("offset %u + cd->within %u", offset, cd->within);
                                VALIDATE(depth + cd->within >= 0 &&
                                         depth + cd->within <= UINT16_MAX);
                                depth = cd->depth = (uint16_t)(offset + cd->within);
                            }
                            SCLogDebug("updated content to have depth %u", cd->depth);
                        } else {
                            if (cd->depth == 0 && depth != 0) {
                                if (cd->within > 0) {
                                    SCLogDebug("within %d distance %d", cd->within, cd->distance);
                                    if (cd->flags & DETECT_CONTENT_DISTANCE && cd->distance >= 0) {
                                        VALIDATE(offset_plus_pat + cd->distance >= 0 &&
                                                 offset_plus_pat + cd->distance <= UINT16_MAX);
                                        cd->offset = (uint16_t)(offset_plus_pat + cd->distance);
                                        SCLogDebug("updated content to have offset %u", cd->offset);
                                    }

                                    VALIDATE(depth + cd->within >= 0 &&
                                             depth + cd->within <= UINT16_MAX);
                                    depth = cd->depth = (uint16_t)(cd->within + depth);
                                    SCLogDebug("updated content to have depth %u", cd->depth);

                                    if (cd->flags & DETECT_CONTENT_ENDS_WITH) {
                                        has_ends_with = true;
                                        if (ends_with_depth == 0)
                                            ends_with_depth = depth;
                                        ends_with_depth = MIN(ends_with_depth, depth);
                                    }
                                }
                            }
                        }
                    }
                    if (cd->offset == 0) {// && offset != 0) {
                        if (cd->flags & DETECT_CONTENT_DISTANCE && cd->distance >= 0) {
                            cd->offset = offset_plus_pat;
                            SCLogDebug("update content to have offset %u", cd->offset);
                        }
                    }

                    if ((cd->flags & (DETECT_CONTENT_DEPTH|DETECT_CONTENT_OFFSET|DETECT_CONTENT_WITHIN|DETECT_CONTENT_DISTANCE)) == (DETECT_CONTENT_DISTANCE|DETECT_CONTENT_WITHIN) ||
                            (cd->flags & (DETECT_CONTENT_DEPTH|DETECT_CONTENT_OFFSET|DETECT_CONTENT_WITHIN|DETECT_CONTENT_DISTANCE)) == (DETECT_CONTENT_DISTANCE)) {
                        if (cd->distance >= 0) {
                            // only distance
                            VALIDATE((uint32_t)offset_plus_pat + cd->distance <= UINT16_MAX);
                            offset = cd->offset = (uint16_t)(offset_plus_pat + cd->distance);
                            offset_plus_pat = offset + cd->content_len;
                            SCLogDebug("offset %u offset_plus_pat %u", offset, offset_plus_pat);
                        }
                    }
                    if (cd->flags & DETECT_CONTENT_OFFSET) {
                        offset = cd->offset;
                        offset_plus_pat = offset + cd->content_len;
                        SCLogDebug("stored offset %u offset_plus_pat %u", offset, offset_plus_pat);
                    }
                    if (cd->depth) {
                        depth = cd->depth;
                        SCLogDebug("stored depth now %u", depth);
                        offset_plus_pat = offset + cd->content_len;
                        if (cd->flags & DETECT_CONTENT_ENDS_WITH) {
                            has_ends_with = true;
                            if (ends_with_depth == 0)
                                ends_with_depth = depth;
                            ends_with_depth = MIN(ends_with_depth, depth);
                        }
                    }
                    if ((cd->flags & (DETECT_CONTENT_WITHIN|DETECT_CONTENT_DEPTH)) == 0) {
                        has_active_depth_chain = false;
                        depth = 0;
                    }
                    break;
                }
                case DETECT_PCRE: {
                    // relative could leave offset_plus_pat set.
                    const DetectPcreData *pd = (const DetectPcreData *)sm->ctx;
                    if (pd->flags & DETECT_PCRE_RELATIVE) {
                        depth = 0;
                    } else {
                        SCLogDebug("non-anchored PCRE not supported, reset offset_plus_pat & offset");
                        offset_plus_pat = offset = depth = 0;
                    }
                    has_active_depth_chain = false;
                    break;
                }
                default: {
                    SCLogDebug("keyword not supported, reset offset_plus_pat & offset");
                    offset_plus_pat = offset = depth = 0;
                    has_active_depth_chain = false;
                    break;
                }
            }
        }
        /* apply anchored 'ends with' as depth to all patterns */
        if (has_depth && has_ends_with) {
            sm = s->init_data->smlists[list];
            for ( ; sm != NULL; sm = sm->next) {
                switch (sm->type) {
                    case DETECT_CONTENT: {
                        DetectContentData *cd = (DetectContentData *)sm->ctx;
                        if (cd->depth == 0)
                            cd->depth = ends_with_depth;
                        cd->depth = MIN(ends_with_depth, cd->depth);
                        if (cd->depth)
                            cd->flags |= DETECT_CONTENT_DEPTH;
                        break;
                    }
                }
            }
        }
    }
#undef VALIDATE
}

static inline bool NeedsAsHex(uint8_t c)
{
    if (!isprint(c))
        return true;

    switch (c) {
        case '/':
        case ';':
        case ':':
        case '\\':
        case ' ':
        case '|':
        case '"':
        case '`':
        case '\'':
            return true;
    }
    return false;
}

void DetectContentPatternPrettyPrint(const DetectContentData *cd, char *str, size_t str_len)
{
    bool hex = false;
    for (uint16_t i = 0; i < cd->content_len; i++) {
        if (NeedsAsHex(cd->content[i])) {
            char hex_str[4];
            snprintf(hex_str, sizeof(hex_str), "%s%02X", !hex ? "|" : " ", cd->content[i]);
            strlcat(str, hex_str, str_len);
            hex = true;
        } else {
            char p_str[3];
            snprintf(p_str, sizeof(p_str), "%s%c", hex ? "|" : "", cd->content[i]);
            strlcat(str, p_str, str_len);
            hex = false;
        }
    }
    if (hex) {
        strlcat(str, "|", str_len);
    }
}

#ifdef UNITTESTS /* UNITTESTS */

static bool TestLastContent(const Signature *s, uint16_t o, uint16_t d)
{
    const SigMatch *sm = s->init_data->smlists_tail[DETECT_SM_LIST_PMATCH];
    if (!sm) {
        SCLogDebug("no sm");
        return false;
    }
    if (!(sm->type == DETECT_CONTENT)) {
        SCLogDebug("not content");
        return false;
    }
    const DetectContentData *cd = (const DetectContentData *)sm->ctx;
    if (o != cd->offset) {
        SCLogDebug("offset mismatch %u != %u", o, cd->offset);
        return false;
    }
    if (d != cd->depth) {
        SCLogDebug("depth mismatch %u != %u", d, cd->depth);
        return false;
    }
    return true;
}

#define TEST_RUN(sig, o, d)                                                                        \
    {                                                                                              \
        SCLogDebug("TEST_RUN start: '%s'", (sig));                                                 \
        DetectEngineCtx *de_ctx = DetectEngineCtxInit();                                           \
        FAIL_IF_NULL(de_ctx);                                                                      \
        de_ctx->flags |= DE_QUIET;                                                                 \
        char rule[2048];                                                                           \
        snprintf(rule, sizeof(rule), "alert tcp any any -> any any (%s sid:1; rev:1;)", (sig));    \
        Signature *s = DetectEngineAppendSig(de_ctx, rule);                                        \
        FAIL_IF_NULL(s);                                                                           \
        SigAddressPrepareStage1(de_ctx);                                                           \
        bool res = TestLastContent(s, (o), (d));                                                   \
        FAIL_IF(res == false);                                                                     \
        DetectEngineCtxFree(de_ctx);                                                               \
    }

#define TEST_DONE \
    PASS

/** \test test propagation of depth/offset/distance/within */
static int DetectContentDepthTest01(void)
{
    // straight depth/offset
    TEST_RUN("content:\"abc\"; offset:1; depth:3;", 1, 4);
    // dsize applied as depth
    TEST_RUN("dsize:10; content:\"abc\";", 0, 10);
    TEST_RUN("dsize:<10; content:\"abc\";", 0, 10);
    TEST_RUN("dsize:5<>10; content:\"abc\";", 0, 10);

    // relative match, directly following anchored content
    TEST_RUN("content:\"abc\"; depth:3; content:\"xyz\"; distance:0; within:3; ", 3, 6);
    // relative match, directly following anchored content
    TEST_RUN("content:\"abc\"; offset:3; depth:3; content:\"xyz\"; distance:0; within:3; ", 6, 9);
    TEST_RUN("content:\"abc\"; depth:6; content:\"xyz\"; distance:0; within:3; ", 3, 9);

    // multiple relative matches after anchored content
    TEST_RUN("content:\"abc\"; depth:3; content:\"klm\"; distance:0; within:3; content:\"xyz\"; distance:0; within:3; ", 6, 9);
    // test 'reset' due to unanchored content
    TEST_RUN("content:\"abc\"; depth:3; content:\"klm\"; content:\"xyz\"; distance:0; within:3; ", 3, 0);
    // test 'reset' due to unanchored pcre
    TEST_RUN("content:\"abc\"; depth:3; pcre:/\"klm\"/; content:\"xyz\"; distance:0; within:3; ", 0, 0);
    // test relative pcre. We can use previous offset+pattern len
    TEST_RUN("content:\"abc\"; depth:3; pcre:/\"klm\"/R; content:\"xyz\"; distance:0; within:3; ", 3, 0);
    TEST_RUN("content:\"abc\"; offset:3; depth:3; pcre:/\"klm\"/R; content:\"xyz\"; distance:0; within:3; ", 6, 0);

    TEST_RUN("content:\"abc\"; depth:3; content:\"klm\"; within:3; content:\"xyz\"; within:3; ", 0, 9);

    TEST_RUN("content:\"abc\"; depth:3; content:\"klm\"; distance:0; content:\"xyz\"; distance:0; ", 6, 0);

    // tests to see if anchored 'ends_with' is applied to other content as depth
    TEST_RUN("content:\"abc\"; depth:6; isdataat:!1,relative; content:\"klm\";", 0, 6);
    TEST_RUN("content:\"abc\"; depth:3; content:\"klm\"; within:3; content:\"xyz\"; within:3; isdataat:!1,relative; content:\"def\"; ", 0, 9);

    TEST_RUN("content:\"|03|\"; depth:1; content:\"|e0|\"; distance:4; within:1;", 5, 6);
    TEST_RUN("content:\"|03|\"; depth:1; content:\"|e0|\"; distance:4; within:1; content:\"Cookie|3a|\"; distance:5; within:7;", 11, 18);

    TEST_RUN("content:\"this\"; content:\"is\"; within:6; content:\"big\"; within:8; content:\"string\"; within:8;", 0, 0);

    TEST_RUN("dsize:<80; content:!\"|00 22 02 00|\"; depth: 4; content:\"|00 00 04|\"; distance:8; within:3; content:\"|00 00 00 00 00|\"; distance:6; within:5;", 17, 80);
    TEST_RUN("content:!\"|00 22 02 00|\"; depth: 4; content:\"|00 00 04|\"; distance:8; within:3; content:\"|00 00 00 00 00|\"; distance:6; within:5;", 17, 0);

    TEST_RUN("content:\"|0d 0a 0d 0a|\"; content:\"code=\"; distance:0;", 4, 0);
    TEST_RUN("content:\"|0d 0a 0d 0a|\"; content:\"code=\"; distance:0; content:\"xploit.class\"; distance:2; within:18;", 11, 0);

    TEST_RUN("content:\"|16 03|\"; depth:2; content:\"|55 04 0a|\"; distance:0;", 2, 0);
    TEST_RUN("content:\"|16 03|\"; depth:2; content:\"|55 04 0a|\"; distance:0; content:\"|0d|LogMeIn, Inc.\"; distance:1; within:14;", 6, 0);
    TEST_RUN("content:\"|16 03|\"; depth:2; content:\"|55 04 0a|\"; distance:0; content:\"|0d|LogMeIn, Inc.\"; distance:1; within:14; content:\".app\";", 0, 0);

    TEST_RUN("content:\"=\"; offset:4; depth:9;", 4, 13);
    // low end: offset 4 + patlen 1 = 5. So 5 + distance 55 = 60.
    // hi end: depth '13' (4+9) + distance 55 = 68 + within 2 = 70
    TEST_RUN("content:\"=\"; offset:4; depth:9; content:\"=&\"; distance:55; within:2;", 60, 70);

    // distance value is too high so we bail and not set anything on this content
    TEST_RUN("content:\"0123456789\"; content:\"abcdef\"; distance:2147483647;", 0, 0);

    // Bug #5162.
    TEST_RUN("content:\"SMB\"; depth:8; content:\"|09 00|\"; distance:8; within:2;", 11, 18);
    TEST_RUN("content:\"SMB\"; depth:8; content:\"|09 00|\"; distance:8; within:2; content:\"|05 "
             "00 00|\"; distance:0;",
            13, 0);
    TEST_RUN("content:\"SMB\"; depth:8; content:\"|09 00|\"; distance:8; within:2; content:\"|05 "
             "00 00|\"; distance:0; content:\"|0c 00|\"; distance:19; within:2;",
            35, 0);
    TEST_RUN("content:\"SMB\"; depth:8; content:\"|09 00|\"; distance:8; within:2; content:\"|05 "
             "00 00|\"; distance:0; content:\"|0c 00|\"; distance:19; within:2; content:\"|15 00 "
             "00 00|\"; distance:20; within:4;",
            57, 0);

    TEST_DONE;
}

/**
 * \brief Print list of DETECT_CONTENT SigMatch's allocated in a
 * SigMatch list, from the current sm to the end
 * \param sm pointer to the current SigMatch to start printing from
 */
static void DetectContentPrintAll(SigMatch *sm)
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

static int g_file_data_buffer_id = 0;
static int g_dce_stub_data_buffer_id = 0;

/**
 * \test DetectCotentParseTest01 this is a test to make sure we can deal with escaped colons
 */
static int DetectContentParseTest01 (void)
{
    int result = 1;
    DetectContentData *cd = NULL;
    const char *teststring = "abc\\:def";
    const char *teststringparsed = "abc:def";

    uint16_t spm_matcher = SinglePatternMatchDefaultMatcher();
    SpmGlobalThreadCtx *spm_global_thread_ctx = SpmInitGlobalThreadCtx(spm_matcher);
    FAIL_IF(spm_global_thread_ctx == NULL);

    cd = DetectContentParse(spm_global_thread_ctx, teststring);
    if (cd != NULL) {
        if (memcmp(cd->content, teststringparsed, strlen(teststringparsed)) != 0) {
            SCLogDebug("expected %s got ", teststringparsed);
            PrintRawUriFp(stdout,cd->content,cd->content_len);
            SCLogDebug(": ");
            result = 0;
            DetectContentFree(NULL, cd);
        }
    } else {
        SCLogDebug("expected %s got NULL: ", teststringparsed);
        result = 0;
    }
    SpmDestroyGlobalThreadCtx(spm_global_thread_ctx);
    return result;
}

/**
 * \test DetectCotentParseTest02 this is a test to make sure we can deal with escaped semi-colons
 */
static int DetectContentParseTest02 (void)
{
    int result = 1;
    DetectContentData *cd = NULL;
    const char *teststring = "abc\\;def";
    const char *teststringparsed = "abc;def";

    uint16_t spm_matcher = SinglePatternMatchDefaultMatcher();
    SpmGlobalThreadCtx *spm_global_thread_ctx = SpmInitGlobalThreadCtx(spm_matcher);
    FAIL_IF(spm_global_thread_ctx == NULL);

    cd = DetectContentParse(spm_global_thread_ctx, teststring);
    if (cd != NULL) {
        if (memcmp(cd->content, teststringparsed, strlen(teststringparsed)) != 0) {
            SCLogDebug("expected %s got ", teststringparsed);
            PrintRawUriFp(stdout,cd->content,cd->content_len);
            SCLogDebug(": ");
            result = 0;
            DetectContentFree(NULL, cd);
        }
    } else {
        SCLogDebug("expected %s got NULL: ", teststringparsed);
        result = 0;
    }
    SpmDestroyGlobalThreadCtx(spm_global_thread_ctx);
    return result;
}

/**
 * \test DetectCotentParseTest03 this is a test to make sure we can deal with escaped double-quotes
 */
static int DetectContentParseTest03 (void)
{
    int result = 1;
    DetectContentData *cd = NULL;
    const char *teststring = "abc\\\"def";
    const char *teststringparsed = "abc\"def";

    uint16_t spm_matcher = SinglePatternMatchDefaultMatcher();
    SpmGlobalThreadCtx *spm_global_thread_ctx = SpmInitGlobalThreadCtx(spm_matcher);
    FAIL_IF(spm_global_thread_ctx == NULL);

    cd = DetectContentParse(spm_global_thread_ctx, teststring);
    if (cd != NULL) {
        if (memcmp(cd->content, teststringparsed, strlen(teststringparsed)) != 0) {
            SCLogDebug("expected %s got ", teststringparsed);
            PrintRawUriFp(stdout,cd->content,cd->content_len);
            SCLogDebug(": ");
            result = 0;
            DetectContentFree(NULL, cd);
        }
    } else {
        SCLogDebug("expected %s got NULL: ", teststringparsed);
        result = 0;
    }
    SpmDestroyGlobalThreadCtx(spm_global_thread_ctx);
    return result;
}

/**
 * \test DetectCotentParseTest04 this is a test to make sure we can deal with escaped backslashes
 */
static int DetectContentParseTest04 (void)
{
    int result = 1;
    DetectContentData *cd = NULL;
    const char *teststring = "abc\\\\def";
    const char *teststringparsed = "abc\\def";

    uint16_t spm_matcher = SinglePatternMatchDefaultMatcher();
    SpmGlobalThreadCtx *spm_global_thread_ctx = SpmInitGlobalThreadCtx(spm_matcher);
    FAIL_IF(spm_global_thread_ctx == NULL);

    cd = DetectContentParse(spm_global_thread_ctx, teststring);
    if (cd != NULL) {
        uint16_t len = (cd->content_len > strlen(teststringparsed));
        if (memcmp(cd->content, teststringparsed, len) != 0) {
            SCLogDebug("expected %s got ", teststringparsed);
            PrintRawUriFp(stdout,cd->content,cd->content_len);
            SCLogDebug(": ");
            result = 0;
            DetectContentFree(NULL, cd);
        }
    } else {
        SCLogDebug("expected %s got NULL: ", teststringparsed);
        result = 0;
    }
    SpmDestroyGlobalThreadCtx(spm_global_thread_ctx);
    return result;
}

/**
 * \test DetectCotentParseTest05 test illegal escape
 */
static int DetectContentParseTest05 (void)
{
    int result = 1;
    DetectContentData *cd = NULL;
    const char *teststring = "abc\\def";

    uint16_t spm_matcher = SinglePatternMatchDefaultMatcher();
    SpmGlobalThreadCtx *spm_global_thread_ctx = SpmInitGlobalThreadCtx(spm_matcher);
    FAIL_IF(spm_global_thread_ctx == NULL);

    cd = DetectContentParse(spm_global_thread_ctx, teststring);
    if (cd != NULL) {
        SCLogDebug("expected NULL got ");
        PrintRawUriFp(stdout,cd->content,cd->content_len);
        SCLogDebug(": ");
        result = 0;
        DetectContentFree(NULL, cd);
    }
    SpmDestroyGlobalThreadCtx(spm_global_thread_ctx);
    return result;
}

/**
 * \test DetectCotentParseTest06 test a binary content
 */
static int DetectContentParseTest06 (void)
{
    int result = 1;
    DetectContentData *cd = NULL;
    const char *teststring = "a|42|c|44|e|46|";
    const char *teststringparsed = "abcdef";

    uint16_t spm_matcher = SinglePatternMatchDefaultMatcher();
    SpmGlobalThreadCtx *spm_global_thread_ctx = SpmInitGlobalThreadCtx(spm_matcher);
    FAIL_IF(spm_global_thread_ctx == NULL);

    cd = DetectContentParse(spm_global_thread_ctx, teststring);
    if (cd != NULL) {
        uint16_t len = (cd->content_len > strlen(teststringparsed));
        if (memcmp(cd->content, teststringparsed, len) != 0) {
            SCLogDebug("expected %s got ", teststringparsed);
            PrintRawUriFp(stdout,cd->content,cd->content_len);
            SCLogDebug(": ");
            result = 0;
            DetectContentFree(NULL, cd);
        }
    } else {
        SCLogDebug("expected %s got NULL: ", teststringparsed);
        result = 0;
    }
    SpmDestroyGlobalThreadCtx(spm_global_thread_ctx);
    return result;
}

/**
 * \test DetectCotentParseTest07 test an empty content
 */
static int DetectContentParseTest07 (void)
{
    int result = 1;
    DetectContentData *cd = NULL;
    const char *teststring = "";

    uint16_t spm_matcher = SinglePatternMatchDefaultMatcher();
    SpmGlobalThreadCtx *spm_global_thread_ctx = SpmInitGlobalThreadCtx(spm_matcher);
    FAIL_IF(spm_global_thread_ctx == NULL);

    cd = DetectContentParse(spm_global_thread_ctx, teststring);
    if (cd != NULL) {
        SCLogDebug("expected NULL got %p: ", cd);
        result = 0;
        DetectContentFree(NULL, cd);
    }
    SpmDestroyGlobalThreadCtx(spm_global_thread_ctx);
    return result;
}

/**
 * \test DetectCotentParseTest08 test an empty content
 */
static int DetectContentParseTest08 (void)
{
    int result = 1;
    DetectContentData *cd = NULL;
    const char *teststring = "";

    uint16_t spm_matcher = SinglePatternMatchDefaultMatcher();
    SpmGlobalThreadCtx *spm_global_thread_ctx = SpmInitGlobalThreadCtx(spm_matcher);
    FAIL_IF(spm_global_thread_ctx == NULL);

    cd = DetectContentParse(spm_global_thread_ctx, teststring);
    if (cd != NULL) {
        SCLogDebug("expected NULL got %p: ", cd);
        result = 0;
        DetectContentFree(NULL, cd);
    }
    SpmDestroyGlobalThreadCtx(spm_global_thread_ctx);
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
static int DetectContentLongPatternMatchTest(uint8_t *raw_eth_pkt, uint16_t pktsize, const char *sig,
                      uint32_t sid)
{
    int result = 0;

    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    DecodeThreadVars dtv;

    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;

    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&th_v, 0, sizeof(th_v));

    FlowInitConfig(FLOW_QUIET);
    DecodeEthernet(&th_v, &dtv, p, raw_eth_pkt, pktsize);

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
static int DetectContentLongPatternMatchTestWrp(const char *sig, uint32_t sid)
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
static int DetectContentLongPatternMatchTest01(void)
{
    const char *sig = "alert tcp any any -> any any (msg:\"Nothing..\";"
                " content:\"Hi, this is a big test\"; sid:1;)";
    return DetectContentLongPatternMatchTestWrp(sig, 1);
}

/**
 * \test Check if we match a splitted pattern
 */
static int DetectContentLongPatternMatchTest02(void)
{
    const char *sig = "alert tcp any any -> any any (msg:\"Nothing..\";"
                " content:\"Hi, this is a big test to check content matches of"
                " splitted patterns between multiple chunks!\"; sid:1;)";
    return DetectContentLongPatternMatchTestWrp(sig, 1);
}

/**
 * \test Check that we don't match the signature if one of the splitted
 * chunks doesn't match the packet
 */
static int DetectContentLongPatternMatchTest03(void)
{
    /** The last chunk of the content should not match */
    const char *sig = "alert tcp any any -> any any (msg:\"Nothing..\";"
                " content:\"Hi, this is a big test to check content matches of"
                " splitted patterns between multiple splitted chunks!\"; sid:1;)";
    return (DetectContentLongPatternMatchTestWrp(sig, 1) == 0) ? 1: 0;
}

/**
 * \test Check if we match multiple content (not splitted)
 */
static int DetectContentLongPatternMatchTest04(void)
{
    const char *sig = "alert tcp any any -> any any (msg:\"Nothing..\"; "
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
static int DetectContentLongPatternMatchTest05(void)
{
    const char *sig = "alert tcp any any -> any any (msg:\"Nothing..\"; "
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
static int DetectContentLongPatternMatchTest06(void)
{
    const char *sig = "alert tcp any any -> any any (msg:\"Nothing..\"; "
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
static int DetectContentLongPatternMatchTest07(void)
{
    const char *sig = "alert tcp any any -> any any (msg:\"Nothing..\"; "
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
static int DetectContentLongPatternMatchTest08(void)
{
    const char *sig = "alert tcp any any -> any any (msg:\"Nothing..\"; "
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
static int DetectContentLongPatternMatchTest09(void)
{
    const char *sig = "alert tcp any any -> any any (msg:\"Nothing..\"; "
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
static int DetectContentLongPatternMatchTest10(void)
{
    const char *sig = "alert tcp any any -> any any (msg:\"Nothing..\"; "
                " content:\"Hi, this is a big test to check \"; "
                " content:\"con\"; "
                " sid:1;)";
    return DetectContentLongPatternMatchTestWrp(sig, 1);
}

/**
 * \test Check if we match two contents of length 1
 */
static int DetectContentLongPatternMatchTest11(void)
{
    const char *sig = "alert tcp any any -> any any (msg:\"Nothing..\"; "
                " content:\"H\"; "
                " content:\"i\"; "
                " sid:1;)";
    return DetectContentLongPatternMatchTestWrp(sig, 1);
}

static int DetectContentParseTest09(void)
{
    DetectContentData *cd = NULL;
    const char *teststring = "boo";

    uint16_t spm_matcher = SinglePatternMatchDefaultMatcher();
    SpmGlobalThreadCtx *spm_global_thread_ctx = SpmInitGlobalThreadCtx(spm_matcher);
    FAIL_IF(spm_global_thread_ctx == NULL);

    cd = DetectContentParse(spm_global_thread_ctx, teststring);
    FAIL_IF_NULL(cd);
    DetectContentFree(NULL, cd);
    SpmDestroyGlobalThreadCtx(spm_global_thread_ctx);
    PASS;
}

/**
 * \test Test cases where if within specified is < content lenggth we invalidate
 *       the sig.
 */
static int DetectContentParseTest17(void)
{
    int result = 0;
    const char *sigstr = "alert tcp any any -> any any (msg:\"Dummy\"; "
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
static int DetectContentParseTest18(void)
{
    Signature *s = SigAlloc();
    int result = 1;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        result = 0;
        goto end;
    }

    if (DetectSignatureSetAppProto(s, ALPROTO_DCERPC) < 0)
        goto end;

    result &= (DetectContentSetup(de_ctx, s, "one") == 0);
    result &= (s->sm_lists[g_dce_stub_data_buffer_id] == NULL && s->sm_lists[DETECT_SM_LIST_PMATCH] != NULL);

    SigFree(de_ctx, s);

    s = SigAlloc();
    if (s == NULL)
        return 0;

    result &= (DetectContentSetup(de_ctx, s, "one") == 0);
    result &= (s->sm_lists[g_dce_stub_data_buffer_id] == NULL && s->sm_lists[DETECT_SM_LIST_PMATCH] != NULL);

 end:
    SigFree(de_ctx, s);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Test content for dce sig.
 */

static int DetectContentParseTest19(void)
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
    if (s->sm_lists_tail[g_dce_stub_data_buffer_id] == NULL) {
        result = 0;
        goto end;
    }
    result &= (s->sm_lists_tail[g_dce_stub_data_buffer_id]->type == DETECT_CONTENT);
    result &= (s->sm_lists[DETECT_SM_LIST_PMATCH] == NULL);
    data = (DetectContentData *)s->sm_lists_tail[g_dce_stub_data_buffer_id]->ctx;
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
    if (s->sm_lists_tail[g_dce_stub_data_buffer_id] == NULL) {
        result = 0;
        goto end;
    }
    result &= (s->sm_lists_tail[g_dce_stub_data_buffer_id]->type == DETECT_CONTENT);
    result &= (s->sm_lists[DETECT_SM_LIST_PMATCH] == NULL);
    data = (DetectContentData *)s->sm_lists_tail[g_dce_stub_data_buffer_id]->ctx;
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
    if (s->sm_lists_tail[g_dce_stub_data_buffer_id] == NULL) {
        result = 0;
        goto end;
    }
    result &= (s->sm_lists_tail[g_dce_stub_data_buffer_id]->type == DETECT_CONTENT);
    result &= (s->sm_lists[DETECT_SM_LIST_PMATCH] == NULL);
    data = (DetectContentData *)s->sm_lists_tail[g_dce_stub_data_buffer_id]->ctx;
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
    data = (DetectContentData *)s->sm_lists[g_dce_stub_data_buffer_id]->ctx;
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
    if (s->sm_lists_tail[g_dce_stub_data_buffer_id] == NULL) {
        result = 0;
        goto end;
    }
    result &= (s->sm_lists_tail[g_dce_stub_data_buffer_id]->type == DETECT_CONTENT);
    result &= (s->sm_lists[DETECT_SM_LIST_PMATCH] == NULL);
    data = (DetectContentData *)s->sm_lists_tail[g_dce_stub_data_buffer_id]->ctx;
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
    if (s->sm_lists_tail[g_dce_stub_data_buffer_id] == NULL) {
        result = 0;
        goto end;
    }
    result &= (s->sm_lists_tail[g_dce_stub_data_buffer_id]->type == DETECT_CONTENT);
    result &= (s->sm_lists[DETECT_SM_LIST_PMATCH] == NULL);
    data = (DetectContentData *)s->sm_lists_tail[g_dce_stub_data_buffer_id]->ctx;
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
    if (s->sm_lists_tail[g_dce_stub_data_buffer_id] == NULL) {
        result = 0;
        goto end;
    }
    result &= (s->sm_lists_tail[g_dce_stub_data_buffer_id]->type == DETECT_CONTENT);
    result &= (s->sm_lists[DETECT_SM_LIST_PMATCH] == NULL);
    data = (DetectContentData *)s->sm_lists_tail[g_dce_stub_data_buffer_id]->ctx;
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
    if (s->sm_lists_tail[g_dce_stub_data_buffer_id] == NULL) {
        result = 0;
        goto end;
    }
    result &= (s->sm_lists_tail[g_dce_stub_data_buffer_id]->type == DETECT_CONTENT);
    result &= (s->sm_lists[DETECT_SM_LIST_PMATCH] == NULL);
    data = (DetectContentData *)s->sm_lists_tail[g_dce_stub_data_buffer_id]->ctx;
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
    if (s->sm_lists_tail[g_dce_stub_data_buffer_id] == NULL) {
        result = 0;
        goto end;
    }
    result &= (s->sm_lists_tail[g_dce_stub_data_buffer_id]->type == DETECT_CONTENT);
    result &= (s->sm_lists[DETECT_SM_LIST_PMATCH] == NULL);
    data = (DetectContentData *)s->sm_lists_tail[g_dce_stub_data_buffer_id]->ctx;
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
    if (s->sm_lists_tail[g_dce_stub_data_buffer_id] != NULL) {
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
static int DetectContentParseTest20(void)
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
static int DetectContentParseTest21(void)
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
static int DetectContentParseTest22(void)
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
static int DetectContentParseTest23(void)
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
static int DetectContentParseTest24(void)
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
static int DetectContentParseTest25(void)
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
static int DetectContentParseTest26(void)
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
static int DetectContentParseTest27(void)
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
static int DetectContentParseTest28(void)
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
static int DetectContentParseTest29(void)
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
static int DetectContentParseTest30(void)
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
static int DetectContentParseTest31(void)
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
static int DetectContentParseTest32(void)
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
static int DetectContentParseTest33(void)
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
static int DetectContentParseTest34(void)
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
static int DetectContentParseTest35(void)
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

    if (de_ctx->sig_list->sm_lists[g_file_data_buffer_id] == NULL) {
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

    if (de_ctx->sig_list->sm_lists[g_file_data_buffer_id] == NULL) {
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

    if (de_ctx->sig_list->sm_lists[g_file_data_buffer_id] == NULL) {
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

static int SigTestPositiveTestContent(const char *rule, uint8_t *buf)
{
    uint16_t buflen = strlen((char *)buf);
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;

    memset(&th_v, 0, sizeof(th_v));
    Packet *p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);
    FAIL_IF_NULL(p);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, rule);
    FAIL_IF_NULL(de_ctx->sig_list);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);
    FAIL_IF_NULL(det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    FAIL_IF(PacketAlertCheck(p, 1) != 1);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    UTHFreePackets(&p, 1);
    PASS;
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

    if (de_ctx->sig_list->sm_lists[g_file_data_buffer_id] == NULL) {
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

    if (de_ctx->sig_list->sm_lists[g_file_data_buffer_id] == NULL) {
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

static int DetectContentParseTest41(void)
{
    int result = 1;
    DetectContentData *cd = NULL;
    int patlen = 255;
    char *teststring = SCMalloc(sizeof(char) * (patlen + 1));
    if (unlikely(teststring == NULL))
        return 0;
    int idx = 0;
    for (int i = 0; i < patlen; idx++, i++) {
        teststring[idx] = 'a';
    }
    teststring[idx++] = '\0';

    uint16_t spm_matcher = SinglePatternMatchDefaultMatcher();
    SpmGlobalThreadCtx *spm_global_thread_ctx = SpmInitGlobalThreadCtx(spm_matcher);
    FAIL_IF(spm_global_thread_ctx == NULL);

    cd = DetectContentParse(spm_global_thread_ctx, teststring);
    if (cd == NULL) {
        SCLogDebug("expected not NULL");
        result = 0;
    }

    SpmDestroyGlobalThreadCtx(spm_global_thread_ctx);
    SCFree(teststring);
    DetectContentFree(NULL, cd);
    return result;
}

/**
 * Tests that content lengths > 255 are supported.
 */
static int DetectContentParseTest42(void)
{
    int result = 1;
    DetectContentData *cd = NULL;
    int patlen = 256;
    char *teststring = SCMalloc(sizeof(char) * (patlen + 1));
    if (unlikely(teststring == NULL))
        return 0;
    int idx = 0;
    for (int i = 0; i < patlen; idx++, i++) {
        teststring[idx] = 'a';
    }
    teststring[idx++] = '\0';

    uint16_t spm_matcher = SinglePatternMatchDefaultMatcher();
    SpmGlobalThreadCtx *spm_global_thread_ctx = SpmInitGlobalThreadCtx(spm_matcher);
    FAIL_IF(spm_global_thread_ctx == NULL);

    cd = DetectContentParse(spm_global_thread_ctx, teststring);
    if (cd == NULL) {
        SCLogDebug("expected not NULL");
        result = 0;
    }

    SpmDestroyGlobalThreadCtx(spm_global_thread_ctx);
    SCFree(teststring);
    DetectContentFree(NULL, cd);
    return result;
}

static int DetectContentParseTest43(void)
{
    int result = 1;
    DetectContentData *cd = NULL;
    int patlen = 258;
    char *teststring = SCMalloc(sizeof(char) * (patlen + 1));
    if (unlikely(teststring == NULL))
        return 0;
    int idx = 0;
    teststring[idx++] = '|';
    teststring[idx++] = '4';
    teststring[idx++] = '6';
    teststring[idx++] = '|';
    for (int i = 0; i < (patlen - 4); idx++, i++) {
        teststring[idx] = 'a';
    }
    teststring[idx++] = '\0';

    uint16_t spm_matcher = SinglePatternMatchDefaultMatcher();
    SpmGlobalThreadCtx *spm_global_thread_ctx = SpmInitGlobalThreadCtx(spm_matcher);
    FAIL_IF(spm_global_thread_ctx == NULL);

    cd = DetectContentParse(spm_global_thread_ctx, teststring);
    if (cd == NULL) {
        SCLogDebug("expected not NULL");
        result = 0;
    }

    SpmDestroyGlobalThreadCtx(spm_global_thread_ctx);
    SCFree(teststring);
    DetectContentFree(NULL, cd);
    return result;
}

/**
 * Tests that content lengths > 255 are supported.
 */
static int DetectContentParseTest44(void)
{
    int result = 1;
    DetectContentData *cd = NULL;
    int patlen = 259;
    char *teststring = SCMalloc(sizeof(char) * (patlen + 1));
    if (unlikely(teststring == NULL))
        return 0;
    int idx = 0;
    teststring[idx++] = '|';
    teststring[idx++] = '4';
    teststring[idx++] = '6';
    teststring[idx++] = '|';
    for (int i = 0; i < (patlen - 4); idx++, i++) {
        teststring[idx] = 'a';
    }
    teststring[idx++] = '\0';

    uint16_t spm_matcher = SinglePatternMatchDefaultMatcher();
    SpmGlobalThreadCtx *spm_global_thread_ctx = SpmInitGlobalThreadCtx(spm_matcher);
    FAIL_IF(spm_global_thread_ctx == NULL);

    cd = DetectContentParse(spm_global_thread_ctx, teststring);
    if (cd == NULL) {
        SCLogDebug("expected not NULL");
        result = 0;
    }

    SpmDestroyGlobalThreadCtx(spm_global_thread_ctx);
    SCFree(teststring);
    DetectContentFree(NULL, cd);
    return result;
}

/**
 * \test Parsing test to check for unescaped quote within content section
 */
static int DetectContentParseTest45(void)
{
    DetectEngineCtx *de_ctx = NULL;

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert tcp any any -> any any "
                               "(msg:\"test\"; content:\"|ff|\" content:\"TEST\"; sid:1;)");
    FAIL_IF_NOT_NULL(de_ctx->sig_list);

    DetectEngineCtxFree(de_ctx);

    PASS;
}

static int SigTestNegativeTestContent(const char *rule, uint8_t *buf)
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
    return SigTestPositiveTestContent("alert tcp any any -> any any "
            "(msg:\"HTTP URI cap\"; content:!\"GES\"; sid:1;)",

            (uint8_t *)"GET /one/ HTTP/1.1\r\n Host: one.example.org\r\n\r\n\r\n"
            "GET /two/ HTTP/1.1\r\nHost: two.example.org\r\n\r\n\r\n");
}

/**
 * \test crash condition: as packet has no direction, it defaults to toclient
 *       in stream ctx inspection of packet. There a null ptr deref happens
 * We don't care about the match/nomatch here.
 */
static int SigTest41aTestNegatedContent(void)
{
    (void)SigTestPositiveTestContent("alert tcp any any -> any any (msg:\"HTTP URI cap\"; flow:to_server; content:\"GET\"; sid:1;)", (uint8_t *)"GET /one/ HTTP/1.1\r\n Host: one.example.org\r\n\r\n\r\nGET /two/ HTTP/1.1\r\nHost: two.example.org\r\n\r\n\r\n");
    return 1;
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
    return SigTestNegativeTestContent("alert tcp any any -> any any (content:\"one\"; content:!\"fourty\"; within:52; sid:1;)", (uint8_t *)"one four nine fourteen twentythree thirtyfive fourtysix fiftysix");
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
    if (UTHPacketMatchSigMpm(p, sig, MPM_AC) == 0) {
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
    if (UTHPacketMatchSigMpm(p, sig, MPM_AC) == 0) {
        result = 0;
        goto end;
    }

    result = 1;
end:
    if (p != NULL)
        UTHFreePacket(p);
    return result;
}

static int DetectLongContentTestCommon(const char *sig, uint32_t sid)
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
    const char *sig = "alert tcp any any -> any any (msg:\"Test Rule\"; content:\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"; sid:1;)";

    return DetectLongContentTestCommon(sig, 1);
}

static int DetectLongContentTest2(void)
{
    /* Signature with 512 A's. */
    const char *sig = "alert tcp any any -> any any (msg:\"Test Rule\"; content:\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"; sid:1;)";

    return DetectLongContentTestCommon(sig, 1);
}

static int DetectLongContentTest3(void)
{
    /* Signature with 513 A's. */
    const char *sig = "alert tcp any any -> any any (msg:\"Test Rule\"; content:\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"; sid:1;)";

    return !DetectLongContentTestCommon(sig, 1);
}

static int DetectBadBinContent(void)
{
    DetectEngineCtx *de_ctx = NULL;
    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;
    FAIL_IF_NOT_NULL(DetectEngineAppendSig(
            de_ctx, "alert tcp any any -> any any (msg:\"test\"; content:\"|a|\"; sid:1;)"));
    FAIL_IF_NOT_NULL(DetectEngineAppendSig(
            de_ctx, "alert tcp any any -> any any (msg:\"test\"; content:\"|aa b|\"; sid:1;)"));
    FAIL_IF_NOT_NULL(DetectEngineAppendSig(
            de_ctx, "alert tcp any any -> any any (msg:\"test\"; content:\"|aa bz|\"; sid:1;)"));
    /* https://redmine.openinfosecfoundation.org/issues/5201 */
    FAIL_IF_NOT_NULL(DetectEngineAppendSig(
            de_ctx, "alert tcp any any -> any any (msg:\"test\"; content:\"|22 2 22|\"; sid:1;)"));
    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \brief this function registers unit tests for DetectContent
 */
static void DetectContentRegisterTests(void)
{
    g_file_data_buffer_id = DetectBufferTypeGetByName("file_data");
    g_dce_stub_data_buffer_id = DetectBufferTypeGetByName("dce_stub_data");

    UtRegisterTest("DetectContentDepthTest01", DetectContentDepthTest01);

    UtRegisterTest("DetectContentParseTest01", DetectContentParseTest01);
    UtRegisterTest("DetectContentParseTest02", DetectContentParseTest02);
    UtRegisterTest("DetectContentParseTest03", DetectContentParseTest03);
    UtRegisterTest("DetectContentParseTest04", DetectContentParseTest04);
    UtRegisterTest("DetectContentParseTest05", DetectContentParseTest05);
    UtRegisterTest("DetectContentParseTest06", DetectContentParseTest06);
    UtRegisterTest("DetectContentParseTest07", DetectContentParseTest07);
    UtRegisterTest("DetectContentParseTest08", DetectContentParseTest08);
    UtRegisterTest("DetectContentParseTest09", DetectContentParseTest09);
    UtRegisterTest("DetectContentParseTest17", DetectContentParseTest17);
    UtRegisterTest("DetectContentParseTest18", DetectContentParseTest18);
    UtRegisterTest("DetectContentParseTest19", DetectContentParseTest19);
    UtRegisterTest("DetectContentParseTest20", DetectContentParseTest20);
    UtRegisterTest("DetectContentParseTest21", DetectContentParseTest21);
    UtRegisterTest("DetectContentParseTest22", DetectContentParseTest22);
    UtRegisterTest("DetectContentParseTest23", DetectContentParseTest23);
    UtRegisterTest("DetectContentParseTest24", DetectContentParseTest24);
    UtRegisterTest("DetectContentParseTest25", DetectContentParseTest25);
    UtRegisterTest("DetectContentParseTest26", DetectContentParseTest26);
    UtRegisterTest("DetectContentParseTest27", DetectContentParseTest27);
    UtRegisterTest("DetectContentParseTest28", DetectContentParseTest28);
    UtRegisterTest("DetectContentParseTest29", DetectContentParseTest29);
    UtRegisterTest("DetectContentParseTest30", DetectContentParseTest30);
    UtRegisterTest("DetectContentParseTest31", DetectContentParseTest31);
    UtRegisterTest("DetectContentParseTest32", DetectContentParseTest32);
    UtRegisterTest("DetectContentParseTest33", DetectContentParseTest33);
    UtRegisterTest("DetectContentParseTest34", DetectContentParseTest34);
    UtRegisterTest("DetectContentParseTest35", DetectContentParseTest35);
    UtRegisterTest("DetectContentParseTest36", DetectContentParseTest36);
    UtRegisterTest("DetectContentParseTest37", DetectContentParseTest37);
    UtRegisterTest("DetectContentParseTest38", DetectContentParseTest38);
    UtRegisterTest("DetectContentParseTest39", DetectContentParseTest39);
    UtRegisterTest("DetectContentParseTest40", DetectContentParseTest40);
    UtRegisterTest("DetectContentParseTest41", DetectContentParseTest41);
    UtRegisterTest("DetectContentParseTest42", DetectContentParseTest42);
    UtRegisterTest("DetectContentParseTest43", DetectContentParseTest43);
    UtRegisterTest("DetectContentParseTest44", DetectContentParseTest44);
    UtRegisterTest("DetectContentParseTest45", DetectContentParseTest45);

    /* The reals */
    UtRegisterTest("DetectContentLongPatternMatchTest01",
                   DetectContentLongPatternMatchTest01);
    UtRegisterTest("DetectContentLongPatternMatchTest02",
                   DetectContentLongPatternMatchTest02);
    UtRegisterTest("DetectContentLongPatternMatchTest03",
                   DetectContentLongPatternMatchTest03);
    UtRegisterTest("DetectContentLongPatternMatchTest04",
                   DetectContentLongPatternMatchTest04);
    UtRegisterTest("DetectContentLongPatternMatchTest05",
                   DetectContentLongPatternMatchTest05);
    UtRegisterTest("DetectContentLongPatternMatchTest06",
                   DetectContentLongPatternMatchTest06);
    UtRegisterTest("DetectContentLongPatternMatchTest07",
                   DetectContentLongPatternMatchTest07);
    UtRegisterTest("DetectContentLongPatternMatchTest08",
                   DetectContentLongPatternMatchTest08);
    UtRegisterTest("DetectContentLongPatternMatchTest09",
                   DetectContentLongPatternMatchTest09);
    UtRegisterTest("DetectContentLongPatternMatchTest10",
                   DetectContentLongPatternMatchTest10);
    UtRegisterTest("DetectContentLongPatternMatchTest11",
                   DetectContentLongPatternMatchTest11);

    /* Negated content tests */
    UtRegisterTest("SigTest41TestNegatedContent", SigTest41TestNegatedContent);
    UtRegisterTest("SigTest41aTestNegatedContent",
                   SigTest41aTestNegatedContent);
    UtRegisterTest("SigTest42TestNegatedContent", SigTest42TestNegatedContent);
    UtRegisterTest("SigTest43TestNegatedContent", SigTest43TestNegatedContent);
    UtRegisterTest("SigTest44TestNegatedContent", SigTest44TestNegatedContent);
    UtRegisterTest("SigTest45TestNegatedContent", SigTest45TestNegatedContent);
    UtRegisterTest("SigTest46TestNegatedContent", SigTest46TestNegatedContent);
    UtRegisterTest("SigTest47TestNegatedContent", SigTest47TestNegatedContent);
    UtRegisterTest("SigTest48TestNegatedContent", SigTest48TestNegatedContent);
    UtRegisterTest("SigTest49TestNegatedContent", SigTest49TestNegatedContent);
    UtRegisterTest("SigTest50TestNegatedContent", SigTest50TestNegatedContent);
    UtRegisterTest("SigTest51TestNegatedContent", SigTest51TestNegatedContent);
    UtRegisterTest("SigTest52TestNegatedContent", SigTest52TestNegatedContent);
    UtRegisterTest("SigTest53TestNegatedContent", SigTest53TestNegatedContent);
    UtRegisterTest("SigTest54TestNegatedContent", SigTest54TestNegatedContent);
    UtRegisterTest("SigTest55TestNegatedContent", SigTest55TestNegatedContent);
    UtRegisterTest("SigTest56TestNegatedContent", SigTest56TestNegatedContent);
    UtRegisterTest("SigTest57TestNegatedContent", SigTest57TestNegatedContent);
    UtRegisterTest("SigTest58TestNegatedContent", SigTest58TestNegatedContent);
    UtRegisterTest("SigTest59TestNegatedContent", SigTest59TestNegatedContent);
    UtRegisterTest("SigTest60TestNegatedContent", SigTest60TestNegatedContent);
    UtRegisterTest("SigTest61TestNegatedContent", SigTest61TestNegatedContent);
    UtRegisterTest("SigTest62TestNegatedContent", SigTest62TestNegatedContent);
    UtRegisterTest("SigTest63TestNegatedContent", SigTest63TestNegatedContent);
    UtRegisterTest("SigTest64TestNegatedContent", SigTest64TestNegatedContent);
    UtRegisterTest("SigTest65TestNegatedContent", SigTest65TestNegatedContent);
    UtRegisterTest("SigTest66TestNegatedContent", SigTest66TestNegatedContent);
    UtRegisterTest("SigTest67TestNegatedContent", SigTest67TestNegatedContent);
    UtRegisterTest("SigTest68TestNegatedContent", SigTest68TestNegatedContent);
    UtRegisterTest("SigTest69TestNegatedContent", SigTest69TestNegatedContent);
    UtRegisterTest("SigTest70TestNegatedContent", SigTest70TestNegatedContent);
    UtRegisterTest("SigTest71TestNegatedContent", SigTest71TestNegatedContent);
    UtRegisterTest("SigTest72TestNegatedContent", SigTest72TestNegatedContent);
    UtRegisterTest("SigTest73TestNegatedContent", SigTest73TestNegatedContent);
    UtRegisterTest("SigTest74TestNegatedContent", SigTest74TestNegatedContent);
    UtRegisterTest("SigTest75TestNegatedContent", SigTest75TestNegatedContent);

    UtRegisterTest("SigTest76TestBug134", SigTest76TestBug134);
    UtRegisterTest("SigTest77TestBug139", SigTest77TestBug139);

    UtRegisterTest("DetectLongContentTest1", DetectLongContentTest1);
    UtRegisterTest("DetectLongContentTest2", DetectLongContentTest2);
    UtRegisterTest("DetectLongContentTest3", DetectLongContentTest3);

    UtRegisterTest("DetectBadBinContent", DetectBadBinContent);
}
#endif /* UNITTESTS */
