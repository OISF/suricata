/* Copyright (C) 2017-2026 Open Information Security Foundation
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
 * Implements the bsize generic buffer length keyword
 */

#include "suricata-common.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-buffer.h"
#include "detect-content.h"
#include "detect-engine-uint.h"

#include "detect-bsize.h"

#include "util-misc.h"

/*prototypes*/
static int DetectBsizeSetup (DetectEngineCtx *, Signature *, const char *);
static void DetectBsizeFree (DetectEngineCtx *, void *);
static int SigParseGetMaxBsize(const DetectU64Data *bsz, uint64_t *bsize);
static bool SigBsizeBufferMaxBound(const SignatureInitDataBuffer *b, uint64_t *bound, bool *exact);
#ifdef UNITTESTS
static void DetectBsizeRegisterTests (void);
#endif

bool DetectBsizeValidateContentCallback(const Signature *s, const SignatureInitDataBuffer *b)
{
    uint64_t bsize;
    int retval = -1;
    const DetectU64Data *bsz;
    for (const SigMatch *sm = b->head; sm != NULL; sm = sm->next) {
        if (sm->type == DETECT_BSIZE) {
            bsz = (const DetectU64Data *)sm->ctx;
            retval = SigParseGetMaxBsize(bsz, &bsize);
            break;
        }
    }

    if (retval == -1) {
        return true;
    }

    uint64_t needed;
    if (retval == 0) {
        int len, offset;
        SigParseRequiredContentSize(s, bsize, b->head, &len, &offset);
        SCLogDebug("bsize: %" PRIu64 "; len: %d; offset: %d [%s]", bsize, len, offset, s->sig_str);
        needed = len;
        if ((uint64_t)len > bsize) {
            goto value_error;
        }
        if ((uint64_t)(len + offset) > bsize) {
            needed += offset;
            goto value_error;
        }
    }

    return true;
value_error:
    if (bsz->mode == DETECT_UINT_RA) {
        SCLogError("signature can't match as required content length %" PRIu64
                   " exceeds bsize range: %" PRIu64 "-%" PRIu64,
                needed, bsz->arg1, bsz->arg2);
    } else {
        SCLogError("signature can't match as required content length %" PRIu64
                   " exceeds bsize value: "
                   "%" PRIu64,
                needed, bsz->arg1);
    }
    return false;
}

/**
 * \brief Registration function for bsize: keyword
 */

void DetectBsizeRegister(void)
{
    sigmatch_table[DETECT_BSIZE].name = "bsize";
    sigmatch_table[DETECT_BSIZE].desc = "match on the length of a buffer";
    sigmatch_table[DETECT_BSIZE].url = "/rules/payload-keywords.html#bsize";
    sigmatch_table[DETECT_BSIZE].Match = NULL;
    sigmatch_table[DETECT_BSIZE].Setup = DetectBsizeSetup;
    sigmatch_table[DETECT_BSIZE].Free = DetectBsizeFree;
    sigmatch_table[DETECT_BSIZE].flags = SIGMATCH_SUPPORT_FIREWALL | SIGMATCH_INFO_UINT64;
#ifdef UNITTESTS
    sigmatch_table[DETECT_BSIZE].RegisterTests = DetectBsizeRegisterTests;
#endif
}

/** \brief bsize match function
 *
 *  \param ctx match ctx
 *  \param buffer_size size of the buffer
 *  \param eof is the buffer closed?
 *
 *  \retval r 1 match, 0 no match, -1 can't match
 */
int DetectBsizeMatch(const SigMatchCtx *ctx, const uint64_t buffer_size, bool eof)
{
    const DetectU64Data *bsz = (const DetectU64Data *)ctx;
    if (DetectU64Match(buffer_size, bsz)) {
        return 1;
    }
    switch (bsz->mode) {
        case DETECT_UINT_LTE:
            return -1;
        case DETECT_UINT_LT:
            return -1;

        case DETECT_UINT_GTE:
            // fallthrough
        case DETECT_UINT_GT:
            if (eof) {
                return -1;
            }
            return 0;

        case DETECT_UINT_EQ:
            if (buffer_size > bsz->arg1) {
                return -1;
            } else if (eof) {
                return -1;
            } else {
                return 0;
            }

        case DETECT_UINT_RA:
            if (buffer_size <= bsz->arg1 && eof) {
                return -1;
            } else if (buffer_size <= bsz->arg1) {
                return 0;
            } else if (buffer_size >= bsz->arg2) {
                return -1;
            }
    }
    return 0;
}

static int SigParseGetMaxBsize(const DetectU64Data *bsz, uint64_t *bsize)
{
    switch (bsz->mode) {
        case DETECT_UINT_LT:
        case DETECT_UINT_EQ:
            *bsize = bsz->arg1;
            SCReturnInt(0);
        case DETECT_UINT_RA:
            *bsize = bsz->arg2;
            SCReturnInt(0);
        case DETECT_UINT_GT:
        default:
            SCReturnInt(-2);
    }
    SCReturnInt(-1);
}

/**
 * \brief find the tightest usable bsize upper bound for a buffer
 *
 * A buffer may carry more than one bsize; the buffer must satisfy them all, so
 * the tightest (smallest) usable upper bound applies. bsize:>N yields no upper
 * bound and is ignored.
 *
 * \param b buffer to scan
 * \param bound set to the smallest usable upper bound on success
 * \param exact if non-NULL, set to true when that bound comes from an exact
 *              bsize (bsize:N)
 * \retval true a usable upper bound was found
 * \retval false no bsize with a usable upper bound (e.g. only bsize:>N)
 */
static bool SigBsizeBufferMaxBound(const SignatureInitDataBuffer *b, uint64_t *bound, bool *exact)
{
    uint64_t b_min = UINT64_MAX;
    bool found = false;
    bool is_exact = false;
    for (const SigMatch *sm = b->head; sm != NULL; sm = sm->next) {
        if (sm->type != DETECT_BSIZE)
            continue;

        const DetectU64Data *bsz = (const DetectU64Data *)sm->ctx;
        uint64_t cur;
        if (SigParseGetMaxBsize(bsz, &cur) != 0)
            continue;
        if (cur < b_min) {
            b_min = cur;
            is_exact = (bsz->mode == DETECT_UINT_EQ);
        }
        found = true;
    }

    if (!found)
        return false;

    *bound = b_min;
    if (exact != NULL)
        *exact = is_exact;
    return true;
}

/**
 * \brief apply each buffer's bsize upper bound to its content matches
 *
 * When a buffer carries a bsize keyword that yields a usable upper bound
 * (bsize:N, bsize:<N or bsize:N<>M), every content in that buffer can be
 * constrained to that depth: the content can't match beyond the end of the
 * buffer, and the buffer is at most \c bsize bytes long. This lets the mpm and
 * content inspection bound their search instead of scanning the whole buffer,
 * mirroring the dsize and urilen optimizations.
 *
 * As a stronger case, when an exact bsize (bsize:N) equals the length of a lone
 * content in the buffer, that content must span the whole buffer: it both
 * starts and ends it. Mark it startswith/endswith so the mpm anchoring and the
 * endswith inspection short-circuit apply, as Victor described in #4226.
 *
 * \param s signature whose buffers are processed
 */
void DetectBsizeApplyToContent(const Signature *s)
{
    for (uint32_t x = 0; x < s->init_data->buffer_index; x++) {
        const SignatureInitDataBuffer *b = &s->init_data->buffers[x];

        uint64_t bsize;
        bool exact;
        if (!SigBsizeBufferMaxBound(b, &bsize, &exact))
            continue;

        /* depth is a uint16_t; a larger bound can't be expressed as a depth */
        if (bsize > UINT16_MAX)
            continue;

        uint32_t content_cnt = 0;
        DetectContentData *single = NULL;
        for (SigMatch *sm = b->head; sm != NULL; sm = sm->next) {
            if (sm->type != DETECT_CONTENT)
                continue;

            DetectContentData *cd = (DetectContentData *)sm->ctx;
            if (cd == NULL)
                continue;

            content_cnt++;
            single = cd;

            if (cd->depth == 0 || cd->depth > (uint16_t)bsize) {
                cd->depth = (uint16_t)bsize;
                cd->flags |= DETECT_CONTENT_DEPTH;
                cd->flags |= DETECT_CONTENT_BSIZE2DEPTH;
                SCLogDebug("updated %u, content %u to have depth %u because of bsize.", s->id,
                        cd->id, cd->depth);
            }
        }

        /* exact bsize matching a lone content's length: the content fills the
         * buffer, so it starts and ends it. Skip if the content is anchored
         * elsewhere or negated, where that doesn't hold. */
        if (content_cnt == 1 && exact && single->content_len == (uint16_t)bsize &&
                (single->flags & (DETECT_CONTENT_OFFSET | DETECT_CONTENT_DISTANCE |
                                         DETECT_CONTENT_WITHIN | DETECT_CONTENT_NEGATED)) == 0) {
            single->depth = single->content_len;
            single->flags |=
                    DETECT_CONTENT_DEPTH | DETECT_CONTENT_STARTS_WITH | DETECT_CONTENT_ENDS_WITH;
            SCLogDebug("updated %u, content %u to startswith/endswith because of exact bsize %u.",
                    s->id, single->id, (uint16_t)bsize);
        }
    }
}

/**
 * \brief this function is used to parse bsize data into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param sizestr pointer to the user provided bsize options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectBsizeSetup (DetectEngineCtx *de_ctx, Signature *s, const char *sizestr)
{
    SCEnter();

    if (DetectBufferGetActiveList(de_ctx, s) == -1)
        SCReturnInt(-1);

    int list = s->init_data->list;
    if (list == DETECT_SM_LIST_NOTSET)
        SCReturnInt(-1);

    DetectU64Data *bsz = DetectU64Parse(sizestr);
    if (bsz == NULL)
        SCReturnInt(-1);

    if (SCSigMatchAppendSMToList(de_ctx, s, DETECT_BSIZE, (SigMatchCtx *)bsz, list) == NULL) {
        goto error;
    }

    SCReturnInt(0);

error:
    DetectBsizeFree(de_ctx, bsz);
    SCReturnInt(-1);
}

/**
 * \brief this function will free memory associated with DetectU64Data
 *
 * \param ptr pointer to DetectU64Data
 */
void DetectBsizeFree(DetectEngineCtx *de_ctx, void *ptr)
{
    if (ptr == NULL)
        return;

    DetectU64Data *bsz = (DetectU64Data *)ptr;
    SCDetectU64Free(bsz);
}

#ifdef UNITTESTS
#include "tests/detect-bsize.c"
#endif
