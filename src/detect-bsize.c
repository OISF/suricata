/* Copyright (C) 2017-2022 Open Information Security Foundation
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
#include "detect-content.h"
#include "detect-engine-uint.h"

#include "detect-bsize.h"

#include "util-misc.h"

/*prototypes*/
static int DetectBsizeSetup (DetectEngineCtx *, Signature *, const char *);
static void DetectBsizeFree (DetectEngineCtx *, void *);
static int SigParseGetMaxBsize(const DetectU64Data *bsz);
#ifdef UNITTESTS
static void DetectBsizeRegisterTests (void);
#endif

bool DetectBsizeValidateContentCallback(Signature *s, const SignatureInitDataBuffer *b)
{
    int bsize = -1;
    const DetectU64Data *bsz;
    for (const SigMatch *sm = b->head; sm != NULL; sm = sm->next) {
        if (sm->type == DETECT_BSIZE) {
            bsz = (const DetectU64Data *)sm->ctx;
            bsize = SigParseGetMaxBsize(bsz);
            break;
        }
    }

    if (bsize == -1) {
        return true;
    }

    uint64_t needed;
    if (bsize >= 0) {
        int len, offset;
        SigParseRequiredContentSize(s, bsize, b->head, &len, &offset);
        SCLogDebug("bsize: %d; len: %d; offset: %d [%s]", bsize, len, offset, s->sig_str);
        needed = len;
        if (len > bsize) {
            goto value_error;
        }
        if ((len + offset) > bsize) {
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

#if UNITTESTS
/**
 * \brief This function is used to parse bsize options passed via bsize: keyword
 *
 * \param bsizestr Pointer to the user provided bsize options
 *
 * \retval bsized pointer to DetectU64Data on success
 * \retval NULL on failure
 */

static DetectU64Data *DetectBsizeParse(const char *str)
{
    return DetectU64Parse(str);
}
#endif

static int SigParseGetMaxBsize(const DetectU64Data *bsz)
{
    switch (bsz->mode) {
        case DETECT_UINT_LT:
        case DETECT_UINT_EQ:
            return bsz->arg1;
        case DETECT_UINT_RA:
            return bsz->arg2;
        case DETECT_UINT_GT:
        default:
            SCReturnInt(-2);
    }
    SCReturnInt(-1);
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
        goto error;

    SigMatch *prev_pm = DetectGetLastSMFromLists(s, DETECT_CONTENT, -1);

    if (prev_pm != NULL && prev_pm->type == DETECT_CONTENT) {
        SCLogNotice("applying to content");
        DetectContentData *cd = (DetectContentData *)prev_pm->ctx;
        if (bsz->mode == DETECT_UINT_EQ) {
            if (bsz->arg1 == cd->content_len) {
                SCLogNotice("adding end_with");
                cd->flags |= DETECT_CONTENT_ENDS_WITH;
            } else if (cd->depth == 0 || cd->depth > bsz->arg1) {
                SCLogNotice("adding depth");
                cd->depth = bsz->arg1;
                cd->flags |= DETECT_CONTENT_DEPTH;
            } else {
                goto add_sm;
            }
            DetectBsizeFree(de_ctx, bsz);
            // $3 = {content = 0x5555578d3ed8 "yundol0727.kro.kr", content_len = 0x11, replace_len = 0x0, fp_chop_len = 0x0, fp_chop_offset = 0x0, flags = 0x400, id = 0x0, depth = 0x0, offset = 0x0, distance = 0x0, within = 0x0, spm_ctx = 0x55555678a070, replace = 0x0}
            SCReturnInt(0);
        }
    }
add_sm:

    SigMatch *sm = SigMatchAppendSMToList(de_ctx, s, DETECT_BSIZE, (SigMatchCtx *)bsz, list);
    if (sm == NULL) {
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
    rs_detect_u64_free(bsz);
}

#ifdef UNITTESTS
#include "tests/detect-bsize.c"
#endif
