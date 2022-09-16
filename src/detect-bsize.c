/* Copyright (C) 2017-2020 Open Information Security Foundation
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
#ifdef UNITTESTS
#endif

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-uint.h"

#include "detect-bsize.h"

/*prototypes*/
static int DetectBsizeSetup (DetectEngineCtx *, Signature *, const char *);
static void DetectBsizeFree (DetectEngineCtx *, void *);
#ifdef UNITTESTS
static void DetectBsizeRegisterTests (void);
#endif

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

/**
 * \brief this function is used to parse bsize data into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param bsizestr pointer to the user provided bsize options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectBsizeSetup (DetectEngineCtx *de_ctx, Signature *s, const char *sizestr)
{
    SCEnter();
    SigMatch *sm = NULL;

    if (DetectBufferGetActiveList(de_ctx, s) == -1)
        SCReturnInt(-1);

    int list = s->init_data->list;
    if (list == DETECT_SM_LIST_NOTSET)
        SCReturnInt(-1);

    DetectU64Data *bsz = DetectBsizeParse(sizestr);
    if (bsz == NULL)
        goto error;
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;
    sm->type = DETECT_BSIZE;
    sm->ctx = (void *)bsz;

    SigMatchAppendSMToList(s, sm, list);

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
