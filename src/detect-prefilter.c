/* Copyright (C) 2007-2016 Open Information Security Foundation
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
 * Implements the prefilter keyword
 */

#include "suricata-common.h"
#include "decode.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-content.h"
#include "detect-prefilter.h"
#include "util-debug.h"

static int DetectPrefilterSetup (DetectEngineCtx *, Signature *, const char *);

void DetectPrefilterRegister(void)
{
    sigmatch_table[DETECT_PREFILTER].name = "prefilter";
    sigmatch_table[DETECT_PREFILTER].desc = "force a condition to be used as prefilter";
    sigmatch_table[DETECT_PREFILTER].Match = NULL;
    sigmatch_table[DETECT_PREFILTER].Setup = DetectPrefilterSetup;
    sigmatch_table[DETECT_PREFILTER].Free  = NULL;
    sigmatch_table[DETECT_PREFILTER].RegisterTests = NULL;

    sigmatch_table[DETECT_PREFILTER].flags |= SIGMATCH_NOOPT;
}

/**
 *  \internal
 *  \brief Apply the prefilter keyword to the last match
 *  \param det_ctx detection engine ctx
 *  \param s signature
 *  \param nullstr should be null
 *  \retval 0 ok
 *  \retval -1 failure
 */
static int DetectPrefilterSetup (DetectEngineCtx *de_ctx, Signature *s, const char *nullstr)
{
    SCEnter();

    SigMatch *sm = NULL;
    int ret = -1;

    if (nullstr != NULL) {
        SCLogError(SC_ERR_INVALID_VALUE, "prefilter has value");
        goto end;
    }

    if (s->flags & SIG_FLAG_PREFILTER) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "prefilter already set");
        goto end;
    }

    sm = DetectGetLastSM(s);
    if (sm == NULL) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "prefilter needs preceding match");
        goto end;
    }

    s->init_data->prefilter_sm = sm;
    s->flags |= SIG_FLAG_PREFILTER;

    /* if the sig match is content, prefilter should act like
     * 'fast_pattern' w/o options. */
    if (sm->type == DETECT_CONTENT) {
        DetectContentData *cd = (DetectContentData *)sm->ctx;
        if ((cd->flags & DETECT_CONTENT_NEGATED) &&
                ((cd->flags & DETECT_CONTENT_DISTANCE) ||
                 (cd->flags & DETECT_CONTENT_WITHIN) ||
                 (cd->flags & DETECT_CONTENT_OFFSET) ||
                 (cd->flags & DETECT_CONTENT_DEPTH)))
        {
            SCLogError(SC_ERR_INVALID_SIGNATURE, "prefilter; cannot be "
                    "used with negated content, along with relative modifiers");
            goto end;
        }
        cd->flags |= DETECT_CONTENT_FAST_PATTERN;
    }

    ret = 0;
 end:
    SCReturnInt(ret);
}
