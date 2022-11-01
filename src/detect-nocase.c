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
 * Implements the nocase keyword
 */

#include "suricata-common.h"

#include "detect-parse.h"
#include "detect-content.h"
#include "detect-nocase.h"

static int DetectNocaseSetup (DetectEngineCtx *, Signature *, const char *);

void DetectNocaseRegister(void)
{
    sigmatch_table[DETECT_NOCASE].name = "nocase";
    sigmatch_table[DETECT_NOCASE].desc = "modify content match to be case insensitive";
    sigmatch_table[DETECT_NOCASE].url = "/rules/payload-keywords.html#nocase";
    sigmatch_table[DETECT_NOCASE].Setup = DetectNocaseSetup;
    sigmatch_table[DETECT_NOCASE].flags |= SIGMATCH_NOOPT;
}

/**
 *  \internal
 *  \brief Apply the nocase keyword to the last pattern match, either content or uricontent
 *  \param det_ctx detection engine ctx
 *  \param s signature
 *  \param nullstr should be null
 *  \retval 0 ok
 *  \retval -1 failure
 */
static int DetectNocaseSetup (DetectEngineCtx *de_ctx, Signature *s, const char *nullstr)
{
    SCEnter();

    SigMatch *pm = NULL;
    int ret = -1;

    if (nullstr != NULL) {
        SCLogError(SC_ERR_INVALID_VALUE, "nocase has value");
        goto end;
    }

    /* retrive the sm to apply the nocase against */
    pm = DetectGetLastSMFromLists(s, DETECT_CONTENT, -1);
    if (pm == NULL) {
        SCLogError(SC_ERR_NOCASE_MISSING_PATTERN, "nocase needs "
                   "preceding content option");
        goto end;
    }

    /* verify other conditions. */
    DetectContentData *cd = (DetectContentData *)pm->ctx;;

    if (cd->flags & DETECT_CONTENT_NOCASE) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "can't use multiple nocase modifiers with the same content");
        goto end;
    }

    /* for consistency in later use (e.g. by MPM construction and hashing),
     * coerce the content string to lower-case. */
    for (uint8_t *c = cd->content; c < cd->content + cd->content_len; c++) {
        *c = u8_tolower(*c);
    }

    cd->flags |= DETECT_CONTENT_NOCASE;
    /* Recreate the context with nocase chars */
    SpmDestroyCtx(cd->spm_ctx);
    cd->spm_ctx = SpmInitCtx(cd->content, cd->content_len, 1,
                             de_ctx->spm_global_thread_ctx);
    if (cd->spm_ctx == NULL) {
        goto end;
    }

    ret = 0;
 end:
    SCReturnInt(ret);
}
