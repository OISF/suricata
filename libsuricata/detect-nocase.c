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
#include "suricata.h"
#include "decode.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-content.h"
#include "detect-nocase.h"

#include "util-debug.h"

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
        SCLogError("nocase has value");
        goto end;
    }

    /* retrieve the sm to apply the nocase against */
    pm = DetectGetLastSMFromLists(s, DETECT_CONTENT, -1);
    if (pm == NULL) {
        SCLogError("nocase needs "
                   "preceding content option");
        goto end;
    }

    DetectContentData *cd = (DetectContentData *)pm->ctx;
    ret = DetectContentConvertToNocase(de_ctx, cd);
 end:
    SCReturnInt(ret);
}
