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
 * \author  Victor Julien <victor@inliniac.net>
 * \author Gurvinder Singh <gurvindersinghdahiya@gmail.com>
 *
 * Simple uricontent match part of the detection engine.
 */

#include "suricata-common.h"
#include "decode.h"
#include "detect.h"
#include "detect-content.h"
#include "detect-http-uri.h"
#include "detect-uricontent.h"
#include "detect-engine-mpm.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-state.h"
#include "flow.h"
#include "detect-flow.h"
#include "flow-var.h"
#include "flow-util.h"
#include "threads.h"

#include "stream-tcp.h"
#include "stream.h"
#include "app-layer.h"
#include "app-layer-parser.h"
#include "app-layer-protos.h"
#include "app-layer-htp.h"

#include "util-mpm.h"
#include "util-print.h"
#include "util-debug.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-spm.h"
#include "conf.h"

/* prototypes */
static int DetectUricontentSetup(DetectEngineCtx *, Signature *, const char *);
static void DetectUricontentFree(DetectEngineCtx *de_ctx, void *);

static int g_http_uri_buffer_id = 0;

/**
 * \brief Registration function for uricontent: keyword
 */
void DetectUricontentRegister (void)
{
    sigmatch_table[DETECT_URICONTENT].name = "uricontent";
    sigmatch_table[DETECT_URICONTENT].desc = "legacy keyword to match on the request URI buffer";
    sigmatch_table[DETECT_URICONTENT].url = "/rules/http-keywords.html#uricontent";
    sigmatch_table[DETECT_URICONTENT].Match = NULL;
    sigmatch_table[DETECT_URICONTENT].Setup = DetectUricontentSetup;
    sigmatch_table[DETECT_URICONTENT].Free = DetectUricontentFree;
    sigmatch_table[DETECT_URICONTENT].flags = (SIGMATCH_QUOTES_MANDATORY|SIGMATCH_HANDLE_NEGATION);
    sigmatch_table[DETECT_URICONTENT].alternative = DETECT_HTTP_URI;

    g_http_uri_buffer_id = DetectBufferTypeRegister("http_uri");
}

/**
 * \brief this function will Free memory associated with DetectContentData
 *
 * \param cd pointer to DetectUricontentData
 */
void DetectUricontentFree(DetectEngineCtx *de_ctx, void *ptr)
{
    SCEnter();
    DetectContentData *cd = (DetectContentData *)ptr;

    if (cd == NULL)
        SCReturn;

    SpmDestroyCtx(cd->spm_ctx);
    SCFree(cd);

    SCReturn;
}

/**
 * \brief Creates a SigMatch for the uricontent keyword being sent as argument,
 *        and appends it to the Signature(s).
 *
 * \param de_ctx    Pointer to the detection engine context
 * \param s         Pointer to signature for the current Signature being parsed
 *                  from the rules
 * \param contentstr  Pointer to the string holding the keyword value
 *
 * \retval 0 on success, -1 on failure
 */
int DetectUricontentSetup(DetectEngineCtx *de_ctx, Signature *s, const char *contentstr)
{
    SCEnter();

    const char *legacy = NULL;
    if (SCConfGet("legacy.uricontent", &legacy) == 1) {
        if (strcasecmp("disabled", legacy) == 0) {
            SCLogError("uricontent deprecated.  To "
                       "use a rule with \"uricontent\", either set the "
                       "option - \"legacy.uricontent\" in the conf to "
                       "\"enabled\" OR replace uricontent with "
                       "\'content:%s; http_uri;\'.",
                    contentstr);
            goto error;
        } else if (strcasecmp("enabled", legacy) == 0) {
            ;
        } else {
            SCLogError("Invalid value found "
                       "for legacy.uricontent - \"%s\".  Valid values are "
                       "\"enabled\" OR \"disabled\".",
                    legacy);
            goto error;
        }
    }

    if (DetectContentSetup(de_ctx, s, contentstr) < 0)
        goto error;

    if (DetectHttpUriSetup(de_ctx, s, NULL) < 0)
        goto error;

    SCReturnInt(0);
error:
    SCReturnInt(-1);
}
