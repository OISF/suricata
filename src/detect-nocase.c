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
#include "decode.h"

#include "detect.h"
#include "detect-parse.h"

#include "flow-var.h"

#include "detect-content.h"
#include "detect-uricontent.h"
#include "detect-pcre.h"
#include "detect-http-client-body.h"
#include "detect-http-cookie.h"
#include "detect-http-header.h"
#include "detect-http-method.h"
#include "detect-http-uri.h"

#include "util-debug.h"

static int DetectNocaseSetup (DetectEngineCtx *, Signature *, char *);

void DetectNocaseRegister(void)
{
    sigmatch_table[DETECT_NOCASE].name = "nocase";
    sigmatch_table[DETECT_NOCASE].desc = "modify content match to be case insensitive";
    sigmatch_table[DETECT_NOCASE].url = "https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Payload_keywords#Nocase";
    sigmatch_table[DETECT_NOCASE].Match = NULL;
    sigmatch_table[DETECT_NOCASE].Setup = DetectNocaseSetup;
    sigmatch_table[DETECT_NOCASE].Free  = NULL;
    sigmatch_table[DETECT_NOCASE].RegisterTests = NULL;

    sigmatch_table[DETECT_NOCASE].flags |= SIGMATCH_NOOPT;
    sigmatch_table[DETECT_NOCASE].flags |= SIGMATCH_PAYLOAD;
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
static int DetectNocaseSetup (DetectEngineCtx *de_ctx, Signature *s, char *nullstr)
{
    SCEnter();

    SigMatch *pm = NULL;
    int ret = -1;

    if (nullstr != NULL) {
        SCLogError(SC_ERR_INVALID_VALUE, "nocase has value");
        goto end;
    }

    /* retrive the sm to apply the depth against */
    if (s->list != DETECT_SM_LIST_NOTSET) {
        pm = SigMatchGetLastSMFromLists(s, 2, DETECT_CONTENT, s->sm_lists_tail[s->list]);
    } else {
        pm =  SigMatchGetLastSMFromLists(s, 28,
                                         DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_PMATCH],
                                         DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_UMATCH],
                                         DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_HRUDMATCH],
                                         DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_HCBDMATCH],
                                         DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_FILEDATA],
                                         DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_HHDMATCH],
                                         DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_HRHDMATCH],
                                         DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_HMDMATCH],
                                         DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_HCDMATCH],
                                         DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_HSCDMATCH],
                                         DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_HSMDMATCH],
                                         DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_HUADMATCH],
                                         DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_HHHDMATCH],
                                         DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_HRHHDMATCH]);
    }
    if (pm == NULL) {
        SCLogError(SC_ERR_NOCASE_MISSING_PATTERN, "nocase needs "
                   "preceding content, uricontent option, http_client_body, "
                   "http_server_body, http_header option, http_raw_header option, "
                   "http_method option, http_cookie, http_raw_uri, "
                   "http_stat_msg, http_stat_code, http_user_agent or "
                   "file_data/dce_stub_data sticky buffer options");
        goto end;
    }


    /* verify other conditions. */
    DetectContentData *cd = (DetectContentData *)pm->ctx;;

    if (cd->flags & DETECT_CONTENT_NOCASE) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "can't use multiple nocase modifiers with the same content");
        goto end;
    }
    cd->flags |= DETECT_CONTENT_NOCASE;
    /* Recreate the context with nocase chars */
    BoyerMooreCtxToNocase(cd->bm_ctx, cd->content, cd->content_len);

    ret = 0;
 end:
    SCReturnInt(ret);
}
