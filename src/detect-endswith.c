/* Copyright (C) 2007-2013 Open Information Security Foundation
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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */

#include "suricata-common.h"
#include "decode.h"
#include "detect.h"
#include "detect-parse.h"
#include "detect-content.h"
#include "util-debug.h"

static int DetectEndswithSetup(DetectEngineCtx *, Signature *, char *);

void DetectEndswithRegister(void)
{
    sigmatch_table[DETECT_ENDSWITH].name = "endswith";
    sigmatch_table[DETECT_ENDSWITH].desc = "checks if the content being matched is at the end of the buffer";
    sigmatch_table[DETECT_ENDSWITH].Match = NULL;
    sigmatch_table[DETECT_ENDSWITH].Setup = DetectEndswithSetup;
    sigmatch_table[DETECT_ENDSWITH].Free  = NULL;
    sigmatch_table[DETECT_ENDSWITH].RegisterTests = NULL;

    sigmatch_table[DETECT_ENDSWITH].flags |= SIGMATCH_NOOPT;
    sigmatch_table[DETECT_ENDSWITH].flags |= SIGMATCH_PAYLOAD;

    return;
}

static int DetectEndswithSetup(DetectEngineCtx *de_ctx, Signature *s, char *no_arg)
{
    if (no_arg != NULL) {
        SCLogError(SC_ERR_INVALID_VALUE, "endswith shouldn't be supplied "
                   "with any argument");
        return -1;
    }

    SigMatch *pm = SigMatchGetLastSMFromLists(s, 24,
            DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_PMATCH],
            DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_UMATCH],
            DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_HCBDMATCH],
            DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_HSBDMATCH],
            DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_HHDMATCH],
            DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_HRHDMATCH],
            DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_HMDMATCH],
            DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_HRUDMATCH],
            DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_HSMDMATCH],
            DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_HSCDMATCH],
            DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_HCDMATCH],
            DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_HUADMATCH]);
    if (pm == NULL) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "\"endswith\" needs a preceding "
                   "content, uricontent(http_uri), http_client_body, "
                   "http_server_body, http_header, http_method, http_uri, "
                   "http_cookie, http_raw_uri, http_stat_msg, http_stat_code "
                   "or http_user_agent option");
        return -1;
    }

    switch (pm->type) {
        case DETECT_CONTENT:
            if (((DetectContentData *)pm->ctx)->flags & DETECT_CONTENT_NEGATED) {
                SCLogError(SC_ERR_INVALID_SIGNATURE, "\"endswith\" cannot be "
                           "used with negated content.");
                return -1;
            }
            BUG_ON(sigmatch_table[DETECT_ISDATAAT].Setup(de_ctx, s, "!1, relative") == -1);

            break;
        default:
            BUG_ON(1);
    }

    return 0;
}
