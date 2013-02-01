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

static int DetectStartswithSetup(DetectEngineCtx *, Signature *, char *);

void DetectStartswithRegister(void)
{
    sigmatch_table[DETECT_STARTSWITH].name = "startswith";
    sigmatch_table[DETECT_STARTSWITH].desc = "checks if the content being matched is at the start of the buffer";
    sigmatch_table[DETECT_STARTSWITH].Match = NULL;
    sigmatch_table[DETECT_STARTSWITH].Setup = DetectStartswithSetup;
    sigmatch_table[DETECT_STARTSWITH].Free  = NULL;
    sigmatch_table[DETECT_STARTSWITH].RegisterTests = NULL;

    sigmatch_table[DETECT_STARTSWITH].flags |= SIGMATCH_NOOPT;
    sigmatch_table[DETECT_STARTSWITH].flags |= SIGMATCH_PAYLOAD;

    return;
}

static int DetectStartswithSetup(DetectEngineCtx *de_ctx, Signature *s, char *no_arg)
{
    if (no_arg != NULL) {
        SCLogError(SC_ERR_INVALID_VALUE, "startswith shouldn't be supplied "
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
        SCLogError(SC_ERR_INVALID_SIGNATURE, "\"startswith\" needs a preceding "
                   "content, uricontent(http_uri), http_client_body, "
                   "http_server_body, http_header, http_method, http_uri, "
                   "http_cookie, http_raw_uri, http_stat_msg, http_stat_code "
                   "or http_user_agent option");
        return -1;
    }

    switch (pm->type) {
        case DETECT_CONTENT:
            {
                DetectContentData *cd = pm->ctx;
                if (cd->flags & DETECT_CONTENT_DEPTH ||
                    cd->flags & DETECT_CONTENT_OFFSET) {
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "\"startswith\" cannot be "
                               "used with \"depth\" or \"offset\" modified content.");
                    return -1;
                }
                char tmp_s[50];
                snprintf(tmp_s, sizeof(tmp_s), "%d", cd->content_len);
                BUG_ON(sigmatch_table[DETECT_DEPTH].Setup(de_ctx, s, tmp_s) == -1);
                cd->flags |= DETECT_CONTENT_STARTSWITH;

                break;
            }
        default:
            BUG_ON(1);
    }

    return 0;
}
