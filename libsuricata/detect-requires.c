/* Copyright (C) 2023 Open Information Security Foundation
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

#include "detect-requires.h"
#include "suricata-common.h"
#include "detect-engine.h"
#include "rust.h"

static int DetectRequiresSetup(DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    if (de_ctx->requirements == NULL) {
        de_ctx->requirements = (void *)SCDetectRequiresStatusNew();
        BUG_ON(de_ctx->requirements == NULL);
    }

    const char *errmsg = NULL;
    int res = SCDetectCheckRequires(rawstr, PROG_VER, &errmsg, de_ctx->requirements);
    if (res == -1) {
        // The requires expression is bad, log an error.
        SCLogError("%s: %s", errmsg, rawstr);
        de_ctx->sigerror = errmsg;
    } else if (res < -1) {
        // This Suricata instance didn't meet the requirements.
        SCLogInfo("Suricata did not meet the rule requirements: %s: %s", errmsg, rawstr);
        return -4;
    }
    return res;
}

void DetectRequiresRegister(void)
{
    sigmatch_table[DETECT_REQUIRES].name = "requires";
    sigmatch_table[DETECT_REQUIRES].desc = "require Suricata version or features";
    sigmatch_table[DETECT_REQUIRES].url = "/rules/meta-keywords.html#requires";
    sigmatch_table[DETECT_REQUIRES].Setup = DetectRequiresSetup;
}
