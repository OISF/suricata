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

#include "suricata-common.h"
#include "rust.h"
#include "detect-min-version.h"
#include "detect-engine.h"
#include "detect-parse.h"

static int DetectMinVersionSetup(DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    if (!rs_min_version_check(rawstr, PROG_VER)) {
        SCLogWarning("rule %u cannot be loaded by this Suricata version, requires %s, is %s", s->id,
                rawstr, PROG_VER);
        de_ctx->sigerror_once = true;
        return -4;
    }

    return 0;
}

void DetectSuricataMinVersionRegister(void)
{
    sigmatch_table[DETECT_SURICATA_MIN_VERSION].name = "min_version";
    sigmatch_table[DETECT_SURICATA_MIN_VERSION].desc = "requires a Suricata minimum version";
    sigmatch_table[DETECT_SURICATA_MIN_VERSION].url = "/rules/meta-keywords.html#min_version";
    sigmatch_table[DETECT_SURICATA_MIN_VERSION].Setup = DetectMinVersionSetup;
}
