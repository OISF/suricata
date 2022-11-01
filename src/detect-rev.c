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
 * Implements the rev keyword
 */

#include "suricata-common.h"
#include "detect.h"
#include "detect-rev.h"

static int DetectRevSetup (DetectEngineCtx *, Signature *, const char *);

void DetectRevRegister (void)
{
    sigmatch_table[DETECT_REV].name = "rev";
    sigmatch_table[DETECT_REV].desc = "set version of the rule";
    sigmatch_table[DETECT_REV].url = "/rules/meta.html#rev-revision";
    sigmatch_table[DETECT_REV].Setup = DetectRevSetup;
}

static int DetectRevSetup (DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    unsigned long rev = 0;
    char *endptr = NULL;
    rev = strtoul(rawstr, &endptr, 10);
    if (endptr == NULL || *endptr != '\0') {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "invalid character as arg "
                   "to rev keyword");
        goto error;
    }
    if (rev >= UINT_MAX) {
        SCLogError(SC_ERR_INVALID_NUMERIC_VALUE, "rev value to high, max %u", UINT_MAX);
        goto error;
    }
    if (rev == 0) {
        SCLogError(SC_ERR_INVALID_NUMERIC_VALUE, "rev value 0 is invalid");
        goto error;
    }
    if (s->rev > 0) {
        SCLogError(SC_ERR_INVALID_RULE_ARGUMENT, "duplicated 'rev' keyword detected");
        goto error;
    }

    s->rev = (uint32_t)rev;

    return 0;

 error:
    return -1;
}