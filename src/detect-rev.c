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
#include "util-debug.h"
#include "util-error.h"

static int DetectRevSetup (DetectEngineCtx *, Signature *, char *);

void DetectRevRegister (void)
{
    sigmatch_table[DETECT_REV].name = "rev";
    sigmatch_table[DETECT_REV].desc = "set version of the rule";
    sigmatch_table[DETECT_REV].url = "https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Meta-settings#Rev-Revision";
    sigmatch_table[DETECT_REV].Match = NULL;
    sigmatch_table[DETECT_REV].Setup = DetectRevSetup;
    sigmatch_table[DETECT_REV].Free  = NULL;
    sigmatch_table[DETECT_REV].RegisterTests = NULL;
}

static int DetectRevSetup (DetectEngineCtx *de_ctx, Signature *s, char *rawstr)
{
    char *str = rawstr;
    char dubbed = 0;

    /* strip "'s */
    if (rawstr[0] == '\"' && rawstr[strlen(rawstr)-1] == '\"') {
        str = SCStrdup(rawstr+1);
        if (unlikely(str == NULL))
            return -1;

        str[strlen(rawstr)-2] = '\0';
        dubbed = 1;
    }

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

    s->rev = (uint32_t)rev;

    if (dubbed)
        SCFree(str);
    return 0;

 error:
    if (dubbed)
        SCFree(str);
    return -1;
}

