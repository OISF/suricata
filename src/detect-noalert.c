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
 * Implements the noalert keyword
 */

#include "suricata-common.h"
#include "detect.h"
#include "detect-noalert.h"
#include "util-debug.h"

static int DetectNoalertSetup (DetectEngineCtx *, Signature *, const char *);

void DetectNoalertRegister (void)
{
    sigmatch_table[DETECT_NOALERT].name = "noalert";
    sigmatch_table[DETECT_NOALERT].Match = NULL;
    sigmatch_table[DETECT_NOALERT].Setup = DetectNoalertSetup;
    sigmatch_table[DETECT_NOALERT].Free  = NULL;
    sigmatch_table[DETECT_NOALERT].RegisterTests = NULL;

    sigmatch_table[DETECT_NOALERT].flags |= SIGMATCH_NOOPT;
}

static int DetectNoalertSetup (DetectEngineCtx *de_ctx, Signature *s, const char *nullstr)
{
    if (nullstr != NULL) {
        SCLogError(SC_ERR_INVALID_VALUE, "nocase has no value");
        return -1;
    }

    s->flags |= SIG_FLAG_NOALERT;
    return 0;
}

