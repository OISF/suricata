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
 * Implements recursive keyword support
 *
 * Used to capture variables recursively in a payload,
 * used for example to extract http_uri for uricontent.
 *
 * Note: non Snort compatible.
 */

#include "suricata-common.h"
#include "decode.h"
#include "detect.h"
#include "flow-var.h"

static int DetectRecursiveSetup (DetectEngineCtx *, Signature *, char *);

void DetectRecursiveRegister (void) {
    sigmatch_table[DETECT_RECURSIVE].name = "recursive";
    sigmatch_table[DETECT_RECURSIVE].Match = NULL;
    sigmatch_table[DETECT_RECURSIVE].Setup = DetectRecursiveSetup;
    sigmatch_table[DETECT_RECURSIVE].Free  = NULL;
    sigmatch_table[DETECT_RECURSIVE].RegisterTests = NULL;

    sigmatch_table[DETECT_RECURSIVE].flags |= SIGMATCH_NOOPT;
}

static int DetectRecursiveSetup (DetectEngineCtx *de_ctx, Signature *s, char *nullstr)
{
    if (nullstr != NULL) {
        printf("DetectRecursiveSetup: recursive has no value\n");
        return -1;
    }

    s->flags |= SIG_FLAG_RECURSIVE;
    return 0;
}

