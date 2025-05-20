/* Copyright (C) 2016-2022 Open Information Security Foundation
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
 * \author Giuseppe Longo <glongo@stamus-networks.com>
 *
 */

#include "suricata-common.h"
#include "threads.h"
#include "app-layer.h"
#include "app-layer-parser.h"
#include "decode.h"

#include "detect.h"
#include "detect-parse.h"

#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-state.h"
#include "detect-engine-sigorder.h"
#include "detect-bypass.h"

#include "flow.h"
#include "flow-var.h"
#include "flow-util.h"

#include "stream-tcp.h"

#include "util-debug.h"
#include "util-spm-bm.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-device-private.h"

static int DetectBypassMatch(DetectEngineThreadCtx *, Packet *,
        const Signature *, const SigMatchCtx *);
static int DetectBypassSetup(DetectEngineCtx *, Signature *, const char *);

/**
 * \brief Registration function for keyword: bypass
 */
void DetectBypassRegister(void)
{
    sigmatch_table[DETECT_BYPASS].name = "bypass";
    sigmatch_table[DETECT_BYPASS].desc = "call the bypass callback when the match of a sig is complete";
    sigmatch_table[DETECT_BYPASS].url = "/rules/bypass-keyword.html";
    sigmatch_table[DETECT_BYPASS].Match = DetectBypassMatch;
    sigmatch_table[DETECT_BYPASS].Setup = DetectBypassSetup;
    sigmatch_table[DETECT_BYPASS].Free  = NULL;
    sigmatch_table[DETECT_BYPASS].flags = SIGMATCH_NOOPT;
}

static int DetectBypassSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{

    if (s->flags & SIG_FLAG_FILESTORE) {
        SCLogError("bypass can't work with filestore keyword");
        return -1;
    }
    s->flags |= SIG_FLAG_BYPASS;

    if (SCSigMatchAppendSMToList(de_ctx, s, DETECT_BYPASS, NULL, DETECT_SM_LIST_POSTMATCH) ==
            NULL) {
        return -1;
    }

    return 0;
}

static int DetectBypassMatch(DetectEngineThreadCtx *det_ctx, Packet *p,
        const Signature *s, const SigMatchCtx *ctx)
{
    PacketBypassCallback(p);

    return 1;
}
