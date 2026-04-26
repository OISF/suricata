/* Copyright (C) 2026 Open Information Security Foundation
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
 * Implements sctp.has_data keyword
 *
 * Author: Giuseppe Longo <glongo@oisf.net>
 */

#include "suricata-common.h"
#include "decode.h"
#include "detect.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-build.h"

#include "detect-sctp-has-data.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"

static int DetectSCTPHasDataMatch(
        DetectEngineThreadCtx *, Packet *, const Signature *, const SigMatchCtx *);
static int DetectSCTPHasDataSetup(DetectEngineCtx *, Signature *, const char *);

#ifdef UNITTESTS
void DetectSCTPHasDataRegisterTests(void);
#endif

void DetectSCTPHasDataRegister(void)
{
    sigmatch_table[DETECT_SCTP_HAS_DATA].name = "sctp.has_data";
    sigmatch_table[DETECT_SCTP_HAS_DATA].desc = "match if the SCTP packet contains a DATA chunk";
    sigmatch_table[DETECT_SCTP_HAS_DATA].url = "/rules/header-keywords.html#sctp-has-data";
    sigmatch_table[DETECT_SCTP_HAS_DATA].Match = DetectSCTPHasDataMatch;
    sigmatch_table[DETECT_SCTP_HAS_DATA].Setup = DetectSCTPHasDataSetup;
    sigmatch_table[DETECT_SCTP_HAS_DATA].flags = SIGMATCH_NOOPT;
#ifdef UNITTESTS
    sigmatch_table[DETECT_SCTP_HAS_DATA].RegisterTests = DetectSCTPHasDataRegisterTests;
#endif
}

static int DetectSCTPHasDataMatch(
        DetectEngineThreadCtx *det_ctx, Packet *p, const Signature *s, const SigMatchCtx *ctx)
{
    if (!PacketIsSCTP(p)) {
        return 0;
    }
    return p->l4.vars.sctp.has_data ? 1 : 0;
}

static int DetectSCTPHasDataSetup(DetectEngineCtx *de_ctx, Signature *s, const char *optstr)
{
    if (!(DetectProtoContainsProto(s->proto, IPPROTO_SCTP)))
        return -1;

    if (SCSigMatchAppendSMToList(de_ctx, s, DETECT_SCTP_HAS_DATA, NULL, DETECT_SM_LIST_MATCH) ==
            NULL) {
        return -1;
    }
    s->flags |= SIG_FLAG_REQUIRE_PACKET;
    return 0;
}

#ifdef UNITTESTS
#include "tests/detect-sctp-has-data.c"
#endif
