/* Copyright (C) 2024 Open Information Security Foundation
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

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-dns-rrtype.h"
#include "rust.h"
#include "detect-engine-uint.h"

static int dns_rrtype_list_id = 0;

static void DetectDnsRrtypeFree(DetectEngineCtx *, void *ptr);

static int DetectDnsRrtypeSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    SCEnter();

    if (DetectSignatureSetAppProto(s, ALPROTO_DNS) != 0) {
        SCReturnInt(-1);
    }

    void *detect = DetectU16Parse(str);
    if (detect == NULL) {
        SCLogError("failed to parse dns.rrtype: %s", str);
        SCReturnInt(-1);
    }

    if (SigMatchAppendSMToList(de_ctx, s, DETECT_AL_DNS_RRTYPE, (SigMatchCtx *)detect,
                dns_rrtype_list_id) == NULL) {
        DetectDnsRrtypeFree(de_ctx, detect);
        SCReturnInt(-1);
    }

    SCReturnInt(0);
}

static void DetectDnsRrtypeFree(DetectEngineCtx *de_ctx, void *ptr)
{
    SCEnter();
    if (ptr != NULL) {
        rs_detect_u16_free(ptr);
    }
    SCReturn;
}

static int DetectDnsRrtypeMatch(DetectEngineThreadCtx *det_ctx, Flow *f, uint8_t flags, void *state,
        void *txv, const Signature *s, const SigMatchCtx *ctx)
{
    return SCDnsDetectRrtypeMatch(txv, (void *)ctx, flags);
}

void DetectDnsRrtypeRegister(void)
{
    sigmatch_table[DETECT_AL_DNS_RRTYPE].name = "dns.rrtype";
    sigmatch_table[DETECT_AL_DNS_RRTYPE].desc = "Match the DNS rrtype in message body.";
    sigmatch_table[DETECT_AL_DNS_RRTYPE].url = "/rules/dns-keywords.html#dns-rrtype";
    sigmatch_table[DETECT_AL_DNS_RRTYPE].Setup = DetectDnsRrtypeSetup;
    sigmatch_table[DETECT_AL_DNS_RRTYPE].Free = DetectDnsRrtypeFree;
    sigmatch_table[DETECT_AL_DNS_RRTYPE].Match = NULL;
    sigmatch_table[DETECT_AL_DNS_RRTYPE].AppLayerTxMatch = DetectDnsRrtypeMatch;

    DetectAppLayerInspectEngineRegister(
            "dns.rrtype", ALPROTO_DNS, SIG_FLAG_TOSERVER, 0, DetectEngineInspectGenericList, NULL);

    DetectAppLayerInspectEngineRegister(
            "dns.rrtype", ALPROTO_DNS, SIG_FLAG_TOCLIENT, 0, DetectEngineInspectGenericList, NULL);

    dns_rrtype_list_id = DetectBufferTypeGetByName("dns.rrtype");
}