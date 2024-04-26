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
#include "detect-dns-rcode.h"
#include "rust.h"
#include "detect-engine-uint.h"

static int dns_rcode_list_id = 0;

static void DetectDnsRcodeFree(DetectEngineCtx *, void *ptr);

static int DetectDnsRcodeSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    SCEnter();

    if (DetectSignatureSetAppProto(s, ALPROTO_DNS) != 0) {
        SCReturnInt(-1);
    }

    void *detect = DetectU8Parse(str);
    if (detect == NULL) {
        SCLogError("failed to parse dns.rcode: %s", str);
        SCReturnInt(-1);
    }

    if (SigMatchAppendSMToList(
                de_ctx, s, DETECT_AL_DNS_RCODE, (SigMatchCtx *)detect, dns_rcode_list_id) == NULL) {
        DetectDnsRcodeFree(de_ctx, detect);
        SCReturnInt(-1);
    }

    SCReturnInt(0);
}

static void DetectDnsRcodeFree(DetectEngineCtx *de_ctx, void *ptr)
{
    SCEnter();
    if (ptr != NULL) {
        rs_detect_u8_free(ptr);
    }
    SCReturn;
}

static int DetectDnsRcodeMatch(DetectEngineThreadCtx *det_ctx, Flow *f, uint8_t flags, void *state,
        void *txv, const Signature *s, const SigMatchCtx *ctx)
{
    return SCDnsDetectRcodeMatch(txv, (void *)ctx, flags);
}

void DetectDnsRcodeRegister(void)
{
    sigmatch_table[DETECT_AL_DNS_RCODE].name = "dns.rcode";
    sigmatch_table[DETECT_AL_DNS_RCODE].desc = "Match the DNS header rcode flag.";
    sigmatch_table[DETECT_AL_DNS_RCODE].url = "/rules/dns-keywords.html#dns-rcode";
    sigmatch_table[DETECT_AL_DNS_RCODE].Setup = DetectDnsRcodeSetup;
    sigmatch_table[DETECT_AL_DNS_RCODE].Free = DetectDnsRcodeFree;
    sigmatch_table[DETECT_AL_DNS_RCODE].Match = NULL;
    sigmatch_table[DETECT_AL_DNS_RCODE].AppLayerTxMatch = DetectDnsRcodeMatch;

    DetectAppLayerInspectEngineRegister(
            "dns.rcode", ALPROTO_DNS, SIG_FLAG_TOSERVER, 0, DetectEngineInspectGenericList, NULL);

    DetectAppLayerInspectEngineRegister(
            "dns.rcode", ALPROTO_DNS, SIG_FLAG_TOCLIENT, 0, DetectEngineInspectGenericList, NULL);

    dns_rcode_list_id = DetectBufferTypeGetByName("dns.rcode");
}