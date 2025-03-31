/* Copyright (C) 2019 Open Information Security Foundation
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
#include "detect-engine-uint.h"
#include "detect-dns-opcode.h"
#include "rust.h"

static int dns_opcode_list_id = 0;

static void DetectDnsOpcodeFree(DetectEngineCtx *, void *ptr);

static int DetectDnsOpcodeSetup(DetectEngineCtx *de_ctx, Signature *s,
   const char *str)
{
    SCEnter();

    if (DetectSignatureSetAppProto(s, ALPROTO_DNS) != 0) {
        return -1;
    }

    void *detect = DetectU8Parse(str);
    if (detect == NULL) {
        SCLogError("failed to parse dns.opcode: %s", str);
        return -1;
    }

    if (SigMatchAppendSMToList(
                de_ctx, s, DETECT_DNS_OPCODE, (SigMatchCtx *)detect, dns_opcode_list_id) == NULL) {
        goto error;
    }

    SCReturnInt(0);

error:
    DetectDnsOpcodeFree(de_ctx, detect);
    SCReturnInt(-1);
}

static void DetectDnsOpcodeFree(DetectEngineCtx *de_ctx, void *ptr)
{
    SCEnter();
    if (ptr != NULL) {
        SCDetectU8Free(ptr);
    }
    SCReturn;
}

static int DetectDnsOpcodeMatch(DetectEngineThreadCtx *det_ctx,
    Flow *f, uint8_t flags, void *state, void *txv, const Signature *s,
    const SigMatchCtx *ctx)
{
    return SCDnsDetectOpcodeMatch(txv, (void *)ctx, flags);
}

void DetectDnsOpcodeRegister(void)
{
    sigmatch_table[DETECT_DNS_OPCODE].name = "dns.opcode";
    sigmatch_table[DETECT_DNS_OPCODE].desc = "Match the DNS header opcode flag.";
    sigmatch_table[DETECT_DNS_OPCODE].Setup = DetectDnsOpcodeSetup;
    sigmatch_table[DETECT_DNS_OPCODE].Free = DetectDnsOpcodeFree;
    sigmatch_table[DETECT_DNS_OPCODE].Match = NULL;
    sigmatch_table[DETECT_DNS_OPCODE].AppLayerTxMatch = DetectDnsOpcodeMatch;

    DetectAppLayerInspectEngineRegister(
            "dns.opcode", ALPROTO_DNS, SIG_FLAG_TOSERVER, 0, DetectEngineInspectGenericList, NULL);

    DetectAppLayerInspectEngineRegister(
            "dns.opcode", ALPROTO_DNS, SIG_FLAG_TOCLIENT, 0, DetectEngineInspectGenericList, NULL);

    dns_opcode_list_id = DetectBufferTypeGetByName("dns.opcode");
}
