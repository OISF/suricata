/* Copyright (C) 2025 Open Information Security Foundation
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
 * Detect keyword for DNS rrnames:
 * - dns.queries.rrname
 * - dns.answers.rrname
 * - dns.authorities.name
 * - dns.additionals.name
 */

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-buffer.h"
#include "detect-engine-content-inspection.h"
#include "detect-engine-helper.h"
#include "detect-dns-name.h"
#include "rust.h"

enum DnsSection {
    DNS_QUERY = 0,
    DNS_ANSWER,
    DNS_AUTHORITY,
    DNS_ADDITIONAL,
};

static int query_buffer_id = 0;
static int answer_buffer_id = 0;
static int authority_buffer_id = 0;
static int additional_buffer_id = 0;

static int DetectSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str, int id)
{
    if (SCDetectBufferSetActiveList(de_ctx, s, id) < 0) {
        return -1;
    }
    if (DetectSignatureSetAppProto(s, ALPROTO_DNS) < 0) {
        return -1;
    }

    return 0;
}

static int SetupQueryBuffer(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    return DetectSetup(de_ctx, s, str, query_buffer_id);
}

static int SetupAnswerBuffer(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    return DetectSetup(de_ctx, s, str, answer_buffer_id);
}

static int SetupAdditionalsBuffer(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    return DetectSetup(de_ctx, s, str, additional_buffer_id);
}

static int SetupAuthoritiesBuffer(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    return DetectSetup(de_ctx, s, str, authority_buffer_id);
}

static int Register(const char *keyword, const char *desc, const char *doc,
        int (*Setup)(DetectEngineCtx *, Signature *, const char *),
        InspectionMultiBufferGetDataPtr GetBufferFn)
{
    int keyword_id = SCDetectHelperNewKeywordId();
    sigmatch_table[keyword_id].name = keyword;
    sigmatch_table[keyword_id].desc = desc;
    sigmatch_table[keyword_id].url = doc;
    sigmatch_table[keyword_id].Setup = Setup;
    sigmatch_table[keyword_id].flags |= SIGMATCH_NOOPT;
    sigmatch_table[keyword_id].flags |= SIGMATCH_INFO_STICKY_BUFFER;

    DetectAppLayerMultiRegister(keyword, ALPROTO_DNS, SIG_FLAG_TOSERVER, 1, GetBufferFn, 2);
    DetectAppLayerMultiRegister(keyword, ALPROTO_DNS, SIG_FLAG_TOCLIENT, 1, GetBufferFn, 2);

    DetectBufferTypeSetDescriptionByName(keyword, keyword);
    DetectBufferTypeSupportsMultiInstance(keyword);

    return DetectBufferTypeGetByName(keyword);
}

void DetectDnsNameRegister(void)
{
    query_buffer_id = Register("dns.queries.rrname", "DNS query rrname sticky buffer",
            "/rules/dns-keywords.html#dns.queries.rrname", SetupQueryBuffer, SCDnsTxGetQueryName);
    answer_buffer_id = Register("dns.answers.rrname", "DNS answer rrname sticky buffer",
            "/rules/dns-keywords.html#dns.answers.rrname", SetupAnswerBuffer, SCDnsTxGetAnswerName);
    additional_buffer_id =
            Register("dns.additionals.rrname", "DNS additionals rrname sticky buffer",
                    "/rules/dns-keywords.html#dns-additionals-rrname", SetupAdditionalsBuffer,
                    SCDnsTxGetAdditionalName);
    authority_buffer_id = Register("dns.authorities.rrname", "DNS authorities rrname sticky buffer",
            "/rules/dns-keywords.html#dns-authorities-rrname", SetupAuthoritiesBuffer,
            SCDnsTxGetAuthorityName);
}
