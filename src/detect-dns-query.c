/* Copyright (C) 2013-2023 Open Information Security Foundation
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
 * \ingroup dnslayer
 *
 * @{
 */


/**
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 */

#include "suricata-common.h"
#include "threads.h"
#include "decode.h"
#include "detect.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-build.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-content-inspection.h"
#include "detect-content.h"
#include "detect-pcre.h"

#include "flow.h"
#include "flow-util.h"
#include "flow-var.h"

#include "util-debug.h"
#include "util-spm.h"
#include "util-print.h"

#include "stream-tcp.h"

#include "app-layer.h"
#include "app-layer-parser.h"
#include "detect-dns-query.h"

#include "util-profiling.h"
#include "rust.h"

static int DetectDnsQuerySetup(DetectEngineCtx *, Signature *, const char *);
static int g_dns_query_buffer_id = 0;

static InspectionBuffer *DnsQueryGetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *f, const uint8_t flags, void *txv,
        int list_id, uint32_t local_id)
{
    SCEnter();

    InspectionBuffer *buffer = InspectionBufferMultipleForListGet(det_ctx, list_id, local_id);
    if (buffer == NULL)
        return NULL;
    if (buffer->initialized)
        return buffer;

    const uint8_t *data;
    uint32_t data_len;
    if (SCDnsTxGetQueryName(txv, false, local_id, &data, &data_len) == 0) {
        InspectionBufferSetupMultiEmpty(buffer);
        return NULL;
    }
    InspectionBufferSetupMulti(buffer, transforms, data, data_len);
    buffer->flags = DETECT_CI_FLAGS_SINGLE;

    SCReturnPtr(buffer, "InspectionBuffer");
}

/**
 * \brief Registration function for keyword: dns_query
 */
void DetectDnsQueryRegister (void)
{
    sigmatch_table[DETECT_DNS_QUERY].name = "dns.query";
    sigmatch_table[DETECT_DNS_QUERY].alias = "dns_query";
    sigmatch_table[DETECT_DNS_QUERY].desc = "sticky buffer to match DNS query-buffer";
    sigmatch_table[DETECT_DNS_QUERY].url = "/rules/dns-keywords.html#dns-query";
    sigmatch_table[DETECT_DNS_QUERY].Setup = DetectDnsQuerySetup;
    sigmatch_table[DETECT_DNS_QUERY].flags |= SIGMATCH_NOOPT;
    sigmatch_table[DETECT_DNS_QUERY].flags |= SIGMATCH_INFO_STICKY_BUFFER;

    DetectAppLayerMultiRegister(
            "dns_query", ALPROTO_DNS, SIG_FLAG_TOSERVER, 1, DnsQueryGetData, 2, 1);

    DetectBufferTypeSetDescriptionByName("dns_query",
            "dns request query");
    DetectBufferTypeSupportsMultiInstance("dns_query");

    g_dns_query_buffer_id = DetectBufferTypeGetByName("dns_query");
}


/**
 * \brief setup the dns_query sticky buffer keyword used in the rule
 *
 * \param de_ctx   Pointer to the Detection Engine Context
 * \param s        Pointer to the Signature to which the current keyword belongs
 * \param str      Should hold an empty string always
 *
 * \retval  0 On success
 * \retval -1 On failure
 */

static int DetectDnsQuerySetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (DetectBufferSetActiveList(de_ctx, s, g_dns_query_buffer_id) < 0)
        return -1;
    if (DetectSignatureSetAppProto(s, ALPROTO_DNS) < 0)
        return -1;
    return 0;
}
