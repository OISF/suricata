/* Copyright (C) 2023 Open Information Security Foundation
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
 * Detect keyword for DNS query names: dns.query.name
 */

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-content-inspection.h"
#include "detect-dns-query-name.h"
#include "util-profiling.h"
#include "rust.h"

static int detect_buffer_id = 0;

static int DetectSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (DetectBufferSetActiveList(de_ctx, s, detect_buffer_id) < 0) {
        return -1;
    }
    if (DetectSignatureSetAppProto(s, ALPROTO_DNS) < 0) {
        return -1;
    }

    return 0;
}

static InspectionBuffer *GetBuffer(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *f, const uint8_t flags, void *txv,
        int list_id, uint32_t index)
{
    InspectionBuffer *buffer = InspectionBufferMultipleForListGet(det_ctx, list_id, index);
    if (buffer == NULL) {
        return NULL;
    }
    if (buffer->initialized) {
        return buffer;
    }

    if (f->alproto == ALPROTO_DOH2) {
        txv = SCDoH2GetDnsTx(txv, flags);
        if (txv == NULL) {
            return NULL;
        }
    }

    bool to_client = (flags & STREAM_TOSERVER) == 0;
    const uint8_t *data = NULL;
    uint32_t data_len = 0;

    if (!SCDnsTxGetQueryName(txv, to_client, index, &data, &data_len)) {
        InspectionBufferSetupMultiEmpty(buffer);
        return NULL;
    }
    InspectionBufferSetupMulti(buffer, transforms, data, data_len);
    buffer->flags = DETECT_CI_FLAGS_SINGLE;
    return buffer;
}

void DetectDnsQueryNameRegister(void)
{
    static const char *keyword = "dns.query.name";
    sigmatch_table[DETECT_AL_DNS_QUERY_NAME].name = keyword;
    sigmatch_table[DETECT_AL_DNS_QUERY_NAME].desc = "DNS query name sticky buffer";
    sigmatch_table[DETECT_AL_DNS_QUERY_NAME].url = "/rules/dns-keywords.html#dns-query-name";
    sigmatch_table[DETECT_AL_DNS_QUERY_NAME].Setup = DetectSetup;
    sigmatch_table[DETECT_AL_DNS_QUERY_NAME].flags |= SIGMATCH_NOOPT;
    sigmatch_table[DETECT_AL_DNS_QUERY_NAME].flags |= SIGMATCH_INFO_STICKY_BUFFER;

    /* Register in both directions as the query is usually echoed back
       in the response. */
    DetectAppLayerMultiRegister(keyword, ALPROTO_DNS, SIG_FLAG_TOSERVER, 0, GetBuffer, 2, 1);
    DetectAppLayerMultiRegister(keyword, ALPROTO_DNS, SIG_FLAG_TOCLIENT, 0, GetBuffer, 2, 1);

    DetectBufferTypeSetDescriptionByName(keyword, "dns query name");
    DetectBufferTypeSupportsMultiInstance(keyword);

    detect_buffer_id = DetectBufferTypeGetByName(keyword);
}
