/* Copyright (C) 2007-2019 Open Information Security Foundation
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
 */

#include "suricata-common.h"
#ifdef UNITTESTS
#endif

#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-ipv4hdr.h"

/* prototypes */
static int DetectIpv4hdrSetup (DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
void DetectIpv4hdrRegisterTests (void);
#endif

static int g_ipv4hdr_buffer_id = 0;

static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Packet *p, const int list_id);

/**
 * \brief Registration function for ipv4.hdr: keyword
 */
void DetectIpv4hdrRegister(void)
{
    sigmatch_table[DETECT_IPV4HDR].name = "ipv4.hdr";
    sigmatch_table[DETECT_IPV4HDR].desc = "sticky buffer to match on the IPV4 header";
    sigmatch_table[DETECT_IPV4HDR].url = "/rules/header-keywords.html#ipv4hdr";
    sigmatch_table[DETECT_IPV4HDR].Setup = DetectIpv4hdrSetup;
    sigmatch_table[DETECT_IPV4HDR].flags |= SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER;
#ifdef UNITTESTS
    sigmatch_table[DETECT_IPV4HDR].RegisterTests = DetectIpv4hdrRegisterTests;
#endif

    g_ipv4hdr_buffer_id = DetectBufferTypeRegister("ipv4.hdr");
    BUG_ON(g_ipv4hdr_buffer_id < 0);

    DetectBufferTypeSupportsPacket("ipv4.hdr");

    DetectPktMpmRegister("ipv4.hdr", 2, PrefilterGenericMpmPktRegister, GetData);

    DetectPktInspectEngineRegister("ipv4.hdr", GetData,
            DetectEngineInspectPktBufferGeneric);

    return;
}

/**
 * \brief setup ipv4.hdr sticky buffer
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param _unused unused
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectIpv4hdrSetup (DetectEngineCtx *de_ctx, Signature *s, const char *_unused)
{
    s->proto.flags |= DETECT_PROTO_IPV4; // TODO

    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    if (DetectBufferSetActiveList(s, g_ipv4hdr_buffer_id) < 0)
        return -1;

    return 0;
}

static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Packet *p, const int list_id)
{
    SCEnter();

    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        if (p->ip4h == NULL) {
            // DETECT_PROTO_IPV4 does not prefilter
            return NULL;
        }
        uint32_t hlen = IPV4_GET_HLEN(p);
        if (((uint8_t *)p->ip4h + (ptrdiff_t)hlen) >
                ((uint8_t *)GET_PKT_DATA(p) + (ptrdiff_t)GET_PKT_LEN(p)))
        {
            SCLogDebug("data out of range: %p > %p",
                    ((uint8_t *)p->ip4h + (ptrdiff_t)hlen),
                    ((uint8_t *)GET_PKT_DATA(p) + (ptrdiff_t)GET_PKT_LEN(p)));
            return NULL;
        }

        const uint32_t data_len = hlen;
        const uint8_t *data = (const uint8_t *)p->ip4h;

        InspectionBufferSetup(det_ctx, list_id, buffer, data, data_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    return buffer;
}

#ifdef UNITTESTS
#include "tests/detect-ipv4hdr.c"
#endif
