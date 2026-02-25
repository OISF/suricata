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
 */

#include "suricata-common.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-buffer.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-content-inspection.h"
#include "detect-fast-pattern.h"
#include "detect-etherhdr.h"

/* prototypes */
static int DetectEtherhdrSetup(DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
void DetectEtherhdrRegisterTests(void);
#endif

static int g_etherhdr_buffer_id = 0;

static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Packet *p, const int list_id);

/**
 * \brief Registration function for ether.hdr: keyword
 */
void DetectEtherhdrRegister(void)
{
    sigmatch_table[DETECT_ETHERHDR].name = "ether.hdr";
    sigmatch_table[DETECT_ETHERHDR].desc = "sticky buffer to match on the Ethernet header";
    sigmatch_table[DETECT_ETHERHDR].url = "/rules/header-keywords.html#etherhdr";
    sigmatch_table[DETECT_ETHERHDR].Setup = DetectEtherhdrSetup;
    sigmatch_table[DETECT_ETHERHDR].flags |= SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER;
#ifdef UNITTESTS
    sigmatch_table[DETECT_ETHERHDR].RegisterTests = DetectEtherhdrRegisterTests;
#endif

    g_etherhdr_buffer_id = DetectBufferTypeRegister("ether.hdr");
    BUG_ON(g_etherhdr_buffer_id < 0);

    DetectBufferTypeSupportsPacket("ether.hdr");

    DetectPktMpmRegister("ether.hdr", 2, PrefilterGenericMpmPktRegister, GetData);

    DetectPktInspectEngineRegister("ether.hdr", GetData, DetectEngineInspectPktBufferGeneric);
}

/**
 * \brief setup ether.hdr sticky buffer
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param _unused unused
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectEtherhdrSetup(DetectEngineCtx *de_ctx, Signature *s, const char *_unused)
{
    s->init_data->proto.flags |= DETECT_PROTO_ETHERNET;
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    if (SCDetectBufferSetActiveList(de_ctx, s, g_etherhdr_buffer_id) < 0)
        return -1;

    return 0;
}

static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Packet *p, const int list_id)
{
    SCEnter();

    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        if (!PacketIsEthernet(p)) {
            // DETECT_PROTO_ETHERNET does not prefilter
            return NULL;
        }
        const EthernetHdr *ethh = PacketGetEthernet(p);
        if (((uint8_t *)ethh + (ptrdiff_t)ETHERNET_HEADER_LEN) >
                ((uint8_t *)GET_PKT_DATA(p) + (ptrdiff_t)GET_PKT_LEN(p))) {
            SCLogDebug("data out of range: %p > %p",
                    ((uint8_t *)ethh + (ptrdiff_t)ETHERNET_HEADER_LEN),
                    ((uint8_t *)GET_PKT_DATA(p) + (ptrdiff_t)GET_PKT_LEN(p)));
            return NULL;
        }

        const uint32_t data_len = (uint32_t)ETHERNET_HEADER_LEN;
        const uint8_t *data = (const uint8_t *)ethh;
        SCLogDebug("inspect data %p / %u", data, data_len);

        InspectionBufferSetupAndApplyTransforms(
                det_ctx, list_id, buffer, data, data_len, transforms);
    }

    return buffer;
}

#ifdef UNITTESTS
#include "tests/detect-etherhdr.c"
#endif
