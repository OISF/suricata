/* Copyright (C) 2015-2019 Open Information Security Foundation
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
 * \author Pierre Chifflier <chifflier@wzdftpd.net>
 *
 * Set up of the "snmp.community" keyword to allow content
 * inspections on the decoded snmp community.
 */

#include "suricata-common.h"
#ifdef UNITTESTS
#include "app-layer-parser.h"
#include "detect-engine-content-inspection.h"
#include "detect.h"
#include "conf.h"
#endif
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "detect-snmp-community.h"
#include "rust.h"

static int DetectSNMPCommunitySetup(DetectEngineCtx *, Signature *,
    const char *);
static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
       const DetectEngineTransforms *transforms,
       Flow *f, const uint8_t flow_flags,
       void *txv, const int list_id);
#ifdef UNITTESTS
static void DetectSNMPCommunityRegisterTests(void);
#endif
static int g_snmp_rust_id = 0;

void DetectSNMPCommunityRegister(void)
{
    sigmatch_table[DETECT_AL_SNMP_COMMUNITY].name = "snmp.community";
    sigmatch_table[DETECT_AL_SNMP_COMMUNITY].desc =
        "SNMP content modifier to match on the SNMP community";
    sigmatch_table[DETECT_AL_SNMP_COMMUNITY].Setup =
        DetectSNMPCommunitySetup;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_SNMP_COMMUNITY].RegisterTests = DetectSNMPCommunityRegisterTests;
#endif
    sigmatch_table[DETECT_AL_SNMP_COMMUNITY].url = "/rules/snmp-keywords.html#snmp-community";

    sigmatch_table[DETECT_AL_SNMP_COMMUNITY].flags |= SIGMATCH_NOOPT|SIGMATCH_INFO_STICKY_BUFFER;

    /* register inspect engines */
    DetectAppLayerInspectEngineRegister2("snmp.community",
            ALPROTO_SNMP, SIG_FLAG_TOSERVER, 0,
            DetectEngineInspectBufferGeneric, GetData);
    DetectAppLayerMpmRegister2("snmp.community", SIG_FLAG_TOSERVER, 2,
            PrefilterGenericMpmRegister, GetData, ALPROTO_SNMP, 0);
    DetectAppLayerInspectEngineRegister2("snmp.community",
            ALPROTO_SNMP, SIG_FLAG_TOCLIENT, 0,
            DetectEngineInspectBufferGeneric, GetData);
    DetectAppLayerMpmRegister2("snmp.community", SIG_FLAG_TOCLIENT, 2,
            PrefilterGenericMpmRegister, GetData, ALPROTO_SNMP, 0);

    DetectBufferTypeSetDescriptionByName("snmp.community", "SNMP Community identifier");

    g_snmp_rust_id = DetectBufferTypeGetByName("snmp.community");
}

static int DetectSNMPCommunitySetup(DetectEngineCtx *de_ctx, Signature *s,
    const char *str)
{
    if (DetectBufferSetActiveList(s, g_snmp_rust_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_SNMP) != 0)
        return -1;

    return 0;
}

static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *f,
        const uint8_t flow_flags, void *txv, const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        uint32_t data_len = 0;
        const uint8_t *data = NULL;

        rs_snmp_tx_get_community(txv, &data, &data_len);
        if (data == NULL || data_len == 0) {
            return NULL;
        }

        InspectionBufferSetup(det_ctx, list_id, buffer, data, data_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    return buffer;
}

#ifdef UNITTESTS
#include "tests/detect-snmp-community.c"
#endif /* UNITTESTS */
