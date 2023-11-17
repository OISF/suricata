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
 * \author Philippe Antoine
 *
 * Set up ENIP Product name keyword
 */

#include "suricata-common.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-prefilter.h"
#include "rust.h"

#include "detect-enip-product-name.h"

static int g_enip_product_name_id = 0;

/**
 * \brief this function is used to setup sticky buffer inspection for product_name
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param rulestr pointer to the user provided enip product name options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectEnipProductNameSetup(DetectEngineCtx *de_ctx, Signature *s, const char *rulestr)
{
    if (DetectBufferSetActiveList(de_ctx, s, g_enip_product_name_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_ENIP) != 0)
        return -1;

    return 0;
}

static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f, const uint8_t _flow_flags, void *txv,
        const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        const uint8_t *b = NULL;
        uint32_t b_len = 0;

        if (rs_enip_tx_get_product_name(txv, &b, &b_len) != 1)
            return NULL;
        if (b == NULL || b_len == 0)
            return NULL;

        InspectionBufferSetup(det_ctx, list_id, buffer, b, b_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }
    return buffer;
}

/**
 * \brief Registration function for enip.product_name: keyword
 */
void DetectEnipProductNameRegister(void)
{
    sigmatch_table[DETECT_ENIP_PRODUCTNAME].name = "enip.product_name"; // rule keyword
    sigmatch_table[DETECT_ENIP_PRODUCTNAME].desc =
            "sticky buffer to match EtherNet/IP product name";
    sigmatch_table[DETECT_ENIP_PRODUCTNAME].url = "/rules/enip-keyword.html#enip-product-name";
    sigmatch_table[DETECT_ENIP_PRODUCTNAME].Setup = DetectEnipProductNameSetup;
    sigmatch_table[DETECT_ENIP_PRODUCTNAME].flags |= SIGMATCH_NOOPT;

    DetectAppLayerInspectEngineRegister("enip.product_name", ALPROTO_ENIP, SIG_FLAG_TOCLIENT, 0,
            DetectEngineInspectBufferGeneric, GetData);

    DetectAppLayerMpmRegister("enip.product_name", SIG_FLAG_TOCLIENT, 2,
            PrefilterGenericMpmRegister, GetData, ALPROTO_ENIP, 1);

    DetectBufferTypeSetDescriptionByName("enip.product_name", "ENIP product name");
    g_enip_product_name_id = DetectBufferTypeGetByName("enip.product_name");
}
