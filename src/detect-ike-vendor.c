/* Copyright (C) 2020-2022 Open Information Security Foundation
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
 *
 * \author Frank Honza <frank.honza@dcso.de>
 */

#include "suricata-common.h"
#include "conf.h"
#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-content-inspection.h"
#include "detect-engine-mpm.h"
#include "detect-ike-vendor.h"
#include "app-layer-parser.h"
#include "util-byte.h"

#include "rust-bindings.h"
#include "util-profiling.h"

static int DetectIkeVendorSetup(DetectEngineCtx *, Signature *, const char *);

static int g_ike_vendor_buffer_id = 0;

static InspectionBuffer *IkeVendorGetData(DetectEngineThreadCtx *det_ctx,
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
    if (rs_ike_tx_get_vendor(txv, local_id, &data, &data_len) == 0) {
        InspectionBufferSetupMultiEmpty(buffer);
        return NULL;
    }

    InspectionBufferSetupMulti(buffer, transforms, data, data_len);
    buffer->flags = DETECT_CI_FLAGS_SINGLE;

    SCReturnPtr(buffer, "InspectionBuffer");
}

/**
 * \brief Registration function for ike.vendor keyword.
 */
void DetectIkeVendorRegister(void)
{
    sigmatch_table[DETECT_AL_IKE_VENDOR].name = "ike.vendor";
    sigmatch_table[DETECT_AL_IKE_VENDOR].desc = "match IKE Vendor";
    sigmatch_table[DETECT_AL_IKE_VENDOR].url = "/rules/ike-keywords.html#ike-vendor";
    sigmatch_table[DETECT_AL_IKE_VENDOR].Setup = DetectIkeVendorSetup;
    sigmatch_table[DETECT_AL_IKE_VENDOR].flags |= SIGMATCH_NOOPT;
    sigmatch_table[DETECT_AL_IKE_VENDOR].flags |= SIGMATCH_INFO_STICKY_BUFFER;

    DetectAppLayerMultiRegister(
            "ike.vendor", ALPROTO_IKE, SIG_FLAG_TOSERVER, 1, IkeVendorGetData, 1, 1);

    g_ike_vendor_buffer_id = DetectBufferTypeGetByName("ike.vendor");

    DetectBufferTypeSupportsMultiInstance("ike.vendor");
}

/**
 * \brief setup the sticky buffer keyword used in the rule
 *
 * \param de_ctx   Pointer to the Detection Engine Context
 * \param s        Pointer to the Signature to which the current keyword belongs
 * \param str      Should hold an empty string always
 *
 * \retval  0 On success
 * \retval -1 On failure
 */

static int DetectIkeVendorSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (DetectBufferSetActiveList(de_ctx, s, g_ike_vendor_buffer_id) < 0)
        return -1;
    if (DetectSignatureSetAppProto(s, ALPROTO_IKE) < 0)
        return -1;
    return 0;
}
