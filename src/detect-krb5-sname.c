/* Copyright (C) 2018-2022 Open Information Security Foundation
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
 */

#include "suricata-common.h"
#include "util-unittest.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-state.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-content-inspection.h"

#include "detect-krb5-sname.h"

#include "rust.h"
#include "app-layer-krb5.h"
#include "util-profiling.h"

static int g_krb5_sname_buffer_id = 0;

static int DetectKrb5SNameSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    if (DetectBufferSetActiveList(de_ctx, s, g_krb5_sname_buffer_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_KRB5) != 0)
        return -1;

    return 0;
}

static InspectionBuffer *GetKrb5SNameData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *f, const uint8_t flags, void *txv,
        int list_id, uint32_t local_id)
{
    SCEnter();

    InspectionBuffer *buffer = InspectionBufferMultipleForListGet(det_ctx, list_id, local_id);
    if (buffer == NULL)
        return NULL;
    if (buffer->initialized)
        return buffer;

    uint32_t b_len = 0;
    const uint8_t *b = NULL;

    if (rs_krb5_tx_get_sname(txv, local_id, &b, &b_len) != 1) {
        InspectionBufferSetupMultiEmpty(buffer);
        return NULL;
    }
    if (b == NULL || b_len == 0) {
        InspectionBufferSetupMultiEmpty(buffer);
        return NULL;
    }

    InspectionBufferSetupMulti(buffer, transforms, b, b_len);
    buffer->flags = DETECT_CI_FLAGS_SINGLE;

    SCReturnPtr(buffer, "InspectionBuffer");
}

void DetectKrb5SNameRegister(void)
{
    sigmatch_table[DETECT_AL_KRB5_SNAME].name = "krb5.sname";
    sigmatch_table[DETECT_AL_KRB5_SNAME].alias = "krb5_sname";
    sigmatch_table[DETECT_AL_KRB5_SNAME].url = "/rules/kerberos-keywords.html#krb5-sname";
    sigmatch_table[DETECT_AL_KRB5_SNAME].Setup = DetectKrb5SNameSetup;
    sigmatch_table[DETECT_AL_KRB5_SNAME].flags |= SIGMATCH_NOOPT|SIGMATCH_INFO_STICKY_BUFFER;
    sigmatch_table[DETECT_AL_KRB5_SNAME].desc = "sticky buffer to match on Kerberos 5 server name";

    DetectAppLayerMultiRegister(
            "krb5_sname", ALPROTO_KRB5, SIG_FLAG_TOCLIENT, 0, GetKrb5SNameData, 2, 1);

    DetectBufferTypeSetDescriptionByName("krb5_sname",
            "Kerberos 5 ticket server name");

    g_krb5_sname_buffer_id = DetectBufferTypeGetByName("krb5_sname");

    DetectBufferTypeSupportsMultiInstance("krb5_sname");
}
