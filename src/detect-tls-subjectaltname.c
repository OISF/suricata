/* Copyright (C) 2024 Open Information Security Foundation
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
 * \author Shivani Bhardwaj <shivani@oisf.net>
 *
 * Implements support for tls.subjectaltname keyword.
 */

#include "suricata-common.h"
#include "threads.h"
#include "decode.h"
#include "detect.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-content-inspection.h"
#include "detect-content.h"
#include "detect-tls-subjectaltname.h"
#include "detect-engine-uint.h"

#include "flow.h"
#include "flow-util.h"
#include "flow-var.h"

#include "util-debug.h"
#include "util-spm.h"
#include "util-print.h"

#include "stream-tcp.h"

#include "app-layer.h"
#include "app-layer-ssl.h"
#include "util-profiling.h"

static int DetectTlsSubjectAltNameSetup(DetectEngineCtx *, Signature *, const char *);
static InspectionBuffer *TlsSubjectAltNameGetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *f, uint8_t flags, void *txv, int list_id,
        uint32_t index);

static int g_tls_subjectaltname_buffer_id = 0;

/**
 * \brief Registration function for keyword: tls.subjectaltname
 */
void DetectTlsSubjectAltNameRegister(void)
{
    sigmatch_table[DETECT_AL_TLS_SUBJECTALTNAME].name = "tls.subjectaltname";
    sigmatch_table[DETECT_AL_TLS_SUBJECTALTNAME].desc =
            "sticky buffer to match the TLS Subject Alternative Name buffer";
    sigmatch_table[DETECT_AL_TLS_SUBJECTALTNAME].url =
            "/rules/tls-keywords.html#tls-subjectaltname";
    sigmatch_table[DETECT_AL_TLS_SUBJECTALTNAME].Setup = DetectTlsSubjectAltNameSetup;
    sigmatch_table[DETECT_AL_TLS_SUBJECTALTNAME].flags |= SIGMATCH_NOOPT;
    sigmatch_table[DETECT_AL_TLS_SUBJECTALTNAME].flags |= SIGMATCH_INFO_STICKY_BUFFER;

    DetectAppLayerMultiRegister("tls.subjectaltname", ALPROTO_TLS, SIG_FLAG_TOCLIENT, 0,
            TlsSubjectAltNameGetData, 2, TLS_STATE_CERT_READY);

    DetectBufferTypeSetDescriptionByName("tls.subjectaltname", "TLS Subject Alternative Name");

    DetectBufferTypeSupportsMultiInstance("tls.subjectaltname");

    g_tls_subjectaltname_buffer_id = DetectBufferTypeGetByName("tls.subjectaltname");
}

/**
 * \brief This function setup the tls.subjectaltname sticky buffer keyword
 *
 * \param de_ctx Pointer to the Detect Engine Context
 * \param s      Pointer to the Signature to which the keyword belongs
 * \param str    Should hold an empty string always
 *
 * \retval  0 On success
 * \retval -1 On failure
 */
static int DetectTlsSubjectAltNameSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (DetectBufferSetActiveList(de_ctx, s, g_tls_subjectaltname_buffer_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_TLS) < 0)
        return -1;

    return 0;
}

static InspectionBuffer *TlsSubjectAltNameGetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *f, uint8_t flags, void *txv, int list_id,
        uint32_t idx)
{
    SCEnter();
    InspectionBuffer *buffer = InspectionBufferMultipleForListGet(det_ctx, list_id, idx);
    if (buffer == NULL || buffer->initialized)
        return buffer;

    const SSLState *ssl_state = (SSLState *)f->alstate;
    const SSLStateConnp *connp;

    connp = &ssl_state->server_connp;

    if (idx >= connp->cert0_sans_len) {
        return NULL;
    }

    InspectionBufferSetupMulti(buffer, transforms, (const uint8_t *)connp->cert0_sans[idx],
            strlen(connp->cert0_sans[idx]));
    buffer->flags = DETECT_CI_FLAGS_SINGLE;

    SCReturnPtr(buffer, "InspectionBuffer");
}
