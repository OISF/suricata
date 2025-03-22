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

#include "detect-engine.h"
#include "detect-engine-helper.h"
#include "detect-parse.h"
#include "app-layer-smtp.h"
#include "detect-email.h"
#include "rust.h"
#include "detect-engine-content-inspection.h"

static int g_mime_email_from_buffer_id = 0;
static int g_mime_email_subject_buffer_id = 0;
static int g_mime_email_cc_buffer_id = 0;

static int DetectMimeEmailFromSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    if (DetectBufferSetActiveList(de_ctx, s, g_mime_email_from_buffer_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_SMTP) < 0)
        return -1;

    return 0;
}

static InspectionBuffer *GetMimeEmailFromData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *f, const uint8_t _flow_flags, void *txv,
        const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        SMTPTransaction *tx = (SMTPTransaction *)txv;

        const uint8_t *b_email_from = NULL;
        uint32_t b_email_from_len = 0;

        if (tx->mime_state == NULL)
            return NULL;

        if (SCDetectMimeEmailGetData(tx->mime_state, &b_email_from, &b_email_from_len, "from") != 1)
            return NULL;

        InspectionBufferSetup(det_ctx, list_id, buffer, b_email_from, b_email_from_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }
    return buffer;
}

static int DetectMimeEmailSubjectSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    if (DetectBufferSetActiveList(de_ctx, s, g_mime_email_subject_buffer_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_SMTP) < 0)
        return -1;

    return 0;
}

static InspectionBuffer *GetMimeEmailSubjectData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *f, const uint8_t _flow_flags, void *txv,
        const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        SMTPTransaction *tx = (SMTPTransaction *)txv;

        const uint8_t *b_email_sub = NULL;
        uint32_t b_email_sub_len = 0;

        if (tx->mime_state == NULL)
            return NULL;

        if (SCDetectMimeEmailGetData(tx->mime_state, &b_email_sub, &b_email_sub_len, "subject") !=
                1)
            return NULL;

        InspectionBufferSetup(det_ctx, list_id, buffer, b_email_sub, b_email_sub_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }
    return buffer;
}

static int DetectMimeEmailCcSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    if (DetectBufferSetActiveList(de_ctx, s, g_mime_email_cc_buffer_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_SMTP) < 0)
        return -1;

    return 0;
}

static InspectionBuffer *GetMimeEmailCcData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *f, const uint8_t _flow_flags, void *txv,
        const int list_id, uint32_t idx)
{
    InspectionBuffer *buffer = InspectionBufferMultipleForListGet(det_ctx, list_id, idx);
    if (buffer == NULL || buffer->initialized)
        return buffer;

    SMTPTransaction *tx = (SMTPTransaction *)txv;

    const uint8_t *b_email_cc = NULL;
    uint32_t b_email_cc_len = 0;

    if (tx->mime_state == NULL) {
        InspectionBufferSetupMultiEmpty(buffer);
        return NULL;
    }

    if (SCDetectMimeEmailGetMultiData(tx->mime_state, &b_email_cc, &b_email_cc_len, "cc", idx) !=
            1) {
        InspectionBufferSetupMultiEmpty(buffer);
        return NULL;
    }

    InspectionBufferSetupMulti(buffer, transforms, b_email_cc, b_email_cc_len);
    buffer->flags = DETECT_CI_FLAGS_SINGLE;
    return buffer;
}

void DetectEmailRegister(void)
{
    SCSigTableElmt kw = { 0 };

    kw.name = "email.from";
    kw.desc = "'From' field from an email";
    kw.url = "/rules/email-keywords.html#email.from";
    kw.Setup = (int (*)(void *, void *, const char *))DetectMimeEmailFromSetup;
    kw.flags = SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER;
    DetectHelperKeywordRegister(&kw);
    g_mime_email_from_buffer_id =
            DetectHelperBufferMpmRegister("email.from", "MIME EMAIL FROM", ALPROTO_SMTP, false,
                    true, // to server
                    GetMimeEmailFromData);

    kw.name = "email.subject";
    kw.desc = "'Subject' field from an email";
    kw.url = "/rules/email-keywords.html#email.subject";
    kw.Setup = (int (*)(void *, void *, const char *))DetectMimeEmailSubjectSetup;
    kw.flags = SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER;
    DetectHelperKeywordRegister(&kw);
    g_mime_email_subject_buffer_id = DetectHelperBufferMpmRegister("email.subject",
            "MIME EMAIL SUBJECT", ALPROTO_SMTP, false,
            true, // to server
            GetMimeEmailSubjectData);

    kw.name = "email.cc";
    kw.desc = "'Cc' field from an email";
    kw.url = "/rules/email-keywords.html#email.cc";
    kw.Setup = (int (*)(void *, void *, const char *))DetectMimeEmailCcSetup;
    kw.flags = SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER;
    DetectHelperKeywordRegister(&kw);
    g_mime_email_cc_buffer_id =
            DetectHelperMultiBufferMpmRegister("email.cc", "MIME EMAIL CC", ALPROTO_SMTP, false,
                    true, // to server
                    GetMimeEmailCcData);
}
