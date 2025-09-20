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
#include "detect-engine-buffer.h"
#include "detect-engine-helper.h"
#include "detect-parse.h"
#include "app-layer-smtp.h"
#include "detect-email.h"
#include "rust.h"
#include "detect-engine-content-inspection.h"

static int g_mime_email_from_buffer_id = 0;
static int g_mime_email_subject_buffer_id = 0;
static int g_mime_email_to_buffer_id = 0;
static int g_mime_email_cc_buffer_id = 0;
static int g_mime_email_date_buffer_id = 0;
static int g_mime_email_message_id_buffer_id = 0;
static int g_mime_email_x_mailer_buffer_id = 0;
static int g_mime_email_url_buffer_id = 0;
static int g_mime_email_received_buffer_id = 0;
static int g_mime_email_body_md5_buffer_id = 0;

static int DetectMimeEmailFromSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    if (SCDetectBufferSetActiveList(de_ctx, s, g_mime_email_from_buffer_id) < 0)
        return -1;

    if (SCDetectSignatureSetAppProto(s, ALPROTO_SMTP) < 0)
        return -1;

    return 0;
}

static bool GetMimeEmailFromData(
        const void *txv, const uint8_t _flow_flags, const uint8_t **data, uint32_t *data_len)
{
    SMTPTransaction *tx = (SMTPTransaction *)txv;
    if (tx->mime_state == NULL)
        return false;
    return (SCDetectMimeEmailGetData(tx->mime_state, data, data_len, "from") == 1);
}

static int DetectMimeEmailSubjectSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    if (SCDetectBufferSetActiveList(de_ctx, s, g_mime_email_subject_buffer_id) < 0)
        return -1;

    if (SCDetectSignatureSetAppProto(s, ALPROTO_SMTP) < 0)
        return -1;

    return 0;
}

static bool GetMimeEmailSubjectData(
        const void *txv, const uint8_t _flow_flags, const uint8_t **data, uint32_t *data_len)
{
    SMTPTransaction *tx = (SMTPTransaction *)txv;
    if (tx->mime_state == NULL)
        return false;
    return (SCDetectMimeEmailGetData(tx->mime_state, data, data_len, "subject") == 1);
}

static int DetectMimeEmailToSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    if (SCDetectBufferSetActiveList(de_ctx, s, g_mime_email_to_buffer_id) < 0)
        return -1;

    if (SCDetectSignatureSetAppProto(s, ALPROTO_SMTP) < 0)
        return -1;

    return 0;
}

static bool GetMimeEmailToData(
        const void *txv, const uint8_t _flow_flags, const uint8_t **data, uint32_t *data_len)
{
    SMTPTransaction *tx = (SMTPTransaction *)txv;
    if (tx->mime_state == NULL)
        return false;
    return (SCDetectMimeEmailGetData(tx->mime_state, data, data_len, "to") == 1);
}

static int DetectMimeEmailCcSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    if (SCDetectBufferSetActiveList(de_ctx, s, g_mime_email_cc_buffer_id) < 0)
        return -1;

    if (SCDetectSignatureSetAppProto(s, ALPROTO_SMTP) < 0)
        return -1;

    return 0;
}

static bool GetMimeEmailCcData(
        const void *txv, const uint8_t _flow_flags, const uint8_t **data, uint32_t *data_len)
{
    SMTPTransaction *tx = (SMTPTransaction *)txv;
    if (tx->mime_state == NULL)
        return false;
    return (SCDetectMimeEmailGetData(tx->mime_state, data, data_len, "cc") == 1);
}

static int DetectMimeEmailDateSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    if (SCDetectBufferSetActiveList(de_ctx, s, g_mime_email_date_buffer_id) < 0)
        return -1;

    if (SCDetectSignatureSetAppProto(s, ALPROTO_SMTP) < 0)
        return -1;

    return 0;
}

static bool GetMimeEmailDateData(
        const void *txv, const uint8_t _flow_flags, const uint8_t **data, uint32_t *data_len)
{
    SMTPTransaction *tx = (SMTPTransaction *)txv;
    if (tx->mime_state == NULL)
        return false;
    return (SCDetectMimeEmailGetData(tx->mime_state, data, data_len, "date") == 1);
}

static int DetectMimeEmailMessageIdSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    if (SCDetectBufferSetActiveList(de_ctx, s, g_mime_email_message_id_buffer_id) < 0)
        return -1;

    if (SCDetectSignatureSetAppProto(s, ALPROTO_SMTP) < 0)
        return -1;

    return 0;
}

static bool GetMimeEmailMessageIdData(
        const void *txv, const uint8_t _flow_flags, const uint8_t **data, uint32_t *data_len)
{
    SMTPTransaction *tx = (SMTPTransaction *)txv;
    if (tx->mime_state == NULL)
        return false;
    return (SCDetectMimeEmailGetData(tx->mime_state, data, data_len, "message-id") == 1);
}

static int DetectMimeEmailXMailerSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    if (SCDetectBufferSetActiveList(de_ctx, s, g_mime_email_x_mailer_buffer_id) < 0)
        return -1;

    if (SCDetectSignatureSetAppProto(s, ALPROTO_SMTP) < 0)
        return -1;

    return 0;
}

static bool GetMimeEmailXMailerData(
        const void *txv, const uint8_t _flow_flags, const uint8_t **data, uint32_t *data_len)
{
    SMTPTransaction *tx = (SMTPTransaction *)txv;
    if (tx->mime_state == NULL)
        return false;
    return (SCDetectMimeEmailGetData(tx->mime_state, data, data_len, "x-mailer") == 1);
}

static int DetectMimeEmailUrlSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    if (SCDetectBufferSetActiveList(de_ctx, s, g_mime_email_url_buffer_id) < 0)
        return -1;

    if (SCDetectSignatureSetAppProto(s, ALPROTO_SMTP) < 0)
        return -1;

    return 0;
}

static bool GetMimeEmailUrlData(DetectEngineThreadCtx *det_ctx, const void *txv,
        const uint8_t flags, uint32_t idx, const uint8_t **buf, uint32_t *buf_len)
{
    SMTPTransaction *tx = (SMTPTransaction *)txv;
    if (tx->mime_state == NULL) {
        return false;
    }

    if (SCDetectMimeEmailGetUrl(tx->mime_state, buf, buf_len, idx) != 1) {
        return false;
    }
    return true;
}

static int DetectMimeEmailReceivedSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    if (SCDetectBufferSetActiveList(de_ctx, s, g_mime_email_received_buffer_id) < 0)
        return -1;

    if (SCDetectSignatureSetAppProto(s, ALPROTO_SMTP) < 0)
        return -1;

    return 0;
}

static bool GetMimeEmailReceivedData(DetectEngineThreadCtx *det_ctx, const void *txv,
        const uint8_t flags, uint32_t idx, const uint8_t **buf, uint32_t *buf_len)
{
    SMTPTransaction *tx = (SMTPTransaction *)txv;

    if (tx->mime_state == NULL) {
        return false;
    }

    if (SCDetectMimeEmailGetDataArray(tx->mime_state, buf, buf_len, "received", idx) != 1) {
        return false;
    }
    return true;
}

int DETECT_EMAIL_BODY_MD5 = 0;

static int DetectMimeEmailBodyMd5Setup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    if (SCDetectBufferSetActiveList(de_ctx, s, g_mime_email_body_md5_buffer_id) < 0)
        return -1;

    if (SCDetectSignatureSetAppProto(s, ALPROTO_SMTP) < 0)
        return -1;

    if (!MimeBodyMd5IsEnabled()) {
        // we registered the keyword if not explicitly disabled, so we are here in auto mode
        SCMimeSmtpConfigBodyMd5(true);
    }

    return 0;
}

static bool GetMimeEmailBodyMd5Data(
        const void *txv, const uint8_t _flow_flags, const uint8_t **data, uint32_t *data_len)
{
    SMTPTransaction *tx = (SMTPTransaction *)txv;
    if (tx->mime_state == NULL)
        return false;

    SCDetectMimeEmailGetBodyMd5(tx->mime_state, data, data_len);

    return true;
}

void DetectEmailRegister(void)
{
    SCSigTableAppLiteElmt kw = { 0 };

    kw.name = "email.from";
    kw.desc = "'From' field from an email";
    kw.url = "/rules/email-keywords.html#email.from";
    kw.Setup = DetectMimeEmailFromSetup;
    kw.flags = SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER;
    SCDetectHelperKeywordRegister(&kw);
    g_mime_email_from_buffer_id = SCDetectHelperBufferMpmRegister(
            "email.from", "MIME EMAIL FROM", ALPROTO_SMTP, STREAM_TOSERVER, GetMimeEmailFromData);

    kw.name = "email.subject";
    kw.desc = "'Subject' field from an email";
    kw.url = "/rules/email-keywords.html#email.subject";
    kw.Setup = DetectMimeEmailSubjectSetup;
    kw.flags = SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER;
    SCDetectHelperKeywordRegister(&kw);
    g_mime_email_subject_buffer_id = SCDetectHelperBufferMpmRegister("email.subject",
            "MIME EMAIL SUBJECT", ALPROTO_SMTP, STREAM_TOSERVER, GetMimeEmailSubjectData);

    kw.name = "email.to";
    kw.desc = "'To' field from an email";
    kw.url = "/rules/email-keywords.html#email.to";
    kw.Setup = DetectMimeEmailToSetup;
    kw.flags = SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER;
    SCDetectHelperKeywordRegister(&kw);
    g_mime_email_to_buffer_id = SCDetectHelperBufferMpmRegister(
            "email.to", "MIME EMAIL TO", ALPROTO_SMTP, STREAM_TOSERVER, GetMimeEmailToData);

    kw.name = "email.cc";
    kw.desc = "'Cc' field from an email";
    kw.url = "/rules/email-keywords.html#email.cc";
    kw.Setup = DetectMimeEmailCcSetup;
    kw.flags = SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER;
    SCDetectHelperKeywordRegister(&kw);
    g_mime_email_cc_buffer_id = SCDetectHelperBufferMpmRegister(
            "email.cc", "MIME EMAIL CC", ALPROTO_SMTP, STREAM_TOSERVER, GetMimeEmailCcData);

    kw.name = "email.date";
    kw.desc = "'Date' field from an email";
    kw.url = "/rules/email-keywords.html#email.date";
    kw.Setup = DetectMimeEmailDateSetup;
    kw.flags = SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER;
    SCDetectHelperKeywordRegister(&kw);
    g_mime_email_date_buffer_id = SCDetectHelperBufferMpmRegister(
            "email.date", "MIME EMAIL DATE", ALPROTO_SMTP, STREAM_TOSERVER, GetMimeEmailDateData);

    kw.name = "email.message_id";
    kw.desc = "'Message-Id' field from an email";
    kw.url = "/rules/email-keywords.html#email.message_id";
    kw.Setup = DetectMimeEmailMessageIdSetup;
    kw.flags = SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER;
    SCDetectHelperKeywordRegister(&kw);
    g_mime_email_message_id_buffer_id = SCDetectHelperBufferMpmRegister("email.message_id",
            "MIME EMAIL Message-Id", ALPROTO_SMTP, STREAM_TOSERVER, GetMimeEmailMessageIdData);

    kw.name = "email.x_mailer";
    kw.desc = "'X-Mailer' field from an email";
    kw.url = "/rules/email-keywords.html#email.x_mailer";
    kw.Setup = DetectMimeEmailXMailerSetup;
    kw.flags = SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER;
    SCDetectHelperKeywordRegister(&kw);
    g_mime_email_x_mailer_buffer_id = SCDetectHelperBufferMpmRegister("email.x_mailer",
            "MIME EMAIL X-Mailer", ALPROTO_SMTP, STREAM_TOSERVER, GetMimeEmailXMailerData);

    kw.name = "email.url";
    kw.desc = "'Url' extracted from an email";
    kw.url = "/rules/email-keywords.html#email.url";
    kw.Setup = DetectMimeEmailUrlSetup;
    kw.flags = SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER | SIGMATCH_INFO_MULTI_BUFFER;
    SCDetectHelperKeywordRegister(&kw);
    g_mime_email_url_buffer_id = SCDetectHelperMultiBufferMpmRegister(
            "email.url", "MIME EMAIL URL", ALPROTO_SMTP, STREAM_TOSERVER, GetMimeEmailUrlData);

    kw.name = "email.received";
    kw.desc = "'Received' field from an email";
    kw.url = "/rules/email-keywords.html#email.received";
    kw.Setup = DetectMimeEmailReceivedSetup;
    kw.flags = SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER | SIGMATCH_INFO_MULTI_BUFFER;
    SCDetectHelperKeywordRegister(&kw);
    g_mime_email_received_buffer_id = SCDetectHelperMultiBufferMpmRegister("email.received",
            "MIME EMAIL RECEIVED", ALPROTO_SMTP, STREAM_TOSERVER, GetMimeEmailReceivedData);

    if (!MimeBodyMd5IsDisabled()) {
        // do not register the keyword if explicitly disabled
        kw.name = "email.body_md5";
        kw.desc = "'md5' hash generated from an email body";
        kw.url = "/rules/email-keywords.html#email.body_md5";
        kw.Setup = DetectMimeEmailBodyMd5Setup;
        kw.flags = SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER;
        DETECT_EMAIL_BODY_MD5 = SCDetectHelperKeywordRegister(&kw);
        // We do not need a progress because SMTP tx has only progress 0 or 1
        // even if we have a MimeSmtpMd5State enumeration
        g_mime_email_body_md5_buffer_id = SCDetectHelperBufferMpmRegister("email.body_md5",
                "MIME EMAIL BODY MD5", ALPROTO_SMTP, STREAM_TOSERVER, GetMimeEmailBodyMd5Data);
        DetectBufferTypeRegisterValidateCallback("email.body_md5", DetectMd5ValidateCallback);
    }
}
