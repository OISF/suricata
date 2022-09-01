/* Copyright (C) 2007-2015 Open Information Security Foundation
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
 * \author Tom DeCanio <td@npulsetech.com>
 * \author Eric Leblond <eric@regit.org>
 *
 * Implements json common email logging portion of the engine.
 */

#include "suricata-common.h"
#include "detect.h"
#include "pkt-var.h"
#include "conf.h"
#include "suricata.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"
#include "tm-threads-common.h"

#include "util-print.h"
#include "util-unittest.h"

#include "util-debug.h"
#include "app-layer-parser.h"
#include "output.h"
#include "app-layer-smtp.h"
#include "app-layer.h"
#include "util-privs.h"
#include "util-buffer.h"
#include "util-byte.h"

#include "util-logopenfile.h"

#include "output-json.h"
#include "output-json-email-common.h"

#define LOG_EMAIL_DEFAULT       0
#define LOG_EMAIL_EXTENDED      (1<<0)
#define LOG_EMAIL_ARRAY         (1<<1) /* require array handling */
#define LOG_EMAIL_COMMA         (1<<2) /* require array handling */
#define LOG_EMAIL_BODY_MD5      (1<<3)
#define LOG_EMAIL_SUBJECT_MD5   (1<<4)

struct {
    const char *config_field;
    const char *email_field;
    uint32_t flags;
} email_fields[] =  {
    { "reply_to", "reply-to", LOG_EMAIL_DEFAULT },
    { "bcc", "bcc", LOG_EMAIL_COMMA|LOG_EMAIL_EXTENDED },
    { "message_id", "message-id", LOG_EMAIL_EXTENDED },
    { "subject", "subject", LOG_EMAIL_EXTENDED },
    { "x_mailer", "x-mailer", LOG_EMAIL_EXTENDED },
    { "user_agent", "user-agent", LOG_EMAIL_EXTENDED },
    { "received", "received", LOG_EMAIL_ARRAY },
    { "x_originating_ip", "x-originating-ip", LOG_EMAIL_DEFAULT },
    { "in_reply_to",  "in-reply-to", LOG_EMAIL_DEFAULT },
    { "references",  "references", LOG_EMAIL_DEFAULT },
    { "importance",  "importance", LOG_EMAIL_DEFAULT },
    { "priority",  "priority", LOG_EMAIL_DEFAULT },
    { "sensitivity",  "sensitivity", LOG_EMAIL_DEFAULT },
    { "organization",  "organization", LOG_EMAIL_DEFAULT },
    { "content_md5",  "content-md5", LOG_EMAIL_DEFAULT },
    { "date", "date", LOG_EMAIL_DEFAULT },
    { NULL, NULL, LOG_EMAIL_DEFAULT},
};

static void EveEmailLogJSONMd5(OutputJsonEmailCtx *email_ctx, JsonBuilder *js, SMTPTransaction *tx)
{
    if (email_ctx->flags & LOG_EMAIL_SUBJECT_MD5) {
        MimeStateSMTP *entity = tx->mime_state;
        if (entity == NULL) {
            return;
        }
        rs_mime_smtp_log_subject_md5(js, entity);
    }

    if (email_ctx->flags & LOG_EMAIL_BODY_MD5) {
        MimeStateSMTP *entity = tx->mime_state;
        if (entity == NULL) {
            return;
        }
        rs_mime_smtp_log_body_md5(js, entity);
    }
}

static void EveEmailLogJSONCustom(OutputJsonEmailCtx *email_ctx, JsonBuilder *js, SMTPTransaction *tx)
{
    int f = 0;
    MimeStateSMTP *entity = tx->mime_state;
    if (entity == NULL) {
        return;
    }

    while(email_fields[f].config_field) {
        if (((email_ctx->fields & (1ULL<<f)) != 0)
              ||
              ((email_ctx->flags & LOG_EMAIL_EXTENDED) && (email_fields[f].flags & LOG_EMAIL_EXTENDED))
           ) {
            if (email_fields[f].flags & LOG_EMAIL_ARRAY) {
                rs_mime_smtp_log_field_array(
                        js, entity, email_fields[f].email_field, email_fields[f].config_field);
            } else if (email_fields[f].flags & LOG_EMAIL_COMMA) {
                rs_mime_smtp_log_field_comma(
                        js, entity, email_fields[f].email_field, email_fields[f].config_field);
            } else {
                rs_mime_smtp_log_field_string(
                        js, entity, email_fields[f].email_field, email_fields[f].config_field);
            }

        }
        f++;
    }
}

/* JSON format logging */
static bool EveEmailLogJsonData(const Flow *f, void *state, void *vtx, uint64_t tx_id, JsonBuilder *sjs)
{
    SMTPState *smtp_state;
    MimeStateSMTP *mime_state;

    /* check if we have SMTP state or not */
    AppProto proto = FlowGetAppProtocol(f);
    switch (proto) {
        case ALPROTO_SMTP:
            smtp_state = (SMTPState *)state;
            if (smtp_state == NULL) {
                SCLogDebug("no smtp state, so no request logging");
                jb_free(sjs);
                SCReturnPtr(NULL, "JsonBuilder");
            }
            SMTPTransaction *tx = vtx;
            mime_state = tx->mime_state;
            SCLogDebug("lets go mime_state %p, state_flag %u", mime_state,
                    mime_state ? mime_state->state_flag : 0);
            break;
        default:
            /* don't know how we got here */
            SCReturnBool(false);
    }
    if ((mime_state != NULL)) {

        rs_mime_smtp_log_data(sjs, mime_state);
        SCReturnBool(true);
    }

    SCReturnBool(false);
}

/* JSON format logging */
TmEcode EveEmailLogJson(JsonEmailLogThread *aft, JsonBuilder *js, const Packet *p, Flow *f, void *state, void *vtx, uint64_t tx_id)
{
    OutputJsonEmailCtx *email_ctx = aft->emaillog_ctx;
    SMTPTransaction *tx = (SMTPTransaction *) vtx;
    JsonBuilderMark mark = { 0, 0, 0 };

    jb_get_mark(js, &mark);
    jb_open_object(js, "email");
    if (!EveEmailLogJsonData(f, state, vtx, tx_id, js)) {
        jb_restore_mark(js, &mark);
        SCReturnInt(TM_ECODE_FAILED);
    }

    if ((email_ctx->flags & LOG_EMAIL_EXTENDED) || (email_ctx->fields != 0))
        EveEmailLogJSONCustom(email_ctx, js, tx);

    if (!g_disable_hashing) {
        EveEmailLogJSONMd5(email_ctx, js, tx);
    }

    jb_close(js);
    SCReturnInt(TM_ECODE_OK);
}

bool EveEmailAddMetadata(const Flow *f, uint32_t tx_id, JsonBuilder *js)
{
    SMTPState *smtp_state = (SMTPState *)FlowGetAppState(f);
    if (smtp_state) {
        SMTPTransaction *tx = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_SMTP, smtp_state, tx_id);
        if (tx) {
            return EveEmailLogJsonData(f, smtp_state, tx, tx_id, js);
        }
    }

    return false;
}

void OutputEmailInitConf(ConfNode *conf, OutputJsonEmailCtx *email_ctx)
{
    if (conf) {
        const char *extended = ConfNodeLookupChildValue(conf, "extended");

        if (extended != NULL) {
            if (ConfValIsTrue(extended)) {
                email_ctx->flags = LOG_EMAIL_EXTENDED;
            }
        }

        email_ctx->fields  = 0;
        ConfNode *custom;
        if ((custom = ConfNodeLookupChild(conf, "custom")) != NULL) {
            ConfNode *field;
            TAILQ_FOREACH(field, &custom->head, next) {
                if (field != NULL) {
                    int f = 0;
                    while(email_fields[f].config_field) {
                        if ((strcmp(email_fields[f].config_field,
                                   field->val) == 0) ||
                            (strcasecmp(email_fields[f].email_field,
                                        field->val) == 0))
                        {
                            email_ctx->fields |= (1ULL<<f);
                            break;
                        }
                        f++;
                    }
                }
            }
        }

        email_ctx->flags  = 0;
        ConfNode *md5_conf;
        if ((md5_conf = ConfNodeLookupChild(conf, "md5")) != NULL) {
            ConfNode *field;
            TAILQ_FOREACH(field, &md5_conf->head, next) {
                if (field != NULL) {
                    if (strcmp("body", field->val) == 0) {
                        SCLogInfo("Going to log the md5 sum of email body");
                        email_ctx->flags |= LOG_EMAIL_BODY_MD5;
                    }
                    if (strcmp("subject", field->val) == 0) {
                        SCLogInfo("Going to log the md5 sum of email subject");
                        email_ctx->flags |= LOG_EMAIL_SUBJECT_MD5;
                    }
                }
            }
        }
    }
    return;
}
