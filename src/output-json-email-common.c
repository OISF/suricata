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
#include "suricata.h"

#include "app-layer-parser.h"
#include "app-layer-smtp.h"
#include "util-byte.h"

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

static inline char *SkipWhiteSpaceTill(char *p, char *savep)
{
    char *sp = p;
    if (unlikely(p == NULL)) {
        return NULL;
    }
    while (((*sp == '\t') || (*sp == ' ')) && (sp < savep)) {
        sp++;
    }
    return sp;
}

static bool EveEmailJsonArrayFromCommaList(JsonBuilder *js, const uint8_t *val, size_t len)
{
    char *savep = NULL;
    char *p;
    char *sp;
    char *to_line = BytesToString((uint8_t *)val, len);
    if (likely(to_line != NULL)) {
        p = strtok_r(to_line, ",", &savep);
        if (p == NULL) {
            SCFree(to_line);
            return false;
        }
        sp = SkipWhiteSpaceTill(p, savep);
        jb_append_string(js, sp);
        while ((p = strtok_r(NULL, ",", &savep)) != NULL) {
            sp = SkipWhiteSpaceTill(p, savep);
            jb_append_string(js, sp);
        }
    } else {
        return false;
    }
    SCFree(to_line);
    return true;
}

static void EveEmailLogJSONMd5(OutputJsonEmailCtx *email_ctx, JsonBuilder *js, SMTPTransaction *tx)
{
    if (email_ctx->flags & LOG_EMAIL_SUBJECT_MD5) {
        MimeDecEntity *entity = tx->msg_tail;
        if (entity == NULL) {
            return;
        }
        MimeDecField *field = MimeDecFindField(entity, "subject");
        if (field != NULL) {
            char smd5[SC_MD5_HEX_LEN + 1];
            SCMd5HashBufferToHex((uint8_t *)field->value, field->value_len, smd5, sizeof(smd5));
            jb_set_string(js, "subject_md5", smd5);
        }
    }

    if (email_ctx->flags & LOG_EMAIL_BODY_MD5) {
        MimeDecParseState *mime_state = tx->mime_state;
        if (mime_state && mime_state->has_md5 && (mime_state->state_flag == PARSE_DONE)) {
            jb_set_hex(js, "body_md5", mime_state->md5, (uint32_t)sizeof(mime_state->md5));
        }
    }
}

static int JsonEmailAddToJsonArray(const uint8_t *val, size_t len, void *data)
{
    JsonBuilder *ajs = data;

    if (ajs == NULL)
        return 0;
    char *value = BytesToString((uint8_t *)val, len);
    jb_append_string(ajs, value);
    SCFree(value);
    return 1;
}

static void EveEmailLogJSONCustom(OutputJsonEmailCtx *email_ctx, JsonBuilder *js, SMTPTransaction *tx)
{
    int f = 0;
    JsonBuilderMark mark = { 0, 0, 0 };
    MimeDecField *field;
    MimeDecEntity *entity = tx->msg_tail;
    if (entity == NULL) {
        return;
    }

    while(email_fields[f].config_field) {
        if (((email_ctx->fields & (1ULL<<f)) != 0)
              ||
              ((email_ctx->flags & LOG_EMAIL_EXTENDED) && (email_fields[f].flags & LOG_EMAIL_EXTENDED))
           ) {
            if (email_fields[f].flags & LOG_EMAIL_ARRAY) {
                jb_get_mark(js, &mark);
                jb_open_array(js, email_fields[f].config_field);
                int found = MimeDecFindFieldsForEach(entity, email_fields[f].email_field, JsonEmailAddToJsonArray, js);
                if (found > 0) {
                    jb_close(js);
                } else {
                    jb_restore_mark(js, &mark);
                }
            } else if (email_fields[f].flags & LOG_EMAIL_COMMA) {
                field = MimeDecFindField(entity, email_fields[f].email_field);
                if (field) {
                    jb_get_mark(js, &mark);
                    jb_open_array(js, email_fields[f].config_field);
                    if (EveEmailJsonArrayFromCommaList(js, field->value, field->value_len)) {
                        jb_close(js);
                    } else {
                        jb_restore_mark(js, &mark);
                    }
                }
            } else {
                field = MimeDecFindField(entity, email_fields[f].email_field);
                if (field != NULL) {
                    char *s = BytesToString((uint8_t *)field->value,
                            (size_t)field->value_len);
                    if (likely(s != NULL)) {
                        jb_set_string(js, email_fields[f].config_field, s);
                        SCFree(s);
                    }
                }
            }

        }
        f++;
    }
}

/* JSON format logging */
static bool EveEmailLogJsonData(const Flow *f, void *state, void *vtx, uint64_t tx_id, JsonBuilder *sjs)
{
    SMTPState *smtp_state;
    MimeDecParseState *mime_state;
    MimeDecEntity *entity;
    JsonBuilderMark mark = { 0, 0, 0 };

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
            entity = tx->msg_tail;
            SCLogDebug("lets go mime_state %p, entity %p, state_flag %u", mime_state, entity, mime_state ? mime_state->state_flag : 0);
            break;
        default:
            /* don't know how we got here */
            SCReturnBool(false);
    }
    if ((mime_state != NULL)) {
        if (entity == NULL) {
            SCReturnBool(false);
        }

        jb_set_string(sjs, "status", MimeDecParseStateGetStatus(mime_state));

        MimeDecField *field;

        /* From: */
        field = MimeDecFindField(entity, "from");
        if (field != NULL) {
            char *s = BytesToString((uint8_t *)field->value,
                                    (size_t)field->value_len);
            if (likely(s != NULL)) {
                //printf("From: \"%s\"\n", s);
                char * sp = SkipWhiteSpaceTill(s, s + strlen(s));
                jb_set_string(sjs, "from", sp);
                SCFree(s);
            }
        }

        /* To: */
        field = MimeDecFindField(entity, "to");
        if (field != NULL) {
            jb_get_mark(sjs, &mark);
            jb_open_array(sjs, "to");
            if (EveEmailJsonArrayFromCommaList(sjs, field->value, field->value_len)) {
                jb_close(sjs);
            } else {
                jb_restore_mark(sjs, &mark);
            }
        }

        /* Cc: */
        field = MimeDecFindField(entity, "cc");
        if (field != NULL) {
            jb_get_mark(sjs, &mark);
            jb_open_array(sjs, "cc");
            if (EveEmailJsonArrayFromCommaList(sjs, field->value, field->value_len)) {
                jb_close(sjs);
            } else {
                jb_restore_mark(sjs, &mark);
            }
        }

        if (mime_state->stack == NULL || mime_state->stack->top == NULL || mime_state->stack->top->data == NULL) {
            SCReturnBool(false);
        }

        entity = (MimeDecEntity *)mime_state->stack->top->data;
        int attch_cnt = 0;
        int url_cnt = 0;
        JsonBuilder *js_attch = jb_new_array();
        JsonBuilder *js_url = jb_new_array();
        if (entity->url_list != NULL) {
            MimeDecUrl *url;
            bool has_ipv6_url = false;
            bool has_ipv4_url = false;
            bool has_exe_url = false;
            for (url = entity->url_list; url != NULL; url = url->next) {
                char *s = BytesToString((uint8_t *)url->url,
                                        (size_t)url->url_len);
                if (s != NULL) {
                    jb_append_string(js_url, s);
                    if (url->url_flags & URL_IS_EXE)
                        has_exe_url = true;
                    if (url->url_flags & URL_IS_IP6)
                        has_ipv6_url = true;
                    if (url->url_flags & URL_IS_IP4)
                        has_ipv6_url = true;
                    SCFree(s);
                    url_cnt += 1;
                }
            }
            jb_set_bool(sjs, "has_ipv6_url", has_ipv6_url);
            jb_set_bool(sjs, "has_ipv4_url", has_ipv4_url);
            jb_set_bool(sjs, "has_exe_url", has_exe_url);
        }
        for (entity = entity->child; entity != NULL; entity = entity->next) {
            if (entity->ctnt_flags & CTNT_IS_ATTACHMENT) {

                char *s = BytesToString((uint8_t *)entity->filename,
                                        (size_t)entity->filename_len);
                jb_append_string(js_attch, s);
                SCFree(s);
                attch_cnt += 1;
            }
            if (entity->url_list != NULL) {
                MimeDecUrl *url;
                for (url = entity->url_list; url != NULL; url = url->next) {
                    char *s = BytesToString((uint8_t *)url->url,
                                            (size_t)url->url_len);
                    if (s != NULL) {
                        jb_append_string(js_url, s);
                        SCFree(s);
                        url_cnt += 1;
                    }
                }
            }
        }
        if (attch_cnt > 0) {
            jb_close(js_attch);
            jb_set_object(sjs, "attachment", js_attch);
        }
        jb_free(js_attch);
        if (url_cnt > 0) {
            jb_close(js_url);
            jb_set_object(sjs, "url", js_url);
        }
        jb_free(js_url);
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
