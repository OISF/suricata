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
#include "debug.h"
#include "detect.h"
#include "pkt-var.h"
#include "conf.h"

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
#include "util-crypt.h"

#include "output-json.h"
#include "output-json-email-common.h"

#ifdef HAVE_LIBJANSSON
#include <jansson.h>

#define LOG_EMAIL_DEFAULT       0
#define LOG_EMAIL_EXTENDED      (1<<0)
#define LOG_EMAIL_ARRAY         (1<<1) /* require array handling */
#define LOG_EMAIL_COMMA         (1<<2) /* require array handling */
#define LOG_EMAIL_BODY_MD5      (1<<3)
#define LOG_EMAIL_SUBJECT_MD5   (1<<4)

struct {
    char *config_field;
    char *email_field;
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

static json_t* JsonEmailJsonArrayFromCommaList(const uint8_t *val, size_t len)
{
    json_t *ajs = json_array();
    if (likely(ajs != NULL)) {
        char *savep = NULL;
        char *p;
        char *sp;
        char *to_line = BytesToString((uint8_t *)val, len);
        if (likely(to_line != NULL)) {
            p = strtok_r(to_line, ",", &savep);
            if (p == NULL) {
                json_decref(ajs);
                SCFree(to_line);
                return NULL;
            }
            sp = SkipWhiteSpaceTill(p, savep);
            json_array_append_new(ajs, json_string(sp));
            while ((p = strtok_r(NULL, ",", &savep)) != NULL) {
                sp = SkipWhiteSpaceTill(p, savep);
                json_array_append_new(ajs, json_string(sp));
            }
        }
        SCFree(to_line);
    }

    return ajs;
}


#ifdef HAVE_NSS
static void JsonEmailLogJSONMd5(OutputJsonEmailCtx *email_ctx, json_t *js, SMTPTransaction *tx)
{
    if (email_ctx->flags & LOG_EMAIL_SUBJECT_MD5) {
        MimeDecField *field;
        MimeDecEntity *entity = tx->msg_tail;
        if (entity == NULL) {
            return;
        }
        field = MimeDecFindField(entity, "subject");
        if (field != NULL) {
            unsigned char md5[MD5_LENGTH];
            char smd5[256];
            char *value = BytesToString((uint8_t *)field->value , field->value_len);
            if (value) {
                size_t i,x;
                HASH_HashBuf(HASH_AlgMD5, md5, (unsigned char *)value, strlen(value));
                for (i = 0, x = 0; x < sizeof(md5); x++) {
                    i += snprintf(smd5 + i, 255 - i, "%02x", md5[x]);
                }
                json_object_set_new(js, "subject_md5", json_string(smd5));
                SCFree(value);
            }
        }
    }

    if (email_ctx->flags & LOG_EMAIL_BODY_MD5) {
        MimeDecParseState *mime_state = tx->mime_state;
        if (mime_state && mime_state->md5_ctx && (mime_state->state_flag == PARSE_DONE)) {
            size_t x;
            int i;
            char s[256];
            if (likely(s != NULL)) {
                for (i = 0, x = 0; x < sizeof(mime_state->md5); x++) {
                    i += snprintf(s + i, 255-i, "%02x", mime_state->md5[x]);
                }
                json_object_set_new(js, "body_md5", json_string(s));
            }
        }
    }
}
#endif

static int JsonEmailAddToJsonArray(const uint8_t *val, size_t len, void *data)
{
    json_t *ajs = data;

    if (ajs == NULL)
        return 0;
    char *value = BytesToString((uint8_t *)val, len);
    json_array_append_new(ajs, json_string(value));
    SCFree(value);
    return 1;
}

static void JsonEmailLogJSONCustom(OutputJsonEmailCtx *email_ctx, json_t *js, SMTPTransaction *tx)
{
    int f = 0;
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
                json_t *ajs = json_array();
                if (ajs) {
                    int found = MimeDecFindFieldsForEach(entity, email_fields[f].email_field, JsonEmailAddToJsonArray, ajs);
                    if (found > 0) {
                        json_object_set_new(js, email_fields[f].config_field, ajs);
                    } else {
                        json_decref(ajs);
                    }
                }
            } else if (email_fields[f].flags & LOG_EMAIL_COMMA) {
                field = MimeDecFindField(entity, email_fields[f].email_field);
                if (field) {
                    json_t *ajs = JsonEmailJsonArrayFromCommaList(field->value, field->value_len);
                    if (ajs) {
                        json_object_set_new(js, email_fields[f].config_field, ajs);
                    }
                }
            } else {
                field = MimeDecFindField(entity, email_fields[f].email_field);
                if (field != NULL) {
                    char *s = BytesToString((uint8_t *)field->value,
                            (size_t)field->value_len);
                    if (likely(s != NULL)) {
                        json_object_set_new(js, email_fields[f].config_field, json_string(s));
                        SCFree(s);
                    }
                }
            }

        }
        f++;
    }
}

/* JSON format logging */
json_t *JsonEmailLogJsonData(const Flow *f, void *state, void *vtx, uint64_t tx_id)
{
    SMTPState *smtp_state;
    MimeDecParseState *mime_state;
    MimeDecEntity *entity;

    json_t *sjs = json_object();
    if (sjs == NULL) {
        SCReturnPtr(NULL, "json_t");
    }

    /* check if we have SMTP state or not */
    AppProto proto = FlowGetAppProtocol(f);
    switch (proto) {
        case ALPROTO_SMTP:
            smtp_state = (SMTPState *)state;
            if (smtp_state == NULL) {
                SCLogDebug("no smtp state, so no request logging");
                SCReturnPtr(NULL, "json_t");
            }
            SMTPTransaction *tx = vtx;
            mime_state = tx->mime_state;
            entity = tx->msg_tail;
            SCLogDebug("lets go mime_state %p, entity %p, state_flag %u", mime_state, entity, mime_state ? mime_state->state_flag : 0);
            break;
        default:
            /* don't know how we got here */
            SCReturnPtr(NULL, "json_t");
    }
    if ((mime_state != NULL)) {
        if (entity == NULL) {
            SCReturnPtr(NULL, "json_t");
        }

        json_object_set_new(sjs, "status",
                            json_string(MimeDecParseStateGetStatus(mime_state)));

        MimeDecField *field;

        /* From: */
        field = MimeDecFindField(entity, "from");
        if (field != NULL) {
            char *s = BytesToString((uint8_t *)field->value,
                                    (size_t)field->value_len);
            if (likely(s != NULL)) {
                //printf("From: \"%s\"\n", s);
                char * sp = SkipWhiteSpaceTill(s, s + strlen(s));
                json_object_set_new(sjs, "from", json_string(sp));
                SCFree(s);
            }
        }

        /* To: */
        field = MimeDecFindField(entity, "to");
        if (field != NULL) {
            json_t *ajs = JsonEmailJsonArrayFromCommaList(field->value, field->value_len);
            if (ajs) {
                json_object_set_new(sjs, "to", ajs);
            }
        }

        /* Cc: */
        field = MimeDecFindField(entity, "cc");
        if (field != NULL) {
            json_t *ajs = JsonEmailJsonArrayFromCommaList(field->value, field->value_len);
            if (ajs) {
                json_object_set_new(sjs, "cc", ajs);
            }
        }

        if (mime_state->stack == NULL || mime_state->stack->top == NULL || mime_state->stack->top->data == NULL)
            SCReturnPtr(NULL, "json_t");

        entity = (MimeDecEntity *)mime_state->stack->top->data;
        int attch_cnt = 0;
        int url_cnt = 0;
        json_t *js_attch = json_array();
        json_t *js_url = json_array();
        if (entity->url_list != NULL) {
            MimeDecUrl *url;
            for (url = entity->url_list; url != NULL; url = url->next) {
                char *s = BytesToString((uint8_t *)url->url,
                                        (size_t)url->url_len);
                if (s != NULL) {
                    json_array_append_new(js_url,
                                      json_string(s));
                    SCFree(s);
                    url_cnt += 1;
                }
            }
        }
        for (entity = entity->child; entity != NULL; entity = entity->next) {
            if (entity->ctnt_flags & CTNT_IS_ATTACHMENT) {

                char *s = BytesToString((uint8_t *)entity->filename,
                                        (size_t)entity->filename_len);
                json_array_append_new(js_attch,
                                      json_string(s));
                SCFree(s);
                attch_cnt += 1;
            }
            if (entity->url_list != NULL) {
                MimeDecUrl *url;
                for (url = entity->url_list; url != NULL; url = url->next) {
                    char *s = BytesToString((uint8_t *)url->url,
                                            (size_t)url->url_len);
                    if (s != NULL) {
                        json_array_append_new(js_url,
                                          json_string(s));
                        SCFree(s);
                        url_cnt += 1;
                    }
                }
            }
        }
        if (attch_cnt > 0) {
            json_object_set_new(sjs, "attachment", js_attch);
        } else {
            json_decref(js_attch);
        }
        if (url_cnt > 0) {
            json_object_set_new(sjs, "url", js_url);
        } else {
            json_decref(js_url);
        }
        SCReturnPtr(sjs, "json_t");
    }

    json_decref(sjs);
    SCReturnPtr(NULL, "json_t");
}

/* JSON format logging */
TmEcode JsonEmailLogJson(JsonEmailLogThread *aft, json_t *js, const Packet *p, Flow *f, void *state, void *vtx, uint64_t tx_id)
{
    json_t *sjs = JsonEmailLogJsonData(f, state, vtx, tx_id);
    OutputJsonEmailCtx *email_ctx = aft->emaillog_ctx;
    SMTPTransaction *tx = (SMTPTransaction *) vtx;

    if ((email_ctx->flags & LOG_EMAIL_EXTENDED) || (email_ctx->fields != 0))
        JsonEmailLogJSONCustom(email_ctx, sjs, tx);

#ifdef HAVE_NSS
    JsonEmailLogJSONMd5(email_ctx, sjs, tx);
#endif

    if (sjs) {
        json_object_set_new(js, "email", sjs);
        SCReturnInt(TM_ECODE_OK);
    } else
        SCReturnInt(TM_ECODE_FAILED);
}

json_t *JsonEmailAddMetadata(const Flow *f, uint32_t tx_id)
{
    SMTPState *smtp_state = (SMTPState *)FlowGetAppState(f);
    if (smtp_state) {
        SMTPTransaction *tx = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_SMTP, smtp_state, tx_id);

        if (tx) {
            return JsonEmailLogJsonData(f, smtp_state, tx, tx_id);
        }
    }

    return NULL;
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


#endif
