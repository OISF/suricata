/* Copyright (C) 2007-2014 Open Information Security Foundation
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

/* JSON format logging */
static TmEcode JsonEmailLogJson(JsonEmailLogThread *aft,
                                json_t *js,
                                const Packet *p)
{
    SMTPState *smtp_state;
    MimeDecParseState *mime_state;
    MimeDecEntity *entity;
    char *protos = NULL;

    /* no flow, no smtp state */
    if (p->flow == NULL) {
        SCReturnInt(TM_ECODE_FAILED);
    }

    json_t *sjs = json_object();
    if (sjs == NULL) {
        SCReturnInt(TM_ECODE_FAILED);
    }

    /* check if we have SMTP state or not */
    FLOWLOCK_WRLOCK(p->flow); /* WRITE lock before we updated flow logged id */
    AppProto proto = FlowGetAppProtocol(p->flow);
    switch (proto) {
        case ALPROTO_SMTP:
            smtp_state = (SMTPState *)FlowGetAppState(p->flow);
            if (smtp_state == NULL) {
                SCLogDebug("no smtp state, so no request logging");
                FLOWLOCK_UNLOCK(p->flow);
                SCReturnInt(TM_ECODE_FAILED);
            }
            mime_state = smtp_state->mime_state;
            entity = smtp_state->msg_tail;
            protos = "smtp";
            break;
        default:
            /* don't know how we got here */
            FLOWLOCK_UNLOCK(p->flow);
            SCReturnInt(TM_ECODE_FAILED);
    }
    if ((mime_state != NULL) &&
        (mime_state->state_flag == PARSE_DONE)) {

        if (entity == NULL) {
            FLOWLOCK_UNLOCK(p->flow);
            SCReturnInt(TM_ECODE_FAILED);
        }

        if ((entity->header_flags & HDR_IS_LOGGED) == 0) {
            MimeDecField *field;
            //printf("email LOG\n");

            /* From: */
            field = MimeDecFindField(entity, "From");
            if (field != NULL) {
                char *s = BytesToString((uint8_t *)field->value,
                                        (size_t)field->value_len);
                if (likely(s != NULL)) {
                    //printf("From: \"%s\"\n", s);
                    json_object_set_new(sjs, "from", json_string(s));
                    SCFree(s);
                }
            }

            /* To: */
            char *to_line = NULL;
            field = MimeDecFindField(entity, "To");
            if (field != NULL) {
                json_t *js_to = json_array();
                if (likely(js_to != NULL)) {
                    char *savep;
                    char *p;
                    to_line = BytesToString((uint8_t *)field->value,
                                            (size_t)field->value_len);
                    //printf("to_line:: TO: \"%s\" (%d)\n", to_line, strlen(to_line));
                    p = strtok_r(to_line, ",", &savep);
                    //printf("got another addr: \"%s\"\n", p);
                    json_array_append_new(js_to, json_string(p));
                    while ((p = strtok_r(NULL, ",", &savep)) != NULL) {
                        //printf("got another addr: \"%s\"\n", p);
                        json_array_append_new(js_to, json_string(&p[strspn(p, " ")]));
                    }
                    json_object_set_new(sjs, "to", js_to);
                }
            }

            /* Cc: */
            char *cc_line = NULL;
            field = MimeDecFindField(entity, "Cc");
            if (field != NULL) {
                json_t *js_cc = json_array();
                if (likely(js_cc != NULL)) {
                    char *savep;
                    char *p;
                    cc_line = BytesToString((uint8_t *)field->value,
                                            (size_t)field->value_len);
                    //printf("cc_line:: CC: \"%s\" (%d)\n", to_line, strlen(to_line));
                    p = strtok_r(cc_line, ",", &savep);
                    //printf("got another addr: \"%s\"\n", p);
                    json_array_append_new(js_cc, json_string(p));
                    while ((p = strtok_r(NULL, ",", &savep)) != NULL) {
                        //printf("got another addr: \"%s\"\n", p);
                        json_array_append_new(js_cc, json_string(&p[strspn(p, " ")]));
                    }
                    json_object_set_new(sjs, "cc", js_cc);
                }
            }

            /* Subject: */
            field = MimeDecFindField(entity, "Subject");
            if (field != NULL) {
                char *s = strndup(field->value, (int) field->value_len);
                if (likely(s != NULL)) {
                    //printf("Subject: \"%s\"\n", s);
                    json_object_set_new(sjs, "subject", json_string(s));
                    SCFree(s);
                }
            }

            entity->header_flags |= HDR_IS_LOGGED;

            entity = (MimeDecEntity *)mime_state->stack->top->data;
            int attch_cnt = 0;
            int url_cnt = 0;
            json_t *js_attch = json_array();
            json_t *js_url = json_array();
            for (entity = entity->child; entity != NULL; entity = entity->next) {
                if (entity->ctnt_flags & CTNT_IS_ATTACHMENT) {

                    char *s = BytesToString((uint8_t *)entity->filename,
                                            (size_t)entity->filename_len);
                    //printf("found attachment \"%s\"\n", s);
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
                            //printf("URL: \"%s\"\n", s);
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
            json_object_set_new(js, protos, sjs);

            FLOWLOCK_UNLOCK(p->flow);
            SCReturnInt(TM_ECODE_OK);
        }
    }

    FLOWLOCK_UNLOCK(p->flow);
    SCReturnInt(TM_ECODE_DONE);
}

int JsonEmailLogger(ThreadVars *tv, void *thread_data, const Packet *p) {
    SCEnter();
    JsonEmailLogThread *jhl = (JsonEmailLogThread *)thread_data;
    MemBuffer *buffer = (MemBuffer *)jhl->buffer;

    json_t *js = CreateJSONHeader((Packet *)p, 1, "smtp");
    if (unlikely(js == NULL))
        return TM_ECODE_OK;

    /* reset */
    MemBufferReset(buffer);

    if (JsonEmailLogJson(jhl, js, p) == TM_ECODE_OK) {
        OutputJSONBuffer(js, jhl->emaillog_ctx->file_ctx, buffer);
    }
    json_object_del(js, "smtp");

    json_object_clear(js);
    json_decref(js);

    SCReturnInt(TM_ECODE_OK);
}

#endif
