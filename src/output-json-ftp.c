/* Copyright (C) 2017-2021 Open Information Security Foundation
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
 * \author Jeff Lucovsky <jeff@lucovsky.org>
 *
 * Implement JSON/eve logging app-layer FTP.
 */

#include "suricata-common.h"
#include "detect.h"
#include "pkt-var.h"
#include "conf.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"

#include "util-unittest.h"
#include "util-buffer.h"
#include "util-debug.h"
#include "util-mem.h"

#include "output.h"
#include "output-json.h"

#include "app-layer.h"
#include "app-layer-parser.h"

#include "app-layer-ftp.h"
#include "output-json-ftp.h"

bool EveFTPLogCommand(void *vtx, JsonBuilder *jb)
{
    FTPTransaction *tx = vtx;
    /* Preallocate array objects to simplify failure case */
    JsonBuilder *js_resplist = NULL;
    if (!TAILQ_EMPTY(&tx->response_list)) {
        js_resplist = jb_new_array();

        if (unlikely(js_resplist == NULL)) {
            return false;
        }
    }
    const char *command_name = NULL;
    uint8_t command_name_length;
    if (tx->command_descriptor.command_code != FTP_COMMAND_UNKNOWN) {
        if (!SCGetFtpCommandInfo(tx->command_descriptor.command_index, &command_name, NULL,
                    &command_name_length)) {
            SCLogDebug("Unable to fetch info for FTP command code %d [index %d]",
                    tx->command_descriptor.command_code, tx->command_descriptor.command_index);
            return false;
        }
    }
    jb_open_object(jb, "ftp");
    if (command_name) {
        jb_set_string(jb, "command", command_name);
        uint32_t min_length = command_name_length + 1; /* command + space */
        if (tx->request_length > min_length) {
            jb_set_string_from_bytes(jb, "command_data", (const uint8_t *)tx->request + min_length,
                    tx->request_length - min_length - 1);
            if (tx->request_truncated) {
                JB_SET_TRUE(jb, "command_truncated");
            } else {
                JB_SET_FALSE(jb, "command_truncated");
            }
        }
    }

    bool reply_truncated = false;

    if (!TAILQ_EMPTY(&tx->response_list)) {
        int resp_cnt = 0;
        FTPResponseWrapper *wrapper;
        bool is_cc_array_open = false;
        TAILQ_FOREACH (wrapper, &tx->response_list, next) {
            /* handle multiple lines within the response, \r\n delimited */
            if (!wrapper->response) {
                continue;
            }
            FTPResponseLine *response = wrapper->response;

            if (!reply_truncated && response->truncated) {
                reply_truncated = true;
            }
            int code_len = strlen(response->code);
            if (code_len > 0) {
                if (!is_cc_array_open) {
                    jb_open_array(jb, "completion_code");
                    is_cc_array_open = true;
                }
                jb_append_string_from_bytes(jb, (const uint8_t *)response->code, code_len);
            }
            if (response->length) {
                jb_append_string_from_bytes(
                        js_resplist, (const uint8_t *)response->response, response->length);
                resp_cnt++;
            }
        }

        if (is_cc_array_open) {
            jb_close(jb);
        }
        if (resp_cnt) {
            jb_close(js_resplist);
            jb_set_object(jb, "reply", js_resplist);
        }
        jb_free(js_resplist);
    }

    if (tx->dyn_port) {
        jb_set_uint(jb, "dynamic_port", tx->dyn_port);
    }

    if (tx->command_descriptor.command_code == FTP_COMMAND_PORT ||
            tx->command_descriptor.command_code == FTP_COMMAND_EPRT) {
        if (tx->active) {
            JB_SET_STRING(jb, "mode", "active");
        } else {
            JB_SET_STRING(jb, "mode", "passive");
        }
    }

    if (tx->done) {
        JB_SET_STRING(jb, "reply_received", "yes");
    } else {
        JB_SET_STRING(jb, "reply_received", "no");
    }

    if (reply_truncated) {
        JB_SET_TRUE(jb, "reply_truncated");
    } else {
        JB_SET_FALSE(jb, "reply_truncated");
    }
    jb_close(jb);
    return true;
}
