/* Copyright (C) 2023 Open Information Security Foundation
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
 * \author Juliana Fajardini <jufajardini@oisf.net>
 *
 * JSON Verdict log module to log the matched rules' final verdict on the packet
 * information
 *
 */

#include "action-globals.h"

#include "output.h"
#include "output-json.h"
#include "output-json-alert.h"
#include "output-json-verdict.h"

#include "packet.h"

#include "suricata.h"
#include "suricata-common.h"

#define MODULE_NAME "JsonVerdictLog"

typedef struct JsonVerdictOutputCtx_ {
    uint8_t flags;
    OutputJsonCtx *eve_ctx;
} JsonVerdictOutputCtx;

typedef struct JsonVerdictLogThread_ {
    JsonVerdictOutputCtx *verdict_ctx;
    OutputJsonThreadCtx *ctx;
} JsonVerdictLogThread;

void GetVerdictJsonInfo(JsonBuilder *jb, const Packet *p)
{
    jb_open_object(jb, "verdict");
    /* add verdict info */
    if (PacketCheckAction(p, ACTION_DROP) && EngineModeIsIPS()) {
        JB_SET_STRING(jb, "action", "drop");
    } else if (PacketCheckAction(p, ACTION_REJECT_ANY)) {
        // check rule to define type of reject packet sent
        if (EngineModeIsIPS()) {
            JB_SET_STRING(jb, "action", "drop");
        } else {
            JB_SET_STRING(jb, "action", "alert");
        }
        if (p->action & ACTION_REJECT || p->action) {
            JB_SET_STRING(jb, "reject-target", "source");
        } else if (p->action & ACTION_REJECT_DST) {
            JB_SET_STRING(jb, "reject-target", "destination");
        } else if (p->action & ACTION_REJECT_BOTH) {
            JB_SET_STRING(jb, "reject-target", "both");
        }
        JB_SET_STRING(jb, "reject", "[tcp-reset, icmp-prohib, user defined]");
    } else if (PacketCheckAction(p, ACTION_PASS)) {
        JB_SET_STRING(jb, "action", "pass");
    } else {
        // TODO make sure we don't have a situation where this wouldn't work
        JB_SET_STRING(jb, "action", "alert");
    }

    /* Close verdict */
    jb_close(jb);

    return;
}

static int VerdictJson(JsonVerdictLogThread *vlt, const Packet *p)
{
    JsonVerdictOutputCtx *verdict_ctx = vlt->verdict_ctx;

    JsonAddrInfo addr = json_addr_info_zero;
    JsonAddrInfoInit(p, LOG_DIR_PACKET, &addr);

    JsonBuilder *jb = CreateEveHeader(p, LOG_DIR_PACKET, "verdict", &addr, verdict_ctx->eve_ctx);

    if (unlikely(jb == NULL))
        return TM_ECODE_OK;

    GetVerdictJsonInfo(jb, p);

    OutputJsonBuilderBuffer(jb, vlt->ctx);
    jb_free(jb);

    return TM_ECODE_OK;
}

/**
 * \brief   Log the final verdict for a packet, based on matched rules
 *
 * \param tv           Pointer to the current thread variables
 * \param thread_data  Pointer to the verdict log structure
 * \param p            Pointer to the packet that stores the info on verdict
 *
 * \return 0 on success
 */
static int JsonVerdictLogger(ThreadVars *tv, void *thread_data, const Packet *p)
{
    JsonVerdictLogThread *vlt = thread_data;

    int r = VerdictJson(vlt, p);

    if (r < 0) {
        return -1;
    }

    return 0;
}

static int JsonVerdictLogCondition(ThreadVars *tv, void *thread_data, const Packet *p)
{
    if (p->alerts.cnt > 0) {
        return TRUE;
    }

    return FALSE;
}

static TmEcode JsonVerdictLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    JsonVerdictLogThread *vlt = SCCalloc(1, sizeof(JsonVerdictLogThread));
    if (unlikely(vlt == NULL))
        return TM_ECODE_FAILED;

    if (initdata == NULL) {
        SCLogDebug("Error getting context for EvLogVerdict. \"initdata\" argument NULL");
        goto error_exit;
    }

    /** Use the Output Context */
    vlt->verdict_ctx = ((OutputCtx *)initdata)->data;
    vlt->ctx = CreateEveThreadCtx(t, vlt->verdict_ctx->eve_ctx);
    if (!vlt->ctx) {
        goto error_exit;
    }

    *data = (void *)vlt;
    return TM_ECODE_OK;

error_exit:
    SCFree(vlt);
    return TM_ECODE_FAILED;
}

static TmEcode JsonVerdictLogThreadDeInit(ThreadVars *t, void *data)
{
    JsonVerdictLogThread *vlt = (JsonVerdictLogThread *)data;
    if (vlt == NULL) {
        return TM_ECODE_OK;
    }

    FreeEveThreadCtx(vlt->ctx);

    /* clear memory */
    memset(vlt, 0, sizeof(*vlt));

    SCFree(vlt);
    return TM_ECODE_OK;
}

static void JsonVerdictOutputCtxFree(JsonVerdictOutputCtx *verdict_ctx)
{
    if (verdict_ctx != NULL) {
        SCFree(verdict_ctx);
    }
}

static void JsonVerdictLogDeInitCtxSub(OutputCtx *output_ctx)
{
    SCLogDebug("cleaning up sub output_ctx %p", output_ctx);
    JsonVerdictOutputCtx *verdict_ctx = (JsonVerdictOutputCtx *)output_ctx->data;

    if (verdict_ctx != NULL) {
        SCFree(verdict_ctx);
    }
    SCFree(output_ctx);
}

static OutputInitResult JsonVerdictLogInitCtxSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *vlt = parent_ctx->data;

    JsonVerdictOutputCtx *verdict_ctx = SCCalloc(1, sizeof(*verdict_ctx));
    if (unlikely(verdict_ctx == NULL))
        return result;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        JsonVerdictOutputCtxFree(verdict_ctx);
        return result;
    }
    memset(verdict_ctx, 0, sizeof(JsonVerdictOutputCtx));

    verdict_ctx->eve_ctx = vlt;

    output_ctx->data = verdict_ctx;
    output_ctx->DeInit = JsonVerdictLogDeInitCtxSub;

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

void JsonVerdictLogRegister(void)
{
    OutputRegisterPacketSubModule(LOGGER_JSON_VERDICT, "eve-log", MODULE_NAME, "eve-log.verdict",
            JsonVerdictLogInitCtxSub, JsonVerdictLogger, JsonVerdictLogCondition,
            JsonVerdictLogThreadInit, JsonVerdictLogThreadDeInit, NULL);
}