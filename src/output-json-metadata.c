/* Copyright (C) 2013-2021 Open Information Security Foundation
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
 * \author Victor Julien <victor@inliniac.net>
 *
 * Logs vars in JSON format.
 *
 */

#include "suricata-common.h"

#include "app-layer-htp.h"

#include "output-json.h"
#include "output-json-metadata.h"

#define MODULE_NAME "JsonMetadataLog"

static int MetadataJson(ThreadVars *tv, OutputJsonThreadCtx *aft, const Packet *p)
{
    JsonBuilder *js = CreateEveHeader(p, LOG_DIR_PACKET, "metadata", NULL, aft->ctx);
    if (unlikely(js == NULL))
        return TM_ECODE_OK;

    /* If metadata is not enabled for eve, explicitly log it here as this is
     * what logging metadata is about. */
    if (!aft->ctx->cfg.include_metadata) {
        EveAddMetadata(p, p->flow, js);
    }
    OutputJsonBuilderBuffer(js, aft);

    jb_free(js);
    return TM_ECODE_OK;
}

static int JsonMetadataLogger(ThreadVars *tv, void *thread_data, const Packet *p)
{
    OutputJsonThreadCtx *aft = thread_data;

    return MetadataJson(tv, aft, p);
}

static int JsonMetadataLogCondition(ThreadVars *tv, void *data, const Packet *p)
{
    if (p->pktvar) {
        return TRUE;
    }
    return FALSE;
}

void JsonMetadataLogRegister (void)
{
    OutputRegisterPacketSubModule(LOGGER_JSON_METADATA, "eve-log", MODULE_NAME, "eve-log.metadata",
            OutputJsonLogInitSub, JsonMetadataLogger, JsonMetadataLogCondition, JsonLogThreadInit,
            JsonLogThreadDeinit, NULL);

    /* Kept for compatibility. */
    OutputRegisterPacketSubModule(LOGGER_JSON_METADATA, "eve-log", MODULE_NAME, "eve-log.vars",
            OutputJsonLogInitSub, JsonMetadataLogger, JsonMetadataLogCondition, JsonLogThreadInit,
            JsonLogThreadDeinit, NULL);
}
