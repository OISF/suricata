/* Copyright (C) 2013-2022 Open Information Security Foundation
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
#include "debug.h"
#include "detect.h"
#include "flow.h"
#include "conf.h"

#include "threads.h"
#include "tm-threads.h"
#include "threadvars.h"
#include "util-debug.h"

#include "util-misc.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-reference.h"
#include "app-layer-parser.h"
#include "app-layer-dnp3.h"
#include "app-layer-htp.h"
#include "app-layer-htp-xff.h"
#include "util-classification-config.h"
#include "util-syslog.h"
#include "util-logopenfile.h"

#include "output.h"
#include "output-json.h"
#include "output-json-metadata.h"

#include "util-byte.h"
#include "util-privs.h"
#include "util-print.h"
#include "util-proto-name.h"
#include "util-optimize.h"
#include "util-buffer.h"

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
