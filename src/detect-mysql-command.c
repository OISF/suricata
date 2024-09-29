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
 * Detect keyword for Mysql command: mysql.command
 */

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-content-inspection.h"
#include "detect-mysql-command.h"
#include "util-profiling.h"
#include "rust.h"

static int detect_buffer_id = 0;

static int DetectSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (DetectBufferSetActiveList(de_ctx, s, detect_buffer_id) < 0) {
        return -1;
    }
    if (DetectSignatureSetAppProto(s, ALPROTO_MYSQL) < 0) {
        return -1;
    }

    return 0;
}

static InspectionBuffer *GetBuffer(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f, const uint8_t flags, void *txv,
        const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (!buffer->initialized) {
        uint32_t data_len = 0;
        const uint8_t *data = NULL;
        SCMysqlTxGetCommand(txv, &data, &data_len);
        InspectionBufferSetup(det_ctx, list_id, buffer, data, data_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }
    return buffer;
}

void DetectMysqlCommandRegister(void)
{
    static const char *keyword = "mysql.command";
    sigmatch_table[DETECT_AL_MYSQL_COMMAND].name = keyword;
    sigmatch_table[DETECT_AL_MYSQL_COMMAND].desc = "Mysql command";
    sigmatch_table[DETECT_AL_MYSQL_COMMAND].url = "todo";
    sigmatch_table[DETECT_AL_MYSQL_COMMAND].Setup = DetectSetup;
    sigmatch_table[DETECT_AL_MYSQL_COMMAND].flags |= SIGMATCH_NOOPT;

    DetectAppLayerInspectEngineRegister(keyword, ALPROTO_MYSQL, SIG_FLAG_TOSERVER, 0,
            DetectEngineInspectBufferGeneric, GetBuffer);

    DetectBufferTypeSetDescriptionByName(keyword, "mysql command");
    DetectBufferTypeSupportsMultiInstance(keyword);

    detect_buffer_id = DetectBufferTypeGetByName(keyword);
}
