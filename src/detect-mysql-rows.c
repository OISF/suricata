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
 * Detect keyword for Mysql rows: mysql.rows
 */

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-content-inspection.h"
#include "detect-mysql-rows.h"
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
        const int list_id, uint32_t local_id)
{
    SCEnter();

    InspectionBuffer *buffer = InspectionBufferMultipleForListGet(det_ctx, list_id, local_id);
    if (buffer == NULL)
        return NULL;
    if (buffer->initialized)
        return buffer;

    const uint8_t *data;
    uint32_t data_len;
    if (SCMysqlGetRowsData(txv, local_id, &data, &data_len) == 0) {
        InspectionBufferSetupMultiEmpty(buffer);
        return NULL;
    }
    InspectionBufferSetupMulti(buffer, transforms, data, data_len);
    buffer->flags = DETECT_CI_FLAGS_SINGLE;

    SCReturnPtr(buffer, "InspectionBuffer");
    return buffer;
}

void DetectMysqlRowsRegister(void)
{
    static const char *keyword = "mysql.rows";
    sigmatch_table[DETECT_AL_MYSQL_ROWS].name = keyword;
    sigmatch_table[DETECT_AL_MYSQL_ROWS].desc = "Mysql rows";
    sigmatch_table[DETECT_AL_MYSQL_ROWS].url = "todo";
    sigmatch_table[DETECT_AL_MYSQL_ROWS].Setup = DetectSetup;
    sigmatch_table[DETECT_AL_MYSQL_ROWS].flags |= SIGMATCH_NOOPT;

     DetectAppLayerMultiRegister(keyword, ALPROTO_MYSQL, SIG_FLAG_TOCLIENT, 0,
            GetBuffer, 2, 1);

    DetectBufferTypeSetDescriptionByName(keyword, "mysql rows");
    DetectBufferTypeSupportsMultiInstance(keyword);

    detect_buffer_id = DetectBufferTypeGetByName(keyword);
}
