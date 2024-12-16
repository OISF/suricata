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
 *  \author Eric Leblond <el@stamus-networks.com>
 */

#ifndef __DETECT_DATAJSON_H__
#define __DETECT_DATAJSON_H__

#include "datasets.h"

#define DETECT_DATAJSON_CMD_ISSET    1
#define DETECT_DATAJSON_CMD_ISNOTSET 2

typedef struct DetectDatajsonData_ {
    Dataset *set;
    uint8_t cmd;
    DataJsonType json;
    char json_key[SIG_JSON_CONTENT_KEY_LEN];
    void *id;
} DetectDatajsonData;

int DetectDatajsonBufferMatch(DetectEngineThreadCtx *det_ctx, const DetectDatajsonData *sd,
        const uint8_t *data, const uint32_t data_len);

/* prototypes */
void DetectDatajsonRegister(void);

#endif /* __DETECT_DATAJSON_H__ */
