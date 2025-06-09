/* Copyright (C) 2018 Open Information Security Foundation
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
 *  \author Victor Julien <victor@inliniac.net>
 */

#ifndef SURICATA_DETECT_DATASET_H
#define SURICATA_DETECT_DATASET_H

#include "datasets.h"
#include "datasets-context-json.h"

typedef struct DetectDatasetData_ {
    Dataset *set;
    uint8_t cmd;
    DatasetFormats format;
    DataJsonType json;
    char json_key[SIG_JSON_CONTENT_KEY_LEN];
    void *id; /* pointer to the triggering signature */
} DetectDatasetData;

int DetectDatasetBufferMatch(DetectEngineThreadCtx *det_ctx,
    const DetectDatasetData *sd,
    const uint8_t *data, const uint32_t data_len);

/* prototypes */
void DetectDatasetRegister (void);

#endif /* SURICATA_DETECT_DATASET_H */
