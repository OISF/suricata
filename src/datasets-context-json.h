/* Copyright (C) 2024 Open Information Security Foundation
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
 * \author Eric Leblond <el@stamus-networks.com>
 */

#ifndef SURICATA_DATASETS_CONTEXT_JSON_H
#define SURICATA_DATASETS_CONTEXT_JSON_H

#include "suricata-common.h"
#include "datasets.h"

#define DATAJSON_JSON_LENGTH 1024

typedef struct DataJsonType {
    char *value;
    uint16_t len;
} DataJsonType;

typedef struct DataJsonResultType {
    bool found;
    DataJsonType json;
    THashData *hashdata;
} DataJsonResultType;

/* Common functions */

Dataset *DatajsonGet(const char *name, enum DatasetTypes type, const char *load, uint64_t memcap,
        uint32_t hashsize, char *json_key_value, char *json_array_key, DatasetFormats format,
        bool remove_key);

DataJsonResultType DatajsonLookup(Dataset *set, const uint8_t *data, const uint32_t data_len);

int DatajsonAddSerialized(Dataset *set, const char *value, const char *json);

void DatajsonUnlockElt(DataJsonResultType *r);

int DatajsonCopyJson(DataJsonType *dst, DataJsonType *src);

#endif /* SURICATA_DATASETS_CONTEXT_JSON_H */
