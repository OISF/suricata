/* Copyright (C) 2017 Open Information Security Foundation
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

#ifndef __DATASETS_H__
#define __DATASETS_H__

#include "util-thash.h"
#include "datasets-reputation.h"

int DatasetsInit(void);
void DatasetsDestroy(void);
void DatasetsSave(void);

enum DatasetTypes {
#define DATASET_TYPE_NOTSET 0
    DATASET_TYPE_STRING = 1,
    DATASET_TYPE_MD5,
    DATASET_TYPE_SHA256,
};

typedef struct Dataset {
    char name[64];
    enum DatasetTypes type;
    uint32_t id;

    THashTableContext *hash;

    char load[PATH_MAX];
    char save[PATH_MAX];

    struct Dataset *next;
} Dataset;

Dataset *DatasetGetByName(const char *name);
Dataset *DatasetGet(const char *name, enum DatasetTypes type,
        const char *save, const char *load);
int DatasetAdd(Dataset *set, const uint8_t *data, const uint32_t data_len);
int DatasetLookup(Dataset *set, const uint8_t *data, const uint32_t data_len);
DataRepResultType DatasetLookupwRep(Dataset *set, const uint8_t *data, const uint32_t data_len,
        const DataRepType *rep);

#endif /* __DATASETS_H__ */
