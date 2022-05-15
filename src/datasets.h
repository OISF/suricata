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
void DatasetReload(void);
void DatasetPostReloadCleanup(void);

enum DatasetTypes {
#define DATASET_TYPE_NOTSET 0
    DATASET_TYPE_STRING = 1,
    DATASET_TYPE_MD5,
    DATASET_TYPE_SHA256,
    DATASET_TYPE_IPV4,
};

#define DATASET_NAME_MAX_LEN 63
typedef struct Dataset {
    char name[DATASET_NAME_MAX_LEN + 1];
    enum DatasetTypes type;
    uint32_t id;
    bool from_yaml;                     /* Mark whether the set was retrieved from YAML */
    bool hidden;                        /* Mark the old sets hidden in case of reload */
    THashTableContext *hash;

    char load[PATH_MAX];
    char save[PATH_MAX];

    struct Dataset *next;
} Dataset;

enum DatasetTypes DatasetGetTypeFromString(const char *s);
Dataset *DatasetFind(const char *name, enum DatasetTypes type);
Dataset *DatasetGet(const char *name, enum DatasetTypes type, const char *save, const char *load,
        uint64_t memcap, uint32_t hashsize);
int DatasetAdd(Dataset *set, const uint8_t *data, const uint32_t data_len);
int DatasetLookup(Dataset *set, const uint8_t *data, const uint32_t data_len);
DataRepResultType DatasetLookupwRep(Dataset *set, const uint8_t *data, const uint32_t data_len,
        const DataRepType *rep);

int DatasetAddSerialized(Dataset *set, const char *string);
int DatasetRemoveSerialized(Dataset *set, const char *string);
int DatasetLookupSerialized(Dataset *set, const char *string);

#endif /* __DATASETS_H__ */
