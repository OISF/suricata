/* Copyright (C) 2019-2022 Open Information Security Foundation
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
 * \author Jeff Lucovsky <jeff@lucovsky.org>
 *
 * Implements feature tracking
 */

#include "suricata-common.h"
#include "suricata.h"
#include "feature.h"

#include "util-hash.h"

typedef struct FeatureEntryType {
	const char *feature;
} FeatureEntryType;

static SCMutex feature_table_mutex = SCMUTEX_INITIALIZER;
static HashListTable *feature_hash_table;

static uint32_t FeatureHashFunc(HashListTable *ht, void *data,
                                uint16_t datalen)
{
    FeatureEntryType *f = (FeatureEntryType *)data;
    uint32_t hash = 0;
    int len = strlen(f->feature);

    for (int i = 0; i < len; i++)
        hash += u8_tolower((unsigned char)f->feature[i]);

    return (hash % ht->array_size);
}

static char FeatureHashCompareFunc(void *data1, uint16_t datalen1,
                                   void *data2, uint16_t datalen2)
{
    FeatureEntryType *f1 = (FeatureEntryType *)data1;
    FeatureEntryType *f2 = (FeatureEntryType *)data2;
    int len1 = 0;
    int len2 = 0;

    if (f1 == NULL || f2 == NULL)
        return 0;

    if (f1->feature == NULL || f2->feature == NULL)
        return 0;

    len1 = strlen(f1->feature);
    len2 = strlen(f2->feature);

    return (len1 == len2 && memcmp(f1->feature, f2->feature, len1) == 0);
}

static void FeatureHashFreeFunc(void *data)
{
    FeatureEntryType *f = data;
    if (f->feature) {
        SCFree((void *)f->feature);
    }
    SCFree(data);
}

static void FeatureInit(void) {
    feature_hash_table = HashListTableInit(256, FeatureHashFunc,
                                           FeatureHashCompareFunc,
                                           FeatureHashFreeFunc);

    if (!feature_hash_table) {
        FatalError(SC_ERR_MEM_ALLOC, "Unable to allocate feature hash table.");
    }
}

static void FeatureAddEntry(const char *feature_name)
{
    int rc;

    FeatureEntryType *feature = SCCalloc(1, sizeof(*feature));
    if (!feature) {
        FatalError(SC_ERR_MEM_ALLOC, "Unable to allocate feature entry memory.");
    }

    feature->feature = SCStrdup(feature_name);
    if (feature->feature) {
        rc = HashListTableAdd(feature_hash_table, feature, sizeof(*feature));
        if (rc == 0)
            return;
    }

    FeatureHashFreeFunc(feature);
}

void ProvidesFeature(const char *feature_name)
{
    FeatureEntryType f = { feature_name };

    SCMutexLock(&feature_table_mutex);

    FeatureEntryType *feature = HashListTableLookup(feature_hash_table, &f, sizeof(f));

    if (!feature) {
        FeatureAddEntry(feature_name);
    }

    SCMutexUnlock(&feature_table_mutex);
}

bool RequiresFeature(const char *feature_name)
{
    FeatureEntryType f = { feature_name };

    SCMutexLock(&feature_table_mutex);
    FeatureEntryType *feature = HashListTableLookup(feature_hash_table, &f, sizeof(f));
    SCMutexUnlock(&feature_table_mutex);
    return feature != NULL;
}

void FeatureTrackingRelease(void)
{
    if (feature_hash_table != NULL) {
        HashListTableFree(feature_hash_table);
        feature_hash_table = NULL;
    }
}

void FeatureDump(void)
{
    HashListTableBucket *hb = HashListTableGetListHead(feature_hash_table);
    for (; hb != NULL; hb = HashListTableGetListNext(hb)) {
        FeatureEntryType *f = HashListTableGetListData(hb);
        printf("provided feature name: %s\n", f->feature);
    }
}
void FeatureTrackingRegister(void)
{
    FeatureInit();
}
