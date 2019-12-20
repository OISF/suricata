/* Copyright (C) 2007-2010 Open Information Security Foundation
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
#include "feature.h"
#include "debug.h"

#include "util-hash.h"

typedef struct _FeatureEntryType {
	uint16_t	id;
	const char *feature;
} FeatureEntryType;

static SCMutex feature_table_mutex = SCMUTEX_INITIALIZER;
static uint16_t feature_table_id = 0;
static HashTable *feature_hash_table;

static uint32_t FeatureHashFunc(HashTable *ht, void *data, uint16_t datalen)
{
    FeatureEntryType *f = (FeatureEntryType *)data;
    uint32_t hash = 0;
    int len = strlen(f->feature);

    for (int i = 0; i < len; i++)
        hash += tolower((unsigned char)f->feature[i]);

    hash = hash % ht->array_size;
    return hash;
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

    if (len1 == len2 && memcmp(f1->feature, f2->feature, len1) == 0) {
        return 1;
    }

    return 0;
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
    feature_hash_table = HashTableInit(256, FeatureHashFunc,
                                       FeatureHashCompareFunc,
                                       FeatureHashFreeFunc);
    BUG_ON(feature_hash_table == NULL);
}

static void FeatureAddEntry(const char *feature_name)
{
    FeatureEntryType *feature = SCCalloc(1, sizeof(*feature));
    BUG_ON(feature == NULL);
    feature->feature = SCStrdup(feature_name);
    feature->id = feature_table_id++;
    BUG_ON(HashTableAdd(feature_hash_table, feature, sizeof(*feature)) < 0);
}

void ProvidesFeature(const char *feature_name)
{
    FeatureEntryType f = { 0, feature_name };

    SCMutexLock(&feature_table_mutex);

    FeatureEntryType *feature = HashTableLookup(feature_hash_table, &f, sizeof(f));

    if (!feature) {
        FeatureAddEntry(feature_name);
    }

    SCMutexUnlock(&feature_table_mutex);
}

bool RequiresFeature(const char *feature_name)
{
    FeatureEntryType t = { 0, feature_name };

    SCMutexLock(&feature_table_mutex);
    FeatureEntryType *feature = HashTableLookup(feature_hash_table, &t, sizeof(t));
    SCMutexUnlock(&feature_table_mutex);

    return feature != NULL;
}

void FeatureTrackingRelease(void)
{
    if (feature_hash_table != NULL) {
        HashTableFree(feature_hash_table);
        feature_hash_table = NULL;
        feature_table_id = 0;
    }
}

void FeatureTrackingRegister(void)
{
    FeatureInit();
}
