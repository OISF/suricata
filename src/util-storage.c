/* Copyright (C) 2007-2013 Open Information Security Foundation
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
 *  \file
 *
 *  \author Victor Julien <victor@inliniac.net>
 *
 *  Storage API
 */

#include "suricata-common.h"
#include "util-unittest.h"
#include "util-storage.h"
#include "util-debug.h"

typedef struct StorageMapping_ {
    const char *name;
    StorageEnum type; // host, flow, tx, stream, ssn, etc
    unsigned int size;
    void *(*Alloc)(unsigned int);
    void (*Free)(void *);
} StorageMapping;

/** \brief list of StorageMapping used at registration time */
typedef struct StorageList_ {
    StorageMapping map;
    int id;
    struct StorageList_ *next;
} StorageList;

static StorageList *storage_list = NULL;
static int storage_max_id[STORAGE_MAX];
static int storage_registration_closed = 0;
static StorageMapping **storage_map = NULL;

static const char *StoragePrintType(StorageEnum type)
{
    switch(type) {
        case STORAGE_HOST:
            return "host";
        case STORAGE_FLOW:
            return "flow";
        case STORAGE_IPPAIR:
            return "ippair";
        case STORAGE_DEVICE:
            return "livedevice";
        case STORAGE_MAX:
            return "max";
    }
    return "invalid";
}

void StorageInit(void)
{
    memset(&storage_max_id, 0x00, sizeof(storage_max_id));
    storage_list = NULL;
    storage_map = NULL;
    storage_registration_closed = 0;
}

void StorageCleanup(void)
{
    if (storage_map) {
        int i;
        for (i = 0; i < STORAGE_MAX; i++) {
            if (storage_map[i] != NULL) {
                SCFree(storage_map[i]);
                storage_map[i] = NULL;
            }
        }
        SCFree(storage_map);
        storage_map = NULL;
    }

    StorageList *entry = storage_list;
    while (entry) {
        StorageList *next = entry->next;
        SCFree(entry);
        entry = next;
    }

    storage_list = NULL;
}

int StorageRegister(const StorageEnum type, const char *name, const unsigned int size, void *(*Alloc)(unsigned int), void (*Free)(void *))
{
    if (storage_registration_closed)
        return -1;

    if (type >= STORAGE_MAX || name == NULL || strlen(name) == 0 ||
            size == 0 || (size != sizeof(void *) && Alloc == NULL) || Free == NULL)
        return -1;

    StorageList *list = storage_list;
    while (list) {
        if (strcmp(name, list->map.name) == 0 && type == list->map.type) {
            SCLogError("storage for type \"%s\" with "
                       "name \"%s\" already registered",
                    StoragePrintType(type), name);
            return -1;
        }

        list = list->next;
    }

    StorageList *entry = SCCalloc(1, sizeof(StorageList));
    if (unlikely(entry == NULL))
        return -1;

    entry->map.type = type;
    entry->map.name = name;
    entry->map.size = size;
    entry->map.Alloc = Alloc;
    entry->map.Free = Free;

    entry->id = storage_max_id[type]++;
    entry->next = storage_list;
    storage_list = entry;

    return entry->id;
}

int StorageFinalize(void)
{
    int count = 0;
    int i;

    storage_registration_closed = 1;

    for (i = 0; i < STORAGE_MAX; i++) {
        if (storage_max_id[i] > 0)
            count++;
    }
    if (count == 0)
        return 0;

    storage_map = SCCalloc(STORAGE_MAX, sizeof(StorageMapping *));
    if (unlikely(storage_map == NULL)) {
        return -1;
    }

    for (i = 0; i < STORAGE_MAX; i++) {
        if (storage_max_id[i] > 0) {
            storage_map[i] = SCCalloc(storage_max_id[i], sizeof(StorageMapping));
            if (storage_map[i] == NULL)
                return -1;
        }
    }

    StorageList *entry = storage_list;
    while (entry) {
        if (storage_map[entry->map.type] != NULL) {
            storage_map[entry->map.type][entry->id].name = entry->map.name;
            storage_map[entry->map.type][entry->id].type = entry->map.type;
            storage_map[entry->map.type][entry->id].size = entry->map.size;
            storage_map[entry->map.type][entry->id].Alloc = entry->map.Alloc;
            storage_map[entry->map.type][entry->id].Free = entry->map.Free;
        }

        StorageList *next = entry->next;
        SCFree(entry);
        entry = next;
    };
    storage_list = NULL;

#ifdef DEBUG
    for (i = 0; i < STORAGE_MAX; i++) {
        if (storage_map[i] == NULL)
            continue;

        int j;
        for (j = 0; j < storage_max_id[i]; j++) {
            StorageMapping *m = &storage_map[i][j];
            SCLogDebug("type \"%s\" name \"%s\" size \"%"PRIuMAX"\"",
                    StoragePrintType(m->type), m->name, (uintmax_t)m->size);
        }
    }
#endif
    return 0;
}

unsigned int StorageGetCnt(StorageEnum type)
{
    return storage_max_id[type];
}

/** \brief get the size of the void array used to store
 *         the pointers
 *  \retval size size in bytes, can return 0 if not storage is needed
 *
 *  \todo we could return -1 when registration isn't closed yet, however
 *        this will break lots of tests currently, so not doing it now */
unsigned int StorageGetSize(StorageEnum type)
{
    return storage_max_id[type] * sizeof(void *);
}

void *StorageGetById(const Storage *storage, const StorageEnum type, const int id)
{
#ifdef DEBUG
    BUG_ON(!storage_registration_closed);
#endif
    SCLogDebug("storage %p id %d", storage, id);
    if (storage == NULL)
        return NULL;
    return storage[id].ptr;
}

int StorageSetById(Storage *storage, const StorageEnum type, const int id, void *ptr)
{
#ifdef DEBUG
    BUG_ON(!storage_registration_closed);
#endif
    SCLogDebug("storage %p id %d", storage, id);
    if (storage == NULL)
        return -1;
    storage[id].ptr = ptr;
    return 0;
}

void *StorageAllocByIdPrealloc(Storage *storage, StorageEnum type, int id)
{
#ifdef DEBUG
    BUG_ON(!storage_registration_closed);
#endif
    SCLogDebug("storage %p id %d", storage, id);

    StorageMapping *map = &storage_map[type][id];
    if (storage[id].ptr == NULL && map->Alloc != NULL) {
        storage[id].ptr = map->Alloc(map->size);
        if (storage[id].ptr == NULL) {
            return NULL;
        }
    }

    return storage[id].ptr;
}

void StorageFreeById(Storage *storage, StorageEnum type, int id)
{
#ifdef DEBUG
    BUG_ON(!storage_registration_closed);
#endif
#ifdef UNITTESTS
    if (storage_map == NULL)
        return;
#endif
    SCLogDebug("storage %p id %d", storage, id);

    Storage *store = storage;
    if (store != NULL) {
        SCLogDebug("store %p", store);
        if (store[id].ptr != NULL) {
            StorageMapping *map = &storage_map[type][id];
            map->Free(store[id].ptr);
            store[id].ptr = NULL;
        }
    }
}

void StorageFreeAll(Storage *storage, StorageEnum type)
{
    if (storage == NULL)
        return;
#ifdef DEBUG
    BUG_ON(!storage_registration_closed);
#endif
#ifdef UNITTESTS
    if (storage_map == NULL)
        return;
#endif

    Storage *store = storage;
    int i;
    for (i = 0; i < storage_max_id[type]; i++) {
        if (store[i].ptr != NULL) {
            StorageMapping *map = &storage_map[type][i];
            map->Free(store[i].ptr);
            store[i].ptr = NULL;
        }
    }
}
