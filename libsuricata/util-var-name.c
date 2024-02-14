/* Copyright (C) 2007-2023 Open Information Security Foundation
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
 * \author Victor Julien <victor@inliniac.net>
 *
 * Generic variable name utility functions
 */

#include "suricata-common.h"
#include "detect.h"
#include "util-hash-string.h"
#include "util-hashlist.h"
#include "util-var-name.h"
#include "util-validate.h"

/* Overall Design:
 *
 * Base Store: "base"
 *
 * Used during keyword registration. Operates under lock. Base is shared
 * between all detect engines, detect engine versions and tenants.
 * Each variable name is ref counted.
 *
 * During the freeing of a detect engine / tenant, unregistration decreases
 * the ref cnt.
 *
 * Base has both a string to id and a id to string hash table. String to
 * id is used during parsing/registration. id to string during unregistration.
 *
 *
 * Active Store Pointer (atomic)
 *
 * The "active" store atomic pointer points to the active store. The call
 * to `VarNameStoreActivate` will build a new lookup store and hot swap
 * the pointer.
 *
 * Ensuring memory safety. During the hot swap, the pointer is replaced, so
 * any new call to the lookup functions will automatically use the new store.
 * This leaves the case of any lookup happening concurrently with the pointer
 * swap. For this case we add the old store to a free list. It gets a timestamp
 * before which it cannot be freed.
 *
 *
 * Free List
 *
 * The free list contains old stores that are waiting to get removed. They
 * contain a timestamp that is checked before they are freed.
 *
 */
typedef struct VarNameStore_ {
    HashListTable *names;
    HashListTable *ids;
    uint32_t max_id;
    struct timeval free_after;
    TAILQ_ENTRY(VarNameStore_) next;
} VarNameStore;
typedef VarNameStore *VarNameStorePtr;

/** \brief Name2idx mapping structure for flowbits, flowvars and pktvars. */
typedef struct VariableName_ {
    char *name;
    enum VarTypes type; /* flowbit, pktvar, etc */
    uint32_t id;
    uint32_t ref_cnt;
} VariableName;

#define VARNAME_HASHSIZE 0x1000
#define VARID_HASHSIZE 0x1000

static SCMutex base_lock = SCMUTEX_INITIALIZER;
static VarNameStore base = { .names = NULL, .ids = NULL, .max_id = 0 };
static TAILQ_HEAD(, VarNameStore_) free_list = TAILQ_HEAD_INITIALIZER(free_list);
static SC_ATOMIC_DECLARE(VarNameStorePtr, active);

static uint32_t VariableNameHash(HashListTable *ht, void *buf, uint16_t buflen);
static char VariableNameCompare(void *buf1, uint16_t len1, void *buf2, uint16_t len2);
static uint32_t VariableIdHash(HashListTable *ht, void *ptr, uint16_t _unused);
static char VariableIdCompare(void *ptr1, uint16_t _unused1, void *ptr2, uint16_t _unused2);
static void VariableNameFree(void *data);

void VarNameStoreInit(void)
{
    SCMutexLock(&base_lock);
    base.names = HashListTableInit(
            VARNAME_HASHSIZE, VariableNameHash, VariableNameCompare, VariableNameFree);
    if (base.names == NULL) {
        FatalError("failed to initialize variable name hash (names)");
    }

    /* base.names owns the allocation, so use a NULL Free pointer here */
    base.ids = HashListTableInit(VARID_HASHSIZE, VariableIdHash, VariableIdCompare, NULL);
    if (base.ids == NULL) {
        FatalError("failed to initialize variable name hash (names)");
    }
    SC_ATOMIC_INITPTR(active);
    SCMutexUnlock(&base_lock);
}

void VarNameStoreDestroy(void)
{
    SCMutexLock(&base_lock);
    VarNameStore *s = SC_ATOMIC_GET(active);
    if (s) {
        HashListTableFree(s->names);
        HashListTableFree(s->ids);
        SCFree(s);
        s = NULL;
    }
    SC_ATOMIC_SET(active, NULL);

    while ((s = TAILQ_FIRST(&free_list))) {
        TAILQ_REMOVE(&free_list, s, next);
        HashListTableFree(s->names);
        HashListTableFree(s->ids);
        SCFree(s);
    }

    for (HashListTableBucket *b = HashListTableGetListHead(base.names); b != NULL;
            b = HashListTableGetListNext(b)) {
        VariableName *vn = HashListTableGetListData(b);
        DEBUG_VALIDATE_BUG_ON(vn->ref_cnt > 0);
        if (vn->ref_cnt > 0) {
            SCLogWarning("%s (type %u, id %u) still has ref_cnt %u", vn->name, vn->type, vn->id,
                    vn->ref_cnt);
        }
    }
    HashListTableFree(base.ids);
    base.ids = NULL;
    HashListTableFree(base.names);
    base.names = NULL;
    base.max_id = 0;
    SCMutexUnlock(&base_lock);
}

/**
 *  \retval id or 0 on error
 */
uint32_t VarNameStoreRegister(const char *name, const enum VarTypes type)
{
    SCMutexLock(&base_lock);
    uint32_t id = 0;

    SCLogDebug("registering: name %s type %u", name, type);
    VariableName lookup = { .type = type, .name = (char *)name };
    VariableName *found = (VariableName *)HashListTableLookup(base.names, (void *)&lookup, 0);
    if (found == NULL) {
        VariableName *vn = SCCalloc(1, sizeof(VariableName));
        if (likely(vn != NULL)) {
            vn->type = type;
            vn->name = SCStrdup(name);
            if (vn->name != NULL) {
                vn->ref_cnt = 1;
                id = vn->id = ++base.max_id;
                HashListTableAdd(base.names, (void *)vn, 0);
                HashListTableAdd(base.ids, (void *)vn, 0);
                SCLogDebug(
                        "new registration %s id %u type %u -> %u", vn->name, vn->id, vn->type, id);
            } else {
                SCFree(vn);
            }
        }
    } else {
        id = found->id;
        found->ref_cnt++;
        SCLogDebug("existing registration %s ref_cnt %u -> %u", name, found->ref_cnt, id);
    }
    SCMutexUnlock(&base_lock);
    return id;
}

const char *VarNameStoreSetupLookup(const uint32_t id, const enum VarTypes type)
{
    const char *name = NULL;
    SCMutexLock(&base_lock);
    VariableName lookup = { .type = type, .id = id };
    VariableName *found = (VariableName *)HashListTableLookup(base.ids, (void *)&lookup, 0);
    if (found) {
        name = found->name;
    }
    SCMutexUnlock(&base_lock);
    return name;
}

void VarNameStoreUnregister(const uint32_t id, const enum VarTypes type)
{
    SCMutexLock(&base_lock);
    VariableName lookup = { .type = type, .id = id };
    VariableName *found = (VariableName *)HashListTableLookup(base.ids, (void *)&lookup, 0);
    if (found) {
        SCLogDebug("found %s ref_cnt %u", found->name, found->ref_cnt);
        DEBUG_VALIDATE_BUG_ON(found->ref_cnt == 0);
        found->ref_cnt--;
    }
    SCMutexUnlock(&base_lock);
}

int VarNameStoreActivate(void)
{
    int result = 0;
    SCMutexLock(&base_lock);
    SCLogDebug("activating new lookup store");

    VarNameStore *new_active = NULL;

    // create lookup hash for id to string, strings should point to base
    for (HashListTableBucket *b = HashListTableGetListHead(base.names); b != NULL;
            b = HashListTableGetListNext(b)) {
        VariableName *vn = HashListTableGetListData(b);
        BUG_ON(vn == NULL);
        SCLogDebug("base: %s/%u/%u", vn->name, vn->id, vn->ref_cnt);
        if (vn->ref_cnt == 0)
            continue;

        if (new_active == NULL) {
            new_active = SCCalloc(1, sizeof(*new_active));
            if (new_active == NULL) {
                result = -1;
                goto out;
            }

            new_active->names = HashListTableInit(
                    VARNAME_HASHSIZE, VariableNameHash, VariableNameCompare, NULL);
            if (new_active->names == NULL) {
                SCFree(new_active);
                result = -1;
                goto out;
            }
            new_active->ids =
                    HashListTableInit(VARID_HASHSIZE, VariableIdHash, VariableIdCompare, NULL);
            if (new_active->ids == NULL) {
                HashListTableFree(new_active->names);
                SCFree(new_active);
                result = -1;
                goto out;
            }
        }

        /* memory is still owned by "base" */
        HashListTableAdd(new_active->names, (void *)vn, 0);
        HashListTableAdd(new_active->ids, (void *)vn, 0);
    }

    if (new_active) {
        VarNameStore *old_active = SC_ATOMIC_GET(active);
        if (old_active) {
            struct timeval ts, add;
            memset(&ts, 0, sizeof(ts));
            memset(&add, 0, sizeof(add));
            gettimeofday(&ts, NULL);
            add.tv_sec = 60;
            timeradd(&ts, &add, &ts);
            old_active->free_after = ts;

            TAILQ_INSERT_TAIL(&free_list, old_active, next);
            SCLogDebug("old active is stored in free list");
        }

        SC_ATOMIC_SET(active, new_active);
        SCLogDebug("new store active");

        struct timeval now;
        memset(&now, 0, sizeof(now));
        gettimeofday(&now, NULL);

        VarNameStore *s = NULL;
        while ((s = TAILQ_FIRST(&free_list))) {
            char timebuf[64];
            CreateIsoTimeString(SCTIME_FROM_TIMEVAL(&s->free_after), timebuf, sizeof(timebuf));

            if (!timercmp(&now, &s->free_after, >)) {
                SCLogDebug("not yet freeing store %p before %s", s, timebuf);
                break;
            }
            SCLogDebug("freeing store %p with time %s", s, timebuf);
            TAILQ_REMOVE(&free_list, s, next);
            HashListTableFree(s->names);
            HashListTableFree(s->ids);
            SCFree(s);
        }
    }
out:
    SCLogDebug("activating new lookup store: complete %d", result);
    SCMutexUnlock(&base_lock);
    return result;
}

/** \brief find name for id+type at packet time. */
const char *VarNameStoreLookupById(const uint32_t id, const enum VarTypes type)
{
    const char *name = NULL;

    const VarNameStore *current = SC_ATOMIC_GET(active);
    if (current) {
        VariableName lookup = { .type = type, .id = id };
        const VariableName *found = HashListTableLookup(current->ids, (void *)&lookup, 0);
        if (found) {
            return found->name;
        }
    }

    return name;
}

/** \brief find name for id+type at packet time. */
uint32_t VarNameStoreLookupByName(const char *name, const enum VarTypes type)
{
    const VarNameStore *current = SC_ATOMIC_GET(active);
    if (current) {
        VariableName lookup = { .name = (char *)name, .type = type };
        const VariableName *found = HashListTableLookup(current->names, (void *)&lookup, 0);
        if (found) {
            return found->id;
        }
    }

    return 0;
}

static uint32_t VariableNameHash(HashListTable *ht, void *buf, uint16_t buflen)
{
    VariableName *vn = (VariableName *)buf;
    uint32_t hash = StringHashDjb2((const uint8_t *)vn->name, strlen(vn->name)) + vn->type;
    return (hash % VARNAME_HASHSIZE);
}

static char VariableNameCompare(void *buf1, uint16_t len1, void *buf2, uint16_t len2)
{
    VariableName *vn1 = (VariableName *)buf1;
    VariableName *vn2 = (VariableName *)buf2;
    return (vn1->type == vn2->type && strcmp(vn1->name, vn2->name) == 0);
}

static uint32_t VariableIdHash(HashListTable *ht, void *ptr, uint16_t _unused)
{
    VariableName *vn = (VariableName *)ptr;
    uint32_t hash = vn->id << vn->type;
    return (hash % VARID_HASHSIZE);
}

static char VariableIdCompare(void *ptr1, uint16_t _unused1, void *ptr2, uint16_t _unused2)
{
    VariableName *vn1 = (VariableName *)ptr1;
    VariableName *vn2 = (VariableName *)ptr2;

    return (vn1->id == vn2->id && vn1->type == vn2->type);
}

static void VariableNameFree(void *data)
{
    VariableName *vn = (VariableName *)data;
    if (vn == NULL)
        return;
    if (vn->name != NULL) {
        SCFree(vn->name);
        vn->name = NULL;
    }
    SCFree(vn);
}
