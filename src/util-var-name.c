/* Copyright (C) 2007-2016 Open Information Security Foundation
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
#include "util-var-name.h"

/* the way this can be used w/o locking lookups:
 * - Lookups use only g_varnamestore_current which is read only
 * - Detection setups a new ctx in staging, which will include the 'current'
 *   entries keeping ID's stable
 * - Detection hot swaps staging into current after a new detect engine was
 *   created. Current remains available through 'old'.
 * - When detect reload is complete (threads are all moved over), 'old' can
 *   be freed.
 */

typedef struct VarNameStore_ {
    HashListTable *names;
    HashListTable *ids;
    uint32_t max_id;
    uint32_t de_ctx_version;    /**< de_ctx version 'owning' this */
} VarNameStore;

static int initialized = 0;
/* currently VarNameStore that is READ ONLY. This way lookups can
 * be done w/o locking or synchronization */
SC_ATOMIC_DECLARE(VarNameStore *, g_varnamestore_current);

/* old VarNameStore on the way out */
static VarNameStore *g_varnamestore_old = NULL;

/* new VarNameStore that is being prepared. Multiple DetectLoader threads
 * may be updating it so a lock is used for synchronization. */
static VarNameStore *g_varnamestore_staging = NULL;
static SCMutex g_varnamestore_staging_m = SCMUTEX_INITIALIZER;

/** \brief Name2idx mapping structure for flowbits, flowvars and pktvars. */
typedef struct VariableName_ {
    char *name;
    enum VarTypes type; /* flowbit, pktvar, etc */
    uint32_t idx;
} VariableName;

#define VARNAME_HASHSIZE 0x1000
#define VARID_HASHSIZE 0x1000

static uint32_t VariableNameHash(HashListTable *ht, void *buf, uint16_t buflen)
{
     VariableName *fn = (VariableName *)buf;
     uint32_t hash = strlen(fn->name) + fn->type;
     uint16_t u;

     for (u = 0; u < buflen; u++) {
         hash += fn->name[u];
     }

     return (hash % VARNAME_HASHSIZE);
}

static char VariableNameCompare(void *buf1, uint16_t len1, void *buf2, uint16_t len2)
{
    VariableName *fn1 = (VariableName *)buf1;
    VariableName *fn2 = (VariableName *)buf2;

    if (fn1->type != fn2->type)
        return 0;

    if (strcmp(fn1->name,fn2->name) == 0)
        return 1;

    return 0;
}

static uint32_t VariableIdxHash(HashListTable *ht, void *buf, uint16_t buflen)
{
    VariableName *fn = (VariableName *)buf;
    uint32_t hash = fn->idx + fn->type;
    return (hash % VARID_HASHSIZE);
}

static char VariableIdxCompare(void *buf1, uint16_t len1, void *buf2, uint16_t len2)
{
    VariableName *fn1 = (VariableName *)buf1;
    VariableName *fn2 = (VariableName *)buf2;

    if (fn1->type != fn2->type)
        return 0;

    if (fn1->idx == fn2->idx)
        return 1;

    return 0;
}

static void VariableNameFree(void *data)
{
    VariableName *fn = (VariableName *)data;

    if (fn == NULL)
        return;

    if (fn->name != NULL) {
        SCFree(fn->name);
        fn->name = NULL;
    }

    SCFree(fn);
}

/** \brief Initialize the Name idx hash.
 */
static VarNameStore *VarNameStoreInit(void)
{
    VarNameStore *v = SCCalloc(1, sizeof(*v));
    if (v == NULL)
        return NULL;

    v->names = HashListTableInit(VARNAME_HASHSIZE, VariableNameHash, VariableNameCompare, VariableNameFree);
    if (v->names == NULL) {
        SCFree(v);
        return NULL;
    }

    v->ids = HashListTableInit(VARID_HASHSIZE, VariableIdxHash, VariableIdxCompare, NULL);
    if (v->ids == NULL) {
        HashListTableFree(v->names);
        SCFree(v);
        return NULL;
    }

    v->max_id = 0;
    return v;
}

static void VarNameStoreDoFree(VarNameStore *v)
{
    if (v) {
        HashListTableFree(v->names);
        HashListTableFree(v->ids);
        SCFree(v);
    }
}


/** \brief Get a name idx for a name. If the name is already used reuse the idx.
 *  \param name nul terminated string with the name
 *  \param type variable type
 *  \retval 0 in case of error
 *  \retval idx the idx or 0
 */
static uint32_t VariableNameGetIdx(VarNameStore *v, const char *name, enum VarTypes type)
{
    uint32_t idx = 0;

    VariableName *fn = SCMalloc(sizeof(VariableName));
    if (unlikely(fn == NULL))
        goto error;

    memset(fn, 0, sizeof(VariableName));

    fn->type = type;
    fn->name = SCStrdup(name);
    if (fn->name == NULL)
        goto error;

    VariableName *lookup_fn = (VariableName *)HashListTableLookup(v->names, (void *)fn, 0);
    if (lookup_fn == NULL) {
        v->max_id++;

        idx = fn->idx = v->max_id;
        HashListTableAdd(v->names, (void *)fn, 0);
        HashListTableAdd(v->ids, (void *)fn, 0);
        SCLogDebug("new registration %s id %u type %u", fn->name, fn->idx, fn->type);
    } else {
        idx = lookup_fn->idx;
        VariableNameFree(fn);
    }

    return idx;
error:
    VariableNameFree(fn);
    return 0;
}

/** \brief Get a name from the idx.
 *  \param idx index of the variable whose name is to be fetched
 *  \param type variable type
 *  \retval NULL in case of error
 *  \retval name of the variable if successful.
 *  \todo no alloc on lookup
 */
static char *VariableIdxGetName(VarNameStore *v, uint32_t idx, enum VarTypes type)
{
    VariableName *fn = SCMalloc(sizeof(VariableName));
    if (unlikely(fn == NULL))
        goto error;

    char *name = NULL;
    memset(fn, 0, sizeof(VariableName));

    fn->type = type;
    fn->idx = idx;

    VariableName *lookup_fn = (VariableName *)HashListTableLookup(v->ids, (void *)fn, 0);
    if (lookup_fn != NULL) {
        name = SCStrdup(lookup_fn->name);
        if (unlikely(name == NULL))
            goto error;

        VariableNameFree(fn);
    } else {
        goto error;
    }

    return name;
error:
    VariableNameFree(fn);
    return NULL;
}

/** \brief setup staging store. Include current store if there is one.
 */
int VarNameStoreSetupStaging(uint32_t de_ctx_version)
{
    SCMutexLock(&g_varnamestore_staging_m);

    if (!initialized) {
        SC_ATOMIC_INITPTR(g_varnamestore_current);
        initialized = 1;
    }

    if (g_varnamestore_staging != NULL &&
        g_varnamestore_staging->de_ctx_version == de_ctx_version) {
        SCMutexUnlock(&g_varnamestore_staging_m);
        return 0;
    }

    VarNameStore *nv = VarNameStoreInit();
    if (nv == NULL) {
        SCMutexUnlock(&g_varnamestore_staging_m);
        return -1;
    }
    g_varnamestore_staging = nv;
    nv->de_ctx_version = de_ctx_version;

    VarNameStore *current = SC_ATOMIC_GET(g_varnamestore_current);
    if (current) {
        /* add all entries from the current hash into this new one. */
        HashListTableBucket *b = HashListTableGetListHead(current->names);
        while (b) {
            VariableName *var = HashListTableGetListData(b);

            VariableName *newvar = SCCalloc(1, sizeof(*newvar));
            BUG_ON(newvar == NULL);
            memcpy(newvar, var, sizeof(*newvar));
            newvar->name = SCStrdup(var->name);
            BUG_ON(newvar->name == NULL);

            HashListTableAdd(nv->names, (void *)newvar, 0);
            HashListTableAdd(nv->ids, (void *)newvar, 0);
            nv->max_id = MAX(nv->max_id, newvar->idx);
            SCLogDebug("xfer %s id %u type %u", newvar->name, newvar->idx, newvar->type);

            b = HashListTableGetListNext(b);
        }
    }

    SCLogDebug("set up staging with detect engine ver %u", nv->de_ctx_version);
    SCMutexUnlock(&g_varnamestore_staging_m);
    return 0;
}

const char *VarNameStoreLookupById(const uint32_t id, const enum VarTypes type)
{
    VarNameStore *current = SC_ATOMIC_GET(g_varnamestore_current);
    BUG_ON(current == NULL);
    VariableName lookup = { NULL, type, id };
    VariableName *found = (VariableName *)HashListTableLookup(current->ids, (void *)&lookup, 0);
    if (found == NULL) {
        return NULL;
    }
    return found->name;
}

uint32_t VarNameStoreLookupByName(const char *name, const enum VarTypes type)
{
    VarNameStore *current = SC_ATOMIC_GET(g_varnamestore_current);
    BUG_ON(current == NULL);
    VariableName lookup = { (char *)name, type, 0 };
    VariableName *found = (VariableName *)HashListTableLookup(current->names, (void *)&lookup, 0);
    if (found == NULL) {
        return 0;
    }
    SCLogDebug("found %u for %s type %u", found->idx, name, type);
    return found->idx;
}

/** \brief add to staging or return existing id if already in there */
uint32_t VarNameStoreSetupAdd(const char *name, const enum VarTypes type)
{
    uint32_t id;
    SCMutexLock(&g_varnamestore_staging_m);
    id = VariableNameGetIdx(g_varnamestore_staging, name, type);
    SCMutexUnlock(&g_varnamestore_staging_m);
    return id;
}

char *VarNameStoreSetupLookup(uint32_t idx, const enum VarTypes type)
{
    SCMutexLock(&g_varnamestore_staging_m);
    char *name = VariableIdxGetName(g_varnamestore_staging, idx, type);
    SCMutexUnlock(&g_varnamestore_staging_m);
    return name;
}

void VarNameStoreActivateStaging(void)
{
    SCMutexLock(&g_varnamestore_staging_m);
    if (g_varnamestore_old) {
        VarNameStoreDoFree(g_varnamestore_old);
        g_varnamestore_old = NULL;
    }
    g_varnamestore_old = SC_ATOMIC_GET(g_varnamestore_current);
    SC_ATOMIC_SET(g_varnamestore_current, g_varnamestore_staging);
    g_varnamestore_staging = NULL;
    SCMutexUnlock(&g_varnamestore_staging_m);
}

void VarNameStoreFreeOld(void)
{
    SCMutexLock(&g_varnamestore_staging_m);
    SCLogDebug("freeing g_varnamestore_old %p", g_varnamestore_old);
    if (g_varnamestore_old) {
        VarNameStoreDoFree(g_varnamestore_old);
        g_varnamestore_old = NULL;
    }
    SCMutexUnlock(&g_varnamestore_staging_m);
}

void VarNameStoreFree(uint32_t de_ctx_version)
{
    SCLogDebug("freeing detect engine version %u", de_ctx_version);
    SCMutexLock(&g_varnamestore_staging_m);
    if (g_varnamestore_old && g_varnamestore_old->de_ctx_version == de_ctx_version) {
        VarNameStoreDoFree(g_varnamestore_old);
        g_varnamestore_old = NULL;
        SCLogDebug("freeing detect engine version %u: old done", de_ctx_version);
    }

    /* if at this point we have a staging area which matches our version
     * we didn't complete the setup and are cleaning up the mess. */
    if (g_varnamestore_staging && g_varnamestore_staging->de_ctx_version == de_ctx_version) {
        VarNameStoreDoFree(g_varnamestore_staging);
        g_varnamestore_staging = NULL;
        SCLogDebug("freeing detect engine version %u: staging done", de_ctx_version);
    }

    VarNameStore *current = SC_ATOMIC_GET(g_varnamestore_current);
    if (current && current->de_ctx_version == de_ctx_version) {
        VarNameStoreDoFree(current);
        SC_ATOMIC_SET(g_varnamestore_current, NULL);
        SCLogDebug("freeing detect engine version %u: current done", de_ctx_version);
    }
    SCMutexUnlock(&g_varnamestore_staging_m);
}
