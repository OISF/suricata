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
 * \author Victor Julien <victor@inliniac.net>
 *
 * Generic variable name utility functions
 */

#include "suricata-common.h"
#include "detect.h"
#include "util-hashlist.h"

HashListTable *variable_names;
HashListTable *variable_idxs;
uint16_t variable_names_idx;

/** \brief Name2idx mapping structure for flowbits, flowvars and pktvars. */
typedef struct VariableName_ {
    char *name;
    uint8_t type; /* flowbit, pktvar, etc */
    uint16_t idx;
    uint8_t flags;
} VariableName;

static uint32_t VariableNameHash(HashListTable *ht, void *buf, uint16_t buflen) {
     VariableName *fn = (VariableName *)buf;
     uint32_t hash = strlen(fn->name) + fn->type;
     uint16_t u;

     for (u = 0; u < buflen; u++) {
         hash += fn->name[u];
     }

     return hash;
}

static char VariableNameCompare(void *buf1, uint16_t len1, void *buf2, uint16_t len2) {
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
    return hash;
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

static void VariableNameFree(void *data) {
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
 *  \param de_ctx Ptr to the detection engine ctx.
 *  \retval -1 in case of error
 *  \retval 0 in case of success
 */
int VariableNameInitHash() {
    variable_names = HashListTableInit(4096, VariableNameHash, VariableNameCompare, VariableNameFree);
    if (variable_names == NULL)
        return -1;

    variable_idxs = HashListTableInit(4096, VariableIdxHash, VariableIdxCompare, NULL);
    if (variable_idxs == NULL)
        return -1;

    variable_names_idx = 0;
    return 0;
}

void VariableNameFreeHash() {
    if (variable_names != NULL) {
        HashListTableFree(variable_names);
        HashListTableFree(variable_idxs);
    }
}

/** \brief Get a name idx for a name. If the name is already used reuse the idx.
 *  \param name nul terminated string with the name
 *  \param type variable type (DETECT_FLOWBITS, DETECT_PKTVAR, etc)
 *  \retval 0 in case of error
 *  \retval _ the idx.
 */
uint16_t VariableNameGetIdx(char *name, uint8_t type) {
    uint16_t idx = 0;
    VariableName *lookup_fn = NULL;

    VariableName *fn = SCMalloc(sizeof(VariableName));
    if (fn == NULL)
        goto error;

    memset(fn, 0, sizeof(VariableName));

    fn->type = type;
    fn->name = SCStrdup(name);
    if (fn->name == NULL)
        goto error;

    lookup_fn = (VariableName *)HashListTableLookup(variable_names, (void *)fn, 0);
    if (lookup_fn == NULL) {
        variable_names_idx++;

        idx = fn->idx = variable_names_idx;
        HashListTableAdd(variable_names, (void *)fn, 0);
        HashListTableAdd(variable_idxs, (void *)fn, 0);
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
 *  \param type variable type (DETECT_FLOWBITS, DETECT_PKTVAR, etc)
 *  \retval NULL in case of error
 *  \retval name of the variable if successful.
 */
char *VariableIdxGetName(uint16_t idx, uint8_t type)
{
    VariableName *lookup_fn = NULL;

    VariableName *fn = SCMalloc(sizeof(VariableName));
    if (fn == NULL)
        goto error;

    char *name = NULL;
    memset(fn, 0, sizeof(VariableName));

    fn->type = type;
    fn->idx = idx;

    lookup_fn = (VariableName *)HashListTableLookup(variable_idxs, (void *)fn, 0);
    if (lookup_fn != NULL) {
        name = SCStrdup(lookup_fn->name);
        if (name == NULL)
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
