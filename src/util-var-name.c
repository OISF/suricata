#include "suricata-common.h"
#include "detect.h"
#include "util-hashlist.h"

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

static void VariableNameFree(void *data) {
    VariableName *fn = (VariableName *)data;

    if (fn == NULL)
        return;

    if (fn->name != NULL) {
        free(fn->name);
        fn->name = NULL;
    }

    free(fn);
}

/** \brief Initialize the Name idx hash.
 *  \param de_ctx Ptr to the detection engine ctx.
 *  \retval -1 in case of error
 *  \retval 0 in case of success
 */
int VariableNameInitHash(DetectEngineCtx *de_ctx) {
    de_ctx->variable_names = HashListTableInit(4096, VariableNameHash, VariableNameCompare, VariableNameFree);
    if (de_ctx->variable_names == NULL)
        return -1;

    return 0;
}

void VariableNameFreeHash(DetectEngineCtx *de_ctx) {
    HashListTableFree(de_ctx->variable_names);
}

/** \brief Get a name idx for a name. If the name is already used reuse the idx.
 *  \param de_ctx Ptr to the detection engine ctx.
 *  \param name nul terminated string with the name
 *  \param type variable type (DETECT_FLOWBITS, DETECT_PKTVAR, etc)
 *  \retval 0 in case of error
 *  \retval _ the idx.
 */
uint16_t VariableNameGetIdx(DetectEngineCtx *de_ctx, char *name, uint8_t type) {
    uint16_t idx = 0;

    VariableName *fn = malloc(sizeof(VariableName));
    if (fn == NULL)
        goto error;

    memset(fn, 0, sizeof(VariableName));

    fn->type = type;
    fn->name = strdup(name);
    if (fn->name == NULL)
        goto error;

    VariableName *lookup_fn = (VariableName *)HashListTableLookup(de_ctx->variable_names, (void *)fn, 0);
    if (lookup_fn == NULL) {
        de_ctx->variable_names_idx++;

        idx = fn->idx = de_ctx->variable_names_idx;
        HashListTableAdd(de_ctx->variable_names, (void *)fn, 0);
    } else {
        idx = lookup_fn->idx;
        VariableNameFree(fn);
    }

    return idx;
error:
    VariableNameFree(fn);
    return 0;
}

