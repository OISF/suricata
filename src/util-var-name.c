#include "eidps.h"
#include "detect.h"
#include "util-hashlist.h"

typedef struct VariableName_ {
    char *name;
    u_int8_t type; /* flowbit, pktvar, etc */
    u_int16_t idx;
    u_int8_t flags;
} VariableName;

static u_int32_t VariableNameHash(HashListTable *ht, void *buf, u_int16_t buflen) {
     VariableName *fn = (VariableName *)buf;
     u_int32_t hash = strlen(fn->name) + fn->type;
     u_int16_t u;

     for (u = 0; u < buflen; u++) {
         hash += fn->name[u];
     }

     return hash;
}

static char VariableNameCompare(void *buf1, u_int16_t len1, void *buf2, u_int16_t len2) {
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

int VariableNameInitHash(DetectEngineCtx *de_ctx) {
    de_ctx->variable_names = HashListTableInit(4096, VariableNameHash, VariableNameCompare, VariableNameFree);
    if (de_ctx->variable_names == NULL)
        return -1;

    return 0;
}

u_int16_t VariableNameGetIdx(DetectEngineCtx *de_ctx, char *name, u_int8_t cmd, u_int8_t type) {
    u_int16_t idx = 0;

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
    }

    return idx;
error:
    VariableNameFree(fn);
    return 0;
}

