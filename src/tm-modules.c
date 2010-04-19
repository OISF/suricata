/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#include "suricata-common.h"
#include "packet-queue.h"
#include "tm-modules.h"
#include "util-debug.h"
#include "threads.h"

void TmModuleDebugList(void) {
    TmModule *t;
    uint16_t i;

    for (i = 0; i < TMM_SIZE; i++) {
        t = &tmm_modules[i];

        if (t->name == NULL)
            continue;

        SCLogDebug("%s:%p", t->name, t->Func);
    }
}

/** \brief get a tm module ptr by name
 *  \param name name string
 *  \retval ptr to the module or NULL */
TmModule *TmModuleGetByName(char *name) {
    TmModule *t;
    uint16_t i;

    for (i = 0; i < TMM_SIZE; i++) {
        t = &tmm_modules[i];

        if (t->name == NULL)
            continue;

        if (strcmp(t->name, name) == 0)
            return t;
    }

    return NULL;
}

/** \brief LogFileNewCtx() Get a new LogFileCtx
 *  \retval LogFileCtx * pointer if succesful, NULL if error
 *  */
LogFileCtx *LogFileNewCtx()
{
    LogFileCtx* lf_ctx;
    lf_ctx=(LogFileCtx*)SCMalloc(sizeof(LogFileCtx));

    if(lf_ctx == NULL)
    {
        SCLogError(SC_ERR_MEM_ALLOC, "Couldn't SCMalloc");
        return NULL;
    }
    memset(lf_ctx, 0, sizeof(LogFileCtx));

    SCMutexInit(&lf_ctx->fp_mutex,NULL);

    return lf_ctx;
}

/** \brief LogFileFreeCtx() Destroy a LogFileCtx (Close the file and free memory)
 *  \param motcx pointer to the OutputCtx
 *  \retval int 1 if succesful, 0 if error
 *  */
int LogFileFreeCtx(LogFileCtx *lf_ctx)
{
    if (lf_ctx == NULL) {
        SCReturnInt(0);
    }

    if (lf_ctx->fp != NULL)
    {
        SCMutexLock(&lf_ctx->fp_mutex);
        fflush(lf_ctx->fp);
        fclose(lf_ctx->fp);
        SCMutexUnlock(&lf_ctx->fp_mutex);
    }

    SCMutexDestroy(&lf_ctx->fp_mutex);

    if (lf_ctx->prefix != NULL)
        SCFree(lf_ctx->prefix);

    if(lf_ctx->filename != NULL)
        SCFree(lf_ctx->filename);

    SCFree(lf_ctx);

    SCReturnInt(1);
}

/** \brief register all unittests for the tm modules */
void TmModuleRegisterTests(void) {
#ifdef UNITTESTS
    TmModule *t;
    uint16_t i;

    for (i = 0; i < TMM_SIZE; i++) {
        t = &tmm_modules[i];

        if (t->name == NULL)
            continue;

        if (t->RegisterTests == NULL) {
            SCLogDebug("threading module %s has no unittest "
                   "registration function.", t->name);
        } else {
            t->RegisterTests();
        }
    }
#endif /* UNITTESTS */
}

