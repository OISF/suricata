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

        SCLogDebug("%s:%p\n", t->name, t->Func);
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
    lf_ctx=(LogFileCtx*)malloc(sizeof(LogFileCtx));

    if(lf_ctx == NULL)
    {
        printf("LogFileCtxNew: Couldn't malloc \n");
        return NULL;
    }
    memset(lf_ctx, 0, sizeof(LogFileCtx));
    /** Ensure that it is unlocked */
    SCMutexInit(&lf_ctx->fp_mutex,NULL);
    SCMutexUnlock(&lf_ctx->fp_mutex);

    return lf_ctx;
}

/** \brief LogFileFreeCtx() Destroy a LogFileCtx (Close the file and free memory)
 *  \param motcx pointer to the OutputCtx
 *  \retval int 1 if succesful, 0 if error
 *  */
int LogFileFreeCtx(LogFileCtx *lf_ctx)
{
    int ret=0;

    if(lf_ctx != NULL)
    {
        if (lf_ctx->fp != NULL)
        {
            SCMutexLock(&lf_ctx->fp_mutex);
            fclose(lf_ctx->fp);
            SCMutexUnlock(&lf_ctx->fp_mutex);
        }
        if (lf_ctx->config_file != NULL);
            free(lf_ctx->config_file);
        free(lf_ctx);
        ret=1;
    }

    return ret;
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

