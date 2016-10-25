/* Copyright (C) 2015 Open Information Security Foundation
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
 */

#include "suricata-common.h"
#include "suricata.h"
#include "conf.h"
#include "debug.h"
#include "detect.h"
#include "runmodes.h"
#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"
#include "queue.h"
#include "util-signal.h"

#include "detect-engine-loader.h"

#define NLOADERS 4
static DetectLoaderControl *loaders = NULL;
static int cur_loader = 0;
void TmThreadWakeupDetectLoaderThreads(void);
static int num_loaders = NLOADERS;

/** \param loader -1 for auto select
 *  \retval loader_id or negative in case of error */
int DetectLoaderQueueTask(int loader_id, LoaderFunc Func, void *func_ctx)
{
    if (loader_id == -1) {
        loader_id = cur_loader;
        cur_loader++;
        if (cur_loader >= num_loaders)
            cur_loader = 0;
    }
    if (loader_id >= num_loaders || loader_id < 0) {
        return -ERANGE;
    }

    DetectLoaderControl *loader = &loaders[loader_id];

    DetectLoaderTask *t = SCCalloc(1, sizeof(*t));
    if (t == NULL)
        return -ENOMEM;

    t->Func = Func;
    t->ctx = func_ctx;

    SCMutexLock(&loader->m);
    TAILQ_INSERT_TAIL(&loader->task_list, t, next);
    SCMutexUnlock(&loader->m);

    TmThreadWakeupDetectLoaderThreads();

    SCLogDebug("%d %p %p", loader_id, Func, func_ctx);
    return loader_id;
}

/** \brief wait for loader tasks to complete
 *  \retval result 0 for ok, -1 for errors */
int DetectLoadersSync(void)
{
    SCLogDebug("waiting");
    int errors = 0;
    int i;
    for (i = 0; i < num_loaders; i++) {
        int done = 0;
        DetectLoaderControl *loader = &loaders[i];
        while (!done) {
            SCMutexLock(&loader->m);
            if (TAILQ_EMPTY(&loader->task_list)) {
                done = 1;
            }
            SCMutexUnlock(&loader->m);
        }
        SCMutexLock(&loader->m);
        if (loader->result != 0) {
            errors++;
            loader->result = 0;
        }
        SCMutexUnlock(&loader->m);

    }
    if (errors) {
        SCLogError(SC_ERR_INITIALIZATION, "%d loaders reported errors", errors);
        return -1;
    }
    SCLogDebug("done");
    return 0;
}

static void DetectLoaderInit(DetectLoaderControl *loader)
{
    memset(loader, 0x00, sizeof(*loader));
    SCMutexInit(&loader->m, NULL);
    TAILQ_INIT(&loader->task_list);
}

void DetectLoadersInit(void)
{
    intmax_t setting = NLOADERS;
    (void)ConfGetInt("multi-detect.loaders", &setting);

    if (setting < 1 || setting > 1024) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS,
                "invalid multi-detect.loaders setting %"PRIdMAX, setting);
        exit(EXIT_FAILURE);
    }
    num_loaders = (int32_t)setting;

    SCLogInfo("using %d detect loader threads", num_loaders);

    BUG_ON(loaders != NULL);
    loaders = SCCalloc(num_loaders, sizeof(DetectLoaderControl));
    BUG_ON(loaders == NULL);

    int i;
    for (i = 0; i < num_loaders; i++) {
        DetectLoaderInit(&loaders[i]);
    }
}

/**
 * \brief Unpauses all threads present in tv_root
 */
void TmThreadWakeupDetectLoaderThreads()
{
    ThreadVars *tv = NULL;
    int i = 0;

    SCMutexLock(&tv_root_lock);
    for (i = 0; i < TVT_MAX; i++) {
        tv = tv_root[i];
        while (tv != NULL) {
            if (strncmp(tv->name,"DL#",3) == 0) {
                BUG_ON(tv->ctrl_cond == NULL);
                pthread_cond_broadcast(tv->ctrl_cond);
            }
            tv = tv->next;
        }
    }
    SCMutexUnlock(&tv_root_lock);

    return;
}

/**
 * \brief Unpauses all threads present in tv_root
 */
void TmThreadContinueDetectLoaderThreads()
{
    ThreadVars *tv = NULL;
    int i = 0;

    SCMutexLock(&tv_root_lock);
    for (i = 0; i < TVT_MAX; i++) {
        tv = tv_root[i];
        while (tv != NULL) {
            if (strncmp(tv->name,"DL#",3) == 0)
                TmThreadContinue(tv);

            tv = tv->next;
        }
    }
    SCMutexUnlock(&tv_root_lock);

    return;
}


SC_ATOMIC_DECLARE(int, detect_loader_cnt);

typedef struct DetectLoaderThreadData_ {
    uint32_t instance;
} DetectLoaderThreadData;

static TmEcode DetectLoaderThreadInit(ThreadVars *t, void *initdata, void **data)
{
    DetectLoaderThreadData *ftd = SCCalloc(1, sizeof(DetectLoaderThreadData));
    if (ftd == NULL)
        return TM_ECODE_FAILED;

    ftd->instance = SC_ATOMIC_ADD(detect_loader_cnt, 1) - 1; /* id's start at 0 */
    SCLogDebug("detect loader instance %u", ftd->instance);

    /* pass thread data back to caller */
    *data = ftd;

    return TM_ECODE_OK;
}

static TmEcode DetectLoaderThreadDeinit(ThreadVars *t, void *data)
{
    SCFree(data);
    return TM_ECODE_OK;
}


static TmEcode DetectLoader(ThreadVars *th_v, void *thread_data)
{
    /* block usr2. usr2 to be handled by the main thread only */
    UtilSignalBlock(SIGUSR2);

    DetectLoaderThreadData *ftd = (DetectLoaderThreadData *)thread_data;
    BUG_ON(ftd == NULL);

    SCLogDebug("loader thread started");
    while (1)
    {
        if (TmThreadsCheckFlag(th_v, THV_PAUSE)) {
            TmThreadsSetFlag(th_v, THV_PAUSED);
            TmThreadTestThreadUnPaused(th_v);
            TmThreadsUnsetFlag(th_v, THV_PAUSED);
        }

        /* see if we have tasks */

        DetectLoaderControl *loader = &loaders[ftd->instance];
        SCMutexLock(&loader->m);

        DetectLoaderTask *task = NULL, *tmptask = NULL;
        TAILQ_FOREACH_SAFE(task, &loader->task_list, next, tmptask) {
            int r = task->Func(task->ctx, ftd->instance);
            loader->result |= r;
            TAILQ_REMOVE(&loader->task_list, task, next);
            SCFree(task->ctx);
            SCFree(task);
        }

        SCMutexUnlock(&loader->m);

        if (TmThreadsCheckFlag(th_v, THV_KILL)) {
            break;
        }

        /* just wait until someone wakes us up */
        SCCtrlMutexLock(th_v->ctrl_mutex);
        SCCtrlCondWait(th_v->ctrl_cond, th_v->ctrl_mutex);
        SCCtrlMutexUnlock(th_v->ctrl_mutex);

        SCLogDebug("woke up...");
    }

    return TM_ECODE_OK;
}

/** \brief spawn the detect loader manager thread */
void DetectLoaderThreadSpawn()
{
    int i;
    for (i = 0; i < num_loaders; i++) {
        ThreadVars *tv_loader = NULL;

        char name[TM_THREAD_NAME_MAX];
        snprintf(name, sizeof(name), "%s#%02d", thread_name_detect_loader, i+1);

        tv_loader = TmThreadCreateCmdThreadByName(name,
                "DetectLoader", 1);
        BUG_ON(tv_loader == NULL);

        if (tv_loader == NULL) {
            printf("ERROR: TmThreadsCreate failed\n");
            exit(1);
        }
        if (TmThreadSpawn(tv_loader) != TM_ECODE_OK) {
            printf("ERROR: TmThreadSpawn failed\n");
            exit(1);
        }
    }
    return;
}

void TmModuleDetectLoaderRegister (void)
{
    tmm_modules[TMM_DETECTLOADER].name = "DetectLoader";
    tmm_modules[TMM_DETECTLOADER].ThreadInit = DetectLoaderThreadInit;
    tmm_modules[TMM_DETECTLOADER].ThreadDeinit = DetectLoaderThreadDeinit;
    tmm_modules[TMM_DETECTLOADER].Management = DetectLoader;
    tmm_modules[TMM_DETECTLOADER].cap_flags = 0;
    tmm_modules[TMM_DETECTLOADER].flags = TM_FLAG_MANAGEMENT_TM;
    SCLogDebug("%s registered", tmm_modules[TMM_DETECTLOADER].name);

    SC_ATOMIC_INIT(detect_loader_cnt);
}
