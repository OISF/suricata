/* Copyright (C) 2015-2022 Open Information Security Foundation
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
 * Detect loader API, for using multiple 'loader' threads
 * that can load multiple detection engines in parallel.
 */

#ifndef __DETECT_ENGINE_LOADER_H__
#define __DETECT_ENGINE_LOADER_H__

/**
 * \param ctx function specific data
 * \param loader_id id of the loader that executed the task
 */
typedef int (*LoaderFunc)(void *ctx, int loader_id);

typedef struct DetectLoaderTask_ {
    LoaderFunc Func;
    void *ctx;
    TAILQ_ENTRY(DetectLoaderTask_) next;
} DetectLoaderTask;

typedef struct DetectLoaderControl_ {
    int id;
    int result;     /* 0 for ok, error otherwise */
    SCMutex m;
    TAILQ_HEAD(, DetectLoaderTask_) task_list;
} DetectLoaderControl;

int DetectLoaderQueueTask(int loader_id, LoaderFunc Func, void *func_ctx);
int DetectLoadersSync(void);
void DetectLoadersInit(void);

void TmThreadContinueDetectLoaderThreads(void);
void DetectLoaderThreadSpawn(void);
void TmModuleDetectLoaderRegister (void);

#endif /* __DETECT_ENGINE_LOADER_H__ */
