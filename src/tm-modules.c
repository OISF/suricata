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
 * Thread Module functions
 */

#include "suricata-common.h"
#include "packet-queue.h"
#include "tm-threads.h"
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

/**
 * \brief Returns a TM Module by its id.
 *
 * \param id Id of the TM Module to return.
 *
 * \retval Pointer of the module to be returned if available;
 *         NULL if unavailable.
 */
TmModule *TmModuleGetById(int id)
{

    if (id < 0 || id >= TMM_SIZE) {
        SCLogError(SC_ERR_TM_MODULES_ERROR, "Threading module with the id "
                   "\"%d\" doesn't exist", id);
        return NULL;
    }

    return &tmm_modules[id];
}

/**
 * \brief Given a TM Module, returns its id.
 *
 * \param tm Pointer to the TM Module.
 *
 * \retval id of the TM Module if available; -1 if unavailable.
 */
int TmModuleGetIDForTM(TmModule *tm)
{
    TmModule *t;
    int i;

    for (i = 0; i < TMM_SIZE; i++) {
        t = &tmm_modules[i];

        if (strcmp(t->name, tm->name) == 0)
            return i;
    }

    return -1;
}

/** \brief LogFileNewCtx() Get a new LogFileCtx
 *  \retval LogFileCtx * pointer if succesful, NULL if error
 *  */
LogFileCtx *LogFileNewCtx()
{
    LogFileCtx* lf_ctx;
    lf_ctx=(LogFileCtx*)SCMalloc(sizeof(LogFileCtx));

    if(lf_ctx == NULL)
        return NULL;
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

void TmModuleRunInit(void) {
    TmModule *t;
    uint16_t i;

    for (i = 0; i < TMM_SIZE; i++) {
        t = &tmm_modules[i];

        if (t->name == NULL)
            continue;

        if (t->Init == NULL)
            continue;

        t->Init();
    }
}

void TmModuleRunDeInit(void) {
    TmModule *t;
    uint16_t i;

    for (i = 0; i < TMM_SIZE; i++) {
        t = &tmm_modules[i];

        if (t->name == NULL)
            continue;

        if (t->DeInit == NULL)
            continue;

        t->DeInit();
    }
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

#define CASE_CODE(E)  case E: return #E

/**
 * \brief Maps the TmmId, to its string equivalent
 *
 * \param id tmm id
 *
 * \retval string equivalent for the tmm id
 */
const char * TmModuleTmmIdToString(TmmId id)
{
    switch (id) {
        CASE_CODE (TMM_DECODENFQ);
        CASE_CODE (TMM_VERDICTNFQ);
        CASE_CODE (TMM_RECEIVENFQ);
        CASE_CODE (TMM_RECEIVEPCAP);
        CASE_CODE (TMM_RECEIVEPCAPFILE);
        CASE_CODE (TMM_DECODEPCAP);
        CASE_CODE (TMM_DECODEPCAPFILE);
        CASE_CODE (TMM_RECEIVEPFRING);
        CASE_CODE (TMM_DECODEPFRING);
        CASE_CODE (TMM_DETECT);
        CASE_CODE (TMM_ALERTFASTLOG);
        CASE_CODE (TMM_ALERTFASTLOG4);
        CASE_CODE (TMM_ALERTFASTLOG6);
        CASE_CODE (TMM_ALERTUNIFIED2ALERT);
        CASE_CODE (TMM_ALERTPRELUDE);
        CASE_CODE (TMM_ALERTDEBUGLOG);
        CASE_CODE (TMM_ALERTSYSLOG);
        CASE_CODE (TMM_LOGDROPLOG);
        CASE_CODE (TMM_ALERTSYSLOG4);
        CASE_CODE (TMM_ALERTSYSLOG6);
        CASE_CODE (TMM_RESPONDREJECT);
        CASE_CODE (TMM_LOGHTTPLOG);
        CASE_CODE (TMM_LOGHTTPLOG4);
        CASE_CODE (TMM_LOGHTTPLOG6);
        CASE_CODE (TMM_LOGTLSLOG);
        CASE_CODE (TMM_LOGTLSLOG4);
        CASE_CODE (TMM_LOGTLSLOG6);
        CASE_CODE (TMM_PCAPLOG);
        CASE_CODE (TMM_FILELOG);
        CASE_CODE (TMM_FILESTORE);
        CASE_CODE (TMM_STREAMTCP);
        CASE_CODE (TMM_DECODEIPFW);
        CASE_CODE (TMM_VERDICTIPFW);
        CASE_CODE (TMM_RECEIVEIPFW);
#ifdef __SC_CUDA_SUPPORT__
        CASE_CODE (TMM_CUDA_MPM_B2G);
        CASE_CODE (TMM_CUDA_PACKET_BATCHER);
#endif
        CASE_CODE (TMM_RECEIVEERFFILE);
        CASE_CODE (TMM_DECODEERFFILE);
        CASE_CODE (TMM_RECEIVEERFDAG);
        CASE_CODE (TMM_DECODEERFDAG);
        CASE_CODE (TMM_RECEIVENAPATECH);
        CASE_CODE (TMM_DECODENAPATECH);
        CASE_CODE (TMM_RECEIVEAFP);
        CASE_CODE (TMM_ALERTPCAPINFO);
        CASE_CODE (TMM_DECODEAFP);

        default:
            return "UNKNOWN";
    }
}
