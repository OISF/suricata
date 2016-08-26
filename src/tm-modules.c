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
#include "util-logopenfile.h"

void TmModuleDebugList(void)
{
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
TmModule *TmModuleGetByName(const char *name)
{
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

/** \brief get the id of a module from it's name
 *  \param name registered name of the module
 *  \retval id the id or -1 in case of error */
int TmModuleGetIdByName(const char *name)
{
    TmModule *tm = TmModuleGetByName(name);
    if (tm == NULL)
        return -1;;
    return TmModuleGetIDForTM(tm);
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

        if (t->name == NULL)
            continue;

        if (strcmp(t->name, tm->name) == 0)
            return i;
    }

    return -1;
}


void TmModuleRunInit(void)
{
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

void TmModuleRunDeInit(void)
{
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
void TmModuleRegisterTests(void)
{
#ifdef UNITTESTS
    TmModule *t;
    uint16_t i;

    for (i = 0; i < TMM_SIZE; i++) {
        t = &tmm_modules[i];

        if (t->name == NULL)
            continue;

        g_ut_modules++;


        if (t->RegisterTests == NULL) {
            if (coverage_unittests)
                SCLogWarning(SC_WARN_NO_UNITTESTS, "threading module %s has no unittest "
                        "registration function.", t->name);
        } else {
            t->RegisterTests();
            g_ut_covered++;
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
        CASE_CODE (TMM_FLOWWORKER);
        CASE_CODE (TMM_RECEIVENFLOG);
        CASE_CODE (TMM_DECODENFLOG);
        CASE_CODE (TMM_DECODENFQ);
        CASE_CODE (TMM_VERDICTNFQ);
        CASE_CODE (TMM_RECEIVENFQ);
        CASE_CODE (TMM_RECEIVEPCAP);
        CASE_CODE (TMM_RECEIVEPCAPFILE);
        CASE_CODE (TMM_DECODEPCAP);
        CASE_CODE (TMM_DECODEPCAPFILE);
        CASE_CODE (TMM_RECEIVEPFRING);
        CASE_CODE (TMM_DECODEPFRING);
        CASE_CODE (TMM_RESPONDREJECT);
        CASE_CODE (TMM_DECODEIPFW);
        CASE_CODE (TMM_VERDICTIPFW);
        CASE_CODE (TMM_RECEIVEIPFW);
        CASE_CODE (TMM_RECEIVEERFFILE);
        CASE_CODE (TMM_DECODEERFFILE);
        CASE_CODE (TMM_RECEIVEERFDAG);
        CASE_CODE (TMM_DECODEERFDAG);
        CASE_CODE (TMM_RECEIVEMPIPE);
        CASE_CODE (TMM_DECODEMPIPE);
        CASE_CODE (TMM_RECEIVENAPATECH);
        CASE_CODE (TMM_DECODENAPATECH);
        CASE_CODE (TMM_RECEIVEAFP);
        CASE_CODE (TMM_ALERTPCAPINFO);
        CASE_CODE (TMM_DECODEAFP);
        CASE_CODE (TMM_STATSLOGGER);
        CASE_CODE (TMM_FLOWMANAGER);
        CASE_CODE (TMM_FLOWRECYCLER);
        CASE_CODE (TMM_UNIXMANAGER);
        CASE_CODE (TMM_DETECTLOADER);
        CASE_CODE (TMM_RECEIVENETMAP);
        CASE_CODE (TMM_DECODENETMAP);

        CASE_CODE (TMM_SIZE);
    }
    return "<unknown>";
}
