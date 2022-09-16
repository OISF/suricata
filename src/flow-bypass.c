/* Copyright (C) 2016-2018 Open Information Security Foundation
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
 * \author Eric Leblond <eleblond@stamus-networks.com>
 */

#include "suricata-common.h"
#ifdef CAPTURE_OFFLOAD_MANAGER
#include "runmodes.h"
#include "util-ebpf.h"
#include "flow-private.h"
#include "flow.h"
#include "tm-threads.h"
#endif
#include "flow-bypass.h"

#ifdef CAPTURE_OFFLOAD_MANAGER

#define FLOW_BYPASS_DELAY       10

#ifndef TIMEVAL_TO_TIMESPEC
#define TIMEVAL_TO_TIMESPEC(tv, ts) {                               \
    (ts)->tv_sec = (tv)->tv_sec;                                    \
    (ts)->tv_nsec = (tv)->tv_usec * 1000;                           \
}
#endif

typedef struct BypassedFlowManagerThreadData_ {
    uint16_t flow_bypassed_cnt_clo;
    uint16_t flow_bypassed_pkts;
    uint16_t flow_bypassed_bytes;
} BypassedFlowManagerThreadData;

#define BYPASSFUNCMAX   4

typedef struct BypassedCheckFuncItem_ {
    BypassedCheckFunc Func;
    BypassedCheckFuncInit FuncInit;
    void *data;
} BypassedCheckFuncItem;

int g_bypassed_func_max_index = 0;
BypassedCheckFuncItem bypassedfunclist[BYPASSFUNCMAX];

typedef struct BypassedUpdateFuncItem_ {
    BypassedUpdateFunc Func;
    void *data;
} BypassedUpdateFuncItem;

int g_bypassed_update_max_index = 0;
BypassedUpdateFuncItem updatefunclist[BYPASSFUNCMAX];

static TmEcode BypassedFlowManager(ThreadVars *th_v, void *thread_data)
{
    int tcount = 0;
    int i;
    BypassedFlowManagerThreadData *ftd = thread_data;
    struct timespec curtime = {0, 0};

    struct timeval tv;
    gettimeofday(&tv, NULL);
    TIMEVAL_TO_TIMESPEC(&tv, &curtime);

    for (i = 0; i < g_bypassed_func_max_index; i++) {
        if (bypassedfunclist[i].FuncInit) {
            bypassedfunclist[i].FuncInit(th_v, &curtime, bypassedfunclist[i].data);
        }
    }

    /* check if we have a periodic check function */
    bool found = false;
    for (i = 0; i < g_bypassed_func_max_index; i++) {
        if (bypassedfunclist[i].FuncInit) {
            found = true;
            break;
        }
    }
    if (!found)
        return TM_ECODE_OK;

    while (1) {
        SCLogDebug("Dumping the table");
        gettimeofday(&tv, NULL);
        TIMEVAL_TO_TIMESPEC(&tv, &curtime);

        for (i = 0; i < g_bypassed_func_max_index; i++) {
            struct flows_stats bypassstats = { 0, 0, 0};
            if (bypassedfunclist[i].Func == NULL)
                continue;
            tcount = bypassedfunclist[i].Func(th_v, &bypassstats, &curtime, bypassedfunclist[i].data);
            if (tcount) {
                StatsAddUI64(th_v, ftd->flow_bypassed_cnt_clo, (uint64_t)bypassstats.count);
            }
            StatsAddUI64(th_v, ftd->flow_bypassed_pkts, (uint64_t)bypassstats.packets);
            StatsAddUI64(th_v, ftd->flow_bypassed_bytes, (uint64_t)bypassstats.bytes);
        }

        if (TmThreadsCheckFlag(th_v, THV_KILL)) {
            StatsSyncCounters(th_v);
            return TM_ECODE_OK;
        }
        for (i = 0; i < FLOW_BYPASS_DELAY * 100; i++) {
            if (TmThreadsCheckFlag(th_v, THV_KILL)) {
                StatsSyncCounters(th_v);
                return TM_ECODE_OK;
            }
            StatsSyncCountersIfSignalled(th_v);
            usleep(10000);
        }
    }
    return TM_ECODE_OK;
}

static TmEcode BypassedFlowManagerThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    BypassedFlowManagerThreadData *ftd = SCCalloc(1, sizeof(BypassedFlowManagerThreadData));
    if (ftd == NULL)
        return TM_ECODE_FAILED;

    *data = ftd;

    ftd->flow_bypassed_cnt_clo = StatsRegisterCounter("flow_bypassed.closed", t);
    ftd->flow_bypassed_pkts = StatsRegisterCounter("flow_bypassed.pkts", t);
    ftd->flow_bypassed_bytes = StatsRegisterCounter("flow_bypassed.bytes", t);

    return TM_ECODE_OK;
}

static TmEcode BypassedFlowManagerThreadDeinit(ThreadVars *t, void *data)
{
    if (data)
        SCFree(data);
    return TM_ECODE_OK;
}

int BypassedFlowManagerRegisterCheckFunc(BypassedCheckFunc CheckFunc,
                                         BypassedCheckFuncInit CheckFuncInit,
                                         void *data)
{
    if (g_bypassed_func_max_index < BYPASSFUNCMAX) {
        bypassedfunclist[g_bypassed_func_max_index].Func = CheckFunc;
        bypassedfunclist[g_bypassed_func_max_index].FuncInit = CheckFuncInit;
        bypassedfunclist[g_bypassed_func_max_index].data = data;
        g_bypassed_func_max_index++;
    } else {
        return -1;
    }
    return 0;
}

int BypassedFlowManagerRegisterUpdateFunc(BypassedUpdateFunc UpdateFunc,
                                          void *data)
{
    if (!UpdateFunc) {
        return -1;
    }
    if (g_bypassed_update_max_index < BYPASSFUNCMAX) {
        updatefunclist[g_bypassed_update_max_index].Func = UpdateFunc;
        updatefunclist[g_bypassed_update_max_index].data = data;
        g_bypassed_update_max_index++;
    } else {
        return -1;
    }
    return 0;
}
#endif

/** \brief spawn the flow bypass manager thread */
void BypassedFlowManagerThreadSpawn()
{
#ifdef CAPTURE_OFFLOAD_MANAGER

    ThreadVars *tv_flowmgr = NULL;
    tv_flowmgr = TmThreadCreateMgmtThreadByName(thread_name_flow_bypass,
            "BypassedFlowManager", 0);
    BUG_ON(tv_flowmgr == NULL);

    if (tv_flowmgr == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(1);
    }
    if (TmThreadSpawn(tv_flowmgr) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(1);
    }
#endif
}

void BypassedFlowUpdate(Flow *f, Packet *p)
{
#ifdef CAPTURE_OFFLOAD_MANAGER
    for (int i = 0; i < g_bypassed_update_max_index; i++) {
        if (updatefunclist[i].Func(f, p, updatefunclist[i].data)) {
            return;
        }
    }
#endif
}

void TmModuleBypassedFlowManagerRegister (void)
{
#ifdef CAPTURE_OFFLOAD_MANAGER
    tmm_modules[TMM_BYPASSEDFLOWMANAGER].name = "BypassedFlowManager";
    tmm_modules[TMM_BYPASSEDFLOWMANAGER].ThreadInit = BypassedFlowManagerThreadInit;
    tmm_modules[TMM_BYPASSEDFLOWMANAGER].ThreadDeinit = BypassedFlowManagerThreadDeinit;
    tmm_modules[TMM_BYPASSEDFLOWMANAGER].Management = BypassedFlowManager;
    tmm_modules[TMM_BYPASSEDFLOWMANAGER].cap_flags = 0;
    tmm_modules[TMM_BYPASSEDFLOWMANAGER].flags = TM_FLAG_MANAGEMENT_TM;
    SCLogDebug("%s registered", tmm_modules[TMM_BYPASSEDFLOWMANAGER].name);
#endif
}

