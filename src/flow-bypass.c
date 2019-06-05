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
#include "tm-threads.h"
#include "flow.h"
#include "flow-bypass.h"
#include "flow-private.h"
#include "util-ebpf.h"

#define FLOW_BYPASS_DELAY       10

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
#ifdef HAVE_PACKET_EBPF
    int tcount = 0;
    int i;
    BypassedFlowManagerThreadData *ftd = thread_data;
    struct timespec curtime = {0, 0};

    if (clock_gettime(CLOCK_REALTIME, &curtime) != 0) {
        SCLogError(SC_ERR_INVALID_VALUE, "Can't get time: %s (%d)",
                strerror(errno), errno);
        return TM_ECODE_FAILED;
    }
    for (i = 0; i < g_bypassed_func_max_index; i++) {
        if (bypassedfunclist[i].FuncInit) {
            bypassedfunclist[i].FuncInit(th_v, &curtime, bypassedfunclist[i].data);
        }
    }

    while (1) {
        SCLogDebug("Dumping the table");
        if (clock_gettime(CLOCK_REALTIME, &curtime) != 0) {
            usleep(10000);
            continue;
        }
        for (i = 0; i < g_bypassed_func_max_index; i++) {
            struct flows_stats bypassstats = { 0, 0, 0};
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
#endif
    return TM_ECODE_OK;
}

void BypassedFlowUpdate(Flow *f, Packet *p)
{
    int i;

    for (i = 0; i < g_bypassed_update_max_index; i++) {
        if (updatefunclist[i].Func(f, p, updatefunclist[i].data)) {
            return;
        }
    }
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

/** \brief spawn the flow manager thread */
void BypassedFlowManagerThreadSpawn()
{
#ifdef AFLFUZZ_DISABLE_MGTTHREADS
    return;
#endif

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
}

int BypassedFlowManagerRegisterCheckFunc(BypassedCheckFunc CheckFunc,
                                         BypassedCheckFuncInit CheckFuncInit,
                                         void *data)
{
    if (!CheckFunc) {
        return -1;
    }
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

void TmModuleBypassedFlowManagerRegister (void)
{
    tmm_modules[TMM_BYPASSEDFLOWMANAGER].name = "BypassedFlowManager";
    tmm_modules[TMM_BYPASSEDFLOWMANAGER].ThreadInit = BypassedFlowManagerThreadInit;
    tmm_modules[TMM_BYPASSEDFLOWMANAGER].ThreadDeinit = BypassedFlowManagerThreadDeinit;
    tmm_modules[TMM_BYPASSEDFLOWMANAGER].Management = BypassedFlowManager;
    tmm_modules[TMM_BYPASSEDFLOWMANAGER].cap_flags = 0;
    tmm_modules[TMM_BYPASSEDFLOWMANAGER].flags = TM_FLAG_MANAGEMENT_TM;
    SCLogDebug("%s registered", tmm_modules[TMM_BYPASSEDFLOWMANAGER].name);
}

