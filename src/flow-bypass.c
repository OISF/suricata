/* Copyright (C) 2016-2017 Open Information Security Foundation
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
int g_bypassed_func_max_index = 0;
BypassedCheckFunc BypassedFuncList[BYPASSFUNCMAX];

static TmEcode BypassedFlowManager(ThreadVars *th_v, void *thread_data)
{
#ifdef HAVE_PACKET_EBPF
    int tcount = 0;
    BypassedFlowManagerThreadData *ftd = thread_data;

    while (1) {
        int i;
        SCLogDebug("Dumping the table");
        struct timespec curtime;
        if (clock_gettime(CLOCK_MONOTONIC, &curtime) != 0) {
            SCLogWarning(SC_ERR_INVALID_VALUE, "Can't get time: %s (%d)",
                         strerror(errno), errno);
            sleep(1);
            continue;
        }
        for (i = 0; i < g_bypassed_func_max_index; i++) {
            struct flows_stats bypassstats = { 0, 0, 0};
            tcount = BypassedFuncList[i](&bypassstats, &curtime);
            if (tcount) {
                StatsAddUI64(th_v, ftd->flow_bypassed_cnt_clo, (uint64_t)bypassstats.count);
                StatsAddUI64(th_v, ftd->flow_bypassed_pkts, (uint64_t)bypassstats.packets);
                StatsAddUI64(th_v, ftd->flow_bypassed_bytes, (uint64_t)bypassstats.bytes);
            }
        }

        if (TmThreadsCheckFlag(th_v, THV_KILL)) {
            StatsSyncCounters(th_v);
            return TM_ECODE_OK;
        }
        sleep(FLOW_BYPASS_DELAY);
        StatsSyncCountersIfSignalled(th_v);
    }
#endif
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

/** \brief spawn the flow manager thread */
void BypassedFlowManagerThreadSpawn()
{
#ifdef AFLFUZZ_DISABLE_MGTTHREADS
    return;
#endif

    ThreadVars *tv_flowmgr = NULL;
    tv_flowmgr = TmThreadCreateMgmtThreadByName("BypassedFlowManager",
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

int BypassedFlowManagerRegisterCheckFunc(BypassedCheckFunc CheckFunc)
{
    if (!CheckFunc) {
        return -1;
    }
    if (g_bypassed_func_max_index < BYPASSFUNCMAX) {
        BypassedFuncList[g_bypassed_func_max_index] = CheckFunc;
        g_bypassed_func_max_index++;
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

