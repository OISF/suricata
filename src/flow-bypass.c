/* Copyright (C) 2016 Open Information Security Foundation
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
#include "flow-private.h"
#include "util-ebpf.h"

#define BYPASSED_FLOW_TIMEOUT 60

typedef struct BypassedFlowManagerThreadData_ {
    uint16_t flow_bypassed_cnt_clo;
} BypassedFlowManagerThreadData;

static int BypassedFlowV4Timeout(int fd, struct flowv4_keys *key, struct pair *value, void *data)
{
    struct timespec *curtime = (struct timespec *)data;
    SCLogDebug("Got curtime %" PRIu64 " and value %" PRIu64 " (sp:%d, dp:%d)",
               curtime->tv_sec, value->time / 1000000000,
               key->port16[0], key->port16[1]
              );

    if (curtime->tv_sec - value->time / 1000000000 > BYPASSED_FLOW_TIMEOUT) {
        SCLogDebug("Got no packet for %d -> %d at %" PRIu64,
                   key->port16[0], key->port16[1], value->time);
        EBPFDeleteKey(fd, key);
        return 1;
    }
    return 0;
}

static TmEcode BypassedFlowManager(ThreadVars *th_v, void *thread_data)
{
    int tcount = 0;
    BypassedFlowManagerThreadData *ftd = thread_data;

    while (1) {
        SCLogDebug("Dumping the table");
        struct timespec curtime;
        if (clock_gettime(CLOCK_MONOTONIC, &curtime) != 0) {
            SCLogError(SC_ERR_INVALID_VALUE, "Can't get time");
            sleep(1);
            continue;
        }
        /* TODO indirection here: AF_PACKET and NFQ should be able to give their iterate function */
        tcount = EBPFForEachFlowV4Table("flow_table_v4", BypassedFlowV4Timeout, &curtime);
        StatsAddUI64(th_v, ftd->flow_bypassed_cnt_clo, (uint64_t)tcount);

        if (TmThreadsCheckFlag(th_v, THV_KILL)) {
            StatsSyncCounters(th_v);
            return TM_ECODE_OK;
        }
        sleep(5);
        StatsSyncCountersIfSignalled(th_v);
    }
}


static TmEcode BypassedFlowManagerThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    BypassedFlowManagerThreadData *ftd = SCCalloc(1, sizeof(BypassedFlowManagerThreadData));
    if (ftd == NULL)
        return TM_ECODE_FAILED;

    *data = ftd;

    ftd->flow_bypassed_cnt_clo = StatsRegisterCounter("flow_bypassed.closed", t);

    return TM_ECODE_OK;
}

static TmEcode BypassedFlowManagerThreadDeinit(ThreadVars *t, void *data)
{
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

