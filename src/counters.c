/* Copyright (C) 2007-2013 Open Information Security Foundation
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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 * \author Victor Julien <victor@inliniac.net>
 *
 * Performance counters
 */

#include "suricata-common.h"
#include "suricata.h"
#include "counters.h"
#include "threadvars.h"
#include "tm-threads.h"
#include "conf.h"
#include "util-time.h"
#include "util-unittest.h"
#include "util-debug.h"
#include "util-privs.h"
#include "util-signal.h"
#include "unix-manager.h"
#include "output.h"

/** \todo Get the default log directory from some global resource. */
#define SC_PERF_DEFAULT_LOG_FILENAME "stats.log"

/* Used to parse the interval for Timebased counters */
#define SC_PERF_PCRE_TIMEBASED_INTERVAL "^(?:(\\d+)([shm]))(?:(\\d+)([shm]))?(?:(\\d+)([shm]))?$"

/* Time interval for syncing the local counters with the global ones */
#define SC_PERF_WUT_TTS 3

/* Time interval at which the mgmt thread o/p the stats */
#define SC_PERF_MGMTT_TTS 8

static void *stats_thread_data = NULL;
static SCPerfOPIfaceContext *sc_perf_op_ctx = NULL;
static time_t sc_start_time;
/** refresh interval in seconds */
static uint32_t sc_counter_tts = SC_PERF_MGMTT_TTS;
/** is the stats counter enabled? */
static char sc_counter_enabled = TRUE;

static int SCPerfOutputCounterFileIface(ThreadVars *tv);

/** stats table is filled each interval and passed to the
 *  loggers. Initialized at first use. */
static StatsTable stats_table = { NULL, 0, 0, {0 , 0}};

/**
 * \brief The output interface dispatcher for the counter api
 */
void SCPerfOutputCounters(ThreadVars *tv)
{
    SCPerfOutputCounterFileIface(tv);
}

/**
 * \brief Adds a value of type uint64_t to the local counter.
 *
 * \param id  ID of the counter as set by the API
 * \param pca Counter array that holds the local counter for this TM
 * \param x   Value to add to this local counter
 */
void SCPerfCounterAddUI64(uint16_t id, SCPerfCounterArray *pca, uint64_t x)
{
    if (!pca) {
        SCLogDebug("counterarray is NULL");
        return;
    }
#ifdef DEBUG
    BUG_ON ((id < 1) || (id > pca->size));
#endif
    pca->head[id].ui64_cnt += x;
    pca->head[id].syncs++;
    return;
}

/**
 * \brief Increments the local counter
 *
 * \param id  Index of the counter in the counter array
 * \param pca Counter array that holds the local counters for this TM
 */
void SCPerfCounterIncr(uint16_t id, SCPerfCounterArray *pca)
{
    if (pca == NULL) {
        SCLogDebug("counterarray is NULL");
        return;
    }

#ifdef DEBUG
    BUG_ON ((id < 1) || (id > pca->size));
#endif

    pca->head[id].ui64_cnt++;
    pca->head[id].syncs++;
    return;
}

/**
 * \brief Sets a value of type double to the local counter
 *
 * \param id  Index of the local counter in the counter array
 * \param pca Pointer to the SCPerfCounterArray
 * \param x   The value to set for the counter
 */
void SCPerfCounterSetUI64(uint16_t id, SCPerfCounterArray *pca,
                                 uint64_t x)
{
    if (!pca) {
        SCLogDebug("counterarray is NULL");
        return;
    }

#ifdef DEBUG
    BUG_ON ((id < 1) || (id > pca->size));
#endif

    if ((pca->head[id].pc->type == SC_PERF_TYPE_Q_MAXIMUM) &&
            (x > pca->head[id].ui64_cnt)) {
        pca->head[id].ui64_cnt = x;
    } else if (pca->head[id].pc->type == SC_PERF_TYPE_Q_NORMAL) {
        pca->head[id].ui64_cnt = x;
    }

    pca->head[id].syncs++;

    return;
}

static ConfNode *GetConfig(void) {
    ConfNode *stats = ConfGetNode("stats");
    if (stats != NULL)
        return stats;

    ConfNode *root = ConfGetNode("outputs");
    ConfNode *node = NULL;
    if (root != NULL) {
        TAILQ_FOREACH(node, &root->head, next) {
            if (strcmp(node->val, "stats") == 0) {
                return node->head.tqh_first;
            }
        }
    }
    return NULL;
}

/**
 * \brief Initializes the output interface context
 *
 * \todo Support multiple interfaces
 */
static void SCPerfInitOPCtx(void)
{
    SCEnter();
    if ( (sc_perf_op_ctx = SCMalloc(sizeof(SCPerfOPIfaceContext))) == NULL) {
        SCLogError(SC_ERR_FATAL, "Fatal error encountered in SCPerfInitOPCtx. Exiting...");
        exit(EXIT_FAILURE);
    }
    memset(sc_perf_op_ctx, 0, sizeof(SCPerfOPIfaceContext));

    ConfNode *stats = GetConfig();
    if (stats != NULL) {
        const char *enabled = ConfNodeLookupChildValue(stats, "enabled");
        if (enabled != NULL && ConfValIsFalse(enabled)) {
            sc_counter_enabled = FALSE;
            SCLogDebug("Stats module has been disabled");
            SCReturn;
        }
        const char *interval = ConfNodeLookupChildValue(stats, "interval");
        if (interval != NULL)
            sc_counter_tts = (uint32_t) atoi(interval);
    }

    if (!OutputStatsLoggersRegistered()) {
        SCLogWarning(SC_WARN_NO_STATS_LOGGERS, "stats are enabled but no loggers are active");
        sc_counter_enabled = FALSE;
        SCReturn;
    }

    /* Store the engine start time */
    time(&sc_start_time);

    /* init the lock used by SCPerfClubTMInst */
    if (SCMutexInit(&sc_perf_op_ctx->pctmi_lock, NULL) != 0) {
        SCLogError(SC_ERR_INITIALIZATION, "error initializing pctmi mutex");
        exit(EXIT_FAILURE);
    }

    SCReturn;
}

/**
 * \brief Releases the resources alloted to the output context of the Perf
 *        Counter API
 */
static void SCPerfReleaseOPCtx()
{
    if (sc_perf_op_ctx == NULL) {
        SCLogDebug("Counter module has been disabled");
        return;
    }

    SCPerfClubTMInst *pctmi = NULL;
    SCPerfClubTMInst *temp = NULL;
    pctmi = sc_perf_op_ctx->pctmi;

    while (pctmi != NULL) {
        if (pctmi->tm_name != NULL)
            SCFree(pctmi->tm_name);

        if (pctmi->head != NULL)
            SCFree(pctmi->head);

        temp = pctmi->next;
        SCFree(pctmi);
        pctmi = temp;
    }

    SCFree(sc_perf_op_ctx);
    sc_perf_op_ctx = NULL;

    /* free stats table */
    if (stats_table.stats != NULL) {
        SCFree(stats_table.stats);
        memset(&stats_table, 0, sizeof(stats_table));
    }

    return;
}

/**
 * \brief The management thread. This thread is responsible for writing the
 *        performance stats information.
 *
 * \param arg is NULL always
 *
 * \retval NULL This is the value that is always returned
 */
static void *SCPerfMgmtThread(void *arg)
{
    /* block usr2.  usr2 to be handled by the main thread only */
    UtilSignalBlock(SIGUSR2);

    ThreadVars *tv_local = (ThreadVars *)arg;
    uint8_t run = 1;
    struct timespec cond_time;

    /* Set the thread name */
    if (SCSetThreadName(tv_local->name) < 0) {
        SCLogWarning(SC_ERR_THREAD_INIT, "Unable to set thread name");
    }

    if (tv_local->thread_setup_flags != 0)
        TmThreadSetupOptions(tv_local);

    /* Set the threads capability */
    tv_local->cap_flags = 0;

    SCDropCaps(tv_local);
    PacketPoolInit();

    if (sc_perf_op_ctx == NULL) {
        SCLogError(SC_ERR_PERF_STATS_NOT_INIT, "Perf Counter API not init"
                   "SCPerfInitCounterApi() has to be called first");
        TmThreadsSetFlag(tv_local, THV_CLOSED | THV_RUNNING_DONE);
        return NULL;
    }

    TmModule *tm = &tmm_modules[TMM_STATSLOGGER];
    BUG_ON(tm->ThreadInit == NULL);
    int r = tm->ThreadInit(tv_local, NULL, &stats_thread_data);
    if (r != 0 || stats_thread_data == NULL) {
        SCLogError(SC_ERR_THREAD_INIT, "Perf Counter API "
                   "ThreadInit failed");
        TmThreadsSetFlag(tv_local, THV_CLOSED | THV_RUNNING_DONE);
        return NULL;
    }
    SCLogDebug("stats_thread_data %p", &stats_thread_data);

    TmThreadsSetFlag(tv_local, THV_INIT_DONE);
    while (run) {
        if (TmThreadsCheckFlag(tv_local, THV_PAUSE)) {
            TmThreadsSetFlag(tv_local, THV_PAUSED);
            TmThreadTestThreadUnPaused(tv_local);
            TmThreadsUnsetFlag(tv_local, THV_PAUSED);
        }

        cond_time.tv_sec = time(NULL) + sc_counter_tts;
        cond_time.tv_nsec = 0;

        SCCtrlMutexLock(tv_local->ctrl_mutex);
        SCCtrlCondTimedwait(tv_local->ctrl_cond, tv_local->ctrl_mutex, &cond_time);
        SCCtrlMutexUnlock(tv_local->ctrl_mutex);

        SCPerfOutputCounters(tv_local);

        if (TmThreadsCheckFlag(tv_local, THV_KILL)) {
            run = 0;
        }
    }

    TmThreadsSetFlag(tv_local, THV_RUNNING_DONE);
    TmThreadWaitForFlag(tv_local, THV_DEINIT);

    TmThreadsSetFlag(tv_local, THV_CLOSED);
    return NULL;
}

/**
 * \brief Wake up thread.  This thread wakes up every TTS(time to sleep) seconds
 *        and sets the flag for every ThreadVars' SCPerfContext
 *
 * \param arg is NULL always
 *
 * \retval NULL This is the value that is always returned
 */
static void *SCPerfWakeupThread(void *arg)
{
    /* block usr2.  usr2 to be handled by the main thread only */
    UtilSignalBlock(SIGUSR2);

    ThreadVars *tv_local = (ThreadVars *)arg;
    uint8_t run = 1;
    ThreadVars *tv = NULL;
    PacketQueue *q = NULL;
    struct timespec cond_time;

    /* Set the thread name */
    if (SCSetThreadName(tv_local->name) < 0) {
        SCLogWarning(SC_ERR_THREAD_INIT, "Unable to set thread name");
    }

    if (tv_local->thread_setup_flags != 0)
        TmThreadSetupOptions(tv_local);

    /* Set the threads capability */
    tv_local->cap_flags = 0;

    SCDropCaps(tv_local);
    PacketPoolInit();

    if (sc_perf_op_ctx == NULL) {
        SCLogError(SC_ERR_PERF_STATS_NOT_INIT, "Perf Counter API not init"
                   "SCPerfInitCounterApi() has to be called first");
        TmThreadsSetFlag(tv_local, THV_CLOSED | THV_RUNNING_DONE);
        return NULL;
    }

    TmThreadsSetFlag(tv_local, THV_INIT_DONE);
    while (run) {
        if (TmThreadsCheckFlag(tv_local, THV_PAUSE)) {
            TmThreadsSetFlag(tv_local, THV_PAUSED);
            TmThreadTestThreadUnPaused(tv_local);
            TmThreadsUnsetFlag(tv_local, THV_PAUSED);
        }

        cond_time.tv_sec = time(NULL) + SC_PERF_WUT_TTS;
        cond_time.tv_nsec = 0;

        SCCtrlMutexLock(tv_local->ctrl_mutex);
        SCCtrlCondTimedwait(tv_local->ctrl_cond, tv_local->ctrl_mutex, &cond_time);
        SCCtrlMutexUnlock(tv_local->ctrl_mutex);

        tv = tv_root[TVT_PPT];
        while (tv != NULL) {
            if (tv->sc_perf_pctx.head == NULL) {
                tv = tv->next;
                continue;
            }

            /* assuming the assignment of an int to be atomic, and even if it's
             * not, it should be okay */
            tv->sc_perf_pctx.perf_flag = 1;

            if (tv->inq != NULL) {
                q = &trans_q[tv->inq->id];
                SCCondSignal(&q->cond_q);
            }

            tv = tv->next;
        }

        /* mgt threads for flow manager */
        tv = tv_root[TVT_MGMT];
        while (tv != NULL) {
            if (tv->sc_perf_pctx.head == NULL) {
                tv = tv->next;
                continue;
            }

            /* assuming the assignment of an int to be atomic, and even if it's
             * not, it should be okay */
            tv->sc_perf_pctx.perf_flag = 1;

            tv = tv->next;
        }

        if (TmThreadsCheckFlag(tv_local, THV_KILL)) {
            run = 0;
        }
    }

    TmThreadsSetFlag(tv_local, THV_RUNNING_DONE);
    TmThreadWaitForFlag(tv_local, THV_DEINIT);

    TmThreadsSetFlag(tv_local, THV_CLOSED);
    return NULL;
}

/**
 * \brief Releases a perf counter.  Used internally by
 *        SCPerfReleasePerfCounterS()
 *
 * \param pc Pointer to the SCPerfCounter to be freed
 */
static void SCPerfReleaseCounter(SCPerfCounter *pc)
{
    if (pc != NULL) {
        if (pc->cname != NULL)
            SCFree(pc->cname);

        if (pc->tm_name != NULL)
            SCFree(pc->tm_name);

        if (pc->desc != NULL)
            SCFree(pc->desc);

        SCFree(pc);
    }

    return;
}

/**
 * \brief Registers a counter.  Used internally by the Perf Counter API
 *
 * \param cname    Name of the counter, to be registered
 * \param tm_name  Thread module to which this counter belongs
 * \param type     Datatype of this counter variable
 * \param desc     Description of this counter
 * \param pctx     SCPerfContext for this tm-tv instance
 * \param type_q   Qualifier describing the type of counter to be registered
 *
 * \retval the counter id for the newly registered counter, or the already
 *         present counter on success
 * \retval 0 on failure
 */
static uint16_t SCPerfRegisterQualifiedCounter(char *cname, char *tm_name,
                                               int type, char *desc,
                                               SCPerfContext *pctx, int type_q)
{
    SCPerfCounter **head = &pctx->head;
    SCPerfCounter *temp = NULL;
    SCPerfCounter *prev = NULL;
    SCPerfCounter *pc = NULL;

    if (cname == NULL || tm_name == NULL || pctx == NULL) {
        SCLogDebug("Counter name, tm name null or SCPerfContext NULL");
        return 0;
    }

    if ((type >= SC_PERF_TYPE_MAX) || (type < 0)) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Counters of type %" PRId32 " can't "
                   "be registered", type);
        return 0;
    }

    temp = prev = *head;
    while (temp != NULL) {
        prev = temp;

        if (strcmp(cname, temp->cname) == 0 &&
            strcmp(tm_name, temp->tm_name) == 0) {
            break;
        }

        temp = temp->next;
    }

    /* We already have a counter registered by this name */
    if (temp != NULL)
        return(temp->id);

    /* if we reach this point we don't have a counter registered by this cname */
    if ( (pc = SCMalloc(sizeof(SCPerfCounter))) == NULL)
        return 0;
    memset(pc, 0, sizeof(SCPerfCounter));

    if ( (pc->cname = SCStrdup(cname)) == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
        exit(EXIT_FAILURE);
    }

    if ( (pc->tm_name = SCStrdup(tm_name)) == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
        exit(EXIT_FAILURE);
    }

    /* assign a unique id to this SCPerfCounter.  The id is local to this
     * PerfContext.  Please note that the id start from 1, and not 0 */
    pc->id = ++(pctx->curr_id);

    if (desc != NULL && (pc->desc = SCStrdup(desc)) == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
        exit(EXIT_FAILURE);
    }

    pc->type = type_q;

    /* we now add the counter to the list */
    if (prev == NULL)
        *head = pc;
    else
        prev->next = pc;

    return pc->id;
}

/**
 * \brief Copies the SCPerfCounter value from the local counter present in the
 *        SCPerfCounterArray to its corresponding global counterpart.  Used
 *        internally by SCPerfUpdateCounterArray()
 *
 * \param pcae     Pointer to the SCPerfCounterArray which holds the local
 *                 versions of the counters
 */
static void SCPerfCopyCounterValue(SCPCAElem *pcae)
{
    SCPerfCounter *pc = NULL;
    uint64_t ui64_temp = 0;

    pc = pcae->pc;
    ui64_temp = pcae->ui64_cnt;

    if (pc->type == SC_PERF_TYPE_Q_AVERAGE) {
        if (pcae->syncs != 0)
            ui64_temp /= pcae->syncs;
        pc->value = ui64_temp;
    } else {
        pc->value = ui64_temp;
    }

    return;
}

/**
 * \brief Calculates counter value that should be sent as output
 *
 *        If we aren't dealing with timebased counters, we just return the
 *        the counter value.  In case of Timebased counters, if we haven't
 *        crossed the interval, we display the current value without any
 *        modifications.  If we have crossed the limit, we calculate the counter
 *        value for the time period and also return 1, to indicate that the
 *        counter value can be reset after use
 *
 * \param pc Pointer to the PerfCounter for which the timebased counter has to
 *           be calculated
 */
static uint64_t SCPerfOutputCalculateCounterValue(SCPerfCounter *pc)
{
    return pc->value;
}


/**
 * \brief The file output interface for the Perf Counter api
 */
static int SCPerfOutputCounterFileIface(ThreadVars *tv)
{
    const SCPerfClubTMInst *pctmi = NULL;
    const SCPerfCounter *pc = NULL;
    SCPerfCounter **pc_heads = NULL;

    uint64_t ui64_temp = 0;
    uint64_t ui64_result = 0;

    uint32_t u = 0;
    int flag = 0;
    void *td = stats_thread_data;

    if (stats_table.nstats == 0) {
        uint32_t nstats = 0;

        pctmi = sc_perf_op_ctx->pctmi;
        while (pctmi != NULL) {
            if (pctmi->size == 0) {
                pctmi = pctmi->next;
                continue;
            }

            if ((pc_heads = SCMalloc(pctmi->size * sizeof(SCPerfCounter *))) == NULL)
                return 0;
            memset(pc_heads, 0, pctmi->size * sizeof(SCPerfCounter *));

            for (u = 0; u < pctmi->size; u++) {
                pc_heads[u] = pctmi->head[u]->head;
                SCMutexLock(&pctmi->head[u]->m);
            }

            flag = 1;
            while (flag) {
                if (pc_heads[0] == NULL)
                    break;

                for (u = 0; u < pctmi->size; u++) {
                    if (pc_heads[u] != NULL)
                        pc_heads[u] = pc_heads[u]->next;
                    if (pc_heads[u] == NULL)
                        flag = 0;
                }

                /* count */
                nstats++;
            }

            for (u = 0; u < pctmi->size; u++)
                SCMutexUnlock(&pctmi->head[u]->m);

            pctmi = pctmi->next;
            SCFree(pc_heads);

        }
        if (nstats == 0) {
            SCLogError(SC_ERR_PERF_STATS_NOT_INIT, "no counters registered");
            return -1;
        }

        stats_table.nstats = nstats;
        stats_table.stats = SCCalloc(stats_table.nstats, sizeof(StatsRecord));
        if (stats_table.stats == NULL) {
            stats_table.nstats = 0;
            SCLogError(SC_ERR_MEM_ALLOC, "could not alloc memory for stats");
            return -1;
        }

        stats_table.start_time = sc_start_time;
    }
    StatsRecord *table = stats_table.stats;

    int table_i = 0;

    pctmi = sc_perf_op_ctx->pctmi;
    while (pctmi != NULL) {
        if (pctmi->size == 0) {
            pctmi = pctmi->next;
            continue;
        }

        if ((pc_heads = SCMalloc(pctmi->size * sizeof(SCPerfCounter *))) == NULL)
            return 0;
        memset(pc_heads, 0, pctmi->size * sizeof(SCPerfCounter *));

        for (u = 0; u < pctmi->size; u++) {
            pc_heads[u] = pctmi->head[u]->head;
            SCMutexLock(&pctmi->head[u]->m);
        }

        flag = 1;
        while (flag) {
            ui64_result = 0;
            if (pc_heads[0] == NULL)
                break;
            /* keep ptr to first pc to we can use it to print the cname */
            pc = pc_heads[0];

            for (u = 0; u < pctmi->size; u++) {
                ui64_temp = SCPerfOutputCalculateCounterValue(pc_heads[u]);
                ui64_result += ui64_temp;

                if (pc_heads[u] != NULL)
                    pc_heads[u] = pc_heads[u]->next;
                if (pc_heads[u] == NULL)
                    flag = 0;
            }

            /* store in the table */
            table[table_i].name = pc->cname;
            table[table_i].tm_name = pctmi->tm_name;
            table[table_i].pvalue = table[table_i].value;
            table[table_i].value = ui64_result;
            table_i++;
        }

        for (u = 0; u < pctmi->size; u++)
            SCMutexUnlock(&pctmi->head[u]->m);

        pctmi = pctmi->next;
        SCFree(pc_heads);

    }

    /* invoke logger(s) */
    OutputStatsLog(tv, td, &stats_table);
    return 1;
}

#ifdef BUILD_UNIX_SOCKET
/**
 * \brief The file output interface for the Perf Counter api
 */
TmEcode SCPerfOutputCounterSocket(json_t *cmd,
                               json_t *answer, void *data)
{
    SCPerfClubTMInst *pctmi = NULL;
    SCPerfCounter *pc = NULL;
    SCPerfCounter **pc_heads = NULL;

    uint64_t ui64_temp = 0;
    uint64_t ui64_result = 0;

    uint32_t u = 0;
    int flag = 0;

    if (sc_perf_op_ctx == NULL) {
        json_object_set_new(answer, "message",
                json_string("No performance counter context"));
        return TM_ECODE_FAILED;
    }

    json_t *tm_array;

    tm_array = json_object();
    if (tm_array == NULL) {
        json_object_set_new(answer, "message",
                json_string("internal error at json object creation"));
        return TM_ECODE_FAILED;
    }

    pctmi = sc_perf_op_ctx->pctmi;
    while (pctmi != NULL) {
        json_t *jdata;
        int filled = 0;
        jdata = json_object();
        if (jdata == NULL) {
            json_decref(tm_array);
            json_object_set_new(answer, "message",
                    json_string("internal error at json object creation"));
            return TM_ECODE_FAILED;
        }
        if ((pc_heads = SCMalloc(pctmi->size * sizeof(SCPerfCounter *))) == NULL) {
            json_decref(tm_array);
            json_object_set_new(answer, "message",
                    json_string("internal memory error"));
            return TM_ECODE_FAILED;
        }
        memset(pc_heads, 0, pctmi->size * sizeof(SCPerfCounter *));

        for (u = 0; u < pctmi->size; u++) {
            pc_heads[u] = pctmi->head[u]->head;

            SCMutexLock(&pctmi->head[u]->m);
        }

        flag = 1;
        while(flag) {
            ui64_result = 0;
            if (pc_heads[0] == NULL)
                break;
            pc = pc_heads[0];

            for (u = 0; u < pctmi->size; u++) {
                ui64_temp = SCPerfOutputCalculateCounterValue(pc_heads[u]);
                ui64_result += ui64_temp;

                if (pc_heads[u] != NULL)
                    pc_heads[u] = pc_heads[u]->next;
                if (pc_heads[u] == NULL)
                    flag = 0;
            }

            filled = 1;
            json_object_set_new(jdata, pc->cname, json_integer(ui64_result));
        }

        for (u = 0; u < pctmi->size; u++)
            SCMutexUnlock(&pctmi->head[u]->m);

        if (filled == 1) {
            json_object_set_new(tm_array, pctmi->tm_name, jdata);
        }
        pctmi = pctmi->next;

        SCFree(pc_heads);

    }

    json_object_set_new(answer, "message", tm_array);

    return TM_ECODE_OK;
}

#endif /* BUILD_UNIX_SOCKET */

/**
 * \brief Initializes the perf counter api.  Things are hard coded currently.
 *        More work to be done when we implement multiple interfaces
 */
void SCPerfInitCounterApi(void)
{
    SCPerfInitOPCtx();

    return;
}

/**
 * \brief Spawns the wakeup, and the management thread used by the perf
 *        counter api
 */
void SCPerfSpawnThreads(void)
{
    SCEnter();

    if (!sc_counter_enabled) {
        SCReturn;
    }

    ThreadVars *tv_wakeup = NULL;
    ThreadVars *tv_mgmt = NULL;

    /* spawn the stats wakeup thread */
    tv_wakeup = TmThreadCreateMgmtThread("SCPerfWakeupThread",
                                         SCPerfWakeupThread, 1);
    if (tv_wakeup == NULL) {
        SCLogError(SC_ERR_THREAD_CREATE, "TmThreadCreateMgmtThread "
                   "failed");
        exit(EXIT_FAILURE);
    }

    if (TmThreadSpawn(tv_wakeup) != 0) {
        SCLogError(SC_ERR_THREAD_SPAWN, "TmThreadSpawn failed for "
                   "SCPerfWakeupThread");
        exit(EXIT_FAILURE);
    }

    /* spawn the stats mgmt thread */
    tv_mgmt = TmThreadCreateMgmtThread("SCPerfMgmtThread",
                                       SCPerfMgmtThread, 1);
    if (tv_mgmt == NULL) {
        SCLogError(SC_ERR_THREAD_CREATE,
                   "TmThreadCreateMgmtThread failed");
        exit(EXIT_FAILURE);
    }

    if (TmThreadSpawn(tv_mgmt) != 0) {
        SCLogError(SC_ERR_THREAD_SPAWN, "TmThreadSpawn failed for "
                   "SCPerfWakeupThread");
        exit(EXIT_FAILURE);
    }

    SCReturn;
}

/**
 * \brief Registers a normal, unqualified counter
 *
 * \param cname Name of the counter, to be registered
 * \param tv    Pointer to the ThreadVars instance for which the counter would
 *              be registered
 * \param type  Datatype of this counter variable
 * \param desc  Description of this counter
 *
 * \retval id Counter id for the newly registered counter, or the already
 *            present counter
 */
uint16_t SCPerfTVRegisterCounter(char *cname, struct ThreadVars_ *tv, int type,
                                 char *desc)
{
    uint16_t id = SCPerfRegisterQualifiedCounter(cname,
                                                 (tv->thread_group_name != NULL) ? tv->thread_group_name : tv->name,
                                                 type, desc,
                                                 &tv->sc_perf_pctx,
                                                 SC_PERF_TYPE_Q_NORMAL);

    return id;
}

/**
 * \brief Registers a counter, whose value holds the average of all the values
 *        assigned to it.
 *
 * \param cname Name of the counter, to be registered
 * \param tv    Pointer to the ThreadVars instance for which the counter would
 *              be registered
 * \param type  Datatype of this counter variable
 * \param desc  Description of this counter
 *
 * \retval id Counter id for the newly registered counter, or the already
 *            present counter
 */
uint16_t SCPerfTVRegisterAvgCounter(char *cname, struct ThreadVars_ *tv,
                                    int type, char *desc)
{
    uint16_t id = SCPerfRegisterQualifiedCounter(cname,
                                                 (tv->thread_group_name != NULL) ? tv->thread_group_name : tv->name,
                                                 type, desc,
                                                 &tv->sc_perf_pctx,
                                                 SC_PERF_TYPE_Q_AVERAGE);

    return id;
}

/**
 * \brief Registers a counter, whose value holds the maximum of all the values
 *        assigned to it.
 *
 * \param cname Name of the counter, to be registered
 * \param tv    Pointer to the ThreadVars instance for which the counter would
 *              be registered
 * \param type  Datatype of this counter variable
 * \param desc  Description of this counter
 *
 * \retval the counter id for the newly registered counter, or the already
 *         present counter
 */
uint16_t SCPerfTVRegisterMaxCounter(char *cname, struct ThreadVars_ *tv,
                                    int type, char *desc)
{
    uint16_t id = SCPerfRegisterQualifiedCounter(cname,
                                                 (tv->thread_group_name != NULL) ? tv->thread_group_name : tv->name,
                                                 type, desc,
                                                 &tv->sc_perf_pctx,
                                                 SC_PERF_TYPE_Q_MAXIMUM);

    return id;
}

/**
 * \brief Registers a normal, unqualified counter
 *
 * \param cname   Name of the counter, to be registered
 * \param tm_name Name of the engine module under which the counter has to be
 *                registered
 * \param type    Datatype of this counter variable
 * \param desc    Description of this counter
 * \param pctx    SCPerfContext corresponding to the tm_name key under which the
 *                key has to be registered
 *
 * \retval id Counter id for the newly registered counter, or the already
 *            present counter
 */
uint16_t SCPerfRegisterCounter(char *cname, char *tm_name, int type, char *desc,
                               SCPerfContext *pctx)
{
    uint16_t id = SCPerfRegisterQualifiedCounter(cname, tm_name, type, desc,
                                                 pctx, SC_PERF_TYPE_Q_NORMAL);

    return id;
}

/**
 * \brief Registers a counter, whose value holds the average of all the values
 *        assigned to it.
 *
 * \param cname   Name of the counter, to be registered
 * \param tm_name Name of the engine module under which the counter has to be
 *                registered
 * \param type    Datatype of this counter variable
 * \param desc    Description of this counter
 * \param pctx    SCPerfContext corresponding to the tm_name key under which the
 *                key has to be registered
 *
 * \retval id Counter id for the newly registered counter, or the already
 *            present counter
 */
uint16_t SCPerfRegisterAvgCounter(char *cname, char *tm_name, int type,
                                  char *desc, SCPerfContext *pctx)
{
    uint16_t id = SCPerfRegisterQualifiedCounter(cname, tm_name, type, desc,
                                                 pctx, SC_PERF_TYPE_Q_AVERAGE);

    return id;
}

/**
 * \brief Registers a counter, whose value holds the maximum of all the values
 *        assigned to it.
 *
 * \param cname   Name of the counter, to be registered
 * \param tm_name Name of the engine module under which the counter has to be
 *                registered
 * \param type    Datatype of this counter variable
 * \param desc    Description of this counter
 * \param pctx    SCPerfContext corresponding to the tm_name key under which the
 *                key has to be registered
 *
 * \retval id Counter id for the newly registered counter, or the already
 *            present counter
 */
uint16_t SCPerfRegisterMaxCounter(char *cname, char *tm_name, int type,
                                  char *desc, SCPerfContext *pctx)
{
    uint16_t id = SCPerfRegisterQualifiedCounter(cname, tm_name, type, desc,
                                                 pctx, SC_PERF_TYPE_Q_MAXIMUM);

    return id;
}

/**
 * \brief Adds a TM to the clubbed TM table.  Multiple instances of the same TM
 *        are stacked together in a PCTMI container.
 *
 * \param tm_name Name of the tm to be added to the table
 * \param pctx    SCPerfContext associated with the TM tm_name
 *
 * \retval 1 on success, 0 on failure
 */
int SCPerfAddToClubbedTMTable(char *tm_name, SCPerfContext *pctx)
{
    void *ptmp;
    if (sc_perf_op_ctx == NULL) {
        SCLogDebug("Counter module has been disabled");
        return 0;
    }

    SCPerfClubTMInst *pctmi = NULL;
    SCPerfClubTMInst *prev = NULL;
    SCPerfClubTMInst *temp = NULL;
    SCPerfContext **hpctx = NULL;
    uint32_t u = 0;

    if (tm_name == NULL || pctx == NULL) {
        SCLogDebug("supplied argument(s) to SCPerfAddToClubbedTMTable NULL");
        return 0;
    }

    SCMutexLock(&sc_perf_op_ctx->pctmi_lock);

    pctmi = sc_perf_op_ctx->pctmi;
    SCLogDebug("pctmi %p", pctmi);
    prev = pctmi;

    while (pctmi != NULL) {
        prev = pctmi;
        if (strcmp(tm_name, pctmi->tm_name) != 0) {
            pctmi = pctmi->next;
            continue;
        }
        break;
    }

    /* get me the bugger who wrote this junk of a code :P */
    if (pctmi == NULL) {
        if ( (temp = SCMalloc(sizeof(SCPerfClubTMInst))) == NULL) {
            SCMutexUnlock(&sc_perf_op_ctx->pctmi_lock);
            return 0;
        }
        memset(temp, 0, sizeof(SCPerfClubTMInst));

        temp->size = 1;
        temp->head = SCMalloc(sizeof(SCPerfContext **));
        if (temp->head == NULL) {
            SCFree(temp);
            SCMutexUnlock(&sc_perf_op_ctx->pctmi_lock);
            return 0;
        }
        temp->head[0] = pctx;
        temp->tm_name = SCStrdup(tm_name);
        if (unlikely(temp->tm_name == NULL)) {
            SCFree(temp->head);
            SCFree(temp);
            SCMutexUnlock(&sc_perf_op_ctx->pctmi_lock);
            return 0;
        }

        if (prev == NULL)
            sc_perf_op_ctx->pctmi = temp;
        else
            prev->next = temp;

        SCMutexUnlock(&sc_perf_op_ctx->pctmi_lock);
        return 1;
    }

    /* see if the pctx is already part of this pctmi */
    hpctx = pctmi->head;
    for (u = 0; u < pctmi->size; u++) {
        if (hpctx[u] != pctx)
            continue;

        SCMutexUnlock(&sc_perf_op_ctx->pctmi_lock);
        return 1;
    }

    ptmp = SCRealloc(pctmi->head,
                     (pctmi->size + 1) * sizeof(SCPerfContext **));
    if (ptmp == NULL) {
        SCFree(pctmi->head);
        pctmi->head = NULL;
        SCMutexUnlock(&sc_perf_op_ctx->pctmi_lock);
        return 0;
    }
    pctmi->head = ptmp;

    hpctx = pctmi->head;

    hpctx[pctmi->size] = pctx;
    for (u = pctmi->size - 1; u > 0; u--) {
        if (pctx->curr_id <= hpctx[u]->curr_id) {
            hpctx[u + 1] = hpctx[u];
            hpctx[u] = pctx;
            continue;
        }
        break;
    }
    pctmi->size++;

    SCMutexUnlock(&sc_perf_op_ctx->pctmi_lock);

    return 1;
}

/**
 * \brief Returns a counter array for counters in this id range(s_id - e_id)
 *
 * \param s_id Counter id of the first counter to be added to the array
 * \param e_id Counter id of the last counter to be added to the array
 * \param pctx Pointer to the tv's SCPerfContext
 *
 * \retval a counter-array in this(s_id-e_id) range for this TM instance
 */
SCPerfCounterArray *SCPerfGetCounterArrayRange(uint16_t s_id, uint16_t e_id,
                                               SCPerfContext *pctx)
{
    SCPerfCounter *pc = NULL;
    SCPerfCounterArray *pca = NULL;
    uint32_t i = 0;

    if (pctx == NULL) {
        SCLogDebug("pctx is NULL");
        return NULL;
    }

    if (s_id < 1 || e_id < 1 || s_id > e_id) {
        SCLogDebug("error with the counter ids");
        return NULL;
    }

    if (e_id > pctx->curr_id) {
        SCLogDebug("end id is greater than the max id for this tv");
        return NULL;
    }

    if ( (pca = SCMalloc(sizeof(SCPerfCounterArray))) == NULL)
        return NULL;
    memset(pca, 0, sizeof(SCPerfCounterArray));

    if ( (pca->head = SCMalloc(sizeof(SCPCAElem) * (e_id - s_id  + 2))) == NULL) {
        SCFree(pca);
        return NULL;
    }
    memset(pca->head, 0, sizeof(SCPCAElem) * (e_id - s_id  + 2));

    pc = pctx->head;
    while (pc->id != s_id)
        pc = pc->next;

    i = 1;
    while ((pc != NULL) && (pc->id <= e_id)) {
        pca->head[i].pc = pc;
        pca->head[i].id = pc->id;
        pc = pc->next;
        i++;
    }
    pca->size = i - 1;

    return pca;
}

/**
 * \brief Returns a counter array for all counters registered for this tm
 *        instance
 *
 * \param pctx Pointer to the tv's SCPerfContext
 *
 * \retval pca Pointer to a counter-array for all counter of this tm instance
 *             on success; NULL on failure
 */
SCPerfCounterArray *SCPerfGetAllCountersArray(SCPerfContext *pctx)
{
    SCPerfCounterArray *pca = ((pctx)?
                               SCPerfGetCounterArrayRange(1, pctx->curr_id, pctx):
                               NULL);

    return pca;
}

/**
 * \brief Syncs the counter array with the global counter variables
 *
 * \param pca      Pointer to the SCPerfCounterArray
 * \param pctx     Pointer the the tv's SCPerfContext
 * \param reset_lc Indicates whether the local counter has to be reset or not
 *
 * \retval  0 on success
 * \retval -1 on error
 */
int SCPerfUpdateCounterArray(SCPerfCounterArray *pca, SCPerfContext *pctx)
{
    SCPerfCounter  *pc = NULL;
    SCPCAElem *pcae = NULL;
    uint32_t i = 0;

    if (pca == NULL || pctx == NULL) {
        SCLogDebug("pca or pctx is NULL inside SCPerfUpdateCounterArray");
        return -1;
    }

    pcae = pca->head;

    SCMutexLock(&pctx->m);
    pc = pctx->head;

    for (i = 1; i <= pca->size; i++) {
        while (pc != NULL) {
            if (pc->id != pcae[i].id) {
                pc = pc->next;
                continue;
            }

            SCPerfCopyCounterValue(&pcae[i]);

            pc = pc->next;
            break;
        }
    }

    SCMutexUnlock(&pctx->m);

    pctx->perf_flag = 0;

    return 1;
}

/*
 * \brief Get the value of the local copy of the counter that hold this id.
 *
 * \param id  The counter id.
 * \param pca Pointer to the SCPerfCounterArray.
 *
 * \retval  0 on success.
 * \retval -1 on error.
 */
double SCPerfGetLocalCounterValue(uint16_t id, SCPerfCounterArray *pca)
{
#ifdef DEBUG
    BUG_ON (pca == NULL);
    BUG_ON ((id < 1) || (id > pca->size));
#endif
    return pca->head[id].ui64_cnt;
}

/**
 * \brief Releases the resources alloted by the Perf Counter API
 */
void SCPerfReleaseResources()
{
    SCPerfReleaseOPCtx();

    return;
}

/**
 * \brief Releases a list of perf counters
 *
 * \param head Pointer to the head of the list of perf counters that have to
 *             be freed
 */
void SCPerfReleasePerfCounterS(SCPerfCounter *head)
{
    SCPerfCounter *pc = NULL;

    while (head != NULL) {
        pc = head;
        head = head->next;
        SCPerfReleaseCounter(pc);
    }

    return;
}

/**
 * \brief Releases the SCPerfCounterArray allocated by the user, for storing and
 *        updating local counter values
 *
 * \param pca Pointer to the SCPerfCounterArray
 */
void SCPerfReleasePCA(SCPerfCounterArray *pca)
{
    if (pca != NULL) {
        if (pca->head != NULL)
            SCFree(pca->head);

        SCFree(pca);
    }

    return;
}

/*----------------------------------Unit_Tests--------------------------------*/

#ifdef UNITTESTS
static int SCPerfTestCounterReg01()
{
    SCPerfContext pctx;

    memset(&pctx, 0, sizeof(SCPerfContext));

    return SCPerfRegisterCounter("t1", "c1", 5, NULL, &pctx);
}

static int SCPerfTestCounterReg02()
{
    SCPerfContext pctx;

    memset(&pctx, 0, sizeof(SCPerfContext));

    return SCPerfRegisterCounter(NULL, NULL, SC_PERF_TYPE_UINT64, NULL, &pctx);
}

static int SCPerfTestCounterReg03()
{
    SCPerfContext pctx;
    int result;

    memset(&pctx, 0, sizeof(SCPerfContext));

    result = SCPerfRegisterCounter("t1", "c1", SC_PERF_TYPE_UINT64, NULL, &pctx);

    SCPerfReleasePerfCounterS(pctx.head);

    return result;
}

static int SCPerfTestCounterReg04()
{
    SCPerfContext pctx;
    int result;

    memset(&pctx, 0, sizeof(SCPerfContext));

    SCPerfRegisterCounter("t1", "c1", SC_PERF_TYPE_UINT64, NULL, &pctx);
    SCPerfRegisterCounter("t2", "c2", SC_PERF_TYPE_UINT64, NULL, &pctx);
    SCPerfRegisterCounter("t3", "c3", SC_PERF_TYPE_UINT64, NULL, &pctx);

    result = SCPerfRegisterCounter("t1", "c1", SC_PERF_TYPE_UINT64, NULL, &pctx);

    SCPerfReleasePerfCounterS(pctx.head);

    return result;
}

static int SCPerfTestGetCntArray05()
{
    ThreadVars tv;
    int id;

    memset(&tv, 0, sizeof(ThreadVars));

    id = SCPerfRegisterCounter("t1", "c1", SC_PERF_TYPE_UINT64, NULL,
                               &tv.sc_perf_pctx);
    if (id != 1) {
        printf("id %d: ", id);
        return 0;
    }

    tv.sc_perf_pca = SCPerfGetAllCountersArray(NULL);

    return (!tv.sc_perf_pca)?1:0;
}

static int SCPerfTestGetCntArray06()
{
    ThreadVars tv;
    int id;
    int result;

    memset(&tv, 0, sizeof(ThreadVars));

    id = SCPerfRegisterCounter("t1", "c1", SC_PERF_TYPE_UINT64, NULL,
                               &tv.sc_perf_pctx);
    if (id != 1)
        return 0;

    tv.sc_perf_pca = SCPerfGetAllCountersArray(&tv.sc_perf_pctx);

    result = (tv.sc_perf_pca)?1:0;

    SCPerfReleasePerfCounterS(tv.sc_perf_pctx.head);
    SCPerfReleasePCA(tv.sc_perf_pca);

    return result;
}

static int SCPerfTestCntArraySize07()
{
    ThreadVars tv;
    SCPerfCounterArray *pca = NULL;
    int result;

    memset(&tv, 0, sizeof(ThreadVars));

    //pca = (SCPerfCounterArray *)&tv.sc_perf_pca;

    SCPerfRegisterCounter("t1", "c1", SC_PERF_TYPE_UINT64, NULL,
                          &tv.sc_perf_pctx);
    SCPerfRegisterCounter("t2", "c2", SC_PERF_TYPE_UINT64, NULL,
                          &tv.sc_perf_pctx);

    pca = SCPerfGetAllCountersArray(&tv.sc_perf_pctx);

    SCPerfCounterIncr(1, pca);
    SCPerfCounterIncr(2, pca);

    result = pca->size;

    SCPerfReleasePerfCounterS(tv.sc_perf_pctx.head);
    SCPerfReleasePCA(pca);

    return result;
}

static int SCPerfTestUpdateCounter08()
{
    ThreadVars tv;
    SCPerfCounterArray *pca = NULL;
    int id;
    int result;

    memset(&tv, 0, sizeof(ThreadVars));

    id = SCPerfRegisterCounter("t1", "c1", SC_PERF_TYPE_UINT64, NULL,
                               &tv.sc_perf_pctx);

    pca = SCPerfGetAllCountersArray(&tv.sc_perf_pctx);

    SCPerfCounterIncr(id, pca);
    SCPerfCounterAddUI64(id, pca, 100);

    result = pca->head[id].ui64_cnt;

    SCPerfReleasePerfCounterS(tv.sc_perf_pctx.head);
    SCPerfReleasePCA(pca);

    return result;
}

static int SCPerfTestUpdateCounter09()
{
    ThreadVars tv;
    SCPerfCounterArray *pca = NULL;
    uint16_t id1, id2;
    int result;

    memset(&tv, 0, sizeof(ThreadVars));

    id1 = SCPerfRegisterCounter("t1", "c1", SC_PERF_TYPE_UINT64, NULL,
                                &tv.sc_perf_pctx);
    SCPerfRegisterCounter("t2", "c2", SC_PERF_TYPE_UINT64, NULL,
                          &tv.sc_perf_pctx);
    SCPerfRegisterCounter("t3", "c3", SC_PERF_TYPE_UINT64, NULL,
                          &tv.sc_perf_pctx);
    SCPerfRegisterCounter("t4", "c4", SC_PERF_TYPE_UINT64, NULL,
                          &tv.sc_perf_pctx);
    id2 = SCPerfRegisterCounter("t5", "c5", SC_PERF_TYPE_UINT64, NULL,
                                &tv.sc_perf_pctx);

    pca = SCPerfGetAllCountersArray(&tv.sc_perf_pctx);

    SCPerfCounterIncr(id2, pca);
    SCPerfCounterAddUI64(id2, pca, 100);

    result = (pca->head[id1].ui64_cnt == 0) && (pca->head[id2].ui64_cnt == 101);

    SCPerfReleasePerfCounterS(tv.sc_perf_pctx.head);
    SCPerfReleasePCA(pca);

    return result;
}

static int SCPerfTestUpdateGlobalCounter10()
{
    ThreadVars tv;
    SCPerfCounterArray *pca = NULL;

    int result = 1;
    uint16_t id1, id2, id3;

    memset(&tv, 0, sizeof(ThreadVars));

    id1 = SCPerfRegisterCounter("t1", "c1", SC_PERF_TYPE_UINT64, NULL,
                                &tv.sc_perf_pctx);
    id2 = SCPerfRegisterCounter("t2", "c2", SC_PERF_TYPE_UINT64, NULL,
                                &tv.sc_perf_pctx);
    id3 = SCPerfRegisterCounter("t3", "c3", SC_PERF_TYPE_UINT64, NULL,
                                &tv.sc_perf_pctx);

    pca = SCPerfGetAllCountersArray(&tv.sc_perf_pctx);

    SCPerfCounterIncr(id1, pca);
    SCPerfCounterAddUI64(id2, pca, 100);
    SCPerfCounterIncr(id3, pca);
    SCPerfCounterAddUI64(id3, pca, 100);

    SCPerfUpdateCounterArray(pca, &tv.sc_perf_pctx);

    result = (1 == tv.sc_perf_pctx.head->value);
    result &= (100 == tv.sc_perf_pctx.head->next->value);
    result &= (101 == tv.sc_perf_pctx.head->next->next->value);

    SCPerfReleasePerfCounterS(tv.sc_perf_pctx.head);
    SCPerfReleasePCA(pca);

    return result;
}

static int SCPerfTestCounterValues11()
{
    ThreadVars tv;
    SCPerfCounterArray *pca = NULL;

    int result = 1;
    uint16_t id1, id2, id3, id4;

    memset(&tv, 0, sizeof(ThreadVars));

    id1 = SCPerfRegisterCounter("t1", "c1", SC_PERF_TYPE_UINT64, NULL,
                                &tv.sc_perf_pctx);
    id2 = SCPerfRegisterCounter("t2", "c2", SC_PERF_TYPE_UINT64, NULL,
                                &tv.sc_perf_pctx);
    id3 = SCPerfRegisterCounter("t3", "c3", SC_PERF_TYPE_UINT64, NULL,
                                &tv.sc_perf_pctx);
    id4 = SCPerfRegisterCounter("t4", "c4", SC_PERF_TYPE_UINT64, NULL,
                                &tv.sc_perf_pctx);

    pca = SCPerfGetAllCountersArray(&tv.sc_perf_pctx);

    SCPerfCounterIncr(id1, pca);
    SCPerfCounterAddUI64(id2, pca, 256);
    SCPerfCounterAddUI64(id3, pca, 257);
    SCPerfCounterAddUI64(id4, pca, 16843024);

    SCPerfUpdateCounterArray(pca, &tv.sc_perf_pctx);

    result &= (1 == tv.sc_perf_pctx.head->value);

    result &= (256 == tv.sc_perf_pctx.head->next->value);

    result &= (257 == tv.sc_perf_pctx.head->next->next->value);

    result &= (16843024 == tv.sc_perf_pctx.head->next->next->next->value);

    SCPerfReleasePerfCounterS(tv.sc_perf_pctx.head);
    SCPerfReleasePCA(pca);

    return result;
}

#endif

void SCPerfRegisterTests()
{
#ifdef UNITTESTS
    UtRegisterTest("SCPerfTestCounterReg01", SCPerfTestCounterReg01, 0);
    UtRegisterTest("SCPerfTestCounterReg02", SCPerfTestCounterReg02, 0);
    UtRegisterTest("SCPerfTestCounterReg03", SCPerfTestCounterReg03, 1);
    UtRegisterTest("SCPerfTestCounterReg04", SCPerfTestCounterReg04, 1);
    UtRegisterTest("SCPerfTestGetCntArray05", SCPerfTestGetCntArray05, 1);
    UtRegisterTest("SCPerfTestGetCntArray06", SCPerfTestGetCntArray06, 1);
    UtRegisterTest("SCPerfTestCntArraySize07", SCPerfTestCntArraySize07, 2);
    UtRegisterTest("SCPerfTestUpdateCounter08", SCPerfTestUpdateCounter08, 101);
    UtRegisterTest("SCPerfTestUpdateCounter09", SCPerfTestUpdateCounter09, 1);
    UtRegisterTest("SCPerfTestUpdateGlobalCounter10",
                   SCPerfTestUpdateGlobalCounter10, 1);
    UtRegisterTest("SCPerfTestCounterValues11", SCPerfTestCounterValues11, 1);
#endif
}
