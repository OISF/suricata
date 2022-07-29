/* Copyright (C) 2007-2021 Open Information Security Foundation
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
 * Engine stats API
 */

#include "suricata-common.h"
#include "suricata.h"
#include "counters.h"
#include "tm-threads.h"
#include "util-time.h"
#include "util-unittest.h"
#include "util-byte.h"
#include "util-privs.h"

#include "output-json-stats.h"

/* Time interval for syncing the local counters with the global ones */
#define STATS_WUT_TTS 3

/* Time interval at which the mgmt thread o/p the stats */
#define STATS_MGMTT_TTS 8

/**
 * \brief Different kinds of qualifier that can be used to modify the behaviour
 *        of the counter to be registered
 */
enum {
    STATS_TYPE_NORMAL = 1,
    STATS_TYPE_AVERAGE = 2,
    STATS_TYPE_MAXIMUM = 3,
    STATS_TYPE_FUNC = 4,

    STATS_TYPE_MAX = 5,
};

/**
 * \brief per thread store of counters
 */
typedef struct StatsThreadStore_ {
    /** thread name used in output */
    const char *name;

    StatsPublicThreadContext *ctx;

    StatsPublicThreadContext **head;
    uint32_t size;

    struct StatsThreadStore_ *next;
} StatsThreadStore;

/**
 * \brief Holds the output interface context for the counter api
 */
typedef struct StatsGlobalContext_ {
    /** list of thread stores: one per thread plus one global */
    StatsThreadStore *sts;
    SCMutex sts_lock;
    int sts_cnt;

    HashTable *counters_id_hash;

    StatsPublicThreadContext global_counter_ctx;
} StatsGlobalContext;

static void *stats_thread_data = NULL;
static StatsGlobalContext *stats_ctx = NULL;
static time_t stats_start_time;
/** refresh interval in seconds */
static uint32_t stats_tts = STATS_MGMTT_TTS;
/** is the stats counter enabled? */
static bool stats_enabled = true;

/**< add decoder events as stats? enabled by default */
bool stats_decoder_events = true;
const char *stats_decoder_events_prefix = "decoder.event";
/**< add stream events as stats? disabled by default */
bool stats_stream_events = false;

static int StatsOutput(ThreadVars *tv);
static int StatsThreadRegister(const char *thread_name, StatsPublicThreadContext *);
void StatsReleaseCounters(StatsCounter *head);

/** stats table is filled each interval and passed to the
 *  loggers. Initialized at first use. */
static StatsTable stats_table = { NULL, NULL, 0, 0, 0, {0 , 0}};
static SCMutex stats_table_mutex = SCMUTEX_INITIALIZER;
static int stats_loggers_active = 1;

static uint16_t counters_global_id = 0;

bool StatsEnabled(void)
{
    return stats_enabled;
}

static void StatsPublicThreadContextInit(StatsPublicThreadContext *t)
{
    SCMutexInit(&t->m, NULL);
}

static void StatsPublicThreadContextCleanup(StatsPublicThreadContext *t)
{
    SCMutexLock(&t->m);
    StatsReleaseCounters(t->head);
    t->head = NULL;
    t->perf_flag = 0;
    t->curr_id = 0;
    SCMutexUnlock(&t->m);
    SCMutexDestroy(&t->m);
}

/**
 * \brief Adds a value of type uint64_t to the local counter.
 *
 * \param id  ID of the counter as set by the API
 * \param pca Counter array that holds the local counter for this TM
 * \param x   Value to add to this local counter
 */
void StatsAddUI64(ThreadVars *tv, uint16_t id, uint64_t x)
{
    StatsPrivateThreadContext *pca = &tv->perf_private_ctx;
#if defined (UNITTESTS) || defined (FUZZ)
    if (pca->initialized == 0)
        return;
#endif
#ifdef DEBUG
    BUG_ON ((id < 1) || (id > pca->size));
#endif
    pca->head[id].value += x;
    pca->head[id].updates++;
    return;
}

/**
 * \brief Increments the local counter
 *
 * \param id  Index of the counter in the counter array
 * \param pca Counter array that holds the local counters for this TM
 */
void StatsIncr(ThreadVars *tv, uint16_t id)
{
    StatsPrivateThreadContext *pca = &tv->perf_private_ctx;
#if defined (UNITTESTS) || defined (FUZZ)
    if (pca->initialized == 0)
        return;
#endif
#ifdef DEBUG
    BUG_ON ((id < 1) || (id > pca->size));
#endif
    pca->head[id].value++;
    pca->head[id].updates++;
    return;
}

/**
 * \brief Decrements the local counter
 *
 * \param id  Index of the counter in the counter array
 * \param pca Counter array that holds the local counters for this TM
 */
void StatsDecr(ThreadVars *tv, uint16_t id)
{
    StatsPrivateThreadContext *pca = &tv->perf_private_ctx;
#if defined(UNITTESTS) || defined(FUZZ)
    if (pca->initialized == 0)
        return;
#endif
#ifdef DEBUG
    BUG_ON((id < 1) || (id > pca->size));
#endif
    pca->head[id].value--;
    pca->head[id].updates++;
    return;
}

/**
 * \brief Sets a value of type double to the local counter
 *
 * \param id  Index of the local counter in the counter array
 * \param pca Pointer to the StatsPrivateThreadContext
 * \param x   The value to set for the counter
 */
void StatsSetUI64(ThreadVars *tv, uint16_t id, uint64_t x)
{
    StatsPrivateThreadContext *pca = &tv->perf_private_ctx;
#if defined (UNITTESTS) || defined (FUZZ)
    if (pca->initialized == 0)
        return;
#endif
#ifdef DEBUG
    BUG_ON ((id < 1) || (id > pca->size));
#endif

    if ((pca->head[id].pc->type == STATS_TYPE_MAXIMUM) && ((int64_t)x > pca->head[id].value)) {
        pca->head[id].value = x;
    } else if (pca->head[id].pc->type == STATS_TYPE_NORMAL) {
        pca->head[id].value = x;
    }

    pca->head[id].updates++;

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
 * \brief Initializes stats context
 */
static void StatsInitCtxPreOutput(void)
{
    SCEnter();
    ConfNode *stats = GetConfig();
    if (stats != NULL) {
        const char *enabled = ConfNodeLookupChildValue(stats, "enabled");
        if (enabled != NULL && ConfValIsFalse(enabled)) {
            stats_enabled = false;
            SCLogDebug("Stats module has been disabled");
            SCReturn;
        }
        /* warn if we are using legacy config to enable stats */
        ConfNode *gstats = ConfGetNode("stats");
        if (gstats == NULL) {
            SCLogWarning(SC_ERR_STATS_LOG_GENERIC, "global stats config is missing. "
                    "Stats enabled through legacy stats.log. "
                    "See %s/configuration/suricata-yaml.html#stats", GetDocURL());
        }

        const char *interval = ConfNodeLookupChildValue(stats, "interval");
        if (interval != NULL)
            if (StringParseUint32(&stats_tts, 10, 0, interval) < 0) {
                SCLogWarning(SC_ERR_INVALID_VALUE, "Invalid value for "
                             "interval: \"%s\". Resetting to %d.", interval,
                             STATS_MGMTT_TTS);
                stats_tts = STATS_MGMTT_TTS;
            }

        int b;
        int ret = ConfGetChildValueBool(stats, "decoder-events", &b);
        if (ret) {
            stats_decoder_events = (b == 1);
        }
        ret = ConfGetChildValueBool(stats, "stream-events", &b);
        if (ret) {
            stats_stream_events = (b == 1);
        }

        const char *prefix = NULL;
        if (ConfGet("stats.decoder-events-prefix", &prefix) != 1) {
            prefix = "decoder.event";
        }
        stats_decoder_events_prefix = prefix;
    }
    SCReturn;
}

static void StatsInitCtxPostOutput(void)
{
    SCEnter();
    /* Store the engine start time */
    time(&stats_start_time);

    /* init the lock used by StatsThreadStore */
    if (SCMutexInit(&stats_ctx->sts_lock, NULL) != 0) {
        FatalError(SC_ERR_FATAL, "error initializing sts mutex");
    }

    if (stats_enabled && !OutputStatsLoggersRegistered()) {
        stats_loggers_active = 0;

        /* if the unix command socket is enabled we do the background
         * stats sync just in case someone runs 'dump-counters' */
        if (!ConfUnixSocketIsEnable()) {
            SCLogWarning(SC_WARN_NO_STATS_LOGGERS, "stats are enabled but no loggers are active");
            stats_enabled = false;
            SCReturn;
        }
    }

    SCReturn;
}

/**
 * \brief Releases the resources alloted to the output context of the
 *        Stats API
 */
static void StatsReleaseCtx(void)
{
    if (stats_ctx == NULL) {
        SCLogDebug("Counter module has been disabled");
        return;
    }

    StatsThreadStore *sts = NULL;
    StatsThreadStore *temp = NULL;
    sts = stats_ctx->sts;

    while (sts != NULL) {
        if (sts->head != NULL)
            SCFree(sts->head);

        temp = sts->next;
        SCFree(sts);
        sts = temp;
    }

    if (stats_ctx->counters_id_hash != NULL) {
        HashTableFree(stats_ctx->counters_id_hash);
        stats_ctx->counters_id_hash = NULL;
        counters_global_id = 0;
    }

    StatsPublicThreadContextCleanup(&stats_ctx->global_counter_ctx);
    SCFree(stats_ctx);
    stats_ctx = NULL;

    SCMutexLock(&stats_table_mutex);
    /* free stats table */
    if (stats_table.tstats != NULL) {
        SCFree(stats_table.tstats);
        stats_table.tstats = NULL;
    }

    if (stats_table.stats != NULL) {
        SCFree(stats_table.stats);
        stats_table.stats = NULL;
    }
    memset(&stats_table, 0, sizeof(stats_table));
    SCMutexUnlock(&stats_table_mutex);

    return;
}

/**
 * \brief management thread. This thread is responsible for writing the stats
 *
 * \param arg thread var
 *
 * \retval NULL This is the value that is always returned
 */
static void *StatsMgmtThread(void *arg)
{
    ThreadVars *tv_local = (ThreadVars *)arg;

    SCSetThreadName(tv_local->name);

    if (tv_local->thread_setup_flags != 0)
        TmThreadSetupOptions(tv_local);

    /* Set the threads capability */
    tv_local->cap_flags = 0;
    SCDropCaps(tv_local);

    if (stats_ctx == NULL) {
        SCLogError(SC_ERR_STATS_NOT_INIT, "Stats API not init"
                   "StatsInitCounterApi() has to be called first");
        TmThreadsSetFlag(tv_local, THV_CLOSED | THV_RUNNING_DONE);
        return NULL;
    }

    TmModule *tm = &tmm_modules[TMM_STATSLOGGER];
    BUG_ON(tm->ThreadInit == NULL);
    int r = tm->ThreadInit(tv_local, NULL, &stats_thread_data);
    if (r != 0 || stats_thread_data == NULL) {
        SCLogError(SC_ERR_THREAD_INIT, "Stats API "
                   "ThreadInit failed");
        TmThreadsSetFlag(tv_local, THV_CLOSED | THV_RUNNING_DONE);
        return NULL;
    }
    SCLogDebug("stats_thread_data %p", &stats_thread_data);

    TmThreadsSetFlag(tv_local, THV_INIT_DONE);
    while (1) {
        if (TmThreadsCheckFlag(tv_local, THV_PAUSE)) {
            TmThreadsSetFlag(tv_local, THV_PAUSED);
            TmThreadTestThreadUnPaused(tv_local);
            TmThreadsUnsetFlag(tv_local, THV_PAUSED);
        }

        struct timeval cur_timev;
        gettimeofday(&cur_timev, NULL);
        struct timespec cond_time = FROM_TIMEVAL(cur_timev);
        cond_time.tv_sec += (stats_tts);

        /* wait for the set time, or until we are woken up by
         * the shutdown procedure */
        SCCtrlMutexLock(tv_local->ctrl_mutex);
        SCCtrlCondTimedwait(tv_local->ctrl_cond, tv_local->ctrl_mutex, &cond_time);
        SCCtrlMutexUnlock(tv_local->ctrl_mutex);

        SCMutexLock(&stats_table_mutex);
        StatsOutput(tv_local);
        SCMutexUnlock(&stats_table_mutex);

        if (TmThreadsCheckFlag(tv_local, THV_KILL)) {
            break;
        }
    }

    TmThreadsSetFlag(tv_local, THV_RUNNING_DONE);
    TmThreadWaitForFlag(tv_local, THV_DEINIT);

    r = tm->ThreadDeinit(tv_local, stats_thread_data);
    if (r != TM_ECODE_OK) {
        SCLogError(SC_ERR_THREAD_DEINIT, "Stats Counter API "
                   "ThreadDeinit failed");
    }

    TmThreadsSetFlag(tv_local, THV_CLOSED);
    return NULL;
}

/**
 * \brief Wake up thread.  This thread wakes up every TTS(time to sleep) seconds
 *        and sets the flag for every ThreadVars' StatsPublicThreadContext
 *
 * \param arg is NULL always
 *
 * \retval NULL This is the value that is always returned
 */
static void *StatsWakeupThread(void *arg)
{
    ThreadVars *tv_local = (ThreadVars *)arg;

    SCSetThreadName(tv_local->name);

    if (tv_local->thread_setup_flags != 0)
        TmThreadSetupOptions(tv_local);

    /* Set the threads capability */
    tv_local->cap_flags = 0;
    SCDropCaps(tv_local);

    if (stats_ctx == NULL) {
        SCLogError(SC_ERR_STATS_NOT_INIT, "Stats API not init"
                   "StatsInitCounterApi() has to be called first");
        TmThreadsSetFlag(tv_local, THV_CLOSED | THV_RUNNING_DONE);
        return NULL;
    }

    TmThreadsSetFlag(tv_local, THV_INIT_DONE);
    while (1) {
        if (TmThreadsCheckFlag(tv_local, THV_PAUSE)) {
            TmThreadsSetFlag(tv_local, THV_PAUSED);
            TmThreadTestThreadUnPaused(tv_local);
            TmThreadsUnsetFlag(tv_local, THV_PAUSED);
        }

        struct timeval cur_timev;
        gettimeofday(&cur_timev, NULL);
        struct timespec cond_time = FROM_TIMEVAL(cur_timev);
        cond_time.tv_sec += STATS_WUT_TTS;

        /* wait for the set time, or until we are woken up by
         * the shutdown procedure */
        SCCtrlMutexLock(tv_local->ctrl_mutex);
        SCCtrlCondTimedwait(tv_local->ctrl_cond, tv_local->ctrl_mutex, &cond_time);
        SCCtrlMutexUnlock(tv_local->ctrl_mutex);

        SCMutexLock(&tv_root_lock);
        ThreadVars *tv = tv_root[TVT_PPT];
        while (tv != NULL) {
            if (tv->perf_public_ctx.head == NULL) {
                tv = tv->next;
                continue;
            }

            /* assuming the assignment of an int to be atomic, and even if it's
             * not, it should be okay */
            tv->perf_public_ctx.perf_flag = 1;

            if (tv->inq != NULL) {
                PacketQueue *q = tv->inq->pq;
                SCCondSignal(&q->cond_q);
            }

            tv = tv->next;
        }

        /* mgt threads for flow manager */
        tv = tv_root[TVT_MGMT];
        while (tv != NULL) {
            if (tv->perf_public_ctx.head == NULL) {
                tv = tv->next;
                continue;
            }

            /* assuming the assignment of an int to be atomic, and even if it's
             * not, it should be okay */
            tv->perf_public_ctx.perf_flag = 1;

            tv = tv->next;
        }
        SCMutexUnlock(&tv_root_lock);

        if (TmThreadsCheckFlag(tv_local, THV_KILL)) {
            break;
        }
    }

    TmThreadsSetFlag(tv_local, THV_RUNNING_DONE);
    TmThreadWaitForFlag(tv_local, THV_DEINIT);
    TmThreadsSetFlag(tv_local, THV_CLOSED);
    return NULL;
}

/**
 * \brief Releases a counter
 *
 * \param pc Pointer to the StatsCounter to be freed
 */
static void StatsReleaseCounter(StatsCounter *pc)
{
    if (pc != NULL) {
        SCFree(pc);
    }

    return;
}

/**
 * \brief Registers a counter.
 *
 * \param name    Name of the counter, to be registered
 * \param tm_name  Thread module to which this counter belongs
 * \param pctx     StatsPublicThreadContext for this tm-tv instance
 * \param type_q   Qualifier describing the type of counter to be registered
 *
 * \retval the counter id for the newly registered counter, or the already
 *         present counter on success
 * \retval 0 on failure
 */
static uint16_t StatsRegisterQualifiedCounter(const char *name, const char *tm_name,
                                              StatsPublicThreadContext *pctx,
                                              int type_q, uint64_t (*Func)(void))
{
    StatsCounter **head = &pctx->head;
    StatsCounter *temp = NULL;
    StatsCounter *prev = NULL;
    StatsCounter *pc = NULL;

    if (name == NULL || pctx == NULL) {
        SCLogDebug("Counter name, StatsPublicThreadContext NULL");
        return 0;
    }

    temp = prev = *head;
    while (temp != NULL) {
        prev = temp;

        if (strcmp(name, temp->name) == 0) {
            break;
        }

        temp = temp->next;
    }

    /* We already have a counter registered by this name */
    if (temp != NULL)
        return(temp->id);

    /* if we reach this point we don't have a counter registered by this name */
    if ( (pc = SCMalloc(sizeof(StatsCounter))) == NULL)
        return 0;
    memset(pc, 0, sizeof(StatsCounter));

    /* assign a unique id to this StatsCounter.  The id is local to this
     * thread context.  Please note that the id start from 1, and not 0 */
    pc->id = ++(pctx->curr_id);
    pc->name = name;
    pc->type = type_q;
    pc->Func = Func;

    /* we now add the counter to the list */
    if (prev == NULL)
        *head = pc;
    else
        prev->next = pc;

    return pc->id;
}

/**
 * \brief Copies the StatsCounter value from the local counter present in the
 *        StatsPrivateThreadContext to its corresponding global counterpart.  Used
 *        internally by StatsUpdateCounterArray()
 *
 * \param pcae     Pointer to the StatsPrivateThreadContext which holds the local
 *                 versions of the counters
 */
static void StatsCopyCounterValue(StatsLocalCounter *pcae)
{
    StatsCounter *pc = pcae->pc;

    pc->value = pcae->value;
    pc->updates = pcae->updates;
    return;
}

/**
 * \brief The output interface for the Stats API
 */
static int StatsOutput(ThreadVars *tv)
{
    const StatsThreadStore *sts = NULL;
    const StatsCounter *pc = NULL;
    void *td = stats_thread_data;

    if (counters_global_id == 0)
        return -1;

    if (stats_table.nstats == 0) {
        StatsThreadRegister("Global", &stats_ctx->global_counter_ctx);

        uint32_t nstats = counters_global_id;

        stats_table.nstats = nstats;
        stats_table.stats = SCCalloc(stats_table.nstats, sizeof(StatsRecord));
        if (stats_table.stats == NULL) {
            stats_table.nstats = 0;
            SCLogError(SC_ERR_MEM_ALLOC, "could not alloc memory for stats");
            return -1;
        }

        stats_table.ntstats = stats_ctx->sts_cnt;
        uint32_t array_size = stats_table.nstats * sizeof(StatsRecord);
        stats_table.tstats = SCCalloc(stats_table.ntstats, array_size);
        if (stats_table.tstats == NULL) {
            stats_table.ntstats = 0;
            SCLogError(SC_ERR_MEM_ALLOC, "could not alloc memory for stats");
            return -1;
        }

        stats_table.start_time = stats_start_time;
    }

    const uint16_t max_id = counters_global_id;
    if (max_id == 0)
        return -1;

    /** temporary local table to merge the per thread counters,
     *  especially needed for the average counters */
    struct CountersMergeTable {
        int type;
        int64_t value;
        uint64_t updates;
    } merge_table[max_id];
    memset(&merge_table, 0x00,
           max_id * sizeof(struct CountersMergeTable));

    int thread = stats_ctx->sts_cnt - 1;
    StatsRecord *table = stats_table.stats;

    /* Loop through the thread counter stores. The global counters
     * are in a separate store inside this list. */
    sts = stats_ctx->sts;
    SCLogDebug("sts %p", sts);
    while (sts != NULL) {
        BUG_ON(thread < 0);

        SCLogDebug("Thread %d %s ctx %p", thread, sts->name, sts->ctx);

        /* temporary table for quickly storing the counters for this
         * thread store, so that we can post process them outside
         * of the thread store lock */
        struct CountersMergeTable thread_table[max_id];
        memset(&thread_table, 0x00,
                max_id * sizeof(struct CountersMergeTable));

        SCMutexLock(&sts->ctx->m);
        pc = sts->ctx->head;
        while (pc != NULL) {
            SCLogDebug("Counter %s (%u:%u) value %"PRIu64,
                    pc->name, pc->id, pc->gid, pc->value);

            thread_table[pc->gid].type = pc->type;
            switch (pc->type) {
                case STATS_TYPE_FUNC:
                    if (pc->Func != NULL)
                        thread_table[pc->gid].value = pc->Func();
                    break;
                case STATS_TYPE_AVERAGE:
                default:
                    thread_table[pc->gid].value = pc->value;
                    break;
            }
            thread_table[pc->gid].updates = pc->updates;
            table[pc->gid].name = pc->name;

            pc = pc->next;
        }
        SCMutexUnlock(&sts->ctx->m);

        /* update merge table */
        for (uint16_t c = 0; c < max_id; c++) {
            struct CountersMergeTable *e = &thread_table[c];
            /* thread only sets type if it has a counter
             * of this type. */
            if (e->type == 0)
                continue;

            switch (e->type) {
                case STATS_TYPE_MAXIMUM:
                    if (e->value > merge_table[c].value)
                        merge_table[c].value = e->value;
                    break;
                case STATS_TYPE_FUNC:
                    merge_table[c].value = e->value;
                    break;
                case STATS_TYPE_AVERAGE:
                default:
                    merge_table[c].value += e->value;
                    break;
            }
            merge_table[c].updates += e->updates;
            merge_table[c].type = e->type;
        }

        /* update per thread stats table */
        for (uint16_t c = 0; c < max_id; c++) {
            struct CountersMergeTable *e = &thread_table[c];
            /* thread only sets type if it has a counter
             * of this type. */
            if (e->type == 0)
                continue;

            uint32_t offset = (thread * stats_table.nstats) + c;
            StatsRecord *r = &stats_table.tstats[offset];
            /* xfer previous value to pvalue and reset value */
            r->pvalue = r->value;
            r->value = 0;
            r->name = table[c].name;
            r->tm_name = sts->name;

            switch (e->type) {
                case STATS_TYPE_AVERAGE:
                    if (e->value > 0 && e->updates > 0) {
                        r->value = (uint64_t)(e->value / e->updates);
                    }
                    break;
                default:
                    r->value = e->value;
                    break;
            }
        }

        sts = sts->next;
        thread--;
    }

    /* transfer 'merge table' to final stats table */
    for (uint16_t x = 0; x < max_id; x++) {
        /* xfer previous value to pvalue and reset value */
        table[x].pvalue = table[x].value;
        table[x].value = 0;
        table[x].tm_name = "Total";

        struct CountersMergeTable *m = &merge_table[x];
        switch (m->type) {
            case STATS_TYPE_MAXIMUM:
                if (m->value > table[x].value)
                    table[x].value = m->value;
                break;
            case STATS_TYPE_AVERAGE:
                if (m->value > 0 && m->updates > 0) {
                    table[x].value = (uint64_t)(m->value / m->updates);
                }
                break;
            default:
                table[x].value += m->value;
                break;
        }
    }

    /* invoke logger(s) */
    if (stats_loggers_active) {
        OutputStatsLog(tv, td, &stats_table);
    }
    return 1;
}

#ifdef BUILD_UNIX_SOCKET
/** \brief callback for getting stats into unix socket
 */
TmEcode StatsOutputCounterSocket(json_t *cmd,
                               json_t *answer, void *data)
{
    json_t *message = NULL;
    TmEcode r = TM_ECODE_OK;

    if (!stats_enabled) {
        r = TM_ECODE_FAILED;
        message = json_string("stats are disabled in the config");
    } else {
        SCMutexLock(&stats_table_mutex);
        if (stats_table.start_time == 0) {
            r = TM_ECODE_FAILED;
            message = json_string("stats not yet synchronized");
        } else {
            message = StatsToJSON(&stats_table, JSON_STATS_TOTALS|JSON_STATS_THREADS);
        }
        SCMutexUnlock(&stats_table_mutex);
    }
    json_object_set_new(answer, "message", message);
    return r;
}
#endif /* BUILD_UNIX_SOCKET */

static void StatsLogSummary(void)
{
    if (!stats_enabled) {
        return;
    }
    uint64_t alerts = 0;
    SCMutexLock(&stats_table_mutex);
    if (stats_table.start_time != 0) {
        const StatsTable *st = &stats_table;
        for (uint32_t u = 0; u < st->nstats; u++) {
            const char *name = st->stats[u].name;
            if (name == NULL || strcmp(name, "detect.alert") != 0)
                continue;
            alerts = st->stats[u].value;
            break;
        }
    }
    SCMutexUnlock(&stats_table_mutex);
    SCLogInfo("Alerts: %"PRIu64, alerts);
}

/**
 * \brief Initializes the perf counter api.  Things are hard coded currently.
 *        More work to be done when we implement multiple interfaces
 */
void StatsInit(void)
{
    BUG_ON(stats_ctx != NULL);
    if ( (stats_ctx = SCMalloc(sizeof(StatsGlobalContext))) == NULL) {
        FatalError(SC_ERR_FATAL,
                   "Fatal error encountered in StatsInitCtx. Exiting...");
    }
    memset(stats_ctx, 0, sizeof(StatsGlobalContext));

    StatsPublicThreadContextInit(&stats_ctx->global_counter_ctx);
}

void StatsSetupPostConfigPreOutput(void)
{
    StatsInitCtxPreOutput();
}

void StatsSetupPostConfigPostOutput(void)
{
    StatsInitCtxPostOutput();
}


/**
 * \brief Spawns the wakeup, and the management thread used by the stats api
 *
 *  The threads use the condition variable in the thread vars to control
 *  their wait loops to make sure the main thread can quickly kill them.
 */
void StatsSpawnThreads(void)
{
    SCEnter();

    if (!stats_enabled) {
        SCReturn;
    }

    ThreadVars *tv_wakeup = NULL;
    ThreadVars *tv_mgmt = NULL;

    /* spawn the stats wakeup thread */
    tv_wakeup = TmThreadCreateMgmtThread(thread_name_counter_wakeup,
                                         StatsWakeupThread, 1);
    if (tv_wakeup == NULL) {
        FatalError(SC_ERR_FATAL, "TmThreadCreateMgmtThread "
                   "failed");
    }

    if (TmThreadSpawn(tv_wakeup) != 0) {
        FatalError(SC_ERR_FATAL, "TmThreadSpawn failed for "
                   "StatsWakeupThread");
    }

    /* spawn the stats mgmt thread */
    tv_mgmt = TmThreadCreateMgmtThread(thread_name_counter_stats,
                                       StatsMgmtThread, 1);
    if (tv_mgmt == NULL) {
                   FatalError(SC_ERR_FATAL, "TmThreadCreateMgmtThread failed");
    }

    if (TmThreadSpawn(tv_mgmt) != 0) {
        FatalError(SC_ERR_FATAL, "TmThreadSpawn failed for "
                   "StatsWakeupThread");
    }

    SCReturn;
}

/**
 * \brief Registers a normal, unqualified counter
 *
 * \param name Name of the counter, to be registered
 * \param tv    Pointer to the ThreadVars instance for which the counter would
 *              be registered
 *
 * \retval id Counter id for the newly registered counter, or the already
 *            present counter
 */
uint16_t StatsRegisterCounter(const char *name, struct ThreadVars_ *tv)
{
    uint16_t id = StatsRegisterQualifiedCounter(name,
            (tv->thread_group_name != NULL) ? tv->thread_group_name : tv->printable_name,
            &tv->perf_public_ctx,
            STATS_TYPE_NORMAL, NULL);
    return id;
}

/**
 * \brief Registers a counter, whose value holds the average of all the values
 *        assigned to it.
 *
 * \param name Name of the counter, to be registered
 * \param tv    Pointer to the ThreadVars instance for which the counter would
 *              be registered
 *
 * \retval id Counter id for the newly registered counter, or the already
 *            present counter
 */
uint16_t StatsRegisterAvgCounter(const char *name, struct ThreadVars_ *tv)
{
    uint16_t id = StatsRegisterQualifiedCounter(name,
            (tv->thread_group_name != NULL) ? tv->thread_group_name : tv->printable_name,
            &tv->perf_public_ctx,
            STATS_TYPE_AVERAGE, NULL);
    return id;
}

/**
 * \brief Registers a counter, whose value holds the maximum of all the values
 *        assigned to it.
 *
 * \param name Name of the counter, to be registered
 * \param tv    Pointer to the ThreadVars instance for which the counter would
 *              be registered
 *
 * \retval the counter id for the newly registered counter, or the already
 *         present counter
 */
uint16_t StatsRegisterMaxCounter(const char *name, struct ThreadVars_ *tv)
{
    uint16_t id = StatsRegisterQualifiedCounter(name,
            (tv->thread_group_name != NULL) ? tv->thread_group_name : tv->printable_name,
            &tv->perf_public_ctx,
            STATS_TYPE_MAXIMUM, NULL);
    return id;
}

/**
 * \brief Registers a counter, which represents a global value
 *
 * \param name Name of the counter, to be registered
 * \param Func  Function Pointer returning a uint64_t
 *
 * \retval id Counter id for the newly registered counter, or the already
 *            present counter
 */
uint16_t StatsRegisterGlobalCounter(const char *name, uint64_t (*Func)(void))
{
#if defined (UNITTESTS) || defined (FUZZ)
    if (stats_ctx == NULL)
        return 0;
#else
    BUG_ON(stats_ctx == NULL);
#endif
    uint16_t id = StatsRegisterQualifiedCounter(name, NULL,
            &(stats_ctx->global_counter_ctx),
            STATS_TYPE_FUNC,
            Func);
    return id;
}

typedef struct CountersIdType_ {
    uint16_t id;
    const char *string;
} CountersIdType;

static uint32_t CountersIdHashFunc(HashTable *ht, void *data, uint16_t datalen)
{
    CountersIdType *t = (CountersIdType *)data;
    uint32_t hash = 0;
    int len = strlen(t->string);

    for (int i = 0; i < len; i++)
        hash += u8_tolower((unsigned char)t->string[i]);

    hash = hash % ht->array_size;
    return hash;
}

static char CountersIdHashCompareFunc(void *data1, uint16_t datalen1,
                               void *data2, uint16_t datalen2)
{
    CountersIdType *t1 = (CountersIdType *)data1;
    CountersIdType *t2 = (CountersIdType *)data2;
    int len1 = 0;
    int len2 = 0;

    if (t1 == NULL || t2 == NULL)
        return 0;

    if (t1->string == NULL || t2->string == NULL)
        return 0;

    len1 = strlen(t1->string);
    len2 = strlen(t2->string);

    if (len1 == len2 && memcmp(t1->string, t2->string, len1) == 0) {
        return 1;
    }

    return 0;
}

static void CountersIdHashFreeFunc(void *data)
{
    SCFree(data);
}


/** \internal
 *  \brief Adds a TM to the clubbed TM table.  Multiple instances of the same TM
 *         are stacked together in a PCTMI container.
 *
 *  \param tm_name Name of the tm to be added to the table
 *  \param pctx    StatsPublicThreadContext associated with the TM tm_name
 *
 *  \retval 1 on success, 0 on failure
 */
static int StatsThreadRegister(const char *thread_name, StatsPublicThreadContext *pctx)
{
    if (stats_ctx == NULL) {
        SCLogDebug("Counter module has been disabled");
        return 0;
    }

    if (thread_name == NULL || pctx == NULL) {
        SCLogDebug("supplied argument(s) to StatsThreadRegister NULL");
        return 0;
    }

    SCMutexLock(&stats_ctx->sts_lock);
    if (stats_ctx->counters_id_hash == NULL) {
        stats_ctx->counters_id_hash = HashTableInit(256, CountersIdHashFunc,
                                                              CountersIdHashCompareFunc,
                                                              CountersIdHashFreeFunc);
        BUG_ON(stats_ctx->counters_id_hash == NULL);
    }
    StatsCounter *pc = pctx->head;
    while (pc != NULL) {
        CountersIdType t = { 0, pc->name }, *id = NULL;
        id = HashTableLookup(stats_ctx->counters_id_hash, &t, sizeof(t));
        if (id == NULL) {
            id = SCCalloc(1, sizeof(*id));
            BUG_ON(id == NULL);
            id->id = counters_global_id++;
            id->string = pc->name;
            BUG_ON(HashTableAdd(stats_ctx->counters_id_hash, id, sizeof(*id)) < 0);
        }
        pc->gid = id->id;
        pc = pc->next;
    }


    StatsThreadStore *temp = NULL;
    if ( (temp = SCMalloc(sizeof(StatsThreadStore))) == NULL) {
        SCMutexUnlock(&stats_ctx->sts_lock);
        return 0;
    }
    memset(temp, 0, sizeof(StatsThreadStore));

    temp->ctx = pctx;
    temp->name = thread_name;

    temp->next = stats_ctx->sts;
    stats_ctx->sts = temp;
    stats_ctx->sts_cnt++;
    SCLogDebug("stats_ctx->sts %p", stats_ctx->sts);

    SCMutexUnlock(&stats_ctx->sts_lock);
    return 1;
}

/** \internal
 *  \brief Returns a counter array for counters in this id range(s_id - e_id)
 *
 *  \param s_id Counter id of the first counter to be added to the array
 *  \param e_id Counter id of the last counter to be added to the array
 *  \param pctx Pointer to the tv's StatsPublicThreadContext
 *
 *  \retval a counter-array in this(s_id-e_id) range for this TM instance
 */
static int StatsGetCounterArrayRange(uint16_t s_id, uint16_t e_id,
                                      StatsPublicThreadContext *pctx,
                                      StatsPrivateThreadContext *pca)
{
    StatsCounter *pc = NULL;
    uint32_t i = 0;

    if (pctx == NULL || pca == NULL) {
        SCLogDebug("pctx/pca is NULL");
        return -1;
    }

    if (s_id < 1 || e_id < 1 || s_id > e_id) {
        SCLogDebug("error with the counter ids");
        return -1;
    }

    if (e_id > pctx->curr_id) {
        SCLogDebug("end id is greater than the max id for this tv");
        return -1;
    }

    if ( (pca->head = SCMalloc(sizeof(StatsLocalCounter) * (e_id - s_id  + 2))) == NULL) {
        return -1;
    }
    memset(pca->head, 0, sizeof(StatsLocalCounter) * (e_id - s_id  + 2));

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

    pca->initialized = 1;
    return 0;
}

/** \internal
 *  \brief Returns a counter array for all counters registered for this tm
 *         instance
 *
 *  \param pctx Pointer to the tv's StatsPublicThreadContext
 *
 *  \retval pca Pointer to a counter-array for all counter of this tm instance
 *              on success; NULL on failure
 */
static int StatsGetAllCountersArray(StatsPublicThreadContext *pctx, StatsPrivateThreadContext *private)
{
    if (pctx == NULL || private == NULL)
        return -1;

    return StatsGetCounterArrayRange(1, pctx->curr_id, pctx, private);
}


int StatsSetupPrivate(ThreadVars *tv)
{
    StatsGetAllCountersArray(&(tv)->perf_public_ctx, &(tv)->perf_private_ctx);

    StatsThreadRegister(tv->printable_name ? tv->printable_name : tv->name,
        &(tv)->perf_public_ctx);
    return 0;
}

/**
 * \brief the private stats store with the public stats store
 *
 * \param pca      Pointer to the StatsPrivateThreadContext
 * \param pctx     Pointer the the tv's StatsPublicThreadContext
 *
 * \retval  1 on success
 * \retval -1 on error
 */
int StatsUpdateCounterArray(StatsPrivateThreadContext *pca, StatsPublicThreadContext *pctx)
{

    if (pca == NULL || pctx == NULL) {
        SCLogDebug("pca or pctx is NULL inside StatsUpdateCounterArray");
        return -1;
    }

    SCMutexLock(&pctx->m);
    StatsLocalCounter *pcae = pca->head;
    for (uint32_t i = 1; i <= pca->size; i++) {
        StatsCopyCounterValue(&pcae[i]);
    }
    SCMutexUnlock(&pctx->m);

    pctx->perf_flag = 0;
    return 1;
}

/**
 * \brief Get the value of the local copy of the counter that hold this id.
 *
 * \param tv threadvars
 * \param id The counter id.
 *
 * \retval  0 on success.
 * \retval -1 on error.
 */
uint64_t StatsGetLocalCounterValue(ThreadVars *tv, uint16_t id)
{
    StatsPrivateThreadContext *pca = &tv->perf_private_ctx;
#ifdef DEBUG
    BUG_ON ((id < 1) || (id > pca->size));
#endif
    return pca->head[id].value;
}

/**
 * \brief Releases the resources alloted by the Stats API
 */
void StatsReleaseResources()
{
    StatsLogSummary();
    StatsReleaseCtx();
}

/**
 * \brief Releases counters
 *
 * \param head Pointer to the head of the list of perf counters that have to
 *             be freed
 */
void StatsReleaseCounters(StatsCounter *head)
{
    StatsCounter *pc = NULL;

    while (head != NULL) {
        pc = head;
        head = head->next;
        StatsReleaseCounter(pc);
    }
}

/** \internal
 *  \brief Releases the StatsPrivateThreadContext allocated by the user,
 *         for storing and updating local counter values
 *
 * \param pca Pointer to the StatsPrivateThreadContext
 */
static void StatsReleasePrivateThreadContext(StatsPrivateThreadContext *pca)
{
    if (pca != NULL) {
        if (pca->head != NULL) {
            SCFree(pca->head);
            pca->head = NULL;
            pca->size = 0;
        }
        pca->initialized = 0;
    }
}

void StatsThreadCleanup(ThreadVars *tv)
{
    StatsPublicThreadContextCleanup(&tv->perf_public_ctx);
    StatsReleasePrivateThreadContext(&tv->perf_private_ctx);
}

/*----------------------------------Unit_Tests--------------------------------*/

#ifdef UNITTESTS
/** \internal
 * \brief Registers a normal, unqualified counter
 *
 * \param name   Name of the counter, to be registered
 * \param tm_name Name of the engine module under which the counter has to be
 *                registered
 * \param type    Datatype of this counter variable
 * \param pctx    StatsPublicThreadContext corresponding to the tm_name key under which the
 *                key has to be registered
 *
 * \retval id Counter id for the newly registered counter, or the already
 *            present counter
 */
static uint16_t RegisterCounter(const char *name, const char *tm_name,
                               StatsPublicThreadContext *pctx)
{
    uint16_t id = StatsRegisterQualifiedCounter(name, tm_name, pctx,
                                                STATS_TYPE_NORMAL, NULL);
    return id;
}

static int StatsTestCounterReg02(void)
{
    StatsPublicThreadContext pctx;

    memset(&pctx, 0, sizeof(StatsPublicThreadContext));

    return RegisterCounter(NULL, NULL, &pctx) == 0;
}

static int StatsTestCounterReg03(void)
{
    StatsPublicThreadContext pctx;
    int result;

    memset(&pctx, 0, sizeof(StatsPublicThreadContext));

    result = RegisterCounter("t1", "c1", &pctx);

    FAIL_IF_NOT(result);

    StatsReleaseCounters(pctx.head);

    PASS;
}

static int StatsTestCounterReg04(void)
{
    StatsPublicThreadContext pctx;
    int result;

    memset(&pctx, 0, sizeof(StatsPublicThreadContext));

    RegisterCounter("t1", "c1", &pctx);
    RegisterCounter("t2", "c2", &pctx);
    RegisterCounter("t3", "c3", &pctx);

    result = RegisterCounter("t1", "c1", &pctx);

    FAIL_IF_NOT(result);

    StatsReleaseCounters(pctx.head);

    PASS;
}

static int StatsTestGetCntArray05(void)
{
    ThreadVars tv;
    int id;

    memset(&tv, 0, sizeof(ThreadVars));

    id = RegisterCounter("t1", "c1", &tv.perf_public_ctx);
    FAIL_IF(id != 1);

    int r = StatsGetAllCountersArray(NULL, &tv.perf_private_ctx);
    FAIL_IF_NOT(r == -1);
    PASS;
}

static int StatsTestGetCntArray06(void)
{
    ThreadVars tv;
    int id;

    memset(&tv, 0, sizeof(ThreadVars));

    id = RegisterCounter("t1", "c1", &tv.perf_public_ctx);
    FAIL_IF(id != 1);

    int r = StatsGetAllCountersArray(&tv.perf_public_ctx, &tv.perf_private_ctx);
    FAIL_IF_NOT(r == 0);

    StatsReleaseCounters(tv.perf_public_ctx.head);
    StatsReleasePrivateThreadContext(&tv.perf_private_ctx);

    PASS;
}

static int StatsTestCntArraySize07(void)
{
    ThreadVars tv;
    StatsPrivateThreadContext *pca = NULL;

    memset(&tv, 0, sizeof(ThreadVars));

    //pca = (StatsPrivateThreadContext *)&tv.perf_private_ctx;

    RegisterCounter("t1", "c1", &tv.perf_public_ctx);
    RegisterCounter("t2", "c2", &tv.perf_public_ctx);

    StatsGetAllCountersArray(&tv.perf_public_ctx, &tv.perf_private_ctx);
    pca = &tv.perf_private_ctx;

    StatsIncr(&tv, 1);
    StatsIncr(&tv, 2);

    FAIL_IF_NOT(pca->size == 2);

    StatsReleaseCounters(tv.perf_public_ctx.head);
    StatsReleasePrivateThreadContext(pca);

    PASS;
}

static int StatsTestUpdateCounter08(void)
{
    ThreadVars tv;
    StatsPrivateThreadContext *pca = NULL;
    int id;

    memset(&tv, 0, sizeof(ThreadVars));

    id = RegisterCounter("t1", "c1", &tv.perf_public_ctx);

    StatsGetAllCountersArray(&tv.perf_public_ctx, &tv.perf_private_ctx);
    pca = &tv.perf_private_ctx;

    StatsIncr(&tv, id);
    StatsAddUI64(&tv, id, 100);

    FAIL_IF_NOT(pca->head[id].value == 101);

    StatsReleaseCounters(tv.perf_public_ctx.head);
    StatsReleasePrivateThreadContext(pca);

    PASS;
}

static int StatsTestUpdateCounter09(void)
{
    ThreadVars tv;
    StatsPrivateThreadContext *pca = NULL;
    uint16_t id1, id2;

    memset(&tv, 0, sizeof(ThreadVars));

    id1 = RegisterCounter("t1", "c1", &tv.perf_public_ctx);
    RegisterCounter("t2", "c2", &tv.perf_public_ctx);
    RegisterCounter("t3", "c3", &tv.perf_public_ctx);
    RegisterCounter("t4", "c4", &tv.perf_public_ctx);
    id2 = RegisterCounter("t5", "c5", &tv.perf_public_ctx);

    StatsGetAllCountersArray(&tv.perf_public_ctx, &tv.perf_private_ctx);
    pca = &tv.perf_private_ctx;

    StatsIncr(&tv, id2);
    StatsAddUI64(&tv, id2, 100);

    FAIL_IF_NOT((pca->head[id1].value == 0) && (pca->head[id2].value == 101));

    StatsReleaseCounters(tv.perf_public_ctx.head);
    StatsReleasePrivateThreadContext(pca);

    PASS;
}

static int StatsTestUpdateGlobalCounter10(void)
{
    ThreadVars tv;
    StatsPrivateThreadContext *pca = NULL;

    int result = 1;
    uint16_t id1, id2, id3;

    memset(&tv, 0, sizeof(ThreadVars));

    id1 = RegisterCounter("t1", "c1", &tv.perf_public_ctx);
    id2 = RegisterCounter("t2", "c2", &tv.perf_public_ctx);
    id3 = RegisterCounter("t3", "c3", &tv.perf_public_ctx);

    StatsGetAllCountersArray(&tv.perf_public_ctx, &tv.perf_private_ctx);
    pca = &tv.perf_private_ctx;

    StatsIncr(&tv, id1);
    StatsAddUI64(&tv, id2, 100);
    StatsIncr(&tv, id3);
    StatsAddUI64(&tv, id3, 100);

    StatsUpdateCounterArray(pca, &tv.perf_public_ctx);

    result = (1 == tv.perf_public_ctx.head->value);
    result &= (100 == tv.perf_public_ctx.head->next->value);
    result &= (101 == tv.perf_public_ctx.head->next->next->value);
    FAIL_IF_NOT(result);

    StatsReleaseCounters(tv.perf_public_ctx.head);
    StatsReleasePrivateThreadContext(pca);

    PASS;
}

static int StatsTestCounterValues11(void)
{
    ThreadVars tv;
    StatsPrivateThreadContext *pca = NULL;

    int result = 1;
    uint16_t id1, id2, id3, id4;

    memset(&tv, 0, sizeof(ThreadVars));

    id1 = RegisterCounter("t1", "c1", &tv.perf_public_ctx);
    id2 = RegisterCounter("t2", "c2", &tv.perf_public_ctx);
    id3 = RegisterCounter("t3", "c3", &tv.perf_public_ctx);
    id4 = RegisterCounter("t4", "c4", &tv.perf_public_ctx);

    StatsGetAllCountersArray(&tv.perf_public_ctx, &tv.perf_private_ctx);
    pca = &tv.perf_private_ctx;

    StatsIncr(&tv, id1);
    StatsAddUI64(&tv, id2, 256);
    StatsAddUI64(&tv, id3, 257);
    StatsAddUI64(&tv, id4, 16843024);

    StatsUpdateCounterArray(pca, &tv.perf_public_ctx);

    result &= (1 == tv.perf_public_ctx.head->value);
    result &= (256 == tv.perf_public_ctx.head->next->value);
    result &= (257 == tv.perf_public_ctx.head->next->next->value);
    result &= (16843024 == tv.perf_public_ctx.head->next->next->next->value);
    FAIL_IF_NOT(result);

    StatsReleaseCounters(tv.perf_public_ctx.head);
    StatsReleasePrivateThreadContext(pca);

    PASS;
}

#endif

void StatsRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("StatsTestCounterReg02", StatsTestCounterReg02);
    UtRegisterTest("StatsTestCounterReg03", StatsTestCounterReg03);
    UtRegisterTest("StatsTestCounterReg04", StatsTestCounterReg04);
    UtRegisterTest("StatsTestGetCntArray05", StatsTestGetCntArray05);
    UtRegisterTest("StatsTestGetCntArray06", StatsTestGetCntArray06);
    UtRegisterTest("StatsTestCntArraySize07", StatsTestCntArraySize07);
    UtRegisterTest("StatsTestUpdateCounter08", StatsTestUpdateCounter08);
    UtRegisterTest("StatsTestUpdateCounter09", StatsTestUpdateCounter09);
    UtRegisterTest("StatsTestUpdateGlobalCounter10",
                   StatsTestUpdateGlobalCounter10);
    UtRegisterTest("StatsTestCounterValues11", StatsTestCounterValues11);
#endif
}
