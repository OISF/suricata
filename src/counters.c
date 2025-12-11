/* Copyright (C) 2007-2025 Open Information Security Foundation
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
#include "counters.h"

#include "suricata.h"
#include "threadvars.h"

#include "output.h"
#include "output-json-stats.h"

#include "util-byte.h"
#include "util-conf.h"
#include "util-hash.h"
#include "util-time.h"

#include "tm-threads.h"
#include "util-privs.h"

/* Time interval for syncing the local counters with the global ones */
#define STATS_WUT_TTS 3

/* Time interval at which the mgmt thread o/p the stats */
#define STATS_MGMTT_TTS 8

/**
 * \brief Different kinds of qualifier that can be used to modify the behaviour
 *        of the counter to be registered
 */
enum StatsType {
    STATS_TYPE_NORMAL = 1,
    STATS_TYPE_AVERAGE = 2,
    STATS_TYPE_MAXIMUM = 3,
    STATS_TYPE_FUNC = 4,
    STATS_TYPE_DERIVE_DIV = 5,

    STATS_TYPE_MAX = 6,
};

/**
 * \brief per thread store of counters
 */
typedef struct StatsThreadStore_ {
    /** thread name used in output */
    const char *name;

    StatsPublicThreadContext *ctx;

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
static void StatsReleaseCounters(StatsCounter *head);
static int StatsUpdateCounterArray(StatsPrivateThreadContext *pca, StatsPublicThreadContext *pctx);

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
    SCSpinInit(&t->lock, 0);
}

static void StatsPublicThreadContextCleanup(StatsPublicThreadContext *t)
{
    SCSpinLock(&t->lock);
    SCFree(t->copy_of_private);
    SCFree(t->pc_array);
    StatsReleaseCounters(t->head);
    t->head = NULL;
    SC_ATOMIC_SET(t->sync_now, false);
    t->curr_id = 0;
    SCSpinUnlock(&t->lock);
    SCSpinDestroy(&t->lock);
}

/**
 * \brief Adds a value of type uint64_t to the local counter.
 *
 * \param id  ID of the counter as set by the API
 * \param pca Counter array that holds the local counter for this TM
 * \param x   Value to add to this local counter
 */
void StatsCounterAddI64(StatsThreadContext *stats, StatsCounterId id, int64_t x)
{
    StatsPrivateThreadContext *pca = &stats->priv;
#if defined (UNITTESTS) || defined (FUZZ)
    if (pca->initialized == 0)
        return;
#endif
#ifdef DEBUG
    BUG_ON((id.id < 1) || (id.id > pca->size));
#endif
    pca->head[id.id].v += x;
}

/**
 * \brief Increments the local counter
 *
 * \param id  Index of the counter in the counter array
 * \param pca Counter array that holds the local counters for this TM
 */
void StatsCounterIncr(StatsThreadContext *stats, StatsCounterId id)
{
    StatsPrivateThreadContext *pca = &stats->priv;
#if defined (UNITTESTS) || defined (FUZZ)
    if (pca->initialized == 0)
        return;
#endif
#ifdef DEBUG
    BUG_ON((id.id < 1) || (id.id > pca->size));
#endif
    pca->head[id.id].v++;
}

/**
 * \brief Decrements the local counter
 *
 * \param stats per thread counter structure
 * \param id  Index of the counter in the counter array
 */
void StatsCounterDecr(StatsThreadContext *stats, StatsCounterId id)
{
    StatsPrivateThreadContext *pca = &stats->priv;
#if defined(UNITTESTS) || defined(FUZZ)
    if (pca->initialized == 0)
        return;
#endif
#ifdef DEBUG
    BUG_ON((id.id < 1) || (id.id > pca->size));
#endif
    pca->head[id.id].v--;
}

/**
 * \brief set, so overwrite, the value of the local counter
 *
 * \param stats per thread counter structure
 * \param id  Index of the local counter in the counter array
 * \param x   The value to set for the counter
 */
void StatsCounterSetI64(StatsThreadContext *stats, StatsCounterId id, int64_t x)
{
    StatsPrivateThreadContext *pca = &stats->priv;
#if defined (UNITTESTS) || defined (FUZZ)
    if (pca->initialized == 0)
        return;
#endif
#ifdef DEBUG
    BUG_ON((id.id < 1) || (id.id > pca->size));
#endif
    pca->head[id.id].v = x;
}

/**
 * \brief update the value of the localmax counter
 *
 * \param stats per thread counter structure
 * \param id  Index of the local counter in the counter array
 * \param x   The value to set for the counter
 */
void StatsCounterMaxUpdateI64(StatsThreadContext *stats, StatsCounterMaxId id, int64_t x)
{
    StatsPrivateThreadContext *pca = &stats->priv;
#if defined(UNITTESTS) || defined(FUZZ)
    if (pca->initialized == 0)
        return;
#endif
#ifdef DEBUG
    BUG_ON((id.id < 1) || (id.id > pca->size));
#endif

    if ((int64_t)x > pca->head[id.id].v) {
        pca->head[id.id].v = x;
    }
}

void StatsCounterAvgAddI64(StatsThreadContext *stats, StatsCounterAvgId id, int64_t x)
{
    StatsPrivateThreadContext *pca = &stats->priv;
#if defined(UNITTESTS) || defined(FUZZ)
    if (pca->initialized == 0)
        return;
#endif
#ifdef DEBUG
    BUG_ON((id.id < 1) || (id.id > pca->size));
#endif

    pca->head[id.id].v += x;
    pca->head[id.id + 1].v++;
}

static SCConfNode *GetConfig(void)
{
    SCConfNode *stats = SCConfGetNode("stats");
    if (stats != NULL)
        return stats;

    SCConfNode *root = SCConfGetNode("outputs");
    SCConfNode *node = NULL;
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
    SCConfNode *stats = GetConfig();
    if (stats != NULL) {
        const char *enabled = SCConfNodeLookupChildValue(stats, "enabled");
        if (enabled != NULL && SCConfValIsFalse(enabled)) {
            stats_enabled = false;
            SCLogDebug("Stats module has been disabled");
            SCReturn;
        }
        /* warn if we are using legacy config to enable stats */
        SCConfNode *gstats = SCConfGetNode("stats");
        if (gstats == NULL) {
            SCLogWarning("global stats config is missing. "
                         "Stats enabled through legacy stats.log. "
                         "See %s/configuration/suricata-yaml.html#stats",
                    GetDocURL());
        }

        const char *interval = SCConfNodeLookupChildValue(stats, "interval");
        if (interval != NULL)
            if (StringParseUint32(&stats_tts, 10, 0, interval) < 0) {
                SCLogWarning("Invalid value for "
                             "interval: \"%s\". Resetting to %d.",
                        interval, STATS_MGMTT_TTS);
                stats_tts = STATS_MGMTT_TTS;
            }

        int b;
        int ret = SCConfGetChildValueBool(stats, "decoder-events", &b);
        if (ret) {
            stats_decoder_events = (b == 1);
        }
        ret = SCConfGetChildValueBool(stats, "stream-events", &b);
        if (ret) {
            stats_stream_events = (b == 1);
        }

        const char *prefix = NULL;
        if (SCConfGet("stats.decoder-events-prefix", &prefix) != 1) {
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
        FatalError("error initializing sts mutex");
    }

    if (stats_enabled && !OutputStatsLoggersRegistered()) {
        stats_loggers_active = 0;

        /* if the unix command socket is enabled we do the background
         * stats sync just in case someone runs 'dump-counters' */
        if (!ConfUnixSocketIsEnable()) {
            SCLogWarning("stats are enabled but no loggers are active");
            stats_enabled = false;
            SCReturn;
        }
    }

    SCReturn;
}

/**
 * \brief Releases the resources allotted to the output context of the
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
        SCLogError("Stats API not init"
                   "StatsInitCounterApi() has to be called first");
        TmThreadsSetFlag(tv_local, THV_CLOSED | THV_RUNNING_DONE);
        return NULL;
    }

    TmModule *tm = &tmm_modules[TMM_STATSLOGGER];
    BUG_ON(tm->ThreadInit == NULL);
    int r = tm->ThreadInit(tv_local, NULL, &stats_thread_data);
    if (r != 0 || stats_thread_data == NULL) {
        SCLogError("Stats API "
                   "ThreadInit failed");
        TmThreadsSetFlag(tv_local, THV_CLOSED | THV_RUNNING_DONE);
        return NULL;
    }
    SCLogDebug("stats_thread_data %p", &stats_thread_data);

    TmThreadsSetFlag(tv_local, THV_INIT_DONE | THV_RUNNING);
    bool run = TmThreadsWaitForUnpause(tv_local);
    while (run) {
        struct timeval cur_timev;
        gettimeofday(&cur_timev, NULL);
        struct timespec cond_time = FROM_TIMEVAL(cur_timev);
        cond_time.tv_sec += (stats_tts);

        /* wait for the set time, or until we are woken up by
         * the shutdown procedure */
        SCCtrlMutexLock(tv_local->ctrl_mutex);
        while (1) {
            if (TmThreadsCheckFlag(tv_local, THV_KILL)) {
                break;
            }
            int rc = SCCtrlCondTimedwait(tv_local->ctrl_cond, tv_local->ctrl_mutex, &cond_time);
            if (rc == ETIMEDOUT || rc < 0) {
                break;
            }
        }
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
        SCLogError("Stats Counter API "
                   "ThreadDeinit failed");
    }

    TmThreadsSetFlag(tv_local, THV_CLOSED);
    return NULL;
}

void StatsSyncCounters(StatsThreadContext *stats)
{
    StatsUpdateCounterArray(&stats->priv, &stats->pub);
}

void StatsSyncCountersIfSignalled(StatsThreadContext *stats)
{
    if (SC_ATOMIC_GET(stats->pub.sync_now)) {
        StatsUpdateCounterArray(&stats->priv, &stats->pub);
    }
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
        SCLogError("Stats API not init"
                   "StatsInitCounterApi() has to be called first");
        TmThreadsSetFlag(tv_local, THV_CLOSED | THV_RUNNING_DONE);
        return NULL;
    }

    TmThreadsSetFlag(tv_local, THV_INIT_DONE | THV_RUNNING);
    bool run = TmThreadsWaitForUnpause(tv_local);

    while (run) {
        struct timeval cur_timev;
        gettimeofday(&cur_timev, NULL);
        struct timespec cond_time = FROM_TIMEVAL(cur_timev);
        cond_time.tv_sec += STATS_WUT_TTS;

        /* wait for the set time, or until we are woken up by
         * the shutdown procedure */
        SCCtrlMutexLock(tv_local->ctrl_mutex);
        while (1) {
            if (TmThreadsCheckFlag(tv_local, THV_KILL)) {
                break;
            }
            int rc = SCCtrlCondTimedwait(tv_local->ctrl_cond, tv_local->ctrl_mutex, &cond_time);
            if (rc == ETIMEDOUT || rc < 0) {
                break;
            }
        }
        SCCtrlMutexUnlock(tv_local->ctrl_mutex);

        SCMutexLock(&tv_root_lock);
        ThreadVars *tv = tv_root[TVT_PPT];
        while (tv != NULL) {
            if (tv->stats.pub.head == NULL) {
                tv = tv->next;
                continue;
            }

            SC_ATOMIC_SET(tv->stats.pub.sync_now, true);

            if (tv->inq != NULL) {
                PacketQueue *q = tv->inq->pq;
                SCMutexLock(&q->mutex_q);
                SCCondSignal(&q->cond_q);
                SCMutexUnlock(&q->mutex_q);
            }

            tv = tv->next;
        }

        /* mgt threads for flow manager */
        tv = tv_root[TVT_MGMT];
        while (tv != NULL) {
            if (tv->stats.pub.head == NULL) {
                tv = tv->next;
                continue;
            }

            SC_ATOMIC_SET(tv->stats.pub.sync_now, true);

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
}

/** \internal
 *  \brief Get ID for counters referenced in a derive counter
 *  \retval id (>=1) or 0 on error
 */
static uint16_t GetIdByName(const StatsPublicThreadContext *pctx, const char *name)
{
    for (const StatsCounter *c = pctx->head; c != NULL; c = c->next) {
        if (strcmp(name, c->name) == 0) {
            return c->id;
        }
    }
    return 0;
}

/**
 * \brief Registers a counter.
 *
 * \param name    Name of the counter, to be registered
 * \param pctx     StatsPublicThreadContext for this tm-tv instance
 * \param type_q   Qualifier describing the type of counter to be registered
 *
 * \retval the counter id for the newly registered counter, or the already
 *         present counter on success
 * \retval 0 on failure
 */
static uint16_t StatsRegisterQualifiedCounter(const char *name, StatsPublicThreadContext *pctx,
        enum StatsType type_q, uint64_t (*Func)(void), const char *dname1, const char *dname2)
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

    uint16_t did1 = 0;
    uint16_t did2 = 0;
    if (type_q == STATS_TYPE_DERIVE_DIV) {
        did1 = GetIdByName(pctx, dname1);
        did2 = GetIdByName(pctx, dname2);
        if (did1 == 0 || did2 == 0) {
            return 0;
        }
    }

    /* if we reach this point we don't have a counter registered by this name */
    if ((pc = SCCalloc(1, sizeof(StatsCounter))) == NULL)
        return 0;

    /* assign a unique id to this StatsCounter.  The id is local to this
     * thread context.  Please note that the id start from 1, and not 0 */
    if (type_q == STATS_TYPE_DERIVE_DIV) {
        pc->id = ++pctx->derive_id;
    } else {
        pc->id = ++(pctx->curr_id);
    }
    /* for AVG counters we use 2 indices into the tables: one for values,
     * the other to track updates. */
    if (type_q == STATS_TYPE_AVERAGE)
        ++(pctx->curr_id);
    pc->name = name;

    /* Precalculate the short name */
    if (strrchr(name, '.') != NULL) {
        pc->short_name = &name[strrchr(name, '.') - name + 1];
    }

    pc->type = type_q;
    pc->Func = Func;
    pc->did1 = did1;
    pc->did2 = did2;

    /* we now add the counter to the list */
    if (prev == NULL)
        *head = pc;
    else
        prev->next = pc;

    return pc->id;
}

/**
 * \brief The output interface for the Stats API
 */
static int StatsOutput(ThreadVars *tv)
{
    const StatsThreadStore *sts = NULL;
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
            SCLogError("could not alloc memory for stats");
            return -1;
        }

        stats_table.ntstats = stats_ctx->sts_cnt;
        uint32_t array_size = stats_table.nstats * sizeof(StatsRecord);
        stats_table.tstats = SCCalloc(stats_table.ntstats, array_size);
        if (stats_table.tstats == NULL) {
            stats_table.ntstats = 0;
            SCLogError("could not alloc memory for stats");
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
        enum StatsType type;
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
        DEBUG_VALIDATE_BUG_ON(thread < 0);

        SCLogDebug("Thread %d %s ctx %p", thread, sts->name, sts->ctx);

        /* temporary table for quickly storing the counters for this
         * thread store, so that we can post process them outside
         * of the thread store lock */
        struct CountersMergeTable thread_table[max_id];
        memset(&thread_table, 0x00,
                max_id * sizeof(struct CountersMergeTable));

        StatsLocalCounter thread_table_from_private[max_id];
        memset(&thread_table_from_private, 0x00, max_id * sizeof(StatsLocalCounter));

        /* copy private table to a local variable to loop it w/o lock */
        bool skip = false;
        SCSpinLock(&sts->ctx->lock);
        const uint16_t table_size = sts->ctx->curr_id + sts->ctx->derive_id + 1;
        if (sts->ctx->copy_of_private == NULL) {
            skip = true;
        } else {
            memcpy(&thread_table_from_private, sts->ctx->copy_of_private,
                    table_size * sizeof(StatsLocalCounter));
        }
        SCSpinUnlock(&sts->ctx->lock);
        if (skip)
            goto next;

        /* loop counters and handle them. This includes the global counters, which
         * access the StatsCounters but don't modify them. */
        for (uint16_t i = 1; i < table_size; i++) {
            const StatsCounter *pc = sts->ctx->pc_array[i];
            thread_table[pc->gid].type = pc->type;

            table[pc->gid].name = pc->name;
            table[pc->gid].short_name = pc->short_name;

            switch (pc->type) {
                case STATS_TYPE_FUNC:
                    if (pc->Func != NULL)
                        thread_table[pc->gid].value = pc->Func();
                    break;
                case STATS_TYPE_AVERAGE:
                    thread_table[pc->gid].value = thread_table_from_private[i].v;
                    thread_table[pc->gid].updates = thread_table_from_private[i + 1].v;
                    /* skip updates row */
                    i++;
                    break;
                case STATS_TYPE_DERIVE_DIV:
                    SCLogDebug("counter %u/%u is derived from counters %u / %u", pc->id, pc->gid,
                            pc->did1, pc->did2);
                    thread_table[pc->gid].value = thread_table_from_private[pc->did1].v;
                    thread_table[pc->gid].updates = thread_table_from_private[pc->did2].v;
                    break;
                default:
                    SCLogDebug("Counter %s (%u:%u) value %" PRIu64, pc->name, pc->id, pc->gid,
                            thread_table_from_private[i].v);

                    thread_table[pc->gid].value = thread_table_from_private[i].v;
                    break;
            }
        }

        /* update merge table */
        for (uint16_t c = 0; c < max_id; c++) {
            const struct CountersMergeTable *e = &thread_table[c];
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
            const struct CountersMergeTable *e = &thread_table[c];
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
            r->short_name = table[c].short_name;
            r->tm_name = sts->name;

            switch (e->type) {
                case STATS_TYPE_AVERAGE:
                case STATS_TYPE_DERIVE_DIV:
                    if (e->value > 0 && e->updates > 0) {
                        r->value = (uint64_t)(e->value / e->updates);
                    }
                    break;
                default:
                    r->value = e->value;
                    break;
            }
        }

    next:
        sts = sts->next;
        thread--;
    }

    /* transfer 'merge table' to final stats table */
    for (uint16_t x = 0; x < max_id; x++) {
        /* xfer previous value to pvalue and reset value */
        table[x].pvalue = table[x].value;
        table[x].value = 0;
        table[x].tm_name = "Total";

        const struct CountersMergeTable *m = &merge_table[x];
        switch (m->type) {
            case STATS_TYPE_MAXIMUM:
                if (m->value > table[x].value)
                    table[x].value = m->value;
                break;
            case STATS_TYPE_AVERAGE:
            case STATS_TYPE_DERIVE_DIV:
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
    if ((stats_ctx = SCCalloc(1, sizeof(StatsGlobalContext))) == NULL) {
        FatalError("Fatal error encountered in StatsInitCtx. Exiting...");
    }

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
        FatalError("TmThreadCreateMgmtThread "
                   "failed");
    }

    if (TmThreadSpawn(tv_wakeup) != 0) {
        FatalError("TmThreadSpawn failed for "
                   "StatsWakeupThread");
    }

    /* spawn the stats mgmt thread */
    tv_mgmt = TmThreadCreateMgmtThread(thread_name_counter_stats,
                                       StatsMgmtThread, 1);
    if (tv_mgmt == NULL) {
        FatalError("TmThreadCreateMgmtThread failed");
    }

    if (TmThreadSpawn(tv_mgmt) != 0) {
        FatalError("TmThreadSpawn failed for "
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
StatsCounterId StatsRegisterCounter(const char *name, StatsThreadContext *stats)
{
    uint16_t id =
            StatsRegisterQualifiedCounter(name, &stats->pub, STATS_TYPE_NORMAL, NULL, NULL, NULL);
    StatsCounterId s = { .id = id };
    return s;
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
StatsCounterAvgId StatsRegisterAvgCounter(const char *name, StatsThreadContext *stats)
{
    uint16_t id =
            StatsRegisterQualifiedCounter(name, &stats->pub, STATS_TYPE_AVERAGE, NULL, NULL, NULL);
    StatsCounterAvgId s = { .id = id };
    return s;
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
StatsCounterMaxId StatsRegisterMaxCounter(const char *name, StatsThreadContext *stats)
{
    uint16_t id =
            StatsRegisterQualifiedCounter(name, &stats->pub, STATS_TYPE_MAXIMUM, NULL, NULL, NULL);
    StatsCounterMaxId s = { .id = id };
    return s;
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
StatsCounterGlobalId StatsRegisterGlobalCounter(const char *name, uint64_t (*Func)(void))
{
    StatsCounterGlobalId s = { .id = 0 };
#if defined (UNITTESTS) || defined (FUZZ)
    if (stats_ctx == NULL)
        return s;
#else
    BUG_ON(stats_ctx == NULL);
#endif
    uint16_t id = StatsRegisterQualifiedCounter(
            name, &(stats_ctx->global_counter_ctx), STATS_TYPE_FUNC, Func, NULL, NULL);
    s.id = id;
    return s;
}

/**
 * \brief Registers a counter which tracks the result of the calculating the value
 * of counter dname1 divided by the value of the counter dname2
 *
 * \param name Name of the counter, to be registered
 * \param dname1 First counter name
 * \param dname2 Second counter name
 *
 * Both counters need to already be registered in this thread.
 *
 * \retval id Counter id for the newly registered counter, or the already
 *            present counter
 */
StatsCounterDeriveId StatsRegisterDeriveDivCounter(
        const char *name, const char *dname1, const char *dname2, StatsThreadContext *stats)
{
    StatsCounterDeriveId s = { .id = 0 };
#if defined(UNITTESTS) || defined(FUZZ)
    if (stats_ctx == NULL)
        return s;
#else
    BUG_ON(stats_ctx == NULL);
#endif
    uint16_t id = StatsRegisterQualifiedCounter(
            name, &stats->pub, STATS_TYPE_DERIVE_DIV, NULL, dname1, dname2);
    s.id = id;
    return s;
}

typedef struct CountersIdType_ {
    uint16_t id;
    const char *string;
} CountersIdType;

static uint32_t CountersIdHashFunc(HashTable *ht, void *data, uint16_t datalen)
{
    CountersIdType *t = (CountersIdType *)data;
    uint32_t hash = 0;
    size_t len = strlen(t->string);

    for (size_t i = 0; i < len; i++)
        hash += u8_tolower((unsigned char)t->string[i]);

    hash = hash % ht->array_size;
    return hash;
}

static char CountersIdHashCompareFunc(void *data1, uint16_t datalen1,
                               void *data2, uint16_t datalen2)
{
    CountersIdType *t1 = (CountersIdType *)data1;
    CountersIdType *t2 = (CountersIdType *)data2;

    if (t1 == NULL || t2 == NULL)
        return 0;

    if (t1->string == NULL || t2->string == NULL)
        return 0;

    return strcmp(t1->string, t2->string) == 0;
}

static void CountersIdHashFreeFunc(void *data)
{
    SCFree(data);
}

static int StatsThreadSetupPublic(StatsPublicThreadContext *pctx)
{
    size_t array_size = pctx->curr_id + pctx->derive_id + 1;
    pctx->pc_array = SCCalloc(array_size, sizeof(StatsCounter *));
    if (pctx->pc_array == NULL) {
        return -1;
    }
    /* regular counters that get direct updates by their id as idx */
    for (StatsCounter *pc = pctx->head; pc != NULL; pc = pc->next) {
        if (pc->type != STATS_TYPE_DERIVE_DIV) {
            SCLogDebug("pc %s gid %u id %u", pc->name, pc->gid, pc->id);
            BUG_ON(pctx->pc_array[pc->id] != NULL);
            pctx->pc_array[pc->id] = pc;
        }
    }
    /* derive counters are not updated by the thread itself and will be put
     * at the end of the array */
    for (StatsCounter *pc = pctx->head; pc != NULL; pc = pc->next) {
        if (pc->type == STATS_TYPE_DERIVE_DIV) {
            uint16_t id = pctx->curr_id + pc->id;
            SCLogDebug("STATS_TYPE_DERIVE_DIV: pc %s gid %u pc->id %u id %u", pc->name, pc->gid,
                    pc->id, id);
            BUG_ON(pctx->pc_array[id] != NULL);
            pctx->pc_array[id] = pc;
        }
    }

    SCLogDebug("array_size %u memory %" PRIu64, (uint32_t)array_size,
            (uint64_t)(array_size * sizeof(StatsLocalCounter)));
    pctx->copy_of_private = SCCalloc(array_size, sizeof(StatsLocalCounter));
    if (pctx->copy_of_private == NULL) {
        return -1;
    }
    return 0;
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
        return 1;
    }

    if (thread_name == NULL || pctx == NULL) {
        SCLogDebug("supplied argument(s) to StatsThreadRegister NULL");
        return 0;
    }

    SCMutexLock(&stats_ctx->sts_lock);
    SCLogDebug("thread %s", thread_name);
    if (stats_ctx->counters_id_hash == NULL) {
        stats_ctx->counters_id_hash = HashTableInit(256, CountersIdHashFunc,
                                                              CountersIdHashCompareFunc,
                                                              CountersIdHashFreeFunc);
        if (stats_ctx->counters_id_hash == NULL) {
            SCMutexUnlock(&stats_ctx->sts_lock);
            return 0;
        }
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
            int r = HashTableAdd(stats_ctx->counters_id_hash, id, sizeof(*id));
            DEBUG_VALIDATE_BUG_ON(r < 0);
            if (r < 0) {
                SCMutexUnlock(&stats_ctx->sts_lock);
                return 0;
            }
        }
        pc->gid = id->id;
        pc = pc->next;
    }

    if (StatsThreadSetupPublic(pctx) != 0) {
        SCLogDebug("failed to setup StatsThreadSetupPublic");
        SCMutexUnlock(&stats_ctx->sts_lock);
        return 0;
    }

    StatsThreadStore *temp = NULL;
    if ((temp = SCCalloc(1, sizeof(StatsThreadStore))) == NULL) {
        SCMutexUnlock(&stats_ctx->sts_lock);
        return 0;
    }

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
 *  \brief Returns a counter array for all counters registered for this tm
 *         instance
 *
 *  \param pctx Pointer to the tv's StatsPublicThreadContext
 *
 *  \retval pca Pointer to a counter-array for all counter of this tm instance
 *              on success; NULL on failure
 */
static int StatsGetAllCountersArray(
        StatsPublicThreadContext *pctx, StatsPrivateThreadContext *private)
{
    if (pctx == NULL || private == NULL)
        return -1;

    private->size = pctx->curr_id + 1;

    private->head = SCCalloc(private->size, sizeof(StatsLocalCounter));
    if (private->head == NULL) {
        return -1;
    }

    private->initialized = 1;
    return 0;
}

int StatsSetupPrivate(StatsThreadContext *stats, const char *thread_name)
{
    int r = StatsGetAllCountersArray(&stats->pub, &stats->priv);
    if (r < 0) {
        return -1;
    }

    r = StatsThreadRegister(thread_name, &stats->pub);
    if (r != 1) {
        return -2;
    }
    return 0;
}

static void StatsThreadInitPublic(StatsPublicThreadContext *pctx)
{
    memset(pctx, 0x00, sizeof(*pctx));
    SCSpinInit(&pctx->lock, 0);
}

void StatsThreadInit(StatsThreadContext *stats)
{
    StatsThreadInitPublic(&stats->pub);
}

/**
 * \brief the private stats store with the public stats store
 *
 * \param pca      Pointer to the StatsPrivateThreadContext
 * \param pctx     Pointer the tv's StatsPublicThreadContext
 *
 * \retval  1 on success
 * \retval -1 on error
 */
static int StatsUpdateCounterArray(StatsPrivateThreadContext *pca, StatsPublicThreadContext *pctx)
{

    if (pca == NULL || pctx == NULL) {
        SCLogDebug("pca or pctx is NULL inside StatsUpdateCounterArray");
        return -1;
    }

    if (pca->size > 0 && pctx->copy_of_private != NULL) {
        /* copy the whole table under lock to the public section
         * and release the lock. The stats thread will copy it from
         * there. */
        SCSpinLock(&pctx->lock);
        memcpy(pctx->copy_of_private, pca->head, pca->size * sizeof(StatsLocalCounter));
        SCSpinUnlock(&pctx->lock);
    }
    SC_ATOMIC_SET(pctx->sync_now, false);
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
int64_t StatsCounterGetLocalValue(StatsThreadContext *stats, StatsCounterId id)
{
    StatsPrivateThreadContext *pca = &stats->priv;
#ifdef DEBUG
    BUG_ON((id.id < 1) || (id.id > pca->size));
#endif
    return pca->head[id.id].v;
}

/**
 * \brief Releases the resources allotted by the Stats API
 */
void StatsReleaseResources(void)
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
static void StatsReleaseCounters(StatsCounter *head)
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

void StatsThreadCleanup(StatsThreadContext *stats)
{
    StatsPublicThreadContextCleanup(&stats->pub);
    StatsReleasePrivateThreadContext(&stats->priv);
}

/*----------------------------------Unit_Tests--------------------------------*/

#ifdef UNITTESTS
/** \internal
 * \brief Registers a normal, unqualified counter
 *
 * \param name   Name of the counter, to be registered
 * \param type    Datatype of this counter variable
 * \param pctx    StatsPublicThreadContext corresponding to the tm_name key under which the
 *                key has to be registered
 *
 * \retval id Counter id for the newly registered counter, or the already
 *            present counter
 */
static StatsCounterId RegisterCounter(
        const char *name, const char *tm_name, StatsPublicThreadContext *pctx)
{
    uint16_t id = StatsRegisterQualifiedCounter(name, pctx, STATS_TYPE_NORMAL, NULL, NULL, NULL);
    StatsCounterId s = { .id = id };
    return s;
}

static int StatsTestCounterReg02(void)
{
    StatsPublicThreadContext pctx;
    StatsThreadInitPublic(&pctx);

    StatsCounterId id = RegisterCounter(NULL, NULL, &pctx);
    FAIL_IF_NOT(id.id == 0);
    PASS;
}

static int StatsTestCounterReg03(void)
{
    StatsPublicThreadContext pctx;
    StatsThreadInitPublic(&pctx);

    StatsCounterId id = RegisterCounter("t1", "c1", &pctx);
    FAIL_IF_NOT(id.id == 1);

    StatsReleaseCounters(pctx.head);
    PASS;
}

static int StatsTestCounterReg04(void)
{
    StatsPublicThreadContext pctx;
    StatsThreadInitPublic(&pctx);

    StatsCounterId c1 = RegisterCounter("t1", "c1", &pctx);
    FAIL_IF_NOT(c1.id == 1);
    StatsCounterId c2 = RegisterCounter("t2", "c2", &pctx);
    FAIL_IF_NOT(c2.id == 2);
    StatsCounterId c3 = RegisterCounter("t3", "c3", &pctx);
    FAIL_IF_NOT(c3.id == 3);
    StatsCounterId id = RegisterCounter("t1", "c1", &pctx);
    FAIL_IF_NOT(id.id == 1);

    StatsReleaseCounters(pctx.head);
    PASS;
}

static int StatsTestGetCntArray05(void)
{
    ThreadVars tv;
    memset(&tv, 0, sizeof(ThreadVars));
    StatsThreadInit(&tv.stats);
    StatsCounterId c1 = RegisterCounter("t1", "c1", &tv.stats.pub);
    FAIL_IF(c1.id != 1);
    int r = StatsGetAllCountersArray(NULL, &tv.stats.priv);
    FAIL_IF_NOT(r == -1);
    StatsThreadCleanup(&tv.stats);
    PASS;
}

static int StatsTestGetCntArray06(void)
{
    ThreadVars tv;
    memset(&tv, 0, sizeof(ThreadVars));
    StatsThreadInit(&tv.stats);
    StatsCounterId c1 = RegisterCounter("t1", "c1", &tv.stats.pub);
    FAIL_IF(c1.id != 1);
    StatsThreadSetupPublic(&tv.stats.pub);
    int r = StatsGetAllCountersArray(&tv.stats.pub, &tv.stats.priv);
    FAIL_IF_NOT(r == 0);
    StatsThreadCleanup(&tv.stats);
    PASS;
}

static int StatsTestCntArraySize07(void)
{
    ThreadVars tv;
    memset(&tv, 0, sizeof(ThreadVars));
    StatsThreadInit(&tv.stats);
    StatsPrivateThreadContext *pca = NULL;

    StatsCounterId id1 = RegisterCounter("t1", "c1", &tv.stats.pub);
    StatsCounterId id2 = RegisterCounter("t2", "c2", &tv.stats.pub);

    StatsThreadSetupPublic(&tv.stats.pub);
    StatsGetAllCountersArray(&tv.stats.pub, &tv.stats.priv);
    pca = &tv.stats.priv;

    StatsCounterIncr(&tv.stats, id1);
    StatsCounterIncr(&tv.stats, id2);

    FAIL_IF_NOT(pca->size == 3);

    StatsThreadCleanup(&tv.stats);
    PASS;
}

static int StatsTestUpdateCounter08(void)
{
    ThreadVars tv;
    memset(&tv, 0, sizeof(ThreadVars));
    StatsThreadInit(&tv.stats);
    StatsCounterId c1 = RegisterCounter("t1", "c1", &tv.stats.pub);
    StatsThreadSetupPublic(&tv.stats.pub);
    StatsGetAllCountersArray(&tv.stats.pub, &tv.stats.priv);
    StatsPrivateThreadContext *pca = &tv.stats.priv;

    StatsCounterIncr(&tv.stats, c1);
    StatsCounterAddI64(&tv.stats, c1, 100);
    FAIL_IF_NOT(pca->head[c1.id].v == 101);

    StatsThreadCleanup(&tv.stats);
    PASS;
}

static int StatsTestUpdateCounter09(void)
{
    ThreadVars tv;
    memset(&tv, 0, sizeof(ThreadVars));
    StatsThreadInit(&tv.stats);

    StatsCounterId c1 = RegisterCounter("t1", "c1", &tv.stats.pub);
    RegisterCounter("t2", "c2", &tv.stats.pub);
    RegisterCounter("t3", "c3", &tv.stats.pub);
    RegisterCounter("t4", "c4", &tv.stats.pub);
    StatsCounterId c5 = RegisterCounter("t5", "c5", &tv.stats.pub);

    StatsThreadSetupPublic(&tv.stats.pub);
    StatsGetAllCountersArray(&tv.stats.pub, &tv.stats.priv);
    StatsPrivateThreadContext *pca = &tv.stats.priv;

    StatsCounterIncr(&tv.stats, c5);
    StatsCounterAddI64(&tv.stats, c5, 100);

    FAIL_IF_NOT(pca->head[c1.id].v == 0);
    FAIL_IF_NOT(pca->head[c5.id].v == 101);

    StatsThreadCleanup(&tv.stats);
    PASS;
}

static int StatsTestUpdateGlobalCounter10(void)
{
    ThreadVars tv;
    memset(&tv, 0, sizeof(ThreadVars));
    StatsThreadInit(&tv.stats);

    StatsCounterId c1 = RegisterCounter("t1", "c1", &tv.stats.pub);
    StatsCounterId c2 = RegisterCounter("t2", "c2", &tv.stats.pub);
    StatsCounterId c3 = RegisterCounter("t3", "c3", &tv.stats.pub);

    StatsThreadSetupPublic(&tv.stats.pub);
    StatsGetAllCountersArray(&tv.stats.pub, &tv.stats.priv);
    StatsPrivateThreadContext *pca = &tv.stats.priv;

    StatsCounterIncr(&tv.stats, c1);
    StatsCounterAddI64(&tv.stats, c2, 100);
    StatsCounterIncr(&tv.stats, c3);
    StatsCounterAddI64(&tv.stats, c3, 100);

    StatsUpdateCounterArray(pca, &tv.stats.pub);

    FAIL_IF_NOT(1 == tv.stats.pub.copy_of_private[c1.id].v);
    FAIL_IF_NOT(100 == tv.stats.pub.copy_of_private[c2.id].v);
    FAIL_IF_NOT(101 == tv.stats.pub.copy_of_private[c3.id].v);

    StatsThreadCleanup(&tv.stats);
    PASS;
}

static int StatsTestCounterValues11(void)
{
    ThreadVars tv;
    memset(&tv, 0, sizeof(ThreadVars));
    StatsThreadInit(&tv.stats);

    StatsCounterId c1 = RegisterCounter("t1", "c1", &tv.stats.pub);
    StatsCounterId c2 = RegisterCounter("t2", "c2", &tv.stats.pub);
    StatsCounterId c3 = RegisterCounter("t3", "c3", &tv.stats.pub);
    StatsCounterId c4 = RegisterCounter("t4", "c4", &tv.stats.pub);

    StatsThreadSetupPublic(&tv.stats.pub);
    StatsGetAllCountersArray(&tv.stats.pub, &tv.stats.priv);
    StatsPrivateThreadContext *pca = &tv.stats.priv;

    StatsCounterIncr(&tv.stats, c1);
    StatsCounterAddI64(&tv.stats, c2, 256);
    StatsCounterAddI64(&tv.stats, c3, 257);
    StatsCounterAddI64(&tv.stats, c4, 16843024);

    StatsUpdateCounterArray(pca, &tv.stats.pub);

    FAIL_IF_NOT(1 == tv.stats.pub.copy_of_private[c1.id].v);
    FAIL_IF_NOT(256 == tv.stats.pub.copy_of_private[c2.id].v);
    FAIL_IF_NOT(257 == tv.stats.pub.copy_of_private[c3.id].v);
    FAIL_IF_NOT(16843024 == tv.stats.pub.copy_of_private[c4.id].v);

    StatsThreadCleanup(&tv.stats);
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
