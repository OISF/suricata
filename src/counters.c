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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
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

/** \todo Get the default log directory from some global resource. */
#define SC_PERF_DEFAULT_LOG_FILENAME "stats.log"

/* Used to parse the interval for Timebased counters */
#define SC_PERF_PCRE_TIMEBASED_INTERVAL "^(?:(\\d+)([shm]))(?:(\\d+)([shm]))?(?:(\\d+)([shm]))?$"

static SCPerfOPIfaceContext *sc_perf_op_ctx = NULL;
static time_t sc_start_time;
/** refresh interval in seconds */
static uint32_t sc_counter_tts = SC_PERF_MGMTT_TTS;
/** is the stats counter enabled? */
static char sc_counter_enabled = TRUE;
/** append or overwrite? 1: append, 0: overwrite */
static char sc_counter_append = TRUE;

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
    if ((id < 1) || (id > pca->size)) {
        SCLogDebug("counter doesn't exist");
        return;
    }

    switch (pca->head[id].pc->value->type) {
        case SC_PERF_TYPE_UINT64:
            pca->head[id].ui64_cnt += x;
            break;
        case SC_PERF_TYPE_DOUBLE:
            pca->head[id].d_cnt += x;
            break;
    }

    if (pca->head[id].syncs == ULONG_MAX) {
        pca->head[id].syncs = 0;
        pca->head[id].wrapped_syncs++;
    }
    pca->head[id].syncs++;

    return;
}

/**
 * \brief Adds a value of type double to the local counter
 *
 * \param id  ID of the counter as set by the API
 * \param pca Counter array that holds the local counter for this TM
 * \param x   Value to add to this local counter
 */
void SCPerfCounterAddDouble(uint16_t id, SCPerfCounterArray *pca, double x)
{
    if (!pca) {
        SCLogDebug("counterarray is NULL");
        return;
    }
    if ((id < 1) || (id > pca->size)) {
        SCLogDebug("counter doesn't exist");
        return;
    }

    /* incase you are trying to add a double to a counter of type SC_PERF_TYPE_UINT64
     * it will be truncated */
    switch (pca->head[id].pc->value->type) {
        case SC_PERF_TYPE_UINT64:
            pca->head[id].ui64_cnt += x;
            break;
        case SC_PERF_TYPE_DOUBLE:
            pca->head[id].d_cnt += x;
            break;
    }

    if (pca->head[id].syncs == ULONG_MAX) {
        pca->head[id].syncs = 0;
        pca->head[id].wrapped_syncs++;
    }
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
    if ((id < 1) || (id > pca->size)) {
        SCLogDebug("counter doesn't exist");
        return;
    }

    switch (pca->head[id].pc->value->type) {
        case SC_PERF_TYPE_UINT64:
            pca->head[id].ui64_cnt++;
            break;
        case SC_PERF_TYPE_DOUBLE:
            pca->head[id].d_cnt++;
            break;
    }

    if (pca->head[id].syncs == ULONG_MAX) {
        pca->head[id].syncs = 0;
        pca->head[id].wrapped_syncs++;
    }
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

    if ((id < 1) || (id > pca->size)) {
        SCLogDebug("counter doesn't exist");
        return;
    }

    switch (pca->head[id].pc->value->type) {
        case SC_PERF_TYPE_UINT64:
            if ( (pca->head[id].pc->type_q->type & SC_PERF_TYPE_Q_MAXIMUM) &&
                 (x > pca->head[id].ui64_cnt)) {
                pca->head[id].ui64_cnt = x;
            } else if (pca->head[id].pc->type_q->type & SC_PERF_TYPE_Q_NORMAL) {
                pca->head[id].ui64_cnt = x;
            }

            break;
        case SC_PERF_TYPE_DOUBLE:
            if ( (pca->head[id].pc->type_q->type & SC_PERF_TYPE_Q_MAXIMUM) &&
                 (x > pca->head[id].d_cnt)) {
                pca->head[id].d_cnt = x;
            } else if (pca->head[id].pc->type_q->type & SC_PERF_TYPE_Q_NORMAL) {
                pca->head[id].d_cnt = x;
            }

            break;
    }

    if (pca->head[id].syncs == ULONG_MAX) {
        pca->head[id].syncs = 0;
        pca->head[id].wrapped_syncs++;
    }
    pca->head[id].syncs++;

    return;
}

/**
 * \brief Sets a local counter to an arg of type double
 *
 * \param id  Index of the local counter in the counter array
 * \param pca Pointer to the SCPerfCounterArray
 * \param x   The value to set for the counter
 */
void SCPerfCounterSetDouble(uint16_t id, SCPerfCounterArray *pca,
                                   double x)
{
    if (!pca) {
        SCLogDebug("counterarray is NULL");
        return;
    }

    if ((id < 1) || (id > pca->size)) {
        SCLogDebug("counter doesn't exist");
        return;
    }

    switch (pca->head[id].pc->value->type) {
        case SC_PERF_TYPE_UINT64:
            if ( (pca->head[id].pc->type_q->type & SC_PERF_TYPE_Q_MAXIMUM) &&
                 (x > pca->head[id].ui64_cnt)) {
                pca->head[id].ui64_cnt = x;
            } else if (pca->head[id].pc->type_q->type & SC_PERF_TYPE_Q_NORMAL) {
                pca->head[id].ui64_cnt = x;
            }

            break;
        case SC_PERF_TYPE_DOUBLE:
            if ( (pca->head[id].pc->type_q->type & SC_PERF_TYPE_Q_MAXIMUM) &&
                 (x > pca->head[id].d_cnt)) {
                pca->head[id].d_cnt = x;
            } else if (pca->head[id].pc->type_q->type & SC_PERF_TYPE_Q_NORMAL) {
                pca->head[id].d_cnt = x;
            }

            break;
    }

    if (pca->head[id].syncs == ULONG_MAX) {
        pca->head[id].syncs = 0;
        pca->head[id].wrapped_syncs++;
    }
    pca->head[id].syncs++;

    return;
}

/**
 * \brief Get the filename with path to the stats log file.
 *
 *        This function returns a string containing the log filename.  It uses
 *        allocated memory simply to drop into the existing code a little better
 *        where a SCStrdup was used.  So as before, it is up to the caller to free
 *        the memory.
 *
 * \retval An allocated string containing the log filename on success or NULL on
 *         failure.
 */
static char *SCPerfGetLogFilename(ConfNode *stats)
{
    char *log_dir = NULL;
    char *log_filename = NULL;
    const char* filename = NULL;

    if (ConfGet("default-log-dir", &log_dir) != 1)
        log_dir = DEFAULT_LOG_DIR;

    if ( (log_filename = SCMalloc(PATH_MAX)) == NULL) {
        return NULL;
    }

    if (stats != NULL) {
        filename = ConfNodeLookupChildValue(stats, "filename");
        if (filename == NULL) {
            filename = SC_PERF_DEFAULT_LOG_FILENAME;
        }
    } else {
        filename = SC_PERF_DEFAULT_LOG_FILENAME;
    }

    if (snprintf(log_filename, PATH_MAX, "%s/%s", log_dir,
                 filename) < 0) {
        SCLogError(SC_ERR_SPRINTF, "Sprintf Error");
        SCFree(log_filename);
        return NULL;
    }

    return log_filename;
}

/**
 * \brief Initializes the output interface context
 *
 * \todo Support multiple interfaces
 */
static void SCPerfInitOPCtx(void)
{
    SCEnter();

    ConfNode *root = ConfGetNode("outputs");
    ConfNode *node = NULL;
    ConfNode *stats = NULL;
    if (root != NULL) {
        TAILQ_FOREACH(node, &root->head, next) {
            if (strncmp(node->val, "stats", 5) == 0) {
                stats = node->head.tqh_first;
            }
        }
    }
    /* Check if the stats module is enabled or not */
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

        const char *append = ConfNodeLookupChildValue(stats, "append");
        if (append != NULL)
            sc_counter_append = ConfValIsTrue(append);
    }

    /* Store the engine start time */
    time(&sc_start_time);

    if ( (sc_perf_op_ctx = SCMalloc(sizeof(SCPerfOPIfaceContext))) == NULL) {
        SCLogError(SC_ERR_FATAL, "Fatal error encountered in SCPerfInitOPCtx. Exiting...");
        exit(EXIT_FAILURE);
    }
    memset(sc_perf_op_ctx, 0, sizeof(SCPerfOPIfaceContext));

    sc_perf_op_ctx->iface = SC_PERF_IFACE_FILE;

    if ( (sc_perf_op_ctx->file = SCPerfGetLogFilename(stats)) == NULL) {
        SCLogInfo("Error retrieving Perf Counter API output file path");
    }

    char *mode;
    if (sc_counter_append)
        mode = "a+";
    else
        mode = "w+";

    if ( (sc_perf_op_ctx->fp = fopen(sc_perf_op_ctx->file, mode)) == NULL) {
        SCLogError(SC_ERR_FOPEN, "fopen error opening file \"%s\".  Resorting "
                   "to using the standard output for output",
                   sc_perf_op_ctx->file);

        SCFree(sc_perf_op_ctx->file);

        /* Let us use the standard output for output */
        sc_perf_op_ctx->fp = stdout;
        if ( (sc_perf_op_ctx->file = SCStrdup("stdout")) == NULL) {
            SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
            exit(EXIT_FAILURE);
        }
    }

    /* club the counter from multiple instances of the tm before o/p */
    sc_perf_op_ctx->club_tm = 1;

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

    if (sc_perf_op_ctx->fp != NULL)
        fclose(sc_perf_op_ctx->fp);

    if (sc_perf_op_ctx->file != NULL)
        SCFree(sc_perf_op_ctx->file);

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

        cond_time.tv_sec = time(NULL) + sc_counter_tts;
        cond_time.tv_nsec = 0;

        SCMutexLock(tv_local->m);
        SCCondTimedwait(tv_local->cond, tv_local->m, &cond_time);
        SCMutexUnlock(tv_local->m);

        SCPerfOutputCounters();

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

        SCMutexLock(tv_local->m);
        SCCondTimedwait(tv_local->cond, tv_local->m, &cond_time);
        SCMutexUnlock(tv_local->m);

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
 * \brief Parses a time based counter interval
 *
 * \param pc       Pointer to the PerfCounter that has to be updated with the
 *                 interval
 * \param interval Pointer to a character string that holds the time interval
 *
 * \retval  0 on successfully parsing the time_interval
 * \retval -1 on error
 */
static int SCPerfParseTBCounterInterval(SCPerfCounter *pc, char *interval)
{
    pcre *regex = NULL;
    pcre_extra *regex_study = NULL;
    int opts = 0;
    const char *ep = NULL;
    const char *str_ptr1 = NULL;
    const char *str_ptr2 = NULL;
    int eo = 0;
    int ret = 0;
    int res = 0;
    int ov[30];
    int temp_value = 0;
    int i = 0;

    regex = pcre_compile(SC_PERF_PCRE_TIMEBASED_INTERVAL, opts, &ep, &eo, NULL);
    if (regex == NULL) {
        SCLogInfo("pcre compile of \"%s\" failed at offset %d: %s", interval,
                  eo, ep);
        goto error;
    }

    regex_study = pcre_study(regex, 0, &ep);
    if (ep != NULL) {
        SCLogInfo("pcre study failed: %s", ep);
        goto error;
    }

    ret = pcre_exec(regex, regex_study, interval, strlen(interval), 0, 0, ov, 30);
    if (ret < 0) {
        SCLogWarning(SC_ERR_INVALID_ARGUMENTS, "Invalid Timebased interval");
        goto error;
    }

    for (i = 1; i < ret; i += 2) {
        res = pcre_get_substring((char *)interval, ov, 30, i, &str_ptr1);
        if (res < 0) {
            SCLogInfo("SCPerfParseTBCounterInterval:pcre_get_substring failed");
            goto error;
        }
        temp_value = atoi(str_ptr1);

        res = pcre_get_substring((char *)interval, ov, 30, i + 1, &str_ptr2);
        if (res < 0) {
            SCLogInfo("SCPerfParseTBCounterInterval:pcre_get_substring failed");
            goto error;
        }

        switch (*str_ptr2) {
            case 'h':
                if (temp_value < 0 || temp_value > 24) {
                    SCLogInfo("Invalid timebased counter interval");
                    goto error;
                }
                pc->type_q->hours = temp_value;

                break;
            case 'm':
                if (temp_value < 0 || temp_value >= 60) {
                    SCLogInfo("Invalid timebased counter interval");
                    goto error;
                }
                pc->type_q->minutes = temp_value;

                break;
            case 's':
                if (temp_value < 0 || temp_value >= 60) {
                    SCLogInfo("Invalid timebased counter interval");
                    goto error;
                }
                pc->type_q->seconds = temp_value;

                break;
        }
    }

    if ( !(pc->type_q->hours | pc->type_q->minutes | pc->type_q->seconds)) {
        SCLogInfo("Invalid timebased counter interval");
        goto error;
    }

    pc->type_q->total_secs = ((pc->type_q->hours * 60 * 60) +
                              (pc->type_q->minutes * 60) + pc->type_q->seconds);

    if (str_ptr1 != NULL) SCFree((char *)str_ptr1);
    if (str_ptr2 != NULL) SCFree((char *)str_ptr2);
    SCFree(regex);
    return 0;

 error:
    if (str_ptr1 != NULL) SCFree((char *)str_ptr1);
    if (str_ptr2 != NULL) SCFree((char *)str_ptr2);
    return -1;
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
        if (pc->name != NULL) {
            if (pc->name->cname != NULL)
                SCFree(pc->name->cname);

            if (pc->name->tm_name != NULL)
                SCFree(pc->name->tm_name);

            SCFree(pc->name);
        }

        if (pc->value != NULL) {
            if (pc->value->cvalue != NULL)
                SCFree(pc->value->cvalue);

            SCFree(pc->value);
        }

        if (pc->desc != NULL)
            SCFree(pc->desc);

        if (pc->type_q != NULL)
            SCFree(pc->type_q);

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
 * \param interval Time interval required by a SC_PERF_TYPE_Q_TIMEBASED counter
 *
 * \retval the counter id for the newly registered counter, or the already
 *         present counter on success
 * \retval 0 on failure
 */
static uint16_t SCPerfRegisterQualifiedCounter(char *cname, char *tm_name,
                                               int type, char *desc,
                                               SCPerfContext *pctx, int type_q,
                                               char *interval)
{
    SCPerfCounter **head = &pctx->head;
    SCPerfCounter *temp = NULL;
    SCPerfCounter *prev = NULL;
    SCPerfCounter *pc = NULL;

    if (cname == NULL || tm_name == NULL || pctx == NULL) {
        SCLogDebug("Counter name, tm name null or SCPerfContext NULL");
        return 0;
    }

    /* (SC_PERF_TYPE_MAX - 1) because we haven't implemented SC_PERF_TYPE_STR */
    if ((type >= (SC_PERF_TYPE_MAX - 1)) || (type < 0)) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Counters of type %" PRId32 " can't "
                   "be registered", type);
        return 0;
    }

    temp = prev = *head;
    while (temp != NULL) {
        prev = temp;

        if (strcmp(cname, temp->name->cname) == 0 &&
            strcmp(tm_name, temp->name->tm_name) == 0) {
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

    if ( (pc->name = SCMalloc(sizeof(SCPerfCounterName))) == NULL) {
        SCFree(pc);
        return 0;
    }
    memset(pc->name, 0, sizeof(SCPerfCounterName));

    if ( (pc->value = SCMalloc(sizeof(SCPerfCounterValue))) == NULL) {
        SCFree(pc->name);
        SCFree(pc);
        return 0;
    }
    memset(pc->value, 0, sizeof(SCPerfCounterValue));

    if ( (pc->name->cname = SCStrdup(cname)) == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
        exit(EXIT_FAILURE);
    }

    if ( (pc->name->tm_name = SCStrdup(tm_name)) == NULL) {
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

    if ( (pc->type_q = SCMalloc(sizeof(SCPerfCounterTypeQ))) == NULL)
        return 0;
    memset(pc->type_q, 0, sizeof(SCPerfCounterTypeQ));

    pc->type_q->type = type_q;

    /* handle timebased counters */
    if (pc->type_q->type & SC_PERF_TYPE_Q_TIMEBASED) {
        /* override for all timebased counters */
        type = SC_PERF_TYPE_DOUBLE;
        if (SCPerfParseTBCounterInterval(pc, interval) == -1) {
            SCPerfReleaseCounter(pc);
            return 0;
        }
    }

    /* allocate memory to hold this counter value */
    pc->value->type = type;
    switch (pc->value->type) {
        case SC_PERF_TYPE_UINT64:
            pc->value->size = sizeof(uint64_t);

            break;
        case SC_PERF_TYPE_DOUBLE:
            pc->value->size = sizeof(double);

            break;
    }

    if ( (pc->value->cvalue = SCMalloc(pc->value->size)) == NULL)
        return 0;
    memset(pc->value->cvalue, 0, pc->value->size);

    /* display flag which specifies if the counter should be displayed or not */
    pc->disp = 1;

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
 * \param reset_lc Flag which indicates if the values of the local counters
 *                 in the SCPerfCounterArray has to be reset or not
 */
static void SCPerfCopyCounterValue(SCPCAElem *pcae, int reset_lc)
{
    SCPerfCounter *pc = NULL;
    double d_temp = 0;
    uint64_t ui64_temp = 0;

    struct timeval curr_ts;

    uint64_t u = 0;

    pc = pcae->pc;
    switch (pc->value->type) {
        case SC_PERF_TYPE_UINT64:
            ui64_temp = pcae->ui64_cnt;

            if (pc->type_q->type & SC_PERF_TYPE_Q_AVERAGE) {
                for (u = 0; u < pcae->wrapped_syncs; u++)
                    ui64_temp /= ULONG_MAX;

                if (pcae->syncs != 0)
                    ui64_temp /= pcae->syncs;

                *((uint64_t *)pc->value->cvalue) = ui64_temp;
            } else if (pc->type_q->type & SC_PERF_TYPE_Q_TIMEBASED) {
                /* we have a timebased counter.  Awesome.  Time for some more processing */
                TimeGet(&curr_ts);
                pc->type_q->tbc_secs += ((curr_ts.tv_sec + curr_ts.tv_usec / 1000000.0) -
                                         (pcae->ts.tv_sec + pcae->ts.tv_usec / 1000000.0));

                /* special treatment for timebased counters.  We add instead of
                 * copying to the global counters.  The job of resetting the
                 * global counters is done by the output function */
                *((uint64_t *)pc->value->cvalue) += ui64_temp;
                pcae->ui64_cnt = 0;
                /* reset it to the current time */
                TimeGet(&pcae->ts);
            } else {
                *((uint64_t *)pc->value->cvalue) = ui64_temp;
            }

            if (reset_lc)
                pcae->ui64_cnt = 0;

            break;
        case SC_PERF_TYPE_DOUBLE:
            d_temp = pcae->d_cnt;

            if (pc->type_q->type & SC_PERF_TYPE_Q_AVERAGE) {
                for (u = 0; u < pcae->wrapped_syncs; u++)
                    d_temp /= ULONG_MAX;

                if (pcae->syncs != 0)
                    d_temp /= pcae->syncs;

                *((double *)pc->value->cvalue) = d_temp;
            } else if (pc->type_q->type & SC_PERF_TYPE_Q_TIMEBASED) {
                /* we have a timebased counter.  Awesome.  Time for some more processing */
                TimeGet(&curr_ts);
                pc->type_q->tbc_secs += ((curr_ts.tv_sec + curr_ts.tv_usec / 1000000.0) -
                                         (pcae->ts.tv_sec + pcae->ts.tv_usec / 1000000.0));

                /* special treatment for timebased counters.  We add instead of
                 * copying to the global counters.  The job of resetting the
                 * global counters is done by the output function */
                *((double *)pc->value->cvalue) += d_temp;
                pcae->d_cnt = 0;
                /* reset it to the current time */
                TimeGet(&pcae->ts);
            } else {
                *((double *)pc->value->cvalue) = d_temp;
            }

            if (reset_lc)
                pcae->d_cnt = 0;

            break;
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
static void SCPerfOutputCalculateCounterValue(SCPerfCounter *pc, void *cvalue_op)
{
    double divisor = 0;

    switch (pc->value->type) {
        case SC_PERF_TYPE_UINT64:
            *((uint64_t *)cvalue_op) = *((uint64_t *)pc->value->cvalue);

            break;
        case SC_PERF_TYPE_DOUBLE:
            *((double *)cvalue_op) = *((double *)pc->value->cvalue);

            break;
    }

    /* if we don't have a Timebased counter, we are out of here */
    if ( !(pc->type_q->type & SC_PERF_TYPE_Q_TIMEBASED))
        return;

    //if (pc->type_q->tbc_secs < pc->type_q->total_secs)
    //    return;

    divisor = pc->type_q->tbc_secs/pc->type_q->total_secs;
    divisor += ((double)(pc->type_q->tbc_secs % pc->type_q->total_secs)/
                pc->type_q->total_secs);

    switch (pc->value->type) {
        case SC_PERF_TYPE_UINT64:
            *((uint64_t *)cvalue_op) /= divisor;

            break;
        case SC_PERF_TYPE_DOUBLE:
            *((double *)cvalue_op) /= divisor;

            break;
    }

    pc->type_q->tbc_secs = 0;
    /* reset the local counter back to 0 */
    memset(pc->value->cvalue, 0, pc->value->size);

    return;
}

/**
 * \brief The file output interface for the Perf Counter api
 */
static int SCPerfOutputCounterFileIface()
{
    ThreadVars *tv = NULL;
    SCPerfClubTMInst *pctmi = NULL;
    SCPerfCounter *pc = NULL;
    SCPerfCounter **pc_heads = NULL;

    uint64_t ui64_temp = 0;
    uint64_t ui64_result = 0;

    double double_temp = 0;
    double double_result = 0;

    struct timeval tval;
    struct tm *tms;

    uint32_t u = 0;
    int flag = 0;

    if (sc_perf_op_ctx->fp == NULL) {
        SCLogDebug("perf_op_ctx->fp is NULL");
        return 0;
    }

    memset(&tval, 0, sizeof(struct timeval));

    gettimeofday(&tval, NULL);
    struct tm local_tm;
    tms = (struct tm *)SCLocalTime(tval.tv_sec, &local_tm);

    /* Calculate the Engine uptime */
    int up_time = (int)difftime(tval.tv_sec, sc_start_time);
    int sec = up_time % 60;     // Seconds in a minute
    int in_min = up_time / 60;
    int min = in_min % 60;      // Minutes in a hour
    int in_hours = in_min / 60;
    int hours = in_hours % 24;  // Hours in a day
    int days = in_hours / 24;

    fprintf(sc_perf_op_ctx->fp, "----------------------------------------------"
            "---------------------\n");
    fprintf(sc_perf_op_ctx->fp, "Date: %" PRId32 "/%" PRId32 "/%04d -- "
            "%02d:%02d:%02d (uptime: %"PRId32"d, %02dh %02dm %02ds)\n",
            tms->tm_mon + 1, tms->tm_mday, tms->tm_year + 1900, tms->tm_hour,
            tms->tm_min, tms->tm_sec, days, hours, min, sec);
    fprintf(sc_perf_op_ctx->fp, "----------------------------------------------"
            "---------------------\n");
    fprintf(sc_perf_op_ctx->fp, "%-25s | %-25s | %-s\n", "Counter", "TM Name",
            "Value");
    fprintf(sc_perf_op_ctx->fp, "----------------------------------------------"
            "---------------------\n");

    if (sc_perf_op_ctx->club_tm == 0) {
        for (u = 0; u < TVT_MAX; u++) {
            tv = tv_root[u];
            //if (pc_heads == NULL || pc_heads[u] == NULL)
            //    continue;

            while (tv != NULL) {
                SCMutexLock(&tv->sc_perf_pctx.m);
                pc = tv->sc_perf_pctx.head;

                while (pc != NULL) {
                    if (pc->disp == 0 || pc->value == NULL) {
                        pc = pc->next;
                        continue;
                    }

                    switch (pc->value->type) {
                        case SC_PERF_TYPE_UINT64:
                            SCPerfOutputCalculateCounterValue(pc,
                                    &ui64_temp);
                            fprintf(sc_perf_op_ctx->fp, "%-25s | %-25s | "
                                    "%-" PRIu64 "\n", pc->name->cname,
                                    pc->name->tm_name, ui64_temp);
                            break;
                        case SC_PERF_TYPE_DOUBLE:
                            SCPerfOutputCalculateCounterValue(pc,
                                    &double_temp);
                            fprintf(sc_perf_op_ctx->fp, "%-25s | %-25s |"
                                    " %-lf\n", pc->name->cname,
                                    pc->name->tm_name, double_temp);
                            break;
                    }

                    pc = pc->next;
                }

                SCMutexUnlock(&tv->sc_perf_pctx.m);
                tv = tv->next;
            }
            fflush(sc_perf_op_ctx->fp);
        }

        return 1;
    }

    pctmi = sc_perf_op_ctx->pctmi;
    while (pctmi != NULL) {
        if ((pc_heads = SCMalloc(pctmi->size * sizeof(SCPerfCounter *))) == NULL)
            return 0;
        memset(pc_heads, 0, pctmi->size * sizeof(SCPerfCounter *));

        for (u = 0; u < pctmi->size; u++) {
            pc_heads[u] = pctmi->head[u]->head;

            SCMutexLock(&pctmi->head[u]->m);

            while(pc_heads[u] != NULL && strcmp(pctmi->tm_name, pc_heads[u]->name->tm_name)) {
                pc_heads[u] = pc_heads[u]->next;
            }
        }

        flag = 1;
        while(flag) {
            ui64_result = 0;
            double_result = 0;
            if (pc_heads[0] == NULL)
                break;
            pc = pc_heads[0];

            for (u = 0; u < pctmi->size; u++) {
                switch (pc->value->type) {
                    case SC_PERF_TYPE_UINT64:
                        SCPerfOutputCalculateCounterValue(pc_heads[u], &ui64_temp);
                        ui64_result += ui64_temp;

                        break;
                    case SC_PERF_TYPE_DOUBLE:
                        SCPerfOutputCalculateCounterValue(pc_heads[u], &double_temp);
                        double_result += double_temp;

                        break;
                }

                if (pc_heads[u] != NULL)
                    pc_heads[u] = pc_heads[u]->next;

                if (pc_heads[u] == NULL ||
                    (pc_heads[0] != NULL &&
                        strcmp(pctmi->tm_name, pc_heads[0]->name->tm_name))) {
                    flag = 0;
                }
            }

            if (pc->disp == 0 || pc->value == NULL)
                continue;

            switch (pc->value->type) {
                case SC_PERF_TYPE_UINT64:
                    fprintf(sc_perf_op_ctx->fp, "%-25s | %-25s | %-" PRIu64 "\n",
                            pc->name->cname, pctmi->tm_name, ui64_result);

                    break;
                case SC_PERF_TYPE_DOUBLE:
                    fprintf(sc_perf_op_ctx->fp, "%-25s | %-25s | %0.0lf\n",
                            pc->name->cname, pctmi->tm_name, double_result);

                    break;
            }
        }

        for (u = 0; u < pctmi->size; u++)
            SCMutexUnlock(&pctmi->head[u]->m);

        pctmi = pctmi->next;

        SCFree(pc_heads);

        fflush(sc_perf_op_ctx->fp);
    }

    return 1;
}

#ifdef BUILD_UNIX_SOCKET
/**
 * \brief The file output interface for the Perf Counter api
 */
TmEcode SCPerfOutputCounterSocket(json_t *cmd,
                               json_t *answer, void *data)
{
    ThreadVars *tv = NULL;
    SCPerfClubTMInst *pctmi = NULL;
    SCPerfCounter *pc = NULL;
    SCPerfCounter **pc_heads = NULL;

    uint64_t ui64_temp = 0;
    uint64_t ui64_result = 0;

    double double_temp = 0;
    double double_result = 0;

    uint32_t u = 0;
    int flag = 0;

    if (sc_perf_op_ctx == NULL) {
        json_object_set_new(answer, "message",
                json_string("No performance counter context"));
        return TM_ECODE_FAILED;
    }

    if (sc_perf_op_ctx->club_tm == 0) {
        json_t *tm_array;

        tm_array = json_object();
        if (tm_array == NULL) {
            json_object_set_new(answer, "message",
                    json_string("internal error at json object creation"));
            return TM_ECODE_FAILED;
        }


        for (u = 0; u < TVT_MAX; u++) {
            tv = tv_root[u];
            //if (pc_heads == NULL || pc_heads[u] == NULL)
            //    continue;


            while (tv != NULL) {
                SCMutexLock(&tv->sc_perf_pctx.m);
                pc = tv->sc_perf_pctx.head;
                json_t *jdata;
                int filled = 0;
                jdata = json_object();
                if (jdata == NULL) {
                    json_decref(tm_array);
                    json_object_set_new(answer, "message",
                            json_string("internal error at json object creation"));
                    SCMutexUnlock(&tv->sc_perf_pctx.m);
                    return TM_ECODE_FAILED;
                }

                while (pc != NULL) {
                    if (pc->disp == 0 || pc->value == NULL) {
                        pc = pc->next;
                        continue;
                    }

                    switch (pc->value->type) {
                        case SC_PERF_TYPE_UINT64:
                            SCPerfOutputCalculateCounterValue(pc,
                                    &ui64_temp);
                            json_object_set_new(jdata, pc->name->cname, json_integer(ui64_temp));
                            filled = 1;
                            break;
                        case SC_PERF_TYPE_DOUBLE:
                            SCPerfOutputCalculateCounterValue(pc,
                                    &double_temp);
                            json_object_set_new(jdata, pc->name->cname, json_real(double_temp));
                            filled = 1;
                            break;
                    }
                    pc = pc->next;
                }

                SCMutexUnlock(&tv->sc_perf_pctx.m);
                if (filled == 1) {
                    json_object_set_new(tm_array, tv->name, jdata);
                }
                tv = tv->next;
            }
        }

        json_object_set_new(answer, "message", tm_array);
        return TM_ECODE_OK;
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

            while(pc_heads[u] != NULL && strcmp(pctmi->tm_name, pc_heads[u]->name->tm_name)) {
                pc_heads[u] = pc_heads[u]->next;
            }
        }

        flag = 1;
        while(flag) {
            ui64_result = 0;
            double_result = 0;
            if (pc_heads[0] == NULL)
                break;
            pc = pc_heads[0];

            for (u = 0; u < pctmi->size; u++) {
                switch (pc->value->type) {
                    case SC_PERF_TYPE_UINT64:
                        SCPerfOutputCalculateCounterValue(pc_heads[u], &ui64_temp);
                        ui64_result += ui64_temp;

                        break;
                    case SC_PERF_TYPE_DOUBLE:
                        SCPerfOutputCalculateCounterValue(pc_heads[u], &double_temp);
                        double_result += double_temp;

                        break;
                }

                if (pc_heads[u] != NULL)
                    pc_heads[u] = pc_heads[u]->next;

                if (pc_heads[u] == NULL ||
                    (pc_heads[0] != NULL &&
                        strcmp(pctmi->tm_name, pc_heads[0]->name->tm_name))) {
                    flag = 0;
                }
            }

            if (pc->disp == 0 || pc->value == NULL)
                continue;

            switch (pc->value->type) {
                case SC_PERF_TYPE_UINT64:
                    filled = 1;
                    json_object_set_new(jdata, pc->name->cname, json_integer(ui64_result));
                    break;
                case SC_PERF_TYPE_DOUBLE:
                    filled = 1;
                    json_object_set_new(jdata, pc->name->cname, json_real(double_result));
                    break;
            }
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
                                                 SC_PERF_TYPE_Q_NORMAL, NULL);

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
                                                 SC_PERF_TYPE_Q_AVERAGE, NULL);

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
                                                 SC_PERF_TYPE_Q_MAXIMUM, NULL);

    return id;
}

/**
 * \brief Registers a counter, whose value holds the value taken held the
 *        counter in a specified time interval
 *
 * \param cname    Name of the counter, to be registered
 * \param tv       Pointer to the ThreadVars instance for which the counter
 *                 would be registered
 * \param type     Datatype of this counter variable
 * \param desc     Description of this counter
 * \param interval The time interval over which the counter value has to be
 *                 calculated.  The format for the time interval is
 *                 "<number><modifier>", where number > 0, and modifier can
 *                 be "s" for seconds, "m" for minutes, "h" for hours
 *
 * \retval id Counter id for the newly registered counter, or the already
 *            present counter
 */
uint16_t SCPerfTVRegisterIntervalCounter(char *cname, struct ThreadVars_ *tv,
                                         int type, char *desc,
                                         char *time_interval)
{
    uint16_t id = SCPerfRegisterQualifiedCounter(cname,
                                                 (tv->thread_group_name != NULL) ? tv->thread_group_name : tv->name,
                                                 type, desc,
                                                 &tv->sc_perf_pctx,
                                                 SC_PERF_TYPE_Q_TIMEBASED |
                                                 SC_PERF_TYPE_Q_NORMAL,
                                                 time_interval);

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
                                                 pctx, SC_PERF_TYPE_Q_NORMAL,
                                                 NULL);

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
                                                 pctx, SC_PERF_TYPE_Q_AVERAGE,
                                                 NULL);

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
                                                 pctx, SC_PERF_TYPE_Q_MAXIMUM,
                                                 NULL);

    return id;
}

/**
 * \brief Registers a counter, whose value holds the value taken held the
 *        counter in a specified time interval
 *
 * \param cname   Name of the counter, to be registered
 * \param tm_name Name of the engine module under which the counter has to be
 *                registered
 * \param type    Datatype of this counter variable
 * \param desc    Description of this counter
 * \param pctx    SCPerfContext corresponding to the tm_name key under which the
 *                key has to be registered
 * \param interval The time interval over which the counter value has to be
 *                 calculated.  The format for the time interval is
 *                 "<number><modifier>", where number > 0, and modifier can
 *                 be "s" for seconds, "m" for minutes, "h" for hours
 *
 * \retval id Counter id for the newly registered counter, or the already
 *            present counter
 */
uint16_t SCPerfRegisterIntervalCounter(char *cname, char *tm_name, int type,
                                     char *desc, SCPerfContext *pctx,
                                     char *time_interval)
{
    uint16_t id = SCPerfRegisterQualifiedCounter(cname, tm_name, type, desc,
                                                 pctx,
                                                 SC_PERF_TYPE_Q_TIMEBASED |
                                                 SC_PERF_TYPE_Q_NORMAL,
                                                 time_interval);

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
            SCMutexUnlock(&sc_perf_op_ctx->pctmi_lock);
            return 0;
        }
        temp->head[0] = pctx;
        temp->tm_name = SCStrdup(tm_name);

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

    pctmi->head = SCRealloc(pctmi->head,
                          (pctmi->size + 1) * sizeof(SCPerfContext **));
    if (pctmi->head == NULL) {
        SCMutexUnlock(&sc_perf_op_ctx->pctmi_lock);
        return 0;
    }
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

    if ( (pca->head = SCMalloc(sizeof(SCPCAElem) * (e_id - s_id  + 2))) == NULL)
        return NULL;
    memset(pca->head, 0, sizeof(SCPCAElem) * (e_id - s_id  + 2));

    pc = pctx->head;
    while (pc->id != s_id)
        pc = pc->next;

    i = 1;
    while ((pc != NULL) && (pc->id <= e_id)) {
        pca->head[i].pc = pc;
        pca->head[i].id = pc->id;
        if (pc->type_q->type & SC_PERF_TYPE_Q_TIMEBASED)
            TimeGet(&pca->head[i].ts);
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
 * \brief Allows the user the set whether the counter identified with the id
 *        should be displayed or not in the output
 *
 * \param id   Id of the counter
 * \param pctx Pointer to the SCPerfContext in which the counter exists
 * \param disp Holds a 0 or a non-zero value, based on whether the counter
 *             should be displayed or not, in the output
 *
 * \retval 1 on success
 * \retval 0 on failure
 */
int SCPerfCounterDisplay(uint16_t id, SCPerfContext *pctx, int disp)
{
    SCPerfCounter *pc = NULL;

    if (pctx == NULL) {
        SCLogDebug("pctx null inside SCPerfCounterDisplay");
        return 0;
    }

    if ( (id < 1) || (id > pctx->curr_id) ) {
        SCLogDebug("counter with the id %d doesn't exist in this tm instance",
                   id);
        return 0;
    }

    pc = pctx->head;
    while(pc->id != id)
        pc = pc->next;

    pc->disp = (disp != 0);

    return 1;
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
int SCPerfUpdateCounterArray(SCPerfCounterArray *pca, SCPerfContext *pctx,
                             int reset_lc)
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

            SCPerfCopyCounterValue(&pcae[i], reset_lc);

            pc->updated++;

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
    if (pca == NULL) {
        SCLogDebug("pca NULL inside SCPerfUpdateCounterArray");
        return -1;
    }

    if ((id < 1) || (id > pca->size)) {
        SCLogDebug("counter doesn't exist");
        return -1;
    }

    /* we check the type of the counter.  Whether it's a counter that holds an
     * unsigned_int_64 value or double value */
    switch (pca->head[id].pc->value->type) {
        /* the counter holds an unsigned_int_64 value */
        case SC_PERF_TYPE_UINT64:
            return pca->head[id].ui64_cnt;
        /* the counter holds a double */
        case SC_PERF_TYPE_DOUBLE:
            return pca->head[id].d_cnt;
        default:
            /* this can never happen */
            return -1;
    }
}

/**
 * \brief The output interface dispatcher for the counter api
 */
void SCPerfOutputCounters()
{
    switch (sc_perf_op_ctx->iface) {
        case SC_PERF_IFACE_FILE:
            SCPerfOutputCounterFileIface();

            break;
        case SC_PERF_IFACE_CONSOLE:
            /* yet to be implemented */

            break;
        case SC_PERF_IFACE_SYSLOG:
            /* yet to be implemented */

            break;
    }

    return;
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

    SCPerfUpdateCounterArray(pca, &tv.sc_perf_pctx, 0);

    result = (1 == *((uint64_t *)tv.sc_perf_pctx.head->value->cvalue) );
    result &= (100 == *((uint64_t *)tv.sc_perf_pctx.head->next->value->cvalue) );
    result &= (101 == *((uint64_t *)tv.sc_perf_pctx.head->next->next->value->cvalue) );

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

    SCPerfUpdateCounterArray(pca, &tv.sc_perf_pctx, 0);

    uint64_t *u64p = (uint64_t *)tv.sc_perf_pctx.head->value->cvalue;
    result &= (1 == *u64p);

    u64p = (uint64_t *)tv.sc_perf_pctx.head->next->value->cvalue;
    result &= (256 == *u64p);

    u64p = (uint64_t *)tv.sc_perf_pctx.head->next->next->value->cvalue;
    result &= (257 == *u64p);

    u64p = (uint64_t *)tv.sc_perf_pctx.head->next->next->next->value->cvalue;
    result &= (16843024 == *u64p);

    SCPerfReleasePerfCounterS(tv.sc_perf_pctx.head);
    SCPerfReleasePCA(pca);

    return result;
}

static int SCPerfTestAverageQual12()
{
    ThreadVars tv;
    SCPerfCounterArray *pca = NULL;

    int result = 1;
    uint16_t id1, id2;

    memset(&tv, 0, sizeof(ThreadVars));

    id1 = SCPerfRegisterAvgCounter("t1", "c1", SC_PERF_TYPE_DOUBLE, NULL,
                                   &tv.sc_perf_pctx);
    id2 = SCPerfRegisterAvgCounter("t2", "c2", SC_PERF_TYPE_UINT64, NULL,
                                   &tv.sc_perf_pctx);

    pca = SCPerfGetAllCountersArray(&tv.sc_perf_pctx);

    SCPerfCounterAddDouble(id1, pca, 1);
    SCPerfCounterAddDouble(id1, pca, 2);
    SCPerfCounterAddDouble(id1, pca, 3);
    SCPerfCounterAddDouble(id1, pca, 4);
    SCPerfCounterAddDouble(id1, pca, 5);
    SCPerfCounterAddDouble(id1, pca, 6);

    SCPerfUpdateCounterArray(pca, &tv.sc_perf_pctx, 0);

    result &= (21 == pca->head[1].d_cnt);
    result &= (6 == pca->head[1].syncs);
    result &= (0 == pca->head[1].wrapped_syncs);
    result &= (3.5 == *((double *)tv.sc_perf_pctx.head->value->cvalue) );

    SCPerfCounterAddUI64(id2, pca, (uint64_t)1.635);
    SCPerfCounterAddUI64(id2, pca, (uint64_t)2.12);
    SCPerfCounterAddUI64(id2, pca, (uint64_t)3.74);
    SCPerfCounterAddUI64(id2, pca, (uint64_t)4.23);
    SCPerfCounterAddUI64(id2, pca, (uint64_t)5.76);
    SCPerfCounterAddDouble(id2, pca, 6.99999);

    SCPerfUpdateCounterArray(pca, &tv.sc_perf_pctx, 0);

    result &= (21 == pca->head[2].ui64_cnt);
    result &= (6 == pca->head[2].syncs);
    result &= (0 == pca->head[2].wrapped_syncs);
    result &= (3 == *((uint64_t *)tv.sc_perf_pctx.head->next->value->cvalue));

    return result;
}

static int SCPerfTestMaxQual13()
{
    ThreadVars tv;
    SCPerfCounterArray *pca = NULL;

    int result = 1;
    uint16_t id1;

    memset(&tv, 0, sizeof(ThreadVars));

    id1 = SCPerfRegisterMaxCounter("t1", "c1", SC_PERF_TYPE_DOUBLE, NULL,
                                   &tv.sc_perf_pctx);

    pca = SCPerfGetAllCountersArray(&tv.sc_perf_pctx);

    SCPerfCounterSetDouble(id1, pca, 1.352);
    SCPerfCounterSetDouble(id1, pca, 5.12412);
    SCPerfCounterSetDouble(id1, pca, 4.1234);
    SCPerfCounterSetDouble(id1, pca, 5.13562);
    SCPerfCounterSetDouble(id1, pca, 1.2342);

    SCPerfUpdateCounterArray(pca, &tv.sc_perf_pctx, 0);
    result &= (5.13562 == *((double *)tv.sc_perf_pctx.head->value->cvalue));

    SCPerfCounterSetDouble(id1, pca, 8);
    SCPerfCounterSetDouble(id1, pca, 7);

    SCPerfUpdateCounterArray(pca, &tv.sc_perf_pctx, 0);
    result &= (8 == *((double *)tv.sc_perf_pctx.head->value->cvalue));

    SCPerfCounterSetDouble(id1, pca, 6);
    SCPerfCounterSetUI64(id1, pca, 10);
    SCPerfCounterSetDouble(id1, pca, 9.562);

    SCPerfUpdateCounterArray(pca, &tv.sc_perf_pctx, 0);
    result &= (10 == *((double *)tv.sc_perf_pctx.head->value->cvalue));

    return result;
}

static int SCPerfTestIntervalQual14()
{
    ThreadVars tv;
    int result = 1;

    memset(&tv, 0, sizeof(ThreadVars));
    SCPerfRegisterIntervalCounter("t1", "c1", SC_PERF_TYPE_DOUBLE, NULL,
                                  &tv.sc_perf_pctx, "10s");

    result &= (tv.sc_perf_pctx.head->type_q->hours == 0);
    result &= (tv.sc_perf_pctx.head->type_q->minutes == 0);
    result &= (tv.sc_perf_pctx.head->type_q->seconds == 10);

    SCPerfReleasePerfCounterS(tv.sc_perf_pctx.head);


    memset(&tv, 0, sizeof(ThreadVars));
    SCPerfRegisterIntervalCounter("t1", "c1", SC_PERF_TYPE_DOUBLE, NULL,
                                  &tv.sc_perf_pctx, "20h10s");

    result &= (tv.sc_perf_pctx.head->type_q->hours == 20);
    result &= (tv.sc_perf_pctx.head->type_q->minutes == 0);
    result &= (tv.sc_perf_pctx.head->type_q->seconds == 10);

    SCPerfReleasePerfCounterS(tv.sc_perf_pctx.head);


    memset(&tv, 0, sizeof(ThreadVars));
    SCPerfRegisterIntervalCounter("t1", "c1", SC_PERF_TYPE_DOUBLE, NULL,
                                  &tv.sc_perf_pctx, "20h30m10s");

    result &= (tv.sc_perf_pctx.head->type_q->hours == 20);
    result &= (tv.sc_perf_pctx.head->type_q->minutes == 30);
    result &= (tv.sc_perf_pctx.head->type_q->seconds == 10);

    SCPerfReleasePerfCounterS(tv.sc_perf_pctx.head);


    memset(&tv, 0, sizeof(ThreadVars));
    SCPerfRegisterIntervalCounter("t1", "c1", SC_PERF_TYPE_DOUBLE, NULL,
                                  &tv.sc_perf_pctx, "30m10s");

    result &= (tv.sc_perf_pctx.head->type_q->hours == 0);
    result &= (tv.sc_perf_pctx.head->type_q->minutes == 30);
    result &= (tv.sc_perf_pctx.head->type_q->seconds == 10);

    SCPerfReleasePerfCounterS(tv.sc_perf_pctx.head);

    return result;
}

static int SCPerfTestIntervalQual15()
{
    ThreadVars tv;
    int result = 1;

    memset(&tv, 0, sizeof(ThreadVars));
    result &= (SCPerfRegisterIntervalCounter("t1", "c1", SC_PERF_TYPE_DOUBLE, NULL,
                                             &tv.sc_perf_pctx, "25h") == 0);
    result &= (tv.sc_perf_pctx.head == NULL);

    memset(&tv, 0, sizeof(ThreadVars));
    result &= (SCPerfRegisterIntervalCounter("t1", "c1", SC_PERF_TYPE_DOUBLE, NULL,
                                             &tv.sc_perf_pctx, "24h61m") == 0);
    result &= (tv.sc_perf_pctx.head == NULL);

    memset(&tv, 0, sizeof(ThreadVars));
    result &= (SCPerfRegisterIntervalCounter("t1", "c1", SC_PERF_TYPE_DOUBLE, NULL,
                                             &tv.sc_perf_pctx, "24h60m") == 0);
    result &= (tv.sc_perf_pctx.head == NULL);

    memset(&tv, 0, sizeof(ThreadVars));
    result &= (SCPerfRegisterIntervalCounter("t1", "c1", SC_PERF_TYPE_DOUBLE, NULL,
                                             &tv.sc_perf_pctx, "24h58m61s") == 0);
    result &= (tv.sc_perf_pctx.head == NULL);

    memset(&tv, 0, sizeof(ThreadVars));
    result &= (SCPerfRegisterIntervalCounter("t1", "c1", SC_PERF_TYPE_DOUBLE, NULL,
                                             &tv.sc_perf_pctx, "24h61m60s") == 0);
    result &= (tv.sc_perf_pctx.head == NULL);

    memset(&tv, 0, sizeof(ThreadVars));
    result &= (SCPerfRegisterIntervalCounter("t1", "c1", SC_PERF_TYPE_DOUBLE, NULL,
                                             &tv.sc_perf_pctx, "") == 0);
    result &= (tv.sc_perf_pctx.head == NULL);

    memset(&tv, 0, sizeof(ThreadVars));
    result &= (SCPerfRegisterIntervalCounter("t1", "c1", SC_PERF_TYPE_DOUBLE, NULL,
                                             &tv.sc_perf_pctx, "24h61ms") == 0);
    result &= (tv.sc_perf_pctx.head == NULL);

    memset(&tv, 0, sizeof(ThreadVars));
    result &= (SCPerfRegisterIntervalCounter("t1", "c1", SC_PERF_TYPE_DOUBLE, NULL,
                                             &tv.sc_perf_pctx, "236m") == 0);
    result &= (tv.sc_perf_pctx.head == NULL);

    memset(&tv, 0, sizeof(ThreadVars));
    result &= (SCPerfRegisterIntervalCounter("t1", "c1", SC_PERF_TYPE_DOUBLE, NULL,
                                             &tv.sc_perf_pctx, "67s") == 0);
    result &= (tv.sc_perf_pctx.head == NULL);

    memset(&tv, 0, sizeof(ThreadVars));
    result &= (SCPerfRegisterIntervalCounter("t1", "c1", SC_PERF_TYPE_DOUBLE, NULL,
                                             &tv.sc_perf_pctx, "0h0m0s") == 0);
    result &= (tv.sc_perf_pctx.head == NULL);

    return result;
}

static int SCPerfTestIntervalQual16()
{
    ThreadVars tv;
    SCPerfCounterArray *pca = NULL;
    double d_temp = 0;

    int result = 1;
    uint16_t id1;

    memset(&tv, 0, sizeof(ThreadVars));

    id1 = SCPerfRegisterIntervalCounter("t1", "c1", SC_PERF_TYPE_DOUBLE, NULL,
                                        &tv.sc_perf_pctx, "3s");

    pca = SCPerfGetAllCountersArray(&tv.sc_perf_pctx);

    SCPerfCounterAddDouble(id1, pca, 1);
    SCPerfCounterAddDouble(id1, pca, 2);
    SCPerfCounterAddDouble(id1, pca, 3);
    SCPerfCounterAddDouble(id1, pca, 4);
    SCPerfCounterAddDouble(id1, pca, 5);
    SCPerfCounterAddDouble(id1, pca, 6);

    /* forward the time 6 seconds */
    TimeSetIncrementTime(6);

    SCPerfUpdateCounterArray(pca, &tv.sc_perf_pctx, 0);

    SCPerfOutputCalculateCounterValue(tv.sc_perf_pctx.head, &d_temp);

    result &= (d_temp > 10 && d_temp < 11);

    return result;
}

static int SCPerfTestIntervalQual17()
{
    ThreadVars tv;
    SCPerfCounterArray *pca = NULL;
    double d_temp = 0;

    uint16_t id1;

    memset(&tv, 0, sizeof(ThreadVars));

    id1 = SCPerfRegisterIntervalCounter("t1", "c1", SC_PERF_TYPE_DOUBLE, NULL,
                                        &tv.sc_perf_pctx, "2m30s");

    pca = SCPerfGetAllCountersArray(&tv.sc_perf_pctx);

    SCPerfCounterAddDouble(id1, pca, 1);
    SCPerfCounterAddDouble(id1, pca, 2);
    SCPerfCounterAddDouble(id1, pca, 3);
    SCPerfCounterAddDouble(id1, pca, 4);
    SCPerfCounterAddDouble(id1, pca, 5);
    SCPerfCounterAddDouble(id1, pca, 6);

    /* forward the time 3 seconds */
    TimeSetIncrementTime(3);

    SCPerfUpdateCounterArray(pca, &tv.sc_perf_pctx, 0);

    SCPerfOutputCalculateCounterValue(tv.sc_perf_pctx.head, &d_temp);

    return (d_temp == 1050.0);
}

static int SCPerfTestIntervalQual18()
{
    ThreadVars tv;
    SCPerfCounterArray *pca = NULL;
    double d_temp = 0;
    int result = 1;

    uint16_t id1;

    memset(&tv, 0, sizeof(ThreadVars));

    id1 = SCPerfRegisterIntervalCounter("t1", "c1", SC_PERF_TYPE_DOUBLE, NULL,
                                        &tv.sc_perf_pctx, "3s");

    pca = SCPerfGetAllCountersArray(&tv.sc_perf_pctx);

    SCPerfCounterAddDouble(id1, pca, 1);
    SCPerfCounterAddDouble(id1, pca, 2);
    SCPerfCounterAddDouble(id1, pca, 3);
    SCPerfCounterAddDouble(id1, pca, 4);
    SCPerfCounterAddDouble(id1, pca, 5);
    SCPerfCounterAddDouble(id1, pca, 6);

    /* forward the time 3 seconds */
    TimeSetIncrementTime(3);

    SCPerfUpdateCounterArray(pca, &tv.sc_perf_pctx, 0);

    SCPerfCounterAddDouble(id1, pca, 1);
    SCPerfCounterAddDouble(id1, pca, 2);
    SCPerfCounterAddDouble(id1, pca, 3);

    /* forward the time 3 seconds */
    TimeSetIncrementTime(3);

    SCPerfUpdateCounterArray(pca, &tv.sc_perf_pctx, 0);

    SCPerfCounterAddDouble(id1, pca, 3);
    SCPerfCounterAddDouble(id1, pca, 3);

    /* forward the time 3 seconds */
    TimeSetIncrementTime(3);

    SCPerfOutputCalculateCounterValue(tv.sc_perf_pctx.head, &d_temp);

    result &= (d_temp == 13.5);

    SCPerfCounterAddDouble(id1, pca, 1);
    SCPerfCounterAddDouble(id1, pca, 2);
    SCPerfCounterAddDouble(id1, pca, 3);

    /* forward the time 3 seconds */
    TimeSetIncrementTime(3);

    SCPerfUpdateCounterArray(pca, &tv.sc_perf_pctx, 0);

    SCPerfCounterAddDouble(id1, pca, 1);
    SCPerfCounterAddDouble(id1, pca, 2);
    SCPerfCounterAddDouble(id1, pca, 3);

    /* forward the time 1 second */
    TimeSetIncrementTime(1);

    SCPerfOutputCalculateCounterValue(tv.sc_perf_pctx.head, &d_temp);

    result &= (d_temp == 6);

    SCPerfCounterAddDouble(id1, pca, 2);

    /* forward the time 1 second */
    TimeSetIncrementTime(1);

    SCPerfUpdateCounterArray(pca, &tv.sc_perf_pctx, 0);

    SCPerfOutputCalculateCounterValue(tv.sc_perf_pctx.head, &d_temp);

    result &= (d_temp == 12.0);

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
    UtRegisterTest("SCPerfTestAverageQual12", SCPerfTestAverageQual12, 1);
    UtRegisterTest("SCPerfTestMaxQual13", SCPerfTestMaxQual13, 1);
    UtRegisterTest("SCPerfTestIntervalQual14", SCPerfTestIntervalQual14, 1);
    UtRegisterTest("SCPerfTestIntervalQual15", SCPerfTestIntervalQual15, 1);
    UtRegisterTest("SCPerfTestIntervalQual16", SCPerfTestIntervalQual16, 1);
    UtRegisterTest("SCPerfTestIntervalQual17", SCPerfTestIntervalQual17, 1);
    UtRegisterTest("SCPerfTestIntervalQual18", SCPerfTestIntervalQual18, 1);
#endif
}
