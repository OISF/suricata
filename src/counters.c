#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/time.h>
#include <limits.h>
#include "time.h"

#include "eidps.h"
#include "counters.h"
#include "threadvars.h"
#include "tm-modules.h"
#include "tm-threads.h"
#include "util-unittest.h"
#include "conf.h"

/** \todo Get the default log directory from some global resource. */
#define DEFAULT_LOG_FILENAME "stats.log"

static PerfOPIfaceContext *perf_op_ctx = NULL;

/**
 * \brief Get the filename with path to the stats log file.
 *
 * This function returns a string containing the log filename.  It
 * uses allocated memory simply to drop into the existing code a
 * little better where a strdup was used.  So as before, it is up to
 * the caller to free the memory.
 *
 * \retval An allocated string containing the log filename or NULL on
 * a failure.
 */
static char *
PerfGetLogFilename(void)
{
    char *log_dir;
    char *log_filename;

    if (ConfGet("default-log-dir", &log_dir) != 1)
        log_dir = DEFAULT_LOG_DIR;
    log_filename = malloc(PATH_MAX);
    if (log_filename == NULL)
        return NULL;
    snprintf(log_filename, PATH_MAX, "%s/%s", log_dir, DEFAULT_LOG_FILENAME);

    return log_filename;
}

/**
 * \brief Initializes the perf counter api.  Things are hard coded currently.
 *        More work to be done when we implement multiple interfaces
 */
void PerfInitCounterApi(void)
{
    PerfInitOPCtx();

    return;
}

/**
 * \brief Initializes the output interface context
 */
void PerfInitOPCtx(void)
{
    if ( (perf_op_ctx = malloc(sizeof(PerfOPIfaceContext))) == NULL) {
        printf("error allocating memory\n");
        exit(0);
    }
    memset(perf_op_ctx, 0, sizeof(PerfOPIfaceContext));

    perf_op_ctx->iface = IFACE_FILE;

    if ( (perf_op_ctx->file = PerfGetLogFilename()) == NULL) {
        printf("error allocating memory\n");
        exit(0);
    }

    if ( (perf_op_ctx->fp = fopen(perf_op_ctx->file, "w+")) == NULL) {
        printf("fopen error opening file %s\n", perf_op_ctx->file);
        exit(0);
    }

    /* club the counter from multiple instances of the tm before o/p */
    perf_op_ctx->club_tm = 1;

    /* init the lock used by PerfClubTMInst */
    if (pthread_mutex_init(&perf_op_ctx->pctmi_lock, NULL) != 0) {
        printf("error initializing the pctmi mutex\n");
        exit(0);
    }

    return;
}

/**
 * \brief Spawns the wakeup, and the management thread
 */
void PerfSpawnThreads(void)
{
    ThreadVars *tv_wakeup = NULL;
    ThreadVars *tv_mgmt = NULL;

    /* Spawn the stats wakeup thread */
    tv_wakeup = TmThreadCreateMgmtThread("PerfWakeupThread", PerfWakeupThread, 1);
    if (tv_wakeup == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(1);
    }
    if (TmThreadSpawn(tv_wakeup) != 0) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(1);
    }

    /* Spawn the stats mgmt thread */
    tv_mgmt = TmThreadCreateMgmtThread("PerfMgmtThread", PerfMgmtThread, 1);
    if (tv_mgmt == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(1);
    }
    if (TmThreadSpawn(tv_mgmt) != 0) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(1);
    }

    return;
}

/**
 * \brief The management thread. This thread is responsible for writing the
 *        performance stats information.
 *
 * \param arg is NULL always
 */
void * PerfMgmtThread(void *arg)
{
    ThreadVars *tv_local = (ThreadVars *)arg;
    uint8_t run = 1;
    struct timespec cond_time;

    printf("PerfMgmtThread: spawned\n");

    if (perf_op_ctx == NULL) {
        printf("error: PerfInitCounterApi() has to be called first\n");
        return NULL;
    }

    tv_local->flags |= THV_INIT_DONE;
    while (run) {
        TmThreadTestThreadUnPaused(tv_local);

        cond_time.tv_sec = time(NULL) + MGMTT_TTS;
        cond_time.tv_nsec = 0;

        pthread_mutex_lock(tv_local->m);
        pthread_cond_timedwait(tv_local->cond, tv_local->m, &cond_time);
        pthread_mutex_unlock(tv_local->m);

        // sleep(MGMTT_TTS);

        PerfOutputCounters();

        if (tv_local->flags & THV_KILL) {
            tv_local->flags |= THV_CLOSED;
            run = 0;
        }
    }

    return NULL;
}

/**
 * \brief Wake up thread.  This thread wakes up every TTS(time to sleep) seconds
 *        and sets the flag for every ThreadVars' PerfContext
 *
 * \param arg is NULL always
 */
void * PerfWakeupThread(void *arg)
{
    ThreadVars *tv_local = (ThreadVars *)arg;
    uint8_t run = 1;
    ThreadVars *tv = NULL;
    PacketQueue *q = NULL;
    struct timespec cond_time;

    printf("PerfWakeupThread: spawned\n");

    tv_local->flags |= THV_INIT_DONE;
    while (run) {
        TmThreadTestThreadUnPaused(tv_local);

        cond_time.tv_sec = time(NULL) + WUT_TTS;
        cond_time.tv_nsec = 0;

        pthread_mutex_lock(tv_local->m);
        pthread_cond_timedwait(tv_local->cond, tv_local->m, &cond_time);
        pthread_mutex_unlock(tv_local->m);

        // sleep(WUT_TTS);

        tv = tv_root[TVT_PPT];
        while (tv != NULL) {
            if (tv->inq == NULL || tv->pctx.head == NULL) {
                tv = tv->next;
                continue;
            }

            q = &trans_q[tv->inq->id];

            /* assuming the assignment of an int to be atomic, and even if it's
               not, it should be okay */
            tv->pctx.perf_flag = 1;

            pthread_cond_signal(&q->cond_q);

            tv = tv->next;
        }

        if (tv_local->flags & THV_KILL) {
            tv_local->flags |= THV_CLOSED;
            run = 0;
        }
    }

    return NULL;
}

/**
 * \brief Registers a counter
 *
 * \param cname   Counter name to be registered
 * \param tm_name Thread module name
 * \param type    Datatype of this counter variable
 * \param desc    Description of this counter
 * \param pctx    PerfContext for this tm-tv instance
 * \param type_q  Qualifier describing the counter to be registered
 *
 * \retval the counter id
 */
static uint16_t PerfRegisterQualifiedCounter(char *cname, char *tm_name,
                                              int type, char *desc,
                                              PerfContext *pctx, int type_q)
{
    PerfCounter **head = &pctx->head;
    PerfCounter *temp = NULL;
    PerfCounter *prev = NULL;
    PerfCounter *pc = NULL;

    if (cname == NULL || tm_name == NULL || pctx == NULL) {
#ifdef DEBUG
        printf("counter name, tm name null or PerfContext NULL\n");
#endif
        return 0;
    }

    /* (TYPE_MAX - 1) because we still haven't implemented TYPE_STR */
    if ((type >= (TYPE_MAX - 1)) || (type < 0)) {
#ifdef DEBUG
        printf("Error: Counters of type %" PRId32 " can't be registered\n", type);
#endif
        return 0;
    }

    temp = prev = *head;
    while (temp != NULL) {
        prev = temp;

        if (strcmp(cname, temp->name->cname) == 0 &&
            strcmp(tm_name, temp->name->tm_name) == 0)
            break;

        temp = temp->next;
    }

    /* We already have a counter registered by this name */
    if (temp != NULL)
        return(temp->id);

    if ( (pc = malloc(sizeof(PerfCounter))) == NULL) {
        printf("error allocating memory\n");
        exit(0);
    }
    memset(pc, 0, sizeof(PerfCounter));

    if (prev == NULL) {
        *head = pc;
    }
    else
        prev->next = pc;

    if( (pc->name = malloc(sizeof(PerfCounterName))) == NULL) {
        printf("error allocating memory.  aborting\n");
        free(pc);
        exit(0);
    }
    memset(pc->name, 0, sizeof(PerfCounterName));

    if ( (pc->value = malloc(sizeof(PerfCounterValue))) == NULL) {
        printf("error allocating memory. aborting\n");
        free(pc->name);
        free(pc);
        exit(0);
    }
    memset(pc->value, 0, sizeof(PerfCounterValue));

    pc->name->cname = strdup(cname);
    pc->name->tm_name = strdup(tm_name);
    pc->name->tid = pthread_self();

    pc->value->type = type;
    switch(pc->value->type) {
        case TYPE_UINT64:
            pc->value->size = sizeof(uint64_t);
            break;
        case TYPE_DOUBLE:
            pc->value->size = sizeof(double);
            break;
    }
    if ( (pc->value->cvalue = malloc(pc->value->size)) == NULL) {
        printf("error allocating memory\n");
        exit(0);
    }
    memset(pc->value->cvalue, 0, pc->value->size);

    /* assign a unique id to this PerfCounter.  The id is local to this tv.
       please note that the ids start from 1 and not 0 */
    pc->id = ++(pctx->curr_id);

    if (desc != NULL)
        pc->desc = strdup(desc);

    pc->type_q = type_q;

    pc->disp = 1;

    return pc->id;
}

uint16_t PerfTVRegisterCounter(char *cname, struct ThreadVars_ *tv, int type,
                                char *desc)
{
    return PerfRegisterQualifiedCounter(cname, tv->name, type, desc,
                                        &tv->pctx, TYPE_Q_NORMAL);
}

uint16_t PerfTVRegisterAvgCounter(char *cname, struct ThreadVars_ *tv,
                                   int type, char *desc)
{
    return PerfRegisterQualifiedCounter(cname, tv->name, type, desc,
                                        &tv->pctx, TYPE_Q_AVERAGE);
}

uint16_t PerfTVRegisterMaxCounter(char *cname, struct ThreadVars_ *tv,
                                   int type, char *desc)
{
    return PerfRegisterQualifiedCounter(cname, tv->name, type, desc,
                                        &tv->pctx, TYPE_Q_MAXIMUM);
}

uint16_t PerfRegisterCounter(char *cname, char *tm_name, int type, char *desc,
                              PerfContext *pctx)
{
    return PerfRegisterQualifiedCounter(cname, tm_name, type, desc,
                                        pctx, TYPE_Q_NORMAL);
}

uint16_t PerfRegisterAvgCounter(char *cname, char *tm_name, int type,
                                 char *desc, PerfContext *pctx)
{
    return PerfRegisterQualifiedCounter(cname, tm_name, type, desc,
                                        pctx, TYPE_Q_AVERAGE);
}

uint16_t PerfRegisterMaxCounter(char *cname, char *tm_name, int type,
                                 char *desc, PerfContext *pctx)
{
    return PerfRegisterQualifiedCounter(cname, tm_name, type, desc,
                                        pctx, TYPE_Q_MAXIMUM);
}

/**
 * \brief Allows the user the set whether the counter identified with the id
 *        should be displayed or not in the output
 *
 * \param id   Id of the counter
 * \param pctx Pointer to the PerfContext in which the counter exists
 * \param disp Holds a 0 or a non-zero value, based on whether the counter
 *             should be displayed or not in the output
 *
 * \retval 1 on success, 0 on failure
 */
int PerfCounterDisplay(uint16_t id, PerfContext *pctx, int disp)
{
    PerfCounter *pc = NULL;

    if (pctx == NULL) {
#ifdef DEBUG
        printf("pctx null inside PerfCounterDisplay\n");
#endif
        return 0;
    }

    if ( (id < 1) || (id > pctx->curr_id) ) {
#ifdef DEBUG
        printf("counter with the id %d doesn't exist in this tm instance", id);
#endif
        return 0;
    }

    pc = pctx->head;
    while(pc->id != id)
        pc = pc->next;

    pc->disp = (disp != 0);

    return 1;
}

/**
 * \brief Increments the local counter
 *
 * \param id  Index of the counter in the counter array
 * \param pca Counter array that holds the local counters for this TM
 */
inline void PerfCounterIncr(uint16_t id, PerfCounterArray *pca)
{
    if (!pca) {
#ifdef DEBUG
        printf("counterarray is NULL\n");
#endif
        return;
    }
    if ((id < 1) || (id > pca->size)) {
#ifdef DEBUG
        printf("counter doesn't exist\n");
#endif
        return;
    }

    switch (pca->head[id].pc->value->type) {
        case TYPE_UINT64:
            pca->head[id].ui64_cnt++;
            break;
        case TYPE_DOUBLE:
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
 * \brief Adds a value of type uint64_t to the local counter.
 *
 * \param id  ID of the counter as set by the API
 * \param pca Counter array that holds the local counter for this TM
 * \param x   Value to add to this local counter
 */
inline void PerfCounterAddUI64(uint16_t id, PerfCounterArray *pca, uint64_t x)
{
    if (!pca) {
#ifdef DEBUG
        printf("counterarray is NULL\n");
#endif
        return;
    }
    if ((id < 1) || (id > pca->size)) {
#ifdef DEBUG
        printf("counter doesn't exist\n");
#endif
        return;
    }

    switch (pca->head[id].pc->value->type) {
        case TYPE_UINT64:
            pca->head[id].ui64_cnt += x;
            break;
        case TYPE_DOUBLE:
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
inline void PerfCounterAddDouble(uint16_t id, PerfCounterArray *pca, double x)
{
    if (!pca) {
#ifdef DEBUG
        printf("counterarray is NULL\n");
#endif
        return;
    }
    if ((id < 1) || (id > pca->size)) {
#ifdef DEBUG
        printf("counter doesn't exist\n");
#endif
        return;
    }

    /* incase you are trying to add a double to a counter of type TYPE_UINT64
       it will be truncated */
    switch (pca->head[id].pc->value->type) {
        case TYPE_UINT64:
            pca->head[id].ui64_cnt += x;
            break;
        case TYPE_DOUBLE:
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
 * \brief Sets a local counter to an arg of type double
 *
 * \param id  Index of the local counter in the counter array
 * \param pca Pointer to the PerfCounterArray
 * \param x   The value to set for the counter
 */
inline void PerfCounterSetUI64(uint16_t id, PerfCounterArray *pca,
                               uint64_t x)
{
    if (!pca) {
#ifdef DEBUG
        printf("counterarray is NULL\n");
#endif
        return;
    }

    if ((id < 1) || (id > pca->size)) {
#ifdef DEBUG
        printf("counter doesn't exist\n");
#endif
        return;
    }

    switch (pca->head[id].pc->value->type) {
        case TYPE_UINT64:
            if (pca->head[id].pc->type_q & TYPE_Q_MAXIMUM) {
                if (x > pca->head[id].ui64_cnt)
                    pca->head[id].ui64_cnt = x;
            } else if (pca->head[id].pc->type_q & TYPE_Q_NORMAL)
                pca->head[id].ui64_cnt = x;
            break;
        case TYPE_DOUBLE:
            if (pca->head[id].pc->type_q & TYPE_Q_MAXIMUM) {
                if (x > pca->head[id].d_cnt)
                    pca->head[id].d_cnt = x;
            } else if (pca->head[id].pc->type_q & TYPE_Q_NORMAL)
                pca->head[id].d_cnt = x;
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
 * \param pca Pointer to the PerfCounterArray
 * \param x   The value to set for the counter
 */
inline void PerfCounterSetDouble(uint16_t id, PerfCounterArray *pca,
                                 double x)
{
    if (!pca) {
#ifdef DEBUG
        printf("counterarray is NULL\n");
#endif
        return;
    }

    if ((id < 1) || (id > pca->size)) {
#ifdef DEBUG
        printf("counter doesn't exist\n");
#endif
        return;
    }

    switch (pca->head[id].pc->value->type) {
        case TYPE_UINT64:
            if (pca->head[id].pc->type_q & TYPE_Q_MAXIMUM) {
                if (x > pca->head[id].ui64_cnt)
                    pca->head[id].ui64_cnt = x;
            } else if (pca->head[id].pc->type_q & TYPE_Q_NORMAL)
                pca->head[id].ui64_cnt = x;
            break;
        case TYPE_DOUBLE:
            if (pca->head[id].pc->type_q & TYPE_Q_MAXIMUM) {
                if (x > pca->head[id].d_cnt)
                    pca->head[id].d_cnt = x;
            } else if (pca->head[id].pc->type_q & TYPE_Q_NORMAL)
                pca->head[id].d_cnt = x;
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
 * \brief Adds a TM to the clubbed TM table.  Multiple instances of the same TM
 *        are stacked together in a PCTMI container
 *
 * \param tm_name Name of the tm to be added to the table
 * \param pctx    PerfContext associated with the TM tm_name
 *
 * \retval 1 on success, 0 on failure
 */
int PerfAddToClubbedTMTable(char *tm_name, PerfContext *pctx)
{
    PerfClubTMInst *pctmi = NULL;
    PerfClubTMInst *prev = NULL;
    PerfClubTMInst *temp = NULL;
    PerfContext **hpctx;
    int i = 0;

    if (tm_name == NULL || pctx == NULL) {
#ifdef DEBUG
        printf("Supplied argument(s) to PerfAddToClubbedTMTable NULL\n");
#endif
        return 0;
    }

    pthread_mutex_lock(&perf_op_ctx->pctmi_lock);

    pctmi = perf_op_ctx->pctmi;
    prev = pctmi;

    while (pctmi != NULL) {
        prev = pctmi;
        if (strcmp(tm_name, pctmi->tm_name) != 0) {
            pctmi = pctmi->next;
            continue;
        }
        break;
    }

    if (pctmi == NULL) {
        if ( (temp = malloc(sizeof(PerfClubTMInst))) == NULL) {
            printf("error allocating memory\n");
            exit(0);
        }
        memset(temp, 0, sizeof(PerfClubTMInst));

        temp->size++;
        temp->head = realloc(temp->head, temp->size * sizeof(PerfContext **));
        temp->head[0] = pctx;
        temp->tm_name = strdup(tm_name);

        if (prev == NULL)
            perf_op_ctx->pctmi = temp;
        else
            prev->next = temp;

        pthread_mutex_unlock(&perf_op_ctx->pctmi_lock);
        return 1;
    }

    hpctx = pctmi->head;
    for (i = 0; i < pctmi->size; i++) {
        if (hpctx[i] != pctx)
            continue;

        pthread_mutex_unlock(&perf_op_ctx->pctmi_lock);
        return 1;
    }

    pctmi->head = realloc(pctmi->head, (pctmi->size + 1) *
                          sizeof(PerfContext **));
    hpctx = pctmi->head;

    hpctx[pctmi->size] = pctx;
    for (i = pctmi->size - 1; i >= 0; i--) {
        if (pctx->curr_id <= hpctx[i]->curr_id) {
            hpctx[i + 1] = hpctx[i];
            hpctx[i] = pctx;
            continue;
        }
        break;
    }
    pctmi->size++;

    pthread_mutex_unlock(&perf_op_ctx->pctmi_lock);

    return 1;
}


/**
 * \brief Returns a counter array for counters in this id range(s_id - e_id)
 *
 * \param s_id Counter id of the first counter to be added to the array
 * \param e_id Counter id of the last counter to be added to the array
 * \param pctx Pointer to the tv's PerfContext
 *
 * \retval a counter-array in this(s_id-e_id) range for this TM instance
 */
PerfCounterArray * PerfGetCounterArrayRange(uint16_t s_id, uint16_t e_id,
                                            PerfContext *pctx)
{
    PerfCounter *pc = NULL;
    PerfCounterArray *pca = NULL;
    uint32_t i = 0;

    if (pctx == NULL) {
#ifdef DEBUG
        printf("pctx is NULL\n");
#endif
        return NULL;
    }

    if (s_id < 1 || e_id < 1 || s_id > e_id) {
#ifdef DEBUG
        printf("error with the counter ids\n");
#endif
        return NULL;
    }

    if (e_id > pctx->curr_id) {
#ifdef DEBUG
        printf("end id is greater than the max id for this tv\n");
#endif
        return NULL;
    }

    if (pctx == NULL) {
#ifdef DEBUG
        printf("perfcontext is NULL\n");
#endif
        return NULL;
    }

    if ( (pca = malloc(sizeof(PerfCounterArray))) == NULL) {
        printf("Error allocating memory\n");
        exit(0);
    }
    memset(pca, 0, sizeof(PerfCounterArray));

    if ( (pca->head = malloc(sizeof(PCAElem) * (e_id - s_id  + 2))) == NULL) {
        printf("Error allocating memory\n");
        exit(0);
    }
    memset(pca->head, 0, sizeof(PCAElem) * (e_id - s_id  + 2));

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
 * \param pctx Pointer to the tv's PerfContext
 *
 * \retval a counter-array for all counters of this tm instance
 */
PerfCounterArray * PerfGetAllCountersArray(PerfContext *pctx)
{
    return((pctx)?PerfGetCounterArrayRange(1, pctx->curr_id, pctx):NULL);
}


/**
 * \brief Updates an individual counter
 *
 * \param cname    Name of the counter to be synced
 * \param tm_name  Thread module name
 * \param id holds Counter id of the counter to be synced
 * \param value    Pointer to the local counter from the client thread
 * \param pctx     PerfContext for this tm-tv instance
 *
 * \retval 1 on success, 0 on failure
 */
int PerfUpdateCounter(char *cname, char *tm_name, u_int64_t id, void *value,
                      PerfContext *pctx)
{
    PerfCounter *pc = NULL;

    if (pctx == NULL) {
#ifdef DEBUG
        printf("pctx null inside PerfUpdateCounter\n");
#endif
        return 0;
    }

    if ((cname == NULL || tm_name == NULL) && (id > pctx->curr_id || id < 1)) {
#ifdef DEBUG
        printf("id supplied doesn't exist.  Please supply cname and "
                    "tm_name instead\n");
#endif
        return 0;
    }

    if (value == NULL) {
#ifdef DEBUG
        printf("Pointer to counter(value) supplied to PerfUpdateCounter is "
               "NULL\n");
#endif
        return 0;
    }

    pc = pctx->head;
    while(pc != NULL) {
        if (pc->id != id) {
            pc = pc->next;
            continue;
        }

        memcpy(pc->value->cvalue, value, pc->value->size);
        pc->updated++;

        break;
    }

    if (pc == NULL) {
#ifdef DEBUG
        printf("this counter isn't registered in this tm\n");
#endif
        return 0;
    }

    return 1;
}

static void PerfCopyCounterValue(PCAElem *pcae, int reset_lc)
{
    PerfCounter *pc = NULL;
    double d_temp = 0;
    uint64_t ui64_temp = 0;
    int i = 0;

    pc = pcae->pc;
    switch (pc->value->type) {
        case TYPE_UINT64:
            ui64_temp = pcae->ui64_cnt;
            if (pc->type_q & TYPE_Q_AVERAGE) {
                for (i = 0; i < pcae->wrapped_syncs; i++)
                    ui64_temp /= ULONG_MAX;

                if (pcae->syncs != 0)
                    ui64_temp /= pcae->syncs;
            }
            memcpy(pc->value->cvalue, &ui64_temp, pc->value->size);

            if (reset_lc)
                pcae->ui64_cnt = 0;

            break;
        case TYPE_DOUBLE:
            d_temp = pcae->d_cnt;
            if (pc->type_q & TYPE_Q_AVERAGE) {
                for (i = 0; i < pcae->wrapped_syncs; i++)
                    d_temp /= ULONG_MAX;

                if (pcae->syncs != 0)
                    d_temp /= pcae->syncs;
            }
            memcpy(pc->value->cvalue, &d_temp, pc->value->size);

            if (reset_lc)
                pcae->d_cnt = 0;

            break;
    }

    return;
}

/**
 * \brief Syncs the counter array with the global counter variables
 *
 * \param pca      Pointer to the PerfCounterArray
 * \param pctx     Pointer the the tv's PerfContext
 * \param reset_lc Indicates whether the local counter has to be reset or not
 */
int PerfUpdateCounterArray(PerfCounterArray *pca, PerfContext *pctx,
                           int reset_lc)
{
    PerfCounter  *pc = NULL;
    PCAElem *pcae = NULL;
    uint32_t i = 0;

    if (pca == NULL || pctx == NULL) {
#ifdef DEBUG
        printf("pca or pctx is NULL inside PerfUpdateCounterArray\n");
#endif
        return -1;
    }

    pc = pctx->head;
    pcae = pca->head;

    pthread_mutex_lock(&pctx->m);
    for (i = 1; i <= pca->size; i++) {
        while (pc != NULL) {
            if (pc->id != pcae[i].id) {
                pc = pc->next;
                continue;
            }

            PerfCopyCounterValue(&pcae[i], reset_lc);

            pc->updated++;

            pc = pc->next;
            break;
        }
    }
    pthread_mutex_unlock(&pctx->m);

    pctx->perf_flag = 0;

    return 1;
}

/**
 * \brief The output interface dispatcher for the counter api
 */
void PerfOutputCounters()
{
    switch (perf_op_ctx->iface) {
        case IFACE_FILE:
            PerfOutputCounterFileIface();
            break;
        case IFACE_CONSOLE:
            // yet to be implemented
            break;
        case IFACE_NETWORK:
            // yet to be implemented
            break;
        case IFACE_SYSLOG:
            // yet to be implemented
            break;
    }

    return;
}

/**
 * \brief The file output interface for the counter api
 */
int PerfOutputCounterFileIface()
{
    ThreadVars *tv = NULL;
    PerfClubTMInst *pctmi = NULL;
    PerfCounter *pc = NULL;
    PerfCounter **pc_heads;

    uint64_t *ui64_cvalue = NULL;
    uint64_t ui64_result = 0;

    double *double_cvalue = NULL;
    double double_result = 0;


    struct timeval tval;
    struct tm *tms;

    int i;
    int flag;

    if (perf_op_ctx->fp == NULL) {
#ifdef DEBUG
        printf("perf_op_ctx->fp is NULL");
#endif
        return 0;
    }

    memset(&tval, 0, sizeof(struct timeval));

    gettimeofday(&tval, NULL);
    tms = (struct tm *)localtime(&tval.tv_sec);

    fprintf(perf_op_ctx->fp, "-------------------------------------------------"
            "------------------\n");
    fprintf(perf_op_ctx->fp, "%" PRId32 "/%" PRId32 "/%04d -- %02d:%02d:%02d\n", tms->tm_mday,
            tms->tm_mon, tms->tm_year + 1900, tms->tm_hour, tms->tm_min,
            tms->tm_sec);
    fprintf(perf_op_ctx->fp, "-------------------------------------------------"
            "------------------\n");
    fprintf(perf_op_ctx->fp, "%-25s | %-25s | %-s\n", "Counter", "TM Name",
            "Value");
    fprintf(perf_op_ctx->fp, "-------------------------------------------------"
            "------------------\n");

    if (perf_op_ctx->club_tm == 0) {
        for (i = 0; i < TVT_MAX; i++) {
            tv = tv_root[i];

            while (tv != NULL) {
                pthread_mutex_lock(&tv->pctx.m);
                pc = tv->pctx.head;

                while (pc != NULL) {
                    if (pc->disp == 0) {
                        pc = pc->next;
                        continue;
                    }

                    ui64_cvalue = (uint64_t *)pc->value->cvalue;
                    fprintf(perf_op_ctx->fp, "%-25s | %-25s | %-" PRIu64 "\n",
                            pc->name->cname, pc->name->tm_name, *ui64_cvalue);
#ifdef DEBUG
                    printf("%-10" PRIuMAX " %-10" PRIu16 " %-10s %-" PRIu64 "\n", pc->name->tid, pc->id,
                           pc->name->cname, *ui64_cvalue);
#endif
                    pc = pc->next;
                }

                pthread_mutex_unlock(&tv->pctx.m);
                tv = tv->next;
            }
            fflush(perf_op_ctx->fp);
        }

        return 1;
    }

    pctmi = perf_op_ctx->pctmi;
    while (pctmi != NULL) {
        if ( (pc_heads = malloc(pctmi->size * sizeof(PerfCounter *))) == NULL) {
            printf("error allocating memory\n");
            exit(0);
        }
        memset(pc_heads, 0, pctmi->size * sizeof(PerfCounter **));

        for (i = 0; i < pctmi->size; i++) {
            pc_heads[i] = pctmi->head[i]->head;

            pthread_mutex_lock(&pctmi->head[i]->m);

            while(strcmp(pctmi->tm_name, pc_heads[i]->name->tm_name))
                pc_heads[i] = pc_heads[i]->next;
        }

        flag = 1;
        while(flag) {
            ui64_result = 0;
            double_result = 0;
            pc = pc_heads[0];
            for (i = 0; i < pctmi->size; i++) {
                switch (pc->value->type) {
                    case TYPE_UINT64:
                        ui64_cvalue = pc_heads[i]->value->cvalue;
                        ui64_result += *ui64_cvalue;
                        break;
                    case TYPE_DOUBLE:
                        double_cvalue = pc_heads[i]->value->cvalue;
                        double_result += *double_cvalue;
                        break;
                }

                pc_heads[i] = pc_heads[i]->next;

                if (pc_heads[i] == NULL ||
                    strcmp(pctmi->tm_name, pc_heads[0]->name->tm_name))
                    flag = 0;
            }

            if (pc->disp == 0)
                continue;

            switch (pc->value->type) {
                case TYPE_UINT64:
                    fprintf(perf_op_ctx->fp, "%-25s | %-25s | %-" PRIu64 "\n",
                            pc->name->cname, pctmi->tm_name, ui64_result);
                    break;
                case TYPE_DOUBLE:
                    fprintf(perf_op_ctx->fp, "%-25s | %-25s | %-lf\n",
                            pc->name->cname, pctmi->tm_name, double_result);
                    break;
            }
#ifdef DEBUG
            /** \todo XXX "result" no longer exists */
#if 0
            printf("%-25s | %-25s | %-" PRIu64 "\n", pc->name->cname,
                   pctmi->tm_name, result);
#endif
#endif
        }
        for (i = 0; i < pctmi->size; i++)
            pthread_mutex_unlock(&pctmi->head[i]->m);

        pctmi = pctmi->next;
        free(pc_heads);

        fflush(perf_op_ctx->fp);
    }

    return 1;
}

/**
 * \brief Releases perf api resources.
 */
void PerfReleaseResources()
{
    PerfReleaseOPCtx();

    return;
}

void PerfReleaseOPCtx()
{
    if (perf_op_ctx != NULL) {
        if (perf_op_ctx->fp != NULL)
            fclose(perf_op_ctx->fp);

        if (perf_op_ctx->file != NULL)
            free(perf_op_ctx->file);

        if (perf_op_ctx->pctmi != NULL) {
            if (perf_op_ctx->pctmi->tm_name != NULL)
                free(perf_op_ctx->pctmi->tm_name);
            if (perf_op_ctx->pctmi->head != NULL)
                free(perf_op_ctx->pctmi->head);
            free(perf_op_ctx->pctmi);
        }

        free(perf_op_ctx);
    }

    return;
}

void PerfReleasePerfCounterS(PerfCounter *head)
{
    PerfCounter *pc = NULL;

    while (head != NULL) {
        pc = head;
        head = head->next;
        PerfReleaseCounter(pc);
    }

    return;
}

void PerfReleaseCounter(PerfCounter *pc)
{
    if (pc != NULL) {
        if (pc->name != NULL) {
            if (pc->name->cname != NULL) free(pc->name->cname);
            if (pc->name->tm_name != NULL) free(pc->name->tm_name);
            free(pc->name);
        }
        if (pc->value != NULL) {
            if (pc->value->cvalue != NULL) free(pc->value->cvalue);
            free(pc->value);
        }
        if (pc->desc != NULL) free(pc->desc);
        free(pc);
    }

    return;
}

void PerfReleasePCA(PerfCounterArray *pca)
{
    if (pca != NULL) {
        if (pca->head != NULL)
            free(pca->head);
        free(pca);
    }

    return;
}


//------------------------------------Unit_Tests--------------------------------


static int PerfTestCounterReg01()
{
    PerfContext pctx;

    memset(&pctx, 0, sizeof(PerfContext));

    return PerfRegisterCounter("t1", "c1", 5, NULL, &pctx);
}

static int PerfTestCounterReg02()
{
    PerfContext pctx;

    memset(&pctx, 0, sizeof(PerfContext));

    return PerfRegisterCounter(NULL, NULL, TYPE_UINT64, NULL, &pctx);
}

static int PerfTestCounterReg03()
{
    PerfContext pctx;
    int result;

    memset(&pctx, 0, sizeof(PerfContext));

    result = PerfRegisterCounter("t1", "c1", TYPE_UINT64, NULL, &pctx);

    PerfReleasePerfCounterS(pctx.head);

    return result;
}

static int PerfTestCounterReg04()
{
    PerfContext pctx;
    int result;

    memset(&pctx, 0, sizeof(PerfContext));

    PerfRegisterCounter("t1", "c1", TYPE_UINT64, NULL, &pctx);
    PerfRegisterCounter("t2", "c2", TYPE_UINT64, NULL, &pctx);
    PerfRegisterCounter("t3", "c3", TYPE_UINT64, NULL, &pctx);

    result =  PerfRegisterCounter("t1", "c1", TYPE_UINT64, NULL, &pctx);

    PerfReleasePerfCounterS(pctx.head);

    return result;
}

static int PerfTestGetCntArray05()
{
    ThreadVars tv;
    int id;

    memset(&tv, 0, sizeof(ThreadVars));

    id = PerfRegisterCounter("t1", "c1", TYPE_UINT64, NULL, &tv.pctx);

    tv.pca = PerfGetAllCountersArray(NULL);

    return (!tv.pca)?1:0;
}

static int PerfTestGetCntArray06()
{
    ThreadVars tv;
    int id;
    int result;

    memset(&tv, 0, sizeof(ThreadVars));

    id = PerfRegisterCounter("t1", "c1", TYPE_UINT64, NULL, &tv.pctx);

    tv.pca = PerfGetAllCountersArray(&tv.pctx);

    result = (tv.pca)?1:0;

    PerfReleasePerfCounterS(tv.pctx.head);
    PerfReleasePCA(tv.pca);

    return result;
}

static int PerfTestCntArraySize07()
{
    ThreadVars tv;
    PerfCounterArray *pca = NULL;
    int result;

    memset(&tv, 0, sizeof(ThreadVars));

    pca = (PerfCounterArray *)&tv.pca;

    PerfRegisterCounter("t1", "c1", TYPE_UINT64, NULL, &tv.pctx);
    PerfRegisterCounter("t2", "c2", TYPE_UINT64, NULL, &tv.pctx);

    pca = PerfGetAllCountersArray(&tv.pctx);

    PerfCounterIncr(1, pca);
    PerfCounterIncr(2, pca);

    result = pca->size;

    PerfReleasePerfCounterS(tv.pctx.head);
    PerfReleasePCA(pca);

    return result;
}

static int PerfTestUpdateCounter08()
{
    ThreadVars tv;
    PerfCounterArray *pca = NULL;
    int id;
    int result;

    memset(&tv, 0, sizeof(ThreadVars));

    id = PerfRegisterCounter("t1", "c1", TYPE_UINT64, NULL, &tv.pctx);

    pca = PerfGetAllCountersArray(&tv.pctx);

    PerfCounterIncr(id, pca);
    PerfCounterAddUI64(id, pca, 100);

    result = pca->head[id].ui64_cnt;

    PerfReleasePerfCounterS(tv.pctx.head);
    PerfReleasePCA(pca);

    return result;
}

static int PerfTestUpdateCounter09()
{
    ThreadVars tv;
    PerfCounterArray *pca = NULL;
    uint16_t id1, id2;
    int result;

    memset(&tv, 0, sizeof(ThreadVars));

    id1 = PerfRegisterCounter("t1", "c1", TYPE_UINT64, NULL, &tv.pctx);
    PerfRegisterCounter("t2", "c2", TYPE_UINT64, NULL, &tv.pctx);
    PerfRegisterCounter("t3", "c3", TYPE_UINT64, NULL, &tv.pctx);
    PerfRegisterCounter("t4", "c4", TYPE_UINT64, NULL, &tv.pctx);
    id2 = PerfRegisterCounter("t5", "c5", TYPE_UINT64, NULL, &tv.pctx);

    pca = PerfGetAllCountersArray(&tv.pctx);

    PerfCounterIncr(id2, pca);
    PerfCounterAddUI64(id2, pca, 100);

    result = (pca->head[id1].ui64_cnt == 0) && (pca->head[id2].ui64_cnt == 101);

    PerfReleasePerfCounterS(tv.pctx.head);
    PerfReleasePCA(pca);

    return result;
}

static int PerfTestUpdateGlobalCounter10()
{
    ThreadVars tv;
    PerfCounterArray *pca = NULL;

    int result = 1;
    uint16_t id1, id2, id3;
    uint64_t *p = NULL;

    memset(&tv, 0, sizeof(ThreadVars));

    id1 = PerfRegisterCounter("t1", "c1", TYPE_UINT64, NULL, &tv.pctx);
    id2 = PerfRegisterCounter("t2", "c2", TYPE_UINT64, NULL, &tv.pctx);
    id3 = PerfRegisterCounter("t3", "c3", TYPE_UINT64, NULL, &tv.pctx);

    pca = PerfGetAllCountersArray(&tv.pctx);

    PerfCounterIncr(id1, pca);
    PerfCounterAddUI64(id2, pca, 100);
    PerfCounterIncr(id3, pca);
    PerfCounterAddUI64(id3, pca, 100);

    PerfUpdateCounterArray(pca, &tv.pctx, 0);

    p = (uint64_t *)tv.pctx.head->value->cvalue;
    result = (1 == *p);

    p = (uint64_t *)tv.pctx.head->next->value->cvalue;
    result &= (100 == *p);

    p = (uint64_t *)tv.pctx.head->next->next->value->cvalue;
    result &= (101 == *p);

    PerfReleasePerfCounterS(tv.pctx.head);
    PerfReleasePCA(pca);

    return result;
}

static int PerfTestCounterValues11()
{
    ThreadVars tv;
    PerfCounterArray *pca = NULL;

    int result = 1;
    uint16_t id1, id2, id3, id4;
    uint8_t *u8p;

    memset(&tv, 0, sizeof(ThreadVars));

    id1 = PerfRegisterCounter("t1", "c1", TYPE_UINT64, NULL, &tv.pctx);
    id2 = PerfRegisterCounter("t2", "c2", TYPE_UINT64, NULL, &tv.pctx);
    id3 = PerfRegisterCounter("t3", "c3", TYPE_UINT64, NULL, &tv.pctx);
    id4 = PerfRegisterCounter("t4", "c4", TYPE_UINT64, NULL, &tv.pctx);

    pca = PerfGetAllCountersArray(&tv.pctx);

    PerfCounterIncr(id1, pca);
    PerfCounterAddUI64(id2, pca, 256);
    PerfCounterAddUI64(id3, pca, 257);
    PerfCounterAddUI64(id4, pca, 16843024);

    PerfUpdateCounterArray(pca, &tv.pctx, 0);

    u8p = (uint8_t *)tv.pctx.head->value->cvalue;
    result &= (1 == *u8p);
    result &= (0 == *(u8p + 1));
    result &= (0 == *(u8p + 2));
    result &= (0 == *(u8p + 3));

    u8p = (uint8_t *)tv.pctx.head->next->value->cvalue;
    result &= (0 == *u8p);
    result &= (1 == *(u8p + 1));
    result &= (0 == *(u8p + 2));
    result &= (0 == *(u8p + 3));

    u8p = (uint8_t *)tv.pctx.head->next->next->value->cvalue;
    result &= (1 == *u8p);
    result &= (1 == *(u8p + 1));
    result &= (0 == *(u8p + 2));
    result &= (0 == *(u8p + 3));

    u8p = (uint8_t *)tv.pctx.head->next->next->next->value->cvalue;
    result &= (16 == *u8p);
    result &= (1 == *(u8p + 1));
    result &= (1 == *(u8p + 2));
    result &= (1 == *(u8p + 3));

    PerfReleasePerfCounterS(tv.pctx.head);
    PerfReleasePCA(pca);

    return result;
}

static int PerfTestAverageQual12()
{
    ThreadVars tv;
    PerfCounterArray *pca = NULL;
    uint64_t *ui64_temp = NULL;
    double *d_temp = NULL;

    int result = 1;
    uint16_t id1, id2;

    memset(&tv, 0, sizeof(ThreadVars));

    id1 = PerfRegisterAvgCounter("t1", "c1", TYPE_DOUBLE, NULL, &tv.pctx);
    id2 = PerfRegisterAvgCounter("t2", "c2", TYPE_UINT64, NULL, &tv.pctx);

    pca = PerfGetAllCountersArray(&tv.pctx);

    PerfCounterAddDouble(id1, pca, 1);
    PerfCounterAddDouble(id1, pca, 2);
    PerfCounterAddDouble(id1, pca, 3);
    PerfCounterAddDouble(id1, pca, 4);
    PerfCounterAddDouble(id1, pca, 5);
    PerfCounterAddDouble(id1, pca, 6);

    PerfUpdateCounterArray(pca, &tv.pctx, 0);

    result &= (21 == pca->head[1].d_cnt);
    result &= (6 == pca->head[1].syncs);
    result &= (0 == pca->head[1].wrapped_syncs);
    d_temp = tv.pctx.head->value->cvalue;
    result &= (3.5 == *d_temp);

    PerfCounterAddUI64(id2, pca, 1.635);
    PerfCounterAddUI64(id2, pca, 2.12);
    PerfCounterAddUI64(id2, pca, 3.74);
    PerfCounterAddUI64(id2, pca, 4.23);
    PerfCounterAddUI64(id2, pca, 5.76);
    PerfCounterAddDouble(id2, pca, 6.99999);

    PerfUpdateCounterArray(pca, &tv.pctx, 0);

    result &= (21 == pca->head[2].ui64_cnt);
    result &= (6 == pca->head[2].syncs);
    result &= (0 == pca->head[2].wrapped_syncs);
    ui64_temp = tv.pctx.head->next->value->cvalue;
    result &= (3 == *ui64_temp);

    return result;
}

static int PerfTestMaxQual13()
{
    ThreadVars tv;
    PerfCounterArray *pca = NULL;
    double *p;

    int result = 1;
    uint16_t id1;

    memset(&tv, 0, sizeof(ThreadVars));

    id1 = PerfRegisterMaxCounter("t1", "c1", TYPE_DOUBLE, NULL, &tv.pctx);

    p = tv.pctx.head->value->cvalue;

    pca = PerfGetAllCountersArray(&tv.pctx);

    PerfCounterSetDouble(id1, pca, 1.352);
    PerfCounterSetDouble(id1, pca, 5.12412);
    PerfCounterSetDouble(id1, pca, 4.1234);
    PerfCounterSetDouble(id1, pca, 5.13562);
    PerfCounterSetDouble(id1, pca, 1.2342);

    PerfUpdateCounterArray(pca, &tv.pctx, 0);
    result &= (5.13562 == *p);

    PerfCounterSetDouble(id1, pca, 8);
    PerfCounterSetDouble(id1, pca, 7);

    PerfUpdateCounterArray(pca, &tv.pctx, 0);
    result &= (8 == *p);

    PerfCounterSetDouble(id1, pca, 6);
    PerfCounterSetUI64(id1, pca, 10);
    PerfCounterSetDouble(id1, pca, 9.562);

    PerfUpdateCounterArray(pca, &tv.pctx, 0);
    result &= (10 == *p);

    return result;
}

void PerfRegisterTests()
{
    UtRegisterTest("PerfTestCounterReg01", PerfTestCounterReg01, 0);
    UtRegisterTest("PerfTestCounterReg02", PerfTestCounterReg02, 0);
    UtRegisterTest("PerfTestCounterReg03", PerfTestCounterReg03, 1);
    UtRegisterTest("PerfTestCounterReg04", PerfTestCounterReg04, 1);
    UtRegisterTest("PerfTestGetCntArray05", PerfTestGetCntArray05, 1);
    UtRegisterTest("PerfTestGetCntArray06", PerfTestGetCntArray06, 1);
    UtRegisterTest("PerfTestCntArraySize07", PerfTestCntArraySize07, 2);
    UtRegisterTest("PerfTestUpdateCounter08", PerfTestUpdateCounter08, 101);
    UtRegisterTest("PerfTestUpdateCounter09", PerfTestUpdateCounter09, 1);
    UtRegisterTest("PerfTestUpdateGlobalCounter10",
                   PerfTestUpdateGlobalCounter10, 1);
    UtRegisterTest("PerfTestCounterValues11", PerfTestCounterValues11, 1);
    UtRegisterTest("PerfTestAverageQual12", PerfTestAverageQual12, 1);
    UtRegisterTest("PerfTestMaxQual13", PerfTestMaxQual13, 1);

    return;
}
