#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/time.h>
#include "time.h"

#include "counters.h"
#include "eidps.h"
#include "threadvars.h"
#include "tm-modules.h"
#include "tm-threads.h"
#include "util-unittest.h"

/** \todo config api */
#define LOGPATH "/var/log/eidps/stats.log"

static PerfThreadContext *perf_tc = NULL;
static PerfOPIfaceContext *perf_op_ctx = NULL;

/**
 * Initializes the perf counter api.  Things are hard coded currently.
 * More work to be done when we implement multiple interfaces
 */
void PerfInitCounterApi()
{
    PerfInitOPCtx();

    return;
}

/**
 * Initializes the output interface context
 */
void PerfInitOPCtx()
{
    if ( (perf_op_ctx = malloc(sizeof(PerfOPIfaceContext))) == NULL) {
        printf("error allocating memory\n");
        exit(0);
    }
    memset(perf_op_ctx, 0, sizeof(PerfOPIfaceContext));

    perf_op_ctx->iface = IFACE_FILE;

    if ( (perf_op_ctx->file = strdup(LOGPATH)) == NULL) {
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
 * Spawns the wakeup, and the management thread
 */
void PerfSpawnThreads()
{
    pthread_attr_t attr;

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

    printf("PerfSpawnThreads: spawning counter threads\n");

    if ( (perf_tc = malloc(sizeof(PerfThreadContext))) == NULL) {
        printf("Error allocating memory\n");
        exit(0);
    }
    memset(perf_tc, 0, sizeof(PerfThreadContext));

    perf_tc->flags = PT_RUN;

    if (pthread_mutex_init(&perf_tc->wakeup_m, NULL) != 0) {
        printf("Error initializing the perf_tc->wakeup_m mutex\n");
        exit(0);
    }

    if (pthread_mutex_init(&perf_tc->mgmt_m, NULL) != 0) {
        printf("Error initializing the perf_tc->mgmt_m mutex\n");
        exit(0);
    }

    if (pthread_cond_init(&perf_tc->tc_cond, NULL) != 0) {
        printf("Error initializing the perf_tc->tc_cond condition variable\n");
        exit(0);
    }

    if (pthread_create(&perf_tc->wakeup_t, &attr, PerfWakeupThread, NULL) != 0) {
        printf("Error creating PerfWakeupFunc thread\n");
        exit(0);
    }

    if (pthread_create(&perf_tc->mgmt_t, &attr, PerfMgmtThread, NULL) != 0) {
        printf("Error creating PerfWakeupFunc thread\n");
        exit(0);
    }

    return;
}

/**
 * Kills the wakeup and the management threads
 */
void PerfDestroyThreads()
{
    perf_tc->flags |= PT_KILL;

    /* prematurely wakeup, the mgmt and wakeup threads */
    pthread_cond_broadcast(&perf_tc->tc_cond);

    pthread_join(perf_tc->wakeup_t, NULL);
    pthread_join(perf_tc->mgmt_t, NULL);

    if (pthread_mutex_destroy(&perf_tc->wakeup_m) != 0) {
        printf("Error destroying the mutex perf_tc->wakeup_m\n");
    }

    if (pthread_mutex_destroy(&perf_tc->mgmt_m) != 0) {
        printf("Error destroying the mutex perf_tc->mgmt_m\n");
    }

    if (pthread_cond_destroy(&perf_tc->tc_cond) != 0) {
        printf("Error destroying the condition variable perf_tc->tc_cond\n");
    }

    if (perf_tc != NULL) free(perf_tc);

    return;
}


/**
 * The management thread. This thread is responsible for writing the performance
 * stats information.
 *
 * @param arg is NULL always
 */
void * PerfMgmtThread(void *arg)
{
    u_int8_t run = 1;
    struct timespec cond_time;

    printf("PerfMgmtThread: spawned\n");

    if (perf_op_ctx == NULL) {
        printf("error: PerfInitCounterApi() has to be called first\n");
        return NULL;
    }

    while (run) {
        cond_time.tv_sec = time(NULL) + MGMTT_TTS;
        cond_time.tv_nsec = 0;

        pthread_mutex_lock(&perf_tc->mgmt_m);
        pthread_cond_timedwait(&perf_tc->tc_cond, &perf_tc->mgmt_m,
                               &cond_time);
        pthread_mutex_unlock(&perf_tc->mgmt_m);

        // sleep(MGMTT_TTS);

        PerfOutputCounters();

        if (perf_tc->flags & PT_KILL)
            run = 0;
    }

    return NULL;
}

/**
 * Wake up thread.  This thread wakes up every TTS(time to sleep) seconds and
 * sets the flag for every ThreadVars' PerfContext
 *
 * @param arg is NULL always
 */
void * PerfWakeupThread(void *arg)
{
    u_int8_t run = 1;
    ThreadVars *tv = NULL;
    PacketQueue *q = NULL;
    struct timespec cond_time;

    printf("PerfWakeupThread: spawned\n");

    while (run) {
        cond_time.tv_sec = time(NULL) + WUT_TTS;
        cond_time.tv_nsec = 0;

        pthread_mutex_lock(&perf_tc->wakeup_m);
        pthread_cond_timedwait(&perf_tc->tc_cond, &perf_tc->wakeup_m,
                               &cond_time);
        pthread_mutex_unlock(&perf_tc->wakeup_m);

        // sleep(WUT_TTS);

        tv = tv_root;

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

        if (perf_tc->flags & PT_KILL)
            run = 0;
    }

    return NULL;
}

/**
 *  Registers a counter
 *
 * @param cname holds the counter name
 * @param tm_name holds the tm_name
 * @param tid holds the tid running this module
 * @param type holds the datatype of this counter variable
 * @param head holds the PerfCounter
 *
 * @returns the counter id
 */
u_int32_t PerfRegisterCounter(char *cname, char *tm_name, int type,
                              char *desc, PerfContext *pctx)
{
    PerfCounter **head = &pctx->head;
    PerfCounter *temp = NULL;
    PerfCounter *prev = NULL;
    PerfCounter *pc = NULL;

    if (cname == NULL || tm_name == NULL || pctx == NULL) {
        printf("counter name, tm name null or PerfContext NULL\n");
        return 0;
    }

    /* (TYPE_MAX - 1) because we still haven't implemented TYPE_STR */
    if ((type >= (TYPE_MAX - 1)) || (type < 0)) {
        printf("Error: Counters of type %d can't be registered\n", type);
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
            pc->value->size = sizeof(u_int64_t);
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

    return pc->id;
}

/**
 * Adds a TM to the clubbed TM table.  Multiple instances of the same TM are
 * stacked together in a PCTMI container
 *
 * @param tm_name is the name of the tm to be added
 * @param pctx holds the PerfContext associated with the TM tm_name
 */
void PerfAddToClubbedTMTable(char *tm_name, PerfContext *pctx)
{
    PerfClubTMInst *pctmi = NULL;
    PerfClubTMInst *prev = NULL;
    PerfClubTMInst *temp = NULL;
    PerfContext **hpctx;
    int i = 0;

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
        return;
    }

    hpctx = pctmi->head;
    for (i = 0; i < pctmi->size; i++) {
        if (hpctx[i] != pctx)
            continue;

        pthread_mutex_unlock(&perf_op_ctx->pctmi_lock);
        return;
    }

    pctmi->head = realloc(pctmi->head, (pctmi->size + 1) * sizeof(PerfContext **));
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

    return;
}


/**
 * Returns a counter array for counters in this id range(s_id - e_id)
 *
 * @param s_id is the start id of the counter
 * @param e_id is the end id of the counter
 * @param pctx is a pointer to the tv's PerfContext
 *
 * @returns a counter-array in this(s_id-e_id) range for this tm instance
 */
PerfCounterArray * PerfGetCounterArrayRange(u_int32_t s_id, u_int32_t e_id,
                                            PerfContext *pctx)
{
    PerfCounterArray *pca = NULL;
    u_int32_t i = 0;

    if (pctx == NULL) {
        printf("pctx is NULL\n");
        return NULL;
    }

    if (s_id < 1 || e_id < 1 || s_id > e_id) {
        printf("error with the counter ids\n");
        return NULL;
    }

    if (e_id > pctx->curr_id) {
        printf("end id is greater than the max id for this tv\n");
        return NULL;
    }

    if (pctx == NULL) {
        printf("perfcontext is NULL\n");
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

    i = 1;
    while (s_id <= e_id) {
        pca->head[i].id = s_id++;
        i++;
    }
    pca->size = i - 1;

    return pca;
}

/**
 * Returns a counter array for all counters registered for this tm instance
 *
 * @param pctx is a pointer to the tv's PerfContext
 *
 * @returns a counter-array for all the counters of this tm instance
 */
PerfCounterArray * PerfGetAllCountersArray(PerfContext *pctx)
{
    return((pctx)?PerfGetCounterArrayRange(1, pctx->curr_id, pctx):NULL);
}


/**
 * Updates an individual counter
 *
 * @param cname holds the counter name
 * @param tm_name holds the tm name
 * @param id holds the counter id for this tm
 * @param value holds a pointer to the local counter from the client thread
 * @param pctx holds the PerfContext associated with this instance of the tm
 */
int PerfUpdateCounter(char *cname, char *tm_name, u_int32_t id, void *value,
                      PerfContext *pctx)
{
    PerfCounter *pc = NULL;

    if (pctx == NULL) {
        printf("pctx null inside PerfUpdateCounter\n");
        return 0;
    }

    if ((cname == NULL || tm_name == NULL) && (id > pctx->curr_id || id < 1)) {
        printf("id supplied doesn't exist.  Please supply cname and "
                    "tm_name instead\n");
        return 0;
    }

    if (value == NULL) {
        printf("Pointer to counter(value) supplied to PerfUpdateCounter is NULL\n");
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
        printf("this counter isn't registered in this tm\n");
        return 0;
    }

    return 1;
}

/**
 * Syncs the counter array with the global counter variables
 *
 * @param pca holds a pointer to the PerfCounterArray
 * @param pctx holds a pointer the the tv's PerfContext
 * @param reset_lc indicates whether the local counter has to be reset or not
 */
int PerfUpdateCounterArray(PerfCounterArray *pca, PerfContext *pctx, int reset_lc)
{
    PerfCounter  *pc = NULL;
    PCAElem *pcae = NULL;
    u_int32_t i = 0;

    if (pca == NULL || pctx == NULL) {
        printf("pca or pctx is NULL inside PerfUpdateCounterArray\n");
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

            memcpy(pc->value->cvalue, &(pcae[i].cnt), pc->value->size);

            pc->updated++;

            if (reset_lc)
                pcae[i].cnt = 0;

            pc = pc->next;
            break;
        }
    }
    pthread_mutex_unlock(&pctx->m);

    pctx->perf_flag = 0;

    return 1;
}

/**
 * The output interface dispatcher for the counter api
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
 * The file output interface for the counter api
 */
int PerfOutputCounterFileIface()
{
    ThreadVars *tv = tv_root;
    PerfClubTMInst *pctmi = NULL;
    PerfCounter *pc = NULL;
    PerfCounter **pc_heads;

    u_int64_t *ui64_cvalue = NULL;
    u_int64_t result = 0;

    struct timeval tval;
    struct tm *tms;

    int i;
    int flag;

    if (perf_op_ctx->fp == NULL) {
        printf("perf_op_ctx->fp is NULL");
        return 0;
    }

    memset(&tval, 0, sizeof(struct timeval));

    gettimeofday(&tval, NULL);
    tms = (struct tm *)localtime(&tval.tv_sec);

    fprintf(perf_op_ctx->fp, "-------------------------------------------------"
            "------------------\n");
    fprintf(perf_op_ctx->fp, "%d/%d/%04d -- %02d:%02d:%02d\n", tms->tm_mday,
            tms->tm_mon, tms->tm_year + 1900, tms->tm_hour, tms->tm_min, tms->tm_sec);
    fprintf(perf_op_ctx->fp, "-------------------------------------------------"
            "------------------\n");
    fprintf(perf_op_ctx->fp, "%-25s | %-25s | %-s\n", "Counter", "TM Name",
            "Value");
    fprintf(perf_op_ctx->fp, "-------------------------------------------------"
            "------------------\n");

    if (perf_op_ctx->club_tm == 0) {
        while (tv != NULL) {
            pthread_mutex_lock(&tv->pctx.m);
            pc = tv->pctx.head;

            while (pc != NULL) {
                ui64_cvalue = (u_int64_t *)pc->value->cvalue;
                fprintf(perf_op_ctx->fp, "%-25s | %-25s | %-llu\n",
                        pc->name->cname, pc->name->tm_name, *ui64_cvalue);
                //printf("%-10d %-10d %-10s %-llu\n", pc->name->tid, pc->id,
                //       pc->name->cname, *ui64_cvalue);
                pc = pc->next;
            }

            pthread_mutex_unlock(&tv->pctx.m);
            tv = tv->next;
        }

        fflush(perf_op_ctx->fp);

        return 1;
    }

    pctmi = perf_op_ctx->pctmi;
    while (pctmi != NULL) {
        if ( (pc_heads = malloc(pctmi->size * sizeof(PerfCounter **))) == NULL) {
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
            result = 0;
            pc = pc_heads[0];
            for (i = 0; i < pctmi->size; i++) {
                ui64_cvalue = pc_heads[i]->value->cvalue;
                result += *ui64_cvalue;

                pc_heads[i] = pc_heads[i]->next;

                if (pc_heads[i] == NULL ||
                    strcmp(pctmi->tm_name, pc_heads[0]->name->tm_name))
                    flag = 0;
            }
            fprintf(perf_op_ctx->fp, "%-25s | %-25s | %-llu\n",
                    pc->name->cname, pctmi->tm_name, result);
            //printf("%-25s | %-25s | %-llu\n", pc->name->cname,
            //       pctmi->tm_name, result);

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
 * Kills the perf threads and releases other resources.
 */
void PerfReleaseResources()
{
    PerfDestroyThreads();

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


//------------------------------------Unit_Tests------------------------------------


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
    PerfCounterAdd(id, pca, 100);

    result = pca->head[id].cnt;

    PerfReleasePerfCounterS(tv.pctx.head);
    PerfReleasePCA(pca);

    return result;
}

static int PerfTestUpdateCounter09()
{
    ThreadVars tv;
    PerfCounterArray *pca = NULL;
    int id1, id2;
    int result;

    memset(&tv, 0, sizeof(ThreadVars));

    id1 = PerfRegisterCounter("t1", "c1", TYPE_UINT64, NULL, &tv.pctx);
    PerfRegisterCounter("t2", "c2", TYPE_UINT64, NULL, &tv.pctx);
    PerfRegisterCounter("t3", "c3", TYPE_UINT64, NULL, &tv.pctx);
    PerfRegisterCounter("t4", "c4", TYPE_UINT64, NULL, &tv.pctx);
    id2 = PerfRegisterCounter("t5", "c5", TYPE_UINT64, NULL, &tv.pctx);

    pca = PerfGetAllCountersArray(&tv.pctx);

    PerfCounterIncr(id2, pca);
    PerfCounterAdd(id2, pca, 100);

    result = (pca->head[id1].cnt == 0) && (pca->head[id2].cnt == 101);

    PerfReleasePerfCounterS(tv.pctx.head);
    PerfReleasePCA(pca);

    return result;
}

static int PerfTestUpdateGlobalCounter10()
{
    ThreadVars tv;
    PerfCounterArray *pca = NULL;

    int result = 1;
    int id1, id2, id3;
    u_int64_t *p = NULL;

    memset(&tv, 0, sizeof(ThreadVars));

    id1 = PerfRegisterCounter("t1", "c1", TYPE_UINT64, NULL, &tv.pctx);
    id2 = PerfRegisterCounter("t2", "c2", TYPE_UINT64, NULL, &tv.pctx);
    id3 = PerfRegisterCounter("t3", "c3", TYPE_UINT64, NULL, &tv.pctx);
    pca = PerfGetAllCountersArray(&tv.pctx);

    PerfCounterIncr(id1, pca);
    PerfCounterAdd(id2, pca, 100);
    PerfCounterIncr(id3, pca);
    PerfCounterAdd(id3, pca, 100);

    PerfUpdateCounterArray(pca, &tv.pctx, 0);

    p = (u_int64_t *)tv.pctx.head->value->cvalue;
    result = (1 == *p);

    p = (u_int64_t *)tv.pctx.head->next->value->cvalue;
    result &= (100 == *p);

    p = (u_int64_t *)tv.pctx.head->next->next->value->cvalue;
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
    int id1, id2, id3, id4;
    u_int8_t *u8p;

    memset(&tv, 0, sizeof(ThreadVars));

    id1 = PerfRegisterCounter("t1", "c1", TYPE_UINT64, NULL, &tv.pctx);
    id2 = PerfRegisterCounter("t2", "c2", TYPE_UINT64, NULL, &tv.pctx);
    id3 = PerfRegisterCounter("t3", "c3", TYPE_UINT64, NULL, &tv.pctx);
    id4 = PerfRegisterCounter("t4", "c4", TYPE_UINT64, NULL, &tv.pctx);

    pca = PerfGetAllCountersArray(&tv.pctx);

    PerfCounterIncr(id1, pca);
    PerfCounterAdd(id2, pca, 256);
    PerfCounterAdd(id3, pca, 257);
    PerfCounterAdd(id4, pca, 16843024);

    PerfUpdateCounterArray(pca, &tv.pctx, 0);

    u8p = (u_int8_t *)tv.pctx.head->value->cvalue;
    result &= (1 == *u8p);
    result &= (0 == *(u8p + 1));
    result &= (0 == *(u8p + 2));
    result &= (0 == *(u8p + 3));

    u8p = (u_int8_t *)tv.pctx.head->next->value->cvalue;
    result &= (0 == *u8p);
    result &= (1 == *(u8p + 1));
    result &= (0 == *(u8p + 2));
    result &= (0 == *(u8p + 3));

    u8p = (u_int8_t *)tv.pctx.head->next->next->value->cvalue;
    result &= (1 == *u8p);
    result &= (1 == *(u8p + 1));
    result &= (0 == *(u8p + 2));
    result &= (0 == *(u8p + 3));

    u8p = (u_int8_t *)tv.pctx.head->next->next->next->value->cvalue;
    result &= (16 == *u8p);
    result &= (1 == *(u8p + 1));
    result &= (1 == *(u8p + 2));
    result &= (1 == *(u8p + 3));

    PerfReleasePerfCounterS(tv.pctx.head);
    PerfReleasePCA(pca);

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

    return;
}
