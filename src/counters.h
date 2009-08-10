/** Copyright (c) 2009 Open Information Security Foundation.
 *  \author Anoop Saldanha <poonaatsoc@gmail.com>
 */

#ifndef __COUNTERS_H__
#define __COUNTERS_H__


/* Time interval for syncing the local counters with the global ones */
#define WUT_TTS 3
/* Time interval at which the mgmt thread o/p the stats */
#define MGMTT_TTS 8

/* These 2 macros can only be used when all the registered counters for the tm,
 * are in the counter array */
#define PerfCounterIncr(id, pca) do { \
                                     if (!pca) { \
                                         printf("counterarray is NULL\n"); \
                                         break; \
                                     } \
                                     if ((id < 1) || (id > pca->size)) { \
                                         printf("counter doesn't exist\n"); \
                                         break; \
                                     } \
                                     pca->head[id].cnt++; \
                                 } while(0)

#define PerfCounterAdd(id, pca, x) do { \
                                       if (!pca) { \
                                           printf("counterarray is NULL\n"); \
                                           break; \
                                       } \
                                       if ((id < 1) || (id > pca->size)) { \
                                           printf("counter doesn't exist\n"); \
                                           break; \
                                       } \
                                       pca->head[id].cnt += x; \
                                   } while(0)

enum {
    TYPE_UINT64,
    TYPE_DOUBLE,
    TYPE_STR,
    TYPE_MAX,
};

enum {
    IFACE_FILE,
    IFACE_CONSOLE,
    IFACE_NETWORK,
    IFACE_SYSLOG,
};

typedef struct _PerfCounterName {
    char *cname;
    char *tm_name;
    int tid;
} PerfCounterName;

typedef struct _PerfCounterValue {
    void *cvalue;
    u_int32_t size;
    u_int32_t type;
} PerfCounterValue;

/* Container to hold the counter variable */
typedef struct _PerfCounter {
    PerfCounterName *name;
    PerfCounterValue *value;

    /* local id for this counter in this tm*/
    pthread_t id;

    char *desc;

    /* no of times the local counter has been synced with this counter */
    u_int64_t updated;

    /* the next perfcounter for this tv's tm instance */
    struct _PerfCounter *next;
} PerfCounter;

/* Holds the Perf Context for a ThreadVars instance */
typedef struct _PerfContext {
    PerfCounter *head;

    /* flag set by the wakeup thread, to inform the client threads to sync */
    u_int32_t perf_flag;
    u_int32_t curr_id;

    /* mutex to prevent simultaneous access during update_counter/output_stat */
    pthread_mutex_t m;
} PerfContext;

/* PerfCounterArray(PCA) Node*/
typedef struct _PCAElem {
    u_int32_t id;
    u_int64_t cnt;
} PCAElem;

/* The PerfCounterArray */
typedef struct _PerfCounterArray {
    /* points to the array holding PCAElems */
    PCAElem *head;

    /* no of PCAElems in head */
    u_int32_t size;
} PerfCounterArray;

/* Holds multiple instances of the same TM together, used when the stats
 * have to be clubbed based on TM, before being sent out*/
typedef struct _PerfClubTMInst {
    char *tm_name;

    PerfContext **head;
    u_int32_t size;

    struct _PerfClubTMInst *next;
} PerfClubTMInst;

/* Holds the output interface context for the counter api */
typedef struct _PerfOPIfaceContext {
    u_int32_t iface;
    char *file;

    /* more interfaces to be supported later.  For now just a file */
    FILE *fp;

    u_int32_t club_tm;

    PerfClubTMInst *pctmi;
    pthread_mutex_t pctmi_lock;
} PerfOPIfaceContext;

void PerfInitCounterApi(void);

void PerfInitOPCtx(void);

void PerfSpawnThreads(void);

void * PerfMgmtThread(void *);

void * PerfWakeupThread(void *);

u_int32_t PerfRegisterCounter(char *, char *, int, char *, PerfContext *);

void PerfAddToClubbedTMTable(char *, PerfContext *);

PerfCounterArray * PerfGetCounterArrayRange(u_int32_t, u_int32_t,
                                            PerfContext *);

PerfCounterArray * PerfGetAllCountersArray(PerfContext *);


int PerfUpdateCounter(char *, char *, u_int32_t, void *,
                      PerfContext *);

int PerfUpdateCounterArray(PerfCounterArray *, PerfContext *, int);

void PerfOutputCounters(void);

int PerfOutputCounterFileIface(void);

void PerfReleaseResources(void);

void PerfReleaseOPCtx(void);

void PerfReleasePerfCounterS(PerfCounter *);

void PerfReleaseCounter(PerfCounter *);

void PerfReleasePCA(PerfCounterArray *);

void PerfRegisterTests(void);

#endif /* __COUNTERS_H__ */
