/** Copyright (c) 2009 Open Information Security Foundation.
 *  \author Anoop Saldanha <poonaatsoc@gmail.com>
 */

#ifndef __COUNTERS_H__
#define __COUNTERS_H__


/* Time interval for syncing the local counters with the global ones */
#define WUT_TTS 3
/* Time interval at which the mgmt thread o/p the stats */
#define MGMTT_TTS 8

/* Type of counter */
enum {
    TYPE_UINT64,
    TYPE_DOUBLE,
    TYPE_STR,
    TYPE_MAX,
};

/* Qualifier for the counter */
enum {
    TYPE_Q_NONE = 0x01,
    TYPE_Q_AVERAGE = 0x02,
    TYPE_Q_MAXIMUM = 0x04,
    TYPE_Q_TIMEBASED = 0x08,
    TYPE_Q_MAX = 0x10,
};

/* Output interfaces */
enum {
    IFACE_FILE,
    IFACE_CONSOLE,
    IFACE_NETWORK,
    IFACE_SYSLOG,
};

typedef struct _PerfCounterName {
    char *cname;
    char *tm_name;
    pthread_t tid;
} PerfCounterName;

typedef struct _PerfCounterValue {
    void *cvalue;
    uint32_t size;
    uint32_t type;
} PerfCounterValue;

/* Container to hold the counter variable */
typedef struct _PerfCounter {
    PerfCounterName *name;
    PerfCounterValue *value;

    /* local id for this counter in this tm*/
    uint64_t id;

    char *desc;

    /* no of times the local counter has been synced with this counter */
    uint64_t updated;

    /* flag that indicates if this counter should be displayed or not */
    int disp;

    /* counter qualifier */
    int type_q;

    /* the next perfcounter for this tv's tm instance */
    struct _PerfCounter *next;
} PerfCounter;

/* Holds the Perf Context for a ThreadVars instance */
typedef struct _PerfContext {
    PerfCounter *head;

    /* flag set by the wakeup thread, to inform the client threads to sync */
    uint32_t perf_flag;
    uint32_t curr_id;

    /* mutex to prevent simultaneous access during update_counter/output_stat */
    pthread_mutex_t m;
} PerfContext;

/* PerfCounterArray(PCA) Node*/
typedef struct _PCAElem {
    PerfCounter *pc;
    uint64_t id;
    union {
        uint64_t ui64_cnt;
        double d_cnt;
    };

    /* no of times the local counter has been updated */
    uint64_t syncs;

    /* indicates the times syncs has overflowed */
    uint64_t wrapped_syncs;
} PCAElem;

/* The PerfCounterArray */
typedef struct _PerfCounterArray {
    /* points to the array holding PCAElems */
    PCAElem *head;

    /* no of PCAElems in head */
    uint32_t size;
} PerfCounterArray;

/* Holds multiple instances of the same TM together, used when the stats
 * have to be clubbed based on TM, before being sent out*/
typedef struct _PerfClubTMInst {
    char *tm_name;

    PerfContext **head;
    uint32_t size;

    struct _PerfClubTMInst *next;
} PerfClubTMInst;

/* Holds the output interface context for the counter api */
typedef struct _PerfOPIfaceContext {
    uint32_t iface;
    char *file;

    /* more interfaces to be supported later.  For now just a file */
    FILE *fp;

    uint32_t club_tm;

    PerfClubTMInst *pctmi;
    pthread_mutex_t pctmi_lock;
} PerfOPIfaceContext;

void PerfInitCounterApi(void);

void PerfInitOPCtx(void);

void PerfSpawnThreads(void);

void * PerfMgmtThread(void *);

void * PerfWakeupThread(void *);

uint32_t PerfRegisterCounter(char *, char *, int, char *, PerfContext *, int,
                              int);

inline void PerfCounterIncr(uint64_t, PerfCounterArray *);

inline void PerfCounterAddUI64(uint64_t, PerfCounterArray *, uint64_t);

inline void PerfCounterAddDouble(uint64_t, PerfCounterArray *, double);

inline void PerfCounterSetUI64(uint64_t, PerfCounterArray *, uint64_t);

inline void PerfCounterSetDouble(uint64_t, PerfCounterArray *, double);

void PerfAddToClubbedTMTable(char *, PerfContext *);

PerfCounterArray * PerfGetCounterArrayRange(uint32_t, uint32_t,
                                            PerfContext *);

PerfCounterArray * PerfGetAllCountersArray(PerfContext *);


int PerfUpdateCounter(char *, char *, uint32_t, void *,
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
