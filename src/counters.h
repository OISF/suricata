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
 * \author Anoop Saldanha <poonaatsoc@gmail.com>
 */

#ifndef __COUNTERS_H__
#define __COUNTERS_H__

/* forward declaration of the ThreadVars structure */
struct ThreadVars_;

/* Time interval for syncing the local counters with the global ones */
#define SC_PERF_WUT_TTS 3

/* Time interval at which the mgmt thread o/p the stats */
#define SC_PERF_MGMTT_TTS 8

/**
 * \brief Data type for different kind of Perf counters that can be registered
 */
enum {
    SC_PERF_TYPE_UINT64,
    SC_PERF_TYPE_DOUBLE,
    SC_PERF_TYPE_STR,
    SC_PERF_TYPE_MAX,
};

/**
 * \brief Different kinds of qualifier that can be used to modify the behaviour
 *        of the Perf counter to be registered
 */
enum {
    SC_PERF_TYPE_Q_NORMAL = 0x01,
    SC_PERF_TYPE_Q_AVERAGE = 0x02,
    SC_PERF_TYPE_Q_MAXIMUM = 0x04,
    SC_PERF_TYPE_Q_TIMEBASED = 0x08,
    SC_PERF_TYPE_Q_MAX = 0x10,
};

/**
 * \brief Different output interfaces made available by the Perf counter API
 */
enum {
    SC_PERF_IFACE_FILE,
    SC_PERF_IFACE_CONSOLE,
    SC_PERF_IFACE_SYSLOG,
    SC_PERF_IFACE_MAX,
};

/**
 * \brief Name of the counter.  Basically like a primary key for a counter
 */
typedef struct SCPerfCounterName_ {
    char *cname;
    char *tm_name;
} SCPerfCounterName;

/**
 * \brief Holds the counter value, type, and the size of the type
 */
typedef struct SCPerfCounterValue_ {
    void *cvalue;
    uint32_t size;
    uint32_t type;
} SCPerfCounterValue;

/**
 * \brief Container that holds the type qualifier for a counter
 */
typedef struct SCPerfCounterTypeQ_ {
    int type;

    int hours;
    int minutes;
    int seconds;

    int total_secs;

    /* the time interval that corresponds to the value stored for this counter.
     * Used for time_based_counters(tbc).  This represents the time period over
     * which the value in this counter was accumulated. */
    uint8_t tbc_secs;
} SCPerfCounterTypeQ;

/**
 * \brief Container to hold the counter variable
 */
typedef struct SCPerfCounter_ {
    SCPerfCounterName *name;
    SCPerfCounterValue *value;

    /* local id for this counter in this tm */
    uint16_t id;

    /* description of this counter */
    char *desc;

    /* no of times the local counter has been synced with this counter */
    uint64_t updated;

    /* flag that indicates if this counter should be displayed or not */
    int disp;

    /* counter qualifier */
    SCPerfCounterTypeQ *type_q;

    /* the next perfcounter for this tv's tm instance */
    struct SCPerfCounter_ *next;
} SCPerfCounter;

/**
 * \brief Holds the Perf Context for a ThreadVars instance
 */
typedef struct SCPerfContext_ {
    /* pointer to the head of a list of counters assigned under this context */
    SCPerfCounter *head;

    /* flag set by the wakeup thread, to inform the client threads to sync */
    uint32_t perf_flag;

    /* holds the total no of counters already assigned for this perf context */
    uint16_t curr_id;

    /* mutex to prevent simultaneous access during update_counter/output_stat */
    SCMutex m;
} SCPerfContext;

/**
 * \brief Node elements used by the SCPerfCounterArray(PCA) Node
 */
typedef struct SCPCAElem_ {
    /* pointer to the PerfCounter that corresponds to this PCAElem */
    SCPerfCounter *pc;

    /* counter id of the above counter(pc) */
    uint16_t id;

    union {
        uint64_t ui64_cnt;
        double d_cnt;
    };

    /* no of times the local counter has been updated */
    uint64_t syncs;

    /* indicates the times syncs has overflowed */
    uint64_t wrapped_syncs;

    /* timestamp to indicate the time, when the counter was last used to update
     * the global counter.  It is used for timebased counter calculations */
    struct timeval ts;
} SCPCAElem;

/**
 * \brief The SCPerfCounterArray used to hold the local version of the counters
 *        registered
 */
typedef struct SCPerfCounterArray_ {
    /* points to the array holding PCAElems */
    SCPCAElem *head;

    /* no of PCAElems in head */
    uint32_t size;
} SCPerfCounterArray;

/**
 * \brief Holds multiple instances of the same TM together, used when the stats
 *        have to be clubbed based on TM, before being sent out
 */
typedef struct SCPerfClubTMInst_ {
    char *tm_name;

    SCPerfContext **head;
    uint32_t size;

    struct SCPerfClubTMInst_ *next;
} SCPerfClubTMInst;

/**
 * \brief Holds the output interface context for the counter api
 */
typedef struct SCPerfOPIfaceContext_ {
    /* the iface to be used for output */
    uint32_t iface;

    /* the file to be used if the output interface used is SC_PERF_IFACE_FILE */
    char *file;

    /* more interfaces to be supported later.  For now just a file */
    FILE *fp;

    /* indicates whether the counter values from the same threading module
     * should be clubbed or not, during output */
    uint32_t club_tm;

    SCPerfClubTMInst *pctmi;
    SCMutex pctmi_lock;
} SCPerfOPIfaceContext;


/* the initialization functions */
void SCPerfInitCounterApi(void);
void SCPerfSpawnThreads(void);

/* the ThreadVars counter registration functions */
uint16_t SCPerfTVRegisterCounter(char *, struct ThreadVars_ *, int, char *);
uint16_t SCPerfTVRegisterAvgCounter(char *, struct ThreadVars_ *, int, char *);
uint16_t SCPerfTVRegisterMaxCounter(char *, struct ThreadVars_ *, int, char *);
uint16_t SCPerfTVRegisterIntervalCounter(char *, struct ThreadVars_ *, int,
                                         char *, char *);

/* the non-ThreadVars counter registration functions */
uint16_t SCPerfRegisterCounter(char *, char *, int, char *, SCPerfContext *);
uint16_t SCPerfRegisterAvgCounter(char *, char *, int, char *, SCPerfContext *);
uint16_t SCPerfRegisterMaxCounter(char *, char *, int, char *, SCPerfContext *);
uint16_t SCPerfRegisterIntervalCounter(char *, char *, int, char *,
                                       SCPerfContext *, char *);

/* utility functions */
int SCPerfAddToClubbedTMTable(char *, SCPerfContext *);
SCPerfCounterArray *SCPerfGetCounterArrayRange(uint16_t, uint16_t, SCPerfContext *);
SCPerfCounterArray * SCPerfGetAllCountersArray(SCPerfContext *);
int SCPerfCounterDisplay(uint16_t, SCPerfContext *, int);

int SCPerfUpdateCounterArray(SCPerfCounterArray *, SCPerfContext *, int);
double SCPerfGetLocalCounterValue(uint16_t, SCPerfCounterArray *);

void SCPerfOutputCounters(void);

/* functions used to free the resources alloted by the Perf counter API */
void SCPerfReleaseResources(void);
void SCPerfReleasePerfCounterS(SCPerfCounter *);
void SCPerfReleasePCA(SCPerfCounterArray *);

void SCPerfCounterSetUI64(uint16_t, SCPerfCounterArray *, uint64_t);
void SCPerfCounterSetDouble(uint16_t, SCPerfCounterArray *, double);
void SCPerfCounterIncr(uint16_t, SCPerfCounterArray *);

void SCPerfRegisterTests(void);

/* functions used to update local counter values */
void SCPerfCounterAddUI64(uint16_t, SCPerfCounterArray *, uint64_t);
void SCPerfCounterAddDouble(uint16_t, SCPerfCounterArray *, double);

#endif /* __COUNTERS_H__ */
