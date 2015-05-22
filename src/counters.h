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
 */

#ifndef __COUNTERS_H__
#define __COUNTERS_H__

/* forward declaration of the ThreadVars structure */
struct ThreadVars_;

/**
 * \brief Data type for different kind of Perf counters that can be registered
 */
enum {
    SC_PERF_TYPE_UINT64,
    SC_PERF_TYPE_MAX,
};

/**
 * \brief Different kinds of qualifier that can be used to modify the behaviour
 *        of the Perf counter to be registered
 */
enum {
    SC_PERF_TYPE_Q_NORMAL = 1,
    SC_PERF_TYPE_Q_AVERAGE = 2,
    SC_PERF_TYPE_Q_MAXIMUM = 3,
    SC_PERF_TYPE_Q_MAX = 4,
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
 * \brief Container to hold the counter variable
 */
typedef struct SCPerfCounter_ {
    int type;

    /* local id for this counter in this tm */
    uint16_t id;

    uint64_t value;

    /* name of the counter */
    char *cname;
    /* name of the thread module this counter is registered to */
    char *tm_name;

    /* the next perfcounter for this tv's tm instance */
    struct SCPerfCounter_ *next;

    /* description of this counter */
    char *desc;
} SCPerfCounter;

/**
 * \brief Holds the Perf Context for a ThreadVars instance
 */
typedef struct SCPerfPublicContext_ {
    /* flag set by the wakeup thread, to inform the client threads to sync */
    uint32_t perf_flag;

    /* pointer to the head of a list of counters assigned under this context */
    SCPerfCounter *head;

    /* holds the total no of counters already assigned for this perf context */
    uint16_t curr_id;

    /* mutex to prevent simultaneous access during update_counter/output_stat */
    SCMutex m;
} SCPerfPublicContext;

/**
 * \brief Node elements used by the SCPerfPrivateContext(PCA) Node
 */
typedef struct SCPCAElem_ {
    /* pointer to the PerfCounter that corresponds to this PCAElem */
    SCPerfCounter *pc;

    /* counter id of the above counter(pc) */
    uint16_t id;

    uint64_t ui64_cnt;

    /* no of times the local counter has been updated */
    uint64_t syncs;
} SCPCAElem;

/**
 * \brief used to hold the private version of the counters registered
 */
typedef struct SCPerfPrivateContext_ {
    /* points to the array holding PCAElems */
    SCPCAElem *head;

    /* no of PCAElems in head */
    uint32_t size;
} SCPerfPrivateContext;

/**
 * \brief Holds multiple instances of the same TM together, used when the stats
 *        have to be clubbed based on TM, before being sent out
 */
typedef struct SCPerfClubTMInst_ {
    char *tm_name;

    SCPerfPublicContext **head;
    uint32_t size;

    struct SCPerfClubTMInst_ *next;
} SCPerfClubTMInst;

/**
 * \brief Holds the output interface context for the counter api
 */
typedef struct SCPerfOPIfaceContext_ {
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

/* the non-ThreadVars counter registration functions */
uint16_t SCPerfRegisterCounter(char *, char *, int, char *, SCPerfPublicContext *);
uint16_t SCPerfRegisterAvgCounter(char *, char *, int, char *, SCPerfPublicContext *);
uint16_t SCPerfRegisterMaxCounter(char *, char *, int, char *, SCPerfPublicContext *);

/* utility functions */
int SCPerfAddToClubbedTMTable(char *, SCPerfPublicContext *);
SCPerfPrivateContext *SCPerfGetCounterArrayRange(uint16_t, uint16_t, SCPerfPublicContext *);
SCPerfPrivateContext * SCPerfGetAllCountersArray(SCPerfPublicContext *);

int SCPerfUpdateCounterArray(SCPerfPrivateContext *, SCPerfPublicContext *);
double SCPerfGetLocalCounterValue(uint16_t, SCPerfPrivateContext *);

/* functions used to free the resources alloted by the Perf counter API */
void SCPerfReleaseResources(void);
void SCPerfReleasePerfCounterS(SCPerfCounter *);
void SCPerfReleasePCA(SCPerfPrivateContext *);

void SCPerfCounterSetUI64(uint16_t, SCPerfPrivateContext *, uint64_t);
void SCPerfCounterIncr(uint16_t, SCPerfPrivateContext *);

void SCPerfRegisterTests(void);

/* functions used to update local counter values */
void SCPerfCounterAddUI64(uint16_t, SCPerfPrivateContext *, uint64_t);

#define SCPerfSyncCounters(tv) \
    SCPerfUpdateCounterArray((tv)->sc_perf_pca, &(tv)->perf_public_ctx);           \

#define SCPerfSyncCountersIfSignalled(tv)                                       \
    do {                                                                        \
        if ((tv)->perf_public_ctx.perf_flag == 1) {                                \
            SCPerfUpdateCounterArray((tv)->sc_perf_pca, &(tv)->perf_public_ctx);   \
        }                                                                       \
    } while (0)

#ifdef BUILD_UNIX_SOCKET
#include <jansson.h>
TmEcode SCPerfOutputCounterSocket(json_t *cmd,
                               json_t *answer, void *data);
#endif

#endif /* __COUNTERS_H__ */

