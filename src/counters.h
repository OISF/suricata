/* Copyright (C) 2007-2015 Open Information Security Foundation
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
 * \brief Container to hold the counter variable
 */
typedef struct SCPerfCounter_ {
    int type;

    /* local id for this counter in this tm */
    uint16_t id;

    /* global id */
    uint16_t gid;

    /* counter value(s): copies from the 'private' counter */
    uint64_t value;     /**< sum of updates/increments, or 'set' value */
    uint64_t updates;   /**< number of updates (for avg) */

    /* when using type SC_PERF_TYPE_Q_FUNC this function is called once
     * to get the counter value, regardless of how many threads there are. */
    uint64_t (*Func)(void);

    /* name of the counter */
    char *cname;

    /* the next perfcounter for this tv's tm instance */
    struct SCPerfCounter_ *next;
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

    /* total value of the adds/increments, or exact value in case of 'set' */
    uint64_t value;

    /* no of times the local counter has been updated */
    uint64_t updates;
} SCPCAElem;

/**
 * \brief used to hold the private version of the counters registered
 */
typedef struct SCPerfPrivateContext_ {
    /* points to the array holding PCAElems */
    SCPCAElem *head;

    /* no of PCAElems in head */
    uint32_t size;

    int initialized;
} SCPerfPrivateContext;

/* the initialization functions */
void StatsInit(void);
void StatsSetupPostConfig(void);
void SCPerfSpawnThreads(void);
void SCPerfRegisterTests(void);

/* counter registration functions */
uint16_t SCPerfTVRegisterCounter(char *, struct ThreadVars_ *, int);
uint16_t SCPerfTVRegisterAvgCounter(char *, struct ThreadVars_ *, int);
uint16_t SCPerfTVRegisterMaxCounter(char *, struct ThreadVars_ *, int);
uint16_t SCPerfTVRegisterGlobalCounter(char *cname, uint64_t (*Func)(void));

/* utility functions */
int SCPerfUpdateCounterArray(SCPerfPrivateContext *, SCPerfPublicContext *);
uint64_t SCPerfGetLocalCounterValue(struct ThreadVars_ *, uint16_t);
int SCPerfSetupPrivate(struct ThreadVars_ *);

/* functions used to free the resources alloted by the Perf counter API */
void SCPerfReleaseResources(void);
void SCPerfReleasePCA(SCPerfPrivateContext *);

/* functions used to update local counter values */
void SCPerfCounterAddUI64(struct ThreadVars_ *, uint16_t, uint64_t);
void SCPerfCounterSetUI64(struct ThreadVars_ *, uint16_t, uint64_t);
void SCPerfCounterIncr(struct ThreadVars_ *, uint16_t);

#define SCPerfSyncCounters(tv) \
    SCPerfUpdateCounterArray(&(tv)->perf_private_ctx, &(tv)->perf_public_ctx);  \

#define SCPerfSyncCountersIfSignalled(tv)                                       \
    do {                                                                        \
        if ((tv)->perf_public_ctx.perf_flag == 1) {                             \
            SCPerfUpdateCounterArray(&(tv)->perf_private_ctx,                   \
                                     &(tv)->perf_public_ctx);                   \
        }                                                                       \
    } while (0)

#ifdef BUILD_UNIX_SOCKET
#include <jansson.h>
TmEcode SCPerfOutputCounterSocket(json_t *cmd,
                               json_t *answer, void *data);
#endif

#endif /* __COUNTERS_H__ */

