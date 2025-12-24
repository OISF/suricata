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
 */

#ifndef SURICATA_COUNTERS_H
#define SURICATA_COUNTERS_H

#include "threads.h"

typedef struct StatsCounterId {
    uint16_t id;
} StatsCounterId;

typedef struct StatsCounterAvgId {
    uint16_t id;
} StatsCounterAvgId;

typedef struct StatsCounterMaxId {
    uint16_t id;
} StatsCounterMaxId;

typedef struct StatsCounterGlobalId {
    uint16_t id;
} StatsCounterGlobalId;

/* derive counters are counters that are derived from 2 other
 * counters. */
typedef struct StatsCounterDeriveId {
    uint16_t id;
} StatsCounterDeriveId;

/**
 * \brief Container to hold the counter variable
 */
typedef struct StatsCounter_ {
    int type; /**< enum StatsType from counters.c */

    /* local id for this counter in this thread */
    uint16_t id;

    /* global id, used in output */
    uint16_t gid;

    /* derive id's: thread specific id's for the 2 counters part
     * of this derive counter. */
    uint16_t did1;
    uint16_t did2;

    /* when using type STATS_TYPE_FUNC this function is called once
     * to get the counter value, regardless of how many threads there are. */
    uint64_t (*Func)(void);

    /* name of the counter */
    const char *name;
    const char *short_name;

    /* the next perfcounter for this tv's tm instance */
    struct StatsCounter_ *next;
} StatsCounter;

/**
 * \brief counter type for local (private) increments.
 * For AVG counters we use 2 to track values and updates.
 */
typedef struct StatsLocalCounter_ {
    int64_t v;
} StatsLocalCounter;

/**
 * \brief Stats Context for a ThreadVars instance
 */
typedef struct StatsPublicThreadContext_ {
    /* pointer to the head of a list of counters assigned under this context */
    StatsCounter *head;

    /* flag set by the wakeup thread, to inform the client threads to sync */
    SC_ATOMIC_DECLARE(bool, sync_now);

    /* holds the total no of counters already assigned for this perf context */
    uint16_t curr_id;

    /* separate id space for derive counters. These are set up per thread, but should not be part
     * the StatsLocalCounter array as they are not updated in the thread directly. */
    uint16_t derive_id;

    /* array of pointers to the StatsCounters in `head` above, indexed by the per
     * thread counter id.
     * Size is `curr_id + 1` after all counters have been registered.
     * Ownership of counters is with `head` above. */
    const StatsCounter **pc_array;

    StatsLocalCounter *copy_of_private;

    /* lock to prevent simultaneous access during update_counter/output_stat */
    SCSpinlock lock;
} StatsPublicThreadContext;

/**
 * \brief used to hold the private version of the counters registered
 */
typedef struct StatsPrivateThreadContext_ {
    /* points to the array holding local counters */
    StatsLocalCounter *head;

    /* size of head array in elements */
    uint32_t size;

    int initialized;
} StatsPrivateThreadContext;

typedef struct StatsThreadContext_ {
    StatsPublicThreadContext pub;
    StatsPrivateThreadContext priv;
} StatsThreadContext;

/* the initialization functions */
void StatsInit(void);
void StatsSetupPostConfigPreOutput(void);
void StatsSetupPostConfigPostOutput(void);
void StatsSpawnThreads(void);
void StatsRegisterTests(void);
bool StatsEnabled(void);

/* functions used to free the resources allotted by the Stats API */
void StatsReleaseResources(void);

/* counter registration functions */
StatsCounterId StatsRegisterCounter(const char *, StatsThreadContext *);
StatsCounterAvgId StatsRegisterAvgCounter(const char *, StatsThreadContext *);
StatsCounterMaxId StatsRegisterMaxCounter(const char *, StatsThreadContext *);
StatsCounterGlobalId StatsRegisterGlobalCounter(const char *cname, uint64_t (*Func)(void));

StatsCounterDeriveId StatsRegisterDeriveDivCounter(
        const char *cname, const char *dname1, const char *dname2, StatsThreadContext *);

/* functions used to update local counter values */
void StatsCounterAddI64(StatsThreadContext *, StatsCounterId, int64_t);
void StatsCounterSetI64(StatsThreadContext *, StatsCounterId, int64_t);
void StatsCounterIncr(StatsThreadContext *, StatsCounterId);
void StatsCounterDecr(StatsThreadContext *, StatsCounterId);

void StatsCounterMaxUpdateI64(StatsThreadContext *, StatsCounterMaxId id, int64_t x);
void StatsCounterAvgAddI64(StatsThreadContext *, StatsCounterAvgId id, int64_t x);

/* utility functions */
int64_t StatsCounterGetLocalValue(StatsThreadContext *, StatsCounterId);
void StatsThreadInit(StatsThreadContext *);
int StatsSetupPrivate(StatsThreadContext *, const char *);
void StatsThreadCleanup(StatsThreadContext *);

void StatsSyncCounters(StatsThreadContext *);
void StatsSyncCountersIfSignalled(StatsThreadContext *);

#ifdef BUILD_UNIX_SOCKET
TmEcode StatsOutputCounterSocket(json_t *cmd,
                                 json_t *answer, void *data);
#endif

#endif /* SURICATA_COUNTERS_H */
