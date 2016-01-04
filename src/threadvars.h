/* Copyright (C) 2007-2013 Open Information Security Foundation
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
 * \author Victor Julien <victor@inliniac.net>
 */

#ifndef __THREADVARS_H__
#define __THREADVARS_H__

#include "util-mpm.h"
#include "util-affinity.h"
#include "tm-queues.h"
#include "counters.h"
#include "threads.h"

struct TmSlot_;

/** Thread flags set and read by threads to control the threads */
#define THV_USE       1 /** thread is in use */
#define THV_INIT_DONE (1 << 1) /** thread initialization done */
#define THV_PAUSE     (1 << 2) /** signal thread to pause itself */
#define THV_PAUSED    (1 << 3) /** the thread is paused atm */
#define THV_KILL      (1 << 4) /** thread has been asked to cleanup and exit */
#define THV_FAILED    (1 << 5) /** thread has encountered an error and failed */
#define THV_CLOSED    (1 << 6) /** thread done, should be joinable */
/* used to indicate the thread is going through de-init.  Introduced as more
 * of a hack for solving stream-timeout-shutdown.  Is set by the main thread. */
#define THV_DEINIT    (1 << 7)
#define THV_RUNNING_DONE (1 << 8) /** thread has completed running and is entering
                                   * the de-init phase */
#define THV_KILL_PKTACQ (1 << 9)    /**< flag thread to stop packet acq */
#define THV_FLOW_LOOP (1 << 10)   /**< thread is in flow shutdown loop */

/** Thread flags set and read by threads, to control the threads, when they
 *  encounter certain conditions like failure */
#define THV_RESTART_THREAD 0x01 /** restart the thread */
#define THV_ENGINE_EXIT 0x02 /** shut the engine down gracefully */

/** Maximum no of times a thread can be restarted */
#define THV_MAX_RESTARTS 50

/** \brief Per thread variable structure */
typedef struct ThreadVars_ {
    pthread_t t;
    char *name;
    char *thread_group_name;

    SC_ATOMIC_DECLARE(unsigned int, flags);

    /** aof(action on failure) determines what should be done with the thread
        when it encounters certain conditions like failures */
    uint8_t aof;

    /** no of times the thread has been restarted on failure */
    uint8_t restarted;

    /** TmModule::flags for each module part of this thread */
    uint8_t tmm_flags;

    /** local id */
    int id;

    /** queue's */
    Tmq *inq;
    Tmq *outq;
    void *outctx;
    char *outqh_name;

    /** queue handlers */
    struct Packet_ * (*tmqh_in)(struct ThreadVars_ *);
    void (*InShutdownHandler)(struct ThreadVars_ *);
    void (*tmqh_out)(struct ThreadVars_ *, struct Packet_ *);

    /** slot functions */
    void *(*tm_func)(void *);
    struct TmSlot_ *tm_slots;

    /** stream packet queue for flow time out injection */
    struct PacketQueue_ *stream_pq;

    uint8_t thread_setup_flags;

    /** the type of thread as defined in tm-threads.h (TVT_PPT, TVT_MGMT) */
    uint8_t type;

    uint16_t cpu_affinity; /** cpu or core number to set affinity to */
    uint16_t rank;
    int thread_priority; /** priority (real time) for this thread. Look at threads.h */

    /* counters */

    /** public counter store: counter syncs update this */
    StatsPublicThreadContext perf_public_ctx;

    /** private counter store: counter updates modify this */
    StatsPrivateThreadContext perf_private_ctx;

    SCCtrlMutex *ctrl_mutex;
    SCCtrlCondT *ctrl_cond;

    uint8_t cap_flags; /**< Flags to indicate the capabilities of all the
                            TmModules resgitered under this thread */
    struct ThreadVars_ *next;
    struct ThreadVars_ *prev;
} ThreadVars;

/** Thread setup flags: */
#define THREAD_SET_AFFINITY     0x01 /** CPU/Core affinity */
#define THREAD_SET_PRIORITY     0x02 /** Real time priority */
#define THREAD_SET_AFFTYPE      0x04 /** Priority and affinity */

#endif /* __THREADVARS_H__ */

