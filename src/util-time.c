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
 * \author Victor Julien <victor@inliniac.net>
 *
 * Time keeping for offline (non-live) packet handling (pcap files)
 */

#include "suricata-common.h"
#include "detect.h"
#include "threads.h"
#include "util-debug.h"

static struct timeval current_time = { 0, 0 };
//static SCMutex current_time_mutex = PTHREAD_MUTEX_INITIALIZER;
static SCSpinlock current_time_spinlock;
static char live = TRUE;

void TimeInit(void) {
    SCSpinInit(&current_time_spinlock, 0);
}

void TimeDeinit(void) {
    SCSpinDestroy(&current_time_spinlock);
}

void TimeModeSetLive(void)
{
    live = TRUE;
    SCLogDebug("live time mode enabled");
}

void TimeModeSetOffline (void)
{
    live = FALSE;
    SCLogDebug("offline time mode enabled");
}

void TimeSet(struct timeval *tv)
{
    if (live == TRUE)
        return;

    if (tv == NULL)
        return;

    SCSpinLock(&current_time_spinlock);
    current_time.tv_sec = tv->tv_sec;
    current_time.tv_usec = tv->tv_usec;

    SCLogDebug("time set to %" PRIuMAX " sec, %" PRIuMAX " usec",
               (uintmax_t)current_time.tv_sec, (uintmax_t)current_time.tv_usec);

    SCSpinUnlock(&current_time_spinlock);
}

/** \brief set the time to "gettimeofday" meant for testing */
void TimeSetToCurrentTime(void) {
    struct timeval tv;
    memset(&tv, 0x00, sizeof(tv));

    gettimeofday(&tv, NULL);

    TimeSet(&tv);
}

void TimeGet(struct timeval *tv)
{
    if (tv == NULL)
        return;

    if (live == TRUE) {
        gettimeofday(tv, NULL);
    } else {
        SCSpinLock(&current_time_spinlock);
        tv->tv_sec = current_time.tv_sec;
        tv->tv_usec = current_time.tv_usec;
        SCSpinUnlock(&current_time_spinlock);
    }

    SCLogDebug("time we got is %" PRIuMAX " sec, %" PRIuMAX " usec",
               (uintmax_t)tv->tv_sec, (uintmax_t)tv->tv_usec);
}

/** \brief increment the time in the engine
 *  \param tv_sec seconds to increment the time with */
void TimeSetIncrementTime(uint32_t tv_sec) {
    struct timeval tv;
    memset(&tv, 0x00, sizeof(tv));
    TimeGet(&tv);

    tv.tv_sec += tv_sec;

    TimeSet(&tv);
}


struct tm *SCLocalTime(time_t timep, struct tm *result)
{
    return localtime_r(&timep, result);
}
