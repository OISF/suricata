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
 * \author Ken Steele <suricata@tilera.com>
 *
 * Time keeping for offline (non-live) packet handling (pcap files).
 * And time string generation for alerts.
 */

#include "suricata-common.h"
#include "detect.h"
#include "threads.h"
#include "util-debug.h"

static struct timeval current_time = { 0, 0 };
//static SCMutex current_time_mutex = SCMUTEX_INITIALIZER;
static SCSpinlock current_time_spinlock;
static char live = TRUE;


struct tm *SCLocalTime(time_t timep, struct tm *result);

void TimeInit(void)
{
    SCSpinInit(&current_time_spinlock, 0);

    /* Initialize Time Zone settings. */
    tzset();
}

void TimeDeinit(void)
{
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
void TimeSetToCurrentTime(void)
{
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
void TimeSetIncrementTime(uint32_t tv_sec)
{
    struct timeval tv;
    memset(&tv, 0x00, sizeof(tv));
    TimeGet(&tv);

    tv.tv_sec += tv_sec;

    TimeSet(&tv);
}

void CreateIsoTimeString (const struct timeval *ts, char *str, size_t size)
{
    time_t time = ts->tv_sec;
    struct tm local_tm;
    struct tm *t = (struct tm*)SCLocalTime(time, &local_tm);
    char time_fmt[64] = { 0 };

    if (likely(t != NULL)) {
        strftime(time_fmt, sizeof(time_fmt), "%Y-%m-%dT%H:%M:%S.%%06u%z", t);
        snprintf(str, size, time_fmt, ts->tv_usec);
    } else {
        snprintf(str, size, "ts-error");
    }
}

/*
 * Time Caching code
 */

#ifndef TLS
/* OpenBSD does not support __thread, so don't use time caching on BSD
 */
struct tm *SCLocalTime(time_t timep, struct tm *result)
{
    return localtime_r(&timep, result);
}

void CreateTimeString (const struct timeval *ts, char *str, size_t size)
{
    time_t time = ts->tv_sec;
    struct tm local_tm;
    struct tm *t = (struct tm*)SCLocalTime(time, &local_tm);

    if (likely(t != NULL)) {
        snprintf(str, size, "%02d/%02d/%02d-%02d:%02d:%02d.%06u",
                t->tm_mon + 1, t->tm_mday, t->tm_year + 1900, t->tm_hour,
                t->tm_min, t->tm_sec, (uint32_t) ts->tv_usec);
    } else {
        snprintf(str, size, "ts-error");
    }
}

#else

/* On systems supporting __thread, use Per-thread values for caching
 * in CreateTimeString */

/* The maximum possible length of the time string.
 * "%02d/%02d/%02d-%02d:%02d:%02d.%06u"
 * Or "01/01/2013-15:42:21.123456", which is 26, so round up to 32. */
#define MAX_LOCAL_TIME_STRING 32

static __thread int mru_time_slot; /* Most recently used cached value */
static __thread time_t last_local_time[2];
static __thread short int cached_local_time_len[2];
static __thread char cached_local_time[2][MAX_LOCAL_TIME_STRING];

/* Per-thread values for caching SCLocalTime() These cached values are
 * independent from the CreateTimeString cached values. */
static __thread int mru_tm_slot; /* Most recently used local tm */
static __thread time_t cached_minute_start[2];
static __thread struct tm cached_local_tm[2];

/** \brief Convert time_t into Year, month, day, hour and minutes.
 * \param timep Time in seconds since defined date.
 * \param result The structure into which the broken down time it put.
 *
 * To convert a time in seconds into year, month, day, hours, minutes
 * and seconds, call localtime_r(), which uses the current time zone
 * to compute these values. Note, glibc's localtime_r() aquires a lock
 * each time it is called, which limits parallelism. To call
 * localtime_r() less often, the values returned are cached for the
 * current and previous minute and then seconds are adjusted to
 * compute the returned result. This is valid as long as the
 * difference between the start of the current minute and the current
 * time is less than 60 seconds. Once the minute value changes, all
 * the other values could change.
 *
 * Two values are cached to prevent thrashing when changing from one
 * minute to the next. The two cached minutes are independent and are
 * not required to be M and M+1. If more than two minutes are
 * requested, the least-recently-used cached value is updated more
 * often, the results are still correct, but performance will be closer
 * to previous performance.
 */
struct tm *SCLocalTime(time_t timep, struct tm *result)
{
    /* Only get a new local time when the time crosses into a new
     * minute. */
    int mru = mru_tm_slot;
    int lru = 1 - mru;
    int mru_seconds = timep - cached_minute_start[mru];
    int lru_seconds = timep - cached_minute_start[lru];
    int new_seconds;
    if (mru_seconds >= 0 && mru_seconds <= 59) {
        /* Use most-recently cached time, adjusting the seconds. */
        new_seconds = mru_seconds;
    } else if (lru_seconds >= 0 && lru_seconds <= 59) {
        /* Use least-recently cached time, update to most recently used. */
        new_seconds = lru_seconds;
        mru = lru;
        mru_tm_slot = mru;
    } else {
        /* Update least-recent cached time. */
        if (localtime_r(&timep, &cached_local_tm[lru]) == NULL)
            return NULL;

        /* Subtract seconds to get back to the start of the minute. */
        new_seconds = cached_local_tm[lru].tm_sec;
        cached_minute_start[lru] = timep - new_seconds;
        mru = lru;
        mru_tm_slot = mru;
    }
    memcpy(result, &cached_local_tm[mru], sizeof(struct tm));
    result->tm_sec = new_seconds;

    return result;
}

/* Update the cached time string in cache index N, for the current minute. */
static int UpdateCachedTime(int n, time_t time)
{
    struct tm local_tm;
    struct tm *t = (struct tm *)SCLocalTime(time, &local_tm);
    int cached_len = snprintf(cached_local_time[n], MAX_LOCAL_TIME_STRING,
                              "%02d/%02d/%02d-%02d:%02d:",
                              t->tm_mon + 1, t->tm_mday, t->tm_year + 1900,
                              t->tm_hour, t->tm_min);
    cached_local_time_len[n] = cached_len;
    /* Store the time of the beginning of the minute. */
    last_local_time[n] = time - t->tm_sec;
    mru_time_slot = n;

    return t->tm_sec;
}

/** \brief Return a formatted string for the provided time.
 *
 * Cache the Month/Day/Year - Hours:Min part of the time string for
 * the current minute. Copy that result into the the return string and
 * then only print the seconds for each call.
 */
void CreateTimeString (const struct timeval *ts, char *str, size_t size)
{
    time_t time = ts->tv_sec;
    int seconds;

    /* Only get a new local time when the time crosses into a new
     * minute */
    int mru = mru_time_slot;
    int lru = 1 - mru;
    int mru_seconds = time - last_local_time[mru];
    int lru_seconds = time - last_local_time[lru];
    if (mru_seconds >= 0 && mru_seconds <= 59) {
        /* Use most-recently cached time. */
        seconds = mru_seconds;
    } else if (lru_seconds >= 0 && lru_seconds <= 59) {
        /* Use least-recently cached time. Change this slot to Most-recent */
        seconds = lru_seconds;
        mru_time_slot = lru;
    } else {
        /* Update least-recent cached time. Lock accessing local time
         * function because it keeps any internal non-spin lock. */
        seconds = UpdateCachedTime(lru, time);
    }

    /* Copy the string up to the current minute then print the seconds
       into the return string buffer. */
    char *cached_str = cached_local_time[mru_time_slot];
    int cached_len = cached_local_time_len[mru_time_slot];
    if (cached_len >= (int)size)
      cached_len = size;
    memcpy(str, cached_str, cached_len);
    snprintf(str + cached_len, size - cached_len,
             "%02d.%06u",
             seconds, (uint32_t) ts->tv_usec);
}

#endif /* defined(__OpenBSD__) */
