/* Copyright (C) 2007-2020 Open Information Security Foundation
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

/* Real time vs offline time
 *
 * When we run on live traffic, time handling is simple. Packets have a
 * timestamp set by the capture method. Management threads can simply
 * use 'gettimeofday' to know the current time. There should never be
 * any serious gap between the two.
 *
 * In offline mode, things are dramatically different. Here we try to keep
 * the time from the pcap, which means that if the packets are in 2011 the
 * log output should also reflect this. Multiple issues:
 * 1. merged pcaps might have huge time jumps or time going backward
 * 2. slowly recorded pcaps may be processed much faster than their 'realtime'
 * 3. management threads need a concept of what the 'current' time is for
 *    enforcing timeouts
 * 4. due to (1) individual threads may have very different views on what
 *    the current time is. E.g. T1 processed packet 1 with TS X, while T2
 *    at the very same time processes packet 2 with TS X+100000s.
 *
 * In offline mode we keep the timestamp per thread. If a management thread
 * needs current time, it will get the minimum of the threads' values. This
 * is to avoid the problem that T2s time value might already trigger a flow
 * timeout as the flow lastts + 100000s is almost certainly meaning the flow
 * would be considered timed out.
 */

#ifdef OS_WIN32
/* for MinGW we need to set _POSIX_C_SOURCE before including
 * sys/time.h. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#endif

#include "suricata-common.h"
#include "suricata.h"
#include "detect.h"
#include "threads.h"
#include "tm-threads.h"
#include "util-debug.h"
#include "util-time.h"

#ifdef UNITTESTS
static struct timeval current_time = { 0, 0 };
#endif
//static SCMutex current_time_mutex = SCMUTEX_INITIALIZER;
static SCSpinlock current_time_spinlock;
static bool live_time_tracking = true;

struct tm *SCLocalTime(time_t timep, struct tm *result);
struct tm *SCUtcTime(time_t timep, struct tm *result);

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

bool TimeModeIsReady(void)
{
    if (live_time_tracking)
        return true;
    return TmThreadsTimeSubsysIsReady();
}

void TimeModeSetLive(void)
{
    live_time_tracking = true;
    SCLogDebug("live time mode enabled");
}

void TimeModeSetOffline (void)
{
    live_time_tracking = false;
    SCLogDebug("offline time mode enabled");
}

bool TimeModeIsLive(void)
{
    return live_time_tracking;
}

void TimeSetByThread(const int thread_id, SCTime_t tv)
{
    if (live_time_tracking)
        return;

    TmThreadsSetThreadTimestamp(thread_id, tv);
}

#ifdef UNITTESTS
void TimeSet(SCTime_t ts)
{
    if (live_time_tracking)
        return;

    SCSpinLock(&current_time_spinlock);
    SCTIME_TO_TIMEVAL(&current_time, ts);

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

    SCTime_t ts = SCTIME_FROM_TIMEVAL(&tv);
    TimeSet(ts);
}
#endif

SCTime_t TimeGet(void)
{
    struct timeval tv = { 0 };
    if (live_time_tracking) {
        gettimeofday(&tv, NULL);
    } else {
#ifdef UNITTESTS
        if (unlikely(RunmodeIsUnittests())) {
            SCSpinLock(&current_time_spinlock);
            tv.tv_sec = current_time.tv_sec;
            tv.tv_usec = current_time.tv_usec;
            SCSpinUnlock(&current_time_spinlock);
        } else {
#endif
            TmThreadsGetMinimalTimestamp(&tv);
#ifdef UNITTESTS
        }
#endif
    }

    SCLogDebug("time we got is %" PRIuMAX " sec, %" PRIuMAX " usec", (uintmax_t)tv.tv_sec,
            (uintmax_t)tv.tv_usec);
    return SCTIME_FROM_TIMEVAL(&tv);
}

#ifdef UNITTESTS
/** \brief increment the time in the engine
 *  \param tv_sec seconds to increment the time with */
void TimeSetIncrementTime(uint32_t tv_sec)
{
    SCTime_t ts = TimeGet();

    ts = SCTIME_ADD_SECS(ts, tv_sec);

    TimeSet(ts);
}
#endif

#ifdef OS_WIN32
/** \internal
 *  \brief wrapper around strftime on Windows to provide output
 *         compatible with posix %z
 */
static inline void WinStrftime(const SCTime_t ts, const struct tm *t, char *str, size_t size)
{
    char time_fmt[64] = { 0 };
    char tz[6] = { 0 };
    const long int tzdiff = -_timezone;
    const int h = abs(_timezone) / 3600 + _daylight;
    const int m = (abs(_timezone) % 3600) / 60;
    snprintf(tz, sizeof(tz), "%c%02d%02d", tzdiff < 0 ? '-' : '+', h, m);
    strftime(time_fmt, sizeof(time_fmt), "%Y-%m-%dT%H:%M:%S.%%06u", t);
    snprintf(str, size, time_fmt, SCTIME_USECS(ts));
    strlcat(str, tz, size); // append our timezone
}
#endif

void CreateIsoTimeString(const SCTime_t ts, char *str, size_t size)
{
    time_t time = SCTIME_SECS(ts);
    struct tm local_tm;
    memset(&local_tm, 0, sizeof(local_tm));
    struct tm *t = (struct tm*)SCLocalTime(time, &local_tm);

    if (likely(t != NULL)) {
#ifdef OS_WIN32
        WinStrftime(ts, t, str, size);
#else
        char time_fmt[64] = { 0 };
        int64_t usec = SCTIME_USECS(ts);
        strftime(time_fmt, sizeof(time_fmt), "%Y-%m-%dT%H:%M:%S.%%06" PRIi64 "%z", t);
        snprintf(str, size, time_fmt, usec);
#endif
    } else {
        snprintf(str, size, "ts-error");
    }
}

void CreateUtcIsoTimeString(const SCTime_t ts, char *str, size_t size)
{
    time_t time = SCTIME_SECS(ts);
    struct tm local_tm;
    memset(&local_tm, 0, sizeof(local_tm));
    struct tm *t = (struct tm*)SCUtcTime(time, &local_tm);

    if (likely(t != NULL)) {
        char time_fmt[64] = { 0 };
        strftime(time_fmt, sizeof(time_fmt), "%Y-%m-%dT%H:%M:%S", t);
        snprintf(str, size, time_fmt, SCTIME_USECS(ts));
    } else {
        snprintf(str, size, "ts-error");
    }
}

void CreateFormattedTimeString (const struct tm *t, const char *fmt, char *str, size_t size)
{
    if (likely(t != NULL)) {
        strftime(str, size, fmt, t);
    } else {
        snprintf(str, size, "ts-error");
    }
}

struct tm *SCUtcTime(time_t timep, struct tm *result)
{
    return gmtime_r(&timep, result);
}

/*
 * Time Caching code
 */

#ifndef TLS
/* OpenBSD does not support thread_local, so don't use time caching on BSD
 */
struct tm *SCLocalTime(time_t timep, struct tm *result)
{
    return localtime_r(&timep, result);
}

void CreateTimeString(const SCTime_t ts, char *str, size_t size)
{
    time_t time = SCTIME_SECS(ts);
    struct tm local_tm;
    struct tm *t = (struct tm*)SCLocalTime(time, &local_tm);

    if (likely(t != NULL)) {
        snprintf(str, size, "%02d/%02d/%02d-%02d:%02d:%02d.%06u", t->tm_mon + 1, t->tm_mday,
                t->tm_year + 1900, t->tm_hour, t->tm_min, t->tm_sec, (uint32_t)SCTIME_USECS(ts));
    } else {
        snprintf(str, size, "ts-error");
    }
}

#else

/* On systems supporting thread_local, use Per-thread values for caching
 * in CreateTimeString */

/* The maximum possible length of the time string.
 * "%02d/%02d/%02d-%02d:%02d:%02d.%06u"
 * Or "01/01/2013-15:42:21.123456", which is 26, so round up to 32. */
#define MAX_LOCAL_TIME_STRING 32

static thread_local int mru_time_slot; /* Most recently used cached value */
static thread_local time_t last_local_time[2];
static thread_local short int cached_local_time_len[2];
static thread_local char cached_local_time[2][MAX_LOCAL_TIME_STRING];

/* Per-thread values for caching SCLocalTime() These cached values are
 * independent from the CreateTimeString cached values. */
static thread_local int mru_tm_slot; /* Most recently used local tm */
static thread_local time_t cached_minute_start[2];
static thread_local struct tm cached_local_tm[2];

/** \brief Convert time_t into Year, month, day, hour and minutes.
 * \param timep Time in seconds since defined date.
 * \param result The structure into which the broken down time it put.
 *
 * To convert a time in seconds into year, month, day, hours, minutes
 * and seconds, call localtime_r(), which uses the current time zone
 * to compute these values. Note, glibc's localtime_r() acquires a lock
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
    if (cached_minute_start[mru]==0 && cached_minute_start[lru]==0) {
        localtime_r(&timep, &cached_local_tm[lru]);
        /* Subtract seconds to get back to the start of the minute. */
        new_seconds = cached_local_tm[lru].tm_sec;
        cached_minute_start[lru] = timep - new_seconds;
        mru = lru;
        mru_tm_slot = mru;
    } else if (lru_seconds > 0 && (mru_seconds >= 0 && mru_seconds <= 59)) {
        /* Use most-recently cached time, adjusting the seconds. */
        new_seconds = mru_seconds;
    } else if (mru_seconds > 0 && (lru_seconds >= 0 && lru_seconds <= 59)) {
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
 * the current minute. Copy that result into the return string and
 * then only print the seconds for each call.
 */
void CreateTimeString(const SCTime_t ts, char *str, size_t size)
{
    time_t time = SCTIME_SECS(ts);
    int seconds;

    /* Only get a new local time when the time crosses into a new
     * minute */
    int mru = mru_time_slot;
    int lru = 1 - mru;
    int mru_seconds = time - last_local_time[mru];
    int lru_seconds = time - last_local_time[lru];
    if (last_local_time[mru]==0 && last_local_time[lru]==0) {
        /* First time here, update both caches */
        UpdateCachedTime(mru, time);
        seconds = UpdateCachedTime(lru, time);
    } else if (mru_seconds >= 0 && mru_seconds <= 59) {
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
    snprintf(str + cached_len, size - cached_len, "%02d.%06u", seconds, (uint32_t)SCTIME_USECS(ts));
}

#endif /* defined(__OpenBSD__) */

/**
 * \brief Convert broken-down time to seconds since Unix epoch.
 *
 * This function is based on: http://www.catb.org/esr/time-programming
 * (released to the public domain).
 *
 * \param tp Pointer to broken-down time.
 *
 * \retval Seconds since Unix epoch.
 */
time_t SCMkTimeUtc (struct tm *tp)
{
    time_t result;
    long year;
#define MONTHSPERYEAR 12
    static const int mdays[MONTHSPERYEAR] =
            { 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334 };

    year = 1900 + tp->tm_year + tp->tm_mon / MONTHSPERYEAR;
    result = (year - 1970) * 365 + mdays[tp->tm_mon % MONTHSPERYEAR];
    result += (year - 1968) / 4;
    result -= (year - 1900) / 100;
    result += (year - 1600) / 400;
    if ((year % 4) == 0 && ((year % 100) != 0 || (year % 400) == 0) &&
            (tp->tm_mon % MONTHSPERYEAR) < 2)
        result--;
    result += tp->tm_mday - 1;
    result *= 24;
    result += tp->tm_hour;
    result *= 60;
    result += tp->tm_min;
    result *= 60;
    result += tp->tm_sec;
#ifndef OS_WIN32
    if (tp->tm_gmtoff)
        result -= tp->tm_gmtoff;
#endif
    return result;
}

/**
 * \brief Parse a date string based on specified patterns.
 *
 * This function is based on GNU C library getdate.
 *
 * \param string       Date string to parse.
 * \param patterns     String array containing patterns.
 * \param num_patterns Number of patterns to check.
 * \param tp           Pointer to broken-down time.
 *
 * \retval 0 on success.
 * \retval 1 on failure.
 */
int SCStringPatternToTime (char *string, const char **patterns, int num_patterns,
                           struct tm *tp)
{
    char *result = NULL;
    int i = 0;

    /* Do the pattern matching */
    for (i = 0; i < num_patterns; i++)
    {
        if (patterns[i] == NULL)
            continue;

        tp->tm_hour = tp->tm_min = tp->tm_sec = 0;
        tp->tm_year = tp->tm_mon = tp->tm_mday = tp->tm_wday = INT_MIN;
        tp->tm_isdst = -1;
#ifndef OS_WIN32
        tp->tm_gmtoff = 0;
        tp->tm_zone = NULL;
#endif
        result = strptime(string, patterns[i], tp);

        if (result && *result == '\0')
            break;
    }

    /* Return if no patterns matched */
    if (result == NULL || *result != '\0')
        return 1;

    /* Return if no date is given */
    if (tp->tm_year == INT_MIN && tp->tm_mon == INT_MIN &&
            tp->tm_mday == INT_MIN)
        return 1;

    /* The first of the month is assumed, if only year and
       month is given */
    if (tp->tm_year != INT_MIN && tp->tm_mon != INT_MIN &&
            tp->tm_mday <= 0)
        tp->tm_mday = 1;

    return 0;
}

/**
 * \brief Convert epoch time to string pattern.
 *
 * This function converts epoch time to a string based on a pattern.
 *
 * \param epoch   Epoch time.
 * \param pattern String pattern.
 * \param str     Formated string.
 * \param size    Size of allocated string.
 *
 * \retval 0 on success.
 * \retval 1 on failure.
 */
int SCTimeToStringPattern (time_t epoch, const char *pattern, char *str, size_t size)
{
    struct tm tm;
    memset(&tm, 0, sizeof(tm));
    struct tm *tp = (struct tm *)SCLocalTime(epoch, &tm);
    char buffer[PATH_MAX] = { 0 };

    if (unlikely(tp == NULL)) {
        return 1;
    }

    size_t r = strftime(buffer, sizeof(buffer), pattern, tp);
    if (r == 0) {
        return 1;
    }

    strlcpy(str, buffer, size);

    return 0;
}

/**
 * \brief Parse string containing time size (1m, 1h, etc).
 *
 * \param str String to parse.
 *
 * \retval size on success.
 * \retval 0 on failure.
 */
uint64_t SCParseTimeSizeString (const char *str)
{
    uint64_t size = 0;
    uint64_t modifier = 1;
    char last = str[strlen(str)-1];

    switch (last)
    {
        case '0' ... '9':
            break;
        /* seconds */
        case 's':
            break;
        /* minutes */
        case 'm':
            modifier = 60;
            break;
        /* hours */
        case 'h':
            modifier = 60 * 60;
            break;
        /* days */
        case 'd':
            modifier = 60 * 60 * 24;
            break;
        /* weeks */
        case 'w':
            modifier = 60 * 60 * 24 * 7;
            break;
        /* invalid */
        default:
            return 0;
    }

    errno = 0;
    size = strtoumax(str, NULL, 10);
    if (errno) {
        return 0;
    }

    return (size * modifier);
}

/**
 * \brief Get seconds until a time unit changes.
 *
 * \param str   String containing time type (minute, hour, etc).
 * \param epoch Epoch time.
 *
 * \retval seconds.
 */
uint64_t SCGetSecondsUntil (const char *str, time_t epoch)
{
    uint64_t seconds = 0;
    struct tm tm;
    memset(&tm, 0, sizeof(tm));
    struct tm *tp = (struct tm *)SCLocalTime(epoch, &tm);

    if (strcmp(str, "minute") == 0)
        seconds = 60 - tp->tm_sec;
    else if (strcmp(str, "hour") == 0)
        seconds = (60 * (60 - tp->tm_min)) + (60 - tp->tm_sec);
    else if (strcmp(str, "day") == 0)
        seconds = (3600 * (24 - tp->tm_hour)) + (60 * (60 - tp->tm_min)) +
                  (60 - tp->tm_sec);

    return seconds;
}

uint64_t SCTimespecAsEpochMillis(const struct timespec* ts)
{
    return ts->tv_sec * 1000L + ts->tv_nsec / 1000000L;
}

uint64_t TimeDifferenceMicros(struct timeval t0, struct timeval t1)
{
    return (uint64_t)(t1.tv_sec - t0.tv_sec) * 1000000L + (t1.tv_usec - t1.tv_usec);
}
