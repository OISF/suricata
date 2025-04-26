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

#ifndef SURICATA_UTIL_TIME_H
#define SURICATA_UTIL_TIME_H

/*
 * The SCTime_t member is broken up as
 *  seconds: 44
 *  useconds: 20
 *
 * Over 500000 years can be represented in 44 bits of seconds:
 *  2^44/(365*24*60*60)
 *  557855.560
 * 1048576 microseconds can be represented in 20 bits:
 *  2^20
 *  1048576
 */

typedef struct {
    uint64_t secs : 44;
    uint64_t usecs : 20;
} SCTime_t;

#define SCTIME_INIT(t)                                                                             \
    {                                                                                              \
        (t).secs = 0;                                                                              \
        (t).usecs = 0;                                                                             \
    }

#define SCTIME_INITIALIZER                                                                         \
    (SCTime_t)                                                                                     \
    {                                                                                              \
        .secs = 0, .usecs = 0                                                                      \
    }
#define SCTIME_USECS(t)          ((t).usecs)
#define SCTIME_SECS(t)           ((t).secs)
#define SCTIME_MSECS(t)          (SCTIME_SECS(t) * 1000 + SCTIME_USECS(t) / 1000)
#define SCTIME_ADD_USECS(ts, us)                                                                   \
    (SCTime_t)                                                                                     \
    {                                                                                              \
        .secs = (ts).secs + ((ts).usecs + (us)) / 1000000, .usecs = ((ts).usecs + (us)) % 1000000  \
    }
#define SCTIME_ADD_SECS(ts, s)                                                                     \
    (SCTime_t)                                                                                     \
    {                                                                                              \
        .secs = (ts).secs + (s), .usecs = (ts).usecs                                               \
    }
#define SCTIME_FROM_SECS(s)                                                                        \
    (SCTime_t)                                                                                     \
    {                                                                                              \
        .secs = (s), .usecs = 0                                                                    \
    }
#define SCTIME_FROM_USECS(us)                                                                      \
    (SCTime_t)                                                                                     \
    {                                                                                              \
        .secs = 0, .usecs = (us)                                                                   \
    }
#define SCTIME_FROM_TIMEVAL(tv)                                                                    \
    (SCTime_t)                                                                                     \
    {                                                                                              \
        .secs = (uint64_t)(tv)->tv_sec, .usecs = (uint32_t)(tv)->tv_usec                           \
    }
/** \brief variant to deal with potentially bad timestamps, like from pcap files */
#define SCTIME_FROM_TIMEVAL_UNTRUSTED(tv)                                                          \
    (SCTime_t)                                                                                     \
    {                                                                                              \
        .secs = ((tv)->tv_sec > 0) ? (tv)->tv_sec : 0,                                             \
        .usecs = ((tv)->tv_usec > 0) ? (tv)->tv_usec : 0                                           \
    }
#define SCTIME_FROM_TIMESPEC(ts)                                                                   \
    (SCTime_t)                                                                                     \
    {                                                                                              \
        .secs = (ts)->tv_sec, .usecs = (ts)->tv_nsec / 1000                                        \
    }

#define SCTIME_TO_TIMEVAL(tv, t)                                                                   \
    (tv)->tv_sec = SCTIME_SECS((t));                                                               \
    (tv)->tv_usec = SCTIME_USECS((t));
#define SCTIME_CMP(a, b, CMP)                                                                      \
    ((SCTIME_SECS(a) == SCTIME_SECS(b)) ? (SCTIME_USECS(a) CMP SCTIME_USECS(b))                    \
                                        : (SCTIME_SECS(a) CMP SCTIME_SECS(b)))
#define SCTIME_CMP_GTE(a, b) SCTIME_CMP((a), (b), >=)
#define SCTIME_CMP_GT(a, b)  SCTIME_CMP((a), (b), >)
#define SCTIME_CMP_LT(a, b)  SCTIME_CMP((a), (b), <)
#define SCTIME_CMP_LTE(a, b) SCTIME_CMP((a), (b), <=)
#define SCTIME_CMP_NEQ(a, b) SCTIME_CMP((a), (b), !=)
#define SCTIME_CMP_EQ(a, b)  SCTIME_CMP((a), (b), ==)

static inline SCTime_t SCTimeGetTime(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return SCTIME_FROM_TIMEVAL(&tv);
}

void TimeInit(void);
void TimeDeinit(void);

void TimeSetByThread(const int thread_id, SCTime_t tv);
SCTime_t TimeGet(void);

/** \brief initialize a 'struct timespec' from a 'struct timeval'. */
#define FROM_TIMEVAL(timev) { .tv_sec = (timev).tv_sec, .tv_nsec = (timev).tv_usec * 1000 }

#ifndef timeradd
#define timeradd(a, b, r)                                                                          \
    do {                                                                                           \
        (r)->tv_sec = (a)->tv_sec + (b)->tv_sec;                                                   \
        (r)->tv_usec = (a)->tv_usec + (b)->tv_usec;                                                \
        if ((r)->tv_usec >= 1000000) {                                                             \
            (r)->tv_sec++;                                                                         \
            (r)->tv_usec -= 1000000;                                                               \
        }                                                                                          \
    } while (0)
#endif

#ifdef UNITTESTS
void TimeSet(SCTime_t);
void TimeSetToCurrentTime(void);
void TimeSetIncrementTime(uint32_t);
#endif

bool TimeModeIsReady(void);
void TimeModeSetLive(void);
void TimeModeSetOffline (void);
bool TimeModeIsLive(void);

struct tm *SCLocalTime(time_t timep, struct tm *result);
void CreateTimeString(const SCTime_t ts, char *str, size_t size);
void CreateIsoTimeString(const SCTime_t ts, char *str, size_t size);
void CreateUtcIsoTimeString(const SCTime_t ts, char *str, size_t size);
void CreateFormattedTimeString(const struct tm *t, const char * fmt, char *str, size_t size);
time_t SCMkTimeUtc(struct tm *tp);
int SCStringPatternToTime(char *string, const char **patterns,
                           int num_patterns, struct tm *time);
int SCTimeToStringPattern (time_t epoch, const char *pattern, char *str,
                           size_t size);
uint64_t SCParseTimeSizeString (const char *str);
uint64_t SCGetSecondsUntil (const char *str, time_t epoch);
uint64_t SCTimespecAsEpochMillis(const struct timespec *ts);
uint64_t TimeDifferenceMicros(struct timeval t0, struct timeval t1);

#endif /* SURICATA_UTIL_TIME_H */
