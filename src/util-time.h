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

#ifndef __UTIL_TIME_H__
#define __UTIL_TIME_H__

void TimeInit(void);
void TimeDeinit(void);

void TimeSetByThread(const int thread_id, const struct timeval *tv);
void TimeGet(struct timeval *);

/** \brief intialize a 'struct timespec' from a 'struct timeval'. */
#define FROM_TIMEVAL(timev) { .tv_sec = (timev).tv_sec, .tv_nsec = (timev).tv_usec * 1000 }

/** \brief compare two 'struct timeval' and return the difference in seconds */
#define TIMEVAL_DIFF_SEC(tv_new, tv_old) \
    (uint64_t)((((uint64_t)(tv_new).tv_sec * 1000000 + (tv_new).tv_usec) - \
                ((uint64_t)(tv_old).tv_sec * 1000000 + (tv_old).tv_usec)) / \
               1000000)

/** \brief compare two 'struct timeval' and return if the first is earlier than the second */
#define TIMEVAL_EARLIER(tv_first, tv_second) \
    (((tv_first).tv_sec < (tv_second).tv_sec) || \
     ((tv_first).tv_sec == (tv_second).tv_sec && (tv_first).tv_usec < (tv_second).tv_usec))

#ifdef UNITTESTS
void TimeSet(struct timeval *);
void TimeSetToCurrentTime(void);
void TimeSetIncrementTime(uint32_t);
#endif

bool TimeModeIsReady(void);
void TimeModeSetLive(void);
void TimeModeSetOffline (void);
bool TimeModeIsLive(void);

struct tm *SCLocalTime(time_t timep, struct tm *result);
void CreateTimeString(const struct timeval *ts, char *str, size_t size);
void CreateIsoTimeString(const struct timeval *ts, char *str, size_t size);
void CreateUtcIsoTimeString(const struct timeval *ts, char *str, size_t size);
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

#endif /* __UTIL_TIME_H__ */

