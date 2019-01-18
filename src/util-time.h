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

/**
 * A timeval with 32 bit fields.
 *
 * Used by the unified on disk file format.
 */
typedef struct SCTimeval32_ {
    uint32_t tv_sec;
    uint32_t tv_usec;
} SCTimeval32;

void TimeInit(void);
void TimeDeinit(void);

void TimeSetByThread(const int thread_id, const struct timeval *tv);
void TimeGet(struct timeval *);

/** \brief intialize a 'struct timespec' from a 'struct timeval'. */
#define FROM_TIMEVAL(timev) { .tv_sec = (timev).tv_sec, .tv_nsec = (timev).tv_usec * 1000 }

#ifdef UNITTESTS
void TimeSet(struct timeval *);
void TimeSetToCurrentTime(void);
void TimeSetIncrementTime(uint32_t);
#endif

void TimeModeSetLive(void);
void TimeModeSetOffline (void);
int TimeModeIsLive(void);

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

#endif /* __UTIL_TIME_H__ */

