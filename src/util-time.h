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

void TimeSet(struct timeval *);
void TimeGet(struct timeval *);

void TimeSetToCurrentTime(void);
void TimeSetIncrementTime(uint32_t);

void TimeModeSetLive(void);
void TimeModeSetOffline (void);

#endif /* __UTIL_TIME_H__ */

