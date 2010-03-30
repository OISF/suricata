#ifndef __UTIL_TIME_H__
#define __UTIL_TIME_H__

/**
 * A timeval with 32 bit fields.
 *
 * Used by the unified on disk file format.
 */
struct sc_timeval32 {
    uint32_t tv_sec;
    uint32_t tv_usec;
};

void TimeSet(struct timeval *);
void TimeGet(struct timeval *);

void TimeSetToCurrentTime(void);
void TimeSetIncrementTime(uint32_t);

void TimeModeSetLive(void);
void TimeModeSetOffline (void);

#endif /* __UTIL_TIME_H__ */

