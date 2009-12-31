#ifndef __UTIL_TIME_H__
#define __UTIL_TIME_H__

void TimeSet(struct timeval *);
void TimeGet(struct timeval *);

void TimeSetToCurrentTime(void);
void TimeSetIncrementTime(uint32_t);

void TimeModeSetLive(void);
void TimeModeSetOffline (void);

#endif /* __UTIL_TIME_H__ */

