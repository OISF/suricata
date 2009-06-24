#ifndef __UTIL_TIME_H__
#define __UTIL_TIME_H__

void TimeSet(struct timeval *);
void TimeGet(struct timeval *);
void TimeModeSetLive(void);
void TimeModeSetNonlive (void);

#endif /* __UTIL_TIME_H__ */

