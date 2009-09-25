/* Time keeping for offline (non-live) packet handling (pcap files) */

#include "eidps-common.h"
#include "detect.h"
#include "threads.h"
#include "util-debug.h"

static struct timeval current_time = { 0,0 };
static pthread_mutex_t current_time_mutex = PTHREAD_MUTEX_INITIALIZER;
static char live = TRUE;

void TimeModeSetLive(void) {
    live = TRUE;
    SCDebug("live time mode enabled");
}

void TimeModeSetOffline (void) {
    live = FALSE;
    SCDebug("offline time mode enabled");
}

void TimeSet(struct timeval *tv) {
    if (live == TRUE)
        return;

    if (tv == NULL)
        return;

    mutex_lock(&current_time_mutex);
    current_time.tv_sec = tv->tv_sec;
    current_time.tv_usec = tv->tv_usec;

    SCDebug("time set to %" PRIuMAX " sec, %" PRIuMAX " usec",
        (uintmax_t)current_time.tv_sec, (uintmax_t)current_time.tv_usec);

    mutex_unlock(&current_time_mutex);
}

void TimeGet(struct timeval *tv) {
    if (tv == NULL)
        return;

    if (live == TRUE) {
        gettimeofday(tv, NULL);
    } else {
        mutex_lock(&current_time_mutex);
        tv->tv_sec = current_time.tv_sec;
        tv->tv_usec = current_time.tv_usec;
        mutex_unlock(&current_time_mutex);
    }

    SCDebug("time we got is %" PRIuMAX " sec, %" PRIuMAX " usec",
        (uintmax_t)tv->tv_sec, (uintmax_t)tv->tv_usec);
}

