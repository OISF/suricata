/* Time keeping for non-live packet handling (pcap files) */

#include "vips.h"
#include "detect.h"
#include "threads.h"

static struct timeval current_time = { 0,0 };
static pthread_mutex_t current_time_mutex = PTHREAD_MUTEX_INITIALIZER;
static char live = TRUE;

void TimeModeSetLive(void) {
    live = TRUE;
}

void TimeModeSetNonlive (void) {
    live = FALSE;
}

void TimeSet(struct timeval *tv) {
    if (live == TRUE)
        return;

    if (tv == NULL)
        return;

    mutex_lock(&current_time_mutex);
    current_time.tv_sec = tv->tv_sec; 
    current_time.tv_usec = tv->tv_usec;
    //printf("TimeSet: time set to %lu sec, %lu usec\n",
    //    current_time.tv_sec, current_time.tv_usec);

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

    //printf("TimeGet: time we got is %lu sec, %lu usec\n",
    //    tv->tv_sec, tv->tv_usec);
}

