/* Time keeping for offline (non-live) packet handling (pcap files) */

#include "suricata-common.h"
#include "detect.h"
#include "threads.h"
#include "util-debug.h"

static struct timeval current_time = { 0, 0 };
static SCMutex current_time_mutex = PTHREAD_MUTEX_INITIALIZER;
static char live = TRUE;

void TimeModeSetLive(void)
{
    live = TRUE;
    SCLogDebug("live time mode enabled");
}

void TimeModeSetOffline (void)
{
    live = FALSE;
    SCLogDebug("offline time mode enabled");
}

void TimeSet(struct timeval *tv)
{
    if (live == TRUE)
        return;

    if (tv == NULL)
        return;

    SCMutexLock(&current_time_mutex);
    current_time.tv_sec = tv->tv_sec;
    current_time.tv_usec = tv->tv_usec;

    SCLogDebug("time set to %" PRIuMAX " sec, %" PRIuMAX " usec",
               (uintmax_t)current_time.tv_sec, (uintmax_t)current_time.tv_usec);

    SCMutexUnlock(&current_time_mutex);
}

/** \brief set the time to "gettimeofday" meant for testing */
void TimeSetToCurrentTime(void) {
    struct timeval tv;
    memset(&tv, 0x00, sizeof(tv));

    gettimeofday(&tv, NULL);

    TimeSet(&tv);
}

void TimeGet(struct timeval *tv)
{
    if (tv == NULL)
        return;

    if (live == TRUE) {
        gettimeofday(tv, NULL);
    } else {
        SCMutexLock(&current_time_mutex);
        tv->tv_sec = current_time.tv_sec;
        tv->tv_usec = current_time.tv_usec;
        SCMutexUnlock(&current_time_mutex);
    }

    SCLogDebug("time we got is %" PRIuMAX " sec, %" PRIuMAX " usec",
               (uintmax_t)tv->tv_sec, (uintmax_t)tv->tv_usec);
}

/** \brief increment the time in the engine
 *  \param tv_sec seconds to increment the time with */
void TimeSetIncrementTime(uint32_t tv_sec) {
    struct timeval tv;
    memset(&tv, 0x00, sizeof(tv));
    TimeGet(&tv);

    tv.tv_sec += tv_sec;

    TimeSet(&tv);
}

/**
 * \brief create a seed number to pass to rand() , rand_r(), and similars
 */
unsigned int TimeRandPreseed(void) {
    /* preseed rand() */
    time_t now = time ( 0 );
    unsigned char *p = (unsigned char *)&now;
    unsigned seed = 0;
    size_t ind;

    for ( ind = 0; ind < sizeof now; ind++ )
      seed = seed * ( UCHAR_MAX + 2U ) + p[ind];

    return seed;
}

