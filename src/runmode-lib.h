/** \file
 *
 *  \author Angelo Mirabella <angelo.mirabella@broadcom.com>
 *
 *  Library runmode.
 */

#ifndef __RUNMODE_LIB_H__
#define __RUNMODE_LIB_H__

/** \brief register runmodes for suricata as a library */
void RunModeIdsLibRegister(void);

/** \brief runmode for live packet processing */
int RunModeIdsLibLive(void);

/** \brief runmode for offline packet processing (pcap files) */
int RunModeIdsLibOffline(void);

/** \brief runmode default mode (live) */
const char *RunModeLibGetDefaultMode(void);

/** \brief create a "fake" worker thread in charge of processing the packets.
 *
 *  This method just creates a context representing the worker, which is handled from the library
 *  client. No actual thread (pthread_t) is created.
 *
 * \return Pointer to ThreadVars structure representing the worker thread */
void *RunModeCreateWorker(void);

/** \brief start the "fake" worker.
 *
 *  This method performs all the initialization tasks.
 */
int RunModeSpawnWorker(void *);

/** \brief destroy a worker thread */
void RunModeDestroyWorker(void *);

#endif /* __RUNMODE_LIB_H__ */
