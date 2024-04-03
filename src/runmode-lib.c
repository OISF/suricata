/** \file
 *
 *  \author Angelo Mirabella <angelo.mirabella@broadcom.com>
 *
 *  Library runmode.
 */
#include "suricata-common.h"
#include "runmode-lib.h"
#include "runmodes.h"
#include "tm-threads.h"
#include "util-device.h"

static int g_thread_id = 0;

/** \brief register runmodes for suricata as a library */
void RunModeIdsLibRegister(void)
{
    RunModeRegisterNewRunMode(RUNMODE_LIB, "offline", "Library offline mode (pcap replaying)",
            RunModeIdsLibOffline, NULL);
    RunModeRegisterNewRunMode(RUNMODE_LIB, "live", "Library live mode", RunModeIdsLibLive, NULL);
    return;
}

/** \brief runmode for offline packet processing (pcap files) */
int RunModeIdsLibOffline(void)
{
    TimeModeSetOffline();

    return 0;
}

/** \brief runmode for live packet processing */
int RunModeIdsLibLive(void)
{
    TimeModeSetLive();

    return 0;
}

const char *RunModeLibGetDefaultMode(void)
{
    return "live";
}

/** \brief create a "fake" worker thread in charge of processing the packets.
 *
 *  This method just creates a context representing the worker, which is handled from the library
 *  client. No actual thread (pthread_t) is created.
 *
 * \return Pointer to ThreadVars structure representing the worker thread */
void *RunModeCreateWorker(void)
{
    char tname[TM_THREAD_NAME_MAX];
    TmModule *tm_module = NULL;
    snprintf(tname, sizeof(tname), "%s#%02d", thread_name_workers, ++g_thread_id);

    ThreadVars *tv = TmThreadCreatePacketHandler(
            tname, "packetpool", "packetpool", "packetpool", "packetpool", "lib");
    if (tv == NULL) {
        SCLogError("TmThreadsCreate failed");
        return NULL;
    }

    tm_module = TmModuleGetByName("DecodeLib");
    if (tm_module == NULL) {
        SCLogError("TmModuleGetByName DecodeLib failed");
        return NULL;
    }
    TmSlotSetFuncAppend(tv, tm_module, NULL);

    tm_module = TmModuleGetByName("FlowWorker");
    if (tm_module == NULL) {
        SCLogError("TmModuleGetByName for FlowWorker failed");
        return NULL;
    }
    TmSlotSetFuncAppend(tv, tm_module, NULL);

    TmThreadAppend(tv, tv->type);

    return tv;
}

/** \brief start the "fake" worker.
 *
 *  This method performs all the initialization tasks.
 */
int RunModeSpawnWorker(void *td)
{
    ThreadVars *tv = (ThreadVars *)td;

    if (TmThreadLibSpawn(tv) != TM_ECODE_OK) {
        SCLogError("TmThreadLibSpawn failed");
        return -1;
    }

    TmThreadsSetFlag(tv, THV_RUNNING);
    return 0;
}

/** \brief destroy a worker thread */
void RunModeDestroyWorker(void *td)
{
    ThreadVars *tv = (ThreadVars *)td;
    TmSlot *s = tv->tm_slots;
    TmEcode r;
    TmSlot *slot = NULL;

    StatsSyncCounters(tv);

    TmThreadsSetFlag(tv, THV_FLOW_LOOP);

    /* process all pseudo packets the flow timeout may throw at us */
    TmThreadTimeoutLoop(tv, s);

    TmThreadsSetFlag(tv, THV_RUNNING_DONE);
    TmThreadWaitForFlag(tv, THV_DEINIT);

    PacketPoolDestroy();

    for (slot = s; slot != NULL; slot = slot->slot_next) {
        if (slot->SlotThreadExitPrintStats != NULL) {
            slot->SlotThreadExitPrintStats(tv, SC_ATOMIC_GET(slot->slot_data));
        }

        if (slot->SlotThreadDeinit != NULL) {
            r = slot->SlotThreadDeinit(tv, SC_ATOMIC_GET(slot->slot_data));
            if (r != TM_ECODE_OK) {
                break;
            }
        }
    }

    tv->stream_pq = NULL;
    --g_thread_id;
    SCLogDebug("%s ending", tv->name);
    TmThreadsSetFlag(tv, THV_CLOSED);
}
