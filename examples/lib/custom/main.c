/* Copyright (C) 2024 Open Information Security Foundation
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

#include "suricata.h"
#include "runmodes.h"
#include "conf.h"
#include "pcap.h"
#include "runmode-lib.h"
#include "source-lib.h"
#include "threadvars.h"
#include "action-globals.h"
#include "packet.h"

static int worker_id = 1;

/**
 * Struct to pass arguments into a worker thread.
 */
struct WorkerArgs {
    ThreadVars *tv;
    char *pcap_filename;
};

/**
 * Release packet callback.
 *
 * If there is any cleanup that needs to be done when Suricata is done
 * with a packet, this is the place to do it.
 *
 * Important: If using a custom release function, you must also
 * release or free the packet.
 *
 * Optionally this is where you would handle IPS like functionality
 * such as forwarding the packet, or triggering some other mechanism
 * to forward the packet.
 */
static void ReleasePacket(Packet *p)
{
    if (PacketCheckAction(p, ACTION_DROP)) {
        SCLogNotice("Dropping packet!");
    }

    /* As we overode the default release function, we must release or
     * free the packet. */
    PacketFreeOrRelease(p);
}

/**
 * Suricata worker thread in library mode.
 * The functions should be wrapped in an API layer.
 */
static void *SimpleWorker(void *arg)
{
    struct WorkerArgs *args = arg;
    ThreadVars *tv = args->tv;

    /* Start worker. */
    if (SCRunModeLibSpawnWorker(tv) != 0) {
        pthread_exit(NULL);
    }

    /* Replay pcap. */
    pcap_t *fp = pcap_open_offline(args->pcap_filename, NULL);
    if (fp == NULL) {
        pthread_exit(NULL);
    }

    LiveDevice *device = LiveGetDevice("lib0");
    assert(device != NULL);

    int datalink = pcap_datalink(fp);
    int count = 0;
    struct pcap_pkthdr pkthdr;
    const u_char *packet;
    while ((packet = pcap_next(fp, &pkthdr)) != NULL) {

        /* Have we been asked to stop? */
        if (suricata_ctl_flags & SURICATA_STOP) {
            goto done;
        }

        Packet *p = PacketGetFromQueueOrAlloc();
        if (unlikely(p == NULL)) {
            /* Memory allocation error. */
            goto done;
        }

        /* If we are processing a PCAP and it is the first packet we need to set the timestamp. */
        SCTime_t timestamp = SCTIME_FROM_TIMEVAL(&pkthdr.ts);
        if (count == 0) {
            TmThreadsInitThreadsTimestamp(timestamp);
        }

        /* Setup the packet, these will become functions to avoid
         * internal Packet access. */
        PKT_SET_SRC(p, PKT_SRC_WIRE);
        p->ts = SCTIME_FROM_TIMEVAL(&pkthdr.ts);
        p->datalink = datalink;
        p->livedev = device;
        p->ReleasePacket = ReleasePacket;

        if (PacketSetData(p, packet, pkthdr.len) == -1) {
            TmqhOutputPacketpool(tv, p);
            goto done;
        }

        if (TmThreadsSlotProcessPkt(tv, tv->tm_slots, p) != TM_ECODE_OK) {
            TmqhOutputPacketpool(tv, p);
            goto done;
        }

        (void)SC_ATOMIC_ADD(device->pkts, 1);
        count++;
    }

done:
    pcap_close(fp);

    /* Stop the engine. */
    EngineStop();

    /* Cleanup.
     *
     * Note that there is some thread synchronization between this
     * function and SuricataShutdown such that they must be run
     * concurrently at this time before either will exit. */
    SCTmThreadsSlotPktAcqLoopFinish(tv);

    SCLogNotice("Worker thread exiting");
    pthread_exit(NULL);
}

int main(int argc, char **argv)
{
    SuricataPreInit(argv[0]);

    /* Parse command line options. This is optional, you could
     * directly configure Suricata through the Conf API. */
    SCParseCommandLine(argc, argv);

    /* Find our list of pcap files, after the "--". */
    while (argc) {
        bool end = strncmp(argv[0], "--", 2) == 0;
        argv++;
        argc--;
        if (end) {
            break;
        }
    }
    if (argc == 0) {
        fprintf(stderr, "ERROR: No PCAP files provided\n");
        return 1;
    }

    /* Set the runmode to library mode. Perhaps in the future this
     * should be done in some library bootstrap function. */
    SCRunmodeSet(RUNMODE_LIB);

    /* Validate/finalize the runmode. */
    if (SCFinalizeRunMode() != TM_ECODE_OK) {
        exit(EXIT_FAILURE);
    }

    /* Handle internal runmodes. Typically you wouldn't do this as a
     * library user, however this example is showing how to replicate
     * the Suricata application with the library. */
    switch (SCStartInternalRunMode(argc, argv)) {
        case TM_ECODE_DONE:
            exit(EXIT_SUCCESS);
        case TM_ECODE_FAILED:
            exit(EXIT_FAILURE);
    }

    /* Load configuration file, could be done earlier but must be done
     * before SuricataInit, but even then its still optional as you
     * may be programmatically configuration Suricata. */
    if (SCLoadYamlConfig() != TM_ECODE_OK) {
        exit(EXIT_FAILURE);
    }

    /* Set "offline" runmode to replay a pcap in library mode. */
    if (!ConfSetFromString("runmode=offline", 1)) {
        exit(EXIT_FAILURE);
    }

    /* Force logging to the current directory. */
    ConfSetFromString("default-log-dir=.", 1);

    if (LiveRegisterDevice("lib0") < 0) {
        fprintf(stderr, "LiveRegisterDevice failed");
        exit(1);
    }

    SuricataInit();

    /* Create and start worker on its own thread, passing the PCAP
     * file as argument. This needs to be done in between SuricataInit
     * and SuricataPostInit. */
    pthread_t worker;
    ThreadVars *tv = SCRunModeLibCreateThreadVars(worker_id++);
    if (!tv) {
        FatalError("Failed to create ThreadVars");
    }
    struct WorkerArgs args = {
        .tv = tv,
        .pcap_filename = argv[argc - 1],
    };
    if (pthread_create(&worker, NULL, SimpleWorker, &args) != 0) {
        exit(EXIT_FAILURE);
    }

    SuricataPostInit();

    /* Run the main loop, this just waits for the worker thread to
     * call EngineStop signalling Suricata that it is done reading the
     * pcap. */
    SuricataMainLoop();

    /* Shutdown engine. */
    SCLogNotice("Shutting down");

    /* Note that there is some thread synchronization between this
     * function and SCTmThreadsSlotPktAcqLoopFinish that require them
     * to be run concurrently at this time. */
    SuricataShutdown();
    GlobalsDestroy();

    return EXIT_SUCCESS;
}
