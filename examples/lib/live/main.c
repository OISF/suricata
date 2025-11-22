/* Copyright (C) 2025 Open Information Security Foundation
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
#include "detect.h"
#include "runmodes.h"
#include "conf.h"
#include "pcap.h"
#include "runmode-lib.h"
#include "tm-threads.h"
#include "threadvars.h"
#include "action-globals.h"
#include "packet.h"
#include "util-device.h"

#include <getopt.h>
#include <unistd.h>

static int worker_id = 1;

/**
 * Struct to pass arguments into a worker thread.
 */
struct WorkerArgs {
    ThreadVars *tv;
    char *interface;
    char *device_name;
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
    int exit_code = EXIT_SUCCESS;

    /* Start worker. */
    if (SCRunModeLibSpawnWorker(tv) != 0) {
        pthread_exit((void *)(intptr_t)EXIT_FAILURE);
    }

    /* Open live capture on interface. */
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *fp = pcap_open_live(args->interface, 65535, 1, 1000, errbuf);
    if (fp == NULL) {
        SCLogError("Failed to open interface: %s", errbuf);
        exit_code = EXIT_FAILURE;
        goto done;
    }

    LiveDevice *device = LiveGetDevice(args->device_name);
    assert(device != NULL);

    int datalink = pcap_datalink(fp);
    struct pcap_pkthdr *pkthdr;
    const u_char *packet;
    int pcap_rc;

    while (1) {
        /* Have we been asked to stop? */
        if (suricata_ctl_flags & SURICATA_STOP) {
            goto done;
        }

        pcap_rc = pcap_next_ex(fp, &pkthdr, &packet);
        if (pcap_rc == 0) {
            /* Timeout - no packet available, continue waiting */
            continue;
        } else if (pcap_rc == -1) {
            /* Error occurred */
            SCLogError("pcap_next_ex failed on %s: %s", args->interface, pcap_geterr(fp));
            exit_code = EXIT_FAILURE;
            goto done;
        } else if (pcap_rc == -2) {
            /* End of file (shouldn't happen in live capture) */
            SCLogNotice("End of capture on %s", args->interface);
            exit_code = EXIT_FAILURE;
            goto done;
        }

        Packet *p = PacketGetFromQueueOrAlloc();
        if (unlikely(p == NULL)) {
            /* Memory allocation error: backoff and continue instead of stopping */
            usleep(1000); /* brief sleep to avoid tight spin */
            continue;
        }

        /* Setup the packet, these will become functions to avoid
         * internal Packet access. */
        SCPacketSetSource(p, PKT_SRC_WIRE);
        SCPacketSetTime(p, SCTIME_FROM_TIMEVAL(&pkthdr->ts));
        SCPacketSetDatalink(p, datalink);
        SCPacketSetLiveDevice(p, device);
        SCPacketSetReleasePacket(p, ReleasePacket);

        if (PacketSetData(p, packet, pkthdr->len) == -1) {
            TmqhOutputPacketpool(tv, p);
            /* Bad packet or setup error; log and continue */
            SCLogDebug("PacketSetData failed on %s", args->interface);
            continue;
        }

        if (TmThreadsSlotProcessPkt(tv, tv->tm_slots, p) != TM_ECODE_OK) {
            TmqhOutputPacketpool(tv, p);
            /* Processing failure for this packet; continue capture */
            SCLogDebug("TmThreadsSlotProcessPkt failed on %s", args->interface);
            continue;
        }

        LiveDevicePktsIncr(device);
    }

done:
    if (fp != NULL) {
        pcap_close(fp);
    }

    /* Signal main loop to shutdown. */
    EngineStop();

    /* Cleanup.
     *
     * Note that there is some thread synchronization between this
     * function and SuricataShutdown such that they must be run
     * concurrently at this time before either will exit. */
    SCTmThreadsSlotPacketLoopFinish(tv);

    SCLogNotice("Worker thread exiting");
    pthread_exit((void *)(intptr_t)exit_code);
}

static uint8_t RateFilterCallback(const Packet *p, const uint32_t sid, const uint32_t gid,
        const uint32_t rev, uint8_t original_action, uint8_t new_action, void *arg)
{
    /* Don't change the action. */
    return new_action;
}

int main(int argc, char **argv)
{
    int opt;
/* Support up to 16 interfaces */
#define MAX_INTERFACES 16
    char *interfaces[MAX_INTERFACES];
    int interface_count = 0;

    /* Parse command line options using getopt */
    while ((opt = getopt(argc, argv, "i:")) != -1) {
        switch (opt) {
            case 'i':
                if (interface_count >= MAX_INTERFACES) {
                    fprintf(stderr, "ERROR: Maximum %d interfaces supported\n", MAX_INTERFACES);
                    exit(EXIT_FAILURE);
                }
                interfaces[interface_count++] = optarg;
                break;
            default:
                fprintf(stderr, "Usage: %s -i interface [-i interface2 ...] [suricata_options]\n",
                        argv[0]);
                fprintf(stderr, "  -i interface    Network interface to capture from (can be "
                                "specified multiple times)\n");
                exit(EXIT_FAILURE);
        }
    }

    if (interface_count == 0) {
        fprintf(stderr, "ERROR: At least one interface (-i) is required\n");
        fprintf(stderr, "Usage: %s -i interface [-i interface2 ...] [suricata_options]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    SuricataPreInit(argv[0]);

    /* Pass through the arguments after -- to Suricata. */
    char *suricata_argv[argc - optind + 2];
    int suricata_argc = 0;
    suricata_argv[suricata_argc++] = argv[0];
    while (optind < argc) {
        suricata_argv[suricata_argc++] = argv[optind++];
    }
    suricata_argv[suricata_argc] = NULL;
    optind = 1;

    /* Log the command line arguments being passed to Suricata */
    if (suricata_argc > 1) {
        fprintf(stderr, "Passing command line arguments to Suricata:");
        for (int i = 1; i < suricata_argc; i++) {
            fprintf(stderr, " %s", suricata_argv[i]);
        }
        fprintf(stderr, "\n");
    }

    SCParseCommandLine(suricata_argc, suricata_argv);

    /* Set the runmode to library mode. Perhaps in the future this
     * should be done in some library bootstrap function. */
    SCRunmodeSet(RUNMODE_LIB);

    /* Validate/finalize the runmode. */
    if (SCFinalizeRunMode() != TM_ECODE_OK) {
        exit(EXIT_FAILURE);
    }

    /* Load configuration file, could be done earlier but must be done
     * before SuricataInit, but even then its still optional as you
     * may be programmatically configuration Suricata. */
    if (SCLoadYamlConfig() != TM_ECODE_OK) {
        exit(EXIT_FAILURE);
    }

    /* Enable default signal handlers including SIGHUP for log file rotation,
     * and SIGUSR2 for reloading rules. This should be done with care by a
     * library user as the application may already have signal handlers
     * loaded. */
    SCEnableDefaultSignalHandlers();

    if (!SCConfSetFromString("runmode=live", 1)) {
        exit(EXIT_FAILURE);
    }

    /* Force logging to the current directory. */
    SCConfSetFromString("default-log-dir=.", 1);

    /* Register a LiveDevice for each interface */
    for (int i = 0; i < interface_count; i++) {
        if (LiveRegisterDevice(interfaces[i]) < 0) {
            FatalError("LiveRegisterDevice failed for %s", interfaces[i]);
        }
        SCLogNotice("Registered device %s", interfaces[i]);
    }

    SuricataInit();

    SCDetectEngineRegisterRateFilterCallback(RateFilterCallback, NULL);

    /* Create and start worker threads, one for each interface.
     * This needs to be done in between SuricataInit and SuricataPostInit. */
    pthread_t workers[MAX_INTERFACES];
    struct WorkerArgs worker_args[MAX_INTERFACES];

    for (int i = 0; i < interface_count; i++) {
        ThreadVars *tv = SCRunModeLibCreateThreadVars(worker_id++);
        if (!tv) {
            FatalError("Failed to create ThreadVars for interface %s", interfaces[i]);
        }

        worker_args[i].tv = tv;
        worker_args[i].interface = interfaces[i];
        worker_args[i].device_name = interfaces[i];

        if (pthread_create(&workers[i], NULL, SimpleWorker, &worker_args[i]) != 0) {
            FatalError("Failed to create worker thread for interface %s", interfaces[i]);
        }

        SCLogNotice("Started worker thread for interface %s", interfaces[i]);
    }

    SuricataPostInit();

    /* Run the main loop, this just waits for the worker threads to
     * call EngineStop signalling Suricata that it is done capturing
     * from the interfaces. */
    SuricataMainLoop();

    /* Shutdown engine. */
    SCLogNotice("Shutting down");

    /* Note that there is some thread synchronization between this
     * function and SCTmThreadsSlotPacketLoopFinish that require them
     * to be run concurrently at this time. */
    SuricataShutdown();

    /* Ensure our capture workers have fully exited before teardown. */
    int exit_status = EXIT_SUCCESS;
    for (int i = 0; i < interface_count; i++) {
        void *worker_status;
        pthread_join(workers[i], &worker_status);
        if ((intptr_t)worker_status != EXIT_SUCCESS) {
            exit_status = EXIT_FAILURE;
        }
    }

    GlobalsDestroy();

    return exit_status;
}
