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
#include "conf.h"
#include "pcap.h"
#include "runmode-lib.h"
#include "source-lib.h"
#include "threadvars.h"

/* Suricata worker thread in library mode.
   The functions should be wrapped in an API layer. */
void *suricataSimpleWorker(void *arg)
{
    char *pcap_file = (char *)arg;

    /* Create worker. */
    ThreadVars *tv = RunModeCreateWorker();
    if (!tv) {
        pthread_exit(NULL);
    }

    /* Start worker. */
    if (RunModeSpawnWorker(tv) != 0) {
        pthread_exit(NULL);
    }

    /* Replay pcap. */
    pcap_t *fp = pcap_open_offline(pcap_file, NULL);
    if (fp == NULL) {
        pthread_exit(NULL);
    }

    int datalink = pcap_datalink(fp);
    struct pcap_pkthdr pkthdr;
    const u_char *packet;
    while ((packet = pcap_next(fp, &pkthdr)) != NULL) {
        if (TmModuleLibHandlePacket(tv, packet, datalink, pkthdr.ts, pkthdr.len, 0, 0, NULL) != 0) {
            pthread_exit(NULL);
        }
    }
    pcap_close(fp);

    /* Cleanup. */
    RunModeDestroyWorker(tv);
    pthread_exit(NULL);
}

int main(int argc, char **argv)
{
    SuricataPreInit(argv[0]);

    /* Parse command line options. This is optional, you could
     * directly configure Suricata through the Conf API.
       The last argument is the PCAP file to replay. */
    SCParseCommandLine(argc - 1, argv);

    /* Set lib runmode. There is currently no way to set it via
       the Conf API. */
    SuricataSetLibRunmode();

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

    SuricataInit();

    /* Create and start worker on its own thread, passing the PCAP file
       as argument. This needs to be done in between SuricataInit and
       SuricataPostInit. */
    pthread_t worker;
    if (pthread_create(&worker, NULL, suricataSimpleWorker, argv[argc - 1]) != 0) {
        exit(EXIT_FAILURE);
    }

    /* Need to introduce a little sleep to allow the worker thread to
       initialize before SuricataPostInit invokes TmThreadContinueThreads().
       This should be handle at the API level. */
    usleep(100);

    SuricataPostInit();

    /* Shutdown engine. */
    SuricataShutdown();
    GlobalsDestroy();

    return EXIT_SUCCESS;
}
