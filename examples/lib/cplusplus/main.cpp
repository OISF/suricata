#include "suricata-common.h"
#include "suricata.h"
#include "conf.h"
#include "util-device.h"

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
    if (!SCConfSetFromString("runmode=offline", 1)) {
        exit(EXIT_FAILURE);
    }

    /* Force logging to the current directory. */
    SCConfSetFromString("default-log-dir=.", 1);

    if (LiveRegisterDevice("lib0") < 0) {
        fprintf(stderr, "LiveRegisterDevice failed");
        exit(1);
    }

    SuricataInit();

    return 0;
}
