#include "suricata.h"

int main(int argc, char **argv)
{
    SuricataPreInit(argv[0]);

#ifdef OS_WIN32
    /* If on Windows, and you wanted initialize as a service, you
     * might register that here. Its at this point in the
     * initialization that the Suricata application initializes as a
     * Windows service. */
    if (WindowsInitService(argc, argv) != 0) {
        exit(EXIT_FAILURE);
    }
#endif /* OS_WIN32 */

    /* Parse command line options. This is optional, you could
     * directly configuration Suricata through the Conf API. */
    SCParseCommandLine(argc, argv);

    /* Validate/finalize the runmode. */
    if (SCFinalizeRunMode() != TM_ECODE_OK) {
        exit(EXIT_FAILURE);
    }

    /* Handle internal runmodes. Typically you wouldn't do this as a
     * library however, however this example is showing how to
     * replicate the Suricata application with the library. */
    switch (SCStartInternalRunMode(argc, argv)) {
        case TM_ECODE_DONE:
            exit(EXIT_SUCCESS);
        case TM_ECODE_FAILED:
            exit(EXIT_FAILURE);
    }

    SuricataInit();
    SuricataPostInit();

    /* Suricata is now running, but we enter a loop to keep it running
     * until it shouldn't be running anymore. */
    SuricataMainLoop();

    /* Shutdown engine. */
    SuricataShutdown();
    GlobalsDestroy();

    return EXIT_SUCCESS;
}
