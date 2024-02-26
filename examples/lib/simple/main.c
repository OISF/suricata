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

    SuricataInit(argc, argv);
    SuricataPostInit();

    /* Suricata is now running, but we enter a loop to keep it running
     * until it shouldn't be running anymore. */
    SuricataMainLoop();

    /* Shutdown engine. */
    SuricataShutdown();
    GlobalsDestroy();

    return EXIT_SUCCESS;
}
