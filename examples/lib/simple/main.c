#include "suricata.h"

int main(int argc, char **argv)
{
    SuricataPreInit(argv[0]);
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
