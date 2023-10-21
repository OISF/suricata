#include "suricata-common.h"
#include "util-running-modes.h"
#include "util-conf.h"
#include "runmodes.h"
#include "util-unittest.h"

void test_missing_run_mode(void) {
    // Simulate missing run mode and check error message
    SCInstance suri;
    char *argv[] = {"suricata", NULL};
    
    int result = FinalizeRunMode(&suri, argv);
    
    FAIL_IF(result != TM_ECODE_FAILED);
    // Add checks to verify the error message, if possible
    PASS;
}

UtRegisterTest("RunModeTest", test_missing_run_mode);
