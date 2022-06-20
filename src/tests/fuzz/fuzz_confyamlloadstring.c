/**
 * @file
 * @author Philippe Antoine <contact@catenacyber.fr>
 * fuzz target for ConfYamlLoadString
 */


#include "suricata-common.h"
#include "suricata.h"
#include "conf-yaml-loader.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static int initialized = 0;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (initialized == 0) {
        //Redirects logs to /dev/null
        setenv("SC_LOG_OP_IFACE", "file", 0);
        setenv("SC_LOG_FILE", "/dev/null", 0);
        //global init
        InitGlobal();
        run_mode = RUNMODE_UNITTEST;
        initialized = 1;
    }

    ConfYamlLoadString((const char *) data, size);

    return 0;
}
