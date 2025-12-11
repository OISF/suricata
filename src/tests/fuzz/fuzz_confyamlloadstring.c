/**
 * @file
 * @author Philippe Antoine <contact@catenacyber.fr>
 * fuzz target for SCConfYamlLoadString
 */

#include "suricata-common.h"
#include "suricata.h"
#include "conf-yaml-loader.h"
#include "nallocinc.c"

SC_ATOMIC_EXTERN(unsigned int, engine_stage);

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
        SCRunmodeSet(RUNMODE_UNITTEST);
        SC_ATOMIC_SET(engine_stage, SURICATA_RUNTIME);
        nalloc_init(NULL);
        // do not restrict nalloc
        initialized = 1;
    }

    nalloc_start(data, size);
    SCConfYamlLoadString((const char *)data, size);
    nalloc_end();

    return 0;
}
