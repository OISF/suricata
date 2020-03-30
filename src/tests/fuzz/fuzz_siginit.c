/**
 * @file
 * @author Philippe Antoine <contact@catenacyber.fr>
 * fuzz target for SigInit
 */


#include "suricata-common.h"
#include "util/reference-config.h"
#include "util/classification-config.h"
#include "detect/engine/detect-engine.h"
#include "detect-parse.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

DetectEngineCtx *de_ctx = NULL;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (de_ctx == NULL) {
        setenv("SC_LOG_OP_IFACE", "file", 0);
        setenv("SC_LOG_FILE", "/dev/null", 0);
        //global init
        InitGlobal();
        run_mode = RUNMODE_UNITTEST;
        MpmTableSetup();
        SpmTableSetup();
        SigTableSetup();
        SCReferenceConfInit();
        SCClassConfInit();
        de_ctx = DetectEngineCtxInit();
    }

    char * buffer = malloc(size+1);
    if (buffer) {
        memcpy(buffer, data, size);
        //null terminate string
        buffer[size] = 0;
        Signature *s = SigInit(de_ctx, buffer);
        free(buffer);
        SigFree(s);
    }

    return 0;
}
