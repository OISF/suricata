/**
 * @file
 * @author Philippe Antoine <contact@catenacyber.fr>
 * fuzz target for SigInit
 */


#include "suricata-common.h"
#include "util-reference-config.h"
#include "util-classification-config.h"
#include "detect-engine.h"
#include "detect-parse.h"

void fuzz_openFile(const char * name) {
}

DetectEngineCtx *de_ctx = NULL;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (de_ctx == NULL) {
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

    uint8_t * buffer = malloc(size+1);
    if (buffer) {
        memcpy(buffer, data, size);
        //null terminate string
        buffer[size] = 0;
        Signature *s = SigInit(de_ctx, buffer);
        free(buffer);
        if (s != NULL) {
            SigFree(s);
        }
    }

    return 0;
}
