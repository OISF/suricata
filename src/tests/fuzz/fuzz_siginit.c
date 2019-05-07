/**
 * @file
 * @author Philippe Antoine <contact@catenacyber.fr>
 * fuzz harness for AppLayerProtoDetectGetProto
 */


#include "suricata-common.h"
#include "util-reference-config.h"
#include "util-classification-config.h"
#include "detect-engine.h"
#include "detect-parse.h"

void fuzz_openFile(const char * name) {
}

DetectEngineCtx *de_ctx = NULL;

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
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

    uint8_t * buffer = malloc(Size+1);
    if (buffer) {
        memcpy(buffer, Data, Size);
        //null terminate string
        buffer[Size] = 0;
        Signature *s = SigInit(de_ctx, buffer);
        if (s != NULL) {
            SigFree(s);
        }
    }

    return 0;
}
