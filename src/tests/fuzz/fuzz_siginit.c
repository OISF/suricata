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

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static uint32_t cnt = 0;
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
    }
    if (cnt++ == 1024) {
        DetectEngineCtxFree(de_ctx);
        de_ctx = NULL;
        cnt = 0;
    }
    if (de_ctx == NULL) {
        de_ctx = DetectEngineCtxInit();
        BUG_ON(de_ctx == NULL);
        de_ctx->flags |= DE_QUIET;
        de_ctx->rule_file = (char *)"fuzzer";
    }

    char * buffer = malloc(size+1);
    if (buffer) {
        memcpy(buffer, data, size);
        //null terminate string
        buffer[size] = 0;
        Signature *s = SigInit(de_ctx, buffer);
        free(buffer);
        if (s && s->next) {
            SigFree(de_ctx, s->next);
            s->next = NULL;
        }
        SigFree(de_ctx, s);
    }

    return 0;
}
