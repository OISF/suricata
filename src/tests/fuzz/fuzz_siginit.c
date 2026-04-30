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
#include "app-layer.h"
#include "nallocinc.c"
#include "detect-engine-analyzer.h"
#include "detect-engine-build.h"
#include "util-conf.h"
#include "conf-yaml-loader.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

DetectEngineCtx *de_ctx = NULL;
static int initialized = 0;
SC_ATOMIC_EXTERN(unsigned int, engine_stage);
bool fp_engine_analysis_set;
extern bool rule_engine_analysis_set;
extern const char *configNoChecksum;
SCInstance surifuzz;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (initialized == 0) {
        // Redirects logs to /dev/null
        setenv("SC_LOG_OP_IFACE", "file", 0);
        setenv("SC_LOG_FILE", "/dev/null", 0);

        InitGlobal();
        rule_engine_analysis_set = true;
        GlobalsInitPreConfig();
        SCRunmodeSet(RUNMODE_ENGINE_ANALYSIS);
        ConfigSetLogDirectory("/tmp/");
        // disables checksums validation for fuzzing
        if (SCConfYamlLoadString(configNoChecksum, strlen(configNoChecksum)) != 0) {
            abort();
        }
        SCConfSetFinal("engine-analysis.rules", "true");
        surifuzz.sig_file_exclusive = 1;
        // loads rules after init
        surifuzz.delayed_detect = 1;
        PostConfLoadedSetup(&surifuzz);
        PostConfLoadedDetectSetup(&surifuzz);

        nalloc_init(NULL);
        nalloc_restrict_file_prefix(3);
        SC_ATOMIC_SET(engine_stage, SURICATA_RUNTIME);
        initialized = 1;
    }
    if (de_ctx == NULL) {
        de_ctx = DetectEngineCtxInit();
        BUG_ON(de_ctx == NULL);
        de_ctx->rule_file = (char *)"fuzzer";
        SetupEngineAnalysis(de_ctx, &fp_engine_analysis_set, &rule_engine_analysis_set);
    }

    char * buffer = malloc(size+1);
    if (buffer) {
        memcpy(buffer, data, size);
        //null terminate string
        buffer[size] = 0;
        nalloc_start(data, size);
        Signature *sig = DetectEngineAppendSig(de_ctx, buffer);
        if (sig) {
            SigGroupBuild(de_ctx);
        }
        CleanupEngineAnalysis(de_ctx);
        DetectEngineCtxFree(de_ctx);
        nalloc_end();
        de_ctx = NULL;
        free(buffer);
    }

    return 0;
}
