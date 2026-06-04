/**
 * @file
 * @author Philippe Antoine <contact@catenacyber.fr>
 */

#include "suricata-common.h"
#include "detect-engine.h"
#include "detect-engine-build.h"
#include "detect-parse.h"
#include "util-fmemopen.h"
#include "reputation.h"
#include "util-unittest-helper.h"
#include "tmqh-packetpool.h"
#include "util-conf.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

SCInstance surifuzz;
static int initialized = 0;
ThreadVars *th_v;
Packet *p;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (initialized == 0) {
        // Redirects logs to /dev/null
        setenv("SC_LOG_OP_IFACE", "file", 0);
        setenv("SC_LOG_FILE", "/dev/null", 0);

        InitGlobal();

        GlobalsInitPreConfig();
        // redirect logs to /tmp
        ConfigSetLogDirectory("/tmp/");

        PostConfLoadedSetup(&surifuzz);
        PreRunPostPrivsDropInit(SCRunmodeGet());
        PostConfLoadedDetectSetup(&surifuzz);

        extern uint32_t max_pending_packets;
        max_pending_packets = 128;
        PacketPoolInit();
        th_v = ThreadVarsAlloc();
        p = UTHBuildPacket((uint8_t *)"fuzzfuzz", 8, IPPROTO_TCP);
        p->alerts.cnt = 0;
        p->action = 0;
        initialized = 1;
    }

    FILE *fd = NULL;
    size_t kw_len = 0;
    size_t split2 = 0;
    while (kw_len < size && data[kw_len] != ';') {
        kw_len++;
    }
    if (kw_len >= size) {
        return 0;
    }
    split2 = kw_len + 1;
    while (split2 < size && data[split2] != 0) {
        split2++;
    }
    if (split2 >= size) {
        return 0;
    }
    const uint8_t *category_data = data + kw_len + 1;
    size_t category_len = split2 - kw_len - 1;
    const uint8_t *ipreplist_data = data + split2 + 1;
    size_t ipreplist_len = size - split2 - 1;

    /* Build the full signature string */
    char sig_buf[DETECT_MAX_RULE_SIZE] = { 0 };
    size_t sig_len = strlcat(sig_buf, "alert ip any any -> any any (iprep:", sizeof(sig_buf));
    if (sig_len + kw_len >= DETECT_MAX_RULE_SIZE) {
        return 0;
    }
    memcpy(sig_buf + sig_len, data, kw_len);
    sig_len += kw_len;
    sig_len += strlcat(sig_buf + sig_len, "; sid:1;)", sizeof(sig_buf) - sig_len);

    /* ------------------------------------------------------------------ *
     * Per-iteration setup, mirroring DetectIPRepTest01
     * ------------------------------------------------------------------ */

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    de_ctx->flags |= DE_QUIET;
    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineThreadCtxInit(th_v, (void *)de_ctx, (void *)&det_ctx);

    /* Reset the global srep_version so that SRepLoadCatFileFromFD (which
     * asserts version == 0) can be called, and so that CIDR reputation
     * entries written with version 0 are visible to the matcher
     * (de_ctx->srep_version also stays 0 because SRepInit returns early
     * when no reputation config is present). */
    SRepResetVersion();

    /* Load the fuzz-controlled reputation categories file (if any) */
    fd = SCFmemopen((void *)category_data, category_len, "r");
    if (fd != NULL) {
        (void)SRepLoadCatFileFromFD(fd);
        fclose(fd);
    }

    /* Load fixed CIDR networks into the per-de_ctx reputation tree */
    fd = SCFmemopen((void *)ipreplist_data, ipreplist_len, "r");
    if (fd != NULL) {
        (void)SRepLoadFileFromFD(de_ctx->srepCIDR_ctx, fd);
        fclose(fd);
    }

    Signature *sig = DetectEngineAppendSig(de_ctx, sig_buf);
    if (sig == NULL) {
        DetectEngineThreadCtxDeinit(th_v, (void *)det_ctx);
        DetectEngineCtxFree(de_ctx);
        return 0;
    }
    SigGroupBuild(de_ctx);
    SigMatchSignatures(th_v, de_ctx, det_ctx, p);
    DetectEngineThreadCtxDeinit(th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    return 0;
}
