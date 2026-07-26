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
#include "stream-tcp-private.h"
#include "stream-tcp.h"
#include "app-layer-parser.h"
#include "flow-util.h"
#include "flow-worker.h"
#include "rust.h"
#include "tm-modules.h"
#include "datasets.h"
#include "util-conf.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

SCInstance surifuzz;
static int initialized = 0;
ThreadVars *th_v;
Packet *p;
TcpSession ssn;
Flow f;
uint8_t http_buf1[] = "GET /";
uint32_t http_len1 = sizeof(http_buf1) - 1;
uint8_t http_buf2[] = " HTTP/1.0\r\n"
                      "Host: suricata.fuzz\r\n\r\n";
uint32_t http_len2 = sizeof(http_buf2) - 1;
AppLayerParserThreadCtx *alp_tctx = NULL;
SC_ATOMIC_EXTERN(unsigned int, engine_stage);
// FlowWorkerThreadData
void *fwd;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (initialized == 0) {
        // Redirects logs to /dev/null
        setenv("SC_LOG_OP_IFACE", "file", 0);
        setenv("SC_LOG_FILE", "/dev/null", 0);

        InitGlobal();

        GlobalsInitPreConfig();
        SCRunmodeSet(RUNMODE_PCAP_FILE);
        // redirect logs to /tmp
        ConfigSetLogDirectory("/tmp/");
        ConfigSetDataDirectory((char *)"/tmp/");

        // do not load rules before reproducible DetectEngineReload
        remove("/tmp/fuzz.rules");
        surifuzz.sig_file = strdup("/tmp/fuzz.rules");
        surifuzz.sig_file_exclusive = 1;
        surifuzz.delayed_detect = 1;

        PostConfLoadedSetup(&surifuzz);
        PreRunPostPrivsDropInit(SCRunmodeGet());
        PostConfLoadedDetectSetup(&surifuzz);

        extern uint32_t max_pending_packets;
        max_pending_packets = 128;
        PacketPoolInit();
        th_v = ThreadVarsAlloc();
        SC_ATOMIC_SET(engine_stage, SURICATA_RUNTIME);
        tmm_modules[TMM_FLOWWORKER].ThreadInit(th_v, NULL, &fwd);

        memset(&f, 0, sizeof(f));
        memset(&ssn, 0, sizeof(ssn));
        p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
        FLOW_INITIALIZE(&f);
        f.protoctx = (void *)&ssn;
        f.proto = IPPROTO_TCP;
        f.flags |= FLOW_IPV4;
        p->flow = &f;
        p->flowflags |= FLOW_PKT_TOSERVER;
        p->flowflags |= FLOW_PKT_ESTABLISHED;
        p->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
        f.alproto = ALPROTO_HTTP1;
        StreamTcpInitConfig(true);
        alp_tctx = AppLayerParserThreadCtxAlloc();
        initialized = 1;
    }

    p->alerts.cnt = 0;
    p->action = 0;
    size_t kw_len = 0;
    if (size == 0) {
        return 0;
    }
    // First byte/bit : datarep or dataset keyword
    bool rep = data[0] & 1;
    data++;
    size--;
    // Then split on first ;
    // Before is the argument in the signature
    // After is the contents of a dataset file
    while (kw_len < size && data[kw_len] != ';') {
        kw_len++;
    }
    if (kw_len >= size) {
        return 0;
    }
    // Then split on first null character
    // Before is the contents of a dataset file
    // After is the uri to use in the network traffic
    const uint8_t *dataset_data = data + kw_len + 1;
    size_t dataset_len = 0;
    while (kw_len + 1 + dataset_len < size && data[kw_len + 1 + dataset_len] != 0) {
        dataset_len++;
    }
    const uint8_t *uri_data = data + kw_len + 1 + dataset_len + 1;
    size_t uri_len = 0;
    if (size > (kw_len + 1 + dataset_len + 1))
        uri_len = size - (kw_len + 1 + dataset_len + 1);

    /* Build the full signature string */
    char sig_buf[DETECT_MAX_RULE_SIZE] = { 0 };
    size_t sig_len = strlcat(sig_buf, "alert http any any -> any any (http.uri; ", sizeof(sig_buf));
    if (sig_len + strlen("datarep:") + kw_len + strlen("; sid:1;)") >= DETECT_MAX_RULE_SIZE) {
        return 0;
    }
    if (rep) {
        sig_len += strlcat(sig_buf + sig_len, "datarep:", sizeof(sig_buf) - sig_len);
    } else {
        sig_len += strlcat(sig_buf + sig_len, "dataset:", sizeof(sig_buf) - sig_len);
    }
    memcpy(sig_buf + sig_len, data, kw_len);
    sig_len += kw_len;
    sig_len += strlcat(sig_buf + sig_len, "; sid:1;)", sizeof(sig_buf) - sig_len);

    if (TestHelperBufferToFile(surifuzz.sig_file, (const uint8_t *)sig_buf, sig_len) < 0) {
        return 0;
    }
    if (TestHelperBufferToFile("/tmp/dataset.fuzz", dataset_data, dataset_len) < 0) {
        return 0;
    }

    // DetectEngineReload is not enough
    DatasetsDestroy();
    DatasetsInit();
    if (DetectEngineReload(&surifuzz) < 0) {
        return 0;
    }
    DetectEngineThreadCtx *old_det_ctx = FlowWorkerGetDetectCtxPtr(fwd);
    DetectEngineCtx *de_ctx = DetectEngineGetCurrent();
    de_ctx->ref_cnt--;
    DetectEngineThreadCtx *new_det_ctx = DetectEngineThreadCtxInitForReload(th_v, de_ctx, 1);
    FlowWorkerReplaceDetectCtx(fwd, new_det_ctx);
    DetectEngineThreadCtxDeinit(NULL, old_det_ctx);

    FLOWLOCK_WRLOCK(&f);
    AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    if (uri_len)
        AppLayerParserParse(
                NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, uri_data, (uint32_t)uri_len);
    AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf2, http_len2);
    SigMatchSignatures(th_v, de_ctx, new_det_ctx, p);
    FlowCleanupAppLayer(&f);
    FLOWLOCK_UNLOCK(&f);

    return 0;
}
