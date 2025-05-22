/**
 * @file
 * @author Philippe Antoine <contact@catenacyber.fr>
 * fuzz target for AppLayerProtoDetectGetProto
 */


#include "suricata-common.h"
#include "suricata.h"
#include "app-layer-detect-proto.h"
#include "flow-util.h"
#include "app-layer.h"
#include "util-unittest-helper.h"
#include "conf-yaml-loader.h"

#define HEADER_LEN 6

extern const char *configNoChecksum;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

AppLayerProtoDetectThreadCtx *alpd_tctx = NULL;
SC_ATOMIC_EXTERN(unsigned int, engine_stage);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    Flow *f;
    TcpSession ssn;
    bool reverse = false;

    if (alpd_tctx == NULL) {
        //global init
        InitGlobal();
        SCRunmodeSet(RUNMODE_UNITTEST);
        if (SCConfYamlLoadString(configNoChecksum, strlen(configNoChecksum)) != 0) {
            abort();
        }
        MpmTableSetup();
        SpmTableSetup();
        EngineModeSetIDS();
        AppLayerSetup();
        alpd_tctx = AppLayerProtoDetectGetCtxThread();
        SC_ATOMIC_SET(engine_stage, SURICATA_RUNTIME);
    }

    if (size < HEADER_LEN) {
        return 0;
    }

    f = TestHelperBuildFlow(AF_INET, "1.2.3.4", "5.6.7.8", (uint16_t)((data[2] << 8) | data[3]),
            (uint16_t)((data[4] << 8) | data[5]));
    if (f == NULL) {
        return 0;
    }
    f->proto = data[1];
    memset(&ssn, 0, sizeof(TcpSession));
    f->protoctx = &ssn;
    f->protomap = FlowGetProtoMapping(f->proto);

    uint8_t flags = STREAM_TOCLIENT;
    if (data[0] & STREAM_TOSERVER) {
        flags = STREAM_TOSERVER;
    }
    AppLayerProtoDetectGetProto(alpd_tctx, f, data + HEADER_LEN, (uint32_t)(size - HEADER_LEN),
            f->proto, flags, &reverse);
    FlowFree(f);

    return 0;
}
