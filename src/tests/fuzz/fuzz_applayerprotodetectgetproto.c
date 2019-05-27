/**
 * @file
 * @author Philippe Antoine <contact@catenacyber.fr>
 * fuzz target for AppLayerProtoDetectGetProto
 */


#include "suricata-common.h"
#include "app-layer-detect-proto.h"
#include "flow-util.h"
#include "app-layer-parser.h"
#include "util-unittest-helper.h"


#define HEADER_LEN 6


int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

AppLayerProtoDetectThreadCtx *alpd_tctx = NULL;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    Flow *f;
    TcpSession ssn;
    bool reverse;

    if (size < HEADER_LEN) {
        return 0;
    }

    if (alpd_tctx == NULL) {
        //global init
        InitGlobal();
        run_mode = RUNMODE_UNITTEST;
        MpmTableSetup();
        SpmTableSetup();
        AppLayerProtoDetectSetup();
        AppLayerParserSetup();
        AppLayerParserRegisterProtocolParsers();
        alpd_tctx = AppLayerProtoDetectGetCtxThread();
    }

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "5.6.7.8", (data[2] << 8) | data[3], (data[4] << 8) | data[5]);
    if (f == NULL) {
        return 0;
    }
    f->proto = data[1];
    memset(&ssn, 0, sizeof(TcpSession));
    f->protoctx = &ssn;
    f->protomap = FlowGetProtoMapping(f->proto);

    AppLayerProtoDetectGetProto(alpd_tctx, f, data+HEADER_LEN, size-HEADER_LEN, f->proto, data[0], &reverse);
    UTHFreeFlow(f);

    return 0;
}
