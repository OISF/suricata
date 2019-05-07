/**
 * @file
 * @author Philippe Antoine <contact@catenacyber.fr>
 * fuzz harness for AppLayerProtoDetectGetProto
 */


#include "suricata-common.h"
#include "app-layer-detect-proto.h"
#include "flow-util.h"
#include "app-layer-parser.h"


#define HEADER_LEN 6


void fuzz_openFile(const char * name) {
}

AppLayerProtoDetectThreadCtx *alpd_tctx = NULL;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    Flow f;
    TcpSession ssn;

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

    memset(&f, 0, sizeof(f));
    FLOW_INITIALIZE(&f);
    f.flags |= FLOW_IPV4;
    f.src.addr_data32[0] = 0x01020304;
    f.dst.addr_data32[0] = 0x05060708;
    f.sp = (data[2] << 8) | data[3];
    f.dp = (data[4] << 8) | data[5];
    f.proto = data[1];
    memset(&ssn, 0, sizeof(TcpSession));
    f.protoctx = &ssn;
    f.protomap = FlowGetProtoMapping(f.proto);

    AppLayerProtoDetectGetProto(alpd_tctx, &f, data+HEADER_LEN, size-HEADER_LEN, f.proto, data[0], NULL);
    //printf("proto %d\n", r);

    return 0;
}
