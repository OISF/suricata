/**
 * @file
 * @author Philippe Antoine <contact@catenacyber.fr>
 * fuzz target for AppLayerProtoDetectGetProto
 */


#include "suricata-common.h"
#include "app-layer-detect-proto.h"
#include "flow-util.h"
#include "app-layer-parser.h"

#define HEADER_LEN 6

void fuzz_openFile(const char * name) {
}

AppLayerParserThreadCtx *alp_tctx = NULL;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    Flow * f;
    TcpSession ssn;

    if (size < HEADER_LEN) {
        return 0;
    }

    if (alp_tctx == NULL) {
        InitGlobal();
        run_mode = RUNMODE_UNITTEST;
        FlowInitConfig(FLOW_QUIET);
        MpmTableSetup();
        SpmTableSetup();
        AppLayerProtoDetectSetup();
        AppLayerParserSetup();
        AppLayerParserRegisterProtocolParsers();
        alp_tctx = AppLayerParserThreadCtxAlloc();
    }

    if (data[0] >= ALPROTO_MAX) {
        return 0;
    }
    f = FlowAlloc();
    if (f == NULL) {
        return 0;
    }
    f->flags |= FLOW_IPV4;
    f->src.addr_data32[0] = 0x01020304;
    f->dst.addr_data32[0] = 0x05060708;
    f->sp = (data[2] << 8) | data[3];
    f->dp = (data[4] << 8) | data[5];
    f->proto = data[1];
    memset(&ssn, 0, sizeof(TcpSession));
    f->protoctx = &ssn;
    f->protomap = FlowGetProtoMapping(f->proto);
    f->alproto = data[0];

    int start = 1;
    int flip = 0;
    size_t offset = HEADER_LEN;
    while (1) {
        int done = 0;
        uint8_t flags = 0;
        size_t onesize = 0;
        if (flip) {
            flags = STREAM_TOCLIENT;
            flip = 0;
        } else {
            flags = STREAM_TOSERVER;
            flip = 1;
        }
        if (start > 0) {
            flags |= STREAM_START;
            start = 0;
        }
        if (size < offset + 2) {
            onesize = 0;
            done = 1;
        } else {
            onesize = ((data[offset]) << 8) | (data[offset+1]);
            offset += 2;
            if (size < offset + onesize) {
                onesize = size - offset;
                done = 1;
            }
        }
        if (done) {
            flags |= STREAM_EOF;
        }

        (void) AppLayerParserParse(NULL, alp_tctx, f, f->alproto, flags, data+offset, onesize);
        offset += onesize;
        if (done)
            break;

    }

    FlowFree(f);

    return 0;
}
