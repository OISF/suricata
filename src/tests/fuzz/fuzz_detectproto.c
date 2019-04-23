/**
 * @file
 * @author Philippe Antoine <contact@catenacyber.fr>
 * fuzz harness for AppLayerProtoDetectGetProto
 */


#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include "suricata-common.h"
#include "app-layer-detect-proto.h"
#include "flow-util.h"
#include "stream-tcp-private.h"
#include "app-layer-parser.h"


#define HEADER_LEN 6


int g_detect_disabled = 0;
int g_disable_randomness = 1;
intmax_t max_pending_packets = 1;
int run_mode = RUNMODE_UNITTEST;
volatile uint8_t suricata_ctl_flags = 0;
int g_ut_covered;
int g_ut_modules;
int coverage_unittests;
uint8_t host_mode = SURI_HOST_IS_SNIFFER_ONLY;

SC_ATOMIC_DECLARE(unsigned int, engine_stage);

void EngineDone(void)
{
}

void EngineStop(void)
{
}

int EngineModeIsIPS(void)
{
    return 0;
}

void PostRunDeinit(const int runmode, struct timeval *start_time)
{
}

void PreRunInit(const int runmode)
{
}

void PreRunPostPrivsDropInit(const int runmode)
{
}

int RunmodeGetCurrent(void)
{
    return RUNMODE_UNITTEST;
}

int RunmodeIsUnittests(void)
{
    return 1;
}

int SuriHasSigFile(void)
{
    return 0;
}

void fuzz_openFile(const char * name) {
}

AppLayerProtoDetectThreadCtx *alpd_tctx = NULL;

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    Flow f;
    TcpSession ssn;

    if (Size < HEADER_LEN) {
        return 0;
    }

    if (alpd_tctx == NULL) {
        //global init
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
    f.sp = (Data[2] << 8) | Data[3];
    f.dp = (Data[4] << 8) | Data[5];
    f.proto = Data[1];
    memset(&ssn, 0, sizeof(TcpSession));
    f.protoctx = &ssn;
    f.protomap = FlowGetProtoMapping(f.proto);

    int r = AppLayerProtoDetectGetProto(alpd_tctx, &f, Data+HEADER_LEN, Size-HEADER_LEN, f.proto, Data[0]);
    //printf("proto %d\n", r);

    return 0;
}
