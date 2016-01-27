/* Copyright (C) 2013 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/** \file
 *
 *  \author Eric Leblond <eric@regit.org>
 */

#include "suricata-common.h"
#include "config.h"
#include "util-unittest.h"

#ifdef UNITTESTS

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-address.h"
#include "detect-engine-proto.h"
#include "detect-engine-port.h"
#include "detect-engine-mpm.h"
#include "detect-engine-sigorder.h"
#include "detect-engine-payload.h"
#include "detect-engine-dcepayload.h"
#include "detect-engine-uri.h"
#include "detect-engine-hcbd.h"
#include "detect-engine-hsbd.h"
#include "detect-engine-hhd.h"
#include "detect-engine-hrhd.h"
#include "detect-engine-hmd.h"
#include "detect-engine-hcd.h"
#include "detect-engine-hrud.h"
#include "detect-engine-hsmd.h"
#include "detect-engine-hscd.h"
#include "detect-engine-hua.h"
#include "detect-engine-hhhd.h"
#include "detect-engine-hrhhd.h"
#include "detect-engine-state.h"
#include "detect-engine-tag.h"
#include "detect-engine-modbus.h"
#include "detect-engine-filedata-smtp.h"
#include "detect-fast-pattern.h"
#include "flow.h"
#include "flow-timeout.h"
#include "flow-manager.h"
#include "flow-var.h"
#include "flow-bit.h"
#include "pkt-var.h"

#include "host.h"
#include "host-bit.h"
#include "ippair.h"
#include "ippair-bit.h"
#include "unix-manager.h"

#include "app-layer-detect-proto.h"
#include "app-layer-parser.h"
#include "app-layer.h"
#include "app-layer-smb.h"
#include "app-layer-dcerpc.h"
#include "app-layer-dcerpc-udp.h"
#include "app-layer-htp.h"
#include "app-layer-ftp.h"
#include "app-layer-ssl.h"
#include "app-layer-ssh.h"
#include "app-layer-smtp.h"

#include "util-action.h"
#include "util-radix-tree.h"
#include "util-host-os-info.h"
#include "util-cidr.h"
#include "util-unittest-helper.h"
#include "util-time.h"
#include "util-rule-vars.h"
#include "util-classification-config.h"
#include "util-threshold-config.h"
#include "util-reference-config.h"
#include "util-profiling.h"
#include "util-magic.h"
#include "util-memcmp.h"
#include "util-misc.h"
#include "util-ringbuffer.h"
#include "util-signal.h"

#include "reputation.h"
#include "util-atomic.h"
#include "util-spm.h"
#include "util-hash.h"
#include "util-hashlist.h"
#include "util-bloomfilter.h"
#include "util-bloomfilter-counting.h"
#include "util-pool.h"
#include "util-byte.h"
#include "util-proto-name.h"
#include "util-memrchr.h"

#include "util-mpm-ac.h"
#include "detect-engine-mpm.h"

#include "util-decode-asn1.h"

#include "conf.h"
#include "conf-yaml-loader.h"
#include "tmqh-flow.h"
#include "defrag.h"
#include "detect-engine-siggroup.h"

#endif /* UNITTESTS */

void RegisterAllModules();
void TmqhSetup (void);

/**
 * Run or list unittests
 *
 * \param list_unittests If set to 1, list unittests. Run them if set to 0.
 * \param regex_arg A regular expression to select unittests to run
 *
 * This function is terminal and will call exit after being called.
 */

void RunUnittests(int list_unittests, char *regex_arg)
{
#ifdef UNITTESTS
    /* Initializations for global vars, queues, etc (memsets, mutex init..) */
    GlobalInits();
    TimeInit();
    SupportFastPatternForSigMatchTypes();

    default_packet_size = DEFAULT_PACKET_SIZE;
#ifdef __SC_CUDA_SUPPORT__
    /* Init the CUDA environment */
    SCCudaInitCudaEnvironment();
    CudaBufferInit();
#endif
    /* load the pattern matchers */
    MpmTableSetup();
#ifdef __SC_CUDA_SUPPORT__
    MpmCudaEnvironmentSetup();
#endif

    AppLayerSetup();

    /* hardcoded initialization code */
    SigTableSetup(); /* load the rule keywords */
    TmqhSetup();

    StorageInit();
    CIDRInit();
    SigParsePrepare();

#ifdef DBG_MEM_ALLOC
    SCLogInfo("Memory used at startup: %"PRIdMAX, (intmax_t)global_mem);
#endif
    SCReputationInitCtx();
    SCProtoNameInit();

    TagInitCtx();
    SCReferenceConfInit();
    SCClassConfInit();

    RegisterAllModules();

    DetectEngineRegisterAppInspectionEngines();

    HostBitInitCtx();

    StorageFinalize();
   /* test and initialize the unittesting subsystem */
    if(regex_arg == NULL){
        regex_arg = ".*";
        UtRunSelftest(regex_arg); /* inits and cleans up again */
    }

    AppLayerHtpEnableRequestBodyCallback();
    AppLayerHtpNeedFileInspection();

    UtInitialize();
    UTHRegisterTests();
    SCReputationRegisterTests();
    TmModuleRegisterTests();
    SigTableRegisterTests();
    HashTableRegisterTests();
    HashListTableRegisterTests();
    BloomFilterRegisterTests();
    BloomFilterCountingRegisterTests();
    PoolRegisterTests();
    ByteRegisterTests();
    MpmRegisterTests();
    FlowBitRegisterTests();
    HostBitRegisterTests();
    IPPairBitRegisterTests();
    StatsRegisterTests();
    DecodePPPRegisterTests();
    DecodeVLANRegisterTests();
    DecodeRawRegisterTests();
    DecodePPPOERegisterTests();
    DecodeICMPV4RegisterTests();
    DecodeICMPV6RegisterTests();
    DecodeIPV4RegisterTests();
    DecodeIPV6RegisterTests();
    DecodeTCPRegisterTests();
    DecodeUDPV4RegisterTests();
    DecodeGRERegisterTests();
    DecodeAsn1RegisterTests();
    DecodeMPLSRegisterTests();
    AppLayerProtoDetectUnittestsRegister();
    ConfRegisterTests();
    ConfYamlRegisterTests();
    TmqhFlowRegisterTests();
    FlowRegisterTests();
    HostRegisterUnittests();
    IPPairRegisterUnittests();
    SCSigRegisterSignatureOrderingTests();
    SCRadixRegisterTests();
    DefragRegisterTests();
    SigGroupHeadRegisterTests();
    SCHInfoRegisterTests();
    SCRuleVarsRegisterTests();
    AppLayerParserRegisterUnittests();
    ThreadMacrosRegisterTests();
    UtilSpmSearchRegistertests();
    UtilActionRegisterTests();
    SCClassConfRegisterTests();
    SCThresholdConfRegisterTests();
    SCRConfRegisterTests();
#ifdef __SC_CUDA_SUPPORT__
    SCCudaRegisterTests();
#endif
    PayloadRegisterTests();
    DcePayloadRegisterTests();
    UriRegisterTests();
#ifdef PROFILING
    SCProfilingRegisterTests();
#endif
    DeStateRegisterTests();
    DetectRingBufferRegisterTests();
    MemcmpRegisterTests();
    DetectEngineHttpClientBodyRegisterTests();
    DetectEngineHttpServerBodyRegisterTests();
    DetectEngineHttpHeaderRegisterTests();
    DetectEngineHttpRawHeaderRegisterTests();
    DetectEngineHttpMethodRegisterTests();
    DetectEngineHttpCookieRegisterTests();
    DetectEngineHttpRawUriRegisterTests();
    DetectEngineHttpStatMsgRegisterTests();
    DetectEngineHttpStatCodeRegisterTests();
    DetectEngineHttpUARegisterTests();
    DetectEngineHttpHHRegisterTests();
    DetectEngineHttpHRHRegisterTests();
    DetectEngineInspectModbusRegisterTests();
    DetectEngineRegisterTests();
    DetectEngineSMTPFiledataRegisterTests();
    SCLogRegisterTests();
    MagicRegisterTests();
    UtilMiscRegisterTests();
    DetectAddressTests();
    DetectProtoTests();
    DetectPortTests();
    SCAtomicRegisterTests();
    MemrchrRegisterTests();
#ifdef __SC_CUDA_SUPPORT__
    CudaBufferRegisterUnittests();
#endif
    AppLayerUnittestsRegister();
    MimeDecRegisterTests();
    if (list_unittests) {
        UtListTests(regex_arg);
    } else {
        /* global packet pool */
        extern intmax_t max_pending_packets;
        max_pending_packets = 128;
        PacketPoolInit();

        uint32_t failed = UtRunTests(regex_arg);
        PacketPoolDestroy();
        UtCleanup();
#ifdef __SC_CUDA_SUPPORT__
        if (PatternMatchDefaultMatcher() == MPM_AC_CUDA)
            MpmCudaBufferDeSetup();
        CudaHandlerFreeProfiles();
#endif
        if (failed) {
            exit(EXIT_FAILURE);
        }
    }

#ifdef DBG_MEM_ALLOC
    SCLogInfo("Total memory used (without SCFree()): %"PRIdMAX, (intmax_t)global_mem);
#endif

    exit(EXIT_SUCCESS);
#else
    SCLogError(SC_ERR_NOT_SUPPORTED, "Unittests are not build-in");
    exit(EXIT_FAILURE);
#endif /* UNITTESTS */
}

