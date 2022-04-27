/* Copyright (C) 2013-2022 Open Information Security Foundation
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
#include "util-unittest.h"
#include "runmode-unittests.h"

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
#include "detect-engine-state.h"
#include "detect-engine-tag.h"
#include "detect-engine-modbus.h"
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

#include "stream-tcp.h"

#include "app-layer-detect-proto.h"
#include "app-layer-parser.h"
#include "app-layer.h"
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
#include "util-macset.h"
#include "util-memrchr.h"

#include "util-mpm-ac.h"
#include "util-mpm-hs.h"

#include "conf.h"
#include "conf-yaml-loader.h"
#include "tmqh-flow.h"
#include "defrag.h"
#include "detect-engine-siggroup.h"

#include "util-streaming-buffer.h"
#include "util-lua.h"

#ifdef OS_WIN32
#include "win32-syscall.h"
#endif

#ifdef WINDIVERT
#include "source-windivert.h"
#endif

#ifdef HAVE_NSS
#include <prinit.h>
#include <nss.h>
#endif

#endif /* UNITTESTS */

void TmqhSetup (void);

#ifdef UNITTESTS
static void RegisterUnittests(void)
{
    UTHRegisterTests();
    StreamTcpRegisterTests();
    SigRegisterTests();
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
    DecodeEthernetRegisterTests();
    DecodeCHDLCRegisterTests();
    DecodePPPRegisterTests();
    DecodeVLANRegisterTests();
    DecodeVNTagRegisterTests();
    DecodeGeneveRegisterTests();
    DecodeVXLANRegisterTests();
    DecodeRawRegisterTests();
    DecodePPPOERegisterTests();
    DecodeICMPV4RegisterTests();
    DecodeICMPV6RegisterTests();
    DecodeIPV4RegisterTests();
    DecodeIPV6RegisterTests();
    DecodeTCPRegisterTests();
    DecodeUDPV4RegisterTests();
    DecodeGRERegisterTests();
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
    PayloadRegisterTests();
    DcePayloadRegisterTests();
#ifdef PROFILING
    SCProfilingRegisterTests();
#endif
    DeStateRegisterTests();
    MemcmpRegisterTests();
    DetectEngineInspectModbusRegisterTests();
    DetectEngineRegisterTests();
    SCLogRegisterTests();
    MagicRegisterTests();
    UtilMiscRegisterTests();
    DetectAddressTests();
    DetectProtoTests();
    DetectPortTests();
    SCAtomicRegisterTests();
    MemrchrRegisterTests();
    AppLayerUnittestsRegister();
    MimeDecRegisterTests();
    StreamingBufferRegisterTests();
    MacSetRegisterTests();
#ifdef OS_WIN32
    Win32SyscallRegisterTests();
#endif
#ifdef WINDIVERT
    SourceWinDivertRegisterTests();
#endif
    SCProtoNameRegisterTests();
    UtilCIDRTests();
}
#endif

/**
 * Run or list unittests
 *
 * \param list_unittests If set to 1, list unittests. Run them if set to 0.
 * \param regex_arg A regular expression to select unittests to run
 *
 * This function is terminal and will call exit after being called.
 */

void RunUnittests(int list_unittests, const char *regex_arg)
{
#ifdef UNITTESTS
    /* Initializations for global vars, queues, etc (memsets, mutex init..) */
    GlobalsInitPreConfig();

#ifdef HAVE_LUAJIT
    if (LuajitSetupStatesPool() != 0) {
        exit(EXIT_FAILURE);
    }
#endif

    default_packet_size = DEFAULT_PACKET_SIZE;
    /* load the pattern matchers */
    MpmTableSetup();
    SpmTableSetup();

    StorageInit();
    AppLayerSetup();

    /* hardcoded initialization code */
    SigTableSetup(); /* load the rule keywords */
    TmqhSetup();

    TagInitCtx();
    SCReferenceConfInit();
    SCClassConfInit();

    UtInitialize();

    RegisterAllModules();

    HostBitInitCtx();

    StorageFinalize();
   /* test and initialize the unittesting subsystem */
    if (regex_arg == NULL){
        regex_arg = ".*";
        UtRunSelftest(regex_arg); /* inits and cleans up again */
    }

#ifdef HAVE_NSS
    /* init NSS for hashing */
    PR_Init(PR_USER_THREAD, PR_PRIORITY_NORMAL, 0);
    NSS_NoDB_Init(NULL);
#endif


    AppLayerHtpEnableRequestBodyCallback();
    AppLayerHtpNeedFileInspection();

    RegisterUnittests();

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
#ifdef BUILD_HYPERSCAN
        MpmHSGlobalCleanup();
#endif
        if (failed) {
            exit(EXIT_FAILURE);
        }
    }

#ifdef HAVE_LUAJIT
    LuajitFreeStatesPool();
#endif

    exit(EXIT_SUCCESS);
#else
    FatalError(SC_ERR_FATAL, "Unittests are not build-in");
#endif /* UNITTESTS */
}

