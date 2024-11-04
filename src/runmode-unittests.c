/* Copyright (C) 2013-2024 Open Information Security Foundation
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
#include "runmode-unittests.h"
#include "util-unittest.h"

#include "util-debug.h"
#ifdef UNITTESTS
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-alert.h"
#include "detect-engine-address.h"
#include "detect-engine-proto.h"
#include "detect-engine-port.h"
#include "detect-engine-mpm.h"
#include "detect-engine-sigorder.h"
#include "detect-engine-payload.h"
#include "detect-engine-dcepayload.h"
#include "detect-engine-state.h"
#include "detect-engine-tag.h"
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
#include "tm-modules.h"
#include "tmqh-packetpool.h"
#include "decode-chdlc.h"
#include "decode-geneve.h"
#include "decode-nsh.h"
#include "decode-pppoe.h"
#include "decode-raw.h"
#include "decode-vntag.h"
#include "decode-vxlan.h"
#include "decode-pppoe.h"

#include "output-json-stats.h"

#ifdef OS_WIN32
#include "win32-syscall.h"
#endif

#ifdef WINDIVERT
#include "source-windivert.h"
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
    DecodeESPRegisterTests();
    DecodeMPLSRegisterTests();
    DecodeNSHRegisterTests();
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
    DetectEngineRegisterTests();
    SCLogRegisterTests();
    MagicRegisterTests();
    UtilMiscRegisterTests();
    DetectAddressTests();
    DetectProtoTests();
    DetectPortTests();
    DetectEngineAlertRegisterTests();
    SCAtomicRegisterTests();
    MemrchrRegisterTests();
    AppLayerUnittestsRegister();
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
    OutputJsonStatsRegisterTests();
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
    EngineModeSetIDS();

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

    UtInitialize();

    RegisterAllModules();

    HostBitInitCtx();

    StorageFinalize();
    /* test and initialize the unit testing subsystem */
    if (regex_arg == NULL){
        regex_arg = ".*";
        UtRunSelftest(regex_arg); /* inits and cleans up again */
    }

    AppLayerHtpEnableRequestBodyCallback();
    AppLayerHtpNeedFileInspection();

    RegisterUnittests();

    if (list_unittests) {
        UtListTests(regex_arg);
    } else {
        /* global packet pool */
        extern uint32_t max_pending_packets;
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

    exit(EXIT_SUCCESS);
#else
    FatalError("Unittests are not build-in");
#endif /* UNITTESTS */
}
