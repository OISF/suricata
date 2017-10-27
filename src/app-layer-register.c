/* Copyright (C) 2017 Open Information Security Foundation
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

/**
 * \file
 *
 * \author Pierre Chifflier <chifflier@wzdftpd.net>
 *
 * Parser registration functions.
 */

#include "suricata-common.h"
#include "stream.h"
#include "conf.h"

#include "app-layer-detect-proto.h"
#include "app-layer-parser.h"

#include "app-layer-register.h"

AppProto AppLayerRegisterParser(const struct AppLayerParser *p)
{
    AppProto AlProto;
    const char *IpProtoStr = NULL;

    if (p == NULL)
        return ALPROTO_FAILED;

    AlProto = StringToAppProto(p->Name);
    if (AlProto == ALPROTO_UNKNOWN || AlProto == ALPROTO_FAILED)
        return AlProto;

    switch (p->IpProto) {
        case IPPROTO_TCP:
            IpProtoStr = "tcp";
            break;
        case IPPROTO_UDP:
            IpProtoStr = "udp";
            break;
        default:
            SCLogDebug("Unknown or unsupported IpProto field in parser");
            return ALPROTO_UNKNOWN;
    };

    /* Check if protocol detection is enabled. If it does not exist in
     * the configuration file then it will be enabled by default. */
    if (AppLayerProtoDetectConfProtoDetectionEnabled(IpProtoStr, p->Name)) {

        SCLogDebug("%s %s protocol detection enabled.", IpProtoStr, p->Name);

        AppLayerProtoDetectRegisterProtocol(AlProto, p->Name);

        if (RunmodeIsUnittests()) {

            SCLogDebug("Unittest mode, registering default configuration.");
            AppLayerProtoDetectPPRegister(p->IpProto, p->DefaultPort,
                AlProto, p->MinDepth, p->MaxDepth, STREAM_TOSERVER,
                p->ProbeTS, p->ProbeTC);

        }
        else {

            if (!AppLayerProtoDetectPPParseConfPorts(IpProtoStr, p->IpProto,
                    p->Name, AlProto, p->MinDepth, p->MaxDepth,
                    p->ProbeTS, p->ProbeTC)) {
                SCLogDebug("No %s app-layer configuration, enabling %s"
                    " detection %s detection on port %s.",
                    p->Name, p->Name, IpProtoStr, p->DefaultPort);
                AppLayerProtoDetectPPRegister(p->IpProto,
                    p->DefaultPort, AlProto,
                    p->MinDepth, p->MaxDepth, STREAM_TOSERVER,
                    p->ProbeTS, p->ProbeTC);
            }

        }
    }
    else {
        SCLogDebug("Protocol detecter and parser disabled for %s.", p->Name);
        return AlProto;
    }

    if (AppLayerParserConfParserEnabled(IpProtoStr, p->Name))
    {
        SCLogDebug("Registering %s protocol parser.", p->Name);

        /* Register functions for state allocation and freeing. A
         * state is allocated for every new flow. */
        AppLayerParserRegisterStateFuncs(p->IpProto, AlProto,
            p->StateAlloc, p->StateFree);

        /* Register request parser for parsing frame from server to server. */
        AppLayerParserRegisterParser(p->IpProto, AlProto,
            STREAM_TOSERVER, p->ParseTS);

        /* Register response parser for parsing frames from server to client. */
        AppLayerParserRegisterParser(p->IpProto, AlProto,
            STREAM_TOCLIENT, p->ParseTC);

        /* Register a function to be called by the application layer
         * when a transaction is to be freed. */
        AppLayerParserRegisterTxFreeFunc(p->IpProto, AlProto,
            p->StateTransactionFree);

        /* Register a function to return the current transaction count. */
        AppLayerParserRegisterGetTxCnt(p->IpProto, AlProto,
            p->StateGetTxCnt);

        /* Transaction handling. */
        AppLayerParserRegisterGetStateProgressCompletionStatus(AlProto,
            p->StateGetProgressCompletionStatus);
        AppLayerParserRegisterGetStateProgressFunc(p->IpProto, AlProto,
            p->StateGetProgress);
        AppLayerParserRegisterGetTx(p->IpProto, AlProto,
            p->StateGetTx);

        if (p->StateGetTxLogged && p->StateSetTxLogged) {
            AppLayerParserRegisterLoggerFuncs(p->IpProto, AlProto,
                    p->StateGetTxLogged, p->StateSetTxLogged);
        }

        /* Application layer event handling. */
        if (p->StateHasEvents) {
            AppLayerParserRegisterHasEventsFunc(p->IpProto, AlProto,
                    p->StateHasEvents);
        }

        /* What is this being registered for? */
        AppLayerParserRegisterDetectStateFuncs(p->IpProto, AlProto,
            p->StateHasTxDetectState, p->GetTxDetectState, p->SetTxDetectState);

        if (p->StateGetEventInfo) {
            AppLayerParserRegisterGetEventInfo(p->IpProto, AlProto,
                    p->StateGetEventInfo);
        }
        if (p->StateGetEvents) {
            AppLayerParserRegisterGetEventsFunc(p->IpProto, AlProto,
                    p->StateGetEvents);
        }
        if (p->LocalStorageAlloc && p->LocalStorageFree) {
            AppLayerParserRegisterLocalStorageFunc(p->IpProto, AlProto,
                    p->LocalStorageAlloc, p->LocalStorageFree);
        }
        if (p->GetTxMpmIDs && p->SetTxMpmIDs) {
            AppLayerParserRegisterMpmIDsFuncs(p->IpProto, AlProto,
                    p->GetTxMpmIDs, p->SetTxMpmIDs);
        }
        if (p->StateGetFiles) {
            AppLayerParserRegisterGetFilesFunc(p->IpProto, AlProto,
                    p->StateGetFiles);
        }
    }
    else {
        SCLogNotice("%s protocol parsing disabled.", p->Name);
    }

#ifdef UNITTESTS
    // AppLayerParserRegisterProtocolUnittests(IPPROTO_UDP, ALPROTO_NFS,
    //    NFSUDPParserRegisterTests);
#endif

    return AlProto;
}
