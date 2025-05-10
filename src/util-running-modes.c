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
#include "app-layer-detect-proto.h"
#include "app-layer.h"
#include "app-layer-parser.h"
#include "detect-engine.h"
#include "util-unittest.h"
#include "util-debug.h"
#include "conf-yaml-loader.h"
#include "util-running-modes.h"

int ListKeywords(const char *keyword_info)
{
    EngineModeSetIDS();
    SCLogLoadConfig(0, 0, 0, 0);
    MpmTableSetup();
    SpmTableSetup();
    AppLayerSetup();
    SigTableInit();
    SigTableSetup(); /* load the rule keywords */
    return SigTableList(keyword_info);
}

int ListAppLayerProtocols(const char *conf_filename)
{
    EngineModeSetIDS();
    if (SCConfYamlLoadFile(conf_filename) != -1)
        SCLogLoadConfig(0, 0, 0, 0);
    MpmTableSetup();
    SpmTableSetup();
    AppLayerSetup();
    AppLayerListSupportedProtocols();

    return TM_ECODE_DONE;
}

static bool IsBuiltIn(const char *n)
{
    if (strcmp(n, "request_started") == 0 || strcmp(n, "response_started") == 0) {
        return true;
    }
    if (strcmp(n, "request_complete") == 0 || strcmp(n, "response_complete") == 0) {
        return true;
    }
    return false;
}

int ListAppLayerHooks(const char *conf_filename)
{
    EngineModeSetIDS();
    if (SCConfYamlLoadFile(conf_filename) != -1)
        SCLogLoadConfig(0, 0, 0, 0);
    MpmTableSetup();
    SpmTableSetup();
    AppLayerSetup();

    AppProto alprotos[g_alproto_max];
    AppLayerProtoDetectSupportedAppProtocols(alprotos);

    printf("=========Supported App Layer Hooks=========\n");
    for (AppProto a = 0; a < g_alproto_max; a++) {
        if (alprotos[a] != 1)
            continue;

        const char *alproto_name = AppProtoToString(a);
        if (strcmp(alproto_name, "http") == 0)
            alproto_name = "http1";
        SCLogDebug("alproto %u/%s", a, alproto_name);

        const int max_progress_ts =
                AppLayerParserGetStateProgressCompletionStatus(a, STREAM_TOSERVER);
        const int max_progress_tc =
                AppLayerParserGetStateProgressCompletionStatus(a, STREAM_TOCLIENT);

        printf("%s:%s\n", alproto_name, "request_started");
        for (int p = 0; p <= max_progress_ts; p++) {
            const char *name = AppLayerParserGetStateNameById(
                    IPPROTO_TCP /* TODO no ipproto */, a, p, STREAM_TOSERVER);
            if (name != NULL && !IsBuiltIn(name)) {
                printf("%s:%s\n", alproto_name, name);
            }
        }
        printf("%s:%s\n", alproto_name, "request_complete");

        printf("%s:%s\n", alproto_name, "response_started");
        for (int p = 0; p <= max_progress_tc; p++) {
            const char *name = AppLayerParserGetStateNameById(
                    IPPROTO_TCP /* TODO no ipproto */, a, p, STREAM_TOCLIENT);
            if (name != NULL && !IsBuiltIn(name)) {
                printf("%s:%s\n", alproto_name, name);
            }
        }
        printf("%s:%s\n", alproto_name, "response_complete");
    }
    return TM_ECODE_DONE;
}
