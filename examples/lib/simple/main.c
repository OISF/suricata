/* Copyright (C) 2024 Open Information Security Foundation
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

#include "suricata.h"

#include "source.h"
#include "runmode.h"

#include "tm-threads-common.h"
#include "util-debug.h"
#include "suricata-plugin.h"

static void InitCapturePlugin(const char *args, int plugin_slot, int receive_slot, int decode_slot)
{
    SCLogNotice("...");
    RegisterCaptureModes(plugin_slot);
    RegisterCapturePluginReceive(receive_slot);
    RegisterCapturePluginDecode(decode_slot);
}

int main(int argc, char **argv)
{
    SuricataPreInit(argv[0]);

    /* Register our custom capture method as a plugin. */
    SCCapturePlugin capture_plugin = {
        .name = (char *)"ci-capture",
        .Init = InitCapturePlugin,
        .GetDefaultMode = DefaultRunMode,
    };
    SCPluginRegisterCapture(&capture_plugin);

    /* Parse command line options. This is optional, you could
     * directly configure Suricata through the Conf API. */
    SCParseCommandLine(argc, argv);

    /* Validate/finalize the runmode. */
    if (SCFinalizeRunMode() != TM_ECODE_OK) {
        exit(EXIT_FAILURE);
    }

    /* Handle internal runmodes. Typically you wouldn't do this as a
     * library user, however this example is showing how to replicate
     * the Suricata application with the library. */
    switch (SCStartInternalRunMode(argc, argv)) {
        case TM_ECODE_DONE:
            exit(EXIT_SUCCESS);
        case TM_ECODE_FAILED:
            exit(EXIT_FAILURE);
    }

    /* Load configuration file, could be done earlier but must be done
     * before SuricataInit, but even then its still optional as you
     * may be programmatically configuration Suricata. */
    if (SCLoadYamlConfig() != TM_ECODE_OK) {
        exit(EXIT_FAILURE);
    }

    SuricataInit();
    SuricataPostInit();

    /* Suricata is now running, but we enter a loop to keep it running
     * until it shouldn't be running anymore. */
    SuricataMainLoop();

    /* Shutdown engine. */
    SuricataShutdown();
    GlobalsDestroy();

    return EXIT_SUCCESS;
}
