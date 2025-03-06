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

#include "suricata-plugin.h"
#include "suricata-common.h"
#include "util-debug.h"

#include "runmode.h"
#include "source.h"

static void InitCapturePlugin(const char *args, int plugin_slot, int receive_slot, int decode_slot)
{
    SCLogNotice("...");
    CiCaptureIdsRegister(plugin_slot);
    TmModuleReceiveCiCaptureRegister(receive_slot);
    TmModuleDecodeCiCaptureRegister(decode_slot);
}

static void SCPluginInit(void)
{
    SCLogNotice("...");
    SCCapturePlugin *plugin = SCCalloc(1, sizeof(SCCapturePlugin));
    if (plugin == NULL) {
        FatalError("Failed to allocate memory for capture plugin");
    }
    plugin->name = "ci-capture";
    plugin->Init = InitCapturePlugin;
    plugin->GetDefaultMode = CiCaptureIdsGetDefaultRunMode;
    SCPluginRegisterCapture(plugin);
}

const SCPlugin PluginRegistration = {
    .version = SC_API_VERSION,
    .suricata_version = SC_PACKAGE_VERSION,
    .name = "ci-capture",
    .plugin_version = "0.1.0",
    .author = "OISF Developer",
    .license = "GPL-2.0-only",
    .Init = SCPluginInit,
};

const SCPlugin *SCPluginRegister()
{
    return &PluginRegistration;
}
