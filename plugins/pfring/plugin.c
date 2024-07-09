#include "suricata-common.h"
#include "suricata-plugin.h"

#include "decode.h"
#include "source-pfring.h"
#include "runmode-pfring.h"
#include "util-device.h"

static char *source_name = "pfring";

void InitCapturePlugin(const char *args, int plugin_slot, int receive_slot, int decode_slot)
{
    LiveBuildDeviceList("pfring");
    RunModeIdsPfringRegister(plugin_slot);
    TmModuleReceivePfringRegister(receive_slot);
    TmModuleDecodePfringRegister(decode_slot);
}

void SCPluginInit(void)
{
    SCLogNotice("SCPluginInit");
    SCCapturePlugin *plugin = SCCalloc(1, sizeof(SCCapturePlugin));
    if (plugin == NULL) {
        FatalError("Failed to allocate memory for capture plugin");
    }
    plugin->name = source_name;
    plugin->Init = InitCapturePlugin;
    plugin->GetDefaultMode = RunModeIdsPfringGetDefaultMode;
    SCPluginRegisterCapture(plugin);
}

const SCPlugin PluginRegistration = {
    .name = "pfring-plugin",
    .author = "Some Developer",
    .license = "GPLv2",
    .Init = SCPluginInit,
};

const SCPlugin *SCPluginRegister()
{
    return &PluginRegistration;
}
