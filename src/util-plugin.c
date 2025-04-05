/* Copyright (C) 2020-2021 Open Information Security Foundation
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

#include "suricata-common.h"
#include "suricata-plugin.h"
#include "suricata.h"
#include "runmodes.h"
#include "util-plugin.h"
#include "util-debug.h"
#include "conf.h"

#ifdef HAVE_PLUGINS

#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "detect-engine-register.h"
#include "output.h"
#include "output-eve-bindgen.h"

#include <dlfcn.h>

typedef struct PluginListNode_ {
    SCPlugin *plugin;
    void *lib;
    TAILQ_ENTRY(PluginListNode_) entries;
} PluginListNode;

/**
 * The list of loaded plugins.
 *
 * Currently only used as a place to stash the pointer returned from
 * dlopen, but could have other uses, such as a plugin unload destructor.
 */
static TAILQ_HEAD(, PluginListNode_) plugins = TAILQ_HEAD_INITIALIZER(plugins);

static TAILQ_HEAD(, SCCapturePlugin_) capture_plugins = TAILQ_HEAD_INITIALIZER(capture_plugins);

bool RegisterPlugin(SCPlugin *plugin, void *lib)
{
    if (plugin->version != SC_API_VERSION) {
        SCLogError("Suricata and plugin versions differ: plugin has %" PRIx64
                   " (%s) vs Suricata %" PRIx64 " (plugin was built with %s)",
                plugin->version, plugin->plugin_version, SC_API_VERSION, plugin->suricata_version);
        return false;
    }
    BUG_ON(plugin->name == NULL);
    BUG_ON(plugin->author == NULL);
    BUG_ON(plugin->license == NULL);
    BUG_ON(plugin->Init == NULL);

    PluginListNode *node = SCCalloc(1, sizeof(*node));
    if (node == NULL) {
        SCLogError("Failed to allocate memory for plugin");
        return false;
    }
    node->plugin = plugin;
    node->lib = lib;
    TAILQ_INSERT_TAIL(&plugins, node, entries);
    SCLogNotice("Initializing plugin %s; version= %s; author=%s; license=%s; built from %s",
            plugin->name, plugin->plugin_version, plugin->author, plugin->license,
            plugin->suricata_version);
    (*plugin->Init)();
    return true;
}

static void InitPlugin(char *path)
{
    void *lib = dlopen(path, RTLD_NOW);
    if (lib == NULL) {
        SCLogNotice("Failed to open %s as a plugin: %s", path, dlerror());
    } else {
        SCLogNotice("Loading plugin %s", path);

        SCPluginRegisterFunc plugin_register = dlsym(lib, "SCPluginRegister");
        if (plugin_register == NULL) {
            SCLogError("Plugin does not export SCPluginRegister function: %s", path);
            dlclose(lib);
            return;
        }

        if (!RegisterPlugin(plugin_register(), lib)) {
            SCLogError("Plugin registration failed: %s", path);
            dlclose(lib);
            return;
        }
    }
}

void SCPluginsLoad(const char *capture_plugin_name, const char *capture_plugin_args)
{
    SCConfNode *conf = SCConfGetNode("plugins");
    if (conf == NULL) {
        return;
    }
    SCConfNode *plugin = NULL;
    TAILQ_FOREACH(plugin, &conf->head, next) {
        struct stat statbuf;
        if (stat(plugin->val, &statbuf) == -1) {
            SCLogError("Bad plugin path: %s: %s", plugin->val, strerror(errno));
            continue;
        }
        if (S_ISDIR(statbuf.st_mode)) {
            // coverity[toctou : FALSE]
            DIR *dir = opendir(plugin->val);
            if (dir == NULL) {
                SCLogError("Failed to open plugin directory %s: %s", plugin->val, strerror(errno));
                continue;
            }
            struct dirent *entry = NULL;
            char path[PATH_MAX];
            while ((entry = readdir(dir)) != NULL) {
                if (strstr(entry->d_name, ".so") != NULL) {
                    snprintf(path, sizeof(path), "%s/%s", plugin->val, entry->d_name);
                    InitPlugin(path);
                }
            }
            closedir(dir);
        } else {
            InitPlugin(plugin->val);
        }
    }

    if (SCRunmodeGet() == RUNMODE_PLUGIN) {
        SCCapturePlugin *capture = SCPluginFindCaptureByName(capture_plugin_name);
        if (capture == NULL) {
            FatalError("No capture plugin found with name %s", capture_plugin_name);
        }
        capture->Init(capture_plugin_args, RUNMODE_PLUGIN, TMM_RECEIVEPLUGIN,
                TMM_DECODEPLUGIN);
    }
}

int SCPluginRegisterCapture(SCCapturePlugin *plugin)
{
    TAILQ_INSERT_TAIL(&capture_plugins, plugin, entries);
    SCLogNotice("Capture plugin registered: %s", plugin->name);
    return 0;
}

SCCapturePlugin *SCPluginFindCaptureByName(const char *name)
{
    SCCapturePlugin *plugin = NULL;
    TAILQ_FOREACH(plugin, &capture_plugins, entries) {
        if (strcmp(name, plugin->name) == 0) {
            return plugin;
        }
    }
    return plugin;
}

int SCPluginRegisterAppLayer(SCAppLayerPlugin *plugin)
{
    AppProto alproto = AppProtoNewProtoFromString(plugin->name);
    if (plugin->Register) {
        if (AppLayerParserPreRegister(plugin->Register) != 0) {
            return 1;
        }
    }
    if (plugin->KeywordsRegister) {
        if (SCSigTablePreRegister(plugin->KeywordsRegister) != 0) {
            return 1;
        }
    }
    if (plugin->Logger) {
        EveJsonTxLoggerRegistrationData reg_data = {
            .confname = plugin->confname,
            .logname = plugin->logname,
            .alproto = alproto,
            .dir = plugin->dir,
            .LogTx = plugin->Logger,
        };
        if (SCOutputEvePreRegisterLogger(reg_data) != 0) {
            return 1;
        }
    }
    return 0;
}
#endif
