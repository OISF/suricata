/* Copyright (C) 2020 Open Information Security Foundation
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
#include "util-plugin.h"
#include "suricata-plugin.h"

#ifdef HAVE_DLFCN_H

#include <dlfcn.h>

static void InitPlugin(char *path)
{
    void *lib = dlopen(path, RTLD_LAZY);
    if (lib != NULL) {
        SCLogNotice("Loading plugin %s", path);
        void (*registerf)(SCPlugin *) = dlsym(lib, "sc_plugin_register");
        if (registerf == NULL) {
            SCLogNotice("Plugin missing registration function: %s", path);
        } else {
            SCPlugin plugin;
            memset(&plugin, 0, sizeof(plugin));
            (*registerf)(&plugin);
            BUG_ON(plugin.name == NULL);
            BUG_ON(plugin.author == NULL);
            BUG_ON(plugin.license == NULL);
            BUG_ON(plugin.Init == NULL);
            SCLogNotice("Initializing plugin %s; author=%s; license=%s",
                plugin.name, plugin.author, plugin.license);
            (*plugin.Init)();
        }
    }
}

void PluginsLoad(void)
{
    DIR *dir = NULL;
    struct dirent *entry;
    char path[PATH_MAX];
    const char plugindir[] = "./plugins";

    dir = opendir(plugindir);
    if (dir == NULL) {
        return;
    }
    while ((entry = readdir(dir)) != NULL) {
        if (strstr(entry->d_name, ".so") != NULL) {
            snprintf(path, sizeof(path), "%s/%s", plugindir, entry->d_name);
            InitPlugin(path);
        }
    }
    free(dir);
}

#else

void PluginsLoad(void)
{
}

#endif
